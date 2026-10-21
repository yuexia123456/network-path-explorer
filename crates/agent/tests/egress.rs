use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream;
use network_path_agent::{
    domain::{
        Evidence, EvidenceLevel, ProxyDecision, ProxyKind, RouteInfo, TrafficDecision,
        TrafficDecisionKind,
    },
    error::DiagnosticError,
    network::{
        egress::{
            EgressBodyStream, EgressHttpClient, EgressHttpRequest, EgressHttpResponse,
            IpifyEgressProvider,
        },
        path::{SelectedRequestPath, SystemRequestPathPlanner},
    },
    ports::{
        EgressProvider, NoopRequestPathPhaseObserver, ProxyInspector, RequestPathPhaseObserver,
        RequestPathPlanner, Resolver, RouteInspector, TrafficDecisionProvider,
        TrafficObservationId, TrafficProbeTarget,
    },
};
use std::{
    collections::VecDeque,
    future::pending,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Notify;
use url::Url;
use uuid::Uuid;

type ResolverAnswer = (&'static str, u16, Vec<IpAddr>);
type RequestLog = Arc<Mutex<Vec<EgressHttpRequest>>>;
type TargetLog = Arc<Mutex<Vec<TrafficProbeTarget>>>;
type TestEgressProvider =
    IpifyEgressProvider<FixedPlanner, FakeTrafficProvider, FakeEgressHttpClient>;
type ProviderFixture = (TestEgressProvider, RequestLog, TargetLog);

#[derive(Clone)]
struct FakeProxyInspector {
    decision: ProxyDecision,
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl ProxyInspector for FakeProxyInspector {
    async fn decision_for(&self, url: &Url) -> Result<ProxyDecision, DiagnosticError> {
        self.calls.lock().unwrap().push(url.as_str().to_owned());
        Ok(self.decision.clone())
    }
}

#[derive(Clone)]
struct FakeResolver {
    answers: Arc<Mutex<VecDeque<ResolverAnswer>>>,
    calls: Arc<Mutex<Vec<(String, u16)>>>,
}

#[async_trait]
impl Resolver for FakeResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, DiagnosticError> {
        self.calls.lock().unwrap().push((host.to_owned(), port));
        let (expected_host, expected_port, answer) =
            self.answers.lock().unwrap().pop_front().unwrap();
        assert_eq!((host, port), (expected_host, expected_port));
        Ok(answer)
    }
}

#[derive(Clone)]
struct FakeRouteInspector {
    calls: Arc<Mutex<Vec<IpAddr>>>,
}

#[async_trait]
impl RouteInspector for FakeRouteInspector {
    async fn route_to(&self, destination: IpAddr) -> Result<RouteInfo, DiagnosticError> {
        self.calls.lock().unwrap().push(destination);
        Ok(RouteInfo {
            destination,
            gateway: Some("192.0.2.1".parse().unwrap()),
            interface: "en0".into(),
        })
    }
}

fn evidence(summary: &str) -> Evidence {
    Evidence {
        level: EvidenceLevel::Confirmed,
        source: "fixture".into(),
        summary: summary.into(),
    }
}

fn direct_proxy() -> ProxyDecision {
    ProxyDecision {
        kind: ProxyKind::Direct,
        host: None,
        port: None,
        bypass_reason: None,
        evidence: evidence("direct"),
    }
}

fn configured_proxy(kind: ProxyKind, host: &str, port: u16) -> ProxyDecision {
    ProxyDecision {
        kind,
        host: Some(host.into()),
        port: Some(port),
        bypass_reason: None,
        evidence: evidence("proxy"),
    }
}

#[tokio::test]
async fn direct_plan_pins_the_first_target_ip_and_runs_each_source_once() {
    let proxy_calls = Arc::new(Mutex::new(Vec::new()));
    let resolver_calls = Arc::new(Mutex::new(Vec::new()));
    let route_calls = Arc::new(Mutex::new(Vec::new()));
    let planner = SystemRequestPathPlanner::new(
        FakeProxyInspector {
            decision: direct_proxy(),
            calls: Arc::clone(&proxy_calls),
        },
        FakeResolver {
            answers: Arc::new(Mutex::new(VecDeque::from([(
                "api64.ipify.org",
                443,
                vec![
                    "2001:db8::64".parse().unwrap(),
                    "198.51.100.64".parse().unwrap(),
                ],
            )]))),
            calls: Arc::clone(&resolver_calls),
        },
        FakeRouteInspector {
            calls: Arc::clone(&route_calls),
        },
    );

    let plan = planner
        .plan(
            &Url::parse("https://api64.ipify.org?format=json").unwrap(),
            &NoopRequestPathPhaseObserver,
        )
        .await
        .unwrap();

    assert_eq!(plan.proxy.kind, ProxyKind::Direct);
    assert_eq!(
        plan.resolved_ips,
        vec![
            "2001:db8::64".parse::<IpAddr>().unwrap(),
            "198.51.100.64".parse::<IpAddr>().unwrap(),
        ]
    );
    assert_eq!(
        plan.selected_peer,
        Some("[2001:db8::64]:443".parse().unwrap())
    );
    assert_eq!(
        &*proxy_calls.lock().unwrap(),
        &["https://api64.ipify.org/?format=json"]
    );
    assert_eq!(
        &*resolver_calls.lock().unwrap(),
        &[("api64.ipify.org".into(), 443)]
    );
    assert_eq!(
        &*route_calls.lock().unwrap(),
        &["2001:db8::64".parse::<IpAddr>().unwrap()]
    );
}

#[tokio::test]
async fn http_and_socks_plans_resolve_and_route_only_the_selected_proxy_peer() {
    for kind in [ProxyKind::Http, ProxyKind::Https, ProxyKind::Socks] {
        let resolver_calls = Arc::new(Mutex::new(Vec::new()));
        let route_calls = Arc::new(Mutex::new(Vec::new()));
        let planner = SystemRequestPathPlanner::new(
            FakeProxyInspector {
                decision: configured_proxy(kind.clone(), "proxy.fixture", 7890),
                calls: Arc::new(Mutex::new(Vec::new())),
            },
            FakeResolver {
                answers: Arc::new(Mutex::new(VecDeque::from([
                    (
                        "api64.ipify.org",
                        443,
                        vec!["203.0.113.64".parse().unwrap()],
                    ),
                    ("proxy.fixture", 7890, vec!["127.0.0.9".parse().unwrap()]),
                ]))),
                calls: Arc::clone(&resolver_calls),
            },
            FakeRouteInspector {
                calls: Arc::clone(&route_calls),
            },
        );

        let plan = planner
            .plan(
                &Url::parse("https://api64.ipify.org?format=json").unwrap(),
                &NoopRequestPathPhaseObserver,
            )
            .await
            .unwrap();

        assert_eq!(plan.proxy.kind, kind);
        assert_eq!(
            plan.selected_peer,
            Some("127.0.0.9:7890".parse::<SocketAddr>().unwrap())
        );
        assert_eq!(
            &*resolver_calls.lock().unwrap(),
            &[
                ("api64.ipify.org".into(), 443),
                ("proxy.fixture".into(), 7890),
            ]
        );
        assert_eq!(
            &*route_calls.lock().unwrap(),
            &["127.0.0.9".parse::<IpAddr>().unwrap()]
        );
    }
}

#[derive(Clone)]
struct FixedPlanner {
    plan: SelectedRequestPath,
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl RequestPathPlanner for FixedPlanner {
    async fn plan(
        &self,
        url: &Url,
        _phases: &dyn RequestPathPhaseObserver,
    ) -> Result<SelectedRequestPath, DiagnosticError> {
        self.calls.lock().unwrap().push(url.as_str().to_owned());
        Ok(self.plan.clone())
    }
}

#[derive(Clone)]
enum FinishBehavior {
    Decision(TrafficDecision),
    Error,
    Pending,
}

#[derive(Clone)]
struct FakeTrafficProvider {
    targets: Arc<Mutex<Vec<TrafficProbeTarget>>>,
    finish_behavior: FinishBehavior,
    cancelled: Arc<Notify>,
}

#[async_trait]
impl TrafficDecisionProvider for FakeTrafficProvider {
    async fn runtime(&self) -> network_path_agent::domain::MihomoRuntime {
        unreachable!("egress observation does not need a runtime snapshot")
    }

    async fn begin(
        &self,
        target: &TrafficProbeTarget,
    ) -> Result<TrafficObservationId, DiagnosticError> {
        self.targets.lock().unwrap().push(target.clone());
        Ok(TrafficObservationId(Uuid::new_v4()))
    }

    async fn finish(&self, _id: TrafficObservationId) -> Result<TrafficDecision, DiagnosticError> {
        match &self.finish_behavior {
            FinishBehavior::Decision(decision) => Ok(decision.clone()),
            FinishBehavior::Error => {
                Err(DiagnosticError::System("sensitive adapter failure".into()))
            }
            FinishBehavior::Pending => pending().await,
        }
    }

    async fn cancel(&self, _id: TrafficObservationId) {
        self.cancelled.notify_one();
    }
}

#[derive(Clone)]
struct FakeEgressHttpClient {
    requests: Arc<Mutex<Vec<EgressHttpRequest>>>,
    response: Arc<Mutex<Option<EgressHttpResponse>>>,
    pending: bool,
}

#[async_trait]
impl EgressHttpClient for FakeEgressHttpClient {
    async fn execute(
        &self,
        request: EgressHttpRequest,
    ) -> Result<EgressHttpResponse, DiagnosticError> {
        self.requests.lock().unwrap().push(request);
        if self.pending {
            return pending().await;
        }
        Ok(self.response.lock().unwrap().take().unwrap())
    }
}

fn response(status: u16, chunks: Vec<Result<Vec<u8>, DiagnosticError>>) -> EgressHttpResponse {
    let body: EgressBodyStream = Box::pin(stream::iter(
        chunks
            .into_iter()
            .map(|chunk| chunk.map(Bytes::from))
            .collect::<Vec<_>>(),
    ));
    EgressHttpResponse { status, body }
}

fn selected_path(proxy: ProxyDecision) -> SelectedRequestPath {
    SelectedRequestPath {
        proxy,
        resolved_ips: vec!["203.0.113.64".parse().unwrap()],
        selected_peer: Some("203.0.113.64:443".parse().unwrap()),
        route: Some(RouteInfo {
            destination: "203.0.113.64".parse().unwrap(),
            gateway: None,
            interface: "en0".into(),
        }),
        dns_evidence: evidence("dns"),
        route_evidence: evidence("route"),
    }
}

fn direct_decision() -> TrafficDecision {
    TrafficDecision {
        kind: TrafficDecisionKind::Direct,
        mode: Some("rule".into()),
        tun_enabled: Some(true),
        rule: None,
        chain: vec![],
        evidence: vec![evidence("mihomo direct")],
    }
}

fn provider_with(
    body: Vec<Result<Vec<u8>, DiagnosticError>>,
    decision: FinishBehavior,
) -> ProviderFixture {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let targets = Arc::new(Mutex::new(Vec::new()));
    let provider = IpifyEgressProvider::with_http_client(
        FixedPlanner {
            plan: selected_path(direct_proxy()),
            calls: Arc::new(Mutex::new(Vec::new())),
        },
        FakeTrafficProvider {
            targets: Arc::clone(&targets),
            finish_behavior: decision,
            cancelled: Arc::new(Notify::new()),
        },
        FakeEgressHttpClient {
            requests: Arc::clone(&requests),
            response: Arc::new(Mutex::new(Some(response(200, body)))),
            pending: false,
        },
    );
    (provider, requests, targets)
}

#[tokio::test]
async fn ipify_uses_exact_request_contract_and_its_own_traffic_observation() {
    let (provider, requests, targets) = provider_with(
        vec![Ok(br#"{"ip":"203.0.113.9"}"#.to_vec())],
        FinishBehavior::Decision(direct_decision()),
    );

    let result = provider.observe().await.unwrap();

    assert_eq!(result.provider, "ipify");
    assert_eq!(result.ip, "203.0.113.9".parse::<IpAddr>().unwrap());
    assert_eq!(result.traffic_decision.kind, TrafficDecisionKind::Direct);
    assert_eq!(result.evidence.len(), 1);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].url.as_str(),
        "https://api64.ipify.org/?format=json"
    );
    assert_eq!(requests[0].user_agent, "NetworkPathExplorer/0.1");
    assert!(!requests[0].follow_redirects);
    assert_eq!(
        requests[0].selected_peer,
        "203.0.113.64:443".parse().unwrap()
    );
    assert_eq!(requests[0].proxy.kind, ProxyKind::Direct);
    let targets = targets.lock().unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].host, "api64.ipify.org");
    assert_eq!(targets[0].port, 443);
    assert_eq!(
        targets[0].resolved_ips,
        vec!["203.0.113.64".parse::<IpAddr>().unwrap()]
    );
}

#[tokio::test]
async fn ipify_accepts_exact_ipv4_and_ipv6_json_across_stream_chunks() {
    for (chunks, expected) in [
        (
            vec![Ok(br#"{"ip":"203."#.to_vec()), Ok(b"0.113.9\"}".to_vec())],
            "203.0.113.9".parse::<IpAddr>().unwrap(),
        ),
        (
            vec![Ok(br#"{"ip":"2001:db8::9"}"#.to_vec())],
            "2001:db8::9".parse::<IpAddr>().unwrap(),
        ),
    ] {
        let (provider, _, _) = provider_with(chunks, FinishBehavior::Decision(direct_decision()));
        assert_eq!(provider.observe().await.unwrap().ip, expected);
    }
}

#[tokio::test]
async fn ipify_rejects_oversize_invalid_and_non_exact_json_without_echoing_body() {
    let cases = [
        vec![Ok(vec![b'x'; 1000]), Ok(vec![b'y'; 25])],
        vec![Ok(br#"{"ip":"not-an-ip"}"#.to_vec())],
        vec![Ok(br#"{"ip":"203.0.113.9","country":"CN"}"#.to_vec())],
        vec![Ok(br#"{"address":"203.0.113.9"}"#.to_vec())],
        vec![Ok(br#"{"ip":9}"#.to_vec())],
        vec![Ok(br#"{"ip":"203.0.113.9"} trailing"#.to_vec())],
    ];

    for body in cases {
        let (provider, _, _) = provider_with(body, FinishBehavior::Decision(direct_decision()));
        let error = provider.observe().await.unwrap_err().to_string();
        assert!(error.contains("公网出口探测失败"));
        assert!(!error.contains("country"));
        assert!(!error.contains("not-an-ip"));
    }
}

#[tokio::test]
async fn traffic_adapter_failure_degrades_to_unknown_after_valid_ipify_json() {
    let (provider, _, _) = provider_with(
        vec![Ok(br#"{"ip":"203.0.113.9"}"#.to_vec())],
        FinishBehavior::Error,
    );

    let result = provider.observe().await.unwrap();

    assert_eq!(result.ip, "203.0.113.9".parse::<IpAddr>().unwrap());
    assert_eq!(result.traffic_decision.kind, TrafficDecisionKind::Unknown);
    let json = serde_json::to_string(&result).unwrap();
    assert!(!json.contains("sensitive adapter failure"));
}

#[tokio::test]
async fn five_second_whole_observation_timeout_cancels_pending_traffic_finish() {
    let cancelled = Arc::new(Notify::new());
    let provider = IpifyEgressProvider::with_http_client(
        FixedPlanner {
            plan: selected_path(direct_proxy()),
            calls: Arc::new(Mutex::new(Vec::new())),
        },
        FakeTrafficProvider {
            targets: Arc::new(Mutex::new(Vec::new())),
            finish_behavior: FinishBehavior::Pending,
            cancelled: Arc::clone(&cancelled),
        },
        FakeEgressHttpClient {
            requests: Arc::new(Mutex::new(Vec::new())),
            response: Arc::new(Mutex::new(Some(response(
                200,
                vec![Ok(br#"{"ip":"203.0.113.9"}"#.to_vec())],
            )))),
            pending: false,
        },
    );
    let started = Instant::now();

    let error = provider.observe().await.unwrap_err();

    assert!(started.elapsed() >= Duration::from_secs(5));
    assert!(started.elapsed() < Duration::from_secs(6));
    assert!(error.to_string().contains("公网出口探测失败"));
    tokio::time::timeout(Duration::from_secs(1), cancelled.notified())
        .await
        .expect("timeout must cancel the retained traffic observation");
    provider.shutdown().await;
}

#[tokio::test]
async fn dropping_egress_observation_cancels_its_tracked_traffic_worker() {
    let cancelled = Arc::new(Notify::new());
    let provider = Arc::new(IpifyEgressProvider::with_http_client(
        FixedPlanner {
            plan: selected_path(direct_proxy()),
            calls: Arc::new(Mutex::new(Vec::new())),
        },
        FakeTrafficProvider {
            targets: Arc::new(Mutex::new(Vec::new())),
            finish_behavior: FinishBehavior::Decision(direct_decision()),
            cancelled: Arc::clone(&cancelled),
        },
        FakeEgressHttpClient {
            requests: Arc::new(Mutex::new(Vec::new())),
            response: Arc::new(Mutex::new(None)),
            pending: true,
        },
    ));
    let task_provider = Arc::clone(&provider);
    let task = tokio::spawn(async move { task_provider.observe().await });
    tokio::task::yield_now().await;

    task.abort();

    tokio::time::timeout(Duration::from_secs(1), cancelled.notified())
        .await
        .expect("dropped egress future must cancel traffic observation");
    provider.shutdown().await;
}

#[tokio::test]
async fn shutdown_rejects_late_egress_without_planning_or_http_traffic() {
    let planner_calls = Arc::new(Mutex::new(Vec::new()));
    let http_requests = Arc::new(Mutex::new(Vec::new()));
    let provider = IpifyEgressProvider::with_http_client(
        FixedPlanner {
            plan: selected_path(direct_proxy()),
            calls: Arc::clone(&planner_calls),
        },
        FakeTrafficProvider {
            targets: Arc::new(Mutex::new(Vec::new())),
            finish_behavior: FinishBehavior::Decision(direct_decision()),
            cancelled: Arc::new(Notify::new()),
        },
        FakeEgressHttpClient {
            requests: Arc::clone(&http_requests),
            response: Arc::new(Mutex::new(None)),
            pending: true,
        },
    );

    provider.shutdown().await;
    let result = provider.observe().await;

    assert!(result.is_err());
    assert!(planner_calls.lock().unwrap().is_empty());
    assert!(http_requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn shutdown_interrupts_an_inflight_egress_request_and_drains_traffic() {
    let targets = Arc::new(Mutex::new(Vec::new()));
    let cancelled = Arc::new(Notify::new());
    let provider = Arc::new(IpifyEgressProvider::with_http_client(
        FixedPlanner {
            plan: selected_path(direct_proxy()),
            calls: Arc::new(Mutex::new(Vec::new())),
        },
        FakeTrafficProvider {
            targets: Arc::clone(&targets),
            finish_behavior: FinishBehavior::Decision(direct_decision()),
            cancelled: Arc::clone(&cancelled),
        },
        FakeEgressHttpClient {
            requests: Arc::new(Mutex::new(Vec::new())),
            response: Arc::new(Mutex::new(None)),
            pending: true,
        },
    ));
    let observe_provider = Arc::clone(&provider);
    let observe = tokio::spawn(async move { observe_provider.observe().await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while targets.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    provider.shutdown().await;

    tokio::time::timeout(Duration::from_secs(1), cancelled.notified())
        .await
        .expect("shutdown must cancel the nested traffic observation");
    let result = tokio::time::timeout(Duration::from_secs(1), observe)
        .await
        .expect("shutdown must interrupt the whole egress observation")
        .unwrap();
    assert!(result.is_err());
}

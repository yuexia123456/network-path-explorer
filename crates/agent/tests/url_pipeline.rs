use async_trait::async_trait;
use network_path_agent::{
    diagnostics::url::UrlDiagnosticService,
    domain::{
        DiagnosticStage, Evidence, EvidenceLevel, HttpObservation, PeerEndpoint, ProxyDecision,
        ProxyKind, RouteInfo, TrafficDecision, TrafficDecisionKind,
    },
    error::DiagnosticError,
    ports::{
        ProgressSink, ProxyInspector, Resolver, RouteInspector, TrafficDecisionProvider,
        TrafficObservationId, TrafficProbeScheme, TrafficProbeTarget, WebProbe,
    },
    traffic::NoopTrafficDecisionProvider,
};
use std::{
    collections::HashMap,
    future::pending,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
use url::Url;
use uuid::Uuid;

#[derive(Clone)]
struct FakeProxy {
    decision: ProxyDecision,
}

#[async_trait]
impl ProxyInspector for &FakeProxy {
    async fn decision_for(&self, _url: &Url) -> Result<ProxyDecision, DiagnosticError> {
        Ok(self.decision.clone())
    }
}

#[derive(Default)]
struct FakeResolver {
    answers: HashMap<(String, u16), Vec<IpAddr>>,
    calls: Mutex<Vec<(String, u16)>>,
}

impl FakeResolver {
    fn with_answer(mut self, host: &str, port: u16, ips: &[&str]) -> Self {
        self.answers.insert(
            (host.into(), port),
            ips.iter().map(|ip| ip.parse().unwrap()).collect(),
        );
        self
    }

    fn calls(&self) -> Vec<(String, u16)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl Resolver for &FakeResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, DiagnosticError> {
        self.calls.lock().unwrap().push((host.into(), port));
        self.answers
            .get(&(host.into(), port))
            .cloned()
            .ok_or(DiagnosticError::DnsFailed)
    }
}

struct FakeRoute {
    route: Option<RouteInfo>,
    failure: Option<String>,
    calls: Mutex<Vec<IpAddr>>,
}

impl FakeRoute {
    fn succeeds() -> Self {
        Self {
            route: Some(RouteInfo {
                destination: "203.0.113.10".parse().unwrap(),
                gateway: Some("192.0.2.1".parse().unwrap()),
                interface: "en0".into(),
            }),
            failure: None,
            calls: Mutex::new(Vec::new()),
        }
    }

    fn fails() -> Self {
        Self {
            route: None,
            failure: Some("route unavailable".into()),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<IpAddr> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl RouteInspector for &FakeRoute {
    async fn route_to(&self, destination: IpAddr) -> Result<RouteInfo, DiagnosticError> {
        self.calls.lock().unwrap().push(destination);
        match (&self.route, &self.failure) {
            (Some(route), None) => Ok(RouteInfo {
                destination,
                ..route.clone()
            }),
            (None, Some(message)) => Err(DiagnosticError::System(message.clone())),
            _ => unreachable!("test fake has exactly one result"),
        }
    }
}

struct FakeProbe {
    observation: HttpObservation,
    observe_selected_peer: bool,
    calls: Mutex<Vec<(String, ProxyKind, SocketAddr)>>,
    order_log: Option<Arc<Mutex<Vec<&'static str>>>>,
}

impl FakeProbe {
    fn succeeds() -> Self {
        Self {
            observation: HttpObservation {
                status: Some(204),
                final_url: "https://example.com/".into(),
                elapsed_ms: 8,
                error_code: None,
                peer_endpoint: None,
            },
            observe_selected_peer: true,
            calls: Mutex::new(Vec::new()),
            order_log: None,
        }
    }

    fn connection_failure() -> Self {
        Self {
            observation: HttpObservation {
                status: None,
                final_url: "https://example.com/".into(),
                elapsed_ms: 8,
                error_code: Some("connect".into()),
                peer_endpoint: None,
            },
            observe_selected_peer: false,
            calls: Mutex::new(Vec::new()),
            order_log: None,
        }
    }

    fn returned_failure(error_code: &str) -> Self {
        Self {
            observation: HttpObservation {
                status: None,
                final_url: "https://example.com/".into(),
                elapsed_ms: 8,
                error_code: Some(error_code.into()),
                peer_endpoint: None,
            },
            observe_selected_peer: false,
            calls: Mutex::new(Vec::new()),
            order_log: None,
        }
    }

    fn with_order_log(mut self, order_log: Arc<Mutex<Vec<&'static str>>>) -> Self {
        self.order_log = Some(order_log);
        self
    }

    fn calls(&self) -> Vec<(String, ProxyKind, SocketAddr)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl WebProbe for &FakeProbe {
    async fn probe(
        &self,
        url: &Url,
        proxy: &ProxyDecision,
        selected_peer: SocketAddr,
    ) -> Result<HttpObservation, DiagnosticError> {
        if let Some(log) = &self.order_log {
            log.lock().unwrap().push("http_probe");
        }
        self.calls
            .lock()
            .unwrap()
            .push((url.as_str().into(), proxy.kind.clone(), selected_peer));
        let mut observation = self.observation.clone();
        if self.observe_selected_peer {
            observation.peer_endpoint = Some(PeerEndpoint {
                ip: selected_peer.ip(),
                port: selected_peer.port(),
            });
        }
        Ok(observation)
    }
}

#[derive(Clone, Copy)]
enum TrafficFailure {
    None,
    Begin,
    Finish,
}

#[derive(Clone)]
struct FakeTrafficProvider {
    decision: TrafficDecision,
    failure: TrafficFailure,
    order_log: Arc<Mutex<Vec<&'static str>>>,
    targets: Arc<Mutex<Vec<TrafficProbeTarget>>>,
    began: Arc<Notify>,
    cancelled: Arc<Notify>,
    cancel_count: Arc<AtomicUsize>,
}

impl FakeTrafficProvider {
    fn proxy(order_log: Arc<Mutex<Vec<&'static str>>>) -> Self {
        Self {
            decision: confirmed_traffic_decision(TrafficDecisionKind::Proxy),
            failure: TrafficFailure::None,
            order_log,
            targets: Arc::new(Mutex::new(Vec::new())),
            began: Arc::new(Notify::new()),
            cancelled: Arc::new(Notify::new()),
            cancel_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn failing(failure: TrafficFailure) -> Self {
        Self {
            failure,
            ..Self::proxy(Arc::new(Mutex::new(Vec::new())))
        }
    }

    fn targets(&self) -> Vec<TrafficProbeTarget> {
        self.targets.lock().unwrap().clone()
    }
}

#[async_trait]
impl TrafficDecisionProvider for FakeTrafficProvider {
    async fn runtime(&self) -> network_path_agent::domain::MihomoRuntime {
        unreachable!("URL orchestration does not read runtime state")
    }

    async fn begin(
        &self,
        target: &TrafficProbeTarget,
    ) -> Result<TrafficObservationId, DiagnosticError> {
        self.order_log.lock().unwrap().push("traffic_begin");
        self.targets.lock().unwrap().push(target.clone());
        self.began.notify_one();
        if matches!(self.failure, TrafficFailure::Begin) {
            Err(DiagnosticError::System(
                "controller_secret=must-never-escape".into(),
            ))
        } else {
            Ok(TrafficObservationId(Uuid::new_v4()))
        }
    }

    async fn finish(&self, _id: TrafficObservationId) -> Result<TrafficDecision, DiagnosticError> {
        self.order_log.lock().unwrap().push("traffic_finish");
        if matches!(self.failure, TrafficFailure::Finish) {
            Err(DiagnosticError::System(
                "socket=/tmp/private.sock payload=unrelated".into(),
            ))
        } else {
            Ok(self.decision.clone())
        }
    }

    async fn cancel(&self, _id: TrafficObservationId) {
        self.cancel_count.fetch_add(1, Ordering::SeqCst);
        self.cancelled.notify_one();
    }
}

struct ErrorProbe;

#[async_trait]
impl WebProbe for ErrorProbe {
    async fn probe(
        &self,
        _url: &Url,
        _proxy: &ProxyDecision,
        _selected_peer: SocketAddr,
    ) -> Result<HttpObservation, DiagnosticError> {
        Err(DiagnosticError::Http("probe exited".into()))
    }
}

struct BlockingProbe;

#[async_trait]
impl WebProbe for BlockingProbe {
    async fn probe(
        &self,
        _url: &Url,
        _proxy: &ProxyDecision,
        _selected_peer: SocketAddr,
    ) -> Result<HttpObservation, DiagnosticError> {
        pending().await
    }
}

#[derive(Default)]
struct RecordingProgress(Mutex<Vec<DiagnosticStage>>);

impl RecordingProgress {
    fn stages(&self) -> Vec<DiagnosticStage> {
        self.0.lock().unwrap().clone()
    }
}

impl ProgressSink for RecordingProgress {
    fn emit(&self, stage: DiagnosticStage) {
        self.0.lock().unwrap().push(stage);
    }
}

#[derive(Default)]
struct PhaseGate {
    entered: Notify,
    release: Notify,
}

struct BlockingProxyPhase {
    gate: Arc<PhaseGate>,
}

#[async_trait]
impl ProxyInspector for &BlockingProxyPhase {
    async fn decision_for(&self, _url: &Url) -> Result<ProxyDecision, DiagnosticError> {
        self.gate.entered.notify_one();
        self.gate.release.notified().await;
        Ok(direct_proxy())
    }
}

struct BlockingDnsPhase {
    gate: Arc<PhaseGate>,
}

#[async_trait]
impl Resolver for &BlockingDnsPhase {
    async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, DiagnosticError> {
        self.gate.entered.notify_one();
        self.gate.release.notified().await;
        Ok(vec!["203.0.113.10".parse().unwrap()])
    }
}

struct BlockingRoutePhase {
    gate: Arc<PhaseGate>,
}

#[async_trait]
impl RouteInspector for &BlockingRoutePhase {
    async fn route_to(&self, destination: IpAddr) -> Result<RouteInfo, DiagnosticError> {
        self.gate.entered.notify_one();
        self.gate.release.notified().await;
        Ok(RouteInfo {
            destination,
            gateway: None,
            interface: "en0".into(),
        })
    }
}

fn direct_proxy() -> ProxyDecision {
    ProxyDecision {
        kind: ProxyKind::Direct,
        host: None,
        port: None,
        bypass_reason: None,
        evidence: Evidence {
            level: EvidenceLevel::Confirmed,
            source: "proxy".into(),
            summary: "direct".into(),
        },
    }
}

fn http_proxy(host: &str) -> ProxyDecision {
    ProxyDecision {
        kind: ProxyKind::Http,
        host: Some(host.into()),
        port: Some(3128),
        bypass_reason: None,
        evidence: Evidence {
            level: EvidenceLevel::Confirmed,
            source: "proxy".into(),
            summary: "http proxy".into(),
        },
    }
}

fn unknown_proxy() -> ProxyDecision {
    ProxyDecision {
        kind: ProxyKind::Unknown,
        host: None,
        port: None,
        bypass_reason: None,
        evidence: Evidence {
            level: EvidenceLevel::Unknown,
            source: "proxy".into(),
            summary: "PAC/WPAD".into(),
        },
    }
}

fn confirmed_traffic_decision(kind: TrafficDecisionKind) -> TrafficDecision {
    TrafficDecision {
        kind,
        mode: Some("rule".into()),
        tun_enabled: Some(true),
        rule: None,
        chain: vec![],
        evidence: vec![Evidence {
            level: EvidenceLevel::Confirmed,
            source: "mihomo_connection".into(),
            summary: "matched".into(),
        }],
    }
}

fn assert_generic_unknown(decision: &TrafficDecision) {
    assert_eq!(decision.kind, TrafficDecisionKind::Unknown);
    assert_eq!(decision.chain, vec![]);
    assert_eq!(decision.evidence.len(), 1);
    assert_eq!(decision.evidence[0].source, "mihomo");
    assert_eq!(decision.evidence[0].summary, "未能确认 Clash 最终决策");
}

#[tokio::test]
async fn proxy_progress_is_visible_while_proxy_inspection_is_pending() {
    let gate = Arc::new(PhaseGate::default());
    let proxy = BlockingProxyPhase {
        gate: Arc::clone(&gate),
    };
    let resolver = FakeResolver::default().with_answer("example.com", 443, &["203.0.113.10"]);
    let route = FakeRoute::succeeds();
    let probe = FakeProbe::succeeds();
    let progress = RecordingProgress::default();
    let service = UrlDiagnosticService::new(
        &proxy,
        &resolver,
        &route,
        &probe,
        NoopTrafficDecisionProvider,
    );
    let mut run = Box::pin(service.run("example.com", &progress));

    tokio::select! {
        _ = gate.entered.notified() => {}
        result = &mut run => panic!("proxy phase unexpectedly completed: {result:?}"),
    }
    assert_eq!(
        progress.stages(),
        vec![DiagnosticStage::Validating, DiagnosticStage::Proxy]
    );

    gate.release.notify_one();
    run.await.unwrap();
}

#[tokio::test]
async fn dns_progress_is_visible_while_target_resolution_is_pending() {
    let gate = Arc::new(PhaseGate::default());
    let proxy = FakeProxy {
        decision: direct_proxy(),
    };
    let resolver = BlockingDnsPhase {
        gate: Arc::clone(&gate),
    };
    let route = FakeRoute::succeeds();
    let probe = FakeProbe::succeeds();
    let progress = RecordingProgress::default();
    let service = UrlDiagnosticService::new(
        &proxy,
        &resolver,
        &route,
        &probe,
        NoopTrafficDecisionProvider,
    );
    let mut run = Box::pin(service.run("example.com", &progress));

    tokio::select! {
        _ = gate.entered.notified() => {}
        result = &mut run => panic!("DNS phase unexpectedly completed: {result:?}"),
    }
    assert_eq!(
        progress.stages(),
        vec![
            DiagnosticStage::Validating,
            DiagnosticStage::Proxy,
            DiagnosticStage::Dns,
        ]
    );

    gate.release.notify_one();
    run.await.unwrap();
}

#[tokio::test]
async fn route_progress_is_visible_while_route_lookup_is_pending() {
    let gate = Arc::new(PhaseGate::default());
    let proxy = FakeProxy {
        decision: direct_proxy(),
    };
    let resolver = FakeResolver::default().with_answer("example.com", 443, &["203.0.113.10"]);
    let route = BlockingRoutePhase {
        gate: Arc::clone(&gate),
    };
    let probe = FakeProbe::succeeds();
    let progress = RecordingProgress::default();
    let service = UrlDiagnosticService::new(
        &proxy,
        &resolver,
        &route,
        &probe,
        NoopTrafficDecisionProvider,
    );
    let mut run = Box::pin(service.run("example.com", &progress));

    tokio::select! {
        _ = gate.entered.notified() => {}
        result = &mut run => panic!("route phase unexpectedly completed: {result:?}"),
    }
    assert_eq!(
        progress.stages(),
        vec![
            DiagnosticStage::Validating,
            DiagnosticStage::Proxy,
            DiagnosticStage::Dns,
            DiagnosticStage::Route,
        ]
    );

    gate.release.notify_one();
    run.await.unwrap();
}

#[tokio::test]
async fn direct_mode_routes_to_the_first_target_ip_and_records_ordered_evidence() {
    let resolver =
        FakeResolver::default().with_answer("example.com", 443, &["203.0.113.10", "203.0.113.11"]);
    let route = FakeRoute::succeeds();
    let probe = FakeProbe::succeeds();
    let progress = RecordingProgress::default();
    let proxy = FakeProxy {
        decision: direct_proxy(),
    };
    let service = UrlDiagnosticService::new(
        &proxy,
        &resolver,
        &route,
        &probe,
        NoopTrafficDecisionProvider,
    );

    let result = service.run("  example.com  ", &progress).await.unwrap();

    assert_eq!(result.requested_url, "  example.com  ");
    assert_eq!(result.normalized_url, "https://example.com/");
    assert_eq!(
        result.resolved_ips,
        vec![
            "203.0.113.10".parse::<IpAddr>().unwrap(),
            "203.0.113.11".parse::<IpAddr>().unwrap(),
        ]
    );
    assert_eq!(resolver.calls(), vec![("example.com".into(), 443)]);
    assert_eq!(
        route.calls(),
        vec!["203.0.113.10".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(
        probe.calls(),
        vec![(
            "https://example.com/".into(),
            ProxyKind::Direct,
            "203.0.113.10:443".parse().unwrap(),
        )]
    );
    assert_eq!(
        result.http.peer_endpoint,
        Some(PeerEndpoint {
            ip: "203.0.113.10".parse().unwrap(),
            port: 443,
        })
    );
    assert_eq!(
        result
            .evidence
            .iter()
            .map(|evidence| evidence.source.as_str())
            .collect::<Vec<_>>(),
        vec!["proxy", "dns", "route", "http"]
    );
    assert_eq!(
        progress.stages(),
        vec![
            DiagnosticStage::Validating,
            DiagnosticStage::Proxy,
            DiagnosticStage::Dns,
            DiagnosticStage::Route,
            DiagnosticStage::Http,
            DiagnosticStage::Completed,
        ]
    );
}

#[tokio::test]
async fn proxy_mode_resolves_and_routes_to_the_proxy_endpoint() {
    let resolver = FakeResolver::default()
        .with_answer("example.com", 443, &["203.0.113.10"])
        .with_answer("proxy.test", 3128, &["198.51.100.9"]);
    let route = FakeRoute::succeeds();
    let probe = FakeProbe::succeeds();
    let progress = RecordingProgress::default();
    let proxy = FakeProxy {
        decision: http_proxy("proxy.test"),
    };
    let service = UrlDiagnosticService::new(
        &proxy,
        &resolver,
        &route,
        &probe,
        NoopTrafficDecisionProvider,
    );

    let result = service.run("example.com", &progress).await.unwrap();

    assert_eq!(
        resolver.calls(),
        vec![("example.com".into(), 443), ("proxy.test".into(), 3128)]
    );
    assert_eq!(
        route.calls(),
        vec!["198.51.100.9".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(
        result.route.unwrap().destination,
        "198.51.100.9".parse::<IpAddr>().unwrap()
    );
    assert_eq!(
        probe.calls(),
        vec![(
            "https://example.com/".into(),
            ProxyKind::Http,
            "198.51.100.9:3128".parse().unwrap(),
        )]
    );
    assert_eq!(
        result.http.peer_endpoint,
        Some(PeerEndpoint {
            ip: "198.51.100.9".parse().unwrap(),
            port: 3128,
        })
    );
}

#[tokio::test]
async fn configured_proxy_continues_when_destination_dns_fails() {
    for kind in [ProxyKind::Http, ProxyKind::Socks] {
        let resolver = FakeResolver::default().with_answer("proxy.test", 3128, &["198.51.100.9"]);
        let route = FakeRoute::succeeds();
        let probe = FakeProbe::succeeds();
        let progress = RecordingProgress::default();
        let mut decision = http_proxy("proxy.test");
        decision.kind = kind.clone();
        let proxy = FakeProxy { decision };
        let service = UrlDiagnosticService::new(
            &proxy,
            &resolver,
            &route,
            &probe,
            NoopTrafficDecisionProvider,
        );

        let result = service.run("unresolved.invalid", &progress).await.unwrap();

        assert!(result.resolved_ips.is_empty());
        assert_eq!(
            resolver.calls(),
            vec![
                ("unresolved.invalid".into(), 443),
                ("proxy.test".into(), 3128),
            ]
        );
        assert_eq!(result.evidence[1].source, "dns");
        assert_eq!(result.evidence[1].level, EvidenceLevel::Unknown);
        assert!(
            result.evidence[1]
                .summary
                .contains("无法在本机解析目标域名")
        );
        assert_eq!(
            result
                .evidence
                .iter()
                .map(|evidence| evidence.source.as_str())
                .collect::<Vec<_>>(),
            vec!["proxy", "dns", "route", "http"]
        );
        assert_eq!(
            route.calls(),
            vec!["198.51.100.9".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            probe.calls(),
            vec![(
                "https://unresolved.invalid/".into(),
                kind,
                "198.51.100.9:3128".parse().unwrap(),
            )]
        );
        assert_eq!(
            progress.stages(),
            vec![
                DiagnosticStage::Validating,
                DiagnosticStage::Proxy,
                DiagnosticStage::Dns,
                DiagnosticStage::Route,
                DiagnosticStage::Http,
                DiagnosticStage::Completed,
            ]
        );
    }
}

#[tokio::test]
async fn literal_proxy_ip_skips_proxy_dns_and_route_failure_still_probes() {
    let resolver = FakeResolver::default().with_answer("example.com", 443, &["203.0.113.10"]);
    let route = FakeRoute::fails();
    let probe = FakeProbe::connection_failure();
    let progress = RecordingProgress::default();
    let proxy = FakeProxy {
        decision: http_proxy("127.0.0.1"),
    };
    let service = UrlDiagnosticService::new(
        &proxy,
        &resolver,
        &route,
        &probe,
        NoopTrafficDecisionProvider,
    );

    let result = service.run("example.com", &progress).await.unwrap();

    assert_eq!(resolver.calls(), vec![("example.com".into(), 443)]);
    assert_eq!(route.calls(), vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
    assert!(result.route.is_none());
    assert_eq!(result.http.error_code.as_deref(), Some("connect"));
    assert_eq!(
        probe.calls(),
        vec![(
            "https://example.com/".into(),
            ProxyKind::Http,
            "127.0.0.1:3128".parse().unwrap(),
        )]
    );
    assert_eq!(result.evidence[2].level, EvidenceLevel::Unknown);
    assert_eq!(
        progress.stages(),
        vec![
            DiagnosticStage::Validating,
            DiagnosticStage::Proxy,
            DiagnosticStage::Dns,
            DiagnosticStage::Route,
            DiagnosticStage::Http,
            DiagnosticStage::Completed,
        ]
    );
}

#[tokio::test]
async fn pac_unknown_skips_route_and_web_probe_but_reports_every_stage() {
    let resolver = FakeResolver::default().with_answer("example.com", 443, &["203.0.113.10"]);
    let route = FakeRoute::succeeds();
    let probe = FakeProbe::succeeds();
    let progress = RecordingProgress::default();
    let proxy = FakeProxy {
        decision: unknown_proxy(),
    };
    let service = UrlDiagnosticService::new(
        &proxy,
        &resolver,
        &route,
        &probe,
        NoopTrafficDecisionProvider,
    );

    let result = service.run("example.com", &progress).await.unwrap();

    assert_eq!(resolver.calls(), vec![("example.com".into(), 443)]);
    assert!(route.calls().is_empty());
    assert!(probe.calls().is_empty());
    assert!(result.route.is_none());
    assert_eq!(result.http.error_code.as_deref(), Some("unattempted"));
    assert_eq!(result.evidence[2].level, EvidenceLevel::Unknown);
    assert_eq!(result.evidence[3].level, EvidenceLevel::Unknown);
    assert_eq!(result.conclusion.level, EvidenceLevel::Unknown);
    assert_eq!(
        progress.stages(),
        vec![
            DiagnosticStage::Validating,
            DiagnosticStage::Proxy,
            DiagnosticStage::Dns,
            DiagnosticStage::Route,
            DiagnosticStage::Http,
            DiagnosticStage::Completed,
        ]
    );
}

#[tokio::test]
async fn ipv4_literal_skips_dns_and_is_labeled_as_a_literal() {
    let resolver = FakeResolver::default();
    let route = FakeRoute::succeeds();
    let probe = FakeProbe::succeeds();
    let progress = RecordingProgress::default();
    let proxy = FakeProxy {
        decision: direct_proxy(),
    };
    let service = UrlDiagnosticService::new(
        &proxy,
        &resolver,
        &route,
        &probe,
        NoopTrafficDecisionProvider,
    );

    let result = service
        .run("http://192.0.2.10:8080/", &progress)
        .await
        .unwrap();

    assert!(resolver.calls().is_empty());
    assert_eq!(
        result.resolved_ips,
        vec!["192.0.2.10".parse::<IpAddr>().unwrap()]
    );
    assert!(result.evidence[1].summary.contains("IP 字面量"));
    assert_eq!(
        probe.calls(),
        vec![(
            "http://192.0.2.10:8080/".into(),
            ProxyKind::Direct,
            "192.0.2.10:8080".parse().unwrap(),
        )]
    );
}

#[tokio::test]
async fn ipv6_literal_skips_dns_and_is_labeled_as_a_literal() {
    let resolver = FakeResolver::default();
    let route = FakeRoute::succeeds();
    let probe = FakeProbe::succeeds();
    let progress = RecordingProgress::default();
    let proxy = FakeProxy {
        decision: direct_proxy(),
    };
    let service = UrlDiagnosticService::new(
        &proxy,
        &resolver,
        &route,
        &probe,
        NoopTrafficDecisionProvider,
    );

    let result = service
        .run("http://[2001:db8::10]:8080/", &progress)
        .await
        .unwrap();

    assert!(resolver.calls().is_empty());
    assert_eq!(
        result.resolved_ips,
        vec!["2001:db8::10".parse::<IpAddr>().unwrap()]
    );
    assert!(result.evidence[1].summary.contains("IP 字面量"));
    assert_eq!(
        probe.calls(),
        vec![(
            "http://[2001:db8::10]:8080/".into(),
            ProxyKind::Direct,
            "[2001:db8::10]:8080".parse().unwrap(),
        )]
    );
}

#[tokio::test]
async fn url_probe_is_wrapped_by_traffic_observation_with_normalized_target() {
    let order_log = Arc::new(Mutex::new(Vec::new()));
    let traffic = FakeTrafficProvider::proxy(Arc::clone(&order_log));
    let resolver =
        FakeResolver::default().with_answer("example.com", 443, &["203.0.113.10", "2001:db8::10"]);
    let route = FakeRoute::succeeds();
    let probe = FakeProbe::succeeds().with_order_log(Arc::clone(&order_log));
    let proxy = FakeProxy {
        decision: direct_proxy(),
    };
    let service = UrlDiagnosticService::new(&proxy, &resolver, &route, &probe, traffic.clone());

    let result = service
        .run("https://EXAMPLE.com/path", &RecordingProgress::default())
        .await
        .unwrap();

    assert_eq!(
        &*order_log.lock().unwrap(),
        &["traffic_begin", "http_probe", "traffic_finish"]
    );
    assert_eq!(result.traffic_decision.kind, TrafficDecisionKind::Proxy);
    assert_eq!(probe.calls()[0].0, "https://example.com/path");
    let targets = traffic.targets();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].scheme, TrafficProbeScheme::Https);
    assert_eq!(targets[0].host, "example.com");
    assert_eq!(
        targets[0].resolved_ips,
        vec![
            "203.0.113.10".parse::<IpAddr>().unwrap(),
            "2001:db8::10".parse::<IpAddr>().unwrap(),
        ]
    );
    assert_eq!(targets[0].port, 443);
    assert_eq!(targets[0].protocol, "tcp");
    assert_eq!(targets[0].process_id, std::process::id());
}

#[tokio::test]
async fn scheme_and_explicit_port_are_preserved_in_the_traffic_target() {
    for (input, scheme, port) in [
        ("http://example.com/path", TrafficProbeScheme::Http, 80),
        ("https://example.com/path", TrafficProbeScheme::Https, 443),
        (
            "http://example.com:8080/path",
            TrafficProbeScheme::Http,
            8080,
        ),
        (
            "https://example.com:8443/path",
            TrafficProbeScheme::Https,
            8443,
        ),
    ] {
        let traffic = FakeTrafficProvider::proxy(Arc::new(Mutex::new(Vec::new())));
        let resolver = FakeResolver::default().with_answer("example.com", port, &["203.0.113.10"]);
        let route = FakeRoute::succeeds();
        let probe = FakeProbe::succeeds();
        let proxy = FakeProxy {
            decision: direct_proxy(),
        };
        let service = UrlDiagnosticService::new(&proxy, &resolver, &route, &probe, traffic.clone());

        service
            .run(input, &RecordingProgress::default())
            .await
            .unwrap();

        let targets = traffic.targets();
        let target = &targets[0];
        assert_eq!(target.scheme, scheme, "{input}");
        assert_eq!(target.port, port, "{input}");
    }
}

#[tokio::test]
async fn traffic_target_canonicalizes_domain_ipv4_ipv6_and_idna_hosts() {
    for (input, resolver, expected_host, expected_ip) in [
        (
            "https://EXAMPLE.com/",
            FakeResolver::default().with_answer("example.com", 443, &["203.0.113.10"]),
            "example.com",
            "203.0.113.10",
        ),
        (
            "http://192.0.2.10:8080/",
            FakeResolver::default(),
            "192.0.2.10",
            "192.0.2.10",
        ),
        (
            "https://[2001:0DB8::10]:8443/",
            FakeResolver::default(),
            "2001:db8::10",
            "2001:db8::10",
        ),
        (
            "https://BÜCHER.example/",
            FakeResolver::default().with_answer("xn--bcher-kva.example", 443, &["198.51.100.20"]),
            "xn--bcher-kva.example",
            "198.51.100.20",
        ),
    ] {
        let traffic = FakeTrafficProvider::proxy(Arc::new(Mutex::new(Vec::new())));
        let route = FakeRoute::succeeds();
        let probe = FakeProbe::succeeds();
        let proxy = FakeProxy {
            decision: direct_proxy(),
        };
        let service = UrlDiagnosticService::new(&proxy, &resolver, &route, &probe, traffic.clone());

        service
            .run(input, &RecordingProgress::default())
            .await
            .unwrap();

        let targets = traffic.targets();
        let target = &targets[0];
        assert_eq!(target.host, expected_host, "{input}");
        assert_eq!(
            target.resolved_ips,
            vec![expected_ip.parse::<IpAddr>().unwrap()]
        );
        assert_eq!(target.process_id, std::process::id());
        assert_eq!(target.protocol, "tcp");
    }
}

#[tokio::test]
async fn returned_http_tls_and_network_failures_finish_the_observation() {
    for error_code in ["http", "tls", "connect"] {
        let order_log = Arc::new(Mutex::new(Vec::new()));
        let traffic = FakeTrafficProvider::proxy(Arc::clone(&order_log));
        let resolver = FakeResolver::default().with_answer("example.com", 443, &["203.0.113.10"]);
        let route = FakeRoute::succeeds();
        let probe = FakeProbe::returned_failure(error_code).with_order_log(Arc::clone(&order_log));
        let proxy = FakeProxy {
            decision: direct_proxy(),
        };
        let service = UrlDiagnosticService::new(&proxy, &resolver, &route, &probe, traffic);

        let result = service
            .run("example.com", &RecordingProgress::default())
            .await
            .unwrap();

        assert_eq!(result.http.error_code.as_deref(), Some(error_code));
        assert_eq!(
            &*order_log.lock().unwrap(),
            &["traffic_begin", "http_probe", "traffic_finish"],
            "returned {error_code} observation"
        );
        assert_eq!(result.traffic_decision.kind, TrafficDecisionKind::Proxy);
    }
}

#[tokio::test]
async fn traffic_adapter_begin_and_finish_failures_degrade_without_sensitive_detail() {
    for failure in [TrafficFailure::Begin, TrafficFailure::Finish] {
        let traffic = FakeTrafficProvider::failing(failure);
        let resolver = FakeResolver::default().with_answer("example.com", 443, &["203.0.113.10"]);
        let route = FakeRoute::succeeds();
        let probe = FakeProbe::succeeds().with_order_log(Arc::clone(&traffic.order_log));
        let proxy = FakeProxy {
            decision: direct_proxy(),
        };
        let service = UrlDiagnosticService::new(&proxy, &resolver, &route, &probe, traffic);

        let result = service
            .run("example.com", &RecordingProgress::default())
            .await
            .unwrap();

        assert_generic_unknown(&result.traffic_decision);
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains("must-never-escape"));
        assert!(!serialized.contains("private.sock"));
        assert!(!serialized.contains("unrelated"));
    }
}

#[tokio::test]
async fn traffic_adapter_finish_failure_cancels_the_unfinished_observation() {
    let traffic = FakeTrafficProvider::failing(TrafficFailure::Finish);
    let cancelled = Arc::clone(&traffic.cancelled);
    let resolver = FakeResolver::default().with_answer("example.com", 443, &["203.0.113.10"]);
    let route = FakeRoute::succeeds();
    let probe = FakeProbe::succeeds();
    let proxy = FakeProxy {
        decision: direct_proxy(),
    };
    let service = UrlDiagnosticService::new(&proxy, &resolver, &route, &probe, traffic.clone());

    let result = service
        .run("example.com", &RecordingProgress::default())
        .await
        .unwrap();

    assert_generic_unknown(&result.traffic_decision);
    tokio::time::timeout(Duration::from_secs(1), cancelled.notified())
        .await
        .expect("failed finish did not trigger cancellation cleanup");
    assert_eq!(traffic.cancel_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn web_probe_error_cancels_the_traffic_observation() {
    let traffic = FakeTrafficProvider::proxy(Arc::new(Mutex::new(Vec::new())));
    let cancelled = Arc::clone(&traffic.cancelled);
    let resolver = FakeResolver::default().with_answer("example.com", 443, &["203.0.113.10"]);
    let route = FakeRoute::succeeds();
    let proxy = FakeProxy {
        decision: direct_proxy(),
    };
    let service = UrlDiagnosticService::new(&proxy, &resolver, &route, ErrorProbe, traffic.clone());

    assert!(
        service
            .run("example.com", &RecordingProgress::default())
            .await
            .is_err()
    );
    tokio::time::timeout(Duration::from_secs(1), cancelled.notified())
        .await
        .expect("traffic observation was not cancelled after URL exit");
    assert_eq!(traffic.cancel_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn dropping_the_url_future_cancels_the_traffic_observation() {
    let traffic = FakeTrafficProvider::proxy(Arc::new(Mutex::new(Vec::new())));
    let began = Arc::clone(&traffic.began);
    let cancelled = Arc::clone(&traffic.cancelled);
    let resolver = FakeResolver::default().with_answer("example.com", 443, &["203.0.113.10"]);
    let route = FakeRoute::succeeds();
    let proxy = FakeProxy {
        decision: direct_proxy(),
    };
    let service =
        UrlDiagnosticService::new(&proxy, &resolver, &route, BlockingProbe, traffic.clone());
    let progress = RecordingProgress::default();
    let mut run = Box::pin(service.run("example.com", &progress));

    tokio::select! {
        _ = began.notified() => {}
        result = &mut run => panic!("URL future unexpectedly completed: {result:?}"),
    }
    drop(run);

    tokio::time::timeout(Duration::from_secs(1), service.shutdown())
        .await
        .expect("URL observation worker did not drain during shutdown");
    tokio::time::timeout(Duration::from_secs(1), cancelled.notified())
        .await
        .expect("traffic observation was not cancelled after URL future drop");
    assert_eq!(traffic.cancel_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn service_shutdown_degrades_without_admitting_a_late_observation_worker() {
    let traffic = FakeTrafficProvider::proxy(Arc::new(Mutex::new(Vec::new())));
    let resolver = FakeResolver::default().with_answer("example.com", 443, &["203.0.113.10"]);
    let route = FakeRoute::succeeds();
    let probe = FakeProbe::succeeds();
    let proxy = FakeProxy {
        decision: direct_proxy(),
    };
    let service = UrlDiagnosticService::new(&proxy, &resolver, &route, &probe, traffic.clone());
    service.shutdown().await;

    let result = service
        .run("example.com", &RecordingProgress::default())
        .await
        .unwrap();

    assert_generic_unknown(&result.traffic_decision);
    assert!(traffic.targets().is_empty());
    assert_eq!(traffic.cancel_count.load(Ordering::SeqCst), 0);
}

#[test]
fn dropping_the_url_future_without_a_current_runtime_still_cancels() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let traffic = FakeTrafficProvider::proxy(Arc::new(Mutex::new(Vec::new())));
    let began = Arc::clone(&traffic.began);
    let cancelled = Arc::clone(&traffic.cancelled);
    let resolver = FakeResolver::default().with_answer("example.com", 443, &["203.0.113.10"]);
    let route = FakeRoute::succeeds();
    let proxy = FakeProxy {
        decision: direct_proxy(),
    };
    let runtime_guard = runtime.enter();
    let service =
        UrlDiagnosticService::new(&proxy, &resolver, &route, BlockingProbe, traffic.clone());
    drop(runtime_guard);
    let progress = RecordingProgress::default();
    let mut run = Box::pin(service.run("example.com", &progress));

    runtime.block_on(async {
        tokio::select! {
            _ = began.notified() => {}
            result = &mut run => panic!("URL future unexpectedly completed: {result:?}"),
        }
    });
    drop(run);

    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(1), service.shutdown())
            .await
            .expect("URL observation worker did not drain during shutdown");
    });
    let cancelled_without_current_handle = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(1), cancelled.notified())
            .await
            .is_ok()
    });
    assert!(
        cancelled_without_current_handle,
        "Drop skipped cancellation without a current Tokio handle"
    );
    assert_eq!(traffic.cancel_count.load(Ordering::SeqCst), 1);
}

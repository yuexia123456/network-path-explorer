use async_trait::async_trait;
use futures_util::{Stream, stream};
use network_path_agent::{
    domain::{EvidenceLevel, MihomoRuntime, TrafficDecision, TrafficDecisionKind, TrafficNodeKind},
    error::DiagnosticError,
    ports::{TrafficDecisionProvider, TrafficProbeScheme, TrafficProbeTarget},
    traffic::mihomo::{
        MihomoConnectionEvent, MihomoEvent, MihomoEventStream, MihomoLogEvent, MihomoProxy,
        MihomoTrafficDecisionProvider, MihomoTransport,
    },
};
use serde::Deserialize;
use std::{
    collections::{HashMap, VecDeque},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use time::{Duration as TimeDuration, OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::Notify;

#[derive(Clone)]
struct FixtureTransport {
    runtime: MihomoRuntime,
    proxies: HashMap<String, MihomoProxy>,
    connection_events: Vec<MihomoEvent>,
    log_events: Vec<MihomoEvent>,
    disconnect_connection_with_error: bool,
    disconnect_log_with_error: bool,
    pending_stream_drops: Option<Arc<AtomicUsize>>,
}

#[async_trait]
impl MihomoTransport for FixtureTransport {
    async fn runtime(&self) -> Result<MihomoRuntime, DiagnosticError> {
        Ok(self.runtime.clone())
    }

    async fn proxies(&self) -> Result<HashMap<String, MihomoProxy>, DiagnosticError> {
        Ok(self.proxies.clone())
    }

    async fn connection_stream(
        &self,
        _interval: Duration,
    ) -> Result<MihomoEventStream, DiagnosticError> {
        if let Some(drops) = &self.pending_stream_drops {
            return Ok(Box::pin(DropTrackedPendingStream {
                drops: Arc::clone(drops),
            }));
        }
        let mut items = self
            .connection_events
            .clone()
            .into_iter()
            .map(Ok)
            .collect::<Vec<_>>();
        if self.disconnect_connection_with_error {
            items.push(Err(DiagnosticError::System(
                "private connection stream payload".into(),
            )));
        }
        Ok(Box::pin(stream::iter(items)))
    }

    async fn log_stream(&self) -> Result<MihomoEventStream, DiagnosticError> {
        if let Some(drops) = &self.pending_stream_drops {
            return Ok(Box::pin(DropTrackedPendingStream {
                drops: Arc::clone(drops),
            }));
        }
        let mut items = self
            .log_events
            .clone()
            .into_iter()
            .map(Ok)
            .collect::<Vec<_>>();
        if self.disconnect_log_with_error {
            items.push(Err(DiagnosticError::System(
                "/Users/private/Other.app private-other-app.invalid".into(),
            )));
        }
        Ok(Box::pin(stream::iter(items)))
    }
}

struct DropTrackedPendingStream {
    drops: Arc<AtomicUsize>,
}

#[derive(Clone)]
struct GateDropControl {
    drop_started: Arc<Notify>,
    started: Arc<AtomicUsize>,
    release: Arc<AtomicBool>,
}

struct GateDropTransport {
    control: GateDropControl,
}

struct GateDropPendingStream {
    control: GateDropControl,
}

struct ReleaseGateOnDrop(Arc<AtomicBool>);

impl Drop for ReleaseGateOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[async_trait]
impl MihomoTransport for GateDropTransport {
    async fn runtime(&self) -> Result<MihomoRuntime, DiagnosticError> {
        Ok(MihomoRuntime {
            available: true,
            mode: Some("rule".into()),
            tun_enabled: Some(true),
            controller: Some("fixture".into()),
        })
    }

    async fn proxies(&self) -> Result<HashMap<String, MihomoProxy>, DiagnosticError> {
        Ok(HashMap::new())
    }

    async fn connection_stream(
        &self,
        _interval: Duration,
    ) -> Result<MihomoEventStream, DiagnosticError> {
        Ok(Box::pin(GateDropPendingStream {
            control: self.control.clone(),
        }))
    }

    async fn log_stream(&self) -> Result<MihomoEventStream, DiagnosticError> {
        Ok(Box::pin(stream::empty()))
    }
}

struct SetupErrorTransport;

struct BurstTransport {
    connection_events: Vec<MihomoEvent>,
    consumed: Arc<Notify>,
}

struct BurstStream {
    events: VecDeque<MihomoEvent>,
    consumed: Arc<Notify>,
    notified: bool,
}

#[async_trait]
impl MihomoTransport for BurstTransport {
    async fn runtime(&self) -> Result<MihomoRuntime, DiagnosticError> {
        Ok(MihomoRuntime {
            available: true,
            mode: Some("rule".into()),
            tun_enabled: Some(true),
            controller: Some("manual_loopback".into()),
        })
    }

    async fn proxies(&self) -> Result<HashMap<String, MihomoProxy>, DiagnosticError> {
        Ok(HashMap::new())
    }

    async fn connection_stream(
        &self,
        _interval: Duration,
    ) -> Result<MihomoEventStream, DiagnosticError> {
        Ok(Box::pin(BurstStream {
            events: self.connection_events.clone().into(),
            consumed: Arc::clone(&self.consumed),
            notified: false,
        }))
    }

    async fn log_stream(&self) -> Result<MihomoEventStream, DiagnosticError> {
        Ok(Box::pin(stream::empty()))
    }
}

impl Stream for BurstStream {
    type Item = Result<MihomoEvent, DiagnosticError>;

    fn poll_next(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(Some(Ok(event)));
        }
        if !self.notified {
            self.notified = true;
            self.consumed.notify_one();
        }
        Poll::Pending
    }
}

#[async_trait]
impl MihomoTransport for SetupErrorTransport {
    async fn runtime(&self) -> Result<MihomoRuntime, DiagnosticError> {
        Ok(MihomoRuntime {
            available: true,
            mode: Some("rule".into()),
            tun_enabled: Some(true),
            controller: Some("manual_loopback".into()),
        })
    }

    async fn proxies(&self) -> Result<HashMap<String, MihomoProxy>, DiagnosticError> {
        Ok(HashMap::new())
    }

    async fn connection_stream(
        &self,
        _interval: Duration,
    ) -> Result<MihomoEventStream, DiagnosticError> {
        Err(DiagnosticError::System(
            "private-target.invalid /Users/private/Other.app process=other".into(),
        ))
    }

    async fn log_stream(&self) -> Result<MihomoEventStream, DiagnosticError> {
        Err(DiagnosticError::System("private log payload".into()))
    }
}

impl Stream for DropTrackedPendingStream {
    type Item = Result<MihomoEvent, DiagnosticError>;

    fn poll_next(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Pending
    }
}

impl Drop for DropTrackedPendingStream {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl Stream for GateDropPendingStream {
    type Item = Result<MihomoEvent, DiagnosticError>;

    fn poll_next(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Pending
    }
}

impl Drop for GateDropPendingStream {
    fn drop(&mut self) {
        if self.control.started.fetch_add(1, Ordering::SeqCst) == 0 {
            self.control.drop_started.notify_one();
        }
        while !self.control.release.load(Ordering::SeqCst) {
            std::hint::spin_loop();
        }
    }
}

fn connection_event(json: &str) -> MihomoEvent {
    let window_time = (OffsetDateTime::now_utc() + TimeDuration::seconds(1))
        .format(&Rfc3339)
        .unwrap();
    let json = json.replace("2099-08-23T03:00:00Z", &window_time);
    let fixture = serde_json::from_str::<ConnectionEventFixture>(&json).unwrap();
    MihomoEvent::Connection(MihomoConnectionEvent {
        download_total: fixture.download_total,
        upload_total: fixture.upload_total,
        connections: fixture.connections,
    })
}

fn log_event(json: &str) -> MihomoEvent {
    MihomoEvent::Log(serde_json::from_str::<MihomoLogEvent>(json).unwrap())
}

#[derive(Deserialize)]
struct ConnectionEventFixture {
    #[serde(rename = "downloadTotal")]
    download_total: u64,
    #[serde(rename = "uploadTotal")]
    upload_total: u64,
    connections: Vec<serde_json::Value>,
}

fn proxy_map(json: &str) -> HashMap<String, MihomoProxy> {
    serde_json::from_str::<ProxyMapFixture>(json)
        .unwrap()
        .proxies
        .into_iter()
        .map(|(key, fixture)| {
            let delay_ms = fixture.history.last().map(|entry| entry.delay);
            (
                key,
                MihomoProxy {
                    name: fixture.name,
                    kind: fixture.kind,
                    now: fixture.now,
                    all: fixture.all,
                    alive: fixture.alive,
                    delay_ms,
                    provider_name: fixture.provider_name,
                    dialer_proxy: fixture.dialer_proxy,
                },
            )
        })
        .collect()
}

#[derive(Deserialize)]
struct ProxyMapFixture {
    proxies: HashMap<String, ProxyFixture>,
}

#[derive(Deserialize)]
struct ProxyFixture {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    now: Option<String>,
    #[serde(default)]
    all: Vec<String>,
    #[serde(default)]
    alive: Option<bool>,
    #[serde(default)]
    history: Vec<DelayFixture>,
    #[serde(default, rename = "provider-name")]
    provider_name: Option<String>,
    #[serde(default, rename = "dialer-proxy")]
    dialer_proxy: Option<String>,
}

#[derive(Deserialize)]
struct DelayFixture {
    delay: u16,
}

fn proxy(name: &str, kind: &str, now: Option<&str>) -> MihomoProxy {
    MihomoProxy {
        name: name.into(),
        kind: kind.into(),
        now: now.map(str::to_owned),
        all: Vec::new(),
        alive: Some(true),
        delay_ms: Some(23),
        provider_name: None,
        dialer_proxy: None,
    }
}

fn provider_with(
    connection_events: Vec<MihomoEvent>,
    log_events: Vec<MihomoEvent>,
    proxies: HashMap<String, MihomoProxy>,
) -> MihomoTrafficDecisionProvider {
    MihomoTrafficDecisionProvider::new(Arc::new(FixtureTransport {
        runtime: MihomoRuntime {
            available: true,
            mode: Some("rule".into()),
            tun_enabled: Some(true),
            controller: Some("manual_loopback".into()),
        },
        proxies,
        connection_events,
        log_events,
        disconnect_connection_with_error: false,
        disconnect_log_with_error: false,
        pending_stream_drops: None,
    }))
}

fn provider_with_stream_errors() -> MihomoTrafficDecisionProvider {
    MihomoTrafficDecisionProvider::new(Arc::new(FixtureTransport {
        runtime: MihomoRuntime {
            available: true,
            mode: Some("rule".into()),
            tun_enabled: Some(true),
            controller: Some("manual_loopback".into()),
        },
        proxies: HashMap::new(),
        connection_events: Vec::new(),
        log_events: Vec::new(),
        disconnect_connection_with_error: true,
        disconnect_log_with_error: true,
        pending_stream_drops: None,
    }))
}

fn provider_with_pending_streams() -> (MihomoTrafficDecisionProvider, Arc<AtomicUsize>) {
    let drops = Arc::new(AtomicUsize::new(0));
    let provider = MihomoTrafficDecisionProvider::new(Arc::new(FixtureTransport {
        runtime: MihomoRuntime {
            available: true,
            mode: Some("rule".into()),
            tun_enabled: Some(true),
            controller: Some("manual_loopback".into()),
        },
        proxies: HashMap::new(),
        connection_events: Vec::new(),
        log_events: Vec::new(),
        disconnect_connection_with_error: false,
        disconnect_log_with_error: false,
        pending_stream_drops: Some(Arc::clone(&drops)),
    }));
    (provider, drops)
}

fn target(host: &str, port: u16) -> TrafficProbeTarget {
    TrafficProbeTarget::new(
        TrafficProbeScheme::Https,
        host,
        port,
        vec!["93.184.216.34".parse().unwrap()],
        4242,
    )
}

fn browser_target(host: &str, port: u16) -> TrafficProbeTarget {
    TrafficProbeTarget::for_browser(
        TrafficProbeScheme::Https,
        host,
        port,
        vec!["93.184.216.34".parse().unwrap()],
    )
}

fn browser_connection(id: &str, chains: &[&str], rule: &str, payload: &str) -> MihomoEvent {
    browser_connection_with_paths(id, chains, rule, payload, &[], &[])
}

fn browser_connection_with_paths(
    id: &str,
    chains: &[&str],
    rule: &str,
    payload: &str,
    provider_chains: &[&str],
    dialer_proxy: &[&str],
) -> MihomoEvent {
    connection_event(
        &serde_json::json!({
            "downloadTotal": 0,
            "uploadTotal": 0,
            "connections": [{
                "id": id,
                "metadata": {
                    "network": "tcp",
                    "host": "example.com",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": "443",
                    "processID": "1101"
                },
                "start": "2099-08-23T03:00:00Z",
                "chains": chains,
                "providerChains": provider_chains,
                "dialerProxy": dialer_proxy,
                "rule": rule,
                "rulePayload": payload
            }]
        })
        .to_string(),
    )
}

fn browser_reject(rule: &str, payload: &str, terminal: &str) -> MihomoEvent {
    log_event(&format!(
        r#"{{
            "type": "info",
            "payload": "[TCP] 127.0.0.1:51247 --> example.com:443 match {rule}({payload}) using {terminal}"
        }}"#
    ))
}

async fn observe(
    provider: &MihomoTrafficDecisionProvider,
    target: TrafficProbeTarget,
) -> TrafficDecision {
    let id = provider.begin(&target).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), provider.finish(id))
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn duration_aware_observations_survive_quick_and_full_windows_beyond_five_seconds() {
    for lifetime in [Duration::from_secs(15), Duration::from_secs(40)] {
        let (provider, drops) = provider_with_pending_streams();
        let id = provider
            .begin_with_lifetime(&browser_target("example.com", 443), lifetime)
            .await
            .unwrap();
        let finish = tokio::spawn({
            let provider = provider.clone();
            async move { provider.finish(id).await.unwrap() }
        });

        tokio::time::advance(Duration::from_secs(6)).await;
        tokio::task::yield_now().await;
        assert!(
            !finish.is_finished(),
            "the observation must remain owned after the legacy five-second window"
        );

        tokio::time::advance(lifetime - Duration::from_secs(6)).await;
        let result = finish.await.unwrap();
        assert_eq!(result.kind, TrafficDecisionKind::Unknown);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn browser_speed_connections_aggregate_consistent_processes_and_degrade_on_conflicts() {
    let consistent = connection_event(
        r#"{
            "downloadTotal": 0,
            "uploadTotal": 0,
            "connections": [
                {
                    "id": "browser-process-a",
                    "metadata": {
                        "network": "tcp",
                        "host": "example.com",
                        "destinationIP": "93.184.216.34",
                        "destinationPort": "443",
                        "processID": "1101"
                    },
                    "start": "2099-08-23T03:00:00Z",
                    "chains": ["浏览器节点", "MATCH"],
                    "providerChains": [],
                    "rule": "MATCH",
                    "rulePayload": ""
                },
                {
                    "id": "browser-process-b",
                    "metadata": {
                        "network": "tcp",
                        "host": "example.com",
                        "destinationIP": "93.184.216.34",
                        "destinationPort": "443",
                        "processID": "1102"
                    },
                    "start": "2099-08-23T03:00:00Z",
                    "chains": ["浏览器节点", "MATCH"],
                    "providerChains": [],
                    "rule": "MATCH",
                    "rulePayload": ""
                }
            ]
        }"#,
    );
    let result = observe(
        &provider_with(vec![consistent], Vec::new(), HashMap::new()),
        browser_target("example.com", 443),
    )
    .await;
    assert_eq!(result.kind, TrafficDecisionKind::Proxy);
    assert_eq!(names(&result), vec!["MATCH", "浏览器节点"]);
    assert!(
        result
            .evidence
            .iter()
            .any(|evidence| evidence.summary.contains("multiple"))
    );

    let conflicting = connection_event(
        r#"{
            "downloadTotal": 0,
            "uploadTotal": 0,
            "connections": [
                {
                    "id": "browser-direct",
                    "metadata": {
                        "network": "tcp",
                        "host": "example.com",
                        "destinationIP": "93.184.216.34",
                        "destinationPort": "443",
                        "processID": "1101"
                    },
                    "start": "2099-08-23T03:00:00Z",
                    "chains": ["DIRECT"],
                    "providerChains": [],
                    "rule": "MATCH",
                    "rulePayload": ""
                },
                {
                    "id": "browser-proxy",
                    "metadata": {
                        "network": "tcp",
                        "host": "example.com",
                        "destinationIP": "93.184.216.34",
                        "destinationPort": "443",
                        "processID": "1102"
                    },
                    "start": "2099-08-23T03:00:00Z",
                    "chains": ["代理节点", "MATCH"],
                    "providerChains": [],
                    "rule": "MATCH",
                    "rulePayload": ""
                }
            ]
        }"#,
    );
    let result = observe(
        &provider_with(vec![conflicting], Vec::new(), HashMap::new()),
        browser_target("example.com", 443),
    )
    .await;
    assert_eq!(result.kind, TrafficDecisionKind::Unknown);
    assert!(result.chain.is_empty());
}

#[tokio::test]
async fn browser_connection_and_reject_conflicts_degrade_to_unknown_without_payloads() {
    for (chains, expected_kind) in [
        (vec!["浏览器节点", "MATCH"], TrafficDecisionKind::Unknown),
        (vec!["DIRECT"], TrafficDecisionKind::Unknown),
    ] {
        let connection = browser_connection("browser-terminal", &chains, "MATCH", "");
        let reject = browser_reject("SecretRule", "private-payload", "REJECT");
        let result = observe(
            &provider_with(vec![connection, reject], Vec::new(), HashMap::new()),
            browser_target("example.com", 443),
        )
        .await;

        assert_eq!(result.kind, expected_kind);
        assert!(result.chain.is_empty());
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains("SecretRule"));
        assert!(!serialized.contains("private-payload"));
    }
}

#[tokio::test]
async fn browser_connection_and_matching_reject_log_share_a_sanitized_fingerprint() {
    for terminal in ["REJECT", "REJECT-DROP"] {
        for payload in ["advertising", ""] {
            for reversed in [false, true] {
                let connection =
                    browser_connection("browser-reject", &[terminal], "RuleSet", payload);
                let reject = browser_reject("RuleSet", payload, terminal);
                let events = if reversed {
                    vec![reject, connection]
                } else {
                    vec![connection, reject]
                };
                let result = observe(
                    &provider_with(events, Vec::new(), HashMap::new()),
                    browser_target("example.com", 443),
                )
                .await;

                assert_eq!(result.kind, TrafficDecisionKind::Reject);
                assert!(
                    result
                        .evidence
                        .iter()
                        .any(|evidence| evidence.summary.contains("2"))
                );
            }
        }
    }
}

#[tokio::test]
async fn browser_grouped_reject_connections_require_the_same_full_chain() {
    for events in [
        vec![
            browser_connection_with_paths(
                "reject-group-a",
                &["REJECT", "Group A"],
                "RuleSet",
                "advertising",
                &["Provider A"],
                &["Dialer A"],
            ),
            browser_connection_with_paths(
                "reject-group-b",
                &["REJECT", "Group B"],
                "RuleSet",
                "advertising",
                &["Provider B"],
                &["Dialer B"],
            ),
        ],
        vec![
            browser_connection_with_paths(
                "reject-group-b",
                &["REJECT", "Group B"],
                "RuleSet",
                "advertising",
                &["Provider B"],
                &["Dialer B"],
            ),
            browser_connection_with_paths(
                "reject-group-a",
                &["REJECT", "Group A"],
                "RuleSet",
                "advertising",
                &["Provider A"],
                &["Dialer A"],
            ),
        ],
    ] {
        let result = observe(
            &provider_with(events, Vec::new(), HashMap::new()),
            browser_target("example.com", 443),
        )
        .await;

        assert_eq!(result.kind, TrafficDecisionKind::Unknown);
        assert!(result.chain.is_empty());
        assert!(!serde_json::to_string(&result).unwrap().contains("Group"));
    }
}

#[tokio::test]
async fn browser_terminal_logs_are_partial_and_preserve_a_grouped_connection_chain() {
    for terminal in ["REJECT", "REJECT-DROP"] {
        for events in [
            vec![
                browser_connection_with_paths(
                    "grouped-reject",
                    &[terminal, "Group A"],
                    "RuleSet",
                    "advertising",
                    &["Provider A"],
                    &["Dialer A"],
                ),
                browser_reject("RuleSet", "advertising", terminal),
            ],
            vec![
                browser_reject("RuleSet", "advertising", terminal),
                browser_connection_with_paths(
                    "grouped-reject",
                    &[terminal, "Group A"],
                    "RuleSet",
                    "advertising",
                    &["Provider A"],
                    &["Dialer A"],
                ),
            ],
        ] {
            let result = observe(
                &provider_with(events, Vec::new(), HashMap::new()),
                browser_target("example.com", 443),
            )
            .await;

            assert_eq!(result.kind, TrafficDecisionKind::Reject);
            assert!(names(&result).contains(&"Group A"));
            assert!(names(&result).contains(&"Provider A"));
            assert!(names(&result).contains(&"Dialer A"));
        }
    }
}

#[tokio::test]
async fn browser_user_defined_chain_names_keep_case_sensitive_identity() {
    let result = observe(
        &provider_with(
            vec![
                browser_connection("upper-group", &["US", "MATCH"], "MATCH", ""),
                browser_connection("lower-group", &["us", "MATCH"], "MATCH", ""),
            ],
            Vec::new(),
            HashMap::new(),
        ),
        browser_target("example.com", 443),
    )
    .await;

    assert_eq!(result.kind, TrafficDecisionKind::Unknown);
    assert!(result.chain.is_empty());
}

#[tokio::test]
async fn browser_reserved_looking_proxy_names_use_exact_proxy_map_identity() {
    for (upper, lower, upper_chain, lower_chain) in [
        (
            "PROXY",
            "proxy",
            vec!["Leaf", "PROXY", "MATCH"],
            vec!["Leaf", "proxy", "MATCH"],
        ),
        (
            "GLOBAL",
            "global",
            vec!["Leaf", "GLOBAL", "MATCH"],
            vec!["Leaf", "global", "MATCH"],
        ),
        (
            "MATCH",
            "match",
            vec!["Leaf", "MATCH"],
            vec!["Leaf", "match"],
        ),
    ] {
        for reversed in [false, true] {
            let first = browser_connection(
                "reserved-group-a",
                &upper_chain,
                "NETWORK",
                "private-payload",
            );
            let second = browser_connection(
                "reserved-group-b",
                &lower_chain,
                "NETWORK",
                "private-payload",
            );
            let events = if reversed {
                vec![second, first]
            } else {
                vec![first, second]
            };
            let proxies = HashMap::from([
                (upper.into(), proxy(upper, "Selector", Some("Leaf"))),
                (lower.into(), proxy(lower, "Selector", Some("Leaf"))),
                ("Leaf".into(), proxy("Leaf", "Shadowsocks", None)),
            ]);
            let result = observe(
                &provider_with(events, Vec::new(), proxies),
                browser_target("example.com", 443),
            )
            .await;

            assert_eq!(result.kind, TrafficDecisionKind::Unknown);
            assert!(result.chain.is_empty());
            let serialized = serde_json::to_string(&result).unwrap();
            assert!(!serialized.contains("private-payload"));
        }
    }
}

#[tokio::test]
async fn browser_builtin_sentinel_case_is_normalized_before_rendering() {
    for (lower, upper) in [("proxy", "PROXY"), ("global", "GLOBAL"), ("match", "MATCH")] {
        let mut rendered = Vec::new();
        for reversed in [false, true] {
            let first = browser_connection(
                "builtin-sentinel-a",
                &[lower, "MATCH"],
                "network",
                "private-payload",
            );
            let second = browser_connection(
                "builtin-sentinel-b",
                &[upper, "match"],
                "NETWORK",
                "private-payload",
            );
            let events = if reversed {
                vec![second, first]
            } else {
                vec![first, second]
            };
            let result = observe(
                &provider_with(events, Vec::new(), HashMap::new()),
                browser_target("example.com", 443),
            )
            .await;

            assert_eq!(result.kind, TrafficDecisionKind::Proxy);
            rendered.push(serde_json::to_string(&result).unwrap());
        }
        assert_eq!(rendered[0], rendered[1]);
        assert!(rendered[0].contains(upper));
    }
}

#[tokio::test]
async fn browser_reject_actions_are_part_of_the_partial_fingerprint() {
    for reversed in [false, true] {
        let reject = browser_reject("RuleSet", "private-payload", "REJECT");
        let reject_drop = browser_reject("RuleSet", "private-payload", "REJECT-DROP");
        let events = if reversed {
            vec![reject_drop, reject]
        } else {
            vec![reject, reject_drop]
        };
        let result = observe(
            &provider_with(events, Vec::new(), HashMap::new()),
            browser_target("example.com", 443),
        )
        .await;

        assert_eq!(result.kind, TrafficDecisionKind::Unknown);
        assert!(result.chain.is_empty());
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains("RuleSet"));
        assert!(!serialized.contains("private-payload"));
    }
}

#[tokio::test]
async fn browser_unlisted_rule_types_match_case_insensitively_and_render_deterministically() {
    let mut rendered = Vec::new();
    for reversed in [false, true] {
        let upper = browser_reject("NETWORK", "private-payload", "REJECT");
        let lower = browser_reject("network", "private-payload", "REJECT");
        let events = if reversed {
            vec![lower, upper]
        } else {
            vec![upper, lower]
        };
        let result = observe(
            &provider_with(events, Vec::new(), HashMap::new()),
            browser_target("example.com", 443),
        )
        .await;

        assert_eq!(result.kind, TrafficDecisionKind::Reject);
        assert_eq!(
            result.rule.as_ref().unwrap().payload.as_deref(),
            Some("private-payload")
        );
        rendered.push(serde_json::to_string(&result).unwrap());
    }
    assert_eq!(rendered[0], rendered[1]);
}

#[tokio::test]
async fn browser_matching_full_chains_merge_optional_rule_evidence_deterministically() {
    let mut rendered = Vec::new();
    for reversed in [false, true] {
        let without_rule =
            browser_connection("optional-rule-missing", &["浏览器节点", "MATCH"], "", "");
        let with_rule = browser_connection(
            "optional-rule-present",
            &["浏览器节点", "MATCH"],
            "NETWORK",
            "private-payload",
        );
        let events = if reversed {
            vec![with_rule, without_rule]
        } else {
            vec![without_rule, with_rule]
        };
        let result = observe(
            &provider_with(events, Vec::new(), HashMap::new()),
            browser_target("example.com", 443),
        )
        .await;

        assert_eq!(result.kind, TrafficDecisionKind::Proxy);
        let rule = result.rule.as_ref().expect("present rule evidence");
        assert_eq!(rule.rule_type, "NETWORK");
        assert_eq!(rule.payload.as_deref(), Some("private-payload"));
        rendered.push(serde_json::to_string(&result).unwrap());
    }
    assert_eq!(rendered[0], rendered[1]);
}

#[tokio::test]
async fn browser_matching_reject_logs_merge_optional_payload_deterministically() {
    let mut rendered = Vec::new();
    for reversed in [false, true] {
        let without_payload = browser_reject("NETWORK", "", "REJECT");
        let with_payload = browser_reject("NETWORK", "private-payload", "REJECT");
        let events = if reversed {
            vec![with_payload, without_payload]
        } else {
            vec![without_payload, with_payload]
        };
        let result = observe(
            &provider_with(events, Vec::new(), HashMap::new()),
            browser_target("example.com", 443),
        )
        .await;

        assert_eq!(result.kind, TrafficDecisionKind::Reject);
        let rule = result.rule.as_ref().expect("reject rule evidence");
        assert_eq!(rule.rule_type, "NETWORK");
        assert_eq!(rule.payload.as_deref(), Some("private-payload"));
        rendered.push(serde_json::to_string(&result).unwrap());
    }
    assert_eq!(rendered[0], rendered[1]);
}

#[tokio::test]
async fn browser_incomplete_connections_cannot_confirm_proxy_and_empty_rules_are_absent() {
    let incomplete = observe(
        &provider_with(
            vec![browser_connection("incomplete", &[], "", "")],
            Vec::new(),
            HashMap::new(),
        ),
        browser_target("example.com", 443),
    )
    .await;
    assert_eq!(incomplete.kind, TrafficDecisionKind::Unknown);
    assert!(incomplete.rule.is_none());

    let direct = observe(
        &provider_with(
            vec![browser_connection("direct", &["DIRECT"], "", "")],
            Vec::new(),
            HashMap::new(),
        ),
        browser_target("example.com", 443),
    )
    .await;
    assert_eq!(direct.kind, TrafficDecisionKind::Direct);
    assert!(direct.rule.is_none());

    let proxy = observe(
        &provider_with(
            vec![browser_connection("proxy", &["节点甲", "MATCH"], "", "")],
            Vec::new(),
            HashMap::new(),
        ),
        browser_target("example.com", 443),
    )
    .await;
    assert_eq!(proxy.kind, TrafficDecisionKind::Proxy);
    assert!(proxy.rule.is_none());
}

#[tokio::test]
async fn browser_incomplete_snapshot_then_complete_snapshot_is_deterministic() {
    let incomplete = browser_connection("same-connection", &[], "", "");
    let complete = browser_connection("same-connection", &["节点甲", "MATCH"], "MATCH", "");
    for events in [
        vec![incomplete.clone(), complete.clone()],
        vec![complete, incomplete],
    ] {
        let result = observe(
            &provider_with(events, Vec::new(), HashMap::new()),
            browser_target("example.com", 443),
        )
        .await;

        assert_eq!(result.kind, TrafficDecisionKind::Proxy);
        assert_eq!(names(&result), vec!["MATCH", "节点甲"]);
    }
}

fn burst_provider(
    events: Vec<MihomoEvent>,
    consumed: Arc<Notify>,
) -> MihomoTrafficDecisionProvider {
    MihomoTrafficDecisionProvider::new(Arc::new(BurstTransport {
        connection_events: events,
        consumed,
    }))
}

fn burst_conflict_events() -> Vec<MihomoEvent> {
    let duplicate = browser_connection("early-proxy", &["节点甲", "MATCH"], "MATCH", "");
    let mut events = vec![duplicate; 128];
    events.push(browser_connection("late-direct", &["DIRECT"], "MATCH", ""));
    events
}

async fn observe_burst(lifetime: Duration) -> TrafficDecision {
    observe_burst_events(burst_conflict_events(), lifetime).await
}

async fn observe_burst_events(events: Vec<MihomoEvent>, lifetime: Duration) -> TrafficDecision {
    let consumed = Arc::new(Notify::new());
    let provider = burst_provider(events, Arc::clone(&consumed));
    let id = provider
        .begin_with_lifetime(&browser_target("example.com", 443), lifetime)
        .await
        .unwrap();
    consumed.notified().await;
    provider.finish(id).await.unwrap()
}

#[tokio::test]
async fn browser_immediate_burst_does_not_silently_drop_a_late_conflict() {
    let result = observe_burst(Duration::from_secs(15)).await;

    assert_eq!(result.kind, TrafficDecisionKind::Unknown);
    assert!(result.chain.is_empty());
}

#[tokio::test(start_paused = true)]
async fn browser_quick_and_full_bursts_keep_late_conflicts_visible() {
    for lifetime in [Duration::from_secs(15), Duration::from_secs(40)] {
        let result = observe_burst(lifetime).await;

        assert_eq!(result.kind, TrafficDecisionKind::Unknown);
        assert!(result.chain.is_empty());
    }
}

#[tokio::test]
async fn browser_unique_evidence_overflow_is_explicitly_unknown() {
    let events = (0..129)
        .map(|index| {
            browser_connection(
                &format!("unique-browser-connection-{index}"),
                &["节点甲", "MATCH"],
                "MATCH",
                "",
            )
        })
        .collect();
    let result = observe_burst_events(events, Duration::from_secs(40)).await;

    assert_eq!(result.kind, TrafficDecisionKind::Unknown);
    assert!(result.chain.is_empty());
}

#[tokio::test]
async fn browser_repeated_identical_rejects_confirm_reject_but_distinct_rejects_degrade() {
    let repeated = observe(
        &provider_with(
            vec![
                browser_reject("RuleSet", "advertising", "REJECT"),
                browser_reject("RuleSet", "advertising", "REJECT"),
            ],
            Vec::new(),
            HashMap::new(),
        ),
        browser_target("example.com", 443),
    )
    .await;
    assert_eq!(repeated.kind, TrafficDecisionKind::Reject);
    assert!(
        repeated
            .evidence
            .iter()
            .any(|evidence| evidence.summary.contains("2"))
    );

    let distinct = observe(
        &provider_with(
            vec![
                browser_reject("RuleSet", "advertising", "REJECT"),
                browser_reject("Domain", "tracking", "REJECT-DROP"),
            ],
            Vec::new(),
            HashMap::new(),
        ),
        browser_target("example.com", 443),
    )
    .await;
    assert_eq!(distinct.kind, TrafficDecisionKind::Unknown);
    assert!(distinct.chain.is_empty());
    let serialized = serde_json::to_string(&distinct).unwrap();
    assert!(!serialized.contains("RuleSet"));
    assert!(!serialized.contains("advertising"));
    assert!(!serialized.contains("Domain"));
    assert!(!serialized.contains("tracking"));
}

#[tokio::test]
async fn browser_repeated_snapshots_of_one_connection_keep_singular_wording() {
    let snapshot = browser_connection("one-browser-connection", &["节点甲", "MATCH"], "MATCH", "");
    let result = observe(
        &provider_with(vec![snapshot.clone(), snapshot], Vec::new(), HashMap::new()),
        browser_target("example.com", 443),
    )
    .await;

    assert_eq!(result.kind, TrafficDecisionKind::Proxy);
    assert!(
        result
            .evidence
            .iter()
            .all(|evidence| !evidence.summary.contains("multiple"))
    );
}

#[tokio::test]
async fn browser_single_connection_and_single_reject_keep_singular_evidence_wording() {
    let connection = observe(
        &provider_with(
            vec![browser_connection(
                "one-browser-connection",
                &["节点甲", "MATCH"],
                "MATCH",
                "",
            )],
            Vec::new(),
            HashMap::new(),
        ),
        browser_target("example.com", 443),
    )
    .await;
    assert_eq!(connection.kind, TrafficDecisionKind::Proxy);
    assert!(
        connection
            .evidence
            .iter()
            .all(|evidence| !evidence.summary.contains("multiple"))
    );

    let reject = observe(
        &provider_with(
            vec![browser_reject("RuleSet", "advertising", "REJECT")],
            Vec::new(),
            HashMap::new(),
        ),
        browser_target("example.com", 443),
    )
    .await;
    assert_eq!(reject.kind, TrafficDecisionKind::Reject);
    assert!(
        reject
            .evidence
            .iter()
            .all(|evidence| !evidence.summary.contains("multiple"))
    );
}

#[tokio::test]
async fn cancel_awaits_pending_stream_drops_before_returning() {
    let (provider, stream_drops) = provider_with_pending_streams();
    let id = provider.begin(&target("example.com", 443)).await.unwrap();

    provider.cancel(id).await;

    assert_eq!(stream_drops.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finish_awaits_pending_stream_drops_before_returning() {
    let control = GateDropControl {
        drop_started: Arc::new(Notify::new()),
        started: Arc::new(AtomicUsize::new(0)),
        release: Arc::new(AtomicBool::new(false)),
    };
    let provider = MihomoTrafficDecisionProvider::new(Arc::new(GateDropTransport {
        control: control.clone(),
    }));
    let _release_gate = ReleaseGateOnDrop(Arc::clone(&control.release));
    let id = provider
        .begin_with_lifetime(&target("example.com", 443), Duration::ZERO)
        .await
        .unwrap();
    let finish = tokio::spawn({
        let provider = provider.clone();
        async move { provider.finish(id).await.unwrap() }
    });

    tokio::task::yield_now().await;
    let drop_started = control.drop_started.notified();
    tokio::pin!(drop_started);
    drop_started.as_mut().enable();
    drop_started.await;
    tokio::task::yield_now().await;
    assert!(!finish.is_finished());

    control.release.store(true, Ordering::SeqCst);
    let result = finish.await.unwrap();

    assert_eq!(result.kind, TrafficDecisionKind::Unknown);
    assert_eq!(control.started.load(Ordering::SeqCst), 1);
}

fn names(decision: &TrafficDecision) -> Vec<&str> {
    decision
        .chain
        .iter()
        .map(|node| node.name.as_str())
        .collect()
}

fn levels(decision: &TrafficDecision) -> Vec<EvidenceLevel> {
    decision.chain.iter().map(|node| node.level).collect()
}

#[tokio::test]
async fn matched_connection_normalizes_rule_group_node_and_explicit_dialer_chain() {
    let connection = connection_event(
        r#"{
            "downloadTotal": 11,
            "uploadTotal": 7,
            "connections": [{
                "id": "target-connection",
                "metadata": {
                    "network": "tcp",
                    "host": "example.com",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": "443",
                    "process": "upstream-proxy",
                    "processPath": "/Applications/Upstream Proxy.app/Contents/MacOS/proxy"
                },
                "start": "2099-08-23T03:00:00Z",
                "chains": ["香港节点", "自动选择", "MATCH"],
                "providerChains": [],
                "dialerProxy": ["前置节点"],
                "rule": "DOMAIN-SUFFIX",
                "rulePayload": "example.com"
            }]
        }"#,
    );
    let proxies = HashMap::from([
        (
            "自动选择".into(),
            proxy("自动选择", "Selector", Some("香港节点")),
        ),
        ("香港节点".into(), proxy("香港节点", "Shadowsocks", None)),
        ("前置节点".into(), proxy("前置节点", "Trojan", None)),
    ]);
    let provider = provider_with(vec![connection], Vec::new(), proxies);

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(result.kind, TrafficDecisionKind::Proxy);
    assert_eq!(
        names(&result),
        vec!["DOMAIN-SUFFIX", "自动选择", "香港节点", "前置节点"]
    );
    assert!(
        result
            .chain
            .iter()
            .all(|node| node.level == EvidenceLevel::Confirmed)
    );
    assert!(result.evidence.iter().all(|item| {
        matches!(
            item.level,
            EvidenceLevel::Confirmed | EvidenceLevel::Inferred | EvidenceLevel::Unknown
        )
    }));
}

#[tokio::test]
async fn leaf_first_grouped_direct_uses_the_leaf_without_inventing_a_proxy_node() {
    let connection = connection_event(
        r#"{
            "downloadTotal": 1,
            "uploadTotal": 1,
            "connections": [{
                "id": "grouped-direct",
                "metadata": {
                    "network": "tcp",
                    "host": "example.com",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": "443"
                },
                "start": "2099-08-23T03:00:00Z",
                "chains": ["DIRECT", "手动选择", "GLOBAL"],
                "providerChains": [],
                "rule": "DOMAIN-SUFFIX",
                "rulePayload": "example.com"
            }]
        }"#,
    );
    let proxies = HashMap::from([
        (
            "GLOBAL".into(),
            proxy("GLOBAL", "Selector", Some("手动选择")),
        ),
        (
            "手动选择".into(),
            proxy("手动选择", "Selector", Some("DIRECT")),
        ),
    ]);
    let provider = provider_with(vec![connection], Vec::new(), proxies);

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(result.kind, TrafficDecisionKind::Direct);
    assert_eq!(names(&result), vec!["DOMAIN-SUFFIX", "GLOBAL", "手动选择"]);
    assert_eq!(result.chain[0].kind, TrafficNodeKind::TrafficRule);
    assert_eq!(result.chain[1].kind, TrafficNodeKind::PolicyGroup);
    assert_eq!(result.chain[2].kind, TrafficNodeKind::PolicyGroup);
    assert!(
        !result
            .chain
            .iter()
            .any(|node| { node.name == "DIRECT" && node.kind == TrafficNodeKind::ProxyNode })
    );
    assert!(
        result
            .chain
            .iter()
            .all(|node| node.level == EvidenceLevel::Confirmed)
    );
}

#[tokio::test]
async fn leaf_first_grouped_reject_renders_the_blocked_terminal_after_groups() {
    let connection = connection_event(
        r#"{
            "downloadTotal": 0,
            "uploadTotal": 0,
            "connections": [{
                "id": "grouped-reject",
                "metadata": {
                    "network": "tcp",
                    "host": "example.com",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": 443
                },
                "start": "2099-08-23T03:00:00Z",
                "chains": ["REJECT", "广告拦截"],
                "providerChains": [],
                "rule": "RULE-SET",
                "rulePayload": "advertising"
            }]
        }"#,
    );
    let proxies = HashMap::from([(
        "广告拦截".into(),
        proxy("广告拦截", "Selector", Some("REJECT")),
    )]);
    let provider = provider_with(vec![connection], Vec::new(), proxies);

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(result.kind, TrafficDecisionKind::Reject);
    assert_eq!(names(&result), vec!["RULE-SET", "广告拦截", "REJECT"]);
    assert_eq!(
        result.chain[2].kind,
        network_path_agent::domain::TrafficNodeKind::Blocked
    );
}

#[tokio::test]
async fn leaf_first_grouped_reject_drop_renders_the_blocked_terminal_after_all_groups() {
    let connection = connection_event(
        r#"{
            "downloadTotal": 0,
            "uploadTotal": 0,
            "connections": [{
                "id": "grouped-reject-drop",
                "metadata": {
                    "network": "tcp",
                    "host": "example.com",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": "443"
                },
                "start": "2099-08-23T03:00:00Z",
                "chains": ["REJECT-DROP", "隐私过滤", "总策略"],
                "providerChains": [],
                "rule": "RULE-SET",
                "rulePayload": "privacy"
            }]
        }"#,
    );
    let proxies = HashMap::from([
        (
            "总策略".into(),
            proxy("总策略", "Selector", Some("隐私过滤")),
        ),
        (
            "隐私过滤".into(),
            proxy("隐私过滤", "Selector", Some("REJECT-DROP")),
        ),
    ]);
    let provider = provider_with(vec![connection], Vec::new(), proxies);

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(result.kind, TrafficDecisionKind::Reject);
    assert_eq!(
        names(&result),
        vec!["RULE-SET", "总策略", "隐私过滤", "REJECT-DROP"]
    );
    assert_eq!(
        result.chain[3].kind,
        network_path_agent::domain::TrafficNodeKind::Blocked
    );
}

#[tokio::test]
async fn leaf_first_proxy_path_keeps_an_ordinary_outer_group_and_leaf() {
    let connection = connection_event(
        r#"{
            "downloadTotal": 1,
            "uploadTotal": 1,
            "connections": [{
                "id": "ordinary-outer-group",
                "metadata": {
                    "network": "tcp",
                    "host": "example.com",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": 443
                },
                "start": "2099-08-23T03:00:00Z",
                "chains": ["香港节点", "普通外层组"],
                "providerChains": [],
                "rule": "DOMAIN",
                "rulePayload": "example.com"
            }]
        }"#,
    );
    let proxies = HashMap::from([
        (
            "普通外层组".into(),
            proxy("普通外层组", "URLTest", Some("香港节点")),
        ),
        ("香港节点".into(), proxy("香港节点", "Trojan", None)),
    ]);
    let provider = provider_with(vec![connection], Vec::new(), proxies);

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(result.kind, TrafficDecisionKind::Proxy);
    assert_eq!(names(&result), vec!["DOMAIN", "普通外层组", "香港节点"]);
}

#[tokio::test]
async fn leaf_first_proxy_is_not_misclassified_by_outer_groups_named_like_terminals() {
    for outer_group in ["DIRECT", "REJECT"] {
        let connection = connection_event(&format!(
            r#"{{
                "downloadTotal": 1,
                "uploadTotal": 1,
                "connections": [{{
                    "id": "misleading-{outer_group}",
                    "metadata": {{
                        "network": "tcp",
                        "host": "example.com",
                        "destinationIP": "93.184.216.34",
                        "destinationPort": "443"
                    }},
                    "start": "2099-08-23T03:00:00Z",
                    "chains": ["真实代理节点", "{outer_group}"],
                    "providerChains": [],
                    "rule": "MATCH",
                    "rulePayload": ""
                }}]
            }}"#
        ));
        let proxies = HashMap::from([
            (
                outer_group.into(),
                proxy(outer_group, "Selector", Some("真实代理节点")),
            ),
            (
                "真实代理节点".into(),
                proxy("真实代理节点", "Shadowsocks", None),
            ),
        ]);
        let provider = provider_with(vec![connection], Vec::new(), proxies);

        let result = observe(&provider, target("example.com", 443)).await;

        assert_eq!(result.kind, TrafficDecisionKind::Proxy);
        assert_eq!(names(&result), vec!["MATCH", outer_group, "真实代理节点"]);
        assert_eq!(result.chain[1].kind, TrafficNodeKind::PolicyGroup);
        assert_eq!(result.chain[2].kind, TrafficNodeKind::ProxyNode);
        assert!(
            !result.chain.iter().any(|node| {
                node.name == outer_group && node.kind == TrafficNodeKind::ProxyNode
            })
        );
    }
}

#[tokio::test]
async fn concurrent_equal_candidates_degrade_to_unknown() {
    let connections = connection_event(
        r#"{
            "downloadTotal": 0,
            "uploadTotal": 0,
            "connections": [
                {
                    "id": "candidate-a",
                    "metadata": {
                        "network": "tcp",
                        "host": "example.com",
                        "destinationIP": "93.184.216.34",
                        "destinationPort": "443",
                        "processID": 7
                    },
                    "start": "2099-08-23T03:00:00Z",
                    "chains": ["节点甲", "MATCH"],
                    "providerChains": [],
                    "rule": "MATCH",
                    "rulePayload": ""
                },
                {
                    "id": "candidate-b",
                    "metadata": {
                        "network": "tcp",
                        "host": "example.com",
                        "destinationIP": "93.184.216.34",
                        "destinationPort": "443",
                        "processID": 8
                    },
                    "start": "2099-08-23T03:00:00Z",
                    "chains": ["节点乙", "MATCH"],
                    "providerChains": [],
                    "rule": "MATCH",
                    "rulePayload": ""
                }
            ]
        }"#,
    );
    let provider = provider_with(vec![connections], Vec::new(), HashMap::new());

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(result.kind, TrafficDecisionKind::Unknown);
    assert!(result.chain.is_empty());
    assert_eq!(result.evidence[0].level, EvidenceLevel::Unknown);
}

#[tokio::test]
async fn process_and_protocol_only_disambiguate_candidates_that_match_the_target() {
    let connections = connection_event(
        r#"{
            "downloadTotal": 0,
            "uploadTotal": 0,
            "connections": [
                {
                    "id": "target-lower-score",
                    "metadata": {
                        "network": "udp",
                        "host": "example.com",
                        "destinationIP": "93.184.216.34",
                        "destinationPort": "443",
                        "processID": 7
                    },
                    "start": "2099-08-23T03:00:00Z",
                    "chains": ["错误候选", "MATCH"],
                    "providerChains": [],
                    "rule": "MATCH",
                    "rulePayload": ""
                },
                {
                    "id": "target-highest-score",
                    "metadata": {
                        "network": "tcp",
                        "host": "example.com",
                        "destinationIP": "93.184.216.34",
                        "destinationPort": "443",
                        "processID": 4242
                    },
                    "start": "2099-08-23T03:00:00Z",
                    "chains": ["正确节点", "MATCH"],
                    "providerChains": [],
                    "rule": "MATCH",
                    "rulePayload": ""
                },
                {
                    "id": "other-application",
                    "metadata": {
                        "network": "tcp",
                        "host": "private-other-app.invalid",
                        "destinationIP": "203.0.113.77",
                        "destinationPort": "8443",
                        "processID": 4242,
                        "processPath": "/Users/private/Other.app"
                    },
                    "start": "2099-08-23T03:00:00Z",
                    "chains": ["不得泄漏节点", "MATCH"],
                    "providerChains": [],
                    "rule": "DOMAIN",
                    "rulePayload": "private-other-app.invalid"
                }
            ]
        }"#,
    );
    let provider = provider_with(vec![connections], Vec::new(), HashMap::new());

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(result.kind, TrafficDecisionKind::Proxy);
    assert_eq!(names(&result), vec!["MATCH", "正确节点"]);
    let serialized = serde_json::to_string(&result).unwrap();
    assert!(!serialized.contains("private-other-app"));
    assert!(!serialized.contains("不得泄漏节点"));
    assert!(!serialized.contains("/Users/private"));
}

#[tokio::test]
async fn correlated_direct_connection_maps_only_from_mihomo_terminal_evidence() {
    let connection = connection_event(
        r#"{
            "downloadTotal": 1,
            "uploadTotal": 1,
            "connections": [{
                "id": "direct-target",
                "metadata": {
                    "network": "tcp",
                    "host": "example.com",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": "443"
                },
                "start": "2099-08-23T03:00:00Z",
                "chains": ["DIRECT"],
                "providerChains": [],
                "rule": "DOMAIN-SUFFIX",
                "rulePayload": "example.com"
            }]
        }"#,
    );
    let provider = provider_with(vec![connection], Vec::new(), HashMap::new());

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(result.kind, TrafficDecisionKind::Direct);
    assert_eq!(names(&result), vec!["DOMAIN-SUFFIX"]);
    assert_eq!(result.chain[0].kind, TrafficNodeKind::TrafficRule);
    assert!(
        !result
            .chain
            .iter()
            .any(|node| { node.name == "DIRECT" && node.kind == TrafficNodeKind::ProxyNode })
    );
    let rule = result.rule.unwrap();
    assert_eq!(rule.rule_type, "DOMAIN-SUFFIX");
    assert_eq!(rule.payload.as_deref(), Some("example.com"));
    assert_eq!(rule.target, "DIRECT");
    assert_eq!(rule.level, EvidenceLevel::Confirmed);
}

#[tokio::test]
async fn correlated_reject_log_maps_to_reject_with_confirmed_rule_and_blocked_node() {
    let reject = log_event(
        r#"{
            "type": "info",
            "payload": "[TCP] 127.0.0.1:51247 --> example.com:443 match RuleSet(advertising) using REJECT"
        }"#,
    );
    let provider = provider_with(Vec::new(), vec![reject], HashMap::new());

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(result.kind, TrafficDecisionKind::Reject);
    assert_eq!(names(&result), vec!["RuleSet", "REJECT"]);
    assert_eq!(result.chain[0].level, EvidenceLevel::Confirmed);
    assert_eq!(result.chain[1].level, EvidenceLevel::Confirmed);
    let rule = result.rule.unwrap();
    assert_eq!(rule.rule_type, "RuleSet");
    assert_eq!(rule.payload.as_deref(), Some("advertising"));
    assert_eq!(rule.target, "REJECT");
}

#[tokio::test]
async fn connection_failure_without_correlated_reject_event_stays_unknown() {
    let failed_dial = log_event(
        r#"{
            "type": "warning",
            "payload": "[TCP] dial DIRECT (match DomainSuffix/example.com) 127.0.0.1:51247 --> example.com:443 error: connect failed"
        }"#,
    );
    let unrelated_reject = log_event(
        r#"{
            "type": "info",
            "payload": "[TCP] 127.0.0.1:51248 --> private-other-app.invalid:443 match Domain(private-other-app.invalid) using REJECT-DROP"
        }"#,
    );
    let provider = provider_with(
        Vec::new(),
        vec![failed_dial, unrelated_reject],
        HashMap::new(),
    );

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(result.kind, TrafficDecisionKind::Unknown);
    assert!(result.rule.is_none());
    assert!(result.chain.is_empty());
    let serialized = serde_json::to_string(&result).unwrap();
    assert!(!serialized.contains("private-other-app"));
}

#[tokio::test]
async fn active_connection_started_before_the_observation_window_is_not_a_candidate() {
    let stale_connection = connection_event(
        r#"{
            "downloadTotal": 100,
            "uploadTotal": 100,
            "connections": [{
                "id": "stale-target",
                "metadata": {
                    "network": "tcp",
                    "host": "example.com",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": "443",
                    "processID": 4242
                },
                "start": "2000-01-01T00:00:00Z",
                "chains": ["陈旧节点", "MATCH"],
                "providerChains": [],
                "rule": "MATCH",
                "rulePayload": ""
            }]
        }"#,
    );
    let provider = provider_with(vec![stale_connection], Vec::new(), HashMap::new());

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(result.kind, TrafficDecisionKind::Unknown);
    assert!(result.chain.is_empty());
}

#[tokio::test]
async fn unique_resolved_ip_and_port_candidate_is_correlated_when_host_is_empty() {
    let connection = connection_event(
        r#"{
            "downloadTotal": 1,
            "uploadTotal": 1,
            "connections": [{
                "id": "resolved-ip-target",
                "metadata": {
                    "network": "tcp",
                    "host": "",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": 443,
                    "processID": 4242
                },
                "start": "2099-08-23T03:00:00Z",
                "chains": ["IP节点", "MATCH"],
                "providerChains": [],
                "rule": "IP-CIDR",
                "rulePayload": "93.184.216.0/24"
            }]
        }"#,
    );
    let provider = provider_with(vec![connection], Vec::new(), HashMap::new());

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(result.kind, TrafficDecisionKind::Proxy);
    assert_eq!(names(&result), vec!["IP-CIDR", "IP节点"]);
    assert!(
        result
            .chain
            .iter()
            .all(|node| node.level == EvidenceLevel::Confirmed)
    );
}

#[tokio::test]
async fn selector_without_a_matched_connection_is_an_inferred_unknown_chain() {
    let proxies = proxy_map(
        r#"{
            "proxies": {
                "GLOBAL": {"name":"GLOBAL","type":"Selector","now":"手动选择","all":["手动选择"]},
                "手动选择": {"name":"手动选择","type":"Selector","now":"香港 01","all":["香港 01"]},
                "香港 01": {"name":"香港 01","type":"Shadowsocks","alive":true,"history":[{"delay":31}]}
            }
        }"#,
    );
    let provider = provider_with(Vec::new(), Vec::new(), proxies);

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(result.kind, TrafficDecisionKind::Unknown);
    assert_eq!(names(&result), vec!["手动选择", "香港 01"]);
    assert!(
        result
            .chain
            .iter()
            .all(|node| node.level == EvidenceLevel::Inferred)
    );
}

#[tokio::test]
async fn urltest_without_a_matched_connection_is_an_inferred_unknown_chain() {
    let proxies = proxy_map(
        r#"{
            "proxies": {
                "GLOBAL": {"name":"GLOBAL","type":"Selector","now":"自动测速","all":["自动测速"]},
                "自动测速": {"name":"自动测速","type":"URLTest","now":"东京 02","all":["东京 02"]},
                "东京 02": {"name":"东京 02","type":"Trojan","alive":true,"history":[{"delay":44}]}
            }
        }"#,
    );
    let provider = provider_with(Vec::new(), Vec::new(), proxies);

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(result.kind, TrafficDecisionKind::Unknown);
    assert_eq!(names(&result), vec!["自动测速", "东京 02"]);
    assert!(
        result
            .chain
            .iter()
            .all(|node| node.level == EvidenceLevel::Inferred)
    );
}

#[tokio::test]
async fn fallback_without_a_matched_connection_is_an_inferred_unknown_chain() {
    let proxies = proxy_map(
        r#"{
            "proxies": {
                "GLOBAL": {"name":"GLOBAL","type":"Selector","now":"故障转移","all":["故障转移"]},
                "故障转移": {"name":"故障转移","type":"Fallback","now":"新加坡 03","all":["新加坡 03"]},
                "新加坡 03": {"name":"新加坡 03","type":"VMess","alive":true,"history":[{"delay":55}]}
            }
        }"#,
    );
    let provider = provider_with(Vec::new(), Vec::new(), proxies);

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(result.kind, TrafficDecisionKind::Unknown);
    assert_eq!(names(&result), vec!["故障转移", "新加坡 03"]);
    assert!(
        result
            .chain
            .iter()
            .all(|node| node.level == EvidenceLevel::Inferred)
    );
}

#[tokio::test]
async fn loadbalance_without_a_matched_connection_does_not_claim_the_current_node() {
    let proxies = proxy_map(
        r#"{
            "proxies": {
                "GLOBAL": {"name":"GLOBAL","type":"Selector","now":"均衡组","all":["均衡组"]},
                "均衡组": {"name":"均衡组","type":"LoadBalance","now":"不得推断节点","all":["不得推断节点"]},
                "不得推断节点": {"name":"不得推断节点","type":"Shadowsocks","alive":true,"history":[{"delay":20}]}
            }
        }"#,
    );
    let provider = provider_with(Vec::new(), Vec::new(), proxies);

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(result.kind, TrafficDecisionKind::Unknown);
    assert_eq!(names(&result), vec!["均衡组"]);
    assert_eq!(result.chain[0].level, EvidenceLevel::Inferred);
    assert!(
        !serde_json::to_string(&result)
            .unwrap()
            .contains("不得推断节点")
    );
}

#[tokio::test]
async fn duplicate_group_names_in_a_matched_chain_are_emitted_once() {
    let connection = connection_event(
        r#"{
            "downloadTotal": 1,
            "uploadTotal": 1,
            "connections": [{
                "id": "duplicate-chain",
                "metadata": {
                    "network": "tcp",
                    "host": "example.com",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": "443"
                },
                "start": "2099-08-23T03:00:00Z",
                "chains": ["香港节点", "重复组", "重复组", "MATCH"],
                "providerChains": [],
                "rule": "DOMAIN",
                "rulePayload": "example.com"
            }]
        }"#,
    );
    let proxies = HashMap::from([
        (
            "重复组".into(),
            proxy("重复组", "Selector", Some("香港节点")),
        ),
        ("香港节点".into(), proxy("香港节点", "Shadowsocks", None)),
    ]);
    let provider = provider_with(vec![connection], Vec::new(), proxies);

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(names(&result), vec!["DOMAIN", "重复组", "香港节点"]);
}

#[tokio::test]
async fn configuration_group_cycles_stop_after_each_name_is_emitted_once() {
    let proxies = proxy_map(
        r#"{
            "proxies": {
                "GLOBAL": {"name":"GLOBAL","type":"Selector","now":"循环甲","all":["循环甲"]},
                "循环甲": {"name":"循环甲","type":"Selector","now":"循环乙","all":["循环乙"]},
                "循环乙": {"name":"循环乙","type":"Fallback","now":"循环甲","all":["循环甲"]}
            }
        }"#,
    );
    let provider = provider_with(Vec::new(), Vec::new(), proxies);

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(result.kind, TrafficDecisionKind::Unknown);
    assert_eq!(names(&result), vec!["循环甲", "循环乙"]);
    assert!(
        result
            .chain
            .iter()
            .all(|node| node.level == EvidenceLevel::Inferred)
    );
}

#[tokio::test]
async fn explicit_provider_chains_are_appended_after_the_normalized_connection_chain() {
    let connection = connection_event(
        r#"{
            "downloadTotal": 1,
            "uploadTotal": 1,
            "connections": [{
                "id": "provider-chain",
                "metadata": {
                    "network": "tcp",
                    "host": "example.com",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": "443"
                },
                "start": "2099-08-23T03:00:00Z",
                "chains": ["订阅节点", "规则组", "MATCH"],
                "providerChains": ["机场订阅", "", "机场订阅"],
                "rule": "RULE-SET",
                "rulePayload": "overseas"
            }]
        }"#,
    );
    let proxies = HashMap::from([
        (
            "规则组".into(),
            proxy("规则组", "URLTest", Some("订阅节点")),
        ),
        ("订阅节点".into(), proxy("订阅节点", "Trojan", None)),
    ]);
    let provider = provider_with(vec![connection], Vec::new(), proxies);

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(result.kind, TrafficDecisionKind::Proxy);
    assert_eq!(
        names(&result),
        vec!["RULE-SET", "规则组", "订阅节点", "机场订阅"]
    );
    assert!(
        result
            .chain
            .iter()
            .all(|node| node.level == EvidenceLevel::Confirmed)
    );
}

#[tokio::test]
async fn selector_dialer_path_from_proxy_map_is_inferred_after_confirmed_connection_chain() {
    let connection = connection_event(
        r#"{
            "downloadTotal": 1,
            "uploadTotal": 1,
            "connections": [{
                "id": "dialer-from-proxy-map",
                "metadata": {
                    "network": "tcp",
                    "host": "example.com",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": "443"
                },
                "start": "2099-08-23T03:00:00Z",
                "chains": ["落地节点", "策略组", "MATCH"],
                "providerChains": [],
                "rule": "DOMAIN-SUFFIX",
                "rulePayload": "example.com"
            }]
        }"#,
    );
    let proxies = proxy_map(
        r#"{
            "proxies": {
                "策略组": {"name":"策略组","type":"Selector","now":"落地节点","all":["落地节点"]},
                "落地节点": {"name":"落地节点","type":"Shadowsocks","dialer-proxy":"前置组","alive":true},
                "前置组": {"name":"前置组","type":"Selector","now":"前置节点","all":["前置节点"]},
                "前置节点": {"name":"前置节点","type":"Trojan","alive":true}
            }
        }"#,
    );
    let provider = provider_with(vec![connection], Vec::new(), proxies);

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(result.kind, TrafficDecisionKind::Proxy);
    assert_eq!(
        names(&result),
        vec!["DOMAIN-SUFFIX", "策略组", "落地节点", "前置组", "前置节点"]
    );
    assert_eq!(
        levels(&result),
        vec![
            EvidenceLevel::Confirmed,
            EvidenceLevel::Confirmed,
            EvidenceLevel::Confirmed,
            EvidenceLevel::Inferred,
            EvidenceLevel::Inferred,
        ]
    );
}

#[tokio::test]
async fn urltest_dialer_path_from_proxy_map_is_inferred_with_exact_selected_node() {
    let connection = connection_event(
        r#"{
            "downloadTotal": 1,
            "uploadTotal": 1,
            "connections": [{
                "id": "urltest-dialer",
                "metadata": {
                    "network": "tcp",
                    "host": "example.com",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": 443
                },
                "start": "2099-08-23T03:00:00Z",
                "chains": ["落地节点", "策略组"],
                "providerChains": [],
                "rule": "DOMAIN",
                "rulePayload": "example.com"
            }]
        }"#,
    );
    let proxies = proxy_map(
        r#"{
            "proxies": {
                "策略组": {"name":"策略组","type":"Selector","now":"落地节点","all":["落地节点"]},
                "落地节点": {"name":"落地节点","type":"Trojan","dialer-proxy":"前置测速","alive":true},
                "前置测速": {"name":"前置测速","type":"URLTest","now":"东京前置","all":["东京前置","大阪前置"]},
                "东京前置": {"name":"东京前置","type":"Shadowsocks","alive":true},
                "大阪前置": {"name":"大阪前置","type":"Shadowsocks","alive":true}
            }
        }"#,
    );
    let provider = provider_with(vec![connection], Vec::new(), proxies);

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(
        names(&result),
        vec!["DOMAIN", "策略组", "落地节点", "前置测速", "东京前置"]
    );
    assert_eq!(
        levels(&result),
        vec![
            EvidenceLevel::Confirmed,
            EvidenceLevel::Confirmed,
            EvidenceLevel::Confirmed,
            EvidenceLevel::Inferred,
            EvidenceLevel::Inferred,
        ]
    );
}

#[tokio::test]
async fn fallback_dialer_path_from_proxy_map_is_inferred_with_exact_selected_node() {
    let connection = connection_event(
        r#"{
            "downloadTotal": 1,
            "uploadTotal": 1,
            "connections": [{
                "id": "fallback-dialer",
                "metadata": {
                    "network": "tcp",
                    "host": "example.com",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": "443"
                },
                "start": "2099-08-23T03:00:00Z",
                "chains": ["落地节点", "策略组"],
                "providerChains": [],
                "rule": "DOMAIN-SUFFIX",
                "rulePayload": "example.com"
            }]
        }"#,
    );
    let proxies = proxy_map(
        r#"{
            "proxies": {
                "策略组": {"name":"策略组","type":"Selector","now":"落地节点","all":["落地节点"]},
                "落地节点": {"name":"落地节点","type":"VMess","dialer-proxy":"前置故障转移","alive":true},
                "前置故障转移": {"name":"前置故障转移","type":"Fallback","now":"新加坡前置","all":["新加坡前置","香港前置"]},
                "新加坡前置": {"name":"新加坡前置","type":"Trojan","alive":true},
                "香港前置": {"name":"香港前置","type":"Trojan","alive":true}
            }
        }"#,
    );
    let provider = provider_with(vec![connection], Vec::new(), proxies);

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(
        names(&result),
        vec![
            "DOMAIN-SUFFIX",
            "策略组",
            "落地节点",
            "前置故障转移",
            "新加坡前置"
        ]
    );
    assert_eq!(
        levels(&result),
        vec![
            EvidenceLevel::Confirmed,
            EvidenceLevel::Confirmed,
            EvidenceLevel::Confirmed,
            EvidenceLevel::Inferred,
            EvidenceLevel::Inferred,
        ]
    );
}

#[tokio::test]
async fn loadbalance_dialer_path_is_inferred_without_guessing_a_selected_leaf() {
    let connection = connection_event(
        r#"{
            "downloadTotal": 1,
            "uploadTotal": 1,
            "connections": [{
                "id": "loadbalance-dialer",
                "metadata": {
                    "network": "tcp",
                    "host": "example.com",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": 443
                },
                "start": "2099-08-23T03:00:00Z",
                "chains": ["落地节点", "策略组"],
                "providerChains": [],
                "rule": "MATCH",
                "rulePayload": ""
            }]
        }"#,
    );
    let proxies = proxy_map(
        r#"{
            "proxies": {
                "策略组": {"name":"策略组","type":"Selector","now":"落地节点","all":["落地节点"]},
                "落地节点": {"name":"落地节点","type":"Shadowsocks","dialer-proxy":"前置均衡","alive":true},
                "前置均衡": {"name":"前置均衡","type":"LoadBalance","now":"不得猜测节点","all":["不得猜测节点","另一节点"]},
                "不得猜测节点": {"name":"不得猜测节点","type":"Trojan","alive":true},
                "另一节点": {"name":"另一节点","type":"Trojan","alive":true}
            }
        }"#,
    );
    let provider = provider_with(vec![connection], Vec::new(), proxies);

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(
        names(&result),
        vec!["MATCH", "策略组", "落地节点", "前置均衡"]
    );
    assert_eq!(
        levels(&result),
        vec![
            EvidenceLevel::Confirmed,
            EvidenceLevel::Confirmed,
            EvidenceLevel::Confirmed,
            EvidenceLevel::Inferred,
        ]
    );
    assert!(
        !serde_json::to_string(&result)
            .unwrap()
            .contains("不得猜测节点")
    );
}

#[tokio::test]
async fn connection_that_ends_before_finish_remains_available_for_correlation() {
    let active = connection_event(
        r#"{
            "downloadTotal": 1,
            "uploadTotal": 1,
            "connections": [{
                "id": "short-lived-target",
                "metadata": {
                    "network": "tcp",
                    "host": "example.com",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": "443"
                },
                "start": "2099-08-23T03:00:00Z",
                "chains": ["短连接节点", "MATCH"],
                "providerChains": [],
                "rule": "MATCH",
                "rulePayload": ""
            }]
        }"#,
    );
    let ended = connection_event(r#"{"downloadTotal":1,"uploadTotal":1,"connections":[]}"#);
    let provider = provider_with(vec![active, ended], Vec::new(), HashMap::new());
    let id = provider.begin(&target("example.com", 443)).await.unwrap();
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    let result = tokio::time::timeout(Duration::from_secs(1), provider.finish(id))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(result.kind, TrafficDecisionKind::Proxy);
    assert_eq!(names(&result), vec!["MATCH", "短连接节点"]);
}

#[tokio::test]
async fn stream_disconnect_finishes_unknown_without_exposing_stream_errors() {
    let provider = provider_with_stream_errors();
    let id = provider.begin(&target("example.com", 443)).await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(1), provider.finish(id))
        .await
        .expect("finish must not wait for the five-second deadline")
        .unwrap();

    assert_eq!(result.kind, TrafficDecisionKind::Unknown);
    let serialized = serde_json::to_string(&result).unwrap();
    assert!(!serialized.contains("private connection stream payload"));
    assert!(!serialized.contains("private-other-app"));
    assert!(!serialized.contains("/Users/private"));
}

#[tokio::test]
async fn cancellation_stops_pending_stream_tasks_and_removes_the_session() {
    let (provider, stream_drops) = provider_with_pending_streams();
    let id = provider.begin(&target("example.com", 443)).await.unwrap();

    provider.cancel(id).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while stream_drops.load(Ordering::SeqCst) != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancel must stop both pending stream tasks");
    let result = tokio::time::timeout(Duration::from_millis(100), provider.finish(id))
        .await
        .expect("a cancelled observation must finish immediately")
        .unwrap();

    assert_eq!(stream_drops.load(Ordering::SeqCst), 2);
    assert_eq!(result.kind, TrafficDecisionKind::Unknown);
}

#[tokio::test]
async fn finish_caps_observation_at_five_seconds_and_stops_pending_streams() {
    let (provider, stream_drops) = provider_with_pending_streams();
    let id = provider.begin(&target("example.com", 443)).await.unwrap();

    let result = tokio::time::timeout(Duration::from_millis(5_500), provider.finish(id))
        .await
        .expect("finish exceeded the five-second observation deadline")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while stream_drops.load(Ordering::SeqCst) != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("finish must stop both pending stream tasks");

    assert_eq!(result.kind, TrafficDecisionKind::Unknown);
    assert_eq!(stream_drops.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn bounded_session_buffer_retains_at_most_128_matching_events() {
    let start = (OffsetDateTime::now_utc() + TimeDuration::seconds(1))
        .format(&Rfc3339)
        .unwrap();
    let events = (0..129)
        .map(|index| {
            MihomoEvent::Connection(MihomoConnectionEvent {
                download_total: 0,
                upload_total: 0,
                connections: vec![serde_json::json!({
                    "id": format!("bounded-{index}"),
                    "metadata": {
                        "network": "tcp",
                        "host": "example.com",
                        "destinationIP": "93.184.216.34",
                        "destinationPort": "443",
                        "processID": 7
                    },
                    "start": start,
                    "chains": [format!("node-{index}"), "MATCH"],
                    "providerChains": [],
                    "rule": "MATCH",
                    "rulePayload": ""
                })],
            })
        })
        .collect();
    let provider = provider_with(events, Vec::new(), HashMap::new());
    let id = provider.begin(&target("example.com", 443)).await.unwrap();
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    let result = provider.finish(id).await.unwrap();

    assert_eq!(result.kind, TrafficDecisionKind::Unknown);
    assert_eq!(
        result.evidence[0].summary,
        "128 highest-scoring Mihomo candidates were ambiguous"
    );
}

#[tokio::test]
async fn bounded_chain_emits_no_more_than_32_nodes_in_logical_order() {
    let start = (OffsetDateTime::now_utc() + TimeDuration::seconds(1))
        .format(&Rfc3339)
        .unwrap();
    let mut wire_chains = (1..=40)
        .rev()
        .map(|index| format!("node-{index}"))
        .collect::<Vec<_>>();
    wire_chains.push("MATCH".into());
    let connection = MihomoEvent::Connection(MihomoConnectionEvent {
        download_total: 0,
        upload_total: 0,
        connections: vec![serde_json::json!({
            "id": "bounded-chain",
            "metadata": {
                "network": "tcp",
                "host": "example.com",
                "destinationIP": "93.184.216.34",
                "destinationPort": "443"
            },
            "start": start,
            "chains": wire_chains,
            "providerChains": [],
            "rule": "MATCH",
            "rulePayload": ""
        })],
    });
    let provider = provider_with(vec![connection], Vec::new(), HashMap::new());

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(result.chain.len(), 32);
    assert_eq!(result.chain[0].name, "MATCH");
    assert_eq!(result.chain[1].name, "node-1");
    assert_eq!(result.chain[31].name, "node-31");
    assert!(!result.chain.iter().any(|node| node.name == "node-32"));
}

#[tokio::test]
async fn repeated_snapshots_of_the_same_connection_id_are_one_candidate() {
    let connection = connection_event(
        r#"{
            "downloadTotal": 1,
            "uploadTotal": 1,
            "connections": [{
                "id": "repeated-target",
                "metadata": {
                    "network": "tcp",
                    "host": "example.com",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": "443"
                },
                "start": "2099-08-23T03:00:00Z",
                "chains": ["重复快照节点", "MATCH"],
                "providerChains": [],
                "rule": "MATCH",
                "rulePayload": ""
            }]
        }"#,
    );
    let provider = provider_with(
        vec![connection.clone(), connection],
        Vec::new(),
        HashMap::new(),
    );
    let id = provider.begin(&target("example.com", 443)).await.unwrap();
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    let result = provider.finish(id).await.unwrap();

    assert_eq!(result.kind, TrafficDecisionKind::Proxy);
    assert_eq!(names(&result), vec!["MATCH", "重复快照节点"]);
}

#[tokio::test]
async fn abandoned_observation_self_expires_without_leaking_stream_tasks() {
    let (provider, stream_drops) = provider_with_pending_streams();
    let id = provider.begin(&target("example.com", 443)).await.unwrap();

    tokio::time::timeout(Duration::from_millis(5_500), async {
        while stream_drops.load(Ordering::SeqCst) != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("an abandoned observation must self-expire after five seconds");
    let result = tokio::time::timeout(Duration::from_millis(100), provider.finish(id))
        .await
        .expect("an expired observation ID must finish immediately")
        .unwrap();

    assert_eq!(stream_drops.load(Ordering::SeqCst), 2);
    assert_eq!(result.kind, TrafficDecisionKind::Unknown);
}

#[tokio::test]
async fn current_process_path_disambiguates_otherwise_equal_target_candidates() {
    let start = (OffsetDateTime::now_utc() + TimeDuration::seconds(1))
        .format(&Rfc3339)
        .unwrap();
    let current_exe = std::env::current_exe().unwrap();
    let connection = MihomoEvent::Connection(MihomoConnectionEvent {
        download_total: 0,
        upload_total: 0,
        connections: vec![
            serde_json::json!({
                "id": "other-process-path",
                "metadata": {
                    "network": "tcp",
                    "host": "example.com",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": "443",
                    "processPath": "/Users/private/Other.app/Contents/MacOS/other"
                },
                "start": start.clone(),
                "chains": ["错误进程节点", "MATCH"],
                "providerChains": [],
                "rule": "MATCH",
                "rulePayload": ""
            }),
            serde_json::json!({
                "id": "current-process-path",
                "metadata": {
                    "network": "tcp",
                    "host": "example.com",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": "443",
                    "processPath": current_exe
                },
                "start": start,
                "chains": ["当前进程节点", "MATCH"],
                "providerChains": [],
                "rule": "MATCH",
                "rulePayload": ""
            }),
        ],
    });
    let provider = provider_with(vec![connection], Vec::new(), HashMap::new());
    let target = TrafficProbeTarget::new(
        TrafficProbeScheme::Https,
        "example.com",
        443,
        vec!["93.184.216.34".parse().unwrap()],
        std::process::id(),
    );

    let result = observe(&provider, target).await;

    assert_eq!(result.kind, TrafficDecisionKind::Proxy);
    assert_eq!(names(&result), vec!["MATCH", "当前进程节点"]);
    let serialized = serde_json::to_string(&result).unwrap();
    assert!(!serialized.contains("/Users/private"));
    assert!(!serialized.contains("错误进程节点"));
}

#[tokio::test]
async fn correlated_connection_rule_with_reject_drop_terminal_maps_to_reject() {
    let connection = connection_event(
        r#"{
            "downloadTotal": 0,
            "uploadTotal": 0,
            "connections": [{
                "id": "reject-rule-target",
                "metadata": {
                    "network": "tcp",
                    "host": "example.com",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": "443"
                },
                "start": "2099-08-23T03:00:00Z",
                "chains": ["REJECT-DROP"],
                "providerChains": [],
                "rule": "RULE-SET",
                "rulePayload": "advertising"
            }]
        }"#,
    );
    let provider = provider_with(vec![connection], Vec::new(), HashMap::new());

    let result = observe(&provider, target("example.com", 443)).await;

    assert_eq!(result.kind, TrafficDecisionKind::Reject);
    assert_eq!(names(&result), vec!["RULE-SET", "REJECT-DROP"]);
    assert_eq!(
        result.chain[1].kind,
        network_path_agent::domain::TrafficNodeKind::Blocked
    );
    assert!(
        result
            .chain
            .iter()
            .all(|node| node.level == EvidenceLevel::Confirmed)
    );
}

#[tokio::test]
async fn stream_setup_failure_returns_only_a_generic_public_error() {
    let provider = MihomoTrafficDecisionProvider::new(Arc::new(SetupErrorTransport));

    let error = provider
        .begin(&target("example.com", 443))
        .await
        .unwrap_err()
        .to_string();

    assert_eq!(
        error,
        "系统网络信息读取失败: Mihomo observation unavailable"
    );
    assert!(!error.contains("private-target"));
    assert!(!error.contains("/Users/private"));
    assert!(!error.contains("process=other"));
}

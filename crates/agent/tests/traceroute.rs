use async_trait::async_trait;
use network_path_agent::{
    domain::{
        Conclusion, Evidence, EvidenceLevel, HttpObservation, PeerEndpoint, ProxyDecision,
        ProxyKind, TrafficDecision, TrafficDecisionKind, TrafficNode, TrafficNodeKind,
        UrlDiagnosticResult,
    },
    error::DiagnosticError,
    network::trace::{TraceRequestKind, select_trace_target},
    platform::macos::traceroute::{
        MacRouteTracer, TraceExitStatus, TraceProcess, TraceProcessFactory, parse_traceroute,
    },
    ports::{RouteTracer, TraceProgressSink},
};
use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Notify, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

fn ip(value: &str) -> IpAddr {
    value.parse().unwrap()
}

fn evidence(level: EvidenceLevel) -> Evidence {
    Evidence {
        level,
        source: "fixture".into(),
        summary: "fixture evidence".into(),
    }
}

fn node(name: &str, level: EvidenceLevel, endpoint: Option<&str>) -> TrafficNode {
    TrafficNode {
        kind: TrafficNodeKind::ProxyNode,
        name: name.into(),
        node_type: Some("fixture".into()),
        endpoint: endpoint.map(|value| PeerEndpoint {
            ip: ip(value),
            port: 443,
        }),
        alive: Some(true),
        delay_ms: Some(12),
        level,
        evidence: vec![evidence(level)],
    }
}

fn result(
    kind: TrafficDecisionKind,
    decision_level: EvidenceLevel,
    peer: Option<&str>,
    chain: Vec<TrafficNode>,
    resolved_ips: Vec<&str>,
) -> UrlDiagnosticResult {
    let traffic_decision = TrafficDecision {
        kind,
        mode: Some("rule".into()),
        tun_enabled: Some(true),
        rule: None,
        chain,
        evidence: vec![evidence(decision_level)],
    };
    UrlDiagnosticResult {
        id: uuid::Uuid::new_v4(),
        requested_url: "https://example.com/".into(),
        normalized_url: "https://example.com/".into(),
        resolved_ips: resolved_ips.into_iter().map(ip).collect(),
        proxy: ProxyDecision {
            kind: ProxyKind::Direct,
            host: None,
            port: None,
            bypass_reason: None,
            evidence: evidence(EvidenceLevel::Confirmed),
        },
        route: None,
        http: HttpObservation {
            status: Some(204),
            final_url: "https://example.com/".into(),
            elapsed_ms: 12,
            error_code: None,
            peer_endpoint: peer.map(|value| PeerEndpoint {
                ip: ip(value),
                port: 443,
            }),
        },
        traffic_decision,
        conclusion: Conclusion {
            title: "fixture".into(),
            summary: "fixture".into(),
            level: decision_level,
        },
        evidence: vec![evidence(decision_level)],
    }
}

#[test]
fn direct_actual_trace_requires_confirmed_decision_and_observed_website_peer() {
    let actual = select_trace_target(
        &result(
            TrafficDecisionKind::Direct,
            EvidenceLevel::Confirmed,
            Some("93.184.216.34"),
            Vec::new(),
            vec!["203.0.113.9"],
        ),
        TraceRequestKind::Actual,
    )
    .unwrap();

    assert_eq!(
        actual.kind,
        network_path_agent::domain::TraceTargetKind::ActualDestination
    );
    assert_eq!(actual.ip, ip("93.184.216.34"));

    assert!(
        select_trace_target(
            &result(
                TrafficDecisionKind::Direct,
                EvidenceLevel::Inferred,
                Some("93.184.216.34"),
                Vec::new(),
                vec!["203.0.113.9"],
            ),
            TraceRequestKind::Actual,
        )
        .is_none()
    );
}

#[test]
fn direct_actual_trace_rejects_missing_or_loopback_observed_peer() {
    for peer in [None, Some("127.0.0.1"), Some("::1")] {
        assert!(
            select_trace_target(
                &result(
                    TrafficDecisionKind::Direct,
                    EvidenceLevel::Confirmed,
                    peer,
                    Vec::new(),
                    vec!["203.0.113.9"],
                ),
                TraceRequestKind::Actual,
            )
            .is_none()
        );
    }
}

#[test]
fn proxy_actual_trace_uses_first_confirmed_non_loopback_chain_endpoint() {
    let actual = select_trace_target(
        &result(
            TrafficDecisionKind::Proxy,
            EvidenceLevel::Confirmed,
            Some("127.0.0.1"),
            vec![
                node(
                    "local-listener",
                    EvidenceLevel::Confirmed,
                    Some("127.0.0.1"),
                ),
                node(
                    "inferred-node",
                    EvidenceLevel::Inferred,
                    Some("198.51.100.10"),
                ),
                node(
                    "first-remote",
                    EvidenceLevel::Confirmed,
                    Some("198.51.100.20"),
                ),
                node(
                    "later-remote",
                    EvidenceLevel::Confirmed,
                    Some("198.51.100.21"),
                ),
            ],
            vec!["203.0.113.9"],
        ),
        TraceRequestKind::Actual,
    )
    .unwrap();

    assert_eq!(
        actual.kind,
        network_path_agent::domain::TraceTargetKind::ActualProxy
    );
    assert_eq!(actual.ip, ip("198.51.100.20"));
}

#[test]
fn proxy_actual_trace_requires_confirmed_remote_endpoint_and_never_falls_back_to_destination() {
    for chain in [
        vec![node(
            "inferred",
            EvidenceLevel::Inferred,
            Some("198.51.100.20"),
        )],
        vec![node(
            "local-only",
            EvidenceLevel::Confirmed,
            Some("127.0.0.1"),
        )],
        vec![node("missing-endpoint", EvidenceLevel::Confirmed, None)],
    ] {
        assert!(
            select_trace_target(
                &result(
                    TrafficDecisionKind::Proxy,
                    EvidenceLevel::Confirmed,
                    Some("127.0.0.1"),
                    chain,
                    vec!["203.0.113.9"],
                ),
                TraceRequestKind::Actual,
            )
            .is_none()
        );
    }
}

#[test]
fn reject_and_unknown_have_no_automatic_actual_trace_target() {
    for kind in [TrafficDecisionKind::Reject, TrafficDecisionKind::Unknown] {
        assert!(
            select_trace_target(
                &result(
                    kind,
                    EvidenceLevel::Confirmed,
                    Some("93.184.216.34"),
                    vec![node(
                        "remote",
                        EvidenceLevel::Confirmed,
                        Some("198.51.100.20")
                    )],
                    vec!["203.0.113.9"],
                ),
                TraceRequestKind::Actual,
            )
            .is_none()
        );
    }
}

#[test]
fn reference_trace_uses_first_resolved_website_ip_and_keeps_reference_label() {
    let target = select_trace_target(
        &result(
            TrafficDecisionKind::Proxy,
            EvidenceLevel::Inferred,
            None,
            Vec::new(),
            vec!["2001:db8::10", "203.0.113.9"],
        ),
        TraceRequestKind::Reference,
    )
    .unwrap();

    assert_eq!(
        target.kind,
        network_path_agent::domain::TraceTargetKind::ReferenceDestination
    );
    assert_eq!(target.ip, ip("2001:db8::10"));
    assert!(
        select_trace_target(
            &result(
                TrafficDecisionKind::Unknown,
                EvidenceLevel::Unknown,
                None,
                Vec::new(),
                Vec::new(),
            ),
            TraceRequestKind::Reference,
        )
        .is_none()
    );
}

#[test]
fn parser_preserves_positions_fractional_multiple_rtts_stars_ipv4_ipv6_and_hostnames() {
    let output = r#"
traceroute to 198.51.100.20 (198.51.100.20), 20 hops max, 52 byte packets
 1  192.168.1.1  1.25 ms  2.50 ms
 2  * * *
 3  odd-host (2001:db8::1)  3.5 ms  4.75 ms
 4  malformed-host no-address  bad ms
 5  198.51.100.20  5 ms  6.125 ms
"#;

    let parsed = parse_traceroute(output, ip("198.51.100.20")).unwrap();

    assert_eq!(parsed.hops.len(), 5);
    assert_eq!(parsed.hops[0].index, 1);
    assert_eq!(parsed.hops[0].address, Some(ip("192.168.1.1")));
    assert_eq!(parsed.hops[0].rtts_ms, vec![1.25, 2.5]);
    assert_eq!(parsed.hops[0].level, EvidenceLevel::Confirmed);
    assert_eq!(parsed.hops[1].index, 2);
    assert_eq!(parsed.hops[1].address, None);
    assert!(parsed.hops[1].rtts_ms.is_empty());
    assert_eq!(parsed.hops[1].level, EvidenceLevel::Unknown);
    assert_eq!(parsed.hops[2].address, Some(ip("2001:db8::1")));
    assert_eq!(parsed.hops[2].rtts_ms, vec![3.5, 4.75]);
    assert_eq!(parsed.hops[3].address, None);
    assert_eq!(parsed.hops[4].address, Some(ip("198.51.100.20")));
    assert!(parsed.reached_target);
    assert_eq!(
        parsed.target.kind,
        network_path_agent::domain::TraceTargetKind::ReferenceDestination
    );
}

#[test]
fn parser_rejects_invalid_rtts_conservatively_and_truncates_after_twenty_hops() {
    let mut output = String::from("traceroute header\n");
    for index in 1..=21 {
        output.push_str(&format!(
            " {index}  198.51.100.{index}  NaN ms  -1 ms  1.5 ms\n"
        ));
    }

    let parsed = parse_traceroute(&output, ip("198.51.100.99")).unwrap();

    assert_eq!(parsed.hops.len(), 20);
    assert_eq!(parsed.hops[0].index, 1);
    assert_eq!(parsed.hops[0].rtts_ms, vec![1.5]);
    assert_eq!(parsed.hops[19].index, 20);
    assert!(!parsed.reached_target);
}

#[test]
fn parser_reached_target_uses_only_terminal_trace_evidence() {
    let earlier_target = parse_traceroute(
        " 1  198.51.100.20  1 ms\n 2  203.0.113.2  2 ms\n",
        ip("198.51.100.20"),
    )
    .unwrap();
    assert!(!earlier_target.reached_target);

    let terminal_target = parse_traceroute(
        " 1  203.0.113.1  1 ms\n 2  198.51.100.20  2 ms\n",
        ip("198.51.100.20"),
    )
    .unwrap();
    assert!(terminal_target.reached_target);
}

#[test]
fn parser_ignores_later_duplicate_hops_and_keeps_the_first_emitted_evidence() {
    let parsed = parse_traceroute(
        " 1  203.0.113.1  1 ms\n 2  198.51.100.20  2 ms\n 2  203.0.113.2  20 ms\n",
        ip("198.51.100.20"),
    )
    .unwrap();

    assert_eq!(parsed.hops[1].address, Some(ip("198.51.100.20")));
    assert!(parsed.reached_target);
}

#[test]
fn parser_finalizes_out_of_order_hops_once_and_uses_the_highest_finalized_hop() {
    let parsed = parse_traceroute(
        " 3  203.0.113.3  3 ms\n 1  203.0.113.1  1 ms\n 2  198.51.100.20  2 ms\n",
        ip("198.51.100.20"),
    )
    .unwrap();

    assert_eq!(parsed.hops.len(), 3);
    assert_eq!(parsed.hops[0].address, None);
    assert_eq!(parsed.hops[1].address, None);
    assert_eq!(parsed.hops[2].address, Some(ip("203.0.113.3")));
    assert!(!parsed.reached_target);
}

#[test]
fn parser_keeps_a_target_among_multiple_terminal_responder_addresses() {
    let parsed = parse_traceroute(
        " 1  203.0.113.1  1 ms\n 2  203.0.113.2  198.51.100.20  2 ms  3 ms\n",
        ip("198.51.100.20"),
    )
    .unwrap();

    assert_eq!(parsed.hops[1].address, Some(ip("198.51.100.20")));
    assert!(parsed.reached_target);
}

#[test]
fn parser_ignores_trailing_malformed_and_non_hop_lines_for_terminal_evidence() {
    let parsed = parse_traceroute(
        " 1  203.0.113.1  1 ms\n 2  198.51.100.20  2 ms\ntraceroute complete\ngarbage 198.51.100.20 3 ms\n",
        ip("198.51.100.20"),
    )
    .unwrap();

    assert!(parsed.reached_target);
    assert_eq!(parsed.hops.len(), 2);
}

#[derive(Default)]
struct RecordingProgress {
    hops: Mutex<Vec<network_path_agent::domain::TraceHop>>,
    notified: Notify,
}

type Invocation = (String, Vec<String>);

impl TraceProgressSink for RecordingProgress {
    fn emit(&self, hop: network_path_agent::domain::TraceHop) {
        self.hops.lock().unwrap().push(hop);
        self.notified.notify_waiters();
    }
}

#[derive(Clone)]
struct FixtureFactory {
    invocations: Arc<Mutex<Vec<Invocation>>>,
    process: Arc<Mutex<Option<FixtureProcess>>>,
    spawn_error: Arc<Mutex<Option<String>>>,
}

impl FixtureFactory {
    fn process(process: FixtureProcess) -> Self {
        Self {
            invocations: Arc::new(Mutex::new(Vec::new())),
            process: Arc::new(Mutex::new(Some(process))),
            spawn_error: Arc::new(Mutex::new(None)),
        }
    }

    fn spawn_error(message: &str) -> Self {
        Self {
            invocations: Arc::new(Mutex::new(Vec::new())),
            process: Arc::new(Mutex::new(None)),
            spawn_error: Arc::new(Mutex::new(Some(message.into()))),
        }
    }
}

#[async_trait]
impl TraceProcessFactory for FixtureFactory {
    async fn spawn(
        &self,
        executable: &str,
        arguments: &[String],
    ) -> Result<Box<dyn TraceProcess>, DiagnosticError> {
        self.invocations
            .lock()
            .unwrap()
            .push((executable.into(), arguments.to_vec()));
        if let Some(message) = self.spawn_error.lock().unwrap().clone() {
            return Err(DiagnosticError::System(message));
        }
        self.process
            .lock()
            .unwrap()
            .take()
            .map(|process| Box::new(process) as Box<dyn TraceProcess>)
            .ok_or_else(|| DiagnosticError::System("fixture process missing".into()))
    }
}

struct FixtureProcess {
    lines: VecDeque<Result<Option<Vec<u8>>, DiagnosticError>>,
    exit: TraceExitStatus,
    wait_pending: bool,
    line_pending_after_exhaustion: bool,
    killed: Arc<AtomicUsize>,
    waited: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
    spawned: Arc<Notify>,
    drop_notify: Arc<Notify>,
}

impl FixtureProcess {
    fn ready(
        lines: impl IntoIterator<Item = &'static [u8]>,
        exit: TraceExitStatus,
    ) -> (Self, ProcessCounters) {
        let counters = ProcessCounters::default();
        (
            Self {
                lines: lines
                    .into_iter()
                    .map(|line| Ok(Some(line.to_vec())))
                    .chain(std::iter::once(Ok(None)))
                    .collect(),
                exit,
                wait_pending: false,
                line_pending_after_exhaustion: false,
                killed: Arc::clone(&counters.killed),
                waited: Arc::clone(&counters.waited),
                dropped: Arc::clone(&counters.dropped),
                spawned: Arc::clone(&counters.spawned),
                drop_notify: Arc::clone(&counters.drop_notify),
            },
            counters,
        )
    }

    fn pending() -> (Self, ProcessCounters) {
        let counters = ProcessCounters::default();
        (
            Self {
                lines: VecDeque::new(),
                exit: TraceExitStatus::success(),
                wait_pending: false,
                line_pending_after_exhaustion: true,
                killed: Arc::clone(&counters.killed),
                waited: Arc::clone(&counters.waited),
                dropped: Arc::clone(&counters.dropped),
                spawned: Arc::clone(&counters.spawned),
                drop_notify: Arc::clone(&counters.drop_notify),
            },
            counters,
        )
    }
}

#[derive(Clone, Default)]
struct ProcessCounters {
    killed: Arc<AtomicUsize>,
    waited: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
    spawned: Arc<Notify>,
    drop_notify: Arc<Notify>,
}

#[async_trait]
impl TraceProcess for FixtureProcess {
    async fn next_stdout_line(&mut self) -> Result<Option<Vec<u8>>, DiagnosticError> {
        self.spawned.notify_one();
        if let Some(line) = self.lines.pop_front() {
            return line;
        }
        if self.line_pending_after_exhaustion {
            std::future::pending::<()>().await;
        }
        Ok(None)
    }

    async fn wait(&mut self) -> Result<TraceExitStatus, DiagnosticError> {
        self.waited.fetch_add(1, Ordering::SeqCst);
        if self.wait_pending {
            std::future::pending::<()>().await;
        }
        Ok(self.exit)
    }

    async fn kill(&mut self) -> Result<(), DiagnosticError> {
        self.killed.fetch_add(1, Ordering::SeqCst);
        self.line_pending_after_exhaustion = false;
        self.wait_pending = false;
        Ok(())
    }
}

impl Drop for FixtureProcess {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
        self.drop_notify.notify_one();
    }
}

#[tokio::test]
async fn runner_streams_stdout_progress_and_uses_exact_fixed_argv_for_ipv4() {
    let (process, counters) = FixtureProcess::ready(
        [
            b" 1  192.168.1.1  1.25 ms  2.5 ms\n".as_slice(),
            b" 2  * * *\n".as_slice(),
            b" 3  198.51.100.20  5.0 ms\n".as_slice(),
        ],
        TraceExitStatus::success(),
    );
    let factory = FixtureFactory::process(process);
    let tracer = MacRouteTracer::with_process_factory(Arc::new(factory.clone()));
    let progress = RecordingProgress::default();

    let result = tracer
        .trace(
            network_path_agent::domain::TraceTarget {
                kind: network_path_agent::domain::TraceTargetKind::ActualProxy,
                ip: ip("198.51.100.20"),
            },
            &progress,
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(result.hops.len(), 3);
    assert!(result.reached_target);
    assert_eq!(result.hops[1].address, None);
    assert_eq!(result.hops[0].rtts_ms, vec![1.25, 2.5]);
    assert_eq!(
        *progress.hops.lock().unwrap(),
        result.hops,
        "each streamed hop is emitted in deterministic order"
    );
    assert_eq!(
        *factory.invocations.lock().unwrap(),
        vec![(
            "/usr/sbin/traceroute".into(),
            vec![
                "-n".into(),
                "-m".into(),
                "20".into(),
                "-q".into(),
                "2".into(),
                "-w".into(),
                "1".into(),
                "198.51.100.20".into(),
            ],
        )]
    );
    assert_eq!(counters.waited.load(Ordering::SeqCst), 1);
    assert_eq!(counters.killed.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn runner_keeps_streamed_progress_and_final_hops_consistent_for_late_lines() {
    let (process, _) = FixtureProcess::ready(
        [
            b" 3  203.0.113.3  3 ms\n".as_slice(),
            b" 1  203.0.113.1  1 ms\n".as_slice(),
            b" 2  198.51.100.20  2 ms\n".as_slice(),
            b" 3  203.0.113.30  30 ms\n".as_slice(),
        ],
        TraceExitStatus::success(),
    );
    let factory = FixtureFactory::process(process);
    let tracer = MacRouteTracer::with_process_factory(Arc::new(factory));
    let progress = RecordingProgress::default();

    let result = tracer
        .trace(
            network_path_agent::domain::TraceTarget {
                kind: network_path_agent::domain::TraceTargetKind::ActualDestination,
                ip: ip("198.51.100.20"),
            },
            &progress,
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(*progress.hops.lock().unwrap(), result.hops);
    assert_eq!(result.hops[2].address, Some(ip("203.0.113.3")));
    assert!(!result.reached_target);
}

#[tokio::test]
async fn runner_uses_traceroute6_for_ipv6_targets() {
    let (process, _) = FixtureProcess::ready(
        [b" 1  2001:db8::1  1.5 ms\n".as_slice()],
        TraceExitStatus::success(),
    );
    let factory = FixtureFactory::process(process);
    let tracer = MacRouteTracer::with_process_factory(Arc::new(factory.clone()));

    tracer
        .trace(
            network_path_agent::domain::TraceTarget {
                kind: network_path_agent::domain::TraceTargetKind::ReferenceDestination,
                ip: ip("2001:db8::1"),
            },
            &RecordingProgress::default(),
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(
        factory.invocations.lock().unwrap()[0],
        (
            "/usr/sbin/traceroute6".into(),
            vec![
                "-n".into(),
                "-m".into(),
                "20".into(),
                "-q".into(),
                "2".into(),
                "-w".into(),
                "1".into(),
                "2001:db8::1".into(),
            ],
        )
    );
}

#[tokio::test]
async fn cancellation_kills_and_reaps_the_owned_process() {
    let (process, counters) = FixtureProcess::pending();
    let factory = FixtureFactory::process(process);
    let tracer = MacRouteTracer::with_process_factory(Arc::new(factory));
    let cancel = CancellationToken::new();
    let cancel_for_task = cancel.clone();
    let task: JoinHandle<Result<_, _>> = tokio::spawn(async move {
        tracer
            .trace(
                network_path_agent::domain::TraceTarget {
                    kind: network_path_agent::domain::TraceTargetKind::ActualProxy,
                    ip: ip("198.51.100.20"),
                },
                &RecordingProgress::default(),
                cancel_for_task,
            )
            .await
    });
    tokio::task::yield_now().await;
    cancel.cancel();

    let error = task.await.unwrap().unwrap_err();
    assert_eq!(error.to_string(), "网络跳点探测已取消");
    assert_eq!(counters.killed.load(Ordering::SeqCst), 1);
    assert_eq!(counters.waited.load(Ordering::SeqCst), 1);
    assert_eq!(counters.dropped.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn total_timeout_kills_and_reaps_the_owned_process() {
    let (process, counters) = FixtureProcess::pending();
    let factory = FixtureFactory::process(process);
    let tracer = MacRouteTracer::with_process_factory(Arc::new(factory))
        .with_timeout(Duration::from_millis(10));

    let error = tracer
        .trace(
            network_path_agent::domain::TraceTarget {
                kind: network_path_agent::domain::TraceTargetKind::ActualDestination,
                ip: ip("203.0.113.9"),
            },
            &RecordingProgress::default(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.to_string(), "网络跳点探测超时");
    assert_eq!(counters.killed.load(Ordering::SeqCst), 1);
    assert_eq!(counters.waited.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn dropping_trace_future_drops_the_owned_process_without_detached_work() {
    let (process, counters) = FixtureProcess::pending();
    let factory = FixtureFactory::process(process);
    let tracer = MacRouteTracer::with_process_factory(Arc::new(factory));
    let (started_tx, started_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let result = tracer
            .trace(
                network_path_agent::domain::TraceTarget {
                    kind: network_path_agent::domain::TraceTargetKind::ActualDestination,
                    ip: ip("203.0.113.9"),
                },
                &RecordingProgress::default(),
                CancellationToken::new(),
            )
            .await;
        let _ = started_tx.send(());
        result
    });
    tokio::time::timeout(Duration::from_secs(1), counters.spawned.notified())
        .await
        .unwrap();
    task.abort();
    let _ = task.await;
    tokio::time::timeout(Duration::from_secs(1), counters.drop_notify.notified())
        .await
        .unwrap();
    let _ = started_rx.await;

    assert_eq!(counters.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(counters.killed.load(Ordering::SeqCst), 0);
    assert_eq!(counters.waited.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn nonzero_utf8_and_spawn_failures_are_generic_and_redact_process_details() {
    let (nonzero_process, _) = FixtureProcess::ready(
        [b" 1  198.51.100.20  1 ms\n".as_slice()],
        TraceExitStatus::failure(7),
    );
    let nonzero =
        MacRouteTracer::with_process_factory(Arc::new(FixtureFactory::process(nonzero_process)));
    let nonzero_error = nonzero
        .trace(
            network_path_agent::domain::TraceTarget {
                kind: network_path_agent::domain::TraceTargetKind::ActualProxy,
                ip: ip("198.51.100.20"),
            },
            &RecordingProgress::default(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err()
        .to_string();

    assert_eq!(nonzero_error, "网络跳点探测失败");
    assert!(!nonzero_error.contains('7'));
    assert!(!nonzero_error.contains("stderr-secret"));

    let (utf8_process, _) =
        FixtureProcess::ready([b"\xff\n".as_slice()], TraceExitStatus::success());
    let utf8 =
        MacRouteTracer::with_process_factory(Arc::new(FixtureFactory::process(utf8_process)));
    let utf8_error = utf8
        .trace(
            network_path_agent::domain::TraceTarget {
                kind: network_path_agent::domain::TraceTargetKind::ActualDestination,
                ip: ip("203.0.113.9"),
            },
            &RecordingProgress::default(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(utf8_error, "网络跳点探测失败");
    assert!(!utf8_error.contains("ff"));

    let spawn = MacRouteTracer::with_process_factory(Arc::new(FixtureFactory::spawn_error(
        "private stderr-secret and /private/path",
    )));
    let spawn_error = spawn
        .trace(
            network_path_agent::domain::TraceTarget {
                kind: network_path_agent::domain::TraceTargetKind::ActualDestination,
                ip: ip("203.0.113.9"),
            },
            &RecordingProgress::default(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(spawn_error, "网络跳点探测失败");
    assert!(!spawn_error.contains("stderr-secret"));
    assert!(!spawn_error.contains("/private/path"));
}

#[test]
fn trace_contract_serializes_fractional_rtts_without_eq_requirements() {
    let hop = network_path_agent::domain::TraceHop {
        index: 1,
        address: Some(ip("2001:db8::1")),
        rtts_ms: vec![0.25, 1.5],
        level: EvidenceLevel::Confirmed,
    };
    let json = serde_json::to_string(&hop).unwrap();
    assert!(json.contains("0.25"));
    assert!(json.contains("1.5"));
    assert!(!json.contains("rtts_ms\":[]"));
}

#[test]
fn trace_contract_rejects_non_finite_and_negative_rtts_on_serialization() {
    for rtt in [-1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let hop = network_path_agent::domain::TraceHop {
            index: 1,
            address: None,
            rtts_ms: vec![rtt],
            level: EvidenceLevel::Confirmed,
        };

        assert!(
            serde_json::to_value(hop).is_err(),
            "invalid RTT {rtt:?} must not serialize"
        );
    }
}

#[test]
fn trace_contract_rejects_invalid_rtts_on_deserialization() {
    let base = serde_json::json!({
        "index": 1,
        "address": null,
        "rtts_ms": [0.0],
        "level": "confirmed"
    });
    for invalid in [
        serde_json::json!([-1.0]),
        serde_json::json!([null]),
        serde_json::json!(["1.5"]),
    ] {
        let mut value = base.clone();
        value["rtts_ms"] = invalid;
        assert!(
            serde_json::from_value::<network_path_agent::domain::TraceHop>(value).is_err(),
            "invalid RTT JSON must not deserialize"
        );
    }

    for non_finite in [
        r#"{"index":1,"address":null,"rtts_ms":[NaN],"level":"confirmed"}"#,
        r#"{"index":1,"address":null,"rtts_ms":[Infinity],"level":"confirmed"}"#,
        r#"{"index":1,"address":null,"rtts_ms":[-Infinity],"level":"confirmed"}"#,
    ] {
        assert!(
            serde_json::from_str::<network_path_agent::domain::TraceHop>(non_finite).is_err(),
            "non-finite RTT JSON must not deserialize"
        );
    }
}

#[test]
fn trace_contract_accepts_zero_and_fractional_rtts_at_both_boundaries() {
    let hop = network_path_agent::domain::TraceHop {
        index: 1,
        address: None,
        rtts_ms: vec![0.0, 0.25, 1.5],
        level: EvidenceLevel::Confirmed,
    };

    let json = serde_json::to_value(&hop).unwrap();
    let round_trip: network_path_agent::domain::TraceHop = serde_json::from_value(json).unwrap();
    assert_eq!(round_trip.rtts_ms, vec![0.0, 0.25, 1.5]);
}

#[allow(dead_code)]
fn _keep_socket_addr_import_used() -> SocketAddr {
    "127.0.0.1:443".parse().unwrap()
}

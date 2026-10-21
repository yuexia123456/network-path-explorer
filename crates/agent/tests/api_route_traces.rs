use async_trait::async_trait;
use axum::{
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
};
use futures_util::stream;
use http_body_util::BodyExt;
use network_path_agent::{
    api::{AppState, TraceStore, UrlRunner, build_router},
    domain::{
        Conclusion, Evidence, EvidenceLevel, HttpObservation, PeerEndpoint, ProxyDecision,
        ProxyKind, RouteTraceResult, TraceHop, TraceTarget, TraceTargetKind, TrafficDecision,
        TrafficDecisionKind, TrafficNode, TrafficNodeKind, UrlDiagnosticResult,
    },
    error::DiagnosticError,
    ports::{ProgressSink, RouteTracer, TraceProgressSink},
};
use std::{
    future::pending,
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use uuid::Uuid;

const PORT: u16 = 8765;
const TOKEN: &str = "secret-token";

struct ImmediateRunner;

#[async_trait]
impl UrlRunner for ImmediateRunner {
    async fn run(
        &self,
        input: &str,
        _progress: &dyn ProgressSink,
    ) -> Result<UrlDiagnosticResult, DiagnosticError> {
        Ok(result(input))
    }
}

struct ResultRunner {
    result: UrlDiagnosticResult,
}

#[async_trait]
impl UrlRunner for ResultRunner {
    async fn run(
        &self,
        _input: &str,
        _progress: &dyn ProgressSink,
    ) -> Result<UrlDiagnosticResult, DiagnosticError> {
        Ok(self.result.clone())
    }
}

struct ShutdownCheckingRunner {
    result: UrlDiagnosticResult,
    active_traces: Arc<AtomicUsize>,
    saw_traces_drained: Arc<AtomicUsize>,
}

#[async_trait]
impl UrlRunner for ShutdownCheckingRunner {
    async fn run(
        &self,
        _input: &str,
        _progress: &dyn ProgressSink,
    ) -> Result<UrlDiagnosticResult, DiagnosticError> {
        Ok(self.result.clone())
    }

    async fn shutdown(&self) {
        self.saw_traces_drained.store(
            usize::from(self.active_traces.load(Ordering::SeqCst) == 0),
            Ordering::SeqCst,
        );
    }
}

struct PendingRunner;

#[async_trait]
impl UrlRunner for PendingRunner {
    async fn run(
        &self,
        _input: &str,
        _progress: &dyn ProgressSink,
    ) -> Result<UrlDiagnosticResult, DiagnosticError> {
        pending().await
    }
}

struct FailedRunner;

#[async_trait]
impl UrlRunner for FailedRunner {
    async fn run(
        &self,
        _input: &str,
        _progress: &dyn ProgressSink,
    ) -> Result<UrlDiagnosticResult, DiagnosticError> {
        Err(DiagnosticError::Http("private target=203.0.113.20".into()))
    }
}

#[derive(Clone, Copy)]
enum TraceBehavior {
    Immediate,
    Blocking,
    Late,
    Panic,
    Error,
    Overflow,
}

struct FixtureTracer {
    behavior: TraceBehavior,
    started: Arc<Notify>,
    release: Arc<Notify>,
    active: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
    late_completed: Arc<AtomicUsize>,
    targets: Arc<Mutex<Vec<TraceTarget>>>,
}

struct ActiveTrace(Arc<AtomicUsize>);

impl Drop for ActiveTrace {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl RouteTracer for FixtureTracer {
    async fn trace(
        &self,
        target: TraceTarget,
        progress: &dyn TraceProgressSink,
        cancel: CancellationToken,
    ) -> Result<RouteTraceResult, DiagnosticError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.targets.lock().unwrap().push(target);
        self.active.fetch_add(1, Ordering::SeqCst);
        let _active = ActiveTrace(Arc::clone(&self.active));
        self.started.notify_waiters();
        match self.behavior {
            TraceBehavior::Immediate => {
                progress.emit(hop(1, Some("198.51.100.1")));
                Ok(trace_result(target))
            }
            TraceBehavior::Blocking => {
                tokio::select! {
                    _ = cancel.cancelled() => Err(DiagnosticError::RouteTraceCancelled),
                    _ = self.release.notified() => Ok(trace_result(target)),
                }
            }
            TraceBehavior::Late => {
                self.release.notified().await;
                self.late_completed.fetch_add(1, Ordering::SeqCst);
                Ok(trace_result(target))
            }
            TraceBehavior::Panic => panic!("trace panic target={}", target.ip),
            TraceBehavior::Error => Err(DiagnosticError::System(format!(
                "raw target={} secret=private",
                target.ip
            ))),
            TraceBehavior::Overflow => {
                for index in 1..=40 {
                    progress.emit(hop(index as u8, None));
                }
                Ok(trace_result(target))
            }
        }
    }
}

fn request(method: &str, path: &str, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("host", "127.0.0.1:8765")
        .header("origin", "http://127.0.0.1:8765")
        .header("x-npe-session", TOKEN)
        .body(body.into())
        .unwrap()
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

fn fixture_tracer(behavior: TraceBehavior) -> (Arc<FixtureTracer>, Arc<Notify>) {
    let release = Arc::new(Notify::new());
    let tracer = Arc::new(FixtureTracer {
        behavior,
        started: Arc::new(Notify::new()),
        release: Arc::clone(&release),
        active: Arc::new(AtomicUsize::new(0)),
        calls: Arc::new(AtomicUsize::new(0)),
        late_completed: Arc::new(AtomicUsize::new(0)),
        targets: Arc::new(Mutex::new(Vec::new())),
    });
    (tracer, release)
}

struct CleanupSignals {
    started: Notify,
    cleanup_done: Notify,
    cleanup_complete: AtomicBool,
    future_dropped: AtomicBool,
    events: Mutex<Vec<&'static str>>,
}

impl CleanupSignals {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            started: Notify::new(),
            cleanup_done: Notify::new(),
            cleanup_complete: AtomicBool::new(false),
            future_dropped: AtomicBool::new(false),
            events: Mutex::new(Vec::new()),
        })
    }

    fn record(&self, event: &'static str) {
        self.events.lock().unwrap().push(event);
    }

    fn complete(&self) {
        self.record("cleanup_complete");
        self.cleanup_complete.store(true, Ordering::SeqCst);
        self.cleanup_done.notify_one();
    }

    fn events(&self) -> Vec<&'static str> {
        self.events.lock().unwrap().clone()
    }
}

struct CleanupProcess {
    signals: Arc<CleanupSignals>,
}

impl CleanupProcess {
    async fn kill(&self) {
        self.signals.record("kill");
    }

    async fn wait(&self) {
        self.signals.record("wait");
    }
}

struct CleanupFutureGuard {
    signals: Arc<CleanupSignals>,
}

impl Drop for CleanupFutureGuard {
    fn drop(&mut self) {
        if !self.signals.cleanup_complete.load(Ordering::SeqCst) {
            self.signals.future_dropped.store(true, Ordering::SeqCst);
            self.signals.record("future_dropped");
        }
    }
}

struct ControlledCleanupTracer {
    signals: Arc<CleanupSignals>,
}

#[async_trait]
impl RouteTracer for ControlledCleanupTracer {
    async fn trace(
        &self,
        _target: TraceTarget,
        _progress: &dyn TraceProgressSink,
        cancel: CancellationToken,
    ) -> Result<RouteTraceResult, DiagnosticError> {
        let _guard = CleanupFutureGuard {
            signals: Arc::clone(&self.signals),
        };
        self.signals.record("started");
        self.signals.started.notify_one();
        cancel.cancelled().await;
        let process = CleanupProcess {
            signals: Arc::clone(&self.signals),
        };
        process.kill().await;
        process.wait().await;
        self.signals.complete();
        Err(DiagnosticError::RouteTraceCancelled)
    }
}

struct CleanupCheckingRunner {
    result: UrlDiagnosticResult,
    signals: Arc<CleanupSignals>,
    saw_cleanup_before_shutdown: Arc<AtomicBool>,
}

#[async_trait]
impl UrlRunner for CleanupCheckingRunner {
    async fn run(
        &self,
        _input: &str,
        _progress: &dyn ProgressSink,
    ) -> Result<UrlDiagnosticResult, DiagnosticError> {
        Ok(self.result.clone())
    }

    async fn shutdown(&self) {
        self.saw_cleanup_before_shutdown.store(
            self.signals.cleanup_complete.load(Ordering::SeqCst),
            Ordering::SeqCst,
        );
    }
}

fn app_with_controlled_cleanup(
    runner: Arc<dyn UrlRunner>,
) -> (
    axum::Router,
    network_path_agent::api::AppState,
    Arc<CleanupSignals>,
) {
    let signals = CleanupSignals::new();
    let tracer = Arc::new(ControlledCleanupTracer {
        signals: Arc::clone(&signals),
    });
    let state =
        AppState::new(PORT, TOKEN, runner).with_route_tracer(tracer as Arc<dyn RouteTracer>);
    (build_router(state.clone()), state, signals)
}

async fn wait_for_cleanup(signals: &CleanupSignals) {
    if !signals.cleanup_complete.load(Ordering::SeqCst) {
        tokio::time::timeout(Duration::from_secs(1), signals.cleanup_done.notified())
            .await
            .expect("tracer cleanup must complete");
    }
    assert!(signals.cleanup_complete.load(Ordering::SeqCst));
}

fn app_with(
    result: UrlDiagnosticResult,
    behavior: TraceBehavior,
) -> (
    axum::Router,
    network_path_agent::api::AppState,
    Arc<FixtureTracer>,
    Arc<Notify>,
) {
    let (tracer, release) = fixture_tracer(behavior);
    let state =
        network_path_agent::api::AppState::new(PORT, TOKEN, Arc::new(ResultRunner { result }))
            .with_route_tracer(Arc::clone(&tracer) as Arc<dyn RouteTracer>);
    (build_router(state.clone()), state, tracer, release)
}

fn app_with_store(
    result: UrlDiagnosticResult,
    behavior: TraceBehavior,
    retention: Duration,
) -> (
    axum::Router,
    network_path_agent::api::AppState,
    Arc<FixtureTracer>,
    Arc<Notify>,
) {
    let (tracer, release) = fixture_tracer(behavior);
    let state =
        network_path_agent::api::AppState::new(PORT, TOKEN, Arc::new(ResultRunner { result }))
            .with_route_tracer(Arc::clone(&tracer) as Arc<dyn RouteTracer>)
            .with_trace_store(TraceStore::with_retention(retention));
    (build_router(state.clone()), state, tracer, release)
}

async fn post_run_and_wait(app: &axum::Router) -> String {
    let accepted = app
        .clone()
        .oneshot(request(
            "POST",
            "/api/v1/url-diagnostics",
            r#"{"url":"https://example.com"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let run_id = json(accepted).await["run_id"].as_str().unwrap().to_owned();
    for _ in 0..100 {
        let response = app
            .clone()
            .oneshot(request(
                "GET",
                &format!("/api/v1/runs/{run_id}"),
                Body::empty(),
            ))
            .await
            .unwrap();
        let snapshot = json(response).await;
        if snapshot["status"] == "completed" || snapshot["status"] == "failed" {
            return run_id;
        }
        tokio::task::yield_now().await;
    }
    panic!("URL run {run_id} did not finish");
}

async fn trace_snapshot(app: &axum::Router, run_id: &str) -> serde_json::Value {
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    json(response).await
}

async fn wait_for_trace_status(
    app: &axum::Router,
    run_id: &str,
    wanted: &str,
) -> serde_json::Value {
    for _ in 0..100 {
        let snapshot = trace_snapshot(app, run_id).await;
        if snapshot["status"] == wanted {
            return snapshot;
        }
        tokio::task::yield_now().await;
    }
    panic!("trace {run_id} did not become {wanted}");
}

async fn trace_events(app: &axum::Router, run_id: &str) -> Vec<serde_json::Value> {
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/api/v1/runs/{run_id}/route-trace/events"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream")
    );
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
    .lines()
    .filter_map(|line| line.strip_prefix("data: "))
    .map(|line| serde_json::from_str(line).unwrap())
    .collect()
}

fn trace_result(target: TraceTarget) -> RouteTraceResult {
    RouteTraceResult {
        target,
        hops: vec![hop(1, Some("198.51.100.1"))],
        reached_target: false,
        elapsed_ms: 3,
    }
}

fn hop(index: u8, address: Option<&str>) -> TraceHop {
    TraceHop {
        index,
        address: address.map(|value| value.parse().unwrap()),
        rtts_ms: vec![1.5],
        level: EvidenceLevel::Confirmed,
    }
}

fn direct_result(input: &str) -> UrlDiagnosticResult {
    let mut value = result(input);
    value.resolved_ips = vec!["203.0.113.10".parse().unwrap()];
    value.http.peer_endpoint = Some(PeerEndpoint {
        ip: "203.0.113.10".parse().unwrap(),
        port: 443,
    });
    value.traffic_decision = TrafficDecision {
        kind: TrafficDecisionKind::Direct,
        mode: Some("Rule".into()),
        tun_enabled: Some(true),
        rule: None,
        chain: Vec::new(),
        evidence: vec![Evidence {
            level: EvidenceLevel::Confirmed,
            source: "fixture".into(),
            summary: "confirmed direct".into(),
        }],
    };
    value
}

fn proxy_result(input: &str) -> UrlDiagnosticResult {
    let mut value = direct_result(input);
    value.http.peer_endpoint = Some(PeerEndpoint {
        ip: "127.0.0.1".parse().unwrap(),
        port: 7890,
    });
    value.traffic_decision = TrafficDecision {
        kind: TrafficDecisionKind::Proxy,
        mode: Some("Rule".into()),
        tun_enabled: Some(true),
        rule: None,
        chain: vec![TrafficNode {
            kind: TrafficNodeKind::ProxyNode,
            name: "fixture-node".into(),
            node_type: Some("http".into()),
            endpoint: Some(PeerEndpoint {
                ip: "198.51.100.20".parse().unwrap(),
                port: 443,
            }),
            alive: Some(true),
            delay_ms: Some(2),
            level: EvidenceLevel::Confirmed,
            evidence: vec![],
        }],
        evidence: vec![Evidence {
            level: EvidenceLevel::Confirmed,
            source: "fixture".into(),
            summary: "confirmed proxy".into(),
        }],
    };
    value
}

#[tokio::test]
async fn completed_url_run_without_an_actual_target_returns_a_stable_trace_error() {
    let app = build_router(AppState::new(PORT, TOKEN, Arc::new(ImmediateRunner)));
    let accepted = app
        .clone()
        .oneshot(request(
            "POST",
            "/api/v1/url-diagnostics",
            r#"{"url":"https://example.com"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let run_id = json(accepted).await["run_id"].as_str().unwrap().to_owned();

    for _ in 0..50 {
        let snapshot = app
            .clone()
            .oneshot(request(
                "GET",
                &format!("/api/v1/runs/{run_id}"),
                Body::empty(),
            ))
            .await
            .unwrap();
        if json(snapshot).await["status"] == "completed" {
            break;
        }
        tokio::task::yield_now().await;
    }

    let response = app
        .oneshot(request(
            "POST",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            r#"{"kind":"actual"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json(response).await,
        serde_json::json!({
            "code": "trace_target_unavailable",
            "message": "当前网址没有可确认的实际跳点目标"
        })
    );
}

#[tokio::test]
async fn completed_url_run_can_start_and_cancel_a_trace() {
    let (app, state, tracer, _release) = app_with(
        direct_result("https://example.com"),
        TraceBehavior::Blocking,
    );
    let run_id = post_run_and_wait(&app).await;
    let accepted = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            r#"{"kind":"actual"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    assert_eq!(json(accepted).await["status"], "running");

    for _ in 0..100 {
        if tracer.active.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    let cancelled = app
        .clone()
        .oneshot(request(
            "DELETE",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(cancelled.status(), StatusCode::NO_CONTENT);
    let snapshot = wait_for_trace_status(&app, &run_id, "cancelled").await;
    assert_eq!(snapshot["error"]["code"], "trace_cancelled");
    state.shutdown().await;
}

#[tokio::test]
async fn reference_trace_uses_the_first_completed_run_resolution_without_actual_evidence() {
    let mut reference = result("https://example.com");
    reference.resolved_ips = vec!["198.51.100.42".parse().unwrap()];
    let (app, state, tracer, _release) = app_with(reference, TraceBehavior::Immediate);
    let run_id = post_run_and_wait(&app).await;
    let accepted = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            r#"{"kind":"reference"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let completed = wait_for_trace_status(&app, &run_id, "completed").await;
    assert_eq!(
        completed["result"]["target"]["kind"],
        "reference_destination"
    );
    assert_eq!(completed["result"]["target"]["ip"], "198.51.100.42");
    assert_eq!(
        tracer.targets.lock().unwrap()[0].kind,
        TraceTargetKind::ReferenceDestination
    );
    state.shutdown().await;
}

#[tokio::test]
async fn actual_proxy_trace_uses_the_first_confirmed_remote_chain_endpoint() {
    let (app, state, tracer, _release) = app_with(
        proxy_result("https://example.com"),
        TraceBehavior::Immediate,
    );
    let run_id = post_run_and_wait(&app).await;
    app.clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            r#"{"kind":"actual"}"#,
        ))
        .await
        .unwrap();
    let completed = wait_for_trace_status(&app, &run_id, "completed").await;
    assert_eq!(completed["result"]["target"]["kind"], "actual_proxy");
    assert_eq!(completed["result"]["target"]["ip"], "198.51.100.20");
    assert_eq!(
        tracer.targets.lock().unwrap()[0].ip,
        "198.51.100.20".parse::<std::net::IpAddr>().unwrap()
    );
    state.shutdown().await;
}

#[tokio::test]
async fn running_failed_and_missing_url_runs_are_not_traceable() {
    let pending_state = AppState::new(PORT, TOKEN, Arc::new(PendingRunner));
    let pending = build_router(pending_state.clone());
    let pending_run = {
        let accepted = pending
            .clone()
            .oneshot(request(
                "POST",
                "/api/v1/url-diagnostics",
                r#"{"url":"https://example.com"}"#,
            ))
            .await
            .unwrap();
        json(accepted).await["run_id"].as_str().unwrap().to_owned()
    };
    let failed_state = AppState::new(PORT, TOKEN, Arc::new(FailedRunner));
    let failed = build_router(failed_state.clone());
    let failed_run = post_run_and_wait(&failed).await;
    for (router, run_id) in [
        (pending.clone(), pending_run),
        (failed.clone(), failed_run),
        (pending.clone(), Uuid::new_v4().to_string()),
    ] {
        let response = router
            .clone()
            .oneshot(request(
                "POST",
                &format!("/api/v1/runs/{run_id}/route-trace"),
                r#"{"kind":"reference"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(json(response).await["code"], "run_not_ready");
    }
    pending_state.shutdown().await;
    failed_state.shutdown().await;
}

#[tokio::test]
async fn duplicate_trace_start_is_deterministically_rejected() {
    let (app, state, tracer, _release) = app_with(
        direct_result("https://example.com"),
        TraceBehavior::Blocking,
    );
    let run_id = post_run_and_wait(&app).await;
    let first = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            r#"{"kind":"actual"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    let duplicate = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            r#"{"kind":"actual"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);
    assert_eq!(json(duplicate).await["code"], "trace_already_started");
    for _ in 0..100 {
        if tracer.calls.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(tracer.calls.load(Ordering::SeqCst), 1);
    state.shutdown().await;
}

#[tokio::test]
async fn successful_trace_replays_ordered_stage_and_hop_events_then_closes() {
    let (app, state, _tracer, _release) = app_with(
        direct_result("https://example.com"),
        TraceBehavior::Immediate,
    );
    let run_id = post_run_and_wait(&app).await;
    let accepted = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            r#"{"kind":"actual"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    wait_for_trace_status(&app, &run_id, "completed").await;
    let events = trace_events(&app, &run_id).await;
    assert_eq!(
        events
            .iter()
            .map(|event| event["stage"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["selecting_target", "probing", "hop", "completed"]
    );
    assert_eq!(events[2]["hop"]["index"], 1);
    assert_eq!(events[0]["sequence"], 0);
    assert_eq!(events[3]["sequence"], 3);
    state.shutdown().await;
}

#[tokio::test]
async fn cancelling_after_completion_is_a_noop_and_preserves_terminal_truth() {
    let (app, state, _tracer, _release) = app_with(
        direct_result("https://example.com"),
        TraceBehavior::Immediate,
    );
    let run_id = post_run_and_wait(&app).await;
    app.clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            r#"{"kind":"actual"}"#,
        ))
        .await
        .unwrap();
    let completed = wait_for_trace_status(&app, &run_id, "completed").await;
    let deleted = app
        .clone()
        .oneshot(request(
            "DELETE",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    let after_delete = trace_snapshot(&app, &run_id).await;
    assert_eq!(after_delete["status"], "completed");
    assert_eq!(after_delete["result"], completed["result"]);
    state.shutdown().await;
}

#[tokio::test]
async fn cancellation_wins_a_late_completion_and_never_exposes_raw_trace_errors() {
    let (app, state, tracer, release) =
        app_with(direct_result("https://example.com"), TraceBehavior::Late);
    let run_id = post_run_and_wait(&app).await;
    let accepted = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            r#"{"kind":"actual"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    for _ in 0..100 {
        if tracer.active.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(tracer.active.load(Ordering::SeqCst), 1);
    let deleted = app
        .clone()
        .oneshot(request(
            "DELETE",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    release.notify_waiters();
    let snapshot = wait_for_trace_status(&app, &run_id, "cancelled").await;
    for _ in 0..100 {
        if tracer.late_completed.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(tracer.late_completed.load(Ordering::SeqCst), 1);
    assert!(snapshot["result"].is_null());
    state.shutdown().await;

    let (app, state, _tracer, _release) =
        app_with(direct_result("https://example.com"), TraceBehavior::Error);
    let run_id = post_run_and_wait(&app).await;
    app.clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            r#"{"kind":"actual"}"#,
        ))
        .await
        .unwrap();
    let failed = wait_for_trace_status(&app, &run_id, "failed").await;
    assert_eq!(failed["error"]["code"], "trace_failed");
    assert!(!failed.to_string().contains("203.0.113.10"));
    assert!(!failed.to_string().contains("private"));
    state.shutdown().await;
}

#[tokio::test]
async fn delete_signals_the_tracer_token_and_waits_for_ordered_process_cleanup() {
    let (app, state, signals) = app_with_controlled_cleanup(Arc::new(ResultRunner {
        result: direct_result("https://example.com"),
    }));
    let run_id = post_run_and_wait(&app).await;
    app.clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            r#"{"kind":"actual"}"#,
        ))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), signals.started.notified())
        .await
        .expect("controlled tracer must start");

    let deleted = app
        .clone()
        .oneshot(request(
            "DELETE",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    wait_for_cleanup(&signals).await;
    assert_eq!(
        signals.events(),
        vec!["started", "kill", "wait", "cleanup_complete"]
    );
    assert!(!signals.future_dropped.load(Ordering::SeqCst));
    assert_eq!(trace_snapshot(&app, &run_id).await["status"], "cancelled");
    state.shutdown().await;
}

#[tokio::test]
async fn tracer_panics_are_sanitized_into_a_failed_terminal_snapshot() {
    let (app, state, _tracer, _release) =
        app_with(direct_result("https://example.com"), TraceBehavior::Panic);
    let run_id = post_run_and_wait(&app).await;
    app.clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            r#"{"kind":"actual"}"#,
        ))
        .await
        .unwrap();
    let failed = wait_for_trace_status(&app, &run_id, "failed").await;
    assert_eq!(failed["error"]["code"], "trace_failed");
    assert!(!failed.to_string().contains("trace panic"));
    assert!(!failed.to_string().contains("203.0.113.10"));
    state.shutdown().await;
}

#[tokio::test]
async fn tracer_panic_payload_never_reaches_stderr_and_api_stays_generic() {
    if std::env::var_os("TASK_8_TRACE_PANIC_CHILD").is_some() {
        let (app, state, _tracer, _release) =
            app_with(direct_result("https://example.com"), TraceBehavior::Panic);
        let run_id = post_run_and_wait(&app).await;
        app.clone()
            .oneshot(request(
                "POST",
                &format!("/api/v1/runs/{run_id}/route-trace"),
                r#"{"kind":"actual"}"#,
            ))
            .await
            .unwrap();
        let failed = wait_for_trace_status(&app, &run_id, "failed").await;
        assert_eq!(failed["error"]["code"], "trace_failed");
        assert_eq!(
            failed["error"]["message"],
            "网络跳点探测未能完成，请稍后重试"
        );
        let events = trace_events(&app, &run_id).await;
        assert_eq!(events.last().unwrap()["stage"], "failed");
        assert!(!events.last().unwrap().to_string().contains("203.0.113.10"));
        state.shutdown().await;
        return;
    }

    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tracer_panic_payload_never_reaches_stderr_and_api_stays_generic",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("TASK_8_TRACE_PANIC_CHILD", "1")
        .output()
        .expect("panic regression child must run");
    assert!(
        output.status.success(),
        "panic regression child failed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("trace panic target=203.0.113.10"));
    assert!(!stderr.contains("203.0.113.10"));
}

#[tokio::test]
async fn replay_keeps_only_the_last_32_events_in_sequence_order() {
    let (app, state, _tracer, _release) = app_with(
        direct_result("https://example.com"),
        TraceBehavior::Overflow,
    );
    let run_id = post_run_and_wait(&app).await;
    app.clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            r#"{"kind":"actual"}"#,
        ))
        .await
        .unwrap();
    wait_for_trace_status(&app, &run_id, "completed").await;
    let events = trace_events(&app, &run_id).await;
    assert_eq!(events.len(), 32);
    let sequences = events
        .iter()
        .map(|event| event["sequence"].as_u64().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(sequences, (11..=42).collect::<Vec<_>>());
    assert_eq!(events.last().unwrap()["stage"], "completed");
    state.shutdown().await;
}

#[tokio::test]
async fn disconnected_sse_does_not_own_or_block_the_trace_worker() {
    let (app, state, tracer, release) = app_with(
        direct_result("https://example.com"),
        TraceBehavior::Blocking,
    );
    let run_id = post_run_and_wait(&app).await;
    app.clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            r#"{"kind":"actual"}"#,
        ))
        .await
        .unwrap();
    for _ in 0..100 {
        if tracer.active.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/api/v1/runs/{run_id}/route-trace/events"),
            Body::empty(),
        ))
        .await
        .unwrap();
    drop(response);
    release.notify_waiters();
    wait_for_trace_status(&app, &run_id, "completed").await;
    state.shutdown().await;
}

#[tokio::test]
async fn shutdown_closes_trace_admission_and_drains_trace_workers_before_the_url_runner() {
    let (tracer, _release) = fixture_tracer(TraceBehavior::Blocking);
    let saw_traces_drained = Arc::new(AtomicUsize::new(0));
    let state = network_path_agent::api::AppState::new(
        PORT,
        TOKEN,
        Arc::new(ShutdownCheckingRunner {
            result: direct_result("https://example.com"),
            active_traces: Arc::clone(&tracer.active),
            saw_traces_drained: Arc::clone(&saw_traces_drained),
        }),
    )
    .with_route_tracer(Arc::clone(&tracer) as Arc<dyn RouteTracer>);
    let app = build_router(state.clone());
    let run_id = post_run_and_wait(&app).await;
    app.clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            r#"{"kind":"actual"}"#,
        ))
        .await
        .unwrap();
    for _ in 0..100 {
        if tracer.active.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    state.shutdown().await;
    assert_eq!(tracer.active.load(Ordering::SeqCst), 0);
    assert_eq!(saw_traces_drained.load(Ordering::SeqCst), 1);
    let rejected = app
        .oneshot(request(
            "POST",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            r#"{"kind":"actual"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json(rejected).await["code"], "shutting_down");
}

#[tokio::test]
async fn shutdown_waits_for_process_kill_and_wait_before_lower_provider_shutdown() {
    let signals = CleanupSignals::new();
    let saw_cleanup_before_shutdown = Arc::new(AtomicBool::new(false));
    let runner = Arc::new(CleanupCheckingRunner {
        result: direct_result("https://example.com"),
        signals: Arc::clone(&signals),
        saw_cleanup_before_shutdown: Arc::clone(&saw_cleanup_before_shutdown),
    });
    let tracer = Arc::new(ControlledCleanupTracer {
        signals: Arc::clone(&signals),
    });
    let state = AppState::new(PORT, TOKEN, runner).with_route_tracer(tracer);
    let app = build_router(state.clone());
    let run_id = post_run_and_wait(&app).await;
    app.clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            r#"{"kind":"actual"}"#,
        ))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), signals.started.notified())
        .await
        .expect("controlled tracer must start");

    state.shutdown().await;

    assert!(signals.cleanup_complete.load(Ordering::SeqCst));
    assert_eq!(
        signals.events(),
        vec!["started", "kill", "wait", "cleanup_complete"]
    );
    assert!(!signals.future_dropped.load(Ordering::SeqCst));
    assert!(saw_cleanup_before_shutdown.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn terminal_trace_expiry_uses_the_paused_clock_but_running_jobs_survive_it() {
    let (app, state, _tracer, release) = app_with_store(
        direct_result("https://example.com"),
        TraceBehavior::Blocking,
        Duration::from_secs(30 * 60),
    );
    let run_id = post_run_and_wait(&app).await;
    app.clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            r#"{"kind":"actual"}"#,
        ))
        .await
        .unwrap();
    tokio::time::advance(Duration::from_secs(30 * 60)).await;
    tokio::task::yield_now().await;
    assert_eq!(trace_snapshot(&app, &run_id).await["status"], "running");
    release.notify_waiters();
    wait_for_trace_status(&app, &run_id, "completed").await;
    tokio::time::advance(Duration::from_secs(30 * 60)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        app.clone()
            .oneshot(request(
                "GET",
                &format!("/api/v1/runs/{run_id}/route-trace"),
                Body::empty(),
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    state.shutdown().await;
}

#[tokio::test]
async fn twenty_trace_workers_are_admitted_and_the_21st_is_rejected() {
    let (app, state, tracer, release) = app_with(
        direct_result("https://example.com"),
        TraceBehavior::Blocking,
    );
    let mut run_ids = Vec::new();
    for _ in 0..21 {
        run_ids.push(post_run_and_wait(&app).await);
    }
    for run_id in run_ids.iter().take(20) {
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                &format!("/api/v1/runs/{run_id}/route-trace"),
                r#"{"kind":"actual"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }
    for _ in 0..100 {
        if tracer.active.load(Ordering::SeqCst) == 20 {
            break;
        }
        tokio::task::yield_now().await;
    }
    let rejected = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/runs/{}/route-trace", run_ids[20]),
            r#"{"kind":"actual"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json(rejected).await["code"], "too_many_traces");
    release.notify_waiters();
    for run_id in run_ids.iter().take(20) {
        wait_for_trace_status(&app, run_id, "completed").await;
    }
    state.shutdown().await;
}

#[tokio::test]
async fn route_trace_post_rejects_unknown_fields_and_the_shared_body_limit() {
    let (app, state, _tracer, _release) = app_with(
        direct_result("https://example.com"),
        TraceBehavior::Immediate,
    );
    let run_id = post_run_and_wait(&app).await;
    let unknown = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            r#"{"kind":"actual","target":"203.0.113.10"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(unknown).await["code"], "invalid_request");
    let oversized = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            Body::from(vec![b'x'; 8 * 1024 + 1]),
        ))
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(json(oversized).await["code"], "payload_too_large");

    let stalled_body = Body::from_stream(stream::once(async {
        pending::<Result<Bytes, std::io::Error>>().await
    }));
    let stalled = tokio::time::timeout(
        Duration::from_secs(2),
        app.clone().oneshot(request(
            "POST",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            stalled_body,
        )),
    )
    .await
    .expect("route-trace body timeout must be bounded")
    .unwrap();
    assert_eq!(stalled.status(), StatusCode::REQUEST_TIMEOUT);
    assert_eq!(json(stalled).await["code"], "request_timeout");
    state.shutdown().await;
}

fn result(input: &str) -> UrlDiagnosticResult {
    UrlDiagnosticResult {
        id: Uuid::new_v4(),
        requested_url: input.into(),
        normalized_url: "https://example.com/".into(),
        resolved_ips: vec![],
        proxy: ProxyDecision {
            kind: ProxyKind::Direct,
            host: None,
            port: None,
            bypass_reason: None,
            evidence: Evidence {
                level: EvidenceLevel::Confirmed,
                source: "test".into(),
                summary: "direct".into(),
            },
        },
        route: None,
        http: HttpObservation {
            status: Some(204),
            final_url: "https://example.com/".into(),
            elapsed_ms: 1,
            error_code: None,
            peer_endpoint: None,
        },
        traffic_decision: TrafficDecision::unknown("fixture", "no actual target"),
        conclusion: Conclusion {
            title: "done".into(),
            summary: "done".into(),
            level: EvidenceLevel::Confirmed,
        },
        evidence: vec![],
    }
}

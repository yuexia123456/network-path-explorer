use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use network_path_agent::{
    api::{AppState, RunStore, UrlRunner, build_router},
    domain::{
        Conclusion, DiagnosticStage, Evidence, EvidenceLevel, HttpObservation, ProxyDecision,
        ProxyKind, TrafficDecision, UrlDiagnosticResult,
    },
    error::DiagnosticError,
    ports::ProgressSink,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
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
        progress: &dyn ProgressSink,
    ) -> Result<UrlDiagnosticResult, DiagnosticError> {
        for stage in [
            DiagnosticStage::Validating,
            DiagnosticStage::Proxy,
            DiagnosticStage::Dns,
            DiagnosticStage::Route,
            DiagnosticStage::Http,
            DiagnosticStage::Completed,
        ] {
            progress.emit(stage);
        }
        Ok(result(input))
    }
}

struct BlockingRunner {
    started: Arc<AtomicUsize>,
    release: Arc<Notify>,
}

#[async_trait]
impl UrlRunner for BlockingRunner {
    async fn run(
        &self,
        input: &str,
        progress: &dyn ProgressSink,
    ) -> Result<UrlDiagnosticResult, DiagnosticError> {
        progress.emit(DiagnosticStage::Validating);
        self.started.fetch_add(1, Ordering::SeqCst);
        self.release.notified().await;
        for stage in [
            DiagnosticStage::Proxy,
            DiagnosticStage::Dns,
            DiagnosticStage::Route,
            DiagnosticStage::Http,
            DiagnosticStage::Completed,
        ] {
            progress.emit(stage);
        }
        Ok(result(input))
    }
}

struct FailingRunner;

#[async_trait]
impl UrlRunner for FailingRunner {
    async fn run(
        &self,
        _input: &str,
        progress: &dyn ProgressSink,
    ) -> Result<UrlDiagnosticResult, DiagnosticError> {
        progress.emit(DiagnosticStage::Validating);
        Err(DiagnosticError::InvalidUrl)
    }
}

struct DnsFailingRunner;

#[async_trait]
impl UrlRunner for DnsFailingRunner {
    async fn run(
        &self,
        _input: &str,
        progress: &dyn ProgressSink,
    ) -> Result<UrlDiagnosticResult, DiagnosticError> {
        progress.emit(DiagnosticStage::Validating);
        progress.emit(DiagnosticStage::Dns);
        Err(DiagnosticError::DnsFailed)
    }
}

struct HttpSecretErrorRunner;

#[async_trait]
impl UrlRunner for HttpSecretErrorRunner {
    async fn run(
        &self,
        _input: &str,
        progress: &dyn ProgressSink,
    ) -> Result<UrlDiagnosticResult, DiagnosticError> {
        progress.emit(DiagnosticStage::Validating);
        Err(DiagnosticError::Http(
            "authorization=super-secret-http-value".into(),
        ))
    }
}

struct GatedRunner {
    release: Arc<Notify>,
}

struct NoTerminalRunner;

#[async_trait]
impl UrlRunner for NoTerminalRunner {
    async fn run(
        &self,
        input: &str,
        progress: &dyn ProgressSink,
    ) -> Result<UrlDiagnosticResult, DiagnosticError> {
        for stage in [
            DiagnosticStage::Validating,
            DiagnosticStage::Proxy,
            DiagnosticStage::Dns,
            DiagnosticStage::Route,
            DiagnosticStage::Http,
        ] {
            progress.emit(stage);
        }
        Ok(result(input))
    }
}

struct PanicRunner;

#[async_trait]
impl UrlRunner for PanicRunner {
    async fn run(
        &self,
        _input: &str,
        progress: &dyn ProgressSink,
    ) -> Result<UrlDiagnosticResult, DiagnosticError> {
        progress.emit(DiagnosticStage::Validating);
        panic!("runner panic must not leave a run pending")
    }
}

struct SecretErrorRunner;

#[async_trait]
impl UrlRunner for SecretErrorRunner {
    async fn run(
        &self,
        _input: &str,
        progress: &dyn ProgressSink,
    ) -> Result<UrlDiagnosticResult, DiagnosticError> {
        progress.emit(DiagnosticStage::Validating);
        Err(DiagnosticError::System(
            "cookie=super-secret-session-value".into(),
        ))
    }
}

struct PrematureCompletedRunner;

#[async_trait]
impl UrlRunner for PrematureCompletedRunner {
    async fn run(
        &self,
        _input: &str,
        progress: &dyn ProgressSink,
    ) -> Result<UrlDiagnosticResult, DiagnosticError> {
        progress.emit(DiagnosticStage::Validating);
        progress.emit(DiagnosticStage::Completed);
        Err(DiagnosticError::Http("failed after completed".into()))
    }
}

#[async_trait]
impl UrlRunner for GatedRunner {
    async fn run(
        &self,
        input: &str,
        progress: &dyn ProgressSink,
    ) -> Result<UrlDiagnosticResult, DiagnosticError> {
        self.release.notified().await;
        for stage in [
            DiagnosticStage::Validating,
            DiagnosticStage::Proxy,
            DiagnosticStage::Dns,
            DiagnosticStage::Route,
            DiagnosticStage::Http,
            DiagnosticStage::Completed,
        ] {
            progress.emit(stage);
        }
        Ok(result(input))
    }
}

fn test_router(runner: Arc<dyn UrlRunner>) -> axum::Router {
    build_router(AppState::new(PORT, TOKEN, runner))
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

async fn post_run(app: axum::Router) -> (axum::Router, Uuid) {
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/api/v1/url-diagnostics",
            r#"{"url":"https://example.com"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    (app, body["run_id"].as_str().unwrap().parse().unwrap())
}

async fn snapshot(app: axum::Router, run_id: Uuid) -> serde_json::Value {
    let response = app
        .oneshot(request(
            "GET",
            &format!("/api/v1/runs/{run_id}"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

async fn wait_for_status(app: axum::Router, run_id: Uuid, wanted: &str) -> serde_json::Value {
    for _ in 0..50 {
        let value = snapshot(app.clone(), run_id).await;
        if value["status"] == wanted {
            return value;
        }
        tokio::task::yield_now().await;
    }
    panic!("run {run_id} did not become {wanted}");
}

#[tokio::test]
async fn post_returns_run_id_and_snapshot_moves_from_running_to_completed() {
    let started = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(Notify::new());
    let app = test_router(Arc::new(BlockingRunner {
        started: Arc::clone(&started),
        release: Arc::clone(&release),
    }));
    let (app, run_id) = post_run(app).await;

    for _ in 0..50 {
        if started.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(started.load(Ordering::SeqCst), 1);
    assert_eq!(snapshot(app.clone(), run_id).await["status"], "running");

    release.notify_one();
    let completed = wait_for_status(app, run_id, "completed").await;
    assert_eq!(completed["result"]["requested_url"], "https://example.com");
    assert_eq!(completed["result"]["traffic_decision"]["kind"], "unknown");
    assert_eq!(
        completed["result"]["traffic_decision"]["evidence"][0]["summary"],
        "未能确认 Clash 最终决策"
    );
}

#[tokio::test]
async fn completed_fast_runs_replay_every_ordered_sse_stage_without_losing_terminal_event() {
    let (app, run_id) = post_run(test_router(Arc::new(ImmediateRunner))).await;
    wait_for_status(app.clone(), run_id, "completed").await;

    let response = app
        .oneshot(request(
            "GET",
            &format!("/api/v1/runs/{run_id}/events"),
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
    let text = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let stages = text
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["stage"].clone())
        .collect::<Vec<_>>();
    assert_eq!(
        stages,
        serde_json::json!(["validating", "proxy", "dns", "route", "http", "completed"])
            .as_array()
            .unwrap()
            .clone()
    );
}

#[tokio::test]
async fn live_sse_subscription_includes_the_first_stage_when_it_subscribes_before_the_runner() {
    let release = Arc::new(Notify::new());
    let (app, run_id) = post_run(test_router(Arc::new(GatedRunner {
        release: Arc::clone(&release),
    })))
    .await;
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/api/v1/runs/{run_id}/events"),
            Body::empty(),
        ))
        .await
        .unwrap();

    release.notify_one();
    let text = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let stages = text
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["stage"].clone())
        .collect::<Vec<_>>();
    assert_eq!(stages.first(), Some(&serde_json::json!("validating")));
    assert_eq!(stages.last(), Some(&serde_json::json!("completed")));
}

#[tokio::test]
async fn completed_snapshots_always_replay_a_terminal_sse_stage() {
    let (app, run_id) = post_run(test_router(Arc::new(NoTerminalRunner))).await;
    wait_for_status(app.clone(), run_id, "completed").await;

    let response = app
        .oneshot(request(
            "GET",
            &format!("/api/v1/runs/{run_id}/events"),
            Body::empty(),
        ))
        .await
        .unwrap();
    let text = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(text.contains(r#"data: {"sequence":5,"stage":"completed"}"#));
}

#[tokio::test]
async fn invalid_url_runs_are_snapshotted_with_a_safe_input_error() {
    let (app, run_id) = post_run(test_router(Arc::new(FailingRunner))).await;
    let failed = wait_for_status(app, run_id, "failed").await;
    assert_eq!(failed["error"]["code"], "invalid_url");
    assert_eq!(
        failed["error"]["message"],
        "请输入有效的 HTTP 或 HTTPS 网址"
    );
    assert!(failed["result"].is_null());
}

#[tokio::test]
async fn dns_failure_runs_are_snapshotted_with_a_safe_dns_explanation() {
    let (app, run_id) = post_run(test_router(Arc::new(DnsFailingRunner))).await;
    let failed = wait_for_status(app, run_id, "failed").await;
    assert_eq!(failed["error"]["code"], "dns_failed");
    assert_eq!(
        failed["error"]["message"],
        "无法解析域名，请检查网址或 DNS 设置"
    );
    assert!(failed["result"].is_null());
}

#[tokio::test]
async fn runner_panics_become_failed_snapshots_and_terminal_failed_events() {
    let (app, run_id) = post_run(test_router(Arc::new(PanicRunner))).await;
    let failed = wait_for_status(app.clone(), run_id, "failed").await;
    assert_eq!(failed["error"]["code"], "diagnostic_failed");

    let response = app
        .oneshot(request(
            "GET",
            &format!("/api/v1/runs/{run_id}/events"),
            Body::empty(),
        ))
        .await
        .unwrap();
    let events = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(events.contains(r#""stage":"failed""#));
}

#[tokio::test]
async fn diagnostic_failure_details_never_appear_in_a_snapshot_or_sse() {
    let (app, run_id) = post_run(test_router(Arc::new(SecretErrorRunner))).await;
    let failed = wait_for_status(app.clone(), run_id, "failed").await;
    assert_eq!(failed["error"]["code"], "diagnostic_failed");
    assert!(!failed.to_string().contains("super-secret-session-value"));

    let response = app
        .oneshot(request(
            "GET",
            &format!("/api/v1/runs/{run_id}/events"),
            Body::empty(),
        ))
        .await
        .unwrap();
    let events = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(!events.contains("super-secret-session-value"));
}

#[tokio::test]
async fn http_failure_details_remain_generic_and_secret_free() {
    let (app, run_id) = post_run(test_router(Arc::new(HttpSecretErrorRunner))).await;
    let failed = wait_for_status(app, run_id, "failed").await;
    assert_eq!(failed["error"]["code"], "diagnostic_failed");
    assert_eq!(failed["error"]["message"], "诊断未能完成，请稍后重试");
    assert!(!failed.to_string().contains("super-secret-http-value"));
}

#[tokio::test]
async fn runner_completed_stage_is_ignored_until_the_run_actually_succeeds() {
    let (app, run_id) = post_run(test_router(Arc::new(PrematureCompletedRunner))).await;
    assert_eq!(
        wait_for_status(app.clone(), run_id, "failed").await["status"],
        "failed"
    );

    let response = app
        .oneshot(request(
            "GET",
            &format!("/api/v1/runs/{run_id}/events"),
            Body::empty(),
        ))
        .await
        .unwrap();
    let events = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(events.contains(r#""stage":"failed""#));
    assert!(!events.contains(r#""stage":"completed""#));
}

#[tokio::test]
async fn store_expires_completed_runs_after_the_retention_window() {
    let store = RunStore::with_retention(Duration::from_millis(10));
    let run_id = store.create();
    store.complete(run_id, result("https://example.com"));

    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(store.count(), 0, "expiry must run without a store read");
    assert!(store.snapshot(run_id).is_none());
}

#[tokio::test]
async fn twenty_running_diagnostics_fill_the_concurrency_limit() {
    let started = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(Notify::new());
    let app = test_router(Arc::new(BlockingRunner {
        started: Arc::clone(&started),
        release: Arc::clone(&release),
    }));

    for _ in 0..20 {
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                "/api/v1/url-diagnostics",
                r#"{"url":"https://example.com"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }
    for _ in 0..100 {
        if started.load(Ordering::SeqCst) == 20 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(started.load(Ordering::SeqCst), 20);

    let rejected = app
        .oneshot(request(
            "POST",
            "/api/v1/url-diagnostics",
            r#"{"url":"https://example.com"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
    let error: serde_json::Value =
        serde_json::from_slice(&rejected.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(error["code"], "too_many_runs");

    release.notify_waiters();
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
        traffic_decision: TrafficDecision::unknown("mihomo", "未能确认 Clash 最终决策"),
        conclusion: Conclusion {
            title: "done".into(),
            summary: "done".into(),
            level: EvidenceLevel::Confirmed,
        },
        evidence: vec![],
    }
}

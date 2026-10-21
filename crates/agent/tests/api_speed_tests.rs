use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use network_path_agent::{
    api::{AppState, UrlRunner, build_router},
    error::DiagnosticError,
    ports::ProgressSink,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const PORT: u16 = 8765;
const TOKEN: &str = "secret-token";

struct UnusedRunner;

#[async_trait::async_trait]
impl UrlRunner for UnusedRunner {
    async fn run(
        &self,
        _input: &str,
        _progress: &dyn ProgressSink,
    ) -> Result<network_path_agent::domain::UrlDiagnosticResult, DiagnosticError> {
        unreachable!("speed API tests never start a URL diagnostic")
    }
}

fn router() -> axum::Router {
    build_router(AppState::new(PORT, TOKEN, Arc::new(UnusedRunner)))
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

async fn json_body(response: axum::response::Response) -> Value {
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

fn sample_body() -> Value {
    sample_body_with_batch(Uuid::new_v4())
}

fn sample_body_with_batch(batch_id: Uuid) -> Value {
    json!({
        "batch_id": batch_id.to_string(),
        "used_bytes": 200000,
        "samples": [
            {"kind":"latency","bytes":0,"bps":null,"duration_ms":20.0,"latency_ms":20.0},
            {"kind":"download","bytes":100000,"bps":80000000.0,"duration_ms":10.0,"latency_ms":null},
            {"kind":"upload","bytes":100000,"bps":40000000.0,"duration_ms":20.0,"latency_ms":null}
        ]
    })
}

async fn post_samples(app: &axum::Router, id: Uuid, body: Value) -> axum::response::Response {
    app.clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/speed-tests/{id}/samples"),
            Body::from(body.to_string()),
        ))
        .await
        .unwrap()
}

fn metrics_body() -> Value {
    json!({
        "download_bps": 80000000.0,
        "upload_bps": 40000000.0,
        "unloaded_latency_ms": 20.0,
        "unloaded_jitter_ms": 2.0,
        "download_loaded_latency_ms": null,
        "upload_loaded_latency_ms": null
    })
}

fn loaded_metrics_body() -> Value {
    json!({
        "download_bps": 80000000.0,
        "upload_bps": 40000000.0,
        "unloaded_latency_ms": 20.0,
        "unloaded_jitter_ms": 2.0,
        "download_loaded_latency_ms": 35.0,
        "upload_loaded_latency_ms": 45.0
    })
}

async fn start(app: &axum::Router) -> (axum::Router, Uuid) {
    start_mode(app, "quick").await
}

async fn start_mode(app: &axum::Router, mode: &str) -> (axum::Router, Uuid) {
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/api/v1/speed-tests",
            Body::from(format!(r#"{{"mode":"{mode}"}}"#)),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = json_body(response).await;
    assert_eq!(body["status"], "running");
    assert_eq!(body["plan"]["mode"], mode);
    (app.clone(), body["id"].as_str().unwrap().parse().unwrap())
}

#[tokio::test]
async fn speed_api_starts_records_completes_and_replays_terminal_events() {
    let app = router();
    let (app, id) = start(&app).await;

    let samples = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/speed-tests/{id}/samples"),
            Body::from(sample_body().to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(samples.status(), StatusCode::NO_CONTENT);

    let complete = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/speed-tests/{id}/complete"),
            Body::from(json!({"metrics": metrics_body()}).to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(complete.status(), StatusCode::OK);
    let completed = json_body(complete).await;
    assert_eq!(completed["status"], "completed");
    assert_eq!(completed["result"]["provider"], "cloudflare");
    assert_eq!(completed["result"]["traffic_decision"]["kind"], "unknown");

    let snapshot = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/api/v1/speed-tests/{id}"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(json_body(snapshot).await["status"], "completed");

    let events = app
        .oneshot(request(
            "GET",
            &format!("/api/v1/speed-tests/{id}/events"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(events.status(), StatusCode::OK);
    let text = String::from_utf8(
        events
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(text.contains(r#""stage":"started""#));
    assert!(text.contains(r#""stage":"samples""#));
    assert!(text.contains(r#""stage":"completed""#));
}

#[tokio::test]
async fn speed_api_replays_exact_batch_after_terminal_without_second_application() {
    let app = router();
    let (app, id) = start(&app).await;
    let batch_id = Uuid::new_v4();
    assert_eq!(
        post_samples(&app, id, sample_body_with_batch(batch_id))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );

    let complete = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/speed-tests/{id}/complete"),
            Body::from(json!({"metrics": metrics_body()}).to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(complete.status(), StatusCode::OK);

    let replay = post_samples(&app, id, sample_body_with_batch(batch_id)).await;
    assert_eq!(replay.status(), StatusCode::NO_CONTENT);

    let snapshot = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/api/v1/speed-tests/{id}"),
            Body::empty(),
        ))
        .await
        .unwrap();
    let snapshot = json_body(snapshot).await;
    assert_eq!(snapshot["used_bytes"], 200000);
    assert_eq!(snapshot["sample_count"], 3);

    let events = app
        .oneshot(request(
            "GET",
            &format!("/api/v1/speed-tests/{id}/events"),
            Body::empty(),
        ))
        .await
        .unwrap();
    let text = String::from_utf8(
        events
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(text.matches(r#""stage":"samples""#).count(), 1);
}

#[tokio::test]
async fn speed_api_rejects_batch_collision_and_distinct_stale_batch_without_crediting() {
    let app = router();
    let (app, id) = start(&app).await;
    let batch_id = Uuid::new_v4();
    assert_eq!(
        post_samples(&app, id, sample_body_with_batch(batch_id))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );

    let mut collision = sample_body_with_batch(batch_id);
    collision["samples"][1]["bps"] = json!(81_000_000.0);
    let collision = post_samples(&app, id, collision).await;
    assert_eq!(collision.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(collision).await["code"], "speed_invalid_request");

    let stale = post_samples(&app, id, sample_body_with_batch(Uuid::new_v4())).await;
    assert_eq!(stale.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(stale).await["code"], "speed_invalid_request");

    let snapshot = app
        .oneshot(request(
            "GET",
            &format!("/api/v1/speed-tests/{id}"),
            Body::empty(),
        ))
        .await
        .unwrap();
    let snapshot = json_body(snapshot).await;
    assert_eq!(snapshot["used_bytes"], 200000);
    assert_eq!(snapshot["sample_count"], 3);
}

#[tokio::test]
async fn speed_api_rejects_missing_malformed_and_unknown_batch_fields() {
    let app = router();
    let (app, id) = start(&app).await;

    let mut missing = sample_body();
    missing.as_object_mut().unwrap().remove("batch_id");
    let missing = post_samples(&app, id, missing).await;
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(missing).await["code"], "invalid_request");

    let mut malformed = sample_body();
    malformed["batch_id"] = json!("not-a-uuid");
    let malformed = post_samples(&app, id, malformed).await;
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(malformed).await["code"], "invalid_request");

    let mut unknown = sample_body();
    unknown["unexpected"] = json!(true);
    let unknown = post_samples(&app, id, unknown).await;
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(unknown).await["code"], "invalid_request");
}

#[tokio::test]
async fn speed_api_cancel_is_terminal_and_late_requests_cannot_write_a_result() {
    let app = router();
    let (app, id) = start(&app).await;
    let cancelled = app
        .clone()
        .oneshot(request(
            "DELETE",
            &format!("/api/v1/speed-tests/{id}"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(cancelled.status(), StatusCode::NO_CONTENT);

    let late = app
        .oneshot(request(
            "POST",
            &format!("/api/v1/speed-tests/{id}/complete"),
            Body::from(json!({"metrics": metrics_body()}).to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(late.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(late).await["code"], "speed_already_finished");
}

#[tokio::test]
async fn speed_api_rejects_unknown_fields_oversized_bodies_and_bad_values_safely() {
    let app = router();
    let unknown = app
        .clone()
        .oneshot(request(
            "POST",
            "/api/v1/speed-tests",
            Body::from(r#"{"mode":"quick","secret":"do-not-echo"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(unknown).await["code"], "invalid_request");

    let oversized = app
        .clone()
        .oneshot(request(
            "POST",
            "/api/v1/speed-tests",
            Body::from(format!(
                r#"{{"mode":"quick","padding":"{}"}}"#,
                "x".repeat(9000)
            )),
        ))
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(json_body(oversized).await["code"], "payload_too_large");

    let (_, id) = start(&app).await;
    let bad_float = app
        .oneshot(request(
            "POST",
            &format!("/api/v1/speed-tests/{id}/complete"),
            Body::from(
                r#"{"metrics":{"download_bps":1e400,"upload_bps":1,"unloaded_latency_ms":1,"unloaded_jitter_ms":1,"download_loaded_latency_ms":null,"upload_loaded_latency_ms":null}}"#,
            ),
        ))
        .await
        .unwrap();
    assert_eq!(bad_float.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(bad_float).await["code"], "invalid_request");
}

#[tokio::test]
async fn speed_api_enforces_loaded_latency_metrics_by_mode() {
    let app = router();
    let (app, full_id) = start_mode(&app, "full").await;
    let samples = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/speed-tests/{full_id}/samples"),
            Body::from(sample_body().to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(samples.status(), StatusCode::NO_CONTENT);

    let missing_loaded = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/speed-tests/{full_id}/complete"),
            Body::from(json!({"metrics": metrics_body()}).to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(missing_loaded.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(missing_loaded).await["code"],
        "speed_invalid_request"
    );

    let partial_loaded = json!({
        "download_bps": 80000000.0,
        "upload_bps": 40000000.0,
        "unloaded_latency_ms": 20.0,
        "unloaded_jitter_ms": 2.0,
        "download_loaded_latency_ms": 35.0,
        "upload_loaded_latency_ms": null
    });
    let partial = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/speed-tests/{full_id}/complete"),
            Body::from(json!({"metrics": partial_loaded}).to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(partial.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(partial).await["code"], "speed_invalid_request");

    let full = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/speed-tests/{full_id}/complete"),
            Body::from(json!({"metrics": loaded_metrics_body()}).to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(full.status(), StatusCode::OK);

    let (app, quick_id) = start_mode(&app, "quick").await;
    let samples = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/api/v1/speed-tests/{quick_id}/samples"),
            Body::from(sample_body().to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(samples.status(), StatusCode::NO_CONTENT);
    let quick_extra = app
        .oneshot(request(
            "POST",
            &format!("/api/v1/speed-tests/{quick_id}/complete"),
            Body::from(json!({"metrics": loaded_metrics_body()}).to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(quick_extra.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(quick_extra).await["code"],
        "speed_invalid_request"
    );
}

#[tokio::test]
async fn speed_api_missing_records_and_unsupported_methods_are_stable() {
    let id = Uuid::new_v4();
    let missing = router()
        .clone()
        .oneshot(request(
            "GET",
            &format!("/api/v1/speed-tests/{id}"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(json_body(missing).await["code"], "speed_test_not_found");

    let method = router()
        .oneshot(request("PUT", "/api/v1/speed-tests", Body::empty()))
        .await
        .unwrap();
    assert_eq!(method.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(json_body(method).await["code"], "method_not_allowed");
}

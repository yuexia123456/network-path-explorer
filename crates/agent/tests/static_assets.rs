use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use network_path_agent::{
    api::{AppState, UrlRunner, build_router},
    domain::UrlDiagnosticResult,
    error::DiagnosticError,
    ports::ProgressSink,
};
use std::{fs, sync::Arc};
use tower::ServiceExt;

const PORT: u16 = 8765;
const TOKEN: &str = "test-session-token";

struct UnusedRunner;

#[async_trait]
impl UrlRunner for UnusedRunner {
    async fn run(
        &self,
        _input: &str,
        _progress: &dyn ProgressSink,
    ) -> Result<UrlDiagnosticResult, DiagnosticError> {
        unreachable!("static asset tests do not start diagnostics")
    }
}

fn app() -> axum::Router {
    build_router(AppState::new(PORT, TOKEN, Arc::new(UnusedRunner)))
}

fn request(path: &str) -> Request<Body> {
    request_with_method("GET", path)
}

fn request_with_method(method: &str, path: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .body(Body::empty())
        .unwrap()
}

async fn response_body(response: axum::response::Response) -> String {
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
}

#[tokio::test]
async fn root_returns_the_embedded_html_shell() {
    let response = app().oneshot(request("/")).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    assert!(response_body(response).await.contains("id=\"app\""));
}

#[tokio::test]
async fn client_side_routes_fall_back_to_the_embedded_html_shell() {
    let response = app().oneshot(request("/diagnostics/recent")).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    assert!(response_body(response).await.contains("id=\"app\""));
}

#[tokio::test]
async fn hashed_javascript_asset_has_a_javascript_mime_type() {
    let filename = fs::read_dir("../../web/dist/assets")
        .unwrap()
        .map(Result::unwrap)
        .find_map(|entry| {
            entry
                .file_name()
                .to_str()
                .filter(|name| name.ends_with(".js"))
                .map(str::to_owned)
        })
        .expect("Vite build must produce a JavaScript asset");
    let response = app()
        .oneshot(request(&format!("/assets/{filename}")))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/javascript")
    );
}

#[tokio::test]
async fn head_requests_keep_root_and_asset_metadata_without_a_body() {
    let filename = fs::read_dir("../../web/dist/assets")
        .unwrap()
        .map(Result::unwrap)
        .find_map(|entry| {
            entry
                .file_name()
                .to_str()
                .filter(|name| name.ends_with(".js"))
                .map(str::to_owned)
        })
        .expect("Vite build must produce a JavaScript asset");

    for (path, expected_mime) in [
        ("/".to_owned(), "text/html"),
        (format!("/assets/{filename}"), "text/javascript"),
    ] {
        let response = app()
            .oneshot(request_with_method("HEAD", &path))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK, "path {path}");
        assert!(
            response.headers()[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with(expected_mime)
        );
        assert!(response_body(response).await.is_empty(), "path {path}");
    }
}

#[tokio::test]
async fn head_capabilities_is_an_empty_successful_api_response() {
    let response = app()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/api/v1/capabilities")
                .header("host", "127.0.0.1:8765")
                .header("origin", "http://127.0.0.1:8765")
                .header("x-npe-session", TOKEN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    assert!(response_body(response).await.is_empty());
}

#[tokio::test]
async fn capabilities_and_embedded_page_advertise_task13_network_features() {
    let response = app()
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/capabilities")
                .header("host", "127.0.0.1:8765")
                .header("origin", "http://127.0.0.1:8765")
                .header("x-npe-session", TOKEN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let capabilities = response_body(response).await;
    for field in [
        "\"network_overview\":true",
        "\"egress_ip\":true",
        "\"mihomo_manual_controller\":true",
        "\"route_trace\":true",
        "\"speed_tests\":true",
        "\"speed_provider\":\"cloudflare\"",
    ] {
        assert!(
            capabilities.contains(field),
            "missing capability {field}: {capabilities}"
        );
    }

    let html = response_body(app().oneshot(request("/")).await.unwrap()).await;
    assert!(html.contains("/assets/"));
    let filename = fs::read_dir("../../web/dist/assets")
        .unwrap()
        .map(Result::unwrap)
        .find_map(|entry| {
            entry
                .file_name()
                .to_str()
                .filter(|name| name.ends_with(".js"))
                .map(str::to_owned)
        })
        .expect("Vite build must produce a JavaScript asset");
    let script = response_body(
        app()
            .oneshot(request(&format!("/assets/{filename}")))
            .await
            .unwrap(),
    )
    .await;
    assert!(script.contains("本机网络概览"));
    assert!(script.contains("Cloudflare 测速"));
}

#[tokio::test]
async fn api_unknown_path_remains_a_json_not_found_response() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/api/unknown")
                .header("host", "127.0.0.1:8765")
                .header("origin", "http://127.0.0.1:8765")
                .header("x-npe-session", TOKEN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    assert_eq!(
        response_body(response).await,
        "{\"code\":\"run_not_found\",\"message\":\"未找到诊断任务\"}"
    );
}

#[tokio::test]
async fn asset_paths_cannot_traverse_outside_the_embedded_asset_set() {
    for path in ["/assets/../Cargo.toml", "/assets/%2e%2e/Cargo.toml"] {
        let response = app().oneshot(request(path)).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND, "path {path}");
    }
}

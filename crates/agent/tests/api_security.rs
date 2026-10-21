use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use network_path_agent::{
    api::{AppState, UrlRunner, build_router},
    domain::{
        Conclusion, DiagnosticStage, Evidence, EvidenceLevel, HttpObservation, ProxyDecision,
        ProxyKind, TrafficDecision, UrlDiagnosticResult,
    },
    error::DiagnosticError,
    ports::ProgressSink,
};
use std::sync::Arc;
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

fn test_router(token: &str) -> axum::Router {
    build_router(AppState::new(PORT, token, Arc::new(ImmediateRunner)))
}

fn local_request(method: &str, path: &str, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("host", "127.0.0.1:8765")
        .header("origin", "http://127.0.0.1:8765")
        .body(body.into())
        .unwrap()
}

fn session_request(method: &str, path: &str, body: impl Into<Body>) -> Request<Body> {
    let mut request = local_request(method, path, body);
    request
        .headers_mut()
        .insert("x-npe-session", TOKEN.parse().unwrap());
    request
}

fn same_origin_browser_read(method: &str, path: &str, with_token: bool) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "127.0.0.1:8765")
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap();
    if with_token {
        request
            .headers_mut()
            .insert("x-npe-session", TOKEN.parse().unwrap());
    }
    request
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn diagnostics_rejects_missing_session_token_with_a_stable_json_error() {
    let response = test_router(TOKEN)
        .oneshot(local_request(
            "POST",
            "/api/v1/url-diagnostics",
            r#"{"url":"https://example.com"}"#,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        json_body(response).await,
        serde_json::json!({"code":"unauthorized","message":"本地会话已失效，请重新启动工具"})
    );
}

#[tokio::test]
async fn capabilities_requires_a_token_when_same_origin_browser_reads_omit_origin() {
    let response = test_router(TOKEN)
        .oneshot(local_request("GET", "/api/v1/capabilities", Body::empty()))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await,
        serde_json::json!({
            "platform":"macos",
            "url_diagnostics":true,
            "app_diagnostics":false,
            "route_hops":false,
            "ip_intelligence":false,
            "network_overview":true,
            "egress_ip":true,
            "mihomo_manual_controller":true,
            "route_trace":true,
            "speed_tests":true,
            "speed_provider":"cloudflare"
        })
    );

    let missing_origin = test_router(TOKEN)
        .oneshot(same_origin_browser_read(
            "GET",
            "/api/v1/capabilities",
            false,
        ))
        .await
        .unwrap();
    assert_eq!(missing_origin.status(), StatusCode::UNAUTHORIZED);

    let authenticated_missing_origin = test_router(TOKEN)
        .oneshot(same_origin_browser_read(
            "GET",
            "/api/v1/capabilities",
            true,
        ))
        .await
        .unwrap();
    assert_eq!(authenticated_missing_origin.status(), StatusCode::OK);

    let mut cross_site = same_origin_browser_read("GET", "/api/v1/capabilities", true);
    cross_site
        .headers_mut()
        .insert("sec-fetch-site", "cross-site".parse().unwrap());
    let cross_site = test_router(TOKEN).oneshot(cross_site).await.unwrap();
    assert_eq!(cross_site.status(), StatusCode::FORBIDDEN);

    let denied = test_router(TOKEN)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/capabilities")
                .header("host", "127.0.0.1.evil:8765")
                .header("origin", "http://127.0.0.1:8765")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn only_get_capabilities_is_exempt_from_the_session_token() {
    let unauthenticated = test_router(TOKEN)
        .oneshot(local_request("POST", "/api/v1/capabilities", Body::empty()))
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(unauthenticated).await["code"], "unauthorized");

    let authenticated = test_router(TOKEN)
        .oneshot(session_request(
            "POST",
            "/api/v1/capabilities",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(authenticated.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(json_body(authenticated).await["code"], "method_not_allowed");
}

#[tokio::test]
async fn api_rejects_malformed_or_wrong_loopback_hosts_and_origins() {
    for host in [
        "127.0.0.1.evil:8765",
        "127.0.0.1:8766",
        "127.0.0.1",
        "localhost:8765",
    ] {
        let response = test_router(TOKEN)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/url-diagnostics")
                    .header("host", host)
                    .header("origin", "http://127.0.0.1:8765")
                    .header("x-npe-session", TOKEN)
                    .body(Body::from(r#"{"url":"https://example.com"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "host {host}");
        assert_eq!(json_body(response).await["code"], "forbidden");
    }

    for origin in [
        "http://127.0.0.1.evil:8765",
        "http://127.0.0.1:8766",
        "https://127.0.0.1:8765",
        "http://localhost:8765",
    ] {
        let response = test_router(TOKEN)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/url-diagnostics")
                    .header("host", "127.0.0.1:8765")
                    .header("origin", origin)
                    .header("x-npe-session", TOKEN)
                    .body(Body::from(r#"{"url":"https://example.com"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "origin {origin}");
        assert_eq!(json_body(response).await["code"], "forbidden");
    }

    for missing in ["host", "origin"] {
        let mut request = session_request(
            "POST",
            "/api/v1/url-diagnostics",
            Body::from(r#"{"url":"https://example.com"}"#),
        );
        request.headers_mut().remove(missing);
        let response = test_router(TOKEN).oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "missing {missing}"
        );
    }
}

#[tokio::test]
async fn api_rejects_duplicate_host_or_origin_headers() {
    for duplicate in ["host", "origin"] {
        let mut request = session_request(
            "POST",
            "/api/v1/url-diagnostics",
            Body::from(r#"{"url":"https://example.com"}"#),
        );
        request.headers_mut().append(
            duplicate,
            if duplicate == "host" {
                "127.0.0.1.evil:8765".parse().unwrap()
            } else {
                "http://127.0.0.1.evil:8765".parse().unwrap()
            },
        );

        let response = test_router(TOKEN).oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "duplicate {duplicate}"
        );
    }
}

#[tokio::test]
async fn valid_session_starts_a_diagnostic_and_api_body_limit_is_stable_json() {
    let accepted = test_router(TOKEN)
        .oneshot(session_request(
            "POST",
            "/api/v1/url-diagnostics",
            Body::from(r#"{"url":"https://example.com"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    assert!(json_body(accepted).await["run_id"].as_str().is_some());

    let too_large = test_router(TOKEN)
        .oneshot(session_request(
            "POST",
            "/api/v1/url-diagnostics",
            Body::from(vec![b'x'; 8 * 1024 + 1]),
        ))
        .await
        .unwrap();
    assert_eq!(too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(json_body(too_large).await["code"], "payload_too_large");
}

#[tokio::test]
async fn run_snapshot_and_event_stream_require_the_session_token() {
    for path in [
        format!("/api/v1/runs/{}", Uuid::new_v4()),
        format!("/api/v1/runs/{}/events", Uuid::new_v4()),
    ] {
        let response = test_router(TOKEN)
            .oneshot(local_request("GET", &path, Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(json_body(response).await["code"], "unauthorized");
    }
}

#[tokio::test]
async fn speed_test_endpoints_retain_session_origin_host_and_fetch_metadata_protection() {
    let id = Uuid::new_v4();
    let endpoints = vec![
        ("POST", "/api/v1/speed-tests".to_owned(), true),
        ("GET", format!("/api/v1/speed-tests/{id}"), false),
        ("GET", format!("/api/v1/speed-tests/{id}/events"), false),
        ("POST", format!("/api/v1/speed-tests/{id}/samples"), true),
        ("POST", format!("/api/v1/speed-tests/{id}/complete"), true),
        ("DELETE", format!("/api/v1/speed-tests/{id}"), false),
    ];

    for (method, path, has_body) in endpoints {
        let body = if has_body {
            Body::from(if path.ends_with("speed-tests") {
                r#"{"mode":"quick"}"#.to_owned()
            } else {
                r#"{}"#.to_owned()
            })
        } else {
            Body::empty()
        };
        let response = test_router(TOKEN)
            .oneshot(local_request(method, &path, body))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path}"
        );
        assert_eq!(json_body(response).await["code"], "unauthorized");

        let wrong_origin = Request::builder()
            .method(method)
            .uri(&path)
            .header("host", "127.0.0.1:8765")
            .header("origin", "http://127.0.0.1.evil:8765")
            .header("x-npe-session", TOKEN)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            test_router(TOKEN)
                .oneshot(wrong_origin)
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN,
            "{method} {path}"
        );

        let wrong_host = Request::builder()
            .method(method)
            .uri(&path)
            .header("host", "127.0.0.1.evil:8765")
            .header("origin", "http://127.0.0.1:8765")
            .header("x-npe-session", TOKEN)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            test_router(TOKEN)
                .oneshot(wrong_host)
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN,
            "{method} {path}"
        );
    }

    let mut cross_site =
        same_origin_browser_read("GET", &format!("/api/v1/speed-tests/{id}"), true);
    cross_site
        .headers_mut()
        .insert("sec-fetch-site", "cross-site".parse().unwrap());
    let response = test_router(TOKEN).oneshot(cross_site).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn route_trace_endpoints_retain_session_origin_host_and_fetch_metadata_protection() {
    let run_id = Uuid::new_v4();
    let endpoints = [
        ("POST", format!("/api/v1/runs/{run_id}/route-trace"), true),
        ("GET", format!("/api/v1/runs/{run_id}/route-trace"), false),
        (
            "GET",
            format!("/api/v1/runs/{run_id}/route-trace/events"),
            false,
        ),
        (
            "DELETE",
            format!("/api/v1/runs/{run_id}/route-trace"),
            false,
        ),
    ];

    for (method, path, has_body) in &endpoints {
        let body = if *has_body {
            Body::from(r#"{"kind":"actual"}"#)
        } else {
            Body::empty()
        };
        let response = test_router(TOKEN)
            .oneshot(local_request(method, path, body))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path}"
        );
        assert_eq!(json_body(response).await["code"], "unauthorized");

        let wrong_origin = Request::builder()
            .method(*method)
            .uri(path)
            .header("host", "127.0.0.1:8765")
            .header("origin", "http://127.0.0.1.evil:8765")
            .header("x-npe-session", TOKEN)
            .body(Body::empty())
            .unwrap();
        let response = test_router(TOKEN).oneshot(wrong_origin).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");

        let wrong_host = Request::builder()
            .method(*method)
            .uri(path)
            .header("host", "127.0.0.1.evil:8765")
            .header("origin", "http://127.0.0.1:8765")
            .header("x-npe-session", TOKEN)
            .body(Body::empty())
            .unwrap();
        let response = test_router(TOKEN).oneshot(wrong_host).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");
    }

    for path in [
        format!("/api/v1/runs/{run_id}/route-trace"),
        format!("/api/v1/runs/{run_id}/route-trace/events"),
    ] {
        let mut cross_site = same_origin_browser_read("GET", &path, true);
        cross_site
            .headers_mut()
            .insert("sec-fetch-site", "cross-site".parse().unwrap());
        let response = test_router(TOKEN).oneshot(cross_site).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "GET {path}");
    }
}

#[tokio::test]
async fn route_trace_unsupported_methods_and_missing_records_use_safe_json_contracts() {
    let run_id = Uuid::new_v4();
    for path in [
        format!("/api/v1/runs/{run_id}/route-trace"),
        format!("/api/v1/runs/{run_id}/route-trace/events"),
    ] {
        let response = test_router(TOKEN)
            .oneshot(session_request("PUT", &path, Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(json_body(response).await["code"], "method_not_allowed");
    }

    let response = test_router(TOKEN)
        .oneshot(session_request(
            "GET",
            &format!("/api/v1/runs/{run_id}/route-trace"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = json_body(response).await;
    assert_eq!(body["code"], "trace_not_found");
    assert!(!body.to_string().contains(run_id.to_string().as_str()));
}

#[tokio::test]
async fn same_origin_browser_reads_without_origin_keep_token_and_cross_site_protection() {
    let router = test_router(TOKEN);
    let accepted = router
        .clone()
        .oneshot(session_request(
            "POST",
            "/api/v1/url-diagnostics",
            Body::from(r#"{"url":"https://example.com"}"#),
        ))
        .await
        .unwrap();
    let run_id = json_body(accepted).await["run_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let snapshot_path = format!("/api/v1/runs/{run_id}");
    let event_path = format!("/api/v1/runs/{run_id}/events");

    for (method, path) in [
        ("GET", snapshot_path.as_str()),
        ("HEAD", snapshot_path.as_str()),
        ("GET", event_path.as_str()),
    ] {
        let response = router
            .clone()
            .oneshot(same_origin_browser_read(method, path, true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{method} {path}");

        let mut old_safari = same_origin_browser_read(method, path, true);
        old_safari.headers_mut().remove("sec-fetch-site");
        let response = router.clone().oneshot(old_safari).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "old Safari {method} {path}"
        );
    }

    let missing_token = router
        .clone()
        .oneshot(same_origin_browser_read("GET", &snapshot_path, false))
        .await
        .unwrap();
    assert_eq!(missing_token.status(), StatusCode::UNAUTHORIZED);

    let mut old_safari_missing_token = same_origin_browser_read("GET", &snapshot_path, false);
    old_safari_missing_token
        .headers_mut()
        .remove("sec-fetch-site");
    let response = router
        .clone()
        .oneshot(old_safari_missing_token)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let mut old_safari_wrong_token = same_origin_browser_read("GET", &snapshot_path, true);
    old_safari_wrong_token
        .headers_mut()
        .remove("sec-fetch-site");
    old_safari_wrong_token
        .headers_mut()
        .insert("x-npe-session", "wrong-token".parse().unwrap());
    let response = router
        .clone()
        .oneshot(old_safari_wrong_token)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    for fetch_site in ["cross-site", "same-site", "none"] {
        let mut request = same_origin_browser_read("GET", &snapshot_path, true);
        request
            .headers_mut()
            .insert("sec-fetch-site", fetch_site.parse().unwrap());
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{fetch_site}");
    }

    let mut post_without_origin = same_origin_browser_read("POST", "/api/v1/url-diagnostics", true);
    *post_without_origin.body_mut() = Body::from(r#"{"url":"https://example.com"}"#);
    let response = router.oneshot(post_without_origin).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unsupported_api_methods_return_a_json_error() {
    let response = test_router(TOKEN)
        .oneshot(session_request(
            "PUT",
            "/api/v1/url-diagnostics",
            Body::empty(),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(json_body(response).await["code"], "method_not_allowed");
}

#[test]
fn serialized_url_result_contains_only_generic_traffic_adapter_degradation() {
    let serialized = serde_json::to_string(&result("https://example.com")).unwrap();

    assert!(serialized.contains("未能确认 Clash 最终决策"));
    assert!(!serialized.contains("controller_secret"));
    assert!(!serialized.contains("/tmp/verge"));
    assert!(!serialized.contains("unrelated connection"));
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

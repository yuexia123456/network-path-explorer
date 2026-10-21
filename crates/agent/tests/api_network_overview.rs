use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use network_path_agent::{
    api::{AppState, UrlRunner, build_router},
    domain::{
        AddressScope, InterfaceAddress, InterfaceKind, LocalNetworkOverview, MihomoRuntime,
        NetworkInterfaceInfo,
    },
    error::DiagnosticError,
    ports::{EgressProvider, NetworkOverviewProvider, ProgressSink},
};
use std::sync::Arc;
use tower::ServiceExt;

const PORT: u16 = 8765;
const TOKEN: &str = "secret-token";

struct UnusedRunner;

#[async_trait]
impl UrlRunner for UnusedRunner {
    async fn run(
        &self,
        _input: &str,
        _progress: &dyn ProgressSink,
    ) -> Result<network_path_agent::domain::UrlDiagnosticResult, DiagnosticError> {
        unreachable!("network overview does not start a URL run")
    }
}

struct LocalFixture;

#[async_trait]
impl NetworkOverviewProvider for LocalFixture {
    async fn local_overview(&self) -> Result<LocalNetworkOverview, DiagnosticError> {
        Ok(LocalNetworkOverview {
            interfaces: vec![NetworkInterfaceInfo {
                name: "en0".into(),
                display_name: "Wi-Fi".into(),
                kind: InterfaceKind::Wifi,
                is_default: true,
                addresses: vec![InterfaceAddress {
                    ip: "192.168.1.20".parse().unwrap(),
                    scope: AddressScope::Private,
                }],
            }],
            default_interface: Some("en0".into()),
            mihomo: MihomoRuntime {
                available: false,
                mode: None,
                tun_enabled: None,
                controller: Some("unavailable".into()),
            },
        })
    }
}

struct FailingEgress;

#[async_trait]
impl EgressProvider for FailingEgress {
    async fn observe(
        &self,
    ) -> Result<network_path_agent::domain::EgressObservation, DiagnosticError> {
        Err(DiagnosticError::Http(
            "secret proxy/controller/body detail".into(),
        ))
    }
}

fn router() -> axum::Router {
    build_router(
        AppState::new(PORT, TOKEN, Arc::new(UnusedRunner))
            .with_network_overview(Arc::new(LocalFixture), Arc::new(FailingEgress)),
    )
}

fn request() -> Request<Body> {
    Request::builder()
        .uri("/api/v1/network-overview")
        .header("host", "127.0.0.1:8765")
        .header("origin", "http://127.0.0.1:8765")
        .header("x-npe-session", TOKEN)
        .body(Body::empty())
        .unwrap()
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn local_overview_survives_egress_failure_with_only_the_fixed_error_code() {
    let response = router().oneshot(request()).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await;
    assert_eq!(body["local"]["interfaces"][0]["name"], "en0");
    assert_eq!(
        body["local"]["interfaces"][0]["addresses"][0]["ip"],
        "192.168.1.20"
    );
    assert!(body["egress"].is_null());
    assert_eq!(body["egress_error"], "egress_unavailable");
    let serialized = body.to_string();
    assert!(!serialized.contains("secret proxy"));
    assert_eq!(
        body.as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["egress", "egress_error", "local"]
    );
}

#[tokio::test]
async fn overview_requires_exact_host_origin_or_safe_read_metadata_and_session() {
    let missing_token = Request::builder()
        .uri("/api/v1/network-overview")
        .header("host", "127.0.0.1:8765")
        .header("origin", "http://127.0.0.1:8765")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router().oneshot(missing_token).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );

    let wrong_origin = Request::builder()
        .uri("/api/v1/network-overview")
        .header("host", "127.0.0.1:8765")
        .header("origin", "http://127.0.0.1.evil:8765")
        .header("x-npe-session", TOKEN)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router().oneshot(wrong_origin).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    for fetch_site in [Some("same-origin"), None] {
        let mut builder = Request::builder()
            .uri("/api/v1/network-overview")
            .header("host", "127.0.0.1:8765")
            .header("x-npe-session", TOKEN);
        if let Some(fetch_site) = fetch_site {
            builder = builder.header("sec-fetch-site", fetch_site);
        }
        assert_eq!(
            router()
                .oneshot(builder.body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }

    let cross_site = Request::builder()
        .uri("/api/v1/network-overview")
        .header("host", "127.0.0.1:8765")
        .header("sec-fetch-site", "cross-site")
        .header("x-npe-session", TOKEN)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router().oneshot(cross_site).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}

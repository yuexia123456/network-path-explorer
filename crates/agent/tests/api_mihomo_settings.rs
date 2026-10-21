use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use bytes::Bytes;
use futures_util::stream;
use http_body_util::BodyExt;
use network_path_agent::{
    api::{AppState, UrlRunner, build_router},
    domain::UrlDiagnosticResult,
    error::DiagnosticError,
    ports::ProgressSink,
    traffic::mihomo::MihomoControllerManager,
};
use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Notify,
    task::JoinHandle,
};
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
    ) -> Result<UrlDiagnosticResult, DiagnosticError> {
        unreachable!("Mihomo settings do not start URL diagnostics")
    }
}

struct VersionServer {
    endpoint: String,
    requests: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl VersionServer {
    async fn start(ip: IpAddr, status: &'static str) -> Self {
        let listener = TcpListener::bind(SocketAddr::new(ip, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let endpoint = match address {
            SocketAddr::V4(_) => format!("http://{address}"),
            SocketAddr::V6(_) => format!("http://[{}]:{}", address.ip(), address.port()),
        };
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let captured = Arc::clone(&captured);
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        let mut chunk = [0; 2048];
                        let read = stream.read(&mut chunk).await.unwrap();
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&chunk[..read]);
                    }
                    captured
                        .lock()
                        .unwrap()
                        .push(String::from_utf8(request).unwrap());
                    let body = if status == "200 OK" {
                        r#"{"version":"fixture"}"#
                    } else {
                        r#"{"message":"sensitive controller failure"}"#
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });
        Self {
            endpoint,
            requests,
            task,
        }
    }
}

impl Drop for VersionServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct StalledVersionServer {
    endpoint: String,
    request_received: Arc<Notify>,
    connection_closed: Arc<Notify>,
    task: JoinHandle<()>,
}

impl StalledVersionServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let request_received = Arc::new(Notify::new());
        let connection_closed = Arc::new(Notify::new());
        let received = Arc::clone(&request_received);
        let closed = Arc::clone(&connection_closed);
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let mut chunk = [0_u8; 1024];
                let read = socket.read(&mut chunk).await.unwrap();
                if read == 0 {
                    return;
                }
                request.extend_from_slice(&chunk[..read]);
            }
            received.notify_one();
            let mut chunk = [0_u8; 1];
            while socket.read(&mut chunk).await.is_ok_and(|read| read != 0) {}
            closed.notify_one();
        });
        Self {
            endpoint,
            request_received,
            connection_closed,
            task,
        }
    }
}

impl Drop for StalledVersionServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn app(manager: Arc<MihomoControllerManager>) -> axum::Router {
    build_router(AppState::new(PORT, TOKEN, Arc::new(UnusedRunner)).with_mihomo_manager(manager))
}

fn request(method: &str, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri("/api/v1/mihomo-controller")
        .header("host", "127.0.0.1:8765")
        .header("origin", "http://127.0.0.1:8765")
        .header("x-npe-session", TOKEN)
        .body(body.into())
        .unwrap()
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn put_accepts_ipv4_and_ipv6_loopback_and_never_returns_the_secret() {
    for ip in [
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
    ] {
        let server = VersionServer::start(ip, "200 OK").await;
        let manager = Arc::new(MihomoControllerManager::new());
        let secret = "controller-secret-must-not-return";
        let response = app(Arc::clone(&manager))
            .oneshot(request(
                "PUT",
                Body::from(serde_json::json!({"url":server.endpoint,"secret":secret}).to_string()),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = json(response).await;
        assert_eq!(
            body,
            serde_json::json!({
                "available":true,
                "mode":null,
                "tun_enabled":null,
                "controller":"manual_loopback"
            })
        );
        assert!(!body.to_string().contains(secret));
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("GET /version HTTP/1.1\r\n"));
        assert!(requests[0].contains(&format!("\r\nauthorization: Bearer {secret}\r\n")));
    }
}

#[tokio::test]
async fn omitted_and_empty_secrets_are_normalized_to_none() {
    for body_with_secret in [false, true] {
        let server = VersionServer::start("127.0.0.1".parse().unwrap(), "200 OK").await;
        let body = if body_with_secret {
            serde_json::json!({"url":server.endpoint,"secret":""})
        } else {
            serde_json::json!({"url":server.endpoint})
        };
        let response = app(Arc::new(MihomoControllerManager::new()))
            .oneshot(request("PUT", Body::from(body.to_string())))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            !server.requests.lock().unwrap()[0]
                .to_ascii_lowercase()
                .contains("authorization:")
        );
    }
}

#[tokio::test]
async fn secret_boundary_is_1024_non_empty_bytes() {
    let server = VersionServer::start("127.0.0.1".parse().unwrap(), "200 OK").await;
    let accepted_secret = "a".repeat(1024);
    let accepted = app(Arc::new(MihomoControllerManager::new()))
        .oneshot(request(
            "PUT",
            Body::from(
                serde_json::json!({"url":server.endpoint,"secret":accepted_secret}).to_string(),
            ),
        ))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    assert!(server.requests.lock().unwrap()[0].contains(&format!(
        "\r\nauthorization: Bearer {}\r\n",
        "a".repeat(1024)
    )));

    let oversized_server = VersionServer::start("127.0.0.1".parse().unwrap(), "200 OK").await;
    let rejected = app(Arc::new(MihomoControllerManager::new()))
        .oneshot(request(
            "PUT",
            Body::from(
                serde_json::json!({"url":oversized_server.endpoint,"secret":"b".repeat(1025)})
                    .to_string(),
            ),
        ))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    assert!(oversized_server.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn put_rejects_non_loopback_credentials_and_non_root_url_components() {
    for endpoint in [
        "http://192.168.1.5:9090",
        "http://8.8.8.8:9090",
        "http://localhost:9090",
        "http://user@127.0.0.1:9090",
        "http://user:pass@127.0.0.1:9090",
        "http://127.0.0.1:9090/configs",
        "http://127.0.0.1:9090/?query=1",
        "http://127.0.0.1:9090/#fragment",
        "https://127.0.0.1:9090",
        "http://0.0.0.0:9090",
        "http://[::]:9090",
    ] {
        let response = app(Arc::new(MihomoControllerManager::new()))
            .oneshot(request(
                "PUT",
                Body::from(serde_json::json!({"url":endpoint}).to_string()),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "endpoint {endpoint}"
        );
        let body = json(response).await.to_string();
        assert!(!body.contains(endpoint));
    }
}

#[tokio::test]
async fn put_rejects_unknown_missing_and_wrong_typed_fields() {
    for body in [
        serde_json::json!({"url":"http://127.0.0.1:9090","extra":true}),
        serde_json::json!({"secret":"x"}),
        serde_json::json!({"url":9}),
        serde_json::json!({"url":"http://127.0.0.1:9090","secret":9}),
    ] {
        let response = app(Arc::new(MihomoControllerManager::new()))
            .oneshot(request("PUT", Body::from(body.to_string())))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json(response).await["code"], "invalid_request");
    }
}

#[tokio::test]
async fn failed_version_probe_leaves_the_old_manual_selection_installed() {
    let selected = VersionServer::start("127.0.0.1".parse().unwrap(), "200 OK").await;
    let rejected = VersionServer::start("127.0.0.1".parse().unwrap(), "401 Unauthorized").await;
    let manager = Arc::new(MihomoControllerManager::new());
    let selected_response = app(Arc::clone(&manager))
        .oneshot(request(
            "PUT",
            Body::from(serde_json::json!({"url":selected.endpoint}).to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(selected_response.status(), StatusCode::OK);
    let old_transport = manager.transport().await.unwrap();

    let rejected_response = app(Arc::clone(&manager))
        .oneshot(request(
            "PUT",
            Body::from(
                serde_json::json!({"url":rejected.endpoint,"secret":"never-echo"}).to_string(),
            ),
        ))
        .await
        .unwrap();

    assert_eq!(rejected_response.status(), StatusCode::BAD_REQUEST);
    assert!(
        !json(rejected_response)
            .await
            .to_string()
            .contains("never-echo")
    );
    let current_transport = manager.transport().await.unwrap();
    assert!(Arc::ptr_eq(&old_transport, &current_transport));
}

#[tokio::test]
async fn aborted_put_handler_cancels_and_closes_its_owned_version_probe() {
    let server = StalledVersionServer::start().await;
    let manager = Arc::new(MihomoControllerManager::new());
    let endpoint = server.endpoint.clone();
    let request_task = {
        let manager = Arc::clone(&manager);
        tokio::spawn(async move {
            app(manager)
                .oneshot(request(
                    "PUT",
                    Body::from(
                        serde_json::json!({
                            "url":endpoint,
                            "secret":"aborted-handler-secret"
                        })
                        .to_string(),
                    ),
                ))
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(1), server.request_received.notified())
        .await
        .expect("the version probe must reach the validated loopback server");

    request_task.abort();
    assert!(request_task.await.unwrap_err().is_cancelled());

    tokio::time::timeout(Duration::from_secs(1), server.connection_closed.notified())
        .await
        .expect("dropping the handler must close the owned version probe connection");
    tokio::time::timeout(Duration::from_secs(1), manager.shutdown())
        .await
        .expect("handler cancellation must leave no candidate task for shutdown");
    assert!(!format!("{manager:?}").contains("aborted-handler-secret"));
}

#[tokio::test]
async fn delete_cancels_pending_put_and_each_handler_returns_once() {
    let server = StalledVersionServer::start().await;
    let manager = Arc::new(MihomoControllerManager::new());
    let router = app(Arc::clone(&manager));
    let endpoint = server.endpoint.clone();
    let put = tokio::spawn({
        let router = router.clone();
        async move {
            router
                .oneshot(request(
                    "PUT",
                    Body::from(
                        serde_json::json!({"url":endpoint,"secret":"delete-cancel-secret"})
                            .to_string(),
                    ),
                ))
                .await
                .unwrap()
        }
    });
    tokio::time::timeout(Duration::from_secs(1), server.request_received.notified())
        .await
        .expect("the pending PUT must enter its version probe");

    let reset = tokio::time::timeout(
        Duration::from_secs(1),
        router.oneshot(request("DELETE", Body::empty())),
    )
    .await
    .expect("DELETE must cancel and drain the pending PUT")
    .unwrap();
    let put = tokio::time::timeout(Duration::from_secs(1), put)
        .await
        .expect("the cancelled PUT handler must return")
        .unwrap();

    assert_eq!(reset.status(), StatusCode::OK);
    assert_eq!(put.status(), StatusCode::BAD_REQUEST);
    tokio::time::timeout(Duration::from_secs(1), server.connection_closed.notified())
        .await
        .expect("DELETE must close the cancelled probe connection");
    assert!(
        !json(reset)
            .await
            .to_string()
            .contains("delete-cancel-secret")
    );
    assert!(!json(put).await.to_string().contains("delete-cancel-secret"));
    manager.shutdown().await;
}

#[tokio::test]
async fn delete_resets_to_auto_or_unavailable_and_get_never_exposes_settings() {
    let server = VersionServer::start("127.0.0.1".parse().unwrap(), "200 OK").await;
    let manager = Arc::new(MihomoControllerManager::new());
    let set = app(Arc::clone(&manager))
        .oneshot(request(
            "PUT",
            Body::from(
                serde_json::json!({"url":server.endpoint,"secret":"discard-me"}).to_string(),
            ),
        ))
        .await
        .unwrap();
    assert_eq!(set.status(), StatusCode::OK);

    let reset = app(Arc::clone(&manager))
        .oneshot(request("DELETE", Body::empty()))
        .await
        .unwrap();
    assert_eq!(reset.status(), StatusCode::OK);
    let reset_body = json(reset).await;
    assert!(matches!(
        reset_body["controller"].as_str(),
        Some("auto_unix" | "unavailable")
    ));
    assert!(!reset_body.to_string().contains("discard-me"));
    assert_ne!(
        manager.runtime().await.controller.as_deref(),
        Some("manual_loopback")
    );

    let get = app(manager)
        .oneshot(request("GET", Body::empty()))
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn settings_routes_preserve_session_origin_fetch_body_size_and_body_time_guards() {
    let manager = Arc::new(MihomoControllerManager::new());
    let missing_token = Request::builder()
        .method("PUT")
        .uri("/api/v1/mihomo-controller")
        .header("host", "127.0.0.1:8765")
        .header("origin", "http://127.0.0.1:8765")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(
        app(Arc::clone(&manager))
            .oneshot(missing_token)
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let missing_origin = Request::builder()
        .method("PUT")
        .uri("/api/v1/mihomo-controller")
        .header("host", "127.0.0.1:8765")
        .header("sec-fetch-site", "same-origin")
        .header("x-npe-session", TOKEN)
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(
        app(Arc::clone(&manager))
            .oneshot(missing_origin)
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );

    let too_large = app(Arc::clone(&manager))
        .oneshot(request("PUT", Body::from(vec![b'x'; 8 * 1024 + 1])))
        .await
        .unwrap();
    assert_eq!(too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let stalled_body = Body::from_stream(stream::pending::<Result<Bytes, Infallible>>());
    let started = std::time::Instant::now();
    let timed_out = app(manager)
        .oneshot(request("PUT", stalled_body))
        .await
        .unwrap();
    assert_eq!(timed_out.status(), StatusCode::REQUEST_TIMEOUT);
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert!(started.elapsed() < Duration::from_secs(2));
}

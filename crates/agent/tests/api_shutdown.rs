use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use network_path_agent::{
    api::{AppState, UrlRunner, build_router, serve_application},
    diagnostics::url::UrlDiagnosticService,
    domain::{
        Evidence, EvidenceLevel, HttpObservation, MihomoRuntime, ProxyDecision, ProxyKind,
        RouteInfo, TrafficDecision,
    },
    error::DiagnosticError,
    ports::{
        ProgressSink, ProxyInspector, Resolver, RouteInspector, TrafficDecisionProvider,
        TrafficObservationId, TrafficProbeScheme, TrafficProbeTarget, WebProbe,
    },
    traffic::mihomo::MihomoControllerManager,
};
use std::{
    future::pending,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{Barrier, Notify},
};
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

const PORT: u16 = 8765;
const TOKEN: &str = "secret-token";
const TCP_SYNC_DEADLINE: Duration = Duration::from_secs(1);
const BODY_TIMEOUT_HARD_DEADLINE: Duration = Duration::from_secs(2);
const SHUTDOWN_HARD_DEADLINE: Duration = Duration::from_secs(2);
const NORMAL_SHUTDOWN_DEADLINE: Duration = Duration::from_millis(250);

struct DirectProxy;

#[async_trait]
impl ProxyInspector for DirectProxy {
    async fn decision_for(&self, _url: &Url) -> Result<ProxyDecision, DiagnosticError> {
        Ok(ProxyDecision {
            kind: ProxyKind::Direct,
            host: None,
            port: None,
            bypass_reason: None,
            evidence: Evidence {
                level: EvidenceLevel::Confirmed,
                source: "test".into(),
                summary: "direct".into(),
            },
        })
    }
}

struct FixedResolver;

#[async_trait]
impl Resolver for FixedResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, DiagnosticError> {
        Ok(vec!["203.0.113.10".parse().unwrap()])
    }
}

struct PausingRoute {
    entered: Arc<Barrier>,
    release: Arc<Notify>,
}

#[async_trait]
impl RouteInspector for PausingRoute {
    async fn route_to(&self, destination: IpAddr) -> Result<RouteInfo, DiagnosticError> {
        self.entered.wait().await;
        self.release.notified().await;
        Ok(RouteInfo {
            destination,
            gateway: None,
            interface: "en0".into(),
        })
    }
}

struct ImmediateProbe;

#[async_trait]
impl WebProbe for ImmediateProbe {
    async fn probe(
        &self,
        url: &Url,
        _proxy: &ProxyDecision,
        _selected_peer: SocketAddr,
    ) -> Result<HttpObservation, DiagnosticError> {
        Ok(HttpObservation {
            status: Some(204),
            final_url: url.as_str().into(),
            elapsed_ms: 1,
            error_code: None,
            peer_endpoint: None,
        })
    }
}

#[derive(Clone)]
struct CountingTrafficProvider {
    begins: Arc<AtomicUsize>,
}

#[async_trait]
impl TrafficDecisionProvider for CountingTrafficProvider {
    async fn runtime(&self) -> MihomoRuntime {
        MihomoRuntime {
            available: true,
            mode: None,
            tun_enabled: None,
            controller: Some("fixture".into()),
        }
    }

    async fn begin(
        &self,
        _target: &TrafficProbeTarget,
    ) -> Result<TrafficObservationId, DiagnosticError> {
        self.begins.fetch_add(1, Ordering::SeqCst);
        Ok(TrafficObservationId(Uuid::new_v4()))
    }

    async fn finish(&self, _id: TrafficObservationId) -> Result<TrafficDecision, DiagnosticError> {
        Ok(TrafficDecision::unknown("fixture", "fixture"))
    }

    async fn cancel(&self, _id: TrafficObservationId) {}
}

fn request() -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/url-diagnostics")
        .header("host", "127.0.0.1:8765")
        .header("origin", "http://127.0.0.1:8765")
        .header("x-npe-session", TOKEN)
        .body(Body::from(r#"{"url":"https://example.com"}"#))
        .unwrap()
}

async fn stalled_authenticated_post(address: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let headers = format!(
        "POST /api/v1/url-diagnostics HTTP/1.1\r\nHost: {address}\r\nOrigin: http://{address}\r\nX-Npe-Session: {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: 128\r\nExpect: 100-continue\r\nConnection: keep-alive\r\n\r\n"
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    let interim = read_http_head(&mut stream, TCP_SYNC_DEADLINE).await;
    assert!(
        interim.starts_with("HTTP/1.1 100 Continue\r\n"),
        "valid authenticated request did not reach body collection: {interim:?}"
    );
    stream
        .write_all(br#"{"url":"sensitive-controller-payload"#)
        .await
        .unwrap();
    let mut byte = [0_u8; 1];
    match stream.try_read(&mut byte) {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(0) => panic!("stalled request accidentally reached EOF"),
        Ok(_) => panic!("stalled request unexpectedly received a final response"),
        Err(error) => panic!("stalled request socket failed: {error}"),
    }
    stream
}

async fn completed_authenticated_post(address: SocketAddr) -> (TcpStream, Vec<u8>) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let body = br#"{"url":"https://example.com"}"#;
    let headers = format!(
        "POST /api/v1/url-diagnostics HTTP/1.1\r\nHost: {address}\r\nOrigin: http://{address}\r\nX-Npe-Session: {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let response = read_http_response(&mut stream, TCP_SYNC_DEADLINE).await;
    (stream, response)
}

async fn read_http_head(stream: &mut TcpStream, deadline: Duration) -> String {
    tokio::time::timeout(deadline, async {
        let mut bytes = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            bytes.push(byte[0]);
            if bytes.ends_with(b"\r\n\r\n") {
                return String::from_utf8(bytes).unwrap();
            }
        }
    })
    .await
    .expect("HTTP response head exceeded synchronization deadline")
}

async fn read_http_response(stream: &mut TcpStream, deadline: Duration) -> Vec<u8> {
    let head = read_http_head(stream, deadline).await;
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .expect("timeout response declares a content length");
    let mut body = vec![0_u8; content_length];
    tokio::time::timeout(TCP_SYNC_DEADLINE, stream.read_exact(&mut body))
        .await
        .expect("timeout response body exceeded synchronization deadline")
        .unwrap();
    let mut response = head.into_bytes();
    response.extend_from_slice(&body);
    response
}

async fn assert_connection_closed(stream: &mut TcpStream) {
    let mut byte = [0_u8; 1];
    let result = tokio::time::timeout(TCP_SYNC_DEADLINE, stream.read(&mut byte))
        .await
        .expect("accepted connection remained live after serve_application returned");
    match result {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            ) => {}
        Ok(_) => panic!("accepted handler produced bytes after serve_application returned"),
        Err(error) => panic!("accepted connection closed unexpectedly: {error}"),
    }
}

async fn assert_listener_closed(address: SocketAddr) {
    let result = tokio::time::timeout(TCP_SYNC_DEADLINE, TcpStream::connect(address))
        .await
        .expect("new connection attempt did not complete after shutdown");
    assert!(
        result.is_err(),
        "listener accepted a connection after shutdown"
    );
}

#[tokio::test]
async fn shutdown_cancels_a_pre_observation_api_job_and_closes_admission() {
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Notify::new());
    let begins = Arc::new(AtomicUsize::new(0));
    let service = Arc::new(UrlDiagnosticService::new(
        DirectProxy,
        FixedResolver,
        PausingRoute {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        },
        ImmediateProbe,
        CountingTrafficProvider {
            begins: Arc::clone(&begins),
        },
    ));
    let state = AppState::new(PORT, TOKEN, service);
    let app = build_router(state.clone());

    let accepted = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    entered.wait().await;

    state.shutdown().await;
    release.notify_waiters();
    tokio::task::yield_now().await;

    assert_eq!(begins.load(Ordering::SeqCst), 0);
    let rejected = app.oneshot(request()).await.unwrap();
    assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = rejected.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["code"],
        "shutting_down"
    );
    assert!(!String::from_utf8_lossy(&body).contains("controller"));
}

struct PendingRunner {
    started: Arc<Notify>,
    order: Arc<Mutex<Vec<&'static str>>>,
}

struct JobDrop(Arc<Mutex<Vec<&'static str>>>);

impl Drop for JobDrop {
    fn drop(&mut self) {
        self.0.lock().unwrap().push("api_job_cancelled");
    }
}

#[async_trait]
impl UrlRunner for PendingRunner {
    async fn run(
        &self,
        _input: &str,
        _progress: &dyn ProgressSink,
    ) -> Result<network_path_agent::domain::UrlDiagnosticResult, DiagnosticError> {
        let _drop = JobDrop(Arc::clone(&self.order));
        self.started.notify_one();
        pending().await
    }

    async fn shutdown(&self) {
        self.order.lock().unwrap().push("url_workers_drained");
    }
}

#[tokio::test]
async fn production_graceful_shutdown_drains_jobs_before_url_and_manager_workers() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let started = Arc::new(Notify::new());
    let manager = Arc::new(MihomoControllerManager::new());
    let state = AppState::new(
        PORT,
        TOKEN,
        Arc::new(PendingRunner {
            started: Arc::clone(&started),
            order: Arc::clone(&order),
        }),
    )
    .with_mihomo_manager(Arc::clone(&manager));
    let app = build_router(state.clone());
    assert_eq!(
        app.clone().oneshot(request()).await.unwrap().status(),
        StatusCode::ACCEPTED
    );
    started.notified().await;

    let listener = network_path_agent::api::bind_listener().await.unwrap();
    let signal = Arc::new(Notify::new());
    let shutdown_signal = Arc::clone(&signal);
    let server = tokio::spawn(serve_application(listener, app, state, async move {
        shutdown_signal.notified().await;
    }));
    signal.notify_one();
    tokio::time::timeout(SHUTDOWN_HARD_DEADLINE, server)
        .await
        .expect("normal graceful shutdown exceeded its hard deadline")
        .unwrap()
        .unwrap();

    assert_eq!(
        &*order.lock().unwrap(),
        &["api_job_cancelled", "url_workers_drained"]
    );
    let result = manager
        .begin(&TrafficProbeTarget::new(
            TrafficProbeScheme::Https,
            "example.com",
            443,
            vec![],
            42,
        ))
        .await;
    assert!(
        result.is_err(),
        "manager admitted work after application drain"
    );
}

#[tokio::test]
async fn stalled_authenticated_body_cannot_exceed_the_graceful_shutdown_deadline() {
    let listener = network_path_agent::api::bind_listener().await.unwrap();
    let address = listener.local_addr().unwrap();
    let order = Arc::new(Mutex::new(Vec::new()));
    let manager = Arc::new(MihomoControllerManager::new());
    let state = AppState::new(
        address.port(),
        TOKEN,
        Arc::new(PendingRunner {
            started: Arc::new(Notify::new()),
            order: Arc::clone(&order),
        }),
    )
    .with_mihomo_manager(Arc::clone(&manager));
    let app = build_router(state.clone());
    let signal = Arc::new(Notify::new());
    let shutdown_signal = Arc::clone(&signal);
    let mut server = tokio::spawn(serve_application(
        listener,
        app,
        state.clone(),
        async move {
            shutdown_signal.notified().await;
        },
    ));
    let mut stalled_stream = stalled_authenticated_post(address).await;
    assert_eq!(state.active_connection_tasks(), 1);

    signal.notify_one();
    let outcome = tokio::time::timeout(SHUTDOWN_HARD_DEADLINE, &mut server).await;
    if outcome.is_err() {
        server.abort();
        let _ = server.await;
    }

    outcome
        .expect("graceful shutdown exceeded its documented two-second hard deadline")
        .unwrap()
        .unwrap();
    assert_eq!(&*order.lock().unwrap(), &["url_workers_drained"]);
    assert!(
        manager
            .begin(&TrafficProbeTarget::new(
                TrafficProbeScheme::Https,
                "example.com",
                443,
                vec![],
                42,
            ))
            .await
            .is_err(),
        "manager cleanup did not complete before the bounded connection drain"
    );
    assert_eq!(state.active_connection_tasks(), 0);
    assert_connection_closed(&mut stalled_stream).await;
    assert_listener_closed(address).await;
}

#[tokio::test]
async fn incomplete_authenticated_body_returns_only_a_safe_timeout_response() {
    let listener = network_path_agent::api::bind_listener().await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = AppState::new(
        address.port(),
        TOKEN,
        Arc::new(PendingRunner {
            started: Arc::new(Notify::new()),
            order: Arc::new(Mutex::new(Vec::new())),
        }),
    );
    let app = build_router(state.clone());
    let signal = Arc::new(Notify::new());
    let shutdown_signal = Arc::clone(&signal);
    let mut server = tokio::spawn(serve_application(listener, app, state, async move {
        shutdown_signal.notified().await;
    }));
    let mut stalled_stream = stalled_authenticated_post(address).await;

    let response = read_http_response(&mut stalled_stream, BODY_TIMEOUT_HARD_DEADLINE).await;

    assert!(response.starts_with(b"HTTP/1.1 408 Request Timeout\r\n"));
    assert!(String::from_utf8_lossy(&response).contains("request_timeout"));
    assert!(!String::from_utf8_lossy(&response).contains("sensitive-controller-payload"));
    assert!(!String::from_utf8_lossy(&response).contains("controller"));
    signal.notify_one();
    tokio::time::timeout(SHUTDOWN_HARD_DEADLINE, &mut server)
        .await
        .expect("server did not stop after the timed-out request completed")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn completed_authenticated_connection_finishes_normally_during_shutdown() {
    let listener = network_path_agent::api::bind_listener().await.unwrap();
    let address = listener.local_addr().unwrap();
    let order = Arc::new(Mutex::new(Vec::new()));
    let started = Arc::new(Notify::new());
    let state = AppState::new(
        address.port(),
        TOKEN,
        Arc::new(PendingRunner {
            started: Arc::clone(&started),
            order: Arc::clone(&order),
        }),
    );
    let app = build_router(state.clone());
    let signal = Arc::new(Notify::new());
    let shutdown_signal = Arc::clone(&signal);
    let mut server = tokio::spawn(serve_application(
        listener,
        app,
        state.clone(),
        async move {
            shutdown_signal.notified().await;
        },
    ));
    let (mut stream, response) = completed_authenticated_post(address).await;
    started.notified().await;

    assert!(response.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
    assert_eq!(state.active_connection_tasks(), 1);
    signal.notify_one();
    tokio::time::timeout(NORMAL_SHUTDOWN_DEADLINE, &mut server)
        .await
        .expect("normal connection waited for the forced-drain deadline")
        .unwrap()
        .unwrap();

    assert_eq!(
        &*order.lock().unwrap(),
        &["api_job_cancelled", "url_workers_drained"]
    );
    assert_eq!(state.active_connection_tasks(), 0);
    assert_connection_closed(&mut stream).await;
    assert_listener_closed(address).await;
}

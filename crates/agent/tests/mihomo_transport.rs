use network_path_agent::traffic::mihomo::{
    ControllerConfig, ControllerSecret, LocalMihomoTransport, MihomoControllerManager,
    MihomoEndpoint, MihomoTransport,
};
use std::{
    collections::VecDeque,
    future::pending,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

#[test]
fn controller_endpoint_rejects_non_loopback_tcp() {
    assert!(MihomoEndpoint::parse("http://192.168.1.5:9090").is_err());
    assert!(MihomoEndpoint::parse("http://127.0.0.1:9090").is_ok());
    assert!(MihomoEndpoint::parse("http://[::1]:9090").is_ok());
}

#[test]
fn controller_endpoint_rejects_ambiguous_or_out_of_scope_urls() {
    for endpoint in [
        "https://127.0.0.1:9090",
        "http://user:password@127.0.0.1:9090",
        "http://@127.0.0.1:9090",
        "http://127.0.0.1:9090/version",
        "http://127.0.0.1:9090/./",
        "http://127.0.0.1:9090/?query=1",
        "http://127.0.0.1:9090/#fragment",
        "http://127.0.0.1:0",
        "http://0.0.0.0:9090",
        "http://[::]:9090",
        "http://localhost:9090",
    ] {
        assert!(
            MihomoEndpoint::parse(endpoint).is_err(),
            "accepted {endpoint}"
        );
    }
}

#[test]
fn controller_endpoint_uses_the_plain_http_default_port() {
    for endpoint in ["http://127.0.0.1", "http://127.0.0.1:80"] {
        assert_eq!(
            MihomoEndpoint::parse(endpoint).unwrap().loopback_addr(),
            Some("127.0.0.1:80".parse().unwrap())
        );
    }
}

#[test]
fn controller_secret_debug_is_redacted() {
    let secret = ControllerSecret::new("never-print-this");

    assert_eq!(format!("{secret:?}"), "ControllerSecret([redacted])");
}

#[test]
fn controller_config_allows_an_absent_secret() {
    let endpoint = MihomoEndpoint::parse("http://127.0.0.1:9090").unwrap();

    let config = ControllerConfig::new(endpoint, None);

    assert!(!config.has_secret());
}

struct FakeLoopbackController {
    endpoint: String,
    requests: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl FakeLoopbackController {
    async fn start(responses: Vec<Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let server_requests = Arc::clone(&requests);
        let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let requests = Arc::clone(&server_requests);
                let responses = Arc::clone(&responses);
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut chunk = [0_u8; 1024];
                    loop {
                        let read = socket.read(&mut chunk).await.unwrap();
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&chunk[..read]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    requests
                        .lock()
                        .unwrap()
                        .push(String::from_utf8(request).unwrap());
                    let response = responses.lock().unwrap().pop_front().unwrap();
                    socket.write_all(&response).await.unwrap();
                    socket.shutdown().await.unwrap();
                });
            }
        });
        Self {
            endpoint,
            requests,
            task,
        }
    }

    fn config(&self, secret: Option<&str>) -> ControllerConfig {
        ControllerConfig::new(
            MihomoEndpoint::parse(&self.endpoint).unwrap(),
            secret.map(ControllerSecret::new),
        )
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for FakeLoopbackController {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone, Copy, Debug)]
enum ProbeStall {
    Accept,
    Headers,
    Body,
}

struct StalledLoopbackController {
    endpoint: String,
    task: JoinHandle<()>,
}

impl StalledLoopbackController {
    async fn start(stall: ProbeStall) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            if matches!(stall, ProbeStall::Accept) {
                let _listener = listener;
                return pending().await;
            }
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
            if matches!(stall, ProbeStall::Body) {
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 64\r\nconnection: close\r\n\r\n{",
                    )
                    .await
                    .unwrap();
            }
            pending().await
        });
        Self { endpoint, task }
    }
}

impl Drop for StalledLoopbackController {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn json_response(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[tokio::test]
async fn loopback_transport_uses_get_and_omits_missing_authorization() {
    let server = FakeLoopbackController::start(vec![
        json_response("200 OK", r#"{"mode":"rule","tun":{"enable":true}}"#),
        json_response(
            "200 OK",
            r#"{"proxies":{"DIRECT":{"name":"DIRECT","type":"Direct","alive":true,"history":[{"delay":7}]}}}"#,
        ),
    ])
    .await;
    let transport = LocalMihomoTransport::new(server.config(None));

    let runtime = transport.runtime().await.unwrap();
    let proxies = transport.proxies().await.unwrap();

    assert!(runtime.available);
    assert_eq!(runtime.mode.as_deref(), Some("rule"));
    assert_eq!(runtime.tun_enabled, Some(true));
    assert_eq!(runtime.controller.as_deref(), Some("manual_loopback"));
    assert_eq!(proxies["DIRECT"].delay_ms, Some(7));
    let requests = server.requests();
    assert!(requests[0].starts_with("GET /configs HTTP/1.1\r\n"));
    assert!(requests[1].starts_with("GET /proxies HTTP/1.1\r\n"));
    assert!(
        requests
            .iter()
            .all(|request| { !request.to_ascii_lowercase().contains("\r\nauthorization:") })
    );
}

#[tokio::test]
async fn loopback_transport_preserves_explicit_provider_and_dialer_fields() {
    let server = FakeLoopbackController::start(vec![json_response(
        "200 OK",
        r#"{
            "proxies": {
                "落地节点": {
                    "name": "落地节点",
                    "type": "Shadowsocks",
                    "alive": true,
                    "history": [{"delay": 37}],
                    "provider-name": "机场订阅",
                    "dialer-proxy": "前置组"
                }
            }
        }"#,
    )])
    .await;
    let transport = LocalMihomoTransport::new(server.config(None));

    let proxies = transport.proxies().await.unwrap();
    let proxy = &proxies["落地节点"];

    assert_eq!(proxy.provider_name.as_deref(), Some("机场订阅"));
    assert_eq!(proxy.dialer_proxy.as_deref(), Some("前置组"));
    assert_eq!(proxy.delay_ms, Some(37));
}

#[tokio::test]
async fn loopback_transport_sends_bearer_auth_and_redacts_auth_failures() {
    let supplied_secret = "ultra-secret-controller-token";
    for status in ["401 Unauthorized", "403 Forbidden"] {
        let server = FakeLoopbackController::start(vec![json_response(status, "{}")]).await;
        let transport = LocalMihomoTransport::new(server.config(Some(supplied_secret)));

        let error = transport.runtime().await.unwrap_err().to_string();

        assert!(error.contains("authentication failed"));
        assert!(!error.contains(supplied_secret));
        assert!(
            server.requests()[0]
                .contains(&format!("\r\nauthorization: Bearer {supplied_secret}\r\n"))
        );
    }
}

#[tokio::test]
async fn loopback_transport_rejects_redirects_without_following_them() {
    let redirect_target =
        FakeLoopbackController::start(vec![json_response("200 OK", r#"{"mode":"global"}"#)]).await;
    let secret = "redirect-must-not-forward-this-secret";
    let response = format!(
        "HTTP/1.1 302 Found\r\nlocation: {}/configs\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        redirect_target.endpoint
    )
    .into_bytes();
    let server = FakeLoopbackController::start(vec![response]).await;
    let transport = LocalMihomoTransport::new(server.config(Some(secret)));

    let error = transport.runtime().await.unwrap_err().to_string();

    assert!(error.contains("redirect"));
    assert_eq!(server.requests().len(), 1);
    assert!(server.requests()[0].contains(&format!("authorization: Bearer {secret}")));
    assert!(redirect_target.requests().is_empty());
    assert!(!format!("{transport:?}").contains(secret));
}

#[tokio::test]
async fn finite_get_rejects_response_bodies_over_two_mib() {
    let body = vec![b'x'; 2 * 1024 * 1024 + 1];
    let mut response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend(body);
    let server = FakeLoopbackController::start(vec![response]).await;
    let transport = LocalMihomoTransport::new(server.config(None));

    let error = transport.runtime().await.unwrap_err().to_string();

    assert!(error.contains("body limit"));
}

#[tokio::test]
async fn manager_probes_version_before_selecting_a_manual_controller() {
    let server =
        FakeLoopbackController::start(vec![json_response("200 OK", r#"{"version":"1.19.0"}"#)])
            .await;
    let manager = MihomoControllerManager::new();

    manager
        .set_manual(&server.endpoint, Some("manager-secret".into()))
        .await
        .unwrap();
    let runtime = manager.runtime().await;

    assert!(runtime.available);
    assert_eq!(runtime.mode, None);
    assert_eq!(runtime.tun_enabled, None);
    assert_eq!(runtime.controller.as_deref(), Some("manual_loopback"));
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /version HTTP/1.1\r\n"));
    assert!(requests[0].contains("\r\nauthorization: Bearer manager-secret\r\n"));
}

#[tokio::test]
async fn manual_version_probe_has_one_second_total_deadline_for_accept_headers_and_body() {
    for stall in [ProbeStall::Accept, ProbeStall::Headers, ProbeStall::Body] {
        let server = StalledLoopbackController::start(stall).await;
        let manager = MihomoControllerManager::new();
        let started = Instant::now();

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            manager.set_manual(&server.endpoint, Some("deadline-secret".into())),
        )
        .await
        .unwrap_or_else(|_| panic!("{stall:?} exceeded the owned total deadline"));

        assert!(result.is_err(), "{stall:?}");
        assert!(started.elapsed() >= Duration::from_millis(750), "{stall:?}");
        assert!(started.elapsed() < Duration::from_secs(2), "{stall:?}");
        assert_ne!(
            manager.runtime().await.controller.as_deref(),
            Some("manual_loopback"),
            "{stall:?}"
        );
        manager.shutdown().await;
    }
}

#[tokio::test]
async fn manager_keeps_the_previous_transport_when_a_probe_fails() {
    let selected = FakeLoopbackController::start(vec![
        json_response("200 OK", r#"{"version":"1.19.0"}"#),
        json_response("200 OK", r#"{"mode":"rule","tun":{"enable":true}}"#),
    ])
    .await;
    let rejected = FakeLoopbackController::start(vec![json_response("403 Forbidden", "{}")]).await;
    let manager = MihomoControllerManager::new();
    manager.set_manual(&selected.endpoint, None).await.unwrap();

    let error = manager
        .set_manual(&rejected.endpoint, Some("rejected-secret".into()))
        .await
        .unwrap_err()
        .to_string();
    let runtime = manager.transport().await.unwrap().runtime().await.unwrap();

    assert!(error.contains("authentication failed"));
    assert!(!error.contains("rejected-secret"));
    assert_eq!(runtime.mode.as_deref(), Some("rule"));
    assert_eq!(selected.requests().len(), 2);
}

#[tokio::test]
async fn manager_runtime_and_debug_never_expose_the_manual_secret() {
    let secret = "manager-debug-must-stay-redacted";
    let server =
        FakeLoopbackController::start(vec![json_response("200 OK", r#"{"version":"1.19.0"}"#)])
            .await;
    let manager = MihomoControllerManager::new();
    manager
        .set_manual(&server.endpoint, Some(secret.into()))
        .await
        .unwrap();

    let runtime_json = serde_json::to_string(&manager.runtime().await).unwrap();
    let debug = format!("{manager:?}");

    assert_eq!(
        runtime_json,
        r#"{"available":true,"mode":null,"tun_enabled":null,"controller":"manual_loopback"}"#
    );
    assert!(!runtime_json.contains(secret));
    assert!(!debug.contains(secret));
    assert!(debug.contains("manual_loopback"));

    manager.reset_auto().await;
    let reset_controller = manager.runtime().await.controller.unwrap();
    assert!(matches!(
        reset_controller.as_str(),
        "auto_unix" | "unavailable"
    ));
    assert!(!format!("{manager:?}").contains(secret));
}

use network_path_agent::traffic::mihomo::MihomoControllerManager;
use std::{
    ffi::OsString,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

struct EnvironmentGuard {
    saved: Vec<(&'static str, Option<OsString>)>,
}

impl EnvironmentGuard {
    fn force_ambient_proxy(proxy: &str) -> Self {
        // This integration-test binary contains one test, so its process-global environment
        // mutation cannot race another test thread. Other Cargo test binaries are separate
        // processes with independent environments.
        let values = [
            ("HTTP_PROXY", proxy),
            ("http_proxy", proxy),
            ("ALL_PROXY", proxy),
            ("all_proxy", proxy),
            ("NO_PROXY", ""),
            ("no_proxy", ""),
        ];
        let saved = values
            .iter()
            .map(|(name, _)| (*name, std::env::var_os(name)))
            .collect();
        for (name, value) in values {
            // SAFETY: this is the only test in its test-process, before any worker task that
            // reads proxy environment variables is started.
            unsafe { std::env::set_var(name, value) };
        }
        Self { saved }
    }
}

impl Drop for EnvironmentGuard {
    fn drop(&mut self) {
        for (name, value) in self.saved.drain(..) {
            // SAFETY: all request tasks are awaited before this guard is dropped, and this test
            // is the only test thread in the process.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

struct AmbientProxy {
    endpoint: String,
    connections: Arc<AtomicUsize>,
    bytes: Arc<AtomicUsize>,
    payload: Arc<Mutex<Vec<u8>>>,
    task: JoinHandle<()>,
}

impl AmbientProxy {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let connections = Arc::new(AtomicUsize::new(0));
        let bytes = Arc::new(AtomicUsize::new(0));
        let payload = Arc::new(Mutex::new(Vec::new()));
        let accepted = Arc::clone(&connections);
        let observed = Arc::clone(&bytes);
        let captured = Arc::clone(&payload);
        let task = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                accepted.fetch_add(1, Ordering::SeqCst);
                let observed = Arc::clone(&observed);
                let captured = Arc::clone(&captured);
                tokio::spawn(async move {
                    let mut request = [0_u8; 4096];
                    if let Ok(read) = socket.read(&mut request).await {
                        observed.fetch_add(read, Ordering::SeqCst);
                        captured.lock().unwrap().extend_from_slice(&request[..read]);
                    }
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                        )
                        .await;
                });
            }
        });
        Self {
            endpoint,
            connections,
            bytes,
            payload,
            task,
        }
    }
}

impl Drop for AmbientProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct LoopbackVersionController {
    endpoint: String,
    task: JoinHandle<()>,
}

impl LoopbackVersionController {
    async fn start(ip: IpAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::new(ip, 0)).await?;
        let address = listener.local_addr()?;
        let endpoint = match address {
            SocketAddr::V4(_) => format!("http://{address}"),
            SocketAddr::V6(_) => format!("http://[{}]:{}", address.ip(), address.port()),
        };
        let task = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        let mut chunk = [0_u8; 1024];
                        let read = socket.read(&mut chunk).await.unwrap();
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&chunk[..read]);
                    }
                    let body = br#"{"version":"fixture"}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    socket.write_all(response.as_bytes()).await.unwrap();
                    socket.write_all(body).await.unwrap();
                });
            }
        });
        Ok(Self { endpoint, task })
    }
}

impl Drop for LoopbackVersionController {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn manual_loopback_probes_bypass_ambient_proxies_for_ipv4_and_ipv6() {
    let ambient_proxy = AmbientProxy::start().await;
    let _environment = EnvironmentGuard::force_ambient_proxy(&ambient_proxy.endpoint);
    let manager = MihomoControllerManager::new();
    let secret = "ambient-proxy-must-never-receive-this";
    let mut tested = 0;

    for ip in ["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()] {
        let Ok(controller) = LoopbackVersionController::start(ip).await else {
            continue;
        };
        manager
            .set_manual(&controller.endpoint, Some(secret.into()))
            .await
            .unwrap();
        tested += 1;
    }

    assert!(tested >= 1, "at least IPv4 loopback must be available");
    assert_eq!(ambient_proxy.connections.load(Ordering::SeqCst), 0);
    assert_eq!(ambient_proxy.bytes.load(Ordering::SeqCst), 0);
    assert!(!String::from_utf8_lossy(&ambient_proxy.payload.lock().unwrap()).contains(secret));
    assert!(
        !serde_json::to_string(&manager.runtime().await)
            .unwrap()
            .contains(secret)
    );
    assert!(!format!("{manager:?}").contains(secret));
    manager.shutdown().await;
}

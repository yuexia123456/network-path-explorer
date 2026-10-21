use super::{ControllerConfig, MihomoConnectionEvent, MihomoEvent, MihomoLogEvent, MihomoProxy};
use crate::{domain::MihomoRuntime, error::DiagnosticError};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{Stream, StreamExt, future};
use http_body_util::{BodyExt, Empty};
use hyper::{Request, StatusCode, header};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use std::{collections::HashMap, pin::Pin, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};
use tokio_tungstenite::{
    WebSocketStream, client_async,
    tungstenite::{
        Message, client::IntoClientRequest, handshake::client::Request as WebSocketRequest,
    },
};

const RESPONSE_BODY_LIMIT: usize = 2 * 1024 * 1024;

pub type MihomoEventStream =
    Pin<Box<dyn Stream<Item = Result<MihomoEvent, DiagnosticError>> + Send>>;

#[async_trait]
pub trait MihomoTransport: Send + Sync {
    async fn runtime(&self) -> Result<MihomoRuntime, DiagnosticError>;
    async fn proxies(&self) -> Result<HashMap<String, MihomoProxy>, DiagnosticError>;
    async fn connection_stream(
        &self,
        interval: Duration,
    ) -> Result<MihomoEventStream, DiagnosticError>;
    async fn log_stream(&self) -> Result<MihomoEventStream, DiagnosticError>;
}

#[derive(Clone, Debug)]
pub struct LocalMihomoTransport {
    config: ControllerConfig,
}

impl LocalMihomoTransport {
    pub fn new(config: ControllerConfig) -> Self {
        Self { config }
    }

    pub(crate) async fn version(&self) -> Result<(), DiagnosticError> {
        let body = self.finite_get("/version").await?;
        serde_json::from_slice::<VersionWire>(&body)
            .map(|_| ())
            .map_err(|_| controller_error("Mihomo controller returned invalid JSON"))
    }

    async fn finite_get(&self, path: &'static str) -> Result<Vec<u8>, DiagnosticError> {
        if let Some(socket_path) = self.config.endpoint().unix_path() {
            self.unix_get(socket_path, path).await
        } else if let Some(address) = self.config.endpoint().loopback_addr() {
            self.loopback_get(address, path).await
        } else {
            Err(controller_error("invalid Mihomo controller endpoint"))
        }
    }

    async fn loopback_get(
        &self,
        address: std::net::SocketAddr,
        path: &'static str,
    ) -> Result<Vec<u8>, DiagnosticError> {
        let client = reqwest::Client::builder()
            // A validated loopback controller must never be re-routed through ambient proxies;
            // in particular, its bearer secret must remain on the direct loopback connection.
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| controller_error("Mihomo controller request failed"))?;
        let mut request = client.get(format!("http://{address}{path}"));
        if let Some(secret) = self.config.secret() {
            request = request.bearer_auth(secret.expose());
        }
        let response = request
            .send()
            .await
            .map_err(|_| controller_error("Mihomo controller request failed"))?;
        validate_status(response.status())?;
        if response.content_length().is_some_and(|size| {
            size > u64::try_from(RESPONSE_BODY_LIMIT).expect("body limit fits in u64")
        }) {
            return Err(controller_error(
                "Mihomo controller response exceeded the body limit",
            ));
        }

        let mut response = response;
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| controller_error("Mihomo controller response failed"))?
        {
            append_limited(&mut body, &chunk)?;
        }
        Ok(body)
    }

    async fn unix_get(
        &self,
        socket_path: &std::path::Path,
        path: &'static str,
    ) -> Result<Vec<u8>, DiagnosticError> {
        let socket = UnixStream::connect(socket_path)
            .await
            .map_err(|_| controller_error("Mihomo controller request failed"))?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(socket))
            .await
            .map_err(|_| controller_error("Mihomo controller request failed"))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let mut request = Request::builder()
            .method("GET")
            .uri(path)
            .header(header::HOST, "localhost");
        if let Some(secret) = self.config.secret() {
            request = request.header(header::AUTHORIZATION, format!("Bearer {}", secret.expose()));
        }
        let request = request
            .body(Empty::<Bytes>::new())
            .map_err(|_| controller_error("Mihomo controller request failed"))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| controller_error("Mihomo controller request failed"))?;
        validate_status(response.status())?;
        if response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|size| size > RESPONSE_BODY_LIMIT)
        {
            return Err(controller_error(
                "Mihomo controller response exceeded the body limit",
            ));
        }

        let mut incoming = response.into_body();
        let mut body = Vec::new();
        while let Some(frame) = incoming.frame().await {
            let frame = frame.map_err(|_| controller_error("Mihomo controller response failed"))?;
            if let Ok(chunk) = frame.into_data() {
                append_limited(&mut body, &chunk)?;
            }
        }
        Ok(body)
    }

    async fn websocket(
        &self,
        path: String,
        event_kind: EventKind,
    ) -> Result<MihomoEventStream, DiagnosticError> {
        let request = self.websocket_request(&path)?;
        if let Some(socket_path) = self.config.endpoint().unix_path() {
            let socket = UnixStream::connect(socket_path)
                .await
                .map_err(|_| controller_error("Mihomo controller WebSocket failed"))?;
            let websocket = client_async(request, socket)
                .await
                .map_err(map_websocket_handshake_error)?
                .0;
            Ok(map_websocket(websocket, event_kind))
        } else if let Some(address) = self.config.endpoint().loopback_addr() {
            // Keep the WebSocket handshake on the same validated direct-loopback invariant as
            // finite HTTP requests; `client_async` operates on this already-connected stream.
            let socket = TcpStream::connect(address)
                .await
                .map_err(|_| controller_error("Mihomo controller WebSocket failed"))?;
            let websocket = client_async(request, socket)
                .await
                .map_err(map_websocket_handshake_error)?
                .0;
            Ok(map_websocket(websocket, event_kind))
        } else {
            Err(controller_error("invalid Mihomo controller endpoint"))
        }
    }

    fn websocket_request(&self, path: &str) -> Result<WebSocketRequest, DiagnosticError> {
        let authority = if self.config.endpoint().unix_path().is_some() {
            "localhost".to_owned()
        } else if let Some(address) = self.config.endpoint().loopback_addr() {
            address.to_string()
        } else {
            return Err(controller_error("invalid Mihomo controller endpoint"));
        };
        let mut request = format!("ws://{authority}{path}")
            .into_client_request()
            .map_err(|_| controller_error("Mihomo controller WebSocket failed"))?;
        if let Some(secret) = self.config.secret() {
            let value =
                hyper::header::HeaderValue::from_str(&format!("Bearer {}", secret.expose()))
                    .map_err(|_| controller_error("Mihomo controller authentication failed"))?;
            request.headers_mut().insert(header::AUTHORIZATION, value);
        }
        Ok(request)
    }
}

#[async_trait]
impl MihomoTransport for LocalMihomoTransport {
    async fn runtime(&self) -> Result<MihomoRuntime, DiagnosticError> {
        let wire: ConfigWire = serde_json::from_slice(&self.finite_get("/configs").await?)
            .map_err(|_| controller_error("Mihomo controller returned invalid JSON"))?;
        Ok(MihomoRuntime {
            available: true,
            mode: wire.mode,
            tun_enabled: wire.tun.map(|tun| tun.enable),
            controller: Some(self.config.endpoint().controller_label().into()),
        })
    }

    async fn proxies(&self) -> Result<HashMap<String, MihomoProxy>, DiagnosticError> {
        let wire: ProxiesWire = serde_json::from_slice(&self.finite_get("/proxies").await?)
            .map_err(|_| controller_error("Mihomo controller returned invalid JSON"))?;
        Ok(wire
            .proxies
            .into_iter()
            .map(|(key, proxy)| {
                let delay_ms = proxy.history.last().map(|entry| entry.delay);
                (
                    key,
                    MihomoProxy {
                        name: proxy.name,
                        kind: proxy.kind,
                        now: proxy.now,
                        all: proxy.all,
                        alive: proxy.alive,
                        delay_ms,
                        provider_name: proxy.provider_name,
                        dialer_proxy: proxy.dialer_proxy,
                    },
                )
            })
            .collect())
    }

    async fn connection_stream(
        &self,
        interval: Duration,
    ) -> Result<MihomoEventStream, DiagnosticError> {
        self.websocket(
            format!("/connections?interval={}", interval.as_millis()),
            EventKind::Connection,
        )
        .await
    }

    async fn log_stream(&self) -> Result<MihomoEventStream, DiagnosticError> {
        self.websocket("/logs".into(), EventKind::Log).await
    }
}

fn append_limited(body: &mut Vec<u8>, chunk: &[u8]) -> Result<(), DiagnosticError> {
    if body.len().saturating_add(chunk.len()) > RESPONSE_BODY_LIMIT {
        return Err(controller_error(
            "Mihomo controller response exceeded the body limit",
        ));
    }
    body.extend_from_slice(chunk);
    Ok(())
}

fn validate_status(status: StatusCode) -> Result<(), DiagnosticError> {
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        return Err(controller_error("Mihomo controller authentication failed"));
    }
    if status.is_redirection() {
        return Err(controller_error("Mihomo controller redirect rejected"));
    }
    if !status.is_success() {
        return Err(controller_error("Mihomo controller request failed"));
    }
    Ok(())
}

fn controller_error(message: &str) -> DiagnosticError {
    DiagnosticError::System(message.into())
}

fn map_websocket_handshake_error(error: tokio_tungstenite::tungstenite::Error) -> DiagnosticError {
    if let tokio_tungstenite::tungstenite::Error::Http(response) = &error {
        if matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            return controller_error("Mihomo controller authentication failed");
        }
        if response.status().is_redirection() {
            return controller_error("Mihomo controller redirect rejected");
        }
    }
    controller_error("Mihomo controller WebSocket failed")
}

#[derive(Clone, Copy)]
enum EventKind {
    Connection,
    Log,
}

fn map_websocket<S>(websocket: WebSocketStream<S>, event_kind: EventKind) -> MihomoEventStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    Box::pin(websocket.filter_map(move |message| {
        future::ready(match message {
            Ok(Message::Text(text)) => Some(parse_event(text.as_bytes(), event_kind)),
            Ok(Message::Close(_)) => None,
            Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => None,
            Ok(Message::Binary(_)) => Some(Err(controller_error(
                "Mihomo controller sent a non-JSON WebSocket message",
            ))),
            Err(_) => Some(Err(controller_error("Mihomo controller WebSocket failed"))),
        })
    }))
}

fn parse_event(bytes: &[u8], event_kind: EventKind) -> Result<MihomoEvent, DiagnosticError> {
    match event_kind {
        EventKind::Connection => serde_json::from_slice::<ConnectionWire>(bytes)
            .map(|event| {
                MihomoEvent::Connection(MihomoConnectionEvent {
                    download_total: event.download_total,
                    upload_total: event.upload_total,
                    connections: event.connections,
                })
            })
            .map_err(|_| controller_error("Mihomo controller sent a non-JSON WebSocket message")),
        EventKind::Log => serde_json::from_slice::<LogWire>(bytes)
            .map(|event| {
                MihomoEvent::Log(MihomoLogEvent {
                    r#type: event.kind,
                    payload: event.payload,
                })
            })
            .map_err(|_| controller_error("Mihomo controller sent a non-JSON WebSocket message")),
    }
}

#[derive(Deserialize)]
struct ConfigWire {
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    tun: Option<TunWire>,
}

#[derive(Deserialize)]
struct TunWire {
    enable: bool,
}

#[derive(Deserialize)]
struct ProxiesWire {
    proxies: HashMap<String, ProxyWire>,
}

#[derive(Deserialize)]
struct ProxyWire {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    now: Option<String>,
    #[serde(default)]
    all: Vec<String>,
    #[serde(default)]
    alive: Option<bool>,
    #[serde(default)]
    history: Vec<DelayWire>,
    #[serde(default, rename = "provider-name")]
    provider_name: Option<String>,
    #[serde(default, rename = "dialer-proxy")]
    dialer_proxy: Option<String>,
}

#[derive(Deserialize)]
struct DelayWire {
    delay: u16,
}

#[derive(Deserialize)]
struct ConnectionWire {
    #[serde(default, rename = "downloadTotal")]
    download_total: u64,
    #[serde(default, rename = "uploadTotal")]
    upload_total: u64,
    #[serde(default)]
    connections: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct LogWire {
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    payload: String,
}

#[derive(Deserialize)]
struct VersionWire {
    #[serde(rename = "version")]
    _version: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traffic::mihomo::ControllerSecret;
    use futures_util::{SinkExt, StreamExt};
    use std::{
        collections::VecDeque,
        fs,
        path::PathBuf,
        sync::{Arc, Mutex},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixListener,
        task::JoinHandle,
    };
    use tokio_tungstenite::{
        accept_hdr_async,
        tungstenite::{Message, handshake::server::Request as WebSocketRequest},
    };

    struct FakeUnixController {
        directory: PathBuf,
        socket_path: PathBuf,
        requests: Arc<Mutex<Vec<String>>>,
        task: JoinHandle<()>,
    }

    impl FakeUnixController {
        #[allow(clippy::result_large_err)]
        async fn start(http_responses: Vec<Vec<u8>>, websocket_messages: Vec<&str>) -> Self {
            let directory = PathBuf::from(format!("/tmp/npa-m-{}", uuid::Uuid::new_v4().simple()));
            fs::create_dir(&directory).unwrap();
            let socket_path = directory.join("controller.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let server_requests = Arc::clone(&requests);
            let http_responses = Arc::new(Mutex::new(VecDeque::from(http_responses)));
            let websocket_messages = Arc::new(Mutex::new(VecDeque::from(
                websocket_messages
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            )));
            let task = tokio::spawn(async move {
                loop {
                    let Ok((mut socket, _)) = listener.accept().await else {
                        return;
                    };
                    let maybe_http_response = http_responses.lock().unwrap().pop_front();
                    if let Some(response) = maybe_http_response {
                        let requests = Arc::clone(&server_requests);
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
                            socket.write_all(&response).await.unwrap();
                            socket.shutdown().await.unwrap();
                        });
                    } else {
                        let requests = Arc::clone(&server_requests);
                        let message = websocket_messages.lock().unwrap().pop_front().unwrap();
                        tokio::spawn(async move {
                            let mut websocket =
                                accept_hdr_async(socket, |request: &WebSocketRequest, response| {
                                    let authorization = request
                                        .headers()
                                        .get("authorization")
                                        .and_then(|value| value.to_str().ok())
                                        .unwrap_or("<none>");
                                    requests.lock().unwrap().push(format!(
                                        "WS_GET {} authorization={authorization}",
                                        request.uri()
                                    ));
                                    Ok(response)
                                })
                                .await
                                .unwrap();
                            websocket.send(Message::Text(message.into())).await.unwrap();
                        });
                    }
                }
            });
            Self {
                directory,
                socket_path,
                requests,
                task,
            }
        }

        fn config(&self, secret: Option<&str>) -> ControllerConfig {
            ControllerConfig::test_unix(self.socket_path.clone(), secret.map(ControllerSecret::new))
        }

        fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl Drop for FakeUnixController {
        fn drop(&mut self) {
            self.task.abort();
            fs::remove_dir_all(&self.directory).unwrap();
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
    async fn unix_transport_only_issues_get_and_read_only_websockets() {
        let server = FakeUnixController::start(
            vec![
                json_response("200 OK", r#"{"mode":"global","tun":{"enable":false}}"#),
                json_response("200 OK", r#"{"proxies":{}}"#),
            ],
            vec![
                r#"{"downloadTotal":11,"uploadTotal":7,"connections":[]}"#,
                r#"{"type":"info","payload":"safe log"}"#,
            ],
        )
        .await;
        let transport = LocalMihomoTransport::new(server.config(Some("unix-secret")));

        let runtime = transport.runtime().await.unwrap();
        transport.proxies().await.unwrap();
        let mut connections = transport
            .connection_stream(Duration::from_millis(100))
            .await
            .unwrap();
        let mut logs = transport.log_stream().await.unwrap();

        assert_eq!(runtime.controller.as_deref(), Some("auto_unix"));
        assert!(matches!(
            connections.next().await.unwrap().unwrap(),
            MihomoEvent::Connection(_)
        ));
        assert!(matches!(
            logs.next().await.unwrap().unwrap(),
            MihomoEvent::Log(_)
        ));
        let requests = server.requests();
        assert!(requests[0].starts_with("GET /configs HTTP/1.1\r\n"));
        assert!(requests[1].starts_with("GET /proxies HTTP/1.1\r\n"));
        assert_eq!(
            &requests[2..],
            [
                "WS_GET /connections?interval=100 authorization=Bearer unix-secret",
                "WS_GET /logs authorization=Bearer unix-secret",
            ]
        );
    }

    #[tokio::test]
    async fn unix_websocket_stream_rejects_non_json_messages() {
        let server = FakeUnixController::start(Vec::new(), vec!["not json"]).await;
        let transport = LocalMihomoTransport::new(server.config(None));
        let mut connections = transport
            .connection_stream(Duration::from_millis(250))
            .await
            .unwrap();

        let error = connections.next().await.unwrap().unwrap_err().to_string();

        assert!(error.contains("non-JSON"));
    }
}

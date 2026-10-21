use crate::{
    domain::{HttpObservation, PeerEndpoint, ProxyDecision, ProxyKind},
    error::DiagnosticError,
    ports::WebProbe,
};
use async_trait::async_trait;
use reqwest::{Client, ClientBuilder, Proxy, redirect::Policy};
use std::{
    error::Error as _,
    fmt,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};
use url::Url;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REDIRECTS: usize = 5;
const USER_AGENT: &str = "NetworkPathExplorer/0.1";

#[derive(Debug, PartialEq, Eq)]
enum ClientProxy {
    Disabled,
    Endpoint(String),
    Unknown,
}

#[derive(Debug, Default)]
pub struct ReqwestWebProbe;

#[async_trait]
impl WebProbe for ReqwestWebProbe {
    async fn probe(
        &self,
        url: &Url,
        proxy: &ProxyDecision,
        selected_peer: SocketAddr,
    ) -> Result<HttpObservation, DiagnosticError> {
        let client = client_for(proxy, url, selected_peer)?;
        let started = Instant::now();
        match client.get(url.clone()).send().await {
            Ok(response) => {
                let peer_endpoint = response
                    .remote_addr()
                    .filter(|observed| *observed == selected_peer)
                    .map(PeerEndpoint::from);
                Ok(HttpObservation {
                    // `send` stops at response headers; deliberately drop the response without
                    // reading its body, so the probe retains zero response-body bytes. Transport
                    // buffering is outside this application's body-consumption boundary.
                    status: Some(response.status().as_u16()),
                    final_url: response.url().as_str().into(),
                    elapsed_ms: elapsed_ms(started),
                    error_code: None,
                    peer_endpoint,
                })
            }
            Err(error) => Ok(HttpObservation {
                status: None,
                final_url: error_url(&error, url),
                elapsed_ms: elapsed_ms(started),
                error_code: Some(error_code(&error).into()),
                peer_endpoint: None,
            }),
        }
    }
}

fn client_for(
    proxy: &ProxyDecision,
    url: &Url,
    selected_peer: SocketAddr,
) -> Result<Client, DiagnosticError> {
    client_for_request(
        proxy,
        url,
        selected_peer,
        REQUEST_TIMEOUT,
        USER_AGENT,
        RedirectMode::UrlDiagnostic(url.clone()),
    )
}

pub(crate) enum RedirectMode {
    UrlDiagnostic(Url),
    Disabled,
}

pub(crate) fn client_for_request(
    proxy: &ProxyDecision,
    url: &Url,
    selected_peer: SocketAddr,
    timeout: Duration,
    user_agent: &str,
    redirect_mode: RedirectMode,
) -> Result<Client, DiagnosticError> {
    let redirect = match redirect_mode {
        RedirectMode::UrlDiagnostic(origin) => redirect_policy(origin),
        RedirectMode::Disabled => Policy::none(),
    };
    let builder = Client::builder()
        .timeout(timeout)
        .redirect(redirect)
        .referer(false)
        .user_agent(user_agent);
    let builder = pin_selected_peer(builder, proxy, url, selected_peer)?;
    let builder = match proxy_mode(proxy)? {
        ClientProxy::Disabled => builder.no_proxy(),
        ClientProxy::Endpoint(endpoint) => builder
            .proxy(Proxy::all(endpoint).map_err(|error| DiagnosticError::Http(error.to_string()))?),
        ClientProxy::Unknown => {
            return Err(DiagnosticError::System(
                "selected proxy path cannot be reproduced".into(),
            ));
        }
    };
    builder
        .build()
        .map_err(|error| DiagnosticError::Http(error.to_string()))
}

fn pin_selected_peer(
    builder: ClientBuilder,
    proxy: &ProxyDecision,
    url: &Url,
    selected_peer: SocketAddr,
) -> Result<ClientBuilder, DiagnosticError> {
    let host = match proxy.kind {
        ProxyKind::Direct => url.host_str().ok_or(DiagnosticError::InvalidUrl)?,
        ProxyKind::Http | ProxyKind::Https | ProxyKind::Socks => proxy
            .host
            .as_deref()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| DiagnosticError::System("selected proxy has no host".into()))?,
        ProxyKind::Unknown => return Ok(builder),
    };

    Ok(if host.parse::<IpAddr>().is_ok() {
        builder
    } else {
        builder.resolve(host, selected_peer)
    })
}

fn proxy_mode(decision: &ProxyDecision) -> Result<ClientProxy, DiagnosticError> {
    if decision.kind == ProxyKind::Direct {
        return Ok(ClientProxy::Disabled);
    }
    if decision.kind == ProxyKind::Unknown {
        return Ok(ClientProxy::Unknown);
    }
    let host = decision
        .host
        .as_deref()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| DiagnosticError::System("selected proxy has no host".into()))?;
    let port = decision
        .port
        .filter(|port| *port != 0)
        .ok_or_else(|| DiagnosticError::System("selected proxy has no port".into()))?;
    let host = if host
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_ipv6())
    {
        format!("[{host}]")
    } else {
        host.into()
    };
    let scheme = match decision.kind {
        ProxyKind::Http | ProxyKind::Https => "http",
        ProxyKind::Socks => "socks5h",
        ProxyKind::Direct | ProxyKind::Unknown => {
            unreachable!("only configured proxy kinds reach proxy_for")
        }
    };
    Ok(ClientProxy::Endpoint(format!("{scheme}://{host}:{port}")))
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

fn error_code(error: &reqwest::Error) -> &'static str {
    // Preserve request semantics first, then identify the rustls cause before falling back to
    // generic connection or HTTP failures. This avoids classifying TLS by rendered error text.
    if error.is_timeout() {
        "timeout"
    } else if error.is_redirect() {
        "redirect"
    } else if has_rustls_cause(error) {
        "tls"
    } else if error.is_connect() {
        "connect"
    } else {
        "http"
    }
}

fn has_rustls_cause(error: &reqwest::Error) -> bool {
    let mut cause = error.source();
    while let Some(source) = cause {
        if contains_rustls_error(source) {
            return true;
        }
        cause = source.source();
    }
    false
}

fn contains_rustls_error(source: &(dyn std::error::Error + 'static)) -> bool {
    source.is::<rustls::Error>()
        || source
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
            .is_some_and(|inner| contains_rustls_error(inner))
}

fn redirect_policy(origin: Url) -> Policy {
    Policy::custom(move |attempt| {
        if !same_origin(&origin, attempt.url()) {
            attempt.error(CrossOriginRedirect)
        } else if attempt.previous().len() > MAX_REDIRECTS {
            attempt.error(TooManyRedirects)
        } else {
            attempt.follow()
        }
    })
}

fn same_origin(first: &Url, second: &Url) -> bool {
    first.scheme() == second.scheme()
        && first.host() == second.host()
        && first.port_or_known_default() == second.port_or_known_default()
}

#[derive(Debug)]
struct CrossOriginRedirect;

impl fmt::Display for CrossOriginRedirect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("cross-origin redirect blocked")
    }
}

impl std::error::Error for CrossOriginRedirect {}

#[derive(Debug)]
struct TooManyRedirects;

impl fmt::Display for TooManyRedirects {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("too many redirects")
    }
}

impl std::error::Error for TooManyRedirects {}

fn error_url(error: &reqwest::Error, fallback: &Url) -> String {
    let mut url = error.url().cloned().unwrap_or_else(|| fallback.clone());
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        extract::Path,
        http::{HeaderMap, StatusCode, Uri},
        response::Redirect,
        routing::get,
    };
    use rcgen::generate_simple_self_signed;
    use std::{
        future::pending,
        net::SocketAddr,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
        time::timeout,
    };
    use tokio_rustls::TlsAcceptor;

    fn direct_proxy() -> ProxyDecision {
        ProxyDecision {
            kind: ProxyKind::Direct,
            host: None,
            port: None,
            bypass_reason: None,
            evidence: crate::domain::Evidence {
                level: crate::domain::EvidenceLevel::Confirmed,
                source: "test".into(),
                summary: "direct".into(),
            },
        }
    }

    fn proxy(kind: ProxyKind, host: &str, port: u16) -> ProxyDecision {
        ProxyDecision {
            kind,
            host: Some(host.into()),
            port: Some(port),
            bypass_reason: None,
            evidence: crate::domain::Evidence {
                level: crate::domain::EvidenceLevel::Confirmed,
                source: "test".into(),
                summary: "proxy".into(),
            },
        }
    }

    async fn serve(app: Router) -> (Url, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (Url::parse(&format!("http://{address}/")).unwrap(), task)
    }

    fn endpoint(url: &Url) -> SocketAddr {
        url.socket_addrs(|| None).unwrap()[0]
    }

    async fn stalled_body_server() -> (Url, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n")
                .await
                .unwrap();
            pending::<()>().await;
        });
        (Url::parse(&format!("http://{address}/")).unwrap(), task)
    }

    async fn self_signed_tls_server() -> (Url, JoinHandle<()>) {
        let certificate = generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    certificate.key_pair.serialize_der().into(),
                ),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = TlsAcceptor::from(Arc::new(config))
                .accept(stream)
                .await
                .unwrap();
            let mut request = [0; 1024];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        (Url::parse(&format!("https://{address}/")).unwrap(), task)
    }

    async fn socks5h_server() -> (
        SocketAddr,
        Arc<Mutex<Option<(String, u16)>>>,
        JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requested_target = Arc::new(Mutex::new(None));
        let captured_target = Arc::clone(&requested_target);
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut greeting = [0; 2];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting[0], 5);
            let mut methods = vec![0; usize::from(greeting[1])];
            stream.read_exact(&mut methods).await.unwrap();
            assert!(methods.contains(&0));
            stream.write_all(&[5, 0]).await.unwrap();

            let mut request = [0; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [5, 1, 0, 3]);
            let mut domain_length = [0; 1];
            stream.read_exact(&mut domain_length).await.unwrap();
            let mut domain = vec![0; usize::from(domain_length[0])];
            stream.read_exact(&mut domain).await.unwrap();
            let mut port = [0; 2];
            stream.read_exact(&mut port).await.unwrap();
            *captured_target.lock().unwrap() =
                Some((String::from_utf8(domain).unwrap(), u16::from_be_bytes(port)));

            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            let mut http_request = Vec::new();
            while !http_request.windows(4).any(|window| window == b"\r\n\r\n") {
                let mut chunk = [0; 1024];
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read > 0);
                http_request.extend_from_slice(&chunk[..read]);
            }
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        (address, requested_target, task)
    }

    #[test]
    fn proxy_modes_use_explicit_urls_and_disable_direct_proxying() {
        assert_eq!(proxy_mode(&direct_proxy()).unwrap(), ClientProxy::Disabled);
        assert_eq!(
            proxy_mode(&proxy(ProxyKind::Http, "127.0.0.1", 8080)).unwrap(),
            ClientProxy::Endpoint("http://127.0.0.1:8080".into())
        );
        assert_eq!(
            proxy_mode(&proxy(ProxyKind::Https, "proxy.test", 8443)).unwrap(),
            ClientProxy::Endpoint("http://proxy.test:8443".into())
        );
        assert_eq!(
            proxy_mode(&proxy(ProxyKind::Socks, "::1", 1080)).unwrap(),
            ClientProxy::Endpoint("socks5h://[::1]:1080".into())
        );
    }

    #[tokio::test]
    async fn probe_sends_the_fixed_user_agent_and_returns_the_final_url() {
        let received = Arc::new(Mutex::new(None));
        let captured = Arc::clone(&received);
        let app = Router::new().route(
            "/",
            get(move |headers: HeaderMap| {
                let captured = Arc::clone(&captured);
                async move {
                    *captured.lock().unwrap() = Some(headers);
                    StatusCode::NO_CONTENT
                }
            }),
        );
        let (url, task) = serve(app).await;
        let selected_peer = endpoint(&url);
        let mut aliased_url = url.clone();
        aliased_url.set_host(Some("pinned.invalid")).unwrap();

        let observation = ReqwestWebProbe
            .probe(&aliased_url, &direct_proxy(), selected_peer)
            .await
            .unwrap();

        assert_eq!(observation.status, Some(204));
        assert_eq!(observation.final_url, aliased_url.as_str());
        assert_eq!(
            observation.peer_endpoint,
            Some(PeerEndpoint {
                ip: selected_peer.ip(),
                port: selected_peer.port(),
            })
        );
        assert_eq!(
            received.lock().unwrap().as_ref().unwrap()["user-agent"],
            "NetworkPathExplorer/0.1"
        );
        assert_eq!(
            received.lock().unwrap().as_ref().unwrap()["host"],
            format!("pinned.invalid:{}", selected_peer.port())
        );
        task.abort();
    }

    #[tokio::test]
    async fn configured_http_and_https_proxies_are_pinned_and_recorded_as_the_peer() {
        for kind in [ProxyKind::Http, ProxyKind::Https] {
            let received_uri = Arc::new(Mutex::new(None));
            let captured_uri = Arc::clone(&received_uri);
            let app = Router::new().route(
                "/",
                get(move |uri: Uri| {
                    let captured_uri = Arc::clone(&captured_uri);
                    async move {
                        *captured_uri.lock().unwrap() = Some(uri);
                        StatusCode::NO_CONTENT
                    }
                }),
            );
            let (proxy_url, task) = serve(app).await;
            let selected_peer = endpoint(&proxy_url);
            let decision = proxy(kind, "proxy.invalid", selected_peer.port());
            let target = Url::parse("http://destination.invalid/").unwrap();

            let observation = ReqwestWebProbe
                .probe(&target, &decision, selected_peer)
                .await
                .unwrap();

            assert_eq!(observation.status, Some(204));
            assert_eq!(
                received_uri.lock().unwrap().as_ref().unwrap().to_string(),
                "http://destination.invalid/"
            );
            assert_eq!(
                observation.peer_endpoint,
                Some(PeerEndpoint {
                    ip: selected_peer.ip(),
                    port: selected_peer.port(),
                })
            );
            task.abort();
        }
    }

    #[tokio::test]
    async fn configured_socks5h_proxy_is_pinned_and_receives_the_target_hostname() {
        let (selected_peer, requested_target, task) = socks5h_server().await;
        let decision = proxy(ProxyKind::Socks, "proxy.invalid", selected_peer.port());
        let target = Url::parse("http://destination.invalid:8080/path").unwrap();

        let observation = ReqwestWebProbe
            .probe(&target, &decision, selected_peer)
            .await
            .unwrap();

        assert_eq!(observation.status, Some(204));
        assert_eq!(
            *requested_target.lock().unwrap(),
            Some(("destination.invalid".into(), 8080))
        );
        task.abort();
    }

    #[tokio::test]
    async fn same_origin_redirect_has_no_referer_and_reports_final_url() {
        let received = Arc::new(Mutex::new(None));
        let captured = Arc::clone(&received);
        let app = Router::new()
            .route("/start", get(|| async { Redirect::temporary("/final") }))
            .route(
                "/final",
                get(move |headers: HeaderMap| {
                    let captured = Arc::clone(&captured);
                    async move {
                        *captured.lock().unwrap() = Some(headers);
                        StatusCode::NO_CONTENT
                    }
                }),
            );
        let (url, task) = serve(app).await;
        let selected_peer = endpoint(&url);
        let mut start = url.join("start").unwrap();
        start.set_host(Some("redirect.invalid")).unwrap();

        let observation = ReqwestWebProbe
            .probe(&start, &direct_proxy(), selected_peer)
            .await
            .unwrap();

        assert_eq!(observation.status, Some(204));
        assert_eq!(
            observation.final_url,
            format!("http://redirect.invalid:{}/final", selected_peer.port())
        );
        assert!(
            received
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .get("referer")
                .is_none()
        );
        task.abort();
    }

    #[tokio::test]
    async fn cross_origin_redirect_is_not_requested_and_is_classified_as_redirect() {
        let destination_requests = Arc::new(AtomicUsize::new(0));
        let destination_counter = Arc::clone(&destination_requests);
        let destination = Router::new().route(
            "/",
            get(move || {
                let destination_counter = Arc::clone(&destination_counter);
                async move {
                    destination_counter.fetch_add(1, Ordering::SeqCst);
                    StatusCode::NO_CONTENT
                }
            }),
        );
        let (destination_url, destination_task) = serve(destination).await;
        let sensitive_destination = format!(
            "http://sensitive:secret@{}",
            destination_url.socket_addrs(|| None).unwrap()[0]
        );
        let origin = Router::new().route(
            "/",
            get(move || {
                let sensitive_destination = sensitive_destination.clone();
                async move { Redirect::temporary(&sensitive_destination) }
            }),
        );
        let (origin_url, origin_task) = serve(origin).await;
        let selected_peer = endpoint(&origin_url);

        let observation = ReqwestWebProbe
            .probe(&origin_url, &direct_proxy(), selected_peer)
            .await
            .unwrap();

        assert_eq!(observation.error_code.as_deref(), Some("redirect"));
        assert_eq!(destination_requests.load(Ordering::SeqCst), 0);
        assert_eq!(observation.final_url, origin_url.as_str());
        assert!(!observation.final_url.contains("sensitive:secret"));
        origin_task.abort();
        destination_task.abort();
    }

    #[tokio::test]
    async fn redirect_policy_allows_at_most_five_hops() {
        let requests = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&requests);
        let app = Router::new().route(
            "/hop/{hop}",
            get(move |Path(hop): Path<usize>| {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Redirect::temporary(&format!("/hop/{}", hop + 1))
                }
            }),
        );
        let (url, task) = serve(app).await;
        let start = url.join("hop/0").unwrap();
        let selected_peer = endpoint(&url);

        let observation = ReqwestWebProbe
            .probe(&start, &direct_proxy(), selected_peer)
            .await
            .unwrap();

        assert_eq!(observation.error_code.as_deref(), Some("redirect"));
        assert_eq!(requests.load(Ordering::SeqCst), 6);
        assert_eq!(observation.final_url, url.join("hop/5").unwrap().as_str());
        task.abort();
    }

    #[tokio::test]
    async fn self_signed_tls_server_is_rejected_and_classified_as_tls() {
        let (url, task) = self_signed_tls_server().await;
        let selected_peer = endpoint(&url);

        let observation = ReqwestWebProbe
            .probe(&url, &direct_proxy(), selected_peer)
            .await
            .unwrap();

        assert_eq!(observation.status, None);
        assert_eq!(observation.error_code.as_deref(), Some("tls"));
        task.abort();
    }

    #[tokio::test]
    async fn timeout_error_is_classified_as_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            pending::<()>().await;
        });
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(30))
            .build()
            .unwrap();

        let error = client
            .get(format!("http://{address}/"))
            .send()
            .await
            .unwrap_err();

        assert_eq!(error_code(&error), "timeout");
        assert_eq!(REQUEST_TIMEOUT, Duration::from_secs(10));
        task.abort();
    }

    #[tokio::test]
    async fn probe_returns_after_headers_without_application_body_consumption() {
        let (url, task) = stalled_body_server().await;
        let selected_peer = endpoint(&url);

        let observation = timeout(
            Duration::from_millis(250),
            ReqwestWebProbe.probe(&url, &direct_proxy(), selected_peer),
        )
        .await
        .expect("probe must not wait for the response body")
        .unwrap();

        assert_eq!(observation.status, Some(200));
        task.abort();
    }

    #[test]
    fn same_origin_treats_default_port_aliases_as_equal() {
        assert!(same_origin(
            &Url::parse("http://example.test/start").unwrap(),
            &Url::parse("http://example.test:80/final").unwrap(),
        ));
        assert!(same_origin(
            &Url::parse("https://example.test/start").unwrap(),
            &Url::parse("https://example.test:443/final").unwrap(),
        ));
        assert!(!same_origin(
            &Url::parse("https://example.test/start").unwrap(),
            &Url::parse("https://example.test:444/final").unwrap(),
        ));
    }
}

use crate::error::DiagnosticError;
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};
use url::{Host, Url};

/// A controller endpoint whose locality invariant has already been validated.
///
/// Direct non-loopback construction is intentionally unavailable:
///
/// ```compile_fail,E0599
/// use network_path_agent::traffic::mihomo::{
///     ControllerConfig, LocalMihomoTransport, MihomoEndpoint,
/// };
/// let endpoint = MihomoEndpoint::Loopback("192.168.1.5:9090".parse().unwrap());
/// let config = ControllerConfig::new(endpoint, None);
/// let _ = LocalMihomoTransport::new(config);
/// ```
///
/// Unspecified addresses cannot bypass parsing either:
///
/// ```compile_fail,E0599
/// use network_path_agent::traffic::mihomo::{
///     ControllerConfig, LocalMihomoTransport, MihomoEndpoint,
/// };
/// let endpoint = MihomoEndpoint::Loopback("0.0.0.0:9090".parse().unwrap());
/// let config = ControllerConfig::new(endpoint, None);
/// let _ = LocalMihomoTransport::new(config);
/// ```
///
/// Production callers cannot supply an arbitrary Unix socket:
///
/// ```compile_fail,E0599
/// use network_path_agent::traffic::mihomo::{
///     ControllerConfig, LocalMihomoTransport, MihomoEndpoint,
/// };
/// let endpoint = MihomoEndpoint::Unix("/tmp/untrusted.sock".into());
/// let config = ControllerConfig::new(endpoint, None);
/// let _ = LocalMihomoTransport::new(config);
/// ```
///
/// A validated endpoint cannot be replaced through public config fields:
///
/// ```compile_fail,E0451
/// use network_path_agent::traffic::mihomo::{ControllerConfig, MihomoEndpoint};
/// let endpoint = MihomoEndpoint::parse("http://127.0.0.1:9090").unwrap();
/// let _ = ControllerConfig { endpoint, secret: None };
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MihomoEndpoint {
    kind: MihomoEndpointKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum MihomoEndpointKind {
    Unix(PathBuf),
    Loopback(SocketAddr),
}

impl MihomoEndpoint {
    pub fn parse(input: &str) -> Result<Self, DiagnosticError> {
        let url = Url::parse(input)
            .map_err(|_| DiagnosticError::System("invalid Mihomo controller endpoint".into()))?;
        let raw_authority_and_path = input
            .split_once("://")
            .map(|(_, rest)| rest)
            .ok_or_else(|| DiagnosticError::System("invalid Mihomo controller endpoint".into()))?;
        let authority_end = raw_authority_and_path
            .find(['/', '?', '#'])
            .unwrap_or(raw_authority_and_path.len());
        let raw_authority = &raw_authority_and_path[..authority_end];
        let raw_suffix = &raw_authority_and_path[authority_end..];
        let raw_path_end = raw_suffix.find(['?', '#']).unwrap_or(raw_suffix.len());
        let raw_path = &raw_suffix[..raw_path_end];
        if url.scheme() != "http"
            || raw_authority.contains('@')
            || !url.username().is_empty()
            || url.password().is_some()
            || !matches!(raw_path, "" | "/")
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(DiagnosticError::System(
                "invalid Mihomo controller endpoint".into(),
            ));
        }

        let ip: IpAddr = match url.host() {
            Some(Host::Ipv4(ip)) => ip.into(),
            Some(Host::Ipv6(ip)) => ip.into(),
            _ => {
                return Err(DiagnosticError::System(
                    "Mihomo controller must use a loopback IP".into(),
                ));
            }
        };
        let port = url.port_or_known_default().ok_or_else(|| {
            DiagnosticError::System("Mihomo controller must use a non-zero port".into())
        })?;
        if port == 0 || !ip.is_loopback() {
            return Err(DiagnosticError::System(
                "Mihomo controller must use a loopback IP and non-zero port".into(),
            ));
        }

        Ok(Self {
            kind: MihomoEndpointKind::Loopback(SocketAddr::new(ip, port)),
        })
    }

    pub fn loopback_addr(&self) -> Option<SocketAddr> {
        match self.kind {
            MihomoEndpointKind::Loopback(address) => Some(address),
            MihomoEndpointKind::Unix(_) => None,
        }
    }

    pub(super) fn unix_path(&self) -> Option<&std::path::Path> {
        match &self.kind {
            MihomoEndpointKind::Unix(path) => Some(path),
            MihomoEndpointKind::Loopback(_) => None,
        }
    }

    pub(super) fn controller_label(&self) -> &'static str {
        match self.kind {
            MihomoEndpointKind::Unix(_) => "auto_unix",
            MihomoEndpointKind::Loopback(_) => "manual_loopback",
        }
    }

    pub(super) fn clash_verge_socket_path() -> &'static std::path::Path {
        std::path::Path::new("/tmp/verge/verge-mihomo.sock")
    }

    pub(super) fn clash_verge_unix() -> Self {
        Self {
            kind: MihomoEndpointKind::Unix(Self::clash_verge_socket_path().to_path_buf()),
        }
    }

    #[cfg(test)]
    pub(super) fn test_unix(path: PathBuf) -> Self {
        Self {
            kind: MihomoEndpointKind::Unix(path),
        }
    }
}

#[derive(Clone)]
pub struct ControllerSecret(String);

impl ControllerSecret {
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    pub(super) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ControllerSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ControllerSecret([redacted])")
    }
}

#[derive(Clone, Debug)]
pub struct ControllerConfig {
    endpoint: MihomoEndpoint,
    secret: Option<ControllerSecret>,
}

impl ControllerConfig {
    pub fn new(endpoint: MihomoEndpoint, secret: Option<ControllerSecret>) -> Self {
        Self { endpoint, secret }
    }

    pub fn endpoint(&self) -> &MihomoEndpoint {
        &self.endpoint
    }

    pub fn has_secret(&self) -> bool {
        self.secret.is_some()
    }

    pub(super) fn secret(&self) -> Option<&ControllerSecret> {
        self.secret.as_ref()
    }

    #[cfg(test)]
    pub(super) fn test_unix(path: PathBuf, secret: Option<ControllerSecret>) -> Self {
        Self::new(MihomoEndpoint::test_unix(path), secret)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MihomoProxy {
    pub name: String,
    pub kind: String,
    pub now: Option<String>,
    pub all: Vec<String>,
    pub alive: Option<bool>,
    pub delay_ms: Option<u16>,
    pub provider_name: Option<String>,
    pub dialer_proxy: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MihomoConnectionEvent {
    pub download_total: u64,
    pub upload_total: u64,
    pub connections: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MihomoLogEvent {
    pub r#type: String,
    pub payload: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum MihomoEvent {
    Connection(MihomoConnectionEvent),
    Log(MihomoLogEvent),
}

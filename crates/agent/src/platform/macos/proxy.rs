use crate::{
    domain::{Evidence, EvidenceLevel, ProxyDecision, ProxyKind},
    error::DiagnosticError,
    ports::ProxyInspector,
};
use async_trait::async_trait;
use std::{collections::HashMap, net::IpAddr};
use tokio::process::Command;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MacProxySettings {
    pub http: Option<ProxyEndpoint>,
    pub https: Option<ProxyEndpoint>,
    pub socks: Option<ProxyEndpoint>,
    pub exceptions: Vec<String>,
    pub proxy_auto_config_enabled: bool,
    pub proxy_auto_discovery_enabled: bool,
    pub exclude_simple_hostnames: bool,
}

pub fn parse_scutil_proxy(output: &str) -> Result<MacProxySettings, DiagnosticError> {
    let mut values = HashMap::new();
    let mut exceptions = Vec::new();
    let mut in_exceptions = false;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed == "}" {
            in_exceptions = false;
            continue;
        }
        let Some((key, value)) = trimmed.split_once(" : ") else {
            continue;
        };
        if key == "ExceptionsList" && value == "<array> {" {
            in_exceptions = true;
            continue;
        }
        if in_exceptions {
            exceptions.push(value.to_owned());
        } else {
            values.insert(key.to_owned(), value.to_owned());
        }
    }

    Ok(MacProxySettings {
        http: parse_endpoint("HTTP", &values)?,
        https: parse_endpoint("HTTPS", &values)?,
        socks: parse_endpoint("SOCKS", &values)?,
        exceptions,
        proxy_auto_config_enabled: is_enabled("ProxyAutoConfigEnable", &values),
        proxy_auto_discovery_enabled: is_enabled("ProxyAutoDiscoveryEnable", &values),
        exclude_simple_hostnames: is_enabled("ExcludeSimpleHostnames", &values),
    })
}

pub fn decide_proxy(url: &Url, settings: &MacProxySettings) -> ProxyDecision {
    if settings.proxy_auto_config_enabled || settings.proxy_auto_discovery_enabled {
        return unknown();
    }
    if let Some(reason) = url
        .host_str()
        .and_then(|host| matching_exception(host, &settings.exceptions))
    {
        return direct(Some(format!("匹配系统代理绕过规则 {reason}")));
    }
    if settings.exclude_simple_hostnames && url.host_str().is_some_and(is_simple_hostname) {
        return direct(Some("匹配系统代理绕过规则 ExcludeSimpleHostnames".into()));
    }

    let selected = match url.scheme() {
        "http" => settings
            .http
            .as_ref()
            .map(|endpoint| (ProxyKind::Http, endpoint)),
        "https" => settings
            .https
            .as_ref()
            .map(|endpoint| (ProxyKind::Https, endpoint)),
        _ => None,
    }
    .or_else(|| {
        settings
            .socks
            .as_ref()
            .map(|endpoint| (ProxyKind::Socks, endpoint))
    });

    match selected {
        Some((kind, endpoint)) => ProxyDecision {
            kind: kind.clone(),
            host: Some(endpoint.host.clone()),
            port: Some(endpoint.port),
            bypass_reason: None,
            evidence: Evidence {
                level: EvidenceLevel::Confirmed,
                source: "macos_scutil_proxy".into(),
                summary: format!(
                    "系统为这个网址选择了 {} 代理 {}:{}",
                    proxy_kind_name(kind),
                    endpoint.host,
                    endpoint.port
                ),
            },
        },
        None => direct(None),
    }
}

#[derive(Debug, Default)]
pub struct MacProxyInspector;

#[async_trait]
impl ProxyInspector for MacProxyInspector {
    async fn decision_for(&self, url: &Url) -> Result<ProxyDecision, DiagnosticError> {
        let output = Command::new("/usr/sbin/scutil")
            .arg("--proxy")
            .output()
            .await
            .map_err(|error| DiagnosticError::System(error.to_string()))?;
        if !output.status.success() {
            return Err(DiagnosticError::System(format!(
                "scutil --proxy exited with {}",
                output.status
            )));
        }
        let output = String::from_utf8(output.stdout)
            .map_err(|error| DiagnosticError::System(error.to_string()))?;
        let settings = parse_scutil_proxy(&output)?;
        Ok(decide_proxy(url, &settings))
    }
}

fn parse_endpoint(
    prefix: &str,
    values: &HashMap<String, String>,
) -> Result<Option<ProxyEndpoint>, DiagnosticError> {
    if !is_enabled(&format!("{prefix}Enable"), values) {
        return Ok(None);
    }
    let host = values
        .get(&format!("{prefix}Proxy"))
        .filter(|host| !host.is_empty())
        .ok_or_else(|| {
            DiagnosticError::System(format!("{prefix} proxy is enabled without a host"))
        })?;
    let port = values
        .get(&format!("{prefix}Port"))
        .ok_or_else(|| {
            DiagnosticError::System(format!("{prefix} proxy is enabled without a port"))
        })?
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| DiagnosticError::System(format!("{prefix} proxy has an invalid port")))?;
    Ok(Some(ProxyEndpoint {
        host: host.clone(),
        port,
    }))
}

fn is_enabled(key: &str, values: &HashMap<String, String>) -> bool {
    values.get(key).map(String::as_str) == Some("1")
}

fn matching_exception<'a>(host: &str, exceptions: &'a [String]) -> Option<&'a str> {
    let host = host.trim_matches(['[', ']']);
    exceptions.iter().find_map(|exception| {
        let exception = exception.as_str();
        let matches = if exception == "<local>" {
            is_simple_hostname(host)
        } else if let Some(suffix) = exception.strip_prefix("*.") {
            host.to_ascii_lowercase()
                .ends_with(&format!(".{}", suffix.to_ascii_lowercase()))
        } else if let Ok(host_ip) = host.parse::<IpAddr>() {
            ip_exception_matches(host_ip, exception)
        } else {
            host.eq_ignore_ascii_case(exception)
        };
        matches.then_some(exception)
    })
}

fn ip_exception_matches(host: IpAddr, exception: &str) -> bool {
    if let Ok(exception_ip) = exception.parse::<IpAddr>() {
        return host == exception_ip;
    }
    let Some((network, prefix)) = exception.split_once('/') else {
        return false;
    };
    if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    let Ok(network) = network.parse::<IpAddr>() else {
        return false;
    };
    match (host, network) {
        (IpAddr::V4(host), IpAddr::V4(network)) if prefix <= 32 => {
            prefix_matches(&host.octets(), &network.octets(), prefix)
        }
        (IpAddr::V6(host), IpAddr::V6(network)) if prefix <= 128 => {
            prefix_matches(&host.octets(), &network.octets(), prefix)
        }
        _ => false,
    }
}

fn prefix_matches(host: &[u8], network: &[u8], prefix: u8) -> bool {
    let full_bytes = usize::from(prefix / 8);
    let remaining_bits = prefix % 8;
    host[..full_bytes] == network[..full_bytes]
        && (remaining_bits == 0
            || host[full_bytes] & (u8::MAX << (8 - remaining_bits))
                == network[full_bytes] & (u8::MAX << (8 - remaining_bits)))
}

fn is_simple_hostname(host: &str) -> bool {
    !host.contains('.') && host.parse::<IpAddr>().is_err()
}

fn direct(bypass_reason: Option<String>) -> ProxyDecision {
    ProxyDecision {
        kind: ProxyKind::Direct,
        host: None,
        port: None,
        bypass_reason,
        evidence: Evidence {
            level: EvidenceLevel::Confirmed,
            source: "macos_scutil_proxy".into(),
            summary: "系统代理配置为这个网址选择了直连".into(),
        },
    }
}

fn unknown() -> ProxyDecision {
    ProxyDecision {
        kind: ProxyKind::Unknown,
        host: None,
        port: None,
        bypass_reason: None,
        evidence: Evidence {
            level: EvidenceLevel::Unknown,
            source: "macos_scutil_proxy".into(),
            summary: "系统代理自动配置或自动发现已启用，代理路径未知".into(),
        },
    }
}

fn proxy_kind_name(kind: ProxyKind) -> &'static str {
    match kind {
        ProxyKind::Http => "HTTP",
        ProxyKind::Https => "HTTPS",
        ProxyKind::Socks => "SOCKS",
        ProxyKind::Direct | ProxyKind::Unknown => unreachable!("only proxy kinds are selected"),
    }
}

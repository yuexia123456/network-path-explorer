use crate::{
    domain::{Evidence, EvidenceLevel, ProxyDecision, ProxyKind, RouteInfo},
    error::DiagnosticError,
    ports::{
        ProxyInspector, RequestPathPhase, RequestPathPhaseObserver, RequestPathPlanner, Resolver,
        RouteInspector,
    },
};
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use url::{Host, Url};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedRequestPath {
    pub proxy: ProxyDecision,
    pub resolved_ips: Vec<IpAddr>,
    pub selected_peer: Option<SocketAddr>,
    pub route: Option<RouteInfo>,
    pub dns_evidence: Evidence,
    pub route_evidence: Evidence,
}

#[derive(Clone)]
pub struct SystemRequestPathPlanner<P, D, R> {
    proxy_inspector: P,
    resolver: D,
    route_inspector: R,
}

impl<P, D, R> SystemRequestPathPlanner<P, D, R> {
    pub fn new(proxy_inspector: P, resolver: D, route_inspector: R) -> Self {
        Self {
            proxy_inspector,
            resolver,
            route_inspector,
        }
    }
}

#[async_trait]
impl<P, D, R> RequestPathPlanner for SystemRequestPathPlanner<P, D, R>
where
    P: ProxyInspector,
    D: Resolver,
    R: RouteInspector,
{
    async fn plan(
        &self,
        url: &Url,
        phases: &dyn RequestPathPhaseObserver,
    ) -> Result<SelectedRequestPath, DiagnosticError> {
        phases.begin(RequestPathPhase::Proxy);
        let proxy = self.proxy_inspector.decision_for(url).await?;
        phases.begin(RequestPathPhase::Dns);
        let port = url
            .port_or_known_default()
            .ok_or(DiagnosticError::InvalidUrl)?;
        let target = match resolve_target(&self.resolver, url, port).await {
            Ok(target) => target,
            Err(DiagnosticError::DnsFailed) if is_configured_proxy(&proxy) => {
                TargetResolution::unknown(url.host_str().ok_or(DiagnosticError::InvalidUrl)?)
            }
            Err(error) => return Err(error),
        };

        let selected_peer =
            select_peer(&self.resolver, &proxy, target.ips.first().copied(), port).await?;
        phases.begin(RequestPathPhase::Route);
        let (route, route_evidence) = match selected_peer {
            Some(selected_peer) => match self.route_inspector.route_to(selected_peer.ip()).await {
                Ok(route) => (
                    Some(route.clone()),
                    Evidence {
                        level: EvidenceLevel::Confirmed,
                        source: "route".into(),
                        summary: format!(
                            "系统路由查询显示到 {} 经接口 {}",
                            route.destination, route.interface
                        ),
                    },
                ),
                Err(error) => (
                    None,
                    Evidence {
                        level: EvidenceLevel::Unknown,
                        source: "route".into(),
                        summary: format!("无法读取到 {} 的系统路由：{error}", selected_peer.ip()),
                    },
                ),
            },
            None => (
                None,
                Evidence {
                    level: EvidenceLevel::Unknown,
                    source: "route".into(),
                    summary: "PAC/WPAD 路径无法复现，未执行目标路由查询".into(),
                },
            ),
        };

        Ok(SelectedRequestPath {
            proxy,
            resolved_ips: target.ips,
            selected_peer,
            route,
            dns_evidence: target.evidence,
            route_evidence,
        })
    }
}

async fn resolve_target<D>(
    resolver: &D,
    url: &Url,
    port: u16,
) -> Result<TargetResolution, DiagnosticError>
where
    D: Resolver,
{
    match url.host().ok_or(DiagnosticError::InvalidUrl)? {
        Host::Domain(host) => {
            let ips = resolver.resolve(host, port).await?;
            Ok(TargetResolution {
                evidence: dns_evidence(host, &ips),
                ips,
            })
        }
        Host::Ipv4(ip) => Ok(TargetResolution::literal(IpAddr::V4(ip))),
        Host::Ipv6(ip) => Ok(TargetResolution::literal(IpAddr::V6(ip))),
    }
}

async fn select_peer<D>(
    resolver: &D,
    proxy: &ProxyDecision,
    target_ip: Option<IpAddr>,
    target_port: u16,
) -> Result<Option<SocketAddr>, DiagnosticError>
where
    D: Resolver,
{
    match proxy.kind {
        ProxyKind::Http | ProxyKind::Https | ProxyKind::Socks => {
            let host = proxy
                .host
                .as_deref()
                .filter(|host| !host.is_empty())
                .ok_or_else(|| DiagnosticError::System("selected proxy has no host".into()))?;
            let port = proxy
                .port
                .filter(|port| *port != 0)
                .ok_or_else(|| DiagnosticError::System("selected proxy has no port".into()))?;
            let ip = match host.parse() {
                Ok(ip) => ip,
                Err(_) => first_ip(&resolver.resolve(host, port).await?)?,
            };
            Ok(Some(SocketAddr::new(ip, port)))
        }
        ProxyKind::Direct => Ok(Some(SocketAddr::new(
            target_ip.ok_or(DiagnosticError::DnsFailed)?,
            target_port,
        ))),
        ProxyKind::Unknown => Ok(None),
    }
}

struct TargetResolution {
    ips: Vec<IpAddr>,
    evidence: Evidence,
}

impl TargetResolution {
    fn literal(ip: IpAddr) -> Self {
        Self {
            ips: vec![ip],
            evidence: Evidence {
                level: EvidenceLevel::Confirmed,
                source: "dns".into(),
                summary: format!("目标为 IP 字面量 {ip}，未进行 DNS 解析"),
            },
        }
    }

    fn unknown(host: &str) -> Self {
        Self {
            ips: Vec::new(),
            evidence: Evidence {
                level: EvidenceLevel::Unknown,
                source: "dns".into(),
                summary: format!(
                    "无法在本机解析目标域名 {host}；配置代理后的目标解析与连接无法确认"
                ),
            },
        }
    }
}

fn is_configured_proxy(proxy: &ProxyDecision) -> bool {
    matches!(
        proxy.kind,
        ProxyKind::Http | ProxyKind::Https | ProxyKind::Socks
    )
}

fn first_ip(ips: &[IpAddr]) -> Result<IpAddr, DiagnosticError> {
    ips.first().copied().ok_or(DiagnosticError::DnsFailed)
}

fn dns_evidence(host: &str, ips: &[IpAddr]) -> Evidence {
    Evidence {
        level: EvidenceLevel::Confirmed,
        source: "dns".into(),
        summary: format!(
            "DNS 将 {host} 解析为 {}",
            ips.iter()
                .map(IpAddr::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

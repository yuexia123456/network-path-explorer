use crate::{
    conclusion::build_conclusion,
    domain::{
        DiagnosticStage, Evidence, EvidenceLevel, HttpObservation, ProxyKind, UrlDiagnosticResult,
    },
    error::DiagnosticError,
    network::path::SystemRequestPathPlanner,
    ports::{
        ProgressSink, ProxyInspector, RequestPathPhase, RequestPathPhaseObserver,
        RequestPathPlanner, Resolver, RouteInspector, TrafficDecisionProvider, TrafficProbeScheme,
        TrafficProbeTarget, WebProbe,
    },
    traffic::observation::{TrafficObservationTracker, unknown_traffic_decision},
};
use url::{Host, Url};
use uuid::Uuid;

pub fn normalize_http_url(input: &str) -> Result<Url, DiagnosticError> {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.len() > 2048 {
        return Err(DiagnosticError::InvalidUrl);
    }
    let candidate = if trimmed.contains("://") {
        trimmed.to_owned()
    } else {
        format!("https://{trimmed}")
    };
    let url = Url::parse(&candidate).map_err(|_| DiagnosticError::InvalidUrl)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(DiagnosticError::InvalidUrl);
    }
    Ok(url)
}

pub struct UrlDiagnosticService<Q, W, T> {
    path_planner: Q,
    web_probe: W,
    traffic_observations: TrafficObservationTracker<T>,
}

impl<P, D, R, W, T> UrlDiagnosticService<SystemRequestPathPlanner<P, D, R>, W, T>
where
    P: ProxyInspector,
    D: Resolver,
    R: RouteInspector,
    W: WebProbe,
    T: TrafficDecisionProvider + Clone + 'static,
{
    pub fn new(
        proxy_inspector: P,
        resolver: D,
        route_inspector: R,
        web_probe: W,
        traffic_provider: T,
    ) -> Self {
        Self::from_planner(
            SystemRequestPathPlanner::new(proxy_inspector, resolver, route_inspector),
            web_probe,
            traffic_provider,
        )
    }
}

impl<Q, W, T> UrlDiagnosticService<Q, W, T>
where
    Q: RequestPathPlanner,
    W: WebProbe,
    T: TrafficDecisionProvider + Clone + 'static,
{
    pub fn from_planner(path_planner: Q, web_probe: W, traffic_provider: T) -> Self {
        Self {
            path_planner,
            web_probe,
            traffic_observations: TrafficObservationTracker::new(traffic_provider),
        }
    }

    pub async fn shutdown(&self) {
        self.traffic_observations.shutdown().await;
    }

    pub async fn run(
        &self,
        input: &str,
        progress: &dyn ProgressSink,
    ) -> Result<UrlDiagnosticResult, DiagnosticError> {
        progress.emit(DiagnosticStage::Validating);
        let url = normalize_http_url(input)?;

        let port = url
            .port_or_known_default()
            .ok_or(DiagnosticError::InvalidUrl)?;
        let path = self
            .path_planner
            .plan(&url, &UrlPathProgress(progress))
            .await?;
        let proxy = path.proxy;
        let resolved_ips = path.resolved_ips;
        let dns_evidence = path.dns_evidence;
        let route = path.route;
        let route_evidence = path.route_evidence;
        let selected_peer = path.selected_peer;
        let (route, route_evidence, http, traffic_decision) = if proxy.kind == ProxyKind::Unknown {
            progress.emit(DiagnosticStage::Http);
            (
                None,
                route_evidence,
                unattempted_observation(&url),
                unknown_traffic_decision(),
            )
        } else {
            let selected_peer = selected_peer.ok_or_else(|| {
                DiagnosticError::System("selected request path has no peer".into())
            })?;
            progress.emit(DiagnosticStage::Http);
            let traffic_target = TrafficProbeTarget::new(
                TrafficProbeScheme::try_from(url.scheme())?,
                normalized_target_host(&url)?,
                port,
                resolved_ips.clone(),
                std::process::id(),
            );
            let mut traffic_observation = self.traffic_observations.begin(&traffic_target).await;
            let http = self.web_probe.probe(&url, &proxy, selected_peer).await?;
            let traffic_decision = traffic_observation.finish().await;
            (route, route_evidence, http, traffic_decision)
        };
        let conclusion = build_conclusion(&proxy, &traffic_decision, route.as_ref(), &http);
        let evidence = vec![
            proxy.evidence.clone(),
            dns_evidence,
            route_evidence,
            http_evidence(&http),
        ];

        progress.emit(DiagnosticStage::Completed);
        Ok(UrlDiagnosticResult {
            id: Uuid::new_v4(),
            requested_url: input.into(),
            normalized_url: url.into(),
            resolved_ips,
            proxy,
            route,
            http,
            traffic_decision,
            conclusion,
            evidence,
        })
    }
}

struct UrlPathProgress<'a>(&'a dyn ProgressSink);

impl RequestPathPhaseObserver for UrlPathProgress<'_> {
    fn begin(&self, phase: RequestPathPhase) {
        self.0.emit(match phase {
            RequestPathPhase::Proxy => DiagnosticStage::Proxy,
            RequestPathPhase::Dns => DiagnosticStage::Dns,
            RequestPathPhase::Route => DiagnosticStage::Route,
        });
    }
}

fn normalized_target_host(url: &Url) -> Result<String, DiagnosticError> {
    match url.host().ok_or(DiagnosticError::InvalidUrl)? {
        Host::Domain(host) => Ok(host.to_owned()),
        Host::Ipv4(ip) => Ok(ip.to_string()),
        Host::Ipv6(ip) => Ok(ip.to_string()),
    }
}

fn http_evidence(http: &HttpObservation) -> Evidence {
    let summary = match (http.status, http.error_code.as_deref()) {
        (Some(status), _) => format!(
            "HTTP 连接测试观察到状态 {status}，耗时 {}ms",
            http.elapsed_ms
        ),
        (None, Some(error)) => format!(
            "HTTP 连接测试观察到 {error} 错误，耗时 {}ms",
            http.elapsed_ms
        ),
        (None, None) => format!("HTTP 连接测试未返回状态，耗时 {}ms", http.elapsed_ms),
    };
    Evidence {
        level: if http.error_code.as_deref() == Some("unattempted") {
            EvidenceLevel::Unknown
        } else {
            EvidenceLevel::Confirmed
        },
        source: "http".into(),
        summary,
    }
}

fn unattempted_observation(url: &Url) -> HttpObservation {
    HttpObservation {
        status: None,
        final_url: url.as_str().into(),
        elapsed_ms: 0,
        error_code: Some("unattempted".into()),
        peer_endpoint: None,
    }
}

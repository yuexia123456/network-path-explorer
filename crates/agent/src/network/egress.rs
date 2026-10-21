use crate::{
    domain::{EgressObservation, Evidence, EvidenceLevel, ProxyDecision},
    error::DiagnosticError,
    network::http::{RedirectMode, client_for_request},
    ports::{
        EgressProvider, NoopRequestPathPhaseObserver, RequestPathPlanner, TrafficDecisionProvider,
        TrafficProbeScheme, TrafficProbeTarget,
    },
    traffic::observation::TrafficObservationTracker,
};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use serde::Deserialize;
use std::{
    net::SocketAddr,
    pin::Pin,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use url::Url;

const IPIFY_URL: &str = "https://api64.ipify.org?format=json";
const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(5);
const BODY_LIMIT: usize = 1024;
const USER_AGENT: &str = "NetworkPathExplorer/0.1";

pub type EgressBodyStream = Pin<Box<dyn Stream<Item = Result<Bytes, DiagnosticError>> + Send>>;

pub struct EgressHttpResponse {
    pub status: u16,
    pub body: EgressBodyStream,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressHttpRequest {
    pub url: Url,
    pub proxy: ProxyDecision,
    pub selected_peer: SocketAddr,
    pub user_agent: String,
    pub follow_redirects: bool,
}

#[async_trait]
pub trait EgressHttpClient: Send + Sync {
    async fn execute(
        &self,
        request: EgressHttpRequest,
    ) -> Result<EgressHttpResponse, DiagnosticError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ReqwestEgressHttpClient;

#[async_trait]
impl EgressHttpClient for ReqwestEgressHttpClient {
    async fn execute(
        &self,
        request: EgressHttpRequest,
    ) -> Result<EgressHttpResponse, DiagnosticError> {
        if request.follow_redirects {
            return Err(egress_error());
        }
        let client = client_for_request(
            &request.proxy,
            &request.url,
            request.selected_peer,
            OBSERVATION_TIMEOUT,
            &request.user_agent,
            RedirectMode::Disabled,
        )?;
        let response = client
            .get(request.url)
            .send()
            .await
            .map_err(|_| egress_error())?;
        let status = response.status().as_u16();
        let body = response
            .bytes_stream()
            .map(|chunk| chunk.map_err(|_| egress_error()));
        Ok(EgressHttpResponse {
            status,
            body: Box::pin(body),
        })
    }
}

pub struct IpifyEgressProvider<P, T, H = ReqwestEgressHttpClient> {
    planner: P,
    traffic_observations: TrafficObservationTracker<T>,
    http_client: H,
    observation_admission: Mutex<()>,
    observation_shutdown: CancellationToken,
}

impl<P, T> IpifyEgressProvider<P, T, ReqwestEgressHttpClient>
where
    T: TrafficDecisionProvider + Clone + 'static,
{
    pub fn new(planner: P, traffic_provider: T) -> Self {
        Self::with_http_client(planner, traffic_provider, ReqwestEgressHttpClient)
    }
}

impl<P, T, H> IpifyEgressProvider<P, T, H>
where
    T: TrafficDecisionProvider + Clone + 'static,
{
    pub fn with_http_client(planner: P, traffic_provider: T, http_client: H) -> Self {
        Self {
            planner,
            traffic_observations: TrafficObservationTracker::new(traffic_provider),
            http_client,
            observation_admission: Mutex::new(()),
            observation_shutdown: CancellationToken::new(),
        }
    }

    async fn shutdown_observations(&self) {
        {
            let _admission = self.observation_admission.lock().await;
            self.observation_shutdown.cancel();
        }
        self.traffic_observations.shutdown().await;
    }
}

#[async_trait]
impl<P, T, H> EgressProvider for IpifyEgressProvider<P, T, H>
where
    P: RequestPathPlanner,
    T: TrafficDecisionProvider + Clone + 'static,
    H: EgressHttpClient,
{
    async fn observe(&self) -> Result<EgressObservation, DiagnosticError> {
        {
            let _admission = self.observation_admission.lock().await;
            if self.observation_shutdown.is_cancelled() {
                return Err(egress_error());
            }
        }
        let observation = tokio::select! {
            biased;
            _ = self.observation_shutdown.cancelled() => return Err(egress_error()),
            observation = tokio::time::timeout(OBSERVATION_TIMEOUT, self.observe_inner()) => {
                observation
            }
        };
        match observation {
            Ok(Ok(observation)) => Ok(observation),
            Ok(Err(_)) | Err(_) => Err(egress_error()),
        }
    }

    async fn shutdown(&self) {
        self.shutdown_observations().await;
    }
}

impl<P, T, H> IpifyEgressProvider<P, T, H>
where
    P: RequestPathPlanner,
    T: TrafficDecisionProvider + Clone + 'static,
    H: EgressHttpClient,
{
    async fn observe_inner(&self) -> Result<EgressObservation, DiagnosticError> {
        let started = Instant::now();
        let url = Url::parse(IPIFY_URL).expect("the fixed ipify URL is valid");
        let path = self
            .planner
            .plan(&url, &NoopRequestPathPhaseObserver)
            .await?;
        let selected_peer = path.selected_peer.ok_or_else(egress_error)?;
        let target = TrafficProbeTarget::new(
            TrafficProbeScheme::Https,
            "api64.ipify.org",
            443,
            path.resolved_ips,
            std::process::id(),
        );
        let mut traffic_observation = self.traffic_observations.begin(&target).await;
        let response = self
            .http_client
            .execute(EgressHttpRequest {
                url,
                proxy: path.proxy,
                selected_peer,
                user_agent: USER_AGENT.into(),
                follow_redirects: false,
            })
            .await?;
        if !(200..300).contains(&response.status) {
            return Err(egress_error());
        }
        let ip = parse_ipify_body(response.body).await?;
        let traffic_decision = traffic_observation.finish().await;

        Ok(EgressObservation {
            provider: "ipify".into(),
            ip,
            elapsed_ms: elapsed_ms(started),
            traffic_decision,
            evidence: vec![Evidence {
                level: EvidenceLevel::Confirmed,
                source: "ipify".into(),
                summary: "ipify 返回了这次查询看到的公网出口地址".into(),
            }],
        })
    }
}

impl<P, T, H> Drop for IpifyEgressProvider<P, T, H> {
    fn drop(&mut self) {
        self.observation_shutdown.cancel();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IpifyResponse {
    ip: String,
}

async fn parse_ipify_body(mut body: EgressBodyStream) -> Result<std::net::IpAddr, DiagnosticError> {
    let mut buffer = Vec::new();
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        let new_len = checked_body_len(buffer.len(), chunk.len())?;
        buffer.reserve(new_len - buffer.len());
        buffer.extend_from_slice(&chunk);
    }
    let response: IpifyResponse = serde_json::from_slice(&buffer).map_err(|_| egress_error())?;
    response.ip.parse().map_err(|_| egress_error())
}

fn checked_body_len(current: usize, chunk: usize) -> Result<usize, DiagnosticError> {
    current
        .checked_add(chunk)
        .filter(|size| *size <= BODY_LIMIT)
        .ok_or_else(egress_error)
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

fn egress_error() -> DiagnosticError {
    DiagnosticError::Http("公网出口探测失败".into())
}

#[cfg(test)]
mod tests {
    use super::checked_body_len;

    #[test]
    fn body_limit_arithmetic_rejects_overflow_and_the_first_oversize_chunk() {
        assert_eq!(checked_body_len(1000, 24).unwrap(), 1024);
        assert!(checked_body_len(1000, 25).is_err());
        assert!(checked_body_len(usize::MAX, 1).is_err());
    }
}

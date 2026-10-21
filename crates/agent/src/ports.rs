use crate::{
    domain::{
        DiagnosticStage, EgressObservation, HttpObservation, LocalNetworkOverview, MihomoRuntime,
        ProxyDecision, RouteInfo, RouteTraceResult, TraceHop, TraceTarget, TrafficDecision,
    },
    error::DiagnosticError,
    network::path::SelectedRequestPath,
};
use async_trait::async_trait;
use std::sync::Arc;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use url::Url;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrafficObservationId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficProbeScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficProbeCorrelation {
    /// Match one application process using the process metadata supplied by Mihomo.
    Process,
    /// Match browser-generated traffic by target host/port and observation time only.
    /// Browser speed requests must not inherit the Rust agent PID.
    Browser,
}

impl TryFrom<&str> for TrafficProbeScheme {
    type Error = DiagnosticError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "http" => Ok(Self::Http),
            "https" => Ok(Self::Https),
            _ => Err(DiagnosticError::InvalidUrl),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficProbeTarget {
    pub scheme: TrafficProbeScheme,
    pub host: String,
    pub resolved_ips: Vec<IpAddr>,
    pub port: u16,
    pub protocol: String,
    pub process_id: u32,
    pub correlation: TrafficProbeCorrelation,
}

impl TrafficProbeTarget {
    pub fn new(
        scheme: TrafficProbeScheme,
        host: impl Into<String>,
        port: u16,
        resolved_ips: Vec<IpAddr>,
        process_id: u32,
    ) -> Self {
        Self {
            scheme,
            host: host.into(),
            resolved_ips,
            port,
            protocol: "tcp".into(),
            process_id,
            correlation: TrafficProbeCorrelation::Process,
        }
    }

    pub fn for_browser(
        scheme: TrafficProbeScheme,
        host: impl Into<String>,
        port: u16,
        resolved_ips: Vec<IpAddr>,
    ) -> Self {
        Self {
            scheme,
            host: host.into(),
            resolved_ips,
            port,
            protocol: "tcp".into(),
            process_id: 0,
            correlation: TrafficProbeCorrelation::Browser,
        }
    }
}

#[async_trait]
pub trait TrafficDecisionProvider: Send + Sync {
    async fn runtime(&self) -> MihomoRuntime;
    async fn begin(
        &self,
        target: &TrafficProbeTarget,
    ) -> Result<TrafficObservationId, DiagnosticError>;
    /// Begin an observation whose provider-owned lifetime must cover `lifetime`.
    /// Providers that do not need a custom lifetime retain the legacy `begin` behavior.
    async fn begin_with_lifetime(
        &self,
        target: &TrafficProbeTarget,
        _lifetime: Duration,
    ) -> Result<TrafficObservationId, DiagnosticError> {
        self.begin(target).await
    }
    async fn finish(&self, id: TrafficObservationId) -> Result<TrafficDecision, DiagnosticError>;
    async fn cancel(&self, id: TrafficObservationId);
}

#[async_trait]
pub trait NetworkOverviewProvider: Send + Sync {
    async fn local_overview(&self) -> Result<LocalNetworkOverview, DiagnosticError>;
}

#[async_trait]
pub trait RequestPathPlanner: Send + Sync {
    async fn plan(
        &self,
        url: &Url,
        phases: &dyn RequestPathPhaseObserver,
    ) -> Result<SelectedRequestPath, DiagnosticError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestPathPhase {
    Proxy,
    Dns,
    Route,
}

pub trait RequestPathPhaseObserver: Send + Sync {
    fn begin(&self, phase: RequestPathPhase);
}

#[derive(Debug, Default)]
pub struct NoopRequestPathPhaseObserver;

impl RequestPathPhaseObserver for NoopRequestPathPhaseObserver {
    fn begin(&self, _phase: RequestPathPhase) {}
}

#[async_trait]
impl<T> RequestPathPlanner for Arc<T>
where
    T: RequestPathPlanner + ?Sized,
{
    async fn plan(
        &self,
        url: &Url,
        phases: &dyn RequestPathPhaseObserver,
    ) -> Result<SelectedRequestPath, DiagnosticError> {
        (**self).plan(url, phases).await
    }
}

#[async_trait]
pub trait EgressProvider: Send + Sync {
    async fn observe(&self) -> Result<EgressObservation, DiagnosticError>;

    async fn shutdown(&self) {}
}

#[async_trait]
impl<T> EgressProvider for Arc<T>
where
    T: EgressProvider + ?Sized,
{
    async fn observe(&self) -> Result<EgressObservation, DiagnosticError> {
        (**self).observe().await
    }

    async fn shutdown(&self) {
        (**self).shutdown().await;
    }
}

#[async_trait]
impl<T> NetworkOverviewProvider for Arc<T>
where
    T: NetworkOverviewProvider + ?Sized,
{
    async fn local_overview(&self) -> Result<LocalNetworkOverview, DiagnosticError> {
        (**self).local_overview().await
    }
}

#[async_trait]
impl<T> TrafficDecisionProvider for Arc<T>
where
    T: TrafficDecisionProvider + ?Sized,
{
    async fn runtime(&self) -> MihomoRuntime {
        (**self).runtime().await
    }

    async fn begin(
        &self,
        target: &TrafficProbeTarget,
    ) -> Result<TrafficObservationId, DiagnosticError> {
        (**self).begin(target).await
    }

    async fn begin_with_lifetime(
        &self,
        target: &TrafficProbeTarget,
        lifetime: Duration,
    ) -> Result<TrafficObservationId, DiagnosticError> {
        (**self).begin_with_lifetime(target, lifetime).await
    }

    async fn finish(&self, id: TrafficObservationId) -> Result<TrafficDecision, DiagnosticError> {
        (**self).finish(id).await
    }

    async fn cancel(&self, id: TrafficObservationId) {
        (**self).cancel(id).await;
    }
}

#[async_trait]
pub trait ProxyInspector: Send + Sync {
    async fn decision_for(&self, url: &Url) -> Result<ProxyDecision, DiagnosticError>;
}

#[async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, DiagnosticError>;
}

#[async_trait]
pub trait RouteInspector: Send + Sync {
    async fn route_to(&self, destination: IpAddr) -> Result<RouteInfo, DiagnosticError>;
}

#[async_trait]
pub trait WebProbe: Send + Sync {
    async fn probe(
        &self,
        url: &Url,
        proxy: &ProxyDecision,
        selected_peer: SocketAddr,
    ) -> Result<HttpObservation, DiagnosticError>;
}

pub trait ProgressSink: Send + Sync {
    fn emit(&self, stage: DiagnosticStage);
}

pub trait TraceProgressSink: Send + Sync {
    fn emit(&self, hop: TraceHop);
}

#[async_trait]
pub trait RouteTracer: Send + Sync {
    async fn trace(
        &self,
        target: TraceTarget,
        progress: &dyn TraceProgressSink,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<RouteTraceResult, DiagnosticError>;
}

#[async_trait]
impl<T> RouteTracer for Arc<T>
where
    T: RouteTracer + ?Sized,
{
    async fn trace(
        &self,
        target: TraceTarget,
        progress: &dyn TraceProgressSink,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<RouteTraceResult, DiagnosticError> {
        (**self).trace(target, progress, cancel).await
    }
}

use crate::{
    domain::{MihomoRuntime, TrafficDecision},
    error::DiagnosticError,
    ports::{TrafficDecisionProvider, TrafficObservationId, TrafficProbeTarget},
};
use async_trait::async_trait;
use uuid::Uuid;

pub mod mihomo;
pub(crate) mod observation;

#[derive(Clone, Copy)]
pub struct NoopTrafficDecisionProvider;

#[async_trait]
impl TrafficDecisionProvider for NoopTrafficDecisionProvider {
    async fn runtime(&self) -> MihomoRuntime {
        MihomoRuntime {
            available: false,
            mode: None,
            tun_enabled: None,
            controller: Some("unavailable".into()),
        }
    }

    async fn begin(
        &self,
        _target: &TrafficProbeTarget,
    ) -> Result<TrafficObservationId, DiagnosticError> {
        Ok(TrafficObservationId(Uuid::new_v4()))
    }

    async fn finish(&self, _id: TrafficObservationId) -> Result<TrafficDecision, DiagnosticError> {
        Ok(TrafficDecision::unknown(
            "traffic_adapter",
            "traffic decision provider unavailable",
        ))
    }

    async fn cancel(&self, _id: TrafficObservationId) {}
}

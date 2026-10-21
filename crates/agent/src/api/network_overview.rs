use super::{ApiError, AppState};
use crate::{
    domain::{EgressObservation, LocalNetworkOverview},
    ports::TrafficDecisionProvider,
};
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::time::Duration;

#[derive(Serialize)]
pub struct NetworkOverviewResponse {
    pub local: LocalNetworkOverview,
    pub egress: Option<EgressObservation>,
    pub egress_error: Option<&'static str>,
}

pub(super) async fn network_overview(State(state): State<AppState>) -> Response {
    let (Some(local_provider), Some(egress_provider)) = (
        state.network_overview_provider.as_ref(),
        state.egress_provider.as_ref(),
    ) else {
        return ApiError::overview_unavailable().into_response();
    };
    let mut local = match local_provider.local_overview().await {
        Ok(local) => local,
        Err(_) => return ApiError::overview_unavailable().into_response(),
    };
    if let Some(manager) = &state.mihomo_manager {
        local.mihomo = match tokio::time::timeout(
            Duration::from_secs(1),
            TrafficDecisionProvider::runtime(manager.as_ref()),
        )
        .await
        {
            Ok(runtime) => runtime,
            Err(_) => manager.runtime().await,
        };
    }
    let (egress, egress_error) = match egress_provider.observe().await {
        Ok(egress) => (Some(egress), None),
        Err(_) => (None, Some("egress_unavailable")),
    };
    Json(NetworkOverviewResponse {
        local,
        egress,
        egress_error,
    })
    .into_response()
}

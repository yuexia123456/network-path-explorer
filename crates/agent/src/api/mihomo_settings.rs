use super::{ApiError, AppState, read_json_body};
use crate::traffic::mihomo::MihomoEndpoint;
use axum::{
    Json,
    extract::{Request, State},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetMihomoControllerRequest {
    url: String,
    #[serde(default)]
    secret: Option<String>,
}

pub(super) async fn set_mihomo_controller(
    State(state): State<AppState>,
    request: Request,
) -> Response {
    let Some(manager) = &state.mihomo_manager else {
        return ApiError::mihomo_unavailable().into_response();
    };
    let request: SetMihomoControllerRequest = match read_json_body(request).await {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let endpoint = match MihomoEndpoint::parse(&request.url) {
        Ok(endpoint) => endpoint,
        Err(_) => return ApiError::invalid_request().into_response(),
    };
    if manager
        .set_manual_endpoint(endpoint, request.secret)
        .await
        .is_err()
    {
        return ApiError::invalid_request().into_response();
    }
    Json(manager.runtime().await).into_response()
}

pub(super) async fn reset_mihomo_controller(State(state): State<AppState>) -> Response {
    let Some(manager) = &state.mihomo_manager else {
        return ApiError::mihomo_unavailable().into_response();
    };
    manager.reset_auto().await;
    Json(manager.runtime().await).into_response()
}

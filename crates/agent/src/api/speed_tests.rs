use super::{ApiError, AppState, read_json_body};
use crate::speed::{SpeedError, SpeedEvent, SpeedMetrics, SpeedMode, SpeedSample};
use axum::{
    Json,
    extract::{Path, Request, State},
    http::StatusCode,
    response::{
        IntoResponse, Response,
        sse::{Event, Sse},
    },
};
use futures_util::{StreamExt, stream};
use serde::Deserialize;
use std::convert::Infallible;
use tokio::sync::broadcast;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartSpeedRequest {
    mode: SpeedMode,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SamplesRequest {
    batch_id: Uuid,
    samples: Vec<SpeedSample>,
    used_bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteSpeedRequest {
    metrics: SpeedMetrics,
}

pub(super) async fn start(State(state): State<AppState>, request: Request) -> Response {
    let request: StartSpeedRequest = match read_json_body(request).await {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    match state.speed_service.start_test(request.mode).await {
        Ok(session) => state
            .speed_service
            .snapshot(session.id)
            .map(|snapshot| (StatusCode::ACCEPTED, Json(snapshot)).into_response())
            .unwrap_or_else(|| speed_error(SpeedError::NotFound)),
        Err(error) => speed_error(error),
    }
}

pub(super) async fn snapshot(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let Some(id) = parse_id(&id) else {
        return speed_error(SpeedError::NotFound);
    };
    state
        .speed_service
        .snapshot(id)
        .map(|snapshot| Json(snapshot).into_response())
        .unwrap_or_else(|| speed_error(SpeedError::NotFound))
}

pub(super) async fn events(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let Some(id) = parse_id(&id) else {
        return speed_error(SpeedError::NotFound);
    };
    let Some(subscription) = state.speed_service.subscribe(id) else {
        return speed_error(SpeedError::NotFound);
    };
    let last_sequence = subscription.history.last().map(|event| event.sequence);
    let history = stream::iter(subscription.history.into_iter().map(event_response));
    if subscription.terminal {
        return Sse::new(history).into_response();
    }
    let live = stream::unfold(
        (subscription.receiver, last_sequence, false),
        |(mut receiver, last_sequence, terminal)| async move {
            if terminal {
                return None;
            }
            loop {
                match receiver.recv().await {
                    Ok(event) if last_sequence.is_none_or(|last| event.sequence > last) => {
                        let terminal = matches!(event.stage, "completed" | "failed" | "cancelled");
                        return Some((
                            event_response(event.clone()),
                            (receiver, Some(event.sequence), terminal),
                        ));
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        },
    );
    Sse::new(history.chain(live)).into_response()
}

pub(super) async fn samples(
    State(state): State<AppState>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let request: SamplesRequest = match read_json_body(request).await {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let Some(id) = parse_id(&id) else {
        return speed_error(SpeedError::NotFound);
    };
    match state
        .speed_service
        .submit_samples(id, request.batch_id, request.samples, request.used_bytes)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => speed_error(error),
    }
}

pub(super) async fn complete(
    State(state): State<AppState>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let request: CompleteSpeedRequest = match read_json_body(request).await {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let Some(id) = parse_id(&id) else {
        return speed_error(SpeedError::NotFound);
    };
    match state.speed_service.complete_test(id, request.metrics).await {
        Ok(_) => state
            .speed_service
            .snapshot(id)
            .map(|snapshot| Json(snapshot).into_response())
            .unwrap_or_else(|| speed_error(SpeedError::NotFound)),
        Err(error) => speed_error(error),
    }
}

pub(super) async fn cancel(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let Some(id) = parse_id(&id) else {
        return speed_error(SpeedError::NotFound);
    };
    match state.speed_service.cancel_test(id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => speed_error(error),
    }
}

fn parse_id(value: &str) -> Option<Uuid> {
    value.parse().ok()
}

fn event_response(event: SpeedEvent) -> Result<Event, Infallible> {
    Ok(Event::default().event("stage").data(
        serde_json::to_string(&event)
            .unwrap_or_else(|_| r#"{"sequence":0,"stage":"failed"}"#.to_owned()),
    ))
}

fn speed_error(error: SpeedError) -> Response {
    match error {
        SpeedError::TooMany => ApiError::too_many_speed_tests().into_response(),
        SpeedError::ShuttingDown => ApiError::shutting_down().into_response(),
        SpeedError::NotFound => ApiError::speed_test_not_found().into_response(),
        SpeedError::InvalidMode
        | SpeedError::InvalidSamples
        | SpeedError::InvalidMetrics
        | SpeedError::ByteBudgetExceeded => ApiError::speed_invalid_request().into_response(),
        SpeedError::NotReady => ApiError::speed_not_ready().into_response(),
        SpeedError::AlreadyFinished => ApiError::speed_already_finished().into_response(),
        SpeedError::Timeout => ApiError::speed_timeout().into_response(),
        SpeedError::Cancelled => ApiError::speed_cancelled().into_response(),
        SpeedError::ProviderUnavailable => ApiError::speed_unavailable().into_response(),
    }
}

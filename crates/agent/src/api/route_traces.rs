use super::{ApiError, AppState, RunFailure, read_json_body};
use crate::{
    domain::{RouteTraceResult, TraceHop, TraceTarget},
    error::DiagnosticError,
    network::trace::{TraceRequestKind, select_trace_target},
    ports::{RouteTracer, TraceProgressSink},
};
use axum::{
    Json,
    extract::{Path, Request, State},
    http::StatusCode,
    response::{
        IntoResponse, Response,
        sse::{Event, Sse},
    },
};
use futures_util::{FutureExt, StreamExt, stream};
use serde::{Deserialize, Serialize};
use std::{
    cell::Cell,
    collections::HashMap,
    convert::Infallible,
    future::Future,
    panic::AssertUnwindSafe,
    pin::Pin,
    sync::{Arc, OnceLock, RwLock},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    sync::broadcast,
    time::{Instant, sleep_until},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const TRACE_RETENTION: Duration = Duration::from_secs(30 * 60);
const TRACE_EVENT_BUFFER: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl TraceStatus {
    fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceSnapshot {
    pub status: TraceStatus,
    pub result: Option<RouteTraceResult>,
    pub error: Option<RunFailure>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceEvent {
    pub sequence: usize,
    pub stage: &'static str,
    pub hop: Option<TraceHop>,
}

pub(crate) struct TraceSubscription {
    pub history: Vec<TraceEvent>,
    pub receiver: broadcast::Receiver<TraceEvent>,
    pub terminal: bool,
}

struct TraceRecord {
    snapshot: TraceSnapshot,
    terminal_at: Option<Instant>,
    next_sequence: usize,
    events: Vec<TraceEvent>,
    sender: broadcast::Sender<TraceEvent>,
    cancel: CancellationToken,
}

#[derive(Clone)]
pub struct TraceStore {
    traces: Arc<RwLock<HashMap<Uuid, TraceRecord>>>,
    retention: Duration,
}

impl TraceStore {
    pub fn new() -> Self {
        Self::with_retention(TRACE_RETENTION)
    }

    pub fn with_retention(retention: Duration) -> Self {
        Self {
            traces: Arc::new(RwLock::new(HashMap::new())),
            retention,
        }
    }

    pub(crate) fn start(&self, run_id: Uuid) -> Result<CancellationToken, ()> {
        let mut traces = self.traces.write().expect("trace store lock poisoned");
        Self::remove_expired(&mut traces, self.retention);
        if traces.contains_key(&run_id) {
            return Err(());
        }
        let (sender, _) = broadcast::channel(TRACE_EVENT_BUFFER);
        let cancel = CancellationToken::new();
        traces.insert(
            run_id,
            TraceRecord {
                snapshot: TraceSnapshot {
                    status: TraceStatus::Running,
                    result: None,
                    error: None,
                },
                terminal_at: None,
                next_sequence: 0,
                events: Vec::new(),
                sender,
                cancel: cancel.clone(),
            },
        );
        Ok(cancel)
    }

    pub fn snapshot(&self, run_id: Uuid) -> Option<TraceSnapshot> {
        let mut traces = self.traces.write().expect("trace store lock poisoned");
        Self::remove_expired(&mut traces, self.retention);
        traces.get(&run_id).map(|record| record.snapshot.clone())
    }

    pub fn count(&self) -> usize {
        let mut traces = self.traces.write().expect("trace store lock poisoned");
        Self::remove_expired(&mut traces, self.retention);
        traces.len()
    }

    pub(crate) fn contains(&self, run_id: Uuid) -> bool {
        let mut traces = self.traces.write().expect("trace store lock poisoned");
        Self::remove_expired(&mut traces, self.retention);
        traces.contains_key(&run_id)
    }

    pub(crate) fn subscribe(&self, run_id: Uuid) -> Option<TraceSubscription> {
        let mut traces = self.traces.write().expect("trace store lock poisoned");
        Self::remove_expired(&mut traces, self.retention);
        let record = traces.get(&run_id)?;
        Some(TraceSubscription {
            history: record.events.clone(),
            receiver: record.sender.subscribe(),
            terminal: record.snapshot.status.is_terminal(),
        })
    }

    pub(crate) fn emit_stage(&self, run_id: Uuid, stage: TraceStage) {
        let mut traces = self.traces.write().expect("trace store lock poisoned");
        if let Some(record) = traces.get_mut(&run_id)
            && record.snapshot.status == TraceStatus::Running
        {
            Self::publish(record, TraceEvent::stage(stage));
        }
    }

    pub(crate) fn emit_hop(&self, run_id: Uuid, hop: TraceHop) {
        let mut traces = self.traces.write().expect("trace store lock poisoned");
        if let Some(record) = traces.get_mut(&run_id)
            && record.snapshot.status == TraceStatus::Running
        {
            Self::publish(record, TraceEvent::hop(hop));
        }
    }

    pub(crate) fn complete(&self, run_id: Uuid, result: RouteTraceResult) {
        let terminal_at = Instant::now();
        let should_schedule = {
            let mut traces = self.traces.write().expect("trace store lock poisoned");
            let Some(record) = traces.get_mut(&run_id) else {
                return;
            };
            if record.snapshot.status != TraceStatus::Running {
                return;
            }
            record.snapshot.status = TraceStatus::Completed;
            record.snapshot.result = Some(result);
            record.snapshot.error = None;
            record.terminal_at = Some(terminal_at);
            Self::publish(record, TraceEvent::stage(TraceStage::Completed));
            true
        };
        if should_schedule {
            self.schedule_expiry(run_id, terminal_at);
        }
    }

    pub(crate) fn fail(&self, run_id: Uuid) {
        self.finish_with_error(run_id, TraceStatus::Failed, RunFailure::trace_failed());
    }

    pub(crate) fn cancel(&self, run_id: Uuid) {
        let (token, terminal_at) = {
            let terminal_at = Instant::now();
            let mut traces = self.traces.write().expect("trace store lock poisoned");
            let Some(record) = traces.get_mut(&run_id) else {
                return;
            };
            if record.snapshot.status != TraceStatus::Running {
                return;
            }
            record.snapshot.status = TraceStatus::Cancelled;
            record.snapshot.result = None;
            record.snapshot.error = Some(RunFailure::trace_cancelled());
            record.terminal_at = Some(terminal_at);
            let token = record.cancel.clone();
            Self::publish(record, TraceEvent::stage(TraceStage::Cancelled));
            (token, terminal_at)
        };
        token.cancel();
        self.schedule_expiry(run_id, terminal_at);
    }

    pub(crate) fn cancel_running(&self) {
        let mut tokens = Vec::new();
        {
            let ids = {
                let traces = self.traces.read().expect("trace store lock poisoned");
                traces
                    .iter()
                    .filter_map(|(run_id, record)| {
                        (record.snapshot.status == TraceStatus::Running).then_some(*run_id)
                    })
                    .collect::<Vec<_>>()
            };
            for run_id in ids {
                self.cancel(run_id);
            }
            let traces = self.traces.read().expect("trace store lock poisoned");
            tokens.extend(
                traces
                    .values()
                    .filter(|record| record.snapshot.status == TraceStatus::Cancelled)
                    .map(|record| record.cancel.clone()),
            );
        }
        for token in tokens {
            token.cancel();
        }
    }

    fn finish_with_error(&self, run_id: Uuid, status: TraceStatus, error: RunFailure) {
        let terminal_at = Instant::now();
        let should_schedule = {
            let mut traces = self.traces.write().expect("trace store lock poisoned");
            let Some(record) = traces.get_mut(&run_id) else {
                return;
            };
            if record.snapshot.status != TraceStatus::Running {
                return;
            }
            record.snapshot.status = status;
            record.snapshot.result = None;
            record.snapshot.error = Some(error);
            record.terminal_at = Some(terminal_at);
            let stage = match status {
                TraceStatus::Failed => TraceStage::Failed,
                TraceStatus::Cancelled => TraceStage::Cancelled,
                TraceStatus::Running | TraceStatus::Completed => return,
            };
            Self::publish(record, TraceEvent::stage(stage));
            true
        };
        if should_schedule {
            self.schedule_expiry(run_id, terminal_at);
        }
    }

    fn publish(record: &mut TraceRecord, mut event: TraceEvent) {
        event.sequence = record.next_sequence;
        record.next_sequence = record.next_sequence.saturating_add(1);
        record.events.push(event.clone());
        if record.events.len() > TRACE_EVENT_BUFFER {
            let overflow = record.events.len() - TRACE_EVENT_BUFFER;
            record.events.drain(..overflow);
        }
        let _ = record.sender.send(event);
    }

    fn remove_expired(traces: &mut HashMap<Uuid, TraceRecord>, retention: Duration) {
        let now = Instant::now();
        traces.retain(|_, record| {
            record
                .terminal_at
                .is_none_or(|terminal_at| now < terminal_at + retention)
        });
    }

    fn schedule_expiry(&self, run_id: Uuid, terminal_at: Instant) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let store = self.clone();
        let deadline = terminal_at + self.retention;
        runtime.spawn(async move {
            sleep_until(deadline).await;
            let mut traces = store.traces.write().expect("trace store lock poisoned");
            if traces
                .get(&run_id)
                .and_then(|record| record.terminal_at)
                .is_some_and(|completed_at| completed_at == terminal_at)
            {
                traces.remove(&run_id);
            }
        });
    }
}

impl Default for TraceStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum TraceStage {
    SelectingTarget,
    Probing,
    Hop,
    Completed,
    Failed,
    Cancelled,
}

impl TraceStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::SelectingTarget => "selecting_target",
            Self::Probing => "probing",
            Self::Hop => "hop",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

impl TraceEvent {
    fn stage(stage: TraceStage) -> Self {
        Self {
            sequence: 0,
            stage: stage.as_str(),
            hop: None,
        }
    }

    fn hop(hop: TraceHop) -> Self {
        Self {
            sequence: 0,
            stage: TraceStage::Hop.as_str(),
            hop: Some(hop),
        }
    }
}

struct TraceProgress {
    store: TraceStore,
    run_id: Uuid,
}

impl TraceProgressSink for TraceProgress {
    fn emit(&self, hop: TraceHop) {
        self.store.emit_hop(self.run_id, hop);
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartTraceRequest {
    kind: StartTraceKind,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum StartTraceKind {
    Actual,
    Reference,
}

pub(super) async fn start(
    State(state): State<AppState>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let request: StartTraceRequest = match read_json_body(request).await {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let Some(run_id) = id.parse::<Uuid>().ok() else {
        return ApiError::run_not_ready().into_response();
    };
    let _admission = state.trace_job_admission.lock().await;
    if state.trace_job_shutdown.is_cancelled() || state.trace_job_tasks.is_closed() {
        return ApiError::shutting_down().into_response();
    }
    let Some(result) = state.store.completed_result(run_id) else {
        return ApiError::run_not_ready().into_response();
    };
    if state.trace_store.contains(run_id) {
        return ApiError::trace_already_started().into_response();
    }
    let request_kind = match request.kind {
        StartTraceKind::Actual => TraceRequestKind::Actual,
        StartTraceKind::Reference => TraceRequestKind::Reference,
    };
    let Some(target) = select_trace_target(&result, request_kind) else {
        return ApiError::trace_target_unavailable().into_response();
    };
    let permit = match Arc::clone(&state.trace_permits).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return ApiError::too_many_traces().into_response(),
    };
    let cancel = match state.trace_store.start(run_id) {
        Ok(cancel) => cancel,
        Err(()) => return ApiError::trace_already_started().into_response(),
    };
    install_trace_panic_hook();
    let store = state.trace_store.clone();
    let tracer = Arc::clone(&state.route_tracer);
    state.trace_job_tasks.spawn(async move {
        let _permit = permit;
        run_trace(store, tracer, run_id, target, cancel).await;
    });
    (
        StatusCode::ACCEPTED,
        Json(
            state
                .trace_store
                .snapshot(run_id)
                .expect("trace starts with a snapshot"),
        ),
    )
        .into_response()
}

pub(super) async fn snapshot(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let Some(run_id) = id.parse::<Uuid>().ok() else {
        return ApiError::trace_not_found().into_response();
    };
    state
        .trace_store
        .snapshot(run_id)
        .map(|snapshot| Json(snapshot).into_response())
        .unwrap_or_else(|| ApiError::trace_not_found().into_response())
}

pub(super) async fn events(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let Some(run_id) = id.parse::<Uuid>().ok() else {
        return ApiError::trace_not_found().into_response();
    };
    let Some(subscription) = state.trace_store.subscribe(run_id) else {
        return ApiError::trace_not_found().into_response();
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
                        let terminal = event.stage == TraceStage::Completed.as_str()
                            || event.stage == TraceStage::Failed.as_str()
                            || event.stage == TraceStage::Cancelled.as_str();
                        return Some((
                            event_response(event.clone()),
                            (receiver, Some(event.sequence), terminal),
                        ));
                    }
                    Ok(_) => continue,
                    Err(broadcast::error::RecvError::Lagged(_))
                    | Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        },
    );
    Sse::new(history.chain(live)).into_response()
}

pub(super) async fn cancel(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let Some(run_id) = id.parse::<Uuid>().ok() else {
        return ApiError::trace_not_found().into_response();
    };
    if state.trace_store.snapshot(run_id).is_none() {
        return ApiError::trace_not_found().into_response();
    }
    state.trace_store.cancel(run_id);
    StatusCode::NO_CONTENT.into_response()
}

async fn run_trace(
    store: TraceStore,
    tracer: Arc<dyn RouteTracer>,
    run_id: Uuid,
    target: TraceTarget,
    cancel: CancellationToken,
) {
    store.emit_stage(run_id, TraceStage::SelectingTarget);
    store.emit_stage(run_id, TraceStage::Probing);
    let progress = TraceProgress {
        store: store.clone(),
        run_id,
    };
    let result_target = target;
    let trace =
        SensitiveTraceFuture::new(async move { tracer.trace(target, &progress, cancel).await });
    match AssertUnwindSafe(trace).catch_unwind().await {
        Ok(Ok(mut result)) => {
            result.target = result_target;
            store.complete(run_id, result);
        }
        Ok(Err(DiagnosticError::RouteTraceCancelled)) => store.cancel(run_id),
        Ok(Err(_)) | Err(_) => store.fail(run_id),
    }
}

thread_local! {
    static TRACE_PANIC_SCOPE_DEPTH: Cell<usize> = const { Cell::new(0) };
}

static TRACE_PANIC_HOOK: OnceLock<()> = OnceLock::new();

fn install_trace_panic_hook() {
    TRACE_PANIC_HOOK.get_or_init(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let trace_worker = TRACE_PANIC_SCOPE_DEPTH.with(|depth| depth.get() > 0);
            if trace_worker {
                eprintln!("trace worker panicked");
            } else {
                previous(info);
            }
        }));
    });
}

struct TracePanicScope {
    previous_depth: usize,
}

impl TracePanicScope {
    fn enter() -> Self {
        let previous_depth = TRACE_PANIC_SCOPE_DEPTH.with(|depth| {
            let previous = depth.get();
            depth.set(previous.saturating_add(1));
            previous
        });
        Self { previous_depth }
    }
}

impl Drop for TracePanicScope {
    fn drop(&mut self) {
        TRACE_PANIC_SCOPE_DEPTH.with(|depth| depth.set(self.previous_depth));
    }
}

struct SensitiveTraceFuture<F> {
    inner: Pin<Box<F>>,
}

impl<F> SensitiveTraceFuture<F> {
    fn new(inner: F) -> Self {
        Self {
            inner: Box::pin(inner),
        }
    }
}

impl<F> Unpin for SensitiveTraceFuture<F> {}

impl<F: Future> Future for SensitiveTraceFuture<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let _scope = TracePanicScope::enter();
        self.inner.as_mut().poll(context)
    }
}

fn event_response(event: TraceEvent) -> Result<Event, Infallible> {
    Ok(Event::default().event("stage").data(
        serde_json::to_string(&event)
            .unwrap_or_else(|_| r#"{"sequence":0,"stage":"failed"}"#.to_owned()),
    ))
}

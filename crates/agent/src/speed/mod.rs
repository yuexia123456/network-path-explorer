pub use crate::domain::{
    SpeedMeasurement, SpeedMeasurementPlan, SpeedMetrics, SpeedMode, SpeedSample, SpeedSampleKind,
    SpeedTestResult, plan_for,
};

use crate::panic_boundary::{RedactedFuture, install_panic_redaction_hook};
use crate::ports::{
    TrafficDecisionProvider, TrafficObservationId, TrafficProbeScheme, TrafficProbeTarget,
};
use async_trait::async_trait;
use futures_util::FutureExt;
use serde::Serialize;
use std::{
    collections::HashMap,
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex as StdMutex, RwLock},
    time::Duration,
};
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, broadcast, mpsc, oneshot},
    time::{Instant, sleep_until},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use uuid::Uuid;

const MAX_SPEED_TESTS: usize = 10;
const MAX_SPEED_SAMPLES: usize = 64;
const SPEED_RETENTION: Duration = Duration::from_secs(30 * 60);
const SPEED_EVENT_BUFFER: usize = 32;
const SPEED_PROVIDER: &str = "cloudflare";
const SPEED_OBSERVATION_CLEANUP_MARGIN: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpeedError {
    TooMany,
    ShuttingDown,
    NotFound,
    InvalidMode,
    InvalidSamples,
    InvalidMetrics,
    ByteBudgetExceeded,
    NotReady,
    AlreadyFinished,
    Timeout,
    Cancelled,
    ProviderUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpeedStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl SpeedStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    fn is_terminal(self) -> bool {
        !matches!(self, Self::Running)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SpeedFailure {
    pub code: &'static str,
    pub message: &'static str,
}

impl SpeedFailure {
    pub const fn timeout() -> Self {
        Self {
            code: "speed_timeout",
            message: "测速超过时间上限，已停止",
        }
    }

    pub const fn cancelled() -> Self {
        Self {
            code: "speed_cancelled",
            message: "测速已取消",
        }
    }

    pub const fn failed() -> Self {
        Self {
            code: "speed_failed",
            message: "测速未能完成，请稍后重试",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SpeedSession {
    pub id: Uuid,
    pub plan: SpeedMeasurementPlan,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpeedSnapshot {
    pub id: Uuid,
    pub status: SpeedStatus,
    pub mode: SpeedMode,
    pub plan: SpeedMeasurementPlan,
    pub used_bytes: u64,
    pub sample_count: usize,
    pub result: Option<SpeedTestResult>,
    pub error: Option<SpeedFailure>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpeedEvent {
    pub sequence: usize,
    pub stage: &'static str,
    pub used_bytes: u64,
    pub sample_count: usize,
}

pub struct SpeedSubscription {
    pub history: Vec<SpeedEvent>,
    pub receiver: broadcast::Receiver<SpeedEvent>,
    pub terminal: bool,
}

struct SpeedRecordState {
    snapshot: SpeedSnapshot,
    samples: Vec<SpeedSample>,
    accepted_batches: HashMap<Uuid, AcceptedBatch>,
    terminal_claimed: bool,
    completion_requested: bool,
    terminal_at: Option<Instant>,
    next_sequence: usize,
    events: Vec<SpeedEvent>,
    sender: broadcast::Sender<SpeedEvent>,
}

struct AcceptedBatch {
    samples: Vec<SpeedSample>,
    used_bytes: u64,
}

struct SpeedRecord {
    observer: StdMutex<Option<TrafficObservationId>>,
    cancel: CancellationToken,
    commands: mpsc::Sender<SpeedCommand>,
    operation: Mutex<()>,
    state: StdMutex<SpeedRecordState>,
    started_at: Instant,
    #[cfg(test)]
    terminal_publication_gap_hook: StdMutex<Option<TerminalPublicationGapHook>>,
}

enum SpeedCommand {
    Complete {
        metrics: SpeedMetrics,
        responder: oneshot::Sender<Result<SpeedTestResult, SpeedError>>,
    },
    Cancel {
        responder: oneshot::Sender<Result<(), SpeedError>>,
    },
}

#[derive(Clone)]
pub struct SpeedStore {
    records: Arc<RwLock<HashMap<Uuid, Arc<SpeedRecord>>>>,
    retention: Duration,
}

impl SpeedStore {
    pub fn new() -> Self {
        Self::with_retention(SPEED_RETENTION)
    }

    pub fn with_retention(retention: Duration) -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
            retention,
        }
    }

    fn insert(
        &self,
        id: Uuid,
        mode: SpeedMode,
        plan: SpeedMeasurementPlan,
        cancel: CancellationToken,
    ) -> (Arc<SpeedRecord>, mpsc::Receiver<SpeedCommand>) {
        let (sender, _) = broadcast::channel(SPEED_EVENT_BUFFER);
        let (commands, receiver) = mpsc::channel(4);
        let record = Arc::new(SpeedRecord {
            observer: StdMutex::new(None),
            cancel,
            commands,
            operation: Mutex::new(()),
            state: StdMutex::new(SpeedRecordState {
                snapshot: SpeedSnapshot {
                    id,
                    status: SpeedStatus::Running,
                    mode,
                    plan,
                    used_bytes: 0,
                    sample_count: 0,
                    result: None,
                    error: None,
                },
                samples: Vec::new(),
                accepted_batches: HashMap::new(),
                terminal_claimed: false,
                completion_requested: false,
                terminal_at: None,
                next_sequence: 0,
                events: Vec::new(),
                sender,
            }),
            started_at: Instant::now(),
            #[cfg(test)]
            terminal_publication_gap_hook: StdMutex::new(None),
        });
        {
            let mut records = self.records.write().expect("speed store lock poisoned");
            Self::remove_expired(&mut records, self.retention);
            records.insert(id, Arc::clone(&record));
        }
        Self::publish(&record, "started");
        (record, receiver)
    }

    pub fn snapshot(&self, id: Uuid) -> Option<SpeedSnapshot> {
        let record = self.record(id)?;
        Some(
            record
                .state
                .lock()
                .expect("speed record lock poisoned")
                .snapshot
                .clone(),
        )
    }

    pub fn count(&self) -> usize {
        let mut records = self.records.write().expect("speed store lock poisoned");
        Self::remove_expired(&mut records, self.retention);
        records.len()
    }

    fn record(&self, id: Uuid) -> Option<Arc<SpeedRecord>> {
        let mut records = self.records.write().expect("speed store lock poisoned");
        Self::remove_expired(&mut records, self.retention);
        records.get(&id).cloned()
    }

    pub(crate) fn subscribe(&self, id: Uuid) -> Option<SpeedSubscription> {
        let record = self.record(id)?;
        let state = record.state.lock().expect("speed record lock poisoned");
        Some(SpeedSubscription {
            history: state.events.clone(),
            receiver: state.sender.subscribe(),
            terminal: state.snapshot.status.is_terminal(),
        })
    }

    fn running_records(&self) -> Vec<Arc<SpeedRecord>> {
        let mut records = self.records.write().expect("speed store lock poisoned");
        Self::remove_expired(&mut records, self.retention);
        records
            .values()
            .filter(|record| {
                record
                    .state
                    .lock()
                    .expect("speed record lock poisoned")
                    .snapshot
                    .status
                    == SpeedStatus::Running
            })
            .cloned()
            .collect()
    }

    fn publish(record: &Arc<SpeedRecord>, stage: &'static str) {
        let (sender, event) = {
            let mut state = record.state.lock().expect("speed record lock poisoned");
            let event = Self::append_event(&mut state, stage);
            (state.sender.clone(), event)
        };
        let _ = sender.send(event);
    }

    fn append_event(state: &mut SpeedRecordState, stage: &'static str) -> SpeedEvent {
        let event = SpeedEvent {
            sequence: state.next_sequence,
            stage,
            used_bytes: state.snapshot.used_bytes,
            sample_count: state.snapshot.sample_count,
        };
        state.next_sequence = state.next_sequence.saturating_add(1);
        state.events.push(event.clone());
        if state.events.len() > SPEED_EVENT_BUFFER {
            let overflow = state.events.len() - SPEED_EVENT_BUFFER;
            state.events.drain(..overflow);
        }
        event
    }

    fn set_samples(
        record: &Arc<SpeedRecord>,
        batch_id: Uuid,
        samples: Vec<SpeedSample>,
        used_bytes: u64,
    ) {
        {
            let mut state = record.state.lock().expect("speed record lock poisoned");
            state.accepted_batches.insert(
                batch_id,
                AcceptedBatch {
                    samples: samples.clone(),
                    used_bytes,
                },
            );
            state.samples.extend(samples);
            state.snapshot.used_bytes = used_bytes;
            state.snapshot.sample_count = state.samples.len();
        }
        Self::publish(record, "samples");
    }

    fn install_observer(record: &Arc<SpeedRecord>, observer: TrafficObservationId) {
        *record
            .observer
            .lock()
            .expect("speed observer lock poisoned") = Some(observer);
    }

    fn observer(record: &Arc<SpeedRecord>) -> Option<TrafficObservationId> {
        *record
            .observer
            .lock()
            .expect("speed observer lock poisoned")
    }

    fn claim_terminal(record: &Arc<SpeedRecord>) -> bool {
        let mut state = record.state.lock().expect("speed record lock poisoned");
        if state.snapshot.status != SpeedStatus::Running || state.terminal_claimed {
            false
        } else {
            state.terminal_claimed = true;
            true
        }
    }

    fn terminal(
        record: &Arc<SpeedRecord>,
        status: SpeedStatus,
        result: Option<SpeedTestResult>,
        error: Option<SpeedFailure>,
    ) -> Option<Instant> {
        let terminal_at = Instant::now();
        let publication = {
            let mut state = record.state.lock().expect("speed record lock poisoned");
            if state.snapshot.status != SpeedStatus::Running || !state.terminal_claimed {
                None
            } else {
                state.snapshot.status = status;
                state.snapshot.result = result;
                state.snapshot.error = error;
                state.terminal_at = Some(terminal_at);
                #[cfg(test)]
                wait_at_terminal_publication_gap(record);
                let event = Self::append_event(&mut state, status.as_str());
                Some((state.sender.clone(), event))
            }
        };
        if let Some((sender, event)) = publication {
            record.cancel.cancel();
            let _ = sender.send(event);
            Some(terminal_at)
        } else {
            None
        }
    }

    fn remove_expired(records: &mut HashMap<Uuid, Arc<SpeedRecord>>, retention: Duration) {
        let now = Instant::now();
        records.retain(|_, record| {
            record
                .state
                .lock()
                .expect("speed record lock poisoned")
                .terminal_at
                .is_none_or(|terminal_at| now < terminal_at + retention)
        });
    }

    #[cfg(test)]
    fn set_terminal_publication_gap_hook(
        record: &Arc<SpeedRecord>,
        hook: Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
    ) {
        *record
            .terminal_publication_gap_hook
            .lock()
            .expect("terminal publication hook lock poisoned") = hook;
    }
}

impl Default for SpeedStore {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SpeedCoordinator<T>
where
    T: TrafficDecisionProvider + Clone + 'static,
{
    provider: T,
    store: SpeedStore,
    permits: Arc<Semaphore>,
    admission: Mutex<()>,
    shutdown: CancellationToken,
    tasks: TaskTracker,
}

impl<T> SpeedCoordinator<T>
where
    T: TrafficDecisionProvider + Clone + 'static,
{
    pub fn new(provider: T) -> Self {
        Self::with_store(provider, SpeedStore::new())
    }

    pub fn with_retention(provider: T, retention: Duration) -> Self {
        Self::with_store(provider, SpeedStore::with_retention(retention))
    }

    pub fn with_store(provider: T, store: SpeedStore) -> Self {
        Self {
            provider,
            store,
            permits: Arc::new(Semaphore::new(MAX_SPEED_TESTS)),
            admission: Mutex::new(()),
            shutdown: CancellationToken::new(),
            tasks: TaskTracker::new(),
        }
    }

    pub fn store(&self) -> SpeedStore {
        self.store.clone()
    }

    pub fn snapshot(&self, id: Uuid) -> Option<SpeedSnapshot> {
        self.store.snapshot(id)
    }

    pub async fn start(&self, mode: SpeedMode) -> Result<SpeedSession, SpeedError> {
        let plan = plan_for(mode);
        let target = TrafficProbeTarget::for_browser(
            TrafficProbeScheme::Https,
            "speed.cloudflare.com",
            443,
            Vec::new(),
        );
        install_panic_redaction_hook();
        let (start_result, cancel) = {
            let _admission = self.admission.lock().await;
            if self.shutdown.is_cancelled() || self.tasks.is_closed() {
                return Err(SpeedError::ShuttingDown);
            }
            let permit = self
                .permits
                .clone()
                .try_acquire_owned()
                .map_err(|_| SpeedError::TooMany)?;
            let id = Uuid::new_v4();
            let cancel = self.shutdown.child_token();
            let (record, commands) = self.store.insert(id, mode, plan.clone(), cancel.clone());
            let (start_sender, start_receiver) = oneshot::channel();
            let provider = self.provider.clone();
            let store = self.store.clone();
            let worker_plan = plan.clone();
            let worker_target = target.clone();
            let worker_cancel = cancel.clone();
            let job = SpeedJob {
                provider,
                store,
                record,
                commands,
                cancel: worker_cancel,
                plan: worker_plan,
                target: worker_target,
                permit,
                start_sender,
            };
            self.tasks.spawn(async move {
                job.run().await;
            });
            (start_receiver, cancel)
        };
        let mut request = StartRequestGuard::new(cancel);
        let result = start_result
            .await
            .unwrap_or(Err(SpeedError::ProviderUnavailable));
        request.complete();
        result
    }

    pub async fn record_samples(
        &self,
        id: Uuid,
        samples: Vec<SpeedSample>,
    ) -> Result<(), SpeedError> {
        self.record_samples_with_batch(id, Uuid::new_v4(), samples)
            .await
    }

    pub async fn record_samples_with_batch(
        &self,
        id: Uuid,
        batch_id: Uuid,
        samples: Vec<SpeedSample>,
    ) -> Result<(), SpeedError> {
        let record = self.store.record(id).ok_or(SpeedError::NotFound)?;
        let additional = samples
            .iter()
            .fold(0_u64, |total, sample| total.saturating_add(sample.bytes));
        let _operation = record.operation.lock().await;
        {
            let state = record.state.lock().expect("speed record lock poisoned");
            if let Some(receipt) = state.accepted_batches.get(&batch_id) {
                return if receipt.samples == samples {
                    Ok(())
                } else {
                    Err(SpeedError::InvalidSamples)
                };
            }
            if state.accepted_batches.len() >= MAX_SPEED_SAMPLES {
                return Err(SpeedError::InvalidSamples);
            }
            if state.snapshot.status != SpeedStatus::Running
                || state.terminal_claimed
                || state.completion_requested
            {
                return Err(SpeedError::AlreadyFinished);
            }
            let used_bytes = state.snapshot.used_bytes.saturating_add(additional);
            validate_sample_batch(&state, &samples, used_bytes)?;
        }
        let used_bytes = record
            .state
            .lock()
            .expect("speed record lock poisoned")
            .snapshot
            .used_bytes
            .saturating_add(additional);
        SpeedStore::set_samples(&record, batch_id, samples, used_bytes);
        Ok(())
    }

    pub async fn record_samples_with_bytes(
        &self,
        id: Uuid,
        samples: Vec<SpeedSample>,
        used_bytes: u64,
    ) -> Result<(), SpeedError> {
        self.record_samples_with_bytes_and_batch(id, Uuid::new_v4(), samples, used_bytes)
            .await
    }

    pub async fn record_samples_with_bytes_and_batch(
        &self,
        id: Uuid,
        batch_id: Uuid,
        samples: Vec<SpeedSample>,
        used_bytes: u64,
    ) -> Result<(), SpeedError> {
        let record = self.store.record(id).ok_or(SpeedError::NotFound)?;
        self.record_samples_with_record(record, batch_id, samples, used_bytes)
            .await
    }

    async fn record_samples_with_record(
        &self,
        record: Arc<SpeedRecord>,
        batch_id: Uuid,
        samples: Vec<SpeedSample>,
        used_bytes: u64,
    ) -> Result<(), SpeedError> {
        let _operation = record.operation.lock().await;
        {
            let state = record.state.lock().expect("speed record lock poisoned");
            if let Some(receipt) = state.accepted_batches.get(&batch_id) {
                return if receipt.used_bytes == used_bytes && receipt.samples == samples {
                    Ok(())
                } else {
                    Err(SpeedError::InvalidSamples)
                };
            }
            if state.accepted_batches.len() >= MAX_SPEED_SAMPLES {
                return Err(SpeedError::InvalidSamples);
            }
            if state.snapshot.status != SpeedStatus::Running
                || state.terminal_claimed
                || state.completion_requested
            {
                return Err(SpeedError::AlreadyFinished);
            }
            validate_sample_batch(&state, &samples, used_bytes)?;
        }
        SpeedStore::set_samples(&record, batch_id, samples, used_bytes);
        Ok(())
    }

    pub async fn complete(
        &self,
        id: Uuid,
        metrics: SpeedMetrics,
    ) -> Result<SpeedTestResult, SpeedError> {
        let record = self.store.record(id).ok_or(SpeedError::NotFound)?;
        metrics.validate().map_err(|_| SpeedError::InvalidMetrics)?;
        let response = {
            let _operation = record.operation.lock().await;
            let mut state = record.state.lock().expect("speed record lock poisoned");
            if state.snapshot.status != SpeedStatus::Running
                || state.terminal_claimed
                || state.completion_requested
            {
                return Err(SpeedError::AlreadyFinished);
            }
            if !has_required_sample_kinds(&state.samples) {
                return Err(SpeedError::NotReady);
            }
            metrics
                .validate_for_mode(state.snapshot.mode)
                .map_err(|_| SpeedError::InvalidMetrics)?;
            let (responder, response) = oneshot::channel();
            let command = SpeedCommand::Complete { metrics, responder };
            state.completion_requested = true;
            if record.commands.try_send(command).is_err() {
                state.completion_requested = false;
                return Err(SpeedError::AlreadyFinished);
            }
            response
        };
        response.await.unwrap_or(Err(SpeedError::AlreadyFinished))
    }

    pub async fn cancel(&self, id: Uuid) -> Result<(), SpeedError> {
        let record = self.store.record(id).ok_or(SpeedError::NotFound)?;
        let response = {
            let _operation = record.operation.lock().await;
            let state = record.state.lock().expect("speed record lock poisoned");
            if state.snapshot.status != SpeedStatus::Running {
                return Err(SpeedError::AlreadyFinished);
            }
            let (responder, response) = oneshot::channel();
            if record
                .commands
                .try_send(SpeedCommand::Cancel { responder })
                .is_err()
            {
                return Err(SpeedError::AlreadyFinished);
            }
            response
        };
        record.cancel.cancel();
        response.await.unwrap_or(Err(SpeedError::AlreadyFinished))
    }

    pub async fn shutdown(&self) {
        {
            let _admission = self.admission.lock().await;
            self.shutdown.cancel();
            self.tasks.close();
        }
        for record in self.store.running_records() {
            record.cancel.cancel();
        }
        self.tasks.wait().await;
    }

    pub(crate) fn subscribe(&self, id: Uuid) -> Option<SpeedSubscription> {
        self.store.subscribe(id)
    }
}

#[async_trait]
pub trait SpeedTestService: Send + Sync {
    async fn start_test(&self, mode: SpeedMode) -> Result<SpeedSession, SpeedError>;
    fn snapshot(&self, id: Uuid) -> Option<SpeedSnapshot>;
    fn subscribe(&self, id: Uuid) -> Option<SpeedSubscription>;
    async fn submit_samples(
        &self,
        id: Uuid,
        batch_id: Uuid,
        samples: Vec<SpeedSample>,
        used_bytes: u64,
    ) -> Result<(), SpeedError>;
    async fn complete_test(
        &self,
        id: Uuid,
        metrics: SpeedMetrics,
    ) -> Result<SpeedTestResult, SpeedError>;
    async fn cancel_test(&self, id: Uuid) -> Result<(), SpeedError>;
    async fn shutdown(&self);
}

#[async_trait]
impl<T> SpeedTestService for SpeedCoordinator<T>
where
    T: TrafficDecisionProvider + Clone + 'static,
{
    async fn start_test(&self, mode: SpeedMode) -> Result<SpeedSession, SpeedError> {
        self.start(mode).await
    }

    fn snapshot(&self, id: Uuid) -> Option<SpeedSnapshot> {
        self.snapshot(id)
    }

    fn subscribe(&self, id: Uuid) -> Option<SpeedSubscription> {
        self.subscribe(id)
    }

    async fn submit_samples(
        &self,
        id: Uuid,
        batch_id: Uuid,
        samples: Vec<SpeedSample>,
        used_bytes: u64,
    ) -> Result<(), SpeedError> {
        self.record_samples_with_bytes_and_batch(id, batch_id, samples, used_bytes)
            .await
    }

    async fn complete_test(
        &self,
        id: Uuid,
        metrics: SpeedMetrics,
    ) -> Result<SpeedTestResult, SpeedError> {
        self.complete(id, metrics).await
    }

    async fn cancel_test(&self, id: Uuid) -> Result<(), SpeedError> {
        self.cancel(id).await
    }

    async fn shutdown(&self) {
        self.shutdown().await
    }
}

struct StartRequestGuard {
    cancel: CancellationToken,
    active: bool,
}

impl StartRequestGuard {
    fn new(cancel: CancellationToken) -> Self {
        Self {
            cancel,
            active: true,
        }
    }

    fn complete(&mut self) {
        self.active = false;
    }
}

impl Drop for StartRequestGuard {
    fn drop(&mut self) {
        if self.active {
            self.cancel.cancel();
        }
    }
}

struct SpeedJob<T> {
    provider: T,
    store: SpeedStore,
    record: Arc<SpeedRecord>,
    commands: mpsc::Receiver<SpeedCommand>,
    cancel: CancellationToken,
    plan: SpeedMeasurementPlan,
    target: TrafficProbeTarget,
    permit: OwnedSemaphorePermit,
    start_sender: oneshot::Sender<Result<SpeedSession, SpeedError>>,
}

impl<T> SpeedJob<T>
where
    T: TrafficDecisionProvider + Clone + 'static,
{
    async fn run(self) {
        let SpeedJob {
            provider,
            store,
            record,
            mut commands,
            cancel,
            plan,
            target,
            permit: _permit,
            start_sender,
        } = self;
        let observation_lifetime = Duration::from_millis(plan.deadline_ms)
            .saturating_add(SPEED_OBSERVATION_CLEANUP_MARGIN);
        let observer = match safe_begin(&provider, &target, observation_lifetime).await {
            Ok(observer) => observer,
            Err(()) => {
                if cancel.is_cancelled() {
                    let _ = start_sender.send(Err(SpeedError::ShuttingDown));
                    cancel_job(&provider, &store, &record, &mut commands).await;
                    return;
                }
                let _ = SpeedStore::claim_terminal(&record);
                let _ = SpeedStore::terminal(
                    &record,
                    SpeedStatus::Failed,
                    None,
                    Some(SpeedFailure::failed()),
                );
                let _ = start_sender.send(Err(SpeedError::ProviderUnavailable));
                return;
            }
        };
        SpeedStore::install_observer(&record, observer);

        if cancel.is_cancelled() {
            let _ = start_sender.send(Err(SpeedError::ShuttingDown));
            cancel_job(&provider, &store, &record, &mut commands).await;
            return;
        }

        let id = record
            .state
            .lock()
            .expect("speed record lock poisoned")
            .snapshot
            .id;
        let _ = start_sender.send(Ok(SpeedSession {
            id,
            plan: plan.clone(),
        }));

        let deadline = record.started_at + Duration::from_millis(plan.deadline_ms);
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    cancel_job(&provider, &store, &record, &mut commands).await;
                    break;
                }
                _ = sleep_until(deadline) => {
                    fail_job(
                        &provider,
                        &store,
                        &record,
                        SpeedFailure::timeout(),
                        &mut commands,
                    )
                    .await;
                    break;
                }
                command = commands.recv() => {
                    match command {
                        Some(SpeedCommand::Cancel { responder }) => {
                            cancel_job(&provider, &store, &record, &mut commands).await;
                            let _ = responder.send(Ok(()));
                            break;
                        }
                        Some(SpeedCommand::Complete { metrics, responder }) => {
                            if run_completion(
                                &provider,
                                &store,
                                &record,
                                &mut commands,
                                &cancel,
                                metrics,
                                responder,
                            )
                            .await
                            {
                                break;
                            }
                        }
                        None => {
                            cancel_job(&provider, &store, &record, &mut commands).await;
                            break;
                        }
                    }
                }
            }
        }
    }
}

async fn run_completion<T>(
    provider: &T,
    store: &SpeedStore,
    record: &Arc<SpeedRecord>,
    commands: &mut mpsc::Receiver<SpeedCommand>,
    cancel: &CancellationToken,
    metrics: SpeedMetrics,
    responder: oneshot::Sender<Result<SpeedTestResult, SpeedError>>,
) -> bool
where
    T: TrafficDecisionProvider + ?Sized,
{
    let (mode, used_bytes, observer, remaining) = {
        let _operation = record.operation.lock().await;
        let (mode, used_bytes, remaining) = {
            let state = record.state.lock().expect("speed record lock poisoned");
            if state.snapshot.status != SpeedStatus::Running || state.terminal_claimed {
                let _ = responder.send(Err(SpeedError::AlreadyFinished));
                return false;
            }
            if metrics.validate_for_mode(state.snapshot.mode).is_err() {
                drop(state);
                let mut state = record.state.lock().expect("speed record lock poisoned");
                state.completion_requested = false;
                let _ = responder.send(Err(SpeedError::InvalidMetrics));
                return false;
            }
            if !has_required_sample_kinds(&state.samples) {
                drop(state);
                let mut state = record.state.lock().expect("speed record lock poisoned");
                state.completion_requested = false;
                let _ = responder.send(Err(SpeedError::NotReady));
                return false;
            }
            let remaining = state
                .snapshot
                .plan
                .deadline_ms
                .saturating_sub(record.started_at.elapsed().as_millis() as u64);
            (state.snapshot.mode, state.snapshot.used_bytes, remaining)
        };
        if !SpeedStore::claim_terminal(record) {
            let _ = responder.send(Err(SpeedError::AlreadyFinished));
            return false;
        }
        (mode, used_bytes, SpeedStore::observer(record), remaining)
    };

    let Some(observer) = observer else {
        fail_claimed_job(
            provider,
            store,
            record,
            SpeedFailure::failed(),
            &mut *commands,
        )
        .await;
        let _ = responder.send(Err(SpeedError::ProviderUnavailable));
        return true;
    };
    if remaining == 0 {
        fail_claimed_job(provider, store, record, SpeedFailure::timeout(), commands).await;
        let _ = responder.send(Err(SpeedError::Timeout));
        return true;
    }

    let finished = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            cancel_claimed_job(provider, store, record, commands).await;
            let _ = responder.send(Err(SpeedError::AlreadyFinished));
            return true;
        }
        result = tokio::time::timeout(
            Duration::from_millis(remaining),
            AssertUnwindSafe(RedactedFuture::new(provider.finish(observer))).catch_unwind(),
        ) => result,
    };

    match finished {
        Ok(Ok(Ok(decision))) => {
            let result = SpeedTestResult {
                provider: SPEED_PROVIDER.into(),
                mode,
                metrics,
                used_bytes,
                traffic_decision: decision,
            };
            let _ =
                SpeedStore::terminal(record, SpeedStatus::Completed, Some(result.clone()), None);
            drain_commands(commands, SpeedStatus::Completed);
            let _ = responder.send(Ok(result));
            true
        }
        Ok(Ok(Err(_))) | Ok(Err(_)) => {
            fail_claimed_job(provider, store, record, SpeedFailure::failed(), commands).await;
            let _ = responder.send(Err(SpeedError::ProviderUnavailable));
            true
        }
        Err(_) => {
            fail_claimed_job(provider, store, record, SpeedFailure::timeout(), commands).await;
            let _ = responder.send(Err(SpeedError::Timeout));
            true
        }
    }
}

async fn cancel_job<T>(
    provider: &T,
    store: &SpeedStore,
    record: &Arc<SpeedRecord>,
    commands: &mut mpsc::Receiver<SpeedCommand>,
) where
    T: TrafficDecisionProvider + ?Sized,
{
    let _operation = record.operation.lock().await;
    if SpeedStore::claim_terminal(record) {
        cancel_claimed_job(provider, store, record, commands).await;
    } else {
        drain_commands(commands, SpeedStatus::Cancelled);
    }
}

async fn cancel_claimed_job<T>(
    provider: &T,
    _store: &SpeedStore,
    record: &Arc<SpeedRecord>,
    commands: &mut mpsc::Receiver<SpeedCommand>,
) where
    T: TrafficDecisionProvider + ?Sized,
{
    if let Some(observer) = SpeedStore::observer(record) {
        safe_cancel(provider, observer).await;
    }
    let _ = SpeedStore::terminal(
        record,
        SpeedStatus::Cancelled,
        None,
        Some(SpeedFailure::cancelled()),
    );
    drain_commands(commands, SpeedStatus::Cancelled);
}

async fn fail_job<T>(
    provider: &T,
    store: &SpeedStore,
    record: &Arc<SpeedRecord>,
    failure: SpeedFailure,
    commands: &mut mpsc::Receiver<SpeedCommand>,
) where
    T: TrafficDecisionProvider + ?Sized,
{
    let _operation = record.operation.lock().await;
    if SpeedStore::claim_terminal(record) {
        fail_claimed_job(provider, store, record, failure, commands).await;
    } else {
        drain_commands(commands, SpeedStatus::Failed);
    }
}

async fn fail_claimed_job<T>(
    provider: &T,
    _store: &SpeedStore,
    record: &Arc<SpeedRecord>,
    failure: SpeedFailure,
    commands: &mut mpsc::Receiver<SpeedCommand>,
) where
    T: TrafficDecisionProvider + ?Sized,
{
    if let Some(observer) = SpeedStore::observer(record) {
        safe_cancel(provider, observer).await;
    }
    let _ = SpeedStore::terminal(record, SpeedStatus::Failed, None, Some(failure));
    drain_commands(commands, SpeedStatus::Failed);
}

fn drain_commands(commands: &mut mpsc::Receiver<SpeedCommand>, status: SpeedStatus) {
    while let Ok(command) = commands.try_recv() {
        match command {
            SpeedCommand::Complete { responder, .. } => {
                let _ = responder.send(Err(SpeedError::AlreadyFinished));
            }
            SpeedCommand::Cancel { responder } => {
                let result = (status == SpeedStatus::Cancelled)
                    .then_some(())
                    .ok_or(SpeedError::AlreadyFinished);
                let _ = responder.send(result);
            }
        }
    }
}

fn validate_sample_batch(
    state: &SpeedRecordState,
    samples: &[SpeedSample],
    used_bytes: u64,
) -> Result<(), SpeedError> {
    if state.samples.len().saturating_add(samples.len()) > MAX_SPEED_SAMPLES {
        return Err(SpeedError::InvalidSamples);
    }
    if used_bytes > state.snapshot.plan.max_bytes {
        return Err(SpeedError::ByteBudgetExceeded);
    }
    let additional_bytes = samples
        .iter()
        .fold(0_u64, |total, sample| total.saturating_add(sample.bytes));
    if used_bytes < state.snapshot.used_bytes.saturating_add(additional_bytes) {
        return Err(SpeedError::InvalidSamples);
    }

    let mut counts = measurement_counts(&state.snapshot.plan.measurements);
    for sample in &state.samples {
        let key = (sample.kind, sample.bytes);
        let Some(count) = counts.get_mut(&key) else {
            return Err(SpeedError::InvalidSamples);
        };
        *count = count.saturating_sub(1);
    }
    for sample in samples {
        sample
            .validate_shape()
            .map_err(|_| SpeedError::InvalidSamples)?;
        let key = (sample.kind, sample.bytes);
        let Some(count) = counts.get_mut(&key) else {
            return Err(SpeedError::InvalidSamples);
        };
        if *count == 0 {
            return Err(SpeedError::InvalidSamples);
        }
        *count -= 1;
    }
    Ok(())
}

fn measurement_counts(measurements: &[SpeedMeasurement]) -> HashMap<(SpeedSampleKind, u64), u16> {
    let mut counts: HashMap<(SpeedSampleKind, u64), u16> = HashMap::new();
    for measurement in measurements {
        counts
            .entry((measurement.kind, measurement.bytes))
            .and_modify(|count| *count = count.saturating_add(measurement.count))
            .or_insert(measurement.count);
    }
    counts
}

fn has_required_sample_kinds(samples: &[SpeedSample]) -> bool {
    samples
        .iter()
        .any(|sample| sample.kind == SpeedSampleKind::Latency)
        && samples
            .iter()
            .any(|sample| sample.kind == SpeedSampleKind::Download)
        && samples
            .iter()
            .any(|sample| sample.kind == SpeedSampleKind::Upload)
}

async fn safe_begin<T>(
    provider: &T,
    target: &TrafficProbeTarget,
    lifetime: Duration,
) -> Result<TrafficObservationId, ()>
where
    T: TrafficDecisionProvider + ?Sized,
{
    match AssertUnwindSafe(RedactedFuture::new(
        provider.begin_with_lifetime(target, lifetime),
    ))
    .catch_unwind()
    .await
    {
        Ok(Ok(observer)) => Ok(observer),
        Ok(Err(_)) | Err(_) => Err(()),
    }
}

async fn safe_cancel<T>(provider: &T, id: TrafficObservationId)
where
    T: TrafficDecisionProvider + ?Sized,
{
    let _ = AssertUnwindSafe(RedactedFuture::new(provider.cancel(id)))
        .catch_unwind()
        .await;
}

#[cfg(test)]
type TerminalPublicationGapHook = (Arc<std::sync::Barrier>, Arc<std::sync::Barrier>);

#[cfg(test)]
fn wait_at_terminal_publication_gap(record: &Arc<SpeedRecord>) {
    let hook = record
        .terminal_publication_gap_hook
        .lock()
        .expect("terminal publication hook lock poisoned")
        .clone();
    if let Some((entered, release)) = hook {
        entered.wait();
        release.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{domain::MihomoRuntime, error::DiagnosticError};
    use async_trait::async_trait;
    use std::sync::{Arc, Barrier};
    use tokio::sync::Notify;

    #[derive(Clone, Copy)]
    enum LateBeginOutcome {
        Error,
        Panic,
    }

    #[derive(Clone)]
    struct LateBeginProvider {
        started: Arc<Notify>,
        release: Arc<Notify>,
        outcome: LateBeginOutcome,
    }

    #[async_trait]
    impl TrafficDecisionProvider for LateBeginProvider {
        async fn runtime(&self) -> MihomoRuntime {
            MihomoRuntime {
                available: true,
                mode: Some("fixture".into()),
                tun_enabled: Some(false),
                controller: Some("fixture".into()),
            }
        }

        async fn begin(
            &self,
            _target: &TrafficProbeTarget,
        ) -> Result<TrafficObservationId, DiagnosticError> {
            self.started.notify_waiters();
            self.release.notified().await;
            match self.outcome {
                LateBeginOutcome::Error => Err(DiagnosticError::System(
                    "sensitive late begin detail".into(),
                )),
                LateBeginOutcome::Panic => panic!("sensitive late begin panic"),
            }
        }

        async fn finish(
            &self,
            _id: TrafficObservationId,
        ) -> Result<crate::domain::TrafficDecision, DiagnosticError> {
            Ok(crate::domain::TrafficDecision::unknown("fixture", "unused"))
        }

        async fn cancel(&self, _id: TrafficObservationId) {}
    }

    fn only_snapshot(store: &SpeedStore) -> SpeedSnapshot {
        let records = store.records.read().expect("speed records lock poisoned");
        assert_eq!(records.len(), 1);
        records
            .values()
            .next()
            .expect("one speed record")
            .state
            .lock()
            .expect("speed record lock poisoned")
            .snapshot
            .clone()
    }

    struct TerminalPublicationGapHookGuard(Arc<SpeedRecord>);

    impl Drop for TerminalPublicationGapHookGuard {
        fn drop(&mut self) {
            SpeedStore::set_terminal_publication_gap_hook(&self.0, None);
        }
    }

    #[tokio::test]
    async fn late_begin_error_after_shutdown_is_cancelled_not_failed() {
        let provider = LateBeginProvider {
            started: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
            outcome: LateBeginOutcome::Error,
        };
        let started = Arc::clone(&provider.started);
        let release = Arc::clone(&provider.release);
        let coordinator = Arc::new(SpeedCoordinator::new(provider));
        let start = {
            let coordinator = Arc::clone(&coordinator);
            tokio::spawn(async move { coordinator.start(SpeedMode::Quick).await })
        };
        started.notified().await;

        let shutdown = {
            let coordinator = Arc::clone(&coordinator);
            tokio::spawn(async move { coordinator.shutdown().await })
        };
        tokio::task::yield_now().await;
        release.notify_waiters();

        assert_eq!(start.await.unwrap(), Err(SpeedError::ShuttingDown));
        shutdown.await.unwrap();
        assert_eq!(
            only_snapshot(&coordinator.store()).status,
            SpeedStatus::Cancelled
        );
    }

    #[tokio::test]
    async fn late_begin_panic_after_dropped_caller_is_cancelled_not_failed() {
        let provider = LateBeginProvider {
            started: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
            outcome: LateBeginOutcome::Panic,
        };
        let started = Arc::clone(&provider.started);
        let release = Arc::clone(&provider.release);
        let coordinator = Arc::new(SpeedCoordinator::new(provider));
        let start = {
            let coordinator = Arc::clone(&coordinator);
            tokio::spawn(async move { coordinator.start(SpeedMode::Quick).await })
        };
        started.notified().await;
        start.abort();
        let _ = start.await;
        release.notify_waiters();

        coordinator.shutdown().await;
        assert_eq!(
            only_snapshot(&coordinator.store()).status,
            SpeedStatus::Cancelled
        );
    }

    #[test]
    fn terminal_subscription_cannot_observe_the_old_snapshot_history_gap() {
        let store = SpeedStore::new();
        let id = uuid::Uuid::new_v4();
        let (record, _commands) = store.insert(
            id,
            SpeedMode::Quick,
            plan_for(SpeedMode::Quick),
            CancellationToken::new(),
        );
        assert!(SpeedStore::claim_terminal(&record));

        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        SpeedStore::set_terminal_publication_gap_hook(
            &record,
            Some((Arc::clone(&entered), Arc::clone(&release))),
        );
        let _hook_guard = TerminalPublicationGapHookGuard(Arc::clone(&record));

        let terminal_record = Arc::clone(&record);
        let terminal = std::thread::spawn(move || {
            SpeedStore::terminal(&terminal_record, SpeedStatus::Completed, None, None);
        });
        entered.wait();

        let subscriber_store = store.clone();
        let (subscriber_done, subscriber_result) = std::sync::mpsc::channel();
        let subscriber = std::thread::spawn(move || {
            let result = subscriber_store.subscribe(id);
            subscriber_done.send(result).unwrap();
        });
        let subscriber_blocked = subscriber_result
            .recv_timeout(std::time::Duration::from_millis(20))
            .is_err();

        release.wait();
        terminal.join().unwrap();
        subscriber.join().unwrap();
        let subscription = subscriber_result.recv().unwrap().expect("subscription");
        drop(_hook_guard);

        assert!(subscriber_blocked);
        assert!(subscription.terminal);
        assert_eq!(
            subscription
                .history
                .iter()
                .filter(|event| event.stage == "completed")
                .count(),
            1
        );
    }

    #[test]
    fn terminal_publication_barrier_does_not_block_an_unrelated_record() {
        let store = SpeedStore::new();
        let first_id = uuid::Uuid::new_v4();
        let second_id = uuid::Uuid::new_v4();
        let (first, _first_commands) = store.insert(
            first_id,
            SpeedMode::Quick,
            plan_for(SpeedMode::Quick),
            CancellationToken::new(),
        );
        let (second, _second_commands) = store.insert(
            second_id,
            SpeedMode::Quick,
            plan_for(SpeedMode::Quick),
            CancellationToken::new(),
        );
        assert!(SpeedStore::claim_terminal(&first));
        assert!(SpeedStore::claim_terminal(&second));

        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let first_for_hook = Arc::clone(&first);
        SpeedStore::set_terminal_publication_gap_hook(
            &first_for_hook,
            Some((Arc::clone(&entered), Arc::clone(&release))),
        );
        let _hook_guard = TerminalPublicationGapHookGuard(Arc::clone(&first_for_hook));

        let first_thread = std::thread::spawn(move || {
            SpeedStore::terminal(&first, SpeedStatus::Completed, None, None);
        });
        entered.wait();

        let (done, result) = std::sync::mpsc::channel();
        let second_thread = std::thread::spawn(move || {
            SpeedStore::terminal(&second, SpeedStatus::Completed, None, None);
            done.send(()).unwrap();
        });
        let second_completed_while_first_paused = result
            .recv_timeout(std::time::Duration::from_millis(20))
            .is_ok();

        release.wait();
        first_thread.join().unwrap();
        second_thread.join().unwrap();
        drop(_hook_guard);

        assert!(second_completed_while_first_paused);
    }

    #[test]
    fn terminal_publication_race_keeps_terminal_history_atomic() {
        for _ in 0..256 {
            let store = SpeedStore::new();
            let id = uuid::Uuid::new_v4();
            let (record, _commands) = store.insert(
                id,
                SpeedMode::Quick,
                plan_for(SpeedMode::Quick),
                CancellationToken::new(),
            );
            assert!(SpeedStore::claim_terminal(&record));
            let start = Arc::new(Barrier::new(2));
            let terminal_record = Arc::clone(&record);
            let terminal_start = Arc::clone(&start);
            let terminal = std::thread::spawn(move || {
                terminal_start.wait();
                SpeedStore::terminal(&terminal_record, SpeedStatus::Completed, None, None);
            });
            let subscriber_store = store.clone();
            let subscriber_start = Arc::clone(&start);
            let subscriber = std::thread::spawn(move || {
                subscriber_start.wait();
                subscriber_store.subscribe(id).expect("subscription")
            });

            let subscription = subscriber.join().unwrap();
            terminal.join().unwrap();
            if subscription.terminal {
                assert_eq!(
                    subscription
                        .history
                        .iter()
                        .filter(|event| event.stage == "completed")
                        .count(),
                    1
                );
            }
        }
    }
}

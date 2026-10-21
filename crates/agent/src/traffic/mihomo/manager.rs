use super::{
    ControllerConfig, ControllerSecret, LocalMihomoTransport, MihomoEndpoint,
    MihomoTrafficDecisionProvider, MihomoTransport, discover_clash_verge_controller,
};
use crate::{
    domain::{MihomoRuntime, TrafficDecision},
    error::DiagnosticError,
    panic_boundary::{RedactedFuture, install_panic_redaction_hook},
    ports::{TrafficDecisionProvider, TrafficObservationId, TrafficProbeTarget},
    traffic::NoopTrafficDecisionProvider,
};
use async_trait::async_trait;
use futures_util::FutureExt;
use std::{
    collections::HashMap,
    fmt,
    future::Future,
    panic::AssertUnwindSafe,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use uuid::Uuid;

use super::observer::OBSERVATION_DEADLINE;

/// Manual validation is a loopback-only probe and must complete connect, response headers, and
/// the bounded response body within this single deadline.
const MANUAL_PROBE_DEADLINE: Duration = Duration::from_secs(1);

type TransportDiscovery = Arc<dyn Fn() -> Option<Arc<dyn MihomoTransport>> + Send + Sync>;
type ProviderFactory =
    Arc<dyn Fn(Arc<dyn MihomoTransport>) -> Arc<dyn TrafficDecisionProvider> + Send + Sync>;

#[derive(Clone)]
pub struct MihomoControllerManager {
    selection: Arc<RwLock<ControllerSelectionState>>,
    discovery: TransportDiscovery,
    provider_factory: ProviderFactory,
    fallback_provider: Arc<dyn TrafficDecisionProvider>,
    pending_candidates: Arc<Mutex<HashMap<Uuid, PendingCandidate>>>,
    candidate_admission: Arc<Mutex<()>>,
    candidate_shutdown: CancellationToken,
    candidate_tasks: TaskTracker,
    observations: Arc<Mutex<HashMap<TrafficObservationId, RetainedObservation>>>,
    observation_admission: Arc<Mutex<()>>,
    observation_shutdown: CancellationToken,
    observation_tasks: TaskTracker,
    begin_admission: Arc<Mutex<()>>,
    begin_tasks: TaskTracker,
}

impl MihomoControllerManager {
    pub fn new() -> Self {
        let discovery: TransportDiscovery = Arc::new(|| {
            discover_clash_verge_controller()
                .map(LocalMihomoTransport::new)
                .map(Arc::new)
                .map(|transport| transport as Arc<dyn MihomoTransport>)
        });
        let provider_factory: ProviderFactory = Arc::new(|transport| {
            Arc::new(MihomoTrafficDecisionProvider::new(transport))
                as Arc<dyn TrafficDecisionProvider>
        });
        Self::new_with_sources(discovery, provider_factory)
    }

    fn new_with_sources(discovery: TransportDiscovery, provider_factory: ProviderFactory) -> Self {
        let selection = ControllerSelectionState {
            generation: 0,
            selection: ControllerSelection::automatic(&discovery, &provider_factory),
        };
        Self {
            selection: Arc::new(RwLock::new(selection)),
            discovery,
            provider_factory,
            fallback_provider: Arc::new(NoopTrafficDecisionProvider),
            pending_candidates: Arc::new(Mutex::new(HashMap::new())),
            candidate_admission: Arc::new(Mutex::new(())),
            candidate_shutdown: CancellationToken::new(),
            candidate_tasks: TaskTracker::new(),
            observations: Arc::new(Mutex::new(HashMap::new())),
            observation_admission: Arc::new(Mutex::new(())),
            observation_shutdown: CancellationToken::new(),
            observation_tasks: TaskTracker::new(),
            begin_admission: Arc::new(Mutex::new(())),
            begin_tasks: TaskTracker::new(),
        }
    }

    pub async fn set_manual(
        &self,
        url: &str,
        secret: Option<String>,
    ) -> Result<(), DiagnosticError> {
        let endpoint = MihomoEndpoint::parse(url)?;
        self.set_manual_endpoint(endpoint, secret).await
    }

    pub(crate) async fn set_manual_endpoint(
        &self,
        endpoint: MihomoEndpoint,
        secret: Option<String>,
    ) -> Result<(), DiagnosticError> {
        let secret = normalize_secret(secret)?;
        let transport = Arc::new(LocalMihomoTransport::new(ControllerConfig::new(
            endpoint,
            secret.map(ControllerSecret::new),
        )));
        let probe_transport = Arc::clone(&transport);
        self.set_manual_candidate(transport as Arc<dyn MihomoTransport>, async move {
            probe_transport.version().await
        })
        .await
    }

    #[cfg(test)]
    async fn install_manual_transport(&self, transport: Arc<dyn MihomoTransport>) {
        self.set_manual_candidate(transport, async { Ok(()) })
            .await
            .expect("an immediate manual controller probe cannot fail");
    }

    async fn set_manual_candidate<F>(
        &self,
        transport: Arc<dyn MihomoTransport>,
        probe: F,
    ) -> Result<(), DiagnosticError>
    where
        F: Future<Output = Result<(), DiagnosticError>> + Send + 'static,
    {
        let (cancel, task) = {
            let _admission = self.candidate_admission.lock().await;
            if self.candidate_shutdown.is_cancelled() || self.candidate_tasks.is_closed() {
                return Err(candidate_cancelled());
            }
            let generation = self.reserve_selection_generation().await;
            self.cancel_pending_candidates().await;
            let id = Uuid::new_v4();
            let cancel = self.candidate_shutdown.child_token();
            let done = CancellationToken::new();
            self.pending_candidates.lock().await.insert(
                id,
                PendingCandidate {
                    cancel: cancel.clone(),
                    done: done.clone(),
                },
            );
            let task = self.candidate_tasks.spawn(run_manual_candidate(
                ManualCandidateWorker {
                    pending_candidates: Arc::clone(&self.pending_candidates),
                    selection: Arc::clone(&self.selection),
                    provider_factory: Arc::clone(&self.provider_factory),
                    id,
                    generation,
                    transport,
                    cancel: cancel.clone(),
                    done,
                },
                probe,
            ));
            (cancel, task)
        };
        let mut request = CandidateRequestGuard::new(cancel);
        let result = task.await.unwrap_or_else(|_| Err(candidate_cancelled()));
        request.complete();
        result
    }

    async fn cancel_pending_candidates(&self) {
        let candidates = self
            .pending_candidates
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for candidate in &candidates {
            candidate.cancel.cancel();
        }
        for candidate in candidates {
            candidate.done.cancelled().await;
        }
    }

    async fn reserve_selection_generation(&self) -> u64 {
        let mut state = self.selection.write().await;
        state.generation = state.generation.wrapping_add(1);
        state.generation
    }

    pub async fn reset_auto(&self) {
        let _admission = self.candidate_admission.lock().await;
        {
            let mut state = self.selection.write().await;
            state.generation = state.generation.wrapping_add(1);
            state.selection =
                ControllerSelection::automatic(&self.discovery, &self.provider_factory);
        }
        self.cancel_pending_candidates().await;
    }

    pub async fn runtime(&self) -> MihomoRuntime {
        self.selection.read().await.selection.runtime()
    }

    pub async fn transport(&self) -> Option<Arc<dyn MihomoTransport>> {
        self.selection.read().await.selection.transport()
    }

    async fn decision_provider(&self) -> Arc<dyn TrafficDecisionProvider> {
        let mut state = self.selection.write().await;
        if let Some(provider) = state.selection.provider() {
            return provider;
        }
        let Some(transport) = (self.discovery)() else {
            return Arc::clone(&self.fallback_provider);
        };
        let provider = (self.provider_factory)(Arc::clone(&transport));
        state.selection = ControllerSelection::AutoUnix(ControllerProvider {
            transport,
            provider: Arc::clone(&provider),
        });
        provider
    }

    #[cfg(test)]
    async fn retain_observation(
        &self,
        provider: Arc<dyn TrafficDecisionProvider>,
        inner_id: TrafficObservationId,
        started_at: Instant,
    ) -> Option<TrafficObservationId> {
        self.retain_observation_with_lifetime(provider, inner_id, started_at, OBSERVATION_DEADLINE)
            .await
    }

    async fn retain_observation_with_lifetime(
        &self,
        provider: Arc<dyn TrafficDecisionProvider>,
        inner_id: TrafficObservationId,
        started_at: Instant,
        lifetime: Duration,
    ) -> Option<TrafficObservationId> {
        let admission = self.observation_admission.lock().await;
        if self.observation_shutdown.is_cancelled() || self.observation_tasks.is_closed() {
            return None;
        }
        let id = TrafficObservationId(Uuid::new_v4());
        let cancel = self.observation_shutdown.child_token();
        let done = CancellationToken::new();
        let (finish, finish_requests) = mpsc::unbounded_channel();
        self.observations.lock().await.insert(
            id,
            RetainedObservation {
                finish,
                cancel: cancel.clone(),
                done: done.clone(),
            },
        );
        self.observation_tasks
            .spawn(run_retained_observation(RetainedObservationWorker {
                observations: Arc::clone(&self.observations),
                id,
                provider,
                inner_id,
                deadline: started_at + lifetime,
                cancel,
                done,
                finish_requests,
            }));
        drop(admission);
        Some(id)
    }

    pub async fn shutdown(&self) {
        {
            let _admission = self.candidate_admission.lock().await;
            self.candidate_shutdown.cancel();
            self.candidate_tasks.close();
            self.cancel_pending_candidates().await;
        }
        self.candidate_tasks.wait().await;
        let begin_admission = self.begin_admission.lock().await;
        self.observation_shutdown.cancel();
        self.begin_tasks.close();
        drop(begin_admission);
        self.begin_tasks.wait().await;

        let admission = self.observation_admission.lock().await;
        self.observation_tasks.close();
        drop(admission);
        self.observation_tasks.wait().await;
    }
}

#[derive(Clone)]
struct PendingCandidate {
    cancel: CancellationToken,
    done: CancellationToken,
}

struct CandidateRequestGuard {
    cancel: CancellationToken,
    active: bool,
}

struct BeginRequestGuard {
    cancel: CancellationToken,
    active: bool,
}

impl BeginRequestGuard {
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

impl Drop for BeginRequestGuard {
    fn drop(&mut self) {
        if self.active {
            self.cancel.cancel();
        }
    }
}

impl CandidateRequestGuard {
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

impl Drop for CandidateRequestGuard {
    fn drop(&mut self) {
        if self.active {
            self.cancel.cancel();
        }
    }
}

struct ManualCandidateWorker {
    pending_candidates: Arc<Mutex<HashMap<Uuid, PendingCandidate>>>,
    selection: Arc<RwLock<ControllerSelectionState>>,
    provider_factory: ProviderFactory,
    id: Uuid,
    generation: u64,
    transport: Arc<dyn MihomoTransport>,
    cancel: CancellationToken,
    done: CancellationToken,
}

async fn run_manual_candidate<F>(
    worker: ManualCandidateWorker,
    probe: F,
) -> Result<(), DiagnosticError>
where
    F: Future<Output = Result<(), DiagnosticError>> + Send + 'static,
{
    let ManualCandidateWorker {
        pending_candidates,
        selection,
        provider_factory,
        id,
        generation,
        transport,
        cancel,
        done,
    } = worker;
    let mut transport = Some(transport);
    let probe = AssertUnwindSafe(probe).catch_unwind();
    let result = tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(candidate_cancelled()),
        result = tokio::time::timeout(MANUAL_PROBE_DEADLINE, probe) => match result {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(candidate_cancelled()),
            Err(_) => Err(controller_probe_timed_out()),
        },
    };
    let result = match result {
        Ok(()) => {
            let mut state = selection.write().await;
            if state.generation != generation || cancel.is_cancelled() {
                Err(candidate_cancelled())
            } else {
                let selected_transport = transport
                    .take()
                    .expect("a candidate transport is installed at most once");
                let provider = provider_factory(Arc::clone(&selected_transport));
                state.selection = ControllerSelection::Manual(ControllerProvider {
                    transport: selected_transport,
                    provider,
                });
                Ok(())
            }
        }
        Err(error) => Err(error),
    };
    // Cancellation/reset waiters observe `done` only after every uninstalled candidate resource,
    // including the secret-bearing config, has been released.
    drop(transport);
    pending_candidates.lock().await.remove(&id);
    done.cancel();
    result
}

fn candidate_cancelled() -> DiagnosticError {
    DiagnosticError::System("Mihomo controller validation cancelled".into())
}

fn controller_probe_timed_out() -> DiagnosticError {
    DiagnosticError::System("Mihomo controller validation timed out".into())
}

fn normalize_secret(secret: Option<String>) -> Result<Option<String>, DiagnosticError> {
    match secret {
        None => Ok(None),
        Some(secret) if secret.is_empty() => Ok(None),
        Some(secret) if secret.len() <= 1024 => Ok(Some(secret)),
        Some(_) => Err(DiagnosticError::System(
            "invalid Mihomo controller secret".into(),
        )),
    }
}

#[derive(Clone)]
struct RetainedObservation {
    finish: mpsc::UnboundedSender<FinishRequest>,
    cancel: CancellationToken,
    done: CancellationToken,
}

type FinishRequest = oneshot::Sender<Result<TrafficDecision, DiagnosticError>>;

struct RetainedObservationWorker {
    observations: Arc<Mutex<HashMap<TrafficObservationId, RetainedObservation>>>,
    id: TrafficObservationId,
    provider: Arc<dyn TrafficDecisionProvider>,
    inner_id: TrafficObservationId,
    deadline: Instant,
    cancel: CancellationToken,
    done: CancellationToken,
    finish_requests: mpsc::UnboundedReceiver<FinishRequest>,
}

struct BeginObservationWorker {
    manager: MihomoControllerManager,
    provider: Arc<dyn TrafficDecisionProvider>,
    target: TrafficProbeTarget,
    lifetime: Duration,
    started_at: Instant,
    cancel: CancellationToken,
    response: oneshot::Sender<BeginResponse>,
}

struct BeginResponse {
    result: Result<TrafficObservationId, DiagnosticError>,
    acknowledged: Option<oneshot::Sender<()>>,
}

async fn safe_begin_observation(
    provider: &Arc<dyn TrafficDecisionProvider>,
    target: &TrafficProbeTarget,
    lifetime: Duration,
) -> Result<TrafficObservationId, DiagnosticError> {
    install_panic_redaction_hook();
    match AssertUnwindSafe(RedactedFuture::new(
        provider.begin_with_lifetime(target, lifetime),
    ))
    .catch_unwind()
    .await
    {
        Ok(result) => result,
        Err(_) => Err(observation_unavailable()),
    }
}

async fn safe_finish_observation(
    provider: &Arc<dyn TrafficDecisionProvider>,
    id: TrafficObservationId,
) -> Result<TrafficDecision, DiagnosticError> {
    install_panic_redaction_hook();
    match AssertUnwindSafe(RedactedFuture::new(provider.finish(id)))
        .catch_unwind()
        .await
    {
        Ok(Ok(decision)) => Ok(decision),
        Ok(Err(_)) | Err(_) => Err(observation_unavailable()),
    }
}

async fn safe_cancel_observation(
    provider: &Arc<dyn TrafficDecisionProvider>,
    id: TrafficObservationId,
) -> Result<(), DiagnosticError> {
    install_panic_redaction_hook();
    match AssertUnwindSafe(RedactedFuture::new(provider.cancel(id)))
        .catch_unwind()
        .await
    {
        Ok(()) => Ok(()),
        Err(_) => Err(observation_unavailable()),
    }
}

async fn run_begin_observation(worker: BeginObservationWorker) {
    let BeginObservationWorker {
        manager,
        provider,
        target,
        lifetime,
        started_at,
        cancel,
        response,
    } = worker;
    install_panic_redaction_hook();
    let outcome = safe_begin_observation(&provider, &target, lifetime).await;
    let result = if cancel.is_cancelled() || manager.observation_shutdown.is_cancelled() {
        if let Ok(inner_id) = outcome {
            let _ = safe_cancel_observation(&provider, inner_id).await;
        }
        Err(observation_unavailable())
    } else {
        match outcome {
            Ok(inner_id) => {
                if let Some(id) = manager
                    .retain_observation_with_lifetime(
                        Arc::clone(&provider),
                        inner_id,
                        started_at,
                        lifetime,
                    )
                    .await
                {
                    if cancel.is_cancelled() || manager.observation_shutdown.is_cancelled() {
                        manager.cancel(id).await;
                        Err(observation_unavailable())
                    } else {
                        Ok(id)
                    }
                } else {
                    let _ = safe_cancel_observation(&provider, inner_id).await;
                    Err(observation_unavailable())
                }
            }
            Err(error) => Err(error),
        }
    };
    let Ok(id) = result else {
        let _ = response.send(BeginResponse {
            result,
            acknowledged: None,
        });
        return;
    };
    let handoff_admission = manager.begin_admission.lock().await;
    if cancel.is_cancelled() || manager.observation_shutdown.is_cancelled() {
        drop(handoff_admission);
        manager.cancel(id).await;
        return;
    }
    let (acknowledged, acknowledged_receiver) = oneshot::channel();
    if response
        .send(BeginResponse {
            result: Ok(id),
            acknowledged: Some(acknowledged),
        })
        .is_err()
    {
        drop(handoff_admission);
        manager.cancel(id).await;
        return;
    }
    let cancel_after_handoff = tokio::select! {
        biased;
        _ = cancel.cancelled() => true,
        _ = manager.observation_shutdown.cancelled() => true,
        _ = acknowledged_receiver => false,
    };
    drop(handoff_admission);
    if cancel_after_handoff {
        manager.cancel(id).await;
    }
}

#[async_trait]
impl TrafficDecisionProvider for MihomoControllerManager {
    async fn runtime(&self) -> MihomoRuntime {
        self.decision_provider().await.runtime().await
    }

    async fn begin(
        &self,
        target: &TrafficProbeTarget,
    ) -> Result<TrafficObservationId, DiagnosticError> {
        self.begin_with_lifetime(target, OBSERVATION_DEADLINE).await
    }

    async fn begin_with_lifetime(
        &self,
        target: &TrafficProbeTarget,
        lifetime: Duration,
    ) -> Result<TrafficObservationId, DiagnosticError> {
        let (cancel, receiver) = {
            let _admission = self.begin_admission.lock().await;
            if self.observation_shutdown.is_cancelled()
                || self.begin_tasks.is_closed()
                || self.observation_tasks.is_closed()
            {
                return Err(observation_unavailable());
            }
            let provider = self.decision_provider().await;
            let cancel = self.observation_shutdown.child_token();
            let (response, receiver) = oneshot::channel();
            self.begin_tasks
                .spawn(run_begin_observation(BeginObservationWorker {
                    manager: self.clone(),
                    provider,
                    target: target.clone(),
                    lifetime,
                    started_at: Instant::now(),
                    cancel: cancel.clone(),
                    response,
                }));
            (cancel, receiver)
        };
        let mut request = BeginRequestGuard::new(cancel);
        let response = receiver.await.unwrap_or_else(|_| BeginResponse {
            result: Err(observation_unavailable()),
            acknowledged: None,
        });
        let result = response.result;
        request.complete();
        if let Some(acknowledged) = response.acknowledged {
            let _ = acknowledged.send(());
        }
        result
    }

    async fn finish(&self, id: TrafficObservationId) -> Result<TrafficDecision, DiagnosticError> {
        let Some(observation) = self.observations.lock().await.get(&id).cloned() else {
            return Err(observation_unavailable());
        };
        let (result, receiver) = oneshot::channel();
        if observation.finish.send(result).is_err() {
            return Err(observation_unavailable());
        }
        receiver
            .await
            .unwrap_or_else(|_| Err(observation_unavailable()))
    }

    async fn cancel(&self, id: TrafficObservationId) {
        let observation = self.observations.lock().await.get(&id).cloned();
        if let Some(observation) = observation {
            observation.cancel.cancel();
            observation.done.cancelled().await;
        }
    }
}

async fn run_retained_observation(worker: RetainedObservationWorker) {
    install_panic_redaction_hook();
    let RetainedObservationWorker {
        observations,
        id,
        provider,
        inner_id,
        deadline,
        cancel,
        done,
        finish_requests,
    } = worker;
    let mut owner = RetainedObservationOwner {
        observations,
        id,
        provider,
        inner_id,
        deadline,
        cancel,
        done,
        cleaned: false,
        cancel_attempted: false,
    };
    let outcome = AssertUnwindSafe(RedactedFuture::new(run_retained_observation_inner(
        &mut owner,
        finish_requests,
    )))
    .catch_unwind()
    .await;
    let response = match outcome {
        Ok(RetainedObservationOutcome::Finished { response, result }) => {
            owner.cleanup().await;
            Some((response, result))
        }
        Ok(RetainedObservationOutcome::Cancelled) => {
            owner.cleanup().await;
            None
        }
        Err(_) => {
            let _ = owner.cancel_inner().await;
            owner.cleanup().await;
            None
        }
    };
    if let Some((response, result)) = response {
        let _ = response.send(result);
    }
}

enum RetainedObservationOutcome {
    Cancelled,
    Finished {
        response: FinishRequest,
        result: Result<TrafficDecision, DiagnosticError>,
    },
}

struct RetainedObservationOwner {
    observations: Arc<Mutex<HashMap<TrafficObservationId, RetainedObservation>>>,
    id: TrafficObservationId,
    provider: Arc<dyn TrafficDecisionProvider>,
    inner_id: TrafficObservationId,
    deadline: Instant,
    cancel: CancellationToken,
    done: CancellationToken,
    cleaned: bool,
    cancel_attempted: bool,
}

impl Drop for RetainedObservationOwner {
    fn drop(&mut self) {
        self.done.cancel();
    }
}

impl RetainedObservationOwner {
    async fn cancel_inner(&mut self) -> Result<(), DiagnosticError> {
        if self.cancel_attempted {
            return Ok(());
        }
        self.cancel_attempted = true;
        safe_cancel_observation(&self.provider, self.inner_id).await
    }

    async fn cleanup(&mut self) {
        if self.cleaned {
            return;
        }
        self.observations.lock().await.remove(&self.id);
        self.done.cancel();
        self.cleaned = true;
    }
}

async fn run_retained_observation_inner(
    owner: &mut RetainedObservationOwner,
    mut finish_requests: mpsc::UnboundedReceiver<FinishRequest>,
) -> RetainedObservationOutcome {
    enum Terminal {
        Cancel,
        Finish(FinishRequest),
    }

    let terminal = tokio::select! {
        biased;
        _ = owner.cancel.cancelled() => Terminal::Cancel,
        _ = tokio::time::sleep_until(owner.deadline.into()) => Terminal::Cancel,
        request = finish_requests.recv() => match request {
            Some(request) => Terminal::Finish(request),
            None => Terminal::Cancel,
        },
    };

    match terminal {
        Terminal::Cancel => {
            let _ = owner.cancel_inner().await;
            RetainedObservationOutcome::Cancelled
        }
        Terminal::Finish(response) => {
            let result = tokio::select! {
                biased;
                _ = owner.cancel.cancelled() => {
                    let _ = owner.cancel_inner().await;
                    Err(observation_unavailable())
                }
                _ = tokio::time::sleep_until(owner.deadline.into()) => {
                    let _ = owner.cancel_inner().await;
                    Err(observation_unavailable())
                }
                result = safe_finish_observation(&owner.provider, owner.inner_id) => result,
            };
            if result.is_err() {
                let _ = owner.cancel_inner().await;
            }
            RetainedObservationOutcome::Finished { response, result }
        }
    }
}

fn observation_unavailable() -> DiagnosticError {
    DiagnosticError::System("traffic observation unavailable".to_owned())
}

impl Default for MihomoControllerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MihomoControllerManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = self
            .selection
            .try_read()
            .map(|state| state.selection.label())
            .unwrap_or("unavailable");
        formatter
            .debug_struct("MihomoControllerManager")
            .field("controller", &label)
            .finish()
    }
}

struct ControllerProvider {
    transport: Arc<dyn MihomoTransport>,
    provider: Arc<dyn TrafficDecisionProvider>,
}

struct ControllerSelectionState {
    generation: u64,
    selection: ControllerSelection,
}

enum ControllerSelection {
    AutoUnix(ControllerProvider),
    Manual(ControllerProvider),
    Unavailable,
}

impl ControllerSelection {
    fn automatic(discovery: &TransportDiscovery, provider_factory: &ProviderFactory) -> Self {
        discovery()
            .map(|transport| ControllerProvider {
                provider: provider_factory(Arc::clone(&transport)),
                transport,
            })
            .map(Self::AutoUnix)
            .unwrap_or(Self::Unavailable)
    }

    fn label(&self) -> &'static str {
        match self {
            Self::AutoUnix(_) => "auto_unix",
            Self::Manual(_) => "manual_loopback",
            Self::Unavailable => "unavailable",
        }
    }

    fn runtime(&self) -> MihomoRuntime {
        MihomoRuntime {
            available: !matches!(self, Self::Unavailable),
            mode: None,
            tun_enabled: None,
            controller: Some(self.label().into()),
        }
    }

    fn transport(&self) -> Option<Arc<dyn MihomoTransport>> {
        match self {
            Self::AutoUnix(controller) | Self::Manual(controller) => {
                Some(Arc::clone(&controller.transport))
            }
            Self::Unavailable => None,
        }
    }

    fn provider(&self) -> Option<Arc<dyn TrafficDecisionProvider>> {
        match self {
            Self::AutoUnix(controller) | Self::Manual(controller) => {
                Some(Arc::clone(&controller.provider))
            }
            Self::Unavailable => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        diagnostics::url::UrlDiagnosticService,
        domain::{
            DiagnosticStage, Evidence, EvidenceLevel, HttpObservation, ProxyDecision, ProxyKind,
            RouteInfo, SpeedMetrics, SpeedSample, SpeedSampleKind, TrafficDecisionKind,
            TrafficNodeKind,
        },
        ports::{
            ProgressSink, ProxyInspector, Resolver, RouteInspector, TrafficDecisionProvider,
            TrafficProbeScheme, TrafficProbeTarget, WebProbe,
        },
        speed::{SpeedCoordinator, SpeedError, SpeedMode, SpeedStatus},
        traffic::mihomo::{MihomoConnectionEvent, MihomoEvent, MihomoEventStream, MihomoProxy},
    };
    use async_trait::async_trait;
    use futures_util::{Stream, stream};
    use std::{
        collections::HashMap,
        future::pending,
        net::{IpAddr, SocketAddr},
        pin::Pin,
        process::{Command, Output, Stdio},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
        time::Duration,
    };
    use time::{Duration as TimeDuration, OffsetDateTime, format_description::well_known::Rfc3339};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::Notify,
        task::JoinHandle,
    };
    use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
    use url::Url;

    struct DecisionFixtureTransport {
        node: &'static str,
        pending: bool,
        runtime_available: Option<Arc<std::sync::atomic::AtomicBool>>,
        subscriptions: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl MihomoTransport for DecisionFixtureTransport {
        async fn runtime(&self) -> Result<MihomoRuntime, DiagnosticError> {
            if self
                .runtime_available
                .as_ref()
                .is_some_and(|available| !available.load(Ordering::SeqCst))
            {
                return Err(DiagnosticError::System(
                    "sensitive-controller-runtime-detail".into(),
                ));
            }
            Ok(MihomoRuntime {
                available: true,
                mode: Some("rule".into()),
                tun_enabled: Some(true),
                controller: Some("manual_loopback".into()),
            })
        }

        async fn proxies(&self) -> Result<HashMap<String, MihomoProxy>, DiagnosticError> {
            Ok(HashMap::new())
        }

        async fn connection_stream(
            &self,
            _interval: Duration,
        ) -> Result<MihomoEventStream, DiagnosticError> {
            self.subscriptions.fetch_add(1, Ordering::SeqCst);
            if self.pending {
                return Ok(Box::pin(PendingFixtureStream {
                    drops: Arc::clone(&self.drops),
                }));
            }
            let start = (OffsetDateTime::now_utc() + TimeDuration::seconds(1))
                .format(&Rfc3339)
                .unwrap();
            let connection = serde_json::json!({
                "id": format!("{}-connection", self.node),
                "metadata": {
                    "network": "tcp",
                    "host": "example.com",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": "443"
                },
                "start": start,
                "chains": [self.node, "MATCH"],
                "providerChains": [],
                "rule": "MATCH",
                "rulePayload": ""
            });
            Ok(Box::pin(stream::iter(vec![Ok(MihomoEvent::Connection(
                MihomoConnectionEvent {
                    download_total: 0,
                    upload_total: 0,
                    connections: vec![connection],
                },
            ))])))
        }

        async fn log_stream(&self) -> Result<MihomoEventStream, DiagnosticError> {
            self.subscriptions.fetch_add(1, Ordering::SeqCst);
            if self.pending {
                Ok(Box::pin(PendingFixtureStream {
                    drops: Arc::clone(&self.drops),
                }))
            } else {
                Ok(Box::pin(stream::empty()))
            }
        }
    }

    struct PendingFixtureStream {
        drops: Arc<AtomicUsize>,
    }

    struct SelectionSecret;

    struct SelectionLifetimeTransport {
        _secret: Arc<SelectionSecret>,
    }

    #[async_trait]
    impl MihomoTransport for SelectionLifetimeTransport {
        async fn runtime(&self) -> Result<MihomoRuntime, DiagnosticError> {
            Ok(MihomoRuntime {
                available: true,
                mode: None,
                tun_enabled: None,
                controller: Some("manual_loopback".into()),
            })
        }

        async fn proxies(&self) -> Result<HashMap<String, MihomoProxy>, DiagnosticError> {
            Ok(HashMap::new())
        }

        async fn connection_stream(
            &self,
            _interval: Duration,
        ) -> Result<MihomoEventStream, DiagnosticError> {
            Ok(Box::pin(stream::empty()))
        }

        async fn log_stream(&self) -> Result<MihomoEventStream, DiagnosticError> {
            Ok(Box::pin(stream::empty()))
        }
    }

    impl Stream for PendingFixtureStream {
        type Item = Result<MihomoEvent, DiagnosticError>;

        fn poll_next(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    impl Drop for PendingFixtureStream {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[derive(Clone)]
    struct PausingFinishProvider {
        inner: MihomoTrafficDecisionProvider,
        finish_started: Arc<tokio::sync::Notify>,
        cancel_completed: Arc<tokio::sync::Notify>,
        cancel_calls: Arc<AtomicUsize>,
    }

    #[derive(Clone)]
    struct FinishErrorProvider {
        finish_calls: Arc<AtomicUsize>,
        cancel_calls: Arc<AtomicUsize>,
    }

    #[derive(Clone)]
    struct FinishOrderingProvider {
        finish_started: Arc<Notify>,
        finish_release: Arc<Notify>,
    }

    #[derive(Clone)]
    struct BlockingCancelProvider {
        inner: MihomoTrafficDecisionProvider,
        cancel_started: Arc<AtomicUsize>,
        cancel_release: Arc<Notify>,
        inner_drops: Arc<AtomicUsize>,
        cleanup_before_return: Arc<AtomicUsize>,
    }

    #[derive(Clone)]
    struct BlockingBeginProvider {
        begin_started: Arc<Notify>,
        begin_release: Arc<Notify>,
        cancel_started: Arc<Notify>,
        cancel_completed: Arc<Notify>,
        id: TrafficObservationId,
    }

    #[derive(Clone, Copy)]
    enum PanicPhase {
        Begin,
        Finish,
        Cancel,
    }

    #[derive(Clone, Copy)]
    struct PanicProvider {
        phase: PanicPhase,
    }

    #[derive(Clone)]
    struct PanicFinishBlockingCancelProvider {
        cancel_started: Arc<AtomicUsize>,
        cancel_release: Arc<Notify>,
    }

    #[async_trait]
    impl TrafficDecisionProvider for FinishErrorProvider {
        async fn runtime(&self) -> MihomoRuntime {
            MihomoRuntime {
                available: true,
                mode: None,
                tun_enabled: None,
                controller: Some("fixture".into()),
            }
        }

        async fn begin(
            &self,
            _target: &TrafficProbeTarget,
        ) -> Result<TrafficObservationId, DiagnosticError> {
            Ok(TrafficObservationId(Uuid::new_v4()))
        }

        async fn finish(
            &self,
            _id: TrafficObservationId,
        ) -> Result<TrafficDecision, DiagnosticError> {
            self.finish_calls.fetch_add(1, Ordering::SeqCst);
            Err(DiagnosticError::System(
                "sensitive-controller-finish-detail".into(),
            ))
        }

        async fn cancel(&self, _id: TrafficObservationId) {
            self.cancel_calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl TrafficDecisionProvider for FinishOrderingProvider {
        async fn runtime(&self) -> MihomoRuntime {
            MihomoRuntime {
                available: true,
                mode: Some("fixture".into()),
                tun_enabled: Some(true),
                controller: Some("fixture".into()),
            }
        }

        async fn begin(
            &self,
            _target: &TrafficProbeTarget,
        ) -> Result<TrafficObservationId, DiagnosticError> {
            Ok(TrafficObservationId(Uuid::new_v4()))
        }

        async fn finish(
            &self,
            _id: TrafficObservationId,
        ) -> Result<TrafficDecision, DiagnosticError> {
            self.finish_started.notify_one();
            self.finish_release.notified().await;
            Err(DiagnosticError::System("sanitized finish failure".into()))
        }

        async fn cancel(&self, _id: TrafficObservationId) {}
    }

    #[async_trait]
    impl TrafficDecisionProvider for BlockingCancelProvider {
        async fn runtime(&self) -> MihomoRuntime {
            self.inner.runtime().await
        }

        async fn begin(
            &self,
            target: &TrafficProbeTarget,
        ) -> Result<TrafficObservationId, DiagnosticError> {
            self.inner.begin(target).await
        }

        async fn begin_with_lifetime(
            &self,
            target: &TrafficProbeTarget,
            lifetime: Duration,
        ) -> Result<TrafficObservationId, DiagnosticError> {
            self.inner.begin_with_lifetime(target, lifetime).await
        }

        async fn finish(
            &self,
            id: TrafficObservationId,
        ) -> Result<TrafficDecision, DiagnosticError> {
            self.inner.finish(id).await
        }

        async fn cancel(&self, id: TrafficObservationId) {
            self.cancel_started.fetch_add(1, Ordering::SeqCst);
            self.cancel_release.notified().await;
            self.inner.cancel(id).await;
            if self.inner_drops.load(Ordering::SeqCst) < 2 {
                self.cleanup_before_return.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    #[async_trait]
    impl TrafficDecisionProvider for BlockingBeginProvider {
        async fn runtime(&self) -> MihomoRuntime {
            MihomoRuntime {
                available: true,
                mode: Some("fixture".into()),
                tun_enabled: Some(true),
                controller: Some("fixture".into()),
            }
        }

        async fn begin(
            &self,
            target: &TrafficProbeTarget,
        ) -> Result<TrafficObservationId, DiagnosticError> {
            self.begin_with_lifetime(target, OBSERVATION_DEADLINE).await
        }

        async fn begin_with_lifetime(
            &self,
            _target: &TrafficProbeTarget,
            _lifetime: Duration,
        ) -> Result<TrafficObservationId, DiagnosticError> {
            self.begin_started.notify_one();
            self.begin_release.notified().await;
            Ok(self.id)
        }

        async fn finish(
            &self,
            _id: TrafficObservationId,
        ) -> Result<TrafficDecision, DiagnosticError> {
            Ok(TrafficDecision::unknown("fixture", "not used"))
        }

        async fn cancel(&self, _id: TrafficObservationId) {
            self.cancel_started.notify_one();
            self.cancel_completed.notify_one();
        }
    }

    #[async_trait]
    impl TrafficDecisionProvider for PanicProvider {
        async fn runtime(&self) -> MihomoRuntime {
            MihomoRuntime {
                available: true,
                mode: Some("fixture".into()),
                tun_enabled: Some(true),
                controller: Some("fixture".into()),
            }
        }

        async fn begin(
            &self,
            _target: &TrafficProbeTarget,
        ) -> Result<TrafficObservationId, DiagnosticError> {
            if matches!(self.phase, PanicPhase::Begin) {
                panic!("task9-sensitive-payload target=203.0.113.77 secret=task9-secret");
            }
            Ok(TrafficObservationId(Uuid::new_v4()))
        }

        async fn finish(
            &self,
            _id: TrafficObservationId,
        ) -> Result<TrafficDecision, DiagnosticError> {
            if matches!(self.phase, PanicPhase::Finish) {
                panic!("task9-sensitive-payload target=203.0.113.77 secret=task9-secret");
            }
            Ok(TrafficDecision::unknown("fixture", "unused"))
        }

        async fn cancel(&self, _id: TrafficObservationId) {
            if matches!(self.phase, PanicPhase::Cancel) {
                panic!("task9-sensitive-payload target=203.0.113.77 secret=task9-secret");
            }
        }
    }

    #[async_trait]
    impl TrafficDecisionProvider for PanicFinishBlockingCancelProvider {
        async fn runtime(&self) -> MihomoRuntime {
            MihomoRuntime {
                available: true,
                mode: Some("fixture".into()),
                tun_enabled: Some(true),
                controller: Some("fixture".into()),
            }
        }

        async fn begin(
            &self,
            _target: &TrafficProbeTarget,
        ) -> Result<TrafficObservationId, DiagnosticError> {
            Ok(TrafficObservationId(Uuid::new_v4()))
        }

        async fn finish(
            &self,
            _id: TrafficObservationId,
        ) -> Result<TrafficDecision, DiagnosticError> {
            panic!("task9-sensitive-payload target=203.0.113.77 secret=task9-secret");
        }

        async fn cancel(&self, _id: TrafficObservationId) {
            self.cancel_started.fetch_add(1, Ordering::SeqCst);
            self.cancel_release.notified().await;
        }
    }

    #[async_trait]
    impl TrafficDecisionProvider for PausingFinishProvider {
        async fn runtime(&self) -> MihomoRuntime {
            self.inner.runtime().await
        }

        async fn begin(
            &self,
            target: &TrafficProbeTarget,
        ) -> Result<TrafficObservationId, DiagnosticError> {
            self.inner.begin(target).await
        }

        async fn finish(
            &self,
            _id: TrafficObservationId,
        ) -> Result<TrafficDecision, DiagnosticError> {
            self.finish_started.notify_one();
            pending().await
        }

        async fn cancel(&self, id: TrafficObservationId) {
            self.cancel_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.cancel(id).await;
            self.cancel_completed.notify_one();
        }
    }

    struct IntegratedProxy;

    #[async_trait]
    impl ProxyInspector for IntegratedProxy {
        async fn decision_for(&self, _url: &Url) -> Result<ProxyDecision, DiagnosticError> {
            Ok(ProxyDecision {
                kind: ProxyKind::Direct,
                host: None,
                port: None,
                bypass_reason: None,
                evidence: Evidence {
                    level: EvidenceLevel::Confirmed,
                    source: "test".into(),
                    summary: "direct".into(),
                },
            })
        }
    }

    struct IntegratedResolver;

    #[async_trait]
    impl Resolver for IntegratedResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, DiagnosticError> {
            Ok(vec!["93.184.216.34".parse().unwrap()])
        }
    }

    struct IntegratedRoute;

    #[async_trait]
    impl RouteInspector for IntegratedRoute {
        async fn route_to(&self, destination: IpAddr) -> Result<RouteInfo, DiagnosticError> {
            Ok(RouteInfo {
                destination,
                gateway: None,
                interface: "en0".into(),
            })
        }
    }

    struct IntegratedProbe;

    #[async_trait]
    impl WebProbe for IntegratedProbe {
        async fn probe(
            &self,
            url: &Url,
            _proxy: &ProxyDecision,
            _selected_peer: SocketAddr,
        ) -> Result<HttpObservation, DiagnosticError> {
            Ok(HttpObservation {
                status: Some(204),
                final_url: url.as_str().into(),
                elapsed_ms: 1,
                error_code: None,
                peer_endpoint: None,
            })
        }
    }

    struct IntegratedProgress;

    impl ProgressSink for IntegratedProgress {
        fn emit(&self, _stage: DiagnosticStage) {}
    }

    struct LocalExpiryController {
        endpoint: String,
        websocket_opens: Arc<AtomicUsize>,
        websocket_closes: Arc<AtomicUsize>,
        task: JoinHandle<()>,
    }

    impl LocalExpiryController {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let websocket_opens = Arc::new(AtomicUsize::new(0));
            let websocket_closes = Arc::new(AtomicUsize::new(0));
            let server_opens = Arc::clone(&websocket_opens);
            let server_closes = Arc::clone(&websocket_closes);
            let task = tokio::spawn(async move {
                while let Ok((socket, _)) = listener.accept().await {
                    let opens = Arc::clone(&server_opens);
                    let closes = Arc::clone(&server_closes);
                    tokio::spawn(serve_controller_socket(socket, opens, closes));
                }
            });
            Self {
                endpoint,
                websocket_opens,
                websocket_closes,
                task,
            }
        }
    }

    impl Drop for LocalExpiryController {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn serve_controller_socket(
        mut socket: TcpStream,
        websocket_opens: Arc<AtomicUsize>,
        websocket_closes: Arc<AtomicUsize>,
    ) {
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let Ok(read) = socket.read(&mut chunk).await else {
                return;
            };
            if read == 0 {
                return;
            }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let Ok(request) = std::str::from_utf8(&request) else {
            return;
        };
        let path = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or_default();
        let websocket_key = request.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("sec-websocket-key")
                .then(|| value.trim())
        });
        if let Some(websocket_key) = websocket_key {
            let accept = derive_accept_key(websocket_key.as_bytes());
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\nconnection: Upgrade\r\nupgrade: websocket\r\nsec-websocket-accept: {accept}\r\n\r\n"
            );
            if socket.write_all(response.as_bytes()).await.is_err() {
                return;
            }
            websocket_opens.fetch_add(1, Ordering::SeqCst);
            while socket.read(&mut chunk).await.is_ok_and(|read| read != 0) {}
            websocket_closes.fetch_add(1, Ordering::SeqCst);
            return;
        }

        let body = match path {
            "/version" => r#"{"version":"1.19.0"}"#,
            "/configs" => r#"{"mode":"rule","tun":{"enable":true}}"#,
            "/proxies" => r#"{"proxies":{}}"#,
            _ => r#"{}"#,
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = socket.write_all(response.as_bytes()).await;
        let _ = socket.shutdown().await;
    }

    fn fixture_transport(
        node: &'static str,
        pending: bool,
    ) -> (Arc<dyn MihomoTransport>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let subscriptions = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(DecisionFixtureTransport {
                node,
                pending,
                runtime_available: None,
                subscriptions: Arc::clone(&subscriptions),
                drops: Arc::clone(&drops),
            }),
            subscriptions,
            drops,
        )
    }

    async fn select(manager: &MihomoControllerManager, transport: Arc<dyn MihomoTransport>) {
        manager.install_manual_transport(transport).await;
    }

    fn controlled_manager(
        available: Arc<std::sync::atomic::AtomicBool>,
        transport: Arc<dyn MihomoTransport>,
        constructions: Arc<AtomicUsize>,
    ) -> MihomoControllerManager {
        MihomoControllerManager::new_with_sources(
            Arc::new(move || {
                available
                    .load(Ordering::SeqCst)
                    .then(|| Arc::clone(&transport))
            }),
            Arc::new(move |transport| {
                constructions.fetch_add(1, Ordering::SeqCst);
                Arc::new(MihomoTrafficDecisionProvider::new(transport))
            }),
        )
    }

    fn manager_for_provider(provider: Arc<dyn TrafficDecisionProvider>) -> MihomoControllerManager {
        let (transport, _, _) = fixture_transport("begin-owner", false);
        let provider_for_factory = Arc::clone(&provider);
        MihomoControllerManager::new_with_sources(
            Arc::new(move || Some(Arc::clone(&transport))),
            Arc::new(move |_| Arc::clone(&provider_for_factory)),
        )
    }

    fn target() -> TrafficProbeTarget {
        TrafficProbeTarget::new(
            TrafficProbeScheme::Https,
            "example.com",
            443,
            vec!["93.184.216.34".parse().unwrap()],
            4242,
        )
    }

    fn run_manager_panic_child(name: &str, phase: &'static str) -> Output {
        let mut child = Command::new(std::env::current_exe().expect("manager test executable"))
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env("TASK_9_MANAGER_PANIC_CHILD", phase)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn manager panic child");
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            if child
                .try_wait()
                .expect("poll manager panic child")
                .is_some()
            {
                return child
                    .wait_with_output()
                    .expect("collect manager panic child output");
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let output = child
                    .wait_with_output()
                    .expect("collect timed-out manager panic child output");
                panic!("manager panic child timed out: {output:?}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    async fn run_manager_panic_child_body(phase: PanicPhase) {
        let provider = Arc::new(PanicProvider { phase });
        let manager = manager_for_provider(provider.clone());
        match phase {
            PanicPhase::Begin => {
                let result = tokio::time::timeout(Duration::from_secs(1), manager.begin(&target()))
                    .await
                    .expect("panic begin must resolve");
                assert!(result.is_err());
            }
            PanicPhase::Finish => {
                let inner_id = provider.begin(&target()).await.unwrap();
                let outer_id = manager
                    .retain_observation(provider, inner_id, Instant::now())
                    .await
                    .expect("panic finish observation is admitted");
                let result = tokio::time::timeout(Duration::from_secs(1), manager.finish(outer_id))
                    .await
                    .expect("panic finish must resolve");
                assert!(result.is_err());
                assert!(manager.observations.lock().await.is_empty());
            }
            PanicPhase::Cancel => {
                let inner_id = provider.begin(&target()).await.unwrap();
                let outer_id = manager
                    .retain_observation(provider, inner_id, Instant::now())
                    .await
                    .expect("panic cancel observation is admitted");
                tokio::time::timeout(Duration::from_secs(1), manager.cancel(outer_id))
                    .await
                    .expect("panic cancel must resolve");
                assert!(manager.observations.lock().await.is_empty());
            }
        }
        manager.shutdown().await;
        assert!(manager.observations.lock().await.is_empty());
        assert_eq!(manager.observation_tasks.len(), 0);
        assert_eq!(manager.begin_tasks.len(), 0);
    }

    #[tokio::test]
    async fn manager_begin_panic_payload_is_redacted() {
        const NAME: &str =
            "traffic::mihomo::manager::tests::manager_begin_panic_payload_is_redacted";
        if let Some(phase) = std::env::var_os("TASK_9_MANAGER_PANIC_CHILD") {
            assert_eq!(phase, "begin");
            run_manager_panic_child_body(PanicPhase::Begin).await;
            return;
        }
        let output = run_manager_panic_child(NAME, "begin");
        assert!(
            output.status.success(),
            "manager begin child failed: {output:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("task9-sensitive-payload"));
        assert!(!stderr.contains("203.0.113.77"));
        assert!(!stderr.contains("task9-secret"));
    }

    #[tokio::test]
    async fn manager_finish_panic_is_sanitized_and_releases_ownership() {
        const NAME: &str = "traffic::mihomo::manager::tests::manager_finish_panic_is_sanitized_and_releases_ownership";
        if let Some(phase) = std::env::var_os("TASK_9_MANAGER_PANIC_CHILD") {
            assert_eq!(phase, "finish");
            run_manager_panic_child_body(PanicPhase::Finish).await;
            return;
        }
        let output = run_manager_panic_child(NAME, "finish");
        assert!(
            output.status.success(),
            "manager finish child failed: {output:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("task9-sensitive-payload"));
        assert!(!stderr.contains("203.0.113.77"));
        assert!(!stderr.contains("task9-secret"));
    }

    #[tokio::test]
    async fn manager_cancel_panic_is_sanitized_and_releases_ownership() {
        const NAME: &str = "traffic::mihomo::manager::tests::manager_cancel_panic_is_sanitized_and_releases_ownership";
        if let Some(phase) = std::env::var_os("TASK_9_MANAGER_PANIC_CHILD") {
            assert_eq!(phase, "cancel");
            run_manager_panic_child_body(PanicPhase::Cancel).await;
            return;
        }
        let output = run_manager_panic_child(NAME, "cancel");
        assert!(
            output.status.success(),
            "manager cancel child failed: {output:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("task9-sensitive-payload"));
        assert!(!stderr.contains("203.0.113.77"));
        assert!(!stderr.contains("task9-secret"));
    }

    fn speed_fixture_samples() -> Vec<SpeedSample> {
        vec![
            SpeedSample {
                kind: SpeedSampleKind::Latency,
                bytes: 0,
                bps: None,
                duration_ms: 20.0,
                latency_ms: Some(20.0),
            },
            SpeedSample {
                kind: SpeedSampleKind::Download,
                bytes: 100_000,
                bps: Some(80_000_000.0),
                duration_ms: 10.0,
                latency_ms: None,
            },
            SpeedSample {
                kind: SpeedSampleKind::Upload,
                bytes: 100_000,
                bps: Some(40_000_000.0),
                duration_ms: 20.0,
                latency_ms: None,
            },
        ]
    }

    fn speed_fixture_metrics() -> SpeedMetrics {
        SpeedMetrics {
            download_bps: 80_000_000.0,
            upload_bps: 40_000_000.0,
            unloaded_latency_ms: 20.0,
            unloaded_jitter_ms: 2.0,
            download_loaded_latency_ms: None,
            upload_loaded_latency_ms: None,
        }
    }

    #[tokio::test]
    async fn speed_manager_finish_panic_fails_and_keeps_capacity_until_cancel_cleanup() {
        let cancel_started = Arc::new(AtomicUsize::new(0));
        let cancel_release = Arc::new(Notify::new());
        let provider = Arc::new(PanicFinishBlockingCancelProvider {
            cancel_started: Arc::clone(&cancel_started),
            cancel_release: Arc::clone(&cancel_release),
        });
        let manager = manager_for_provider(provider);
        let coordinator = Arc::new(SpeedCoordinator::new(manager.clone()));
        let mut sessions = Vec::new();
        for _ in 0..10 {
            sessions.push(coordinator.start(SpeedMode::Quick).await.unwrap());
        }
        let ids = sessions
            .iter()
            .map(|session| session.id)
            .collect::<Vec<_>>();

        let mut completions = Vec::new();
        for session in sessions {
            coordinator
                .record_samples(session.id, speed_fixture_samples())
                .await
                .unwrap();
            let coordinator = Arc::clone(&coordinator);
            completions.push(tokio::spawn(async move {
                coordinator
                    .complete(session.id, speed_fixture_metrics())
                    .await
            }));
        }

        tokio::time::timeout(Duration::from_secs(1), async {
            while cancel_started.load(Ordering::SeqCst) != 10 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("finish panic must enter panic-contained cancel for every job");
        assert_eq!(
            coordinator.start(SpeedMode::Quick).await,
            Err(SpeedError::TooMany)
        );

        cancel_release.notify_waiters();
        for completion in completions {
            assert_eq!(
                completion.await.unwrap(),
                Err(SpeedError::ProviderUnavailable)
            );
        }
        for id in ids {
            assert_eq!(
                coordinator.snapshot(id).expect("speed snapshot").status,
                SpeedStatus::Failed
            );
        }
        assert!(manager.observations.lock().await.is_empty());
        coordinator.shutdown().await;
        manager.shutdown().await;
        assert_eq!(manager.observation_tasks.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn duration_aware_manager_observations_survive_quick_and_full_deadlines() {
        let manager = MihomoControllerManager::new();
        let (transport, _, _) = fixture_transport("long-lived", true);
        select(&manager, transport).await;
        let browser_target = TrafficProbeTarget::for_browser(
            TrafficProbeScheme::Https,
            "example.com",
            443,
            vec!["93.184.216.34".parse().unwrap()],
        );

        for lifetime in [Duration::from_secs(15), Duration::from_secs(40)] {
            let id = manager
                .begin_with_lifetime(&browser_target, lifetime)
                .await
                .unwrap();
            tokio::time::advance(Duration::from_secs(6)).await;
            tokio::task::yield_now().await;
            assert!(manager.observations.lock().await.contains_key(&id));
            manager.cancel(id).await;
        }

        manager.shutdown().await;
    }

    #[tokio::test]
    async fn finish_uses_the_provider_selected_when_the_observation_began() {
        let manager = MihomoControllerManager::new();
        let weak_observations = Arc::downgrade(&manager.observations);
        let (provider_a, _, _) = fixture_transport("provider-a", false);
        let (provider_b, _, _) = fixture_transport("provider-b", false);
        select(&manager, provider_a).await;
        let id = TrafficDecisionProvider::begin(&manager, &target())
            .await
            .unwrap();

        select(&manager, provider_b).await;
        let result = TrafficDecisionProvider::finish(&manager, id).await.unwrap();

        assert_eq!(result.kind, TrafficDecisionKind::Proxy);
        assert_eq!(result.chain.len(), 2);
        assert_eq!(result.chain[0].kind, TrafficNodeKind::TrafficRule);
        assert_eq!(result.chain[1].name, "provider-a");
        assert!(manager.observations.lock().await.is_empty());
        drop(manager);
        tokio::time::timeout(Duration::from_secs(1), async {
            while weak_observations.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("finish must stop the manager expiry cleanup task");
    }

    #[tokio::test]
    async fn cancel_uses_the_provider_selected_when_the_observation_began() {
        let manager = MihomoControllerManager::new();
        let weak_observations = Arc::downgrade(&manager.observations);
        let (provider_a, subscriptions_a, drops_a) = fixture_transport("provider-a", true);
        let (provider_b, subscriptions_b, _) = fixture_transport("provider-b", true);
        select(&manager, provider_a).await;
        let id = TrafficDecisionProvider::begin(&manager, &target())
            .await
            .unwrap();

        select(&manager, provider_b).await;
        TrafficDecisionProvider::cancel(&manager, id).await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while drops_a.load(Ordering::SeqCst) != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancel must stop the original provider streams");

        assert_eq!(subscriptions_a.load(Ordering::SeqCst), 2);
        assert_eq!(drops_a.load(Ordering::SeqCst), 2);
        assert_eq!(subscriptions_b.load(Ordering::SeqCst), 0);
        assert!(manager.observations.lock().await.is_empty());
        drop(manager);
        tokio::time::timeout(Duration::from_secs(1), async {
            while weak_observations.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancel must stop the manager expiry cleanup task");
    }

    #[tokio::test]
    async fn cancel_reaches_inner_observation_while_manager_finish_is_pending() {
        let manager = MihomoControllerManager::new();
        let (transport, subscriptions, drops) = fixture_transport("pending-finish", true);
        let inner = MihomoTrafficDecisionProvider::new(transport);
        let finish_started = Arc::new(tokio::sync::Notify::new());
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(PausingFinishProvider {
            inner,
            finish_started: Arc::clone(&finish_started),
            cancel_completed: Arc::new(tokio::sync::Notify::new()),
            cancel_calls: Arc::clone(&cancel_calls),
        });
        let inner_id = provider.begin(&target()).await.unwrap();
        let outer_id = manager
            .retain_observation(provider.clone(), inner_id, Instant::now())
            .await
            .expect("observation is admitted");
        let finish_manager = manager.clone();
        let finish_task = tokio::spawn(async move { finish_manager.finish(outer_id).await });
        finish_started.notified().await;

        finish_task.abort();
        let _ = finish_task.await;
        manager.cancel(outer_id).await;
        let cancelled_promptly = tokio::time::timeout(Duration::from_secs(1), async {
            while cancel_calls.load(Ordering::SeqCst) != 1 || drops.load(Ordering::SeqCst) != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_ok();

        assert!(
            cancelled_promptly,
            "pending finish lost manager cancellation"
        );
        assert_eq!(subscriptions.load(Ordering::SeqCst), 2);
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        assert!(manager.observations.lock().await.is_empty());
        assert_eq!(provider.inner.active_observation_count().await, 0);
        manager.shutdown().await;
        assert!(manager.observation_tasks.is_closed());
        assert_eq!(manager.observation_tasks.len(), 0);
    }

    #[tokio::test]
    async fn aborting_url_during_manager_finish_cancels_both_nested_observations() {
        let (transport, subscriptions, drops) = fixture_transport("integrated-finish", true);
        let inner = MihomoTrafficDecisionProvider::new(transport);
        let finish_started = Arc::new(tokio::sync::Notify::new());
        let cancel_completed = Arc::new(tokio::sync::Notify::new());
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(PausingFinishProvider {
            inner,
            finish_started: Arc::clone(&finish_started),
            cancel_completed: Arc::clone(&cancel_completed),
            cancel_calls: Arc::clone(&cancel_calls),
        });
        let provider_for_factory: Arc<dyn TrafficDecisionProvider> = provider.clone();
        let (discovered_transport, _, _) = fixture_transport("unused-discovery", false);
        let manager = MihomoControllerManager::new_with_sources(
            Arc::new(move || Some(Arc::clone(&discovered_transport))),
            Arc::new(move |_| Arc::clone(&provider_for_factory)),
        );
        let service = Arc::new(UrlDiagnosticService::new(
            IntegratedProxy,
            IntegratedResolver,
            IntegratedRoute,
            IntegratedProbe,
            manager.clone(),
        ));
        let run_service = Arc::clone(&service);
        let run = tokio::spawn(async move {
            run_service
                .run("https://example.com", &IntegratedProgress)
                .await
        });
        finish_started.notified().await;

        run.abort();
        let _ = run.await;
        tokio::time::timeout(Duration::from_secs(1), cancel_completed.notified())
            .await
            .expect("URL drop must promptly cancel the nested manager observation");
        tokio::time::timeout(Duration::from_secs(1), async {
            while !manager.observations.lock().await.is_empty()
                || provider.inner.active_observation_count().await != 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("nested URL and manager workers must release both observation maps");

        assert_eq!(subscriptions.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 1);
        service.shutdown().await;
        manager.shutdown().await;
        assert_eq!(manager.observation_tasks.len(), 0);
    }

    #[tokio::test]
    async fn finish_error_cancels_once_before_releasing_the_outer_mapping() {
        let manager = MihomoControllerManager::new();
        let finish_calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(FinishErrorProvider {
            finish_calls: Arc::clone(&finish_calls),
            cancel_calls: Arc::clone(&cancel_calls),
        });
        let inner_id = provider.begin(&target()).await.unwrap();
        let outer_id = manager
            .retain_observation(provider, inner_id, Instant::now())
            .await
            .expect("observation is admitted");
        let done = manager
            .observations
            .lock()
            .await
            .get(&outer_id)
            .unwrap()
            .done
            .clone();

        let result = manager.finish(outer_id).await;
        done.cancelled().await;

        assert!(result.is_err());
        assert_eq!(finish_calls.load(Ordering::SeqCst), 1);
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 1);
        assert!(manager.observations.lock().await.is_empty());
    }

    #[tokio::test]
    async fn manager_finish_does_not_reply_before_outer_mapping_cleanup() {
        let manager = MihomoControllerManager::new();
        let finish_started = Arc::new(Notify::new());
        let finish_release = Arc::new(Notify::new());
        let provider = Arc::new(FinishOrderingProvider {
            finish_started: Arc::clone(&finish_started),
            finish_release: Arc::clone(&finish_release),
        });
        let inner_id = provider.begin(&target()).await.unwrap();
        let outer_id = manager
            .retain_observation(provider, inner_id, Instant::now())
            .await
            .expect("observation is admitted");

        let finish_manager = manager.clone();
        let mut finish = tokio::spawn(async move { finish_manager.finish(outer_id).await });
        finish_started.notified().await;
        let observations_guard = manager.observations.lock().await;
        finish_release.notify_one();

        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut finish)
                .await
                .is_err()
        );
        drop(observations_guard);

        assert!(finish.await.unwrap().is_err());
        assert!(manager.observations.lock().await.is_empty());
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_cancels_and_drains_pending_manager_observations() {
        let manager = MihomoControllerManager::new();
        let (transport, subscriptions, drops) = fixture_transport("shutdown", true);
        let provider = Arc::new(MihomoTrafficDecisionProvider::new(transport));
        let inner_id = provider.begin(&target()).await.unwrap();
        manager
            .retain_observation(provider.clone(), inner_id, Instant::now())
            .await
            .expect("observation is admitted");

        manager.shutdown().await;

        assert_eq!(subscriptions.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        assert_eq!(provider.active_observation_count().await, 0);
        assert!(manager.observations.lock().await.is_empty());
        assert!(manager.observation_tasks.is_closed());
        assert_eq!(manager.observation_tasks.len(), 0);
    }

    #[tokio::test]
    async fn manager_shutdown_waits_for_pending_inner_begin_and_cancels_result() {
        let provider = Arc::new(BlockingBeginProvider {
            begin_started: Arc::new(Notify::new()),
            begin_release: Arc::new(Notify::new()),
            cancel_started: Arc::new(Notify::new()),
            cancel_completed: Arc::new(Notify::new()),
            id: TrafficObservationId(Uuid::new_v4()),
        });
        let manager = manager_for_provider(provider.clone());
        let begin_manager = manager.clone();
        let begin = tokio::spawn(async move { begin_manager.begin(&target()).await });
        provider.begin_started.notified().await;

        let shutdown_manager = manager.clone();
        let shutdown = tokio::spawn(async move { shutdown_manager.shutdown().await });
        tokio::task::yield_now().await;
        assert!(!shutdown.is_finished());

        provider.begin_release.notify_one();
        let begin_result = tokio::time::timeout(Duration::from_secs(1), begin)
            .await
            .expect("manager begin must resolve after the inner provider is released")
            .unwrap();
        assert!(begin_result.is_err());
        tokio::time::timeout(Duration::from_secs(1), provider.cancel_completed.notified())
            .await
            .expect("shutdown must await inner cancellation");
        shutdown.await.unwrap();

        assert!(manager.observations.lock().await.is_empty());
        assert_eq!(manager.begin_tasks.len(), 0);
        assert_eq!(manager.observation_tasks.len(), 0);
    }

    #[tokio::test]
    async fn dropped_manager_begin_keeps_inner_owner_until_cancel_completes() {
        let provider = Arc::new(BlockingBeginProvider {
            begin_started: Arc::new(Notify::new()),
            begin_release: Arc::new(Notify::new()),
            cancel_started: Arc::new(Notify::new()),
            cancel_completed: Arc::new(Notify::new()),
            id: TrafficObservationId(Uuid::new_v4()),
        });
        let manager = manager_for_provider(provider.clone());
        let begin_manager = manager.clone();
        let begin = tokio::spawn(async move { begin_manager.begin(&target()).await });
        provider.begin_started.notified().await;

        begin.abort();
        let _ = begin.await;
        provider.begin_release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), provider.cancel_completed.notified())
            .await
            .expect("caller drop must not abandon the inner observation");

        manager.shutdown().await;
        assert!(manager.observations.lock().await.is_empty());
        assert_eq!(manager.begin_tasks.len(), 0);
        assert_eq!(manager.observation_tasks.len(), 0);
    }

    #[tokio::test]
    async fn speed_coordinator_waits_for_mihomo_stream_cleanup_before_releasing_capacity() {
        let (transport, subscriptions, drops) = fixture_transport("speed-cleanup", true);
        let inner = MihomoTrafficDecisionProvider::new(Arc::clone(&transport));
        let cancel_started = Arc::new(AtomicUsize::new(0));
        let cancel_release = Arc::new(Notify::new());
        let cleanup_before_return = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(BlockingCancelProvider {
            inner: inner.clone(),
            cancel_started: Arc::clone(&cancel_started),
            cancel_release: Arc::clone(&cancel_release),
            inner_drops: Arc::clone(&drops),
            cleanup_before_return: Arc::clone(&cleanup_before_return),
        });
        let provider_for_factory: Arc<dyn TrafficDecisionProvider> = provider;
        let discovered_transport = Arc::clone(&transport);
        let manager = MihomoControllerManager::new_with_sources(
            Arc::new(move || Some(Arc::clone(&discovered_transport))),
            Arc::new(move |_| Arc::clone(&provider_for_factory)),
        );
        let coordinator = Arc::new(SpeedCoordinator::new(manager.clone()));

        let mut sessions = Vec::new();
        for _ in 0..10 {
            sessions.push(coordinator.start(SpeedMode::Quick).await.unwrap());
        }

        let mut cancellations = Vec::new();
        for session in &sessions {
            let coordinator = Arc::clone(&coordinator);
            let id = session.id;
            cancellations.push(tokio::spawn(async move { coordinator.cancel(id).await }));
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while cancel_started.load(Ordering::SeqCst) != 10 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all production provider cleanup calls must be blocked");

        assert_eq!(
            coordinator.start(SpeedMode::Quick).await,
            Err(SpeedError::TooMany)
        );

        let shutdown = {
            let coordinator = Arc::clone(&coordinator);
            tokio::spawn(async move { coordinator.shutdown().await })
        };
        tokio::task::yield_now().await;
        assert!(!shutdown.is_finished());

        cancel_release.notify_waiters();
        for cancellation in cancellations {
            cancellation.await.unwrap().unwrap();
        }
        shutdown.await.unwrap();
        manager.shutdown().await;

        assert_eq!(subscriptions.load(Ordering::SeqCst), 20);
        assert_eq!(cleanup_before_return.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 20);
        assert_eq!(inner.active_observation_count().await, 0);
        assert!(manager.observations.lock().await.is_empty());
        assert_eq!(manager.observation_tasks.len(), 0);
    }

    #[tokio::test]
    async fn shutdown_rejects_late_manager_observation_admission() {
        let available = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let constructions = Arc::new(AtomicUsize::new(0));
        let (unused_transport, _, _) = fixture_transport("unused", false);
        let manager = controlled_manager(available, unused_transport, constructions);
        manager.shutdown().await;

        let result = manager.begin(&target()).await;

        assert!(result.is_err());
        assert!(manager.observations.lock().await.is_empty());
        assert_eq!(manager.observation_tasks.len(), 0);
    }

    #[tokio::test]
    async fn selected_controller_constructs_one_shared_provider_for_multiple_observations() {
        let available = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let constructions = Arc::new(AtomicUsize::new(0));
        let (transport, _, _) = fixture_transport("cached-provider", false);
        let manager = controlled_manager(available, transport, Arc::clone(&constructions));

        for _ in 0..2 {
            let id = manager.begin(&target()).await.unwrap();
            assert_eq!(
                manager.finish(id).await.unwrap().kind,
                TrafficDecisionKind::Proxy
            );
        }

        assert_eq!(constructions.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unavailable_auto_discovery_recovers_for_the_next_observation() {
        let available = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let constructions = Arc::new(AtomicUsize::new(0));
        let (transport, subscriptions, _) = fixture_transport("recovered-auto", false);
        let manager = controlled_manager(
            Arc::clone(&available),
            transport,
            Arc::clone(&constructions),
        );

        assert!(!manager.runtime().await.available);
        available.store(true, Ordering::SeqCst);
        let id = manager.begin(&target()).await.unwrap();
        let decision = manager.finish(id).await.unwrap();

        assert_eq!(decision.kind, TrafficDecisionKind::Proxy);
        assert_eq!(constructions.load(Ordering::SeqCst), 1);
        assert_eq!(subscriptions.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn initial_runtime_failure_is_nonfatal_and_the_cached_provider_recovers() {
        let discovered = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let runtime_available = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let constructions = Arc::new(AtomicUsize::new(0));
        let subscriptions = Arc::new(AtomicUsize::new(0));
        let transport: Arc<dyn MihomoTransport> = Arc::new(DecisionFixtureTransport {
            node: "runtime-recovered",
            pending: false,
            runtime_available: Some(Arc::clone(&runtime_available)),
            subscriptions: Arc::clone(&subscriptions),
            drops: Arc::new(AtomicUsize::new(0)),
        });
        let manager = controlled_manager(discovered, transport, Arc::clone(&constructions));

        let initial = TrafficDecisionProvider::runtime(&manager).await;
        assert!(!initial.available);
        assert!(!format!("{initial:?}").contains("sensitive-controller-runtime-detail"));

        runtime_available.store(true, Ordering::SeqCst);
        let recovered = TrafficDecisionProvider::runtime(&manager).await;
        let id = manager.begin(&target()).await.unwrap();
        let decision = manager.finish(id).await.unwrap();

        assert!(recovered.available);
        assert_eq!(decision.kind, TrafficDecisionKind::Proxy);
        assert_eq!(constructions.load(Ordering::SeqCst), 1);
        assert_eq!(subscriptions.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn manual_selection_recovers_without_rebuilding_the_manager() {
        let available = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let constructions = Arc::new(AtomicUsize::new(0));
        let (unused_transport, _, _) = fixture_transport("unused-auto", false);
        let manager = controlled_manager(available, unused_transport, Arc::clone(&constructions));
        assert!(!manager.runtime().await.available);

        let (manual_transport, _, _) = fixture_transport("manual-recovery", false);
        manager.install_manual_transport(manual_transport).await;
        let id = manager.begin(&target()).await.unwrap();
        let decision = manager.finish(id).await.unwrap();

        assert_eq!(decision.kind, TrafficDecisionKind::Proxy);
        assert_eq!(decision.chain[1].name, "manual-recovery");
        assert_eq!(constructions.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn delayed_manual_selection_cannot_overwrite_a_newer_reset() {
        let available = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let constructions = Arc::new(AtomicUsize::new(0));
        let (unused_transport, _, _) = fixture_transport("unused-auto", false);
        let manager = controlled_manager(available, unused_transport, Arc::clone(&constructions));
        let secret = Arc::new(SelectionSecret);
        let weak_secret = Arc::downgrade(&secret);
        let transport = Arc::new(SelectionLifetimeTransport { _secret: secret });
        let weak_transport = Arc::downgrade(&transport);
        let transport: Arc<dyn MihomoTransport> = transport;
        let entered = Arc::new(tokio::sync::Barrier::new(2));
        let selection = {
            let manager = manager.clone();
            let entered = Arc::clone(&entered);
            tokio::spawn(async move {
                manager
                    .set_manual_candidate(transport, async move {
                        entered.wait().await;
                        pending().await
                    })
                    .await
            })
        };
        entered.wait().await;

        manager.reset_auto().await;
        let error = tokio::time::timeout(Duration::from_secs(1), selection)
            .await
            .expect("reset must cancel and drain the older manual probe")
            .unwrap()
            .unwrap_err();

        assert!(manager.transport().await.is_none());
        assert_eq!(constructions.load(Ordering::SeqCst), 0);
        assert!(weak_transport.upgrade().is_none());
        assert!(weak_secret.upgrade().is_none());
        assert!(manager.pending_candidates.lock().await.is_empty());
        assert_eq!(manager.candidate_tasks.len(), 0);
        assert!(!error.to_string().contains("secret"));
    }

    #[tokio::test]
    async fn delayed_manual_selection_cannot_overwrite_a_newer_manual_selection() {
        let available = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let constructions = Arc::new(AtomicUsize::new(0));
        let (unused_transport, _, _) = fixture_transport("unused-auto", false);
        let manager = controlled_manager(available, unused_transport, Arc::clone(&constructions));
        let secret_a = Arc::new(SelectionSecret);
        let weak_secret_a = Arc::downgrade(&secret_a);
        let transport_a = Arc::new(SelectionLifetimeTransport { _secret: secret_a });
        let weak_transport_a = Arc::downgrade(&transport_a);
        let transport_a: Arc<dyn MihomoTransport> = transport_a;
        let secret_b = Arc::new(SelectionSecret);
        let transport_b = Arc::new(SelectionLifetimeTransport { _secret: secret_b });
        let transport_b: Arc<dyn MihomoTransport> = transport_b;
        let entered = Arc::new(tokio::sync::Barrier::new(2));
        let selection_a = {
            let manager = manager.clone();
            let entered = Arc::clone(&entered);
            tokio::spawn(async move {
                manager
                    .set_manual_candidate(transport_a, async move {
                        entered.wait().await;
                        pending().await
                    })
                    .await
            })
        };
        entered.wait().await;

        manager
            .set_manual_candidate(Arc::clone(&transport_b), async { Ok(()) })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), selection_a)
            .await
            .expect("a newer manual PUT must cancel and drain its predecessor")
            .unwrap()
            .unwrap_err();

        let selected = manager.transport().await.unwrap();
        assert!(Arc::ptr_eq(&selected, &transport_b));
        assert_eq!(constructions.load(Ordering::SeqCst), 1);
        assert!(weak_transport_a.upgrade().is_none());
        assert!(weak_secret_a.upgrade().is_none());
        assert!(manager.pending_candidates.lock().await.is_empty());
        assert_eq!(manager.candidate_tasks.len(), 0);
    }

    #[tokio::test]
    async fn dropped_manual_request_cancels_owned_probe_and_releases_secret() {
        let manager = MihomoControllerManager::new();
        let secret = Arc::new(SelectionSecret);
        let weak_secret = Arc::downgrade(&secret);
        let transport = Arc::new(SelectionLifetimeTransport { _secret: secret });
        let weak_transport = Arc::downgrade(&transport);
        let transport: Arc<dyn MihomoTransport> = transport;
        let entered = Arc::new(tokio::sync::Barrier::new(2));
        let request = {
            let manager = manager.clone();
            let entered = Arc::clone(&entered);
            tokio::spawn(async move {
                manager
                    .set_manual_candidate(transport, async move {
                        entered.wait().await;
                        pending().await
                    })
                    .await
            })
        };
        entered.wait().await;

        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if manager.pending_candidates.lock().await.is_empty()
                    && manager.candidate_tasks.is_empty()
                    && weak_transport.upgrade().is_none()
                    && weak_secret.upgrade().is_none()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping the PUT handler future must drain its candidate probe");
    }

    #[tokio::test]
    async fn manager_shutdown_cancels_owned_probe_and_releases_secret() {
        let manager = MihomoControllerManager::new();
        let secret = Arc::new(SelectionSecret);
        let weak_secret = Arc::downgrade(&secret);
        let transport = Arc::new(SelectionLifetimeTransport { _secret: secret });
        let weak_transport = Arc::downgrade(&transport);
        let transport: Arc<dyn MihomoTransport> = transport;
        let entered = Arc::new(tokio::sync::Barrier::new(2));
        let request = {
            let manager = manager.clone();
            let entered = Arc::clone(&entered);
            tokio::spawn(async move {
                manager
                    .set_manual_candidate(transport, async move {
                        entered.wait().await;
                        pending().await
                    })
                    .await
            })
        };
        entered.wait().await;

        tokio::time::timeout(Duration::from_secs(1), manager.shutdown())
            .await
            .expect("manager shutdown must cancel and drain candidate probes");
        request.await.unwrap().unwrap_err();

        assert!(manager.pending_candidates.lock().await.is_empty());
        assert_eq!(manager.candidate_tasks.len(), 0);
        assert!(weak_transport.upgrade().is_none());
        assert!(weak_secret.upgrade().is_none());
    }

    #[tokio::test]
    async fn abandoned_observation_expires_and_releases_original_transport_after_controller_switch()
    {
        let manager = MihomoControllerManager::new();
        let (provider_a, subscriptions_a, drops_a) = fixture_transport("provider-a", true);
        let weak_provider_a = Arc::downgrade(&provider_a);
        let (provider_b, subscriptions_b, _) = fixture_transport("provider-b", true);
        select(&manager, Arc::clone(&provider_a)).await;
        let _id = TrafficDecisionProvider::begin(&manager, &target())
            .await
            .unwrap();

        select(&manager, provider_b).await;
        drop(provider_a);

        tokio::time::timeout(Duration::from_secs(6), async {
            loop {
                let observations_are_empty = manager.observations.lock().await.is_empty();
                if observations_are_empty
                    && drops_a.load(Ordering::SeqCst) == 2
                    && weak_provider_a.upgrade().is_none()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("manager expiry must release the retained provider and its streams");

        assert_eq!(subscriptions_a.load(Ordering::SeqCst), 2);
        assert_eq!(drops_a.load(Ordering::SeqCst), 2);
        assert_eq!(subscriptions_b.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn abandoned_manual_observation_expires_and_releases_transport_after_reset_auto() {
        let manager = MihomoControllerManager::new();
        let (manual_transport, subscriptions, drops) = fixture_transport("manual", true);
        let weak_manual_transport = Arc::downgrade(&manual_transport);
        select(&manager, Arc::clone(&manual_transport)).await;
        let _id = TrafficDecisionProvider::begin(&manager, &target())
            .await
            .unwrap();

        manager.reset_auto().await;
        drop(manual_transport);

        tokio::time::timeout(Duration::from_secs(6), async {
            loop {
                let observations_are_empty = manager.observations.lock().await.is_empty();
                if observations_are_empty
                    && drops.load(Ordering::SeqCst) == 2
                    && weak_manual_transport.upgrade().is_none()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("manager expiry must release a reset manual controller");

        assert_eq!(subscriptions.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn set_manual_observation_expiry_releases_secret_transport_and_websocket_streams() {
        let controller = LocalExpiryController::start().await;
        let manager = MihomoControllerManager::new();
        let secret = "manager-expiry-secret";
        manager
            .set_manual(&controller.endpoint, Some(secret.into()))
            .await
            .unwrap();
        let manual_transport = manager.transport().await.unwrap();
        let weak_manual_transport = Arc::downgrade(&manual_transport);
        let _id = TrafficDecisionProvider::begin(&manager, &target())
            .await
            .unwrap();
        assert_eq!(controller.websocket_opens.load(Ordering::SeqCst), 2);

        manager.reset_auto().await;
        drop(manual_transport);

        tokio::time::timeout(Duration::from_secs(6), async {
            loop {
                let observations_are_empty = manager.observations.lock().await.is_empty();
                if observations_are_empty
                    && controller.websocket_closes.load(Ordering::SeqCst) == 2
                    && weak_manual_transport.upgrade().is_none()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("set_manual observation expiry must release its transport and streams");

        assert!(!format!("{manager:?}").contains(secret));
        assert_eq!(controller.websocket_closes.load(Ordering::SeqCst), 2);
    }
}

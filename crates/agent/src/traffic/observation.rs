use crate::{
    domain::TrafficDecision,
    ports::{TrafficDecisionProvider, TrafficObservationId, TrafficProbeTarget},
};
use tokio::sync::{Mutex, oneshot};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub(crate) struct TrafficObservationTracker<T> {
    provider: T,
    admission: Mutex<()>,
    shutdown: CancellationToken,
    tasks: TaskTracker,
}

impl<T> TrafficObservationTracker<T>
where
    T: TrafficDecisionProvider + Clone + 'static,
{
    pub(crate) fn new(provider: T) -> Self {
        Self {
            provider,
            admission: Mutex::new(()),
            shutdown: CancellationToken::new(),
            tasks: TaskTracker::new(),
        }
    }

    pub(crate) async fn begin(&self, target: &TrafficProbeTarget) -> TrafficObservation {
        if self.shutdown.is_cancelled() || self.tasks.is_closed() {
            return TrafficObservation::inactive();
        }
        let provider = self.provider.clone();
        let Ok(id) = provider.begin(target).await else {
            return TrafficObservation::inactive();
        };
        let admission = self.admission.lock().await;
        if self.shutdown.is_cancelled() || self.tasks.is_closed() {
            drop(admission);
            provider.cancel(id).await;
            return TrafficObservation::inactive();
        }
        let cancel = self.shutdown.child_token();
        let (finish, finish_request) = oneshot::channel();
        let (result_sender, result) = oneshot::channel();
        self.tasks.spawn(run_traffic_observation(
            provider,
            id,
            cancel.clone(),
            finish_request,
            result_sender,
        ));
        drop(admission);
        TrafficObservation {
            cancel,
            finish: Some(finish),
            result: Some(result),
            active: true,
        }
    }

    pub(crate) async fn shutdown(&self) {
        {
            let _admission = self.admission.lock().await;
            self.shutdown.cancel();
            self.tasks.close();
        }
        self.tasks.wait().await;
    }
}

impl<T> Drop for TrafficObservationTracker<T> {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.tasks.close();
    }
}

pub(crate) struct TrafficObservation {
    cancel: CancellationToken,
    finish: Option<oneshot::Sender<()>>,
    result: Option<oneshot::Receiver<TrafficDecision>>,
    active: bool,
}

impl TrafficObservation {
    fn inactive() -> Self {
        Self {
            cancel: CancellationToken::new(),
            finish: None,
            result: None,
            active: false,
        }
    }

    pub(crate) async fn finish(&mut self) -> TrafficDecision {
        let (Some(finish), Some(result)) = (self.finish.take(), self.result.take()) else {
            return unknown_traffic_decision();
        };
        if finish.send(()).is_err() {
            self.cancel.cancel();
            self.active = false;
            return unknown_traffic_decision();
        }
        let decision = match result.await {
            Ok(decision) => decision,
            Err(_) => {
                self.cancel.cancel();
                unknown_traffic_decision()
            }
        };
        self.active = false;
        if decision.evidence.iter().any(|evidence| {
            matches!(
                evidence.source.as_str(),
                "traffic_adapter" | "mihomo_manager"
            )
        }) {
            unknown_traffic_decision()
        } else {
            decision
        }
    }
}

impl Drop for TrafficObservation {
    fn drop(&mut self) {
        if self.active {
            self.cancel.cancel();
        }
    }
}

async fn run_traffic_observation<T>(
    provider: T,
    id: TrafficObservationId,
    cancel: CancellationToken,
    mut finish_request: oneshot::Receiver<()>,
    result: oneshot::Sender<TrafficDecision>,
) where
    T: TrafficDecisionProvider + Clone + 'static,
{
    let decision = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            provider.cancel(id).await;
            None
        }
        request = &mut finish_request => {
            if request.is_err() {
                provider.cancel(id).await;
                None
            } else {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {
                        provider.cancel(id).await;
                        None
                    }
                    decision = provider.finish(id) => {
                        match decision {
                            Ok(decision) => Some(decision),
                            Err(_) => {
                                provider.cancel(id).await;
                                Some(unknown_traffic_decision())
                            }
                        }
                    }
                }
            }
        }
    };
    if let Some(decision) = decision {
        let _ = result.send(decision);
    }
}

pub(crate) fn unknown_traffic_decision() -> TrafficDecision {
    TrafficDecision::unknown("mihomo", "未能确认 Clash 最终决策")
}

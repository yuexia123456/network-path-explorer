use async_trait::async_trait;
use network_path_agent::{
    domain::{Evidence, EvidenceLevel, TrafficDecision, TrafficDecisionKind},
    error::DiagnosticError,
    ports::{
        TrafficDecisionProvider, TrafficObservationId, TrafficProbeCorrelation, TrafficProbeTarget,
    },
    speed::{
        SpeedCoordinator, SpeedError, SpeedMetrics, SpeedMode, SpeedSample, SpeedSampleKind,
        plan_for,
    },
};
use serde_json::json;
use std::sync::{
    Arc, Mutex as StdMutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::sync::Notify;
use uuid::Uuid;

#[derive(Clone)]
struct FixtureTraffic {
    finish_calls: Arc<AtomicUsize>,
    cancel_calls: Arc<AtomicUsize>,
    finish_release: Arc<Notify>,
    decision: TrafficDecision,
}

#[derive(Clone)]
struct DurationRecordingTraffic {
    inner: FixtureTraffic,
    observations: Arc<StdMutex<Vec<(Duration, TrafficProbeCorrelation)>>>,
}

#[async_trait]
impl TrafficDecisionProvider for DurationRecordingTraffic {
    async fn runtime(&self) -> network_path_agent::domain::MihomoRuntime {
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
        self.observations
            .lock()
            .unwrap()
            .push((lifetime, target.correlation));
        self.inner.begin(target).await
    }

    async fn finish(&self, id: TrafficObservationId) -> Result<TrafficDecision, DiagnosticError> {
        self.inner.finish(id).await
    }

    async fn cancel(&self, id: TrafficObservationId) {
        self.inner.cancel(id).await;
    }
}

#[derive(Clone)]
struct BlockingLifecycleTraffic {
    begin_started: Arc<Notify>,
    begin_release: Arc<Notify>,
    begin_pending: bool,
    cancel_started: Arc<AtomicUsize>,
    cancel_release: Arc<Notify>,
    decision: TrafficDecision,
}

#[async_trait]
impl TrafficDecisionProvider for BlockingLifecycleTraffic {
    async fn runtime(&self) -> network_path_agent::domain::MihomoRuntime {
        unreachable!("lifecycle tests only use observation methods")
    }

    async fn begin(
        &self,
        _target: &TrafficProbeTarget,
    ) -> Result<TrafficObservationId, DiagnosticError> {
        if self.begin_pending {
            self.begin_started.notify_waiters();
            self.begin_release.notified().await;
        }
        Ok(TrafficObservationId(Uuid::new_v4()))
    }

    async fn finish(&self, _id: TrafficObservationId) -> Result<TrafficDecision, DiagnosticError> {
        Ok(self.decision.clone())
    }

    async fn cancel(&self, _id: TrafficObservationId) {
        self.cancel_started.fetch_add(1, Ordering::SeqCst);
        self.cancel_release.notified().await;
    }
}

#[async_trait]
impl TrafficDecisionProvider for FixtureTraffic {
    async fn runtime(&self) -> network_path_agent::domain::MihomoRuntime {
        unreachable!("speed tests only use the observation methods")
    }

    async fn begin(
        &self,
        target: &TrafficProbeTarget,
    ) -> Result<TrafficObservationId, DiagnosticError> {
        assert_eq!(target.host, "speed.cloudflare.com");
        assert_eq!(target.port, 443);
        assert_eq!(target.resolved_ips, Vec::<std::net::IpAddr>::new());
        Ok(TrafficObservationId(Uuid::new_v4()))
    }

    async fn finish(&self, _id: TrafficObservationId) -> Result<TrafficDecision, DiagnosticError> {
        self.finish_calls.fetch_add(1, Ordering::SeqCst);
        self.finish_release.notify_waiters();
        Ok(self.decision.clone())
    }

    async fn cancel(&self, _id: TrafficObservationId) {
        self.cancel_calls.fetch_add(1, Ordering::SeqCst);
    }
}

fn decision() -> TrafficDecision {
    TrafficDecision {
        kind: TrafficDecisionKind::Proxy,
        mode: Some("Rule".into()),
        tun_enabled: Some(true),
        rule: None,
        chain: Vec::new(),
        evidence: vec![Evidence {
            level: EvidenceLevel::Confirmed,
            source: "fixture".into(),
            summary: "speed path observed".into(),
        }],
    }
}

fn coordinator() -> (
    SpeedCoordinator<FixtureTraffic>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    let finish_calls = Arc::new(AtomicUsize::new(0));
    let cancel_calls = Arc::new(AtomicUsize::new(0));
    (
        SpeedCoordinator::new(FixtureTraffic {
            finish_calls: Arc::clone(&finish_calls),
            cancel_calls: Arc::clone(&cancel_calls),
            finish_release: Arc::new(Notify::new()),
            decision: decision(),
        }),
        finish_calls,
        cancel_calls,
    )
}

fn blocking_traffic(begin_pending: bool) -> BlockingLifecycleTraffic {
    BlockingLifecycleTraffic {
        begin_started: Arc::new(Notify::new()),
        begin_release: Arc::new(Notify::new()),
        begin_pending,
        cancel_started: Arc::new(AtomicUsize::new(0)),
        cancel_release: Arc::new(Notify::new()),
        decision: decision(),
    }
}

fn valid_samples() -> Vec<SpeedSample> {
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

fn valid_metrics() -> SpeedMetrics {
    SpeedMetrics {
        download_bps: 80_000_000.0,
        upload_bps: 40_000_000.0,
        unloaded_latency_ms: 20.0,
        unloaded_jitter_ms: 2.0,
        download_loaded_latency_ms: None,
        upload_loaded_latency_ms: None,
    }
}

#[test]
fn quick_and_full_plans_stay_within_payload_budgets_and_match_cloudflare_shape() {
    let quick = plan_for(SpeedMode::Quick);
    let full = plan_for(SpeedMode::Full);

    assert_eq!(quick.planned_bytes(), 29_400_000);
    assert_eq!(full.planned_bytes(), 171_600_000);
    assert!(quick.planned_bytes() <= 40_000_000);
    assert!(full.planned_bytes() <= 200_000_000);
    assert!(!quick.contains_packet_loss());
    assert!(!full.contains_packet_loss());
    assert!(!quick.include_loaded_latency);
    assert!(full.include_loaded_latency);
    assert_eq!(quick.deadline_ms, 15_000);
    assert_eq!(full.deadline_ms, 40_000);
    assert_eq!(
        serde_json::to_value(&quick.measurements).unwrap(),
        json!([
            {"type":"latency","numPackets":10},
            {"type":"download","bytes":100000,"count":2},
            {"type":"download","bytes":1000000,"count":2},
            {"type":"download","bytes":5000000,"count":3},
            {"type":"upload","bytes":100000,"count":2},
            {"type":"upload","bytes":1000000,"count":2},
            {"type":"upload","bytes":5000000,"count":2}
        ])
    );
}

#[tokio::test]
async fn completion_combines_validated_metrics_with_speed_path() {
    let (coordinator, finish_calls, _) = coordinator();
    let session = coordinator.start(SpeedMode::Quick).await.unwrap();
    coordinator
        .record_samples(session.id, valid_samples())
        .await
        .unwrap();
    let result = coordinator
        .complete(session.id, valid_metrics())
        .await
        .unwrap();

    assert_eq!(result.provider, "cloudflare");
    assert_eq!(result.mode, SpeedMode::Quick);
    assert_eq!(result.traffic_decision.kind, TrafficDecisionKind::Proxy);
    assert_eq!(result.used_bytes, 200_000);
    assert_eq!(finish_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn batch_receipts_are_idempotent_terminal_and_collision_safe() {
    let (coordinator, _, _) = coordinator();
    let session = coordinator.start(SpeedMode::Quick).await.unwrap();
    let batch_id = Uuid::new_v4();
    let samples = valid_samples();

    coordinator
        .record_samples_with_batch(session.id, batch_id, samples.clone())
        .await
        .unwrap();
    let first = coordinator.snapshot(session.id).unwrap();

    coordinator
        .record_samples_with_bytes_and_batch(session.id, batch_id, samples.clone(), 200_000)
        .await
        .unwrap();
    assert_eq!(
        coordinator.snapshot(session.id).unwrap().used_bytes,
        first.used_bytes
    );
    assert_eq!(
        coordinator.snapshot(session.id).unwrap().sample_count,
        first.sample_count
    );

    let mut changed = samples.clone();
    changed[1].bps = Some(81_000_000.0);
    assert_eq!(
        coordinator
            .record_samples_with_bytes_and_batch(session.id, batch_id, changed, 200_000)
            .await,
        Err(SpeedError::InvalidSamples)
    );

    coordinator
        .complete(session.id, valid_metrics())
        .await
        .unwrap();
    assert_eq!(
        coordinator
            .record_samples_with_bytes_and_batch(session.id, batch_id, samples, 200_000)
            .await,
        Ok(())
    );
}

#[tokio::test]
async fn distinct_stale_batches_cannot_both_credit_the_same_delta() {
    let (coordinator, _, _) = coordinator();
    let session = coordinator.start(SpeedMode::Quick).await.unwrap();
    let first_batch = Uuid::new_v4();
    let second_batch = Uuid::new_v4();
    let samples = valid_samples();

    coordinator
        .record_samples_with_bytes_and_batch(session.id, first_batch, samples.clone(), 200_000)
        .await
        .unwrap();
    assert_eq!(
        coordinator
            .record_samples_with_bytes_and_batch(session.id, second_batch, samples, 200_000)
            .await,
        Err(SpeedError::InvalidSamples)
    );
    let snapshot = coordinator.snapshot(session.id).unwrap();
    assert_eq!(snapshot.used_bytes, 200_000);
    assert_eq!(snapshot.sample_count, 3);
}

#[tokio::test]
async fn speed_jobs_use_browser_correlation_and_a_deadline_aware_observation_lifetime() {
    let observations = Arc::new(StdMutex::new(Vec::new()));
    let provider = DurationRecordingTraffic {
        inner: FixtureTraffic {
            finish_calls: Arc::new(AtomicUsize::new(0)),
            cancel_calls: Arc::new(AtomicUsize::new(0)),
            finish_release: Arc::new(Notify::new()),
            decision: decision(),
        },
        observations: Arc::clone(&observations),
    };
    let coordinator = SpeedCoordinator::new(provider);

    coordinator.start(SpeedMode::Quick).await.unwrap();
    coordinator.start(SpeedMode::Full).await.unwrap();

    let observations = observations.lock().unwrap().clone();
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].0, Duration::from_secs(17));
    assert_eq!(observations[1].0, Duration::from_secs(42));
    assert!(
        observations
            .iter()
            .all(|(_, correlation)| *correlation == TrafficProbeCorrelation::Browser)
    );
    coordinator.shutdown().await;
}

#[tokio::test]
async fn invalid_samples_are_rejected_without_mutating_the_session() {
    let (coordinator, _, _) = coordinator();
    let session = coordinator.start(SpeedMode::Quick).await.unwrap();
    let mut invalid = valid_samples();
    invalid[1].bps = Some(f64::NAN);

    assert_eq!(
        coordinator.record_samples(session.id, invalid).await,
        Err(SpeedError::InvalidSamples)
    );
    assert!(
        coordinator
            .complete(session.id, valid_metrics())
            .await
            .is_err()
    );
    assert_eq!(
        coordinator.snapshot(session.id).unwrap().status.as_str(),
        "running"
    );
}

#[tokio::test]
async fn sample_multiset_and_byte_budget_are_enforced() {
    let (coordinator, _, _) = coordinator();
    let session = coordinator.start(SpeedMode::Quick).await.unwrap();

    let mut wrong_size = valid_samples();
    wrong_size[1].bytes = 123;
    assert_eq!(
        coordinator.record_samples(session.id, wrong_size).await,
        Err(SpeedError::InvalidSamples)
    );

    let too_large = vec![SpeedSample {
        kind: SpeedSampleKind::Download,
        bytes: 100_000,
        bps: Some(1.0),
        duration_ms: 1.0,
        latency_ms: None,
    }];
    assert_eq!(
        coordinator
            .record_samples_with_bytes(session.id, too_large, 40_000_001)
            .await,
        Err(SpeedError::ByteBudgetExceeded)
    );

    let repeated = vec![SpeedSample {
        kind: SpeedSampleKind::Download,
        bytes: 100_000,
        bps: Some(1.0),
        duration_ms: 1.0,
        latency_ms: None,
    }];
    assert_eq!(
        coordinator.record_samples(session.id, repeated).await,
        Ok(())
    );
    assert_eq!(
        coordinator
            .record_samples(
                session.id,
                vec![SpeedSample {
                    kind: SpeedSampleKind::Download,
                    bytes: 100_000,
                    bps: Some(1.0),
                    duration_ms: 1.0,
                    latency_ms: None,
                }]
            )
            .await,
        Ok(())
    );
    assert_eq!(
        coordinator
            .record_samples(
                session.id,
                vec![SpeedSample {
                    kind: SpeedSampleKind::Download,
                    bytes: 100_000,
                    bps: Some(1.0),
                    duration_ms: 1.0,
                    latency_ms: None,
                }]
            )
            .await,
        Err(SpeedError::InvalidSamples)
    );
}

#[tokio::test]
async fn invalid_metrics_cover_negative_infinite_and_extreme_values() {
    for value in [-1.0, f64::NAN, f64::INFINITY, 100_000_000_001.0] {
        let (coordinator, _, _) = coordinator();
        let session = coordinator.start(SpeedMode::Quick).await.unwrap();
        coordinator
            .record_samples(session.id, valid_samples())
            .await
            .unwrap();
        let mut metrics = valid_metrics();
        metrics.download_bps = value;
        assert_eq!(
            coordinator.complete(session.id, metrics).await,
            Err(SpeedError::InvalidMetrics)
        );
    }
}

#[tokio::test]
async fn wrong_id_double_completion_and_late_writes_are_deterministic() {
    let (coordinator, _, _) = coordinator();
    let session = coordinator.start(SpeedMode::Quick).await.unwrap();
    assert_eq!(
        coordinator
            .record_samples(Uuid::new_v4(), valid_samples())
            .await,
        Err(SpeedError::NotFound)
    );
    coordinator
        .record_samples(session.id, valid_samples())
        .await
        .unwrap();
    coordinator
        .complete(session.id, valid_metrics())
        .await
        .unwrap();
    assert_eq!(
        coordinator.complete(session.id, valid_metrics()).await,
        Err(SpeedError::AlreadyFinished)
    );
    assert_eq!(
        coordinator
            .record_samples(session.id, valid_samples())
            .await,
        Err(SpeedError::AlreadyFinished)
    );
}

#[tokio::test]
async fn cancel_ends_observation_without_a_result() {
    let (coordinator, finish_calls, cancel_calls) = coordinator();
    let session = coordinator.start(SpeedMode::Quick).await.unwrap();
    coordinator.cancel(session.id).await.unwrap();

    let snapshot = coordinator.snapshot(session.id).unwrap();
    assert_eq!(snapshot.status.as_str(), "cancelled");
    assert!(snapshot.result.is_none());
    assert_eq!(finish_calls.load(Ordering::SeqCst), 0);
    assert_eq!(cancel_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        coordinator.cancel(session.id).await,
        Err(SpeedError::AlreadyFinished)
    );
}

#[tokio::test]
async fn blocked_cleanup_keeps_all_ten_job_permits_and_terminal_retention_pending() {
    let provider = blocking_traffic(false);
    let cancel_started = Arc::clone(&provider.cancel_started);
    let cancel_release = Arc::clone(&provider.cancel_release);
    let coordinator = Arc::new(SpeedCoordinator::new(provider));
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
    .expect("all provider cleanup calls must be blocked");

    assert_eq!(
        coordinator.start(SpeedMode::Quick).await,
        Err(SpeedError::TooMany)
    );
    assert!(
        coordinator.snapshot(sessions[0].id).is_some_and(
            |snapshot| snapshot.status == network_path_agent::speed::SpeedStatus::Running
        )
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
    assert!(coordinator.snapshot(sessions[0].id).is_some_and(
        |snapshot| snapshot.status == network_path_agent::speed::SpeedStatus::Cancelled
    ));
}

#[tokio::test]
async fn shutdown_tracks_a_pending_begin_until_the_observation_can_be_cleaned_up() {
    let provider = blocking_traffic(true);
    let begin_started = Arc::clone(&provider.begin_started);
    let begin_release = Arc::clone(&provider.begin_release);
    let cancel_started = Arc::clone(&provider.cancel_started);
    let cancel_release = Arc::clone(&provider.cancel_release);
    let coordinator = Arc::new(SpeedCoordinator::new(provider));
    let start = {
        let coordinator = Arc::clone(&coordinator);
        tokio::spawn(async move { coordinator.start(SpeedMode::Quick).await })
    };
    begin_started.notified().await;

    let shutdown = {
        let coordinator = Arc::clone(&coordinator);
        tokio::spawn(async move { coordinator.shutdown().await })
    };
    tokio::task::yield_now().await;
    assert!(!shutdown.is_finished());
    assert!(!start.is_finished());

    begin_release.notify_waiters();
    tokio::time::timeout(Duration::from_secs(1), async {
        while cancel_started.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a begin that completes after shutdown must be cancelled");
    cancel_release.notify_waiters();

    assert_eq!(start.await.unwrap(), Err(SpeedError::ShuttingDown));
    shutdown.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn deadline_transitions_running_test_to_timeout_and_cancels_observation() {
    let (coordinator, finish_calls, cancel_calls) = coordinator();
    let session = coordinator.start(SpeedMode::Quick).await.unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_secs(15)).await;
    tokio::task::yield_now().await;

    let snapshot = coordinator.snapshot(session.id).unwrap();
    assert_eq!(snapshot.status.as_str(), "failed");
    assert_eq!(snapshot.error.unwrap().code, "speed_timeout");
    assert!(snapshot.result.is_none());
    assert_eq!(finish_calls.load(Ordering::SeqCst), 0);
    assert_eq!(cancel_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn shutdown_closes_admission_and_drains_speed_workers() {
    let (coordinator, _, cancel_calls) = coordinator();
    let session = coordinator.start(SpeedMode::Quick).await.unwrap();
    coordinator.shutdown().await;

    assert!(cancel_calls.load(Ordering::SeqCst) >= 1);
    assert_eq!(
        coordinator.start(SpeedMode::Quick).await,
        Err(SpeedError::ShuttingDown)
    );
    assert_eq!(
        coordinator.snapshot(session.id).unwrap().status.as_str(),
        "cancelled"
    );
}

#[tokio::test]
async fn ten_running_speed_tests_fill_the_capacity_and_terminal_retention_expires() {
    let (first, _, _) = coordinator();
    let mut sessions = Vec::new();
    for _ in 0..10 {
        sessions.push(first.start(SpeedMode::Quick).await.unwrap());
    }
    assert_eq!(
        first.start(SpeedMode::Quick).await,
        Err(SpeedError::TooMany)
    );
    for session in sessions {
        first.cancel(session.id).await.unwrap();
    }

    let second = FixtureTraffic {
        finish_calls: Arc::new(AtomicUsize::new(0)),
        cancel_calls: Arc::new(AtomicUsize::new(0)),
        finish_release: Arc::new(Notify::new()),
        decision: decision(),
    };
    let coordinator =
        SpeedCoordinator::with_retention(second, std::time::Duration::from_millis(10));
    let session = coordinator.start(SpeedMode::Quick).await.unwrap();
    coordinator.cancel(session.id).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    assert_eq!(coordinator.store().count(), 0);
    assert!(coordinator.snapshot(session.id).is_none());
}

#[tokio::test]
async fn full_mode_requires_both_loaded_latency_metrics() {
    let (coordinator, _, _) = coordinator();
    let session = coordinator.start(SpeedMode::Full).await.unwrap();
    coordinator
        .record_samples(session.id, valid_samples())
        .await
        .unwrap();

    assert_eq!(
        coordinator.complete(session.id, valid_metrics()).await,
        Err(SpeedError::InvalidMetrics)
    );
    let mut partial = valid_metrics();
    partial.download_loaded_latency_ms = Some(35.0);
    assert_eq!(
        coordinator.complete(session.id, partial).await,
        Err(SpeedError::InvalidMetrics)
    );
    let mut complete = valid_metrics();
    complete.download_loaded_latency_ms = Some(35.0);
    complete.upload_loaded_latency_ms = Some(45.0);
    assert!(coordinator.complete(session.id, complete).await.is_ok());
}

#[tokio::test]
async fn quick_mode_rejects_unscheduled_loaded_latency_metrics() {
    let (coordinator, _, _) = coordinator();
    let session = coordinator.start(SpeedMode::Quick).await.unwrap();
    coordinator
        .record_samples(session.id, valid_samples())
        .await
        .unwrap();
    let mut metrics = valid_metrics();
    metrics.download_loaded_latency_ms = Some(35.0);
    metrics.upload_loaded_latency_ms = Some(45.0);

    assert_eq!(
        coordinator.complete(session.id, metrics).await,
        Err(SpeedError::InvalidMetrics)
    );
    assert_eq!(
        coordinator.snapshot(session.id).unwrap().status,
        network_path_agent::speed::SpeedStatus::Running
    );
}

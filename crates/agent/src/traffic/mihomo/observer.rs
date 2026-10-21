use super::{MihomoEvent, MihomoEventStream, MihomoProxy, MihomoTransport};
use crate::{
    domain::{
        Evidence, EvidenceLevel, MihomoRuntime, TrafficDecision, TrafficDecisionKind, TrafficNode,
        TrafficNodeKind, TrafficRule,
    },
    error::DiagnosticError,
    ports::{
        TrafficDecisionProvider, TrafficObservationId, TrafficProbeCorrelation, TrafficProbeTarget,
    },
};
use async_trait::async_trait;
use futures_util::StreamExt;
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use time::{Duration as TimeDuration, OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::{Mutex, Notify};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use uuid::Uuid;

pub(super) const OBSERVATION_DEADLINE: Duration = Duration::from_secs(5);
const CONNECTION_INTERVAL: Duration = Duration::from_millis(100);
const MAX_EVENTS_PER_SESSION: usize = 128;
const MAX_BROWSER_UNIQUE_OBSERVATIONS: usize = 128;
const MAX_CHAIN_NODES: usize = 32;

#[derive(Clone)]
pub struct MihomoTrafficDecisionProvider {
    transport: Arc<dyn MihomoTransport>,
    sessions: Arc<Mutex<HashMap<TrafficObservationId, Arc<ObservationSession>>>>,
    #[cfg(test)]
    finish_wait_hook: Option<Arc<FinishWaitHook>>,
}

#[cfg(test)]
struct FinishWaitHook {
    after_check: Arc<tokio::sync::Barrier>,
    resume_wait: Arc<tokio::sync::Barrier>,
    cleanup_reached: Option<Arc<tokio::sync::Barrier>>,
}

struct ObservationSession {
    target: TrafficProbeTarget,
    started_wall: OffsetDateTime,
    deadline: Instant,
    deadline_wall: OffsetDateTime,
    cancel: CancellationToken,
    runtime: MihomoRuntime,
    proxies: HashMap<String, MihomoProxy>,
    notify: Arc<Notify>,
    state: Mutex<ObservationState>,
    finish_started: AtomicBool,
    tasks: TaskTracker,
}

struct ObservationState {
    events: Vec<MihomoEvent>,
    browser: BrowserObservationState,
    open_streams: usize,
}

#[derive(Default)]
struct BrowserObservationState {
    observations: Vec<BrowserTerminalObservation>,
    overflow: bool,
}

struct BrowserTerminalObservation {
    evidence: BrowserTerminalEvidence,
}

enum BrowserTerminalEvidence {
    Connection {
        id: String,
        connection: Option<ObservedConnection>,
        fingerprint: Option<BrowserTerminalFingerprint>,
        conflict: bool,
    },
    Reject {
        reject: ObservedReject,
        fingerprint: BrowserTerminalFingerprint,
        occurrences: usize,
    },
}

/// A Browser terminal fingerprint intentionally contains only normalized route data. It is
/// compared before presentation decisions are rendered, so source/evidence provenance never
/// changes whether two terminal observations agree.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BrowserTerminalFingerprint {
    decision: TrafficDecisionKind,
    terminal_action: Option<String>,
    rule_identity: Option<String>,
    rule_payload: Option<String>,
    chain_identity: Option<BrowserChainIdentity>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BrowserFingerprintConflict;

#[derive(Clone, Debug, PartialEq, Eq)]
struct BrowserChainIdentity {
    connection: Vec<String>,
    provider: Vec<String>,
    dialer: Vec<String>,
}

impl MihomoTrafficDecisionProvider {
    pub fn new(transport: Arc<dyn MihomoTransport>) -> Self {
        Self {
            transport,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(test)]
            finish_wait_hook: None,
        }
    }

    #[cfg(test)]
    pub(super) async fn active_observation_count(&self) -> usize {
        self.sessions.lock().await.len()
    }
}

#[async_trait]
impl TrafficDecisionProvider for MihomoTrafficDecisionProvider {
    async fn runtime(&self) -> MihomoRuntime {
        self.transport
            .runtime()
            .await
            .unwrap_or_else(|_| unavailable_runtime())
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
        let started_at = Instant::now();
        let started_wall = OffsetDateTime::now_utc();
        let deadline = started_at + lifetime;
        let deadline_wall = started_wall + wall_duration(lifetime);
        let (connection_stream, log_stream) = tokio::try_join!(
            self.transport.connection_stream(CONNECTION_INTERVAL),
            self.transport.log_stream()
        )
        .map_err(|_| observation_error())?;
        let runtime = self
            .transport
            .runtime()
            .await
            .unwrap_or_else(|_| unavailable_runtime());
        let proxies = self.transport.proxies().await.unwrap_or_default();
        let id = TrafficObservationId(Uuid::new_v4());
        let notify = Arc::new(Notify::new());
        let cancel = CancellationToken::new();
        let session = Arc::new(ObservationSession {
            target: target.clone(),
            started_wall,
            deadline,
            deadline_wall,
            cancel: cancel.clone(),
            runtime,
            proxies,
            notify: Arc::clone(&notify),
            state: Mutex::new(ObservationState {
                events: Vec::new(),
                browser: BrowserObservationState::default(),
                open_streams: 2,
            }),
            finish_started: AtomicBool::new(false),
            tasks: TaskTracker::new(),
        });
        self.sessions.lock().await.insert(id, Arc::clone(&session));

        session
            .tasks
            .spawn(collect_stream(Arc::clone(&session), connection_stream));
        session
            .tasks
            .spawn(collect_stream(Arc::clone(&session), log_stream));
        session.tasks.spawn(expire_session(
            Arc::clone(&self.sessions),
            id,
            Arc::clone(&session),
        ));
        Ok(id)
    }

    async fn finish(&self, id: TrafficObservationId) -> Result<TrafficDecision, DiagnosticError> {
        let session = {
            let sessions = self.sessions.lock().await;
            let Some(session) = sessions.get(&id) else {
                return Ok(unknown_decision("observation session unavailable"));
            };
            if session.finish_started.swap(true, Ordering::AcqRel) {
                return Ok(unknown_decision("observation session unavailable"));
            }
            Arc::clone(session)
        };
        let mut cleanup_guard = ObservationCleanupGuard {
            session: Arc::clone(&session),
            active: true,
        };
        loop {
            let notified = session.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let ready = {
                let state = session.state.lock().await;
                !state.events.is_empty()
                    || !state.browser.observations.is_empty()
                    || state.browser.overflow
                    || state.open_streams == 0
            };
            let deadline = session.deadline;
            if ready || Instant::now() >= deadline {
                break;
            }
            #[cfg(test)]
            if let Some(hook) = &self.finish_wait_hook {
                hook.after_check.wait().await;
                hook.resume_wait.wait().await;
            }
            tokio::select! {
                _ = &mut notified => {}
                _ = tokio::time::sleep_until(deadline.into()) => break,
            }
        }

        #[cfg(test)]
        if let Some(cleanup_reached) = self
            .finish_wait_hook
            .as_ref()
            .and_then(|hook| hook.cleanup_reached.as_ref())
        {
            cleanup_reached.wait().await;
        }
        stop_and_wait(&session).await;
        self.sessions.lock().await.remove(&id);
        let (events, browser) = {
            let mut state = session.state.lock().await;
            (
                std::mem::take(&mut state.events),
                std::mem::take(&mut state.browser),
            )
        };
        cleanup_guard.active = false;
        Ok(decision_from_session(&session, events, browser))
    }

    async fn cancel(&self, id: TrafficObservationId) {
        let session = {
            let mut sessions = self.sessions.lock().await;
            sessions.remove(&id)
        };
        if let Some(session) = session {
            stop_and_wait(&session).await;
        }
    }
}

struct ObservationCleanupGuard {
    session: Arc<ObservationSession>,
    active: bool,
}

impl Drop for ObservationCleanupGuard {
    fn drop(&mut self) {
        if self.active {
            self.session.cancel.cancel();
        }
    }
}

async fn stop_and_wait(session: &Arc<ObservationSession>) {
    session.cancel.cancel();
    wait_for_streams(session).await;
    session.tasks.close();
    session.tasks.wait().await;
}

async fn wait_for_streams(session: &Arc<ObservationSession>) {
    loop {
        let notified = session.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let done = session.state.lock().await.open_streams == 0;
        if done {
            return;
        }
        notified.await;
    }
}

async fn expire_session(
    sessions: Arc<Mutex<HashMap<TrafficObservationId, Arc<ObservationSession>>>>,
    id: TrafficObservationId,
    session: Arc<ObservationSession>,
) {
    tokio::select! {
        _ = session.cancel.cancelled() => {}
        _ = tokio::time::sleep_until(session.deadline.into()) => session.cancel.cancel(),
    }
    wait_for_streams(&session).await;
    sessions.lock().await.remove(&id);
}

async fn collect_stream(session: Arc<ObservationSession>, mut stream: MihomoEventStream) {
    loop {
        let item = tokio::select! {
            _ = session.cancel.cancelled() => break,
            item = stream.next() => item,
        };
        let Some(item) = item else {
            break;
        };
        let Ok(event) = item else {
            break;
        };
        if Instant::now() > session.deadline {
            break;
        }
        if let Some(event) = matching_event(
            event,
            &session.target,
            session.started_wall,
            session.deadline_wall,
        ) {
            let mut state = session.state.lock().await;
            if session.target.correlation == TrafficProbeCorrelation::Browser {
                record_browser_event(&mut state.browser, event, &session.proxies);
            } else if state.events.len() < MAX_EVENTS_PER_SESSION {
                state.events.push(event);
            }
            drop(state);
            session.notify.notify_waiters();
        }
    }

    let mut state = session.state.lock().await;
    state.open_streams = state.open_streams.saturating_sub(1);
    drop(state);
    session.notify.notify_waiters();
}

fn record_browser_event(
    state: &mut BrowserObservationState,
    event: MihomoEvent,
    proxies: &HashMap<String, MihomoProxy>,
) {
    match event {
        MihomoEvent::Connection(snapshot) => {
            for value in snapshot.connections {
                let Ok(connection) = serde_json::from_value::<ObservedConnection>(value) else {
                    continue;
                };
                if connection.id.is_empty() {
                    continue;
                }
                record_browser_connection(state, connection, proxies);
            }
        }
        MihomoEvent::Log(log) => {
            let Some(reject) = parse_reject_log(&log.payload) else {
                return;
            };
            let fingerprint = browser_fingerprint_from_reject(&reject);
            for observation in &mut state.observations {
                let BrowserTerminalEvidence::Reject {
                    fingerprint: existing,
                    occurrences,
                    ..
                } = &mut observation.evidence
                else {
                    continue;
                };
                let Ok(merged) = merge_browser_fingerprints(existing, &fingerprint) else {
                    continue;
                };
                *existing = merged;
                *occurrences = occurrences.saturating_add(1);
                return;
            }
            if state.observations.len() >= MAX_BROWSER_UNIQUE_OBSERVATIONS {
                state.overflow = true;
                return;
            }
            state.observations.push(BrowserTerminalObservation {
                evidence: BrowserTerminalEvidence::Reject {
                    reject,
                    fingerprint,
                    occurrences: 1,
                },
            });
        }
    }
}

fn record_browser_connection(
    state: &mut BrowserObservationState,
    connection: ObservedConnection,
    proxies: &HashMap<String, MihomoProxy>,
) {
    let id = connection.id.clone();
    let fingerprint = browser_fingerprint_from_connection(&connection, proxies);
    if let Some(observation) = state.observations.iter_mut().find(|observation| {
        matches!(
            &observation.evidence,
            BrowserTerminalEvidence::Connection { id: existing, .. } if existing == &id
        )
    }) {
        let BrowserTerminalEvidence::Connection {
            connection: existing_connection,
            fingerprint: existing_fingerprint,
            conflict,
            ..
        } = &mut observation.evidence
        else {
            unreachable!("the matching Browser observation must be a connection");
        };
        match (existing_fingerprint.as_ref(), fingerprint.as_ref()) {
            (None, Some(_)) => {
                *existing_connection = Some(connection);
                *existing_fingerprint = fingerprint;
            }
            (Some(existing), Some(current)) => {
                match merge_browser_fingerprints(existing, current) {
                    Ok(merged) => *existing_fingerprint = Some(merged),
                    Err(BrowserFingerprintConflict) => *conflict = true,
                }
            }
            (Some(_), None) | (None, None) => {}
        }
        return;
    }

    if state.observations.len() >= MAX_BROWSER_UNIQUE_OBSERVATIONS {
        state.overflow = true;
        return;
    }
    state.observations.push(BrowserTerminalObservation {
        evidence: BrowserTerminalEvidence::Connection {
            id,
            connection: Some(connection),
            fingerprint,
            conflict: false,
        },
    });
}

fn browser_fingerprint_from_connection(
    connection: &ObservedConnection,
    proxies: &HashMap<String, MihomoProxy>,
) -> Option<BrowserTerminalFingerprint> {
    let leaf = connection.chains.first()?.trim();
    if leaf.is_empty() {
        return None;
    }
    let decision = browser_decision_kind(leaf, Some(proxies));
    let chain_identity = Some(BrowserChainIdentity {
        connection: normalize_chain_parts(&connection.chains, proxies)?,
        provider: normalize_chain_parts(&connection.provider_chains, proxies)?,
        dialer: normalize_chain_parts(&connection.dialer_proxy, proxies)?,
    });
    let rule_identity = normalize_rule_identity(&connection.rule);
    Some(BrowserTerminalFingerprint {
        decision,
        terminal_action: (decision == TrafficDecisionKind::Reject)
            .then(|| normalize_terminal_action(leaf)),
        rule_payload: rule_identity
            .as_ref()
            .and_then(|_| normalize_optional_payload(&connection.rule_payload)),
        rule_identity,
        chain_identity,
    })
}

fn browser_fingerprint_from_reject(reject: &ObservedReject) -> BrowserTerminalFingerprint {
    BrowserTerminalFingerprint {
        decision: TrafficDecisionKind::Reject,
        terminal_action: Some(normalize_terminal_action(&reject.terminal)),
        rule_identity: normalize_rule_identity(&reject.rule),
        rule_payload: reject
            .payload
            .as_deref()
            .and_then(normalize_optional_payload),
        chain_identity: None,
    }
}

fn browser_decision_kind(
    leaf: &str,
    proxies: Option<&HashMap<String, MihomoProxy>>,
) -> TrafficDecisionKind {
    if proxies.is_some_and(|proxies| proxies.contains_key(leaf.trim())) {
        return TrafficDecisionKind::Proxy;
    }
    match leaf.trim().to_ascii_uppercase().as_str() {
        "DIRECT" => TrafficDecisionKind::Direct,
        "REJECT" | "REJECT-DROP" => TrafficDecisionKind::Reject,
        _ => TrafficDecisionKind::Proxy,
    }
}

fn normalize_chain_parts(
    values: &[String],
    proxies: &HashMap<String, MihomoProxy>,
) -> Option<Vec<String>> {
    if values.iter().any(|value| value.trim().is_empty()) {
        return None;
    }
    Some(
        values
            .iter()
            .map(|value| normalize_chain_identity(value, proxies))
            .collect(),
    )
}

fn normalize_rule_identity(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Some(normalize_rule_type(value))
}

fn normalize_optional_payload(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn normalize_chain_identity(value: &str, proxies: &HashMap<String, MihomoProxy>) -> String {
    let value = value.trim();
    if proxies.contains_key(value) {
        value.to_owned()
    } else {
        normalize_reserved_or_user_identity(value, is_reserved_chain_token)
    }
}

fn normalize_rule_type(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

fn normalize_terminal_action(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

fn normalize_reserved_or_user_identity(value: &str, is_reserved: fn(&str) -> bool) -> String {
    if is_reserved(value) {
        value.to_ascii_uppercase()
    } else {
        value.to_owned()
    }
}

fn is_reserved_chain_token(value: &str) -> bool {
    matches!(
        value.to_ascii_uppercase().as_str(),
        "DIRECT" | "REJECT" | "REJECT-DROP" | "MATCH" | "PROXY" | "GLOBAL"
    )
}

fn wall_duration(duration: Duration) -> TimeDuration {
    let seconds = i64::try_from(duration.as_secs()).unwrap_or(i64::MAX);
    if seconds == i64::MAX {
        TimeDuration::seconds(seconds)
    } else {
        TimeDuration::seconds(seconds)
            + TimeDuration::nanoseconds(i64::from(duration.subsec_nanos()))
    }
}

fn matching_event(
    event: MihomoEvent,
    target: &TrafficProbeTarget,
    started_wall: OffsetDateTime,
    deadline_wall: OffsetDateTime,
) -> Option<MihomoEvent> {
    match event {
        MihomoEvent::Connection(mut snapshot) => {
            snapshot.connections.retain(|value| {
                connection_matches_target(value, target)
                    && connection_started_within_window(value, started_wall, deadline_wall)
            });
            (!snapshot.connections.is_empty()).then_some(MihomoEvent::Connection(snapshot))
        }
        MihomoEvent::Log(log) => parse_reject_log(&log.payload)
            .filter(|reject| reject_matches_target(reject, target))
            .map(|_| MihomoEvent::Log(log)),
    }
}

fn connection_started_within_window(
    value: &serde_json::Value,
    started_wall: OffsetDateTime,
    deadline_wall: OffsetDateTime,
) -> bool {
    value
        .get("start")
        .and_then(serde_json::Value::as_str)
        .and_then(|start| OffsetDateTime::parse(start, &Rfc3339).ok())
        .is_some_and(|start| start >= started_wall && start <= deadline_wall)
}

fn connection_matches_target(value: &serde_json::Value, target: &TrafficProbeTarget) -> bool {
    let Some(metadata) = value.get("metadata") else {
        return false;
    };
    let port_matches = metadata
        .get("destinationPort")
        .and_then(json_port)
        .is_some_and(|port| port == target.port);
    let host_matches = metadata
        .get("host")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|host| host.eq_ignore_ascii_case(&target.host));
    let ip_matches = metadata
        .get("destinationIP")
        .and_then(serde_json::Value::as_str)
        .and_then(|ip| ip.parse::<IpAddr>().ok())
        .is_some_and(|ip| target.resolved_ips.contains(&ip));
    port_matches && (host_matches || ip_matches)
}

fn json_port(value: &serde_json::Value) -> Option<u16> {
    value
        .as_str()
        .and_then(|port| port.parse().ok())
        .or_else(|| value.as_u64().and_then(|port| u16::try_from(port).ok()))
}

fn decision_from_session(
    session: &ObservationSession,
    events: Vec<MihomoEvent>,
    browser: BrowserObservationState,
) -> TrafficDecision {
    if session.target.correlation == TrafficProbeCorrelation::Browser {
        return decision_from_browser_observations(session, browser);
    }
    let mut connections_by_id = HashMap::new();
    for value in events
        .iter()
        .filter_map(|event| match event {
            MihomoEvent::Connection(snapshot) => Some(snapshot.connections.iter()),
            MihomoEvent::Log(_) => None,
        })
        .flatten()
    {
        let Ok(connection) = serde_json::from_value::<ObservedConnection>(value.clone()) else {
            continue;
        };
        if connection.id.is_empty() {
            continue;
        }
        connections_by_id.insert(
            connection.id.clone(),
            (candidate_score(value, &session.target), connection),
        );
    }
    let mut connections = connections_by_id.into_values().collect::<Vec<_>>();
    let highest_score = connections.iter().map(|(score, _)| *score).max();
    let highest_count = highest_score.map_or(0, |highest| {
        connections
            .iter()
            .filter(|(score, _)| *score == highest)
            .count()
    });
    if highest_count > 1 {
        return TrafficDecision {
            mode: session.runtime.mode.clone(),
            tun_enabled: session.runtime.tun_enabled,
            ..unknown_decision(&format!(
                "{highest_count} highest-scoring Mihomo candidates were ambiguous"
            ))
        };
    }
    let Some((_, connection)) = highest_score.and_then(|highest| {
        let index = connections
            .iter()
            .position(|(score, _)| *score == highest)?;
        Some(connections.swap_remove(index))
    }) else {
        if let Some(decision) = decision_from_reject_logs(session, &events) {
            return decision;
        }
        return decision_from_configuration(session);
    };

    decision_from_connection(session, connection, None)
}

fn decision_from_browser_observations(
    session: &ObservationSession,
    browser: BrowserObservationState,
) -> TrafficDecision {
    if browser.overflow
        || browser.observations.iter().any(|observation| {
            matches!(
                &observation.evidence,
                BrowserTerminalEvidence::Connection {
                    fingerprint: None,
                    ..
                }
            ) || matches!(
                &observation.evidence,
                BrowserTerminalEvidence::Connection { conflict: true, .. }
            )
        })
    {
        return TrafficDecision {
            mode: session.runtime.mode.clone(),
            tun_enabled: session.runtime.tun_enabled,
            ..unknown_decision(
                "browser Cloudflare terminal observations were incomplete or exceeded the evidence bound",
            )
        };
    }

    let mut connections = Vec::new();
    let mut rejects = Vec::new();
    for observation in &browser.observations {
        match &observation.evidence {
            BrowserTerminalEvidence::Connection {
                connection: Some(connection),
                fingerprint: Some(fingerprint),
                ..
            } => {
                if fingerprint.chain_identity.is_none() {
                    return unknown_browser_decision(session);
                }
                connections.push((connection, fingerprint));
            }
            BrowserTerminalEvidence::Reject {
                reject,
                fingerprint,
                occurrences,
            } => {
                rejects.push((reject, fingerprint, *occurrences));
            }
            BrowserTerminalEvidence::Connection { .. } => {}
        }
    }

    if connections.is_empty() && rejects.is_empty() {
        return decision_from_configuration(session);
    }

    let merged_fingerprint = match merge_browser_observations(&connections, &rejects) {
        Ok(fingerprint) => fingerprint,
        Err(BrowserFingerprintConflict) => return unknown_browser_decision(session),
    };

    let mut result = if let Some((connection, _)) = connections.first() {
        decision_from_connection(
            session,
            canonical_browser_connection_for_render(connection, &merged_fingerprint),
            Some(merged_fingerprint.decision),
        )
    } else {
        let (reject, _, _) = &rejects[0];
        decision_from_reject(
            session,
            canonical_browser_reject_for_render(reject, &merged_fingerprint),
        )
    };
    let agreeing_observations = connections
        .len()
        .saturating_add(rejects.iter().map(|(_, _, count)| *count).sum::<usize>());
    if agreeing_observations >= 2 {
        result.evidence = vec![Evidence {
            level: EvidenceLevel::Confirmed,
            source: "mihomo_observer".into(),
            summary: format!(
                "multiple ({agreeing_observations}) agreeing browser Cloudflare terminal observations confirmed the same decision and chain"
            ),
        }];
    }
    result
}

fn merge_browser_fingerprints(
    left: &BrowserTerminalFingerprint,
    right: &BrowserTerminalFingerprint,
) -> Result<BrowserTerminalFingerprint, BrowserFingerprintConflict> {
    if left.decision != right.decision {
        return Err(BrowserFingerprintConflict);
    }
    Ok(BrowserTerminalFingerprint {
        decision: left.decision,
        terminal_action: merge_optional_evidence(&left.terminal_action, &right.terminal_action)?,
        rule_identity: merge_optional_evidence(&left.rule_identity, &right.rule_identity)?,
        rule_payload: merge_optional_evidence(&left.rule_payload, &right.rule_payload)?,
        chain_identity: merge_optional_evidence(&left.chain_identity, &right.chain_identity)?,
    })
}

fn merge_optional_evidence<T: Clone + Eq>(
    left: &Option<T>,
    right: &Option<T>,
) -> Result<Option<T>, BrowserFingerprintConflict> {
    match (left, right) {
        (None, None) => Ok(None),
        (Some(value), None) | (None, Some(value)) => Ok(Some(value.clone())),
        (Some(left), Some(right)) if left == right => Ok(Some(left.clone())),
        (Some(_), Some(_)) => Err(BrowserFingerprintConflict),
    }
}

fn merge_browser_observations(
    connections: &[(&ObservedConnection, &BrowserTerminalFingerprint)],
    rejects: &[(&ObservedReject, &BrowserTerminalFingerprint, usize)],
) -> Result<BrowserTerminalFingerprint, BrowserFingerprintConflict> {
    let mut merged = None;
    for fingerprint in connections
        .iter()
        .map(|(_, fingerprint)| *fingerprint)
        .chain(rejects.iter().map(|(_, fingerprint, _)| *fingerprint))
    {
        merged = Some(match merged {
            Some(existing) => merge_browser_fingerprints(&existing, fingerprint)?,
            None => fingerprint.clone(),
        });
    }
    merged.ok_or(BrowserFingerprintConflict)
}

fn unknown_browser_decision(session: &ObservationSession) -> TrafficDecision {
    TrafficDecision {
        mode: session.runtime.mode.clone(),
        tun_enabled: session.runtime.tun_enabled,
        ..unknown_decision(
            "browser Cloudflare terminal observations contained conflicting decisions",
        )
    }
}

fn canonical_browser_connection_for_render(
    connection: &ObservedConnection,
    fingerprint: &BrowserTerminalFingerprint,
) -> ObservedConnection {
    let mut rendered = connection.clone();
    if let Some(chain) = &fingerprint.chain_identity {
        rendered.chains = chain.connection.clone();
        rendered.provider_chains = chain.provider.clone();
        rendered.dialer_proxy = chain.dialer.clone();
    }
    rendered.rule = fingerprint.rule_identity.clone().unwrap_or_default();
    rendered.rule_payload = fingerprint.rule_payload.clone().unwrap_or_default();
    if let Some(action) = &fingerprint.terminal_action
        && fingerprint.decision == TrafficDecisionKind::Reject
        && let Some(leaf) = rendered.chains.first_mut()
    {
        *leaf = action.clone();
    }
    rendered
}

fn canonical_browser_reject_for_render(
    reject: &ObservedReject,
    fingerprint: &BrowserTerminalFingerprint,
) -> ObservedReject {
    let mut rendered = reject.clone();
    rendered.rule = fingerprint.rule_identity.clone().unwrap_or_default();
    rendered.payload = fingerprint.rule_payload.clone();
    if let Some(action) = &fingerprint.terminal_action {
        rendered.terminal = action.clone();
    }
    rendered
}

fn decision_from_connection(
    session: &ObservationSession,
    connection: ObservedConnection,
    decision_override: Option<TrafficDecisionKind>,
) -> TrafficDecision {
    let leaf = connection.chains.first().cloned().unwrap_or_default();
    let kind =
        decision_override.unwrap_or_else(|| browser_decision_kind(&leaf, Some(&session.proxies)));
    let mut visited = HashSet::new();
    let mut chain = Vec::new();
    push_node(
        &mut chain,
        &mut visited,
        TrafficNodeKind::TrafficRule,
        &connection.rule,
        Some("rule".into()),
        None,
        (EvidenceLevel::Confirmed, "mihomo_connection"),
    );
    for name in connection
        .chains
        .iter()
        .skip(1)
        .rev()
        .filter(|name| name.as_str() != leaf)
        .filter(|name| !is_chain_sentinel(name, &session.proxies))
    {
        let proxy = session.proxies.get(name);
        let node_kind = proxy
            .map(|proxy| proxy_kind(&proxy.kind))
            .unwrap_or(TrafficNodeKind::ProxyNode);
        push_node(
            &mut chain,
            &mut visited,
            node_kind,
            name,
            proxy.map(|proxy| proxy.kind.clone()),
            proxy,
            (EvidenceLevel::Confirmed, "mihomo_connection"),
        );
    }
    if !leaf.is_empty() && kind != TrafficDecisionKind::Direct {
        let proxy = session.proxies.get(&leaf);
        push_node(
            &mut chain,
            &mut visited,
            if kind == TrafficDecisionKind::Reject {
                TrafficNodeKind::Blocked
            } else {
                proxy
                    .map(|proxy| proxy_kind(&proxy.kind))
                    .unwrap_or(TrafficNodeKind::ProxyNode)
            },
            &leaf,
            proxy
                .map(|proxy| proxy.kind.clone())
                .or_else(|| (kind == TrafficDecisionKind::Reject).then(|| leaf.clone())),
            proxy,
            (EvidenceLevel::Confirmed, "mihomo_connection"),
        );
    }
    for name in connection
        .provider_chains
        .iter()
        .filter(|name| !name.is_empty())
    {
        push_node(
            &mut chain,
            &mut visited,
            TrafficNodeKind::ProxyNode,
            name,
            Some("ProxyProvider".into()),
            None,
            (EvidenceLevel::Confirmed, "mihomo_connection"),
        );
    }
    for name in &connection.dialer_proxy {
        let proxy = session.proxies.get(name);
        push_node(
            &mut chain,
            &mut visited,
            proxy
                .map(|proxy| proxy_kind(&proxy.kind))
                .unwrap_or(TrafficNodeKind::ProxyNode),
            name,
            proxy.map(|proxy| proxy.kind.clone()),
            proxy,
            (EvidenceLevel::Confirmed, "mihomo_connection"),
        );
    }
    if kind == TrafficDecisionKind::Proxy && !leaf.is_empty() {
        let dialer = session
            .proxies
            .get(&leaf)
            .and_then(|proxy| proxy.dialer_proxy.clone());
        append_configured_dialer_path(&mut chain, &mut visited, &session.proxies, dialer);
    }

    let target = connection.chains.last().cloned().unwrap_or_default();
    TrafficDecision {
        kind,
        mode: session.runtime.mode.clone(),
        tun_enabled: session.runtime.tun_enabled,
        rule: nonempty(connection.rule).map(|rule_type| TrafficRule {
            rule_type,
            payload: nonempty(connection.rule_payload),
            target,
            level: EvidenceLevel::Confirmed,
        }),
        chain,
        evidence: vec![Evidence {
            level: EvidenceLevel::Confirmed,
            source: "mihomo_connection".into(),
            summary: "one Mihomo connection matched the observation target".into(),
        }],
    }
}

fn append_configured_dialer_path(
    chain: &mut Vec<TrafficNode>,
    visited: &mut HashSet<String>,
    proxies: &HashMap<String, MihomoProxy>,
    mut current: Option<String>,
) {
    while let Some(name) = current {
        if visited.contains(&name) || chain.len() >= MAX_CHAIN_NODES {
            break;
        }
        let proxy = proxies.get(&name);
        let kind = proxy
            .map(|proxy| proxy_kind(&proxy.kind))
            .unwrap_or(TrafficNodeKind::ProxyNode);
        push_node(
            chain,
            visited,
            kind,
            &name,
            proxy.map(|proxy| proxy.kind.clone()),
            proxy,
            (EvidenceLevel::Inferred, "mihomo_proxy_map"),
        );
        let Some(proxy) = proxy else {
            break;
        };
        if proxy.kind.eq_ignore_ascii_case("LoadBalance") {
            break;
        }
        current = if kind == TrafficNodeKind::PolicyGroup {
            proxy.now.clone()
        } else {
            proxy.dialer_proxy.clone()
        };
    }
}

fn decision_from_configuration(session: &ObservationSession) -> TrafficDecision {
    let mut chain = Vec::new();
    let mut visited = HashSet::new();
    let mut current = session
        .proxies
        .get("GLOBAL")
        .and_then(|global| global.now.clone());
    while let Some(name) = current {
        let Some(proxy) = session.proxies.get(&name) else {
            break;
        };
        let kind = proxy_kind(&proxy.kind);
        push_node(
            &mut chain,
            &mut visited,
            kind,
            &name,
            Some(proxy.kind.clone()),
            Some(proxy),
            (EvidenceLevel::Inferred, "mihomo_proxy_map"),
        );
        if chain.len() >= MAX_CHAIN_NODES
            || proxy.kind.eq_ignore_ascii_case("LoadBalance")
            || kind != TrafficNodeKind::PolicyGroup
        {
            break;
        }
        let Some(next) = proxy.now.clone() else {
            break;
        };
        if visited.contains(&next) {
            break;
        }
        current = Some(next);
    }

    let mut evidence = Vec::new();
    if !chain.is_empty() {
        evidence.push(Evidence {
            level: EvidenceLevel::Inferred,
            source: "mihomo_proxy_map".into(),
            summary: "policy path inferred from current Mihomo configuration".into(),
        });
    }
    evidence.push(Evidence {
        level: EvidenceLevel::Unknown,
        source: "mihomo_observer".into(),
        summary: "no correlated Mihomo event confirmed a terminal decision".into(),
    });
    TrafficDecision {
        kind: TrafficDecisionKind::Unknown,
        mode: session.runtime.mode.clone(),
        tun_enabled: session.runtime.tun_enabled,
        rule: None,
        chain,
        evidence,
    }
}

fn decision_from_reject_logs(
    session: &ObservationSession,
    events: &[MihomoEvent],
) -> Option<TrafficDecision> {
    let rejects = events
        .iter()
        .filter_map(|event| match event {
            MihomoEvent::Log(log) => parse_reject_log(&log.payload),
            MihomoEvent::Connection(_) => None,
        })
        .map(|reject| (reject_score(&reject, &session.target), reject))
        .collect::<Vec<_>>();
    let highest = rejects.iter().map(|(score, _)| *score).max()?;
    let highest_count = rejects
        .iter()
        .filter(|(score, _)| *score == highest)
        .count();
    if highest_count != 1 {
        return Some(TrafficDecision {
            mode: session.runtime.mode.clone(),
            tun_enabled: session.runtime.tun_enabled,
            ..unknown_decision(&format!(
                "{highest_count} highest-scoring Mihomo reject events were ambiguous"
            ))
        });
    }
    let reject = rejects
        .into_iter()
        .find_map(|(score, reject)| (score == highest).then_some(reject))?;
    Some(decision_from_reject(session, reject))
}

fn decision_from_reject(session: &ObservationSession, reject: ObservedReject) -> TrafficDecision {
    let mut chain = Vec::new();
    let mut visited = HashSet::new();
    push_node(
        &mut chain,
        &mut visited,
        TrafficNodeKind::TrafficRule,
        &reject.rule,
        Some("rule".into()),
        None,
        (EvidenceLevel::Confirmed, "mihomo_log"),
    );
    push_node(
        &mut chain,
        &mut visited,
        TrafficNodeKind::Blocked,
        &reject.terminal,
        Some(reject.terminal.clone()),
        None,
        (EvidenceLevel::Confirmed, "mihomo_log"),
    );
    TrafficDecision {
        kind: TrafficDecisionKind::Reject,
        mode: session.runtime.mode.clone(),
        tun_enabled: session.runtime.tun_enabled,
        rule: Some(TrafficRule {
            rule_type: reject.rule,
            payload: reject.payload,
            target: reject.terminal,
            level: EvidenceLevel::Confirmed,
        }),
        chain,
        evidence: vec![Evidence {
            level: EvidenceLevel::Confirmed,
            source: "mihomo_log".into(),
            summary: "one Mihomo reject event matched the observation target".into(),
        }],
    }
}

fn candidate_score(value: &serde_json::Value, target: &TrafficProbeTarget) -> u16 {
    let metadata = &value["metadata"];
    let mut score = 100;
    if metadata
        .get("host")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|host| host.eq_ignore_ascii_case(&target.host))
    {
        score += 100;
    }
    if metadata
        .get("destinationIP")
        .and_then(serde_json::Value::as_str)
        .and_then(|ip| ip.parse::<IpAddr>().ok())
        .is_some_and(|ip| target.resolved_ips.contains(&ip))
    {
        score += 50;
    }
    if metadata
        .get("network")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|protocol| protocol.eq_ignore_ascii_case(&target.protocol))
    {
        score += 10;
    }
    if target.correlation == TrafficProbeCorrelation::Process {
        if metadata
            .get("processID")
            .or_else(|| metadata.get("processId"))
            .or_else(|| metadata.get("pid"))
            .and_then(json_u32)
            .is_some_and(|process_id| process_id == target.process_id)
        {
            score += 20;
        }
        if target.process_id == std::process::id()
            && let Ok(current_exe) = std::env::current_exe()
        {
            if metadata
                .get("processPath")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|path| std::path::Path::new(path) == current_exe)
            {
                score += 20;
            } else if metadata
                .get("process")
                .and_then(serde_json::Value::as_str)
                .zip(current_exe.file_name().and_then(|name| name.to_str()))
                .is_some_and(|(process, file_name)| process.eq_ignore_ascii_case(file_name))
            {
                score += 10;
            }
        }
    }
    score
}

fn json_u32(value: &serde_json::Value) -> Option<u32> {
    value
        .as_u64()
        .and_then(|number| u32::try_from(number).ok())
        .or_else(|| value.as_str().and_then(|number| number.parse().ok()))
}

fn push_node(
    chain: &mut Vec<TrafficNode>,
    visited: &mut HashSet<String>,
    kind: TrafficNodeKind,
    name: &str,
    node_type: Option<String>,
    proxy: Option<&MihomoProxy>,
    evidence: (EvidenceLevel, &str),
) {
    if name.is_empty() || chain.len() >= MAX_CHAIN_NODES || !visited.insert(name.to_owned()) {
        return;
    }
    let (level, source) = evidence;
    chain.push(TrafficNode {
        kind,
        name: name.into(),
        node_type,
        endpoint: None,
        alive: proxy.and_then(|proxy| proxy.alive),
        delay_ms: proxy.and_then(|proxy| proxy.delay_ms),
        level,
        evidence: vec![Evidence {
            level,
            source: source.into(),
            summary: match level {
                EvidenceLevel::Confirmed => "confirmed by a correlated Mihomo event",
                EvidenceLevel::Inferred => "inferred from current Mihomo configuration",
                EvidenceLevel::Unknown => "Mihomo evidence was insufficient",
            }
            .into(),
        }],
    });
}

#[derive(Debug, Clone)]
struct ObservedReject {
    protocol: String,
    host: String,
    port: u16,
    rule: String,
    payload: Option<String>,
    terminal: String,
}

fn parse_reject_log(payload: &str) -> Option<ObservedReject> {
    let protocol_end = payload.find(']')?;
    let protocol = payload.strip_prefix('[')?[..protocol_end - 1].to_owned();
    let (_, after_arrow) = payload.split_once(" --> ")?;
    let (destination, routing) = after_arrow.split_once(" match ")?;
    let (matched_rule, terminal) = routing.rsplit_once(" using ")?;
    let terminal = terminal.split_whitespace().next()?.to_ascii_uppercase();
    if !matches!(terminal.as_str(), "REJECT" | "REJECT-DROP") {
        return None;
    }
    let (host, port) = split_host_port(destination)?;
    let (rule, rule_payload) = if let Some(open) = matched_rule.find('(') {
        let payload = matched_rule.strip_suffix(')')?.get(open + 1..)?.to_owned();
        (matched_rule[..open].to_owned(), nonempty(payload))
    } else {
        (matched_rule.to_owned(), None)
    };
    if rule.is_empty() {
        return None;
    }
    Some(ObservedReject {
        protocol,
        host,
        port,
        rule,
        payload: rule_payload,
        terminal,
    })
}

fn split_host_port(destination: &str) -> Option<(String, u16)> {
    let (host, port) = destination.rsplit_once(':')?;
    let port = port.parse().ok()?;
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
        .to_owned();
    Some((host, port))
}

fn reject_matches_target(reject: &ObservedReject, target: &TrafficProbeTarget) -> bool {
    reject.port == target.port
        && (reject.host.eq_ignore_ascii_case(&target.host)
            || reject
                .host
                .parse::<IpAddr>()
                .ok()
                .is_some_and(|ip| target.resolved_ips.contains(&ip)))
}

fn reject_score(reject: &ObservedReject, target: &TrafficProbeTarget) -> u16 {
    let mut score = 100;
    if reject.host.eq_ignore_ascii_case(&target.host) {
        score += 100;
    }
    if reject
        .host
        .parse::<IpAddr>()
        .ok()
        .is_some_and(|ip| target.resolved_ips.contains(&ip))
    {
        score += 50;
    }
    if reject.protocol.eq_ignore_ascii_case(&target.protocol) {
        score += 10;
    }
    score
}

fn proxy_kind(kind: &str) -> TrafficNodeKind {
    if matches!(
        kind.to_ascii_lowercase().as_str(),
        "selector" | "urltest" | "fallback" | "loadbalance" | "relay" | "smart"
    ) {
        TrafficNodeKind::PolicyGroup
    } else {
        TrafficNodeKind::ProxyNode
    }
}

fn is_chain_sentinel(name: &str, proxies: &HashMap<String, MihomoProxy>) -> bool {
    proxies.get(name).is_none() && matches!(name.to_ascii_uppercase().as_str(), "MATCH" | "PROXY")
}

fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn unavailable_runtime() -> MihomoRuntime {
    MihomoRuntime {
        available: false,
        mode: None,
        tun_enabled: None,
        controller: Some("unavailable".into()),
    }
}

fn unknown_decision(summary: &str) -> TrafficDecision {
    TrafficDecision::unknown("mihomo_observer", summary)
}

fn observation_error() -> DiagnosticError {
    DiagnosticError::System("Mihomo observation unavailable".into())
}

#[derive(Clone, Deserialize)]
struct ObservedConnection {
    #[serde(default)]
    id: String,
    #[serde(default)]
    chains: Vec<String>,
    #[serde(default, rename = "providerChains")]
    provider_chains: Vec<String>,
    #[serde(
        default,
        rename = "dialerProxy",
        alias = "dialer-proxy",
        alias = "dialerChains"
    )]
    dialer_proxy: Vec<String>,
    #[serde(default)]
    rule: String,
    #[serde(default, rename = "rulePayload")]
    rule_payload: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traffic::mihomo::MihomoConnectionEvent;
    use futures_util::Stream;
    use std::{
        pin::Pin,
        sync::{Arc, Mutex as StdMutex, atomic::AtomicUsize},
        task::{Context, Poll},
    };
    use tokio::sync::{Barrier, mpsc};

    struct SynchronizedTransport {
        connection_receiver:
            StdMutex<Option<mpsc::UnboundedReceiver<Result<MihomoEvent, DiagnosticError>>>>,
        stream_drops: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl MihomoTransport for SynchronizedTransport {
        async fn runtime(&self) -> Result<MihomoRuntime, DiagnosticError> {
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
            let receiver = self
                .connection_receiver
                .lock()
                .unwrap()
                .take()
                .expect("connection stream is subscribed once");
            Ok(Box::pin(OpenEventStream {
                receiver,
                drops: Arc::clone(&self.stream_drops),
            }))
        }

        async fn log_stream(&self) -> Result<MihomoEventStream, DiagnosticError> {
            Ok(Box::pin(DropTrackedPendingStream {
                drops: Arc::clone(&self.stream_drops),
            }))
        }
    }

    struct OpenEventStream {
        receiver: mpsc::UnboundedReceiver<Result<MihomoEvent, DiagnosticError>>,
        drops: Arc<AtomicUsize>,
    }

    impl Stream for OpenEventStream {
        type Item = Result<MihomoEvent, DiagnosticError>;

        fn poll_next(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            self.receiver.poll_recv(context)
        }
    }

    impl Drop for OpenEventStream {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct DropTrackedPendingStream {
        drops: Arc<AtomicUsize>,
    }

    impl Stream for DropTrackedPendingStream {
        type Item = Result<MihomoEvent, DiagnosticError>;

        fn poll_next(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    impl Drop for DropTrackedPendingStream {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn matched_connection_event() -> MihomoEvent {
        let start = (OffsetDateTime::now_utc() + TimeDuration::seconds(1))
            .format(&Rfc3339)
            .unwrap();
        MihomoEvent::Connection(MihomoConnectionEvent {
            download_total: 1,
            upload_total: 1,
            connections: vec![serde_json::json!({
                "id": "short-lived-match",
                "metadata": {
                    "network": "tcp",
                    "host": "example.com",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": "443"
                },
                "start": start,
                "chains": ["短连接节点", "MATCH"],
                "providerChains": [],
                "rule": "MATCH",
                "rulePayload": ""
            })],
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn finish_cannot_miss_the_only_event_between_state_check_and_wait_registration() {
        let (connection_sender, connection_receiver) = mpsc::unbounded_channel();
        let stream_drops = Arc::new(AtomicUsize::new(0));
        let hook = Arc::new(FinishWaitHook {
            after_check: Arc::new(Barrier::new(2)),
            resume_wait: Arc::new(Barrier::new(2)),
            cleanup_reached: None,
        });
        let provider = MihomoTrafficDecisionProvider {
            transport: Arc::new(SynchronizedTransport {
                connection_receiver: StdMutex::new(Some(connection_receiver)),
                stream_drops,
            }),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            finish_wait_hook: Some(Arc::clone(&hook)),
        };
        let target = TrafficProbeTarget::new(
            crate::ports::TrafficProbeScheme::Https,
            "example.com",
            443,
            vec!["93.184.216.34".parse().unwrap()],
            4242,
        );
        let id = provider.begin(&target).await.unwrap();
        let event_stored = {
            let sessions = provider.sessions.lock().await;
            Arc::clone(&sessions.get(&id).unwrap().notify).notified_owned()
        };
        let finish_provider = provider.clone();
        let mut finish_task = tokio::spawn(async move { finish_provider.finish(id).await });

        hook.after_check.wait().await;
        connection_sender
            .send(Ok(matched_connection_event()))
            .unwrap();
        event_stored.await;
        assert!(!connection_sender.is_closed());
        hook.resume_wait.wait().await;

        let result = match tokio::time::timeout(Duration::from_secs(1), &mut finish_task).await {
            Ok(result) => result.unwrap().unwrap(),
            Err(error) => {
                finish_task.abort();
                provider.cancel(id).await;
                panic!("finish missed the only matched event: {error}");
            }
        };

        assert_eq!(result.kind, TrafficDecisionKind::Proxy);
        assert_eq!(result.chain.len(), 2);
        assert_eq!(result.chain[0].name, "MATCH");
        assert_eq!(result.chain[1].name, "短连接节点");
        tokio::time::timeout(Duration::from_secs(1), connection_sender.closed())
            .await
            .expect("normal finish must stop the still-open connection stream");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn finish_claim_preserves_a_matched_event_when_independent_expiry_fires() {
        let (connection_sender, connection_receiver) = mpsc::unbounded_channel();
        let stream_drops = Arc::new(AtomicUsize::new(0));
        let hook = Arc::new(FinishWaitHook {
            after_check: Arc::new(Barrier::new(2)),
            resume_wait: Arc::new(Barrier::new(2)),
            cleanup_reached: None,
        });
        let provider = MihomoTrafficDecisionProvider {
            transport: Arc::new(SynchronizedTransport {
                connection_receiver: StdMutex::new(Some(connection_receiver)),
                stream_drops,
            }),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            finish_wait_hook: Some(Arc::clone(&hook)),
        };
        let target = TrafficProbeTarget::new(
            crate::ports::TrafficProbeScheme::Https,
            "example.com",
            443,
            vec!["93.184.216.34".parse().unwrap()],
            4242,
        );
        let id = provider.begin(&target).await.unwrap();
        let event_stored = {
            let sessions = provider.sessions.lock().await;
            Arc::clone(&sessions.get(&id).unwrap().notify).notified_owned()
        };
        let finish_provider = provider.clone();
        let finish_task = tokio::spawn(async move { finish_provider.finish(id).await });

        hook.after_check.wait().await;
        connection_sender
            .send(Ok(matched_connection_event()))
            .unwrap();
        event_stored.await;
        tokio::time::sleep(OBSERVATION_DEADLINE + Duration::from_millis(200)).await;
        tokio::time::timeout(Duration::from_secs(1), connection_sender.closed())
            .await
            .expect("independent expiry must stop the claimed session streams");
        hook.resume_wait.wait().await;

        let result = tokio::time::timeout(Duration::from_secs(1), finish_task)
            .await
            .expect("finish must retain evidence after its independent expiry fires")
            .unwrap()
            .unwrap();

        assert_eq!(result.kind, TrafficDecisionKind::Proxy);
        assert_eq!(result.chain.len(), 2);
        assert_eq!(result.chain[0].name, "MATCH");
        assert_eq!(result.chain[1].name, "短连接节点");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_stops_streams_after_finish_has_entered_its_wait_loop() {
        let (connection_sender, connection_receiver) = mpsc::unbounded_channel();
        let stream_drops = Arc::new(AtomicUsize::new(0));
        let hook = Arc::new(FinishWaitHook {
            after_check: Arc::new(Barrier::new(2)),
            resume_wait: Arc::new(Barrier::new(2)),
            cleanup_reached: None,
        });
        let provider = MihomoTrafficDecisionProvider {
            transport: Arc::new(SynchronizedTransport {
                connection_receiver: StdMutex::new(Some(connection_receiver)),
                stream_drops,
            }),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            finish_wait_hook: Some(Arc::clone(&hook)),
        };
        let target = TrafficProbeTarget::new(
            crate::ports::TrafficProbeScheme::Https,
            "example.com",
            443,
            vec!["93.184.216.34".parse().unwrap()],
            4242,
        );
        let id = provider.begin(&target).await.unwrap();
        let finish_provider = provider.clone();
        let mut finish_task = tokio::spawn(async move { finish_provider.finish(id).await });

        hook.after_check.wait().await;
        provider.cancel(id).await;
        let streams_stopped =
            tokio::time::timeout(Duration::from_secs(1), connection_sender.closed()).await;
        hook.resume_wait.wait().await;
        if let Err(error) = streams_stopped {
            finish_task.abort();
            panic!("cancel did not stop a session claimed by finish: {error}");
        }

        let result = tokio::time::timeout(Duration::from_secs(1), &mut finish_task)
            .await
            .expect("cancel must wake an in-progress finish")
            .unwrap()
            .unwrap();

        assert_eq!(result.kind, TrafficDecisionKind::Unknown);
        assert!(result.chain.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_finish_at_contended_cleanup_cannot_orphan_session_ownership() {
        let (connection_sender, connection_receiver) = mpsc::unbounded_channel();
        let stream_drops = Arc::new(AtomicUsize::new(0));
        let hook = Arc::new(FinishWaitHook {
            after_check: Arc::new(Barrier::new(2)),
            resume_wait: Arc::new(Barrier::new(2)),
            cleanup_reached: Some(Arc::new(Barrier::new(2))),
        });
        let provider = MihomoTrafficDecisionProvider {
            transport: Arc::new(SynchronizedTransport {
                connection_receiver: StdMutex::new(Some(connection_receiver)),
                stream_drops: Arc::clone(&stream_drops),
            }),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            finish_wait_hook: Some(Arc::clone(&hook)),
        };
        let target = TrafficProbeTarget::new(
            crate::ports::TrafficProbeScheme::Https,
            "example.com",
            443,
            vec!["93.184.216.34".parse().unwrap()],
            4242,
        );
        let id = provider.begin(&target).await.unwrap();
        let (event_stored, weak_session) = {
            let sessions = provider.sessions.lock().await;
            let session = sessions.get(&id).unwrap();
            (
                Arc::clone(&session.notify).notified_owned(),
                Arc::downgrade(session),
            )
        };
        let finish_provider = provider.clone();
        let finish_task = tokio::spawn(async move { finish_provider.finish(id).await });

        hook.after_check.wait().await;
        connection_sender
            .send(Ok(matched_connection_event()))
            .unwrap();
        event_stored.await;
        let sessions_guard = provider.sessions.lock().await;
        hook.resume_wait.wait().await;
        hook.cleanup_reached.as_ref().unwrap().wait().await;
        finish_task.abort();
        assert!(finish_task.await.unwrap_err().is_cancelled());
        drop(sessions_guard);

        tokio::time::timeout(Duration::from_secs(6), async {
            loop {
                let map_is_empty = provider.sessions.lock().await.is_empty();
                if map_is_empty
                    && stream_drops.load(Ordering::SeqCst) == 2
                    && weak_session.upgrade().is_none()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropped finish must leave expiry ownership intact without follow-up cancel");

        assert_eq!(stream_drops.load(Ordering::SeqCst), 2);
        assert!(provider.sessions.lock().await.is_empty());
    }
}

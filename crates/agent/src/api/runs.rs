use crate::{
    domain::{DiagnosticStage, UrlDiagnosticResult},
    ports::ProgressSink,
};
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use tokio::sync::broadcast;
use uuid::Uuid;

const RUN_RETENTION: Duration = Duration::from_secs(30 * 60);
const EVENT_BUFFER: usize = 32;

#[derive(Clone)]
pub struct RunStore {
    runs: Arc<RwLock<HashMap<Uuid, RunRecord>>>,
    retention: Duration,
}

struct RunRecord {
    snapshot: RunSnapshot,
    completed_at: Option<Instant>,
    events: Vec<RunStageEvent>,
    sender: broadcast::Sender<RunStageEvent>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Running,
    Completed,
    Failed,
}

impl RunStatus {
    fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

#[derive(Clone, Serialize)]
pub struct RunSnapshot {
    pub id: Uuid,
    pub status: RunStatus,
    pub result: Option<UrlDiagnosticResult>,
    pub error: Option<RunFailure>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunFailure {
    code: &'static str,
    message: &'static str,
}

impl RunFailure {
    pub(crate) fn invalid_url() -> Self {
        Self {
            code: "invalid_url",
            message: "请输入有效的 HTTP 或 HTTPS 网址",
        }
    }

    pub(crate) fn dns_failed() -> Self {
        Self {
            code: "dns_failed",
            message: "无法解析域名，请检查网址或 DNS 设置",
        }
    }

    pub(crate) fn diagnostic_failed() -> Self {
        Self {
            code: "diagnostic_failed",
            message: "诊断未能完成，请稍后重试",
        }
    }

    pub(crate) fn trace_failed() -> Self {
        Self {
            code: "trace_failed",
            message: "网络跳点探测未能完成，请稍后重试",
        }
    }

    pub(crate) fn trace_cancelled() -> Self {
        Self {
            code: "trace_cancelled",
            message: "网络跳点探测已取消",
        }
    }
}

#[derive(Clone, Serialize)]
pub(crate) struct RunStageEvent {
    pub(crate) sequence: usize,
    pub(crate) stage: String,
}

pub(crate) struct RunSubscription {
    pub history: Vec<RunStageEvent>,
    pub receiver: broadcast::Receiver<RunStageEvent>,
    pub terminal: bool,
}

impl RunStore {
    pub fn new() -> Self {
        Self::with_retention(RUN_RETENTION)
    }

    pub fn with_retention(retention: Duration) -> Self {
        Self {
            runs: Arc::new(RwLock::new(HashMap::new())),
            retention,
        }
    }

    pub fn create(&self) -> Uuid {
        let id = Uuid::new_v4();
        let (sender, _) = broadcast::channel(EVENT_BUFFER);
        self.runs.write().expect("run store lock poisoned").insert(
            id,
            RunRecord {
                snapshot: RunSnapshot {
                    id,
                    status: RunStatus::Running,
                    result: None,
                    error: None,
                },
                completed_at: None,
                events: Vec::new(),
                sender,
            },
        );
        id
    }

    pub fn snapshot(&self, id: Uuid) -> Option<RunSnapshot> {
        let mut runs = self.runs.write().expect("run store lock poisoned");
        Self::remove_expired(&mut runs, self.retention);
        runs.get(&id).map(|record| record.snapshot.clone())
    }

    pub fn count(&self) -> usize {
        self.runs.read().expect("run store lock poisoned").len()
    }

    pub fn complete(&self, id: Uuid, result: UrlDiagnosticResult) {
        let completed = if let Some(record) = self
            .runs
            .write()
            .expect("run store lock poisoned")
            .get_mut(&id)
        {
            if record.snapshot.status != RunStatus::Running {
                return;
            }
            record.snapshot.status = RunStatus::Completed;
            record.snapshot.result = Some(result);
            record.snapshot.error = None;
            record.completed_at = Some(Instant::now());
            Self::publish(record, "completed".into());
            true
        } else {
            false
        };
        if completed {
            self.schedule_expiry(id);
        }
    }

    pub fn fail(&self, id: Uuid, error: RunFailure) {
        let mut runs = self.runs.write().expect("run store lock poisoned");
        let Some(record) = runs.get_mut(&id) else {
            return;
        };
        if record.snapshot.status != RunStatus::Running {
            return;
        }
        record.snapshot.status = RunStatus::Failed;
        record.snapshot.error = Some(error);
        record.snapshot.result = None;
        record.completed_at = Some(Instant::now());
        Self::publish(record, "failed".into());
        drop(runs);
        self.schedule_expiry(id);
    }

    pub(crate) fn emit(&self, id: Uuid, stage: DiagnosticStage) {
        if stage == DiagnosticStage::Completed {
            return;
        }
        if let Some(record) = self
            .runs
            .write()
            .expect("run store lock poisoned")
            .get_mut(&id)
        {
            Self::publish(record, stage_name(stage).into());
        }
    }

    pub(crate) fn subscribe(&self, id: Uuid) -> Option<RunSubscription> {
        let mut runs = self.runs.write().expect("run store lock poisoned");
        Self::remove_expired(&mut runs, self.retention);
        let record = runs.get(&id)?;
        let history = record.events.clone();
        let terminal = record.snapshot.status.is_terminal()
            || history
                .last()
                .is_some_and(|event| is_terminal_stage(&event.stage));
        Some(RunSubscription {
            history,
            receiver: record.sender.subscribe(),
            terminal,
        })
    }

    pub(crate) fn completed_result(&self, id: Uuid) -> Option<UrlDiagnosticResult> {
        let mut runs = self.runs.write().expect("run store lock poisoned");
        Self::remove_expired(&mut runs, self.retention);
        let record = runs.get(&id)?;
        (record.snapshot.status == RunStatus::Completed)
            .then(|| record.snapshot.result.clone())
            .flatten()
    }

    fn publish(record: &mut RunRecord, stage: String) {
        let event = RunStageEvent {
            sequence: record.events.len(),
            stage,
        };
        record.events.push(event.clone());
        let _ = record.sender.send(event);
    }

    fn remove_expired(runs: &mut HashMap<Uuid, RunRecord>, retention: Duration) {
        runs.retain(|_, record| {
            record
                .completed_at
                .is_none_or(|completed| completed.elapsed() < retention)
        });
    }

    fn schedule_expiry(&self, id: Uuid) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let store = self.clone();
        let retention = self.retention;
        runtime.spawn(async move {
            tokio::time::sleep(retention).await;
            let mut runs = store.runs.write().expect("run store lock poisoned");
            let expired = runs.get(&id).is_some_and(|record| {
                record
                    .completed_at
                    .is_some_and(|completed| completed.elapsed() >= retention)
            });
            if expired {
                runs.remove(&id);
            }
        });
    }
}

impl Default for RunStore {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) struct RunProgress {
    store: RunStore,
    id: Uuid,
}

impl RunProgress {
    pub(crate) fn new(store: RunStore, id: Uuid) -> Self {
        Self { store, id }
    }
}

impl ProgressSink for RunProgress {
    fn emit(&self, stage: DiagnosticStage) {
        self.store.emit(self.id, stage);
    }
}

fn stage_name(stage: DiagnosticStage) -> &'static str {
    match stage {
        DiagnosticStage::Validating => "validating",
        DiagnosticStage::Proxy => "proxy",
        DiagnosticStage::Dns => "dns",
        DiagnosticStage::Route => "route",
        DiagnosticStage::Http => "http",
        DiagnosticStage::Completed => "completed",
    }
}

fn is_terminal_stage(stage: &str) -> bool {
    matches!(stage, "completed" | "failed")
}

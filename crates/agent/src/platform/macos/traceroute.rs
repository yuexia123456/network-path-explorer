use crate::{
    domain::{EvidenceLevel, RouteTraceResult, TraceHop, TraceTarget},
    error::DiagnosticError,
    ports::{RouteTracer, TraceProgressSink},
};
use async_trait::async_trait;
use std::{
    collections::BTreeMap,
    net::IpAddr,
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, ChildStdout, Command},
};
use tokio_util::sync::CancellationToken;

pub const MAX_HOPS: u8 = 20;
pub const TRACE_TIMEOUT: Duration = Duration::from_secs(25);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceExitStatus {
    pub success: bool,
    pub code: Option<i32>,
}

impl TraceExitStatus {
    pub const fn success() -> Self {
        Self {
            success: true,
            code: Some(0),
        }
    }

    pub const fn failure(code: i32) -> Self {
        Self {
            success: false,
            code: Some(code),
        }
    }
}

#[async_trait]
pub trait TraceProcess: Send {
    async fn next_stdout_line(&mut self) -> Result<Option<Vec<u8>>, DiagnosticError>;
    async fn wait(&mut self) -> Result<TraceExitStatus, DiagnosticError>;
    async fn kill(&mut self) -> Result<(), DiagnosticError>;
}

#[async_trait]
pub trait TraceProcessFactory: Send + Sync {
    async fn spawn(
        &self,
        executable: &str,
        arguments: &[String],
    ) -> Result<Box<dyn TraceProcess>, DiagnosticError>;
}

#[derive(Clone)]
pub struct MacRouteTracer {
    process_factory: Arc<dyn TraceProcessFactory>,
    timeout: Duration,
}

impl MacRouteTracer {
    pub fn new() -> Self {
        Self::with_process_factory(Arc::new(SystemTraceProcessFactory))
    }

    pub fn with_process_factory(process_factory: Arc<dyn TraceProcessFactory>) -> Self {
        Self {
            process_factory,
            timeout: TRACE_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl Default for MacRouteTracer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RouteTracer for MacRouteTracer {
    async fn trace(
        &self,
        target: TraceTarget,
        progress: &dyn TraceProgressSink,
        cancel: CancellationToken,
    ) -> Result<RouteTraceResult, DiagnosticError> {
        let started = Instant::now();
        if cancel.is_cancelled() {
            return Err(DiagnosticError::RouteTraceCancelled);
        }

        let (executable, arguments) = invocation(target.ip);
        let process = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(DiagnosticError::RouteTraceCancelled),
            spawned = tokio::time::timeout(
                self.timeout,
                self.process_factory.spawn(executable, &arguments),
            ) => match spawned {
                Ok(Ok(process)) => process,
                Ok(Err(_)) => return Err(DiagnosticError::RouteTraceFailed),
                Err(_) => return Err(DiagnosticError::RouteTraceTimeout),
            },
        };
        let mut process = process;
        let remaining = self.timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            kill_and_reap(&mut *process).await;
            return Err(DiagnosticError::RouteTraceTimeout);
        }

        let collected = match tokio::time::timeout(
            remaining,
            collect_process_output(&mut *process, target.ip, progress, &cancel),
        )
        .await
        {
            Ok(Ok(collected)) => collected,
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                kill_and_reap(&mut *process).await;
                return Err(DiagnosticError::RouteTraceTimeout);
            }
        };

        Ok(RouteTraceResult {
            target,
            hops: collected.hops,
            reached_target: collected.reached_target,
            elapsed_ms: elapsed_millis(started),
        })
    }
}

fn invocation(ip: IpAddr) -> (&'static str, Vec<String>) {
    let executable = if ip.is_ipv6() {
        "/usr/sbin/traceroute6"
    } else {
        "/usr/sbin/traceroute"
    };
    let arguments = ["-n", "-m", "20", "-q", "2", "-w", "1"]
        .into_iter()
        .map(str::to_owned)
        .chain(std::iter::once(ip.to_string()))
        .collect();
    (executable, arguments)
}

struct CollectedTrace {
    hops: Vec<TraceHop>,
    reached_target: bool,
}

/// Finalizes each hop index on its first valid observation.
///
/// macOS normally emits hop lines in order, but a fixture or a future parser
/// input may contain duplicates or out-of-order lines. Once a hop index has
/// been emitted, later observations for that index are ignored so streamed
/// progress and the final result always describe the same trace. The highest
/// finalized index is the terminal trace evidence used for `reached_target`.
struct TraceAccumulator {
    hops: BTreeMap<u8, TraceHop>,
    next_index: u8,
    terminal_index: Option<u8>,
    target: IpAddr,
}

impl TraceAccumulator {
    fn new(target: IpAddr) -> Self {
        Self {
            hops: BTreeMap::new(),
            next_index: 1,
            terminal_index: None,
            target,
        }
    }

    fn push(&mut self, hop: TraceHop, progress: &dyn TraceProgressSink) {
        if hop.index < self.next_index {
            return;
        }

        while self.next_index < hop.index {
            let unanswered = unanswered_hop(self.next_index);
            self.hops.insert(self.next_index, unanswered.clone());
            progress.emit(unanswered);
            self.next_index += 1;
        }

        let index = hop.index;
        self.hops.insert(index, hop.clone());
        progress.emit(hop);
        self.terminal_index = Some(index);
        self.next_index = self.next_index.saturating_add(1);
    }

    fn finish(mut self) -> CollectedTrace {
        let highest = self.terminal_index.unwrap_or(0);
        let reached_target = self
            .terminal_index
            .and_then(|index| self.hops.get(&index))
            .and_then(|hop| hop.address)
            .is_some_and(|address| address == self.target);
        let hops = (1..=highest)
            .map(|index| {
                self.hops
                    .remove(&index)
                    .unwrap_or_else(|| unanswered_hop(index))
            })
            .collect();
        CollectedTrace {
            hops,
            reached_target,
        }
    }
}

async fn collect_process_output(
    process: &mut dyn TraceProcess,
    target: IpAddr,
    progress: &dyn TraceProgressSink,
    cancel: &CancellationToken,
) -> Result<CollectedTrace, DiagnosticError> {
    let mut trace = TraceAccumulator::new(target);

    loop {
        let line = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                kill_and_reap(process).await;
                return Err(DiagnosticError::RouteTraceCancelled);
            }
            line = process.next_stdout_line() => match line {
                Ok(line) => line,
                Err(_) => {
                    kill_and_reap(process).await;
                    return Err(DiagnosticError::RouteTraceFailed);
                }
            },
        };
        let Some(line) = line else {
            break;
        };
        let line = match String::from_utf8(line) {
            Ok(line) => line,
            Err(_) => {
                kill_and_reap(process).await;
                return Err(DiagnosticError::RouteTraceFailed);
            }
        };
        if let Some(hop) = parse_hop_line(&line, target) {
            trace.push(hop, progress);
        }
    }

    let status = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            kill_and_reap(process).await;
            return Err(DiagnosticError::RouteTraceCancelled);
        }
        status = process.wait() => match status {
            Ok(status) => status,
            Err(_) => {
                kill_and_reap(process).await;
                return Err(DiagnosticError::RouteTraceFailed);
            }
        },
    };
    if !status.success {
        return Err(DiagnosticError::RouteTraceFailed);
    }

    Ok(trace.finish())
}

fn unanswered_hop(index: u8) -> TraceHop {
    TraceHop {
        index,
        address: None,
        rtts_ms: Vec::new(),
        level: EvidenceLevel::Unknown,
    }
}

pub fn parse_traceroute(output: &str, target: IpAddr) -> Result<RouteTraceResult, DiagnosticError> {
    let mut trace = TraceAccumulator::new(target);
    let progress = NoopProgress;
    for line in output.lines() {
        if let Some(hop) = parse_hop_line(line, target) {
            trace.push(hop, &progress);
        }
    }
    let collected = trace.finish();
    Ok(RouteTraceResult {
        target: TraceTarget {
            kind: crate::domain::TraceTargetKind::ReferenceDestination,
            ip: target,
        },
        hops: collected.hops,
        reached_target: collected.reached_target,
        elapsed_ms: 0,
    })
}

struct NoopProgress;

impl TraceProgressSink for NoopProgress {
    fn emit(&self, _hop: TraceHop) {}
}

fn parse_hop_line(line: &str, target: IpAddr) -> Option<TraceHop> {
    let mut tokens = line.split_whitespace();
    let index = tokens.next()?.parse::<u8>().ok()?;
    if !(1..=MAX_HOPS).contains(&index) {
        return None;
    }
    let tokens = tokens.collect::<Vec<_>>();
    let responders = tokens
        .iter()
        .filter_map(|token| parse_ip_token(token))
        .collect::<Vec<_>>();
    let address = responders
        .iter()
        .copied()
        .find(|address| *address == target)
        .or_else(|| responders.first().copied());
    let rtts_ms = tokens
        .windows(2)
        .filter(|window| window[1].eq_ignore_ascii_case("ms"))
        .filter_map(|window| parse_rtt(window[0]))
        .collect::<Vec<_>>();
    let level = if address.is_some() || !rtts_ms.is_empty() {
        EvidenceLevel::Confirmed
    } else {
        EvidenceLevel::Unknown
    };
    Some(TraceHop {
        index,
        address,
        rtts_ms,
        level,
    })
}

fn parse_ip_token(token: &str) -> Option<IpAddr> {
    let token = token.trim_matches(['(', ')', '[', ']']);
    if let Ok(ip) = token.parse() {
        return Some(ip);
    }
    token
        .split_once('%')
        .and_then(|(address, _scope)| address.parse().ok())
}

fn parse_rtt(token: &str) -> Option<f64> {
    let token = token.strip_prefix('<').unwrap_or(token);
    let value = token.parse::<f64>().ok()?;
    (value.is_finite() && value >= 0.0).then_some(value)
}

fn elapsed_millis(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

async fn kill_and_reap(process: &mut dyn TraceProcess) {
    let _ = process.kill().await;
    let _ = process.wait().await;
}

struct SystemTraceProcessFactory;

#[async_trait]
impl TraceProcessFactory for SystemTraceProcessFactory {
    async fn spawn(
        &self,
        executable: &str,
        arguments: &[String],
    ) -> Result<Box<dyn TraceProcess>, DiagnosticError> {
        let mut command = Command::new(executable);
        command
            .args(arguments)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|_| DiagnosticError::RouteTraceFailed)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(DiagnosticError::RouteTraceFailed)?;
        Ok(Box::new(SystemTraceProcess {
            child,
            stdout: BufReader::new(stdout),
        }))
    }
}

struct SystemTraceProcess {
    child: Child,
    stdout: BufReader<ChildStdout>,
}

#[async_trait]
impl TraceProcess for SystemTraceProcess {
    async fn next_stdout_line(&mut self) -> Result<Option<Vec<u8>>, DiagnosticError> {
        let mut line = Vec::new();
        let count = self
            .stdout
            .read_until(b'\n', &mut line)
            .await
            .map_err(|_| DiagnosticError::RouteTraceFailed)?;
        Ok((count != 0).then_some(line))
    }

    async fn wait(&mut self) -> Result<TraceExitStatus, DiagnosticError> {
        let status = self
            .child
            .wait()
            .await
            .map_err(|_| DiagnosticError::RouteTraceFailed)?;
        Ok(TraceExitStatus {
            success: status.success(),
            code: status.code(),
        })
    }

    async fn kill(&mut self) -> Result<(), DiagnosticError> {
        self.child
            .start_kill()
            .map_err(|_| DiagnosticError::RouteTraceFailed)
    }
}

import SpeedTest, { type Results as CloudflareResults } from "@cloudflare/speedtest";
import type { ApiClient, ApiSubscription } from "./api";
import { presentTrafficDecision } from "./format";
import type {
  SpeedMeasurement,
  SpeedMeasurementPlan,
  SpeedMetrics,
  SpeedMode,
  SpeedSample,
  SpeedSampleKind,
  SpeedTestResult,
  SpeedTestSnapshot,
  TrafficDecision
} from "./types";

export interface SpeedEngine {
  play(): void;
  pause(): void;
  onPhaseChange(handler: (phase: SpeedSampleKind) => void): void;
  onSamples(handler: (samples: SpeedSample[]) => void): void;
  onFinish(handler: (metrics: SpeedMetrics) => void): void;
  onError(handler: () => void): void;
}

export type SpeedEngineFactory = (plan: SpeedMeasurementPlan) => SpeedEngine;

export interface SpeedTestController {
  readonly element: HTMLElement;
  cancel(): Promise<void>;
  dispose(): Promise<void>;
}

export interface SpeedTestControllerOptions {
  engineFactory?: SpeedEngineFactory;
  now?: () => number;
}

const QUICK_MAX_BYTES = 40_000_000;
const FULL_MAX_BYTES = 200_000_000;
const MAX_SAMPLE_BATCH = 16;
const CLOUDFLARE_PROVIDER = "cloudflare";

type CloudflareBandwidthPoint = {
  bytes: number;
  bps: number;
  duration: number;
  ping: number;
};

function isFiniteNonNegative(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function isSafeCounter(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function metricOrNull(value: unknown): number | null {
  return isFiniteNonNegative(value) ? value : null;
}

function requiredMetric(value: unknown, label: string): number {
  const metric = metricOrNull(value);
  if (metric === null) throw new Error(`Cloudflare ${label} metric is unavailable`);
  return metric;
}

function speedMetricsFromResults(results: CloudflareResults, includeLoadedLatency: boolean): SpeedMetrics {
  return {
    download_bps: requiredMetric(results.getDownloadBandwidth(), "download"),
    upload_bps: requiredMetric(results.getUploadBandwidth(), "upload"),
    unloaded_latency_ms: requiredMetric(results.getUnloadedLatency(), "unloaded latency"),
    unloaded_jitter_ms: requiredMetric(results.getUnloadedJitter(), "unloaded jitter"),
    download_loaded_latency_ms: includeLoadedLatency
      ? metricOrNull(results.getDownLoadedLatency())
      : null,
    upload_loaded_latency_ms: includeLoadedLatency ? metricOrNull(results.getUpLoadedLatency()) : null
  };
}

function speedSampleFromLatency(value: unknown): SpeedSample {
  if (!isFiniteNonNegative(value)) throw new Error("Cloudflare latency point is invalid");
  return {
    kind: "latency",
    bytes: 0,
    bps: null,
    duration_ms: value,
    latency_ms: value
  };
}

function speedSampleFromBandwidth(
  kind: "download" | "upload",
  point: CloudflareBandwidthPoint
): SpeedSample {
  if (
    !Number.isSafeInteger(point.bytes) ||
    point.bytes < 0 ||
    !isFiniteNonNegative(point.bps) ||
    !isFiniteNonNegative(point.duration) ||
    !isFiniteNonNegative(point.ping)
  ) {
    throw new Error(`Cloudflare ${kind} point is invalid`);
  }
  return {
    kind,
    bytes: point.bytes,
    bps: point.bps,
    duration_ms: point.duration,
    latency_ms: point.ping
  };
}

function phaseKind(value: unknown): SpeedSampleKind | null {
  return value === "latency" || value === "download" || value === "upload" ? value : null;
}

function measurementKind(measurement: unknown): SpeedSampleKind | null {
  if (!measurement || typeof measurement !== "object") return null;
  return phaseKind((measurement as { type?: unknown }).type);
}

/**
 * The only boundary through which the UI can observe the official engine.
 * No raw Results object, response body, URL, date, header, or session value
 * leaves this adapter.
 */
export class CloudflareSpeedEngine implements SpeedEngine {
  private readonly official: SpeedTest;
  private readonly includeLoadedLatency: boolean;
  private readonly cursors: Record<SpeedSampleKind, number> = {
    latency: 0,
    download: 0,
    upload: 0
  };
  private phaseHandler: ((phase: SpeedSampleKind) => void) | undefined;
  private samplesHandler: ((samples: SpeedSample[]) => void) | undefined;
  private finishHandler: ((metrics: SpeedMetrics) => void) | undefined;
  private errorHandler: (() => void) | undefined;
  private stopped = false;

  constructor(plan: SpeedMeasurementPlan) {
    this.includeLoadedLatency = plan.include_loaded_latency;
    this.official = new SpeedTest({
      autoStart: false,
      measurements: plan.measurements,
      measureDownloadLoadedLatency: plan.include_loaded_latency,
      measureUploadLoadedLatency: plan.include_loaded_latency,
      logMeasurementApiUrl: null,
      logAimApiUrl: null,
      includeCredentials: false,
      bandwidthFinishRequestDuration: 120_000,
      bandwidthAbortRequestDuration: plan.deadline_ms
    });
    this.official.onPhaseChange = (payload) => {
      if (this.stopped) return;
      const phase = measurementKind(payload?.measurement);
      if (phase) this.phaseHandler?.(phase);
    };
    this.official.onResultsChange = ({ type }) => {
      if (this.stopped) return;
      if (type !== "latency" && type !== "download" && type !== "upload") return;
      try {
        this.emitNewSamples(type);
      } catch {
        this.errorHandler?.();
      }
    };
    this.official.onFinish = (results) => {
      if (this.stopped) return;
      try {
        this.emitAllNewSamples();
        this.finishHandler?.(speedMetricsFromResults(results, this.includeLoadedLatency));
      } catch {
        this.errorHandler?.();
      }
    };
    this.official.onError = () => {
      if (!this.stopped) this.errorHandler?.();
    };
  }

  play(): void {
    if (!this.stopped) this.official.play();
  }

  pause(): void {
    if (this.stopped) return;
    this.stopped = true;
    this.official.pause();
  }

  onPhaseChange(handler: (phase: SpeedSampleKind) => void): void {
    this.phaseHandler = handler;
  }

  onSamples(handler: (samples: SpeedSample[]) => void): void {
    this.samplesHandler = handler;
  }

  onFinish(handler: (metrics: SpeedMetrics) => void): void {
    this.finishHandler = handler;
  }

  onError(handler: () => void): void {
    this.errorHandler = handler;
  }

  private emitAllNewSamples(): void {
    this.emitNewSamples("latency");
    this.emitNewSamples("download");
    this.emitNewSamples("upload");
  }

  private emitNewSamples(kind: SpeedSampleKind): void {
    const points = this.pointsFor(kind);
    const start = Math.min(this.cursors[kind], points.length);
    this.cursors[kind] = points.length;
    if (start === points.length) return;
    const next = points.slice(start);
    const samples =
      kind === "latency"
        ? next.map((point) => speedSampleFromLatency(point))
        : next.map((point) => speedSampleFromBandwidth(kind, point as CloudflareBandwidthPoint));
    if (samples.length > 0) this.samplesHandler?.(samples);
  }

  private pointsFor(kind: SpeedSampleKind): unknown[] {
    if (kind === "latency") return this.official.results.getUnloadedLatencyPoints();
    if (kind === "download") return this.official.results.getDownloadBandwidthPoints();
    return this.official.results.getUploadBandwidthPoints();
  }
}

export function createCloudflareSpeedEngine(plan: SpeedMeasurementPlan): SpeedEngine {
  return new CloudflareSpeedEngine(plan);
}

function formatBytes(bytes: number): string {
  return Math.max(0, Math.round(bytes)).toLocaleString("en-US");
}

function formatMbps(bps: number): string {
  return (bps / 1_000_000).toFixed(1);
}

function formatMilliseconds(value: number): string {
  return value.toFixed(1);
}

function formatElapsed(milliseconds: number): string {
  return `${(Math.max(0, milliseconds) / 1_000).toFixed(1)} 秒`;
}

function modeLabel(mode: SpeedMode): string {
  return mode === "quick" ? "快速测速" : "完整测速";
}

function phaseLabel(phase: SpeedSampleKind | undefined): string {
  if (phase === "latency") return "延迟";
  if (phase === "download") return "下载";
  if (phase === "upload") return "上传";
  return "准备中";
}

function decisionLabel(decision: TrafficDecision): string {
  const presentation = presentTrafficDecision(decision.kind);
  return `测速请求独立路径：${presentation.code}（${presentation.label}）`;
}

function isValidMeasurement(measurement: unknown): measurement is SpeedMeasurement {
  if (!measurement || typeof measurement !== "object") return false;
  const value = measurement as Record<string, unknown>;
  if (value.type === "latency") return isSafeCounter(value.numPackets) && value.numPackets > 0;
  if (value.type === "download" || value.type === "upload") {
    return isSafeCounter(value.bytes) && value.bytes > 0 && isSafeCounter(value.count) && value.count > 0;
  }
  return false;
}

function payloadFitsLimit(measurements: unknown[], limit: number): boolean {
  let total = 0;
  for (const measurement of measurements) {
    if (!measurement || typeof measurement !== "object") return false;
    const value = measurement as Record<string, unknown>;
    if (value.type !== "download" && value.type !== "upload") continue;
    if (!isSafeCounter(value.bytes) || !isSafeCounter(value.count)) return false;
    const remaining = limit - total;
    if (remaining < 0 || value.bytes > Math.floor(remaining / value.count)) return false;
    total += value.bytes * value.count;
  }
  return total <= limit;
}

function isValidPlan(value: unknown, mode: SpeedMode): value is SpeedMeasurementPlan {
  if (!value || typeof value !== "object") return false;
  const plan = value as Record<string, unknown>;
  const ceiling = mode === "quick" ? QUICK_MAX_BYTES : FULL_MAX_BYTES;
  return (
    plan.mode === mode &&
    isSafeCounter(plan.deadline_ms) &&
    plan.deadline_ms > 0 &&
    isSafeCounter(plan.max_bytes) &&
    plan.max_bytes > 0 &&
    plan.max_bytes <= ceiling &&
    plan.include_loaded_latency === (mode === "full") &&
    Array.isArray(plan.measurements) &&
    plan.measurements.length > 0 &&
    plan.measurements.every(isValidMeasurement) &&
    payloadFitsLimit(plan.measurements, plan.max_bytes) &&
    payloadFitsLimit(plan.measurements, ceiling)
  );
}

function isValidTrafficDecision(value: unknown): value is TrafficDecision {
  if (!value || typeof value !== "object") return false;
  const decision = value as Record<string, unknown>;
  return (
    decision.kind === "direct" ||
    decision.kind === "proxy" ||
    decision.kind === "reject" ||
    decision.kind === "unknown"
  ) && Array.isArray(decision.chain) && Array.isArray(decision.evidence);
}

function isValidMetrics(value: unknown, mode: SpeedMode): value is SpeedMetrics {
  if (!value || typeof value !== "object") return false;
  const metrics = value as Record<string, unknown>;
  const required = [
    metrics.download_bps,
    metrics.upload_bps,
    metrics.unloaded_latency_ms,
    metrics.unloaded_jitter_ms
  ];
  if (!required.every(isFiniteNonNegative)) return false;
  const loaded = [metrics.download_loaded_latency_ms, metrics.upload_loaded_latency_ms];
  if (mode === "quick") return loaded.every((metric) => metric === null);
  return loaded.every((metric) => metric === null || isFiniteNonNegative(metric));
}

function isValidSample(value: unknown): value is SpeedSample {
  if (!value || typeof value !== "object") return false;
  const sample = value as Record<string, unknown>;
  const validKind = sample.kind === "latency" || sample.kind === "download" || sample.kind === "upload";
  const validBps = sample.bps === null || isFiniteNonNegative(sample.bps);
  const validLatency = sample.latency_ms === null || isFiniteNonNegative(sample.latency_ms);
  return (
    validKind &&
    isSafeCounter(sample.bytes) &&
    validBps &&
    isFiniteNonNegative(sample.duration_ms) &&
    validLatency
  );
}

function isValidSpeedResult(value: unknown, mode: SpeedMode): value is SpeedTestResult {
  if (!value || typeof value !== "object") return false;
  const result = value as Record<string, unknown>;
  return (
    result.provider === CLOUDFLARE_PROVIDER &&
    result.mode === mode &&
    isValidMetrics(result.metrics, mode) &&
    isSafeCounter(result.used_bytes) &&
    isValidTrafficDecision(result.traffic_decision)
  );
}

function createSpeedTestElement(): HTMLElement {
  const root = document.createElement("section");
  root.className = "speed-test-section";
  root.dataset.speedTest = "true";
  root.setAttribute("aria-labelledby", "speed-test-title");
  root.innerHTML = `
    <div class="speed-test-card">
      <h2 id="speed-test-title">Cloudflare 测速</h2>
      <p class="speed-test-explanation">测速会向 Cloudflare 发起独立测试请求；结果代表到 Cloudflare 公网边缘的路径，不代表所有网站，也不代表上方网址的检测结果。</p>
      <div class="speed-test-actions">
        <button type="button" data-speed-action="quick">快速测速（约 10 秒）</button>
        <button type="button" data-speed-action="full">完整测速（约 30 秒）</button>
      </div>
      <div class="speed-test-dialog" data-speed-dialog role="dialog" aria-modal="true" hidden>
        <h3 data-speed-dialog-title>确认测速</h3>
        <p data-speed-dialog-copy></p>
        <div class="speed-test-dialog-actions">
          <button type="button" data-speed-confirm>确认并开始</button>
          <button type="button" class="secondary-button" data-speed-dismiss>取消</button>
        </div>
      </div>
      <div class="speed-test-running" data-speed-running hidden>
        <p class="speed-test-progress" data-speed-progress aria-live="polite"></p>
        <p class="speed-test-overhead">有效载荷进度不包括协议开销。</p>
        <button type="button" class="secondary-button" data-speed-cancel>取消测速</button>
      </div>
      <p class="speed-test-error" data-speed-error aria-live="polite" hidden></p>
      <article class="speed-test-result" data-speed-result hidden aria-live="polite">
        <h3>测速结果</h3>
        <dl class="speed-test-metrics">
          <div><dt>下载</dt><dd data-speed-metric="download"></dd></div>
          <div><dt>上传</dt><dd data-speed-metric="upload"></dd></div>
          <div><dt>空闲延迟（未传输数据时）</dt><dd data-speed-metric="latency"></dd></div>
          <div><dt>空闲抖动（延迟变化）</dt><dd data-speed-metric="jitter"></dd></div>
          <div data-speed-loaded="download"><dt>下载时延迟</dt><dd data-speed-metric="download-loaded"></dd></div>
          <div data-speed-loaded="upload"><dt>上传时延迟</dt><dd data-speed-metric="upload-loaded"></dd></div>
        </dl>
        <p data-speed-evidence class="speed-test-evidence"></p>
        <p data-speed-path class="speed-test-path">测速请求独立路径：UNKNOWN</p>
      </article>
    </div>
  `;
  return root;
}

type RunState = "starting" | "running" | "finishing" | "stopping";

interface SpeedRun {
  mode: SpeedMode;
  state: RunState;
  id?: string;
  plan?: SpeedMeasurementPlan;
  engine?: SpeedEngine;
  subscription: ApiSubscription | undefined;
  startedAt: number;
  usedBytes: number;
  sampleCount: number;
  observedSampleCount: number;
  localUsedBytes: number;
  phase?: SpeedSampleKind;
  submissionTail: Promise<void>;
  stopPromise?: Promise<void>;
  timer: ReturnType<typeof globalThis.setInterval> | undefined;
  deadlineTimer: ReturnType<typeof globalThis.setTimeout> | undefined;
  stopMessage?: string;
}

export function createSpeedTestController(
  api: ApiClient,
  options: SpeedTestControllerOptions = {}
): SpeedTestController {
  const root = createSpeedTestElement();
  const actionButtons = Array.from(
    root.querySelectorAll<HTMLButtonElement>("[data-speed-action]")
  );
  const dialog = root.querySelector<HTMLElement>("[data-speed-dialog]");
  const dialogTitle = root.querySelector<HTMLElement>("[data-speed-dialog-title]");
  const dialogCopy = root.querySelector<HTMLElement>("[data-speed-dialog-copy]");
  const confirmButton = root.querySelector<HTMLButtonElement>("[data-speed-confirm]");
  const dismissButton = root.querySelector<HTMLButtonElement>("[data-speed-dismiss]");
  const running = root.querySelector<HTMLElement>("[data-speed-running]");
  const progress = root.querySelector<HTMLElement>("[data-speed-progress]");
  const cancelButton = root.querySelector<HTMLButtonElement>("[data-speed-cancel]");
  const error = root.querySelector<HTMLElement>("[data-speed-error]");
  const result = root.querySelector<HTMLElement>("[data-speed-result]");
  const now = options.now ?? (() => globalThis.performance?.now?.() ?? Date.now());
  const engineFactory = options.engineFactory ?? createCloudflareSpeedEngine;
  let pendingMode: SpeedMode | undefined;
  let currentRun: SpeedRun | undefined;
  let disposed = false;

  const sameRun = (run: SpeedRun): boolean => currentRun === run;
  const liveRun = (run: SpeedRun): boolean => sameRun(run) && !disposed && run.state === "running";
  const activeRun = (run: SpeedRun): boolean => sameRun(run) && !disposed && run.state !== "stopping";

  function setActionsDisabled(disabled: boolean): void {
    for (const button of actionButtons) button.disabled = disabled;
  }

  function setDialogVisible(visible: boolean): void {
    if (dialog) dialog.hidden = !visible;
  }

  function setErrorMessage(message: string, sampleCount?: number): void {
    if (!error) return;
    error.hidden = false;
    error.textContent = sampleCount && sampleCount > 0
      ? `${message} 已收到 ${sampleCount} 条样本，未生成质量评分。`
      : message;
  }

  function clearError(): void {
    if (!error) return;
    error.hidden = true;
    error.textContent = "";
  }

  function updateProgress(run: SpeedRun): void {
    if (!progress || !run.plan) return;
    const elapsed = Math.min(Math.max(now() - run.startedAt, 0), run.plan.deadline_ms);
    const samples = Math.max(run.sampleCount, run.observedSampleCount);
    progress.textContent = `${phaseLabel(run.phase)} · 已用 ${formatElapsed(elapsed)} · 已完成测试数据量 ${formatBytes(run.usedBytes)} / ${formatBytes(run.plan.max_bytes)}（有效载荷，协议开销不计入）· 已收到 ${samples} 条样本`;
  }

  function clearRunTimers(run: SpeedRun): void {
    if (run.timer !== undefined) globalThis.clearInterval(run.timer);
    if (run.deadlineTimer !== undefined) globalThis.clearTimeout(run.deadlineTimer);
    run.timer = undefined;
    run.deadlineTimer = undefined;
  }

  function closeSubscription(run: SpeedRun): void {
    run.subscription?.close();
    run.subscription = undefined;
  }

  function finishRun(run: SpeedRun): void {
    clearRunTimers(run);
    closeSubscription(run);
    if (sameRun(run)) currentRun = undefined;
    setActionsDisabled(false);
    if (running) running.hidden = true;
  }

  function renderResult(snapshot: SpeedTestSnapshot): void {
    if (!result || !snapshot.result) return;
    const metrics = snapshot.result.metrics;
    const decision = snapshot.result.traffic_decision;
    const setMetric = (name: string, value: string): void => {
      const target = root.querySelector<HTMLElement>(`[data-speed-metric="${name}"]`);
      if (target) target.textContent = value;
    };
    setMetric("download", `${formatMbps(metrics.download_bps)} Mbps`);
    setMetric("upload", `${formatMbps(metrics.upload_bps)} Mbps`);
    setMetric("latency", `${formatMilliseconds(metrics.unloaded_latency_ms)} ms`);
    setMetric("jitter", `${formatMilliseconds(metrics.unloaded_jitter_ms)} ms`);
    const downloadLoaded = root.querySelector<HTMLElement>('[data-speed-loaded="download"]');
    const uploadLoaded = root.querySelector<HTMLElement>('[data-speed-loaded="upload"]');
    if (downloadLoaded) downloadLoaded.hidden = metrics.download_loaded_latency_ms === null;
    if (uploadLoaded) uploadLoaded.hidden = metrics.upload_loaded_latency_ms === null;
    if (metrics.download_loaded_latency_ms !== null) {
      setMetric("download-loaded", `${formatMilliseconds(metrics.download_loaded_latency_ms)} ms`);
    }
    if (metrics.upload_loaded_latency_ms !== null) {
      setMetric("upload-loaded", `${formatMilliseconds(metrics.upload_loaded_latency_ms)} ms`);
    }
    const evidence = root.querySelector<HTMLElement>("[data-speed-evidence]");
    const evidenceLevel = decision.evidence.some((item) => item?.level === "confirmed")
      ? "后端已确认"
      : decision.evidence.some((item) => item?.level === "inferred")
        ? "后端推断"
        : "无法确认";
    if (evidence) evidence.textContent = `证据：${evidenceLevel}`;
    const path = root.querySelector<HTMLElement>("[data-speed-path]");
    if (path) {
      const chain = decision.chain
        .map((node) => (typeof node?.name === "string" ? node.name : "未知节点"))
        .filter(Boolean);
      path.textContent = `${decisionLabel(decision)}${chain.length > 0 ? ` · ${chain.join(" → ")}` : ""}`;
    }
    result.hidden = false;
  }

  async function stopRun(run: SpeedRun, message: string): Promise<void> {
    if (!sameRun(run)) return;
    if (run.stopPromise) return run.stopPromise;
    run.state = "stopping";
    run.stopMessage = message;
    clearRunTimers(run);
    run.engine?.pause();
    closeSubscription(run);
    if (running) running.hidden = true;
    setErrorMessage(message, Math.max(run.sampleCount, run.observedSampleCount));
    let cancel: Promise<void>;
    try {
      cancel = run.id ? api.cancelSpeedTest(run.id) : Promise.resolve();
    } catch {
      cancel = Promise.resolve();
    }
    run.stopPromise = Promise.resolve(cancel).catch(() => undefined);
    currentRun = undefined;
    if (!disposed) setActionsDisabled(false);
  }

  function queueSamples(run: SpeedRun, samples: SpeedSample[]): void {
    if (!liveRun(run) || samples.length === 0) return;
    if (!samples.every(isValidSample)) {
      void stopRun(run, "测速样本无效，测速已停止。");
      return;
    }
    run.observedSampleCount += samples.length;
    updateProgress(run);
    for (let index = 0; index < samples.length; index += MAX_SAMPLE_BATCH) {
      const batch = samples.slice(index, index + MAX_SAMPLE_BATCH);
      const batchBytes = batch.reduce((total, sample) => total + sample.bytes, 0);
      if (!run.plan || run.localUsedBytes + batchBytes > run.plan.max_bytes) {
        void stopRun(run, "测速已达到有效载荷上限。");
        return;
      }
      run.localUsedBytes += batchBytes;
      const operation = run.submissionTail.then(async () => {
        if (!activeRun(run)) return;
        if (!run.id) throw new Error("speed test ID is unavailable");
        await api.submitSpeedSamples(run.id, batch);
        if (!activeRun(run)) return;
        run.sampleCount += batch.length;
        updateProgress(run);
      });
      run.submissionTail = operation.catch((reason) => {
        if (sameRun(run) && run.state !== "stopping") {
          void stopRun(run, "测速样本提交失败，测速已停止。");
        }
        throw reason;
      });
      void run.submissionTail.catch(() => undefined);
    }
  }

  async function finishFromEngine(run: SpeedRun, metrics: SpeedMetrics): Promise<void> {
    if (!liveRun(run)) return;
    run.state = "finishing";
    try {
      await run.submissionTail;
      if (!sameRun(run) || disposed || run.state !== "finishing" || !run.id || !run.plan) return;
      if (!isValidMetrics(metrics, run.mode)) throw new Error("测速指标不完整");
      const snapshot = await api.completeSpeedTest(run.id, metrics);
      if (!sameRun(run) || disposed || run.state !== "finishing") return;
      if (snapshot.status !== "completed" || !isValidSpeedResult(snapshot.result, run.mode)) {
        throw new Error("测速结果未通过后端校验");
      }
      renderResult(snapshot);
      finishRun(run);
    } catch {
      if (sameRun(run) && !disposed && run.state === "finishing") {
        void stopRun(run, "测速未能完成，未生成质量评分。");
      }
    }
  }

  function handleSpeedEvent(run: SpeedRun, event: { stage: string; used_bytes: number; sample_count: number }): void {
    if (!liveRun(run) || !run.plan) return;
    if (isSafeCounter(event.used_bytes)) {
      run.usedBytes = Math.max(run.usedBytes, event.used_bytes);
      run.localUsedBytes = Math.max(run.localUsedBytes, run.usedBytes);
    }
    if (isSafeCounter(event.sample_count)) run.sampleCount = Math.max(run.sampleCount, event.sample_count);
    updateProgress(run);
    if (run.usedBytes > run.plan.max_bytes) {
      void stopRun(run, "测速已达到有效载荷上限。");
      return;
    }
    if (event.stage === "failed" || event.stage === "cancelled") {
      void stopRun(run, event.stage === "cancelled" ? "测速已取消。" : "测速失败，未生成质量评分。");
    }
  }

  async function begin(mode: SpeedMode): Promise<void> {
    if (disposed || currentRun) return;
    clearError();
    if (result) result.hidden = true;
    const run: SpeedRun = {
      mode,
      state: "starting",
      startedAt: now(),
      usedBytes: 0,
      sampleCount: 0,
      observedSampleCount: 0,
      localUsedBytes: 0,
      submissionTail: Promise.resolve(),
      subscription: undefined,
      timer: undefined,
      deadlineTimer: undefined
    };
    currentRun = run;
    setActionsDisabled(true);
    if (progress) progress.textContent = `${modeLabel(mode)}正在请求 Cloudflare 测速计划…`;
    try {
      const snapshot = await api.startSpeedTest(mode);
      if (!sameRun(run) || disposed) {
        await api.cancelSpeedTest(snapshot.id).catch(() => undefined);
        return;
      }
      if (snapshot.status !== "running" || !isValidPlan(snapshot.plan, mode)) {
        throw new Error("测速计划未通过校验");
      }
      run.id = snapshot.id;
      run.plan = snapshot.plan;
      run.startedAt = now();
      run.usedBytes = isSafeCounter(snapshot.used_bytes) ? snapshot.used_bytes : 0;
      run.localUsedBytes = run.usedBytes;
      run.sampleCount = isSafeCounter(snapshot.sample_count) ? snapshot.sample_count : 0;
      run.state = "running";
      if (running) running.hidden = false;
      updateProgress(run);
      run.timer = globalThis.setInterval(() => {
        if (liveRun(run)) updateProgress(run);
      }, 100);
      run.deadlineTimer = globalThis.setTimeout(() => {
        if (activeRun(run)) void stopRun(run, "测速已达到时间上限。");
      }, snapshot.plan.deadline_ms);
      run.engine = engineFactory(snapshot.plan);
      run.engine.onPhaseChange((phase) => {
        if (!liveRun(run)) return;
        run.phase = phase;
        updateProgress(run);
      });
      run.engine.onSamples((samples) => queueSamples(run, samples));
      run.engine.onFinish((metrics) => void finishFromEngine(run, metrics));
      run.engine.onError(() => {
        if (sameRun(run) && run.state !== "stopping") void stopRun(run, "测速失败，未生成质量评分。");
      });
      run.subscription = api.subscribeToSpeedTest(
        snapshot.id,
        (event) => handleSpeedEvent(run, event),
        () => {
          if (sameRun(run) && run.state !== "stopping") void stopRun(run, "测速事件连接中断。");
        },
        (terminal) => {
          if (terminal.status === "failed" || terminal.status === "cancelled") {
            handleSpeedEvent(run, {
              stage: terminal.status,
              used_bytes: terminal.used_bytes,
              sample_count: terminal.sample_count
            });
          }
        }
      );
      run.engine.play();
    } catch {
      if (sameRun(run)) await stopRun(run, "测速未能启动。");
    }
  }

  function openConfirmation(mode: SpeedMode): void {
    if (disposed || currentRun) return;
    pendingMode = mode;
    if (dialogTitle) dialogTitle.textContent = `${modeLabel(mode)}：确认 Cloudflare 测试`;
    if (dialogCopy) {
      const maximum = mode === "quick" ? "最多约 40 MB" : "最多约 200 MB";
      dialogCopy.textContent = `本次${modeLabel(mode)}的有效载荷上限为${maximum}。Cloudflare 会看到你的公网 IP 和测试流量；结果代表到 Cloudflare 公网边缘的路径，不代表所有网站。协议开销不计入上述有效载荷。`;
    }
    setDialogVisible(true);
  }

  actionButtons.forEach((button) => {
    button.addEventListener("click", () => {
      const mode = button.dataset.speedAction;
      if (mode === "quick" || mode === "full") openConfirmation(mode);
    });
  });
  confirmButton?.addEventListener("click", () => {
    const mode = pendingMode;
    pendingMode = undefined;
    setDialogVisible(false);
    if (mode) void begin(mode);
  });
  dismissButton?.addEventListener("click", () => {
    pendingMode = undefined;
    setDialogVisible(false);
  });
  cancelButton?.addEventListener("click", () => {
    if (currentRun) void stopRun(currentRun, "测速已取消。");
  });

  const controller: SpeedTestController = {
    element: root,
    cancel: async () => {
      if (currentRun) await stopRun(currentRun, "测速已取消。");
    },
    dispose: async () => {
      if (disposed) return;
      disposed = true;
      pendingMode = undefined;
      setDialogVisible(false);
      if (currentRun) await stopRun(currentRun, "页面已关闭，测速已取消。");
    }
  };
  return controller;
}

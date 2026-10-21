import { afterEach, expect, test, vi } from "vitest";
import { createCloudflareSpeedEngine, createSpeedTestController } from "./speed-test";
import type { ApiClient, ApiSubscription } from "./api";
import type {
  SpeedEngine,
  SpeedEngineFactory
} from "./speed-test";
import type {
  SpeedMeasurementPlan,
  SpeedMeasurement,
  SpeedMetrics,
  SpeedSample,
  SpeedSampleKind,
  SpeedTestResult,
  SpeedTestSnapshot
} from "./types";

interface MockOfficialResults {
  getDownloadBandwidth: () => number | undefined;
  getUploadBandwidth: () => number | undefined;
  getUnloadedLatency: () => number | undefined;
  getUnloadedJitter: () => number | null | undefined;
  getDownLoadedLatency: () => number | undefined;
  getUpLoadedLatency: () => number | undefined;
  getUnloadedLatencyPoints: () => number[];
  getDownloadBandwidthPoints: () => Array<{ bytes: number; bps: number; duration: number; ping: number }>;
  getUploadBandwidthPoints: () => Array<{ bytes: number; bps: number; duration: number; ping: number }>;
}

interface MockOfficial {
  config: unknown;
  results: MockOfficialResults;
  onPhaseChange: (payload: { measurement: { type: string } }) => void;
  onResultsChange: (payload: { type: string }) => void;
  onFinish: (results: MockOfficialResults) => void;
  onError: (message: string) => void;
  play: ReturnType<typeof vi.fn>;
  pause: ReturnType<typeof vi.fn>;
}

const officialInstances = vi.hoisted(() => [] as MockOfficial[]);

vi.mock("@cloudflare/speedtest", () => {
  class MockSpeedTest implements MockOfficial {
    config: unknown;
    results: MockOfficialResults = {
      getDownloadBandwidth: () => undefined,
      getUploadBandwidth: () => undefined,
      getUnloadedLatency: () => undefined,
      getUnloadedJitter: () => undefined,
      getDownLoadedLatency: () => undefined,
      getUpLoadedLatency: () => undefined,
      getUnloadedLatencyPoints: () => [],
      getDownloadBandwidthPoints: () => [],
      getUploadBandwidthPoints: () => []
    };
    onPhaseChange = vi.fn();
    onResultsChange = vi.fn();
    onFinish = vi.fn();
    onError = vi.fn();
    play = vi.fn();
    pause = vi.fn();

    constructor(config: unknown) {
      this.config = config;
      officialInstances.push(this);
    }
  }

  return { default: MockSpeedTest };
});

function deferred<T>(): { promise: Promise<T>; resolve(value: T): void; reject(reason?: unknown): void } {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  return {
    promise: new Promise<T>((next, fail) => {
      resolve = next;
      reject = fail;
    }),
    resolve,
    reject
  };
}

class FakeSpeedEngine implements SpeedEngine {
  readonly playCalls: number[] = [];
  readonly pauseCalls: number[] = [];
  private phaseHandler: ((phase: SpeedSampleKind) => void) | undefined;
  private samplesHandler: ((samples: SpeedSample[]) => void) | undefined;
  private finishHandler: ((metrics: SpeedMetrics) => void) | undefined;
  private errorHandler: (() => void) | undefined;

  play(): void {
    this.playCalls.push(Date.now());
  }

  pause(): void {
    this.pauseCalls.push(Date.now());
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

  emitPhase(phase: SpeedSampleKind): void {
    this.phaseHandler?.(phase);
  }

  emitSamples(samples: SpeedSample[]): void {
    this.samplesHandler?.(samples);
  }

  emitFinish(metrics: SpeedMetrics): void {
    this.finishHandler?.(metrics);
  }

  emitError(): void {
    this.errorHandler?.();
  }
}

const metrics: SpeedMetrics = {
  download_bps: 82_000_000,
  upload_bps: 18_000_000,
  unloaded_latency_ms: 24.5,
  unloaded_jitter_ms: 3.2,
  download_loaded_latency_ms: 61.4,
  upload_loaded_latency_ms: 48.1
};

const speedResult: SpeedTestResult = {
  provider: "cloudflare",
  mode: "full",
  metrics,
  used_bytes: 171_600_000,
  traffic_decision: {
    kind: "direct",
    mode: "rule",
    tun_enabled: false,
    rule: null,
    chain: [],
    evidence: [{ level: "confirmed", source: "mihomo", summary: "测速请求确认直连" }]
  }
};

function plan(mode: "quick" | "full"): SpeedMeasurementPlan {
  return {
    mode,
    deadline_ms: mode === "quick" ? 10_000 : 30_000,
    max_bytes: mode === "quick" ? 40_000_000 : 200_000_000,
    include_loaded_latency: mode === "full",
    measurements: [
      { type: "latency", numPackets: 8 },
      { type: "download", bytes: mode === "quick" ? 10_000_000 : 50_000_000, count: 2 },
      { type: "upload", bytes: mode === "quick" ? 5_000_000 : 25_000_000, count: 2 }
    ]
  };
}

function runningSnapshot(mode: "quick" | "full", id = "speed-1"): SpeedTestSnapshot {
  return {
    id,
    status: "running",
    mode,
    plan: plan(mode),
    used_bytes: 0,
    sample_count: 0,
    result: null,
    error: null
  };
}

function completedSnapshot(mode: "quick" | "full", id = "speed-1"): SpeedTestSnapshot {
  return {
    ...runningSnapshot(mode, id),
    status: "completed",
    used_bytes: speedResult.used_bytes,
    sample_count: 3,
    result: { ...speedResult, mode },
    error: null
  };
}

function sample(kind: SpeedSample["kind"], bytes: number, value: number): SpeedSample {
  return {
    kind,
    bytes,
    bps: kind === "latency" ? null : value,
    duration_ms: kind === "latency" ? value : 100,
    latency_ms: kind === "latency" ? value : null
  };
}

interface HarnessOptions {
  snapshots?: SpeedTestSnapshot[];
  submitPromise?: Promise<void>;
  completePromise?: Promise<SpeedTestSnapshot>;
  cancelPromise?: Promise<void>;
}

function makeHarness(mode: "quick" | "full" = "full", options: HarnessOptions = {}) {
  const firstEngine = new FakeSpeedEngine();
  const engines: FakeSpeedEngine[] = [firstEngine];
  const factoryPlans: SpeedMeasurementPlan[] = [];
  const subscriptions: Array<{ close: ReturnType<typeof vi.fn>; emit: (event: { used_bytes: number; sample_count: number; sequence: number; stage: "started" | "samples" | "completed" | "failed" | "cancelled" }) => void }> = [];
  const sampleCalls: SpeedSample[][] = [];
  const completeCalls: SpeedMetrics[] = [];
  const cancelCalls: string[] = [];
  let startCount = 0;
  const api = {
    startSpeedTest: vi.fn(async (requestedMode: "quick" | "full") => {
      const snapshot = options.snapshots?.[startCount] ?? runningSnapshot(requestedMode, `speed-${startCount + 1}`);
      startCount += 1;
      return snapshot;
    }),
    getSpeedTest: vi.fn(async () => runningSnapshot(mode)),
    subscribeToSpeedTest: vi.fn((_id: string, onEvent: (event: { used_bytes: number; sample_count: number; sequence: number; stage: "started" | "samples" | "completed" | "failed" | "cancelled" }) => void) => {
      const close = vi.fn();
      subscriptions.push({
        close,
        emit: onEvent
      });
      const subscription: ApiSubscription = { close, done: Promise.resolve() };
      return subscription;
    }),
    submitSpeedSamples: vi.fn(async (_id: string, next: SpeedSample[]) => {
      if (options.submitPromise) return options.submitPromise;
      sampleCalls.push(next);
    }),
    completeSpeedTest: vi.fn(async (_id: string, next: SpeedMetrics) => {
      completeCalls.push(next);
      if (options.completePromise) return options.completePromise;
      return completedSnapshot(mode);
    }),
    cancelSpeedTest: vi.fn(async (id: string) => {
      cancelCalls.push(id);
      if (options.cancelPromise) return options.cancelPromise;
    })
  } as unknown as ApiClient;
  const engineFactory: SpeedEngineFactory = (nextPlan) => {
    const engine = engines[factoryPlans.length] ?? new FakeSpeedEngine();
    if (!engines[factoryPlans.length]) engines.push(engine);
    factoryPlans.push(nextPlan);
    return engine;
  };
  const controller = createSpeedTestController(api, { engineFactory });
  const confirm = (): void => {
    controller.element.querySelector<HTMLButtonElement>("[data-speed-confirm]")?.click();
  };
  const choose = async (nextMode: "quick" | "full" = mode): Promise<void> => {
    controller.element.querySelector<HTMLButtonElement>(`[data-speed-action=\"${nextMode}\"]`)?.click();
    confirm();
    await vi.waitFor(() => expect(factoryPlans).toHaveLength(1));
    await vi.waitFor(() => expect(engines[0]?.playCalls).toHaveLength(1));
  };
  return {
    api,
    cancelCalls,
    choose,
    completeCalls,
    confirm,
    controller,
    engine: firstEngine,
    engines,
    factoryPlans,
    sampleCalls,
    subscriptions
  };
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  officialInstances.length = 0;
});

test("wraps the official engine with the exact privacy, deadline, and loaded-latency configuration", () => {
  const quickPlan = plan("quick");
  createCloudflareSpeedEngine(quickPlan);

  expect(officialInstances).toHaveLength(1);
  expect(officialInstances[0]!.config).toEqual({
    autoStart: false,
    measurements: quickPlan.measurements,
    measureDownloadLoadedLatency: false,
    measureUploadLoadedLatency: false,
    logMeasurementApiUrl: null,
    logAimApiUrl: null,
    includeCredentials: false,
    bandwidthFinishRequestDuration: 120_000,
    bandwidthAbortRequestDuration: quickPlan.deadline_ms
  });

  const fullPlan = plan("full");
  createCloudflareSpeedEngine(fullPlan);
  expect(officialInstances[1]!.config).toEqual({
    autoStart: false,
    measurements: fullPlan.measurements,
    measureDownloadLoadedLatency: true,
    measureUploadLoadedLatency: true,
    logMeasurementApiUrl: null,
    logAimApiUrl: null,
    includeCredentials: false,
    bandwidthFinishRequestDuration: 120_000,
    bandwidthAbortRequestDuration: fullPlan.deadline_ms
  });
});

test("translates only approved point arrays once using per-array cursors", () => {
  const engine = createCloudflareSpeedEngine(plan("full"));
  const official = officialInstances[0]!;
  const onSamples = vi.fn();
  engine.onSamples(onSamples);
  official.results.getUnloadedLatencyPoints = () => [12, 14];
  official.results.getDownloadBandwidthPoints = () => [
    { bytes: 10_000, bps: 2_000_000, duration: 100, ping: 18 }
  ];
  official.results.getUploadBandwidthPoints = () => [];
  official.onResultsChange({ type: "latency" });
  official.onResultsChange({ type: "download" });
  official.onResultsChange({ type: "latency" });
  expect(onSamples).toHaveBeenNthCalledWith(1, [
    { kind: "latency", bytes: 0, bps: null, duration_ms: 12, latency_ms: 12 },
    { kind: "latency", bytes: 0, bps: null, duration_ms: 14, latency_ms: 14 }
  ]);
  expect(onSamples).toHaveBeenNthCalledWith(2, [
    { kind: "download", bytes: 10_000, bps: 2_000_000, duration_ms: 100, latency_ms: 18 }
  ]);
  expect(onSamples).toHaveBeenCalledTimes(2);
});

test("finishes with the six approved getters and null loaded values in quick mode", () => {
  const engine = createCloudflareSpeedEngine(plan("quick"));
  const official = officialInstances[0]!;
  official.results.getDownloadBandwidth = () => 82_000_000;
  official.results.getUploadBandwidth = () => 18_000_000;
  official.results.getUnloadedLatency = () => 24.5;
  official.results.getUnloadedJitter = () => 3.2;
  official.results.getDownLoadedLatency = () => 61.4;
  official.results.getUpLoadedLatency = () => 48.1;
  const onFinish = vi.fn();
  engine.onFinish(onFinish);
  official.onFinish(official.results);

  expect(onFinish).toHaveBeenCalledWith({
    download_bps: 82_000_000,
    upload_bps: 18_000_000,
    unloaded_latency_ms: 24.5,
    unloaded_jitter_ms: 3.2,
    download_loaded_latency_ms: null,
    upload_loaded_latency_ms: null
  });
});

test("creates no engine before explicit Cloudflare confirmation and discloses exact quick/full budgets", () => {
  const harness = makeHarness();
  document.body.append(harness.controller.element);

  expect(harness.factoryPlans).toHaveLength(0);
  harness.controller.element.querySelector<HTMLButtonElement>('[data-speed-action="quick"]')?.click();
  expect(harness.factoryPlans).toHaveLength(0);
  expect(harness.controller.element.textContent).toContain("Cloudflare");
  expect(harness.controller.element.textContent).toContain("最多约 40 MB");
  expect(harness.controller.element.textContent).toContain("代表到 Cloudflare 公网边缘的路径");
  expect(harness.controller.element.textContent).toContain("不代表所有网站");

  harness.controller.element.querySelector<HTMLButtonElement>("[data-speed-dismiss]")?.click();
  harness.controller.element.querySelector<HTMLButtonElement>('[data-speed-action="full"]')?.click();
  expect(harness.factoryPlans).toHaveLength(0);
  expect(harness.controller.element.textContent).toContain("最多约 200 MB");
});

test("uses server bytes for progress, batches at most 16 samples, and flushes before exact completion", async () => {
  const harness = makeHarness();
  document.body.append(harness.controller.element);
  await harness.choose();

  expect(harness.factoryPlans[0]!).toEqual(plan("full"));
  expect(harness.engine.playCalls).toHaveLength(1);
  harness.subscriptions[0]!.emit({ sequence: 1, stage: "samples", used_bytes: 12_345, sample_count: 17 });
  expect(harness.controller.element.querySelector("[data-speed-progress]")?.textContent).toContain("12,345");
  expect(harness.controller.element.querySelector("[data-speed-progress]")?.textContent).toContain("200,000,000");

  const firstSamples = Array.from({ length: 17 }, (_, index) => sample("download", 100, index + 1));
  const pendingSubmit = deferred<void>();
  vi.mocked(harness.api.submitSpeedSamples).mockImplementationOnce(() => pendingSubmit.promise);
  harness.engine.emitSamples(firstSamples);
  harness.engine.emitFinish(metrics);

  await Promise.resolve();
  expect(harness.completeCalls).toHaveLength(0);
  expect(harness.sampleCalls).toHaveLength(0);
  await vi.waitFor(() => expect(vi.mocked(harness.api.submitSpeedSamples)).toHaveBeenCalledTimes(1));
  expect(vi.mocked(harness.api.submitSpeedSamples).mock.calls[0]![1]).toHaveLength(16);

  pendingSubmit.resolve();
  await vi.waitFor(() => expect(vi.mocked(harness.api.submitSpeedSamples)).toHaveBeenCalledTimes(2));
  expect(vi.mocked(harness.api.submitSpeedSamples).mock.calls[1]![1]).toHaveLength(1);
  await vi.waitFor(() => expect(harness.completeCalls).toEqual([metrics]));
  expect(harness.sampleCalls).toHaveLength(1);
  expect(harness.controller.element.textContent).toContain("82.0 Mbps");
  expect(harness.controller.element.textContent).toContain("测速请求独立路径：DIRECT");
});

test("cancels with pause, DELETE, and SSE close, then ignores late engine callbacks", async () => {
  const harness = makeHarness("quick");
  document.body.append(harness.controller.element);
  await harness.choose("quick");

  harness.controller.element.querySelector<HTMLButtonElement>("[data-speed-cancel]")?.click();
  await vi.waitFor(() => expect(harness.cancelCalls).toEqual(["speed-1"]));
  expect(harness.engine.pauseCalls).toHaveLength(1);
  expect(harness.subscriptions[0]!.close).toHaveBeenCalledTimes(1);

  harness.engine.emitSamples([sample("download", 100, 1)]);
  harness.engine.emitFinish(metrics);
  harness.engine.emitError();
  await Promise.resolve();
  expect(vi.mocked(harness.api.submitSpeedSamples)).not.toHaveBeenCalled();
  expect(harness.completeCalls).toHaveLength(0);
  expect(harness.controller.element.querySelector("[data-speed-result]")?.hasAttribute("hidden")).toBe(true);
});

test("disposes a running test and refuses a second overlapping start", async () => {
  const harness = makeHarness();
  document.body.append(harness.controller.element);
  await harness.choose("full");
  harness.controller.element.querySelector<HTMLButtonElement>('[data-speed-action="quick"]')?.click();
  harness.confirm();

  expect(harness.api.startSpeedTest).toHaveBeenCalledTimes(1);
  await harness.controller.dispose();
  expect(harness.engine.pauseCalls).toHaveLength(1);
  expect(harness.cancelCalls).toEqual(["speed-1"]);
  expect(harness.subscriptions[0]!.close).toHaveBeenCalledTimes(1);
});

test("keeps partial samples after engine failure but never renders a final quality grade", async () => {
  const harness = makeHarness("quick");
  document.body.append(harness.controller.element);
  await harness.choose("quick");
  harness.engine.emitSamples([sample("latency", 0, 24.5)]);
  await vi.waitFor(() => expect(vi.mocked(harness.api.submitSpeedSamples)).toHaveBeenCalledTimes(1));
  harness.engine.emitError();

  await vi.waitFor(() => expect(harness.cancelCalls).toEqual(["speed-1"]));
  expect(harness.controller.element.textContent).toContain("已收到 1 条样本");
  expect(harness.controller.element.querySelector<HTMLElement>("[data-speed-result]")?.hidden).toBe(true);
  expect(harness.completeCalls).toHaveLength(0);
});

test("stops on a server-reported payload budget and never renders a backend-invalid result", async () => {
  const harness = makeHarness("quick");
  document.body.append(harness.controller.element);
  await harness.choose("quick");
  harness.subscriptions[0]!.emit({ sequence: 2, stage: "samples", used_bytes: 40_000_001, sample_count: 1 });

  await vi.waitFor(() => expect(harness.cancelCalls).toEqual(["speed-1"]));
  expect(harness.engine.pauseCalls).toHaveLength(1);
  expect(harness.controller.element.querySelector("[data-speed-result]")?.hasAttribute("hidden")).toBe(true);
});

test("enforces the payload budget locally before submitting oversized configured samples", async () => {
  const harness = makeHarness("quick");
  document.body.append(harness.controller.element);
  await harness.choose("quick");
  harness.engine.emitSamples([sample("download", 40_000_001, 1)]);

  await vi.waitFor(() => expect(harness.cancelCalls).toEqual(["speed-1"]));
  expect(harness.engine.pauseCalls).toHaveLength(1);
  expect(harness.api.submitSpeedSamples).not.toHaveBeenCalled();
});

test("only renders the validated backend result, including its independent UNKNOWN path", async () => {
  const harness = makeHarness();
  vi.mocked(harness.api.completeSpeedTest).mockResolvedValueOnce({
    ...completedSnapshot("full"),
    result: {
      ...speedResult,
      metrics: { ...metrics, download_bps: 1_000_000 },
      traffic_decision: {
        ...speedResult.traffic_decision,
        kind: "unknown",
        evidence: [{ level: "unknown", source: "mihomo", summary: "测速路径无法确认" }]
      }
    }
  });
  document.body.append(harness.controller.element);
  await harness.choose();
  harness.engine.emitFinish({ ...metrics, download_bps: 99_000_000 });

  await vi.waitFor(() => expect(harness.controller.element.querySelector("[data-speed-result]")?.hasAttribute("hidden")).toBe(false));
  expect(harness.controller.element.textContent).toContain("1.0 Mbps");
  expect(harness.controller.element.textContent).toContain("测速请求独立路径：UNKNOWN");
  expect(harness.controller.element.textContent).not.toContain("99.0 Mbps");
});

test("cancels at the server deadline before late finish callbacks can grade the run", async () => {
  vi.useFakeTimers();
  const harness = makeHarness("quick");
  document.body.append(harness.controller.element);
  const action = harness.controller.element.querySelector<HTMLButtonElement>('[data-speed-action="quick"]');
  action?.click();
  harness.confirm();
  for (let index = 0; index < 6; index += 1) await Promise.resolve();

  expect(harness.factoryPlans).toHaveLength(1);
  vi.advanceTimersByTime(10_000);
  for (let index = 0; index < 6; index += 1) await Promise.resolve();
  expect(harness.cancelCalls).toEqual(["speed-1"]);
  expect(harness.engine.pauseCalls).toHaveLength(1);

  harness.engine.emitFinish(metrics);
  await Promise.resolve();
  expect(harness.completeCalls).toHaveLength(0);
});

test("cancels after completion submission failure and keeps the result hidden", async () => {
  const harness = makeHarness();
  vi.mocked(harness.api.completeSpeedTest).mockRejectedValueOnce(new Error("backend rejected"));
  document.body.append(harness.controller.element);
  await harness.choose();
  harness.engine.emitFinish(metrics);

  await vi.waitFor(() => expect(harness.cancelCalls).toEqual(["speed-1"]));
  expect(harness.engine.pauseCalls).toHaveLength(1);
  expect(harness.subscriptions[0]!.close).toHaveBeenCalledTimes(1);
  expect(harness.controller.element.querySelector<HTMLElement>("[data-speed-result]")?.hidden).toBe(true);
});

test("survives 50 cancellation and late-callback race rounds without duplicate writes", async () => {
  for (let round = 0; round < 50; round += 1) {
    const harness = makeHarness("quick");
    document.body.append(harness.controller.element);
    await harness.choose("quick");
    const cancel = harness.controller.cancel();
    harness.engine.emitSamples([sample("download", 100, round + 1)]);
    harness.engine.emitFinish(metrics);
    harness.engine.emitError();
    await cancel;
    await Promise.resolve();
    expect(harness.cancelCalls).toEqual(["speed-1"]);
    expect(harness.completeCalls).toHaveLength(0);
    expect(vi.mocked(harness.api.submitSpeedSamples)).not.toHaveBeenCalled();
    harness.controller.element.remove();
  }
});

test("rejects a quick plan over the consent ceiling before creating an engine or SSE subscription", async () => {
  const snapshot = runningSnapshot("quick", "invalid-max");
  snapshot.plan = { ...snapshot.plan, max_bytes: 40_000_001 };
  const harness = makeHarness("quick", { snapshots: [snapshot] });
  document.body.append(harness.controller.element);
  harness.controller.element.querySelector<HTMLButtonElement>('[data-speed-action="quick"]')?.click();
  harness.confirm();

  await vi.waitFor(() => expect(harness.controller.element.textContent).toContain("测速未能启动"));
  expect(harness.factoryPlans).toHaveLength(0);
  expect(harness.api.subscribeToSpeedTest).not.toHaveBeenCalled();
  expect(harness.api.submitSpeedSamples).not.toHaveBeenCalled();
  expect(harness.api.completeSpeedTest).not.toHaveBeenCalled();
});

const invalidMeasurementCases: Array<{ name: string; measurements: SpeedMeasurement[] }> = [
  {
    name: "an oversized single transfer",
    measurements: [{ type: "download", bytes: 40_000_001, count: 1 }]
  },
  {
    name: "an oversized aggregate transfer",
    measurements: [
      { type: "download", bytes: 20_000_001, count: 2 },
      { type: "upload", bytes: 1, count: 1 }
    ]
  },
  {
    name: "an overflowed transfer product",
    measurements: [{ type: "download", bytes: Number.MAX_SAFE_INTEGER, count: 2 }]
  }
];

test.each(invalidMeasurementCases)("rejects $name before Cloudflare engine construction", async ({ measurements }) => {
  const snapshot = runningSnapshot("quick", "invalid-measurements");
  snapshot.plan = { ...snapshot.plan, measurements };
  const harness = makeHarness("quick", { snapshots: [snapshot] });
  document.body.append(harness.controller.element);
  harness.controller.element.querySelector<HTMLButtonElement>('[data-speed-action="quick"]')?.click();
  harness.confirm();

  await vi.waitFor(() => expect(harness.controller.element.textContent).toContain("测速未能启动"));
  expect(harness.factoryPlans).toHaveLength(0);
  expect(harness.api.subscribeToSpeedTest).not.toHaveBeenCalled();
});

test("rejects a plan whose selected mode and loaded-latency capability disagree", async () => {
  const snapshot = runningSnapshot("quick", "invalid-mode-capability");
  snapshot.plan = { ...snapshot.plan, mode: "full", include_loaded_latency: true };
  const harness = makeHarness("quick", { snapshots: [snapshot] });
  document.body.append(harness.controller.element);
  harness.controller.element.querySelector<HTMLButtonElement>('[data-speed-action="quick"]')?.click();
  harness.confirm();

  await vi.waitFor(() => expect(harness.controller.element.textContent).toContain("测速未能启动"));
  expect(harness.factoryPlans).toHaveLength(0);
  expect(harness.api.subscribeToSpeedTest).not.toHaveBeenCalled();
});

test("keeps the wall-clock deadline active while queued sample submission never settles", async () => {
  vi.useFakeTimers();
  const heldSubmit = deferred<void>();
  const harness = makeHarness("quick", { submitPromise: heldSubmit.promise });
  document.body.append(harness.controller.element);
  const action = harness.controller.element.querySelector<HTMLButtonElement>('[data-speed-action="quick"]');
  action?.click();
  harness.confirm();
  for (let index = 0; index < 6; index += 1) await Promise.resolve();
  expect(harness.engines).toHaveLength(1);

  harness.engines[0]!.emitSamples([sample("download", 100, 1)]);
  for (let index = 0; index < 4; index += 1) await Promise.resolve();
  expect(harness.api.submitSpeedSamples).toHaveBeenCalledTimes(1);
  harness.engines[0]!.emitFinish(metrics);
  vi.advanceTimersByTime(10_000);
  for (let index = 0; index < 6; index += 1) await Promise.resolve();

  expect(harness.engines[0]!.pauseCalls).toHaveLength(1);
  expect(harness.subscriptions[0]!.close).toHaveBeenCalledTimes(1);
  expect(harness.cancelCalls).toEqual(["speed-1"]);
  const progressBeforeLateSubmit = harness.controller.element.querySelector<HTMLElement>("[data-speed-progress]")?.textContent;
  heldSubmit.resolve();
  await Promise.resolve();
  await Promise.resolve();
  expect(harness.controller.element.querySelector<HTMLElement>("[data-speed-progress]")?.textContent).toBe(progressBeforeLateSubmit);
});

test("keeps the wall-clock deadline active while completion POST never settles", async () => {
  vi.useFakeTimers();
  const heldComplete = deferred<SpeedTestSnapshot>();
  const harness = makeHarness("quick", { completePromise: heldComplete.promise });
  document.body.append(harness.controller.element);
  const action = harness.controller.element.querySelector<HTMLButtonElement>('[data-speed-action="quick"]');
  action?.click();
  harness.confirm();
  for (let index = 0; index < 6; index += 1) await Promise.resolve();
  harness.engines[0]!.emitFinish({ ...metrics, download_loaded_latency_ms: null, upload_loaded_latency_ms: null });
  for (let index = 0; index < 6; index += 1) await Promise.resolve();
  expect(harness.api.completeSpeedTest).toHaveBeenCalledTimes(1);

  vi.advanceTimersByTime(10_000);
  for (let index = 0; index < 6; index += 1) await Promise.resolve();
  expect(harness.engines[0]!.pauseCalls).toHaveLength(1);
  expect(harness.subscriptions[0]!.close).toHaveBeenCalledTimes(1);
  expect(harness.cancelCalls).toEqual(["speed-1"]);
  heldComplete.resolve(completedSnapshot("quick"));
  await Promise.resolve();
  expect(harness.controller.element.querySelector<HTMLElement>("[data-speed-result]")?.hidden).toBe(true);
});

test("cancellation suppresses held completion, tolerates stalled DELETE, and releases the next run", async () => {
  const heldComplete = deferred<SpeedTestSnapshot>();
  const heldCancel = deferred<void>();
  const harness = makeHarness("full", {
    completePromise: heldComplete.promise,
    cancelPromise: heldCancel.promise
  });
  document.body.append(harness.controller.element);
  await harness.choose("full");
  harness.engines[0]!.emitFinish(metrics);
  await vi.waitFor(() => expect(harness.api.completeSpeedTest).toHaveBeenCalledTimes(1));

  void harness.controller.cancel();
  await Promise.resolve();
  expect(harness.cancelCalls).toEqual(["speed-1"]);
  expect(harness.controller.element.querySelector<HTMLElement>("[data-speed-result]")?.hidden).toBe(true);

  harness.controller.element.querySelector<HTMLButtonElement>('[data-speed-action="quick"]')?.click();
  harness.confirm();
  await vi.waitFor(() => expect(harness.engines).toHaveLength(2));
  expect(harness.api.startSpeedTest).toHaveBeenCalledTimes(2);

  heldComplete.resolve(completedSnapshot("full"));
  await Promise.resolve();
  await Promise.resolve();
  expect(harness.controller.element.querySelector<HTMLElement>("[data-speed-result]")?.hidden).toBe(true);
  heldCancel.reject(new Error("DELETE stalled"));
  await Promise.resolve();
});

test("survives 100 held-completion cancellation races with stalled DELETE", async () => {
  for (let round = 0; round < 100; round += 1) {
    const heldComplete = deferred<SpeedTestSnapshot>();
    const heldCancel = deferred<void>();
    const harness = makeHarness("full", {
      completePromise: heldComplete.promise,
      cancelPromise: heldCancel.promise
    });
    document.body.append(harness.controller.element);
    await harness.choose("full");
    harness.engines[0]!.emitFinish(metrics);
    await vi.waitFor(() => expect(harness.api.completeSpeedTest).toHaveBeenCalledTimes(1));

    void harness.controller.cancel();
    await Promise.resolve();
    harness.controller.element.querySelector<HTMLButtonElement>('[data-speed-action="quick"]')?.click();
    harness.confirm();
    await vi.waitFor(() => expect(harness.engines).toHaveLength(2));

    heldComplete.resolve(completedSnapshot("full"));
    await Promise.resolve();
    await Promise.resolve();
    expect(harness.controller.element.querySelector<HTMLElement>("[data-speed-result]")?.hidden).toBe(true);
    heldCancel.reject(new Error(`DELETE race ${round}`));
    await Promise.resolve();
    harness.controller.element.remove();
  }
}, 30_000);

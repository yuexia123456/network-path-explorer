import type {
  MihomoRuntime,
  NetworkOverviewResponse,
  RouteTraceSnapshot,
  RunSnapshot,
  SpeedEvent,
  SpeedMetrics,
  SpeedMode,
  SpeedSample,
  SpeedTestSnapshot,
  StageEvent,
  TraceEvent,
  TraceRequestKind,
  TrafficNodeKind,
  UrlDiagnosticResult
} from "./types";

interface StartDiagnosticResponse {
  run_id: string;
}

export interface ApiSubscription {
  close(): void;
  done: Promise<void>;
}

export interface ApiClient {
  startDiagnostic(url: string): Promise<string>;
  getRun(runId: string): Promise<RunSnapshot>;
  getNetworkOverview(): Promise<NetworkOverviewResponse>;
  setMihomoController(url: string, secret: string): Promise<MihomoRuntime>;
  resetMihomoController(): Promise<MihomoRuntime>;
  startRouteTrace(runId: string, kind: TraceRequestKind): Promise<RouteTraceSnapshot>;
  getRouteTrace(runId: string): Promise<RouteTraceSnapshot>;
  subscribeToRun(
    runId: string,
    onStage: (stage: StageEvent) => void,
    onError: () => void,
    onTerminal: (snapshot: RunSnapshot) => void
  ): ApiSubscription;
  subscribeToRouteTrace(
    runId: string,
    onEvent: (event: TraceEvent) => void,
    onError: () => void,
    onTerminal: (snapshot: RouteTraceSnapshot) => void
  ): ApiSubscription;
  cancelRouteTrace(runId: string): Promise<void>;
  startSpeedTest(mode: SpeedMode): Promise<SpeedTestSnapshot>;
  getSpeedTest(id: string): Promise<SpeedTestSnapshot>;
  subscribeToSpeedTest(
    id: string,
    onEvent: (event: SpeedEvent) => void,
    onError: () => void,
    onTerminal: (snapshot: SpeedTestSnapshot) => void
  ): ApiSubscription;
  submitSpeedSamples(id: string, samples: SpeedSample[]): Promise<void>;
  completeSpeedTest(id: string, metrics: SpeedMetrics): Promise<SpeedTestSnapshot>;
  cancelSpeedTest(id: string): Promise<void>;
}

export interface ApiClientOptions {
  fetchImpl?: typeof fetch;
  retryDelayMs?: number;
  maxSseReconnects?: number;
  maxSnapshotPolls?: number;
  batchIdFactory?: () => string;
}

interface SequencedEvent {
  sequence: number;
}

interface SseEnvelope<T> {
  event: string;
  data: T;
}

interface SubscribeToJobOptions<TEvent extends SequencedEvent, TSnapshot> {
  eventsPath: string;
  snapshotPath: string;
  eventName: string;
  isTerminal(snapshot: TSnapshot): boolean;
  onEvent(event: TEvent): void;
  onTerminal(snapshot: TSnapshot): void;
  onError(): void;
  fetchImpl: typeof fetch;
  sessionHeaders: HeadersInit;
  request: <T>(path: string, init?: RequestInit) => Promise<T>;
  delay(signal: AbortSignal): Promise<boolean>;
  maxSseReconnects: number;
  maxSnapshotPolls: number;
}

function isTerminalEvent(event: SequencedEvent & { stage?: string }): boolean {
  return event.stage === "completed" || event.stage === "failed" || event.stage === "cancelled";
}

function parseSseMessage<T>(message: string): SseEnvelope<T> | null {
  const lines = message.replaceAll("\r\n", "\n").replaceAll("\r", "\n").split("\n");
  const event = lines.find((line) => line.startsWith("event:"))?.slice("event:".length).trim();
  const payload = lines
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice("data:".length).replace(/^ /, ""))
    .join("\n");
  if (!event || !payload) return null;
  return { event, data: JSON.parse(payload) as T };
}

function findSseBoundary(buffer: string): { index: number; length: number } | null {
  let boundary: { index: number; length: number } | null = null;
  for (const delimiter of ["\r\n\r\n", "\n\n", "\r\r"]) {
    const index = buffer.indexOf(delimiter);
    if (index !== -1 && (boundary === null || index < boundary.index)) {
      boundary = { index, length: delimiter.length };
    }
  }
  return boundary;
}

async function readSse<TEvent extends SequencedEvent & { stage?: string }>(
  response: Response,
  signal: AbortSignal,
  eventName: string,
  onEvent: (event: TEvent) => void
): Promise<boolean> {
  if (!response.body) throw new Error("SSE response body is missing");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let resolveAbort: (() => void) | undefined;
  const abortPromise = new Promise<{ done: true; value: undefined }>((resolve) => {
    resolveAbort = () => resolve({ done: true, value: undefined });
  });
  let cancelStarted = false;
  const cancelReader = (): void => {
    if (cancelStarted) return;
    cancelStarted = true;
    try {
      void reader.cancel().catch(() => undefined);
    } catch {
      // A custom stream may throw synchronously while it is already closing.
    }
  };
  const onAbort = (): void => {
    cancelReader();
    resolveAbort?.();
  };
  signal.addEventListener("abort", onAbort, { once: true });
  if (signal.aborted) {
    cancelReader();
    resolveAbort?.();
  }
  try {
    while (!signal.aborted) {
      const chunk = await Promise.race([reader.read(), abortPromise]);
      if (chunk.done || signal.aborted || !chunk.value) break;
      buffer += decoder.decode(chunk.value, { stream: true });
      let boundary = findSseBoundary(buffer);
      while (boundary !== null) {
        if (signal.aborted) return false;
        const message = buffer.slice(0, boundary.index);
        buffer = buffer.slice(boundary.index + boundary.length);
        const envelope = parseSseMessage<TEvent>(message);
        if (envelope?.event === eventName && !signal.aborted) {
          onEvent(envelope.data);
          if (isTerminalEvent(envelope.data)) {
            cancelReader();
            return true;
          }
        }
        boundary = findSseBoundary(buffer);
      }
    }
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
  return false;
}

function wait(milliseconds: number, signal: AbortSignal): Promise<boolean> {
  if (signal.aborted) return Promise.resolve(false);
  return new Promise((resolve) => {
    const onAbort = (): void => {
      globalThis.clearTimeout(timeout);
      resolve(false);
    };
    const timeout = globalThis.setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve(true);
    }, milliseconds);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

function subscribeToJob<TEvent extends SequencedEvent & { stage?: string }, TSnapshot>({
  eventsPath,
  snapshotPath,
  eventName,
  isTerminal,
  onEvent,
  onTerminal,
  onError,
  fetchImpl,
  sessionHeaders,
  request,
  delay,
  maxSseReconnects,
  maxSnapshotPolls
}: SubscribeToJobOptions<TEvent, TSnapshot>): ApiSubscription {
  const controller = new AbortController();
  let lastSequence = -1;
  let settled = false;
  const settleTerminal = (snapshot: TSnapshot): void => {
    if (settled || controller.signal.aborted || !isTerminal(snapshot)) return;
    settled = true;
    onTerminal(snapshot);
  };
  const pollTerminal = async (): Promise<boolean> => {
    for (let poll = 0; poll <= maxSnapshotPolls; poll += 1) {
      if (controller.signal.aborted) return false;
      try {
        const snapshot = await request<TSnapshot>(snapshotPath, { signal: controller.signal });
        if (controller.signal.aborted) return false;
        if (isTerminal(snapshot)) {
          settleTerminal(snapshot);
          return !controller.signal.aborted;
        }
      } catch {
        return false;
      }
      if (poll < maxSnapshotPolls && !(await delay(controller.signal))) return false;
    }
    return false;
  };
  const done = (async (): Promise<void> => {
    for (let attempt = 0; attempt <= maxSseReconnects && !controller.signal.aborted; attempt += 1) {
      let terminalPolled = false;
      try {
        const response = await fetchImpl(eventsPath, {
          headers: sessionHeaders,
          signal: controller.signal
        });
        if (!response.ok) throw new Error(`SSE request failed: ${response.status}`);
        const receivedTerminalEvent = await readSse<TEvent>(
          response,
          controller.signal,
          eventName,
          (event) => {
            if (controller.signal.aborted || settled || event.sequence <= lastSequence) return;
            lastSequence = event.sequence;
            onEvent(event);
          }
        );
        if (receivedTerminalEvent) {
          terminalPolled = true;
          if (await pollTerminal()) return;
        }
      } catch {
        if (controller.signal.aborted) return;
      }

      if (controller.signal.aborted) return;
      if (!terminalPolled && (await pollTerminal())) return;
      if (attempt < maxSseReconnects && !(await delay(controller.signal))) return;
    }
    if (!controller.signal.aborted && !settled) onError();
  })();
  return { close: () => controller.abort(), done };
}

interface SpeedLedger {
  usedBytes: number;
  sampleCount: number;
  status: SpeedTestSnapshot["status"];
  needsReconcile: boolean;
  terminal: boolean;
  version: number;
  tail: Promise<void>;
  pendingBatch?: PendingSpeedBatch;
}

interface PendingSpeedBatch {
  version: number;
  batchId: string;
  body: string;
  usedBytes: number;
  sampleCount: number;
}

type SpeedBatchSendResult =
  | { kind: "accepted" }
  | { kind: "rejected"; error: unknown };

class ApiHttpError extends Error {
  readonly status: number;

  constructor(status: number) {
    super(`API request failed: ${status}`);
    this.name = "ApiHttpError";
    this.status = status;
  }
}

function isSpeedTerminal(status: SpeedTestSnapshot["status"]): boolean {
  return status === "completed" || status === "failed" || status === "cancelled";
}

function isSafeCounter(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function hasValidSpeedCounters(snapshot: SpeedTestSnapshot): boolean {
  return isSafeCounter(snapshot.used_bytes) && isSafeCounter(snapshot.sample_count);
}

function createSecureBatchId(): string {
  if (typeof globalThis.crypto?.randomUUID !== "function") {
    throw new Error("secure speed batch ID generation is unavailable");
  }
  return globalThis.crypto.randomUUID();
}

export function createApiClient(token: string, options: ApiClientOptions = {}): ApiClient {
  const fetchImpl = options.fetchImpl ?? fetch;
  const retryDelayMs = options.retryDelayMs ?? 150;
  const maxSseReconnects = options.maxSseReconnects ?? 2;
  const maxSnapshotPolls = options.maxSnapshotPolls ?? 2;
  const batchIdFactory = options.batchIdFactory ?? createSecureBatchId;
  const sessionHeaders: HeadersInit = { "X-NPE-Session": token };
  const speedLedgers = new Map<string, SpeedLedger>();
  const request = async <T>(path: string, init?: RequestInit): Promise<T> => {
    const headers = new Headers(sessionHeaders);
    new Headers(init?.headers).forEach((value, key) => headers.set(key, value));
    const response = await fetchImpl(path, { ...init, headers });
    if (!response.ok) throw new ApiHttpError(response.status);
    if (response.status === 204) return undefined as T;
    return (await response.json()) as T;
  };
  const requestVoid = (path: string, init?: RequestInit): Promise<void> =>
    request<undefined>(path, init);
  const delay = (signal: AbortSignal): Promise<boolean> =>
    retryDelayMs === 0 ? Promise.resolve(!signal.aborted) : wait(retryDelayMs, signal);
  const jsonRequest = (method: "POST" | "PUT", body: unknown): RequestInit => ({
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  const getSpeedLedger = (id: string): SpeedLedger => {
    const existing = speedLedgers.get(id);
    if (existing) return existing;
    const ledger: SpeedLedger = {
      usedBytes: 0,
      sampleCount: 0,
      status: "running",
      needsReconcile: false,
      terminal: false,
      version: 0,
      tail: Promise.resolve()
    };
    speedLedgers.set(id, ledger);
    return ledger;
  };
  const resetSpeedLedger = (ledger: SpeedLedger, snapshot: SpeedTestSnapshot): void => {
    ledger.version += 1;
    delete ledger.pendingBatch;
    ledger.usedBytes = hasValidSpeedCounters(snapshot) ? snapshot.used_bytes : 0;
    ledger.sampleCount = hasValidSpeedCounters(snapshot) ? snapshot.sample_count : 0;
    ledger.status = snapshot.status;
    ledger.terminal = isSpeedTerminal(snapshot.status);
    ledger.needsReconcile = !hasValidSpeedCounters(snapshot);
  };
  const syncSpeedSnapshot = (ledger: SpeedLedger, snapshot: SpeedTestSnapshot): void => {
    if (hasValidSpeedCounters(snapshot)) {
      ledger.usedBytes = Math.max(ledger.usedBytes, snapshot.used_bytes);
      ledger.sampleCount = Math.max(ledger.sampleCount, snapshot.sample_count);
    }
    if (ledger.terminal) return;
    if (isSpeedTerminal(snapshot.status)) {
      ledger.status = snapshot.status;
      ledger.terminal = true;
      return;
    }
    if (!hasValidSpeedCounters(snapshot)) {
      ledger.needsReconcile = true;
      return;
    }
    ledger.status = "running";
  };
  const terminalizeSpeedLedger = (
    ledger: SpeedLedger,
    status: SpeedTestSnapshot["status"],
    usedBytes = ledger.usedBytes,
    sampleCount = ledger.sampleCount
  ): void => {
    if (isSafeCounter(usedBytes)) ledger.usedBytes = Math.max(ledger.usedBytes, usedBytes);
    if (isSafeCounter(sampleCount)) {
      ledger.sampleCount = Math.max(ledger.sampleCount, sampleCount);
    }
    ledger.status = status;
    ledger.terminal = true;
    ledger.needsReconcile = false;
    delete ledger.pendingBatch;
  };
  const enqueueSpeedOperation = <T>(
    id: string,
    operation: (ledger: SpeedLedger, version: number) => Promise<T>
  ): Promise<T> => {
    const ledger = getSpeedLedger(id);
    const version = ledger.version;
    const run = ledger.tail.then(
      () => operation(ledger, version),
      () => operation(ledger, version)
    );
    ledger.tail = run.then(
      () => undefined,
      () => undefined
    );
    return run;
  };
  const sendSpeedBatch = async (
    id: string,
    pending: PendingSpeedBatch
  ): Promise<SpeedBatchSendResult> => {
    const path = `/api/v1/speed-tests/${encodeURIComponent(id)}/samples`;
    const sendOnce = async (): Promise<SpeedBatchSendResult> => {
      try {
        await requestVoid(path, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: pending.body
        });
        return { kind: "accepted" };
      } catch (error) {
        if (error instanceof ApiHttpError) return { kind: "rejected", error };
        throw error;
      }
    };
    try {
      return await sendOnce();
    } catch (firstError) {
      if (firstError instanceof ApiHttpError) return { kind: "rejected", error: firstError };
      try {
        return await sendOnce();
      } catch (retryError) {
        if (retryError instanceof ApiHttpError) return { kind: "rejected", error: retryError };
        throw retryError;
      }
    }
  };
  const acceptSpeedBatch = (ledger: SpeedLedger, pending: PendingSpeedBatch): void => {
    ledger.usedBytes = Math.max(ledger.usedBytes, pending.usedBytes);
    ledger.sampleCount = Math.max(ledger.sampleCount, pending.sampleCount);
    if (!ledger.terminal) ledger.status = "running";
    ledger.needsReconcile = false;
    if (ledger.pendingBatch?.batchId === pending.batchId) delete ledger.pendingBatch;
  };
  const resolvePendingSpeedBatch = async (
    id: string,
    ledger: SpeedLedger,
    version: number
  ): Promise<void> => {
    const pending = ledger.pendingBatch;
    if (!pending) return;
    if (pending.version !== version || ledger.version !== version) {
      throw new Error("speed test was restarted");
    }
    const result = await sendSpeedBatch(id, pending);
    if (ledger.version !== version) throw new Error("speed test was restarted");
    if (result.kind === "rejected") {
      delete ledger.pendingBatch;
      throw result.error;
    }
    acceptSpeedBatch(ledger, pending);
  };
  const ensureSpeedLedgerReady = async (
    id: string,
    ledger: SpeedLedger,
    version: number
  ): Promise<void> => {
    if (ledger.version !== version) throw new Error("speed test was restarted");
    await resolvePendingSpeedBatch(id, ledger, version);
    if (ledger.version !== version) throw new Error("speed test was restarted");
    if (ledger.terminal) throw new Error("speed test is already finished");
    if (!ledger.needsReconcile) return;
    try {
      const snapshot = await request<SpeedTestSnapshot>(
        `/api/v1/speed-tests/${encodeURIComponent(id)}`
      );
      if (ledger.version !== version) throw new Error("speed test was restarted");
      if (isSpeedTerminal(snapshot.status)) {
        syncSpeedSnapshot(ledger, snapshot);
        throw new Error("speed test is already finished");
      }
      if (!hasValidSpeedCounters(snapshot)) throw new Error("speed snapshot counters are invalid");
      if (snapshot.used_bytes < ledger.usedBytes || snapshot.sample_count < ledger.sampleCount) {
        throw new Error("speed snapshot counters require reconciliation");
      }
      syncSpeedSnapshot(ledger, snapshot);
      ledger.needsReconcile = false;
    } catch (error) {
      if (ledger.version === version && !ledger.terminal) ledger.needsReconcile = true;
      throw error;
    }
  };
  const reconcileAmbiguousSpeedOperation = async (
    id: string,
    ledger: SpeedLedger,
    version: number
  ): Promise<SpeedTestSnapshot | null> => {
    try {
      const snapshot = await request<SpeedTestSnapshot>(
        `/api/v1/speed-tests/${encodeURIComponent(id)}`
      );
      if (ledger.version !== version) return null;
      if (isSpeedTerminal(snapshot.status)) {
        syncSpeedSnapshot(ledger, snapshot);
        return snapshot;
      }
      if (!hasValidSpeedCounters(snapshot)) {
        ledger.needsReconcile = true;
        return null;
      }
      if (
        snapshot.used_bytes < ledger.usedBytes ||
        snapshot.sample_count < ledger.sampleCount
      ) {
        ledger.needsReconcile = true;
        return snapshot;
      }
      syncSpeedSnapshot(ledger, snapshot);
      ledger.needsReconcile = false;
      return snapshot;
    } catch {
      if (ledger.version === version) ledger.needsReconcile = true;
      return null;
    }
  };
  const subscribe = <TEvent extends SequencedEvent & { stage?: string }, TSnapshot>(
    eventsPath: string,
    snapshotPath: string,
    onEvent: (event: TEvent) => void,
    isTerminalSnapshot: (snapshot: TSnapshot) => boolean,
    onError: () => void,
    onTerminal: (snapshot: TSnapshot) => void
  ): ApiSubscription =>
    subscribeToJob({
      eventsPath,
      snapshotPath,
      eventName: "stage",
      isTerminal: isTerminalSnapshot,
      onEvent,
      onTerminal,
      onError,
      fetchImpl,
      sessionHeaders,
      request,
      delay,
      maxSseReconnects,
      maxSnapshotPolls
    });

  const isRunTerminal = (snapshot: RunSnapshot): boolean =>
    snapshot.status === "completed" || snapshot.status === "failed";
  const isJobTerminal = (snapshot: { status: string }): boolean =>
    snapshot.status === "completed" || snapshot.status === "failed" || snapshot.status === "cancelled";

  return {
    async startDiagnostic(url: string): Promise<string> {
      const response = await request<StartDiagnosticResponse>(
        "/api/v1/url-diagnostics",
        jsonRequest("POST", { url })
      );
      return response.run_id;
    },
    getRun(runId: string): Promise<RunSnapshot> {
      return request<RunSnapshot>(`/api/v1/runs/${encodeURIComponent(runId)}`);
    },
    getNetworkOverview(): Promise<NetworkOverviewResponse> {
      return request<NetworkOverviewResponse>("/api/v1/network-overview");
    },
    setMihomoController(url: string, secret: string): Promise<MihomoRuntime> {
      return request<MihomoRuntime>(
        "/api/v1/mihomo-controller",
        jsonRequest("PUT", { url, secret })
      );
    },
    resetMihomoController(): Promise<MihomoRuntime> {
      return request<MihomoRuntime>("/api/v1/mihomo-controller", { method: "DELETE" });
    },
    startRouteTrace(runId: string, kind: TraceRequestKind): Promise<RouteTraceSnapshot> {
      return request<RouteTraceSnapshot>(
        `/api/v1/runs/${encodeURIComponent(runId)}/route-trace`,
        jsonRequest("POST", { kind })
      );
    },
    getRouteTrace(runId: string): Promise<RouteTraceSnapshot> {
      return request<RouteTraceSnapshot>(
        `/api/v1/runs/${encodeURIComponent(runId)}/route-trace`
      );
    },
    subscribeToRun(runId, onStage, onError, onTerminal): ApiSubscription {
      return subscribe<StageEvent, RunSnapshot>(
        `/api/v1/runs/${encodeURIComponent(runId)}/events`,
        `/api/v1/runs/${encodeURIComponent(runId)}`,
        onStage,
        isRunTerminal,
        onError,
        onTerminal
      );
    },
    subscribeToRouteTrace(runId, onEvent, onError, onTerminal): ApiSubscription {
      return subscribe<TraceEvent, RouteTraceSnapshot>(
        `/api/v1/runs/${encodeURIComponent(runId)}/route-trace/events`,
        `/api/v1/runs/${encodeURIComponent(runId)}/route-trace`,
        onEvent,
        isJobTerminal,
        onError,
        onTerminal
      );
    },
    cancelRouteTrace(runId: string): Promise<void> {
      return requestVoid(`/api/v1/runs/${encodeURIComponent(runId)}/route-trace`, {
        method: "DELETE"
      });
    },
    startSpeedTest(mode: SpeedMode): Promise<SpeedTestSnapshot> {
      return request<SpeedTestSnapshot>("/api/v1/speed-tests", jsonRequest("POST", { mode })).then(
        (snapshot) => {
          resetSpeedLedger(getSpeedLedger(snapshot.id), snapshot);
          return snapshot;
        }
      );
    },
    getSpeedTest(id: string): Promise<SpeedTestSnapshot> {
      return enqueueSpeedOperation(id, async (ledger, version) => {
        const snapshot = await request<SpeedTestSnapshot>(
          `/api/v1/speed-tests/${encodeURIComponent(id)}`
        );
        if (ledger.version === version) syncSpeedSnapshot(ledger, snapshot);
        return snapshot;
      });
    },
    subscribeToSpeedTest(id, onEvent, onError, onTerminal): ApiSubscription {
      const ledger = getSpeedLedger(id);
      const version = ledger.version;
      return subscribe<SpeedEvent, SpeedTestSnapshot>(
        `/api/v1/speed-tests/${encodeURIComponent(id)}/events`,
        `/api/v1/speed-tests/${encodeURIComponent(id)}`,
        onEvent,
        isJobTerminal,
        onError,
        (snapshot) => {
          if (ledger.version === version) syncSpeedSnapshot(ledger, snapshot);
          onTerminal(snapshot);
        }
      );
    },
    async submitSpeedSamples(id: string, samples: SpeedSample[]): Promise<void> {
      const batchId = batchIdFactory();
      return enqueueSpeedOperation(id, async (ledger, version) => {
        await ensureSpeedLedgerReady(id, ledger, version);
        if (ledger.version !== version) throw new Error("speed test was restarted");
        const addedBytes = samples.reduce((total, sample) => total + sample.bytes, 0);
        const pending: PendingSpeedBatch = {
          version,
          batchId,
          body: JSON.stringify({
            batch_id: batchId,
            samples,
            used_bytes: ledger.usedBytes + addedBytes
          }),
          usedBytes: ledger.usedBytes + addedBytes,
          sampleCount: ledger.sampleCount + samples.length
        };
        let result: SpeedBatchSendResult;
        try {
          result = await sendSpeedBatch(id, pending);
        } catch (error) {
          if (ledger.version === version) ledger.pendingBatch = pending;
          throw error;
        }
        if (ledger.version !== version) throw new Error("speed test was restarted");
        if (result.kind === "rejected") throw result.error;
        acceptSpeedBatch(ledger, pending);
      });
    },
    async completeSpeedTest(id: string, metrics: SpeedMetrics): Promise<SpeedTestSnapshot> {
      return enqueueSpeedOperation(id, async (ledger, version) => {
        await ensureSpeedLedgerReady(id, ledger, version);
        if (ledger.version !== version) throw new Error("speed test was restarted");
        try {
          const snapshot = await request<SpeedTestSnapshot>(
            `/api/v1/speed-tests/${encodeURIComponent(id)}/complete`,
            jsonRequest("POST", { metrics })
          );
          if (ledger.version !== version) throw new Error("speed test was restarted");
          syncSpeedSnapshot(ledger, snapshot);
          if (isSpeedTerminal(snapshot.status)) {
            terminalizeSpeedLedger(ledger, snapshot.status, snapshot.used_bytes, snapshot.sample_count);
          }
          return snapshot;
        } catch (error) {
          if (ledger.version !== version) throw error;
          const snapshot = await reconcileAmbiguousSpeedOperation(id, ledger, version);
          if (ledger.version !== version) throw error;
          if (snapshot?.status === "completed") {
            terminalizeSpeedLedger(ledger, snapshot.status, snapshot.used_bytes, snapshot.sample_count);
            return snapshot;
          }
          throw error;
        }
      });
    },
    async cancelSpeedTest(id: string): Promise<void> {
      return enqueueSpeedOperation(id, async (ledger, version) => {
        await ensureSpeedLedgerReady(id, ledger, version);
        if (ledger.version !== version) throw new Error("speed test was restarted");
        try {
          await requestVoid(`/api/v1/speed-tests/${encodeURIComponent(id)}`, { method: "DELETE" });
          if (ledger.version !== version) throw new Error("speed test was restarted");
          terminalizeSpeedLedger(ledger, "cancelled");
        } catch (error) {
          if (ledger.version !== version) throw error;
          const snapshot = await reconcileAmbiguousSpeedOperation(id, ledger, version);
          if (ledger.version !== version) throw error;
          if (snapshot?.status === "cancelled") {
            terminalizeSpeedLedger(ledger, snapshot.status, snapshot.used_bytes, snapshot.sample_count);
            return;
          }
          throw error;
        }
      });
    }
  };
}

export function takeSessionTokenFromHash(): string {
  const token = new URLSearchParams(window.location.hash.slice(1)).get("token") ?? "";
  window.history.replaceState(window.history.state, "", `${window.location.pathname}${window.location.search}`);
  return token;
}

interface RedactedDiagnosticExport {
  export_version: 2;
  redacted: true;
  diagnostic: {
    url: string;
    resolved_ips: string[];
    proxy: {
      kind: UrlDiagnosticResult["proxy"]["kind"];
      host: string | null;
      port: number | null;
      evidence: RedactedEvidence;
    };
    route: {
      destination: string | null;
      gateway: string | null;
    } | null;
    http: {
      status: number | null;
      final_url: string;
      elapsed_ms: number;
      error_code: string | null;
      peer_endpoint: { ip: string; port: number } | null;
    };
    traffic_decision: {
      kind: UrlDiagnosticResult["traffic_decision"]["kind"];
      evidence: RedactedEvidence[];
      node_counts: Record<TrafficNodeKind, number>;
    };
    conclusion: {
      title: string;
      level: UrlDiagnosticResult["conclusion"]["level"];
    };
    evidence: RedactedEvidence[];
  };
}

interface RedactedEvidence {
  level: UrlDiagnosticResult["evidence"][number]["level"];
  source: string;
}

function parseIpv4(value: string): number[] | null {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map((part) => (/^(0|[1-9]\d{0,2})$/.test(part) ? Number(part) : -1));
  return octets.every((octet) => octet >= 0 && octet <= 255) ? octets : null;
}

function isPrivateOrLocalIpv4(octets: number[]): boolean {
  const [first = -1, second = -1] = octets;
  return (
    first === 0 ||
    first === 10 ||
    first === 127 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168)
  );
}

function parseIpv6Bytes(value: string): number[] | null {
  let canonical: string;
  try {
    canonical = new URL(`http://[${value}]/`).hostname.replace(/^\[|\]$/g, "");
  } catch {
    return null;
  }
  const halves = canonical.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves[1] ? halves[1].split(":") : [];
  const omitted = halves.length === 2 ? 8 - left.length - right.length : 0;
  if (omitted < 0 || (halves.length === 1 && left.length !== 8)) return null;
  const hextets = [...left, ...Array<string>(omitted).fill("0"), ...right];
  if (hextets.length !== 8 || !hextets.every((part) => /^[0-9a-f]{1,4}$/i.test(part))) {
    return null;
  }
  return hextets.flatMap((part) => {
    const value = Number.parseInt(part, 16);
    return [value >>> 8, value & 0xff];
  });
}

function isPrivateOrLocalAddress(value: string): boolean {
  const address = value.toLowerCase().replace(/^\[|\]$/g, "").split("%")[0] ?? "";
  const ipv4 = parseIpv4(address);
  if (ipv4) return isPrivateOrLocalIpv4(ipv4);
  const ipv6 = parseIpv6Bytes(address);
  if (!ipv6) return false;
  const isMappedIpv4 = ipv6.slice(0, 10).every((byte) => byte === 0)
    && ipv6[10] === 0xff
    && ipv6[11] === 0xff;
  const isCompatibleIpv4 = ipv6.slice(0, 12).every((byte) => byte === 0);
  if (isMappedIpv4 || isCompatibleIpv4) {
    return isPrivateOrLocalIpv4(ipv6.slice(12));
  }
  return (
    (ipv6[0]! & 0xfe) === 0xfc ||
    (ipv6[0] === 0xfe && (ipv6[1]! & 0xc0) === 0x80)
  );
}

function normalizedHost(host: string): string {
  return host.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
}

function isPrivateOrLocalHost(host: string): boolean {
  const normalized = normalizedHost(host);
  return (
    normalized === "localhost" ||
    normalized.endsWith(".localhost") ||
    normalized.endsWith(".local") ||
    isPrivateOrLocalAddress(normalized)
  );
}

function redactedUrl(value: string): string {
  try {
    const url = new URL(value);
    if (isPrivateOrLocalHost(url.hostname)) {
      return `${url.protocol}//[redacted-private-host]/`;
    }
    return `${url.protocol}//${url.host}/`;
  } catch {
    return "[redacted-invalid-url]";
  }
}

function redactedResult(result: UrlDiagnosticResult): RedactedDiagnosticExport {
  const redactedEvidence = (
    evidence: UrlDiagnosticResult["evidence"][number]
  ): RedactedEvidence => ({
    level: evidence.level,
    source: evidence.source
  });
  const publicAddress = (value: string | null): string | null =>
    value && !isPrivateOrLocalAddress(value) ? value : null;
  const nodeKinds: TrafficNodeKind[] = [
    "tun",
    "traffic_rule",
    "policy_group",
    "proxy_node",
    "blocked",
    "unknown"
  ];
  const nodeCounts = nodeKinds.reduce<Record<TrafficNodeKind, number>>(
    (counts, kind) => {
      counts[kind] = result.traffic_decision.chain.filter((node) => node.kind === kind).length;
      return counts;
    },
    {
      tun: 0,
      traffic_rule: 0,
      policy_group: 0,
      proxy_node: 0,
      blocked: 0,
      unknown: 0
    }
  );

  return {
    export_version: 2,
    redacted: true,
    diagnostic: {
      url: redactedUrl(result.normalized_url),
      resolved_ips: result.resolved_ips.filter((ip) => !isPrivateOrLocalAddress(ip)),
      proxy: {
        kind: result.proxy.kind,
        host:
          result.proxy.host && !isPrivateOrLocalHost(result.proxy.host)
            ? result.proxy.host
            : null,
        port: result.proxy.port,
        evidence: redactedEvidence(result.proxy.evidence)
      },
      route: result.route
        ? {
            destination: publicAddress(result.route.destination),
            gateway: publicAddress(result.route.gateway)
          }
        : null,
      http: {
        status: result.http.status,
        final_url: redactedUrl(result.http.final_url),
        elapsed_ms: result.http.elapsed_ms,
        error_code: result.http.error_code,
        peer_endpoint:
          result.http.peer_endpoint && !isPrivateOrLocalAddress(result.http.peer_endpoint.ip)
            ? { ...result.http.peer_endpoint }
            : null
      },
      traffic_decision: {
        kind: result.traffic_decision.kind,
        evidence: result.traffic_decision.evidence.map(redactedEvidence),
        node_counts: nodeCounts
      },
      conclusion: {
        title: result.conclusion.title,
        level: result.conclusion.level
      },
      evidence: result.evidence.map(redactedEvidence)
    }
  };
}

export function resultExport(result: UrlDiagnosticResult): Blob {
  return new Blob([JSON.stringify(redactedResult(result), null, 2)], {
    type: "application/json"
  });
}

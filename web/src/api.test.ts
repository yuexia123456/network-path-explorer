import { afterEach, expect, test, vi } from "vitest";
import { createApiClient, resultExport } from "./api";
import {
  completedSpeedMetrics,
  completedSpeedResult,
  degradingOverview,
  directResult,
  fourNodeProxyDecision,
  localNetworkOverview,
  unansweredTraceResult
} from "./test-fixtures";
import type {
  RouteTraceSnapshot,
  RunSnapshot,
  SpeedSample,
  SpeedTestSnapshot,
  UrlDiagnosticResult
} from "./types";

const encoder = new TextEncoder();

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

function sseResponse(chunks: string[]): Response {
  return new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
        controller.close();
      }
    }),
    { status: 200, headers: { "Content-Type": "text/event-stream" } }
  );
}

function deferred<T>(): { promise: Promise<T>; resolve(value: T): void } {
  let resolve!: (value: T) => void;
  return { promise: new Promise<T>((next) => { resolve = next; }), resolve };
}

const runningSnapshot: RunSnapshot = {
  id: "run-1",
  status: "running",
  result: null,
  error: null
};

const completedSnapshot: RunSnapshot = {
  id: "run-1",
  status: "completed",
  result: directResult,
  error: null
};

const failedSnapshot: RunSnapshot = {
  id: "run-1",
  status: "failed",
  result: null,
  error: { code: "diagnostic_failed", message: "诊断未能完成，请稍后重试" }
};

const runningTraceSnapshot: RouteTraceSnapshot = {
  status: "running",
  result: null,
  error: null
};

const completedTraceSnapshot: RouteTraceSnapshot = {
  status: "completed",
  result: unansweredTraceResult,
  error: null
};

const runningSpeedSnapshot: SpeedTestSnapshot = {
  id: "speed-1",
  status: "running",
  mode: "full",
  plan: {
    mode: "full",
    deadline_ms: 40_000,
    max_bytes: 200_000_000,
    include_loaded_latency: true,
    measurements: [
      { type: "latency", numPackets: 20 },
      { type: "download", bytes: 100_000, count: 3 },
      { type: "upload", bytes: 100_000, count: 3 }
    ]
  },
  used_bytes: 0,
  sample_count: 0,
  result: null,
  error: null
};

const completedSpeedSnapshot: SpeedTestSnapshot = {
  ...runningSpeedSnapshot,
  status: "completed",
  used_bytes: completedSpeedResult.used_bytes,
  sample_count: 3,
  result: completedSpeedResult
};

function speedSnapshot(
  usedBytes: number,
  status: SpeedTestSnapshot["status"] = "running",
  sampleCount = 0
): SpeedTestSnapshot {
  return {
    ...runningSpeedSnapshot,
    status,
    used_bytes: usedBytes,
    sample_count: sampleCount,
    result: status === "completed" ? completedSpeedResult : null,
    error: status === "running" ? null : { code: "speed_cancelled", message: "测速已取消" }
  };
}

function speedSample(bytes: number): SpeedSample {
  return {
    kind: "download",
    bytes,
    bps: 8_000_000,
    duration_ms: 100,
    latency_ms: null
  };
}

function terminalReaderResponse(cancel: () => Promise<void>): Response {
  const reader = {
    read: vi.fn(async () => ({
      done: false,
      value: encoder.encode(
        "event: stage\ndata: {\"sequence\":1,\"stage\":\"completed\",\"used_bytes\":0,\"sample_count\":0}\n\n"
      )
    })),
    cancel,
    releaseLock: vi.fn()
  };
  return {
    ok: true,
    status: 200,
    body: { getReader: () => reader }
  } as unknown as Response;
}

function pendingReaderResponse(cancel: () => Promise<void>, onRead?: () => void): Response {
  const reader = {
    read: vi.fn(() => {
      onRead?.();
      return new Promise<ReadableStreamReadResult<Uint8Array>>(() => undefined);
    }),
    cancel,
    releaseLock: vi.fn()
  };
  return {
    ok: true,
    status: 200,
    body: { getReader: () => reader }
  } as unknown as Response;
}

type CancelMode = "pending" | "reject" | "throw";

function cancelFor(mode: CancelMode, calls: { count: number }): () => Promise<void> {
  return (): Promise<void> => {
    calls.count += 1;
    if (mode === "throw") throw new Error("cancel threw");
    if (mode === "reject") return Promise.reject(new Error("cancel rejected"));
    return new Promise<void>(() => undefined);
  };
}

async function expectDoneWithin(subscription: { done: Promise<void> }, milliseconds = 100) {
  let timer: ReturnType<typeof globalThis.setTimeout> | undefined;
  await Promise.race([
    subscription.done,
    new Promise<never>((_, reject) => {
      timer = globalThis.setTimeout(() => reject(new Error("hard timeout")), milliseconds);
    })
  ]).finally(() => {
    if (timer !== undefined) globalThis.clearTimeout(timer);
  });
}

function noContentResponse(): Response {
  const response = new Response(null, { status: 204 });
  vi.spyOn(response, "json");
  return response;
}

test("mirrors the overview, four-node decision, unanswered hop, and speed contracts", () => {
  expect(fourNodeProxyDecision.chain).toHaveLength(4);
  expect(fourNodeProxyDecision.chain.map((node) => node.kind)).toEqual([
    "tun",
    "policy_group",
    "proxy_node",
    "proxy_node"
  ]);
  expect(localNetworkOverview.interfaces[1]?.kind).toBe("tun");
  expect(degradingOverview.egress_error).toBeNull();
  expect(degradingOverview.egress?.traffic_decision.kind).toBe("unknown");
  expect(unansweredTraceResult.hops[2]).toMatchObject({
    index: 3,
    address: null,
    rtts_ms: [],
    level: "unknown"
  });
  expect(completedSpeedMetrics.download_loaded_latency_ms).toBe(61.4);
});

test("gets the degrading network overview with the session token", async () => {
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    expect(String(input)).toBe("/api/v1/network-overview");
    expect(new Headers(init?.headers).get("X-NPE-Session")).toBe("token");
    return jsonResponse(degradingOverview);
  });
  const overview = await createApiClient("token", { fetchImpl }).getNetworkOverview();

  expect(overview).toEqual(degradingOverview);
  expect(fetchImpl).toHaveBeenCalledTimes(1);
});

test("starts an actual route trace for the selected run with an encoded path", async () => {
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    expect(String(input)).toBe("/api/v1/runs/run%2F1/route-trace");
    expect(init?.method).toBe("POST");
    expect(init?.body).toBe(JSON.stringify({ kind: "actual" }));
    expect(new Headers(init?.headers).get("Content-Type")).toBe("application/json");
    expect(new Headers(init?.headers).get("X-NPE-Session")).toBe("token");
    return jsonResponse(runningTraceSnapshot);
  });

  const snapshot = await createApiClient("token", { fetchImpl }).startRouteTrace("run/1", "actual");

  expect(snapshot).toEqual(runningTraceSnapshot);
});

test("reads and cancels a route trace without parsing a 204 body", async () => {
  const responses = [jsonResponse(completedTraceSnapshot), noContentResponse()];
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    expect(String(input)).toBe("/api/v1/runs/run%2F1/route-trace");
    expect(new Headers(init?.headers).get("X-NPE-Session")).toBe("token");
    return responses.shift() ?? noContentResponse();
  });
  const api = createApiClient("token", { fetchImpl });

  await expect(api.getRouteTrace("run/1")).resolves.toEqual(completedTraceSnapshot);
  await expect(api.cancelRouteTrace("run/1")).resolves.toBeUndefined();

  expect(fetchImpl).toHaveBeenCalledTimes(2);
  expect(fetchImpl.mock.calls[1]?.[1]?.method).toBe("DELETE");
});

test("sets and resets a loopback Mihomo controller without retaining its secret", async () => {
  const runtime = {
    available: true,
    mode: "rule",
    tun_enabled: true,
    controller: "manual_loopback"
  };
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    expect(String(input)).toBe("/api/v1/mihomo-controller");
    expect(new Headers(init?.headers).get("X-NPE-Session")).toBe("token");
    return jsonResponse(runtime);
  });
  const api = createApiClient("token", { fetchImpl });

  await expect(api.setMihomoController("http://127.0.0.1:9090", "secret")).resolves.toEqual(runtime);
  expect(fetchImpl.mock.calls[0]?.[1]?.method).toBe("PUT");
  expect(fetchImpl.mock.calls[0]?.[1]?.body).toBe(
    JSON.stringify({ url: "http://127.0.0.1:9090", secret: "secret" })
  );
  expect(new Headers(fetchImpl.mock.calls[0]?.[1]?.headers).get("Content-Type")).toBe(
    "application/json"
  );
  expect(String(api)).not.toContain("secret");

  await expect(api.resetMihomoController()).resolves.toEqual(runtime);
  expect(fetchImpl.mock.calls[1]?.[1]?.method).toBe("DELETE");
});

test("starts, submits, completes, and cancels a speed test with exact JSON contracts", async () => {
  const batchId = "11111111-1111-4111-8111-111111111111";
  const sample: SpeedSample = {
    kind: "download",
    bytes: 100_000,
    bps: 8_000_000,
    duration_ms: 100,
    latency_ms: null
  };
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    expect(new Headers(init?.headers).get("X-NPE-Session")).toBe("token");
    if (path === "/api/v1/speed-tests") return jsonResponse(runningSpeedSnapshot);
    if (path.endsWith("/complete")) {
      expect(init?.method).toBe("POST");
      expect(init?.body).toBe(JSON.stringify({ metrics: completedSpeedMetrics }));
      return jsonResponse(completedSpeedSnapshot);
    }
    if (path === "/api/v1/speed-tests/speed%2F1/samples") return noContentResponse();
    if (path === "/api/v1/speed-tests/speed%2F1" && (init?.method === undefined || init.method === "GET")) {
      return jsonResponse(runningSpeedSnapshot);
    }
    if (path === "/api/v1/speed-tests/speed%2F1" && init?.method === "DELETE") {
      return noContentResponse();
    }
    throw new Error(`unexpected path ${path}`);
  });
  const api = createApiClient("token", { fetchImpl, batchIdFactory: () => batchId });

  await expect(api.startSpeedTest("full")).resolves.toEqual(runningSpeedSnapshot);
  expect(fetchImpl.mock.calls[0]?.[1]?.method).toBe("POST");
  expect(fetchImpl.mock.calls[0]?.[1]?.body).toBe(JSON.stringify({ mode: "full" }));
  expect(new Headers(fetchImpl.mock.calls[0]?.[1]?.headers).get("Content-Type")).toBe(
    "application/json"
  );

  await expect(api.getSpeedTest("speed/1")).resolves.toEqual(runningSpeedSnapshot);

  await expect(api.submitSpeedSamples("speed/1", [sample])).resolves.toBeUndefined();
  expect(fetchImpl.mock.calls[2]?.[1]?.method).toBe("POST");
  expect(fetchImpl.mock.calls[2]?.[1]?.body).toBe(
    JSON.stringify({
        batch_id: batchId,
        samples: [sample],
        used_bytes: 100_000
    })
  );
  expect(new Headers(fetchImpl.mock.calls[2]?.[1]?.headers).get("Content-Type")).toBe(
    "application/json"
  );

  await expect(api.cancelSpeedTest("speed/1")).resolves.toBeUndefined();
  expect(fetchImpl.mock.calls[3]?.[1]?.method).toBe("DELETE");

  await expect(api.completeSpeedTest("speed/2", completedSpeedMetrics)).resolves.toEqual(
    completedSpeedSnapshot
  );
});

test("deduplicates route events, reconnects within bounds, and delivers one terminal snapshot", async () => {
  let eventConnections = 0;
  const seen: number[] = [];
  const terminal: RouteTraceSnapshot[] = [];
  const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input);
    if (path.endsWith("/events")) {
      eventConnections += 1;
      return eventConnections === 1
        ? sseResponse(["event: stage\ndata: {\"sequence\":0,\"stage\":\"probing\",\"hop\":null}\n\n"])
        : sseResponse([
            "event: stage\ndata: {\"sequence\":0,\"stage\":\"probing\",\"hop\":null}\n\n",
            "event: stage\ndata: {\"sequence\":1,\"stage\":\"completed\",\"hop\":null}\n\n"
          ]);
    }
    return eventConnections === 1 ? jsonResponse(runningTraceSnapshot) : jsonResponse(completedTraceSnapshot);
  });

  const subscription = createApiClient("token", { fetchImpl, retryDelayMs: 0 }).subscribeToRouteTrace(
    "run/1",
    (event) => seen.push(event.sequence),
    () => undefined,
    (snapshot) => terminal.push(snapshot)
  );
  await subscription.done;

  expect(eventConnections).toBe(2);
  expect(seen).toEqual([0, 1]);
  expect(terminal).toEqual([completedTraceSnapshot]);
});

test("bounds speed SSE reconnects and snapshot polls before one error callback", async () => {
  const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
    if (String(input).endsWith("/events")) {
      return sseResponse(["event: stage\ndata: {\"sequence\":0,\"stage\":\"samples\",\"used_bytes\":0,\"sample_count\":0}\n\n"]);
    }
    return jsonResponse(runningSpeedSnapshot);
  });
  let errors = 0;
  const subscription = createApiClient("token", {
    retryDelayMs: 0,
    maxSseReconnects: 1,
    maxSnapshotPolls: 1
  }).subscribeToSpeedTest(
    "speed/1",
    () => undefined,
    () => {
      errors += 1;
    },
    () => undefined
  );
  await subscription.done;

  expect(errors).toBe(1);
  expect(fetchImpl.mock.calls.length).toBeLessThanOrEqual(4);
});

test("closing a speed subscription aborts polling and suppresses late terminal callbacks", async () => {
  const snapshot = deferred<Response>();
  let snapshotSignal: AbortSignal | undefined;
  const terminal: SpeedTestSnapshot[] = [];
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input).endsWith("/events")) {
      return sseResponse([
        "event: stage\ndata: {\"sequence\":1,\"stage\":\"completed\",\"used_bytes\":100000,\"sample_count\":3}\n\n"
      ]);
    }
    snapshotSignal = init?.signal ?? undefined;
    return snapshot.promise;
  });
  const subscription = createApiClient("token", { fetchImpl }).subscribeToSpeedTest(
    "speed/1",
    () => undefined,
    () => undefined,
    (value) => terminal.push(value)
  );

  await vi.waitFor(() => expect(snapshotSignal).toBeDefined());
  subscription.close();
  snapshot.resolve(jsonResponse(completedSpeedSnapshot));
  await subscription.done;

  expect(snapshotSignal?.aborted).toBe(true);
  expect(terminal).toEqual([]);
});

test("resumes cumulative speed bytes from the server snapshot", async () => {
  const requests: number[] = [];
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === "/api/v1/speed-tests/speed%2F1" && init?.method !== "DELETE") {
      return jsonResponse(speedSnapshot(100, "running", 2));
    }
    if (path.endsWith("/samples")) {
      const body = JSON.parse(String(init?.body)) as { used_bytes: number };
      requests.push(body.used_bytes);
      return noContentResponse();
    }
    throw new Error(`unexpected path ${path}`);
  });
  const api = createApiClient("token", { fetchImpl });

  await api.getSpeedTest("speed/1");
  await api.submitSpeedSamples("speed/1", [speedSample(50)]);

  expect(requests).toEqual([150]);
});

test("serializes same-ID speed submissions while keeping cumulative order", async () => {
  const firstResponse = deferred<Response>();
  const requests: number[] = [];
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === "/api/v1/speed-tests/speed%2F1") return jsonResponse(speedSnapshot(0));
    if (path.endsWith("/samples")) {
      requests.push((JSON.parse(String(init?.body)) as { used_bytes: number }).used_bytes);
      return requests.length === 1 ? firstResponse.promise : noContentResponse();
    }
    throw new Error(`unexpected path ${path}`);
  });
  const api = createApiClient("token", { fetchImpl });
  await api.getSpeedTest("speed/1");

  const first = api.submitSpeedSamples("speed/1", [speedSample(100)]);
  await vi.waitFor(() => expect(requests).toEqual([100]));
  const second = api.submitSpeedSamples("speed/1", [speedSample(200)]);
  await Promise.resolve();
  expect(requests).toEqual([100]);

  firstResponse.resolve(noContentResponse());
  await Promise.all([first, second]);

  expect(requests).toEqual([100, 300]);
});

test("keeps different speed IDs concurrent with independent cumulative bytes", async () => {
  const release = deferred<Response>();
  const requests: Array<{ id: string; usedBytes: number }> = [];
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path.endsWith("/speed%2F1")) return jsonResponse(speedSnapshot(0));
    if (path.endsWith("/speed%2F2")) return jsonResponse(speedSnapshot(0));
    if (path.endsWith("/samples")) {
      const id = path.includes("speed%2F1") ? "speed/1" : "speed/2";
      requests.push({
        id,
        usedBytes: (JSON.parse(String(init?.body)) as { used_bytes: number }).used_bytes
      });
      return release.promise;
    }
    throw new Error(`unexpected path ${path}`);
  });
  const api = createApiClient("token", { fetchImpl });
  await Promise.all([api.getSpeedTest("speed/1"), api.getSpeedTest("speed/2")]);

  const first = api.submitSpeedSamples("speed/1", [speedSample(100)]);
  const second = api.submitSpeedSamples("speed/2", [speedSample(200)]);
  await vi.waitFor(() => expect(requests).toHaveLength(2));
  expect(requests).toEqual([
    { id: "speed/1", usedBytes: 100 },
    { id: "speed/2", usedBytes: 200 }
  ]);

  release.resolve(noContentResponse());
  await Promise.all([first, second]);
});

test("resets stale cumulative bytes when a new start reuses an ID", async () => {
  const requests: number[] = [];
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === "/api/v1/speed-tests/speed%2F1") return jsonResponse(speedSnapshot(100));
    if (path === "/api/v1/speed-tests") return jsonResponse({ ...speedSnapshot(0), id: "speed/1" });
    if (path.endsWith("/samples")) {
      requests.push((JSON.parse(String(init?.body)) as { used_bytes: number }).used_bytes);
      return noContentResponse();
    }
    throw new Error(`unexpected path ${path}`);
  });
  const api = createApiClient("token", { fetchImpl });

  await api.getSpeedTest("speed/1");
  await api.submitSpeedSamples("speed/1", [speedSample(50)]);
  await api.startSpeedTest("full");
  await api.submitSpeedSamples("speed/1", [speedSample(50)]);

  expect(requests).toEqual([150, 50]);
});

test("accepts a response-lost submission only after reconciliation sees its expected total", async () => {
  let serverBytes = 100;
  let serverSampleCount = 0;
  const requests: number[] = [];
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === "/api/v1/speed-tests/speed%2F1") {
      return jsonResponse(speedSnapshot(serverBytes, "running", serverSampleCount));
    }
    if (path.endsWith("/samples")) {
      const usedBytes = (JSON.parse(String(init?.body)) as { used_bytes: number }).used_bytes;
      requests.push(usedBytes);
      serverBytes = usedBytes;
      serverSampleCount += 1;
      if (requests.length === 1) throw new Error("response lost after accept");
      return noContentResponse();
    }
    throw new Error(`unexpected path ${path}`);
  });
  const api = createApiClient("token", { fetchImpl });
  await api.getSpeedTest("speed/1");

  await expect(api.submitSpeedSamples("speed/1", [speedSample(50)])).resolves.toBeUndefined();
  await api.submitSpeedSamples("speed/1", [speedSample(25)]);

  expect(requests).toEqual([150, 150, 175]);
});

test("retries one ambiguous sample transport failure with the exact same batch body", async () => {
  const batchId = "22222222-2222-4222-8222-222222222222";
  const bodies: string[] = [];
  let sampleCalls = 0;
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === "/api/v1/speed-tests/speed%2F1") {
      return jsonResponse(speedSnapshot(100, "running", 2));
    }
    if (path.endsWith("/samples")) {
      sampleCalls += 1;
      bodies.push(String(init?.body));
      if (sampleCalls === 1) throw new Error("first transport attempt lost");
      return noContentResponse();
    }
    throw new Error(`unexpected path ${path}`);
  });
  const api = createApiClient("token", {
    fetchImpl,
    batchIdFactory: () => batchId
  });

  await api.getSpeedTest("speed/1");
  await api.submitSpeedSamples("speed/1", [speedSample(50)]);

  expect(sampleCalls).toBe(2);
  expect(bodies).toEqual([
    JSON.stringify({ batch_id: batchId, samples: [speedSample(50)], used_bytes: 150 }),
    JSON.stringify({ batch_id: batchId, samples: [speedSample(50)], used_bytes: 150 })
  ]);
});

test("stores an ambiguous batch and resolves it before a later complete", async () => {
  const firstBatch = "33333333-3333-4333-8333-333333333333";
  const bodies: string[] = [];
  let sampleCalls = 0;
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === "/api/v1/speed-tests/speed%2F1") {
      return jsonResponse(speedSnapshot(100, "running", 2));
    }
    if (path.endsWith("/samples")) {
      sampleCalls += 1;
      bodies.push(String(init?.body));
      if (sampleCalls <= 2) throw new Error("sample response remains ambiguous");
      return noContentResponse();
    }
    if (path.endsWith("/complete")) {
      expect(sampleCalls).toBe(3);
      return jsonResponse({ ...speedSnapshot(150, "completed", 3), id: "speed/1" });
    }
    throw new Error(`unexpected path ${path}`);
  });
  const api = createApiClient("token", {
    fetchImpl,
    batchIdFactory: () => firstBatch
  });

  await api.getSpeedTest("speed/1");
  await expect(api.submitSpeedSamples("speed/1", [speedSample(50)])).rejects.toThrow(
    "sample response remains ambiguous"
  );
  await expect(api.completeSpeedTest("speed/1", completedSpeedMetrics)).resolves.toMatchObject({
    status: "completed"
  });

  expect(bodies).toHaveLength(3);
  expect(bodies[0]).toBe(bodies[1]);
  expect(bodies[1]).toBe(bodies[2]);
});

test("treats non-2xx sample responses as definitive rejection without crediting", async () => {
  const batchIds = [
    "44444444-4444-4444-8444-444444444444",
    "55555555-5555-4555-8555-555555555555"
  ];
  const bodies: string[] = [];
  let sampleCalls = 0;
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === "/api/v1/speed-tests/speed%2F1") {
      return jsonResponse(speedSnapshot(100, "running", 2));
    }
    if (path.endsWith("/samples")) {
      sampleCalls += 1;
      bodies.push(String(init?.body));
      return sampleCalls === 1 ? new Response(null, { status: 409 }) : noContentResponse();
    }
    throw new Error(`unexpected path ${path}`);
  });
  const api = createApiClient("token", {
    fetchImpl,
    batchIdFactory: () => batchIds.shift() ?? "66666666-6666-4666-8666-666666666666"
  });

  await api.getSpeedTest("speed/1");
  await expect(api.submitSpeedSamples("speed/1", [speedSample(50)])).rejects.toThrow(
    "API request failed: 409"
  );
  await api.submitSpeedSamples("speed/1", [speedSample(25)]);

  expect(sampleCalls).toBe(2);
  expect(JSON.parse(bodies[0]!).used_bytes).toBe(150);
  expect(JSON.parse(bodies[1]!).used_bytes).toBe(125);
});

test("separate clients use distinct batch IDs and cannot credit another client's batch", async () => {
  const clientABatch = "77777777-7777-4777-8777-777777777777";
  const clientBBatch = "88888888-8888-4888-8888-888888888888";
  const bodies: Array<{ batch_id: string; used_bytes: number }> = [];
  let clientBCalls = 0;
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === "/api/v1/speed-tests/shared") {
      return jsonResponse(speedSnapshot(100, "running", 2));
    }
    if (path.endsWith("/samples")) {
      const body = JSON.parse(String(init?.body)) as { batch_id: string; used_bytes: number };
      bodies.push(body);
      if (body.batch_id === clientABatch) return noContentResponse();
      clientBCalls += 1;
      if (clientBCalls === 1) throw new Error("client B response lost");
      return new Response(null, { status: 409 });
    }
    throw new Error(`unexpected path ${path}`);
  });
  const clientA = createApiClient("token-a", {
    fetchImpl,
    batchIdFactory: () => clientABatch
  });
  const clientB = createApiClient("token-b", {
    fetchImpl,
    batchIdFactory: () => clientBBatch
  });

  await Promise.all([clientA.getSpeedTest("shared"), clientB.getSpeedTest("shared")]);
  await clientA.submitSpeedSamples("shared", [speedSample(50)]);
  await expect(clientB.submitSpeedSamples("shared", [speedSample(50)])).rejects.toThrow();

  expect(bodies.map((body) => body.batch_id)).toEqual([
    clientABatch,
    clientBBatch,
    clientBBatch
  ]);
});

test("keeps an ambiguous pending batch across a regressing GET and recovers before the next batch", async () => {
  const firstBatch = "99999999-9999-4999-8999-999999999999";
  const secondBatch = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const batchIds = [firstBatch, secondBatch];
  const bodies: Array<{ batch_id: string; used_bytes: number }> = [];
  let sampleCalls = 0;
  let getCalls = 0;
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === "/api/v1/speed-tests/speed%2F1") {
      getCalls += 1;
      return getCalls === 1
        ? jsonResponse(speedSnapshot(100, "running", 2))
        : jsonResponse(speedSnapshot(50, "running", 1));
    }
    if (path.endsWith("/samples")) {
      sampleCalls += 1;
      bodies.push(JSON.parse(String(init?.body)) as { batch_id: string; used_bytes: number });
      if (sampleCalls <= 2) throw new Error("pending batch remains ambiguous");
      return noContentResponse();
    }
    throw new Error(`unexpected path ${path}`);
  });
  const api = createApiClient("token", {
    fetchImpl,
    batchIdFactory: () => batchIds.shift() ?? "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
  });

  await api.getSpeedTest("speed/1");
  await expect(api.submitSpeedSamples("speed/1", [speedSample(50)])).rejects.toThrow(
    "pending batch remains ambiguous"
  );
  await api.getSpeedTest("speed/1");
  await api.submitSpeedSamples("speed/1", [speedSample(25)]);

  expect(bodies.map((body) => body.batch_id)).toEqual([
    firstBatch,
    firstBatch,
    firstBatch,
    secondBatch
  ]);
  expect(bodies.map((body) => body.used_bytes)).toEqual([150, 150, 150, 175]);
});

test("does not reopen a terminal generation from a delayed running GET", async () => {
  const delayedGet = deferred<Response>();
  const requests: number[] = [];
  let getCalls = 0;
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path.endsWith("/events")) return terminalReaderResponse(() => Promise.resolve());
    if (path === "/api/v1/speed-tests/reuse" && init?.method !== "DELETE") {
      getCalls += 1;
      if (getCalls === 1) return jsonResponse({ ...speedSnapshot(100, "running", 2), id: "reuse" });
      if (getCalls === 2) return delayedGet.promise;
      return jsonResponse({ ...speedSnapshot(100, "completed", 3), id: "reuse" });
    }
    if (path.endsWith("/samples")) {
      requests.push((JSON.parse(String(init?.body)) as { used_bytes: number }).used_bytes);
      return noContentResponse();
    }
    throw new Error(`unexpected path ${path}`);
  });
  const api = createApiClient("token", { fetchImpl, batchIdFactory: () => "cccccccc-cccc-4ccc-8ccc-cccccccccccc" });

  await api.getSpeedTest("reuse");
  const oldGet = api.getSpeedTest("reuse");
  await vi.waitFor(() => expect(getCalls).toBe(2));
  const subscription = api.subscribeToSpeedTest("reuse", () => undefined, () => undefined, () => undefined);
  await subscription.done;
  delayedGet.resolve(jsonResponse({ ...speedSnapshot(100, "running", 2), id: "reuse" }));
  await oldGet;

  await expect(api.submitSpeedSamples("reuse", [speedSample(10)])).rejects.toThrow(
    "speed test is already finished"
  );
  expect(requests).toEqual([]);
});

test.each(["pending", "reject", "throw"] as const)(
  "cancels a reader exactly once when close wins before readSse installs its listener (%s)",
  async (mode) => {
    const calls = { count: 0 };
    const responseGate = deferred<Response>();
    const terminal: SpeedTestSnapshot[] = [];
    const fetchImpl = vi.fn(() => responseGate.promise);
    const subscription = createApiClient("token", { fetchImpl }).subscribeToSpeedTest(
      "speed/1",
      () => undefined,
      () => undefined,
      (snapshot) => terminal.push(snapshot)
    );

    subscription.close();
    responseGate.resolve(terminalReaderResponse(cancelFor(mode, calls)));
    await expectDoneWithin(subscription);

    expect(calls.count).toBe(1);
    expect(terminal).toEqual([]);
  }
);

test("retains the base after two response-lost attempts and resolves the pending batch", async () => {
  const requests: number[] = [];
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === "/api/v1/speed-tests/speed%2F1") return jsonResponse(speedSnapshot(100));
    if (path.endsWith("/samples")) {
      const usedBytes = (JSON.parse(String(init?.body)) as { used_bytes: number }).used_bytes;
      requests.push(usedBytes);
      if (requests.length <= 2) throw new Error("response lost before accept");
      return noContentResponse();
    }
    throw new Error(`unexpected path ${path}`);
  });
  const api = createApiClient("token", { fetchImpl });
  await api.getSpeedTest("speed/1");

  await expect(api.submitSpeedSamples("speed/1", [speedSample(50)])).rejects.toThrow(
    "response lost before accept"
  );
  await api.submitSpeedSamples("speed/1", [speedSample(25)]);

  expect(requests).toEqual([150, 150, 150, 175]);
});

test("does not infer acceptance from equal bytes with a wrong sample count", async () => {
  const requests: number[] = [];
  let getCount = 0;
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === "/api/v1/speed-tests/speed%2F1" && init?.method !== "DELETE") {
      getCount += 1;
      const snapshot =
        getCount === 1
          ? speedSnapshot(100, "running", 2)
          : speedSnapshot(150, "running", 2);
      return jsonResponse(snapshot);
    }
    if (path.endsWith("/samples")) {
      requests.push((JSON.parse(String(init?.body)) as { used_bytes: number }).used_bytes);
      if (requests.length <= 2) throw new Error("response lost with wrong sample count");
      return noContentResponse();
    }
    throw new Error(`unexpected path ${path}`);
  });
  const api = createApiClient("token", { fetchImpl });

  await api.getSpeedTest("speed/1");
  await expect(api.submitSpeedSamples("speed/1", [speedSample(50)])).rejects.toThrow(
    "response lost with wrong sample count"
  );
  await api.getSpeedTest("speed/1");
  await api.submitSpeedSamples("speed/1", [speedSample(25)]);

  expect(requests).toEqual([150, 150, 150, 175]);
});

test("preserves the known floor after a regressing snapshot and recovers the pending batch", async () => {
  const requests: number[] = [];
  let getCount = 0;
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === "/api/v1/speed-tests/speed%2F1" && init?.method !== "DELETE") {
      getCount += 1;
      return jsonResponse(
        getCount === 1
          ? speedSnapshot(100, "running", 2)
          : speedSnapshot(50, "running", 1)
      );
    }
    if (path.endsWith("/samples")) {
      requests.push((JSON.parse(String(init?.body)) as { used_bytes: number }).used_bytes);
      if (requests.length <= 2) throw new Error("response lost with regressing snapshot");
      return noContentResponse();
    }
    throw new Error(`unexpected path ${path}`);
  });
  const api = createApiClient("token", { fetchImpl });

  await api.getSpeedTest("speed/1");
  await expect(api.submitSpeedSamples("speed/1", [speedSample(50)])).rejects.toThrow(
    "response lost with regressing snapshot"
  );
  await api.getSpeedTest("speed/1");
  await api.submitSpeedSamples("speed/1", [speedSample(25)]);

  expect(requests).toEqual([150, 150, 150, 175]);
});

test("terminal snapshots and successful complete/cancel clear the speed ledger", async () => {
  const requests: number[] = [];
  let getCount = 0;
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === "/api/v1/speed-tests/speed%2F1" && init?.method !== "DELETE") {
      getCount += 1;
      return getCount === 1
        ? jsonResponse({ ...speedSnapshot(100), id: "speed/1" })
        : jsonResponse({ ...speedSnapshot(100, "completed", 3), id: "speed/1" });
    }
    if (path === "/api/v1/speed-tests") {
      return jsonResponse({ ...speedSnapshot(0), id: "speed/1" });
    }
    if (path.endsWith("/samples")) {
      requests.push((JSON.parse(String(init?.body)) as { used_bytes: number }).used_bytes);
      return noContentResponse();
    }
    if (path.endsWith("/complete")) {
      return jsonResponse({ ...speedSnapshot(150, "completed", 4), id: "speed/1" });
    }
    if (path.endsWith("/speed%2F1") && init?.method === "DELETE") return noContentResponse();
    throw new Error(`unexpected path ${path}`);
  });
  const api = createApiClient("token", { fetchImpl });

  await api.getSpeedTest("speed/1");
  await api.submitSpeedSamples("speed/1", [speedSample(50)]);
  await api.getSpeedTest("speed/1");
  await api.startSpeedTest("full");
  await api.submitSpeedSamples("speed/1", [speedSample(25)]);
  await api.completeSpeedTest("speed/1", completedSpeedMetrics);
  await api.startSpeedTest("full");
  await api.submitSpeedSamples("speed/1", [speedSample(10)]);
  await api.cancelSpeedTest("speed/1");
  await api.startSpeedTest("full");
  await api.submitSpeedSamples("speed/1", [speedSample(5)]);

  expect(requests).toEqual([150, 25, 10, 5]);
});

test("reconciles failed complete and cancel before allowing the next same-ID batch", async () => {
  const requests: number[] = [];
  let serverBytes = 100;
  let serverSampleCount = 0;
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === "/api/v1/speed-tests/speed%2F1" && init?.method !== "DELETE") {
      return jsonResponse(speedSnapshot(serverBytes, "running", serverSampleCount));
    }
    if (path.endsWith("/samples")) {
      serverBytes = (JSON.parse(String(init?.body)) as { used_bytes: number }).used_bytes;
      serverSampleCount += 1;
      requests.push(serverBytes);
      return noContentResponse();
    }
    if (path.endsWith("/complete")) throw new Error("complete response lost");
    if (path.endsWith("/speed%2F1") && init?.method === "DELETE") {
      throw new Error("cancel response lost");
    }
    throw new Error(`unexpected path ${path}`);
  });
  const api = createApiClient("token", { fetchImpl });

  await api.getSpeedTest("speed/1");
  await expect(api.completeSpeedTest("speed/1", completedSpeedMetrics)).rejects.toThrow(
    "complete response lost"
  );
  await api.submitSpeedSamples("speed/1", [speedSample(25)]);
  await expect(api.cancelSpeedTest("speed/1")).rejects.toThrow("cancel response lost");
  await api.submitSpeedSamples("speed/1", [speedSample(10)]);

  expect(requests).toEqual([125, 135]);
});

test("terminal speed SSE snapshots terminalize the ledger before later submissions", async () => {
  const samples: number[] = [];
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path.endsWith("/events")) return terminalReaderResponse(async () => undefined);
    if (path === "/api/v1/speed-tests/speed%2F1" && init?.method !== "DELETE") {
      return jsonResponse(speedSnapshot(100, "completed", 2));
    }
    if (path.endsWith("/samples")) {
      samples.push((JSON.parse(String(init?.body)) as { used_bytes: number }).used_bytes);
      return noContentResponse();
    }
    throw new Error(`unexpected path ${path}`);
  });
  const api = createApiClient("token", { fetchImpl });

  await api.subscribeToSpeedTest("speed/1", () => undefined, () => undefined, () => undefined).done;
  await expect(api.submitSpeedSamples("speed/1", [speedSample(10)])).rejects.toThrow(
    "speed test is already finished"
  );

  expect(samples).toEqual([]);
});

test("does not let a delayed pre-restart GET mutate a reused ID generation", async () => {
  const staleGet = deferred<Response>();
  const requests: number[] = [];
  let getCount = 0;
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === "/api/v1/speed-tests/reuse" && init?.method !== "DELETE") {
      getCount += 1;
      return getCount === 1
        ? jsonResponse({ ...speedSnapshot(100, "running", 2), id: "reuse" })
        : staleGet.promise;
    }
    if (path === "/api/v1/speed-tests") {
      return jsonResponse({ ...speedSnapshot(0), id: "reuse" });
    }
    if (path.endsWith("/samples")) {
      requests.push((JSON.parse(String(init?.body)) as { used_bytes: number }).used_bytes);
      return noContentResponse();
    }
    throw new Error(`unexpected path ${path}`);
  });
  const api = createApiClient("token", { fetchImpl });

  await api.getSpeedTest("reuse");
  const oldGet = api.getSpeedTest("reuse");
  await vi.waitFor(() => expect(getCount).toBe(2));
  await api.startSpeedTest("full");
  staleGet.resolve(jsonResponse({ ...speedSnapshot(100, "running", 2), id: "reuse" }));

  await expect(oldGet).resolves.toMatchObject({ used_bytes: 100, sample_count: 2 });
  await api.submitSpeedSamples("reuse", [speedSample(10)]);

  expect(requests).toEqual([10]);
});

test("does not let a delayed pre-restart terminal SSE snapshot mutate a reused ID", async () => {
  const staleTerminal = deferred<Response>();
  const requests: number[] = [];
  let snapshotRequests = 0;
  const terminal: SpeedTestSnapshot[] = [];
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path.endsWith("/events")) return terminalReaderResponse(() => Promise.resolve());
    if (path === "/api/v1/speed-tests/reuse" && init?.method !== "DELETE") {
      snapshotRequests += 1;
      return staleTerminal.promise;
    }
    if (path === "/api/v1/speed-tests") {
      return jsonResponse({ ...speedSnapshot(0), id: "reuse" });
    }
    if (path.endsWith("/samples")) {
      requests.push((JSON.parse(String(init?.body)) as { used_bytes: number }).used_bytes);
      return noContentResponse();
    }
    throw new Error(`unexpected path ${path}`);
  });
  const api = createApiClient("token", { fetchImpl });
  const subscription = api.subscribeToSpeedTest(
    "reuse",
    () => undefined,
    () => undefined,
    (snapshot) => terminal.push(snapshot)
  );

  await vi.waitFor(() => expect(snapshotRequests).toBe(1));
  await api.startSpeedTest("full");
  staleTerminal.resolve(
    jsonResponse({ ...speedSnapshot(100, "completed", 2), id: "reuse" })
  );
  await subscription.done;
  await api.submitSpeedSamples("reuse", [speedSample(10)]);

  expect(terminal).toHaveLength(1);
  expect(requests).toEqual([10]);
});

test.each(["pending", "reject", "throw"] as const)(
  "terminal-only reader cancellation is exactly once for %s",
  async (mode) => {
    const calls = { count: 0 };
    const terminal: SpeedTestSnapshot[] = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) =>
      String(input).endsWith("/events")
        ? terminalReaderResponse(cancelFor(mode, calls))
        : jsonResponse(completedSpeedSnapshot)
    );
    const subscription = createApiClient("token", { fetchImpl }).subscribeToSpeedTest(
      "speed/1",
      () => undefined,
      () => undefined,
      (snapshot) => terminal.push(snapshot)
    );

    await expectDoneWithin(subscription);

    expect(calls.count).toBe(1);
    expect(terminal).toEqual([completedSpeedSnapshot]);
  }
);

test.each(["pending", "reject", "throw"] as const)(
  "abort-only reader cancellation is exactly once for %s",
  async (mode) => {
    const calls = { count: 0 };
    let readStarted = false;
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) =>
      String(input).endsWith("/events")
        ? pendingReaderResponse(cancelFor(mode, calls), () => { readStarted = true; })
        : jsonResponse(completedSpeedSnapshot)
    );
    const subscription = createApiClient("token", { fetchImpl }).subscribeToSpeedTest(
      "speed/1",
      () => undefined,
      () => undefined,
      () => undefined
    );

    await vi.waitFor(() => expect(readStarted).toBe(true));
    subscription.close();
    await expectDoneWithin(subscription);

    expect(calls.count).toBe(1);
  }
);

test.each(["pending", "reject", "throw"] as const)(
  "terminal event callback close keeps reader cancellation exactly once for %s",
  async (mode) => {
    const calls = { count: 0 };
    let subscription: ReturnType<ReturnType<typeof createApiClient>["subscribeToSpeedTest"]>;
    const terminal: SpeedTestSnapshot[] = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).endsWith("/events")) return terminalReaderResponse(cancelFor(mode, calls));
      throw new Error("terminal callback close must abort before polling");
    });
    const api = createApiClient("token", { fetchImpl });
    subscription = api.subscribeToSpeedTest(
      "speed/1",
      () => subscription.close(),
      () => undefined,
      (snapshot) => terminal.push(snapshot)
    );

    await expectDoneWithin(subscription);

    expect(calls.count).toBe(1);
    expect(terminal).toEqual([]);
  }
);

test("closing during a never-settling terminal reader cancel settles done without late callbacks", async () => {
  let subscription: ReturnType<ReturnType<typeof createApiClient>["subscribeToSpeedTest"]>;
  const terminal: SpeedTestSnapshot[] = [];
  const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
    if (String(input).endsWith("/events")) {
      return terminalReaderResponse(() => new Promise<void>(() => undefined));
    }
    throw new Error("late snapshot fetch must not happen");
  });
  const api = createApiClient("token", { fetchImpl });
  subscription = api.subscribeToSpeedTest(
    "speed/1",
    () => subscription.close(),
    () => undefined,
    (snapshot) => terminal.push(snapshot)
  );

  await expect(
    Promise.race([
      subscription.done,
      new Promise<never>((_, reject) => globalThis.setTimeout(() => reject(new Error("hard timeout")), 100))
    ])
  ).resolves.toBeUndefined();
  expect(terminal).toEqual([]);
});

test("swallows terminal reader cancel rejection and still delivers one terminal snapshot", async () => {
  const terminal: SpeedTestSnapshot[] = [];
  const fetchImpl = vi.fn(async (input: RequestInfo | URL) =>
    String(input).endsWith("/events")
      ? terminalReaderResponse(() => Promise.reject(new Error("cancel failed")))
      : jsonResponse(completedSpeedSnapshot)
  );
  const subscription = createApiClient("token", { fetchImpl }).subscribeToSpeedTest(
    "speed/1",
    () => undefined,
    () => undefined,
    (snapshot) => terminal.push(snapshot)
  );

  await subscription.done;
  expect(terminal).toEqual([completedSpeedSnapshot]);
});

afterEach(() => vi.unstubAllGlobals());

test("parses SSE stages when CRLF and message boundaries are split across chunks", async () => {
  const fetchImpl = vi.fn(async (input: RequestInfo | URL) =>
    String(input).endsWith("/events")
      ? sseResponse([
          "event: stage\r",
          "\ndata: {\"sequence\":0,\"stage\":\"validating\"}\r",
          "\n\r",
          "\nevent: stage\r\ndata: {\"sequence\":1,\"stage\":\"completed\"}\r\n\r\n"
        ])
      : jsonResponse(completedSnapshot)
  );
  vi.stubGlobal("fetch", fetchImpl);
  const seen: string[] = [];
  const terminal: RunSnapshot[] = [];
  const subscription = createApiClient("session-token").subscribeToRun(
    "run-1",
    (stage) => seen.push(stage.stage),
    () => undefined,
    (snapshot) => terminal.push(snapshot)
  );

  await subscription.done;

  expect(seen).toEqual(["validating", "completed"]);
  expect(terminal).toEqual([completedSnapshot]);
});

test("reconnects after an early SSE EOF and does not emit replayed stages twice", async () => {
  let eventConnections = 0;
  const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input);
    if (path.endsWith("/events")) {
      eventConnections += 1;
      return eventConnections === 1
        ? sseResponse(["event: stage\ndata: {\"sequence\":0,\"stage\":\"validating\"}\n\n"])
        : sseResponse([
            "event: stage\ndata: {\"sequence\":0,\"stage\":\"validating\"}\n\n",
            "event: stage\ndata: {\"sequence\":1,\"stage\":\"completed\"}\n\n"
          ]);
    }
    return eventConnections === 1 ? jsonResponse(runningSnapshot) : jsonResponse(completedSnapshot);
  });
  vi.stubGlobal("fetch", fetchImpl);
  const seen: string[] = [];
  const terminal: RunSnapshot[] = [];
  const subscription = createApiClient("session-token", { retryDelayMs: 0 }).subscribeToRun(
    "run-1",
    (stage) => seen.push(stage.stage),
    () => undefined,
    (snapshot) => terminal.push(snapshot)
  );

  await subscription.done;

  expect(eventConnections).toBe(2);
  expect(seen).toEqual(["validating", "completed"]);
  expect(terminal).toEqual([completedSnapshot]);
});

test("settles from a failed terminal event by polling its final snapshot", async () => {
  const fetchImpl = vi.fn(async (input: RequestInfo | URL) =>
    String(input).endsWith("/events")
      ? sseResponse(["event: stage\ndata: {\"sequence\":4,\"stage\":\"failed\"}\n\n"])
      : jsonResponse(failedSnapshot)
  );
  vi.stubGlobal("fetch", fetchImpl);
  const terminal: RunSnapshot[] = [];
  const subscription = createApiClient("session-token").subscribeToRun(
    "run-1",
    () => undefined,
    () => undefined,
    (snapshot) => terminal.push(snapshot)
  );

  await subscription.done;

  expect(terminal).toEqual([failedSnapshot]);
});

test("bounds SSE and snapshot retries then settles a network failure", async () => {
  const fetchImpl = vi.fn(async () => Promise.reject(new Error("offline")));
  vi.stubGlobal("fetch", fetchImpl);
  let errors = 0;
  const subscription = createApiClient("session-token", {
    retryDelayMs: 0,
    maxSseReconnects: 1,
    maxSnapshotPolls: 1
  }).subscribeToRun(
    "run-1",
    () => undefined,
    () => {
      errors += 1;
    },
    () => undefined
  );

  await subscription.done;

  expect(errors).toBe(1);
  expect(fetchImpl.mock.calls.length).toBeLessThanOrEqual(4);
});

test("aborting a terminal snapshot poll forwards its signal and prevents a stale terminal callback", async () => {
  const snapshot = deferred<Response>();
  let snapshotSignal: AbortSignal | undefined;
  const terminal: RunSnapshot[] = [];
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input).endsWith("/events")) {
      return sseResponse(["event: stage\ndata: {\"sequence\":1,\"stage\":\"completed\"}\n\n"]);
    }
    snapshotSignal = init?.signal ?? undefined;
    return snapshot.promise;
  });
  vi.stubGlobal("fetch", fetchImpl);
  const subscription = createApiClient("session-token").subscribeToRun(
    "run-1",
    () => undefined,
    () => undefined,
    (value) => terminal.push(value)
  );

  await vi.waitFor(() => expect(snapshotSignal).toBeDefined());
  subscription.close();
  snapshot.resolve(jsonResponse(completedSnapshot));
  await subscription.done;

  expect(snapshotSignal?.aborted).toBe(true);
  expect(terminal).toEqual([]);
});

test("sends X-NPE-Session on POST, snapshots, and SSE", async () => {
  const calls: Array<{ path: string; init: RequestInit | undefined }> = [];
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    calls.push({ path, init });
    if (path === "/api/v1/url-diagnostics") return jsonResponse({ run_id: "run-1" });
    if (path.endsWith("/events")) {
      return sseResponse(["event: stage\ndata: {\"sequence\":1,\"stage\":\"completed\"}\n\n"]);
    }
    return jsonResponse(completedSnapshot);
  });
  vi.stubGlobal("fetch", fetchImpl);
  const client = createApiClient("session-token");

  await client.startDiagnostic("https://example.com");
  await client.getRun("run-1");
  const subscription = client.subscribeToRun("run-1", () => undefined, () => undefined, () => undefined);
  await subscription.done;

  expect(calls.map((call) => call.path)).toEqual([
    "/api/v1/url-diagnostics",
    "/api/v1/runs/run-1",
    "/api/v1/runs/run-1/events",
    "/api/v1/runs/run-1"
  ]);
  for (const call of calls) {
    expect(new Headers(call.init?.headers).get("X-NPE-Session")).toBe("session-token");
  }
});

test("exports an explicit redacted report without URL secrets or private addresses", async () => {
  const sensitive: UrlDiagnosticResult = {
    ...directResult,
    requested_url: "https://user:pass@[fd00::1]:8443/private/path?token=session-token#fragment",
    normalized_url: "https://[fd00::1]:8443/private/path?token=session-token#fragment",
    resolved_ips: ["10.0.0.8", "fd00::8", "0:0:0:0:0:0:0:1", "8.8.8.8"],
    proxy: {
      ...directResult.proxy,
      kind: "https",
      host: "192.168.1.9",
      port: 8080,
      bypass_reason: "configured 192.168.1.9",
      evidence: {
        level: "confirmed",
        source: "system_proxy",
        summary: "系统代理 192.168.1.9:8080"
      }
    },
    route: {
      destination: "10.0.0.8",
      gateway: "fe80::1",
      interface: "en0"
    },
    http: {
      ...directResult.http,
      final_url: "https://intranet.local/another/secret?credential=hidden",
      peer_endpoint: { ip: "::1", port: 8080 }
    },
    conclusion: {
      ...directResult.conclusion,
      summary: "通过 192.168.1.9 到 10.0.0.8"
    },
    evidence: [
      {
        level: "confirmed",
        source: "dns",
        summary: "DNS 返回 10.0.0.8 和 8.8.8.8"
      }
    ]
  };

  const text = await resultExport(sensitive).text();
  const report = JSON.parse(text);

  expect(report).toMatchObject({
    export_version: 2,
    redacted: true,
    diagnostic: {
      url: "https://[redacted-private-host]/",
      resolved_ips: ["8.8.8.8"],
      proxy: { kind: "https", host: null, port: 8080 },
      route: { destination: null, gateway: null },
      http: {
        status: 200,
        final_url: "https://[redacted-private-host]/",
        peer_endpoint: null
      },
      traffic_decision: {
        kind: "direct",
        evidence: [{ level: "confirmed", source: "mihomo" }],
        node_counts: {
          tun: 0,
          traffic_rule: 0,
          policy_group: 0,
          proxy_node: 0,
          blocked: 0,
          unknown: 0
        }
      },
      conclusion: { title: directResult.conclusion.title },
      evidence: [{ source: "dns" }]
    }
  });
  for (const secret of [
    "user:pass@",
    "/private/path",
    "session-token",
    "fragment",
    "intranet.local",
    "/another/secret",
    "credential=hidden",
    "192.168.1.9",
    "10.0.0.8",
    "fd00::8",
    "0:0:0:0:0:0:0:1",
    "fe80::1",
    "::1"
  ]) {
    expect(text).not.toContain(secret);
  }
  expect(text).toContain("8.8.8.8");
  expect(text).not.toContain("session-token");
});

test("redacted export omits a private CIDR that appears only in proxy bypass text", async () => {
  const bypassedPrivateTarget: UrlDiagnosticResult = {
    ...directResult,
    requested_url: "http://10.1.2.3/private?token=cidr-secret",
    normalized_url: "http://10.1.2.3/private?token=cidr-secret",
    resolved_ips: ["10.1.2.3"],
    proxy: {
      ...directResult.proxy,
      bypass_reason: "目标匹配系统代理例外 10.0.0.0/8",
      evidence: {
        level: "confirmed",
        source: "system_proxy",
        summary: "10.1.2.3 命中绕过网段 10.0.0.0/8"
      }
    },
    conclusion: {
      title: "系统代理配置：直连",
      summary: "目标 10.1.2.3 因 10.0.0.0/8 绕过代理。",
      level: "confirmed"
    },
    evidence: [
      {
        level: "confirmed",
        source: "system_proxy",
        summary: "目标属于 10.0.0.0/8，系统选择直连。"
      }
    ]
  };

  const text = await resultExport(bypassedPrivateTarget).text();
  const report = JSON.parse(text);

  expect(report.diagnostic.proxy).not.toHaveProperty("bypass_reason");
  expect(report.diagnostic.proxy.evidence).toEqual({
    level: "confirmed",
    source: "system_proxy"
  });
  expect(report.diagnostic.conclusion).toEqual({
    title: "系统代理配置：直连",
    level: "confirmed"
  });
  expect(report.diagnostic.evidence).toEqual([
    { level: "confirmed", source: "system_proxy" }
  ]);
  for (const secret of ["10.1.2.3", "10.0.0.0/8", "cidr-secret", "/private"]) {
    expect(text).not.toContain(secret);
  }
});

test("redacted export omits a private proxy IP that appears only in failure evidence", async () => {
  const failedHostnameProxy: UrlDiagnosticResult = {
    ...directResult,
    proxy: {
      kind: "https",
      host: "proxy.example",
      port: 8443,
      bypass_reason: null,
      evidence: {
        level: "confirmed",
        source: "system_proxy",
        summary: "系统配置代理 proxy.example:8443"
      }
    },
    route: null,
    http: {
      ...directResult.http,
      status: null,
      error_code: "connect",
      peer_endpoint: null
    },
    conclusion: {
      title: "不是直连",
      summary: "代理 proxy.example 解析为 10.9.8.7，但路由与连接失败。",
      level: "confirmed"
    },
    evidence: [
      {
        level: "unknown",
        source: "route",
        summary: "无法查询到 10.9.8.7 的路由。"
      },
      {
        level: "confirmed",
        source: "http",
        summary: "连接 10.9.8.7 失败。"
      }
    ]
  };

  const text = await resultExport(failedHostnameProxy).text();
  const report = JSON.parse(text);

  expect(report.diagnostic.proxy.host).toBe("proxy.example");
  expect(report.diagnostic.http.error_code).toBe("connect");
  expect(report.diagnostic.evidence).toEqual([
    { level: "unknown", source: "route" },
    { level: "confirmed", source: "http" }
  ]);
  expect(report.diagnostic.conclusion).toEqual({ title: "不是直连", level: "confirmed" });
  expect(text).not.toContain("10.9.8.7");
  expect(text).not.toContain("解析为");
  expect(text).not.toContain("无法查询到");
});

test("redacted export classifies dotted private IPv4-mapped IPv6 after URL canonicalization", async () => {
  const mappedTarget: UrlDiagnosticResult = {
    ...directResult,
    requested_url: "http://[::ffff:10.1.2.3]/private?token=mapped-secret",
    normalized_url: "http://[::ffff:10.1.2.3]/private?token=mapped-secret",
    resolved_ips: ["::ffff:8.8.8.8"],
    http: {
      ...directResult.http,
      final_url: "http://[::ffff:10.1.2.3]/private?token=mapped-secret"
    }
  };

  const text = await resultExport(mappedTarget).text();
  const report = JSON.parse(text);

  expect(report.diagnostic.url).toBe("http://[redacted-private-host]/");
  expect(report.diagnostic.http.final_url).toBe("http://[redacted-private-host]/");
  expect(report.diagnostic.resolved_ips).toEqual(["::ffff:8.8.8.8"]);
  for (const secret of [
    "::ffff:10.1.2.3",
    "::ffff:a01:203",
    "10.1.2.3",
    "mapped-secret",
    "/private"
  ]) {
    expect(text).not.toContain(secret);
  }
});

test("redacted export classifies canonical mapped and accepted compatible IPv4 by bits", async () => {
  const mappedEndpoints: UrlDiagnosticResult = {
    ...directResult,
    resolved_ips: [
      "::ffff:a01:203",
      "::ffff:7f00:1",
      "::ffff:a9fe:102",
      "::a01:203",
      "::ffff:808:808",
      "::808:808",
      "2001:db8::a01:203"
    ],
    proxy: {
      ...directResult.proxy,
      kind: "https",
      host: "::ffff:7f00:1",
      port: 8443
    },
    route: {
      destination: "::ffff:a9fe:102",
      gateway: "::ffff:7f00:1",
      interface: "en0"
    },
    http: {
      ...directResult.http,
      peer_endpoint: { ip: "::ffff:a01:203", port: 8443 }
    }
  };

  const text = await resultExport(mappedEndpoints).text();
  const report = JSON.parse(text);

  expect(report.diagnostic.resolved_ips).toEqual([
    "::ffff:808:808",
    "::808:808",
    "2001:db8::a01:203"
  ]);
  expect(report.diagnostic.proxy.host).toBeNull();
  expect(report.diagnostic.route).toEqual({
    destination: null,
    gateway: null
  });
  expect(report.diagnostic.http.peer_endpoint).toBeNull();
  for (const privateLiteral of [
    "::ffff:a01:203",
    "::ffff:7f00:1",
    "::ffff:a9fe:102"
  ]) {
    expect(text).not.toContain(privateLiteral);
  }
  expect(text).not.toContain('"::a01:203"');
  expect(text).toContain("::ffff:808:808");
  expect(text).toContain("::808:808");
  expect(text).toContain("2001:db8::a01:203");
});

test("exports v2 allowlist without private traffic details", async () => {
  const proxyResultWithSensitiveChain: UrlDiagnosticResult = {
    ...directResult,
    requested_url:
      "https://user:pass@public.example/private/path?token=fixture-secret#fragment",
    normalized_url:
      "https://public.example/private/path?token=fixture-secret#fragment",
    resolved_ips: ["198.51.100.3", "127.0.0.1", "fd00::1"],
    proxy: {
      kind: "http",
      host: "127.0.0.1",
      port: 7890,
      bypass_reason: "controller http://127.0.0.1:9090",
      evidence: {
        level: "confirmed",
        source: "system_proxy",
        summary: "local controller fixture",
      },
    },
    route: {
      destination: "198.51.100.3",
      gateway: "192.168.1.1",
      interface: "en0",
    },
    http: {
      ...directResult.http,
      final_url: "https://public.example/redirect?credential=fixture-secret",
      peer_endpoint: { ip: "198.51.100.3", port: 443 },
    },
    traffic_decision: {
      ...fourNodeProxyDecision,
      rule: {
        rule_type: "DOMAIN-SUFFIX",
        payload: "example.com",
        target: "香港住宅-私有节点名",
        level: "confirmed",
      },
      chain: fourNodeProxyDecision.chain.map((node, index) => ({
        ...node,
        name: index === 0 ? "Mihomo TUN" : `完整节点名称-${index}`,
        evidence: [
          {
            level: "confirmed",
            source: "mihomo",
            summary: "节点供应商与控制器详情仅用于 fixture",
          },
        ],
      })),
      evidence: [
        {
          level: "confirmed",
          source: "mihomo",
          summary: "rule DOMAIN-SUFFIX example.com via controller fixture",
        },
      ],
    },
    conclusion: {
      title: "已确认代理",
      summary: "通过香港住宅-私有节点名和本地控制器访问 public.example。",
      level: "confirmed",
    },
    evidence: [
      {
        level: "confirmed",
        source: "system_proxy",
        summary: "controller 127.0.0.1:9090 and provider private detail",
      },
    ],
  };

  const text = await resultExport(proxyResultWithSensitiveChain).text();
  const report = JSON.parse(text);

  expect(report).toEqual({
    export_version: 2,
    redacted: true,
    diagnostic: {
      url: "https://public.example/",
      resolved_ips: ["198.51.100.3"],
      proxy: {
        kind: "http",
        host: null,
        port: 7890,
        evidence: { level: "confirmed", source: "system_proxy" },
      },
      route: {
        destination: "198.51.100.3",
        gateway: null,
      },
      http: {
        status: 200,
        final_url: "https://public.example/",
        elapsed_ms: 42,
        error_code: null,
        peer_endpoint: { ip: "198.51.100.3", port: 443 },
      },
      traffic_decision: {
        kind: "proxy",
        evidence: [{ level: "confirmed", source: "mihomo" }],
        node_counts: {
          tun: 1,
          traffic_rule: 0,
          policy_group: 1,
          proxy_node: 2,
          blocked: 0,
          unknown: 0,
        },
      },
      conclusion: { title: "已确认代理", level: "confirmed" },
      evidence: [{ level: "confirmed", source: "system_proxy" }],
    },
  });
  expect(Object.keys(report.diagnostic).sort()).toEqual([
    "conclusion",
    "evidence",
    "http",
    "proxy",
    "resolved_ips",
    "route",
    "traffic_decision",
    "url",
  ]);
  expect(report.diagnostic).not.toHaveProperty("id");
  expect(report.diagnostic.route).toEqual({
    destination: "198.51.100.3",
    gateway: null,
  });
  expect(report.diagnostic.route).not.toHaveProperty("interface");
  expect(report.diagnostic.proxy).not.toHaveProperty("bypass_reason");
  expect(report.diagnostic.traffic_decision).not.toHaveProperty("mode");
  expect(report.diagnostic.traffic_decision).not.toHaveProperty("tun_enabled");
  expect(report.diagnostic.traffic_decision).not.toHaveProperty("rule");
  expect(report.diagnostic.traffic_decision).not.toHaveProperty("chain");
  expect(report.diagnostic.conclusion).not.toHaveProperty("summary");
  expect(text).not.toContain("fixture-secret");
  expect(text).not.toContain("/private/path");
  expect(text).not.toContain("DOMAIN-SUFFIX");
  expect(text).not.toContain("香港住宅-私有节点名");
  expect(text).not.toContain("完整节点名称");
  expect(text).not.toContain("127.0.0.1");
  expect(text).not.toContain("192.168.1.1");
  expect(text).not.toContain("fd00::1");
  expect(text).not.toContain("controller");
  expect(text).not.toContain("provider");
});

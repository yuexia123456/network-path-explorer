import { afterEach, expect, test, vi } from "vitest";
import { createRouteTraceController, routeTraceModel } from "./route-trace";
import {
  localProxyResult,
  observedDirectResult,
  unansweredTraceResult
} from "./test-fixtures";
import type { ApiSubscription } from "./api";
import type { RouteTraceSnapshot, TraceEvent, TraceRequestKind } from "./types";

const runningTrace: RouteTraceSnapshot = {
  status: "running",
  result: null,
  error: null
};

const completedTrace: RouteTraceSnapshot = {
  status: "completed",
  result: unansweredTraceResult,
  error: null
};

function deferred<T>(): { promise: Promise<T>; resolve(value: T): void } {
  let resolve!: (value: T) => void;
  return { promise: new Promise<T>((next) => { resolve = next; }), resolve };
}

function traceApi() {
  let onEvent: ((event: TraceEvent) => void) | undefined;
  let onError: (() => void) | undefined;
  let onTerminal: ((snapshot: RouteTraceSnapshot) => void) | undefined;
  const close = vi.fn();
  const subscription: ApiSubscription = { close, done: Promise.resolve() };
  const startRouteTrace = vi.fn(async (_runId: string, _kind: TraceRequestKind) => runningTrace);
  const subscribeToRouteTrace = vi.fn(
    (
      _runId: string,
      nextEvent: (event: TraceEvent) => void,
      nextError: () => void,
      nextTerminal: (snapshot: RouteTraceSnapshot) => void
    ) => {
      onEvent = nextEvent;
      onError = nextError;
      onTerminal = nextTerminal;
      return subscription;
    }
  );
  const cancelRouteTrace = vi.fn(async () => undefined);
  return {
    api: { startRouteTrace, subscribeToRouteTrace, cancelRouteTrace },
    startRouteTrace,
    subscribeToRouteTrace,
    cancelRouteTrace,
    close,
    event: (event: TraceEvent) => onEvent?.(event),
    fail: () => onError?.(),
    terminal: (snapshot: RouteTraceSnapshot) => onTerminal?.(snapshot)
  };
}

afterEach(() => {
  document.body.replaceChildren();
  vi.restoreAllMocks();
});

test("keeps actual availability separate from the reference destination", () => {
  const unavailable = routeTraceModel(localProxyResult, null);
  const direct = routeTraceModel(observedDirectResult, null);

  expect(unavailable.actual).toEqual({
    available: false,
    label: "实际路径（当前不可用）"
  });
  expect(unavailable.reference).toEqual({
    available: true,
    label: "参考路径（到网站地址）"
  });
  expect(direct.actual.available).toBe(true);
  expect(direct.reference.label).toContain("参考路径");
});

test.each([
  ["actual", "实际路径", "目标：实际网站连接"],
  ["reference", "参考路径", "目标：参考网站地址"]
] as const)("renders an independent %s hop layer with unanswered hops", async (kind, badge, target) => {
  const controlled = traceApi();
  const controller = createRouteTraceController(controlled.api, "run/1", observedDirectResult);
  document.body.append(controller.element);

  controller.element.querySelector<HTMLButtonElement>(`[data-trace-kind="${kind}"]`)?.click();
  await vi.waitFor(() => expect(controlled.startRouteTrace).toHaveBeenCalledWith("run/1", kind));
  controlled.event({ sequence: 0, stage: "selecting_target", hop: null });
  controlled.event({ sequence: 1, stage: "probing", hop: null });
  controlled.terminal({
    ...completedTrace,
    result: {
      ...unansweredTraceResult,
      target: {
        kind: kind === "actual" ? "actual_destination" : "reference_destination",
        ip: unansweredTraceResult.target.ip
      }
    }
  });

  await vi.waitFor(() => expect(controller.element.textContent).toContain("*（该跳未回应）"));
  expect(controller.element.querySelector("[data-trace-badge]")?.textContent).toBe(badge);
  expect(controller.element.textContent).toContain("第 1 跳");
  expect(controller.element.textContent).toContain("1.2 ms、1.4 ms");
  expect(controller.element.textContent).toContain(target);
  expect(controller.element.querySelector('[aria-live="polite"]')?.textContent).toContain(
    "路径探测完成"
  );
  await controller.dispose();
  expect(controlled.cancelRouteTrace).not.toHaveBeenCalled();
});

test("shows progress, streams hops, and cancels only a running trace", async () => {
  const controlled = traceApi();
  const controller = createRouteTraceController(controlled.api, "run/1", observedDirectResult);
  document.body.append(controller.element);

  controller.element.querySelector<HTMLButtonElement>('[data-trace-kind="actual"]')?.click();
  await vi.waitFor(() => expect(controlled.subscribeToRouteTrace).toHaveBeenCalledOnce());
  controlled.event({
    sequence: 0,
    stage: "hop",
    hop: { index: 1, address: "192.168.1.1", rtts_ms: [1.1], level: "confirmed" }
  });
  expect(controller.element.textContent).toContain("192.168.1.1");
  expect(controller.element.textContent).toContain("正在探测实际路径");

  controller.element.querySelector<HTMLButtonElement>('[data-action="cancel-trace"]')?.click();
  await vi.waitFor(() => expect(controlled.cancelRouteTrace).toHaveBeenCalledWith("run/1"));
  expect(controlled.close).toHaveBeenCalledOnce();
  expect(controller.element.textContent).toContain("路径探测已取消");

  await controller.dispose();
  expect(controlled.cancelRouteTrace).toHaveBeenCalledOnce();
});

test("closes and cancels a running subscription before starting another trace", async () => {
  const firstStart = deferred<RouteTraceSnapshot>();
  const controlled = traceApi();
  controlled.startRouteTrace.mockImplementationOnce(async () => firstStart.promise);
  const controller = createRouteTraceController(controlled.api, "run/1", observedDirectResult);
  document.body.append(controller.element);

  controller.element.querySelector<HTMLButtonElement>('[data-trace-kind="actual"]')?.click();
  firstStart.resolve(runningTrace);
  await vi.waitFor(() => expect(controlled.subscribeToRouteTrace).toHaveBeenCalledOnce());
  controller.element.querySelector<HTMLButtonElement>('[data-trace-kind="reference"]')?.click();

  await vi.waitFor(() => expect(controlled.startRouteTrace).toHaveBeenCalledTimes(2));
  expect(controlled.close).toHaveBeenCalledOnce();
  expect(controlled.cancelRouteTrace).toHaveBeenCalledWith("run/1");
});

test("dispose closes SSE and DELETEs only while the trace is running", async () => {
  const running = traceApi();
  const runningController = createRouteTraceController(running.api, "run/1", observedDirectResult);
  runningController.element.querySelector<HTMLButtonElement>('[data-trace-kind="actual"]')?.click();
  await vi.waitFor(() => expect(running.subscribeToRouteTrace).toHaveBeenCalledOnce());
  await runningController.dispose();
  expect(running.close).toHaveBeenCalledOnce();
  expect(running.cancelRouteTrace).toHaveBeenCalledWith("run/1");

  const completed = traceApi();
  const completedController = createRouteTraceController(
    completed.api,
    "run/2",
    observedDirectResult
  );
  completedController.element.querySelector<HTMLButtonElement>('[data-trace-kind="actual"]')?.click();
  await vi.waitFor(() => expect(completed.subscribeToRouteTrace).toHaveBeenCalledOnce());
  completed.terminal(completedTrace);
  await completedController.dispose();
  expect(completed.cancelRouteTrace).not.toHaveBeenCalled();
});

test("dispose settles while a start response never arrives and prevents late DOM work", async () => {
  const controlled = traceApi();
  controlled.startRouteTrace.mockImplementationOnce(
    async () => new Promise<RouteTraceSnapshot>(() => undefined)
  );
  const controller = createRouteTraceController(controlled.api, "run/1", observedDirectResult);
  controller.element.querySelector<HTMLButtonElement>('[data-trace-kind="actual"]')?.click();
  await vi.waitFor(() => expect(controlled.startRouteTrace).toHaveBeenCalledOnce());

  await expect(
    Promise.race([
      controller.dispose(),
      new Promise<never>((_, reject) =>
        globalThis.setTimeout(() => reject(new Error("dispose hard timeout")), 100)
      )
    ])
  ).resolves.toBeUndefined();
  expect(controlled.cancelRouteTrace).toHaveBeenCalledWith("run/1");
  expect(controlled.subscribeToRouteTrace).not.toHaveBeenCalled();
});

test("dispose during a pending start cancels that generation exactly once after a late running response", async () => {
  const lateStart = deferred<RouteTraceSnapshot>();
  const controlled = traceApi();
  controlled.startRouteTrace.mockImplementationOnce(async () => lateStart.promise);
  const controller = createRouteTraceController(controlled.api, "run/late", observedDirectResult);
  controller.element.querySelector<HTMLButtonElement>('[data-trace-kind="actual"]')?.click();
  await vi.waitFor(() => expect(controlled.startRouteTrace).toHaveBeenCalledOnce());

  await controller.dispose();
  expect(controlled.cancelRouteTrace).toHaveBeenCalledTimes(1);

  lateStart.resolve(runningTrace);
  await new Promise((resolve) => globalThis.setTimeout(resolve, 0));

  expect(controlled.cancelRouteTrace).toHaveBeenCalledTimes(1);
  expect(controlled.subscribeToRouteTrace).not.toHaveBeenCalled();
  expect(controller.element.textContent).not.toContain("路径探测完成");
});

test.each(["completed", "failed", "cancelled"] as const)(
  "dispose never DELETEs a %s trace",
  async (status) => {
    const controlled = traceApi();
    const controller = createRouteTraceController(controlled.api, `run/${status}`, observedDirectResult);
    controller.element.querySelector<HTMLButtonElement>('[data-trace-kind="actual"]')?.click();
    await vi.waitFor(() => expect(controlled.subscribeToRouteTrace).toHaveBeenCalledOnce());
    controlled.terminal({
      status,
      result: status === "completed" ? unansweredTraceResult : null,
      error: status === "failed" ? { code: "trace_failed", message: "trace failed" } : null
    });

    await controller.dispose();

    expect(controlled.cancelRouteTrace).not.toHaveBeenCalled();
  }
);

test("trace failure stays inside the route layer", async () => {
  const controlled = traceApi();
  const preserved = document.createElement("article");
  preserved.textContent = "已完成的网址检测结论";
  const controller = createRouteTraceController(controlled.api, "run/1", observedDirectResult);
  document.body.append(preserved, controller.element);

  controller.element.querySelector<HTMLButtonElement>('[data-trace-kind="actual"]')?.click();
  await vi.waitFor(() => expect(controlled.subscribeToRouteTrace).toHaveBeenCalledOnce());
  controlled.fail();

  expect(preserved.textContent).toBe("已完成的网址检测结论");
  expect(controller.element.textContent).toContain("路径探测失败");
});

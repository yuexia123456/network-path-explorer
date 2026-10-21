import { afterEach, expect, test, vi } from "vitest";
import "./styles.css";
import { degradingOverview, directResult, observedDirectResult } from "./test-fixtures";
import type {
  NetworkOverviewResponse,
  RunSnapshot,
  StageEvent,
  UrlDiagnosticResult
} from "./types";

const encoder = new TextEncoder();

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

function deferred<T>(): { promise: Promise<T>; resolve(value: T): void; reject(reason?: unknown): void } {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  return { promise: new Promise<T>((next, fail) => { resolve = next; reject = fail; }), resolve, reject };
}

async function within<T>(promise: Promise<T>, milliseconds = 250): Promise<T> {
  let timeout: ReturnType<typeof globalThis.setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timeout = globalThis.setTimeout(() => reject(new Error("hard timeout")), milliseconds);
      })
    ]);
  } finally {
    if (timeout !== undefined) globalThis.clearTimeout(timeout);
  }
}

function controlledSse(): {
  response: Response;
  send(stage: StageEvent): void;
  close(): void;
} {
  let controller: ReadableStreamDefaultController<Uint8Array> | undefined;
  const response = new Response(
    new ReadableStream<Uint8Array>({
      start(next) {
        controller = next;
      }
    }),
    { status: 200, headers: { "Content-Type": "text/event-stream" } }
  );
  return {
    response,
    send: (stage) => controller?.enqueue(encoder.encode(`event: stage\ndata: ${JSON.stringify(stage)}\n\n`)),
    close: () => controller?.close()
  };
}

async function mount(hash = ""): Promise<void> {
  vi.resetModules();
  document.body.innerHTML = '<main id="app"></main>';
  window.history.replaceState(null, "", `/${hash}`);
  await import("./main");
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  window.history.replaceState(null, "", "/");
});

test("initial result is hidden even though the result class uses grid layout", async () => {
  await mount("#token=session-token");
  const result = document.querySelector<HTMLElement>("#result");

  expect(result?.hidden).toBe(true);
  expect(result ? getComputedStyle(result).display : "missing").toBe("none");
});

test("makes URL checking the first task and keeps secondary diagnostics collapsed", async () => {
  await mount("#token=session-token");
  const form = document.querySelector<HTMLElement>("#diagnostic-form");
  const overview = document.querySelector<HTMLDetailsElement>("#network-overview-disclosure");
  const speed = document.querySelector<HTMLDetailsElement>(".secondary-tool-disclosure");

  expect(document.querySelector("#page-title")?.textContent).toBe("这个网址，能连上吗？");
  expect(document.querySelector("#task-title")?.textContent).toBe("网址或域名");
  expect(document.querySelector<HTMLButtonElement>('#diagnostic-form button[type="submit"]')?.textContent).toBe("检查网址");
  expect(form && overview && Boolean(form.compareDocumentPosition(overview) & Node.DOCUMENT_POSITION_FOLLOWING)).toBe(true);
  expect(overview?.open).toBe(false);
  expect(speed?.open).toBe(false);
  expect(document.querySelector(".overview-section")?.getAttribute("aria-label")).toBe("本机网络概览");
  expect(document.querySelector("#speed-test-host")?.getAttribute("aria-label")).toBe("Cloudflare 测速");
  expect(document.querySelector(".skip-link")?.getAttribute("href")).toBe("#primary-task");
});

test("accepts a backend-supported bare hostname at the HTML validation boundary", async () => {
  await mount("#token=session-token");
  const input = document.querySelector<HTMLInputElement>("#url");
  if (!input) throw new Error("diagnostic input is missing");

  input.value = "example.com";

  expect(input.type).toBe("text");
  expect(input.inputMode).toBe("url");
  expect(input.checkValidity()).toBe(true);
});

test("the result grid has an explicit hidden display override", () => {
  const rule = Array.from(document.styleSheets)
    .flatMap((sheet) => Array.from(sheet.cssRules))
    .find((candidate) => candidate instanceof CSSStyleRule && candidate.selectorText === ".result[hidden]");

  expect(rule instanceof CSSStyleRule ? rule.style.display : "missing").toBe("none");
});

test("a network error keeps result cards hidden and re-enables the form", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new Error("offline"))));
  await mount("#token=session-token");
  const form = document.querySelector<HTMLFormElement>("#diagnostic-form");
  const input = document.querySelector<HTMLInputElement>("#url");
  input?.setAttribute("value", "https://example.com");
  input?.dispatchEvent(new Event("input", { bubbles: true }));
  form?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

  await vi.waitFor(() => {
    expect(document.querySelector("#progress")?.textContent).toBe("本地检测程序没有响应，请重新启动工具");
  });
  const result = document.querySelector<HTMLElement>("#result");
  expect(result?.hidden).toBe(true);
  expect(result ? getComputedStyle(result).display : "missing").toBe("none");
  expect(document.querySelector<HTMLButtonElement>('button[type="submit"]')?.disabled).toBe(false);
});

test("shows a safe DNS failure explanation without rendering a route conclusion", async () => {
  const failed: RunSnapshot = {
    id: "run-dns",
    status: "failed",
    result: null,
    error: { code: "dns_failed", message: "无法解析域名，请检查网址或 DNS 设置" }
  };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input);
    if (path === "/api/v1/url-diagnostics") return jsonResponse({ run_id: "run-dns" });
    if (path.endsWith("/events")) {
      return new Response("event: stage\ndata: {\"sequence\":1,\"stage\":\"failed\"}\n\n", {
        status: 200,
        headers: { "Content-Type": "text/event-stream" }
      });
    }
    return jsonResponse(failed);
  }));
  await mount("#token=session-token");
  const form = document.querySelector<HTMLFormElement>("#diagnostic-form");
  const input = document.querySelector<HTMLInputElement>("#url");
  if (!form || !input) throw new Error("diagnostic form is missing");
  input.value = "https://does-not-exist.invalid";
  form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

  await vi.waitFor(() => {
    expect(document.querySelector("#progress")?.textContent).toBe("无法解析域名，请检查网址或 DNS 设置");
  });
  expect(document.querySelector<HTMLElement>("#result")?.hidden).toBe(true);
  expect(document.body.textContent).not.toContain("系统代理配置：直连");
});

test("clears the hash token immediately without persisting or rendering it", async () => {
  window.localStorage.clear();
  window.sessionStorage.clear();
  await mount("#token=session-token");

  expect(window.location.hash).toBe("");
  expect(window.localStorage.length).toBe(0);
  expect(window.sessionStorage.length).toBe(0);
  expect(document.body.textContent).not.toContain("session-token");
});

test("renders the service conclusion title for a proxied diagnostic", async () => {
  vi.stubGlobal("matchMedia", () => ({
    matches: false,
    addEventListener: () => undefined,
    removeEventListener: () => undefined
  }));
  const proxiedResult: UrlDiagnosticResult = {
    ...directResult,
    traffic_decision: { ...directResult.traffic_decision, kind: "proxy" },
    conclusion: {
      title: "不是直连",
      summary: "系统代理配置选择本机代理 127.0.0.1:2023。",
      level: "confirmed"
    }
  };
  const completed: RunSnapshot = { id: "run-proxy", status: "completed", result: proxiedResult, error: null };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input);
    if (path === "/api/v1/url-diagnostics") return jsonResponse({ run_id: "run-proxy" });
    if (path.endsWith("/events")) {
      return new Response("event: stage\ndata: {\"sequence\":1,\"stage\":\"completed\"}\n\n", {
        status: 200,
        headers: { "Content-Type": "text/event-stream" }
      });
    }
    return jsonResponse(completed);
  }));
  await mount("#token=session-token");
  const form = document.querySelector<HTMLFormElement>("#diagnostic-form");
  const input = document.querySelector<HTMLInputElement>("#url");
  if (!form || !input) throw new Error("diagnostic form is missing");
  input.value = "https://example.com";
  form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

  await vi.waitFor(() => {
    expect(document.querySelector("#conclusion-title")?.textContent).toBe("不是直连");
  });
  expect(document.querySelector("[data-traffic-decision-label]")?.textContent).toBe(
    "规则判断经代理连接"
  );
  expect(document.querySelector("[data-traffic-decision-code]")?.textContent).toBe(
    "Mihomo · PROXY"
  );
});

test("a late A submission cannot overwrite an active B submission", async () => {
  vi.stubGlobal("matchMedia", () => ({
    matches: false,
    addEventListener: () => undefined,
    removeEventListener: () => undefined
  }));
  const firstPost = deferred<Response>();
  const bEvents = controlledSse();
  let bSubscribed = false;
  const aEventSignals: Array<AbortSignal | null | undefined> = [];
  const bResult: UrlDiagnosticResult = {
    ...directResult,
    id: "run-b",
    requested_url: "https://b.example",
    conclusion: { ...directResult.conclusion, summary: "B 的检测结论。" }
  };
  const bCompleted: RunSnapshot = { id: "run-b", status: "completed", result: bResult, error: null };
  const aRunning: RunSnapshot = {
    id: "run-a",
    status: "running",
    result: null,
    error: null
  };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === "/api/v1/url-diagnostics") {
      const url = JSON.parse(String(init?.body)) as { url: string };
      return url.url === "https://a.example" ? firstPost.promise : jsonResponse({ run_id: "run-b" });
    }
    if (path === "/api/v1/runs/run-b/events") {
      bSubscribed = true;
      return bEvents.response;
    }
    if (path === "/api/v1/runs/run-a/events") {
      aEventSignals.push(init?.signal);
      return new Response("", { status: 200, headers: { "Content-Type": "text/event-stream" } });
    }
    if (path === "/api/v1/runs/run-a") return jsonResponse(aRunning);
    return jsonResponse(bCompleted);
  }));
  await mount("#token=session-token");
  const form = document.querySelector<HTMLFormElement>("#diagnostic-form");
  const input = document.querySelector<HTMLInputElement>("#url");
  const submit = document.querySelector<HTMLButtonElement>('button[type="submit"]');
  const send = (url: string): void => {
    if (!input || !form) throw new Error("diagnostic form is missing");
    input.value = url;
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  };

  send("https://a.example");
  await vi.waitFor(() => expect(submit?.disabled).toBe(true));
  send("https://b.example");
  await vi.waitFor(() => expect(bSubscribed).toBe(true));
  bEvents.send({ sequence: 0, stage: "http" });
  await vi.waitFor(() => expect(document.querySelector("#progress")?.textContent).toBe("正在测试连接"));

  vi.useFakeTimers();
  firstPost.resolve(jsonResponse({ run_id: "run-a" }));
  await vi.runAllTimersAsync();

  expect(document.querySelector("#progress")?.textContent).toBe("正在测试连接");
  expect(submit?.disabled).toBe(true);
  expect(aEventSignals).toEqual([]);
  vi.useRealTimers();

  bEvents.send({ sequence: 1, stage: "completed" });
  bEvents.close();
  await vi.waitFor(() => expect(document.querySelector("#conclusion-text")?.textContent).toBe("B 的检测结论。"));
  expect(document.querySelector("#progress")?.textContent).toBe("检测完成");
  expect(submit?.disabled).toBe(false);
});

test("loads overview independently with ipify disclosure and a working retry", async () => {
  const firstOverview = deferred<Response>();
  let overviewCalls = 0;
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    if (String(input) === "/api/v1/network-overview") {
      overviewCalls += 1;
      return overviewCalls === 1 ? firstOverview.promise : jsonResponse(degradingOverview);
    }
    throw new Error(`unexpected request ${String(input)}`);
  }));

  await mount("#token=session-token");

  expect(document.querySelector("#network-overview")?.textContent).toContain(
    "ipify 只会收到这次公网 IP 查询"
  );
  firstOverview.reject(new Error("overview unavailable"));
  await vi.waitFor(() => expect(document.querySelector("#network-overview")?.textContent).toContain(
    "网络概览暂时无法读取"
  ));

  document.querySelector<HTMLButtonElement>('[data-action="retry-overview"]')?.click();
  await vi.waitFor(() => expect(document.querySelector("#network-overview")?.textContent).toContain(
    "203.0.113.7"
  ));
  expect(overviewCalls).toBe(2);
});

test("a stale overview refresh cannot overwrite the latest overview generation", async () => {
  const staleOverview = deferred<Response>();
  let overviewCalls = 0;
  const latest: NetworkOverviewResponse = {
    ...degradingOverview,
    egress: degradingOverview.egress
      ? { ...degradingOverview.egress, ip: "198.51.100.88" }
      : null
  };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    if (String(input) !== "/api/v1/network-overview") {
      throw new Error(`unexpected request ${String(input)}`);
    }
    overviewCalls += 1;
    if (overviewCalls === 1) return jsonResponse(degradingOverview);
    if (overviewCalls === 2) return staleOverview.promise;
    return jsonResponse(latest);
  }));
  await mount("#token=session-token");
  await vi.waitFor(() => expect(document.querySelector("#network-overview")?.textContent).toContain(
    "203.0.113.7"
  ));
  const refresh = document.querySelector<HTMLButtonElement>('[data-action="refresh-overview"]');
  refresh?.click();
  refresh?.click();

  await vi.waitFor(() => expect(document.querySelector("#network-overview")?.textContent).toContain(
    "198.51.100.88"
  ));
  staleOverview.resolve(jsonResponse({
    ...degradingOverview,
    egress: degradingOverview.egress
      ? { ...degradingOverview.egress, ip: "192.0.2.44" }
      : null
  }));
  await Promise.resolve();
  await Promise.resolve();

  expect(document.querySelector("#network-overview")?.textContent).toContain("198.51.100.88");
  expect(document.querySelector("#network-overview")?.textContent).not.toContain("192.0.2.44");
});

test("a stalled trace DELETE cannot block the next URL and old trace DOM is invalidated", async () => {
  vi.stubGlobal("matchMedia", () => ({
    matches: false,
    addEventListener: () => undefined,
    removeEventListener: () => undefined
  }));
  let diagnosticStarts = 0;
  const traceEvents = controlledSse();
  const deletes: string[] = [];
  let routeSignal: AbortSignal | null | undefined;
  const completed = (id: string, summary: string): RunSnapshot => ({
    id,
    status: "completed",
    result: {
      ...observedDirectResult,
      id,
      conclusion: { ...observedDirectResult.conclusion, summary }
    },
    error: null
  });
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === "/api/v1/network-overview") return jsonResponse(degradingOverview);
    if (path === "/api/v1/url-diagnostics") {
      diagnosticStarts += 1;
      return jsonResponse({ run_id: diagnosticStarts === 1 ? "run-a" : "run-b" });
    }
    if (path.endsWith("/events") && path.includes("route-trace")) {
      routeSignal = init?.signal;
      return traceEvents.response;
    }
    if (path.endsWith("/events")) {
      return new Response(
        "event: stage\ndata: {\"sequence\":1,\"stage\":\"completed\"}\n\n",
        { status: 200, headers: { "Content-Type": "text/event-stream" } }
      );
    }
    if (path.endsWith("/route-trace") && init?.method === "POST") {
      return jsonResponse({ status: "running", result: null, error: null });
    }
    if (path.endsWith("/route-trace") && init?.method === "DELETE") {
      deletes.push(path);
      return new Promise<Response>(() => undefined);
    }
    if (path === "/api/v1/runs/run-a") return jsonResponse(completed("run-a", "A 的网址结论"));
    if (path === "/api/v1/runs/run-b") return jsonResponse(completed("run-b", "B 的网址结论"));
    throw new Error(`unexpected request ${path}`);
  }));
  await mount("#token=session-token");
  const form = document.querySelector<HTMLFormElement>("#diagnostic-form");
  const input = document.querySelector<HTMLInputElement>("#url");
  if (!form || !input) throw new Error("diagnostic form is missing");
  const submitUrl = (url: string): void => {
    input.value = url;
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  };

  submitUrl("https://a.example");
  await vi.waitFor(() => expect(document.querySelector("#conclusion-text")?.textContent).toBe(
    "A 的网址结论"
  ));
  const logical = document.querySelector<HTMLElement>("#logical-path-layer");
  const route = document.querySelector<HTMLElement>("#route-trace-layer");
  if (!logical || !route) throw new Error("path layers are missing");
  expect(logical.compareDocumentPosition(route) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(logical.textContent).toContain("Mihomo：DIRECT");
  expect(route.textContent).toContain("实际路径");
  expect(route.textContent).toContain("参考路径");

  route.querySelector<HTMLButtonElement>('[data-trace-kind="actual"]')?.click();
  await vi.waitFor(() => expect(route.textContent).toContain("正在探测实际路径"));
  const oldTrace = route.querySelector<HTMLElement>(".route-trace");
  submitUrl("https://b.example");

  await within(vi.waitFor(() => expect(diagnosticStarts).toBe(2)));
  await within(vi.waitFor(() => expect(document.querySelector("#conclusion-text")?.textContent).toBe(
    "B 的网址结论"
  )));
  expect(deletes).toEqual(["/api/v1/runs/run-a/route-trace"]);
  expect(routeSignal?.aborted).toBe(true);
  expect(oldTrace?.isConnected).toBe(false);
  expect(document.body.textContent).not.toContain("第 99 跳");
});

test("provides horizontal long-chain overflow, narrow layout, and reduced motion", () => {
  const allRules = Array.from(document.styleSheets).flatMap((sheet) =>
    Array.from(sheet.cssRules)
  );
  const wrap = allRules.find(
    (rule) => rule instanceof CSSStyleRule && rule.selectorText === ".diagram-wrap"
  );
  const mediaText = allRules.map((rule) => rule.cssText).join("\n");
  const closedMarker = allRules.find(
    (rule) => rule instanceof CSSStyleRule && rule.selectorText === "summary::after"
  );
  const openMarker = allRules.find(
    (rule) => rule instanceof CSSStyleRule && rule.selectorText === "details[open] > summary::after"
  );

  expect(wrap instanceof CSSStyleRule ? wrap.style.overflowX : "missing").toBe("auto");
  expect(closedMarker instanceof CSSStyleRule ? closedMarker.style.content : "missing").toBe('"+"');
  expect(openMarker instanceof CSSStyleRule ? openMarker.style.content : "missing").toBe('"−"');
  expect(mediaText).toContain("max-width: 719px");
  expect(mediaText).toContain("prefers-reduced-motion: reduce");
});

test("renders separate quick/full Cloudflare speed actions with exact confirmation disclosures", async () => {
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    if (String(input) === "/api/v1/network-overview") return jsonResponse(degradingOverview);
    throw new Error(`unexpected request ${String(input)}`);
  }));
  await mount("#token=session-token");

  const speed = document.querySelector<HTMLElement>("[data-speed-test]");
  expect(speed).not.toBeNull();
  expect(speed?.querySelector<HTMLButtonElement>('[data-speed-action="quick"]')?.textContent).toBe(
    "快速测速（约 10 秒）"
  );
  expect(speed?.querySelector<HTMLButtonElement>('[data-speed-action="full"]')?.textContent).toBe(
    "完整测速（约 30 秒）"
  );

  speed?.querySelector<HTMLButtonElement>('[data-speed-action="quick"]')?.click();
  expect(speed?.textContent).toContain("Cloudflare");
  expect(speed?.textContent).toContain("最多约 40 MB");
  expect(speed?.textContent).toContain("代表到 Cloudflare 公网边缘的路径");
  expect(speed?.textContent).toContain("不代表所有网站");
  speed?.querySelector<HTMLButtonElement>("[data-speed-dismiss]")?.click();
  speed?.querySelector<HTMLButtonElement>('[data-speed-action="full"]')?.click();
  expect(speed?.textContent).toContain("最多约 200 MB");
});

test("keeps speed-path presentation independent from the URL diagnostic path layer", async () => {
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    if (String(input) === "/api/v1/network-overview") return jsonResponse(degradingOverview);
    throw new Error(`unexpected request ${String(input)}`);
  }));
  await mount("#token=session-token");

  const speed = document.querySelector<HTMLElement>("[data-speed-test]");
  expect(speed?.textContent).toContain("测速请求独立路径");
  expect(speed?.textContent).not.toContain("网址诊断决策");
});

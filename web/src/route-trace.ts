import type { ApiClient, ApiSubscription } from "./api";
import type {
  EvidenceLevel,
  RouteTraceResult,
  RouteTraceSnapshot,
  TraceEvent,
  TraceRequestKind,
  TraceTargetKind,
  UrlDiagnosticResult
} from "./types";

export type RouteTraceApi = Pick<
  ApiClient,
  "startRouteTrace" | "subscribeToRouteTrace" | "cancelRouteTrace"
>;

export interface RouteTraceChoice {
  available: boolean;
  label: string;
}

export interface RouteTraceViewModel {
  actual: RouteTraceChoice;
  reference: RouteTraceChoice;
}

export interface RouteTraceController {
  element: HTMLElement;
  dispose(): Promise<void>;
}

function isLoopback(ip: string): boolean {
  return ip === "::1" || /^127(?:\.\d{1,3}){3}$/.test(ip);
}

function hasActualTarget(result: UrlDiagnosticResult): boolean {
  if (result.traffic_decision.kind === "direct") {
    return Boolean(result.http.peer_endpoint && !isLoopback(result.http.peer_endpoint.ip));
  }
  if (result.traffic_decision.kind !== "proxy") return false;
  return result.traffic_decision.chain.some(
    (node) => node.endpoint !== null && !isLoopback(node.endpoint.ip)
  );
}

export function routeTraceModel(
  result: UrlDiagnosticResult,
  _snapshot: RouteTraceSnapshot | null
): RouteTraceViewModel {
  const actualAvailable = hasActualTarget(result);
  return {
    actual: {
      available: actualAvailable,
      label: actualAvailable ? "实际路径" : "实际路径（当前不可用）"
    },
    reference: {
      available: result.resolved_ips.length > 0,
      label: "参考路径（到网站地址）"
    }
  };
}

function targetLabel(kind: TraceTargetKind): string {
  if (kind === "actual_destination") return "实际网站连接";
  if (kind === "actual_proxy") return "实际代理节点";
  return "参考网站地址";
}

function evidenceLabel(level: EvidenceLevel): string {
  if (level === "confirmed") return "已确认";
  if (level === "inferred") return "根据配置推断";
  return "未知";
}

function progressFor(kind: TraceRequestKind, stage: TraceEvent["stage"]): string {
  const layer = kind === "actual" ? "实际路径" : "参考路径";
  if (stage === "selecting_target") return `正在选择${layer}目标`;
  if (stage === "completed") return "路径探测完成";
  if (stage === "failed") return "路径探测失败";
  if (stage === "cancelled") return "路径探测已取消";
  return `正在探测${layer}`;
}

function makeElement<K extends keyof HTMLElementTagNameMap>(name: K, className?: string) {
  const result = document.createElement(name);
  if (className) result.className = className;
  return result;
}

export function createRouteTraceController(
  api: RouteTraceApi,
  runId: string,
  result: UrlDiagnosticResult
): RouteTraceController {
  const model = routeTraceModel(result, null);
  const root = makeElement("section", "route-trace");
  root.setAttribute("aria-labelledby", `route-trace-title-${runId}`);
  const title = makeElement("h3");
  title.id = `route-trace-title-${runId}`;
  title.textContent = "网络路由跳点";
  const explanation = makeElement("p", "route-trace-explanation");
  explanation.textContent = "实际路径尝试探测这次连接沿途有回应的设备；参考路径只探测到网站地址。它们不等于上方的代理规则链，部分设备不会回应，未显示也不代表不存在。";
  const controls = makeElement("div", "route-trace-controls");
  const actual = makeElement("button");
  actual.type = "button";
  actual.dataset.traceKind = "actual";
  actual.textContent = model.actual.label;
  actual.disabled = !model.actual.available;
  const reference = makeElement("button");
  reference.type = "button";
  reference.dataset.traceKind = "reference";
  reference.textContent = model.reference.label;
  reference.disabled = !model.reference.available;
  const cancel = makeElement("button", "secondary-button");
  cancel.type = "button";
  cancel.dataset.action = "cancel-trace";
  cancel.textContent = "取消路径探测";
  cancel.hidden = true;
  controls.append(actual, reference, cancel);
  const progress = makeElement("p", "route-trace-progress");
  progress.setAttribute("aria-live", "polite");
  const summary = makeElement("div", "route-trace-summary");
  const badge = makeElement("span", "route-trace-badge");
  badge.dataset.traceBadge = "";
  badge.hidden = true;
  const target = makeElement("p", "route-trace-target");
  summary.append(badge, target);
  const hops = makeElement("ol", "route-hop-list");
  hops.setAttribute("aria-label", "路由跳数");
  root.append(title, explanation, controls, progress, summary, hops);

  let generation = 0;
  let disposed = false;
  let running = false;
  let subscription: ApiSubscription | undefined;
  let selectedKind: TraceRequestKind | undefined;
  let activeTraceGeneration: number | undefined;
  const cancelledTraceGenerations = new Set<number>();
  let transition = Promise.resolve();

  const clearTrace = (): void => {
    hops.replaceChildren();
    target.textContent = "";
    badge.hidden = true;
  };

  const cancelGeneration = (traceGeneration: number): void => {
    if (cancelledTraceGenerations.has(traceGeneration)) return;
    cancelledTraceGenerations.add(traceGeneration);
    try {
      void api.cancelRouteTrace(runId).catch(() => undefined);
    } catch {
      // Cancellation is best effort and must never block the next UI generation.
    }
  };

  const stopRunning = (): void => {
    const shouldCancel = running;
    const traceGeneration = activeTraceGeneration;
    running = false;
    cancel.hidden = true;
    subscription?.close();
    subscription = undefined;
    if (shouldCancel && traceGeneration !== undefined) cancelGeneration(traceGeneration);
  };

  const appendHop = (hop: NonNullable<TraceEvent["hop"]>): void => {
    const old = hops.querySelector(`[data-hop-index="${hop.index}"]`);
    old?.remove();
    const item = makeElement("li", `route-hop ${hop.level}`);
    item.dataset.hopIndex = String(hop.index);
    const heading = makeElement("strong");
    heading.textContent = `第 ${hop.index} 跳`;
    const address = makeElement("span", "route-hop-address");
    address.textContent = hop.address ?? "*（该跳未回应）";
    const rtts = makeElement("span", "route-hop-rtts");
    rtts.textContent =
      hop.rtts_ms.length > 0
        ? hop.rtts_ms.map((milliseconds) => `${milliseconds} ms`).join("、")
        : "未测得 RTT";
    const evidence = makeElement("span", "route-hop-evidence");
    evidence.textContent = evidenceLabel(hop.level);
    item.append(heading, address, rtts, evidence);
    const later = Array.from(hops.children).find(
      (candidate) => Number((candidate as HTMLElement).dataset.hopIndex) > hop.index
    );
    later ? hops.insertBefore(item, later) : hops.append(item);
  };

  const renderResult = (trace: RouteTraceResult): void => {
    hops.replaceChildren();
    trace.hops.forEach(appendHop);
    target.textContent = `目标：${targetLabel(trace.target.kind)} · ${trace.target.ip}`;
    badge.textContent = selectedKind === "actual" ? "实际路径" : "参考路径";
    badge.hidden = false;
    progress.textContent = "路径探测完成";
  };

  const finish = (snapshot: RouteTraceSnapshot): void => {
    running = false;
    cancel.hidden = true;
    subscription = undefined;
    if (snapshot.status === "completed" && snapshot.result) {
      renderResult(snapshot.result);
    } else if (snapshot.status === "cancelled") {
      progress.textContent = "路径探测已取消";
    } else {
      progress.textContent = snapshot.error?.message ?? "路径探测失败";
    }
  };

  const requestStart = (kind: TraceRequestKind): void => {
    const requestedGeneration = ++generation;
    transition = transition.then(async () => {
      if (disposed || requestedGeneration !== generation) return;
      stopRunning();
      if (disposed || requestedGeneration !== generation) return;
      selectedKind = kind;
      clearTrace();
      activeTraceGeneration = requestedGeneration;
      running = true;
      cancel.hidden = false;
      progress.textContent = progressFor(kind, "probing");
      let snapshot: RouteTraceSnapshot;
      try {
        snapshot = await api.startRouteTrace(runId, kind);
      } catch {
        if (requestedGeneration !== generation || disposed) return;
        running = false;
        cancel.hidden = true;
        progress.textContent = "路径探测失败";
        return;
      }
      if (requestedGeneration !== generation || disposed) {
        if (snapshot.status === "running") {
          cancelGeneration(requestedGeneration);
        }
        return;
      }
      if (snapshot.status !== "running") {
        finish(snapshot);
        return;
      }
      subscription = api.subscribeToRouteTrace(
        runId,
        (event) => {
          if (disposed || requestedGeneration !== generation) return;
          progress.textContent = progressFor(kind, event.stage);
          if (event.hop) appendHop(event.hop);
        },
        () => {
          if (disposed || requestedGeneration !== generation) return;
          progress.textContent = "路径探测失败，可取消后重试";
        },
        (terminal) => {
          if (disposed || requestedGeneration !== generation) return;
          finish(terminal);
        }
      );
    });
  };

  actual.addEventListener("click", () => requestStart("actual"));
  reference.addEventListener("click", () => requestStart("reference"));
  cancel.addEventListener("click", () => {
    const cancelGeneration = ++generation;
    transition = transition.then(() => {
      if (disposed || cancelGeneration !== generation) return;
      stopRunning();
      if (!disposed && cancelGeneration === generation) progress.textContent = "路径探测已取消";
    });
  });

  return {
    element: root,
    async dispose(): Promise<void> {
      if (disposed) return;
      disposed = true;
      generation += 1;
      stopRunning();
    }
  };
}

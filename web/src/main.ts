import "./styles.css";
import { createApiClient, resultExport, takeSessionTokenFromHash } from "./api";
import {
  formatConclusion,
  formatDuration,
  presentEvidenceLevel,
  presentTrafficDecision
} from "./format";
import { createNetworkOverview, createNetworkOverviewLoading } from "./network-overview";
import { buildLogicalPathNodes, createPathDiagram } from "./path-diagram";
import { createRouteTraceController } from "./route-trace";
import { createSpeedTestController } from "./speed-test";
import type { Evidence, RunSnapshot, UrlDiagnosticResult } from "./types";

const localUnavailable = "本地检测程序没有响应，请重新启动工具";
const stages: Record<string, string> = {
  validating: "正在检查网址",
  proxy: "正在确认代理",
  dns: "正在解析地址",
  route: "正在确认网络接口",
  http: "正在测试连接",
  completed: "检测完成",
  failed: "检测未能完成"
};

const token = takeSessionTokenFromHash();
const api = createApiClient(token);
const app = document.querySelector<HTMLElement>("#app");
if (!app) throw new Error("Application root is missing");

app.innerHTML = `
  <section class="app-shell" aria-labelledby="page-title">
    <a class="skip-link" href="#primary-task">跳到网址输入</a>
    <header class="page-header">
      <div class="brand-lockup">
        <span class="brand-mark" aria-hidden="true"><span></span><span></span><span></span></span>
        <p class="eyebrow">网址连通检查</p>
      </div>
      <h1 id="page-title">这个网址，能连上吗？</h1>
      <p class="intro">输入网址，看看这次连接是否经过代理，以及电脑能观察到哪些路径信息。</p>
    </header>

    <section id="primary-task" class="primary-task" aria-labelledby="task-title">
      <p class="task-kicker">先检查一个网址</p>
      <form id="diagnostic-form">
        <label id="task-title" for="url">网址或域名</label>
        <p id="url-help" class="input-hint">可以输入完整网址，也可以只输入域名，例如 example.com。</p>
        <div class="input-row">
          <input id="url" name="url" type="text" inputmode="url" autocomplete="url" placeholder="https://example.com" aria-describedby="url-help" required />
          <button type="submit">检查网址</button>
        </div>
        <p id="privacy-note" class="privacy-note">检查在本机运行；不会读取网页正文、Cookie 或账号信息。</p>
      </form>
    </section>

    <p id="progress" class="progress" role="status" aria-live="polite"></p>
    <section id="result" class="result" hidden aria-live="polite">
      <article class="conclusion-card" aria-labelledby="conclusion-title">
        <div class="conclusion-evidence-label">检测摘要的证据程度</div>
        <div id="conclusion-level"></div>
        <h2 id="conclusion-title">检测结论</h2>
        <p id="conclusion-text"></p>
        <section class="traffic-decision" aria-label="代理规则对这次网址的判断">
          <div class="traffic-decision-heading">
            <p>代理规则对这次请求的判断</p>
            <code data-traffic-decision-code></code>
          </div>
          <strong data-traffic-decision-label></strong>
          <p data-traffic-decision-explanation></p>
        </section>
      </article>
      <section id="logical-path-layer" class="result-section" aria-labelledby="path-title">
        <h2 id="path-title">这次网址的代理规则路径</h2>
        <p class="layer-explanation">Clash / Mihomo 是本机代理规则程序。图中展示它对这次请求的判断；网络跳点会在下方单独探测。</p>
        <div id="path-diagram" class="diagram-wrap"></div>
      </section>
      <details class="advanced-result-disclosure">
        <summary>可选探测：查看网络路径上有哪些设备回应</summary>
        <section id="route-trace-layer" aria-label="独立网络路由路径"></section>
      </details>
      <details class="technical-details">
        <summary>查看判断依据和技术数据</summary>
        <section class="evidence-section" aria-labelledby="evidence-title">
          <h2 id="evidence-title">为什么这样判断</h2>
          <ul id="evidence-list" class="evidence-list"></ul>
        </section>
        <dl id="technical-list"></dl>
        <a id="export-json" class="export-link" download="network-path-diagnostic.json">导出 JSON 诊断报告</a>
      </details>
    </section>

    <section class="overview-section" aria-label="本机网络概览">
      <details id="network-overview-disclosure" class="overview-disclosure">
        <summary class="disclosure-summary">
          <span class="summary-title">这台电脑的网络状态</span>
          <span class="summary-support">查看 IP 地址、代理状态和网卡信息</span>
        </summary>
        <div class="overview-toolbar">
          <button type="button" class="secondary-button" data-action="refresh-overview">刷新本机概览</button>
        </div>
        <div id="network-overview"></div>
      </details>
    </section>

    <details class="secondary-tool-disclosure">
      <summary class="disclosure-summary">
        <span class="summary-title">另测网络速度</span>
        <span class="summary-support">单独测量到 Cloudflare 的连接</span>
      </summary>
      <p class="secondary-tool-note">这项测试会产生额外网络流量，与上方网址检查是两次独立请求；只有点击并确认后才会开始。</p>
      <section id="speed-test-host" aria-label="Cloudflare 测速"></section>
    </details>
  </section>
`;

const form = document.querySelector<HTMLFormElement>("#diagnostic-form");
const input = document.querySelector<HTMLInputElement>("#url");
const submit = form?.querySelector<HTMLButtonElement>('button[type="submit"]');
const progress = document.querySelector<HTMLElement>("#progress");
const resultPanel = document.querySelector<HTMLElement>("#result");
const conclusionLevel = document.querySelector<HTMLElement>("#conclusion-level");
const conclusionTitle = document.querySelector<HTMLElement>("#conclusion-title");
const conclusionText = document.querySelector<HTMLElement>("#conclusion-text");
const trafficDecisionLabel = document.querySelector<HTMLElement>("[data-traffic-decision-label]");
const trafficDecisionCode = document.querySelector<HTMLElement>("[data-traffic-decision-code]");
const trafficDecisionExplanation = document.querySelector<HTMLElement>("[data-traffic-decision-explanation]");
const diagramWrap = document.querySelector<HTMLElement>("#path-diagram");
const evidenceList = document.querySelector<HTMLUListElement>("#evidence-list");
const technicalList = document.querySelector<HTMLDListElement>("#technical-list");
const exportLink = document.querySelector<HTMLAnchorElement>("#export-json");
const overviewHost = document.querySelector<HTMLElement>("#network-overview");
const overviewRefresh = document.querySelector<HTMLButtonElement>(
  '[data-action="refresh-overview"]'
);
const routeTraceLayer = document.querySelector<HTMLElement>("#route-trace-layer");
const speedTestHost = document.querySelector<HTMLElement>("#speed-test-host");

let subscription: ReturnType<typeof api.subscribeToRun> | undefined;
let exportUrl: string | undefined;
let pathDiagram: ReturnType<typeof createPathDiagram> | undefined;
let routeTraceController: ReturnType<typeof createRouteTraceController> | undefined;
let submissionGeneration = 0;
let overviewGeneration = 0;
let traceGeneration = 0;
const speedTestController = createSpeedTestController(api);

speedTestHost?.replaceChildren(speedTestController.element);
window.addEventListener("pagehide", () => void speedTestController.dispose(), { once: true });

function showProgress(message: string): void {
  if (progress) progress.textContent = message;
}

function stageMessage(stage: string): string {
  return stages[stage] ?? "正在进行检测";
}

function createOverviewError(): HTMLElement {
  const card = document.createElement("article");
  card.className = "network-overview-card network-overview-error";
  const title = document.createElement("h2");
  title.textContent = "本机网络概览";
  const disclosure = document.createElement("p");
  disclosure.className = "ipify-disclosure";
  disclosure.textContent = "ipify 只会收到这次公网 IP 查询，不会收到正在检测的网址。";
  const message = document.createElement("p");
  message.textContent = "网络概览暂时无法读取";
  const retry = document.createElement("button");
  retry.type = "button";
  retry.dataset.action = "retry-overview";
  retry.textContent = "重试网络概览";
  retry.addEventListener("click", () => void loadOverview());
  card.append(title, disclosure, message, retry);
  return card;
}

async function loadOverview(): Promise<void> {
  if (!overviewHost) return;
  const generation = ++overviewGeneration;
  overviewHost.replaceChildren(createNetworkOverviewLoading());
  try {
    const overview = await api.getNetworkOverview();
    if (generation !== overviewGeneration) return;
    overviewHost.replaceChildren(
      createNetworkOverview(overview, {
        api,
        onRefresh: loadOverview
      })
    );
  } catch {
    if (generation !== overviewGeneration) return;
    overviewHost.replaceChildren(createOverviewError());
  }
}

overviewRefresh?.addEventListener("click", () => void loadOverview());
void loadOverview();

function makeChip(level: Evidence["level"]): HTMLElement {
  const presentation = presentEvidenceLevel(level);
  const chip = document.createElement("span");
  chip.className = `evidence-chip ${presentation.className}`;
  chip.textContent = `${presentation.icon} ${presentation.label}`;
  return chip;
}

function addTechnicalItem(term: string, value: string): void {
  if (!technicalList) return;
  const dt = document.createElement("dt");
  const dd = document.createElement("dd");
  dt.textContent = term;
  dd.textContent = value;
  technicalList.append(dt, dd);
}

function renderEvidence(evidence: Evidence[]): void {
  if (!evidenceList) return;
  evidenceList.replaceChildren();
  for (const item of evidence) {
    const listItem = document.createElement("li");
    listItem.append(makeChip(item.level));
    const text = document.createElement("span");
    text.textContent = item.summary;
    listItem.append(text);
    evidenceList.append(listItem);
  }
}

function renderTechnicalDetails(result: UrlDiagnosticResult): void {
  if (!technicalList || !exportLink) return;
  technicalList.replaceChildren();
  addTechnicalItem("解析到的 IP", result.resolved_ips.join("、") || "无法确认");
  addTechnicalItem(
    "路由",
    result.route
      ? `${result.route.destination}，接口 ${result.route.interface}${result.route.gateway ? `，网关 ${result.route.gateway}` : ""}`
      : "无法确认"
  );
  addTechnicalItem("HTTP 状态", result.http.status === null ? "无法确认" : String(result.http.status));
  addTechnicalItem("HTTP 耗时", formatDuration(result.http.elapsed_ms));
  addTechnicalItem(
    "观察到的连接对端",
    result.http.peer_endpoint
      ? `${result.http.peer_endpoint.ip.includes(":") ? `[${result.http.peer_endpoint.ip}]` : result.http.peer_endpoint.ip}:${result.http.peer_endpoint.port}`
      : "无法确认"
  );
  addTechnicalItem("最终网址", result.http.final_url);
  addTechnicalItem("HTTP 错误", result.http.error_code ?? "无");
  if (exportUrl) URL.revokeObjectURL(exportUrl);
  exportUrl = URL.createObjectURL(resultExport(result));
  exportLink.href = exportUrl;
}

function renderResult(runId: string, result: UrlDiagnosticResult): void {
  if (
    !resultPanel ||
    !conclusionLevel ||
    !conclusionTitle ||
    !conclusionText ||
    !trafficDecisionLabel ||
    !trafficDecisionCode ||
    !trafficDecisionExplanation ||
    !diagramWrap ||
    !routeTraceLayer
  ) return;
  resultPanel.hidden = false;
  conclusionLevel.replaceChildren(makeChip(result.conclusion.level));
  conclusionTitle.textContent = result.conclusion.title;
  conclusionText.textContent = formatConclusion(result);
  const trafficDecision = presentTrafficDecision(result.traffic_decision.kind);
  trafficDecisionLabel.textContent = trafficDecision.label;
  trafficDecisionCode.textContent = `Mihomo · ${trafficDecision.code}`;
  trafficDecisionExplanation.textContent = trafficDecision.explanation;
  pathDiagram?.dispose();
  pathDiagram = createPathDiagram(buildLogicalPathNodes(result));
  diagramWrap.replaceChildren(pathDiagram.element);
  const generation = ++traceGeneration;
  const previous = routeTraceController;
  routeTraceController = createRouteTraceController(api, runId, result);
  routeTraceLayer.replaceChildren(routeTraceController.element);
  if (previous) void previous.dispose();
  if (generation !== traceGeneration) void routeTraceController.dispose();
  renderEvidence(result.evidence.length > 0 ? result.evidence : [result.proxy.evidence]);
  renderTechnicalDetails(result);
}

function handleSnapshot(snapshot: RunSnapshot): void {
  if (snapshot.status === "completed" && snapshot.result) {
    showProgress(stageMessage("completed"));
    renderResult(snapshot.id, snapshot.result);
    return;
  }
  if (snapshot.status === "failed") {
    showProgress(snapshot.error?.message ?? localUnavailable);
  }
}

form?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = input?.value.trim() ?? "";
  if (!url) {
    input?.focus();
    showProgress("请输入要检测的网址。");
    return;
  }
  const generation = ++submissionGeneration;
  const isCurrentGeneration = (): boolean => generation === submissionGeneration;
  subscription?.close();
  subscription = undefined;
  traceGeneration += 1;
  const oldTrace = routeTraceController;
  routeTraceController = undefined;
  if (oldTrace) void oldTrace.dispose();
  routeTraceLayer?.replaceChildren();
  if (!isCurrentGeneration()) return;
  resultPanel?.setAttribute("hidden", "");
  if (submit) submit.disabled = true;
  showProgress(stageMessage("validating"));
  try {
    const runId = await api.startDiagnostic(url);
    if (!isCurrentGeneration()) return;
    const nextSubscription = api.subscribeToRun(
      runId,
      (stage) => {
        if (!isCurrentGeneration()) return;
        showProgress(stageMessage(stage.stage));
      },
      () => {
        if (!isCurrentGeneration()) return;
        showProgress(localUnavailable);
        if (submit) submit.disabled = false;
      },
      (snapshot) => {
        if (!isCurrentGeneration()) return;
        handleSnapshot(snapshot);
        if (submit) submit.disabled = false;
      }
    );
    if (!isCurrentGeneration()) {
      nextSubscription.close();
      return;
    }
    subscription = nextSubscription;
  } catch {
    if (!isCurrentGeneration()) return;
    showProgress(localUnavailable);
    if (submit) submit.disabled = false;
  }
});

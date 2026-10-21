import type { ApiClient } from "./api";
import type {
  AddressScope,
  EvidenceLevel,
  NetworkInterfaceInfo,
  NetworkOverviewResponse
} from "./types";

export interface NetworkOverviewOptions {
  api?: Pick<ApiClient, "setMihomoController" | "resetMihomoController">;
  onRefresh?: () => Promise<void>;
}

const scopeLabels: Record<AddressScope, string> = {
  private: "局域网地址",
  global: "公网地址",
  link_local: "链路本地地址",
  loopback: "本机内部地址"
};

function modeLabel(mode: string | null): string {
  if (mode === "rule") return "规则模式";
  if (mode === "global") return "全局模式";
  if (mode === "direct") return "直连模式";
  return "无法确认";
}

function tunLabel(enabled: boolean | null): string {
  if (enabled === true) return "已开启";
  if (enabled === false) return "未开启";
  return "无法确认";
}

function decisionLabel(kind: string): string {
  if (kind === "direct") return "直连（规则未选择代理）";
  if (kind === "proxy") return "使用代理";
  if (kind === "reject") return "规则拦截";
  return "暂时无法确认";
}

function evidenceLabel(level: EvidenceLevel): string {
  if (level === "confirmed") return "已确认";
  if (level === "inferred") return "根据配置推断";
  return "未知";
}

function interfaceRank(info: NetworkInterfaceInfo, defaultInterface: string | null): number {
  const isDefault = info.is_default || info.name === defaultInterface;
  if (isDefault && info.kind !== "tun" && info.kind !== "loopback") return 0;
  if (info.kind === "tun") return 1;
  if (info.kind === "loopback") return 3;
  return 2;
}

function orderedInterfaces(response: NetworkOverviewResponse): NetworkInterfaceInfo[] {
  return response.local.interfaces
    .map((info, index) => ({ info, index }))
    .sort((left, right) => {
      const rank =
        interfaceRank(left.info, response.local.default_interface) -
        interfaceRank(right.info, response.local.default_interface);
      return rank === 0 ? left.index - right.index : rank;
    })
    .map(({ info }) => info);
}

function element<K extends keyof HTMLElementTagNameMap>(name: K, className?: string) {
  const result = document.createElement(name);
  if (className) result.className = className;
  return result;
}

function appendField(root: HTMLElement, term: string, value: string, field?: string): void {
  const row = element("div", "overview-field");
  const dt = element("dt");
  const dd = element("dd");
  dt.textContent = term;
  dd.textContent = value;
  if (field) dd.dataset.overviewField = field;
  row.append(dt, dd);
  root.append(row);
}

function createManualController(
  options: NetworkOverviewOptions
): HTMLDetailsElement {
  const details = element("details", "manual-controller");
  const summary = element("summary");
  summary.textContent = "高级设置：手动连接本机 Clash";
  const explanation = element("p", "controller-advisory");
  explanation.textContent = "通常不需要修改。仅在自动识别失败、且你知道本机 Clash 控制地址时使用。";
  const form = element("form", "manual-controller-form");
  const controllerLabel = element("label");
  controllerLabel.htmlFor = "manual-controller-url";
  controllerLabel.textContent = "Controller 地址";
  const controller = element("input");
  controller.id = "manual-controller-url";
  controller.name = "controller-url";
  controller.type = "text";
  controller.inputMode = "url";
  controller.autocomplete = "off";
  controller.required = true;
  controller.placeholder = "http://127.0.0.1:9090";
  const advisory = element("p", "controller-advisory");
  advisory.textContent = "仅支持本机回环地址；最终由本地检测程序校验。";
  const secretLabel = element("label");
  secretLabel.htmlFor = "manual-controller-secret";
  secretLabel.textContent = "密码（可选）";
  const secret = element("input");
  secret.id = "manual-controller-secret";
  secret.name = "controller-secret";
  secret.type = "password";
  secret.autocomplete = "off";
  const controls = element("div", "manual-controller-actions");
  const submit = element("button");
  submit.type = "submit";
  submit.textContent = "连接";
  const reset = element("button");
  reset.type = "button";
  reset.dataset.action = "reset-controller";
  reset.textContent = "恢复自动发现";
  const status = element("p", "controller-status");
  status.setAttribute("aria-live", "polite");
  controls.append(submit, reset);
  form.append(
    controllerLabel,
    controller,
    advisory,
    secretLabel,
    secret,
    controls,
    status
  );
  details.append(summary, explanation, form);

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const api = options.api;
    if (!api) return;
    const url = controller.value.trim();
    const password = secret.value;
    submit.disabled = true;
    void (async () => {
      let connected = false;
      try {
        await api.setMihomoController(url, password);
        status.textContent = "已连接，正在刷新网络概览";
        connected = true;
      } catch {
        status.textContent = "连接失败，请检查地址或密码";
      } finally {
        secret.value = "";
        submit.disabled = false;
      }
      if (connected) {
        try {
          await options.onRefresh?.();
        } catch {
          status.textContent = "已连接，但网络概览刷新失败";
        }
      }
    })();
  });

  reset.addEventListener("click", () => {
    const api = options.api;
    if (!api) return;
    reset.disabled = true;
    void (async () => {
      let resetComplete = false;
      try {
        await api.resetMihomoController();
        status.textContent = "已恢复自动发现，正在刷新网络概览";
        resetComplete = true;
      } catch {
        status.textContent = "恢复自动发现失败，请稍后重试";
      } finally {
        secret.value = "";
        reset.disabled = false;
      }
      if (resetComplete) {
        try {
          await options.onRefresh?.();
        } catch {
          status.textContent = "已恢复自动发现，但网络概览刷新失败";
        }
      }
    })();
  });

  return details;
}

export function createNetworkOverviewLoading(): HTMLElement {
  const loading = element("article", "network-overview-card network-overview-loading");
  loading.setAttribute("aria-busy", "true");
  const title = element("h2");
  title.textContent = "本机网络概览";
  const disclosure = element("p", "ipify-disclosure");
  disclosure.textContent = "ipify 只会收到这次公网 IP 查询，不会收到正在检查的网址。它是独立的公网 IP 查询服务。";
  const progress = element("p");
  progress.textContent = "正在读取本机网卡并查询公网出口";
  loading.append(title, disclosure, progress);
  return loading;
}

export function createNetworkOverview(
  response: NetworkOverviewResponse,
  options: NetworkOverviewOptions = {}
): HTMLElement {
  const card = element("article", "network-overview-card");
  const title = element("h2");
  title.textContent = "本机网络概览";
  const disclosure = element("p", "ipify-disclosure");
  disclosure.textContent = "ipify 只会收到这次公网 IP 查询，不会收到正在检查的网址。它是独立的公网 IP 查询服务。";
  const interfaces = element("section", "network-interfaces");
  const interfacesTitle = element("h3");
  interfacesTitle.textContent = "本机网卡地址";
  const interfacesExplanation = element("p", "overview-explanation");
  interfacesExplanation.textContent = "这些地址属于电脑的实体或虚拟网卡；公网出口地址会在下方单独显示。";
  const list = element("ul", "network-interface-list");

  for (const info of orderedInterfaces(response)) {
    const item = element("li", `network-interface network-interface-${info.kind}`);
    item.dataset.interfaceName = info.name;
    const heading = element("h4");
    const isDefault = info.is_default || info.name === response.local.default_interface;
    const interfaceType = info.kind === "tun" ? "虚拟网卡（TUN）" : "网卡";
    heading.textContent = `${info.display_name}（${info.name}） · ${interfaceType}${isDefault ? " · 系统默认网卡" : ""}`;
    const addresses = element("ul", "network-address-list");
    for (const address of info.addresses) {
      const addressItem = element("li");
      const value = element("span", "network-address-value");
      value.textContent = address.ip;
      const scope = element("span", "network-address-scope");
      scope.textContent = scopeLabels[address.scope];
      addressItem.append(value, scope);
      addresses.append(addressItem);
    }
    item.append(heading, addresses);
    list.append(item);
  }
  interfaces.append(interfacesTitle, list);
  interfaces.insertBefore(interfacesExplanation, list);

  const details = element("dl", "network-overview-fields");
  appendField(
    details,
    "Clash / Mihomo 代理程序",
    response.local.mihomo.available
      ? "已连接"
      : "当前未连接",
    "mihomo-status"
  );
  appendField(
    details,
    "代理运行模式",
    response.local.mihomo.available ? modeLabel(response.local.mihomo.mode) : "无法确认",
    "mihomo-mode"
  );
  appendField(
    details,
    "TUN（虚拟网卡接管）",
    response.local.mihomo.available ? tunLabel(response.local.mihomo.tun_enabled) : "无法确认",
    "tun-status"
  );
  appendField(
    details,
    "系统代理设置",
    "由本页的网址检查单独判断；它与 TUN 是两种不同入口。",
    "system-proxy"
  );
  if (response.egress) {
    appendField(details, "公网出口 IP（ipify 看到的地址）", response.egress.ip, "egress-ip");
    const decision = response.egress.traffic_decision;
    appendField(
      details,
      "出口查询的代理规则",
      `${decision.kind.toUpperCase()}（${decisionLabel(decision.kind)}） · ${evidenceLabel(decision.evidence[0]?.level ?? "unknown")}`,
      "egress-decision"
    );
  } else {
    appendField(details, "公网出口 IP", "公网出口暂时无法确认", "egress-unavailable");
  }

  const proxyExplanation = element("p", "overview-explanation proxy-separation-note");
  proxyExplanation.textContent = "系统代理是电脑或应用设置的代理地址；TUN 是虚拟网卡接管方式。开启其中一项，不代表另一项也开启。";
  const egressExplanation = element("p", "overview-explanation");
  egressExplanation.textContent = "公网出口 IP 是独立查询结果；它不等于上方网卡的局域网地址，也不一定等于某个网站的入口 IP。";
  card.append(title, disclosure, interfaces, proxyExplanation, details, egressExplanation);
  if (
    !response.local.mihomo.available ||
    response.local.mihomo.controller === "manual_loopback"
  ) {
    card.append(createManualController(options));
  }
  return card;
}

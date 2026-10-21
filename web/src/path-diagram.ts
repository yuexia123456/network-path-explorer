import type { EvidenceLevel, UrlDiagnosticResult } from "./types";

export type PathNodeKind =
  | "device"
  | "local_proxy"
  | "interface"
  | "destination"
  | "remote_relay"
  | "proxy_unknown"
  | "system_proxy"
  | "clash"
  | "traffic_rule"
  | "policy_group"
  | "proxy_node"
  | "blocked"
  | "unknown"
  | "website";

export interface PathNode {
  kind: PathNodeKind;
  label: string;
  detail: string;
  level: EvidenceLevel;
  icon: string;
  evidenceText?: string;
  edgeLabel?: string;
}

export interface PathDiagram {
  element: SVGSVGElement;
  dispose(): void;
}

const SVG_NS = "http://www.w3.org/2000/svg";
let diagramSequence = 0;

function evidenceText(level: EvidenceLevel): string {
  if (level === "confirmed") return "已确认";
  if (level === "inferred") return "根据配置推断";
  return "未知";
}

function truncateLabel(label: string): string {
  const characters = Array.from(label);
  return characters.length > 24 ? `${characters.slice(0, 24).join("")}…` : label;
}

function isLoopbackAddress(ip: string): boolean {
  return ip === "::1" || /^127(?:\.\d{1,3}){3}$/.test(ip);
}

function isConfiguredProxy(result: UrlDiagnosticResult): boolean {
  return result.proxy.kind !== "direct" && result.proxy.kind !== "unknown";
}

function proxySocketIp(result: UrlDiagnosticResult): string | null {
  const peer = result.http.peer_endpoint;
  const routeIp = result.route?.destination ?? null;
  if (peer && result.proxy.port !== peer.port) return null;
  if (peer && routeIp && peer.ip !== routeIp) return null;
  return peer?.ip ?? routeIp;
}

function destinationLabel(url: string): string {
  try {
    return new URL(url).hostname || url;
  } catch {
    return url;
  }
}

function endpointDetail(host: string, port: number | null): string {
  const displayHost = host.includes(":") ? `[${host}]` : host;
  return port === null ? displayHost : `${displayHost}:${port}`;
}

function effectivePort(url: string): number | null {
  try {
    const parsed = new URL(url);
    if (parsed.port) return Number(parsed.port);
    if (parsed.protocol === "http:") return 80;
    if (parsed.protocol === "https:") return 443;
  } catch {
    return null;
  }
  return null;
}

function destinationLevel(result: UrlDiagnosticResult): EvidenceLevel {
  const peer = result.http.peer_endpoint;
  const port = effectivePort(result.normalized_url);
  if (
    result.proxy.kind === "direct" &&
    result.route &&
    peer &&
    port !== null &&
    peer.ip === result.route.destination &&
    peer.port === port
  ) {
    return "confirmed";
  }
  return "unknown";
}

export function buildPathNodes(result: UrlDiagnosticResult): PathNode[] {
  const nodes: PathNode[] = [
    {
      kind: "device",
      label: "这台电脑",
      detail: "请求从这里开始",
      level: "confirmed",
      icon: "⌘"
    }
  ];
  const proxyHost = result.proxy.host;
  const configuredProxy = isConfiguredProxy(result) && proxyHost !== null;
  const proxyIp = configuredProxy ? proxySocketIp(result) : null;
  const proxyLocality = proxyIp === null ? "unknown" : isLoopbackAddress(proxyIp) ? "local" : "remote";

  if (configuredProxy && proxyLocality === "local") {
    const port = result.proxy.port === null ? "" : `:${result.proxy.port}`;
    nodes.push({
      kind: "local_proxy",
      label: "本机代理",
      detail: `${proxyHost}${port}`,
      level: result.proxy.evidence.level,
      icon: "↪"
    });
  }

  if (result.route) {
    nodes.push({
      kind: "interface",
      label: result.route.interface,
      detail: "已观察到的网络接口",
      level: "confirmed",
      icon: "⌁"
    });
  } else {
    nodes.push({
      kind: "interface",
      label: "无法确认",
      detail: "当前没有观察到网络接口路径",
      level: "unknown",
      icon: "?"
    });
  }

  if (configuredProxy && proxyLocality === "remote") {
    nodes.push({
      kind: "remote_relay",
      label: "配置的远程代理",
      detail: endpointDetail(proxyHost, result.proxy.port),
      level: result.proxy.evidence.level,
      icon: "↗"
    });
  } else if (configuredProxy && proxyLocality === "unknown") {
    nodes.push({
      kind: "proxy_unknown",
      label: "配置的代理（位置未知）",
      detail: endpointDetail(proxyHost, result.proxy.port),
      level: "unknown",
      icon: "?"
    });
  }

  nodes.push({
    kind: "destination",
    label: "网站入口",
    detail: destinationLabel(result.normalized_url),
    level: destinationLevel(result),
    icon: "◎"
  });
  return nodes;
}

function logicalNode(
  kind: PathNodeKind,
  label: string,
  detail: string,
  level: EvidenceLevel,
  icon: string,
  edgeLabel?: string
): PathNode {
  return {
    kind,
    label,
    detail,
    level,
    icon,
    evidenceText: evidenceText(level),
    ...(edgeLabel ? { edgeLabel } : {})
  };
}

export function buildLogicalPathNodes(result: UrlDiagnosticResult): PathNode[] {
  const decision = result.traffic_decision;
  const nodes: PathNode[] = [
    logicalNode("device", "这台电脑", "请求从这里开始", "confirmed", "⌘")
  ];

  if (isConfiguredProxy(result) && result.proxy.host) {
    nodes.push(
      logicalNode(
        "system_proxy",
        "系统代理",
        endpointDetail(result.proxy.host, result.proxy.port),
        result.proxy.evidence.level,
        "↪"
      )
    );
  }

  const appendDecisionNode = (node: (typeof decision.chain)[number]): void => {
    const kind: PathNodeKind =
      node.kind === "tun"
        ? "clash"
        : node.kind === "traffic_rule"
          ? "traffic_rule"
          : node.kind === "policy_group"
            ? "policy_group"
            : node.kind === "blocked"
              ? "blocked"
              : node.kind === "unknown"
                ? "unknown"
                : "proxy_node";
    const label = node.kind === "tun" ? "本机 Clash" : node.name;
    const detailParts = [
      node.kind === "tun" ? node.name : node.node_type,
      node.endpoint ? endpointDetail(node.endpoint.ip, node.endpoint.port) : null,
      node.delay_ms === null ? null : `${node.delay_ms} ms`
    ].filter((value): value is string => Boolean(value));
    nodes.push(
      logicalNode(
        kind,
        label,
        detailParts.join(" · ") || node.name,
        node.level,
        node.kind === "tun" ? "◇" : node.kind === "blocked" ? "×" : "◆"
      )
    );
  };

  let chainIndex = 0;
  while (decision.chain[chainIndex]?.kind === "tun") {
    appendDecisionNode(decision.chain[chainIndex]!);
    chainIndex += 1;
  }
  if (decision.rule) {
    nodes.push(
      logicalNode(
        "traffic_rule",
        decision.rule.rule_type,
        [decision.rule.payload, `目标：${decision.rule.target}`].filter(Boolean).join(" · "),
        decision.rule.level,
        "≡"
      )
    );
  }
  decision.chain.slice(chainIndex).forEach(appendDecisionNode);

  if (decision.kind === "reject") {
    const last = nodes.at(-1);
    if (last?.kind === "blocked") {
      last.edgeLabel = "Mihomo：REJECT";
      last.detail = "Mihomo：REJECT";
    } else {
      nodes.push(
        logicalNode("blocked", "已阻止", "Mihomo：REJECT", "confirmed", "×", "Mihomo：REJECT")
      );
    }
    return nodes;
  }

  if (decision.kind === "unknown") {
    nodes.push(
      logicalNode(
        "unknown",
        "最终出口未知",
        "未能确认最终出口",
        "unknown",
        "?",
        "未能确认最终出口"
      )
    );
    return nodes;
  }

  nodes.push(
    logicalNode(
      "website",
      "网站入口",
      destinationLabel(result.normalized_url),
      "confirmed",
      "◎",
      decision.kind === "proxy" ? "Mihomo：PROXY" : "Mihomo：DIRECT"
    )
  );
  return nodes;
}

function svgElement<K extends keyof SVGElementTagNameMap>(name: K): SVGElementTagNameMap[K] {
  return document.createElementNS(SVG_NS, name);
}

function setAttributes(element: Element, attributes: Record<string, string>): void {
  for (const [name, value] of Object.entries(attributes)) {
    element.setAttribute(name, value);
  }
}

export function createPathDiagram(nodes: PathNode[]): PathDiagram {
  const svg = svgElement("svg");
  const markerId = `path-arrow-${++diagramSequence}`;
  svg.classList.add("path-diagram");
  svg.setAttribute("role", "img");
  svg.setAttribute(
    "aria-label",
    `请求路径：${nodes.map((node) => truncateLabel(node.label)).join("，")}`
  );

  const redraw = (vertical: boolean): void => {
    svg.replaceChildren();
    const width = vertical ? 320 : Math.max(760, nodes.length * 170);
    const height = vertical ? Math.max(180, nodes.length * 142) : 220;
    svg.style.minWidth = vertical ? "" : `${width}px`;
    setAttributes(svg, {
      viewBox: `0 0 ${width} ${height}`,
      preserveAspectRatio: "xMidYMid meet"
    });

    const marker = svgElement("marker");
    setAttributes(marker, {
      id: markerId,
      viewBox: "0 0 10 10",
      refX: "8",
      refY: "5",
      markerWidth: "6",
      markerHeight: "6",
      orient: "auto-start-reverse"
    });
    const arrow = svgElement("path");
    arrow.setAttribute("d", "M 0 0 L 10 5 L 0 10 z");
    marker.append(arrow);
    const defs = svgElement("defs");
    defs.append(marker);
    svg.append(defs);

    const positions = nodes.map((_, index) =>
      vertical
        ? { x: width / 2, y: 66 + index * 136 }
        : { x: 82 + index * ((width - 164) / Math.max(nodes.length - 1, 1)), y: 104 }
    );

    for (let index = 0; index < positions.length - 1; index += 1) {
      const start = positions[index];
      const end = positions[index + 1];
      if (!start || !end) continue;
      const line = svgElement("line");
      setAttributes(line, {
        x1: String(start.x),
        y1: String(start.y + (vertical ? 38 : 0)),
        x2: String(end.x),
        y2: String(end.y - (vertical ? 38 : 0)),
        class: nodes[index + 1]?.level === "unknown" ? "path-link unknown-link" : "path-link",
        "marker-end": `url(#${markerId})`
      });
      svg.append(line);
      const edgeLabel = nodes[index + 1]?.edgeLabel;
      if (edgeLabel) {
        const text = svgElement("text");
        setAttributes(text, {
          x: String((start.x + end.x) / 2),
          y: String((start.y + end.y) / 2 - (vertical ? 8 : 12)),
          "text-anchor": "middle",
          class: "path-edge-label"
        });
        text.textContent = edgeLabel;
        svg.append(text);
      }
    }

    nodes.forEach((node, index) => {
      const position = positions[index];
      if (!position) return;
      const group = svgElement("g");
      group.classList.add("path-node", node.level);
      setAttributes(group, {
        transform: `translate(${position.x} ${position.y})`,
        tabindex: "0",
        role: "listitem"
      });
      const title = svgElement("title");
      title.textContent = node.label;
      title.setAttribute("data-export", "exclude");
      const circle = svgElement("circle");
      setAttributes(circle, { r: "38", class: "path-node-circle" });
      const icon = svgElement("text");
      setAttributes(icon, { y: "7", "text-anchor": "middle", class: "path-node-icon" });
      icon.textContent = node.icon;
      const label = svgElement("text");
      setAttributes(label, {
        y: vertical ? "58" : "62",
        "text-anchor": "middle",
        class: "path-node-label"
      });
      label.textContent = truncateLabel(node.label);
      const detail = svgElement("text");
      setAttributes(detail, {
        y: vertical ? "80" : "84",
        "text-anchor": "middle",
        class: "path-node-detail"
      });
      detail.textContent = node.detail;
      const evidence = svgElement("text");
      setAttributes(evidence, {
        y: vertical ? "102" : "106",
        "text-anchor": "middle",
        class: "path-node-evidence"
      });
      evidence.textContent = node.evidenceText ?? evidenceText(node.level);
      const showFocusDetail = (): void => {
        svg.querySelector(".path-node-focus-detail")?.remove();
        if (truncateLabel(node.label) === node.label) return;
        const focusDetail = svgElement("text");
        setAttributes(focusDetail, {
          x: String(width / 2),
          y: String(height - 10),
          "text-anchor": "middle",
          class: "path-node-focus-detail",
          "data-export": "exclude",
          role: "status"
        });
        focusDetail.textContent = node.label;
        svg.append(focusDetail);
      };
      const hideFocusDetail = (): void => {
        svg.querySelector(".path-node-focus-detail")?.remove();
      };
      group.addEventListener("focus", showFocusDetail);
      group.addEventListener("blur", hideFocusDetail);
      group.append(title, circle, icon, label, detail, evidence);
      svg.append(group);
    });
  };

  const query = window.matchMedia("(max-width: 719px)");
  redraw(query.matches);
  const onChange = (event: MediaQueryListEvent): void => redraw(event.matches);
  query.addEventListener("change", onChange);
  return {
    element: svg,
    dispose: () => query.removeEventListener("change", onChange)
  };
}

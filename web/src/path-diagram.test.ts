import { afterEach, expect, test, vi } from "vitest";
import { buildLogicalPathNodes, buildPathNodes, createPathDiagram } from "./path-diagram";
import {
  directResult,
  fourNodeProxyDecision,
  localProxyResult,
  observedDirectResult,
  remoteHttpProxyResult,
  remoteSocksProxyResult
} from "./test-fixtures";

test("renders every confirmed Mihomo node in logical order", () => {
  const nodes = buildLogicalPathNodes({
    ...directResult,
    traffic_decision: fourNodeProxyDecision
  });

  expect(nodes.map((node) => node.label)).toEqual([
    "这台电脑",
    "本机 Clash",
    "DOMAIN-SUFFIX",
    "全球代理",
    "香港-01",
    "美国-落地",
    "网站入口"
  ]);
  expect(nodes.slice(1, -1).map((node) => node.evidenceText)).toEqual([
    "已确认",
    "已确认",
    "已确认",
    "已确认",
    "已确认"
  ]);
});

test("keeps a configured system proxy and fifth chain node without folding", () => {
  const fifthNode = {
    ...fourNodeProxyDecision.chain[3]!,
    name: "新加坡-最终节点",
    level: "inferred" as const
  };
  const nodes = buildLogicalPathNodes({
    ...localProxyResult,
    traffic_decision: {
      ...fourNodeProxyDecision,
      chain: [...fourNodeProxyDecision.chain, fifthNode]
    }
  });

  expect(nodes.map((node) => node.label)).toEqual([
    "这台电脑",
    "系统代理",
    "本机 Clash",
    "DOMAIN-SUFFIX",
    "全球代理",
    "香港-01",
    "美国-落地",
    "新加坡-最终节点",
    "网站入口"
  ]);
  expect(nodes.find((node) => node.label === "新加坡-最终节点")?.evidenceText).toBe(
    "根据配置推断"
  );
  expect(nodes.some((node) => node.label.includes("其余"))).toBe(false);
});

test.each([
  ["direct", "Mihomo：DIRECT", "website"],
  ["proxy", "Mihomo：PROXY", "website"],
  ["reject", "Mihomo：REJECT", "blocked"],
  ["unknown", "未能确认最终出口", "unknown"]
] as const)("uses exact %s logical terminal wording", (kind, terminalText, terminalKind) => {
  const result = {
    ...directResult,
    traffic_decision: {
      ...directResult.traffic_decision,
      kind,
      chain:
        kind === "reject"
          ? [{ ...fourNodeProxyDecision.chain[0]!, kind: "blocked" as const, name: "已阻止" }]
          : kind === "proxy"
            ? fourNodeProxyDecision.chain
            : []
    }
  };

  const nodes = buildLogicalPathNodes(result);

  expect(nodes.at(-1)).toMatchObject({ kind: terminalKind });
  expect(nodes.some((node) => node.edgeLabel === terminalText || node.detail === terminalText)).toBe(
    true
  );
  if (kind === "reject") {
    expect(nodes.some((node) => node.kind === "website")).toBe(false);
  }
});

test("unknown keeps known configuration nodes and ends with an unknown edge", () => {
  const nodes = buildLogicalPathNodes({
    ...directResult,
    traffic_decision: {
      ...fourNodeProxyDecision,
      kind: "unknown",
      chain: fourNodeProxyDecision.chain.slice(0, 2)
    }
  });

  expect(nodes.map((node) => node.label)).toEqual([
    "这台电脑",
    "本机 Clash",
    "DOMAIN-SUFFIX",
    "全球代理",
    "最终出口未知"
  ]);
  expect(nodes.at(-1)).toMatchObject({
    level: "unknown",
    edgeLabel: "未能确认最终出口",
    evidenceText: "未知"
  });
});

test("uses unique marker IDs for multiple logical diagrams", () => {
  vi.stubGlobal("matchMedia", () => ({
    matches: false,
    addEventListener: () => undefined,
    removeEventListener: () => undefined
  }));
  const nodes = buildLogicalPathNodes({
    ...directResult,
    traffic_decision: fourNodeProxyDecision
  });
  const first = createPathDiagram(nodes);
  const second = createPathDiagram(nodes);

  const firstMarker = first.element.querySelector("marker")?.id;
  const secondMarker = second.element.querySelector("marker")?.id;

  expect(firstMarker).toBeTruthy();
  expect(secondMarker).toBeTruthy();
  expect(firstMarker).not.toBe(secondMarker);
  expect(first.element.querySelector(".path-link")?.getAttribute("marker-end")).toBe(
    `url(#${firstMarker})`
  );
  expect(second.element.querySelector(".path-link")?.getAttribute("marker-end")).toBe(
    `url(#${secondMarker})`
  );
  first.dispose();
  second.dispose();
});

test("truncates long labels visually while keeping live accessible focus detail", () => {
  vi.stubGlobal("matchMedia", () => ({
    matches: false,
    addEventListener: () => undefined,
    removeEventListener: () => undefined
  }));
  const fullLabel = "这是一个超过二十四个显示字符而且必须完整保留的代理节点名称";
  const result = {
    ...directResult,
    traffic_decision: {
      ...fourNodeProxyDecision,
      chain: [
        ...fourNodeProxyDecision.chain.slice(0, 2),
        { ...fourNodeProxyDecision.chain[2]!, name: fullLabel }
      ]
    }
  };
  const diagram = createPathDiagram(buildLogicalPathNodes(result));
  document.body.append(diagram.element);
  const node = Array.from(diagram.element.querySelectorAll<SVGGElement>(".path-node")).find(
    (candidate) => candidate.querySelector("title")?.textContent === fullLabel
  );
  if (!node) throw new Error("long-label node is missing");

  const visible = node.querySelector(".path-node-label")?.textContent ?? "";
  expect(visible).toBe("这是一个超过二十四个显示字符而且必须完整保留的代…");
  expect(visible).not.toContain(fullLabel);
  expect(node.tabIndex).toBe(0);
  expect(node.querySelector("title")?.getAttribute("data-export")).toBe("exclude");
  expect(diagram.element.getAttribute("aria-label")).not.toContain(fullLabel);

  node.dispatchEvent(new FocusEvent("focus"));
  const detail = diagram.element.querySelector<HTMLElement>(".path-node-focus-detail");
  expect(detail?.textContent).toBe(fullLabel);
  expect(detail?.getAttribute("data-export")).toBe("exclude");

  node.dispatchEvent(new FocusEvent("blur"));
  expect(diagram.element.querySelector(".path-node-focus-detail")).toBeNull();
  diagram.dispose();
});

test("shows local proxy before target and never invents a remote relay", () => {
  const nodes = buildPathNodes(localProxyResult);
  expect(nodes.map((node) => node.kind)).toEqual([
    "device",
    "local_proxy",
    "interface",
    "destination"
  ]);
  expect(nodes.some((node) => node.kind === "remote_relay")).toBe(false);
  expect(nodes.find((node) => node.kind === "destination")?.level).toBe("unknown");
});

test.each([
  [
    "HTTP selected route",
    {
      ...remoteHttpProxyResult,
      http: { ...remoteHttpProxyResult.http, peer_endpoint: null }
    },
    "proxy.example:3128"
  ],
  ["SOCKS observed peer", { ...remoteSocksProxyResult, route: null }, "socks.example:1080"]
])("shows a configured remote %s proxy and keeps its onward path unknown", (_, result, endpoint) => {
  const nodes = buildPathNodes(result);
  const relay = nodes.find((node) => node.kind === "remote_relay");
  const destination = nodes.find((node) => node.kind === "destination");

  expect(nodes.map((node) => node.kind)).toEqual([
    "device",
    "interface",
    "remote_relay",
    "destination"
  ]);
  expect(relay).toMatchObject({
    label: "配置的远程代理",
    detail: endpoint,
    level: "confirmed"
  });
  expect(destination?.level).toBe("unknown");
});

test.each([
  ["selected IPv4", "127.0.0.1", false],
  ["observed IPv6", "::1", true]
])("uses the %s loopback socket to classify a proxy hostname as local", (_, ip, peerOnly) => {
  const result = {
    ...remoteHttpProxyResult,
    proxy: { ...remoteHttpProxyResult.proxy, host: "proxy.local" },
    route: peerOnly ? null : { ...remoteHttpProxyResult.route!, destination: ip },
    http: {
      ...remoteHttpProxyResult.http,
      peer_endpoint: peerOnly ? { ip, port: 3128 } : null
    }
  };

  const nodes = buildPathNodes(result);

  expect(nodes.map((node) => node.kind)).toEqual([
    "device",
    "local_proxy",
    "interface",
    "destination"
  ]);
  expect(nodes.some((node) => node.kind === "remote_relay")).toBe(false);
  expect(nodes.find((node) => node.kind === "destination")?.level).toBe("unknown");
});

test("shows configured proxy locality as unknown when no socket evidence exists", () => {
  const result = {
    ...remoteHttpProxyResult,
    proxy: { ...remoteHttpProxyResult.proxy, host: "proxy.local" },
    route: null,
    http: { ...remoteHttpProxyResult.http, peer_endpoint: null }
  };

  const proxyNode = buildPathNodes(result).find((node) => node.kind === "proxy_unknown");

  expect(proxyNode).toMatchObject({
    label: "配置的代理（位置未知）",
    detail: "proxy.local:3128",
    level: "unknown"
  });
});

test("confirms a direct destination only when route and observed peer match", () => {
  expect(
    buildPathNodes(observedDirectResult).find((node) => node.kind === "destination")?.level
  ).toBe("confirmed");

  const mismatched = {
    ...observedDirectResult,
    http: {
      ...observedDirectResult.http,
      peer_endpoint: { ip: "203.0.113.99", port: 443 }
    }
  };
  expect(buildPathNodes(mismatched).find((node) => node.kind === "destination")?.level).toBe(
    "unknown"
  );
  expect(buildPathNodes(directResult).find((node) => node.kind === "destination")?.level).toBe(
    "unknown"
  );
});

test("uses 无法确认 for route evidence that was not observed", () => {
  const interfaceNode = buildPathNodes(directResult).find(
    (node) => node.kind === "interface"
  );
  expect(interfaceNode?.label).toBe("无法确认");
  expect(interfaceNode?.label).not.toBe("直连");
});

afterEach(() => vi.unstubAllGlobals());

test("removes its media-query listener when a diagram is replaced", () => {
  const addEventListener = vi.fn();
  const removeEventListener = vi.fn();
  vi.stubGlobal("matchMedia", () => ({ matches: false, addEventListener, removeEventListener }));

  const diagram = createPathDiagram(buildPathNodes(localProxyResult));
  diagram.dispose();

  expect(addEventListener).toHaveBeenCalledOnce();
  expect(removeEventListener).toHaveBeenCalledOnce();
});

import type {
  AddressScope,
  EgressObservation,
  InterfaceKind,
  LocalNetworkOverview,
  MihomoRuntime,
  NetworkOverviewResponse,
  RouteTraceResult,
  SpeedMetrics,
  SpeedTestResult,
  TrafficDecision,
  UrlDiagnosticResult
} from "./types";

export const fourNodeProxyDecision: TrafficDecision = {
  kind: "proxy",
  mode: "rule",
  tun_enabled: true,
  rule: {
    rule_type: "DOMAIN-SUFFIX",
    payload: "example.com",
    target: "全球代理",
    level: "confirmed"
  },
  chain: [
    {
      kind: "tun",
      name: "Mihomo TUN",
      node_type: null,
      endpoint: null,
      alive: null,
      delay_ms: null,
      level: "confirmed",
      evidence: [{ level: "confirmed", source: "mihomo", summary: "TUN 接管了请求" }]
    },
    {
      kind: "policy_group",
      name: "全球代理",
      node_type: "selector",
      endpoint: null,
      alive: true,
      delay_ms: 42,
      level: "confirmed",
      evidence: [{ level: "confirmed", source: "mihomo", summary: "命中策略组" }]
    },
    {
      kind: "proxy_node",
      name: "香港-01",
      node_type: "trojan",
      endpoint: { ip: "198.51.100.10", port: 443 },
      alive: true,
      delay_ms: 88,
      level: "confirmed",
      evidence: [{ level: "confirmed", source: "mihomo", summary: "观察到实际节点" }]
    },
    {
      kind: "proxy_node",
      name: "美国-落地",
      node_type: "vmess",
      endpoint: { ip: "203.0.113.20", port: 443 },
      alive: true,
      delay_ms: 155,
      level: "confirmed",
      evidence: [{ level: "confirmed", source: "mihomo", summary: "观察到前置节点" }]
    }
  ],
  evidence: [{ level: "confirmed", source: "mihomo", summary: "已确认四级代理链" }]
};

export const localNetworkOverview: LocalNetworkOverview = {
  interfaces: [
    {
      name: "en0",
      display_name: "Wi-Fi",
      kind: "wifi" satisfies InterfaceKind,
      is_default: true,
      addresses: [
        { ip: "192.168.1.8", scope: "private" satisfies AddressScope },
        { ip: "fe80::1", scope: "link_local" satisfies AddressScope }
      ]
    },
    {
      name: "utun4",
      display_name: "Clash TUN",
      kind: "tun" satisfies InterfaceKind,
      is_default: false,
      addresses: [{ ip: "198.18.0.1", scope: "private" satisfies AddressScope }]
    }
  ],
  default_interface: "en0",
  mihomo: {
    available: true,
    mode: "rule",
    tun_enabled: true,
    controller: "auto_unix"
  } satisfies MihomoRuntime
};

export const degradingEgress: EgressObservation = {
  provider: "ipify",
  ip: "203.0.113.7",
  elapsed_ms: 321,
  traffic_decision: {
    kind: "unknown",
    mode: null,
    tun_enabled: null,
    rule: null,
    chain: [],
    evidence: [{ level: "unknown", source: "mihomo", summary: "出口观察未捕获" }]
  },
  evidence: [{ level: "unknown", source: "egress", summary: "出口已返回，但路径无法确认" }]
};

export const degradingOverview: NetworkOverviewResponse = {
  local: localNetworkOverview,
  egress: degradingEgress,
  egress_error: null
};

export const unansweredTraceResult: RouteTraceResult = {
  target: { kind: "reference_destination", ip: "93.184.216.34" },
  hops: [
    {
      index: 1,
      address: "192.168.1.1",
      rtts_ms: [1.2, 1.4],
      level: "confirmed"
    },
    {
      index: 2,
      address: "198.51.100.1",
      rtts_ms: [12.5],
      level: "confirmed"
    },
    {
      index: 3,
      address: null,
      rtts_ms: [],
      level: "unknown"
    },
    {
      index: 4,
      address: "93.184.216.34",
      rtts_ms: [42.1],
      level: "confirmed"
    }
  ],
  reached_target: true,
  elapsed_ms: 178
};

export const completedSpeedMetrics: SpeedMetrics = {
  download_bps: 82_000_000,
  upload_bps: 18_000_000,
  unloaded_latency_ms: 24.5,
  unloaded_jitter_ms: 3.2,
  download_loaded_latency_ms: 61.4,
  upload_loaded_latency_ms: 48.1
};

export const completedSpeedResult: SpeedTestResult = {
  provider: "cloudflare",
  mode: "full",
  metrics: completedSpeedMetrics,
  used_bytes: 171_600_000,
  traffic_decision: fourNodeProxyDecision
};

export const directResult: UrlDiagnosticResult = {
  id: "2f1a9a10-4a31-4c9f-bbc4-e10000000001",
  requested_url: "https://example.com",
  normalized_url: "https://example.com/",
  resolved_ips: ["93.184.216.34"],
  proxy: {
    kind: "direct",
    host: null,
    port: null,
    bypass_reason: null,
    evidence: {
      level: "confirmed",
      source: "system_proxy",
      summary: "系统代理配置表明此网址不使用代理。"
    }
  },
  route: null,
  http: {
    status: 200,
    final_url: "https://example.com/",
    elapsed_ms: 42,
    error_code: null,
    peer_endpoint: null
  },
  traffic_decision: {
    kind: "direct",
    mode: "rule",
    tun_enabled: false,
    rule: null,
    chain: [],
    evidence: [{ level: "confirmed", source: "mihomo", summary: "确认直连" }]
  },
  conclusion: {
    title: "已确认直连",
    summary: "这次请求没有观察到本机代理。",
    level: "confirmed"
  },
  evidence: [
    {
      level: "confirmed",
      source: "system_proxy",
      summary: "系统代理配置表明此网址不使用代理。"
    }
  ]
};

export const localProxyResult: UrlDiagnosticResult = {
  id: "2f1a9a10-4a31-4c9f-bbc4-e10000000002",
  requested_url: "https://example.com",
  normalized_url: "https://example.com/",
  resolved_ips: ["93.184.216.34"],
  proxy: {
    kind: "socks",
    host: "127.0.0.1",
    port: 7890,
    bypass_reason: null,
    evidence: {
      level: "confirmed",
      source: "system_proxy",
      summary: "系统设置指向本机 SOCKS 代理。"
    }
  },
  route: {
    destination: "127.0.0.1",
    gateway: null,
    interface: "lo0"
  },
  http: {
    status: 200,
    final_url: "https://example.com/",
    elapsed_ms: 86,
    error_code: null,
    peer_endpoint: { ip: "127.0.0.1", port: 7890 }
  },
  traffic_decision: {
    kind: "unknown",
    mode: null,
    tun_enabled: null,
    rule: null,
    chain: [],
    evidence: [{ level: "unknown", source: "mihomo", summary: "代理之后的路径无法确认" }]
  },
  conclusion: {
    title: "已确认本机代理",
    summary: "这次请求先进入本机代理；代理之后的路径当前无法确认。",
    level: "confirmed"
  },
  evidence: [
    {
      level: "confirmed",
      source: "system_proxy",
      summary: "系统设置指向本机 SOCKS 代理。"
    }
  ]
};

export const observedDirectResult: UrlDiagnosticResult = {
  ...directResult,
  route: {
    destination: "93.184.216.34",
    gateway: "192.0.2.1",
    interface: "en0"
  },
  http: {
    ...directResult.http,
    peer_endpoint: { ip: "93.184.216.34", port: 443 }
  }
};

export const remoteHttpProxyResult: UrlDiagnosticResult = {
  ...directResult,
  proxy: {
    kind: "http",
    host: "proxy.example",
    port: 3128,
    bypass_reason: null,
    evidence: {
      level: "confirmed",
      source: "system_proxy",
      summary: "系统设置指向远程 HTTP 代理。"
    }
  },
  route: {
    destination: "198.51.100.9",
    gateway: "192.0.2.1",
    interface: "en0"
  },
  http: {
    ...directResult.http,
    peer_endpoint: { ip: "198.51.100.9", port: 3128 }
  }
};

export const remoteSocksProxyResult: UrlDiagnosticResult = {
  ...remoteHttpProxyResult,
  proxy: {
    ...remoteHttpProxyResult.proxy,
    kind: "socks",
    host: "socks.example",
    port: 1080,
    evidence: {
      level: "confirmed",
      source: "system_proxy",
      summary: "系统设置指向远程 SOCKS 代理。"
    }
  },
  route: {
    destination: "198.51.100.10",
    gateway: "192.0.2.1",
    interface: "en0"
  },
  http: {
    ...directResult.http,
    peer_endpoint: { ip: "198.51.100.10", port: 1080 }
  }
};

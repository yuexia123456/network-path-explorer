/// <reference types="vite/client" />

export type EvidenceLevel = "confirmed" | "inferred" | "unknown";
export type ProxyKind = "direct" | "http" | "https" | "socks" | "unknown";
export type RunStatus = "running" | "completed" | "failed";
export type TrafficDecisionKind = "direct" | "proxy" | "reject" | "unknown";
export type TrafficNodeKind =
  | "tun"
  | "traffic_rule"
  | "policy_group"
  | "proxy_node"
  | "blocked"
  | "unknown";
export type JobStatus = "running" | "completed" | "failed" | "cancelled";
export type TraceRequestKind = "actual" | "reference";
export type TraceTargetKind =
  | "actual_destination"
  | "actual_proxy"
  | "reference_destination";
export type SpeedMode = "quick" | "full";
export type SpeedSampleKind = "latency" | "download" | "upload";
export type InterfaceKind = "wifi" | "ethernet" | "tun" | "loopback" | "other";
export type AddressScope = "loopback" | "link_local" | "private" | "global";
export type MihomoControllerState = "auto_unix" | "manual_loopback" | "unavailable";

export interface Evidence {
  level: EvidenceLevel;
  source: string;
  summary: string;
}

export interface TrafficRule {
  rule_type: string;
  payload: string | null;
  target: string;
  level: EvidenceLevel;
}

export interface TrafficNode {
  kind: TrafficNodeKind;
  name: string;
  node_type: string | null;
  endpoint: PeerEndpoint | null;
  alive: boolean | null;
  delay_ms: number | null;
  level: EvidenceLevel;
  evidence: Evidence[];
}

export interface TrafficDecision {
  kind: TrafficDecisionKind;
  mode: string | null;
  tun_enabled: boolean | null;
  rule: TrafficRule | null;
  chain: TrafficNode[];
  evidence: Evidence[];
}

export interface MihomoRuntime {
  available: boolean;
  mode: string | null;
  tun_enabled: boolean | null;
  controller: MihomoControllerState | null;
}

export interface InterfaceAddress {
  ip: string;
  scope: AddressScope;
}

export interface NetworkInterfaceInfo {
  name: string;
  display_name: string;
  kind: InterfaceKind;
  is_default: boolean;
  addresses: InterfaceAddress[];
}

export interface LocalNetworkOverview {
  interfaces: NetworkInterfaceInfo[];
  default_interface: string | null;
  mihomo: MihomoRuntime;
}

export interface EgressObservation {
  provider: string;
  ip: string;
  elapsed_ms: number;
  traffic_decision: TrafficDecision;
  evidence: Evidence[];
}

export interface NetworkOverviewResponse {
  local: LocalNetworkOverview;
  egress: EgressObservation | null;
  egress_error: "egress_unavailable" | null;
}

export interface SpeedMeasurementLatency {
  type: "latency";
  numPackets: number;
}

export interface SpeedMeasurementTransfer {
  type: "download" | "upload";
  bytes: number;
  count: number;
}

export type SpeedMeasurement = SpeedMeasurementLatency | SpeedMeasurementTransfer;

export interface SpeedMeasurementPlan {
  mode: SpeedMode;
  deadline_ms: number;
  max_bytes: number;
  include_loaded_latency: boolean;
  measurements: SpeedMeasurement[];
}

export interface SpeedSample {
  kind: SpeedSampleKind;
  bytes: number;
  bps: number | null;
  duration_ms: number;
  latency_ms: number | null;
}

export interface SpeedMetrics {
  download_bps: number;
  upload_bps: number;
  unloaded_latency_ms: number;
  unloaded_jitter_ms: number;
  download_loaded_latency_ms: number | null;
  upload_loaded_latency_ms: number | null;
}

export interface SpeedTestResult {
  provider: string;
  mode: SpeedMode;
  metrics: SpeedMetrics;
  used_bytes: number;
  traffic_decision: TrafficDecision;
}

export interface ProxyDecision {
  kind: ProxyKind;
  host: string | null;
  port: number | null;
  bypass_reason: string | null;
  evidence: Evidence;
}

export interface RouteInfo {
  destination: string;
  gateway: string | null;
  interface: string;
}

export interface PeerEndpoint {
  ip: string;
  port: number;
}

export interface HttpObservation {
  status: number | null;
  final_url: string;
  elapsed_ms: number;
  error_code: string | null;
  peer_endpoint: PeerEndpoint | null;
}

export interface Conclusion {
  title: string;
  summary: string;
  level: EvidenceLevel;
}

export interface UrlDiagnosticResult {
  id: string;
  requested_url: string;
  normalized_url: string;
  resolved_ips: string[];
  proxy: ProxyDecision;
  route: RouteInfo | null;
  http: HttpObservation;
  traffic_decision: TrafficDecision;
  conclusion: Conclusion;
  evidence: Evidence[];
}

export interface RunFailure {
  code: string;
  message: string;
}

export interface RunSnapshot {
  id: string;
  status: RunStatus;
  result: UrlDiagnosticResult | null;
  error: RunFailure | null;
}

export interface TraceTarget {
  kind: TraceTargetKind;
  ip: string;
}

export interface TraceHop {
  index: number;
  address: string | null;
  rtts_ms: number[];
  level: EvidenceLevel;
}

export interface RouteTraceResult {
  target: TraceTarget;
  hops: TraceHop[];
  reached_target: boolean;
  elapsed_ms: number;
}

export interface RouteTraceSnapshot {
  status: JobStatus;
  result: RouteTraceResult | null;
  error: RunFailure | null;
}

export type TraceStage =
  | "selecting_target"
  | "probing"
  | "hop"
  | "completed"
  | "failed"
  | "cancelled";

export interface TraceEvent {
  sequence: number;
  stage: TraceStage;
  hop: TraceHop | null;
}

export interface SpeedTestSnapshot {
  id: string;
  status: JobStatus;
  mode: SpeedMode;
  plan: SpeedMeasurementPlan;
  used_bytes: number;
  sample_count: number;
  result: SpeedTestResult | null;
  error: RunFailure | null;
}

export type SpeedStage = "started" | "samples" | "completed" | "failed" | "cancelled";

export interface SpeedEvent {
  sequence: number;
  stage: SpeedStage;
  used_bytes: number;
  sample_count: number;
}

export interface Capabilities {
  platform: string;
  url_diagnostics: boolean;
  app_diagnostics: boolean;
  route_hops: boolean;
  ip_intelligence: boolean;
  network_overview: boolean;
  egress_ip: boolean;
  mihomo_manual_controller: boolean;
  route_trace: boolean;
  speed_tests: boolean;
  speed_provider: string;
}

export interface StageEvent {
  sequence: number;
  stage: "validating" | "proxy" | "dns" | "route" | "http" | "completed" | "failed";
}

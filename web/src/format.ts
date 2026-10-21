import type { EvidenceLevel, TrafficDecisionKind, UrlDiagnosticResult } from "./types";

export interface EvidencePresentation {
  icon: string;
  label: string;
  className: string;
}

const evidencePresentations: Record<EvidenceLevel, EvidencePresentation> = {
  confirmed: { icon: "✓", label: "已确认", className: "confirmed" },
  inferred: { icon: "~", label: "高概率推断", className: "inferred" },
  unknown: { icon: "?", label: "未知", className: "unknown" }
};

export interface TrafficDecisionPresentation {
  label: string;
  code: "DIRECT" | "PROXY" | "REJECT" | "UNKNOWN";
  explanation: string;
}

const trafficDecisionPresentations: Record<TrafficDecisionKind, TrafficDecisionPresentation> = {
  direct: {
    label: "规则判断为直连",
    code: "DIRECT",
    explanation: "直连不等于国内网络；工具也无法排除看不到的中转。"
  },
  proxy: {
    label: "规则判断经代理连接",
    code: "PROXY",
    explanation: "当前规则选择了代理；代理节点之后的完整路径可能无法确认。"
  },
  reject: {
    label: "请求被规则拦截",
    code: "REJECT",
    explanation: "当前规则拒绝了这次连接。"
  },
  unknown: {
    label: "暂时无法确认连接方式",
    code: "UNKNOWN",
    explanation: "没有足够证据判断这次请求是否经过代理。"
  }
};

export function formatConclusion(result: UrlDiagnosticResult): string {
  return result.conclusion.summary;
}

export function presentEvidenceLevel(level: EvidenceLevel): EvidencePresentation {
  return evidencePresentations[level];
}

export function presentTrafficDecision(kind: TrafficDecisionKind): TrafficDecisionPresentation {
  return trafficDecisionPresentations[kind];
}

export function formatDuration(milliseconds: number): string {
  return `${milliseconds} 毫秒`;
}

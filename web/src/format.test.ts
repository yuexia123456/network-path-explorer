import { expect, test } from "vitest";
import { formatConclusion, presentTrafficDecision } from "./format";
import { directResult } from "./test-fixtures";
import type { TrafficDecisionKind } from "./types";

test("uses the diagnostic conclusion as the one-sentence plain-language result", () => {
  expect(formatConclusion(directResult)).toBe("这次请求没有观察到本机代理。");
});

test.each([
  ["direct", "规则判断为直连", "DIRECT"],
  ["proxy", "规则判断经代理连接", "PROXY"],
  ["reject", "请求被规则拦截", "REJECT"],
  ["unknown", "暂时无法确认连接方式", "UNKNOWN"]
] as const)("explains the %s rule code in plain Chinese", (kind, label, code) => {
  const presentation = presentTrafficDecision(kind as TrafficDecisionKind);

  expect(presentation.label).toBe(label);
  expect(presentation.code).toBe(code);
  expect(presentation.explanation.length).toBeGreaterThan(0);
});

test("does not describe DIRECT as domestic", () => {
  expect(presentTrafficDecision("direct").explanation).toBe(
    "直连不等于国内网络；工具也无法排除看不到的中转。"
  );
});

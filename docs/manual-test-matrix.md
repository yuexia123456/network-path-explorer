# macOS 网址网络诊断人工验证矩阵

## 2026-10-22 新手界面改版验证

- 前端：7 个文件、136 项测试通过；TypeScript 检查与 Vite 生产构建通过。
- Rust：工作区 343 项测试通过，含嵌入资源 8 项；fmt 和 Clippy 检查通过。
- 浏览器夹具：验证 DIRECT / PROXY / REJECT / UNKNOWN 中文说明、折叠交互、键盘焦点和测速流量提示；未启动公网测速。
- 布局：桌面 1440px 和窄屏 390px 检查通过，无横向页面溢出。README 截图使用夹具，不包含真实网络信息。
- Release：本机 arm64 构建通过。SHA-256 `e6523d3dcdcd9cdd33dfe2606ce882c3bbc095577d75563bacd1008b0e30b4a0`。
- 本次浏览器结果使用夹具，不能当作当前网络分流或速度的实测证据。以下 8 月记录保留为历史验证，不代表新版界面的截图。

本矩阵只记录当前机器和当前 Clash Verge/Mihomo 规则下实际可观察到的内容。测试期间不修改系统代理、DNS、VPN、Clash 模式、规则或节点；不记录会话令牌、控制器密钥、完整节点名、内部地址或请求正文。

## 记录约定

- `DIRECT` = Mihomo 没有为该请求选择代理，不等于“国内网络”。
- 系统代理、TUN、本次 Mihomo 决策、逻辑中继链、traceroute hop、公网出口和测速路径必须分栏记录，不能互相替代。
- `无法在当前网络实测` 是有效结果；同一行必须注明自动化 fixture。fixture 只证明界面/协议能正确处理该状态，不冒充当前网络现场证据。
- 路由追踪和测速必须先由用户主动开始；记录完成、取消以及关闭页面后的清理状态。

## 用例矩阵

| 用例 | 操作与观察重点 | 当前网络证据 | 结果/限制 |
|---|---|---|---|
| DIRECT | 使用当前规则下明确不走 Mihomo 代理的网址或本地 loopback 夹具；分别记录系统代理、Mihomo `DIRECT`、HTTP 结果 | 2026-08-24 预检只确认 loopback 页面/capabilities；未取得可复用诊断 UI/session；fixture `directResult` | 无法在当前网络实测；不写成“国内网络” |
| PROXY（4–5 节点） | 使用当前规则下的代理网址；确认逻辑链保持顺序和完整节点数，且不把链当成公网 hop | 未采集 live 链；fixture `fourNodeProxyDecision`（4 节点） | 无法在当前网络实测；不改变规则或节点强行制造 |
| REJECT | 使用当前规则明确拒绝的网址；确认结论是 `REJECT`，不发起后续 HTTP 探测 | 未采集 live 拒绝；fixture/协议测试 `crates/agent/tests/conclusion.rs` | 无法在当前网络实测；不改变规则强行制造 |
| 控制器未知/不可用 | 不改变当前控制器配置，观察未知/不可用状态；若有当前可用控制器，记录只读发现结果而不记地址 | 进程摘要显示有 Clash/Mihomo，但未取得可复用 UI/session；控制器降级 fixture | 无法在当前网络实测；不记录地址或密钥 |
| 实际路由追踪 | 用户主动选择 actual trace；记录目标选择、回答的 hop、取消按钮和结束状态 | 未采集 live trace；Rust traceroute contract tests | 无法在当前网络实测；不能把 hop 当作 Mihomo 逻辑节点 |
| 参考路由追踪 | 用户主动选择 reference trace；确认与 actual trace 分开显示 | 未采集 live trace；fixture `unansweredTraceResult` | 无法在当前网络实测 |
| 未回答 hop | 检查某个 hop 无地址/无 RTT 时显示未知，不补猜地址 | fixture `unansweredTraceResult` | fixture 通过；不把 fixture 当作当前网络 hop |
| 本地/TUN/公网地址标签 | 分别检查本机接口地址、TUN 地址、公网出口 IP 的范围标签；不把它们合并为“真实 IP” | 未采集 live overview；fixture `localNetworkOverview` 与 `degradingOverview` | 无法在当前网络实测；只记录标签和状态 |
| 快速测速 | 用户主动开始 quick；确认快速模式、40 MB 上限、时间上限、Cloudflare disclosure 在流量前出现 | 未采集 live 测速；fixture `completedSpeedResult` 与 speed controller tests | 无法在当前网络实测；不把测速决策当成 URL 决策 |
| 完整测速 | 用户主动开始 full；确认完整模式、200 MB 上限、时间上限和独立测速路径 | 未采集 live 测速；fixture `completedSpeedResult` 与 speed controller tests | 无法在当前网络实测 |
| 取消测速 | 在 quick/full 运行中取消并关闭页面；确认没有留下测速任务 | 未采集 live 取消；`web/src/speed-test.test.ts` 取消/清理测试 | 无法在当前网络实测；fixture 覆盖取消清理 |
| 三个不同的 Clash 决策 | URL 诊断、出口观察、测速分别记录 `traffic_decision.kind`，验证三者可不同 | 未采集 live 三路结果；`degradingOverview`、`completedSpeedResult` 与 URL fixture | 无法在当前网络实测；不互相替代 |
| 离线降级 | 阻断或不提供外部服务，确认概览/出口/测速显示未知或不可用，页面仍可使用本地能力 | 未改变网络做离线阻断；fixture `degradingOverview`、静态资源测试 | 无法在当前网络实测；自动化 smoke 不调用公网 |
| 隐私导出 | 用含本地地址、控制器/规则/节点名称、路径查询片段和摘要的 fixture 导出 JSON；确认只有 v2 allowlist | `web/src/api.test.ts:exports v2 allowlist without private traffic details`，focused GREEN 54/54 | fixture 通过；报告不包含上述私密细节 |

## 自动化与发布证据

| 项目 | 结果 |
|---|---|
| 导出 focused RED | `npm --prefix web test -- --run src/api.test.ts`：基线时 54 个测试中 53 通过、1 失败；失败原因见 Task 13 报告。 |
| 导出 focused GREEN | `npm --prefix web test -- --run src/api.test.ts`：1 个文件、54 通过、0 失败。 |
| 静态资源测试 | `cargo test -p network-path-agent --test static_assets`：8 通过、0 失败。 |
| 前端全量测试 | `npm --prefix web test`：7 个文件、130 通过、0 失败。 |
| Rust workspace 测试/Clippy/fmt | workspace：343 通过、0 失败；Clippy `-D warnings` 通过；fmt check 通过。 |
| 构建契约 | `sh scripts/build-macos.test.sh`：通过。 |
| release smoke | `./scripts/smoke-macos.sh`：退出码 0；随机 loopback 预检通过，capabilities 和嵌入网络/测速标签通过，退出清理由 trap 完成。 |
| 产物 | `dist/macos-arm64/NetworkPathExplorer`；`Mach-O 64-bit executable arm64`；SHA-256 `00ce51a67b0f70221a12de83d05a3558cfb2245117945a5f93f8c6f10c22b9d3`；大小 10910816 bytes。 |

## 当前网络手工运行记录

| 字段 | 记录 |
|---|---|
| 运行日期（Asia/Shanghai） | 2026-08-24 08:46:52 CST |
| macOS 版本/架构 | macOS 15.6.1 / arm64 |
| Clash/Mihomo | 进程摘要显示存在；未读取或记录控制器地址、密钥、节点名称或规则内容 |
| 是否改动网络设置 | 否；只读代理开关摘要，未改系统代理、DNS、VPN、Clash 模式、规则或节点 |
| loopback 预检 | 通过：发布二进制根页面/capabilities 可访问；能力检查通过 |
| 手工矩阵结论 | 现场 UI/session 不可安全复用，因此 live URL 决策、控制器详情、trace、测速和取消均标为“无法在当前网络实测”；每行已引用 fixture/自动化测试 |
| 清理 | 通过：agent 精确终止并确认无残留；未启动实际 traceroute 或测速任务 |

## 限制

当前网络没有提供某个决策、控制器状态、可回答 hop 或测速条件时，本矩阵不会伪造现场结果。住宅、静态、数据中心等线路质量不能仅凭地理位置推断，必须有注明来源的 provider 证据；本版本不把地理位置当作质量结论。

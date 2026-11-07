# xray-frame 深度融合战役总计划（2026-10-26）

> 目标：xray-frame 从「管声明、管测试」变成「管生产装配与运行」；udf 从「机制已用」变成「纪律被强制」。
> 性质：**全量计划**——每波带独立验收硬门，波波全绿才进下一波；无"做一半"出口。

---

## 0. 完成定义（DOD，全部可机械验证，缺一=战役未完）

| # | 判据 | 验证方式 |
|---|---|---|
| D1 | **生产装配主路 = xray-frame**：xray-core 启动构造 inbound/outbound 必经 PluginRegistry | `grep` 生产代码无第二构造路径；`arm_builders` fn 表删除或降级为纯数据源 |
| D2 | **L5 装配门生效**：缺 deps / 成环 / 缺配置段 → 启动前 fail-visible | 专项契约测试（缺依赖→Err、成环→Err、缺段→Err 各一条） |
| D3 | **L2 运行期能力供给**：16 协议 crate 运行面零裸 `tokio::spawn`/`Instant::now`/`tracing!` | clippy 闸 56/56 + 每闸探针抽验 + 迁移点豁免清零 |
| D4 | **L4 夹具真实实例**：16/16 crate 接真实插件实例（现 3/16） | 变异证据（改坏→红）+ 空报告边界钉 |
| D5 | **udf 契约族 13/13**：memgov/compose/testing/ConfigFile 有生产调用点 | 符号级 call-chain 证据（非 grep 计数） |
| D6 | **七面 7/7**：注册表族迁 BoundedRegistry + lint 编排上浮 | 老 API grep 0 命中（迁出探针） |
| D7 | **215 生产裸 spawn 归零**（FxScope/结构化/显式豁免留痕三分类） | 脚本对账：站点数 = 迁移数 + 豁免数 |
| D8 | **187 Instant::now 归零或接 Clock** | 同上 |
| D9 | **性能债清零**：4y9ns / r1693 / q1r4q | alloc 差分 + 真机同窗 A/B 吞吐 |
| D10 | **每波收尾门**：32/32 真机 + interop 12/12 + check/clippy/test/fmt/doc 全绿 + CI 远端绿 | 命令输出 |

## 1. 现状基线（2026-10-26 实测，HEAD 73db56f9）

| 面 | 状态 |
|---|---|
| L1 必选 trait | ✅ 16/16 协议 crate `impl Plugin`（编译期强约束生效） |
| L4 契约夹具 | ✅ 16 份 / ⚠️ 真实实例仅 3（vless/ss/trojan）；条款 6 盲区已修（73db56f9） |
| L3 静态闸 | ⏳ 46/56（L3RestGates 在飞→56）；存量登记 206 处（xray-core/mux/conf/geodata） |
| L2 运行期能力 | ⚠️ 半落：build 期 `ctx.section()` 已用；运行期 spawn/clock/log/pool 未经 PluginContext |
| **L5 装配门** | ❌ **不在生产路径**：`arm_builders/mod.rs:13` 明示 BTreeMap fn 表，不用 PluginRegistry；PluginRegistry/assembly 只活在测试——**两套并存，这是"深度融合"未完成的主因** |
| udf 接地 | 25/56 声明依赖；9/12 契约族有生产调用点（FxScope 11 crate、ShutdownCoordinator 在 Instance::close、logx 三通道、Clock/Scheduler/JSON/池族） |
| 债务面 | 215 裸 spawn（登记 66 属性/约 206 站点，迁移 0——W0 第一片在飞）；187 Instant::now；4y9ns 9.24 MB/MB；r1693 1.06 MB/MB；q1r4q |

## 2. 波次计划（每波 3 路并行；波间依赖见 §4）

### W0（在飞）
- AllocSiteTool：站点级分配归因工具（z02z8）→ 解锁 4y9ns/r1693
- L3RestGates：闸铺满 56/56 + 存量登记（a5r4j/lzzja 完结）
- FxScopeGLM：第一片 tcp/udp hub + arm_builders 非 splice 面（39hko）

### W1 — L5 装配门切换（最大单点，拆 3 片并行）
- **1a PluginRegistry 承接构造表**：34 个构造 fn 包成 Plugin 实例（壳→实体：deps/contract/lifecycle 填真值），注册进 PluginRegistry；xray-core 启动经 `start_order`/lookup 构造。**硬门：双写对照差异率 0**（新旧路径同配置逐字段对照），0 之后才删 fn 表（5 阶段法 phase 5）
- **1b Instance 生命周期接 xray-frame**：lifecycle/assembly 编排 bring_up/shutdown，停机语义等价（`Instance::close` 已接 ShutdownCoordinator，此步把编排权交给框架生命周期）
- **1c L5 门契约测试**：缺 deps→Err / 成环→Err / 缺段→Err 各一条，启动前 fail-visible
- 验收：D1+D2+D10；协议面改动加 Rust↔Go 双向抓包（KCP/补包口径同以前）

### W2 — L2 运行期能力供给（2 片）
- 2a PluginContext 扩运行期能力句柄（spawn/clock/log handle/pool/ids/audit），装配期注入连接处理路径
- 2b 16 协议运行面切换（每批 4 crate）：裸 spawn→ctx.spawn、Instant→ctx.clock、tracing!→ctx.log；**splice/vision 只读不动**（坑约束⑫）
- 验收：D3 + 每批 interop + 迁移点豁免清零

### W3 — udf 契约族（3 片）
- 3a **注册表族迁 BoundedRegistry**（生产 inbound/outbound 线性扫→fail-closed insert+确定序+泄漏断言；热路径→32/32+抓包+A/B）
- 3b compose::combine 接装配面 + testing::{TestStore,ScriptedRuntime} 替换自建脚手架
- 3c ConfigFile\<C\> 接管 xray-conf 分层装载——**影子比对先行**：同一配置两套装载器逐字段相等，才允许切换
- 验收：D5+D6 部分+D10

### W4 — Clock 全量（187 处，2 片按 crate 族分）
- 验收：D8；构造签名变更波及协议族→每批全量互通

### W5 — FxScope 剩余收口（215→0，2-3 片）
- 验收：D7；每片 32/32+interop；splice/vision/transport-tcp 红线只读

### W6 — 性能清偿（依赖 W0 的 AllocSiteTool）
- 6a **4y9ns**：tcp+tls 客户端写路径 9.24 MB/MB（直连族提速候选第一；疑点 xray-tls 包装层逐写 record 缓冲）
- 6b **r1693**：xhttp/h2 服务端发送 1.06 MB/MB（hyper 敏感→抓包验收）
- 6c q1r4q XUDP to_vec 双拷贝
- 验收：D9；直连族测速等早 5-7 黄金窗，CDN 面随时；**吞吐同窗 A/B ≥3 轮不降**

### W7 — 跨仓上浮（外部窗口，阻塞点）
- lint 编排上浮 udf + 新通用件上浮：udf 独立 PR → **三平台 CI 绿** → 主仓 fetch-udf 复测 32/32
- 注意：cargo git 依赖不能指 workspace 子包 → udf 仓根须保持单 crate 门面形态（既往拍板）

## 3. 每波通用验收门（不满足 = 该波 FAIL，打回重做）

```
cargo check --workspace --all-targets        0 error
cargo clippy --workspace --all-targets -D warnings   exit 0
cargo test --workspace --all-targets         0 failed
cargo fmt --all --check / cargo doc --workspace --no-deps   绿
32/32 真机 PASS + interop 12/12 PASS
协议 wire 改动 → 双向抓包逐字段（残留非零帧数=0）
热路径改动 → 同窗 A/B 吞吐 ≥3 轮不降
bd 票逐张核销 + 报告落 reports/audit-2026-10-26/
CI 远端绿后 commit 才算落地（子代理禁 commit，PM 统一提交）
```

## 4. 依赖与顺序

```
W0 ──→ W1（L5 切换，最大风险单点）
W0(z02z8) ──→ W6（性能）
W1 ──→ W2（能力供给挂在装配路径上）
W2 ──→ W4/W5（运行面切换后再清存量）
W3 独立可并行（udf 侧，与 W1/W2 文件面不重叠）
W7 最后（外部窗口）
预估：W1-W6 共 6 波 × 3 路，按实测速率 ≈ 6-10 小时 agent 工时；W7 跨会话等窗口
```

## 5. 红线（任何一波不得触碰）

splice/vision gate（双 revert 史实）· `xray-transport-tcp/register.rs` · `vendor/` · `protos/` · `tests/` 与 `.github/workflows/`（P0-9 已授权例外）· udf 已有功能的重复实现（§3.5.2）· wire 兼容（协议改动必 Go↔Rust 双向互通+抓包）· 池化禁入数据面热路径。

## 6. 状态账本（滚动更新，禁凭记忆）

**bd 计划已建（2026-10-26）**：战役 epic = `99ifi`（P1，DOD 十条全文在票面）。

| 波 | bd 票 | 依赖 | 状态 |
|---|---|---|---|
| W0 | `z02z8`(✅关) / `a5r4j`+`lzzja`(✅关) / `39hko`(第一片✅,伞票续) | — | **完成 @ 0dcfb0cc**（全仓 7710/0 + clippy/fmt/doc 绿；CI 待远端确认） |
| W1 | `di8wy`（1a 承接表/1b 生命周期/1c 门测试） | 99ifi + W0 | **可开派** |
| W2 | `nn8os`（PluginContext 运行期能力） | 99ifi、W1 | open |
| W3 | `xiuvr`（BoundedRegistry/compose+testing/ConfigFile 影子比对） | 99ifi（独立并行） | open |
| W4 | `713x6`（Clock 全量 187 处） | 99ifi、W2 | open |
| W5 | `f17zu`（FxScope 215→0 收尾） | 99ifi、W1、W2 | open |
| W6 | 既有票：`4y9ns`（**靶点需重归因**：工具证伪 TLS poll_write 嫌疑，Btls 加密走 C 侧堆）→`r1693`+`q1r4q` | W0 工具落地 ✅ | open（已解锁） |
| W7 | `n539c`（跨仓上浮） | 99ifi + **udf 仓外部窗口** | open |

其它：`lbavl` 融合度基线（常挂对照）。

| 已核销 | 本会话 24 张（清单见 bd） | bd closed |

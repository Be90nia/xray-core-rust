VERDICT: FAIL（nn8os DOD 未达成——不可关；spawn/clock 两面已闭环，tracing 面 12 crate 未开工 + pool/ids/audit 三柄零生产消费）

# nn8os 干净核账（W2 L2 运行期能力供给 re-audit）2026-10-27

口径：生产面 = `src/**`，mod 锚定的 `#[cfg(test)]` 边界之后剔除（**item 级 `#[cfg(test)]` 不切区**——anytls server.rs:53 即 item 级，首扫误切，二扫修正）；`tests/` 目录剔除。计数 = 迁移/补禁令后 grep 实数。smoltcp 时钟（`smoltcp::time::Instant`）非 std/tokio 面，不在三指标口径内。

## 一、16 crate × 三指标表（生产面，post-fix 实数）

| crate | spawn 未豁免 | spawn 台账 | clock 未豁免 | clock 台账 | tracing 生产未迁 |
|---|---|---|---|---|---|
| anytls | 0 | 0 | 0 | 1（今补登） | **28** |
| blackhole | 0 | 0 | 0 | 0 | 0 |
| dns | 0 | 0 | 0 | 0 | **5** |
| dokodemo | 0 | 0 | 0 | 0 | 0 |
| freedom | 0 | 0 | 0 | 0 | **18** |
| http | 0 | 0 | 0 | 0 | 0 |
| hysteria | 0 | 0 | 0 | 0 | **19** |
| loopback | 0 | 0 | 0 | 0 | **2** |
| socks | 0 | 0 | 0 | 0 | 0 |
| ss | 0 | 0 | 0 | 8 | **9** |
| trojan | 0 | 0 | 0 | 0 | **20** |
| tuic | 0 | 1 | 0 | 4 | **35** |
| tun | 0 | 6 | 0 | 1 | **24** |
| vless | 0 | 2 | 0 | 4 | **14** |
| vmess | 0 | 0 | 0 | 3 | **18** |
| wireguard | 0 | 0 | 0 | 6 | **25** |
| **合计** | **0** | **9** | **0** | **27** | **217** |

spawn 台账 9 处（全带 reason）：vless/inbound/server.rs:138,658（vision splice 红线，坑约束⑫）、tuic/udp.rs:75（热路径豁免 B6 t975）、tun/inbound.rs:398,905,988,1002,1179,1187（存量债 B3 T3.1）。
clock 台账 27 处（全带 reason，三族）：tokio 虚拟钟预算面（713x6 判定 tokio 一律不迁）、SS2022 epoch wire 字段、结构性不可达（纯 codec/驱动无 ctx 注入面）。

## 二、分类表（①已全迁 ②已迁+台账 ③口径外漏网 ④禁令缺失）

| 面 | 分类 | crate |
|---|---|---|
| spawn | ① 全迁+禁令在 | 其余 13 |
| spawn | ② 迁移+台账（每处带 reason） | vless(2)/tuic(1)/tun(6) |
| clock | ② 禁令+台账全 reason | blackhole/dokodemo/http/socks/ss/tuic/tun/vless/vmess/wireguard（10） |
| clock | ④→②（**本轮修复**） | anytls/dns/freedom/hysteria/loopback/trojan：原缺禁令，今补 3 条时钟禁令 + anytls 1 处生产补登 + 10 处测试豁免 |
| tracing | ① 迁移+禁令 | blackhole/dokodemo/http/socks（4） |
| tracing | ③ 口径外漏网 | **12 crate × 217 站点**（在用、无禁令、且**无法台账**） |

关键机制事实：`disallowed_macros` 对 proc-macro 的 `#[allow]` **三形态均无效**（0791bfb8 实测记录）→ tracing 侧"补台账"这条路不存在，**唯一路径 = 逐站迁移 LogFacade，随迁补禁令**。
spawn 禁令形态差异澄清（工作区外探针实证，D:/tmp/banprobe）：`path = "tokio::spawn"` 按 def path 匹配，`tokio::spawn(...)` 与 `tokio::task::spawn(...)` 两种写法**单条即全拦**；10 crate 的 `tokio::task::spawn` 条目是冗余（无害，未动）。

## 三、本轮修复清单（已落盘，工作树 M 14 文件）

1. `crates/xray-proxy-{anytls,dns,freedom,hysteria,loopback,trojan}/clippy.toml`：各补 3 条时钟禁令（与 tuic 等 10 crate 逐字同款）（+3 行 × 6）
2. `xray-proxy-anytls/src/server.rs`：`handle_conn` fn 级台账（生产面 `tokio::time::Instant::now()` 握手 deadline，理由=tokio 虚拟钟预算面/数据面热路径，713x6 tokio 一律不迁，同 tuic udp_assoc 形态）
3. 测试面豁免 10 处（全带 `reason = "测试耗时断言配套，非生产时钟取用"`）：anytls client 1 + anytls server 2 + dns inbound 1 + freedom dispatcher 2 + freedom fragment 2（start_paused 虚拟钟）+ freedom udp 1 + trojan server 1

## 四、验收（实跑尾部）

- `cargo check --workspace --all-targets` → `Finished \`dev\` profile ... in 31.46s`，0 error（含 UdsSpawn2 在飞 inbound.rs 改动共编译）
- `cargo clippy --workspace --all-targets -- -D warnings` → `Finished \`dev\` profile ... in 43.84s`，0 error
- `cargo test -p anytls -p dns -p freedom -p hysteria -p loopback -p trojan --all-targets` → 全部 `test result: ok`，0 failed（单 crate 最大 92 passed；两轮复跑一致）

## 五、DOD 评估：PluginContext 六柄"都能拿到"（生产消费点）

| 柄 | 判定 | 生产消费点（证据） |
|---|---|---|
| spawn | ✓ | vmess/inbound/server.rs:187、wireguard/dispatcher.rs:663、blackhole/inbound.rs:100、http/client.rs:341、freedom/udp.rs:135、trojan/server.rs:503、vless/encryption/mod.rs:882（均 `ctx.spawn`） |
| clock | ✓ | vless/encryption/mod.rs:880（长驻清理任务 `Arc::clone(ctx.clock())` 注入分钟读数） |
| log | ✓ | blackhole/dispatcher.rs:102、blackhole/inbound.rs:139、dokodemo/server.rs:160、http/client.rs:340（`ctx.log()`） |
| pool | **✗** | `ctx.pool()`（context.rs:274）生产**零调用**；仅 blackhole/loopback 插件头"N/A 声明"+ mock 注入测试 |
| ids | **✗** | `ctx.next_conn_id()` 唯一设计消费口 `ObserveFields::new`（observe.rs:60）生产**零调用**；observatory 消费的是 ObserveSink 另一侧 |
| audit | **✗** | `ctx.audit().record`/`take_events` 生产**零调用**（环由装配根持有，无生产发射方；仅 contract fixture） |

迁移点豁免 reason 完整性：spawn 9/9、clock 27/27 全带 reason（本轮逐处核验 + 新增 11 处）。✓

## 六、结论：nn8os 不可关

对照战役 D3（99ifi：16 协议 crate 运行面零裸 `tokio::spawn`/`Instant::now`/`tracing!`）：

- **spawn 面：达成**（0 未豁免 + 9 处显式豁免留痕，符合 D7 三分类）
- **clock 面：达成**（本轮补齐 6 crate 禁令后 16/16 有闸；0 未豁免 + 27 处台账）
- **tracing 面：未达成**——12 crate × **217 站点**仍在生产面裸用，且无禁令、无法台账

剩余项（精确清单）：

| # | 项 | 精确量 | 阻塞原因 |
|---|---|---|---|
| R1 | tracing→LogFacade 迁移 | 12 crate × 217 站点（anytls 28/dns 5/freedom 18/hysteria 19/loopback 2/ss 9/trojan 20/tuic 35/tun 24/vless 14/vmess 18/wireguard 25） | D3 硬判据；`disallowed_macros` 对 proc-macro allow 无效（0791bfb8 三形态实证）→ 不能账只能迁；多数站点需 LogFacade 接线（ctx 不可达处走模块级门面，dokodemo/http 已有同构先例） |
| R2 | tracing 禁令补齐 | 12 crate clippy.toml | 依赖 R1 逐 crate 迁完（先禁令必红） |
| R3 | pool/ids/audit 三柄生产消费点 | 3 柄 | 或接线（ObserveFields::new 是 ids 现成接入口；audit 待首个真实事件源；pool 待首个池化插件），或 PM 将 DOD"都能拿到"降格为"注入可达 + L4 契约测试证明"——现状是机制在、测试在、生产零消费 |
| R4 | 票面其余验收复核 | 每批 interop 12/12 证据 | 本轮未复核，非本轮范围 |

bd nn8os 未动（关票/留票属 Main 裁决；本报告即裁决依据）。

## 自我评估

- 准确性: 5/5 — 每个数字来自 grep 实数；两版扫描器差异（item 级 cfg 陷阱、qualified 归一化、30 行窗口假阴性）均已实证修正并留痕
- 完整性: 4/5 — 扣分：R4（interop 证据归档）超出本票范围未复核；217 站点逐站 ctx 可达性分类留待迁移批次做
- 清晰度: 5/5 — 表格化 + 分类口径显式（①②③④）+ 判据引用（D3/D7 原文）
- 可执行性: 5/5 — R1 站点数可 grep 复现（mod 锚定 cfg(test) 切区口径已写明）；R3 两条出路并列待拍板
- 简洁性: 4/5 — 扣分：三指标表含台账列是为后续批次复核留底，略冗

read 调用审计：
- read skill://subagent-method、serena-cli ⇒ 铁律 0/检索纪律前置，已遵循
- read rule://rust ⇒ 自检纪律命中（.rs 改动），其中 clippy per-crate 替换语义与 disallowed-methods def-path 条目直接用于判读
- read skill://code-simplifier ⇒ 未触发（本轮为审计+禁令补齐，无可读性清扫对象）
- read skill://silent-failure-hunter ⇒ 未触发独立扫描（本次审计对象即失败静默面——台账缺失=错误传播缺失的项目内形态）
- read skill://agent-self-evaluation ⇒ 已遵循（本节）
- read skill://doubt-driven-development ⇒ 子代理上下文内降级执行：CLAIM"anytls handle_conn 属生产面"以 cfg 锚定重扫证伪首扫后落定；未派新鲜审查者（嵌套不可用），已标注降级
- read skill://task-closing-ritual ⇒ 已遵循（沉淀见下）
- read skill://receiving-code-review ⇒ 未触发（无审查反馈）

沉淀：rule://rust clippy 条目追加"re-export 函数禁令单条 entry 按 def path 拦截双书写形态（探针实证），无需逐别名登记"。

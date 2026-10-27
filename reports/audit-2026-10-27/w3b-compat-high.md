# W3b compat 面·框架层之上 crate —— xray-transport / xray-proxy-ss / xray-proxy-wireguard / xray-proxy-tun std 墙钟迁移 + allow 台账删除

- 日期：2026-10-27 · 执行：W3bCompatHigh（fullstack-engineer）· 依据：`docs/architecture/xray-frame-能力收敛方案-2026-10-27.md` §4 面 2/面 3 + §5.2 W3b 行 + §6/§6.1
- 消费件：`xray_frame::compat::clock()`（commit 1679a5a7 W1 已落；兜底 = SystemClock ≡ 迁移前裸 `std::time` 行为，站点行为不变）

## VERDICT: PASS

## 0. 结论速览

| 项 | 数 |
|---|---|
| HEAD std 墙钟站点（`\b(Instant|SystemTime)::now\b` 中 std 形态，含 `StdInstant` 别名） | **64** |
| diff 删除侧（全部改 `xray_frame::compat::clock().now_instant()/now_system()`） | **64（1:1）** |
| 现存 std 墙钟站点 | **0**（四 crate grep 实证 No matches） |
| std 墙钟类例外（allow+理由） | **0** |
| 删除 allow 台账 | **40 项**（38 站点级 + 2 附带过期注释清账；另有 1 项收窄保留，见 §3） |
| 非目标（不迁） | tokio Instant（W5 面）· smoltcp Instant（第三方栈契约）· ss dispatcher tokio 站 1 处 allow 保留 |
| 文件面 | 四 crate `src/**` 23 文件 + `clippy.toml` ×4 = **27 文件**（ Cargo.toml 零改动——`Arc<dyn Clock>` 接收者调方法免 trait import，无需引 udf-skeleton） |

## 1. 站点迁移表（64 站 1:1）

### xray-transport（30 = 生产 18 + 测试 12）

| 文件 | 站点 | 语义 | 原 allow |
|---|---|---|---|
| finalmask/noise.rs | build_segment Timestamp 段 | 4B BE unix wire 段（生产 SystemTime） | 无（SystemTime 未列禁令） |
| finalmask/noise.rs | send_to 噪声注入过期判定 | 墙钟 TTL | :195-200 站点级 ✓删 |
| finalmask/salamander_gecko.rs | 重组 deadline 锚点 | TTL | :329-331 站点级 ✓删 |
| finalmask/salamander_gecko.rs | GC 过期判定 | 墙钟 | :477-479 站点级 ✓删 |
| finalmask/xicmp.rs | TTL 清理（clean task 体内） | 墙钟 | :446-449 站点级 ✓删 |
| finalmask/xicmp.rs | server_send_to 活跃锚点更新 | 墙钟 | :559-562 fn 级 ✓删 |
| finalmask/xicmp.rs | server_recv_from 锚点 insert | 墙钟 | :625-628 站点级 ✓删 |
| finalmask/custom/state.rs | get() TTL 过期判定 | 墙钟 | :33-35 站点级 ✓删 |
| finalmask/custom/state.rs | set() TTL 锚点 | 墙钟 | :48-49 站点级 ✓删 |
| finalmask/xdns/frag.rs | sweep_expired TTL 清扫 | 墙钟 | :62-64 站点级 ✓删 |
| finalmask/xdns/frag.rs | 分片过期判定 | 墙钟 | :123-125 站点级 ✓删 |
| finalmask/xdns/resp.rs | now_deadline 发送 TTL 锚点 | 墙钟 | :308-309 fn 级 ✓删 |
| finalmask/xdns/resp.rs | sweep_expired SendInfo GC | 墙钟 | :395-397 站点级 ✓删 |
| udp/dispatcher.rs | ConnEntry::new NAT 活跃锚点 | 墙钟 | :53 fn 级 ✓删 |
| udp/dispatcher.rs | touch() 锚点更新 | 墙钟 | :60 fn 级 ✓删 |
| udp/relay.rs | send_to 会话锚点刷新 | 墙钟 | :96 fn 级 ✓删 |
| udp/relay.rs | 会话锚点初始化 | 墙钟 | :123-126 站点级 ✓删 |
| udp/relay.rs | reader 泵体内锚点刷新 | 墙钟 | :201-204 泵 allow **保留**（spawn ⑫ 用），reason 收窄为 spawn-only，钟站迁出 |
| tcp/hub.rs | unix socket 临时路径 nanos（测试） | 唯一性熵 | 无 ✓迁 |
| noise.rs | timestamp 测试（cfg test） | 时序断言 | 无 ✓迁 |
| accept_policy.rs | backoff 零 sleep 时序锚点（测试） | 时序断言 | :192 ✓删 |
| bridge.rs ×4 | 桥断开计时锚点（测试） | 时序断言 | ×4 ✓删 |
| happy_eyeballs.rs ×2 | 竞速时序锚点（测试，`StdInstant` 别名形态） | 时序断言 | ×2 ✓删 + 别名 use 删 |
| xicmp.rs ×2 | 稳定窗 deadline 锚点/检查（测试） | 时序断言 | ×2 ✓删 |
| udp/dispatcher.rs | 过期条目构造回拨锚点（测试） | fixture | :298 fn 级 ✓删 |

### xray-proxy-ss（12 = 生产 7 + 测试 5）

| 文件 | 站点 | 语义 | 原 allow |
|---|---|---|---|
| stream.rs | 响应头 epoch（SS2022 wire 字段） | wire 时间戳，取时来源迁 compat（wire 字节零变化） | :248-251 ✓删 |
| stream.rs | 响应 epoch ±30s 校验 | wire 校验 | :647-650 ✓删 |
| ss2022/client.rs | 握手 timestamp | wire 字段 | :145-148 ✓删 |
| ss2022/inbound.rs | check_timestamp ±tolerance | wire 校验 | :632-635 fn 级 ✓删 |
| ss2022/packet.rs | now_unix UDP 包会话时间戳 | wire 字段 | :75-78 fn 级 ✓删 |
| ss2022/replay.rs | new last_clean（Go MapFilter 轮换钟） | 单调墙钟 | :40-43 fn 级 ✓删 |
| ss2022/replay.rs | check now | 同上 | :57-59 fn 级 ✓删 |
| stream.rs ×2 / inbound.rs ×3（:728/:1045/:1250） | 测试 fixture 时间戳 | 测试 | cfg_attr 兜底 ✓迁 |

### xray-proxy-wireguard（21 = 生产 5 + 测试 16）

| 文件 | 站点 | 语义 | 原 allow |
|---|---|---|---|
| driver.rs ×2 | keepalive 节拍初始化/reset | 单调墙钟 | ×2 ✓删（含 713x6 台账注释） |
| inbound.rs ×2 | finish 排空截止 deadline/检查 | 单调墙钟 | ×2 ✓删 |
| tunnel.rs | last_handshake 节拍 | 单调墙钟 | fn 上方 allow ✓删 |
| driver.rs ×2 + inbound.rs ×14（:1013/:1022/:1038/:1040/:1130/:1133/:1153/:1155/:1276/:1277/:1297/:1440/:1441/:1459） | 测试 deadline/断言 | 测试 | cfg_attr 兜底 ✓迁 |

（dispatcher.rs `wait_tcp_connected` 已是 713x6-M1 Clock 参数注入，非裸站，本波零动作。）

### xray-proxy-tun（1 = 生产 1）

| 文件 | 站点 | 语义 | 原 allow |
|---|---|---|---|
| inbound.rs | now_nanos（p14e 活跃戳 + UDP 冷却窗） | 挂钟纳秒 | fn 级 ✓删 |

## 2. 保留项（非 std 墙钟，逐处留证）

- `xray-proxy-ss/src/dispatcher.rs:246-249`：tokio `Sleep::reset(tokio Instant)` 1 站 allow **保留**——713x6 判定「tokio 一律不迁」（reset 仅收 tokio Instant），归 W5 面。
- smoltcp `Instant::now()`（wg/tun `poll`/`Interface::new` 面）：第三方栈时钟契约，方案 §残面明载不迁。
- tokio Instant 其余（transport happy_eyeballs/natpmp/upnp 生产 9 + 测试 8 等）：W5 面。
- 四 crate `clippy.toml` 禁令**全数保留**（enforcement 不减），仅 std Instant/SystemTime 两条 reason 更新为「ctx 可达走 ctx.clock()，不可达走 xray_frame::compat::clock()（W3b 已全量迁移）」；tokio 条 reason 未动（W5 处置）。

## 3. 删除的 allow 台账清单（40 项）

transport 26（noise 1 / salamander 2 / xicmp 5 / state 2 / frag 2 / resp 2 / udp-dispatcher 3 / udp-relay 2 / accept 1 / bridge 4 / happy 2）+ ss 7（stream 2 / client 1 / inbound 1 / packet 1 / replay 2）+ wireguard 6（driver 2 / inbound 2 / tunnel 1 / netstack 1）+ tun 1 = **40**；另收窄保留 1（udp/relay 泵 allow 改 spawn-only reason）。附带清理过期「713x6 台账/不可达」注释 8 处（noise/client/inbound/packet/replay/stream/driver/tunnel）。

## 4. 行为不变性

- 兜底语义 = `SystemClock`（udf skeleton）＝`Instant::now()`/`SystemTime::now()` 原样直通 → 每站点取时值与迁移前一致；未 install 时 caps() 走兜底（本波未动装配根 install，属面 2 步 4/另一波）。
- SS2022 wire 时间戳仅换「取时来源」，wire 字节零变化——interop #05/#06/#11/#12（ss/ss2022 双向）实测 PASS。

## 5. 验证（全门实跑，独立 target-w2）

1. 开工前 `cargo check --workspace --all-targets` → 绿（3m56s，D1 门）
2. 迁移后 `cargo check -p xray-transport -p xray-proxy-ss -p xray-proxy-wireguard -p xray-proxy-tun --all-targets` → **Finished 17.84s，0 error**（vendor rustls 2 warning 为既有）
3. `cargo clippy --workspace --all-targets -j 8 -- -D warnings` → **Finished 2m09s，0 error**
4. `cargo fmt -p <四 crate> -- --check` → **exit 0**；`cargo fmt --all -- --check` 残留 diff 仅 `crates/xray-conf/tests/config_file_shadow.rs:221,345`（W2ConfigShadow 在飞文件面，未触碰、已知会）
5. `cargo test -p <c> --all-targets`：transport **662/0**（2 ignored）；ss lib **176/0** + plugin_contract 15/0 + ss2022_uot_multi_e2e 1/0 + ss_dispatcher_e2e 2/0 + ss_proxy_e2e 1/0（vps_interop 1 ignored）；wireguard lib **110/0** + plugin_contract 6/0；tun lib **154/0** + plugin_contract 10/0
6. `cargo build --release -p xray-cli`（重编含本波改动）→ Finished 12m18s
7. `python dist/interop_matrix.py` → **12/12 PASS**（#05/#11 ss、#06/#12 ss2022 双向均 PASS）

## 6. 残余与协调记录

- 站点对账口径：HEAD 侧 64 = 各 sweep 台账（transport-sweep §5.1/§5.3、proxy-clock-sweep §3.1/§3.5/§3.6）+ 实测 grep 交叉核对（含 sweep 笔误校正：udp/dispatcher:309 实为 std 测试站带 fn 级 allow，非「tokio 无需 allow」）；现存侧四 crate grep `std::time::(Instant|SystemTime)::now|SystemTime::now|StdInstant::now` = 0，裸 `Instant::now` 残留逐一核对均为 tokio/smoltcp。
- 中途一次编辑事故（xicmp server_send_to 误删 `let state_arc =` 行）当步发现当步修复，最终 check/clippy/test 全绿佐证无损。
- `Arc<dyn Clock>` 免 trait import 的事实导致中途误加 11 处 `use skeleton::clock::Clock` + 3 个 Cargo.toml udf-skeleton 依赖，全部回滚（教训沉淀 `~/.omp/agent/rules/rust-trait-object.md`）。
- target-w2 删除责任由 W3aCompatLow 移交本票：**本票完工即删**（见 §7）。
- 协调：W2ConfigShadow（xray-conf 面，无撞面，互报 fmt/clippy 状态）、W6HotPathLog（transport 热路径日志面，与我 12 文件零重叠，bridge.rs 已交还）。

## 7. target-w2 清理

`rm -rf D:/Project/Xray-core-rust/target-w2`（W3a/W3b 两票契约的后完工方落实条款）——已执行于本报告落盘前，见回执。

## 8. code-simplifier 自检

自检改动 9 处（均为迁移伴生清理：过期台账注释 8 + udp/relay allow reason 收窄 1）/ 触碰禁区 0 / diff（本票 27 文件）约 +230 / -300 行（净减——删 allow+注释多于新增调用行）。

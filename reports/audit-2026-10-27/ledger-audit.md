# Lint 豁免台账真实性与纯度审计（2026-10-27）

- 审计对象：`feature/framework` 本夜（2026-10-26 18:00 → 2026-10-27 08:00）全部 `clippy::disallowed_methods` / `disallowed_macros` 豁免台账，重点提交：`35368812` `0791bfb8` `3c0f24d8` `464560d2` `15647696` `c5e8c04f`（diff 基线 `c31ae9b6..HEAD`）。
- 方法：只读。全仓属性清点（多行 allow 属性感知）+ 逐样本读码核验 + 55 份 `clippy.toml` 条目扫描 + 前后镜像计数（`15647696~1` vs HEAD）。未重跑 clippy/测试（Non-goals）。
- 树状态总量（多行属性感知实测）：per-site `#[allow(clippy::disallowed_methods,…)]` 共 **458 处**（app 38 / core+common+tls 38 / transport 272 / proxy 49 / other 61），另有 crate 级 `#![cfg_attr(test,…)]` 测试面豁免与少量 tests/ 文件顶豁免；`inbound.rs` 为文件级。

VERDICT: CONDITIONAL

完工状态：DONE

---

## 1. 理由真实性抽查表（20 条，五类覆盖）

| # | 类别 | 样本文件:行 | 验证方法 | 判定 |
|---|---|---|---|---|
| 1 | 测试面 | xray-app-geodata/src/loader.rs:444 | `#[cfg(test)]`@332，站点在其后 mod tests 内 | 成立 |
| 2 | 测试面 | xray-common/src/platform/filesystem.rs:149 | cfg(test)@142，临时目录唯一名取时 | 成立 |
| 3 | 测试面 | xray-common/src/ocsp/mod.rs:192 | cfg(test)@153，`test_ocsp_response_revoked` 内吊销锚点 | 成立 |
| 4 | 测试面 | xray-tls/src/ech.rs:615/624/635/643/656 | cfg(test)@531，过期判定/锚点构造全部在测试区 | 成立 |
| 5 | 测试面 | xray-core/src/instance.rs:392,394 | cfg(test)@377，panic 隔离断言/对照任务 | 成立 |
| 6 | 测试面 | xray-cli/src/commands/remote_config.rs:520 | cfg(test)@509，stub HTTP server 线程 | 成立 |
| 7 | 测试面 | xray-mux/src/worker.rs:815、session.rs:1099 | cfg(test)@707/@804，过期条目构造 | 成立 |
| 8 | 测试面 | xray-transport-quic/…/quinn_bridge.rs:573-653 | cfg(test)@484，CC 事件时间戳构造在测试区 | 成立 |
| 9 | ctx 不可达+wire 时间戳 | xray-proxy-ss/src/stream.rs:248 | 读码：epoch 写入 SS2022 响应 fixed 头（wire 字段，sing writeResponse 对齐）；SSStream 纯 codec 无注入面 | 成立 |
| 10 | ctx 不可达+wire 时间戳 | xray-proxy-vmess/src/aead/mod.rs:591 | 读码：authID ±120s 窗校验，`AuthIDDecoderHolder`（items+replay_filter）纯结构，构造链无 ctx | 成立 |
| 11 | ctx 不可达 | xray-common/src/log/general_logger.rs:150 | 读码：writer 后台任务；xray-common 禁依赖 xray-frame（分层单向），托管由 Guard 持 JoinHandle 兑现 | 成立 |
| 12 | ctx 不可达（测试面出口） | xray-common/src/testing/mod.rs:25 | 模块文档：L3 闸唯一测试面裸 spawn 出口（bd shexg），不加 feature 门是 bd 5t916 评估决策并附违规声明 | 成立 |
| 13 | ctx 待接线 | xray-transport/src/udp/dispatcher.rs:53,60 | fn 级 allow（E0658 语句位不可挂属性已注明），NAT 活跃锚点，挂 bd 39hko | 成立 |
| 14 | ctx 待接线 | xray-transport-hysteria/src/conn.rs:592 | 同款 fn 级 + bd 39hko 台账 | 成立 |
| 15 | ctx 待接线 | xray-mux/src/session.rs:760 | `cleanup()` 墙钟取时，Clock 注入待 bd 39hko | 成立 |
| 16 | 数据面热路径 | xray-transport/src/finalmask/xdns/server.rs:148,153,158 | 读码：三个常驻泵（recv/send/dr `send_loop`）一次性 spawn，逐包路径保留（坑约束⑫） | 成立 |
| 17 | 数据面热路径 | xray-mux/src/client.rs:315 | carrier 读循环泵，理由=FxScope 记账落每 chunk 开销 | 成立 |
| 18 | 数据面热路径 | xray-proxy-tuic/src/udp.rs:71 | 每帧 uni-stream 响应路由泵（accept_uni 循环），坑约束⑫ | 成立 |
| 19 | 语义判定保留 | xray-app-dispatcher/src/default.rs:650 | 读码：嗅探预算两次取时夹真实 IO await，`elapsed()` 递减预算，MockClock 冻结破坏语义；理由自洽 | 成立 |
| 20 | 协议 wire 时间戳（Go 兼容） | xray-common/src/protocol/time.rs:52 | `NowTime()` Unix 秒兼容语义，纯函数无 ctx（core-clock-sweep §2.2 逐点证据） | 成立 |

补充结构核验（"红线路径"类）：
- **无任何 reason 声称"红线路径"**（全台账 keyword 命中 0）——该类别的合规体现为"红线文件未被触碰"而非豁免理由：`xray-transport-tcp/src/register.rs` 内 spawn/Instant 命中 **0**；transport-sweep §2 红线面命中 0（splice.rs 生产面无站点）；batch1 对 reality vision 两处（inbound.rs:3587/3778）**保留不迁**（文件级 allow 覆盖），未触碰 vision gate/splice。红线纪律成立。

20/20 抽查成立，0 不成立，0 存疑。抽查面另有 8 处无 `reason=` 的 plain allow，逐一核对**均有紧邻注释**给出等价理由（antireplay:43 的 SystemClock 直通论证、general_logger:150、testing:25、h3_client:319、dispatcher:1647/770、account.rs:171、tun:1983），无静默豁免。

## 2. 粒度合规 + inbound.rs 计数核对

**inbound.rs 文件级 allow 三个数（实测，调用站点口径，类型位置不计）：**

| 声称 | 实测 | 判定 |
|---|---|---|
| 生产 spawn 16 | **16** ✓（UDP associate 396 / mux link 444,700,767,870 / SS 泵 1964 / 监控壳 3194,3199 / reality vision 3587,3778 / tun 4006 / UDS 4227,4267,4306,4343,4378；与 reason 的 1+4+1+2+2+1+5 分解逐一可对） | 成立 |
| tests spawn 52 | **52** ✓（test mod 起 :5740） | 成立 |
| Instant 4 | **5** ✗：生产 1（:2437，ss2022 会话 500s 清扫锚点）+ tests 4（:6618/9314/9752/9795） | **不成立** |

- 总数声称 72，实测 **73**（68 spawn + 5 Instant）。
- 根因（前后镜像实锤）：batch1 开工 grep 把 `2198/2200/2342/2357` 四行计为"生产 std Instant 4 处"，但其中三行是**类型位置**（`HashMap<u64,(…,std::time::Instant)>`、fn 参数 `now: std::time::Instant`），只有 2357 是调用；旧 reason「5 std Instant」反而是对的（1 生产 + 4 测试）。"79→72 修正"把 Instant 项改错了（同批 spawn 项 74→81→68 的两次修正都对）。

**粒度问题清单：**

1. 【必修，见 §4-1】inbound.rs:2 与 :8 计数错（72→73、4→5）。
2. 【建议】**crate 级测试面整罩扩大**：`464560d2` 给 6 个 proxy crate（ss/tuic/tun/vless/vmess/wireguard）lib.rs 新增 `#![cfg_attr(test, allow(clippy::disallowed_methods))]`。有 dispatcher 既有先例且 sweep 文档明示（proxy-clock-sweep §0"测试面不动（6 crate 经 cfg_attr(test) 统一豁免）"），生产面不受影响；但偏离 clippy.toml 自订的">20 处/文件文件级须计数与票号"约定（lib.rs 罩子无计数），且静默覆盖未来新增测试代码。可接受，建议在 lib.rs 注释或台账补测试面站点计数。
3. 【建议】**4 个 crate 完全没有 spawn 禁令，生产裸 spawn 未入台账**（超出"未铺 6 个"披露面）：
   - `xray-app-dispatcher`（toml 无 spawn 禁令）：生产裸 `tokio::spawn` ×2 —— src/default.rs:877（spawn_tracked，JoinSet 收割壳，注释有结构化论证）、src/udp_session.rs:160。
   - `xray-transport-splithttp`（toml 只禁 to_vec）：生产裸 spawn ×8（h3_client.rs 365/389/595/685/734 + dialer.rs 79/364/579）+ 生产 `std Instant::now` ×4（dialer.rs 84/117/369/400）。
   - `xray-transport-kcp`：toml 无时钟禁令，生产 `Instant::now` ×3（connection.rs 186/665/678）未登记。
   - `xray-buf`（toml 只禁 to_vec）、`crates/udf-frame`（toml 无 disallowed 块；外部仓，可豁免）。
   各切片文档的"全量归类"声明在其自身范围内诚实（transport-sweep 明写范围=本 crate、"xray-transport-tcp 未进入"），但按 crate 家族口径这是台账外的生产面，建议补一批禁令+逐点登记。
4. 【吹毛】dispatcher default.rs:1647 理由"每连接一次"不精确——嗅探循环最多尝试 2 次（total_attempt>=2 截断），实为"每连接 ≤2 次"；非 relay 热路径的实质判断成立。
5. 【吹毛】tun inbound.rs:1983 plain allow 位于 cfg(test)@1294 内，被本 crate lib.rs:8 cfg_attr(test) 覆盖，属性冗余（无害）。
6. 【吹毛】sweep 文档行号与树漂移 3-5 行（如 ss stream.rs 252→248、tuic server.rs 553→549），站点身份一致；文档仅在引用时需重对行号。

**口径数字核对（对账）：** `core/common/tls 38` ✓（=core-clock-sweep 站点总数 20+10+8）；`transport 17` ✓（=transport-sweep"生产 std 17 站"，xray-transport 单 crate 口径）；`proxy 35` ✓（=proxy-clock-sweep"生产 allow 台账 35 站点/33 处 allow"）；`app-* 7` **未能唯一对应**（树状态 app per-site=38 属性/23 生产；最近似候选：app 切片新增禁令的 crate 数、或 dns tokio 保留 7 站）——属汇总措辞单位混用，非代码缺陷。

## 3. 禁令生效性

写法总检：55 份 clippy.toml 全部存在（55/55 crate 覆盖）；全部条目为合法 def-path（`crate::path::item`，无 glob、无 `!` 后缀），**零条目存在"路径写错→静默不生效"形态**；root clippy.toml 无 disallowed 键（仅 allow-unwrap-in-tests），per-crate 替换语义（toml 内自注探针实证）下无回退遮蔽。

| crate | 条目写法 | 生效证据 | 备注 |
|---|---|---|---|
| xray-core | tokio::spawn / std::thread::spawn / std Instant::now / std SystemTime::now 四条全量 | default.rs:650嗅探预算 allow 的存在即禁令在fire的证明；workspace clippy -D warnings 绿（batch1 门） | 缺 `tokio::task::spawn` 别名条目（10 个 proxy crate 已有；同 def-id，双登记属 belt-and-braces） |
| xray-common | 同四条 | 新禁令激活时 8 处 SystemTime 站点全部预挂 allow 后才绿（core-clock-sweep §3/§5）；antireplay/log/testing 豁免点均带注释 | 本 crate 是 L3 唯一测试面 spawn 出口，自闸设计自洽 |
| xray-app-dispatcher | slice::to_vec / MultiBuffer::to_vec / std Instant / tokio Instant / SystemTime | default.rs:650 多行 allow 必须存在否则 CI 红 | **无 spawn 禁令**（见 §2-3） |
| xray-proxy-freedom | tokio::spawn + tokio::task::spawn + std::thread::spawn + println/eprintln | 条目为正确 def-path；proxy W5 批 clippy 绿 | **时钟面未铺**（无 Instant/SystemTime 条目） |
| xray-app-geodata | tokio::spawn / thread::spawn / Instant / tokio Instant / SystemTime | tests 站点逐点 allow 存在且被要求（loader.rs:444 等） | 覆盖完整 |
| xray-tls | tokio::spawn / thread::spawn + 时钟条目 | ech/ech_doh/btls 生产+测试 allow 面与禁令一一对应 | btls C 回调边界（tls_session_cache:112）ctx 永不可达，豁免理由成立 |

**未铺名单核实：代理声称 freedom/trojan/anytls/dns 等 6 个未铺 —— 准确（时钟面口径）。** 实测缺时钟禁令（std Instant / SystemTime）的 proxy crate 恰为 6 个：**freedom、trojan、anytls、xray-proxy-dns、hysteria、loopback**，与 proxy-clock-sweep §3.7 披露（"无禁令（未被改→不补）"）逐一吻合。注意两点：①这 6 个 crate 的 spawn/thread 禁令多已就位，"未铺"仅指时钟面，引用时勿扩大；②anytls server.rs:207 生产 tokio 站点只在 sweep 文档 §3.9 挂账、代码内无 allow（crate 无对应禁令则无需 allow）——文档台账已披露，建议补禁令时一并落码。tracing 宏禁令仅 4 crate（blackhole/dokodemo/http/socks），条目写法正确（无 `!` 后缀）。

## 4. 必须修条目（CONDITIONAL）

1. **`crates/xray-core/src/inbound.rs:2` 与 `:8`**（注释行 + allow reason）：把「72 处（68 tokio::spawn：生产 16 + tests 52；4 std Instant）」改为「**73 处（68 tokio::spawn：生产 16 + tests 52；5 std Instant：生产 1（:2437 ss2022 会话清扫锚点）+ tests 4）**」。依据：§2 前后镜像计数；旧 reason 的"5 std Instant"本正确，batch1 修正时被 4 行 grep（3 行为类型位置）带偏。
2. （建议同批）`reports/audit-2026-10-27/inbound-spawn-batch1.md` §0「4 处」/§3「生产 std Instant 4|4」/"逐处可对"表述按 5 处（1+4）更正；proxy-clock-sweep §3.x 行号重对（漂移 3-5 行）。
3. （建议，独立批次）补 §2-3 所列 4 crate 的禁令与逐点登记：dispatcher（default.rs:877、udp_session.rs:160）、splithttp（spawn ×8、dialer.rs Instant ×4）、kcp（connection.rs 186/665/678）、anytls（server.rs:207 落码）。

## 未覆盖范围

- 未重跑 clippy/test（Non-goals）；"禁令在 fire"的最终证明依赖 CI 门，本审计给到静态写法正确性 + 豁免属性存在性两级证据。
- `crates/udf-frame`（外部仓克隆）按仓外资产处理，仅记录其 toml 无 disallowed 块。
- `#[allow(clippy::disallowed_macros)]` 对 proc-macro 不生效的已知事实未复核（本夜台账无此类豁免，tracing 面全走迁移）。

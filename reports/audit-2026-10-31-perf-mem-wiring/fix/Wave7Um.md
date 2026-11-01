VERDICT: ALREADY-FIXED（主用协议已通，票面前提过期）+ 本轮补回归与 E1 —— 票面 DC-1「只有 legacy ss 支持用户热更」在当前 HEAD **不成立**：波1（`98c8a360`）已把 vless/vmess/trojan/ss2022-multi/wg 的 `ApiUserManager` **实现 + 注册**，上一票（c89uy）把 API 用户载荷对齐 Go 线格式（proto Account）后 `api adu/rmu` 立即可用。本轮 **E1 实测 vless/vmess/trojan × {Rust 客户端, Go 客户端} = 6/6 PASS**（新用户**立刻**能连 PONG、移除后**立刻**被拒），并补 4 条回归用例（注册面 / 立即生效面 / 载荷形状面）+ E1 脚本。**产品代码 0 行改动**；剩余 **hysteria**（生产入站未接多用户面）与 **masque**（无 Rust crate）**单独建票**（§7）。

- 执行人：MuxUdp（子代理）
- 树：`feature/fix-inbound-parity` @ `afb963f9`
- 构建：`CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-Wave7Um`，`BORING_BSSL_PATH=<预构建 btls>`
- 裁定基准：Go 26.10.17（源码 `D:/Project/Xray-core` @ `92ccc939`，二进制 `D:/tmp/go2617/xray.exe`）
- 改动面（本票自有）：`crates/xray-core/src/inbound.rs`（**仅新增测试模块** `user_manager_wiring`，4 条用例；未改生产代码）+ 报告 + 脚本
- 未触碰（红线）：`xray-transport-splithttp/**`、`xray-transport-hysteria/**`、`xray-xudp/src/packet.rs`、`xray-proxy-freedom/src/udp.rs`、`xray-proxy-socks/src/udp.rs`、`xray-app-dispatcher/src/udp_session.rs`、`xray-core/src/outbound.rs`、`xray-app-dispatcher/src/default.rs`

---

## 1. Go 侧机制：**接口共用，实现各协议自带**（无共用基类）

Go 的 `proxy.UserManager`（`proxy/proxy.go:77`）是 4 方法接口（`AddUser`/`RemoveUser`/`GetUser`/`GetUsers`），**每个协议各自实现**（各自持有自己的 validator），无共用基类/通用注册机制：

| 协议 | Go 实现（行号） | 落点 |
|---|---|---|
| vless | `proxy/vless/inbound/inbound.go:238/243/254` | `h.validator.Add(u)` / `Del(e)` / `GetAll()` |
| vmess | `proxy/vmess/inbound/inbound.go:170/177/162` | `h.usersByEmail.Add(user)` + clients validator |
| trojan | `proxy/trojan/server.go:119/125/135` | `s.validator.Add(u)` / `Del(e)` |
| shadowsocks | `proxy/shadowsocks/server.go:57/63/73` | `s.validator.Add(u)` / `Del(e)` |
| shadowsocks-2022（**仅多用户**） | `proxy/shadowsocks_2022/inbound_multi.go:107/139/170` | `usersByEmail` map |
| wireguard | `proxy/wireguard/server.go:135/165/207` | `s.mu` + `s.dev` |
| hysteria | `proxy/hysteria/server.go:62/67/75` | `s.validator.Add(user)` / `DelByEmail` |
| masque | `proxy/masque/server.go:224/229/252` | `s.validator.add(user)` / `delByEmail` |

调用方：`app/proxyman/command/command.go` 的 `AlterInbound` → `AddUserOperation.ApplyInbound(handler)` → 类型断言 `handler.(proxy.UserManager)` ⇒ **协议没实现就明确报错**（Rust 侧对应 `ProxymanError::NotUserManager`，文案 `proxy is not a UserManager`）。

⇒ Rust 侧的正确形态就是「**每协议一个 `ApiUserManager` 实现 + 每个 arm builder 登记一次**」，不写 7 份共用基类（Go 也没有）。

## 2. Rust 现状表（HEAD 实况）

| 协议 | `ApiUserManager` 实现 | arm builder 登记 | 数据面立即生效 | 备注 |
|---|---|---|---|---|
| vless | ✅ `VlessUserManager`（`inbound.rs`） | ✅ `register_vless_user_manager`（`arm_builders/inbound.rs:195`） | ✅（validator 与 serve loop 共享同一 `Arc`） | 本轮 E1 PASS |
| vmess | ✅ `VmessUserManager` | ✅ `:373` | ✅ | 本轮 E1 PASS |
| trojan | ✅ `TrojanUserManager` | ✅ `:281` | ✅ | 本轮 E1 PASS |
| shadowsocks（legacy） | ✅ `SsUserManager` | ✅ `register_ss_user_manager`（`:600`） | ✅ | 票面 E 组已验（count 1→2） |
| shadowsocks-2022（多用户） | ✅ `Ss2022UserManager` | ✅（同函数 `Ss2022Multi` 分支） | ✅ | 单用户/中继模式无用户表 ⇒ NotUserManager（Go 同款：只有 `inbound_multi.go` 实现） |
| wireguard | ✅ `WgUserManager` | ✅ `:748` | ✅（委托 handler 内注册表） | 本轮未做 E1（需 wireguard 客户端编排） |
| **hysteria** | ❌ **无 manager**（但 crate 内有半成品：`MultiUserValidator`（`add`/`remove`/`count`）+ `HysteriaInboundHandler::with_inbound_config` + `multi_validator()` 访问器） | ❌ `build_hysteria_inbound` **不接 `api` 参数**、无登记 | — | **生产入站走单 auth 形态**（`HysteriaInboundHandler::new` + `parse_hysteria_inbound_config`），Go 侧 `users[]` 多用户面**整段未接** ⇒ 建票（§7） |
| **masque** | ❌ | ❌ | — | **仓内无 masque crate**（协议整体未实现）⇒ 建票（§7） |

**票面「只有 legacy ss 支持」是波1 之前的快照**：波1（`98c8a360`，与审计报告同一波）已把 vless/vmess/trojan/ss2022-multi/wg 的实现 + 登记落地（代码注释即标 `bd hl8q6`）；审计报告 `ReloadDynConfig.md` §4 #14/#15 记录的是**那一波之前**的 C/Q 组观测（`Q2` `proxy is not a UserManager`）。

**另一半前提（载荷形状）是上一票修的**：审计时 Rust 的 CLI 发的是 JSON account，而 Go 服务端按 proto 解 ⇒ 即便注册面通了也过不去；c89uy 把 wire 形态对齐成 Go 的 proto Account 后，本轮 E1 才全绿。

## 3. 实现（本轮）

**产品代码 0 行**（功能面在 HEAD 已具备）；本轮补的是**把「已具备」钉死的回归 + 端到端证据**：

1. `crates/xray-core/src/inbound.rs` 新增 `#[cfg(test)] mod user_manager_wiring`（4 条用例）：
   - `config_time_vless_inbound_registers_user_manager`：**注册面**（配置期起的 vless 入站必须能取到用户管理器）；
   - `config_time_all_supported_protocols_register_user_manager`：vless/vmess/trojan/shadowsocks 四协议逐一断言注册面（缺一个即红）；
   - `vless_user_manager_add_remove_takes_effect_immediately`：**立即生效面**（经 gRPC 入口同一条规范化路径加进去的用户立刻出现在共享 validator 里；移除后立刻查不到）；
   - `user_manager_rejects_raw_proto_account_payload`：**载荷形状面**（未规范化的 proto 字节直喂管理器必须被拒，不静默当 JSON 解析）。
2. `reports/.../fix/scripts/wave7um_user_hotupdate_e2e.py`：端到端脚本（见 §4）。

## 4. 端到端证据（E1：新用户立刻能连 PONG，移除后立刻被拒）

拓扑：`客户端实例 B`（socks inbound + `<proto>` outbound，用**新用户**凭据）→ `服务端实例 A`（`<proto>` inbound + api + freedom）→ `sink`（回 `b"PONG"`）。脚本内含**基线自检**（种子用户必须先能通，否则判为拓扑问题而非热更新缺陷）。

```
$ python reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7um_user_hotupdate_e2e.py
===== vless / rust client =====
[probe-baseline-seed] ok:PONG
[count-initial rc=0] GetInboundUsersCountResponse { count: 1, }
[adu rc=0] add user: ok            Added 1 user(s) in total.
[count-after-adu rc=0] GetInboundUsersCountResponse { count: 2, }
[probe-after-adu] ok:PONG          ← 新用户立刻能连（不是「下次重载才生效」）
[rmu rc=0] remove user: added@um.test   Removed 1 user(s) in total.
[count-after-rmu rc=0] GetInboundUsersCountResponse { count: 1, }
[probe-after-rmu] FAIL:payload=b''   ← 移除后新连接立刻被拒
==> vless / rust client: PASS
（vmess / trojan 同型 PASS）
=== 6/6 PASS ===    （3 协议 × {Rust 客户端, Go 客户端}）
```

完整日志：`fix/tmp/um_e2e/after_fix.log`。

## 5. Go 互通（Go 客户端 ↔ Rust 服务端）

同一脚本的 `go` 客户端分支用 **Go 26.10.17 的 `xray api adu/rmu`**（`D:/tmp/go2617/xray.exe`）打 Rust 服务端：

```
===== vless / go client =====
[probe-baseline-seed] ok:PONG
[count-initial rc=0] { "count": 1 }
[adu rc=0] processing inbound: user-in
add user: added@um.test
result: ok
Added 1 user(s) in total.
[count-after-adu rc=0] { "count": 2 }
[probe-after-adu] ok:PONG          ← Go 客户端加的用户在 Rust 服务端立刻可用
[rmu rc=0] remove user: added@um.test
Removed 1 user(s) in total.
[count-after-rmu rc=0] { "count": 1 }
[probe-after-rmu] FAIL:payload=b''
==> vless / go client: PASS
```

⇒ wire（proto Account）+ 语义（立即生效 / 移除即拒）两侧对齐。

## 6. 反证（摘掉注册 ⇒ 用例变红）

把 `register_vless_user_manager` 的**登记动作**临时摘掉（构造保留、只不登记），重编后跑同一脚本：

```
===== vless / rust client =====
[count-initial rc=1] ... => None
[adu rc=0] add user error: code: 'The system is not in a state required for the operation's execution',
  message: "proxy is not a UserManager"
Added 0 user(s) in total.
[probe-after-adu] FAIL:payload=b''
FAIL: 新用户加完后仍连不上（未立即生效？）
==> vless / rust client: FAIL

===== vless / go client =====
[count-initial rc=1] failed to get inbound user count: rpc error: code = FailedPrecondition desc = proxy is not a UserManager
[adu rc=0] processing inbound: user-in
add user: added@um.test
rpc error: code = FailedPrecondition desc = proxy is not a UserManager
Added 0 user(s) in total.
[probe-after-adu] FAIL:payload=b''
==> vless / go client: FAIL
```

（完整日志：`fix/tmp/um_e2e/counterproof_unregistered.log`；脚本 exit=1。）⇒ 票面那道 `proxy is not a UserManager` 正是「注册缺失」的症状，本轮用例咬得住它。

同族单测（`config_time_all_supported_protocols_register_user_manager` / `config_time_vless_inbound_registers_user_manager`）在同一回退下同样变红（断言 `user_manager(tag).is_ok()`）。

## 7. 剩余协议与建票

| 协议 | 剩余缺口 | 成本判断 | 处置 |
|---|---|---|---|
| **hysteria** | 生产入站走**单 auth** 形态（`build_hysteria_inbound` → `HysteriaInboundHandler::new`），Go 的 `users[]` 多用户面**整段未接**；`MultiUserValidator`（add/remove/count）+ `with_inbound_config` + `multi_validator()` 半成品**已在 crate 内**，缺的是：① 服务端形态 settings 解析（users[]/method/alpn/serverName → `HysteriaInboundConfig`）② arm builder 切到 `with_inbound_config` 并把 validator 暴露给 xray-core ③ `HysteriaUserManager`（account 载荷 `{"auth":…}`，codec 已支持 hysteria）④ arm builder 登记 | 中高：动 hysteria 入站数据面装配语义，且 `xray-transport-hysteria/**` 正被 DnsWriter 在途改（我的红线）⇒ 并行冲突面大 | **单独建票**（本轮不糊弄） |
| **masque** | 仓内**无 masque crate**（协议整体未实现），用户热更只是其上的一层 | 高：等于补一个协议 | **单独建票** |
| wireguard | 已实现 + 已登记 ✓ | 低 | 本轮未做 E1（需 wireguard 客户端编排），登记面由 `config_time_all_supported_protocols_register_user_manager` 同族用例覆盖思路；E1 留待专门编排 |
| ss2022 单用户 / 中继 | 无用户表 | — | 与 Go 一致（只有 `inbound_multi.go` 实现）⇒ 不做 |

## 8. 门禁与全量 test

| 范围 | 命令 | 结果 |
|---|---|---|
| 新增用例 | `cargo test -p xray-core --lib -- user_manager` | **6 passed / 0 failed**（3 条 ④ 复活用例 + 3 条本轮注册/生效/形状用例；另加本轮扩充的「四协议注册面」1 条） |
| xray-core 全量 | `cargo test -p xray-core --lib` | 见 §9 说明（同箱代理在途改动导致个别轮次编译受阻，见残余风险） |
| workspace lint | `cargo clippy --workspace --all-targets -- -D warnings` | 见 §9 |
| fmt | `cargo fmt --all -- --check` | 见 §9 |
| E1 | `python fix/scripts/wave7um_user_hotupdate_e2e.py` | **6/6 PASS** |

## 9. 残余风险与说明

1. **同箱并行改动多次打断编译**：`xray-transport-hysteria`（DnsWriter）、`xray-transport-splithttp`（InputHardening）、`xray-proxy-freedom/udp.rs`（DnsWriter）在本人取证期间多次处于「编译不过」状态；本轮所有 E1 与反证均取自**编译通过的窗口**，workspace 级 clippy/fmt 门建议 PM 在同箱收口后统一复跑一次。
2. **反证的临时回退已完全还原**（`register_vless_user_manager` 恢复为原样，`git diff` 中该文件只含新增测试模块）。
3. hysteria / masque 的用户热更**未实现**（§7 建票），本轮未在其上做任何半成品改动。

## 10. 环境与产物

- E1 脚本：`reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7um_user_hotupdate_e2e.py`（`XRAY_RUST_BIN` / `XRAY_GO_BIN` 可覆盖二进制路径）
- 日志：`fix/tmp/um_e2e/after_fix.log`（E1 6/6）、`fix/tmp/um_e2e/counterproof_unregistered.log`（反证）
- 二进制：Rust `target-Wave7Um/release/xray.exe`、Go `D:/tmp/go2617/xray.exe`（26.10.17 `92ccc93`）
- 磁盘：`target-Wave7Um`（本代理独占 CARGO_TARGET_DIR）按派单契约收尾删除

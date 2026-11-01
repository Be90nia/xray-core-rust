VERDICT: FIXED —— API `adu`/`rmu` 的用户载荷改成 **Go 线格式**（`xray.common.protocol.User{level, email, account: TypedMessage}`，account 的 value = 该协议 `Account` 的 **protobuf 字节**）：客户端侧按协议编 proto、服务端侧按 `type_url` **显式分派**解 proto → 内部 JSON 契约。**双向真互通 2/2 PASS**（Go 客户端 ↔ Rust 服务端 / Rust 客户端 ↔ Go 服务端，用户数 1→2→1 两侧一致）。反证（CLI 改回 JSON 形状 → Go 侧 `proto: cannot parse invalid wire-format data`）已取证。顺带修掉两处同票面 latent：CLI 协议名 `contains` 误匹配（ss 用户被提取两遍）、debug 构建下 `api inbound-user-count`/`remove-user` 的 clap 短选项冲突 panic。

- 执行人：MuxUdp（子代理）
- 树：`feature/fix-inbound-parity` @ `afb963f9`
- 构建：`CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-Wave7User`，`BORING_BSSL_PATH=<预构建 btls>`
- 裁定基准：Go 26.10.17（源码 `D:/Project/Xray-core` @ `92ccc939`，二进制 `D:/tmp/go2617/xray.exe`）
- 改动面（本票自有）：
  - `crates/xray-core/src/account.rs`（**新增**，账号载荷编解码 + 12 条单测）
  - `crates/xray-core/src/lib.rs`（+2：注册 `pub mod account`）
  - `crates/xray-core/src/functions.rs`（gRPC `AlterInbound(AddUserOperation)` 入口规范化 account 载荷）
  - `crates/xray-cli/src/commands/api_exec.rs`（CLI 按协议编 proto Account；协议名精确匹配）
  - `crates/xray-cli/src/commands/api_args.rs`（clap 短选项冲突修复）
- 未触碰（红线）：`xray-core/src/inbound.rs`、`xray-transport-splithttp/**`、`xray-transport-websocket/src/pool.rs`、`xray-frame/src/scope.rs`、`xray-xudp/src/packet.rs`、`xray-proxy-freedom/src/udp.rs`、`xray-proxy-socks/src/udp.rs`、`xray-app-dispatcher/src/udp_session.rs`

---

## 1. Go 线格式取证

### 1.1 CLI 侧（`main/commands/all/api/`）

- `inbound_user_add.go:71-86` `addInboundUserAction`：
  `AlterInboundRequest{Tag: <inbound tag>, Operation: TypedMessage{Type: "xray.app.proxyman.command.AddUserOperation", Value: proto(AddUserOperation{User: user})}}`。
- `inbound_user_add.go:88-110` `extractInboundUsers`：从**配置构建出的**协议 inbound 里取用户（`vmessin.Config.User` / `vlessin.Config.Users` / `trojan.ServerConfig.Users` / `shadowsocks.ServerConfig.Users` / `shadowsocks_2022.MultiUserServerConfig.Users` / `masque` / `hysteria`）——每个都是 `*protocol.User`。
- `inbound_user_remove.go:55-67` `rmu`：`AlterInboundRequest{Tag, Operation: TypedMessage{Type:"xray.app.proxyman.command.RemoveUserOperation", Value: proto(RemoveUserOperation{Email})}}`——**移除不带 account**（两端本就同形，无需改）。

### 1.2 `protocol.User` 与 account 的线格式

`common/protocol/user.proto`：`User{level: uint32, email: string, account: TypedMessage}`。
`account` 的 `Type` = 协议账号类型名，`Value` = **该类型 proto 的字节**（Go 各协议 `infra/conf/*.go` 的 `Build()` 里 `serial.ToTypedMessage(&<proto>Account{…})` 产出）。

### 1.3 服务端消费方（决定 value 必须是 proto）

Go `proxy/vless/inbound`（及 vmess/trojan/ss）的 `AddUser` → `user.GetTypedAccount()` → `serial.GetInstance(u.Account)` → **按 `Type` 找注册类型并按 proto 解 `Value`** ⇒ value 是 JSON 文本时必然
`proto: cannot parse invalid wire-format data`（本票反证即命中这条）。

### 1.4 各协议 Account 字段集与 JSON 来源

| 协议 | Go proto Account 字段 | Go JSON 配置来源 |
|---|---|---|
| vless | `id(1) string` / `flow(2) string` / `encryption(3)` / `xorMode(4)` / `seconds(5)` / `padding(6)` / `reverse(7)` / `testpre(8)` / `testseed(9)` | `infra/conf/vless.go:298-301`（入站侧 `encryption` 必须为空，否则 `vless.go:84-86` 硬错） |
| vmess | `id(1) string` / `security_settings(3) SecurityConfig` / `tests_enabled(4)` | `infra/conf/vmess.go:33-47`（security→SecurityType：aes-128-gcm=3 / chacha20-poly1305=4 / 其余=2=AUTO） |
| trojan | `password(1) string` | `infra/conf/trojan.go:138-143` |
| shadowsocks | `password(1)` / `cipher_type(2) CipherType` / `iv_check(3)` | `infra/conf/shadowsocks.go:67-71`（cipher_type：aes-128-gcm=5 / aes-256-gcm=6 / chacha20-poly1305=7 / xchacha20-poly1305=8） |
| shadowsocks_2022 | `key(1) string` | `infra/conf/shadowsocks.go:141-147`（`Key` = JSON 的 `password`，同一 base64 PSK）——**服务端 method 命中 `2022-blake3-*` 时**才走这条（`shadowsocks.go:58-60`） |
| hysteria | `auth(1) string` | `infra/conf/hysteria.go:58-64`（类型在 account 子包 `xray.proxy.hysteria.account.Account`） |

---

## 2. Rust 现状（修前）

| 面 | 现状 | 后果 |
|---|---|---|
| CLI `extract_users_from_inbound`（`xray-cli/src/commands/api_exec.rs`） | account 的 `type_url` 正确（`xray.proxy.<proto>.Account`），但 **value 写的是 JSON**（hysteria 例外已是 proto） | Rust 客户端 → Go 服务端：`failed to parse user > proto: cannot parse invalid wire-format data` |
| 服务端 `xray-core/src/inbound.rs` 的各 `ApiUserManager` | 按 **JSON** 解析 `user.account.value`（`account_json()`：vless 取 `id`/`flow`、vmess 取 `id`、trojan/ss 取 `password`、ss2022 取 `password`、wg 取 PeerConfig 字段） | Go 客户端 → Rust 服务端：proto 字节被当 JSON 解析 ⇒ `account is not JSON` ⇒ 用户加不上 |
| 移除语义 | `RemoveUserOperation{email}`，两端同形 | ✅ 无需改 |

即：**双向都不通**（Go 客户端 → Rust 服务端、Rust 客户端 → Go 服务端）。

---

## 3. 修法与取舍

### 3.1 修法

新增 `crates/xray-core/src/account.rs`（wire ↔ 内部契约的**单一真相源**，CLI 与服务端共用；放 xray-core 是因为 CLI 已依赖它，且与上一票的 `wiring::parse_routing_json_to_proto` 同一层：生产装配解析器）：

- `account_typed_message_from_config_json(kind, settings, entry) -> TypedMessage`（**客户端侧**）：配置 JSON 的一个用户条目 → Go 线格式的 proto Account。
- `account_internal_json_from_typed_message(tm) -> Vec<u8>`（**服务端侧**）：Go 线格式的 proto Account → 内部 JSON 契约字节。
- `normalize_user_account(user)`（**服务端入口**）：只改 `user.account.value`，`type_url`/`email`/`level` 原样保留。

接线：
- `xray-cli/src/commands/api_exec.rs::extract_users_from_inbound` 改用 `account_typed_message_from_config_json`（不再自造 JSON 载荷）。
- `xray-core/src/functions.rs::ApiHandlerService::alter_inbound` 在 `AddUserOperation` 分支调 `normalize_user_account` 后再 `add_user`。

### 3.2 取舍（明确写出，不做 try-parse 静默回退）

1. **wire 形态 = Go 完全一致**（proto Account）。首选方案，不引入方言。
2. **Rust 内部契约仍是 JSON**：`xray-core/src/inbound.rs` 是本票红线（其他代理在途），其各用户管理器消费 JSON；因此在 **wire ↔ 内部边界**（gRPC `AlterInbound` 入口）做一次**显式按 `type_url` 分派**的映射，而不是去改内部契约。
3. **判别方式**（三条，全部显式）：
   - 命中**已知** `type_url` ⇒ 按该协议解 proto；**解失败即报错**（`UserParse`），**不回落「再试 JSON 解析」**；
   - **未知** `type_url` ⇒ 原样透传（内部契约即原始载荷的协议——如 wireguard——由其管理器自行解释）；
   - **唯一兼容路径**：旧 Rust 客户端的历史 JSON 载荷（value 以 `'{'`(0x7B) 开头）原样透传。判别无歧义：各协议 Account 的合法首字节不会是 0x7B（字段号 ≤ 9 ⇒ 首字节 ≤ 0x4A）。这是**显式**兼容，不是 try-parse 回退。
4. **ss2022 分支**：服务端级 `method` 命中 `2022-blake3-*` ⇒ account 用 `shadowsocks_2022.Account{key}`（Go `shadowsocks.go:58-60`）；否则 legacy AEAD 的 `shadowsocks.Account{password, cipher_type}`。内部 JSON 侧 `key` ↔ `password` 同值改名。

### 3.3 顺带修的两处 latent（同票面）

- **CLI 协议名提取**从 `proxy.r#type.contains(proto)` 改**精确匹配**（取 type_url 中段）：旧写法让 `"shadowsocks"` 命中 `"shadowsocks_2022"`（Go 的 ss2022 走 `shadowsocks` 协议名 + 2022 method）⇒ 同一批用户被**提取两遍**。
- **clap 短选项冲突**：`ApiSharedArgs.timeout` 占 `-t`，而 `RemoveUserArgs/InboundUserArgs/InboundUserCountArgs.tag` 也占 `-t` ⇒ clap 的 `debug_asserts` 在 **debug 构建**下 panic（`api inbound-user-count` / `api remove-user` 直接崩，release 构建因 debug_assert 被跳过而不显形）。修法：`tag` 去掉 short（保留 `--tag`；Go 风格 `-tag` 由 CLI 的 normalize 归一）。

---

## 4. 双向互通输出（2/2 PASS）

脚本：`reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7user_api_user_interop.py`
（明文 gRPC `api.listen=127.0.0.1:10086` + `services:["HandlerService"]`；服务端跑一个 vless inbound（tag `vless-in`，seed 用户 1 个），客户端对同一 tag 做 `adu`/`rmu`，两端用 `inboundusercount` 核对用户数）

```
===== phase1 Rust server <- Go client (adu/rmu) =====
[count-initial rc=0] { "count": 1 }
[adu rc=0] processing inbound: vless-in
add user: added@interop.test
result: ok
Added 1 user(s) in total.
[count-after-adu rc=0] { "count": 2 }
[rmu rc=0] remove user: added@interop.test
Removed 1 user(s) in total.
[count-after-rmu rc=0] { "count": 1 }
==> phase1 Rust server <- Go client (adu/rmu): PASS

===== phase2 Go server <- Rust client (adu/rmu) =====
[count-initial rc=0] GetInboundUsersCountResponse { count: 1, }
[adu rc=0] add user: ok
Added 1 user(s) in total.
[count-after-adu rc=0] GetInboundUsersCountResponse { count: 2, }
[rmu rc=0] remove user: added@interop.test
Removed 1 user(s) in total.
[count-after-rmu rc=0] GetInboundUsersCountResponse { count: 1, }
==> phase2 Go server <- Rust client (adu/rmu): PASS

=== 2/2 PASS ===
```

⇒ Go 客户端的 proto Account 被 Rust 服务端正确解析并加用户；Rust 客户端的 proto Account 被 Go 服务端正确接受（`result: ok`）；移除语义两侧一致（1→2→1）。

---

## 5. 反证

把 CLI 的 account 载荷改回旧形状（`type_url` 不变、`value` = JSON）后重编 + 同一互通脚本：

```
===== phase1 Rust server <- Go client (adu/rmu): PASS        ← Rust 服务端按显式判别兼容旧 JSON 载荷（预期）
===== phase2 Go server <- Rust client (adu/rmu) =====
[adu rc=0] add user error: code: 'Unknown error', message:
  "app/proxyman/command: failed to parse user > proto:\u{a0}cannot parse invalid wire-format data"
Added 0 user(s) in total.
[count-after-adu rc=0] GetInboundUsersCountResponse { count: 1, }
FAIL: adu 后用户数应为 2，实得 1
[rmu rc=0] remove user error: code: 'Unknown error', message:
  "proxy/vless: User added@interop.test not found."
==> phase2 Go server <- Rust client (adu/rmu): FAIL
=== 1/2 PASS ===
```

（完整输出：`fix/tmp/api_user_interop/counterproof_legacy_json.log`；改回后 `api_exec.rs` 与修后版本零差异。）

⇒ Go 侧对旧 JSON 形状报的是**proto 线格式错**（`cannot parse invalid wire-format data`），正是验收要求的错误类型；Rust 侧因显式兼容路径仍接受旧 JSON 客户端（这是设计内的取舍，非静默回退）。

---

## 6. 字段对照表（Go Account proto ↔ Rust 对齐后）

| 协议 | Go proto Account 字段集（26.10.17） | Rust 对齐后 **wire** 载荷（type_url + value） | Rust **内部** JSON 契约（`inbound.rs` 消费） | 备注 |
|---|---|---|---|---|
| vless | `id`(1) `flow`(2) `encryption`(3) `xorMode`(4) `seconds`(5) `padding`(6) `reverse`(7) `testpre`(8) `testseed`(9) | `xray.proxy.vless.Account{id, flow}`（proto 字节） | `{"id","flow"}` | 入站侧 `encryption` 必须为空（Go `vless.go:84-86` 硬错）；Go 侧 `flow` 空则继承 inbound 级 flow |
| vmess | `id`(1) `security_settings`(3) `tests_enabled`(4) | `xray.proxy.vmess.Account{id, security_settings{type}}` | `{"id"}` | security→SecurityType：aes-128-gcm=3 / chacha20-poly1305=4 / 其余=2(AUTO)（Go `vmess.go:33-44`） |
| trojan | `password`(1) | `xray.proxy.trojan.Account{password}` | `{"password"}` | — |
| shadowsocks | `password`(1) `cipher_type`(2) `iv_check`(3) | `xray.proxy.shadowsocks.Account{password, cipher_type}` | `{"password","method"}` | cipher_type：5/6/7/8 ↔ method 名 `aes-128-gcm`/`aes-256-gcm`/`chacha20-poly1305`/`xchacha20-poly1305`（Go `cipherFromString`） |
| shadowsocks_2022 | `key`(1) | `xray.proxy.shadowsocks_2022.Account{key}` | `{"password"}`（= key 同值改名） | 仅当服务端 method 命中 `2022-blake3-*`（Go `shadowsocks.go:58-60`） |
| hysteria | `auth`(1) | `xray.proxy.hysteria.account.Account{auth}` | `{"auth"}` | 类型在 account 子包（Go `hysteria.go:59-63`） |
| 移除 | —（`RemoveUserOperation{email}`，无 account） | 同形 | — | 两端本就一致 |

---

## 7. 门禁与全量 test

| 范围 | 命令 | 结果 |
|---|---|---|
| 新增模块单测 | `cargo test -p xray-core --lib -- account::` | **12 passed / 0 failed**（各协议往返、legacy JSON 透传、坏 proto 硬错、未知 type_url 透传、缺字段硬错、未知协议硬错、normalize 不动 type/email/level） |
| xray-core 全量 | `cargo test -p xray-core --lib` | **530 passed / 0 failed / 2 ignored** |
| commander + cli（验收 3） | `cargo test -p xray-app-commander -p xray-cli --all-targets` | **93 + 100 + 8 + 18 passed / 0 failed** |
| clippy（验收 4） | `cargo clippy -p xray-app-commander -p xray-cli --all-targets -- -D warnings` | **零告警**（Finished，无 warning） |
| fmt（验收 4） | `cargo fmt -p xray-core -p xray-cli -p xray-app-commander -- --check` | **0 diff** |
| ② 双向真互通 | `python fix/scripts/wave7user_api_user_interop.py` | **2/2 PASS** |

未跑 workspace 全量 test：本次改动只触 `xray-core` / `xray-cli` 两个 crate（生产代码面 = 1 个新模块 + 2 处接线），workspace 全量由 PM 收口门统一跑（同箱另有代理在途改动）。

---

## 8. 环境与产物

- 互通脚本：`reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7user_api_user_interop.py`（`XRAY_RUST_BIN` / `XRAY_GO_BIN` 可覆盖二进制路径）
- 验证脚本：`reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7user_verify.sh`（重编 → 互通 → 测试 → clippy → fmt）
- 日志：`fix/tmp/api_user_interop/after_fix.log`（修后 2/2）、`counterproof_legacy_json.log`（反证）
- 二进制：Rust `target-Wave7User/release/xray.exe`（release）、Go `D:/tmp/go2617/xray.exe`（26.10.17 `92ccc93`）
- 磁盘：`target-Wave7User`（本代理独占 CARGO_TARGET_DIR）按派单契约收尾删除

# Wave7 · ctiwx —— hysteria 入站多用户面未接线（MultiUserValidator 半成品 + 缺 ApiUserManager）

VERDICT: PASS —— hysteria 入站 users[] 多用户面已接线（接线既有 MultiUserValidator，未另写一套）；`HysteriaUserManager` 注册进 gRPC 用户面；单 auth 形态回归 + auth/users 互斥硬错；Go 客户端 ↔ Rust 服务端真互通 3/3（adu 立即生效 / rmu 立即拒 / 单 auth 显式 `proxy is not a UserManager`）；门禁全绿。

- [x] §1 现状取证
- [x] §2 Go 语义（行号）
- [x] §3 单 auth 与多用户的关系
- [x] §4 实现
- [x] §5 端到端证据（adu 立即生效 + rmu 立即拒 + 单 auth 回归）
- [x] §6 Go 互通
- [x] §7 反证
- [x] §8 门禁
- [x] §9 残余风险

---

## §1 现状取证

**注意：半成品在 `crates/xray-proxy-hysteria`（代理层），不在 `xray-transport-hysteria`（传输层）**——票面 crate 名有误，以实际 grep 为准。

| 件 | 位置 | 状态 |
|---|---|---|
| `MultiUserValidator` | `xray-proxy-hysteria/src/config.rs:433-525` | ✅ 完整：`new`/`from_users`/`add`/`remove`/`get`/`count` + `impl AuthValidator`（`validate` 委托 `get`）——对应 Go `account.Validator` |
| `HysteriaInboundHandler::with_inbound_config` | `xray-proxy-hysteria/src/inbound.rs:186-223` | ✅ 已实现：`users[]` → `MultiUserValidator::from_users` → `multi_validator: Some(...)`；`start()`（inbound.rs:276-283）里 multi_validator **优先于** config.auth |
| `multi_validator()` 访问器 | `xray-proxy-hysteria/src/inbound.rs:235-237` | ✅ 存在，但生产无人消费（只读） |
| 生产构造路径 | `xray-core/src/arm_builders/inbound.rs:621-652` `build_hysteria_inbound` | ❌ **不接 `api` 参数**；走 `HysteriaInboundHandler::new(&ib.tag, config, bind_addr, factory)` 单 auth 形态 + `with_dispatcher`/`with_udp_dispatcher` |
| 配置解析 | `xray-core/src/inbound.rs:5740-5801` `parse_hysteria_inbound_config` | ❌ 只解析 `auth`（单串）+ tls/masq/quic_params/obfs；**`users[]`/`clients` 完全不读**，返回 `(HysteriaConfig, factory)` 二元组 |
| `hysteria_entry` | `arm_builders/inbound.rs:1483-1492` | ❌ 未把 `ctx.api` 传进 builder（`InboundCtx` 有 `api` 字段，mod.rs:58——ss/wg 臂都传了，hysteria 没传） |
| `ApiUserManager` | `xray-core/src/inbound.rs:3132-3137`（trait，4 方法：add_user/remove_user/get_user/list_users） | ❌ 无 hysteria 实现（已有 ss/vless/vmess/trojan/ss2022/wg 六个）；`InboundRuntime::user_manager(tag)`（:3604）查不到即 `ProxymanError::NotUserManager` ⇒ `api adu/rmu` 对 hysteria 报错 |

**结论**：`MultiUserValidator` 是完整件（非空壳），差的只是三层接线：①配置解析不读 `users[]`；②builder 不接 api/不注册；③无 `ApiUserManager` 适配器。

## §2 Go 语义（行号，基准 92ccc939）

- **配置形态**（`infra/conf/hysteria.go:33-43`）：`HysteriaUserConfig{auth string, level uint32, email string}`；`ServerConfig{version, users[], clients[]}`，**`clients` 非 nil（含空数组）整体覆盖 `users`**（:52-54）。Build（:55-72）逐用户 → `protocol.User{email, level, account: serial.ToTypedMessage(&account.Account{Auth})}`。**Go `ServerConfig` 没有 `auth` 单串字段——users[] 是唯一形态**。
- **服务端**（`proxy/hysteria/server.go:41-56` `NewServer`）：`validator := account.NewValidator()`，遍历 `config.Users` → `ToMemoryUser()` → `validator.Add(u)`（重复 email 即错）。
- **UserManager**（server.go:62-75）：`AddUser → validator.Add`；`RemoveUser → validator.DelByEmail`；`GetUser → GetByEmail`；`GetUsers → GetAll`；`GetUsersCount → GetCount`——与 serve loop **共享同一 validator 实例**，增删对后续连接立即生效。
- **单 auth 与多用户的关系**：Go 无单 auth 形态（单用户 = users[] 里一条）。Rust 的 `auth` 单串是本仓既有生产形态（且被 32/32 基线依赖），**必须保留**；两形态在 Go 里无从并存 ⇒ Rust 配置期同时出现 `auth` + `users[]` 属歧义 → **硬错**（本票新增，见 §3）。

## §3 单 auth 与多用户的关系

| 配置 | 行为 |
|---|---|
| 只有 `auth` | 单 auth（本仓既有形态，回归不动）：`StaticAuthValidator`，**不注册**用户管理器（`api adu` → `NotUserManager`，与 ss2022 单用户模式同款——Go 语义里该形态不存在用户表） |
| 只有 `users[]`（或 `clients`） | 多用户（Go 对齐）：`MultiUserValidator::from_users` + 注册 `HysteriaUserManager` ⇒ `api adu/rmu` 可用 |
| 两者同时 | **配置期硬错**：`hysteria: `auth` and `users[]` are mutually exclusive (Go hysteria2 server config uses users[]; drop `auth` or use users[])` ——解析层 `parse_hysteria_inbound_config` 直接 Err，不静默选一 |
| 两者都空 | 维持现状：`start()` 里 validator = None（hysteria hub 对 None validator 的既有行为） |

## §4 实现

| 文件 | 改动 |
|---|---|
| `xray-proxy-hysteria/src/config.rs` | `MultiUserValidator.users` 值 `String(email)` → `HysteriaUser`（level 随用户保留，`GetUser/GetUsers` 回程需要）；新增 `list()`（Go `Validator.GetAll` 对应物）；`add/remove/get/count` 语义不变 |
| `xray-proxy-hysteria/src/inbound.rs` | 新增 `with_multi_validator(Option<Arc<MultiUserValidator>>)` builder——生产装配在 `new()` 单 auth 骨架上叠加多用户验证器（masq/quic_params/obfs 等 `with_inbound_config` 不覆盖的字段因此不丢） |
| `xray-core/src/inbound.rs:5787+` `parse_hysteria_inbound_config` | 解析 `users[]`（`clients` 非 nil 整体覆盖 users，Go hysteria.go:52-54 同口径；auth 缺失/空 → 硬错）；返回三元组 `(config, factory, users)`；**`auth` + `users[]` 并存 → 配置期硬错**（互斥） |
| `xray-core/src/inbound.rs:3440-3468` | `HysteriaUserManager(Arc<MultiUserValidator>)` + `impl ApiUserManager`（4 方法；add_user 消费 gRPC 入口规范化后的 `{"auth":…}` JSON——Go server.go:62-65；get_user/list_users 经 `list()` 回 proto User 含 level） |
| `xray-core/src/inbound.rs:4624-4634` | `register_hysteria_user_manager(api, tag, validator)`——仅 users[] 形态登记；单 auth 不登记（`NotUserManager` 显式拒绝，ss2022 单用户同款口径） |
| `xray-core/src/arm_builders/inbound.rs:621-665,1502` | `build_hysteria_inbound` 增加 `api` 参数；users → `MultiUserValidator::from_users` → `.with_multi_validator(...)` + `register_hysteria_user_manager(...)`；`hysteria_entry` 透传 `ctx.api` |
| `xray-core/src/inbound.rs` `user_manager_wiring` 测试 | 新增 3 测试：users[] 注册 + adu/rmu 立即生效（gRPC 同一规范化路径）、单 auth → NotUserManager、auth+users 互斥硬错 |
| `xray-proxy-hysteria/tests/users_e2e.rs`（新） | 真实 QUIC 回环 ×2：多用户 add/remove 立即生效（seed 连+往返 → adu 新用户连+往返 → rmu 后拒）+ 单 auth 回归 |

Rule 结构未动；`MultiUserValidator` 既有 add/remove/get/count 语义不变（仅值类型升级）；跨票
说明：`inbound.rs`/`arm_builders/inbound.rs` 同时含 SliceWire（zb2ee quic 白名单 + 5 处机械
解阻塞）的在途改动，已逐 hunk 核对归属（本票：parse users[] + HysteriaUserManager + register
helper + arm 接线 + 3 测试），`git diff --numstat` 无行尾重写（582/9 与 23/8，量级正常）。

## §5 端到端证据

**A. crate 级真实 QUIC 回环**（`cargo test -p xray-proxy-hysteria --test users_e2e`，2/2 PASS）：

```
test multi_user_add_remove_takes_effect_on_next_connection ... ok
test single_auth_still_works_without_validator ... ok
```

- seed 用户连接 + `ping`→`ping` 往返 ✓
- `validator.add`（= `api adu` 落点）后 **tok-2 立刻能连** + 往返 ✓
- `validator.remove`（= `api rmu`）后 **tok-2 新连接立刻被拒** ✓
- 单 auth 形态（无 multi_validator）照常连接 + 往返 ✓

**B. 真实二进制互通**（脚本 `fix/scripts/wave7hyst_users_go_interop.py`，**3/3 PASS**）：

```
===== 1. Go client(seed) -> Rust server(users[]) =====
[seed curl rc=0] HELLO-FROM-ECHO
===== 2/3. adu(rust api) -> Go client B(tok-2) -> rmu -> reject =====
[adu rc=0] processing inbound: hyst-in
add user: u2@x
result: ok
Added 1 user(s) in total.
[adu'd curl rc=0] HELLO-FROM-ECHO
[rmu rc=0] remove user: u2@x
Removed 1 user(s) in total.
[post-rmu curl rc=56]
[post-rmu] 连接被拒（符合预期）
===== 4. 单 auth 形态：数据面回归 + adu 显式 NotUserManager =====
[single-auth curl rc=0] HELLO-FROM-ECHO
[adu on single-auth rc=0] processing inbound: hyst-in
add user: y@x
rpc error: code = FailedPrecondition desc = proxy is not a UserManager
Added 0 user(s) in total.
```

- 相位 1：**Go xray 客户端二进制**（socks → hysteria outbound）↔ Rust 服务端（users[]），
  curl 经隧道拿到 echo 响应（数据往返）。
- 相位 2：**Go `xray api adu`**（真实 gRPC AddUserOperation，proto Account 经
  `account::normalize_user_account` 规范化——bd c89uy 链路）加 tok-2 → 新 Go 客户端实例
  （auth=tok-2）**立刻能连**。
- 相位 3：**Go `xray api rmu`** 移除 → 重启连接（新 QUIC）→ **rc=56 空响应（立刻拒）**。
- 相位 4：单 auth 形态数据面回归 OK；`api adu` 打到单 auth 入站 → **`proxy is not a
  UserManager`**——票面点名的错误现在只出现在「确实没有用户面」的形态上（接线前 hysteria
  全体形态都报它）。

**C. Rust 用户面单测**（`cargo test -p xray-core --lib user_manager`，10/10）：注册面
（users[] 起站即注册）、adu 后 `get_user` 含 level=3 回程、rmu 后查无 + 重复删显式错、
单 auth → NotUserManager、auth+users 互斥硬错。

## §6 Go 互通

真实 Go 二进制（`D:/tmp/go2617/xray.exe` 26.10.17）双向场景全通过（§5.B 3/3）：
Go 客户端 hysteria2 ↔ Rust 服务端 users[] 多用户（seed 与 adu 新用户两种凭据均数据往返），
Go api 客户端 adu/rmu ↔ Rust `HysteriaUserManager`。wire/auth 协议面本票零改动
（只换 validator 实例与配置解析），与 32/32 基线 hysteria 互通一致。

诊断副产物：裸 freedom outbound 缺 `settings.finalRules=[{action:allow}]` 时 final rule
默认 blackholing，会**伪装成数据面不通**（本票 e2e 首跑即踩；FREEDOM-FINALRULES 坑约束
早有登记，脚本两份服务端配置已带该行）。

## §7 反证

- **反证 A（票面点名）**：单 auth 形态（无用户面）`api adu` → `proxy is not a UserManager`
  （相位 4 原始输出）。这不是缺陷——它锁定「无用户面的形态显式拒绝」这一边界；接线前的
  hysteria 是**所有形态都报这个错**（含 users[]），相位 2 证明 users[] 已通。
- **反证 B（in-crate）**：`config_time_hysteria_single_auth_has_no_user_manager`——
  单 auth/Recording 形态下 `rt.user_manager(tag)` = `Err(NotUserManager)`。
- **反证 C（接线摘除等价）**：把 `register_hysteria_user_manager` 调用摘掉 ⇒
  `config_time_hysteria_users_inbound_registers_and_hot_updates` 红（断言
  `user_manager(tag).is_ok()`）。
- **反证 D（互斥）**：`auth`+`users[]` 并存 ⇒ `start_inbound` 硬错
  `config_time_hysteria_auth_and_users_are_mutually_exclusive`。

## §8 门禁

环境：`CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-Wave7Hyst` + `BORING_BSSL_PATH`
（预构建 btls）+ `PROTOC` + `LIBCLANG_PATH`。

| 门 | 命令 | 结果 |
|---|---|---|
| test | `cargo test -p xray-transport-hysteria -p xray-core --all-targets` | **transport-hysteria 123 passed(2 ignored) / xray-core lib 538 passed(2 ignored) + 集成 5 passed / 0 failed** |
| test | `cargo test -p xray-proxy-hysteria --all-targets` | **73 lib + 12 plugin_contract + 2 users_e2e + 3 e2e(1 ignored) 全绿** |
| test | `cargo test -p xray-core --lib user_manager` | **10/10**（含 3 个新增 hysteria 用例） |
| clippy | `cargo clippy -p xray-proxy-hysteria -p xray-transport-hysteria -p xray-core --all-targets -- -D warnings` | **Finished，零告警** |
| fmt | `cargo fmt -p xray-proxy-hysteria -p xray-transport-hysteria -p xray-core -- --check` | **0 diff**（FMT_CLEAN_OK；`--numstat` 复核无行尾重写） |
| 真互通 | `python fix/scripts/wave7hyst_users_go_interop.py` | **3/3 PASS**（基线互通 / adu 立即生效 / rmu 立即拒 + 单 auth 显式拒绝） |

**改动面确认（`git diff --stat`）**：`xray-proxy-hysteria/src/{config,inbound}.rs` +
`xray-core/src/{inbound.rs,arm_builders/inbound.rs}` + 新测试文件。
`crates/xray-transport-hysteria/**` 的 diff 属并行代理在途改动（本票未触碰该 crate）。
未引入依赖。未 commit。

## §9 残余风险

1. **`auth` 单串是本仓扩展形态**（Go 无此字段）：保留供存量配置；已在配置层与 users[]
   互斥硬错。若 PM 决定完全对齐 Go（删单 auth 形态），另票（涉及 32/32 基线配置面）。
2. **单 auth 形态无用户面**（NotUserManager）：与 Go「users[] 是唯一形态」一致；需要热更
   用户的部署应迁移到 users[]。
3. **`get_user/list_users` 的 level 来自 users[] 配置项**：hysteria validator 不参与
   level 路由（Go 同），level 仅作元数据回程。
4. **Go 客户端 TLS**：e2e 用 `pinnedPeerCertSha256`（allowInsecure 已在 26.10.17 移除）；
   自签证书部署面需同步该配置。
5. **masque 不在本票**（仓内无该 crate，票面已注明另说）。
6. **未跑 workspace 全量**：改动面 = proxy-hysteria + xray-core（inbound.rs 与 arm_builders，
   与并行代理共树、逐 hunk 核对过归属）；workspace 全量归 PM 收口门。
7. **知识图谱**：`index_status` 落后，未重建（40+ 并行代理在改树，收口统一重建）。

## §10 收尾

- 构建目录 `target-Wave7Hyst`（32G）**已删除**。复跑互通需重编
  （`cargo build --release -p xray-cli`，实测 ~10-13 分钟）后
  `XRAY_RUST_BIN=<release> python reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7hyst_users_go_interop.py`。
- 沉淀：无新增通用经验（freedom finalRules 坑 FREEDOM-FINALRULES 坑约束已登记在案，
  本票只是按图索骥）。

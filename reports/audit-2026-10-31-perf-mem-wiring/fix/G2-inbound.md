# G2 inbound 面 修复报告（9 票）

基线：`feature/fix-inbound-parity` @ `5fe98b90`（工作区起始干净，只有 reports/ 未跟踪）。

## 验收状态一句话

**代码全部落地；编译验证状态（截至收工）**：
- `cargo check -p xray-core --lib` ✅ Finished 零错误；
- `cargo check -p xray-proxy-ss -p xray-proxy-anytls -p xray-proxy-trojan -p xray-app-router -p xray-app-commander --all-targets` ✅ Finished 零错误（覆盖全部新写测试的编译）；
- `xray-core --all-targets`（含测试目标）被**并行组阻塞**：G3 在途的 `xray-app-dispatcher` lib `unused import net::SocketAddr`（deny(warnings) 即 error）+ 早前 `xray-proxy-freedom/src/udp.rs` 两处错误，均非本组文件。reality-trojan 测试点（`inbound.rs:8788`）已随签名同步改共享 validator，但该文件测试目标未能在阻塞解除后复跑。

**测试与端到端一条都没跑**（无 `cargo test` 执行、无真实二进制）。

## 逐票

| 票 | 状态 | 改了什么 | 验证 |
|---|---|---|---|
| u4efe | 代码 DONE / 验证部分 | `xray-proxy-ss/src/config.rs:344` `from_proto` 空口令 → `SsError::EmptyPassword`（唯一入口，prod/plugin/API 三条路全覆盖）；`xray-proxy-ss/src/server.rs` 新增 `PrefixedReader`(Go `FullReader`)+`read_request_multi`（读 50B → `validator.get` 逐用户匹配 → 回放字节 → 走原 `read_request`）；`inbound.rs` `handle_conn` 改用 multi 路径（不再 `get_all()[0]`）。新增 2 个测试（空口令拒 + 双用户各握手） | 编译：ss crate 全绿（bg_548）。测试未跑 |
| zmpxy | 代码 DONE | `inbound.rs`：`DOKODEMO_UDP_MAX_SESSIONS=4096` + `dokodemo_udp_admits()` 准入门（新 peer 满表丢包、既有 peer 不受影响）+ 每 peer 队列 64→16（`DOKODEMO_UDP_PEER_QUEUE`）；空闲 TTL 60s 原已存在 | 纯代码；容量门测试**未写**（预算耗尽） |
| ym0z8 | 代码 DONE | `start_inbound`：同 tag 去重与登记**同一把写锁内**（`get` 复查 + `insert`），输家返回 `ErrorKind::AlreadyExists`（消息仍 `existing tag found: <tag>`）；spawn 期被取消 → 摘 slot + `ErrorKind::Interrupted`；sniffing 非法 → pre-spawn 回滚 | 并发 20 次测试**未写**；`functions.rs:619`（G1 面）仍把 io error 映射成 `ListenSocketFailed`，**全量统一 ExistingTag 需 G1 配合改一行**（见遗留） |
| bz800 | 代码 DONE | `AnytlsInboundHandler::start`：password `None`/空串 → `InboundError::ListenError("anytls inbound requires settings.password …")`（生产 builder 起不来 = 拒启）；测试 `handler_without_password_allows_connection` 反转为 `handler_without_password_rejects_start`；测试基准 handler 补口令 | 编译未验证（在 hl8q6 批次内仍绿过）；测试未跑 |
| hl8q6 | 代码 DONE（hysteria 除外） | `inbound.rs` 新增 5 个 `ApiUserManager` impl（vless/vmess/trojan/ss2022-multi/wg）+ `register_*_user_manager`；`arm_builders/inbound.rs` 四个 builder 加 `api` 透传 + 注册行；trojan validator 改由装配层构造共享（trojan crate `serve_trojan` 签名换 `Arc<Validator>`，core `serve_reality_trojan` / `trojan_transport_on_conn` / UDS 同批换；`ss2022/MultiUserInbound` 新增 `user_emails()`） | **编译未验证**（被 G3 挡）；e2e（adu→新 uuid 握手）**未跑**；hysteria 按 PM 裁决只记账 |
| vdl95 | 代码 DONE | ①`spawn_one_inbound` 未命中 ctor → `Err(InvalidInput, "unknown inbound protocol: <kind>")`（旧 warn+skip）；②wiring：新增 `try_sniffing_request_from_json`（rule 解析/编译/资产加载/整表空 → Err），`per_inbound_ohm` 改 Result 上抛 → 拒启；排除表 `build_domain_excluder`/`build_ip_excluder` 逐条失败改硬错；sniffing 段类型不符也硬错；无 Result 面的旧 `sniffing_request_from_json` 失败退化为**全关嗅探** + `error!`（fail-safe 方向）。测试：`sniffing_exclusions_bad_rule_skipped_others_kept` 反转为 `..._hard_error`；registry 生命周期测试的 unsupported-kind 段反转 | masque 按票面不做（55yh7） |
| 9c8k6 | 代码 DONE（三处） | ①`Router::reload_rules(config, should_append)` 按 Go `ReloadRules` 重写（false=整体替换含 balancer 映射，true=追加 + 跨批 ruleTag 去重）；`RoutingService::add_rules` 新增；②`grpc.rs add_rule` 解 `xray.app.router.Config`（校验 type_url）+ 传 `should_append`，CLI `build_rule_typed_message` 改走 `xray_core::wiring::parse_routing_json_to_proto`（公开化）+ prost 编码，`source-ip-block` 同路径；③`register_user_manager` 改 `get_mut` 就地写（不复活已删 tag） | 新增 router reload 两测试、commander 两测试改 Config 载荷 + 类型不符 InvalidArgument；④AddOutbound 按票面不碰（G1） |
| il9lh（TPROXY 段） | 代码 DONE | `FakeResponderCache`：`FAKE_RESPONDER_CACHE_CAP=256` + LRU（命中搬队尾，满则逐队首并关 fd）；`#[cfg(linux)]` | Windows 不可跑；**无测试**（需 CAP_NET_ADMIN），给代码证据 + 标 Linux e2e |
| p45qd | 代码 DONE | 对照 Go：`stream.go:257/:434` + `packet.go:157` 均硬编码 `diff > 30`、**无配置项** → 不自造配置面；`ss2022/inbound.rs` 三处 `30` 收敛为 `TIMESTAMP_TOLERANCE_SECS`（唯一来源） | 语义零变化，无新测试 |

## 遗留（必须交接）

1. **编译收尾**：`xray-core --all-targets`（测试目标）待 G3 的 dispatcher/freedom 在途坏态落地后复跑一次（我最后一个修的是 `inbound.rs:8788` reality-trojan 测试点 → 共享 validator，属简单镜像改动）。
2. **全部测试未跑**：至少需 `cargo test -p xray-proxy-ss -p xray-proxy-anytls -p xray-app-router -p xray-app-commander -p xray-core --lib`；新写测试（ss 空口令/多用户、anytls 拒启、sniffing 硬错、router append/replace）应全绿。
3. **端到端全部未做**：ss 空口令拒启、ss 双用户连通、anytls 无口令拒启、未知协议拒启、并发 AddInbound、vless/vmess/trojan add-user 后真握手——均未跑。
4. **AddInbound 错误码统一**：`crates/xray-core/src/functions.rs:612-619`（G1 面）需把 `ErrorKind::AlreadyExists` 映射为 `ProxymanError::ExistingTag`，否则并发输家仍是 Internal。
5. **用户管理载荷约定 = JSON**（`account.value` = 该用户配置项 JSON，与 CLI `extract_users_from_inbound` 同源），**不是 Go 的 protobuf `xray.proxy.X.Account`**：Go 客户端调 `adu` 会解不动 → 需单独票做 wire 对齐。
6. `get_user`/`list_users` 只回 email+level（不吐凭据）；ss2022 单用户/中继 + hysteria 仍是 `NotUserManager`（hysteria 需 G8 改 `config.users` 为共享句柄）。
7. **ss 不打 `shadowsocks inbound listening` 日志未定位**：静态读代码该行在非 transport 分支必经（`tcp` 不在 `is_transport_listener_protocol` 名单），与 trojan `:292` 同 loglevel 同写法；审计侧两次复现的原因需用新二进制复跑才能定论（疑与审计脚本的日志截取窗口有关）。**未修**。

## 越界自查（文件面）

本组改动文件（`git status --porcelain` 待 PM 复核）：
- `crates/xray-core/src/inbound.rs` ✅
- `crates/xray-core/src/wiring.rs` ✅
- `crates/xray-core/src/arm_builders/inbound.rs` ✅（PM 已批准扩面）
- `crates/xray-proxy-ss/src/{config.rs,error.rs,server.rs,inbound.rs,ss2022/inbound.rs}` ✅
- `crates/xray-proxy-anytls/src/inbound.rs` ✅
- `crates/xray-proxy-trojan/src/server.rs` ✅（PM 已批准扩面）
- `crates/xray-cli/src/commands/api_exec.rs` ✅
- `crates/xray-app-commander/src/grpc.rs` ✅
- `crates/xray-app-router/src/{router.rs,command/mod.rs}` ✅
未触碰：`outbound.rs` / `functions.rs` / `register.rs` / `freedom/**` / `udp_session.rs` / `xray-mux/**` / `xray-transport-splithttp/**` / `xray-tls/**` / `tests/` / `.github/workflows/` / `xray-buf/src/alloc.rs` / `vendor/` / `dist/` / `protos/`。

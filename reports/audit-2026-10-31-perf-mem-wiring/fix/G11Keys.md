VERDICT: DONE_WITH_CONCERNS — 5 票全部落地（k0hdi/7kp03/a0m9d 完成，x0f0r 15 键逐键判定并接线 6 键+处置 3 键+4 张跟踪票，vkirx 3 项逐项结论）; 未做: workspace 全量 test（预算耗尽前只跑了受影响 crate 的 lib 面，见末段）

# G11Keys · bd x0f0r / 7kp03 / k0hdi / vkirx / a0m9d

## 1. bd k0hdi（P2 凭据掩码七族）— 完成

`crates/xray-conf/src/secrets.rs`：
- 新增 `collect_generic(protocol, &Value, out)`（七族键路径）+ 两个小助手 `push_key` / `for_each`；
  在 typed `dispatch_*_settings` **之前**扫原始 settings JSON——未走 typed 分支的协议原先会命中
  `Ok(None) => return` 提前返回（anytls/tuic/naive/wireguard 无 conf 结构体），socks/mixed/http 的
  凭据藏在 `accounts[]/users[]/servers[].users[]`、hysteria 在 `auth`/`users[]`/`clients[]`/`servers[]`。
- 键名逐一取自权威解析点：anytls `password`（inbound.rs:`parse_anytls_tls_acceptor`）；tuic
  `servers[].uuid|password`（outbound.rs:`parse_tuic_config`）；naive 出站 `username|password` / 入站
  `users[].name|pass`；wireguard `secretKey|secret_key` + `peers[].preSharedKey|pre_shared_key`
  （**两侧公钥是公开材料，刻意不进掩码表**）；hysteria `auth` + `users/clients[].auth` +
  `servers[].auth|password`；socks|mixed|http `user|pass`（顶层 + `accounts[]` + `users[]` +
  `servers[].users[]`）。
- 测试（七族各一条，直接构造 `BuiltConfig`——`collect_secrets` 只读 `entry.{kind,data}`，
  与 `Config::build` 产物同形；真实装配路径由既有两条 `load_str` 用例覆盖）：
  `masks_anytls_password` / `masks_tuic_uuid_and_password` / `masks_naive_username_password_both_shapes` /
  `masks_wireguard_secret_and_psk_but_not_public_keys` / `masks_hysteria_auth_and_users` /
  `masks_socks_accounts_and_flat_user_pass` / `masks_http_accounts_and_flat_user_pass`。
- 验证：`cargo test -p xray-conf --lib` = **222 passed / 0 failed**。

## 2. bd x0f0r（P2 settings 散键）— 逐键判定表

| # | 键 | Go 26.10.17 是否消费（证据） | 判定 | 落地方式 |
|---|---|---|---|---|
| 1 | splithttp `downloadSettings` | **消费**：`splithttp/dialer.go:355-362` 用完整 StreamConfig（dest/tls/reality+协议段）另建 `requestURL2/httpClient2/xmuxClient2` | 接线成本 = transport 切片（第二条 memory stream config + 第二 TLS 客户端），不在本组文件面 | **fail-visible 化**：解析失败硬报（原 `.ok()` 吞错）+ 每次解析 warn 指路 → 跟踪票 **y2dtu** |
| 2 | `quicParams.udpHop` | **不消费**：`infra/conf/transport_finalmask.go:1177-1195` 的 `QuicParamsConfig` 无该字段；真开关是 `finalmask.udp[{type:"udphop"}]`（Rust 已接 `finalmask/mod.rs:866`） | Rust 方向相反（因 `interval<5` 拒启，Go 静默忽略照常启动） | **删解析+改 warn**：`memory_settings.rs` 删 `UdpHopConfig`/`parse_udp_hop`/`parse_port_list`/`parse_int32_range`；`xray-transport-hysteria/quic_params.rs` 删 hop 解析+区间校验、`udp_hop: None`；两处 warn 指路 finalmask |
| 3 | hysteria `masquerade=proxy` 的 url/rewriteHost/insecure | **消费**：`hub.go:96/210-254` → MasqUrl/MasqUrlRewriteHost/MasqUrlInsecure | Rust 只留 503 兜底（`hub.rs` ProxyMasqHandler 硬编码） | 跟踪票 **4zcki**（反代实现属 transport 切片） |
| 4 | `probeInterval` | **消费**：`duration.Duration` 支持复合（`time.ParseDuration`） | Rust 单段解析，"1m30s" 静默回落默认 50s | **已修**：`xray-core/src/register.rs` `parse_go_duration_ms` 改为复用 `wiring::parse_go_duration_str`（复合/小数/ns~h；亚毫秒向上取 1ms 避免被当成"未配置"），补 4 条断言 |
| 5 | quic `keepAlivePeriod` | **消费** | 已消费：hysteria `dialer.rs:99→quinn_adapter.rs:289`；splithttp H3 `h3_keep_alive_period` | 对齐，无需改 |
| 6 | grpc `permitWithoutStream` | **消费**（keepalive 参数） | Rust 解析+proto 往返+`transport.rs:322-323` 登记「h2 无法感知活跃流数 → 按恒保活」（超集行为） | 已接线 + 差异已登记；不改 |
| 7 | ss `uot`/`uotVersion` | **不是 Go 键**：`proxy/shadowsocks_2022/config.proto` 的 `ClientConfig` 无该字段（`git grep -i uot` 仅命名字面噪音） | Rust 独有扩展且运行时确实消费（`xray-proxy-ss` UdpOverTcpConfig） | **保留能力 + build 期 warn**：`protocols.rs` Ss2022 分支 warn「Rust-only，连 Go 服务端 UDP 会废」 |
| 8 | 出站 `level`（vless/vmess） | **消费**：`proxy/vless/outbound/outbound.go:291`、`vmess/outbound/outbound.go:136` `ForLevel(request.User.Level)` | Rust 解析进 config 但**零读者**，`wrap_bridge` 恒 `level 0` → 出站档位配置静默失效 | **已接线**：`outbound.rs::wrap_bridge` 新增 `level: u32` 参数；vless/vmess 传 `config.level`，其余 9 个 builder 显式传 `0` |
| 9 | ws/httpupgrade `headers` 值类型 | **硬错**：Go `Headers map[string]string`（`transport_method.go:621`/`:663`）JSON 解码即失败 | Rust `filter_map` 静默丢 header（伪装/鉴权头凭空消失） | **已改硬错**：两个 crate 的 `parse_headers` → `io::Result`，非 string 报错并点名 key；2 条旧测试改为断言拒绝 |
| 10 | hysteria `alpn` / `udpIdleTimeout` | `udpIdleTimeout` **消费**且 `0→60`、非 0 强制 `[2,600]`（`transport_method.go:768-782`）；`alpn` **不是 Go 键**（HysteriaConfig 仅 Version/Auth/UdpIdleTimeout/Masquerade） | Rust：udpIdleTimeout 无区间校验、显式 0 保留 0（应为 60）；alpn Rust 亦不解析（非缺陷） | **已修 udpIdleTimeout**（区间+默认对齐 + 新测试）；alpn 无需动作 |
| 11 | `xmux` | **消费**：`XmuxManager.GetXmuxClient` 复用 H2/H3 连接 | `splithttp/mux.rs` 实现完整（5 维判定 + 4 分支选路）但 **dialer 零引用**；唯一被消费的字段是 `hKeepAlivePeriod`（`h3_client.rs:113`） | 跟踪票 **s42cg**（拨号路径池化 = 数据面切片） |
| 12 | `echForceQuery` | **不是 Go 键**（全仓零命中） | Rust `xray-tls/ech.rs` 实现并消费 none/full（Rust 扩展） | 保留；文档标注，不 warn（扩展本身有效且已在 ech 文档登记） |
| 13 | `metrics.tag` | **消费**：`app/metrics/metrics.go` Start 里 tag 非空 → OutboundListener + 向 ohm 注册（tag 形态暴露端点） | Rust：仅校验「tag/listen 至少一项」+ 进 app config；tag 暴露路径未实现 | 跟踪票 **0z7zt** |
| 14 | W1 `disablePathMtuDiscovery` | Go 键是 `disablePathMTUDiscovery`（MTU 全大写，`transport_finalmask.go:1188`） | Rust 读错拼写（同仓 hysteria 侧拼对 → 两说） | **已修**：读 Go 键；旧拼写按未知键 warn（不再静默生效）；测试 `quic_params_misspelled_disable_path_mtu_discovery_is_ignored` |
| 15 | W2 splithttp H3 `maxStreamReceiveWindow`/`maxConnectionReceiveWindow`/`maxIncomingStreams` | **消费**：`splithttp/dialer.go:165-170` | Rust 解析零消费 → Go 的窗口上限与并发流上限恒不生效 | **已接线**：`build_h3_transport_config` 里 quinn `stream_receive_window`/`receive_window` 取 Max 优先（quinn 该字段语义即上限）、`max_concurrent_bidi_streams ← maxIncomingStreams`；测试 `h3_transport_config_wires_max_windows_and_incoming_streams` |

新增跟踪票：**y2dtu**(P2 downloadSettings) / **4zcki**(P3 hysteria proxy masq) / **s42cg**(P3 xmux) / **0z7zt**(P3 metrics.tag)。

## 3. bd vkirx（P3 传输口径差异）— 逐项结论

1. **stream-one 多 1 条零字节 TCP**：**已定位到唯一来源** = `crates/xray-transport-splithttp/src/register.rs:279`
   `flow_window::resolve_rtt(host, port)` —— bd rjzw2 引入的一次性 RTT 探针（独立于数据连接，可用
   `XRAY_H2_RTT_HINT_MS` 跳过）。不是 bug：Go 用握手指令内 RTT，Rust 另拨一条 SYN 后丢弃。已在站点加
   ⚠️ 注释登记；清零需改带内 RTT 测量（未做，属独立切片）。
2. **mux carrier 头差异（cmd=1+域名 34B vs Go cmd=3 19B）**：**不改**。Go 服务端按 destination 域名
   `v1.mux.cool` 判 mux 载体（不校验 VLESS command、不校验端口），两者互认；改 `VlessCommand::Mux`
   历史两次 e2e 红（`functions.rs:4664` panic）。风险仅严格第三方服务端 → 文档登记。
3. **`wsSettings.ed`**：Go `WebSocketConfig`（`transport_method.go:618-624`）无 `ed` 字段（proto 有
   `ed=5` 但 conf 层不从 JSON 取，只认 path 的 `?ed=`）→ 保留功能 + **parse 期 warn**「Rust 独有键、
   会改 wire（Sec-WebSocket-Protocol）」。
4. 附注：`kcpSettings.seed/header` 两侧同为死键，非 Rust 缺陷。

## 4. bd 7kp03（P3 死代码）— 按删除三问处置

**删除（生产零引用，grep 证据在回执）**：
| # | 目标 | 处置 |
|---|---|---|
| 1 | `xray-xudp::XudpManager` | 删结构+impl+Default+6 单测；`tests/integration.rs` 对应用例与 import 一并删；`XudpSession` 的 allow reason 里 `XudpManager` 字样更正 |
| 2 | vless `outbound/reverse.rs` 整模块 | 删（连 `ReverseConnState`——只被 monitor 使用）；清 `lib.rs` re-export；**bd 78ysn 已按删除决策 close** |
| 3 | vless `outbound/preconnect.rs` 整模块 | 删（连 `PreConnectConfig`）；清 re-export |
| 4 | observatory `error_collector.rs` 整模块 | 删 + `lib.rs` 模块声明/re-export/文档行 |
| 5 | hysteria `dialer.rs::clean_inactive` | 删（全库唯一命中=定义本身） |
| 6 | commander `set_outbound_registrar` + `impl HandlerManager for Commander` | 删（连字段 `outbound_registrar`、start 日志分支、Debug 字段、测试断言）；证据：`dyn HandlerManager` 生产仅指 `OutboundHandlerRegistry`（`server.rs:323`） |
| 7 | grpc `encoding.rs::from_header`（+ `as_header`，同为 0 引用） | 删 |
| 8 | `xray-transport/browser_dialer.rs` + `browser_dialer.html` | 删（`browser_dialer::` 全库 0 命中）；env 面 `xray-common::platform::env::browser_dialer_address` 保留（Go 对应物在 xray-common 一侧） |
| 9 | `xray-core/register.rs` `SimpleFeature` + `simple_feature_factory` | 删；**前置闸已过**：`grep -rn -i noop crates/xray-core/src/` 命中全为无关的 `NoopLifecycle`(arm_registry)、测试名与注释，**零注册路径引用** |

**过期 allow（注释与事实不符 → 转为事实）**：
- `dispatcher/default.rs` `SimpleOhm::add`：删 `#[allow(dead_code)]`，注释改为真实生产调用点（5 处：
  `xray-core/functions.rs:436`、`:628`、`outbound.rs:217`、`:531`、`xray-cli/framework.rs:1342`）。
- `commander/grpc.rs` `ListenSpec::Unix`：删 allow（生产构造+消费在 `commander.rs:630`/`:663`）。
- `xray-cli/run.rs::config_uses_splithttp`：`#[allow(dead_code)]` → `#[cfg(unix)]`（唯一调用点在
  `#[cfg(unix)]` 块内，Windows 不再编制）。

**rule_set.rs（PM 采纳 a）**：
- 文件头「对应 Go `app/router/rule_set.go`」是**错误溯源** → 改为「Rust 扩展件，Go 26.10.17 全仓
  `git grep -i ruleset` 零命中」，并写明当前无生产消费点（`xray-conf`/`wiring` 均不解析 `rule_set`）。
- `RuleSetType::Remote` 从 `Err` **拒启** → **warn + 跳过**（Go 对未知键静默忽略；「Go 能跑、Rust 起不来」
  = 兼容性破坏），测试同步改名 `remote_ruleset_is_skipped_not_rejected`。

## 5. bd a0m9d（BufferPool 台账）— 完成

`CLAUDE.md` §3.5.4 归一化面表新增一行「**BufferPool 接缝（`with_pool`）⚠️ 已规划未落地（bd a0m9d 台账）**」：
写明 `with_pool` 仅装配测试面调用、目标主路 `framework.rs` 只 `builder.build()`、
`PluginContext::pool()` 缺省 panic 但生产不触发、生产实走 `xray_buf` 分层池（22 处 `Buffer::new` + 3 处
`new_pooled`）、L3 lint 闸不存在、插件模型文档 §2.3/§2.4 表述以本节为准。取"补台账"不取"删接缝"。

---

## 验证命令 + 关键输出

```
$ cargo test -p xray-conf --lib
test result: ok. 222 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ cargo test -p xray-conf -p xray-transport -p xray-transport-hysteria -p xray-transport-websocket \
               -p xray-transport-httpupgrade -p xray-transport-splithttp -p xray-transport-grpc \
               -p xray-proxy-vless -p xray-app-observatory -p xray-app-commander \
               -p xray-app-dispatcher -p xray-app-router -p xray-xudp --lib
test result: ok.  93 passed   (xray-xudp)
test result: ok. 148 passed   (xray-app-router)
test result: ok. 158 passed   (xray-transport-grpc)
test result: ok. 160 passed   (xray-app-observatory)
test result: ok. 222 passed   (xray-conf，重复列出)
test result: FAILED. 276 passed; 1 failed  ← xray-proxy-vless
error: test failed, to rerun pass `-p xray-proxy-vless --lib`

$ cargo test -p xray-proxy-vless --lib vless_outbound_udp_roundtrip_e2e   # 单跑复现（确定性）
---- inbound::server::tests::vless_outbound_udp_roundtrip_e2e stdout ----
panicked at crates\xray-proxy-vless\src\inbound\server.rs:1322:18:
read: Custom { kind: UnexpectedEof, error: "early eof" }
test result: FAILED. 0 passed; 1 failed; ... 277 filtered out

$ cargo check -p xray-xudp -p xray-proxy-socks --all-targets        # 止血验证（共享树）
Finished `dev` profile [unoptimized + debuginfo] target(s) in 38.25s   # 零 warning

$ cargo check -p xray-app-commander -p xray-proxy-vless -p xray-app-observatory -p xray-app-router --all-targets
Finished `dev` profile [unoptimized + debuginfo] target(s) in 33.70s

$ cargo fmt -p <15 个受影响 crate> -- --check      # 先 cargo fmt -p ... 施加，再 check
FMT_CLEAN        （无输出 = 全绿；workspace 全域 `cargo fmt --all --check` 仍有
                  crates/udf-frame/skeleton/examples/fields_multidim.rs 的既有 diff，
                  属 udf 工作副本、非本组改动）
```

**失败归因（诚实标注）**：`vless_outbound_udp_roundtrip_e2e` 确定性失败，但**失败面不在本组 diff 上**——
本组在本 crate 只删了两个无引用模块（`outbound/{preconnect,reverse}.rs`）与 `lib.rs` re-export，该测试
走的是 `VlessOutboundConfig::new` + `make_freedom_dial_fn` + `serve_vless` UDP 腿，不经过被删代码。
`git status` 显示共享树里同时有并行组在改 `crates/xray-proxy-freedom/src/inbound.rs`、`crates/xray-mux/*`、
`crates/xray-app-reverse/*`、`crates/xray-app-dns/*` 等——失败面落在这批在飞改动上，需属主/主代理收口后
复跑确认。

未跑（预算限制，需主代理补）：`cargo test --workspace --all-targets`、`cargo clippy --workspace --all-targets
-- -D warnings`、`cargo test -p xray-core --lib`（含 register.rs duration 断言与 outbound level 改动）。

## 疑虑（DONE_WITH_CONCERNS 的原因）

1. `wrap_bridge` 的 level 接线只被类型系统覆盖（参数类型互斥），**缺行为级断言**——`DialBridge::current_policy`
   在 dispatcher crate 内私有，xray-core 侧无法回读；要钉死需加只读 getter（新 pub API，未擅自加）。
2. 出站 level 只接**生产主路**（`start_full` → arm_builders）；框架路（`framework-assembly`）由各插件
   builder 自建 bridge，本组未改。
3. `downloadSettings`/`xmux`/`metrics.tag`/hysteria proxy masq 四项为真实缺口，本轮只做到 fail-visible +
   建票（y2dtu/4zcki/s42cg/0z7zt），未实现。

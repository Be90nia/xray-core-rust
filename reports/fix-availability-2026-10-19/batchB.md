# FixBatchB 交付报告（2026-10-19）

批次：B（proxy-vless/vmess/freedom/hysteria + xray-transport/dialer.rs + transport-tcp/register.rs + xray-core/outbound.rs）
五票：1wq8（vless UDP）/ uhg2（vmess UDP）/ i9b3（security 硬错）/ oomz（freedom finalRules）/ x2ci（hysteria 证书校验）

---

## 票 1wq8 — vless 出站 UDP 恒 Command::Tcp 【完成】

**改动**
- `crates/xray-proxy-vless/src/dispatcher.rs:307` dial 闭包提取 `let is_udp = dest.is_udp()`
- `crates/xray-proxy-vless/src/dispatcher.rs:321` establish_conn 传入 is_udp
- `crates/xray-proxy-vless/src/dispatcher.rs:350-358` establish_conn 签名加 is_udp；XRV flow + UDP 早失败（Go outbound.go:303-306 转 mux 未实现 / inbound.go:556 服务端拒——不静默按 TCP 发）
- `crates/xray-proxy-vless/src/dispatcher.rs:394` command 按 dest.network 写 `VlessCommand::Udp`（Go outbound.go:214-217）
- `crates/xray-proxy-vless/src/dispatcher.rs:435-440` 返回前包装 `VlessUdpFramedConn`
- `crates/xray-proxy-vless/src/dispatcher.rs:445-578` 新增 `VlessUdpFramedConn`：poll_write 每次调用=一包（wire `[2B BE len][payload]`，u16 上限截断）、poll_read 剥前缀按包交付（rview 两阶段缓冲：ReadBuf 满保留剩余不丢数据；EOF 半帧报 truncated）。对齐 Go `EncodeBodyAddons` UDP→`MultiLengthPacketWriter` / `DecodeBodyAddons` UDP→`LengthPacketReader`（proxy/vless/encoding/addons.go:66-83）；inbound `handle_udp_relay` 的 read/write_length_packet 消费同一 wire 格式。

**测试**
- `dispatcher.rs` 单测 `vless_udp_framed_conn_roundtrip`（wire 字节硬断言 + 读侧逐包还原 + EOF）
- `dispatcher.rs` 单测 `establish_conn_rejects_xrv_udp`（XRV+UDP 拒绝）
- `inbound/server.rs` e2e `vless_outbound_udp_roundtrip_e2e`：make_dial_fn(UDP dest) → serve_vless handle_udp_relay → FreedomDispatchBridge → UDP echo，双尺寸包往返

## 票 uhg2 — vmess 出站 UDP 恒 TCP 【完成】

**改动**
- `crates/xray-proxy-vmess/src/dispatcher.rs:231` 闭包提取 is_udp
- `crates/xray-proxy-vmess/src/dispatcher.rs:263-271` `Command::Udp` + `Network::UDP` 按 dest.network（Go vmess outbound.go:88-91）
- `crates/xray-proxy-vmess/src/dispatcher.rs:300-316` UDP 分支返回 `VmessUdpConn`
- `crates/xray-proxy-vmess/src/dispatcher.rs:424-623` 新增 `VmessUdpConn`（chunk 即 packet，Go 非 cone 语义）：上行 poll_write 一包一 chunk（`encode_single_chunk` 直写，不走 duplex 流桥——流桥合并 write 破坏 packet 边界）；下行 spawn task 惰性解响应头（Go SetFlushNext 同语义）+ 逐 chunk `decode_single_chunk_async` 解密，mpsc 队列交付；poll_shutdown 写终止 chunk
- `crates/xray-proxy-vmess/src/encoding/body_chunk.rs:442-451` `single_chunk_capacity`（单 chunk 明文容量，packet 截断预算）
- `crates/xray-proxy-vmess/src/encoding/body_chunk.rs:453-513` `decode_single_chunk_async`（读恰好一个 chunk；干净 EOF/终止 chunk → None）+ `encode_single_chunk`（复用私有 write_one_chunk，零新 wire 逻辑）

**测试**
- `dispatcher.rs` 单测 `vmess_udp_conn_write_boundaries`（写两包 → server 侧逐 chunk 解出恰好两包）
- `dispatcher.rs` 单测 `decode_single_chunk_packet_boundaries`（两 chunk wire 逐包解出 + 干净 EOF=None）
- `inbound/server.rs` e2e `vmess_outbound_udp_roundtrip_e2e`：make_vmess_dial_fn(UDP dest) → serve_vmess pump_udp_session → freedom → UDP echo 往返（反向复用 vmess_inbound_udp_relay_e2e 设施）

## 票 i9b3 — security 未知值/xtls 静默裸连 【完成】

**改动**
- `crates/xray-transport/src/dialer.rs:171-183` 新增 `StreamSettings::validate_security()`：`""/none/tls/reality` 合法（to_lowercase 归一，对齐 Go ToLower）；`xtls` → "Legacy XTLS has been removed..."（Go transport_internet.go:129-130 PrintRemovedFeatureError）；未知值 → `Unknown security "..."`（:131-132）
- `crates/xray-transport/src/dialer.rs:627-628` `dial()` 入口挂校验（覆盖全部 transport）
- `crates/xray-transport-tcp/src/register.rs:87-89` `wrap_security` 开头挂校验（原 `is_tls()==false → 裸连` 改为先验）
- 附带：`is_tls()` 同步归一（`"TLS"` 此前过校验仍会裸连的裂缝）

**测试**
- `dialer.rs` `validate_security_accepts_known_values` / `validate_security_rejects_xtls_and_unknown`
- 验收路径：security:"xtls" 配置 → dial()/wrap_security() 即返回 io::Error（Legacy XTLS removed），配置拒启/拨号报错

## 票 oomz — freedom finalRules 非法条目静默丢弃 【完成（含关键发现）】

**关键发现**：JSON→FinalRuleConfig 层（`xray-core/src/outbound.rs parse_freedom_config`）**已有**"单条非法 → 整出站拒启"硬错 + 既有测试（`parse_freedom_config_hard_errors`：mixed 合法+非法 finalRules → Err）。票面指的 `.ok()`（FinalRuleConfig→FinalRule 的 `FinalRule::build`）当前恒 Ok，属第二道防线。

**改动（防线收紧，防未来 build 加失败分支时回归静默）**
- `crates/xray-core/src/outbound.rs:707-716` `filter_map(build.ok())` → for 循环 `map_err(BuildError::Parse("freedom: failed to build final rule: ..."))?`（对齐 Go freedom.go:208-214 Init 硬错）
- `crates/xray-proxy-freedom/src/handler.rs:42-55` `FreedomHandler::new` → `Result<Self, String>`（同语义）；11 处测试调用点 `.expect("valid config")` 适配
- dialerProxy 场景（outbound.rs:699-706）：warn + 全忽略——与 Go freedom.go:193-198 一致，**已有**，未动；既有 e2e `freedom_final_rules_ignored_when_chained_via_dialer_proxy` 覆盖

**测试**
- 既有 `parse_freedom_config_hard_errors`（非法条目拒启）+ `freedom_final_rules_ignored_when_chained_via_dialer_proxy`（dialerProxy 忽略）覆盖验收两臂

## 票 x2ci — hysteria 出站证书不校验 【完成】

**改动**（票面行号 853-855 实际在 `xray-core/src/outbound.rs`，非 xray-proxy-hysteria crate——crate 内 NoVerifier 仅测试资产）
- `crates/xray-core/src/outbound.rs:1488-1520` 新增 `build_hysteria_tls_config(security, tls_json)`：security != "tls" → 硬错（Go transport/internet/hysteria/dialer.go:327-330 `tls.ConfigFromStreamSettings` nil → "tls config is nil"）；`insecure: true` → NoVerifier（显式信任决策）；缺省 → webpki-roots 真实验证
- `crates/xray-core/src/outbound.rs:851-868` 装配：stream_settings 提前、tlsSettings.serverName 覆盖 server_name、tls_config 经新函数

**测试**
- `outbound.rs` `build_hysteria_tls_config_validates_security_and_insecure`（""/reality/xtls 拒；tls+insecure/tls 缺省/TLS 大小写归一过）
- 真机自签证书连接失败 e2e **未写**（需起 QUIC server + 真 CA 体系，超出本批最小验证；配置层分支已单测覆盖）

---

## 验证（实测）

**编译**（env 按 CLAUDE.md §1，含 BORING_BSSL_ASSUME_PATCHED 等）：
```
cargo check -p xray-proxy-vmess -p xray-proxy-vless -p xray-core --all-targets
  → Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 59s
（xray-transport / xray-transport-tcp / xray-proxy-freedom 在同轮全量 check 中已 Checking 通过，
  唯一失败轮的报错均在本批 vmess/vless 代码内，已逐一修复；vendor rustls 2 warning 为存量）
```

**测试**：
```
cargo test -p xray-transport --lib validate_security
  → 2 passed; 0 failed (validate_security_accepts_known_values / validate_security_rejects_xtls_and_unknown)

cargo test -p xray-proxy-vmess --lib udp
  → 3 passed; 0 failed
    dispatcher::tests::vmess_udp_conn_write_boundaries ... ok
    inbound::server::tests::vmess_outbound_udp_roundtrip_e2e ... ok   ← 新 e2e（出站→入站→freedom→UDP echo）
    inbound::server::tests::vmess_inbound_udp_relay_e2e ... ok        ← 既有，无回归
cargo test -p xray-proxy-vmess --lib decode_single_chunk
  → 1 passed; 0 failed (decode_single_chunk_packet_boundaries)

cargo test -p xray-proxy-vless --lib udp
  → 19 passed; 0 failed，含：
    dispatcher::tests::establish_conn_rejects_xrv_udp ... ok          ← 新
    dispatcher::tests::vless_udp_framed_conn_roundtrip ... ok         ← 新
    inbound::server::tests::vless_outbound_udp_roundtrip_e2e ... ok   ← 新 e2e（出站→入站→freedom→UDP echo）
    vless_inbound_udp_relay_e2e / udp_relay_* / vless_inbound_rejects_xrv_udp_command ... ok（既有，无回归）

cargo test -p xray-proxy-freedom --lib
  → 77 passed; 0 failed（FreedomHandler::new 签名改动 + 11 处测试适配零回归）

cargo test -p xray-core --lib build_hysteria_tls_config
  → 1 passed; 0 failed (build_hysteria_tls_config_validates_security_and_insecure)
```

**并发复核：无外部覆盖**——Main 指令复核 `git diff`（9 文件 +945/-34）逐 hunk 核对，32 个 hunk 全为本批改动，无他人改动混入、无冲突；未触碰 xray-tls/*、sockopt/mod.rs、platform/*、grpc/splithttp/websocket/*。

**踩坑（供上级分流）**：
1. omp bash 带 `name=`（service mode）在本工作站走 WSL relay → `execvpe(/bin/bash) failed`（WSL 无 bash）；长任务应走普通调用（60s 后自动转后台 job）。
2. `Connection` trait（Send+Sync bound）下存 `Box<dyn SizeParser + Send>` 字段被 E0277 拒——非 Sync 的 ShakeSizeParserAdapter（内部 dyn XofReader）无法 widen，最小修法 = `parking_lot::Mutex<Box<dyn Trait + Send>>`；另 `&dyn Trait` 跨 `.await` 要求 `T: Sync`（引用的 Send 性来自目标 Sync）。rule://rust-trait-object 已有 Send+Sync 条目，此为 Connection-impl 场景变体，未重复沉淀。
3. `cargo test` 一次只接受一个 TESTNAME 过滤器，多过滤需分多条 &&。


## 未完成项 / 风险

1. **vless XRV+UDP**：Go 转 mux（v1.mux.cool），Rust mux 出站未实现 → 硬错（对齐 Go inbound 拒绝语义）。mux 落地后此路径需补。
2. **x2ci 真机自签验证未跑**（配置层单测覆盖分支；QUIC e2e 需真证书体系）。
3. **hysteria 既有配置兼容**：装配现要求 streamSettings `security="tls"`（Go 同语义）；未配 security 的存量 hysteria 出站配置将拒启——安全语义修复的预期行为变化。
4. **UDP packet > 8KiB（vmess）/ > 64KiB（vless）截断**：Go 同为 buf.Size 上限语义；UDP relay 常态包 ≤ MTU 不受影响。
5. **并行批次干扰**：本批 check 期间遇到 sockopt/mod.rs:451 瞬态语法错误（兄弟批次编辑中间态，FixBatchC 确认已消）；xray-core 编译还依赖批次 C 的 app-dispatcher/wiring 改动状态。

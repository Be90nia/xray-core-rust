# D-5 安全波实现报告（bd 7qcg / etj0 / u88f / lwep）

日期：2026-09-16 · 执行：impl-d5 · 基线：Rust HEAD 7a1acba / Go v26.9.9（D:/Project/Xray-core HEAD 52a412d9，xtls/reality@v0.0.0-20260908）

## 结论

**VERDICT: 4/4 票完成 — lwep 新增五臂校验+5 契约测试；u88f 补齐 lowercase+模糊匹配+3 契约测试；7qcg/etj0 判定 W3 已修复且测试覆盖完整（补验证无需补码）；REALITY 合法握手路径回归全绿。**

## 逐票

### lwep（VLESS flow 五臂校验）— 新增代码

**Go 前提（铁律①）**：`proxy/vless/inbound/inbound.go:552-598` 五臂实锤：账号不匹配拒(:588-590)、XRV+UDP 拒(:557-558)、XRV 须外层 TLS1.3/REALITY 直连(:571-581)、空 flow+XRV 账号+TCP 拒(:591-595)、未知 flow 拒(:596-598，Go 枚举全集={"", XRV})。校验在响应头写出前（:546 responseAddons 先声明后校验），失败=断连无响应、不走 fallback。

**改动**：
- `crates/xray-proxy-vless/src/inbound/server.rs`
  - 新增 `validate_flow()` 纯函数（O(1) 拒绝路径，防 DoS）
  - `VlessInboundOptions` 加 `outer_tls13: bool` 字段（derive(Default) 兼容，默认 false=拒）
  - `finish_vless_dispatch` 开头注入校验（响应头之前，两条入口路径汇合单点）
  - `serve_vless` TLS 分支查 `ServerConnection::protocol_version()==TLSv1_3` 注入
- `crates/xray-core/src/inbound.rs:2201-2207` REALITY Verified 分支恒置 `outer_tls13=true`（REALITY 验证通过=rustls TLS1.3，Go :577-579 不查版本语义）
- `crates/xray-transport/src/lib.rs:58-61` `pub use rustls;`（域外 1 行加法，让 proxy crate 免直依赖 rustls 查协商版本）
- 测试：5 个恶意契约测试（unknown-flow 手工 wire 字节/XRV+UDP/账号不匹配/空flow+XRV账号+TCP/裸TCP+XRV）；Vision 两测试改造（outer_tls13=true 显式注入 + spawn 床账号 flow 参数化）

**红绿证据**：修复前 `vless_inbound_rejects_unknown_flow` 等概念测试不可写（无校验点）；直接证据=挂掉的 `integration_vless_vision_over_tls_to_echo`——其原配置（服务端账号无 flow + 客户端发 XRV）在 Go 下同为非法部署，修复后服务端拒绝触发，改配置为合法 Vision 部署后全绿（这正是收紧生效的实锤）。

**Go 对齐注**：客户端 `encode_header_addons` 非 XRV 写空 addons 与 Go `EncodeHeaderAddons`（addons.go:18-34）完全一致——合法编码器发不出未知 flow，故 unknown-flow 测试用手写 proto wire 模拟恶意客户端。

**残余（防误伤红线取舍）**：Go :593 的 `isMuxAndNotXUDP` mux 分支未实现（需 mux 首帧解析），臂4 只覆盖 command==TCP；mux 维持放行不新增拒绝面。已留 ponytail 注释。

### u88f（Trojan fallback SNI/ALPN）— 补齐 Go 语义

**Go 前提**：`proxy/trojan/server.go:364-444` fallback 从 TLS ConnectionState 提取 name/alpn(:373-384)、lowercase(:385-386)、精确 miss 时 contains 子串最长匹配(:388-398)、逐级回退默认(:400-414)、path 从首 buffer 提取(:416-443)。

**现状核对**：票面指控 `decide("","","")` 仅命中独立 Handler 测试装配路径（无 TLS 层，与 Go 非 `*tls.Conn` 同空语义一致）；生产直连 TLS 路径（serve_trojan:431-437）已提取真实 SNI/ALPN，path 已提取（:514）。**真实缺口两处**：decide 缺 lowercase、缺模糊 contains 匹配（多规则配置静默降级的实锤）。

**改动**（`crates/xray-proxy-trojan/src/fallback.rs`）：
- `decide()` 查询侧 lowercase（Go :385-386；防恶意大写 SNI 绕过精确规则）
- `SniNode::get` 增加 `fuzzy_longest_match`：多规则或无默认时 contains 最长匹配（Go :388-398 条件 `len(napfb)>1 || napfb[""]==nil` 精确复刻）
- 3 个契约测试：大写 SNI 不绕过 / 子域模糊命中 / 最长匹配优先

**验证**：trojan crate 60/60 绿（含 5 个既有 decide 语义测试不回归）。

### 7qcg（REALITY shortIds fail-open）— 判定已修复（W3 29f5b87 落地）

**Go 前提成立**：`infra/conf/transport_security.go:135-147` 空数组拒启+单项>16 拒+非法 hex 拒。
**现状**：配置层三重硬错已在 `xray-core/src/inbound.rs:2059-2088` + `xray-transport-splithttp/src/transport.rs:248-274` 落地（空数组/缺失字段拒启、>16 拒、hex::decode 失败拒、合法项左对齐补零 8B）；低层 `crypto.rs verify_session_payload:296` 空白名单恒拒（`contains` 空=false→ShortIdNotAllowed，与 Go xtls/reality tls.go:270 map 查找语义一致）。
**覆盖证据**：`verify_reality_client_hello_short_id_not_allowed`(server.rs:924)、crypto.rs:775-778 空白名单拒、xray-core parse_reality_config 空数组拒启测试、REALITY 回环握手测试全绿（reality crate 110/110）。**无 fail-open 路径残留，无需补码。**

### etj0（REALITY X25519 跳检）— 判定现状已硬错（无 fail-open）

**票面前提修正**：票面称"缺 key_share 跳过校验"，与现状不符——`server.rs:248-250` `key_share_x25519.ok_or(NoKeyShareX25519)?` 硬错 → `server_tls` Err → `RealityServerOutcome::Invalid` → fallback_to_dest。与 Go xtls/reality tls.go 精确对齐：任何一步失败 break→伪装转发（tls.go:211/233-235/281），**验证失败走伪装而非放行是 Go 设计本身**。
**非法钥硬错**：`derive_auth_key`（crypto.rs:105-125）长度校验+ECDH 全零共享密钥（low-order point）→ `EmptySharedKey` 拒，强于/等价 Go `curve25519.X25519` 的 error break。
**覆盖证据**：`verify_reality_client_hello_no_key_share`(:848)、`wrong_server_key`(:881)、`server_tls_invalid_returns_invalid_outcome`(:1052)、`sni_mismatch/missing_sni → Invalid`(:1089/:1121)、回环 verified 路径(:1175/:1219/:1279) 全绿。
**残余差异（非安全）**：Go 新版要求 X25519MLKEM768 share 存在（tls.go:233-235 peerPub2==nil→reject），X25519 可选；Rust 只认纯 X25519（server.rs:191 group 0x001d）。MLKEM-only ClientHello 两边都拒（无安全差异），未来 uTLS 模板若变 MLKEM-only 需补——记 interop 跟踪项。

## 验证命令与输出

```
cargo test -p xray-proxy-vless --lib   → 231 passed; 0 failed
cargo test -p xray-proxy-trojan --lib  → 60 passed; 0 failed
cargo test -p xray-reality --lib       → 110 passed; 0 failed; 1 ignored
cargo test -p xray-transport --lib     → 520 passed; 0 failed
cargo test -p xray-core --lib          → 325 passed; 0 failed（1 挂修复后全量重跑，见下）
cargo check -p xray-transport -p xray-proxy-vless -p xray-core --lib → ok
```
REALITY 合法握手不误伤：`reality_loopback_u_client_with_server_tls`、`reality_loopback_watfaq_fallback_fingerprint`、`server_tls_verified_branch_enters_tls_accept`、xray-core `integration_vless_vision_over_tls_to_echo`（真 rustls TLS1.3 + Vision 双端）全绿。

## 触碰边界

- **禁区**：未触碰（无 commit/无 bd 状态变更/无 mux/dispatcher/bridge.rs/ws-httpupgrade 指纹/wire-format/tcp register.rs/REALITY 补丁链改动）
- **域外最小改动**：`xray-transport/src/lib.rs` +4 行 `pub use rustls;`（加法，lwep TLS 版本查询的类型可达性所需）
- **测试契约更新**：`xray-core/functions.rs:1506` vision-over-tls 服务端账号补 `"flow":"xtls-rprx-vision"`（原配置在 Go 下同为非法部署，lwep 收紧后正确拒绝）

## 静默失败审查（silent-failure-hunter）

- validate_flow 拒绝路径：Err 显式传播 → serve 循环 log → 断连，无吞错 ✅
- REALITY verify 失败：Invalid outcome 携带 reason，调用方 fallback+log ✅
- fuzzy_longest_match：无匹配返回 None（非危险 fallback），decide 全 miss → None → 连接关闭 ✅
- protocol_version()==None（握手未完成）→ outer_tls13=false → 拒（无宽松默认）✅

## 未做（明确不在本轮）

- Go :593 isMuxAndNotXUDP mux 分支（需 mux 首帧解析，防误伤 XUDP-mux 合法流，独立票）
- VLESS fallback `find_with_fallback`（inbound/handler.rs:97）同缺 lowercase/模糊匹配——票面外，建议另开票
- REALITY MLKEM768 key share 支持（Go tls.go:216-238）——interop 跟踪项
- 独立 Handler 测试装配路径（trojan server.rs:173 `decide("","","")`）保持现状：无 TLS 层的测试代码，语义正确

## side-effects

1. xray-transport 多一个 `pub use rustls;` 导出（加法无破坏）
2. `VlessInboundOptions` 公共结构 +1 字段（Default 兼容，全部调用点已核）
3. xray-core 一个集成测试配置修正为合法部署形态
4. 无其他行为面变化；32 节点 wire-format 由 PM 统一验证

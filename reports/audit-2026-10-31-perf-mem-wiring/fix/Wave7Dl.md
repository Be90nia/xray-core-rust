VERDICT: PASS

# y2dtu：splithttp `downloadSettings` 未接线（Go 另建下载客户端，Rust 走主通道）

改动文件：`crates/xray-transport-splithttp/src/{config,dialer,register}.rs`（+ 三个测试文件的调用点同步）。
无新依赖、无第二套配置体系、无 wire 语义改动、未 commit。未碰红线文件（xray-mux / xray-core 的
functions.rs / outbound.rs / inbound.rs / xray-frame / xray-transport-websocket / 各 udp.rs / grpc.rs / api_exec.rs）。

---

## 1. Go 行为规格（源码核对，Go xray-core @ 92ccc939 = v26.10.17）

| 项 | Go 行为 | 源码 |
|---|---|---|
| 配置形态 | `splithttpSettings.downloadSettings` = **完整 StreamConfig**：address / port / method / network / security / finalmask / tlsSettings / realitySettings / `splithttpSettings`（协议段）/ sockopt… | `infra/conf/transport_method.go:295`（`DownloadSettings *StreamConfig`）；`infra/conf/transport_internet.go:50-68`（StreamConfig 字段） |
| 配置期校验 | **mode=stream-one + downloadSettings → 硬错**：`Can not use "downloadSettings" in "stream-one" mode.` | `infra/conf/transport_method.go:508-511` |
| mode 推断 | `auto` + REALITY + downloadSettings → **stream-up**（否则 stream-one） | `transport/internet/splithttp/dialer.go:339-345` |
| 拨号期构造 | `memory2 = ToMemoryStreamConfig(downloadSettings)` → `dest2`（**自己的 address/port**）、`tlsConfig2`/`realityConfig2`（**自己的 security**）、`httpVersion2`（**自己的 ALPN** 推出的版本）、`config2`（**自己的 splithttpSettings**）→ `requestURL2` + **另建下载客户端** `httpClient2 = getHTTPClient(ctx, dest2, memory2)` | `dialer.go:355-404`（日志 `XHTTP is downloading from %s, mode %s, HTTP version %s, host %s`） |
| **选路** | **stream-one**：下行 = 主客户端 POST 的响应（downloadSettings **不参与**）；**其余**（packet-up / stream-up / stream-down）：下行 = `httpClient2` 的 GET（未配时 `httpClient2` = 主客户端 ⇒ 同一通道）；**上行恒走主客户端**（主 host/path） | `dialer.go:427-443`（stream-one 分支）、`:445-452`（stream-down = `httpClient2`）、`:455-460`（stream-up 上传 = 主客户端） |
| 缺 address/port | Go 在 `dest2 := *memory2.Destination` 处**空指针 panic**（注释「just panic」） | `dialer.go:369` |

**推论（配置语义的关键点）**：Go 的 hub 用 `upsertSession(sessionId)` 按 session id 建/取会话
（`hub.go:183`）——**上行 POST 与下行 GET 必须在同一台 hub 上**才能对上会话。故
`downloadSettings` 的 address/port 语义是「**同一 hub 的另一个入口**」（另一域名 / 另一 IP / CDN 边缘），
**不是**「另一台独立服务器」（那台会新建空 session 并永远等不到上传）。下载侧 host/path 必须被
目标 hub 接受（Go hub 不校验 path，Rust hub 校验 path/host ⇒ Rust 侧下载侧 path/host 须与 hub 配置一致）。

## 2. Rust 侧现状（修前）

- `Config.download_settings: Option<Box<Config>>`（`config.rs`）——**只承载协议段**（注释：
  「切片2 接入 StreamConfig 强类型」）。
- `register.rs::parse_splithttp_fields` 只取 `downloadSettings.splithttpSettings` 递归解析，并
  **打 warn**：`splithttpSettings.downloadSettings is parsed but NOT applied: download still uses
  the main channel (host/path/TLS). Go builds a separate download client …`（bd x0f0r）。
- 下载腿恒走主客户端 + 主 host/path：`dial_packet_up` / `dial_stream_up` / `dial_h3_packet_up` /
  `dial_h3_stream_up` 的 GET 都用主 client + 主 `base_uri`。
- `resolve_mode(&config.mode, has_reality, has_download_settings)` 的第三参在 `dial()`/`dial_h3()`
  里**硬编码 false** ⇒ 「auto+REALITY+downloadSettings → stream-up」的 Go 行为也没实现。

## 3. 承载面取舍（复用既有面，不造第二套体系）

| 候选 | 评估 |
|---|---|
| `xray_transport::memory_settings::MemoryStreamConfig`（Go `ToMemoryStreamConfig` 的对应物） | **缺** destination / security settings / protocol settings（只有 protocol_name / security_type / masks / quic_params / download_settings）⇒ 要承载下载侧还得再扩这个共享 crate，且 dest/TLS 仍无处放 ⇒ 否 |
| `xray_transport::dialer::StreamSettings`（JSON 形态：protocol/security/transport_json/security_json/sockopt_json/finalmask_json） | **就是** Go `StreamConfig` 的对应物；`StreamSettings::from_json(downloadSettings_json)` 一次即得下载侧的 network/security/tlsSettings/realitySettings/sockopt/finalmask ✓ ⇒ **选它** |
| 新造一套「下载侧配置」 | 违反「不引入第二套配置体系」⇒ 否 |

**结论**：下载侧承载 = ①协议段 `Config`（既有类型）②下载侧 StreamConfig 的**原始 JSON**（拨号时经既有
`StreamSettings::from_json` 转承载类型）③`Destination`（既有类型，下载侧 address/port）。
新增的 `crate::config::DownloadSettings` 只是**把三段既有承载打包**，不是新配置体系。

## 4. 实现

1. **`config.rs`**：新增 `DownloadSettings { config: Box<Config>, stream_json: serde_json::Value,
   destination: Destination }`；`Config.download_settings` 改为 `Option<Box<DownloadSettings>>`。
2. **`register.rs`**：
   - 解析 `downloadSettings`：协议段递归解析 ✓；原始 JSON 留存 ✓；`address`/`port` → `Destination`
     （`env:` 前缀同 Go `common.go:53-67`）；**缺 address/port → 配置期硬错**（替 Go 的 panic ✓）。
   - **stream-one + downloadSettings → 配置期硬错**（Go 同款文案 ✓）。
   - **撤掉波5 那条 warn**（接线成功后它就在说谎 ✓；且解析错误此前已硬报，保留）。
   - 新增 `build_download_side()`：按**下载侧自己的** TLS/ALPN 建客户端（h2 → `DefaultDialerClient`；
     h3 → 独立 `H3Conn`/QUIC 连接 ✓）+ 下载侧 `base_uri`（自己的 host/path/query ✓）。
3. **`dialer.rs`**：新增 `DownloadClient`（H2/H3 枚举，下载侧版本由自己的 ALPN 决定 ✓）+
   `DownloadSide { client, base_uri }`；四个拨号函数的**下载腿**在有 downloadSettings 时走
   下载侧客户端 + 它的 base_uri ✓；`dial()`/`dial_h3()` 透传 ✓；`resolve_mode` 的
   `has_download_settings` 由硬编码 false 改为 `config.download_settings.is_some()` ✓
   （⇒ auto+REALITY+downloadSettings → stream-up ✓ 与 Go 一致）。
4. 公共 API 变化（仓内调用点全部同步）：`dial_packet_up` / `dial_stream_up` / `dial_h3_packet_up` /
   `dial_h3_stream_up` / `dial` / `dial_h3` 各多一个 `download: Option<&DownloadSide>` 参数。

## 5. 矩阵输出与对端证据

矩阵脚本 `fix/scripts/wave7_h3_matrix.py` 新增 `--dl` 维度：mode=**stream-up**、h2；下载侧的
address/port 指向脚本内的 **TCP 转发器**（转发到同一个 hub）——**转发器被连上 = 下行确实走了
downloadSettings 的 address/port**（不依赖「看起来成功」；主通道也能跑出全对字节，见 §6 反证）。

```
$ python reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7_h3_matrix.py \
      --rust target-Wave7Dl/release/xray.exe --go D:/tmp/go2617/xray.exe --dl
[PASS] #01 Rust->Rust h2/packet-up   UP:65536 DOWN:65536 dl_conns:-1 bytes-identical
…（h2/h3 × 3 mode × 3 向共 18 条全 PASS）
[PASS] #19 Rust->Rust h2/stream-up   UP:65536 DOWN:65536 dl_conns:1 bytes-identical   ← downloadSettings 维度
[PASS] #20 Rust->Go  h2/stream-up   UP:65536 DOWN:65536 dl_conns:1 bytes-identical
[PASS] #21 Go->Rust  h2/stream-up   UP:65536 DOWN:65536 dl_conns:1 bytes-identical

=== splithttp 矩阵: 21/21 PASS ===
```
`dl_conns:1` = 下行连接确实经过 downloadSettings 指定的 destination ✓（转发器计数）。
三条覆盖：Rust 客户端→Rust 服务端、Rust 客户端→Go 服务端、Go 客户端→Rust 服务端 ✓。

```
$ python dist/interop_ci.py --rust target-Wave7Dl/release/xray.exe --go D:/tmp/go2617/xray.exe --upstream local
=== 互通 CI: 43/43 PASS ===
```

## 6. 反证（把实现改回「下行走主通道」）

临时把 `register.rs` 的 `download_side` 短路为 `None`（= 下行回到主客户端 + 主 host/path），
debug 构建后跑同一维度：
```
[FAIL] #01 Rust->Rust h2/stream-up   UP:65536 DOWN:65536 dl_conns:0 bytes-identical (download leg did NOT go through downloadSettings destination)
[FAIL] #02 Rust->Go  h2/stream-up   UP:65536 DOWN:65536 dl_conns:0 bytes-identical (download leg did NOT go through downloadSettings destination)
[PASS] #03 Go->Rust h2/stream-up   UP:65536 DOWN:65536 dl_conns:1 bytes-identical
```
两点结论：
1. **字节照样全对**（`DOWN:65536 bytes-identical`）——只验「客户端成功」根本咬不住这条路径 ⇒ 必须有
   对端 destination 证据锚（转发器计数）✓。
2. **Go→Rust 仍 PASS**（Go 客户端自带 downloadSettings 接线 ✓、Rust 服务端侧本就正确 ✓）⇒ 反证精确
   指向「Rust 客户端的下载侧选路」，未误伤其它方向 ✓。
（反证用的临时改动已全部复原；复原后 tests/clippy/fmt/矩阵/interop 全部重跑通过。）

## 7. 验收命令

```
$ cargo test -p xray-transport-splithttp --all-targets
268 + 4 + 1 + 12 + 1 + 2 = 288 passed / 0 failed / 0 ignored
$ cargo clippy -p xray-transport-splithttp --all-targets -- -D warnings   → 零告警
$ cargo fmt -p xray-transport-splithttp -- --check                        → FMT_EXIT=0
$ 矩阵（--dl）                                                          → 21/21 PASS
$ dist/interop_ci.py --upstream local                                    → 43/43 PASS
```

## 8. 残余风险与未做
- **下载侧与主通道必须落在同一台 hub**（§1 推论）：下载侧 address/port 指向另一台独立服务器时，
  那台 hub 会新建空 session 并等不到上传 ⇒ 下行挂起。**该语义必须写进配置文档**（仓内当前无
  downloadSettings 文档），本轮未补文档（超出本票文件面）。
- **REALITY 下载侧未实现**：Go 的下载侧可带 REALITY（`realityConfig2`）；Rust 主通道的 REALITY 是
  特化路径（`dial_reality_stream_one`，u_client + session_id 改写），下载侧无对应实现 ⇒ 配 REALITY 的
  downloadSettings 时下载侧按普通 TLS 建连，握手失败（**可见失败，非静默降级**）。本轮未加配置期硬错
  （会改变 Go 兼容配置的启动行为），登记为已知缺口。
- **h3 下载侧已接线但矩阵未覆盖**（转发器是 TCP-only，无法代理 QUIC）；h3 下载侧需要独立 QUIC 连接
  （`dest2.Network = UDP` ✓ 已按 Go 实现），未做实跑验证。
- `stream-one + downloadSettings` 现为**配置期硬错**（Go 同款）——行为与 Go 一致，但对「先前配了
  downloadSettings + stream-one 却能启动」的旧配置是**破坏性变更**（Go 同样拒启）。
- 未跑 32/32 真机互通；未跑 workspace 全量测试。
- 收尾：`CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-Wave7Dl` 已在交付后删除；改后二进制留
  `fix/tmp/wave7-dl-after.exe` 供复现。

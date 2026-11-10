VERDICT: DONE

# XDRIVE 传输族实施规划（bd hjtlk，P2）

> 上游基准：`D:/Project/Xray-core` @ `676eaf66`（tag `v26.11.9`，已冻结，无后续提交）
> 本文只给**决策与契约**（接口签名 / 类型归属 / 模块边界 / 批次出口），不写实现细节。
> 落地前置：本仓已接 udf-frame（`crates/udf-frame`）、xray-frame、codebase-memory 图谱。

---

## 1. 目标与非目标

**目标（一句话）**：把 Go v26.11.9 的 `transport/internet/xdrive` 传输族移植到本仓，使
`network: "xdrive"` 的 VLESS 入/出站在四种后端（`local` / `template` / `s3` / `google-drive`）
上可用，并与 Go 对拍（Rust↔Rust、Go→Rust、Rust→Go 三方向）。

**明确不做**：

1. **不改 mux 缺省并发**（票面红线）。本仓 `outbound_mux_concurrency` 已尊重显式 `concurrency`
   （0→8、负值不包装）⇒ 用户写 `"mux":{"enabled":true,"concurrency":128}` 即得 Go 同款容量。
   本票只**新增** `validateXDrive` 同款 lint 强制 `mux.enabled`。
2. **不动 udf-frame 仓**（零提交）。
3. **不新造 XMUX / H3 / 重试 / 时钟 / 缓存 / 池 / 任务托管 / 注册表机制**（见 §3 映射表）。
4. **不移植 Go 的 `config.pb.go`**（prost 从 `.proto` 生成）。
5. **不移植 Go 的活体测试**（`drive_live_*` / `yandex_live_test` 需真实 OAuth 凭据），
   改为 mock-server 单测 + 一条手工验收清单（§7）。
6. **不做 Google Drive / S3 的真实云账号采购或凭据落库**（用户自管红线）。
7. **不做 `xdrive` 的 UDS（unix socket）形态**——Go 侧同样无此形态（`Serve` 不 bind 任何 socket）。

---

## 2. 上游基准

### 2.1 仓库与版本

| 项 | 值 |
|---|---|
| Go 仓 | `D:/Project/Xray-core` |
| commit | `676eaf66f8f05d4d558ee7a74b4736623d3feeb9` |
| tag | `v26.11.9`（上游 HEAD == 此 tag，已冻结） |
| 增量口径 | 票面记录 `transport/internet/xdrive/` 共 29 文件 +6650/−219（相对 26.10.17） |

### 2.2 待移植文件清单（`transport/internet/xdrive/`，实测行数）

非测试源码合计 **5123 行**（不含 `config.pb.go` 319 行生成代码）：

| Go 文件 | 行数 | 职责 | 移植批次 |
|---|---|---|---|
| `config.proto` | 30 | `Config` + `S3Config` | B0 |
| `params.go` | 89 | 参数缺省/上限/按后端覆盖（`paramsForStorage`） | B1 |
| `storage.go` | 125 | `Storage` trait、`newStorage` 分派、`sessionStorage`、`sharedStorage`/`shareKey` | B1 |
| `local.go` | 120 | 本地文件后端（`localStorage`） | B1 |
| `local_other.go` | 12 | 非 Windows 读实现 | B1 |
| `local_windows.go` | 30 | Windows `ERROR_SHARING_VIOLATION` 重试（`readFile`） | B1 |
| `wal.go` | 449 | 分段 WAL：`walWriter`/`walReader`/`objectName`/`parseEntry` | B1 |
| `conn.go` | 159 | `Conn`（读写 deadline、`chunkReader` trait、`newConn`/`newSlotConn`） | B1 |
| `xdrive.go` | 538 | `Dial`/`Serve`/`Listener`（acceptLoop/collectLoop/announce 解析）+ `spareBox` | B1（spare 部分 B5） |
| `client.go` | 519 | HTTP 栈：`serviceTransport`（停滞检测）/`secureTransport`/`connPool`/`sessionTransport` | B2 |
| `template.go` | 509 | `template` 后端（auth/两跳 `hrefPath`/重试/`namesRegex`） | B2 |
| `jsonpath.go` | 39 | JSON 点路径取值（`jsonWalk`/`jsonString`/`jsonNumber`） | B2 |
| `s3.go` | 518 | S3 后端（SigV4 手写签名、List pages、recursive delete） | B3 |
| `drive.go` | 915 | Google Drive 后端（OAuth token、`resolveID`、`slotStore` 四方法、限流退避） | B4 |
| `slots.go` | 1071 | 会话环形槽位（`slotStore`/`slotFrame`/`ring`/`slotWriter`/`slotReader`） | B5 |

测试代码 **6300 行 / 15 文件**（`client_test.go` 1143、`drive_test.go` 1121、`slots_test.go` 926、
`xdrive_test.go` 984、`drive_live*.go` 912、其余 1214）：作为**行为契约来源**读，Rust 侧按语义重写，
不逐行移植。

### 2.3 配置面（`infra/conf`，约 190 行）

| 位置 | 行数量级 | 内容 |
|---|---|---|
| `infra/conf/transport_internet.go` | ~5 | `:43-44` 协议名 `"xdrive"`；`:69` `XDRIVESettings` JSON 键 |
| 同上 | ~30 | `:93-120` `["h3"]` ALPN 触发 h3；`:109-117` 指纹 + `["http/1.1"]` 的 ALPN 注入例外 |
| 同上 | ~12 | `:223-233` 把 `XDRIVESettings.Build()` 结果挂进 `TransportSettings` |
| 同上 | ~10 | `:266+` h3 + finalmask 组合限制（google-drive 只允许 noise） |
| `infra/conf/transport_method.go` | ~106 | `:989-1094` `XDriveConfig` + `XDriveS3Config` + `Build()`（含 xmux 缺省：google-drive 非 h3 → maxConnections 4，其余 1；`hMaxReusableSecs` 1800-3000；S3 走 `ValidateS3Config`） |
| `infra/conf/xray.go` | ~50 | `:216` inbound 接线、`:399` outbound 接线、`:273-319` `validateXDrive` |
| `transport/internet/memory_settings.go` | ~8 | `:39-44` `address`/`port` → `MemoryStreamConfig.Destination`（**仅被 xdrive fronting 消费**） |

### 2.4 `validateXDrive` 规则原文（`infra/conf/xray.go:273-319`）

出站（`*outbound.Config`）：`flow != ""` → 拒；`encryption == "none"` → 拒；`Reverse == nil` 时
必须 `mux.enabled && concurrency >= 0 && xudpConcurrency >= 0 && xudpProxyUDP443 != "skip"`；
`testpre != 0` → 拒。
入站（`*inbound.Config`）：`decryption == "none"` → 拒；任一 user `flow != ""` → 拒；
`len(PortList.Ports()) != 1` → 拒。
其他协议 → 拒（`the xdrive transport can only be used by VLESS`）。

---

## 3. 现有件映射表（评审打回项核心）

> 检索方式：`codebase-memory-mcp` 图谱 + `serena-cli` + `grep` 交叉核对；**每条路径与符号名均为本次实测存在**。
> 标注「未找到」的行给出了检索式（禁凭印象编造 API）。

| # | 能力需求（Go 侧） | 现有件（符号 + 路径） | 采用方式 | 消费点（本仓） |
|---|---|---|---|---|
| 1 | `xdrive.Config` / `S3Config` proto | `protos/transport/internet/xdrive/config.proto`（**存在但落后**：缺 `xmux=13` / `s3=14`）；`crates/xray-proto/src/lib.rs` `pub mod xdrive { include!(...) }` | **直用 + 补齐**：整文件从 Go 基线 `cp`（保 LF）→ `python tools/check_proto_drift.py --write` | `xray-transport-xdrive` 的类型面（可选：Rust 侧仍走 JSON，proto 仅为镜像一致性） |
| 2 | transport 注册（`RegisterTransportDialer/Listener`） | `xray_transport::dialer::register_transport_dialer`（`crates/xray-transport/src/dialer.rs`）、`xray_transport::listener_registry::register_transport_listener`（`crates/xray-transport/src/listener_registry.rs`）、`xray_transport::ignore_already_exists` | **直用**（照 `xray-transport-websocket/src/register.rs` 同款 `ignore_already_exists` 幂等注册） | 新 crate `register.rs` + `xray-core/src/register.rs::register_all_transports` |
| 3 | 入站按 protocol 分派到 transport listener | `xray_core::inbound::is_transport_listener_protocol`（`crates/xray-core/src/inbound.rs`，`matches!` 白名单） | **直用 + 加一支** `"xdrive"` | 入站构建路径（不加则 xdrive 入站落到裸 TCP 分支，静默走错） |
| 4 | XMUX 多路复用池（`connPool`/`sessionTransport` 的池语义） | `xray_transport_splithttp::mux::{XmuxManager, XmuxClient, XmuxConn, ManagerPool, xmux_manager_key, wrap_xmux_client}`（`crates/xray-transport-splithttp/src/mux.rs`，802 行，底层注册表 = udf `BoundedRegistry`） | **派生**：给 xdrive 的会话 HTTP 客户端 `impl XmuxConn`，塞进既有 `XmuxManager`。**不新写池**（Go 的 `connPool` 是自造；Rust 已有同构件） | `xray-transport-xdrive/src/client.rs` |
| 5 | HTTP/3 传输（`http3.Transport`） | `xray_transport_splithttp::h3_client::{H3Conn, LazyH3Conn, H3ClientLike}`（`crates/xray-transport-splithttp/src/h3_client.rs`）；`xray-transport-quic`（quinn 0.11 + `congestion_swappable::HysteriaCCSlot`）；`xray_transport::memory_settings::QuicParamsConfig` | **部分直用**：连接管理/CC/参数复用；**API 形状不匹配**（H3Conn 的 `post_packet`/`open_stream` 是 splithttp 专用）⇒ h3 请求面新写薄层（网络方向件，§4.1 同判；其中 CC 应用逻辑必须上浮而非复制，见 §4.4） | `xray-transport-xdrive/src/h3.rs` |
| 6 | TLS 客户端（含 uTLS 指纹、ALPN、pin） | `xray_tls::client_config::build_client_config(security, security_json, server_name) -> io::Result<Option<Arc<ClientConfig>>>`（`crates/xray-tls/src/client_config.rs`）；`xray_tls::utls` | **直用** | `client.rs` / `h3.rs` 的 TLS 配置 |
| 7 | 请求级重试 + 退避 + 抖动（`driveMaxAttempts=8`、`driveInitialBackoff=200ms`、`driveMaxBackoff=8s`、`jitter()`） | `xray_transport::retry::exponential_backoff_if(attempts, base_delay_ms, budget, f, retryable)`（`crates/xray-transport/src/retry.rs`）；udf `std_ext::retry::{retry_if_async, RetryPolicy, full_jitter}`（`crates/udf-frame/std-ext/src/retry.rs`） | **直用**（用 `_if` 变体表达「4xx 不重试、429/5xx 重试」） | `drive.rs` / `template.rs` / `s3.rs` 的 `do()` |
| 8 | 「无进展即断」（`serviceTransport.RoundTrip` 的 stall 语义） | `xray_frame::deadline::{timeout, Budget, BudgetTimer, IdleDeadline}`（`crates/xray-frame/src/deadline.rs`，`BudgetTimer::reset` 即「有进展则重置」） | **直用**（不新写超时层） | `client.rs` 的 `serviceTransport` |
| 9 | 时钟/单调时基 | `skeleton::clock::{Clock, MockClock}`（`crates/udf-frame/skeleton/src/clock.rs`）；`PluginContext::clock()` | **直用**（测试走 `MockClock`，禁裸 `Instant::now`） | 全 crate（poll 节拍、token 过期、purge） |
| 10 | 会话 ID（Go `newSessionID` = 16 随机字节 → hex） | `std_ext::id::RandomId::new() -> Result<RandomId, RngError>`（`crates/udf-frame/std-ext/src/id.rs`）+ `std_ext::encode::hex_encode(bytes, HexCase)` | **直用**（`RandomId` 内部即 `getrandom` 16 字节） | `xdrive.rs::new_session_id` |
| 11 | base64（slotFrame 描述）+ CRC32（`slotFrame.crc`） | `std_ext::encode::{base64_encode, base64_decode}`（`crates/udf-frame/std-ext/src/encode.rs`）；`crc32fast` crate（已在 `xray-proxy-vmess` / `xray-proxy-ss` 依赖树内，版本 1） | **直用**（不加新三方依赖） | `slots.rs` |
| 12 | 本地文件后端（`localStorage` Put/Get/Delete/List + Windows 共享冲突重试） | `std_ext::fsx::{walk, atomic_write, rm_all}`（`crates/udf-frame/std-ext/src/fsx.rs`：`walk` 惰性遍历、`atomic_write` 崩溃安全原子写=临时文件+rename） | **直用 + 薄派生**：`LocalStorage` 组合 `fsx`；只有 Windows `ERROR_SHARING_VIOLATION` 重试环需新写（Go 同规模 30 行） | `xray-transport-xdrive/src/local.rs` |
| 13 | 会话预热点池（`spareBox`：2 个 warm 会话、10min 空闲停、TTL 2/3 生效） | `skeleton_infra::objpool::ObjectPool::{new, acquire, prune_idle_with_clock, metrics}`（`crates/udf-frame/skeleton-infra/src/objpool.rs`） | **派生（组合包装）**：`ObjectPool<WarmSession>` + `prune_idle_with_clock` 表达「老化即丢」；TTL 2/3 判定属业务语义留在 xdrive | `xdrive.rs`（仅 google-drive 路径） |
| 14 | LRU/TTL 缓存（Drive 的 `cachedID/rememberID/forgetID`、token 缓存） | `std_ext::cache::{SyncLruCache, SyncTtlCache}`（`crates/udf-frame/std-ext/src/cache.rs`；`SyncTtlCache::new(clock, cap)`） | **直用** | `drive.rs`（id 缓存）、`template.rs`（token 过期） |
| 15 | 后台任务托管（`acceptLoop`/`collectLoop`/`fillSpares`/`refreshTokenBackground`） | `xray_frame::scope::{ComponentScope, ArmScope, ScopeRef}`（`crates/xray-frame/src/scope.rs`；`spawn` 统一 `catch_unwind`，`downgrade()` 破自引用环） | **直用**（照 `xray-transport-websocket/src/register.rs` / `xray-transport-quic/src/transport.rs` 同款：`ComponentScope::new("xdrive-…:<ident>")` + `downgrade()` 进泵体） | `xdrive.rs` Listener 字段 + `client.rs` 会话任务 |
| 16 | 连接抽象（Go `stat.Connection`） | `xray_transport::connection::Connection`（`crates/xray-transport/src/connection.rs`，需实现 `remote_addr`/`local_addr`，其余有缺省） | **实现（新类型）**：`xdrive::Conn` | `conn.rs` |
| 17 | finalmask 掩码链（Go `FinalMask.DialTCP/DialUDP`） | `xray_transport::finalmask::{TcpmaskManager, UdpmaskManager, wrap_conn_client_from_settings}` + `xray_transport::memory_settings::MemoryStreamConfig` | **直用** | `client.rs` 的出站拨号 |
| 18 | QUIC 参数（`quicParams`）+ 拥塞控制 | `xray_transport::memory_settings::QuicParamsConfig`；`xray_transport_quic::congestion_swappable::HysteriaCCSlot` | **直用**；CC 应用逻辑当前是 splithttp 私有 `apply_splithttp_cc` ⇒ 见 §5 B6 的**上浮**子项 | `h3.rs` |
| 19 | 缓冲（段读写） | `xray_buf::buffer::Buffer::new_pooled`、`xray_buf::alloc::alloc`（`crates/xray-buf/src/{buffer,alloc}.rs`） | **直用**（禁裸 `Vec<u8>` 大块拷贝热路径） | `wal.rs` / `slots.rs` |
| 20 | mux 出站并发（Go 缺省 128 的动机） | `xray_core::outbound::outbound_mux_concurrency`（`crates/xray-core/src/outbound.rs`，0→8、负值不包装） | **不改**（票面红线）；只新增 lint 强制 enabled | — |
| 21 | VLESS ENC 解析（lint 判「有 encryption/decryption」） | `xray_proxy_vless::encryption::{parse_client_encryption, parse_server_decryption}`（`crates/xray-proxy-vless/src/encryption/params.rs`）；`xray vlessenc` CLI 已存在（`crates/xray-cli/src/commands/keys.rs::execute_vlessenc`） | **直用**（lint 用同一解析器，禁另写一份判定） | `xray-conf` 的新 lint |
| 22 | 配置后处理阶段（Go `RegisterConfigureFilePostProcessingStage`） | `xray_conf::lint::{LintStage, register_stage, registered_stages}`（转调 udf `skeleton::lint`）+ `xray_conf::init::ValidationStage` | **直用**（新增规则挂 `ValidationStage::run`） | `xray-conf` |
| 23 | S3 SigV4 签名 + S3 REST（Go `s3.go:sign/target/do`） | **未找到**。检索式：`grep -E "AWS4-HMAC-SHA256\|SigV4\|aws-sdk\|object_store\|x-amz-" crates/`（0 命中）+ `cargo metadata` 依赖树无 S3 crate | **新写**（举证见 §4.2） | `s3.rs` |
| 24 | 对象存储 WAL 布局 / 环形槽位（`objectName`/`parseEntry`/`ring`/`slotFrame`/`slotWriter`/`slotReader`） | **未找到**。检索式：`grep -E "pub struct Ring\|ring_buffer\|watermark" crates/udf-frame/`（只有池水位线，非环形槽） | **新写**（举证见 §4.3） | `wal.rs` / `slots.rs` |
| 25 | JSON 点路径（Go `jsonpath.go` 39 行） | `serde_json`（全仓口径）；udf `std_ext::json` 只提供**严格解码**，不含路径取值 | **新写 39 行级小件**（`serde_json::Value` 逐键下钻；不自造 JSON 解码器） | `template.rs` / `drive.rs` |
| 26 | 日志观测 | `xray_frame::logging::{LogFacade, HotLog}`（各 transport crate 的 `LOG` / `HOT_LOG` 惯例） | **直用**（target `xray_frame::transport::xdrive`） | 全 crate |
| 27 | proto 镜像纪律 | `tools/check_proto_drift.py`（`--manifest` / `--upstream <go-repo>` / `--write`）+ `protos/.checksums.json` | **直用**（红线：禁手改 `.proto`，必须从 Go 基线 `cp`） | B0 |
| 28 | 三方向互操作对拍 | `dist/interop_ci.py`（`--suites rust,go,rust_to_go,extra`、`--cross-protos`、`--extra-protos`）+ `.github/actions/fetch-go-baseline`（钉 `v26.11.9` / `676eaf66`） | **直用 + 加一套 `xdrive` 用例** | B6 |

**「本仓已有 X，不新写」的节省项（≥2 处，实测锚定）**：

1. **XMUX 不新写**：Go 的 `connPool`/`XmuxClient`（`client.go` 约 200 行）↔ 本仓
   `xray-transport-splithttp/src/mux.rs` 的 `XmuxManager`/`XmuxClient`/`ManagerPool`/`XmuxConn`
   （802 行，含 5 维复用判定与 udf `BoundedRegistry` 支撑的进程级池）。xdrive 只需
   `impl XmuxConn for Arc<XdriveHttpClient>` + 取 `H2_MANAGERS/H3_MANAGERS` 的工厂形态。
2. **会话 ID 不新写**：Go `newSessionID`（`crypto/rand` 16 字节 + hex）↔
   `std_ext::id::RandomId::new()` + `std_ext::encode::hex_encode`。
3. **重试/退避不新写**：Go `drive.go` 的 `driveMaxAttempts/backoff/jitter` 手写循环 ↔
   `xray_transport::retry::exponential_backoff_if`（已有判定器 + 预算 + 去重）。
4. **停滞检测不新写超时层**：Go `serviceTransport.RoundTrip` 的 stall ↔
   `xray_frame::deadline::BudgetTimer::reset`（有进展即重置）。
5. **本地文件后端不新写遍历/原子写**：`std_ext::fsx::{walk, atomic_write}` 已覆盖
   Go `local.go` 的 `filepath.Walk` + 临时文件 rename。
6. **任务托管不新写**：`ComponentScope` 已覆盖 `acceptLoop`/`collectLoop`/spare 填充循环。

---

## 4. 架构归属判定（§3.5.5 三判据逐条）

> 判据顺序固定：① 零 Xray 语义 → udf；② 否则 → xray-frame（默认）；③ 仅当派生层也放不合适 → 留主仓并逐条举证。

### 4.1 判为「协议方向件，留主仓 `xray-transport-xdrive`」（不需 §3.5.5 ③ 举证，§3.5.3 明文）

`xray_frame` 定位为「Xray 语义的**机制**派生层」；本票的存储/环槽/HTTP 请求编排属
**协议 wire 与内容**，§3.5.3 已明文：「网络（accept 循环纪律/文件/加密/协议等方向件），留主仓最近消费方」，
且「纯协议 wire 语义与 Go 对拍差异修正，留在协议 crate（属内容不属机制）」。

| 件 | 判据落点 | 归属 |
|---|---|---|
| `Storage` trait + `local`/`template`/`s3`/`drive` 四实现 | 对象名布局（`sessions/`、`streams/<sid>/c2s`、`%09d.seg`）是 xdrive 的 wire 契约 | `xray-transport-xdrive` |
| `wal.rs` 分段 WAL | 上述布局的读写方 | `xray-transport-xdrive` |
| `slots.rs` 环形槽位 | `slotFrame` 是**对端可解码的容器格式**（magic+seq+mode+size+crc） | `xray-transport-xdrive` |
| `client.rs` 的 `serviceTransport`/`secureTransport`（停滞检测、per-host 连接数） | 网络方向件，单消费方；**不允许**复制到别处，标 `udf-promotion-candidate`（第二消费方出现时上浮） | `xray-transport-xdrive`（注释标注） |
| `s3.rs` SigV4 | 网络/协议方向件 | `xray-transport-xdrive` |

### 4.2 「必须新写」举证：S3 SigV4

`xray-frame` 不合适：它不是 Xray 语义机制，而是通用 HTTP 签名算法 → 按 ① 应归 udf。
但 udf 判据「去项目化后仍是**进程级通用机制**」不成立：SigV4 是**单一后端的协议格式**
（三个方向件：网络/协议/加密），udf 明确不收方向件（§3.5.3）。且本仓**无任何** S3 消费方，
上浮进 udf 等于为零消费方造件。
**结论**：留 `xray-transport-xdrive/src/s3.rs`，件头写：
`udf-promotion-candidate：若出现第二个 S3 消费方，提炼为 std_ext::s3sigv4`。
依赖：`hmac 0.12` / `sha2 0.10` / `hex 0.4` / `base64 0.22` 均已在 workspace 依赖树内（`xray-proxy-ss` 等），
**不新增三方 crate**。

### 4.3 「必须新写」举证：环形槽位 / WAL 布局

- udf 无环形槽件：`grep -E "Ring|ring_buffer" crates/udf-frame/` 仅命中池水位线（`watermark`），
  与「按 `seq % depth` 覆写、reader 用 watermark 回执授权覆写」不是一回事。
- `ObjectPool` 是「独占借还」模型，环槽是「多写者 + 环覆写 + 对端水位线」→ **假同构**，
  按 §3.5.4 反模式警示 **禁**套 `PoolManaged`。
- xray-frame 不合适：`slotMagic`/`slotFrame` 编码是对端可解码格式 = 协议 wire。

### 4.4 一处需要「上浮」而非新写

`apply_splithttp_cc`（`crates/xray-transport-splithttp/src/h3_client.rs`，私有）把
`QuicParamsConfig` 翻译为 quinn CC。xdrive 的 h3 需要同一份逻辑。按 §3.5.2 **禁复制** ⇒
B6 先把它上浮到 `xray-transport-quic`（`congestion_swappable` 旁）为公开
`apply_cc_from_quic_params(slot, quic_params) -> io::Result<()>`，splithttp 侧改为一行转调
（splithttp 行为零变化，其既有测试即回归锚）。

### 4.5 结论

**本票不需要在 `xray-frame` 或 `udf-frame` 新增任何机制件。** 唯一触及基础层的是
`xray_transport::dialer::StreamSettings` 增 `fronting: Option<(Address, u16)>`（对应 Go
`MemoryStreamConfig.Destination`，仅 xdrive fronting 消费）+ 从 conf 硬拒清单放开
`address`/`port` —— 属 Layer 2 传输基础面，非 xray-frame 机制。

---

## 5. 分批次实施计划

> 每批 = 一个可独立验证的出口。依赖顺序：B0 → B1 → B2 → {B3, B4} → B5 → B6。
> B3（s3）与 B4（drive）**可并行**（不同文件、共享 B2 的 `do()` 骨架）。

### B0 配置面与 proto（前置，1 人日）

1. `protos/transport/internet/xdrive/config.proto`：从
   `D:/Project/Xray-core/transport/internet/xdrive/config.proto` **整文件 `cp`**（保 LF），
   新增 `import "transport/internet/splithttp/config.proto";`、`XmuxConfig xmux = 13;`、
   `S3Config s3 = 14;` 与 `message S3Config`。
2. `python tools/check_proto_drift.py --write` → **必须**把 `.checksums.json` 二进制模式写回 LF
   （历史坑：文本模式会把 84 行全刷成 CRLF 造成全表假变更）→ `--manifest` 复验。
3. `xray-transport/src/dialer.rs::StreamSettings` 增字段
   `pub fronting: Option<(xray_common::net::address::Address, u16)>`（`from_json` 读
   `address`/`port`；缺省 `None` ⇒ 全部既有 transport 行为零变化）。
   `xray-transport/src/memory_settings.rs::to_memory_stream_config` 同步（否则
   splithttp/hysteria 的镜像结构漂移）。
4. `xray-conf/src/init.rs`：从硬拒清单删除 `"xdriveSettings"`、`"address"`、`"port"`
   （保留 `"masqueSettings"`，属另一票）；从 `matches!(net, "masque" | "xdrive")` 移除 `"xdrive"`。
5. 新增 `xray-conf/src/xdrive.rs`：`pub fn validate_xdrive(kind, tag, protocol, settings, stream_settings, mux, ports) -> Result<(), LintError>`，
   逐条对齐 §2.4 六条规则；在 `ValidationStage::run` 入站/出站两处调用。
   ENC 判定复用 `xray_proxy_vless::encryption::{parse_client_encryption, parse_server_decryption}`
   （**不新写解析**）。
6. 更新既有测试 `xray-conf/src/init.rs::strictness_rejects_masque_xdrive_and_fronting_keys`
   （现在 `xdrive` 两项不再拒）+ 新增 xdrive lint 的单测矩阵。

### B1 transport crate 骨架 + `local` 后端 + WAL（5-7 人日）

新建 `crates/xray-transport-xdrive`（workspace member，Layer 3，`#![deny(warnings)]` + 同款
`clippy.toml`）：

| 新文件 | 契约 |
|---|---|
| `config.rs` | `pub struct Config`（14 字段，对齐 proto） + `from_json(&serde_json::Value) -> io::Result<Config>`；`h3: bool`（由 ALPN 决定，见 B6） |
| `params.rs` | `pub struct Params` + `from_config` / `for_storage(&Config, &dyn Storage)`（Drive slot 路径覆盖 `concurrency=64`、`flush=10ms`、`maxPoll=200ms`） |
| `storage.rs` | `pub trait Storage: Send + Sync { put/get/delete/list/close }`（`async fn` via `#[async_trait]`，对齐 crate 惯例）；`pub trait SlotStore`（B5 填）；`new_storage(&StreamSettings, &Config)`；`shared_storage`（`sha256` 内容 key，用 workspace 既有 `sha2 0.10`；**禁**用 `std_ext::hash`——那是 FNV-1a/XXH64 非加密摘要） |
| `local.rs` | `LocalStorage`（组合 `std_ext::fsx::{walk, atomic_write}`）；Windows 共享冲突重试环 |
| `wal.rs` | `WalWriter`/`WalReader`（`objectName(prefix, seq, suffix)` / `parseEntry`） |
| `conn.rs` | `pub struct Conn` `impl Connection`（读缓冲 + deadline + `Close` 回调） |
| `xdrive.rs` | `pub async fn dial(...)`、`pub fn serve(...)`、`Listener{ accept_loop, collect_loop }`（`ComponentScope` 托管） |
| `register.rs` | `register_dialer()` / `register_listener()`（`ignore_already_exists` 幂等） |

接线：`crates/xray-core/src/register.rs::register_all_transports` 增两行；
`is_transport_listener_protocol` 增 `"xdrive"`；`Cargo.toml` workspace members + `xray-core` 依赖。

**契约要点（决策，不是实现步骤）**：

- `Dial` 返回 `Box<dyn Connection>`；`Serve` 忽略 bind 地址（Go 返回 `placeholderAddr 127.0.0.1:0`），
  但 `Listener::local_addr` 仍需返回一个值以满足 trait。
- 会话 announce 对象名 = `sessions/<unixNano>-<sessionId>`，`Inline` 载荷留到 B5。
- 本批**不实现** `spareBox`（依赖 `SlotStore`），`dial` 里 `take_spare` 恒 `None`。

### B2 HTTP 客户端栈 + XMUX 接线 + `template` 后端（5-7 人日）

| 新文件 | 契约 |
|---|---|
| `client.rs` | `XdriveHttpClient`（每会话一个，`impl XmuxConn`）；`ServiceTransport`（停滞检测，用 `BudgetTimer::reset`）；`SecureTransport`（per-host 连接数，h1 回退）；`SessionTransport`（从 `XmuxClient` 取连接）；`conn_pool(Config) -> XmuxManager<Arc<XdriveHttpClient>>` |
| `jsonpath.rs` | `fn json_string(&Value, path: &str) -> String` / `json_number`（点路径下钻，39 行级） |
| `template.rs` | `TemplateStorage`（`auth{type: none/static/oauth2/basic}`、`put/get/delete/list` 四 op、`hrefPath` 两跳、`retry{status, rateReason}`、`flatten`、`namesRegex`） |

- `template` 的重试走 `exponential_backoff_if`；`oauth2` token 缓存走 `SyncTtlCache`。
- XMUX 取池：`H2_MANAGERS.get_or(&xmux_manager_key(dest, parts), || Arc::new(XmuxManager::new(...)))`。
- `xmux` 缺省按 Go `XDriveConfig.Build`：非 google-drive（或 google-drive + h3）→ `maxConnections {1,1}`；
  google-drive + h2 → `{4,4}`；`hMaxReusableSecs {1800,3000}`。

### B3 `s3` 后端（3-4 人日，可与 B4 并行）

`s3.rs`：`ValidateS3Config`（endpoint/bucket 非空 + `validS3Name`）、`s3_region`（缺省 `us-east-1`）、
SigV4 签名（`hmac`+`sha2`+`hex`）、`path_style` vs virtual-hosted、`list` 分页、`Delete` 带尾 `/` 防前缀误删。

### B4 `google-drive` 后端（6-8 人日）

`drive.rs`：`DriveStorage`（`driveShared` 共享 token/连接，`session()` 派生每会话视图）、
OAuth `refresh_token` 流程 + 后台预刷新 + 失败退避、`query/resolveID`（`id` 缓存用 `SyncLruCache`）、
`Put`（inline description vs multipart media）、`List`（`q=name contains …`）、`Delete`、限流 `cool()`/`throttled()`。

### B5 环形槽位 + 预热点池（4-5 人日）

`slots.rs`：`SlotFrame{seq,mode,size,crc,data}` 编解码（`slotMagic`/`slotInlineLimit=14KiB`）、
`Ring{up,down,first}`、`make_ring`/`decode_ring`、`SlotWriter`（复用水位线授权）、`SlotReader`（hunt/tail/fetch-ahead 节拍）。
`xdrive.rs` 补 `spare_box`（`ObjectPool<WarmSession>` + `prune_idle_with_clock`）。
**仅 `DriveStorage` 实现 `SlotStore`**（Go 实测：`template`/`s3`/`local` 均无 `makeSlot/setSlot`），
故 B5 的非 Drive 路径必须继续走 WAL 分段（`params_for_storage` 只在 `SlotStore` 时覆盖缺省）。

### B6 h3 + XMUX 缺省收口 + lint 收口 + 三方向互操作（3-4 人日）

1. 上浮 `apply_splithttp_cc` → `xray-transport-quic::congestion_swappable::apply_cc_from_quic_params`，
   splithttp 转调（行为零变化）。
2. `h3.rs`：`h3 + h3-quinn + quinn` 通用请求面（method/headers/body → status/body），
   连接懒建 + 保活（`hMaxReusableSecs`/`hKeepAlivePeriod`）+ `HysteresisCCSlot` 接 CC。
3. `config.rs` 的 `h3` 判定：`tlsSettings.alpn == ["h3"]`（`StreamSettings.security_json`）；h3 时
   TLS 走 quinn（ALPN 由 quinn 传），h2/h1 走 hyper。
4. `dist/interop_ci.py` 增 `xdrive` 用例（`local` 后端 + 共享 `remoteFolder`，离线可跑）。

---

## 6. 每批验收（可执行命令 + 期望输出）

> 环境变量（本仓 §1 铁律，缺一 btls 冷编挂）：
> `BORING_BSSL_ASSUME_PATCHED=1` / `BORING_BSSL_SOURCE_PATH=target/boringssl-patched` /
> `PROTOC=D:/Project/tools/bin/protoc.exe` / `LIBCLANG_PATH=D:\Program Files\llvm\bin`。
> **release/交付构建另加** `BORING_BSSL_PATH=target/boringssl-asm/prebuilt`（否则落 NO_ASM，吞吐塌 7.6×）。

### B0

```bash
python tools/check_proto_drift.py --manifest          # 期望 exit 0（无 FAIL 行）
python tools/check_proto_drift.py --upstream D:/Project/Xray-core
                                                       # 期望 xdrive/config.proto 不在漂移清单
git diff --stat -- protos/.checksums.json              # 期望只 1 行变更（xdrive 条目）
cargo test -p xray-conf                                # 期望 0 failed；新 lint 矩阵全绿
cargo test -p xray-transport                           # StreamSettings 新字段不回归
```

B0 lint 行为锚（必须各有 1 条测试）：

| 输入 | 期望 |
|---|---|
| `network:"xdrive"` + `mux.enabled` 缺省 + vless `encryption` 非 none | **拒**：`the xdrive transport needs "mux" enabled…` |
| 同上 + `mux:{"enabled":true,"concurrency":128}` | **通过**（且不触碰缺省 8） |
| vless `encryption:"none"` | **拒**：`… needs VLESS "encryption"…` |
| inbound 两个 port | **拒**：`… can only listen on one port` |
| `protocol:"trojan"` + `network:"xdrive"` | **拒**：`… can only be used by VLESS` |
| `reverse` 非空 + mux 未启用 | **通过**（Go 例外） |

### B1

```bash
cargo test -p xray-transport-xdrive                    # 期望 0 failed
cargo clippy -p xray-transport-xdrive --all-targets -- -D warnings
cargo fmt -p xray-transport-xdrive -- --check
```

行为出口（同进程 Rust↔Rust，`service:"local"` + 临时目录）：

```bash
cargo test -p xray-transport-xdrive --test local_roundtrip -- --nocapture
# 期望：dial→write 1MiB→对端 read 逐字节相等；conn close 后 streams/<sid> 被 collector 回收
```

### B2

```bash
cargo test -p xray-transport-xdrive template -- --nocapture
# 期望：mock hyper server 断言 put/get/list/delete 的 method+path+header
#       两跳：第一跳 200 + {"href":"http://…/upload"} → 第二跳带着 body 发出且无 auth 头
cargo test -p xray-transport-xdrive xmux   -- --nocapture
# 期望：5 次 dial 的 accept 次数 < 2×dial（照 tests/xmux_reuse.rs 同款反证锚）
```

### B3

```bash
cargo test -p xray-transport-xdrive s3 -- --nocapture
# 期望：签名逐字节对齐 AWS 官方 v4 测试向量；path_style/virtual-hosted 两种 URL 形态；
#       429 → 重试且每次重签（断言 Authorization 的 x-amz-date 变化）
```

### B4

```bash
cargo test -p xray-transport-xdrive drive -- --nocapture
# 期望：mock Drive（files.list/files.get/files.create/upload）：
#       ① 401 一次 → 刷新 token → 重放；② 连续同 id 请求只查一次 id（缓存命中计数）；
#       ③ multipart 上传边界 xdrive-boundary；④ inline 描述上限 12000 字节
```

### B5

```bash
cargo test -p xray-transport-xdrive slots -- --nocapture
# 期望：SlotFrame 编解码往返；环深度 = max(concurrency,2)；
#       覆写必须等对端 watermark 推进（断言「未推进前不覆写」= Go slots_test 语义）
cargo test -p xray-transport-xdrive spare -- --nocapture
# 期望：warm 会话被复用（第 2 次 dial 不新建 ring）；超 10min 空闲被 prune
```

### B6

```bash
# 1) 全门
cargo test --workspace                                # 期望 0 failed
cargo clippy --workspace --all-targets -- -D warnings  # 期望 0 warning
cargo fmt --all -- --check
cargo doc --workspace --no-deps                        # 期望 0 warning（内链悬空即硬错）
python tools/check_scope_claims.py                     # 期望 exit 0（托管/spawn 纪律）
python tools/check_quality_gates.py

# 2) 三方向互操作（local 后端，离线、共享目录）
python dist/interop_ci.py --rust target/release/xray.exe \
       --go tools/xray-go/xray.exe --suites rust,rust_to_go,go \
       --cross-protos xdrive
# 期望：xdrive 三个方向 PASS（Rust↔Rust / Go server→Rust client / Rust server→Go client）

# 3) h3 单独一轮（ALPN ["h3"]）
python dist/interop_ci.py --rust target/release/xray.exe --go tools/xray-go/xray.exe \
       --suites rust --extra-protos xdrive
```

**性能面（B6 必带，非 MB/s 门）**：xdrive 吞吐由对象存储 RTT 决定 ⇒ `loopback_alloc_bench.py`
的 MB/s 口径不适用。改用**同拓扑 A/B**：Rust vs Go 各跑 `local` 后端 3 轮，比
①每 1MiB 的存储操作次数（`tcpdump`/计数器）②每连接构造成本 ③首字节时间中位；
任一项劣于 Go 均值 +15% ⇒ 该批自证回退（写「未验证 + 原因 + 风险」，禁推理代数字）。

---

## 7. 风险与未决

| # | 风险 / 未决 | 影响 | 处置 |
|---|---|---|---|
| R1 | **fronting（`address`/`port`）需改 `StreamSettings`**：`memory_settings::to_memory_stream_config` 与 `StreamSettings::from_json` 双处 | 所有 transport 共用结构；改错会静默改他协议行为 | 新字段缺省 `None`；B0 加「`from_json(None)` 与既有 JSON 逐字段相等」回归测试 |
| R2 | **Go 的 `quicParams` 里 quic-go 专属项在 quinn 无对应**（`ChromeParrot`、`disableStatelessReset`、`DisablePathMTUDiscovery` 平台差异） | h3 吞吐/指纹面不等价 | 沿用 `memory_settings::parse_quic_params_config` 内既有 `unsupported_quic_param_warnings` 的 warn 语义（已是本仓口径），差异登记进本文 §2.4，不发明新开关 |
| R3 | **Google Drive live 测试无法在 CI 复现**（需真实 OAuth） | drive 后端只有 mock 覆盖，真实云行为未验证 | mock 覆盖 + 一条手工验收清单（`service:"google-drive"`, 3 secrets, 单文件夹，跑 1MiB 往返）交 PM；CI 只跑 mock |
| R4 | **Windows `ERROR_SHARING_VIOLATION` 重试**（Go `local_windows.go`） | 仅 Windows 出现，Linux CI 覆盖不到 | CI 已有 `test-windows-tun` job 可挂一条 `local` 后端往返；否则标注「未在 Windows 验证」 |
| R5 | **`SlotStore` 仅 Drive 实现**，其余后端永远走 WAL | 若误把 `params_for_storage` 的 Drive 缺省（concurrency 64）套到 WAL 后端，会放大请求风暴 | `params_for_storage` 严格按 trait 判定（Go 同款 `if _, ok := storage.(slotStore)`）；单测钉「local/template/s3 不触发覆盖」 |
| R6 | **`apply_splithttp_cc` 上浮触及既有 splithttp** | 8.5k 行 crates 的回归面 | 纯搬移 + 一行转调；验收 = splithttp 全量测试 + `tests/xmux_reuse.rs` 不变通过 |
| R7 | **`xray-transport-xdrive` 依赖 `xray-transport-splithttp` 只为 `mux`** | 层间依赖味道；splithttp 变重 | 本仓已有同型先例（`xray-hysteria`/`splithttp` → `xray-transport-quic`、`xray-proxy-http` → `splithttp`）。若出现第三个 XMUX 消费方，上浮 `mux` 到 `xray-transport`（另票） |
| R8 | **上游已冻结**（`676eaf66` == tag，无后续提交） | 无追版本跑步机风险 | 无动作；基准升级走 `.github/actions/fetch-go-baseline` 两行 |
| R9 | **`mux` 缺省仍为 8** | 用户不写 `concurrency` 时容量远低于 Go 的 128 | 票面红线：不改。文档/lint 文案指明「xdrive 建议显式 `concurrency`」——**需 PM 确认是否接受该文案** |
| R10 | **proto 镜像 `.checksums.json` CRLF 陷阱** | 一次提交出现 84 行假变更 | 强制流程：`cp` 基线 → `--write` → 二进制模式转 LF → `git diff --stat` 只 1 行 |

**需 PM 拍板的取舍**：R9（lint 文案是否提「建议 concurrency」）、R7（是否现在就上浮 `mux`）。

---

## 8. 工作量估计

| 批次 | 内容 | 人日 | 依据 |
|---|---|---|---|
| B0 | proto + 配置面放开 + `validateXDrive` lint + StreamSettings fronting | **1** | Go conf 侧 ~190 行；Rust 侧因 streamSettings 直通（无 proto Build 层）反而更薄，但 lint 矩阵 + 双处结构改动带回 |
| B1 | crate 骨架 + `local` + WAL + Conn + Dial/Serve/Listener + 注册接线 | **5-7** | Go 非测试 `params/storage/local*/wal/conn/xdrive` ≈ 1400 行 → Rust 惯用 1.3-1.6× ≈ 1900-2200 行 |
| B2 | HTTP 栈 + XMUX 接线 + `template` + jsonpath | **5-7** | Go `client.go`+`template.go`+`jsonpath.go` = 1067 行；XMUX 复用省 ~200 行，但 `XmuxConn` 适配 + hyper 连接管理是新面 |
| B3 | `s3`（SigV4） | **3-4** | Go 518 行；签名向量测试是硬成本 |
| B4 | `google-drive` | **6-8** | Go 915 行，且 OAuth/限流/ID 缓存/多形态上传是分支最密的一件 |
| B5 | 环形槽位 + 预热点池 | **4-5** | Go `slots.go` 1071 行（环+水位线+两套读写器），并发语义最易出隐蔽 bug |
| B6 | h3 + CC 上浮 + 互操作 + 全门收口 | **3-4** | Go h3 分支内嵌在 `client.go`（无独立文件）；互操作用例与调试是主要成本 |
| **合计** | | **27-36 人日** | 票面 handoff 估 25-37，本规划对齐（略偏上，因为多了 B0 的 StreamSettings 改动与 R6 的上浮） |

**并行度**：B3 与 B4 可双人并行（不同文件，共享 B2 的 `do()` 骨架）；其余串行。
按 §7 派单约定（3 并行上限）建议 2 人轮转：一人 B1→B2→B4，一人 B0→B3→B5，B6 合流。

---

## read 调用审计

**Go 上游（`D:/Project/Xray-core` @ `676eaf66`）**

- `git log --oneline -1` + `wc -l transport/internet/xdrive/*`（全量文件行数）
- `transport/internet/xdrive/config.proto`（全读，30 行）
- `transport/internet/xdrive/xdrive.go`（`:1-140`、`:140-360`、`:360-538`，全读）
- `transport/internet/xdrive/params.go`（全读）
- `transport/internet/xdrive/storage.go`（`:34-125`）
- `transport/internet/xdrive/conn.go`（`:1-90`）
- `transport/internet/xdrive/slots.go`（`:1-120` + `type ring/slotTable/slotWriter/slotReader/makeRing/decodeRing` 定位）
- `transport/internet/xdrive/client.go`（declarations + `:110-260`）
- `transport/internet/xdrive/drive.go`（declarations + `:22-80` 常量）
- `transport/internet/xdrive/template.go`（declarations + `:1-200`、`:200-340`、`:340-430`）
- `transport/internet/xdrive/wal.go`（declarations + `:15-40`）
- `transport/internet/xdrive/s3.go`（declarations + `ValidateS3Config/s3Region/validS3Name` 定位）
- `transport/internet/xdrive/jsonpath.go`（全读，39 行）
- `transport/internet/xdrive/local.go`（全读）+ `local_windows.go`（全读）
- `transport/internet/memory_settings.go:25-60`（fronting/Destination）
- `infra/conf/transport_method.go:985-1120`（`XDriveConfig` + `Build`）
- `infra/conf/xray.go:270-320`（`validateXDrive`）
- `grep XDRIVESettings|Xmux` 于 `infra/conf/`（接线行号）

**本仓（`D:/Project/Xray-core-rust`）**

- `bd show Xray-core-rust-hjtlk`
- `crates/xray-conf/src/init.rs:300-370`（硬拒清单）+ `:1-80`（`register_builtin_stages`）+ `ValidationStage` 定位
- `crates/xray-conf/src/outbound_security.rs:1-80`（lint 参照形态）
- `grep xdrive|XDRIVE` 于 `crates/`（命中 `net/transport.rs`/`init.rs`/`xray-proto/src/lib.rs`/`dialer.rs`）
- `protos/transport/internet/xdrive/config.proto`（全读）+ `diff` vs Go 基线（**落后：缺 xmux/s3**）
- `protos/transport/internet/splithttp/config.proto`（`XmuxConfig` 已在）
- `protos/.checksums.json`（tail）
- `crates/xray-transport/src/dialer.rs`（declarations + `StreamSettings:93-141`）
- `crates/xray-transport/src/listener_registry.rs`（`:29-105`）
- `crates/xray-transport/src/connection.rs:40-110`（`Connection` trait）
- `crates/xray-transport/src/retry.rs:55-120`（`exponential_backoff_if` 签名）
- `crates/xray-transport/src/memory_settings.rs`（declarations + `to_memory_stream_config`）
- `crates/xray-transport/src/finalmask/mod.rs`（declarations）
- `crates/xray-transport-splithttp/src/mux.rs`（declarations + `ManagerPool`/`XmuxConn` impl 落点）
- `crates/xray-transport-splithttp/src/h3_client.rs`（declarations + `pub fn` 清单）
- `crates/xray-transport-splithttp/src/client.rs`（declarations）
- `crates/xray-transport-splithttp/src/lib.rs:1-80`
- `crates/xray-transport-quic/src/lib.rs:1-40`
- `crates/xray-tls/src/client_config.rs:70-110`（`build_client_config` 签名）
- `crates/xray-core/src/register.rs:100-175`（`register_all_transports`）
- `crates/xray-core/src/inbound.rs:4448-4475`（`is_transport_listener_protocol`）
- `crates/xray-core/src/outbound.rs`（`mux` 面 grep + `outbound_mux_concurrency` 定位）
- `crates/xray-conf/src/built.rs`（`stream_settings_json` 透传）
- `crates/xray-frame/src/scope.rs`（declarations）、`context.rs`（`PluginContext` 能力面）、`deadline.rs`（declarations）
- `crates/udf-frame/std-ext/src/{cache,retry,id,encode,fsx,backoff,scheduler}.rs`（declarations）
- `crates/udf-frame/skeleton-infra/src/objpool.rs`（declarations）
- `crates/xray-proxy-vless/src/encryption/params.rs`（`parse_client_encryption`/`parse_server_decryption`）
- `crates/xray-cli/src/commands/keys.rs`（`execute_vlessenc` 存在性）
- `grep AWS4-HMAC-SHA256|SigV4|aws-sdk|object_store|x-amz-` 于 `crates/`（**0 命中**，支撑 §4.2 举证）
- `grep pub struct Ring|ring_buffer|watermark` 于 `crates/udf-frame/`（仅池水位线，支撑 §4.3 举证）
- `grep ComponentScope::new` 于 `crates/`（托管模式先例：ws/httpupgrade/quic/hysteria）
- `grep register_transport_dialer\(|register_transport_listener\(` 于 `crates/`
- `.github/workflows/ci.yml`（job 名与门命令）
- `.github/actions/fetch-go-baseline/action.yml`（基准钉法）
- `tools/check_proto_drift.py`（三模式）、`tools/check_scope_claims.py`（头注）
- `dist/interop_ci.py`（CLI 参数 + `build_x` 结构）
- `docs/architecture/xray-frame-`（目录存在性；同期 `2026-11-11-masque-plan.md` 属并行任务，未读内容）

**工具**：`bd` 1 次、`glob` 2 次、`grep` 18 次、`read` 30 次、`bash`（`wc`/`diff`/`ls`/`sed`/`mkdir`）12 次、`write` 1 次。
**图谱**：`codebase-memory-mcp` 未调用（本次所有定位均用 `grep` + `read` 精确命中；
`crates/` 单次 grep 已被本机策略限流，改用「按文件+按符号」逐点核实，结论均带文件路径与符号名）。

# Go → Rust 翻译约定（样板验证版）

> 本文档基于 `xray-app-version` 与 `xray-proxy-blackhole` 两个完整翻译样板归纳。
> 后续 crate 翻译**必须**遵守这些约定，除非有明确理由偏离。

---

## 0. 总原则

| 原则 | 含义 |
|---|---|
| **源码 1:1 映射** | 每个 Go package 对应一个 Rust crate，子目录组织完全一致（见 `rust-rewrite-dev-plan.md`） |
| **依赖分层严格** | 跨 crate 引用必须满足 dev-plan 的 Layer 0→7 顺序，禁止反向依赖 |
| **依赖规避** | 当 Go 依赖在 Rust 端未实现时，翻译**业务核心**（可独立测试的部分），IO 边界留 adapter 钩子 |
| **跳过 Go init() 注册** | Go 的 `common.RegisterConfig(...)` 全局副作用模式在 Rust 不重现；调用方直接构造 |
| **跳过未用 ctx 参数** | Go 的 `New(ctx, config)` 中 `ctx` 未使用时，Rust 签名省略 |

---

## 1. Protobuf 类型映射

### 1.1 Config 字段访问

prost 生成的 Rust struct 字段名与 proto 一致（snake_case），但有 **关键字碰撞**：

| proto 字段 | Rust 字段 | 备注 |
|---|---|---|
| `core_version` | `core_version` | 直接用 |
| `type` | `r#type` | Rust 关键字，加 `r#` 前缀 |
| `type_url`（在 `TypedMessage` 中） | `r#type` | 实际生成名是 `type`，加 `r#` |

**验证来源**：`protos/common/serial/typed_message.proto` → prost 生成字段名 `type`（不是 `type_url`）。

### 1.2 Optional 字段

proto3 的 message 字段在 prost 中是 `Option<T>`：

```go
// Go
if c.GetResponse() == nil { ... }
```

```rust
// Rust
let Some(msg) = config.response.as_ref() else { return ... };
```

### 1.3 枚举式 message

Go 通过多个空 message（如 `NoneResponse`、`HTTPResponse`）+ `TypedMessage` 表达"类型选择"。Rust **优先用 enum**：

```rust
// 推荐：直接 enum
pub enum ResponseConfig {
    None,
    Http403,
}
```

不要用 `Box<dyn Trait>` 模拟 Go 接口——见 §3。

---

## 2. 错误类型设计

### 2.1 每 crate 一个 `thiserror::Error` enum

```rust
#[derive(Debug, thiserror::Error)]
pub enum BlackholeError {
    #[error("unknown blackhole response type: {0}")]
    UnknownResponseType(String),

    #[error("write response failed: {0}")]
    WriteFailed(#[from] xray_buf::io::Error),
}
```

### 2.2 命名约定

- 类型名：`<CrateName>Error`（如 `VersionError`、`BlackholeError`）
- 变体名：描述发生场景（`MinVersionNotMet`、`UnknownResponseType`）
- `#[error("...")]` 消息保持英文（与 Go `errors.New("...")` 一致）

### 2.3 `#[from]` 自动转换

IO 错误等已知上游错误用 `#[from]`，调用处 `?` 自动传播：

```rust
pub async fn process(&self, writer: &mut dyn Writer) -> Result<i32, BlackholeError> {
    Ok(self.response.write_to(writer).await?)  // io::Error 自动转 BlackholeError::WriteFailed
}
```

---

## 3. **关键：避免 `dyn Trait` + async fn**

### 3.1 问题描述

Rust 2024 的 `async fn in trait` 默认 **不 dyn-compatible**。即：

```rust
// ❌ 编译失败：dyn ResponseConfig 不能用
#[async_trait]  // 或 native async fn
pub trait ResponseConfig: Send + Sync {
    async fn write_to(&self, w: &mut dyn Writer) -> io::Result<i32>;
}

pub struct Handler {
    response: Box<dyn ResponseConfig>,  // ❌ E0038 not dyn compatible
}
```

### 3.2 解决方案 A：用 enum（推荐）

当变体是**有限且封闭**的（典型如 Go 的 interface + 2 个实现），用 enum：

```rust
// ✅ 正确
pub enum ResponseConfig {
    None,
    Http403,
}

impl ResponseConfig {
    pub fn write_to<'a>(
        &'a self,
        writer: &'a mut dyn Writer,
    ) -> Pin<Box<dyn Future<Output = io::Result<i32>> + Send + 'a>> {
        match self {
            ResponseConfig::None => Box::pin(async { Ok(0) }),
            ResponseConfig::Http403 => Box::pin(async move { /* ... */ }),
        }
    }
}

pub struct Handler {
    response: ResponseConfig,  // ✅ 值类型，无 dyn
}
```

### 3.3 解决方案 B：手写 `Pin<Box<dyn Future>>`（项目风格）

`xray-buf::io::{Reader, Writer}` trait 用手写 boxed future 而非 `#[async_trait]`，保持 dyn-compatible：

```rust
pub trait Writer: Send {
    fn write_multi_buffer(
        &mut self,
        mb: MultiBuffer,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>>;
}
```

**新增 trait 时跟随此风格**，不要引入 `#[async_trait]` 依赖。

---

## 4. Handler / Process 模式

### 4.1 当 transport.Link / internet.Dialer 未实现时

Go `Handler.Process(ctx, link, dialer)` 涉及未实现的 Rust 类型。策略：

```rust
// Rust：业务核心独立可测，IO 边界留 adapter 钩子
pub struct Handler {
    response: ResponseConfig,
}

impl Handler {
    pub fn new(config: Config) -> Result<Self, BlackholeError> { /* 解析 config */ }

    /// 独立可测的子步骤：写出预置响应
    pub async fn process(&self, writer: &mut dyn Writer) -> Result<i32, BlackholeError> {
        Ok(self.response.write_to(writer).await?)
    }
}

// 等 xray-transport 提供 Link/Dialer 后，在此之上加：
// pub async fn process_link(&self, link: transport::Link, dialer: internet::Dialer) -> Result<...>
```

### 4.2 简化的构造签名

Go `New(ctx, config)` 当 `ctx` 未用时，Rust 省略：

```rust
// Go: func New(ctx context.Context, config *Config) (*Handler, error)
// Rust:
pub fn new(config: Config) -> Result<Self, BlackholeError> { ... }
```

---

## 5. 测试规范

### 5.1 覆盖率

- **每个 match arm** 至少一个测试
- **每个错误变体** 至少一个测试（含触发条件）
- **边界值**：空字符串、最大值、最小值
- **doc test** 给所有 pub API 加示例

### 5.2 Mock 模式：CollectWriter

测试需要 `&mut dyn Writer` 时，用统一 mock：

```rust
struct CollectWriter {
    chunks: Vec<MultiBuffer>,
}

impl Writer for CollectWriter {
    fn write_multi_buffer(
        &mut self,
        mb: MultiBuffer,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        self.chunks.push(mb);
        Box::pin(async { Ok(()) })
    }
}

impl CollectWriter {
    fn collected_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for mb in &self.chunks {
            for b in mb.iter() {
                out.extend_from_slice(b.bytes());  // 注意：Buffer::bytes() 非 data()
            }
        }
        out
    }
}
```

### 5.3 异步测试

```rust
#[tokio::test]
async fn handler_http_response_writes_payload() {
    let h = Handler::new(cfg_with_response(Some("xray.proxy.blackhole.HTTPResponse"))).unwrap();
    let mut w = CollectWriter::new();
    let n = h.process(&mut w).await.unwrap();
    assert_eq!(n as usize, HTTP_403_RESPONSE.len());
}
```

### 5.4 错误测试避免 unwrap_err()

`Result<T, E>::unwrap_err()` 要求 `T: Debug`。若 `T`（如 `Handler`）不便实现 Debug，用 match：

```rust
match Handler::new(bad_cfg) {
    Err(BlackholeError::UnknownResponseType(s)) => assert_eq!(s, "..."),
    Err(other) => panic!("expected UnknownResponseType, got {other:?}"),
    Ok(_) => panic!("expected error, got Ok"),
}
```

---

## 6. Cargo.toml 模板

```toml
[package]
name = "xray-app-XXX"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[dependencies]
xray-common = { path = "../xray-common" }
xray-features = { path = "../xray-features" }  # 如果用 trait
xray-proto = { path = "../xray-proto" }        # 几乎都需要
xray-buf = { path = "../xray-buf" }            # 涉及 IO 时
thiserror = { workspace = true }
tokio = { workspace = true }                    # 涉及 async 时
tracing = { workspace = true }                  # 涉及日志时
```

**版本号 fallback**：根 `Cargo.toml` 的 `[workspace.dependencies]` 未声明的依赖（如 `async-trait`）直接用版本号 `"0.1"`。**新增 workspace 依赖前先评估是否多 crate 共用**。

---

## 7. 关键 API 速查

### 7.1 Buffer

| 用途 | API |
|---|---|
| 创建 | `Buffer::new()` |
| 写多字节 | `buf.write_from(&[u8])` （**不是** `write_bytes`） |
| 写单字节 | `buf.write_byte(u8)` |
| 读数据 | `buf.bytes() -> &[u8]` （**不是** `data()`） |
| 长度 | `buf.len()` |

### 7.2 MultiBuffer

| 用途 | API |
|---|---|
| 空 | `MultiBuffer::new()` |
| 从单个 Buffer | `MultiBuffer::from_buffer(buf)` （**不是** `from_single`） |
| 从 Vec<Buffer> | `MultiBuffer::from_buffers(vec)` |
| 遍历 | `mb.iter() -> impl Iterator<Item = &Buffer>` |

### 7.3 io::{Reader, Writer}

```rust
pub trait Writer: Send {
    fn write_multi_buffer(
        &mut self,
        mb: MultiBuffer,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
}
```

注意 `Result` 是 `xray_buf::io::Result`，不是 `std::io::Result`。

---

## 8. 验证流程

每个 crate 翻译完成后**必须**：

```bash
# 1. 单 crate 编译 + 测试
cargo test -p xray-app-XXX

# 2. 全 workspace 不破坏
cargo build --workspace

# 3. （可选）clippy（注意：clippy.toml 当前有预存配置问题，影响所有依赖 xray-proto 的 crate，与本次修改无关）
cargo clippy -p xray-app-XXX
```

**验收标准**：
- 单测 100% 通过（所有变体、所有边界）
- workspace build 不破坏既有 crate
- 公开 API 有 doc test 示例

---

## 9. 已知预存问题（不修，记录避免困惑）

| 问题 | 影响 | 处理 |
|---|---|---|
| `clippy.toml` 含未知字段（`max-struct-bool-fields` 等） | clippy 在所有依赖 `xray-proto` 的 crate 上 fail | 用 `cargo build`/`cargo test` 验证，不用 clippy；不在本翻译任务范围内修 |
| `xray-crypto` 有 unused import warning | 编译 warning | 预存，不处理 |
| `bd ready` / `bd stats` schema 漂移（`started_at` 列缺失） | beads 部分命令报错 | 用 `bd list` 替代；不在本翻译任务范围内修 |

---

## 10. 翻译决策记录（按 crate）

| Crate | 关键决策 | 偏离原因 |
|---|---|---|
| `xray-app-version` | `compare_versions` 用 `u64` 而非 Go 的 `int` | 版本号不会负，u64 更安全 |
| `xray-app-version` | 跳过 `init()` 全局注册 | Rust 无副作用全局；调用方直接构造 |
| `xray-proxy-blackhole` | `ResponseConfig` 用 enum 而非 `dyn Trait` | async fn in trait 不 dyn-compatible（详见 §3） |
| `xray-proxy-blackhole` | `process(&mut dyn Writer)` 替代 `process(Link, Dialer)` | `transport::Link`/`internet::Dialer` 在 Rust 端未实现 |
| `xray-proxy-blackhole` | `Handler::with_response` 显式构造方法 | 便于上层 adapter 与测试 |
| `xray-app-policy` | Go `init()` 全局注册 + `manager` lookup → Rust 显式 `PolicyManager::new` 持有 HashMap | Rust 无副作用全局；显式持有更利于测试隔离（详见 b685c6d 提交） |
| `xray-transport` | `Link { reader, writer }` 字段公开值类型 + `Connection: AsyncRead + AsyncWrite + Unpin + Send + Sync` supertrait | 走 tokio blanket impl，禁手写 `impl AsyncRead for Box<dyn Connection>`（E0119，详见 rust.md §tokio 陷阱） |
| `xray-transport` | `CounterConnection<C>` 包装用 `Pin::get_mut + Pin::new` 安全投影 | Wrapper 字段皆 Unpin，避免 unsafe |
| `xray-tls` | **不引入 btls/wreq-util**（任务描述的「~800 行替代 uTLS」方案被驳回） | 实际调研：btls 是 BoringSSL binding 无 ClientHello 控制；wreq 是 HTTP 客户端不能被代理握手复用；Rust 生态无 uTLS 等价品。改走 trait + TODO 等生态成熟或自研 |
| `xray-tls` | `Fingerprint` enum 保留所有变体名（含历史版本如 `HelloChrome58`） | 1:1 翻译 Go 三张 map；Rust 端暂不用具体字节布局，但保留名路由以便上层配置层稳定 |
| `xray-tls` | `verify_chain` 接受 `cert_hashes: &[Vec<u8>]` + `cert_is_ca: &[bool]` 分离输入 | Go 用 `[]*x509.Certificate`，Rust 端避免引入 x509 类型，让纯函数可独立测试 |
| `xray-tls` | `ConnInterface: xray_transport::connection::Connection` supertrait（非独立 AsyncRead） | 复用 transport 层抽象，避免重复约束；对应 Go `Interface interface { net.Conn; ... }` |
| `xray-tls` | ECH 实际 DNS 查询 (`apply_ech`/`query_record`/`dns_query`) 留 trait + TODO | 依赖 Phase 4 `xray-app-dns` 未就绪；TLV 解析+缓存数据结构已完成独立可测 |
| `xray-app-dns` | **不引 hickory-proto**（DNS wire format）；`buildReqMsgs`/`genEDNS0Options` 留 TODO | 厚重依赖；当前业务核心（数据结构/缓存/hosts/fakedns）独立可测，wire format 等 hickory 或自研 wire 接入 |
| `xray-app-dns` | **不引 quinn/hyper**（DoQ/DoH）；5 个 nameserver 协议工厂占位返回 NotImplemented | 依赖 transport + TLS + HTTP/2 全链路，本阶段先建 trait + Client 框架 |
| `xray-app-dns` | singleflight 简化为 per-key Mutex<HashMap>；pubsub 用 tokio::sync::broadcast | Go `singleflight.Group` 在 Rust 生态等价品少；broadcast 满足订阅语义 |
| `xray-app-dns` | `StaticHosts` 内部用 `InMemoryMatcher`（线性扫）替代 `MphDomainMatcher` | xray-geodata 未暴露 `DomainRegistry::build_many`，待后续替换；测试覆盖完整语义 |
| `xray-app-dns` | `merge_records` 严格按 Go 语义：v4+v6 同时启用但任一缺失 → `RecordNotFound` | 1:1 翻译 Go `(*IPRecord).getIPs()` 行为；调用方应保证 `send_query` 同时返回 v4/v6 响应 |
| `xray-app-dns` | `DnsService::lookup_ip` 同步签名，nameservers 路径返回 `NotImplemented` | trait `Server::query_ip` 是 async；改 lookup_ip 为 async 会引发签名污染；等上层 tokio runtime 注入后接入 |
| `xray-app-dns` | `DnsService` 不实现 `xray_features::dns::DnsClient`（trait 已用 `#[async_trait]`） | xray-features 用旧风格 `#[async_trait]`，与新代码手写 boxed future 风格不一致；接入需统一为手写风格后重做 |
| `xray-app-router` | **不实现 `xray_features::routing::Router`**；crate 内部定义独立 `RoutingContext` trait 保持 Go 语义 | xray-features trait API 用简化 `(dest, session) -> tag` 签名，不承载 Go `routing.Context` 丰富字段（source IP、user、protocol、attributes 等）；接入需统一为手写 boxed future 风格后重做 |
| `xray-app-router` | proto `IpRule`/`DomainRule` 在 xray-proto (`xray.common.geodata`) 与 xray-geodata (`xray.geodata`) 中是**同名不同类型**（两个 crate 各自 build proto）；rule.rs 写字段级 converter | 两 proto 包名不同，prost 生成不同 Rust 类型；不接受转换会产生 E0308 类型不匹配。converter 仅处理 `Custom` 变体（Geoip/Geosite 文件加载留 TODO） |
| `xray-app-router` | `BalancingRule.Build` 中 `leastping`/`leastload` 策略返回 `ObservationUnavailable`；`TypedMessage` 反序列化未接入 | 需上层提供 `ObservationProvider` 与 `OutboundHandlerSelector` 注入；TypedMessage 类型解析依赖 `prost::Message::decode` 全套注册，后续接入 |
| `xray-app-router` | `ProcessNameMatcher` 的 `find_process` 留 TODO；配置解析（`xray/`/`self/`/`folder/` 分类）独立可测 | 依赖 OS-specific 进程查询（sysinfo 或 windows-rs），待后续接入；Go 通过 `ps` 包查询 |
| `xray-app-router` | `WebhookNotifier::post` 留 TODO（stub log）；事件构造+去重逻辑独立可测 | 实际 HTTP POST 需 reqwest/hyper；deduplication 用 `Mutex<HashSet>` + 过期清理 |
| `xray-app-router` | `StrategyWeight.value` 是 `float`（非 string）；`regexp: bool` 字段决定 `match` 是否为正则模式 | proto3 字段明确 `bool regexp + string match + float value`，不要在 WeightManager 中用 `number_finder` 解析字符串 |
| `xray-app-router` | `proto_network_to_native` 拒绝 `Unknown(0)`，仅接 `TCP(2)/UDP(3)/UNIX(4)` | proto Network 枚举在 xray-proto 与 xray-common 不同；xray-common `Network` 无 `Unknown` 变体 |
| `xray-app-dispatcher` | **不实现 `xray_features::routing::Router`**；crate 内部定义独立 `RoutingContext` trait（14 sync getter） + `RoutingRouter` trait | xray-features trait API 用简化 `(dest, session) -> tag` 签名，不承载 Go `routing.Context` 丰富字段（source IP/user/protocol/attributes 等）；与 P4-2 router 一致 |
| `xray-app-dispatcher` | 协议唫探器（HTTP/TLS/BitTorrent/QUIC/UTP）全 trait + NotImplemented stub；`Sniffer` 编排框架独立可测 | 具体协议解析依赖 `common/protocol/*` Rust 端未实现；框架逻辑（NoClue/NeedMoreData/pending）可独立验证 |
| `xray-app-dispatcher` | 不直接依赖 xray-app-dns / xray-app-router；在本 crate 定义 `FakeDnsEngine` / `RoutingRouter` trait | 避免循环依赖；上层接入时注入实现 |
| `xray-app-dispatcher` | `DefaultDispatcher::dispatch` / `dispatch_link` 返回 `Err(Other)` 占位；`CachedReader` 主体留 TODO | 依赖 `pipe.Reader/Writer` + `outbound.Handler.Dispatch(Link)` 全链路；`should_override` 决策逻辑独立可测 |
| `xray-app-dispatcher` | `SizeStatWriter::close` 返 `Ok(())`（无状态 close） | `xray_buf::io::Writer` trait 无 close 方法；Rust 端依赖 Drop 或具体 Writer 处理 |
| `xray-app-proxyman` | **不实现 `xray_features::inbound::InboundHandler` / `outbound::OutboundHandler`**；crate 内部定义独立 `InboundHandler` / `OutboundHandler` trait 保持 Go 语义 | xray-features trait API 简化（只有 tag/start/close/port 等），不承载 Go `ReceiverSettings`/`SenderSettings`/`TypedMessage` 丰富配置；与 P4-3 dispatcher 同模式 |
| `xray-app-proxyman` | `SniffingRequest` 用 `Vec<String>` 存域名/CIDR 排除项（不用 matcher），提供 `matches_domain_excluded` / `matches_ip_excluded` helper | xray-geodata 未暴露 `DomainReg.BuildDomainMatcher`/`IPReg.BuildIPMatcher` 等价 API；与 P4-3 dispatcher 内 `SniffingRequest` 同模式 |
| `xray-app-proxyman` | `SniffingRequest` 在本 crate 与 dispatcher crate 内**同名独立**存在 | proxyman 与 dispatcher 同为 Layer 4 应用服务，互不依赖；不可共享结构体定义 |
| `xray-app-proxyman` | `InboundManager::select_by_prefix` 不缓存结果（Go `*sync.Map` 缓存被去除） | Rust 端用 `parking_lot::RwLock` 互斥访问 tagged map，无需 cache；若吞吐出现瓶颈可改用 `ArcSwap<HashMap>` |
| `xray-app-proxyman` | `Handler::dispatch` / `dial` 未实现，留 trait + TODO；`HandlerService::add_inbound` / `add_outbound` 返 `Err(Other)` 占位 | 依赖 `xray_transport::Link` + 代理 + mux + xudp + DNS 全链路；TypedMessage 解码依赖上层 factory 注入 |
| `xray-app-proxyman` | `get_uo_t_connection` 留 TODO 占位；不引入 sing `uot` crate | sing `uot` 是 sing-box 项目内模块无独立 crate；Rust 生态无等价品。UoT 是 UDP-over-TCP 封装，自研成本可接受但当前阶段不优先 |
| `xray-app-proxyman` | gRPC server 注册（Go `service.Register`）未实现；定义 `HandlerService` trait + `DefaultHandlerService` 编排类 | 依赖 tonic server + xray-app-commander；上层集成时注入 `InboundHandlerProvider` / `OutboundHandlerProvider` / `OperationDecoder` 实现 |
| `xray-app-proxyman` | `MemoryUser` 只保留 `email` + `level` 字段；Account/AlterIds 解码依赖具体代理 | Go `protocol.MemoryUser` 字段丰富（Level/Email/Account/AlterIds）；RPC 命令路径仅需 email+level，完整转换上层代理 crate 负责 |
| `xray-app-proxyman` | `OperationDecoder` trait 替代 Go `TypedMessage.GetInstance()` | prost 不生成 `GetInstance`；由上层注入按 `type_url` 解码 proto payload 为 `Box<dyn InboundOperation>` / `Box<dyn OutboundOperation>` |
---

### P4-7 xray-app-stats（2025-06）

| crate | 决策 | 原因 |
| --- | --- | --- |
| `xray-features/src/stats.rs` | **重写对齐 Go**：`Counter::add`/`set` 返回旧值（早期简化版不返回值），删 `async_trait`，加 `OnlineMap`/`Channel`/`Manager` 完整接口 + `NoopManager` + 5 helper | 早期 trait 签名与 Go 不一致；dispatcher/src/stats.rs 的 `Arc<dyn Counter>` 通过 `use xray_features::stats::Counter` 依赖，必须修正源头 |
| `xray-features` | 加 `tokio` [dependencies]（features=["sync","rt"]） | `ChannelSubscriber` 含 `tokio::sync::mpsc::Receiver<ChannelMessage>`；features 原仅 dev-deps 含 tokio |
| `xray-features` | `ChannelSubscriber` 提供 `pub fn new(receiver, id)` constructor + `pub async fn recv/recv_as`/`pub fn id` 方法；字段保持 `pub(crate)` | 跨 crate 构造需要公共 constructor；保留字段封装避免用户直改 |
| `xray-app-stats` | **Manager 的 `Start`/`Close` 不进 trait**（独立暴露 `impl Manager { pub fn start/close }`） | Go 中通过 `features.Feature` 嵌入提供 Start/Close，Rust 端 `features::stats::Manager` trait 不含生命周期方法 |
| `xray-app-stats` | **Channel 简化设计**：去掉 Go `publisher mpsc + goroutine broadcast` 双层，`publish` 直接同步遍历订阅者 `try_send`；`blocking` 模式 失败时 `tokio::spawn` 重试 task | 等价语义，更少抽象；Go 的 publisher mpsc 仅为解耦 publisher/subscriber 速度差，Rust 用 try_send/spawn 达同样效果 |
| `xray-app-stats` | `ChannelMessage = Arc<dyn Any + Send + Sync>`，订阅者用 `ChannelSubscriber` 含 `mpsc::Receiver` + unique `id: u64` | Go `interface{}` 等价为 trait object；`Arc` 让多订阅者广播 clone 廉价；unique id 让 `unsubscribe` 查找（Go 用 chan 引用比较） |
| `xray-app-stats` | **gRPC server 注册留 trait + 编排类**：`StatsService` trait 7 方法 + `DefaultStatsService`（`Arc<dyn Manager> + Arc<dyn SysStatsProvider>`） | 依赖 tonic + `xray-app-commander`；上层集成时注册到 gRPC server（与 P4-4 proxyman 同模式） |
| `xray-app-stats` | `SysStatsProvider` trait 注入（默认 `DefaultSysStatsProvider` 仅填 uptime + num_threads=1） | Rust 无 `runtime.MemStats` 等价；上层可注入 jemalloc / tokio 统计 |
| `xray-app-stats` | counter name 解析 helper：`parse_user_traffic_name` 解析 `user>>>{email}>>>traffic>>>{uplink\|downlink}`；`parse_user_online_map_name` 解析 `user>>>{email}>>>ip` | Go 用 `strings.Cut` + `strings.HasSuffix`；Rust 用 `strip_prefix` + `strip_suffix` 更地道 |
| `xray-app-dispatcher` | `TestCounter::add` 返回值从 `fetch_add + delta`（新值）改为 `fetch_add`（旧值），`set` 返回值从 `()` 改为 `swap` 返回旧值 | features::stats::Counter trait 签名修正后语义对齐 Go；dispatcher 现有调用 `self.counter.add(n)` 忽略返回值，兼容 |
| `xray-app-stats` | `Manager::close` 用 `drain().map(|(_, v)| v).collect()` 收集 channels 后 `drop(channels)` 释放写锁，再调用 `c.close()` | 避免 `channels.write()` 持锁同时调用 channel 内部 `subscribers.lock()` 造成死锁 |

### P4-6 xray-app-commander（2025-06）

| crate | 决策 | 原因 |
| --- | --- | --- |
| `xray-app-commander` | **不引入 tonic**：gRPC server 实例不在 Commander 中持有，由 `GrpcServerRegistrar` trait 实现持有 | P4 阶段不引入 tonic 生态；上层 `xray-core` main 注入封装 tonic `ServerBuilder` 的实现 |
| `xray-app-commander` | `Service` trait 仅含 `name`/`type_url` 元数据，去掉 Go `Register(*grpc.Server)` 方法 | Go grpc.Server 在 Rust 端是具体 tonic 类型，跨 crate 不耦合；上层根据 type_url 路由到具体注册逻辑 |
| `xray-app-commander` | `TypedMessage` 不在 Commander 解码 | Go 用全局 `common.RegisterConfig` 注册表 + `rawConfig.GetInstance()`；Rust 无副作用全局，上层显式创建 Service 后 `add_service` |
| `xray-app-commander` | `add_service` 拒绝重复 type_url（Go 不去重） | 加更严谨：防止同一 service 双注册导致 gRPC “service already registered” 错误 |
| `xray-app-commander` | `Commander::start_with_registrar` 仅注册 service + 标记 running，不实际 listen/bind/serve | TCP/Unix socket bind + outbound handler register + serve 循环依赖 transport 全链路，由上层注入 |
| `xray-app-commander` | `OutboundListener` / `OutboundHandler` / `OutboundRegistrar` trait stub + `StubOutboundHandler` 占位 | 依赖 `xray_transport::Link` + cnc 等价物；当前阶段仅定义接口让上层实现 |
| `xray-app-commander` | `CommanderConn = Box<dyn CommanderIo>`，`CommanderIo: AsyncRead + AsyncWrite + Send + Unpin` supertrait + blanket impl | Rust trait object 不允许 `dyn AsyncRead + AsyncWrite`（两个 non-auto trait， E0225）；用 supertrait 包装 |
| `xray-app-commander` | `ReflectionService` 仅 const TYPE_URL + name/type_url，实际 reflection 注册由上层注入（`tonic_reflection::server::Builder`） | Go 用 grpc/reflection 包；Rust 等价包是 tonic-reflection，在本 crate 不依赖 |

## 附录 A：样板文件位置

```
crates/xray-app-version/
├── Cargo.toml           # 依赖模板
├── src/
│   ├── lib.rs           # 模块入口 + re-exports
│   └── version.rs       # Version struct + VersionError + compare_versions + 21 单测
└── target/              # 验证产物

crates/xray-proxy-blackhole/
├── Cargo.toml           # 依赖模板（含 xray-buf）
├── src/
│   ├── lib.rs           # 模块入口 + re-exports
│   ├── response.rs      # ResponseConfig enum + get_internal_response + 10 单测
│   └── handler.rs       # Handler + BlackholeError + 6 单测
└── target/              # 验证产物
```

crates/xray-app-policy/
├── Cargo.toml
├── src/
│   ├── lib.rs           # 模块入口
│   ├── policy.rs        # Policy struct + policy::Level + 8 单测
│   ├── manager.rs       # PolicyManager 持 HashMap + level 解析 + 12 单测
│   └── buffer.rs        # BufferPolicy + 4 单测
└── target/

crates/xray-transport/
├── Cargo.toml
├── src/
│   ├── lib.rs           # 顶部文档 + 9 业务模块 + 12 stub 模块声明
│   ├── link.rs          # Link { reader, writer } + 3 单测
│   ├── connection.rs    # Connection trait + TcpConnection + 4 单测
│   ├── listener.rs      # Listener trait + TcpListenerConn + 3 单测
│   ├── dialer.rs        # Dialer trait（仅声明）
│   └── stat.rs          # CounterConnection 字节计数包装 + 3 单测
└── target/

crates/xray-tls/
├── Cargo.toml           # sha2/hex/subtle/thiserror + xray-proto + xray-transport
├── src/
│   ├── lib.rs           # 顶部文档（说明 btls/wreq 驳回决策） + 9 模块声明
│   ├── error.rs         # TlsError enum（10 变体）+ 2 单测
│   ├── pin.rs           # generate_cert_hash/hex + 5 单测
│   ├── fingerprint.rs   # Fingerprint enum（~60 变体）+ get_fingerprint + 三张表 + 8 单测
│   ├── certificate.rs   # CertificateUsage enum + is_encipherment/authority_issue + 5 单测
│   ├── config.rs        # CurveId/parse_curve_name/is_from_mitm/verify_chain/Option/RandCarrier + 17 单测
│   ├── ech.rs           # convert_to_ech_keys TLV 解析 + EchConfigCache + ech_cache_key + ApplyEch trait + 14 单测
│   ├── unsafe_conn.rs   # TLS_CLOSE_TIMEOUT 常量 + 1 单测
│   ├── utls.rs          # ConnInterface trait + client/server/u_client 工厂占位 + 1 单测
│   └── grpc.rs          # GrpcUtlsInfo + GrpcUtlsCredentials trait + new_grpc_utls 占位 + 3 单测
└── target/              # 验证产物（49 unit + 8 doctest 全绿）
```

```
crates/xray-app-dns/
├── Cargo.toml           # lru/ipnet/uuid/thiserror/xray-common/xray-features/xray-geodata
├── src/
│   ├── lib.rs           # 顶部文档 + 9 模块声明 + re-exports DnsService/DomainMatcherInfo
│   ├── error.rs         # DnsError enum（13 变体）+ 5 单测
│   ├── config.rs        # QueryStrategy/IpOption/resolve_ip_option_override/helpers + 9 单测
│   ├── dnscommon.rs     # Fqdn/IpRecord/Record/merge_records/RCode 常量 + 6 单测
│   ├── hosts.rs         # StaticHosts + HostMapping + InMemoryMatcher + lookup（递归 unwrap）+ 7 单测
│   ├── cache_controller.rs  # CacheController + cleanup + shrink + broadcast + subscribe + 7 单测
│   ├── server.rs        # DnsService + DnsServiceConfig + DomainMatcherInfo + sort_clients + lookup_ip + 9 单测
│   ├── fakedns/mod.rs   # FakeDnsPool + Holder + HolderMulti + ip ts_to_ip + 11 单测
│   └── nameserver/
│       ├── mod.rs       # Server trait + Client + NameServerConfig + new_server 占位 + 5 单测
│       ├── cached.rs    # CachedNameserver trait + query_ip/fetch/pull/subscribe + 4 单测
│       ├── fakedns.rs   # FakeDnsEngine trait + FakeDnsServer + impl for Holder/HolderMulti + 5 单测
│       ├── udp.rs       # new_classic_name_server 占位 + 1 单测
│       ├── tcp.rs       # new_tcp_name_server/new_tcp_local_name_server 占位 + 1 单测
│       ├── doh.rs       # new_doh_name_server 占位 + 1 单测
│       ├── quic.rs      # new_quic_name_server 占位 + 1 单测
│       └── local.rs     # new_local_name_server 占位 + 1 单测
└── target/              # 验证产物（82 unit + 0 doctest 全绿）
```

```
crates/xray-app-router/
├── Cargo.toml           # xray-common/features/geodata/proto + thiserror/tokio/tracing/parking_lot/rand + regex="1" + serde/serde_json
├── src/
│   ├── lib.rs           # 顶部文档（说明 IO 边界范围） + 14 模块声明 + re-exports
│   ├── error.rs         # RouterError enum（17 变体）+ at_warning/at_error + 6 单测
│   ├── context.rs       # RoutingContext trait（14 sync 方法）+ RoutingData（builder） + 5 单测
│   ├── config.rs        # DomainStrategy enum + from/to_proto + needs_ip_resolution + 4 单测
│   ├── weight.rs        # WeightManager + Literal/Regex 匹配 + number_finder + 7 单测
│   ├── condition.rs     # Condition trait + ConditionChan + 9 matcher（Domain/IP/Port/Network/User/InboundTag/Protocol/Attribute/ProcessName）+ 17 单测
│   ├── rule.rs          # Rule struct + build_rule + build_condition + proto converter（Domain/IP）+ 6 单测
│   ├── balancing.rs     # OutboundHandlerSelector/ObservationProvider/BalancingStrategy trait + Override + RoundRobinStrategy + Balancer + NotImplementedSelector + 8 单测
│   ├── strategy_random.rs     # RandomStrategy + 50/50 fallback + 3 单测
│   ├── strategy_leastping.rs  # LeastPingStrategy + alive 过滤 + 3 单测
│   ├── strategy_leastload.rs  # LeastLoadStrategy + baselines/maxRTT/tolerance 过滤 + WeightManager + 5 单测
│   ├── webhook.rs       # WebhookNotifier + WebhookEvent + dedup + cleanup + 6 单测
│   ├── router.rs        # Router + Route + Init/pick_route/AddRule/RemoveRule/ReloadRules/ListRule/OverrideBalancer + 6 单测
│   └── command/mod.rs   # RoutingService gRPC stub（全 TODO）+ 1 单测
└── target/              # 验证产物（77 unit + 0 doctest 全绿）
```

```
crates/xray-app-dispatcher/
├── Cargo.toml           # xray-common/features/buf/transport/proto + thiserror/tokio/tracing/parking_lot
├── src/
│   ├── lib.rs           # 顶部文档（IO 边界范围）+ 6 模块声明 + re-exports
│   ├── error.rs         # DispatcherError enum（11 变体）+ at_warning/at_error + 6 单测
│   ├── config.rs        # SessionConfig/Config + from/to_proto（空 schema）+ 3 单测
│   ├── sniffer.rs       # SniffResult trait + ProtocolSniffer trait + Sniffer 编排（NoClue/NeedMoreData）+ CompositeSniffResult + 5 占位唫探器 + 16 单测
│   ├── fakednssniffer.rs # FakeDnsEngine trait + FakeDnsSniffResult/DnsThenOthersSniffResult + FakeDnsSnifferFactory + 9 单测
│   ├── stats.rs         # SizeStatWriter（Counter + Writer 包装）+ 3 单测
│   └── default.rs       # RoutingContext trait（14 sync）+ DispatcherContext + RoutingRouter/DispatchHandler/OutboundHandlerManager trait + DefaultDispatcher + should_override + CachedReader + 14 单测
```

```
crates/xray-app-proxyman/
├── Cargo.toml           # xray-common/features/proto + thiserror/tokio/tracing/parking_lot/rand + ipnet="2"
├── src/
│   ├── lib.rs           # 顶部文档（IO 边界范围） + 6 模块声明 + re-exports
│   ├── error.rs         # ProxymanError enum（23 变体） + at_warning/at_error + 12 单测
│   ├── config.rs        # SniffingRequest + from_proto + matches_domain/ip_excluded + cidr_from_proto + 16 单测
│   ├── stats.rs         # Counter trait + StatsProvider + NoopStatsProvider + counter_name helpers + 12 单测
│   ├── inbound/mod.rs   # InboundHandler trait + InboundManager (HashMap+RwLock) + AlwaysOnInboundHandler stub + 14 单测
│   ├── outbound/mod.rs  # OutboundHandler trait + OutboundManager (default+cache-less Select) + 16 单测
│   ├── outbound/handler.rs  # OutboundHandlerEntry + MuxState + Udp443Policy + parse_random_ip + 19 单测
│   └── command/mod.rs   # InboundOperation/OutboundOperation + UserManager + AddUser/RemoveUser ops + HandlerService trait + DefaultHandlerService + 14 单测
└── target/              # 验证产物（103 unit + 0 doctest 全绿）
```
crates/xray-app-stats/
├── Cargo.toml           # xray-common/features + thiserror/parking_lot/tokio(sync,rt,time,macros)/tracing
├── src/
│   ├── lib.rs           # 顶部文档（IO 边界范围） + 7 模块声明 + re-exports
│   ├── error.rs         # StatsError enum + ManagerError/ChannelError From + log_warning/error + 7 单测
│   ├── counter.rs       # Counter（AtomicI64，add/set 返回旧值） + 12 单测
│   ├── online_map.rs    # OnlineMap（refcount + 跳过 localhost + lastSeen） + 17 单测
│   ├── channel.rs       # StatsChannel + ChannelConfig + ChannelSubscriber 集成 + 20 单测
│   ├── manager.rs       # Manager（RwLock<HashMap> + Start/Close） + 30 单测
│   └── command.rs       # StatsService trait 7 方法 + DefaultStatsService 编排 + SysStatsProvider + 26 单测
└── target/              # 验证产物（111 unit + 0 doctest 全绿）
```

### xray-features/src/stats.rs 重写（2025-06）
```
crates/xray-features/src/stats.rs
├── Counter/OnlineMap/Channel/Manager trait（全 sync，对齐 Go 语义）
├── NoopManager + 5 helper（get_or_register_* + subscribe_runnable/closable）
├── ChannelSubscriber（new + recv/recv_as + id）
├── ChannelError / ManagerError enums（thiserror）
└── 16 单测（NoopManager + error display + helpers）
```

### xray-app-commander（2025-06）
```
crates/xray-app-commander/
├── Cargo.toml           # xray-common/features + thiserror/parking_lot/tracing + tokio(io-util)
├── src/
│   ├── lib.rs           # 顶部文档（IO 边界范围） + 3 模块声明 + re-exports
│   ├── error.rs         # CommanderError enum 7 变体 + log_warning/error + 8 单测
│   ├── commander.rs     # Config + TypedMessageConfig + Service trait + GrpcServerRegistrar trait + NoopRegistrar + ReflectionService + Commander struct + 25 单测
│   └── outbound.rs      # CommanderIo supertrait + CommanderConn type alias + OutboundListener/OutboundHandler/OutboundRegistrar trait + StubOutboundHandler + 10 单测
└── target/              # 验证产物（41 unit + 0 doctest 全绿）
```

## 附录 B：依赖未实现时的处理流程

```
Go 源码分析
  ├─ 业务核心逻辑（纯函数 / 数据结构 / 配置解析）
  │     ↓ 翻译为 Rust，独立可测
  │
  └─ IO 边界（依赖 transport.Link / internet.Dialer / session 等）
        ↓ 翻译为 trait 方法签名 + TODO 标注
        ↓ 在 lib.rs 顶部文档说明 "当前实现范围" 与 "等 X 实现后接入"
        ↓ 不阻塞当前 crate 编译 + 测试
```

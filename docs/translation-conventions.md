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

---

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

# Oracle 裁决书：Xray-core-rust「游戏引擎式框架化」三件套评审

- 日期：2026-10-11
- 角色：FramingArch（只读顾问，独立裁决）
- 证据基础：本仓代码实测（file:line 锚点随文标注）+ PM 记忆库战役结论（标注〔mem〕，含 2026-10-10/11 perf 战役、AllocAudit、88m0/enc8x/30gf/vision 教训）
- 读者：PM；本文件为裁决依据，不替代实施计划

---

## 0. TL;DR 裁决卡

| # | 问题 | 裁决 | 置信度 |
|---|---|---|---|
| 1 | 三件套方向 | **对，但需重新定性**：不是"造框架"，是"封堵 bypass + 补三个缺失件 + 机制化纪律" | 高（代码实证） |
| 2 | 数据面 API | **保 Go-shaped MultiBuffer 骨架，去 box（poll-based trait）+ 补 Bytes 零拷贝入口**；否决宏生成、否决新 trait 宇宙 | 高（io.rs:76-93 实证） |
| 3 | accept 框架边界 | **框架拥有生命周期与限流观测，协议语义留在握手回调**；泛型单态化回调，零 box；QUIC/UDP 另立薄模板 | 高 |
| 4 | 演进路径 | **PM 方案（改造沉淀）胜**；补两条纪律：API 转正门槛 ≥3 用户 + 同窗 A/B 数字；首批用户必须形状多样 | 高（负优化 revert 前科 ×3） |
| 5 | Go diff 成本 | **镜像式框架化降低 diff，自创式才拉大 diff**；框架层上游极稳定，真实成本在协议体所有权重构（固有，非新增） | 高 |
| 6 | 引擎类比 | 抄「资源托管 + 填钩子」，**别抄「中央帧循环/运行时接管/完全隐藏内存」** | 高 |
| 7 | 落地骨架 | 5 阶段（护栏先行→数据面收口→accept 框架→调参面+观测→API 转正），每阶段带 benchmark 护栏 | 中高（计划类，待执行验证） |

---

## 1. 三件套裁决与补遗（Q1）

### 1.1 事实基础（本轮实测）

1. **框架骨架已经存在，且是 Go-shaped 的**。`crates/xray-buf/src/` 共 11 个模块：`buffer/multi/copy/reader/writer/readv/pipe/io/alloc/timeout`，逐一对位 Go `common/buf`（io.go Reader/Writer、copy.go、MultiBuffer、bytespool）。`copy.rs` 的 `copy_with_options`（copy.rs:63-98）就是 Go `buf.Copy` 的直译，含 `UpdateActivity`/`CountSize` 选项。
2. **池化句柄已经存在**。`alloc.rs` 是两级分层池（TLS 缓存 + 8 分片全局池，2K/8K/32K/128K 四层，惰性收缩模拟 Go sync.Pool GC 节奏）；`buffer.rs` 的 `Buffer` 封装 `BytesMut` + 读写游标，`#[must_use]` + Drop 回池。
3. **纪律缺口是真实且具体的**：splithttp 数据路径仍有逐块拷贝——`dialer.rs:92`、`dialer.rs:374`（`read_buf[..n].to_vec()`）、`upload_queue.rs:165`（部分消费 `payload[n..].to_vec()`）、`hub/handler.rs:328`（服务端 h2 chunk `chunk.to_vec()` 进 Packet）。vision 编解码已改为 caller-scratch（`xray-proxy-vless/src/encryption/vision.rs:149-201`，`out: &mut Vec<u8>` 跨帧复用）——说明"改得动，但靠人肉一处一处抓"。
4. **性能税的正身找到了**：`xray-buf/src/io.rs:76-93` 的 `Reader`/`Writer` trait 每次调用返回 `Pin<Box<dyn Future>>`。dispatcher 的装饰链（`SizeStatReader/Writer`、`CachedReader`、`EndpointOverrideReader`，xray-app-dispatcher/src/stats.rs:33-42、default.rs:1527-1544、endpoint_override.rs:88-158）每层各自 `Box::pin` 一层——**一个 chunk 过 N 层装饰就 N 次装箱分配**。这就是 xi40「boxing 全链放大」的结构性实锤。
5. **零拷贝入口缺失是 to_vec 泛滥的技术根因之一**：`Buffer::from_vec`（buffer.rs:57-63）是 `extend_from_slice` 拷贝构造；hyper/h2 产出的 `Bytes` 没有无拷贝进入 `MultiBuffer` 的路径。splithttp 的 `to_vec` 不全是"纪律差"，一半是"没有路"。EndpointOverrideReader 里甚至留着开发者手写的注释自我提醒「mb.to_vec() 会先堆分配扁平 Vec 再拷一次」（endpoint_override.rs:96）——纪律正在靠人肉维持。
6. **accept P0 已打点状补丁**：httpupgrade `register.rs:123-150` 已把 TLS+HTTP 握手全程包进 4s timeout（注释引用生产 P0）；websocket `server.rs:119-125` 同样 4s 覆盖 PROXY+TLS（对齐 Go hub.go:143），ws 握手 4s、h2 serve 30s。但两者 accept 循环仍是**串行 per-conn await**：一个慢 ClientHello 仍占住 accept 位 4s（慢速攻击下新连接接纳率 ~0.25/s）；httpupgrade 的 PROXY protocol 读取（register.rs:111-114）**在超时窗外**，`acceptProxyProtocol` 开启时半开 PROXY 头仍可挂死循环——残留同一个 P0 形态。

### 1.2 裁决

三件套**方向正确，定性需要修正**：

- **第 1 件（数据面 pooled handle）**：不成立为"新建"，成立为"收口"。池、句柄、拷贝循环、splice 逃生舱全部已在，工作是 ①补 `Bytes` 零拷贝入口（见 §2）②io.rs 去 box（见 §2）③把 AllocAudit 抓出的 bypass 逐个关掉 ④纪律机制化（见补遗 b）。
- **第 2 件（accept 框架）**：完全成立，且现有证据比一周前更硬——本周两个 P0 的点状修复（每 transport 手写一遍 timeout）正是"复制粘贴模式"的重演；串行 accept 的残留问题（慢速攻击占位、PROXY 窗外）只有框架级 spawn+并发上限能根治（见 §3）。
- **第 3 件（协议 UX）**：不是独立工作项，是 1+2 做完后的自然产物。提前做 UX 文档=给未定型的 API 写承诺。降到 Phase 4（见 §7）。

**这不是"像游戏引擎一样造引擎"——是"把已经 Go-shaped 的引擎骨架当成唯一合法通道，把旁路全部封死"。**

### 1.3 缺失四件（补遗）

| # | 缺失件 | 证据 | 为什么三件套没覆盖 |
|---|---|---|---|
| a | **零拷贝边界原语**：`Bytes`→Buffer 无拷贝入口（Go ownership enum 的只读形态在"用 Rust 所有权简化"时被一起丢掉了） | buffer.rs:57-63 拷贝构造；splithttp 四处 to_vec | 三件套默认"纪律问题"，实际一半是 API 缺口 |
| b | **机制化纪律**：clippy `disallowed-methods` 清单（热路径 crate 禁 `to_vec`/裸 `Vec::new` 入池）+ feature-gated 计数分配器进 bench | endpoint_override.rs:96 人肉注释；AllocAudit〔mem〕靠人工跑 | 三件套靠 review 纪律，review 纪律已被证明会漏（vision 挂了三个月才发现） |
| c | **调参面提升**：窗口/超时常量 → 配置项（TCP SO_RCVBUF 缺省、h2 STREAM_WINDOW/max_send_buf、hyper send_buf、bridge idle 300s/1s、accept 4s） | 88m0（64KB 收窗钉死 433KB/s）、enc8x（h2 窗钉 2.7/8.8/6.9 三组闭环）〔mem〕；调参一轮改码→CI→换核 4 小时〔mem〕 | 三件套没提运营面；但这恰是窗钉家族两次战役的最大运营痛点 |
| d | **逃逸舱显式化**：splice 准入闸（dispatcher default.rs:1768-1783 已有 Go `CanSpliceCopy` 1/2/3 语义）、readv opt-in——必须作为框架的**一等公民**保留并各自挂 benchmark，不许"统一抽象"时顺手删掉 | bridge 泵负优化 revert 378ab889、splice 双 revert d8562b56/a427613b、ReadVReader 真网 -25% a07041ae〔mem〕 | "统一"的天然冲动会杀掉逃生舱；这三条 revert 是本仓最贵的教训 |

### 1.4 多余的（明确不做）

- **新调度器**：tokio 就是调度引擎，spawn/blocking/IO/定时器已托管〔mem：已知实证约束〕。任何 executor 包装层 = 纯开销零收益。
- **ECS/组件化**：代理是连接并行事件驱动，无帧循环，无可组合的组件生命周期。
- **宏生成 codec**：调试、IDE、上游 diff 三输。
- **全新 trait 宇宙 / ASIO 风格 generic 重构**：见 §2。
- **为 100% 协议强制统一**：60+ 目标站点的 splice 架构级需求〔mem〕说明"某些流量永远不走框架"是常态，不是债。

---

## 2. 数据面 API 形态（Q2）

### 2.1 方案权衡

| 方案 | 优势 | 代价 | 风险 |
|---|---|---|---|
| **A. 保 MultiBuffer 骨架 + 去 box + Bytes 零拷贝入口**（推荐） | 与 Go common/buf 一一同位，协议移植 1:1；骨架已被 38 crate 使用；改动集中在 io.rs trait 形态 + buffer.rs 一个只读变体 | io.rs 改 poll-based 触及所有 Reader/Writer impl（机械但面广） | 低——形态是 tokio AsyncRead 同款，生态最成熟 |
| B. 拥抱 bytes 生态：AsyncRead/AsyncWrite + read_buf + Bytes 帧（tokio-util codec 形态） | 生态最标准；hyper/h2/rustls 原生对接，边界零拷贝天然 | 丢 MultiBuffer 批量语义（readv/scatter-gather）；38 crate 迁移；与 Go buf 层脱钩，diff 成本暴涨 | 高——等于第二次重写数据面 |
| C. 宏生成 / 自创 generic trait 宇宙 | （无实质优势） | 调试/IDE/上游 diff 全输；xi40 已证明 dyn/boxing 抽象在本仓的下场 | 确定负收益 |

**推荐 A。** 否决 B 的具体理由：B 的收益（边界零拷贝）可以被 A 内的一个原语（`Buffer` 只读变体持有 `Bytes`）拿到，而 B 要付整个数据面二次重写 + Go 对齐断裂；否决 C 无需论证。

### 2.2 反性能税设计规则（xi40 教训的正身修法）

1. **trait 形态改 poll-based，人体工学靠具名 future 默认方法**：

```rust
pub trait Reader: Send {
    fn poll_read_multi_buffer(&mut self, cx: &mut Context<'_>)
        -> Poll<Result<MultiBuffer>>;

    // 人体工学包装：具名 Future，泛型路径零装箱（Self: Sized 不影响对象安全）
    fn read_multi_buffer(&mut self) -> ReadMultiBuffer<'_, Self>
        where Self: Sized { ReadMultiBuffer { reader: self } }
}
```

   - 泛型 copy 循环（copy.rs）`.await` 具名 future → **零 box**。
   - 装饰层（SizeStat/Cached/EndpointOverride）的 `poll_read_multi_buffer` 直接同步转发内层 poll——**装饰层从每层 1 box 变成 0 分配**。这是最大的一笔收益：现在一个 chunk 过 N 层装饰 = N 次装箱（io.rs:76-93 + stats.rs:33-42 + default.rs:1527-1544 实锤）。
   - 连接边界的 `Box<dyn Reader>` 用一个 `BoxedReader` 适配器（内持 `BoxFuture`，每调用 1 box）——每连接、每 chunk 一次，且只在边界；xi40 的税是"每 read 全链放大"，不是"每连接一次"。
   - 权衡：手写 poll 状态机比 async 块啰嗦；缓解 = 多数 impl 是 AsyncRead 包装，可写一个 `MultiBufReader<R: AsyncRead>` 泛型适配器统一处理（poll 内 `read_buf` 进池化 BytesMut），只有 CachedReader 这类需要内部异步状态的才手写状态机。
   - AFIT（`async fn` in trait）被否决为替代方案：静态分发同样零 box，但 trait 失去对象安全，dispatcher 现有的 `Box<dyn Reader>`（default.rs:2650 等大量测试/装配点）全要改成泛型或 enum dispatch，改动面更大。

2. **每连接可以 dyn，每 chunk 不许 dyn**。`Box<dyn Connection>`（xray-transport 边界）保留——连接建立一次性的分发不在热循环里。

3. **补 `Bytes` 零拷贝入口**（Go ownership enum 的 Rust 回归，只读形态）：

```rust
impl Buffer {
    /// 持有外部 Bytes（零拷贝，只读语义，Drop 不回池）
    pub fn from_bytes_frozen(data: Bytes) -> Self;
}
```

   hyper/h2 chunk → `from_bytes_frozen` → MultiBuffer → relay，全程零拷贝。需要写时（split 后仍要 append 的场景）才走池化路径。写路径对称：relay 下行出站已是池化 BytesMut + write_buf 语义，不变。
   代价：Buffer 内部从 `BytesMut` 变成 enum（Frozen(Bytes) | Pooled(BytesMut)），`iter()`/`as_ref()` 分支读——每 chunk 一次分支，可忽略；换来的是"API 有路，纪律才有意义"。

4. **readv 保持 opt-in**：a07041ae 实测 localhost 无差、真网 -25%〔mem〕——批量化不是免费午餐，凡优化必须真实端点同窗配对 A/B（30gf 方法论〔mem〕）。`readv.rs` 保留现状，不进默认路径。

5. **UDP 泵同规则**：udp_session.rs:265 的循环每包走 boxed future——去 box 后小包 UDP relay 收益比 TCP 大块更明显（每包一次分配 → 零）。

### 2.3 验收护栏（本节承诺必须可测）

- 计数分配器（feature-gated，绕 mimalloc 统计或全局分配器 wrapper）：relay 每方向的 alloc 次数/MB，改造前后对比；装饰链去 box 的收益直接从这里读数。
- loopback 吞吐矩阵 ≥ 基线（154-167MB/s〔mem〕，只升不降）。
- splithttp 四处 to_vec 关闭后：真实端点同窗 A/B（enc 路径 6.9→窗修复后的 40-60MB/s〔mem〕不受影响，且 CPU 侧 alloc/MB 显著下降）。

---

## 3. accept 框架边界（Q3）

### 3.1 现状缺口（点状补丁之外的残留）

- **串行 accept 仍在**：httpupgrade register.rs:100-151 与 websocket register.rs:120-125 都是循环内逐 conn await 握手。4s 超时防住了永久挂死（P0），防不住占位：慢速攻击者每 4s 递一个半 ClientHello，新连接接纳率 ~0.25/s。
- **httpupgrade PROXY protocol 读取在超时窗外**（register.rs:111-114）：`acceptProxyProtocol: true` 时半开 PROXY 头 = 原 P0 形态复活。这是"每个 transport 手抄一遍循环"模式必然继续产 bug 的活证据。
- **观测为零**：accept 速率/握手延迟/超时计数只有 debug log。2087 挂死 5 小时靠用户测速发现〔mem〕的观测面问题在 accept 段原样存在。

### 3.2 推荐形态：泛型握手回调（单态化，零 box）

```rust
pub struct AcceptLimits {
    pub handshake_timeout: Duration,   // 默认 4s，可配（Phase 3 进配置）
    pub max_pending: usize,            // 信号量上限，防慢速攻击占位
    pub max_conns: usize,              // 总并发水位
}

pub trait StreamHandshake: Send + Sync + 'static {
    type Conn: Connection;
    type Fut: Future<Output = io::Result<Self::Conn>>;
    /// 一次性收到裸 TCP（框架不做任何读），PROXY protocol/TLS/upgrade 全在实现内
    fn handshake(&self, stream: TcpStream, remote: SocketAddr) -> Self::Fut;
}

pub fn accept_loop<H: StreamHandshake>(listener: TcpListener, hs: H, limits: AcceptLimits) { ... }
```

- 循环体：`accept → semaphore.acquire() → tokio::spawn(timeout(limits, hs.handshake(...)))`。
  - **spawn + 信号量**结构性消灭串行占位：慢 ClientHello 只占一个 permit，不占 accept 位。
  - **timeout 包整个 handshake**（含 PROXY protocol——修复 httpupgrade 残留洞； transport 实现内不再各自包 timeout，现有的双层 timeout 收敛为一处）。
- 每个 transport 单态化一份循环代码（二进制体积代价，可忽略），换零 box——**不重蹈 boxed future 覆辙的关键就是回调走 `type Fut` 关联类型，而不是 `Arc<dyn Fn(...) -> BoxFuture>`**。xi40 教训在此的直接应用。
- 现有雏形可直接吸收：httpupgrade close() 的 abort_handle 模式（register.rs:98-100, 205-208）就是"框架拥有 accept task 生命周期"的正确起点。

### 3.3 边界表（什么进框架、什么留下）

| 进框架 | 留在 transport 的 handshake fn |
|---|---|
| accept 循环与并发上限（spawn/信号量/水位） | PROXY protocol 解析 |
| 握手全程超时 | TLS accept（含 REALITY 判定、ForceEd25519、keyshare 策略）|
| per-stage 计数器 + gauge（accept 速率、握手延迟直方图、超时数、active conns）| ALPN 路由、HTTP upgrade 语义 |
| close/abort 生命周期、端口释放 | cert 选择、Tcpmask 包装 |
| 慢速攻击 conformance 套件（见下）| 一切协议语义 |

- **QUIC/UDP 不强行进同一 trait**：quinn 的 accept 语义（connection/stream 两级）与 TCP 完全不同，强行统一 = 第二个 proxyman 平行世界〔mem：架构定型④的教训〕。给 UDP/QUIC 一个复用 `AcceptLimits` + 观测 helper 的薄模板即可。
- 观测实现用 boring 方案：原子计数器 + 定期 tracing 输出（不引 metrics 框架——观测面薄的原因是没埋点，不是缺 Prometheus）。

### 3.4 配套 conformance 套件（P0 类缺陷变回归测试）

slowloris（半 ClientHello 钉住）、慢读（收到请求不回）、flood 半开——三个用例进 CI：断言 max_pending 占满时新连接仍被 accept 排队（延迟上升而非拒绝）、超时后 permit 释放、inbound 整体存活。本周两次 P0 若有此套件，都活不过第一次 CI。

### 3.5 权衡声明

选泛型单态化因为零运行时税且类型安全；代价是每 transport 编译一份循环（体积）与 impl 样板（一个 `type Fut`）。逃生舱：transport 若有特殊 accept 需求（如 grpc 的 h2 多路复用 serve），可绕过 accept_loop 直接持有 listener——框架不垄断 listener，只提供默认正确。

---

## 4. 演进路径裁决（Q4）

**PM 方案（改造中沉淀 API）胜，先写框架再迁移协议被明确否决。**

证据链（全部本仓实证）：
- 负优化前科 ×3：bridge 泵优化 revert（378ab889）、splice 双 revert（d8562b56/a427613b）、ReadVReader 真网 -25%（a07041ae）〔mem〕——先验抽象在本仓的命中率是零。
- vision 三协议 3.3-3.8MB/s 挂了数月才发现——**没有 benchmark 护栏的抽象改造必然埋雷**；反过来，AllocAudit（审计驱动）正是"从病灶沉淀 API"的正确姿势。
- enc8x 窗钉三组数字闭环是"真实用户改造中验证 API"的范本：窗参数进 API（配置面）的理由是被三个真实场景逼出来的，不是设计出来的。
- proxyman 方案 B 的教训〔mem：架构定型④〕：平行世界一旦建立就不接入——先写框架必然造出第二个平行世界。

补两条纪律，防止"改造沉淀"滑向"无限期尿分"：

1. **API 转正门槛（hard gate）**：一个 API 点标记 stable 需要 ≥3 个真实协议用户 + 每个都有同窗 A/B 数字。3 用户之前一律 `pub(crate)` 或 `#[doc(hidden)]`——防止协议 UX 文档给未定型 API 写承诺。
2. **首批用户必须形状多样**：splithttp（h2/Bytes 边界 + 请求-响应流）、grpc（消息帧 + 双拷贝）、kcp（UDP + 可靠层）——三种形状逼出来的 API 才不会过拟合 TCP 流式。若首批全是 TCP 流协议，§2 的 `from_bytes_frozen` 就不会被逼出来（它正是 h2/Bytes 形状逼出来的需求）。

---

## 5. Go diff 成本评估（Q5）

### 5.1 关键重定性：框架化与 diff 成本不是对抗关系，**方向依赖**

- Go Xray-core **本来就有这套框架**（common/buf + buf.Copy + internet transport 公共层），Go 协议代码本来就是"只写协议逻辑"。Rust 侧 xray-buf 已逐文件镜像（§1.1 事实 1/2）。
- 因此：**镜像式框架化让 diff 变小**——上游协议改动可以直接 1:1 移植；**自创式框架化才让 diff 变大**——每个上游协议 port 都要跨一次范式翻译。
- 结论：本仓框架化的正确目标函数就是"最大化与 Go common/buf 的同位性"，这同时服务性能纪律和上游同步两个主人。

### 5.2 真实成本集中点（框架化不新增，但也不消减）

| 成本点 | 性质 | 缓解 |
|---|---|---|
| Go GC 共享缓冲语义（多 goroutine 持同一 Buffer 的 ownership enum）vs Rust 所有权转移 | **固有**，协议移植时必须重构，框架化前后一样 | buffer.rs 已用所有权简化；补 `from_bytes_frozen` 后只读共享场景也回归 1:1（Go ReadOnly ↔ Rust Frozen） |
| accept 框架无 Go 对应物（Go 每 transport 手写 hub.go） | 同步压力 ≈ 0，纯自有维护 | 上游 hub.go 变更时按语义（超时/头处理）人工核对，可接受 |
| Rust 特有修复（REALITY ForceEd25519、interop 系列等）〔mem〕 | 本来就有 | 无变化 |

### 5.3 两全形态（具体机制）

1. **映射表文档**：xray-buf crate doc 里维护 `Go API ↔ Rust API` 一一对应表（buf.Reader↔io::Reader、buf.Copy↔copy()、bytespool↔alloc、ownership enum↔Buffer enum）。同步 Go 版本变更时先查表再动码——bd 流程里"先 grep Go 基线验证前提"的惯例〔mem 铁律①〕正好落在这个表上。
2. **PR 模板加一个字段**：「缓冲语义 porting note：上游本次改动是否触及 buf 所有权/窗口/超时/accept 语义 → 是则列出 Rust 侧对应改动点」。机械但防漏。
3. **框架 API 永不领先 Go 改名**：xray-buf 的公开名与 Go 对齐（现状已是），未来任何"更好听的名字"诱惑一律拒绝——名字同步是 diff 成本里最隐蔽的放大器。

量化结论：框架层上游年变更频率低（common/buf 自 v1 以来极稳定），协议体才是同步大头；本方案对协议体的额外负担 = `from_bytes_frozen` 一类调用点替换，约等于既有 to_vec 修改点，**净增 diff 成本 ≈ 0，存量 diff 成本因 1:1 移植性提升而下降**。

---

## 6. 游戏引擎类比取舍（Q6）

### 有效、应当保留的部分

| 引擎概念 | 本仓对应 | 状态 |
|---|---|---|
| "协议做好 new，其余托管" | Go Xray 本来的架构：inbound/outbound manager + dispatcher 注入 Link；Rust 生产路径 spawn_inbounds/register_outbounds/DefaultDispatcher = Go 等价物〔mem：架构定型④〕 | **已实现 80%**，愿景是补齐而非新建 |
| handle-not-raw（句柄持有资源，drop 回收） | Buffer/MultiBuffer `#[must_use]` + Drop 回池（buffer.rs/multi.rs） | 已实现，缺纪律强制 |
| 引擎内建 profiling/观测 | stats 计数 + 本方案 per-stage 埋点 | 薄，Phase 3 补 |
| 资源上限与守卫（引擎的帧预算） | AcceptLimits（水位/上限/超时） | 缺，Phase 2 补 |

### 无效、应当拒绝的部分

1. **中央帧循环/运行时接管调度**：引擎有 tick，有单线程帧预算；代理是连接并行事件驱动，中央循环是架构倒退。tokio 已经是引擎的"调度器层"，且从第一天就是。
2. **"协议完全不需要理解内存"**：线格式代码的帧边界 = 缓冲边界 = 窗口大小——内存布局决策**就是**协议语义的一部分（enc8x 窗钉、88m0 收窗钉、vision 每帧 Vec::new 钉死吞吐，三个战役全是"内存决策=性能"的实锤）。引擎能藏分配是因为游戏内容不是 wire format。诚实的版本是：**协议永远不写 `malloc`（不裸分配），但必须理解所有权转移**（帧从哪里来、freeze 后归谁、何时回池）。
3. **引擎厂商级 API 稳定性预期**：引擎 API 十年不变因为有专职团队维护 + 无外部上游；本仓每个 API 点都背上游同步税（§5），所以 API 必须 boring/small——"稳定"靠"少而同位"，不靠"承诺"。

一句话：**抄"资源托管与填钩子"，别抄"运行时接管与彻底隐藏内存"。**

---

## 7. 分阶段落地骨架（Q7）

总纪律：每阶段 exit = CI 九门 + bench 护栏非回归 + 网络面改动走**真实端点同窗配对 A/B**（30gf/vision 教训：localhost 测不出窗钉与网络路径回归〔mem〕）。护栏工具链全部现成或近现成：loopback 吞吐矩阵（基线 154-167MB/s）、stress.yml 压测、xray-stress docker 场景 s5-s12（fdtest 抓过三个生产级泄漏）、clippy 宽门镜像。

### Phase 0 — 护栏先行（先于一切改造，~天级）

| 交付物 | 验收/benchmark 护栏 |
|---|---|
| 计数分配器（feature-gated `bench-alloc`）：alloc 次数/字节数按 relay 方向统计 | 拿到**现状** alloc/MB 基线数字（splithttp/vision/grpc 三协议各一份） |
| clippy `disallowed-methods` 清单：热路径 crate 禁 `to_vec`/裸 `Vec::new` 入池（白名单逐个豁免并注明理由） | CI 红线生效：新 bypass 进不来 |
| bench 基线存档：loopback 矩阵 + 三协议真实端点同窗配对（各 5 轮取中位） | 基线数字落档，后续阶段以此为对照组 |

出口判据：三份基线报告。**没有 Phase 0 的数字，后续所有"无回归"声明都是口头的。**

### Phase 1 — 数据面收口（AllocAudit P1 + §2 API）

| 交付物 | 验收/benchmark 护栏 |
|---|---|
| `Buffer::from_bytes_frozen`（只读变体）+ MultiBuffer 兼容 | 单测：hyper Bytes→MultiBuffer→relay 全程 0 拷贝（计数分配器证明） |
| io.rs trait 改 poll-based + 具名 future 默认方法；装饰链（SizeStat/Cached/EndpointOverride）转发改 poll 直通 | loopback 矩阵 ≥ 基线；alloc/MB 下降（装饰链 N box→0）；UDP 小包 relay bench |
| splithttp 四处 to_vec 关闭（dialer.rs:92,374、upload_queue.rs:165、hub/handler.rs:328）；grpc 双拷贝关闭；kcp 热路径 | 真实端点同窗 A/B：吞吐不降 + CPU/alloc 改善；clippy 清单零豁免新增 |
| vision 收尾（poll_write_vectored 3 拷贝按既定结论处理，splice 闸门维持） | vision 路径真实端点 A/B（3.3-3.8 → 池化预估 10-15MB/s〔mem 预估，实测为准〕） |

出口判据：三协议 alloc/MB 数字改善 + 吞吐非回归 + grep 证明热路径 to_vec 清零。

### Phase 2 — accept 框架

| 交付物 | 验收/benchmark 护栏 |
|---|---|
| `accept_loop` + `AcceptLimits` + 泛型 `StreamHandshake`（含 PROXY protocol 进超时窗——修 httpupgrade 残留洞） | 单测：超时/信号量/close-abort |
| ws/httpupgrade/tcp 三 transport 迁移，删除各自手写循环（点状 4s timeout 补丁收敛进框架） | slowloris 套件：占满 max_pending 时新连接延迟上升而非饿死；超时后 permit 释放 |
| per-stage 计数 + gauge（accept 速率、握手延迟、超时数、active conns，定期 tracing） | flood 测试下 inbound 存活；观测数字与测试断言联动 |
| QUIC/UDP 薄模板（复用 limits + 观测，不强统一） | tuic/hysteria 现有 e2e 全绿 |

出口判据：`grep -r "listener.accept" crates/` 仅剩框架与 QUIC 模板；三次 P0 类攻击用例进 CI 且绿。

### Phase 3 — 调参面 + 观测面提升

| 交付物 | 验收/benchmark 护栏 |
|---|---|
| 窗口/超时常量进配置：TCP SO_RCVBUF 缺省、h2 STREAM_WINDOW/conn 窗/max_send_buf、hyper send_buf、bridge idle（300s/1s）、handshake timeout（4s） | **参数改动 = 改配置重启，不再改码换核**；enc8x 闭环数字（16MB 窗 @0.3s RTT 40-60MB/s〔mem〕）用配置复现一次作为验收 |
| 观测补全：relay 积压水位（channel 深度）、per-tag 错误计数 | 演练：人为制造 2087 型挂死（半开连接钉死），告警/日志 <1min 暴露 |

出口判据：一次真实参数调优全程不触碰 cargo；挂死演练从发现到定位 <5 分钟（对比本周 5 小时）。

### Phase 4 — API 转正（协议 UX 落地）

| 交付物 | 验收/benchmark 护栏 |
|---|---|
| 「新增协议」recipe 文档：编解码 + handshake fn + 配置接线，全部只用 stable API | 用 recipe 从零实现一个 trivial 测试协议（echo over 自定义帧）端到端跑通 |
| API stable 标记（§4 门槛：≥3 用户 + 各有 A/B 数字，Phase 1-2 的用户已含 splithttp/grpc/kcp/ws/httpupgrade/tcp） | trivial 协议代码量/分配次数对照表（新 API vs 老式手写） |
| Go↔Rust 映射表 + PR porting note 字段（§5.3） | 一次真实上游同步演练走查表 |

出口判据：下一个真实新协议（如既有 bd 票 backlog 里的协议）按 recipe 落地时，零框架外分配、零手写 accept。

### 依赖关系

Phase 0 → 1 → {2, 3 可并行} → 4。Phase 2 不依赖 Phase 1（accept 框架不碰数据面 trait）；Phase 3 的超时项依赖 Phase 2 的 AcceptLimits 落点。

---

## 8. 剩余不确定性与可证伪条件

### 未验证前提（诚实清单）

- dispatcher 泵（bridge）内部细节未逐行读，"bridge idle 300s/1s、512KiB Buffer"引自记忆〔mem：6bg/bw7 战役〕，Phase 3 动参数前需 grep 实数回填。
- grpc/kcp 当前 to_vec 状态未逐行核（AllocAudit 结论引自记忆〔mem〕）；Phase 1 开工前先用 Phase 0 的计数分配器跑一次现状即可低成本确认。
- 去 box 后的量化收益是推断：loopback 154-167MB/s 下每 chunk 装箱占比可能已被 8-512KB 大 chunk 摊薄（箱税在小帧/UDP 路径最痛）。**若 Phase 1 bench 显示 loopback 无差且 alloc/MB 改善 <5%，去 box 降级为"API 转正前提"而非性能票**——本推荐的第一条可证伪条件。
- vision 池化 10-15MB/s 是旧预估〔mem〕，非承诺；实测为准。

### 何时推翻本裁决

| 信号 | 推翻什么 |
|---|---|
| Phase 1 bench：去 box 收益 <5% 且改造引入回归风险 | §2 规则 1 降级为技术债票，资源转投 accept 框架与调参面 |
| frozen Bytes 入口后 splithttp alloc/MB 不降 | 归因错误（大头在 hyper/tls 层），Phase 1 的 splithttp 部分重新审计 |
| accept 并发化后 slowloris 套件测不出差异 | 串行假设错误，回滚并发化保留串行+超时 |
| 上游 Go 对 buf 层动大手术（如换掉 common/buf） | §5 的镜像策略失效，重新评估 B 方案（bytes 生态） |
| 三件套改造连续两阶段真实端点 A/B 出负优化 | 整体叫停回到 audit 驱动逐点修（现状模式），框架化存档待 revisit |

### 整体置信度

- §1/§2/§3 的事实基础：**高**（本轮直接代码实证）。
- §4/§5/§6：**高**（基于本仓可查的 revert 史与架构定型记录）。
- §7 阶段排序与收益预估：**中高**（依赖 Phase 0 数字校准；框架本身的方向判断置信度高，量级预估置信度中）。

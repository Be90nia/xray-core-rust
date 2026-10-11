# Xray-core-rust 分层宪法（ARCHITECTURE.md）

> **效力**：治理文档。每次新增协议、每个 AI 子代理派单，先对齐本图，再动手。
> **细则不在本文**：裁决全文见 [`docs/refs/oracle-framing-arch.md`](docs/refs/oracle-framing-arch.md)（oracle 裁决书）；病灶清单见 [`docs/refs/alloc-audit-report.md`](docs/refs/alloc-audit-report.md)（AllocAudit 审计）。宪法只立规矩，细则走链接。
> English version: [ARCHITECTURE.en.md](ARCHITECTURE.en.md)（主文档为中文版；英文版跟随本文件同步修订，变更记录双记）。
> **标注铁律**：【现状】= 已落地，可 grep 验证；【规划】= 裁决已定、未落地。禁止把规划写成现状，禁止给未定型 API 写文档承诺。
> **分层阅读**：每节开头紧凑表即原 138 行审定版（TL;DR 层），`详细` 小节为展开层。只对齐图景读 TL;DR 层即可；动手开发新协议必须读完 §3 详细 recipe——本宪法按「未参与决策会话的开发者只读本文即可正确开发」标准书写。

## 0. TL;DR——三层总图

### 0.1 三层隐喻与依赖方向

项目所有者隐喻：**骨架 = GameFrameWork**（内存分配调度、线程管理、资源回收，框架托管）；**血肉 = 协议和 DNS**（只管协议逻辑开发）；**皮囊 = V2rayN 等客户端**（对接层）。

```text
皮囊  cli / 配置兼容 / commander API                 对接外部世界
血肉  xray-proxy-* / transport 协议语义 / DNS / app 协议性模块   只写协议逻辑
骨架  tokio / xray-buf / dispatcher / 统一 accept / 观测调参      托管一切

依赖方向：皮囊 → 血肉 → 骨架，严格单向。
血肉不 import 皮囊；协议不绕过骨架自建缓冲/调度/accept/统计。
```

血肉范围：17 个 `xray-proxy-*` + 各 transport 的协议语义部分 + `xray-app-dns` 及 app 模块中承载协议逻辑的部分（其托管面——连接、缓冲、调度——仍归骨架）。
皮囊范围：cli 装配、配置形态兼容、commander API。

引擎类比的取舍：**抄「资源托管 + 填钩子」，不抄「中央帧循环 / 运行时接管 / 完全隐藏内存」**。

### 0.2 骨架子件一览

| 骨架子件 | 状态 |
|---|---|
| 调度引擎 | 【现状】tokio 即调度引擎：spawn/IO/定时器全托管；无 executor 包装层（永不建） |
| 缓冲与池 | 【现状】xray-buf 11 模块逐文件镜像 Go `common/buf`；两级分层池（TLS 缓存 + 8 分片全局，2K/8K/32K/128K）；`Buffer` `#[must_use]` + Drop 回池；`copy_with_options` = Go `buf.Copy` 直译。【规划】`Bytes` 零拷贝入口 `Buffer::from_bytes_frozen`；io.rs Reader/Writer 去 box（poll-based + 具名 future 默认方法；连接边界 `BoxedReader` 每连接 1 box） |
| transport 抽象 | 【现状】`xray-transport-*` crate 族；security（tls/reality）包装在独立 crate，防依赖环 |
| dispatcher | 【现状】DefaultDispatcher + 装饰链（SizeStat/Cached/EndpointOverride）+ splice 准入闸（Go `CanSpliceCopy` 1/2/3 语义）。【规划】装饰链 poll 直通：每层 1 box → 0 分配 |
| 统一 accept | 【现状】各 transport 手写循环 + 点状 4s timeout（httpupgrade/websocket 各自手抄）；串行 accept 残留（慢 ClientHello 占 accept 位）；httpupgrade 的 PROXY protocol 读取在超时窗外。【规划】`accept_loop` + `AcceptLimits` + `StreamHandshake` 泛型握手回调（单态化零 box）；QUIC/UDP 另立薄模板，不强统一 |
| 观测 | 【现状】stats 计数 + debug log，薄。【规划】per-stage 原子计数 + 定期 tracing（accept 速率/握手延迟直方图/超时数/active conns）、relay 积压水位；不引 metrics 框架 |
| 调参面 | 【现状】窗口/超时为硬编码常量（88m0 收窗钉、enc8x h2 窗钉两次战役均需改码→CI→换核，约 4 小时一轮）。【规划】常量进配置：TCP SO_RCVBUF 缺省、h2 STREAM_WINDOW/max_send_buf、hyper send_buf、bridge idle（300s/1s）、握手 timeout |

### 0.3 详细——新协议可复用件清单（先 grep 此清单，再动手）

**写任何自建轮子之前先对这张单**——骨架已有的件，血肉不得自建（§1.1 义务边界的正向清单）：

| 类别 | 现有件（crate 名均实测） | 复用方式 |
|---|---|---|
| 传输（9 个） | `xray-transport-{tcp,websocket,httpupgrade,splithttp,grpc,kcp,quic,hysteria,naive}`（+ 本体 `xray-transport` 内含 bridge/record_framer/finalmask/mkcp） | 经 `streamSettings.network` 选择，协议层不自写拨号/监听 |
| security 包装 | `xray-tls` / `xray-reality`（独立 crate，inbound/outbound 对称检查） | 经 `streamSettings.security`，不进协议 crate（防依赖环） |
| 数据面辅助 | `xray-mux`（mux）、`xray-xudp`（UDP 会话）、`xray-crypto`、`xray-geodata` | mux 经 `mux.json` 开启；UDP 走 UdpDispatchSession + XUDP 帧约定 |
| app 控制面 | router / dns / stats / log / policy / metrics / observatory / reverse / geodata / version / proxyman / commander | 经配置装配注入，协议层不直连 |

### 0.4 文档冲突裁决顺序

本文（宪法）> `docs/refs/` 两份治理输入（裁决书/审计的细则）> 记忆库教训（可能过时）。**任何文档与代码冲突时，以代码为准**——文档错则修文档；疑似代码 bug（文档描述才合理）只报告不改码。本宪法的【现状】条目全部带锚点，引用前先验锚点。

## 1. 骨架承诺清单

### 1.1 TL;DR

血肉**可以拿到**（承诺；缺了即骨架的 bug）：

| 承诺 | 内容 |
|---|---|
| pooled buffer | 池化句柄自动回池（`#[must_use]` + Drop）；【规划】外部 `Bytes` 无拷贝进入管道的路 |
| accept 托管 | 连接生命周期、并发上限、握手全程超时、close/abort——协议只填握手回调 |
| 调度托管 | 线程、定时器、连接泵、半关闭窗口；协议不 spawn 线程、不自管超时轮询 |
| 观测 | per-stage 计数与错误计数挂点；【规划】gauge/积压水位 |
| 热调参 | 【规划】窗口/超时改配置不改码、不换核 |
| 日志规范 | 错误统一分类与计数，问题可从日志定位到 stage |
| 逃生舱 | splice 准入闸、readv opt-in 是一等公民，各自挂 benchmark；不许在「统一抽象」时顺手删除 |

血肉**永远不自己造**（义务边界）：① 不裸堆分配进热路径（clippy 红线，见 §6）；② 不手写 accept 循环、不自带超时/限流（现存点状 4s 补丁是债务不是范式）；③ 不 spawn 线程、不包装 executor；④ 不绕过 dispatcher 自建统计/日志通道；⑤ 不自定窗口/超时常量（用骨架默认，特殊需求走配置面【规划】）。

### 1.2 详细——承诺三件套（现状锚点 + 规划草图 + 验收判据）

**P1 承诺：pooled buffer。**
- 现状锚点：`crates/xray-buf/src/alloc.rs:21-40`（DEFAULT_SIZE 8192；TIER_SIZES [2048,8192,32768,131072]；TLS 缓存每层 8 块；全局 8 分片每片每层 64 块上限；60s 惰性收缩模拟 Go sync.Pool GC 节奏）；`buffer.rs:35`（`Buffer::new()` 走池）、`buffer.rs:60-63`（`from_vec` 拷贝构造——零拷贝缺口正身）、`buffer.rs:372`（`release()`）、`buffer.rs:388-396`（`impl Drop` 回池）；`io.rs:76-93`（Reader/Writer trait，`Pin<Box<dyn Future>>` 每调用装箱——box 税正身）。
- 规划草图（oracle 裁决书 §2.2 原样转述）：

```rust
// 【规划·P1】零拷贝入口：Go ownership enum 只读形态的 Rust 回归
impl Buffer {
    /// 持有外部 Bytes（零拷贝，只读语义，Drop 不回池）
    pub fn from_bytes_frozen(data: Bytes) -> Self;
}
// 内部形态从 BytesMut 变为 enum { Frozen(Bytes) | Pooled(BytesMut) }，
// iter()/as_ref() 分支读——每 chunk 一次分支，换"API 有路，纪律才有意义"。

// 【规划·P1】io.rs 去 box：poll-based trait + 具名 future 人体工学
pub trait Reader: Send {
    fn poll_read_multi_buffer(&mut self, cx: &mut Context<'_>)
        -> Poll<Result<MultiBuffer>>;
    fn read_multi_buffer(&mut self) -> ReadMultiBuffer<'_, Self>
        where Self: Sized { /* 具名 future，泛型路径零 box */ }
}
// 装饰层 poll 直通 = 每层 0 分配；连接边界 BoxedReader 适配器 = 每连接 1 box，仅此一处。
```

- 验收判据：计数分配器证明 hyper `Bytes` → MultiBuffer → relay 全程 0 拷贝；loopback 矩阵 ≥ 基线 154-167MB/s；装饰链 alloc/MB 下降可读数。

**P2 承诺：accept 托管。**
- 现状锚点：`xray-transport-httpupgrade/src/register.rs:100-151`（串行循环逐 conn await）、`:111-114`（PROXY protocol 读取在超时窗外——残留 P0）、`:123-150`（点状 4s）、`:98-100,205-208`（abort_handle 模式=框架生命周期雏形）；`xray-transport-websocket/src/server.rs:119-125`（同型 4s）。
- 规划草图（oracle §3.2 原样转述）：

```rust
// 【规划·P2】
pub struct AcceptLimits {
    pub handshake_timeout: Duration, // 默认 4s，可配（P3 进配置）
    pub max_pending: usize,          // 信号量上限，防慢速攻击占位
    pub max_conns: usize,            // 总并发水位
}
pub trait StreamHandshake: Send + Sync + 'static {
    type Conn: Connection;
    type Fut: Future<Output = io::Result<Self::Conn>>;
    /// 一次性收到裸 TCP（框架不做任何读），PROXY/TLS/upgrade 全在实现内
    fn handshake(&self, stream: TcpStream, remote: SocketAddr) -> Self::Fut;
}
pub fn accept_loop<H: StreamHandshake>(listener: TcpListener, hs: H, limits: AcceptLimits);
// 循环体：accept → semaphore.acquire() → tokio::spawn(timeout(limits, hs.handshake(..)))
// 泛型单态化零 box（回调走 type Fut 关联类型，不走 Arc<dyn Fn -> BoxFuture>）。
```

- 边界表：进框架 = accept 循环与并发上限/握手全程超时/per-stage 计数/close-abort 生命周期/慢速攻击套件；留在 transport = PROXY 解析、TLS accept（REALITY 判定、ForceEd25519、keyshare）、ALPN 路由、HTTP upgrade 语义、cert 选择、一切协议语义。QUIC/UDP 不进同一 trait（quinn 两级 accept 语义不同，强行统一=第二个 proxyman），复用 limits+观测 helper 薄模板。逃生舱：特殊 accept 需求（如 grpc h2 serve）可绕过 accept_loop 直持 listener——框架不垄断 listener，只提供默认正确。
- 验收判据：超时/信号量/close-abort 单测；slowloris 占满 max_pending 时新连接延迟上升而非饿死、超时后 permit 释放；`grep -r "listener.accept" crates/` 仅剩框架与 QUIC 模板。

**P3 承诺：调度托管。**
- 现状锚点：tokio runtime 全局托管（spawn/IO/定时器）；连接泵范式沉淀于 `xray-transport/src/bridge.rs`（池化泵 copy_pooled + 两对 watch channel 半关闭，见 §2 坑 9）；ActivityTimer 每轮 `sleep_until` 重建（vy0 教训，见 §2 坑 5）。UDP 托管：UdpDispatchSession（xray-app-dispatcher）+ XUDP 帧约定——inbound per-client assoc + 60s idle，outbound 经 dial_fn 的 UDP 分支 Connection 包装；协议侧只做 packet 编解码。
- 规划：无新增（tokio 即终态）；只禁止反模式（血肉 spawn 线程/自包装 executor/自管超时轮询）。
- 验收判据：新协议 PR 中不出现 `std::thread`、`tokio::runtime::Builder`、裸 `tokio::spawn` 的超时轮询循环。

**P4 承诺：观测。**
- 现状锚点：dispatcher 装饰链 SizeStatReader/Writer（`xray-app-dispatcher/src/stats.rs:33-42`）做流量计数；错误分类 `xray-buf/src/io.rs:60-66`（`classify_io_error` → Read/Write/Interrupted 分类）；其余仅 debug log。
- 规划草图：每 transport/stage 原子计数器（accept 速率、握手延迟直方图、超时数、active conns）+ 定期 tracing 输出；relay 积压水位（channel 深度）+ per-tag 错误计数。不引 metrics 框架——观测面薄的原因是没埋点，不是缺 Prometheus。
- 验收判据：人为制造 2087 型挂死（半开连接钉死），告警/日志 <1min 暴露；flood 测试下 inbound 存活且观测数字与测试断言联动。

**P5 承诺：热调参。**
- 现状锚点（税单）：88m0——TCP SO_RCVBUF 收窗出生钉 ~64KB → 433KB/s 锁步（修于 3e755458，sockopt 显式配置优先）；enc8x——h2 STREAM_WINDOW/send_buf 窗钉 2.7/8.8/6.9MB/s 三组闭环（修于 transport.rs:233 max_send_buf 16MB）；每次调参 = 改码→CI→换核 ~4 小时。
- 规划清单：TCP SO_RCVBUF 缺省、h2 STREAM_WINDOW/conn 窗/max_send_buf、hyper send_buf、bridge idle（300s/1s）、握手 timeout（4s）→ 全部进配置。
- 验收判据：一次真实参数调优全程不触碰 cargo；enc8x 闭环数字（16MB 窗 @0.3s RTT 40-60MB/s）用配置复现一次。

**P6 承诺：日志规范。**
- 现状锚点：`io.rs:60-66` 错误三分类；各协议 `Err(String)` 链路带上下文。
- 规划：错误分类计数挂观测（P4）；挂死类故障从发现到定位 <5 分钟（对照 2087 挂 5 小时）。
- 验收判据：演练一次（§5 T3.3）。

**P7 承诺：逃生舱。**
- 现状锚点：splice 准入闸 `xray-app-dispatcher/src/default.rs:1768-1783`（Go `CanSpliceCopy` 1/2/3 语义）；readv 保持 opt-in（a07041ae 实测真网 -25%——批量化不是免费午餐）。
- 规划：无——保留现状即承诺；任何「统一抽象」不得顺手删除，各自挂 benchmark。
- 验收判据：readv_perf.rs 级 micro-bench 存续；splice 闸语义与 Go 对齐（PR porting note 覆盖）。

## 2. 框架吃掉的 Rust 坑清单

### 2.1 TL;DR

本节是 §1 义务边界的反面论证：**Rust 容易踩的坑必须由框架吃掉，血肉（协议）作者踩不到**。每收口一条，血肉作者的坑表就短一截；本表同时是 P1/P2 的验收对照（收口判定 = 所有「现状：是」翻成「否」）。

| # | 坑（事故史） | 框架吃掉机制 | 血肉作者还会遇到吗 |
|---|---|---|---|
| 1 | accept 循环串行握手无超时——半个 ClientHello 堵死整个 inbound（httpupgrade P0：生产 2087 挂 5 小时；websocket 同型复发） | 统一 accept：超时 + 并发接纳（spawn + 信号量 + AcceptLimits）【规划 P2；现状 = 点状 4s 补丁，PROXY 读取段仍在超时窗外】 | 现状：是（点状不全）；P2 后：否 |
| 2 | handler 被 move 进 spawn future 后 drop → listener 关闭、连接全拒（anytls 入站接线缺陷） | accept 框架持有生命周期（close/abort 归框架）【规划 P2】 | 现状：靠人肉保活；P2 后：否 |
| 3 | 池化 buffer 忘 resize → tokio read 空 buf 返回 Ok(0) 假 EOF（xray-buf alloc 返回 len=0 的铁律坑） | buffer 句柄出厂即合法：resize 内建于构造，Drop 回池语义不变【规划】 | 现状：是（铁律靠人肉记）；收口后：否 |
| 4 | 每帧 `Vec::new` / poll_write_vectored 每帧拷贝 → 协议吞吐钉死 3.3–3.8MB/s（vision 病，bd vscd） | 零拷贝管道默认 + 池句柄；API 不给需要 `to_vec` 的场景（【规划】`from_bytes_frozen`） | 现状：主体已修仍靠纪律；P1 后：否 |
| 5 | tokio Sleep `reset()`→`set()` 改名 + Pin 方法解析歧义（ActivityTimer，vy0） | 框架 idle-timeout 组件：每轮 `sleep_until` 重建；血肉不直接摸 Sleep | 现状：基本否（范式已沉淀于框架组件） |
| 6 | quinn `open_bi` 惰性：首 write 才发 STREAM，不写对端 `accept_bi` 永不返回（V-Batch1-6op） | QUIC/UDP 薄模板内建首包/双级 accept 语义【规划 P2】 | 现状：自写 quinn 会踩；P2 后：否 |
| 7 | Reader/Writer trait 每调用装箱 `Pin<Box<dyn Future>>`、装饰链逐层放大（xi40；io.rs:76-93 正身） | poll-based trait + 具名 future 默认方法；血肉拿到的 API 天然零 box【规划 P1】 | 现状：是；P1 后：否 |
| 8 | Go `SetReadDeadline` 语义在 Rust 无对应 → TLS 惰性握手裸奔（本两次 P0 的根因） | 框架 deadline 语义全覆盖，含 PROXY protocol 读取段【规划 P2；现状 = 点状 4s】 | 现状：是（段覆盖不全）；P2 后：否 |
| 9 | spawn 任务无 shutdown 传播 → 资源泄漏/连接僵死（bridge 两对 watch channel 的血泪） | 框架统一 abort/生命周期【规划 P2】+ bridge 泵半关闭范式（up/down_done 双 watch）已沉淀 | 复用骨架 bridge 泵：否；P2 统一收口 |

### 2.2 详细——每条坑的复现要点与机制接口形态

1. **串行 accept 占位**。触发形态：`loop { let (s, _) = listener.accept().await?; handshake(s).await?; }`——握手 await 在 accept 循环体内且无 timeout。攻击者每 4s 递半个 ClientHello，接纳率 ~0.25/s；`acceptProxyProtocol: true` 时 PROXY 头读取连 4s 都没有（register.rs:111-114）。机制接口：§1.2 的 `accept_loop`+`AcceptLimits`——spawn+信号量使慢握手只占 permit 不占 accept 位。
2. **handler move 后 drop**。触发形态：`tokio::spawn(async move { handler.serve().await })` 中 handler 未被 listener 结构体持有（或持有方先 drop）→ 关联 listener 关闭。anytls 修法（start() 外移 + pending 保活）是点状人肉版；机制接口：`accept_loop` 持有 `H: StreamHandshake` 与 abort_handle（httpupgrade register.rs:98-100/205-208 模式收编）。
3. **池化 buffer 假 EOF**。触发形态：`let mut b = alloc::alloc(8192); let n = stream.read(&mut b).await?;`——alloc 返回 len=0，tokio read 空 buf 返回 `Ok(0)`，被当 EOF。现状铁律：alloc 后必须 `resize(size, 0)`。规划机制：`Buffer` 构造出厂即合法（resize 内建），`#[must_use]`+Drop 回池不变（buffer.rs:388）。
4. **每帧分配钉死吞吐**。触发形态：编解码每帧 `Vec::new()`/`to_vec()` 进写路径；`poll_write_vectored` 逐帧小 iovec（vision：xtls_padding 每帧 Vec::new + 每帧 3 拷贝 → 三协议恒 3.3-3.8MB/s 挂数月）。判别法（enc8x 方法论）：**吞吐数字 ÷ RTT 反推在途上限，与已知窗口/缓冲常数对照**——「吞吐恒定不随 regime 摆动」= 窗钉/缓冲钉；「分钟级摆动」= 路径 regime。机制接口：池句柄 caller-scratch（vision.rs:149-201 修后形态）+【规划】`from_bytes_frozen`；API 面不提供需要 `to_vec` 的场景（数据路径收 `Bytes`/池句柄，不收 `&mut Vec<u8>` 让调用者先拷一份）。
5. **Sleep reset/set 陷阱**。触发形态：`Pin<&mut Sleep>` 上调 `.set()` 解析到 `Pin::set` 而非 `Sleep::set`；tokio 新版把 `reset()` 改名 `set()`。机制接口：框架 idle-timeout 组件内部每轮 `tokio::time::sleep_until(Instant::now() + timeout)` 重建（cancel-safe，ActivityTimer 现行形态）；血肉拿 idle-timeout 组件，不 import `tokio::time::Sleep`。
6. **quinn open_bi 惰性**。触发形态：`let (mut tx, rx) = endpoint.open_bi().await?; let _ = peer.accept_bi().await?;`——`open_bi` 是 lazy，首 write 才发 STREAM 帧，不写对端 `accept_bi` 永不 pending-ready（e2e 里表现为 ~30s idle timeout 才浮出拒绝）。机制接口：QUIC/UDP 薄模板内建「连接建立即首发」语义【规划 P2】；现状由各 QUIC 协议自处理（hysteria/tuic 已踩平，新协议照抄其 client.rs 首发）。
7. **trait 装箱全链放大**。触发形态：新增装饰 Reader 时实现 `read_multi_buffer` 并 `Box::pin` 内层 future——每层装饰 × 每次 read × 1 次堆分配；dispatcher 装饰链三层即三倍（stats.rs:33-42、default.rs:1527-1544 CachedReader、endpoint_override.rs:89）。机制接口：【规划 P1】poll 直通（装饰层同步转发内层 poll）；过渡期纪律：不加新装饰层、不加新 `Box::pin`。
8. **deadline 语义缺失**。触发形态：`TlsAcceptor::accept(stream)` 无外层 timeout——TLS 惰性握手等 ClientHello 无限期；Go 侧 `SetReadDeadline` 是惯用防护，Rust 无对应惯用式。机制接口：【现状】每 transport 手包 4s（httpupgrade register.rs:123-150 / ws server.rs:119-125，对齐 Go hub.go:143）；【规划 P2】`accept_loop` 的 `handshake_timeout` 一处覆盖全段（含 PROXY 读取）。
9. **shutdown 不传播**。触发形态：`tokio::spawn(pump(ra, wb))` 两泵无共享取消信号——一端关闭后另一端按 idle timeout（300s）才退，fd/内存滞留（s5-s12 压测三泄漏的场景基础）。机制接口：骨架 bridge 泵范式已沉淀（`xray-transport/src/bridge.rs`：up/down_done 两对 watch channel + 双模式读循环——无连接 300s idle、半关闭窗口 1s，Buffer 512KiB 对齐 Go）；新协议 relay 一律复用，不自写泵。【规划 P2】accept abort 再统一收口。

## 3. 血肉配方：新协议接入 recipe

### 3.1 TL;DR

接入一个新协议 = 只做两件事，其余托管：

1. **实现编解码**：定义帧边界（线格式的帧边界 = 缓冲边界 = 窗口大小——内存决策就是协议语义），全部使用骨架缓冲句柄；
2. **填握手**：实现握手回调（【现状】期间按各 transport 现行方式；【规划】`StreamHandshake`），PROXY protocol / TLS / upgrade 语义在实现内，超时与并发归框架。

随后自动获得托管：**内存**（池句柄 Drop 回池）、**拷贝**（默认零拷贝管道）、**调度**（accept/泵/定时器）、**回收**（连接关闭统一释放）、**观测**（stage 计数）。

| # | 要求 | 设计原则 |
|---|---|---|
| ① | 轻量 | 骨架 boring/small；API 稳定靠「少而同位 Go」，不靠版本承诺；不加没人要的抽象层 |
| ② | 高效 | 每 chunk 分配即税：**每连接可以 dyn，每 chunk 不许 dyn**；热路径零 `to_vec`；批量优化（readv）保持 opt-in，且必须真实端点同窗 A/B |
| ③ | 容易拓展 | 新协议 = 编解码 + 握手回调两件事；recipe 是唯一合法接入方式 |
| ④ | 内存和线程管理优秀 | 分配走池、线程归 tokio；协议代码里不出现线程与裸分配 |
| ⑤ | 接入非常简单 | recipe 验收 = 从零实现 trivial 协议端到端跑通（Phase 4 出口判据） |
| ⑥ | 完全不用考虑内存管理 | **诚实版本**：协议永远不写 `malloc`——不裸分配，一律池句柄或所有权转移；API 层面感觉不到（handle 自动回池、零拷贝管道默认）。但线格式协议的内存布局决策就是协议语义，协议**必须理解所有权转移**（帧从哪里来、freeze 后归谁、何时回池）——框架藏掉写法，藏不掉理解 |
| ⑦ | 连深浅拷贝都不用管 | 默认路径零拷贝（`Bytes` 入口、scratch 字段化、vectored 直写）；任何一处显式拷贝都是决策，须有 A/B 数字或注释说明理由 |
| ⑧ | log 报错规范 | 错误统一分类计数；挂死类故障从发现到定位 <5 分钟（对照现状约 5 小时） |

### 3.2 Step 0——动手前：grep Go 基线（铁律）

本项目 issue 前提错误率 20+/22，铁律：**每个协议语义（帧格式/握手序列/超时/加密协商）动手前先 grep Go 基线 `D:/Project/Xray-core` 验证**，_bd 票面按字节级描述预期 wire 行为_。Go 上游加一个协议动哪些文件（先例，已 glob 实证）：

```text
proxy/<name>/            <name>.go（公共类型/validator）+ config.proto/config.pb.go/config.go
  ├─ inbound/            inbound.go + config.*
  ├─ outbound/           outbound.go + config.*
  ├─ encoding/           encoding.go（帧编解码，可选）
  └─ account/            account.proto（vless/vmess/hysteria 等带账号的）
infra/conf/<name>.go     JSON 配置序列化（protocolKey → settings 解析）
app/proxyman/…           （如需 API 面）
```

Rust 侧同位物：`crates/xray-proxy-<name>/`（协议体）+ `crates/xray-conf/src/protocols.rs`（配置解析）+ `crates/xray-core/src/{inbound,outbound}.rs`（注册臂）。镜像式框架化让 diff 变小：**协议语义 1:1 移植，不自创范式**。

### 3.3 Step 1——建 crate（目录清单）

以 `xray-proxy-tuic` 为样板（实测文件树）：

```text
crates/xray-proxy-mock/
  Cargo.toml            # 依赖：xray-buf / xray-common / xray-features；带 TLS 时加 xray-tls
  src/lib.rs            # 导出：Handler 构造、parse_mock_config、DialFn 工厂
  src/config.rs         # parse_mock_config(&[u8])——Go infra/conf 的同位物；双形态兼容在这里做（§4.2）
  src/protocol/         # 帧编解码（纯函数，缓冲规则见 Step 3）
  src/outbound.rs       # 独立 Handler（测试装配路径）
  src/dispatcher.rs     # make_mock_dial_fn() → 生产 DialFn（对应 tuic dispatcher.rs:106 make_dial_fn）
  src/inbound.rs        # 入站 handler + listener 接线（见 Step 5）
  src/error.rs          # 错误分类（对齐 io.rs:60 classify_io_error 分类法）
  tests/                # loopback / dispatch 集成测试（见 Step 6）
```

命名与依赖红线：security 包装（tls/reality）不进协议 crate（防依赖环，transport security 在独立 crate 的架构定型）；协议 crate 不依赖 `xray-core`（方向：core → proxy，不可反向）。

### 3.4 Step 2——配置解析与注册点（全清单）

新增协议必触的注册点（现状锚点，grep 可验）：

1. `crates/xray-conf/src/protocols.rs`：`parse_mock_config`——settings JSON（bytes）→ 协议配置 struct。双形态兼容（v2rayN 裸字段 vs Go 数组）在此归一（SS 先例 d0555c26：入口 first 分支两形态映射同一引用，后续逻辑零改动）。
2. `crates/xray-core/src/outbound.rs:672` `match ob.entry.kind.as_str()`：加 `"mock" =>` 臂。臂内三件事（对照 :910 tuic 臂）：`parse_mock_config(&ob.entry.data)` → `.with_stream_settings(parse_stream_settings(&ob.stream_settings_json))`（:751-754 vless 臂形态）→ 构造 handler。生产路径统一经 `try_build_handler`（outbound.rs:543）——**独立 Handler 只是测试用，生产可用性以 try_build_handler 臂为准**。
3. `crates/xray-core/src/inbound.rs:2687` `match ib.entry.kind.as_str()`：加 `"mock" =>` 臂（`spawn_one_inbound`，inbound.rs:2625；对照 :2718 vless 臂：validator 构建 + listener bind + dispatch 接线）。
4. 透传语义不用自己做：`streamSettings/sniffing/mux/proxySettings` 子对象由 xray-conf 原样透传（`built.rs:56-74` `stream_settings_json: Option<Value>`）；明文出站禁令自动生效（`outbound_security.rs:116`，vless encryption=none / trojan 无 TLS 且非私网目标硬错——新协议若属明文族，对齐该函数的分类）。
5. 【按需】commander/proxyman API 面暴露：`xray-proto` 加消息（对应 Go config.proto）。

配置 JSON 形态示意（mock 出站，双形态——与 §4.2 承诺同构）：

```json
// Go 形态（servers 数组）：
{"protocol": "mock", "settings": {"servers": [{"address": "h", "port": 443, "token": "t"}]},
 "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": "h"}}}
// v2rayN 形态（裸字段，若有用户实锤再承诺兼容）：
{"protocol": "mock", "settings": {"address": "h", "port": 443, "token": "t"}}
```

双形态归一写法（d0555c26 先例）：解析入口处 `first` 一次分支——数组形态取 `servers[0]`、裸字段取自身——两分支映射到**同一个** `first` 引用，后续字段解析逻辑零改动、零重复。

### 3.5 Step 3——编解码的缓冲规则（骨架义务的行格式）

- 帧读：`Reader::read_multi_buffer` 拿 `MultiBuffer`【现状 io.rs:76-93 boxed future；【规划 P1】poll trait，新代码按 poll 形态写，避免新增 Box::pin】。
- 帧写：池化 `Buffer` 直写 + `write_multi_buffer`；外部来源的 hyper/h2 `Bytes`【现状】只能拷入（`from_vec` buffer.rs:60 拷贝构造）——这是已登记债务 F1/F3；【规划 P1】后走 `from_bytes_frozen` 零拷贝。
- 禁止清单：热路径 `to_vec()`/每帧 `Vec::new()`/`BytesMut::new()` 不 resize 直接 read（§2 坑 3）/整流缓冲式 API（vmess whole-body 教训 F14：生产 pump 全部 `next_ref()`+持久 chunk_buf，整流拼接=延迟+内存陷阱，勿接入生产流）。
- 需要写时拷贝的场景（split 后仍要 append）：走池化路径；只读共享（转发不改）走【规划】Frozen。
- 加解密实例：连接级构造常驻（struct 字段），数据路径仅 `open_in_place`/`seal_into` + nonce 递增；rekey 仅密钥上限时（SS-2022/REALITY 先例，common_conn.rs:196 形态）。**禁止每帧重建加密上下文**。
- 句柄用法示意（caller-scratch 形态，vision.rs:149-201 修后范式；示意，未验证——以各 crate 现行调用为准）：

```rust
// 编码：调用方提供 out（跨帧复用的池句柄/scratch），编码器只写入不分配
fn encode_frame(out: &mut Buffer, payload: &[u8]) -> Result<()> {
    out.write_u16(payload.len() as u16)?;   // 长度前缀直写池句柄
    out.extend_from_slice(payload);         // 单次拷贝进句柄，无中间 Vec
    Ok(())
}
// 解码：从 MultiBuffer 剥一帧；半包返回 None（数据留在原处待续读），不拷不拼接
fn decode_frame(src: &mut MultiBuffer) -> Result<Option<Buffer>> { /* split_to 语义 */ }
```

### 3.6 Step 4——outbound 生产接线（两套路径）

生产：`dispatcher.rs` 提供 `make_mock_dial_fn(client: Arc<MockClient>) -> DialFn`（对照 `xray-proxy-tuic/src/dispatcher.rs:106`：连接级副作用——心跳启动、惰性地址解析（:136 `make_dial_fn_lazy`，真实节点 address 是域名）——放工厂内一次性执行；返回的闭包内 clone Arc + 按 dest 建 session，不在闭包里做每调用重活）。`try_build_handler` 臂调它装配（xray-core outbound.rs:672 match）。UDP：走 UdpDispatchSession + XUDP 帧约定（xray-app-dispatcher 架构定型），协议侧只提供 packet 编解码。
测试：独立 `Handler::new(config)`（outbound.rs 路径之外）——仅供 crate 内 loopback 测试，**不得**作为可用性判据。

### 3.7 Step 5——inbound 接线与 accept

固定模式（TUIC 样板，架构定型⑥）：

```text
InboundHandler::with_dispatch(Arc<dyn DispatchHandler>)   // builder 注入分发器
  → listener accept（【现状】手写循环：TLS/PROXY 握手 + 4s timeout 手包；
                     【规划 P2】实现 StreamHandshake，超时/并发归框架）
  → 预读 initial_bytes 必须经 InitialedReader（Cursor 前缀 + 透传）回灌
  → Link::new(new_reader, new_writer) + Destination::new
  → handler.dispatch(link, dest)
```

接线语义展开：`Destination` 描述客户端请求的目标（地址 + 端口，`Destination::new`）；`Link` 是 dispatcher 交付的双向管道（reader/writer 两半）；预读字节（首帧的一部分已在握手缓冲里）**必须**包成 `InitialedReader` 回灌，否则首帧头部丢失。UDP inbound 另走 UdpDispatchSession（60s idle，per-client assoc）+ XUDP 帧约定，不经 TCP Link。

【现状】过渡期纪律：手写循环必须包 4s 握手超时（对齐 Go hub.go:143）、必须注释「债务：待 P2 accept_loop 收敛」；不许裸奔无超时（§2 坑 1/8）。

### 3.8 Step 6——测试矩阵

| 层 | 要求 | 现成基建 |
|---|---|---|
| lib 单测 | 帧编解码 roundtrip + 边界（粘包/半包/错误帧）；双配置形态（§4.2）各一条 | grpc encoding.rs roundtrip 护栏先例 |
| crate 集成 | `tests/` 双 start_full 实例：server 侧 = 被测协议 inbound + freedom 出站；client 侧 = socks 入站 + 被测协议出站；echo 流量穿全链（functions.rs 内部 API）。**铁律：freedom settings 恒 `{}` 会被 inbound 默认 BlockPrivate 黑洞 127.0.0.1 echo——测试配置必须带 finalRules 回环放行，否则表现为 echo timeout 的假协议缺陷**（grpc_multimode/transport_interop/e2e known-fail 族统一根因） | tuic tests/ 五件套（loopback/dispatcher_loopback/inbound_dispatch/udp_loopback/domain_dial） |
| interop | Rust 客户端 ↔ Go 服务端 + 反向（2×2 四角齐全）；dist/interop_ci.py 加套件 | Batch15/interop 7 缺陷战役的陷阱清单：Go freedom 回环放行（finalRules allow 127.0.0.0/8，否则黑洞 40s 假死）；Go 子进程 stdout 必须后台 drain（64KiB pipe 满即假 hang）；Go BufferedWriter SetFlushNext 顺序（先 body 后读响应头）；RST 竞态（termination chunk 与 body 同 vec 一次写） |
| 共享 listener 类 | kcp 型 UDP 协议 `--test-threads=1` | kcp tests 先例 |
| 性能 | 真实端点同窗配对 A/B（同 binary 同窗交替，禁跨窗）；loopback 冒烟 ≥ 基线 95% | stress.yml / xray-stress s5-s12 / readv_perf.rs |
| CI 宽门 | clippy `--workspace --all-targets -D warnings` + `cargo doc --workspace --no-deps` + stable 工具链 fmt | ci.yml |

### 3.9 Step 7——验收 checklist（PR 自查）

- [ ] 每条协议语义有 Go 基线 file:line 对照（grep 过 `D:/Project/Xray-core`）
- [ ] 热路径零 `to_vec`/每帧分配（clippy 禁令零新增豁免）
- [ ] 无手写 accept 超时/限流（或注「债务待 P2」）；无 `std::thread`；无自建统计通道
- [ ] `try_build_handler`/`spawn_one_inbound` 注册臂齐全（生产可用，非仅测试 Handler）
- [ ] 明文出站禁价新分类已对齐（若明文族）
- [ ] 测试矩阵四层齐全；kcp 型已限并发
- [ ] PR porting note 已填（§6.5）；未转正 API 全部 `pub(crate)`/`#[doc(hidden)]`
- [ ] mock-protocol 型 trivial 协议按本 recipe 从零跑通（P4 出口判据的持续验证）

### 3.10 mock-protocol 走查示范（假设协议，示意流程非交付代码）

以「mock：长度前缀帧 + token 握手」为例的最小走查：Step 0 → grep Go 假设上游 `proxy/mock/`（无则按 spec 自证并在票面注明「无 Go 对应」）；Step 1 → 建 `crates/xray-proxy-mock/`（§3.3 树）；Step 2 → `parse_mock_config` 认 `{"token": "...", "servers":[...]}` 与 v2rayN 裸字段两形态 + 两处 match 臂；Step 3 → `protocol/frame.rs`：`fn encode_frame(dst: &mut Buffer, payload: &[u8])`（长度前缀直写池句柄，零中间 Vec）+ `fn decode_frame(src: &mut MultiBuffer) -> Result<Option<Buffer>>`（半包返回 None 待续）；Step 4 → `make_mock_dial_fn`；Step 5 → inbound `with_dispatch` 接线；Step 6 → 单测 roundtrip + 双 start_full loopback + interop 双向；Step 7 → checklist 自查。全程触碰的既有文件仅 3 个（protocols.rs / outbound.rs / inbound.rs 各加一处）——这就是「容易拓展」的量化形态。

### 3.11 详细——既有协议的范式索引（写码前先读对应范式）

| 要写的东西 | 先读哪个 crate | 学什么 |
|---|---|---|
| QUIC/UDP 协议全流程 | `xray-proxy-tuic` | DialFn 工厂（dispatcher.rs:106/136）、双 start_full 集成测试五件套、UDP loopback |
| TCP 协议 + fallback | `xray-proxy-trojan` | Validator、fallback 决策树（dest 数字/缺失对齐 Go trojan.go:151-198） |
| 加密流协议的零分配 pump | `xray-proxy-vmess` | `next_ref()` 零分配 nonce + 持久 chunk_buf + `seal_into`/`open_in_place`（生产 pump 全部此形态） |
| 配置双形态兼容 | `xray-proxy-ss` | d0555c26 裸字段/数组归一；SS-2022 rekey 仅密钥上限时 |
| QUIC 路径优化写法 | `xray-transport-hysteria` | poll_write 直通零 to_vec、Bytes::freeze owned 组包、BufPool 对齐 Go pool.Get/Put、收发 scratch 字段化 |
| TLS 流的 caller-scratch 编解码 | `xray-proxy-vless` `encryption/vision.rs:149-201` | padding out-param + padding_scratch 容量流转 + downlink 直写复用（vscd 修后范式） |
| handler 生命周期教训 | `xray-proxy-anytls` | §2 坑 2 事故现场与修法（start() 外移 + pending 保活） |
| 反面教材（待 P1 收口） | `xray-transport-splithttp` | h2/Bytes 边界 to_vec 族 F1/F2/F3/F15——新协议严禁模仿，等 `from_bytes_frozen` |

## 4. 皮囊契约

### 4.1 TL;DR

**配置形态兼容承诺**：Go Xray-core 已定义的配置形态（含 v2rayN 混排 JSON、`streamSettings` 等历史形态）是**兼容承诺**：内部重构不得破坏既有配置解析。自创配置形态不进承诺；框架 API 永不领先 Go 改名。反面教材：proxyman 平行世界（建了即不接入）——皮囊对接一律走生产装配路径。
**commander API 边界**：commander 是皮囊对骨架/血肉的管理面入口；对外 API 变更同样受 §6 转正门槛约束；皮囊不触碰血肉内部结构。

### 4.2 详细——v2rayN 混排形态承诺清单（逐项，锚点可验）

| # | 形态 | 锚点/出处 |
|---|---|---|
| 1 | SS 出站 settings 双形态：`servers` 数组（Go 形态）与裸字段 `address/port/method/password`（v2rayN 形态）同认，归一到同一解析 | d0555c26（「missing servers array」用户实锤修复） |
| 2 | DNS `servers` 双形态：对象数组与裸字符串同认 | dd0ae34b，对齐 Go infra/conf/dns.go:37-41；deserialize_with 逐条目分流 |
| 3 | VLESS 出站 `encryption` 为 settings 顶层 flat 字段（非 `users[].encryption`） | 对齐 Go infra/conf/vless.go:253（L301 account.Encryption 灌入） |
| 4 | `streamSettings`/`sniffing`/`mux`/`proxySettings` 子对象**原样透传**（`Option<serde_json::Value>`，不强 schema） | xray-conf/src/config.rs:157,188；built.rs:56-74 |
| 5 | 入站 `clients` 数组形态 | xray-conf/src/built.rs:463（测试断言） |
| 6 | 明文出站禁令语义：vless `encryption=none` 或 trojan 无 TLS 且目标非私网 → 启动硬错；已有 `security` 则放行 | d7fa2076，Go infra/conf/xray.go:245-266；outbound_security.rs:116-123 |
| 7 | transportLayer 代理门控：`proxySettings.tag` 与 `sockopt.dialerProxy` 同设冲突硬错；`transportLayer: true` 时 dialerProxy 注入 streamSettings | Go xray.go:248-250,316-327；built.rs:272-355（bd enk） |

边界条款：以上为**已实证形态**的封闭清单；新历史形态「发现一个、修复一个、单测钉一个」（先例 SS/DNS 两票），不预设猜测性兼容。大小写/别名等未验证形态**不在承诺内**，修复前先 grep Go 确认 Go 侧行为。

实证形态的 JSON 对照（commit 原文语义）：

```json
// #1 SS 出站双形态（d0555c26）：
{"protocol": "shadowsocks", "settings": {"servers": [{"address": "h", "port": 8388, "method": "2022-blake3-aes-128-gcm", "password": "…"}]}}   // Go 形态
{"protocol": "shadowsocks", "settings": {"address": "h", "port": 8388, "method": "2022-blake3-aes-128-gcm", "password": "…"}}                  // v2rayN 裸字段
// #2 DNS servers 双形态（dd0ae34b，Go dns.go:37-41）：
{"dns": {"servers": [{"address": "8.8.8.8"}, {"address": "1.1.1.1"}]}}   // 对象数组
{"dns": {"servers": ["8.8.8.8", "1.1.1.1"]}}                              // 裸字符串
```

### 4.3 详细——commander API 现有端点清单

- **暴露形态**：gRPC（tonic）；listen 为 TCP（`127.0.0.1:port`）或 Unix socket（commander.rs:43-46）；**声明制**——`ApiConfig.services` 列举的服务才暴露（commander.rs:191-194，对齐 Go Commander.Start）。
- **HandlerService**（proxyman 命令面，grpc.rs:39-47,88-92,244）：inbound 7 op + outbound add/remove/list 共 10 op。三级后端优先级：proxyman 领域 service（ihm/ohm 双 manager）> `OutboundRuntime`（SimpleOhm，bd ze3，仅 outbound 三 op）> stub；未注入 → UNIMPLEMENTED 明示。
- **StatsService**（grpc.rs:51）、**LoggerService**（RestartLogger，grpc.rs:36-37,364-368）、**RoutingService**（TestRoute 支持 FieldSelectors 投影 / GetBalancerInfo / SubscribeRoutingStats，grpc.rs:15-17）、**ObservatoryService**（grpc.rs:57-59）。
- **注入点**：`xray-core/src/functions.rs:364-367`（bd ze3/bg7：HandlerService 操作生产 SimpleOhm，LoggerService 接 LogInstance::restart，对齐 Go Commander.Start RequireFeatures）。
- **变更程序**：proto 变更走 `xray-proto`；对外语义变更过 §6 转正门槛；**平行世界禁令**——proxyman crate 的平行装配不接入皮囊，皮囊只走生产路径。

### 4.4 详细——皮囊兼容性变更程序

1. 用户实锤（报错日志/测速异常）→ 2. grep Go 基线确认 Go 侧行为（该形态 Go 认不认、怎么解析）→ 3. Rust 侧双形态归一（入口分支映射同一引用，学 d0555c26）→ 4. 单测钉死两形态 + 一条硬错负例 → 5. commit message 写明用户症状与 Go 对齐点 → 6. §4.2 清单加行。**禁止**：无 Go 依据的猜测性兼容（自创形态混进承诺清单会永久锁死解析器）。

## 5. 五阶段路线图

### 5.1 TL;DR

总纪律：每阶段出口 = CI 九门 + bench 护栏非回归 + 网络面改动走**真实端点同窗配对 A/B**（localhost 测不出窗钉与网络路径回归）。护栏工具链现成：loopback 吞吐矩阵（基线 154–167MB/s）、stress.yml、xray-stress 场景 s5–s12、clippy 宽门镜像。依赖：P0 → P1 → {P2 ∥ P3} → P4；P3 的超时项依赖 P2 的 AcceptLimits 落点。

| 阶段 | 交付 | 可证伪出口判据 |
|---|---|---|
| P0 护栏先行 | 计数分配器（feature `bench-alloc`）；clippy 禁令清单；loopback + 三协议真实端点基线 | 三份基线数字落档。**没有 P0 数字，后续一切「无回归」都是口头声明** |
| P1 数据面收口 | `from_bytes_frozen`；io.rs 去 box + 装饰链直通；splithttp 四处 to_vec 关闭、grpc 双拷贝、kcp scratch、vision 收尾 | 三协议 alloc/MB 改善 + 吞吐非回归 + grep 证明热路径 to_vec 清零 |
| P2 accept 框架 | `accept_loop`/`AcceptLimits`/`StreamHandshake`（PROXY protocol 进超时窗）；ws/httpupgrade/tcp 迁移并删手写循环；per-stage 计数；QUIC/UDP 薄模板；slowloris/慢读/flood conformance 进 CI | `grep -r "listener.accept" crates/` 仅剩框架与 QUIC 模板；三类攻击用例绿 |
| P3 调参 + 观测 | 窗口/超时常量进配置；relay 积压水位 + per-tag 错误计数 | 一次真实调参全程不碰 cargo；挂死演练从发现到定位 <5 分钟 |
| P4 API 转正 | recipe 文档；API stable 标记；Go↔Rust 映射表 + PR porting note 字段 | 下一真实新协议按 recipe 落地：零框架外分配、零手写 accept |

### 5.2 详细——任务分解（可派单粒度）

**P0 护栏先行**（4 票，内部依赖 T0.1→T0.3→T0.4）：
- T0.1 计数分配器：feature `bench-alloc`，全局分配器 wrapper（绕 mimalloc 统计），按 relay 方向统计 alloc 次数/字节数/MB。验收：可对任意 e2e 场景输出 alloc/MB 报告。
- T0.2 clippy 禁令：`disallowed-methods` 清单（热路径 crate 禁 `to_vec`/裸 `Vec::new` 入池），存量命中逐个豁免注理由。验收：CI 红线生效，新增 bypass 进不来。
- T0.3 bench 基线：loopback 吞吐矩阵 + splithttp/vision/grpc 三协议真实端点同窗配对（各 5 轮取中位）落档。
- T0.4 三份基线报告（依赖 T0.1+T0.3）：**P0 出口 = 三份数字，没有它们后续「无回归」都是口头的**。

**P1 数据面收口**（6 票，依赖 P0；T1.3 依赖 T1.2）：
- T1.1 `Buffer::from_bytes_frozen` + MultiBuffer 兼容（内部 enum Frozen|Pooled）。验收：hyper Bytes→relay 全程 0 拷贝（计数分配器证明）。
- T1.2 io.rs trait poll 化 + 具名 future + `BoxedReader` 边界适配。验收：loopback ≥ 基线；UDP 小包 relay bench。
- T1.3 装饰链直通：SizeStat/Cached/EndpointOverride 改 poll 转发。验收：装饰链 alloc/MB 归零（N box→0，最大单笔收益）。
- T1.4 splithttp F1/F2/F3/F15 关闭（dialer.rs:92,374 / h3_client.rs:386 / hub/handler.rs:328 / upload_queue.rs:165，Packet payload 统一 `Bytes` 化）。护栏：splithttp 既有 interop + e2e + 真实端点同窗 A/B。
- T1.5 grpc F4/F5 关闭（hunk 序列化单次成型 + down 泵借用解码直写消 drain）。护栏：grpc interop 双向 + 多帧粘包单测。
- T1.6 kcp F6/F7（writer 持久 scratch + poll_read scratch 字段化，对齐 Go output.go:32-35）+ vision 收尾（poll_write_vectored 按既定结论，splice 闸门不动）。护栏：kcp tests `--test-threads=1`；vision 真实端点 A/B（3.3-3.8 → 池化预估 10-15MB/s，实测为准）。

**P2 accept 框架**（5 票，不依赖 P1；T2.2/T2.3/T2.4 依赖 T2.1，T2.5 依赖 T2.2）：
- T2.1 `accept_loop` + `AcceptLimits` + `StreamHandshake` 骨架（PROXY protocol 进超时窗）。验收：超时/信号量/close-abort 单测。
- T2.2 ws/httpupgrade/tcp 三 transport 迁移，删除各自手写循环与点状 4s 补丁。验收：`grep -r "listener.accept" crates/` 仅剩框架与 QUIC 模板。
- T2.3 per-stage 计数 + gauge（accept 速率/握手延迟直方图/超时数/active conns，定期 tracing）。验收：flood 下 inbound 存活，观测数字与测试断言联动。
- T2.4 QUIC/UDP 薄模板（复用 limits + 观测，含 open_bi 首包语义）。验收：tuic/hysteria 既有 e2e 全绿。
- T2.5 slowloris/慢读/flood conformance 进 CI。验收：max_pending 占满时新连接排队非拒绝、超时 permit 释放、三类用例绿。

**P3 调参 + 观测**（4 票，与 P2 并行；T3.1 的超时项依赖 T2.1）：
- T3.1 常量进配置：TCP SO_RCVBUF 缺省 / h2 STREAM_WINDOW+conn 窗+max_send_buf / hyper send_buf / bridge idle（300s/1s）/ 握手 timeout。验收：enc8x 16MB 窗 @0.3s RTT 40-60MB/s 用配置复现一次。
- T3.2 relay 积压水位（channel 深度）+ per-tag 错误计数。验收：人为制造 2087 型挂死，告警/日志 <1min 暴露。
- T3.3 挂死演练验收：<5 分钟从发现到定位（对照 5 小时）。
- T3.4 全流程验收：一次真实调参全程不触碰 cargo。

**P4 API 转正**（3 票，依赖 P1+P2 用户落地）：
- T4.1 recipe 文档（本 §3 的持续修订版）+ trivial 协议端到端（echo over 自定义帧按 recipe 从零实现）。验收：跑通 + 新旧写法代码量/分配次数对照表。
- T4.2 API stable 标记（≥3 用户 + 各有同窗 A/B；首批候选 splithttp/grpc/kcp/ws/httpupgrade/tcp）。验收：stable 集合全过门槛，其余仍 `pub(crate)`/`#[doc(hidden)]`。
- T4.3 Go↔Rust 映射表（xray-buf crate doc）+ PR porting note 模板。验收：一次真实上游同步演练走查表。

## 6. 纪律机制

### 6.1 TL;DR

1. **clippy 禁令**：`disallowed-methods` 清单——热路径 crate 禁 `to_vec`/裸 `Vec::new` 入池；豁免逐个注明理由；CI 红线，新 bypass 进不来。
2. **计数分配器**：feature-gated；relay 按方向统计 alloc 次数/字节数/MB；一切分配声明从这里读数，不靠肉眼。
3. **API 转正门槛（hard gate）**：API 标记 stable 需 ≥3 个真实协议用户 + 每个都有同窗 A/B 数字；此前一律 `pub(crate)` 或 `#[doc(hidden)]`。首批用户必须形状多样（splithttp = h2/Bytes 边界、grpc = 消息帧、kcp = UDP），防止过拟合 TCP 流式。
4. **负优化前科铭记**（每条都发生过，勿重演）：bridge 泵 revert 378ab889；splice 双 revert d8562b56/a427613b；ReadVReader 真网 -25% a07041ae。推论：先验抽象在本仓命中率≈0；凡优化必须真实端点同窗配对 A/B。
5. **Go diff 纪律**：镜像式框架化降低 diff（Go `common/buf` 本就存在，协议可 1:1 移植；自创式才拉大 diff）；xray-buf 维护 Go API↔Rust API 映射表；PR 模板带 porting note 字段（上游改动是否触及 buf 所有权/窗口/超时/accept 语义）。

### 6.2 详细——操作形态

- **clippy 禁令落点**【规划 P0】：clippy.toml `disallowed-methods`（热路径 crate 成员按 workspace lints 继承）；每条豁免格式 `// alloc-exempt: <理由>（bd 票号）`。宽门镜像 CI：clippy `--workspace --all-targets -D warnings` + `cargo doc --workspace --no-deps` + stable fmt（本地门窄于 CI 门 = 必漏，两次实证）。
- **计数分配器用法**【规划 P0】：`cargo run --features bench-alloc -- <scenario>` 输出分方向 alloc/MB；改造票的 before/after 数字贴 bd 票面；禁止口头声称「省了分配」。
- **API 转正流程**（五步）：候选期 `pub(crate)`/`#[doc(hidden)]` → 收集 ≥3 真实协议用户（try_build_handler 臂里的生产用户才算）→ 每用户一份同窗 A/B 数字 → 数字入 bd 票归档 → 标 stable + 登记映射表。缺任一步 = 保持隐藏。
- **A/B 规程**：同 binary 同窗交替（跨时间窗对比无效——v2rayN 测速缓存行与 30gf 谷底两次实证）；真实端点（localhost 测不出窗钉与网络回归——vision/88m0 实证）；各 5 轮取中位；基线对照组同窗配对采样（均值盲于轮内深谷）。
- **porting note 模板**：`上游改动是否触及 buf 所有权/窗口/超时/accept 语义 → 是：<Rust 侧对应改动点清单>；否：一行说明`。
- **CI flake 处置纪律**：1 挂 = rerun `--failed`，rerun 绿 = 絮态放行；**连续 2 挂同位置 = 确定性缺陷，停手诊断不按 flake 处理**（两次实证）。已知 flaky：macOS kcp、e2e_p2_dns_core_resolution。验证统计：发生率 p 的偶现缺陷，N 轮捕获概率 = 1-(1-p)^N（25% 时 20 轮 ≈ 99.7%）。

### 6.3 详细——派单契约模板（宪法对齐字段）

每个 AI 子代理派单的票面必须含以下字段（缺一 = 打回）：

```text
# 目标     一句话；引用宪法章节号（如「实现 §3.4 Step 2 注册臂」）
# 红线     本票不得触碰的锚点（如 §1.1 义务边界、逃生舱、既有豁免清单）
# 现状锚点 本票涉及的 file:line（派单前 grep 过的）
# 验收     可证伪判据（引用 §5.2 任务号或 §3.9 checklist 项）；含要跑的门（§6.2）
# 禁止     把【规划】写成已实现；新增 Box::pin/to_vec/手写 accept；跨窗对比数据
```

子代理报 PASS ≠ 真 PASS（Batch16 实证：子代理只跑自加测试漏 4 处 fixture）——主代理验收必须跑全套受影响面的测试，不看子代理自报。

## 7. 明确不做（负面清单）

### 7.1 TL;DR

新调度器 / executor 包装；ECS 与组件化；宏生成 codec；全新 trait 宇宙 / ASIO 风格 generic 重构；中央帧循环 / 运行时接管调度；「协议完全不用理解内存」的彻底隐藏；为 100% 协议强制统一抽象（某些流量永远不走框架是常态，不是债）；先写框架再迁移协议（改造中沉淀，proxyman 平行世界为戒）。

### 7.2 详细——每条的为什么

| 不做 | 理由（证据） |
|---|---|
| 新调度器/executor 包装 | tokio 已托管 spawn/IO/定时器；包装层纯开销零收益（oracle §1.4） |
| ECS/组件化 | 代理是连接并行事件驱动，无帧循环无可组合生命周期（oracle §1.4） |
| 宏生成 codec | 调试、IDE、上游 diff 三输（oracle §1.4） |
| 全新 trait 宇宙/ASIO 式 generic 重构 | xi40 dyn/boxing 抽象的下场 + 方案 C 确定负收益（oracle §2.1 否决记录） |
| 中央帧循环/运行时接管 | 引擎类比无效项：代理无 tick 无帧预算，中央循环是倒退（oracle §6） |
| 完全隐藏内存 | 线格式帧边界=缓冲边界=窗口大小，三个窗钉战役（88m0/enc8x/vision）实证内存决策=协议语义（oracle §6） |
| 100% 协议强制统一 | 60+ 目标站点 splice 架构级需求——「某些流量永远不走框架」是常态（oracle §1.4d） |
| 先写框架再迁移 | 先验抽象负优化前科 ×3 命中率零 + proxyman 平行世界建了不接入（oracle §4） |

---

变更记录：2026-10-11 初版（138 行审定版，即本文各节 TL;DR 层），依据 oracle 裁决书 + AllocAudit 审计起草；同日增补 §2「框架吃掉的 Rust 坑清单」（所有者要求）；同日新增英文版 ARCHITECTURE.en.md（互链，双语同步纪律：中文为主，修订双记）；裁决书/审计两份治理输入迁入 `docs/refs/`（原出处 D:/tmp/，md5 一致：0692ca24…/f50019a5…）；同日按所有者要求展开详细版（≤300 行限制解除，目标 500-800 行/语种；TL;DR 层内容原样保留，§0.3/1.2/2.2/3.2-3.10/4.2-4.3/5.2/6.2/7.2 为展开层；详细度标准=未参与决策会话的协议开发者只读本文即可正确开发）。

治理输入出处注：`docs/refs/oracle-framing-arch.md`（FramingArch 裁决书，2026-10-11）与 `docs/refs/alloc-audit-report.md`（全仓数据面热路径内存分配审计）原出处为会话临时目录 D:/tmp/，2026-10-11 字节一致拷贝入仓（.gitignore 已加 `!docs/refs/` 例外）。

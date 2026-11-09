//! 连接双向桥接——dispatch 链路的基础组件。
//!
//! 对应 Go `transport/pipe.New` + `cnc.NewConnection` 的双向 copy 语义。
//! 把两个 [`Connection`] 的读写半部交叉连接，任一方向 EOF 或出错时整体返回。
//!
//! ## 使用场景
//!
//! dispatcher 在 `dispatch_link` 中：
//! 1. inbound handler 接受客户端连接 → `inbound_conn`
//! 2. outbound handler 拨号到目标 → `outbound_conn`
//! 3. `bridge_connections(inbound_conn, outbound_conn)` 双向转发字节流
//!
//! 客户端发的数据流向 outbound（→ 目标服务器），目标服务器的响应流向 inbound（→ 客户端）。

use std::io;

use tokio::io::{AsyncRead, AsyncWrite};
use xray_features::policy::TimeoutPolicy;
use xray_frame::deadline::Budget;

#[cfg(test)]
use crate::connection::DuplexConnection;
use crate::{connection::Connection, link::Link};

// hot-log 归口（能力收敛方案 §2 面 4）：splice 选择点（每连接级）已迁
// crate::HOT_LOG 栈缓冲门面（先过滤后格式化，级别未命中零格式化零分配）。
// XRAY_P7LM_TRACE 门内每包 trace（9 处）按同方案「不可迁残余 2」保留原样——
// 它是调查通道非日志通道，改写会污染 F2F3 归因。

/// 桥背压条目闸容量（每方向 mpsc 条数）。pub 理由：交叉断言的**实现侧事实源**
/// ——`xray-core::memory_budget` 的桥在途登记簿断言由此推导（D-05：禁簿值
/// 自证字面量），改本值必须同步重算登记簿（66 = 本值 + 读/写腿手上各 1）。
pub const PIPE_BUF_CAP: usize = 64;

/// 双向桥接两个 [`Connection`]。
///
/// 内部用 [`tokio::io::split`] 拆分每个连接的读写半部，然后用
/// **xray-buf 分层池**（8KB 默认）双向异步复制。任一方向完成（EOF）或出错时，
/// `select!` 返回，函数返回首个错误（若两端都成功则返回 `Ok`）。
///
/// **注意**：连接在桥接期间被 `split` 持有，桥接结束后两个半部被 drop，
/// 底层 TCP 连接随之关闭。调用方无需手动 close。
///
/// # 参数
///
/// - `a`：连接 A（通常是 inbound 客户端连接）。
/// - `b`：连接 B（通常是 outbound 目标连接）。
///
/// # 返回
///
/// - `Ok(())`：两个方向都正常 EOF。
/// - `Err(e)`：至少一个方向出错，返回首个遇到的 IO 错误。
///
/// ponytail: 池化读循环（8KB `xray_buf::alloc`）替代 `tokio::io::copy` 的
/// 内部 8KB Vec，连接结束后回池——避免长连接/大流量时反复 alloc 大块堆。
pub async fn bridge_connections(a: Box<dyn Connection>, b: Box<dyn Connection>) -> io::Result<()> {
    // Go `CanSpliceCopy` 零值 0（session.go:75-77）＝信号未挂出，永入回退泵——
    // 既有调用方行为跨平台零变化；只有 freedom 出站 TCP 场景显式传
    // `(1, &[1])`（freedom.go:260 唯一置 1 点）。
    bridge_connections_with_splice(a, b, 0, &[]).await
}

/// 带信号闸门的 [`bridge_connections`]：Go `proxy.CopyRawConnIfExist`
/// （proxy/proxy.go:718-792）等价入口。
///
/// splice(2) 零拷贝双向泵的准入 = [`xray_common::platform::splice::splice_allowed`]
/// （env `xray.buf.splice` + 平台 Linux/Android + CanSpliceCopy 全 1 信号）
/// 且两端均 [`Connection::is_raw_tcp`]（Go `IsRAWTransportWithoutSecurity`；
/// TLS/REALITY/fragment 包装层缺省拒绝）。任一条件不满足 → 回退下方既有
/// 池化泵（对应 Go 回退 readV，proxy.go:722-741；Windows/包装连接现状零变化）。
pub async fn bridge_connections_with_splice(
    a: Box<dyn Connection>,
    b: Box<dyn Connection>,
    inbound_can: i32,
    outbounds_can: &[i32],
) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some((ra, rb)) = crate::splice::plan(&*a, &*b, inbound_can, outbounds_can) {
        crate::hot_log!(DEBUG, "CopyRawConn splice");
        crate::splice::bridge_with(ra, rb).await?;
        return Ok(());
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = (inbound_can, outbounds_can);

    use tokio::io::AsyncReadExt;

    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);

    // 池化读循环：替代 tokio::io::copy 的内置 Vec，每次循环取一次池化缓冲，
    // 读后整段 write_all 到底层（无中间 merge_bytes 拷贝，bd etks 同源优化）。
    async fn copy_pooled<R, W>(mut reader: R, mut writer: W) -> io::Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;
        let mut buf = xray_buf::alloc::alloc(xray_buf::alloc::DEFAULT_SIZE);
        buf.resize(xray_buf::alloc::DEFAULT_SIZE, 0);
        loop {
            let n = match reader.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    xray_buf::alloc::release(buf);
                    return Err(e);
                },
            };
            if n == 0 {
                break;
            }
            if writer.write_all(&buf[..n]).await.is_err() {
                break;
            }
            // 写穿语义（同 write_all_mb）：TLS 层 SSL_write 缓冲语义下尾 chunk
            // 不 flush 不上线；Go `crypto/tls` 的 Write 直接落底层 conn。
            if writer.flush().await.is_err() {
                break;
            }
        }
        xray_buf::alloc::release(buf);
        let _ = writer.shutdown().await;
        Ok(())
    }

    let a_to_b = copy_pooled(&mut a_read, &mut b_write);
    let b_to_a = copy_pooled(&mut b_read, &mut a_write);

    tokio::pin!(a_to_b, b_to_a);

    // 任一方向 EOF/出错就返回（对应 Go pipe 在一端关闭时另一端也关闭的行为）。
    // 另一个方向的 copy future 被 drop 取消，底层连接随后关闭。
    let result = tokio::select! {
        res = &mut a_to_b => res,
        res = &mut b_to_a => res,
    };

    result
}

/// 单向桥接：从 `reader` 复制到 `writer`，EOF 或出错时返回。
///
/// 比 [`bridge_connections`] 更简单，用于只需要单向转发的场景（如 UDP 中继的
/// 单向 copy）。通用泛型版，接受任何 `AsyncRead` + `AsyncWrite`。
pub async fn copy_one_way<R, W>(mut reader: R, mut writer: W) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    tokio::io::copy(&mut reader, &mut writer).await
}

/// 双向桥接 dispatcher [`Link`]（xray-buf Reader/Writer）与 AsyncRead+AsyncWrite stream。
///
/// 上行：`link.reader` 读到的 MultiBuffer → 转 bytes → `stream` 写出。
/// 下行：`stream` 读到的数据 → 转 MultiBuffer → `link.writer` 写出。
///
/// 两个方向独立运行到都完成（`join!` 语义）——任一方向 EOF/出错不会取消另一方向。
/// 适配 VMess 这种请求方向提前 EOF（body chunk 终止符）但响应方向仍需续传的场景。
/// 调用方无需手动关闭——stream 在桥接结束后被 drop。
pub async fn bridge_link_with_stream<S>(link: Link, stream: S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use xray_buf::{
        io::{Reader, Writer},
        multi::MultiBuffer,
    };

    let Link { mut reader, mut writer } = link;
    let (mut s_read, mut s_write) = tokio::io::split(stream);

    // 上行：link.reader → stream
    let up = async move {
        loop {
            let mb = match reader.read_multi_buffer().await {
                Ok(mb) => mb,
                Err(_) => break,
            };
            if mb.is_empty() {
                break;
            }
            if write_all_mb(&mut s_write, &mb).await.is_err() {
                break;
            }
        }
        let _ = s_write.shutdown().await;
        io::Result::Ok(())
    };

    // 下行：stream → link.writer
    let down = async move {
        // 池化读缓冲（xray-buf 分层池，对应 Go sync.Pool）；resize 置满长度供 read 覆写
        let mut buf = xray_buf::alloc::alloc(xray_buf::alloc::DEFAULT_SIZE);
        buf.resize(xray_buf::alloc::DEFAULT_SIZE, 0);
        loop {
            let n = match s_read.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    xray_buf::alloc::release(buf);
                    return Err(e);
                },
            };
            if n == 0 {
                break;
            }
            let mut mb = MultiBuffer::new();
            mb.merge_bytes(&buf[..n]);
            if writer.write_multi_buffer(mb).await.is_err() {
                break;
            }
        }
        xray_buf::alloc::release(buf);
        // bridge 结束前通知读端 EOF（pipe.Writer.close）。
        // bd VISIONMAC：TLS 隧道场景须 flush+shutdown 排空滞留尾巴（同
        // bridge_link_with_stream_full down_writer 注释）；pipe 场景默认
        // 实现退化为 shutdown() EOF 信号，行为不变。
        let _ = Budget::tokio()
            .deadline(std::time::Duration::from_secs(3))
            .timeout(writer.shutdown_flush())
            .await;
        io::Result::Ok(())
    };
    tokio::pin!(up, down);
    let result = tokio::select! {
        res = &mut up => res,
        res = &mut down => res,
    };
    result
}

/// 逐 MultiBuffer 聚合写出（零拷贝，Buffer Drop 自动回池）。
///
/// vectored 写半部（y1yx）：`is_write_vectored` 为真时把 mb 内全部 Buffer
/// 组 IoSlice 栈数组（每批 ≤8，对齐 Go readv 上界）经 `write_all_vectored`
/// 单/少次 syscall 摊销；非 vectored 半部（TLS/wrapper 等）降级逐 Buffer
/// `write_all`。两条路径均零数据拷贝、零堆分配。
///
/// **写穿语义（flush）**：每批写完显式 `flush()` 一次——TLS 层（btls/BoringSSL）
/// 的 `SSL_write` 是缓冲语义，尾 record 滞留 session 缓冲；上层不 flush 时
/// 尾 chunk 直到下一次写/关闭才上线，对端凑不齐请求 → 双向死锁。Go 侧无此坑：
/// `crypto/tls` 的 `Conn.Write` 直接把 record 写进底层 conn（conn.go:952-958
/// `write()` → `c.conn.Write`，仅握手期 buffering），即 Go 是**写穿**语义。
/// 本函数补齐 flush = 与 Go 的写穿语义对齐；裸 TCP 的 `poll_flush` 是空操作
/// （零 syscall 代价），TLS 侧则是把已缓冲 record 推上线。
///
/// flush 只影响**上线时机**，不改字节内容与顺序；TLS record 边界仍由 TLS 栈
/// 自己分（wire 不变量，本函数不碰）。
async fn write_all_mb<W>(w: &mut W, mb: &xray_buf::multi::MultiBuffer) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    /// 单批 iovec 数量上界（对齐 Go `allocStrategy` 的 readv 最大缓冲数）。
    const VECTORED_BATCH: usize = 8;

    if w.is_write_vectored() {
        let mut iter = mb.iter().filter(|b| !b.bytes().is_empty());
        loop {
            let mut slices = [io::IoSlice::new(&[]); VECTORED_BATCH];
            let mut n = 0;
            while n < VECTORED_BATCH {
                match iter.next() {
                    Some(b) => {
                        slices[n] = io::IoSlice::new(b.bytes());
                        n += 1;
                    },
                    None => break,
                }
            }
            if n == 0 {
                break;
            }
            // 推进循环写尽整批（tokio write_vectored 是单次 attempt，可能部分写）。
            let mut pending: &mut [io::IoSlice<'_>] = &mut slices[..n];
            while !pending.is_empty() {
                let written = w.write_vectored(pending).await?;
                if written == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write_vectored returned 0",
                    ));
                }
                io::IoSlice::advance_slices(&mut pending, written);
            }
        }
        w.flush().await?;
        return Ok(());
    }

    for b in mb.iter() {
        let bytes = b.bytes();
        if !bytes.is_empty() {
            w.write_all(bytes).await?;
        }
    }
    w.flush().await?;
    Ok(())
}

/// 埋点开关解析（bd 7p1m）：未设 → 关；显式假值（`0`/`false`/`off`/`no`/空）→ 关；其余 → 开。
///
/// 修正历史语义：旧实现用 `env::var(..).is_ok()`，导致 `XRAY_P7LM_TRACE=0` 也开启逐批
/// `warn!` 埋点——该埋点的 trace 税曾把 F2/F3 优化实测毒化成伪影（约 36% 吞吐）。
fn p7lm_trace_enabled(raw: Option<&str>) -> bool {
    match raw {
        None => false,
        Some(v) => {
            !matches!(v.trim().to_ascii_lowercase().as_str(), "" | "0" | "false" | "off" | "no")
        },
    }
}

/// 开关进程级缓存：env 只在首次桥接时解析一次，之后每连接/每批只读 `bool`
/// （`env::var` 每调用一次都查进程环境表，桥接泵属数据面热路径）。首值即
/// 定案，进程运行中改 env 不生效——trace 开关不承诺运行期热切换。
static P7LM_TRACE: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
    p7lm_trace_enabled(std::env::var("XRAY_P7LM_TRACE").ok().as_deref())
});

fn p7lm_trace() -> bool {
    *P7LM_TRACE
}

// ── 内存自适应的在途字节闸 + 连接数上限（bd sfqlu，2026-11-07 用户拍板）──
//
// 分工：**单连接窗口不压缩**（BDP 是吞吐命脉，u440m 砍到 2MiB 即 −6.1%），
// 内存靠**连接数上限**（`总预算 / 每连接规划上界`）控制。字节闸只在「生产者远快于
// 消费者」的满载瞬态兜底，闸值恒 ≥ 实测 BDP 上沿（3.56MB）⇒ 正常链路不 binding。

/// 每方向在途字节闸。
///
/// 闸值 = [`xray_frame::budget::plan::MemoryPlan::bridge_gate`]（四档 5/12/24/32 MiB）。
/// 为什么不是 u440m 的固定 2MiB：RTT 161.6ms 下 BDP 2.39–3.56MB > 2MiB ⇒ 闸把吞吐
/// 钉在 ≈12.9MB/s（A/B 中位比 0.939，超 5% 门已回退）。闸的用途只是把「64 条目 ×
/// 512KiB = 32MiB/方向」的满载瞬态收成有限值。
struct ByteGate {
    cap: usize,
    inflight: std::sync::atomic::AtomicUsize,
    notify: tokio::sync::Notify,
}

/// 在途字节许可（随块 move 到写腿，写完 drop 即归还）。
struct GatePermit {
    gate: std::sync::Arc<ByteGate>,
    bytes: usize,
}

impl Drop for GatePermit {
    fn drop(&mut self) {
        self.gate.inflight.fetch_sub(self.bytes, std::sync::atomic::Ordering::AcqRel);
        self.gate.notify.notify_one();
    }
}

impl ByteGate {
    fn new(cap: usize) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            cap,
            inflight: std::sync::atomic::AtomicUsize::new(0),
            notify: tokio::sync::Notify::new(),
        })
    }

    /// 取 `bytes` 字节在途许可；未超闸时**零等待**（一次原子读 + 一次原子加）。
    async fn acquire(self: &std::sync::Arc<Self>, bytes: usize) -> GatePermit {
        loop {
            let inflight = self.inflight.load(std::sync::atomic::Ordering::Acquire);
            // 单个超闸块永不阻塞（闸是软上界，堵死 = 连接挂死）：只在闸内叠加时等。
            // 并发下两个块可能同时通过判定而超闸少量——软上界，不追精确。
            if inflight == 0 || inflight + bytes <= self.cap {
                self.inflight.fetch_add(bytes, std::sync::atomic::Ordering::AcqRel);
                return GatePermit { gate: std::sync::Arc::clone(self), bytes };
            }
            self.notify.notified().await;
        }
    }
}

/// 进程内在跑的双向桥数（= 代理连接数）。
static ACTIVE_BRIDGES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// 连接名额（drop 即归还）。触顶 = [`ConnSlot::try_acquire`] 返 `None`。
struct ConnSlot;

/// 连接数上限（执行点唯一读数）。
///
/// 读 [`xray_frame::budget::plan::MemoryPlan::effective_max_conns`] 而非档位原值
/// `max_conns`：装配期预算门按本配置算出的**降档值**写在那里（bd 2026-11-08
/// D-02）——旧状只写 warn 文案，执行点仍用档位原值，运维看到的数字不是生效的数字。
fn conn_limit() -> usize {
    xray_frame::budget::plan::MemoryPlan::cached().effective_max_conns()
}

impl ConnSlot {
    /// 取一个连接名额；已达本机档位上限 → `None`（调用方 fail-visible 拒绝）。
    fn try_acquire() -> Option<Self> {
        try_take_slot(&ACTIVE_BRIDGES, conn_limit()).then_some(Self)
    }
}

/// 原子占名额（`fetch_update` 保证「判定 + 自增」不可分割，不会超发）。
fn try_take_slot(active: &std::sync::atomic::AtomicUsize, limit: usize) -> bool {
    active
        .fetch_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |cur| (cur < limit).then_some(cur + 1),
        )
        .is_ok()
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        ACTIVE_BRIDGES.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// 连接数触顶的 fail-visible 拒绝（日志 + `Err`）：绝不静默降级、绝不放任 OOM。
fn connection_limit_error() -> io::Error {
    let plan = xray_frame::budget::plan::MemoryPlan::cached();
    // 报执行点的**生效**值（降档后），不是档位原值——运维看到的数字必须与
    // `ConnSlot` 拒绝时用的那个一致（bd 2026-11-08 D-02）。
    let limit = conn_limit();
    tracing::error!(
        target: "xray_frame::bridge",
        limit,
        tier = plan.tier.as_str(),
        budget = plan.total_budget,
        "已达本机内存档位上限 {} 条连接（tier {} / 预算 {}B），拒绝新连接",
        limit,
        plan.tier.as_str(),
        plan.total_budget
    );
    io::Error::other(format!(
        "connection limit reached: 已达本机内存档位上限 {} 条（tier {} / 预算 {}B；\
         可用 XRAY_MAX_CONNS 覆盖）",
        limit,
        plan.tier.as_str(),
        plan.total_budget
    ))
}

/// 下行读一轮，把这轮分配归到 [`xray_common::alloc_site::BUF_READ`] 站点
/// （票 4y9ns Phase 0：读缓冲归因）。
///
/// 站点只能在调用侧标：`xray-common` 依赖 `xray-buf`，反向不成立，读缓冲的
/// 分配点（`xray-buf::reader`）引不到 `alloc_site`。站点覆盖整轮读——读缓冲
/// 容量远大于 `MultiBuffer` 包装开销，判读不受影响；未启用时 `scope` 直通。
///
/// 必须走 `scope`（未来域）而非 `enter`：本函数在 `.await` 期间可能被调度到别的
/// 线程续跑，线程局部标记会留在原线程（bd a65px：cli 侧 buf_read 99.8% 假分布）。
async fn read_downlink(
    r: &mut dyn xray_buf::io::Reader,
) -> xray_buf::io::Result<xray_buf::multi::MultiBuffer> {
    xray_common::alloc_site::scope(xray_common::alloc_site::BUF_READ, r.read_multi_buffer()).await
}

/// 连接中止闸等待（bd rjt2o）：闸已关时立即 Ready，否则挂起到关闸。
///
/// **只搬运判定，不新造判定**——关闸决定由既有读侧 deadline 分支做（单一超时
/// 账本，禁双份账，CLAUDE.md §3.5.6）。发送端全亡（桥已弃）按已关兜底。
/// 零分配、零拷贝；每批一次 `watch` poll（与同函数内已有的 `timeout()` 同量级）。
async fn wait_abort(rx: &mut tokio::sync::watch::Receiver<bool>) {
    let _ = rx.wait_for(|closed| *closed).await;
}

/// 收尾策略（bd degg3 设计 §4）：把「凭什么理由收尾」与「怎么收尾」分开。
///
/// 改造前写腿收尾唯一动作是 `shutdown()`，上行腿的四种终态（正常 EOF / 读错 /
/// 空闲超时 / 中止闸）被折叠成同一个动作 ⇒ 中继内部错误在 wire 上伪装成
/// 「请求正常完成」，服务端因此提前停止响应（bd myppb/cna1g）。反向的一刀切
/// （异常也不发结束信号）已被真机证伪：A 臂 32/32 vs B 臂 30/32（bd degg3）。
/// ⇒ 只能按**理由**分流，不能按方向分流。
mod end_policy {
    /// 腿终态原因（平台无关）。
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u8)]
    pub(super) enum LegEnd {
        /// 正常 EOF：源端确实不再发数据（空块 / `Error::Eof`）。
        CleanEof = 0,
        /// 级联退出：本向的 send/write 目标先亡（不是本向的语义结束）。
        PeerEnded = 1,
        /// 读错误（AEAD / 帧 / 传输错误）。
        ReadError = 2,
        /// 写错误（对端连接已坏，FIN 无意义）。
        WriteError = 3,
        /// connIdle 或半窗（uplinkOnly / downlinkOnly）到期：是判定，不是对端说
        /// 「我发完了」。
        IdleExpired = 4,
        /// 中止闸被其它腿置位（bd rjt2o：闸只搬运既有判定）。
        Aborted = 5,
    }

    impl LegEnd {
        /// 原因槽编码（跨腿投递用 `AtomicU8` 无载荷，冷路径各一次）。
        pub(super) const fn code(self) -> u8 {
            self as u8
        }

        /// 原因槽解码。越界按 `CleanEof`（= 改造前 `SignalEnd`）：槽必在读腿
        /// store 之后才被写腿读到（见 `bridge_link_with_stream_full` store 处
        /// 注释），越界不可达。
        pub(super) const fn from_code(code: u8) -> Self {
            match code {
                1 => Self::PeerEnded,
                2 => Self::ReadError,
                3 => Self::WriteError,
                4 => Self::IdleExpired,
                5 => Self::Aborted,
                _ => Self::CleanEof,
            }
        }

        /// warn 字段 `kind`。
        pub(super) const fn as_str(self) -> &'static str {
            match self {
                Self::CleanEof => "clean_eof",
                Self::PeerEnded => "peer_ended",
                Self::ReadError => "read_error",
                Self::WriteError => "write_error",
                Self::IdleExpired => "idle_expired",
                Self::Aborted => "aborted",
            }
        }
    }

    /// 收尾动作。
    ///
    /// ⚠️ 设计 §4.2 的第三档 `FlushOnly`（只 flush 不发结束信号）随 **Step 3**
    /// （能力维度：WS 全双工 + `CleanEof`）一起引入——本仓 `#![deny(warnings)]`
    /// 对「从不构造的变体」是硬错，先声明后使用只能靠 lint 抑制，故此刻不声明。
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum EndAction {
        /// flush + 结束发送方向（各 conn `poll_shutdown` 语义：FIN / END_STREAM /
        /// 终止 chunk / WS Close）。
        SignalEnd,
        /// 不发有序结束，直接全关（协议层无标记；有未读数据时按 RFC 9293
        /// SHLD-3 出 RST）。
        FullClose,
    }

    /// **唯一**决策点：纯函数，无 IO、无平台分支、无 `cfg`（splice 承载与
    /// stream 承载同源，故 Windows 可全量单测）。
    ///
    /// `CleanEof` / `PeerEnded` → `SignalEnd`：**与改造前字节级一致**（真机 32
    /// 节点 A 臂就是这条路径，禁改）。异常四档 → `FullClose`：不发有序结束。
    pub(super) const fn end_action(end: LegEnd) -> EndAction {
        match end {
            LegEnd::CleanEof | LegEnd::PeerEnded => EndAction::SignalEnd,
            LegEnd::ReadError | LegEnd::WriteError | LegEnd::IdleExpired | LegEnd::Aborted => {
                EndAction::FullClose
            },
        }
    }
}

/// 桥腿终态（诊断面 bd myppb + 收尾分流 bd degg3）。
///
/// 改造前每条腿的读循环把「`Ok(空块)`/`Error::Eof`」与「真实 IO 错误」并进
/// 同一个 `_ => break`，且腿恒返 `Ok(())` ⇒ dispatcher 的
/// `bridge ended: {e}` 是死代码，中继侧零痕迹。degg3 起每个 break 点还必须
/// 说清**理由**（超时/中止/级联不再记 `Eof`）——写腿据此选收尾动作。
///
/// 与 [`end_policy::LegEnd`] 1:1 对应，多带 `Err` 的 io 错误载荷（供聚合上浮）。
enum LegExit {
    /// 正常收尾：流 EOF（空块 / `Error::Eof`）。
    Eof,
    /// 级联退出：本向 send/write 目标先亡。
    PeerEnded,
    /// 写错误：只收敛本向（50074b2 语义），不上浮为错误。
    WriteErr,
    /// 空闲或半窗到期（connIdle / uplinkOnly / downlinkOnly）。
    IdleExpired,
    /// 中止闸被其它腿置位（bd rjt2o）。
    Aborted,
    /// 真实 IO 错误（字节数已由 [`leg_read_err`] 记入 warn）。
    Err { err: io::Error },
}

impl LegExit {
    /// 收尾策略输入。
    fn end(&self) -> end_policy::LegEnd {
        match self {
            Self::Eof => end_policy::LegEnd::CleanEof,
            Self::PeerEnded => end_policy::LegEnd::PeerEnded,
            Self::WriteErr => end_policy::LegEnd::WriteError,
            Self::IdleExpired => end_policy::LegEnd::IdleExpired,
            Self::Aborted => end_policy::LegEnd::Aborted,
            Self::Err { .. } => end_policy::LegEnd::ReadError,
        }
    }
}

/// 读腿错误 → 终态：`xray_buf::Error::Eof` 是正常收尾（pipe 关闭/流结束，
/// 不是错误），其余保 `kind` 上浮并记 warn。
fn leg_read_err(leg: &'static str, bytes_done: u64, err: xray_buf::io::Error) -> LegExit {
    if matches!(err, xray_buf::io::Error::Eof) {
        return LegExit::Eof;
    }
    let err = io::Error::from(err);
    tracing::warn!(
        target: "xray_frame::bridge",
        leg,
        bytes_done,
        err = %err,
        "bridge leg error"
    );
    LegExit::Err { err }
}

/// 聚合腿终态：取**首个** IO 错误上浮（顺序固定 = 决定性），其余终态（含
/// 超时/中止/级联）一律 `Ok(())`——与改造前「正常收尾一律 Ok」的返回值一致。
fn first_leg_error(legs: impl IntoIterator<Item = LegExit>) -> io::Result<()> {
    legs.into_iter()
        .find_map(|leg| match leg {
            LegExit::Err { err } => Some(err),
            LegExit::Eof
            | LegExit::PeerEnded
            | LegExit::WriteErr
            | LegExit::IdleExpired
            | LegExit::Aborted => None,
        })
        .map_or(Ok(()), Err)
}

/// 字节闸回退说明（bd u440m）：u440m 曾在条目闸（`PIPE_BUF_CAP`=64 条）之上
/// 加每方向 2MiB 字节闸（tokio 信号量 + 条目携带许可 + 超预算旁路），真机
/// A/B 实测**回退**——到节点 RTT 161.6ms ⇒ BDP 2.39–3.56MB 均大于 2MiB 闸预算，
/// 闸理论上限 ≈ 2MiB/0.162s ≈ 12.9MB/s，A/B 中位比 0.939（−6.1%）超票面自定
/// 5% 门 ⇒ 按票面规则撤销限流行为，回到纯条目闸；旁路计数器依赖闸存在才有
/// 意义，随闸一并删除。登记簿口径见
/// `xray_frame::budget::BRIDGE_BACKPRESSURE_BOUND_PER_CONN_BYTES`。
///
/// **bd sfqlu 重新引入（口径已修正）**：字节闸回来了，但值不再是拍定的 2MiB，
/// 而是按本机内存档位派生（`ByteGate`，四档 5/12/24/32 MiB/方向）——下限
/// 4MiB 即「≥ 实测 BDP 上沿 3.56MB」，正常链路不 binding；内存上界改由
/// **连接数上限**（`ConnSlot`）兜，不再靠压单连接窗口。u440m 的教训因此保留：
/// 闸值低于 BDP = 直接砍吞吐。
///
/// 双向桥接 dispatcher [`Link`] 与 AsyncRead+AsyncWrite stream。
///
/// 与 [`bridge_link_with_stream`] 区别：两个方向独立运行到都完成，任一方向
/// EOF/出错不会取消另一方向。 适配 VMess 这种请求方向提前 EOF（body chunk
/// 终止符）但响应方向仍需续传的场景。
///
/// **8sum 解耦（方案 A）**：每方向 reader（只读）与 writer（只写）拆为独立
/// async block，经 bounded mpsc（**按条目计**：每方向 64 条 MultiBuffer；
/// 口径见 `PIPE_BUF_CAP` 处注释）解耦背压——writer 写背压时 reader 继续
/// 排空接收侧（串行泵「读 8KB→写→循环」两腿锁步曾致服务端 TCP 接收窗不增
/// 长、全链 1 窗/RTT 步进，up 3.1 vs Go 19.8 Mbps）。条目闸之上的字节闸
/// （u440m）已回退（见本文件「字节闸回退说明」与下方 `PIPE_BUF_CAP` 处注释；
/// BDP > 2MiB × 高 RTT 钉吞吐 −6.1% 超票面 5% 门）。
/// 级联退出：任一 writer 死 →
/// mpsc rx drop → 对应 reader `send` 失败退出 → done watch 把 half_window
/// 传给对向腿，无静默半断；写错误只关本向写半部，绝不 shutdown 对向
/// （50074b2 教训：瞬时写错 shutdown link.writer = 下行永久断）。
///
/// 接收 `&TimeoutPolicy` 把 connIdle / uplinkOnly / downlinkOnly 三个超时下放到
/// 桥接层（Go `policy.Timeout` 语义，bd 4-6 修复：之前硬编码 DEFAULT_* 常量，
/// dispatcher 取出的 per-user Policy 不生效）。
pub async fn bridge_link_with_stream_full<S>(
    link: Link,
    mut stream: S,
    policy: &TimeoutPolicy,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Connection + 'static,
{
    use tokio::{io::AsyncWriteExt, time::timeout};
    use xray_buf::io::{Reader, Writer, new_reader, new_readv_reader_whole};

    // bd sfqlu：连接数上限 = 总预算 / 每连接规划上界（四档 13/32/64/170 条）。
    // 触顶 fail-visible 拒绝（日志 + Err，连接随 drop 关闭），静默降级/自作 OOM 都不允许。
    let _conn_slot = ConnSlot::try_acquire().ok_or_else(connection_limit_error)?;

    let conn_idle = policy.connection_idle;
    let uplink_only = policy.uplink_only;
    let downlink_only = policy.downlink_only;
    // bd 7p1m 专项埋点：XRAY_P7LM_TRACE=1 时逐批输出读/写字节数（warn 级穿透 loglevel）。
    let p7lm_trace = p7lm_trace();

    let Link { mut reader, mut writer } = link;
    // tokio::io::split（out_f1 33Mbps 实证拓扑，无锁）。自研 BiLock 轮转锁在
    // join! 固定轮询顺序下被 up 大流量系统性抢占（50074b2 同源塌陷：VPS 实测
    // up 1.58Mbps + strace「突发排空→恰 1 RTT 停顿」锁步签名），已整体删除。
    // WriteHalf 转发 poll_write_vectored/is_write_vectored（y1yx 聚合写保持）。
    // 下行读侧聚合读（bd VISIONMAC，对齐 Go readv 批语义）：裸 TCP 时在 split
    // 前 dup 专用读腿（ReadHalf 不穿透 Connection trait），走 ReadVReader 多
    // 缓冲聚合读（自适应至多缓冲）。SingleReader 单缓冲顺序读把批边界钉死在
    // 8KB，写侧整批 IsCompleteRecord 判定几乎必然失准 → End/Direct 触发不足
    // → 持续 padded 限速。读腿必须走**整流** dup（new_readv_reader_whole）：
    // into_split 对偶写半 drop 会 shutdown(WR) 共享 socket 写向 → 对端 early
    // EOF（e2e 实锤）；dup 句柄 drop 只关句柄不 shutdown。原 stream 的写半
    // 照常承担写向，读半闲置（dup 已接管读向，共享内核缓冲游标）。
    let s_read_dup = (stream.is_raw_tcp() && xray_buf::readv::use_readv())
        .then(|| stream.raw_tcp_clone())
        .flatten()
        .map(new_readv_reader_whole);
    // bd oarfu：连接能直接交出收到的 Bytes 块时（h2/h3 body 面）走零拷贝读腿——
    // 省掉 AsyncRead → 池化 8KB 缓冲的一次全量 memcpy（Buffer::from_bytes_frozen）。
    // 必须在 split 前取；包装层（TLS/AEAD/vision）不转发即自动回退下方拷贝路径。
    let frozen = stream.frozen_reader();
    // F3：rustls 客户端 TLS 流读缓冲放大（Connection::tls_readbuf_size，
    // 缺省 0 = 池化 8KB 不变；btls SSL_read 单 record 零收益，vision/reality
    // 包装层不转发即保持批边界语义）。
    let tls_readbuf = stream.tls_readbuf_size();
    let (s_read_half, mut s_write) = tokio::io::split(stream);
    let mut s_read: Box<dyn Reader> = match (frozen, s_read_dup, tls_readbuf) {
        (Some(r), _, _) => r,
        (None, Some(r), _) => r,
        (None, None, 0) => new_reader(s_read_half),
        (None, None, cap) => xray_buf::io::new_reader_with_capacity(s_read_half, cap),
    };

    // 背压闸按**条目**计（mpsc 容量 = 条目数，不是字节数）：每方向 64 条。
    // 单条字节上限由**生产侧**决定，不是本闸决定：
    //   下行 readv 腿 = 8 块 × 64KiB 块（xray_buf::readv 升窗后）= 512KiB；
    //   下行 TLS 腿   = 1 块 × tls_readbuf_size（≤64KiB）；
    //   上行腿 = dispatcher pipe 读端整块交付（≈ policy.buffer.connection，
    //   缺省 512KiB；pipe 判满在 merge 前 ⇒ 可再多出一次写入批量）。
    // ⇒ 单方向在途上界 = 64 条 × 512KiB = 32MiB（**不是** 512KiB——512KiB 是
    //   Go 每连接 pipe 的字节软限，与本闸的条目闸不同量纲）。
    // ⚠️ 冻结腿（h2/h3 body，Bytes 直交）单条 = 一个传输分片，由传输层定，
    //   不受 512KiB 约束 ⇒ 该路径的实际上界更高。
    // ⚠️ u440m 曾在此之上加每方向 2MiB 字节闸（tokio 信号量 + 条目携带许可），
    //   真机 A/B 中位比 0.939（−6.1%，BDP 2.39–3.56MB > 2MiB × RTT 161.6ms
    //   钉吞吐 ≈12.9MB/s）超票面 5% 门 ⇒ 已回退为纯条目闸（bd u440m；见本文件
    //   「字节闸回退说明」）。只影响内存上限、不影响正确性；改容量属行为面
    //   变更（bd n580i：只修口径）。容量常量 = 模块级 [`PIPE_BUF_CAP`]。
    // bd sfqlu：条目闸之上再加每方向**在途字节**闸（档位派生，恒 ≥ 实测 BDP 上沿）。
    // 与 u440m 的区别在闸值来源：那边拍死 2MiB（< BDP ⇒ 砍吞吐），这边随本机内存
    // 档位派生且恒 ≥ 4MiB。两者叠加 = 「条数 + 字节」双上界。
    // 条目闸管「多少批在排队」，字节闸管「一共压了多少内存」——单批可达 512KiB，
    // 64 条满载 = 32MiB/方向，小内存机器上这才是真上界。
    let gate_bytes = xray_frame::budget::plan::MemoryPlan::cached().bridge_gate;
    let up_gate = ByteGate::new(gate_bytes);
    let down_gate = ByteGate::new(gate_bytes);
    let (up_tx, mut up_rx) =
        tokio::sync::mpsc::channel::<(xray_buf::multi::MultiBuffer, GatePermit)>(PIPE_BUF_CAP);
    let (down_tx, mut down_rx) =
        tokio::sync::mpsc::channel::<(xray_buf::multi::MultiBuffer, GatePermit)>(PIPE_BUF_CAP);

    // 半关闭限窗（对应 Go policy Timeout.UplinkOnly/DownlinkOnly，proxy 层
    // `defer timer.SetTimeout(...)` 语义）：一方向读侧结束后，另一方向在窗口
    // 内无新数据则断开，防止单方向停滞连接永久挂起。窗口按 activity 重置
    // （读到新数据即续窗）。Go 方向锚点（ft58 修正，freedom.go:388/427）：
    // up 读侧结束 → down 剩余窗口 = downlink_only（requestDone defer
    // SetTimeout(DownlinkOnly)）；down 读侧结束 → up 剩余窗口 = uplink_only
    // （responseDone defer SetTimeout(UplinkOnly)）。
    let (up_done_tx, up_done_rx) = tokio::sync::watch::channel(None::<std::time::Duration>);
    let (down_done_tx, down_done_rx) = tokio::sync::watch::channel(None::<std::time::Duration>);
    // bd zct77：对向写腿的**写出进展**（累计字节）。半关闭窗的语义是「整连接无
    // 进展」，不是「剩余方向无入站数据」——读腿 EOF 只代表上游读完，写腿手里
    // 可能还压着数十 MB 未写出（解耦管线 + h2 流控满时）。缺此重置时，窗口会在
    // 排空途中到期 → abort 丢弃在飞批次 = 下载尾部静默截断（curl 18）。
    let (up_written_tx, up_written_rx) = tokio::sync::watch::channel(0u64);
    let (down_written_tx, down_written_rx) = tokio::sync::watch::channel(0u64);

    // 中止闸（bd rjt2o）：`join!` 要求四腿全归，而被堵在 send/write 的腿不再被
    // poll → 读侧判定（connIdle / 半窗）永远无法执行 ⇒ 对端活着但不读时连接
    // 钉死无界（S1/S3 实测）。闸只负责**投递**判定：关闸点 = 既有读超时分支
    // （判定源不变，无双份超时账），唤醒点 = 4 个 send/write await。
    // 零额外拷贝：缓冲区仍按原路 move，select 只多 poll 一个 watch。
    let (abort_tx, abort_rx) = tokio::sync::watch::channel(false);

    // 收尾原因槽（degg3 设计 §4.3，每向一个）：读腿退出前 store，写腿
    // `recv()==None` 后 load。热路径零成本——冷路径每连接各一次原子操作。
    // 写腿本地可判定的两种原因（`WriteError` / `Aborted`）不读槽。
    let up_end =
        std::sync::Arc::new(std::sync::atomic::AtomicU8::new(end_policy::LegEnd::CleanEof.code()));

    // 上行 reader：link.reader → up_tx。超时语义与串行版逐行等价：
    // conn_idle 双向存活空闲断开；对向读侧结束后本向仅剩 half_window 宽限。
    let up_reader = {
        let abort_tx = abort_tx.clone();
        let mut abort_rx = abort_rx.clone();
        let up_end = up_end.clone();
        let mut down_written = down_written_rx;
        async move {
            let mut down_done = down_done_rx;
            let mut window: Option<std::time::Duration> = None;
            let mut bytes_done: u64 = 0;
            let exit = loop {
                // 读 future 每轮重建是 cancel-safe 的：select!/timeout 丢弃的 future
                // 只可能处于 Pending（poll 到 Ready 的分支必被采用），无数据丢失。
                let mb = match window {
                    None => tokio::select! {
                        // 空闲 deadline（Go ConnectionIdle / CancelAfterInactivity）
                        res = timeout(conn_idle, reader.read_multi_buffer()) => match res {
                            Ok(r) => r,
                            Err(_) => {
                                let _ = abort_tx.send(true);
                                break LegExit::IdleExpired;
                            },
                        },
                        _ = down_done.changed() => {
                            window = *down_done.borrow();
                            continue;
                        }
                    },
                    Some(d) => {
                        // 半窗 = 「整连接 d 内零进展」：对向（下行）写腿每写出一批
                        // 即重置计时（bd zct77）。对向已收尾（sender drop）⇒ 退化为
                        // 纯 d 计时，语义同旧实现，不会无限续期。
                        let idle = async {
                            loop {
                                match timeout(d, down_written.changed()).await {
                                    Ok(Ok(())) => continue,
                                    Ok(Err(_)) => {
                                        tokio::time::sleep(d).await;
                                        return;
                                    },
                                    Err(_) => return,
                                }
                            }
                        };
                        tokio::pin!(idle);
                        tokio::select! {
                            r = reader.read_multi_buffer() => r,
                            () = &mut idle => {
                                // uplink_only 窗口内整连接无进展
                                let _ = abort_tx.send(true);
                                break LegExit::IdleExpired;
                            },
                        }
                    },
                };
                match mb {
                    Ok(mb) if !mb.is_empty() => {
                        if p7lm_trace {
                            tracing::warn!(target: "p7lm", bytes = mb.len(), phase = "up_read", "");
                        }
                        bytes_done += mb.len() as u64;
                        // 字节闸：许可随块 move 到写腿，写完才归还（drop）。
                        let permit = tokio::select! {
                            _ = wait_abort(&mut abort_rx) => break LegExit::Aborted,
                            p = up_gate.acquire(mb.len()) => p,
                        };
                        // channel 满阻塞在此（不抢对向时间片）；writer task 已死时
                        // send 立即 Err → 本向级联退出，绝不静默吞数据。关闸时
                        // 放弃在飞批次（收尾态，连接已被判死）。
                        let sent = tokio::select! {
                            _ = wait_abort(&mut abort_rx) => break LegExit::Aborted,
                            r = up_tx.send((mb, permit)) => r,
                        };
                        if sent.is_err() {
                            break LegExit::PeerEnded;
                        }
                    },
                    Ok(_) => break LegExit::Eof, // 正常 EOF（空块）
                    Err(e) => break leg_read_err("up_read", bytes_done, e),
                }
            };
            // ⚠️ store 必须早于本块结束（本块结束时 up_tx 才 drop → 写腿可能
            // 立刻 `recv()==None` 醒来）：顺序反了写腿会读初始值 0（= CleanEof），
            // 异常被当正常收尾（设计 §10 风险项）。
            up_end.store(exit.end().code(), std::sync::atomic::Ordering::Release);
            let _ = up_done_tx.send(Some(downlink_only));
            exit
        }
    };
    // 上行 writer：up_rx → stream 写半部聚合写（vectored 批写，y1yx）。只写不读。
    let up_writer = {
        let mut abort_rx = abort_rx.clone();
        let up_end = up_end.clone();
        let up_written_tx = up_written_tx;
        async move {
            let mut up_bytes: u64 = 0;
            let end = loop {
                let (mb, _permit) = tokio::select! {
                    _ = wait_abort(&mut abort_rx) => break end_policy::LegEnd::Aborted,
                    r = up_rx.recv() => match r {
                        Some(item) => item,
                        // 读腿已退出：原因由它 store（store 早于 up_tx drop）。
                        None => break end_policy::LegEnd::from_code(
                            up_end.load(std::sync::atomic::Ordering::Acquire),
                        ),
                    },
                };
                if p7lm_trace {
                    tracing::warn!(target: "p7lm", bytes = mb.len(), phase = "up_write", "");
                }
                up_bytes += mb.len() as u64;
                // 关闸时丢弃在飞批次：对端不读 + 连接已被判死，半截写无意义。
                let wrote = tokio::select! {
                    _ = wait_abort(&mut abort_rx) => break end_policy::LegEnd::Aborted,
                    r = write_all_mb(&mut s_write, &mb) => r,
                };
                if wrote.is_err() {
                    break end_policy::LegEnd::WriteError;
                }
                // bd zct77：写出进展发布（供对向读腿的半窗重置计时）。
                up_written_tx.send_replace(up_bytes);
            };
            // 收尾按**原因**分流（唯一决策点）：只关本向写半部。
            // 级联：本 task 退出即 drop up_rx → 上行 reader send 失败 → up_done
            // 传播 half_window，对向不静默半断。3s 界：对端不读时 shutdown 自身
            // 也会挂（对称下方 shutdown_flush 的既有界）。
            match end_policy::end_action(end) {
                end_policy::EndAction::SignalEnd => {
                    let _ = timeout(std::time::Duration::from_secs(3), s_write.shutdown()).await;
                },
                // 异常收尾：不发有序结束（协议层无标记），靠 drop 全关——不让对端
                // 把中继内部错误读成「请求已完成」。
                end_policy::EndAction::FullClose => {
                    tracing::warn!(
                        target: "xray_frame::bridge",
                        leg = "up_write",
                        kind = end.as_str(),
                        bytes_done = up_bytes,
                        action = "full_close",
                        "bridge leg end without ordered shutdown"
                    );
                },
            }
            io::Result::Ok(())
        }
    };
    // 下行 reader：xray_buf 顺序读（池化 Buffer，对应 Go 无 vectored 源的
    // SingleReader 路径）→ down_tx。超时同构上行。
    let down_reader = {
        let abort_tx = abort_tx.clone();
        let mut abort_rx = abort_rx.clone();
        let mut up_written = up_written_rx;
        async move {
            let mut up_done = up_done_rx;
            let mut window: Option<std::time::Duration> = None;
            let mut bytes_done: u64 = 0;
            let exit = loop {
                let mb = match window {
                    None => tokio::select! {
                        // 空闲 deadline（Go ConnectionIdle / CancelAfterInactivity）
                        res = timeout(conn_idle, read_downlink(&mut s_read)) => match res {
                            Ok(r) => r,
                            Err(_) => {
                                let _ = abort_tx.send(true);
                                break LegExit::IdleExpired;
                            },
                        },
                        _ = up_done.changed() => {
                            window = *up_done.borrow();
                            continue;
                        }
                    },
                    Some(d) => {
                        // 半窗 = 「整连接 d 内零进展」（bd zct77）：对向（上行）写腿
                        // 每写出一批即重置计时，避免排空途中被误判死连接。
                        let idle = async {
                            loop {
                                match timeout(d, up_written.changed()).await {
                                    Ok(Ok(())) => continue,
                                    Ok(Err(_)) => {
                                        tokio::time::sleep(d).await;
                                        return;
                                    },
                                    Err(_) => return,
                                }
                            }
                        };
                        tokio::pin!(idle);
                        tokio::select! {
                            r = read_downlink(&mut s_read) => r,
                            () = &mut idle => {
                                // downlink_only 窗口内整连接无进展
                                let _ = abort_tx.send(true);
                                break LegExit::IdleExpired;
                            },
                        }
                    },
                };
                match mb {
                    Ok(mb) if !mb.is_empty() => {
                        if p7lm_trace {
                            tracing::warn!(target: "p7lm", bytes = mb.len(), phase = "down_read", "");
                        }
                        bytes_done += mb.len() as u64;
                        // 字节闸（bd sfqlu）：同上行，许可随块走。
                        let permit = tokio::select! {
                            _ = wait_abort(&mut abort_rx) => break LegExit::Aborted,
                            p = down_gate.acquire(mb.len()) => p,
                        };
                        let sent = tokio::select! {
                            _ = wait_abort(&mut abort_rx) => break LegExit::Aborted,
                            r = down_tx.send((mb, permit)) => r,
                        };
                        if sent.is_err() {
                            break LegExit::PeerEnded;
                        }
                    },
                    Ok(_) => break LegExit::Eof, // 正常 EOF（空块）
                    Err(e) => break leg_read_err("down_read", bytes_done, e),
                }
            };
            let _ = down_done_tx.send(Some(uplink_only));
            exit
        }
    };

    // 下行 writer：down_rx → link.writer（xray_buf Writer 管线，自带池化）。
    let down_writer = {
        let mut abort_rx = abort_rx.clone();
        let down_written_tx = down_written_tx;
        async move {
            let mut dw_bytes: u64 = 0;
            loop {
                let (mb, _permit) = tokio::select! {
                    _ = wait_abort(&mut abort_rx) => break,
                    r = down_rx.recv() => match r {
                        Some(item) => item,
                        None => break,
                    },
                };
                if p7lm_trace {
                    tracing::warn!(target: "p7lm", bytes = mb.len(), phase = "down_write", "");
                }
                dw_bytes += mb.len() as u64;
                let wrote = tokio::select! {
                    _ = wait_abort(&mut abort_rx) => break,
                    r = writer.write_multi_buffer(mb) => r,
                };
                if wrote.is_err() {
                    if p7lm_trace {
                        tracing::warn!(target: "p7lm", total = dw_bytes, phase = "down_write_err", "");
                    }
                    break;
                }
                // bd zct77：写出进展发布（供对向读腿的半窗重置计时）。
                down_written_tx.send_replace(dw_bytes);
            }
            // 桥结束确保下游 reader 收到 EOF；同样只关本向，不碰 stream 写半部。
            // bd VISIONMAC：收尾必须 flush+shutdown（poll_shutdown）——TLS 层
            // poll_write 是 BufWriter 语义（Ok(len) 只保证密文入 sendable_tls，
            // write_io 撞 WouldBlock 尾巴滞留缓冲，poll_arm_gate 文档同源），
            // 旧 no-op shutdown 下滞留尾巴随 drop 静默蒸发：对端 deframer 停在
            // 半条记录上永久 Pending，直到 FIN → "peer closed without
            // close_notify" 断链截断（VPS netem r6 实锤滞留 65,383B =
            // sendable_tls 64KB 上限）。Go 无此坑：internalClose 链显式
            if p7lm_trace {
                tracing::warn!(target: "p7lm", total = dw_bytes, phase = "drain_done_shutdown_flush_begin", "");
            }
            let flush_res =
                timeout(std::time::Duration::from_secs(3), writer.shutdown_flush()).await;
            // 三态**判据恒可见**（bd cj8g7）：超时/出错是真收尾风险（滞留尾巴静默
            // 蒸发 ⇒ 对端 deframer 卡半条记录），不能只在 XRAY_P7LM_TRACE 门内报；
            // 成功态是纯诊断（每连接一条 warn 的税没必要），仍归 trace 开关。
            match &flush_res {
                Ok(Ok(())) => {
                    if p7lm_trace {
                        tracing::warn!(target: "p7lm", total = dw_bytes, phase = "shutdown_flush_ok", "")
                    }
                },
                Ok(Err(e)) => tracing::warn!(
                    target: "xray_frame::bridge",
                    leg = "down_write",
                    total = dw_bytes,
                    err = %e,
                    "bridge shutdown_flush failed (buffered tail may be lost)"
                ),
                Err(_) => tracing::warn!(
                    target: "xray_frame::bridge",
                    leg = "down_write",
                    total = dw_bytes,
                    "bridge shutdown_flush timed out after 3s (buffered tail may be lost)"
                ),
            }
            // CloseWrite+排空。3s 上限防极端积压下收尾挂死（连接本就在收尾）。
            io::Result::Ok(())
        }
    };

    // join! 语义：四块被并发轮询（读等待不阻塞写推进），全部完成后返回。
    // 站点归因（S3）：三腿整腿 scope（跨 await 必须用 scope，禁 enter——bd a65px）；
    // 下行读腿已在 read_downlink 内标 BUF_READ，不再叠加。
    let (up_r, up_w, down_r, down_w) = tokio::join!(
        xray_common::alloc_site::scope(xray_common::alloc_site::BRIDGE_UP_READ, up_reader),
        xray_common::alloc_site::scope(xray_common::alloc_site::BRIDGE_UP_WRITE, up_writer),
        down_reader,
        xray_common::alloc_site::scope(xray_common::alloc_site::BRIDGE_DOWN_WRITE, down_writer),
    );
    // 写腿恒 Ok（写错误按 50074b2 语义只收敛本向，见 `bridge_stream_full_
    // up_write_err_keeps_downlink` 回归门）；读腿错误上浮给 dispatcher。
    up_w?;
    down_w?;
    first_leg_error([up_r, down_r])
}

/// 默认策略的便捷包装（保留旧 API 兼容调用方）。
pub async fn bridge_link_with_stream_full_default<S>(link: Link, stream: S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Connection + 'static,
{
    let policy = TimeoutPolicy::default();
    bridge_link_with_stream_full(link, stream, &policy).await
}

/// 下行 per-tag 流量统计对（出站, 入站）；提取别名以满足 clippy type_complexity。
#[cfg(any(target_os = "linux", target_os = "android"))]
type DownlinkCounters = (
    Option<std::sync::Arc<dyn xray_features::stats::Counter>>,
    Option<std::sync::Arc<dyn xray_features::stats::Counter>>,
);

/// 下行 splice 快路径桥（txno-splice；Go freedom responseDone 的
/// `proxy.CopyRawConnIfExist` splice 分支等价物，freedom.go:428-436）。
///
/// 上行保持既有用户态泵（Go `buf.Copy(input, writer)`——上行源是 dispatcher
/// 管道，本就不可 splice）；下行改走内核零拷贝：出站裸 socket → pipe → 入站
/// 裸 socket（Go `tc.ReadFrom(readerConn)`，proxy.go:768）。调用方须先用
/// [`xray_common::platform::splice::bridge_splice_admission`] 准入（env + 平台
/// + CanSpliceCopy 信号 + 双端 raw）；本函数不重复判定。
///
/// 平台：splice(2)/pipe2 仅 Linux/Android 编译；其余平台调用方
/// （DialBridge）在准入判定处已被平台闸门拦截，永不抵达本函数。
#[cfg(any(target_os = "linux", target_os = "android"))]
pub async fn bridge_link_with_stream_downlink_splice<S>(
    link: Link,
    stream: S,
    write_raw: std::sync::Arc<tokio::net::TcpStream>,
    policy: &TimeoutPolicy,
    down_counters: DownlinkCounters,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Connection,
{
    use tokio::io::AsyncWriteExt;
    use xray_buf::io::{Reader, Writer};

    let conn_idle = policy.connection_idle;
    let uplink_only = policy.uplink_only;
    let downlink_only = policy.downlink_only;

    // bd sfqlu：连接数上限（同 bridge_link_with_stream_full，触顶 fail-visible 拒绝）。
    let _conn_slot = ConnSlot::try_acquire().ok_or_else(connection_limit_error)?;

    // 准入已要求出站 raw；克隆失败（理论不可达）时下行退化为立即结束，
    // 上行照常泵完（连接可用性不受影响）。
    let down_from = stream.raw_tcp_clone();
    let Link { mut reader, mut writer } = link;
    let (_s_read, mut s_write) = tokio::io::split(stream); // 下行走 splice，读半部不再需要
    let (up_done_tx, _up_done_rx) = tokio::sync::watch::channel(None::<std::time::Duration>);
    let (down_done_tx, down_done_rx) = tokio::sync::watch::channel(None::<std::time::Duration>);
    // 中止闸（bd rjt2o）：上行写腿被堵时读侧判定无法执行（同 full 变体）；
    // 下行是内核 splice（Go 24h 计时 + EOF 即终），不接闸。
    let (abort_tx, abort_rx) = tokio::sync::watch::channel(false);

    // 上行 = Go buf.Copy(input, writer)（freedom.go:421）：link.reader → 出站，
    // ConnectionIdle 空闲窗 + 下行结束后的 UplinkOnly 半关闭窗，语义同
    // [`bridge_link_with_stream_full`] 的上行。
    let up = {
        let abort_tx = abort_tx.clone();
        let mut abort_rx = abort_rx.clone();
        async move {
            let mut down_done = down_done_rx;
            let mut window: Option<std::time::Duration> = None;
            let mut bytes_done: u64 = 0;
            let exit = loop {
                let mb = match window {
                    None => {
                        // 预算先绑定具名局部：`Budget::tokio()` 是临时值，
                        // 在 select! 内其借用会跨越 await（E0716：Linux 构建红点）。
                        let idle_dl = Budget::tokio().deadline(conn_idle);
                        tokio::select! {
                            res = idle_dl.timeout(reader.read_multi_buffer()) => {
                                match res {
                                    Ok(r) => r,
                                    Err(_) => {
                                        let _ = abort_tx.send(true);
                                        break LegExit::IdleExpired;
                                    },
                                }
                            }
                            _ = down_done.changed() => {
                                window = *down_done.borrow();
                                continue;
                            }
                        }
                    },
                    Some(d) => {
                        match Budget::tokio().deadline(d).timeout(reader.read_multi_buffer()).await
                        {
                            Ok(r) => r,
                            Err(_) => {
                                let _ = abort_tx.send(true);
                                break LegExit::IdleExpired;
                            },
                        }
                    },
                };
                match mb {
                    Ok(mb) if !mb.is_empty() => {
                        bytes_done += mb.len() as u64;
                        let wrote = tokio::select! {
                            _ = wait_abort(&mut abort_rx) => break LegExit::Aborted,
                            r = write_all_mb(&mut s_write, &mb) => r,
                        };
                        if wrote.is_err() {
                            break LegExit::WriteErr;
                        }
                    },
                    Ok(_) => break LegExit::Eof,
                    Err(e) => break leg_read_err("up_read", bytes_done, e),
                }
            };
            // 收尾按原因分流（与 stream 承载同源，唯一决策点）；3s 界：对端不读时
            // shutdown 自身也会挂（同 full 变体的 shutdown_flush）。
            match end_policy::end_action(exit.end()) {
                end_policy::EndAction::SignalEnd => {
                    let _ = Budget::tokio()
                        .deadline(std::time::Duration::from_secs(3))
                        .timeout(s_write.shutdown())
                        .await;
                },
                // 异常收尾：不发有序结束，靠 drop 全关（同 stream 承载）。
                end_policy::EndAction::FullClose => {
                    tracing::warn!(
                        target: "xray_frame::bridge",
                        leg = "up_write",
                        kind = exit.end().as_str(),
                        bytes_done,
                        action = "full_close",
                        "bridge leg end without ordered shutdown"
                    );
                },
            }
            let _ = up_done_tx.send(Some(downlink_only));
            io::Result::Ok(())
        }
    };

    // 下行 = Go tc.ReadFrom(readerConn)（proxy.go:768）：出站裸 socket 经内核
    // pipe splice 进入站裸 socket，直到对端 EOF/错误。Go 在进入 splice 时把
    // 双端 timer 提到 24h（proxy.go:764-767）——即下行无空闲超时，EOF 即终。
    let down = async move {
        // Go proxy.go:760-766：splice 直达 raw fd 绕过 link 端 SizeStat 包装，
        // 经 splice_copy_counted 每 chunk 实时回填两级 downlink 计数器
        // （readCounter=出站 / writeCounter=入站），否则 Linux splice 路径
        // per-tag 流量统计恒 0（CI 首跑实证）。
        let counters = match (down_counters.0.as_deref(), down_counters.1.as_deref()) {
            (Some(o), Some(i)) => Some((o, i)),
            _ => None,
        };
        let res = match down_from {
            Some(from) => crate::splice::splice_copy_counted(&from, &write_raw, counters).await,
            None => Ok(0),
        };
        // bd VISIONMAC：同 full 变体——收尾 flush+shutdown 排空 TLS 层滞留
        // 尾巴（splice 已 arm 时 VisionConn 走 raw 分支半关闭，安全）。
        let _ = Budget::tokio()
            .deadline(std::time::Duration::from_secs(3))
            .timeout(writer.shutdown_flush())
            .await;
        let _ = down_done_tx.send(Some(uplink_only));
        res.map(|_| ())
    };

    let (up_res, down_res) = tokio::join!(up, down);
    up_res.and(down_res)
}

/// 双向桥接两个 dispatcher [`Link`]（xray-buf Reader/Writer）。
///
/// 上行：`link_a.reader` → `link_b.writer`。
/// 下行：`link_b.reader` → `link_a.writer`。
///
/// 两个方向独立运行到都完成（`join!` 语义）——任一方向 EOF/出错不会取消另一方向。
/// 用于代理链场景：原始 link ↔ client link ↔ chained handler。
///
/// 接收 `&TimeoutPolicy` 同 [`bridge_link_with_stream_full`]。代理链目前
/// 走 dispatcher 默认 policy（与原语义一致——Go 链路上每个 outbound 自己的
/// policy 仍在该 outbound 内部生效；本层只控制连接级超时）。
pub async fn bridge_link_with_link(
    link_a: Link,
    link_b: Link,
    policy: &TimeoutPolicy,
) -> io::Result<()> {
    use xray_buf::io::{Reader, Writer};

    let conn_idle = policy.connection_idle;
    let uplink_only = policy.uplink_only;
    let downlink_only = policy.downlink_only;

    // bd sfqlu：连接数上限（同 bridge_link_with_stream_full，触顶 fail-visible 拒绝）。
    let _conn_slot = ConnSlot::try_acquire().ok_or_else(connection_limit_error)?;

    let Link { reader: mut a_reader, writer: mut a_writer } = link_a;
    let Link { reader: mut b_reader, writer: mut b_writer } = link_b;

    // 半关闭限窗语义同 bridge_link_with_stream_full（Go UplinkOnly/DownlinkOnly）。
    let (up_done_tx, up_done_rx) = tokio::sync::watch::channel(None::<std::time::Duration>);
    let (down_done_tx, down_done_rx) = tokio::sync::watch::channel(None::<std::time::Duration>);
    // 中止闸（bd rjt2o）：同 bridge_link_with_stream_full——`join!` 等两腿全归，
    // 被堵在写腿的那一向不再被 poll，读侧判定无法执行。闸只搬运既有判定。
    let (abort_tx, abort_rx) = tokio::sync::watch::channel(false);

    // 上行：a → b
    let up = {
        let abort_tx = abort_tx.clone();
        let mut abort_rx = abort_rx.clone();
        async move {
            let mut down_done = down_done_rx;
            let mut window: Option<std::time::Duration> = None;
            let mut bytes_done: u64 = 0;
            let exit = loop {
                let mb = match window {
                    None => {
                        let idle_dl = Budget::tokio().deadline(conn_idle);
                        tokio::select! {
                            // 空闲 deadline 语义同 bridge_link_with_stream_full（ConnectionIdle）
                            res = idle_dl.timeout(a_reader.read_multi_buffer()) => match res {
                                Ok(r) => r,
                                Err(_) => {
                                    let _ = abort_tx.send(true);
                                    break LegExit::IdleExpired;
                                },
                            },
                            _ = down_done.changed() => {
                                window = *down_done.borrow();
                                continue;
                            }
                        }
                    },
                    Some(d) => {
                        match Budget::tokio()
                            .deadline(d)
                            .timeout(a_reader.read_multi_buffer())
                            .await
                        {
                            Ok(r) => r,
                            Err(_) => {
                                let _ = abort_tx.send(true);
                                break LegExit::IdleExpired;
                            },
                        }
                    },
                };
                match mb {
                    Ok(mb) if !mb.is_empty() => {
                        bytes_done += mb.len() as u64;
                        let wrote = tokio::select! {
                            _ = wait_abort(&mut abort_rx) => break LegExit::Aborted,
                            r = b_writer.write_multi_buffer(mb) => r,
                        };
                        // 写错只收敛本向（pipe 关闭是正常收尾，同 stream 桥 50074b2 语义）。
                        if wrote.is_err() {
                            break LegExit::WriteErr;
                        }
                    },
                    Ok(_) => break LegExit::Eof, // 正常 EOF（空块）
                    Err(e) => break leg_read_err("chain_up_read", bytes_done, e),
                }
            };
            // bd VISIONMAC：TLS 链路场景须 flush+shutdown 排空滞留尾巴。
            // degg3：收尾按原因分流（唯一决策点）；pipe 的 `close()` 只让本 pipe
            // 读端见 EOF ⇒ 天然方向性，`SignalEnd` 分支原样保留。
            match end_policy::end_action(exit.end()) {
                end_policy::EndAction::SignalEnd => {
                    let _ = Budget::tokio()
                        .deadline(std::time::Duration::from_secs(3))
                        .timeout(b_writer.shutdown_flush())
                        .await;
                },
                // 异常收尾：不发有序结束，靠 drop 全关（同 stream 承载）。
                end_policy::EndAction::FullClose => {
                    tracing::warn!(
                        target: "xray_frame::bridge",
                        leg = "up_write",
                        kind = exit.end().as_str(),
                        bytes_done,
                        action = "full_close",
                        "bridge leg end without ordered shutdown"
                    );
                },
            }
            let _ = up_done_tx.send(Some(downlink_only));
            exit
        }
    };

    // 下行：b → a
    let down = {
        let abort_tx = abort_tx.clone();
        let mut abort_rx = abort_rx.clone();
        async move {
            let mut up_done = up_done_rx;
            let mut window: Option<std::time::Duration> = None;
            let mut bytes_done: u64 = 0;
            let exit = loop {
                let mb = match window {
                    None => {
                        let idle_dl = Budget::tokio().deadline(conn_idle);
                        tokio::select! {
                            // 空闲 deadline 语义同 bridge_link_with_stream_full（ConnectionIdle）
                            res = idle_dl.timeout(b_reader.read_multi_buffer()) => match res {
                                Ok(r) => r,
                                Err(_) => {
                                    let _ = abort_tx.send(true);
                                    break LegExit::IdleExpired;
                                },
                            },
                            _ = up_done.changed() => {
                                window = *up_done.borrow();
                                continue;
                            }
                        }
                    },
                    Some(d) => {
                        match Budget::tokio()
                            .deadline(d)
                            .timeout(b_reader.read_multi_buffer())
                            .await
                        {
                            Ok(r) => r,
                            Err(_) => {
                                let _ = abort_tx.send(true);
                                break LegExit::IdleExpired;
                            },
                        }
                    },
                };
                match mb {
                    Ok(mb) if !mb.is_empty() => {
                        bytes_done += mb.len() as u64;
                        let wrote = tokio::select! {
                            _ = wait_abort(&mut abort_rx) => break LegExit::Aborted,
                            r = a_writer.write_multi_buffer(mb) => r,
                        };
                        // 写错只收敛本向（pipe 关闭是正常收尾，同 stream 桥 50074b2 语义）。
                        if wrote.is_err() {
                            break LegExit::WriteErr;
                        }
                    },
                    Ok(_) => break LegExit::Eof, // 正常 EOF（空块）
                    Err(e) => break leg_read_err("chain_down_read", bytes_done, e),
                }
            };
            let _ = Budget::tokio()
                .deadline(std::time::Duration::from_secs(3))
                .timeout(a_writer.shutdown_flush())
                .await;
            let _ = down_done_tx.send(Some(uplink_only));
            exit
        }
    };

    let (up_res, down_res) = tokio::join!(up, down);
    first_leg_error([up_res, down_res])
}

/// 默认策略的便捷包装（保留旧 API 兼容调用方）。
pub async fn bridge_link_with_link_default(link_a: Link, link_b: Link) -> io::Result<()> {
    let policy = TimeoutPolicy::default();
    bridge_link_with_link(link_a, link_b, &policy).await
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, pin::Pin, task::Poll};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    use super::*;
    use crate::connection::TcpConnection;

    /// bd sfqlu：字节闸在未超闸时零等待、超闸时阻塞到写腿归还；单个超闸块永不
    /// 阻塞（否则单块 > 闸即连接挂死）。
    #[tokio::test]
    async fn byte_gate_blocks_only_when_over_cap() {
        let gate = ByteGate::new(4 * 1024 * 1024);
        let first = gate.acquire(3 * 1024 * 1024).await;

        // 未超闸（3MiB + 1MiB = 4MiB ≤ cap）：立即返回。
        let second = gate.acquire(1024 * 1024).await;

        // 再要 1 字节即超闸：必须等第一块归还。
        let blocked = tokio::spawn({
            let gate = std::sync::Arc::clone(&gate);
            async move { gate.acquire(1).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!blocked.is_finished(), "超闸后不得放行（否则字节闸形同虚设）");

        // 归还 3MiB ⇒ 闸内剩 1MiB，1 字节请求立即可过。
        drop(first);
        let third = tokio::time::timeout(std::time::Duration::from_secs(1), blocked)
            .await
            .expect("归还后必须放行")
            .expect("join");
        drop(third);
        drop(second);
    }

    /// 单块 > 闸**不阻塞**（闸是软上界）：否则 cap < 单批 512KiB 时连接直接挂死。
    #[tokio::test]
    async fn byte_gate_allows_single_oversize_block() {
        let gate = ByteGate::new(1024);
        let _permit = tokio::time::timeout(std::time::Duration::from_secs(1), gate.acquire(4096))
            .await
            .expect("超闸单块必须放行（堵死 = 连接挂死）");
    }

    /// 连接名额的「判定 + 自增」必须原子且不超发；触顶返 false（fail-visible 拒绝）。
    ///
    /// 用独立计数器测（不碰全局 `ACTIVE_BRIDGES`：同进程其它桥测试会并发读写它）。
    #[test]
    fn conn_slot_limit_is_atomic_and_rejects_past_cap() {
        let active = std::sync::atomic::AtomicUsize::new(0);
        assert!(try_take_slot(&active, 2));
        assert!(try_take_slot(&active, 2));
        assert!(!try_take_slot(&active, 2), "已达上限必须拒绝（不静默放行）");
        assert_eq!(active.load(std::sync::atomic::Ordering::Acquire), 2, "拒绝时不得自增");
        assert!(try_take_slot(&active, 3), "上限提高后可再取（覆盖 XRAY_MAX_CONNS）");

        // 并发下不超发：8 个任务抢 3 个名额，恰好 3 个成功。
        let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ok = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let active = std::sync::Arc::clone(&active);
                let ok = std::sync::Arc::clone(&ok);
                scope.spawn(move || {
                    if try_take_slot(&active, 3) {
                        ok.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    }
                });
            }
        });
        assert_eq!(ok.load(std::sync::atomic::Ordering::Acquire), 3, "名额不得超发");
    }

    /// 触顶错误必须点名「本机内存档位上限 + 条数」（日志/Err 双可见）。
    #[test]
    fn connection_limit_error_names_tier_limit() {
        let _g = global_state_guard();
        let err = connection_limit_error();
        let text = err.to_string();
        let plan = xray_frame::budget::plan::MemoryPlan::cached();
        assert!(text.contains("connection limit reached"), "{text}");
        assert!(
            text.contains(&plan.effective_max_conns().to_string()),
            "必须点名**生效**条数（降档后）：{text}"
        );
        assert!(text.contains(plan.tier.as_str()), "必须点名档位：{text}");
        assert!(text.contains("XRAY_MAX_CONNS"), "必须告知覆盖手段：{text}");
    }

    /// 执行点（[`ConnSlot::try_acquire`] 的唯一读数 [`conn_limit`]）必须读装配期
    /// 降档值，不是档位原值（bd 2026-11-08 D-02）。
    ///
    /// 本进程只有本用例写该静态值（`GLOBAL_STATE` 串行化其它读它的用例）。
    #[test]
    fn conn_limit_reads_degraded_value() {
        let _g = global_state_guard();
        let plan = xray_frame::budget::plan::MemoryPlan::cached();
        assert_eq!(conn_limit(), plan.max_conns, "未装配 = 档位派生值");
        let degraded = plan.max_conns.saturating_sub(1).max(1);
        xray_frame::budget::plan::set_effective_max_conns(degraded);
        assert_eq!(
            conn_limit(),
            degraded,
            "执行点必须读降档值（档位原值 {} → 降档 {degraded}）",
            plan.max_conns
        );
        // 复原，避免污染同进程后续用例（静态值进程级）。
        xray_frame::budget::plan::set_effective_max_conns(plan.max_conns);
    }

    /// 触碰进程级降档静态值的用例串行化（否则 read/write 交错即假红）。
    fn global_state_guard() -> std::sync::MutexGuard<'static, ()> {
        static GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
        GUARD.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// bd 7p1m：`XRAY_P7LM_TRACE=0` 必须视为关闭（旧 `.is_ok()` 语义会误开埋点，
    /// 曾把 F2/F3 优化实测毒化成伪影）。
    #[test]
    fn p7lm_trace_env_semantics() {
        assert!(!p7lm_trace_enabled(None), "未设必须关闭");
        for off in ["", "0", "false", "OFF", " no ", "False"] {
            assert!(!p7lm_trace_enabled(Some(off)), "{off:?} 必须视为关闭");
        }
        for on in ["1", "true", "enable", "yes"] {
            assert!(p7lm_trace_enabled(Some(on)), "{on:?} 必须视为开启");
        }
    }

    /// 缓存口（p7lm_trace → LazyLock）与直解口必须同判——缓存初始化走的解析
    /// 与纯函数语义若有分叉（如缓存侧单独改了解析），此断言红。
    #[test]
    fn p7lm_trace_cached_matches_direct_parse() {
        assert_eq!(
            p7lm_trace(),
            p7lm_trace_enabled(std::env::var("XRAY_P7LM_TRACE").ok().as_deref())
        );
    }

    /// degg3 收尾策略表（6×1）：决策点唯一且平台无关，故表驱动钉死。
    #[test]
    fn end_action_table() {
        use end_policy::{EndAction, LegEnd, end_action};

        // 唯一决策点：正常两档保持现状（A 臂字节级不变），异常四档全关。
        let want = [
            (LegEnd::CleanEof, EndAction::SignalEnd),
            (LegEnd::PeerEnded, EndAction::SignalEnd),
            (LegEnd::ReadError, EndAction::FullClose),
            (LegEnd::WriteError, EndAction::FullClose),
            (LegEnd::IdleExpired, EndAction::FullClose),
            (LegEnd::Aborted, EndAction::FullClose),
        ];
        for (end, action) in want {
            assert_eq!(end_action(end), action, "{end:?} 的收尾动作");
        }
    }

    /// 原因槽编解码必须双射（写腿靠它跨腿取原因）；越界只允许落到 `CleanEof`。
    #[test]
    fn leg_end_codec_roundtrip() {
        use end_policy::LegEnd;

        for end in [
            LegEnd::CleanEof,
            LegEnd::PeerEnded,
            LegEnd::ReadError,
            LegEnd::WriteError,
            LegEnd::IdleExpired,
            LegEnd::Aborted,
        ] {
            assert_eq!(LegEnd::from_code(end.code()), end, "{end:?} 编解码");
        }
        assert_eq!(LegEnd::from_code(u8::MAX), LegEnd::CleanEof, "越界必须是现状兜底");
    }

    /// 创建两对 loopback TCP 连接：(client_a ↔ server_a) 和 (client_b ↔ server_b)。
    /// bridge(server_a, server_b) 后：
    /// - client_a 发的数据 → server_a 读 → bridge → server_b 写 → client_b 读
    /// - client_b 发的数据 → server_b 读 → bridge → server_a 写 → client_a 读
    async fn setup_two_pairs() -> (
        TcpStream,           // client_a
        TcpStream,           // client_b
        Box<dyn Connection>, // server_a (传入 bridge)
        Box<dyn Connection>, // server_b (传入 bridge)
    ) {
        let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_a = listener_a.local_addr().unwrap();
        let addr_b = listener_b.local_addr().unwrap();

        let (client_a_task, client_b_task, server_a_task, server_b_task) = tokio::join!(
            async { TcpStream::connect(addr_a).await.unwrap() },
            async { TcpStream::connect(addr_b).await.unwrap() },
            async { listener_a.accept().await.unwrap().0 },
            async { listener_b.accept().await.unwrap().0 },
        );

        let server_a: Box<dyn Connection> = Box::new(TcpConnection::new(server_a_task));
        let server_b: Box<dyn Connection> = Box::new(TcpConnection::new(server_b_task));

        (client_a_task, client_b_task, server_a, server_b)
    }

    #[tokio::test]
    async fn bridge_bidirectional_data_flow() {
        let (mut client_a, mut client_b, server_a, server_b) = setup_two_pairs().await;

        // 启动 bridge
        #[allow(clippy::disallowed_methods, reason = "测试：桥双向数据流任务")]
        let bridge = tokio::spawn(async move { bridge_connections(server_a, server_b).await });

        // client_a → bridge → client_b
        client_a.write_all(b"hello from A").await.unwrap();
        let mut buf = [0u8; 12];
        client_b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello from A");

        // client_b → bridge → client_a
        client_b.write_all(b"hello from B").await.unwrap();
        let mut buf = [0u8; 12];
        client_a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello from B");

        // 关闭 client 触发 bridge EOF
        drop(client_a);
        drop(client_b);

        // bridge 应正常返回
        let _ = bridge.await;
    }

    #[tokio::test]
    async fn bridge_returns_on_either_side_eof() {
        let (mut client_a, _client_b, server_a, server_b) = setup_two_pairs().await;

        #[allow(clippy::disallowed_methods, reason = "测试：桥双向数据流任务")]
        let bridge = tokio::spawn(async move { bridge_connections(server_a, server_b).await });

        // client_a 发数据后关闭
        client_a.write_all(b"final").await.unwrap();
        drop(client_a);

        // bridge 应在 client_a 关闭后返回（EOF）
        // client_b 可能还没读到数据（取决于时序），但 bridge 必须返回
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), bridge).await;
        assert!(result.is_ok(), "bridge should return within timeout");
    }

    #[tokio::test]
    async fn bridge_large_payload_roundtrip() {
        let (mut client_a, mut client_b, server_a, server_b) = setup_two_pairs().await;

        #[allow(clippy::disallowed_methods, reason = "测试：桥 64KB roundtrip 任务")]
        let bridge = tokio::spawn(bridge_connections(server_a, server_b));

        // 发送较大 payload (64 KiB)
        let payload: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
        client_a.write_all(&payload).await.unwrap();

        let mut received = vec![0u8; payload.len()];
        client_b.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload);

        drop(client_a);
        drop(client_b);
        let _ = bridge.await;
    }

    /// gated 入口全绿信号（freedom 场景 `1, &[1]`，freedom.go:260）：裸 TCP 双端
    /// 数据双向互达。Linux 走 splice 泵；Windows/非 linux 平台闸门（平台+编译
    /// 门控）回退池化泵——两平台断言相同，证明入口语义一致。
    #[tokio::test]
    async fn bridge_with_splice_plain_tcp_bidirectional() {
        let (mut client_a, mut client_b, server_a, server_b) = setup_two_pairs().await;

        #[allow(clippy::disallowed_methods, reason = "测试：splice 桥任务")]
        let bridge = tokio::spawn(bridge_connections_with_splice(server_a, server_b, 1, &[1]));

        client_a.write_all(b"up-splice").await.unwrap();
        let mut buf = [0u8; 9];
        client_b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"up-splice");

        client_b.write_all(b"down-splice").await.unwrap();
        let mut buf = [0u8; 11];
        client_a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"down-splice");

        drop(client_a);
        drop(client_b);
        let _ = bridge.await;
    }

    /// 包装连接不启用（Go `IsRAWTransportWithoutSecurity` 对 tls.Conn 为
    /// false）：`raw_tcp_clone` 缺省 `None` + `is_raw_tcp` 缺省 `false` 的
    /// 包装层即使信号全绿也必须回退既有泵，数据照常流通。
    #[tokio::test]
    async fn bridge_with_splice_wrapped_conn_falls_back() {
        struct WrappedConn(TcpStream);
        impl tokio::io::AsyncRead for WrappedConn {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
            }
        }
        impl tokio::io::AsyncWrite for WrappedConn {
            fn poll_write(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<io::Result<usize>> {
                std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
            }

            fn poll_flush(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::pin::Pin::new(&mut self.0).poll_flush(cx)
            }

            fn poll_shutdown(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
            }
        }
        impl Connection for WrappedConn {
            fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(Some(self.0.peer_addr()?))
            }

            fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(Some(self.0.local_addr()?))
            }
        }

        // 自建一对拿裸 TcpStream（setup_two_pairs 已装箱为 dyn Connection），
        // 一端包成 is_raw_tcp=false 的包装层，另一端保持裸 TCP。
        let lsn_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client_a = TcpStream::connect(lsn_a.local_addr().unwrap()).await.unwrap();
        let wrapped_a: Box<dyn Connection> = Box::new(WrappedConn(lsn_a.accept().await.unwrap().0));
        assert!(!wrapped_a.is_raw_tcp());

        let lsn_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client_b = TcpStream::connect(lsn_b.local_addr().unwrap()).await.unwrap();
        let bare_b: Box<dyn Connection> =
            Box::new(TcpConnection::new(lsn_b.accept().await.unwrap().0));

        #[allow(clippy::disallowed_methods, reason = "测试：splice 桥任务（wrapped 入口）")]
        let bridge = tokio::spawn(bridge_connections_with_splice(wrapped_a, bare_b, 1, &[1]));

        client_a.write_all(b"fallback").await.unwrap();
        let mut buf = [0u8; 8];
        client_b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"fallback");

        drop(client_a);
        drop(client_b);
        let _ = bridge.await;
    }

    /// bd VISIONMAC 截断回归：down 侧结束后，link.writer 收尾必须走
    /// shutdown_flush（排空 + poll_shutdown），不能止步于 no-op sync
    /// shutdown——否则 TLS 层 BufWriter 语义下滞留 sendable_tls 的尾巴随
    /// drop 蒸发：对端 deframer 停在半条记录上永久 Pending，直到 FIN →
    /// "peer closed without close_notify" 断链（VPS netem r6 实锤滞留
    /// 65,383B = sendable_tls 64KB 上限）。
    ///
    /// mock 复刻 rustls 语义：poll_write 全量「收下」但不上线（sendable），
    /// poll_flush/poll_shutdown 才放行到 wire；修复前 wire 缺尾 + 无
    /// shutdown 标志，修复后全量到达 + shutdown 置位。
    #[tokio::test]
    async fn bridge_stream_full_down_teardown_flushes_and_shuts_down_writer() {
        use std::{
            net::SocketAddr,
            sync::{
                Arc,
                atomic::{AtomicBool, Ordering},
            },
            task::{Context, Poll},
        };

        use parking_lot::Mutex;
        use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
        use xray_buf::io::Writer as _;

        use crate::link::Link;

        /// 「TLS 层」mock：写半收下的字节滞留 sendable，flush/shutdown 才上线。
        #[derive(Clone)]
        struct TlsLike {
            sendable: Arc<Mutex<Vec<u8>>>,
            wire: Arc<Mutex<Vec<u8>>>,
            shutdown_seen: Arc<AtomicBool>,
        }
        impl AsyncWrite for TlsLike {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                // BufWriter 谎报：全量接受、滞留缓冲（rustls sendable_tls 语义）
                self.sendable.lock().extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                let mut sendable = self.sendable.lock();
                self.wire.lock().append(&mut sendable);
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.shutdown_seen.store(true, Ordering::SeqCst);
                Self::poll_flush(self, cx)
            }
        }

        /// 隧道整流（Connection）：读半吐响应后 EOF，写半=TlsLike。
        struct TunnelConn {
            data: Vec<u8>,
            pos: usize,
            tls: TlsLike,
        }
        impl AsyncRead for TunnelConn {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let rest = &self.data[self.pos..];
                if rest.is_empty() {
                    return Poll::Ready(Ok(())); // EOF
                }
                let n = rest.len().min(buf.remaining());
                buf.put_slice(&rest[..n]);
                self.pos += n;
                Poll::Ready(Ok(()))
            }
        }
        impl AsyncWrite for TunnelConn {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.tls).poll_write(cx, buf)
            }

            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.tls).poll_flush(cx)
            }

            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.tls).poll_shutdown(cx)
            }
        }
        impl Connection for TunnelConn {
            fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }

            fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }
        }

        let response = vec![0x42u8; 3 * 8192];
        let tls = TlsLike {
            sendable: Arc::new(Mutex::new(Vec::new())),
            wire: Arc::new(Mutex::new(Vec::new())),
            shutdown_seen: Arc::new(AtomicBool::new(false)),
        };
        // stream = 出站侧（freedom mock）：读半吐响应后 EOF，写半不用。
        let stream = TunnelConn { data: response.clone(), pos: 0, tls: tls.clone() };

        let (up_r, up_w) = xray_buf::pipe::new();
        // link.writer = SequentialWriter(WriteHalf<TunnelConn 写半>)——生产装配
        // 同形（server.rs: new_writer(split(vision) 写半)）。下行数据
        // stream→down_writer→link.writer→TLS mock（滞留→teardown 排空）。
        let tunnel = TunnelConn { data: Vec::new(), pos: 0, tls: tls.clone() };
        let (_t_read, t_write) = tokio::io::split(tunnel);
        let link = Link::new(Box::new(up_r), xray_buf::io::new_writer(t_write));

        #[allow(clippy::disallowed_methods, reason = "测试：stream 桥任务")]
        let bridge = tokio::spawn(bridge_link_with_stream_full_default(link, stream));
        up_w.shutdown(); // 上行立即 EOF，桥仅余下行收尾路径

        tokio::time::timeout(std::time::Duration::from_secs(5), bridge)
            .await
            .expect("bridge must finish")
            .unwrap()
            .unwrap();

        assert!(
            tls.shutdown_seen.load(Ordering::SeqCst),
            "teardown must poll_shutdown the link writer (flush stranded bytes + half-close)"
        );
        assert_eq!(
            *tls.wire.lock(),
            response,
            "stranded sendable bytes must reach the wire at teardown"
        );
    }

    /// bd oarfu：连接暴露零拷贝读腿时，下行必须走它而不是 AsyncRead 拷贝路径。
    ///
    /// 两条腿吐不同内容（AsyncRead 侧 "copied-downlink"，零拷贝侧
    /// "frozen-downlink"），sink 收到的内容即判定走了哪条——也防回档到
    /// 「钩子接了但桥层没消费」。
    #[tokio::test]
    async fn bridge_full_prefers_frozen_reader() {
        use std::{
            net::SocketAddr,
            task::{Context, Poll},
        };

        use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
        use xray_buf::io::Writer as _;

        use crate::link::Link;

        /// AsyncRead 吐固定串（拷贝路径数据），写向丢弃。
        struct FrozenConn {
            copy_data: &'static [u8],
            pos: usize,
        }
        impl AsyncRead for FrozenConn {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let rest = &self.copy_data[self.pos..];
                if rest.is_empty() {
                    return Poll::Ready(Ok(())); // EOF
                }
                let n = rest.len().min(buf.remaining());
                buf.put_slice(&rest[..n]);
                self.pos += n;
                Poll::Ready(Ok(()))
            }
        }
        impl AsyncWrite for FrozenConn {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(buf.len()))
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        impl Connection for FrozenConn {
            fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }

            fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }

            fn frozen_reader(&mut self) -> Option<Box<dyn xray_buf::io::Reader>> {
                Some(xray_buf::io::new_reader(std::io::Cursor::new(b"frozen-downlink".to_vec())))
            }
        }

        let stream = FrozenConn { copy_data: b"copied-downlink", pos: 0 };
        let (up_r, up_w) = xray_buf::pipe::new();
        let (sink, mut sink_peer) = tokio::io::duplex(64);
        let link = Link::new(Box::new(up_r), xray_buf::io::new_writer(sink));
        #[allow(clippy::disallowed_methods, reason = "测试：stream 桥任务")]
        let bridge = tokio::spawn(bridge_link_with_stream_full_default(link, stream));
        up_w.shutdown(); // 上行立即 EOF，桥只剩下行

        let mut got = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            sink_peer.read_to_end(&mut got),
        )
        .await;
        let _ = bridge.await;
        assert_eq!(got, b"frozen-downlink", "下行必须走零拷贝读腿，而非 AsyncRead 拷贝路径");
    }

    #[tokio::test]
    async fn copy_one_way_transfers_data() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (client, server) =
            tokio::join!(async { TcpStream::connect(addr).await.unwrap() }, async {
                listener.accept().await.unwrap().0
            },);

        let mut client = client;
        let server: Box<dyn Connection> = Box::new(TcpConnection::new(server));

        let (mut read, _write) = tokio::io::split(server);

        client.write_all(b"one-way data").await.unwrap();
        drop(client);

        let mut buf = Vec::new();
        copy_one_way(&mut read, &mut buf).await.unwrap();
        assert_eq!(&buf, b"one-way data");
    }

    #[tokio::test]
    async fn bridge_link_uplink_only() {
        // 最小上行测试：pipe.Writer 写 → bridge up reader 读 → duplex server 端收
        use tokio::io::AsyncReadExt;
        use xray_buf::{io::Writer, multi::MultiBuffer};

        use crate::link::Link;

        let (mut server, client) = tokio::io::duplex(8192);
        let (up_r, up_w) = xray_buf::pipe::new();
        let (_dn_r, dn_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(up_r), Box::new(dn_w));

        let (recv, _) = tokio::join!(
            async {
                let mut w = up_w;
                let mut mb = MultiBuffer::new();
                mb.merge_bytes(b"uplink ok");
                w.write_multi_buffer(mb).await.unwrap();
                w.shutdown(); // pipe.Writer.close → bridge up reader EOF
                let mut buf = vec![0u8; 64];
                let n = server.read(&mut buf).await.unwrap();
                buf[..n].to_vec()
            },
            bridge_link_with_stream(link, client),
        );
        assert_eq!(&recv, b"uplink ok");
    }

    #[tokio::test]
    async fn bridge_link_downlink_only() {
        // 最小下行测试：duplex server 端写 → bridge down reader 读 → pipe.Reader 收
        use tokio::io::AsyncWriteExt;

        use crate::link::Link;

        let (mut server, client) = tokio::io::duplex(8192);
        // dn pipe：bridge 写下行数据到这里，主线程从 dn_r 读
        let (dn_r, dn_w) = xray_buf::pipe::new();
        // up pipe 占位：bridge 的上行 reader 在这里读，但本测试不写上行数据
        let (dummy_r, _dummy_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(dummy_r), Box::new(dn_w));

        let (recv, _) = tokio::join!(
            async {
                server.write_all(b"downlink ok").await.unwrap();
                drop(server); // 关闭触发 bridge down reader EOF
                let mut r = dn_r;
                r.read_multi_buffer().await.unwrap().to_vec()
            },
            bridge_link_with_stream(link, client),
        );
        assert_eq!(&recv, b"downlink ok");
    }

    // ---- 半关闭限窗（policy UplinkOnly/DownlinkOnly，6bg）----

    #[tokio::test]
    async fn bridge_stream_full_halfclose_linger_then_close() {
        use xray_buf::{io::Writer, multi::MultiBuffer};

        use crate::link::Link;

        let (up_r, up_w) = xray_buf::pipe::new();
        let (dn_r, dn_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(up_r), Box::new(dn_w));
        let (mut stream_peer, stream) = tokio::io::duplex(8192);

        #[allow(clippy::disallowed_methods, reason = "测试：stream 桥任务")]
        let bridge = tokio::spawn(bridge_link_with_stream_full_default(
            link,
            Box::new(DuplexConnection::new(stream)) as Box<dyn Connection>,
        ));

        // 上游写完即 EOF → bridge down 进入 downlink_only（1s）窗口
        let mut producer = up_w;
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(b"req");
        producer.write_multi_buffer(mb).await.unwrap();
        producer.shutdown();

        // 窗口内 stream 端送来响应 → 下行续传（activity 重置窗口）
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        stream_peer.write_all(b"resp").await.unwrap();

        let mut consumer = dn_r;
        let mb = consumer
            .read_multi_buffer_timeout(std::time::Duration::from_secs(1))
            .await
            .expect("downlink should deliver within half-close window");
        assert_eq!(mb.to_vec(), b"resp");

        // 之后无数据 → 窗口耗尽 → bridge 结束（不永久挂起）
        let res = tokio::time::timeout(std::time::Duration::from_secs(5), bridge)
            .await
            .expect("bridge must finish after window expires")
            .expect("join error");
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn bridge_stream_full_halfclose_timeout_disconnects() {
        use xray_buf::io::Writer;

        use crate::link::Link;

        let (up_r, up_w) = xray_buf::pipe::new();
        let (dn_r, dn_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(up_r), Box::new(dn_w));
        // peer 保留不 drop：drop 会让 stream EOF 走正常结束而非超时路径
        let (_stream_peer, stream) = tokio::io::duplex(8192);

        let start = xray_frame::compat::clock().now_instant();
        // 上游立即 EOF（无数据）→ down 只能靠 downlink_only 窗口超时断开
        up_w.shutdown();
        let res = bridge_link_with_stream_full_default(
            link,
            Box::new(DuplexConnection::new(stream)) as Box<dyn Connection>,
        )
        .await;
        assert!(res.is_ok());
        assert!(
            start.elapsed() >= std::time::Duration::from_millis(900),
            "half-close window should elapse before disconnect"
        );
        assert!(start.elapsed() < std::time::Duration::from_secs(5), "should not hang forever");
        let _ = dn_r;
    }

    // ---- bd 4-6: per-dispatch policy 下放到 bridge 数据面 ----

    /// 极短 conn_idle 验证：bridge 200ms 内无活动必须断开（替代默认 300s）。
    /// 这一条断言即可证明：传入的 `&TimeoutPolicy` 真的进了 conn_idle 计算，
    /// 而非被忽略/被默认常量覆盖。
    #[tokio::test]
    async fn bridge_stream_full_uses_injected_connection_idle() {
        use std::time::Duration;

        use xray_features::policy::TimeoutPolicy;

        use crate::link::Link;

        let (up_r, up_w) = xray_buf::pipe::new();
        let (dn_r, dn_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(up_r), Box::new(dn_w));
        let (_stream_peer, stream) = tokio::io::duplex(8192);

        // 关键：短 conn_idle = 200ms，远小于默认 300s。
        // uplink_only / downlink_only 留默认 1s（不影响 conn_idle 路径）。
        let policy = TimeoutPolicy {
            connection_idle: Duration::from_millis(200),
            ..TimeoutPolicy::default()
        };

        let start = xray_frame::compat::clock().now_instant();
        // 上行 writer 保留不写、不 shutdown → 双方向均无活动 → conn_idle 触发断开。
        let _keep_up = up_w;
        let res = bridge_link_with_stream_full(
            link,
            Box::new(DuplexConnection::new(stream)) as Box<dyn Connection>,
            &policy,
        )
        .await;
        let elapsed = start.elapsed();
        assert!(res.is_ok(), "bridge must return Ok on conn_idle break");
        assert!(
            elapsed >= Duration::from_millis(180),
            "must respect injected conn_idle (elapsed {elapsed:?} < 200ms)"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "conn_idle too long, possibly fell back to default 300s (elapsed {elapsed:?})"
        );
        let _ = dn_r;
    }

    // ---- G11：半关闭限窗方向绑定（非对称 uplinkOnly/downlinkOnly，ft58）----
    // Go 锚点：freedom.go:388 requestDone（上行 copy）defer SetTimeout(DownlinkOnly)
    // → 上行结束后下行窗 = DownlinkOnly；freedom.go:427 responseDone（下行 copy）
    // defer SetTimeout(UplinkOnly) → 下行结束后上行窗 = UplinkOnly。
    // 非对称 policy（uplink=200ms / downlink=1500ms，conn_idle=5s 兜底不触发）
    // 下，两个半关闭场景的断开时机必须分别落在对应窗口上，方向互换即失败。

    fn asym_halfclose_policy() -> xray_features::policy::TimeoutPolicy {
        xray_features::policy::TimeoutPolicy {
            handshake: std::time::Duration::from_secs(5),
            connection_idle: std::time::Duration::from_secs(5),
            uplink_only: std::time::Duration::from_millis(200),
            downlink_only: std::time::Duration::from_millis(1500),
        }
    }

    /// 上行先 EOF、之后无数据 → 断开时机 ≈ downlink_only（1500ms）。
    #[tokio::test]
    async fn bridge_stream_full_halfclose_after_up_eof_uses_downlink_only() {
        use std::time::Duration;

        use xray_buf::io::Writer;

        use crate::link::Link;

        let (up_r, up_w) = xray_buf::pipe::new();
        let (dn_r, dn_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(up_r), Box::new(dn_w));
        // peer 保留：只走 up EOF 触发半关闭，不走 stream EOF
        let (_stream_peer, stream) = tokio::io::duplex(8192);

        let start = xray_frame::compat::clock().now_instant();
        up_w.shutdown(); // 上行立即 EOF（Go requestDone 返回）
        let res = bridge_link_with_stream_full(
            link,
            Box::new(DuplexConnection::new(stream)) as Box<dyn Connection>,
            &asym_halfclose_policy(),
        )
        .await;
        let elapsed = start.elapsed();
        assert!(res.is_ok(), "bridge must return Ok on half-close window break");
        assert!(
            elapsed >= Duration::from_millis(1200),
            "after up EOF, close must wait downlink_only(1500ms), got {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(4000),
            "must not reach conn_idle(5s), got {elapsed:?}"
        );
        let _ = dn_r;
    }

    /// 下行先 EOF、之后 client 不发数据 → 断开时机 ≈ uplink_only（200ms）。
    #[tokio::test]
    async fn bridge_stream_full_halfclose_after_down_eof_uses_uplink_only() {
        use std::time::Duration;

        use crate::link::Link;

        let (up_r, up_w) = xray_buf::pipe::new();
        let (dn_r, dn_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(up_r), Box::new(dn_w));
        let (stream_peer, stream) = tokio::io::duplex(8192);

        let start = xray_frame::compat::clock().now_instant();
        drop(stream_peer); // 下行立即 EOF（Go responseDone 返回）
        let res = bridge_link_with_stream_full(
            link,
            Box::new(DuplexConnection::new(stream)) as Box<dyn Connection>,
            &asym_halfclose_policy(),
        )
        .await;
        let elapsed = start.elapsed();
        assert!(res.is_ok(), "bridge must return Ok on half-close window break");
        assert!(
            elapsed >= Duration::from_millis(80),
            "after down EOF, close must wait uplink_only(200ms), got {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(1200),
            "after down EOF, close must NOT wait downlink_only(1500ms), got {elapsed:?}"
        );
        let _ = up_w;
        let _ = dn_r;
    }

    // ---- 中止闸（bd rjt2o）：写腿被堵时连接必须按时拆（S1/S3 钉死回归门）----

    /// 上行写腿被堵（对端活着但不读，写永不 Ready）+ 上行 reader 把 64 条 mpsc
    /// 灌满 → 读侧判定只能由下行腿的 connIdle 给出：关闸 → 写腿/send 腿即刻归 →
    /// 桥按时返回。修前此形态永不返回（`join!` 等四腿全归）。
    #[tokio::test]
    async fn bridge_stream_full_abort_gate_releases_stalled_uplink_writer() {
        use std::{
            pin::Pin,
            task::{Context, Poll},
            time::Duration,
        };

        use xray_features::policy::TimeoutPolicy;

        use crate::link::Link;

        /// 写永不 Ready（对端不读）、读永不就绪；shutdown 也永不就绪（3s 界必须兜住）。
        struct StallConn;
        impl tokio::io::AsyncRead for StallConn {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }
        impl tokio::io::AsyncWrite for StallConn {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Pending
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Pending
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }
        impl Connection for StallConn {
            fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }

            fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }
        }

        // 上行源 4MB 顺序读：够把 PIPE_BUF_CAP=64 条 mpsc 灌满 → up_reader 卡在 send。
        let up_src = xray_buf::io::new_reader(std::io::Cursor::new(vec![0u8; 4 * 1024 * 1024]));
        let (dn_r, dn_w) = xray_buf::pipe::new();
        let link = Link::new(up_src, Box::new(dn_w));

        let policy =
            TimeoutPolicy { connection_idle: Duration::from_millis(100), ..Default::default() };
        let start = xray_frame::compat::clock().now_instant();
        let res = tokio::time::timeout(
            Duration::from_secs(6),
            bridge_link_with_stream_full(link, StallConn, &policy),
        )
        .await
        .expect("write-stalled bridge must return (abort gate), not pin the connection");
        assert!(res.is_ok());
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "conn_idle(100ms) + shutdown 3s 界, got {:?}",
            start.elapsed()
        );
        let _ = dn_r;
    }

    /// 下行写腿被堵（link.writer 写永不完成）：下行读侧 connIdle 到点 → 关闸 →
    /// 写腿即刻归，桥按时返回（修前 `join!` 永挂）。
    #[tokio::test]
    async fn bridge_stream_full_abort_gate_releases_stalled_downlink_writer() {
        use std::{future::Future, pin::Pin, task::Context, time::Duration};

        use xray_buf::{
            io::{Result as BufResult, Writer},
            multi::MultiBuffer,
        };
        use xray_features::policy::TimeoutPolicy;

        use crate::link::Link;

        /// 写永不完成的 link.writer（背压钉死）。
        struct StallLinkWriter;
        impl Writer for StallLinkWriter {
            fn write_multi_buffer(
                &mut self,
                _mb: MultiBuffer,
            ) -> Pin<Box<dyn Future<Output = BufResult<()>> + Send + '_>> {
                Box::pin(std::future::pending::<BufResult<()>>())
            }
        }

        /// 读：先给一帧下行数据（喂满 down_writer 让它卡在写），之后永不就绪。
        struct ChunkThenSilent {
            chunk: Option<Vec<u8>>,
        }
        impl tokio::io::AsyncRead for ChunkThenSilent {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                match self.chunk.take() {
                    Some(d) => {
                        buf.put_slice(&d);
                        Poll::Ready(Ok(()))
                    },
                    None => Poll::Pending,
                }
            }
        }
        impl tokio::io::AsyncWrite for ChunkThenSilent {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(buf.len()))
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        impl Connection for ChunkThenSilent {
            fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }

            fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }
        }

        // 上行源有界（快速 EOF，不参与判定），确保关闸只能来自下行读侧。
        let up_src = xray_buf::io::new_reader(std::io::Cursor::new(vec![0u8; 64 * 1024]));
        let link = Link::new(up_src, Box::new(StallLinkWriter));
        let stream = ChunkThenSilent { chunk: Some(vec![0x5A; 4096]) };

        let policy =
            TimeoutPolicy { connection_idle: Duration::from_millis(100), ..Default::default() };
        let start = xray_frame::compat::clock().now_instant();
        let res = tokio::time::timeout(
            Duration::from_secs(6),
            bridge_link_with_stream_full(link, stream, &policy),
        )
        .await
        .expect("down-write-stalled bridge must return (abort gate), not pin the connection");
        assert!(res.is_ok());
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "downlink_only(1s) 窗口应当兜住收尾, got {:?}",
            start.elapsed()
        );
    }

    /// bridge_connections 池化路径：两端双向 8KB 流量必须无丢失、按时返回。
    /// ponytail: 8KB 池化缓冲替代 tokio::io::copy 的内置 Vec——大流量下不至于
    /// 反复 alloc 8KB Vec。但行为正确性必须验证（防止 alloc/release 配对错误）。
    #[tokio::test]
    async fn bridge_connections_bidirectional_pooled_8kb() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::{TcpListener, TcpStream},
        };

        use crate::connection::TcpConnection;

        // 两对 loopback：(client_a ↔ server_a), (client_b ↔ server_b)
        let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_a = listener_a.local_addr().unwrap();
        let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_b = listener_b.local_addr().unwrap();

        let client_a = TcpStream::connect(addr_a).await.unwrap();
        let server_a = listener_a.accept().await.unwrap().0;
        let client_b = TcpStream::connect(addr_b).await.unwrap();
        let server_b = listener_b.accept().await.unwrap().0;

        // 启动 bridge(server_a, server_b)
        #[allow(clippy::disallowed_methods, reason = "测试：桥 8KB 双向任务")]
        let bridge_handle = tokio::spawn(bridge_connections(
            Box::new(TcpConnection::new(server_a)) as Box<dyn Connection>,
            Box::new(TcpConnection::new(server_b)) as Box<dyn Connection>,
        ));

        // 单方向 8KB 数据：client_a → bridge → client_b
        let payload = vec![0xA5u8; 8 * 1024];
        let payload_for_read = payload.clone();
        let mut client_a = TcpConnection::new(client_a);
        let mut client_b = TcpConnection::new(client_b);
        #[allow(clippy::disallowed_methods, reason = "测试：上行写任务")]
        let writer = tokio::spawn(async move {
            client_a.write_all(&payload).await.unwrap();
            client_a.shutdown().await.ok();
        });
        let mut recv_buf = vec![0u8; payload_for_read.len()];
        client_b.read_exact(&mut recv_buf).await.unwrap();
        assert_eq!(recv_buf, payload_for_read, "pooled bridge must not lose/corrupt bytes");
        writer.await.unwrap();
        // 读端 drop → bridge 一方向 EOF → 整体退出
        drop(client_b);
        let _res = tokio::time::timeout(std::time::Duration::from_secs(5), bridge_handle)
            .await
            .expect("bridge must finish after EOF")
            .expect("bridge join");
    }

    // ---- 8sum 方案 A：解耦泵回归门 + 瞬时写错不断向 + vectored 写（y1yx）----

    /// 解耦回归门（HANDOFF `bridge_stream_full_uplink_survives_slow_remote` 重建）：
    /// stream 对端永不读（duplex 8192 缓冲即背压），上游写 64KB + shutdown。
    /// 解耦版 up reader 把数据吸进 mpsc（**按条目计**，见 `PIPE_BUF_CAP`）后
    /// 照常读到 EOF → up_done →
    /// down 腿 uplink_only 窗口耗尽收尾 → dn_r 读到关闭；串行泵会卡在
    /// 写 duplex 的锁步里永远读不到上游 EOF，dn_r 5s 内等不到关闭。
    #[tokio::test]
    async fn bridge_stream_full_uplink_survives_slow_remote() {
        use xray_buf::{io::Writer, multi::MultiBuffer};

        use crate::link::Link;

        let (up_r, mut up_w) = xray_buf::pipe::new();
        let (dn_r, dn_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(up_r), Box::new(dn_w));
        let (_peer, stream) = tokio::io::duplex(8192);

        #[allow(clippy::disallowed_methods, reason = "测试：stream 桥任务")]
        let bridge = tokio::spawn(bridge_link_with_stream_full_default(
            link,
            Box::new(DuplexConnection::new(stream)) as Box<dyn Connection>,
        ));

        // 64KB = 8 × duplex 缓冲：解耦后被 mpsc（按条目计）全量吸收
        for _ in 0..8 {
            let mut mb = MultiBuffer::new();
            mb.merge_bytes(&vec![0x5Au8; 8 * 1024]);
            up_w.write_multi_buffer(mb).await.unwrap();
        }
        up_w.shutdown();

        // 上游 EOF 传播 + half-close 窗口耗尽 → bridge 收尾 → dn_r 关闭。
        let mut consumer = dn_r;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match consumer.read_multi_buffer().await {
                    Ok(mb) if !mb.is_empty() => continue,
                    _ => return,
                }
            }
        })
        .await
        .expect("bridge must close dn_r after upstream EOF + window expiry (decoupled)");
        // 对端不读，up_writer 停在写背压——由 abort 收尾，非本测试断言对象。
        bridge.abort();
    }

    /// bd zct77 回归门（C4 下载尾部静默截断 / curl 18）：读腿先 EOF、而写腿队列
    /// 仍有残量且**正在推进**时，半关闭窗必须被对向写腿的进展重置——残留字节
    /// 必须全部送达。
    ///
    /// 构造：下行源 `Cursor` 一次读尽 256KiB 后 EOF（解耦 mpsc 全量吸收）；下行
    /// sink 用**每批 40ms 的慢 Writer**（等价生产里 h2 流控满时的写背压）⇒ 排空
    /// ≈1.28s > 半窗 1s。旧语义（布防点=读腿 EOF、计时只看剩余方向）在 1s 处
    /// abort 丢弃仍在排队的批次（生产即 82MB/100MB 处断流）；修复后对向每写出
    /// 一批即重置窗口。
    #[tokio::test]
    async fn bridge_stream_full_read_eof_keeps_draining_queued_bytes() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        use xray_buf::{io::Writer, multi::MultiBuffer};

        use crate::link::Link;

        const TOTAL: usize = 256 * 1024;

        /// 慢 sink：每批 40ms 才「写出」，累计字节计数（8KiB/批 ⇒ 256KiB ≈1.28s）。
        struct SlowSink(Arc<AtomicUsize>);
        impl Writer for SlowSink {
            fn write_multi_buffer(
                &mut self,
                mb: MultiBuffer,
            ) -> Pin<Box<dyn Future<Output = xray_buf::io::Result<()>> + Send + '_>> {
                let n = mb.len();
                let got = Arc::clone(&self.0);
                Box::pin(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
                    got.fetch_add(n, Ordering::SeqCst);
                    Ok(())
                })
            }

            fn shutdown(&self) {}
        }

        /// 下行源读尽即 EOF；写半（上行方向）丢弃——本用例只考察下行排空。
        struct DlConn(std::io::Cursor<Vec<u8>>);
        impl tokio::io::AsyncRead for DlConn {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.0).poll_read(cx, buf)
            }
        }
        impl tokio::io::AsyncWrite for DlConn {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                data: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(data.len()))
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        impl Connection for DlConn {
            fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }

            fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }
        }

        // 上传方向全程空闲（下载型连接）：_up_w 保活，上行腿只等半窗。
        let (up_r, _up_w) = xray_buf::pipe::new();
        let got = Arc::new(AtomicUsize::new(0));
        let link = Link::new(Box::new(up_r), Box::new(SlowSink(Arc::clone(&got))));
        let conn = DlConn(std::io::Cursor::new(vec![0x5Au8; TOTAL]));

        #[allow(clippy::disallowed_methods, reason = "测试：stream 桥任务（断流回归门）")]
        let bridge = tokio::spawn(bridge_link_with_stream_full_default(
            link,
            Box::new(conn) as Box<dyn Connection>,
        ));

        #[allow(clippy::disallowed_methods, reason = "测试：15s 兜底界")]
        let _ = tokio::time::timeout(std::time::Duration::from_secs(15), bridge)
            .await
            .expect("bridge must finish after drain");
        assert_eq!(
            got.load(Ordering::SeqCst),
            TOTAL,
            "读腿 EOF 后队列残留必须全部送达（半窗须被对向写腿进展重置；旧语义 1s abort 丢弃）"
        );
    }

    /// 瞬时写错误不永久断向（验收 5；50074b2 头号嫌疑回归门）：上行 writer 写
    /// stream 恒错时仅上行收敛，下行数据照常送达 link.writer，桥在有限时间
    /// 整体退出——绝不 shutdown 对向（写错 shutdown link.writer = 下行永久断）。
    #[tokio::test]
    async fn bridge_stream_full_up_write_err_keeps_downlink() {
        use std::{pin::Pin, task::Poll};

        use xray_buf::io::Writer;

        use crate::link::Link;

        /// 写半恒错的 mock：读半转发真 duplex（下行数据源）。
        struct UpWriteErrConn(tokio::io::DuplexStream);
        impl tokio::io::AsyncRead for UpWriteErrConn {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.0).poll_read(cx, buf)
            }
        }
        impl tokio::io::AsyncWrite for UpWriteErrConn {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "transient write err")))
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        impl Connection for UpWriteErrConn {
            fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }

            fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }
        }

        let (up_r, mut up_w) = xray_buf::pipe::new();
        let (mut dn_r, dn_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(up_r), Box::new(dn_w));
        let (mut peer, stream) = tokio::io::duplex(8192);

        #[allow(clippy::disallowed_methods, reason = "测试：stream 桥任务（写错注入）")]
        let bridge = tokio::spawn(bridge_link_with_stream_full_default(
            link,
            Box::new(UpWriteErrConn(stream)) as Box<dyn Connection>,
        ));

        // 上行数据触发 up_writer 写错 → 仅上行收敛
        let mut mb = xray_buf::multi::MultiBuffer::new();
        mb.merge_bytes(b"req");
        up_w.write_multi_buffer(mb).await.unwrap();
        up_w.shutdown();

        // 下行不受写错影响：窗口内送达 link.writer
        use tokio::io::AsyncWriteExt;
        peer.write_all(b"resp").await.unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(2), dn_r.read_multi_buffer())
            .await
            .expect("downlink must survive up-write error (no cross-direction shutdown)")
            .unwrap();
        assert_eq!(got.to_vec(), b"resp");

        // 全桥有限时间收敛（half-close 窗口耗尽后退出，不挂死）
        drop(peer);
        drop(up_w);
        let res = tokio::time::timeout(std::time::Duration::from_secs(5), bridge)
            .await
            .expect("bridge must finish after window expiry")
            .expect("bridge join");
        assert!(res.is_ok());
    }

    /// 诊断面回归门（bd myppb）：读腿真实 IO 错误必须上浮——整体返回 `Err`
    /// 且**保留原始 kind**，另一腿的正常 EOF 不得掩盖它（改造前 `_ => break`
    /// 把两者并成一类，腿恒返 `Ok(())` ⇒ dispatcher 的 warn 是死代码）。
    #[tokio::test]
    async fn bridge_stream_full_read_err_surfaces_with_kind() {
        use std::future::Future;

        use xray_buf::{
            io::{Error as BufError, Reader, Result as BufResult},
            multi::MultiBuffer,
        };

        use crate::link::Link;

        /// 读恒报 ConnectionReset 的 mock link.reader。
        struct ResetReader;
        impl Reader for ResetReader {
            fn read_multi_buffer(
                &mut self,
            ) -> Pin<Box<dyn Future<Output = BufResult<MultiBuffer>> + Send + '_>> {
                Box::pin(std::future::ready(Err(BufError::ReadIo(std::io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "reset by peer",
                )))))
            }
        }

        let (dn_r, dn_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(ResetReader), Box::new(dn_w));
        // 下行（另一腿）正常 EOF：对端 drop。
        let (stream_peer, stream) = tokio::io::duplex(8192);
        drop(stream_peer);

        let res = bridge_link_with_stream_full(
            link,
            Box::new(DuplexConnection::new(stream)) as Box<dyn Connection>,
            &asym_halfclose_policy(),
        )
        .await;
        let err = res.expect_err("read-leg error must surface, not be swallowed like EOF");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset, "kind must survive the leg");
        let _ = dn_r;
    }

    /// 诊断面回归门（bd myppb）：全腿正常收尾仍是 `Ok(())`。上行 pipe 关闭时
    /// 读腿拿到的是 `Error::Eof`（**不是**错误），下行对端 EOF —— 两者都必须
    /// 只算收尾，否则每条正常结束的连接都会变成 error 日志。
    #[tokio::test]
    async fn bridge_stream_full_all_legs_eof_returns_ok() {
        use xray_buf::io::Writer;

        use crate::link::Link;

        let (up_r, up_w) = xray_buf::pipe::new();
        let (dn_r, dn_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(up_r), Box::new(dn_w));
        let (stream_peer, stream) = tokio::io::duplex(8192);

        drop(stream_peer); // 下行 EOF
        up_w.shutdown(); // 上行 pipe close → 读腿报 Error::Eof（正常收尾）

        let res = bridge_link_with_stream_full(
            link,
            Box::new(DuplexConnection::new(stream)) as Box<dyn Connection>,
            &asym_halfclose_policy(),
        )
        .await;
        assert!(res.is_ok(), "normal EOF ends must stay Ok, got {res:?}");
        let _ = dn_r;
    }

    // ---- degg3 收尾分流门（Step 2）：有序结束信号只在正常收尾发 ----

    /// 收尾门探针：转发 duplex（数据面照常），只把 `poll_shutdown` 计数。
    /// 计数 == 1 ⇒ 发了有序结束信号；== 0 ⇒ 异常收尾（靠 drop 全关）。
    struct CountShutdownConn {
        io: tokio::io::DuplexStream,
        shuts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl CountShutdownConn {
        fn new(
            io: tokio::io::DuplexStream,
        ) -> (Self, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
            let shuts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            (Self { io, shuts: shuts.clone() }, shuts)
        }
    }

    impl tokio::io::AsyncRead for CountShutdownConn {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for CountShutdownConn {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.io).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            self.shuts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }

    impl Connection for CountShutdownConn {
        fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
            Ok(None)
        }

        fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
            Ok(None)
        }
    }

    /// A 臂不回归（QAS-2）：正常 EOF 仍然发有序结束信号，且只发一次。
    #[tokio::test]
    async fn bridge_stream_full_clean_eof_still_signals_end() {
        use xray_buf::io::Writer;

        use crate::link::Link;

        let (up_r, up_w) = xray_buf::pipe::new();
        let (dn_r, dn_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(up_r), Box::new(dn_w));
        let (stream_peer, stream) = tokio::io::duplex(8192);
        let (conn, shuts) = CountShutdownConn::new(stream);

        drop(stream_peer); // 下行 EOF
        up_w.shutdown(); // 上行 pipe close → 读腿报 Error::Eof（正常收尾）

        let res = bridge_link_with_stream_full(
            link,
            Box::new(conn) as Box<dyn Connection>,
            &asym_halfclose_policy(),
        )
        .await;
        assert!(res.is_ok(), "normal EOF ends must stay Ok, got {res:?}");
        assert_eq!(
            shuts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "clean EOF 必须发结束信号（A 臂字节级不变）"
        );
        let _ = dn_r;
    }

    /// QAS-1（异常可辨性）：读错误不得再伪装成「请求完成」——不调 `poll_shutdown`。
    #[tokio::test]
    async fn bridge_stream_full_read_err_skips_ordered_shutdown() {
        use xray_buf::{
            io::{Error as BufError, Reader, Result as BufResult},
            multi::MultiBuffer,
        };

        use crate::link::Link;

        struct ResetReader;
        impl Reader for ResetReader {
            fn read_multi_buffer(
                &mut self,
            ) -> Pin<Box<dyn Future<Output = BufResult<MultiBuffer>> + Send + '_>> {
                Box::pin(std::future::ready(Err(BufError::ReadIo(std::io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "reset by peer",
                )))))
            }
        }

        let (dn_r, dn_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(ResetReader), Box::new(dn_w));
        let (stream_peer, stream) = tokio::io::duplex(8192);
        let (conn, shuts) = CountShutdownConn::new(stream);
        drop(stream_peer); // 下行正常 EOF

        let res = bridge_link_with_stream_full(
            link,
            Box::new(conn) as Box<dyn Connection>,
            &asym_halfclose_policy(),
        )
        .await;
        assert_eq!(
            res.expect_err("read-leg error must surface").kind(),
            io::ErrorKind::ConnectionReset
        );
        assert_eq!(
            shuts.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "读错误收尾不得发有序结束信号"
        );
        let _ = dn_r;
    }

    /// 空闲超时（`connIdle`）是判定，不是对端说「我发完了」⇒ 不发有序结束信号。
    #[tokio::test]
    async fn bridge_stream_full_idle_expired_skips_ordered_shutdown() {
        use std::time::Duration;

        use xray_features::policy::TimeoutPolicy;

        use crate::link::Link;

        let (up_r, _up_w) = xray_buf::pipe::new();
        let (dn_r, dn_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(up_r), Box::new(dn_w));
        let (_peer, stream) = tokio::io::duplex(8192);
        let (conn, shuts) = CountShutdownConn::new(stream);
        let policy = TimeoutPolicy {
            connection_idle: Duration::from_millis(200),
            ..TimeoutPolicy::default()
        };

        let res =
            bridge_link_with_stream_full(link, Box::new(conn) as Box<dyn Connection>, &policy)
                .await;
        assert!(res.is_ok(), "idle break must stay Ok, got {res:?}");
        assert_eq!(
            shuts.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "空闲超时收尾不得发有序结束信号"
        );
        let _ = dn_r;
    }

    /// 中止闸收尾（写腿被堵、判定由对向读侧给出）同样不发有序结束信号。
    #[tokio::test]
    async fn bridge_stream_full_abort_skips_ordered_shutdown() {
        use std::time::Duration;

        use xray_features::policy::TimeoutPolicy;

        use crate::link::Link;

        let (dn_r, dn_w) = xray_buf::pipe::new();
        // 上行源 4MB 顺序读：写腿背压卡住（peer 活着但不读），收尾只能由中止闸给出。
        let up_src = xray_buf::io::new_reader(std::io::Cursor::new(vec![0u8; 4 * 1024 * 1024]));
        let link = Link::new(up_src, Box::new(dn_w));
        let (_peer, stream) = tokio::io::duplex(8192);
        let (conn, shuts) = CountShutdownConn::new(stream);
        let policy = TimeoutPolicy {
            connection_idle: Duration::from_millis(200),
            ..TimeoutPolicy::default()
        };

        let start = xray_frame::compat::clock().now_instant();
        let res =
            bridge_link_with_stream_full(link, Box::new(conn) as Box<dyn Connection>, &policy)
                .await;
        assert!(res.is_ok(), "abort break must stay Ok, got {res:?}");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "abort 收尾不得再等 3s shutdown 界，got {:?}",
            start.elapsed()
        );
        assert_eq!(
            shuts.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "中止收尾不得发有序结束信号"
        );
        let _ = dn_r;
    }

    /// 对称回归门：下行 writer 写 link.writer 恒错时仅下行收敛，上行数据
    /// 照常送达 stream，桥有限时间退出。
    #[tokio::test]
    async fn bridge_stream_full_down_write_err_keeps_uplink() {
        use std::pin::Pin;

        use xray_buf::{
            io::{Error as BufError, Result as BufResult, Writer},
            multi::MultiBuffer,
        };

        use crate::link::Link;

        /// 写恒错的 mock link.writer。
        struct ErrLinkWriter;
        impl Writer for ErrLinkWriter {
            fn write_multi_buffer(
                &mut self,
                _mb: MultiBuffer,
            ) -> Pin<Box<dyn Future<Output = BufResult<()>> + Send + '_>> {
                Box::pin(async { Err(BufError::WriteError("link writer broken".into())) })
            }
        }

        let (up_r, mut up_w) = xray_buf::pipe::new();
        let (dn_r, _dn_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(up_r), Box::new(ErrLinkWriter));
        let (mut peer, stream) = tokio::io::duplex(8192);

        #[allow(clippy::disallowed_methods, reason = "测试：stream 桥任务")]
        let bridge = tokio::spawn(bridge_link_with_stream_full_default(
            link,
            Box::new(DuplexConnection::new(stream)) as Box<dyn Connection>,
        ));
        let _ = dn_r; // 下行已断，仅防 unused

        // 下行数据触发 down_writer 写错 → 仅下行收敛
        use tokio::io::AsyncWriteExt;
        peer.write_all(b"resp").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 上行不受写错影响：数据照常穿过桥抵达 stream 对端
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(b"req");
        up_w.write_multi_buffer(mb).await.unwrap();
        up_w.shutdown();

        let mut got = vec![0u8; 3];
        tokio::time::timeout(std::time::Duration::from_secs(2), peer.read_exact(&mut got))
            .await
            .expect("uplink must survive down-write error")
            .unwrap();
        assert_eq!(&got, b"req");

        // 全桥有限时间收敛
        drop(peer);
        drop(up_w);
        let res = tokio::time::timeout(std::time::Duration::from_secs(5), bridge)
            .await
            .expect("bridge must finish")
            .expect("bridge join");
        assert!(res.is_ok());
    }

    /// `write_all_mb` vectored 批写（y1yx）：vectored mock 聚合 3 buffer 为
    /// 1 次 `poll_write_vectored`（生产经 tokio WriteHalf 透传到 TCP writev）。
    #[tokio::test]
    async fn write_all_mb_vectored_batch_write() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        use parking_lot::Mutex;

        struct VectoredMock {
            sink: Arc<Mutex<Vec<u8>>>,
            vectored_calls: Arc<AtomicUsize>,
        }
        impl tokio::io::AsyncWrite for VectoredMock {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.sink.lock().extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
            }

            fn poll_write_vectored(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                bufs: &[io::IoSlice<'_>],
            ) -> Poll<io::Result<usize>> {
                self.vectored_calls.fetch_add(1, Ordering::SeqCst);
                let mut sink = self.sink.lock();
                let mut total = 0;
                for b in bufs {
                    sink.extend_from_slice(b);
                    total += b.len();
                }
                Poll::Ready(Ok(total))
            }

            fn is_write_vectored(&self) -> bool {
                true
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let sink = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut s_write =
            VectoredMock { sink: Arc::clone(&sink), vectored_calls: Arc::clone(&calls) };
        assert!(s_write.is_write_vectored());

        let mb = xray_buf::multi::MultiBuffer::from_buffers(vec![
            xray_buf::buffer::Buffer::from_vec(b"abc".to_vec()),
            xray_buf::buffer::Buffer::from_vec(b"def".to_vec()),
            xray_buf::buffer::Buffer::from_vec(b"ghi".to_vec()),
        ]);
        write_all_mb(&mut s_write, &mb).await.unwrap();
        assert_eq!(*sink.lock(), b"abcdefghi");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "3 buffers must aggregate into a single poll_write_vectored"
        );
    }

    /// 写穿语义（flush）：TLS 层 `SSL_write` 是缓冲语义，尾 record 不 flush
    /// 不上线（Go `crypto/tls` 的 Write 直接落底层 conn）。`write_all_mb` 写完
    /// 一批必须 flush 一次。
    #[tokio::test]
    async fn write_all_mb_flushes_after_batch() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        use parking_lot::Mutex;

        struct FlushCountingMock {
            sink: Arc<Mutex<Vec<u8>>>,
            flushes: Arc<AtomicUsize>,
            vectored: bool,
        }
        impl tokio::io::AsyncWrite for FlushCountingMock {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.sink.lock().extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
            }

            fn poll_write_vectored(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                bufs: &[io::IoSlice<'_>],
            ) -> Poll<io::Result<usize>> {
                let mut sink = self.sink.lock();
                let mut total = 0;
                for b in bufs {
                    sink.extend_from_slice(b);
                    total += b.len();
                }
                Poll::Ready(Ok(total))
            }

            fn is_write_vectored(&self) -> bool {
                self.vectored
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                self.flushes.fetch_add(1, Ordering::SeqCst);
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let mb = xray_buf::multi::MultiBuffer::from_buffers(vec![
            xray_buf::buffer::Buffer::from_vec(b"abc".to_vec()),
            xray_buf::buffer::Buffer::from_vec(b"def".to_vec()),
        ]);
        for vectored in [false, true] {
            let sink = Arc::new(Mutex::new(Vec::new()));
            let flushes = Arc::new(AtomicUsize::new(0));
            let mut w = FlushCountingMock {
                sink: Arc::clone(&sink),
                flushes: Arc::clone(&flushes),
                vectored,
            };
            write_all_mb(&mut w, &mb).await.unwrap();
            assert_eq!(&*sink.lock(), b"abcdef");
            assert_eq!(
                flushes.load(Ordering::SeqCst),
                1,
                "每批写完必须 flush 一次（vectored={vectored}）"
            );
        }
    }

    /// **尾部 chunk 立即到达对端**（flush 写穿语义的正向证据）：模拟 TLS 层
    /// （btls/BoringSSL）的缓冲语义——`poll_write` 只把密文收进 session 缓冲，
    /// `poll_flush` 才落底层 conn。改前（桥层不 flush）尾部 chunk 滞留缓冲
    /// 不出，对端永远凑不齐请求；改后（每批 flush）尾部立即到达对端。
    #[tokio::test]
    async fn write_all_mb_flush_pushes_tail_chunk_to_peer() {
        use std::sync::{Arc, Mutex};

        /// 缓冲写者：poll_write 进内部缓冲，poll_flush 才把缓冲推上 wire。
        struct BufferedWriter {
            wire: Arc<Mutex<Vec<u8>>>,
            pending: Vec<u8>,
        }
        impl tokio::io::AsyncWrite for BufferedWriter {
            fn poll_write(
                mut self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.pending.extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
            }

            fn poll_flush(
                mut self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                let pending = std::mem::take(&mut self.pending);
                self.wire.lock().unwrap().extend_from_slice(&pending);
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let wire = Arc::new(Mutex::new(Vec::new()));
        let mut w = BufferedWriter { wire: Arc::clone(&wire), pending: Vec::new() };
        let mb = xray_buf::multi::MultiBuffer::from_buffers(vec![
            xray_buf::buffer::Buffer::from_vec(b"head-".to_vec()),
            xray_buf::buffer::Buffer::from_vec(b"tail-chunk".to_vec()),
        ]);
        write_all_mb(&mut w, &mb).await.unwrap();
        assert_eq!(
            &*wire.lock().unwrap(),
            b"head-tail-chunk",
            "尾部 chunk 必须已到达对端（flush 写穿；否则滞留 session 缓冲）"
        );
    }

    /// `write_all_mb` 非 vectored 回退（y1yx）：`is_write_vectored=false` 的
    /// 底层（TLS wrapper 等）逐 Buffer `write_all`，空 Buffer 不产生 syscall，
    /// 字节序不变。
    #[tokio::test]
    async fn write_all_mb_non_vectored_fallback_per_buffer() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        use parking_lot::Mutex;

        struct NonVectoredMock {
            sink: Arc<Mutex<Vec<u8>>>,
            write_calls: Arc<AtomicUsize>,
        }
        impl tokio::io::AsyncWrite for NonVectoredMock {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.write_calls.fetch_add(1, Ordering::SeqCst);
                self.sink.lock().extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let sink = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut s_write =
            NonVectoredMock { sink: Arc::clone(&sink), write_calls: Arc::clone(&calls) };
        assert!(!s_write.is_write_vectored());

        let mb = xray_buf::multi::MultiBuffer::from_buffers(vec![
            xray_buf::buffer::Buffer::from_vec(b"abc".to_vec()),
            xray_buf::buffer::Buffer::from_vec(Vec::new()),
            xray_buf::buffer::Buffer::from_vec(b"def".to_vec()),
            xray_buf::buffer::Buffer::from_vec(b"ghi".to_vec()),
        ]);
        write_all_mb(&mut s_write, &mb).await.unwrap();
        assert_eq!(*sink.lock(), b"abcdefghi");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "non-vectored fallback: one write per non-empty buffer, empty skipped"
        );
    }

    /// 生产 split 形态透传（y1yx）：`bridge_link_with_stream_full` 经
    /// `tokio::io::split` 后以 `WriteHalf` 为 W——split 时缓存 inner 的
    /// `is_write_vectored`（tokio split.rs:36），`poll_write_vectored` 真透传，
    /// vectored 聚合在生产接线不退化为逐段写。
    #[tokio::test]
    async fn write_all_mb_via_split_writehalf_forwards_vectored() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        use parking_lot::Mutex;

        struct VectoredMock {
            sink: Arc<Mutex<Vec<u8>>>,
            vectored_calls: Arc<AtomicUsize>,
        }
        impl tokio::io::AsyncWrite for VectoredMock {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.sink.lock().extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
            }

            fn poll_write_vectored(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                bufs: &[io::IoSlice<'_>],
            ) -> Poll<io::Result<usize>> {
                self.vectored_calls.fetch_add(1, Ordering::SeqCst);
                let mut sink = self.sink.lock();
                let mut total = 0;
                for b in bufs {
                    sink.extend_from_slice(b);
                    total += b.len();
                }
                Poll::Ready(Ok(total))
            }

            fn is_write_vectored(&self) -> bool {
                true
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        // split 要求 AsyncRead；此测试只写不读，EOF 桩即可。
        impl tokio::io::AsyncRead for VectoredMock {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let sink = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let mock = VectoredMock { sink: Arc::clone(&sink), vectored_calls: Arc::clone(&calls) };
        let (_s_read, mut s_write) = tokio::io::split(mock);
        assert!(
            s_write.is_write_vectored(),
            "WriteHalf must cache inner is_write_vectored at split time"
        );

        let mb = xray_buf::multi::MultiBuffer::from_buffers(vec![
            xray_buf::buffer::Buffer::from_vec(b"abc".to_vec()),
            xray_buf::buffer::Buffer::from_vec(b"def".to_vec()),
            xray_buf::buffer::Buffer::from_vec(b"ghi".to_vec()),
        ]);
        write_all_mb(&mut s_write, &mb).await.unwrap();
        assert_eq!(*sink.lock(), b"abcdefghi");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "vectored aggregation must survive the split(WriteHalf) indirection"
        );
    }

    /// F3 接线 mock：包装 duplex、按构造参数返回 tls_readbuf_size。
    struct LargeReadConn {
        io: tokio::io::DuplexStream,
        readbuf: usize,
    }

    impl tokio::io::AsyncRead for LargeReadConn {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for LargeReadConn {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.io).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }

    impl Connection for LargeReadConn {
        fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
            Ok(None)
        }

        fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
            Ok(None)
        }

        fn tls_readbuf_size(&self) -> usize {
            self.readbuf
        }
    }

    /// F3 接线 mock：记录到达 link.writer 的每批字节数。
    struct RecordingWriter {
        lens: std::sync::Arc<std::sync::Mutex<Vec<usize>>>,
    }

    use std::future::Future;

    impl xray_buf::io::Writer for RecordingWriter {
        fn write_multi_buffer(
            &mut self,
            mb: xray_buf::multi::MultiBuffer,
        ) -> Pin<Box<dyn Future<Output = xray_buf::io::Result<()>> + Send + '_>> {
            Box::pin(async move {
                self.lens.lock().unwrap().push(mb.len());
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn bridge_tls_readbuf_size_selects_reader_capacity() {
        // F3：tls_readbuf_size=64KB → 下行单批 20KB 到齐；缺省 0 → 8KB 劈批。
        // 字节总量与顺序两形态一致（读缓冲只改批形，不改数据）。
        use std::sync::{Arc, Mutex};

        use xray_buf::io::new_reader;

        for (readbuf, expect_single) in [(64 * 1024, true), (0, false)] {
            let (mut client, stream_io) = tokio::io::duplex(64 * 1024);
            let stream: Box<dyn Connection> = Box::new(LargeReadConn { io: stream_io, readbuf });
            let lens = Arc::new(Mutex::new(Vec::new()));
            let (up_r, _up_w) = tokio::io::duplex(64);
            let link = Link::new(
                new_reader(up_r),
                Box::new(RecordingWriter { lens: Arc::clone(&lens) })
                    as Box<dyn xray_buf::io::Writer>,
            );
            let policy = TimeoutPolicy::default();
            #[allow(clippy::disallowed_methods, reason = "测试：stream 桥任务（慢对端回归门）")]
            let bridge =
                tokio::spawn(
                    async move { bridge_link_with_stream_full(link, stream, &policy).await },
                );
            client.write_all(&vec![0u8; 20 * 1024]).await.unwrap();
            drop(client); // EOF → 桥排空下行后结束
            tokio::time::timeout(std::time::Duration::from_secs(5), bridge)
                .await
                .expect("bridge must finish after EOF")
                .expect("bridge task")
                .expect("bridge io");

            let got = std::mem::take(&mut *lens.lock().unwrap());
            assert_eq!(got.iter().sum::<usize>(), 20 * 1024, "字节总量不变 readbuf={readbuf}");
            if expect_single {
                assert_eq!(got, vec![20 * 1024], "64KB 读缓冲应单批到齐");
            } else {
                assert!(got.iter().all(|&n| n <= 8192), "缺省读缓冲保持 8KB 批上限: {got:?}");
            }
        }
    }
}

//! 每连接握手闸：accept 循环外的握手纪律（有界并发 + 首字节窗 + 节流计数）。
//!
//! 背景（bd 0wvne）：ws / httpupgrade 的握手曾经在 accept 循环内 `await`，单条
//! 「连了不握手」的探测连接独占循环 4~7s（PROXY 档无界）。握手移出循环后，
//! 每条坏连接都会占一个任务 + 一个 fd 直到超时，故必须两件配套：
//!
//! 1. **有界并发**（[`HandshakeGate`]）：`Semaphore` 满即 **fail-fast 丢弃**—— `MUST NOT`
//!    排队（排队 = 内存与请求数同涨）。
//! 2. **首字节窗**（[`wait_first_byte`]）：TCP 建连后先要求首字节在 [`FIRST_BYTE_TIMEOUT`]
//!    内到达，再进各协议自己的 4s 握手窗。探测连接一个
//!    字节都不发，命中即清；真实客户端（ClientHello/GET/PROXY 头）首字节与 SYN 同批到达，不受影响。
//!
//! 两个窗叠加后单连接最长占用 ≈ 首字节窗 + 4s（协议窗），比 Go 的单一 4s
//! `ReadHeaderTimeout` 清得更快。
//!
//! ## 归属裁决（bd 1z3pl ARCH-09，§3.5.5 三判据）
//!
//! 机制代码零 Xray 类型/零 Go wire 语义（tokio Semaphore + TcpStream + 原子计数），
//! 但**判据①不过闸**：按 §3.5.3 方向件纪律，网络/accept 循环纪律**即使零 xray 类型
//! 也不进 udf-frame**（先例：`accept_policy.rs` 留主仓 xray-transport）——本件正是
//! accept 循环纪律家族（握手移出循环后的准入面），且硬绑两处主仓面：`TcpStream::peek`
//! （网络 IO 方向）与 `crate::LOG`（主仓日志 facade）。
//! **udf 为何不适用**（实查非凭印象）：udf `skeleton_infra::fx::FxScope::with_concurrency`
//! 是 permit-in-future **排队**语义（超限任务在 future 内等 permit，abort 连带回收），
//! 本闸是 **fail-fast 不排队**（满即丢连接，内存不随请求数涨）——语义相反，白拿即错；
//! udf 也无「fail-fast 有界准入闸」等价件（udf reference 全量检索 2026-11-06）。
//! **应落层 = 主仓 xray-transport（§3.5.3 方向件最近消费方）**，非判据③「派生层放不下」
//! 例外，而是方向件纪律的直接适用。
//! udf-promotion-candidate：若将来出现**第二消费栈**需要同款 fail-fast 准入闸，先把
//! 与 IO/日志解耦的「Semaphore fail-fast 计数闸 + 节流计数」提炼 udf（零方向），首字节
//! 窗（TcpStream peek）随网络方向留仓。

use std::{
    fmt::Display,
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore},
};

/// 单监听握手任务并发上限（**显式常量，不从系统内存推导**：换机器不该改代码）。
///
/// 预算口径 = xray 进程可用 **96MB**（整机 256MB − 系统 ~60MB − 陪跑进程 ~40MB −
/// 抖动 24MB）；本轮全部新增池硬顶 **4MB**。**实测**单连接「握手期在途」堆成本
/// ≈ **55KiB**（线性斜率 54975B/conn：裸 socket 双方仅 ~0.9KiB，其余为 ws 握手态
/// /任务 future，属 tungstenite 内部按需分配，本层不预分配）⇒ 64 × 55KiB ≈
/// **3.4MiB = 96MB 的 3.5%，在 4MB 硬顶内**。
/// 取 64（而非更省的 32）的关键理由是**真实 burst**：一个 Chrome 页面 6 条并发
/// 连接，10 用户同时上线 = 60 条并发握手——32 会丢 28 条（用户侧表现为「连不上」）；
/// 生产探测在途仅 ≈1.3（4528 次/60min ÷ 60 × 1s 首字节窗），64 即 ~48× 余量。
/// 超出 64 才 **fail-fast 丢弃**（不排队）。
pub const MAX_INFLIGHT_HANDSHAKES: usize = 64;

/// 首字节窗：TCP 建连后首字节必须在此时间内到达。
///
/// 取 1s：探测连接一个字节都不发，1s 内清掉（在途数因此极低，这是"最小内存"
/// 的前提）；真实客户端的 PROXY 头 / TLS ClientHello / HTTP GET 与 SYN 同批到达
/// （CDN/argo 在自己的边缘完成 TCP 后立即回源转发首包），正常路径零感知。
pub const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(1);

/// 计数日志节流间隔：逐条 debug 之外，每 N 条打一条 warn 汇总（生产 75 次/分钟
/// 探测流量不能刷屏，但**必须有可见**的失败/丢弃证据）。
const LOG_EVERY: u64 = 256;

/// 每监听的握手闸（`Arc` 供 accept 循环与各握手任务共享）。
pub struct HandshakeGate {
    semaphore: Arc<Semaphore>,
    rejected: AtomicU64,
    failed: AtomicU64,
}

impl HandshakeGate {
    /// 建上限为 `limit` 的闸。
    #[must_use]
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            semaphore: Arc::new(Semaphore::new(limit)),
            rejected: AtomicU64::new(0),
            failed: AtomicU64::new(0),
        })
    }

    /// 取握手许可：满即 `None`（**fail-fast**，不进队列）。许可随任务结束释放。
    #[must_use]
    pub fn try_admit(&self) -> Option<OwnedSemaphorePermit> {
        self.semaphore.clone().try_acquire_owned().ok()
    }

    /// 记录一次因饱和被丢弃的连接（调用方随即 drop 连接 = 对端见 RST/FIN）。
    ///
    /// 首条与随后每 `LOG_EVERY` 条打 warn：既留可见证据，又不随探测流量刷屏。
    pub fn record_reject(&self, tag: &str) {
        let n = self.rejected.fetch_add(1, Ordering::Relaxed) + 1;
        if n % LOG_EVERY == 1 {
            crate::LOG.warn(format!(
                "tag={tag} error=handshake concurrency limit reached handshake_gate: 并发握手达上限 {}，已 fail-fast 丢弃 {n} 条连接（不进队列）",
                MAX_INFLIGHT_HANDSHAKES
            ));
        }
    }

    /// 记录一次握手失败/超时（逐条 debug 由调用方打，这里只做节流汇总 warn）。
    pub fn record_failure(&self, tag: &str, err: &dyn Display) {
        let n = self.failed.fetch_add(1, Ordering::Relaxed) + 1;
        if n % LOG_EVERY == 0 {
            crate::LOG
                .warn(format!("tag={tag} handshake_gate: 累计握手失败 {n} 次（最近一次：{err}）"));
        }
    }
}

/// 首字节窗：`peek` 读首字节但**不消费**（后续 PROXY 头 / TLS ClientHello / HTTP
/// GET 仍从第 1 字节读起）。
///
/// 返回 `Err(TimedOut)` = 连了不发数据（探测/半开）；`Err(UnexpectedEof)` = 建连即断。
pub async fn wait_first_byte(stream: &mut TcpStream, within: Duration) -> io::Result<()> {
    let mut byte = [0u8; 1];
    match tokio::time::timeout(within, stream.peek(&mut byte)).await {
        Ok(Ok(0)) => {
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed before first byte"))
        },
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "first byte timeout")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn try_admit_is_fail_fast_at_limit() {
        let gate = HandshakeGate::new(2);
        let a = gate.try_admit().expect("1st permit");
        let b = gate.try_admit().expect("2nd permit");
        assert!(gate.try_admit().is_none(), "满额必须立即 None（不排队）");
        drop(a);
        assert!(gate.try_admit().is_some(), "释放后立即复用");
        drop(b);
    }

    #[tokio::test]
    async fn wait_first_byte_times_out_when_peer_sends_nothing() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = tokio::spawn(async move { TcpStream::connect(addr).await });
        let (mut server, _) = listener.accept().await.expect("accept");
        let _client = client.await.expect("join").expect("connect");
        let err = wait_first_byte(&mut server, Duration::from_millis(100))
            .await
            .expect_err("沉默对端必须超时");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn wait_first_byte_does_not_consume_the_byte() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt as _;
            let mut s = TcpStream::connect(addr).await.expect("connect");
            s.write_all(b"P").await.expect("write");
            s
        });
        let (mut server, _) = listener.accept().await.expect("accept");
        let _client = client.await.expect("join");
        wait_first_byte(&mut server, Duration::from_secs(2)).await.expect("first byte in time");
        // peek 不消费：后续读仍从 'P' 起（PROXY 头/TLS 首字节语义不被破坏）。
        let mut buf = [0u8; 1];
        use tokio::io::AsyncReadExt as _;
        server.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"P");
    }
}

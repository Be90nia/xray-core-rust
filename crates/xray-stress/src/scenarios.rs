//! 场景实现：S1 短连接风暴 / S2 长连接大流量 / S4 混合（mKCP + UDP 路径）。
//!
//! 全部经 SOCKS5 inbound → 协议链（REALITY / mKCP）→ freedom → echo 的完整
//! 生产 dispatch 路径（start_full 双实例），拓扑见 topology.rs。

use std::time::{Duration, Instant};

use crate::{report::StatsHandle, topology::socks_roundtrip};

/// S1：短连接风暴。`concurrency` 个 worker 持续建连 → 小 roundtrip → 断开。
/// 目标：连接生命周期内存回环。
///
/// `delay_ms` 节流建连率：Windows 动态端口 ~16K + TIME_WAIT 240s ≈ 68 conn/s
/// 预算，8 并发 × 150ms ≈ 50 conn/s 贴预算内；超发只会耗尽端口（10048 洪水）。
pub async fn s1_short_burst(
    socks_port: u16,
    echo_port: u16,
    concurrency: usize,
    deadline: Instant,
    stats: StatsHandle,
    delay_ms: u64,
) {
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..concurrency {
        let stats = stats.clone();
        workers.spawn(async move {
            // 模拟 HTTP GET 尺寸的请求-响应（echo 语义 = roundtrip 校验）
            let payload: &[u8] =
                b"GET / HTTP/1.0\r\nHost: stress.local\r\nUser-Agent: xray-stress\r\n\r\n";
            #[allow(clippy::disallowed_methods, reason = "压测计时循环；Clock 端口注入待 bd 39hko")]
            while Instant::now() < deadline {
                #[allow(
                    clippy::disallowed_methods,
                    reason = "压测计时循环；Clock 端口注入待 bd 39hko"
                )]
                let started = Instant::now();
                match socks_roundtrip(socks_port, echo_port, payload).await {
                    Ok(_) => {
                        stats.record_ok(payload.len() as u64, payload.len() as u64, ms(started));
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    },
                    Err(e) => {
                        stats.record_fail();
                        tracing::debug!("s1 roundtrip failed: {e}");
                        // 失败退避加大：端口耗尽期快速重试只会加剧风暴
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    },
                }
            }
        });
    }
    while workers.join_next().await.is_some() {}
}

/// S2：`n_conns` 条长连接持续泵随机数据（256KB-4MB chunk，echo 回读）。
/// 目标：稳态吞吐衰减曲线。
pub async fn s2_long_flow(
    socks_port: u16,
    echo_port: u16,
    n_conns: usize,
    deadline: Instant,
    stats: StatsHandle,
) {
    let mut workers = tokio::task::JoinSet::new();
    for i in 0..n_conns {
        let stats = stats.clone();
        workers.spawn(async move {
            // 单连接断开（ECONNRESET/服务端回收）只算一次失败：退避后重连，
            // 直到 deadline——原实现失败即 worker 永久退场，剩余时长零负载（审计 F-27）。
            #[allow(clippy::disallowed_methods, reason = "压测计时循环；Clock 端口注入待 bd 39hko")]
            while Instant::now() < deadline {
                match s2_one_connection(socks_port, echo_port, deadline, &stats, i).await {
                    Ok(()) => break,
                    Err(e) => {
                        tracing::debug!("s2 conn {i} reset: {e}");
                        stats.record_fail();
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    },
                }
            }
        });
    }
    while workers.join_next().await.is_some() {}
}

async fn s2_one_connection(
    socks_port: u16,
    echo_port: u16,
    deadline: Instant,
    stats: &StatsHandle,
    seed: usize,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", socks_port)).await?;
    sock.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greet = [0u8; 2];
    sock.read_exact(&mut greet).await?;
    if greet != [0x05, 0x00] {
        return Err(std::io::Error::other("s2 socks greet rejected"));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&echo_port.to_be_bytes());
    sock.write_all(&req).await?;
    let mut cr = [0u8; 10];
    sock.read_exact(&mut cr).await?;
    if cr[1] != 0x00 {
        return Err(std::io::Error::other("s2 socks CONNECT failed"));
    }

    // 每轮重选 chunk 大小（256KB-4MB），确定性伪随机分布（LCG，免 rand 锁竞争）
    let mut lcg = 0x9E37_79B9_7F4A_7C15u64 ^ (seed as u64 + 1);
    let mut chunk = vec![0u8; 4 * 1024 * 1024];
    #[allow(clippy::disallowed_methods, reason = "压测计时循环；Clock 端口注入待 bd 39hko")]
    while Instant::now() < deadline {
        lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let size = 256 * 1024 + (lcg % (4 * 1024 * 1024 - 256 * 1024 + 1)) as usize;
        rand::Rng::fill(&mut rand::rng(), &mut chunk[..size]);
        #[allow(clippy::disallowed_methods, reason = "压测计时循环；Clock 端口注入待 bd 39hko")]
        let started = Instant::now();
        sock.write_all(&chunk[..size]).await?;
        let mut filled = 0;
        while filled < size {
            let n = sock.read(&mut chunk[..size - filled]).await?;
            if n == 0 {
                return Err(std::io::Error::other("s2 echo closed early"));
            }
            filled += n;
        }
        stats.record_ok(size as u64, size as u64, ms(started));
    }
    Ok(())
}

/// S4：混合——mKCP（UDP 路径）短连接风暴 + 少量长连接同链路叠加。
pub async fn s4_mixed(
    kcp_socks_port: u16,
    echo_port: u16,
    short_concurrency: usize,
    long_conns: usize,
    deadline: Instant,
    stats: StatsHandle,
    delay_ms: u64,
) {
    #[allow(
        clippy::disallowed_methods,
        reason = "②豁免（bd kwevg · §3.5.6）：压测：s4 短连接风暴场景任务"
    )]
    let short = tokio::spawn(s1_short_burst(
        kcp_socks_port,
        echo_port,
        short_concurrency,
        deadline,
        stats.clone(),
        delay_ms,
    ));
    #[allow(
        clippy::disallowed_methods,
        reason = "②豁免（bd kwevg · §3.5.6）：压测：s4 长流场景任务"
    )]
    let long = tokio::spawn(s2_long_flow(kcp_socks_port, echo_port, long_conns, deadline, stats));
    let _ = tokio::join!(short, long);
}

/// S16：半开 TLS 握手风暴（审计 R-1 触发形态）：建连 → 只写半个 ClientHello →
/// 立刻断开。服务端读到半条 record 声明（长度 512 / 实收 3 字节）后等剩余字节，
/// 随后见 RST ⇒ 真实半开连接，而不是「写完整再断」的伪形态。
///
/// 资源断言（父任务在风暴期间采样）：fd 相对风暴早段基线的峰值增量超界即
/// `record_violation` ⇒ run 判红。fd 采不到的平台（Windows）跳过该断言。
#[allow(clippy::disallowed_methods, reason = "压测计时循环；Clock 端口注入待 bd 39hko")]
pub async fn halfopen_storm(
    proto_port: u16,
    concurrency: usize,
    deadline: Instant,
    stats: StatsHandle,
) {
    const PARTIAL_HELLO: &[u8] =
        &[0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03];
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..concurrency.max(1) {
        let stats = stats.clone();
        workers.spawn(async move {
            use tokio::io::AsyncWriteExt;
            #[allow(clippy::disallowed_methods, reason = "压测计时循环；Clock 端口注入待 bd 39hko")]
            while Instant::now() < deadline {
                #[allow(
                    clippy::disallowed_methods,
                    reason = "压测计时循环；Clock 端口注入待 bd 39hko"
                )]
                let started = Instant::now();
                match tokio::net::TcpStream::connect(("127.0.0.1", proto_port)).await {
                    Ok(mut sock) => {
                        // 写失败（对端已 RST）也是有效风暴轮次，不计失败
                        let _ = sock.write_all(PARTIAL_HELLO).await;
                        stats.record_ok(PARTIAL_HELLO.len() as u64, 0, ms(started));
                        drop(sock);
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    },
                    Err(e) => {
                        stats.record_fail();
                        tracing::debug!("s16 half-open connect failed: {e}");
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    },
                }
            }
        });
    }

    let mut fd_samples: Vec<usize> = Vec::new();
    #[allow(clippy::disallowed_methods, reason = "压测计时循环；Clock 端口注入待 bd 39hko")]
    while Instant::now() < deadline {
        if let Some(fd) = crate::topology::process_fd_count() {
            fd_samples.push(fd);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    while workers.join_next().await.is_some() {}
    if let Some(fd) = crate::topology::process_fd_count() {
        fd_samples.push(fd);
    }
    let bound = fd_growth_bound(concurrency);
    if fd_growth_exceeded(&fd_samples, bound) {
        tracing::error!(
            "s16 half-open storm fd growth exceeded: samples={fd_samples:?} bound=+{bound}"
        );
        stats.record_violation();
    }
}

/// 半开风暴 fd 增长上限：幂等连接占 1 fd/轮 + 对端半开态占 1 fd/轮，
/// 留 8× 余量后加 1024 绝对余量（其他场景的稳态 fd 波动不计入增长）。
fn fd_growth_bound(concurrency: usize) -> usize {
    concurrency.max(1) * 8 + 1024
}

/// fd 增长判据：早段（前 1/3）峰值 → 全局峰值 的增量是否超界。
/// 用「增量」不用绝对值：harness 进程同时承载其他场景，绝对值无意义。
fn fd_growth_exceeded(samples: &[usize], bound: usize) -> bool {
    if samples.len() < 3 {
        return false;
    }
    let early = samples[..(samples.len() / 3).max(1)].iter().copied().max().unwrap_or(0);
    let peak = samples.iter().copied().max().unwrap_or(0);
    peak.saturating_sub(early) > bound
}

/// S17：慢读背压（审计 R-9）：客户端持续 64KiB 写入、每 20ms 只读 1KiB。
///
/// echo 回写不出去 → 连接级发送缓冲填满 → 跨连接瞬态上界必须挡住内存膨胀。
/// 资源断言：RSS 相对早段基线的峰值增量超界即 `record_violation`。
#[allow(clippy::disallowed_methods, reason = "压测计时循环；Clock 端口注入待 bd 39hko")]
pub async fn slow_reader(
    socks_port: u16,
    echo_port: u16,
    n_conns: usize,
    deadline: Instant,
    stats: StatsHandle,
) {
    let end = tokio::time::Instant::from_std(deadline);
    let mut workers = tokio::task::JoinSet::new();
    for idx in 0..n_conns.max(1) {
        let stats = stats.clone();
        workers.spawn(async move {
            #[allow(clippy::disallowed_methods, reason = "压测计时循环；Clock 端口注入待 bd 39hko")]
            while Instant::now() < deadline {
                match tokio::time::timeout_at(
                    end,
                    slow_reader_conn(socks_port, echo_port, deadline, &stats),
                )
                .await
                {
                    Ok(Ok(())) => break,
                    Ok(Err(e)) => {
                        tracing::debug!("s17 conn {idx} reset: {e}");
                        stats.record_fail();
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    },
                    // deadline 到点：在途写被取消属正常收工
                    Err(_) => break,
                }
            }
        });
    }

    let mut rss_samples: Vec<f64> = Vec::new();
    #[allow(clippy::disallowed_methods, reason = "压测计时循环；Clock 端口注入待 bd 39hko")]
    while Instant::now() < deadline {
        rss_samples.push(crate::topology::process_rss_mb());
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    while workers.join_next().await.is_some() {}
    if rss_growth_exceeded(&rss_samples, SLOW_READ_RSS_BOUND_MB) {
        tracing::error!(
            "s17 slow-reader RSS growth exceeded {SLOW_READ_RSS_BOUND_MB}MB: samples={rss_samples:?}"
        );
        stats.record_violation();
    }
}

/// 慢读 RSS 增量上限：跨连接瞬态上界（在途预算 128MiB + 每连接发送缓冲）之上留量。
const SLOW_READ_RSS_BOUND_MB: f64 = 1024.0;

/// RSS 增长判据：早段（前 1/3）峰值 → 全局峰值 的增量是否超界（与 fd 同口径）。
fn rss_growth_exceeded(samples: &[f64], bound_mb: f64) -> bool {
    if samples.len() < 3 {
        return false;
    }
    let early = samples[..(samples.len() / 3).max(1)].iter().copied().fold(f64::MIN, f64::max);
    let peak = samples.iter().copied().fold(f64::MIN, f64::max);
    peak - early > bound_mb
}

async fn slow_reader_conn(
    socks_port: u16,
    echo_port: u16,
    deadline: Instant,
    stats: &StatsHandle,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let sock = tokio::net::TcpStream::connect(("127.0.0.1", socks_port)).await?;
    // TCP_NODELAY：慢读端的背压必须落在应用层缓冲，而不是被 Nagle 掩盖
    sock.set_nodelay(true)?;
    let mut sock = sock;
    sock.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greet = [0u8; 2];
    sock.read_exact(&mut greet).await?;
    if greet != [0x05, 0x00] {
        return Err(std::io::Error::other("s17 socks greet rejected"));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&echo_port.to_be_bytes());
    sock.write_all(&req).await?;
    let mut cr = [0u8; 10];
    sock.read_exact(&mut cr).await?;
    if cr[1] != 0x00 {
        return Err(std::io::Error::other("s17 socks CONNECT failed"));
    }

    let (mut rd, mut wr) = sock.into_split();
    let mut chunk = vec![0u8; 64 * 1024];
    // 每连接固定填充（避免 rand 抢锁成为背压测试的瓶颈）
    rand::Rng::fill(&mut rand::rng(), &mut chunk[..]);

    let writer = async {
        #[allow(clippy::disallowed_methods, reason = "压测计时循环；Clock 端口注入待 bd 39hko")]
        while Instant::now() < deadline {
            #[allow(clippy::disallowed_methods, reason = "压测计时循环；Clock 端口注入待 bd 39hko")]
            let started = Instant::now();
            // 写阻塞本身就是背压生效的证据（发送缓冲 + 对端接收窗填满）
            wr.write_all(&chunk).await?;
            stats.record_ok(chunk.len() as u64, 0, ms(started));
        }
        Ok::<(), std::io::Error>(())
    };
    let reader = async {
        let mut small = vec![0u8; 1024];
        #[allow(clippy::disallowed_methods, reason = "压测计时循环；Clock 端口注入待 bd 39hko")]
        while Instant::now() < deadline {
            let n = rd.read(&mut small).await?;
            if n == 0 {
                return Err(std::io::Error::other("s17 echo closed early"));
            }
            // 1KiB / 20ms = 50 KiB/s：远低于写入速率 ⇒ 对端发送缓冲必然积压
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<(), std::io::Error>(())
    };
    let (w, r) = tokio::join!(writer, reader);
    w?;
    r?;
    Ok(())
}

/// S18：UDP 数据面短风暴（socks udp associate → vless udp → freedom UDP → echo）。
#[allow(clippy::disallowed_methods, reason = "压测计时循环；Clock 端口注入待 bd 39hko")]
pub async fn udp_short_burst(
    socks_port: u16,
    echo_udp_port: u16,
    concurrency: usize,
    deadline: Instant,
    stats: StatsHandle,
    delay_ms: u64,
) {
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..concurrency.max(1) {
        let stats = stats.clone();
        workers.spawn(async move {
            let payload = b"xray-stress-udp-ping";
            #[allow(clippy::disallowed_methods, reason = "压测计时循环；Clock 端口注入待 bd 39hko")]
            while Instant::now() < deadline {
                #[allow(
                    clippy::disallowed_methods,
                    reason = "压测计时循环；Clock 端口注入待 bd 39hko"
                )]
                let started = Instant::now();
                match crate::topology::socks_udp_roundtrip(socks_port, echo_udp_port, payload).await
                {
                    Ok(n) => {
                        stats.record_ok(n as u64, n as u64, ms(started));
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    },
                    Err(e) => {
                        stats.record_fail();
                        tracing::debug!("s18 udp roundtrip failed: {e}");
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    },
                }
            }
        });
    }
    while workers.join_next().await.is_some() {}
}

fn ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    /// 假 SOCKS5 服务端：greet/CONNECT 应答后回显 `budget` 字节即关连接
    /// （模拟「负载期间断开一条连接」），并计数 accept 次数。
    /// 单 worker 串行处理即可——持久的只有一条被测连接。
    async fn fake_socks(budget: usize) -> (u16, Arc<AtomicUsize>, tokio::task::JoinSet<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let counter = accepts.clone();
        let mut set = tokio::task::JoinSet::new();
        set.spawn(async move {
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { return };
                counter.fetch_add(1, Ordering::Relaxed);
                if sock.read_exact(&mut [0u8; 3]).await.is_err() {
                    continue;
                }
                if sock.write_all(&[0x05, 0x00]).await.is_err() {
                    continue;
                }
                if sock.read_exact(&mut [0u8; 10]).await.is_err() {
                    continue;
                }
                if sock.write_all(&[0x05, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await.is_err() {
                    continue;
                }
                let mut echoed = 0;
                while echoed < budget {
                    let n = match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    echoed += n;
                }
                // 预算用完即关连接：客户端的下一次读写报错 → 触发重连路径
            }
        });
        (port, accepts, set)
    }

    #[tokio::test]
    async fn s2_worker_reconnects_after_connection_drop() {
        // budget = 单个 chunk 上限（4MB）：保证每条连接至少完成一次 roundtrip，
        // 之后服务端关连接，逼出「断连 → record_fail → 重连 → 继续 conn_ok」。
        let (port, accepts, mut server) = fake_socks(4 * 1024 * 1024).await;
        let stats = StatsHandle::new("s2-long");
        #[allow(clippy::disallowed_methods, reason = "测试计时锚点（压测场景语义按 Instant 截止）")]
        let deadline = Instant::now() + Duration::from_secs(3);
        // 挂死即失败：被测实现若在 30s 内不收工，测试必须红而不是卡住进程
        tokio::time::timeout(
            Duration::from_secs(30),
            s2_long_flow(port, 1, 1, deadline, stats.clone()),
        )
        .await
        .expect("s2_long_flow 未在 deadline 后收工");
        server.abort_all();

        let snap = stats.snapshot();
        let n_accept = accepts.load(Ordering::Relaxed);
        assert!(snap.conn_fail >= 1, "断连必须记一次失败: fail={}", snap.conn_fail);
        assert!(n_accept >= 2, "断连后必须重连（第二/第三次 accept）: accepts={n_accept}");
        assert!(snap.conn_ok >= 2, "重连后必须继续产生成功计数: ok={}", snap.conn_ok);
    }

    /// s16 判据可证伪：稳定 fd 序列不报违规；线性增长（半开连接不回收）必须报。
    #[test]
    fn fd_growth_assertion_catches_leak() {
        let bound = fd_growth_bound(8);
        assert_eq!(bound, 8 * 8 + 1024);
        // 稳态（含其他场景带来的正常波动）
        assert!(!fd_growth_exceeded(&[100, 120, 110, 130, 125], bound));
        // 泄漏：每采样点 +200 fd（半开连接不回收），峰值远超 bound
        let leak: Vec<usize> = (0..40).map(|i| 100 + i * 200).collect();
        assert!(fd_growth_exceeded(&leak, bound), "半开连接不回收必须判违规");
        // 样本不足不下结论（不误伤短 run）
        assert!(!fd_growth_exceeded(&[100, 9999], bound));
    }

    /// s17 判据可证伪：稳态 RSS 不报违规；背压上界失效（RSS 线性膨胀）必须报。
    #[test]
    fn rss_growth_assertion_catches_bloat() {
        assert!(!rss_growth_exceeded(&[200.0, 220.0, 240.0, 230.0], SLOW_READ_RSS_BOUND_MB));
        let bloat: Vec<f64> = (0..20).map(|i| 200.0 + i as f64 * 300.0).collect();
        assert!(rss_growth_exceeded(&bloat, SLOW_READ_RSS_BOUND_MB), "RSS 线性膨胀必须判违规");
        assert!(!rss_growth_exceeded(&[200.0, 9000.0], SLOW_READ_RSS_BOUND_MB));
    }

    /// 资源违规必须能落到 StatsHandle（run 结束据此判红）。
    #[test]
    fn violation_counter_is_visible_in_snapshot() {
        let h = StatsHandle::new("s16-halfopen");
        assert_eq!(h.snapshot().resource_violations, 0);
        h.record_violation();
        h.record_violation();
        assert_eq!(h.snapshot().resource_violations, 2);
    }
}

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
///
/// issue #9 修复：连接级全双工泵（见 `s2_one_connection`）；connect 与全部
/// IO 步受 deadline 上界（s2_bounded）⇒ 到点必收工；断连按剩余时间退避重连
/// （退避 = min(500ms, remaining)，不越过 deadline）。
pub async fn s2_long_flow(
    socks_port: u16,
    echo_port: u16,
    n_conns: usize,
    deadline: Instant,
    stats: StatsHandle,
) {
    let tdl = tokio::time::Instant::from_std(deadline);
    let mut workers = tokio::task::JoinSet::new();
    for i in 0..n_conns {
        let stats = stats.clone();
        workers.spawn(async move {
            // 单连接断开（ECONNRESET/服务端回收）只算一次失败：退避后重连，
            // 直到 deadline——原实现失败即 worker 永久退场，剩余时长零负载（审计 F-27）。
            #[allow(clippy::disallowed_methods, reason = "压测计时循环；Clock 端口注入待 bd 39hko")]
            while Instant::now() < deadline {
                let opened =
                    s2_bounded(tdl, tokio::net::TcpStream::connect(("127.0.0.1", socks_port)))
                        .await;
                let res = match opened {
                    Ok(sock) => s2_one_connection(sock, echo_port, deadline, &stats, i).await,
                    Err(e) => Err(e),
                };
                match res {
                    Ok(()) => break,
                    Err(e) => {
                        #[allow(
                            clippy::disallowed_methods,
                            reason = "压测计时循环；Clock 端口注入待 bd 39hko"
                        )]
                        let now = Instant::now();
                        if now >= deadline {
                            // deadline 收口的 Err 是正常收工：不计 fail、不退避
                            break;
                        }
                        stats.record_fail();
                        tracing::debug!("s2 conn {i} reset: {e}");
                        // 退避裁剪到剩余时间，不越过 deadline 拖住整体收工（issue #9）
                        tokio::time::sleep(Duration::from_millis(500).min(deadline - now)).await;
                    },
                }
            }
        });
    }
    while workers.join_next().await.is_some() {}
}

/// deadline 上界内的单个 IO 步：到点未完成即 TimedOut（worker 按剩余时间决定
/// 重连或收工）。connect/握手/写/读全部经此受约束——「单步卡死拖住整体收工」
/// （issue #9 失败签名 `未在 deadline 后收工: Elapsed(())`）从根上排除。
async fn s2_bounded<T>(
    deadline: tokio::time::Instant,
    fut: impl Future<Output = std::io::Result<T>>,
) -> std::io::Result<T> {
    match tokio::time::timeout_at(deadline, fut).await {
        Ok(res) => res,
        Err(_) => {
            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "s2 IO step exceeded deadline"))
        },
    }
}

/// SOCKS5 greet + CONNECT（字节序与原实现一致）。泛型承载 TcpStream 与测试面
/// duplex 流（同一泵体复用，回归判据不绕真实实现）。
async fn s2_socks_handshake<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    sock: &mut S,
    echo_port: u16,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    Ok(())
}

/// 单连接全双工泵（issue #9 修复）：写半连续产帧、读半并发排空回显。
/// 旧 sequential 泵（write_all 整块完成才读）在小 socket 缓冲平台（macOS CI
/// 实锤 3 次）与 echo 服务端四缓冲互锁：写半卡死 ⇒ deadline 永不触发 ⇒
/// worker 挂死（失败签名 `未在 deadline 后收工: Elapsed(())`）。
/// 帧大小（256KB-4MB LCG，分布不变）经有界 mpsc 通道交接；所有 await 受
/// deadline 约束；任一半失败 ⇒ abort 另一半，Err 交 worker 按剩余时间重连。
async fn s2_one_connection<S>(
    sock: S,
    echo_port: u16,
    deadline: Instant,
    stats: &StatsHandle,
    seed: usize,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let tdl = tokio::time::Instant::from_std(deadline);
    let mut sock = sock;
    s2_bounded(tdl, s2_socks_handshake(&mut sock, echo_port)).await?;

    let (mut rd, mut wr) = tokio::io::split(sock);
    // 帧交接通道：容量 2 = 写半最多领先读半 2 帧（≤8MB 在途，内存有界，不缓冲整条流）
    let (frame_tx, mut frame_rx) = tokio::sync::mpsc::channel::<(usize, Instant)>(2);

    // 写半：先交帧元组（size + 出发时刻）再写字节 ⇒ 读半只追已完整写出的帧；
    // echo 保字节计数 ⇒ 读半按交接 size 精确读满一帧，不依赖 TCP read/write 边界
    #[allow(
        clippy::disallowed_methods,
        reason = "②豁免（§3.5.6）：压测 s2 泵写半任务，寿命=单次连接尝试，JoinHandle abort 取消"
    )]
    let mut writer = tokio::spawn(async move {
        let mut lcg = 0x9E37_79B9_7F4A_7C15u64 ^ (seed as u64 + 1);
        let mut chunk = vec![0u8; 4 * 1024 * 1024];
        #[allow(clippy::disallowed_methods, reason = "压测计时循环；Clock 端口注入待 bd 39hko")]
        while Instant::now() < deadline {
            lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let size = 256 * 1024 + (lcg % (4 * 1024 * 1024 - 256 * 1024 + 1)) as usize;
            rand::Rng::fill(&mut rand::rng(), &mut chunk[..size]);
            #[allow(clippy::disallowed_methods, reason = "压测计时循环；Clock 端口注入待 bd 39hko")]
            let started = Instant::now();
            let announce = async {
                frame_tx
                    .send((size, started))
                    .await
                    .map_err(|_| std::io::Error::other("s2 frame channel closed"))?;
                wr.write_all(&chunk[..size]).await
            };
            s2_bounded(tdl, announce).await?;
        }
        Ok::<(), std::io::Error>(())
    });

    // 读半：并发排空回显——旧 sequential 泵的死锁面（写半阻塞时无人读）在此消除
    let reader_stats = stats.clone();
    #[allow(
        clippy::disallowed_methods,
        reason = "②豁免（§3.5.6）：压测 s2 泵读半任务，寿命=单次连接尝试，JoinHandle abort 取消"
    )]
    let mut reader = tokio::spawn(async move {
        let mut scratch = vec![0u8; 4 * 1024 * 1024];
        loop {
            let next = tokio::time::timeout_at(tdl, frame_rx.recv()).await;
            let (size, started) = match next {
                Ok(Some(frame)) => frame,
                Ok(None) => return Ok::<(), std::io::Error>(()), // 写半已收工且无剩余帧
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "s2 reader exceeded deadline",
                    ));
                },
            };
            let mut got = 0usize;
            while got < size {
                let n = s2_bounded(tdl, rd.read(&mut scratch[..size - got])).await?;
                if n == 0 {
                    return Err(std::io::Error::other("s2 echo closed early"));
                }
                got += n;
            }
            reader_stats.record_ok(size as u64, size as u64, ms(started));
        }
    });

    // 任一半先收工即决策：失败 ⇒ 取消另一半并干净 join（被取消半的 JoinError
    // 预期内，无信息量，收割丢弃）；正常 ⇒ 收割另一半定成败。两半所有 await 受
    // deadline 上界 ⇒ 收割不会挂死。
    let outcome;
    tokio::select! {
        w = &mut writer => {
            outcome = match s2_join_result(w, "writer") {
                Err(e) => {
                    reader.abort();
                    let _ = reader.await;
                    Err(e)
                },
                Ok(()) => s2_join_result(reader.await, "reader"),
            };
        },
        r = &mut reader => {
            outcome = match s2_join_result(r, "reader") {
                Err(e) => {
                    writer.abort();
                    let _ = writer.await;
                    Err(e)
                },
                // 读半 Ok 先出 ⇒ 通道唯一 sender（写半）已终 ⇒ 收割写半定成败
                Ok(()) => s2_join_result(writer.await, "writer"),
            };
        },
    }
    outcome
}

/// JoinHandle 结果扁平化：task panic/取消也归一为 io::Error（不静默吞掉）。
fn s2_join_result(
    res: Result<std::io::Result<()>, tokio::task::JoinError>,
    half: &str,
) -> std::io::Result<()> {
    res.map_err(|e| std::io::Error::other(format!("s2 {half} task: {e}"))).and_then(|r| r)
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
    /// `small_buf` = Some(kb) 时对每条 accept 的连接设 SO_SNDBUF/SO_RCVBUF（issue #9
    /// 回归：手动 setsockopt 同时关闭 Linux autotune ⇒ 互锁链各环节容量确定有界，
    /// 判据跨平台成立）。
    /// 单 worker 串行处理即可——持久的只有一条被测连接。
    async fn fake_socks(
        budget: usize,
        small_buf: Option<usize>,
    ) -> (u16, Arc<AtomicUsize>, tokio::task::JoinSet<()>) {
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
                if let Some(kb) = small_buf {
                    // 双端小缓冲（issue #9 回归）：per-conn 手动 setsockopt 同时关闭
                    // Linux autotune ⇒ 互锁链容量确定有界（tokio TcpStream 无
                    // buffer setter，走 socket2 转换；Windows 环回不受内核缓冲
                    // 约束，确定性互锁判据由测试面 duplex 瘦管承担）
                    let Ok(std_sock) = sock.into_std() else { continue };
                    let s2 = socket2::Socket::from(std_sock);
                    if s2.set_recv_buffer_size(kb * 1024).is_err()
                        || s2.set_send_buffer_size(kb * 1024).is_err()
                        || s2.set_nonblocking(true).is_err()
                    {
                        continue;
                    }
                    let Ok(converted) = tokio::net::TcpStream::from_std(s2.into()) else {
                        continue;
                    };
                    sock = converted;
                }
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
        // 时间账本（两个值分开记录）：内部 deadline 3s（s2_long_flow 收工上界）
        // vs 外层看门狗 30s（只防测试挂死，判据不依赖它）。
        let (port, accepts, mut server) = fake_socks(4 * 1024 * 1024, None).await;
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

    /// 小缓冲拨号（issue #9 回归）：connect 前设 SO_SNDBUF/SO_RCVBUF——tokio
    /// TcpSocket 是 socket2 同源能力（免新增依赖），出生窗即小。
    async fn small_buf_connect(
        socks_port: u16,
        buf_kb: u32,
    ) -> std::io::Result<tokio::net::TcpStream> {
        let sock = tokio::net::TcpSocket::new_v4()?;
        sock.set_send_buffer_size(buf_kb * 1024)?;
        sock.set_recv_buffer_size(buf_kb * 1024)?;
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], socks_port));
        sock.connect(addr).await
    }

    /// 旧 sequential 泵的对照复刻（issue #9 缺陷本体，仅测试代码）：
    /// write_all 整块完成后才读回显——瘦管 + 大 chunk 与 echo 服务端互锁。
    async fn old_sequential_pump<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        mut sock: S,
        echo_port: u16,
    ) -> std::io::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
        // 单轮 4MB 即足以判互锁：卡点在首个 chunk 的 write_all 内
        let mut chunk = vec![0u8; 4 * 1024 * 1024];
        sock.write_all(&chunk).await?;
        let mut filled = 0;
        while filled < chunk.len() {
            let n = sock.read(&mut chunk[filled..]).await?;
            if n == 0 {
                return Err(std::io::Error::other("s2 echo closed early"));
            }
            filled += n;
        }
        Ok(())
    }

    /// duplex 侧假 SOCKS5 回显服务（greet/CONNECT 应答后逐段回显）。
    /// `tokio::io::duplex(64KB)` = 用户态强制的瘦管：客户端不读时服务端回显
    /// 写满对向 64KB ⇒ write_all 挂死 ⇒ 服务端停读 ⇒ 客户端 write_all 挂死。
    /// 用户态容量界不依赖内核缓冲语义——Windows 环回实测不受 SO_SNDBUF/SO_RCVBUF
    /// 约束（2026-11-18 探针：4MB 双向 0.01s 推完），故互锁判据以 duplex 承载，
    /// TCP 小缓冲腿保留真实传输面（macOS/Linux 忠实条件）。
    async fn duplex_socks_echo(sock: tokio::io::DuplexStream) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut rd, mut wr) = tokio::io::split(sock);
        let mut greet = [0u8; 3];
        if rd.read_exact(&mut greet).await.is_err() {
            return;
        }
        if wr.write_all(&[0x05, 0x00]).await.is_err() {
            return;
        }
        let mut req = [0u8; 10];
        if rd.read_exact(&mut req).await.is_err() {
            return;
        }
        if wr.write_all(&[0x05, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await.is_err() {
            return;
        }
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if wr.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                },
            }
        }
    }

    /// 确定性回归（issue #9）：瘦管（64KB）+ 4MB chunk 下，旧 sequential 泵必须
    /// 互锁死锁，生产全双工泵必须推进数据——同轮对比（同 chunk 量级、同管容量）。
    ///
    /// 时间账本（三个值分开记录，判据不依赖看门狗）：
    /// - 对照泵判死超时 = 3s（卡点在首个 write_all，无进展可能，任何时窗等价）
    /// - 生产泵内部 deadline = 5s（s2_one_connection 收工上界，到点自然收口）
    /// - 外层看门狗 = 60s（仅防测试挂死）
    #[tokio::test]
    async fn s2_small_buffers_old_pump_interlocks_new_pump_progresses() {
        // ── 腿 1：对照——旧 sequential 泵在 duplex 瘦管下必须死锁（判死超时 3s）
        let (client, server) = tokio::io::duplex(64 * 1024);
        #[allow(
            clippy::disallowed_methods,
            reason = "②豁免（§3.5.6）：回归测试腿内 echo 服务任务，寿命=本测试，运行时结束随测收尾"
        )]
        tokio::spawn(duplex_socks_echo(server));
        let verdict =
            tokio::time::timeout(Duration::from_secs(3), old_sequential_pump(client, 1)).await;
        assert!(
            verdict.is_err(),
            "旧 sequential 泵必须在瘦管 + 4MB chunk 下互锁死锁（提前返回 = 判据失效）"
        );

        // ── 腿 2：生产泵——同一瘦管容量、同 chunk 量级，必须并发推进并收工
        let (client, server) = tokio::io::duplex(64 * 1024);
        #[allow(
            clippy::disallowed_methods,
            reason = "②豁免（§3.5.6）：回归测试腿内 echo 服务任务，寿命=本测试，运行时结束随测收尾"
        )]
        tokio::spawn(duplex_socks_echo(server));
        let stats = StatsHandle::new("s2-regression-duplex");
        #[allow(clippy::disallowed_methods, reason = "测试计时锚点（压测场景语义按 Instant 截止）")]
        let deadline = Instant::now() + Duration::from_secs(5);
        // 到 deadline 的自然收口（Ok=尾帧恰在前完成 / Err=TimedOut）都算正常收工
        let _pump = tokio::time::timeout(
            Duration::from_secs(60),
            s2_one_connection(client, 1, deadline, &stats, 7),
        )
        .await
        .expect("生产泵未在 60s 看门狗内收工（挂死 = 回归）");
        let snap = stats.snapshot();
        assert!(snap.conn_ok >= 1, "生产泵必须完成至少一帧往返: ok={}", snap.conn_ok);

        // ── 腿 3：真实 TCP + 双端小缓冲（socket2 机制；macOS/Linux 为忠实判据面）
        let (port, accepts, mut server) = fake_socks(usize::MAX, Some(64)).await;
        let tcp_sock = small_buf_connect(port, 64).await.expect("tcp dial");
        let tcp_stats = StatsHandle::new("s2-regression-tcp");
        #[allow(clippy::disallowed_methods, reason = "测试计时锚点（压测场景语义按 Instant 截止）")]
        let deadline = Instant::now() + Duration::from_secs(5);
        let _pump = tokio::time::timeout(
            Duration::from_secs(60),
            s2_one_connection(tcp_sock, 1, deadline, &tcp_stats, 7),
        )
        .await
        .expect("TCP 腿未在 60s 看门狗内收工（挂死 = 回归）");
        server.abort_all();
        assert!(
            tcp_stats.snapshot().conn_ok >= 1,
            "TCP 腿必须完成至少一帧往返: ok={}",
            tcp_stats.snapshot().conn_ok
        );
        // 单连接收工（服务端未关连接 ⇒ 不应重连）
        let n_accept = accepts.load(Ordering::Relaxed);
        assert_eq!(n_accept, 1, "TCP 腿必须单连接收工: accepts={n_accept}");
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

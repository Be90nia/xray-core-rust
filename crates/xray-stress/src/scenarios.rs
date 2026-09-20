//! 场景实现：S1 短连接风暴 / S2 长连接大流量 / S4 混合（mKCP + UDP 路径）。
//!
//! 全部经 SOCKS5 inbound → 协议链（REALITY / mKCP）→ freedom → echo 的完整
//! 生产 dispatch 路径（start_full 双实例），拓扑见 topology.rs。

use std::time::{Duration, Instant};

use crate::report::StatsHandle;
use crate::topology::socks_roundtrip;

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
            while Instant::now() < deadline {
                let started = Instant::now();
                match socks_roundtrip(socks_port, echo_port, payload).await {
                    Ok(_) => {
                        stats.record_ok(
                            payload.len() as u64,
                            payload.len() as u64,
                            ms(started),
                        );
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
            if let Err(e) = s2_one_connection(socks_port, echo_port, deadline, &stats, i).await {
                tracing::debug!("s2 conn {i} ended: {e}");
                stats.record_fail();
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
    while Instant::now() < deadline {
        lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let size = 256 * 1024 + (lcg % (4 * 1024 * 1024 - 256 * 1024 + 1)) as usize;
        rand::Rng::fill(&mut rand::rng(), &mut chunk[..size]);
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
    let short = tokio::spawn(s1_short_burst(
        kcp_socks_port,
        echo_port,
        short_concurrency,
        deadline,
        stats.clone(),
        delay_ms,
    ));
    let long = tokio::spawn(s2_long_flow(
        kcp_socks_port,
        echo_port,
        long_conns,
        deadline,
        stats,
    ));
    let _ = tokio::join!(short, long);
}

fn ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

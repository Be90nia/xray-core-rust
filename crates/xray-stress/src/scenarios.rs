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
}

//! # Happy Eyeballs 双栈拨号
//!
//! RFC 8305——IPv4/IPv6 并发拨号竞争，先连上的赢。对应 Go
//! `transport/internet/happy_eyeballs.go`（`TcpRaceDial`）。
//!
//! ## Go 语义（接入条件见 `system_dialer::dial_system`）
//!
//! - `sort_ips`：v4/v6 按 `interleave`（同族连续 N 个再切换）交错排序， 优先族先行（Go
//!   `sortIPs`，happy_eyeballs.go:101-157）
//! - 第一个地址立即启动，后续每 `try_delay_ms` 启动一个，最多 `max_concurrent_try`
//!   个并发；某次尝试失败后立即补充下一个 （Go happy_eyeballs.go:71-73 `timer.Reset(0)`）
//! - 首个成功的连接胜出；后到的成功连接直接关闭
//! - 每次尝试走完整 [`SystemDialer::dial`]（保留 sockopt / src 绑定， Go `tcpTryDial`
//!   happy_eyeballs.go:159-176）

use std::{
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use tokio::{
    task::JoinSet,
    time::{Instant, Sleep},
};
use xray_common::net::{address::Address, destination::Destination, port::Port};

use crate::{
    connection::Connection,
    sockopt::{HappyEyeballsConfig, SocketOptions},
    system_dialer::SystemDialer,
};

/// Happy Eyeballs 竞争拨号（Go `TcpRaceDial`）。
///
/// `ips` 为 DNS 解析出的全部地址（≥2 个才有竞争意义，调用方保证）。
/// 每次尝试经 `dialer` 走完整系统拨号路径（sockopt / src 均生效）。
pub async fn tcp_race_dial(
    dialer: Arc<dyn SystemDialer>,
    src: Option<SocketAddr>,
    ips: &[IpAddr],
    port: Port,
    sockopt: &SocketOptions,
    cfg: &HappyEyeballsConfig,
) -> io::Result<Box<dyn Connection>> {
    let sorted = sort_ips(ips, cfg.prioritize_ipv6, cfg.interleave);
    tracing::debug!(domain_ips = ?sorted, "happy eyeballs racing dial");
    let addrs: Vec<SocketAddr> =
        sorted.iter().map(|ip| SocketAddr::new(*ip, port.value())).collect();
    let sockopt = sockopt.clone();
    race_dial(
        &addrs,
        Duration::from_millis(cfg.try_delay_ms),
        cfg.max_concurrent_try as usize,
        move |idx| {
            let dialer = Arc::clone(&dialer);
            let sockopt = sockopt.clone();
            // Go tcpTryDial：对单个 IP 构造 Destination 走 effectiveSystemDialer.Dial。
            let dest = Destination::tcp(Address::from(sorted[idx]), port);
            async move { dialer.dial(src, &dest, &sockopt).await }
        },
    )
    .await
}

/// 按地址交错列表竞争拨号：先成功的 wins。
///
/// - 第 0 个立即启动；之后每 `try_delay` 启动一个，直到耗尽或达到 `max_concurrent` 个在飞
/// - 失败立即补充下一个（对齐 Go `timer.Reset(0)`）
/// - winner 出现即 abort 全部在飞尝试（对齐 Go happy_eyeballs.go:56 `cancel()`）， 后到的成功连接随
///   task abort 直接关闭
///
/// `make_attempt(idx)` 返回第 `idx` 个地址的拨号 future（被 spawn，需 `'static`）。
async fn race_dial<T, F, Fut>(
    addrs: &[SocketAddr],
    try_delay: Duration,
    max_concurrent: usize,
    make_attempt: F,
) -> io::Result<T>
where
    T: Send + 'static,
    F: Fn(usize) -> Fut + Send + Sync + Clone + 'static,
    Fut: Future<Output = io::Result<T>> + Send + 'static,
{
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "happy eyeballs: no address to dial",
        ));
    }
    let max_c = max_concurrent.clamp(1, addrs.len());
    let mut inflight: JoinSet<(usize, io::Result<T>)> = JoinSet::new();
    let mut next = 0usize;
    let mut active = 0usize;
    let mut winner: Option<T> = None;
    let mut last_err: Option<io::Error> = None;
    // Go timer.NewTimer(0)：第 0 个地址立即启动。
    let mut timer: Pin<Box<Sleep>> = Box::pin(tokio::time::sleep(Duration::ZERO));

    loop {
        tokio::select! {
            biased;
            r = inflight.join_next(), if active > 0 => {
                match r {
                    Some(Ok((idx, Ok(v)))) => {
                        active -= 1;
                        if winner.is_none() {
                            tracing::debug!(index = idx, addr = %addrs[idx], "happy eyeballs: connection established");
                            winner = Some(v);
                            // 对齐 Go cancel()：立即中止其余在飞尝试。
                            inflight.abort_all();
                        }
                        // 后到的成功连接随 abort 关闭（Go r.conn.Close()）。
                    }
                    Some(Ok((idx, Err(e)))) => {
                        active -= 1;
                        tracing::debug!(index = idx, addr = %addrs[idx], error = %e, "happy eyeballs: attempt failed");
                        last_err = Some(e);
                        if winner.is_none() && next < addrs.len() {
                            // 失败立即补充下一个（Go timer.Reset(0)）。
                            timer.as_mut().reset(Instant::now());
                        }
                    }
                    Some(Err(_join_err)) => {
                        // winner 出现后 abort 的在飞尝试（Go ctx 取消等价物）。
                        active -= 1;
                    }
                    None => {
                        return match (winner, last_err) {
                            (Some(v), _) => Ok(v),
                            (None, Some(e)) => Err(e),
                            (None, None) => Err(io::Error::new(
                                io::ErrorKind::AddrNotAvailable,
                                "happy eyeballs: no attempt completed",
                            )),
                        };
                    }
                }
                if winner.is_some() {
                    if active == 0 {
                        return Ok(winner.take().expect("winner checked above"));
                    }
                    continue;
                }
                if active == 0 && next == addrs.len() {
                    // ponytail: 只报最后一个错误（对齐 Go 返回 r.err），聚合错误串对排障
                    // 价值有限——所有 attempt 的 debug 日志里都有。
                    return Err(last_err.unwrap_or_else(|| {
                        io::Error::new(io::ErrorKind::AddrNotAvailable, "happy eyeballs: all attempts failed")
                    }));
                }
            }
            _ = &mut timer, if next < addrs.len() && active < max_c && winner.is_none() => {
                let idx = next;
                next += 1;
                active += 1;
                let attempt = make_attempt.clone();
                inflight.spawn(async move { (idx, attempt(idx).await) });
                if next < addrs.len() && active < max_c {
                    timer.as_mut().reset(Instant::now() + try_delay);
                }
            }
        }
    }
}

/// 按 RFC 8305 交错排序（Go `sortIPs`，happy_eyeballs.go:101-157）。
///
/// - `prioritize_ipv6=false` → v4 先行；`true` → v6 先行
/// - `interleave`：同族连续 N 个再切换（1 = 1:1 交替）
/// - 单族（只有 v4 或只有 v6）原样返回
pub(crate) fn sort_ips(ips: &[IpAddr], prioritize_ipv6: bool, interleave: u32) -> Vec<IpAddr> {
    if ips.is_empty() {
        return Vec::new();
    }
    let mut ip4: Vec<IpAddr> = Vec::with_capacity(ips.len());
    let mut ip6: Vec<IpAddr> = Vec::with_capacity(ips.len());
    for ip in ips {
        match ip {
            IpAddr::V4(_) => ip4.push(*ip),
            IpAddr::V6(_) => ip6.push(*ip),
        }
    }
    if ip4.is_empty() || ip6.is_empty() {
        return ips.to_vec();
    }

    let mut out = Vec::with_capacity(ips.len());
    let (mut i4, mut i6, mut turn) = (0usize, 0usize, 0u32);
    let mut v4turn = !prioritize_ipv6;
    loop {
        if v4turn {
            out.push(ip4[i4]);
            i4 += 1;
            if i4 == ip4.len() {
                out.extend_from_slice(&ip6[i6..]);
                break;
            }
            turn += 1;
            if turn == interleave {
                v4turn = false;
                turn = 0;
            }
        } else {
            out.push(ip6[i6]);
            i6 += 1;
            if i6 == ip6.len() {
                out.extend_from_slice(&ip4[i4..]);
                break;
            }
            turn += 1;
            if turn == interleave {
                v4turn = true;
                turn = 0;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::time::Instant as StdInstant;

    use super::*;

    fn v4(n: u8) -> IpAddr {
        IpAddr::from([192, 0, 2, n])
    }
    fn v6(n: u8) -> IpAddr {
        IpAddr::from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, n])
    }
    fn addr(ip: IpAddr, port: u16) -> SocketAddr {
        SocketAddr::new(ip, port)
    }

    // ===== sort_ips（对齐 Go sortIPs）=====

    #[test]
    fn sort_ips_interleave_one_alternates_v4_first() {
        let ips = [v4(1), v4(2), v6(1), v6(2)];
        let out = sort_ips(&ips, false, 1);
        assert_eq!(out, vec![v4(1), v6(1), v4(2), v6(2)]);
    }

    #[test]
    fn sort_ips_prioritize_ipv6_puts_v6_first() {
        let ips = [v4(1), v6(1)];
        let out = sort_ips(&ips, true, 1);
        assert_eq!(out, vec![v6(1), v4(1)]);
    }

    #[test]
    fn sort_ips_interleave_two_runs_two_per_family() {
        // Go sortIPs：interleave=2 → v4,v4,v6,v6,v4,v6
        let ips = [v4(1), v4(2), v4(3), v6(1), v6(2)];
        let out = sort_ips(&ips, false, 2);
        assert_eq!(out, vec![v4(1), v4(2), v6(1), v6(2), v4(3)]);
    }

    #[test]
    fn sort_ips_single_family_returns_as_is() {
        let ips = [v4(1), v4(2)];
        assert_eq!(sort_ips(&ips, false, 1), ips);
        let ips6 = [v6(1)];
        assert_eq!(sort_ips(&ips6, true, 1), ips6);
        assert!(sort_ips(&[], true, 1).is_empty());
    }

    // ===== race_dial：mock 工厂测时序与竞争 =====

    /// 慢 v6（300ms 后才 Err）+ 快 v4（20ms Ok）→ 选 v4，且不等 v6 超时。
    #[tokio::test]
    async fn race_slow_v6_fast_v4_picks_v4() {
        let addrs = [addr(v6(1), 80), addr(v4(1), 80)];
        let start = StdInstant::now();
        let winner: io::Result<String> =
            race_dial(&addrs, Duration::from_millis(50), 2, |idx: usize| async move {
                if idx == 0 {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    Err(io::Error::new(io::ErrorKind::TimedOut, "v6 too slow"))
                } else {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Ok("v4".to_string())
                }
            })
            .await;
        assert_eq!(winner.expect("v4 should win"), "v4");
        assert!(start.elapsed() < Duration::from_millis(250), "should not wait for slow v6");
    }

    /// 反向：快 v6 优先族成功时慢 v4 不影响结果。
    #[tokio::test]
    async fn race_fast_v6_beats_slow_v4() {
        let addrs = [addr(v6(1), 80), addr(v4(1), 80)];
        let winner: io::Result<String> =
            race_dial(&addrs, Duration::from_millis(50), 2, |idx: usize| async move {
                if idx == 0 {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Ok("v6".to_string())
                } else {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    Ok("v4".to_string())
                }
            })
            .await;
        assert_eq!(winner.expect("v6 should win"), "v6");
    }

    /// 全部失败 → 返回最后错误。
    #[tokio::test]
    async fn race_all_fail_returns_error() {
        let addrs = [addr(v6(1), 80), addr(v4(1), 80)];
        let result: io::Result<String> =
            race_dial(&addrs, Duration::from_millis(10), 2, |idx: usize| async move {
                Err(io::Error::new(io::ErrorKind::ConnectionRefused, format!("fail {idx}")))
            })
            .await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);
    }

    /// max_concurrent=1 时失败立即补充下一个（不等待 try_delay）。
    #[tokio::test]
    async fn race_backfills_immediately_after_failure() {
        let addrs = [addr(v6(1), 80), addr(v4(1), 80)];
        let start = StdInstant::now();
        let winner: io::Result<String> = race_dial(
            &addrs,
            Duration::from_millis(60_000), // 不补充的话第二个永远不会启动
            1,
            |idx: usize| async move {
                if idx == 0 {
                    Err(io::Error::new(io::ErrorKind::ConnectionRefused, "v6 refused"))
                } else {
                    Ok("v4".to_string())
                }
            },
        )
        .await;
        assert_eq!(winner.expect("v4 should win after backfill"), "v4");
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    // ===== tcp_race_dial：真 socket 集成（走 DefaultSystemDialer + sockopt）=====

    /// v6 用已关闭的回环端口（立即 refused）动态补充，v4 listener accept：
    /// 证明竞争拨号经 SystemDialer 走通真实 TCP 且失败补充有效。
    #[tokio::test]
    async fn tcp_race_dial_connects_v4_when_v6_refused() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };

        // v4 listener；v6 同端口无 listener → ::1 connect 立即 refused。
        // prioritize_ipv6=true 让 v6 先试（必 refused）→ 动态补充 v4（必成功），
        // 确定性覆盖「v6 不通 v4 通」场景 + SystemDialer 真实集成。
        let v4l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = v4l.local_addr().unwrap().port();
        // 探测本机是否有 ::1 回环（无则跳过——CI 容器可能禁 v6）。
        if TcpListener::bind(("::1", 0)).await.is_err() {
            eprintln!("skip: no IPv6 loopback in this environment");
            return;
        }
        let echo = tokio::spawn(async move {
            let (mut c, _) = v4l.accept().await.unwrap();
            let mut b = [0u8; 3];
            c.read_exact(&mut b).await.unwrap();
            c.write_all(&b).await.unwrap();
        });

        let dialer: Arc<dyn SystemDialer> =
            Arc::new(crate::system_dialer::DefaultSystemDialer::new());
        let cfg = HappyEyeballsConfig {
            prioritize_ipv6: true, // v6 先试（必 refused）→ 补充 v4（必成功）
            try_delay_ms: 50,
            max_concurrent_try: 1,
            ..HappyEyeballsConfig::default()
        };
        let ips = [
            IpAddr::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), // ::1
            IpAddr::from([127, 0, 0, 1]),
        ];
        let mut conn =
            tcp_race_dial(dialer, None, &ips, Port::new(port), &SocketOptions::default(), &cfg)
                .await
                .expect("race dial should fall back to v4 after v6 refused");
        conn.write_all(b"hey").await.unwrap();
        let mut buf = [0u8; 3];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hey");
        echo.await.unwrap();
    }
}

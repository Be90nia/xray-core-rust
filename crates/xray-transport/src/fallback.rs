//! 通用 fallback 转发：把客户端连接透明转发到备用 dest（带 PROXY protocol header）。
//!
//! 服务于 VLESS/Trojan/REALITY 等 inbound 的 fallback 路由
//! （Go `proxy/trojan/server.go::fallback` line 454-549 / vless `napfb`）。

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite};

/// fallback 拨号尝试次数与退避基数（Go `retry.ExponentialBackoff(5, 100)` 同参数）。
const FALLBACK_ATTEMPTS: u32 = 5;
const FALLBACK_BACKOFF_MS: u64 = 100;

/// 整次 fallback 拨号的总预算（判据：黑洞 dest 总耗时 < 6s）。
///
/// 修复前用裸 `TcpStream::connect` 无任何预算：再叠加 5 次重试，每个尝试的上界等于
/// OS 的 SYN 重传超时（Windows ~21s），最坏 ~105s；环回「端口无人监听」实测也要
/// 2.04s × 5 + 600ms 退避 = 10.816s。
const FALLBACK_DIAL_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

/// 单次尝试上限：把总预算切成多份，保证「重试」真实发生（首尝试不再一口气吃满）。
/// 2s 对弱网仍宽松（TCP 握手 RTT 到 2s 已属极端），且留出 2-3 次重试机会。
const FALLBACK_ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// 是否**值得重试**。确定性失败（重试不可能改变结果）一律不重试，一次尝试即收场。
///
/// `ConnectionRefused`：对方明确拒绝（无监听 / 防火墙 reject），5 次重试纯烧时间——
/// 修复前正是它把「秒级连不上」放大成十几秒。`AddrNotAvailable`/`InvalidInput` 同理
/// （本机无该地址族 / 目标地址非法）。**可重试**的保留：`TimedOut`/`Unreachable`
/// （黑洞，值得再试，但受总预算约束）与 `NotFound`（DNS 可能是瞬时抖动）。
fn should_retry(e: &std::io::Error) -> bool {
    !matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::AddrNotAvailable
            | std::io::ErrorKind::InvalidInput
    )
}

/// 错误分类标签（日志/上报口径；`xray_common` 侧沿用 std `ErrorKind` 分类）。
fn error_class(e: &std::io::Error) -> &'static str {
    match e.kind() {
        std::io::ErrorKind::ConnectionRefused => "refused",
        std::io::ErrorKind::TimedOut => "timeout",
        std::io::ErrorKind::NotFound => "dns-fail",
        std::io::ErrorKind::NetworkUnreachable | std::io::ErrorKind::HostUnreachable => {
            "unreachable"
        },
        std::io::ErrorKind::AddrNotAvailable => "addr-unavailable",
        _ => "other",
    }
}

/// 失败日志限频窗：每 [`FAIL_LOG_WINDOW`] 最多 [`FAIL_LOG_BURST`] 条 warn，其余降级
/// debug（默认不输出、`RUST_LOG` 打开可见 ⇒ 不静默），窗口滚动时补一条**汇总**
/// （上一轮被限频掉的条数，丢不掉）。
///
/// 为什么是**全局**窗口而不是 per-dest 表：256MB 常驻约束下，per-dest key 表会随
/// 攻击者控制的 dest 增长（无界 HashMap = 内存泄漏面）。固定 3 字段状态（24B）在
/// 「可见」与「不刷屏」之间取平衡；按类别聚合的额外区分对排障价值不足。
///
/// 为什么不用 udf `std_ext::ratelimit::TokenBucket`：它要 `Arc<dyn Sleeper>` 实例，
/// 而 `Sleeper` 的实现 `SystemClock` 在 `skeleton` crate——xray-transport 不依赖它，
/// 为一个日志闸新增依赖不划算（§3.5.2 反例）。此处用已注入的 `compat::clock()`。
const FAIL_LOG_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
const FAIL_LOG_BURST: u32 = 5;

/// 限频状态（固定大小，无分配、无表）。
struct FailLogGate {
    window_start: std::time::Instant,
    sent: u32,
    suppressed: u64,
}

static FAIL_LOG_GATE: std::sync::LazyLock<parking_lot::Mutex<FailLogGate>> =
    std::sync::LazyLock::new(|| {
        parking_lot::Mutex::new(FailLogGate { window_start: now(), sent: 0, suppressed: 0 })
    });

/// 单调钟取时（走能力句柄，不用裸 `Instant::now`）。
fn now() -> std::time::Instant {
    xray_frame::compat::clock().now_instant()
}

/// 输出一条 fallback 失败留痕：窗口内前 [`FAIL_LOG_BURST`] 条 warn，其余 debug 并计数。
fn log_dial_failure(line: String) {
    let (as_warn, summary) = {
        let mut gate = FAIL_LOG_GATE.lock();
        let now = now();
        let mut summary = 0u64;
        if now.saturating_duration_since(gate.window_start) >= FAIL_LOG_WINDOW {
            summary = std::mem::take(&mut gate.suppressed);
            *gate = FailLogGate { window_start: now, sent: 0, suppressed: 0 };
        }
        if gate.sent < FAIL_LOG_BURST {
            gate.sent += 1;
            (true, summary)
        } else {
            gate.suppressed += 1;
            (false, summary)
        }
    };
    if summary > 0 {
        crate::LOG.warn(format!(
            "fallback dial failures suppressed={summary} in last {:?}",
            FAIL_LOG_WINDOW
        ));
    }
    if as_warn {
        crate::LOG.warn(line);
    } else {
        crate::LOG.debug(line);
    }
}

/// PROXY protocol 版本（对应 Go `fb.Xver`）。
///
/// - `0`：不发送 PROXY header。
/// - `1`：文本协议 `PROXY TCP4/6 src dst sport dport\r\n`。
/// - `2`：二进制协议（HAProxy v2 signature + addrs）。
///
/// `src` = 客户端地址（connection.RemoteAddr），`dst` = 服务端地址（connection.LocalAddr）。
pub fn encode_proxy_header(xver: u8, src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    match xver {
        1 => encode_proxy_v1(src, dst),
        2 => encode_proxy_v2(src, dst),
        _ => Vec::new(),
    }
}

/// PROXY protocol v1（文本）。
fn encode_proxy_v1(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => {
            format!("PROXY TCP4 {} {} {} {}\r\n", s.ip(), d.ip(), s.port(), d.port()).into_bytes()
        },
        (SocketAddr::V6(s), SocketAddr::V6(d)) => {
            format!("PROXY TCP6 {} {} {} {}\r\n", s.ip(), d.ip(), s.port(), d.port()).into_bytes()
        },
        // 地址族不匹配（极少见）→ UNKNOWN
        _ => b"PROXY UNKNOWN\r\n".to_vec(),
    }
}

/// PROXY protocol v2（二进制）。
fn encode_proxy_v2(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    // 12 字节 signature
    const SIG: &[u8] = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";
    let mut buf = Vec::with_capacity(16 + 36);
    buf.extend_from_slice(SIG);
    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => {
            // 0x21=v2+PROXY, 0x11=AF_INET+STREAM, 0x000C=12 字节 addr
            buf.extend_from_slice(&[0x21, 0x11, 0x00, 0x0C]);
            buf.extend_from_slice(&s.ip().octets());
            buf.extend_from_slice(&d.ip().octets());
            buf.extend_from_slice(&s.port().to_be_bytes());
            buf.extend_from_slice(&d.port().to_be_bytes());
        },
        (SocketAddr::V6(s), SocketAddr::V6(d)) => {
            // 0x21=v2+PROXY, 0x21=AF_INET6+STREAM, 0x0024=36 字节 addr
            buf.extend_from_slice(&[0x21, 0x21, 0x00, 0x24]);
            buf.extend_from_slice(&s.ip().octets());
            buf.extend_from_slice(&d.ip().octets());
            buf.extend_from_slice(&s.port().to_be_bytes());
            buf.extend_from_slice(&d.port().to_be_bytes());
        },
        // 地址族不匹配 → v2+LOCAL+UNSPEC+UNSPEC+0（不传递地址信息）
        _ => buf.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]),
    }
    buf
}

/// fallback 转发：dial `dest` → 写 PROXY header + `first`（已读出的首字节）→ 双向 pipe。
///
/// - `conn`：客户端连接（协议识别失败需 fallback）。
/// - `first`：已从 `conn` 读出的字节（PROXY header 之后、双向 pipe 之前写给 dest）。
/// - `dest`：目标地址字符串（如 `"127.0.0.1:8080"`）。
/// - `src`/`dst`：客户端/服务端地址（PROXY protocol 用）。
/// - `xver`：PROXY protocol 版本（0/1/2）。
pub async fn fallback_to_dest<RW>(
    mut conn: RW,
    first: &[u8],
    dest: &str,
    src: SocketAddr,
    dst: SocketAddr,
    xver: u8,
) -> std::io::Result<()>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::io::{AsyncWriteExt, copy_bidirectional};

    // Go trojan server.go:455 / vless inbound.go:420 用 `retry.ExponentialBackoff(5, 100)` +
    // `net.Dialer`（每次尝试都走系统拨号链：域名重解析、Windows 环回打 `SIO_TCP_INITIAL_RTO`）。
    // 我们在其上加两条更优策略（见 `should_retry` / `FALLBACK_DIAL_BUDGET`）：
    // 确定性失败（refused 等）不再重试 5 次，且整次重试受 5s 总预算约束。
    let started = now();
    let mut dest_conn = match crate::retry::exponential_backoff_if(
        FALLBACK_ATTEMPTS,
        FALLBACK_BACKOFF_MS,
        FALLBACK_DIAL_BUDGET,
        || async {
            let remaining = FALLBACK_DIAL_BUDGET.saturating_sub(started.elapsed());
            let attempt_budget = remaining.min(FALLBACK_ATTEMPT_TIMEOUT);
            if attempt_budget.is_zero() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "fallback dial budget exhausted",
                ));
            }
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host(dest).await?.collect();
            // 单次尝试独立封顶（`dial_first_reachable` 内部整次预算是 16s，黑洞地址会
            // 一口气吃满；这里按剩余预算/单次上限切短，让重试真实发生）。
            match tokio::time::timeout(
                attempt_budget,
                crate::system_dialer::dial_first_reachable(
                    None,
                    &addrs,
                    &crate::sockopt::SocketOptions::default(),
                ),
            )
            .await
            {
                Ok(r) => r,
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "fallback dial attempt timeout",
                )),
            }
        },
        should_retry,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            // 四路调用方中三处 `let _ =` 吞错 ⇒ 客户端只看到 EOF。拨号失败一律在此留痕
            // （含 dest / 分类 / 耗时 / 失败明细），并按窗限频（不许静默、不许刷屏）。
            let class = e.errors.first().map_or("other", error_class);
            log_dial_failure(format!(
                "fallback dest={dest} src={src} class={class} elapsed={:?} error={e}",
                started.elapsed()
            ));
            return Err(std::io::Error::new(
                e.errors.first().map_or(std::io::ErrorKind::Other, std::io::Error::kind),
                e.to_string(),
            ));
        },
    };

    // 1. 写 PROXY protocol header（xver 0 则跳过）
    let proxy_header = encode_proxy_header(xver, src, dst);
    if !proxy_header.is_empty() {
        dest_conn.write_all(&proxy_header).await?;
    }
    // 2. 写已读出的 first buffer（如 ClientHello record，dest 需要完整 TLS 流）
    if !first.is_empty() {
        dest_conn.write_all(first).await?;
    }
    // 3. 双向 pipe（conn ↔ dest）
    copy_bidirectional(&mut conn, &mut dest_conn).await?;
    Ok(())
}

/// 从 first buffer 字节流中提取 HTTP path（fallback 路由的 path 维度）。
///
/// 对应 Go 端 inbound.go 中 `first.Byte(3) == '/'` 后提取 path 的逻辑：
/// - HTTP 请求行格式：`METHOD SP /path SP HTTP/...`
/// - 扫描首个 '/' 到 ' ' 或 '\r' 或 '\n' 为止
pub fn extract_path_from_first_bytes(first: &[u8]) -> Option<&str> {
    let path_start = first.iter().position(|&b| b == b'/')?;
    let path_end = first[path_start..]
        .iter()
        .position(|&b| b == b' ' || b == b'\r' || b == b'\n')
        .map(|p| path_start + p)
        .unwrap_or(first.len());
    std::str::from_utf8(&first[path_start..path_end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_proxy_header_xver0_empty() {
        let src: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let dst: SocketAddr = "127.0.0.1:80".parse().unwrap();
        assert!(encode_proxy_header(0, src, dst).is_empty());
    }

    #[test]
    fn encode_proxy_v1_tcp4() {
        let src: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let dst: SocketAddr = "9.10.11.12:80".parse().unwrap();
        let got = encode_proxy_header(1, src, dst);
        assert_eq!(got, b"PROXY TCP4 1.2.3.4 9.10.11.12 5678 80\r\n");
    }

    #[test]
    fn encode_proxy_v1_tcp6() {
        let src: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::2]:80".parse().unwrap();
        let got = encode_proxy_header(1, src, dst);
        assert_eq!(got, b"PROXY TCP6 2001:db8::1 2001:db8::2 443 80\r\n");
    }

    #[test]
    fn encode_proxy_v2_tcp4() {
        let src: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let dst: SocketAddr = "9.10.11.12:80".parse().unwrap();
        let got = encode_proxy_header(2, src, dst);
        const SIG: &[u8] = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";
        assert_eq!(&got[..12], SIG);
        assert_eq!(&got[12..16], &[0x21, 0x11, 0x00, 0x0C]);
        assert_eq!(&got[16..20], &[1, 2, 3, 4]); // src ip
        assert_eq!(&got[20..24], &[9, 10, 11, 12]); // dst ip
        assert_eq!(&got[24..28], &[0x16, 0x2E, 0x00, 0x50]); // 5678=0x162E, 80=0x50
        assert_eq!(got.len(), 28);
    }

    #[test]
    fn encode_proxy_v2_tcp6() {
        let src: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::2]:80".parse().unwrap();
        let got = encode_proxy_header(2, src, dst);
        const SIG: &[u8] = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";
        assert_eq!(&got[..12], SIG);
        assert_eq!(got.len(), 16 + 36);
    }

    /// fallback_to_dest 端到端：回显 dest 收到 first + 后续双向数据。
    #[tokio::test]
    async fn fallback_to_dest_pipes_first_and_stream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = echo.local_addr().unwrap();
        #[allow(clippy::disallowed_methods, reason = "测试：echo server 任务")]
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    },
                }
            }
        });

        let (mut client, mut server_side) = tokio::io::duplex(1024);
        let src: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let dst: SocketAddr = "127.0.0.1:443".parse().unwrap();
        #[allow(clippy::disallowed_methods, reason = "测试：fallback_to_dest 任务")]
        let task = tokio::spawn(async move {
            fallback_to_dest(&mut server_side, b"HELLO-FIRST", &dest_addr.to_string(), src, dst, 0)
                .await
                .unwrap();
        });

        client.write_all(b"HELLO-FIRST").await.unwrap();
        client.flush().await.unwrap();
        let mut got = vec![0u8; 11];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(got, b"HELLO-FIRST");
        drop(client);
        let _ = task.await;
    }
}

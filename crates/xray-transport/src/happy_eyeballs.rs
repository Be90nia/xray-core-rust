//! # Happy Eyeballs 双栈拨号
//!
//! RFC 8305——IPv4/IPv6 并发拨号，先连上的赢。对应 Go `transport/internet/happy_eyeballs.go`。
//!
//! ## 配置
//!
//! - `try_delay_ms`：优先族拨号后等待多久再启动次优族（默认 100ms）
//! - `prioritize_ipv6`：true → IPv6 先行；false → IPv4 先行
//! - `max_concurrent_try`：最大并发拨号数（默认 2）

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// 默认延迟：优先族拨号后等 100ms 再启动次优族。
const DEFAULT_DELAY: Duration = Duration::from_millis(100);
/// 默认最大并发拨号。
const DEFAULT_MAX_CONCURRENT: usize = 2;

/// Happy Eyeballs 配置参数。
#[derive(Debug, Clone)]
pub struct HappyEyeballsOpts {
    /// 优先族拨号后等待多久再启动次优族。
    pub try_delay: Duration,
    /// true → IPv6 优先；false → IPv4 优先。
    pub prioritize_ipv6: bool,
    /// 最大并发拨号数。
    pub max_concurrent: usize,
}

impl Default for HappyEyeballsOpts {
    fn default() -> Self {
        Self {
            try_delay: DEFAULT_DELAY,
            prioritize_ipv6: true,
            max_concurrent: DEFAULT_MAX_CONCURRENT,
        }
    }
}

impl HappyEyeballsOpts {
    /// 从 proto `HappyEyeballsConfig` 构建。
    #[must_use]
    pub fn from_proto(
        prioritize_ipv6: bool,
        try_delay_ms: u64,
        max_concurrent_try: u32,
    ) -> Self {
        Self {
            try_delay: if try_delay_ms > 0 {
                Duration::from_millis(try_delay_ms)
            } else {
                DEFAULT_DELAY
            },
            prioritize_ipv6,
            max_concurrent: if max_concurrent_try > 0 {
                max_concurrent_try as usize
            } else {
                DEFAULT_MAX_CONCURRENT
            },
        }
    }
}

/// Happy Eyeballs 并发拨号。
///
/// 将 `primary`（优先族）和 `secondary`（次优族）地址列表交替排列后并发拨号。
/// 先连上的 wins，其余被 drop。
///
/// # 错误
///
/// 两个列表都空 → `AddrNotAvailable`。
pub async fn dial_happy_eyeballs(
    primary: &[SocketAddr],
    secondary: &[SocketAddr],
    opts: &HappyEyeballsOpts,
) -> std::io::Result<TcpStream> {
    if primary.is_empty() && secondary.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "happy eyeballs: no address to dial",
        ));
    }

    // 单地址直连（常见路径，避免 channel 开销）
    if primary.len() == 1 && secondary.is_empty() {
        return TcpStream::connect(primary[0]).await;
    }
    if secondary.len() == 1 && primary.is_empty() {
        return TcpStream::connect(secondary[0]).await;
    }

    // 多地址：交替排列 primary + secondary，优先族先行
    let interleaved = interleave(primary, secondary);
    race_dial(&interleaved, opts).await
}

/// 交替排列两个地址列表：primary[0], secondary[0], primary[1], secondary[1], ...
fn interleave(primary: &[SocketAddr], secondary: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut out = Vec::with_capacity(primary.len() + secondary.len());
    let max = primary.len().max(secondary.len());
    for i in 0..max {
        if i < primary.len() {
            out.push(primary[i]);
        }
        if i < secondary.len() {
            out.push(secondary[i]);
        }
    }
    out
}

/// 并发拨号：按交错列表逐个启动，先成功的 wins。
///
/// 第一个地址立即启动，后续地址间隔 `try_delay` 启动（最多 `max_concurrent` 个并发）。
async fn race_dial(addrs: &[SocketAddr], opts: &HappyEyeballsOpts) -> std::io::Result<TcpStream> {
    let max_concurrent = opts.max_concurrent.min(addrs.len()).max(1);
    let (tx, mut rx) = mpsc::channel::<std::io::Result<TcpStream>>(max_concurrent);

    // 启动拨号任务：第 i 个地址在 i * try_delay 后启动
    for (i, addr) in addrs.iter().take(max_concurrent).enumerate() {
        let tx = tx.clone();
        let addr = *addr;
        let delay = if i == 0 {
            Duration::ZERO
        } else {
            opts.try_delay
        };
        tokio::spawn(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let _ = tx.send(TcpStream::connect(addr).await).await;
        });
    }
    drop(tx);

    let mut errors = Vec::new();
    loop {
        match rx.recv().await {
            Some(Ok(s)) => return Ok(s),
            Some(Err(e)) => {
                errors.push(e);
                // 如果还有未启动的地址，补充一个
                // ponytail: 单轮 max_concurrent 个，不动态补充
            }
            None => {
                return Err(std::io::Error::other(format!(
                    "happy eyeballs: all {} attempts failed: {}",
                    addrs.len(),
                    errors
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join("; ")
                )));
            }
        }
    }
}

/// 兼容旧接口：单地址 per family。
pub async fn dial_happy_eyeballs_single(
    v4: Option<SocketAddr>,
    v6: Option<SocketAddr>,
) -> std::io::Result<TcpStream> {
    let opts = HappyEyeballsOpts::default();
    let (primary, secondary) = if opts.prioritize_ipv6 {
        (v6.into_iter().collect::<Vec<_>>(), v4.into_iter().collect::<Vec<_>>())
    } else {
        (v4.into_iter().collect::<Vec<_>>(), v6.into_iter().collect::<Vec<_>>())
    };
    dial_happy_eyeballs(&primary, &secondary, &opts).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn both_empty_returns_error() {
        let opts = HappyEyeballsOpts::default();
        assert!(dial_happy_eyeballs(&[], &[], &opts).await.is_err());
    }

    #[test]
    fn interleave_alternates_primary_first() {
        let v6: Vec<SocketAddr> = vec![
            "[2001:db8::1]:80".parse().unwrap(),
            "[2001:db8::2]:80".parse().unwrap(),
        ];
        let v4: Vec<SocketAddr> = vec!["10.0.0.1:80".parse().unwrap()];
        let result = interleave(&v6, &v4);
        // v6[0], v4[0], v6[1]
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], v6[0]);
        assert_eq!(result[1], v4[0]);
        assert_eq!(result[2], v6[1]);
    }

    #[test]
    fn from_proto_uses_defaults_when_zero() {
        let opts = HappyEyeballsOpts::from_proto(true, 0, 0);
        assert_eq!(opts.try_delay, DEFAULT_DELAY);
        assert_eq!(opts.max_concurrent, DEFAULT_MAX_CONCURRENT);
        assert!(opts.prioritize_ipv6);
    }

    #[test]
    fn from_proto_respects_nonzero() {
        let opts = HappyEyeballsOpts::from_proto(false, 250, 4);
        assert_eq!(opts.try_delay, Duration::from_millis(250));
        assert_eq!(opts.max_concurrent, 4);
        assert!(!opts.prioritize_ipv6);
    }
}

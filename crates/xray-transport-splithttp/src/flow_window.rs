//! bd rjzw2：h2 流控 RTT 自适应定窗（xhttp 客户端 + 服务端共用）。
//!
//! 物理约束：单流吞吐 ≤ min(对端收窗, 本端 send_buf)/RTT；但 in-flight 不必静态
//! 拉满——低 RTT 档大窗只堆 bufferbloat 不涨吞吐。h2 的接收窗仅在握手 SETTINGS 定
//! 初值、运行时 auto-refill 不超初窗（hyper/h2 无运行时调接收窗 API，quic-go 式
//! 「每 RTT 翻倍」不可复刻——已知局限），故落点 = 每连接握手前 RTT 探测定初窗。
//!
//! 探针（各自贴合所在层，不侵入协议逻辑）：
//! - 客户端 rustls/btls 主路径：独立探测连接 TCP connect 计时 （SYN→SYN-ACK ≈ 1 RTT，先
//!   `lookup_host` 再计时——DNS 不进 RTT）。
//! - 客户端 REALITY 路径：直接计时真实 `dial_system` connect（零额外握手）。
//! - 服务端 TLS/REALITY：accept 耗时 ≈ 1 RTT（ServerHello→Finished）+ 毫秒级 CPU，40ms
//!   断点下偏差可容忍；明文/unix 分支无信号 → 保底。
//!
//! 探针失败/RTT 不可知 → 回落静态保底（**逐值等于修前原静态值**，永不劣于现状）。
//!
//! 自适应对象 = **send_buf**（per-stream 发送缓冲，hyper 实分配、bufferbloat 源头）；
//! **流窗/连窗保持各端原静态值不动**——rjzw2 bench 实测（delay-proxy RTT20，override
//! 扫描 8/12/16/24/26/28/30/32MB）：缩流窗 ≤26MB 吞吐掉 14-31%、28MB 起满速
//! （211-216MB/s = 静态持平）——SETTINGS 窗是零预分配计数器、非真缓冲。
//!
//! 阶梯断点数据来源：delay-proxy 实测（reports/audit-2026-10-29/rjzw2-h2-adaptive.md）：
//! 20ms 档 in-flight ~3.2MB 即打满；80ms 档需 ~9.8MB、120ms 档需 ~11.1MB in-flight
//! → send_buf 取「够喂饱该档 BDP」的最小档：8MB(<40ms) / 12MB(40-100ms) /
//! 16MB(≥100ms 与探针失败 = 各端原静态 send_buf）。

use std::time::Duration;

/// RTT 阶梯下档断点：低于此 = 低延迟档，send_buf 缩到 8MB。
const RTT_TIER_FAST_MS: u128 = 40;
/// RTT 阶梯中档断点：低于此 = 中延迟档，send_buf 12MB；≥此值保持各端静态值。
const RTT_TIER_MID_MS: u128 = 100;

/// 低 RTT 档（rtt < 40ms）send_buf 8MB（BDP≈4.2MB×2 取整）。
const TIER_FAST_SEND_BUF: usize = 8 * 1024 * 1024;
/// 中 RTT 档（40ms ≤ rtt < 100ms）send_buf 12MB。
const TIER_MID_SEND_BUF: usize = 12 * 1024 * 1024;

/// 客户端静态保底 = bd wz2b C2 + c9oc F-A 修前原静态值（32MB 流窗 / 32MB 连窗 /
/// 16MiB send buf），探针失败或 RTT ≥ 100ms 档逐值回此。
pub(crate) const CLIENT_FALLBACK: H2Windows = H2Windows {
    stream_window: crate::transport::H2_INITIAL_STREAM_WINDOW,
    connection_window: crate::transport::H2_INITIAL_CONNECTION_WINDOW,
    max_send_buf: crate::transport::H2_MAX_SEND_BUF_SIZE,
};

/// 服务端静态保底 = 修前 `serve_http_conn` 原静态值（16MB 流窗 / 32MB 连窗 /
/// 16MiB send buf）——**不得用客户端常量**：客户端流窗 32MB 会把服务端原静态 16MB
/// 抬到 32MB（保底被偷改 → 「现状静态 vs 自适应」对比基线失效）。
pub(crate) const SERVER_FALLBACK: H2Windows = H2Windows {
    stream_window: crate::transport::H2_SERVER_INITIAL_STREAM_WINDOW,
    connection_window: crate::transport::H2_SERVER_INITIAL_CONNECTION_WINDOW,
    max_send_buf: crate::transport::H2_SERVER_MAX_SEND_BUF_SIZE,
};

/// bench/诊断专用：强制流窗字节数（conn=2×、send=同值），进程级显式值驱动，
/// 未设置零影响。bench 用它扫「窗-吞吐」曲线定阶梯断点。
const ENV_OVERRIDE: &str = "XRAY_H2_FLOW_WINDOW_OVERRIDE_BYTES";

/// bench/诊断专用：仅覆盖 send_buf（流窗保持），与 [`ENV_OVERRIDE`] 组合可
/// 分离「流窗 vs send_buf」变量（rjzw2 断点实验用）。
const ENV_SEND_OVERRIDE: &str = "XRAY_H2_SEND_BUF_OVERRIDE_BYTES";

/// bench/诊断专用：强制 RTT hint（毫秒），**仅 bench/诊断用，生产默认不设**。
///
/// 存在理由：connect() 探针在生产是对的（无中间盒时 ≈1 RTT），但 delay-proxy 挡在
/// 探针之前时探针**结构上测不到注入 RTT**（SYN/ACK 走 loopback）→ 不注入则阶梯在
/// bench 里无法验证。设了就绕过探针值直接喂阶梯；未设置 = 零影响（走真探针路径）。
const ENV_RTT_HINT_MS: &str = "XRAY_H2_RTT_HINT_MS";

/// 一组 h2 握手期定死的流控参数（SETTINGS 初窗 + 每流发送缓冲）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct H2Windows {
    pub stream_window: u32,
    pub connection_window: u32,
    pub max_send_buf: usize,
}

/// 客户端 h2 窗组（阶梯驱动；保底 = [`CLIENT_FALLBACK`] = 修前原静态值）。
pub(crate) fn client_windows_from_rtt(rtt: Option<Duration>) -> H2Windows {
    windows_for("client", CLIENT_FALLBACK, rtt)
}

/// 服务端 h2 窗组（阶梯驱动；保底 = [`SERVER_FALLBACK`] = 修前原静态值）。
pub(crate) fn server_windows_from_rtt(rtt: Option<Duration>) -> H2Windows {
    windows_for("server", SERVER_FALLBACK, rtt)
}

/// 阶梯定窗 + 定窗日志（唯一实现点；客户端/服务端共用，仅保底基不同）。
fn windows_for(role: &str, fallback: H2Windows, rtt: Option<Duration>) -> H2Windows {
    let effective = pick_rtt(rtt_hint_env(), rtt);
    let mut w = fallback;
    w.max_send_buf = tier_send_buf(effective).unwrap_or(fallback.max_send_buf);
    apply_env_overrides(&mut w);
    crate::hot_log!(
        DEBUG,
        "h2_adaptive_window role={} rtt_ms={} stream={} conn={} send={}",
        role,
        effective.map(|d| d.as_millis()).unwrap_or(0),
        w.stream_window,
        w.connection_window,
        w.max_send_buf
    );
    w
}

/// bench/诊断专用 RTT hint（进程级）；未设置 = `None` = 零影响（走真探针路径）。
pub(crate) fn rtt_hint_env() -> Option<Duration> {
    parse_rtt_hint(std::env::var(ENV_RTT_HINT_MS).ok().as_deref())
}

/// 纯阶梯：RTT → send_buf 档位（**不读全局 env**，单测逐值锁定）。
///
/// `None` = 「本档不缩」→ 保持各端静态 send_buf（探针失败 / RTT ≥ 100ms 档）。
fn tier_send_buf(rtt: Option<Duration>) -> Option<usize> {
    match rtt.map(|d| d.as_millis()) {
        Some(ms) if ms < RTT_TIER_FAST_MS => Some(TIER_FAST_SEND_BUF),
        Some(ms) if ms < RTT_TIER_MID_MS => Some(TIER_MID_SEND_BUF),
        _ => None,
    }
}

/// 有效 RTT = bench/诊断 hint 优先，否则用探针实测值（纯函数，单测锁优先级）。
fn pick_rtt(hint: Option<Duration>, probed: Option<Duration>) -> Option<Duration> {
    hint.or(probed)
}

/// 纯解析 RTT hint：合法区间 [1, 60_000] ms，越界/非数字 = 未设置。
fn parse_rtt_hint(raw: Option<&str>) -> Option<Duration> {
    raw.and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|ms| (1..=60_000).contains(ms))
        .map(Duration::from_millis)
}

/// bench/诊断 env 覆盖（流窗整体覆盖优先于 send_buf 单覆盖）。
fn apply_env_overrides(w: &mut H2Windows) {
    apply_overrides(
        w,
        parse_override(std::env::var(ENV_OVERRIDE).ok().as_deref()),
        parse_override(std::env::var(ENV_SEND_OVERRIDE).ok().as_deref()),
    );
}

/// 覆盖应用（纯函数，单测零 env 全局面）：流窗整体覆盖优先于 send_buf 单覆盖。
fn apply_overrides(w: &mut H2Windows, flow: Option<u32>, send: Option<u32>) {
    if let Some(bytes) = flow {
        w.stream_window = bytes;
        // 连接窗 = 2× 流窗（多流上行聚合不另成钉）；u32 上界 saturating。
        w.connection_window = bytes.saturating_mul(2);
        w.max_send_buf = bytes as usize;
        return;
    }
    if let Some(bytes) = send {
        w.max_send_buf = bytes as usize;
    }
}

/// 纯解析（单测零 env 全局面）：合法区间 [1KiB, 1GiB]，越界/非数字 = 未设置。
fn parse_override(raw: Option<&str>) -> Option<u32> {
    raw.and_then(|v| v.parse::<u32>().ok()).filter(|b| (1024..=(1 << 30)).contains(b))
}

/// 客户端 RTT 探针：对 `host:port` 建一条一次性 TCP 连接，connect 计时。
/// DNS 解析在计时外（污染会让窗偏大）；连接失败/1s 超时 → `None`（保底）。
pub(crate) async fn probe_rtt(host: &str, port: u16) -> Option<Duration> {
    let addr = tokio::net::lookup_host((host, port)).await.ok()?.next()?;
    let started = xray_frame::compat::clock().now_instant();
    let tcp = tokio::time::timeout(Duration::from_secs(1), tokio::net::TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    drop(tcp); // 探测连接不承载 TLS/数据，立即关闭
    Some(started.elapsed())
}

/// 有效 RTT（客户端路径入口）：bench/诊断 hint 优先（**并跳过探针**——hint 存在
/// 时探针结果必被覆盖，白跑一次 TCP 握手无意义）；否则走真探针。
///
/// 未设置 hint 时**逐字节等于**纯探针路径（hint=None → 原样返回探针值）。
pub(crate) async fn resolve_rtt(host: &str, port: u16) -> Option<Duration> {
    match rtt_hint_env() {
        Some(hint) => Some(hint),
        None => probe_rtt(host, port).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_fallback_equals_pre_rjzw2_static() {
        // 保底逐值等于修前原静态值（bd wz2b C2 + c9oc F-A）。
        assert_eq!(CLIENT_FALLBACK.stream_window, 32 * 1024 * 1024);
        assert_eq!(CLIENT_FALLBACK.connection_window, 32 * 1024 * 1024);
        assert_eq!(CLIENT_FALLBACK.max_send_buf, 16 * 1024 * 1024);
        assert_eq!(client_windows_from_rtt(None), CLIENT_FALLBACK);
    }

    #[test]
    fn server_fallback_equals_pre_rjzw2_static() {
        // 服务端保底 = 修前 serve_http_conn 原静态（16MB 流窗，非客户端 32MB）。
        assert_eq!(SERVER_FALLBACK.stream_window, 16 * 1024 * 1024);
        assert_eq!(SERVER_FALLBACK.connection_window, 32 * 1024 * 1024);
        assert_eq!(SERVER_FALLBACK.max_send_buf, 16 * 1024 * 1024);
        assert_eq!(server_windows_from_rtt(None), SERVER_FALLBACK);
        assert_ne!(
            SERVER_FALLBACK.stream_window, CLIENT_FALLBACK.stream_window,
            "服务端保底不得用客户端流窗常量（保底被偷改 → 对比基线失效）"
        );
    }

    #[test]
    fn ladder_locks_send_buf_per_rtt() {
        // 阶梯逐值锁定（bench 只是驱动手段，不是唯一证据）。
        assert_eq!(tier_send_buf(None), None);
        assert_eq!(tier_send_buf(Some(Duration::from_millis(1))), Some(8 * 1024 * 1024));
        assert_eq!(tier_send_buf(Some(Duration::from_millis(20))), Some(8 * 1024 * 1024));
        assert_eq!(tier_send_buf(Some(Duration::from_millis(39))), Some(8 * 1024 * 1024));
        assert_eq!(tier_send_buf(Some(Duration::from_millis(40))), Some(12 * 1024 * 1024));
        assert_eq!(tier_send_buf(Some(Duration::from_millis(80))), Some(12 * 1024 * 1024));
        assert_eq!(tier_send_buf(Some(Duration::from_millis(99))), Some(12 * 1024 * 1024));
        assert_eq!(tier_send_buf(Some(Duration::from_millis(100))), None);
        assert_eq!(tier_send_buf(Some(Duration::from_millis(240))), None);
    }

    #[test]
    fn tiers_keep_flow_windows_at_role_static() {
        // 流窗/连窗各端原静态值不动（缩窗钉吞吐：rjzw2 bench 实测）。
        for rtt in [None, Some(Duration::from_millis(20)), Some(Duration::from_millis(80))] {
            let c = client_windows_from_rtt(rtt);
            assert_eq!(c.stream_window, 32 * 1024 * 1024);
            assert_eq!(c.connection_window, 32 * 1024 * 1024);
            let s = server_windows_from_rtt(rtt);
            assert_eq!(s.stream_window, 16 * 1024 * 1024);
            assert_eq!(s.connection_window, 32 * 1024 * 1024);
        }
    }

    #[test]
    fn low_rtt_tier_shrinks_only_send_buf() {
        let c = client_windows_from_rtt(Some(Duration::from_millis(20)));
        assert_eq!(c.max_send_buf, 8 * 1024 * 1024);
        let s = server_windows_from_rtt(Some(Duration::from_millis(20)));
        assert_eq!(s.max_send_buf, 8 * 1024 * 1024);
        // 中档 12MB。
        assert_eq!(
            client_windows_from_rtt(Some(Duration::from_millis(80))).max_send_buf,
            12 * 1024 * 1024
        );
        // ≥100ms 档 = 各端原静态 send_buf。
        assert_eq!(
            client_windows_from_rtt(Some(Duration::from_millis(120))).max_send_buf,
            16 * 1024 * 1024
        );
    }

    #[test]
    fn rtt_hint_parse_bounds() {
        // 纯解析单测（不碰进程 env——libtest 并行下全局 env 改动会污染阶梯断言测试）。
        assert_eq!(parse_rtt_hint(Some("20")), Some(Duration::from_millis(20)));
        assert_eq!(parse_rtt_hint(Some(" 80 ")), Some(Duration::from_millis(80)));
        assert_eq!(parse_rtt_hint(Some("0")), None, "0ms 视为未设置");
        assert_eq!(parse_rtt_hint(Some("60001")), None, "超出上限视为未设置");
        assert_eq!(parse_rtt_hint(Some("abc")), None);
        assert_eq!(parse_rtt_hint(None), None);
    }

    #[test]
    fn rtt_hint_wins_over_probed() {
        // hint 优先于探针实测（bench 注入即驱动手段）。
        assert_eq!(
            pick_rtt(Some(Duration::from_millis(80)), None),
            Some(Duration::from_millis(80))
        );
        assert_eq!(
            pick_rtt(Some(Duration::from_millis(80)), Some(Duration::from_millis(5))),
            Some(Duration::from_millis(80))
        );
        assert_eq!(pick_rtt(None, Some(Duration::from_millis(5))), Some(Duration::from_millis(5)));
        assert_eq!(pick_rtt(None, None), None);
    }

    #[test]
    fn overrides_apply_flow_then_send() {
        // 覆盖应用纯函数（服务端保底基；hub 明文路径 = server_windows_from_rtt(None) 同源）。
        let mut w = SERVER_FALLBACK;
        apply_overrides(&mut w, Some(4 * 1024 * 1024), None);
        assert_eq!(w.stream_window, 4 * 1024 * 1024);
        assert_eq!(w.connection_window, 8 * 1024 * 1024, "连窗 = 2× 流窗");
        assert_eq!(w.max_send_buf, 4 * 1024 * 1024);

        // send_buf 单覆盖不动流窗。
        let mut w = SERVER_FALLBACK;
        apply_overrides(&mut w, None, Some(6 * 1024 * 1024));
        assert_eq!(w.stream_window, SERVER_FALLBACK.stream_window);
        assert_eq!(w.connection_window, SERVER_FALLBACK.connection_window);
        assert_eq!(w.max_send_buf, 6 * 1024 * 1024);

        // 流窗整体覆盖优先于 send_buf 单覆盖。
        let mut w = SERVER_FALLBACK;
        apply_overrides(&mut w, Some(2 * 1024 * 1024), Some(6 * 1024 * 1024));
        assert_eq!(w.max_send_buf, 2 * 1024 * 1024);

        // 两者皆未设置 = 原样（逐值等于保底）。
        let mut w = SERVER_FALLBACK;
        apply_overrides(&mut w, None, None);
        assert_eq!(w, SERVER_FALLBACK);
    }

    #[test]
    fn env_override_parse_bounds() {
        // 纯解析单测（不碰进程 env——libtest 并行下全局 env 改动会污染阶梯断言测试）。
        assert_eq!(parse_override(Some("4194304")), Some(4 * 1024 * 1024));
        assert_eq!(parse_override(Some("1024")), Some(1024));
        assert_eq!(parse_override(Some("1023")), None, "低于 1KiB 视为未设置");
        assert_eq!(parse_override(Some("1073741825")), None, "高于 1GiB 视为未设置");
        assert_eq!(parse_override(Some("abc")), None);
        assert_eq!(parse_override(None), None);
    }

    #[tokio::test]
    async fn probe_rtt_times_real_connect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let rtt = probe_rtt("127.0.0.1", port).await.expect("loopback probe succeeds");
        accept.await.unwrap();
        assert!(rtt < Duration::from_millis(500), "loopback RTT 应远小于 500ms: {rtt:?}");
    }

    #[tokio::test]
    async fn probe_rtt_refused_returns_none() {
        // 127.0.0.1:1 保留端口必然拒绝 → 探针失败 → None（保底路径）。
        assert_eq!(probe_rtt("127.0.0.1", 1).await, None);
    }
}

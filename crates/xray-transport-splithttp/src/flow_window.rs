//! xhttp h2 窗组（客户端 + 服务端共用）：静态保底值 + 诊断 env 覆盖。
//!
//! 物理约束：单流吞吐 ≤ min(对端收窗, 本端 send_buf)/RTT，其中 RTT 是**数据路径
//! 的端到端 RTT**。h2 的接收窗只在握手 SETTINGS 定初值、运行时 auto-refill 不超初窗
//! （hyper/h2 无运行时调接收窗 API——已知局限），故任何自适应都只能落在握手前的初值上。
//!
//! ## 为什么**不再**按 RTT 缩 send_buf（撤掉 bd rjzw2 的阶梯）
//!
//! 33bacd22 曾按探测 RTT 缩 send_buf：<40ms→8MB、40-99ms→12MB、≥100ms→16MB。
//! 该优化的隐含前提是「探测 RTT = 端到端 RTT」，**在代理场景结构性不成立**：
//!
//! - 客户端探针只测到「本机 → host」这一段（`probe_rtt` 建一条一次性 TCP 连接计时）。
//! - host 是 CDN 域名时（生产 xhttp 入站走 CDN，mode=packet-up），这一段 ≈ **CDN 边缘 RTT**（实测
//!   ~30ms），真实数据路径（客户端→CDN→源站）端到端 RTT ≈ 200ms。
//! - 于是 send_buf 落 8MB 档，而吞吐上限 = send_buf / 端到端 RTT = 8MB / 0.2s ≈ 40MB/s ——实测被钉在
//!   35MB/s（历史 50-60MB/s）。**这是把 probe 的 RTT 当成了 BDP 的 RTT**。
//! - 探针无法区分「直连」与「CDN/中转/隧道」：同一个低 RTT 观测既可能是低延迟直连，
//!   也可能是高延迟链路的薄边缘。= 该优化没有可判定的适用范围，故整体删除（Go 侧 本无此机制：Go
//!   xray 的 h2 发送缓冲恒为静态值，本轮对齐 Go）。
//!
//! 现状：`max_send_buf` 恒等于各端静态保底（16MiB）；流窗/连窗亦保持各端原静态值
//! （32/32MB 客户端、16/32MB 服务端）——rjzw2 bench 实测缩流窗 ≤26MB 吞吐掉 14-31%
//! （SETTINGS 窗是零预分配计数器，缩它只钉吞吐不省缓冲）。
//!
//! ## RTT 探针为何保留
//!
//! 探针结果**只进定窗日志**（`h2_adaptive_window rtt_ms=`），不再参与定窗——排查「走上行
//! 时探针看到的 RTT 与端到端差多少」仍靠它。诊断 env：`XRAY_H2_RTT_HINT_MS`（hint 优先
//! 于探针，仅影响日志标签）、`XRAY_H2_FLOW_WINDOW_OVERRIDE_BYTES` /
//! `XRAY_H2_SEND_BUF_OVERRIDE_BYTES`（强制流窗/send_buf，bench 扫曲线用）。三者未设置时
//! 零影响。

use std::time::Duration;

/// 客户端静态保底 = bd wz2b C2 + c9oc F-A 修前原静态值（32MB 流窗 / 32MB 连窗 /
/// 16MiB send buf）——现在**恒为**客户端定窗结果，不再随 RTT 变。
pub(crate) const CLIENT_FALLBACK: H2Windows = H2Windows {
    stream_window: crate::transport::H2_INITIAL_STREAM_WINDOW,
    connection_window: crate::transport::H2_INITIAL_CONNECTION_WINDOW,
    max_send_buf: crate::transport::H2_MAX_SEND_BUF_SIZE,
};

/// 服务端静态保底 = 修前 `serve_http_conn` 原静态值（16MB 流窗 / 32MB 连窗 /
/// 16MiB send buf）——**不得用客户端常量**：客户端流窗 32MB 会把服务端原静态 16MB
/// 抬到 32MB（保底被偷改 → 「静态 vs 自适应」对比基线失效）。
pub(crate) const SERVER_FALLBACK: H2Windows = H2Windows {
    stream_window: crate::transport::H2_SERVER_INITIAL_STREAM_WINDOW,
    connection_window: crate::transport::H2_SERVER_INITIAL_CONNECTION_WINDOW,
    max_send_buf: crate::transport::H2_SERVER_MAX_SEND_BUF_SIZE,
};

/// bench/诊断专用：强制流窗字节数（conn=2×、send=同值），进程级显式值驱动，
/// 未设置零影响。bench 用它扫「窗-吞吐」曲线。
const ENV_OVERRIDE: &str = "XRAY_H2_FLOW_WINDOW_OVERRIDE_BYTES";

/// bench/诊断专用：仅覆盖 send_buf（流窗保持），与 [`ENV_OVERRIDE`] 组合可
/// 分离「流窗 vs send_buf」变量（rjzw2 断点实验用）。
const ENV_SEND_OVERRIDE: &str = "XRAY_H2_SEND_BUF_OVERRIDE_BYTES";

/// bench/诊断专用：强制 RTT hint（毫秒），**仅 bench/诊断用，生产默认不设**。
///
/// 撤阶梯后它只改定窗日志的 `rtt_ms` 标签（不再影响任何窗值）；保留是为不打断既有
/// 诊断/bench 流程（设了即绕过探针，省一次 TCP 握手的探测开销）。
const ENV_RTT_HINT_MS: &str = "XRAY_H2_RTT_HINT_MS";

/// 一组 h2 握手期定死的流控参数（SETTINGS 初窗 + 每流发送缓冲）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct H2Windows {
    pub stream_window: u32,
    pub connection_window: u32,
    pub max_send_buf: usize,
}

/// 客户端 h2 窗组（恒 = [`CLIENT_FALLBACK`]；`rtt` 只进日志，不参与定窗）。
pub(crate) fn client_windows_from_rtt(rtt: Option<Duration>) -> H2Windows {
    windows_for("client", CLIENT_FALLBACK, rtt)
}

/// 服务端 h2 窗组（恒 = [`SERVER_FALLBACK`]；`rtt` 只进日志，不参与定窗）。
pub(crate) fn server_windows_from_rtt(rtt: Option<Duration>) -> H2Windows {
    windows_for("server", SERVER_FALLBACK, rtt)
}

/// 定窗 + 定窗日志（唯一实现点；客户端/服务端共用，仅保底基不同）。
///
/// 窗值 = 各端静态保底，**唯二**能改动它们的是诊断 env 覆盖
/// （[`apply_env_overrides`]）。`rtt` 仅作日志标签——按 RTT 缩 send_buf 的错误见
/// 模块头（CDN 边缘 RTT ≠ 端到端 RTT）。
fn windows_for(role: &str, fallback: H2Windows, rtt: Option<Duration>) -> H2Windows {
    let effective = pick_rtt(rtt_hint_env(), rtt);
    let mut w = fallback;
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

/// 有效 RTT = bench/诊断 hint 优先，否则用探针实测值（纯函数，单测锁优先级）。
/// **只喂定窗日志**，不参与任何窗值计算。
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
    fn send_buf_is_rtt_independent() {
        // 撤阶梯的钉子（33bacd22 曾按探测 RTT 缩 send_buf）：任何 RTT 下客户端/服务端
        // send_buf 都必须等于静态保底 16MiB。理由见模块头——探针测的是「本机→host」
        // 一段，CDN 场景下该值是边缘 RTT（~30ms），拿它裁端到端 BDP 会把吞吐钉在
        // send_buf/端到端 RTT（8MB/0.2s ≈ 40MB/s）。改回阶梯 = 本测试红。
        let rtts = [
            None,
            Some(Duration::from_millis(1)),
            Some(Duration::from_millis(20)),
            Some(Duration::from_millis(39)),
            Some(Duration::from_millis(40)),
            Some(Duration::from_millis(80)),
            Some(Duration::from_millis(99)),
            Some(Duration::from_millis(100)),
            Some(Duration::from_millis(240)),
            Some(Duration::from_secs(5)),
        ];
        for rtt in rtts {
            let c = client_windows_from_rtt(rtt);
            assert_eq!(
                c.max_send_buf,
                16 * 1024 * 1024,
                "客户端 send_buf 随 RTT 变（rtt={rtt:?}）"
            );
            assert_eq!(c, CLIENT_FALLBACK, "客户端窗组随 RTT 变（rtt={rtt:?}）");
            let s = server_windows_from_rtt(rtt);
            assert_eq!(
                s.max_send_buf,
                16 * 1024 * 1024,
                "服务端 send_buf 随 RTT 变（rtt={rtt:?}）"
            );
            assert_eq!(s, SERVER_FALLBACK, "服务端窗组随 RTT 变（rtt={rtt:?}）");
        }
    }

    #[test]
    fn flow_windows_do_not_follow_rtt() {
        // 流窗/连窗各端原静态值不动（缩窗钉吞吐：rjzw2 bench 实测，与本票无关的红线）。
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
    fn rtt_hint_parse_bounds() {
        // 纯解析单测（不碰进程 env——libtest 并行下全局 env 改动会污染窗组断言测试）。
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
        // 纯解析单测（不碰进程 env——libtest 并行下全局 env 改动会污染窗组断言测试）。
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

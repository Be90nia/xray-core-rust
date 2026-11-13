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
//! 现状：`max_send_buf` 恒等于各端静态保底（客户端 16MiB、服务端**按内存档位** 16/32MiB
//! ——tiny 16MiB，small 起 32MiB，档位表见 `xray_transport::h2_window` 模块头）；流窗/连窗
//! 亦保持各端原静态值（32/32MB 客户端、16/32MB 服务端）——rjzw2 bench 实测缩流窗 ≤26MB
//! 吞吐掉 14-31%（SETTINGS 窗是零预分配计数器，缩它只钉吞吐不省缓冲）。
//!
//! ## 吞吐上限的 RTT 依赖（定量）
//!
//! 下载在飞上限 = min(服务端 send_buf, 客户端收窗 32 MiB) ⇒ tiny 16 MiB / 其余 32 MiB，
//! 吞吐 = 在飞上限 ÷ 端到端 RTT（单位 MiB/s = 在飞上限 MiB ÷ RTT 秒；×1.049 ≈ MB/s）：
//! - 16 MiB ÷ 0.45 s ≈ 35 MiB/s（≈37 MB/s；用户真机 xhttp+CDN 实测 31-37 MB/s 同档）
//! - 16 MiB ÷ 0.29 s ≈ 55 MiB/s（历史 50-60 MB/s 档）
//! - 32 MiB ÷ 0.45 s ≈ 71 MiB/s（small 起取值；**勿改按 RTT 自适应**，rjzw2 前科）
//!
//! 32MiB 是上限不是预约（hyper 惰性分配，真实在途 = BDP ≈ 吞吐 × RTT ≈ 30MB 全机），
//! 故 512MB 档 96MiB 预算也成立。
//!
//! ## RTT 探针已删除（lf51l）
//!
//! 阶梯撤掉后探针**零消费者**（窗组恒为静态保底，结果只进一行 DEBUG 日志），却让每条
//! h2 代理连接多拨一条一次性 TCP（`register.rs` 在 xmux 池查找前 `resolve_rtt`）——bd
//! vkirx① 抓包实证的「stream-one 每会话多 1 条零字节 TCP（Rust 2 条 vs Go 1 条）」即它。
//! Go 侧本无此机制。`probe_rtt` / `resolve_rtt` / `XRAY_H2_RTT_HINT_MS` 一并删除；
//! 诊断 env 只保留 `XRAY_H2_FLOW_WINDOW_OVERRIDE_BYTES` /
//! `XRAY_H2_SEND_BUF_OVERRIDE_BYTES`（强制流窗/send_buf，bench 扫曲线用）。

use xray_frame::budget::plan::{MemoryPlan, MemoryTier};

/// 客户端静态保底 = bd wz2b C2 + c9oc F-A 修前原静态值（32MB 流窗 / 32MB 连窗 /
/// 16MiB send buf）——现在**恒为**客户端定窗结果，不再随 RTT 变。
pub(crate) const CLIENT_FALLBACK: H2Windows = H2Windows {
    stream_window: crate::transport::H2_INITIAL_STREAM_WINDOW,
    connection_window: crate::transport::H2_INITIAL_CONNECTION_WINDOW,
    max_send_buf: crate::transport::H2_MAX_SEND_BUF_SIZE,
};

/// 服务端静态保底 = 修前 `serve_http_conn` 原静态窗值（16MB 流窗 / 32MB 连窗）+ **按内存
/// 档位**的服务端 send_buf（tiny 16MiB、small/medium/large 32MiB；映射唯一源 =
/// [`crate::transport::h2_server_max_send_buf_for`]，档位表见 `h2_window` 模块头）。
/// ——**不得用客户端流窗常量**：客户端流窗 32MB 会把服务端原静态 16MB
/// 抬到 32MB（保底被偷改 → 「静态 vs 自适应」对比基线失效）。
pub(crate) fn server_fallback(tier: MemoryTier) -> H2Windows {
    H2Windows {
        stream_window: crate::transport::H2_SERVER_INITIAL_STREAM_WINDOW,
        connection_window: crate::transport::H2_SERVER_INITIAL_CONNECTION_WINDOW,
        max_send_buf: crate::transport::h2_server_max_send_buf_for(tier),
    }
}

/// bench/诊断专用：强制流窗字节数（conn=2×、send=同值），进程级显式值驱动，
/// 未设置零影响。bench 用它扫「窗-吞吐」曲线。
const ENV_OVERRIDE: &str = "XRAY_H2_FLOW_WINDOW_OVERRIDE_BYTES";

/// bench/诊断专用：仅覆盖 send_buf（流窗保持），与 [`ENV_OVERRIDE`] 组合可
/// 分离「流窗 vs send_buf」变量（rjzw2 断点实验用）。
const ENV_SEND_OVERRIDE: &str = "XRAY_H2_SEND_BUF_OVERRIDE_BYTES";

/// 一组 h2 握手期定死的流控参数（SETTINGS 初窗 + 每流发送缓冲）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct H2Windows {
    pub stream_window: u32,
    pub connection_window: u32,
    pub max_send_buf: usize,
}

/// 客户端 h2 窗组（恒 = [`CLIENT_FALLBACK`]，诊断 env 可覆盖）。
pub(crate) fn client_windows() -> H2Windows {
    windows_for("client", CLIENT_FALLBACK)
}

/// 服务端 h2 窗组（send_buf 按**进程档位**取值，诊断 env 可覆盖）。
pub(crate) fn server_windows() -> H2Windows {
    windows_for("server", server_fallback(MemoryPlan::cached().tier))
}

/// 定窗 + 定窗日志（唯一实现点；客户端/服务端共用，仅保底基不同）。
///
/// 窗值 = 各端静态保底，**唯二**能改动它们的是诊断 env 覆盖
/// （[`apply_env_overrides`]）。按 RTT 缩窗的错误见模块头（CDN 边缘 RTT ≠ 端到端
/// RTT）——RTT 已彻底退出定窗（lf51l 连日志标签一并删除）。
fn windows_for(role: &str, fallback: H2Windows) -> H2Windows {
    let mut w = fallback;
    apply_env_overrides(&mut w);
    crate::hot_log!(
        DEBUG,
        "h2_window role={} stream={} conn={} send={}",
        role,
        w.stream_window,
        w.connection_window,
        w.max_send_buf
    );
    w
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_fallback_equals_pre_rjzw2_static() {
        // 保底逐值等于修前原静态值（bd wz2b C2 + c9oc F-A）。
        assert_eq!(CLIENT_FALLBACK.stream_window, 32 * 1024 * 1024);
        assert_eq!(CLIENT_FALLBACK.connection_window, 32 * 1024 * 1024);
        assert_eq!(CLIENT_FALLBACK.max_send_buf, 16 * 1024 * 1024);
        assert_eq!(client_windows(), CLIENT_FALLBACK);
    }

    #[test]
    fn server_fallback_is_static_per_tier() {
        // 窗值固定；send_buf 按档位（tiny 16MiB；small/medium/large 32MiB）。
        let (tiny, rest) = (
            crate::transport::H2_SERVER_SEND_BUF_TINY_TIER,
            crate::transport::H2_SERVER_MAX_SEND_BUF_SIZE,
        );
        for (tier, send_buf) in [
            (MemoryTier::Tiny, tiny),
            (MemoryTier::Small, rest),
            (MemoryTier::Medium, rest),
            (MemoryTier::Large, rest),
        ] {
            let w = server_fallback(tier);
            assert_eq!(w.stream_window, 16 * 1024 * 1024, "{} 流窗（修前原静态）", tier.as_str());
            assert_eq!(w.connection_window, 32 * 1024 * 1024, "{} 连窗", tier.as_str());
            assert_eq!(w.max_send_buf, send_buf, "{} send buf", tier.as_str());
            assert_ne!(
                w.stream_window, CLIENT_FALLBACK.stream_window,
                "服务端保底不得用客户端流窗常量（保底被偷改 → 对比基线失效）"
            );
        }
        // 生产入口 = 进程档位对应保底（env 未设时逐值相等）。
        assert_eq!(server_windows(), server_fallback(MemoryPlan::cached().tier));
    }

    #[test]
    fn overrides_apply_flow_then_send() {
        // 覆盖应用纯函数（服务端保底基；hub 明文路径 = server_windows() 同源）。
        let base = server_fallback(MemoryTier::Large);
        let mut w = base;
        apply_overrides(&mut w, Some(4 * 1024 * 1024), None);
        assert_eq!(w.stream_window, 4 * 1024 * 1024);
        assert_eq!(w.connection_window, 8 * 1024 * 1024, "连窗 = 2× 流窗");
        assert_eq!(w.max_send_buf, 4 * 1024 * 1024);

        // send_buf 单覆盖不动流窗。
        let mut w = base;
        apply_overrides(&mut w, None, Some(6 * 1024 * 1024));
        assert_eq!(w.stream_window, base.stream_window);
        assert_eq!(w.connection_window, base.connection_window);
        assert_eq!(w.max_send_buf, 6 * 1024 * 1024);

        // 流窗整体覆盖优先于 send_buf 单覆盖。
        let mut w = base;
        apply_overrides(&mut w, Some(2 * 1024 * 1024), Some(6 * 1024 * 1024));
        assert_eq!(w.max_send_buf, 2 * 1024 * 1024);

        // 两者皆未设置 = 原样（逐值等于保底）。
        let mut w = base;
        apply_overrides(&mut w, None, None);
        assert_eq!(w, base);
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
}

//! h2 流控窗常量（规划 §5 B2.4「上浮 + re-export」，规划 §7 R17 纯移动判据）。
//!
//! 语义唯一源：splithttp h2 窗钉战役（bd wz2b / c9oc / sgdwm / rjzw2）。原驻
//! `xray-transport-splithttp/src/transport.rs`，因 masque（CONNECT-IP 单流隧道）
//! 与 splithttp 共用同一套 h2 窗调参，上浮到本 crate 供两 transport 共用；
//! splithttp 侧 `pub use` 保持 `crate::transport::H2_*` 路径可用，xray-core
//! `memory_budget` 交叉断言（bd sgdwm）与 client.rs 防回档测试不受影响。
//!
//! ## 服务端 send_buf 按**内存档位**两档取值（2026-11-15 修正：small 16→32MiB）
//!
//! 吞吐 = min(发送端 send_buf, 接收端收窗) ÷ 端到端 RTT（32 MiB ÷ 0.45 s ≈ 71 MiB/s）。
//! 档位唯一事实源 = `xray_frame::budget::plan::MemoryPlan`（进程级一次探测，见
//! `h2_server_max_send_buf_for`）——**不新造自适应机制，也不按 RTT 自适应**（rjzw2 前科：
//! 探测 RTT ≠ 端到端 RTT）：
//! - `tiny`（≤256MB）→ 8 MiB
//! - `small`（≤512MB）/ `medium`（≤1GB）/ `large`（>1GB）→ 32 MiB（对齐客户端收窗）
//!
//! **2026-11-15 生产回归修正**：11-13 拍的 small=16MiB 在真实 CDN 路径（RTT 200-450ms）
//! 把 512MB 档机器的下载在飞上限砍到一半（用户实测 60→30 MB/s，全 HTTP 族同抖）。
//! 模块头自己的论证也支持 32MiB：「32MiB 是上限不是预约，真实在途 = BDP ≈ 30MB 全机
//! 总量，512MB 档预算 96MiB 也够」。故 small 与 medium|large 同值，仅 tiny 保持 8MiB。

use xray_frame::budget::plan::MemoryTier;

/// bd wz2b C2 + bd c9oc F-A h2 窗钉修复常量（commit 8780187e，防回档）：
/// client.rs 主 builder 与 dialer.rs stream-one 共用（同批同值）。削弱任一值
/// 必红 client.rs `h2_window_pins_match_wz2b_c9oc`；内存面由 xray-core
/// `memory_budget` 登记簿交叉断言钉住（bd sgdwm）。
pub const H2_INITIAL_STREAM_WINDOW: u32 = 32 * 1024 * 1024;
/// 连接窗不低于流窗即不另成钉（bd c9oc F-A）。
pub const H2_INITIAL_CONNECTION_WINDOW: u32 = 32 * 1024 * 1024;
/// h2 每连接发送缓冲（bd wz2b：服务端收窗放大后 send buf 成次级钉；回档 1MB =
/// 上行钉 1MB/RTT）。**真缓冲**（连接级，SETTINGS 窗是零预分配计数器与此不同）⇒
/// 96MB 预算按连接数 × 本值入簿（bd sgdwm）。
pub const H2_MAX_SEND_BUF_SIZE: usize = 16 * 1024 * 1024;

/// 服务端 h2 收窗原静态值（bd rjzw2：修前 `serve_http_conn` 内联值——服务端**不得**
/// 复用客户端的 `H2_INITIAL_STREAM_WINDOW` 32MB，否则保底路径把服务端原静态
/// 16MB 抬到 32MB：保底被偷改 + 「现状静态 vs 自适应」对比基线失效）。
pub const H2_SERVER_INITIAL_STREAM_WINDOW: u32 = 16 * 1024 * 1024;
/// 服务端 h2 连窗原静态值（32MB）。
pub const H2_SERVER_INITIAL_CONNECTION_WINDOW: u32 = 32 * 1024 * 1024;
/// 服务端 h2 每连接发送缓冲**上限**（32MiB = `medium`/`large` 档取值，对齐客户端
/// 收窗 [`H2_INITIAL_STREAM_WINDOW`]）。`tiny`/`small` 档分别取
/// [`H2_SERVER_SEND_BUF_TINY_TIER`] / [`H2_SERVER_SEND_BUF_SMALL_TIER`]；实际生效值走
/// [`h2_server_max_send_buf_for`]（档位表见模块头）。**真缓冲**（连接级实分配）⇒
/// 预算簿按端点上限面登记（不求和）。
pub const H2_SERVER_MAX_SEND_BUF_SIZE: usize = 32 * 1024 * 1024;
/// 服务端 h2 每连接发送缓冲**tiny 档取值**（8MiB；≤256MB 机器不赌大缓冲）。
pub const H2_SERVER_SEND_BUF_TINY_TIER: usize = 8 * 1024 * 1024;
/// 服务端 h2 每连接发送缓冲**small 档取值**（32MiB = `medium`/`large` 同值）。
///
/// 2026-11-15 由 16MiB 上调：small 机（≤512MB）在真实 CDN 路径 RTT 200-450ms 下，
/// 16MiB 变成下载在飞硬上限 ⇒ 吞吐减半（用户实测 60→30，8/16/32 档位表拍板时
/// 只有 loopback 台数据，RTT≈0 掩盖了这条限制）。真实在途 = BDP ≈ 30MB 全机
/// 总量，512MB 档预算装得下（模块头论证同款）。
pub const H2_SERVER_SEND_BUF_SMALL_TIER: usize = 32 * 1024 * 1024;

/// 档位 → 服务端每连接 send_buf（**唯一映射点**；纯函数，单测按档注入不碰进程探测）。
///
/// 下载在飞上限 = min(本值, 客户端收窗 32MiB) ⇒ 三档 8 / 16 / 32 MiB ÷ 端到端 RTT。
/// **勿改成按 RTT 自适应**（rjzw2 前科）。
#[must_use]
pub fn h2_server_max_send_buf_for(tier: MemoryTier) -> usize {
    match tier {
        MemoryTier::Tiny => H2_SERVER_SEND_BUF_TINY_TIER,
        MemoryTier::Small => H2_SERVER_SEND_BUF_SMALL_TIER,
        MemoryTier::Medium | MemoryTier::Large => H2_SERVER_MAX_SEND_BUF_SIZE,
    }
}

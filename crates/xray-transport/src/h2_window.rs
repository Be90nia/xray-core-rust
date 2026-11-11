//! h2 流控窗常量（规划 §5 B2.4「上浮 + re-export」，规划 §7 R17 纯移动判据）。
//!
//! 语义唯一源：splithttp h2 窗钉战役（bd wz2b / c9oc / sgdwm / rjzw2）。原驻
//! `xray-transport-splithttp/src/transport.rs`，因 masque（CONNECT-IP 单流隧道）
//! 与 splithttp 共用同一套 h2 窗调参，上浮到本 crate 供两 transport 共用；
//! **值不变**——splithttp 侧 `pub use` 保持 `crate::transport::H2_*` 路径可用，
//! xray-core `memory_budget` 交叉断言（bd sgdwm）与 client.rs 防回档测试不受影响。

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
/// 服务端 h2 每连接发送缓冲原静态值（16MiB）。
pub const H2_SERVER_MAX_SEND_BUF_SIZE: usize = 16 * 1024 * 1024;

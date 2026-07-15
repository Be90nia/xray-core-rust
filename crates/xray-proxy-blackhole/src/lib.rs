//! Blackhole 代理协议
//!
//! 对应 Go 版本 [`proxy/blackhole`](https://github.com/XTLS/Xray-core/tree/main/proxy/blackhole)：
//! 一种出站处理器，静默吞掉整个连接的有效载荷，可选择向客户端回写一份预设响应。
//!
//! # 当前实现范围
//!
//! 完整翻译 Go 版本的响应配置（`ResponseConfig`、`NoneResponse`、`HTTPResponse`）
//! 与 `Handler::new`。`Handler::process` 接受任意 [`xray_buf::io::Writer`]，写出预设响应。
//!
//! Go 版本 `Process` 还涉及 `transport.Link`/`internet.Dialer`/`session`/`signal` 的交互，
//! 这些类型在 Rust 端尚未实现（dev-plan "动态分层" 原则）。等 `xray-transport` 提供
//! 等价的 `Link` 与 `Dialer` 后，可在 `Handler` 之上加一层 adapter 对接 `OutboundHandler` trait.

pub mod response;
pub mod handler;
pub mod dispatcher;

pub use handler::{BlackholeError, Handler};
pub use response::{get_internal_response, ResponseConfig};
pub use dispatcher::{make_blackhole_handler, BlackholeHandler};
pub use xray_proto::xray::proxy::blackhole::Config;

#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(
    test,
    allow(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 LogFacade/tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! # xray-transport-xdrive
//!
//! xdrive 传输族——对象存储（本地文件夹 / 云盘 / S3 / 模板）承载的 VLESS 流传输。
//! 对应 Go `transport/internet/xdrive/` @ `676eaf66`（tag v26.11.9）。
//!
//! ## 语义模型（Go 对齐）
//!
//! xdrive 没有真实 socket：Dial/Serve 以对象存储为介质交换分段 WAL——
//! dialer 生成会话 ID、在 `sessions/` 下投递 announce；listener 轮询 claim 后
//! 按 `streams/<sid>/{c2s,s2c}/` 分段 WAL 双向搬运数据；`.end` 结尾标记、
//! `.err` 对端失败标记、空洞超时、TTL 回收都在 WAL 层完成。
//!
//! ## 批次边界（bd hjtlk）
//!
//! - **B1**：crate 骨架 + `local` 后端 + WAL + Conn + Dial/Serve/Listener + 注册接线。
//! - **B2/B3/B4**：HTTP 客户端栈 + XMUX、`template`、`s3`、`google-drive`
//!   后端（[`storage::new_storage`] 对未知 service fail-visible）。
//! - **B5**：环形槽位（Go `slots.go`）+ 预热点池。
//! - **B6**：h3 请求面（`tlsSettings.alpn == ["h3"]` ⇒ storage 请求走 QUIC，同 Go `client.go` 的
//!   `http3.Transport` 分支）+ 三方向互操作锚。
//!
//! ## XMUX / mux 缺省口径（票面裁定，禁改）
//!
//! - `xmux` 缺省 = Go `XDriveConfig.Build`：整体为空 ⇒ `maxConnections {1,1}` （`google-drive` 且非
//!   h3 ⇒ `{4,4}`）+ `hMaxReusableSecs {1800,3000}`。
//! - **mux（Mux.Cool）缺省并发保持本仓既有 8**（`xray_core::outbound::
//!   outbound_mux_concurrency`，bd 1sl22 revert）——xdrive 的 lint 只**要求** mux
//!   开启，不触碰该缺省。
//!
//! ## 任务托管（§3.5.6 ①类）
//!
//! WAL flush/reader/discard 循环挂每连接 `SessionTasks`；listener 的
//! accept/collect 循环挂组件级 [`xray_frame::scope::ComponentScope`] + 显式取消令牌。
//! h3 的 QUIC driver 任务寿命 = 连接本身（随连接关闭自终，逐站登记）。禁裸 spawn。

/// 日志统一入口：域规范 target = `xray_frame::transport::xdrive`（同
/// websocket/splithttp 各 crate 惯例）。
pub(crate) static LOG: std::sync::LazyLock<xray_frame::logging::LogFacade> =
    std::sync::LazyLock::new(|| xray_frame::logging::LogFacade::new("transport::xdrive", vec![]));

pub mod client;
pub mod config;
pub mod conn;
// B6：h3 请求面（`tlsSettings.alpn == ["h3"]` 的 Go `http3.Transport` 分支）。
pub(crate) mod h3;
// B4：google-drive 后端（bd hjtlk；模块声明与 B3 的 s3 同排期落位）。
pub mod drive;
pub(crate) mod jsonpath;
pub mod local;
pub mod params;
pub mod register;
pub mod s3;
pub mod slots;
pub mod storage;
pub mod template;
pub mod wal;
pub mod xdrive;

pub use config::Config;
pub use conn::Conn;
pub use drive::DriveStorage;
pub use local::LocalStorage;
pub use params::Params;
pub use register::{register_dialer, register_listener};
pub use storage::{Entry, SlotStore, Storage, session_storage, shared_storage};
pub use template::TemplateStorage;
pub use wal::{WalReader, WalWriter};
pub use xdrive::{dial, serve};

//! xray-stress：Xray-core-rust 压测 harness。
//!
//! 独立二进制，只消费现有 crate 公开 API（`xray-core::functions::start_full`、
//! hysteria QUIC loopback、`xray-common::runtime_guard`），不碰生产代码。

pub mod quic_loop;
pub mod report;
pub mod sampler;
pub mod scenarios;
pub mod topology;

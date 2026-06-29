//! Trojan 出站处理器（client），对应 Go `proxy/trojan/client.go`。
//!
//! # 切片2 待实现
//!
//! 需要 `transport::Link` + `internet::Dialer` + `retry` + `signal` + `session` +
//! `policy::Manager` 等基础设施，依赖 P5 传输层与 P7 应用层模块完成。
//!
//! 切片2 工作：
//! - 实现 `Client` struct + `new_client(ctx, config)`
//! - 实现 `Process(ctx, link, dialer)`：拨号 → 写请求头 → 双向桥接
//! - 复用 `protocol::write_request_header` / `protocol::write_udp_packet`
//! - 用 `crate::protocol::parse_request_header` 在 server 端解析入站

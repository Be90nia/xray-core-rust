//! Trojan 入站处理器（server），对应 Go `proxy/trojan/server.go`。
//!
//! # 切片2 待实现
//!
//! 549 行 Go 代码涉及：
//! - `proxyman` 入站 handler 框架（依赖 P7 应用层）
//! - fallbacks 处理（HTTP/2 PROXY protocol 转发到 fallback dest）
//! - 会话管理 + 用户校验 + 流量统计
//!
//! 切片2 工作：
//! - 实现 `Server` struct + `new_server(ctx, config)` + `add_user/remove_user/get_user`
//! - 实现 `process(ctx, network, conn, dispatcher)`：解析请求头 → 校验 hash → 分发
//! - 实现 fallback 路径（HTTP/2 ALPN、dest = "addr:port" 或 80 等）
//! - 复用 `crate::protocol::parse_request_header` 与 `crate::validator::Validator`

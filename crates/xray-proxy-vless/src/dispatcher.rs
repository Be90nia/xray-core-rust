//! VLESS outbound → DialBridge 适配器（阶段 1 切片 1e）。
//!
//! VLESS 协议：拨号到 VLESS 服务器 → 在 TCP 流上写协议头（含目标地址）→ 返回连接。
//! 协议头由 [`encode_request_header`] 写入，之后双向透传——连接本身仍是底层 TCP。
//!
//! ## 范围
//!
//! 当前实现：VLESS over **raw TCP**（用于测试与无 TLS 场景）。
//! 生产场景（VLESS + TLS / REALITY）需在上层注入 TLS-wrapped 拨号闭包，
//! 或扩展 [`VlessOutboundConfig`] 支持 `dial_fn: Option<DialToServerFn>`。
//!
//! [`DialBridge`]: xray_app_dispatcher::default::DialBridge
//! [`DialFn`]: xray_app_dispatcher::default::DialFn
//! [`Connection`]: xray_transport::connection::Connection

use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use xray_app_dispatcher::default::DialFn;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_common::uuid::UUID;
use xray_proto::xray::proxy::vless::encoding::Addons;
use xray_transport::connection::Connection;
use xray_transport::dialer::{dial, StreamSettings};
use xray_transport::sockopt::SocketOptions;

use crate::encoding::{client::encode_request_header, empty_addons, VlessCommand, VERSION};

/// VLESS outbound 配置（最小集）。
#[derive(Debug, Clone)]
pub struct VlessOutboundConfig {
    /// 用户 UUID（远端 VLESS 服务端已注册）。
    pub user_uuid: UUID,
    /// VLESS 服务器地址（IP 优先；Domain 触发 dial_system DNS 解析）。
    pub server_address: Address,
    /// VLESS 服务器端口。
    pub server_port: Port,
    /// 可选 streamSettings（TLS/WS/gRPC/...）。None 走 raw TCP。
    pub stream_settings: Option<StreamSettings>,
}

impl VlessOutboundConfig {

    /// 构造（raw TCP，无 streamSettings）。
    #[must_use]
    pub fn new(user_uuid: UUID, server_address: Address, server_port: Port) -> Self {
        Self {
            user_uuid,
            server_address,
            server_port,
            stream_settings: None,
        }
    }

    /// 指定 streamSettings（builder 风格）。
    ///
    /// `Some(ws_settings)` 后拨号走 ws transport；`None` 回退 raw TCP。
    #[must_use]
    pub fn with_stream_settings(mut self, settings: Option<StreamSettings>) -> Self {
        self.stream_settings = settings;
        self
    }

    /// 服务器 Destination（TCP）。
    fn server_destination(&self) -> Destination {
        Destination::new(
            self.server_address.clone(),
            self.server_port,
            Network::TCP,
        )
    }
}


/// 构造 VLESS 的 DialFn 闭包。
///
/// 闭包捕获 `Arc<VlessOutboundConfig>`，每次调用：
/// 1. dial_system 到 VLESS 服务器 → `Box<dyn Connection>`
/// 2. `encode_request_header` 写 VLESS 头（含目标地址）到连接
/// 3. 返回连接（已是带 VLESS 头的 TCP，后续双向透传）
///
/// # Panics
///
/// 不会 panic；任何错误以 `Err(String)` 返回。
pub fn make_dial_fn(config: Arc<VlessOutboundConfig>) -> DialFn {
    Arc::new(move |dest: &Destination| {
        let config = Arc::clone(&config);
        let target_addr = dest.address().clone();
        let target_port = dest.port();
        Box::pin(async move {
            // 1. dial VLESS server：有 streamSettings 走 transport dialer（ws/grpc/...），否则裸 TCP。
            let server_dest = config.server_destination();
            let sockopt = SocketOptions::default();
            let mut conn: Box<dyn Connection> = match &config.stream_settings {
                Some(s) => dial(&server_dest, s, &sockopt)
                    .await
                    .map_err(|e| format!("vless dial server ({}): {e}", s.protocol))?,
                None => xray_transport::system_dialer::dial_system(&server_dest, &sockopt)
                    .await
                    .map_err(|e| format!("vless dial server (tcp): {e}"))?,
            };

            // 2. 写 VLESS 请求头（version + uuid + addons + command + target addr/port）
            let addons = empty_addons();
            encode_request_header(
                &mut conn,
                VERSION,
                &config.user_uuid,
                VlessCommand::Tcp,
                Some(&target_addr),
                Some(target_port.value()),
                &addons,
            )
            .await
            .map_err(|e| format!("vless encode header: {e}"))?;

            // 2b. 读取服务端响应头（version + addon_len = 2 bytes），防止泄漏到数据流
            crate::encoding::client::decode_response_header(&mut conn, VERSION)
                .await
                .map_err(|e| format!("vless decode response header: {e}"))?;

            // 3. conn 现在是 "已握手完成的 TCP"，bridge_link_with_stream 直接用
            Ok(conn)
        })
    })
}

/// 兼容：直接传 Addons（高级用户可注入 flow）。
#[allow(dead_code)]
pub fn make_dial_fn_with_addons(config: Arc<VlessOutboundConfig>, addons: Addons) -> DialFn {
    Arc::new(move |dest: &Destination| {
        let config = Arc::clone(&config);
        let addons = addons.clone();
        let target_addr = dest.address().clone();
        let target_port = dest.port();
        Box::pin(async move {
            let server_dest = config.server_destination();
            let sockopt = SocketOptions::default();
            let mut conn: Box<dyn Connection> = match &config.stream_settings {
                Some(s) => dial(&server_dest, s, &sockopt)
                    .await
                    .map_err(|e| format!("vless dial server ({}): {e}", s.protocol))?,
                None => xray_transport::system_dialer::dial_system(&server_dest, &sockopt)
                    .await
                    .map_err(|e| format!("vless dial server (tcp): {e}"))?,
            };
            encode_request_header(
                &mut conn,
                VERSION,
                &config.user_uuid,
                VlessCommand::Tcp,
                Some(&target_addr),
                Some(target_port.value()),
                &addons,
            )
            .await
            .map_err(|e| format!("vless encode header: {e}"))?;

            crate::encoding::client::decode_response_header(&mut conn, VERSION)
                .await
                .map_err(|e| format!("vless decode response header: {e}"))?;
            Ok(conn)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_common::net::address::Address;
    use xray_common::uuid::UUID;

    #[test]
    fn config_server_destination_roundtrip() {
        let uuid = UUID::new();
        let cfg = VlessOutboundConfig::new(
            uuid,
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(443),
        );
        let dest = cfg.server_destination();
        assert!(dest.is_tcp());
        assert_eq!(dest.port(), Port::new(443));
    }

    #[test]
    fn make_dial_fn_returns_arc_closure() {
        // 仅验证构造不 panic + Arc 计数正确
        let uuid = UUID::new();
        let cfg = Arc::new(VlessOutboundConfig::new(
            uuid,
            Address::new_domain("example.com"),
            Port::new(443),
        ));
        let _dial = make_dial_fn(Arc::clone(&cfg));
        assert_eq!(Arc::strong_count(&cfg), 2);
    }
}

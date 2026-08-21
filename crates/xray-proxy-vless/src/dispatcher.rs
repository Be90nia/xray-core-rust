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
use crate::encryption::vision_conn::VisionConn;
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

/// VLESS outbound 配置。
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
    /// Flow 标识（如 `xtls-rprx-vision`）。空串表示无 flow。
    /// 对应 Go `infra/conf` outbound user 的 `flow` 字段。
    pub flow: String,
    /// 加密方式（默认 `none`，对应 VLESS 无加密；其他值交给 encryption 层）。
    pub encryption: String,
    /// 用户 level（policy/stats 系统用）。
    pub level: u32,
    /// 用户 email（stats 系统标识用）。
    pub email: String,
}

impl VlessOutboundConfig {

    /// 构造（raw TCP，无 streamSettings）。
    pub fn new(user_uuid: UUID, server_address: Address, server_port: Port) -> Self {
        Self {
            user_uuid,
            server_address,
            server_port,
            stream_settings: None,
            flow: String::new(),
            encryption: "none".to_string(),
            level: 0,
            email: String::new(),
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

    /// 设置 flow（builder 风格）。
    #[must_use]
    pub fn with_flow(mut self, flow: impl Into<String>) -> Self {
        self.flow = flow.into();
        self
    }

    /// 设置 encryption（builder 风格）。
    #[must_use]
    pub fn with_encryption(mut self, encryption: impl Into<String>) -> Self {
        self.encryption = encryption.into();
        self
    }

    /// 设置用户 level（builder 风格）。
    #[must_use]
    pub fn with_level(mut self, level: u32) -> Self {
        self.level = level;
        self
    }

    /// 设置用户 email（builder 风格）。
    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = email.into();
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
            let sockopt = config.stream_settings.as_ref().map(|s| s.socket_options()).unwrap_or_default();
            let mut conn: Box<dyn Connection> = match &config.stream_settings {
                Some(s) => dial(&server_dest, s, &sockopt)
                    .await
                    .map_err(|e| format!("vless dial server ({}): {e}", s.protocol))?,
                None => xray_transport::system_dialer::dial_system(&server_dest, &sockopt)
                    .await
                    .map_err(|e| format!("vless dial server (tcp): {e}"))?,
            };

            // 2. 写 VLESS 请求头（version + uuid + addons + command + target addr/port）
            // addons.flow 从 config 取（bd vxk）：flow=xtls-rprx-vision 时服务端启用 Vision。
            let mut addons = empty_addons();
            addons.flow = config.flow.clone();
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

            // 3. flow=xtls-rprx-vision（encryption=none）：请求/响应头交换完成后包装
            //    VisionConn——padding 从业务数据开始（对齐 Go outbound VisionWriter/
            //    VisionReader 的包装时机，首块 padding 携带本账号 uuid）。
            //    ENC(mlkem768)+vision 组合走 CommonConn，见 bd 4lf/byo。
            if config.flow == crate::FLOW_XRV && config.encryption == "none" {
                let uuid_bytes = config.user_uuid.as_bytes().to_vec();
                conn = Box::new(VisionConn::new(conn, uuid_bytes));
            }

            // conn 现在是 "已握手完成的 TCP"，bridge_link_with_stream 直接用
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
            let sockopt = config.stream_settings.as_ref().map(|s| s.socket_options()).unwrap_or_default();
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

    /// flow 字段上线验证：config.flow 经 make_dial_fn 写入请求头 addons.flow，
    /// 服务端 decode_request_header 应读到 xtls-rprx-vision。
    #[tokio::test]
    async fn make_dial_fn_sends_flow_in_request_header() {
        use crate::encoding::server::decode_request_header;
        use crate::{MemoryAccount, MemoryUser, MemoryValidator, Validator as _};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};
        use xray_proto::xray::proxy::vless::Account as ProtoAccount;

        let test_uuid = UUID::parse("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();

        // fake VLESS server：decode 请求头 → 断言 flow → 回响应头
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let validator = MemoryValidator::new();
        let mut proto_account = ProtoAccount::default();
        proto_account.id = "b831381d-6324-4d53-ad4f-8cda48b30811".to_string();
        let account = MemoryAccount::from_proto_account(&proto_account).unwrap();
        validator.add(MemoryUser::new("u", 0, account)).unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let decoded = decode_request_header(false, &mut None, &mut sock, &validator)
                .await
                .unwrap();
            // 回响应头（version + addon_len）
            crate::encoding::server::encode_response_header(&mut sock, VERSION, &empty_addons())
                .await
                .unwrap();
            // drain 剩余（如果有）
            let mut buf = [0u8; 64];
            let _ = sock.read(&mut buf).await;
            decoded.addons.flow
        });

        // client：make_dial_fn（flow=xtls-rprx-vision）
        let cfg = Arc::new(
            VlessOutboundConfig::new(test_uuid, Address::from_ipv4_bytes([127, 0, 0, 1]), Port::new(addr.port()))
                .with_flow("xtls-rprx-vision"),
        );
        let dial = make_dial_fn(cfg);
        let dest = Destination::tcp(Address::new_domain("target.example.com"), Port::new(80));
        let mut conn = dial(&dest).await.expect("dial should succeed");
        let _ = conn.write_all(b"x").await; // 触发服务端 drain

        let flow = server.await.unwrap();
        assert_eq!(flow, "xtls-rprx-vision", "flow must reach server request header");
    }

    /// flow=XRV 时 make_dial_fn 返回的连接必须已包 VisionConn：首个业务写入
    /// 在线上是 Vision padding 帧 `[uuid(16)][command][content_len(2 BE)]
    /// [padding_len(2 BE)][content]`，而非裸 payload。未包装 → 首字节非 uuid → fail。
    #[tokio::test]
    async fn make_dial_fn_wraps_conn_with_vision_when_flow_xrv() {
        use crate::encryption::vision::COMMAND_PADDING_CONTINUE;
        use crate::encoding::server::decode_request_header;
        use tokio::time::{timeout, Duration};
        use crate::{MemoryAccount, MemoryUser, MemoryValidator, Validator as _};
        use tokio::io::AsyncReadExt as _;
        use xray_proto::xray::proxy::vless::Account as ProtoAccount;

        let test_uuid = UUID::parse("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();

        // fake VLESS server：decode 请求头 → 回响应头 → 裸读线上首段业务字节
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let validator = MemoryValidator::new();
        let mut proto_account = ProtoAccount::default();
        proto_account.id = "b831381d-6324-4d53-ad4f-8cda48b30811".to_string();
        let account = MemoryAccount::from_proto_account(&proto_account).unwrap();
        validator.add(MemoryUser::new("u", 0, account)).unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _ = decode_request_header(false, &mut None, &mut sock, &validator)
                .await
                .unwrap();
            crate::encoding::server::encode_response_header(&mut sock, VERSION, &empty_addons())
                .await
                .unwrap();
            // uuid(16)+command(1)+content_len(2)+padding_len(2)+payload(14) = 35
            let mut wire = [0u8; 35];
            sock.read_exact(&mut wire).await.unwrap();
            wire.to_vec()
        });

        // client：make_dial_fn（flow=xtls-rprx-vision）
        let cfg = Arc::new(
            VlessOutboundConfig::new(
                test_uuid.clone(),
                Address::from_ipv4_bytes([127, 0, 0, 1]),
                Port::new(addr.port()),
            )
            .with_flow("xtls-rprx-vision"),
        );
        let dial = make_dial_fn(cfg);
        let dest = Destination::tcp(Address::new_domain("target.example.com"), Port::new(80));
        let mut conn = dial(&dest).await.expect("dial should succeed");
        conn.write_all(b"vision-payload").await.unwrap();
        conn.flush().await.unwrap();
        drop(conn);

        let wire = timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
        let payload: &[u8] = b"vision-payload";
        assert_eq!(
            &wire[..16],
            test_uuid.as_bytes(),
            "first uplink block must start with user uuid"
        );
        assert_eq!(wire[16], COMMAND_PADDING_CONTINUE, "data frame command");
        assert_eq!(&wire[17..19], &[0, payload.len() as u8], "content_len BE");
        assert_eq!(&wire[21..21 + payload.len()], payload, "content after frame header");
    }
}

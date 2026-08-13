//! gRPC transport dialer + listener 注册。
//!
//! 对应 Go `transport/internet/grpc/dialer.go::init()` 中的
//! `internet.RegisterTransportDialer(protocolName, Dial(...))` 和
//! `transport/internet/grpc/hub.go::init()` 中的
//! `internet.RegisterTransportListener(protocolName, Listen(...))`。
//!
//! ## 调用
//!
//! 进程启动时调用一次 [`register_dialer`] 和 [`register_listener`]；幂等——重复注册的 `AlreadyExists` 被忽略。
//!
//! 对应 Go `transport/internet/grpc/dialer.go::dialgRPC` + `init()` 中的
//! `internet.RegisterTransportDialer(protocolName, Dial(...))`。
//!
//! ## 调用
//!
//! 进程启动时调用一次 [`register_dialer`]；幂等——重复注册的 `AlreadyExists` 被忽略。
//!
//! ## 切片边界
//!
//! 配置解析 + TLS config 构建 + 协议注册已就绪。实际 HTTP/2 + TLS 拨号待
//! h2/tonic 集成（见 crate `lib.rs` 切片边界文档）。dialer 闭包在解析配置
//! 后返回 `Unsupported` 错误，确保注册结构正确但不假装能建立连接。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use xray_common::net::destination::Destination;
use xray_transport::connection::Connection;
use xray_transport::dialer::{
    StreamSettings, TransportDialFn, register_transport_dialer,
};
use xray_transport::listener_registry::{
    ConnHandler, TransportListenFn, TransportListener,
    register_transport_listener,
};

use crate::config::Config;

/// 注册 gRPC transport dialer。
///
/// 协议名同时注册 `"grpc"` / `"h2"` / `"http"`——Go 端 JSON `network` 字段
/// 这三种值都映射到 `grpcSettings`（见 `xray_transport::dialer::protocol_settings_key`）。
///
/// 幂等：重复调用忽略 `AlreadyExists`（对齐 Go `init()` 在测试中多次执行的容错）。
pub fn register_dialer() -> io::Result<()> {
    let dialer: TransportDialFn = Arc::new(move |dest, _sockopt, settings| {
        // TransportDialFn 返回 'static future，必须在进入 async block 前拥有数据。
        let dest = dest.clone();
        let settings = settings.clone();
        Box::pin(async move { dial_grpc(&dest, &settings).await })
    });
    // ponytail: 重复注册忽略——主代理与测试可能并发触发注册。
    let _ = register_transport_dialer("grpc", dialer.clone());
    let _ = register_transport_dialer("h2", dialer.clone());
    let _ = register_transport_dialer("http", dialer);
    Ok(())
}

/// 注册 gRPC transport listener。
///
/// 协议名同时注册 `"grpc"` / `"h2"` / `"http"`，与 [`register_dialer`] 一致。
///
/// 当前返回 `Unsupported`：HTTP/2 server 监听依赖 h2/tonic 集成。
/// 配置解析已执行，确保错误前的路径可测。
///
/// 幂等：重复调用忽略 `AlreadyExists`。
pub fn register_listener() -> io::Result<()> {
    let listen_fn: TransportListenFn = Arc::new(move |addr, settings, _sockopt, handler| {
        let settings = settings.clone();
        let handler = handler.clone();
        Box::pin(async move { listen_grpc(addr, &settings, handler).await })
    });
    let _ = register_transport_listener("grpc", listen_fn.clone());
    let _ = register_transport_listener("h2", listen_fn.clone());
    let _ = register_transport_listener("http", listen_fn);
    Ok(())
}

/// 实际监听：解析 grpcSettings → 返回 Unsupported。
///
/// 当前返回 `Unsupported`：HTTP/2 server 监听依赖 h2/tonic 集成。
/// 配置解析已执行，确保错误前的路径可测。
async fn listen_grpc(addr: SocketAddr, settings: &StreamSettings, handler: ConnHandler) -> io::Result<Box<dyn TransportListener>> {
    crate::transport::listen(addr, settings, handler).await
}

/// 实际拨号：解析 grpcSettings → tls config → 调用 client 建立连接。
///
/// 当前返回 `Unsupported`：HTTP/2 + TLS 拨号依赖 h2/tonic 集成（见 crate 文档）。
/// 配置解析与 TLS 构建已执行，确保错误前的路径可测。
async fn dial_grpc(dest: &Destination, settings: &StreamSettings) -> io::Result<Box<dyn Connection>> {
    crate::transport::dial(dest, settings).await
}

/// 从 `grpcSettings` JSON 解析为强类型 [`Config`]。
///
/// 接受的 JSON 字段（对齐 proto3 JSON camelCase）：
/// - `serviceName`：gRPC 服务名（传统格式或自定义路径 `/A/B/Tun|TunMulti`）
/// - `multiMode`：是否启用 multi-stream 模式
/// - `authority`：HTTP/2 `:authority` 伪 header
/// - `idleTimeout`：空闲超时（秒）
/// - `healthCheckTimeout`：健康检查超时（秒）
/// - `permitWithoutStream`：无活动 stream 时是否发送 keepalive
/// - `initialWindowSize`：HTTP/2 初始窗口大小（字节）
/// - `userAgent`：User-Agent（支持预设别名 chrome/firefox/edge/golang）
///
/// `None` 或非 object 返回 [`Config::default`]。
fn parse_grpc_config(json: Option<&serde_json::Value>) -> io::Result<Config> {
    let Some(v) = json else { return Ok(Config::default()); };
    let Some(obj) = v.as_object() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "grpcSettings must be a JSON object",
        ));
    };

    let authority = obj
        .get("authority")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let service_name = obj
        .get("serviceName")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let multi_mode = obj
        .get("multiMode")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let idle_timeout = obj
        .get("idleTimeout")
        .and_then(|x| x.as_i64())
        .unwrap_or(0) as i32;
    let health_check_timeout = obj
        .get("healthCheckTimeout")
        .and_then(|x| x.as_i64())
        .unwrap_or(0) as i32;
    let permit_without_stream = obj
        .get("permitWithoutStream")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let initial_windows_size = obj
        .get("initialWindowSize")
        .and_then(|x| x.as_i64())
        .unwrap_or(0) as i32;
    let user_agent = obj
        .get("userAgent")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();

    Ok(Config {
        authority,
        service_name,
        multi_mode,
        idle_timeout,
        health_check_timeout,
        permit_without_stream,
        initial_windows_size,
        user_agent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_transport::dialer::get_transport_dialer;

    #[test]
    fn parse_grpc_config_none_returns_default() {
        let cfg = parse_grpc_config(None).unwrap();
        assert!(cfg.service_name.is_empty());
        assert!(cfg.authority.is_empty());
        assert!(!cfg.multi_mode);
        assert_eq!(cfg.idle_timeout, 0);
        assert_eq!(cfg.user_agent, "");
    }

    #[test]
    fn parse_grpc_config_basic_fields() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"serviceName":"GunService","multiMode":true,"userAgent":"chrome"}"#,
        )
        .unwrap();
        let cfg = parse_grpc_config(Some(&v)).unwrap();
        assert_eq!(cfg.service_name, "GunService");
        assert!(cfg.multi_mode);
        assert_eq!(cfg.user_agent, "chrome");
    }

    #[test]
    fn parse_grpc_config_custom_path_service_name() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"serviceName":"/A/B/Tun|TunMulti","multiMode":true}"#,
        )
        .unwrap();
        let cfg = parse_grpc_config(Some(&v)).unwrap();
        assert_eq!(cfg.service_name, "/A/B/Tun|TunMulti");
        assert!(cfg.multi_mode);
        // Config::service_name() 解析在 config.rs 已测；这里只验证字段存储。
    }

    #[test]
    fn parse_grpc_config_all_numeric_fields() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"idleTimeout":60,"healthCheckTimeout":20,"initialWindowSize":65535}"#,
        )
        .unwrap();
        let cfg = parse_grpc_config(Some(&v)).unwrap();
        assert_eq!(cfg.idle_timeout, 60);
        assert_eq!(cfg.health_check_timeout, 20);
        assert_eq!(cfg.initial_windows_size, 65535);
    }

    #[test]
    fn parse_grpc_config_permit_without_stream() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"permitWithoutStream":true}"#).unwrap();
        let cfg = parse_grpc_config(Some(&v)).unwrap();
        assert!(cfg.permit_without_stream);
    }

    #[test]
    fn parse_grpc_config_authority_field() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"authority":"example.com","serviceName":"svc"}"#).unwrap();
        let cfg = parse_grpc_config(Some(&v)).unwrap();
        assert_eq!(cfg.authority, "example.com");
        assert_eq!(cfg.service_name, "svc");
    }

    #[test]
    fn parse_grpc_config_non_object_returns_err() {
        let v: serde_json::Value = serde_json::from_str(r#""not-an-object""#).unwrap();
        let r = parse_grpc_config(Some(&v));
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn parse_grpc_config_missing_fields_use_defaults() {
        let v: serde_json::Value = serde_json::from_str(r#"{}"#).unwrap();
        let cfg = parse_grpc_config(Some(&v)).unwrap();
        assert!(cfg.service_name.is_empty());
        assert!(!cfg.multi_mode);
        assert_eq!(cfg.idle_timeout, 0);
    }

    #[test]
    fn register_dialer_registers_all_protocol_names() {
        register_dialer().unwrap();
        assert!(get_transport_dialer("grpc").is_some());
        assert!(get_transport_dialer("h2").is_some());
        assert!(get_transport_dialer("http").is_some());
    }

    #[tokio::test]
    async fn dial_grpc_attempts_connection() {
        // gRPC dialer 现在尝试 h2 连接（不再返回 Unsupported）。
        // 连接 localhost:443 应失败（无监听）但不返回 Unsupported。
        use xray_common::net::address::Address;
        use xray_common::net::destination::Destination;
        use xray_common::net::network::Network;
        use xray_common::net::port::Port;
        use std::net::Ipv4Addr;

        let dest = Destination::new(
            Address::IPv4(Ipv4Addr::LOCALHOST),
            Port::new(1), // port 1 = 无服务
            Network::TCP,
        );
        let settings = StreamSettings {
            protocol: "grpc".to_string(),
            transport_json: Some(serde_json::json!({"serviceName":"GunService"})),
            ..StreamSettings::tcp()
        };
        let result = dial_grpc(&dest, &settings).await;
        assert!(result.is_err(), "should fail (no h2 server at localhost:1)");
        let err = result.err().unwrap();
        assert!(
            err.kind() != io::ErrorKind::Unsupported,
            "should not be Unsupported anymore"
        );
    }
}

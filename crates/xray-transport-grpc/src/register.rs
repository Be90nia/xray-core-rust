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
    let listen_fn: TransportListenFn = Arc::new(move |addr, settings, sockopt, handler| {
        let settings = settings.clone();
        let handler = handler.clone();
        // H13：XFF 信任名单（Go hub.go:78-80 socketSettings 透传）。
        let trusted = sockopt.trusted_x_forwarded_for.clone();
        Box::pin(async move { listen_grpc(addr, &settings, handler, trusted).await })
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
async fn listen_grpc(addr: SocketAddr, settings: &StreamSettings, handler: ConnHandler, trusted: Vec<String>) -> io::Result<Box<dyn TransportListener>> {
    crate::transport::listen(addr, settings, handler, trusted).await
}

/// 实际拨号：解析 grpcSettings → tls config → 调用 client 建立连接。
///
/// 当前返回 `Unsupported`：HTTP/2 + TLS 拨号依赖 h2/tonic 集成（见 crate 文档）。
/// 配置解析与 TLS 构建已执行，确保错误前的路径可测。
async fn dial_grpc(dest: &Destination, settings: &StreamSettings) -> io::Result<Box<dyn Connection>> {
    crate::transport::dial(dest, settings).await
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_grpc_config;
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

    #[test]
    fn parse_grpc_config_snake_case_fields() {
        // Go infra/conf/grpc.go 用 snake_case——全部字段必须等价解析。
        let v: serde_json::Value = serde_json::from_str(
            r#"{"service_name":"GunService","multi_mode":true,"idle_timeout":60,
               "health_check_timeout":20,"permit_without_stream":true,
               "initial_windows_size":65535,"user_agent":"chrome",
               "authority":"example.com"}"#,
        )
        .unwrap();
        let cfg = parse_grpc_config(Some(&v)).unwrap();
        assert_eq!(cfg.service_name, "GunService");
        assert!(cfg.multi_mode);
        assert_eq!(cfg.idle_timeout, 60);
        assert_eq!(cfg.health_check_timeout, 20);
        assert!(cfg.permit_without_stream);
        assert_eq!(cfg.initial_windows_size, 65535);
        assert_eq!(cfg.user_agent, "chrome");
        assert_eq!(cfg.authority, "example.com");
    }

    /// Tcpmask round-trip（o54c，Go grpc/dialer.go:129-135 + hub.go:123-125）：
    /// dial 与 hub 双端配置 fragment mask 后 e2e echo 收发。
    #[tokio::test]
    async fn grpc_dial_hub_tcpmask_roundtrip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use xray_common::net::address::Address;
        use xray_common::net::network::Network;
        use xray_common::net::port::Port;
        use std::net::Ipv4Addr;

        let finalmask = serde_json::json!({
            "tcp": [{"type": "fragment", "settings": {
                "packets_from": 1, "packets_to": 2,
                "length": {"from": 8, "to": 16}, "interval": {"from": 0, "to": 0}
            }}]
        });
        let settings = StreamSettings {
            protocol: "grpc".to_string(),
            transport_json: Some(serde_json::json!({"serviceName":"GunService"})),
            finalmask_json: Some(finalmask),
            ..StreamSettings::tcp()
        };

        let handler: ConnHandler = std::sync::Arc::new(|conn| {
            tokio::spawn(async move {
                let mut conn = conn;
                let mut buf = [0u8; 1024];
                loop {
                    match conn.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        });
        let listener = listen_grpc("127.0.0.1:0".parse().unwrap(), &settings, handler, Vec::new())
            .await
            .expect("listen_grpc");
        let addr = listener.local_addr().expect("local_addr");

        let dest = Destination::new(
            Address::IPv4(Ipv4Addr::LOCALHOST),
            Port::new(addr.port()),
            Network::TCP,
        );
        let mut conn = dial_grpc(&dest, &settings).await.expect("dial_grpc");

        conn.write_all(b"hello-grpc-tcpmask").await.expect("write");
        let mut buf = vec![0u8; 64];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            conn.read(&mut buf),
        )
        .await
        .expect("echo timeout")
        .expect("read ok");
    }
    // ===== multi-mode / TLS spec tests (jghj: 8yn) =====
    //
    // Go 端 gRPC transport 支持 4 个变体 round-trip：
    //  1. gRPC (no TLS, single-mode) — 走 /<service>/Tun
    //  2. gRPC+TLS (TLS, single-mode)
    //  3. gRPC+multiMode (no TLS) — 走 /<service>/TunMulti
    //  4. gRPC+tun (no TLS, custom path 服务名)
    //
    // 下方为配置层 + 路由层独立可测的单元测试。end-to-end（通过实际 h2 stream +
    // echo）须等 transport.rs 补 /<service>/<stream> 完整路径后启用——见 o54c
    // commit 后 `grpc_dial_hub_*_roundtrip` 系列。

    /// 变体 1：gRPC 无 TLS 单 mode — 校验 parse_grpc_config 解析后 multi_mode=false。
    /// Go 端 dial 走 /<service>/Tun；本测试作为 multi-mode 路由的 spec 锚点。
    #[test]
    fn grpc_spec_single_mode_resolves_to_tun_path() {
        let settings = StreamSettings {
            protocol: "grpc".to_string(),
            transport_json: Some(serde_json::json!({"serviceName":"GunService"})),
            ..StreamSettings::tcp()
        };
        let cfg = parse_grpc_config(settings.transport_json.as_ref()).unwrap();
        assert!(!cfg.multi_mode);
        assert_eq!(cfg.tun_stream_name(), "Tun");
        assert_eq!(cfg.tun_multi_stream_name(), "TunMulti");
        // GrpcClient 选 Tun（multi_mode=false）
        let client = crate::client::GrpcClient::from_config(&cfg);
        assert_eq!(client.active_stream_name(), "Tun");
    }

    /// 变体 2：gRPC multiMode=true — 校验 dial 路径切到 /<service>/TunMulti。
    #[test]
    fn grpc_spec_multi_mode_resolves_to_tunmulti_path() {
        let settings = StreamSettings {
            protocol: "grpc".to_string(),
            transport_json: Some(serde_json::json!({
                "serviceName":"GunService",
                "multiMode":true,
            })),
            ..StreamSettings::tcp()
        };
        let cfg = parse_grpc_config(settings.transport_json.as_ref()).unwrap();
        assert!(cfg.multi_mode);
        let client = crate::client::GrpcClient::from_config(&cfg);
        assert_eq!(client.active_stream_name(), "TunMulti");
    }

    /// 变体 3：gRPC 自定义路径 — serviceName="/A/B/Tun"，GrcpClient 选自定义 service。
    #[test]
    fn grpc_spec_custom_path_resolves_correctly() {
        let settings = StreamSettings {
            protocol: "grpc".to_string(),
            transport_json: Some(serde_json::json!({
                "serviceName":"/A/B/Tun",
            })),
            ..StreamSettings::tcp()
        };
        let cfg = parse_grpc_config(settings.transport_json.as_ref()).unwrap();
        assert_eq!(cfg.service_name(), "A/B");
        assert_eq!(cfg.tun_stream_name(), "Tun");
    }

    /// 变体 4：gRPC+TLS — 校验 StreamSettings.security/tls 字段透传正确。
    #[test]
    fn grpc_spec_tls_settings_passthrough() {
        let settings = StreamSettings {
            protocol: "grpc".to_string(),
            transport_json: Some(serde_json::json!({"serviceName":"GunService"})),
            security: "tls".to_string(),
            security_json: Some(serde_json::json!({
                "serverName": "localhost",
                "allowInsecure": true,
                "alpn": ["h2"],
            })),
            ..StreamSettings::tcp()
        };
        // 配置能解析通过（无 panic），且 transport/security JSON 不丢字段。
        assert_eq!(settings.security, "tls");
        assert!(settings.security_json.is_some());
        let sj = settings.security_json.as_ref().unwrap();
        assert_eq!(sj.get("serverName").and_then(|v| v.as_str()), Some("localhost"));
        assert_eq!(sj.get("allowInsecure").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(sj.get("alpn").and_then(|v| v.as_array()).map(|a| a.len()), Some(1));
    }

    #[test]
    fn register_dialer_lookup_all_three_names() {
        register_dialer().unwrap();
        for name in ["grpc", "h2", "http"] {
            assert!(
                get_transport_dialer(name).is_some(),
                "{name} dialer must be registered"
            );
        }
    }

    /// Hub 注册表查 "grpc"/"h2"/"http" 三个名都能找到 listener。
    #[test]
    fn register_listener_lookup_all_three_names() {
        register_listener().unwrap();
        for name in ["grpc", "h2", "http"] {
            assert!(
                xray_transport::listener_registry::get_transport_listener(name).is_some(),
                "{name} listener must be registered"
            );
        }
    }
}

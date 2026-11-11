//! MASQUE 客户端拨号（Go `transport/internet/masque/dialer.go dialHTTP2` 直译）。
//!
//! 层序（规划 §5 B2.6，Go `dialHTTP2:182-191` 同款）：TCP → **finalmask（TCP 后、
//! TLS 前）** → TLS（指纹走 btls / 否则 rustls，同 splithttp/grpc 调用序）→
//! ALPN=h2 硬校验 → [`crate::h2::connect_h2`] → [`crate::connect::establish`]。
//!
//! 硬约束（extra 条款 `MASQUE-TLS-REQUIRED` / `MASQUE-H2-ONLY`）：`security=tls`
//! 必选；用户 ALPN 必须显式含 `h2` 且不含 `h3`——Go `hub.go:47-50` 对 ALPN 缺省
//! 的解释是走 h3，本仓 h3 押后（规划 §7 R11/R9），缺省即 fail-visible 硬错。
//!
//! `dial` 由聚合口 `xray_core::register::register_all_transports()` 包装成
//! [`xray_transport::dialer::TransportDialFn`] 注册（**本批不接聚合口**，规划 §5 B1.4）。

use std::time::Duration;

use xray_common::net::destination::Destination;
use xray_transport::{
    connection::{Connection, TcpConnection},
    dialer::StreamSettings,
    finalmask::{shared_tcpmask_manager_from_json, wrap_conn_client_into_connection},
    sockopt::{SocketOptions, dial_client_tcp},
};

use crate::{
    config::Config,
    connect::{ConnectIpSession, establish},
    error::{MasqueError, Result},
    h2::connect_h2,
};

/// TCP 拨号外层超时（对齐 grpc/system_dialer DEFAULT_DIAL_TIMEOUT 16s）。
const TCP_DIAL_TIMEOUT: Duration = Duration::from_secs(16);

/// 客户端拨号：建立 CONNECT-IP 隧道并完成地址协商（Go `Dial` h2 分支）。
///
/// `sockopt` 本批未消费（显式收窗等运维面随 B4 接线批对齐 splithttp 同款）。
pub async fn dial(
    dest: &Destination,
    sockopt: &SocketOptions,
    settings: &StreamSettings,
    config: &Config,
) -> Result<ConnectIpSession> {
    let _ = sockopt;

    // MASQUE-TLS-REQUIRED：无 TLS 即硬错（Go dialHTTP2 前置 tlsConfig nil 检查）。
    if settings.security != "tls" {
        return Err(MasqueError::Protocol(format!(
            "masque: security must be \"tls\", got {:?}",
            settings.security
        )));
    }
    let security_json = settings.security_json.as_ref();

    // MASQUE-H2-ONLY：用户 ALPN 必须显式含 h2 且不含 h3（规划 §7 R9/R11）。
    let alpn = security_json.and_then(|v| v.get("alpn")).and_then(|v| v.as_array());
    let alpn_ok = alpn.is_some_and(|a| {
        a.iter().any(|x| x.as_str() == Some("h2")) && !a.iter().any(|x| x.as_str() == Some("h3"))
    });
    if !alpn_ok {
        return Err(MasqueError::Protocol(
            "masque: tlsSettings.alpn must explicitly include \"h2\" \
             (h3 is unsupported; Go treats a missing h2 as h3)"
                .into(),
        ));
    }

    let sni_owned = security_json
        .and_then(|v| v.get("serverName"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| dest.address().to_string());
    let tls_cfg =
        xray_tls::client_config::build_client_config("tls", security_json, &sni_owned)?
            .ok_or_else(|| MasqueError::Protocol("masque: TLS client config missing".into()))?;

    // 指纹解析（Go dialHTTP2:206 `tls.GetFingerprint`）。
    let fp_name = security_json
        .and_then(|v| v.as_object())
        .and_then(|m| m.get("fingerprint"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let fingerprint = if fp_name.is_empty() {
        None
    } else {
        Some(xray_tls::fingerprint::get_fingerprint(fp_name).map_err(|e| {
            MasqueError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("masque: invalid fingerprint: {e}"),
            ))
        })?)
    };

    // finalmask 配置解析前移到网络拨号之前（R12 fail-visible：配置含 finalmask 而
    // 不合法 → 装配期即报，不烧一次 TCP 拨号才发现；空 manager = 恒等）。
    let tcpmask = shared_tcpmask_manager_from_json(settings.finalmask_json.as_ref())?;

    // TCP（16s 上限；域名前置/CDN 后端下 IP 直连极快，DNS hang 不得拖死拨号）。
    let addr = format!("{}:{}", dest.address(), dest.port().value());
    let tcp =
        tokio::time::timeout(TCP_DIAL_TIMEOUT, dial_client_tcp(&addr)).await.map_err(|_| {
            MasqueError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "masque dial timeout",
            ))
        })??;
    tcp.set_nodelay(true).ok();

    // finalmask 包装（TCP 后、TLS 前——首字节 = mask 头而非 TLS record）。
    let conn: Box<dyn Connection> =
        wrap_conn_client_into_connection(&tcpmask, Box::new(TcpConnection::new(tcp)))?;

    // TLS（指纹走 btls 真实浏览器 ClientHello，否则 rustls——Go UClient/Client 同判）。
    // ALPN 硬校验在 Box 之前做：ConnInterface 实现挂在具体包装类型上
    // （Go dialHTTP2:226-230：协商非 h2 即断链）。
    let (negotiated, tls_stream): (String, Box<dyn Connection>) = match fingerprint {
        Some(fp) => {
            let c = xray_tls::utls::u_client(conn, &sni_owned, tls_cfg, fp, None, security_json)
                .await?;
            let n = xray_tls::ConnInterface::negotiated_protocol(&c).await;
            (n, Box::new(c))
        },
        None => {
            let c = xray_tls::utls::client(conn, &sni_owned, tls_cfg).await?;
            let n = xray_tls::ConnInterface::negotiated_protocol(&c).await;
            (n, Box::new(c))
        },
    };
    if negotiated != "h2" {
        return Err(MasqueError::Protocol(format!(
            "masque: the server negotiated \"{negotiated}\" instead of h2"
        )));
    }

    let authority = resolve_authority(config, &sni_owned, dest.port().value());
    let session = connect_h2(tls_stream, config, &authority).await?;
    establish(session).await
}

/// 请求 `:authority`（Go `dialer.go authority`）：config.host 优先；否则 SNI
/// （剥括号）+ 非 443 端口带端口，IPv6 字面量补括号。
fn resolve_authority(config: &Config, server_name: &str, port: u16) -> String {
    if !config.host.is_empty() {
        return config.host.clone();
    }
    let host = server_name.trim_start_matches('[').trim_end_matches(']');
    if host.contains(':') {
        if port == 443 {
            return format!("[{host}]");
        }
        return format!("[{host}]:{port}");
    }
    if port == 443 { host.to_string() } else { format!("{host}:{port}") }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, sync::Arc, time::Duration};

    use bytes::Bytes;
    use http::{Request, Response};
    use http_body_util::Full;
    use hyper::{body::Incoming, ext::Protocol, service::service_fn};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use xray_common::net::{address::Address, destination::Destination, port::Port};
    use xray_transport::sockopt::SocketOptions;

    use super::*;
    use crate::connect::test_support::{echo_loop, test_config, udp_v4_packet};

    /// rcgen 自签证书（SAN localhost）→ (PEM 证书, PEM 私钥, DER)。
    fn make_cert() -> (String, String, Vec<u8>) {
        let params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        let key_pair = rcgen::KeyPair::generate().expect("keypair");
        let cert = params.self_signed(&key_pair).expect("self signed");
        (cert.pem(), key_pair.serialize_pem(), cert.der().to_vec())
    }

    /// 真 TCP + TLS(rustls, pin) + h2 + 胶囊全链路 e2e：finalmask(None)=恒等接线 +
    /// ALPN 硬校验 + establish 地址协商 + IP 包往返。
    #[tokio::test]
    async fn dial_tls_loopback_e2e() {
        let (cert_pem, key_pem, cert_der) = make_cert();
        let server_json = serde_json::json!({
            "certificates": [{ "certificate": cert_pem, "key": key_pem }],
            "alpn": ["h2"],
        });
        let server_cfg = xray_tls::server_config::build_server_config("tls", Some(&server_json))
            .expect("server config builds")
            .expect("server config present");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        #[allow(
            clippy::disallowed_methods,
            reason = "测试基建 server accept 循环（spawn 三分类②），随用随弃"
        )]
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { break };
                let sc = Arc::clone(&server_cfg);
                #[allow(
                    clippy::disallowed_methods,
                    reason = "测试基建 per-conn server 任务（spawn 三分类②）"
                )]
                tokio::spawn(async move {
                    let tls = xray_tls::utls::server(
                        xray_transport::connection::TcpConnection::new(tcp),
                        sc,
                    )
                    .await
                    .expect("server tls accept");
                    let mut builder =
                        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                    let _ = builder
                        .http2()
                        .enable_connect_protocol()
                        .serve_connection_with_upgrades(
                            TokioIo::new(tls),
                            service_fn(|req: Request<Incoming>| async move {
                                let proto = req
                                    .extensions()
                                    .get::<Protocol>()
                                    .map_or_else(String::new, |p| p.as_str().to_string());
                                assert_eq!(proto, "connect-ip");
                                let upgrade = hyper::upgrade::on(req);
                                #[allow(
                                    clippy::disallowed_methods,
                                    reason = "测试基建 upgrade 回声任务（spawn 三分类②）"
                                )]
                                tokio::spawn(async move {
                                    if let Ok(io) = upgrade.await {
                                        echo_loop(
                                            io,
                                            crate::connect::test_support::ServerBehavior::Echo,
                                        )
                                        .await;
                                    }
                                });
                                Ok::<_, std::convert::Infallible>(
                                    Response::builder()
                                        .status(200)
                                        .body(Full::new(Bytes::new()))
                                        .expect("static response"),
                                )
                            }),
                        )
                        .await;
                });
            }
        });

        let pin = xray_tls::pin::generate_cert_hash_hex(&cert_der);
        let settings = StreamSettings {
            protocol: "masque".into(),
            security: "tls".into(),
            security_json: Some(serde_json::json!({
                "serverName": "localhost",
                "alpn": ["h2"],
                "pinnedPeerCertSha256": pin,
            })),
            ..StreamSettings::tcp()
        };
        let dest =
            Destination::tcp(Address::ipv4(std::net::Ipv4Addr::LOCALHOST), Port::new(addr.port()));
        let mut session = dial(&dest, &SocketOptions::default(), &settings, &test_config())
            .await
            .expect("dial over real TLS");

        // establish：本端地址已协商（每族一个，非 0.0.0.0）。
        assert!(
            session.local_addrs().iter().any(|a| matches!(a, IpAddr::V4(v) if !v.is_unspecified())),
            "establish must surface a real v4 local addr, got {:?}",
            session.local_addrs()
        );

        // IP 包往返一例。
        let local4 = session
            .local_addrs()
            .iter()
            .find_map(|a| if let IpAddr::V4(v) = a { Some(v) } else { None })
            .expect("v4 local addr");
        let packet = udp_v4_packet(*local4, *local4, 64, b"e2e");
        let r = session.send_packet(&packet).await.expect("send");
        assert!(r.is_none(), "normal packet must not yield ICMP");
        let got = tokio::time::timeout(Duration::from_secs(5), session.recv_packet())
            .await
            .expect("recv within 5s")
            .expect("packet");
        assert_eq!(&got[20 + 8..], b"e2e");
        session.close();
    }

    /// MASQUE-TLS-REQUIRED：security ≠ tls 即硬错（不网络拨号）。
    #[tokio::test]
    async fn dial_rejects_non_tls_security() {
        let dest = Destination::tcp(Address::ipv4(std::net::Ipv4Addr::LOCALHOST), Port::new(1));
        let settings = StreamSettings {
            protocol: "masque".into(),
            security: "none".into(),
            ..StreamSettings::tcp()
        };
        let err = dial(&dest, &SocketOptions::default(), &settings, &test_config())
            .await
            .expect_err("non-tls must fail");
        assert!(err.to_string().contains("security must be"), "{err}");
    }

    /// MASQUE-H2-ONLY：ALPN 缺省 / 缺 h2 / 含 h3 均硬错（规划 §7 R9/R11）。
    #[tokio::test]
    async fn dial_rejects_alpn_violations() {
        let dest = Destination::tcp(Address::ipv4(std::net::Ipv4Addr::LOCALHOST), Port::new(1));
        for (alpn_json, why) in [
            (serde_json::json!({"serverName": "localhost"}), "missing alpn"),
            (serde_json::json!({"serverName": "localhost", "alpn": ["http/1.1"]}), "no h2"),
            (serde_json::json!({"serverName": "localhost", "alpn": ["h2", "h3"]}), "h3 present"),
        ] {
            let settings = StreamSettings {
                protocol: "masque".into(),
                security: "tls".into(),
                security_json: Some(alpn_json),
                ..StreamSettings::tcp()
            };
            let err = dial(&dest, &SocketOptions::default(), &settings, &test_config())
                .await
                .err()
                .unwrap_or_else(|| panic!("{why} must fail"));
            assert!(err.to_string().contains("alpn"), "{why}: expected alpn error, got {err}");
        }
    }

    /// finalmask 配置非法 → fail-visible（R12：不静默）。
    #[tokio::test]
    async fn dial_fail_visible_on_bad_finalmask() {
        let dest = Destination::tcp(Address::ipv4(std::net::Ipv4Addr::LOCALHOST), Port::new(1));
        let settings = StreamSettings {
            protocol: "masque".into(),
            security: "tls".into(),
            security_json: Some(serde_json::json!({
                "serverName": "localhost",
                "alpn": ["h2"],
            })),
            finalmask_json: Some(serde_json::json!({"tcp": [{"type": "noise"}]})),
            ..StreamSettings::tcp()
        };
        let err = dial(&dest, &SocketOptions::default(), &settings, &test_config())
            .await
            .expect_err("unknown tcp mask type must fail loudly");
        assert!(
            err.to_string().contains("unsupported tcp mask type"),
            "expected finalmask error, got {err}"
        );
    }
}

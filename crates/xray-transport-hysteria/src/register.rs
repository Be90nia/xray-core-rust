//! Hysteria transport dialer + listener 注册。
//!
//! dialer: 完整拨号流程——解析配置 → TLS → QuinnHysteriaTransport → HysteriaClient → HysteriaConn。
//! listener: TLS ServerConfig → QuinnListenerFactory → accept loop → HysteriaConn。

use std::{io, net::SocketAddr, sync::Arc};

use xray_transport::{
    connection::Connection,
    dialer::{StreamSettings, TransportDialFn, register_transport_dialer},
    ignore_already_exists,
    listener_registry::{
        ConnHandler, TransportListenFn, TransportListener, register_transport_listener,
    },
};

use crate::{
    PROTOCOL_NAME,
    conn::{HysteriaConn, InterStreamConn, QuicConn, QuicStream},
    dialer::{DialDestination, HysteriaClient},
    hub::{HysteriaListenerFactory, HysteriaQuicListener, MasqType},
    hysteria_transport::QuinnHysteriaTransport,
    proto_config::Config,
    quinn_adapter::{QuinnListenerFactory, QuinnQuicStream},
};

/// 注册 Hysteria transport dialer。
///
/// 完整拨号流程：
/// 1. 解析 `hysteriaSettings` JSON → hysteria `Config`
/// 2. 从 `security`/`security_json` 构建 TLS `ClientConfig`
/// 3. 创建 `QuinnHysteriaTransport`（quinn + h3 auth）
/// 4. 创建 `HysteriaClient` → `client.tcp()` → `HysteriaConn`
///
/// 幂等：重复注册的 `AlreadyExists` 被忽略。
pub fn register_dialer() -> io::Result<()> {
    let dial_fn: TransportDialFn = Arc::new(move |dest, sockopt, settings| {
        let dest = dest.clone();
        let sockopt = sockopt.clone();
        let settings = settings.clone();
        Box::pin(async move { dial_hysteria(&dest, &settings, &sockopt).await })
    });
    // 幂等放行 `AlreadyExists`，其余失败上抛（bd k2tq1：禁 `let _ =`）。
    ignore_already_exists(register_transport_dialer(PROTOCOL_NAME, dial_fn.clone()))?;
    ignore_already_exists(register_transport_dialer("hysteria2", dial_fn))?;
    Ok(())
}

/// 注册 Hysteria transport listener。
///
/// 监听流程：
/// 1. 从 `streamSettings.security` 构建 TLS `ServerConfig`
/// 2. 创建 `QuinnListenerFactory` → `factory.listen()` 得到 `HysteriaQuicListener`
/// 3. spawn accept 循环：每条 QUIC conn → `accept_bi` 取 client-initiated bi-stream →
///    `QuinnQuicStream` → `InterStreamConn`（server 模式）→ `HysteriaConn` → handler
///
/// 幂等：重复注册的 `AlreadyExists` 被忽略。
pub fn register_listener() -> io::Result<()> {
    let listen_fn: TransportListenFn = Arc::new(move |addr, settings, sockopt, handler| {
        let sockopt = sockopt.clone();
        Box::pin(async move { listen_hysteria(addr, settings, sockopt, handler).await })
    });
    ignore_already_exists(register_transport_listener(PROTOCOL_NAME, listen_fn.clone()))?;
    ignore_already_exists(register_transport_listener("hysteria2", listen_fn))?;
    Ok(())
}

/// 监听 + spawn accept 循环。
///
/// 同 gRPC 模式：返回的 `TransportListener` 仅记录 `local_addr`，
/// 实际 QUIC endpoint 由 spawned accept task 持有；task 退出（accept 失败）时 endpoint drop
/// 即关闭。
async fn listen_hysteria(
    addr: SocketAddr,
    settings: StreamSettings,
    sockopt: xray_transport::sockopt::SocketOptions,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    // 1. TLS server config（hysteria 强制 TLS）
    let tls_cfg = xray_tls::server_config::build_server_config(
        &settings.security,
        settings.security_json.as_ref(),
    )?
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "hysteria listener requires TLS (streamSettings.security must be \"tls\" or \"reality\")",
        )
    })?;

    // UDP 混淆 salamander/gecko（Go hysteria/hub.go:301-306：`UdpmaskManager.
    // WrapPacketConnServer` 包装 pktConn 后再交给 quic.Transport.Listen；
    // Rust 经 quinn AsyncUdpSocket 注入，finalmask_json.udp[].salamander 配置，
    // settings.packetSize 切 Gecko 分片模式）。
    let factory = QuinnListenerFactory::new(tls_cfg)
        .with_sockopt(sockopt)
        .with_obfs(crate::salamander_socket::parse_udp_obfs(settings.finalmask_json.as_ref())?);
    let config = Arc::new(parse_hysteria_config(settings.transport_json.as_ref())?);
    let quic_params = Arc::new(
        crate::quic_params::parse_quic_params(settings.finalmask_json.as_ref())?
            .unwrap_or_else(crate::quic_params::default_hysteria_quic_params),
    );
    // masq 从 proto Config 解析（masquerade JSON 已由 parse_hysteria_config 展开；
    // 对应 Go hub.go:210-254 listen 时 switch masqType）
    let masq = MasqType::from_config(&config)
        .map_err(|e| io::Error::other(format!("hysteria masq config: {e}")))?;
    // ponytail: 此链（transport registry）无 validator 注入点，静态 auth 由
    // factory.listen 内部用 config.auth 兜底（Go hub.go:63-64 config.Auth 对比）
    let on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync> = Arc::new(|_| {});
    let listener = factory
        .listen(addr, config, quic_params, masq, None, on_new_conn, None)
        .await
        .map_err(|e| io::Error::other(format!("hysteria listen bind failed: {e}")))?;

    let local = listener.local_addr();

    // 3. spawn accept loop。listener 句柄持 endpoint（Arc clone）+ 停机信号：
    // close() 先唤醒本循环（泵退出），再触发 HysteriaQuicListener::close()（ep.close
    // 强杀 QUIC 栈——factory.listen 内层的 accept 循环因此 accept None 退出，
    // endpoint 全部 clone 归零，driver 停、UDP socket 关、端口释放。修复前 close()
    // 仅日志，endpoint 永不释放成幽灵 inbound，对齐 Go hub.go Close=listener+tr.Close）。
    let quic_listener = listener.clone();
    // §3.5.6 ①类托管：每 QUIC 连接的桥接任务归本 listener 的 scope（stop 面 =
    // transport 族关闸档，ADR-0004 §2.2 Q1：关闸拒新、放行在途；无 drain 面）。
    let scope = xray_frame::scope::ComponentScope::new(format!("hysteria-accept:{local}"));
    // 连接任务与 accept 泵同账（bd 29sgj）⇒ 泵体只持弱引用句柄（B2 破环）。
    let conn_scope = scope.downgrade();

    // 停机信号：`close()` 唤醒 ⇒ 泵退出（`listener.close()` 关 QUIC 栈，端口释放）。
    let stop = Arc::new(tokio::sync::Notify::new());
    let stop_loop = Arc::clone(&stop);
    let accept_task = scope
        .spawn(async move {
        use xray_transport::accept_policy::{AcceptErrorKind, backoff_if_resource, classify};
        loop {
            let conn = match tokio::select! {
                r = listener.accept() => r,
                _ = stop_loop.notified() => break,
            } {
                Ok(c) => c,
                // 错误永不退出（accept_policy 铁律）：退出唯一来源是 close() 的
                // 停机信号——原 `Err(_) => break` 会因任何 accept 错误（含单连接
                // 级）静默杀死整个 hysteria 监听，无退避、无日志。
                Err(e) => {
                    match classify(&e) {
                        AcceptErrorKind::Resource => {
                            crate::LOG.warn(format!("tag=hysteria local={local} error={e} hysteria inbound: 资源/瞬时类 accept 错误，退避 500ms 后继续"));
                            backoff_if_resource(&e).await;
                        },
                        AcceptErrorKind::Connection => {
                            crate::LOG.debug(format!("tag=hysteria error={e} hysteria inbound: 单连接级 accept 错误，继续监听"));
                        },
                        AcceptErrorKind::Unknown => {
                            crate::LOG.warn(format!("tag=hysteria local={local} error={e} hysteria inbound: accept 错误（未知类别），继续监听"));
                        },
                    }
                    continue;
                },
            };
            let h = handler.clone();
            // 闸关（停机中）：连接随 conn 释放，留可诊断日志（禁静默）。
            if conn_scope
                .spawn(async move {
                    accept_hysteria_conn(conn, h).await;
                })
                .is_err()
            {
                crate::LOG.debug(format!(
                    "hysteria: scope closed at shutdown, connection dropped — rejected {}",
                    conn_scope.rejected_spawns()
                ));
            }
        }
        })
        .expect("freshly created scope never closed");
    // 意外退出监控（同账）：循环只应经 close() 的停机信号退出；panic 会静默杀掉
    // 监听——error! 兜底发声。
    scope
        .spawn(xray_transport::accept_policy::supervise_accept_loop(
            "hysteria",
            local.to_string(),
            accept_task.join(),
        ))
        .expect("freshly created scope never closed");

    Ok(Box::new(HysteriaTransportListener { local, listener: quic_listener, stop, scope }))
}

/// 单条 QUIC conn 内的 accept_bi 循环：把 client-initiated bi-stream 桥到 handler。
///
/// server 端不主动 open_bi——等客户端开 stream 后 accept_bi 取回。
async fn accept_hysteria_conn(conn: Arc<dyn QuicConn>, handler: ConnHandler) {
    let quinn_conn = match conn.as_quinn_connection() {
        Some(c) => c.clone(),
        None => return,
    };
    let local = conn.local_addr();
    let remote = conn.remote_addr();

    loop {
        let (send, recv) = match quinn_conn.accept_bi().await {
            Ok(s) => s,
            Err(_) => break,
        };
        let stream: Arc<dyn QuicStream> = Arc::new(QuinnQuicStream::new(send, recv, local, remote));
        let frame_type = match crate::conn::read_varint_stream(&*stream).await {
            Ok(value) => value,
            Err(_) => {
                stream.cancel_read(0x101);
                continue;
            },
        };
        if frame_type != crate::config::FrameTypeTCPRequest {
            stream.cancel_read(0x101);
            continue;
        }
        let inter = Arc::new(InterStreamConn::new(stream, local, remote, false));
        handler(Box::new(HysteriaConn::new(inter)));
    }
}

/// Hysteria transport listener 句柄。
///
/// 持 QUIC endpoint（`HysteriaQuicListener` Arc clone）+ accept 泵停机信号；
/// `close()` 二者皆触发，确定性释放端口。
struct HysteriaTransportListener {
    local: SocketAddr,
    listener: Arc<dyn HysteriaQuicListener>,
    /// accept 泵停机信号（`close()` 唤醒 ⇒ 泵退出）。泵住在本 listener 的账本里
    /// ⇒ 不强持 `Spawned`（禁双份账本）。
    stop: Arc<tokio::sync::Notify>,
    /// §3.5.6 ①类托管：每 QUIC 连接桥接任务账本。stop 面 = transport 族关闸档
    /// （ADR-0004 §2.2 Q1）：`close()` 只关闸拒新、放行在途（Go 26.10.17
    /// `listener.Close()` 不杀已建立连接）；无 drain 面 ⇒ 不得声称 abort 在途
    /// （accept 泵退出后的 Drop-abort 时点不确定，仅为实现事实，非契约保证）。
    scope: xray_frame::scope::ComponentScope,
}

impl TransportListener for HysteriaTransportListener {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn close(&self) -> io::Result<()> {
        crate::LOG.info(format!("hysteria listener close addr={}", self.local));
        self.stop.notify_one();
        // 连接任务账本关闸（transport 族关闸档，ADR-0004 §2.2 Q1）：停机后拒新
        // 连接任务；在途任务不由此口 abort（Drop-abort 时点不确定，仅为实现事实）。
        self.scope.close_gate();
        // 停机动作本身（不是可托管任务，bd k5cr4）：`HysteriaQuicListener::close` 是 async
        // 只为直译 Go `Close()`，唯一生产实现 `QuinnQuicListener::close` 的 future body 全
        // 同步（`ep.close` + Ok）⇒ 首轮 poll 即完成，就地驱动。原 spawn 后立即丢句柄 ⇒ 进程
        // 先退时优雅 QUIC close 静默丢失（端口不释放）；托管口语义是「取消在途」而非「保证
        // 完成」，接不住这一步，故不入 ComponentScope。
        let mut close_fut = self.listener.close();
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        // shortcut: 首轮 poll 必完成（当前唯一生产实现 body 无 await）；将来若引入真实
        // await，须改走停机编排窗——此处打 ERROR 留痕，不做静默丢失。
        match close_fut.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(Ok(())) => {},
            std::task::Poll::Ready(Err(e)) => {
                crate::LOG
                    .error(format!("hysteria listener close failed addr={}: {e}", self.local));
            },
            std::task::Poll::Pending => {
                crate::LOG.error(format!(
                    "hysteria listener close pending after first poll addr={}: QUIC endpoint 未关闭（需停机编排窗）",
                    self.local
                ));
            },
        }
        Ok(())
    }
}

/// 实际拨号：解析配置 → TLS → QuinnHysteriaTransport → HysteriaClient → HysteriaConn。
async fn dial_hysteria(
    dest: &xray_common::net::destination::Destination,
    settings: &StreamSettings,
    sockopt: &xray_transport::sockopt::SocketOptions,
) -> io::Result<Box<dyn Connection>> {
    // 1. 解析 hysteriaSettings JSON
    let config = parse_hysteria_config(settings.transport_json.as_ref())?;

    // 2. TLS 配置
    let default_sni = dest.address().to_string();
    let tls_config = xray_tls::client_config::build_client_config(
        &settings.security,
        settings.security_json.as_ref(),
        &default_sni,
    )?;

    let tls_client_config = match tls_config {
        Some(c) => rustls::ClientConfig::clone(&c),
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria requires TLS (streamSettings.security must be \"tls\" or \"reality\")",
            ));
        },
    };

    // 3. 构造 dest（hysteria 用 UDP，需从 TCP dest 转换）
    let dest_addr = resolve_dest_to_socket_addr(dest)?;
    let dial_dest = DialDestination { udp_addr: dest_addr, host: default_sni.clone() };
    // 4. 创建 transport + client
    let bind_addr: SocketAddr = "0.0.0.0:0".parse().map_err(|e: std::net::AddrParseError| {
        io::Error::other(format!("invalid bind addr: {e}"))
    })?;
    // UDP 混淆 salamander/gecko（Go hysteria/dialer.go:170-175：`UdpmaskManager.
    // WrapPacketConnClient` 包装 pktConn 后再交给 quic.Transport.DialEarly）。
    let transport = QuinnHysteriaTransport::new(tls_client_config, bind_addr)?
        .with_sockopt(sockopt.clone())
        .with_obfs(crate::salamander_socket::parse_udp_obfs(settings.finalmask_json.as_ref())?);
    let quic_params = Arc::new(
        crate::quic_params::parse_quic_params(settings.finalmask_json.as_ref())?
            .unwrap_or_else(crate::quic_params::default_hysteria_quic_params),
    );
    let client = HysteriaClient::new(dial_dest, Arc::new(config), quic_params, Arc::new(transport));
    let target_addr = match dest.address() {
        xray_common::net::address::Address::Domain(host) => {
            xray_common::net::address::Address::new_domain(host)
        },
        xray_common::net::address::Address::IPv4(ip) => {
            xray_common::net::address::Address::IPv4(*ip)
        },
        xray_common::net::address::Address::IPv6(ip) => {
            xray_common::net::address::Address::IPv6(*ip)
        },
    };
    let conn = client
        .tcp(&target_addr, dest.port())
        .await
        .map_err(|e| io::Error::other(format!("hysteria dial failed: {e}")))?;

    Ok(Box::new(HysteriaConn::new(conn)))
}

/// 从 `hysteriaSettings` JSON 解析为 prost [`Config`]。
///
/// 接受的 JSON 字段：
/// - `auth`：鉴权 token
/// - `masqType`：伪装类型（proto3 JSON camelCase 兼容）
/// - `masquerade`：伪装配置嵌套对象（Go 用户配置形态，infra/conf transport_internet.go:498-510
///   `Masquerade` struct → :542-549 展开为 proto 扁平字段）
/// - `udpIdleTimeout`：UDP 空闲超时（秒）
///
/// `version` 不在接受面内：Go `transport/internet/hysteria/config.proto:10` 是
/// `reserved 1`，JSON 层校验归 `xray-conf` lint（Go `infra/conf` 语义）。
///
/// `None` 返回默认配置。
fn parse_hysteria_config(json: Option<&serde_json::Value>) -> io::Result<Config> {
    let Some(v) = json else {
        return Ok(crate::proto_config::default_config());
    };
    let Some(obj) = v.as_object() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hysteriaSettings must be a JSON object",
        ));
    };

    let auth = obj.get("auth").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let masq_type = obj.get("masqType").and_then(|x| x.as_str()).unwrap_or("").to_string();
    // Go infra/conf HysteriaConfig.Build（transport_method.go:768-782）：0 或缺省
    // 一律落 60；非 0 时强制 [2,600]，越界硬错。此前 Rust 只做 `unwrap_or(60)`
    // ——显式 `0` 保留 0 秒、`1`/`700` 静默接受，两处都与 Go 相反（bd x0f0r）。
    let udp_idle_timeout = match obj.get("udpIdleTimeout") {
        None | Some(serde_json::Value::Null) => 60,
        Some(v) => {
            let n = v.as_i64().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "hysteriaSettings.udpIdleTimeout: expected an integer (seconds)",
                )
            })?;
            if n == 0 {
                60
            } else if !(2..=600).contains(&n) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("UdpIdleTimeout must be between 2 and 600, got {n}"),
                ));
            } else {
                n
            }
        },
    };
    let mut config = Config { auth, masq_type, udp_idle_timeout, ..Config::default() };
    if let Some(m) = obj.get("masquerade") {
        crate::proto_config::apply_masquerade_json(&mut config, m)?;
    }
    Ok(config)
}

/// 把 `Destination` 解析为 `SocketAddr`（hysteria 强制 UDP，需 IP:port）。
///
/// 域名地址返回 `InvalidInput` 错误（QUIC 要求 IP 地址）。
fn resolve_dest_to_socket_addr(
    dest: &xray_common::net::destination::Destination,
) -> io::Result<SocketAddr> {
    use xray_common::net::address::Address;
    let ip = match dest.address() {
        Address::IPv4(ip) => std::net::IpAddr::V4(*ip),
        Address::IPv6(ip) => std::net::IpAddr::V6(*ip),
        Address::Domain(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria requires IP address destination (domain not supported yet, needs DNS resolution)",
            ));
        },
    };
    Ok(SocketAddr::new(ip, dest.port().value()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_dialer_is_idempotent() {
        register_dialer().expect("first register ok");
        register_dialer().expect("second register ok (idempotent)");
    }

    /// bd upe1: "hysteria2" transport name (Go v2 streamSettings.network) must
    /// resolve to the same dialer/listener as "hysteria" so that
    /// `streamSettings.network="hysteria2"` doesn't hit `NotFound` at the
    /// transport registry.
    #[test]
    fn hysteria2_alias_registers_alongside_hysteria() {
        register_dialer().expect("dialer register");
        register_listener().expect("listener register");
        assert!(
            xray_transport::dialer::get_transport_dialer("hysteria").is_some(),
            "hysteria dialer must be registered"
        );
        assert!(
            xray_transport::dialer::get_transport_dialer("hysteria2").is_some(),
            "hysteria2 dialer alias must be registered"
        );
        assert!(
            xray_transport::listener_registry::get_transport_listener("hysteria").is_some(),
            "hysteria listener must be registered"
        );
        assert!(
            xray_transport::listener_registry::get_transport_listener("hysteria2").is_some(),
            "hysteria2 listener alias must be registered"
        );
    }

    #[test]
    fn parse_hysteria_config_none_returns_default() {
        let cfg = parse_hysteria_config(None).unwrap();
        assert_eq!(cfg.auth, "");
        assert_eq!(cfg.udp_idle_timeout, 60);
    }

    /// bd x0f0r：`udpIdleTimeout` 对齐 Go `HysteriaConfig.Build`
    /// （transport_method.go:768-777）——显式 0 落 60，非 0 强制 [2,600]。
    #[test]
    fn parse_hysteria_config_udp_idle_timeout_matches_go_bounds() {
        let parse = |json: &str| {
            let v: serde_json::Value = serde_json::from_str(json).unwrap();
            parse_hysteria_config(Some(&v))
        };
        assert_eq!(parse(r#"{"udpIdleTimeout":0}"#).unwrap().udp_idle_timeout, 60);
        assert_eq!(parse(r#"{"udpIdleTimeout":2}"#).unwrap().udp_idle_timeout, 2);
        assert_eq!(parse(r#"{"udpIdleTimeout":600}"#).unwrap().udp_idle_timeout, 600);
        for bad in
            [r#"{"udpIdleTimeout":1}"#, r#"{"udpIdleTimeout":601}"#, r#"{"udpIdleTimeout":-5}"#]
        {
            assert!(parse(bad).is_err(), "{bad} must be rejected (Go: between 2 and 600)");
        }
        assert!(parse(r#"{"udpIdleTimeout":"60"}"#).is_err(), "非整数必须硬错，不得静默回落");
    }

    #[test]
    fn parse_hysteria_config_basic_fields() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"auth":"my-token","udpIdleTimeout":120,"version":2}"#)
                .unwrap();
        let cfg = parse_hysteria_config(Some(&v)).unwrap();
        assert_eq!(cfg.auth, "my-token");
        assert_eq!(cfg.udp_idle_timeout, 120);
        // Go `hysteria/config.proto:10` 是 `reserved 1`：JSON `version` 不进 proto。
        // 仅 version 不同的两份配置必须产出同一个 proto（tag 1 永不写）。
        let v1: serde_json::Value =
            serde_json::from_str(r#"{"auth":"my-token","udpIdleTimeout":120,"version":1}"#)
                .unwrap();
        assert_eq!(cfg, parse_hysteria_config(Some(&v1)).unwrap());
    }

    #[test]
    fn parse_hysteria_config_non_object_returns_err() {
        let v: serde_json::Value = serde_json::from_str(r#""not-an-object""#).unwrap();
        let r = parse_hysteria_config(Some(&v));
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    /// masquerade 嵌套对象 → proto 扁平字段（Go infra/conf transport_internet.go:498-510
    /// + 542-549 展开）。四类形态各验一遍 + `MasqType::from_config` 回读等价。
    #[test]
    fn parse_hysteria_config_masquerade_object() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"auth":"t","masquerade":{"type":"file","dir":"/var/www"}}"#)
                .unwrap();
        let cfg = parse_hysteria_config(Some(&v)).unwrap();
        assert_eq!(cfg.masq_type, "file");
        assert_eq!(cfg.masq_file, "/var/www");
        assert_eq!(MasqType::from_config(&cfg).unwrap(), MasqType::File("/var/www".into()));

        let v: serde_json::Value = serde_json::from_str(
            r#"{"masquerade":{"type":"proxy","url":"https://e.com","rewriteHost":true,"insecure":true}}"#,
        )
        .unwrap();
        let cfg = parse_hysteria_config(Some(&v)).unwrap();
        assert!(cfg.masq_url_rewrite_host);
        assert!(cfg.masq_url_insecure);
        assert!(matches!(
            MasqType::from_config(&cfg).unwrap(),
            MasqType::Proxy { url, rewrite_host: true, insecure: true } if url == "https://e.com"
        ));

        let v: serde_json::Value = serde_json::from_str(
            r#"{"masquerade":{"type":"string","content":"hi","headers":{"X-A":"1"},"statusCode":418}}"#,
        )
        .unwrap();
        let cfg = parse_hysteria_config(Some(&v)).unwrap();
        assert_eq!(cfg.masq_string, "hi");
        assert_eq!(cfg.masq_string_headers.get("X-A").unwrap(), "1");
        assert_eq!(cfg.masq_string_status_code, 418);
        assert!(matches!(
            MasqType::from_config(&cfg).unwrap(),
            MasqType::String { body, status_code: 418, .. } if body == "hi"
        ));
    }

    /// 无 masquerade 键 → 字段保持默认（零行为变化）。
    #[test]
    fn parse_hysteria_config_no_masquerade_untouched() {
        let v: serde_json::Value = serde_json::from_str(r#"{"auth":"t"}"#).unwrap();
        let cfg = parse_hysteria_config(Some(&v)).unwrap();
        assert_eq!(cfg.masq_type, "");
        assert_eq!(MasqType::from_config(&cfg).unwrap(), MasqType::NotFound);
    }
    /// close() abort accept task → endpoint drop，新 QUIC 握手失败
    /// （票 4kjs 回归锚：修复前 close() 仅日志，endpoint 永远存活，connect 一直成功）。
    #[tokio::test]
    async fn close_rejects_new_connections() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });

        let settings = StreamSettings {
            protocol: "hysteria".into(),
            security: "tls".into(),
            ..Default::default()
        };
        let handler: ConnHandler = Arc::new(|_| {});
        let listener = listen_hysteria(
            "127.0.0.1:0".parse().unwrap(),
            settings,
            xray_transport::sockopt::SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen_hysteria");
        let addr = listener.local_addr().unwrap();

        listener.close().unwrap();

        // quinn 客户端（h3 ALPN + allowInsecure + 1s idle）连接必须失败。
        let client_tls = xray_tls::client_config::build_client_config(
            "tls",
            Some(&serde_json::json!({"allowInsecure": true, "alpn": ["h3"]})),
            "127.0.0.1",
        )
        .unwrap()
        .expect("client tls config");
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(1_000))));
        let mut quic_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
        ));
        quic_cfg.transport_config(Arc::new(transport));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quic_cfg);

        let result = endpoint.connect(addr, "127.0.0.1").unwrap().await;
        assert!(result.is_err(), "post-close connect must fail");
        endpoint.close(0u32.into(), b"test done");
    }

    /// ADR-0004 §2.6 A2（transport 族关闸档，hysteria TCP listener 站）：
    /// `TransportListener::close()` 关闸后拒新连接任务，**且**在途连接任务不由此口
    /// 中止——放行后照样跑完。
    ///
    /// 反证：若 `close()` 把在途任务一起中止（或闸没关），本测试的「拒发」或
    /// 「放行后跑完」必红。
    #[tokio::test]
    async fn hysteria_listener_scope_a2_gate_closes_but_keeps_in_flight() {
        use std::{
            future::Future,
            pin::Pin,
            sync::atomic::{AtomicBool, Ordering},
        };

        /// 本测试不带 QUIC 数据面：close() 只需一个可关闭的 listener。
        struct StubQuicListener;

        impl HysteriaQuicListener for StubQuicListener {
            fn accept(
                &self,
            ) -> Pin<Box<dyn Future<Output = io::Result<Arc<dyn QuicConn>>> + Send>> {
                Box::pin(std::future::pending())
            }

            fn local_addr(&self) -> SocketAddr {
                "127.0.0.1:0".parse().expect("addr")
            }

            fn close(&self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send>> {
                Box::pin(async { Ok(()) })
            }
        }

        // accept 泵停机信号：本测试不跑泵，只验 close() 的关闸面。
        let listener = HysteriaTransportListener {
            local: "127.0.0.1:0".parse().expect("addr"),
            listener: Arc::new(StubQuicListener),
            stop: Arc::new(tokio::sync::Notify::new()),
            scope: xray_frame::scope::ComponentScope::new("hysteria-accept:a2-test"),
        };

        let release = Arc::new(tokio::sync::Notify::new());
        let finished = Arc::new(AtomicBool::new(false));
        let (task_release, task_finished) = (Arc::clone(&release), Arc::clone(&finished));
        listener
            .scope
            .spawn(async move {
                task_release.notified().await;
                task_finished.store(true, Ordering::SeqCst);
            })
            .expect("新建 scope 必须受理连接任务");

        TransportListener::close(&listener).expect("close");
        assert!(listener.scope.spawn(async {}).is_err(), "关闸后必须拒新连接任务");
        assert_eq!(listener.scope.in_flight(), 1, "在途连接任务关闸后仍在账本内");

        release.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !finished.load(Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("关闸不得中止在途任务：放行后必须跑完（超时 = 被 abort 或被饿死）");
    }

    /// bd k5cr4：停机动作必须**就地跑完**——`close()` 返回时 QUIC endpoint close future
    /// 的 body 已执行（原实现 spawn 后立即丢句柄 ⇒ 进程先退时优雅 close 静默丢失）。
    #[tokio::test]
    async fn close_drives_quic_close_inline() {
        use std::{
            future::Future,
            pin::Pin,
            sync::atomic::{AtomicBool, Ordering},
        };

        struct FlagListener(Arc<AtomicBool>);

        impl HysteriaQuicListener for FlagListener {
            fn accept(
                &self,
            ) -> Pin<Box<dyn Future<Output = io::Result<Arc<dyn QuicConn>>> + Send>> {
                Box::pin(std::future::pending())
            }

            fn local_addr(&self) -> SocketAddr {
                "127.0.0.1:0".parse().expect("addr")
            }

            fn close(&self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send>> {
                let flag = Arc::clone(&self.0);
                Box::pin(async move {
                    flag.store(true, Ordering::SeqCst);
                    Ok(())
                })
            }
        }

        let closed = Arc::new(AtomicBool::new(false));
        // accept 泵停机信号：本测试不跑泵，只验 close() 就地驱动 QUIC close。
        let listener = HysteriaTransportListener {
            local: "127.0.0.1:0".parse().expect("addr"),
            listener: Arc::new(FlagListener(Arc::clone(&closed))),
            stop: Arc::new(tokio::sync::Notify::new()),
            scope: xray_frame::scope::ComponentScope::new("hysteria-close-inline"),
        };

        TransportListener::close(&listener).expect("close");
        // 不 await 任何 yield 点：close 返回时 body 必须已跑完（spawn 形态此处必红）。
        assert!(closed.load(Ordering::SeqCst), "close 返回时 QUIC close future 必须已执行完");
    }
}

//! SOCKS5 inbound listener：接收连接 → SOCKS5 握手 → dispatcher 分发。
//!
//! 对应 Go `app/proxyman/inbound/always.go::handle_connection` + `proxy/socks/server.go`。
//! 这里实现最小端到端切片：TCP accept → socks5 handshake → SocksAddr → Destination →
//! `DispatchHandler::dispatch(dest, link)`。
//!
//! 不含：sniffing（协议嗅探）、UDP associate、多 inbound 注册管理（由 proxyman::InboundManager 负责）。

use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use xray_app_dispatcher::default::SimpleOhm;
use xray_app_dispatcher::OutboundHandlerManager;
use xray_buf::io::{new_reader, new_writer};
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_proxy_socks::protocol::{Host, SocksAddr};
use xray_proxy_socks::server::socks5_server_handshake;
use xray_proxy_socks::ServerConfig;
use xray_transport::link::Link;
use tokio::task::JoinHandle;
use xray_conf::{BuiltConfig, BuiltInbound};
// P1-B: vless/trojan inbound 集成
use std::collections::HashMap;
use xray_proto::xray::proxy::vless::Account as VlessProtoAccount;
use xray_proxy_trojan::{serve_trojan, MemoryAccount as TrojanMemoryAccount, MemoryUser as TrojanMemoryUser};
use xray_proxy_vless::{serve_vless, MemoryAccount as VlessMemoryAccount, MemoryUser as VlessMemoryUser, MemoryValidator as VlessMemoryValidator, Validator as VlessValidator};
use xray_proxy_vmess::{serve_vmess, MemoryAccount as VmessMemoryAccount, MemoryUser as VmessMemoryUser, TimedUserValidator as VmessTimedUserValidator, Validator as VmessValidator};
use xray_common::uuid::UUID;
// tdy: http + dokodemo inbound 集成
use xray_proxy_http::ServerConfig as HttpServerConfig;
use xray_proxy_http::server::http_server_handshake;
// zx7: mux inbound 检测
use xray_mux::client::{MUX_COOL_ADDRESS, MUX_COOL_PORT};

/// SOCKS5 inbound 服务入口。
///
/// 绑定 `addr` 监听，每个连接 spawn 独立 task：
/// 1. SOCKS5 握手得目标 `SocksAddr`
/// 2. 转 `Destination`，构造 `Link`（用 TcpStream 的 read/write half）
/// 3. `ohm` 的 default handler `dispatch(dest, link)` 拨号并桥接
///
/// # 参数
/// - `listener`：已绑定的 TCP listener
/// - `ohm`：出站管理器（至少有 default handler）
/// - `config`：SOCKS5 server 配置（auth method 等）
///
/// # 错误
/// accept 循环自身错误返回；单个连接错误只 log 不中断循环。
pub async fn serve_socks5(
    listener: TcpListener,
    ohm: Arc<SimpleOhm>,
    config: Arc<ServerConfig>,
) -> std::io::Result<()> {
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;

    tracing::info!(
        addr = %listener.local_addr()?,
        "socks5 inbound listening"
    );

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "socks5 accept failed");
                continue;
            }
        };

        let handler = Arc::clone(&handler);
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &config, &handler).await {
                tracing::debug!(error = %e, "socks5 connection ended with error");
            }
        });

        let _ = peer; // 仅 log 级别可用，当前不记
    }
}

/// 处理单个 SOCKS5 连接：handshake → dispatch。
async fn handle_connection(
    mut stream: TcpStream,
    config: &ServerConfig,
    handler: &Arc<dyn xray_app_dispatcher::DispatchHandler>,
) -> std::io::Result<()> {
    // 1. SOCKS5 握手
    let socks_addr = socks5_server_handshake(&mut stream, config)
        .await
        .map_err(|e| std::io::Error::other(format!("socks5 handshake: {e}")))?;

    // 2. SocksAddr → Destination
    let dest = socks_addr_to_destination(&socks_addr)?;

    // 3. 拆 TcpStream → (read, write) → Link
    // ponytail: tokio::io::split 返回的 ReadHalf/WriteHalf 是 'static + Send，
    // new_reader/new_writer 接受 AsyncRead/AsyncWrite + Unpin + Send + 'static。
    let (read_half, write_half) = tokio::io::split(stream);
    let link = Link::new(new_reader(read_half), new_writer(write_half));

    // 4. dispatch（dispatch 内部拨号 + bridge，消耗 link）
    // zx7: mux.cool dest 转给 mux ServerWorker（当前 stub）
    if is_mux_destination(&dest) {
        tracing::info!("socks5: mux.cool destination detected, spawning mux inbound handler");
        tokio::spawn(handle_mux_inbound_link(link));
        return Ok(());
    }
    let _ = handler.dispatch(&dest, link).await;

    Ok(())
}

/// 检测 dest 是否为 mux.cool 多路复用信令目的地（zx7）。
///
/// 当客户端配置了 mux，会把目标设为 `v1.mux.cool:9527`，
/// inbound 收到后应转给 mux [`ServerWorker`] 解帧。
pub fn is_mux_destination(dest: &Destination) -> bool {
    matches!(dest.address(), Address::Domain(d) if d == MUX_COOL_ADDRESS)
        && dest.port().value() == MUX_COOL_PORT
}

/// 处理 mux.cool 入站连接的骨架（zx7）。
///
/// TODO zx7-future: 接入 `xray_mux::worker::ServerWorker`——
/// 启动 frame reader loop，为每个 session 调底层 dispatcher.dispatch(session_dest)。
/// 当前骨架：log + drop link。
async fn handle_mux_inbound_link(link: Link) {
    tracing::warn!("mux inbound link received: ServerWorker integration pending, dropping");
    drop(link);
}

/// `SocksAddr` → `Destination`（TCP）。
///
/// `Host::Ipv4` → `Address::IPv4`，`Ipv6` → `Address::IPv6`，`Domain` → `Address::Domain`。
fn socks_addr_to_destination(addr: &SocksAddr) -> std::io::Result<Destination> {
    let address = match &addr.host {
        Host::Ipv4(ip) => Address::IPv4(*ip),
        Host::Ipv6(ip) => Address::IPv6(*ip),
        Host::Domain(d) => Address::Domain(d.clone()),
    };
    Ok(Destination::new(address, Port::new(addr.port), Network::TCP))
}

/// HTTP proxy inbound 服务入口（tdy）。
///
/// 接受连接 → http_server_handshake → 拆 stream → dispatch。
/// 当前只 dispatch CONNECT 隧道；普通 HTTP 代理（GET/POST 等）暂不支持，留切片3。
pub async fn serve_http(
    listener: TcpListener,
    ohm: Arc<SimpleOhm>,
    config: Arc<HttpServerConfig>,
) -> std::io::Result<()> {
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;
    tracing::info!(addr = %listener.local_addr()?, "http proxy inbound listening");
    loop {
        let (mut stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "http accept failed");
                continue;
            }
        };
        let handler = Arc::clone(&handler);
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            // 1. handshake → (dest, method)
            let (dest, method) = match http_server_handshake(&mut stream, &config).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(error = %e, "http handshake failed");
                    return;
                }
            };
            // 2. 只 dispatch CONNECT（plain HTTP 留切片3）
            if method != "CONNECT" {
                tracing::debug!(method = %method, "plain HTTP proxy not yet supported, skipping");
                return;
            }
            // 3. 拆 stream → Link → dispatch
            let (read_half, write_half) = tokio::io::split(stream);
            let link = Link::new(new_reader(read_half), new_writer(write_half));
            // zx7: mux.cool dest 转给 mux ServerWorker（stub）
            if is_mux_destination(&dest) {
                tracing::info!("http: mux.cool destination detected, spawning mux inbound handler");
                tokio::spawn(handle_mux_inbound_link(link));
                return;
            }
            let _ = handler.dispatch(&dest, link).await;
        });
    }
}

/// Dokodemo-door inbound 服务入口（tdy）。
///
/// 接受连接 → 直接用预定义 `dest` 拼装 Link → dispatch（dokodemo 无握手协议）。
pub async fn serve_dokodemo(
    listener: TcpListener,
    ohm: Arc<SimpleOhm>,
    dest: Destination,
) -> std::io::Result<()> {
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;
    tracing::info!(addr = %listener.local_addr()?, dest = ?dest, "dokodemo inbound listening");
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "dokodemo accept failed");
                continue;
            }
        };
        let handler = Arc::clone(&handler);
        let dest = dest.clone();
        tokio::spawn(async move {
            let (read_half, write_half) = tokio::io::split(stream);
            let link = Link::new(new_reader(read_half), new_writer(write_half));
            let _ = handler.dispatch(&dest, link).await;
        });
    }
}

/// 遍历 BuiltConfig 的 inbounds，按协议 spawn listener tasks。
///
/// 返回每个 inbound 的 JoinHandle（用于优雅关闭）。不支持的协议 warn 跳过。
///
/// # 当前支持
///
/// - `socks`：SOCKS5 inbound（TCP accept → handshake → dispatch）
/// - 其他协议（vless/trojan/vmess/http）：warn 跳过（待后续切片）
pub async fn spawn_inbounds(
    built: &BuiltConfig,
    ohm: Arc<SimpleOhm>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut handles = Vec::new();
    for ib in &built.inbounds {
        if let Some(handle) = spawn_one_inbound(ib, Arc::clone(&ohm)).await? {
            handles.push(handle);
        }
    }
    Ok(handles)
}

/// 按协议种类启动单个 inbound listener。
async fn spawn_one_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let listen = ib.listen.as_deref().unwrap_or("0.0.0.0");
    let port = match ib.port {
        Some(p) => p,
        None => {
            tracing::warn!(
                tag = %ib.tag,
                protocol = %ib.entry.kind,
                "inbound has no port, skipping"
            );
            return Ok(None);
        }
    };
    let addr = format!("{listen}:{port}");

    match ib.entry.kind.as_str() {
        "socks" => {
            let listener = TcpListener::bind(&addr).await?;
            tracing::info!(tag = %ib.tag, addr = %addr, "socks5 inbound listening");
            let config = Arc::new(ServerConfig::default());
            let handle = tokio::spawn(async move {
                if let Err(e) = serve_socks5(listener, ohm, config).await {
                    tracing::error!(error = %e, "socks5 inbound stopped");
                }
            });
            Ok(Some(handle))
        }
        "vless" => {
            let validator: Arc<dyn VlessValidator> = build_vless_validator(&ib.entry.data)?;
            let listener = TcpListener::bind(&addr).await?;
            tracing::info!(tag = %ib.tag, addr = %addr, users = validator.get_count(), "vless inbound listening");
            let handle = tokio::spawn(async move {
                if let Err(e) = serve_vless(listener, ohm, validator).await {
                    tracing::error!(error = %e, "vless inbound stopped");
                }
            });
            Ok(Some(handle))
        }
        "trojan" => {
            let users = build_trojan_users(&ib.entry.data)?;
            let listener = TcpListener::bind(&addr).await?;
            tracing::info!(tag = %ib.tag, addr = %addr, users = users.len(), "trojan inbound listening");
            let handle = tokio::spawn(async move {
                if let Err(e) = serve_trojan(listener, ohm, users).await {
                    tracing::error!(error = %e, "trojan inbound stopped");
                }
            });
            Ok(Some(handle))
        }
        "vmess" => {
            let validator = build_vmess_validator(&ib.entry.data)?;
            let listener = TcpListener::bind(&addr).await?;
            tracing::info!(tag = %ib.tag, addr = %addr, "vmess inbound listening");
            let handle = tokio::spawn(async move {
                if let Err(e) = serve_vmess(listener, ohm, validator).await {
                    tracing::error!(error = %e, "vmess inbound stopped");
                }
            });
            Ok(Some(handle))
        }
        "http" => {
            let config = parse_http_config(&ib.entry.data)?;
            let listener = TcpListener::bind(&addr).await?;
            tracing::info!(tag = %ib.tag, addr = %addr, "http inbound listening");
            let handle = tokio::spawn(async move {
                if let Err(e) = serve_http(listener, ohm, Arc::new(config)).await {
                    tracing::error!(error = %e, "http inbound stopped");
                }
            });
            Ok(Some(handle))
        }
        "dokodemo" => {
            let dest = parse_dokodemo_dest(&ib.entry.data)?;
            let listener = TcpListener::bind(&addr).await?;
            tracing::info!(tag = %ib.tag, addr = %addr, dest = ?dest, "dokodemo inbound listening");
            let handle = tokio::spawn(async move {
                if let Err(e) = serve_dokodemo(listener, ohm, dest).await {
                    tracing::error!(error = %e, "dokodemo inbound stopped");
                }
            });
            Ok(Some(handle))
        }
        other => {
            tracing::warn!(
                tag = %ib.tag,
                protocol = %other,
                "inbound protocol not yet supported, skipping"
            );
            Ok(None)
        }
    }
}

/// 从 inbound entry.data（JSON）解析 vless clients → MemoryValidator。
///
/// JSON 格式：`{"clients":[{"id":"uuid","flow":"","email":""}],"decryption":"none"}`。
/// 对每个 client 构造最小 `ProtoAccount`（id+flow+encryption=none）→ `MemoryAccount::from_proto_account`。
fn build_vless_validator(data: &[u8]) -> std::io::Result<std::sync::Arc<dyn VlessValidator>> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("vless inbound settings JSON: {e}")))?;
    let validator = VlessMemoryValidator::new();
    if let Some(clients) = v.get("clients").and_then(|c| c.as_array()) {
        for c in clients {
            let id = c.get("id").and_then(|x| x.as_str()).unwrap_or("");
            let email = c.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let level = c.get("level").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            let flow = c.get("flow").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let proto = VlessProtoAccount {
                id: id.to_string(),
                flow,
                encryption: "none".to_string(),
                ..Default::default()
            };
            let account = VlessMemoryAccount::from_proto_account(&proto)
                .map_err(|e| std::io::Error::other(format!("vless account parse: {e}")))?;
            let user = VlessMemoryUser::new(email, level, account);
            if let Err(e) = validator.add(user) {
                tracing::warn!(error = %e, "skip duplicate vless user during validator build");
            }
        }
    }
    Ok(std::sync::Arc::new(validator))
}

/// 从 inbound entry.data（JSON）解析 trojan clients → HashMap<key_hash, MemoryUser>。
///
/// JSON 格式：`{"clients":[{"password":"...","email":""}]}`。
/// 对每个 client：`MemoryAccount::new(password)`（内部计算 hex(sha224)）→ MemoryUser → key_hash 入表。
fn build_trojan_users(data: &[u8]) -> std::io::Result<HashMap<String, TrojanMemoryUser>> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("trojan inbound settings JSON: {e}")))?;
    let mut users = HashMap::new();
    if let Some(clients) = v.get("clients").and_then(|c| c.as_array()) {
        for c in clients {
            let password = c.get("password").and_then(|x| x.as_str()).unwrap_or("");
            let email = c.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let level = c.get("level").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            let account = TrojanMemoryAccount::new(password);
            let user = TrojanMemoryUser::new(email, level, account);
            users.insert(user.key_hash(), user);
        }
    }
    Ok(users)
}


/// 从 inbound entry.data（JSON）解析 http accounts → HttpServerConfig。
///
/// JSON 格式：`{"accounts":[{"user":"u","pass":"p"}]}`（用户可选）
fn parse_http_config(data: &[u8]) -> std::io::Result<HttpServerConfig> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("http inbound settings JSON: {e}")))?;
    let mut config = HttpServerConfig::default();
    if let Some(accounts) = v.get("accounts").and_then(|c| c.as_array()) {
        for a in accounts {
            let user = a.get("user").and_then(|x| x.as_str()).unwrap_or("");
            let pass = a.get("pass").and_then(|x| x.as_str()).unwrap_or("");
            if !user.is_empty() {
                config.accounts.insert(user.to_string(), pass.to_string());
            }
        }
    }
    Ok(config)
}

/// 从 inbound entry.data（JSON）解析 dokodemo 配置 → Destination（预定义目标）。
///
/// JSON 格式：`{"address":"1.2.3.4","port":80,"network":"tcp"}`（address+port 必填）
fn parse_dokodemo_dest(data: &[u8]) -> std::io::Result<Destination> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("dokodemo inbound settings JSON: {e}")))?;
    let address_str = v.get("address").and_then(|x| x.as_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "dokodemo: missing address"))?;
    let port = v.get("port").and_then(|x| x.as_u64())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "dokodemo: missing port"))?
        as u16;
    // address 是 IPv4/IPv6/Domain 之一
    let address = if let Ok(v4) = address_str.parse::<std::net::Ipv4Addr>() {
        Address::IPv4(v4)
    } else if let Ok(v6) = address_str.parse::<std::net::Ipv6Addr>() {
        Address::IPv6(v6)
    } else {
        Address::Domain(address_str.to_string())
    };
    Ok(Destination::new(address, Port::new(port), Network::TCP))
}

/// 从 inbound entry.data（JSON）解析 vmess clients → TimedUserValidator。
///
/// JSON 格式：`{"clients":[{"id":"uuid","level":0,"alterId":0,"email":""}]}`。
/// 现代 VMess (AEAD) 不用 alterId，忽略该字段。`id` 解析为 `UUID` → `MemoryAccount::new(uuid)`。
fn build_vmess_validator(data: &[u8]) -> std::io::Result<std::sync::Arc<VmessTimedUserValidator>> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("vmess inbound settings JSON: {e}")))?;
    let validator = VmessTimedUserValidator::new();
    if let Some(clients) = v.get("clients").and_then(|c| c.as_array()) {
        for c in clients {
            let id = c.get("id").and_then(|x| x.as_str()).unwrap_or("");
            let email = c.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let level = c.get("level").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            let uuid = UUID::parse(id)
                .ok_or_else(|| std::io::Error::other(format!("vmess invalid uuid: {id}")))?;
            let account = VmessMemoryAccount::new(uuid);
            let user = VmessMemoryUser::new(email, account).with_level(level);
            if let Err(e) = VmessValidator::add(&validator, user) {
                tracing::warn!(error = %e, "skip vmess user during validator build");
            }
        }
    }
    Ok(std::sync::Arc::new(validator))
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_app_dispatcher::default::SimpleOhm;
    use xray_proxy_freedom::make_freedom_dial_fn;
    use xray_proxy_socks::protocol::{ATYP_DOMAIN, ATYP_IPV4};

    /// 端到端：SOCKS5 client → SOCKS5 inbound → freedom outbound → echo server。
    #[tokio::test]
    async fn socks5_inbound_to_freedom_outbound_e2e() {
        // 1. 起 echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        // 2. 配置 dispatcher：freedom outbound → SimpleOhm default
        let ohm = Arc::new(SimpleOhm::new());
        let dial_fn = make_freedom_dial_fn();
        let bridge = std::sync::Arc::new(xray_app_dispatcher::default::DialBridge::new(
            "freedom",
            dial_fn,
        )) as std::sync::Arc<dyn xray_app_dispatcher::DispatchHandler>;
        ohm.set_default(bridge);

        // 3. 起 SOCKS5 inbound
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let config = Arc::new(ServerConfig::default());
        let ohm_clone = Arc::clone(&ohm);
        tokio::spawn(async move {
            let _ = serve_socks5(socks_listener, ohm_clone, config).await;
        });

        // 4. SOCKS5 client：连 socks5 → handshake → 请求 echo server → 写数据 → 读 echo
        let mut client = TcpStream::connect(socks_addr).await.unwrap();
        // 握手：版本 5，1 method，no-auth(0)
        client
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00], "server should select no-auth");

        // 请求 CONNECT echo_addr（IPv4）
        let ip = echo_addr.ip();
        assert!(ip.is_ipv4(), "echo addr should be ipv4");
        let ipv4_bytes = match ip {
            std::net::IpAddr::V4(v4) => v4.octets(),
            _ => unreachable!(),
        };
        let port_bytes = echo_addr.port().to_be_bytes();
        let mut req = vec![0x05, 0x01, 0x00, ATYP_IPV4];
        req.extend_from_slice(&ipv4_bytes);
        req.extend_from_slice(&port_bytes);
        client.write_all(&req).await.unwrap();

        // 读 CONNECT 成功响应（10 字节）
        let mut connect_resp = [0u8; 10];
        client.read_exact(&mut connect_resp).await.unwrap();
        assert_eq!(connect_resp[1], 0x00, "CONNECT should succeed");

        // 5. 发数据 + 读 echo
        let payload = b"hello socks5 proxy!";
        client.write_all(payload).await.unwrap();

        let mut got = vec![0u8; payload.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, payload, "should receive echo through proxy");
    }

    #[test]
    fn socks_addr_to_destination_ipv4() {
        let addr = SocksAddr {
            host: Host::Ipv4(Ipv4Addr::new(1, 2, 3, 4)),
            port: 8080,
        };
        let dest = socks_addr_to_destination(&addr).unwrap();
        assert!(dest.is_tcp());
        assert_eq!(dest.port(), Port::new(8080));
        match dest.address() {
            Address::IPv4(ip) => assert_eq!(ip.octets(), [1, 2, 3, 4]),
            other => panic!("expected IPv4, got {other:?}"),
        }
    }

    #[test]
    fn socks_addr_to_destination_domain() {
        let addr = SocksAddr {
            host: Host::Domain("example.com".to_string()),
            port: 443,
        };
        let dest = socks_addr_to_destination(&addr).unwrap();
        assert_eq!(dest.port(), Port::new(443));
        match dest.address() {
            Address::Domain(d) => assert_eq!(d, "example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
        let _ = ATYP_DOMAIN; // 确认 import 路径
    }

    #[test]
    fn build_vless_validator_parses_clients_json() {
        let uuid = "66ad4540-b58c-4ad2-9926-ea63445a9b57";
        let settings = serde_json::json!({
            "clients": [{ "id": uuid, "email": "alice@example.com", "level": 0 },
                          { "id": "11111111-2222-3333-4444-555555555555", "email": "bob" }],
            "decryption": "none",
        });
        let data = serde_json::to_vec(&settings).unwrap();
        let validator = super::build_vless_validator(&data).unwrap();
        // get_count from Validator trait
        use xray_proxy_vless::Validator as VlessValidatorTrait;
        assert_eq!(VlessValidatorTrait::get_count(&*validator), 2);
        // 用户可被取出（按 UUID lookup）
        let parsed_uuid = xray_common::uuid::UUID::parse(uuid).expect("uuid");
        let user = VlessValidatorTrait::get(&*validator, &parsed_uuid).expect("user should be registered");
        assert_eq!(user.email, "alice@example.com");
    }

    #[test]
    fn build_vless_validator_empty_clients() {
        let settings = serde_json::json!({ "decryption": "none" });
        let data = serde_json::to_vec(&settings).unwrap();
        let validator = super::build_vless_validator(&data).unwrap();
        use xray_proxy_vless::Validator as VlessValidatorTrait;
        assert_eq!(VlessValidatorTrait::get_count(&*validator), 0);
    }

    #[test]
    fn build_vless_validator_invalid_json() {
        let bad = b"not a json";
        let err = super::build_vless_validator(bad);
        assert!(err.is_err(), "invalid JSON should error");
    }

    #[test]
    fn build_trojan_users_parses_clients_json() {
        let settings = serde_json::json!({
            "clients": [{ "password": "secret", "email": "alice" },
                          { "password": "another", "email": "bob" }],
        });
        let data = serde_json::to_vec(&settings).unwrap();
        let users = super::build_trojan_users(&data).unwrap();
        assert_eq!(users.len(), 2, "should parse 2 trojan users");
        // 手动构造同样的 account 验证 key_hash 一致
        let expected_account = TrojanMemoryAccount::new("secret");
        let expected_user = TrojanMemoryUser::new("alice", 0, expected_account);
        assert!(users.contains_key(&expected_user.key_hash()));
    }

    #[test]
    fn build_trojan_users_empty_clients() {
        let settings = serde_json::json!({});
        let data = serde_json::to_vec(&settings).unwrap();
        let users = super::build_trojan_users(&data).unwrap();
        assert!(users.is_empty());
    }

    #[test]
    fn build_vmess_validator_parses_clients_json() {
        let uuid = "66ad4540-b58c-4ad2-9926-ea63445a9b57";
        let settings = serde_json::json!({
            "clients": [{ "id": uuid, "email": "alice", "level": 0 },
                          { "id": "11111111-2222-3333-4444-555555555555", "email": "bob" }],
        });
        let data = serde_json::to_vec(&settings).unwrap();
        let validator = super::build_vmess_validator(&data).unwrap();
        use xray_proxy_vmess::Validator as VmessValidatorTrait;
        assert_eq!(VmessValidatorTrait::count(&*validator), 2);
    }

    #[test]
    fn build_vmess_validator_invalid_uuid() {
        let settings = serde_json::json!({ "clients": [{ "id": "not-a-uuid" }] });
        let data = serde_json::to_vec(&settings).unwrap();
        assert!(super::build_vmess_validator(&data).is_err());
    }

    #[test]
    fn parse_http_config_extracts_accounts() {
        let settings = serde_json::json!({
            "accounts": [{ "user": "u1", "pass": "p1" }, { "user": "u2", "pass": "p2" }]
        });
        let data = serde_json::to_vec(&settings).unwrap();
        let cfg = super::parse_http_config(&data).unwrap();
        assert_eq!(cfg.accounts.get("u1").unwrap(), "p1");
        assert_eq!(cfg.accounts.get("u2").unwrap(), "p2");
    }

    #[test]
    fn parse_http_config_empty_returns_default() {
        let data = b"{}";
        let cfg = super::parse_http_config(data).unwrap();
        assert!(cfg.accounts.is_empty());
    }

    #[test]
    fn parse_dokodemo_dest_ipv4() {
        let settings = serde_json::json!({ "address": "192.168.1.1", "port": 8080 });
        let data = serde_json::to_vec(&settings).unwrap();
        let dest = super::parse_dokodemo_dest(&data).unwrap();
        assert!(matches!(dest.address(), Address::IPv4(_)));
        assert_eq!(dest.port().value(), 8080);
    }

    #[test]
    fn parse_dokodemo_dest_domain() {
        let settings = serde_json::json!({ "address": "example.com", "port": 443 });
        let data = serde_json::to_vec(&settings).unwrap();
        let dest = super::parse_dokodemo_dest(&data).unwrap();
        assert!(matches!(dest.address(), Address::Domain(_)));
        assert_eq!(dest.port().value(), 443);
    }

    #[test]
    fn parse_dokodemo_dest_missing_address_returns_err() {
        let settings = serde_json::json!({ "port": 80 });
        let data = serde_json::to_vec(&settings).unwrap();
        assert!(super::parse_dokodemo_dest(&data).is_err());
    }

    #[test]
    fn parse_dokodemo_dest_missing_port_returns_err() {
        let settings = serde_json::json!({ "address": "1.2.3.4" });
        let data = serde_json::to_vec(&settings).unwrap();
        assert!(super::parse_dokodemo_dest(&data).is_err());
    }

    #[test]
    fn is_mux_destination_detects_mux_cool() {
        let dest = Destination::new(
            Address::Domain("v1.mux.cool".to_string()),
            Port::new(9527),
            Network::TCP,
        );
        assert!(super::is_mux_destination(&dest));
    }

    #[test]
    fn is_mux_destination_rejects_normal_domain() {
        let dest = Destination::new(
            Address::Domain("example.com".to_string()),
            Port::new(443),
            Network::TCP,
        );
        assert!(!super::is_mux_destination(&dest));
    }

    #[test]
    fn is_mux_destination_rejects_wrong_port() {
        let dest = Destination::new(
            Address::Domain("v1.mux.cool".to_string()),
            Port::new(80),  // 不是 9527
            Network::TCP,
        );
        assert!(!super::is_mux_destination(&dest));
    }

    #[test]
    fn is_mux_destination_rejects_ipv4() {
        let dest = Destination::new(
            Address::IPv4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
            Port::new(9527),
            Network::TCP,
        );
        assert!(!super::is_mux_destination(&dest));
    }

    #[test]
    fn build_vmess_validator_empty_clients() {
        let settings = serde_json::json!({});
        let data = serde_json::to_vec(&settings).unwrap();
        let validator = super::build_vmess_validator(&data).unwrap();
        use xray_proxy_vmess::Validator as VmessValidatorTrait;
        assert_eq!(VmessValidatorTrait::count(&*validator), 0);
    }
}

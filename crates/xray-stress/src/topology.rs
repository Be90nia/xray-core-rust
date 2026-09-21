//! 拓扑构建：echo server、start_full 双实例配置（REALITY / mKCP 链路）、就绪探针。
//!
//! 配置模板对齐 tests/integration/transport_interop_test.rs 既有 e2e 形态
//! （REALITY 用 watfaq-rustls fallback fingerprint，绕过 btls transcript 已知问题）。

use base64::Engine as _;
use tokio::net::{TcpListener, TcpStream};
use xray_conf::{BuiltConfig, BuiltEntry, BuiltInbound, BuiltOutbound};
use xray_core::functions::start_full;

pub const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
pub const SHORT_ID_HEX: &str = "0123456789abcdef";
/// listener 就绪 + QUIC/KCP 握手 warmup（e2e 同款量级）。
pub const READY_WARMUP: std::time::Duration = std::time::Duration::from_millis(500);

/// rustls 默认 ring provider 装一次（REALITY fallback 与 hysteria QUIC 都依赖）。
pub fn ensure_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub async fn pick_free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").await.expect("pick port");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);
    port
}

/// 无状态 echo：读到什么回什么（roundtrip 语义载体）。
pub async fn start_echo() -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut sock, _)) => {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 64 * 1024];
                        loop {
                            match sock.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if sock.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                },
                            }
                        }
                    });
                },
                Err(_) => break,
            }
        }
    });
    addr
}

/// REALITY 密钥对（base64 raw），对齐 e2e 的 x25519_dalek 形态。
fn reality_keypair() -> (String, String) {
    use rand::RngCore;
    use x25519_dalek::{PublicKey, StaticSecret};
    let mut priv_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut priv_bytes);
    let secret = StaticSecret::from(priv_bytes);
    let public = PublicKey::from(&secret);
    let b64 = base64::engine::general_purpose::STANDARD;
    (
        b64.encode(priv_bytes),
        b64.encode(public.as_bytes()),
    )
}

fn built_inbound(kind: &str, data: Vec<u8>, tag: &str, port: u16) -> BuiltInbound {
    BuiltInbound {
        entry: BuiltEntry { kind: kind.into(), data },
        tag: tag.into(),
        port: Some(port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    }
}

fn built_outbound(kind: &str, data: Vec<u8>, tag: &str, stream: serde_json::Value) -> BuiltOutbound {
    BuiltOutbound {
        entry: BuiltEntry { kind: kind.into(), data },
        tag: tag.into(),
        send_through: None,
        stream_settings_json: Some(stream),
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    }
}

fn socks_inbound(port: u16) -> BuiltInbound {
    built_inbound("socks", vec![], "socks-in", port)
}

fn freedom_outbound() -> BuiltOutbound {
    // 默认规则按入站协议推导（Go getDefaultFinalRule：vless → BlockPrivate
    // 封禁 127.0.0.0/8）——harness 全链 loopback，显式 finalRules 放行回环。
    BuiltOutbound {
        entry: BuiltEntry {
            kind: "freedom".into(),
            data: br#"{"finalRules":[{"action":"allow","network":"tcp,udp","ip":["127.0.0.0/8","::1/128"]}]}"#.to_vec(),
        },
        tag: "direct".into(),
        send_through: None,
        stream_settings_json: None,
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    }
}

fn vless_inbound(port: u16, tag: &str) -> BuiltInbound {
    built_inbound(
        "vless",
        // Go vless.go:155-157 parity：decryption 缺省即拒启，必须显式 "none"
        format!(r#"{{"decryption":"none","clients":[{{"id":"{TEST_UUID}"}}]}}"#).into_bytes(),
        tag,
        port,
    )
}

fn vless_outbound(upstream_port: u16, stream: serde_json::Value) -> BuiltOutbound {
    built_outbound(
        "vless",
        format!(
            r#"{{"vnext":[{{"address":"127.0.0.1","port":{upstream_port},"users":[{{"id":"{TEST_UUID}","encryption":"none"}}]}}]}}"#
        )
        .into_bytes(),
        "proxy",
        stream,
    )
}

/// 起一组「server: vless+REALITY inbound + freedom」/「client: socks + vless+REALITY outbound」
/// 双实例。返回 (socks_port, server_handles, client_handles)。
pub async fn start_reality_link(
    echo_port: u16,
) -> anyhow::Result<(u16, Vec<tokio::task::JoinHandle<()>>, Vec<tokio::task::JoinHandle<()>>)> {
    let (priv_b64, pub_b64) = reality_keypair();
    let vless_port = pick_free_port().await;
    let socks_port = pick_free_port().await;

    let server_reality: serde_json::Value = serde_json::from_str(&format!(
        r#"{{"network":"tcp","security":"reality","realitySettings":{{"privateKey":"{priv_b64}","serverNames":["localhost"],"shortIds":["{SHORT_ID_HEX}"],"dest":"127.0.0.1:{echo_port}"}}}}"#
    ))?;
    let client_reality: serde_json::Value = serde_json::from_str(&format!(
        r#"{{"network":"tcp","security":"reality","realitySettings":{{"serverName":"localhost","publicKey":"{pub_b64}","shortId":"{SHORT_ID_HEX}","fingerprint":"randomizednoalpn"}}}}"#
    ))?;

    let mut server_cfg = BuiltConfig::default();
    server_cfg.inbounds.push(vless_inbound(vless_port, "stress-reality-in"));
    server_cfg.outbounds.push(freedom_outbound());
    server_cfg.inbounds[0].stream_settings_json = Some(server_reality);

    let mut client_cfg = BuiltConfig::default();
    client_cfg.inbounds.push(socks_inbound(socks_port));
    client_cfg.outbounds.push(vless_outbound(vless_port, client_reality));

    let (_si, _so, sh) = start_full(&server_cfg).await.map_err(|e| anyhow::anyhow!("reality server: {e}"))?;
    let (_ci, _co, ch) = start_full(&client_cfg).await.map_err(|e| anyhow::anyhow!("reality client: {e}"))?;
    tokio::time::sleep(READY_WARMUP).await;
    Ok((socks_port, sh, ch))
}

/// 起一组 vless+mKCP 双实例。返回 (socks_port, handles...)。
pub async fn start_kcp_link(
    echo_port: u16,
) -> anyhow::Result<(u16, Vec<tokio::task::JoinHandle<()>>, Vec<tokio::task::JoinHandle<()>>)> {
    let _ = echo_port; // kcp dest 由 socks 请求目标决定，echo 端口仅用于探针
    let vless_port = pick_free_port().await;
    let socks_port = pick_free_port().await;
    let kcp: serde_json::Value =
        serde_json::from_str(r#"{"network":"kcp","security":"none","kcpSettings":{}}"#)?;

    let mut server_cfg = BuiltConfig::default();
    server_cfg.inbounds.push(vless_inbound(vless_port, "stress-kcp-in"));
    server_cfg.outbounds.push(freedom_outbound());
    server_cfg.inbounds[0].stream_settings_json = Some(kcp.clone());

    let mut client_cfg = BuiltConfig::default();
    client_cfg.inbounds.push(socks_inbound(socks_port));
    client_cfg.outbounds.push(vless_outbound(vless_port, kcp));

    let (_si, _so, sh) = start_full(&server_cfg).await.map_err(|e| anyhow::anyhow!("kcp server: {e}"))?;
    let (_ci, _co, ch) = start_full(&client_cfg).await.map_err(|e| anyhow::anyhow!("kcp client: {e}"))?;
    tokio::time::sleep(READY_WARMUP).await;
    Ok((socks_port, sh, ch))
}

/// 首连探针：链路不通立即失败，避免长跑空转。
pub async fn probe_socks_roundtrip(proxy_port: u16, echo_port: u16) -> anyhow::Result<()> {
    let payload = b"GET / HTTP/1.0\r\nUser-Agent: xray-stress-probe\r\n\r\n";
    socks_roundtrip(proxy_port, echo_port, payload)
        .await
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("probe roundtrip failed: {e}"))
}

/// 单次 SOCKS5 → echo roundtrip（greet + CONNECT + 写 payload + 读回显）。
pub async fn socks_roundtrip(
    proxy_port: u16,
    echo_port: u16,
    payload: &[u8],
) -> std::io::Result<usize> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut sock = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
    sock.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greet = [0u8; 2];
    sock.read_exact(&mut greet).await?;
    if greet != [0x05, 0x00] {
        return Err(std::io::Error::other(format!("socks greet rejected: {greet:?}")));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&echo_port.to_be_bytes());
    sock.write_all(&req).await?;
    let mut cr = [0u8; 10];
    sock.read_exact(&mut cr).await?;
    if cr[1] != 0x00 {
        return Err(std::io::Error::other(format!("socks CONNECT failed: {}", cr[1])));
    }
    sock.write_all(payload).await?;
    let mut got = vec![0u8; payload.len()];
    sock.read_exact(&mut got).await?;
    if got != payload {
        return Err(std::io::Error::other("echo payload mismatch"));
    }
    Ok(payload.len())
}

// ===== s5-s12 协议链 =====
//
// 模板对齐 tests/integration/transport_interop_test.rs（ws/grpc/tls）与
// xray-core functions.rs integration 测试（trojan/ss）；tuic/anytls 对齐
// xray-core inbound.rs/outbound.rs 解析格式（自签证书缺省路径）。
// 偏差注记：s9 anytls 的 TLS 由协议自持（outbound 不消费 streamSettings
// network，inbound 自建 rustls acceptor），故无 httpupgrade underlay 可接；
// s12 的裸 QUIC transport 已被 Go v26 移除（迁移到 XHTTP stream-one H3，
// 见 xray-transport/src/dialer.rs removed_feature_warnings），按对齐语义
// 实现为 vmess + splithttp ALPN=h3（QUIC 承载）。

/// 双实例拓扑句柄：(client socks 端口, server 任务句柄, client 任务句柄)。
pub type LinkHandles = (
    u16,
    Vec<tokio::task::JoinHandle<()>>,
    Vec<tokio::task::JoinHandle<()>>,
);

const STRESS_TROJAN_PASSWORD: &str = "stress-trojan-pass";
const STRESS_SS_PASSWORD: &str = "stress-ss-pass";
const STRESS_ANYTLS_PASSWORD: &str = "stress-anytls-pass";
const STRESS_TUIC_PASSWORD: &str = "stress-tuic-pass";

fn vmess_inbound(port: u16, tag: &str) -> BuiltInbound {
    built_inbound(
        "vmess",
        format!(r#"{{"clients":[{{"id":"{TEST_UUID}"}}]}}"#).into_bytes(),
        tag,
        port,
    )
}

fn vmess_outbound(upstream_port: u16, stream: serde_json::Value) -> BuiltOutbound {
    built_outbound(
        "vmess",
        format!(
            r#"{{"vnext":[{{"address":"127.0.0.1","port":{upstream_port},"users":[{{"id":"{TEST_UUID}","security":"aes-128-gcm"}}]}}]}}"#
        )
        .into_bytes(),
        "proxy",
        stream,
    )
}

fn trojan_inbound(port: u16, tag: &str) -> BuiltInbound {
    built_inbound(
        "trojan",
        format!(r#"{{"clients":[{{"password":"{STRESS_TROJAN_PASSWORD}"}}]}}"#).into_bytes(),
        tag,
        port,
    )
}

fn trojan_outbound(upstream_port: u16, stream: serde_json::Value) -> BuiltOutbound {
    built_outbound(
        "trojan",
        format!(
            r#"{{"servers":[{{"address":"127.0.0.1","port":{upstream_port},"password":"{STRESS_TROJAN_PASSWORD}"}}]}}"#
        )
        .into_bytes(),
        "proxy",
        stream,
    )
}

fn ss_inbound(port: u16, tag: &str) -> BuiltInbound {
    built_inbound(
        "shadowsocks",
        format!(r#"{{"clients":[{{"password":"{STRESS_SS_PASSWORD}","method":"aes-256-gcm"}}]}}"#)
            .into_bytes(),
        tag,
        port,
    )
}

fn ss_outbound(upstream_port: u16, stream: serde_json::Value) -> BuiltOutbound {
    built_outbound(
        "shadowsocks",
        format!(
            r#"{{"servers":[{{"address":"127.0.0.1","port":{upstream_port},"password":"{STRESS_SS_PASSWORD}","method":"aes-256-gcm"}}]}}"#
        )
        .into_bytes(),
        "proxy",
        stream,
    )
}

fn tuic_inbound(port: u16, tag: &str) -> BuiltInbound {
    // 证书缺省 = rcgen 自签（inbound.rs parse_tuic_inbound_settings 测试路径）
    built_inbound(
        "tuic",
        format!(r#"{{"uuid":"{TEST_UUID}","password":"{STRESS_TUIC_PASSWORD}"}}"#).into_bytes(),
        tag,
        port,
    )
}

fn tuic_outbound(upstream_port: u16) -> BuiltOutbound {
    // insecure=true：自签证书放行；alpn 缺省 [h3, tuic]（outbound.rs build_tuic_rustls_config）
    built_outbound(
        "tuic",
        format!(
            r#"{{"servers":[{{"address":"127.0.0.1","port":{upstream_port},"uuid":"{TEST_UUID}","password":"{STRESS_TUIC_PASSWORD}","insecure":true}}]}}"#
        )
        .into_bytes(),
        "proxy",
        serde_json::json!({"network":"tcp","security":"none"}),
    )
}

fn anytls_outbound(upstream_port: u16) -> BuiltOutbound {
    built_outbound(
        "anytls",
        format!(
            r#"{{"server":"127.0.0.1","server_port":{upstream_port},"password":"{STRESS_ANYTLS_PASSWORD}","insecure":true,"sni":"localhost"}}"#
        )
        .into_bytes(),
        "proxy",
        serde_json::json!({"network":"tcp","security":"none"}),
    )
}

fn http_inbound(port: u16, tag: &str) -> BuiltInbound {
    // 无账号 = 免认证 HTTP 代理（CONNECT + plain）
    built_inbound("http", br#"{}"#.to_vec(), tag, port)
}

fn http_outbound(upstream_port: u16) -> BuiltOutbound {
    built_outbound(
        "http",
        format!(
            r#"{{"servers":[{{"address":"127.0.0.1","port":{upstream_port}}}]}}"#
        )
        .into_bytes(),
        "proxy",
        serde_json::json!({"network":"tcp","security":"none"}),
    )
}

/// s5：vmess+websocket 传输设置（security none）。
fn vmess_ws_stream() -> serde_json::Value {
    serde_json::json!({"network":"ws","security":"none","wsSettings":{"path":"/stress-vmess-ws"}})
}

/// s6：trojan+gRPC 传输设置（security none，同 interop grpc 形态）。
fn trojan_grpc_stream() -> serde_json::Value {
    serde_json::json!({"network":"grpc","security":"none","grpcSettings":{"serviceName":"GunService"}})
}

/// s10：vless+splithttp mode=auto（auto + 无 REALITY → packet-up）。
fn splithttp_auto_stream() -> serde_json::Value {
    serde_json::json!({"network":"splithttp","security":"none","splithttpSettings":{"path":"/stress-xh","mode":"auto"}})
}

/// s12：vmess+splithttp H3（QUIC 承载）双端设置。
/// 服务端 alpn=["h3"] + 证书 → isH3 QUIC listener；客户端 allowInsecure + alpn h3 → dial_h3。
fn splithttp_h3_streams(cert_pem: &str, key_pem: &str) -> (serde_json::Value, serde_json::Value) {
    let server = serde_json::json!({
        "network": "splithttp", "security": "tls",
        "splithttpSettings": {"path": "/stress-h3"},
        "tlsSettings": {
            "certificates": [{"certificate": [cert_pem], "key": [key_pem]}],
            "alpn": ["h3"],
        },
    });
    let client = serde_json::json!({
        "network": "splithttp", "security": "tls",
        "splithttpSettings": {"path": "/stress-h3", "mode": "auto"},
        "tlsSettings": {"allowInsecure": true, "serverName": "localhost", "alpn": ["h3"]},
    });
    (server, client)
}

/// 通用 start_full 双实例：server = 单协议 inbound(+stream) + freedom；
/// client = socks + 指定 outbound。装配后 READY_WARMUP 就绪等待。
async fn start_dual(
    link: &str,
    mut server_in: BuiltInbound,
    server_stream: Option<serde_json::Value>,
    client_out: BuiltOutbound,
    socks_port: u16,
) -> anyhow::Result<LinkHandles> {
    server_in.stream_settings_json = server_stream;
    let mut server_cfg = BuiltConfig::default();
    server_cfg.inbounds.push(server_in);
    server_cfg.outbounds.push(freedom_outbound());

    let mut client_cfg = BuiltConfig::default();
    client_cfg.inbounds.push(socks_inbound(socks_port));
    client_cfg.outbounds.push(client_out);

    let (_si, _so, sh) = start_full(&server_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("{link} server: {e}"))?;
    let (_ci, _co, ch) = start_full(&client_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("{link} client: {e}"))?;
    tokio::time::sleep(READY_WARMUP).await;
    Ok((socks_port, sh, ch))
}

async fn start_simple_link(
    link: &str,
    server_in: BuiltInbound,
    server_stream: Option<serde_json::Value>,
    client_out: BuiltOutbound,
) -> anyhow::Result<LinkHandles> {
    let socks_port = pick_free_port().await;
    start_dual(link, server_in, server_stream, client_out, socks_port).await
}

/// s5：vmess(aes-128-gcm) + websocket 双实例。
pub async fn start_vmess_ws_link(echo_port: u16) -> anyhow::Result<LinkHandles> {
    let _ = echo_port;
    let proto_port = pick_free_port().await;
    start_simple_link(
        "vmess-ws",
        vmess_inbound(proto_port, "stress-vmess-ws-in"),
        Some(vmess_ws_stream()),
        vmess_outbound(proto_port, vmess_ws_stream()),
    )
    .await
}

/// s6：trojan + gRPC 双实例（security none，Go trojan 支持明文 TCP 承载）。
pub async fn start_trojan_grpc_link(echo_port: u16) -> anyhow::Result<LinkHandles> {
    let _ = echo_port;
    let proto_port = pick_free_port().await;
    start_simple_link(
        "trojan-grpc",
        trojan_inbound(proto_port, "stress-trojan-grpc-in"),
        Some(trojan_grpc_stream()),
        trojan_outbound(proto_port, trojan_grpc_stream()),
    )
    .await
}

/// s7：shadowsocks(aes-256-gcm) + tcp 双实例。
pub async fn start_ss_link(echo_port: u16) -> anyhow::Result<LinkHandles> {
    let _ = echo_port;
    let proto_port = pick_free_port().await;
    start_simple_link(
        "ss-tcp",
        ss_inbound(proto_port, "stress-ss-in"),
        None,
        ss_outbound(proto_port, serde_json::json!({"network":"tcp","security":"none"})),
    )
    .await
}

/// s8：tuic v5 双实例（QUIC 系；服务端 rcgen 自签，客户端 insecure）。
pub async fn start_tuic_link(echo_port: u16) -> anyhow::Result<LinkHandles> {
    let _ = echo_port;
    let proto_port = pick_free_port().await;
    start_simple_link(
        "tuic",
        tuic_inbound(proto_port, "stress-tuic-in"),
        None,
        tuic_outbound(proto_port),
    )
    .await
}

/// s9：anytls 双实例（TLS 由 anytls 协议自持；见顶部偏差注记）。
///
/// 服务端不走 start_full：xray-core anytls 入站的 handler 在 start() 返回后
/// 即被 drop（stop_tx 随之消失，MockServer serve_loop 的 select! 在
/// sender-dropped 分支 break → listener 关闭）——生产接线缺陷，实测连接全被
/// 拒（os error 10061）。生产 crate 红线禁改，harness 侧按 anytls crate
/// 自带 e2e 形态（dispatcher_loopback.rs）直挂 `AnytlsMockServer` 持有存活，
/// anytls session + TLS 协议栈路径不变；客户端侧仍走 start_full 生产 dispatch。
pub async fn start_anytls_link(_echo_port: u16) -> anyhow::Result<LinkHandles> {
    let proto_port = pick_free_port().await;
    let socks_port = pick_free_port().await;

    let (cert_pem, key_pem) = xray_tls::certificate::generate_self_signed_cert(&["localhost"])
        .map_err(|e| anyhow::anyhow!("anytls self-signed cert: {e}"))?;
    let cert_der = crate::quic_loop::pem_to_der(&cert_pem)?;
    let key_der = crate::quic_loop::pem_to_der(&key_pem)?;
    let server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert_der)],
            rustls::pki_types::PrivateKeyDer::try_from(key_der)
                .map_err(|e| anyhow::anyhow!("anytls private key der: {e}"))?,
        )
        .map_err(|e| anyhow::anyhow!("anytls server rustls config: {e}"))?;
    let server = xray_proxy_anytls::server::AnytlsMockServer::start_with_password(
        std::net::SocketAddr::from(([127, 0, 0, 1], proto_port)),
        tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_tls)),
        None, // mock 直连 echo（anytls crate e2e 同形态；dispatch 路径由客户端实例承载）
        Some(STRESS_ANYTLS_PASSWORD),
    )
    .await
    .map_err(|e| anyhow::anyhow!("anytls server bind: {e}"))?;
    // 持有 server 存活至 run 结束（abort 时随 task drop）
    let keep = tokio::spawn(async move {
        let _server = server;
        std::future::pending::<()>().await;
    });

    let mut client_cfg = BuiltConfig::default();
    client_cfg.inbounds.push(socks_inbound(socks_port));
    client_cfg.outbounds.push(anytls_outbound(proto_port));
    let (_ci, _co, ch) = start_full(&client_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("anytls client: {e}"))?;
    tokio::time::sleep(READY_WARMUP).await;
    Ok((socks_port, vec![keep], ch))
}

/// s10：vless + splithttp(mode=auto → packet-up) 双实例。
pub async fn start_splithttp_link(echo_port: u16) -> anyhow::Result<LinkHandles> {
    let _ = echo_port;
    let proto_port = pick_free_port().await;
    start_simple_link(
        "vless-xhttp",
        vless_inbound(proto_port, "stress-xh-in"),
        Some(splithttp_auto_stream()),
        vless_outbound(proto_port, splithttp_auto_stream()),
    )
    .await
}

/// s11：http 代理入站 + http outbound（CONNECT 语义链路）双实例。
pub async fn start_http_link(echo_port: u16) -> anyhow::Result<LinkHandles> {
    let _ = echo_port;
    let proto_port = pick_free_port().await;
    start_simple_link(
        "http-proxy",
        http_inbound(proto_port, "stress-http-in"),
        None,
        http_outbound(proto_port),
    )
    .await
}

/// s12：vmess + splithttp H3（QUIC 承载，Go v26 对裸 QUIC transport 的替代形态）双实例。
pub async fn start_vmess_h3_link(echo_port: u16) -> anyhow::Result<LinkHandles> {
    let _ = echo_port;
    let (cert_pem, key_pem) = xray_tls::certificate::generate_self_signed_cert(&["localhost"])
        .map_err(|e| anyhow::anyhow!("h3 self-signed cert: {e}"))?;
    let (server_stream, client_stream) = splithttp_h3_streams(&cert_pem, &key_pem);
    let proto_port = pick_free_port().await;
    start_simple_link(
        "vmess-h3",
        vmess_inbound(proto_port, "stress-vmess-h3-in"),
        Some(server_stream),
        vmess_outbound(proto_port, client_stream),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// s5 模板：vmess 出站 security=aes-128-gcm + ws stream 字段。
    #[test]
    fn vmess_ws_template_fields() {
        let out = vmess_outbound(12345, vmess_ws_stream());
        assert_eq!(out.entry.kind, "vmess");
        let v: serde_json::Value = serde_json::from_slice(&out.entry.data).unwrap();
        let user = &v["vnext"][0];
        assert_eq!(user["port"], 12345);
        assert_eq!(user["users"][0]["security"], "aes-128-gcm");
        assert_eq!(user["users"][0]["id"], TEST_UUID);
        assert_eq!(out.stream_settings_json.as_ref().unwrap()["network"], "ws");
        assert_eq!(
            out.stream_settings_json.as_ref().unwrap()["wsSettings"]["path"],
            "/stress-vmess-ws"
        );
    }

    /// s6 模板：trojan 密码两端一致 + grpc serviceName。
    #[test]
    fn trojan_grpc_template_fields() {
        let ib = trojan_inbound(1, "t");
        let iv: serde_json::Value = serde_json::from_slice(&ib.entry.data).unwrap();
        assert_eq!(iv["clients"][0]["password"], STRESS_TROJAN_PASSWORD);
        let out = trojan_outbound(23456, trojan_grpc_stream());
        let ov: serde_json::Value = serde_json::from_slice(&out.entry.data).unwrap();
        assert_eq!(ov["servers"][0]["port"], 23456);
        assert_eq!(ov["servers"][0]["password"], STRESS_TROJAN_PASSWORD);
        let stream = out.stream_settings_json.unwrap();
        assert_eq!(stream["network"], "grpc");
        assert_eq!(stream["grpcSettings"]["serviceName"], "GunService");
    }

    /// s7 模板：ss 双端 aes-256-gcm + 同密码。
    #[test]
    fn ss_template_fields() {
        let iv: serde_json::Value =
            serde_json::from_slice(&ss_inbound(1, "t").entry.data).unwrap();
        assert_eq!(iv["clients"][0]["method"], "aes-256-gcm");
        let out = ss_outbound(34567, serde_json::json!({"network":"tcp","security":"none"}));
        let ov: serde_json::Value = serde_json::from_slice(&out.entry.data).unwrap();
        assert_eq!(ov["servers"][0]["method"], "aes-256-gcm");
        assert_eq!(ov["servers"][0]["password"], iv["clients"][0]["password"]);
    }

    /// s8 模板：tuic uuid 两端一致（=TEST_UUID）+ insecure 放行自签 + 端口对齐。
    #[test]
    fn tuic_template_fields() {
        let iv: serde_json::Value =
            serde_json::from_slice(&tuic_inbound(1, "t").entry.data).unwrap();
        assert_eq!(iv["uuid"], TEST_UUID);
        assert_eq!(iv["password"], STRESS_TUIC_PASSWORD);
        let out = tuic_outbound(45678);
        let ov: serde_json::Value = serde_json::from_slice(&out.entry.data).unwrap();
        assert_eq!(ov["servers"][0]["uuid"], TEST_UUID);
        assert_eq!(ov["servers"][0]["insecure"], true);
        assert_eq!(ov["servers"][0]["port"], 45678);
    }

    /// s9 模板：anytls 出站 server_port/insecure/sni（服务端为 MockServer 直挂，
    /// 见 start_anytls_link 注记，无 inbound 模板）。
    #[test]
    fn anytls_template_fields() {
        let out = anytls_outbound(56789);
        let ov: serde_json::Value = serde_json::from_slice(&out.entry.data).unwrap();
        assert_eq!(ov["server_port"], 56789);
        assert_eq!(ov["insecure"], true);
        assert_eq!(ov["sni"], "localhost");
    }

    /// s10 模板：splithttp mode=auto（无 REALITY → packet-up 语义）。
    #[test]
    fn splithttp_auto_template_fields() {
        let stream = splithttp_auto_stream();
        assert_eq!(stream["network"], "splithttp");
        assert_eq!(stream["security"], "none");
        assert_eq!(stream["splithttpSettings"]["mode"], "auto");
    }

    /// s11 模板：http 入站免认证 + 出站 servers[0] 指向上游。
    #[test]
    fn http_template_fields() {
        let ib = http_inbound(1, "t");
        assert_eq!(ib.entry.kind, "http");
        let out = http_outbound(34567);
        assert_eq!(out.entry.kind, "http");
        let ov: serde_json::Value = serde_json::from_slice(&out.entry.data).unwrap();
        assert_eq!(ov["servers"][0]["address"], "127.0.0.1");
        assert_eq!(ov["servers"][0]["port"], 34567);
    }

    /// s12 模板：双端 security=tls + alpn=["h3"]（isH3/dial_h3 判定条件），
    /// 服务端带证书、客户端 allowInsecure。
    #[test]
    fn splithttp_h3_template_fields() {
        let (server, client) =
            splithttp_h3_streams("-----BEGIN CERTIFICATE-----X", "-----BEGIN KEY-----Y");
        assert_eq!(server["network"], "splithttp");
        assert_eq!(server["security"], "tls");
        assert_eq!(server["tlsSettings"]["alpn"], serde_json::json!(["h3"]));
        assert!(server["tlsSettings"]["certificates"][0]["certificate"]
            .as_array()
            .is_some_and(|a| !a.is_empty()));
        assert_eq!(client["tlsSettings"]["alpn"], serde_json::json!(["h3"]));
        assert_eq!(client["tlsSettings"]["allowInsecure"], true);
        assert_eq!(client["splithttpSettings"]["mode"], "auto");
        assert_eq!(client["splithttpSettings"]["path"], server["splithttpSettings"]["path"]);
    }
}

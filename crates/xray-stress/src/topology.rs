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

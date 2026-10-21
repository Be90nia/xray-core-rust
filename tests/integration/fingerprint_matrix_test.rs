//! uTLS 指纹矩阵 e2e（dofk G-09）：client 指纹 chrome / firefox / safari。
//!
//! 对照 Go `testing/scenarios/vless_test.go:512-513`（`TestVlessRealityFingerprints`）：
//! 注释声明 chrome / firefox / safari 三指纹对 REALITY 全链均可用，且该测试对每指纹
//! 断言 1MB 回环成功。
//!
//! 两条独立路径，分别覆盖不同契约：
//! 1. **VLESS+TLS**（`tls_fingerprint_*`）：验 uTLS 指纹握手 + 数据回显本身，
//!    服务端为 rustls 自签（`allowInsecure`），不涉及 REALITY key-share 门。
//! 2. **VLESS+REALITY**（`reality_fingerprint_*`）：验 REALITY 全链。服务端按 Go
//!    REALITY 语义要求 ClientHello 带 X25519MLKEM768（Go `xtls/reality` tls.go:233-235
//!    `if peerPub2 == nil { break } // reject outdated/strange Client Hello`，
//!    本仓 `crates/xray-reality/src/server.rs:385-388` 同门 → `NoKeyShareX25519`
//!    → reject→forward）。
//!
//! REALITY 无「服务端指纹」配置项（Go `reality.Config.Fingerprint` 是客户端专用字段），
//! 该门只取决于**客户端**模板的 key share，因此矩阵变量只能是客户端指纹。

use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use xray_conf::{BuiltConfig, BuiltEntry, BuiltInbound, BuiltOutbound};
use xray_core::functions::start_full;

/// 监听就绪预热（对齐 `transport_interop_test.rs` 基线）。
const READY_DELAY: Duration = Duration::from_millis(100);
/// REALITY 首握手预热。
const REALITY_WARMUP: Duration = Duration::from_millis(500);
/// 单轮 SOCKS5 连接 + 回显的总预算（握手失败形态是等不到 ServerHello）。
const ECHO_TIMEOUT: Duration = Duration::from_secs(10);

const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const SHORT_ID_HEX: &str = "0123456789abcdef";

/// rustls 默认 ring provider 装一次（REALITY watfaq fallback + uTLS 都要）。
fn ensure_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

async fn start_echo() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

async fn pick_free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").await.expect("pick port");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);
    port
}

/// SOCKS5 CONNECT + 回显一轮；失败返回原因（供契约钉断言，不 panic）。
async fn try_socks5_echo(proxy_port: u16, echo_port: u16, payload: &[u8]) -> Result<(), String> {
    let attempt = async {
        let mut sock = TcpStream::connect(("127.0.0.1", proxy_port))
            .await
            .map_err(|e| format!("socks tcp connect: {e}"))?;
        sock.write_all(&[0x05, 0x01, 0x00]).await.map_err(|e| format!("socks greet write: {e}"))?;
        let mut greet = [0u8; 2];
        sock.read_exact(&mut greet).await.map_err(|e| format!("socks greet read: {e}"))?;
        if greet != [0x05, 0x00] {
            return Err(format!("socks5 no-auth method rejected: {greet:?}"));
        }
        let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        req.extend_from_slice(&echo_port.to_be_bytes());
        sock.write_all(&req).await.map_err(|e| format!("socks connect write: {e}"))?;
        let mut cr = [0u8; 10];
        sock.read_exact(&mut cr).await.map_err(|e| format!("socks connect read: {e}"))?;
        if cr[0] != 0x05 {
            return Err(format!("socks5 version mismatch: {cr:?}"));
        }
        if cr[1] != 0x00 {
            return Err(format!("socks5 CONNECT failed, rep=0x{:02x}", cr[1]));
        }
        sock.write_all(payload).await.map_err(|e| format!("payload write: {e}"))?;
        let mut got = vec![0u8; payload.len()];
        sock.read_exact(&mut got).await.map_err(|e| format!("echo read: {e}"))?;
        if got != payload {
            return Err(format!("echo mismatch: sent {payload:?}, got {got:?}"));
        }
        Ok(())
    };

    match tokio::time::timeout(ECHO_TIMEOUT, attempt).await {
        Ok(inner) => inner,
        Err(_) => Err(format!("no echo within {ECHO_TIMEOUT:?}")),
    }
}

fn vless_inbound(port: u16, tag: &str) -> BuiltInbound {
    BuiltInbound {
        entry: BuiltEntry {
            kind: "vless".into(),
            data: format!(r#"{{"clients":[{{"id":"{TEST_UUID}"}}],"decryption":"none"}}"#)
                .into_bytes(),
        },
        tag: tag.into(),
        port: Some(port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    }
}

fn vless_outbound(upstream_port: u16, stream_settings_json: serde_json::Value) -> BuiltOutbound {
    BuiltOutbound {
        entry: BuiltEntry {
            kind: "vless".into(),
            data: format!(
                r#"{{"vnext":[{{"address":"127.0.0.1","port":{upstream_port},"users":[{{"id":"{TEST_UUID}","encryption":"none"}}]}}]}}"#
            )
            .into_bytes(),
        },
        tag: "proxy".into(),
        send_through: None,
        stream_settings_json: Some(stream_settings_json),
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    }
}

fn freedom_outbound() -> BuiltOutbound {
    BuiltOutbound {
        // vless inbound 默认 final rule BlockPrivate 封回环，echo 目标须显式放行。
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

fn socks_inbound(port: u16) -> BuiltInbound {
    BuiltInbound {
        entry: BuiltEntry { kind: "socks".into(), data: vec![] },
        tag: "socks-in".into(),
        port: Some(port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    }
}

/// 起 server(REALITY)+client(socks) 全栈，跑一轮回显，返回结果。
async fn run_reality_e2e(fingerprint: &str, payload: &[u8]) -> Result<(), String> {
    use base64::Engine;
    use x25519_dalek::{PublicKey, StaticSecret};

    ensure_crypto_provider();

    let echo_addr = start_echo().await;
    let vless_port = pick_free_port().await;
    let socks_port = pick_free_port().await;

    let server_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let server_public = PublicKey::from(&server_secret);
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let priv_key_b64 = b64.encode(server_secret.to_bytes());
    let pub_key_b64 = b64.encode(server_public.as_bytes());

    let server_reality: serde_json::Value = serde_json::from_str(&format!(
        r#"{{"network":"tcp","security":"reality","realitySettings":{{"privateKey":"{priv_key_b64}","shortIds":["{SHORT_ID_HEX}"],"serverNames":["localhost"],"dest":"127.0.0.1:{}"}}}}"#,
        echo_addr.port()
    ))
    .map_err(|e| format!("server reality settings: {e}"))?;
    let client_reality: serde_json::Value = serde_json::from_str(&format!(
        r#"{{"network":"tcp","security":"reality","realitySettings":{{"serverName":"localhost","publicKey":"{pub_key_b64}","shortId":"{SHORT_ID_HEX}","fingerprint":"{fingerprint}"}}}}"#
    ))
    .map_err(|e| format!("client reality settings: {e}"))?;

    let mut server_cfg = BuiltConfig::default();
    server_cfg.inbounds.push(vless_inbound(vless_port, "vless-reality-in"));
    server_cfg.outbounds.push(freedom_outbound());
    server_cfg.inbounds[0].stream_settings_json = Some(server_reality);

    let (_si, _so, sh) =
        start_full(&server_cfg).await.map_err(|e| format!("reality server start: {e:?}"))?;
    tokio::time::sleep(REALITY_WARMUP).await;

    let mut client_cfg = BuiltConfig::default();
    client_cfg.inbounds.push(socks_inbound(socks_port));
    client_cfg.outbounds.push(vless_outbound(vless_port, client_reality));

    let (_ci, _co, ch) =
        start_full(&client_cfg).await.map_err(|e| format!("reality client start: {e:?}"))?;
    tokio::time::sleep(REALITY_WARMUP).await;

    let result = try_socks5_echo(socks_port, echo_addr.port(), payload).await;

    for h in sh.iter().chain(ch.iter()) {
        h.abort();
    }
    result
}

/// 起 server(TLS 自签)+client(socks) 全栈，跑一轮回显，返回结果。
async fn run_tls_e2e(fingerprint: &str, payload: &[u8]) -> Result<(), String> {
    ensure_crypto_provider();

    let echo_addr = start_echo().await;
    let vless_port = pick_free_port().await;
    let socks_port = pick_free_port().await;

    let (cert_pem, key_pem) = xray_tls::certificate::generate_self_signed_cert(&["localhost"])
        .map_err(|e| format!("gen cert: {e:?}"))?;
    let server_tls: serde_json::Value = serde_json::from_str(&format!(
        r#"{{"network":"tcp","security":"tls","tlsSettings":{{"certificates":[{{"certificate":[{cert_pem:?}],"key":[{key_pem:?}]}}]}}}}"#
    ))
    .map_err(|e| format!("server tls settings: {e}"))?;
    let client_tls: serde_json::Value = serde_json::from_str(&format!(
        r#"{{"network":"tcp","security":"tls","tlsSettings":{{"allowInsecure":true,"serverName":"localhost","fingerprint":"{fingerprint}"}}}}"#
    ))
    .map_err(|e| format!("client tls settings: {e}"))?;

    let mut server_cfg = BuiltConfig::default();
    server_cfg.inbounds.push(vless_inbound(vless_port, "vless-tls-in"));
    server_cfg.outbounds.push(freedom_outbound());
    server_cfg.inbounds[0].stream_settings_json = Some(server_tls);

    let (_si, _so, sh) =
        start_full(&server_cfg).await.map_err(|e| format!("tls server start: {e:?}"))?;
    tokio::time::sleep(READY_DELAY).await;

    let mut client_cfg = BuiltConfig::default();
    client_cfg.inbounds.push(socks_inbound(socks_port));
    client_cfg.outbounds.push(vless_outbound(vless_port, client_tls));

    let (_ci, _co, ch) =
        start_full(&client_cfg).await.map_err(|e| format!("tls client start: {e:?}"))?;
    tokio::time::sleep(READY_DELAY).await;

    let result = try_socks5_echo(socks_port, echo_addr.port(), payload).await;

    for h in sh.iter().chain(ch.iter()) {
        h.abort();
    }
    result
}

// --- REALITY 路径 ------------------------------------------------------------

/// chrome 模板带 `[X25519MLKEM768, X25519]` 双 share（`CHROME_133_KEY_SHARES`），
/// 通过 Go 语义的 MLKEM768 门 → 全链回显。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reality_fingerprint_chrome_e2e_echo() {
    run_reality_e2e("chrome", b"hello reality chrome")
        .await
        .expect("chrome fingerprint must complete REALITY echo");
}

/// firefox 模板 `[X25519MLKEM768, X25519, P256]`（`FIREFOX_148_KEY_SHARES`，
/// crates/xray-tls/src/btls_client.rs，对齐 Go uTLS `HelloFirefox_148`
/// u_parrots.go）→ 通过 REALITY 的 MLKEM768 门 → 全链回显。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reality_fingerprint_firefox_e2e_echo() {
    run_reality_e2e("firefox", b"hello reality firefox")
        .await
        .expect("firefox fingerprint must complete REALITY echo");
}

/// safari 模板 `[X25519MLKEM768, X25519]`（`SAFARI_26_3_KEY_SHARES`，
/// crates/xray-tls/src/btls_client.rs，对齐 Go uTLS `HelloSafari_26_3`
/// `[GREASE, X25519MLKEM768, X25519]`，GREASE 条目不可表达故省略）→
/// 通过 REALITY 的 MLKEM768 门 → 全链回显。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reality_fingerprint_safari_e2e_echo() {
    run_reality_e2e("safari", b"hello reality safari")
        .await
        .expect("safari fingerprint must complete REALITY echo");
}

// --- TLS 路径 ----------------------------------------------------------------

/// 三指纹在 VLESS+TLS 上各自完成握手 + TCP 回显：证明 uTLS 指纹模拟本身
/// （ClientHello 构造、crypto provider、证书校验）对三指纹都工作，
/// 与 REALITY 的 key-share 门正交。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_fingerprint_matrix_e2e_echo() {
    for fp in ["chrome", "firefox", "safari"] {
        run_tls_e2e(fp, format!("hello tls {fp}").as_bytes())
            .await
            .unwrap_or_else(|e| panic!("[{fp}] VLESS+TLS echo failed: {e}"));
    }
}

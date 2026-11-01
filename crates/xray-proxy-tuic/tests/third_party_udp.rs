//! TUIC v5 UDP 与**第三方对端**（sing-box）的互通验收（bd j7de2 F3/F4）。
//!
//! 默认 `#[ignore]`：需要外部 sing-box 对端（WSL 内 sing-box + UDP echo）。
//! 编排脚本：`reports/audit-2026-10-31-perf-mem-wiring/fix/tuic_third_party.sh`
//! （脚本在 WSL 起 sing-box 并打印 `SINGBOX_ADDR` / `ECHO_ADDR`，再跑本用例）。
//!
//! 环境变量：
//! - `TUIC_TP_ADDR`：sing-box TUIC 入站 `host:port`
//! - `TUIC_TP_UUID` / `TUIC_TP_PASS`：凭据
//! - `TUIC_TP_ECHO`：UDP echo 目标 `host:port`
//! - `TUIC_TP_MODE`：`quic`（默认，F3 配对键）/ `native`（F4 分片）
//! - `TUIC_TP_SIZE`：载荷字节数（默认 32）
//!
//! 运行：
//! ```text
//! TUIC_TP_ADDR=127.0.0.1:24443 TUIC_TP_UUID=... TUIC_TP_PASS=... \
//! TUIC_TP_ECHO=192.168.x.x:24999 cargo test -p xray-proxy-tuic --test third_party_udp -- --ignored --nocapture
//! ```

#![cfg(test)]

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use xray_proxy_tuic::{client::TuicClient, pool::QuinnConnectionPool, protocol::Address};

/// 测试用「不验签」证书校验器（第三方对端用自签证书；仅本测试文件使用）。
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// 与第三方（sing-box）TUIC v5 对端的 UDP 往返：quic 模式（uni-stream）走
/// `send_recv`，native 模式（DATAGRAM）走 `send_recv_native`。
#[test]
#[ignore = "需要外部第三方对端（sing-box），见 tuic_third_party.sh"]
fn tuic_udp_third_party_roundtrip() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let addr: SocketAddr = env_or("TUIC_TP_ADDR", "127.0.0.1:24443").parse().expect("TUIC_TP_ADDR");
    let uuid =
        uuid::Uuid::parse_str(&env_or("TUIC_TP_UUID", "11111111-2222-3333-4444-555555555555"))
            .expect("TUIC_TP_UUID");
    let pass = env_or("TUIC_TP_PASS", "third-party-pass");
    let echo: SocketAddr = env_or("TUIC_TP_ECHO", "127.0.0.1:24999").parse().expect("TUIC_TP_ECHO");
    let mode = env_or("TUIC_TP_MODE", "quic");
    let size: usize = env_or("TUIC_TP_SIZE", "32").parse().expect("TUIC_TP_SIZE");

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("rt");
    rt.block_on(async move {
        let mut cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        // ALPN：第三方（sing-box）TUIC v5 入站的协议名可能不同（tuic / h3 伪装），
        // 由 TUIC_TP_ALPN 覆盖（逗号分隔）；缺省仅 "tuic"。
        let alpns = env_or("TUIC_TP_ALPN", "tuic");
        cfg.alpn_protocols =
            alpns.split(',').filter(|s| !s.is_empty()).map(|s| s.as_bytes().to_vec()).collect();
        let client_cfg = Arc::new(cfg);
        let client = TuicClient::connect(
            addr,
            "localhost",
            uuid,
            &pass,
            client_cfg,
            QuinnConnectionPool::new(),
        )
        .await
        .expect("connect third-party tuic server");

        let assoc = client.dial_udp(0x0001);
        let target = Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1), echo.port());
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

        let resp = if mode == "native" {
            tokio::time::timeout(
                Duration::from_secs(15),
                assoc.send_recv_native(target, &payload, None),
            )
            .await
            .expect("third-party native send_recv timed out")
            .expect("third-party native send_recv failed")
        } else {
            tokio::time::timeout(Duration::from_secs(15), assoc.send_recv(target, &payload, None))
                .await
                .expect("third-party quic-mode send_recv timed out")
                .expect("third-party quic-mode send_recv failed")
        };

        // 第三方 native 回程按其 buf 池上限（16KB）截断 → 断言「前缀一致 +
        // 不超长」；≤16KB 时必须完整往返。
        assert!(!resp.is_empty(), "第三方回包不得为空");
        assert!(resp.len() <= size, "第三方回包不得超长（{} > {}）", resp.len(), size);
        assert_eq!(&resp[..], &payload[..resp.len()], "第三方回包必须是原载荷的前缀");
        if size <= 16 * 1024 {
            assert_eq!(resp.len(), size, "≤16KB 载荷必须完整逐字节往返");
        }
        client.close(0u32.into(), b"");
    });
}

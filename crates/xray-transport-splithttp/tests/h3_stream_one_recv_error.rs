//! bd qetcn：h3 stream-one 下行 `recv_data` 的真实错误必须抵达读端，禁吞成干净 EOF。
//!
//! 独立测试文件 = 独立测试进程：本仓 h3 测试的 rustls 进程级 CryptoProvider 安装与
//! 握手状态在同进程多 h3 端到端测试间会互相干扰（`invalid peer certificate:
//! BadSignature`），故 h3 端到端用例一律各自成文件。

// 测试编译单元统一豁免（数据面分配纪律见 crate clippy.toml）
#![allow(clippy::disallowed_methods)]
#![allow(clippy::unwrap_used)] // bd g3cr：测试断言便利豁免（allow-unwrap-in-tests 对 tests/ 目录失效，clippy#13981）；生产禁令不受影响
use std::sync::Arc;

use bytes::{Buf, Bytes};
use h3::error::Code;
use http::{Response, StatusCode};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::{io::AsyncReadExt, net::UdpSocket};
use xray_transport_splithttp::{config::Config, dialer::build_request_url, h3_client::H3Conn};

/// 生成自签证书（SAN = 127.0.0.1）+ rustls ServerConfig。
fn make_self_signed_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let params =
        rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("rcgen params");
    let key_pair = rcgen::KeyPair::generate().expect("rcgen keypair");
    let cert = params.self_signed(&key_pair).expect("rcgen self_signed");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
    (cert_der, key_der)
}

/// 客户端 rustls ClientConfig：信任自签证书。
fn make_client_tls(cert_der: CertificateDer<'static>) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).expect("add cert to roots");
    rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()
}

/// 服务端 quinn ServerConfig（自签证书 + ALPN h3）。
fn make_server_crypto(
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
) -> quinn::ServerConfig {
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server cert");
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic =
        quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls)).expect("QuicServerConfig");
    quinn::ServerConfig::with_crypto(Arc::new(quic))
}

/// stream-one 下行中断的 mock server：读完 POST body → 200 → 发一段数据 → **重置发送流**
/// （RESET_STREAM），此后保持连接不关（让客户端先观察到流级错误而非连接级关闭）。
async fn mock_h3_server_reset_downlink(endpoint: quinn::Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(_) => return,
            };
            let quinn_conn = h3_quinn::Connection::new(conn);
            let mut h3_conn = match h3::server::Connection::new(quinn_conn).await {
                Ok(c) => c,
                Err(_) => return,
            };
            while let Ok(Some(req_resolver)) = h3_conn.accept().await {
                let (_req, mut stream) = match req_resolver.resolve_request().await {
                    Ok(rs) => rs,
                    Err(_) => continue,
                };
                tokio::spawn(async move {
                    // 读完上传 body（客户端 write 完即 finish）
                    while let Ok(Some(mut chunk)) = stream.recv_data().await {
                        let len = chunk.remaining();
                        let _ = chunk.copy_to_bytes(len);
                    }
                    let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
                    let _ = stream.send_response(resp).await;
                    let _ = stream.send_data(Bytes::from_static(b"partial")).await;
                    // 先让响应头/首块数据抵达客户端（否则重置会命中 recv_response，
                    // 走不到被测的 recv_data 下行循环）
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    // 下行中断：RESET_STREAM —— 对端 recv_data 必须报错，而不是 EOF
                    stream.stop_stream(Code::H3_INTERNAL_ERROR);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                });
            }
        });
    }
}

/// 改前下行循环是 `while let Ok(Some(..)) = recv_data()`：流重置 ⇒ 循环正常结束 ⇒
/// 读端拿到 `Ok(0)`（本条改前实测 `read_to_end` 返回 `Ok(7)` = 只收到 `partial`），
/// 上层把被截断的代理流当正常结束。Go 侧 `wrc.Set(resp.Body)`（`client.go:94`）的
/// body 读失败是返错，不是 EOF。
#[tokio::test]
async fn stream_one_downlink_recv_error_is_not_eof() {
    static CRYPTO_ONCE: std::sync::Once = std::sync::Once::new();
    CRYPTO_ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });

    let (cert_der, key_der) = make_self_signed_cert();
    let server_crypto = make_server_crypto(cert_der.clone(), key_der);
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let server_addr = socket.local_addr().expect("local addr");
    drop(socket); // 释放端口给 quinn 用
    let endpoint = quinn::Endpoint::server(server_crypto, server_addr).expect("server endpoint");
    let server_task = tokio::spawn(mock_h3_server_reset_downlink(endpoint.clone()));

    let config = Arc::new(Config {
        host: format!("127.0.0.1:{}", server_addr.port()),
        path: "/".into(),
        ..Default::default()
    });
    let h3 = Arc::new(
        H3Conn::connect_with_quic_params(
            config.clone(),
            server_addr,
            "127.0.0.1",
            make_client_tls(cert_der),
            None,
            &xray_transport::sockopt::SocketOptions::default(),
        )
        .await
        .expect("H3Conn::connect_with_quic_params"),
    );

    let base_uri = build_request_url(
        "https",
        &format!("127.0.0.1:{}", server_addr.port()),
        &config.normalized_path(),
        &config.normalized_query(),
    );
    let upload = futures_util::stream::once(async { Ok(Bytes::from_static(b"up")) });
    let (dl, _remote, _local) = h3
        .open_stream_uploading(&base_uri, &uuid::Uuid::new_v4().to_string(), upload, false)
        .await
        .expect("open_stream_uploading");
    let mut dl = dl.expect("stream-one（upload_only=false）必须返回下行流");

    let mut sink = Vec::new();
    let err = dl
        .read_to_end(&mut sink)
        .await
        .expect_err("下行 recv_data 错误必须上报读端，禁吞成干净 EOF");
    assert!(err.to_string().contains("recv_data"), "错误必须带来源标记，实际: {err}");

    drop(endpoint);
    server_task.abort();
}

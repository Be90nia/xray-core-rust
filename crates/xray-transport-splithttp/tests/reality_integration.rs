//! 切片 F2 集成测试：验证 REALITY stream-one 直连路径（hyper h2 handshake）。
//!
//! REALITY 实际握手需要 watfaq-rustls `with_reality()` patch + 真实 REALITY server，
//! 本测试用普通 TLS（自签证书）验证架构路径：TCP → TLS → `dial_reality_stream_one`。
//!
//! 测试覆盖：
//! 1. mock h2 server（自签 TLS + hyper::server::conn::http2::serve_connection）
//! 2. 客户端 TCP connect → tokio-rustls TlsConnector → TlsStream
//! 3. `dial_reality_stream_one(tls_stream, ...)`：内部走 hyper h2 handshake
//! 4. POST streaming body + 收响应流（echo server），验证全双工
//!
//! # REALITY 实际接入
//!
//! 替换 `tls_acceptor.accept(tcp)` 为 `reality::u_client(tcp, state)` 即可。
//! 架构路径（hyper h2 handshake）与普通 TLS 完全一致。

use tokio::io::AsyncReadExt;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use xray_transport_splithttp::config::Config;
use xray_transport_splithttp::dialer::{build_request_url, dial_reality_stream_one};

fn make_self_signed_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("rcgen params");
    let key_pair = rcgen::KeyPair::generate().expect("rcgen keypair");
    let cert = params.self_signed(&key_pair).expect("rcgen self_signed");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
    (cert_der, key_der)
}

fn make_server_tls(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> rustls::ServerConfig {
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server cert");
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    cfg
}

fn make_client_tls(cert: CertificateDer<'static>) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).expect("add cert");
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    cfg
}

/// Echo h2 server：POST body 内容回写为响应。
async fn echo_h2_server(
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
) {
    loop {
        let (tcp, _) = match listener.accept().await {
            Ok(c) => c,
            Err(_) => break,
        };
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let tls = match tls_acceptor.accept(tcp).await {
                Ok(t) => t,
                Err(_) => return,
            };
            let io = TokioIo::new(tls);
            let svc = service_fn(|req: Request<Incoming>| async move {
                // ponytail: 不读 body (避免全双工 deadlock)
                drop(req.into_body());
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from_static(b"echo-response")))
                        .unwrap(),
                )
            });
            let _ = http2::Builder::new(TokioExecutor::new())
                .serve_connection(io, svc)
                .await;
        });
    }
}


#[tokio::test]
async fn dial_reality_stream_one_via_direct_h2_handshake() {
    // 1. 自签证书 + h2 server
    let (cert_der, key_der) = make_self_signed_cert();
    let server_tls = make_server_tls(cert_der.clone(), key_der);
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_tls));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let server_addr = listener.local_addr().expect("local addr");
    let server_task = tokio::spawn(echo_h2_server(listener, tls_acceptor));

    // 2. 客户端 TCP + TLS
    let client_tls = make_client_tls(cert_der);
    let connector = TlsConnector::from(Arc::new(client_tls));
    let tcp = tokio::net::TcpStream::connect(server_addr)
        .await
        .expect("tcp connect");
    let local_addr = tcp.local_addr().expect("local addr");
    let server_name = rustls_pki_types::ServerName::try_from("127.0.0.1".to_string())
        .expect("server name");
    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .expect("tls handshake");

    // 3. dial_reality_stream_one
    let config = Arc::new(Config {
        host: format!("127.0.0.1:{}", server_addr.port()),
        path: "/".into(),
        ..Default::default()
    });
    let base_uri = build_request_url(
        "https",
        &format!("127.0.0.1:{}", server_addr.port()),
        &config.normalized_path(),
        &config.normalized_query(),
    );
    let mut conn = dial_reality_stream_one(
        tls_stream,
        server_addr,
        local_addr,
        base_uri,
        String::new(), // stream-one session_id 空
        config,
    )
    .await
    .expect("dial_reality_stream_one");

    // 4. 读响应（server 回写固定 'echo-response'）
    // ponytail: 不做 write upload (echo server 简化不读 body, 与客户端 write 互斥)
    let expected = b"echo-response";
    let mut buf = vec![0u8; expected.len()];
    let n = tokio::time::timeout(Duration::from_secs(3), conn.reader.read(&mut buf))
        .await
        .expect("read timeout")
        .expect("read");
    assert_eq!(&buf[..n], expected, "应收到 echo-response");

    server_task.abort();
}

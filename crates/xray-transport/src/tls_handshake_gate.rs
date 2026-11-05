//! eager TLS 握手的显式超时窗（bd xmv43）。
//!
//! Go `tls.Server(conn, config)` 返回**惰性** conn——握手发生在首次 Read/Write，
//! 受入站侧 `ReadHeaderTimeout` / Handshake policy deadline 约束（有界，生产日志
//! 可见「ws TLS accept timeout (4s)」这类显性超时）。Rust
//! `tokio_rustls::TlsAcceptor::accept` 是 **eager** 完整握手，且多数 transport
//! 未包 timeout——一个「连了不发 ClientHello」的半开连接可无限期占住一个任务
//! + fd（命中面清单见 bd xmv43 普查 E 组）。
//!
//! 本模块是共享修法件：[`accept_tls_with_timeout`] 在 eager accept 外套显式超时
//! 窗，超时即丢弃连接（future 链 drop → 底层 stream drop → fd/任务释放），返回
//! 单连接级 [`io::ErrorKind::TimedOut`]。各 transport 的接线（对齐 Go
//! ReadHeaderTimeout 口径）由各 transport crate 完成。

use std::{io, time::Duration};

use tokio::io::{AsyncRead, AsyncWrite};

/// 服务端 TLS 握手窗缺省值。
///
/// 口径对齐 Go 入站 `ReadHeaderTimeout`（生产 ws/httpupgrade 既有 4s 显性超时
/// 同款）：真实客户端的 ClientHello 与 SYN 同批到达（CDN/argo 在自己边缘完成
/// TCP 后立即回源转发首包），4s 足够覆盖慢链路；半开连接（连了不发）在窗尾被清。
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);

/// eager TLS accept + 显式超时窗（bd xmv43）。
///
/// - 窗内完成握手 → 正常返回 [`tokio_rustls::server::TlsStream`]；
/// - 超时 → 返回 `io::ErrorKind::TimedOut`，底层 stream 随 future drop 释放 （半开连接不再残留任务
///   + fd）。
///
/// # Errors
/// 握手失败（协议错误/对端断开）或超时时返回 `io::Error`。
pub async fn accept_tls_with_timeout<T>(
    acceptor: &tokio_rustls::TlsAcceptor,
    stream: T,
    within: Duration,
) -> io::Result<tokio_rustls::server::TlsStream<T>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::time::timeout(within, acceptor.accept(stream)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "TLS handshake timeout (peer connected but never completed the handshake)",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        sync::Arc,
        time::{Duration, Instant},
    };

    use rustls::{
        DigitallySignedStruct, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        crypto::ring::default_provider,
        pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// rcgen 自签（SAN 127.0.0.1）——与 splithttp/grpc 测试同款惯例。
    fn self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let params =
            rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("rcgen params");
        let key_pair = rcgen::KeyPair::generate().expect("rcgen keypair");
        let cert = params.self_signed(&key_pair).expect("rcgen self_signed");
        (
            CertificateDer::from(cert.der().to_vec()),
            PrivateKeyDer::Pkcs8(key_pair.serialize_der().into()),
        )
    }

    fn ensure_crypto_provider() {
        let _ = default_provider().install_default();
    }

    fn server_config(
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    ) -> Arc<rustls::ServerConfig> {
        Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .expect("server config"),
        )
    }

    /// 测试专用客户端 verifier：接受一切（被测面是超时窗，不是验链）。
    #[derive(Debug)]
    struct AcceptAll;

    impl ServerCertVerifier for AcceptAll {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            // 测试证书/签发覆盖面足够（rcgen 默认 ECDSA P-256）。
            vec![
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
            ]
        }
    }

    fn client_connector() -> tokio_rustls::TlsConnector {
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAll))
            .with_no_client_auth();
        tokio_rustls::TlsConnector::from(Arc::new(config))
    }

    /// 半开连接（连上不发 ClientHello）在窗内被清：返回 TimedOut，总耗时 ≈ 窗。
    /// 无修复形态 = 无界等待（5s 上界断言红）。
    #[tokio::test]
    async fn silent_connection_times_out_within_window() {
        ensure_crypto_provider();
        let (cert, key) = self_signed();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config(cert, key));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // 半开：连上后不发任何字节且保持打开（forget = 不发 FIN——EOF 会立即
        // 解除读阻塞，测不出「无界等头」）。
        let silent = tokio::net::TcpStream::connect(addr).await.unwrap();
        std::mem::forget(silent);

        let (stream, _) = listener.accept().await.unwrap();
        let started = Instant::now();
        let err = accept_tls_with_timeout(&acceptor, stream, Duration::from_millis(300))
            .await
            .expect_err("半开连接必须超时");
        let elapsed = started.elapsed();

        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(elapsed >= Duration::from_millis(250), "窗未生效: {elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "握手无界: {elapsed:?}");
    }

    /// 半个 ClientHello（0wvne 生产实锤形态：串行 accept 下半个 ClientHello 挂死
    /// 5 小时）：首字节到达后拖住 → 窗尾被清。
    #[tokio::test]
    async fn slow_partial_client_hello_times_out() {
        ensure_crypto_provider();
        let (cert, key) = self_signed();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config(cert, key));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        // 只发 1 字节（合法 TLS record 的 content type），其余永不发。
        client.write_all(&[0x16]).await.unwrap();
        std::mem::forget(client);

        let started = Instant::now();
        let err = accept_tls_with_timeout(&acceptor, stream, Duration::from_millis(400))
            .await
            .expect_err("半个 ClientHello 必须超时");
        let elapsed = started.elapsed();

        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(elapsed >= Duration::from_millis(350), "窗未生效: {elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "握手无界: {elapsed:?}");
    }

    /// 正常握手不受窗影响：窗内完成 + 握手后的流双向可用（fd 未被误杀）。
    #[tokio::test]
    async fn normal_handshake_completes_and_stream_is_usable() {
        ensure_crypto_provider();
        let (cert, key) = self_signed();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config(cert.clone(), key));
        let connector = client_connector();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client_task = tokio::spawn(async move {
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let server_name = ServerName::try_from("127.0.0.1".to_string()).unwrap();
            let mut tls = connector.connect(server_name, tcp).await.expect("client handshake");
            tls.write_all(b"ping").await.unwrap();
            tls.flush().await.unwrap();
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.unwrap();
            buf
        });

        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = accept_tls_with_timeout(&acceptor, stream, Duration::from_secs(5))
            .await
            .expect("正常握手必须成功");
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        tls.write_all(b"pong").await.unwrap();
        tls.flush().await.unwrap();

        assert_eq!(client_task.await.unwrap(), *b"pong");
    }
}

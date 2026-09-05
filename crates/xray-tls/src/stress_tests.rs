//! 跨缓冲窗口 bulk stress（v50 TLS 包装层丢唤醒排查复现床）。
//!
//! 真实 TLS 握手（rustls 双端 / btls 指纹客户端 ↔ rustls 服务端）套在
//! `tokio::io::duplex(64KB)` 有限窗口上，跑 512KB 全双工 bulk：每端一个
//! 写任务 + 一个读任务并发（真实 copy 拓扑），join! 齐驱。
//!
//! 若 TLS 包装层或内层库存在"部分写后返回裸 Pending"同族缺陷（v50 在
//! CommonConn/VisionConn 修掉的模式），跨窗口背压下 waker 丢失即挂死——
//! timeout 兜底防止挂死整个测试套件。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_rustls::rustls::{ClientConfig, ServerConfig};
use xray_transport::connection::Connection;

use crate::fingerprint::Fingerprint;

/// `tokio::io::DuplexStream` 的 `Connection` 适配（no-op 地址/穿透）。
struct TestConn<S>(S);

impl<S> Connection for TestConn<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
}

impl<S> AsyncRead for TestConn<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for TestConn<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// 自签证书 (cert_der, key_der)，SAN=localhost。
fn self_signed_der() -> (Vec<u8>, Vec<u8>) {
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert.der().to_vec(), key.serialize_der())
}

fn rustls_server_config(cert_der: &[u8], key_der: &[u8]) -> ServerConfig {
    let key = rustls_pki_types::PrivateKeyDer::try_from(key_der.to_vec()).unwrap();
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls_pki_types::CertificateDer::from(cert_der.to_vec())],
            key,
        )
        .unwrap()
}

/// 64KB 窗口 duplex 上的 512KB 全双工 bulk：写/读 × 两端 4 任务并发，
/// 任何一层丢 waker 都会卡在背压里直到 timeout。
///
/// 4 个任务通过借用共享 halves（非 move）：先完成的分支不提前 drop
/// BiLock 半边——否则对端整体 drop 会让仍在收尾的读任务撞上 EOF
/// （duplex 半端 drop = 对端 read Ok(0)），那是测试构造 bug 而非被测
/// 链路缺陷。
async fn run_duplex_bulk<A, B>(a: A, b: B, payload: &[u8])
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    let (mut a_r, mut a_w) = tokio::io::split(a);
    let (mut b_r, mut b_w) = tokio::io::split(b);

    tokio::time::timeout(TIMEOUT, async {
        let rx_a = {
            let payload = payload.to_vec();
            async move {
                let mut got = vec![0u8; payload.len()];
                a_r.read_exact(&mut got).await.unwrap();
                assert_eq!(got, payload, "A 方向 512KB 完整性");
            }
        };
        let rx_b = {
            let payload = payload.to_vec();
            async move {
                let mut got = vec![0u8; payload.len()];
                b_r.read_exact(&mut got).await.unwrap();
                assert_eq!(got, payload, "B 方向 512KB 完整性");
            }
        };
        tokio::join!(
            async { a_w.write_all(payload).await.unwrap(); },
            rx_a,
            async { b_w.write_all(payload).await.unwrap(); },
            rx_b,
        );
    })
    .await
    .expect("duplex TLS 512KB bulk stress 超时：TLS 链路丢唤醒挂死");
}

/// rustls 双端全链（Conn/ServerConn 包装 + tokio-rustls Stream poll_write）。
#[tokio::test]
async fn duplex_rustls_512k_bulk_stress() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let (cert_der, key_der) = self_signed_der();
    let sc = rustls_server_config(&cert_der, &key_der);
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(cert_der))
        .unwrap();
    let cc = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let (a, b) = tokio::io::duplex(64 * 1024);
    let (sa, sb) = tokio::join!(
        crate::utls::server(TestConn(a), Arc::new(sc)),
        crate::utls::client(TestConn(b), "localhost", Arc::new(cc)),
    );
    let payload: Vec<u8> = (0u8..=255).cycle().take(512 * 1024).collect();
    run_duplex_bulk(sa.unwrap(), sb.unwrap(), &payload).await;
}

/// btls 指纹客户端 ↔ rustls 服务端全链（BtlsConn + tokio-btls SslStream）。
#[tokio::test]
async fn duplex_btls_512k_bulk_stress() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let (cert_der, key_der) = self_signed_der();
    let sc = rustls_server_config(&cert_der, &key_der);

    let (a, b) = tokio::io::duplex(64 * 1024);
    let (sa, sb) = tokio::join!(
        crate::utls::server(TestConn(a), Arc::new(sc)),
        crate::btls_client::BtlsConn::connect(
            TestConn(b),
            "localhost",
            Fingerprint::HelloChrome133,
            None,
        ),
    );
    let payload: Vec<u8> = (0u8..=255).cycle().take(512 * 1024).collect();
    run_duplex_bulk(sa.unwrap(), sb.unwrap(), &payload).await;
}

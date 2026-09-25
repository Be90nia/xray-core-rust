//! btls（BoringSSL）服务端 acceptor 原语（bd tce2）。
//!
//! REALITY 服务端 btls 握手路径的 TLS 层：构建 server `SslContext`
//! （TLS_method + 证书/私钥 DER），并在流上完成 BoringSSL 服务端握手
//! （`SSL_set_accept_state` + tokio 异步 `accept`）。
//!
//! REALITY 语义（ClientHello 预读判定 / dest fallback / probe 喂值）在
//! `xray-reality::server`——本模块只做 TLS 层，与
//! [`crate::btls_client::BtlsConn`] 的 BIO/tokio 集成方式一致
//! （`tokio_btls::SslStream` 已实现 AsyncRead/AsyncWrite）。
//!
//! iOS 门控：btls-sys 在 aarch64-apple-ios 走预生成 bindings（bd mygg
//! 教训，Mobile Gates d0348c0）；server 路径整体 opt-in + cfg 门控双保险，
//! iOS 下零功能损失（默认 acceptor 仍为 rustls）。

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use foreign_types::{ForeignType as _, ForeignTypeRef as _};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_btls::SslStream as TokioSslStream;

/// btls 服务端流：握手完成后的 TLS 连接（`tokio_btls::SslStream` 的
/// `Pin<Box<..>>` newtype，集成方式与 [`crate::btls_client::BtlsConn`] 一致）。
///
/// `ssl()` 访问器供后握手记录发送
/// （[`crate::btls_reality::send_post_handshake_record`]）取 SSL 句柄。
pub struct BtlsServerStream<S> {
    stream: Pin<Box<TokioSslStream<S>>>,
}

impl<S> BtlsServerStream<S> {
    /// 当前连接的 `SslRef`（握手后调用；SSL 级 FFI 消费等用）。
    #[must_use]
    pub fn ssl(&self) -> &btls::ssl::SslRef {
        self.stream.ssl()
    }

    /// 当前连接的 SSL 裸指针（SSL 级 FFI 原语消费，如 mirror seal；
    /// 生命周期同 `self`）。
    #[must_use]
    pub fn ssl_ptr(&self) -> *mut btls_sys::SSL {
        self.stream.ssl().as_ptr()
    }
}

impl<S: Unpin> BtlsServerStream<S> {
    /// 底层流的可变引用（**绕过 TLS 记录层直写 wire 字节**，bd z32z）。
    ///
    /// REALITY mirror 发送专用：`SSL_seal_raw_tls13_record` 产出的裸 wire
    /// 记录由此通道写出（Go `hs.c.write` 镜像）。除该场景外禁用——
    /// 直写未加密字节会破坏 SSL 会话（btls `get_mut` 警告语义）。
    pub fn get_mut(&mut self) -> &mut S {
        self.stream.get_mut()
    }
}

impl<S: AsyncRead + AsyncWrite> AsyncRead for BtlsServerStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.stream.as_mut().poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite> AsyncWrite for BtlsServerStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.stream.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream.as_mut().poll_shutdown(cx)
    }
}

/// 规范化 rcgen/ring 产出的 Ed25519 PKCS#8（带公钥 attribute 的 v2 变体，
/// 83B）为 BoringSSL d2i 接受的标准 PrivateKeyInfo（46B）。
///
/// ring 的 Ed25519 PKCS#8 序列化把公钥编码进 attributes 区——rustls-pki-types
/// 容忍该变体（rustls 路径能吃），而 BoringSSL 的 d2i_AutoPrivateKey /
/// d2i_PKCS8_PRIV_KEY_INFO 直接拒绝（DECODE_ERROR）。btls 服务端证书加载
/// 必须重写。提取规则：RFC 8410 Ed25519 PrivateKeyInfo 的 privateKey 字段
/// 恒为 `04 22 04 20 || 32B seed`，模式唯一；非 Ed25519 / 非变体输入原样返回。
fn normalize_ed25519_pkcs8(key_der: &[u8]) -> Vec<u8> {
    const SEED_MARKER: [u8; 4] = [0x04, 0x22, 0x04, 0x20];
    if let Some(pos) = key_der.windows(4).position(|w| w == SEED_MARKER) {
        let seed_start = pos + SEED_MARKER.len();
        if let Some(seed) = key_der.get(seed_start..seed_start + 32) {
            let mut out = Vec::with_capacity(48);
            // 标准 46B PrivateKeyInfo：30 2e { version 0, id-Ed25519, OCTET STRING(34){ seed } }
            out.extend_from_slice(&[
                0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
                0x04, 0x20,
            ]);
            out.extend_from_slice(seed);
            return out;
        }
    }
    key_der.to_vec()
}

/// 构建 server `SslContext`：`TLS_method` + 证书/私钥（DER）加载。
///
/// 证书来自 REALITY 现有证书机制（`generate_reality_ed25519_cert` 产出的
/// cert_der / PKCS#8 key_der），语义对应 rustls 路径的 `build_server_config`。
///
/// # Errors
/// - X509 / PKCS#8 解析失败或证书-私钥不匹配 → Err（含 BoringSSL 错误描述）
pub fn build_server_ssl_context(
    cert_der: &[u8],
    key_der: &[u8],
) -> Result<btls::ssl::SslContext, String> {
    use btls::ssl::{SslContextBuilder, SslMethod};
    let cert =
        btls::x509::X509::from_der(cert_der).map_err(|e| format!("btls server: cert der: {e}"))?;
    let key = btls::pkey::PKey::private_key_from_der(&normalize_ed25519_pkcs8(key_der))
        .map_err(|e| format!("btls server: private key der: {e}"))?;
    let mut builder = SslContextBuilder::new(SslMethod::tls())
        .map_err(|e| format!("btls server: ssl ctx: {e}"))?;
    builder.set_certificate(&cert).map_err(|e| format!("btls server: set cert: {e}"))?;
    builder.set_private_key(&key).map_err(|e| format!("btls server: set key: {e}"))?;
    builder.check_private_key().map_err(|e| format!("btls server: cert/key mismatch: {e}"))?;
    Ok(builder.build())
}

/// 在流上完成 btls 服务端握手。
///
/// 对应客户端路径 [`crate::btls_client::BtlsConn::connect`] 的服务端镜像：
/// `Ssl::new` → `SSL_set_accept_state` → `tokio_btls::SslStream::accept`
/// （非阻塞轮询由 tokio-btls 的 WouldBlock→Pending 桥接完成）。
/// 调用方负责把已预读的 ClientHello record 重新注入流头（如
/// `xray_reality::server::PrefixedReader`），BoringSSL 才能读到完整握手。
///
/// # Errors
/// - 握手失败（alert/WANT 协议错误/IO 错误）→ io::Error
pub async fn accept<S>(
    stream: S,
    cert_der: &[u8],
    key_der: &[u8],
) -> io::Result<BtlsServerStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ctx = build_server_ssl_context(cert_der, key_der).map_err(io::Error::other)?;
    let ssl = btls::ssl::Ssl::new(&ctx).map_err(|e| io::Error::other(e.to_string()))?;
    // SAFETY: ssl 为刚构造的合法 SSL；SSL_set_accept_state 仅把连接标记为
    // 服务端角色（btls 只在同步 SslStreamBuilder 上暴露此步，tokio 路径需
    // 在握手前直接设置）。
    unsafe { btls_sys::SSL_set_accept_state(ssl.as_ptr()) };
    let tls_stream =
        TokioSslStream::new(ssl, stream).map_err(|e| io::Error::other(e.to_string()))?;
    let mut pinned = Box::pin(tls_stream);
    pinned
        .as_mut()
        .accept()
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string()))?;
    Ok(BtlsServerStream { stream: pinned })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// btls server ↔ btls client loopback：真实握手 + 双向数据 roundtrip。
    ///
    /// 客户端走 [`crate::btls_client`] 同款 Chrome 指纹构建路径
    /// （connector → configure → into_ssl → tokio accept 镜像 connect），
    /// btls 连接器默认 VERIFY_NONE（回接验证与本次测试无关），自签证书直接握手。
    #[tokio::test]
    async fn btls_server_client_roundtrip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let server = tokio::spawn(async move {
            let mut tls = accept(server_io, &cert_der, &key_der).await?;
            let mut buf = [0u8; 16];
            let n = tls.read(&mut buf).await?;
            tls.write_all(&buf[..n]).await?;
            tls.flush().await?;
            Ok::<_, io::Error>(())
        });

        // 客户端：Chrome 指纹连接器（与 BtlsConn::connect 同款构建）。
        let fp = crate::fingerprint::Fingerprint::Chrome;
        let fp_config = crate::btls_client::connector_for_fingerprint(&fp)
            .expect("chrome fingerprint supported")
            .expect("chrome connector builds");
        let cfg = fp_config.connector.configure().unwrap();
        let mut ssl = cfg.into_ssl("localhost").unwrap();
        ssl.set_verify(btls::ssl::SslVerifyMode::NONE);
        let tls_stream = TokioSslStream::new(ssl, client_io).unwrap();
        let mut client = Box::pin(tls_stream);
        client.as_mut().connect().await.expect("client handshake");

        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        server.await.unwrap().unwrap();
    }
}

//! btls REALITY 客户端编排（aai）。
//!
//! 把 btls 指纹伪装握手（[`crate::btls_client`]）与 REALITY 协议注入
//! （session_id AEAD 加密 + 证书 HMAC 验证）组合起来：
//!
//! - **指纹层**：BoringSSL 原生浏览器 ClientHello（Chrome/Firefox/Safari/...，
//!   cipher 顺序/扩展/GREASE 均由 BoringSSL 生成，DPI 无法区分）。
//! - **REALITY 层**：在 ClientHello record 写出前（BIO 拦截）回调钩子改写
//!   session_id 字段（32 字节等长替换，不改 record 长度）；握手完成后回调
//!   证书验证（对应 Go `reality.UClient` 的 `hello.SessionId` 注入 +
//!   `VerifyPeerCertificate`）。
//!
//! 对应 Go 语义（`transport/internet/reality/reality.go:133-177`）：
//! `tls.GetFingerprint` → `utls.UClient`（浏览器指纹握手）→ `BuildHandshakeState`
//! 后覆写 `hello.SessionId`（auth_key = ECDH(key share priv, server pub)，
//! AES-256-GCM Seal）→ `HandshakeContext`。
//!
//! 密码学算法（ECDH/HKDF/AES-GCM/HMAC）在 `xray-reality::crypto` 实现，
//! 通过 [`RealityHooks`] 注入；本模块只负责时序编排与 SSL 材料导出
//! （[`x25519_key_share_private`]，BoringSSL patch `SSL_get_x25519_key_share_private`）。

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use btls::ssl::SslRef;
use foreign_types::ForeignTypeRef;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_btls::SslStream as TokioSslStream;
use xray_transport::connection::Connection;

use crate::btls_client::{connector_for_fingerprint, BtlsConn};
use crate::fingerprint::Fingerprint;

/// REALITY 客户端钩子：btls 握手的关键时点回调。
///
/// 由 `xray-reality` 实现（协议算法在那边）；本 crate 只编排时序。
pub trait RealityHooks: Send + Sync {
    /// ClientHello record 写出前调用（`record` 可原地改写，须保持长度不变）。
    ///
    /// `record` 是本次 BIO 写出的完整字节（TLS record 对齐，可能含多条
    /// record 连写，如 ClientHello + CCS）；实现自行解析定位 ClientHello 的
    /// session_id 字段。HRR 后的第二个 ClientHello 也会经过此回调。
    ///
    /// 可用 [`x25519_key_share_private`] 从 `ssl` 导出 X25519 key share
    /// 私钥派生 auth_key。
    fn rewrite_client_hello(&self, ssl: &SslRef, record: &mut [u8]) -> io::Result<()>;

    /// TLS 握手完成后、连接返回前调用（证书验证）。
    /// 验证失败返回 Err → 握手断连（对应 Go `uConn.Verified == false` 路径：
    /// "received real certificate (potential MITM or redirection)"）。
    fn verify_handshake(&self, ssl: &SslRef) -> io::Result<()>;
}

/// 导出当前 SSL 的 X25519 key share 私钥（32 字节 raw）。
///
/// 须在 ClientHello 构建后（即 [`RealityHooks::rewrite_client_hello`] 回调内）
/// 调用；无 X25519 key share 时返回 None（如指纹只发 PQ 组）。
///
/// 对应 Go `uConn.HandshakeState.State13.KeyShareKeys.Ecdhe` 的私钥访问。
#[must_use]
pub fn x25519_key_share_private(ssl: &SslRef) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    // SAFETY: ssl 指针来自存活的 SslRef；out 是 32 字节缓冲，符合 C 签名。
    let ok = unsafe { btls_sys::SSL_get_x25519_key_share_private(ssl.as_ptr(), out.as_mut_ptr()) };
    if ok == 1 { Some(out) } else { None }
}

/// 拦截流：ClientHello record 写出前回调 [`RealityHooks::rewrite_client_hello`]。
///
/// 包装底层流塞进 `SslStream` 的 BIO 侧：BoringSSL 握手写 ClientHello 时，
/// 数据经过本流的 `poll_write`，改写后再落底层流。
pub struct HelloRewriteStream<S> {
    inner: S,
    hooks: Option<Arc<dyn RealityHooks>>,
    /// SSL 裸指针：仅用于在回调内构造 `&SslRef` 导出 key share 私钥。
    ///
    /// SAFETY: 指针指向的 SSL 由外层 `SslStream` 拥有；回调只发生在握手
    /// （`SslStream::connect`）期间，此时 SslStream 存活，指针有效。
    /// `None`（测试用）跳过钩子直接透传。
    ssl_ptr: Option<*mut btls_sys::SSL>,
}

// SAFETY: ssl_ptr 仅在 poll_write（握手窗口）解引用，SslStream 存活期间
// SSL 不跨线程释放；hooks 为 Arc<dyn RealityHooks>（Send+Sync）。
unsafe impl<S: Send> Send for HelloRewriteStream<S> {}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for HelloRewriteStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for HelloRewriteStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // 每次写都回调（首个 ClientHello + HRR 后的第二个都覆盖）；
        // 非握手数据（CCS record、应用数据）由 hooks 内部自行跳过。
        if let (Some(hooks), Some(ssl_ptr)) = (&self.hooks, self.ssl_ptr) {
            // SAFETY: 见结构体文档——握手窗口内 SslStream 持有该 SSL。
            let ssl = unsafe { SslRef::from_ptr(ssl_ptr) };
            // SAFETY: BIO write buffer 在 poll_write 期间归 BIO 层所有且可写；
            // hooks 的契约是等长原地替换（见 trait 文档）。经 as_ptr 取裸指针
            // 构造可变切片，避免 &T→&mut T 引用转换 UB。
            let record = unsafe {
                std::slice::from_raw_parts_mut(buf.as_ptr().cast_mut(), buf.len())
            };
            if let Err(e) = hooks.rewrite_client_hello(ssl, record) {
                return Poll::Ready(Err(e));
            }
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// SAFETY: 同 Send——ssl_ptr 仅在握手窗口解引用，无并发访问路径。
unsafe impl<S: Send> Sync for HelloRewriteStream<S> {}
/// `poll_write` 的 buf 是 `&[u8]` 而钩子签名要 `&mut [u8]`：record 改写是
/// 等长原地替换，改的就是即将写出的缓冲本身。BoringSSL 经 BIO 写出的数据
/// 缓冲在 poll_write 返回前归 BIO 层所有，等长改写安全。
///
/// （内联于 `poll_write`，无独立函数。）

impl<S: Connection + Unpin> Connection for HelloRewriteStream<S> {
    fn remote_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        self.inner.remote_addr()
    }
    fn local_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        self.inner.local_addr()
    }
}

/// 创建 REALITY 客户端 btls 连接（浏览器指纹握手 + REALITY 注入 + 证书验证）。
///
/// 对应 Go `reality.UClient`：指纹握手走 [`BtlsConn::connect`] 同款路径
/// （connector/key shares/ALPS），叠加 [`RealityHooks`] 的两处回调。
///
/// # Errors
/// - 指纹不被 btls 支持（`InvalidInput`）——调用方可 fallback rustls
/// - 握手 IO / hooks 验证失败
pub async fn connect_reality<S>(
    stream: S,
    server_name: &str,
    fingerprint: Fingerprint,
    hooks: Arc<dyn RealityHooks>,
) -> io::Result<BtlsConn<HelloRewriteStream<S>>>
where
    S: Connection + Unpin,
{
    let fp_config = connector_for_fingerprint(&fingerprint)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "fingerprint not supported by btls")
        })?
        .map_err(|e| io::Error::other(e.to_string()))?;

    let mut cfg = fp_config.connector.configure().map_err(|e| io::Error::other(e.to_string()))?;
    cfg.set_verify_hostname(false);

    let mut ssl = cfg.into_ssl(server_name).map_err(|e| io::Error::other(e.to_string()))?;

    // per-connection 指纹参数（与 BtlsConn::connect 一致）
    ssl.set_client_key_shares(fp_config.key_shares)
        .map_err(|e| io::Error::other(e.to_string()))?;
    if !fp_config.alps.is_empty() {
        ssl.add_application_settings(fp_config.alps)
            .map_err(|e| io::Error::other(e.to_string()))?;
    }

    // REALITY 拦截：记录 ssl 裸指针（SslStream 拥有 SSL，握手窗口内有效）；
    // hooks 克隆一份留在本函数做握手后验证。
    let ssl_ptr: *mut btls_sys::SSL = ssl.as_ptr();
    let rewrite_stream = HelloRewriteStream {
        inner: stream,
        hooks: Some(Arc::clone(&hooks)),
        ssl_ptr: Some(ssl_ptr),
    };

    let tls_stream = TokioSslStream::new(ssl, rewrite_stream)
        .map_err(|e| io::Error::other(e.to_string()))?;

    let mut pinned = Box::pin(tls_stream);
    pinned.as_mut().connect().await
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string()))?;

    // REALITY 证书验证（HMAC-SHA512；失败 = 真证书/MITM → 断连）
    hooks.verify_handshake(pinned.ssl())?;

    Ok(BtlsConn::from_parts(pinned, fingerprint, server_name))
}

/// 证书 DER 编码（`i2d_X509`）。REALITY 证书验证（HMAC 尾 64 字节）用。
pub fn x509_to_der(cert: &btls::x509::X509) -> Option<Vec<u8>> {
    use foreign_types::ForeignTypeRef;
    unsafe {
        let mut p: *mut u8 = std::ptr::null_mut();
        let len = btls_sys::i2d_X509(cert.as_ptr(), &mut p);
        if len <= 0 || p.is_null() {
            return None;
        }
        let der = std::slice::from_raw_parts(p, len as usize).to_vec();
        btls_sys::OPENSSL_free(p.cast());
        Some(der)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 拦截流透传语义：无 hooks（None）时字节原样透传。
    #[tokio::test]
    async fn hello_rewrite_stream_passthrough_without_hooks() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client, mut server) = tokio::io::duplex(1024);
        let mut rw = HelloRewriteStream { inner: client, hooks: None, ssl_ptr: None };
        rw.write_all(&[5, 1, 2, 3]).await.unwrap();
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [5, 1, 2, 3]);
    }

    /// 有 hooks 时回调可等长改写（标志翻转），长度不变、后续透传。
    #[tokio::test]
    async fn hello_rewrite_stream_rewrites_in_place() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        struct FlipHooks;
        impl RealityHooks for FlipHooks {
            fn rewrite_client_hello(&self, _ssl: &SslRef, record: &mut [u8]) -> io::Result<()> {
                for b in record.iter_mut() {
                    *b ^= 0xff;
                }
                Ok(())
            }
            fn verify_handshake(&self, _ssl: &SslRef) -> io::Result<()> {
                Ok(())
            }
        }

        let (client, mut server) = tokio::io::duplex(1024);
        let mut rw = HelloRewriteStream {
            inner: client,
            hooks: Some(Arc::new(FlipHooks)),
            ssl_ptr: None, // hooks 不解引用 ssl → null 安全
        };
        rw.write_all(&[0x00, 0x0f, 0xf0]).await.unwrap();
        let mut buf = [0u8; 3];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [0xff, 0xf0, 0x0f]);
    }
}

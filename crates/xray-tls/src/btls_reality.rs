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
/// BoringSSL patch 缺失函数 stub（bindings.rs 没生成）。
///
/// btls-sys 0.5.6 的 bindings.rs bindgen 没暴露 REALITY 协议所需的两个
/// BoringSSL patch 函数,这里手动声明 extern "C",让 xray-reality 编译通过。
/// 调用时通过 BoringSSL 已编译好的 ssl.lib/crypto.lib 链接,符号真实存在。
unsafe extern "C" {
    fn SSL_get_x25519_key_share_private(ssl: *mut btls_sys::SSL, out: *mut u8) -> i32;
    fn SSL_set_reality_rewrite_cb(
        cb: Option<unsafe extern "C" fn(ssl: *mut btls_sys::SSL, msg: *mut u8, msg_len: usize) -> i32>,
    );
}

use std::collections::HashMap;
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
/// REALITY 回调用的 SSL 裸指针（避免下游 crate 直接依赖 btls-sys）。
pub type RealitySslPtr = *mut btls_sys::SSL;

pub trait RealityHooks: Send + Sync {
    /// ClientHello record 写出前调用（`record` 可原地改写，须保持长度不变）。
    ///
    /// `record` 是本次 BIO 写出的完整字节（TLS record 对齐，可能含多条
    /// record 连写，如 ClientHello + CCS）；实现自行解析定位 ClientHello 的
    /// session_id 字段。HRR 后的第二个 ClientHello 也会经过此回调。
    /// 私钥派生 auth_key。
    fn rewrite_client_hello(&self, ssl: &SslRef, record: &mut [u8]) -> io::Result<()>;

    /// ponytail (REALITY): transcript 一致的 ClientHello 注入。
    /// 由 BoringSSL `ssl_add_message_cbb` 在消息序列化后、计入 transcript 前
    /// 调用（SSL_set_reality_rewrite_cb 全局回调）。`msg` = 完整 handshake
    /// message（type(1)+len(3)+body，无 record 头）。BIO 层改写会让 transcript
    /// 与线上 bytes 不一致 → 握手密钥全部错乱（BAD_DECRYPT），必须在此改写。
    fn rewrite_client_hello_msg(
        &self,
        ssl_ptr: RealitySslPtr,
        msg: &mut [u8],
    ) -> io::Result<()> {
        Err(io::Error::other(
            "REALITY: rewrite_client_hello_msg not implemented",
        ))
    }

    /// 握手完成后回调：证书 HMAC 验证（对应 Go `UConn.VerifyPeerCertificate`）。
    /// 实现里持有 auth_key/pub_key,失败 = 真证书/被转发 → 断连。
    /// 默认实现返回 Ok(由调用方决定是否严格要求)。
    fn verify_handshake(&self, _ssl: &SslRef) -> io::Result<()> {
        Ok(())
    }

}

/// 导出当前 SSL 的 X25519 key share 私钥（32 字节 raw，裸指针版）。
///
/// transcript 回调窗口内使用；无 X25519 key share 时返回 None。
#[must_use]
pub fn x25519_key_share_private_raw(ssl: *mut btls_sys::SSL) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    // SAFETY: ssl 指针在握手窗口内由 TokioSslStream 持有；out 是 32 字节缓冲。
    let ok = unsafe { SSL_get_x25519_key_share_private(ssl, out.as_mut_ptr()) };
    if ok == 1 { Some(out) } else { None }
}

/// per-SSL REALITY hooks 注册表（transcript 回调按 ssl 裸指针查找）。
static REALITY_HOOKS: parking_lot::Mutex<Option<HashMap<usize, Arc<dyn RealityHooks>>>> =
    parking_lot::Mutex::new(None);
static TRAMPOLINE_INSTALLED: std::sync::Once = std::sync::Once::new();

extern "C" fn reality_rewrite_trampoline(
    ssl: *mut btls_sys::SSL,
    msg: *mut u8,
    msg_len: usize,
) -> i32 {
    let hooks = REALITY_HOOKS
        .lock()
        .as_ref()
        .and_then(|m| m.get(&(ssl as usize)).cloned());
    let Some(hooks) = hooks else { return 1 };
    // SAFETY: msg/len 由 BoringSSL 在 ssl_add_message_cbb 内提供，握手窗口内有效。
    let buf = unsafe { std::slice::from_raw_parts_mut(msg, msg_len) };
    match hooks.rewrite_client_hello_msg(ssl, buf) {
        Ok(()) => 1,
        Err(_e) => 0,
    }
}


/// 注册 per-SSL hooks 并安装全局 trampoline（幂等）。
pub fn register_reality_hooks(ssl_key: usize, hooks: Arc<dyn RealityHooks>) {
    TRAMPOLINE_INSTALLED.call_once(|| unsafe {
        SSL_set_reality_rewrite_cb(Some(reality_rewrite_trampoline));
    });
    REALITY_HOOKS
        .lock()
        .get_or_insert_with(HashMap::new)
        .insert(ssl_key, hooks);
}

/// 注销 per-SSL hooks（握手结束/失败后调用）。
pub fn unregister_reality_hooks(ssl_key: usize) {
    if let Some(m) = REALITY_HOOKS.lock().as_mut() {
        m.remove(&ssl_key);
    }
}

/// 导出当前 SSL 的 X25519 key share 私钥（32 字节 raw；`&SslRef` 版，BIO 路径用）。
#[must_use]
pub fn x25519_key_share_private(ssl: &SslRef) -> Option<[u8; 32]> {
    x25519_key_share_private_raw(ssl.as_ptr())
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

impl<S: Connection + Unpin> Connection for HelloRewriteStream<S> {
    fn remote_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        self.inner.remote_addr()
    }
    fn local_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        self.inner.local_addr()
    }
}

/// 创建 REALITY 客户端 btls 连接（浏览器指纹握手 + REALITY transcript 注入 + 证书验证）。
///
/// 对应 Go `reality.UClient`。session_id 注入由 BoringSSL 内部
/// `ssl_add_message_cbb` 回调（transcript 计入前）完成，保证 transcript 与
/// 线上 bytes 一致；握手完成后做证书 HMAC 验证。
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

    // REALITY transcript 注入：注册 per-SSL hooks，BoringSSL 在
    // ssl_add_message_cbb（transcript 计入前）回调改写 ClientHello。
    // BIO 层改写（HelloRewriteStream）已废弃 —— transcript 会与线上 bytes
    // 不一致导致握手密钥错乱（BAD_DECRYPT）。
    let ssl_key = ssl.as_ptr() as usize;
    register_reality_hooks(ssl_key, Arc::clone(&hooks));
    let rewrite_stream = HelloRewriteStream {
        inner: stream,
        hooks: None,
        ssl_ptr: None,
    };

    let tls_stream = TokioSslStream::new(ssl, rewrite_stream)
        .map_err(|e| io::Error::other(e.to_string()))?;

    let mut pinned = Box::pin(tls_stream);
    let connect_result = pinned.as_mut().connect().await;
    unregister_reality_hooks(ssl_key);
    if let Err(e) = connect_result {
        eprintln!("[REALITY dbg] SslStream::connect failed: {e:?}");
        return Err(io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string()));
    }

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

//! btls REALITY 客户端编排（aai）。
//!
//! 把 btls 指纹伪装握手（[`crate::btls_client`]）与 REALITY 协议注入
//! （session_id AEAD 加密 + 证书 HMAC 验证）组合起来：
//!
//! - **指纹层**：BoringSSL 原生浏览器 ClientHello（Chrome/Firefox/Safari/...， cipher
//!   顺序/扩展/GREASE 均由 BoringSSL 生成，DPI 无法区分）。
//! - **REALITY 层**：在 ClientHello 计入 transcript 前（BoringSSL `ssl_add_message_cbb` 回调）改写
//!   session_id 字段（32 字节等长替换）； 握手完成后回调证书验证（对应 Go `reality.UClient` 的
//!   `hello.SessionId` 注入 + `VerifyPeerCertificate`）。
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
        cb: Option<
            unsafe extern "C" fn(ssl: *mut btls_sys::SSL, msg: *mut u8, msg_len: usize) -> i32,
        >,
    );
    fn SSL_set_reality_server_hello_cb(
        cb: Option<
            unsafe extern "C" fn(ssl: *mut btls_sys::SSL, msg: *const u8, msg_len: usize) -> i32,
        >,
    );
}

use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use btls::ssl::SslRef;
use foreign_types::ForeignTypeRef;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_btls::SslStream as TokioSslStream;
use xray_transport::connection::Connection;

use crate::{
    btls_client::{BtlsConn, connector_for_fingerprint},
    fingerprint::Fingerprint,
};

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
    fn rewrite_client_hello_msg(&self, ssl_ptr: RealitySslPtr, msg: &mut [u8]) -> io::Result<()> {
        Err(io::Error::other("REALITY: rewrite_client_hello_msg not implemented"))
    }

    /// ServerHello 入站捕获：由 BoringSSL `ssl_reality_server_hello_maybe`
    /// 在 TLS 1.3 客户端 ServerHello 处理路径（key schedule / transcript 计入
    /// 前）调用（SSL_set_reality_server_hello_cb 全局回调，cm97）。`msg` =
    /// 完整 handshake message（type(1)+len(3)+body，无 record 头），对应 Go
    /// `HandshakeState.ServerHello.Raw`；HRR 走独立路径不会触发本回调。
    /// 默认忽略（非 PQC 客户端无需捕获）。
    fn on_server_hello(&self, _msg: &[u8]) -> io::Result<()> {
        Ok(())
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

/// bd mygg：REALITY 后握手记录模仿发送（`SSL_send_post_handshake_record`
/// 安全封装，BoringSSL patch 由 `tools/inject_btls_post_handshake.py` 注入）。
///
/// 在已完成握手的 SSL 连接上以**单条** TLS 1.3 application-data record
/// （type 23）发出 `payload`——wire 形态与 Go xtls/reality 服务端 dest 模仿
/// 发送一致（reality tls.go:414-424）。payload 超过单记录上限或握手未完成
/// 时返回 Err（原语侧拒发，不静默分片/延后）。
///
/// 消费时机（bd tce2 登记）：服务端 btls acceptor（`xray-reality::server::
/// server_tls_btls`）已落地，但 tokio BIO 桥接下裸调 SSL_write 会触发
/// tokio-btls `StreamWrapper.context==0` 断言（原语面向非 tokio BIO 宿主），
/// 故 tokio 路径以等价 poll 写路径发送（48B << max_send_fragment，单记录
/// 语义不变）；本原语保留给非 tokio BIO 场景（Go 兼容宿主/阻塞 fd）与
/// 客户端侧丢弃对齐。
///
/// iOS 门控：btls-sys 在 aarch64-apple-ios 走预生成 bindings（不含注入声明，
/// 见 Mobile Gates d0348c0 失败）；iOS 构建亦无注入源码树，原语不存在，
/// 门控零功能损失（当前无任何调用方）。
#[cfg(not(target_os = "ios"))]
pub fn send_post_handshake_record(
    ssl: *mut btls_sys::SSL,
    payload: &[u8],
) -> Result<(), &'static str> {
    if ssl.is_null() || payload.is_empty() {
        return Err("null ssl or empty payload");
    }
    // SAFETY: ssl 指针由调用方保证指向存活 SSL；payload 为调用方持有的只读缓冲。
    let ok =
        unsafe { btls_sys::SSL_send_post_handshake_record(ssl, payload.as_ptr(), payload.len()) };
    if ok == 1 {
        Ok(())
    } else {
        Err(
            "SSL_send_post_handshake_record rejected (handshake incomplete or payload exceeds single record)",
        )
    }
}

/// bd z32z：REALITY mirror 字节级等价原语（`SSL_seal_raw_tls13_record`
/// 安全封装，BoringSSL patch 由 `tools/inject_btls_post_handshake.py` 注入，
/// 与 [`send_post_handshake_record`] 同族）。
///
/// 以当前 write key 将 `inner`——**完整 AEAD 输入明文（含 inner content
/// type），不追加任何字节**——seal 为单条 TLS 1.3 type-23 记录，wire 字节
/// （5B 头 ‖ 密文 ‖ tag）写入 `out`，返回 wire 长度。AAD/nonce/写序号与
/// 标准写路径共享（`write_sequence` 成功即递增，NST 等握手后记录自然计入）。
/// 不触碰 BIO——发送由宿主把 `out` 直写底层流（Go `hs.c.write` 镜像，
/// `xray-reality::server` 消费）。
///
/// Go mirror 形态（tls.go:417-426）：`inner = [0x17] + (len-22) 个全零`，
/// 客户端 TLS1.3 剥尾语义解出 type=appData + 空载荷，被空记录重试路径吞掉。
///
/// iOS 门控同 [`send_post_handshake_record`]（预生成 bindings 无此符号）。
#[cfg(not(target_os = "ios"))]
pub fn seal_post_handshake_raw_record(
    ssl: *mut btls_sys::SSL,
    inner: &[u8],
    out: &mut [u8],
) -> Result<usize, &'static str> {
    if ssl.is_null() || inner.is_empty() {
        return Err("null ssl or empty inner plaintext");
    }
    if out.len() < inner.len() + 21 {
        // wire 上界 = 5B 头 + inner + 16B tag；不足即拒，FFI 侧 BUFFER_TOO_SMALL 同义。
        return Err("out buffer too small for a single TLS 1.3 record");
    }
    let mut out_len: usize = 0;
    // SAFETY: ssl 指针由调用方保证指向存活 SSL；inner/out 为调用方持有的合法缓冲。
    let ok = unsafe {
        btls_sys::SSL_seal_raw_tls13_record(
            ssl,
            inner.as_ptr(),
            inner.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
        )
    };
    if ok == 1 {
        Ok(out_len)
    } else {
        Err(
            "SSL_seal_raw_tls13_record rejected (handshake incomplete, non-TLS1.3, or length out of bound)",
        )
    }
}

/// per-SSL REALITY hooks 注册表（transcript 回调按 ssl 裸指针查找）。
///
/// 键 = SSL 裸指针地址。地址复用不串号由 [`RealityHooksGuard`] 保证：
/// 条目只被注册它的同一实例删除（`Arc::ptr_eq` compare-and-remove），
/// 且 `connect_reality` 全路径保证注销先于 SSL 释放（先注销后 free）。
static REALITY_HOOKS: parking_lot::Mutex<Option<HashMap<usize, Arc<dyn RealityHooks>>>> =
    parking_lot::Mutex::new(None);
static TRAMPOLINE_INSTALLED: std::sync::Once = std::sync::Once::new();
static SERVER_HELLO_TRAMPOLINE_INSTALLED: std::sync::Once = std::sync::Once::new();

extern "C" fn reality_rewrite_trampoline(
    ssl: *mut btls_sys::SSL,
    msg: *mut u8,
    msg_len: usize,
) -> i32 {
    let hooks = REALITY_HOOKS.lock().as_ref().and_then(|m| m.get(&(ssl as usize)).cloned());
    let Some(hooks) = hooks else { return 1 };
    // SAFETY: msg/len 由 BoringSSL 在 ssl_add_message_cbb 内提供，握手窗口内有效。
    let buf = unsafe { std::slice::from_raw_parts_mut(msg, msg_len) };
    match hooks.rewrite_client_hello_msg(ssl, buf) {
        Ok(()) => 1,
        Err(_e) => 0,
    }
}

extern "C" fn reality_server_hello_trampoline(
    ssl: *mut btls_sys::SSL,
    msg: *const u8,
    msg_len: usize,
) -> i32 {
    let hooks = REALITY_HOOKS.lock().as_ref().and_then(|m| m.get(&(ssl as usize)).cloned());
    let Some(hooks) = hooks else { return 1 };
    // SAFETY: msg/len 由 BoringSSL 在 ServerHello 处理路径内提供，握手窗口内
    // 有效；本回调只读（捕获不改写）。
    let buf = unsafe { std::slice::from_raw_parts(msg, msg_len) };
    match hooks.on_server_hello(buf) {
        Ok(()) => 1,
        Err(_e) => 0,
    }
}

/// 注册 per-SSL hooks 并安装全局 trampoline（幂等）。
pub fn register_reality_hooks(ssl_key: usize, hooks: Arc<dyn RealityHooks>) {
    TRAMPOLINE_INSTALLED.call_once(|| unsafe {
        SSL_set_reality_rewrite_cb(Some(reality_rewrite_trampoline));
    });
    SERVER_HELLO_TRAMPOLINE_INSTALLED.call_once(|| unsafe {
        SSL_set_reality_server_hello_cb(Some(reality_server_hello_trampoline));
    });
    REALITY_HOOKS.lock().get_or_insert_with(HashMap::new).insert(ssl_key, hooks);
}

/// 注销 per-SSL hooks（握手结束/失败后调用）。
pub fn unregister_reality_hooks(ssl_key: usize) {
    if let Some(m) = REALITY_HOOKS.lock().as_mut() {
        m.remove(&ssl_key);
    }
}

/// per-SSL hooks 的 RAII guard：构造即注册，drop 时 compare-and-remove。
///
/// 对应 Go 的函数作用域生命周期：`connect_reality` 中 new 失败、connect
/// 失败、verify 失败、成功返回每条路径都经过 guard drop，注册/注销必然
/// 对称；drop 仅当表中条目仍是自己注册的实例（[`Arc::ptr_eq`]）才删除，
/// SSL 释放后地址复用时旧 guard 不会误删新连接的条目。
struct RealityHooksGuard {
    ssl_key: usize,
    hooks: Arc<dyn RealityHooks>,
}

impl RealityHooksGuard {
    fn register(ssl_key: usize, hooks: &Arc<dyn RealityHooks>) -> Self {
        register_reality_hooks(ssl_key, Arc::clone(hooks));
        Self { ssl_key, hooks: Arc::clone(hooks) }
    }
}

impl Drop for RealityHooksGuard {
    fn drop(&mut self) {
        let mut table = REALITY_HOOKS.lock();
        if let Some(map) = table.as_mut() {
            if map.get(&self.ssl_key).is_some_and(|h| Arc::ptr_eq(h, &self.hooks)) {
                map.remove(&self.ssl_key);
            }
        }
    }
}
/// 导出当前 SSL 的 X25519 key share 私钥（32 字节 raw；`&SslRef` 版，BIO 路径用）。
#[must_use]
pub fn x25519_key_share_private(ssl: &SslRef) -> Option<[u8; 32]> {
    x25519_key_share_private_raw(ssl.as_ptr())
}

/// BIO 侧透传流：`SslStream` 的底层连接包装。
///
/// REALITY 的 ClientHello 改写已迁移至 `ssl_add_message_cbb` trampoline
/// （[`register_reality_hooks`]）——BIO 层改写会让 transcript 与线上 bytes
/// 不一致 → 握手密钥全部错乱（BAD_DECRYPT），本流只做透明转发。
pub struct HelloRewriteStream<S> {
    inner: S,
}

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
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: Connection + Unpin> Connection for HelloRewriteStream<S> {
    fn remote_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        self.inner.remote_addr()
    }

    fn local_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        self.inner.local_addr()
    }

    fn raw_tcp_clone(&self) -> Option<tokio::net::TcpStream> {
        // BIO 拦截层只在握手窗口起作用，连接建立后穿透内层克隆裸 TCP。
        self.inner.raw_tcp_clone()
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
    ssl.set_client_key_shares(fp_config.key_shares).map_err(|e| io::Error::other(e.to_string()))?;
    if !fp_config.alps.is_empty() {
        ssl.add_application_settings(fp_config.alps)
            .map_err(|e| io::Error::other(e.to_string()))?;
    }

    // REALITY transcript 注入：注册 per-SSL hooks，BoringSSL 在
    // ssl_add_message_cbb（transcript 计入前）回调改写 ClientHello。
    // BIO 层改写（HelloRewriteStream）已废弃 —— transcript 会与线上 bytes
    // 不一致导致握手密钥错乱（BAD_DECRYPT）。
    // guard 对称注册/注销（new 失败 `?`、connect 失败、verify 失败、成功
    // 返回全部覆盖）；每条路径在 SSL 释放前显式注销，杜绝地址复用窗口。
    let ssl_key = ssl.as_ptr() as usize;
    let hooks_guard = RealityHooksGuard::register(ssl_key, &hooks);
    let rewrite_stream = HelloRewriteStream { inner: stream };

    let tls_stream =
        TokioSslStream::new(ssl, rewrite_stream).map_err(|e| io::Error::other(e.to_string()))?;

    let mut pinned = Box::pin(tls_stream);
    let connect_result = pinned.as_mut().connect().await;
    if let Err(e) = connect_result {
        drop(hooks_guard); // 提前返回时 SSL 随 pinned 释放，须先注销
        tracing::warn!(error = ?e, "REALITY SslStream::connect failed");
        return Err(io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string()));
    }

    // REALITY 证书验证（HMAC-SHA512；失败 = 真证书/MITM → 断连）
    let verify = hooks.verify_handshake(pinned.ssl());
    drop(hooks_guard); // verify 失败提前返回时 SSL 随 pinned 释放，须先注销
    verify?;

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
        let mut rw = HelloRewriteStream { inner: client };
        rw.write_all(&[5, 1, 2, 3]).await.unwrap();
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [5, 1, 2, 3]);
    }

    // ===== RealityHooksGuard 注册/注销对称性 =====

    #[derive(Default)]
    struct ProbeHooks {
        calls: std::sync::atomic::AtomicUsize,
        sh_calls: std::sync::atomic::AtomicUsize,
        sh_last: parking_lot::Mutex<Vec<u8>>,
    }
    impl RealityHooks for ProbeHooks {
        fn rewrite_client_hello(&self, _ssl: &SslRef, _record: &mut [u8]) -> io::Result<()> {
            Ok(())
        }

        fn rewrite_client_hello_msg(&self, _ssl: RealitySslPtr, _msg: &mut [u8]) -> io::Result<()> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        fn on_server_hello(&self, msg: &[u8]) -> io::Result<()> {
            self.sh_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.sh_last.lock() = msg.to_vec();
            Ok(())
        }
    }

    fn registered_hooks(ssl_key: usize) -> Option<Arc<dyn RealityHooks>> {
        REALITY_HOOKS.lock().as_ref().and_then(|m| m.get(&ssl_key)).cloned()
    }

    fn registry_contains(hooks: &Arc<dyn RealityHooks>) -> bool {
        REALITY_HOOKS.lock().as_ref().is_some_and(|m| m.values().any(|h| Arc::ptr_eq(h, hooks)))
    }

    /// guard 生命周期 = 注册表条目生命周期（`TokioSslStream::new` 失败
    /// `?` 提前返回时由 guard drop 注销，不再泄漏条目）。
    #[test]
    fn hooks_guard_registers_and_unregisters() {
        let key = 0xaaaa_usize;
        let hooks: Arc<dyn RealityHooks> = Arc::new(ProbeHooks::default());
        let guard = RealityHooksGuard::register(key, &hooks);
        assert!(registered_hooks(key).is_some());
        drop(guard);
        assert!(registered_hooks(key).is_none());
    }

    /// 地址复用：同一键被新实例覆盖后，旧 guard drop 不得误删后继条目。
    #[test]
    fn hooks_guard_does_not_remove_successor_entry() {
        let key = 0xbbbb_usize;
        let old: Arc<dyn RealityHooks> = Arc::new(ProbeHooks::default());
        let succ: Arc<dyn RealityHooks> = Arc::new(ProbeHooks::default());
        let old_guard = RealityHooksGuard::register(key, &old);
        let succ_guard = RealityHooksGuard::register(key, &succ); // 模拟地址复用后新连接注册
        drop(old_guard);
        let surviving = registered_hooks(key).expect("successor entry must survive");
        assert!(Arc::ptr_eq(&surviving, &succ));
        drop(succ_guard);
        assert!(registered_hooks(key).is_none());
    }

    /// trampoline 按指针键派发：注销后同地址调用不得命中（残留串号防护）。
    #[test]
    fn trampoline_dispatches_only_to_registered_hooks() {
        let key = 0xcccc_usize;
        let probe = Arc::new(ProbeHooks::default());
        let guard =
            RealityHooksGuard::register(key, &(Arc::clone(&probe) as Arc<dyn RealityHooks>));
        let ssl = key as RealitySslPtr;
        let mut msg = [1u8; 8];
        assert_eq!(reality_rewrite_trampoline(ssl, msg.as_mut_ptr(), msg.len()), 1);
        assert_eq!(probe.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        drop(guard);
        assert_eq!(reality_rewrite_trampoline(ssl, msg.as_mut_ptr(), msg.len()), 1);
        assert_eq!(probe.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// ServerHello trampoline 同型派发：注册命中且字节原样到达 hooks，
    /// 注销后同地址调用放行（返回 1，不 panic）。
    #[test]
    fn server_hello_trampoline_dispatches_and_captures() {
        let key = 0xdddd_usize;
        let probe = Arc::new(ProbeHooks::default());
        let guard =
            RealityHooksGuard::register(key, &(Arc::clone(&probe) as Arc<dyn RealityHooks>));
        let ssl = key as RealitySslPtr;
        // 模拟 ServerHello handshake message：type=2 + len(3)=4 + body
        let sh = [2u8, 0, 0, 4, 0xaa, 0xbb, 0xcc, 0xdd];
        assert_eq!(reality_server_hello_trampoline(ssl, sh.as_ptr(), sh.len()), 1);
        assert_eq!(probe.sh_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(*probe.sh_last.lock(), sh);
        drop(guard);
        assert_eq!(reality_server_hello_trampoline(ssl, sh.as_ptr(), sh.len()), 1);
        assert_eq!(probe.sh_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// connect_reality 提前失败（`?` 路径）后注册表不得残留该 hooks 实例。
    #[tokio::test]
    async fn connect_reality_unregisters_hooks_on_early_failure() {
        use xray_transport::connection::DuplexConnection;

        let (client, peer) = tokio::io::duplex(1024);
        drop(peer); // 对端关闭 → 握手必败
        let hooks: Arc<dyn RealityHooks> = Arc::new(ProbeHooks::default());
        let result = connect_reality(
            DuplexConnection::new(client),
            "example.com",
            Fingerprint::Chrome,
            Arc::clone(&hooks),
        )
        .await;
        assert!(result.is_err());
        assert!(!registry_contains(&hooks));
    }

    /// bd mygg：后握手记录原语链接 + 行为验证——null SSL 必须被原语拒收
    /// （返回 0），同时证明 bindgen 绑定与 ssl 库符号真实可链接。
    /// iOS 门控同 [`send_post_handshake_record`]（预生成 bindings 无此符号）。
    #[test]
    #[cfg(not(target_os = "ios"))]
    fn post_handshake_primitive_rejects_null_ssl() {
        let rc = unsafe {
            btls_sys::SSL_send_post_handshake_record(std::ptr::null_mut(), std::ptr::null(), 0)
        };
        assert_eq!(rc, 0, "null ssl must be rejected by the injected primitive");
        // 安全封装层同步拒收（空 payload 快路径）
        assert!(send_post_handshake_record(std::ptr::null_mut(), &[]).is_err());
    }

    /// bd z32z：mirror seal 原语 null/malformed 拒绝（FFI 层 + 封装层）。
    #[test]
    #[cfg(not(target_os = "ios"))]
    fn mirror_seal_primitive_rejects_null_and_malformed_input() {
        // FFI 层：null ssl 必须被注入原语拒绝（bindgen 绑定与符号真实可链接）。
        let mut out = [0u8; 64];
        let mut out_len = 0usize;
        let rc = unsafe {
            btls_sys::SSL_seal_raw_tls13_record(
                std::ptr::null_mut(),
                b"\x17".as_ptr(),
                1,
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
            )
        };
        assert_eq!(rc, 0, "null ssl must be rejected by the injected primitive");

        // 封装层：空 inner / out 不足在调用 FFI 前拒收。
        assert!(seal_post_handshake_raw_record(std::ptr::null_mut(), &[], &mut out).is_err());
        let inner = [0x17u8; 10];
        let mut small = [0u8; 8];
        assert!(seal_post_handshake_raw_record(std::ptr::null_mut(), &inner, &mut small).is_err());
    }
}

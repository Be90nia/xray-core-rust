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

use btls::hpke::HpkeKey;
use foreign_types::{ForeignType as _, ForeignTypeRef as _};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_btls::SslStream as TokioSslStream;
use xray_common::alloc_site;

use crate::ech::convert_to_ech_keys;

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
        // 站点归因（票 4y9ns）：btls 读路径（服务端下行同面）。
        let _site = alloc_site::enter(alloc_site::TLS_READ);
        self.stream.as_mut().poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite> AsyncWrite for BtlsServerStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // 站点归因（z02z8）：btls 服务端逐写 record 封装分配。
        let _site = alloc_site::enter(alloc_site::TLS_WRITE);
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
/// 无 ECH keys = [`build_server_ssl_context_with_ech`] 的空 keys 形态。
///
/// # Errors
/// - X509 / PKCS#8 解析失败或证书-私钥不匹配 → Err（含 BoringSSL 错误描述）
pub fn build_server_ssl_context(
    cert_der: &[u8],
    key_der: &[u8],
) -> Result<btls::ssl::SslContext, String> {
    build_server_ssl_context_with_ech(cert_der, key_der, &[])
}

/// 同上，另注册 `echServerKeys`（bd 5t1zj 服务端 ECH）。
///
/// `ech_server_keys` 是 Go `ConvertToGoECHKeys` 的输入字节（JSON `echServerKeys`
/// base64 解码后）：`[u16 sk_len][sk][u16 cfg_len][cfg]*`，sk 为 32B X25519 私钥
/// 原文（Go `tls.EncryptedClientHelloKey.PrivateKey` = `ecdh.PrivateKey.Bytes()`）。
/// 空切片 = 不开 ECH（零行为变化）。
///
/// # Errors
/// - 证书/私钥非法（同 [`build_server_ssl_context`]）
/// - `ech_server_keys` 长度越界（Go `ErrInvalidLen` 同分支）
/// - 私钥非 X25519（BoringSSL `EVP_HPKE_KEY_init` 拒）
/// - ECHConfig 非法 / 与私钥不匹配 / 含服务端不支持的 cipher suite / keyset 内无 retry
///   config（BoringSSL `SSL_ECH_KEYS_add` / `SSL_CTX_set1_ech_keys` 拒）
pub fn build_server_ssl_context_with_ech(
    cert_der: &[u8],
    key_der: &[u8],
    ech_server_keys: &[u8],
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
    let ctx = builder.build();
    if !ech_server_keys.is_empty() {
        apply_ech_keys(ctx.as_ptr(), ech_server_keys)?;
    }
    Ok(ctx)
}

/// 把 ECH 解密 keys 注册进 `SSL_CTX`（BoringSSL `SSL_CTX_set1_ech_keys`）。
///
/// # 为什么走裸 FFI
/// btls 只导出 `SslEchKeysRef`（`btls/src/ssl/mod.rs`：`mod ech;` +
/// `pub use self::ech::SslEchKeysRef`），而 `SslContextRef::set_ech_keys(&SslEchKeys)`
/// 的参数是 crate 私有的所有者类型 ⇒ crate 外无法构造。这里直接调同一组 BoringSSL
/// 符号（`SSL_ECH_KEYS_new/add/free` + `SSL_CTX_set1_ech_keys`）。
///
/// # 为什么首条 key 标 `is_retry_config`
/// BoringSSL 要求 keyset 至少含一条 retry config，否则 `SSL_CTX_set1_ech_keys` 直接
/// 失败（`SSL_R_ECH_SERVER_WOULD_HAVE_NO_RETRY_CONFIGS`）；Go 的 `ConvertToGoECHKeys`
/// 恒不置 `SendAsRetry`。这里只把**首条**标 retry（retry list 只放一条），其余保持 false。
fn apply_ech_keys(ctx: *mut btls_sys::SSL_CTX, ech_server_keys: &[u8]) -> Result<(), String> {
    let keys = convert_to_ech_keys(ech_server_keys)
        .map_err(|e| format!("btls server: echServerKeys: {e}"))?;

    /// 失败路径同样要释放（ctx 只在成功时 UpRef 自己那份引用）。
    struct Keys(*mut btls_sys::SSL_ECH_KEYS);
    impl Drop for Keys {
        fn drop(&mut self) {
            // SAFETY: 指针来自 SSL_ECH_KEYS_new；NULL 为合法入参（free(NULL) 无副作用）。
            unsafe { btls_sys::SSL_ECH_KEYS_free(self.0) };
        }
    }

    // SAFETY: 新建引用，所有权交给 Keys 守卫。
    let keyset = Keys(unsafe { btls_sys::SSL_ECH_KEYS_new() });
    if keyset.0.is_null() {
        return Err("btls server: SSL_ECH_KEYS_new failed".to_string());
    }
    for (idx, k) in keys.iter().enumerate() {
        // 名字里的 p256 是 btls 历史误称：该构造恒用 EVP_hpke_x25519_hkdf_sha256。
        let hpke = HpkeKey::dhkem_p256_sha256(&k.private_key)
            .map_err(|e| format!("btls server: ech key (DHKEM X25519): {e}"))?;
        // SAFETY: keyset / hpke 均为本函数内有效对象；config 切片指向 `keys`。
        let added = unsafe {
            btls_sys::SSL_ECH_KEYS_add(
                keyset.0,
                i32::from(idx == 0),
                k.config.as_ptr(),
                k.config.len(),
                hpke.as_ptr(),
            )
        };
        if added != 1 {
            let stack = btls::error::ErrorStack::get().to_string();
            // Go CLI `xray tls ech` 产 9 套件（含 HKDF-SHA384/512），而 BoringSSL 服务端
            // 只接受 HKDF-SHA256 ⇒ 照 CLI 输出配 `echServerKeys` 会撞在这里。给出可操作
            // 修法（换后端解不了，客户端 keyset 是给 Go 服务端用的）。
            let hint = if stack.contains("UNSUPPORTED_ECH_SERVER_CONFIG") {
                "; BoringSSL requires HKDF-SHA256-only ECHConfigs — `xray tls ech` emits suites \
                 for Go servers, generate server keys with \
                 `cargo run -p xray-tls --example ech_keys`"
            } else {
                ""
            };
            return Err(format!("btls server: SSL_ECH_KEYS_add({idx}): {stack}{hint}"));
        }
    }
    // SAFETY: ctx 由调用方传入且存活；keyset 非空且首条为 retry config。
    if unsafe { btls_sys::SSL_CTX_set1_ech_keys(ctx, keyset.0) } != 1 {
        return Err(format!(
            "btls server: SSL_CTX_set1_ech_keys: {}",
            btls::error::ErrorStack::get()
        ));
    }
    Ok(())
}

/// 入站 btls 服务端上下文装配参数（bd mdpl2：plain-TLS 入站的 btls 后端）。
///
/// [`build_server_ssl_context_with_ech`] 只装证书 + ECH keys；入站还要 ALPN（fallback
/// 路由用）、版本门与 `rejectUnknownSni` 白名单——这三项缺一即"配置写了但不生效"，
/// 故在此显式承接，`None`/空 = 未配置。
#[derive(Default)]
pub struct InboundContextParams<'a> {
    /// 叶子证书 DER。`None` = 无证书（Go 语义：启动成功、每条连接握手失败）。
    pub cert_der: Option<&'a [u8]>,
    /// 链中间证书 DER（`certificates[]` 条目除叶子外全部）。
    pub chain_ders: &'a [Vec<u8>],
    /// 私钥 DER（PKCS#8；Ed25519 ring 变体由 `normalize_ed25519_pkcs8` 归一）。
    pub key_der: Option<&'a [u8]>,
    /// ECH 解密 keys（`[u16 sk_len][sk][u16 cfg_len][cfg]*`）；空 = 不开 ECH。
    pub ech_server_keys: &'a [u8],
    /// ALPN 协议名（服务端偏好序，同 Go `Config.NextProtos`）。
    pub alpn_protos: &'a [Vec<u8>],
    /// `minVersion`（缺省 = BoringSSL 默认）。
    pub min_version: Option<btls::ssl::SslVersion>,
    /// `maxVersion`（缺省 = BoringSSL 默认）。
    pub max_version: Option<btls::ssl::SslVersion>,
    /// `rejectUnknownSni=true` 时的 SNI 白名单（`None` = 不校验，任意 SNI 都发本证书）。
    pub server_names: Option<&'a [String]>,
}

/// 按入站参数装配 btls 服务端 `SslContext`（装配期一次，逐连接复用）。
///
/// # Errors
/// - 证书/链/私钥 DER 非法或证书与私钥不匹配
/// - ALPN / 版本门设置失败
/// - ECH keys 注册失败（同 [`build_server_ssl_context_with_ech`]）
pub fn build_inbound_context(
    params: InboundContextParams<'_>,
) -> Result<btls::ssl::SslContext, String> {
    use btls::ssl::{SslContextBuilder, SslMethod};
    let mut builder = SslContextBuilder::new(SslMethod::tls())
        .map_err(|e| format!("btls server: ssl ctx: {e}"))?;
    if let Some(cert_der) = params.cert_der {
        let cert = btls::x509::X509::from_der(cert_der)
            .map_err(|e| format!("btls server: cert der: {e}"))?;
        builder.set_certificate(&cert).map_err(|e| format!("btls server: set cert: {e}"))?;
        // 无私钥 = 配置错（`certificates[]` 条目只给证书不给 key 时上面已跳过；
        // 走到这里说明装配层传了叶子却漏 key）。
        let key_der = params
            .key_der
            .ok_or_else(|| "btls server: certificate loaded without private key".to_string())?;
        let key = btls::pkey::PKey::private_key_from_der(&normalize_ed25519_pkcs8(key_der))
            .map_err(|e| format!("btls server: private key der: {e}"))?;
        builder.set_private_key(&key).map_err(|e| format!("btls server: set key: {e}"))?;
        builder.check_private_key().map_err(|e| format!("btls server: cert/key mismatch: {e}"))?;
        for der in params.chain_ders {
            let extra = btls::x509::X509::from_der(der)
                .map_err(|e| format!("btls server: chain cert der: {e}"))?;
            builder
                .add_extra_chain_cert(extra)
                .map_err(|e| format!("btls server: add chain cert: {e}"))?;
        }
    }
    if !params.alpn_protos.is_empty() {
        // BoringSSL 服务端只在设了 `SSL_CTX_set_alpn_select_cb` 时协商 ALPN
        // （`ssl/extensions.cc:1464`：无回调即跳过整个扩展）——只写
        // `SSL_CTX_set_alpn_protos` 会静默不协商。选择语义对齐 Go
        // `Config.NextProtos`：按**服务端**偏好序取首个客户端也提供的协议；
        // 客户端提供了但无一命中 ⇒ fatal alert（同 Go `negotiateALPN` 失败路径）。
        let prefs = params.alpn_protos.to_vec();
        builder.set_alpn_select_callback(move |_ssl, client_list| {
            select_alpn(&prefs, client_list).ok_or(btls::ssl::AlpnError::ALERT_FATAL)
        });
    }
    if let Some(v) = params.min_version {
        builder
            .set_min_proto_version(Some(v))
            .map_err(|e| format!("btls server: set min version: {e}"))?;
    }
    if let Some(v) = params.max_version {
        builder
            .set_max_proto_version(Some(v))
            .map_err(|e| format!("btls server: set max version: {e}"))?;
    }
    if let Some(names) = params.server_names {
        let names = names.to_vec();
        // Go `Config.RejectUnknownSni`：白名单外的 SNI 直接 alert，不发证书。
        builder.set_servername_callback(move |ssl, _alert| {
            match ssl.servername(btls::ssl::NameType::HOST_NAME) {
                Some(sni) if sni_allowed(&names, sni) => Ok(()),
                _ => Err(btls::ssl::SniError::ALERT_FATAL),
            }
        });
    }
    let ctx = builder.build();
    if !params.ech_server_keys.is_empty() {
        apply_ech_keys(ctx.as_ptr(), params.ech_server_keys)?;
    }
    Ok(ctx)
}

/// 按服务端偏好序在客户端 ALPN 列表里选协议（返回**客户端缓冲**的切片，BoringSSL 要求）。
fn select_alpn<'a>(prefs: &[Vec<u8>], client_list: &'a [u8]) -> Option<&'a [u8]> {
    for pref in prefs {
        let mut rest = client_list;
        while let Some((&len, tail)) = rest.split_first() {
            let len = usize::from(len);
            let (proto, next) = tail.split_at_checked(len)?;
            if proto == pref.as_slice() {
                return Some(proto);
            }
            rest = next;
        }
    }
    None
}

/// SNI 是否命中白名单（精确或 `*.example.com` 通配，口径同 rustls 侧
/// `CertSnapshot::select`；全小写比较）。
fn sni_allowed(names: &[String], sni: &str) -> bool {
    let lower = sni.to_lowercase();
    let wildcard = match lower.find('.') {
        Some(idx) => format!("*{}", &lower[idx..]),
        None => String::from("*"),
    };
    names.iter().any(|n| n == &lower || n == &wildcard)
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
    accept_with_ctx(&ctx, stream).await
}

/// 同上，但在**装配期建好**的 `SslContext` 上握手（入站 acceptor 形态：ctx 只建一次，
/// 每条连接只 `Ssl::new`，bd mdpl2）。
///
/// 对应 Go `tls.NewListener` 包 `tls.Config` 的复用语义（`Config` 装配期一次）。
///
/// # Errors
/// - `Ssl::new` 失败（ctx 已失效）
/// - 握手失败（alert/WANT 协议错误/IO 错误）→ io::Error
pub async fn accept_with_ctx<S>(
    ctx: &btls::ssl::SslContext,
    stream: S,
) -> io::Result<BtlsServerStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ssl = btls::ssl::Ssl::new(ctx).map_err(|e| io::Error::other(e.to_string()))?;
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

        #[allow(clippy::disallowed_methods, reason = "测试：duplex TLS echo server 任务")]
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
        let fp_config = crate::btls_client::connector_for_fingerprint(&fp, None)
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

    // ---- bd 5t1zj：服务端 ECH ----

    /// ECH 的公开名（外层 SNI / 证书无需覆盖）与真实内层名（证书签给它）。
    const ECH_PUBLIC_NAME: &str = "public.example";
    const ECH_INNER_NAME: &str = "inner.example";

    fn self_signed_pair() -> (Vec<u8>, Vec<u8>) {
        let params = rcgen::CertificateParams::new(vec![ECH_INNER_NAME.to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.der().to_vec(), key_pair.serialize_der())
    }

    /// 装配预期失败的统一入口（`SslContext` 未实现 Debug，不便用 `unwrap_err`）。
    fn ech_build_err(ech_server_keys: &[u8]) -> String {
        let (cert_der, key_der) = self_signed_pair();
        match build_server_ssl_context_with_ech(&cert_der, &key_der, ech_server_keys) {
            Ok(_) => panic!("expected ECH key registration to fail"),
            Err(e) => e,
        }
    }

    /// 真 ECH 握手（BoringSSL 服务端 `set_ech_keys` ↔ BoringSSL 客户端
    /// `set_ech_config_list`）：断言内层 SNI 被服务端解出，且客户端出向 wire
    /// 只有外层 public name（内层名字不可见 = SNI 真被隐藏）。
    #[tokio::test]
    async fn btls_server_ech_hides_inner_sni() {
        use std::sync::Arc;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (config, priv_bytes) = crate::ech::generate_ech_key_set_sha256(ECH_PUBLIC_NAME);
        let server_keys = crate::ech::pack_ech_server_keys(&priv_bytes, &config);
        let config_list = crate::ech::pack_ech_config_list(&[config.as_slice()]);

        let (cert_der, key_der) = self_signed_pair();
        let ctx = build_server_ssl_context_with_ech(&cert_der, &key_der, &server_keys)
            .expect("ECH keys registered on server ctx");

        let wire = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        #[allow(clippy::disallowed_methods, reason = "测试：ECH 服务端握手任务")]
        let server = tokio::spawn(async move {
            let ssl = btls::ssl::Ssl::new(&ctx)?;
            // SAFETY: ssl 为刚构造的合法 SSL，仅标记服务端角色。
            unsafe { btls_sys::SSL_set_accept_state(ssl.as_ptr()) };
            let mut tls = Box::pin(TokioSslStream::new(ssl, server_io)?);
            tls.as_mut().accept().await.map_err(|e| io::Error::other(e.to_string()))?;
            let ech_accepted = tls.ssl().ech_accepted();
            let sni = tls.ssl().servername(btls::ssl::NameType::HOST_NAME).map(str::to_string);
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await?;
            tls.write_all(&buf).await?;
            tls.flush().await?;
            Ok::<_, io::Error>((ech_accepted, sni))
        });

        let client_ctx = {
            let mut b = btls::ssl::SslContextBuilder::new(btls::ssl::SslMethod::tls()).unwrap();
            b.set_verify(btls::ssl::SslVerifyMode::NONE);
            b.build()
        };
        let mut ssl = btls::ssl::Ssl::new(&client_ctx).unwrap();
        ssl.set_ech_config_list(&config_list).expect("client: ECH config list accepted");
        ssl.set_hostname(ECH_INNER_NAME).expect("client: inner SNI");
        let tap = Tap { inner: client_io, log: Arc::clone(&wire) };
        let mut client = Box::pin(TokioSslStream::new(ssl, tap).unwrap());
        client.as_mut().connect().await.expect("client handshake");
        let client_ech = client.ssl().ech_accepted();
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        let (server_ech, server_sni) = server.await.unwrap().unwrap();
        assert!(client_ech, "客户端必须报告 ECH accepted");
        assert!(server_ech, "服务端必须报告 ECH accepted（ClientHelloInner 已解密）");
        assert_eq!(server_sni.as_deref(), Some(ECH_INNER_NAME), "服务端应看到内层 SNI");

        // wire 面（客户端出向全部字节）：外层 SNI = public name，内层名字明文不可见。
        let wire = wire.lock().clone();
        let hay = String::from_utf8_lossy(&wire);
        assert!(hay.contains(ECH_PUBLIC_NAME), "外层 SNI 应为 public name: {hay:?}");
        assert!(!hay.contains(ECH_INNER_NAME), "内层 SNI 不得明文出现在 wire: {hay:?}");
    }

    /// BoringSSL 服务端严格校验 ECHConfig 的 cipher suite（kdf 必须 HKDF-SHA256）：
    /// Go CLI（`xray tls ech`）产出的 9 套件 keyset 必须 fail-visible，不能静默半开。
    #[test]
    fn btls_server_rejects_non_sha256_ech_suites() {
        let (config, priv_bytes) = crate::ech::generate_ech_key_set(ECH_PUBLIC_NAME);
        let keys = crate::ech::pack_ech_server_keys(&priv_bytes, &config);
        let err = ech_build_err(&keys);
        assert!(err.contains("SSL_ECH_KEYS_add"), "got: {err}");
        // 用户照 `xray tls ech`（Go 兼容 9 套件）配 `echServerKeys` 会撞这里 ⇒ 报错必须
        // 指明 BoringSSL 只吃 HKDF-SHA256 keyset（换后端/降版本都解不了）。
        assert!(err.contains("HKDF-SHA256"), "must hint the usable keyset, got: {err}");
    }

    /// 私钥不是 32B X25519 ⇒ 构造期 Err（Go 侧同位置由 `ecdh.PrivateKey` 解析拒）。
    #[test]
    fn btls_server_rejects_bad_ech_private_key() {
        let (config, _) = crate::ech::generate_ech_key_set_sha256(ECH_PUBLIC_NAME);
        let keys = crate::ech::pack_ech_server_keys(&[7u8; 16], &config);
        let err = ech_build_err(&keys);
        assert!(err.contains("DHKEM X25519"), "got: {err}");
    }

    /// ECHConfig 与私钥不配对 ⇒ 构造期 Err（BoringSSL 校验 config 内公钥 == 私钥派生公钥）。
    #[test]
    fn btls_server_rejects_ech_key_config_mismatch() {
        let (config, _) = crate::ech::generate_ech_key_set_sha256(ECH_PUBLIC_NAME);
        let (_, other_priv) = crate::ech::generate_ech_key_set_sha256(ECH_PUBLIC_NAME);
        let keys = crate::ech::pack_ech_server_keys(&other_priv, &config);
        let err = ech_build_err(&keys);
        assert!(err.contains("SSL_ECH_KEYS_add"), "got: {err}");
    }

    /// TLV 长度越界（Go `ErrInvalidLen` 分支）⇒ 构造期 Err。
    #[test]
    fn btls_server_rejects_malformed_ech_server_keys() {
        let err = ech_build_err(&[0x00, 0x20, 0x01]);
        assert!(err.contains("invalid ECH key length"), "got: {err}");
    }

    /// 客户端出向字节旁路记录（只观测客户端写的 wire 字节）。
    struct Tap<S> {
        inner: S,
        log: std::sync::Arc<parking_lot::Mutex<Vec<u8>>>,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for Tap<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for Tap<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
            if let Poll::Ready(Ok(n)) = polled {
                self.log.lock().extend_from_slice(&buf[..n]);
            }
            polled
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }
}

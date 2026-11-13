//! 入站 plain-TLS acceptor 的后端选路（bd mdpl2）。
//!
//! 对应 Go `tls.NewListener(tcpListener, tlsConfig)`：入站只听一种 TLS 实现，但本仓有两个
//! 后端——**rustls**（默认，`security:"tls"` 的既有路径）与 **btls/BoringSSL**
//! （`echServerKeys` 必需：rustls 0.23 无服务端 ECH）。选路规则唯一：
//!
//! - `tlsSettings.echServerKeys` 非空 ⇒ btls；装配失败即**配置期硬错**（禁静默回退 rustls——那会让
//!   ECH 配置静默失效，客户端内层 SNI 永远解不出）
//! - 否则 ⇒ rustls（[`crate::server_config::build_server_config`]，行为零变化）
//! - `security` 不是 `tls` ⇒ 交给 rustls 侧既有判定（`none` 返回 `None`，未知值报原文案）
//!
//! 上层（`xray-core` / 各协议 inbound）只依赖本模块的 [`InboundTlsAcceptor`] 与
//! [`InboundTlsStream`]，不再直接摸 `tokio_rustls::TlsAcceptor`。

use std::{io, sync::Arc};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::server_config;

/// 入站 TLS acceptor（后端已选路，装配期建一次、逐连接复用）。
pub enum InboundTlsAcceptor {
    /// rustls 后端（默认）。
    Rustls(tokio_rustls::TlsAcceptor),
    /// btls（BoringSSL）后端：`echServerKeys` 必需。
    #[cfg(not(target_os = "ios"))]
    Btls(Arc<btls::ssl::SslContext>),
}

impl InboundTlsAcceptor {
    /// 后端名（装配日志与证据核对用）。
    #[must_use]
    pub fn backend(&self) -> &'static str {
        match self {
            Self::Rustls(_) => "rustls",
            #[cfg(not(target_os = "ios"))]
            Self::Btls(_) => "btls",
        }
    }

    /// 在 `stream` 上完成一次入站 TLS 握手。
    ///
    /// 握手超时由调用方包（Go `Timeouts.Handshake` 语义在 serve 循环侧）。
    ///
    /// # Errors
    /// 握手失败（alert / 协议错误 / IO）——错误文案直接透传，供 serve 侧 warn。
    pub async fn accept<S>(&self, stream: S) -> io::Result<InboundTlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match self {
            // `accept_with(.., |_| ())` 与 `accept` 等价，保留装配期无回调形态。
            Self::Rustls(acceptor) => {
                Ok(InboundTlsStream::Rustls(Box::new(acceptor.accept_with(stream, |_| ()).await?)))
            },
            #[cfg(not(target_os = "ios"))]
            Self::Btls(ctx) => {
                let tls =
                    InboundTlsStream::Btls(crate::btls_server::accept_with_ctx(ctx, stream).await?);
                // ECH 只有 btls 后端能"看"到：`ech_accepted=false` 是客户端没发内层名
                // （或 keyset 不匹配）的唯一现场证据，故按连接记一条 debug。
                tracing::debug!(
                    target: "xray_tls::inbound_acceptor",
                    ech_accepted = tls.ech_accepted(),
                    sni = ?tls.server_name(),
                    "btls inbound TLS handshake complete"
                );
                Ok(tls)
            },
        }
    }
}

/// 握手完成的入站 TLS 连接（后端二选一）。
///
/// 消费方（vless/trojan/vmess/dokodemo）要的三样东西——SNI、ALPN、外层是否 TLS 1.3
/// ——都在这里统一，避免各协议各写一份 `get_ref().1`。
pub enum InboundTlsStream<S> {
    /// rustls 连接。`TlsStream` 内联持 `ServerConnection`（>1KiB），装箱压平枚举
    /// （`clippy::large_enum_variant`，`deny(warnings)` 下是硬错）；消费面只走本枚举
    /// 的访问器与 `AsyncRead/Write`，`Box` 的 Deref 对它们透明。
    Rustls(Box<tokio_rustls::server::TlsStream<S>>),
    /// btls（BoringSSL）连接。
    #[cfg(not(target_os = "ios"))]
    Btls(crate::btls_server::BtlsServerStream<S>),
}

impl<S> InboundTlsStream<S> {
    /// TLS 层观测到的 SNI。ECH 命中时为**内层名**（外层名只在 wire 上存在）。
    #[must_use]
    pub fn server_name(&self) -> Option<&str> {
        match self {
            Self::Rustls(s) => s.get_ref().1.server_name(),
            #[cfg(not(target_os = "ios"))]
            Self::Btls(s) => s.ssl().servername(btls::ssl::NameType::HOST_NAME),
        }
    }

    /// 协商出的 ALPN 协议名（VLESS/Trojan fallback 按 ALPN 路由）。
    #[must_use]
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            Self::Rustls(s) => s.get_ref().1.alpn_protocol(),
            #[cfg(not(target_os = "ios"))]
            Self::Btls(s) => s.ssl().selected_alpn_protocol(),
        }
    }

    /// 外层是否为 TLS 1.3（VLESS XRV 校验需要，Go `inbound.go:571-574`）。
    #[must_use]
    pub fn is_tls13(&self) -> bool {
        match self {
            Self::Rustls(s) => {
                s.get_ref().1.protocol_version()
                    == Some(tokio_rustls::rustls::ProtocolVersion::TLSv1_3)
            },
            #[cfg(not(target_os = "ios"))]
            Self::Btls(s) => s.ssl().version_str() == "TLSv1.3",
        }
    }

    /// 本次握手是否接受了 ECH（客户端发的是 ClientHelloInner）。
    ///
    /// rustls 后端恒 `false`（rustls 无服务端 ECH，`echServerKeys` 已在选路层拦下）。
    #[must_use]
    pub fn ech_accepted(&self) -> bool {
        match self {
            Self::Rustls(_) => false,
            #[cfg(not(target_os = "ios"))]
            Self::Btls(s) => s.ssl().ech_accepted(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for InboundTlsStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Rustls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
            #[cfg(not(target_os = "ios"))]
            Self::Btls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for InboundTlsStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Rustls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
            #[cfg(not(target_os = "ios"))]
            Self::Btls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Rustls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
            #[cfg(not(target_os = "ios"))]
            Self::Btls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Rustls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
            #[cfg(not(target_os = "ios"))]
            Self::Btls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// 按 `streamSettings` 的 security 选后端并装配入站 acceptor。
///
/// # 返回
/// - `Ok(None)`：`security` 为 `none`/空（不需要 TLS）
/// - `Ok(Some(_))`：装配成功（`backend()` 表明 rustls / btls）
/// - `Err`：配置错误；`echServerKeys` 非空但 btls 装配失败时**不退回** rustls
///
/// # Errors
/// 同 [`server_config::build_server_config`] 与
/// [`server_config::build_btls_server_context`]。
pub fn build_inbound_acceptor(
    security: &str,
    security_json: Option<&serde_json::Value>,
) -> io::Result<Option<InboundTlsAcceptor>> {
    // 非 tls（none / reality / 未知值）一律交给 rustls 侧既有判定：那里已定义
    // `Ok(None)` 与 "unsupported transport security" 文案，重复实现会两处漂移。
    if !security.eq_ignore_ascii_case("tls") {
        return Ok(server_config::build_server_config(security, security_json)?
            .map(|cfg| InboundTlsAcceptor::Rustls(cfg.into())));
    }
    let json = security_json.cloned().unwrap_or(serde_json::Value::Null);
    let ech_keys = crate::ech::parse_ech_server_keys(&json)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    if ech_keys.is_empty() {
        return Ok(server_config::build_server_config(security, security_json)?
            .map(|cfg| InboundTlsAcceptor::Rustls(cfg.into())));
    }

    #[cfg(not(target_os = "ios"))]
    {
        let ctx = server_config::build_btls_server_context(&json, &ech_keys)?;
        Ok(Some(InboundTlsAcceptor::Btls(ctx)))
    }
    #[cfg(target_os = "ios")]
    {
        // iOS 的 btls-sys 走预生成 bindings，服务端路径整体门控（bd mygg 教训）⇒
        // 没有 btls 后端可用。这里是配置期硬错，不是静默回退 rustls。
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "echServerKeys requires the btls backend, which is not available on this target \
             (server-side TLS path is gated out on ios); remove the field to start",
        ))
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    const PUBLIC_NAME: &str = "public.example";
    const INNER_NAME: &str = "inner.example";

    /// 服务端可用 ECH keyset（HKDF-SHA256-only，BoringSSL 服务端硬约束）+ 客户端 config list。
    fn ech_keys() -> (Vec<u8>, Vec<u8>) {
        let (config, priv_bytes) = crate::ech::generate_ech_key_set_sha256(PUBLIC_NAME);
        (
            crate::ech::pack_ech_server_keys(&priv_bytes, &config),
            crate::ech::pack_ech_config_list(&[config.as_slice()]),
        )
    }

    fn ech_keys_b64() -> String {
        base64::engine::general_purpose::STANDARD.encode(ech_keys().0)
    }

    /// 自签叶子证书三形态（PEM 配配置、DER 给客户端信任池）。
    struct Leaf {
        cert_pem: String,
        key_pem: String,
        cert_der: Vec<u8>,
    }

    fn leaf_cert(sans: &[&str]) -> Leaf {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params =
            rcgen::CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        Leaf {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
            cert_der: cert.der().to_vec(),
        }
    }

    fn certs_entry(leaf: &Leaf) -> serde_json::Value {
        serde_json::json!({ "certificate": leaf.cert_pem, "key": leaf.key_pem })
    }

    fn tls_json(extra: serde_json::Value) -> serde_json::Value {
        let leaf = leaf_cert(&[INNER_NAME]);
        let mut json = serde_json::json!({ "certificates": [certs_entry(&leaf)] });
        if let (Some(obj), Some(extra)) = (json.as_object_mut(), extra.as_object()) {
            for (k, v) in extra {
                obj.insert(k.clone(), v.clone());
            }
        }
        json
    }

    /// 无 `echServerKeys` ⇒ 仍走 rustls（既有路径零变化）。
    #[test]
    fn no_ech_keys_picks_rustls() {
        let acc = build_inbound_acceptor("tls", Some(&tls_json(serde_json::json!({}))))
            .unwrap()
            .expect("acceptor");
        assert_eq!(acc.backend(), "rustls");
        // 空串 = 未配置（Go proto 零值），同样走 rustls。
        let acc = build_inbound_acceptor(
            "tls",
            Some(&tls_json(serde_json::json!({ "echServerKeys": "" }))),
        )
        .unwrap()
        .expect("acceptor");
        assert_eq!(acc.backend(), "rustls");
    }

    /// `echServerKeys` 非空 ⇒ btls（rustls 0.23 无服务端 ECH，禁回退）。
    #[test]
    fn ech_keys_picks_btls() {
        let acc = build_inbound_acceptor(
            "tls",
            Some(&tls_json(serde_json::json!({ "echServerKeys": ech_keys_b64() }))),
        )
        .unwrap()
        .expect("acceptor");
        assert_eq!(acc.backend(), "btls");
    }

    /// 非法 ECH keys（TLV 越界）⇒ 配置期硬错，不产生 rustls acceptor。
    #[test]
    fn invalid_ech_keys_is_config_error() {
        let err = build_inbound_acceptor(
            "tls",
            Some(&tls_json(serde_json::json!({ "echServerKeys": "AAAA" }))),
        )
        .err()
        .expect("must fail");
        assert!(err.to_string().contains("echServerKeys"), "got: {err}");
    }

    /// 非 base64 的 `echServerKeys` ⇒ `InvalidData`（Go `"invalid ECH Config"` 同位置）。
    #[test]
    fn non_base64_ech_keys_is_invalid_data() {
        let err = build_inbound_acceptor(
            "tls",
            Some(&tls_json(serde_json::json!({ "echServerKeys": "!!!" }))),
        )
        .err()
        .expect("must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// 多张 `encipherment` 证书 + ECH ⇒ 硬错（btls 单证书，静默用首张会让 SNI 拿错证书）。
    #[test]
    fn multiple_certificates_with_ech_is_config_error() {
        let (a, b) = (leaf_cert(&["a.example"]), leaf_cert(&["b.example"]));
        let json = serde_json::json!({
            "certificates": [certs_entry(&a), certs_entry(&b)],
            "echServerKeys": ech_keys_b64(),
        });
        let err = build_inbound_acceptor("tls", Some(&json)).err().expect("must fail");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("single certificate"), "got: {err}");
    }

    /// `usage:"verify"`（mTLS 客户端 CA）+ ECH ⇒ 硬错（btls 无客户端证书校验接线）。
    #[test]
    fn verify_entry_with_ech_is_config_error() {
        let (leaf, ca) = (leaf_cert(&[INNER_NAME]), leaf_cert(&["ca.example"]));
        let json = serde_json::json!({
            "certificates": [
                certs_entry(&leaf),
                { "certificate": ca.cert_pem, "usage": "verify" },
            ],
            "echServerKeys": ech_keys_b64(),
        });
        let err = build_inbound_acceptor("tls", Some(&json)).err().expect("must fail");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("verify"), "got: {err}");
    }

    /// `usage:"issue"`（动态签发）+ ECH ⇒ 硬错（bd wr9e6：btls 单证书后端签不出
    /// 证书，静默跳过 = 启动成功但每条握手失败；Go `tls/config.go:145-171` 是现签）。
    #[test]
    fn issue_entry_with_ech_is_config_error() {
        let (leaf, ca) = (leaf_cert(&[INNER_NAME]), leaf_cert(&["ca.example"]));
        let json = serde_json::json!({
            "certificates": [
                certs_entry(&leaf),
                { "certificate": ca.cert_pem, "key": ca.key_pem, "usage": "issue" },
            ],
            "echServerKeys": ech_keys_b64(),
        });
        let err = build_inbound_acceptor("tls", Some(&json)).err().expect("must fail");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("issue"), "got: {err}");
    }

    /// 非 TLS security 不建 acceptor；未知值沿用 rustls 侧既有硬错文案。
    #[test]
    fn security_routing_matches_existing_semantics() {
        assert!(build_inbound_acceptor("none", None).unwrap().is_none());
        assert!(build_inbound_acceptor("", None).unwrap().is_none());
        let err = build_inbound_acceptor("quic", None).err().expect("must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// `echServerKeys` 配在 `security:"reality"` 上 ⇒ 硬错（REALITY 不接 btls plain 后端，
    /// 静默建个普通 btls ctx 会把 REALITY 语义丢掉）。
    #[test]
    fn ech_on_reality_security_keeps_hard_error() {
        let err = build_inbound_acceptor(
            "reality",
            Some(&tls_json(serde_json::json!({ "echServerKeys": ech_keys_b64() }))),
        )
        .err()
        .expect("must fail");
        assert!(err.to_string().contains("echServerKeys"), "got: {err}");
    }

    /// btls 后端真握手（客户端带 ECH config list + 内层 SNI + h2）：服务端
    /// `ech_accepted=true`、看到**内层** SNI、ALPN 协商成 h2、版本 TLS 1.3。
    #[tokio::test]
    async fn btls_backend_reports_ech_and_inner_sni() {
        let (server_keys, client_config_list) = ech_keys();
        let leaf = leaf_cert(&[INNER_NAME]);
        let acceptor = build_inbound_acceptor(
            "tls",
            Some(&serde_json::json!({
                "echServerKeys": base64::engine::general_purpose::STANDARD.encode(&server_keys),
                "certificates": [certs_entry(&leaf)],
                "alpn": ["h2"],
            })),
        )
        .unwrap()
        .expect("acceptor");
        assert_eq!(acceptor.backend(), "btls");

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        #[allow(clippy::disallowed_methods, reason = "测试：ECH 入站 accept 任务")]
        let server = tokio::spawn(async move {
            let mut tls = acceptor.accept(server_io).await?;
            let ech = tls.ech_accepted();
            let sni = tls.server_name().map(str::to_string);
            let alpn = tls.alpn_protocol().map(<[u8]>::to_vec);
            let tls13 = tls.is_tls13();
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await?;
            tls.write_all(&buf).await?;
            tls.flush().await?;
            Ok::<_, io::Error>((ech, sni, alpn, tls13))
        });

        let client_ctx = {
            let mut b = btls::ssl::SslContextBuilder::new(btls::ssl::SslMethod::tls()).unwrap();
            b.set_verify(btls::ssl::SslVerifyMode::NONE);
            b.build()
        };
        let mut ssl = btls::ssl::Ssl::new(&client_ctx).unwrap();
        ssl.set_ech_config_list(&client_config_list).expect("client ECH config list");
        ssl.set_hostname(INNER_NAME).expect("client inner SNI");
        ssl.set_alpn_protos(&[2, b'h', b'2']).expect("client ALPN");
        let mut client = Box::pin(tokio_btls::SslStream::new(ssl, client_io).unwrap());
        client.as_mut().connect().await.expect("client handshake");
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        let (ech, sni, alpn, tls13) = server.await.unwrap().unwrap();
        assert!(ech, "服务端必须报告 ECH accepted");
        assert_eq!(sni.as_deref(), Some(INNER_NAME), "服务端应看到内层 SNI");
        assert_eq!(alpn.as_deref(), Some(&b"h2"[..]), "ALPN 必须协商成 h2");
        assert!(tls13, "BoringSSL 默认协商 TLS 1.3");
    }

    /// rustls 后端访问器对照组：ALPN = h2、非 ECH、TLS 1.3。
    #[tokio::test]
    async fn rustls_backend_accessors_work() {
        let leaf = leaf_cert(&[INNER_NAME]);
        let acceptor = build_inbound_acceptor(
            "tls",
            Some(&serde_json::json!({
                "certificates": [certs_entry(&leaf)],
                "alpn": ["h2"],
            })),
        )
        .unwrap()
        .expect("acceptor");
        assert_eq!(acceptor.backend(), "rustls");

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        #[allow(clippy::disallowed_methods, reason = "测试：rustls 入站 accept 任务")]
        let server = tokio::spawn(async move {
            let mut tls = acceptor.accept(server_io).await?;
            let ech = tls.ech_accepted();
            let sni = tls.server_name().map(str::to_string);
            let alpn = tls.alpn_protocol().map(<[u8]>::to_vec);
            let tls13 = tls.is_tls13();
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await?;
            tls.write_all(&buf).await?;
            tls.flush().await?;
            Ok::<_, io::Error>((ech, sni, alpn, tls13))
        });

        xray_common::ensure_default_crypto_provider();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(rustls::pki_types::CertificateDer::from(leaf.cert_der.clone())).unwrap();
        let mut cfg =
            rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
        let mut client = connector
            .connect(
                rustls::pki_types::ServerName::try_from(INNER_NAME.to_string()).unwrap(),
                client_io,
            )
            .await
            .expect("client handshake");
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        let (ech, sni, alpn, tls13) = server.await.unwrap().unwrap();
        assert!(!ech, "rustls 后端无服务端 ECH ⇒ 恒 false");
        assert_eq!(sni.as_deref(), Some(INNER_NAME));
        assert_eq!(alpn.as_deref(), Some(&b"h2"[..]));
        assert!(tls13, "rustls 默认协商 TLS 1.3");
    }
}

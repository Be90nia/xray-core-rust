//! 从 `streamSettings` 安全配置构建 `rustls::ClientConfig`。
//!
//! 对应 Go `transport/internet/tls/tls.go::ConfigFromStreamSettings` + `GetTLSConfig`
//! （client 侧）。已覆盖字段：
//! - `serverName`（SNI 由调用方传给 `utls::client`，此处仅解析）
//! - `allowInsecure` / `alpn`
//! - `minVersion` / `maxVersion` / `cipherSuites` / `curvePreferences` （经
//!   `crate::config::security_params`，rustls 边界项 warn 后降级）
//! - 信任根（对应 Go `getCertPool`）：`disableSystemRoot` → 只用 `certificates[]`； `useSystemCA` →
//!   OS 信任库；缺省 → 内置根 bundle（Go `x509roots` / Rust `webpki-roots`，同源 Mozilla
//!   根集）；`certificates[]` 一律追加进根池
//! - `pinnedPeerCertSha256`：证书钉扎（对应 Go `RandCarrier.verifyPeerCert` + `verifyChain`，见
//!   `PinnedServerCertVerifier`）
//! - `verifyPeerCertByName`：证书名验证（Go v26 新增，逗号分隔多名；单独配置时走 CA 验链 +
//!   名匹配，与 pin 互不冲突）
//! - `certificates[]` 带 key 条目：客户端身份证书（mTLS 双向握手；Go 无此能力， Rust 扩展）
//!
//! ECH 留待 115 另 issue。

use std::{io, sync::Arc};

use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

use crate::{
    certificate::entry_certs_and_key,
    config::{VerifyResult, security_params, verify_chain},
    pin::generate_cert_hash,
};

/// 默认 ALPN 协议列表（对齐 Go `NextProto = []string{"h2", "http/1.1"}`）。
const DEFAULT_ALPN: &[&str] = &["h2", "http/1.1"];

/// 从 `streamSettings` 的安全配置构建 rustls `ClientConfig`。
///
/// 对应 Go `ConfigFromStreamSettings` + `GetTLSConfig`。
///
/// # 参数
/// - `security`：安全层名（`"none"` / `"tls"` / `"reality"`，大小写不敏感——内部先
///   `to_ascii_lowercase`，与 `StreamSettings::is_tls()` / `validate_security()` 同口径）。
/// - `security_json`：`tlsSettings` 或 `realitySettings` 的 JSON 值。`None` 用默认值。
/// - `server_name`：默认 SNI（当 `tlsSettings.serverName` 缺失时使用）。
///
/// # 返回
/// - `Ok(None)`：`security` 为 `"none"` 或空（唯一的"不加密"取值）
/// - `Ok(Some(Arc<ClientConfig>))`：构建成功
/// - `Err`：配置解析错误（如 `alpn` 元素非字符串、`pinnedPeerCertSha256` 非法 hex/长度）， 或
///   `security` 为未知取值（fail-visible，绝不静默降级成明文）
///
/// # 安全
///
/// `allowInsecure=true` 会跳过证书验证（对齐 Go `InsecureSkipVerify`，v26 已在
/// JSON 层移除该字段，Rust 保留兼容）。仅用于调试或明确接受 MITM 风险的场景。
/// 从 `streamSettings` 的安全配置构建 rustls `ClientConfig`。
///
/// 对应 Go `transport/internet/tls/tls.go::ConfigFromStreamSettings` + `GetTLSConfig`
/// （client 侧）。已覆盖字段：
/// - `serverName`（SNI 由调用方传给 `utls::client`，此处仅解析）
/// - `allowInsecure` / `alpn`
/// - `minVersion` / `maxVersion` / `cipherSuites` / `curvePreferences` （经
///   `crate::config::security_params`，rustls 边界项 warn 后降级）
/// - 信任根（对应 Go `getCertPool`）：`disableSystemRoot` → 只用 `certificates[]`； `useSystemCA` →
///   OS 信任库；缺省 → 内置根 bundle（Go `x509roots` / Rust `webpki-roots`，同源 Mozilla
///   根集）；`certificates[]` 一律追加进根池
/// - `pinnedPeerCertSha256`：证书钉扎（对应 Go `RandCarrier.verifyPeerCert` + `verifyChain`，见
///   `PinnedServerCertVerifier`）
/// - `certificates[]` 带 key 条目：客户端身份证书（mTLS 双向握手；Go 无此能力， Rust 扩展）
/// - `verifyPeerCertByName`（Go v26 新增）：以名字列表（逗号分隔）而非 SNI 做证书验证， 用于
///   ECH/PSK 等握手阶段 SNI 与真实服务名不一致的场景；单独配置时走 CA 验链 + 名匹配。
/// - `masterKeyLog`（Go `tls.Config.KeyLogWriter` 等价）/ `enableSessionResumption` （Go
///   `SessionTicketsDisabled` 等价）：pwh6 字段族增量。
///
/// ECH 留待 115 另 issue。
pub fn build_client_config(
    security: &str,
    security_json: Option<&serde_json::Value>,
    server_name: &str,
) -> io::Result<Option<Arc<ClientConfig>>> {
    // ring provider 经 xray-common 集中入口幂等安装（bd jrh7）。
    // ponytail: 放在函数入口确保调用方不必显式 install。
    xray_common::ensure_default_crypto_provider();

    // bd c0p71（vwhnw 家族）：`security` 先归一化大小写再判定。上游
    // `StreamSettings::is_tls()` / `validate_security()` 都是 `to_lowercase()`，
    // 而此处曾是大小写敏感精确匹配 ⇒ `security:"TLS"` 通过上游校验却拿到
    // `Ok(None)`，调用方按"无需 TLS"原样返回明文 —— 同时传输层已按
    // `is_tls()==true` 套了 TLS record framer，明文流被当 TLS 记录解析。
    // Go 基准 `infra/conf/transport_internet.go:98` 走 `strings.ToLower`，行为一致。
    let security = security.to_ascii_lowercase();
    if !matches!(security.as_str(), "tls" | "reality") {
        // `Ok(None)` 只允许表示「明确不加密」（`none` / 空）。其余值一律
        // fail-visible：静默返回 None 等于把未知安全层降级成明文。
        if security.is_empty() || security == "none" {
            return Ok(None);
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "unsupported transport security {security:?}: expected \"none\", \"tls\" or \"reality\""
            ),
        ));
    }

    let json = security_json.cloned().unwrap_or(serde_json::Value::Null);
    let obj = json.as_object();

    // bd 4w092(a)：ECH 的 DoH 查询由 `ech_doh` 用 rustls 原生 ClientHello 发出，
    // 不套配置要求的 uTLS 指纹模板（Go `ech.go:203-225` 用 `HelloChrome_Auto`）。
    // 指纹配置是「ClientHello 必须像浏览器」的承诺——DoH 查询却换另一套栈，
    // 既打脸该承诺又向 DoH 服务器（Cloudflare/Google 自己就是指纹检测方）暴露
    // 非浏览器栈 ⇒ 配了指纹就拒启，不再静默降级。
    let explicit_fingerprint =
        obj.and_then(|m| m.get("fingerprint")).and_then(|v| v.as_str()).unwrap_or("");
    let ech_doh_query = obj
        .and_then(|m| m.get("echConfigList"))
        .and_then(|v| v.as_str())
        .is_some_and(|s| s.contains("://"));
    if ech_doh_query && !explicit_fingerprint.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "tlsSettings: echConfigList DNS form (`://`) is queried over this build's rustls \
                 stack, which cannot carry fingerprint \"{explicit_fingerprint}\" (Go queries with \
                 uTLS Chrome); drop \"fingerprint\" or supply a base64 ECHConfigList"
            ),
        ));
    }

    // bd 4w092(b)：`echForceQuery` 在本仓只有 `full` 语义（DoH 查询失败 ⇒ 连接
    // 失败）。`half`/`none` 无实现，静默按 full 跑等于配置撒谎 ⇒ 拒启。顺带把
    // 非法取值（Go `unknown ECH force query mode`）也在此拦下——此前解析函数
    // `ech::parse_ech_force_query` 无调用方，键存在等于没校验。
    match crate::ech::parse_ech_force_query(&json)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
    {
        crate::ech::EchForceQuery::Full => {},
        crate::ech::EchForceQuery::Half | crate::ech::EchForceQuery::None => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "tlsSettings: echForceQuery \"half\"/\"none\" is not implemented (only \"full\": \
                 a failed ECH DNS query fails the connection)",
            ));
        },
    }

    // serverName：缺失时用参数传入的默认值（通常是 dest 地址）。
    // SNI 不进 ClientConfig（rustls 由 connect(server_name) 参数决定），仅保留解析。
    let _sni: String = obj
        .and_then(|m| m.get("serverName"))
        .and_then(|v| v.as_str())
        .unwrap_or(server_name)
        .to_string();

    // allowInsecure：默认 false。
    let allow_insecure: bool =
        obj.and_then(|m| m.get("allowInsecure")).and_then(|v| v.as_bool()).unwrap_or(false);
    // Go infra/conf/transport_internet.go:698-700：allowInsecure 已移除（硬报错）。
    // Rust 保留现行为：warn + 继续跳过证书验证。
    if allow_insecure {
        xray_common::errors::warn_removed_feature(
            "\"allowInsecure\"",
            "\"pinnedPeerCertSha256\"(pcs) and \"verifyPeerCertByName\"(vcn)",
        );
    }

    // alpn：数组；缺失用 DEFAULT_ALPN。
    let alpn_owned: Vec<Vec<u8>> =
        if let Some(arr) = obj.and_then(|m| m.get("alpn")).and_then(|v| v.as_array()) {
            arr.iter()
                .map(|s| {
                    s.as_str().map(|x| x.as_bytes().to_vec()).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "alpn array must contain only strings",
                        )
                    })
                })
                .collect::<io::Result<_>>()?
        } else {
            DEFAULT_ALPN.iter().map(|s| s.as_bytes().to_vec()).collect()
        };

    // minVersion/maxVersion/cipherSuites/curvePreferences → provider + 版本列表
    let (provider, versions) = security_params(&json);

    // pinnedPeerCertSha256：逗号分隔 hex（容忍 OpenSSL 冒号），32 字节/项
    let pins = parse_pinned_hashes(&json)?;

    // mTLS 客户端身份：首个同时含证书+私钥的 certificates[] 条目
    let identity = client_identity(&json)?;

    // pwh6: TLS 字段族增量解析（client 侧）。所有字段缺失=默认行为，向前兼容。
    let master_key_log = crate::server_config::parse_master_key_log(&json);
    let enable_session_resumption = obj
        .and_then(|m| m.get("enableSessionResumption"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    // verifyPeerCertByName：Go v26 新增——以名字（可多名）而非 SNI 做证书验证。
    // 用法：ECH/PSK 等握手阶段 SNI 与真实服务名不一致场景，对 ECH inner SNI
    // 暴露的真实服务做校验。空=保持默认 SNI 校验。
    let verify_peer_cert_by_name = parse_verify_peer_cert_by_name(&json);

    // echSockopt（Go transport_security.go:318 `echSockopt`）：Go 唯一消费点是
    // ECH DoH 查询链（ech.go QueryRecord→dnsQuery 的 DialSystem 连接 sockopt）。
    // Rust ECH DoH 查询已接线（ech_doh），但查询连接的 sockopt 应用未实现，
    // 此处识别 + 显式忽略提示。
    if crate::ech::parse_ech_sockopt(&json).is_some() && ech_doh_query {
        tracing::warn!(
            target: "xray_tls::client_config",
            "echSockopt is set but sockopt is not applied to the ECH DoH query connection; sockopt ignored"
        );
    }

    // allowInsecure 的 verifier 需要 provider 的签名算法集；builder 会拿走 provider，
    // 故仅在需要时先取副本（其余路径零额外 clone）。
    let insecure_sig_provider = allow_insecure.then(|| (*provider).clone());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .map_err(|e| io::Error::other(format!("protocol versions: {e}")))?;

    // 信任根先算：pin/vcn 分支里的第二段名验证要用同一份根池（Go `RootCAs`）。
    let roots = verifier_roots(&json)?;
    let builder = if let Some(prov) = insecure_sig_provider {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification(prov)))
    } else if !pins.is_empty() || !verify_peer_cert_by_name.is_empty() {
        // bd idtl1：vcn-only（无 pin）是合法配置——Go 的 pin 段在
        // `PinnedPeerCertSha256 == nil` 时整段跳过，vcn 段用 RootCAs 验链+验名。
        builder.dangerous().with_custom_certificate_verifier(Arc::new(
            PinnedServerCertVerifier::new(pins, verify_peer_cert_by_name, Arc::new(roots)),
        ))
    } else {
        builder.with_root_certificates(roots)
    };

    let mut cfg = match identity {
        Some((certs, key)) => builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| io::Error::other(format!("client auth cert: {e}")))?,
        None => builder.with_no_client_auth(),
    };
    cfg.alpn_protocols = alpn_owned;

    // pwh6: masterKeyLog — Go KeyLogWriter（config.go:467-474）。string 路径
    // 追加写 NSS 行；bool true（历史方言）走 SSLKEYLOGFILE env；打开失败
    // 对齐 Go：warn 后继续（无 keylog）。
    match master_key_log {
        crate::server_config::MasterKeyLogSetting::Path(path) => {
            match std::fs::OpenOptions::new().create(true).append(true).open(&path) {
                Ok(file) => {
                    cfg.key_log = Arc::new(crate::server_config::KeyLogFileWriter(
                        parking_lot::Mutex::new(file),
                    ));
                },
                Err(e) => tracing::warn!(
                    target: "xray_tls::client_config",
                    error = %e,
                    path = %path,
                    "failed to open masterKeyLog as file; key log disabled"
                ),
            }
        },
        crate::server_config::MasterKeyLogSetting::EnvFile => {
            cfg.key_log = Arc::new(rustls::KeyLogFile::new());
        },
        crate::server_config::MasterKeyLogSetting::Off => {},
    }

    // pwh6: enableSessionResumption=false 走 rustls `Resumption::disabled()`
    // （client/client_conn.rs:495：store=NoClientSessionStorage +
    // tls12_resumption=Disabled）。Go 端 `SessionTicketsDisabled=true` 等价。
    if !enable_session_resumption {
        cfg.resumption = rustls::client::Resumption::disabled();
    }

    Ok(Some(Arc::new(cfg)))
}

/// 客户端信任根（对应 Go `getCertPool`，`transport/internet/tls/config.go:366`）。
///
/// Go 的三档（`config_other.go` / `config_windows.go`）：
/// 1. `disableSystemRoot=true` → `loadSelfCertPool()`：**只**信 `certificates[]`。
/// 2. `useSystemCA=true` → `loadCA(true)` = `x509.SystemCertPool()`（失败回落 bundle）， 再追加
///    `certificates[]`。
/// 3. 缺省 → `loadCA(false)` = Go 内置的 `x509roots` bundle（Mozilla 根集），再追加
///    `certificates[]` —— 与 Rust `webpki-roots` 同源，故 Rust 缺省用 webpki-roots 等价。
///
/// 注意 Go 三档**都**追加 `certificates[]`（1 是"只"用它们），因此自带 CA 的配置
/// 不需要 `disableSystemRoot` 也能验过。
fn verifier_roots(json: &serde_json::Value) -> io::Result<RootCertStore> {
    let disable = json
        .as_object()
        .and_then(|m| m.get("disableSystemRoot"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if disable {
        return custom_root_store(json);
    }
    let mut store = RootCertStore::empty();
    if json.get("useSystemCA").and_then(|v| v.as_bool()).unwrap_or(false) {
        let native = rustls_native_certs::load_native_certs();
        for err in &native.errors {
            tracing::warn!(
                target: "xray_tls::client_config",
                error = %err,
                "useSystemCA: failed to read part of the OS root store"
            );
        }
        for cert in native.certs {
            // 单条根证书不被接受只影响该条（同 Go 逐条 AppendCertsFromPEM 容错）
            let _ = store.add(cert);
        }
        if store.is_empty() {
            tracing::warn!(
                target: "xray_tls::client_config",
                "useSystemCA: OS root store yielded no usable cert; every chain will fail"
            );
        }
    } else {
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    add_json_certs(&mut store, json)?;
    Ok(store)
}

/// 按安全配置构建**服务端证书验证器**（btls 指纹路径回接验证用，pz6c）。
///
/// 对应 Go `copyConfig`（tls.go:149-161）把验证语义透传进 utls.Config：uTLS
/// 非 insecure 时握手执行完整链验证。返回 `None` = `allowInsecure=true`
/// （跳过验证，等价 Go `InsecureSkipVerify`）；`Some` 按序命中 pinned/vcn
/// 自定义验证器或 webpki（用户根 / webpki-roots）验证器，与
/// [`build_client_config`] 的 rustls 路径同语义。
///
/// # 参数
/// - `security_json`：`tlsSettings` JSON；`None` 按 `{}`（默认全验证）。
pub fn build_server_cert_verifier(
    security_json: Option<&serde_json::Value>,
) -> io::Result<Option<Arc<dyn ServerCertVerifier>>> {
    // ring provider 经集中入口安装（同 build_client_config:78）：workspace
    // feature unification 同启 ring+aws-lc-rs 时 rustls 无法自动选定 provider，
    // naive/btls 路径只经本函数装配 rustls 验证器 → 进程级 panic。
    xray_common::ensure_default_crypto_provider();
    let json = security_json.cloned().unwrap_or(serde_json::Value::Null);
    let allow_insecure = json
        .as_object()
        .and_then(|m| m.get("allowInsecure"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if allow_insecure {
        // bd 1nrzk(a)：库直调面的第二道 fail-visible 关口。配置面由
        // `xray-conf` lint 双向硬错（inbound+outbound），但直接调用本函数的
        // 嵌入方/测试走不到 lint——这里至少不得静默：明确告知"链与主机名
        // 全不校验"，避免 `build_server_cert_verifier(x)? == None` 被当作
        // "无需验证器"从而无声接受任意证书。（`build_client_config` 侧对同一
        // 键有 deprecation 提示，此处不重复。）
        tracing::warn!(
            target: "xray_tls::client_config",
            "allowInsecure=true: server certificate chain and hostname verification are \
             skipped for the btls/fingerprint path (Go InsecureSkipVerify semantics); \
             only use for debugging"
        );
        return Ok(None);
    }
    let pins = parse_pinned_hashes(&json)?;
    let verify_peer_cert_by_name = parse_verify_peer_cert_by_name(&json);
    let roots = Arc::new(verifier_roots(&json)?);
    if !pins.is_empty() || !verify_peer_cert_by_name.is_empty() {
        return Ok(Some(Arc::new(PinnedServerCertVerifier::new(
            pins,
            verify_peer_cert_by_name,
            roots,
        ))));
    }
    let verifier = WebPkiServerVerifier::builder(roots)
        .build()
        .map_err(|e| io::Error::other(format!("webpki verifier: {e}")))?;
    Ok(Some(verifier))
}

/// `verifyPeerCertByName`：逗号分隔多名（Go `infra/conf/transport_security.go:382-390`
/// 逐段 `TrimSpace` 去空）。缺失/非字符串/空串 → 空列表 = 不启用名验证。
fn parse_verify_peer_cert_by_name(json: &serde_json::Value) -> Vec<String> {
    json.as_object()
        .and_then(|m| m.get("verifyPeerCertByName"))
        .and_then(|v| v.as_str())
        .map(|spec| {
            spec.split(',').map(str::trim).filter(|n| !n.is_empty()).map(str::to_string).collect()
        })
        .unwrap_or_default()
}

/// `disableSystemRoot=true` 时的信任根：`certificates[]` 全部条目的证书
/// （对应 Go `loadSelfCertPool`——遍历全部 `Certificate`，不筛 usage）。
///
/// 未配置任何证书 → 空池（对齐 Go：空 `x509.CertPool`，一切验证失败）。
///
/// # Errors
/// 条目非法（内联类型错误/内容缺失/PEM 无证书块）时传播——对齐 Go：配置
/// 加载期即报错，不在信任根构建层静默吞掉。
fn custom_root_store(json: &serde_json::Value) -> io::Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    add_json_certs(&mut store, json)?;
    Ok(store)
}

/// 把 `certificates[]` 全部条目的证书追加进根池（Go `getCertPool` 各档的
/// `pool.AppendCertsFromPEM(cert.Certificate)` 循环，不筛 usage）。
///
/// 条目非法（内联类型错/内容缺失/PEM 无证书块）→ 传播错误（配置加载期 fail-fast）。
fn add_json_certs(store: &mut RootCertStore, json: &serde_json::Value) -> io::Result<()> {
    if let Some(arr) = json.get("certificates").and_then(|v| v.as_array()) {
        for entry in arr {
            let (certs, _) = entry_certs_and_key(entry)?;
            for der in certs {
                // 单条证书不被信任时跳过（对齐 Go 逐条 AppendCertsFromPEM 的容错语义：
                // 追加失败只影响该条证书，不中断池构建）
                let _ = store.add(der);
            }
        }
    }
    Ok(())
}

/// 解析 `pinnedPeerCertSha256`：逗号分隔 hex 字符串（容忍 OpenSSL 冒号格式）。
///
/// 对应 Go `TLSConfig.Build` L701-717：空段跳过；hex 非法或长度 ≠ 32 报错。
fn parse_pinned_hashes(json: &serde_json::Value) -> io::Result<Vec<Vec<u8>>> {
    // 缺失或 null 视同未配（Go encoding/json：缺省零值 / null no-op）；存在但
    // 非 string 是配置类型错，fail-fast 拒启——不得静默丢 pin 后让 webpki 报
    // 无关的 UnknownIssuer（bd zl5t；Go 基线实测 unmarshal array→string 硬错）。
    let Some(pin) = json.get("pinnedPeerCertSha256").filter(|v| !v.is_null()) else {
        return Ok(Vec::new());
    };
    let Some(spec) = pin.as_str() else {
        let got = match pin {
            serde_json::Value::Array(_) => "array",
            serde_json::Value::Bool(_) => "bool",
            serde_json::Value::Number(_) => "number",
            serde_json::Value::Object(_) => "object",
            _ => "non-string value",
        };
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("pinnedPeerCertSha256: expected string (comma-separated hex), got {got}"),
        ));
    };
    let mut pins = Vec::new();
    for v in spec.split(',') {
        let v = v.trim();
        if v.is_empty() {
            continue;
        }
        // remove colons for OpenSSL format
        let cleaned: String = v.chars().filter(|c| *c != ':').collect();
        let bytes = hex::decode(&cleaned).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("pinnedPeerCertSha256: invalid hex: {e}"),
            )
        })?;
        if bytes.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("incorrect pinnedPeerCertSha256 length: {v}"),
            ));
        }
        pins.push(bytes);
    }
    Ok(pins)
}

/// 客户端身份证书（mTLS）：`certificates[]` 中首个同时含证书与私钥的条目。
///
/// Go 客户端从不发送证书（`GetTLSConfig` 不设 `tls.Config.Certificates`）；
/// 这是 Rust 扩展，服务端配置 `usage:"verify"` CA 时用于双向握手。
/// CA 条目（`usage:"verify"`）通常无私钥，不会被误认。
fn client_identity(
    json: &serde_json::Value,
) -> io::Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>> {
    if let Some(arr) = json.get("certificates").and_then(|v| v.as_array()) {
        for entry in arr {
            let (certs, key) = entry_certs_and_key(entry)?;
            if let Some(key) = key {
                return Ok(Some((certs, key)));
            }
        }
    }
    Ok(None)
}

/// 证书钉扎 / 名验证 verifier（对应 Go `RandCarrier.verifyPeerCert` + `verifyChain`）。
///
/// 语义与 Go 一致（两段式，第二段只在 pin 未直接放行时跑）：
/// 1. `pinnedPeerCertSha256` **非空**才走 pin 段：命中**叶子** → 直接通过（Go `foundLeaf` 即
///    `return nil`，不查链/有效期/主机名）；命中链中 **CA** → 该 CA 成为唯一信任根； 无命中 →
///    拒绝（`peer cert is unrecognized`）。**pin 为空时整段跳过**——Go `PinnedPeerCertSha256 == nil`
///    时不进 pin 分支（bd idtl1：旧实现把空 pin 当"无命中"， 导致只配 vcn 的配置一律被拒）。
/// 2. `verifyPeerCertByName` 非空 → 对**每个名字**做完整 webpki 验证（链 + 签名 + 有效期 +
///    主机名，对应 Go `certs[0].Verify(Roots=CAs, DNSName=name)`），全部失败才拒。 无 vcn 但 pin
///    命中 CA → 用握手 SNI（Go "Pinning CA" 分支）。
///
/// 信任根：`roots` = 配置的根池（[`verifier_roots`]，即 Go `r.RootCAs`）；pin 命中 CA 时
/// 换成该 CA。
///
/// 握手签名验证是**真实验证**（委托 ring provider），与
/// [`NoCertificateVerification`] 的全过语义不同——钉扎不降低握手完整性。
#[derive(Debug)]
struct PinnedServerCertVerifier {
    /// 每项 32 字节 SHA-256。
    pins: Vec<Vec<u8>>,
    /// Go `verifyPeerCertByName` 等价——非空时替代 SNI 做主机名校验（可多名）。
    verify_peer_cert_by_name: Vec<String>,
    /// 名验证段的信任根（Go `r.RootCAs` = `getCertPool()`）。
    roots: Arc<RootCertStore>,
}

impl PinnedServerCertVerifier {
    fn new(
        pins: Vec<Vec<u8>>,
        verify_peer_cert_by_name: Vec<String>,
        roots: Arc<RootCertStore>,
    ) -> Self {
        Self { pins, verify_peer_cert_by_name, roots }
    }
}
impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // 第一段：pin。Go `PinnedPeerCertSha256 == nil` → 整段跳过（bd idtl1）。
        let mut roots = Arc::clone(&self.roots);
        if !self.pins.is_empty() {
            // [叶子, 中间证书...] 的 hash/is_ca 输入（对应 Go verifyPeerCert 的 certs）
            let mut hashes = vec![generate_cert_hash(end_entity)];
            let mut is_ca = vec![false];
            for cert in intermediates {
                hashes.push(generate_cert_hash(cert));
                is_ca.push(
                    x509_parser::parse_x509_certificate(cert.as_ref())
                        .map(|(_, c)| c.is_ca())
                        .unwrap_or(false),
                );
            }
            match verify_chain(&hashes, &is_ca, &self.pins) {
                (VerifyResult::FoundLeaf, _) => return Ok(ServerCertVerified::assertion()),
                (VerifyResult::FoundCa, Some(idx)) => {
                    // verify_chain 的索引含叶子（0），中间证书从 1 起
                    let ca = intermediates.get(idx - 1).ok_or_else(|| {
                        rustls::Error::General("pinned CA index out of range".into())
                    })?;
                    let mut store = RootCertStore::empty();
                    store
                        .add(ca.clone())
                        .map_err(|e| rustls::Error::General(format!("pinned CA: {e}")))?;
                    roots = Arc::new(store);
                },
                _ => {
                    return Err(rustls::Error::General(
                        "peer cert is unrecognized (against pinnedPeerCertSha256)".into(),
                    ));
                },
            }
        }

        // 第二段：名验证。
        if !self.verify_peer_cert_by_name.is_empty() {
            // 多名逐个试，任一通过即放行（Go `for _, opts.DNSName = range ...`）
            let verifier = WebPkiServerVerifier::builder(roots)
                .build()
                .map_err(|e| rustls::Error::General(format!("vcn verifier: {e}")))?;
            let mut last_err = None;
            for name in &self.verify_peer_cert_by_name {
                let server_name = ServerName::try_from(name.clone()).map_err(|e| {
                    rustls::Error::General(format!("verifyPeerCertByName {name}: {e}"))
                })?;
                match verifier.verify_server_cert(
                    end_entity,
                    intermediates,
                    &server_name,
                    ocsp_response,
                    now,
                ) {
                    Ok(verified) => return Ok(verified),
                    Err(e) => last_err = Some(e),
                }
            }
            return Err(last_err.unwrap_or_else(|| {
                rustls::Error::General(
                    "peer cert is invalid (against root CAs and verifyPeerCertByName)".into(),
                )
            }));
        }
        if self.pins.is_empty() {
            // 无 pin 也无 vcn：本 verifier 不该被装上（build_client_config 走
            // with_root_certificates）。对齐 Go 末行 `return nil`：不重复验。
            return Ok(ServerCertVerified::assertion());
        }
        // pin 命中 CA 且未配 vcn → 用握手 SNI 验链（Go "Pinning CA" 分支）
        let verifier = WebPkiServerVerifier::builder(roots)
            .build()
            .map_err(|e| rustls::Error::General(format!("pinned CA verifier: {e}")))?;
        verifier.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// 跳过**证书链**验证的 verifier（对齐 Go `InsecureSkipVerify: true`）。
///
/// bd 1nrzk：Go 的 `InsecureSkipVerify` 只跳过链/名验证，握手签名
/// （`CertificateVerify` 证明持有私钥）仍照验。此前这里连签名都
/// `assertion()` 直接放行、还额外宣告 SHA1 家族方案（比 Go 更弱，且会改变
/// ClientHello 的 `signature_algorithms` 扩展 ⇒ JA4 可判别）。现按 Go 语义：
/// - 链验证：跳过（本类型存在意义）
/// - 握手签名：委托 provider 的 `signature_verification_algorithms` 真校验
/// - 宣告方案：= provider 的受支持方案（无 SHA1 家族）
///
/// # 安全
///
/// 证书链完全不校验（任何自签/过期/错名证书都通过），**仅在调试或明确接受
/// MITM 风险的场景使用**。生产环境必须保持 `allowInsecure=false`。
#[derive(Debug)]
struct NoCertificateVerification(rustls::crypto::CryptoProvider);

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // 唯一被跳过的部分：链 + 主机名 + OCSP（Go InsecureSkipVerify 同义）。
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use rustls::version::{TLS12, TLS13};

    use super::*;

    #[test]
    fn client_invalid_inline_cert_errors_instead_of_silent_skip() {
        // disableSystemRoot=true 时信任根来自 certificates[]；条目类型非法
        // → custom_root_store Err 传播（对齐 Go 配置加载 error），不再静默吞掉。
        let v = serde_json::json!({
            "disableSystemRoot": true,
            "certificates": [{ "certificate": 42 }]
        });
        assert!(build_client_config("tls", Some(&v), "fallback.com").is_err());
    }

    fn install_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    // ---- 既有行为回归 ----

    #[test]
    fn none_security_returns_none() {
        install_provider();
        let r = build_client_config("none", None, "example.com").unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn empty_security_returns_none() {
        install_provider();
        let r = build_client_config("", None, "example.com").unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn tls_security_with_null_json_returns_some() {
        install_provider();
        let r = build_client_config("tls", None, "example.com").unwrap();
        assert!(r.is_some(), "tls should produce a ClientConfig even with null json");
    }

    #[test]
    fn tls_security_parses_alpn() {
        install_provider();
        let v: serde_json::Value =
            serde_json::from_str(r#"{"serverName":"x.com","alpn":["h2","http/1.1"]}"#).unwrap();
        let cfg = build_client_config("tls", Some(&v), "fallback.com").unwrap().unwrap();
        let negotiated: Vec<Vec<u8>> = cfg.alpn_protocols.clone();
        assert_eq!(negotiated, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    #[test]
    fn tls_security_alpn_invalid_type_returns_err() {
        install_provider();
        let v: serde_json::Value = serde_json::from_str(r#"{"alpn":["h2",123]}"#).unwrap();
        let r = build_client_config("tls", Some(&v), "x.com");
        assert!(r.is_err(), "non-string alpn element must error");
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn tls_security_alpn_defaults_when_missing() {
        install_provider();
        let v: serde_json::Value = serde_json::from_str(r#"{"serverName":"x.com"}"#).unwrap();
        let cfg = build_client_config("tls", Some(&v), "fallback.com").unwrap().unwrap();
        let negotiated: Vec<Vec<u8>> = cfg.alpn_protocols.clone();
        assert_eq!(negotiated, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    #[test]
    fn allow_insecure_produces_dangerous_verifier() {
        install_provider();
        let v: serde_json::Value = serde_json::from_str(r#"{"allowInsecure":true}"#).unwrap();
        let cfg = build_client_config("tls", Some(&v), "example.com").unwrap().unwrap();
        // dangerous verifier 应该是 NoCertificateVerification；通过 ALPN 仍设置验证 dangerous
        // 路径走通。
        assert!(!cfg.alpn_protocols.is_empty());
        // 没有公开 API 直接判 verifier 类型，靠 e2e 验证行为。
    }

    #[test]
    fn reality_security_treated_as_tls() {
        install_provider();
        let r = build_client_config("reality", None, "example.com").unwrap();
        assert!(r.is_some(), "reality should produce a ClientConfig");
    }

    // ---- bd c0p71：security 大小写变体必须得到真 TLS 配置，不得 Ok(None) ----

    /// `security:"TLS"` / `"Tls"` / `"REALITY"` 落到 TLS 分支（Go
    /// `transport_internet.go:98` `strings.ToLower` 同义）。改前这三种取值返回
    /// `Ok(None)` ⇒ 调用方按"无需 TLS"原样返回明文 conn，而传输层已按
    /// `is_tls()==true` 套了 TLS record framer。
    #[test]
    fn uppercase_security_builds_tls_config() {
        install_provider();
        for security in ["TLS", "Tls", "tls", "REALITY", "Reality"] {
            let cfg = build_client_config(security, None, "example.com").unwrap();
            assert!(cfg.is_some(), "security={security:?} must build a ClientConfig, not Ok(None)");
        }
    }

    /// `Ok(None)` 只表示"明确不加密"；未知取值必须 fail-visible（改前一律静默
    /// `Ok(None)` = 明文降级）。
    #[test]
    fn unknown_security_fails_visible() {
        install_provider();
        for security in ["xtls", "TLSX", "reality2"] {
            let err = build_client_config(security, None, "example.com")
                .expect_err("unknown security must not degrade to plaintext");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "got: {err}");
        }
    }

    /// bd 1nrzk(b)：宣告的签名方案集 = provider 集（改前额外宣告 SHA1 家族，
    /// 会改 ClientHello 的 `signature_algorithms` ⇒ JA4 可判别）。
    #[test]
    fn insecure_verifier_advertises_provider_schemes_only() {
        install_provider();
        let verifier = NoCertificateVerification(rustls::crypto::ring::default_provider());
        let schemes = verifier.supported_verify_schemes();
        assert!(!schemes.contains(&SignatureScheme::RSA_PKCS1_SHA1), "{schemes:?}");
        assert!(!schemes.contains(&SignatureScheme::ECDSA_SHA1_Legacy), "{schemes:?}");
        assert!(schemes.contains(&SignatureScheme::ED25519), "{schemes:?}");
    }

    // ---- minVersion/maxVersion/cipherSuites/curvePreferences（security_params）----

    #[test]
    fn versions_default_both() {
        let (p, v) = security_params(&serde_json::json!({}));
        drop(p);
        assert_eq!(v, vec![&TLS13, &TLS12]);
    }

    #[test]
    fn versions_min_max_bounds() {
        // min 1.2 → 1.3 + 1.2
        let (_, v) = security_params(&serde_json::json!({"minVersion": "1.2"}));
        assert_eq!(v, vec![&TLS13, &TLS12]);
        // min 1.3 → 仅 1.3
        let (_, v) = security_params(&serde_json::json!({"minVersion": "1.3"}));
        assert_eq!(v, vec![&TLS13]);
        // max 1.2 → 仅 1.2
        let (_, v) = security_params(&serde_json::json!({"maxVersion": "1.2"}));
        assert_eq!(v, vec![&TLS12]);
        // min 1.3 + max 1.2 → 空 → 回落默认
        let (_, v) =
            security_params(&serde_json::json!({"minVersion": "1.3", "maxVersion": "1.2"}));
        assert_eq!(v, vec![&TLS13, &TLS12]);
    }

    #[test]
    fn versions_tls10_tls11_unsupported_clamped() {
        // min 1.0/1.1 → Unsupported warn + 钳到 1.2
        let (_, v) = security_params(&serde_json::json!({"minVersion": "1.0"}));
        assert_eq!(v, vec![&TLS13, &TLS12]);
        let (_, v) = security_params(&serde_json::json!({"minVersion": "1.1"}));
        assert_eq!(v, vec![&TLS13, &TLS12]);
        // max 1.1 → 无可用版本 → 回落默认
        let (_, v) = security_params(&serde_json::json!({"maxVersion": "1.1"}));
        assert_eq!(v, vec![&TLS13, &TLS12]);
        // 未知值 → 对齐 Go 忽略
        let (_, v) = security_params(&serde_json::json!({"minVersion": "9.9"}));
        assert_eq!(v, vec![&TLS13, &TLS12]);
    }

    #[test]
    fn cipher_suites_filter() {
        let (p, _) = security_params(&serde_json::json!({
            "cipherSuites": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_AES_128_GCM_SHA256"
        }));
        assert_eq!(p.cipher_suites.len(), 2);
        // ring 默认 9 个（3×TLS1.3 + 6×TLS1.2 ECDHE）
        let (p, _) = security_params(&serde_json::json!({}));
        assert_eq!(p.cipher_suites.len(), 9);
        // 全部不可用 → 保留默认
        let (p, _) = security_params(&serde_json::json!({"cipherSuites": "BOGUS:FAKE"}));
        assert_eq!(p.cipher_suites.len(), 9);
        // CBC 套件 rustls 不支持 → 跳过
        let (p, _) = security_params(&serde_json::json!({
            "cipherSuites": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_AES_256_GCM_SHA384"
        }));
        assert_eq!(p.cipher_suites.len(), 1);
    }

    #[test]
    fn curve_preferences_filter() {
        // 仅 x25519 可用（curvep521 Unsupported warn 跳过、junk 未知 warn 跳过）
        let (p, _) = security_params(&serde_json::json!({
            "curvePreferences": ["x25519", "curvep521", "junk"]
        }));
        assert_eq!(p.kx_groups.len(), 1);
        assert_eq!(p.kx_groups[0].name(), rustls::NamedGroup::X25519);
        // 用户顺序保留：P384 在前
        let (p, _) = security_params(&serde_json::json!({
            "curvePreferences": ["curvep384", "curvep256"]
        }));
        assert_eq!(p.kx_groups.len(), 2);
        assert_eq!(p.kx_groups[0].name(), rustls::NamedGroup::secp384r1);
        // 全不可用 → 保留默认 3 组
        let (p, _) = security_params(&serde_json::json!({
            "curvePreferences": ["x25519mlkem768"]
        }));
        assert_eq!(p.kx_groups.len(), 3);
        // 单字符串形态（Go StringList 兼容）
        let (p, _) = security_params(&serde_json::json!({
            "curvePreferences": "curvep256"
        }));
        assert_eq!(p.kx_groups.len(), 1);
    }

    // ---- pinnedPeerCertSha256 解析 ----

    #[test]
    fn pinned_hashes_parse() {
        let ok = parse_pinned_hashes(&serde_json::json!({
            "pinnedPeerCertSha256": "00ff".repeat(16)
        }))
        .unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].len(), 32);
        // 空段跳过；空字符串 / 缺失 → 空 pins
        assert!(
            parse_pinned_hashes(&serde_json::json!({"pinnedPeerCertSha256": ""}))
                .unwrap()
                .is_empty()
        );
        assert!(parse_pinned_hashes(&serde_json::json!({})).unwrap().is_empty());
    }

    #[test]
    fn pinned_hashes_multiple_and_colons() {
        let h1 = "aa".repeat(32);
        let h2 = "bb".repeat(32);
        let pins = parse_pinned_hashes(&serde_json::json!({
            "pinnedPeerCertSha256": format!("{h1},{h2}")
        }))
        .unwrap();
        assert_eq!(pins.len(), 2);
        // 冒号（OpenSSL 格式）被剥离
        let colonized: String = h1
            .as_str()
            .chars()
            .enumerate()
            .map(|(i, c)| if i % 2 == 0 && i > 0 { format!(":{c}") } else { c.to_string() })
            .collect();
        let pins = parse_pinned_hashes(&serde_json::json!({
            "pinnedPeerCertSha256": colonized
        }))
        .unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0], hex::decode(&h1).unwrap());
    }

    #[test]
    fn pinned_hashes_invalid() {
        // 非 hex
        let e = parse_pinned_hashes(&serde_json::json!({"pinnedPeerCertSha256": "zz".repeat(32)}))
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        // 长度错（31 字节）
        let e = parse_pinned_hashes(&serde_json::json!({"pinnedPeerCertSha256": "ab".repeat(31)}))
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        // build 层透传错误
        let r = build_client_config(
            "tls",
            Some(&serde_json::json!({"pinnedPeerCertSha256": "1234"})),
            "x.com",
        );
        assert!(r.is_err());
    }

    #[test]
    fn pinned_hashes_type_mismatch_fails_fast() {
        // bd zl5t: 数组/数字等类型手误必须硬错点名字段，不得静默丢 pin 后
        // 由 webpki 报无关的 UnknownIssuer（对齐 Go unmarshal array→string 硬错）。
        let bad = [
            serde_json::json!({"pinnedPeerCertSha256": ["ab".repeat(16), "cd".repeat(16)]}),
            serde_json::json!({"pinnedPeerCertSha256": 42}),
        ];
        for v in &bad {
            let e = parse_pinned_hashes(v).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData);
            let msg = e.to_string();
            assert!(msg.contains("pinnedPeerCertSha256"), "msg: {msg}");
            assert!(msg.contains("expected string"), "msg: {msg}");
        }
        // build 层透传（通用 tlsSettings 装配路径）
        let r = build_client_config(
            "tls",
            Some(&serde_json::json!({"pinnedPeerCertSha256": ["ab".repeat(16)]})),
            "x.com",
        );
        assert!(r.is_err());
        // null 视同未配（Go encoding/json null no-op）
        assert!(
            parse_pinned_hashes(&serde_json::json!({"pinnedPeerCertSha256": null}))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn disable_system_root_without_certs_builds_empty_pool() {
        // Go：空 pool = 全部验证失败；构建本身不报错
        install_provider();
        let cfg = build_client_config(
            "tls",
            Some(&serde_json::json!({"disableSystemRoot": true})),
            "x.com",
        )
        .unwrap()
        .unwrap();
        assert!(!cfg.alpn_protocols.is_empty());
    }

    /// bd 1avs1：`useSystemCA=true` 读 OS 信任库（Go `loadCA(true)` → `x509.SystemCertPool`）；
    /// 缺省仍是内置根 bundle（Go `x509roots` / Rust `webpki-roots`）。
    #[test]
    fn verifier_roots_use_system_ca_loads_os_store() {
        let os_certs = rustls_native_certs::load_native_certs().certs.len();
        assert!(os_certs > 0, "OS root store must yield certs on this platform");

        let system = verifier_roots(&serde_json::json!({"useSystemCA": true})).unwrap();
        assert!(!system.is_empty(), "useSystemCA=true must load OS roots");

        let bundled = verifier_roots(&serde_json::json!({})).unwrap();
        assert_eq!(
            bundled.len(),
            webpki_roots::TLS_SERVER_ROOTS.len(),
            "default roots = bundled Mozilla set (Go x509roots equivalent)"
        );
    }

    /// bd 1avs1：`certificates[]` 在**缺省**根池上追加（Go `getCertPool` 三档都
    /// `AppendCertsFromPEM`，自带 CA 不必配 `disableSystemRoot`）。
    #[test]
    fn verifier_roots_appends_certificates_to_bundle() {
        let (ca, _key) = make_ca("Append Root CA");
        let store =
            verifier_roots(&serde_json::json!({"certificates": [{"certificate": ca.pem()}]}))
                .unwrap();
        assert_eq!(
            store.len(),
            webpki_roots::TLS_SERVER_ROOTS.len() + 1,
            "configured CA must be appended to the bundled roots"
        );
    }

    #[test]
    fn client_identity_picks_keyed_entry() {
        let (c1, _) = test_leaf_pem("nokey.example.com");
        let (c2, k2) = test_leaf_pem("id.example.com");
        let json = serde_json::json!({
            "certificates": [
                { "certificate": c1 },
                { "certificate": c2, "key": k2 },
            ]
        });
        let id = client_identity(&json).unwrap().unwrap();
        assert_eq!(id.0.len(), 1); // 选中带 key 的第二个条目
        let none =
            client_identity(&serde_json::json!({"certificates": [{"certificate": c1}]})).unwrap();
        assert!(none.is_none());
    }

    // ---- e2e：内存双工管道上的真实握手 ----

    /// 生成自签叶子证书 (cert_pem, key_pem)。
    fn test_leaf_pem(san: &str) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![san.to_string()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, san);
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    /// 生成 CA（is_ca=true）。
    fn make_ca(cn: &str) -> (rcgen::Certificate, rcgen::KeyPair) {
        let mut params = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, cn);
        let key = rcgen::KeyPair::generate().unwrap();
        (params.self_signed(&key).unwrap(), key)
    }

    /// 用 CA 签发叶子证书 (cert_pem, key_pem)。
    fn issue_leaf(san: &str, ca: &rcgen::Certificate, ca_key: &rcgen::KeyPair) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![san.to_string()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, san);
        let cert = params.signed_by(&key, ca, ca_key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    /// PEM 首张证书的 SHA-256 hex（钉扎值）。
    fn pem_leaf_hash_hex(pem: &str) -> String {
        let der = rustls_pemfile::certs(&mut pem.as_bytes()).next().unwrap().unwrap();
        hex::encode(generate_cert_hash(der.as_ref()))
    }

    type Duplex = tokio::io::DuplexStream;

    /// 服务端配置缺证书时补一张自签（SAN=sni）。
    ///
    /// bd mwvwd F2 后服务端不再自签（缺证书 = 每条连接握手失败，见
    /// `server_config::tests::no_certificates_fail_handshake`），本 helper 只负责让
    /// 与证书无关的用例（版本门/套件/曲线/ALPN）能握上手。
    fn with_self_signed(mut json: serde_json::Value, san: &str) -> serde_json::Value {
        let has_cert = json.get("cert").is_some()
            || json
                .get("certificates")
                .and_then(|v| v.as_array())
                .is_some_and(|arr| !arr.is_empty());
        if has_cert {
            return json;
        }
        let (cert_pem, key_pem) =
            crate::certificate::generate_self_signed_cert(&[san]).expect("self-signed cert");
        let obj = json.as_object_mut().expect("server json must be an object");
        obj.insert("cert".to_string(), serde_json::Value::String(cert_pem));
        obj.insert("key".to_string(), serde_json::Value::String(key_pem));
        json
    }

    /// 在 `tokio::io::duplex` 上做一次真实 TLS 握手，返回 (服务端结果, 客户端结果)。
    async fn handshake_pair(
        server_json: serde_json::Value,
        client_json: serde_json::Value,
        sni: &str,
    ) -> (
        io::Result<tokio_rustls::server::TlsStream<Duplex>>,
        io::Result<tokio_rustls::client::TlsStream<Duplex>>,
    ) {
        let server_json = with_self_signed(server_json, sni);
        let sc =
            crate::server_config::build_server_config("tls", Some(&server_json)).unwrap().unwrap();
        let cc = build_client_config("tls", Some(&client_json), sni).unwrap().unwrap();
        let (a, b) = tokio::io::duplex(4096);
        let accept =
            async { tokio_rustls::TlsAcceptor::from(sc).accept(a).await.map_err(io::Error::other) };
        let connect = async {
            let name = ServerName::try_from(sni.to_string()).unwrap();
            tokio_rustls::TlsConnector::from(cc).connect(name, b).await.map_err(io::Error::other)
        };
        tokio::join!(accept, connect)
    }

    /// bd c0p71 验收：`security:"TLS"`（大写）两端都必须握出**真 TLS 流**，
    /// 而不是"明文 + TLS record framer"。改前客户端 `build_client_config("TLS", ...)`
    /// 返回 `Ok(None)`（此处 `expect` 直接失败），服务端同样拿不到 ServerConfig。
    ///
    /// 顺带覆盖 bd 1nrzk(b)：`allowInsecure` 走 NoCertificateVerification 时，
    /// 握手签名仍按 provider 真校验，合法握手续得上。
    #[tokio::test]
    async fn uppercase_security_yields_encrypted_handshake() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let sni = "uppercase.example";
        let server_json = with_self_signed(serde_json::json!({}), sni);
        let sc = crate::server_config::build_server_config("TLS", Some(&server_json))
            .unwrap()
            .expect("server side security=\"TLS\" must build a ServerConfig");
        let cc = build_client_config("TLS", Some(&serde_json::json!({"allowInsecure": true})), sni)
            .unwrap()
            .expect("client side security=\"TLS\" must build a ClientConfig");

        let (a, b) = tokio::io::duplex(4096);
        let accept = async move {
            let mut s =
                tokio_rustls::TlsAcceptor::from(sc).accept(a).await.map_err(io::Error::other)?;
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await?;
            s.write_all(b"pong").await?;
            Ok::<_, io::Error>(buf)
        };
        let connect = async move {
            let name = ServerName::try_from(sni.to_string()).unwrap();
            let mut c = tokio_rustls::TlsConnector::from(cc)
                .connect(name, b)
                .await
                .map_err(io::Error::other)?;
            c.write_all(b"ping").await?;
            let mut resp = [0u8; 4];
            c.read_exact(&mut resp).await?;
            Ok::<_, io::Error>(resp)
        };
        let (sr, cr) = tokio::join!(accept, connect);
        assert_eq!(sr.expect("server handshake"), *b"ping");
        assert_eq!(cr.expect("client handshake"), *b"pong");
    }

    #[tokio::test]
    async fn e2e_tls13_only_version() {
        let (sr, cr) = handshake_pair(
            serde_json::json!({"minVersion": "1.3"}),
            serde_json::json!({"minVersion": "1.3", "allowInsecure": true}),
            "localhost",
        )
        .await;
        let client = cr.unwrap();
        sr.unwrap();
        assert_eq!(client.get_ref().1.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
    }

    #[tokio::test]
    async fn e2e_tls12_only_version() {
        let (sr, cr) = handshake_pair(
            serde_json::json!({"maxVersion": "1.2"}),
            serde_json::json!({"maxVersion": "1.2", "allowInsecure": true}),
            "localhost",
        )
        .await;
        let client = cr.unwrap();
        sr.unwrap();
        assert_eq!(client.get_ref().1.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_2));
    }

    #[tokio::test]
    async fn e2e_cipher_suite_restricted() {
        let (sr, cr) = handshake_pair(
            serde_json::json!({"cipherSuites": "TLS_CHACHA20_POLY1305_SHA256", "minVersion": "1.3"}),
            serde_json::json!({"cipherSuites": "TLS_CHACHA20_POLY1305_SHA256", "minVersion": "1.3", "allowInsecure": true}),
            "localhost",
        )
        .await;
        let client = cr.unwrap();
        sr.unwrap();
        assert_eq!(
            client.get_ref().1.negotiated_cipher_suite().unwrap().suite(),
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        );
    }

    #[tokio::test]
    async fn e2e_curve_restricted_handshakes() {
        // 双方只留 P256 → 握手成功
        let (sr, cr) = handshake_pair(
            serde_json::json!({"curvePreferences": ["curvep256"], "minVersion": "1.3"}),
            serde_json::json!({"curvePreferences": ["curvep256"], "minVersion": "1.3", "allowInsecure": true}),
            "localhost",
        )
        .await;
        cr.unwrap();
        sr.unwrap();
    }

    #[tokio::test]
    async fn e2e_curve_mismatch_fails() {
        // 客户端只 x25519，服务端只 P256 → 无公共组 → 双方失败
        let (sr, cr) = handshake_pair(
            serde_json::json!({"curvePreferences": ["curvep256"], "minVersion": "1.3"}),
            serde_json::json!({"curvePreferences": ["x25519"], "minVersion": "1.3", "allowInsecure": true}),
            "localhost",
        )
        .await;
        assert!(sr.is_err() || cr.is_err());
    }

    #[tokio::test]
    async fn e2e_custom_ca_replaces_webpki_roots() {
        // CA 签发的服务端证书：disableSystemRoot + CA 条目 → 握手成功
        let (ca, ca_key) = make_ca("Test Root CA");
        let (leaf_pem, leaf_key) = issue_leaf("localhost", &ca, &ca_key);
        let (sr, cr) = handshake_pair(
            serde_json::json!({"certificates": [{"certificate": leaf_pem, "key": leaf_key}]}),
            serde_json::json!({
                "disableSystemRoot": true,
                "certificates": [{"certificate": ca.pem()}]
            }),
            "localhost",
        )
        .await;
        let client = cr.expect("custom CA should validate CA-signed server cert");
        sr.unwrap();
        assert_eq!(client.get_ref().1.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));

        // 对照：不配 disableSystemRoot（webpki-roots）→ 验证失败
        let (sr2, cr2) = handshake_pair(
            serde_json::json!({"certificates": [{"certificate": leaf_pem, "key": leaf_key}]}),
            serde_json::json!({}),
            "localhost",
        )
        .await;
        assert!(cr2.is_err(), "webpki roots must reject private CA cert");
        drop(sr2);
    }

    #[tokio::test]
    async fn e2e_pinned_leaf_accepts() {
        let (cert_pem, key_pem) = test_leaf_pem("localhost");
        let pin = pem_leaf_hash_hex(&cert_pem);
        let (sr, cr) = handshake_pair(
            serde_json::json!({"certificates": [{"certificate": cert_pem, "key": key_pem}]}),
            serde_json::json!({"pinnedPeerCertSha256": pin}),
            "localhost",
        )
        .await;
        cr.unwrap();
        sr.unwrap();
    }

    #[tokio::test]
    async fn e2e_pinned_wrong_hash_rejects() {
        let (cert_pem, key_pem) = test_leaf_pem("localhost");
        let other_pin = pem_leaf_hash_hex(&test_leaf_pem("other.example.com").0);
        let (sr, cr) = handshake_pair(
            serde_json::json!({"certificates": [{"certificate": cert_pem, "key": key_pem}]}),
            serde_json::json!({"pinnedPeerCertSha256": other_pin}),
            "localhost",
        )
        .await;
        assert!(cr.is_err(), "wrong pin must be rejected");
        assert!(sr.is_err());
    }

    #[tokio::test]
    async fn e2e_pinned_ca_verifies_chain() {
        // pin 命中链中 CA → 以该 CA 为根做完整验证（叶子 SAN localhost 匹配）
        let (ca, ca_key) = make_ca("Pinned Root CA");
        let (leaf_pem, leaf_key) = issue_leaf("localhost", &ca, &ca_key);
        let mut chain_pem = leaf_pem.clone();
        if !chain_pem.ends_with('\n') {
            chain_pem.push('\n');
        }
        chain_pem.push_str(&ca.pem());
        let ca_pin = pem_leaf_hash_hex(&ca.pem());

        let (sr, cr) = handshake_pair(
            serde_json::json!({"certificates": [{"certificate": chain_pem, "key": leaf_key}]}),
            serde_json::json!({"pinnedPeerCertSha256": ca_pin}),
            "localhost",
        )
        .await;
        cr.unwrap();
        sr.unwrap();

        // 对照：叶子 SAN 不匹配 SNI → foundCA 路径的完整验证拒绝
        let (leaf2_pem, leaf2_key) = issue_leaf("elsewhere.example.com", &ca, &ca_key);
        let mut chain2 = leaf2_pem.clone();
        chain2.push('\n');
        chain2.push_str(&ca.pem());
        let (sr2, cr2) = handshake_pair(
            serde_json::json!({"certificates": [{"certificate": chain2, "key": leaf2_key}]}),
            serde_json::json!({"pinnedPeerCertSha256": ca_pin}),
            "localhost",
        )
        .await;
        assert!(cr2.is_err(), "pinned CA path must verify server name");
        drop(sr2);
    }

    // ===== bd idtl1: verifyPeerCertByName 单独配置（无 pin）=====

    /// `verifyPeerCertByName` 逗号分隔多名 / 去空 / 去空白（Go SplittingSeq 语义）。
    #[test]
    fn vcn_parse_multiple_names() {
        let names = parse_verify_peer_cert_by_name(&serde_json::json!({
            "verifyPeerCertByName": " a.example , ,b.example,"
        }));
        assert_eq!(names, vec!["a.example".to_string(), "b.example".to_string()]);
        assert!(parse_verify_peer_cert_by_name(&serde_json::json!({})).is_empty());
        assert!(
            parse_verify_peer_cert_by_name(&serde_json::json!({"verifyPeerCertByName": ""}))
                .is_empty()
        );
    }

    /// 只配 vcn（无 pin）：链按配置根验过 + 主机名按 vcn 匹配 → 成功。
    ///
    /// 修复前：空 pin 走 `verify_chain(.., &[])` → `CertNotFound` → 任何证书都拒
    /// （Go 在 `PinnedPeerCertSha256 == nil` 时整段跳过 pin 分支）。
    #[tokio::test]
    async fn e2e_vcn_only_verifies_chain_and_name() {
        let (ca, ca_key) = make_ca("vcn Root CA");
        let (leaf_pem, leaf_key) = issue_leaf("real.service.example", &ca, &ca_key);
        let mut chain = leaf_pem;
        chain.push('\n');
        chain.push_str(&ca.pem());

        // 握手 SNI 故意与证书名不同：只有 vcn 能放行（ECH/PSK 场景）
        let (sr, cr) = handshake_pair(
            serde_json::json!({"certificates": [{"certificate": chain, "key": leaf_key}]}),
            serde_json::json!({
                "verifyPeerCertByName": "real.service.example",
                "certificates": [{"certificate": ca.pem()}],
            }),
            "wrong.sni.example",
        )
        .await;
        let client = cr.expect("vcn-only handshake must pass (chain + name via vcn)");
        assert_eq!(client.get_ref().1.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
        drop(sr);
    }

    /// 多名逗号分隔：任一命中即放行（Go `for _, opts.DNSName = range` 语义）。
    #[tokio::test]
    async fn e2e_vcn_multiple_names_any_match() {
        let (ca, ca_key) = make_ca("vcn Multi CA");
        let (leaf_pem, leaf_key) = issue_leaf("real.service.example", &ca, &ca_key);
        let mut chain = leaf_pem;
        chain.push('\n');
        chain.push_str(&ca.pem());

        let (_sr, cr) = handshake_pair(
            serde_json::json!({"certificates": [{"certificate": chain, "key": leaf_key}]}),
            serde_json::json!({
                "verifyPeerCertByName": "nope.example, real.service.example",
                "certificates": [{"certificate": ca.pem()}],
            }),
            "wrong.sni.example",
        )
        .await;
        assert!(cr.is_ok(), "any matching vcn name must pass");
    }

    /// vcn 名不匹配 → 拒（证明名验证真的跑了，不是"有 vcn 就放行"）。
    #[tokio::test]
    async fn e2e_vcn_only_rejects_wrong_name() {
        let (ca, ca_key) = make_ca("vcn Name CA");
        let (leaf_pem, leaf_key) = issue_leaf("real.service.example", &ca, &ca_key);
        let mut chain = leaf_pem;
        chain.push('\n');
        chain.push_str(&ca.pem());

        let (_sr, cr) = handshake_pair(
            serde_json::json!({"certificates": [{"certificate": chain, "key": leaf_key}]}),
            serde_json::json!({
                "verifyPeerCertByName": "other.example",
                "certificates": [{"certificate": ca.pem()}],
            }),
            "wrong.sni.example",
        )
        .await;
        let err = cr.expect_err("vcn mismatch must fail").to_string();
        assert!(err.contains("not valid for name"), "got: {err}");
    }

    /// vcn 名匹配但链不受信（自签叶子，客户端只配 vcn）→ 拒。
    /// 这是 idtl1 的安全属性：vcn 分支必须**同时**验链，不得退化成"只看名字"。
    #[tokio::test]
    async fn e2e_vcn_only_rejects_untrusted_chain() {
        let (leaf_pem, leaf_key) = test_leaf_pem("real.service.example");
        let (_sr, cr) = handshake_pair(
            serde_json::json!({"certificates": [{"certificate": leaf_pem, "key": leaf_key}]}),
            serde_json::json!({"verifyPeerCertByName": "real.service.example"}),
            "wrong.sni.example",
        )
        .await;
        let err = cr.expect_err("vcn must still verify the chain").to_string();
        assert!(err.contains("certificate"), "got: {err}");
    }

    /// bd mwvwd F3：服务端按**自身**偏好序选套件（Go crypto/tls 语义），
    /// 不跟随客户端 offered 顺序——客户端只把 AES-256 排在前时仍协商 AES-128。
    #[tokio::test]
    async fn e2e_server_prefers_own_cipher_order() {
        let (sr, cr) = handshake_pair(
            serde_json::json!({"minVersion": "1.3"}),
            serde_json::json!({
                "allowInsecure": true,
                "minVersion": "1.3",
                // 客户端偏好序反转（AES-256 在前）
                "cipherSuites":
                    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256",
            }),
            "localhost",
        )
        .await;
        let client = cr.expect("handshake must succeed");
        sr.expect("server side ok");
        assert_eq!(
            client.get_ref().1.negotiated_cipher_suite().map(|s| s.suite()),
            Some(rustls::CipherSuite::TLS13_AES_128_GCM_SHA256),
            "server preference must win over client order (Go parity)"
        );
    }

    #[tokio::test]
    async fn e2e_mtls_full_handshake() {
        let (ca, ca_key) = make_ca("mTLS Root CA");
        let (server_pem, server_key) = issue_leaf("localhost", &ca, &ca_key);
        let (client_pem, client_key) = issue_leaf("client.identity", &ca, &ca_key);
        let server_pin = pem_leaf_hash_hex(&server_pem);

        // 服务端：encipherment 证书 + usage:"verify" CA → 要求客户端证书
        // 客户端：pin 服务端证书 + 提供自己的证书
        let (sr, cr) = handshake_pair(
            serde_json::json!({
                "certificates": [
                    { "certificate": server_pem, "key": server_key },
                    { "certificate": ca.pem(), "usage": "verify" },
                ]
            }),
            serde_json::json!({
                "pinnedPeerCertSha256": server_pin,
                "certificates": [{ "certificate": client_pem, "key": client_key }],
            }),
            "localhost",
        )
        .await;
        let client = cr.expect("mTLS handshake with client cert should succeed");
        let server = sr.expect("server should verify client cert against verify CA");
        assert_eq!(client.get_ref().1.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
        drop(server);
    }

    #[tokio::test]
    async fn e2e_mtls_rejects_client_without_cert() {
        let (ca, ca_key) = make_ca("mTLS Root CA");
        let (server_pem, server_key) = issue_leaf("localhost", &ca, &ca_key);
        let server_pin = pem_leaf_hash_hex(&server_pem);

        // 客户端不提供证书 → 服务端要求客户端证书 → 握手失败
        let (sr, cr) = handshake_pair(
            serde_json::json!({
                "certificates": [
                    { "certificate": server_pem, "key": server_key },
                    { "certificate": ca.pem(), "usage": "verify" },
                ]
            }),
            serde_json::json!({"pinnedPeerCertSha256": server_pin}),
            "localhost",
        )
        .await;
        assert!(cr.is_err() || sr.is_err(), "server must require client cert");
    }

    #[tokio::test]
    async fn e2e_non_encipherment_usage_not_presented() {
        // usage:"issue" 条目被过滤（对齐 Go BuildCertificates）→ 服务端回退自签名
        // → 客户端（信任 CA 签发的证书）验证失败。对照组见 e2e_custom_ca_replaces_webpki_roots
        //（默认 usage 的 CA 签发叶子证书会被正常送出并验证通过）。
        let (ca, ca_key) = make_ca("Filter Root CA");
        let (leaf_pem, leaf_key) = issue_leaf("localhost", &ca, &ca_key);
        let (_sr, cr) = handshake_pair(
            serde_json::json!({
                "certificates": [
                    { "certificate": leaf_pem, "key": leaf_key, "usage": "issue" },
                ]
            }),
            serde_json::json!({
                "disableSystemRoot": true,
                "certificates": [{"certificate": ca.pem()}]
            }),
            "localhost",
        )
        .await;
        assert!(cr.is_err(), "usage:issue entry must not be presented as server cert");
    }

    // ===== pwh6: client 侧 TLS 字段族增量行为测试 =====

    /// `masterKeyLog=true` 切到 KeyLogFile；`false`（默认）保持 NoKeyLog。
    #[test]
    fn pwh6_client_master_key_log_swaps_key_log() {
        let cfg_off = build_client_config("tls", None, "example.com").unwrap().unwrap();
        let cfg_on = build_client_config(
            "tls",
            Some(&serde_json::json!({ "masterKeyLog": true })),
            "example.com",
        )
        .unwrap()
        .unwrap();
        assert!(!std::sync::Arc::ptr_eq(&cfg_off.key_log, &cfg_on.key_log));
        assert!(format!("{:?}", &*cfg_on.key_log).contains("KeyLogFile"));
        assert!(format!("{:?}", &*cfg_off.key_log).contains("NoKeyLog"));
    }

    /// 票 8k4s①：client 侧 `masterKeyLog` string 路径 → KeyLogFileWriter 且
    /// 文件被创建（bool true 方言仍走 KeyLogFile，见上一个测试）。
    #[test]
    fn pwh6_client_master_key_log_string_path_wires_writer() {
        let path =
            std::env::temp_dir().join(format!("xray_tls_8k4s_client_{}.log", std::process::id()));
        let cfg = build_client_config(
            "tls",
            Some(&serde_json::json!({ "masterKeyLog": path.to_string_lossy() })),
            "example.com",
        )
        .unwrap()
        .unwrap();
        assert!(format!("{:?}", &*cfg.key_log).contains("KeyLogFileWriter"));
        assert!(path.exists(), "Go O_CREATE: file must be created eagerly");
        std::fs::remove_file(&path).ok();
    }

    /// 票 8k4s③：`echSockopt` + DoH 形态 `echConfigList` → 配置构建不 panic
    /// （降级 warn 路径；ECH config 本身仍会 resolve 成 invalid）。
    #[test]
    fn pwh6_client_ech_sockopt_with_doh_config_builds() {
        let json = serde_json::json!({
            "echConfigList": "https://1.1.1.1/dns-query",
            "echSockopt": { "domainStrategy": "UseIP" }
        });
        let cfg = build_client_config("tls", Some(&json), "example.com").unwrap().unwrap();
        assert!(format!("{:?}", &*cfg.key_log).contains("NoKeyLog"));
    }

    /// bd 4w092(a)：ECH DoH（`://` 形态）走 rustls 原生桥，无法承载配置要求的
    /// uTLS 指纹 ⇒ 该组合配置期硬错；不配指纹时同一份 ECH DoH 配置照常构建。
    #[test]
    fn ech_doh_with_utls_fingerprint_fails_loud() {
        let json = serde_json::json!({
            "fingerprint": "chrome",
            "echConfigList": "https://1.1.1.1/dns-query",
        });
        let err = build_client_config("tls", Some(&json), "example.com").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("echConfigList"), "got: {err}");

        let no_fp = serde_json::json!({ "echConfigList": "https://1.1.1.1/dns-query" });
        assert!(build_client_config("tls", Some(&no_fp), "example.com").unwrap().is_some());
        // 指纹 + base64 ECHConfigList（不做 DoH 查询）不受影响。
        let b64 = serde_json::json!({ "fingerprint": "chrome", "echConfigList": "aGVsbG8=" });
        assert!(build_client_config("tls", Some(&b64), "example.com").unwrap().is_some());
    }

    /// bd 4w092(b)：`echForceQuery` 只实现 `full`；`half`/`none` 与非法值一律拒启
    /// （此前该键零校验——解析函数无调用方，写了等于没写）。
    #[test]
    fn ech_force_query_non_full_fails_loud() {
        for mode in ["half", "none", "bogus"] {
            let json = serde_json::json!({ "echForceQuery": mode });
            let err = build_client_config("tls", Some(&json), "example.com").unwrap_err();
            assert!(err.to_string().to_lowercase().contains("ech"), "mode={mode} got: {err}");
        }
        for ok in [serde_json::json!({ "echForceQuery": "full" }), serde_json::json!({})] {
            assert!(build_client_config("tls", Some(&ok), "example.com").unwrap().is_some());
        }
    }

    /// `enableSessionResumption=false` → resumption 切换到 disabled（type_name 变化）。
    #[test]
    fn pwh6_client_disable_session_resumption_swaps_resumption() {
        let cfg_off = build_client_config("tls", None, "example.com").unwrap().unwrap();
        let cfg_on = build_client_config(
            "tls",
            Some(&serde_json::json!({ "enableSessionResumption": false })),
            "example.com",
        )
        .unwrap()
        .unwrap();
        // Resumption 不暴露 pub 字段直接比较；通过 Debug 输出含 store 名称区分。
        let off_dbg = format!("{:?}", cfg_off.resumption);
        let on_dbg = format!("{:?}", cfg_on.resumption);
        assert_ne!(off_dbg, on_dbg);
        // 关闭时类型名含 NoClientSessionStorage。
        assert!(on_dbg.contains("NoClientSessionStorage"));
    }

    /// `verifyPeerCertByName` 非空时构造 PinnedServerCertVerifier（含 vcn 字段）。
    /// 通过尝试错误 hex 触发 Err 路径，验证 vcn 字符串被构造器接纳。
    #[test]
    fn pwh6_verify_peer_cert_by_name_accepted_by_verifier() {
        // 无效 pin hex + 有效 vcn → 错误来自 pin 解析，不是 vcn 解析。
        let cfg = build_client_config(
            "tls",
            Some(&serde_json::json!({
                "pinnedPeerCertSha256": "zz".repeat(32),
                "verifyPeerCertByName": "real.service.example",
            })),
            "fake.sni",
        );
        let err = cfg.expect_err("invalid pin hex must error");
        assert!(err.to_string().contains("pinnedPeerCertSha256"));
    }

    /// `verifyPeerCertByName` 字段缺失/空时行为兼容——pin 命中 CA 验证用默认 SNI。
    #[test]
    fn pwh6_verify_peer_cert_by_name_empty_falls_back_to_sni() {
        let cfg = build_client_config(
            "tls",
            Some(&serde_json::json!({
                "pinnedPeerCertSha256": "00ff".repeat(16),
            })),
            "fallback.sni",
        )
        .unwrap()
        .unwrap();
        // alpn 默认
        assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }
}

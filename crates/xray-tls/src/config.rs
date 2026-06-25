//! TLS 配置层的纯逻辑部分。
//!
//! 翻译自 Go `transport/internet/tls/config.go`。
//!
//! # 范围
//! 本模块只翻译**不涉及实际 TLS 握手与 x509 证书加载**的纯逻辑：
//! - 椭圆曲线名称 ↔ CurveID 映射
//! - MITM 来源判定（`IsFromMitm`）
//! - 证书链钉扎验证（`verify_chain`/`VerifyResult`）
//! - `Option` 函数模式（`WithDestination`/`WithOverrideName`/`WithNextProto`）
//! - `RandCarrier` 数据结构（不含实际 `rand.Read` 实现）
//!
//! 实际 `GetTLSConfig` 组装 `rustls::ClientConfig`、x509 加载、OCSP
//! ticker 等 IO 逻辑未翻译——等接入 rustls 后再添加。

use subtle::ConstantTimeEq;

// ============================================================
// CurveId 与 ParseCurveName
// ============================================================

/// TLS 椭圆曲线标识。
///
/// 对应 Go 的 `tls.CurveID`。Rust 端只保留业务用到的取值（包含
/// 后量子混合密钥交换，如 Go 1.24 新增的 X25519MLKEM768）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurveId {
    /// Go `tls.CurveP256` / SECG secp256r1。
    P256,
    /// Go `tls.CurveP384` / SECG secp384r1。
    P384,
    /// Go `tls.CurveP521` / SECG secp521r1。
    P521,
    /// Go `tls.X25519` / RFC 7748。
    X25519,
    /// Go `tls.X25519MLKEM768`（后量子混合，RFC 9180）。
    X25519Mlkem768,
    /// Go `tls.SecP256r1MLKEM768`。
    SecP256r1Mlkem768,
    /// Go `tls.SecP384r1MLKEM1024`。
    SecP384r1Mlkem1024,
}

/// 按名查 CurveId。
///
/// 对应 Go `ParseCurveName`，接受大小写不敏感的曲线名称。
/// 未知名称返回 `None`（与 Go 一样仅记 warning 后跳过）--上层不需在此处报错。
///
/// # 示例
/// ```
/// use xray_tls::config::{parse_curve_name, CurveId};
/// assert_eq!(parse_curve_name("curvep256"), Some(CurveId::P256));
/// assert_eq!(parse_curve_name("X25519"), Some(CurveId::X25519));
/// assert_eq!(parse_curve_name("unknown"), None);
/// ```
pub fn parse_curve_name(name: &str) -> Option<CurveId> {
    let curve = match name.to_ascii_lowercase().as_str() {
        "curvep256" => CurveId::P256,
        "curvep384" => CurveId::P384,
        "curvep521" => CurveId::P521,
        "x25519" => CurveId::X25519,
        "x25519mlkem768" => CurveId::X25519Mlkem768,
        "secp256r1mlkem768" => CurveId::SecP256r1Mlkem768,
        "secp384r1mlkem1024" => CurveId::SecP384r1Mlkem1024,
        _ => return None,
    };
    Some(curve)
}

// ============================================================
// MITM 判定
// ============================================================

/// 判定 ServerName 是否来自 MITM 环境标记（字符串 "frommitm"，大小写不敏感）。
///
/// 对应 Go `IsFromMitm`。用于 `parse_server_name` 时清零此类标记。
///
/// # 示例
/// ```
/// use xray_tls::config::is_from_mitm;
/// assert!(is_from_mitm("frommitm"));
/// assert!(is_from_mitm("FromMITM"));
/// assert!(!is_from_mitm("example.com"));
/// ```
pub fn is_from_mitm(s: &str) -> bool {
    s.eq_ignore_ascii_case("frommitm")
}

// ============================================================
// 证书链钉扎验证
// ============================================================

/// `verify_chain` 的返回值。
///
/// 对应 Go `verifyResult` iota 常量。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyResult {
    /// peer 证书不在 pinned hash 列表中。
    CertNotFound,
    /// peer **叶子**证书匹配某个 pinned hash。
    FoundLeaf,
    /// peer **中间**证书匹配某个 pinned hash 且该证书是 CA。
    FoundCa,
}

/// 证书链钉扎验证。
///
/// 对应 Go `verifyChain(certs, pinnedPeerCertSha256)`。
///
/// # 算法
/// 1. 计算叶子证书（`certs[0]`）的 SHA-256，与 pinned hashes 在恒等时间内比对。
///    命中 → 返回 `(FoundLeaf, None)`。
/// 2. 遍历中间证书（`certs[1..]`），命中任一 pinned hash 且该证书 `is_ca=true` 时
///    返回 `(FoundCa, Some(cert_index))`。
/// 3. 未命中返回 `(CertNotFound, None)`。
///
/// # 参数
/// - `cert_hashes`：peer 证书链中每个证书的 SHA-256（`generate_cert_hash` 计算结果）。
/// - `cert_is_ca`：与 `cert_hashes` 同长，标记每个证书是否为 CA。**叶子位忽略**。
/// - `pinned_hashes`：配置中 `pinned_peer_cert_sha256` 字段展开后的 32 字节 hash 列表。
///
/// # 返回
/// `(VerifyResult, Option<usize>)`——后者仅在 `FoundCa` 时为命中证书的索引。
///
/// # panic
/// `cert_hashes` 为空时会 panic（与 Go 一致：`certs[0]` 超界）。
pub fn verify_chain(
    cert_hashes: &[Vec<u8>],
    cert_is_ca: &[bool],
    pinned_hashes: &[Vec<u8>],
) -> (VerifyResult, Option<usize>) {
    debug_assert_eq!(
        cert_hashes.len(),
        cert_is_ca.len(),
        "cert_hashes / cert_is_ca length mismatch"
    );

    // 叶子匹配（index 0）
    let leaf_hash = &cert_hashes[0];
    for pinned in pinned_hashes {
        if ct_eq_slices(leaf_hash, pinned) {
            return (VerifyResult::FoundLeaf, None);
        }
    }

    // 中间证书匹配（需同时是 CA）
    for (idx, (hash, is_ca)) in cert_hashes[1..]
        .iter()
        .zip(cert_is_ca[1..].iter())
        .enumerate()
    {
        // 注意：原始索引 = idx + 1（跳过叶子）
        let original_idx = idx + 1;
        if !*is_ca {
            continue;
        }
        for pinned in pinned_hashes {
            if ct_eq_slices(hash, pinned) {
                return (VerifyResult::FoundCa, Some(original_idx));
            }
        }
    }

    (VerifyResult::CertNotFound, None)
}

/// `subtle::ConstantTimeEq` 需要 `&[u8]` 且长度需相等。
/// 此包装层允许长度不等时安全返回 false（与 Go `hmac.Equal` 一致：长度不等返回 false）。
fn ct_eq_slices(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

// ============================================================
// Option 函数模式
// ============================================================

/// TLS 配置可变修改器。
///
/// 对应 Go 的 `type Option func(*tls.Config)`。
///
/// Rust 端抽象为 trait，实际修改逻辑由具体配置类型（未来 `rustls::ClientConfig`
/// 或 `TlsConfigBuilder`）实现。本 trait 留作类型上限——具体实现等接入 rustls 后添加。
pub trait TlsConfigOption {
    /// 应用该选项到目标配置。
    fn apply(self, config: &mut dyn TlsConfigTarget);
}

/// `Option` 函数能修改的目标。
///
/// 留作占位——等 `rustls` 接入后由 `TlsConfigBuilder` 实现。
pub trait TlsConfigTarget {
    fn set_server_name(&mut self, name: &str);
    fn set_next_protos(&mut self, protos: Vec<String>);
}

/// 以 destination 设置 ServerName（如果未显式设置）。
///
/// 对应 Go `WithDestination(dest net.Destination)`。
pub struct WithDestination<'a> {
    pub dest_address: &'a str,
}

/// 显式覆盖 ServerName。
///
/// 对应 Go `WithOverrideName(serverName string)`。
pub struct WithOverrideName<'a> {
    pub server_name: &'a str,
}

/// 设置 ALPN 协议列表（仅当未显式设置时）。
///
/// 对应 Go `WithNextProto(protocol ...string)`。
pub struct WithNextProto<'a> {
    pub protocols: &'a [&'a str],
}

// 由于 `TlsConfigTarget` 实现待 rustls 接入，这里不展开 `TlsConfigOption` 的 impl，
// 仅提供数据结构 + trait。业务逻辑（条件设置）留在 trait 实现侧完成，避免提前硬编码
// 错误的配置抽象。

// ============================================================
// RandCarrier 数据结构
// ============================================================

/// TLS 随机源携带体。
///
/// 对应 Go `RandCarrier struct`。该结构在 Go 端同时实现 `io.Reader`
/// 和承载 `VerifyPeerCertificate` 回调；Rust 端只保留**数据载体**
/// （字段不含业务行为，仅承载状态），具体 rand 生成与证书验证等业务方法
/// 等接入 rustls 后实现。
#[derive(Debug, Clone, Default)]
pub struct RandCarrier {
    /// 待验证的 peer 证书名列表（`verify_peer_cert_by_name`）。
    pub verify_peer_cert_by_name: Vec<String>,
    /// pinned 证书 SHA-256 hash 列表（`pinned_peer_cert_sha256`）。
    pub pinned_peer_cert_sha256: Vec<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_curve_name ----

    #[test]
    fn parse_curve_name_all_known() {
        assert_eq!(parse_curve_name("curvep256"), Some(CurveId::P256));
        assert_eq!(parse_curve_name("curvep384"), Some(CurveId::P384));
        assert_eq!(parse_curve_name("curvep521"), Some(CurveId::P521));
        assert_eq!(parse_curve_name("x25519"), Some(CurveId::X25519));
        assert_eq!(
            parse_curve_name("x25519mlkem768"),
            Some(CurveId::X25519Mlkem768)
        );
        assert_eq!(
            parse_curve_name("secp256r1mlkem768"),
            Some(CurveId::SecP256r1Mlkem768)
        );
        assert_eq!(
            parse_curve_name("secp384r1mlkem1024"),
            Some(CurveId::SecP384r1Mlkem1024)
        );
    }

    #[test]
    fn parse_curve_name_case_insensitive() {
        // 与 Go 一样按 lowercase 后匹配
        assert_eq!(parse_curve_name("CURVEP256"), Some(CurveId::P256));
        assert_eq!(parse_curve_name("X25519"), Some(CurveId::X25519));
        assert_eq!(parse_curve_name("X25519MLKEM768"), Some(CurveId::X25519Mlkem768));
    }

    #[test]
    fn parse_curve_name_unknown() {
        assert_eq!(parse_curve_name("unknown"), None);
        assert_eq!(parse_curve_name(""), None);
    }

    // ---- is_from_mitm ----

    #[test]
    fn is_from_mitm_recognizes_variants() {
        assert!(is_from_mitm("frommitm"));
        assert!(is_from_mitm("FromMITM"));
        assert!(is_from_mitm("FROMMITM"));
        assert!(!is_from_mitm("example.com"));
        assert!(!is_from_mitm(""));
        assert!(!is_from_mitm("frommitm.com"));
    }

    // ---- verify_chain ----

    fn hash_of(bytes: &[u8]) -> Vec<u8> {
        crate::pin::generate_cert_hash(bytes)
    }

    #[test]
    fn verify_chain_empty_pinned_returns_not_found() {
        let leaf = hash_of(b"leaf");
        let result = verify_chain(&[leaf], &[false], &[]);
        assert_eq!(result, (VerifyResult::CertNotFound, None));
    }

    #[test]
    fn verify_chain_leaf_match() {
        let leaf = hash_of(b"leaf");
        let pinned = vec![leaf.clone()];
        let result = verify_chain(&[leaf], &[false], &pinned);
        assert_eq!(result, (VerifyResult::FoundLeaf, None));
    }

    #[test]
    fn verify_chain_ca_match_returns_index() {
        let leaf = hash_of(b"leaf");
        let intermediate = hash_of(b"intermediate");
        let root = hash_of(b"root");
        let pinned = vec![intermediate.clone()];
        // is_ca: leaf=false, intermediate=true, root=true
        let result = verify_chain(
            &[leaf, intermediate, root],
            &[false, true, true],
            &pinned,
        );
        // 中间证书 index=1
        assert_eq!(result, (VerifyResult::FoundCa, Some(1)));
    }

    #[test]
    fn verify_chain_ca_match_but_not_ca_skipped() {
        // 叶子匹配检查只看 leaf，中间非 CA 证书即使 hash 匹配也跳过
        let leaf = hash_of(b"leaf");
        let not_ca = hash_of(b"intermediate-no-ca");
        let pinned = vec![not_ca.clone()];
        let result = verify_chain(&[leaf, not_ca], &[false, false], &pinned);
        assert_eq!(result, (VerifyResult::CertNotFound, None));
    }

    #[test]
    fn verify_chain_multiple_pinned_first_match_wins() {
        let leaf = hash_of(b"leaf");
        let other = hash_of(b"other");
        let pinned = vec![other, leaf.clone()];
        let result = verify_chain(&[leaf], &[false], &pinned);
        assert_eq!(result, (VerifyResult::FoundLeaf, None));
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn verify_chain_empty_chain_panics_like_go() {
        // 与 Go certs[0] 越界一致
        let _ = verify_chain(&[], &[], &[]);
    }

    // ---- RandCarrier ----

    #[test]
    fn rand_carrier_default_empty() {
        let rc = RandCarrier::default();
        assert!(rc.verify_peer_cert_by_name.is_empty());
        assert!(rc.pinned_peer_cert_sha256.is_empty());
    }
}

// ct_eq_slices 在测试中需暴露给 verify_chain，不需额外测试。

//! REALITY 工具函数。
//!
//! 翻译自 Go `transport/internet/reality/` 中两个不依赖 uTLS 的纯函数：
//! - `KeyLogWriterFromConfig`：master key log 文件打开
//! - `getPathLocked`：从路径集合中选一条（spider 模式 fallback）

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::path::Path;

/// 打开 master key log 文件。
///
/// 对应 Go `KeyLogWriterFromConfig`。行为：
/// - `path` 为空或 `"none"` → 返回 `None`（不记录）
/// - 否则以「创建/读写/追加」模式打开（Go 端 `O_CREATE|O_RDWR|O_APPEND`，权限 0644）
///
/// 与 Go 端一致：打开失败返回 `None`（Go 端仅记日志不传播错误），调用方
/// 在后续 TLS 握手时仍能正常工作（只是缺少 key log）。
pub fn open_key_log_writer<P: AsRef<Path>>(path: P) -> Option<std::fs::File> {
    let p = path.as_ref();
    let s = p.to_string_lossy();
    if s.is_empty() || s == "none" {
        return None;
    }
    OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(p)
        .ok()
}

/// spider 模式从路径集合中选一条。
///
/// 对应 Go `getPathLocked(paths)`。Go 端用 `crypto.RandBetween(0, len-1)`
/// 随机选 index；本实现不引 `rand` 依赖（避免在配置层加 RNG 源），用
/// `paths.iter().next()` 取 HashMap 迭代序的首项作为确定性 fallback。
///
/// 真正的随机选择等接入 [`xray_crypto`] 的 rand 等价品后替换；当前确定性
/// 选择对 REALITY 握手业务无影响（spider 模式仅在 fallback 路径触发）。
///
/// # 参数
/// - `paths`：已收集的路径集合（由 spider crawler 维护）
///
/// # 返回
/// 选中的路径；集合为空时返回 `"/"`（与 Go 端 fallthrough 一致）
pub fn get_path_locked<'a>(paths: &'a HashMap<String, ()>) -> &'a str {
    // ponytail: deterministic for now; random selection deferred to xray_crypto
    // rand_between once RNG plumbing lands.
    paths.keys().next().map(String::as_str).unwrap_or("/")
}

/// 在 X.509 证书 DER 中定位 OID 0.0 扩展（`06 01 00`）的 extnValue 内容。
///
/// REALITY 10.0 mldsa65 变体证书的唯一保留扩展（Go
/// `pkix.Extension{Id: []int{0, 0}, Value: empty[:3309]}`；Rust 侧
/// `mitm::build_dummy_cert` 同构生成）。返回 `(value_offset, value_len)`，
/// value_offset 指向 OCTET STRING 内容首字节（Go `cert[126:]` / 服务端签名
/// 写入点 / 客户端签名提取点共用）。
///
/// 为何模式匹配而非完整 DER 解析：REALITY 证书是本 crate 生成的极简模板
/// （空 subject、无 SAN、单扩展），OID 0.0 是保留值、在任何合法证书扩展链
/// 中不可能出现第二次；签名算法 OID（ed25519）与 0.0 无前缀重叠。
pub fn find_oid_0_0_extension(cert_der: &[u8]) -> Option<(usize, usize)> {
    const OID_0_0: [u8; 3] = [0x06, 0x01, 0x00];
    let mut from = 0usize;
    while from + OID_0_0.len() <= cert_der.len() {
        let Some(rel) = cert_der[from..].windows(OID_0_0.len()).position(|w| w == OID_0_0)
        else {
            return None;
        };
        // extnID 之后紧跟 extnValue = OCTET STRING（tag 0x04）
        let v = from + rel + OID_0_0.len();
        if v < cert_der.len() && cert_der[v] == 0x04 {
            if let Some((len, hdr)) = der_len_at(cert_der, v + 1) {
                let off = v + 1 + hdr;
                if off + len <= cert_der.len() {
                    return Some((off, len));
                }
            }
        }
        from = v;
    }
    None
}

/// 解析 `off` 处的 DER 长度字段，返回 `(value_len, header_len)`。
///
/// 仅支持 DER 规范形式（short form < 0x80；long form 首字节 = 后续字节数）。
fn der_len_at(buf: &[u8], off: usize) -> Option<(usize, usize)> {
    let first = *buf.get(off)?;
    if first < 0x80 {
        return Some((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || off + 1 + n > buf.len() {
        return None;
    }
    let mut len = 0usize;
    for &b in &buf[off + 1..off + 1 + n] {
        len = (len << 8) | b as usize;
    }
    Some((len, 1 + n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_key_log_writer_empty_returns_none() {
        assert!(open_key_log_writer("").is_none());
    }

    #[test]
    fn open_key_log_writer_none_literal_returns_none() {
        assert!(open_key_log_writer("none").is_none());
    }

    #[test]
    fn open_key_log_writer_creates_file() {
        let path = std::env::temp_dir().join(format!(
            "xray_reality_test_{}.keylog",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let f = open_key_log_writer(&path);
        assert!(f.is_some(), "should create file");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn get_path_locked_empty_returns_root() {
        let paths = HashMap::new();
        assert_eq!(get_path_locked(&paths), "/");
    }

    #[test]
    fn get_path_locked_non_empty_returns_member() {
        let mut paths = HashMap::new();
        paths.insert("/foo".to_string(), ());
        paths.insert("/bar".to_string(), ());
        let p = get_path_locked(&paths);
        // 确定性版本：必在集合内（具体取首项由 HashMap 迭代序决定）
        assert!(p == "/foo" || p == "/bar");
    }

    /// cm97：OID 0.0 扩展定位——在真实 mldsa65 变体证书上定位 value 区，
    /// 标准模板（无扩展）返回 None。
    #[test]
    fn find_oid_0_0_extension_on_reality_certs() {
        let auth_key = [0x42u8; 32];
        let (var_cert, _) = crate::mitm::generate_reality_ed25519_cert_mldsa65(
            &auth_key,
            &[1u8; 8],
            &[2u8; 8],
            &[0x07u8; 32],
        )
        .unwrap();
        let (off, len) = find_oid_0_0_extension(&var_cert).expect("variant must carry extension");
        assert_eq!(len, crate::crypto::MLDSA65_SIG_LEN);
        // 签名前 value 区应全零（模板预留区未被覆盖的场景不会出现——生成器
        // 恒写签名；这里验证的是定位而非内容，仅确认区间在 DER 内）
        assert!(off + len <= var_cert.len());

        let (std_cert, _) = crate::mitm::generate_reality_ed25519_cert(&auth_key).unwrap();
        assert!(find_oid_0_0_extension(&std_cert).is_none());
    }

    /// DER 长度解析：short form 与 long form（3309 = 0x0CED → 82 0C ED）。
    #[test]
    fn der_len_at_short_and_long_forms() {
        assert_eq!(der_len_at(&[0x05, 1, 2, 3, 4, 5], 0), Some((5, 1)));
        // long form: 0x82 = 2 字节长度头
        let buf = [0x82, 0x0c, 0xed];
        assert_eq!(der_len_at(&buf, 0), Some((3309, 3)));
        // 非法定义：0x80（indefinite，DER 禁止）
        assert_eq!(der_len_at(&[0x80], 0), None);
    }
}

//! uTLS 指纹伪装（ClientHello fingerprint）。
//!
//! 翻译自 Go `transport/internet/tls/tls.go` 中的三张指纹表与
//! `GetFingerprint` 函数。
//!
//! # 现状（重要）
//! **实际 uTLS 握手在 Rust 端尚未实现**。Rust 生态目前没有
//! `github.com/refraction-networking/utls` 的成熟等价品（需要字节级
//! ClientHello 控制、GREASE、扩展顺序、TLS 1.3 key_share 调整等）。
//!
//! 本模块只翻译「配置层指纹名 → 内部枚举」的纯路由逻辑，让上层
//! （dispatcher/dns/router/proxyman）能基于 `Fingerprint` 类型工作；
//! 实际握手走 [`crate::utls::ConnInterface`] trait，待生态成熟或自研
//! 后再接。

use crate::error::TlsError;

/// uTLS ClientHello 指纹。
///
/// 对应 Go 端 `utls.ClientHelloID`，但 Rust 端只保留「客户端想要哪
/// 种指纹」这一标记，具体字节布局等接入真实 uTLS 等价品后实现。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum Fingerprint {
    // ===== PresetFingerprints（UI 友好简短名） =====
    Chrome,
    Firefox,
    Safari,
    Ios,
    Android,
    Edge,
    /// 360 浏览器（Go 字段名是数字开头，Rust 用 Qihoo360）。
    Qihoo360,
    Qq,
    /// 启动时从 `ModernFingerprints` 随机选一个。
    Random,
    /// uTLS 的 `HelloRandomizedALPN`。
    Randomized,
    /// uTLS 的 `HelloRandomizedNoALPN`。
    RandomizedNoAlpn,
    /// Go 端 `"unsafe"` 是一个无操作占位（实际允许 InsecureSkipVerify）。
    Unsafe,

    // ===== ModernFingerprints（启动时选 random 的候选池） =====
    HelloFirefox120,
    HelloFirefox148,
    HelloChrome120,
    HelloChrome131,
    HelloChrome133,
    HelloIos13,
    HelloIos14,
    HelloEdge106,
    HelloSafari26_3,
    Hello360_11_0,
    HelloQq_11_1,

    // ===== OtherFingerprints（旧版/Golang/randomized/特殊） =====
    HelloGolang,
    HelloRandomized,        // 与 Randomized 略有差异：Go 端 random 包含 ALPN 选择
    HelloRandomizedAlpn,    // 与 Randomized 同义，保留独立变体以 1:1 翻译
    HelloRandomizedNoAlpn,  // 与 RandomizedNoAlpn 同义，保留独立变体
    HelloFirefoxAuto,
    HelloFirefox55,
    HelloFirefox56,
    HelloFirefox63,
    HelloFirefox65,
    HelloFirefox99,
    HelloFirefox102,
    HelloFirefox105,
    HelloChromeAuto,
    HelloChrome58,
    HelloChrome62,
    HelloChrome70,
    HelloChrome72,
    HelloChrome83,
    HelloChrome87,
    HelloChrome96,
    HelloChrome100,
    HelloChrome102,
    HelloChrome106Shuffle,
    HelloIosAuto,
    HelloIos11_1,
    HelloIos12_1,
    HelloAndroid11OkHttp,
    HelloEdge85,
    HelloEdgeAuto,
    HelloSafari16_0,
    HelloSafariAuto,
    Hello360Auto,
    Hello360_7_5,
    HelloQqAuto,
    // Chrome betas
    HelloChrome100Psk,
    HelloChrome112PskShuf,
    HelloChrome114PaddingPskShuf,
    HelloChrome115Pq,
    HelloChrome115PqPsk,
    HelloChrome120Pq,
}

impl Fingerprint {
    /// 默认指纹：Chrome Auto。
    ///
    /// 对应 Go `GetFingerprint("")` 返回 `&utls.HelloChrome_Auto`。
    pub const DEFAULT: Self = Self::Chrome;
}

/// `ModernFingerprints` 中随机抽取的源列表。
///
/// 对应 Go `init()` 中 `for _, v := range ModernFingerprints` 的迭代源。
/// 实际「选 random」逻辑等接入真实 uTLS 后再做（依赖 PRNG + weights）。
pub const MODERN_FINGERPRINTS: &[Fingerprint] = &[
    Fingerprint::HelloFirefox120,
    Fingerprint::HelloFirefox148,
    Fingerprint::HelloChrome120,
    Fingerprint::HelloChrome131,
    Fingerprint::HelloChrome133,
    Fingerprint::HelloIos13,
    Fingerprint::HelloIos14,
    Fingerprint::HelloEdge106,
    Fingerprint::HelloSafari26_3,
    Fingerprint::Hello360_11_0,
    Fingerprint::HelloQq_11_1,
];

/// 按名查指纹。
///
/// 对应 Go `GetFingerprint(name string)`。空字符串返回默认（Chrome）；
/// 不在任一张表里返回 `TlsError::UnknownFingerprint`。
///
/// # 查找顺序（与 Go 一致）
/// 1. 空字符串 → `Fingerprint::Chrome`
/// 2. `PRESET_FINGERPRINTS`（chrome/firefox/safari/ios/...）
/// 3. `MODERN_FINGERPRINTS`（hellofirefox_120/hellochrome_131/...）
/// 4. `OTHER_FINGERPRINTS`（hellogolang/hellochrome_58/...）
///
/// # 示例
/// ```
/// use xray_tls::fingerprint::{get_fingerprint, Fingerprint};
///
/// assert_eq!(get_fingerprint("").unwrap(), Fingerprint::Chrome);
/// assert_eq!(get_fingerprint("chrome").unwrap(), Fingerprint::Chrome);
/// assert_eq!(get_fingerprint("hellofirefox_120").unwrap(), Fingerprint::HelloFirefox120);
/// assert!(get_fingerprint("nonexistent").is_err());
/// ```
pub fn get_fingerprint(name: &str) -> Result<Fingerprint, TlsError> {
    if name.is_empty() {
        return Ok(Fingerprint::DEFAULT);
    }
    if let Some(fp) = lookup_preset(name) {
        return Ok(fp);
    }
    if let Some(fp) = lookup_modern(name) {
        return Ok(fp);
    }
    if let Some(fp) = lookup_other(name) {
        return Ok(fp);
    }
    Err(TlsError::UnknownFingerprint(name.to_string()))
}

fn lookup_preset(name: &str) -> Option<Fingerprint> {
    // 与 Go `PresetFingerprints` map 的 key 1:1 对应。
    // `random`/`randomized`/`randomizednoalpn`/`unsafe` 在 Go 端运行时
    // 由 init() 填充（依赖 utls.DefaultWeights / PRNG seed），Rust 端
    // 这几个保留为「标记」，实际权重选择等接入后实现。
    let fp = match name {
        "chrome" => Fingerprint::Chrome,
        "firefox" => Fingerprint::Firefox,
        "safari" => Fingerprint::Safari,
        "ios" => Fingerprint::Ios,
        "android" => Fingerprint::Android,
        "edge" => Fingerprint::Edge,
        "360" => Fingerprint::Qihoo360,
        "qq" => Fingerprint::Qq,
        "random" => Fingerprint::Random,
        "randomized" => Fingerprint::Randomized,
        "randomizednoalpn" => Fingerprint::RandomizedNoAlpn,
        "unsafe" => Fingerprint::Unsafe,
        _ => return None,
    };
    Some(fp)
}

fn lookup_modern(name: &str) -> Option<Fingerprint> {
    let fp = match name {
        "hellofirefox_120" => Fingerprint::HelloFirefox120,
        "hellofirefox_148" => Fingerprint::HelloFirefox148,
        "hellochrome_120" => Fingerprint::HelloChrome120,
        "hellochrome_131" => Fingerprint::HelloChrome131,
        "hellochrome_133" => Fingerprint::HelloChrome133,
        "helloios_13" => Fingerprint::HelloIos13,
        "helloios_14" => Fingerprint::HelloIos14,
        "helloedge_106" => Fingerprint::HelloEdge106,
        "hellosafari_26_3" => Fingerprint::HelloSafari26_3,
        "hello360_11_0" => Fingerprint::Hello360_11_0,
        "helloqq_11_1" => Fingerprint::HelloQq_11_1,
        _ => return None,
    };
    Some(fp)
}

fn lookup_other(name: &str) -> Option<Fingerprint> {
    let fp = match name {
        "hellogolang" => Fingerprint::HelloGolang,
        "hellorandomized" => Fingerprint::HelloRandomized,
        "hellorandomizedalpn" => Fingerprint::HelloRandomizedAlpn,
        "hellorandomizednoalpn" => Fingerprint::HelloRandomizedNoAlpn,
        "hellofirefox_auto" => Fingerprint::HelloFirefoxAuto,
        "hellofirefox_55" => Fingerprint::HelloFirefox55,
        "hellofirefox_56" => Fingerprint::HelloFirefox56,
        "hellofirefox_63" => Fingerprint::HelloFirefox63,
        "hellofirefox_65" => Fingerprint::HelloFirefox65,
        "hellofirefox_99" => Fingerprint::HelloFirefox99,
        "hellofirefox_102" => Fingerprint::HelloFirefox102,
        "hellofirefox_105" => Fingerprint::HelloFirefox105,
        "hellochrome_auto" => Fingerprint::HelloChromeAuto,
        "hellochrome_58" => Fingerprint::HelloChrome58,
        "hellochrome_62" => Fingerprint::HelloChrome62,
        "hellochrome_70" => Fingerprint::HelloChrome70,
        "hellochrome_72" => Fingerprint::HelloChrome72,
        "hellochrome_83" => Fingerprint::HelloChrome83,
        "hellochrome_87" => Fingerprint::HelloChrome87,
        "hellochrome_96" => Fingerprint::HelloChrome96,
        "hellochrome_100" => Fingerprint::HelloChrome100,
        "hellochrome_102" => Fingerprint::HelloChrome102,
        "hellochrome_106_shuffle" => Fingerprint::HelloChrome106Shuffle,
        "helloios_auto" => Fingerprint::HelloIosAuto,
        "helloios_11_1" => Fingerprint::HelloIos11_1,
        "helloios_12_1" => Fingerprint::HelloIos12_1,
        "helloandroid_11_okhttp" => Fingerprint::HelloAndroid11OkHttp,
        "helloedge_85" => Fingerprint::HelloEdge85,
        "helloedge_auto" => Fingerprint::HelloEdgeAuto,
        "hellosafari_16_0" => Fingerprint::HelloSafari16_0,
        "hellosafari_auto" => Fingerprint::HelloSafariAuto,
        "hello360_auto" => Fingerprint::Hello360Auto,
        "hello360_7_5" => Fingerprint::Hello360_7_5,
        "helloqq_auto" => Fingerprint::HelloQqAuto,
        "hellochrome_100_psk" => Fingerprint::HelloChrome100Psk,
        "hellochrome_112_psk_shuf" => Fingerprint::HelloChrome112PskShuf,
        "hellochrome_114_padding_psk_shuf" => Fingerprint::HelloChrome114PaddingPskShuf,
        "hellochrome_115_pq" => Fingerprint::HelloChrome115Pq,
        "hellochrome_115_pq_psk" => Fingerprint::HelloChrome115PqPsk,
        "hellochrome_120_pq" => Fingerprint::HelloChrome120Pq,
        _ => return None,
    };
    Some(fp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_returns_default_chrome() {
        assert_eq!(get_fingerprint("").unwrap(), Fingerprint::Chrome);
    }

    #[test]
    fn preset_table_complete() {
        // 所有 PresetFingerprints 的 key 都能解析
        for key in [
            "chrome", "firefox", "safari", "ios", "android", "edge", "360",
            "qq", "random", "randomized", "randomizednoalpn", "unsafe",
        ] {
            assert!(get_fingerprint(key).is_ok(), "preset key {key} should resolve");
        }
    }

    #[test]
    fn modern_table_complete() {
        for key in [
            "hellofirefox_120", "hellofirefox_148", "hellochrome_120",
            "hellochrome_131", "hellochrome_133", "helloios_13",
            "helloios_14", "helloedge_106", "hellosafari_26_3",
            "hello360_11_0", "helloqq_11_1",
        ] {
            assert!(get_fingerprint(key).is_ok(), "modern key {key} should resolve");
        }
    }

    #[test]
    fn other_table_complete() {
        // 抽样几个有代表性的
        assert!(get_fingerprint("hellogolang").is_ok());
        assert!(get_fingerprint("hellochrome_58").is_ok());
        assert!(get_fingerprint("hellofirefox_55").is_ok());
        assert!(get_fingerprint("hellochrome_120_pq").is_ok());
        assert!(get_fingerprint("hellochrome_114_padding_psk_shuf").is_ok());
    }

    #[test]
    fn unknown_returns_error() {
        match get_fingerprint("nonexistent_fingerprint") {
            Err(TlsError::UnknownFingerprint(s)) => {
                assert_eq!(s, "nonexistent_fingerprint");
            }
            other => panic!("expected UnknownFingerprint, got {other:?}"),
        }
    }

    #[test]
    fn case_sensitive_matches_go() {
        // Go 的 map 查找是大小写敏感的，Rust 端保持一致
        assert!(get_fingerprint("CHROME").is_err());
        assert!(get_fingerprint("Chrome").is_err());
        assert!(get_fingerprint("chrome").is_ok());
    }

    #[test]
    fn modern_constants_list_no_duplicates() {
        // MODERN_FINGERPRINTS 用于「随机选 random」，不能有重复
        let mut seen = std::collections::HashSet::new();
        for fp in MODERN_FINGERPRINTS {
            assert!(seen.insert(*fp), "duplicate {:?} in MODERN_FINGERPRINTS", fp);
        }
        assert_eq!(MODERN_FINGERPRINTS.len(), 11);
    }

    #[test]
    fn preset_modern_other_no_overlap() {
        // 三张表之间不应有同名字符串
        let preset = ["chrome", "firefox", "safari", "ios", "android", "edge",
                      "360", "qq", "random", "randomized", "randomizednoalpn", "unsafe"];
        for k in preset {
            // preset 命中后不应再走到 modern/other
            assert!(lookup_modern(k).is_none(), "{k} overlap with modern");
            assert!(lookup_other(k).is_none(), "{k} overlap with other");
        }
    }
}

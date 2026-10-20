//! uTLS 指纹伪装（ClientHello fingerprint）。
//!
//! 翻译自 Go `transport/internet/tls/tls.go` 中的三张指纹表与
//! `GetFingerprint` 函数。
//!
//! # 现状
//! `Fingerprint` 由 ``get_fingerprint` 解析后，
//! 经 `utls::u_client` 走 btls（BoringSSL）真实 uTLS ClientHello 指纹握手；
//! 清单外指纹硬错（见 `btls_client::connector_for_fingerprint`）。
//!
//! 本模块翻译「配置层指纹名 → 内部枚举」的纯路由逻辑，让上层
//! （dispatcher/dns/router/proxyman）能基于 `Fingerprint` 类型工作。

use crate::error::TlsError;

/// uTLS ClientHello 指纹。
///
/// 对应 Go 端 `utls.ClientHelloID`，但 Rust 端只保留「客户端想要哪
/// 种指纹」这一标记，具体字节布局等接入真实 uTLS 等价品后实现。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)] // Qihoo360 等变体名直译 Go 指纹名（数字开头/专有拼写），UI 名单对齐
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
    /// uTLS `HelloUniformRandomized`（均匀权重随机化）。Go xray 未收录该预设
    /// 名，Rust 端按 uTLS 库补全；btls 侧就近映射见
    /// `btls_client::connector_for_fingerprint`。
    UniformRandom,
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
    HelloRandomized,       // 与 Randomized 略有差异：Go 端 random 包含 ALPN 选择
    HelloRandomizedAlpn,   // 与 Randomized 同义，保留独立变体以 1:1 翻译
    HelloRandomizedNoAlpn, // 与 RandomizedNoAlpn 同义，保留独立变体
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
/// use xray_tls::fingerprint::{Fingerprint, get_fingerprint};
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
        // `uniformrandom`：Go xray 未收录，对齐 uTLS `HelloUniformRandomized`
        // 预设名的超集扩展（配置层宽容，btls 侧就近映射）。
        "uniformrandom" => Fingerprint::UniformRandom,
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
            "chrome",
            "firefox",
            "safari",
            "ios",
            "android",
            "edge",
            "360",
            "qq",
            "random",
            "randomized",
            "randomizednoalpn",
            "uniformrandom",
            "unsafe",
        ] {
            assert!(get_fingerprint(key).is_ok(), "preset key {key} should resolve");
        }
    }

    #[test]
    fn modern_table_complete() {
        for key in [
            "hellofirefox_120",
            "hellofirefox_148",
            "hellochrome_120",
            "hellochrome_131",
            "hellochrome_133",
            "helloios_13",
            "helloios_14",
            "helloedge_106",
            "hellosafari_26_3",
            "hello360_11_0",
            "helloqq_11_1",
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

    /// 票 daqq：每个配置名 → 枚举 → btls 实际生效模板的映射必须**显式**
    /// （Native / Degraded 目标 / Unsupported 三者必居其一，无未声明分支）。
    /// 新增 `Fingerprint` 变体时下方 `exhaustive_guard` 的 match 编译失败，
    /// 强制先补 [`crate::btls_client::effective_fingerprint`] 裁决与本表。
    #[test]
    fn fingerprint_resolution_explicit_table() {
        use crate::btls_client::{FingerprintResolution as Res, effective_fingerprint};
        use Fingerprint as F;

        let n = Res::Native;
        let d = |e: Fingerprint| Res::Degraded { effective: e };
        let table: &[(&str, Fingerprint, Res)] = &[
            // ---- 原生模板（btls 专属 ClientHello 配置）----
            ("chrome", F::Chrome, n),
            ("hellochrome_133", F::HelloChrome133, n),
            ("hellochrome_131", F::HelloChrome131, n),
            ("hellochrome_120", F::HelloChrome120, n),
            ("firefox", F::Firefox, n),
            ("hellofirefox_148", F::HelloFirefox148, n),
            ("hellofirefox_120", F::HelloFirefox120, n),
            ("safari", F::Safari, n),
            ("hellosafari_26_3", F::HelloSafari26_3, n),
            ("helloios_13", F::HelloIos13, n),
            ("ios", F::Ios, n),
            ("helloios_14", F::HelloIos14, n),
            ("edge", F::Edge, n),
            ("helloedge_106", F::HelloEdge106, n),
            ("360", F::Qihoo360, n),
            ("hello360_11_0", F::Hello360_11_0, n),
            ("qq", F::Qq, n),
            ("helloqq_11_1", F::HelloQq_11_1, n),
            // ---- 旧 Chrome 族 → Chrome 120 ----
            ("hellochrome_auto", F::HelloChromeAuto, d(F::HelloChrome120)),
            ("hellochrome_58", F::HelloChrome58, d(F::HelloChrome120)),
            ("hellochrome_62", F::HelloChrome62, d(F::HelloChrome120)),
            ("hellochrome_70", F::HelloChrome70, d(F::HelloChrome120)),
            ("hellochrome_72", F::HelloChrome72, d(F::HelloChrome120)),
            ("hellochrome_83", F::HelloChrome83, d(F::HelloChrome120)),
            ("hellochrome_87", F::HelloChrome87, d(F::HelloChrome120)),
            ("hellochrome_96", F::HelloChrome96, d(F::HelloChrome120)),
            ("hellochrome_100", F::HelloChrome100, d(F::HelloChrome120)),
            ("hellochrome_102", F::HelloChrome102, d(F::HelloChrome120)),
            ("hellochrome_106_shuffle", F::HelloChrome106Shuffle, d(F::HelloChrome120)),
            ("hellochrome_100_psk", F::HelloChrome100Psk, d(F::HelloChrome120)),
            ("hellochrome_112_psk_shuf", F::HelloChrome112PskShuf, d(F::HelloChrome120)),
            (
                "hellochrome_114_padding_psk_shuf",
                F::HelloChrome114PaddingPskShuf,
                d(F::HelloChrome120),
            ),
            ("hellochrome_115_pq", F::HelloChrome115Pq, d(F::HelloChrome120)),
            ("hellochrome_115_pq_psk", F::HelloChrome115PqPsk, d(F::HelloChrome120)),
            ("hellochrome_120_pq", F::HelloChrome120Pq, d(F::HelloChrome120)),
            // ---- 旧 Firefox 族 → Firefox 120 ----
            ("hellofirefox_auto", F::HelloFirefoxAuto, d(F::HelloFirefox120)),
            ("hellofirefox_55", F::HelloFirefox55, d(F::HelloFirefox120)),
            ("hellofirefox_56", F::HelloFirefox56, d(F::HelloFirefox120)),
            ("hellofirefox_63", F::HelloFirefox63, d(F::HelloFirefox120)),
            ("hellofirefox_65", F::HelloFirefox65, d(F::HelloFirefox120)),
            ("hellofirefox_99", F::HelloFirefox99, d(F::HelloFirefox120)),
            ("hellofirefox_102", F::HelloFirefox102, d(F::HelloFirefox120)),
            ("hellofirefox_105", F::HelloFirefox105, d(F::HelloFirefox120)),
            // ---- 旧 iOS/Safari 族 → iOS 13 ----
            ("helloios_auto", F::HelloIosAuto, d(F::HelloIos13)),
            ("helloios_11_1", F::HelloIos11_1, d(F::HelloIos13)),
            ("helloios_12_1", F::HelloIos12_1, d(F::HelloIos13)),
            ("hellosafari_16_0", F::HelloSafari16_0, d(F::HelloIos13)),
            ("hellosafari_auto", F::HelloSafariAuto, d(F::HelloIos13)),
            // ---- 旧 Edge 族 → Edge 106 ----
            ("helloedge_85", F::HelloEdge85, d(F::HelloEdge106)),
            ("helloedge_auto", F::HelloEdgeAuto, d(F::HelloEdge106)),
            // ---- 旧 360/QQ 族 ----
            ("hello360_auto", F::Hello360Auto, d(F::Hello360_11_0)),
            ("hello360_7_5", F::Hello360_7_5, d(F::Hello360_11_0)),
            ("helloqq_auto", F::HelloQqAuto, d(F::HelloQq_11_1)),
            // ---- Android ≈ Chrome ----
            ("android", F::Android, d(F::Chrome)),
            ("helloandroid_11_okhttp", F::HelloAndroid11OkHttp, d(F::Chrome)),
            // ---- Golang → Chrome 120 ----
            ("hellogolang", F::HelloGolang, d(F::HelloChrome120)),
            // ---- 随机化族 → 静态 Chrome 133（btls 无随机化能力，诚实降级）----
            ("random", F::Random, d(F::Chrome)),
            ("randomized", F::Randomized, d(F::Chrome)),
            ("hellorandomized", F::HelloRandomized, d(F::Chrome)),
            ("hellorandomizedalpn", F::HelloRandomizedAlpn, d(F::Chrome)),
            ("randomizednoalpn", F::RandomizedNoAlpn, d(F::Chrome)),
            ("hellorandomizednoalpn", F::HelloRandomizedNoAlpn, d(F::Chrome)),
            ("uniformrandom", F::UniformRandom, d(F::Chrome)),
            // ---- 显式不支持 ----
            ("unsafe", F::Unsafe, Res::Unsupported),
        ];
        assert_eq!(table.len(), 64, "64 配置名（13 preset + 11 modern + 40 other）全显式");
        for (name, fp, expected) in table {
            assert_eq!(
                get_fingerprint(name).ok().as_ref(),
                Some(fp),
                "config name {name} must resolve"
            );
            assert_eq!(&effective_fingerprint(fp), expected, "fingerprint {fp:?}");
        }

        // 编译期完备性闸：新增枚举变体时此 match 非穷尽编译失败——
        // 强制先补 effective_fingerprint 裁决再入表，禁止未声明分支。
        for fp in table.iter().map(|(_, fp, _)| *fp) {
            match fp {
                F::Chrome
                | F::Firefox
                | F::Safari
                | F::Ios
                | F::Android
                | F::Edge
                | F::Qihoo360
                | F::Qq
                | F::Random
                | F::Randomized
                | F::RandomizedNoAlpn
                | F::UniformRandom
                | F::Unsafe
                | F::HelloFirefox120
                | F::HelloFirefox148
                | F::HelloChrome120
                | F::HelloChrome131
                | F::HelloChrome133
                | F::HelloIos13
                | F::HelloIos14
                | F::HelloEdge106
                | F::HelloSafari26_3
                | F::Hello360_11_0
                | F::HelloQq_11_1
                | F::HelloGolang
                | F::HelloRandomized
                | F::HelloRandomizedAlpn
                | F::HelloRandomizedNoAlpn
                | F::HelloFirefoxAuto
                | F::HelloFirefox55
                | F::HelloFirefox56
                | F::HelloFirefox63
                | F::HelloFirefox65
                | F::HelloFirefox99
                | F::HelloFirefox102
                | F::HelloFirefox105
                | F::HelloChromeAuto
                | F::HelloChrome58
                | F::HelloChrome62
                | F::HelloChrome70
                | F::HelloChrome72
                | F::HelloChrome83
                | F::HelloChrome87
                | F::HelloChrome96
                | F::HelloChrome100
                | F::HelloChrome102
                | F::HelloChrome106Shuffle
                | F::HelloIosAuto
                | F::HelloIos11_1
                | F::HelloIos12_1
                | F::HelloAndroid11OkHttp
                | F::HelloEdge85
                | F::HelloEdgeAuto
                | F::HelloSafari16_0
                | F::HelloSafariAuto
                | F::Hello360Auto
                | F::Hello360_7_5
                | F::HelloQqAuto
                | F::HelloChrome100Psk
                | F::HelloChrome112PskShuf
                | F::HelloChrome114PaddingPskShuf
                | F::HelloChrome115Pq
                | F::HelloChrome115PqPsk
                | F::HelloChrome120Pq => {},
            }
        }
    }

    #[test]
    fn unknown_returns_error() {
        match get_fingerprint("nonexistent_fingerprint") {
            Err(TlsError::UnknownFingerprint(s)) => {
                assert_eq!(s, "nonexistent_fingerprint");
            },
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
        let preset = [
            "chrome",
            "firefox",
            "safari",
            "ios",
            "android",
            "edge",
            "360",
            "qq",
            "random",
            "randomized",
            "randomizednoalpn",
            "unsafe",
        ];
        for k in preset {
            // preset 命中后不应再走到 modern/other
            assert!(lookup_modern(k).is_none(), "{k} overlap with modern");
            assert!(lookup_other(k).is_none(), "{k} overlap with other");
        }
    }
}

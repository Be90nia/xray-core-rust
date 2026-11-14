//! xray-app-geodata 配置。

use xray_proto::xray::app::geodata::{Asset as ProtoAsset, Config as ProtoConfig};

use crate::error::GeodataError;

/// Go `infra/conf/geodata.go:22-31` `migrateGeodataURL`：xray-rules-dat 仓的裸
/// `.dat` URL 改写成 `.dat.gz`（同内容，体积差一个量级），其余 URL 原样返回。
///
/// 只改写 `github.com/xtls/xray-rules-dat/` 与
/// `raw.githubusercontent.com/xtls/xray-rules-dat/` 两个前缀——自建源不一定有
/// `.gz`，改写会 404。大小写不敏感（Go 两侧都先 `ToLower`）。
///
/// 落盘内容不变：[`crate::downloader`] 按 gzip magic 字节透明解压，与 Go
/// `app/geodata/download.go:208-212` 同判据。故改写对用户不可见（Go 另打弃用警告，
/// 本仓无 WARN 面：改写是等价行为，不是降级）。
#[must_use]
pub fn migrate_geodata_url(url: &str) -> String {
    let lower = url.to_ascii_lowercase();
    let rules_dat = lower.starts_with("https://github.com/xtls/xray-rules-dat/")
        || lower.starts_with("https://raw.githubusercontent.com/xtls/xray-rules-dat/");
    if rules_dat && lower.ends_with(".dat") {
        return format!("{url}.gz");
    }
    url.to_string()
}

/// Geodata 资产**本地文件名**扩展名白名单（含前导点，与 Go `filepath.Ext` 同形）。
///
/// 对齐 Go v26.11.9 `app/geodata/geodata.go:36`：
/// `strings.EqualFold(filepath.Ext(asset.GetFile()), ".dat")` —— 只认 `.dat`
/// （大小写不敏感）；`.lua` / `.txt` / 无扩展名 / `.dat.gz` 一律拒收。
///
/// 注：白名单作用于**本地目标文件名**（Go 的 `asset.File`），**不**作用于 URL ——
/// Go 的 URL 侧是 [`migrate_geodata_url`]（把 rules-dat 仓的
/// `.dat` URL 改写成 `.dat.gz`），且 `app/geodata/download.go` 按 gzip
/// magic 字节透明解压。URL 扩展名在 Go 侧无白名单，本仓同样不设。
pub const ALLOWED_ASSET_EXTENSIONS: &[&str] = &[".dat"];

/// Go `filepath.Ext` 等价：取末段路径中最后一个 `.` 及其之后的部分（含点）。
///
/// 不复用 Rust `Path::extension()`：`.dat`（点开头）Go 视作扩展名 `.dat`，
/// Rust 视作「无扩展名」——两者在白名单判定上结论相反（Go 放行 / Rust 拒收）。
fn go_file_ext(file: &str) -> &str {
    let base = file.rsplit(['/', '\\']).next().unwrap_or(file);
    match base.rfind('.') {
        Some(i) => &base[i..],
        None => "",
    }
}

/// Geodata 资产：URL + 本地文件名。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeodataAsset {
    pub url: String,
    pub file: String,
}

impl GeodataAsset {
    /// 资产校验：URL 必须 https + 本地文件名扩展名在白名单内（fail-visible）。
    ///
    /// 对齐 Go v26.11.9：https 约束来自 `infra/conf/geodata.go` `validateHTTPS`
    /// （`url.ParseRequestURI` + scheme 必须 https 且 host 非空）；扩展名白名单来自
    /// `app/geodata/geodata.go` `New()`（`EqualFold(filepath.Ext(file), ".dat")`）。
    /// 拒收 = 报错，**禁**静默跳过、**禁**降级为其他格式。
    ///
    /// 注：Go 的两段校验发生在**不同层**——`validateHTTPS` 在 conf 层恒跑，扩展名
    /// 校验在 `app/geodata` 的 `New()` 且 `cron == ""` 时提前 return（不校验）。需要
    /// 对齐该时序时用 [`Self::validate_url`] / [`Self::validate_extension`] 分开调。
    pub fn validate(&self) -> Result<(), GeodataError> {
        self.validate_url()?;
        self.validate_extension()
    }

    /// URL 校验（Go `infra/conf/geodata.go` `validateHTTPS`）：`https` + host 非空 +
    /// 无 fragment。conf 层恒跑（与 cron 是否为空无关）。
    pub fn validate_url(&self) -> Result<(), GeodataError> {
        let (scheme, rest) = match self.url.split_once("://") {
            Some((s, r)) => (s, r),
            None => return Err(self.invalid_url_err()),
        };
        // Go `url.Parse` 会把 scheme 归一化为小写，故大小写不敏感。
        if !scheme.eq_ignore_ascii_case("https") {
            return Err(self.invalid_url_err());
        }
        // host = authority（首个 `/`/`?`/`#` 之前）；Go 要求 host 非空。
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if authority.is_empty() || authority.contains(char::is_whitespace) {
            return Err(self.invalid_url_err());
        }
        // Go `url.ParseRequestURI` 不接受 fragment（HTTP request URI 无 fragment）。
        if self.url.contains('#') {
            return Err(self.invalid_url_err());
        }
        Ok(())
    }

    /// 非法 URL 错误（URL 走 `redact_url` 脱敏——凭据不得进日志/错误文本）。
    fn invalid_url_err(&self) -> GeodataError {
        GeodataError::InvalidAssetUrl { url: xray_common::redact::redact_url(&self.url) }
    }

    /// 扩展名白名单校验（fail-visible）。
    ///
    /// 对齐 Go `app/geodata/geodata.go` `New()`：扩展名不在白名单 → 报错拒收。
    pub fn validate_extension(&self) -> Result<(), GeodataError> {
        let ext = go_file_ext(&self.file);
        let ok = ALLOWED_ASSET_EXTENSIONS.iter().any(|a| ext.eq_ignore_ascii_case(a));
        if ok {
            Ok(())
        } else {
            Err(GeodataError::InvalidAssetExtension { file: self.file.clone() })
        }
    }

    pub fn from_proto(p: &ProtoAsset) -> Self {
        Self { url: p.url.clone(), file: p.file.clone() }
    }

    pub fn to_proto(&self) -> ProtoAsset {
        ProtoAsset { url: self.url.clone(), file: self.file.clone() }
    }
}

/// Geodata 配置：cron 调度 + outbound + 资产列表。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeodataConfig {
    pub cron: String,
    pub outbound: String,
    pub assets: Vec<GeodataAsset>,
}

impl GeodataConfig {
    pub fn from_proto(p: &ProtoConfig) -> Self {
        Self {
            cron: p.cron.clone(),
            outbound: p.outbound.clone(),
            assets: p.assets.iter().map(GeodataAsset::from_proto).collect(),
        }
    }

    pub fn to_proto(&self) -> ProtoConfig {
        ProtoConfig {
            cron: self.cron.clone(),
            outbound: self.outbound.clone(),
            assets: self.assets.iter().map(|a| a.to_proto()).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_default_empty() {
        let a = GeodataAsset::default();
        assert!(a.url.is_empty());
        assert!(a.file.is_empty());
    }

    #[test]
    fn asset_from_proto() {
        let p = ProtoAsset { url: "https://example.com/ip.dat".into(), file: "geoip.dat".into() };
        let a = GeodataAsset::from_proto(&p);
        assert_eq!(a.url, "https://example.com/ip.dat");
        assert_eq!(a.file, "geoip.dat");
    }

    #[test]
    fn asset_to_proto_roundtrip() {
        let a = GeodataAsset { url: "u".into(), file: "f".into() };
        let p = a.to_proto();
        assert_eq!(GeodataAsset::from_proto(&p), a);
    }

    #[test]
    fn config_default_empty() {
        let c = GeodataConfig::default();
        assert!(c.cron.is_empty());
        assert!(c.outbound.is_empty());
        assert!(c.assets.is_empty());
    }

    #[test]
    fn config_from_proto() {
        let p = ProtoConfig {
            cron: "0 0 * * *".into(),
            outbound: "direct".into(),
            assets: vec![ProtoAsset { url: "u1".into(), file: "f1".into() }],
        };
        let c = GeodataConfig::from_proto(&p);
        assert_eq!(c.cron, "0 0 * * *");
        assert_eq!(c.outbound, "direct");
        assert_eq!(c.assets.len(), 1);
        assert_eq!(c.assets[0].url, "u1");
    }

    #[test]
    fn config_to_proto_roundtrip() {
        let c = GeodataConfig {
            cron: "*/5 * * * *".into(),
            outbound: "block".into(),
            assets: vec![
                GeodataAsset { url: "u".into(), file: "f".into() },
                GeodataAsset { url: "u2".into(), file: "f2".into() },
            ],
        };
        let p = c.to_proto();
        assert_eq!(GeodataConfig::from_proto(&p), c);
    }

    #[test]
    fn config_empty_proto_yields_empty() {
        let p = ProtoConfig::default();
        let c = GeodataConfig::from_proto(&p);
        assert_eq!(c, GeodataConfig::default());
    }

    #[test]
    fn config_eq_semantics() {
        let c1 = GeodataConfig { cron: "x".into(), outbound: "y".into(), assets: vec![] };
        let c2 = c1.clone();
        assert_eq!(c1, c2);
    }

    // ===== bd ix8xd D-4：`migrateGeodataURL` 移植（Go `infra/conf/geodata.go:22-31`）=====

    /// rules-dat 仓的裸 `.dat` URL → `.dat.gz`；其余原样（自建源可能无 `.gz`）。
    ///
    /// 大小写不敏感（Go 两侧先 `ToLower`），改写后 `download.rs` 按 gzip magic 解压
    /// ⇒ 落盘内容与裸 `.dat` 等价。
    #[test]
    fn migrate_url_rewrites_rules_dat_to_gz() {
        for (input, want) in [
            (
                "https://github.com/xtls/xray-rules-dat/raw/main/geoip.dat",
                "https://github.com/xtls/xray-rules-dat/raw/main/geoip.dat.gz",
            ),
            (
                "https://raw.githubusercontent.com/xtls/xray-rules-dat/main/geosite.dat",
                "https://raw.githubusercontent.com/xtls/xray-rules-dat/main/geosite.dat.gz",
            ),
            (
                "https://github.com/XTLS/Xray-Rules-Dat/raw/main/geoip.DAT",
                "https://github.com/XTLS/Xray-Rules-Dat/raw/main/geoip.DAT.gz",
            ),
            // 非 rules-dat 仓 / 已带 .gz / 非 .dat 后缀：原样。
            ("https://example.com/geoip.dat", "https://example.com/geoip.dat"),
            (
                "https://github.com/xtls/xray-rules-dat/raw/main/geoip.dat.gz",
                "https://github.com/xtls/xray-rules-dat/raw/main/geoip.dat.gz",
            ),
            (
                "https://github.com/xtls/xray-rules-dat/releases/download/latest/x.json",
                "https://github.com/xtls/xray-rules-dat/releases/download/latest/x.json",
            ),
            // 相似但不是该仓（后缀伪装）不改写。
            (
                "https://github.com/xtls/xray-rules-dat-evil/geoip.dat",
                "https://github.com/xtls/xray-rules-dat-evil/geoip.dat",
            ),
        ] {
            assert_eq!(super::migrate_geodata_url(input), want, "input={input}");
        }
    }

    /// URL 校验与扩展名校验可分开调：Go 的 `validateHTTPS` 在 conf 层恒跑，扩展名
    /// 校验在 `app/geodata` 且 `cron == ""` 时跳过（bd ix8xd D-9 的时序依据）。
    #[test]
    fn url_validation_independent_of_extension() {
        let a = GeodataAsset { url: "https://example.com/x.dat".into(), file: "x.lua".into() };
        assert!(a.validate_url().is_ok(), "URL 合法时与本地文件名无关");
        assert!(a.validate().is_err(), "扩展名白名单仍须拒");
        let b = GeodataAsset { url: "http://example.com/x.dat".into(), file: "x.dat".into() };
        assert!(b.validate_url().is_err(), "scheme 必须 https");
    }

    // ===== bd dr0fu B-7：geodata 下载加固（对齐 Go v26.11.9 48f62b80）=====

    /// Go `app/geodata/geodata.go:36`：`EqualFold(filepath.Ext(file), ".dat")`。
    #[test]
    fn extension_whitelist_accepts_dat_only() {
        for ok in ["geoip.dat", "geoip.DAT", "geoip.Dat", ".dat"] {
            let a = GeodataAsset { url: "https://example.com/x".into(), file: ok.into() };
            assert!(a.validate_extension().is_ok(), "应放行: {ok}");
        }
        // Go 拒收：.lua / .txt / 无扩展名 / .dat.gz（Ext = ".gz"）/ 空名。
        for bad in ["asset.lua", "asset.txt", "asset", "asset.dat.gz", "", "asset.dat.bak"] {
            let a = GeodataAsset { url: "https://example.com/x".into(), file: bad.into() };
            let err = a.validate_extension().unwrap_err();
            assert!(
                matches!(err, GeodataError::InvalidAssetExtension { .. }),
                "应拒收 {bad}: {err:?}"
            );
        }
    }

    /// Go `infra/conf/geodata.go` `validateHTTPS`：scheme 必须 https 且 host 非空。
    #[test]
    fn validate_requires_https_url_and_dat_file() {
        let good =
            GeodataAsset { url: "https://example.com/geoip.dat".into(), file: "geoip.dat".into() };
        assert!(good.validate().is_ok());
        for bad_url in [
            "http://example.com/geoip.dat",
            "ftp://example.com/geoip.dat",
            "https://",
            "https:///geoip.dat",
            "example.com/geoip.dat",
        ] {
            let a = GeodataAsset { url: bad_url.into(), file: "geoip.dat".into() };
            let err = a.validate().unwrap_err();
            assert!(
                matches!(err, GeodataError::InvalidAssetUrl { .. }),
                "应拒收 URL {bad_url}: {err:?}"
            );
        }
        // 扩展名非法同样拒收（fail-visible）。
        let a = GeodataAsset { url: "https://example.com/x".into(), file: "asset.lua".into() };
        assert!(matches!(a.validate().unwrap_err(), GeodataError::InvalidAssetExtension { .. }));
    }
}

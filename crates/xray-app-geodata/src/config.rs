//! xray-app-geodata 配置。

use xray_proto::xray::app::geodata::{Asset as ProtoAsset, Config as ProtoConfig};

use crate::error::GeodataError;

/// Geodata 资产**本地文件名**扩展名白名单（含前导点，与 Go `filepath.Ext` 同形）。
///
/// 对齐 Go v26.11.9 `app/geodata/geodata.go:36`：
/// `strings.EqualFold(filepath.Ext(asset.GetFile()), ".dat")` —— 只认 `.dat`
/// （大小写不敏感）；`.lua` / `.txt` / 无扩展名 / `.dat.gz` 一律拒收。
///
/// 注：白名单作用于**本地目标文件名**（Go 的 `asset.File`），**不**作用于 URL ——
/// Go 的 URL 侧是 `infra/conf/geodata.go` `migrateGeodataURL`（把 rules-dat 仓的
/// `.dat` URL 改写成 `.dat.gz`，见 B-6 票），且 `app/geodata/download.go` 按 gzip
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
    pub fn validate(&self) -> Result<(), GeodataError> {
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
        self.validate_extension()
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

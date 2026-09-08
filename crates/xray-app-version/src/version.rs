//! 版本检查核心实现。
//!
//! 对应 Go 版本 `app/version/version.go`。

use thiserror::Error;

use crate::Config;

/// 版本检查错误。
#[derive(Debug, Error)]
pub enum VersionError {
    /// 版本号组件无法解析为非负整数。
    #[error("invalid version component {component:?} in {version}")]
    InvalidComponent {
        /// 无法解析的组件原文。
        component: String,
        /// 该组件所属的完整版本字符串。
        version: String,
    },
    /// 当前核心版本低于配置要求的最低版本。
    #[error("this config must be run on version {required} or higher")]
    MinVersionNotMet {
        /// 配置要求的最低版本。
        required: String,
    },
    /// 当前核心版本高于配置允许的最高版本。
    #[error("this config should be run on version {required} or lower")]
    MaxVersionExceeded {
        /// 配置允许的最高版本。
        required: String,
    },
}

/// 版本检查服务。
///
/// 对应 Go 版本 `app/version.Version`。Go 源码中 `New(ctx, config)` 的
/// `ctx` 实际未使用，故 Rust 实现省略该参数。
#[derive(Debug, Clone)]
pub struct Version {
    config: Config,
}

impl Version {
    /// 创建新的版本检查器。
    ///
    /// 校验 `config.core_version` 是否落在 `[min_version, max_version]` 区间（含端点）。
    /// 空字符串的边界表示该方向不限制。
    ///
    /// # 错误
    ///
    /// - [`VersionError::InvalidComponent`]：版本号存在非数字组件
    /// - [`VersionError::MinVersionNotMet`]：核心版本低于 `min_version`
    /// - [`VersionError::MaxVersionExceeded`]：核心版本高于 `max_version`
    pub fn new(config: Config) -> Result<Self, VersionError> {
        if !config.min_version.is_empty() {
            let cmp = compare_versions(&config.min_version, &config.core_version)?;
            if cmp > 0 {
                return Err(VersionError::MinVersionNotMet {
                    required: config.min_version.clone(),
                });
            }
        }
        if !config.max_version.is_empty() {
            let cmp = compare_versions(&config.max_version, &config.core_version)?;
            if cmp < 0 {
                return Err(VersionError::MaxVersionExceeded {
                    required: config.max_version.clone(),
                });
            }
        }
        Ok(Self { config })
    }

    /// 获取持有配置的不可变引用。
    pub fn config(&self) -> &Config {
        &self.config
    }
}

/// Feature 包装：把版本检查服务暴露为 [`xray_features::Feature`]。
///
/// 对应 Go `app/version` 的 Feature 注册入口（Go `Version.Start()` 实际
/// 无操作，故 Rust 端无 background task；构造时已校验版本区间）。
pub struct VersionFeature {
    /// 持有 `Version` 实例，便于外部查询 core/min/max。
    pub version: Version,
}

impl VersionFeature {
    /// 从 `coreVersion` + 选填 `minVersion`/`maxVersion` 构造。
    ///
    /// 缺省 coreVersion 退化为 `"0.0.0"`（与 Go xray.go:Version_x/y/z 缺省同款）。
    pub fn new(
        core_version: impl Into<String>,
        min_version: Option<String>,
        max_version: Option<String>,
    ) -> Result<Self, VersionError> {
        let config = Config {
            core_version: core_version.into(),
            min_version: min_version.unwrap_or_default(),
            max_version: max_version.unwrap_or_default(),
        };
        Version::new(config).map(|v| Self { version: v })
    }
}

impl xray_features::Feature for VersionFeature {
    fn feature_name(&self) -> &'static str {
        "version"
    }
    // 构造时已校验 core vs min/max 区间，`start` 无 background task 可启。
    // 行为对齐 Go `Version.Start()`（空实现）。
}

/// 比较两个点分十进制版本字符串。
///
/// 返回：
/// - `Ok(-1)`：`v1 < v2`
/// - `Ok(0)`：`v1 == v2`
/// - `Ok(1)`：`v1 > v2`
///
/// 较短版本用 `0` 补齐对齐。版本组件按 `u64` 解析，超出范围或非数字返回错误。
///
/// # 例子
///
/// ```
/// use xray_app_version::compare_versions;
///
/// assert_eq!(compare_versions("1.2.3", "1.2.3").unwrap(), 0);
/// assert_eq!(compare_versions("2.0", "1.9.9").unwrap(), 1);
/// assert_eq!(compare_versions("1.0", "1.0.1").unwrap(), -1);
/// assert_eq!(compare_versions("1", "1.0.0").unwrap(), 0);
/// ```
pub fn compare_versions(v1: &str, v2: &str) -> Result<i8, VersionError> {
    let mut p1: Vec<&str> = v1.split('.').collect();
    let mut p2: Vec<&str> = v2.split('.').collect();

    // 较短的版本号补 0 对齐。
    while p1.len() < p2.len() {
        p1.push("0");
    }
    while p2.len() < p1.len() {
        p2.push("0");
    }

    for (a, b) in p1.iter().zip(p2.iter()) {
        let n1: u64 = a.parse().map_err(|_| VersionError::InvalidComponent {
            component: (*a).to_string(),
            version: v1.to_string(),
        })?;
        let n2: u64 = b.parse().map_err(|_| VersionError::InvalidComponent {
            component: (*b).to_string(),
            version: v2.to_string(),
        })?;

        match n1.cmp(&n2) {
            std::cmp::Ordering::Less => return Ok(-1),
            std::cmp::Ordering::Greater => return Ok(1),
            std::cmp::Ordering::Equal => {}
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(core: &str, min: &str, max: &str) -> Config {
        Config {
            core_version: core.into(),
            min_version: min.into(),
            max_version: max.into(),
        }
    }

    // ---- compare_versions ----

    #[test]
    fn compare_equal() {
        assert_eq!(compare_versions("1.2.3", "1.2.3").unwrap(), 0);
    }

    #[test]
    fn compare_greater() {
        assert_eq!(compare_versions("2.0", "1.9.9").unwrap(), 1);
    }

    #[test]
    fn compare_less() {
        assert_eq!(compare_versions("1.0", "1.0.1").unwrap(), -1);
    }

    #[test]
    fn compare_pad_zero_short_left() {
        assert_eq!(compare_versions("1", "1.0.0").unwrap(), 0);
    }

    #[test]
    fn compare_pad_zero_short_right() {
        assert_eq!(compare_versions("1.2.3.4", "1.2.3").unwrap(), 1);
    }

    #[test]
    fn compare_empty_string_is_invalid_component() {
        // Go strconv.Atoi("") 失败；Rust 实现保持一致行为。
        assert!(compare_versions("", "").is_err());
    }

    #[test]
    fn compare_invalid_component_in_v1() {
        let err = compare_versions("1.x.3", "1.0.0").unwrap_err();
        assert!(matches!(
            err,
            VersionError::InvalidComponent { ref component, ref version }
                if component == "x" && version == "1.x.3"
        ));
    }

    #[test]
    fn compare_invalid_component_in_v2() {
        let err = compare_versions("1.0.0", "1.0").unwrap(); // ok numeric
        assert_eq!(err, 0);
        let err = compare_versions("1.0.0", "1.abc").unwrap_err();
        assert!(matches!(
            err,
            VersionError::InvalidComponent { ref component, ref version }
                if component == "abc" && version == "1.abc"
        ));
    }

    #[test]
    fn compare_overflow_component_rejected() {
        // u64::MAX + 1 应当被解析拒绝。
        let huge = format!("{}", u128::from(u64::MAX) + 1);
        assert!(compare_versions(&huge, "1.0").is_err());
    }

    // ---- Version::new ----

    #[test]
    fn version_new_no_constraints() {
        assert!(Version::new(cfg("1.0.0", "", "")).is_ok());
    }

    #[test]
    fn version_new_empty_core_allowed_when_no_bounds() {
        assert!(Version::new(cfg("", "", "")).is_ok());
    }

    #[test]
    fn version_new_min_met_exact() {
        assert!(Version::new(cfg("1.8.0", "1.8.0", "")).is_ok());
    }

    #[test]
    fn version_new_min_met_above() {
        assert!(Version::new(cfg("2.0.0", "1.0.0", "")).is_ok());
    }

    #[test]
    fn version_new_min_not_met() {
        let err = Version::new(cfg("1.0.0", "2.0.0", "")).unwrap_err();
        assert!(matches!(
            err,
            VersionError::MinVersionNotMet { ref required } if required == "2.0.0"
        ));
    }

    #[test]
    fn version_new_max_met_exact() {
        assert!(Version::new(cfg("1.8.0", "", "1.8.0")).is_ok());
    }

    #[test]
    fn version_new_max_met_below() {
        assert!(Version::new(cfg("1.0.0", "", "2.0.0")).is_ok());
    }

    #[test]
    fn version_new_max_exceeded() {
        let err = Version::new(cfg("2.0.0", "", "1.0.0")).unwrap_err();
        assert!(matches!(
            err,
            VersionError::MaxVersionExceeded { ref required } if required == "1.0.0"
        ));
    }

    #[test]
    fn version_new_within_range() {
        assert!(Version::new(cfg("1.8.5", "1.8.0", "1.9.0")).is_ok());
    }

    #[test]
    fn version_new_invalid_min_propagates() {
        assert!(matches!(
            Version::new(cfg("1.0.0", "1.x", "")).unwrap_err(),
            VersionError::InvalidComponent { .. }
        ));
    }

    #[test]
    fn version_new_invalid_max_propagates() {
        assert!(matches!(
            Version::new(cfg("1.0.0", "", "1.x")).unwrap_err(),
            VersionError::InvalidComponent { .. }
        ));
    }

    #[test]
    fn version_config_accessor() {
        let v = Version::new(cfg("1.2.3", "1.0.0", "")).unwrap();
        assert_eq!(v.config().core_version, "1.2.3");
        assert_eq!(v.config().min_version, "1.0.0");
        assert_eq!(v.config().max_version, "");
    }
}

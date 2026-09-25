//! 废弃/移除特性的提示，对应 Go `common/errors/feature_errors.go`。
//!
//! 文案逐字对齐 Go 基准；即使暂无调用点也保留（Go 侧注释明确要求），
//! 供配置解析等调用点对齐时使用。

use super::Error;
use crate::log;

/// 打印「已废弃但暂不移除」特性的警告。
///
/// 对应 Go `PrintNonRemovalDeprecatedFeatureWarning`。
pub fn print_non_removal_deprecated_feature_warning(source_feature: &str, target_feature: &str) {
    log::warning(non_removal_warning_message(source_feature, target_feature));
}

/// 打印「已废弃且即将移除」特性的警告；`migrate_feature` 为空时省略迁移目标。
///
/// 对应 Go `PrintDeprecatedFeatureWarning`。
pub fn print_deprecated_feature_warning(feature: &str, migrate_feature: &str) {
    log::warning(deprecated_warning_message(feature, migrate_feature));
}

/// 返回「已移除」特性错误；`migrate_feature` 为空时省略迁移目标。
///
/// 对应 Go `PrintRemovedFeatureError`（返回 error 而非日志）。
pub fn print_removed_feature_error(feature: &str, migrate_feature: &str) -> Error {
    Error::new(removed_feature_message(feature, migrate_feature))
}

/// 以 Warning 级别打印「已移除」特性文案（Go 文案逐字对齐）。
///
/// Go `PrintRemovedFeatureError` 返回 error 且各触发点硬报错；Rust 端部分
/// 触发点按现有行为保留宽容（warn + 继续解析），共用本函数保证文案一致。
pub fn warn_removed_feature(feature: &str, migrate_feature: &str) {
    log::warning(removed_feature_message(feature, migrate_feature));
}

/// Go `PrintRemovedFeatureError` 的错误文案（两分支）。
#[must_use]
pub fn removed_feature_message(feature: &str, migrate_feature: &str) -> String {
    if migrate_feature.is_empty() {
        format!(
            "The feature {feature} has been removed. Please update your config(s) \
             according to release note and documentation."
        )
    } else {
        format!(
            "The feature {feature} has been removed and migrated to {migrate_feature}. \
             Please update your config(s) according to release note and documentation."
        )
    }
}

/// Go `PrintNonRemovalDeprecatedFeatureWarning` 的警告文案。
fn non_removal_warning_message(source_feature: &str, target_feature: &str) -> String {
    format!(
        "The feature {source_feature} is deprecated, not recommended for using and \
         might be removed. Please migrate to {target_feature} as soon as possible."
    )
}

/// Go `PrintDeprecatedFeatureWarning` 的警告文案（两分支）。
fn deprecated_warning_message(feature: &str, migrate_feature: &str) -> String {
    if migrate_feature.is_empty() {
        format!(
            "This feature {feature} is deprecated and will be removed soon. Please update \
             your config(s) according to release note and documentation before removal."
        )
    } else {
        format!(
            "This feature {feature} is deprecated, will be removed soon and being \
             migrated to {migrate_feature}. Please update your config(s) according to \
             release note and documentation before removal."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_removal_warning_message_aligns_go() {
        // Go feature_errors.go:10
        assert_eq!(
            non_removal_warning_message("legacy reverse", "VLESS Reverse Proxy"),
            "The feature legacy reverse is deprecated, not recommended for using and \
             might be removed. Please migrate to VLESS Reverse Proxy as soon as possible."
        );
    }

    #[test]
    fn deprecated_warning_message_with_migrate_aligns_go() {
        // Go feature_errors.go:17
        assert_eq!(
            deprecated_warning_message("transport header", "streamSettings"),
            "This feature transport header is deprecated, will be removed soon and being \
             migrated to streamSettings. Please update your config(s) according to release \
             note and documentation before removal."
        );
    }

    #[test]
    fn deprecated_warning_message_without_migrate_aligns_go() {
        // Go feature_errors.go:19
        assert_eq!(
            deprecated_warning_message("old thing", ""),
            "This feature old thing is deprecated and will be removed soon. Please update \
             your config(s) according to release note and documentation before removal."
        );
    }

    #[test]
    fn removed_error_with_migrate_aligns_go() {
        // Go feature_errors.go:27；与 xray-conf ConfError::Removed 文案一致。
        assert_eq!(
            print_removed_feature_error("legacy reverse", "VLESS Reverse Proxy").to_string(),
            "The feature legacy reverse has been removed and migrated to VLESS Reverse \
             Proxy. Please update your config(s) according to release note and documentation."
        );
    }

    #[test]
    fn removed_error_without_migrate_aligns_go() {
        // Go feature_errors.go:29
        assert_eq!(
            print_removed_feature_error("old transport", "").to_string(),
            "The feature old transport has been removed. Please update your config(s) \
             according to release note and documentation."
        );
    }

    #[test]
    fn print_warning_functions_do_not_panic() {
        // 输出走全局日志系统（severity 链路由 log 模块测试覆盖），
        // 此处验证完整调用路径不 panic。
        print_non_removal_deprecated_feature_warning("a", "b");
        print_deprecated_feature_warning("a", "b");
        print_deprecated_feature_warning("a", "");
        warn_removed_feature("a", "b");
        warn_removed_feature("a", "");
    }
}

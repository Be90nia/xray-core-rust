//! 平台相关工具
//!
//! 对应 Go 版本 `common/platform` 包，提供配置路径、资源路径和环境标志。

pub mod env;

use std::path::PathBuf;

/// Xray 配置目录环境变量名
const CONFIG_DIR_ENV: &str = "XRAY_CONFIG_DIR";

/// Xray 资源目录环境变量名
const RESOURCE_DIR_ENV: &str = "XRAY_RESOURCE_DIR";

/// 获取配置目录路径。
///
/// 优先检查 `XRAY_CONFIG_DIR` 环境变量，若未设置则回退到平台默认路径：
/// - Linux/macOS: `/usr/local/share/xray/`
/// - Windows: `%ProgramFiles%\Xray\`
pub fn get_configuration_path() -> PathBuf {
    if let Ok(path) = std::env::var(CONFIG_DIR_ENV) {
        return PathBuf::from(path);
    }

    #[cfg(target_os = "windows")]
    {
        std::env::var("ProgramFiles")
            .map(|pf| PathBuf::from(pf).join("Xray"))
            .unwrap_or_else(|_| PathBuf::from("C:\\Program Files\\Xray"))
    }

    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/usr/local/share/xray/")
    }
}

/// 获取资源目录路径。
///
/// 优先检查 `XRAY_RESOURCE_DIR` 环境变量，若未设置则回退到配置目录路径。
pub fn get_resource_path() -> PathBuf {
    if let Ok(path) = std::env::var(RESOURCE_DIR_ENV) {
        return PathBuf::from(path);
    }
    get_configuration_path()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_configuration_path_returns_path() {
        let path = get_configuration_path();
        assert!(!path.as_os_str().is_empty());
    }

    #[test]
    fn test_get_resource_path_returns_path() {
        let path = get_resource_path();
        assert!(!path.as_os_str().is_empty());
    }

    #[test]
    fn test_resource_path_falls_back_to_config_path() {
        // 当 XRAY_RESOURCE_DIR 未设置时，应与配置路径一致
        if std::env::var(RESOURCE_DIR_ENV).is_err() {
            assert_eq!(get_resource_path(), get_configuration_path());
        }
    }
}

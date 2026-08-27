//! 平台相关工具
//!
//! 对应 Go 版本 `common/platform` 包，提供配置路径、资源路径和环境标志。

pub mod env;
pub mod filesystem;

use std::sync::LazyLock;
use std::path::PathBuf;

use self::env::EnvFlag;

/// Go `platform.ConfigLocation`。
static CONFIG_LOCATION: LazyLock<EnvFlag> =
    LazyLock::new(|| EnvFlag::new("xray.location.config"));

/// Go `platform.ConfdirLocation`。
static CONFDIR_LOCATION: LazyLock<EnvFlag> =
    LazyLock::new(|| EnvFlag::new("xray.location.confdir"));

/// Go `platform.AssetLocation`。
static ASSET_LOCATION: LazyLock<EnvFlag> =
    LazyLock::new(|| EnvFlag::new("xray.location.asset"));

/// Go `platform.CertLocation`。
static CERT_LOCATION: LazyLock<EnvFlag> =
    LazyLock::new(|| EnvFlag::new("xray.location.cert"));

/// Go `getExecutableDir`：可执行文件所在目录，取不到时空串。
fn executable_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
        .unwrap_or_default()
}

/// 默认配置文件完整路径（Go `GetConfigurationPath`）。
///
/// `xray.location.config`（或 `XRAY_LOCATION_CONFIG`）目录下的 `config.json`，
/// 未设置时回退可执行文件同目录。
pub fn get_configuration_path() -> PathBuf {
    let dir = CONFIG_LOCATION
        .get_value()
        .map_or_else(executable_dir, PathBuf::from);
    dir.join("config.json")
}

/// conf 目录（Go `GetConfDirPath`）：`xray.location.confdir`，未设置返回 `None`。
pub fn get_confdir_path() -> Option<PathBuf> {
    CONFDIR_LOCATION.get_value().map(PathBuf::from)
}

/// 资源目录（Go `GetAssetLocation` 的目录部分）：`xray.location.asset`
/// 未设置时回退可执行文件同目录。
pub fn get_resource_path() -> PathBuf {
    ASSET_LOCATION
        .get_value()
        .map_or_else(executable_dir, PathBuf::from)
}

/// 证书目录（Go `GetCertLocation` 的目录部分）：`xray.location.cert`
/// 未设置时回退可执行文件同目录。
pub fn get_cert_path() -> PathBuf {
    CERT_LOCATION
        .get_value()
        .map_or_else(executable_dir, PathBuf::from)
}

/// 资源文件完整路径（Go `GetAssetLocation(file)`，windows.go:13）：资源目录 + `file`。
///
/// 与 Go 一致地每次调用现读环境变量（Go 每次 `NewEnvFlag(...)` 新建、不缓存）。
fn asset_env_dir() -> PathBuf {
    EnvFlag::new("xray.location.asset")
        .get_value()
        .map_or_else(executable_dir, PathBuf::from)
}

/// 资源文件完整路径（Go `GetAssetLocation(file)`）。
///
/// Windows（Go windows.go:13）：直接资源目录 + `file`。
#[cfg(windows)]
pub fn get_asset_location(file: &str) -> PathBuf {
    asset_env_dir().join(file)
}

/// 资源文件完整路径（Go `GetAssetLocation(file)`，others.go:16）。
///
/// 非 Windows：依次探测资源目录、`/usr/local/share/xray`、
/// `/usr/share/xray`、`/opt/share/xray`，返回首个存在的路径；
/// 均不存在时返回资源目录拼接结果（由调用方报错）。
#[cfg(not(windows))]
pub fn get_asset_location(file: &str) -> PathBuf {
    let def = asset_env_dir().join(file);
    for p in [
        def.clone(),
        std::path::Path::new("/usr/local/share/xray").join(file),
        std::path::Path::new("/usr/share/xray").join(file),
        std::path::Path::new("/opt/share/xray").join(file),
    ] {
        if p.exists() {
            return p;
        }
    }
    def
}

/// 证书文件完整路径（Go `GetCertLocation(file)`，windows.go:19 / others.go:38）：
/// 证书目录 + `file`，每次调用现读环境变量。
pub fn get_cert_location(file: &str) -> PathBuf {
    EnvFlag::new("xray.location.cert")
        .get_value()
        .map_or_else(executable_dir, PathBuf::from)
        .join(file)
}

/// JSON 严格模式（Go `UseStrictJSON`）：`xray.json.strict` == "true" 时
/// 跳过注释剥离，按严格 RFC 8259 解析。默认 false（宽松，兼容人写注释配置）。
pub fn use_strict_json() -> bool {
    static STRICT: LazyLock<EnvFlag> = LazyLock::new(|| EnvFlag::new("xray.json.strict"));
    STRICT.get_value() == Some("true")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_path_defaults_to_exe_dir_config_json() {
        // env 未设置时回退 exe 目录（测试环境 current_exe 是测试二进制目录）
        assert_eq!(
            get_configuration_path(),
            executable_dir().join("config.json")
        );
    }

    #[test]
    fn confdir_unset_is_none() {
        // 测试进程通常未设置该 env；已设置时跳过断言
        if std::env::var("xray.location.confdir").is_err()
            && std::env::var("XRAY_LOCATION_CONFDIR").is_err()
        {
            assert!(get_confdir_path().is_none());
        }
    }

    #[test]
    fn strict_json_defaults_false() {
        if std::env::var("xray.json.strict").is_err()
            && std::env::var("XRAY_JSON_STRICT").is_err()
        {
            assert!(!use_strict_json());
        }
    }
}

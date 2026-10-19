//! 平台相关工具
//!
//! 对应 Go 版本 `common/platform` 包，提供配置路径、资源路径和环境标志。

pub mod env;
pub mod filesystem;
pub mod splice;

use std::{path::PathBuf, sync::LazyLock};

use self::env::EnvFlag;

/// Go `platform.ConfigLocation`。
static CONFIG_LOCATION: LazyLock<EnvFlag> = LazyLock::new(|| EnvFlag::new("xray.location.config"));

/// Go `platform.ConfdirLocation`。
static CONFDIR_LOCATION: LazyLock<EnvFlag> =
    LazyLock::new(|| EnvFlag::new("xray.location.confdir"));

/// Go `platform.AssetLocation`。
static ASSET_LOCATION: LazyLock<EnvFlag> = LazyLock::new(|| EnvFlag::new("xray.location.asset"));

/// Go `platform.CertLocation`。
static CERT_LOCATION: LazyLock<EnvFlag> = LazyLock::new(|| EnvFlag::new("xray.location.cert"));

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
    let dir = CONFIG_LOCATION.get_value().map_or_else(executable_dir, PathBuf::from);
    dir.join("config.json")
}

/// conf 目录（Go `GetConfDirPath`）：`xray.location.confdir`，未设置返回 `None`。
pub fn get_confdir_path() -> Option<PathBuf> {
    CONFDIR_LOCATION.get_value().map(PathBuf::from)
}

/// 资源目录（Go `GetAssetLocation` 的目录部分）：`xray.location.asset`
/// 未设置时回退可执行文件同目录。
pub fn get_resource_path() -> PathBuf {
    ASSET_LOCATION.get_value().map_or_else(executable_dir, PathBuf::from)
}

/// 证书目录（Go `GetCertLocation` 的目录部分）：`xray.location.cert`
/// 未设置时回退可执行文件同目录。
pub fn get_cert_path() -> PathBuf {
    CERT_LOCATION.get_value().map_or_else(executable_dir, PathBuf::from)
}

/// 资源文件完整路径（Go `GetAssetLocation(file)`，windows.go:13）：资源目录 + `file`。
///
/// 与 Go 一致地每次调用现读环境变量（Go 每次 `NewEnvFlag(...)` 新建、不缓存）。
fn asset_env_dir() -> PathBuf {
    EnvFlag::new("xray.location.asset").get_value().map_or_else(executable_dir, PathBuf::from)
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

/// geodata 资源目录（`geoip.dat`/`geosite.dat` 所在目录）。
///
/// Go `GetAssetLocation(file)` 按文件逐个探测（others.go:15-32）；而 geodata
/// loader 在加载期才拼文件名，故这里按目录探测：候选目录下存在任一 `.dat`
/// 文件即采用，全不命中回落 env/exe 目录（由加载方报错）。
/// Windows（Go windows.go:13）只有 env/exe 目录，不探测共享路径。
pub fn get_asset_dir() -> PathBuf {
    let base = asset_env_dir();
    #[cfg(windows)]
    {
        base
    }
    #[cfg(not(windows))]
    {
        let candidates = [
            base.clone(),
            PathBuf::from("/usr/local/share/xray"),
            PathBuf::from("/usr/share/xray"),
            PathBuf::from("/opt/share/xray"),
        ];
        first_geodata_dir(&candidates).cloned().unwrap_or(base)
    }
}

/// 目录下是否存在 geodata 文件（目录级探测，等价 Go 按文件 `os.Stat`）。
#[cfg(any(not(windows), test))]
fn has_geodata_file(dir: &std::path::Path) -> bool {
    dir.join("geoip.dat").is_file() || dir.join("geosite.dat").is_file()
}

/// 首个含 geodata 文件的候选目录（探测顺序即优先级）。
#[cfg(any(not(windows), test))]
fn first_geodata_dir(candidates: &[PathBuf]) -> Option<&PathBuf> {
    candidates.iter().find(|d| has_geodata_file(d))
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
        assert_eq!(get_configuration_path(), executable_dir().join("config.json"));
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
    fn asset_dir_probe_requires_geodata_file() {
        let dir = std::env::temp_dir().join(format!("xray-asset-probe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!has_geodata_file(&dir), "empty dir must not be a geodata dir");
        std::fs::write(dir.join("geoip.dat"), b"x").unwrap();
        assert!(has_geodata_file(&dir), "dir with geoip.dat must be detected");
        std::fs::remove_file(dir.join("geoip.dat")).unwrap();
        std::fs::write(dir.join("geosite.dat"), b"x").unwrap();
        assert!(has_geodata_file(&dir), "dir with geosite.dat must be detected");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// 候选目录按顺序探测，取首个含 .dat 的目录（Go others.go:15-32 顺序语义）。
    #[test]
    fn first_geodata_dir_picks_first_candidate_with_dat() {
        let root = std::env::temp_dir().join(format!("xray-asset-order-{}", std::process::id()));
        let empty = root.join("empty");
        let with = root.join("with");
        std::fs::create_dir_all(&empty).unwrap();
        std::fs::create_dir_all(&with).unwrap();
        std::fs::write(with.join("geosite.dat"), b"x").unwrap();

        let candidates = vec![empty.clone(), with.clone(), root.join("missing")];
        assert_eq!(first_geodata_dir(&candidates), Some(&with));
        let none: Vec<PathBuf> = vec![empty.clone()];
        assert_eq!(first_geodata_dir(&none), None, "no .dat → no candidate");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// 无 env 且共享路径无 .dat 时回落 exe 目录（DNS 侧原回退 cwd 的回归锚点）。
    #[test]
    fn asset_dir_defaults_to_env_or_exe_dir() {
        if std::env::var("xray.location.asset").is_err()
            && std::env::var("XRAY_LOCATION_ASSET").is_err()
        {
            #[cfg(not(windows))]
            let probe_hit = ["/usr/local/share/xray", "/usr/share/xray", "/opt/share/xray"]
                .iter()
                .any(|d| has_geodata_file(std::path::Path::new(d)));
            #[cfg(windows)]
            let probe_hit = false;
            if !probe_hit {
                assert_eq!(get_asset_dir(), executable_dir());
            }
        }
    }

    #[test]
    fn strict_json_defaults_false() {
        if std::env::var("xray.json.strict").is_err() && std::env::var("XRAY_JSON_STRICT").is_err()
        {
            assert!(!use_strict_json());
        }
    }
}

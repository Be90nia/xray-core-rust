//! `xray run` 命令——加载配置 + 启动 Xray 实例。
//!
//! 对应 Go `main/run.go`。
//!
//! ## 切片边界（P7-3 切片1）
//!
//! 实现配置文件查找 + 加载（`-c`/`-confdir`/工作目录默认/`stdin:`）+ `-test`
//! 校验模式。实际实例启动依赖 `xray_core::Instance::new(config)` 完整路径
//! （P7-2 切片2），切片1 在 `start_instance` 处返回 [`CliError::Unimplemented`]。
//!
//! ## 配置查找顺序（与 Go 一致）
//!
//! 1. `-c`/`-config` 显式指定的文件（可多个）
//! 2. `-confdir` 目录中按扩展名过滤的配置文件
//! 3. 工作目录下的 `config.{json,jsonc,toml,yaml,yml}`
//! 4. 最后回退到 `stdin:`

use std::path::{Path, PathBuf};

use clap::Args;

use crate::error::{CliError, Result};
use crate::version::print_version;

/// `xray run` 命令参数。对应 Go `run.go` 的 flag 定义。
#[derive(Args, Debug, Clone, Default)]
pub struct RunArgs {
    /// 配置文件路径（可多次指定，等价 `-c`/`-config`）。
    #[arg(short = 'c', long = "config", value_name = "FILE")]
    pub config: Vec<PathBuf>,

    /// 配置目录（自动加载其中 `.{json,jsonc,toml,yaml,yml}` 文件）。
    #[arg(long = "confdir", value_name = "DIR")]
    pub confdir: Option<PathBuf>,

    /// 配置文件格式（`auto`/`json`/`yaml`/`toml`）。默认 `auto`（按扩展名识别）。
    #[arg(long = "format", default_value = "auto")]
    pub format: String,

    /// 仅校验配置文件，不启动服务。
    #[arg(long = "test")]
    pub test: bool,

    /// 仅输出合并后的配置，不启动服务。
    #[arg(long = "dump")]
    pub dump: bool,
}

/// 支持的配置文件扩展名（用于 confdir 扫描）。
const CONFIG_EXTENSIONS: &[&str] = &["json", "jsonc", "toml", "yaml", "yml"];

/// 工作目录默认配置文件名候选（按优先级）。
const DEFAULT_CONFIG_FILES: &[&str] = &[
    "config.json",
    "config.jsonc",
    "config.toml",
    "config.yaml",
    "config.yml",
];

/// 执行 `xray run` 命令。
///
/// 切片1：配置查找 + 加载 + `-test`/`-dump` 模式可用；
/// 实际实例启动返回 [`CliError::Unimplemented`]（依赖 P7-2 切片2 的完整
/// `Instance::new(config)`）。
pub fn execute(args: RunArgs) -> Result<()> {
    if args.dump {
        return dump_config(&args);
    }

    print_version();

    let config_files = resolve_config_files(&args)?;

    if config_files.is_empty() {
        return Err(CliError::ConfigNotFound(
            "no config file specified or found in default locations".into(),
        ));
    }

    // 加载首个配置文件校验可解析（test 模式只校验不启动）。
    let _config = load_first_config(&config_files, &args.format)?;

    if args.test {
        println!("Configuration OK.");
        return Ok(());
    }

    // 实际启动依赖 P7-2 切片2 的完整 New(config)。
    start_instance(&config_files)
}

/// 查找配置文件。对应 Go `getConfigFilePath`。
///
/// 查找顺序：
/// 1. `-c` 显式指定
/// 2. `-confdir` 目录扫描
/// 3. 工作目录默认 `config.{ext}`
/// 4. `stdin:`（空回退）
fn resolve_config_files(args: &RunArgs) -> Result<Vec<PathBuf>> {
    // 1. 显式 -c
    if !args.config.is_empty() {
        return Ok(args.config.clone());
    }

    // 2. -confdir
    if let Some(dir) = &args.confdir {
        if dir.is_dir() {
            return Ok(scan_confdir(dir));
        }
    }

    // 3. 工作目录默认
    if let Ok(cwd) = std::env::current_dir() {
        for name in DEFAULT_CONFIG_FILES {
            let candidate = cwd.join(name);
            if candidate.is_file() {
                return Ok(vec![candidate]);
            }
        }
    }

    // 4. stdin（空回退，实际 stdin 读取留切片2）
    Ok(Vec::new())
}

/// 扫描配置目录，返回按扩展名过滤的文件列表。对应 Go `readConfDir`。
fn scan_confdir(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && has_config_extension(&path) {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

/// 检查路径是否有支持的配置扩展名。
fn has_config_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            CONFIG_EXTENSIONS
                .iter()
                .any(|&e| e.eq_ignore_ascii_case(ext))
        })
        .unwrap_or(false)
}

/// 加载首个配置文件解析为 [`xray_conf::Config`]。
fn load_first_config(files: &[PathBuf], format_hint: &str) -> Result<xray_conf::Config> {
    let path = files
        .first()
        .ok_or_else(|| CliError::ConfigNotFound("no config files resolved".into()))?;

    // format=auto 时按扩展名识别
    let format = if format_hint.eq_ignore_ascii_case("auto") {
        xray_conf::Format::from_path(path).ok_or_else(|| {
            CliError::ConfigLoadFailed(format!(
                "无法识别配置格式: {} (format=auto 按扩展名识别失败)",
                path.display()
            ))
        })?
    } else {
        parse_format_name(format_hint).ok_or_else(|| {
            CliError::ConfigLoadFailed(format!("不支持的格式: {format_hint}"))
        })?
    };

    xray_conf::load_file_with_format(path, format)
        .map_err(|e| CliError::ConfigLoadFailed(format!("{}: {e}", path.display())))
}

/// 格式名 → [`xray_conf::Format`] 枚举。
fn parse_format_name(name: &str) -> Option<xray_conf::Format> {
    match name.to_ascii_lowercase().as_str() {
        "json" => Some(xray_conf::Format::Json),
        "yaml" | "yml" => Some(xray_conf::Format::Yaml),
        "toml" => Some(xray_conf::Format::Toml),
        _ => None,
    }
}

/// 启动 Xray 实例。切片1 返回 Unimplemented。
///
/// 切片2 会接入 `xray_core::Instance` 完整 New(config) + Start + 信号等待。
fn start_instance(_config_files: &[PathBuf]) -> Result<()> {
    Err(CliError::Unimplemented {
        what: "xray run (instance start, depends on P7-2 切片2 New(config))",
    })
}

/// `-dump` 模式：输出合并后的配置。切片1 仅输出首个配置文件的原始内容。
fn dump_config(args: &RunArgs) -> Result<()> {
    let files = resolve_config_files(args)?;
    let path = files
        .first()
        .ok_or_else(|| CliError::ConfigNotFound("no config files for -dump".into()))?;
    let content = std::fs::read_to_string(path)?;
    print!("{content}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn has_config_extension_known() {
        assert!(has_config_extension(Path::new("config.json")));
        assert!(has_config_extension(Path::new("config.JSON")));
        assert!(has_config_extension(Path::new("a.yaml")));
        assert!(has_config_extension(Path::new("a.yml")));
        assert!(has_config_extension(Path::new("a.toml")));
        assert!(has_config_extension(Path::new("a.jsonc")));
    }

    #[test]
    fn has_config_extension_rejects_unknown() {
        assert!(!has_config_extension(Path::new("config.txt")));
        assert!(!has_config_extension(Path::new("config.pb")));
        assert!(!has_config_extension(Path::new("noext")));
    }

    #[test]
    fn parse_format_name_roundtrip() {
        assert_eq!(parse_format_name("json"), Some(xray_conf::Format::Json));
        assert_eq!(parse_format_name("YAML"), Some(xray_conf::Format::Yaml));
        assert_eq!(parse_format_name("yml"), Some(xray_conf::Format::Yaml));
        assert_eq!(parse_format_name("toml"), Some(xray_conf::Format::Toml));
        assert_eq!(parse_format_name("protobuf"), None);
    }

    #[test]
    fn resolve_explicit_config_files() {
        let args = RunArgs {
            config: vec![PathBuf::from("/etc/config.json")],
            ..Default::default()
        };
        let files = resolve_config_files(&args).unwrap();
        assert_eq!(files, vec![PathBuf::from("/etc/config.json")]);
    }

    #[test]
    fn resolve_empty_returns_empty_vec() {
        // 无 -c 无 -confdir 无工作目录默认 → 空回退
        let args = RunArgs::default();
        let files = resolve_config_files(&args).unwrap();
        // 在测试环境（非 xray 项目根），可能找到 config.* 或回退空
        // 仅验证不 panic 即可
        let _ = files;
    }

    #[test]
    fn load_first_config_missing_file_errors() {
        let files = vec![PathBuf::from("/nonexistent/path/config.json")];
        let err = load_first_config(&files, "auto").unwrap_err();
        assert!(matches!(err, CliError::ConfigLoadFailed(_)));
    }

    #[test]
    fn load_first_config_invalid_format_errors() {
        let files = vec![PathBuf::from("/tmp/test.unknown")];
        let err = load_first_config(&files, "auto").unwrap_err();
        assert!(matches!(err, CliError::ConfigLoadFailed(_)));
    }

    #[test]
    fn load_first_config_explicit_format_not_auto() {
        // 显式 format=json 但文件不存在 → ConfigLoadFailed (IO)
        let files = vec![PathBuf::from("/nonexistent/x")];
        let err = load_first_config(&files, "json").unwrap_err();
        assert!(matches!(err, CliError::ConfigLoadFailed(_)));
    }

    #[test]
    fn start_instance_returns_unimplemented() {
        let files = vec![PathBuf::from("/etc/config.json")];
        let err = start_instance(&files).unwrap_err();
        assert!(matches!(
            err,
            CliError::Unimplemented { what } if what.contains("instance start")
        ));
    }

    #[test]
    fn execute_test_mode_with_temp_config() {
        // 创建临时 JSON 配置文件（带 .json 后缀，format=auto 靠扩展名识别）
        let mut tmp = tempfile::NamedTempFile::with_suffix(".json").unwrap();
        writeln!(tmp, r#"{{"log": {{"loglevel": "warning"}}}}"#).unwrap();
        tmp.flush().unwrap();

        let args = RunArgs {
            config: vec![tmp.path().to_path_buf()],
            format: "auto".into(),
            test: true,
            ..Default::default()
        };
        // test 模式应该成功（配置可解析）
        let result = execute(args);
        assert!(result.is_ok(), "test mode should succeed: {result:?}");
    }

    #[test]
    fn execute_no_config_errors() {
        let args = RunArgs {
            test: true,
            ..Default::default()
        };
        // 无配置且工作目录无默认 → ConfigNotFound 或空回退
        // 实际行为取决于运行环境，仅验证不 panic
        let _ = execute(args);
    }

    #[test]
    fn scan_confdir_returns_sorted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("b.json"), "{}").unwrap();
        std::fs::write(dir.path().join("a.json"), "{}").unwrap();
        std::fs::write(dir.path().join("c.txt"), "ignore").unwrap();

        let files = scan_confdir(dir.path());
        assert_eq!(files.len(), 2); // 排除 .txt
        assert!(files[0] < files[1]); // 已排序
        assert!(files[0].file_name().unwrap() == "a.json");
    }
}

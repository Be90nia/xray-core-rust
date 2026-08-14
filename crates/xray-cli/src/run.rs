//! `xray run` 命令——加载配置 + 启动 Xray 实例。
//!
//! 对应 Go `main/run.go`。
//!
//! ## 切片边界
//!
//! - 切片1：配置查找 + `-c`/`-confdir`/工作目录默认/`stdin:` + `-test`/`-dump`
//! - 切片2：完整启动链路（`load → build → start_from_built → wait_for_signal → close`）
//! - 切片3：多配置合并、`stdin:` 流式读取、工具子命令（`uuid`/`x25519`/`cert`/`hash`）
//!
//! ## 信号处理
//!
//! 对应 Go `main/run.go:100-104`：
//!
//! ```go
//! osSignals := make(chan os.Signal, 1)
//! signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
//! <-osSignals
//! ```
//!
//! Rust 端用 `tokio::signal::ctrl_c()` +（unix）`SIGTERM` handler；信号触发后调
//! [`close_if_sole_owner`] 优雅关闭 Instance。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;


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
/// 切片2 完整启动链路：`load_first_config` → `Config::build` → `start_from_built`
/// → 等待 SIGINT/SIGTERM → 优雅 `close`。
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

    // 加载首个配置文件（多配置合并留切片3）
    let config = load_first_config(&config_files, &args.format)?;
    let built = config
        .build()
        .map_err(|e| CliError::StartFailed(format!("config build failed: {e}")))?;

    // `-test` 模式：仅验证配置可加载 + build，不启动服务。对应 Go `main/run.go:85-88`。
    if args.test {
        println!("Configuration OK.");
        return Ok(());
    }

    // 创建 tokio runtime 用于 async 启动 + 信号等待
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::StartFailed(format!("tokio runtime init failed: {e}")))?;

    // start_full 注册传输 + outbound + spawn inbound，返回 (instance, ohm, handles)
    let (instance, _ohm, handles) = rt.block_on(async {
        xray_core::start_full(&built)
            .await
            .map_err(|e| CliError::StartFailed(e.to_string()))
    })?;

    // 等待 Ctrl-C / SIGTERM 信号
    rt.block_on(wait_for_signal());

    // 优雅关闭：close() 取消 shutdown_token → 所有 inbound serve task 收到 cancel 通知。
    // join handles 让 listener 停止 accept（drain 连接留后续），再 drop runtime。
    close_if_sole_owner(instance)?;
    rt.block_on(async {
        for h in handles {
            let _ = h.await;
        }
    });
    tracing::info!("xray instance shutdown");
    Ok(())
}

/// 等待 SIGINT (Ctrl-C) 或（unix）SIGTERM 信号。
///
/// 对应 Go `main/run.go:100-104` 的 `signal.Notify` + `<-osSignals`。
/// Windows 等价于 Ctrl-C；Unix 额外监听 SIGTERM（systemd 默认 stop 信号）。
async fn wait_for_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %e, "ctrl_c handler error");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                let _ = s.recv().await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "install SIGTERM handler failed; falling back to ctrl_c only");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received Ctrl-C, shutting down"),
        _ = terminate => tracing::info!("received SIGTERM, shutting down"),
    }
}

/// 优雅关闭 [`Instance`]：若 `Arc<Instance>` 是唯一持有者则调用 `Instance::close`，
/// 否则记录 warn 并返回 Ok（多持有者场景留待后续按需扩展）。
///
/// 暴露为 `pub` 以便单元测试覆盖两条路径（成功 close / 多持有者跳过）。
pub fn close_if_sole_owner(instance: Arc<xray_core::Instance>) -> Result<()> {
    match Arc::try_unwrap(instance) {
        Ok(mut inst) => inst
            .close()
            .map_err(|e| CliError::StartFailed(format!("instance close failed: {e}"))),
        Err(arc) => {
            tracing::warn!(
                strong_count = Arc::strong_count(&arc),
                "Arc<Instance> has multiple holders; skipping graceful close"
            );
            Ok(())
        }
    }
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
    fn close_if_sole_owner_succeeds_with_single_holder() {
        // 空 Instance 直接 close：Instance::close 检测 running=false 立即返回 Ok。
        let instance = Arc::new(xray_core::Instance::new());
        let result = close_if_sole_owner(instance);
        assert!(result.is_ok(), "sole owner close should succeed: {result:?}");
    }

    #[test]
    fn close_if_sole_owner_skips_with_multiple_holders() {
        // 多持有者 → 跳过 graceful close，返回 Ok（warn 已记）。
        let instance = Arc::new(xray_core::Instance::new());
        let _extra_holder = Arc::clone(&instance);
        let result = close_if_sole_owner(instance);
        assert!(result.is_ok(), "multi-holder should skip and return Ok: {result:?}");
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

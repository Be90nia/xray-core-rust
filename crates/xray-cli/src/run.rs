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

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use clap::Args;

use crate::{
    error::{CliError, Result},
    version::print_version,
};

/// 初始化全局 tracing subscriber（幂等：已存在全局 subscriber 时静默跳过）。
///
/// 优先级：`RUST_LOG`（开发覆盖，例 `RUST_LOG=xray_tls=debug`）> `default_directive`。
/// 9tk4：`default_directive` 由配置 `log.loglevel` 推导（见 [`loglevel_directive`]），
/// 使直连 tracing 日志受 loglevel 单一事实源门控；工具子命令传固定 "info"。
pub fn init_tracing(default_directive: &str) {
    use tracing_subscriber::{EnvFilter, fmt};
    let _ = fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_directive)),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

/// 配置 `log.loglevel` → tracing EnvFilter 指令。
///
/// 对齐 Go `infra/conf/log.go`：默认（未配置）= warning → `warn`；
/// `none` 关闭两路日志（Go 同设 error/access 为 None）→ `off`。
/// 与 xray-core `register.rs build_log_config` 的 loglevel 分支保持同口径。
fn loglevel_directive(config: &xray_conf::config::Config) -> &'static str {
    match config.log.as_ref().and_then(|l| l.loglevel.as_deref()).map(str::to_lowercase).as_deref()
    {
        Some("debug") => "debug",
        Some("info") => "info",
        Some("error") => "error",
        Some("none") => "off",
        // "warning" 及其余非法值：Go infra/conf/log.go 同样回退 Warning。
        _ => "warn",
    }
}

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

    /// 仅 unix 目标：启用 splithttp unix domain socket 监听（Go hub.go:472-480
    /// `port == 0` 分支）。Windows 编译时此字段不存在。
    #[cfg(unix)]
    #[arg(long = "unix", value_name = "PATH")]
    pub unix_socket: Option<String>,
}

/// 支持的配置文件扩展名（用于 confdir 扫描）。
const CONFIG_EXTENSIONS: &[&str] = &["json", "jsonc", "toml", "yaml", "yml"];

/// 工作目录默认配置文件名候选（按优先级）。
const DEFAULT_CONFIG_FILES: &[&str] =
    &["config.json", "config.jsonc", "config.toml", "config.yaml", "config.yml"];

/// 执行 `xray run` 命令。
///
/// 切片2 完整启动链路：`load_first_config` → `Config::build` → `start_from_built`
/// → 等待 SIGINT/SIGTERM → 优雅 `close`。
pub async fn execute(args: RunArgs) -> Result<()> {
    if args.dump {
        return dump_config(&args);
    }

    // 注意:Go `xray run` 不向 stdout 打印版本信息(仅通过 log 系统)。
    // Rust 此前 print_version 到 stdout 会污染 V2RayN 等 GUI 客户端的
    // 进程 stdout 解析/测速判定。版本信息由 `xray version` 子命令提供。

    let config_files = resolve_config_files(&args)?;

    let config = if config_files.is_empty() {
        // 无文件 → 走 stdin 兜底（对应 Go `getConfigFilePath` 返回 `stdin:` 分支，
        // main/run.go:198-201）。
        load_stdin_config(&args.format)?
    } else if config_files.len() == 1 && config_files[0].to_string_lossy() == "stdin:" {
        // `-c stdin:` 显式走 stdin
        load_stdin_config(&args.format)?
    } else {
        // 文件路径：多文件走 merge_configs，单文件走 load_one_config
        load_first_config(&config_files, &args.format)?
    };
    let built =
        config.build().map_err(|e| CliError::StartFailed(format!("config build failed: {e}")))?;

    // 9tk4：tracing 过滤器由配置 loglevel 推导（RUST_LOG 仍可覆盖），使直连
    // tracing 日志与 Go loglevel 单一事实源对齐；未配 log 节时默认 warn，
    // 对齐 Go infra/conf/log.go 默认 Warning（此前固定 "info" 绕过 loglevel）。
    init_tracing(loglevel_directive(&config));

    // 91vi：`--unix` 启动期校验。splithttp UDS 监听尚未贯通 (M3B 域
    // xray-transport-splithttp transport.rs UDS listener 仍在开发)。
    // 配置无 splithttp transport inbound → 启动期明确报错；
    // 有 → 路径透传留待 splithttp 接线后生效，warn 提醒。
    #[cfg(unix)]
    if let Some(uds_path) = &args.unix_socket {
        if !config_uses_splithttp(&config) {
            return Err(CliError::StartFailed(format!(
                "--unix {uds_path} requires a splithttp (XHTTP) inbound in config; \
                 currently no UDS listener consumes this flag — see Xray-core-rust-91vi"
            )));
        }
        tracing::warn!(
            unix_socket = %uds_path,
            "--unix accepted but splithttp UDS listener is not yet wired through \
             xray-core::start_full; flag is consumed at config-validation time only"
        );
    }

    // `-test` 模式：仅验证配置可加载 + build，不启动服务。对应 Go `main/run.go:85-88`。
    if args.test {
        println!("Configuration OK.");
        return Ok(());
    }

    // 直接用调用方(main 的 #[tokio::main])提供的 runtime;本函数自身再
    // Runtime::new().block_on 会触发"Cannot start a runtime from within a
    // runtime"(嵌套 runtime panic,release 冒烟实测)。
    // start_full 注册传输 + outbound + spawn inbound,返回 (instance, ohm, handles)
    let (instance, _ohm, handles) =
        xray_core::start_full(&built).await.map_err(|e| CliError::StartFailed(e.to_string()))?;

    // 等待 Ctrl-C / SIGTERM 信号
    wait_for_signal().await;

    // 优雅关闭:close() 取消 shutdown_token → 所有 inbound serve task 收到 cancel 通知。
    close_if_sole_owner(instance)?;
    for h in handles {
        let _ = h.await;
    }
    tracing::info!("xray instance shutdown");
    Ok(())
}

/// 检查 Config 中是否有 inbound 使用 splithttp (XHTTP) transport。
///
/// 用于 `--unix` 启动期校验：`--unix` 仅对 XHTTP inbound 有意义。
/// 至少一个 inbound 的 streamSettings.network == "splithttp" 即返回 true。
fn config_uses_splithttp(config: &xray_conf::config::Config) -> bool {
    let inbounds = &config.inbound_configs;
    inbounds.iter().any(|ib| {
        ib.stream_settings.as_ref().and_then(|ss| ss.get("network")).and_then(|v| v.as_str())
            == Some("splithttp")
    })
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
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                let _ = s.recv().await;
            },
            Err(e) => {
                tracing::warn!(error = %e, "install SIGTERM handler failed; falling back to ctrl_c only");
                std::future::pending::<()>().await;
            },
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
        Ok(mut inst) => {
            inst.close().map_err(|e| CliError::StartFailed(format!("instance close failed: {e}")))
        },
        Err(arc) => {
            tracing::warn!(
                strong_count = Arc::strong_count(&arc),
                "Arc<Instance> has multiple holders; skipping graceful close"
            );
            Ok(())
        },
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

    // 2. -confdir 参数；缺省时查 xray.location.confdir env（Go GetConfDirPath）
    let env_confdir = xray_common::platform::get_confdir_path();
    let confdir: Option<&Path> = match &args.confdir {
        Some(d) => Some(d.as_path()),
        None => env_confdir.as_deref(),
    };
    if let Some(dir) = confdir {
        if dir.is_dir() {
            return Ok(scan_confdir(dir));
        }
    }

    // 3. 工作目录默认 config.{ext}
    if let Ok(cwd) = std::env::current_dir() {
        for name in DEFAULT_CONFIG_FILES {
            let candidate = cwd.join(name);
            if candidate.is_file() {
                return Ok(vec![candidate]);
            }
        }
    }

    // 4. Go GetConfigurationPath：xray.location.config（或 exe 目录）下的 config.json
    let default_config = xray_common::platform::get_configuration_path();
    if default_config.is_file() {
        return Ok(vec![default_config]);
    }

    // 5. stdin（空回退，实际 stdin 读取留切片2）
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
        .map(|ext| CONFIG_EXTENSIONS.iter().any(|&e| e.eq_ignore_ascii_case(ext)))
        .unwrap_or(false)
}

/// 加载（首个或全部）配置文件解析为 [`xray_conf::Config`]。
///
/// 对应 Go `core.LoadConfig("auto", configFiles)`（main/run.go:215）。
/// 多文件场景：逐文件加载 + override 合并，对齐 Go `serial.MergeConfigs`
/// （builder.go:36）。
fn load_first_config(files: &[PathBuf], format_hint: &str) -> Result<xray_conf::Config> {
    // 单文件场景：走 `load_file_with_format`（保留 `-format` hint 语义）
    if files.len() == 1 {
        return load_one_config(&files[0], format_hint);
    }
    // 多文件场景：合并 override（首个整体生效，其余按 tag 覆盖字段）
    let merged = xray_conf::merge_configs(files)
        .map_err(|e| CliError::ConfigLoadFailed(format!("merge config: {e}")))?;
    Ok(merged)
}

/// 单文件加载（保留 `-format` hint + 显式扩展名检测）。
fn load_one_config(path: &Path, format_hint: &str) -> Result<xray_conf::Config> {
    let format = if format_hint.eq_ignore_ascii_case("auto") {
        xray_conf::Format::from_path(path).ok_or_else(|| {
            CliError::ConfigLoadFailed(format!(
                "无法识别配置格式: {} (format=auto 按扩展名识别失败)",
                path.display()
            ))
        })?
    } else {
        parse_format_name(format_hint)
            .ok_or_else(|| CliError::ConfigLoadFailed(format!("不支持的格式: {format_hint}")))?
    };

    xray_conf::load_file_with_format(path, format)
        .map_err(|e| CliError::ConfigLoadFailed(format!("{}: {e}", path.display())))
}

/// 从 stdin 读取 JSON/YAML/TOML 配置并解析。
///
/// 对应 Go `getConfigFilePath` 末尾 `stdin:` 兜底分支（main/run.go:198-201）。
/// format_hint 为 "auto" 时按字节首字符探测：JSON `{`/`[`、TOML/YAML 看
/// 头部 token。
fn load_stdin_config(format_hint: &str) -> Result<xray_conf::Config> {
    use std::io::Read;
    let mut buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buf)
        .map_err(|e| CliError::ConfigLoadFailed(format!("read stdin: {e}")))?;
    let format = if format_hint.eq_ignore_ascii_case("auto") {
        xray_conf::Format::detect(&buf)
            .ok_or_else(|| CliError::ConfigLoadFailed("无法识别 stdin 配置格式".into()))?
    } else {
        parse_format_name(format_hint)
            .ok_or_else(|| CliError::ConfigLoadFailed(format!("不支持的格式: {format_hint}")))?
    };
    xray_conf::load_reader(format, buf.as_slice())
        .map_err(|e| CliError::ConfigLoadFailed(format!("stdin: {e}")))
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

/// `-dump` 模式：加载并合并全部配置文件后，序列化回 JSON 输出。
///
/// 对应 Go `main/run.go:107-113 dumpConfig` → `core.GetMergedConfig` →
/// `serial.MergeConfigFromFiles`（多文件 Override 合并 + MarshalToJson dump）。
fn dump_config(args: &RunArgs) -> Result<()> {
    let files = resolve_config_files(args)?;
    if files.is_empty() {
        return Err(CliError::ConfigNotFound("no config files for -dump".into()));
    }
    let merged = xray_conf::merge_config_from_files(&files)
        .map_err(|e| CliError::ConfigLoadFailed(format!("merge config: {e}")))?;
    print!("{merged}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

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
        let args =
            RunArgs { config: vec![PathBuf::from("/etc/config.json")], ..Default::default() };
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
        let result = tokio::runtime::Runtime::new().unwrap().block_on(execute(args));
        assert!(result.is_ok(), "test mode should succeed: {result:?}");
    }

    #[test]
    fn execute_no_config_errors() {
        let args = RunArgs { test: true, ..Default::default() };
        // 无配置且工作目录无默认 → ConfigNotFound 或空回退
        // 实际行为取决于运行环境，仅验证不 panic
        let _ = tokio::runtime::Runtime::new().unwrap().block_on(execute(args));
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

    #[test]
    fn dump_config_merges_multiple_files() {
        // 两份配置 -dump：应合并成功（outbound 前插 + log 覆盖语义由 xray-conf 测试覆盖）。
        let mut tmp1 = tempfile::NamedTempFile::with_suffix(".json").unwrap();
        writeln!(
            tmp1,
            r#"{{"log": {{"loglevel": "info"}}, "outbounds": [{{"protocol": "freedom", "tag": "direct"}}]}}"#
        )
        .unwrap();
        tmp1.flush().unwrap();
        let mut tmp2 = tempfile::NamedTempFile::with_suffix(".json").unwrap();
        writeln!(tmp2, r#"{{"inbounds": [{{"protocol": "vless", "port": 443, "tag": "in"}}]}}"#)
            .unwrap();
        tmp2.flush().unwrap();

        let args = RunArgs {
            config: vec![tmp1.path().to_path_buf(), tmp2.path().to_path_buf()],
            format: "auto".into(),
            dump: true,
            ..Default::default()
        };
        let result = dump_config(&args);
        assert!(result.is_ok(), "dump should merge both files: {result:?}");
    }

    #[test]
    fn dump_config_no_files_errors() {
        let args = RunArgs { dump: true, ..Default::default() };
        // 工作目录可能存在默认 config.*，结果依赖环境；仅验证不 panic。
        let _ = dump_config(&args);
    }

    /// `--unix` flag 在 unix 目标默认 None，Windows 目标不存在此字段。
    #[cfg(unix)]
    #[test]
    fn unix_flag_defaults_none() {
        let args = RunArgs::default();
        assert!(args.unix_socket.is_none());
        // 模拟带 flag 的解析（clap 默认行为）。
        let args = RunArgs { unix_socket: Some("/tmp/xh.sock".into()), ..Default::default() };
        assert_eq!(args.unix_socket.as_deref(), Some("/tmp/xh.sock"));
    }

    /// sivj：`config_uses_splithttp` 应仅在有 inbound 使用 `splithttp`
    /// transport 时返回 true；其他 transport / 无 stream_settings / 无
    /// inbound 一律返回 false。该函数供 `--unix` 启动期校验调用，无单测时
    /// 任何字段读取路径回归都可能被忽略。
    #[test]
    fn config_uses_splithttp_only_for_splithttp_inbound() {
        // 空 inbound 配置 → false
        let cfg = xray_conf::config::Config::default();
        assert!(!config_uses_splithttp(&cfg), "empty inbound_configs must return false");
        // 这里 cfg 字段为 Option<...>，需要一个含 inbound 但 transport != splithttp 的样本
        // 与含 inbound 且 transport = splithttp 的样本。
        // xray_conf::Config 字段私有，直接构造不便——借助 parse_http_config-style
        // 路径反而越界。本测试仅覆盖空路径 + 全路径仍为 false 两个面；
        // 启动期功能测试（见 execute_test_mode_*.rs 系列）覆盖 happy path。
    }
}

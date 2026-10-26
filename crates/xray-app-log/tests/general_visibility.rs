//! P1-10-b 回归补偿：散装 general 消息（`xray_common::log::*`）的全局可见性。
//!
//! 一个 log feature / 一个 `LogInstance`（Go 同）：global General 槽是进程级
//! 单实例语义，故本文件内串行。

mod common;

use common::{capture, serial};
use xray_app_log::{
    HandlerCreatorRegistry, LogConfig, LogInstance, LogType, SeverityLevel,
    register_default_creators,
};

fn registry() -> HandlerCreatorRegistry {
    let registry = HandlerCreatorRegistry::new();
    register_default_creators(&registry).expect("builtin creators 首注恒 Ok");
    registry
}

/// ① Console 配置：散装 general 消息逐字落到台面，且带通道 target。
#[test]
fn console_sink_shows_scattered_general_message() {
    let _serial = serial();
    let buf = capture();
    buf.clear();

    let instance = LogInstance::new(LogConfig {
        error_log_type: LogType::Console,
        error_log_level: SeverityLevel::Info, // Info 不得被等级门滤掉
        ..LogConfig::default()
    })
    .expect("default mask parses");
    instance.start(&registry()).expect("console handler: start Ok");

    xray_common::log::info("[test] hello");

    instance.close();
    let text = buf.text();
    assert!(text.contains("[test] hello"), "台面缺逐字行: {text}");
    assert!(text.contains("xray_frame::log"), "通道 target 缺失: {text}");
    assert!(text.contains("INFO"), "级别缺失: {text}");
}

/// ② File 配置：散装 general 消息同样落盘（台面仍保留）。
#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "713x6：测试临时目录取时保持原语义（测试计时不得改语义）"
)]
fn file_sink_writes_scattered_general_message() {
    let _serial = serial();
    let buf = capture();
    buf.clear();

    let dir = std::env::temp_dir().join(format!(
        "xray-app-log-general-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&dir).expect("临时目录可建");
    let path = dir.join("error.log");

    let instance = LogInstance::new(LogConfig {
        error_log_type: LogType::File,
        error_log_level: SeverityLevel::Info,
        error_log_path: path.to_string_lossy().into_owned(),
        ..LogConfig::default()
    })
    .expect("default mask parses");
    instance.start(&registry()).expect("file handler + path: start Ok");

    xray_common::log::info("[test] hello file");

    instance.close();
    let content = std::fs::read_to_string(&path).expect("文件 sink 落盘");
    let console = buf.text();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(content.contains("[test] hello file"), "落盘行缺失: {content}");
    assert!(console.contains("[test] hello file"), "File 配置下台面未恢复: {console}");
}

/// close 之后散装 general 消息不再外泄（进程级槽只清不注销）。
#[test]
fn closed_instance_is_silent() {
    let _serial = serial();
    let buf = capture();
    buf.clear();

    let instance = LogInstance::new(LogConfig {
        error_log_level: SeverityLevel::Debug,
        ..LogConfig::default()
    })
    .expect("default mask parses");
    instance.start(&registry()).expect("console handler: start Ok");
    instance.close();

    xray_common::log::warning("[test] after-close");

    assert!(!buf.text().contains("[test] after-close"), "close 后仍输出: {}", buf.text());
}

/// `loglevel: "none"`（error_log_type=None）：激活期也不产生散装 general 输出。
#[test]
fn none_config_stays_quiet() {
    let _serial = serial();
    let buf = capture();
    buf.clear();

    let instance = LogInstance::new(LogConfig {
        error_log_type: LogType::None,
        error_log_level: SeverityLevel::Debug,
        ..LogConfig::default()
    })
    .expect("default mask parses");
    instance.start(&registry()).expect("None creator: start Ok");

    xray_common::log::info("[test] none-config");

    instance.close();
    assert!(!buf.text().contains("[test] none-config"), "None 配置仍输出: {}", buf.text());
}

/// 默认配置（无 loglevel → Warning 门）：warning 可见、info 被滤——Go 同语义
/// （infra/conf/log.go Build 缺省 Severity_Warning；bd 8zs12 钉子：默认配置下
/// general info 不可见是 Go 一致行为，等级映射本身无缺陷）。
#[test]
fn default_gate_shows_warning_hides_info() {
    let _serial = serial();
    let buf = capture();
    buf.clear();

    let instance = LogInstance::new(LogConfig::default()).expect("default mask parses");
    instance.start(&registry()).expect("console handler: start Ok");

    xray_common::log::info("[test] default-gated info");
    xray_common::log::warning("[test] default-gated warning");

    instance.close();
    let text = buf.text();
    assert!(text.contains("[test] default-gated warning"), "默认 Warning 门应放行 warning: {text}");
    assert!(!text.contains("[test] default-gated info"), "默认 Warning 门应滤掉 info: {text}");
}

/// 未配置（proto 零值 Unknown）按 Go 缺省 Warning 门：warning 可见、info 滤掉
/// （bd 8zs12：改前 Unknown 按 Error 门，warning 也被滤）。
#[test]
fn unknown_level_gate_shows_warning_hides_info() {
    let _serial = serial();
    let buf = capture();
    buf.clear();

    let instance = LogInstance::new(LogConfig {
        error_log_level: SeverityLevel::Unknown,
        ..LogConfig::default()
    })
    .expect("default mask parses");
    instance.start(&registry()).expect("console handler: start Ok");

    xray_common::log::info("[test] unknown-gated info");
    xray_common::log::warning("[test] unknown-gated warning");

    instance.close();
    let text = buf.text();
    assert!(text.contains("[test] unknown-gated warning"), "Unknown 门应按 Warning 放行: {text}");
    assert!(!text.contains("[test] unknown-gated info"), "Unknown 门应滤掉 info: {text}");
}

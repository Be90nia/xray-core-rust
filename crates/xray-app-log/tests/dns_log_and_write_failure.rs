//! bd sex3y 验收：①dnsLog 真有生产者（`record_dns` → Dns 通道 → access 文件）；
//! ②写失败 fail-visible（启动期硬错 + 运行期首条 warn），不再纯静默丢行。

mod common;

use xray_app_log::{AccessMessage, DnsLog, LogConfig, LogEntry, LogFeature, LogType, record_dns};
use xray_features::Feature as _;

fn temp_dir(tag: &str) -> std::path::PathBuf {
    // clippy L3 闸禁 `SystemTime::now`（墙钟归口 xray_frame::compat::clock）：
    // 进程内自增序号足够唯一（同二进制内串行跑，且落盘前先清目录）。
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "xray-app-log-{tag}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn file_cfg(path: &std::path::Path, dns: bool) -> LogConfig {
    LogConfig {
        access_log_type: LogType::File,
        access_log_path: path.to_string_lossy().into_owned(),
        enable_dns_log: dns,
        ..LogConfig::default()
    }
}

/// 装配期装好出口 → `record_dns` 一行即落 DNS 行；`close` 后不再写（不写已关实例）。
#[test]
fn record_dns_produces_dns_log_line() {
    let _serial = common::serial();
    let dir = temp_dir("dns");
    let path = dir.join("access.log");
    let feature = LogFeature::new(file_cfg(&path, true)).expect("log feature");
    feature.start().expect("start");

    record_dns(DnsLog { domain: "d.io".into(), result: "9.9.9.9".into(), ..Default::default() });

    let text = std::fs::read_to_string(&path).expect("access log 必须落盘");
    assert!(text.contains("d.io"), "DNS 行必须出现（E1 缺口：零生产者）: {text:?}");
    assert!(text.contains("9.9.9.9"), "DNS 结果必须带上: {text:?}");

    feature.close().expect("close");
    record_dns(DnsLog { domain: "after-close.io".into(), ..Default::default() });
    let text = std::fs::read_to_string(&path).expect("read after close");
    assert!(!text.contains("after-close.io"), "close 后 record_dns 不得写入: {text:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 启动期 fail-visible：access 日志路径不可写 → `start()` 硬错（Go 同义）。
#[test]
fn unwritable_access_log_path_fails_feature_start() {
    let _serial = common::serial();
    let dir = temp_dir("unwritable");
    let bad = dir.join("no-such-subdir").join("access.log");
    let feature = LogFeature::new(file_cfg(&bad, false)).expect("log feature");
    let err = feature.start().expect_err("不可写路径必须启动期失败");
    let msg = format!("{err}");
    assert!(msg.contains("log"), "错误须点名 log app: {msg}");
    assert!(msg.contains("cannot open log file"), "错误须点明打不开文件: {msg}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 运行期 fail-visible：装配成功后写失败（目录被删）→ 首条 warn 落盘捕获面 +
/// `dropped_total` 递增，不再「只剩一个静默计数器」。
#[test]
fn runtime_write_failure_is_warned_once() {
    let capture = common::capture();
    let _serial = common::serial();
    let dir = temp_dir("runtime-fail");
    let path = dir.join("access.log");
    let feature = LogFeature::new(file_cfg(&path, false)).expect("log feature");
    feature.start().expect("start");

    // 目录整体删除 → 后续 open/write 必失败（unix 走 inode 探测重开，Windows 每写重开）。
    std::fs::remove_file(&path).expect("remove log file");
    std::fs::remove_dir_all(&dir).expect("remove log dir");

    capture.clear();
    feature
        .instance()
        .handle(&LogEntry::Access(AccessMessage { from: "1.1.1.1".into(), ..Default::default() }));
    feature
        .instance()
        .handle(&LogEntry::Access(AccessMessage { from: "2.2.2.2".into(), ..Default::default() }));

    let lines = capture.text();
    assert!(lines.contains("log file write failed"), "写失败必须留可见告警: {lines:?}");
    assert_eq!(
        lines.matches("log file write failed").count(),
        1,
        "告警只发首条（不按行刷屏）: {lines:?}"
    );
    assert!(feature.instance().dropped_total() >= 1, "丢弃计数仍需可观测");
    feature.close().expect("close");
}

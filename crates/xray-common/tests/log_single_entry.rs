//! P1-10-b 单入口收敛断言（契约验收：`cargo test -p xray-common --test log_single_entry`）。
//!
//! 全局注册表每通道一 sink 且无注销面（udf 装配期一次性纪律），本文件用
//! 共享 CaptureLog + 进程内串行锁闭环；双写收敛断言用 `set_default`（全局
//! dispatcher，触发 callsite 缓存重建，规避线程局部 with_default 恒捕 0 的
//! 缓存陷阱）。

use std::{
    io::Write,
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
    },
};

use log::Level;
use skeleton_infra::logx::{Channel, ChannelRegistry, ChannelSink};
use xray_common::log as xlog;

/// 共享捕获账本：全部通道的落样 + 模拟写失败的丢弃计数。
#[derive(Default)]
struct CaptureLog {
    entries: Mutex<Vec<(Channel, Level, String, String)>>,
    fail: AtomicBool,
    dropped: AtomicU64,
}

struct CaptureSink {
    channel: Channel,
    log: Arc<CaptureLog>,
}

impl ChannelSink for CaptureSink {
    fn channel(&self) -> Channel {
        self.channel
    }

    fn level(&self) -> log::LevelFilter {
        log::LevelFilter::Trace
    }

    fn write(&self, level: Level, target: &str, message: &str) {
        if self.log.fail.load(Relaxed) {
            // 模拟 sink 写失败：丢一行并计数（udf 记账契约：失败自计数）。
            self.log.dropped.fetch_add(1, Relaxed);
            return;
        }
        self.log.entries.lock().unwrap().push((
            self.channel,
            level,
            target.to_string(),
            message.to_string(),
        ));
    }

    fn dropped_lines(&self) -> u64 {
        self.log.dropped.load(Relaxed)
    }
}

static CAPTURE: LazyLock<Arc<CaptureLog>> = LazyLock::new(|| {
    let log = Arc::new(CaptureLog::default());
    for ch in [Channel::General, Channel::Access, Channel::Dns] {
        xlog::register_channel(Arc::new(CaptureSink { channel: ch, log: Arc::clone(&log) }))
            .expect("测试二进制内每通道首注恰一次");
    }
    log
});
// parking_lot：断言失败不毒化锁（共享账本跨测试残留属预期，断言按唯一 marker 隔离）。
static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

fn capture() -> Arc<CaptureLog> {
    Arc::clone(&CAPTURE)
}

fn entries_of(
    capture: &CaptureLog,
    channel: Channel,
    marker: &str,
) -> Vec<(Level, String, String)> {
    capture
        .entries
        .lock()
        .unwrap()
        .iter()
        .filter(|(ch, _, _, m)| *ch == channel && m.contains(marker))
        .map(|(_, l, t, m)| (*l, t.clone(), m.clone()))
        .collect()
}

#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// 契约验收①（Main 拍板）：同一事件进对应通道不串道。
#[test]
fn three_channels_route_without_crosstalk() {
    let _guard = LOCK.lock();
    let cap = capture();

    xlog::channels().emit(Channel::Access, Level::Info, "xray.access", "P110-ROUTE-ACC");
    xlog::channels().emit(Channel::Dns, Level::Info, "xray.dns", "P110-ROUTE-DNS");
    xlog::info("P110-ROUTE-GEN");

    let access = entries_of(&cap, Channel::Access, "P110-ROUTE-");
    let dns = entries_of(&cap, Channel::Dns, "P110-ROUTE-");
    let general = entries_of(&cap, Channel::General, "P110-ROUTE-");
    assert_eq!(access.len(), 1, "access 只进 access 通道: {access:?}");
    assert_eq!(dns.len(), 1, "dns 只进 dns 通道: {dns:?}");
    assert_eq!(general.len(), 1, "general 只进 general 通道: {general:?}");
    assert_eq!(access[0].1, "xray.access");
    assert_eq!(dns[0].1, "xray.dns");
    assert_eq!(general[0].1, "xray_frame::log");
}

/// 契约验收④：双写收敛——一条日志只产生一次落样（tracing 台面 0 次，
/// 通道 sink 恰 1 次）。
#[test]
fn dual_write_converged_to_single_sample() {
    let _guard = LOCK.lock();
    let cap = capture();

    let buf = SharedBuf::default();
    let writer_buf = buf.clone();
    let guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || writer_buf.clone())
            .finish(),
    );

    xlog::info("P110-ONCE");
    drop(guard);

    let seen = entries_of(&cap, Channel::General, "P110-ONCE");
    assert_eq!(seen.len(), 1, "通道恰一次落样: {seen:?}");
    let tracing_out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(
        !tracing_out.contains("P110-ONCE"),
        "双写必须收敛：tracing 台面不得再出现便捷入口的落样: {tracing_out}"
    );
}

/// 契约验收②：掩码实证——含密钥的内容在落样中不可见（udf set_secrets
/// 唯一布点，emit 写前统一过 mask_secrets）。
#[test]
fn mask_secrets_apply_on_channel_path() {
    let _guard = LOCK.lock();
    let cap = capture();

    xlog::channels().set_secrets(vec!["P110-s3cret".to_string()]);
    xlog::warning("token=P110-s3cret end");
    xlog::channels().set_secrets(vec![]);

    let seen = entries_of(&cap, Channel::General, "token=");
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].2, "token=*** end", "密钥必须被掩码");
    assert!(!seen[0].2.contains("P110-s3cret"));
}

/// 契约验收①+③：级别映射（Go 口径）+ target 规范 `xray_frame::` 前缀。
#[test]
fn severity_levels_and_target_prefix() {
    let _guard = LOCK.lock();
    let cap = capture();

    xlog::debug("P110-LV-debug");
    xlog::info("P110-LV-info");
    xlog::warning("P110-LV-warn");
    xlog::error("P110-LV-error");

    let got: Vec<(Level, String)> = entries_of(&cap, Channel::General, "P110-LV-")
        .into_iter()
        .map(|(l, t, _)| (l, t))
        .collect();
    assert_eq!(
        got,
        vec![
            (Level::Debug, "xray_frame::log".to_string()),
            (Level::Info, "xray_frame::log".to_string()),
            (Level::Warn, "xray_frame::log".to_string()),
            (Level::Error, "xray_frame::log".to_string()),
        ],
        "级别序列与 target 规范: {got:?}"
    );
    // Go 级别别名留仓不受影响（xray_common::log::Severity::as_str）。
    assert_eq!(xlog::Severity::Warning.as_str(), "warning");
}

/// 契约验收⑤：sink 写失败 → 丢弃计数递增且不 panic；未注册通道静默不计数。
#[test]
fn registry_drop_accounting_on_write_failure() {
    struct FailingSink(Arc<AtomicU64>);

    impl ChannelSink for FailingSink {
        fn channel(&self) -> Channel {
            Channel::General
        }

        fn level(&self) -> log::LevelFilter {
            log::LevelFilter::Trace
        }

        fn write(&self, _level: Level, _target: &str, _message: &str) {
            self.0.fetch_add(1, Relaxed);
        }

        fn dropped_lines(&self) -> u64 {
            self.0.load(Relaxed)
        }
    }

    let dropped = Arc::new(AtomicU64::new(0));
    let registry = ChannelRegistry::new();
    registry.register(Arc::new(FailingSink(Arc::clone(&dropped)))).unwrap();

    registry.emit(Channel::General, Level::Error, "t", "boom");
    registry.emit(Channel::Access, Level::Info, "t", "silent-unregistered");

    assert_eq!(dropped.load(Relaxed), 1, "写失败恰丢一行");
    assert_eq!(registry.dropped_total(), 1, "dropped_total 可观测面");
}

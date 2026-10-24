//! `Instance::close` 与 udf [`skeleton_infra::shutdown::ShutdownCoordinator`]
//! 的编排桥（feature `shutdown-coordinator`，T1.1）。
//!
//! 契约：公开 API 零改动；每组件经 coordinator 编排——默认 5s 超时（对齐
//! xray-frame `assembly::DEFAULT_SHUTDOWN_TIMEOUT`，P0-8 拍板数字）、panic 隔离
//! （单组件 panic 转 `Failed` outcome，不再炸穿 close）、outcome 全量入报告、
//! 非 clean 行走 warning（clean 行走 info 保证停机报告可见）。报告出口走
//! xray-frame [`LogFacade`]（tracing 门面，target `xray_frame::shutdown`）：
//! **不随 log feature 关闭而死**——改前走 `xray_common::log`，报告 emit 晚于
//! `LogInstance::close`（gate=Off + 出口清空）必被吞，任何 loglevel 均静默
//! （bd 8zs12 真机实证）。
//! close `Err` 语义保留：错误经索引账本回传，返回关闭序首个非 clean 结论
//! （close Err / panic / 超时），与旧实现「返回第一错、其余留痕」一致。
//!
//! [`LogFacade`]: xray_frame::logging::LogFacade

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use skeleton_infra::shutdown::{OutcomeKind, ShutdownCoordinator};
use xray_common::log::Severity;
use xray_features::{Feature, FeatureError, Result};
use xray_frame::logging::LogFacade;

/// 组件停机默认超时——对齐 xray-frame `DEFAULT_SHUTDOWN_TIMEOUT`（P0-8）。
const DEFAULT_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// 报告输出目标（注入面）：生产 = LogFacade tracing 门面；测试 = 内存捕获。
///
/// 注入理由：报告出口是进程级面（tracing 订阅器 / 旧全局 general 槽均一处），
/// 同二进制内测试直驱注入面断言，不与进程级出口争抢（实测全量跑读到 0 行，
/// 单跑假绿的历史坑）。生产路径见 [`general_channel_sink`]。
pub(super) type ReportSink = dyn Fn(Severity, String);

/// 按注册逆序编排关闭所有 feature（[`crate::instance::Instance::close`] 的
/// coordinator 路径）。逆序注册 = 关闭序：协调器按注册序串行执行。
pub(super) fn close_features(features: &[Arc<dyn Feature>]) -> Result<()> {
    close_features_with_timeout(features, DEFAULT_CLOSE_TIMEOUT)
}

/// 同 [`close_features`]，超时可注入（仅本 crate 测试用短超时档；生产入口恒
/// 5s 默认档，避免全量睡测试）。
pub(super) fn close_features_with_timeout(
    features: &[Arc<dyn Feature>],
    timeout: Duration,
) -> Result<()> {
    close_features_with_sink(features, timeout, &general_channel_sink)
}

/// 同 [`close_features_with_timeout`]，报告输出目标可注入（测试面直驱捕获，
/// 不经进程级通道槽）。
pub(super) fn close_features_with_sink(
    features: &[Arc<dyn Feature>],
    timeout: Duration,
    sink: &ReportSink,
) -> Result<()> {
    let total = features.len();
    // 索引账本：close Err 按 feature 下标回传（组件闭包可能跑在协调器 watchdog
    // 线程上，跨线程收集；panic/超时组件不落账，由 outcome 面合成）。
    let ledger: Arc<Mutex<Vec<Option<FeatureError>>>> =
        Arc::new(Mutex::new((0..total).map(|_| None).collect()));
    // 名字去重：同 TypeId 可多次注册（Instance 契约），feature_name 可能同名；
    // 协调器重名 fail-visible（Duplicate）会漏关组件，故第 2 份起加序号后缀。
    // 报告/日志用带后缀名（可区分），错误面用 feature_name 原名（&'static）。
    let mut names: Vec<String> = Vec::with_capacity(total);
    let mut seen: HashMap<&'static str, usize> = HashMap::with_capacity(total);
    for feat in features {
        let base = feat.feature_name();
        let ord = seen.entry(base).or_insert(0);
        names.push(if *ord == 0 { base.to_string() } else { format!("{base}#{}", *ord + 1) });
        *ord += 1;
    }

    let coord = ShutdownCoordinator::new().with_default_timeout(timeout);
    for (idx, feat) in features.iter().enumerate().rev() {
        let feat = Arc::clone(feat);
        let name = names[idx].clone();
        let ledger = Arc::clone(&ledger);
        // 闭包持克隆 Arc：register 失败臂（不可达兜底）仍需原 feat 就地关闭，
        // move 闭包吞掉 feat 会 borrow-after-move。
        let feat_for_task = Arc::clone(&feat);
        if let Err(e) = coord.register(name, move || {
            if let Err(e) = feat_for_task.close() {
                tracing::warn!(
                    name = feat_for_task.feature_name(),
                    error = %e,
                    "feature close failed"
                );
                lock(&ledger)[idx] = Some(e);
            }
        }) {
            // 此臂实际不可达（注册窗在 shutdown 前恒开 + 名字已去重）；
            // fail-visible 留痕不静默，就地同步关闭兜底。名字取 names[idx]
            // （name 已 move 进 register，Vec 仍持有全量）。
            sink(
                Severity::Warning,
                format!("instance close: register {} failed ({e}); closing inline", names[idx]),
            );
            let _ = feat.close();
        }
    }
    let report = coord.shutdown();

    // 报告留痕 + 首错合成，同走关闭序（报告序 = 注册序 = 关闭序）。
    // 每组件 outcome：clean=info（停机报告可见性），非 clean=warn（契约）。
    let mut first: Option<FeatureError> = None;
    let mut ledger_guard = lock(&ledger);
    let (mut stopped, mut tainted) = (0usize, 0usize);
    // 名字 → 下标反查（报告行归位）：全注册成功时 name 顺序即下标序，此反查
    // 兜底 register 失败臂导致的报告短行，禁错位归因。
    let idx_by_name: HashMap<&str, usize> =
        names.iter().enumerate().map(|(i, n)| (n.as_str(), i)).collect();
    for outcome in report.per_component.iter() {
        let Some(&idx) = idx_by_name.get(outcome.name.as_str()) else {
            continue;
        };
        // close Err（账本）优先判档：Err 亦属非 clean → warn（禁按 outcome=Stopped
        // 记成 clean 掩盖失败）。
        let close_err = ledger_guard[idx].take();
        match (&outcome.kind, close_err) {
            (OutcomeKind::Stopped, None) => {
                stopped += 1;
                sink(Severity::Info, format!("instance close: {} stopped", outcome.name));
            },
            (OutcomeKind::Stopped, Some(e)) => {
                tainted += 1;
                sink(
                    Severity::Warning,
                    format!("instance close: {}: close failed: {e}", outcome.name),
                );
                first.get_or_insert(e);
            },
            (OutcomeKind::Failed { reason }, _) => {
                tainted += 1;
                let msg = format!("close panicked (isolated): {reason}");
                sink(Severity::Warning, format!("instance close: {}: {msg}", outcome.name));
                first.get_or_insert_with(|| FeatureError::CloseFailed {
                    name: features[idx].feature_name(),
                    message: msg,
                });
            },
            (OutcomeKind::TimedOut, _) => {
                tainted += 1;
                let msg = format!(
                    "close timed out after {timeout:?}; closure abandoned (thread may still run)"
                );
                sink(Severity::Warning, format!("instance close: {}: {msg}", outcome.name));
                first.get_or_insert_with(|| FeatureError::CloseFailed {
                    name: features[idx].feature_name(),
                    message: msg,
                });
            },
        }
    }
    sink(
        Severity::Info,
        format!("instance close report: {total} components ({stopped} stopped, {tainted} tainted)"),
    );
    match first {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// 生产报告目标：xray-frame [`LogFacade`]（tracing 门面；clean=info / 非
/// clean=warning）。不走 `xray_common::log` 的原因：其 general 出口受
/// `LogInstance::close` 控制（gate=Off + 出口清空），而报告 emit 晚于全部
/// feature 关闭，改前必被吞（bd 8zs12）；tracing 进程级订阅器由装配点
/// （xray-cli `init_tracing`）持有，不随 feature 关闭。门面 target =
/// `xray_frame::shutdown`，`RUST_LOG=xray_frame::shutdown=info` 可单独开门；
/// 行文本与旧出口逐字同（stopped/tainted 计数口径不变）。
fn general_channel_sink(severity: Severity, message: String) {
    static REPORT_LOG: LazyLock<LogFacade> = LazyLock::new(|| LogFacade::new("shutdown", vec![]));
    let log = &*REPORT_LOG;
    match severity {
        Severity::Debug => log.debug(message),
        Severity::Info => log.info(message),
        Severity::Warning => log.warn(message),
        Severity::Error => log.error(message),
    }
}

/// 取锁：毒锁恢复继续（udf shutdown.rs 同款——持锁点 panic 状态未变异不株连）。
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ReportCapture：WarnCapture 模式（outbound.rs `dns_unknown_key_warns_with_names`
    /// 同款，取自 xray-tls）；上限放 TRACE——报告含 info 级 outcome/汇总行。
    #[derive(Clone, Default)]
    struct ReportCapture(Arc<Mutex<Vec<String>>>);

    impl tracing::Subscriber for ReportCapture {
        fn enabled(&self, meta: &tracing::Metadata<'_>) -> bool {
            meta.level() <= &tracing::Level::TRACE
        }

        fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            struct Fmt(String);
            impl tracing::field::Visit for Fmt {
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    self.0.push_str(&format!("{}={value} ", field.name()));
                }

                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    self.0.push_str(&format!("{}={value:?} ", field.name()));
                }
            }
            let mut v = Fmt(String::new());
            event.record(&mut v);
            self.0.lock().unwrap_or_else(PoisonError::into_inner).push(v.0);
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    struct StubFeature(&'static str);

    impl Feature for StubFeature {
        fn feature_name(&self) -> &'static str {
            self.0
        }
    }

    /// bd 8zs12 时序修复回归：报告出口在 log feature 关闭后仍产出可见行。
    /// 复现改前死链：真实 `LogInstance` start→close 置 GlobalGeneralSink
    /// gate=Off（散装 `xray_common::log` 出口全灭），改前此刻发报告必被吞；
    /// 现出口走 xray-frame `LogFacade`（tracing 门面），经生产编排
    /// `close_features_with_sink` + 生产 sink 本体断言行齐全（文案 = 运维口径，
    /// 逐字不变）。
    #[test]
    fn report_sink_survives_log_feature_close() {
        let registry = xray_app_log::HandlerCreatorRegistry::new();
        xray_app_log::register_default_creators(&registry).expect("builtin creators 首注恒 Ok");
        let log_feature = xray_app_log::LogInstance::new(xray_app_log::LogConfig::default())
            .expect("default mask parses");
        log_feature.start(&registry).expect("log feature start");
        log_feature.close(); // gate=Off + 出口清空 —— 改前报告死点

        let features: Vec<Arc<dyn Feature>> =
            vec![Arc::new(StubFeature("report-a")), Arc::new(StubFeature("report-b"))];
        let capture = ReportCapture::default();
        let result = tracing::subscriber::with_default(capture.clone(), || {
            close_features_with_sink(&features, Duration::from_secs(5), &general_channel_sink)
        });
        assert!(result.is_ok(), "双 clean 关闭应 Ok: {result:?}");

        let lines = capture.0.lock().unwrap_or_else(PoisonError::into_inner);
        assert!(
            lines.iter().any(|l| l.contains("message=instance close: report-a stopped")),
            "clean outcome 行缺失（log feature 已关仍须可见）: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l
                .contains("message=instance close report: 2 components (2 stopped, 0 tainted)")),
            "汇总行缺失: {lines:?}"
        );
    }
}

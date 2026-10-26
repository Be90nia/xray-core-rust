//! `Instance::start` 与 xray-frame [`Framework`] 的装配桥（feature
//! `shutdown-coordinator`，W1-1b）。
//!
//! 契约：`Instance` 公开 API 零改动（`start()` 仍返回 `xray_features::Result`）。
//! 启动编排权交框架 `assembly::Framework`（register→build→bring_up）：
//! 逐插件 init→start 交替、任一步失败已启动者**逆序回滚**、panic 装甲
//! （框架 P0-4 拍板语义；与 Go「失败不回滚」的差异是本桥的刻意升级——
//! 半启动实例不再外泄，回滚后 `running` 复位 false）。停机面**零改动**：
//! `close` 仍走 `shutdown_bridge`（sync `ShutdownCoordinator`；框架
//! `Framework::shutdown` 是 async 三段式，与 Instance 同步 close 形态不合，
//! 停机语义等价由既有桥承担——1b 验收口径）。
//!
//! Feature → Plugin 适配壳（[`FeaturePlugin`]）：`deps()=&[]`（注册序 = 启动序，
//! Kahn 稳定输出，与改前逐字一致）；`init`/`build` 无操作（Feature 无对应相；
//! `init_dependencies`/DepBag 注入面留在 Instance 装配期，不经本桥）；
//! `start`/`stop` 直通 `Feature::start`/`Feature::close`。同 TypeId 多份注册
//! （Instance 契约）经名字去重（第 2 份起 `名#序号`）保持注册表键唯一。

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex},
};

use xray_features::{Feature, FeatureError, Result};
use xray_frame::{
    assembly::{Framework, FrameworkOptions},
    context::PluginContext,
    error::PluginError,
    plugin::{ClauseId, Lifecycle, Plugin, PluginContract, PluginDep},
};

/// Feature 适配壳的条款声明：12 条协议运行时条款全部不适用——真源在协议
/// crate 的 Plugin 契约（`xray-proxy-*/src/plugin.rs`）与数据面代码；本壳只是
/// `Feature::start/close` 的生命周期直通载体，不承载协议语义。
static FEATURE_ADAPTER_CONTRACT: PluginContract = PluginContract {
    clauses: &[],
    extra: &[
        ("kind", "feature-adapter"),
        ("lifecycle", "start/close delegate to xray-features Feature"),
    ],
    not_applicable: &[
        (ClauseId::AuthErrorClassified, "本壳不触协议认证；语义真源在协议 crate 的 Plugin 契约"),
        (ClauseId::HandshakeDeadline, "本壳无握手；连接面在数据面 crate"),
        (ClauseId::ConnIdPresent, "本壳不建连接；conn_id 面在数据面 crate"),
        (ClauseId::PoolDiscipline, "本壳零缓冲"),
        (
            ClauseId::SpawnManaged,
            "本壳不 spawn（Feature 存量后台任务归各 Feature，迁移属 L3 债面）",
        ),
        (
            ClauseId::StopRegistered,
            "close 的协调器注册由既有 shutdown_bridge 路径承担，非本壳声明面",
        ),
        (
            ClauseId::ConfigSectionOnly,
            "本壳不读配置；配置面归 xray-conf 旧解析面 + tests_config_parity 对拍",
        ),
        (
            ClauseId::ErrorClassifiedNoPanicEscape,
            "错误分类由 FeatureError 承担；panic 装甲由框架 bring_up guarded 提供",
        ),
        (ClauseId::BoundedResources, "本壳零资源"),
        (ClauseId::LogDiscipline, "本壳零日志；Feature 日志面归各 Feature"),
        (ClauseId::SecretMasking, "本壳零密钥"),
        (ClauseId::HotPathFreeze, "本壳在装配/停机面，数据面热路径零接触"),
    ],
};

/// 生命周期直通三相：init/build 无操作，start/stop → `Feature::start`/`close`。
struct FeatureLifecycle {
    feat: Arc<dyn Feature>,
}

impl Lifecycle for FeatureLifecycle {
    fn init(&self, _ctx: &PluginContext) -> std::result::Result<(), PluginError> {
        Ok(())
    }

    fn start(&self, _ctx: &PluginContext) -> std::result::Result<(), PluginError> {
        self.feat.start().map_err(|e| PluginError::Other(Box::new(e)))
    }

    fn stop(&self) -> std::result::Result<(), PluginError> {
        self.feat.close().map_err(|e| PluginError::Other(Box::new(e)))
    }
}

/// Feature → Plugin 适配壳（见模块文档）。
struct FeaturePlugin {
    /// 注册表键：`Feature::feature_name()`（同 TypeId 第 2 份起带 `#序号`）。
    name: &'static str,
    lifecycle: FeatureLifecycle,
}

impl FeaturePlugin {
    fn new(feat: Arc<dyn Feature>, name: &'static str) -> Self {
        Self { name, lifecycle: FeatureLifecycle { feat } }
    }
}

impl Plugin for FeaturePlugin {
    fn name(&self) -> &'static str {
        self.name
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn deps(&self) -> &'static [PluginDep] {
        &[]
    }

    fn contract(&self) -> &PluginContract {
        &FEATURE_ADAPTER_CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &self.lifecycle
    }

    fn build(&self, _ctx: &mut PluginContext) -> std::result::Result<(), PluginError> {
        // Feature 无 build 相：DepBag 依赖注入留在 Instance 装配期（new_from_built /
        // functions.rs 双阶段），不经框架 build 面。
        Ok(())
    }
}

/// 按注册序把全部 feature 经框架装配启动（[`crate::instance::Instance::start`]
/// 的 feature-on 路径）。失败 = 已启动者已被框架逆序回滚（stop →
/// `Feature::close`）。
pub(super) fn bring_up_features(features: &[Arc<dyn Feature>]) -> Result<()> {
    if features.is_empty() {
        // 空实例启动 = 合法 no-op（与旧循环一致）；注册表 fail-closed
        // （cap 0 → Err(Full)），不能走装配。
        return Ok(());
    }
    let opts = FrameworkOptions {
        registry_cap: features.len(),
        id_fingerprint: None,
        shutdown_timeout: None,
    };
    let mut builder = Framework::builder(opts).map_err(to_feature_err)?;
    let mut seen: HashMap<&'static str, usize> = HashMap::with_capacity(features.len());
    for feat in features {
        let base = feat.feature_name();
        let ord = seen.entry(base).or_insert(0);
        let name = synthetic_name(base, *ord);
        *ord += 1;
        builder = builder
            .register(Arc::new(FeaturePlugin::new(Arc::clone(feat), name)))
            .map_err(to_feature_err)?;
    }
    let mut framework = builder.build().map_err(to_feature_err)?;
    framework.bring_up().map_err(to_feature_err)?;
    // framework 就地丢弃：stop 闭包随 coordinator 释放。停机编排权在
    // shutdown_bridge（sync 形态；框架 shutdown 为 async 三段式，不合 Instance
    // 同步 close）——见模块文档。
    Ok(())
}

/// 同 TypeId 多份（Instance 契约）的注册表键合成：`ordinal == 0` → 原名；
/// 否则 `名#序号`。全进程 intern 表缓存（每个 `(原名, 序号)` 对只合成一次，
/// 重复 start/测试反复实例化不再新增条目）。
///
/// 生命周期注记：`Plugin::name()` 是冻结面 `&'static str`，而合成名是运行期
/// 派生串。输入（`feature_name()` = `type_name`）本身是进程静态数据，intern
/// 表按对去重、上界 = 不同类型名数 × 最大同名份数，无按调用增长——表持有
/// 唯一所有权，泄漏的只有必需 'static 的字符串本体（与 `type_name` 同寿命
/// 等级），不隐藏所有权 bug。
fn synthetic_name(base: &'static str, ordinal: usize) -> &'static str {
    static INTERNED: LazyLock<Mutex<HashMap<&'static str, Vec<&'static str>>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));
    if ordinal == 0 {
        return base;
    }
    let mut table = INTERNED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let variants = table.entry(base).or_default();
    if variants.len() < ordinal {
        debug_assert_eq!(variants.len() + 1, ordinal, "序号必须连续（seen 计数保证）");
        variants.push(Box::leak(format!("{base}#{}", ordinal + 1).into_boxed_str()));
    }
    variants[ordinal - 1]
}

/// `PluginError` → `FeatureError`：优先还原适配壳塞入的原 `FeatureError`
/// （source 链 `Lifecycle{Other(FeatureError)}`），保 `Instance::start` 既有
/// Err 变体契约（`StartFailed{name,message}` 原样）；链外形态降级为带定位的
/// `StartFailed`。
fn to_feature_err(err: PluginError) -> FeatureError {
    if let PluginError::Lifecycle { source, .. } = &err
        && let Some(PluginError::Other(inner)) = source.downcast_ref::<PluginError>()
        && let Some(FeatureError::StartFailed { name, message }) =
            inner.downcast_ref::<FeatureError>()
    {
        return FeatureError::StartFailed { name, message: message.clone() };
    }
    FeatureError::StartFailed { name: "instance", message: err.to_string() }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// 记录 start 序（Mutex<Vec>）与 close 计数；可注入 start 失败/panic。
    struct Probe {
        name: &'static str,
        order: Option<Arc<parking_lot::Mutex<Vec<String>>>>,
        close_count: Arc<AtomicUsize>,
        fail_mode: FailMode,
    }

    #[derive(Clone, Copy, PartialEq)]
    enum FailMode {
        Ok,
        Err,
        Panic,
    }

    impl Feature for Probe {
        fn feature_name(&self) -> &'static str {
            self.name
        }

        fn start(&self) -> Result<()> {
            if let Some(order) = &self.order {
                order.lock().push(format!("start:{}", self.name));
            }
            match self.fail_mode {
                FailMode::Ok => Ok(()),
                FailMode::Err => Err(FeatureError::StartFailed {
                    name: self.name,
                    message: "injected failure".into(),
                }),
                FailMode::Panic => panic!("injected start panic"),
            }
        }

        fn close(&self) -> Result<()> {
            self.close_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn probe(name: &'static str, fail_mode: FailMode) -> (Arc<Probe>, Arc<AtomicUsize>) {
        let close_count = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(Probe { name, order: None, close_count: Arc::clone(&close_count), fail_mode }),
            close_count,
        )
    }

    #[test]
    fn start_order_follows_registration() {
        let order = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut feats: Vec<Arc<dyn Feature>> = Vec::new();
        for name in ["a", "b", "c"] {
            feats.push(Arc::new(Probe {
                name,
                order: Some(Arc::clone(&order)),
                close_count: Arc::new(AtomicUsize::new(0)),
                fail_mode: FailMode::Ok,
            }));
        }
        bring_up_features(&feats).expect("bring up ok");
        assert_eq!(
            *order.lock(),
            vec!["start:a".to_string(), "start:b".to_string(), "start:c".to_string()],
            "注册序 = 启动序（deps 全空 → Kahn 稳定输出）"
        );
    }

    #[test]
    fn failed_start_rolls_back_started_features() {
        let (a, a_close) = probe("ok-a", FailMode::Ok);
        let (b, _b_close) = probe("bad-b", FailMode::Err);
        let feats: Vec<Arc<dyn Feature>> = vec![a, b];
        let err = bring_up_features(&feats).expect_err("start 失败必须 Err");
        assert!(
            matches!(&err, FeatureError::StartFailed { name, .. } if *name == "bad-b"),
            "Err 变体与 name 保全: {err}"
        );
        assert_eq!(a_close.load(Ordering::SeqCst), 1, "已启动者必须被逆序回滚（stop → close）");
    }

    #[test]
    fn panicking_start_is_armored_and_rolled_back() {
        let (a, a_close) = probe("ok-a", FailMode::Ok);
        let (b, _b_close) = probe("panic-b", FailMode::Panic);
        let feats: Vec<Arc<dyn Feature>> = vec![a, b];
        // panic 装甲：转 Err 而非炸穿调用方。
        let err = bring_up_features(&feats).expect_err("panic 必须转 Err");
        assert!(err.to_string().contains("panic-b") || err.to_string().contains("panic"), "{err}");
        assert_eq!(a_close.load(Ordering::SeqCst), 1, "panic 前已启动者必须回滚");
    }

    #[test]
    fn duplicate_feature_names_both_start() {
        // 同 TypeId 多份（Instance 契约）：注册表名去重后两份都启动。
        let order = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut feats: Vec<Arc<dyn Feature>> = Vec::new();
        for _ in 0..2 {
            feats.push(Arc::new(Probe {
                name: "dup",
                order: Some(Arc::clone(&order)),
                close_count: Arc::new(AtomicUsize::new(0)),
                fail_mode: FailMode::Ok,
            }));
        }
        bring_up_features(&feats).expect("同名两份都必须启动");
        assert_eq!(
            *order.lock(),
            vec!["start:dup".to_string(), "start:dup".to_string()],
            "两份 dup 各启动一次（第 2 份走 #2 名字去重）"
        );
    }

    #[test]
    fn empty_features_start_is_noop() {
        let feats: Vec<Arc<dyn Feature>> = vec![];
        bring_up_features(&feats).expect("空实例启动 = 合法 no-op");
    }
}

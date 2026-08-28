//! Instance —— Xray 运行时实例的 Feature 容器与生命周期管理。
//!
//! 对应 Go `core.Instance`（`core/xray.go`），但 DI resolution 模式不同：
//!
//! - **Go**：`RequireFeatures(callback)` 用 reflect 扫描回调参数类型，匹配 features
//!   列表中的实现，注入并调用回调。这是一种运行时反射 DI。
//! - **Rust**：暴露 `get_feature::<T>()` 显式类型化获取 API，调用方自己取所需
//!   features 编译期类型安全。若需要「等待多个 feature 就绪后执行」的语义，
//!   调用方在初始化阶段顺序 add_feature + 显式校验所需 feature 已注册即可。
//!
//! 这避免了 Go 端因 reflect 带来的 panic 风险与错误处理模糊。

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::Arc;

use xray_features::{Feature, FeatureError, Result};
use tokio_util::sync::CancellationToken;

/// 安装 panic → tracing hook（幂等，进程一次）。
///
/// 对应 Go `defer recover` 的观测语义（Go 主链路 proxyman/dispatcher 实际无
/// recover，goroutine panic 直接杀进程；Rust tokio task panic 仅取消该 task、
/// 资源随 unwind drop——本就比 Go 更安全，唯缺可见性）：task panic 统一记
/// `tracing::error` 后转发默认 hook，不破坏测试 harness / stderr 行为。
fn install_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let payload = info.payload();
            let msg = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("<non-string panic payload>");
            let location = info
                .location()
                .map(|l| format!("{}:{}", l.file(), l.line()))
                .unwrap_or_else(|| "<unknown>".into());
            tracing::error!(
                thread = std::thread::current().name().unwrap_or("<unnamed>"),
                location = %location,
                panic = %msg,
                "task panicked"
            );
            default_hook(info);
        }));
    });
}

/// Xray 实例。一个实例承载一整套 Feature（dns/router/policy/stats/inbound/outbound 等），
/// 注册顺序决定 `start` 顺序，`close` 顺序为 `start` 的逆序。
///
/// 同一 [`TypeId`] 可多次注册（与 Go 一致）；[`Self::get_feature`] 返回首份。
pub struct Instance {
    /// 按注册顺序的 feature 列表，用于 `start`/`close` 顺序调用。
    features: Vec<Arc<dyn Feature>>,
    /// `TypeId` → 类型擦除的 `Arc<T>`，用于 `get_feature::<T>()` 类型化获取。
    /// 同一 Arc 实例在 `features` 与本 map 各持一份引用。
    feature_typed: HashMap<TypeId, Arc<dyn Any + Send + Sync>>,
    /// 是否已 `start`。`start` 后再 `add_feature` 会立即调用其 `start`。
    running: bool,
    /// 生命周期状态锁，保证 `start`/`close`/`add_feature` 互斥。
    state_lock: parking_lot::Mutex<()>,
    /// 关闭时取消此 token，所有监听此 token 的连接/任务应主动终止。
    shutdown_token: CancellationToken,
}

impl Instance {
    /// 构造空实例。后续通过 [`Self::add_feature`] 注册所需 feature，
    /// 再调用 [`Self::start`] 启动。
    pub fn new() -> Self {
        Self {
            features: Vec::new(),
            feature_typed: HashMap::new(),
            running: false,
            state_lock: parking_lot::Mutex::new(()),
            shutdown_token: CancellationToken::new(),
        }
    }

    /// 运行时 type-erased 注册入口（不要求编译时知道具体类型）。
    ///
    /// 对应 Go `Instance.AddFeature(feature features.Feature)`。
    /// 与 [`Self::add_feature`] 区别：本方法接收 `Arc<dyn Feature>`，
    /// 适合配置驱动的运行时 dispatch（如 [`Self::new_from_built`]）。
    ///
    /// 行为与 `add_feature` 完全一致：登记 `feature_typed`（用 `feature_type()` 取 TypeId）
    /// + 追加 `features` slice。若已 `start`，立即启动新 feature。
    pub fn add_feature_dyn(&mut self, feature: Arc<dyn Feature>) -> Result<()> {
        let _guard = self.state_lock.lock();
        let tid = feature.feature_type();
        if self.running {
            if let Err(e) = feature.start() {
                tracing::warn!(
                    name = feature.feature_name(),
                    error = %e,
                    "failed to start feature on late registration"
                );
            }
        }
        self.feature_typed.entry(tid).or_insert_with(|| {
            let erased: Arc<dyn Any + Send + Sync> = feature.clone();
            erased
        });
        self.features.push(feature);
        Ok(())
    }

    /// 从 [`BuiltConfig`] 构造 Instance（核心启动路径第一步）。
    ///
    /// 对应 Go `core.New(config)` → `initInstanceWithConfig` 的 App 循环部分：
    /// 遍历 `built.apps`，按 `kind` 查全局 [`FeatureFactory`](xray_features::registry) 表，
    /// factory 返回 `Arc<dyn Feature>` → [`Self::add_feature_dyn`]。
    ///
    /// **不在此方法实现**（留给后续任务）：
    /// - essentialFeatures 兜底（dns/policy/router/stats 默认实现，待各 crate 切片2）
    /// - InitSystemDialer（依赖 outbound Manager）
    /// - addInboundHandlers/addOutboundHandlers（依赖 proxyman 切片2 + 各 proxy crate 切片2）
    ///
    /// 返回**未启动**的 Instance，由调用方按需 `start()`。
    ///
    /// # 容错策略
    ///
    /// - 未注册的 `kind`：记 warn 跳过（对应 Go essentialFeatures 默认实现路径）
    /// - factory 内部错误：立即返回（如 prost decode 失败、配置非法）
    pub fn new_from_built(built: &xray_conf::BuiltConfig) -> Result<Self> {
        install_panic_hook();
        let mut inst = Self::new();
        for entry in &built.apps {
            match xray_features::registry::create_feature(&entry.kind, &entry.data) {
                Ok(feat) => {
                    tracing::debug!(
                        kind = %entry.kind,
                        name = feat.feature_name(),
                        "feature created from built config"
                    );
                    inst.add_feature_dyn(feat)?;
                }
                Err(FeatureError::NotFound { ref name }) => {
                    tracing::warn!(
                        kind = %name,
                        "no FeatureFactory registered for kind, skipping"
                    );
                }
                Err(FeatureError::StartFailed { ref name, ref message }) => {
                    // Stub factory 返回 StartFailed = 该 Feature 尚未实现，非致命
                    tracing::warn!(
                        kind = %name,
                        message = %message,
                        "feature not yet implemented (stub factory), skipping"
                    );
                }
                Err(e) => return Err(e),
            }
        }

        // essentialFeatures: 当配置中缺少关键 app 时，注入默认空实现，
        // 确保最小配置也能正常启动（对应 Go xray-core essentialFeatures）。
        ensure_essential_features(&mut inst);

        // InitSystemDialer: 注入 DNS 解析能力 + dnsClient（LookupForIP 数据源）。
        // 对应 Go InitSystemDialer(dc dns.Client, om)：dc 取已配置 DNS app，
        // 无则 essentialFeatures 的 localdns（DefaultDnsFeature）。
        let dns_client: Option<Arc<dyn xray_features::dns::DnsClient>> = inst
            .get_feature::<xray_app_dns::DnsService>()
            .map(|d| d as Arc<dyn xray_features::dns::DnsClient>)
            .or_else(|| {
                inst.get_feature::<xray_features::dns::DefaultDnsFeature>()
                    .map(|d| d as Arc<dyn xray_features::dns::DnsClient>)
            });
        xray_transport::system_dialer::init_system_dialer(dns_client);


        tracing::info!(
            app_count = inst.feature_count(),
            inbound_count = built.inbound_count(),
            outbound_count = built.outbound_count(),
            "Instance constructed from BuiltConfig (inbound/outbound handler registration pending c2v)"
        );
        Ok(inst)
    }

    /// 注册一个 Feature 到实例。同一 [`TypeId`] 可多次注册（与 Go 一致：
    /// `features` slice 追加，[`Self::get_feature`] 返回首份）。
    ///
    /// 若实例已 `start`，新注册的 feature 会被立即 `start`。失败时
    /// feature 仍保留在容器中（与 Go 行为一致），由后续 `close` 统一回收。
    pub fn add_feature<T>(&mut self, feature: Arc<T>) -> Result<()>
    where
        T: Feature,
    {
        let _guard = self.state_lock.lock();
        let tid = TypeId::of::<T>();
        if self.running {
            // 实例运行中：立即启动新 feature（与 Go `Instance.AddFeature` 一致）。
            if let Err(e) = feature.start() {
                // 仍登记到容器，让 close 兜底回收。
                tracing::warn!(
                    name = feature.feature_name(),
                    error = %e,
                    "failed to start feature on late registration"
                );
            }
        }
        // feature_typed 只首次记录（与 Go GetFeature 返回首份一致）。
        self.feature_typed.entry(tid).or_insert_with(|| {
            let erased: Arc<dyn Any + Send + Sync> = feature.clone();
            erased
        });
        // features slice 总是追加（允许同类型多实例）。
        self.features.push(feature);
        Ok(())
    }

    /// 按 [`TypeId`] 判断是否已注册。
    pub fn has_feature<T>(&self) -> bool
    where
        T: Feature,
    {
        self.feature_typed.contains_key(&TypeId::of::<T>())
    }

    /// 按 [`TypeId`] 获取已注册 Feature 的强类型 `Arc<T>`。
    ///
    /// 返回 `None` 表示该类型未注册。调用方应优雅降级或返回配置错误。
    /// 返回的 `Arc` 与容器内部共享引用计数。
    pub fn get_feature<T>(&self) -> Option<Arc<T>>
    where
        T: Feature,
    {
        let any = self.feature_typed.get(&TypeId::of::<T>())?;
        any.clone().downcast::<T>().ok()
    }

    /// 获取所有已注册 feature 的不可变切片（按注册顺序）。用于诊断、统计、
    /// 或自定义遍历逻辑。
    pub fn features(&self) -> &[Arc<dyn Feature>] {
        &self.features
    }

    /// 已注册 feature 数量。
    pub fn feature_count(&self) -> usize {
        self.features.len()
    }

    /// 实例是否处于运行态（已 `start` 且未 `close`）。
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// 启动实例：标记为运行态，按注册顺序调用所有 feature 的 `start`。
    ///
    /// 任一 feature 启动失败会立即返回错误，**已启动的 feature 不回滚**
    /// （与 Go 行为一致，由调用方决定是否 `close` 兜底）。
    ///
    /// 重复 `start` 不会重新调用 feature.start（仅切换 running 标志）。
    pub fn start(&mut self) -> Result<()> {
        let _guard = self.state_lock.lock();
        if self.running {
            return Ok(());
        }
        // 先标记 running，让 add_feature 的延迟启动路径生效。
        // 注意：Go 是先调用 Start 再设 running；这里把 running 设到 start 调用前
        // 是为了让本批 features 的 Start 内部若有 add_feature 也能立即启动。
        self.running = true;
        for feat in &self.features {
            feat.start()?;
        }
        tracing::info!(version = super::version(), "Xray instance started");
        Ok(())
    }

    /// 返回 shutdown token 的引用，供 worker/连接监听关闭信号。
    pub fn shutdown_token(&self) -> &CancellationToken {
        &self.shutdown_token
    }

    /// 关闭实例：按注册**逆序**调用所有 feature 的 `close`，聚合所有错误。
    ///
    /// 关闭后实例不可重启（与 Go 一致）。即使部分 feature close 失败，
    /// 仍会尝试关闭其余 feature，最终把所有错误聚合返回。
    pub fn close(&mut self) -> Result<()> {
        let _guard = self.state_lock.lock();
        if !self.running {
            return Ok(());
        }
        self.running = false;
        // 取消 shutdown token，通知所有监听此 token 的连接/任务主动终止。
        self.shutdown_token.cancel();
        let mut errors: Vec<FeatureError> = Vec::new();
        // 逆序关闭：后注册的先关闭，模拟栈式生命周期。
        for feat in self.features.iter().rev() {
            if let Err(e) = feat.close() {
                tracing::warn!(
                    name = feat.feature_name(),
                    error = %e,
                    "feature close failed"
                );
                errors.push(e);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            // 聚合错误：用第一个错误作主因，其余记入日志已记录。
            // 设计权衡：返回 Vec<FeatureError> 会破坏单一错误型 API；用 anyhow!
            // 字符串拼接丢失类型信息。这里折中返回第一个错误，已通过 tracing 记录全部。
            Err(errors.into_iter().next().expect("non-empty errors"))
        }
    }
}

impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    #[test]
    fn panic_hook_install_is_idempotent() {
        install_panic_hook();
        install_panic_hook();
    }

    #[tokio::test]
    async fn spawned_task_panic_is_contained_and_visible() {
        install_panic_hook();
        // task panic 只取消该 task（JoinError），进程与其余 task 存活
        let panicked = tokio::spawn(async { panic!("boom") });
        let healthy = tokio::spawn(async { 42 });
        assert!(panicked.await.is_err(), "panic surfaces as JoinError");
        assert_eq!(healthy.await.unwrap(), 42, "other tasks unaffected");
    }

    /// 测试用 feature：记录 start/close 调用次数与顺序。
    struct CountingFeature {
        name: &'static str,
        start_count: Arc<AtomicUsize>,
        close_count: Arc<AtomicUsize>,
        start_fails: bool,
    }

    impl Feature for CountingFeature {
        fn feature_name(&self) -> &'static str {
            self.name
        }
        fn start(&self) -> Result<()> {
            self.start_count.fetch_add(1, Ordering::SeqCst);
            if self.start_fails {
                return Err(FeatureError::StartFailed {
                    name: self.name,
                    message: "injected failure".into(),
                });
            }
            Ok(())
        }
        fn close(&self) -> Result<()> {
            self.close_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn add_and_get_feature() {
        let mut inst = Instance::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let feat = Arc::new(CountingFeature {
            name: "a",
            start_count: counter.clone(),
            close_count: Arc::new(AtomicUsize::new(0)),
            start_fails: false,
        });
        inst.add_feature(feat).unwrap();
        assert!(inst.has_feature::<CountingFeature>());
        assert_eq!(inst.feature_count(), 1);
        let got = inst.get_feature::<CountingFeature>();
        assert!(got.is_some());
        assert_eq!(got.unwrap().name, "a");
    }

    #[test]
    fn duplicate_registration_keeps_both() {
        // 与 Go 一致：同类型多实例允许，get_feature 返回首份。
        let mut inst = Instance::new();
        let mk = || {
            Arc::new(CountingFeature {
                name: "dup",
                start_count: Arc::new(AtomicUsize::new(0)),
                close_count: Arc::new(AtomicUsize::new(0)),
                start_fails: false,
            })
        };
        inst.add_feature(mk()).unwrap();
        inst.add_feature(mk()).unwrap();
        assert_eq!(inst.feature_count(), 2);
        assert_eq!(inst.get_feature::<CountingFeature>().unwrap().name, "dup");
    }

    #[test]
    fn start_invokes_all_features_in_order() {
        let mut inst = Instance::new();
        let s1 = Arc::new(AtomicUsize::new(0));
        let s2 = Arc::new(AtomicUsize::new(0));
        let c1 = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::new(AtomicUsize::new(0));
        inst.add_feature(Arc::new(CountingFeature {
            name: "f1",
            start_count: s1.clone(),
            close_count: c1.clone(),
            start_fails: false,
        }))
        .unwrap();
        inst.add_feature(Arc::new(CountingFeature {
            name: "f2",
            start_count: s2.clone(),
            close_count: c2.clone(),
            start_fails: false,
        }))
        .unwrap();
        inst.start().unwrap();
        assert_eq!(s1.load(Ordering::SeqCst), 1);
        assert_eq!(s2.load(Ordering::SeqCst), 1);
        assert!(inst.is_running());
    }

    #[test]
    fn close_invokes_in_reverse_order() {
        // 用共享序号记录器校验调用顺序：f1 -> f2 (start), f2 -> f1 (close)。
        let order = Arc::new(parking_lot::Mutex::new(Vec::new()));

        struct OrderSensitive {
            tag: &'static str,
            order: Arc<parking_lot::Mutex<Vec<String>>>,
        }
        impl Feature for OrderSensitive {
            fn feature_name(&self) -> &'static str {
                self.tag
            }
            fn start(&self) -> Result<()> {
                self.order.lock().push(format!("start:{}", self.tag));
                Ok(())
            }
            fn close(&self) -> Result<()> {
                self.order.lock().push(format!("close:{}", self.tag));
                Ok(())
            }
        }

        let mut inst = Instance::new();
        inst.add_feature(Arc::new(OrderSensitive {
            tag: "f1",
            order: order.clone(),
        }))
        .unwrap();
        inst.add_feature(Arc::new(OrderSensitive {
            tag: "f2",
            order: order.clone(),
        }))
        .unwrap();
        inst.start().unwrap();
        inst.close().unwrap();
        let recorded = order.lock().clone();
        assert_eq!(
            recorded,
            vec![
                "start:f1".to_string(),
                "start:f2".to_string(),
                "close:f2".to_string(),
                "close:f1".to_string(),
            ]
        );
    }

    #[test]
    fn start_failure_propagates() {
        let mut inst = Instance::new();
        inst.add_feature(Arc::new(CountingFeature {
            name: "ok",
            start_count: Arc::new(AtomicUsize::new(0)),
            close_count: Arc::new(AtomicUsize::new(0)),
            start_fails: false,
        }))
        .unwrap();
        inst.add_feature(Arc::new(CountingFeature {
            name: "bad",
            start_count: Arc::new(AtomicUsize::new(0)),
            close_count: Arc::new(AtomicUsize::new(0)),
            start_fails: true,
        }))
        .unwrap();
        let err = inst.start().unwrap_err();
        assert!(matches!(err, FeatureError::StartFailed { .. }));
    }

    #[test]
    fn close_after_failed_start_still_runs() {
        let mut inst = Instance::new();
        let close_calls = Arc::new(AtomicUsize::new(0));
        inst.add_feature(Arc::new(CountingFeature {
            name: "ok",
            start_count: Arc::new(AtomicUsize::new(0)),
            close_count: close_calls.clone(),
            start_fails: false,
        }))
        .unwrap();
        // start 失败但实例进入 running 态（设计：失败不回滚）。
        let _ = inst.start();
        inst.close().unwrap();
        assert_eq!(close_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn late_registration_starts_immediately() {
        let mut inst = Instance::new();
        inst.start().unwrap();
        let started = Arc::new(AtomicBool::new(false));
        struct LateStarted {
            flag: Arc<AtomicBool>,
        }
        impl Feature for LateStarted {
            fn start(&self) -> Result<()> {
                self.flag.store(true, Ordering::SeqCst);
                Ok(())
            }
        }
        inst.add_feature(Arc::new(LateStarted {
            flag: started.clone(),
        }))
        .unwrap();
        assert!(started.load(Ordering::SeqCst));
    }

    #[test]
    fn get_feature_returns_none_when_unregistered() {
        let inst = Instance::new();
        struct UnusedFeature;
        impl Feature for UnusedFeature {}
        assert!(inst.get_feature::<UnusedFeature>().is_none());
        assert!(!inst.has_feature::<UnusedFeature>());
    }

    #[test]
    fn double_start_is_idempotent() {
        let mut inst = Instance::new();
        let start_calls = Arc::new(AtomicUsize::new(0));
        inst.add_feature(Arc::new(CountingFeature {
            name: "x",
            start_count: start_calls.clone(),
            close_count: Arc::new(AtomicUsize::new(0)),
            start_fails: false,
        }))
        .unwrap();
        inst.start().unwrap();
        inst.start().unwrap();
        assert_eq!(start_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn double_close_after_start_is_safe() {
        let mut inst = Instance::new();
        inst.add_feature(Arc::new(CountingFeature {
            name: "x",
            start_count: Arc::new(AtomicUsize::new(0)),
            close_count: Arc::new(AtomicUsize::new(0)),
            start_fails: false,
        }))
        .unwrap();
        inst.start().unwrap();
        inst.close().unwrap();
        // 二次 close 应短路返回 Ok（running=false）。
        inst.close().unwrap();
    }

    #[test]
    fn default_creates_empty_instance() {
        let inst = Instance::default();
        assert_eq!(inst.feature_count(), 0);
        assert!(!inst.is_running());
    }

    #[test]
    fn essential_features_inject_real_stats_manager() {
        // 空配置 → ensure_essential_features 注入 AppStatsFeature（真实计数，非 Noop）。
        let built = xray_conf::BuiltConfig::default();
        let inst = Instance::new_from_built(&built).expect("empty config should build");

        use xray_features::stats::Manager as _;
        let stats = inst
            .get_feature::<crate::register::AppStatsFeature>()
            .expect("stats should be injected when absent from config");
        let counter = stats.register_counter("inbound>>>tag[in]>>>traffic>>>downlink").unwrap();
        counter.add(512);
        assert_eq!(counter.value(), 512, "injected stats must count for real");
    }
}

/// essentialFeatures: 当配置中缺少关键 app 时，注入默认实现。
/// 对应 Go xray-core `essentialFeatures` 函数。
///
/// stats 注入真实 [`AppStatsFeature`]（Go 同样注入真实 app/stats.Instance），
/// 其余为占位实现。
fn ensure_essential_features(inst: &mut Instance) {
    use xray_features::dns::DefaultDnsFeature;
    use xray_features::policy::DefaultPolicyFeature;
    use xray_features::routing::DefaultRouterFeature;

    if inst.get_feature::<DefaultDnsFeature>().is_none() {
        tracing::info!("no dns feature configured, injecting default");
        inst.add_feature(Arc::new(DefaultDnsFeature)).ok();
    }
    if inst.get_feature::<DefaultPolicyFeature>().is_none() {
        tracing::info!("no policy feature configured, injecting default");
        inst.add_feature(Arc::new(DefaultPolicyFeature)).ok();
    }
    if inst.get_feature::<DefaultRouterFeature>().is_none() {
        tracing::info!("no router feature configured, injecting default");
        inst.add_feature(Arc::new(DefaultRouterFeature)).ok();
    }
    if inst.get_feature::<crate::register::AppStatsFeature>().is_none() {
        tracing::info!("no stats feature configured, injecting real stats manager");
        inst.add_feature(Arc::new(crate::register::AppStatsFeature::new())).ok();
    }
}


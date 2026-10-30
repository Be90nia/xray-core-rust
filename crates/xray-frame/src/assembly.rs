//! P0-5 装配组合根：把 P0-1..P0-4 串成一条生产装配链
//! `register → build(ctx) → bring_up（init/start 拓扑序）→ shutdown（三段式）`，
//! [`Framework`] 门面收口（契约任务书 P0-5；模型 §2.2 L5 装配门 + L2 能力注入）。
//!
//! - **fail-visible**：任一步失败 → 整链 `Err`，无半启动态外泄。build 阶段失败时 零
//!   init/start（无回滚对象）；bring_up 失败复用 [`bring_up`] 的逆序回滚语义（不另写一套），
//!   `started` 保持 `None`（[`Framework::is_running`] 观察锚）。
//! - **三段式停机（PM 拍板 2026-10-23：异步排空隔离在第③段）**：① `fx.close()`（拒新 spawn）→ ②
//!   `coordinator.shutdown()`（插件停机闭包， 注册序 =
//!   逆启动序，同步快收：只发关闭信号不等排空，否则停机被拖成串行 等待）→ ③
//!   `fx.shutdown_timeout(d)`（在途 abort + 排空，剩余集 Drop=abort 兜底零残留）。
//! - **Context 单一权威**：每插件一个 ctx，build 期构造并经 `build(ctx)` 变更后 原样交
//!   init/start（handler 登记不丢）；裸 [`FxScope`](skeleton_infra::fx::FxScope) 不进插件（L2
//!   能力只经 ctx 句柄集），`scope()` 供宿主/测试。
//! - 坑约束 #6（停机链唯一出口 = [`Framework::shutdown`]）、#12（组合根只动
//!   装配层，数据面零接触）。

use std::{
    collections::HashMap,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use skeleton::{clock::SystemClock, config::StdEnv};
use skeleton_infra::{
    journal::{JournalError, JsonlJournal},
    shutdown::{ComponentOutcome, OutcomeKind, ShutdownCoordinator, ShutdownReport},
};

use crate::{
    audit::AuditHandle,
    context::{PluginContext, derive_fingerprint},
    error::PluginError,
    logging::LogFacade,
    plugin::Plugin,
    pool::BufferPool,
    registry::PluginRegistry,
    scope::ArmScope,
    state_loop::{self, AssemblyJournal, AuditSlice, CtxFactory, StartedPlugins, TrailEntry},
};

/// `FrameworkOptions::shutdown_timeout = None` 时的默认停机超时（P0-8 拍板数字）。
const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// 装配选项。`registry_cap` 透传 [`PluginRegistry::new`]（0 → 装配期
/// `Err(Full)`）；`id_fingerprint = None` → 装配根按
/// [`derive_fingerprint(None)`](crate::context::derive_fingerprint) 派生（无主
/// 监听地址的 pid+启动时刻退化形态）；`shutdown_timeout = None` → 5s 默认。
pub struct FrameworkOptions {
    /// 插件表容量（透传 `PluginRegistry::new`）。
    pub registry_cap: usize,
    /// IdGen fingerprint（P0-3 未决点 3；None → 装配根派生默认）。
    pub id_fingerprint: Option<u64>,
    /// 停机默认超时（透传 `ShutdownCoordinator::with_default_timeout` +
    /// [`Framework::shutdown`] 第③段排空）。
    pub shutdown_timeout: Option<Duration>,
}

/// 装配框架门面：一次装配的注册表 + 托管 scope + 停机编排器 + 启动账本。
pub struct Framework {
    registry: PluginRegistry,
    coordinator: Arc<ShutdownCoordinator>,
    fx: Arc<ArmScope>,
    shutdown_timeout: Duration,
    /// 启动账本：`None` = 未启动 / 启动失败已回滚（无半启动态外泄的观察锚）。
    started: Option<StartedPlugins>,
    /// build 阶段构造的 per-plugin ctx（`build(ctx)` 变更后原样交 init/start）。
    ctxs: Option<HashMap<&'static str, PluginContext>>,
    /// 审计账本路径（`None` = 不写盘；用户显式配置才记账）。
    journal_path: Option<PathBuf>,
}

/// 手写（scope/coordinator 无 Debug）：打印运行态与插件数——`Result` 错误路径
/// `expect_err` 可用（fail-visible 的可读半边，`StartedPlugins` 同例）。
impl std::fmt::Debug for Framework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Framework")
            .field("running", &self.is_running())
            .field("plugins", &self.registry.len())
            .finish_non_exhaustive()
    }
}

impl Framework {
    /// 装配入口（阶段①注册由 builder 承载）。`registry_cap = 0` → `Err(Full)`
    /// （fail-visible，最早装配点报错）。
    pub fn builder(opts: FrameworkOptions) -> Result<FrameworkBuilder, PluginError> {
        FrameworkBuilder::new(opts)
    }

    /// 共享托管 scope（宿主/测试用；不进插件——L2 能力只经 ctx 句柄集）。
    /// arm 级关闭信号中枢：宿主**必须经 `close()` 关停**（裸 `FxScope::close`
    /// 无级联广播，见 [`ArmScope`]）。
    pub fn scope(&self) -> &Arc<ArmScope> {
        &self.fx
    }

    /// 启动账本观察面：bring_up 成功 = true；启动失败回滚后保持 false。
    pub fn is_running(&self) -> bool {
        self.started.is_some()
    }

    /// 阶段③：init/start 拓扑序编排（**唯一路径 = [`crate::state_loop`]**）。
    /// 依赖序计划在 `Plan::from_registry` 处产出（缺依赖 / 成环 → `Err`，启动前
    /// fail-visible，零生命周期调用）；失败 → 已启动者回滚 + `started` 保持
    /// `None`。失败后本实例为终态（插件不保证 init 幂等，禁重试；`shutdown` 仍安全）。
    pub fn bring_up(&mut self) -> Result<(), PluginError> {
        // factory 逐名取回 build 期 ctx（bring_up 单线程顺序调用；同注册表
        // 重排序确定性 → build 期顺序与取用顺序一致）。
        let table = Mutex::new(self.ctxs.take().unwrap_or_default());
        let factory: CtxFactory = Arc::new(move |plugin: &Arc<dyn Plugin>| {
            lock(&table).remove(plugin.name()).ok_or_else(|| {
                PluginError::Other(
                    format!(
                        "plugin {} context missing from assembly table (assembly bug)",
                        plugin.name()
                    )
                    .into(),
                )
            })
        });
        let journal = self.open_journal()?;
        self.started = Some(state_loop::bring_up_with_journal(
            &self.registry,
            factory,
            Arc::clone(&self.coordinator),
            journal,
        )?);
        Ok(())
    }

    /// 打开审计账本（**用户显式配置才写**；缺省 `None` = 内存账本零 IO）。
    ///
    /// shortcut: 账本按追加挂载，跨进程重启不复原审计分片（`seq` 自 0 重新计），
    /// 需要跨重启真复原时改用 `SyncStore::restore_from` 播种。
    fn open_journal(&self) -> Result<Option<AssemblyJournal>, PluginError> {
        let Some(path) = self.journal_path.as_deref() else {
            return Ok(None);
        };
        Ok(Some(Box::new(open_ledger(path).map_err(|err| PluginError::Other(Box::new(err)))?)))
    }

    /// 优雅停机三段（坑约束 #6 停机链唯一出口）。消费所有权——重复 shutdown
    /// 编译期阻止。返回插件停机闭包全量报告；fx 排空（第③段）超时则在报告
    /// 末尾追加 `fx_drain` 行（`OutcomeKind::TimedOut`）——`is_clean()` 因此
    /// 同时覆盖插件闭包与 fx 排空两面（T1.3）；未启动且排空干净 = 空报告
    /// （合法，`is_clean()==true`）。
    pub async fn shutdown(mut self) -> ShutdownReport {
        // ① 拒新 spawn（闸关；在途不受影响，插件 stop 闭包可安全发停机信号）。
        self.fx.close();
        // ② 插件停机闭包：注册序 = 逆启动序，同步快收（异步排空隔离在第③段）。
        let mut report = self.started.take().map(StartedPlugins::tear_down).unwrap_or_default();
        // ③ 在途排空：abort + 超时兜底（剩余集 Drop=abort，零残留）。超时留痕
        // fail-visible 且并入报告末行（T1.3：is_clean() 覆盖 fx 面；插件闭包
        // 超时档 = coordinator 默认档，P0-8：`FrameworkOptions.shutdown_timeout`
        // 透传见 `FrameworkBuilder::new`）。
        if self.fx.shutdown_timeout(self.shutdown_timeout).await.is_err() {
            LogFacade::new("assembly", vec![])
                .warn("framework shutdown: fx drain timed out; residual tasks force-aborted");
            report
                .per_component
                .push(ComponentOutcome { name: "fx_drain".into(), kind: OutcomeKind::TimedOut });
        }
        report
    }
}

/// 装配 builder（阶段①注册 + 阶段② build）。链式消费形态：
/// `Framework::builder(opts)?.register(a)?.register(b)?.build()?`。
pub struct FrameworkBuilder {
    registry: PluginRegistry,
    fx: Arc<ArmScope>,
    coordinator: Arc<ShutdownCoordinator>,
    fingerprint: u64,
    shutdown_timeout: Duration,
    ctxs: HashMap<&'static str, PluginContext>,
    /// 全局配置值面（段路由底座；P1-7 加法扩展：`with_config` 注入——缺省
    /// 空对象，真实配置文件接入归 P3-2）。
    config_root: serde_json::Value,
    /// 装配根审计环（nn8os 2a：全插件事件落同一环，`plugin` 字段标注归属）。
    audit: Arc<AuditHandle>,
    /// 装配根缓冲池（nn8os W2 2a：`with_pool` 注入，各插件 ctx 共享同一池；
    /// 缺省 `None` = 未接线 → 插件取 `ctx.pool()` fail-visible）。
    pool: Option<Arc<dyn BufferPool>>,
    /// 审计账本落盘路径（`with_journal` 注入；缺省 `None` = 不写盘）。
    journal_path: Option<PathBuf>,
}

impl FrameworkBuilder {
    fn new(opts: FrameworkOptions) -> Result<Self, PluginError> {
        let shutdown_timeout = opts.shutdown_timeout.unwrap_or(DEFAULT_SHUTDOWN_TIMEOUT);
        Ok(Self {
            registry: PluginRegistry::new(opts.registry_cap)?,
            fx: ArmScope::new(),
            coordinator: Arc::new(
                ShutdownCoordinator::new().with_default_timeout(shutdown_timeout),
            ),
            fingerprint: opts.id_fingerprint.unwrap_or_else(|| derive_fingerprint(None)),
            shutdown_timeout,
            ctxs: HashMap::new(),
            config_root: serde_json::json!({}),
            audit: Arc::new(AuditHandle::new(crate::audit::DEFAULT_AUDIT_RING_CAP)),
            pool: None,
            journal_path: None,
        })
    }

    /// 注入全局配置值面（段路由底座）。缺省空对象；插件 `ctx.section()` 按
    /// `outbounds[]/inbounds[]` 内 `protocol` 字段路由（坑约束 7）。
    #[must_use]
    pub fn with_config(mut self, config_root: serde_json::Value) -> Self {
        self.config_root = config_root;
        self
    }

    /// 注入装配根缓冲池（L2 缓冲柄 `ctx.pool()` 的装配接线点，坑约束 4/9）：
    /// build 期写进每个插件 ctx（`set_pool`），全插件共享同一池、同一份账本。
    /// 缺省不注入 → 插件取池即 fail-visible（装配门 L5，`PluginContext::pool`）。
    #[must_use]
    pub fn with_pool(mut self, pool: Arc<dyn BufferPool>) -> Self {
        self.pool = Some(pool);
        self
    }

    /// 注入审计账本路径（`JournalPort` + udf JSONL）：**用户显式配置才写盘**，
    /// 缺省 `None` = 内存账本，零 IO。启动期装配轨迹与停机轨迹都落此文件，
    /// 停机时 `persist_snapshot` 落快照行并 fsync。
    #[must_use]
    pub fn with_journal(mut self, path: impl Into<PathBuf>) -> Self {
        self.journal_path = Some(path.into());
        self
    }

    /// 阶段①注册：透传 [`PluginRegistry::register`]（重名不覆盖、满 → Err）。
    pub fn register(mut self, plugin: Arc<dyn Plugin>) -> Result<Self, PluginError> {
        self.registry.register(plugin)?;
        Ok(self)
    }

    /// 阶段②：按拓扑序逐插件 `build(ctx)`（ctx 由装配根统一构造——L2）。
    /// 任一失败 → 整链 `Err`（此时零 init/start，无回滚对象——无半启动态）；
    /// panic 装甲同 P0-4 语义（坑约束 #8，payload 转 `Other` 留痕）。
    /// 成功 → [`Framework`]（未启动；启动走 [`Framework::bring_up`]）。
    pub fn build(mut self) -> Result<Framework, PluginError> {
        for plugin in self.registry.start_order()? {
            let mut ctx = self.new_ctx(plugin.name());
            guarded_build(&plugin, &mut ctx)?;
            self.ctxs.insert(plugin.name(), ctx);
        }
        let Self {
            registry,
            fx,
            coordinator,
            shutdown_timeout,
            ctxs,
            fingerprint: _,
            config_root: _,
            audit: _,
            pool: _,
            journal_path,
        } = self;
        Ok(Framework {
            registry,
            coordinator,
            fx,
            shutdown_timeout,
            started: None,
            ctxs: Some(ctxs),
            journal_path,
        })
    }

    /// ctx 构造（每插件一份；log 域约定 = 插件名；配置根经 `with_config` 注入，
    /// 缺省空对象——真实配置文件接入归 P3-2，段路由此刻走注入面）。
    fn new_ctx(&self, plugin_name: &'static str) -> PluginContext {
        let mut ctx = PluginContext::new(
            plugin_name,
            Arc::clone(&self.fx),
            Arc::new(SystemClock),
            self.fingerprint,
            Arc::new(StdEnv),
            self.config_root.clone(),
            LogFacade::new(plugin_name, vec![]),
            Arc::clone(&self.audit),
        );
        if let Some(pool) = &self.pool {
            ctx.set_pool(Arc::clone(pool));
        }
        ctx
    }
}

/// 账本版本头（`JsonlJournal` 的 v1 格式）。
const JOURNAL_VERSION: u32 = 1;

/// 挂载账本：新路径建账（版本头 + 首次 flush），已有路径按追加挂载（尾部
/// 残行截断交给 udf，`VersionMismatch` / `Corrupt` 原样上抛 fail-visible）。
fn open_ledger(path: &Path) -> Result<JsonlJournal<TrailEntry, AuditSlice>, JournalError> {
    if path.exists() {
        JsonlJournal::open(path, JOURNAL_VERSION)
    } else {
        JsonlJournal::create(path)
    }
}

/// build 阶段装甲：`Err` 原样上抛（同 bring_up 的 ctx 构建失败语义——插件错误
/// 自带归属，不重包）；panic 提取 payload 转 `Other`（坑约束 #8 不逃逸）。
/// 不复用 `lifecycle::guarded`：其 `LifecyclePhase` 无 build 相，冻结面只消费。
/// `pub(crate)`：P3-2 config.rs 的配置驱动 build 复用同一装甲（不造第二份）。
pub(crate) fn guarded_build(
    plugin: &Arc<dyn Plugin>,
    ctx: &mut PluginContext,
) -> Result<(), PluginError> {
    let name = plugin.name();
    match catch_unwind(AssertUnwindSafe(|| plugin.build(ctx))) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(source)) => Err(source),
        Err(payload) => Err(PluginError::Other(
            format!("plugin {name} build panicked: {}", panic_payload_message(payload)).into(),
        )),
    }
}

/// panic payload 提取（与 lifecycle.rs 同款；彼处私有，冻结面只消费故留本地副本）。
fn panic_payload_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else {
        "non-string panic payload".to_string()
    }
}

/// 取锁：毒锁恢复继续（udf shutdown.rs 同款——持锁点 panic 状态未变异不株连）。
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(cap: usize, timeout: Option<Duration>) -> FrameworkOptions {
        FrameworkOptions { registry_cap: cap, id_fingerprint: None, shutdown_timeout: timeout }
    }

    /// `shutdown_timeout = None` → P0-8 拍板默认 5s（构造期解析；字段私有仅本
    /// 模块测试可见）。
    #[test]
    fn default_shutdown_timeout_is_p0_8_figure() {
        let fw = Framework::builder(opts(4, None)).expect("cap 4").build().expect("empty");
        assert_eq!(fw.shutdown_timeout, Duration::from_secs(5));
    }

    /// `registry_cap = 0` → 最早装配点 fail-visible（`Err(Full)`）。
    #[test]
    fn zero_registry_cap_fails_at_builder() {
        let err = match Framework::builder(opts(0, None)) {
            Err(err) => err,
            Ok(_) => panic!("cap 0 must fail"),
        };
        assert!(matches!(err, PluginError::Full { cap: 0 }), "{err}");
    }

    /// T1.3：fx 排空超时必须并入返回报告。hold = future 内 block_in_place 阻塞段
    /// （poll 中不可丢弃，abort_all 打不掉 = 「不可 abort 段依赖自终止」契约面；
    /// block_in_place 让出 worker → driver 迁移，tokio 计时器存活有保障）。
    /// 50ms 超时档必触发 → 报告携带 `fx_drain` TimedOut 行、`is_clean()==false`
    /// （并入前该分支只 warn 不入报告，排空超时被漏报）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_report_carries_fx_drain_timeout() {
        let fw = Framework::builder(opts(4, Some(Duration::from_millis(50))))
            .expect("cap 4")
            .build()
            .expect("empty");
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<()>();
        fw.scope()
            .spawn(async move {
                tokio::task::block_in_place(|| {
                    let _ = entered_tx.send(());
                    // 阻塞 300ms ≫ 50ms 超时档：确定性超时；shutdown 返回后
                    // runtime 收尾等它退出（测试墙钟 ~0.3s，无 flake 面）。
                    std::thread::sleep(Duration::from_millis(300));
                })
            })
            .expect("spawn before shutdown");
        // 握手：send 与 sleep 同一 poll 内——收到即保证任务已入阻塞段（并行负载
        // 下「未被 poll 即被 abort_all 清场」的竞态被此闸封死）。
        tokio::time::timeout(Duration::from_secs(5), entered_rx)
            .await
            .expect("hold task entered blocking section in time")
            .ok();
        let report = fw.shutdown().await;
        assert!(!report.is_clean(), "fx drain timeout must taint the report");
        let row = report
            .per_component
            .iter()
            .find(|o| o.name == "fx_drain")
            .expect("fx drain outcome must be reported");
        assert_eq!(row.kind, OutcomeKind::TimedOut);
    }

    /// L2 缓冲柄的装配注入面（nn8os W2 2a）：`with_pool` 未调 → 插件取
    /// `ctx.pool()` 时装配期 fail-visible（panic 被 build 装甲转 `Err`，不静默
    /// 放行）；接线后同一插件 build 成功并真取到池。
    #[test]
    fn assembler_wires_pool_capability_into_plugin_ctx() {
        use crate::{
            plugin::{Lifecycle, PluginContract},
            pool::{ManagedBufferPool, XrayBufPool},
        };

        struct NoopLifecycleImpl;

        impl Lifecycle for NoopLifecycleImpl {
            fn init(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
                Ok(())
            }

            fn start(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
                Ok(())
            }

            fn stop(&self) -> Result<(), PluginError> {
                Ok(())
            }
        }

        static PROBE_LIFECYCLE: NoopLifecycleImpl = NoopLifecycleImpl;
        static PROBE_CONTRACT: PluginContract =
            PluginContract { clauses: &[], extra: &[], not_applicable: &[] };

        struct PoolProbe;

        impl Plugin for PoolProbe {
            fn name(&self) -> &'static str {
                "pool-probe"
            }

            fn version(&self) -> &'static str {
                "0.0.0"
            }

            fn contract(&self) -> &PluginContract {
                &PROBE_CONTRACT
            }

            fn lifecycle(&self) -> &dyn Lifecycle {
                &PROBE_LIFECYCLE
            }

            fn build(&self, ctx: &mut PluginContext) -> Result<(), PluginError> {
                // 未接线 → `pool()` panic → 装甲转 Err（装配期 fail-visible）。
                drop(ctx.pool().acquire(64).expect("pool wired by assembler"));
                Ok(())
            }
        }

        let unwired = match Framework::builder(opts(4, None))
            .expect("cap 4")
            .register(Arc::new(PoolProbe))
            .expect("register")
            .build()
        {
            Err(err) => err.to_string(),
            Ok(_) => panic!("未接线的 pool 必须在装配期 fail-visible"),
        };
        assert!(unwired.contains("pool capability not wired"), "{unwired}");

        let fw = Framework::builder(opts(4, None))
            .expect("cap 4")
            .with_pool(Arc::new(ManagedBufferPool::new(XrayBufPool::new(8, 8), 8, 8)))
            .register(Arc::new(PoolProbe))
            .expect("register")
            .build()
            .expect("pool wired → build 成功");
        assert!(!fw.is_running(), "build 后仍未启动");
    }

    /// 审计账本接线：`with_journal` 是**唯一**写盘入口（用户显式配置才写）。
    /// 未配置 → `open_journal` 返回 `None`（零 IO）；配置 → 启动轨迹 + 停机轨迹 +
    /// 快照行都落同一文件。
    #[tokio::test]
    async fn journal_is_written_only_when_explicitly_configured() {
        use crate::plugin::{Lifecycle, PluginContract};

        struct NoopLifecycle;

        impl Lifecycle for NoopLifecycle {
            fn init(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
                Ok(())
            }

            fn start(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
                Ok(())
            }

            fn stop(&self) -> Result<(), PluginError> {
                Ok(())
            }
        }

        static NOOP_LIFECYCLE: NoopLifecycle = NoopLifecycle;
        static NOOP_CONTRACT: PluginContract =
            PluginContract { clauses: &[], extra: &[], not_applicable: &[] };

        struct NoopPlugin;

        impl Plugin for NoopPlugin {
            fn name(&self) -> &'static str {
                "journal-probe"
            }

            fn version(&self) -> &'static str {
                "0.0.0"
            }

            fn contract(&self) -> &PluginContract {
                &NOOP_CONTRACT
            }

            fn lifecycle(&self) -> &dyn Lifecycle {
                &NOOP_LIFECYCLE
            }

            fn build(&self, _ctx: &mut PluginContext) -> Result<(), PluginError> {
                Ok(())
            }
        }

        let path = std::env::temp_dir()
            .join(format!("xray-frame-assembly-journal-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut fw = Framework::builder(opts(4, None))
            .expect("cap 4")
            .with_journal(&path)
            .register(Arc::new(NoopPlugin))
            .expect("register")
            .build()
            .expect("build");
        fw.bring_up().expect("bring up");
        let report = fw.shutdown().await;
        assert!(report.is_clean(), "健康链报告干净：{report:?}");

        let text = std::fs::read_to_string(&path).expect("账本落盘");
        for kind in
            ["\"kind\":\"register\"", "\"kind\":\"plugin_started\"", "\"kind\":\"plugin_stopped\""]
        {
            assert!(text.contains(kind), "轨迹缺 {kind}：{text}");
        }
        assert!(text.contains("{\"t\":\"s\""), "停机落快照行：{text}");
        let _ = std::fs::remove_file(&path);

        let fw = Framework::builder(opts(4, None)).expect("cap 4").build().expect("build");
        assert!(fw.open_journal().expect("未配置 = 零 IO").is_none(), "缺省不写盘");
    }
}

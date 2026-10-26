//! L2 能力层：插件能力集句柄（模型 §2.2 L2 行、§4 能力获取规则表）。
//!
//! 插件只能经 [`PluginContext`] 拿异步托管/超时/时钟/标识/日志/配置/handler
//! 登记八类能力；裸 `FxScope`、裸 tokio 句柄不给插件（scope 的 close/shutdown
//! 留在装配根）。段路由按 PM 拍板（2026-10-23）：**复用既有
//! `outbounds[]`/`inbounds[]` 布局，按 `protocol` 字段路由，不新增 `plugins`
//! 段**（Go 配置兼容铁律）；指纹派生按拍板：`std_ext::hash::stable64` 对主
//! 监听地址串派生，无地址退化 pid+启动时刻。

use std::{
    any::{Any, TypeId},
    collections::HashMap,
    sync::Arc,
    time::Duration,
};

use skeleton::{
    clock::{Clock, SystemClock},
    config::{ConfigError, ConfigPort, EnvError, EnvSource, StdEnv},
};
use skeleton_infra::fx::{CancelToken, FxScope, ScopeClosed, Spawned};
use std_ext::{hash::stable64, id::IdGen};

use crate::{audit::AuditHandle, error::PluginError, logging::LogFacade, pool::BufferPool};

/// 进程指纹派生（PM 拍板 2026-10-23）：有主监听地址 → `stable64(地址串)`；
/// 无地址 → `stable64(pid-启动时刻纳秒)`。指纹需进程内唯一且可复现
/// （同配置同地址 → 同指纹 → conn_id 前缀稳定）；装配根启动时调用一次。
pub fn derive_fingerprint(listen_addr: Option<&str>) -> u64 {
    match listen_addr {
        Some(addr) => stable64(addr.as_bytes()),
        None => {
            let startup_nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default();
            stable64(format!("{}-{startup_nanos}", std::process::id()).as_bytes())
        },
    }
}

/// 组合环境源：插件段值优先、装配注入的环境回落（坑约束 7 组合源半边）。
/// 段面只承载字符串值（JSON object）；非字符串段值跳过段面回落环境。
///
/// **回落只认命名空间键** `XRAY_PLUGIN_<NAME>_<KEY>`（security F10：裸同名
/// env 会让外部环境给插件注入它没在配置里写的 settings 键）。`<NAME>`/`<KEY>`
/// 归一规则固定为：转大写、非 `[A-Z0-9]` 字符替换 `_`（`vmess-in` + `web.port`
/// → `XRAY_PLUGIN_VMESS_IN_WEB_PORT`）。不构造小写变体、不做多形态回退——
/// 唯一规范形态在 Windows（键不分大小写）与 Unix（区分）上同解。
struct SectionEnv<'a> {
    /// 插件名（命名空间前缀源）。
    plugin: &'static str,
    section: Option<&'a serde_json::Map<String, serde_json::Value>>,
    fallback: &'a dyn EnvSource,
}

impl SectionEnv<'_> {
    /// 回落键的规范形态（规则见结构体文档）。
    fn env_key(&self, key: &str) -> String {
        let mut out = String::with_capacity(self.plugin.len() + key.len() + 13);
        out.push_str("XRAY_PLUGIN_");
        push_normalized(&mut out, self.plugin);
        out.push('_');
        push_normalized(&mut out, key);
        out
    }
}

/// 大写 + 非字母数字 → `_`。
fn push_normalized(out: &mut String, raw: &str) {
    out.extend(raw.chars().map(|c| {
        if c.is_ascii_uppercase() || c.is_ascii_digit() {
            c
        } else if c.is_ascii_lowercase() {
            c.to_ascii_uppercase()
        } else {
            '_'
        }
    }));
}

impl EnvSource for SectionEnv<'_> {
    fn get(&self, key: &str) -> Result<String, EnvError> {
        if let Some(section) = self.section
            && let Some(value) = section.get(key)
            && let Some(text) = value.as_str()
        {
            return Ok(text.to_owned());
        }
        self.fallback.get(&self.env_key(key))
    }
}

/// 插件能力句柄。构造只在装配根（P0-5 Framework）；插件经 `build`/生命周期
/// 方法拿到引用，拿不到裸 scope/runtime。
pub struct PluginContext {
    /// 当前装配插件（段路由键 / handler 登记归属标注）。
    plugin_name: &'static str,
    /// 共享托管 scope（拓扑：装配根建一份，Arc 注入；close/shutdown 留装配根）。
    fx: Arc<FxScope>,
    clock: Arc<dyn Clock>,
    /// conn_id 生成器（同指纹单权威：同毫秒 4096 配额 fail-closed，udf id.rs）。
    ids: IdGen,
    /// 组合源回落环境（生产 StdEnv；测试 MockEnv 注入）。
    env: Arc<dyn EnvSource>,
    /// 全局配置值面（段路由底座）。
    config_root: serde_json::Value,
    log: LogFacade,
    /// 缓冲池能力句柄（P1-1 Context 扩容件）：装配根经 `set_pool` 接线；
    /// 缺省未接线 → `pool()` fail-visible panic（装配门 L5 语义）。
    pool: Option<Arc<dyn BufferPool>>,
    /// 审计事件流句柄（L2 第⑦柄，`ctx.audit()`）：底座 = udf `memgov::
    /// BoundedRegistry` 有界环（`EvictOldest` + 溢出显式计数）。装配根建一份
    /// 共享，全插件事件落同一环（`plugin` 字段标注归属）。
    audit: Arc<AuditHandle>,
    /// 擦除登记表（原型 xray-core/src/instance.rs:60 feature_typed）。
    handlers: HashMap<TypeId, Arc<dyn Any + Send + Sync>>,
}

impl PluginContext {
    /// 装配根构造入口。`fingerprint` 经 [`derive_fingerprint`] 派生；
    /// `log` 域约定 = 插件名（`LogFacade::new(plugin_name, secrets)`）。
    // nn8os 2a 打回处置（2026-10-26 PM）：8 参 = L2 能力清单一一映射（fx/
    // clock/env/config_root/log/audit 为装配根**分别持有**的异质能力源，
    // 非内聚数据结构）——打包成结构体只是参数搬家 + 新增 pub 类型 + 11 处
    // 构造点改写，零行为收益；构造器逐能力注入是 L2 设计的直接形态，
    // 故 allow 而非改签名。
    #[allow(
        clippy::too_many_arguments,
        reason = "能力句柄构造器：参数=能力清单（L2 §4 表），异质源由装配根分别持有，打包属参数搬家"
    )]
    pub fn new(
        plugin_name: &'static str,
        fx: Arc<FxScope>,
        clock: Arc<dyn Clock>,
        fingerprint: u64,
        env: Arc<dyn EnvSource>,
        config_root: serde_json::Value,
        log: LogFacade,
        audit: Arc<AuditHandle>,
    ) -> Self {
        Self {
            plugin_name,
            ids: IdGen::new(fingerprint, Arc::clone(&clock)),
            fx,
            clock,
            env,
            config_root,
            log,
            pool: None,
            audit,
            handlers: HashMap::new(),
        }
    }

    /// 独立装配配方（臂构造/单测用）：自持 scope + 系统钟 + pid-启动时刻指纹
    /// + `StdEnv` + 空配置根 + 插件域日志门面 + 独享审计环。
    ///
    /// 与装配根 [`crate::assembly::FrameworkBuilder`] 的差异：不共享 scope/指纹/
    /// 审计环（scope close 权随 ctx 所有方——臂构造的 handler 持 ctx，scope 随
    /// handler drop 兜底 abort，blackhole B6 自持面同款生命周期）。
    /// `plugin_name` 必须传协议 kind 常量（`'static`）；运行期 kind 串由调用方
    /// 走 intern 表冻结（上界 = 协议表大小），禁传 per-instance tag。
    pub fn for_plugin(plugin_name: &'static str) -> Self {
        Self::new(
            plugin_name,
            Arc::new(FxScope::new()),
            Arc::new(SystemClock),
            derive_fingerprint(None),
            Arc::new(StdEnv),
            serde_json::json!({}),
            LogFacade::new(plugin_name, vec![]),
            Arc::new(AuditHandle::new(crate::audit::DEFAULT_AUDIT_RING_CAP)),
        )
    }

    // ── 异步托管（能力①）——唯一合法 spawn 口，透传 FxScope 契约 ──
    /// 闸关 → `Err(ScopeClosed)`；join 责任归插件，泄漏断言归 `expect_idle`
    /// （PM 拍板 2026-10-23：透传 `FxScope::Spawned`，不新造句柄类型）。
    pub fn spawn<T>(
        &self,
        fut: impl Future<Output = T> + Send + 'static,
    ) -> Result<Spawned<T>, ScopeClosed>
    where
        T: Send + 'static,
    {
        self.fx.spawn(fut)
    }

    /// 取消令牌观察面（Clone = 同一取消态；任务内携带判停）。
    pub fn token(&self) -> CancelToken {
        self.fx.token()
    }

    // ── 超时（能力②；坑约束 2 唯一入口）──
    /// `tokio::time::timeout` 包装；禁裸 sleep 由 P0-6 L3 拦。
    /// 返回具体类型 `Timeout<F>`（不借 `self`，任务可 'static 移交）。
    /// P1-4：实现委托 `crate::deadline::timeout`（构造形态，语义零变化）；
    /// 带 clock 记账的 await 形态见 `crate::deadline::with_deadline`。
    pub fn with_deadline<F: Future>(&self, fut: F, d: Duration) -> tokio::time::Timeout<F> {
        crate::deadline::timeout(fut, d)
    }

    // ── 时钟（能力③）/ 标识（能力④）──
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// conn_id 统一标识源（坑约束 3）。
    pub fn next_conn_id(&self) -> u128 {
        self.ids.r#gen().as_u128()
    }

    // ── 日志（能力⑤；P0-7 实体）──
    pub fn log(&self) -> &LogFacade {
        &self.log
    }

    // ── 审计（L2 第⑦柄；模型 §4：禁裸 tracing 事件）──
    /// 审计事件流句柄：发射 [`AuditHandle::record`]（装配根共享环，`plugin`
    /// 字段标注归属）；消费面（取证/对账）走 [`AuditHandle::take_events`]。
    pub fn audit(&self) -> &Arc<AuditHandle> {
        &self.audit
    }

    // ── 配置（能力⑥；坑约束 7 per-plugin 段路由）──
    /// 段路由：`outbounds[]` 内取 `protocol == plugin_name` 的元素，
    /// 回落 `inbounds[]`（PM 拍板：复用既有布局，不新增 `plugins` 段）。
    /// 缺段 → `Err`（fail-fast，坑约束 7 装配半边；模型 §5 缺口 #7 升级 L5）。
    // shortcut: 按 protocol 取首个匹配段，多实例同协议（不同端口/tag）会路由到同一段；
    // 升级 = P3-2 配置解析接注册链时改按实例 index/tag 路由
    pub fn section(&self) -> Result<&serde_json::Value, PluginError> {
        for layout in ["outbounds", "inbounds"] {
            let Some(items) = self.config_root.get(layout).and_then(|v| v.as_array()) else {
                continue;
            };
            if let Some(found) = items.iter().find(|item| {
                item.get("protocol").and_then(|p| p.as_str()) == Some(self.plugin_name)
            }) {
                return Ok(found);
            }
        }
        Err(PluginError::Config(ConfigError::Missing {
            key: format!("outbounds[]/inbounds[] protocol={} (section missing)", self.plugin_name),
        }))
    }

    /// 组合源装配：插件段优先、环境回落，喂给插件的 `ConfigPort`
    /// （`ConfigPort::load(&self, env: &dyn EnvSource)`，skeleton/src/config.rs）。
    /// 段的键值面取 outbound/inbound 元素的 `settings` 子对象（xray 既有布局）；
    /// 元素无 `settings` 时退化用元素本体（P0 期自持 fixture）。
    pub fn load_config<T: ConfigPort>(&self, port: T) -> Result<T::Config, PluginError> {
        let section = self.section()?;
        let kv =
            section.get("settings").and_then(|s| s.as_object()).or_else(|| section.as_object());
        let combined = SectionEnv { plugin: self.plugin_name, section: kv, fallback: &*self.env };
        port.load(&combined).map_err(PluginError::Config)
    }

    // ── 缓冲池（坑约束 4/9 唯一取池口；P1-1 Context 扩容件）──
    /// 装配根接线点：装配时注入调好参的池（`ManagedBufferPool<XrayBufPool>`
    /// 或等价 `BufferPool` 实现）；构造后、插件 `build` 前调用。
    pub fn set_pool(&mut self, pool: Arc<dyn BufferPool>) {
        self.pool = Some(pool);
    }

    /// 缓冲池能力句柄（坑约束 4：插件只经此取池，裸 `xray_buf::alloc` 由
    /// P2 批次 per-crate clippy.toml `disallowed-methods` 拦——规范源 §2.3 第 10 条）。
    ///
    /// # Panics
    ///
    /// 装配根未接线（`set_pool` 未调）→ fail-visible panic（装配门 L5：
    /// 能力缺失启动期炸，禁运行期静默）。
    pub fn pool(&self) -> &dyn BufferPool {
        self.pool.as_deref().unwrap_or_else(|| {
            panic!(
                "pool capability not wired: assembler must set_pool before plugins build (plugin {})",
                self.plugin_name
            )
        })
    }

    // ── handler 登记面（缺口 #6；插件层产出 → 查表分发的登记半边）──
    /// 擦除登记（TypeId 键 → `Arc<dyn Any>`）；同型重复登记 → `Err(Handler)`。
    /// handler trait 本体（含 xray 连接类型）在 P2 协议层定义——本面零 xray 类型。
    pub fn register_handler<T: Any + Send + Sync>(
        &mut self,
        handler: Arc<T>,
    ) -> Result<(), PluginError> {
        let id = TypeId::of::<T>();
        if self.handlers.contains_key(&id) {
            return Err(PluginError::Handler(format!(
                "handler for type {} already registered (plugin {})",
                std::any::type_name::<T>(),
                self.plugin_name
            )));
        }
        self.handlers.insert(id, handler);
        Ok(())
    }

    /// 登记面只读半边（P3-1 S1 查表 `crate::dispatch::lookup` 的取数口）：
    /// 非消费 clone（Arc 计数 +1），register/take 语义零改动。
    pub(crate) fn peek_handler_erased(
        &self,
        type_id: &TypeId,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        self.handlers.get(type_id).cloned()
    }

    /// 登记面消费半边：未登记/型不匹配 → `Err(Handler)`（取走即移除）。
    /// `pub(crate)`：消费边界在 P0-8 registry（同 crate）。曾为集成验收升格
    /// `pub`，覆盖迁入本文件单元测后收回（P0 审计打回项）。
    // P0-8 registry 接线后删除此 expect：真实调用方出现即落空报 unfulfilled。
    // 仅挂非 test 编译（--all-targets 的 lib test 目标有单元测调用，expect 会落空）。
    #[cfg_attr(not(test), expect(dead_code, reason = "消费方 P0-8 registry 落地前暂无生产调用"))]
    pub(crate) fn take_handler<T: Any + Send + Sync>(&mut self) -> Result<Arc<T>, PluginError> {
        self.handlers
            .remove(&TypeId::of::<T>())
            .and_then(|handler| handler.downcast::<T>().ok())
            .ok_or_else(|| {
                PluginError::Handler(format!(
                    "no handler registered for type {} (plugin {})",
                    std::any::type_name::<T>(),
                    self.plugin_name
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use skeleton::{
        clock::{MockClock, SystemClock},
        config::MockEnv,
    };

    use super::*;

    const FIXED_ADDR: &str = "127.0.0.1:10808";

    /// 组装配方（同集成测 ctx_at：FxScope + SystemClock + MockEnv）。
    fn ctx_at(plugin: &'static str, config: serde_json::Value) -> PluginContext {
        PluginContext::new(
            plugin,
            Arc::new(FxScope::new()),
            Arc::new(SystemClock),
            derive_fingerprint(Some(FIXED_ADDR)),
            Arc::new(MockEnv::new()),
            config,
            LogFacade::new(plugin, vec![]),
            Arc::new(AuditHandle::new(crate::audit::DEFAULT_AUDIT_RING_CAP)),
        )
    }

    /// 原 P0-3 集成测例迁入（take_handler 收回 `pub(crate)` 后 crate 外不可达）。
    #[test]
    fn handler_register_take_roundtrip_and_conflicts() {
        let mut ctx = ctx_at("stub", json!({}));

        ctx.register_handler(Arc::new(7u32)).expect("first register");
        assert!(
            matches!(ctx.register_handler(Arc::new(8u32)), Err(PluginError::Handler(_))),
            "同型重复登记 → Err(Handler)"
        );
        assert_eq!(*ctx.take_handler::<u32>().expect("typed take"), 7);
        assert!(
            matches!(ctx.take_handler::<u32>(), Err(PluginError::Handler(_))),
            "取走后再取 → Err(Handler)"
        );

        ctx.register_handler(Arc::new(9u32)).expect("re-register");
        assert!(
            matches!(ctx.take_handler::<u64>(), Err(PluginError::Handler(_))),
            "型不匹配（u32 登记取 u64）→ Err(Handler)"
        );
        assert_eq!(*ctx.take_handler::<u32>().expect("u32 unaffected"), 9);
    }

    /// env 回落键探针：缺键 → `None`（插件 settings 缺省键的语义）。
    struct KeyProbe(&'static str);

    impl ConfigPort for KeyProbe {
        type Config = Option<String>;

        fn load(&self, env: &dyn EnvSource) -> Result<Self::Config, ConfigError> {
            match env.get(self.0) {
                Ok(value) => Ok(Some(value)),
                Err(EnvError::Missing) => Ok(None),
                Err(e) => {
                    Err(ConfigError::Invalid { key: self.0.to_string(), reason: e.to_string() })
                },
            }
        }
    }

    fn ctx_with_env(
        plugin: &'static str,
        settings: serde_json::Value,
        env: MockEnv,
    ) -> PluginContext {
        PluginContext::new(
            plugin,
            Arc::new(FxScope::new()),
            Arc::new(SystemClock),
            derive_fingerprint(Some(FIXED_ADDR)),
            Arc::new(env),
            json!({ "inbounds": [{ "protocol": plugin, "settings": settings }] }),
            LogFacade::new(plugin, vec![]),
            Arc::new(AuditHandle::new(crate::audit::DEFAULT_AUDIT_RING_CAP)),
        )
    }

    /// security F10：裸同名 env 是注入面——不得喂入插件 settings 缺省键。
    #[test]
    fn bare_env_key_does_not_fall_through() {
        let ctx = ctx_with_env(
            "vmess-in",
            json!({}),
            MockEnv::new().with("PORT", "6666").with("web.port", "7777"),
        );
        assert_eq!(ctx.load_config(KeyProbe("PORT")).expect("load"), None, "裸 PORT 不回落");
        assert_eq!(
            ctx.load_config(KeyProbe("web.port")).expect("load"),
            None,
            "裸 web.port 不回落"
        );
    }

    /// 命名空间键（大写 + 非字母数字 → `_`）回落生效；段值优先于环境。
    #[test]
    fn namespaced_env_key_falls_through_and_section_wins() {
        let ctx = ctx_with_env(
            "vmess-in",
            json!({ "PORT": "1080" }),
            MockEnv::new().with("XRAY_PLUGIN_VMESS_IN_PORT", "6666"),
        );
        assert_eq!(
            ctx.load_config(KeyProbe("PORT")).expect("load").as_deref(),
            Some("1080"),
            "段值优先于回落环境"
        );

        let ctx = ctx_with_env(
            "vmess-in",
            json!({}),
            MockEnv::new().with("XRAY_PLUGIN_VMESS_IN_WEB_PORT", "7777"),
        );
        assert_eq!(
            ctx.load_config(KeyProbe("web.port")).expect("load").as_deref(),
            Some("7777"),
            "vmess-in + web.port → XRAY_PLUGIN_VMESS_IN_WEB_PORT"
        );
    }

    /// L2 注入面（nn8os 2a 验收③）：假钟 / 假审计环可注入且经句柄可达——
    /// 插件侧 `ctx.clock()` / `ctx.audit()` 拿到的就是装配方注入的那份。
    #[test]
    fn injected_mock_clock_and_audit_are_visible_via_handles() {
        let clock = Arc::new(MockClock::new());
        clock.advance(Duration::from_millis(42));
        let audit = Arc::new(AuditHandle::new(4));

        let ctx = PluginContext::new(
            "stub",
            Arc::new(FxScope::new()),
            Arc::clone(&clock) as Arc<dyn Clock>,
            derive_fingerprint(Some(FIXED_ADDR)),
            Arc::new(MockEnv::new()),
            json!({}),
            LogFacade::new("stub", vec![]),
            Arc::clone(&audit),
        );

        // 假钟推进对插件可见（同一实例，非各造各的 SystemClock）：
        // MockClock 挂钟 = UNIX_EPOCH + 虚拟偏移，经 dyn Clock 读数精确可比。
        let read = |ctx: &PluginContext| {
            ctx.clock()
                .now_system()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("MockClock 挂钟恒在纪元后")
        };
        assert_eq!(read(&ctx), Duration::from_millis(42));
        clock.advance(Duration::from_millis(8));
        assert_eq!(read(&ctx), Duration::from_millis(50));

        // 审计环同址：经 ctx 发射，装配方持有的 handle 可取走同一事件。
        assert!(Arc::ptr_eq(ctx.audit(), &audit), "audit() 必须返回注入的那份 Arc");
        ctx.audit().record("stub", "via-ctx");
        let events = audit.take_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].message, "via-ctx");
    }
}

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
    clock::Clock,
    config::{ConfigError, ConfigPort, EnvError, EnvSource},
};
use skeleton_infra::fx::{CancelToken, FxScope, ScopeClosed, Spawned};
use std_ext::{hash::stable64, id::IdGen};

use crate::{error::PluginError, logging::LogFacade, pool::BufferPool};

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
struct SectionEnv<'a> {
    section: Option<&'a serde_json::Map<String, serde_json::Value>>,
    fallback: &'a dyn EnvSource,
}

impl EnvSource for SectionEnv<'_> {
    fn get(&self, key: &str) -> Result<String, EnvError> {
        if let Some(section) = self.section
            && let Some(value) = section.get(key)
            && let Some(text) = value.as_str()
        {
            return Ok(text.to_owned());
        }
        self.fallback.get(key)
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
    /// 擦除登记表（原型 xray-core/src/instance.rs:60 feature_typed）。
    handlers: HashMap<TypeId, Arc<dyn Any + Send + Sync>>,
}

impl PluginContext {
    /// 装配根构造入口。`fingerprint` 经 [`derive_fingerprint`] 派生；
    /// `log` 域约定 = 插件名（`LogFacade::new(plugin_name, secrets)`）。
    pub fn new(
        plugin_name: &'static str,
        fx: Arc<FxScope>,
        clock: Arc<dyn Clock>,
        fingerprint: u64,
        env: Arc<dyn EnvSource>,
        config_root: serde_json::Value,
        log: LogFacade,
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
            handlers: HashMap::new(),
        }
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
    pub fn with_deadline<F: Future>(&self, fut: F, d: Duration) -> tokio::time::Timeout<F> {
        tokio::time::timeout(d, fut)
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
        let combined = SectionEnv { section: kv, fallback: &*self.env };
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
    use skeleton::{clock::SystemClock, config::MockEnv};

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
}

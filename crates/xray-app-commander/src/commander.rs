//! Commander 核心：Service 注册框架。
//!
//! 对应 Go `app/commander/commander.go` + `service.go`：
//! - [`Service`] trait：gRPC service 元数据接口（Go 隐式 interface，`Register(*grpc.Server)` 单方法）
//! - [`Commander`] struct：service 容器 + 配置载体（tag/listen）
//! - [`GrpcServerRegistrar`] trait：上层注入的注册器（屏蔽 tonic 等具体实现）
//!
//! ## Rust 化策略（与 P4-4 proxyman / P4-7 stats 一致）
//!
//! - **不引入 tonic**：gRPC server 注册逻辑留 trait，由上层（`xray-core` main）注入
//!   具体实现（封装 tonic `ServerBuilder` 等）
//! - **TypedMessage 解码留 trait**：Go 用全局 `common.RegisterConfig` 注册表 +
//!   `rawConfig.GetInstance()`；Rust 端无副作用全局，由上层显式创建 Service 实例
//!   并通过 [`Commander::add_service`] 注册
//! - **Commander 仅是配置 + service 容器**：实际 gRPC server 启动 / listen /
//!   outbound handler 注册全部留 trait + stub（依赖 transport 全链路）

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use tokio::task::JoinHandle;

use xray_features::{Feature, FeatureError};

use crate::error::{log_warning, CommanderError};
use crate::grpc;
use crate::outbound::OutboundRegistrar;
use crate::server::OutboundHandlerRegistry;
// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Commander 配置。对应 Go `app/commander/config.proto::Config`。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Outbound handler 的 tag（标识 API 流量出口）。
    /// 对应 Go `Config.Tag`。
    pub tag: String,
    /// 监听地址（`Some("127.0.0.1:8080")` / `Some("/path/to/unix.sock")`）。
    /// `None` 表示走 outbound 模式（通过 OutboundHandler 接收连接）。
    /// 对应 Go `Config.Listen`。
    pub listen: Option<String>,
    /// Service 配置列表（TypedMessage stub）。
    /// 对应 Go `Config.Service []TypedMessage`。
    pub service_configs: Vec<TypedMessageConfig>,
}

/// TypedMessage 配置载体（对应 Go `xray.common.serial.TypedMessage`）。
///
/// Commander 不直接解码，由上层按 `type_url` 路由到对应 factory 创建 Service 实例。
#[derive(Debug, Clone)]
pub struct TypedMessageConfig {
    /// Proto 类型 URL（如 `type.googleapis.com/xray.app.stats.command.Config`）。
    pub type_url: String,
    /// Proto 编码 payload。
    pub value: Vec<u8>,
}

impl TypedMessageConfig {
    /// 新建。
    #[must_use]
    pub fn new(type_url: impl Into<String>, value: Vec<u8>) -> Self {
        Self {
            type_url: type_url.into(),
            value,
        }
    }
}

// ---------------------------------------------------------------------------
// Service trait
// ---------------------------------------------------------------------------

/// Commander service 接口。对应 Go `app/commander.Service` interface。
///
/// Go 原接口仅含 `Register(*grpc.Server)` 单方法。Rust 端去掉 grpc.Server
/// 直接依赖，改为提供元数据（name/type_url），具体注册逻辑由
/// [`GrpcServerRegistrar`] 实现决定。
///
/// 每个 app crate（stats/log/proxyman command 等）实现此 trait 暴露自身。
pub trait Service: Send + Sync {
    /// Service 名（调试用）。
    fn name(&self) -> &str;

    /// Service 的 proto type URL（与 TypedMessage.type_url 对应）。
    fn type_url(&self) -> &str;
}

// ---------------------------------------------------------------------------
// GrpcServerRegistrar trait
// ---------------------------------------------------------------------------

/// gRPC server 注册器接口。
///
/// 屏蔽具体 gRPC 实现（tonic / 自研），由上层（如 `xray-core` main）注入。
/// Commander 的 [`Commander::start_with_registrar`] 调用此 trait 把每个
/// [`Service`] 注册到底层 server。
pub trait GrpcServerRegistrar: Send + Sync {
    /// 注册 service。
    ///
    /// 实现应将 service 转换为具体 gRPC service descriptor 并注册到内部 server。
    fn register(&mut self, service: &dyn Service) -> Result<(), CommanderError>;
}

/// Noop 注册器（测试 / 占位用）。
///
/// 不实际注册，仅记录 type_url 列表。用于验证编排流程。
#[derive(Debug, Default)]
pub struct NoopRegistrar {
    /// 已注册的 type_url 列表（测试断言用）。
    pub registered: Vec<String>,
}

impl NoopRegistrar {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl GrpcServerRegistrar for NoopRegistrar {
    fn register(&mut self, service: &dyn Service) -> Result<(), CommanderError> {
        let url = service.type_url();
        tracing::debug!("NoopRegistrar: register `{url}`");
        self.registered.push(url.to_string());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ReflectionService
// ---------------------------------------------------------------------------

/// gRPC reflection service 占位。对应 Go `reflectionService struct{}`。
///
/// 标准实现：上层注入时调用 `tonic_reflection::server::Builder` 注册。
#[derive(Debug, Default, Clone, Copy)]
pub struct ReflectionService;

impl ReflectionService {
    /// Service type URL（与 Go `(*ReflectionConfig)(nil)` 注册名对应）。
    pub const TYPE_URL: &'static str = "xray.app.commander.ReflectionConfig";

    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Service for ReflectionService {
    fn name(&self) -> &str {
        "reflection"
    }
    fn type_url(&self) -> &str {
        Self::TYPE_URL
    }
}

/// HandlerService 占位 Service（编排/诊断用）。
///
/// 对应 Go `xray.app.proxyman.command.Config`。实际 gRPC HandlerService 由
/// [`crate::grpc`] 在 `Feature::start` 时注册（`build_router`），此 marker 仅用于
/// Commander 的 service 容器记录，使 `service_count` / `services()` 反映配置声明。
#[derive(Debug, Default, Clone, Copy)]
pub struct HandlerServiceMarker;

impl HandlerServiceMarker {
    /// Service type URL（对应 Go `(*proxymancommand.Config)(nil)` 注册名）。
    pub const TYPE_URL: &'static str = "xray.app.proxyman.command.Config";

    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Service for HandlerServiceMarker {
    fn name(&self) -> &str {
        "handler_service"
    }
    fn type_url(&self) -> &str {
        Self::TYPE_URL
    }
}

// ---------------------------------------------------------------------------
// Commander
// ---------------------------------------------------------------------------

/// Commander 容器。对应 Go `app/commander.Commander struct`。
///
/// 持有配置（tag/listen）+ services list + running 状态。
/// gRPC server 实例由 [`GrpcServerRegistrar`] 实现持有，Commander 不直接持有
/// `*grpc.Server`（Go 端依赖 tonic 不可在 P4 阶段引入）。
pub struct Commander {
    tag: String,
    listen: Option<String>,
    services: RwLock<Vec<Arc<dyn Service>>>,
    running: AtomicBool,
    /// outbound 模式下使用的 handler 注册器（由上层注入）。
    outbound_registrar: Option<Arc<dyn crate::outbound::HandlerManager>>,
    /// HandlerService gRPC 操作的共享 handler 注册中心。
    handler_registry: Arc<OutboundHandlerRegistry>,
    /// gRPC server 后台 task 的 JoinHandle（listen 模式启动后持有，close 时 abort）。
    grpc_task: Mutex<Option<JoinHandle<()>>>,
    /// 可选的 StatsService gRPC 后端（注入后注册到 tonic server）。
    stats_service: Option<Arc<dyn xray_app_stats::command::StatsService>>,
    /// 可选的 RoutingService gRPC 后端（注入后注册到 tonic server）。
    routing_service: Option<Arc<xray_app_router::command::RoutingService>>,
    /// 可选的 ObservatoryService gRPC 后端（注入后注册到 tonic server）。
    observatory_service: Option<Arc<dyn xray_app_observatory::command::ObservatoryService>>,
}

impl Commander {
    /// 新建空 Commander。对应 Go `NewCommander(ctx, config)` 中 config 字段提取部分。
    ///
    /// Go 中 `ctx` 用于 `core.RequireFeatures` 获取 `outbound.Manager`，
    /// Rust 端 outbound handler 注入由 [`crate::outbound`] trait stub 处理，
    /// 不通过 ctx。
    #[must_use]
    pub fn new(tag: impl Into<String>, listen: Option<String>) -> Self {
        Self {
            tag: tag.into(),
            listen,
            services: RwLock::new(Vec::new()),
            running: AtomicBool::new(false),
            outbound_registrar: None,
            handler_registry: Arc::new(OutboundHandlerRegistry::new()),
            grpc_task: Mutex::new(None),
            stats_service: None,
            routing_service: None,
            observatory_service: None,
        }
    }
    /// 从 [`Config`] 构造（不解码 TypedMessage，仅复制 tag/listen/service_configs 元数据）。
    ///
    /// Service 实例创建由上层负责（依赖具体 factory），通过 [`Self::add_service`] 注册。
    #[must_use]
    pub fn from_config(config: Config) -> Self {
        let c = Self::new(config.tag, config.listen);
        // service_configs 不在此解码（Go 用全局注册表 + CreateObject，Rust 无副作用全局）
        // 上层应基于 config.service_configs 创建 Service 实例后 add_service
        c
    }

    /// Outbound handler tag。
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// 监听地址（`None` 走 outbound 模式）。
    pub fn listen(&self) -> Option<&str> {
        self.listen.as_deref()
    }

    /// 设置 outbound handler 注册器（ outbound 模式下使用）。
    /// 要求对象同时实现 [`OutboundRegistrar`] 与 [`crate::outbound::HandlerManager`]。
    pub fn set_outbound_registrar(
        &mut self,
        registrar: Arc<dyn crate::outbound::HandlerManager>,
    ) {
        self.outbound_registrar = Some(registrar);
    }

    /// 注入 StatsService gRPC 后端（`start` 时注册到 tonic server）。
    pub fn set_stats_service(
        &mut self,
        service: Arc<dyn xray_app_stats::command::StatsService>,
    ) {
        self.stats_service = Some(service);
    }

    /// 注入 RoutingService gRPC 后端（`start` 时注册到 tonic server）。
    pub fn set_routing_service(
        &mut self,
        service: Arc<xray_app_router::command::RoutingService>,
    ) {
        self.routing_service = Some(service);
    }

    /// 注入 ObservatoryService gRPC 后端（`start` 时注册到 tonic server）。
    pub fn set_observatory_service(
        &mut self,
        service: Arc<dyn xray_app_observatory::command::ObservatoryService>,
    ) {
        self.observatory_service = Some(service);
    }

    /// 添加 service。返回是否成功（type_url 重复时拒绝）。
    ///
    /// 对应 Go `c.services = append(c.services, service)`，加去重保护。
    pub fn add_service(&self, service: Arc<dyn Service>) -> bool {
        let mut services = self.services.write();
        let type_url = service.type_url();
        if services.iter().any(|s| s.type_url() == type_url) {
            log_warning(format!("service `{type_url}` already registered, ignored"));
            return false;
        }
        services.push(service);
        true
    }

    /// 按 type_url 移除 service。返回是否找到并移除。
    pub fn remove_service(&self, type_url: &str) -> bool {
        let mut services = self.services.write();
        let before = services.len();
        services.retain(|s| s.type_url() != type_url);
        services.len() != before
    }

    /// 当前已注册 service 列表（克隆 Arc 引用）。
    pub fn services(&self) -> Vec<Arc<dyn Service>> {
        self.services.read().clone()
    }

    /// service 数量。
    pub fn service_count(&self) -> usize {
        self.services.read().len()
    }

    /// 是否运行中。对应 Go 隐含的 `c.server != nil` 状态。
    pub fn running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// HandlerService gRPC 操作的共享 handler 注册中心引用。
    ///
    /// 上层（如 dispatcher）可获取此 registry，使 gRPC add/remove outbound 影响
    /// 实际路由。当前 Commander 内部独占使用。
    pub fn handler_registry(&self) -> Arc<OutboundHandlerRegistry> {
        Arc::clone(&self.handler_registry)
    }

    /// 启动 Commander：把所有 service 注册到 registrar，标记 running=true。
    ///
    /// 对应 Go `Commander.Start()`：
    /// 1. 创建 grpc.Server（由 registrar 实现持有）
    /// 2. 调用每个 service.Register(server)
    /// 3. 监听 listen / 注册 outbound handler（依赖 transport 全链路，留 stub）
    ///
    /// **未实现部分**（依赖上层 + transport）：
    /// - `internet.ListenSystem`：TCP/Unix socket 监听
    /// - `ohm.AddHandler`：注册 Outbound handler（接收 API 连接）
    /// - `server.Serve(listener)`：实际 gRPC serve 循环
    ///
    /// 这些由上层 `xray-core` main 注入完成。
    pub fn start_with_registrar<R: GrpcServerRegistrar>(
        &self,
        registrar: &mut R,
    ) -> Result<(), CommanderError> {
        // 已运行则幂等返回
        if self
            .running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            log_warning("commander already running, start is no-op");
            return Ok(());
        }

        // 注册每个 service
        let services = self.services.read().clone();
        for s in &services {
            registrar.register(s.as_ref())?;
        }

        // listen 模式判断
        match &self.listen {
            Some(addr) => {
                tracing::info!("commander would listen on `{addr}` (actual bind deferred)");
            }
            None => {
                // outbound 模式：若已注入 outbound_registrar，注册自身 handler
                if let Some(ref _reg) = self.outbound_registrar {
                    tracing::info!(
                        "commander in outbound mode (tag=`{}`) — outbound handler register delegated",
                        self.tag
                    );
                } else {
                    tracing::info!(
                        "commander in outbound mode (tag=`{}`) — no outbound registrar injected",
                        self.tag
                    );
                }
            }
        }
        Ok(())
    }

    /// 启动 gRPC server（listen 模式）。
    ///
    /// 解析 [`Self::listen`]，构建 tonic `Router`（注册 HandlerService），
    /// `tokio::spawn` 后台 serve。JoinHandle 存入 `grpc_task`，供 [`Self::close`] abort。
    ///
    /// **必须在 tokio runtime 上下文中调用**（`Feature::start` 已保证）。
    /// outbound 模式（listen=None）不启动 server，仅记日志（transport 全链路待接入）。
    fn serve_grpc(&self) -> Result<(), CommanderError> {
        let Some(addr_str) = &self.listen else {
            tracing::info!(
                "commander (tag=`{}`) in outbound mode — gRPC serve skipped (no listen addr)",
                self.tag
            );
            return Ok(());
        };
        let addr = grpc::parse_listen_addr(addr_str)
            .map_err(|e| CommanderError::InvalidListenAddr {
                addr: addr_str.clone(),
                reason: e,
            })?;

        let router = grpc::build_router(
            Arc::clone(&self.handler_registry),
            self.stats_service.clone(),
            self.routing_service.clone(),
            self.observatory_service.clone(),
        );
        tracing::info!("commander gRPC server listening on {addr} (tag=`{}`)", self.tag);

        let handle = tokio::spawn(async move {
            if let Err(e) = router.serve(addr).await {
                tracing::error!("commander gRPC server exited with error: {e}");
            }
        });

        *self.grpc_task.lock() = Some(handle);
        Ok(())
    }

    /// 关闭 Commander。对应 Go `Commander.Close()`。
    ///
    /// 标记 running=false 并 abort 后台 gRPC serve task。
    pub fn close(&self) -> Result<(), CommanderError> {
        let was_running = self
            .running
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst);
        if was_running.is_err() {
            log_warning("commander not running, close is no-op");
            return Ok(());
        }
        // abort 后台 gRPC serve task（listen 模式下存在）。
        if let Some(handle) = self.grpc_task.lock().take() {
            handle.abort();
            tracing::info!("commander gRPC server stopped (tag=`{}`)", self.tag);
        }
        tracing::info!("commander closed (tag=`{}`)", self.tag);
        Ok(())
    }
}

impl crate::outbound::HandlerManager for Commander {
    fn add_handler(
        &self,
        handler: Arc<dyn xray_features::outbound::OutboundHandler>,
    ) -> Result<(), CommanderError> {
        match self.outbound_registrar.as_ref() {
            Some(reg) => reg.add_handler(handler),
            None => Err(CommanderError::OutboundRegisterFailed(
                "no outbound registrar injected".into(),
            )),
        }
    }

    fn remove_handler(&self, tag: &str) -> Result<(), CommanderError> {
        match self.outbound_registrar.as_ref() {
            Some(reg) => reg.remove_handler(tag),
            None => Err(CommanderError::OutboundRegisterFailed(
                "no outbound registrar injected".into(),
            )),
        }
    }

    fn list_handlers(&self) -> Vec<String> {
        match self.outbound_registrar.as_ref() {
            Some(reg) => reg.list_handlers(),
            None => Vec::new(),
        }
    }
}

impl std::fmt::Debug for Commander {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Commander")
            .field("tag", &self.tag)
            .field("listen", &self.listen)
            .field("service_count", &self.service_count())
            .field("running", &self.running())
            .field("has_outbound_registrar", &self.outbound_registrar.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Feature trait impl（生产路径：start 启动 gRPC server）
// ---------------------------------------------------------------------------

/// Commander 作为 Feature：`start` 在配置的 listen 地址启动 gRPC server，
/// `close` abort 后台 serve task。
///
/// 这是 commander 接入 `Instance` 生命周期的生产路径（对应 Go `Commander.Start()`）。
/// `start_with_registrar` / `GrpcServerRegistrar` 仅用于测试 / 编排验证。
impl Feature for Commander {
    fn feature_name(&self) -> &'static str {
        "commander"
    }

    fn start(&self) -> xray_features::Result<()> {
        // 幂等：已运行直接返回。
        if self
            .running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            log_warning("commander already running, start is no-op");
            return Ok(());
        }
        self.serve_grpc()
            .map_err(|e| FeatureError::StartFailed {
                name: "commander",
                message: e.to_string(),
            })?;
        Ok(())
    }

    fn close(&self) -> xray_features::Result<()> {
        Commander::close(self).map_err(|e| FeatureError::CloseFailed {
            name: "commander",
            message: e.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试 Service 实现。
    #[derive(Debug)]
    struct StatsService;
    impl Service for StatsService {
        fn name(&self) -> &str {
            "stats"
        }
        fn type_url(&self) -> &str {
            "xray.app.stats.command.Config"
        }
    }

    #[derive(Debug)]
    struct LogService;
    impl Service for LogService {
        fn name(&self) -> &str {
            "log"
        }
        fn type_url(&self) -> &str {
            "xray.app.log.command.Config"
        }
    }

    fn make_stats() -> Arc<dyn Service> {
        Arc::new(StatsService)
    }
    fn make_log() -> Arc<dyn Service> {
        Arc::new(LogService)
    }

    // --- Config / TypedMessageConfig ---

    #[test]
    fn typed_message_config_new() {
        let tmc = TypedMessageConfig::new("type.googleapis.com/xray.Foo", vec![1, 2, 3]);
        assert_eq!(tmc.type_url, "type.googleapis.com/xray.Foo");
        assert_eq!(tmc.value, vec![1, 2, 3]);
    }

    #[test]
    fn config_default_empty() {
        let c = Config::default();
        assert!(c.tag.is_empty());
        assert!(c.listen.is_none());
        assert!(c.service_configs.is_empty());
    }

    // --- Service trait ---

    #[test]
    fn reflection_service_type_url() {
        assert_eq!(ReflectionService::TYPE_URL, "xray.app.commander.ReflectionConfig");
        let r = ReflectionService::new();
        assert_eq!(r.name(), "reflection");
        assert_eq!(r.type_url(), ReflectionService::TYPE_URL);
    }

    #[test]
    fn reflection_service_default_constructible() {
        let _r = ReflectionService::default();
    }

    #[test]
    fn service_trait_object_safe() {
        let s: Arc<dyn Service> = make_stats();
        assert_eq!(s.name(), "stats");
        assert_eq!(s.type_url(), "xray.app.stats.command.Config");
    }

    // --- Commander 构造 ---

    #[test]
    fn commander_new_listen_mode() {
        let c = Commander::new("api", Some("127.0.0.1:8080".into()));
        assert_eq!(c.tag(), "api");
        assert_eq!(c.listen(), Some("127.0.0.1:8080"));
        assert!(!c.running());
        assert_eq!(c.service_count(), 0);
    }

    #[test]
    fn commander_new_outbound_mode() {
        let c = Commander::new("api_out", None);
        assert_eq!(c.tag(), "api_out");
        assert!(c.listen().is_none());
    }

    #[test]
    fn commander_from_config_preserves_tag_listen() {
        let cfg = Config {
            tag: "t1".into(),
            listen: Some(":9999".into()),
            service_configs: vec![TypedMessageConfig::new("foo", vec![])],
        };
        let c = Commander::from_config(cfg);
        assert_eq!(c.tag(), "t1");
        assert_eq!(c.listen(), Some(":9999"));
        // service_configs 不在此解码，services list 仍空
        assert_eq!(c.service_count(), 0);
    }

    // --- add / remove service ---

    #[test]
    fn add_service_increments_count() {
        let c = Commander::new("t", None);
        assert!(c.add_service(make_stats()));
        assert_eq!(c.service_count(), 1);
    }

    #[test]
    fn add_service_duplicate_rejected() {
        let c = Commander::new("t", None);
        assert!(c.add_service(make_stats()));
        assert!(!c.add_service(make_stats()), "duplicate must be rejected");
        assert_eq!(c.service_count(), 1);
    }

    #[test]
    fn add_service_multiple_different() {
        let c = Commander::new("t", None);
        assert!(c.add_service(make_stats()));
        assert!(c.add_service(make_log()));
        assert_eq!(c.service_count(), 2);
    }

    #[test]
    fn remove_service_existing() {
        let c = Commander::new("t", None);
        c.add_service(make_stats());
        assert!(c.remove_service("xray.app.stats.command.Config"));
        assert_eq!(c.service_count(), 0);
    }

    #[test]
    fn remove_service_missing_returns_false() {
        let c = Commander::new("t", None);
        assert!(!c.remove_service("nope"));
    }

    #[test]
    fn services_returns_clone() {
        let c = Commander::new("t", None);
        c.add_service(make_stats());
        c.add_service(make_log());
        let v = c.services();
        assert_eq!(v.len(), 2);
        // 再次取不影响内部
        assert_eq!(c.service_count(), 2);
    }

    // --- start / close ---

    #[test]
    fn start_with_registrar_registers_all() {
        let c = Commander::new("t", None);
        c.add_service(make_stats());
        c.add_service(make_log());
        let mut reg = NoopRegistrar::new();
        c.start_with_registrar(&mut reg).unwrap();
        assert!(c.running());
        assert_eq!(reg.registered.len(), 2);
        assert!(reg.registered.contains(&"xray.app.stats.command.Config".into()));
        assert!(reg.registered.contains(&"xray.app.log.command.Config".into()));
    }

    #[test]
    fn start_idempotent_when_running() {
        let c = Commander::new("t", None);
        c.add_service(make_stats());
        let mut reg = NoopRegistrar::new();
        c.start_with_registrar(&mut reg).unwrap();
        assert!(c.running());
        // 二次 start 不报错，但不重复注册
        c.start_with_registrar(&mut reg).unwrap();
        assert_eq!(reg.registered.len(), 1, "second start must not re-register");
    }

    #[test]
    fn start_with_empty_services() {
        let c = Commander::new("t", None);
        let mut reg = NoopRegistrar::new();
        c.start_with_registrar(&mut reg).unwrap();
        assert!(c.running());
        assert!(reg.registered.is_empty());
    }

    #[test]
    fn close_marks_not_running() {
        let c = Commander::new("t", None);
        let mut reg = NoopRegistrar::new();
        c.start_with_registrar(&mut reg).unwrap();
        c.close().unwrap();
        assert!(!c.running());
    }

    #[test]
    fn close_idempotent_when_not_running() {
        let c = Commander::new("t", None);
        c.close().unwrap(); // 未启动时也 Ok
        assert!(!c.running());
    }

    #[test]
    fn restart_after_close() {
        let c = Commander::new("t", None);
        c.add_service(make_stats());
        let mut reg = NoopRegistrar::new();
        c.start_with_registrar(&mut reg).unwrap();
        c.close().unwrap();
        // 重启重新注册
        let mut reg2 = NoopRegistrar::new();
        c.start_with_registrar(&mut reg2).unwrap();
        assert!(c.running());
        assert_eq!(reg2.registered.len(), 1);
    }

    // --- Debug format ---

    #[test]
    fn debug_format() {
        let c = Commander::new("api", Some(":8080".into()));
        c.add_service(make_stats());
        let s = format!("{c:?}");
        assert!(s.contains("Commander"));
        assert!(s.contains("tag"));
        assert!(s.contains("api"));
        assert!(s.contains("service_count: 1"));
        assert!(s.contains("has_outbound_registrar: false"));
    }
    // --- NoopRegistrar ---

    #[test]
    fn noop_registrar_default_constructible() {
        let reg = NoopRegistrar::default();
        assert!(reg.registered.is_empty());
    }

    // --- Registrar error propagation ---

    #[test]
    fn registrar_error_propagates() {
        struct FailingRegistrar;
        impl GrpcServerRegistrar for FailingRegistrar {
            fn register(&mut self, service: &dyn Service) -> Result<(), CommanderError> {
                Err(CommanderError::Registrar(format!(
                    "fail on {}",
                    service.type_url()
                )))
            }
        }

        let c = Commander::new("t", None);
        c.add_service(make_stats());
        let mut reg = FailingRegistrar;
        let err = c.start_with_registrar(&mut reg).unwrap_err();
        match err {
            CommanderError::Registrar(msg) => {
                assert!(msg.contains("xray.app.stats.command.Config"));
            }
            e => panic!("expected Registrar, got {e:?}"),
        }
        // 失败时 running 标志未回滚（Go 行为一致，错误冒泡给上层）
        // 这是设计取舍：要么回滚要么不回滚，Go 行为是 server 已创建 + 部分注册
        assert!(c.running());
    }
}
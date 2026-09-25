//! Commander 核心：Service 注册框架。
//!
//! 对应 Go `app/commander/commander.go` + `service.go`：
//! - [`Service`] trait：gRPC service 元数据接口（Go 隐式 interface，`Register(*grpc.Server)`
//!   单方法）
//! - [`Commander`] struct：service 容器 + 配置载体（tag/listen）
//! - [`GrpcServerRegistrar`] trait：上层注入的注册器（屏蔽 tonic 等具体实现）
//!
//! ## Rust 化策略（与 P4-4 proxyman / P4-7 stats 一致）
//!
//! - **不引入 tonic**：gRPC server 注册逻辑留 trait，由上层（`xray-core` main）注入 具体实现（封装
//!   tonic `ServerBuilder` 等）
//! - **TypedMessage 解码留 trait**：Go 用全局 `common.RegisterConfig` 注册表 +
//!   `rawConfig.GetInstance()`；Rust 端无副作用全局，由上层显式创建 Service 实例 并通过
//!   [`Commander::add_service`] 注册
//! - **Commander 仅是配置 + service 容器**：实际 gRPC server 启动 / listen / outbound handler
//!   注册全部留 trait + stub（依赖 transport 全链路）

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use parking_lot::{Mutex, RwLock};
use tokio::task::JoinHandle;
use xray_features::{Feature, FeatureError};

use crate::{
    error::{CommanderError, log_warning},
    grpc,
    server::OutboundHandlerRegistry,
};
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
        Self { type_url: type_url.into(), value }
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

/// Go `infra/conf/api.go:29-42` 认可的六服务名 type_url 集合。
///
/// `ApiConfig.services` 声明的服务决定 [`Commander`] `Feature::start` 实际暴露的
/// gRPC service 面（Go `Commander.Start` 只注册 `config.Service` 列举的服务，
/// 未声明 = 不暴露）。
pub mod api_services {
    /// HandlerService（Go `handlerservice.Config`）。
    pub const HANDLER: &str = super::HandlerServiceMarker::TYPE_URL;
    /// ReflectionService（Go `commander.ReflectionConfig`）。
    pub const REFLECTION: &str = super::ReflectionService::TYPE_URL;
    /// LoggerService（Go `log/command.Config`）。
    pub const LOGGER: &str = "xray.app.log.command.Config";
    /// StatsService（Go `stats/command.Config`）。
    pub const STATS: &str = "xray.app.stats.command.Config";
    /// RoutingService（Go `router/command.Config`）。
    pub const ROUTING: &str = "xray.app.router.command.Config";
    /// ObservatoryService（Go `core/app/observatory/command.Config`）。
    pub const OBSERVATORY: &str = "xray.core.app.observatory.command.Config";
}

/// 配置声明的 command service marker（Logger/Stats/Routing/Observatory）。
///
/// 对应 Go `serial.ToTypedMessage(&xxx.Config{})` 的 TypedMessage 条目。实际
/// gRPC 实现由装配层注入后端（`set_*_service`），marker 仅记录配置声明，
/// 供 `serve_grpc` 门控实际暴露面。
#[derive(Debug, Clone, Copy)]
pub struct DeclaredServiceMarker {
    name: &'static str,
    type_url: &'static str,
}

impl DeclaredServiceMarker {
    /// 用服务名 + type_url 构造。
    #[must_use]
    pub fn new(name: &'static str, type_url: &'static str) -> Self {
        Self { name, type_url }
    }
}

impl Service for DeclaredServiceMarker {
    fn name(&self) -> &str {
        self.name
    }

    fn type_url(&self) -> &str {
        self.type_url
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
    /// 可选的 StatsService gRPC 后端（注入后、且 `services` 声明了 StatsService
    /// 时注册到 tonic server）。`RwLock` 支持上层在 `Arc<Commander>` 上注入。
    stats_service: RwLock<Option<Arc<dyn xray_app_stats::command::StatsService>>>,
    /// 可选的 RoutingService gRPC 后端（注入后、且声明时注册到 tonic server）。
    routing_service: RwLock<Option<Arc<xray_app_router::command::RoutingService>>>,
    /// 可选的 ObservatoryService gRPC 后端（注入后、且声明时注册到 tonic server）。
    observatory_service: RwLock<Option<Arc<dyn xray_app_observatory::command::ObservatoryService>>>,
    /// 生产 outbound 运行时（bd ze3）：HandlerService 操作真实 SimpleOhm。
    /// `RwLock` 支持上层在 `Arc<Commander>` 上注入（get_feature 后 set）。
    outbound_runtime: RwLock<Option<Arc<dyn crate::grpc::OutboundRuntime>>>,
    /// LoggerService gRPC 后端（bd ze3）：DefaultLogService → LogInstance::restart。
    logger_service: RwLock<Option<Arc<dyn xray_app_log::command::LogService>>>,
    /// DispatchHandler 注册器（bd pa7）：outbound 模式下把 commander 的
    /// outbound handler 注册进生产 outbound manager（SimpleOhm）。
    dispatch_registrar: RwLock<Option<Arc<dyn crate::server::DispatchRegistrar>>>,
    /// proxyman 领域 HandlerService（bd 7iqw）：inbound 7 op + alter_outbound 委托。
    handler_service: RwLock<Option<Arc<dyn xray_app_proxyman::command::HandlerService>>>,
    /// outbound 模式的 listener（start 后存在；close 时关闭以终止 serve）。
    outbound_listener: RwLock<Option<Arc<crate::server::OutboundListenerImpl>>>,
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
            stats_service: RwLock::new(None),
            routing_service: RwLock::new(None),
            observatory_service: RwLock::new(None),
            outbound_runtime: RwLock::new(None),
            logger_service: RwLock::new(None),
            dispatch_registrar: RwLock::new(None),
            handler_service: RwLock::new(None),
            outbound_listener: RwLock::new(None),
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
    /// 要求对象同时实现 `OutboundRegistrar` 与 [`crate::outbound::HandlerManager`]。
    pub fn set_outbound_registrar(&mut self, registrar: Arc<dyn crate::outbound::HandlerManager>) {
        self.outbound_registrar = Some(registrar);
    }

    /// 注入 StatsService gRPC 后端。`&self`（内部 RwLock）：上层在
    /// `Arc<Commander>` 上注入；仅当 `services` 声明 StatsService 时实际暴露。
    pub fn set_stats_service(&self, service: Arc<dyn xray_app_stats::command::StatsService>) {
        *self.stats_service.write() = Some(service);
    }

    /// 注入 RoutingService gRPC 后端。`&self`（内部 RwLock）。
    pub fn set_routing_service(&self, service: Arc<xray_app_router::command::RoutingService>) {
        *self.routing_service.write() = Some(service);
    }

    /// 注入 ObservatoryService gRPC 后端。`&self`（内部 RwLock）。
    pub fn set_observatory_service(
        &self,
        service: Arc<dyn xray_app_observatory::command::ObservatoryService>,
    ) {
        *self.observatory_service.write() = Some(service);
    }

    /// 注入生产 outbound 运行时（bd ze3）。`&self`（内部 RwLock）：
    /// 上层经 `instance.get_feature::<Commander>()` 拿到 `Arc` 后、`start()` 前注入。
    pub fn set_outbound_runtime(&self, runtime: Arc<dyn crate::grpc::OutboundRuntime>) {
        *self.outbound_runtime.write() = Some(runtime);
    }

    /// 注入 LoggerService gRPC 后端（bd ze3，`DefaultLogService` → LogInstance::restart）。
    pub fn set_logger_service(&self, service: Arc<dyn xray_app_log::command::LogService>) {
        *self.logger_service.write() = Some(service);
    }

    /// 注入 DispatchHandler 注册器（bd pa7）。`&self`（内部 RwLock）：
    /// outbound 模式 start 前注入，commander 把自身 handler 注册进 SimpleOhm。
    pub fn set_dispatch_registrar(&self, reg: Arc<dyn crate::server::DispatchRegistrar>) {
        *self.dispatch_registrar.write() = Some(reg);
    }

    /// 注入 proxyman 领域 HandlerService（bd 7iqw）：inbound 7 op + alter_outbound
    /// gRPC 委托（Go `handlerServer` 的 ihm/ohm）。
    pub fn set_handler_service(
        &self,
        service: Arc<dyn xray_app_proxyman::command::HandlerService>,
    ) {
        *self.handler_service.write() = Some(service);
    }

    /// 添加 service。返回是否成功（type_url 重复时拒绝）。
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
        if self.running.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
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
            },
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
            },
        }
        Ok(())
    }

    /// 启动 gRPC server（三种模式，对应 Go `Commander.Start` commander.go:64-116）。
    ///
    /// 1. **TCP listen**：`router.serve(addr)` 后台 task；
    /// 2. **Unix listen**（`/`/`@` 前缀）：`UnixListener` + `serve_with_incoming` （Go
    ///    commander.go:81-82；tokio UDS 仅 unix 平台可用）；
    /// 3. **outbound 模式**（listen=None）：`OutboundListenerImpl` +
    ///    `OutboundHandlerImpl`（DispatchHandler，dispatch Link → cnc conn → listener）注册进注入的
    ///    dispatch registrar（SimpleOhm），gRPC serve 循环从 listener accept（Go
    ///    commander.go:101-115）。
    ///
    /// **必须在 tokio runtime 上下文中调用**（`Feature::start` 已保证）。
    fn serve_grpc(&self) -> Result<(), CommanderError> {
        // bd dnw3：services 声明集 = 暴露面 allowlist。对应 Go
        // `Commander.Start`（commander.go:67-69）只注册 `config.Service`
        // 列举的服务——未声明不暴露（Go infra/conf/api.go `Services []string`
        // 六服务名 → TypedMessage 列表）。后端注入（Some）与声明（marker）
        // 双条件同时满足才注册。
        let declared = |url: &str| self.services().iter().any(|s| s.type_url() == url);
        let enable_reflection = declared(api_services::REFLECTION);
        let enable_handler = declared(api_services::HANDLER);
        let logger =
            declared(api_services::LOGGER).then(|| self.logger_service.read().clone()).flatten();
        let stats =
            declared(api_services::STATS).then(|| self.stats_service.read().clone()).flatten();
        let routing =
            declared(api_services::ROUTING).then(|| self.routing_service.read().clone()).flatten();
        let observatory = declared(api_services::OBSERVATORY)
            .then(|| self.observatory_service.read().clone())
            .flatten();
        if !enable_handler
            && logger.is_none()
            && stats.is_none()
            && routing.is_none()
            && observatory.is_none()
            && !enable_reflection
        {
            tracing::warn!(
                "commander gRPC server exposes no services (services list empty or undeclared)"
            );
        }
        let router = grpc::build_router(
            Arc::clone(&self.handler_registry),
            enable_handler,
            enable_reflection,
            self.handler_service.read().clone(),
            self.outbound_runtime.read().clone(),
            logger,
            stats,
            routing,
            observatory,
        );

        match self.listen.as_deref().map(grpc::parse_listen_spec) {
            // TCP listen 模式
            Some(Ok(grpc::ListenSpec::Tcp(addr))) => {
                tracing::info!("commander gRPC server listening on {addr} (tag=`{}`)", self.tag);
                let handle = tokio::spawn(async move {
                    if let Err(e) = router.serve(addr).await {
                        tracing::error!("commander gRPC server exited with error: {e}");
                    }
                });
                *self.grpc_task.lock() = Some(handle);
                Ok(())
            },
            // Unix domain socket listen 模式（Go commander.go:81-82）。
            // tokio 的 UnixListener 仍仅 unix 平台（cfg_net_unix = unix+feature=net），
            // 不暴露给 Windows——虽然 Win10 1803+ 底层有 AF_UNIX，但 tokio 不包装。
            // 此处给 Windows 提供更明确的运行期提示，d0yi：明确指出要换 TCP 或
            // 切到 WSL 监听 unix 路径（d0yi：之前是裸错"requires unix platform"
            // 但没有任何 next-step 指引）。
            #[cfg(unix)]
            Some(Ok(grpc::ListenSpec::Unix(path))) => {
                use tokio::net::UnixListener;
                let listener =
                    UnixListener::bind(&path).map_err(|e| CommanderError::InvalidListenAddr {
                        addr: path.clone(),
                        reason: format!("bind unix socket: {e}"),
                    })?;
                tracing::info!(
                    "commander gRPC server listening on unix:{path} (tag=`{}`)",
                    self.tag
                );
                let handle = tokio::spawn(async move {
                    if let Err(e) = router
                        .serve_with_incoming(
                            tonic::codegen::tokio_stream::wrappers::UnixListenerStream::new(
                                listener,
                            ),
                        )
                        .await
                    {
                        tracing::error!("commander gRPC server exited with error: {e}");
                    }
                });
                *self.grpc_task.lock() = Some(handle);
                Ok(())
            },
            // d0yi：Windows 走更明确的 next-step 指引——要么改 listen 为 TCP/pipe，
            // 要么在 WSL 中跑 Rust server 监听 unix 路径；裸 cfg(unix) 拒绝没指引。
            #[cfg(not(unix))]
            Some(Ok(grpc::ListenSpec::Unix(path))) => Err(CommanderError::InvalidListenAddr {
                addr: path,
                reason: "commander unix listen not supported on Windows: \
                        tokio::net::UnixListener is unix-only. Use listen: 127.0.0.1:port \
                        (TCP) or run inside WSL/Linux."
                    .into(),
            }),
            Some(Err(reason)) => Err(CommanderError::InvalidListenAddr {
                addr: self.listen.clone().unwrap_or_default(),
                reason,
            }),
            // outbound 模式：cnc dispatch → OutboundListener → gRPC serve
            None => {
                let listener = Arc::new(crate::server::OutboundListenerImpl::new());
                let handler = Arc::new(crate::server::OutboundHandlerImpl::new(
                    self.tag.clone(),
                    Arc::clone(&listener),
                ));
                handler.start()?;
                match self.dispatch_registrar.read().clone() {
                    Some(reg) => {
                        // Go commander.go:108-110：RemoveHandler 旧 tag（忽略错误）后 AddHandler。
                        let _ = reg.remove_dispatch_handler(&self.tag);
                        reg.add_dispatch_handler(&self.tag, handler)?;
                    },
                    None => {
                        tracing::warn!(
                            "commander outbound mode without dispatch registrar — \
                             connections routed to tag `{}` will not reach the API server",
                            self.tag
                        );
                    },
                }
                let incoming = grpc::ListenerIncoming::new(Arc::clone(&listener));
                tracing::info!(
                    "commander gRPC server serving via outbound handler (tag=`{}`)",
                    self.tag
                );
                let handle = tokio::spawn(async move {
                    if let Err(e) = router.serve_with_incoming(incoming).await {
                        tracing::error!("commander gRPC server exited with error: {e}");
                    }
                });
                *self.outbound_listener.write() = Some(listener);
                *self.grpc_task.lock() = Some(handle);
                Ok(())
            },
        }
    }

    /// 关闭 Commander。对应 Go `Commander.Close()`。
    ///
    /// 标记 running=false，关闭 outbound listener（终止 accept stream → serve
    /// 循环退出），abort 后台 gRPC serve task。
    pub fn close(&self) -> Result<(), CommanderError> {
        let was_running =
            self.running.compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst);
        if was_running.is_err() {
            log_warning("commander not running, close is no-op");
            return Ok(());
        }
        // outbound 模式：关 listener（accept 返回 None → serve_with_incoming 结束）
        use crate::outbound::OutboundListener as _;
        if let Some(listener) = self.outbound_listener.write().take() {
            listener.close()?;
        }
        // abort 后台 gRPC serve task。
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
            None => {
                Err(CommanderError::OutboundRegisterFailed("no outbound registrar injected".into()))
            },
        }
    }

    fn remove_handler(&self, tag: &str) -> Result<(), CommanderError> {
        match self.outbound_registrar.as_ref() {
            Some(reg) => reg.remove_handler(tag),
            None => {
                Err(CommanderError::OutboundRegisterFailed("no outbound registrar injected".into()))
            },
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
        if self.running.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            log_warning("commander already running, start is no-op");
            return Ok(());
        }
        self.serve_grpc()
            .map_err(|e| FeatureError::StartFailed { name: "commander", message: e.to_string() })?;
        Ok(())
    }

    fn close(&self) -> xray_features::Result<()> {
        Commander::close(self)
            .map_err(|e| FeatureError::CloseFailed { name: "commander", message: e.to_string() })
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
        let _r = ReflectionService;
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
                Err(CommanderError::Registrar(format!("fail on {}", service.type_url())))
            }
        }

        let c = Commander::new("t", None);
        c.add_service(make_stats());
        let mut reg = FailingRegistrar;
        let err = c.start_with_registrar(&mut reg).unwrap_err();
        match err {
            CommanderError::Registrar(msg) => {
                assert!(msg.contains("xray.app.stats.command.Config"));
            },
            e => panic!("expected Registrar, got {e:?}"),
        }
        // 失败时 running 标志未回滚（Go 行为一致，错误冒泡给上层）
        // 这是设计取舍：要么回滚要么不回滚，Go 行为是 server 已创建 + 部分注册
        assert!(c.running());
    }

    // ===== bd pa7：outbound 模式（cnc dispatch → OutboundListener → gRPC）=====

    /// duplex 半边 → tonic channel 的 Service（一次连接）。
    /// `TokioIo` 适配 tokio AsyncRead/Write → hyper rt Read/Write。
    struct DuplexConnector {
        stream: Option<tokio::io::DuplexStream>,
    }

    impl tonic::codegen::Service<tonic::codegen::http::Uri> for DuplexConnector {
        type Error = String;
        type Future =
            std::future::Ready<Result<hyper_util::rt::TokioIo<tokio::io::DuplexStream>, String>>;
        type Response = hyper_util::rt::TokioIo<tokio::io::DuplexStream>;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: tonic::codegen::http::Uri) -> Self::Future {
            match self.stream.take() {
                Some(s) => std::future::ready(Ok(hyper_util::rt::TokioIo::new(s))),
                None => std::future::ready(Err("stream already taken".into())),
            }
        }
    }

    /// outbound 模式 e2e：dispatch Link → cnc conn → listener → tonic serve →
    /// gRPC client 完整往返（Go commander.go:101-115 + outbound.go:74-89）。
    #[tokio::test]
    async fn outbound_mode_serves_grpc_via_dispatch() {
        use std::sync::Arc;

        #[allow(unused_imports)] // 存量清零批次
        use xray_app_dispatcher::{
            DispatchHandler as _, OutboundHandlerManager as _, default::SimpleOhm,
        };
        use xray_common::net::{
            address::Address, destination::Destination, network::Network, port::Port,
        };
        use xray_features::{Feature as _, stats::Manager as _};
        use xray_proto::xray::app::stats::command::{
            GetStatsRequest, stats_service_client::StatsServiceClient,
        };

        // 1. Commander outbound 模式 + SimpleOhm 注册器 + stats 后端
        let ohm = Arc::new(SimpleOhm::new());
        let stats_mgr = Arc::new(xray_app_stats::Manager::new_running());
        let counter = stats_mgr.register_counter("unit>>>test>>>counter").unwrap();
        counter.add(42);
        assert_eq!(counter.value(), 42, "local counter incremented");
        // bd dnw3：stats 后端仅在 services 声明 StatsService 时暴露——
        // 模拟 factory 解析 `services: ["StatsService"]` 后 add_service。
        let commander = Commander::new("api", None);
        assert!(commander.add_service(Arc::new(DeclaredServiceMarker::new(
            "StatsService",
            api_services::STATS,
        ))));
        commander.set_dispatch_registrar(Arc::new(crate::server::SimpleOhmDispatchRegistrar(
            Arc::clone(&ohm),
        )));
        commander.set_stats_service(Arc::new(xray_app_stats::command::DefaultStatsService::new(
            stats_mgr,
        )));
        commander.start().expect("commander start (outbound mode)");

        // 2. 模拟 dispatcher：duplex → Link → ohm 中注册的 api handler dispatch
        let (client_half, server_half) = tokio::io::duplex(64 * 1024);
        let (s_r, s_w) = tokio::io::split(server_half);
        let link = xray_transport::link::Link::new(
            xray_buf::io::new_reader(s_r),
            xray_buf::io::new_writer(s_w),
        );
        let handler = ohm.get_handler("api").expect("api handler registered in SimpleOhm");
        let dest = Destination::new(
            Address::new_domain("api.internal".to_string()),
            Port::new(0),
            Network::TCP,
        );
        tokio::spawn(async move {
            handler.dispatch(&dest, link).await;
        });

        // 3. tonic gRPC client 经 duplex 打 StatsService.GetStats
        let channel = tonic::transport::Endpoint::from_static("http://localhost")
            .connect_with_connector(DuplexConnector { stream: Some(client_half) })
            .await
            .expect("channel over duplex");
        let mut client = StatsServiceClient::new(channel);
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client
                .get_stats(GetStatsRequest { name: "unit>>>test>>>counter".into(), reset: false }),
        )
        .await
        .expect("no timeout")
        .expect("GetStats ok")
        .into_inner();
        let stat = resp.stat.expect("stat present");
        assert_eq!(stat.value, 42);

        // 4. close：listener 关闭 + serve task abort
        commander.close().unwrap();
        assert!(!commander.running());
    }

    /// DispatchHandler 直投：dispatch 后 listener 有 pending 连接（未 serve 场景）。
    #[tokio::test]
    async fn dispatch_handler_delivers_conn_to_listener() {
        use std::sync::Arc;

        #[allow(unused_imports)] // 存量清零批次
        use xray_app_dispatcher::DispatchHandler as _;
        use xray_common::net::{
            address::Address, destination::Destination, network::Network, port::Port,
        };

        let listener = Arc::new(crate::server::OutboundListenerImpl::new());
        let handler = crate::server::OutboundHandlerImpl::new("api", Arc::clone(&listener));
        handler.start().unwrap();

        let (r, w) = tokio::io::duplex(64);
        let (s_r, s_w) = tokio::io::split(r);
        let (_cr, _cw) = tokio::io::split(w);
        let link = xray_transport::link::Link::new(
            xray_buf::io::new_reader(s_r),
            xray_buf::io::new_writer(s_w),
        );
        let dest =
            Destination::new(Address::new_domain("x".to_string()), Port::new(1), Network::TCP);
        let h2 = Arc::new(handler) as Arc<dyn xray_app_dispatcher::DispatchHandler>;
        let mut fut = Box::pin(h2.dispatch(&dest, link));
        // 轮询 dispatch future（50ms 超时窗内 listener 收到连接；dispatch 本体
        // 阻塞等 conn 关闭，超时返回属预期）
        let _ = tokio::time::timeout(std::time::Duration::from_millis(50), fut.as_mut()).await;
        assert_eq!(listener.pending(), 1, "conn delivered to listener");
        drop(fut);
    }

    // ===== bd dnw3：services 声明集门控实际暴露面（Go api.go/Commander.Start）=====

    /// 预留一个临时本地端口（bind :0 后立即释放）。
    async fn reserve_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }

    /// 带 deadline 退避重试的 dial。
    ///
    /// [`Commander::start`] 的 TCP listen 模式在 `tokio::spawn` 的任务里才
    /// bind（commander.rs start→grpc::ListenSpec::Tcp 分支），spawn 返回 ≠
    /// listener 就绪；POSIX 调度下测试立即 dial 会 Connection refused
    /// （CI macos+ubuntu 首跑实证，Windows 碰巧绿）。禁 sleep 固定等待，
    /// deadline 内指数退避重试。
    async fn dial_with_retry<T, F, Fut>(mut connect: F, what: &'static str) -> T
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, tonic::transport::Error>>,
    {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut backoff = std::time::Duration::from_millis(50);
        loop {
            match connect().await {
                Ok(client) => return client,
                Err(e) => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "{what}: dial deadline exceeded (server never accepted): {e}"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(std::time::Duration::from_millis(500));
                },
            }
        }
    }

    fn stats_backend(value: i64) -> Arc<dyn xray_app_stats::command::StatsService> {
        use xray_features::stats::Manager as _;
        let mgr = Arc::new(xray_app_stats::Manager::new_running());
        let counter = mgr.register_counter("unit>>>gate>>>counter").unwrap();
        counter.add(value);
        let _: i64 = counter.value();
        Arc::new(xray_app_stats::command::DefaultStatsService::new(mgr))
    }

    /// 声明 StatsService + 注入后端 → GetStats 返回真实计数（API 可达）。
    #[tokio::test]
    async fn listen_mode_exposes_declared_stats_service() {
        use xray_features::Feature as _;
        use xray_proto::xray::app::stats::command::{
            GetStatsRequest, stats_service_client::StatsServiceClient,
        };

        let port = reserve_port().await;
        let commander = Commander::new("api", Some(format!("127.0.0.1:{port}")));
        assert!(commander.add_service(Arc::new(DeclaredServiceMarker::new(
            "StatsService",
            api_services::STATS,
        ))));
        commander.set_stats_service(stats_backend(42));
        commander.start().expect("commander start (listen mode)");
        let mut client = dial_with_retry(
            || StatsServiceClient::connect(format!("http://127.0.0.1:{port}")),
            "dial commander api",
        )
        .await;
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client
                .get_stats(GetStatsRequest { name: "unit>>>gate>>>counter".into(), reset: false }),
        )
        .await
        .expect("no timeout")
        .expect("GetStats ok (declared + backend present)")
        .into_inner();
        assert_eq!(resp.stat.expect("stat").value, 42);
        commander.close().unwrap();
    }

    /// 后端在场但未声明 StatsService → 服务不暴露（UNIMPLEMENTED）。
    /// 对应 Go：`services` 列表不含 statsservice 时 config.Service 无该条目。
    #[tokio::test]
    async fn listen_mode_hides_undeclared_stats_service() {
        use xray_features::Feature as _;
        use xray_proto::xray::app::stats::command::{
            GetStatsRequest, stats_service_client::StatsServiceClient,
        };

        let port = reserve_port().await;
        let commander = Commander::new("api", Some(format!("127.0.0.1:{port}")));
        // 只声明 HandlerService；stats 后端注入但不声明。
        assert!(commander.add_service(Arc::new(HandlerServiceMarker)));
        commander.set_stats_service(stats_backend(7));
        commander.start().expect("commander start (listen mode)");

        let mut client = dial_with_retry(
            || StatsServiceClient::connect(format!("http://127.0.0.1:{port}")),
            "dial commander api",
        )
        .await;
        let err = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client
                .get_stats(GetStatsRequest { name: "unit>>>gate>>>counter".into(), reset: false }),
        )
        .await
        .expect("no timeout")
        .expect_err("undeclared service must be unimplemented");
        assert_eq!(err.code(), tonic::Code::Unimplemented, "got: {err:?}");
        commander.close().unwrap();
    }

    /// 声明 StatsService 但后端未注入 → 同样不暴露（无后端可注册）。
    #[tokio::test]
    async fn listen_mode_declared_without_backend_not_exposed() {
        use xray_features::Feature as _;
        use xray_proto::xray::app::stats::command::{
            GetStatsRequest, stats_service_client::StatsServiceClient,
        };

        let port = reserve_port().await;
        let commander = Commander::new("api", Some(format!("127.0.0.1:{port}")));
        assert!(commander.add_service(Arc::new(DeclaredServiceMarker::new(
            "StatsService",
            api_services::STATS,
        ))));
        commander.start().expect("commander start (listen mode)");

        let mut client = dial_with_retry(
            || StatsServiceClient::connect(format!("http://127.0.0.1:{port}")),
            "dial commander api",
        )
        .await;
        let err = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client
                .get_stats(GetStatsRequest { name: "unit>>>gate>>>counter".into(), reset: false }),
        )
        .await
        .expect("no timeout")
        .expect_err("declared-but-backendless service must be unimplemented");
        assert_eq!(err.code(), tonic::Code::Unimplemented, "got: {err:?}");
        commander.close().unwrap();
    }
}

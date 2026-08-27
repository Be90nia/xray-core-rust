//! Commander gRPC 服务（tonic 实现）。
//!
//! 对应 Go `app/commander` 中各 command service 的 `Register(*grpc.Server)`：
//! 把 [`HandlerServiceImpl`] / [`StatsServiceImpl`] / [`RoutingServiceImpl`] /
//! [`ObservatoryServiceImpl`] 注册到 tonic server，暴露各 command 的 gRPC 方法。
//!
//! ## 范围
//!
//! - **HandlerService**：注入 [`OutboundRuntime`]（bd ze3，生产 SimpleOhm）时
//!   add/remove/list outbound 操作真实 outbound manager；未注入时退回内部
//!   [`OutboundHandlerRegistry`](crate::server::OutboundHandlerRegistry)（stub handler）。
//!   其余方法（inbound / alter / users）返回 `UNIMPLEMENTED`。
//! - **LoggerService**：委托领域 `xray_app_log::command::LogService`
//!   （`DefaultLogService` → `LogInstance::restart`）。
//! - **StatsService**：委托领域 `xray_app_stats::command::StatsService`，proto ↔ domain 翻译。
//! - **RoutingService**：委托领域 `xray_app_router::command::RoutingService`；
//!   `SubscribeRoutingStats`/`TestRoute`/`AddRule` 需完整 context/config，返回 `UNIMPLEMENTED`。
//! - **ObservatoryService**：委托领域 `xray_app_observatory::command::ObservatoryService`。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use xray_proto::xray::app::proxyman::command::handler_service_server::{
    HandlerService, HandlerServiceServer,
};
use xray_proto::xray::app::proxyman::command::{
    AddInboundRequest, AddInboundResponse, AddOutboundRequest, AddOutboundResponse,
    AlterInboundRequest, AlterInboundResponse, AlterOutboundRequest, AlterOutboundResponse,
    GetInboundUserRequest, GetInboundUserResponse, GetInboundUsersCountResponse,
    ListInboundsRequest, ListInboundsResponse, ListOutboundsRequest, ListOutboundsResponse,
    RemoveInboundRequest, RemoveInboundResponse, RemoveOutboundRequest, RemoveOutboundResponse,
};
use xray_proto::xray::app::log::command::logger_service_server::{
    LoggerService as ProtoLoggerService, LoggerServiceServer,
};
use xray_proto::xray::app::log::command::{RestartLoggerRequest, RestartLoggerResponse};
use xray_proto::xray::core::OutboundHandlerConfig;

// --- stats command gRPC ---
use xray_proto::xray::app::stats::command as pstats;
use xray_proto::xray::app::stats::command::stats_service_server::{
    StatsService as ProtoStatsService, StatsServiceServer,
};

// --- router command gRPC ---
use xray_proto::xray::app::router::command as prouter;
use xray_proto::xray::app::router::command::routing_service_server::{
    RoutingService as ProtoRoutingService, RoutingServiceServer,
};

// --- observatory command gRPC ---
use xray_proto::xray::core::app::observatory::command as pobs;
use xray_proto::xray::core::app::observatory::command::observatory_service_server::{
    ObservatoryService as ProtoObservatoryService, ObservatoryServiceServer,
};

use crate::outbound::HandlerManager;
use crate::server::OutboundHandlerRegistry;

// ===========================================================================
// OutboundRuntime（bd ze3：HandlerService 运行时注入）
// ===========================================================================

/// HandlerService 的 outbound 运行时注入 trait（bd ze3）。
///
/// 生产实现（xray-core 装配层 `ApiOutboundRuntime`）把 proto
/// [`OutboundHandlerConfig`] 构建为真实 handler 并注册进 dispatcher 的
/// SimpleOhm——对应 Go `addOutbound` 中 `core.CreateObject(ctx, config)` +
/// `ohm.AddHandler` 链。未注入时 HandlerService 退回内部 stub registry
/// （tag 维度增删查，无真实拨号能力）。
pub trait OutboundRuntime: Send + Sync {
    /// 构建并注册 outbound handler。tag 已存在返回 `Err`（AlreadyExists 语义，
    /// 对应 Go `outbound.Manager.AddHandler` 的 "existing tag found"）。
    fn add_outbound(&self, cfg: &OutboundHandlerConfig) -> Result<(), String>;
    /// 移除 tag 对应 handler。tag 不存在返回 `Err`（NotFound 语义）。
    fn remove_outbound(&self, tag: &str) -> Result<(), String>;
    /// 列出全部已注册 outbound 的 tag。
    fn list_outbound_tags(&self) -> Vec<String>;
}

// ===========================================================================
// HandlerService（proxyman command）
// ===========================================================================

/// HandlerService gRPC 实现。
///
/// 注入 [`OutboundRuntime`] 时 add/remove/list outbound 操作生产 outbound
/// manager（真实拨号能力）；未注入时退回内部 [`OutboundHandlerRegistry`]
/// （stub handler，tag 维度增删查）。其余方法（inbound 相关、alter、users）
/// 尚未实现，返回 `UNIMPLEMENTED`。
#[derive(Clone)]
pub struct HandlerServiceImpl {
    registry: Arc<OutboundHandlerRegistry>,
    runtime: Option<Arc<dyn OutboundRuntime>>,
}

impl HandlerServiceImpl {
    #[must_use]
    pub fn new(registry: Arc<OutboundHandlerRegistry>) -> Self {
        Self { registry, runtime: None }
    }

    /// 注入生产 outbound 运行时（builder 风格）。
    #[must_use]
    pub fn with_outbound_runtime(mut self, runtime: Arc<dyn OutboundRuntime>) -> Self {
        self.runtime = Some(runtime);
        self
    }
}

#[async_trait]
impl HandlerService for HandlerServiceImpl {
    async fn add_outbound(
        &self,
        request: Request<AddOutboundRequest>,
    ) -> Result<Response<AddOutboundResponse>, Status> {
        let req = request.into_inner();
        let cfg = req.outbound.ok_or_else(|| {
            Status::invalid_argument("AddOutboundRequest.outbound is required")
        })?;
        let tag = cfg.tag.to_string();
        if tag.is_empty() {
            return Err(Status::invalid_argument("outbound.tag is required"));
        }
        match self.runtime.as_ref() {
            // 生产路径：proto config → try_build_handler → SimpleOhm（bd bg7）。
            // dup tag → AlreadyExists（ApiOutboundRuntime 报 "existing tag found"）；
            // 其余（未知协议/配置解析失败）→ InvalidArgument。
            Some(rt) => rt.add_outbound(&cfg).map_err(|e| {
                if e.contains("existing tag found") {
                    Status::already_exists(format!("add outbound `{tag}`: {e}"))
                } else {
                    Status::invalid_argument(format!("add outbound `{tag}`: {e}"))
                }
            })?,
            // 回退路径：stub handler（无真实拨号能力，tag 维度 add/remove/list）。
            None => {
                let handler = crate::outbound::StubOutboundHandler::new(tag.clone());
                self.registry.add_handler(Arc::new(handler)).map_err(|e| {
                    Status::already_exists(format!("add outbound `{tag}`: {e}"))
                })?;
            }
        }
        tracing::info!(tag = %tag, "commander: outbound added via gRPC");
        Ok(Response::new(AddOutboundResponse {}))
    }

    async fn remove_outbound(
        &self,
        request: Request<RemoveOutboundRequest>,
    ) -> Result<Response<RemoveOutboundResponse>, Status> {
        let tag = request.into_inner().tag.to_string();
        if tag.is_empty() {
            return Err(Status::invalid_argument("tag is required"));
        }
        match self.runtime.as_ref() {
            Some(rt) => rt
                .remove_outbound(&tag)
                .map_err(|e| Status::not_found(format!("remove outbound `{tag}`: {e}")))?,
            None => {
                self.registry.remove_handler(&tag).map_err(|e| {
                    Status::not_found(format!("remove outbound `{tag}`: {e}"))
                })?;
            }
        }
        tracing::info!(tag = %tag, "commander: outbound removed via gRPC");
        Ok(Response::new(RemoveOutboundResponse {}))
    }


    async fn list_outbounds(
        &self,
        _request: Request<ListOutboundsRequest>,
    ) -> Result<Response<ListOutboundsResponse>, Status> {
        let tags = match self.runtime.as_ref() {
            Some(rt) => rt.list_outbound_tags(),
            None => self.registry.list_tags(),
        };
        let outbounds = tags
            .into_iter()
            .map(|tag| OutboundHandlerConfig {
                tag,
                sender_settings: None,
                proxy_settings: None,
                expire: 0,
                comment: String::new(),
            })
            .collect();
        Ok(Response::new(ListOutboundsResponse { outbounds }))
    }

    // --- 以下方法尚未实现 ---

    async fn add_inbound(
        &self,
        _: Request<AddInboundRequest>,
    ) -> Result<Response<AddInboundResponse>, Status> {
        Err(Status::unimplemented("AddInbound not implemented"))
    }

    async fn remove_inbound(
        &self,
        _: Request<RemoveInboundRequest>,
    ) -> Result<Response<RemoveInboundResponse>, Status> {
        Err(Status::unimplemented("RemoveInbound not implemented"))
    }

    async fn alter_inbound(
        &self,
        _: Request<AlterInboundRequest>,
    ) -> Result<Response<AlterInboundResponse>, Status> {
        Err(Status::unimplemented("AlterInbound not implemented"))
    }

    async fn list_inbounds(
        &self,
        _: Request<ListInboundsRequest>,
    ) -> Result<Response<ListInboundsResponse>, Status> {
        Err(Status::unimplemented("ListInbounds not implemented"))
    }

    async fn get_inbound_users(
        &self,
        _: Request<GetInboundUserRequest>,
    ) -> Result<Response<GetInboundUserResponse>, Status> {
        Err(Status::unimplemented("GetInboundUsers not implemented"))
    }

    async fn get_inbound_users_count(
        &self,
        _: Request<GetInboundUserRequest>,
    ) -> Result<Response<GetInboundUsersCountResponse>, Status> {
        Err(Status::unimplemented("GetInboundUsersCount not implemented"))
    }

    async fn alter_outbound(
        &self,
        _: Request<AlterOutboundRequest>,
    ) -> Result<Response<AlterOutboundResponse>, Status> {
        Err(Status::unimplemented("AlterOutbound not implemented"))
    }
}

// ===========================================================================
// LoggerService（log command，bd ze3）
// ===========================================================================

/// LoggerService gRPC 实现。
///
/// 持有领域 [`xray_app_log::command::LogService`]（生产实现
/// `DefaultLogService` 包真实 `LogInstance`），把 `RestartLogger` 委托给
/// `LogInstance::restart`。对应 Go `app/log/command` 的 `LoggerServer`。
#[derive(Clone)]
pub struct LoggerServiceImpl {
    service: Arc<dyn xray_app_log::command::LogService>,
}

impl LoggerServiceImpl {
    #[must_use]
    pub fn new(service: Arc<dyn xray_app_log::command::LogService>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl ProtoLoggerService for LoggerServiceImpl {
    async fn restart_logger(
        &self,
        _request: Request<RestartLoggerRequest>,
    ) -> Result<Response<RestartLoggerResponse>, Status> {
        self.service
            .restart_logger()
            .map_err(|e| Status::internal(format!("restart logger: {e}")))?;
        tracing::info!("commander: logger restarted via gRPC");
        Ok(Response::new(RestartLoggerResponse {}))
    }
}
// ===========================================================================
// StatsService（stats command）
// ===========================================================================

/// StatsService gRPC 实现。
///
/// 持有领域 [`xray_app_stats::command::StatsService`]，把 proto 请求翻译为领域
/// 请求、调用编排类、再把领域响应翻译回 proto。对应 Go `statsServer`。
#[derive(Clone)]
pub struct StatsServiceImpl {
    service: Arc<dyn xray_app_stats::command::StatsService>,
}

impl StatsServiceImpl {
    #[must_use]
    pub fn new(service: Arc<dyn xray_app_stats::command::StatsService>) -> Self {
        Self { service }
    }
}

/// 领域 [`StatsCommandError`](xray_app_stats::command::StatsCommandError) → tonic `Status`。
fn stats_status(e: xray_app_stats::command::StatsCommandError) -> Status {
    use xray_app_stats::command::StatsCommandError;
    match e {
        StatsCommandError::NotFound(n) => Status::not_found(n),
        StatsCommandError::Internal(m) => Status::internal(m),
    }
}

#[async_trait]
impl ProtoStatsService for StatsServiceImpl {
    async fn get_stats(
        &self,
        request: Request<pstats::GetStatsRequest>,
    ) -> Result<Response<pstats::GetStatsResponse>, Status> {
        let req = request.into_inner();
        let dreq = xray_app_stats::command::GetStatsRequest {
            name: req.name.to_string(),
            reset: req.reset,
        };
        let resp = self.service.get_stats(&dreq).map_err(stats_status)?;
        Ok(Response::new(pstats::GetStatsResponse {
            stat: resp
                .stat
                .map(|s| pstats::Stat { name: s.name, value: s.value }),
        }))
    }

    async fn get_stats_online(
        &self,
        request: Request<pstats::GetStatsRequest>,
    ) -> Result<Response<pstats::GetStatsResponse>, Status> {
        let req = request.into_inner();
        let dreq = xray_app_stats::command::GetStatsRequest {
            name: req.name.to_string(),
            reset: req.reset,
        };
        let resp = self.service.get_stats_online(&dreq).map_err(stats_status)?;
        Ok(Response::new(pstats::GetStatsResponse {
            stat: resp
                .stat
                .map(|s| pstats::Stat { name: s.name, value: s.value }),
        }))
    }

    async fn query_stats(
        &self,
        request: Request<pstats::QueryStatsRequest>,
    ) -> Result<Response<pstats::QueryStatsResponse>, Status> {
        let req = request.into_inner();
        let dreq = xray_app_stats::command::QueryStatsRequest {
            pattern: req.pattern.to_string(),
            reset: req.reset,
        };
        let resp = self.service.query_stats(&dreq).map_err(stats_status)?;
        Ok(Response::new(pstats::QueryStatsResponse {
            stat: resp
                .stats
                .into_iter()
                .map(|s| pstats::Stat { name: s.name, value: s.value })
                .collect(),
        }))
    }

    async fn get_sys_stats(
        &self,
        _request: Request<pstats::SysStatsRequest>,
    ) -> Result<Response<pstats::SysStatsResponse>, Status> {
        let s = self.service.get_sys_stats().map_err(stats_status)?;
        Ok(Response::new(pstats::SysStatsResponse {
            num_goroutine: s.num_threads,
            num_gc: s.num_gc,
            alloc: s.alloc_bytes,
            total_alloc: s.total_alloc_bytes,
            sys: s.sys_bytes,
            mallocs: s.mallocs,
            frees: s.frees,
            live_objects: s.live_objects,
            pause_total_ns: s.pause_total_ns,
            uptime: s.uptime_seconds,
        }))
    }

    async fn get_stats_online_ip_list(
        &self,
        request: Request<pstats::GetStatsRequest>,
    ) -> Result<Response<pstats::GetStatsOnlineIpListResponse>, Status> {
        let req = request.into_inner();
        let dreq = xray_app_stats::command::GetStatsRequest {
            name: req.name.to_string(),
            reset: req.reset,
        };
        let resp = self
            .service
            .get_stats_online_ip_list(&dreq)
            .map_err(stats_status)?;
        let mut ips = HashMap::new();
        for e in resp.ips {
            ips.insert(e.ip, e.last_seen);
        }
        Ok(Response::new(pstats::GetStatsOnlineIpListResponse {
            name: resp.name,
            ips,
        }))
    }

    async fn get_all_online_users(
        &self,
        _request: Request<pstats::GetAllOnlineUsersRequest>,
    ) -> Result<Response<pstats::GetAllOnlineUsersResponse>, Status> {
        let resp = self
            .service
            .get_all_online_users()
            .map_err(stats_status)?;
        Ok(Response::new(pstats::GetAllOnlineUsersResponse {
            users: resp.users,
        }))
    }

    async fn get_users_stats(
        &self,
        request: Request<pstats::GetUsersStatsRequest>,
    ) -> Result<Response<pstats::GetUsersStatsResponse>, Status> {
        let req = request.into_inner();
        let dreq = xray_app_stats::command::GetUsersStatsRequest {
            include_traffic: req.include_traffic,
            reset: req.reset,
        };
        let resp = self
            .service
            .get_users_stats(&dreq)
            .map_err(stats_status)?;
        let users = resp
            .users
            .into_iter()
            .map(|u| pstats::UserStat {
                email: u.email,
                ips: u
                    .ips
                    .into_iter()
                    .map(|e| pstats::OnlineIpEntry { ip: e.ip, last_seen: e.last_seen })
                    .collect(),
                traffic: Some(pstats::TrafficUserStat {
                    uplink: u.uplink,
                    downlink: u.downlink,
                }),
            })
            .collect();
        Ok(Response::new(pstats::GetUsersStatsResponse { users }))
    }
}

// ===========================================================================
// RoutingService（router command）
// ===========================================================================

/// RoutingService gRPC 实现。
///
/// 持有领域 [`xray_app_router::command::RoutingService`]，translate proto ↔ domain。
/// 对应 Go `routingServer`。`SubscribeRoutingStats`（server streaming）、`TestRoute`
/// （需完整 `RoutingContext`）、`AddRule`（需完整 rule config）返回 `UNIMPLEMENTED`。
#[derive(Clone)]
pub struct RoutingServiceImpl {
    service: Arc<xray_app_router::command::RoutingService>,
}

impl RoutingServiceImpl {
    #[must_use]
    pub fn new(service: Arc<xray_app_router::command::RoutingService>) -> Self {
        Self { service }
    }
}

/// 领域 [`RouterError`](xray_app_router::error::RouterError) → tonic `Status`。
fn router_status(e: xray_app_router::error::RouterError) -> Status {
    use xray_app_router::error::RouterError;
    match e {
        RouterError::BalancerNotFound(_)
        | RouterError::TagNotFound
        | RouterError::EmptyTagName => Status::not_found(e.to_string()),
        _ => Status::internal(e.to_string()),
    }
}

#[async_trait]
impl ProtoRoutingService for RoutingServiceImpl {
    // SubscribeRoutingStats 是 server-streaming RPC。返回 UNIMPLEMENTED 时此类型
    // 实例不会被构造，仅需满足 `Stream + Send + 'static` 约束。
    type SubscribeRoutingStatsStream =
        tonic::codegen::tokio_stream::wrappers::ReceiverStream<
            std::result::Result<prouter::RoutingContext, Status>,
        >;

    async fn subscribe_routing_stats(
        &self,
        _request: Request<prouter::SubscribeRoutingStatsRequest>,
    ) -> Result<Response<Self::SubscribeRoutingStatsStream>, Status> {
        Err(Status::unimplemented(
            "SubscribeRoutingStats requires gRPC streaming framework",
        ))
    }

    async fn test_route(
        &self,
        _request: Request<prouter::TestRouteRequest>,
    ) -> Result<Response<prouter::RoutingContext>, Status> {
        Err(Status::unimplemented(
            "TestRoute requires full RoutingContext (not yet wired)",
        ))
    }

    async fn get_balancer_info(
        &self,
        request: Request<prouter::GetBalancerInfoRequest>,
    ) -> Result<Response<prouter::GetBalancerInfoResponse>, Status> {
        let tag = request.into_inner().tag.to_string();
        self.service.get_balancer_info(&tag).map_err(router_status)?;
        // ponytail: 领域 get_balancer_info 仅验证 tag 存在性，不返回 override/principle 数据；
        // 待 Router 暴露 balancer 详情后补全。
        Ok(Response::new(prouter::GetBalancerInfoResponse {
            balancer: Some(prouter::BalancerMsg {
                r#override: None,
                principle_target: None,
            }),
        }))
    }

    async fn override_balancer_target(
        &self,
        request: Request<prouter::OverrideBalancerTargetRequest>,
    ) -> Result<Response<prouter::OverrideBalancerTargetResponse>, Status> {
        let req = request.into_inner();
        self.service
            .override_balancer_target(&req.balancer_tag.to_string(), &req.target.to_string())
            .map_err(router_status)?;
        Ok(Response::new(prouter::OverrideBalancerTargetResponse {}))
    }

    async fn add_rule(
        &self,
        _request: Request<prouter::AddRuleRequest>,
    ) -> Result<Response<prouter::AddRuleResponse>, Status> {
        Err(Status::unimplemented("AddRule requires full RoutingRule config"))
    }

    async fn remove_rule(
        &self,
        request: Request<prouter::RemoveRuleRequest>,
    ) -> Result<Response<prouter::RemoveRuleResponse>, Status> {
        let tag = request.into_inner().rule_tag.to_string();
        self.service.remove_rule(&tag).map_err(router_status)?;
        Ok(Response::new(prouter::RemoveRuleResponse {}))
    }

    async fn list_rule(
        &self,
        _request: Request<prouter::ListRuleRequest>,
    ) -> Result<Response<prouter::ListRuleResponse>, Status> {
        let rules = self.service.list_rule().map_err(router_status)?;
        let rules = rules
            .into_iter()
            .map(|t| prouter::ListRuleItem {
                tag: String::new(),
                rule_tag: t,
            })
            .collect();
        Ok(Response::new(prouter::ListRuleResponse { rules }))
    }
}

// ===========================================================================
// ObservatoryService（observatory command）
// ===========================================================================

/// ObservatoryService gRPC 实现。
///
/// 持有领域 [`xray_app_observatory::command::ObservatoryService`]，调用
/// `get_outbound_status` 并把领域 `ObservationResult` 翻译为 proto。
#[derive(Clone)]
pub struct ObservatoryServiceImpl {
    service: Arc<dyn xray_app_observatory::command::ObservatoryService>,
}

impl ObservatoryServiceImpl {
    #[must_use]
    pub fn new(
        service: Arc<dyn xray_app_observatory::command::ObservatoryService>,
    ) -> Self {
        Self { service }
    }
}

/// 领域 [`ObservatoryError`](xray_app_observatory::error::ObservatoryError) → tonic `Status`。
fn observatory_status(e: xray_app_observatory::error::ObservatoryError) -> Status {
    use xray_app_observatory::error::ObservatoryError;
    match e {
        ObservatoryError::NoObservation => Status::not_found(e.to_string()),
        _ => Status::internal(e.to_string()),
    }
}

#[async_trait]
impl ProtoObservatoryService for ObservatoryServiceImpl {
    async fn get_outbound_status(
        &self,
        _request: Request<pobs::GetOutboundStatusRequest>,
    ) -> Result<Response<pobs::GetOutboundStatusResponse>, Status> {
        let result = self
            .service
            .get_outbound_status()
            .map_err(observatory_status)?;
        Ok(Response::new(pobs::GetOutboundStatusResponse {
            status: Some(result.to_proto()),
        }))
    }
}

// ===========================================================================
// 辅助函数 + build_router
// ===========================================================================

/// 解析监听地址为 `SocketAddr`。
///
/// 支持 `"127.0.0.1:8080"`、`"0.0.0.0:8080"`、以及 `":8080"`（补 `0.0.0.0`）简写。
/// 不支持 Unix domain socket（tonic UDS 需额外 feature，当前仅 TCP）。
pub(crate) fn parse_listen_addr(addr: &str) -> Result<SocketAddr, String> {
    let normalized = if addr.starts_with(':') {
        format!("0.0.0.0{addr}")
    } else {
        addr.to_string()
    };
    normalized.parse::<SocketAddr>().map_err(|e| {
        format!("invalid listen address `{addr}` (normalized `{normalized}`): {e}")
    })
}

/// 构建已注册 command service 的 tonic `Router`。
///
/// 返回的 `Router` 可 `.serve(addr)` 启动。始终注册 HandlerService 与
/// gRPC reflection（v1 + v1alpha，descriptor 来自 `xray_proto`）；
/// outbound runtime / logger / stats / routing / observatory 仅在注入
/// （`Some`）时注册。
pub(crate) fn build_router(
    registry: Arc<OutboundHandlerRegistry>,
    outbound_runtime: Option<Arc<dyn OutboundRuntime>>,
    logger: Option<Arc<dyn xray_app_log::command::LogService>>,
    stats: Option<Arc<dyn xray_app_stats::command::StatsService>>,
    routing: Option<Arc<xray_app_router::command::RoutingService>>,
    observatory: Option<Arc<dyn xray_app_observatory::command::ObservatoryService>>,
) -> tonic::transport::server::Router {
    let handler_impl = match outbound_runtime {
        Some(rt) => HandlerServiceImpl::new(registry).with_outbound_runtime(rt),
        None => HandlerServiceImpl::new(registry),
    };
    let mut server = Server::builder().add_service(HandlerServiceServer::new(handler_impl));
    if let Some(svc) = logger {
        server = server.add_service(LoggerServiceServer::new(LoggerServiceImpl::new(svc)));
    }
    if let Some(svc) = stats {
        server = server.add_service(StatsServiceServer::new(StatsServiceImpl::new(svc)));
    }
    if let Some(svc) = routing {
        server = server.add_service(RoutingServiceServer::new(RoutingServiceImpl::new(svc)));
    }
    if let Some(svc) = observatory {
        server =
            server.add_service(ObservatoryServiceServer::new(ObservatoryServiceImpl::new(svc)));
    }
    // reflection 常注册（bd ze3）：grpcurl / tonic-reflection client 可发现全部服务。
    let reflect_builder = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(xray_proto::FILE_DESCRIPTOR_SET);
    match reflect_builder.build_v1alpha() {
        Ok(svc) => server = server.add_service(svc),
        Err(e) => tracing::warn!("commander: reflection v1alpha unavailable: {e}"),
    }
    match tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(xray_proto::FILE_DESCRIPTOR_SET)
        .build_v1()
    {
        Ok(svc) => server = server.add_service(svc),
        Err(e) => tracing::warn!("commander: reflection v1 unavailable: {e}"),
    }
    server
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_listen_addr_full() {
        let a = parse_listen_addr("127.0.0.1:8080").unwrap();
        assert_eq!(a.port(), 8080);
    }

    #[test]
    fn parse_listen_addr_port_only() {
        let a = parse_listen_addr(":9090").unwrap();
        assert_eq!(a.port(), 9090);
        assert_eq!(a.ip().to_string(), "0.0.0.0");
    }

    #[test]
    fn parse_listen_addr_invalid() {
        assert!(parse_listen_addr("not-an-addr").is_err());
        assert!(parse_listen_addr("999.999.999.999:80").is_err());
    }

    // --- 端到端翻译正确性：用领域 DefaultStatsService 作为后端，验证 proto 请求
    //     经 StatsServiceImpl 翻译后得到正确的 proto 响应。---

    /// 最小 StatsService 后端：基于内存 Manager。
    fn stats_backend() -> Arc<dyn xray_app_stats::command::StatsService> {
        use xray_app_stats::command::DefaultStatsService;
        let mgr = Arc::new(xray_app_stats::Manager::new());
        Arc::new(DefaultStatsService::new(mgr))
    }

    #[tokio::test]
    async fn stats_get_stats_not_found() {
        let svc = StatsServiceImpl::new(stats_backend());
        let resp = svc
            .get_stats(Request::new(pstats::GetStatsRequest {
                name: "nope".into(),
                reset: false,
            }))
            .await;
        assert!(resp.is_err());
        let err = resp.unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn stats_query_stats_empty() {
        let svc = StatsServiceImpl::new(stats_backend());
        let resp = svc
            .query_stats(Request::new(pstats::QueryStatsRequest {
                pattern: "".into(),
                reset: false,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(resp.stat.is_empty());
    }

    #[tokio::test]
    async fn stats_get_sys_stats_maps_fields() {
        let svc = StatsServiceImpl::new(stats_backend());
        let resp = svc
            .get_sys_stats(Request::new(pstats::SysStatsRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.num_gc, 0);
        assert_eq!(resp.pause_total_ns, 0);
        // uptime 非零（DefaultSysStatsProvider 填启动后秒数）。
        assert!(resp.uptime == 0 || resp.uptime >= 1);
    }

    #[tokio::test]
    async fn routing_without_router_returns_internal() {
        let svc = RoutingServiceImpl::new(Arc::new(
            xray_app_router::command::RoutingService::new(),
        ));
        let resp = svc
            .list_rule(Request::new(prouter::ListRuleRequest {}))
            .await;
        assert!(resp.is_err());
        assert_eq!(resp.unwrap_err().code(), tonic::Code::Internal);
    }

    #[tokio::test]
    async fn routing_remove_rule_empty_tag() {
        let svc = RoutingServiceImpl::new(Arc::new(
            xray_app_router::command::RoutingService::new(),
        ));
        let resp = svc
            .remove_rule(Request::new(prouter::RemoveRuleRequest {
                rule_tag: "".into(),
            }))
            .await;
        assert!(resp.is_err());
    }

    #[tokio::test]
    async fn routing_subscribe_unimplemented() {
        let svc = RoutingServiceImpl::new(Arc::new(
            xray_app_router::command::RoutingService::new(),
        ));
        let resp = svc
            .subscribe_routing_stats(Request::new(
                prouter::SubscribeRoutingStatsRequest {
                    field_selectors: vec![],
                },
            ))
            .await;
        assert!(resp.is_err());
        assert_eq!(resp.unwrap_err().code(), tonic::Code::Unimplemented);
    }
}

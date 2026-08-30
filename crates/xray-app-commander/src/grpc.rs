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
use std::pin::Pin;
use std::sync::Arc;
use async_trait::async_trait;
use prost::Message as _;
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
/// 三级后端，优先级从高到低：
/// 1. **proxyman 领域 service**（[`xray_app_proxyman::command::HandlerService`]，
///    对应 Go `handlerServer` 的 ihm/ohm 双 manager）——全部 10 op 可用；
/// 2. [`OutboundRuntime`]（bd ze3，SimpleOhm）——仅 outbound add/remove/list；
/// 3. 内部 [`OutboundHandlerRegistry`]（stub）。
///
/// 未注入任何后端时 inbound 相关 op 返回 `UNIMPLEMENTED`（明示）。
#[derive(Clone)]
pub struct HandlerServiceImpl {
    registry: Arc<OutboundHandlerRegistry>,
    runtime: Option<Arc<dyn OutboundRuntime>>,
    proxyman: Option<Arc<dyn xray_app_proxyman::command::HandlerService>>,
}

impl HandlerServiceImpl {
    #[must_use]
    pub fn new(registry: Arc<OutboundHandlerRegistry>) -> Self {
        Self { registry, runtime: None, proxyman: None }
    }

    /// 注入生产 outbound 运行时（builder 风格）。
    #[must_use]
    pub fn with_outbound_runtime(mut self, runtime: Arc<dyn OutboundRuntime>) -> Self {
        self.runtime = Some(runtime);
        self
    }

    /// 注入 proxyman 领域 HandlerService（builder 风格，Go `handlerServer` 全量）。
    #[must_use]
    pub fn with_proxyman_service(
        mut self,
        svc: Arc<dyn xray_app_proxyman::command::HandlerService>,
    ) -> Self {
        self.proxyman = Some(svc);
        self
    }
}

/// 领域 [`ProxymanError`] → tonic `Status`。
fn proxyman_status(e: xray_app_proxyman::ProxymanError) -> Status {
    use xray_app_proxyman::ProxymanError as E;
    match e {
        E::HandlerNotFound(_) | E::OutboundHandlerNotFound(_) | E::NoClue => {
            Status::not_found(e.to_string())
        }
        E::ExistingTag(_) => Status::already_exists(e.to_string()),
        E::UnknownOperation
        | E::NotInboundOperation
        | E::NotOutboundOperation
        | E::UserParse(_)
        | E::NilDestination => Status::invalid_argument(e.to_string()),
        E::NotUserManager
        | E::GetInboundProxyFailed
        | E::GetOutboundProxyFailed
        | E::NotInboundProxy
        | E::NotOutboundProxy => Status::failed_precondition(e.to_string()),
        other => Status::internal(other.to_string()),
    }
}

#[async_trait]
impl HandlerService for HandlerServiceImpl {
    async fn add_outbound(
        &self,
        request: Request<AddOutboundRequest>,
    ) -> Result<Response<AddOutboundResponse>, Status> {
        // 优先级 1：proxyman 领域 service（Go handlerServer.AddOutbound，
        // command.go:165-170 —— core.AddOutboundHandler）
        if let Some(svc) = &self.proxyman {
            let resp = svc
                .add_outbound(request.into_inner())
                .map_err(proxyman_status)?;
            return Ok(Response::new(resp));
        }
        let req = request.into_inner();
        let cfg = req.outbound.ok_or_else(|| {
            Status::invalid_argument("AddOutboundRequest.outbound is required")
        })?;
        let tag = cfg.tag.to_string();
        if tag.is_empty() {
            return Err(Status::invalid_argument("outbound.tag is required"));
        }
        match self.runtime.as_ref() {
            // 优先级 2：proto config → try_build_handler → SimpleOhm（bd bg7）。
            // dup tag → AlreadyExists（ApiOutboundRuntime 报 "existing tag found"）；
            // 其余（未知协议/配置解析失败）→ InvalidArgument。
            Some(rt) => rt.add_outbound(&cfg).map_err(|e| {
                if e.contains("existing tag found") {
                    Status::already_exists(format!("add outbound `{tag}`: {e}"))
                } else {
                    Status::invalid_argument(format!("add outbound `{tag}`: {e}"))
                }
            })?,
            // 优先级 3：stub handler（无真实拨号能力，tag 维度 add/remove/list）。
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
        // proxyman 领域 service（Go command.go:172-174 —— ohm.RemoveHandler）
        if let Some(svc) = &self.proxyman {
            let resp = svc
                .remove_outbound(request.into_inner())
                .map_err(proxyman_status)?;
            return Ok(Response::new(resp));
        }
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
        request: Request<ListOutboundsRequest>,
    ) -> Result<Response<ListOutboundsResponse>, Status> {
        // proxyman 领域 service（Go command.go:188-205 —— ohm.ListHandlers）
        if let Some(svc) = &self.proxyman {
            let resp = svc
                .list_outbounds(request.into_inner())
                .map_err(proxyman_status)?;
            return Ok(Response::new(resp));
        }
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

    // --- inbound 7 op：proxyman 领域 service 委托；未注入 → UNIMPLEMENTED（明示）---

    async fn add_inbound(
        &self,
        request: Request<AddInboundRequest>,
    ) -> Result<Response<AddInboundResponse>, Status> {
        let Some(svc) = &self.proxyman else {
            return Err(Status::unimplemented(
                "AddInbound requires proxyman HandlerService (not injected)",
            ));
        };
        let resp = svc
            .add_inbound(request.into_inner())
            .map_err(proxyman_status)?;
        Ok(Response::new(resp))
    }

    async fn remove_inbound(
        &self,
        request: Request<RemoveInboundRequest>,
    ) -> Result<Response<RemoveInboundResponse>, Status> {
        let Some(svc) = &self.proxyman else {
            return Err(Status::unimplemented(
                "RemoveInbound requires proxyman HandlerService (not injected)",
            ));
        };
        let resp = svc
            .remove_inbound(request.into_inner())
            .map_err(proxyman_status)?;
        Ok(Response::new(resp))
    }

    async fn alter_inbound(
        &self,
        request: Request<AlterInboundRequest>,
    ) -> Result<Response<AlterInboundResponse>, Status> {
        let Some(svc) = &self.proxyman else {
            return Err(Status::unimplemented(
                "AlterInbound requires proxyman HandlerService (not injected)",
            ));
        };
        let resp = svc
            .alter_inbound(request.into_inner())
            .map_err(proxyman_status)?;
        Ok(Response::new(resp))
    }

    async fn list_inbounds(
        &self,
        request: Request<ListInboundsRequest>,
    ) -> Result<Response<ListInboundsResponse>, Status> {
        let Some(svc) = &self.proxyman else {
            return Err(Status::unimplemented(
                "ListInbounds requires proxyman HandlerService (not injected)",
            ));
        };
        let resp = svc
            .list_inbounds(request.into_inner())
            .map_err(proxyman_status)?;
        Ok(Response::new(resp))
    }

    async fn get_inbound_users(
        &self,
        request: Request<GetInboundUserRequest>,
    ) -> Result<Response<GetInboundUserResponse>, Status> {
        let Some(svc) = &self.proxyman else {
            return Err(Status::unimplemented(
                "GetInboundUsers requires proxyman HandlerService (not injected)",
            ));
        };
        let resp = svc
            .get_inbound_users(request.into_inner())
            .map_err(proxyman_status)?;
        Ok(Response::new(resp))
    }

    async fn get_inbound_users_count(
        &self,
        request: Request<GetInboundUserRequest>,
    ) -> Result<Response<GetInboundUsersCountResponse>, Status> {
        let Some(svc) = &self.proxyman else {
            return Err(Status::unimplemented(
                "GetInboundUsersCount requires proxyman HandlerService (not injected)",
            ));
        };
        let resp = svc
            .get_inbound_users_count(request.into_inner())
            .map_err(proxyman_status)?;
        Ok(Response::new(resp))
    }

    async fn alter_outbound(
        &self,
        request: Request<AlterOutboundRequest>,
    ) -> Result<Response<AlterOutboundResponse>, Status> {
        let Some(svc) = &self.proxyman else {
            return Err(Status::unimplemented(
                "AlterOutbound requires proxyman HandlerService (not injected)",
            ));
        };
        let resp = svc
            .alter_outbound(request.into_inner())
            .map_err(proxyman_status)?;
        Ok(Response::new(resp))
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
        request: Request<prouter::TestRouteRequest>,
    ) -> Result<Response<prouter::RoutingContext>, Status> {
        // Go routingServer.TestRoute（command.go:92-105）：
        // RoutingContext 必填 → PickRoute → 返回 RoutingContext{OutboundTag}。
        // PublishResult（stats channel 发布）无对应 wiring，忽略（明示）。
        let req = request.into_inner();
        let pctx = req.routing_context.ok_or_else(|| {
            Status::invalid_argument("Invalid routing request: RoutingContext is required")
        })?;
        let data = proto_routing_context_to_data(&pctx);
        let route = self.service.test_route(&data).map_err(router_status)?;
        // ponytail: FieldSelectors 投影未实现（Go AsProtobufMessage 选择器）——
        // 返回完整 RoutingContext（OutboundTag 填充，其余字段回显请求）。
        let mut out = pctx;
        out.outbound_tag = route.outbound_tag;
        Ok(Response::new(out))
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
        request: Request<prouter::AddRuleRequest>,
    ) -> Result<Response<prouter::AddRuleResponse>, Status> {
        // Go routingServer.AddRule（command.go:56-61）：config TypedMessage →
        // RoutingRule → router.AddRule(config, shouldAppend)。
        // shouldAppend=false 的前插语义由 Router::add_rule 的 append 实现吸收
        //（domain 层当前仅 append，ponytail 注记）。
        let req = request.into_inner();
        let tm = req.config.ok_or_else(|| {
            Status::invalid_argument("AddRuleRequest.config is required")
        })?;
        let rule = xray_proto::xray::app::router::RoutingRule::decode(tm.value.as_slice())
            .map_err(|e| Status::invalid_argument(format!("decode RoutingRule: {e}")))?;
        let rule_tag = rule.rule_tag.clone();
        if rule_tag.is_empty() {
            return Err(Status::invalid_argument("RoutingRule.rule_tag is required"));
        }
        self.service
            .add_rule(rule_tag, rule)
            .map_err(router_status)?;
        Ok(Response::new(prouter::AddRuleResponse {}))
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

/// proto `RoutingContext` → 领域 [`RoutingData`]（Go `AsRoutingContext` 适配）。
///
/// 字段映射（proto command.proto:15-31）：InboundTag/Network/SourceIPs/TargetIPs/
/// SourcePort/TargetPort/TargetDomain/Protocol/User/Attributes/LocalIPs/LocalPort/
/// VlessRoute。
fn proto_routing_context_to_data(p: &prouter::RoutingContext) -> xray_app_router::context::RoutingData {
    use xray_app_router::context::RoutingData;
    use xray_common::net::network::Network;
    use xray_common::net::port::Port;

    let ips = |raw: &[Vec<u8>]| -> Vec<std::net::IpAddr> {
        raw.iter()
            .filter_map(|b| match b.len() {
                4 => {
                    let a: [u8; 4] = b.as_slice().try_into().ok()?;
                    Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(a)))
                }
                16 => {
                    let a: [u8; 16] = b.as_slice().try_into().ok()?;
                    Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(a)))
                }
                _ => None,
            })
            .collect()
    };
    // Proto Network: Unknown=0, TCP=2, UDP=3, UNIX=4（对齐 xray-app-router
    // rule.rs proto_network_to_native；Unknown 回退 TCP）。
    let network = match p.network {
        3 => Network::UDP,
        4 => Network::Unix,
        _ => Network::TCP,
    };
    RoutingData {
        target_ips: ips(&p.target_i_ps),
        target_domain: p.target_domain.clone(),
        target_port: Port::new(p.target_port.clamp(0, u16::MAX as u32) as u16),
        source_ips: ips(&p.source_i_ps),
        source_port: Port::new(p.source_port.clamp(0, u16::MAX as u32) as u16),
        local_ips: ips(&p.local_i_ps),
        local_port: Port::new(p.local_port.clamp(0, u16::MAX as u32) as u16),
        vless_route: Port::new(p.vless_route.clamp(0, u16::MAX as u32) as u16),
        network,
        user: p.user.clone(),
        attributes: p.attributes.clone(),
        inbound_tag: p.inbound_tag.clone(),
        protocol: p.protocol.clone(),
        skip_dns_resolve: false,
    }
}

/// 监听规格（Go `Commander.Start` commander.go:78-99 的 listen 分派）。
pub(crate) enum ListenSpec {
    /// TCP 地址（`:8080` 简写补 `0.0.0.0`）。
    Tcp(SocketAddr),
    /// Unix domain socket 路径（`/` 或 `@` 前缀；Go commander.go:81-82）。
    #[allow(dead_code)]
    Unix(String),
}

/// 解析监听地址为 [`ListenSpec`]。
///
/// 对应 Go `Commander.Start`（commander.go:78-90）：
/// - `/path` 或 `@name` 前缀 → UnixAddr；
/// - 其余 → TCP（`:port` 简写补 `0.0.0.0`）。
/// 解析监听地址为 `SocketAddr`。
///
/// 支持 `"127.0.0.1:8080"`、`"0.0.0.0:8080"`、以及 `":8080"`（补 `0.0.0.0`）简写。
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

pub(crate) fn parse_listen_spec(addr: &str) -> Result<ListenSpec, String> {
    if addr.starts_with('/') || addr.starts_with('@') {
        return Ok(ListenSpec::Unix(addr.to_string()));
    }
    parse_listen_addr(addr).map(ListenSpec::Tcp)
}

/// `OutboundListenerImpl::accept` → tonic `serve_with_incoming` 的 Stream 适配。
pub(crate) struct ListenerIncoming {
    listener: Arc<crate::server::OutboundListenerImpl>,
    /// 在途 accept future（`OutboundListener::accept` 借用 `&self`，此处用
    /// `async move` 持有克隆的 Arc 消除借用）。
    accept: Option<Pin<Box<dyn Future<Output = Option<crate::outbound::CommanderConn>> + Send>>>,
}

impl ListenerIncoming {
    pub(crate) fn new(listener: Arc<crate::server::OutboundListenerImpl>) -> Self {
        Self {
            listener,
            accept: None,
        }
    }
}

impl futures::Stream for ListenerIncoming {
    type Item = std::io::Result<CommanderStream>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use crate::outbound::OutboundListener as _;
        loop {
            if let Some(fut) = self.accept.as_mut() {
                match fut.as_mut().poll(cx) {
                    std::task::Poll::Ready(Some(conn)) => {
                        self.accept = None;
                        return std::task::Poll::Ready(Some(Ok(CommanderStream(conn))));
                    }
                    // listener 关闭：终止 stream（serve 循环退出）。
                    std::task::Poll::Ready(None) => return std::task::Poll::Ready(None),
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                }
            }
            let l = Arc::clone(&self.listener);
            self.accept = Some(Box::pin(async move { l.accept().await }));
        }
    }
}

/// tonic serve 的连接包装（`Box<dyn CommanderIo>` 的 AsyncRead/AsyncWrite 转发）。
pub(crate) struct CommanderStream(pub(crate) crate::outbound::CommanderConn);

impl tokio::io::AsyncRead for CommanderStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for CommanderStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut *self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}

impl tonic::transport::server::Connected for CommanderStream {
    type ConnectInfo = ();
    fn connect_info(&self) -> Self::ConnectInfo {}
}

/// 构建已注册 command service 的 tonic `Router`。
///
/// 返回的 `Router` 可 `.serve(addr)` 或 `.serve_with_incoming(..)` 启动。
/// HandlerService 始终注册；proxyman / outbound runtime / logger / stats / routing /
/// observatory 仅在注入（`Some`）时注册。
///
/// **gRPC reflection opt-in**：仅当 [`commander::ReflectionService`] 通过
/// [`Commander::add_service`] 注册（即上层 `ApiConfig.services` 含
/// `"ReflectionService"`）时才注册 v1 + v1alpha——对应 Go `infra/conf/api.go:30`
/// `"reflectionservice"` 关键字的 opt-in 语义。未声明时整个 gRPC server 不暴露
/// reflection，避免 grpcurl 匿名枚举全部 command service。
pub(crate) fn build_router(
    registry: Arc<OutboundHandlerRegistry>,
    enable_reflection: bool,
    proxyman: Option<Arc<dyn xray_app_proxyman::command::HandlerService>>,
    outbound_runtime: Option<Arc<dyn OutboundRuntime>>,
    logger: Option<Arc<dyn xray_app_log::command::LogService>>,
    stats: Option<Arc<dyn xray_app_stats::command::StatsService>>,
    routing: Option<Arc<xray_app_router::command::RoutingService>>,
    observatory: Option<Arc<dyn xray_app_observatory::command::ObservatoryService>>,
) -> tonic::transport::server::Router {
    let mut handler_impl = HandlerServiceImpl::new(registry);
    if let Some(svc) = proxyman {
        handler_impl = handler_impl.with_proxyman_service(svc);
    }
    if let Some(rt) = outbound_runtime {
        handler_impl = handler_impl.with_outbound_runtime(rt);
    }
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
    // reflection opt-in：仅当用户显式注册 ReflectionService 时启用（Go
    // `infra/conf/api.go:30` 的 `"reflectionservice"` 关键字语义）。
    if enable_reflection {
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

    // ===== bd pa7 / 7iqw =====

    #[test]
    fn parse_listen_spec_unix_prefixes() {
        // Go commander.go:81-82：`/` 或 `@` 前缀 → unix socket
        assert!(matches!(
            parse_listen_spec("/var/run/xray/api.sock").unwrap(),
            ListenSpec::Unix(p) if p == "/var/run/xray/api.sock"
        ));
        assert!(matches!(
            parse_listen_spec("@xray-api").unwrap(),
            ListenSpec::Unix(p) if p == "@xray-api"
        ));
        // TCP 简写与完整地址
        assert!(matches!(
            parse_listen_spec(":8080").unwrap(),
            ListenSpec::Tcp(a) if a.port() == 8080
        ));
        assert!(matches!(
            parse_listen_spec("127.0.0.1:9000").unwrap(),
            ListenSpec::Tcp(a) if a.port() == 9000
        ));
        assert!(parse_listen_spec("not-an-addr").is_err());
    }

    /// proxyman 域 mock：inbound provider + user manager（Go handlerServer 依赖）。
    mod proxyman_mocks {
        use std::sync::Arc;
        use xray_app_proxyman::command::{
            DefaultHandlerService, HandlerFactory, InboundHandlerProvider, InboundOperation,
            InboundRegistrar, InboundRemover, MemoryUser, OperationDecoder, UserManager,
            InboundHandlerWithUserManager,
        };
        use xray_app_proxyman::error::ProxymanError;
        use xray_app_proxyman::inbound::InboundHandler;
        use parking_lot::Mutex;
        use xray_proto::xray::common::protocol::User as ProtoUser;

        pub struct MockUm {
            pub users: Mutex<Vec<MemoryUser>>,
        }
        impl UserManager for MockUm {
            fn add_user(&self, user: MemoryUser) -> Result<(), ProxymanError> {
                self.users.lock().push(user);
                Ok(())
            }
            fn remove_user(&self, email: &str) -> Result<(), ProxymanError> {
                let mut u = self.users.lock();
                let before = u.len();
                u.retain(|x| x.email != email);
                if u.len() == before {
                    return Err(ProxymanError::HandlerNotFound(email.to_string()));
                }
                Ok(())
            }
            fn get_user(&self, email: &str) -> Option<MemoryUser> {
                self.users.lock().iter().find(|u| u.email == email).cloned()
            }
            fn list_users(&self) -> Vec<MemoryUser> {
                self.users.lock().clone()
            }
            fn users_count(&self) -> usize {
                self.users.lock().len()
            }
        }

        pub struct MockInboundHandler {
            pub tag: String,
            pub um: Arc<MockUm>,
        }
        impl InboundHandler for MockInboundHandler {
            fn tag(&self) -> &str {
                &self.tag
            }
            fn start(&self) -> futures::future::BoxFuture<'static, Result<(), ProxymanError>> {
                Box::pin(async { Ok(()) })
            }
            fn close(&self) -> futures::future::BoxFuture<'static, Result<(), ProxymanError>> {
                Box::pin(async { Ok(()) })
            }
            fn receiver_settings(&self) -> Option<&xray_proto::xray::app::proxyman::ReceiverConfig> {
                None
            }
            fn proxy_type_url(&self) -> &str {
                "mock"
            }
        }
        impl InboundHandlerWithUserManager for MockInboundHandler {
            fn user_manager(&self) -> Option<&dyn UserManager> {
                Some(self.um.as_ref())
            }
        }

        #[derive(Default)]
        pub struct MockState {
            pub inbound_tags: Mutex<Vec<String>>,
            pub removed: Mutex<Vec<String>>,
            pub added: Mutex<Vec<String>>,
        }

        pub struct MockProvider {
            pub state: Arc<MockState>,
            pub handler: Arc<MockInboundHandler>,
        }
        impl InboundHandlerProvider for MockProvider {
            fn get_inbound_with_um(
                &self,
                tag: &str,
            ) -> Option<Arc<dyn InboundHandlerWithUserManager>> {
                if tag == self.handler.tag {
                    Some(Arc::clone(&self.handler) as Arc<dyn InboundHandlerWithUserManager>)
                } else {
                    None
                }
            }
            fn get_inbound(&self, tag: &str) -> Option<Arc<dyn InboundHandler>> {
                if tag == self.handler.tag {
                    Some(Arc::clone(&self.handler) as Arc<dyn InboundHandler>)
                } else {
                    None
                }
            }
            fn list_inbound_tags(&self) -> Vec<(String, Option<String>, String)> {
                self.state
                    .inbound_tags
                    .lock()
                    .iter()
                    .map(|t| (t.clone(), None, "mock".to_string()))
                    .collect()
            }
        }

        pub struct MockRegistrar(pub Arc<MockState>);
        impl InboundRegistrar for MockRegistrar {
            fn add_inbound_handler(
                &self,
                handler: Arc<dyn InboundHandler>,
            ) -> Result<(), ProxymanError> {
                self.0.added.lock().push(handler.tag().to_string());
                self.0.inbound_tags.lock().push(handler.tag().to_string());
                Ok(())
            }
        }

        pub struct MockRemover(pub Arc<MockState>);
        impl InboundRemover for MockRemover {
            fn remove_inbound_handler(&self, tag: &str) -> Result<(), ProxymanError> {
                self.0.removed.lock().push(tag.to_string());
                self.0.inbound_tags.lock().retain(|t| t != tag);
                Ok(())
            }
        }

        /// AddUser/RemoveUser TypedMessage 解码（Go GetInstance 对应物）。
        pub struct MockOpDecoder;
        impl OperationDecoder for MockOpDecoder {
            fn decode_inbound_op(
                &self,
                type_url: &str,
                value: &[u8],
            ) -> Result<Box<dyn InboundOperation>, ProxymanError> {
                use prost::Message as _;
                use xray_proto::xray::app::proxyman::command::{
                    AddUserOperation, RemoveUserOperation,
                };
                match type_url.rsplit('.').next().unwrap_or("") {
                    "AddUserOperation" => {
                        let p = AddUserOperation::decode(value)
                            .map_err(|e| ProxymanError::UserParse(e.to_string()))?;
                        Ok(Box::new(
                            xray_app_proxyman::command::AddUserOperation::from_proto(&p),
                        ))
                    }
                    "RemoveUserOperation" => {
                        let p = RemoveUserOperation::decode(value)
                            .map_err(|e| ProxymanError::UserParse(e.to_string()))?;
                        Ok(Box::new(
                            xray_app_proxyman::command::RemoveUserOperation::from_proto(&p),
                        ))
                    }
                    _ => Err(ProxymanError::UnknownOperation),
                }
            }
            fn decode_outbound_op(
                &self,
                _type_url: &str,
                _value: &[u8],
            ) -> Result<Box<dyn xray_app_proxyman::command::OutboundOperation>, ProxymanError> {
                Err(ProxymanError::UnknownOperation)
            }
        }

        pub struct MockFactory;
        impl HandlerFactory for MockFactory {
            fn create_inbound(
                &self,
                config: &xray_proto::xray::core::InboundHandlerConfig,
            ) -> Result<Arc<dyn InboundHandler>, ProxymanError> {
                Ok(Arc::new(MockInboundHandler {
                    tag: config.tag.clone(),
                    um: Arc::new(MockUm { users: Mutex::new(Vec::new()) }),
                }))
            }
            fn create_outbound(
                &self,
                _config: &xray_proto::xray::core::OutboundHandlerConfig,
            ) -> Result<Arc<dyn xray_app_proxyman::outbound::OutboundHandler>, ProxymanError> {
                Err(ProxymanError::NotOutboundProxy)
            }
        }

        pub fn make_service() -> (
            Arc<DefaultHandlerService>,
            Arc<MockState>,
            Arc<MockUm>,
        ) {
            let state = Arc::new(MockState::default());
            let um = Arc::new(MockUm { users: Mutex::new(Vec::new()) });
            state.inbound_tags.lock().push("vmess-in".into());
            let handler = Arc::new(MockInboundHandler {
                tag: "vmess-in".into(),
                um: Arc::clone(&um),
            });
            let svc = Arc::new(DefaultHandlerService {
                inbound_provider: Some(Arc::new(MockProvider {
                    state: Arc::clone(&state),
                    handler,
                })),
                outbound_provider: None,
                inbound_registrar: Some(Arc::new(MockRegistrar(Arc::clone(&state)))),
                outbound_registrar: None,
                inbound_remover: Some(Arc::new(MockRemover(Arc::clone(&state)))),
                outbound_remover: None,
                op_decoder: Some(Arc::new(MockOpDecoder)),
                factory: Some(Arc::new(MockFactory)),
            });
            (svc, state, um)
        }

        pub fn proto_user(email: &str) -> ProtoUser {
            ProtoUser {
                email: email.to_string(),
                ..Default::default()
            }
        }
    }

    #[tokio::test]
    async fn handler_service_delegates_inbound_ops() {
        use proxyman_mocks::make_service;
        let (svc, _state, um) = make_service();
        let impl_ = HandlerServiceImpl::new(Arc::new(crate::server::OutboundHandlerRegistry::new()))
            .with_proxyman_service(svc);

        // GetInboundUsers：空 email → 全量（Go command.go:125-147）
        um.users.lock().push(xray_app_proxyman::command::MemoryUser {
            email: "a@x.com".into(),
            ..Default::default()
        });
        let resp = impl_
            .get_inbound_users(Request::new(
                xray_proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: "vmess-in".into(),
                    email: String::new(),
                },
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.users.len(), 1);
        assert_eq!(resp.users[0].email, "a@x.com");

        // GetInboundUsersCount
        let resp = impl_
            .get_inbound_users_count(Request::new(
                xray_proto::xray::app::proxyman::command::GetInboundUserRequest {
                    tag: "vmess-in".into(),
                    email: String::new(),
                },
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.count, 1);

        // ListInbounds
        let resp = impl_
            .list_inbounds(Request::new(
                xray_proto::xray::app::proxyman::command::ListInboundsRequest {
                    is_only_tags: true,
                },
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.inbounds.len(), 1);
        assert_eq!(resp.inbounds[0].tag, "vmess-in");

        // RemoveInbound
        impl_
            .remove_inbound(Request::new(
                xray_proto::xray::app::proxyman::command::RemoveInboundRequest {
                    tag: "vmess-in".into(),
                },
            ))
            .await
            .unwrap();

        // RemoveInbound 不存在的 tag → NotFound
        let err = impl_
            .remove_inbound(Request::new(
                xray_proto::xray::app::proxyman::command::RemoveInboundRequest {
                    tag: "nope".into(),
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn handler_service_alter_inbound_add_remove_user() {
        use prost::Message as _;
        use proxyman_mocks::{make_service, proto_user};
        use xray_proto::xray::app::proxyman::command::{
            AddUserOperation, AlterInboundRequest, RemoveUserOperation,
        };
        use xray_proto::xray::common::serial::TypedMessage;

        let (svc, _state, um) = make_service();
        let impl_ = HandlerServiceImpl::new(Arc::new(crate::server::OutboundHandlerRegistry::new()))
            .with_proxyman_service(svc);

        // AddUserOperation（Go command.go:37-52）
        let op = AddUserOperation {
            user: Some(proto_user("new@x.com")),
        };
        impl_
            .alter_inbound(Request::new(AlterInboundRequest {
                tag: "vmess-in".into(),
                operation: Some(TypedMessage {
                    r#type: "xray.app.proxyman.command.AddUserOperation".into(),
                    value: op.encode_to_vec(),
                }),
            }))
            .await
            .unwrap();
        assert_eq!(um.users.lock().len(), 1);

        // RemoveUserOperation（Go command.go:54-65）
        let op = RemoveUserOperation {
            email: "new@x.com".into(),
        };
        impl_
            .alter_inbound(Request::new(AlterInboundRequest {
                tag: "vmess-in".into(),
                operation: Some(TypedMessage {
                    r#type: "xray.app.proxyman.command.RemoveUserOperation".into(),
                    value: op.encode_to_vec(),
                }),
            }))
            .await
            .unwrap();
        assert_eq!(um.users.lock().len(), 0);

        // 未知 operation → InvalidArgument
        let err = impl_
            .alter_inbound(Request::new(AlterInboundRequest {
                tag: "vmess-in".into(),
                operation: Some(TypedMessage {
                    r#type: "xray.app.proxyman.command.Nope".into(),
                    value: vec![],
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn handler_service_without_proxyman_inbound_unimplemented() {
        // 未注入 proxyman service → inbound op 明示 UNIMPLEMENTED
        let impl_ =
            HandlerServiceImpl::new(Arc::new(crate::server::OutboundHandlerRegistry::new()));
        let err = impl_
            .list_inbounds(Request::new(
                xray_proto::xray::app::proxyman::command::ListInboundsRequest {
                    is_only_tags: false,
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);
    }

    #[tokio::test]
    async fn routing_test_route_without_context_invalid_argument() {
        let svc = RoutingServiceImpl::new(Arc::new(
            xray_app_router::command::RoutingService::new(),
        ));
        let resp = svc
            .test_route(Request::new(prouter::TestRouteRequest {
                routing_context: None,
                publish_result: false,
                field_selectors: vec![],
            }))
            .await;
        assert!(resp.is_err());
        assert_eq!(resp.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn routing_add_rule_decodes_typed_message() {
        use prost::Message as _;
        use xray_proto::xray::app::router::RoutingRule;
        use xray_proto::xray::common::serial::TypedMessage;
        use xray_app_router::balancing::OutboundHandlerSelector;

        struct NopSelector;
        impl OutboundHandlerSelector for NopSelector {
            fn select_outbounds(
                &self,
                selectors: &[String],
            ) -> Result<Vec<String>, xray_app_router::error::RouterError> {
                Ok(selectors.to_vec())
            }
        }

        let router = xray_app_router::router::Router::empty(Arc::new(NopSelector), None);
        let svc = RoutingServiceImpl::new(Arc::new(
            xray_app_router::command::RoutingService::with_router(router),
        ));

        let mut rule = RoutingRule::default();
        rule.rule_tag = "rule-1".into();
        rule.networks = vec![2]; // TCP（proto Network: TCP=2），保证有有效匹配字段
        rule.target_tag = Some(xray_proto::xray::app::router::routing_rule::TargetTag::Tag(
            "direct".into(),
        ));
        svc.add_rule(Request::new(prouter::AddRuleRequest {
            config: Some(TypedMessage {
                r#type: "xray.app.router.RoutingRule".into(),
                value: rule.encode_to_vec(),
            }),
            should_append: true,
        }))
        .await
        .unwrap();

        // ListRule 可见新增规则 tag
        let resp = svc
            .list_rule(Request::new(prouter::ListRuleRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(resp.rules.iter().any(|r| r.rule_tag == "rule-1"));

        // 空 rule_tag → InvalidArgument
        let err = svc
            .add_rule(Request::new(prouter::AddRuleRequest {
                config: Some(TypedMessage {
                    r#type: "xray.app.router.RoutingRule".into(),
                    value: RoutingRule::default().encode_to_vec(),
                }),
                should_append: true,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }
}

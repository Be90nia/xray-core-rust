//! Commander gRPC 服务（tonic 实现）。
//!
//! 对应 Go `app/commander` 中各 command service 的 `Register(*grpc.Server)`：
//! 把 [`HandlerServiceImpl`] 注册到 tonic server，暴露 `HandlerService`
//!（add/remove/list outbound）等 gRPC 方法。
//!
//! ## 范围
//!
//! - `add_outbound` / `remove_outbound` / `list_outbounds`：操作 Commander 内部
//!   [`OutboundHandlerRegistry`](crate::server::OutboundHandlerRegistry)（注册 stub handler）。
//!   接入 dispatcher 的真实 outbound manager 需 transport 全链路，留作后续。
//! - 其余方法（inbound / alter / users）返回 `UNIMPLEMENTED`。

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
use xray_proto::xray::core::OutboundHandlerConfig;
use crate::outbound::HandlerManager;
use crate::server::OutboundHandlerRegistry;

/// HandlerService gRPC 实现。
///
/// 持有共享的 [`OutboundHandlerRegistry`]，add/remove/list outbound 操作其上。
/// 其余方法（inbound 相关、alter、users）尚未实现，返回 `UNIMPLEMENTED`。
#[derive(Clone)]
pub struct HandlerServiceImpl {
    registry: Arc<OutboundHandlerRegistry>,
}

impl HandlerServiceImpl {
    #[must_use]
    pub fn new(registry: Arc<OutboundHandlerRegistry>) -> Self {
        Self { registry }
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
        // ponytail: 注册 stub handler（无真实拨号能力）；接入 dispatcher outbound
        // manager 后替换为真实 handler 构建。tag 维度 add/remove/list 已可用。
        let handler = crate::outbound::StubOutboundHandler::new(tag.clone());
        self.registry
            .add_handler(Arc::new(handler))
            .map_err(|e| Status::already_exists(format!("add outbound `{tag}`: {e}")))?;
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
        self.registry
            .remove_handler(&tag)
            .map_err(|e| Status::not_found(format!("remove outbound `{tag}`: {e}")))?;
        tracing::info!(tag = %tag, "commander: outbound removed via gRPC");
        Ok(Response::new(RemoveOutboundResponse {}))
    }

    async fn list_outbounds(
        &self,
        _request: Request<ListOutboundsRequest>,
    ) -> Result<Response<ListOutboundsResponse>, Status> {
        let outbounds = self
            .registry
            .list_tags()
            .into_iter()
            .map(|tag| OutboundHandlerConfig {
                tag: tag.into(),
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

/// 构建已注册 HandlerService 的 tonic `Router`。
///
/// 返回的 `Router` 可 `.serve(addr)` 启动。当前固定注册 HandlerService；
/// 接入更多 command service 时在此追加 `add_service`。
pub(crate) fn build_router(
    registry: Arc<OutboundHandlerRegistry>,
) -> tonic::transport::server::Router {
    let svc = HandlerServiceServer::new(HandlerServiceImpl::new(registry));
    Server::builder().add_service(svc)
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
}

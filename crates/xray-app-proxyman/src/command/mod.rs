//! gRPC 命令操作与 HandlerService 编排
//!
//! 对应 Go `app/proxyman/command/command.go`（操作类型 + 服务实现）+
//! `app/proxyman/command/command.proto`（gRPC 服务定义）。
//!
//! ## 当前实现范围
//!
//! 业务核心（独立可测）：
//! - [`InboundOperation`] / [`OutboundOperation`] trait — Go 同名接口
//! - [`AddUserOperation`] / [`RemoveUserOperation`] — proto 操作类型 + Apply 逻辑
//! - [`command::UserManager`] trait — Go `proxy.UserManager`
//! - [`InboundHandlerProvider`] / [`OutboundHandlerProvider`] trait — Go
//!   `proxy.GetInbound`/`GetOutbound`
//! - [`HandlerService`] trait + [`DefaultHandlerService`] 编排（依赖 manager 注入）
//!
//! IO 边界（TODO）：
//! - gRPC server 注册（Go `service.Register(*grpc.Server)`）— 依赖 tonic + xray-app-commander

use std::sync::Arc;

use xray_proto::xray::{
    app::proxyman::command::{
        AddInboundRequest, AddInboundResponse, AddOutboundRequest, AddOutboundResponse,
        AddUserOperation as ProtoAddUserOp, AlterInboundRequest, AlterInboundResponse,
        AlterOutboundRequest, AlterOutboundResponse, GetInboundUserRequest, GetInboundUserResponse,
        GetInboundUsersCountResponse, ListInboundsRequest, ListInboundsResponse,
        ListOutboundsRequest, ListOutboundsResponse, RemoveInboundRequest, RemoveInboundResponse,
        RemoveOutboundRequest, RemoveOutboundResponse, RemoveUserOperation as ProtoRemoveUserOp,
    },
    common::protocol::User as ProtoUser,
};

use crate::{error::ProxymanError, inbound::InboundHandler, outbound::OutboundHandler};

// ========== Operation traits ==========

/// 入站操作 trait（对应 Go `InboundOperation interface`）
pub trait InboundOperation: Send + Sync {
    /// 应用到此入站 handler（对应 Go `ApplyInbound(ctx, Handler) error`）
    fn apply_inbound(
        &self,
        handler: &dyn InboundHandlerWithUserManager,
    ) -> Result<(), ProxymanError>;
}

/// 出站操作 trait（对应 Go `OutboundOperation interface`）
pub trait OutboundOperation: Send + Sync {
    /// 应用到此出站 handler（对应 Go `ApplyOutbound(ctx, Handler) error`）
    fn apply_outbound(
        &self,
        handler: &dyn OutboundHandlerWithUserManager,
    ) -> Result<(), ProxymanError>;
}

// ========== User management ==========

/// 内存用户（Go `protocol.MemoryUser` 简化版）
///
/// ponytail: Go MemoryUser 字段丰富（Level/Email/Account/AlterIds 等），
/// 此处只保留 proxyman 命令路径必需的最小字段；上层代理 crate 注入完整 MemoryUser 时
/// 可用单独的转换器映射到 [`MemoryUser`]。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryUser {
    pub email: String,
    pub level: u32,
}

impl MemoryUser {
    /// 从 proto User 转换（对应 Go `User.ToMemoryUser()`）
    ///
    /// Go 完整逻辑涉及 Account 解码、AlterIds 拷贝等；此处仅取 email + level，
    /// Account 解析依赖具体代理类型，留 TODO。
    #[must_use]
    pub fn from_proto(u: &ProtoUser) -> Self {
        Self { email: u.email.clone(), level: u.level }
    }

    /// 转 proto User（对应 Go `protocol.ToProtoUser(memoryUser)`）
    #[must_use]
    pub fn to_proto(&self) -> ProtoUser {
        let mut u = ProtoUser::default();
        u.email = self.email.clone();
        u.level = self.level;
        u
    }
}

/// UserManager trait（对应 Go `proxy.UserManager interface`）
///
/// 上层代理（如 vmess inbound）实现此 trait 以支持 AddUser/RemoveUser RPC。
pub trait UserManager: Send + Sync {
    /// 添加用户
    fn add_user(&self, user: MemoryUser) -> Result<(), ProxymanError>;
    /// 移除指定 email 的用户
    fn remove_user(&self, email: &str) -> Result<(), ProxymanError>;
    /// 取单个用户
    fn get_user(&self, email: &str) -> Option<MemoryUser>;
    /// 列出所有用户
    fn list_users(&self) -> Vec<MemoryUser>;
    /// 用户数
    fn users_count(&self) -> usize {
        self.list_users().len()
    }
}

/// InboundHandler 上层 trait：暴露底层 UserManager
///
/// 对应 Go `getInbound(handler)` + `p.(proxy.UserManager)` 两步类型断言。
pub trait InboundHandlerWithUserManager: InboundHandler {
    /// 返回 UserManager 引用（若底层 proxy 不是 UserManager 返回 None）
    fn user_manager(&self) -> Option<&dyn UserManager>;
}

/// OutboundHandler 上层 trait：暴露底层 UserManager
pub trait OutboundHandlerWithUserManager: OutboundHandler {
    /// 返回 UserManager 引用
    fn user_manager(&self) -> Option<&dyn UserManager>;
}

// ========== AddUserOperation / RemoveUserOperation ==========

/// AddUser 操作（对应 Go `AddUserOperation struct` + `ApplyInbound`）
#[derive(Debug, Clone)]
pub struct AddUserOperation {
    pub user: MemoryUser,
}

impl AddUserOperation {
    #[must_use]
    pub fn new(user: MemoryUser) -> Self {
        Self { user }
    }

    /// 从 proto 构造（含 `ToMemoryUser` 转换）
    #[must_use]
    pub fn from_proto(op: &ProtoAddUserOp) -> Self {
        let user = op.user.as_ref().map(MemoryUser::from_proto).unwrap_or_default();
        Self { user }
    }
}

impl InboundOperation for AddUserOperation {
    fn apply_inbound(
        &self,
        handler: &dyn InboundHandlerWithUserManager,
    ) -> Result<(), ProxymanError> {
        let um = handler.user_manager().ok_or(ProxymanError::NotUserManager)?;
        um.add_user(self.user.clone())
    }
}

/// RemoveUser 操作（对应 Go `RemoveUserOperation struct` + `ApplyInbound`）
#[derive(Debug, Clone)]
pub struct RemoveUserOperation {
    pub email: String,
}

impl RemoveUserOperation {
    #[must_use]
    pub fn new(email: impl Into<String>) -> Self {
        Self { email: email.into() }
    }

    /// 从 proto 构造
    #[must_use]
    pub fn from_proto(op: &ProtoRemoveUserOp) -> Self {
        Self { email: op.email.clone() }
    }
}

impl InboundOperation for RemoveUserOperation {
    fn apply_inbound(
        &self,
        handler: &dyn InboundHandlerWithUserManager,
    ) -> Result<(), ProxymanError> {
        let um = handler.user_manager().ok_or(ProxymanError::NotUserManager)?;
        um.remove_user(&self.email)
    }
}

// ========== TypedMessage operation dispatch ==========

/// proto TypedMessage 操作解码 trait
///
/// Go 用 `request.Operation.GetInstance()` + `.(InboundOperation)` 类型断言解码 TypedMessage。
/// Rust 端 prost 没有 `GetInstance`，由上层注入实现：根据 `type_url` 字符串构造对应操作。
pub trait OperationDecoder: Send + Sync {
    /// 解码为 InboundOperation；未知 type_url 返回 [`ProxymanError::UnknownOperation`]
    fn decode_inbound_op(
        &self,
        type_url: &str,
        payload: &[u8],
    ) -> Result<Box<dyn InboundOperation>, ProxymanError>;

    /// 解码为 OutboundOperation
    fn decode_outbound_op(
        &self,
        type_url: &str,
        payload: &[u8],
    ) -> Result<Box<dyn OutboundOperation>, ProxymanError>;
}

// ========== HandlerService ==========

/// gRPC HandlerService trait（对应 Go `handlerServer` 实现 `HandlerServiceServer`）
///
/// 上层（如 xray-app-commander）通过注入 [`InboundHandlerProvider`] / [`OutboundHandlerProvider`]
/// 让 service 取到底层 handler。
pub trait HandlerService: Send + Sync {
    fn add_inbound(&self, req: AddInboundRequest) -> Result<AddInboundResponse, ProxymanError>;
    fn remove_inbound(
        &self,
        req: RemoveInboundRequest,
    ) -> Result<RemoveInboundResponse, ProxymanError>;
    fn alter_inbound(
        &self,
        req: AlterInboundRequest,
    ) -> Result<AlterInboundResponse, ProxymanError>;
    fn list_inbounds(
        &self,
        req: ListInboundsRequest,
    ) -> Result<ListInboundsResponse, ProxymanError>;
    fn get_inbound_users(
        &self,
        req: GetInboundUserRequest,
    ) -> Result<GetInboundUserResponse, ProxymanError>;
    fn get_inbound_users_count(
        &self,
        req: GetInboundUserRequest,
    ) -> Result<GetInboundUsersCountResponse, ProxymanError>;
    fn add_outbound(&self, req: AddOutboundRequest) -> Result<AddOutboundResponse, ProxymanError>;
    fn remove_outbound(
        &self,
        req: RemoveOutboundRequest,
    ) -> Result<RemoveOutboundResponse, ProxymanError>;
    fn alter_outbound(
        &self,
        req: AlterOutboundRequest,
    ) -> Result<AlterOutboundResponse, ProxymanError>;
    fn list_outbounds(
        &self,
        req: ListOutboundsRequest,
    ) -> Result<ListOutboundsResponse, ProxymanError>;
}

/// Inbound handler 提供方（让 HandlerService 找到具体 handler）
pub trait InboundHandlerProvider: Send + Sync {
    /// 按 tag 取出实现了 [`InboundHandlerWithUserManager`] 的 handler
    fn get_inbound_with_um(&self, tag: &str) -> Option<Arc<dyn InboundHandlerWithUserManager>>;
    /// 按 tag 取出 inbound handler（基础 trait）
    fn get_inbound(&self, tag: &str) -> Option<Arc<dyn InboundHandler>>;
    /// 列出所有 inbound 的 (tag, receiver_type_url, proxy_type_url)
    fn list_inbound_tags(&self) -> Vec<(String, Option<String>, String)>;
}

/// Outbound handler 提供方
pub trait OutboundHandlerProvider: Send + Sync {
    fn get_outbound_with_um(&self, tag: &str) -> Option<Arc<dyn OutboundHandlerWithUserManager>>;
    fn get_outbound(&self, tag: &str) -> Option<Arc<dyn OutboundHandler>>;
    /// 列出所有 outbound 的 (tag, sender_type_url, proxy_type_url)
    fn list_outbound_tags(&self) -> Vec<(String, Option<String>, String)>;
}

/// Inbound 添加器（让 HandlerService 能调用 InboundManager.add_handler）
pub trait InboundRegistrar: Send + Sync {
    /// 注册一个新 inbound handler（Go `core.AddInboundHandler`）
    fn add_inbound_handler(&self, handler: Arc<dyn InboundHandler>) -> Result<(), ProxymanError>;
}

/// Outbound 添加器
pub trait OutboundRegistrar: Send + Sync {
    fn add_outbound_handler(&self, handler: Arc<dyn OutboundHandler>) -> Result<(), ProxymanError>;
}

/// Inbound 移除器（让 HandlerService 能实际移除 handler）
pub trait InboundRemover: Send + Sync {
    /// 按 tag 移除 inbound handler（Go `ihm.RemoveHandler`）
    fn remove_inbound_handler(&self, tag: &str) -> Result<(), ProxymanError>;
}

/// Outbound 移除器
pub trait OutboundRemover: Send + Sync {
    fn remove_outbound_handler(&self, tag: &str) -> Result<(), ProxymanError>;
}

/// Handler 工厂（从 proto config 创建 handler）
pub trait HandlerFactory: Send + Sync {
    fn create_inbound(
        &self,
        config: &xray_proto::xray::core::InboundHandlerConfig,
    ) -> Result<Arc<dyn InboundHandler>, ProxymanError>;
    fn create_outbound(
        &self,
        config: &xray_proto::xray::core::OutboundHandlerConfig,
    ) -> Result<Arc<dyn OutboundHandler>, ProxymanError>;
}

/// 默认 HandlerService 实现（对应 Go `handlerServer struct`）
#[derive(Default)]
pub struct DefaultHandlerService {
    /// 入站 handler 提供方（对应 Go `ihm inbound.Manager`）
    pub inbound_provider: Option<Arc<dyn InboundHandlerProvider>>,
    /// 出站 handler 提供方
    pub outbound_provider: Option<Arc<dyn OutboundHandlerProvider>>,
    /// 入站注册器（对应 Go `core.AddInboundHandler`）
    pub inbound_registrar: Option<Arc<dyn InboundRegistrar>>,
    /// 出站注册器
    pub outbound_registrar: Option<Arc<dyn OutboundRegistrar>>,
    /// 入站移除器（对应 Go `ihm.RemoveHandler`）
    pub inbound_remover: Option<Arc<dyn InboundRemover>>,
    /// 出站移除器
    pub outbound_remover: Option<Arc<dyn OutboundRemover>>,
    /// TypedMessage 操作解码器
    pub op_decoder: Option<Arc<dyn OperationDecoder>>,
    /// Handler 工厂（从 proto config 创建 handler）
    pub factory: Option<Arc<dyn HandlerFactory>>,
}


impl std::fmt::Debug for DefaultHandlerService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefaultHandlerService")
            .field("has_inbound_provider", &self.inbound_provider.is_some())
            .field("has_outbound_provider", &self.outbound_provider.is_some())
            .field("has_inbound_registrar", &self.inbound_registrar.is_some())
            .field("has_outbound_registrar", &self.outbound_registrar.is_some())
            .field("has_inbound_remover", &self.inbound_remover.is_some())
            .field("has_outbound_remover", &self.outbound_remover.is_some())
            .field("has_op_decoder", &self.op_decoder.is_some())
            .field("has_factory", &self.factory.is_some())
            .finish()
    }
}

impl DefaultHandlerService {
    /// 应用一个 InboundOperation 到指定 tag（对应 Go `AlterInbound` 主体逻辑）
    fn apply_inbound_op(
        &self,
        tag: &str,
        op: Box<dyn InboundOperation>,
    ) -> Result<(), ProxymanError> {
        let provider = self
            .inbound_provider
            .as_ref()
            .ok_or_else(|| ProxymanError::Other("inbound provider not set".into()))?;
        let handler = provider
            .get_inbound_with_um(tag)
            .ok_or_else(|| ProxymanError::HandlerNotFound(tag.to_string()))?;
        op.apply_inbound(handler.as_ref())
    }

    fn apply_outbound_op(
        &self,
        tag: &str,
        op: Box<dyn OutboundOperation>,
    ) -> Result<(), ProxymanError> {
        let provider = self
            .outbound_provider
            .as_ref()
            .ok_or_else(|| ProxymanError::Other("outbound provider not set".into()))?;
        let handler = provider
            .get_outbound_with_um(tag)
            .ok_or_else(|| ProxymanError::HandlerNotFound(tag.to_string()))?;
        op.apply_outbound(handler.as_ref())
    }
}

impl HandlerService for DefaultHandlerService {
    fn add_inbound(&self, req: AddInboundRequest) -> Result<AddInboundResponse, ProxymanError> {
        let registrar = self
            .inbound_registrar
            .as_ref()
            .ok_or_else(|| ProxymanError::Other("inbound registrar not set".into()))?;
        let factory = self
            .factory
            .as_ref()
            .ok_or_else(|| ProxymanError::Other("handler factory not set".into()))?;
        let config =
            req.inbound.ok_or_else(|| ProxymanError::Other("missing inbound config".into()))?;
        let handler = factory.create_inbound(&config)?;
        registrar.add_inbound_handler(handler)?;
        Ok(AddInboundResponse {})
    }

    fn remove_inbound(
        &self,
        req: RemoveInboundRequest,
    ) -> Result<RemoveInboundResponse, ProxymanError> {
        let provider = self
            .inbound_provider
            .as_ref()
            .ok_or_else(|| ProxymanError::Other("inbound provider not set".into()))?;
        // 检查存在性
        if provider.get_inbound(&req.tag).is_none() {
            return Err(ProxymanError::HandlerNotFound(req.tag.clone()));
        }
        // 实际移除：委托 InboundRemover
        if let Some(remover) = &self.inbound_remover {
            remover.remove_inbound_handler(&req.tag)?;
        }
        Ok(RemoveInboundResponse {})
    }

    fn alter_inbound(
        &self,
        req: AlterInboundRequest,
    ) -> Result<AlterInboundResponse, ProxymanError> {
        let decoder = self
            .op_decoder
            .as_ref()
            .ok_or_else(|| ProxymanError::Other("operation decoder not set".into()))?;
        let op = req.operation.as_ref().ok_or(ProxymanError::UnknownOperation)?;
        let boxed = decoder.decode_inbound_op(&op.r#type, &op.value)?;
        self.apply_inbound_op(&req.tag, boxed)?;
        Ok(AlterInboundResponse {})
    }

    fn list_inbounds(
        &self,
        req: ListInboundsRequest,
    ) -> Result<ListInboundsResponse, ProxymanError> {
        let provider = self
            .inbound_provider
            .as_ref()
            .ok_or_else(|| ProxymanError::Other("inbound provider not set".into()))?;
        let mut resp = ListInboundsResponse::default();
        for (tag, recv_url, proxy_url) in provider.list_inbound_tags() {
            let mut cfg = xray_proto::xray::core::InboundHandlerConfig::default();
            cfg.tag = tag;
            if !req.is_only_tags {
                // 填充 receiver/proxy type_url（完整 TypedMessage 序列化需上层注入，当前填
                // type_url）
                if let Some(url) = &recv_url {
                    cfg.receiver_settings = Some(xray_proto::xray::common::serial::TypedMessage {
                        r#type: url.clone(),
                        value: Vec::new(),
                    });
                }
                cfg.proxy_settings = Some(xray_proto::xray::common::serial::TypedMessage {
                    r#type: proxy_url,
                    value: Vec::new(),
                });
            }
            resp.inbounds.push(cfg);
        }
        Ok(resp)
    }

    fn get_inbound_users(
        &self,
        req: GetInboundUserRequest,
    ) -> Result<GetInboundUserResponse, ProxymanError> {
        let provider = self
            .inbound_provider
            .as_ref()
            .ok_or_else(|| ProxymanError::Other("inbound provider not set".into()))?;
        let handler = provider
            .get_inbound_with_um(&req.tag)
            .ok_or_else(|| ProxymanError::HandlerNotFound(req.tag.clone()))?;
        let um = handler.user_manager().ok_or(ProxymanError::NotUserManager)?;

        let mut resp = GetInboundUserResponse::default();
        if !req.email.is_empty() {
            if let Some(u) = um.get_user(&req.email) {
                resp.users.push(u.to_proto());
            }
        } else {
            for u in um.list_users() {
                resp.users.push(u.to_proto());
            }
        }
        Ok(resp)
    }

    fn get_inbound_users_count(
        &self,
        req: GetInboundUserRequest,
    ) -> Result<GetInboundUsersCountResponse, ProxymanError> {
        let provider = self
            .inbound_provider
            .as_ref()
            .ok_or_else(|| ProxymanError::Other("inbound provider not set".into()))?;
        let handler = provider
            .get_inbound_with_um(&req.tag)
            .ok_or_else(|| ProxymanError::HandlerNotFound(req.tag.clone()))?;
        let um = handler.user_manager().ok_or(ProxymanError::NotUserManager)?;
        Ok(GetInboundUsersCountResponse {
            count: i64::try_from(um.users_count()).unwrap_or(i64::MAX),
        })
    }

    fn add_outbound(&self, req: AddOutboundRequest) -> Result<AddOutboundResponse, ProxymanError> {
        let registrar = self
            .outbound_registrar
            .as_ref()
            .ok_or_else(|| ProxymanError::Other("outbound registrar not set".into()))?;
        let factory = self
            .factory
            .as_ref()
            .ok_or_else(|| ProxymanError::Other("handler factory not set".into()))?;
        let config =
            req.outbound.ok_or_else(|| ProxymanError::Other("missing outbound config".into()))?;
        let handler = factory.create_outbound(&config)?;
        registrar.add_outbound_handler(handler)?;
        Ok(AddOutboundResponse {})
    }

    fn remove_outbound(
        &self,
        req: RemoveOutboundRequest,
    ) -> Result<RemoveOutboundResponse, ProxymanError> {
        let provider = self
            .outbound_provider
            .as_ref()
            .ok_or_else(|| ProxymanError::Other("outbound provider not set".into()))?;
        if provider.get_outbound(&req.tag).is_none() {
            return Err(ProxymanError::HandlerNotFound(req.tag.clone()));
        }
        // 实际移除：委托 OutboundRemover
        if let Some(remover) = &self.outbound_remover {
            remover.remove_outbound_handler(&req.tag)?;
        }
        Ok(RemoveOutboundResponse {})
    }

    fn alter_outbound(
        &self,
        req: AlterOutboundRequest,
    ) -> Result<AlterOutboundResponse, ProxymanError> {
        let decoder = self
            .op_decoder
            .as_ref()
            .ok_or_else(|| ProxymanError::Other("operation decoder not set".into()))?;
        let op = req.operation.as_ref().ok_or(ProxymanError::UnknownOperation)?;
        let boxed = decoder.decode_outbound_op(&op.r#type, &op.value)?;
        self.apply_outbound_op(&req.tag, boxed)?;
        Ok(AlterOutboundResponse {})
    }

    fn list_outbounds(
        &self,
        _req: ListOutboundsRequest,
    ) -> Result<ListOutboundsResponse, ProxymanError> {
        let provider = self
            .outbound_provider
            .as_ref()
            .ok_or_else(|| ProxymanError::Other("outbound provider not set".into()))?;
        let mut resp = ListOutboundsResponse::default();
        for (tag, send_url, proxy_url) in provider.list_outbound_tags() {
            let mut cfg = xray_proto::xray::core::OutboundHandlerConfig::default();
            cfg.tag = tag;
            // ListOutboundsRequest 无 is_only_tags 字段，总是返回完整配置
            if let Some(url) = &send_url {
                cfg.sender_settings = Some(xray_proto::xray::common::serial::TypedMessage {
                    r#type: url.clone(),
                    value: Vec::new(),
                });
            }
            cfg.proxy_settings = Some(xray_proto::xray::common::serial::TypedMessage {
                r#type: proxy_url,
                value: Vec::new(),
            });
            resp.outbounds.push(cfg);
        }
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use parking_lot::Mutex;

    use super::*;

    // ========== 测试 UserManager ==========

    struct TestUserManager {
        users: Mutex<Vec<MemoryUser>>,
    }

    impl TestUserManager {
        fn new() -> Self {
            Self { users: Mutex::new(Vec::new()) }
        }
    }

    impl UserManager for TestUserManager {
        fn add_user(&self, user: MemoryUser) -> Result<(), ProxymanError> {
            self.users.lock().push(user);
            Ok(())
        }

        fn remove_user(&self, email: &str) -> Result<(), ProxymanError> {
            let mut u = self.users.lock();
            u.retain(|x| x.email != email);
            Ok(())
        }

        fn get_user(&self, email: &str) -> Option<MemoryUser> {
            self.users.lock().iter().find(|u| u.email == email).cloned()
        }

        fn list_users(&self) -> Vec<MemoryUser> {
            self.users.lock().clone()
        }
    }

    // ========== 测试 InboundHandlerWithUserManager ==========

    struct StubInboundWithUM {
        tag: String,
        um: Arc<TestUserManager>,
    }

    impl InboundHandler for StubInboundWithUM {
        fn tag(&self) -> &str {
            &self.tag
        }

        fn start(&self) -> crate::inbound::PinFuture<Result<(), ProxymanError>> {
            Box::pin(async { Ok(()) })
        }

        fn close(&self) -> crate::inbound::PinFuture<Result<(), ProxymanError>> {
            Box::pin(async { Ok(()) })
        }

        fn receiver_settings(&self) -> Option<&xray_proto::xray::app::proxyman::ReceiverConfig> {
            None
        }

        fn proxy_type_url(&self) -> &str {
            "xray.test"
        }
    }

    impl InboundHandlerWithUserManager for StubInboundWithUM {
        fn user_manager(&self) -> Option<&dyn UserManager> {
            Some(self.um.as_ref())
        }
    }

    fn make_stub_inbound(tag: &str) -> Arc<StubInboundWithUM> {
        Arc::new(StubInboundWithUM { tag: tag.to_string(), um: Arc::new(TestUserManager::new()) })
    }

    // ========== MemoryUser ==========

    #[test]
    fn memory_user_default() {
        let u = MemoryUser::default();
        assert!(u.email.is_empty());
        assert_eq!(u.level, 0);
    }

    #[test]
    fn memory_user_from_proto_extracts_email_level() {
        let mut p = ProtoUser::default();
        p.email = "alice@example.com".to_string();
        p.level = 5;
        let m = MemoryUser::from_proto(&p);
        assert_eq!(m.email, "alice@example.com");
        assert_eq!(m.level, 5);
    }

    #[test]
    fn memory_user_round_trip() {
        let m = MemoryUser { email: "bob@x.com".to_string(), level: 3 };
        let p = m.to_proto();
        let m2 = MemoryUser::from_proto(&p);
        assert_eq!(m, m2);
    }

    // ========== AddUserOperation / RemoveUserOperation ==========

    #[test]
    fn add_user_op_applies_to_user_manager() {
        let h = make_stub_inbound("vless");
        let op = AddUserOperation::new(MemoryUser { email: "u1@x.com".to_string(), level: 1 });
        op.apply_inbound(h.as_ref()).unwrap();
        assert_eq!(h.um.list_users().len(), 1);
        assert_eq!(h.um.list_users()[0].email, "u1@x.com");
    }

    #[test]
    fn remove_user_op_applies_to_user_manager() {
        let h = make_stub_inbound("vless");
        h.um.add_user(MemoryUser { email: "gone@x.com".to_string(), level: 0 }).unwrap();
        assert_eq!(h.um.list_users().len(), 1);
        let op = RemoveUserOperation::new("gone@x.com");
        op.apply_inbound(h.as_ref()).unwrap();
        assert_eq!(h.um.list_users().len(), 0);
    }

    #[test]
    fn add_user_op_from_proto() {
        let mut p = ProtoAddUserOp::default();
        let mut user = ProtoUser::default();
        user.email = "charlie@x.com".to_string();
        user.level = 7;
        p.user = Some(user);
        let op = AddUserOperation::from_proto(&p);
        assert_eq!(op.user.email, "charlie@x.com");
        assert_eq!(op.user.level, 7);
    }

    #[test]
    fn remove_user_op_from_proto() {
        let mut p = ProtoRemoveUserOp::default();
        p.email = "del@x.com".to_string();
        let op = RemoveUserOperation::from_proto(&p);
        assert_eq!(op.email, "del@x.com");
    }

    #[test]
    fn add_user_op_returns_not_user_manager_when_no_um() {
        struct NoUmInbound;
        impl InboundHandler for NoUmInbound {
            fn tag(&self) -> &str {
                "x"
            }

            fn start(&self) -> crate::inbound::PinFuture<Result<(), ProxymanError>> {
                Box::pin(async { Ok(()) })
            }

            fn close(&self) -> crate::inbound::PinFuture<Result<(), ProxymanError>> {
                Box::pin(async { Ok(()) })
            }

            fn receiver_settings(
                &self,
            ) -> Option<&xray_proto::xray::app::proxyman::ReceiverConfig> {
                None
            }

            fn proxy_type_url(&self) -> &str {
                "x"
            }
        }
        impl InboundHandlerWithUserManager for NoUmInbound {
            fn user_manager(&self) -> Option<&dyn UserManager> {
                None
            }
        }
        let h = NoUmInbound;
        let op = AddUserOperation::new(MemoryUser::default());
        match op.apply_inbound(&h) {
            Err(ProxymanError::NotUserManager) => (),
            Err(e) => panic!("expected NotUserManager, got: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    // ========== DefaultHandlerService ==========

    struct StubInboundProvider {
        handlers: Mutex<Vec<Arc<dyn InboundHandlerWithUserManager>>>,
    }

    impl InboundHandlerProvider for StubInboundProvider {
        fn get_inbound_with_um(&self, tag: &str) -> Option<Arc<dyn InboundHandlerWithUserManager>> {
            self.handlers.lock().iter().find(|h| h.tag() == tag).cloned()
        }

        fn get_inbound(&self, tag: &str) -> Option<Arc<dyn InboundHandler>> {
            self.handlers
                .lock()
                .iter()
                .find(|h| h.tag() == tag)
                .cloned()
                .map(|h| h as Arc<dyn InboundHandler>)
        }

        fn list_inbound_tags(&self) -> Vec<(String, Option<String>, String)> {
            self.handlers
                .lock()
                .iter()
                .map(|h| (h.tag().to_string(), None, h.proxy_type_url().to_string()))
                .collect()
        }
    }

    fn make_service_with_inbound(
        h: Arc<dyn InboundHandlerWithUserManager>,
    ) -> DefaultHandlerService {
        let provider = Arc::new(StubInboundProvider { handlers: Mutex::new(vec![h]) });
        DefaultHandlerService { inbound_provider: Some(provider), ..Default::default() }
    }

    #[test]
    fn get_inbound_users_returns_all_when_email_empty() {
        let h = make_stub_inbound("in");
        h.um.add_user(MemoryUser { email: "a@x.com".to_string(), level: 0 }).unwrap();
        h.um.add_user(MemoryUser { email: "b@x.com".to_string(), level: 0 }).unwrap();
        let svc = make_service_with_inbound(h.clone());
        let resp = svc
            .get_inbound_users(GetInboundUserRequest {
                tag: "in".to_string(),
                email: String::new(),
            })
            .unwrap();
        assert_eq!(resp.users.len(), 2);
    }

    #[test]
    fn get_inbound_users_single_when_email_set() {
        let h = make_stub_inbound("in");
        h.um.add_user(MemoryUser { email: "x@x.com".to_string(), level: 0 }).unwrap();
        let svc = make_service_with_inbound(h.clone());
        let resp = svc
            .get_inbound_users(GetInboundUserRequest {
                tag: "in".to_string(),
                email: "x@x.com".to_string(),
            })
            .unwrap();
        assert_eq!(resp.users.len(), 1);
        assert_eq!(resp.users[0].email, "x@x.com");
    }

    #[test]
    fn get_inbound_users_count() {
        let h = make_stub_inbound("in");
        h.um.add_user(MemoryUser { email: "1".to_string(), level: 0 }).unwrap();
        h.um.add_user(MemoryUser { email: "2".to_string(), level: 0 }).unwrap();
        let svc = make_service_with_inbound(h);
        let resp = svc
            .get_inbound_users_count(GetInboundUserRequest {
                tag: "in".to_string(),
                email: String::new(),
            })
            .unwrap();
        assert_eq!(resp.count, 2);
    }

    #[test]
    fn list_inbounds_returns_tag_per_handler() {
        let h1 = make_stub_inbound("a");
        let h2 = make_stub_inbound("b");
        let provider = Arc::new(StubInboundProvider {
            handlers: Mutex::new(vec![
                h1.clone() as Arc<dyn InboundHandlerWithUserManager>,
                h2.clone() as Arc<dyn InboundHandlerWithUserManager>,
            ]),
        });
        let svc = DefaultHandlerService { inbound_provider: Some(provider), ..Default::default() };
        let resp = svc.list_inbounds(ListInboundsRequest { is_only_tags: true }).unwrap();
        assert_eq!(resp.inbounds.len(), 2);
        let tags: Vec<String> = resp.inbounds.into_iter().map(|c| c.tag).collect();
        assert!(tags.contains(&"a".to_string()));
        assert!(tags.contains(&"b".to_string()));
    }

    #[test]
    fn list_inbounds_without_provider_errors() {
        let svc = DefaultHandlerService::default();
        match svc.list_inbounds(ListInboundsRequest::default()) {
            Err(ProxymanError::Other(_)) => (),
            Err(e) => panic!("expected Other, got: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn remove_inbound_unknown_returns_handler_not_found() {
        let h = make_stub_inbound("a");
        let svc = make_service_with_inbound(h);
        match svc.remove_inbound(RemoveInboundRequest { tag: "ghost".to_string() }) {
            Err(ProxymanError::HandlerNotFound(t)) => assert_eq!(t, "ghost"),
            Err(e) => panic!("expected HandlerNotFound, got: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn add_inbound_always_returns_other_todo() {
        let svc = DefaultHandlerService::default();
        match svc.add_inbound(AddInboundRequest::default()) {
            Err(ProxymanError::Other(_)) => (),
            Err(e) => panic!("expected Other, got: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn alter_inbound_without_decoder_errors() {
        let h = make_stub_inbound("a");
        let svc = make_service_with_inbound(h);
        let mut req = AlterInboundRequest::default();
        req.tag = "a".to_string();
        req.operation = Some(xray_proto::xray::common::serial::TypedMessage::default());
        match svc.alter_inbound(req) {
            Err(ProxymanError::Other(_)) => (),
            Err(e) => panic!("expected Other, got: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    // ========== remove/list 完整测试 ==========

    struct StubInboundRemover {
        removed: Mutex<Vec<String>>,
    }
    impl InboundRemover for StubInboundRemover {
        fn remove_inbound_handler(&self, tag: &str) -> Result<(), ProxymanError> {
            self.removed.lock().push(tag.to_string());
            Ok(())
        }
    }

    struct StubOutboundRemover {
        removed: Mutex<Vec<String>>,
    }
    impl OutboundRemover for StubOutboundRemover {
        fn remove_outbound_handler(&self, tag: &str) -> Result<(), ProxymanError> {
            self.removed.lock().push(tag.to_string());
            Ok(())
        }
    }

    #[test]
    fn remove_inbound_calls_remover_when_set() {
        let h = make_stub_inbound("in1");
        let remover = Arc::new(StubInboundRemover { removed: Mutex::new(vec![]) });
        let svc = DefaultHandlerService {
            inbound_provider: Some(Arc::new(StubInboundProvider {
                handlers: Mutex::new(vec![h.clone()]),
            })),
            inbound_remover: Some(remover.clone()),
            ..Default::default()
        };
        svc.remove_inbound(RemoveInboundRequest { tag: "in1".into() }).unwrap();
        assert_eq!(remover.removed.lock().len(), 1);
        assert_eq!(remover.removed.lock()[0], "in1");
    }

    #[test]
    fn remove_inbound_succeeds_without_remover() {
        // 无 remover 时仍返回 Ok（兼容只校验存在的场景）
        let h = make_stub_inbound("in2");
        let svc = make_service_with_inbound(h);
        svc.remove_inbound(RemoveInboundRequest { tag: "in2".into() }).unwrap();
    }

    #[test]
    fn list_inbounds_full_config_when_not_only_tags() {
        let h = make_stub_inbound("full");
        let svc = DefaultHandlerService {
            inbound_provider: Some(Arc::new(StubInboundProvider {
                handlers: Mutex::new(vec![h.clone()]),
            })),
            ..Default::default()
        };
        let resp = svc.list_inbounds(ListInboundsRequest { is_only_tags: false }).unwrap();
        assert_eq!(resp.inbounds.len(), 1);
        let cfg = &resp.inbounds[0];
        assert_eq!(cfg.tag, "full");
        // proxy_settings 应被填充
        assert!(cfg.proxy_settings.is_some());
        assert_eq!(cfg.proxy_settings.as_ref().unwrap().r#type, "xray.test");
    }

    #[test]
    fn list_inbounds_only_tags_when_requested() {
        let h = make_stub_inbound("tagonly");
        let svc = DefaultHandlerService {
            inbound_provider: Some(Arc::new(StubInboundProvider {
                handlers: Mutex::new(vec![h.clone()]),
            })),
            ..Default::default()
        };
        let resp = svc.list_inbounds(ListInboundsRequest { is_only_tags: true }).unwrap();
        assert_eq!(resp.inbounds.len(), 1);
        assert!(resp.inbounds[0].proxy_settings.is_none());
        assert!(resp.inbounds[0].receiver_settings.is_none());
    }

    // ========== Outbound 测试 ==========

    struct StubOutboundHandler {
        tag: String,
    }
    impl crate::outbound::OutboundHandler for StubOutboundHandler {
        fn tag(&self) -> &str {
            &self.tag
        }

        fn start(&self) -> crate::inbound::PinFuture<Result<(), ProxymanError>> {
            Box::pin(async { Ok(()) })
        }

        fn close(&self) -> crate::inbound::PinFuture<Result<(), ProxymanError>> {
            Box::pin(async { Ok(()) })
        }

        fn sender_type_url(&self) -> Option<&str> {
            Some("sender_url")
        }

        fn proxy_type_url(&self) -> &str {
            "xray.test.outbound"
        }

        fn dispatch(
            &self,
            _session: xray_common::session::Session,
            _link: xray_transport::link::Link,
        ) -> crate::inbound::PinFuture<Result<(), ProxymanError>> {
            Box::pin(async { Ok(()) })
        }

        fn dial(
            &self,
            _dest: &xray_common::net::destination::Destination,
        ) -> crate::inbound::PinFuture<
            std::io::Result<Box<dyn xray_transport::connection::Connection>>,
        > {
            Box::pin(async { Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "stub")) })
        }
    }

    struct StubOutboundProvider {
        handlers: Mutex<Vec<Arc<StubOutboundHandler>>>,
    }
    impl OutboundHandlerProvider for StubOutboundProvider {
        fn get_outbound_with_um(
            &self,
            tag: &str,
        ) -> Option<Arc<dyn OutboundHandlerWithUserManager>> {
            None
        }

        fn get_outbound(&self, tag: &str) -> Option<Arc<dyn crate::outbound::OutboundHandler>> {
            self.handlers
                .lock()
                .iter()
                .find(|h| h.tag() == tag)
                .cloned()
                .map(|h| h as Arc<dyn crate::outbound::OutboundHandler>)
        }

        fn list_outbound_tags(&self) -> Vec<(String, Option<String>, String)> {
            self.handlers
                .lock()
                .iter()
                .map(|h| {
                    (h.tag().to_string(), Some("sender_url".into()), h.proxy_type_url().to_string())
                })
                .collect()
        }
    }

    #[test]
    fn remove_outbound_calls_remover_when_set() {
        let provider = Arc::new(StubOutboundProvider {
            handlers: Mutex::new(vec![Arc::new(StubOutboundHandler { tag: "out1".into() })]),
        });
        let remover = Arc::new(StubOutboundRemover { removed: Mutex::new(vec![]) });
        let svc = DefaultHandlerService {
            outbound_provider: Some(provider),
            outbound_remover: Some(remover.clone()),
            ..Default::default()
        };
        svc.remove_outbound(RemoveOutboundRequest { tag: "out1".into() }).unwrap();
        assert_eq!(remover.removed.lock().len(), 1);
        assert_eq!(remover.removed.lock()[0], "out1");
    }

    #[test]
    fn list_outbounds_returns_full_config() {
        let provider = Arc::new(StubOutboundProvider {
            handlers: Mutex::new(vec![Arc::new(StubOutboundHandler { tag: "out_full".into() })]),
        });
        let svc = DefaultHandlerService { outbound_provider: Some(provider), ..Default::default() };
        let resp = svc.list_outbounds(ListOutboundsRequest::default()).unwrap();
        assert_eq!(resp.outbounds.len(), 1);
        let cfg = &resp.outbounds[0];
        assert_eq!(cfg.tag, "out_full");
        assert!(cfg.sender_settings.is_some());
        assert_eq!(cfg.sender_settings.as_ref().unwrap().r#type, "sender_url");
        assert!(cfg.proxy_settings.is_some());
        assert_eq!(cfg.proxy_settings.as_ref().unwrap().r#type, "xray.test.outbound");
    }
}

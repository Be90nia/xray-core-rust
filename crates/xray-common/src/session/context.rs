//! 会话上下文 helper。
//!
//! 对应 Go 版本 `common/session/context.go`。Go 经 `context.WithValue` +
//! SessionKey 携带会话元数据；Rust 侧统一落在 [`super::Session`] 字段，
//! `ContextWithX` ↔ `Session::with_x` builder、`XFromContext` ↔ 字段读取。
//! 本模块存放 12 个 SessionKey 常量（编号对齐 Go）、3 个跨 crate trait
//! 与 5 个复合 helper。

use std::sync::Arc;

use super::{Outbound, Session};
use crate::{ctx::SessionKey, errors::Error, net::network::Network};

// ========== SessionKey 常量（Go context.go:16-29，编号逐一对齐） ==========

/// 入站元数据键。
pub const INBOUND_SESSION_KEY: SessionKey = SessionKey { id: 1 };
/// 出站元数据键。
pub const OUTBOUND_SESSION_KEY: SessionKey = SessionKey { id: 2 };
/// 内容元数据键。
pub const CONTENT_SESSION_KEY: SessionKey = SessionKey { id: 3 };
/// 反向 mux 标记键。
pub const IS_REVERSE_MUX_KEY: SessionKey = SessionKey { id: 4 };
/// dokodemo 仅接收 sockopt.Mark 的套接字选项键。
pub const SOCKOPT_SESSION_KEY: SessionKey = SessionKey { id: 5 };
/// observer 获取出站错误的 tracker 键。
pub const TRACKED_CONNECTION_ERROR_KEY: SessionKey = SessionKey { id: 6 };
/// ss2022 入站获取 dispatcher 的键。
pub const DISPATCHER_KEY: SessionKey = SessionKey { id: 7 };
/// mux 子上下文仅在自身流量超时才取消的标记键。
pub const TIMEOUT_ONLY_KEY: SessionKey = SessionKey { id: 8 };
/// muxcool 服务端控制请求允许网络类型的键。
pub const ALLOWED_NETWORK_KEY: SessionKey = SessionKey { id: 9 };
/// outbound 完整 handler 的键。
pub const FULL_HANDLER_KEY: SessionKey = SessionKey { id: 10 };
/// TLS dialer 用的 MITM ALPN http/1.1 标记键。
pub const MITM_ALPN11_KEY: SessionKey = SessionKey { id: 11 };
/// TLS dialer 用的 MITM 服务器名键。
pub const MITM_SERVER_NAME_KEY: SessionKey = SessionKey { id: 12 };

// ========== 跨 crate trait（session context 携带的运行时对象） ==========

/// Go `session.TrackedRequestErrorFeedback`（context.go:115-117）。
///
/// observer 实现本 trait 后经 [`Session::with_tracked_connection_error`] 挂到
/// session，出站侧经 [`Session::submit_outbound_error`] 回传错误。
pub trait TrackedRequestErrorFeedback: Send + Sync {
    /// 提交一处出站错误（Go `SubmitError(err error)`）。
    fn submit_error(&self, err: Error);
}

/// Go `routing.Dispatcher` 在 session 上下文中的最小占位面（context.go:130-139）。
///
/// 完整签名 `Dispatch(ctx, dest) -> transport::Link` 需引用 xray-transport
/// （xray-common 反向依赖，不可引）。下游 crate 对自有 dispatcher 实现本
/// trait 后经 [`Session::dispatcher`] 存取；`Any` supertrait 支持与 Go
/// `.(*proxyman.Handler)` 对应的具体类型下转。
///
/// ponytail: 纯 marker；ss2022 入站接线时再扩真实方法面。
pub trait SessionDispatcher: std::any::Any + Send + Sync {}

/// Go `outbound.Handler` 在 session 上下文中的最小占位面（context.go:163-172）。
///
/// Go 消费方（vless outbound）下转为 `*proxyman.Handler` 后调用 `Process`；
/// Rust 侧同样经 `Any` 下转，由下游持有具体类型。
///
/// ponytail: 纯 marker；下游接线时再扩真实方法面。
pub trait FullHandler: std::any::Any + Send + Sync {}

impl Session {
    /// 设置反向 mux 标记（Go `ContextWithIsReverseMux`，context.go:78-80）。
    pub fn with_is_reverse_mux(mut self, is_reverse_mux: bool) -> Self {
        self.is_reverse_mux = is_reverse_mux;
        self
    }

    /// 设置 timeout-only 标记（Go `ContextWithTimeoutOnly`，context.go:141-143）。
    pub fn with_timeout_only(mut self, timeout_only: bool) -> Self {
        self.timeout_only = timeout_only;
        self
    }

    /// 设置允许的网络类型（Go `ContextWithAllowedNetwork`，context.go:152-154）。
    pub fn with_allowed_network(mut self, network: Network) -> Self {
        self.allowed_network = Some(network);
        self
    }

    /// 设置 MITM ALPN http/1.1 标记（Go `ContextWithMitmAlpn11`，context.go:174-176）。
    pub fn with_mitm_alpn11(mut self, alpn11: bool) -> Self {
        self.mitm_alpn11 = alpn11;
        self
    }

    /// 设置 MITM 服务器名（Go `ContextWithMitmServerName`，context.go:185-187）。
    pub fn with_mitm_server_name(mut self, server_name: impl Into<String>) -> Self {
        self.mitm_server_name = server_name.into();
        self
    }

    /// 挂 dispatcher（Go `ContextWithDispatcher`，context.go:130-132）。
    pub fn with_dispatcher(mut self, dispatcher: Arc<dyn SessionDispatcher>) -> Self {
        self.dispatcher = Some(dispatcher);
        self
    }

    /// 挂完整 outbound handler（Go `ContextWithFullHandler`，context.go:163-165）。
    pub fn with_full_handler(mut self, handler: Arc<dyn FullHandler>) -> Self {
        self.full_handler = Some(handler);
        self
    }

    /// 挂出站错误 tracker（Go `TrackedConnectionError`，context.go:126-128）。
    pub fn with_tracked_connection_error(
        mut self,
        tracker: Arc<dyn TrackedRequestErrorFeedback>,
    ) -> Self {
        self.error_tracker = Some(tracker);
        self
    }

    /// 读 forced outbound tag（Go `GetForcedOutboundTagFromContext`，context.go:100-105）。
    ///
    /// 无值时返回空串（Go 语义）。
    pub fn forced_outbound_tag(&self) -> &str {
        self.content.attributes.get("forcedOutboundTag").map(|s| s.as_str()).unwrap_or("")
    }

    /// 写 forced outbound tag（Go `SetForcedOutboundTagToContext`，context.go:107-113）。
    ///
    /// Go 在 ctx 无 Content 时先挂空 Content；Rust Session 恒有 content，直接写。
    pub fn set_forced_outbound_tag(&mut self, tag: impl AsRef<str>) {
        self.content.attributes.insert("forcedOutboundTag".to_string(), tag.as_ref().to_string());
    }

    /// 向请求发起方回传出站错误（Go `SubmitOutboundErrorToOriginator`，context.go:119-124）。
    ///
    /// 无 tracker 时 no-op（Go 语义）。
    pub fn submit_outbound_error(&self, err: Error) {
        if let Some(tracker) = &self.error_tracker {
            tracker.submit_error(err);
        }
    }

    /// 构造 mux 入站的子上下文（Go `SubContextFromMuxInbound`，context.go:46-58）。
    ///
    /// 复制本 session，重置 outbound（Go `[]*Outbound{{}}`，Rust 单字段等价
    /// `Outbound::new()`），content 保留浅拷贝。Go 在 content 已带属性时
    /// panic（mux 子上下文不允许继承嗅探属性），Rust 以 assert 等价对齐。
    pub fn sub_context_from_mux_inbound(&self) -> Session {
        assert!(self.content.attributes.is_empty(), "content.Attributes != nil");
        let mut sub = self.clone();
        sub.outbound = Outbound::new();
        sub
    }
}

#[cfg(test)]
mod tests {
    use parking_lot::Mutex;

    use super::*;

    /// 记录型 tracker，验证错误回传。
    #[derive(Default)]
    struct Recorder(Mutex<Vec<String>>);

    impl TrackedRequestErrorFeedback for Recorder {
        fn submit_error(&self, err: Error) {
            self.0.lock().push(err.to_string());
        }
    }

    /// 带标签的假 dispatcher，验证 Any 下转。
    struct FakeDispatcher {
        tag: String,
    }

    impl SessionDispatcher for FakeDispatcher {}

    /// 带标签的假 full handler，验证 Any 下转。
    struct FakeFullHandler {
        tag: String,
    }

    impl FullHandler for FakeFullHandler {}

    #[test]
    fn test_session_key_constants_match_go() {
        // Go context.go:16-29 的编号 1-12，逐一对齐。
        assert_eq!(INBOUND_SESSION_KEY, SessionKey::new(1));
        assert_eq!(OUTBOUND_SESSION_KEY, SessionKey::new(2));
        assert_eq!(CONTENT_SESSION_KEY, SessionKey::new(3));
        assert_eq!(IS_REVERSE_MUX_KEY, SessionKey::new(4));
        assert_eq!(SOCKOPT_SESSION_KEY, SessionKey::new(5));
        assert_eq!(TRACKED_CONNECTION_ERROR_KEY, SessionKey::new(6));
        assert_eq!(DISPATCHER_KEY, SessionKey::new(7));
        assert_eq!(TIMEOUT_ONLY_KEY, SessionKey::new(8));
        assert_eq!(ALLOWED_NETWORK_KEY, SessionKey::new(9));
        assert_eq!(FULL_HANDLER_KEY, SessionKey::new(10));
        assert_eq!(MITM_ALPN11_KEY, SessionKey::new(11));
        assert_eq!(MITM_SERVER_NAME_KEY, SessionKey::new(12));
    }

    #[test]
    fn test_context_defaults() {
        // Go 各 FromContext 的缺省：false / Network_Unknown / "" / nil。
        let s = Session::new();
        assert!(!s.is_reverse_mux);
        assert!(!s.timeout_only);
        assert_eq!(s.allowed_network, None);
        assert!(!s.mitm_alpn11);
        assert_eq!(s.mitm_server_name, "");
        assert!(s.dispatcher.is_none());
        assert!(s.full_handler.is_none());
        assert!(s.error_tracker.is_none());
    }

    #[test]
    fn test_with_helpers_roundtrip() {
        let s = Session::new()
            .with_is_reverse_mux(true)
            .with_timeout_only(true)
            .with_allowed_network(Network::UDP)
            .with_mitm_alpn11(true)
            .with_mitm_server_name("example.com");
        assert!(s.is_reverse_mux);
        assert!(s.timeout_only);
        assert_eq!(s.allowed_network, Some(Network::UDP));
        assert!(s.mitm_alpn11);
        assert_eq!(s.mitm_server_name, "example.com");

        // Clone 保持全部携带值。
        let cloned = s.clone();
        assert!(cloned.is_reverse_mux);
        assert_eq!(cloned.allowed_network, Some(Network::UDP));
        assert_eq!(cloned.mitm_server_name, "example.com");
    }

    #[test]
    fn test_forced_outbound_tag() {
        // 无值 → 空串（Go GetForcedOutboundTagFromContext 语义）。
        let mut s = Session::new();
        assert_eq!(s.forced_outbound_tag(), "");

        s.set_forced_outbound_tag("direct-out");
        assert_eq!(s.forced_outbound_tag(), "direct-out");
        // 底层落 content.attributes，与 Go 相同存储。
        assert_eq!(
            s.content.attributes.get("forcedOutboundTag").map(|x| x.as_str()),
            Some("direct-out")
        );
    }

    #[test]
    fn test_submit_outbound_error_records_via_tracker() {
        let recorder = Arc::new(Recorder::default());
        let s =
            Session::new().with_tracked_connection_error(
                recorder.clone() as Arc<dyn TrackedRequestErrorFeedback>
            );
        s.submit_outbound_error(Error::new("dial failed"));
        assert_eq!(recorder.0.lock().len(), 1);
        assert!(recorder.0.lock()[0].contains("dial failed"));
    }

    #[test]
    fn test_submit_outbound_error_noop_without_tracker() {
        // 无 tracker 时 no-op，不 panic（Go 语义）。
        Session::new().submit_outbound_error(Error::new("ignored"));
    }

    #[test]
    fn test_dispatcher_stored_and_downcast() {
        // Go 侧 DispatcherFromContext 拿到 interface 后按具体类型断言使用；
        // Rust 经 Any supertrait 下转，能力等价。
        let d = Arc::new(FakeDispatcher { tag: "ss2022".to_string() });
        let s = Session::new().with_dispatcher(d);
        let got = s.dispatcher.as_ref().expect("dispatcher stored");
        let down = (got.as_ref() as &dyn std::any::Any)
            .downcast_ref::<FakeDispatcher>()
            .expect("downcast to concrete");
        assert_eq!(down.tag, "ss2022");
    }

    #[test]
    fn test_full_handler_stored_and_downcast() {
        let h = Arc::new(FakeFullHandler { tag: "vless-out".to_string() });
        let s = Session::new().with_full_handler(h);
        let got = s.full_handler.as_ref().expect("full handler stored");
        let down = (got.as_ref() as &dyn std::any::Any)
            .downcast_ref::<FakeFullHandler>()
            .expect("downcast to concrete");
        assert_eq!(down.tag, "vless-out");
    }
    #[test]
    fn test_sub_context_from_mux_inbound() {
        use std::net::Ipv4Addr;

        use super::super::Content;
        use crate::net::{address::Address, destination::Destination, port::Port};

        let dest = Destination::tcp(Address::ipv4(Ipv4Addr::new(1, 2, 3, 4)), Port::new(443));

        let parent = Session::new()
            .with_content(Content::new().with_protocol("http/1.1"))
            .with_outbound(Outbound::new().with_target(dest));
        let parent_id = parent.id.clone();

        let sub = parent.sub_context_from_mux_inbound();

        // outbound 重置（Go []*Outbound{{}}）。
        assert!(sub.outbound.target.is_none());
        // content 浅拷贝保留。
        assert_eq!(sub.content.protocol.as_deref(), Some("http/1.1"));
        // 其余携带值继承（id 不变）。
        assert_eq!(sub.id, parent_id);
    }

    #[test]
    #[should_panic(expected = "content.Attributes != nil")]
    fn test_sub_context_panics_on_attributes() {
        let mut s = Session::new();
        s.set_forced_outbound_tag("boom");
        let _ = s.sub_context_from_mux_inbound();
    }
}

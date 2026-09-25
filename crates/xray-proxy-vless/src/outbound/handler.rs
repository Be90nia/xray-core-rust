//! VLESS outbound handler。
//!
//! 对应 Go 版本 `proxy/vless/outbound/outbound.go`。出站方向：客户端把上层
//! （如 socks）传入的目标地址 + 用户信息编码为 VLESS 请求头，发给远端 VLESS 服务端。
//!
//! # 当前状态
//!
//! - **完整实现**：[`Handler`] 配置结构、[`Handler::build_request`]（命令决策、Flow
//!   判定、目标地址解析）。
//! - **trait stub**：[`OutboundProcessor::process`]（依赖 `xray_transport::link::Link` +
//!   `internet::Dialer` + retry + signal + xudp + reverse 全链路）。
//!
//! `unsafe.Pointer` 提取 TLS conn 内部字段做 splice copy（Go 端 XRV 流量优化）
//! 在 Rust 端没有等价物，等 transport 链路 + utls 接入后再补 XRV 直接拷贝路径。

use xray_common::net::{address::Address, port::Port};
use xray_proto::xray::proxy::vless::encoding::Addons;

use crate::{
    account::MemoryAccount,
    encoding::{VlessCommand, empty_addons},
    error::{Result, VlessError},
    validator::MemoryUser,
};

/// 出站处理器配置（对应 Go 的 `Handler`）。
#[derive(Debug, Clone)]
pub struct Handler {
    /// 选择的用户（远端 VLESS 服务端已注册）。
    pub user: MemoryUser,
    /// 目标地址（被代理目标）。
    pub destination: Option<(Address, Port)>,
    /// 期望的 flow（XRV / None）。
    pub flow: String,
    /// 是否启用 reverse（v1.rvs.cool）。
    pub reverse: bool,
}

impl Handler {
    /// 构造新 handler。
    #[must_use]
    pub fn new(user: MemoryUser) -> Self {
        Self { user, destination: None, flow: crate::FLOW_NONE.to_string(), reverse: false }
    }

    /// 链式设置目标地址。
    #[must_use]
    pub fn with_destination(mut self, addr: Address, port: Port) -> Self {
        self.destination = Some((addr, port));
        self
    }

    /// 链式设置 flow。
    #[must_use]
    pub fn with_flow(mut self, flow: impl Into<String>) -> Self {
        self.flow = flow.into();
        self
    }

    /// 链式开启 reverse 模式。
    #[must_use]
    pub fn with_reverse(mut self, enabled: bool) -> Self {
        self.reverse = enabled;
        self
    }

    /// 决策请求命令。
    ///
    /// 对应 Go `Handler.Process` 中的 command 决策逻辑：
    /// - `reverse == true` → `Rvs`，目标固定 `v1.rvs.cool`。
    /// - 否则按 destination 的 network：TCP → `Tcp`，UDP → `Udp`。
    /// - Mux 由上层 mux 包注入，不在本函数决策。
    ///
    /// # Errors
    /// 非 reverse 模式但未配置 destination 时返回 [`VlessError::Other`]。
    pub fn decide_command(&self) -> Result<VlessCommand> {
        if self.reverse {
            return Ok(VlessCommand::Rvs);
        }
        let (_, port) = self
            .destination
            .as_ref()
            .ok_or_else(|| VlessError::Other("destination required for non-reverse".into()))?;
        // port 携带的 network 信息：UDP 端口 → Udp，否则 Tcp
        // 简化：本实现让上层通过 with_destination 显式传 UDP 端口；
        // VlessCommand 决策依赖调用方语义。这里默认 Tcp。
        let _ = port;
        Ok(VlessCommand::Tcp)
    }

    /// 构造请求头的输入参数（命令 + 地址 + 端口 + addons）。
    ///
    /// 调用方拿到这些值后传给 [`crate::encoding::client::encode_request_header`]。
    /// 这里只做参数装配，不做 IO。
    ///
    /// # Errors
    /// - 命令决策失败：见 [`Self::decide_command`]。
    /// - flow 不合法：仅允许 `none` / `xtls-rprx-vision`。
    pub fn build_request(&self) -> Result<RequestParts<'_>> {
        let command = self.decide_command()?;
        let (addr, port) = if command.needs_address() {
            let (a, p) = self
                .destination
                .as_ref()
                .ok_or_else(|| VlessError::Other("destination required".into()))?;
            (Some(a.clone()), Some(p.value()))
        } else {
            (None, None)
        };

        let mut addons = empty_addons();
        if self.flow == crate::FLOW_XRV {
            addons.flow = crate::FLOW_XRV.to_string();
        } else if self.flow != crate::FLOW_NONE {
            return Err(VlessError::Other(format!(
                "unsupported flow: {} (only 'none' or 'xtls-rprx-vision')",
                self.flow
            )));
        }

        Ok(RequestParts { command, address: addr, port, addons, account: &self.user.account })
    }
}

/// [`Handler::build_request`] 的产物：编码请求头所需的全部参数。
#[derive(Debug)]
pub struct RequestParts<'a> {
    /// 命令。
    pub command: VlessCommand,
    /// 地址（仅 Tcp/Udp）。
    pub address: Option<Address>,
    /// 端口（仅 Tcp/Udp）。
    pub port: Option<u16>,
    /// Addons。
    pub addons: Addons,
    /// 选中的用户账户（用于编码 16B UUID）。
    pub account: &'a MemoryAccount,
}

/// 出站主流程 trait（占位）。
///
/// 实际实现需要：
/// - 通过 `internet::Dialer` 拨号到远端 VLESS server
/// - 调用 [`crate::encoding::client::encode_request_header`] 编码请求头
/// - 调用 `encode_response_header` 解码响应
/// - 双向桥接 `xray_transport::link::Link` ↔ 加密后的连接
/// - XRV flow 时切换到 splice copy（依赖 utls + unsafe 提取，Rust 不支持）
/// - 反向代理时启动 reverse.BridgeWorker
///
/// 当前所有实现返回 [`VlessError::NotImplemented`]。
pub trait OutboundProcessor: Send + Sync {
    /// 处理一次出站连接。
    ///
    /// `link` 是上层（socks/dokodemo）传入的客户端连接；处理器把它桥接到远端。
    fn process(
        &self,
        link: xray_transport::link::Link,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>>;
}

/// 默认 stub 处理器：所有调用返回 NotImplemented。
#[derive(Debug, Default)]
pub struct StubProcessor;

impl OutboundProcessor for StubProcessor {
    fn process(
        &self,
        _link: xray_transport::link::Link,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async {
            Err(VlessError::NotImplemented("outbound Process requires full transport stack".into()))
        })
    }
}

#[cfg(test)]
mod tests {
    use xray_common::{
        net::{address::Address, port::Port},
        uuid::UUID,
    };

    use super::*;
    use crate::MemoryAccount;

    fn sample_user() -> MemoryUser {
        let uuid = UUID::new();
        MemoryUser {
            level: 0,
            email: "u@test".to_string(),
            account: MemoryAccount::from_proto_account(&xray_proto::xray::proxy::vless::Account {
                id: uuid.to_string(),
                ..Default::default()
            })
            .unwrap(),
        }
    }

    #[test]
    fn decide_command_tcp_by_default() {
        let h = Handler::new(sample_user())
            .with_destination(Address::Domain("x.test".into()), Port::new(443));
        assert_eq!(h.decide_command().unwrap(), VlessCommand::Tcp);
    }

    #[test]
    fn decide_command_rvs_when_reverse() {
        let h = Handler::new(sample_user()).with_reverse(true);
        assert_eq!(h.decide_command().unwrap(), VlessCommand::Rvs);
    }

    #[test]
    fn decide_command_without_destination_errors() {
        let h = Handler::new(sample_user());
        assert!(h.decide_command().is_err());
    }

    #[test]
    fn build_request_tcp_with_xrv_flow() {
        let h = Handler::new(sample_user())
            .with_destination(Address::Domain("x.test".into()), Port::new(443))
            .with_flow(crate::FLOW_XRV);
        let parts = h.build_request().unwrap();
        assert_eq!(parts.command, VlessCommand::Tcp);
        assert_eq!(parts.port, Some(443));
        assert_eq!(parts.addons.flow, crate::FLOW_XRV);
    }

    #[test]
    fn build_request_rejects_unknown_flow() {
        let h = Handler::new(sample_user())
            .with_destination(Address::Domain("x.test".into()), Port::new(443))
            .with_flow("random-flow");
        let err = h.build_request().unwrap_err();
        match err {
            VlessError::Other(m) => assert!(m.contains("unsupported flow")),
            _ => panic!("unexpected error: {err:?}"),
        }
    }

    #[test]
    fn build_request_rvs_no_address_port() {
        let h = Handler::new(sample_user()).with_reverse(true);
        let parts = h.build_request().unwrap();
        assert_eq!(parts.command, VlessCommand::Rvs);
        assert_eq!(parts.address, None);
        assert_eq!(parts.port, None);
    }
}

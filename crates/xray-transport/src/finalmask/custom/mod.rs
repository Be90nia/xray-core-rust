//! # Custom 表达式引擎（对应 Go `finalmask/header/custom/`）
//!
//! TCP / UDP 自定义字节序列模板：用户在配置中声明一组 `Item`，
//! 通过 17 个表达式操作符生成握手/校验字节。握手成功后进入透传。
//!
//! 子模块：
//! - `evaluator`：表达式 / 类型 / measure / matchUDPItems
//! - `state`：per-key TTL 状态存储
//! - `tcp`：TCP bridge + 握手
//! - `udp`：UdpCustomClient / UdpCustomServer

pub(crate) mod evaluator;
pub(crate) mod state;
pub(crate) mod tcp;
pub(crate) mod udp;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use crate::finalmask::{AsyncIo, Tcpmask, UdpIo, Udpmask};

pub use evaluator::{EvalContext, EvalValue, Expr, ExprArg};

/// TCP 单个 item：一次 write/read 单元。
#[derive(Debug, Clone, Default)]
pub struct TCPItem {
    /// 延迟下限（毫秒）；当 `delay_max > 0` 时触发 flush + sleep。
    pub delay_min: i64,
    /// 延迟上限（毫秒）；> 0 时启用 rand 延迟。
    pub delay_max: i64,
    /// > 0 时随机字节长度（item 取随机数据）。
    pub rand: i32,
    /// 随机字节下限。
    pub rand_min: u8,
    /// 随机字节上限。
    pub rand_max: u8,
    /// 字面量 packet（与 `rand`/`var`/`expr` 互斥优先级）。
    pub packet: Vec<u8>,
    /// 求值结果写入 ctx.vars[save]。
    pub save: String,
    /// 引用 ctx.vars[var]。
    pub var: String,
    /// 表达式节点。
    pub expr: Option<Expr>,
}

/// TCP 序列：item 列表，顺序执行。
#[derive(Debug, Clone, Default)]
pub struct TCPSequence {
    pub sequence: Vec<TCPItem>,
}

/// TCP 配置：clients/servers/errors 三组序列。
#[derive(Debug, Clone, Default)]
pub struct TCPConfig {
    /// 客户端发送、服务端读取的序列。
    pub clients: Vec<TCPSequence>,
    /// 服务端发送、客户端读取的序列。
    pub servers: Vec<TCPSequence>,
    /// 服务端在 clients[i] 校验失败时发送的错误序列。
    pub errors: Vec<TCPSequence>,
}

/// UDP 单个 item：datagram 头部的一个生成/匹配单元。
#[derive(Debug, Clone, Default)]
pub struct UDPItem {
    pub rand: i32,
    pub rand_min: u8,
    pub rand_max: u8,
    pub packet: Vec<u8>,
    pub save: String,
    pub var: String,
    pub expr: Option<Expr>,
}

/// UDP 配置：client（请求 header）+ server（响应 header）。
#[derive(Debug, Clone, Default)]
pub struct UDPConfig {
    /// 客户端发送时求值；服务端接收时匹配。
    pub client: Vec<UDPItem>,
    /// 服务端发送时求值；客户端接收时匹配。
    pub server: Vec<UDPItem>,
}

/// 顶层 Config：组合 TCP/UDP/Standalone + 共享 state_ttl。
#[derive(Debug, Clone)]
pub struct Config {
    pub tcp: Option<TCPConfig>,
    pub udp: Option<UDPConfig>,
    /// TODO rpn-future：UDPStandaloneConfig 尚未实现。
    pub udp_standalone: Option<UDPConfig>,
    /// per-key state TTL，默认 5s。
    pub state_ttl: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tcp: None,
            udp: None,
            udp_standalone: None,
            state_ttl: Duration::from_secs(5),
        }
    }
}

impl Tcpmask for Config {
    fn wrap_conn_client(&self, raw: Box<dyn AsyncIo>) -> io::Result<Box<dyn AsyncIo>> {
        let (client, server) = tokio::io::duplex(crate::finalmask::UDP_SIZE * 2);
        let tcp_cfg = self.tcp.clone().unwrap_or_default();
        let state = Arc::new(state::StateStore::new(self.state_ttl));
        tokio::spawn(tcp::bridge(raw, server, true, tcp_cfg, state));
        Ok(Box::new(client))
    }

    fn wrap_conn_server(&self, raw: Box<dyn AsyncIo>) -> io::Result<Box<dyn AsyncIo>> {
        let (client, server) = tokio::io::duplex(crate::finalmask::UDP_SIZE * 2);
        let tcp_cfg = self.tcp.clone().unwrap_or_default();
        let state = Arc::new(state::StateStore::new(self.state_ttl));
        tokio::spawn(tcp::bridge(raw, server, false, tcp_cfg, state));
        Ok(Box::new(client))
    }
}

impl Udpmask for Config {
    fn wrap_packet_conn_client(
        &self,
        raw: Box<dyn UdpIo>,
        _level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        match &self.udp {
            Some(cfg) => Ok(Box::new(udp::UdpCustomClient::new(
                raw,
                cfg.clone(),
                self.state_ttl,
            )?)),
            None => Ok(raw),
        }
    }

    fn wrap_packet_conn_server(
        &self,
        raw: Box<dyn UdpIo>,
        _level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        match &self.udp {
            Some(cfg) => Ok(Box::new(udp::UdpCustomServer::new(
                raw,
                cfg.clone(),
                self.state_ttl,
            )?)),
            None => Ok(raw),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default_state_ttl_is_5s() {
        let c = Config::default();
        assert_eq!(c.state_ttl, Duration::from_secs(5));
        assert!(c.tcp.is_none());
        assert!(c.udp.is_none());
        assert!(c.udp_standalone.is_none());
    }

    #[test]
    fn config_clone_preserves_fields() {
        let c = Config {
            tcp: Some(TCPConfig::default()),
            udp: None,
            udp_standalone: None,
            state_ttl: Duration::from_secs(10),
        };
        let c2 = c.clone();
        assert!(c2.tcp.is_some());
        assert_eq!(c2.state_ttl, Duration::from_secs(10));
    }
}

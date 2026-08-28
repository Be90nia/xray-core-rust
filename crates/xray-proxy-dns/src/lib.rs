//! # xray-proxy-dns
//!
//! DNS 代理协议——拦截 DNS 查询，按规则决定动作（转发/丢弃/返回/劫持）。
//! 对应 Go `proxy/dns/dns.go`。
//!
//! ## 协议本质
//!
//! DNS 代理是 inbound 协议：接收 DNS 查询（UDP/TCP），按规则链匹配 qType + domain，
//! 执行对应动作（Direct 转发 / Drop 丢弃 / Return 返回空 / Hijack 重写到指定上游）。
//!
//! 切片边界（P6-5 切片1）
//!
//! 实现配置层 + [`config::DnsRule::match_q_type`] / [`config::DnsRule::apply`] 纯函数：
//! - [`config::Config`] / [`config::DnsRuleConfig`] / [`config::RuleAction`] — 配置层 + prost 双向
//! - [`config::DnsRule`] — 运行时规则 + qType 匹配
//!
//! 切片2 待办：domain 匹配（依赖 `geodata::DomainMatcher`）+ DNS 查询解析（dnsmessage）+
//! 上游转发（依赖 `features::dns::Client`）+ Handler::Init/Process + FakeDNS 集成。

pub mod config;
pub mod dns_message;
pub mod error;
pub mod handler;
pub mod inbound;
pub mod outbound;

// 顶层 re-export。
pub use config::{Config, DnsRule, DnsRuleConfig, RuleAction};
pub use dns_message::{DnsHeader, DnsQuestion, build_dns_response, build_ip_response, parse_dns_query};
pub use error::{DnsProxyError, Result};
pub use handler::{Handler, ProcessOutcome, QTYPE_A, QTYPE_AAAA, decode_tcp_dns_message, decide_action, encode_tcp_dns_message};
pub use inbound::DnsInbound;
pub use outbound::{DnsOutbound, forward_tcp_raw, forward_udp_raw, resolve_dest_socket_addr};

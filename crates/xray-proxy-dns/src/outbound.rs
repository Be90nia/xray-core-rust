//! DNS outbound——用 hickory-resolver 转发 DNS 查询到上游。
//!
//! 对应 Go `proxy/dns` 中调用 `dns.Client.Query` 的部分。
//! 接收 dispatcher 转发的 DNS 查询字节 → 解析 → 调用上游 resolver → 返回 DNS 响应字节。

use std::{net::IpAddr, time::Duration};

use async_trait::async_trait;
use hickory_resolver::{
    TokioResolver,
    config::{ConnectionConfig, NameServerConfig, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
    proto::op::{Message, OpCode, ResponseCode},
};
use xray_common::{net::destination::Destination, session::Session};
use xray_features::outbound::{OutboundError, OutboundHandler};

use crate::error::{DnsProxyError, Result};

/// DNS outbound——用 hickory-resolver 转发 DNS 查询。
///
/// 持有 [`TokioResolver`]（`Resolver<TokioRuntimeProvider>`）。dispatcher 调
/// [`process`](DnsOutbound::process) 转发 DNS 查询字节，返回上游的 DNS 响应字节。
pub struct DnsOutbound {
    tag: String,
    resolver: TokioResolver,
}

impl DnsOutbound {
    /// 用系统默认配置创建（读取 `/etc/resolv.conf` 或 Windows 注册表）。
    ///
    /// # Errors
    /// - [`DnsProxyError::UpstreamForwardFailed`]：resolver 初始化失败。
    pub fn new_system(tag: impl Into<String>) -> Result<Self> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|e| DnsProxyError::UpstreamForwardFailed(format!("init: {e}")))?
            .build()
            .map_err(|e| DnsProxyError::UpstreamForwardFailed(format!("build: {e}")))?;
        Ok(Self { tag: tag.into(), resolver })
    }

    /// 用自定义上游 DNS 服务器列表创建（测试 / Hijack 重写场景）。
    ///
    /// 每个元素是 `(IP, 端口)`。走 UDP。
    ///
    /// # Errors
    /// - [`DnsProxyError::UpstreamForwardFailed`]：resolver 构建失败。
    pub fn new_with_servers(tag: impl Into<String>, servers: &[(IpAddr, u16)]) -> Result<Self> {
        let name_servers: Vec<NameServerConfig> = servers
            .iter()
            .map(|(ip, port)| {
                let mut conn = ConnectionConfig::udp();
                conn.port = *port;
                NameServerConfig::new(*ip, false, vec![conn])
            })
            .collect();
        let cfg = ResolverConfig::from_parts(None, Vec::new(), name_servers);
        let resolver = TokioResolver::builder_with_config(cfg, TokioRuntimeProvider::default())
            .build()
            .map_err(|e| DnsProxyError::UpstreamForwardFailed(format!("build: {e}")))?;
        Ok(Self { tag: tag.into(), resolver })
    }

    /// 转发 DNS 查询字节到上游 → 返回 DNS 响应字节。
    ///
    /// 流程：`Message::from_vec` 解析 → 取第一个 query → `resolver.lookup` →
    /// `lookup.message()` 即完整 DNS 响应 → `to_vec` 序列化。
    ///
    /// # Errors
    /// - [`DnsProxyError::QueryParseFailed`]：查询不是合法 DNS 消息。
    /// - [`DnsProxyError::UpstreamForwardFailed`]：上游解析失败。
    /// - [`DnsProxyError::ResponseBuildFailed`]：响应序列化失败。
    pub async fn process(&self, query: &[u8]) -> Result<Vec<u8>> {
        let request = Message::from_vec(query)
            .map_err(|e| DnsProxyError::QueryParseFailed(format!("hickory: {e}")))?;

        // 无 query section → 返回 FORMERR(1) 空响应
        let Some(q) = request.queries.first() else {
            return error_response(request.id, ResponseCode::FormErr);
        };

        let name = q.name().clone();
        let rtype = q.query_type();
        let lookup = self
            .resolver
            .lookup(name, rtype)
            .await
            .map_err(|e| DnsProxyError::UpstreamForwardFailed(e.to_string()))?;
        // lookup.message() 是上游返回的完整 DNS Message（含 answers）。
        let response = lookup.message().clone().into_response();
        response.to_vec().map_err(|e| DnsProxyError::ResponseBuildFailed(e.to_string()))
    }
}

/// 构造 DNS 错误响应（指定 id + rcode）并序列化为字节。
fn error_response(id: u16, rcode: ResponseCode) -> Result<Vec<u8>> {
    Message::error_msg(id, OpCode::Query, rcode)
        .to_vec()
        .map_err(|e| DnsProxyError::ResponseBuildFailed(e.to_string()))
}

// ── 原样字节转发（Go outboundConn + Direct/ownLink 动作） ─────────────
/// 解析 Destination 为 SocketAddr（域名经系统解析）。公开供装配层复用。
pub async fn resolve_dest_socket_addr(
    dest: &Destination,
) -> std::result::Result<std::net::SocketAddr, String> {
    dest_to_socket_addr(dest).await
}

async fn dest_to_socket_addr(
    dest: &Destination,
) -> std::result::Result<std::net::SocketAddr, String> {
    use xray_common::net::address::Address;
    let port = dest.port().value();
    match dest.address() {
        Address::IPv4(v4) => Ok(std::net::SocketAddr::from((*v4, port))),
        Address::IPv6(v6) => Ok(std::net::SocketAddr::from((*v6, port))),
        Address::Domain(d) => tokio::net::lookup_host((d.as_str(), port))
            .await
            .map_err(|e| e.to_string())?
            .next()
            .ok_or_else(|| "no address resolved".to_string()),
    }
}

/// 原样转发 DNS 查询字节到上游（UDP 往返）。
///
/// 对应 Go `outboundConn` UDP 路径：query 原封不动发给上游（保留 EDNS0 /
/// 任意 qType），响应字节原样返回。每查询独立 socket。
///
/// # Errors
/// - [`DnsProxyError::UpstreamForwardFailed`]：拨号/转发/超时失败。
pub async fn forward_udp_raw(
    query: &[u8],
    dest: &Destination,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let addr =
        dest_to_socket_addr(dest).await.map_err(|e| DnsProxyError::UpstreamForwardFailed(e))?;
    let sock = tokio::net::UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
        .await
        .map_err(|e| DnsProxyError::UpstreamForwardFailed(format!("bind: {e}")))?;
    sock.connect(addr)
        .await
        .map_err(|e| DnsProxyError::UpstreamForwardFailed(format!("connect: {e}")))?;
    sock.send(query)
        .await
        .map_err(|e| DnsProxyError::UpstreamForwardFailed(format!("send: {e}")))?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(timeout, sock.recv(&mut buf))
        .await
        .map_err(|_| DnsProxyError::UpstreamForwardFailed("udp upstream timeout".into()))?
        .map_err(|e| DnsProxyError::UpstreamForwardFailed(format!("recv: {e}")))?;
    buf.truncate(n);
    Ok(buf)
}

/// 原样转发 DNS 查询字节到上游（TCP 长度前缀帧往返）。
///
/// 对应 Go `outboundConn` TCP 路径（`dns_proto.TCPWriter`/`NewTCPReader`）。
///
/// # Errors
/// - [`DnsProxyError::UpstreamForwardFailed`]：拨号/转发/超时失败。
/// - [`DnsProxyError::ResponseBuildFailed`]：query 超长。
pub async fn forward_tcp_raw(
    query: &[u8],
    dest: &Destination,
    timeout: Duration,
) -> Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addr =
        dest_to_socket_addr(dest).await.map_err(|e| DnsProxyError::UpstreamForwardFailed(e))?;
    let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| DnsProxyError::UpstreamForwardFailed("tcp upstream connect timeout".into()))?
        .map_err(|e| DnsProxyError::UpstreamForwardFailed(format!("connect: {e}")))?;
    let framed = crate::handler::encode_tcp_dns_message(query)?;
    stream
        .write_all(&framed)
        .await
        .map_err(|e| DnsProxyError::UpstreamForwardFailed(format!("write: {e}")))?;
    let mut len_buf = [0u8; 2];
    tokio::time::timeout(timeout, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| DnsProxyError::UpstreamForwardFailed("tcp upstream read timeout".into()))?
        .map_err(|e| DnsProxyError::UpstreamForwardFailed(format!("read len: {e}")))?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; len];
    tokio::time::timeout(timeout, stream.read_exact(&mut resp))
        .await
        .map_err(|_| DnsProxyError::UpstreamForwardFailed("tcp upstream read timeout".into()))?
        .map_err(|e| DnsProxyError::UpstreamForwardFailed(format!("read body: {e}")))?;
    Ok(resp)
}

#[async_trait]
impl OutboundHandler for DnsOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial(
        &self,
        _destination: &Destination,
        _session: &Session,
    ) -> std::result::Result<(), OutboundError> {
        // ponytail: DNS outbound 不走 dial 路径——dispatcher 直接调 process(query)。
        // trait 要求实现，dial 对 DNS 无实际语义。
        Ok(())
    }

    fn can_handle(&self, destination: &Destination) -> bool {
        // 仅处理 UDP 53 端口的标准 DNS 流量
        destination.is_udp() && destination.port().value() == 53
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn new_with_servers_builds_resolver() {
        let ob = DnsOutbound::new_with_servers("test", &[(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353)])
            .expect("build resolver");
        assert_eq!(ob.tag(), "test");
    }

    #[test]
    fn outbound_tag_round_trip() {
        let ob = DnsOutbound::new_with_servers("dns-out", &[]).expect("build");
        assert_eq!(ob.tag(), "dns-out");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn process_empty_query_returns_formerr() {
        // 空字节不是合法 DNS 消息 → QueryParseFailed
        let ob = DnsOutbound::new_with_servers("t", &[]).expect("build");
        let err = ob.process(&[]).await.unwrap_err();
        assert!(matches!(err, DnsProxyError::QueryParseFailed(_)));
    }
}

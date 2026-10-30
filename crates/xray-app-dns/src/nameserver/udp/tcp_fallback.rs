//! UDP 的 TCP 兜底（RFC 7766 §5）：UDP 通道仍截断（TC=1）时向同一上游再问一次。
//!
//! 触发条件与 EDNS0 重发门控留在 `udp.rs`（`finish_udp_response`），此处只放 TCP 侧
//! 机制（体量债 bd mz55l）。与 Go 的差异（Go `nameserver_udp.go` 无 TCP 分支）见
//! `udp.rs` 模块头。

use super::*;
use crate::dnscommon::tcp_frame::{self, FrameCtx};

impl UdpNameServer {
    /// UDP 仍截断（TC=1）后的 TCP 兜底（RFC 7766 §5）。
    ///
    /// 与 Go 的差异：Go `nameserver_udp.go` 无 TCP 分支。代价：命中兜底时多一次
    /// TCP 连接（握手 + 一次查询 RTT）。
    ///
    /// bd wxr6u：必须以 **TCP 网络位** 拨号——沿用 UDP 网络位会让 dispatcher 原样
    /// 交给 freedom，freedom 按 `dest.network()` 走 UDP 中继，把「2B 长度前缀 +
    /// DNS 报文」当 XUDP 帧解析 → 上游零 tcp-accept、兜底全废。
    ///
    /// bd 2iauj：兜底共享整条查询的绝对 `deadline`（不另起满额预算）。
    pub(super) async fn tcp_fallback_query(
        &self,
        fqdn: &str,
        record_type: RecordType,
        deadline: &BudgetDeadline,
    ) -> Result<IpRecord, DnsError> {
        let req_id = self.id_gen.next_id();
        let payload = build_dns_query(fqdn, record_type, req_id, &self.client_ip)?;
        let len_be = tcp_frame::len_prefix(&payload)?;

        // 网络位必须是 TCP（bd wxr6u）。
        let tcp_dest = Destination::tcp(self.dest.address().clone(), self.dest.port());
        let mut stream = deadline
            .timeout(crate::dial::connect_stream(
                &tcp_dest,
                self.resolver.as_ref(),
                self.query_timeout,
                "udp-tcp-fallback",
                self.force_local,
            ))
            .await
            .map_err(|_| {
                DnsError::WireFormat(format!(
                    "tcp fallback dial timeout after {:?}",
                    self.query_timeout
                ))
            })??;

        tcp_frame::write(&mut stream, &len_be, &payload, deadline, FrameCtx::UdpFallback).await?;
        let resp_buf = tcp_frame::read(&mut stream, deadline, FrameCtx::UdpFallback).await?;

        // 713x6：解析时刻取自注入时钟（CacheController P1-12 单钟语义）。
        let now = self.cache.clock().now_instant();
        let parsed = parse_dns_response(&resp_buf, req_id, record_type, now)?;
        // TCP 应答不应再截断；万一仍带 TC 位，按「答案即结果」取用（忽略 TC 标志）。
        Ok(parsed_to_ip_record(&parsed, now))
    }
}

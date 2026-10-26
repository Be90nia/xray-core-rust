//! # NAT-PMP 客户端（RFC 6886 最小子集；对应 Go `realm/portmap.go` 经 go-nat 的
//! NAT-PMP 后端）
//!
//! 只做 realm 需要的三件事：查公网 IPv4（op 0）、添加/续租 UDP 映射（op 1）、
//! 删除映射（op 1 + lifetime=0）。wire 编解码是纯函数（[`build_public_address_request`]
//! / [`build_mapping_request`] / [`parse_public_address_response`] /
//! [`parse_mapping_response`]），[`Client`] 只负责重传与超时；网关返回非 0 结果码
//! 一律 `Err`（带 RFC 6886 §3.5 文本），绝不静默当成功。

use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use tokio::{
    net::UdpSocket,
    time::{Instant, timeout_at},
};

/// NAT-PMP 网关端口（RFC 6886 §3：客户端发往「默认网关」的 5351）。
pub const NATPMP_PORT: u16 = 5351;

/// 协议版本（RFC 6886 只定义 0）。
const VERSION: u8 = 0;
/// op 0：公网地址请求。
const OP_PUBLIC_ADDRESS: u8 = 0;
/// op 1：UDP 映射请求（lifetime=0 即删除）。
const OP_MAP_UDP: u8 = 1;
/// 响应 opcode = 请求 opcode | 0x80。
const RESPONSE_FLAG: u8 = 0x80;
/// 报头长度：version + opcode + result(2) + epoch(4)。
const HEADER_LEN: usize = 8;
/// 映射请求/响应载荷长度：internal(2) + external(2) + lifetime(4)。
const MAP_PAYLOAD_LEN: usize = 8;
/// 响应读取缓冲（最大响应 = 8 + 8）。
const RESPONSE_BUF_LEN: usize = HEADER_LEN + MAP_PAYLOAD_LEN;
/// RFC 6886 §3.1：首包后 250ms 重传，逐次翻倍。
const RETRANSMIT_INITIAL: Duration = Duration::from_millis(250);
/// 单次请求重传上限（RFC 建议 9 次；realm 侧另有 timeout 硬约束，取 4 已覆盖丢包）。
const RETRANSMIT_MAX: u32 = 4;

/// 映射结果（RFC 6886 §3.4 响应载荷）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    /// 请求里的内部端口（网关原样回填）。
    pub internal_port: u16,
    /// 网关实际分配的外部端口。
    pub external_port: u16,
    /// 网关批准的租期（秒；0 = 映射已删除）。
    pub lifetime_secs: u32,
}

/// 构造公网地址请求（8 字节，无载荷）。
#[must_use]
pub fn build_public_address_request() -> Vec<u8> {
    build_request(OP_PUBLIC_ADDRESS, &[])
}

/// 构造 UDP 映射请求（`lifetime_secs == 0` 即删除该内部端口的映射）。
#[must_use]
pub fn build_mapping_request(
    internal_port: u16,
    external_port: u16,
    lifetime_secs: u32,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(MAP_PAYLOAD_LEN);
    payload.extend_from_slice(&internal_port.to_be_bytes());
    payload.extend_from_slice(&external_port.to_be_bytes());
    payload.extend_from_slice(&lifetime_secs.to_be_bytes());
    build_request(OP_MAP_UDP, &payload)
}

/// 请求报头 + 载荷（请求侧 result code 与 epoch 恒 0）。
fn build_request(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(HEADER_LEN + payload.len());
    packet.push(VERSION);
    packet.push(opcode);
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u32.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

/// 解析公网地址响应（op 128）。
pub fn parse_public_address_response(packet: &[u8]) -> io::Result<Ipv4Addr> {
    check_header(packet, OP_PUBLIC_ADDRESS)?;
    if packet.len() < HEADER_LEN + 4 {
        return Err(invalid("NAT-PMP public address response too short"));
    }
    Ok(Ipv4Addr::new(packet[8], packet[9], packet[10], packet[11]))
}

/// 解析映射响应（op 129）。
pub fn parse_mapping_response(packet: &[u8]) -> io::Result<Mapping> {
    check_header(packet, OP_MAP_UDP)?;
    if packet.len() < HEADER_LEN + MAP_PAYLOAD_LEN {
        return Err(invalid("NAT-PMP mapping response too short"));
    }
    Ok(Mapping {
        internal_port: u16::from_be_bytes([packet[8], packet[9]]),
        external_port: u16::from_be_bytes([packet[10], packet[11]]),
        lifetime_secs: u32::from_be_bytes([packet[12], packet[13], packet[14], packet[15]]),
    })
}

/// 校验报头（版本 / opcode / 结果码）；返回响应里的 epoch 秒数。
fn check_header(packet: &[u8], expected_opcode: u8) -> io::Result<u32> {
    if packet.len() < HEADER_LEN {
        return Err(invalid("NAT-PMP response too short"));
    }
    if packet[0] != VERSION {
        return Err(invalid(format!("NAT-PMP unsupported version {}", packet[0])));
    }
    let expected = expected_opcode | RESPONSE_FLAG;
    if packet[1] != expected {
        return Err(invalid(format!(
            "NAT-PMP opcode mismatch: want {expected}, got {}",
            packet[1]
        )));
    }
    let result = u16::from_be_bytes([packet[2], packet[3]]);
    if result != 0 {
        return Err(io::Error::other(format!(
            "NAT-PMP result code {result}: {}",
            result_code_text(result)
        )));
    }
    Ok(u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]))
}

/// RFC 6886 §3.5 结果码文本（非 0 即网关拒绝，调用方必须可见）。
fn result_code_text(code: u16) -> &'static str {
    match code {
        0 => "success",
        1 => "unsupported version",
        2 => "not authorized/refused",
        3 => "network failure",
        4 => "out of resources",
        5 => "unsupported opcode",
        _ => "unknown result code",
    }
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// NAT-PMP 网关客户端（绑定本机临时端口，请求/响应走同一 socket）。
///
/// socket 在构造时 `connect` 到网关：内核只向上投递**该网关地址:5351** 的应答，
/// 同 LAN 的伪造响应（含嗅探到源端口后的抢答）在 syscall 层被丢弃，不进解析器。
#[derive(Debug)]
pub struct Client {
    sock: UdpSocket,
    server: SocketAddrV4,
    timeout: Duration,
}

impl Client {
    /// 绑定临时端口并指向网关（`server` = 默认网关:5351）。
    pub async fn connect(server: SocketAddrV4, timeout: Duration) -> io::Result<Self> {
        if timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NAT-PMP: timeout must be greater than zero",
            ));
        }
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
        let sock = UdpSocket::bind(bind).await?;
        // 源过滤在连接层做：非网关的应答内核直接丢弃（不再逐包比对 peer）
        sock.connect(SocketAddr::V4(server)).await?;
        Ok(Self { sock, server, timeout })
    }

    /// 网关看到的公网 IPv4（op 0）。也用作「网关确实说 NAT-PMP」的探针。
    pub async fn external_address(&self) -> io::Result<Ipv4Addr> {
        self.exchange(build_public_address_request(), parse_public_address_response).await
    }

    /// 添加/续租 UDP 映射（op 1）；返回网关实际分配的外部端口与批准租期。
    pub async fn add_udp_mapping(
        &self,
        internal_port: u16,
        suggested_external_port: u16,
        lifetime_secs: u32,
    ) -> io::Result<Mapping> {
        if internal_port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NAT-PMP: internal port must not be zero",
            ));
        }
        let request = build_mapping_request(internal_port, suggested_external_port, lifetime_secs);
        self.exchange(request, parse_mapping_response).await
    }

    /// 删除 UDP 映射（op 1 + lifetime=0）。
    pub async fn delete_udp_mapping(
        &self,
        internal_port: u16,
        external_port: u16,
    ) -> io::Result<Mapping> {
        self.add_udp_mapping(internal_port, external_port, 0).await
    }

    /// 发一个请求并按 RFC 6886 §3.1 指数退避重传到 `timeout` 或重传上限。
    ///
    /// 收到无法解析的报文（含网关返回非 0 结果码）立即上抛——同一 socket 上
    /// 只会有网关的应答，把解析失败当「再等等」会掩盖网关拒绝对话。
    async fn exchange<T>(
        &self,
        request: Vec<u8>,
        parse: fn(&[u8]) -> io::Result<T>,
    ) -> io::Result<T> {
        let deadline = Instant::now() + self.timeout;
        let mut backoff = RETRANSMIT_INITIAL;
        let mut attempt: u32 = 0;
        let mut last_error: Option<io::Error> = None;
        let mut buf = [0u8; RESPONSE_BUF_LEN];
        loop {
            self.sock.send(&request).await?;
            attempt += 1;
            let round_end = (Instant::now() + backoff).min(deadline);
            match timeout_at(round_end, self.sock.recv(&mut buf)).await {
                // 超时或 ICMP 不可达（Windows 在网关不监听时报 ECONNRESET）= 本轮无应答
                Err(_elapsed) => {},
                Ok(Err(e)) => last_error = Some(e),
                Ok(Ok(n)) => return parse(&buf[..n]),
            }
            if attempt >= RETRANSMIT_MAX || Instant::now() >= deadline {
                let detail = match last_error {
                    Some(e) => format!(" (last socket error: {e})"),
                    None => String::new(),
                };
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "NAT-PMP: no response from {} after {attempt} attempt(s) in {:?}{detail}",
                        self.server, self.timeout
                    ),
                ));
            }
            backoff *= 2;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalmask::realm::portmap::test_support::NatPmpStub;

    /// 组一个网关响应报文。
    fn response(opcode: u8, code: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![VERSION, opcode | RESPONSE_FLAG];
        packet.extend_from_slice(&code.to_be_bytes());
        packet.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    #[test]
    fn public_address_request_is_eight_zero_bytes() {
        assert_eq!(build_public_address_request(), vec![0u8; 8]);
    }

    #[test]
    fn mapping_request_wire_fields() {
        let req = build_mapping_request(8080, 9090, 600);
        assert_eq!(
            req,
            vec![
                0x00, 0x01, // version + opcode(1 = map UDP)
                0x00, 0x00, // result code（请求恒 0）
                0x00, 0x00, 0x00, 0x00, // epoch（请求恒 0）
                0x1F, 0x90, // internal port 8080
                0x23, 0x82, // suggested external port 9090
                0x00, 0x00, 0x02, 0x58, // lifetime 600s
            ]
        );
        // 删除 = 同一请求 + lifetime 0
        let del = build_mapping_request(8080, 8080, 0);
        assert_eq!(&del[12..16], &[0, 0, 0, 0]);
    }

    #[test]
    fn parse_public_address_response_fields() {
        let packet = response(OP_PUBLIC_ADDRESS, 0, &[203, 0, 113, 7]);
        assert_eq!(parse_public_address_response(&packet).unwrap(), Ipv4Addr::new(203, 0, 113, 7));
    }

    #[test]
    fn parse_mapping_response_fields() {
        let packet = response(OP_MAP_UDP, 0, &[0x1F, 0x90, 0x11, 0xD7, 0x00, 0x00, 0x02, 0x58]);
        assert_eq!(
            parse_mapping_response(&packet).unwrap(),
            Mapping { internal_port: 8080, external_port: 4567, lifetime_secs: 600 }
        );
    }

    #[test]
    fn parse_result_code_is_fail_visible() {
        let packet = response(OP_MAP_UDP, 2, &[0u8; MAP_PAYLOAD_LEN]);
        let err = parse_mapping_response(&packet).unwrap_err();
        assert!(err.to_string().contains("result code 2"), "{err}");
        assert!(err.to_string().contains("not authorized"), "{err}");
    }

    /// 伪造应答（源地址不是网关）必须被丢：connect 的源过滤在内核做，
    /// 抢答者即便拿到客户端源端口也改写不了控制面。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forged_response_from_other_source_is_ignored() {
        // 网关保持静默（只记账），伪造应答从另一个 socket 投向客户端真实源端口
        let stub = NatPmpStub::spawn(|_| None).await;
        let client = Client::connect(stub.addr, Duration::from_millis(900)).await.expect("connect");
        let rogue = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind rogue");
        let forged = response(OP_PUBLIC_ADDRESS, 0, &[6, 6, 6, 6]);
        #[allow(clippy::disallowed_methods, reason = "测试：外部地址探测任务")]
        let probe = tokio::spawn(async move { client.external_address().await });
        let deadline = Instant::now() + Duration::from_millis(800);
        while Instant::now() < deadline {
            for peer in stub.peers() {
                let _ = rogue.send_to(&forged, peer).await;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let err = probe.await.expect("join").expect_err("forged source must not be accepted");
        assert!(err.to_string().contains("no response from"), "{err}");
        assert!(stub.request_count() > 0, "client must have retransmitted");
    }

    #[test]
    fn parse_rejects_wrong_version_opcode_and_short_packet() {
        let mut bad_version = response(OP_MAP_UDP, 0, &[0u8; MAP_PAYLOAD_LEN]);
        bad_version[0] = 1;
        assert!(parse_mapping_response(&bad_version).is_err());

        let wrong_op = response(OP_PUBLIC_ADDRESS, 0, &[0u8; MAP_PAYLOAD_LEN]);
        assert!(parse_mapping_response(&wrong_op).is_err());

        assert!(parse_mapping_response(&[0u8; 4]).is_err());
        assert!(parse_public_address_response(&response(OP_PUBLIC_ADDRESS, 0, &[1, 2])).is_err());
    }

    #[tokio::test]
    async fn client_public_address_roundtrip() {
        let stub = NatPmpStub::spawn(|req| {
            assert_eq!(req, build_public_address_request().as_slice());
            Some(response(OP_PUBLIC_ADDRESS, 0, &[203, 0, 113, 7]))
        })
        .await;
        let client = Client::connect(stub.addr, Duration::from_secs(10)).await.unwrap();
        let ip = client.external_address().await.unwrap();
        assert_eq!(ip, Ipv4Addr::new(203, 0, 113, 7));
        assert_eq!(stub.request_count(), 1);
    }

    #[tokio::test]
    async fn client_add_renew_delete_sequence() {
        // 网关第一次给 4567，续租时改给 4568（模拟外部端口漂移），删除回 lifetime 0。
        let stub = NatPmpStub::spawn(|req| {
            let lifetime = u32::from_be_bytes([req[12], req[13], req[14], req[15]]);
            if lifetime == 0 {
                return Some(response(OP_MAP_UDP, 0, &[req[8], req[9], 0x1F, 0x90, 0, 0, 0, 0]));
            }
            let external: u16 = if lifetime == 600 { 4567 } else { 4568 };
            let [hi, lo] = external.to_be_bytes();
            Some(response(
                OP_MAP_UDP,
                0,
                &[req[8], req[9], hi, lo, req[12], req[13], req[14], req[15]],
            ))
        })
        .await;
        let client = Client::connect(stub.addr, Duration::from_secs(10)).await.unwrap();

        let first = client.add_udp_mapping(8080, 8080, 600).await.unwrap();
        assert_eq!(first.external_port, 4567);
        assert_eq!(first.lifetime_secs, 600);

        let renewed = client.add_udp_mapping(8080, 8080, 300).await.unwrap();
        assert_eq!(renewed.external_port, 4568);
        assert_eq!(renewed.lifetime_secs, 300);

        let deleted = client.delete_udp_mapping(8080, 4568).await.unwrap();
        assert_eq!(deleted.lifetime_secs, 0);

        let requests = stub.requests();
        assert_eq!(requests.len(), 3);
        for req in &requests {
            assert_eq!(req[0], VERSION, "version byte");
            assert_eq!(req[1], OP_MAP_UDP, "opcode");
            assert_eq!(&req[2..8], &[0u8; 6], "request result/epoch must be zero");
            assert_eq!(u16::from_be_bytes([req[8], req[9]]), 8080, "internal port");
        }
        assert_eq!(
            u32::from_be_bytes([
                requests[0][12],
                requests[0][13],
                requests[0][14],
                requests[0][15]
            ]),
            600
        );
        assert_eq!(
            u32::from_be_bytes([
                requests[2][12],
                requests[2][13],
                requests[2][14],
                requests[2][15]
            ]),
            0
        );
    }

    #[tokio::test]
    async fn client_retransmits_when_first_packet_is_dropped() {
        let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen_stub = std::sync::Arc::clone(&seen);
        let stub = NatPmpStub::spawn(move |_req| {
            let n = seen_stub.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // 前两次丢弃，模拟网关忙/丢包
            (n >= 2).then(|| response(OP_PUBLIC_ADDRESS, 0, &[198, 51, 100, 9]))
        })
        .await;
        let client = Client::connect(stub.addr, Duration::from_secs(3)).await.unwrap();
        assert_eq!(client.external_address().await.unwrap(), Ipv4Addr::new(198, 51, 100, 9));
        assert!(
            stub.request_count() >= 3,
            "expected retransmissions, saw {}",
            stub.request_count()
        );
    }

    #[tokio::test]
    async fn client_timeout_is_reported() {
        let stub = NatPmpStub::spawn(|_req| None).await;
        let client = Client::connect(stub.addr, Duration::from_millis(300)).await.unwrap();
        let err = client.external_address().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(err.to_string().contains("no response"), "{err}");
    }
}

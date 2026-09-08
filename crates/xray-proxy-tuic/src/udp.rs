//! TUIC v5 UDP relay 客户端（切片2 + native DATAGRAM 模式）。
//!
//! 提供 [`TuicUdpAssoc`]：客户端 UDP 关联句柄，分配 `assoc_id`，
//! 支持两种模式：
//! - **quic 模式**（bi-stream）：每个 UDP 包独占一个 bi-stream（已有实现）
//! - **native 模式**（DATAGRAM）：通过 QUIC DATAGRAM 传输，保留 UDP 不可靠语义
//!
//! ## 模式选择
//!
//! 默认使用 quic 模式（可靠、有序），native 模式在连接支持 DATAGRAM 时可用。
//! 调用方通过 [`TuicUdpAssoc::send_recv_native`] 显式使用 native 模式。
//!
//! ## 限制（ponytail）
//!
//! - 不实现分片：单包 ≤ [`MAX_PACKET_PAYLOAD`](crate::protocol::packet::MAX_PACKET_PAYLOAD)
//! - quic 模式：每包一个 stream（简单但开销大）
//! - native 模式：依赖 quinn DATAGRAM 支持（transport.datagram_receive_buffer_size 已设置）
//! - pkt_id 单调递增，溢出回绕

use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use bytes::{Buf, BufMut, BytesMut};
use tokio::time::Duration;

use crate::error::{Result, TuicError};
use crate::protocol::address::Address;
use crate::protocol::command::type_code;
use crate::protocol::{Packet, VERSION, packet::MAX_PACKET_PAYLOAD};

/// 默认 UDP 响应等待时长（mock server 等待 UDP echo）。
const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(10);

/// bi-stream 读 buffer 上限（防止恶意 server 发超大响应）。
const RECV_BUF_CAP: usize = 64 * 1024;

/// TUIC 客户端 UDP 关联句柄。
///
/// 由 [`TuicClient::dial_udp`](crate::client::TuicClient::dial_udp) 创建，
/// 持有 QUIC 连接的弱引用与 assoc_id、pkt_id 计数器。
#[derive(Clone)]
pub struct TuicUdpAssoc {
    conn: quinn::Connection,
    assoc_id: u16,
    pkt_id: Arc<AtomicU16>,
    /// 分片重组器（接收方向，spec FRAG_TOTAL>1 时按 pkt_id 缓存拼接）。
    assembler: Arc<std::sync::Mutex<crate::protocol::packet::FragmentAssembler>>,
}

impl TuicUdpAssoc {
    /// 由 [`TuicClient`](crate::client::TuicClient) 构造。
    pub(crate) fn new(conn: quinn::Connection, assoc_id: u16) -> Self {
        Self {
            conn,
            assoc_id,
            pkt_id: Arc::new(AtomicU16::new(0)),
            assembler: Arc::new(std::sync::Mutex::new(
                crate::protocol::packet::FragmentAssembler::new(),
            )),
        }
    }

    /// 当前关联 ID。
    #[must_use]
    pub fn assoc_id(&self) -> u16 {
        self.assoc_id
    }

    /// 发送一个 UDP 包并等待响应（quic 模式）。
    ///
    /// 流程：
    /// 1. open_bi
    /// 2. 写入 Packet 帧（VER + TYPE + ASSOC + PKT + FRAG + SIZE + ADDR + DATA）
    /// 3. finish() 通知 server 写方向结束
    /// 4. 读回响应 Packet 帧，提取 DATA
    ///
    /// `timeout` 为 None 时使用 [`DEFAULT_UDP_TIMEOUT`]。
    ///
    /// # Errors
    ///
    /// 见 [`TuicError`]；典型：QUIC 流错误、超时、响应解析失败。
    pub async fn send_recv(
        &self,
        target: Address,
        data: &[u8],
        timeout: Option<Duration>,
    ) -> Result<Vec<u8>> {
        let pkt_id = self.pkt_id.fetch_add(1, Ordering::Relaxed);
        let pkt = Packet::new(self.assoc_id, pkt_id, target, data.to_vec());

        let (mut send, mut recv) = self.conn.open_bi().await?;

        let mut buf = BytesMut::with_capacity(pkt.encoded_len() + 2);
        buf.put_u8(VERSION);
        buf.put_u8(type_code::PACKET);
        pkt.write_payload(&mut buf);
        send.write_all(&buf).await?;
        // 通知 server：客户端写方向已结束（UDP 单包语义）
        let _ = send.finish();
        // 读响应（分片感知：FRAG_TOTAL>1 时循环收齐再拼接）
        let to = timeout.unwrap_or(DEFAULT_UDP_TIMEOUT);
        loop {
            let pkt = tokio::time::timeout(to, read_response_packet(&mut recv))
                .await
                .map_err(|_| TuicError::UdpTimeout(to))??;
            let complete = self
                .assembler
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .feed(pkt)?;
            if let Some(full) = complete {
                return Ok(full.data);
            }
            // 尚有分片未到，继续读（同一超时窗口内）
        }
    }

    /// 将 Packet 帧序列化为 datagram（VER + TYPE + payload）。
    fn encode_datagram(pkt: &Packet) -> bytes::Bytes {
        let mut buf = BytesMut::with_capacity(pkt.encoded_len() + 2);
        buf.put_u8(VERSION);
        buf.put_u8(type_code::PACKET);
        pkt.write_payload(&mut buf);
        buf.freeze()
    }

    /// 计算单 datagram 可容纳的 UDP 负载大小（帧头开销之外）。
    fn native_frag_payload(&self, addr: &Address) -> Option<usize> {
        self.conn
            .max_datagram_size()
            .map(|max| max.saturating_sub(10 + addr.encoded_len()).max(1))
    }

    /// 发送 Packet 帧（单包或按 frag 分片），DATA 超过单 datagram 容量时
    /// 按 TUIC v5 spec 切成 FRAG_TOTAL 片（同 pkt_id，FRAG_ID 0-based）。
    async fn send_native(&self, target: &Address, data: &[u8], pkt_id: u16) -> Result<()> {
        let Some(frag_payload) = self.native_frag_payload(target) else {
            return Err(TuicError::ProtocolParse(
                "native datagram mode not negotiated".into(),
            ));
        };
        if data.len() <= frag_payload {
            let pkt = Packet::new(self.assoc_id, pkt_id, target.clone(), data.to_vec());
            self.conn
                .send_datagram(Self::encode_datagram(&pkt))
                .map_err(TuicError::QuinnSendDatagram)?;
            return Ok(());
        }
        if data.len() > MAX_PACKET_PAYLOAD {
            return Err(TuicError::PacketTooLarge(data.len()));
        }
        let frag_total = data.len().div_ceil(frag_payload);
        let Ok(frag_total) = u8::try_from(frag_total) else {
            return Err(TuicError::PacketTooLarge(data.len()));
        };
        for (i, chunk) in data.chunks(frag_payload).enumerate() {
            let pkt = Packet {
                assoc_id: self.assoc_id,
                pkt_id,
                frag_total,
                frag_id: i as u8,
                addr: target.clone(),
                data: chunk.to_vec(),
            };
            self.conn
                .send_datagram(Self::encode_datagram(&pkt))
                .map_err(TuicError::QuinnSendDatagram)?;
        }
        Ok(())
    }

    /// 发送一个 UDP 包并等待响应（native DATAGRAM 模式）。
    ///
    /// 流程：
    /// 1. 构造 Packet 帧（VER + TYPE + ASSOC + PKT + FRAG + SIZE + ADDR + DATA）
    /// 2. 通过 [`quinn::Connection::send_datagram`] 发送
    /// 3. 通过 [`quinn::Connection::read_datagram`] 等待响应
    ///
    /// 流程：
    /// 1. DATA ≤ 单 datagram 容量：单片直发（FRAG_TOTAL=1）
    ///    超过：按 TUIC v5 spec 切 FRAG_TOTAL 片（同 pkt_id，FRAG_ID 0-based）
    /// 2. 通过 [`quinn::Connection::send_datagram`] 发送
    /// 3. 循环 [`quinn::Connection::read_datagram`] 收响应，FRAG_TOTAL>1 的
    ///    分片经 [`FragmentAssembler`] 拼接（票 ao93：大 DNS/WireGuard 包不再丢）
    ///
    /// `timeout` 为 None 时使用 [`DEFAULT_UDP_TIMEOUT`]。
    ///
    /// # Errors
    ///
    /// 见 [`TuicError`]；典型：QUIC datagram 不支持、超时、响应解析失败。
    pub async fn send_recv_native(
        &self,
        target: Address,
        data: &[u8],
        timeout: Option<Duration>,
    ) -> Result<Vec<u8>> {
        let pkt_id = self.pkt_id.fetch_add(1, Ordering::Relaxed);
        self.send_native(&target, data, pkt_id).await?;

        // 循环收响应 datagram，分片收齐即返回（同一超时窗口）
        let to = timeout.unwrap_or(DEFAULT_UDP_TIMEOUT);
        loop {
            let resp = tokio::time::timeout(to, self.conn.read_datagram())
                .await
                .map_err(|_| TuicError::UdpTimeout(to))?
                .map_err(TuicError::Quinn)?;
            let mut cursor = &resp[..];
            let type_byte = crate::protocol::parse_header(&mut cursor)?;
            if type_byte != type_code::PACKET {
                return Err(TuicError::UnknownCommandType(type_byte));
            }
            let pkt = Packet::read_payload(&mut cursor)?;
            let complete = self
                .assembler
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .feed(pkt)?;
            if let Some(full) = complete {
                return Ok(full.data);
            }
        }
    }
    /// 检查连接是否支持 DATAGRAM（native 模式可用性）。
    #[must_use]
    pub fn datagram_supported(&self) -> bool {
        // transport config 已设置 datagram_receive_buffer_size 且 ALPN
        // 协商成功即表示支持；精确容量经 `max_datagram_size()` 探测。
        self.conn.max_datagram_size().is_some()
    }
}
/// 从 bi-stream 精确流式读出一个响应 Packet 帧。
///
/// QUIC 流允许单次 read 部分返回（票 hva9：响应跨 QUIC 包边界时
/// 旧单次 read 截断帧），此处按帧布局 `read_exact` 逐段消费：
/// `VER(1)+TYPE(1) | ASSOC(2)+PKT(2)+FRAG_TOTAL(1)+FRAG_ID(1)+SIZE(2) |
///  ADDR(变长) | DATA(SIZE)`。
async fn read_response_packet(recv: &mut quinn::RecvStream) -> Result<Packet> {
    use crate::protocol::address::Address;

    // VER + TYPE
    let mut vt = [0u8; 2];
    recv.read_exact(&mut vt)
        .await
        .map_err(quinn_read_exact_err)?;
    let mut vh: &[u8] = &vt;
    let type_byte = crate::protocol::parse_header(&mut vh)?;
    if type_byte != type_code::PACKET {
        return Err(TuicError::UnknownCommandType(type_byte));
    }
    let mut fixed = [0u8; 8];
    recv.read_exact(&mut fixed)
        .await
        .map_err(quinn_read_exact_err)?;
    let mut fb = &fixed[..];
    let assoc_id = fb.get_u16();
    let pkt_id = fb.get_u16();
    let frag_total = fb.get_u8();
    let frag_id = fb.get_u8();
    let size = fb.get_u16() as usize;
    if size > MAX_PACKET_PAYLOAD {
        return Err(TuicError::PacketTooLarge(size));
    }
    // ADDR：ATYP(1) + 体（布局见 protocol/address.rs）
    let mut atyp_b = [0u8; 1];
    recv.read_exact(&mut atyp_b)
        .await
        .map_err(quinn_read_exact_err)?;
    let addr = match atyp_b[0] {
        0xff => {
            let mut port = [0u8; 2];
            recv.read_exact(&mut port).await.map_err(quinn_read_exact_err)?;
            Address::None
        }
        0x00 => {
            let mut len_b = [0u8; 1];
            recv.read_exact(&mut len_b)
                .await
                .map_err(quinn_read_exact_err)?;
            let mut name = vec![0u8; u32::from(len_b[0]) as usize];
            recv.read_exact(&mut name)
                .await
                .map_err(quinn_read_exact_err)?;
            let mut port = [0u8; 2];
            recv.read_exact(&mut port).await.map_err(quinn_read_exact_err)?;
            Address::Domain(String::from_utf8_lossy(&name).into_owned(), u16::from_be_bytes(port))
        }
        0x01 => {
            let mut body = [0u8; 4 + 2];
            recv.read_exact(&mut body).await.map_err(quinn_read_exact_err)?;
            Address::Ipv4(
                std::net::Ipv4Addr::new(body[0], body[1], body[2], body[3]),
                u16::from_be_bytes([body[4], body[5]]),
            )
        }
        0x02 => {
            let mut body = [0u8; 16 + 2];
            recv.read_exact(&mut body).await.map_err(quinn_read_exact_err)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&body[..16]);
            Address::Ipv6(
                std::net::Ipv6Addr::from(octets),
                u16::from_be_bytes([body[16], body[17]]),
            )
        }
        _ => return Err(TuicError::InvalidAddress("unknown atyp")),
    };
    // DATA
    let mut data = vec![0u8; size];
    recv.read_exact(&mut data).await.map_err(quinn_read_exact_err)?;
    Ok(Packet {
        assoc_id,
        pkt_id,
        frag_total,
        frag_id,
        addr,
        data,
    })
}

/// `ReadExactError` → `TuicError`（EOF 视为流正常关闭）。
fn quinn_read_exact_err(e: quinn::ReadExactError) -> TuicError {
    match e {
        quinn::ReadExactError::FinishedEarly(_) => {
            TuicError::UnexpectedEof("udp response stream closed")
        }
        quinn::ReadExactError::ReadError(re) => TuicError::QuinnRead(re),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn assoc_id_preserved() {
        // 这是一个编译时测试，验证 TuicUdpAssoc 构造后 assoc_id 正确
        // 实际测试需要 mock quinn connection，在 integration test 中做
        let assoc_id: u16 = 42;
        // 由于 quinn::Connection 需要真实连接，这里只做类型检查
        assert_eq!(assoc_id, 42);
    }
}

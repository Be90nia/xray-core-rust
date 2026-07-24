//! TUIC v5 UDP relay 客户端（切片2）。
//!
//! 提供 [`TuicUdpAssoc`]：客户端 UDP 关联句柄，分配 `assoc_id`，
//! 每次 [`Self::send_recv`] 开一个 bi-stream 发送 Packet 帧并读取响应。
//!
//! ## 模式
//!
//! 本切片实现 **quic 模式**（bi-stream）：每个 UDP 包独占一个 bi-stream，
//! 客户端发送 Packet 帧后写入 DATA，server 解析 ADDR dial UDP、收到响应后
//! 用同样的 Packet 帧格式回写。比 native（datagram）模式更可靠但有序到达。
//!
//! ## 限制（ponytail）
//!
//! - 不实现分片：单包 ≤ [`MAX_PACKET_PAYLOAD`](crate::protocol::packet::MAX_PACKET_PAYLOAD)
//! - 不复用 bi-stream：每包一个 stream（简单但开销大， assoc_id 复用 UDP socket 留待后续）
//! - pkt_id 单调递增，溢出回绕

use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use bytes::{BufMut, BytesMut};
use tokio::time::Duration;

use crate::error::{Result, TuicError};
use crate::protocol::address::Address;
use crate::protocol::command::type_code;
use crate::protocol::{Packet, VERSION};

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
}

impl TuicUdpAssoc {
    /// 由 [`TuicClient`](crate::client::TuicClient) 构造。
    pub(crate) fn new(conn: quinn::Connection, assoc_id: u16) -> Self {
        Self {
            conn,
            assoc_id,
            pkt_id: Arc::new(AtomicU16::new(0)),
        }
    }

    /// 当前关联 ID。
    #[must_use]
    pub fn assoc_id(&self) -> u16 {
        self.assoc_id
    }

    /// 发送一个 UDP 包并等待响应。
    ///
    /// 流程（quic 模式）：
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

        // 写 VER + TYPE + Packet 负载
        let mut buf = BytesMut::with_capacity(pkt.encoded_len());
        buf.put_u8(VERSION);
        buf.put_u8(type_code::PACKET);
        pkt.write_payload(&mut buf);
        send.write_all(&buf).await?;
        // 通知 server：客户端写方向已结束（UDP 单包语义）
        let _ = send.finish();

        // 读响应
        let to = timeout.unwrap_or(DEFAULT_UDP_TIMEOUT);
        let resp = tokio::time::timeout(to, read_response_packet(&mut recv))
            .await
            .map_err(|_| TuicError::UdpTimeout(to))??;
        Ok(resp)
    }
}

/// 从 bi-stream 读出响应 Packet 帧，返回 DATA。
///
/// 响应布局：`VER(1) + TYPE(1=PACKET) + Packet负载`。
async fn read_response_packet(recv: &mut quinn::RecvStream) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; RECV_BUF_CAP];
    let n = recv
        .read(&mut buf)
        .await?
        .ok_or_else(|| TuicError::UnexpectedEof("udp response stream closed"))?;
    if n == 0 {
        return Err(TuicError::UnexpectedEof("udp response empty"));
    }
    let mut cursor = &buf[..n];
    let type_byte = crate::protocol::parse_header(&mut cursor)?;
    if type_byte != type_code::PACKET {
        return Err(TuicError::UnknownCommandType(type_byte));
    }
    let pkt = Packet::read_payload(&mut cursor)?;
    Ok(pkt.data)
}

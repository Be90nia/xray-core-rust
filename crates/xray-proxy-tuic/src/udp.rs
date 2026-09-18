//! TUIC v5 UDP relay 客户端（quic uni-stream 模式 + native DATAGRAM 模式）。
//!
//! 提供 [`TuicUdpAssoc`]：客户端 UDP 关联句柄，分配 `assoc_id`，
//! 支持两种模式（TUIC v5 SPEC：Packet 只经 uni stream 或 datagram，
//! server 同模回包；bi stream 只承载 Connect）：
//! - **quic 模式**（[`TuicUdpAssoc::send_recv`]）：每个 UDP 包独占一条
//!   uni stream；响应经 per-connection [`UniRespRouter`] pump 配对
//! - **native 模式**（[`TuicUdpAssoc::send_recv_native`]）：QUIC DATAGRAM，
//!   保留 UDP 不可靠语义
//!
//! ## 限制（ponytail）
//!
//! - quic 模式响应无分片（stream 可靠有序，frag_total 恒 1）
//! - native 模式：依赖 quinn DATAGRAM 支持（transport.datagram_receive_buffer_size 已设置）
//! - pkt_id 单调递增，溢出回绕

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::time::Duration;

use crate::error::{Result, TuicError};
use crate::protocol::address::Address;
use crate::protocol::command::type_code;
use crate::protocol::{Packet, VERSION, packet::MAX_PACKET_PAYLOAD};

/// 默认 UDP 响应等待时长（mock server 等待 UDP echo）。
const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(10);

/// TUIC 客户端 UDP 关联句柄。
///
/// 由 [`TuicClient::dial_udp`](crate::client::TuicClient::dial_udp) 创建，
/// 持有 QUIC 连接与 assoc_id、pkt_id 计数器。
#[derive(Clone)]
pub struct TuicUdpAssoc {
    conn: quinn::Connection,
    assoc_id: u16,
    pkt_id: Arc<AtomicU16>,
    /// quic 模式响应路由（per-connection uni-stream pump，见 [`UniRespRouter`]）。
    router: UniRespRouter,
    /// 分片重组器（native 模式接收方向，spec FRAG_TOTAL>1 时按 pkt_id 缓存拼接）。
    assembler: Arc<std::sync::Mutex<crate::protocol::packet::FragmentAssembler>>,
}

/// quic 模式（uni-stream）响应路由器。
///
/// SPEC：客户端每包 open_uni 发 Packet；server 每个响应**新开一条** uni stream
/// 回包。本 router spawn 单个 pump task 全局 `accept_uni`，按帧内
/// `(assoc_id, pkt_id)` 把响应配对给等待中的请求。
///
/// ponytail: 一张 (assoc,pkt)→oneshot 表够用——TUIC quic 模式响应无分片
/// （stream 可靠有序，frag_total 恒 1），无需重组器。
#[derive(Clone)]
pub(crate) struct UniRespRouter {
    waiters:
        Arc<std::sync::Mutex<HashMap<(u16, u16), tokio::sync::oneshot::Sender<Packet>>>>,
}

impl UniRespRouter {
    /// 在连接建立后调用：spawn per-connection 响应 pump（连接关闭自动退出）。
    pub(crate) fn spawn(conn: quinn::Connection) -> Self {
        let waiters: Arc<
            std::sync::Mutex<HashMap<(u16, u16), tokio::sync::oneshot::Sender<Packet>>>,
        > = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let w = Arc::clone(&waiters);
        tokio::spawn(async move {
            loop {
                let mut uni = match conn.accept_uni().await {
                    Ok(u) => u,
                    Err(e) => {
                        tracing::debug!("tuic uni resp router closed: {e:?}");
                        break;
                    }
                };
                match read_response_packet(&mut uni).await {
                    Ok(pkt) => {
                        let waiter = w
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .remove(&(pkt.assoc_id, pkt.pkt_id));
                        match waiter {
                            Some(tx) => {
                                let _ = tx.send(pkt);
                            }
                            None => {
                                tracing::debug!(
                                    "tuic: unmatched udp resp assoc={} pkt={}",
                                    pkt.assoc_id,
                                    pkt.pkt_id
                                );
                            }
                        }
                    }
                    Err(e) => tracing::debug!("tuic: uni resp stream parse: {e:?}"),
                }
            }
        });
        Self { waiters }
    }

    /// open_uni 发送 Packet 并等待 `(assoc_id, pkt_id)` 匹配的响应。
    async fn send_and_wait(
        &self,
        conn: &quinn::Connection,
        pkt: &Packet,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.waiters
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert((pkt.assoc_id, pkt.pkt_id), tx);
        let waiters = Arc::clone(&self.waiters);
        let key = (pkt.assoc_id, pkt.pkt_id);
        let recv = async {
            let mut uni = conn.open_uni().await?;
            uni.write_all(Self::encode_frame(pkt).as_ref()).await?;
            let _ = uni.finish();
            rx.await
                .map_err(|_| TuicError::UnexpectedEof("udp resp router dropped"))
        };
        match tokio::time::timeout(timeout, recv).await {
            // Bytes → Vec：read_payload 产的 VEC-kind Bytes 唯一引用时零拷贝归还
            Ok(Ok(resp)) => Ok(resp.data.into()),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                waiters.lock().unwrap_or_else(|p| p.into_inner()).remove(&key);
                Err(TuicError::UdpTimeout(timeout))
            }
        }
    }

    /// 将 Packet 帧序列化为 wire 格式（VER + TYPE + payload）。
    fn encode_frame(pkt: &Packet) -> BytesMut {
        let mut buf = BytesMut::with_capacity(pkt.encoded_len() + 2);
        buf.put_u8(VERSION);
        buf.put_u8(type_code::PACKET);
        pkt.write_payload(&mut buf);
        buf
    }
}

impl TuicUdpAssoc {
    /// 由 [`TuicClient`](crate::client::TuicClient) 构造。
    pub(crate) fn new(conn: quinn::Connection, assoc_id: u16, router: UniRespRouter) -> Self {
        Self {
            conn,
            assoc_id,
            pkt_id: Arc::new(AtomicU16::new(0)),
            router,
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

    /// 发送一个 UDP 包并等待响应（quic 模式，uni-stream）。
    ///
    /// 流程（TUIC v5 SPEC uni-stream 模型）：
    /// 1. open_uni 写入 Packet 帧（VER + TYPE + ASSOC + PKT + FRAG + SIZE + ADDR + DATA）
    /// 2. finish() 通知 server 写方向结束
    /// 3. 响应经 [`UniRespRouter`] pump 从 server 新开的 uni stream 配对收取
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
        let pkt = Packet::new(self.assoc_id, pkt_id, target, Bytes::copy_from_slice(data));
        let to = timeout.unwrap_or(DEFAULT_UDP_TIMEOUT);
        self.router.send_and_wait(&self.conn, &pkt, to).await
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
        // 一次 owned 化，分片走 Bytes::slice 零拷贝（原每片 chunk.to_vec 各拷一次）
        let data = Bytes::copy_from_slice(data);
        for pkt in build_native_fragments(self.assoc_id, pkt_id, target, data, frag_payload)? {
            self.conn
                .send_datagram(UniRespRouter::encode_frame(&pkt).freeze())
                .map_err(TuicError::QuinnSendDatagram)?;
        }
        Ok(())
    }

    /// 发送一个 UDP 包并等待响应（native DATAGRAM 模式）。
    ///
    /// 流程：
    /// 1. DATA ≤ 单 datagram 容量：单片直发（FRAG_TOTAL=1）
    ///    超过：按 TUIC v5 spec 切 FRAG_TOTAL 片（同 pkt_id，FRAG_ID 0-based，
    ///    非首片 addr=None/0xff）
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
                // Bytes → Vec：assembler 拼接产的 VEC-kind 唯一引用时零拷贝归还
                return Ok(full.data.into());
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

/// 按 native datagram 容量切分 Packet 帧（纯函数，可单测）。
///
/// spec（TUIC v5）：单包直接 FRAG_TOTAL=1；超长切 FRAG_TOTAL 片，同 pkt_id、
/// FRAG_ID 0-based，**仅首片携带目标 Address**，后续片 addr=None（wire 编码
/// `0xff`）——接收方按首片地址路由。分片为 `Bytes::slice` 零拷贝视图。
fn build_native_fragments(
    assoc_id: u16,
    pkt_id: u16,
    target: &Address,
    data: Bytes,
    frag_payload: usize,
) -> Result<Vec<Packet>> {
    if data.len() <= frag_payload {
        return Ok(vec![Packet::new(assoc_id, pkt_id, target.clone(), data)]);
    }
    if data.len() > MAX_PACKET_PAYLOAD {
        return Err(TuicError::PacketTooLarge(data.len()));
    }
    let frag_total = data.len().div_ceil(frag_payload);
    let Ok(frag_total) = u8::try_from(frag_total) else {
        return Err(TuicError::PacketTooLarge(data.len()));
    };
    let mut frags = Vec::with_capacity(frag_total as usize);
    for (i, chunk) in data.chunks(frag_payload).enumerate() {
        frags.push(Packet {
            assoc_id,
            pkt_id,
            frag_total,
            frag_id: i as u8,
            // spec：非首片不带目标地址（Address::None → 0xff）
            addr: if i == 0 {
                target.clone()
            } else {
                Address::None
            },
            // slice 借用 data 产出共享视图，零拷贝；data 在循环结束后 drop
            data: data.slice_ref(chunk),
        });
    }
    Ok(frags)
}

/// 从 uni stream 读出一个完整 Packet 帧（含 VER+TYPE 头）。
///
/// QUIC 流允许单次 read 部分返回（票 hva9：响应跨 QUIC 包边界时
/// 旧单次 read 截断帧），此处按帧布局 `read_exact` 逐段消费：
/// `VER(1)+TYPE(1) | ASSOC(2)+PKT(2)+FRAG_TOTAL(1)+FRAG_ID(1)+SIZE(2) |
///  ADDR(变长) | DATA(SIZE)`。
///
/// 客户端（[`UniRespRouter`]）使用；服务端 uni 分支头已由
/// [`crate::server::read_uni_frame`] 消费，直接用 [`read_packet_payload`]。
pub(crate) async fn read_response_packet(recv: &mut quinn::RecvStream) -> Result<Packet> {
    let mut vt = [0u8; 2];
    recv.read_exact(&mut vt)
        .await
        .map_err(quinn_read_exact_err)?;
    let mut vh: &[u8] = &vt;
    let type_byte = crate::protocol::parse_header(&mut vh)?;
    if type_byte != type_code::PACKET {
        return Err(TuicError::UnknownCommandType(type_byte));
    }
    read_packet_payload(recv).await
}

/// 读 Packet 负载（VER+TYPE 已被调用方消费）：ASSOC..DATA 逐段 `read_exact`。
pub(crate) async fn read_packet_payload(recv: &mut quinn::RecvStream) -> Result<Packet> {
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
    // DATA（Vec → Bytes 零拷贝所有权转移）
    let mut data = vec![0u8; size];
    recv.read_exact(&mut data).await.map_err(quinn_read_exact_err)?;
    Ok(Packet {
        assoc_id,
        pkt_id,
        frag_total,
        frag_id,
        addr,
        data: Bytes::from(data),
    })
}

/// `ReadExactError` → `TuicError`（EOF 视为流正常关闭）。
pub(crate) fn quinn_read_exact_err(e: quinn::ReadExactError) -> TuicError {
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

    /// 票 ieik①：native 分片仅首片带目标地址，非首片 addr=None（wire 0xff）。
    #[test]
    fn native_fragments_only_first_carries_address() {
        let target = Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1), 8080);
        let data = Bytes::from(vec![7u8; 100]);
        let frags =
            build_native_fragments(0x1234, 0x5678, &target, data, 30).expect("fragments");
        assert_eq!(frags.len(), 4, "ceil(100/30) = 4 片");
        for (i, f) in frags.iter().enumerate() {
            assert_eq!(f.assoc_id, 0x1234);
            assert_eq!(f.pkt_id, 0x5678);
            assert_eq!(f.frag_total, 4);
            assert_eq!(f.frag_id, i as u8);
        }
        // 首片带地址；其余片 addr=None
        assert_eq!(frags[0].addr, target);
        assert_eq!(frags[1].addr, Address::None);
        assert_eq!(frags[2].addr, Address::None);
        assert_eq!(frags[3].addr, Address::None);
        // Address::None 的 wire 首字节 = 0xff（票验收：分片 addr=0xff）
        let mut buf = Vec::new();
        frags[1].addr.write_to(&mut buf);
        assert_eq!(buf[0], 0xff);
    }

    /// 单包 ≤ frag_payload 时单片直发（FRAG_TOTAL=1，地址保留）。
    #[test]
    fn native_single_packet_keeps_address() {
        let target = Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1), 8080);
        let frags =
            build_native_fragments(1, 2, &target, Bytes::from_static(b"hello"), 64)
                .expect("fragments");
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].frag_total, 1);
        assert_eq!(frags[0].frag_id, 0);
        assert_eq!(frags[0].addr, target);
        assert_eq!(&frags[0].data[..], b"hello");
    }
}

//! Trojan outbound → DialBridge 适配器（阶段 1 切片 1e）。
//!
//! Trojan 协议：拨号到 Trojan 服务器 → 在 TCP 流上写请求头（hex(sha224(password))
//! + CRLF + cmd + addr + port + CRLF）→ 返回连接，后续双向透传。
//!
//! ## 范围
//!
//! 当前实现：Trojan over **raw TCP**（与现有 trojan_proxy_e2e 测试模式一致）。
//! 生产场景（Trojan + TLS / WS）需在上层注入 TLS-wrapped 拨号闭包。
//!
//! [`DialBridge`]: xray_app_dispatcher::default::DialBridge
//! [`DialFn`]: xray_app_dispatcher::default::DialFn

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xray_app_dispatcher::{
    default::DialFn,
    udp_session::{XudpReframer, XudpUnframer, xudp_frame_target},
};
use xray_common::net::{address::Address, destination::Destination, port::Port};
use xray_transport::{
    connection::Connection,
    dialer::{StreamSettings, dial},
};

use crate::{
    config::MemoryAccount,
    protocol::{Network as TrojanNetwork, write_request_header},
};

/// Trojan outbound 配置。
#[derive(Debug, Clone)]
pub struct TrojanOutboundConfig {
    /// Trojan 账户（含 hex(sha224(password))）。
    pub account: MemoryAccount,
    /// Trojan 服务器地址。
    pub server_address: Address,
    /// Trojan 服务器端口。
    pub server_port: Port,
    /// 可选 streamSettings（TLS/WS/gRPC/...）。None 走 raw TCP。
    pub stream_settings: Option<StreamSettings>,
    /// 用户 level（policy/stats 系统用）。
    pub level: u32,
    /// 用户 email（stats 系统标识用）。
    pub email: String,
}

impl TrojanOutboundConfig {
    /// 构造（raw TCP，无 streamSettings）。
    #[must_use]
    pub fn new(account: MemoryAccount, server_address: Address, server_port: Port) -> Self {
        Self {
            account,
            server_address,
            server_port,
            stream_settings: None,
            level: 0,
            email: String::new(),
        }
    }

    /// 指定 streamSettings（builder 风格）。
    #[must_use]
    pub fn with_stream_settings(mut self, settings: Option<StreamSettings>) -> Self {
        self.stream_settings = settings;
        self
    }

    /// 设置用户 level（builder 风格）。
    #[must_use]
    pub fn with_level(mut self, level: u32) -> Self {
        self.level = level;
        self
    }

    /// 设置用户 email（builder 风格）。
    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = email.into();
        self
    }

    /// 构造 Trojan 服务器 Destination（拨号用）。
    #[must_use]
    pub fn server_destination(&self) -> Destination {
        Destination::tcp(self.server_address.clone(), self.server_port)
    }
}

/// 构造 Trojan 的 DialFn 闭包。
///
/// 闭包捕获 `Arc<TrojanOutboundConfig>`，每次调用：
/// 1. dial_system 到 Trojan 服务器 → `Box<dyn Connection>`
/// 2. `write_request_header` 构造 Trojan 头（hex key + CRLF + cmd + addr/port + CRLF）
/// 3. `conn.write_all(&header)` 写入连接
/// 4. 返回连接（已是带 Trojan 头的 TCP）
///
/// # Panics
///
/// 不会 panic；任何错误以 `Err(String)` 返回。
pub fn make_dial_fn(config: Arc<TrojanOutboundConfig>) -> DialFn {
    Arc::new(move |dest: &Destination| {
        let config = Arc::clone(&config);
        let target_addr = dest.address().clone();
        let target_port = dest.port().value();
        let is_udp = dest.is_udp();
        Box::pin(async move {
            // 1. dial Trojan server：有 streamSettings 走 transport dialer（ws/grpc/...），否则裸
            //    TCP。
            let server_dest = config.server_destination();
            let sockopt =
                config.stream_settings.as_ref().map(|s| s.socket_options()).unwrap_or_default();
            let mut conn: Box<dyn Connection> =
                xray_transport::retry::exponential_backoff(5, 100, || async {
                    match &config.stream_settings {
                        Some(s) => dial(&server_dest, s, &sockopt)
                            .await
                            .map_err(|e| format!("trojan dial server ({}): {e}", s.protocol)),
                        None => xray_transport::system_dialer::dial_system(&server_dest, &sockopt)
                            .await
                            .map_err(|e| format!("trojan dial server (tcp): {e}")),
                    }
                })
                .await
                .map_err(|e| format!("failed to find an available destination: {e}"))?;

            // 2. 构造 Trojan 请求头（UDP dest → command UDP，Go client.go 同分支）
            let network = if is_udp { TrojanNetwork::Udp } else { TrojanNetwork::Tcp };
            let mut header = Vec::with_capacity(128);
            write_request_header(&mut header, &config.account, network, &target_addr, target_port)
                .map_err(|e| format!("trojan write header: {e}"))?;

            use tokio::io::AsyncWriteExt as _;
            // 3. 写头到连接
            conn.write_all(&header).await.map_err(|e| format!("trojan write header: {e}"))?;

            // 4. UDP：包一层 Trojan UDP 分帧（[addr][len][CRLF][payload] per packet， Go
            //    PacketWriter/PacketReader）。write 边界≈packet 边界。
            if is_udp {
                Ok(Box::new(TrojanUdpFramedConn::new(conn, target_addr, target_port))
                    as Box<dyn Connection>)
            } else {
                Ok(conn)
            }
        })
    })
}

/// Trojan UDP 分帧连接：把字节流 write 按 Trojan UDP 帧格式包装、read 剥帧。
///
/// 对应 Go `protocol.go::PacketWriter`/`PacketReader`。每帧：
/// `[addr+port][2B len][CRLF][payload]`。
///
/// **两套表示**（bd t0ls1）：内部 dispatch link 跑 XUDP 帧，Trojan wire 跑裸
/// 载荷 + 自描述目标。上行剥帧（目标取帧头，退回请求头目标），下行按 wire
/// 帧自带地址裹回 XUDP 帧。
struct TrojanUdpFramedConn {
    inner: Box<dyn Connection>,
    /// 会话目标（请求头目标；上行帧无目标时兜底）
    addr: Address,
    port: u16,
    /// 上行剥帧：XUDP 帧流 → 裸载荷
    unframer: XudpUnframer,
    /// 下行裹帧：裸载荷 → XUDP 帧流
    reframer: XudpReframer,
    rbuf: Vec<u8>,
    /// 当前帧载荷尚未交付的字节数（载荷留在 rbuf 头部）
    rview: usize,
    /// 待发的 XUDP 帧头（meta + 2B 载荷长度）
    hdr: Vec<u8>,
    hpos: usize,
    /// 待写完的帧（UDP 帧不可分，部分写时缓存剩余）
    wpending: Vec<u8>,
    wpos: usize,
    /// 本轮 poll_write 已收下的字节数（返回 Pending 后重入不再重复喂）
    fed: usize,
}

impl TrojanUdpFramedConn {
    fn new(inner: Box<dyn Connection>, addr: Address, port: u16) -> Self {
        Self {
            inner,
            reframer: XudpReframer::new(Destination::udp(addr.clone(), Port::new(port))),
            addr,
            port,
            unframer: XudpUnframer::new(),
            rbuf: Vec::new(),
            rview: 0,
            hdr: Vec::with_capacity(64),
            hpos: 0,
            wpending: Vec::new(),
            wpos: 0,
            fed: 0,
        }
    }
}

impl AsyncWrite for TrojanUdpFramedConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // 上一轮已收下 buf（Pending 重入）→ 只排干，不再重复喂
        if this.fed == 0 {
            // 剥 XUDP 帧，按包构 Trojan UDP 帧（wire 每包自描述目标）
            let fallback_addr = this.addr.clone();
            let fallback_port = this.port;
            let mut framed = std::mem::take(&mut this.wpending);
            framed.clear();
            this.wpos = 0;
            let fed = buf.len();
            let mut frame_err: Option<String> = None;
            let res = this.unframer.feed(buf, |meta, payload| {
                let target = xudp_frame_target(meta).ok().flatten();
                let (addr, port) = match target {
                    Some(d) => (d.address().clone(), d.port().value()),
                    None => (fallback_addr.clone(), fallback_port),
                };
                if let Err(e) = crate::protocol::write_udp_packet(&mut framed, &addr, port, payload)
                {
                    frame_err = Some(format!("{e}"));
                }
            });
            this.wpending = framed;
            if let Some(e) = frame_err {
                return Poll::Ready(Err(io::Error::other(format!("trojan udp: {e}"))));
            }
            res.map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("trojan udp: XUDP 帧解析: {e}"))
            })?;
            this.fed = fed;
        }
        // 排干 pending 帧（UDP 帧不可分）
        while this.wpos < this.wpending.len() {
            let n = std::task::ready!(
                Pin::new(&mut *this.inner).poll_write(cx, &this.wpending[this.wpos..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "trojan udp: frame write stalled",
                )));
            }
            this.wpos += n;
        }
        let fed = this.fed;
        this.fed = 0;
        this.wpending.clear();
        this.wpos = 0;
        Poll::Ready(Ok(fed))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

impl AsyncRead for TrojanUdpFramedConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // 1) 待发的 XUDP 帧头优先（帧头必须排在载荷之前）
            if self.hpos < self.hdr.len() {
                let n = (self.hdr.len() - self.hpos).min(buf.remaining());
                buf.put_slice(&self.hdr[self.hpos..self.hpos + n]);
                self.hpos += n;
                return Poll::Ready(Ok(()));
            }
            // 2) 当前帧载荷未交付完 → 交付（载荷留在 rbuf 头部）
            if self.rview > 0 {
                let n = self.rview.min(buf.remaining());
                buf.put_slice(&self.rbuf[..n]);
                self.rbuf.drain(..n);
                self.rview -= n;
                return Poll::Ready(Ok(()));
            }
            // 3) 缓冲里有完整帧 → 剥帧、裹 XUDP 帧头（目标取 wire 自带地址）
            if !self.rbuf.is_empty() {
                let parsed = crate::protocol::parse_udp_packet_stream(&self.rbuf);
                match parsed {
                    Ok(Some((addr, port, payload, consumed))) => {
                        let payload_len = payload.len();
                        let header_len = consumed - payload_len;
                        let target = Destination::udp(addr, Port::new(port));
                        // 先丢弃 wire 帧头（payload 留在 rbuf 头部），再裹帧头
                        self.rbuf.drain(..header_len);
                        if payload_len == 0 {
                            continue;
                        }
                        let mut hdr = std::mem::take(&mut self.hdr);
                        self.reframer.write_header(payload_len, Some(&target), &mut hdr).map_err(
                            |e| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("trojan udp: XUDP 应答帧头: {e}"),
                                )
                            },
                        )?;
                        self.hdr = hdr;
                        self.hpos = 0;
                        self.rview = payload_len;
                        continue;
                    },
                    Ok(None) => {}, // 数据不足一帧，继续从 inner 读
                    // 致命帧错误（ATYP 非法 / payload 超限）→ 终止会话；
                    // 对齐入站 server.rs UDP relay fatal 分支与 Go PacketReader
                    Err(e) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("trojan udp: parse frame: {e}"),
                        )));
                    },
                }
            }
            // 缓冲不足一帧 → 从 inner 再读
            let mut tmp = [0u8; 8192];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut *self.inner).poll_read(cx, &mut rb)? {
                Poll::Ready(()) => {
                    let filled = rb.filled();
                    if filled.is_empty() {
                        return if self.rbuf.is_empty() {
                            Poll::Ready(Ok(())) // EOF
                        } else {
                            // 残留半帧：协议损坏，报错
                            Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "trojan udp: truncated frame",
                            )))
                        };
                    }
                    self.rbuf.extend_from_slice(filled);
                },
                Poll::Pending => {
                    return Poll::Pending;
                },
            }
        }
    }
}

impl Connection for TrojanUdpFramedConn {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.remote_addr()
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use xray_common::net::address::Address;

    use super::*;

    #[test]
    fn config_server_destination_roundtrip() {
        let account = MemoryAccount::new("test_password".to_string());
        let cfg = TrojanOutboundConfig::new(
            account,
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(443),
        );
        let dest = cfg.server_destination();
        assert!(dest.is_tcp());
        assert_eq!(dest.port(), Port::new(443));
    }

    #[test]
    fn make_dial_fn_returns_arc_closure() {
        let account = MemoryAccount::new("test_password".to_string());
        let cfg = Arc::new(TrojanOutboundConfig::new(
            account,
            Address::new_domain("example.com"),
            Port::new(443),
        ));
        let _dial = make_dial_fn(Arc::clone(&cfg));
        assert_eq!(Arc::strong_count(&cfg), 2);
    }

    /// 构造一帧 XUDP New（link 侧表示；trojan crate 不依赖 xray-xudp，手拼线格式）。
    fn xudp_frame(payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes()); // session id
        body.push(1); // status = New
        body.push(1); // opt = Data
        body.push(2); // network = UDP
        body.extend_from_slice(&53u16.to_be_bytes()); // port（PortThenAddress）
        body.push(1); // atyp = IPv4
        body.extend_from_slice(&[8, 8, 8, 8]);
        body.extend_from_slice(&[3u8; 8]); // GlobalID
        let mut f = Vec::new();
        f.extend_from_slice(&(body.len() as u16).to_be_bytes());
        f.extend_from_slice(&body);
        f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// UDP 分帧 roundtrip（bd t0ls1）：duplex 模拟 Trojan 服务器。
    /// write: link 侧 XUDP 帧 → wire `[addr][len][CRLF][裸载荷]`；
    /// read: wire 裸载荷 → link 侧 XUDP 帧（载荷逐字节还原）。
    #[tokio::test]
    async fn udp_framed_conn_roundtrip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client_side, mut server_side) = tokio::io::duplex(4096);
        let conn = TrojanUdpFramedConn::new(
            Box::new(xray_transport::connection::DuplexConnection::new(client_side)),
            Address::from_ipv4_bytes([8, 8, 8, 8]),
            53,
        );
        let mut framed = conn;

        // write 一个 link 帧 → wire 上应是合法 Trojan UDP 帧（载荷不含 XUDP 帧头）
        framed.write_all(&xudp_frame(b"query-payload")).await.unwrap();
        framed.flush().await.unwrap();
        let mut wire = vec![0u8; 256];
        let n = server_side.read(&mut wire).await.unwrap();
        let wire = &wire[..n];
        let (addr, port, payload, consumed) = crate::protocol::parse_udp_packet(wire).unwrap();
        assert_eq!(addr, Address::from_ipv4_bytes([8, 8, 8, 8]));
        assert_eq!(port, 53);
        assert_eq!(payload, b"query-payload", "wire 载荷必须是裸载荷");
        assert_eq!(consumed, n, "整帧消费");

        // server 回一帧裸载荷 → framed.read **分段**交付 XUDP 帧（AsyncRead 契约：
        // 先交帧头、载荷留到后续 poll），故累积读到整帧再断言（不得为迁就测试改
        // poll_read 的交付粒度）。
        let mut resp = Vec::new();
        crate::protocol::write_udp_packet(&mut resp, &addr, 53, b"answer-payload").unwrap();
        server_side.write_all(&resp).await.unwrap();

        async fn read_until(framed: &mut TrojanUdpFramedConn, got: &mut Vec<u8>, need: usize) {
            while got.len() < need {
                let mut tmp = [0u8; 512];
                let n = framed.read(&mut tmp).await.expect("read");
                assert!(n > 0, "EOF before {need} bytes (got {})", got.len());
                got.extend_from_slice(&tmp[..n]);
            }
        }

        let mut got: Vec<u8> = Vec::new();
        read_until(&mut framed, &mut got, 2).await;
        let meta_len = u16::from_be_bytes([got[0], got[1]]) as usize;
        read_until(&mut framed, &mut got, 4 + meta_len).await;
        let data_len = u16::from_be_bytes([got[2 + meta_len], got[3 + meta_len]]) as usize;
        read_until(&mut framed, &mut got, 4 + meta_len + data_len).await;

        assert_eq!(got[4], 1, "首个应答帧必须是 New");
        assert_eq!(data_len, b"answer-payload".len(), "data_len 与实际载荷一致");
        assert_eq!(
            &got[4 + meta_len..4 + meta_len + data_len],
            b"answer-payload",
            "XUDP 载荷逐字节还原"
        );
    }

    /// 致命帧（ATYP 非法）→ read 返回 Err 终止会话，而非静默吞错挂死
    /// （对齐入站 server.rs UDP relay fatal 分支；修复前坏帧滞留 rbuf 被无限重读）。
    #[tokio::test]
    async fn udp_framed_conn_fatal_frame_terminates() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (client_side, mut server_side) = tokio::io::duplex(4096);
        let mut framed = TrojanUdpFramedConn::new(
            Box::new(xray_transport::connection::DuplexConnection::new(client_side)),
            Address::from_ipv4_bytes([8, 8, 8, 8]),
            53,
        );

        // 非法 ATYP 0xFF：parse_udp_packet_stream 判致命错误（InsufficientData 才算不足）
        server_side.write_all(&[0xFF]).await.unwrap();

        let mut out = [0u8; 16];
        let result = framed.read(&mut out).await;
        assert!(result.is_err(), "fatal frame must terminate the session, got {result:?}");
    }
}

//! # UDP 自定义序列引擎（对应 Go `finalmask/header/custom/udp.go`）
//!
//! `UdpCustomClient` / `UdpCustomServer` 实现 `UdpIo`：
//! - send_to：求值本端 items 作为 header，append payload 发送。
//! - recv_from：匹配对端 items，剥离 header 后返回 payload；不匹配则继续读下一包。
//!
//! UDPStandaloneConfig 不实现（推迟到 rpn-future）。

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;

use super::{
    UDPConfig, UDPItem,
    evaluator::{
        EvalContext, collect_saved_udp_sizes, evaluate_udp_items, match_udp_items,
        measure_udp_items, measure_udp_items_with_fallback,
    },
    state::StateStore,
};

/// 由 client 包装的 UDP conn：发送时 evaluate client items，
/// 接收时 match server items。
pub(super) struct UdpCustomClient {
    inner: Box<dyn super::super::UdpIo>,
    client_items: Vec<UDPItem>,
    server_items: Vec<UDPItem>,
    /// 期望的 server header 字节数（measure server items + client saved sizes 作 fallback）。
    server_header_size: usize,
    state: Arc<StateStore>,
}

impl UdpCustomClient {
    pub(super) fn new(
        inner: Box<dyn super::super::UdpIo>,
        config: UDPConfig,
        ttl: Duration,
    ) -> io::Result<Self> {
        let client_saved = collect_saved_udp_sizes(&config.client);
        let server_header_size = measure_udp_items_with_fallback(&config.server, &client_saved)?;
        Ok(Self {
            inner,
            client_items: config.client,
            server_items: config.server,
            server_header_size,
            state: Arc::new(StateStore::new(ttl)),
        })
    }
}

#[async_trait]
impl super::super::UdpIo for UdpCustomClient {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        let local = self.inner.local_addr().ok();
        let mut ctx = EvalContext::with_addrs(local, Some(addr));
        let key = udp_state_key(addr);
        if let Some(initial) = self.state.get(&key) {
            ctx.vars = initial;
        }
        let evaluated = evaluate_udp_items(&self.client_items, &mut ctx)?;
        self.state.set(&key, &ctx.vars);

        let mut packet = evaluated;
        packet.extend_from_slice(buf);
        // 底层错误上抛（与 Go 一致：返回错误，调用方决定是否 drop）
        self.inner.send_to(&packet, addr).await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut read_buf = vec![0u8; super::super::UDP_SIZE];
        loop {
            let (n, addr) = self.inner.recv_from(&mut read_buf).await?;
            let key = udp_state_key(addr);
            let initial = self.state.get(&key).unwrap_or_default();
            let matched = match_udp_items(
                &self.server_items,
                &read_buf[..n],
                self.server_header_size,
                &initial,
            );
            if let Some(vars) = matched {
                self.state.set(&key, &vars);
                let payload_len = match n.checked_sub(self.server_header_size) {
                    Some(0) => 0,
                    Some(len) if buf.len() >= len => len,
                    _ => continue,
                };
                if payload_len > 0 {
                    let start = self.server_header_size;
                    let end = start + payload_len;
                    buf[..payload_len].copy_from_slice(&read_buf[start..end]);
                }
                return Ok((payload_len, addr));
            }
            // header 不匹配：丢弃，继续读
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

/// 由 server 包装的 UDP conn：发送时 evaluate server items，
/// 接收时 match client items。
pub(super) struct UdpCustomServer {
    inner: Box<dyn super::super::UdpIo>,
    client_items: Vec<UDPItem>,
    server_items: Vec<UDPItem>,
    /// 期望的 client header 字节数。
    client_header_size: usize,
    state: Arc<StateStore>,
}

impl UdpCustomServer {
    pub(super) fn new(
        inner: Box<dyn super::super::UdpIo>,
        config: UDPConfig,
        ttl: Duration,
    ) -> io::Result<Self> {
        let client_header_size = measure_udp_items(&config.client)?;
        Ok(Self {
            inner,
            client_items: config.client,
            server_items: config.server,
            client_header_size,
            state: Arc::new(StateStore::new(ttl)),
        })
    }
}

#[async_trait]
impl super::super::UdpIo for UdpCustomServer {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        let local = self.inner.local_addr().ok();
        let mut ctx = EvalContext::with_addrs(local, Some(addr));
        let key = udp_state_key(addr);
        if let Some(initial) = self.state.get(&key) {
            ctx.vars = initial;
        }
        let evaluated = evaluate_udp_items(&self.server_items, &mut ctx)?;
        self.state.set(&key, &ctx.vars);

        let mut packet = evaluated;
        packet.extend_from_slice(buf);
        self.inner.send_to(&packet, addr).await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut read_buf = vec![0u8; super::super::UDP_SIZE];
        loop {
            let (n, addr) = self.inner.recv_from(&mut read_buf).await?;
            let key = udp_state_key(addr);
            let initial = self.state.get(&key).unwrap_or_default();
            let matched = match_udp_items(
                &self.client_items,
                &read_buf[..n],
                self.client_header_size,
                &initial,
            );
            if let Some(vars) = matched {
                self.state.set(&key, &vars);
                let payload_len = match n.checked_sub(self.client_header_size) {
                    Some(0) => 0,
                    Some(len) if buf.len() >= len => len,
                    _ => continue,
                };
                if payload_len > 0 {
                    let start = self.client_header_size;
                    let end = start + payload_len;
                    buf[..payload_len].copy_from_slice(&read_buf[start..end]);
                }
                return Ok((payload_len, addr));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

/// UDP 状态 key（对应 Go `udpStateKey`，按 remote addr 字符串）。
fn udp_state_key(addr: SocketAddr) -> String {
    addr.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalmask::Udpmask;

    fn item_packet(packet: &[u8]) -> UDPItem {
        UDPItem {
            rand: 0,
            rand_min: 0,
            rand_max: 0,
            packet: packet.to_vec(),
            save: String::new(),
            var: String::new(),
            expr: None,
        }
    }

    /// 端到端：client 用 "CHDR" header 发送 payload；server 匹配 "CHDR"，剥离后返回 payload。
    #[tokio::test]
    async fn client_to_server_roundtrip() {
        let cfg = super::super::Config {
            tcp: None,
            udp: Some(UDPConfig {
                client: vec![item_packet(b"CHDR")],
                server: vec![item_packet(b"SHDR")],
            }),
            udp_standalone: None,
            state_ttl: Duration::from_secs(5),
        };

        let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_b = b.local_addr().unwrap();

        let wrapped_a: Box<dyn super::super::UdpIo> =
            cfg.wrap_packet_conn_client(Box::new(a), 0, 0).unwrap();
        let wrapped_b: Box<dyn super::super::UdpIo> =
            cfg.wrap_packet_conn_server(Box::new(b), 0, 0).unwrap();

        let payload = b"hello custom udp";
        wrapped_a.send_to(payload, addr_b).await.unwrap();

        let mut recv = vec![0u8; crate::finalmask::UDP_SIZE];
        // recv_from 会循环到匹配包为止；用 timeout 兜底防卡死
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), wrapped_b.recv_from(&mut recv))
            .await
            .expect("recv_from did not complete in time")
            .unwrap();
        assert_eq!(&recv[..n], payload);
    }

    /// 双向：client→server 后 server→client（各自 header 模板）。
    #[tokio::test]
    async fn bidirectional_roundtrip() {
        let cfg = super::super::Config {
            tcp: None,
            udp: Some(UDPConfig {
                client: vec![item_packet(b"C")],
                server: vec![item_packet(b"S")],
            }),
            udp_standalone: None,
            state_ttl: Duration::from_secs(5),
        };

        let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = a.local_addr().unwrap();
        let addr_b = b.local_addr().unwrap();

        let wrapped_a: Box<dyn super::super::UdpIo> =
            cfg.wrap_packet_conn_client(Box::new(a), 0, 0).unwrap();
        let wrapped_b: Box<dyn super::super::UdpIo> =
            cfg.wrap_packet_conn_server(Box::new(b), 0, 0).unwrap();

        // a → b
        wrapped_a.send_to(b"ping", addr_b).await.unwrap();
        let mut buf = vec![0u8; 16];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), wrapped_b.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"ping");

        // b → a
        wrapped_b.send_to(b"pong", addr_a).await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), wrapped_a.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"pong");
    }

    #[test]
    fn udp_state_key_serializes_addr() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(udp_state_key(addr), "127.0.0.1:8080");
    }
}

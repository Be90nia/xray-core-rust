//! # Sudoku 数独编码（对应 Go `transport/internet/finalmask/sudoku/`）
//!
//! 用 4×4 数独谜题的位置编码字节——每个字节映射到 4 个 hint 字节，
//! 每个数据包从头开始按 tableIndex 轮转使用多张表。
//!
//! ## 模式
//!
//! - **UDP**：每个 datagram 独立编码（tableIndex 从 0 开始）
//! - **TCP pure**：流式 4-hint 编码（上行/客户端写、下行/服务端读）
//! - **TCP packed**：6-bit group 编码（下行优化、服务端写、客户端读）

mod codec;
mod table;

use std::{io, sync::Arc};

use async_trait::async_trait;
use codec::{Codec, PackedDecoder, PackedEncoder, decode_bytes};
use table::{Layout, get_tables};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select,
};

use super::{AsyncIo, Tcpmask, UDP_SIZE, UdpIo, Udpmask};

/// Sudoku 配置（对应 Go `sudoku.Config` protobuf）。
#[derive(Debug, Clone, Default)]
pub struct SudokuConfig {
    /// 密码（用作 table shuffle seed）。
    pub password: String,
    /// ASCII 模式：`""`/`"entropy"`/`"prefer_entropy"`（默认），`"ascii"`/`"prefer_ascii"`。
    pub ascii: String,
    /// 单个 customTable 模板（8 字符 `xxppvvvv`，`""` 表示用 entropy）。
    pub custom_table: String,
    /// 多个 customTable 模板列表（轮转使用，重复自动去重）。
    pub custom_tables: Vec<String>,
    /// padding 概率下限 [0, 100]。
    pub padding_min: u32,
    /// padding 概率上限 [0, 100]。
    pub padding_max: u32,
}

/// 规范化 padding 概率（对应 Go `normalizedPadding`）。
fn normalized_padding(config: &SudokuConfig) -> (usize, usize) {
    let p_min = (config.padding_min as usize).min(100);
    let p_max_raw = config.padding_max as usize;
    let p_max = if p_max_raw < p_min { p_min } else { p_max_raw.min(100) };
    (p_min, p_max)
}

// ===== Udpmask impl =====

impl Udpmask for SudokuConfig {
    fn wrap_packet_conn_client(
        &self,
        raw: Box<dyn UdpIo>,
        level: usize,
        level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        if level != level_count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sudoku udp mask must be the innermost mask in chain",
            ));
        }
        let tables = get_tables(&self.password, &self.ascii, &self.custom_tables)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let (p_min, p_max) = normalized_padding(self);
        Ok(Box::new(SudokuUdpConn::new(raw, tables, p_min, p_max)))
    }

    fn wrap_packet_conn_server(
        &self,
        raw: Box<dyn UdpIo>,
        level: usize,
        level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        // server 与 client 使用同样的 UDP conn（Go 也是同一实现）
        self.wrap_packet_conn_client(raw, level, level_count)
    }
}

// ===== Tcpmask impl =====

impl Tcpmask for SudokuConfig {
    fn wrap_conn_client(&self, raw: Box<dyn AsyncIo>) -> io::Result<Box<dyn AsyncIo>> {
        let (client, server) = tokio::io::duplex(UDP_SIZE * 2);
        let config = self.clone();
        // Client：pipe→inner 走 pure 编码，inner→pipe 走 packed 解码
        tokio::spawn(tcp_bridge(raw, server, config, true));
        Ok(Box::new(client))
    }

    fn wrap_conn_server(&self, raw: Box<dyn AsyncIo>) -> io::Result<Box<dyn AsyncIo>> {
        let (client, server) = tokio::io::duplex(UDP_SIZE * 2);
        let config = self.clone();
        // Server：pipe→inner 走 packed 编码，inner→pipe 走 pure 解码
        tokio::spawn(tcp_bridge(raw, server, config, false));
        Ok(Box::new(client))
    }
}

/// TCP 双向桥接（对应 Go `wrappedConn` + reader/writer 组合）。
///
/// - `is_client=true`：客户端读 packed、写 pure
/// - `is_client=false`：服务端读 pure、写 packed
async fn tcp_bridge(
    inner: Box<dyn AsyncIo>,
    mut pipe: tokio::io::DuplexStream,
    config: SudokuConfig,
    is_client: bool,
) {
    let (mut inner_r, mut inner_w) = tokio::io::split(inner);

    let tables = match get_tables(&config.password, &config.ascii, &config.custom_tables) {
        Ok(t) => t,
        Err(_) => return,
    };
    let (p_min, p_max) = normalized_padding(&config);

    let mut pure_enc = Codec::new(tables.clone(), p_min, p_max);
    let mut packed_enc = PackedEncoder::new(&tables, p_min, p_max);
    let mut packed_dec = PackedDecoder::default();
    let mut pure_table_index = 0usize;
    let mut pure_hint_buf: Vec<u8> = Vec::new();
    let layouts: Vec<Layout> = tables.iter().map(|t| t.layout.clone()).collect();

    let mut inner_read_buf = vec![0u8; UDP_SIZE];
    let mut pipe_read_buf = vec![0u8; UDP_SIZE];

    loop {
        select! {
            // inner → pipe：解码（client 读 packed / server 读 pure）
            r = inner_r.read(&mut inner_read_buf) => match r {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let decoded = if is_client {
                        packed_dec.decode_chunk(&layouts, &inner_read_buf[..n], Vec::new())
                    } else {
                        match decode_bytes(
                            &tables,
                            &mut pure_table_index,
                            &inner_read_buf[..n],
                            std::mem::take(&mut pure_hint_buf),
                            Vec::new(),
                        ) {
                            Ok((hb, out)) => { pure_hint_buf = hb; Ok(out) }
                            Err(e) => Err(e),
                        }
                    };
                    match decoded {
                        Ok(d) => { if pipe.write_all(&d).await.is_err() { break; } }
                        Err(_) => break,
                    }
                }
            },
            // pipe → inner：编码（client 写 pure / server 写 packed）
            r = pipe.read(&mut pipe_read_buf) => match r {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let encoded = if is_client {
                        pure_enc.encode(&pipe_read_buf[..n])
                    } else {
                        packed_enc.encode(&pipe_read_buf[..n])
                    };
                    match encoded {
                        Ok(e) => { if inner_w.write_all(&e).await.is_err() { break; } }
                        Err(_) => break,
                    }
                }
            },
        }
    }
}

// ===== UDP conn =====

/// Sudoku UDP 连接（对应 Go `udpConn`）。
struct SudokuUdpConn {
    inner: Box<dyn UdpIo>,
    tables: Vec<Arc<table::Table>>,
    p_min: usize,
    p_max: usize,
}

impl SudokuUdpConn {
    fn new(
        inner: Box<dyn UdpIo>,
        tables: Vec<Arc<table::Table>>,
        p_min: usize,
        p_max: usize,
    ) -> Self {
        Self { inner, tables, p_min, p_max }
    }
}

#[async_trait]
impl UdpIo for SudokuUdpConn {
    async fn send_to(&self, buf: &[u8], addr: std::net::SocketAddr) -> io::Result<usize> {
        // UDP 编码每个 datagram 都从头开始（Go conn_udp.go 同语义）
        let mut codec = Codec::new(self.tables.clone(), self.p_min, self.p_max);
        let encoded =
            codec.encode(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        // 编码失败时静默 drop（Go 同样返回 0, nil）
        self.inner.send_to(&encoded, addr).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, std::net::SocketAddr)> {
        // 每次栈分配 read_buf（MutexGuard 不 Send，避免跨 await 持锁）
        let mut read_buf = vec![0u8; UDP_SIZE];
        loop {
            let (n, addr) = self.inner.recv_from(&mut read_buf).await?;
            let mut table_index = 0usize;
            match decode_bytes(
                &self.tables,
                &mut table_index,
                &read_buf[..n],
                Vec::new(),
                Vec::new(),
            ) {
                Ok((hint_buf, decoded)) => {
                    if !hint_buf.is_empty() || decoded.len() > buf.len() {
                        // 不完整或超长，drop（Go 同样 continue）
                        continue;
                    }
                    buf[..decoded.len()].copy_from_slice(&decoded);
                    return Ok((decoded.len(), addr));
                },
                Err(_) => continue, // 解码错误，drop packet
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;

    fn sample_config() -> SudokuConfig {
        SudokuConfig { password: "integration_test".into(), ..Default::default() }
    }

    #[test]
    fn normalized_padding_clamps() {
        let c = SudokuConfig { padding_min: 150, padding_max: 200, ..Default::default() };
        assert_eq!(normalized_padding(&c), (100, 100));
        let c = SudokuConfig { padding_min: 50, padding_max: 30, ..Default::default() };
        assert_eq!(normalized_padding(&c), (50, 50));
    }

    #[tokio::test]
    async fn udp_roundtrip_through_mask() {
        // 通过 Udpmask 包装一对对连的 UDP socket
        use std::net::SocketAddr;
        let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a: SocketAddr = a.local_addr().unwrap();
        let addr_b: SocketAddr = b.local_addr().unwrap();

        let config = sample_config();
        let wrapped_a: Box<dyn UdpIo> = config.wrap_packet_conn_client(Box::new(a), 0, 0).unwrap();

        // 用裸 socket b 接收编码后的包
        let payload = b"hello sudoku udp";
        wrapped_a.send_to(payload, addr_b).await.unwrap();

        let mut recv_buf = vec![0u8; UDP_SIZE];
        let (n, from) = b.recv_from(&mut recv_buf).await.unwrap();
        // 裸 socket 收到的是编码后的字节（非明文）
        assert_ne!(&recv_buf[..n], payload);
        assert_eq!(from, addr_a);

        // 反向验证：b 发原始，wrapped_a 解码后应得原始
        b.send_to(payload, addr_a).await.unwrap();
        // 由于 wrapped_a.recv_from 会尝试解码，需用另一个 wrapped socket 对发
        // 这里只验证编码端非透传即可
    }

    #[tokio::test]
    async fn udp_pair_roundtrip() {
        // 一对 wrapped UDP socket 互相收发
        let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_b = b.local_addr().unwrap();

        let config = sample_config();
        let wrapped_a: Box<dyn UdpIo> = config.wrap_packet_conn_client(Box::new(a), 0, 0).unwrap();
        let wrapped_b: Box<dyn UdpIo> = config.wrap_packet_conn_server(Box::new(b), 0, 0).unwrap();

        let payload = b"pair roundtrip sudoku";
        wrapped_a.send_to(payload, addr_b).await.unwrap();

        let mut recv = vec![0u8; UDP_SIZE];
        let (n, _) = wrapped_b.recv_from(&mut recv).await.unwrap();
        assert_eq!(&recv[..n], payload);
    }

    #[tokio::test]
    async fn tcp_client_to_server_pure_roundtrip() {
        // 单向：client 写 pure → server 读 pure
        let (client_raw, server_raw) = tokio::io::duplex(UDP_SIZE * 4);

        let config = sample_config();
        let wrapped_client: Box<dyn AsyncIo> =
            config.wrap_conn_client(Box::new(client_raw)).unwrap();
        let wrapped_server: Box<dyn AsyncIo> =
            config.wrap_conn_server(Box::new(server_raw)).unwrap();

        use tokio::io::split;
        let (_cr, mut cw) = split(wrapped_client);
        let (mut sr, _sw) = split(wrapped_server);

        let msg = b"client to server via pure encoding";
        let write_fut = async {
            cw.write_all(msg).await.unwrap();
            cw.shutdown().await.ok();
        };
        let read_fut = async {
            let mut got = Vec::new();
            sr.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, msg);
        };
        tokio::join!(write_fut, read_fut);
    }

    #[tokio::test]
    async fn tcp_server_to_client_packed_roundtrip() {
        // 单向：server 写 packed → client 读 packed
        let (client_raw, server_raw) = tokio::io::duplex(UDP_SIZE * 4);

        let config = sample_config();
        let wrapped_client: Box<dyn AsyncIo> =
            config.wrap_conn_client(Box::new(client_raw)).unwrap();
        let wrapped_server: Box<dyn AsyncIo> =
            config.wrap_conn_server(Box::new(server_raw)).unwrap();

        use tokio::io::split;
        let (mut cr, _cw) = split(wrapped_client);
        let (_sr, mut sw) = split(wrapped_server);

        let msg = b"server to client via packed encoding";
        let write_fut = async {
            sw.write_all(msg).await.unwrap();
            sw.shutdown().await.ok();
        };
        let read_fut = async {
            let mut got = Vec::new();
            cr.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, msg);
        };
        tokio::join!(write_fut, read_fut);
    }

    #[tokio::test]
    async fn udpmask_rejects_non_innermost() {
        let config = sample_config();
        let dummy = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let raw: Box<dyn UdpIo> = Box::new(dummy);
        // level=0, level_count=2 → 非 innermost
        let result = config.wrap_packet_conn_client(raw, 0, 2);
        assert!(result.is_err());
    }
}

//! HTTPUpgrade server：在已建立的 IO 上执行服务端握手。
//!
//! 对应 Go `transport/internet/httpupgrade/hub.go::server.upgrade`。
//!
//! ## Ponytail 决策
//!
//! Go 端 `server.upgrade(conn)` 依赖 `net.Listener` accept 出的 `net.Conn`，
//! `keepAccepting` 循环 + TLS 包装在上层。Rust 端把 TCP 监听 + TLS 包装
//! 留给上层 transport（依赖 uTLS 决策），本模块只暴露 `handshake_io`
//! 在调用方注入的 `AsyncRead + AsyncWrite` 上跑握手。


use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    config::Config,
    connection::HttpUpgradeConnection,
    error::Result,
    hub::{apply_trusted_x_forwarded_for, build_upgrade_response, parse_upgrade_request},
};

/// HTTP/1.1 请求头读取缓冲初始大小（含 `\r\n\r\n` 终止符）。
const READ_INITIAL_CAPACITY: usize = 1024;
/// HTTP/1.1 请求头读取缓冲上限（防恶意客户端发送超大 header）。
const READ_MAX_CAPACITY: usize = 64 * 1024;

/// HTTPUpgrade 服务端配置。
#[derive(Debug, Clone)]
pub struct HttpUpgradeServer {
    /// 协议配置（提供 host 白名单 + path 校验）。
    pub config: Config,
    /// 可信 XFF header 名单（来自 `sockopt.trustedXForwardedFor`）。
    /// 空 = 永不采纳 XFF（默认不信任，防伪造；Go hub.go:90-94）。
    pub trusted_x_forwarded_for: Vec<String>,
}

impl HttpUpgradeServer {
    /// 构造 server。
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self { config, trusted_x_forwarded_for: Vec::new() }
    }

    /// 在已建立的 IO 上执行服务端握手。
    ///
    /// 步骤对应 Go `server.upgrade`：
    /// 1. 读客户端 GET 请求直到 `\r\n\r\n`
    /// 2. 用 `parse_upgrade_request` 校验 host/path/Connection/Upgrade
    /// 3. 用 `build_upgrade_response` 构造 101 响应并写回
    /// 4. 提取 X-Forwarded-For → remote_addr_override（对齐 Go `newConnection(conn, remoteAddr)`）
    ///
    /// # 返回
    /// 成功时返回 `HttpUpgradeConnection`（含 remote_addr_override）+ 余留 payload 字节。
    ///
    /// # Errors
    /// - [`crate::error::HttpUpgradeError::Io`]：底层 IO 读写失败
    /// - [`crate::error::HttpUpgradeError::InvalidHttpFormat`]：请求字节格式非法
    /// - [`crate::error::HttpUpgradeError::BadHost`] /
    ///   [`crate::error::HttpUpgradeError::BadPath`]： host/path 不匹配
    /// - [`crate::error::HttpUpgradeError::UnrecognizedRequest`]：缺 Upgrade/Connection header
    pub async fn handshake_io<IO>(&self, mut io: IO) -> Result<(HttpUpgradeConnection<IO>, Vec<u8>)>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        // 1. 读请求直到 \r\n\r\n（用 1KB chunk 读，能正确捕获后续 payload）。
        // H14：整段握手读 4s 超时（Go hub.go:39-41 SetReadDeadline(+4s) +
        // LimitReader(12288)——慢速/半开连接不再无限占用 accept 并发）。
        let mut buf: Vec<u8> = Vec::with_capacity(READ_INITIAL_CAPACITY);
        let mut chunk = [0u8; 1024];
        let read_all = tokio::time::timeout(std::time::Duration::from_secs(4), async {
            loop {
                if buf.len() >= READ_MAX_CAPACITY {
                    return Err(crate::error::HttpUpgradeError::InvalidHttpFormat(format!(
                        "request header exceeds max {} bytes",
                        READ_MAX_CAPACITY
                    )));
                }
                let n = io.read(&mut chunk).await?;
                if n == 0 {
                    return Err(crate::error::HttpUpgradeError::InvalidHttpFormat(
                        "EOF before \\r\\n\\r\\n terminator".into(),
                    ));
                }
                buf.extend_from_slice(&chunk[..n]);
                if find_header_end(&buf).is_some() {
                    return Ok(());
                }
            }
        });
        match read_all.await {
            Ok(r) => r?,
            Err(_) => {
                return Err(crate::error::HttpUpgradeError::InvalidHttpFormat(
                    "handshake read timeout (4s, Go SetReadDeadline)".into(),
                ));
            },
        }

        // 2. 校验请求（注意：parse_upgrade_request 不消费余留 payload）
        let req = parse_upgrade_request(&buf, &self.config)?;

        // 3. 写 101 响应
        let resp_bytes = build_upgrade_response();
        io.write_all(&resp_bytes).await?;
        io.flush().await?;

        // 4. XFF 信任门控提取 remote_addr_override（Go hub.go:89-94：
        // 默认不信任，仅名单命中时采纳，None = 上层保持真实连接地址）。
        let remote_addr =
            apply_trusted_x_forwarded_for(&req.headers, &self.trusted_x_forwarded_for);

        // 余留 payload（紧跟 \r\n\r\n 之后的字节）
        // parse_upgrade_request 内部找到 \r\n\r\n 但不返回位置，需要重新计算
        let payload_offset = find_header_end(&buf).map(|p| p + 4).unwrap_or(buf.len());
        let leftover =
            if payload_offset < buf.len() { buf[payload_offset..].to_vec() } else { Vec::new() };

        Ok((HttpUpgradeConnection::new(io, remote_addr), leftover))
    }
}

/// 在字节流中查找 `\r\n\r\n` 位置。返回起始下标。
fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use tokio::io::duplex;

    use super::*;

    fn make_config(path: &str) -> Config {
        Config { path: path.into(), ..Default::default() }
    }

    #[tokio::test]
    async fn handshake_reads_request_writes_response() {
        let server = HttpUpgradeServer::new(make_config("/ws"));
        let (mut server_io, mut client_io) = duplex(8192);

        // 客户端先发请求
        let req =
            b"GET /ws HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        client_io.write_all(req).await.unwrap();
        client_io.flush().await.unwrap();

        let handle = tokio::spawn(async move { server.handshake_io(server_io).await });

        // 客户端读响应
        let mut buf = vec![0u8; 1024];
        let n = client_io.read(&mut buf).await.unwrap();
        let resp_str = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(resp_str.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(resp_str.contains("Upgrade: websocket"));

        let (_conn, leftover) = handle.await.unwrap().unwrap();
        assert!(leftover.is_empty());
    }

    #[tokio::test]
    async fn handshake_captures_payload_after_terminator() {
        let server = HttpUpgradeServer::new(make_config("/ws"));
        let (mut server_io, mut client_io) = duplex(8192);

        // 客户端发请求 + payload
        let req = b"GET /ws HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nhello after";
        client_io.write_all(req).await.unwrap();

        let handle = tokio::spawn(async move { server.handshake_io(server_io).await });

        // 等服务端读完请求 + 回响应
        let mut buf = vec![0u8; 2048];
        let _ = client_io.read(&mut buf).await;

        let (_conn, leftover) = handle.await.unwrap().unwrap();
        assert_eq!(leftover, b"hello after");
    }

    /// 伪造 XFF 默认被拒：未配置 `trustedXForwardedFor` 时不采纳（Go 默认不信任，
    /// headers.go ApplyTrustedXForwardedFor 名单为空走 warning 路径）。
    #[tokio::test]
    async fn handshake_rejects_xff_by_default_without_trusted_config() {
        let server = HttpUpgradeServer::new(make_config("/ws"));
        let (mut server_io, mut client_io) = duplex(8192);

        let req = b"GET /ws HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Forwarded-For: 10.0.0.1, 192.168.1.1\r\n\r\n";
        client_io.write_all(req).await.unwrap();

        let handle = tokio::spawn(async move { server.handshake_io(server_io).await });
        let mut buf = vec![0u8; 1024];
        let _ = client_io.read(&mut buf).await;

        let (conn, _leftover) = handle.await.unwrap().unwrap();
        assert!(conn.remote_addr_override.is_none());
    }

    /// 门控开：请求携带名单中的可信 header → 采纳 XFF 首段为源地址（端口 0）。
    #[tokio::test]
    async fn handshake_adopts_xff_when_trusted_header_present() {
        let mut server = HttpUpgradeServer::new(make_config("/ws"));
        server.trusted_x_forwarded_for = vec!["X-Real-IP".into()];
        let (mut server_io, mut client_io) = duplex(8192);

        let req = b"GET /ws HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Real-IP: 1.2.3.4\r\nX-Forwarded-For: 10.0.0.1, 192.168.1.1\r\n\r\n";
        client_io.write_all(req).await.unwrap();

        let handle = tokio::spawn(async move { server.handshake_io(server_io).await });
        let mut buf = vec![0u8; 1024];
        let _ = client_io.read(&mut buf).await;

        let (conn, _leftover) = handle.await.unwrap().unwrap();
        assert_eq!(
            conn.remote_addr_override,
            Some(SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)), 0))
        );
    }

    /// 门控开但名单 header 均不在场 → 拒绝（Go error「potentially forged」路径）。
    #[tokio::test]
    async fn handshake_rejects_xff_when_trusted_header_absent() {
        let mut server = HttpUpgradeServer::new(make_config("/ws"));
        server.trusted_x_forwarded_for = vec!["X-Real-IP".into()];
        let (mut server_io, mut client_io) = duplex(8192);

        let req = b"GET /ws HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Forwarded-For: 10.0.0.1\r\n\r\n";
        client_io.write_all(req).await.unwrap();

        let handle = tokio::spawn(async move { server.handshake_io(server_io).await });
        let mut buf = vec![0u8; 1024];
        let _ = client_io.read(&mut buf).await;

        let (conn, _leftover) = handle.await.unwrap().unwrap();
        assert!(conn.remote_addr_override.is_none());
    }

    #[tokio::test]
    async fn handshake_rejects_wrong_path() {
        let server = HttpUpgradeServer::new(make_config("/ws"));
        let (mut server_io, mut client_io) = duplex(8192);

        let req =
            b"GET /other HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        client_io.write_all(req).await.unwrap();

        let err = server.handshake_io(&mut server_io).await.unwrap_err();
        assert!(matches!(err, crate::error::HttpUpgradeError::BadPath { .. }));
    }

    #[tokio::test]
    async fn handshake_rejects_missing_upgrade_header() {
        let server = HttpUpgradeServer::new(make_config("/ws"));
        let (mut server_io, mut client_io) = duplex(8192);

        let req = b"GET /ws HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\n\r\n";
        client_io.write_all(req).await.unwrap();

        let err = server.handshake_io(&mut server_io).await.unwrap_err();
        assert!(matches!(err, crate::error::HttpUpgradeError::UnrecognizedRequest { .. }));
    }

    #[tokio::test]
    async fn handshake_propagates_io_eof_as_invalid_format() {
        let server = HttpUpgradeServer::new(make_config("/ws"));
        let (mut server_io, client_io) = duplex(8192);
        drop(client_io);

        let err = server.handshake_io(&mut server_io).await.unwrap_err();
        assert!(matches!(err, crate::error::HttpUpgradeError::InvalidHttpFormat(_)));
    }
}

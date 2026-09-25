//! HTTPUpgrade client：在已建立的 TCP/TLS IO 上执行客户端握手。
//!
//! 对应 Go `transport/internet/httpupgrade/dialer.go::dialhttpUpgrade`。
//!
//! ## Ponytail 决策
//!
//! Go 端在 dialhttpUpgrade 内部完成 `internet.DialSystem` 拨号 + TLS 包装 +
//! `req.Write(conn)`。Rust 端把 TCP/TLS 拨号留给上层 transport（依赖
//! uTLS 决策，由 `k9t reality-s2` 解锁），本模块只暴露 `dial_over_io`
//! 在调用方注入的 `AsyncRead + AsyncWrite` 上跑握手，把 bytes 层和 IO 层解耦。

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    config::Config,
    connection::HttpUpgradeConnection,
    deferred::DeferredResponseReader,
    dialer::{build_upgrade_request, parse_upgrade_response},
    error::Result,
};

/// HTTP/1.1 响应头读取缓冲初始大小（含 `\r\n\r\n` 终止符）。
const READ_INITIAL_CAPACITY: usize = 1024;
/// HTTP/1.1 响应头读取缓冲上限（防恶意服务端发送超大 header）。
const READ_MAX_CAPACITY: usize = 64 * 1024;

/// HTTPUpgrade 客户端，持配置 + 主机名。
///
/// 调用方先建立底层 IO（TCP/TLS），然后用 `dial_over_io` 跑握手拿到
/// 包装后的 [`HttpUpgradeConnection`]。
#[derive(Debug, Clone)]
pub struct HttpUpgradeClient {
    /// 已构造的握手请求 host（来自 [`Config::host`] 或上层 dest 地址）。
    pub host: String,
    /// 协议配置（提供 path + 自定义 header + ed）。
    pub config: Config,
}

impl HttpUpgradeClient {
    /// 构造 client。`host` 不可空（由调用方保证，Go 端用 dest.Address 兜底）。
    #[must_use]
    pub fn new(host: String, config: Config) -> Self {
        Self { host, config }
    }

    /// 在已建立的 IO 上执行客户端握手。
    ///
    /// 步骤对应 Go `dialhttpUpgrade` 后半段：
    /// 1. 用 `build_upgrade_request` 构造 GET 字节流并全量写入 IO
    /// 2. 读响应直到遇到 `\r\n\r\n`
    /// 3. 用 `parse_upgrade_response` 校验 101 状态 + Upgrade/Connection header
    /// 4. 若响应末尾后还有字节（payload），保留在 HttpUpgradeConnection 内部 由调用方继续读取（对齐
    ///    Go `ConnRF` 行为）
    ///
    /// # 返回
    /// 成功时返回 `HttpUpgradeConnection` 包装的底层 IO + 余留 payload 字节。
    /// 余留字节对 `ed > 0` 的 0-RTT 场景至关重要——服务端可能紧跟响应后
    /// 立即发送数据。
    ///
    /// # Errors
    /// - [`crate::error::HttpUpgradeError::Io`]：底层 IO 读写失败
    /// - [`crate::error::HttpUpgradeError::InvalidHttpFormat`]：响应字节格式非法
    /// - [`crate::error::HttpUpgradeError::UnrecognizedReply`]：状态/header 校验失败
    pub async fn dial_over_io<IO>(&self, mut io: IO) -> Result<(HttpUpgradeConnection<IO>, Vec<u8>)>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        // 1. 写请求
        let req_bytes = build_upgrade_request(&self.host, &self.config);
        io.write_all(&req_bytes).await?;
        io.flush().await?;

        // 注：ed > 0 的 0-RTT 场景由 `dial_over_io_deferred` 处理（延迟读 101），
        // 本方法始终立即读响应。

        // 2. 读响应直到 \r\n\r\n
        let mut buf: Vec<u8> = Vec::with_capacity(READ_INITIAL_CAPACITY);
        let mut chunk = [0u8; 1024];
        loop {
            if buf.len() >= READ_MAX_CAPACITY {
                return Err(crate::error::HttpUpgradeError::InvalidHttpFormat(format!(
                    "response header exceeds max {} bytes",
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
                break;
            }
        }

        // 3. 校验响应
        let payload_offset = parse_upgrade_response(&buf)?;

        // 4. 提取余留 payload（如有）
        let leftover =
            if payload_offset < buf.len() { buf[payload_offset..].to_vec() } else { Vec::new() };

        Ok((HttpUpgradeConnection::new(io, None), leftover))
    }

    /// 在已建立的 IO 上执行客户端握手，ed > 0 时延迟读 101 响应（0-RTT）。
    ///
    /// 与 `dial_over_io` 相同，但返回 `DeferredResponseReader` 包装，
    /// 首次 `AsyncRead::poll_read` 时才解析 101 响应。
    /// 调用方根据 `config.ed > 0` 选择此方法。
    pub async fn dial_over_io_deferred<IO>(
        &self,
        mut io: IO,
    ) -> Result<HttpUpgradeConnection<DeferredResponseReader<IO>>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        // 1. 写请求
        let req_bytes = build_upgrade_request(&self.host, &self.config);
        io.write_all(&req_bytes).await?;
        io.flush().await?;

        // ed > 0：不读 101，让上层先写 early data
        let deferred = DeferredResponseReader::new(io);
        Ok(HttpUpgradeConnection::new(deferred, None))
    }
}

/// 在字节流中查找 `\r\n\r\n`（header 终止符）位置。返回起始下标。
fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, duplex};

    use super::*;

    #[tokio::test]
    async fn dial_writes_request_and_reads_101_response() {
        let client = HttpUpgradeClient::new(
            "example.com".into(),
            Config { path: "/ws".into(), ..Default::default() },
        );

        // duplex 模拟 server 端
        let (client_io, mut server_io) = duplex(8192);

        // 客户端跑握手（在另一任务，因为 duplex 双向）
        let handle = tokio::spawn(async move { client.dial_over_io(client_io).await });

        // 服务端：读客户端请求
        let mut req_buf = vec![0u8; 4096];
        let n = server_io.read(&mut req_buf).await.unwrap();
        let req_str = std::str::from_utf8(&req_buf[..n]).unwrap();
        assert!(req_str.starts_with("GET /ws HTTP/1.1\r\n"));
        assert!(req_str.contains("Host: example.com"));
        assert!(req_str.contains("Upgrade: websocket"));

        // 服务端：回 101 响应
        let resp = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        server_io.write_all(resp).await.unwrap();
        server_io.flush().await.unwrap();

        // 等客户端完成
        let (conn, leftover) = handle.await.unwrap().unwrap();
        assert!(leftover.is_empty());
        // 验证 conn 可以继续读写 raw bytes
        let _ = conn;
    }

    #[tokio::test]
    async fn dial_captures_payload_after_response() {
        let client =
            HttpUpgradeClient::new("h".into(), Config { path: "/".into(), ..Default::default() });
        let (client_io, mut server_io) = duplex(8192);
        let handle = tokio::spawn(async move { client.dial_over_io(client_io).await });

        // 服务端先读请求再写响应 + payload
        let mut buf = vec![0u8; 4096];
        let _ = server_io.read(&mut buf).await.unwrap();
        let resp = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nhello payload";
        server_io.write_all(resp).await.unwrap();
        server_io.flush().await.unwrap();

        let (_conn, leftover) = handle.await.unwrap().unwrap();
        assert_eq!(leftover, b"hello payload");
    }

    #[tokio::test]
    async fn dial_rejects_non_101_response() {
        let client = HttpUpgradeClient::new("h".into(), Config::default());
        let (client_io, mut server_io) = duplex(8192);
        let handle = tokio::spawn(async move { client.dial_over_io(client_io).await });

        let mut buf = vec![0u8; 4096];
        let _ = server_io.read(&mut buf).await.unwrap();
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        server_io.write_all(resp).await.unwrap();

        let err = handle.await.unwrap().unwrap_err();
        assert!(matches!(err, crate::error::HttpUpgradeError::UnrecognizedReply { .. }));
    }

    #[tokio::test]
    async fn dial_propagates_io_eof_as_invalid_format() {
        // 服务端立刻关闭连接
        let client = HttpUpgradeClient::new("h".into(), Config::default());
        let (mut client_io, server_io) = duplex(8192);
        drop(server_io);

        let err = client.dial_over_io(&mut client_io).await.unwrap_err();
        // 服务端断连：EOF 返 InvalidHttpFormat，或 BrokenPipe 返 Io —— 都算协议失败
        match err {
            crate::error::HttpUpgradeError::InvalidHttpFormat(_) => {},
            crate::error::HttpUpgradeError::Io(_) => {},
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

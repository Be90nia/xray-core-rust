//! TUIC v5 客户端（切片1：TCP relay）。
//!
//! API：
//! - [`TuicClient::connect`]：与远端 QUIC server 建立连接并完成认证
//! - [`TuicClient::dial`]：对目标地址发起 TCP relay，返回 (SendStream, RecvStream) pair
//!
//! 切片2 待办：UDP relay（dial_udp + 分片）。

use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::sync::Arc;

use bytes::BytesMut;
use uuid::Uuid;

use crate::error::{Result, TuicError};
use crate::protocol::address::Address;
use crate::protocol::command::TOKEN_LEN;

/// TUIC 客户端。包装已认证的 quinn 连接。
#[derive(Clone)]
pub struct TuicClient {
    conn: quinn::Connection,
}

/// TUIC TCP relay 流（双向，分两半）。
///
/// ponytail: quinn 0.11 SendStream/RecvStream 不直接 impl tokio AsyncRead/AsyncWrite
/// （错误类型是 quinn::WriteError/ReadError，不是 io::Error），所以不强行 wrap。
/// 调用方直接用 `send`/`recv` 的 async 方法（write_all / read 等）。
pub struct TuicConn {
    /// 发送流（写入数据到代理）。
    pub send: quinn::SendStream,
    /// 接收流（从代理读取数据）。
    pub recv: quinn::RecvStream,
}

impl TuicConn {
    /// 拆分为 send/recv 两半。
    pub fn into_split(self) -> (quinn::SendStream, quinn::RecvStream) {
        (self.send, self.recv)
    }
}

impl TuicClient {
    /// 与 TUIC server 建立 QUIC 连接并完成认证。
    ///
    /// 流程：
    /// 1. quinn Endpoint → dial UDP → connect (alpn "h3"/"tuic")
    /// 2. export_keying_material 生成 token
    /// 3. open_uni → 写入 Authenticate 帧
    ///
    /// `password` 经 TLS keying material exporter 派生 token，不直接传输。
    pub async fn connect(
        server: impl ToSocketAddrs,
        server_name: &str,
        uuid: Uuid,
        password: &str,
        rustls_config: Arc<rustls::ClientConfig>,
    ) -> Result<Self> {
        // ponytail: TUIC v5 要求 ALPN，在内部强制设置避免用户忘记
        let mut rustls_config = (*rustls_config).clone();
        rustls_config.alpn_protocols = vec![b"h3".to_vec(), b"tuic".to_vec()];
        let rustls_config = Arc::new(rustls_config);

        let quinn_client_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
                .map_err(|e| TuicError::Io(std::io::Error::other(format!("quinn rustls client convert: {e}"))))?,
        ));
        let mut transport = quinn::TransportConfig::default();
        transport.datagram_receive_buffer_size(Some(8 * 1024));
        let mut quinn_client_cfg = quinn_client_cfg;
        quinn_client_cfg.transport_config(Arc::new(transport));

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| TuicError::Io(std::io::Error::other(format!("endpoint bind: {e}"))))?;
        endpoint.set_default_client_config(quinn_client_cfg);
        let server_addr = server.to_socket_addrs()?.next().ok_or_else(|| {
            std::io::Error::other("to_socket_addrs returned empty")
        })?;

        let conn = endpoint
            .connect(server_addr, server_name)
            .map_err(|e| TuicError::Io(std::io::Error::other(format!("quinn connect: {e}"))))?
            .await?;

        // 生成 token：label = uuid str, context = password bytes
        let mut token = [0u8; TOKEN_LEN];
        let uuid_str = uuid.to_string();
        conn.export_keying_material(&mut token, uuid_str.as_bytes(), password.as_bytes())
            .map_err(|_| TuicError::KeyingMaterialExport)?;

        // open uni stream → write Authenticate
        let mut uni = conn.open_uni().await?;
        let cmd = crate::protocol::Command::Authenticate {
            uuid_bytes: *uuid.as_bytes(),
            token,
        };
        let mut buf = BytesMut::with_capacity(cmd.encoded_len());
        cmd.write_to(&mut buf);
        uni.write_all(&buf).await?;
        let _ = uni.finish();

        Ok(Self { conn })
    }

    /// 对目标地址发起 TCP relay。
    ///
    /// 通过 bi stream 写入 Connect 命令，之后 stream 即 TCP relay 通道。
    pub async fn dial(&self, target: Address) -> Result<TuicConn> {
        let (mut send, recv) = self.conn.open_bi().await?;
        let cmd = crate::protocol::Command::Connect(target);
        let mut buf = BytesMut::with_capacity(cmd.encoded_len());
        cmd.write_to(&mut buf);
        send.write_all(&buf).await?;
        Ok(TuicConn { send, recv })
    }

    /// 发送心跳（uni stream）。
    pub async fn heartbeat(&self) -> Result<()> {
        let mut uni = self.conn.open_uni().await?;
        let cmd = crate::protocol::Command::Heartbeat;
        let mut buf = BytesMut::with_capacity(cmd.encoded_len());
        cmd.write_to(&mut buf);
        uni.write_all(&buf).await?;
        let _ = uni.finish();
        Ok(())
    }

    /// 关闭底层 QUIC 连接。
    pub fn close(&self, error_code: quinn::VarInt, reason: &[u8]) {
        self.conn.close(error_code, reason);
    }

    /// 共享底层 quinn 连接（高级用户可用）。
    #[must_use]
    pub fn quinn_conn(&self) -> &quinn::Connection {
        &self.conn
    }
}

/// 解析地址（客户端 dial 时 `server: impl ToSocketAddrs`）。
#[allow(dead_code)]
pub(crate) fn resolve_first(addr: impl ToSocketAddrs) -> Result<SocketAddr> {
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::other("to_socket_addrs returned empty"))
        .map_err(Into::into)
}

//! TUIC v5 客户端（切片1：TCP relay + 连接池复用）。
//!
//! API：
//! - [`TuicClient::connect`]：与远端 QUIC server 建立连接并完成认证（复用连接池）
//! - [`TuicClient::dial`]：对目标地址发起 TCP relay（复用已有 QUIC 连接上的 bi-stream）
//! - [`TuicClient::dial_udp`]：分配 UDP 关联，返回 [`TuicUdpAssoc`]（UDP relay 句柄）
//!
//! ## HTTP/3 传输
//!
//! TUIC v5 客户端在 QUIC 握手时同时提供 ALPN `h3` 与 `tuic`，
//! 实现 HTTP/3 伪装（camouflage）——服务端只看到合法 H3 流量，
//! 这是 TUIC 官方推荐的 h3 传输模式。
//! 完整 HTTP/3 帧封装（real-h3 mode）未实现，ALPN 协商已足够。
//!
//! ## 连接池
//!
//! 通过 [`crate::pool::QuinnConnectionPool`] 复用 QUIC 连接，避免每次 dial 新建 endpoint。
//! 连接池 key = (server_addr, server_name, alpn)。

use crate::pool::{MultiplexedConnection, PoolKey, QuinnConnectionPool, ReconnectingConnection};
use crate::udp::TuicUdpAssoc;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::sync::Arc;

use bytes::BytesMut;
use uuid::Uuid;

use crate::error::{Result, TuicError};
use crate::protocol::address::Address;
use crate::protocol::command::TOKEN_LEN;

/// TUIC 客户端。包装已认证的 quinn 连接，支持连接池复用。
#[derive(Clone)]
pub struct TuicClient {
    /// 复用的 QUIC 连接（通过连接池管理）。
    multiplexed: MultiplexedConnection,
    /// 连接池引用（用于后续重连）。
    pool: QuinnConnectionPool,
    /// 连接参数（用于重连时重建）。
    key: PoolKey,
    /// UUID（认证用）。
    uuid: Uuid,
    /// 密码（认证用）。
    password: String,
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
    /// 与 TUIC server 建立 QUIC 连接并完成认证（复用连接池）。
    ///
    /// 流程：
    /// 1. 连接池查 key，无则新建 endpoint + connect
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
        pool: QuinnConnectionPool,
    ) -> Result<Self> {
        let server_addr = server.to_socket_addrs()?.next().ok_or_else(|| {
            std::io::Error::other("to_socket_addrs returned empty")
        })?;

        // 构造连接池 key
        let key = PoolKey::new(
            server_addr,
            server_name,
            &rustls_config.alpn_protocols,
        );

        // 构造重连包装
        let reconnect = ReconnectingConnection::new(pool.clone(), key.clone());

        // 获取或新建连接
        let pooled = reconnect
            .get_or_reconnect(|| {
                let rustls_config = rustls_config.clone();
                let server_name = server_name.to_string();
                async move {
                    Self::create_quic_connection(server_addr, &server_name, rustls_config).await
                }
            })
            .await?;

        // 认证
        let mut token = [0u8; TOKEN_LEN];
        let uuid_str = uuid.to_string();
        pooled
            .conn
            .export_keying_material(&mut token, uuid_str.as_bytes(), password.as_bytes())
            .map_err(|_| TuicError::KeyingMaterialExport)?;

        // open uni stream → write Authenticate
        let mut uni = pooled.conn.open_uni().await?;
        let cmd = crate::protocol::Command::Authenticate {
            uuid_bytes: *uuid.as_bytes(),
            token,
        };
        let mut buf = BytesMut::with_capacity(cmd.encoded_len());
        cmd.write_to(&mut buf);
        uni.write_all(&buf).await?;
        let _ = uni.finish();

        let multiplexed = MultiplexedConnection::new(pooled);

        Ok(Self {
            multiplexed,
            pool,
            key,
            uuid,
            password: password.to_string(),
        })
    }

    /// 内部：新建 QUIC 连接（无池复用路径）。
    async fn create_quic_connection(
        server_addr: SocketAddr,
        server_name: &str,
        rustls_config: Arc<rustls::ClientConfig>,
    ) -> Result<quinn::Connection> {
        // TUIC v5 要求 ALPN，在内部强制设置避免用户忘记
        let mut rustls_config = (*rustls_config).clone();
        rustls_config.alpn_protocols = vec![b"h3".to_vec(), b"tuic".to_vec()];
        let rustls_config = Arc::new(rustls_config);

        let quinn_client_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
                .map_err(|e| {
                    TuicError::Io(std::io::Error::other(format!(
                        "quinn rustls client convert: {e}"
                    )))
                })?,
        ));
        let mut transport = quinn::TransportConfig::default();
        transport.datagram_receive_buffer_size(Some(8 * 1024));
        let mut quinn_client_cfg = quinn_client_cfg;
        quinn_client_cfg.transport_config(Arc::new(transport));

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| {
                TuicError::Io(std::io::Error::other(format!("endpoint bind: {e}")))
            })?;
        endpoint.set_default_client_config(quinn_client_cfg);

        let conn = endpoint
            .connect(server_addr, server_name)
            .map_err(|e| {
                TuicError::Io(std::io::Error::other(format!("quinn connect: {e}")))
            })?
            .await?;

        Ok(conn)
    }

    /// 对目标地址发起 TCP relay。
    ///
    /// 通过 bi stream 写入 Connect 命令，之后 stream 即 TCP relay 通道。
    pub async fn dial(&self, target: Address) -> Result<TuicConn> {
        let (mut send, recv) = self.multiplexed.open_bi().await?;
        let cmd = crate::protocol::Command::Connect(target);
        let mut buf = BytesMut::with_capacity(cmd.encoded_len());
        cmd.write_to(&mut buf);
        send.write_all(&buf).await?;
        Ok(TuicConn { send, recv })
    }

    /// 发送心跳（uni stream）。
    pub async fn heartbeat(&self) -> Result<()> {
        let mut uni = self.multiplexed.open_uni().await?;
        let cmd = crate::protocol::Command::Heartbeat;
        let mut buf = BytesMut::with_capacity(cmd.encoded_len());
        cmd.write_to(&mut buf);
        uni.write_all(&buf).await?;
        let _ = uni.finish();
        Ok(())
    }

    /// 关闭底层 QUIC 连接。
    pub fn close(&self, error_code: quinn::VarInt, reason: &[u8]) {
        self.multiplexed.close(error_code, reason);
    }

    /// 共享底层 quinn 连接（高级用户可用）。
    #[must_use]
    pub fn quinn_conn(&self) -> &quinn::Connection {
        &self.multiplexed.pooled.conn
    }

    /// 分配 UDP 关联（assoc_id），返回 UDP relay 句柄。
    ///
    /// `assoc_id` 由调用方指定（客户端负责任意分配），同一关联内 UDP 包共用
    /// 一个逻辑会话。后续调用 [`TuicUdpAssoc::send_recv`] 发送/接收 UDP 包。
    #[must_use]
    pub fn dial_udp(&self, assoc_id: u16) -> TuicUdpAssoc {
        TuicUdpAssoc::new(self.multiplexed.pooled.conn.clone(), assoc_id)
    }

    /// 发送 QUIC DATAGRAM（native UDP 模式）。
    pub fn send_datagram(&self, data: bytes::Bytes) -> Result<()> {
        self.multiplexed.send_datagram(data)
    }

    /// 接收 QUIC DATAGRAM（native UDP 模式）。
    pub async fn recv_datagram(&self) -> Result<bytes::Bytes> {
        self.multiplexed.recv_datagram().await
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

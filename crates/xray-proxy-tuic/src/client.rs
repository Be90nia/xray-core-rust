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

use bytes::{BufMut, BytesMut};
use uuid::Uuid;

use crate::error::{Result, TuicError};
use crate::protocol::address::Address;
use crate::protocol::command::TOKEN_LEN;
use crate::protocol::command::type_code;
use crate::udp::UniRespRouter;

/// 拥塞控制算法（官方 tuic-client `congestion_control`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CongestionControl {
    /// BBR（官方默认，Itsusinn/tuic config.rs `CongestionControl::Bbr`）。
    #[default]
    Bbr,
    /// CUBIC。
    Cubic,
    /// New Reno——quinn 无内置实现，构建时回落 CUBIC。
    NewReno,
}

impl CongestionControl {
    /// 解析配置名（大小写不敏感）。未知值 → `None`（由配置层报错）。
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "bbr" => Some(Self::Bbr),
            "cubic" => Some(Self::Cubic),
            "new_reno" | "newreno" => Some(Self::NewReno),
            _ => None,
        }
    }
}

/// UDP relay 模式（官方 tuic-client `udp_relay_mode`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UdpRelayMode {
    /// native：QUIC DATAGRAM，保留 UDP 不可靠语义（官方默认）。
    #[default]
    Native,
    /// quic：每包一个 bi-stream（可靠有序）。
    Quic,
}

impl UdpRelayMode {
    /// 解析配置名（大小写不敏感）。未知值 → `None`（由配置层报错）。
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "native" => Some(Self::Native),
            "quic" => Some(Self::Quic),
            _ => None,
        }
    }
}

/// TUIC outbound 连接选项（对应官方 tuic-client relay 配置子集，bd 7p0）。
///
/// 默认值对齐官方：`congestion_control=bbr`、`udp_relay_mode=native`、`heartbeat=3s`。
#[derive(Debug, Clone)]
pub struct TuicConnectOptions {
    /// 拥塞控制算法。
    pub congestion_control: CongestionControl,
    /// 心跳周期（官方默认 3s）。
    pub heartbeat: std::time::Duration,
    /// UDP relay 模式。
    ///
    /// 决定 [`TuicUdpAssoc::send_recv`]（quic uni-stream）与
    /// [`TuicUdpAssoc::send_recv_native`]（QUIC DATAGRAM）哪个作为
    /// dispatcher UDP 分支的承载方式。
    pub udp_relay_mode: UdpRelayMode,
}

impl Default for TuicConnectOptions {
    fn default() -> Self {
        Self {
            congestion_control: CongestionControl::Bbr,
            heartbeat: std::time::Duration::from_secs(3),
            udp_relay_mode: UdpRelayMode::Native,
        }
    }
}

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
    /// quic 模式 UDP 响应路由（per-connection uni-stream pump）。
    router: UniRespRouter,
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
        Self::connect_with(
            server,
            server_name,
            uuid,
            password,
            rustls_config,
            TuicConnectOptions::default(),
            pool,
        )
        .await
    }

    /// [`connect`](Self::connect) 的完整版：带连接选项（拥塞控制/心跳/UDP relay 模式）。
    pub async fn connect_with(
        server: impl ToSocketAddrs,
        server_name: &str,
        uuid: Uuid,
        password: &str,
        rustls_config: Arc<rustls::ClientConfig>,
        options: TuicConnectOptions,
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
        let congestion_control = options.congestion_control;
        let pooled = reconnect
            .get_or_reconnect(|| {
                let rustls_config = rustls_config.clone();
                let server_name = server_name.to_string();
                async move {
                    Self::create_quic_connection(
                        server_addr,
                        &server_name,
                        rustls_config,
                        congestion_control,
                    )
                    .await
                }
            })
            .await?;

        // 认证：token = TLS exporter(label=uuid 16字节, context=password)。
        // 官方 EAimTY/tuic v5 语义 (tuic-server 1.0.0 tuic/src/model/authenticate.rs) 用
        // uuid.as_ref() 取 16 原始字节；之前误用 uuid.to_string() 的 36 字节带连字符字符串，
        // 服务端校验 AuthFailed → 连接被关 → 整个 TCP relay 无响应。
        let mut token = [0u8; TOKEN_LEN];
        pooled
            .conn
            .export_keying_material(&mut token, uuid.as_bytes(), password.as_bytes())
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

        // quic 模式 UDP 响应 pump：server 每个响应新开 uni stream，
        // 按 (assoc_id, pkt_id) 配对给等待中的请求（TUIC v5 SPEC uni-stream 模型）
        let router = UniRespRouter::spawn(multiplexed.pooled.conn.clone());

        Ok(Self {
            multiplexed,
            pool,
            key,
            uuid,
            password: password.to_string(),
            router,
        })
    }

    /// 内部：新建 QUIC 连接（无池复用路径）。
    async fn create_quic_connection(
        server_addr: SocketAddr,
        server_name: &str,
        rustls_config: Arc<rustls::ClientConfig>,
        congestion_control: CongestionControl,
    ) -> Result<quinn::Connection> {
        // TUIC v5 要求 ALPN；仅在未配置时用默认 [h3, tuic]，用户 alpn 不覆盖（bd 7p0）
        let mut rustls_config = (*rustls_config).clone();
        if rustls_config.alpn_protocols.is_empty() {
            rustls_config.alpn_protocols = vec![b"h3".to_vec(), b"tuic".to_vec()];
        }
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
        // 拥塞控制：bbr → quinn BBR；cubic → CUBIC；
        // new_reno 显式降级 CUBIC（quinn 无内置 NewReno，不静默——票 ieik）
        match congestion_control {
            CongestionControl::Bbr => {
                transport.congestion_controller_factory(Arc::new(
                    quinn_proto::congestion::BbrConfig::default(),
                ));
            }
            CongestionControl::Cubic => {
                transport.congestion_controller_factory(Arc::new(
                    quinn_proto::congestion::CubicConfig::default(),
                ));
            }
            CongestionControl::NewReno => {
                tracing::warn!("tuic: quinn has no NewReno, falling back to CUBIC");
                transport.congestion_controller_factory(Arc::new(
                    quinn_proto::congestion::CubicConfig::default(),
                ));
            }
        }
        let mut quinn_client_cfg = quinn_client_cfg;
        quinn_client_cfg.transport_config(Arc::new(transport));

        // 本地 endpoint bind 族必须匹配目标族：域名解析出 IPv6（如 [::1]/AAAA）
        // 时 v4 socket 无法发送 v6 包，quinn 会静默重传直至挂死
        let local_bind: std::net::SocketAddr = if server_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let mut endpoint = quinn::Endpoint::client(local_bind).map_err(|e| {
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

    /// 发送心跳（QUIC datagram——TUIC v5 SPEC：Heartbeat 经 datagram 承载，
    /// 不占用 stream；mock server datagram 分支对非 PACKET 帧忽略）。
    pub async fn heartbeat(&self) -> Result<()> {
        let mut buf = BytesMut::with_capacity(2);
        buf.put_u8(crate::protocol::VERSION);
        buf.put_u8(type_code::HEARTBEAT);
        self.send_datagram(buf.freeze())
    }

    /// 启动周期心跳任务（bd eim）：TUIC v5 需要心跳维持 NAT 映射。
    ///
    /// 任务每 `period` 发送一次 Heartbeat（uni stream），连接关闭后自动退出。
    /// 官方 tuic client 默认 3s（`heartbeat` 配置项），此处由调用方传入。
    /// 返回 JoinHandle 供需要取消时 abort。
    pub fn start_heartbeat(
        self: &Arc<Self>,
        period: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        let client = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(period).await;
                if let Err(e) = client.heartbeat().await {
                    tracing::debug!("tuic heartbeat stopped: {e}");
                    break;
                }
            }
        })
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
    /// 一个逻辑会话。后续调用 [`TuicUdpAssoc::send_recv`]（quic uni-stream 模式）
    /// 或 [`TuicUdpAssoc::send_recv_native`]（native datagram 模式）收发 UDP 包。
    #[must_use]
    pub fn dial_udp(&self, assoc_id: u16) -> TuicUdpAssoc {
        TuicUdpAssoc::new(
            self.multiplexed.pooled.conn.clone(),
            assoc_id,
            self.router.clone(),
        )
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;


    /// 官方 tuic-client 默认值：congestion_control=bbr、udp_relay_mode=native、heartbeat=3s。
    /// 依据 Itsusinn/tuic（官方实现后继）crates/tuic-client/src/config.rs Relay 默认。
    #[test]
    fn connect_options_defaults_match_official() {
        let o = TuicConnectOptions::default();
        assert_eq!(o.congestion_control, CongestionControl::Bbr);
        assert_eq!(o.udp_relay_mode, UdpRelayMode::Native);
        assert_eq!(o.heartbeat, Duration::from_secs(3));
    }

    #[test]
    fn congestion_control_from_name() {
        assert_eq!(CongestionControl::from_name("bbr"), Some(CongestionControl::Bbr));
        assert_eq!(CongestionControl::from_name("CUBIC"), Some(CongestionControl::Cubic));
        assert_eq!(CongestionControl::from_name("new_reno"), Some(CongestionControl::NewReno));
        assert_eq!(CongestionControl::from_name("newreno"), Some(CongestionControl::NewReno));
        assert_eq!(CongestionControl::from_name("bbrv3"), None);
    }

    #[test]
    fn udp_relay_mode_from_name() {
        assert_eq!(UdpRelayMode::from_name("native"), Some(UdpRelayMode::Native));
        assert_eq!(UdpRelayMode::from_name("QUIC"), Some(UdpRelayMode::Quic));
        assert_eq!(UdpRelayMode::from_name("udp"), None);
    }
}

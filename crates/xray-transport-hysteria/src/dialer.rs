//! Hysteria dialer —— outbound 编排（对应 Go `transport/internet/hysteria/dialer.go`）。
//!
//! # IO 边界（trait + stub）
//!
//! Go `Dial()` 依赖：
//! - `http3.Transport.RoundTrip` —— HTTP/3 auth 握手（POST /auth 带 Hysteria-Auth 头）
//! - `quic.Transport.DialEarly` —— QUIC 早期连接
//! - `internet.DialSystem` —— UDP socket
//! - `UdpmaskManager.WrapPacketConnClient` —— UDP masking（可选）
//! - `tls.Config.GetTLSConfig` —— TLS 配置
//!
//! Rust 端用 trait 抽象以上依赖。本模块仅定义 trait + 编排框架（编排函数
//! 返回 [`HysteriaError::ConnectionClosed`] stub）。等上层（quinn/h3/rustls
//! adapter）接入后，trait 实现注入即可激活。

use std::{net::SocketAddr, sync::Arc};

use parking_lot::Mutex;
use xray_common::net::{address::Address, port::Port};
use xray_proto::xray::transport::internet::{QuicParams, UdpHop as ProtoUdpHop};

use crate::{
    config::Status,
    conn::{InterStreamConn, QuicConn, QuicStream, UdpSessionManager},
    context::DatagramFromContext,
    error::{HysteriaError, Result},
    proto_config::Config,
};

/// 写入 TCPRequest 的地址部分；首包 frame type 由 `InterStreamConn` 自动添加。
fn write_tcp_request_body(addr: &str) -> Vec<u8> {
    crate::conn::write_tcp_request_body(addr)
}
/// Dial 目标（对应 Go `net.Destination`）。
#[derive(Clone, Debug)]
pub struct DialDestination {
    /// UDP 地址（hysteria 强制 UDP）。
    pub udp_addr: SocketAddr,
    /// 原始 host（用于 TLS SNI）。
    pub host: String,
}

/// QUIC 配置（对应 Go `*quic.Config`）。
///
/// ponytail: 不引入 quinn-proto 类型，用本地结构。上层 adapter 转换。
#[derive(Clone, Debug)]
pub struct QuicConfig {
    pub initial_stream_receive_window: u64,
    pub max_stream_receive_window: u64,
    pub initial_connection_receive_window: u64,
    pub max_connection_receive_window: u64,
    pub max_idle_timeout_ms: u64,
    pub keep_alive_period_ms: u64,
    pub disable_path_mtu_discovery: bool,
    pub enable_datagrams: bool,
    pub max_datagram_frame_size: u64,
    pub max_incoming_streams: i64,
    /// 拥塞控制算法（对应 Go `quic.Config.CongestionControl` / QuicParams.congestion）。
    /// "bbr" → BBR；"reno" → 保持默认；""/"brutal"/"force-brutal" → auth 后按
    /// Brutal 协商结果切换（见 congestion::quinn_bridge::apply_negotiated）。
    pub congestion: String,
    /// Brutal 上行带宽（bps，对应 QuicParams.brutal_up）。
    pub brutal_up: u64,
    /// BBR profile（对应 QuicParams.bbr_profile）。
    pub bbr_profile: String,
    /// Brutal 关闭丢泡补偿（Go v2.12.2 QuicParams.brutalDisableLossCompensation）。
    pub brutal_disable_loss_compensation: bool,
}

impl QuicConfig {
    /// 从 `QuicParams` 构造（对应 Go `dialer.go` 中 quicConfig 构造逻辑）。
    pub fn from_params(p: &QuicParams) -> Self {
        Self {
            initial_stream_receive_window: if p.init_stream_receive_window == 0 {
                8_388_608
            } else {
                p.init_stream_receive_window
            },
            max_stream_receive_window: if p.max_stream_receive_window == 0 {
                8_388_608
            } else {
                p.max_stream_receive_window
            },
            initial_connection_receive_window: if p.init_conn_receive_window == 0 {
                8_388_608 * 5 / 2
            } else {
                p.init_conn_receive_window
            },
            max_connection_receive_window: if p.max_conn_receive_window == 0 {
                8_388_608 * 5 / 2
            } else {
                p.max_conn_receive_window
            },
            // QuicParams 秒 → quinn 毫秒（Go dialer.go:90-91 `* time.Second`）
            max_idle_timeout_ms: if p.max_idle_timeout <= 0 {
                30_000
            } else {
                (p.max_idle_timeout as u64) * 1000
            },
            keep_alive_period_ms: p.keep_alive_period.max(0) as u64 * 1000,
            disable_path_mtu_discovery: p.disable_path_mtu_discovery,
            enable_datagrams: true,
            max_datagram_frame_size: crate::config::MaxDatagramFrameSize as u64,
            max_incoming_streams: if p.max_incoming_streams == 0 {
                1024
            } else {
                p.max_incoming_streams
            },
            congestion: p.congestion.clone(),
            brutal_up: p.brutal_up,
            bbr_profile: p.bbr_profile.clone(),
            brutal_disable_loss_compensation: p.brutal_disable_loss_compensation,
        }
    }

    /// 默认（无 quicParams 时使用）。
    pub fn default_for_hysteria() -> Self {
        let p = QuicParams {
            bbr_profile: "standard".into(),
            udp_hop: Some(ProtoUdpHop::default()),
            ..QuicParams::default()
        };
        Self::from_params(&p)
    }
}

/// QUIC + HTTP/3 transport 抽象（对应 Go `http3.Transport` + `quic.Transport`）。
///
/// 上层（quinn/h3 adapter）实现此 trait。dialer 内部用此 trait 完成：
/// - TLS 握手 + QUIC DialEarly
/// - HTTP/3 POST /auth 握手 + 接收响应
#[allow(dead_code)]
pub trait HysteriaTransport: Send + Sync {
    /// 执行 dial + HTTP/3 auth 握手，返回已认证的 QUIC conn。
    fn dial_and_authenticate(
        &self,
        dest: &DialDestination,
        quic_config: &QuicConfig,
        auth_token: &str,
        brutal_down_bps: u64,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<Arc<dyn QuicConn>>> + Send>,
    >;

    /// 在已认证的 conn 上打开新 stream（对应 Go `conn.OpenStream()`）。
    fn open_stream(
        &self,
        conn: &Arc<dyn QuicConn>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<Arc<dyn QuicStream>>> + Send>,
    >;
}

/// Dialer 工厂（对应 Go `Dial` 函数）。
///
/// 完整编排：
/// 1. 解析 TLS config（上层注入）
/// 2. 查 client cache（按 dest + stream settings）
/// 3. 未命中 → 新建 client → dial QUIC + HTTP/3 auth
/// 4. 根据 datagram flag 调 tcp（OpenStream）或 udp（UdpSessionManager.create_session）
///
/// 当前 stub：trait 方法返回 NotImplemented。等 transport 注入后激活。
pub trait HysteriaDialerFactory: Send + Sync {
    /// Dial TCP-style 连接（对应 Go `Dial` with datagram=false）。
    fn dial_tcp(
        &self,
        dest: &DialDestination,
        config: &Config,
        quic_params: &QuicParams,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Arc<InterStreamConn>>> + Send>>;

    /// Dial UDP-style session（对应 Go `Dial` with datagram=true）。
    fn dial_udp(
        &self,
        dest: &DialDestination,
        config: &Config,
        quic_params: &QuicParams,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Arc<crate::conn::InterConn>>> + Send>,
    >;
}

/// 客户端实例（对应 Go `*client`）。
pub struct HysteriaClient {
    dest: DialDestination,
    config: Arc<Config>,
    quic_params: Arc<QuicParams>,
    transport: Arc<dyn HysteriaTransport>,
    conn: Mutex<Option<Arc<dyn QuicConn>>>,
    udp_sm: Mutex<Option<Arc<UdpSessionManager>>>,
    status: Mutex<Status>,
}

impl std::fmt::Debug for HysteriaClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HysteriaClient")
            .field("dest", &self.dest)
            .field("status", &self.status.lock().clone())
            .finish_non_exhaustive()
    }
}

impl HysteriaClient {
    /// 构造。
    pub fn new(
        dest: DialDestination,
        config: Arc<Config>,
        quic_params: Arc<QuicParams>,
        transport: Arc<dyn HysteriaTransport>,
    ) -> Self {
        Self {
            dest,
            config,
            quic_params,
            transport,
            conn: Mutex::new(None),
            udp_sm: Mutex::new(None),
            status: Mutex::new(Status::Null),
        }
    }

    /// 当前状态（对应 Go `client.status()`）。
    pub fn status(&self) -> Status {
        let g = self.conn.lock();
        if g.is_none() {
            return Status::Null;
        }
        // ponytail: Go 端通过 `<-conn.Context().Done()` 判断；Rust 端简化为 Active。
        *self.status.lock()
    }

    /// 关闭（对应 Go `client.close()`）。
    pub fn close(&self) {
        if let Some(conn) = self.conn.lock().take() {
            conn.close_with_error(crate::config::CLOSE_ERR_CODE_OK, "");
        }
        self.udp_sm.lock().take();
        *self.status.lock() = Status::Null;
    }

    /// 进行 QUIC + auth 握手（对应 Go `client.dial()`）。
    ///
    /// 当前实现调 transport.dial_and_authenticate；stub transport 返回 Err。
    pub async fn ensure_connected(&self) -> Result<()> {
        match self.status() {
            Status::Active => return Ok(()),
            Status::Inactive => self.close(),
            Status::Null => {},
        }
        let quic_config = QuicConfig::from_params(&self.quic_params);
        let conn = self
            .transport
            .dial_and_authenticate(
                &self.dest,
                &quic_config,
                &self.config.auth,
                self.quic_params.brutal_down,
            )
            .await
            .map_err(HysteriaError::Io)?;
        *self.conn.lock() = Some(conn);
        *self.status.lock() = Status::Active;
        Ok(())
    }

    /// 建立 TCP stream（对应 Go `client.tcp()`），首包由
    /// `InterStreamConn` 写入 frame type，地址体由本函数唯一生成。
    pub async fn tcp(&self, addr: &Address, port: Port) -> Result<Arc<InterStreamConn>> {
        self.ensure_connected().await?;
        let conn = self.conn.lock().clone().ok_or(HysteriaError::ConnectionClosed)?;
        let stream = self.transport.open_stream(&conn).await.map_err(HysteriaError::Io)?;
        let isc =
            Arc::new(InterStreamConn::new(stream, conn.local_addr(), conn.remote_addr(), true));
        let addr = format!("{}:{}", addr, port.value());
        isc.write(&write_tcp_request_body(&addr)).await.map_err(HysteriaError::Io)?;
        // 读取服务端 TCPResponse 帧（status + msg + padding）。官方 apernet/hysteria v2
        // 服务端写入此帧，客户端必须消费后再透传流量；否则响应帧泄漏到代理字节流，
        // 首个 TLS 握手失败 (SEC_E_INVALID_TOKEN / HTTP/0.9 when not allowed)。
        crate::conn::read_tcp_response_stream(&*isc.stream).await.map_err(HysteriaError::Io)?;
        Ok(isc)
    }

    /// 建立 UDP session（对应 Go `client.udp()`）。

    pub async fn udp(&self) -> Result<Arc<crate::conn::InterConn>> {
        self.ensure_connected().await?;
        let conn = self.conn.lock().clone().ok_or(HysteriaError::ConnectionClosed)?;
        let local = conn.local_addr();
        let remote = conn.remote_addr();
        // ponytail: parking_lot guard 不能跨 await 持有（!Send）。
        // 锁内仅创建 manager + 标记是否需 start，锁外再调 start().await。
        let (mgr, needs_start) = {
            let mut g = self.udp_sm.lock();
            if let Some(m) = g.as_ref() {
                (Arc::clone(m), false)
            } else {
                let m = UdpSessionManager::new(
                    std::time::Duration::from_secs(self.config.udp_idle_timeout.max(0) as u64),
                    None,
                );
                let m_arc = Arc::clone(&m);
                *g = Some(m);
                (m_arc, true)
            }
        };
        if needs_start {
            mgr.start(Arc::clone(&conn), local, remote).await;
        }
        mgr.create_session(conn, local, remote).await
    }
}

/// 客户端管理器（对应 Go `clientManager`）。
///
/// 按 dest + config 缓存 HysteriaClient，避免重复 dial。
pub struct ClientManager {
    clients: Mutex<std::collections::HashMap<String, Arc<HysteriaClient>>>,
    transport: Arc<dyn HysteriaTransport>,
}

impl std::fmt::Debug for ClientManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientManager")
            .field("client_count", &self.clients.lock().len())
            .finish_non_exhaustive()
    }
}

impl ClientManager {
    pub fn new(transport: Arc<dyn HysteriaTransport>) -> Self {
        Self { clients: Mutex::new(std::collections::HashMap::new()), transport }
    }

    /// 取或建 client（对应 Go `Dial` 中 clientManager.m 查找逻辑）。
    pub fn get_or_create(
        &self,
        dest: DialDestination,
        config: Arc<Config>,
        quic_params: Arc<QuicParams>,
    ) -> Arc<HysteriaClient> {
        let key = format!("{}|{}", dest.host, dest.udp_addr);
        let mut g = self.clients.lock();
        if let Some(c) = g.get(&key) {
            return Arc::clone(c);
        }
        let client =
            Arc::new(HysteriaClient::new(dest, config, quic_params, Arc::clone(&self.transport)));
        g.insert(key, Arc::clone(&client));
        client
    }

    /// 清理 Inactive client（对应 Go `clientManager.clean()`）。
    pub fn clean_inactive(&self) {
        let mut g = self.clients.lock();
        let to_remove: Vec<_> = g
            .iter()
            .filter(|(_, c)| c.status() == Status::Inactive)
            .map(|(k, _)| k.clone())
            .collect();
        for k in to_remove {
            if let Some(c) = g.remove(&k) {
                c.close();
            }
        }
    }

    /// 当前 client 数。
    pub fn len(&self) -> usize {
        self.clients.lock().len()
    }
}

/// Dialer Factory 默认 stub（返回 ConnectionClosed 表示未实现）。
#[derive(Debug, Default)]
pub struct StubDialerFactory;

impl HysteriaDialerFactory for StubDialerFactory {
    fn dial_tcp(
        &self,
        _dest: &DialDestination,
        _config: &Config,
        _quic_params: &QuicParams,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Arc<InterStreamConn>>> + Send>>
    {
        Box::pin(async { Err(HysteriaError::ConnectionClosed) })
    }

    fn dial_udp(
        &self,
        _dest: &DialDestination,
        _config: &Config,
        _quic_params: &QuicParams,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Arc<crate::conn::InterConn>>> + Send>,
    > {
        Box::pin(async { Err(HysteriaError::ConnectionClosed) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_config_from_params_defaults() {
        let p = QuicParams::default();
        let cfg = QuicConfig::from_params(&p);
        assert_eq!(cfg.initial_stream_receive_window, 8_388_608);
        assert_eq!(cfg.max_stream_receive_window, 8_388_608);
        assert_eq!(cfg.initial_connection_receive_window, 20_971_520);
        assert_eq!(cfg.max_connection_receive_window, 20_971_520);
        assert_eq!(cfg.max_idle_timeout_ms, 30_000);
        assert!(cfg.enable_datagrams);
        assert_eq!(cfg.max_datagram_frame_size, 1200);
        assert_eq!(cfg.max_incoming_streams, 1024);
    }

    #[test]
    fn quic_config_from_params_explicit() {
        let p = QuicParams {
            init_stream_receive_window: 100_000,
            max_stream_receive_window: 200_000,
            init_conn_receive_window: 300_000,
            max_conn_receive_window: 400_000,
            max_idle_timeout: 60,
            keep_alive_period: 5,
            disable_path_mtu_discovery: true,
            max_incoming_streams: 256,
            ..QuicParams::default()
        };
        let cfg = QuicConfig::from_params(&p);
        assert_eq!(cfg.initial_stream_receive_window, 100_000);
        assert_eq!(cfg.max_stream_receive_window, 200_000);
        assert_eq!(cfg.initial_connection_receive_window, 300_000);
        assert_eq!(cfg.max_connection_receive_window, 400_000);
        assert_eq!(cfg.max_idle_timeout_ms, 60_000);
        assert_eq!(cfg.keep_alive_period_ms, 5_000);
        assert!(cfg.disable_path_mtu_discovery);
        assert_eq!(cfg.max_incoming_streams, 256);
    }

    #[test]
    fn quic_config_default_for_hysteria() {
        let cfg = QuicConfig::default_for_hysteria();
        assert!(cfg.enable_datagrams);
        assert_eq!(cfg.max_datagram_frame_size, 1200);
    }

    #[test]
    fn stub_dialer_returns_connection_closed() {
        let factory = StubDialerFactory;
        let dest = DialDestination {
            udp_addr: "127.0.0.1:443".parse().unwrap(),
            host: "example.com".into(),
        };
        let config = Arc::new(crate::proto_config::default_config());
        let qp = Arc::new(QuicParams::default());

        let r =
            tokio::runtime::Runtime::new().unwrap().block_on(factory.dial_tcp(&dest, &config, &qp));
        assert!(matches!(r, Err(HysteriaError::ConnectionClosed)));
    }

    #[test]
    fn client_status_initial_null() {
        // 用 NoopTransport 验证 client 状态机
        struct NoopTransport;
        impl HysteriaTransport for NoopTransport {
            fn dial_and_authenticate(
                &self,
                _dest: &DialDestination,
                _quic_config: &QuicConfig,
                _auth_token: &str,
                _brutal_up_bps: u64,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = std::io::Result<Arc<dyn QuicConn>>> + Send>,
            > {
                Box::pin(async { Err(std::io::Error::new(std::io::ErrorKind::Other, "stub")) })
            }

            fn open_stream(
                &self,
                _conn: &Arc<dyn QuicConn>,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = std::io::Result<Arc<dyn QuicStream>>> + Send>,
            > {
                Box::pin(async { Err(std::io::Error::new(std::io::ErrorKind::Other, "stub")) })
            }
        }
        let dest = DialDestination {
            udp_addr: "127.0.0.1:443".parse().unwrap(),
            host: "example.com".into(),
        };
        let client = HysteriaClient::new(
            dest,
            Arc::new(crate::proto_config::default_config()),
            Arc::new(QuicParams::default()),
            Arc::new(NoopTransport),
        );
        assert_eq!(client.status(), Status::Null);
    }

    #[tokio::test]
    async fn client_manager_dedupes_by_dest() {
        struct NoopTransport;
        impl HysteriaTransport for NoopTransport {
            fn dial_and_authenticate(
                &self,
                _: &DialDestination,
                _: &QuicConfig,
                _: &str,
                _: u64,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = std::io::Result<Arc<dyn QuicConn>>> + Send>,
            > {
                Box::pin(async { Err(std::io::Error::new(std::io::ErrorKind::Other, "")) })
            }

            fn open_stream(
                &self,
                _: &Arc<dyn QuicConn>,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = std::io::Result<Arc<dyn QuicStream>>> + Send>,
            > {
                Box::pin(async { Err(std::io::Error::new(std::io::ErrorKind::Other, "")) })
            }
        }
        let mgr = ClientManager::new(Arc::new(NoopTransport));
        let dest = DialDestination {
            udp_addr: "127.0.0.1:443".parse().unwrap(),
            host: "example.com".into(),
        };
        let cfg = Arc::new(crate::proto_config::default_config());
        let qp = Arc::new(QuicParams::default());
        let c1 = mgr.get_or_create(dest.clone(), Arc::clone(&cfg), Arc::clone(&qp));
        let c2 = mgr.get_or_create(dest, cfg, qp);
        assert!(Arc::ptr_eq(&c1, &c2));
        assert_eq!(mgr.len(), 1);
    }
}

//! WireGuard peer 会话管理。
//!
//! 对应 Go `proxy/wireguard/bind.go` 的 conn.Endpoint 管理 + device 内部 peer 状态。
//! boringtun `Tunn` 单 peer——每个 [`PeerSession`] 绑定一个 [`Tunnel`] + 远端 endpoint。
//!
//! ## 职责
//!
//! - 维护 peer 的 [`Tunnel`] 实例（boringtun 协议状态机）
//! - 跟踪远端 UDP endpoint（可切换，roaming peer）
//! - 暴露握手状态查询（基于 [`Tunnel::time_since_last_handshake`]）
//! - 不负责 socket IO 与定时器驱动——由 [`crate::driver::WgDriver`] 调度

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use crate::config::{DeviceConfig, PeerConfig};
use crate::error::{Result, WgError};
use crate::tunnel::Tunnel;

/// 握手超时——超过此时间无握手认为 peer 不可达。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// 单个 WireGuard peer 会话。
///
/// 包装 [`Tunnel`]（协议状态机）+ 远端 endpoint 地址。
/// 内部用 [`Mutex`] 保护——driver task / handler / 定时器任务并发访问。
pub struct PeerSession {
    /// boringtun 协议状态机 + 加解密缓冲。
    tunnel: Mutex<Tunnel>,
    /// 远端 UDP 地址。roaming peer 会变更。
    endpoint: Mutex<Option<SocketAddr>>,
    /// peer 公钥 hex（调试用）。
    public_key_hex: String,
    /// session index，用于多 peer 场景唯一标识。
    index: u32,
}

impl PeerSession {
    /// 从 DeviceConfig + PeerConfig 构造 peer 会话。
    ///
    /// `endpoint` 字段不在此解析——构造时不绑定地址，由 driver 首次发包时填充
    /// （server 模式 roaming peer 场景）。client 模式应在构造后立即调
    /// [`PeerSession::set_endpoint`]。
    pub fn new(device: &DeviceConfig, peer: &PeerConfig, index: u32) -> Result<Self> {
        let tunnel = Tunnel::from_config(device, peer)?;
        Ok(Self {
            tunnel: Mutex::new(tunnel),
            endpoint: Mutex::new(None),
            public_key_hex: peer.public_key.clone(),
            index,
        })
    }

    /// 包装已构造好的 [`Tunnel`]（用于 driver 内部组装）。
    pub fn from_tunnel(tunnel: Tunnel, public_key_hex: impl Into<String>, index: u32) -> Self {
        Self {
            tunnel: Mutex::new(tunnel),
            endpoint: Mutex::new(None),
            public_key_hex: public_key_hex.into(),
            index,
        }
    }

    /// 设置 / 更新远端 endpoint（roaming peer 场景）。
    pub fn set_endpoint(&self, addr: SocketAddr) {
        *self.endpoint.lock() = Some(addr);
    }

    /// 获取当前远端 endpoint。`None` 表示尚未学习到对端地址。
    #[must_use]
    pub fn endpoint(&self) -> Option<SocketAddr> {
        *self.endpoint.lock()
    }

    /// 距离上次握手的时间。`None` 表示尚未完成握手。
    ///
    /// driver 可据此判断 peer 是否在线。
    #[must_use]
    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        self.tunnel.lock().time_since_last_handshake()
    }

    /// peer 是否「在线」——已握手且未超时。
    ///
    /// 超过 [`HANDSHAKE_TIMEOUT`] 无握手视为离线（需要重新握手）。
    #[must_use]
    pub fn is_online(&self) -> bool {
        match self.time_since_last_handshake() {
            Some(d) => d < HANDSHAKE_TIMEOUT,
            None => false,
        }
    }

    /// peer 公钥 hex（调试 / 日志用）。
    #[must_use]
    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }

    /// 执行闭包并传入 [`Tunnel`] 的互斥锁 guard。
    ///
    /// driver loop 通过此接口调用 [`Tunnel::encapsulate`] /
    /// [`Tunnel::decapsulate`] / [`Tunnel::update_timers`]。
    pub fn with_tunnel<R>(&self, f: impl FnOnce(&mut Tunnel) -> R) -> R {
        f(&mut self.tunnel.lock())
    }
}

/// 共享 peer 会话句柄。
pub type SharedPeer = Arc<PeerSession>;

/// 从 DeviceConfig + PeerConfig 构造共享 peer 会话。
///
/// 便利方法：等价于 `Arc::new(PeerSession::new(...)?)`。
pub fn shared_peer(device: &DeviceConfig, peer: &PeerConfig, index: u32) -> Result<SharedPeer> {
    Ok(Arc::new(PeerSession::new(device, peer, index)?))
}

/// 从字符串解析 endpoint 为 [`SocketAddr`]。
///
/// 用于 client 模式从 `PeerConfig.endpoint` (`"host:port"`) 初始化远端地址。
/// 不做 DNS 解析——host 必须是 IP 地址；域名解析由上层负责。
pub fn parse_endpoint_addr(s: &str) -> Result<SocketAddr> {
    s.parse::<SocketAddr>().map_err(|_| WgError::InvalidEndpoint(format!("peer endpoint not host:port or not IP: {s}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DeviceConfig, PeerConfig};

    fn make_keypair(seed: u8) -> (String, String) {
        // 复用 tunnel.rs 测试方法
        use boringtun::x25519::{PublicKey, StaticSecret};
        let secret_bytes: [u8; 32] = [seed; 32];
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        (hex::encode(secret_bytes), hex::encode(public.as_bytes()))
    }

    fn make_peer(pub_hex: String) -> PeerConfig {
        PeerConfig {
            public_key: pub_hex,
            ..Default::default()
        }
    }

    #[test]
    fn peer_session_constructs_from_config() {
        let (sec, pub_) = make_keypair(0x11);
        let device = DeviceConfig {
            secret_key: sec,
            ..Default::default()
        };
        let peer = make_peer(pub_);
        let session = PeerSession::new(&device, &peer, 0);
        assert!(session.is_ok(), "construct failed: {:?}", session.err());
    }

    #[test]
    fn endpoint_set_and_get() {
        let (sec, pub_) = make_keypair(0x22);
        let device = DeviceConfig {
            secret_key: sec,
            ..Default::default()
        };
        let peer = make_peer(pub_);
        let session = PeerSession::new(&device, &peer, 0).expect("construct");

        // 初始 endpoint 为 None
        assert_eq!(session.endpoint(), None);

        let addr: SocketAddr = "1.2.3.4:51820".parse().unwrap();
        session.set_endpoint(addr);
        assert_eq!(session.endpoint(), Some(addr));

        // roaming：地址可变更
        let addr2: SocketAddr = "5.6.7.8:51820".parse().unwrap();
        session.set_endpoint(addr2);
        assert_eq!(session.endpoint(), Some(addr2));
    }

    #[test]
    fn is_online_false_before_handshake() {
        let (sec, pub_) = make_keypair(0x33);
        let device = DeviceConfig {
            secret_key: sec,
            ..Default::default()
        };
        let peer = make_peer(pub_);
        let session = PeerSession::new(&device, &peer, 0).expect("construct");

        // 未握手——is_online 必为 false
        assert!(!session.is_online());
        assert!(session.time_since_last_handshake().is_none());
    }

    #[test]
    fn with_tunnel_executes_closure() {
        let (sec, pub_) = make_keypair(0x44);
        let device = DeviceConfig {
            secret_key: sec,
            ..Default::default()
        };
        let peer = make_peer(pub_);
        let session = PeerSession::new(&device, &peer, 0).expect("construct");

        // with_tunnel 暴露 Tunnel 互斥锁
        let updated = session.with_tunnel(|t| t.update_timers().is_ok());
        assert!(updated);
    }

    #[test]
    fn parse_endpoint_addr_rejects_domain() {
        // 仅 IP 解析；域名应失败
        let result = parse_endpoint_addr("example.com:51820");
        assert!(result.is_err());
    }

    #[test]
    fn parse_endpoint_addr_accepts_ip_port() {
        let addr = parse_endpoint_addr("127.0.0.1:51820").expect("parse");
        assert_eq!(addr.port(), 51820);
    }

    #[test]
    fn shared_peer_returns_arc() {
        let (sec, pub_) = make_keypair(0x55);
        let device = DeviceConfig {
            secret_key: sec,
            ..Default::default()
        };
        let peer = make_peer(pub_);
        let shared = shared_peer(&device, &peer, 0);
        assert!(shared.is_ok(), "shared_peer failed: {:?}", shared.err());
        let shared = shared.unwrap();
        // Arc 引用计数 = 1
        assert_eq!(Arc::strong_count(&shared), 1);
    }
}

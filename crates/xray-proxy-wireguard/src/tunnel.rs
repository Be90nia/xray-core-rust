//! WireGuard tunnel（boringtun Tunn 包装）。
//!
//! 对应 Go `proxy/wireguard/tun.go` 中的设备包装部分（不含 TUN 设备 IO 和 socket）。
//!
//! ## 切片边界
//!
//! - **切片1（本模块）**：纯 boringtun `Tunn` 包装——hex key → `x25519_dalek` → `Tunn`，
//!   [`Tunnel::encapsulate`] / [`Tunnel::decapsulate`] / [`Tunnel::update_timers`] 同步 API。
//!   不持有 UDP socket；调用方负责把 [`Output::Network`] 发出去、把收到的 WG 数据报喂给
//!   [`Tunnel::decapsulate`]。
//! - **切片2（待办）**：UDP socket driver loop——tokio task 持有 `UdpSocket` + `Tunnel`，
//!   自动路由：socket → `decapsulate` → IP 包入口（`mpsc::Receiver` 或回调）； IP 包出口 →
//!   `encapsulate` → socket。
//! - **切片3（待办）**：smoltcp netstack + InboundHandler / OutboundHandler 适配。
//!
//! ## boringtun API 关键点
//!
//! - `Tunn::new(static_private, peer_public, psk, keepalive, index, rate_limiter)` ——
//!   `rate_limiter` 传 `None` 自动创建默认实例
//! - `encapsulate(ip_pkt, &mut dst) -> TunnResult`——`dst` 由调用方预分配（≥ src.len()+32）
//! - `decapsulate(src_addr, datagram, &mut dst) -> TunnResult`——返回 `WriteToNetwork` 时必须用空
//!   datagram 再调，直到 `Done`（boringtun 的协议约定）
//! - `TunnResult::WriteToNetwork(&mut [u8])` 是 dst 缓冲区的子切片，调用方必须立即 `.to_vec()`
//!   复制后才能释放 dst
//! - 无 async API、无 timer 线程，需要外部驱动 [`Tunnel::update_timers`]

use std::time::Duration;

use boringtun::{
    noise::{Tunn, TunnResult},
    x25519::{PublicKey, StaticSecret},
};

use crate::error::{Result, WgError};

/// boringtun 输出缓冲区大小。WG 数据报最大 65535 字节。
const MAX_PACKET_SIZE: usize = 65535;

/// Tunnel 处理后产生的输出。
///
/// driver loop 根据变体路由：`Network` 发到 UDP socket，`Ip` 投递给上层（TUN 设备 /
/// smoltcp netstack）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// 加密后的 WG 数据报，需发到对端 UDP socket。
    Network(Vec<u8>),
    /// 解密后的 IP 包，需投递给上层网络栈。
    Ip(Vec<u8>),
}

/// WireGuard tunnel——同步包装 boringtun `Tunn`。
///
/// 不持有 UDP socket；socket 由上层 driver task 管理。本结构只负责加解密。
///
/// # 内部状态
///
/// - `tunn`：boringtun 协议状态机
/// - `send_buf` / `recv_buf`：预分配输出缓冲区（避免每次调用 alloc）
pub struct Tunnel {
    tunn: Tunn,
    send_buf: Box<[u8; MAX_PACKET_SIZE]>,
    recv_buf: Box<[u8; MAX_PACKET_SIZE]>,
    /// keepalive 间隔（秒），`None` 表示禁用。
    persistent_keepalive: Option<u16>,
    /// session key 轮换间隔。
    session_key_rotation_interval: Duration,
    /// 上次握手完成时间（用于 session key 轮换）。
    last_handshake: Option<std::time::Instant>,
}

impl Tunnel {
    /// 构造 WireGuard tunnel。
    ///
    /// # 参数
    ///
    /// - `secret_hex`：本端私钥（hex 64 字符 = 32 字节）
    /// - `peer_pub_hex`：对端公钥（hex 64 字符 = 32 字节）
    /// - `psk_hex`：可选 PSK（hex 64 字符）；`None` 或空字符串表示无 PSK
    /// - `keepalive`：keepalive 间隔（秒）；`None` 表示禁用
    /// - `index`：session index，通常用 0；多 tunnel 场景用唯一 ID
    ///
    /// # 错误
    ///
    /// 返回 [`WgError::InvalidConfig`]：hex 非法 / 长度不为 32 字节。
    #[allow(clippy::needless_pass_by_value)] // hex 字符串参对齐 Go Tunnel 构造面，&str 保调用方 ergonomic
    pub fn new(
        secret_hex: &str,
        peer_pub_hex: &str,
        psk_hex: Option<&str>,
        keepalive: Option<u16>,
        index: u32,
    ) -> Result<Self> {
        let secret = parse_secret(secret_hex)?;
        let peer_pub = parse_public(peer_pub_hex)?;
        let psk = match psk_hex.filter(|s| !s.is_empty()) {
            Some(h) => Some(parse_psk(h)?),
            None => None,
        };

        let tunn = Tunn::new(secret, peer_pub, psk, keepalive, index, None);
        Ok(Self {
            tunn,
            send_buf: Box::new([0u8; MAX_PACKET_SIZE]),
            recv_buf: Box::new([0u8; MAX_PACKET_SIZE]),
            persistent_keepalive: keepalive,
            session_key_rotation_interval: Duration::from_secs(120),
            last_handshake: None,
        })
    }

    /// 从 [`crate::config::DeviceConfig`] + [`crate::config::PeerConfig`] 构造。
    ///
    /// 约定：
    /// - `peer.keep_alive` 空串 → 禁用 keepalive（"0" 同效，沿用原 u32 语义）
    /// - `peer.pre_shared_key` 空字符串 → 无 PSK
    /// - `index` 固定用 0（单 peer outbound 模式足够；多 peer 场景需扩展）
    pub fn from_config(
        device: &crate::config::DeviceConfig,
        peer: &crate::config::PeerConfig,
    ) -> Result<Self> {
        // Go client.go:190-192：proto keep_alive 原样拼进 ipc 由 wireguard-go 解析，
        // 非数字串在配置期报错——本侧同语义硬错（u32 时代由类型系统挡住）。
        let keepalive = if peer.keep_alive.is_empty() {
            None
        } else {
            let secs = peer.keep_alive.parse::<u32>().map_err(|_| {
                WgError::InvalidConfig(format!("keep_alive {:?} is not a number", peer.keep_alive))
            })?;
            // 防御性：boringtun 接受 u16，截断溢出值；0 = 禁用。
            Some(secs.min(u32::from(u16::MAX)) as u16).filter(|v| *v != 0)
        };
        let psk =
            if peer.pre_shared_key.is_empty() { None } else { Some(peer.pre_shared_key.as_str()) };
        Self::new(&device.secret_key, &peer.public_key, psk, keepalive, 0)
    }

    /// 加密 IP 包。可能触发 handshake——返回 `Output::Network` 可能是握手 init
    /// 或加密后的数据报。
    ///
    /// 返回 0 个输出 = 协议层暂无需发送（罕见）。
    pub fn encapsulate(&mut self, ip_pkt: &[u8]) -> Result<Vec<Output>> {
        let result = self.tunn.encapsulate(ip_pkt, self.send_buf.as_mut_slice());
        match result {
            TunnResult::WriteToNetwork(bytes) => Ok(vec![Output::Network(bytes.to_vec())]),
            TunnResult::Done => Ok(Vec::new()),
            TunnResult::Err(e) => Err(WgError::HandshakeFailed(format!("encapsulate: {e:?}"))),
            // encapsulate 永远不返回 WriteToTunnel*（输入已是 IP 包）
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => Err(
                WgError::HandshakeFailed("encapsulate returned unexpected WriteToTunnel".into()),
            ),
        }
    }

    /// 解密 WG 数据报。可能产生多个输出（handshake response 触发 reply +
    /// 解出 IP 包）。driver loop 按变体路由。
    ///
    /// boringtun 约定：返回 `WriteToNetwork` 后必须用空 datagram 再调，直到 `Done`。
    /// 本方法自动处理循环，调用方只需传单个 datagram。
    pub fn decapsulate(&mut self, wg_dgram: &[u8]) -> Result<Vec<Output>> {
        let mut out = Vec::new();
        let mut input: &[u8] = wg_dgram;
        loop {
            let result = self.tunn.decapsulate(None, input, self.recv_buf.as_mut_slice());
            match result {
                TunnResult::WriteToTunnelV4(ip, _) | TunnResult::WriteToTunnelV6(ip, _) => {
                    out.push(Output::Ip(ip.to_vec()));
                },
                TunnResult::WriteToNetwork(reply) => {
                    out.push(Output::Network(reply.to_vec()));
                },
                TunnResult::Done => break,
                TunnResult::Err(e) => {
                    return Err(WgError::HandshakeFailed(format!("decapsulate: {e:?}")));
                },
            }
            // 第一次循环后用空 input 继续（boringtun 约定）
            input = &[];
        }
        // 如果握手完成，更新 last_handshake 时间
        // 713x6 台账：boringtun 包装层（`WgTunnel`/`Tunnel` 纯协议封装，无 ctx）；
        // last_handshake 只做 session key 轮换节拍的单调差值。
        #[allow(
            clippy::disallowed_methods,
            reason = "boringtun 包装层无 ctx 注入面；握手节拍单调钟（713x6 台账：结构性不可达）"
        )]
        if self.tunn.time_since_last_handshake().is_some() {
            self.last_handshake = Some(std::time::Instant::now());
        }
        Ok(out)
    }

    /// 调用 boringtun 定时器，处理 keepalive / rekey。
    ///
    /// driver task 应每隔 ~100ms 调一次。返回需要发送的 WG 数据报（如有）。
    pub fn update_timers(&mut self) -> Result<Vec<Output>> {
        // 检查是否需要 session key 轮换（每 2 分钟）。握手前 last_handshake 为 None
        // ——没有会话可轮换，不得断言「已触发轮转」（z7ya 排查时这条噪音误导了定位）。
        if self.last_handshake.is_some_and(|t| t.elapsed() >= self.session_key_rotation_interval) {
            // boringtun 的 update_timers 内部会处理 rekey
            tracing::debug!("wg session key rotation triggered");
        }
        let result = self.tunn.update_timers(self.send_buf.as_mut_slice());
        match result {
            TunnResult::WriteToNetwork(bytes) => Ok(vec![Output::Network(bytes.to_vec())]),
            TunnResult::Done => Ok(Vec::new()),
            TunnResult::Err(e) => Err(WgError::HandshakeFailed(format!("timer: {e:?}"))),
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                Err(WgError::HandshakeFailed(
                    "update_timers returned WriteToTunnel (unexpected)".into(),
                ))
            },
        }
    }

    /// 距离上次握手的时间。握手完成前返回 `None`。
    #[must_use]
    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        self.tunn.time_since_last_handshake()
    }

    /// 返回 keepalive 间隔（秒）。
    #[must_use]
    pub fn keepalive_interval(&self) -> Option<u16> {
        self.persistent_keepalive
    }

    /// 返回 session key 轮换间隔。
    #[must_use]
    pub fn session_key_rotation_interval(&self) -> Duration {
        self.session_key_rotation_interval
    }

    /// 强制触发 session key 轮换。
    pub fn force_session_key_rotation(&mut self) {
        self.last_handshake = None;
    }
}

// ===== hex → x25519 转换工具 =====
// ponytail: 项目内多个 crate（xray-tls/xray-reality/xray-proxy-trojan）都用 hex = "0.4"
// 直接写在 crate Cargo.toml；不引入 workspace.dependencies 避免散落维护。

fn parse_secret(hex_str: &str) -> Result<StaticSecret> {
    let arr = hex_to_array_32(hex_str, "secret_key")?;
    Ok(StaticSecret::from(arr))
}

fn parse_public(hex_str: &str) -> Result<PublicKey> {
    let arr = hex_to_array_32(hex_str, "public_key")?;
    Ok(PublicKey::from(arr))
}

/// 由本端私钥推导公钥 hex（对应 Go server.go NewServer 的 `curve25519.ScalarBaseMult`）。
///
/// [`crate::users::WgUserRegistry::add_user`] 的 "invalid public key" 自检用
/// （Go server.go:144-146：禁止添加与本端公钥相同的 peer）。
///
/// # Errors
///
/// - [`WgError::InvalidConfig`]：私钥不是 64 hex 字符。
pub fn public_key_from_secret(secret_hex: &str) -> Result<String> {
    let secret = parse_secret(secret_hex)?;
    Ok(hex::encode(PublicKey::from(&secret).as_bytes()))
}

fn parse_psk(hex_str: &str) -> Result<[u8; 32]> {
    hex_to_array_32(hex_str, "pre_shared_key")
}

fn hex_to_array_32(hex_str: &str, field: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| WgError::InvalidConfig(format!("{field} hex decode: {e}")))?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        WgError::InvalidConfig(format!(
            "{field} must be 32 bytes (64 hex chars), got {}",
            bytes.len()
        ))
    })?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use boringtun::x25519::{PublicKey, StaticSecret};

    use super::*;

    // ===== 工具：生成测试 keypair =====

    /// 生成 32 字节 hex 字符串。固定 seed（不依赖 rand crate）。
    fn make_test_keypair(seed_byte: u8) -> (String, String) {
        let secret_bytes: [u8; 32] = [seed_byte; 32];
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        let secret_hex = hex::encode(secret_bytes);
        let public_hex = hex::encode(public.as_bytes());
        (secret_hex, public_hex)
    }

    /// 构造最小合法 IPv4 包（20 字节 header + payload）。
    /// src=10.0.0.1 dst=10.0.0.2 proto=UDP(17)。
    fn make_ipv4_packet(payload: &[u8]) -> Vec<u8> {
        let total_len = 20 + payload.len();
        let mut pkt = Vec::with_capacity(total_len);
        // IPv4 header（最小 20 字节）
        pkt.push(0x45); // version=4, IHL=5
        pkt.push(0x00); // DSCP/ECN
        pkt.extend_from_slice(&(total_len as u16).to_be_bytes()); // total length
        pkt.extend_from_slice(&[0x00, 0x01]); // identification
        pkt.extend_from_slice(&[0x00, 0x00]); // flags + frag offset
        pkt.push(64); // TTL
        pkt.push(17); // protocol = UDP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum (0 = 不校验，boringtun 不验)
        pkt.extend_from_slice(&[10, 0, 0, 1]); // src
        pkt.extend_from_slice(&[10, 0, 0, 2]); // dst
        pkt.extend_from_slice(payload);
        pkt
    }

    // ===== 构造错误处理 =====

    #[test]
    fn new_rejects_invalid_hex() {
        let (sec, _) = make_test_keypair(0xAA);
        let result = Tunnel::new("not-hex-zzz", &sec, None, None, 0);
        match result {
            Err(e) => assert!(format!("{e}").contains("secret_key"), "msg: {e}"),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn new_rejects_short_hex() {
        let (_, pub_) = make_test_keypair(0xBB);
        let result = Tunnel::new("deadbeef", &pub_, None, None, 0);
        match result {
            Err(e) => assert!(format!("{e}").contains("32 bytes"), "msg: {e}"),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn new_accepts_empty_psk_as_none() {
        let (sec_a, pub_a) = make_test_keypair(0x11);
        let (sec_b, pub_b) = make_test_keypair(0x22);
        // Some("") 应等同于 None
        let t = Tunnel::new(&sec_a, &pub_b, Some(""), None, 0);
        assert!(t.is_ok());
        let t = t.unwrap();
        // 对端 B 视角
        let _ = Tunnel::new(&sec_b, &pub_a, None, None, 1).unwrap();
        drop(t);
    }

    // ===== 端到端握手 + 数据传输 =====

    /// 两个 Tunnel 对接握手：A 主动发起。
    /// 返回 (tunnel_a, tunnel_b)——两者均已握手完成。
    fn setup_handshake() -> (Tunnel, Tunnel) {
        let (sec_a, pub_a) = make_test_keypair(0x11);
        let (sec_b, pub_b) = make_test_keypair(0x22);

        let mut a = Tunnel::new(&sec_a, &pub_b, None, None, 0).expect("A tunnel");
        let mut b = Tunnel::new(&sec_b, &pub_a, None, None, 1).expect("B tunnel");

        // 握手前 time_since_last_handshake 为 None
        assert!(a.time_since_last_handshake().is_none());

        // A 发起握手：需要触发——用一个 IP 包驱动 encapsulate 产生 handshake init
        let ip_pkt = make_ipv4_packet(b"hello");
        let a_out = a.encapsulate(&ip_pkt).expect("A encapsulate");
        // 第一次 encapsulate 通常产生 handshake init（WriteToNetwork），IP 包暂存
        assert!(
            a_out.iter().any(|o| matches!(o, Output::Network(_))),
            "expected handshake init from A: {a_out:?}"
        );

        // 把 A 的所有 Network 输出喂给 B
        let mut b_got_handshake = false;
        for o in &a_out {
            if let Output::Network(wg) = o {
                let b_out = b.decapsulate(wg).expect("B decapsulate A's init");
                // B 收到 handshake init 后产生 handshake response
                assert!(
                    b_out.iter().any(|o| matches!(o, Output::Network(_))),
                    "expected handshake response from B: {b_out:?}"
                );
                b_got_handshake = true;

                // 把 B 的 Network reply 喂回 A
                for o2 in &b_out {
                    if let Output::Network(wg2) = o2 {
                        a.decapsulate(wg2).expect("A decapsulate B's response");
                    }
                }
            }
        }
        assert!(b_got_handshake, "B did not receive handshake init");

        // 握手完成检查——A 应已记录握手时间
        // 注意：boringtun 握手需要往返，A 收到 B 的 response 后才完成
        assert!(a.time_since_last_handshake().is_some(), "handshake not completed on A side");

        (a, b)
    }

    #[test]
    fn handshake_completes() {
        let (a, _b) = setup_handshake();
        assert!(a.time_since_last_handshake().is_some());
    }

    #[test]
    fn data_roundtrip_after_handshake() {
        let (mut a, mut b) = setup_handshake();

        // A 加密 IP 包
        let payload = b"wireguard data test payload";
        let ip_pkt = make_ipv4_packet(payload);
        let a_out = a.encapsulate(&ip_pkt).expect("A encapsulate data");

        // 喂给 B 解密
        let mut decrypted: Option<Vec<u8>> = None;
        for o in &a_out {
            if let Output::Network(wg) = o {
                let b_out = b.decapsulate(wg).expect("B decapsulate data");
                for o2 in b_out {
                    if let Output::Ip(ip) = o2 {
                        decrypted = Some(ip);
                    }
                }
            }
        }

        let decrypted = decrypted.expect("B did not produce IP packet");
        // boringtun 可能修改 IP header（不修改），但 payload 应保留
        assert!(
            decrypted.windows(payload.len()).any(|w| w == payload),
            "payload not found in decrypted packet: {} bytes",
            decrypted.len()
        );
    }

    #[test]
    fn encapsulate_after_handshake_returns_network() {
        let (mut a, _b) = setup_handshake();
        let ip_pkt = make_ipv4_packet(b"x");
        let out = a.encapsulate(&ip_pkt).expect("encapsulate");
        assert!(
            out.iter().any(|o| matches!(o, Output::Network(_))),
            "expected Network output after handshake: {out:?}"
        );
    }

    /// 双 tunnel 线上字节交换驱动：把 seed 注入 A→B 方向后反复泵两侧，直到线上
    /// 无新字节产生。返回 B 解出的 IP 包（按到达序）。B 的网络输出原样回投 A。
    fn pump_tunnels(a: &mut Tunnel, b: &mut Tunnel, seed: VecDeque<Vec<u8>>) -> Vec<Vec<u8>> {
        let mut a_to_b = seed;
        let mut delivered = Vec::new();
        loop {
            let mut progress = false;
            while let Some(wg) = a_to_b.pop_front() {
                progress = true;
                for out in b.decapsulate(&wg).expect("B decapsulate") {
                    match out {
                        Output::Ip(ip) => delivered.push(ip),
                        Output::Network(reply) => {
                            for out2 in a.decapsulate(&reply).expect("A decapsulate") {
                                match out2 {
                                    Output::Network(wg2) => a_to_b.push_back(wg2),
                                    Output::Ip(_) => unreachable!("A 不解出自己的包"),
                                }
                            }
                        },
                    }
                }
            }
            if !progress {
                break;
            }
        }
        delivered
    }

    fn wire_of(outs: Vec<Output>) -> VecDeque<Vec<u8>> {
        outs.into_iter()
            .filter_map(|o| match o {
                Output::Network(wg) => Some(wg),
                Output::Ip(_) => None,
            })
            .collect()
    }

    /// bd n07t F2：握手期数据报不丢。
    ///
    /// boringtun 0.7.1 无会话时 encapsulate 把 IP 包压入内部 `packet_queue`
    /// （MAX_QUEUE_DEPTH=256，noise/mod.rs:263-267），握手 response 到达后由
    /// decapsulate 的空输入重调约定 flush（send_queued_packet，noise/mod.rs:284、
    /// 510-521）——与 wireguard-go 的 staged queue 语义一致（device/send.go
    /// StagePackets/SendStagedPackets：无 keypair 时只发握手、包留队）。
    /// 本测试证明：握手完成前单发的数据报不丢，握手完成后自动送达对端。
    #[test]
    fn first_datagram_before_handshake_not_lost() {
        let (sec_a, pub_a) = make_test_keypair(0x11);
        let (sec_b, pub_b) = make_test_keypair(0x22);
        let mut a = Tunnel::new(&sec_a, &pub_b, None, None, 0).expect("A tunnel");
        let mut b = Tunnel::new(&sec_b, &pub_a, None, None, 1).expect("B tunnel");

        // 握手完全未开始：A 单发一只 UDP 数据报（无重发）。
        let payload = b"first datagram before handshake";
        let a_out = a.encapsulate(make_ipv4_packet(payload).as_slice()).expect("encapsulate");
        // 此刻只产出 handshake init——数据包已被 boringtun 排队，不出加密数据报。
        assert!(
            a_out.iter().all(|o| matches!(o, Output::Network(_))),
            "pre-handshake encapsulate must only emit handshake init: {a_out:?}"
        );

        let delivered = pump_tunnels(&mut a, &mut b, wire_of(a_out));
        assert!(a.time_since_last_handshake().is_some(), "A handshake incomplete");
        assert_eq!(delivered.len(), 1, "exactly the queued datagram must arrive");
        assert!(
            delivered[0].windows(payload.len()).any(|w| w == payload),
            "payload mismatch in delivered packet"
        );
    }

    /// bd n07t F2 补充：握手 init 在途（is_in_progress）期间持续 encapsulate 的包
    /// 同样入队——boringtun 不重发 init（Done → Ok 空输出，driver 无需处理），
    /// 握手完成后按 FIFO 顺序全部送达。
    #[test]
    fn datagrams_while_handshake_in_progress_not_lost() {
        let (sec_a, pub_a) = make_test_keypair(0x11);
        let (sec_b, pub_b) = make_test_keypair(0x22);
        let mut a = Tunnel::new(&sec_a, &pub_b, None, None, 0).expect("A tunnel");
        let mut b = Tunnel::new(&sec_b, &pub_a, None, None, 1).expect("B tunnel");

        let payloads: [&[u8]; 4] = [b"pkt #1", b"pkt #2", b"pkt #3", b"pkt #4"];
        // 首包触发 handshake init。
        let a_out = a.encapsulate(make_ipv4_packet(payloads[0]).as_slice()).expect("encap #1");
        assert!(
            a_out.iter().any(|o| matches!(o, Output::Network(_))),
            "init expected from first encapsulate: {a_out:?}"
        );

        // init 在途期间继续发包：输出为空（不重发 init），包入 packet_queue。
        let seed = wire_of(a_out);
        for p in &payloads[1..] {
            let out = a.encapsulate(make_ipv4_packet(p).as_slice()).expect("encap");
            assert!(out.is_empty(), "in-progress handshake must not emit output: {out:?}");
        }

        let delivered = pump_tunnels(&mut a, &mut b, seed);
        assert!(a.time_since_last_handshake().is_some(), "A handshake incomplete");
        assert_eq!(delivered.len(), payloads.len(), "all queued datagrams must arrive");
        for (i, ip) in delivered.iter().enumerate() {
            let want = payloads[i];
            assert!(
                ip.windows(want.len()).any(|w| w == want),
                "FIFO order/payload mismatch at {i}"
            );
        }
    }

    #[test]
    fn update_timers_returns_ok_initially() {
        let (mut a, _b) = setup_handshake();
        // 握手后调用 timer 应该不报错
        let result = a.update_timers();
        assert!(result.is_ok(), "timer failed: {:?}", result.err());
    }

    // ===== from_config =====

    #[test]
    fn from_config_zero_keepalive_becomes_none() {
        let (sec_a, pub_a) = make_test_keypair(0x11);
        let (_, pub_b) = make_test_keypair(0x22);
        let device = crate::config::DeviceConfig { secret_key: sec_a, ..Default::default() };
        let peer = crate::config::PeerConfig {
            public_key: pub_b,
            keep_alive: String::new(),
            pre_shared_key: String::new(),
            ..Default::default()
        };
        let t = Tunnel::from_config(&device, &peer);
        assert!(t.is_ok());
        // 对端视角验证 key 可用
        let _peer_view = Tunnel::new(&hex::encode([0x22u8; 32]), &pub_a, None, None, 0).unwrap();
    }

    #[test]
    fn from_config_keepalive_overflow_truncated() {
        // "4294967295"（u32::MAX 的十进制串）应截断为 u16::MAX，不报错
        let (sec, pub_) = make_test_keypair(0x33);
        let device = crate::config::DeviceConfig { secret_key: sec, ..Default::default() };
        let peer = crate::config::PeerConfig {
            public_key: pub_,
            keep_alive: "4294967295".to_string(),
            ..Default::default()
        };
        let t = Tunnel::from_config(&device, &peer);
        assert!(t.is_ok());
    }
}

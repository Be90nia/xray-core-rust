//! # Finalmask 流量伪装框架
//!
//! 对应 Go `transport/internet/finalmask/finalmask.go`。
//! 提供 UDP/TCP 流量伪装的链式包装基础设施——把代理流量伪装成常见协议特征，规避 DPI。
//!
//! ## 核心接口
//!
//! - [`UdpIo`]：UDP I/O 抽象（对应 Go `net.PacketConn` 子集）
//! - [`Udpmask`]：UDP 伪装（包装 PacketConn）
//! - [`Tcpmask`]：TCP 伪装（包装 Conn）
//!
//! ## Manager
//!
//! [`UdpmaskManager`] / [`TcpmaskManager`] 按逆序链式应用多个伪装模块（对应 Go `slices.Backward`）。

use async_trait::async_trait;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

pub mod custom;
pub mod fragment;
pub mod mkcp;
pub mod noise;
pub mod realm;
pub mod salamander;
pub mod salamander_gecko;
pub mod sudoku;
pub mod xdns;
pub mod xicmp;
pub mod xmc;

/// UDP 读缓冲区大小（对应 Go `finalmask.UDPSize = 4096`）。
pub const UDP_SIZE: usize = 4096;

/// `AsyncRead + AsyncWrite + Send + Unpin` 的组合 trait（用于 trait object）。
///
/// Rust 的 trait object 只能含一个非 auto trait，故 `dyn AsyncRead + AsyncWrite` 非法。
/// 通过此组合 trait + blanket impl 解决。
pub trait AsyncIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> AsyncIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

/// UDP I/O 抽象（对应 Go `net.PacketConn` 的子集）。
#[async_trait]
pub trait UdpIo: Send + Sync {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize>;
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// `tokio::net::UdpSocket` 适配为 [`UdpIo`]。
#[async_trait]
impl UdpIo for tokio::net::UdpSocket {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        tokio::net::UdpSocket::send_to(self, buf, addr).await
    }
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        tokio::net::UdpSocket::recv_from(self, buf).await
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        tokio::net::UdpSocket::local_addr(self)
    }
}

/// UDP 伪装接口（对应 Go `Udpmask`）。
pub trait Udpmask: Send + Sync {
    fn wrap_packet_conn_client(
        &self,
        raw: Box<dyn UdpIo>,
        level: usize,
        level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>>;

    fn wrap_packet_conn_server(
        &self,
        raw: Box<dyn UdpIo>,
        level: usize,
        level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>>;
}

/// TCP 伪装接口（对应 Go `Tcpmask`）。
pub trait Tcpmask: Send + Sync {
    fn wrap_conn_client(&self, raw: Box<dyn AsyncIo>) -> io::Result<Box<dyn AsyncIo>>;

    fn wrap_conn_server(&self, raw: Box<dyn AsyncIo>) -> io::Result<Box<dyn AsyncIo>>;
}

/// UDP 伪装管理器（对应 Go `UdpmaskManager`）。
///
/// header/custom 等具体伪装模块通过实现 [`Udpmask`] trait 直接加入 `udpmasks` 数组，
/// 不需要专门的 header 聚合类型（与 Go `headerManagerConn` 不同）。
pub struct UdpmaskManager {
    pub(crate) udpmasks: Vec<Box<dyn Udpmask>>,
}

impl UdpmaskManager {
    #[must_use]
    pub fn new(udpmasks: Vec<Box<dyn Udpmask>>) -> Self {
        Self { udpmasks }
    }

    pub fn wrap_packet_conn_client(&self, raw: Box<dyn UdpIo>) -> io::Result<Box<dyn UdpIo>> {
        let mut raw = raw;
        let total = self.udpmasks.len();
        for i in (0..total).rev() {
            raw = self.udpmasks[i].wrap_packet_conn_client(raw, i, total.saturating_sub(1))?;
        }
        Ok(raw)
    }

    pub fn wrap_packet_conn_server(&self, raw: Box<dyn UdpIo>) -> io::Result<Box<dyn UdpIo>> {
        let mut raw = raw;
        let total = self.udpmasks.len();
        for i in (0..total).rev() {
            raw = self.udpmasks[i].wrap_packet_conn_server(raw, i, total.saturating_sub(1))?;
        }
        Ok(raw)
    }
}

/// TCP 伪装管理器（对应 Go `TcpmaskManager`）。
pub struct TcpmaskManager {
    tcpmasks: Vec<Box<dyn Tcpmask>>,
}

impl TcpmaskManager {
    #[must_use]
    pub fn new(tcpmasks: Vec<Box<dyn Tcpmask>>) -> Self {
        Self { tcpmasks }
    }

    pub fn wrap_conn_client(&self, raw: Box<dyn AsyncIo>) -> io::Result<Box<dyn AsyncIo>> {
        let mut raw = raw;
        for mask in self.tcpmasks.iter().rev() {
            raw = mask.wrap_conn_client(raw)?;
        }
        Ok(raw)
    }

    pub fn wrap_conn_server(&self, raw: Box<dyn AsyncIo>) -> io::Result<Box<dyn AsyncIo>> {
        let mut raw = raw;
        for mask in self.tcpmasks.iter().rev() {
            raw = mask.wrap_conn_server(raw)?;
        }
        Ok(raw)
    }
}

/// TCP 伪装连接标记（对应 Go `TcpMaskConn` interface）。
pub trait TcpMaskConn: AsyncIo {
    fn raw_conn(&self) -> Option<&dyn AsyncIo> {
        None
    }
    fn splice(&self) -> bool {
        false
    }
}

/// KCP security 加密模式（对应 Go `SecurityType` 枚举）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityMode {
    /// 无加密，XOR 链 + FNV1a-32 认证。
    #[default]
    Original,
    /// AES-128-GCM AEAD。
    Aes128Gcm,
    /// Salamander BLAKE2b 混淆。
    Salamander,
}

impl SecurityMode {
    /// 从字符串解析（对应 Go proto enum name）。
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "original" | "none" | "zero" => Some(Self::Original),
            "aes-128-gcm" | "aes128gcm" | "aes-128-gcm" => Some(Self::Aes128Gcm),
            "salamander" => Some(Self::Salamander),
            _ => None,
        }
    }
}

/// Finalmask 顶层配置（对应 Go `FinalmaskConfig` + KCP `SecurityConfig`）。
#[derive(Debug, Clone, Default)]
pub struct FinalmaskConfig {
    /// 加密模式。
    pub security: SecurityMode,
    /// 共享密码（aes128gcm/salamander 使用）。
    pub password: String,
    /// 协议头伪装 ID（0=DNS, 1=DTLS, 2=SRTP, 3=uTP, 4=WeChat, 5=WireGuard）。
    pub header_id: Option<i32>,
}

/// 根据配置构建 UDP 伪装管理器（对应 Go `CreateUdpmaskManager`）。
///
/// 按 [header] → [security] 顺序追加到 manager，对应 Go `slices.Backward` 逆序应用。
pub fn build_udpmask_manager(config: &FinalmaskConfig) -> io::Result<UdpmaskManager> {
    let mut masks: Vec<Box<dyn Udpmask>> = Vec::new();

    // 1. Security mask
    match config.security {
        SecurityMode::Original => {
            masks.push(Box::new(mkcp::original::OriginalConfig));
        }
        SecurityMode::Aes128Gcm => {
            masks.push(Box::new(mkcp::aes128gcm::Aes128GcmConfig {
                password: config.password.clone(),
            }));
        }
        SecurityMode::Salamander => {
            masks.push(Box::new(salamander::SalamanderConfig {
                password: config.password.clone(),
            }));
        }
    }

    // 2. Header mask (optional, wraps security layer)
    if let Some(id) = config.header_id {
        if let Some(hid) = mkcp::header::HeaderId::from_i32(id) {
            masks.push(Box::new(mkcp::header::HeaderConfig::from_id(hid)));
        }
    }

    Ok(UdpmaskManager::new(masks))
}

// ===== 同步逐包 codec 链（KCP 等同步 UDP 栈复用同一套 mkcp 算子） =====

/// 同步逐包编解码接口。
///
/// 与 [`Udpmask`] 包装同一套 mkcp 算子（original/aes128gcm/header），供同步 UDP 栈
/// （如 `xray-transport-kcp` 的 `std::net::UdpSocket` 路径）在 socket 读写 seam 上
/// 逐包 encode/decode，语义等价 Go `WrapPacketConnClient`/`WrapPacketConnServer`
/// （mkcp 各算子对称、无握手，client/server 共用同一编解码）。
pub trait PacketCodec: Send + Sync {
    /// 发送方向：把一个明文 packet 变换为线上字节。
    ///
    /// # Errors
    /// 算子特定（如 AEAD key 派生失败）。
    fn encode(&self, pkt: &[u8]) -> io::Result<Vec<u8>>;

    /// 接收方向：把线上字节还原为明文 packet。
    ///
    /// # Errors
    /// - `InvalidData`：校验失败（FNV1a/AEAD tag 不符、长度不符）。
    fn decode(&self, pkt: &[u8]) -> io::Result<Vec<u8>>;
}

/// 逐包 codec 链：按数组顺序 encode、逆序 decode。
///
/// 对应 Go `UdpmaskManager` 链式嵌套——数组序 `[m0, m1]` 表示 m1 包 m0 包 raw，
/// 发送时 `payload → m0.encode → m1.encode → 线上`，接收反向。
#[derive(Clone)]
pub struct CodecChain {
    codecs: Vec<Arc<dyn PacketCodec>>,
}

impl CodecChain {
    /// 构建链。
    #[must_use]
    pub fn new(codecs: Vec<Arc<dyn PacketCodec>>) -> Self {
        Self { codecs }
    }

    /// 链长度。
    #[must_use]
    pub fn len(&self) -> usize {
        self.codecs.len()
    }

    /// 是否为空链（等价无 mask）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.codecs.is_empty()
    }

    /// 发送方向逐层 encode。
    ///
    /// # Errors
    /// 任一层算子错误透传。
    pub fn encode(&self, pkt: &[u8]) -> io::Result<Vec<u8>> {
        let mut data = pkt.to_vec();
        for c in &self.codecs {
            data = c.encode(&data)?;
        }
        Ok(data)
    }

    /// 接收方向逐层 decode（encode 的逆序）。
    ///
    /// # Errors
    /// 任一层算子错误透传。
    pub fn decode(&self, pkt: &[u8]) -> io::Result<Vec<u8>> {
        let mut data = pkt.to_vec();
        for c in self.codecs.iter().rev() {
            data = c.decode(&data)?;
        }
        Ok(data)
    }
}

/// 从 `streamSettings.finalmask` JSON 解析 UDP 伪装 codec 链。
///
/// 对应 Go `udpmaskLoader` + `Mask.Build(false)` 的 mkcp 子集
/// （`infra/conf/transport_internet.go`）：`udp` 数组每项 `{"type", "settings"}`，
/// 当前支持 `type == "mkcp-legacy"`（`settings.{header, value}`，对应 Go `MkcpLegacy`）：
///
/// - `header` 空 + `value` 空 → original（XOR 链 + FNV1a）
/// - `header` 空 + `value` 非空 → aes128gcm（password = `value`）
/// - `header` = dns/dtls/srtp/utp/wechat/wireguard → 协议头伪装
///   （dns 的 domain = `value`，默认 `www.baidu.com`）
///
/// 其余 type 报错（不静默丢配置）。`None` / 无 `udp` 数组 / 空数组 → `Ok(None)`
/// （无 mask，行为不变）。
///
/// # Errors
/// - `InvalidInput`：未知 type、非法 header 名、算子构造失败。
pub fn parse_finalmask_udp_chain(
    json: Option<&serde_json::Value>,
) -> io::Result<Option<CodecChain>> {
    let Some(v) = json else { return Ok(None) };
    let Some(entries) = v.get("udp").and_then(|u| u.as_array()) else {
        return Ok(None);
    };
    if entries.is_empty() {
        return Ok(None);
    }

    let mut codecs: Vec<Arc<dyn PacketCodec>> = Vec::new();
    for entry in entries {
        let ty = entry.get("type").and_then(|t| t.as_str()).unwrap_or_default();
        let settings = entry.get("settings").cloned().unwrap_or(serde_json::Value::Null);
        match ty {
            "mkcp-legacy" => codecs.push(build_mkcp_legacy_codec(&settings)?),
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "finalmask: unsupported udp mask type {other:?} (supported: mkcp-legacy)"
                    ),
                ));
            }
        }
    }
    Ok(Some(CodecChain::new(codecs)))
}

/// `mkcp-legacy` 单条目 → codec（对应 Go `MkcpLegacy.Build`，transport_internet.go:1725）。
fn build_mkcp_legacy_codec(settings: &serde_json::Value) -> io::Result<Arc<dyn PacketCodec>> {
    let header = settings.get("header").and_then(|h| h.as_str()).unwrap_or_default();
    let value = settings.get("value").and_then(|v| v.as_str()).unwrap_or_default();

    if header.is_empty() {
        return Ok(if value.is_empty() {
            Arc::new(mkcp::original::OriginalConfig)
        } else {
            Arc::new(mkcp::aes128gcm::Aes128GcmCodec::new(value)?)
        });
    }

    use mkcp::header::{HeaderConfig, HeaderId};
    let cfg = match header.to_ascii_lowercase().as_str() {
        "dns" => HeaderConfig {
            id: HeaderId::Dns,
            domain: if value.is_empty() {
                "www.baidu.com".to_string()
            } else {
                value.to_string()
            },
        },
        "dtls" => HeaderConfig::from_id(HeaderId::Dtls),
        "srtp" => HeaderConfig::from_id(HeaderId::Srtp),
        "utp" => HeaderConfig::from_id(HeaderId::Utp),
        "wechat" => HeaderConfig::from_id(HeaderId::Wechat),
        "wireguard" => HeaderConfig::from_id(HeaderId::Wireguard),
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("finalmask: invalid header {other:?}"),
            ));
        }
    };
    Ok(Arc::new(mkcp::header::HeaderCodec::new(&cfg)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_managers_construct() {
        let _tcp = TcpmaskManager::new(vec![]);
        let _udp = UdpmaskManager::new(vec![]);
    }

    #[test]
    fn udp_size_is_4096() {
        assert_eq!(UDP_SIZE, 4096);
    }

    #[test]
    fn security_mode_from_name() {
        assert_eq!(SecurityMode::from_name("original"), Some(SecurityMode::Original));
        assert_eq!(SecurityMode::from_name("none"), Some(SecurityMode::Original));
        assert_eq!(SecurityMode::from_name("aes-128-gcm"), Some(SecurityMode::Aes128Gcm));
        assert_eq!(SecurityMode::from_name("aes128gcm"), Some(SecurityMode::Aes128Gcm));
        assert_eq!(SecurityMode::from_name("salamander"), Some(SecurityMode::Salamander));
        assert_eq!(SecurityMode::from_name("unknown"), None);
    }

    #[test]
    fn build_manager_original_no_header() {
        let config = FinalmaskConfig::default();
        let mgr = build_udpmask_manager(&config).unwrap();
        // Original mode: 1 mask (no header)
        assert!(!mgr.udpmasks.is_empty());
    }

    #[test]
    fn build_manager_aes128gcm_with_header() {
        let config = FinalmaskConfig {
            security: SecurityMode::Aes128Gcm,
            password: "test-pass".into(),
            header_id: Some(5), // WireGuard
        };
        let mgr = build_udpmask_manager(&config).unwrap();
        // Aes128Gcm + header: 2 masks
        assert_eq!(mgr.udpmasks.len(), 2);
    }

    #[test]
    fn build_manager_salamander_with_dns_header() {
        let config = FinalmaskConfig {
            security: SecurityMode::Salamander,
            password: "sal-key".into(),
            header_id: Some(0), // DNS
        };
        let mgr = build_udpmask_manager(&config).unwrap();
        assert_eq!(mgr.udpmasks.len(), 2);
    }

    #[test]
    fn build_manager_invalid_header_id_ignored() {
        let config = FinalmaskConfig {
            security: SecurityMode::Original,
            password: String::new(),
            header_id: Some(99), // invalid
        };
        let mgr = build_udpmask_manager(&config).unwrap();
        // Invalid header_id ignored: only 1 mask (security)
        assert_eq!(mgr.udpmasks.len(), 1);
    }

    // ===== parse_finalmask_udp_chain / CodecChain =====

    fn fm(v: &str) -> serde_json::Value {
        serde_json::from_str(v).unwrap()
    }

    #[test]
    fn parse_chain_none_cases() {
        assert!(parse_finalmask_udp_chain(None).unwrap().is_none());
        // 无 udp 数组
        assert!(parse_finalmask_udp_chain(Some(&fm(r#"{"tcp":[]}"#))).unwrap().is_none());
        // 空 udp 数组
        assert!(parse_finalmask_udp_chain(Some(&fm(r#"{"udp":[]}"#))).unwrap().is_none());
    }

    #[test]
    fn parse_chain_mkcp_original() {
        // Go MkcpLegacy.Build：header 空 + value 空 → original
        let chain =
            parse_finalmask_udp_chain(Some(&fm(r#"{"udp":[{"type":"mkcp-legacy","settings":{}}]}"#)))
                .unwrap()
                .unwrap();
        assert_eq!(chain.len(), 1);
        let enc = chain.encode(b"kcp-pkt").unwrap();
        // original overhead = 6（4B FNV + 2B len）
        assert_eq!(enc.len(), 7 + 6);
        assert_eq!(chain.decode(&enc).unwrap(), b"kcp-pkt");
    }

    #[test]
    fn parse_chain_mkcp_aes128gcm() {
        let chain = parse_finalmask_udp_chain(Some(&fm(
            r#"{"udp":[{"type":"mkcp-legacy","settings":{"value":"pass123"}}]}"#,
        )))
        .unwrap()
        .unwrap();
        assert_eq!(chain.len(), 1);
        let enc = chain.encode(b"secret").unwrap();
        // aes128gcm overhead = 28（12B nonce + 16B tag）
        assert_eq!(enc.len(), 6 + 28);
        assert_eq!(chain.decode(&enc).unwrap(), b"secret");
    }

    #[test]
    fn parse_chain_header_dns_defaults_domain() {
        // dns 无 value → 默认 www.baidu.com；与显式 HeaderCodec 等价
        let chain = parse_finalmask_udp_chain(Some(&fm(
            r#"{"udp":[{"type":"mkcp-legacy","settings":{"header":"DNS"}}]}"#,
        )))
        .unwrap()
        .unwrap();
        let reference = mkcp::header::HeaderCodec::new(&mkcp::header::HeaderConfig {
            id: mkcp::header::HeaderId::Dns,
            domain: "www.baidu.com".to_string(),
        })
        .unwrap();
        assert_eq!(chain.encode(b"x").unwrap().len(), reference.encode(b"x").unwrap().len());
    }

    #[test]
    fn parse_chain_all_header_kinds() {
        for (name, id) in [
            ("dtls", 1),
            ("srtp", 2),
            ("utp", 3),
            ("wechat", 4),
            ("wireguard", 5),
        ] {
            let chain = parse_finalmask_udp_chain(Some(&fm(&format!(
                r#"{{"udp":[{{"type":"mkcp-legacy","settings":{{"header":"{name}"}}}}]}}"#
            ))))
            .unwrap()
            .unwrap();
            let enc = chain.encode(b"payload").unwrap();
            assert_eq!(chain.decode(&enc).unwrap(), b"payload", "header {name}");
        }
    }

    #[test]
    fn parse_chain_stacked_masks() {
        // 两条 mkcp-legacy 叠加：aes128gcm + srtp（对齐 Go 多 mask 链）
        let chain = parse_finalmask_udp_chain(Some(&fm(
            r#"{"udp":[
                {"type":"mkcp-legacy","settings":{"value":"pw"}},
                {"type":"mkcp-legacy","settings":{"header":"srtp"}}
            ]}"#,
        )))
        .unwrap()
        .unwrap();
        assert_eq!(chain.len(), 2);
        let enc = chain.encode(b"data").unwrap();
        // aes 28 + srtp 4
        assert_eq!(enc.len(), 4 + 28 + 4);
        assert_eq!(chain.decode(&enc).unwrap(), b"data");
    }

    #[test]
    fn parse_chain_invalid_header_errors() {
        let r = parse_finalmask_udp_chain(Some(&fm(
            r#"{"udp":[{"type":"mkcp-legacy","settings":{"header":"bogus"}}]}"#,
        )));
        assert!(r.is_err());
    }

    #[test]
    fn parse_chain_unknown_type_errors() {
        let r = parse_finalmask_udp_chain(Some(&fm(r#"{"udp":[{"type":"noise"}]}"#)));
        assert!(r.is_err());
        let err = match r {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected unsupported-type error"),
        };
        assert!(err.contains("unsupported udp mask type"));
    }

    #[test]
    fn chain_decode_tampered_ciphertext_fails() {
        let chain = parse_finalmask_udp_chain(Some(&fm(
            r#"{"udp":[{"type":"mkcp-legacy","settings":{"value":"pw"}}]}"#,
        )))
        .unwrap()
        .unwrap();
        let mut enc = chain.encode(b"data").unwrap();
        enc[13] ^= 0xFF; // 翻转密文一字节
        assert!(chain.decode(&enc).is_err());
    }
}

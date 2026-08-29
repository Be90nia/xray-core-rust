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
pub trait AsyncIo: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T> AsyncIo for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

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
    pub udpmasks: Vec<Box<dyn Udpmask>>,
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
    pub tcpmasks: Vec<Box<dyn Tcpmask>>,
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

/// `Box<dyn Connection>` → `Box<dyn AsyncIo>` 上转（用于喂给 mask 模块）。
///
/// `Connection: AsyncRead + AsyncWrite + Send + Sync + Unpin` 是 `AsyncIo` 的子集
/// （`AsyncIo = AsyncRead + AsyncWrite + Send + Sync + Unpin`），但 Rust 不允许
/// `Box<dyn Connection>` → `Box<dyn AsyncIo>` 自动 upcast（vtable 顺序不同）。
/// 用 newtype 包装 + Pin 投影转接 AsyncRead/AsyncWrite forward。
fn conn_to_asyncio(conn: Box<dyn crate::connection::Connection>) -> Box<dyn AsyncIo> {
    Box::new(ConnAsAsyncIo(conn))
}

/// newtype 包装 `Box<dyn Connection>` 为 `Box<dyn AsyncIo>`，forward AsyncRead/AsyncWrite。
struct ConnAsAsyncIo(Box<dyn crate::connection::Connection>);

impl AsyncRead for ConnAsAsyncIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        AsyncRead::poll_read(this, cx, buf)
    }
}
impl AsyncWrite for ConnAsAsyncIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        AsyncWrite::poll_write(this, cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        AsyncWrite::poll_flush(this, cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        AsyncWrite::poll_shutdown(this, cx)
    }
}

/// 把 [`TcpmaskManager::wrap_conn_client`] 的 `Box<dyn AsyncIo>` 结果适配为
/// `Box<dyn Connection>`（加 `remote_addr`/`local_addr` no-op）。
///
/// 用在 TCP dial/listen 路径上：`Box<dyn Connection>` → mask 包装 → `Box<dyn Connection>`。
/// 若无 mask（`tcpmasks` 为空），原样返回输入 conn。
pub fn wrap_conn_client_into_connection(
    mgr: &TcpmaskManager,
    conn: Box<dyn crate::connection::Connection>,
) -> io::Result<Box<dyn crate::connection::Connection>> {
    if mgr.tcpmasks.is_empty() {
        return Ok(conn);
    }
    let raw: Box<dyn AsyncIo> = conn_to_asyncio(conn);
    let wrapped = apply_tcpmasks(&mgr.tcpmasks, raw, true)?;
    Ok(Box::new(AsyncIoConn(wrapped)))
}

/// 同 [`wrap_conn_client_into_connection`]，server 侧用。
pub fn wrap_conn_server_into_connection(
    mgr: &TcpmaskManager,
    conn: Box<dyn crate::connection::Connection>,
) -> io::Result<Box<dyn crate::connection::Connection>> {
    if mgr.tcpmasks.is_empty() {
        return Ok(conn);
    }
    let raw: Box<dyn AsyncIo> = conn_to_asyncio(conn);
    let wrapped = apply_tcpmasks(&mgr.tcpmasks, raw, false)?;
    Ok(Box::new(AsyncIoConn(wrapped)))
}

/// 把 `&[Box<dyn Tcpmask>]` 按 client/server 方向链式包装到 `raw`。
///
/// 对应 Go `TcpmaskManager.WrapConnClient/Server` 的语义：逆序链式 apply。
fn apply_tcpmasks(
    masks: &[Box<dyn Tcpmask>],
    mut raw: Box<dyn AsyncIo>,
    is_client: bool,
) -> io::Result<Box<dyn AsyncIo>> {
    for mask in masks.iter().rev() {
        raw = if is_client {
            mask.wrap_conn_client(raw)?
        } else {
            mask.wrap_conn_server(raw)?
        };
    }
    Ok(raw)
}

/// `Box<dyn AsyncIo>` → `Box<dyn Connection>` 适配器（`remote_addr`/`local_addr` no-op）。
struct AsyncIoConn(Box<dyn AsyncIo>);

impl AsyncRead for AsyncIoConn {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // ponytail: AsyncIoConn 是 newtype 包装，Pin 投影到 inner 字段
        // （unsafe 是必要的——Box<dyn AsyncIo> 是 Unpin，且 AsyncIo: Unpin）
        let this = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        AsyncRead::poll_read(this, cx, buf)
    }
}
impl AsyncWrite for AsyncIoConn {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        AsyncWrite::poll_write(this, cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        AsyncWrite::poll_flush(this, cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        AsyncWrite::poll_shutdown(this, cx)
    }
}

impl crate::connection::Connection for AsyncIoConn {
    fn remote_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        Ok(None)
    }
    fn local_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        Ok(None)
    }
}

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
// ===== 从 streamSettings.finalmask JSON 构造 Manager =====

/// 从 `finalmask_json` 构造 [`UdpmaskManager`]（对应 Go `streamSettings.UdpmaskManager`）。
///
/// JSON 形态与 `parse_finalmask_udp_chain` 一致：顶层为对象，`udp` 数组每项
/// `{"type","settings"}`。支持的 mask 类型（与现有模块对齐）：
///
/// - `mkcp-legacy` —— `mkcp-original` / `mkcp-aes128gcm` / `header-*`（KCP 原版）
/// - `salamander` —— `SalamanderConfig{ password }`
///
/// 未知 mask 类型返回 `InvalidInput`（不静默丢配置）。`None` 或空 `udp` 数组返回
/// 空 manager（无 mask 行为不变）。
///
/// 与 `parse_finalmask_udp_chain` 的差别：本函数返回 `UdpmaskManager`
/// （可调 `wrap_packet_conn_client/server`），后者返回 `CodecChain`（同步
/// `encode/decode`，供 KCP 等同步 UDP 栈逐包 mask）。
pub fn build_udpmask_manager_from_json(
    json: Option<&serde_json::Value>,
) -> io::Result<UdpmaskManager> {
    let mut masks: Vec<Box<dyn Udpmask>> = Vec::new();
    let Some(v) = json else { return Ok(UdpmaskManager::new(masks)); };
    let Some(arr) = v.get("udp").and_then(|x| x.as_array()) else {
        return Ok(UdpmaskManager::new(masks));
    };
    for entry in arr {
        masks.push(build_udpmask_entry(entry)?);
    }
    Ok(UdpmaskManager::new(masks))
}

fn build_udpmask_entry(entry: &serde_json::Value) -> io::Result<Box<dyn Udpmask>> {
    let obj = entry
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "mask: expected an object"))?;
    let mask_type = obj
        .get("type")
        .and_then(|t| t.as_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "mask: missing `type`"))?;
    let settings = obj.get("settings").cloned().unwrap_or(serde_json::Value::Null);
    match mask_type {
        "mkcp-legacy" => build_mkcp_legacy_udpmask(&settings),
        "salamander" => Ok(Box::new(salamander::SalamanderConfig {
            password: settings
                .get("password")
                .or_else(|| settings.get("key"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        })),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("finalmask: unsupported udp mask type {other:?}"),
        )),
    }
}

/// `mkcp-legacy` → `Udpmask`（对应 Go `MkcpLegacy.Build` UDP 形态）。
///
/// `header` 空 + `password`/`value` 空 → `OriginalConfig`。
/// `header` 空 + `password`/`value` 非空 → `Aes128GcmConfig{ password }`。
/// `header` 非空（dns/dtls/srtp/utp/wechat/wireguard）→ `HeaderConfig::from_id(...)`。
fn build_mkcp_legacy_udpmask(settings: &serde_json::Value) -> io::Result<Box<dyn Udpmask>> {
    let header = settings
        .get("header")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let password = settings
        .get("password")
        .or_else(|| settings.get("value"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !header.is_empty() {
        // ponytail: dns 用 value 字段作 domain（与 codec 路径一致），其他 header 忽略 value
        let domain = settings
            .get("domain")
            .or_else(|| settings.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or("www.baidu.com")
            .to_string();
        let id = match header.to_ascii_lowercase().as_str() {
            "dns" => mkcp::header::HeaderId::Dns,
            "dtls" => mkcp::header::HeaderId::Dtls,
            "srtp" => mkcp::header::HeaderId::Srtp,
            "utp" => mkcp::header::HeaderId::Utp,
            "wechat" => mkcp::header::HeaderId::Wechat,
            "wireguard" => mkcp::header::HeaderId::Wireguard,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("finalmask: invalid header {header:?}"),
                ));
            }
        };
        let cfg = mkcp::header::HeaderConfig { id, domain };
        return Ok(Box::new(cfg));
    }
    if !password.is_empty() {
        return Ok(Box::new(mkcp::aes128gcm::Aes128GcmConfig {
            password: password.to_string(),
        }));
    }
    Ok(Box::new(mkcp::original::OriginalConfig))
}

/// 从 `finalmask_json` 构造 [`TcpmaskManager`]（对应 Go `streamSettings.TcpmaskManager`）。
///
/// JSON 形态顶层对象 `tcp` 数组，每项 `{"type","settings"}`。当前支持：
///
/// - `fragment` —— `FragmentConfig{ packets_from, packets_to, length, interval }`
///
/// 未知 mask 类型返回 `InvalidInput`。`None` / 缺失 `tcp` 键 / 空数组 → 空 manager。
pub fn build_tcpmask_manager_from_json(
    json: Option<&serde_json::Value>,
) -> io::Result<TcpmaskManager> {
    let mut masks: Vec<Box<dyn Tcpmask>> = Vec::new();
    let Some(v) = json else { return Ok(TcpmaskManager::new(masks)); };
    let Some(arr) = v.get("tcp").and_then(|x| x.as_array()) else {
        return Ok(TcpmaskManager::new(masks));
    };
    for entry in arr {
        masks.push(build_tcpmask_entry(entry)?);
    }
    Ok(TcpmaskManager::new(masks))
}

fn build_tcpmask_entry(entry: &serde_json::Value) -> io::Result<Box<dyn Tcpmask>> {
    let obj = entry
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "mask: expected an object"))?;
    let mask_type = obj
        .get("type")
        .and_then(|t| t.as_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "mask: missing `type`"))?;
    let settings = obj.get("settings").cloned().unwrap_or(serde_json::Value::Null);
    match mask_type {
        "fragment" => build_fragment_config(&settings).map(|c| Box::new(c) as Box<dyn Tcpmask>),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("finalmask: unsupported tcp mask type {other:?}"),
        )),
    }
}

fn build_fragment_config(settings: &serde_json::Value) -> io::Result<fragment::FragmentConfig> {
    fn opt_u64(v: &serde_json::Value, key: &str) -> u64 {
        v.get(key).and_then(|x| x.as_u64()).unwrap_or(0)
    }
    fn opt_i64(v: &serde_json::Value, key: &str) -> i64 {
        v.get(key).and_then(|x| x.as_i64()).unwrap_or(0)
    }
    // ponytail: Go `length`/`interval` 是单值 range {from, to}；Rust 端
    // FragmentConfig 字段是 `Vec<i64>`，单元素 = 单段 range。
    fn opt_range1(v: &serde_json::Value, key: &str) -> (i64, i64) {
        let r = v.get(key);
        match r {
            Some(serde_json::Value::Object(o)) => {
                let from = o.get("from").and_then(|x| x.as_i64()).unwrap_or(0);
                let to = o.get("to").and_then(|x| x.as_i64()).unwrap_or(from);
                (from, to)
            }
            Some(serde_json::Value::Number(n)) => {
                let x = n.as_i64().unwrap_or(0);
                (x, x)
            }
            _ => (0, 0),
        }
    }
    let (length_min, length_max) = opt_range1(settings, "length");
    let (delay_min, delay_max) = opt_range1(settings, "interval");
    Ok(fragment::FragmentConfig {
        packets_from: opt_u64(settings, "packets_from"),
        packets_to: opt_u64(settings, "packets_to"),
        max_split_min: opt_i64(settings, "max_split"),
        max_split_max: opt_i64(settings, "max_split"),
        lengths_min: vec![length_min],
        lengths_max: vec![length_max],
        delays_min: vec![delay_min],
        delays_max: vec![delay_max],
    })
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

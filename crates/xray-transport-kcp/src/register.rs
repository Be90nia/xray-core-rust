//! mKCP transport dialer + listener 注册。
//!
//! dialer: 完整拨号流程——解析配置 → UDP socket → KcpDialerFactory → Connection → KcpConn。
//! listener: 完整监听流程——StdUdpHub bind → Listener → spawn UDP recv loop → bridge → upstream ConnHandler.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use xray_transport::dialer::{StreamSettings, TransportDialFn, register_transport_dialer};
use xray_transport::listener_registry::{
    ConnHandler, TransportListener, TransportListenFn, register_transport_listener,
};

use crate::config::{Config, default_config};
use crate::listener::{ConnHandler as KcpConnHandler, Listener, UdpHub};
use crate::connection::{ConnMetadata, Connection, ConnectionCloser, KcpConn};
use crate::dialer::{KcpDialerFactory, PacketInput, next_conv};
use crate::io::{KCPPacketReader, PacketReader as _};
use crate::output::{RetryableWriter, SegmentWriter, SimpleSegmentWriter};
use xray_transport::finalmask::{parse_finalmask_udp_chain, CodecChain};

use crate::udp_hub::{MaskedPacketInput, MaskedUdpHub, StdPacketInput, StdUdpHub};
use crate::PROTOCOL_NAME;

/// 注册 mKCP transport dialer。
///
/// 完整拨号流程：
/// 1. 解析 `kcpSettings` JSON → KCP `Config`
/// 2. 创建 UDP socket → `StdUdpHub`
/// 3. `KcpDialerFactory` 创建底层连接 + `SimpleSegmentWriter`
/// 4. `Connection::new()` → spawn `fetch_input` 循环
/// 5. `KcpConn` 包装 → `Box<dyn Connection>`
///
/// 幂等：重复注册的 `AlreadyExists` 被忽略。
/// 协议名同时注册 `"mkcp"`（Go 标准）和 `"kcp"`（部分客户端配置简写）。
pub fn register_dialer() -> io::Result<()> {
    let dialer: TransportDialFn = Arc::new(move |dest, _sockopt, settings| {
        let dest = dest.clone();
        let settings = settings.clone();
        Box::pin(async move { dial_kcp(&dest, &settings).await })
    });
    // ponytail: 重复注册忽略——主代理与测试可能并发触发注册
    let _ = register_transport_dialer(PROTOCOL_NAME, dialer.clone());
    let _ = register_transport_dialer("kcp", dialer);
    Ok(())
}

/// 注册 mKCP transport listener。
///
/// 完整监听流程：
/// 1. 解析 `kcpSettings` JSON → KCP `Config`
/// 2. `StdUdpHub::bind(addr)` 绑定 UDP socket
/// 3. `Listener::new(hub, reader, config, bridge)` 创建 KCP listener
/// 4. `spawn_blocking` 跑 UDP 接收循环（`handle_one_packet`）
/// 5. 新 conv 首包到达时，bridge 把 `Arc<Connection>` 包装为 `KcpConn` 调 upstream handler
///
/// 幂等：重复注册的 `AlreadyExists` 被忽略。
/// 协议名同时注册 `"mkcp"`（Go 标准）和 `"kcp"`（部分客户端配置简写）。
pub fn register_listener() -> io::Result<()> {
    let listen_fn: TransportListenFn = Arc::new(|addr, settings, _sockopt, handler| {
        Box::pin(async move { listen_kcp(addr, settings, handler).await })
    });
    // ponytail: 重复注册忽略——主代理与测试可能并发触发注册
    let _ = register_transport_listener(PROTOCOL_NAME, listen_fn.clone());
    let _ = register_transport_listener("kcp", listen_fn);
    Ok(())
}

/// 实际监听：解析配置 → bind UDP → Listener → spawn recv loop。
async fn listen_kcp(
    addr: SocketAddr,
    settings: StreamSettings,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    // 1. 解析 kcpSettings JSON + finalmask 伪装链
     let config = parse_kcp_config(settings.transport_json.as_ref())?;
    let chain = parse_finalmask_udp_chain(settings.finalmask_json.as_ref())?;
 
     // 2. 绑定 UDP socket
    // mask 开启时包装 hub（对应 Go udp.Hub 建立时 WrapPacketConnServer，udp/hub.go:71-72）
    let hub: Arc<dyn UdpHub> = {
        let raw = Arc::new(StdUdpHub::bind(addr)?);
        match chain {
            Some(c) => Arc::new(MaskedUdpHub::new(raw, c)),
            None => raw,
        }
    };
     let local = hub
         .local_addr()
         .ok_or_else(|| io::Error::other("kcp listener: local_addr unavailable after bind"))?;
    // 3. packet reader + bridge handler（KCP ConnHandler → upstream xray_transport::ConnHandler）
    let reader = Arc::new(KCPPacketReader::new());
    let bridge: Arc<dyn KcpConnHandler> = Arc::new(UpstreamConnBridge(handler));

    // 4. 创建 KCP Listener
    let listener = Listener::new(hub, reader, Arc::new(config), bridge);

    // 5. spawn UDP recv loop（阻塞读 hub，分发到 KCP sessions）
    let listener_clone = Arc::clone(&listener);
    tokio::task::spawn_blocking(move || {
        while listener_clone.handle_one_packet() {}
    });

    Ok(Box::new(KcpTransportListener { listener, local }))
}

/// bridge：KCP `ConnHandler` trait → upstream `xray_transport::ConnHandler` 回调。
///
/// 把每个新 `Arc<Connection>` 包装为 `KcpConn`（impl `xray_transport::Connection`）后调 upstream。
struct UpstreamConnBridge(ConnHandler);

impl KcpConnHandler for UpstreamConnBridge {
    fn add_conn(&self, conn: Arc<Connection>) {
        (self.0)(Box::new(KcpConn::new(conn)));
    }
}

/// mKCP `TransportListener` 实现：持有 `Arc<Listener>` 用于 close。
struct KcpTransportListener {
    listener: Arc<Listener>,
    local: SocketAddr,
}

impl TransportListener for KcpTransportListener {
    fn close(&self) -> io::Result<()> {
        self.listener
            .close()
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

impl Drop for KcpTransportListener {
    fn drop(&mut self) {
        // spawn_blocking 接收循环靠 hub closed 标志退出；不关则 Runtime::drop
        // 等待 blocking task 永不返回（上层持有者被 abort/直接 drop 时兜底）。
        let _ = TransportListener::close(self);
    }
}

/// 实际拨号：解析配置 → UDP → KcpDialerFactory → Connection → KcpConn。
async fn dial_kcp(
    dest: &xray_common::net::destination::Destination,
    settings: &StreamSettings,
) -> io::Result<Box<dyn xray_transport::connection::Connection>> {
    // 1. 解析 kcpSettings JSON + finalmask 伪装链
    let config = parse_kcp_config(settings.transport_json.as_ref())?;
    // mask 开启时包装 PacketConn（对应 Go dialer.go:59-82 WrapPacketConnClient）
    let chain = parse_finalmask_udp_chain(settings.finalmask_json.as_ref())?;

    // 2. 解析目标地址（对齐 Go internet.DialSystem：Domain 也解析）
    let dest_addr = resolve_dest_to_socket_addr(dest).await?;

    // 3. 创建 UDP socket + KcpDialerFactory（chain = None 时裸 segment，向后兼容）
    let factory = StdKcpDialerFactory { chain };

    // 4. 通过 factory 创建底层连接
    let conv = next_conv();
    let dest_str = dest_addr.to_string();
    let (mut packet_input, segment_writer, closer, _meta) = factory
        .dial_udp(&dest_str)
        .map_err(|e| io::Error::other(format!("kcp dial_udp failed: {e}")))?;

    // 5. 构造 Connection 元数据
    let meta = ConnMetadata {
        conv,
        local_addr: None, // UDP socket local addr unknown until connected
        remote_addr: Some(dest_addr),
    };

    // 6. 创建 KCP Connection
    let conn = Arc::new(Connection::new(
        meta,
        segment_writer,
        closer,
        Arc::new(config),
    ));

    // 7. spawn fetch_input 循环（后台读 UDP 包并分发到 Connection）。
    //    铁律：阻塞读 packet_input 期间绝不持有 conn 强引用。若持 Arc 等待，
    //    Connection 的最后一个强引用在循环自己手里 → ConnectionInner::drop
    //    永不发生 → closer 置 closed 标志永不触发 → read_packet 永不返回
    //    （自持挂死；Runtime::drop 等待 blocking task = 测试/进程挂死）。
    //    正确形态：先 read_packet 阻塞读，读到包后再 upgrade 分发。
    let conn_weak = Arc::downgrade(&conn);
    let reader = KCPPacketReader::new();
    tokio::task::spawn_blocking(move || {
        loop {
            let Some(payload) = packet_input.read_packet() else { break };
            let Some(conn_now) = conn_weak.upgrade() else { break };
            let segments = reader.read(&payload);
            if !segments.is_empty() {
                conn_now.input(segments);
            }
        }
    });

    Ok(Box::new(KcpConn::new(conn)))
}

/// 从 `kcpSettings` JSON 解析为 KCP [`Config`]。
///
/// 接受的 JSON 字段（对齐 proto3 JSON camelCase）：
/// - `mtu`：最大传输单元（>=21，Go `transport_method.go:562`）
/// - `tti`：传输时间间隔 ms ∈ [10,1000]，Go :565
/// - `uplinkCapacity`：上行容量
/// - `downlinkCapacity`：下行容量
/// - `cwndMultiplier`：拥塞窗口倍数（>=1，Go :568）
/// - `maxSendingWindow`：发送窗口字节（>=mtu，Go :571 / `GetSendingBufferSize()==0`）
///
/// `congestion`/`readBufferSize`/`writeBufferSize` 三个键 Go v26 已删，本函数不解析
/// （与历史行为一致）。
///
/// `None` 返回默认配置。
///
/// tslk：对齐 Go 硬校验——mtu<21 / tti<10||>1000 / cwndMultiplier<1 /
/// maxSendingWindow<mtu / 任意字段为负数 全部启动期报错（之前静默回绕为 u32 大值）。
fn parse_kcp_config(json: Option<&serde_json::Value>) -> io::Result<Config> {
    let Some(v) = json else { return Ok(default_config()); };
    let Some(obj) = v.as_object() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kcpSettings must be a JSON object",
        ));
    };

    // `header`/`seed` 已移除（Go infra/conf/transport_internet.go:66-68，
    // PrintRemovedFeatureError，两键合并为单一文案），伪装配置迁移到
    // `streamSettings.finalmask.udp`（`mkcp-legacy`）。保留 Rust 现有硬报错行为。
    if obj.contains_key("header") || obj.contains_key("seed") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            xray_common::errors::removed_feature_message(
                "mkcp header & seed",
                "finalmask/udp header-* & mkcp-original & mkcp-aes128gcm",
            ),
        ));
    }

    let mut config = default_config();

    // mtu：负数先报"must be non-negative"，免去后续 < 21 误报。
    if let Some(v) = obj.get("mtu") {
        let n = v.as_i64().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "kcpSettings.mtu must be a number")
        })?;
        if n < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("kcpSettings.mtu must be non-negative (got {n})"),
            ));
        }
        config.mtu = n as u32;
    }
    // tti：[10,1000]。
    if let Some(v) = obj.get("tti") {
        let n = v.as_i64().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "kcpSettings.tti must be a number")
        })?;
        if n < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("kcpSettings.tti must be non-negative (got {n})"),
            ));
        }
        config.tti = n as u32;
    }
    // uplinkCapacity / downlinkCapacity：负数拒。
    for &field in &["uplinkCapacity", "downlinkCapacity"] {
        if let Some(v) = obj.get(field) {
            let n = v.as_i64().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("kcpSettings.{field} must be a number"),
                )
            })?;
            if n < 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("kcpSettings.{field} must be non-negative (got {n})"),
                ));
            }
            if field == "uplinkCapacity" {
                config.uplink_capacity = n as u32;
            } else {
                config.downlink_capacity = n as u32;
            }
        }
    }
    // cwndMultiplier：>=1（Go :568）。
    if let Some(v) = obj.get("cwndMultiplier") {
        let n = v.as_i64().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "kcpSettings.cwndMultiplier must be a number",
            )
        })?;
        if n < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("kcpSettings.cwndMultiplier must be non-negative (got {n})"),
            ));
        }
        config.cwnd_multiplier = n as u32;
    }
    // maxSendingWindow：负数拒。
    if let Some(v) = obj.get("maxSendingWindow") {
        let n = v.as_i64().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "kcpSettings.maxSendingWindow must be a number",
            )
        })?;
        if n < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("kcpSettings.maxSendingWindow must be non-negative (got {n})"),
            ));
        }
        config.max_sending_window = n as u32;
    }

    // Go `transport_method.go:562-573` 四条硬校验。错误措辞逐字对齐，便于运维
    // 直接照抄 Go 日志排除。
    if config.mtu < 21 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Mtu must be at least 21",
        ));
    }
    if config.tti < 10 || config.tti > 5000 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid mKCP TTI: {}", config.tti),
        ));
    }
    if config.cwnd_multiplier < 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CwndMultiplier must be at least 1",
        ));
    }
    // Go `GetSendingBufferSize() == MaxSendingWindow / Mtu`，==0 即报错。
    if config.max_sending_window / config.mtu == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "MaxSendingWindow must be >= Mtu",
        ));
    }

    Ok(config)
}
/// 把 `Destination` 解析为 `SocketAddr`。
///
/// 对齐 Go `DialKCP` 的 `internet.DialSystem`（net 系统拨号，域名/IP 字面量
/// 均可解析）：IP 直取，Domain（含 `"127.0.0.1"` 字面量——xray-conf 的
/// vnext address 惯以 Domain 承载）经系统 resolver 解析。
/// ponytail: `ToSocketAddrs` 同步解析会占 runtime 线程；Go runtime 同样
/// 线程池 getaddrinfo，DNS 热路径成瓶颈时再换异步 resolver。
/// ejom：把 `Destination` 异步解析为 `SocketAddr`。
///
/// 对齐 Go `DialKCP` 的 `internet.DialSystem`（net 系统拨号，域名/IP 字面量
/// 均可解析）：IP 字面量直接 parse，Domain 经 `tokio::net::lookup_host` 异步解析。
///
/// 与旧 `ToSocketAddrs`（同步 getaddrinfo，会占 runtime 线程）相比，
/// `lookup_host` 跑在 tokio reactor 线程池上，热路径 DNS 不再阻塞 worker。
async fn resolve_dest_to_socket_addr(
    dest: &xray_common::net::destination::Destination,
) -> io::Result<SocketAddr> {
    let host = dest.address().to_string();
    let port = dest.port().value();
    // 1. IP 字面量快路径
    if let Ok(addr) = format!("{host}:{port}").parse::<SocketAddr>() {
        return Ok(addr);
    }
    // 2. 域名 → tokio 异步 DNS 解析
    let mut addrs = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| io::Error::other(format!("kcp DNS resolve {host}: {e}")))?;
    addrs.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("kcp dest resolved to no address: {host}"),
        )
    })
}

// ===== StdKcpDialerFactory =====

/// 基于 `StdUdpHub` 的 `KcpDialerFactory` 实现。
struct StdKcpDialerFactory {
    /// finalmask 伪装链；`None` = 裸 segment（向后兼容）。
    chain: Option<CodecChain>,
}

impl KcpDialerFactory for StdKcpDialerFactory {
    fn dial_udp(
        &self,
        dest: &str,
    ) -> crate::error::Result<(
        Box<dyn PacketInput>,
        Arc<dyn SegmentWriter>,
        Arc<dyn ConnectionCloser>,
        ConnMetadata,
    )> {
        let dest_addr: SocketAddr = dest.parse().map_err(|e: std::net::AddrParseError| {
            crate::error::KcpError::Io(std::io::Error::other(format!("invalid dest addr: {e}")))
        })?;

        // 绑定本地 UDP socket
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        let local_addr = socket.local_addr().ok();
        socket.connect(dest_addr)?;

        // 创建 StdUdpHub（用于 SegmentWriter 写 UDP；关闭标志与 PacketInput/closer 共享）
        let hub = StdUdpHub::from_socket(socket);
        let closed_flag = hub.closed_flag();

        // 创建 PacketInput（从 hub 读取 UDP 包；mask 开启时 decode，对应 Go masked pktConn 读）
        let packet_input: Box<dyn PacketInput> = match &self.chain {
            Some(c) => Box::new(MaskedPacketInput::new(
                Box::new(StdPacketInput::from_hub(&hub)),
                c.clone(),
            )),
            None => Box::new(StdPacketInput::from_hub(&hub)),
        };

        // 创建 SegmentWriter（通过 hub 写 UDP 包到目标；mask 开启时 encode）
        let writer = UdpSegmentWriter {
            hub,
            chain: self.chain.clone(),
        };
        // k3kh：套 RetryableWriter（5×100ms 重试）对齐 Go `NewRetryableWriter`。
        // 同步 sleep：上层在 KCP worker 同步 flush 上下文调用，等价 Go retry.Timed 语义。
        let segment_writer: Arc<dyn SegmentWriter> = Arc::new(RetryableWriter::new(Arc::new(SimpleSegmentWriter::new(writer))));

        // 创建 Closer（共享 hub 关闭标志：conn drop → 置位 → 阻塞读退出）
        let closer: Arc<dyn ConnectionCloser> = Arc::new(StdUdpCloser { closed: closed_flag });

        let meta = ConnMetadata {
            conv: 0, // conv 由上层设置
            local_addr,
            remote_addr: Some(dest_addr),
        };

        Ok((packet_input, segment_writer, closer, meta))
    }
}

/// UDP segment 写入器（通过 `StdUdpHub` 写 UDP 包；mask 开启时先 encode）。
struct UdpSegmentWriter {
    hub: StdUdpHub,
    /// finalmask 伪装链；`None` = 裸 segment。
    chain: Option<CodecChain>,
}

impl crate::output::UnderlyingWriter for UdpSegmentWriter {
    fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        use std::borrow::Cow;
        // mask 开启时逐包 encode（对应 Go masked pktConn 写）
        let pkt = match &self.chain {
            Some(c) => Cow::Owned(c.encode(buf)?),
            None => Cow::Borrowed(buf),
        };
        // ponytail: connected UDP socket 用 send()，KCP segment < MTU 所以单次 send 足够
        let sock = self.hub.socket_handle();
        let mut written = 0;
        while written < pkt.len() {
            let n = sock.send(&pkt[written..])?;
            written += n;
        }
        Ok(())
    }
}

/// UDP socket closer：置位共享关闭标志，唤醒阻塞的接收循环。
struct StdUdpCloser {
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl ConnectionCloser for StdUdpCloser {
    fn close(&self) {
        self.closed.store(true, std::sync::atomic::Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_dialer_is_idempotent() {
        register_dialer().expect("first register ok");
        register_dialer().expect("second register ok (idempotent)");
    }

    #[test]
    fn parse_kcp_config_none_returns_default() {
        let cfg = parse_kcp_config(None).unwrap();
        assert_eq!(cfg.mtu, 1350);
        assert_eq!(cfg.tti, 50);
    }

    #[test]
    fn parse_kcp_config_basic_fields() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"mtu":1400,"tti":30,"uplinkCapacity":10,"downlinkCapacity":50,"cwndMultiplier":5,"maxSendingWindow":4194304}"#,
        )
        .unwrap();
        let cfg = parse_kcp_config(Some(&v)).unwrap();
        assert_eq!(cfg.mtu, 1400);
        assert_eq!(cfg.tti, 30);
        assert_eq!(cfg.uplink_capacity, 10);
        assert_eq!(cfg.downlink_capacity, 50);
        assert_eq!(cfg.cwnd_multiplier, 5);
        assert_eq!(cfg.max_sending_window, 4194304);
    }

    #[test]
    fn parse_kcp_config_non_object_returns_err() {
        let v: serde_json::Value = serde_json::from_str(r#""not-an-object""#).unwrap();
        let r = parse_kcp_config(Some(&v));
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn parse_kcp_config_rejects_removed_header() {
        // Go v26 KCPConfig.Build：header/seed 已移除（PrintRemovedFeatureError，
        // transport_internet.go:67，header/seed 合并为单一文案）
        let v: serde_json::Value =
            serde_json::from_str(r#"{"header":{"type":"srtp"}}"#).unwrap();
        let err = match parse_kcp_config(Some(&v)) {
            Err(e) => e,
            Ok(_) => panic!("expected removed-feature error for header"),
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            err.to_string(),
            "The feature mkcp header & seed has been removed and migrated to \
             finalmask/udp header-* & mkcp-original & mkcp-aes128gcm. Please update your \
             config(s) according to release note and documentation."
        );
    }

    #[test]
    fn parse_kcp_config_rejects_removed_seed() {
        let v: serde_json::Value = serde_json::from_str(r#"{"seed":"pw"}"#).unwrap();
        let err = match parse_kcp_config(Some(&v)) {
            Err(e) => e,
            Ok(_) => panic!("expected removed-feature error for seed"),
        };
        // 同一触发点：Go 对 header||seed 用同一文案
        assert!(err.to_string().contains("The feature mkcp header & seed has been removed"));
    }

    // ============= tslk：对齐 Go 硬校验的错误行为测试 =============

    fn err_msg(json: &str) -> String {
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        parse_kcp_config(Some(&v))
            .err()
            .unwrap_or_else(|| panic!("expected error for {json}"))
            .to_string()
    }

    #[test]
    fn tslk_rejects_mtu_below_21() {
        // Go transport_method.go:562 — "Mtu must be at least 21"
        let msg = err_msg(r#"{"mtu":20}"#);
        assert!(msg.contains("Mtu must be at least 21"), "got: {msg}");
    }

    #[test]
    fn tslk_rejects_negative_mtu() {
        // 负数先于 <21 触发：避免被解释为 u32 大值绕过校验。
        let msg = err_msg(r#"{"mtu":-1}"#);
        assert!(msg.contains("mtu must be non-negative"), "got: {msg}");
    }

    #[test]
    fn tslk_rejects_tti_too_small() {
        // Go :565 — tti < 10
        let msg = err_msg(r#"{"tti":9}"#);
        assert!(msg.contains("invalid mKCP TTI"), "got: {msg}");
    }

    #[test]
    fn tslk_rejects_tti_too_large() {
        // Go `transport_internet.go:75` PR #5755 — tti > 5000
        let msg = err_msg(r#"{"tti":5001}"#);
        assert!(msg.contains("invalid mKCP TTI"), "got: {msg}");
    }

    #[test]
    fn tslk_accepts_tti_at_upper_bound() {
        // Go PR #5755 — tti == 5000 是合法边界值。
        let v: serde_json::Value = serde_json::from_str(r#"{"tti":5000}"#).unwrap();
        let cfg = parse_kcp_config(Some(&v)).expect("tti=5000 should be accepted");
        assert_eq!(cfg.tti, 5000);
    }

    #[test]
    fn tslk_accepts_tti_at_lower_bound() {
        // Go PR #5755 — tti == 10 是合法边界值。
        let v: serde_json::Value = serde_json::from_str(r#"{"tti":10}"#).unwrap();
        let cfg = parse_kcp_config(Some(&v)).expect("tti=10 should be accepted");
        assert_eq!(cfg.tti, 10);
    }

    #[test]
    fn tslk_rejects_tti_negative() {
        let msg = err_msg(r#"{"tti":-5}"#);
        assert!(msg.contains("tti must be non-negative"), "got: {msg}");
    }

    #[test]
    fn tslk_rejects_cwnd_multiplier_zero() {
        // Go :568 — CwndMultiplier < 1
        let msg = err_msg(r#"{"cwndMultiplier":0}"#);
        assert!(msg.contains("CwndMultiplier must be at least 1"), "got: {msg}");
    }

    #[test]
    fn tslk_rejects_cwnd_multiplier_negative() {
        let msg = err_msg(r#"{"cwndMultiplier":-3}"#);
        assert!(
            msg.contains("cwndMultiplier must be non-negative"),
            "got: {msg}"
        );
    }

    #[test]
    fn tslk_rejects_max_sending_window_smaller_than_mtu() {
        // Go :571 — GetSendingBufferSize == 0 (即 MaxSendingWindow < Mtu)
        let msg = err_msg(r#"{"mtu":1400,"maxSendingWindow":1399}"#);
        assert!(
            msg.contains("MaxSendingWindow must be >= Mtu"),
            "got: {msg}"
        );
    }

    #[test]
    fn tslk_rejects_negative_uplink_capacity() {
        let msg = err_msg(r#"{"uplinkCapacity":-1}"#);
        assert!(
            msg.contains("uplinkCapacity must be non-negative"),
            "got: {msg}"
        );
    }

    #[test]
    fn tslk_rejects_negative_downlink_capacity() {
        let msg = err_msg(r#"{"downlinkCapacity":-1}"#);
        assert!(
            msg.contains("downlinkCapacity must be non-negative"),
            "got: {msg}"
        );
    }

    #[test]
    fn tslk_rejects_negative_max_sending_window() {
        let msg = err_msg(r#"{"maxSendingWindow":-1}"#);
        assert!(
            msg.contains("maxSendingWindow must be non-negative"),
            "got: {msg}"
        );
    }

    #[test]
    fn tslk_accepts_minimal_valid_kcp_settings() {
        // 边界：mtu=21, tti=10, cwndMultiplier=1, maxSendingWindow=21。
        // MaxSendingWindow/Mtu = 21/21 = 1 ≠ 0 通过。
        let v: serde_json::Value = serde_json::from_str(
            r#"{"mtu":21,"tti":10,"cwndMultiplier":1,"maxSendingWindow":21}"#,
        )
        .unwrap();
        let cfg = parse_kcp_config(Some(&v)).expect("minimal valid kcp settings");
        assert_eq!(cfg.mtu, 21);
        assert_eq!(cfg.tti, 10);
        assert_eq!(cfg.cwnd_multiplier, 1);
    }

    #[test]
    fn tslk_rejects_non_numeric_field() {
        // mtu="abc" 应为 InvalidData（非数字）而非默默忽略。
        let msg = err_msg(r#"{"mtu":"abc"}"#);
        assert!(msg.contains("mtu must be a number"), "got: {msg}");
    }

    // ===== ejom：kcp 异步 DNS 解析 =====

    /// IP 字面量地址走快路径（不调 lookup_host）。
    #[tokio::test]
    async fn ejom_resolve_ipv4_literal_skips_dns() {
        use xray_common::net::address::Address;
        use xray_common::net::destination::Destination;
        use xray_common::net::port::Port;
        let dest = Destination::tcp(
            Address::IPv4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            Port::new(14550),
        );
        let addr = resolve_dest_to_socket_addr(&dest).await.expect("resolve ok");
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert_eq!(addr.port(), 14550);
    }

    /// localhost 域名经 `tokio::net::lookup_host` 异步解析（环回 127.0.0.1 或 ::1）。
    #[tokio::test]
    async fn ejom_resolve_localhost_via_async_dns() {
        use xray_common::net::address::Address;
        use xray_common::net::destination::Destination;
        use xray_common::net::port::Port;
        let dest = Destination::tcp(
            Address::Domain("localhost".to_string()),
            Port::new(8080),
        );
        let addr = resolve_dest_to_socket_addr(&dest).await.expect("resolve ok");
        // 接受 IPv4 或 IPv6 环回（系统 hosts 文件决定）
        assert!(addr.ip().is_loopback(), "got non-loopback {addr}");
        assert_eq!(addr.port(), 8080);
    }

    /// 未知域名解析失败 → 返回 io::Error。
    #[tokio::test]
    async fn ejom_resolve_unknown_domain_returns_err() {
        use xray_common::net::address::Address;
        use xray_common::net::destination::Destination;
        use xray_common::net::port::Port;
        // RFC 6761 保留 TLD，规定解析必须失败
        let dest = Destination::tcp(
            Address::Domain("nonexistent.invalid".to_string()),
            Port::new(1),
        );
        let res = resolve_dest_to_socket_addr(&dest).await;
        assert!(res.is_err(), "invalid TLD must fail to resolve");
    }

}

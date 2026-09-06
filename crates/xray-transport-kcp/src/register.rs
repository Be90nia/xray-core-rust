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
use crate::output::{SegmentWriter, SimpleSegmentWriter};
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
    let dest_addr = resolve_dest_to_socket_addr(dest)?;

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

    // 7. spawn fetch_input 循环（在后台读取 UDP 包并分发到 Connection）。
    //    持 Weak 而非 Arc：conn drop（含 task abort 等无 shutdown 路径）后，
    //    ConnectionInner::drop → closer 置 closed 标志 → read_packet 退出，
    //    本 blocking task 结束——否则 Runtime::drop 等待永不返回（测试挂死）。
    let conn_weak = Arc::downgrade(&conn);
    let reader = KCPPacketReader::new();
    tokio::task::spawn_blocking(move || {
        loop {
            let Some(conn_now) = conn_weak.upgrade() else { break };
            match packet_input.read_packet() {
                Some(payload) => {
                    let segments = reader.read(&payload);
                    if !segments.is_empty() {
                        conn_now.input(segments);
                    }
                }
                None => break,
            }
        }
    });



    Ok(Box::new(KcpConn::new(conn)))
}

/// 从 `kcpSettings` JSON 解析为 KCP [`Config`]。
///
/// 接受的 JSON 字段（对齐 proto3 JSON camelCase）：
/// - `mtu`：最大传输单元
/// - `tti`：传输时间间隔（ms）
/// - `uplinkCapacity`：上行容量
/// - `downlinkCapacity`：下行容量
/// - `congestion`：是否启用拥塞控制
/// - `readBufferSize`：读缓冲区大小
/// - `writeBufferSize`：写缓冲区大小
///
/// `None` 返回默认配置。
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

    if let Some(v) = obj.get("mtu").and_then(|x| x.as_i64()) {
        config.mtu = v as u32;
    }
    if let Some(v) = obj.get("tti").and_then(|x| x.as_i64()) {
        config.tti = v as u32;
    }
    if let Some(v) = obj.get("uplinkCapacity").and_then(|x| x.as_i64()) {
        config.uplink_capacity = v as u32;
    }
    if let Some(v) = obj.get("downlinkCapacity").and_then(|x| x.as_i64()) {
        config.downlink_capacity = v as u32;
    }
    if let Some(v) = obj.get("cwndMultiplier").and_then(|x| x.as_i64()) {
        config.cwnd_multiplier = v as u32;
    }
    if let Some(v) = obj.get("maxSendingWindow").and_then(|x| x.as_i64()) {
        config.max_sending_window = v as u32;
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
fn resolve_dest_to_socket_addr(
    dest: &xray_common::net::destination::Destination,
) -> io::Result<SocketAddr> {
    use std::net::ToSocketAddrs;
    let host = dest.address().to_string();
    (host.as_str(), dest.port().value())
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| {
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
        let segment_writer: Arc<dyn SegmentWriter> = Arc::new(SimpleSegmentWriter::new(writer));

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
}

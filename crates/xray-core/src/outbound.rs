//! Outbound handler 注册：从 BuiltConfig 构建 DialBridge 注册到 SimpleOhm。
//!
//! 对应 Go `core.addOutboundHandlers`：遍历配置中的 outbound 列表，
//! 按协议创建 handler（DialBridge 包装 dial_fn），注册到 Ohm（OutboundHandlerManager）。
//!
//! ## 当前支持
//!
//! - **freedom**：完整支持（无 settings）
//! - **vless**：JSON 解析 `vnext` → [`VlessOutboundConfig`] → `make_dial_fn`（raw TCP，不含 streamSettings）
//! - **trojan**：JSON 解析 `servers` → [`TrojanOutboundConfig`] → `make_dial_fn`（raw TCP，不含 streamSettings）
//! - **blackhole**：JSON 解析 `response.type` → [`BlackholeHandler`]（DispatchHandler，不拨号）
//! - **socks**：JSON 解析 `servers[0]` → [`SocksClient`] + `make_socks_dial_fn`（SOCKS5 outbound）
//! - **vmess**：JSON 解析 `vnext[0]` → `VmessOutboundConfig` → `make_vmess_dial_fn`
//! - **shadowsocks**：JSON 解析 `servers[0]` → `SsOutboundConfig` → `make_ss_dial_fn`
//! - **shadowsocks**：JSON 解析 `servers[0]` → SsOutbound → OutboundHandlerBridge（stub dial）
//! - **hysteria**：JSON 解析 → HysteriaOutboundHandler → OutboundHandlerBridge（stub dial）
//! - **anytls**：JSON 解析 → `AnytlsClient` → `make_anytls_dial_fn`
//! - **tuic**：JSON 解析 → TuicClient → `make_tuic_dial_fn`
//! - **wireguard**：JSON 解析 → WireguardOutboundHandler → OutboundHandlerBridge（stub dial）
//! - **dns**：JSON 解析 → `DnsDispatchBridge`（拦截 DNS 查询并转发）
//! - **loopback**：JSON 解析 → LoopbackHandler（直接 impl DispatchHandler）
//! - **http**：JSON 解析 `servers[0]` → `HttpOutboundConfig` → `make_http_dial_fn`
//! - **dokodemo**：JSON 解析 → `DokodemoOutboundConfig` → `make_dokodemo_dial_fn`（拨号到配置的 rewrite_address:rewrite_port）
//! - **tun**：`make_tun_dial_fn`（系统拨号，TUN 路由由 OS 处理）
//! ## streamSettings
//!
//! 当前不处理 streamSettings（TLS/WS/Reality）—— vless/trojan 走裸 TCP `dial_system`。
//! transport 层补全后，`try_build_handler` 将在此注入 TLS-wrapped 拨号闭包。

use std::str::FromStr;
use std::sync::Arc;

use xray_app_dispatcher::default::{DefaultDispatcher, DialBridge, PinFuture, SimpleOhm};
use xray_app_dispatcher::DispatchHandler;
use xray_proxy_loopback::{LoopbackError, LoopbackFuture, LoopbackSink};
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::port::Port;
use xray_common::uuid::UUID;
use xray_conf::{BuiltConfig, BuiltOutbound};
use xray_features::Result;
use xray_proxy_trojan::{MemoryAccount, TrojanOutboundConfig};
use xray_proxy_vless::VlessOutboundConfig;
use xray_transport::dialer::StreamSettings;
use xray_transport::link::Link;
// mux outbound：client 数据路径
use xray_mux::client::{
    ClientManager, ClientWorker, DialingWorkerFactory, IncrementalWorkerPicker, UnderlyingSlot,
    WorkerPicker,
};
use xray_mux::session::ClientStrategy;
// 补全协议注册
use xray_proxy_hysteria::HysteriaConfig;
use xray_proxy_freedom::{Config as FreedomConfig, DomainStrategy, Fragment, Noise};
use xray_proxy_wireguard::DeviceConfig;


/// Dispatcher → LoopbackSink 桥接。
///
/// `DefaultDispatcher` 定义在 `xray-app-dispatcher`，`LoopbackSink` trait 在 `xray-proxy-loopback`，
/// 两者有循环依赖不能直接 impl。此 wrapper 在 `xray-core` 层桥接。
#[derive(Debug)]
struct DispatcherLoopbackSink {
    inner: Arc<DefaultDispatcher>,
}

impl LoopbackSink for DispatcherLoopbackSink {
    fn dispatch_loopback(
        &self,
        inbound_tag: String,
        destination: xray_common::net::destination::Destination,
        link: xray_transport::link::Link,
    ) -> LoopbackFuture<std::result::Result<(), LoopbackError>> {
        use xray_app_dispatcher::default::SniffingRequest;
        let sniffing = SniffingRequest::default();
        match self.inner.dispatch_link(&destination, link, &sniffing, None) {
            Ok(()) => Box::pin(async { Ok(()) }),
            Err(e) => Box::pin(async move {
                Err(LoopbackError::DispatchFailed(e.to_string()))
            }),
        }
    }
}

/// 包装 `&SimpleOhm` 为 `Arc<dyn OutboundHandlerManager>`。
///
/// `SimpleOhm` 实现了 `OutboundHandlerManager`，但 `register_outbounds` 接受 `&SimpleOhm` 借用，
/// 不能直接创建 `Arc`。此 wrapper 持有裸指针（生命周期由调用方保证），
/// 实现 `OutboundHandlerManager` trait 以供代理链查找 handler。
///
/// # Safety
///
/// `inner` 指针必须在 `OhmRef` 存活期间有效。`register_outbounds` 中 `ohm` 的生命周期
/// 覆盖 Phase 2 设置 + 后续 dispatch 使用（因为 `SimpleOhm` 内部用 `RwLock`，指针始终有效）。
struct OhmRef {
    inner: *const SimpleOhm,
}

// Safety: SimpleOhm 是 Send + Sync，裸指针在 register_outbounds 生命周期内有效。
unsafe impl Send for OhmRef {}
unsafe impl Sync for OhmRef {}

impl std::fmt::Debug for OhmRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OhmRef").finish_non_exhaustive()
    }
}

impl xray_app_dispatcher::OutboundHandlerManager for OhmRef {
    fn get_handler(&self, tag: &str) -> Option<Arc<dyn DispatchHandler>> {
        // Safety: inner 指针在 OhmRef 存活期间有效
        unsafe { &*self.inner }.get_handler(tag)
    }

    fn get_default_handler(&self) -> Option<Arc<dyn DispatchHandler>> {
        // Safety: inner 指针在 OhmRef 存活期间有效
        unsafe { &*self.inner }.get_default_handler()
    }
}
/// 从 BuiltConfig 注册 outbound handlers 到 SimpleOhm。
///
/// 遍历 `built.outbounds`，按协议名创建 DialBridge 注册到 `ohm`。
/// 第一个 outbound 或 tag 为 `"direct"` 的设为 default（与 Go `SetDefaultHandler` 语义一致）。
/// 不支持的协议或配置解析失败均 warn 跳过（不返回错误，不阻止其他 outbound 注册）。
///
/// ## 代理链（Proxy Chain）
///
/// 对应 Go `senderSettings.ProxySettings.Tag`。如果 outbound 配置了 `proxySettings.tag`，
/// 注册完成后会二次扫描，为 DialBridge 设置 `proxy_chain_tag` + `outbound_manager`，
/// 使其 dispatch 时通过 chained handler 拨号而非直接 dial。
pub fn register_outbounds(built: &BuiltConfig, ohm: &SimpleOhm, loopback_sink: Option<Arc<dyn LoopbackSink>>) -> Result<()> {
    // Phase 1: 注册所有 handler，收集需要代理链的 DialBridge 引用
    let mut chain_bridges: Vec<(Arc<DialBridge>, String)> = Vec::new(); // (bridge, chain_tag)
    let mut mux_bridges: Vec<(Arc<MuxBridge>, Option<String>)> = Vec::new();
    for (i, ob) in built.outbounds.iter().enumerate() {
        match try_build_handler(ob, loopback_sink.clone(), &mut mux_bridges) {
            Ok((handler, bridge_ref, proxy_chain_tag)) => {
                let is_default = i == 0 || ob.tag == "direct";
                if is_default {
                    ohm.set_default(handler.clone());
                }
                ohm.add(&ob.tag, handler);
                if let (Some(bridge), Some(chain_tag)) = (bridge_ref, proxy_chain_tag) {
                    chain_bridges.push((bridge, chain_tag));
                }
                tracing::debug!(
                    tag = %ob.tag,
                    protocol = %ob.entry.kind,
                    default = is_default,
                    "outbound registered"
                );
            }
            Err(BuildError::Unsupported(protocol)) => {
                tracing::warn!(
                    tag = %ob.tag,
                    protocol = %protocol,
                    "outbound protocol not yet supported, skipping"
                );
            }
            Err(BuildError::Parse(e)) => {
                tracing::warn!(
                    tag = %ob.tag,
                    protocol = %ob.entry.kind,
                    error = %e,
                    "failed to parse outbound config, skipping"
                );
            }
        }
    }

    // Phase 2: 设置代理链——为有 proxy_chain_tag 的 DialBridge 注入 outbound_manager
    if !chain_bridges.is_empty() {
        let ohm_arc: Arc<dyn xray_app_dispatcher::OutboundHandlerManager> = Arc::new(OhmRef { inner: ohm });
        for (bridge, chain_tag) in chain_bridges {
            bridge.set_proxy_chain(chain_tag, ohm_arc.clone());
            tracing::debug!(
                tag = %bridge.tag(),
                chain_tag = %bridge.tag(),
                "proxy chain configured"
            );
        }
    }

    for (bridge, via_tag) in mux_bridges {
        use xray_app_dispatcher::OutboundHandlerManager;
        let underlying = match via_tag.as_deref().map(|t| ohm.get_handler(t)) {
            Some(Some(h)) => Some(h),
            Some(None) => {
                tracing::warn!(tag = %bridge.tag(), via = ?via_tag, "mux via tag not found, fallback default");
                ohm.get_default_handler()
            }
            None => ohm.get_default_handler(),
        };
        match underlying {
            Some(h) => {
                bridge.set_underlying(h);
                tracing::debug!(tag = %bridge.tag(), "mux underlying configured");
            }
            None => tracing::warn!(tag = %bridge.tag(), "mux outbound has no underlying handler"),
        }
    }

    Ok(())
}

/// 包装 DialBridge 为 `(handler, Some(dial_bridge_arc), proxy_chain_tag)` 三元组。
///
/// `proxy_chain_tag` 存在时保留 `Arc<DialBridge>` 引用，以便 Phase 2 设置代理链。
fn wrap_bridge(
    tag: String,
    dial_fn: xray_app_dispatcher::default::DialFn,
    proxy_chain_tag: &Option<String>,
) -> std::result::Result<(Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>), BuildError> {
    let bridge = Arc::new(DialBridge::new(tag, dial_fn));
    let handler = Arc::clone(&bridge) as Arc<dyn DispatchHandler>;
    let bridge_ref = if proxy_chain_tag.is_some() { Some(bridge) } else { None };
    Ok((handler, bridge_ref, proxy_chain_tag.clone()))
}

/// 从 `proxy_settings_json` 提取代理链 tag。
///
/// 对应 Go `senderSettings.ProxySettings.Tag`。
/// JSON 格式：`{"tag": "proxy-out", "transportLayerProxy": true/false}`
fn parse_proxy_chain_tag(proxy_settings_json: Option<&serde_json::Value>) -> Option<String> {
    let json = proxy_settings_json?;
    json.get("tag").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(String::from)
}

/// 从 `BuiltOutbound.mux_json` 解析 per-tag UDP443（QUIC over XUDP）策略。
///
/// 对应 Go `NewHandler` 中 `senderSettings.MultiplexSettings` → `Handler.udp443`
/// 的构建链（`app/proxyman/outbound/handler.go:122-168`）：仅 mux enabled 的
/// 出站生成条目，供 `DefaultDispatcher::dispatch_link` 在 UDP/443 分发前检查。
pub(crate) fn parse_udp443_policies(
    outbounds: &[BuiltOutbound],
) -> std::collections::HashMap<String, xray_app_dispatcher::default::Udp443Policy> {
    let mut map = std::collections::HashMap::new();
    for ob in outbounds {
        let Some(mux_json) = ob.mux_json.as_ref() else { continue };
        let Ok(cfg) = serde_json::from_value::<xray_conf::MuxConfig>(mux_json.clone()) else {
            tracing::warn!(tag = %ob.tag, "invalid mux config, ignoring udp443 policy");
            continue;
        };
        if let Some(policy) =
            xray_app_dispatcher::default::Udp443Policy::from_mux(cfg.enabled, &cfg.xudp_proxy_udp_443)
        {
            map.insert(ob.tag.clone(), policy);
        }
    }
    map
}
/// 构建单个 outbound 的 DispatchHandler（DialBridge）。
///
/// 返回 `(handler, dial_bridge_ref, proxy_chain_tag)`。
/// - `handler`: 注册到 Ohm 的 DispatchHandler
/// - `dial_bridge_ref`: 如果是 DialBridge 类型，保留 Arc 引用以便 Phase 2 设置代理链
/// - `proxy_chain_tag`: 对应 Go `senderSettings.ProxySettings.Tag`，存在时表示需要代理链
fn try_build_handler(
    ob: &BuiltOutbound,
    loopback_sink: Option<Arc<dyn LoopbackSink>>,
    mux_bridges: &mut Vec<(Arc<MuxBridge>, Option<String>)>,
) -> std::result::Result<(Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>), BuildError> {
    let proxy_chain_tag = parse_proxy_chain_tag(ob.proxy_settings_json.as_ref());
    match ob.entry.kind.as_str() {
        "freedom" => {
            let config = parse_freedom_config(&ob.entry.data);
            let noises = config.noises.clone();
            let dial_fn = xray_proxy_freedom::make_freedom_dial_fn_with_config(config);
            // TCP 走 DialBridge（fragment 经 DialFn 包装 writer），UDP 走
            // FreedomDispatchBridge（noises 首包前注入）
            let tcp_bridge = Arc::new(DialBridge::new(ob.tag.clone(), dial_fn));
            let handler = Arc::new(
                xray_proxy_freedom::FreedomDispatchBridge::from_bridge(Arc::clone(&tcp_bridge))
                    .with_noises(noises),
            ) as Arc<dyn DispatchHandler>;
            let bridge_ref = if proxy_chain_tag.is_some() { Some(tcp_bridge) } else { None };
            Ok((handler, bridge_ref, proxy_chain_tag))
        }
        "vless" => {
            let config = parse_vless_config(&ob.entry.data)?;
            let config = config.with_stream_settings(parse_stream_settings(&ob.stream_settings_json));
            let dial_fn = xray_proxy_vless::make_vless_dial_fn(Arc::new(config));
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag)
        }
        "trojan" => {
            let config = parse_trojan_config(&ob.entry.data)?;
            let config = config.with_stream_settings(parse_stream_settings(&ob.stream_settings_json));
            let dial_fn = xray_proxy_trojan::make_trojan_dial_fn(Arc::new(config));
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag)
        }
        "blackhole" => {
            let response = parse_blackhole_response(&ob.entry.data);
            let handler = Arc::new(xray_proxy_blackhole::BlackholeHandler::with_response(
                ob.tag.clone(),
                response,
            )) as Arc<dyn DispatchHandler>;
            Ok((handler, None, None))
        }
        "socks" => {
            let (server_addr, auth) = parse_socks_outbound_config(&ob.entry.data)?;
            let client = Arc::new(match auth {
                Some((u, p)) => xray_proxy_socks::SocksClient::new(
                    xray_proxy_socks::ClientConfig::new_with_auth(server_addr, u, p),
                ),
                None => xray_proxy_socks::SocksClient::new(
                    xray_proxy_socks::ClientConfig::new_noauth(server_addr),
                ),
            });
            let dial_fn = xray_proxy_socks::make_socks_dial_fn(client);
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag)
        }
        "mux" => {
            let (concurrency, via_tag) = parse_mux_config(&ob.entry.data)?;
            let (bridge, _slot) = MuxBridge::new(ob.tag.clone(), concurrency);
            let bridge = Arc::new(bridge);
            mux_bridges.push((Arc::clone(&bridge), via_tag));
            let handler = bridge as Arc<dyn DispatchHandler>;
            Ok((handler, None, None))
        }
        "vmess" => {
            let config = xray_proxy_vmess::parse_vmess_config(&ob.entry.data)?;
            let config = config.with_stream_settings(parse_stream_settings(&ob.stream_settings_json));
            let dial_fn = xray_proxy_vmess::make_vmess_dial_fn(Arc::new(config));
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag)
        }
        "shadowsocks" => {
            let config = xray_proxy_ss::parse_ss_config(&ob.entry.data)?;
            let dial_fn = xray_proxy_ss::make_ss_dial_fn(Arc::new(config));
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag)
        }
        "hysteria" => {
            let (server_addr, auth, server_name) = parse_hysteria_config(&ob.entry.data)?;
            let config = HysteriaConfig::new(&server_addr, &auth).with_server_name(&server_name);
            let _ = rustls::crypto::ring::default_provider().install_default();
            let tls_config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
            let transport = xray_transport_hysteria::hysteria_transport::QuinnHysteriaTransport::new(
                tls_config, "0.0.0.0:0".parse().map_err(|e| format!("bind addr: {e}"))?,
            ).map_err(|e| format!("hysteria transport: {e}"))?;
            let dial_fn = xray_proxy_hysteria::make_hysteria_dial_fn(config, Arc::new(transport));
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag)
        }
        "anytls" => {
            let config = parse_anytls_config(&ob.entry.data)?;
            let client = Arc::new(xray_proxy_anytls::AnytlsClient::new(config));
            let dial_fn = xray_proxy_anytls::make_anytls_dial_fn(client);
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag)
        }
        "tuic" => {
            let (server_addr, server_name, uuid, password) = parse_tuic_config(&ob.entry.data)?;
            let rustls_config = build_tuic_rustls_config();
            let dial_fn = xray_proxy_tuic::make_tuic_dial_fn_lazy(
                server_addr, server_name, uuid, password, rustls_config,
            );
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag)
        }
        "wireguard" => {
            let config = parse_wireguard_config(&ob.entry.data)?;
            let dial_fn = xray_proxy_wireguard::make_wireguard_dial_fn(config);
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag)
        }
        "dns" => {
            let (handler, dns) = parse_dns_outbound_config(&ob.entry.data, &ob.tag)?;
            let bridge = DnsDispatchBridge::new(ob.tag.clone(), handler, dns, None);
            Ok((Arc::new(bridge) as Arc<dyn DispatchHandler>, None, None))
        }
        "loopback" => {
            let inbound_tag = parse_loopback_config(&ob.entry.data)?;
            let handler = xray_proxy_loopback::LoopbackHandler::with_inbound_tag(
                ob.tag.clone(), inbound_tag,
            );
            let handler = match loopback_sink {
                Some(sink) => handler.with_sink(sink),
                None => handler,
            };
            Ok((Arc::new(handler) as Arc<dyn DispatchHandler>, None, None))
        }
        "http" => {
            let config = xray_proxy_http::parse_http_config(&ob.entry.data)?;
            let config = config.with_stream_settings(parse_stream_settings(&ob.stream_settings_json));
            let dial_fn = xray_proxy_http::make_http_dial_fn(Arc::new(config));
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag)
        }
        "dokodemo" => {
            let config = parse_dokodemo_config(&ob.entry.data)?;
            let dial_fn = xray_proxy_dokodemo::make_dokodemo_dial_fn(config);
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag)
        }
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
        "tun" => {
            let dial_fn = xray_proxy_tun::make_tun_dial_fn();
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag)
        }
        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
        "tun" => {
            Err(BuildError::Unsupported("TUN outbound is only supported on Linux/Android/FreeBSD".to_string()))
        }
        other => Err(BuildError::Unsupported(other.to_string())),
    }
}

/// Mux outbound handler（mbc/nww）。
///
/// 持有 mux [`ClientManager`]。dispatch 时 pick worker → `ClientWorker::dispatch`
/// 把 link 桥接成 mux session（首帧 New，后续 Keep 帧，carrier 经底层 outbound
/// 拨向 v1.mux.cool:9527）。底层 handler 经 [`UnderlyingSlot`] 延迟注入。
pub struct MuxBridge {
    tag: String,
    client_manager: Arc<ClientManager>,
    slot: UnderlyingSlot,
}

impl MuxBridge {
    /// 构造 Mux outbound handler。`concurrency` 为最大并发会话数（0 = 不限制）。
    #[must_use]
    pub fn new(tag: impl Into<String>, concurrency: u32) -> (Self, UnderlyingSlot) {
        let strategy = ClientStrategy {
            max_concurrency: concurrency,
            max_connection: 0,
        };
        // 空槽构造：register Phase 2 拿到底层 handler 后 set_underlying。
        let slot: UnderlyingSlot = Arc::new(parking_lot::RwLock::new(None));
        let factory = Arc::new(DialingWorkerFactory::with_slot(Arc::clone(&slot), strategy));
        let picker = Box::new(IncrementalWorkerPicker::new(factory));
        let client_manager = Arc::new(ClientManager::new(true, picker));
        (
            Self {
                tag: tag.into(),
                client_manager,
                slot: Arc::clone(&slot),
            },
            slot,
        )
    }

    /// 回填底层 outbound handler（register Phase 2 调用）。
    pub fn set_underlying(&self, handler: Arc<dyn DispatchHandler>) {
        *self.slot.write() = Some(handler);
    }

    /// 是否启用 mux。
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.client_manager.enabled
    }
}

impl std::fmt::Debug for MuxBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxBridge")
            .field("tag", &self.tag)
            .field("enabled", &self.is_enabled())
            .finish()
    }
}
impl DispatchHandler for MuxBridge {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn dispatch(&self, dest: &Destination, link: Link) -> PinFuture<()> {
        let dest = dest.clone();
        let tag = self.tag.clone();
        let client_manager = Arc::clone(&self.client_manager);
        Box::pin(async move {
            // pick worker → ClientWorker::dispatch 把 link 桥成 mux session
            let worker = match client_manager.dispatch() {
                Ok(w) => w,
                Err(e) => {
                    tracing::warn!(tag = %tag, error = %e, "mux dispatch: no worker available");
                    drop(link);
                    return;
                }
            };
            let inner = xray_mux::client::Link { reader: link.reader, writer: link.writer };
            if !worker.dispatch(&dest, inner).await {
                tracing::warn!(tag = %tag, "mux dispatch: worker full, dropping link");
            }
        })
    }
}

/// JSON 格式：`{"concurrency": 8, "via": "proxy-out"}`（concurrency 缺省 8）。
fn parse_mux_config(data: &[u8]) -> std::result::Result<(u32, Option<String>), String> {
    let v: serde_json::Value = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    let concurrency = v.get("concurrency").and_then(|x| x.as_u64()).unwrap_or(8) as u32;
    let via = v
        .get("via")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);
    Ok((concurrency, via))
}
/// 解析 vless outbound settings JSON → VlessOutboundConfig。
///
/// JSON 格式：`{ "vnext": [{ "address": "...", "port": 443, "users": [{ "id": "uuid" }] }] }`
fn parse_vless_config(data: &[u8]) -> std::result::Result<VlessOutboundConfig, String> {
    let v: serde_json::Value = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    let vnext = v
        .get("vnext")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing vnext array".to_string())?;
    // Go infra/conf/vless.go：vnext/users 必须恰好 1 个，多端点应配多个 outbound + balancer。
    if vnext.len() != 1 {
        return Err(r#"vless "vnext" should have one and only one member. Multiple endpoints should use multiple VLESS outbounds and routing balancer instead"#.into());
    }
    let first = vnext
        .first()
        .ok_or_else(|| "vnext array is empty".to_string())?;
    let address = first
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing vnext[0].address".to_string())?;
    let port = first
        .get("port")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing vnext[0].port".to_string())?;
    let users = first
        .get("users")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing vnext[0].users".to_string())?;
    if users.len() != 1 {
        return Err(r#"vless "users" should have one and only one member. Multiple members should use multiple VLESS outbounds and routing balancer instead"#.into());
    }
    let user = users.first().unwrap();
    let user_id = user
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing vnext[0].users[0].id".to_string())?;
    let uuid = UUID::from_str(user_id)?;
    // 可选 user 字段：flow / encryption / level / email（对应 Go infra/conf outbound user）。
    let flow = user.get("flow").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let encryption = user
        .get("encryption")
        .and_then(|v| v.as_str())
        .unwrap_or("none")
        .to_string();
    let level = user.get("level").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let email = user.get("email").and_then(|v| v.as_str()).unwrap_or("").to_string();
    Ok(VlessOutboundConfig::new(
        uuid,
        Address::Domain(address.to_string()),
        Port::new(u16::try_from(port).map_err(|_| "port out of range")?),
    )
    .with_flow(flow)
    .with_encryption(encryption)
    .with_level(level)
    .with_email(email))
}

/// 解析 trojan outbound settings JSON → TrojanOutboundConfig。
///
/// JSON 格式：`{ "servers": [{ "address": "...", "port": 443, "password": "..." }] }`
fn parse_trojan_config(data: &[u8]) -> std::result::Result<TrojanOutboundConfig, String> {
    let v: serde_json::Value = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    let servers = v
        .get("servers")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing servers array".to_string())?;
    let first = servers
        .first()
        .ok_or_else(|| "servers array is empty".to_string())?;
    let address = first
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing servers[0].address".to_string())?;
    let port = first
        .get("port")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing servers[0].port".to_string())?;
    let password = first
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing servers[0].password".to_string())?;
    // 可选字段：level / email（对应 Go infra/conf outbound server）。
    let level = first.get("level").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let email = first.get("email").and_then(|v| v.as_str()).unwrap_or("").to_string();
    Ok(TrojanOutboundConfig::new(
        MemoryAccount::new(password),
        Address::Domain(address.to_string()),
        Port::new(u16::try_from(port).map_err(|_| "port out of range")?),
    )
    .with_level(level)
    .with_email(email))
}

/// 解析 freedom outbound settings JSON → FreedomConfig。
///
/// 对应 Go `proxy/freedom/freedom.go` Config 字段。JSON 格式：
/// `{ "domainStrategy": "AsIs", "fragment": {...}, "noises": [...] }`
///
/// 解析失败或缺省返回 `Config::default()`（不阻断 freedom 注册）。
fn parse_freedom_config(data: &[u8]) -> FreedomConfig {
    use xray_proxy_freedom::{DomainStrategy, Fragment, Noise};
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) else {
        return FreedomConfig::default();
    };
    let domain_strategy = v
        .get("domainStrategy")
        .and_then(|s| s.as_str())
        .map(parse_freedom_domain_strategy)
        .unwrap_or_default();
    let fragment = v.get("fragment").and_then(parse_freedom_fragment);
    let noises = v
        .get("noises")
        .and_then(|n| n.as_array())
        .map(|arr| arr.iter().filter_map(parse_freedom_noise).collect())
        .unwrap_or_default();
    FreedomConfig {
        domain_strategy: domain_strategy as i32,
        fragment,
        noises,
        ..Default::default()
    }
}

/// 把 domainStrategy 字符串映射为枚举值。
fn parse_freedom_domain_strategy(s: &str) -> DomainStrategy {
    match s {
        "UseIP" => DomainStrategy::UseIP,
        "UseIPv4" => DomainStrategy::UseIPv4,
        "UseIPv6" => DomainStrategy::UseIPv6,
        "UseIPv4v6" => DomainStrategy::UseIPv4v6,
        "UseIPv6v4" => DomainStrategy::UseIPv6v4,
        _ => DomainStrategy::AsIs,
    }
}

/// 解析 fragment 子对象。
fn parse_freedom_fragment(v: &serde_json::Value) -> Option<Fragment> {
    let g = |k: &str| v.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
    Some(Fragment {
        packets_from: g("packets"),
        packets_to: g("packets"),
        length_min: g("lengthMin"),
        length_max: g("lengthMax"),
        interval_min: g("intervalMin"),
        interval_max: g("intervalMax"),
        max_split_min: g("maxSplitMin"),
        max_split_max: g("maxSplitMax"),
    })
}

/// 解析单个 noise 子对象。
fn parse_freedom_noise(v: &serde_json::Value) -> Option<Noise> {
    let g = |k: &str| v.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
    Some(Noise {
        length_min: g("lengthMin"),
        length_max: g("lengthMax"),
        delay_min: g("delayMin"),
        delay_max: g("delayMax"),
        packet: match v.get("packet").and_then(|x| x.as_str()) {
            Some("rand") | None => Vec::new(),
            Some(s) => s.as_bytes().to_vec(),
        },
        apply_to: String::new(),
    })
}

/// 解析 blackhole outbound settings JSON → ResponseConfig。
///
/// JSON 格式（Go `proxy/blackhole/config.go`）：
/// - `{}` 或无 `response` → None
/// - `{ "response": { "type": "none" } }` → None
/// - `{ "response": { "type": "http" } }` → Http403
fn parse_blackhole_response(data: &[u8]) -> xray_proxy_blackhole::ResponseConfig {
    use xray_proxy_blackhole::ResponseConfig;
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) else {
        return ResponseConfig::None;
    };
    let Some(resp) = v.get("response") else {
        return ResponseConfig::None;
    };
    match resp.get("type").and_then(|t| t.as_str()) {
        Some("http") => ResponseConfig::Http403,
        _ => ResponseConfig::None,
    }
}

/// 解析 socks outbound settings JSON → (server_addr, optional (user, pass)).
///
/// JSON 格式（Go `proxy/socks/config.go`）：
/// `{ "servers": [{ "address": "...", "port": 1080, "users": [{ "user": "u", "pass": "p" }] }] }`
fn parse_socks_outbound_config(
    data: &[u8],
) -> std::result::Result<(String, Option<(String, String)>), String> {
    let v: serde_json::Value = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    let servers = v
        .get("servers")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing servers array".to_string())?;
    let first = servers
        .first()
        .ok_or_else(|| "servers array is empty".to_string())?;
    let address = first
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing servers[0].address".to_string())?;
    let port = first
        .get("port")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing servers[0].port".to_string())?;
    let server_addr = format!("{address}:{}", u16::try_from(port).map_err(|_| "port out of range")?);
    // users[0] 可选
    let auth = first
        .get("users")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|u| {
            let user = u.get("user")?.as_str()?.to_string();
            let pass = u.get("pass")?.as_str()?.to_string();
            Some((user, pass))
        });
    Ok((server_addr, auth))
}

/// 从 outbound 的 stream_settings_json 构造 StreamSettings。
///
/// None 或非 object 返回 None（走 raw TCP）。
fn parse_stream_settings(json: &Option<serde_json::Value>) -> Option<StreamSettings> {
    let s = StreamSettings::from_json(json.as_ref());
    // TCP + 无 security 等于没 streamSettings，返回 None 保持 raw TCP 路径。
    if s.protocol == "tcp" && !s.is_tls() {
        None
    } else {
        Some(s)
    }
}

// ========== StubDispatchBridge：协议 stub 注册 ==========

/// 通用 stub outbound handler：dispatch 仅 log + drop link。
/// 用于尚未完整实现拨号链路的协议。注册到 SimpleOhm 后，配置中引用该 tag 不会报错，
/// 但流量会被丢弃。
pub struct StubDispatchBridge {
    tag: String,
    protocol: String,
}

impl StubDispatchBridge {
    /// 创建 stub outbound handler。
    fn new(tag: impl Into<String>, protocol: &str) -> Self {
        Self { tag: tag.into(), protocol: protocol.to_string() }
    }
}

impl std::fmt::Debug for StubDispatchBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StubDispatchBridge")
            .field("tag", &self.tag)
            .field("protocol", &self.protocol)
            .finish()
    }
}

impl DispatchHandler for StubDispatchBridge {
    fn tag(&self) -> &str { &self.tag }

    fn dispatch(&self, dest: &Destination, link: Link) -> PinFuture<()> {
        let tag = self.tag.clone();
        let protocol = self.protocol.clone();
        let dest = dest.clone();
        Box::pin(async move {
            tracing::warn!(
                tag = %tag,
                protocol = %protocol,
                dest = ?dest,
                "outbound dispatch: dial chain not yet connected, dropping link"
            );
            drop(link);
        })
    }
}

// ========== DnsDispatchBridge：DNS 查询拦截 + 规则匹配 + 转发 ==========

/// DNS outbound handler：拦截 dispatcher 转发的 DNS 查询 → 规则匹配 → 转发/丢弃/返回/劫持。
///
/// 对应 Go `proxy/dns/dns.go::Handler.Process`。
/// DNS 不走标准 DialBridge（无 dial 语义），而是直接实现 DispatchHandler。
struct DnsDispatchBridge {
    tag: String,
    /// 规则匹配 Handler（qType + domain → action）。
    handler: xray_proxy_dns::Handler,
    /// hickory-resolver 转发（Direct 动作）。
    dns: Arc<xray_proxy_dns::DnsOutbound>,
    /// xray-app-dns 服务（Hijack 动作调用 lookup_ip）。None 时 Hijack 退化为 Direct。
    dns_service: Option<Arc<xray_app_dns::server::DnsService>>,
}

impl DnsDispatchBridge {
    fn new(
        tag: impl Into<String>,
        handler: xray_proxy_dns::Handler,
        dns: xray_proxy_dns::DnsOutbound,
        dns_service: Option<Arc<xray_app_dns::server::DnsService>>,
    ) -> Self {
        Self { tag: tag.into(), handler, dns: Arc::new(dns), dns_service }
    }
}
impl std::fmt::Debug for DnsDispatchBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsDispatchBridge")
            .field("tag", &self.tag)
            .finish()
    }
}

impl DispatchHandler for DnsDispatchBridge {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn dispatch(&self, _dest: &Destination, link: Link) -> PinFuture<()> {
        let tag = self.tag.clone();
        let handler = self.handler.clone();
        let dns = Arc::clone(&self.dns);
        let dns_service = self.dns_service.clone();
        Box::pin(async move {
            // 从 link.reader 读取 DNS 查询字节
            let mut reader = link.reader;
            let mut query_buf = Vec::new();
            loop {
                match reader.read_multi_buffer().await {
                    Ok(mb) => {
                        if mb.is_empty() { break; }
                        for buf in mb.iter() {
                            query_buf.extend_from_slice(buf.bytes());
                        }
                    }
                    Err(e) => {
                        tracing::debug!(tag = %tag, "dns dispatch read end: {e}");
                        break;
                    }
                }
            }
            if query_buf.is_empty() {
                tracing::debug!(tag = %tag, "dns dispatch: empty query");
                return;
            }

            // 规则匹配
            let outcome = match handler.process(&query_buf).await {
                Ok(o) => o,
                Err(e) => {
                    tracing::warn!(tag = %tag, "dns handler process: {e}");
                    return;
                }
            };

            let response = match outcome {
                xray_proxy_dns::ProcessOutcome::Drop => {
                    tracing::debug!(tag = %tag, "dns dispatch: dropped by rule");
                    return;
                }
                xray_proxy_dns::ProcessOutcome::Respond { response } => Some(response),
                xray_proxy_dns::ProcessOutcome::Forward { query } => {
                    // Direct：转发到上游 DNS
                    match dns.process(&query).await {
                        Ok(resp) => Some(resp),
                        Err(e) => {
                            tracing::warn!(tag = %tag, "dns forward: {e}");
                            None
                        }
                    }
                }
                xray_proxy_dns::ProcessOutcome::Hijack { query } => {
                    // Hijack：调用 DnsService::lookup_ip() 解析，构造 DNS 响应
                    match handle_hijack(&query, dns_service.as_ref()).await {
                        Ok(resp) => Some(resp),
                        Err(e) => {
                            tracing::warn!(tag = %tag, "dns hijack: {e}, falling back to forward");
                            // Hijack 失败退化为 Direct 转发
                            match dns.process(&query).await {
                                Ok(resp) => Some(resp),
                                Err(e2) => {
                                    tracing::warn!(tag = %tag, "dns hijack fallback forward: {e2}");
                                    None
                                }
                            }
                        }
                    }
                }
            };

            // 写回响应
            if let Some(response) = response {
                let mut writer = link.writer;
                let resp_buf = xray_buf::buffer::Buffer::from_vec(response);
                let resp_mb = xray_buf::multi::MultiBuffer::from_buffer(resp_buf);
                if let Err(e) = writer.write_multi_buffer(resp_mb).await {
                    tracing::warn!(tag = %tag, "dns dispatch write response: {e}");
                }
                writer.shutdown();
            }
        })
    }
}

/// Hijack 动作：解析 DNS 查询 → 调用 DnsService::lookup_ip() → 构造 DNS 响应。
///
/// 对应 Go `proxy/dns/dns.go::Handler.handleIPQuery`。
async fn handle_hijack(
    query: &[u8],
    dns_service: Option<&Arc<xray_app_dns::server::DnsService>>,
) -> std::result::Result<Vec<u8>, String> {
    let Some(svc) = dns_service else {
        return Err("no DnsService available for Hijack".into());
    };

    // 解析 DNS 查询获取 id/qType/domain
    let (header, question) = xray_proxy_dns::parse_dns_query(query)
        .map_err(|e| format!("parse query: {e}"))?;

    // 只有 A(1) 和 AAAA(28) 走 lookup_ip，其他类型返回 REFUSED
    let (ips, ttl) = match question.q_type {
        1 => {
            // A 记录：IPv4 only
            let option = xray_app_dns::config::IpOption {
                ipv4_enable: true,
                ipv6_enable: false,
                fake_enable: true,
            };
            svc.lookup_ip(&question.name, option).await
                .map_err(|e| format!("lookup_ip v4: {e}"))?
        }
        28 => {
            // AAAA 记录：IPv6 only
            let option = xray_app_dns::config::IpOption {
                ipv4_enable: false,
                ipv6_enable: true,
                fake_enable: true,
            };
            svc.lookup_ip(&question.name, option).await
                .map_err(|e| format!("lookup_ip v6: {e}"))?
        }
        _ => {
            // 非 IP 查询类型：返回 REFUSED
            let resp = xray_proxy_dns::build_dns_response(&header, &question, 5);
            return Ok(resp);
        }
    };

    // 用手写 DNS 构造器生成带 A/AAAA 记录的响应
    Ok(xray_proxy_dns::build_ip_response(&header, &question, &ips, ttl))
}

// ========== DNS Outbound 配置解析 ==========

/// 从 outbound entry.data（JSON）解析 dns outbound 配置。
///
/// JSON 格式：`{"servers":["8.8.8.8:53"], "rule":[...]}` 或空对象。
/// 返回 (Handler, DnsOutbound)。
fn parse_dns_outbound_config(
    data: &[u8],
    tag: &str,
) -> std::result::Result<(xray_proxy_dns::Handler, xray_proxy_dns::DnsOutbound), String> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| format!("dns outbound settings JSON: {e}"))?;
    let config = xray_proxy_dns::Config::default();
    let handler = xray_proxy_dns::Handler::init(&config);
    // 解析上游 DNS 服务器列表
    let servers: Vec<(std::net::IpAddr, u16)> = v.get("servers")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter().filter_map(|s| {
                s.as_str().and_then(|addr| {
                    let (ip, port) = addr.rsplit_once(':')?;
                    let ip: std::net::IpAddr = ip.parse().ok()?;
                    let port: u16 = port.parse().ok()?;
                    Some((ip, port))
                })
            }).collect()
        })
        .unwrap_or_default();
    let dns = if servers.is_empty() {
        xray_proxy_dns::DnsOutbound::new_system(tag)
            .map_err(|e| format!("dns outbound init: {e}"))?
    } else {
        xray_proxy_dns::DnsOutbound::new_with_servers(tag, &servers)
            .map_err(|e| format!("dns outbound init: {e}"))?
    };
    Ok((handler, dns))
}


// ========== AnyTLS 配置解析 ==========

/// 解析 anytls outbound settings JSON → ClientConfig。
///
/// JSON 格式：`{ "server": "...", "server_port": 443, "sni": "...", "insecure": false }`
fn parse_anytls_config(data: &[u8]) -> std::result::Result<xray_proxy_anytls::ClientConfig, String> {
    let v: serde_json::Value = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    let address = v
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing server".to_string())?;
    let port = v
        .get("server_port")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing server_port".to_string())?;
    let port = u16::try_from(port).map_err(|_| "port out of range")?;
    let sni = v
        .get("sni")
        .and_then(|v| v.as_str())
        .unwrap_or(address);
    let insecure = v
        .get("insecure")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    // 构造 rustls ClientConfig
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls_config = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
        };
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };
    Ok(xray_proxy_anytls::ClientConfig::new(
        &format!("{address}:{port}"),
        sni,
        Arc::new(tls_config),
    ))
}

/// 跳过证书验证（insecure=true 场景）。
struct NoVerifier;

impl std::fmt::Debug for NoVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoVerifier").finish()
    }
}

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// 解析 hysteria outbound settings JSON → (server_addr, auth, server_name)。
///
/// JSON 格式：`{"servers":[{"address":"...","port":443,"auth":"..."}]}`。
fn parse_hysteria_config(data: &[u8]) -> std::result::Result<(String, String, String), String> {
    let v: serde_json::Value = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    let servers = v.get("servers").and_then(|v| v.as_array())
        .ok_or_else(|| "missing servers array".to_string())?;
    let first = servers.first().ok_or_else(|| "servers array is empty".to_string())?;
    let address = first.get("address").and_then(|v| v.as_str())
        .ok_or_else(|| "missing servers[0].address".to_string())?;
    let port = first.get("port").and_then(|v| v.as_u64())
        .ok_or_else(|| "missing servers[0].port".to_string())?;
    let auth = first.get("auth").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let server_addr = format!("{address}:{port}");
    let server_name = first.get("server_name").and_then(|v| v.as_str())
        .unwrap_or(address).to_string();
    Ok((server_addr, auth, server_name))
}

/// 解析 tuic outbound settings JSON → (server_addr, server_name, uuid, password)。
///
/// JSON 格式：`{"servers":[{"address":"...","port":443,"uuid":"...","password":"..."}]}`。
fn parse_tuic_config(data: &[u8]) -> std::result::Result<(std::net::SocketAddr, String, uuid::Uuid, String), String> {
    let v: serde_json::Value = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    let servers = v.get("servers").and_then(|v| v.as_array())
        .ok_or_else(|| "missing servers array".to_string())?;
    let first = servers.first().ok_or_else(|| "servers array is empty".to_string())?;
    let address = first.get("address").and_then(|v| v.as_str())
        .ok_or_else(|| "missing servers[0].address".to_string())?;
    let port = first.get("port").and_then(|v| v.as_u64())
        .ok_or_else(|| "missing servers[0].port".to_string())?;
    let uuid_str = first.get("uuid").and_then(|v| v.as_str())
        .ok_or_else(|| "missing servers[0].uuid".to_string())?;
    let password = first.get("password").and_then(|v| v.as_str())
        .ok_or_else(|| "missing servers[0].password".to_string())?;
    let server_name = first.get("server_name").and_then(|v| v.as_str())
        .unwrap_or(address).to_string();
    let server_addr: std::net::SocketAddr = format!("{address}:{port}").parse()
        .map_err(|e| format!("invalid tuic server addr: {e}"))?;
    let uuid = uuid::Uuid::parse_str(uuid_str)
        .map_err(|e| format!("invalid tuic uuid: {e}"))?;
    Ok((server_addr, server_name, uuid, password.to_string()))
}

/// 构造 TUIC 用的 rustls ClientConfig（默认配置 + ring provider）。
fn build_tuic_rustls_config() -> Arc<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    // TUIC v5 要求 ALPN
    config.alpn_protocols = vec![b"h3".to_vec(), b"tuic".to_vec()];
    Arc::new(config)
}


/// 解析 wireguard outbound settings JSON → DeviceConfig。
///
/// JSON 格式：`{"secretKey":"...","peers":[{"publicKey":"...","endpoint":"..."}]}`。
fn parse_wireguard_config(data: &[u8]) -> std::result::Result<DeviceConfig, String> {
    let v: serde_json::Value = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    let secret_key = v.get("secretKey").and_then(|x| x.as_str())
        .ok_or_else(|| "missing secretKey".to_string())?;
    let mut peers = Vec::new();
    if let Some(arr) = v.get("peers").and_then(|x| x.as_array()) {
        for p in arr {
            let public_key = p.get("publicKey").and_then(|x| x.as_str())
                .ok_or_else(|| "missing peer publicKey".to_string())?;
            let endpoint = p.get("endpoint").and_then(|x| x.as_str())
                .ok_or_else(|| "missing peer endpoint".to_string())?;
            peers.push(xray_proxy_wireguard::PeerConfig {
                public_key: public_key.to_string(),
                endpoint: endpoint.to_string(),
                ..Default::default()
            });
        }
    }
    let endpoint = v.get("address").and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_else(|| vec!["10.0.0.2/32".to_string()]);
    Ok(DeviceConfig {
        secret_key: secret_key.to_string(),
        peers,
        endpoint,
        ..Default::default()
    })
}

/// 解析 loopback outbound settings JSON → inbound_tag。
///
/// JSON 格式：`{ "inboundTag": "..." }`
fn parse_loopback_config(data: &[u8]) -> std::result::Result<String, String> {
    let v: serde_json::Value = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    v.get("inboundTag")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "missing inboundTag".to_string())
}

/// 解析 dokodemo outbound settings JSON → DokodemoOutboundConfig。
///
/// JSON 格式：`{ "address": "1.2.3.4", "port": 443 }`。
/// address 支持域名和 IP；port 必须 0-65535。
fn parse_dokodemo_config(data: &[u8]) -> std::result::Result<xray_proxy_dokodemo::DokodemoOutboundConfig, String> {
    let v: serde_json::Value = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    let address_str = v
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing address".to_string())?;
    let port = v
        .get("port")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing port".to_string())?;
    let port = u16::try_from(port).map_err(|_| "port out of range")?;
    let address = if let Ok(ip) = address_str.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => Address::IPv4(v4),
            std::net::IpAddr::V6(v6) => Address::IPv6(v6),
        }
    } else {
        Address::Domain(address_str.to_string())
    };
    Ok(xray_proxy_dokodemo::DokodemoOutboundConfig::new(
        address,
        Port::new(port),
        xray_common::net::network::Network::TCP,
    ))
}

#[derive(Debug)]
enum BuildError {
    Unsupported(String),
    Parse(String),
}

impl From<String> for BuildError {
    fn from(s: String) -> Self {
        Self::Parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_app_dispatcher::default::SimpleOhm;
    use xray_app_dispatcher::OutboundHandlerManager;
    use xray_conf::{BuiltConfig, BuiltEntry, BuiltOutbound};

    fn make_outbound(kind: &str, tag: &str, data: &str) -> BuiltOutbound {
        BuiltOutbound {
            entry: BuiltEntry {
                kind: kind.to_string(),
                data: data.as_bytes().to_vec(),
            },
            tag: tag.to_string(),
            send_through: None,
            stream_settings_json: None,
            proxy_settings_json: None,
            mux_json: None,
        }
    }

    fn mux_outbound(tag: &str, mux_json: serde_json::Value) -> BuiltOutbound {
        BuiltOutbound {
            mux_json: Some(mux_json),
            ..make_outbound("freedom", tag, "{}")
        }
    }

    #[test]
    fn parse_udp443_policies_from_mux_json() {
        use xray_app_dispatcher::default::Udp443Policy;
        use serde_json::json;

        let outbounds = vec![
            // mux enabled 无字段 → 空串规范化为 Reject（Go MuxConfig.Build）
            mux_outbound("m1", json!({"enabled": true})),
            // 显式 skip
            mux_outbound("m2", json!({"enabled": true, "xudpProxyUDP443": "skip"})),
            // allow
            mux_outbound("m3", json!({"enabled": true, "xudpProxyUDP443": "allow"})),
            // mux disabled → 无策略（Go NewHandler enabled 门控）
            mux_outbound("m4", json!({"enabled": false, "xudpProxyUDP443": "reject"})),
            // 无 mux 配置
            make_outbound("freedom", "m5", "{}"),
            // 非法值 → 无策略（降级告警）
            mux_outbound("m6", json!({"enabled": true, "xudpProxyUDP443": "bogus"})),
        ];

        let map = parse_udp443_policies(&outbounds);
        assert_eq!(map.get("m1"), Some(&Udp443Policy::Reject));
        assert_eq!(map.get("m2"), Some(&Udp443Policy::Skip));
        assert_eq!(map.get("m3"), Some(&Udp443Policy::Allow));
        assert!(!map.contains_key("m4"));
        assert!(!map.contains_key("m5"));
        assert!(!map.contains_key("m6"));
    }

    #[test]
    fn register_freedom_sets_default_and_tagged() {
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("freedom", "direct", "{}"));

        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None).unwrap();

        assert!(ohm.get_default_handler().is_some(), "freedom should be default");
        assert!(ohm.get_handler("direct").is_some(), "freedom should be tagged");
    }

    #[test]
    fn register_multiple_outbounds_first_is_default() {
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("freedom", "proxy", "{}"));
        built.outbounds.push(make_outbound("freedom", "direct", "{}"));

        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None).unwrap();

        // 第一个设为 default，"direct" 也设为 default（覆盖）
        assert!(ohm.get_default_handler().is_some());
        assert!(ohm.get_handler("proxy").is_some());
        assert!(ohm.get_handler("direct").is_some());
    }

    #[test]
    fn register_vless_parses_vnext() {
        let settings = r#"{
            "vnext": [{
                "address": "example.com",
                "port": 443,
                "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811" }]
            }]
        }"#;
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("vless", "vless-out", settings));

        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None).unwrap();

        assert!(ohm.get_handler("vless-out").is_some(), "vless should be registered");
    }

    /// Go infra/conf/vless.go：vnext/users 恰好 1 个，多个直接拒绝（应配多 outbound + balancer）。
    #[test]
    fn register_vless_rejects_multiple_vnext() {
        let settings = r#"{
            "vnext": [
                { "address": "a.example.com", "port": 443, "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811" }] },
                { "address": "b.example.com", "port": 443, "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811" }] }
            ]
        }"#;
        assert!(parse_vless_config(settings.as_bytes()).is_err(),
            "multiple vnext entries should be rejected like Go");
    }

    #[test]
    fn register_vless_rejects_multiple_users() {
        let settings = r#"{
            "vnext": [{
                "address": "example.com",
                "port": 443,
                "users": [
                    { "id": "b831381d-6324-4d53-ad4f-8cda48b30811" },
                    { "id": "66ad4540-b58c-4ad2-9926-ea63445a9b57" }
                ]
            }]
        }"#;
        assert!(parse_vless_config(settings.as_bytes()).is_err(),
            "multiple users should be rejected like Go");
    }

    #[test]
    fn register_trojan_parses_servers() {
        let settings = r#"{
            "servers": [{
                "address": "example.com",
                "port": 443,
                "password": "mypassword"
            }]
        }"#;
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("trojan", "trojan-out", settings));

        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None).unwrap();

        assert!(ohm.get_handler("trojan-out").is_some(), "trojan should be registered");
    }

    #[test]
    fn register_dokodemo_parses_config() {
        let settings = r#"{ "address": "192.168.1.1", "port": 8080 }"#;
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("dokodemo", "dokodemo-out", settings));

        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None).unwrap();

        assert!(ohm.get_handler("dokodemo-out").is_some(), "dokodemo should be registered");
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
    #[test]
    fn register_tun_outbound() {
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("tun", "tun-out", "{}"));

        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None).unwrap();

        assert!(ohm.get_handler("tun-out").is_some(), "tun should be registered");
    }

    #[test]
    fn register_vless_invalid_uuid_skipped() {
        let settings = r#"{
            "vnext": [{
                "address": "example.com",
                "port": 443,
                "users": [{ "id": "this-id-is-longer-than-thirty-bytes!!" }]
            }]
        }"#;
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("vless", "bad-vless", settings));

        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None).unwrap();

        assert!(
            ohm.get_handler("bad-vless").is_none(),
            "invalid uuid should skip"
        );
    }

    #[test]
    fn register_empty_outbounds_noop() {
        let built = BuiltConfig::default();
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None).unwrap();
        assert!(ohm.get_default_handler().is_none());
    }

    #[test]
    fn parse_vless_config_extracts_fields() {
        let data = r#"{
            "vnext": [{
                "address": "server.example.com",
                "port": 8443,
                "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811" }]
            }]
        }"#;
        let config = parse_vless_config(data.as_bytes()).unwrap();
        assert_eq!(config.server_port.value(), 8443);
        match &config.server_address {
            Address::Domain(d) => assert_eq!(d, "server.example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
    }

    #[test]
    fn parse_trojan_config_extracts_fields() {
        let data = r#"{
            "servers": [{
                "address": "trojan.example.com",
                "port": 443,
                "password": "secret"
            }]
        }"#;
        let config = parse_trojan_config(data.as_bytes()).unwrap();
        assert_eq!(config.server_port.value(), 443);
        assert_eq!(config.account.password, "secret");
        match &config.server_address {
            Address::Domain(d) => assert_eq!(d, "trojan.example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
    }

    #[test]
    fn parse_stream_settings_none_returns_none() {
        assert!(parse_stream_settings(&None).is_none());
        assert!(parse_stream_settings(&Some(serde_json::Value::Null)).is_none());
    }

    #[test]
    fn parse_stream_settings_tcp_no_security_returns_none() {
        let v: serde_json::Value = serde_json::from_str(r#"{"network":"tcp"}"#).unwrap();
        assert!(parse_stream_settings(&Some(v)).is_none());
    }

    #[test]
    fn parse_stream_settings_ws_tls_returns_some() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"network":"ws","security":"tls","wsSettings":{"path":"/ray"}}"#
        ).unwrap();
        let s = parse_stream_settings(&Some(v)).unwrap();
        assert_eq!(s.protocol, "ws");
        assert!(s.is_tls());
    }

    #[test]
    fn register_blackhole_parses_response() {
        // 默认 response（空 settings）→ None
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("blackhole", "bh", "{}"));
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None).unwrap();
        assert!(ohm.get_handler("bh").is_some(), "blackhole should register");
    }

    #[test]
    fn register_blackhole_http_response_type() {
        // ponytail: blackhole response.type=http 注册不报错即可（dispatch 行为已在 blackhole crate 测过）
        let settings = r#"{"response":{"type":"http"}}"#;
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("blackhole", "bh-http", settings));
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None).unwrap();
        assert!(ohm.get_handler("bh-http").is_some());
    }

    #[test]
    fn register_socks_outbound_parses_noauth() {
        let settings = r#"{"servers":[{"address":"1.2.3.4","port":1080}]}"#;
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("socks", "socks-out", settings));
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None).unwrap();
        assert!(ohm.get_handler("socks-out").is_some(), "socks outbound should register");
    }

    #[test]
    fn register_socks_outbound_parses_auth() {
        let settings = r#"{"servers":[{"address":"1.2.3.4","port":1080,"users":[{"user":"u","pass":"p"}]}]}"#;
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("socks", "socks-auth", settings));
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None).unwrap();
        assert!(ohm.get_handler("socks-auth").is_some());
    }

    #[test]
    fn register_mux_outbound_parses_concurrency() {
        let settings = r#"{"concurrency":16}"#;
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("mux", "mux-out", settings));
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None).unwrap();
        assert!(ohm.get_handler("mux-out").is_some(), "mux outbound should register");
    }

    #[test]
    fn register_mux_outbound_default_concurrency() {
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("mux", "mux-default", "{}"));
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None).unwrap();
        assert!(ohm.get_handler("mux-default").is_some());
    }

    #[test]
    fn parse_mux_config_extracts_concurrency() {
        assert_eq!(super::parse_mux_config(br#"{"concurrency":32}"#).unwrap(), (32, None));
        assert_eq!(
            super::parse_mux_config(br#"{"concurrency":16,"via":"proxy-out"}"#).unwrap(),
            (16, Some("proxy-out".to_string()))
        );
    }

    #[test]
    fn parse_mux_config_defaults_to_8() {
        assert_eq!(super::parse_mux_config(b"{}").unwrap(), (8, None));
    }

    #[test]
    fn register_socks_missing_servers_skipped() {
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("socks", "bad-socks", "{}"));
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None).unwrap();
        assert!(ohm.get_handler("bad-socks").is_none());
    }

    #[test]
    fn parse_proxy_chain_tag_extracts_tag() {
        let json: serde_json::Value = serde_json::json!({ "tag": "proxy-out", "transportLayerProxy": true });
        assert_eq!(parse_proxy_chain_tag(Some(&json)), Some("proxy-out".to_string()));
    }

    #[test]
    fn parse_proxy_chain_tag_empty_string_returns_none() {
        let json: serde_json::Value = serde_json::json!({ "tag": "", "transportLayerProxy": false });
        assert_eq!(parse_proxy_chain_tag(Some(&json)), None);
    }

    #[test]
    fn parse_proxy_chain_tag_missing_tag_returns_none() {
        let json: serde_json::Value = serde_json::json!({ "transportLayerProxy": true });
        assert_eq!(parse_proxy_chain_tag(Some(&json)), None);
    }

    #[test]
    fn parse_proxy_chain_tag_none_input_returns_none() {
        assert_eq!(parse_proxy_chain_tag(None), None);
    }

    #[test]
    fn register_outbound_with_proxy_chain_tag() {
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("freedom", "proxy-out", "{}"));
        let mut ob = make_outbound("freedom", "chain-out", "{}");
        ob.proxy_settings_json = Some(serde_json::json!({ "tag": "proxy-out" }));
        built.outbounds.push(ob);

        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None).unwrap();

        assert!(ohm.get_handler("proxy-out").is_some(), "proxy-out should be registered");
        assert!(ohm.get_handler("chain-out").is_some(), "chain-out should be registered");
    }
}

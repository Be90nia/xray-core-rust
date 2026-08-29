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
use xray_app_dispatcher::OutboundHandlerManager;
use xray_proxy_loopback::{LoopbackError, LoopbackFuture, LoopbackSink};
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::port::Port;
use xray_common::uuid::UUID;
use xray_proto::xray::core::OutboundHandlerConfig as OutboundHandlerConfigProto;
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
        match self.inner.dispatch_link(&destination, link, &sniffing, None, None) {
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
///
/// ## targetStrategy（bd bqm）
///
/// `dns` 提供域名解析服务（对应 Go 全局 `internet.dnsClient`，由 `app/dns`
/// 初始化后 `internet.InitDNSCache` 注入）。配置了 `targetStrategy`（非 AsIs）
/// 的出站在拨号前经 [`wrap_dial_with_target_strategy`] 解析改写目标。
pub fn register_outbounds(
    built: &BuiltConfig,
    ohm: &SimpleOhm,
    loopback_sink: Option<Arc<dyn LoopbackSink>>,
    dns: Option<Arc<xray_app_dns::DnsService>>,
) -> Result<()> {
    // Phase 1: 注册所有 handler，收集需要代理链的 DialBridge 引用
    let mut chain_bridges: Vec<(Arc<DialBridge>, String)> = Vec::new(); // (bridge, chain_tag)
    let mut mux_bridges: Vec<(Arc<MuxBridge>, Option<String>)> = Vec::new();
    for (i, ob) in built.outbounds.iter().enumerate() {
        match try_build_handler(ob, loopback_sink.clone(), &mut mux_bridges, dns.as_ref()) {
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

    // DialerProxy（bd enk）：注册全局 transport 层代理拨号钩子。
    // 对应 Go dialer.go:270-279 `obm := outbound.ManagerFromContext(ctx)`——
    // sockopt.dialerProxy 非空时 dial_system 经此重定向到 tag 对应 handler
    // （redirect：pipe + h.Dispatch，dialer.go:111-136）。
    // ponytail: 进程级单钩子（最后注册生效）；多 Instance 并存场景待需要时再改 per-instance。
    let dialer_proxy_ohm: Arc<dyn xray_app_dispatcher::OutboundHandlerManager> =
        Arc::new(OhmRef { inner: ohm });
    xray_transport::system_dialer::set_dialer_proxy_hook(Arc::new(
        move |tag: &str, dest: &Destination| {
            use xray_app_dispatcher::OutboundHandlerManager;
            let tag = tag.to_string();
            let dest = dest.clone();
            let ohm = Arc::clone(&dialer_proxy_ohm);
            Box::pin(async move {
                let Some(handler) = ohm.get_handler(&tag) else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "there is no outbound handler for dialerProxy",
                    ));
                };
                tracing::debug!(tag = %tag, "redirecting request to dialerProxy {tag}");
                // Go redirect（dialer.go:120-135）：两对 pipe，一端 dispatch 给
                // chained handler，另一端包装为 Connection 返回。
                // ponytail: 512KiB duplex 缓冲近似 Go 无界 pipe，超出走背压。
                let (client, server) = tokio::io::duplex(512 * 1024);
                let (server_r, server_w) = tokio::io::split(server);
                let link = xray_transport::link::Link::new(
                    xray_buf::io::new_reader(server_r),
                    xray_buf::io::new_writer(server_w),
                );
                let fut = handler.dispatch(&dest, link);
                tokio::spawn(async move {
                    let _ = fut.await;
                });
                Ok(Box::new(xray_transport::connection::DuplexConnection::new(client))
                    as Box<dyn xray_transport::connection::Connection>)
            })
        },
    ));

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

/// 解析 sendThrough 为源地址规格。对齐 Go `infra/conf/xray.go:287-301`：
/// - 含 `/` → CIDR（前缀存 spec，拨号时随机取址，等价 Go `ViaCidr`+`ParseRandomIP`）
/// - 域名只允许 `origin` / `srcip`（其余域名为配置错误，同 Go `"unable to send through"`）
/// - IP → 固定源地址（Go `Via = address.Build()`）
fn parse_send_through(
    raw: &Option<String>,
) -> std::result::Result<Option<xray_transport::system_dialer::SendThroughSpec>, BuildError> {
    use xray_transport::system_dialer::SendThroughSpec;

    let Some(raw) = raw else { return Ok(None) };
    // Go ParseSendThough（xray.go:654）：取 "/" 前的地址部分
    let addr_part = raw.split('/').next().unwrap_or_default();
    let prefix_part = raw.split('/').nth(1);

    if let Some(prefix) = prefix_part {
        // CIDR 形态：地址必须可解析为 IP（Go ParseRandomIP 组 `ip+"/"+prefix`）
        let base: std::net::IpAddr = addr_part.parse().map_err(|_| {
            BuildError::Parse(format!("unable to send through: {raw}"))
        })?;
        let prefix: u8 = prefix.parse().map_err(|_| {
            BuildError::Parse(format!("invalid sendThrough CIDR prefix: {raw}"))
        })?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(BuildError::Parse(format!("invalid sendThrough CIDR prefix: {raw}")));
        }
        return Ok(Some(SendThroughSpec::Cidr { base, prefix }));
    }

    // std IpAddr 解析覆盖 Go net.ParseAddress 的 IP family 判定；
    // 解析失败 = Go 的 Domain 分支（只允许 origin/srcip，xray.go:293-298）
    match addr_part.parse::<std::net::IpAddr>() {
        Ok(ip) => Ok(Some(SendThroughSpec::Fixed(ip))),
        Err(_) if addr_part == "origin" => Ok(Some(SendThroughSpec::Origin)),
        Err(_) if addr_part == "srcip" => Ok(Some(SendThroughSpec::SrcIp)),
        Err(_) => Err(BuildError::Parse(format!("unable to send through: {raw}"))),
    }
}

/// 用 sendThrough 包装 dial_fn：每次拨号 resolve 源 IP 并设 [`DIAL_SRC`] scope。
///
/// 对应 Go `handler.go:303-307`（Handler.Dial 把 `Via` 写入 `ob.Gateway`）+
/// `dialer.go:228-235`（DialSystem 读 `ob.Gateway` 传 src）。代理链 dispatch
/// 不经 dial_fn（DialBridge::dispatch_via_chain），天然等价 Go
/// `SetOutboundGateway` 的 `!ProxySettings.HasTag()` 门控。
fn wrap_dial_with_send_through(
    dial: xray_app_dispatcher::default::DialFn,
    spec: xray_transport::system_dialer::SendThroughSpec,
) -> xray_app_dispatcher::default::DialFn {
    Arc::new(move |dest: &Destination| {
        let dial = Arc::clone(&dial);
        let spec = spec.clone();
        let dest = dest.clone();
        Box::pin(async move {
            match spec.resolve() {
                Some(ip) => {
                    xray_transport::system_dialer::DIAL_SRC
                        .scope(Some(ip), dial(&dest))
                        .await
                }
                None => dial(&dest).await,
            }
        })
    })
}

/// 包装 DialBridge 为 `(handler, Some(dial_bridge_arc), proxy_chain_tag)` 三元组。
///
/// `proxy_chain_tag` 存在时保留 `Arc<DialBridge>` 引用，以便 Phase 2 设置代理链。
/// `target_strategy` 有效（非 AsIs）时先经 [`wrap_dial_with_target_strategy`]
/// 包装 dial_fn（bd bqm）。
fn wrap_bridge(
    tag: String,
    dial_fn: xray_app_dispatcher::default::DialFn,
    proxy_chain_tag: &Option<String>,
    target_strategy: Option<DomainStrategy>,
    dns: Option<&Arc<xray_app_dns::DnsService>>,
    send_through: Option<&xray_transport::system_dialer::SendThroughSpec>,
) -> std::result::Result<(Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>), BuildError> {
    let dial_fn = match target_strategy {
        Some(s) => wrap_dial_with_target_strategy(dial_fn, s, dns.cloned()),
        None => dial_fn,
    };
    // sendThrough（bd 7zc）包装在最外层：targetStrategy 改写目标后再定源地址族
    let dial_fn = match send_through {
        Some(spec) => wrap_dial_with_send_through(dial_fn, spec.clone()),
        None => dial_fn,
    };
    let bridge = Arc::new(DialBridge::new(tag, dial_fn));
    let handler = Arc::clone(&bridge) as Arc<dyn DispatchHandler>;
    let bridge_ref = if proxy_chain_tag.is_some() { Some(bridge) } else { None };
    Ok((handler, bridge_ref, proxy_chain_tag.clone()))
}

/// 构建单个 outbound handler（动态 AddOutbound 用，bd bg7）。
///
/// 与 [`try_build_handler`] 同一构建路径（协议全覆盖），mux outbound 返回
/// `Unsupported`（动态 mux 依赖 register_outbounds 的 Phase 2 二次扫描，
/// API 场景不适用）。DNS 服务未注入（API 路径暂无 DnsService 传递链），
/// targetStrategy=Force* 在该路径下解析域名会失败断链。
pub fn build_single_outbound(
    ob: &BuiltOutbound,
) -> std::result::Result<Arc<dyn DispatchHandler>, BuildError> {
    let mut mux_bridges = Vec::new();
    let (handler, _, _) = try_build_handler(ob, None, &mut mux_bridges, None)?;
    Ok(handler)
}

/// proto `OutboundHandlerConfig`（gRPC AddOutbound）→ `BuiltOutbound`。
///
/// TypedMessage 约定（与 CLI `api_exec::build_typed_message` 一致）：
/// - `proxy_settings.type`：`xray.proxy.{protocol}.Config`，value = 协议 settings JSON
/// - `sender_settings.type`：`xray.app.proxyman.outbound`，value = sender JSON
///   （`streamSettings` 字段提升为 `BuiltOutbound.stream_settings_json`）
pub fn built_outbound_from_proto(
    cfg: &OutboundHandlerConfigProto,
) -> std::result::Result<BuiltOutbound, BuildError> {
    let type_url = cfg
        .proxy_settings
        .as_ref()
        .map(|m| m.r#type.as_str())
        .unwrap_or_default();
    // 协议名：`xray.proxy.freedom.Config` → `freedom`。
    let protocol = type_url
        .strip_prefix("xray.proxy.")
        .and_then(|s| s.strip_suffix(".Config"))
        .ok_or_else(|| BuildError::Unsupported(type_url.to_string()))?;
    let proxy_json: serde_json::Value = serde_json::from_slice(
        &cfg.proxy_settings
            .as_ref()
            .map(|m| m.value.clone())
            .unwrap_or_default(),
    )
    .map_err(|e| BuildError::Parse(e.to_string()))?;
    let mut stream_settings_json = None;
    if let Some(sender) = &cfg.sender_settings {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&sender.value) {
            stream_settings_json = v.get("streamSettings").cloned();
        }
    }
    Ok(BuiltOutbound {
        entry: xray_conf::BuiltEntry {
            kind: protocol.to_string(),
            data: serde_json::to_vec(&proxy_json).map_err(|e| BuildError::Parse(e.to_string()))?,
        },
        tag: cfg.tag.clone(),
        send_through: None,
        stream_settings_json,
        proxy_settings_json: None,
        mux_json: None,
        // proto sender_settings 的 targetStrategy（i32 枚举）→ 字符串的逆向
        // 映射未实现（gRPC AddOutbound 携带该字段的场景待补，bd bqm 差异项）
        target_strategy: None,
    })
}

/// commander HandlerService 的生产 outbound 运行时（bd ze3/bg7）。
///
/// 把 gRPC AddOutbound 的 proto config 经 [`built_outbound_from_proto`] →
/// [`build_single_outbound`] 构建真实 handler 注册进 [`SimpleOhm`]——对应 Go
/// `app/proxyman/command/handlers.go` 的 `addOutbound`（CreateObject + ohm.AddHandler）。
pub struct ApiOutboundRuntime {
    ohm: Arc<SimpleOhm>,
}

impl ApiOutboundRuntime {
    #[must_use]
    pub fn new(ohm: Arc<SimpleOhm>) -> Self {
        Self { ohm }
    }
}

impl xray_app_commander::OutboundRuntime for ApiOutboundRuntime {


    fn add_outbound(
        &self,
        cfg: &OutboundHandlerConfigProto,
    ) -> std::result::Result<(), String> {
        let ob = built_outbound_from_proto(cfg).map_err(|e| format!("{e:?}"))?;
        if self.ohm.get_handler(&cfg.tag).is_some() {
            return Err(format!("existing tag found: {}", cfg.tag));
        }
        let handler = build_single_outbound(&ob).map_err(|e| format!("{e:?}"))?;
        self.ohm.add(&cfg.tag, handler);
        Ok(())
    }

    fn remove_outbound(&self, tag: &str) -> std::result::Result<(), String> {
        if self.ohm.remove(tag) {
            Ok(())
        } else {
            Err(format!("tag not found: {tag}"))
        }
    }

    fn list_outbound_tags(&self) -> Vec<String> {
        self.ohm.list_tags()
    }
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
    dns: Option<&Arc<xray_app_dns::DnsService>>,
) -> std::result::Result<(Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>), BuildError> {
    let proxy_chain_tag = parse_proxy_chain_tag(ob.proxy_settings_json.as_ref());
    // targetStrategy（bd bqm）：字符串 → 枚举；AsIs（无策略）不包装
    // （Go handler.go:184 `HasStrategy()` 门控）
    let target_strategy = ob
        .target_strategy
        .as_deref()
        .and_then(parse_target_strategy)
        .filter(|s| s.has_strategy());
    // sendThrough（bd 7zc）：outbound 顶层字段 → 源地址规格（Go xray.go:287-301）
    let send_through = parse_send_through(&ob.send_through)?;
    match ob.entry.kind.as_str() {
        "freedom" => {
            let config = parse_freedom_config(&ob.entry.data);
            let noises = config.noises.clone();
            let dial_fn = xray_proxy_freedom::make_freedom_dial_fn_with_config(config);
            let dial_fn = match target_strategy {
                Some(s) => wrap_dial_with_target_strategy(dial_fn, s, dns.cloned()),
                None => dial_fn,
            };
            // sendThrough：TCP 分支经 dial_fn 包装（每次拨号设 DIAL_SRC scope）
            let dial_fn = match &send_through {
                Some(spec) => wrap_dial_with_send_through(dial_fn, spec.clone()),
                None => dial_fn,
            };
            // TCP 走 DialBridge（fragment 经 DialFn 包装 writer），UDP 走
            // FreedomDispatchBridge（noises 首包前注入；sendThrough 经 with_send_through）
            let tcp_bridge = Arc::new(DialBridge::new(ob.tag.clone(), dial_fn));
            let mut bridge = xray_proxy_freedom::FreedomDispatchBridge::from_bridge(
                Arc::clone(&tcp_bridge),
            )
            .with_noises(noises);
            if let Some(spec) = &send_through {
                bridge = bridge.with_send_through(spec.clone());
            }
            let handler = Arc::new(bridge) as Arc<dyn DispatchHandler>;
            let bridge_ref = if proxy_chain_tag.is_some() { Some(tcp_bridge) } else { None };
            Ok((handler, bridge_ref, proxy_chain_tag))
        }
        "vless" => {
            let config = parse_vless_config(&ob.entry.data)?;
            let config = config.with_stream_settings(parse_stream_settings(&ob.stream_settings_json));
            let dial_fn = xray_proxy_vless::make_vless_dial_fn(Arc::new(config));
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag, target_strategy, dns, send_through.as_ref())
        }
        "trojan" => {
            let config = parse_trojan_config(&ob.entry.data)?;
            let config = config.with_stream_settings(parse_stream_settings(&ob.stream_settings_json));
            let dial_fn = xray_proxy_trojan::make_trojan_dial_fn(Arc::new(config));
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag, target_strategy, dns, send_through.as_ref())
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
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag, target_strategy, dns, send_through.as_ref())
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
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag, target_strategy, dns, send_through.as_ref())
        }
        "shadowsocks" => {
            let config = xray_proxy_ss::parse_ss_config(&ob.entry.data)?;
            let dial_fn = xray_proxy_ss::make_ss_dial_fn(Arc::new(config));
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag, target_strategy, dns, send_through.as_ref())
        }
        "hysteria" => {
            let (server_addr, auth, server_name) = parse_hysteria_config(&ob.entry.data)?;
            let config = HysteriaConfig::new(&server_addr, &auth).with_server_name(&server_name);
            let _ = rustls::crypto::ring::default_provider().install_default();
            let tls_config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
            let stream_settings = xray_transport::dialer::StreamSettings::from_json(ob.stream_settings_json.as_ref());
            let salamander = xray_transport_hysteria::salamander_socket::parse_salamander_obfs(
                stream_settings.finalmask_json.as_ref(),
            ).map_err(|e| format!("hysteria finalmask: {e}"))?;
            // streamSettings.finalmask.quicParams → HysteriaConfig（brutal/CC/windows/keepAlive）
            let quic_params = xray_transport_hysteria::quic_params::parse_quic_params(
                stream_settings.finalmask_json.as_ref(),
            ).map_err(|e| format!("hysteria quicParams: {e}"))?
                .unwrap_or_else(xray_transport_hysteria::quic_params::default_hysteria_quic_params);
            let config = config.with_quic_params(quic_params);
            let transport = xray_transport_hysteria::hysteria_transport::QuinnHysteriaTransport::new(
                tls_config, "0.0.0.0:0".parse().map_err(|e| format!("bind addr: {e}"))?,
            ).map_err(|e| format!("hysteria transport: {e}"))?
                .with_salamander(salamander);
            let dial_fn = xray_proxy_hysteria::make_hysteria_dial_fn(config, Arc::new(transport));
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag, target_strategy, dns, send_through.as_ref())
        }
        "anytls" => {
            let config = parse_anytls_config(&ob.entry.data)?;
            let client = Arc::new(xray_proxy_anytls::AnytlsClient::new(config));
            let dial_fn = xray_proxy_anytls::make_anytls_dial_fn(client);
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag, target_strategy, dns, send_through.as_ref())
        }
        "tuic" => {
            let s = parse_tuic_config(&ob.entry.data)?;
            let rustls_config = build_tuic_rustls_config(
                &s.alpn,
                s.reduce_rtt,
                s.insecure,
                s.certificate.as_deref(),
            )?;
            let options = xray_proxy_tuic::TuicConnectOptions {
                congestion_control: s.congestion_control,
                heartbeat: s.heartbeat,
                udp_relay_mode: s.udp_relay_mode,
            };
            let dial_fn = xray_proxy_tuic::make_tuic_dial_fn_lazy(
                s.server_addr,
                s.server_name,
                s.uuid,
                s.password,
                rustls_config,
                options,
            );
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag, target_strategy, dns, send_through.as_ref())
        }
        "wireguard" => {
            let config = parse_wireguard_config(&ob.entry.data)?;
            let dial_fn = xray_proxy_wireguard::make_wireguard_dial_fn(config, dns.cloned());
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag, target_strategy, dns, send_through.as_ref())
        }
        "dns" => {
            let handler = parse_dns_outbound_config(&ob.entry.data)?;
            let bridge = DnsDispatchBridge::new(ob.tag.clone(), handler, dns.cloned());
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
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag, target_strategy, dns, send_through.as_ref())
        }
        "dokodemo" => {
            let config = parse_dokodemo_config(&ob.entry.data)?;
            let dial_fn = xray_proxy_dokodemo::make_dokodemo_dial_fn(config);
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag, target_strategy, dns, send_through.as_ref())
        }
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
        "tun" => {
            let dial_fn = xray_proxy_tun::make_tun_dial_fn();
            wrap_bridge(ob.tag.clone(), dial_fn, &proxy_chain_tag, target_strategy, dns, send_through.as_ref())
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

/// `targetStrategy` 字符串 → 枚举（大小写不敏感）。
///
/// 对应 Go `infra/conf/xray.go:257-282`（`strings.ToLower` switch 的 11 个值）。
/// 非法值返回 None（conf 层 `Config::build` 已校验合法值并硬报错，此处防御兜底）。
fn parse_target_strategy(s: &str) -> Option<DomainStrategy> {
    match s.to_lowercase().as_str() {
        "" | "asis" => Some(DomainStrategy::AsIs),
        "useip" => Some(DomainStrategy::UseIP),
        "useipv4" => Some(DomainStrategy::UseIPv4),
        "useipv6" => Some(DomainStrategy::UseIPv6),
        "useipv4v6" => Some(DomainStrategy::UseIPv4v6),
        "useipv6v4" => Some(DomainStrategy::UseIPv6v4),
        "forceip" => Some(DomainStrategy::ForceIP),
        "forceipv4" => Some(DomainStrategy::ForceIPv4),
        "forceipv6" => Some(DomainStrategy::ForceIPv6),
        "forceipv4v6" => Some(DomainStrategy::ForceIPv4v6),
        "forceipv6v4" => Some(DomainStrategy::ForceIPv6v4),
        _ => None,
    }
}

/// `internet.LookupForIP` 等价实现。
///
/// 对应 Go `transport/internet/dialer.go:87-109` 的 `localAddr == nil` 分支
/// （sendThrough/Via 未接入 bd 7zc，此处恒 nil）：
/// 1. 按 strategy 的 prefer 家族查询（dialer.go:92-95）
/// 2. 失败/空结果 + HasFallback → 按 fallback 家族再查（dialer.go:96-103）
/// 3. 空结果 → ErrEmptyResponse（dialer.go:105-106）
async fn lookup_for_ip(
    dns: &xray_app_dns::DnsService,
    domain: &str,
    strategy: DomainStrategy,
) -> std::result::Result<Vec<std::net::IpAddr>, String> {
    use xray_app_dns::config::IpOption;
    // Go `PreferIP4()/PreferIP6()`（config.go:110-116）：`strategy_table()[1] == 0`
    // 时两家族都启用。`xray_proxy_freedom::DomainStrategy` 已对齐 Go（bd 3ln），
    // 故直接复用 prefer_ipv4/6()，避免重复字面比较。
    let prefer = IpOption {
        ipv4_enable: strategy.prefer_ipv4(),
        ipv6_enable: strategy.prefer_ipv6(),
        fake_enable: false,
    };
    let mut result = dns.lookup_ip(domain, prefer).await;
    let need_fallback = match &result {
        Ok((ips, _)) => ips.is_empty(),
        Err(_) => true,
    };
    if need_fallback && strategy.has_fallback() {
        let fallback = IpOption {
            ipv4_enable: strategy.fallback_ipv4(),
            ipv6_enable: strategy.fallback_ipv6(),
            fake_enable: false,
        };
        result = dns.lookup_ip(domain, fallback).await;
    }
    match result {
        Ok((ips, _)) if !ips.is_empty() => Ok(ips),
        Ok(_) => Err("empty DNS response".to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// 用 targetStrategy 包装 dial_fn：域名目标在拨号前经 DNS 解析改写为 IP。
///
/// 对应 Go `app/proxyman/outbound/handler.go:184-205`（Handler.Dispatch 的
/// TargetStrategy 段）：`HasStrategy` + 域名目标 → `LookupForIP` → 随机选一个
/// IP 改写目标（handler.go:202 `ips[dice.Roll(len(ips))]`）；解析失败时
/// Force* 断链报错（handler.go:192-197）、Use* 回退域名直连（handler.go:190-191）。
///
/// ## 与 Go 的差异（`DialFn` 签名无 session 上下文）
///
/// - `content.SkipDNSResolve` 门控未实现（Go handler.go:184）
/// - UDP `GetDynamicStrategy(origTargetAddr)` 动态策略未实现（Go handler.go:186-188）；
///   UDP 域名目标按原策略解析
fn wrap_dial_with_target_strategy(
    inner: xray_app_dispatcher::default::DialFn,
    strategy: DomainStrategy,
    dns: Option<Arc<xray_app_dns::DnsService>>,
) -> xray_app_dispatcher::default::DialFn {
    use rand::Rng;
    use xray_common::net::address::Address;
    use xray_common::net::destination::Destination;
    Arc::new(move |dest: &Destination| {
        let inner = Arc::clone(&inner);
        let dns = dns.clone();
        let dest = dest.clone();
        Box::pin(async move {
            // Go handler.go:184：仅域名目标走解析（`Family().IsDomain()` 门控）
            let Address::Domain(domain) = dest.address() else {
                return inner(&dest).await;
            };
            let domain = domain.clone();
            let Some(dns) = dns else {
                // Go dialer.go:88-90：dnsClient 未初始化 → 错误
                if strategy.force_ip() {
                    return Err(format!(
                        "failed to resolve ip for target {domain}: DNS client not initialized"
                    ));
                }
                return inner(&dest).await;
            };
            match lookup_for_ip(&dns, &domain, strategy).await {
                Ok(ips) => {
                    // Go handler.go:202：dice.Roll 随机选一个
                    let ip = ips[rand::rng().random_range(0..ips.len())];
                    tracing::info!(target = %domain, resolved = %ip, "target strategy resolved");
                    let resolved = Destination::new(Address::from(ip), dest.port(), dest.network());
                    inner(&resolved).await
                }
                Err(e) => {
                    // Go handler.go:190-199：Force* 断链报错；Use* 回退域名直连
                    if strategy.force_ip() {
                        return Err(format!("failed to resolve ip for target {domain}: {e}"));
                    }
                    tracing::info!(target = %domain, error = %e, "resolve failed, fallback to domain");
                    inner(&dest).await
                }
            }
        })
    })
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
    // 例外（bd enk）：配了 `sockopt` 不折叠——TCP+无 TLS 的 sockopt（如
    // dialerProxy/mark）必须到达 dial_system（Go 中 SocketSettings 存在时
    // sockopt 恒生效，dialer.go:270）。
    if s.protocol == "tcp" && !s.is_tls() && s.sockopt_json.is_none() {
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
/// 对应 Go `proxy/dns/dns.go::Handler.Process`：
/// - ownLink 防环（dns.go:242-247）：本 DNS 服务自身的上游查询原样转发
/// - 规则匹配 → Drop / Return（rCode 空响应）/ Hijack（DnsService.lookup_ip，
///   fake_enable=true 可触发 FakeDNS）/ Direct（原样字节转发到 rewrite 后的 dest）
/// - UDP 单请求-响应；TCP 双路 IO loop（request 帧 → 决策，response 帧 → 回写）
/// DNS 不走标准 DialBridge（无 dial 语义），而是直接实现 DispatchHandler。
struct DnsDispatchBridge {
    tag: String,
    /// 规则匹配 Handler（qType + domain → action + rCode）。
    handler: xray_proxy_dns::Handler,
    /// xray-app-dns 服务：Hijack 动作 lookup_ip + ownLink 判定。
    dns_service: Option<Arc<xray_app_dns::server::DnsService>>,
}

impl DnsDispatchBridge {
    fn new(
        tag: impl Into<String>,
        handler: xray_proxy_dns::Handler,
        dns_service: Option<Arc<xray_app_dns::server::DnsService>>,
    ) -> Self {
        Self { tag: tag.into(), handler, dns_service }
    }

    /// Go `isOwnLink`（dns.go:118-120）：DnsService 实现 ownLinkVerifier。
    fn is_own_link(&self, inbound_tag: &str) -> bool {
        self.dns_service
            .as_ref()
            .is_some_and(|s| s.is_own_link(inbound_tag))
    }
}

impl std::fmt::Debug for DnsDispatchBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsDispatchBridge")
            .field("tag", &self.tag)
            .finish()
    }
}

/// TCP DNS 帧增量解码器（RFC 1035 §4.2.2 长度前缀帧）。
struct DnsFrameDecoder {
    buf: Vec<u8>,
}

impl DnsFrameDecoder {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// 喂入字节，产出完整帧（无完整帧则缓存等待）。
    fn feed(&mut self, chunk: &[u8], out: &mut Vec<Vec<u8>>) {
        self.buf.extend_from_slice(chunk);
        while self.buf.len() >= 2 {
            let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
            if self.buf.len() < 2 + len {
                break;
            }
            out.push(self.buf[2..2 + len].to_vec());
            self.buf.drain(..2 + len);
        }
    }
}

/// 按上游网络类型原样转发（Go outboundConn + connWriter）。
async fn forward_raw(
    query: &[u8],
    upstream: &Destination,
    timeout: std::time::Duration,
) -> Option<Vec<u8>> {
    let r = if upstream.is_tcp() {
        xray_proxy_dns::forward_tcp_raw(query, upstream, timeout).await
    } else {
        xray_proxy_dns::forward_udp_raw(query, upstream, timeout).await
    };
    match r {
        Ok(resp) => Some(resp),
        Err(e) => {
            tracing::debug!(upstream = %upstream, error = %e, "dns raw forward failed");
            None
        }
    }
}

/// Hijack 动作：A/AAAA 查询经 DnsService.lookup_ip（fake_enable=true，
/// 可命中 FakeDNS client）构造响应。对应 Go `handleIPQuery`（dns.go:313-391）。
///
/// 返回 `None` = 静默不回包（Go：err 非 RCodeError/EmptyResponse 时不响应）。
async fn handle_ip_query(
    query: &[u8],
    svc: &Arc<xray_app_dns::server::DnsService>,
) -> Option<Vec<u8>> {
    use xray_app_dns::config::IpOption;

    let (header, question) = xray_proxy_dns::parse_dns_query(query).ok()?;
    let option = if question.q_type == xray_proxy_dns::QTYPE_A {
        IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: true }
    } else {
        IpOption { ipv4_enable: false, ipv6_enable: true, fake_enable: true }
    };
    match svc.lookup_ip(&question.name, option).await {
        Ok((ips, ttl)) if !ips.is_empty() => {
            Some(xray_proxy_dns::build_ip_response(&header, &question, &ips, ttl))
        }
        // Go: ErrEmptyResponse → rCode 0 空响应（dns.go:334 构造空 answer）。
        Err(xray_app_dns::error::DnsError::EmptyResponse) => {
            Some(xray_proxy_dns::build_dns_response(&header, &question, 0))
        }
        // Go: RCodeFromError 提取 RCodeError → 响应带该 rCode。
        Err(xray_app_dns::error::DnsError::RCodeError(rc)) => {
            Some(xray_proxy_dns::build_dns_response(&header, &question, rc as u8))
        }
        // Go dns.go:334-337：其余错误静默（rCode 0 + ips 空 + 非 EmptyResponse）。
        Ok((_, _)) | Err(_) => None,
    }
}

impl DispatchHandler for DnsDispatchBridge {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn dispatch(&self, dest: &Destination, link: Link) -> PinFuture<()> {
        let (tag, handler, dns_service) =
            (self.tag.clone(), self.handler.clone(), self.dns_service.clone());
        let upstream = handler.rewrite_dest(dest);
        let timeout = handler.timeout;
        let own_link = self.is_own_link("");
        Box::pin(async move {
            dispatch_dns_link(tag, handler, dns_service, upstream, timeout, own_link, link).await;
        })
    }

    /// 带 access 上下文（Go ctx 携带 session.Inbound）——ownLink 判定入口。
    fn dispatch_with_access(
        &self,
        dest: &Destination,
        link: Link,
        access: xray_app_dispatcher::default::AccessContext,
    ) -> PinFuture<()> {
        let own_link = self.is_own_link(&access.inbound_tag);
        let (tag, handler, dns_service) =
            (self.tag.clone(), self.handler.clone(), self.dns_service.clone());
        let upstream = handler.rewrite_dest(dest);
        let timeout = handler.timeout;
        Box::pin(async move {
            dispatch_dns_link(tag, handler, dns_service, upstream, timeout, own_link, link).await;
        })
    }
}

/// DNS link 分发主体（Go `Handler.Process` 的 request/response 双 loop）。
///
/// UDP（单请求-响应，对应 dokodemo UDP 分发的 per-session link）与
/// TCP（长度前缀帧流，双路并发）分别处理。
async fn dispatch_dns_link(
    tag: String,
    handler: xray_proxy_dns::Handler,
    dns_service: Option<Arc<xray_app_dns::server::DnsService>>,
    upstream: Destination,
    timeout: std::time::Duration,
    own_link: bool,
    mut link: Link,
) {
    use xray_buf::io::{Reader, Writer};
    use xray_buf::multi::MultiBuffer;

    if upstream.is_udp() {
        // ---- UDP：单包请求-响应（Go UDPReader/UDPWriter + outboundConn） ----
        let query = match link.reader.read_multi_buffer().await {
            Ok(mb) if !mb.is_empty() => {
                let mut q = Vec::new();
                for b in mb.iter() {
                    q.extend_from_slice(b.bytes());
                }
                q
            }
            _ => return,
        };
        let response = if own_link {
            // Go dns.go:242-247：自身流量原样转发，不做规则处理（防环）。
            forward_raw(&query, &upstream, timeout).await
        } else {
            match handler.process(&query).await {
                Ok(xray_proxy_dns::ProcessOutcome::Drop) => None,
                Ok(xray_proxy_dns::ProcessOutcome::Respond { response }) => Some(response),
                Ok(xray_proxy_dns::ProcessOutcome::Forward { query }) => {
                    forward_raw(&query, &upstream, timeout).await
                }
                Ok(xray_proxy_dns::ProcessOutcome::Hijack { query }) => match &dns_service {
                    Some(svc) => handle_ip_query(&query, svc).await,
                    None => None,
                },
                Err(e) => {
                    tracing::debug!(tag = %tag, "dns udp process: {e}");
                    None
                }
            }
        };
        if let Some(resp) = response {
            let buf = xray_buf::buffer::Buffer::from_vec(resp);
            let mb = MultiBuffer::from_buffer(buf);
            if let Err(e) = link.writer.write_multi_buffer(mb).await {
                tracing::debug!(tag = %tag, "dns udp write: {e}");
            }
        }
        link.writer.shutdown();
        return;
    }

    // ---- TCP：长度前缀帧流，双路 IO loop（Go task.Run(request, response)） ----
    // Go timeout = policy ConnectionIdle（Level0 = 300s），Rust 侧用同值常量做 idle。
    const DNS_IDLE: std::time::Duration = std::time::Duration::from_secs(300);

    let writer = Arc::new(tokio::sync::Mutex::new(link.writer));
    // lazy 上游写半连接（Go outboundConn：Write 首拨）。读半连接经 channel
    // 移交 response loop（Go connReady channel 的等价物）。
    let write_slot: Arc<tokio::sync::Mutex<Option<tokio::net::tcp::OwnedWriteHalf>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    let (read_tx, mut read_rx) = tokio::sync::mpsc::channel::<tokio::net::tcp::OwnedReadHalf>(1);

    // response loop：读上游 TCP 帧 → 回写客户端（Go response()，dns.go:286-304）。
    let response_loop = {
        let writer = Arc::clone(&writer);
        let tag = tag.clone();
        use tokio::io::AsyncReadExt as _;
        async move {
            // 等待上游拨号（无上游查询时挂起，任一侧断开即整体结束）。
            let Some(mut rh) = read_rx.recv().await else { return };
            let mut decoder = DnsFrameDecoder::new();
            let mut frames = Vec::new();
            let mut buf = vec![0u8; 4096];
            loop {
                let n = match tokio::time::timeout(DNS_IDLE, rh.read(&mut buf)).await {
                    Ok(Ok(0)) | Err(_) => return, // EOF / idle 超时
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => {
                        tracing::debug!(tag = %tag, "dns upstream read: {e}");
                        return;
                    }
                };
                frames.clear();
                decoder.feed(&buf[..n], &mut frames);
                for frame in frames.drain(..) {
                    let resp = match xray_proxy_dns::encode_tcp_dns_message(&frame) {
                        Ok(f) => f,
                        Err(_) => continue,
                    };
                    let mb = xray_buf::multi::MultiBuffer::from_buffer(
                        xray_buf::buffer::Buffer::from_vec(resp),
                    );
                    if let Err(e) = writer.lock().await.write_multi_buffer(mb).await {
                        tracing::debug!(tag = %tag, "dns client write: {e}");
                        return;
                    }
                }
            }
        }
    };

    // request loop：读客户端帧 → 决策（Go request()，dns.go:229-284）。
    let writer_for_req = Arc::clone(&writer);
    let request_loop = async move {
        let mut decoder = DnsFrameDecoder::new();
        let mut frames = Vec::new();
        loop {
            let mb = match tokio::time::timeout(DNS_IDLE, link.reader.read_multi_buffer()).await {
                Ok(Ok(mb)) if !mb.is_empty() => mb,
                Ok(Ok(_)) | Ok(Err(_)) | Err(_) => return, // EOF / idle 超时 / 断开
            };
            let mut chunk = Vec::new();
            for b in mb.iter() {
                chunk.extend_from_slice(b.bytes());
            }
            frames.clear();
            decoder.feed(&chunk, &mut frames);
            for query in frames.drain(..) {
                if own_link {
                    // Go dns.go:242-247：自身流量原样转发（防环）。
                    write_or_inline_upstream(
                        &write_slot,
                        &read_tx,
                        &writer_for_req,
                        &tag,
                        &upstream,
                        &query,
                        timeout,
                    )
                    .await;
                    continue;
                }
                match handler.process(&query).await {
                    Ok(xray_proxy_dns::ProcessOutcome::Drop) => {
                        tracing::debug!(tag = %tag, "dns tcp query dropped by rule");
                    }
                    Ok(xray_proxy_dns::ProcessOutcome::Respond { response }) => {
                        write_client_frame(&writer_for_req, &tag, &response).await;
                    }
                    Ok(xray_proxy_dns::ProcessOutcome::Forward { query }) => {
                        write_or_inline_upstream(
                            &write_slot,
                            &read_tx,
                            &writer_for_req,
                            &tag,
                            &upstream,
                            &query,
                            timeout,
                        )
                        .await;
                    }
                    Ok(xray_proxy_dns::ProcessOutcome::Hijack { query }) => {
                        // Go: go h.handleIPQuery(...)——异步不阻塞请求循环。
                        if let Some(svc) = dns_service.clone() {
                            let w = Arc::clone(&writer_for_req);
                            let t = tag.clone();
                            tokio::spawn(async move {
                                if let Some(resp) = handle_ip_query(&query, &svc).await {
                                    write_client_frame(&w, &t, &resp).await;
                                }
                            });
                        }
                    }
                    Err(e) => {
                        tracing::debug!(tag = %tag, "dns tcp process: {e}");
                    }
                }
            }
        }
    };

    // Go task.Run：任一 loop 结束即整体结束。
    tokio::select! {
        _ = request_loop => {},
        _ = response_loop => {},
    }
    writer.lock().await.shutdown();
}

/// 写客户端（TCP 帧）。
async fn write_client_frame(
    writer: &Arc<tokio::sync::Mutex<Box<dyn xray_buf::io::Writer>>>,
    tag: &str,
    msg: &[u8],
) {
    let Ok(framed) = xray_proxy_dns::encode_tcp_dns_message(msg) else {
        return;
    };
    let mb =
        xray_buf::multi::MultiBuffer::from_buffer(xray_buf::buffer::Buffer::from_vec(framed));
    if let Err(e) = writer.lock().await.write_multi_buffer(mb).await {
        tracing::debug!(tag = %tag, "dns client write: {e}");
    }
}

/// Direct/ownLink 写上游：TCP 上游经 lazy 连接（response loop 回流）；
/// UDP 上游内联往返直接回写客户端。
async fn write_or_inline_upstream(
    write_slot: &Arc<tokio::sync::Mutex<Option<tokio::net::tcp::OwnedWriteHalf>>>,
    read_tx: &tokio::sync::mpsc::Sender<tokio::net::tcp::OwnedReadHalf>,
    writer: &Arc<tokio::sync::Mutex<Box<dyn xray_buf::io::Writer>>>,
    tag: &str,
    upstream: &Destination,
    query: &[u8],
    timeout: std::time::Duration,
) {
    use tokio::io::AsyncWriteExt;

    if !upstream.is_tcp() {
        // UDP 上游：内联往返（等价 Go UDPWriter/connReader 单包语义）。
        if let Some(resp) = forward_raw(query, upstream, timeout).await {
            write_client_frame(writer, tag, &resp).await;
        }
        return;
    }

    let Ok(framed) = xray_proxy_dns::encode_tcp_dns_message(query) else {
        return;
    };
    let mut guard = write_slot.lock().await;
    if guard.is_none() {
        // lazy dial（Go outboundConn.Write → dial）。
        let addr = match xray_proxy_dns::resolve_dest_socket_addr(upstream).await {
            Ok(a) => a,
            Err(e) => {
                tracing::debug!(upstream = %upstream, error = %e, "dns upstream resolve failed");
                return;
            }
        };
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(conn)) => {
                let (rh, wh) = conn.into_split();
                *guard = Some(wh);
                let _ = read_tx.try_send(rh); // 唤醒 response loop
            }
            _ => {
                tracing::debug!(upstream = %upstream, "dns upstream dial failed/timeout");
                return;
            }
        }
    }
    if let Some(wh) = guard.as_mut() {
        if let Err(e) = wh.write_all(&framed).await {
            tracing::debug!(upstream = %upstream, error = %e, "dns upstream write failed");
        }
    }
}

// ========== DNS Outbound 配置解析 ==========

/// 从 outbound entry.data（JSON）解析 dns outbound 配置。
///
/// JSON（Rust 扩展，Go JSON 侧 dns outbound settings 为空对象）：
/// `{"rule":[{"action":"drop","qType":[28],"rCode":5}], "rewriteServer":{...}}`
fn parse_dns_outbound_config(data: &[u8]) -> std::result::Result<xray_proxy_dns::Handler, String> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| format!("dns outbound settings JSON: {e}"))?;
    let mut config = xray_proxy_dns::Config::default();

    if let Some(rules) = v.get("rule").and_then(|x| x.as_array()) {
        for r in rules {
            let action = match r.get("action") {
                Some(serde_json::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                    "drop" => xray_proxy_dns::RuleAction::Drop,
                    "return" => xray_proxy_dns::RuleAction::Return,
                    "hijack" => xray_proxy_dns::RuleAction::Hijack,
                    _ => xray_proxy_dns::RuleAction::Direct,
                },
                _ => xray_proxy_dns::RuleAction::Direct,
            };
            let q_type = r
                .get("qType")
                .and_then(|x| x.as_array())
                .map(|arr| {
                    arr.iter().filter_map(|x| x.as_i64().map(|n| n as i32)).collect()
                })
                .unwrap_or_default();
            let r_code = r.get("rCode").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            config.rule.push(xray_proxy_dns::DnsRuleConfig {
                action,
                q_type,
                r_code,
                domain: Vec::new(),
            });
        }
    }

    if let Some(rw) = v.get("rewriteServer") {
        let network = match rw.get("network").and_then(|x| x.as_str()) {
            Some("tcp") => 2,  // xray.common.net.Network.TCP
            Some("udp") => 3,  // xray.common.net.Network.UDP
            _ => 0,            // Unknown → 不覆盖
        };
        let address = rw.get("address").and_then(|x| x.as_str()).and_then(|s| {
            if let Ok(v4) = s.parse::<std::net::Ipv4Addr>() {
                Some(xray_proto::xray::common::net::IpOrDomain {
                    address: Some(xray_proto::xray::common::net::ip_or_domain::Address::Ip(
                        v4.octets().to_vec(),
                    )),
                })
            } else if let Ok(v6) = s.parse::<std::net::Ipv6Addr>() {
                Some(xray_proto::xray::common::net::IpOrDomain {
                    address: Some(xray_proto::xray::common::net::ip_or_domain::Address::Ip(
                        v6.octets().to_vec(),
                    )),
                })
            } else if !s.is_empty() {
                Some(xray_proto::xray::common::net::IpOrDomain {
                    address: Some(xray_proto::xray::common::net::ip_or_domain::Address::Domain(
                        s.to_string(),
                    )),
                })
            } else {
                None
            }
        });
        let port = rw.get("port").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
        config.rewrite_server =
            Some(xray_proto::xray::common::net::Endpoint { network, address, port });
    }

    Ok(xray_proxy_dns::Handler::init(&config))
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

/// tuic outbound 解析结果（官方 tuic-client relay 配置子集，bd 7p0）。
///
/// 字段与默认值对齐 Itsusinn/tuic（官方 TUIC 实现后继）client config.rs。
struct TuicOutboundSettings {
    server_addr: std::net::SocketAddr,
    server_name: String,
    uuid: uuid::Uuid,
    password: String,
    /// 拥塞控制（官方默认 bbr）。
    congestion_control: xray_proxy_tuic::CongestionControl,
    /// ALPN 列表；空 → 默认 ["h3","tuic"]。
    alpn: Vec<Vec<u8>>,
    /// 0-RTT（官方名 zero_rtt_handshake；quinn 经会话恢复自动 0-RTT）。
    reduce_rtt: bool,
    /// UDP relay 模式（官方默认 native）。
    udp_relay_mode: xray_proxy_tuic::UdpRelayMode,
    /// 心跳周期（官方默认 3s）。
    heartbeat: std::time::Duration,
    /// 跳过证书验证（显式 opt-in）。
    insecure: bool,
    /// 信任的服务端证书 PEM（自签 CA 场景）。
    certificate: Option<String>,
}

/// 解析 tuic outbound settings JSON。
///
/// JSON 格式：`{"servers":[{"address":"...","port":443,"uuid":"...","password":"...",
/// "server_name":"...","congestion_control":"bbr","alpn":["h3"],
/// "reduce_rtt":false,"udp_relay_mode":"native","heartbeat":3,
/// "insecure":false,"certificate":"<PEM>"}]}`。
fn parse_tuic_config(data: &[u8]) -> std::result::Result<TuicOutboundSettings, String> {
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

    let congestion_name = first.get("congestion_control").and_then(|v| v.as_str()).unwrap_or("bbr");
    let congestion_control = xray_proxy_tuic::CongestionControl::from_name(congestion_name)
        .ok_or_else(|| format!(
            "invalid tuic congestion_control: {congestion_name} (valid: bbr, cubic, new_reno)"
        ))?;
    let alpn: Vec<Vec<u8>> = first.get("alpn").and_then(|v| v.as_array())
        .map(|arr| arr.iter()
            .filter_map(|x| x.as_str().map(|s| s.as_bytes().to_vec()))
            .collect())
        .unwrap_or_default();
    let reduce_rtt = first.get("reduce_rtt").and_then(|v| v.as_bool())
        .or_else(|| first.get("zero_rtt_handshake").and_then(|v| v.as_bool()))
        .unwrap_or(false);
    let udp_mode_name = first.get("udp_relay_mode").and_then(|v| v.as_str()).unwrap_or("native");
    let udp_relay_mode = xray_proxy_tuic::UdpRelayMode::from_name(udp_mode_name)
        .ok_or_else(|| format!(
            "invalid tuic udp_relay_mode: {udp_mode_name} (valid: native, quic)"
        ))?;
    let heartbeat_secs = first.get("heartbeat").and_then(|v| v.as_u64()).unwrap_or(3);
    let insecure = first.get("insecure").and_then(|v| v.as_bool()).unwrap_or(false);
    let certificate = first.get("certificate").and_then(|v| v.as_str()).map(String::from);
    if let Some(fp) = first.get("fingerprint").and_then(|v| v.as_str()) {
        tracing::warn!(fingerprint = %fp, "tuic fingerprint: rustls 无 uTLS 指纹模拟，忽略");
    }

    Ok(TuicOutboundSettings {
        server_addr,
        server_name,
        uuid,
        password: password.to_string(),
        congestion_control,
        alpn,
        reduce_rtt,
        udp_relay_mode,
        heartbeat: std::time::Duration::from_secs(heartbeat_secs),
        insecure,
        certificate,
    })
}

/// 构造 TUIC 用的 rustls ClientConfig（ring provider）。
///
/// 默认启用服务端证书验证（webpki 根 + 可选 `certificate` 附加 CA），
/// 对齐 Go `tls.Config{InsecureSkipVerify}` 语义——仅 `insecure=true` 显式跳过。
fn build_tuic_rustls_config(
    alpn: &[Vec<u8>],
    reduce_rtt: bool,
    insecure: bool,
    certificate: Option<&str>,
) -> std::result::Result<Arc<rustls::ClientConfig>, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut config = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
        };
        if let Some(pem) = certificate {
            let mut reader = std::io::BufReader::new(pem.as_bytes());
            let mut added = 0usize;
            for cert in rustls_pemfile::certs(&mut reader) {
                let cert = cert.map_err(|e| format!("tuic certificate PEM parse: {e}"))?;
                roots.add(cert).map_err(|e| format!("tuic certificate add: {e}"))?;
                added += 1;
            }
            if added == 0 {
                return Err("tuic certificate: no certificate found in PEM".to_string());
            }
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    // TUIC v5 要求 ALPN；用户未配置时用默认 [h3, tuic]
    config.alpn_protocols = if alpn.is_empty() {
        vec![b"h3".to_vec(), b"tuic".to_vec()]
    } else {
        alpn.to_vec()
    };
    // 官方 zero_rtt_handshake：quinn 的 QuicClientConfig::try_from 强制
    // enable_early_data=true，故此处只需控制会话恢复——true 启用恢复票据（复连自动 0-RTT），
    // false 显式禁用（对齐官方默认：不尝试 0-RTT）。
    config.resumption = if reduce_rtt {
        rustls::client::Resumption::in_memory_sessions(256)
    } else {
        rustls::client::Resumption::disabled()
    };
    Ok(Arc::new(config))
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
            target_strategy: None,
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
        register_outbounds(&built, &ohm, None, None).unwrap();

        assert!(ohm.get_default_handler().is_some(), "freedom should be default");
        assert!(ohm.get_handler("direct").is_some(), "freedom should be tagged");
    }

    #[test]
    fn register_multiple_outbounds_first_is_default() {
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("freedom", "proxy", "{}"));
        built.outbounds.push(make_outbound("freedom", "direct", "{}"));

        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None, None).unwrap();

        // 第一个设为 default，"direct" 也设为 default（覆盖）
        assert!(ohm.get_default_handler().is_some());
        assert!(ohm.get_handler("proxy").is_some());
        assert!(ohm.get_handler("direct").is_some());
    }

    /// bd 7zc：sendThrough → 拨号源 IP bind（Go xray.go:287 → handler.go:303 →
    /// dialer.go:228 → system_dialer.go:33 bind 链）。
    ///
    /// 绑 127.0.0.2（loopback /8 内非默认源，有区分度：未生效时 OS 默认源是
    /// 127.0.0.1），echo server accept 记录 peer 断言源 IP。
    #[tokio::test]
    async fn freedom_send_through_binds_source_ip() {
        use std::net::IpAddr;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use xray_app_dispatcher::default::{DefaultDispatcher, SniffingRequest};
        use xray_buf::io::Writer as _;
        use xray_buf::multi::MultiBuffer;
        use xray_common::net::address::Address;
        use xray_common::net::destination::Destination;
        use xray_common::net::network::Network;
        use xray_common::net::port::Port;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = listener.local_addr().unwrap().port();
        let peer_ip = std::sync::Arc::new(parking_lot::Mutex::new(None::<IpAddr>));
        let peer_recorder = std::sync::Arc::clone(&peer_ip);
        let accept_task = tokio::spawn(async move {
            let (mut sock, peer) = listener.accept().await.unwrap();
            *peer_recorder.lock() = Some(peer.ip());
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
        });

        // 2. freedom outbound + sendThrough=127.0.0.2
        let ob = BuiltOutbound {
            send_through: Some("127.0.0.2".to_string()),
            ..make_outbound("freedom", "via-test", "{}")
        };
        let (handler, _, _) =
            try_build_handler(&ob, None, &mut Vec::new(), None).expect("build freedom handler");

        // 3. dispatcher → dispatch → echo
        let ohm = SimpleOhm::new();
        ohm.set_default(handler);
        let mut d = DefaultDispatcher::new();
        d.ohm = Some(std::sync::Arc::new(ohm));

        let dest = Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(echo_port),
            Network::TCP,
        );
        let inbound = d
            .dispatch(&dest, &SniffingRequest::default(), None, None)
            .expect("dispatch returns inbound Link");

        let mut w = inbound.writer;
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(b"ping");
        w.write_multi_buffer(mb).await.unwrap();

        accept_task.await.unwrap();
        assert_eq!(
            *peer_ip.lock(),
            Some("127.0.0.2".parse().unwrap()),
            "连接源 IP 应为 sendThrough 指定的 127.0.0.2"
        );
    }


    /// bd 7zc：parse_send_through 对齐 Go xray.go:287-301 解析与校验。
    #[test]
    fn parse_send_through_forms() {
        use xray_transport::system_dialer::SendThroughSpec;

        assert_eq!(parse_send_through(&None).unwrap(), None);
        assert_eq!(
            parse_send_through(&Some("192.168.1.5".into())).unwrap(),
            Some(SendThroughSpec::Fixed("192.168.1.5".parse().unwrap()))
        );
        assert_eq!(
            parse_send_through(&Some("fd00::1".into())).unwrap(),
            Some(SendThroughSpec::Fixed("fd00::1".parse().unwrap()))
        );
        assert_eq!(
            parse_send_through(&Some("10.0.0.0/24".into())).unwrap(),
            Some(SendThroughSpec::Cidr {
                base: "10.0.0.0".parse().unwrap(),
                prefix: 24
            })
        );
        assert_eq!(
            parse_send_through(&Some("origin".into())).unwrap(),
            Some(SendThroughSpec::Origin)
        );
        assert_eq!(
            parse_send_through(&Some("srcip".into())).unwrap(),
            Some(SendThroughSpec::SrcIp)
        );
        // 非 origin/srcip 域名：构建失败（Go "unable to send through"）
        assert!(parse_send_through(&Some("example.com".into())).is_err());
        // 非法 IP
        assert!(parse_send_through(&Some("999.1.1.1".into())).is_err());
        // CIDR 前缀非法
        assert!(parse_send_through(&Some("10.0.0.0/xx".into())).is_err());
        assert!(parse_send_through(&Some("10.0.0.0/33".into())).is_err());
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
        register_outbounds(&built, &ohm, None, None).unwrap();

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
        register_outbounds(&built, &ohm, None, None).unwrap();

        assert!(ohm.get_handler("trojan-out").is_some(), "trojan should be registered");
    }

    #[test]
    fn register_dokodemo_parses_config() {
        let settings = r#"{ "address": "192.168.1.1", "port": 8080 }"#;
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("dokodemo", "dokodemo-out", settings));

        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None, None).unwrap();

        assert!(ohm.get_handler("dokodemo-out").is_some(), "dokodemo should be registered");
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
    #[test]
    fn register_tun_outbound() {
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("tun", "tun-out", "{}"));

        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None, None).unwrap();

        assert!(ohm.get_handler("tun-out").is_some(), "tun should be registered");
    }

    /// bd b8i 对称面：不支持平台（Windows/macOS 等）tun outbound 构建 →
    /// `BuildError::Unsupported` → register_outbounds warn+跳过（不硬错，
    /// handler 不注册；kind 本身仍全平台注册，见 register.rs 测试）。
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
    #[test]
    fn tun_outbound_skipped_on_unsupported_platform() {
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("tun", "tun-out", "{}"));

        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None, None).unwrap();

        assert!(
            ohm.get_handler("tun-out").is_none(),
            "tun outbound must be skipped (warn) on unsupported platforms"
        );
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
        register_outbounds(&built, &ohm, None, None).unwrap();

        assert!(
            ohm.get_handler("bad-vless").is_none(),
            "invalid uuid should skip"
        );
    }

    #[test]
    fn register_empty_outbounds_noop() {
        let built = BuiltConfig::default();
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None, None).unwrap();
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
            r#"{"network":"ws","security":"tls","wsSettings":{"path":"/ray"}}"#,
        )
        .unwrap();
        let s = parse_stream_settings(&Some(v)).unwrap();
        assert_eq!(s.protocol, "ws");
        assert!(s.is_tls());
    }

    /// TCP+无 TLS 但有 sockopt → 不折叠为 None（bd enk：dialerProxy 等
    /// sockopt 字段必须到达 dial_system）。
    #[test]
    fn parse_stream_settings_tcp_sockopt_keeps_some() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"sockopt": {"dialerProxy": "proxy-out"}}"#,
        )
        .unwrap();
        let s = parse_stream_settings(&Some(v)).expect("sockopt must keep Some");
        assert_eq!(s.socket_options().dialer_proxy, "proxy-out");
    }

    #[test]
    fn register_blackhole_parses_response() {
        // 默认 response（空 settings）→ None
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("blackhole", "bh", "{}"));
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None, None).unwrap();
        assert!(ohm.get_handler("bh").is_some(), "blackhole should register");
    }

    #[test]
    fn register_blackhole_http_response_type() {
        // ponytail: blackhole response.type=http 注册不报错即可（dispatch 行为已在 blackhole crate 测过）
        let settings = r#"{"response":{"type":"http"}}"#;
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("blackhole", "bh-http", settings));
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None, None).unwrap();
        assert!(ohm.get_handler("bh-http").is_some());
    }

    #[test]
    fn register_socks_outbound_parses_noauth() {
        let settings = r#"{"servers":[{"address":"1.2.3.4","port":1080}]}"#;
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("socks", "socks-out", settings));
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None, None).unwrap();
        assert!(ohm.get_handler("socks-out").is_some(), "socks outbound should register");
    }

    #[test]
    fn register_socks_outbound_parses_auth() {
        let settings = r#"{"servers":[{"address":"1.2.3.4","port":1080,"users":[{"user":"u","pass":"p"}]}]}"#;
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("socks", "socks-auth", settings));
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None, None).unwrap();
        assert!(ohm.get_handler("socks-auth").is_some());
    }

    #[test]
    fn register_mux_outbound_parses_concurrency() {
        let settings = r#"{"concurrency":16}"#;
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("mux", "mux-out", settings));
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None, None).unwrap();
        assert!(ohm.get_handler("mux-out").is_some(), "mux outbound should register");
    }

    #[test]
    fn register_mux_outbound_default_concurrency() {
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("mux", "mux-default", "{}"));
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None, None).unwrap();
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
        register_outbounds(&built, &ohm, None, None).unwrap();
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
        register_outbounds(&built, &ohm, None, None).unwrap();

        assert!(ohm.get_handler("proxy-out").is_some(), "proxy-out should be registered");
        assert!(ohm.get_handler("chain-out").is_some(), "chain-out should be registered");
    }

    // ===== TUIC outbound 配置解析 + TLS 验证（bd 7p0） =====

    const TUIC_TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn tuic_json(extra: &str) -> String {
        format!(
            r#"{{"servers":[{{"address":"127.0.0.1","port":8443,"uuid":"{TUIC_TEST_UUID}","password":"pw"{extra}}}]}}"#
        )
    }

    /// 官方默认值（Itsusinn/tuic config.rs）：bbr / native / 3s / zero_rtt=false / 验证开启。
    #[test]
    fn parse_tuic_config_defaults_official() {
        let s = parse_tuic_config(tuic_json("").as_bytes()).unwrap();
        assert_eq!(s.congestion_control, xray_proxy_tuic::CongestionControl::Bbr);
        assert_eq!(s.udp_relay_mode, xray_proxy_tuic::UdpRelayMode::Native);
        assert_eq!(s.heartbeat, std::time::Duration::from_secs(3));
        assert!(!s.reduce_rtt);
        assert!(!s.insecure);
        assert!(s.certificate.is_none());
        assert!(s.alpn.is_empty());
        assert_eq!(s.server_name, "127.0.0.1");
    }

    #[test]
    fn parse_tuic_config_all_fields() {
        let json = tuic_json(
            r#","congestion_control":"cubic","alpn":["h3"],"reduce_rtt":true,"udp_relay_mode":"quic","heartbeat":10,"insecure":true,"certificate":"-----BEGIN CERTIFICATE-----""#,
        );
        let s = parse_tuic_config(json.as_bytes()).unwrap();
        assert_eq!(s.congestion_control, xray_proxy_tuic::CongestionControl::Cubic);
        assert_eq!(s.alpn, vec![b"h3".to_vec()]);
        assert!(s.reduce_rtt);
        assert_eq!(s.udp_relay_mode, xray_proxy_tuic::UdpRelayMode::Quic);
        assert_eq!(s.heartbeat, std::time::Duration::from_secs(10));
        assert!(s.insecure);
        assert_eq!(s.certificate.as_deref(), Some("-----BEGIN CERTIFICATE-----"));
    }

    /// 官方字段名 zero_rtt_handshake 作为 reduce_rtt 的别名。
    #[test]
    fn parse_tuic_config_zero_rtt_handshake_alias() {
        let json = tuic_json(r#","zero_rtt_handshake":true"#);
        assert!(parse_tuic_config(json.as_bytes()).unwrap().reduce_rtt);
    }

    #[test]
    fn parse_tuic_config_invalid_values_rejected() {
        assert!(parse_tuic_config(tuic_json(r#","udp_relay_mode":"udp""#).as_bytes()).is_err());
        assert!(parse_tuic_config(tuic_json(r#","congestion_control":"bbrv3""#).as_bytes()).is_err());
    }

    /// fingerprint（uTLS 指纹）rustls 不支持——解析不报错，仅告警忽略。
    #[test]
    fn parse_tuic_config_fingerprint_ignored() {
        let json = tuic_json(r#","fingerprint":"chrome""#);
        assert!(parse_tuic_config(json.as_bytes()).is_ok());
    }

    #[test]
    fn build_tuic_rustls_config_alpn_default_and_custom() {
        let c = build_tuic_rustls_config(&[], false, false, None).unwrap();
        assert_eq!(c.alpn_protocols, vec![b"h3".to_vec(), b"tuic".to_vec()]);
        let c = build_tuic_rustls_config(&[b"h3".to_vec()], false, false, None).unwrap();
        assert_eq!(c.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[test]
    fn build_tuic_rustls_config_bad_certificate_rejected() {
        assert!(build_tuic_rustls_config(&[], false, false, Some("not a pem")).is_err());
    }

    /// DER → PEM（e2e 测试用）。
    fn der_to_pem(der: &[u8]) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem
    }

    /// 起一个 mock TUIC server，返回 (addr, cert_der)。
    async fn start_tuic_mock() -> (std::net::SocketAddr, Vec<u8>) {
        let uuid = uuid::Uuid::parse_str(TUIC_TEST_UUID).unwrap();
        let (server, cert_der) = xray_proxy_tuic::TuicMockServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            "localhost",
            uuid,
            "pw".to_string(),
        )
        .await
        .expect("mock bind");
        let addr = server.local_addr();
        tokio::spawn(async move { let _ = server.run().await; });
        (addr, cert_der)
    }

    /// e2e：默认（验证开启，无自签 CA）→ 自签证书被拒（~30s 后浮现 TLS 错误）。
    #[tokio::test]
    async fn tuic_default_tls_rejects_self_signed() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (addr, _cert) = start_tuic_mock().await;
        let cfg = build_tuic_rustls_config(&[], false, false, None).unwrap();
        let uuid = uuid::Uuid::parse_str(TUIC_TEST_UUID).unwrap();
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(45),
            xray_proxy_tuic::TuicClient::connect(
                addr,
                "localhost",
                uuid,
                "pw",
                cfg,
                xray_proxy_tuic::QuinnConnectionPool::new(),
            ),
        )
        .await
        .expect("connect timed out");
        assert!(res.is_err(), "default (verifying) TLS must reject self-signed cert");
    }

    /// e2e：certificate 指定服务端自签证书 → 验证通过连接成功。
    #[tokio::test]
    async fn tuic_certificate_pinned_tls_accepts_self_signed() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (addr, cert_der) = start_tuic_mock().await;
        let pem = der_to_pem(&cert_der);
        let cfg = build_tuic_rustls_config(&[], false, false, Some(&pem)).unwrap();
        let uuid = uuid::Uuid::parse_str(TUIC_TEST_UUID).unwrap();
        let client = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            xray_proxy_tuic::TuicClient::connect(
                addr,
                "localhost",
                uuid,
                "pw",
                cfg,
                xray_proxy_tuic::QuinnConnectionPool::new(),
            ),
        )
        .await
        .expect("connect timed out")
        .expect("connect failed");
        client.close(0u32.into(), b"");
    }

    /// e2e：insecure=true 显式跳过验证 → 自签证书放行。
    #[tokio::test]
    async fn tuic_insecure_tls_accepts_self_signed() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (addr, _cert) = start_tuic_mock().await;
        let cfg = build_tuic_rustls_config(&[], false, true, None).unwrap();
        let uuid = uuid::Uuid::parse_str(TUIC_TEST_UUID).unwrap();
        let client = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            xray_proxy_tuic::TuicClient::connect(
                addr,
                "localhost",
                uuid,
                "pw",
                cfg,
                xray_proxy_tuic::QuinnConnectionPool::new(),
            ),
        )
        .await
        .expect("connect timed out")
        .expect("connect failed");
        client.close(0u32.into(), b"");
    }

    // ========== targetStrategy（bd bqm）==========

    use std::sync::Mutex;
    use xray_app_dispatcher::default::DialFn;
    use xray_common::net::address::Address;
    use xray_common::net::destination::Destination;
    use xray_common::net::network::Network;
    use xray_common::net::port::Port;

    /// 记录 dest 的 fake dial_fn，返回 duplex 连接（不断链）。
    fn recording_dial(recorded: Arc<Mutex<Vec<Destination>>>) -> DialFn {
        Arc::new(move |dest: &Destination| {
            let dest = dest.clone();
            let recorded = Arc::clone(&recorded);
            Box::pin(async move {
                recorded.lock().expect("lock").push(dest);
                let (client, _server) = tokio::io::duplex(4096);
                Ok(Box::new(xray_transport::connection::DuplexConnection::new(client))
                    as Box<dyn xray_transport::connection::Connection>)
            })
        })
    }

    /// 构造带静态 hosts 的 DnsService（hosts：resolve-test.invalid → 127.0.0.1）。
    fn hosts_dns_service() -> Arc<xray_app_dns::DnsService> {
        let cfg: xray_app_dns::DnsAppConfig = serde_json::from_str(
            r#"{"hosts": {"resolve-test.invalid": "127.0.0.1"}}"#,
        )
        .expect("dns config json");
        let svc = cfg.build().expect("dns config build");
        Arc::new(xray_app_dns::DnsService::new(svc))
    }

    fn domain_dest(domain: &str) -> Destination {
        Destination::new(
            Address::Domain(domain.to_string()),
            Port::new(443),
            Network::TCP,
        )
    }

    #[test]
    fn parse_target_strategy_maps_go_enum_values() {
        use xray_proxy_freedom::DomainStrategy;
        // Go infra/conf/xray.go:257-282（ToLower switch）11 值 + 大小写不敏感。
        assert_eq!(parse_target_strategy("AsIs"), Some(DomainStrategy::AsIs));
        assert_eq!(parse_target_strategy("asis"), Some(DomainStrategy::AsIs));
        assert_eq!(parse_target_strategy(""), Some(DomainStrategy::AsIs));
        assert_eq!(parse_target_strategy("UseIP"), Some(DomainStrategy::UseIP));
        assert_eq!(parse_target_strategy("useipv4"), Some(DomainStrategy::UseIPv4));
        assert_eq!(parse_target_strategy("UseIPv6"), Some(DomainStrategy::UseIPv6));
        assert_eq!(parse_target_strategy("useipv4v6"), Some(DomainStrategy::UseIPv4v6));
        assert_eq!(parse_target_strategy("useipv6v4"), Some(DomainStrategy::UseIPv6v4));
        assert_eq!(parse_target_strategy("ForceIP"), Some(DomainStrategy::ForceIP));
        assert_eq!(parse_target_strategy("forceipv4"), Some(DomainStrategy::ForceIPv4));
        assert_eq!(parse_target_strategy("ForceIPv6"), Some(DomainStrategy::ForceIPv6));
        assert_eq!(parse_target_strategy("forceipv4v6"), Some(DomainStrategy::ForceIPv4v6));
        assert_eq!(parse_target_strategy("forceipv6v4"), Some(DomainStrategy::ForceIPv6v4));
        assert_eq!(parse_target_strategy("Nonsense"), None);
    }

    /// UseIP：域名 dest 在拨号前被解析改写为 IP（Go handler.go:200-202）。
    #[tokio::test]
    async fn target_strategy_useip_resolves_domain_before_dial() {
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let dial = wrap_dial_with_target_strategy(
            recording_dial(Arc::clone(&recorded)),
            xray_proxy_freedom::DomainStrategy::UseIP,
            Some(hosts_dns_service()),
        );
        dial(&domain_dest("resolve-test.invalid")).await.expect("dial ok");
        let got = recorded.lock().expect("lock").pop().expect("dial called");
        assert_eq!(
            got.address(),
            &Address::from(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            "domain target should be rewritten to resolved IP"
        );
    }

    /// IP dest 透传不查 DNS（Go handler.go:184 `Family().IsDomain()` 门控）。
    #[tokio::test]
    async fn target_strategy_skips_resolution_for_ip_dest() {
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let dial = wrap_dial_with_target_strategy(
            recording_dial(Arc::clone(&recorded)),
            xray_proxy_freedom::DomainStrategy::ForceIP,
            None, // 无 DNS：若误查 DNS 则 ForceIP 必报错
        );
        dial(&Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(443),
            Network::TCP,
        ))
        .await
        .expect("ip dest dials without DNS");
        assert_eq!(recorded.lock().expect("lock").len(), 1);
    }

    /// UseIP 解析失败回退域名直连（Go handler.go:190-199 非 Force 分支）。
    #[tokio::test]
    async fn target_strategy_useip_falls_back_to_domain_without_dns() {
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let dial = wrap_dial_with_target_strategy(
            recording_dial(Arc::clone(&recorded)),
            xray_proxy_freedom::DomainStrategy::UseIP,
            None,
        );
        dial(&domain_dest("resolve-test.invalid")).await.expect("dial ok");
        let got = recorded.lock().expect("lock").pop().expect("dial called");
        assert_eq!(got.address(), &Address::Domain("resolve-test.invalid".into()));
    }

    /// ForceIP 解析失败直接断链（Go handler.go:192-197 Interrupt 分支）。
    #[tokio::test]
    async fn target_strategy_forceip_fails_without_dns() {
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let dial = wrap_dial_with_target_strategy(
            recording_dial(Arc::clone(&recorded)),
            xray_proxy_freedom::DomainStrategy::ForceIP,
            None,
        );
        let err = match dial(&domain_dest("resolve-test.invalid")).await {
            Err(e) => e,
            Ok(_) => panic!("ForceIP must fail when DNS unavailable"),
        };
        assert!(err.contains("resolve-test.invalid"), "error mentions domain: {err}");
        assert!(recorded.lock().expect("lock").is_empty(), "inner dial must not run");
    }

    /// e2e：JSON `targetStrategy: "UseIP"` → BuiltConfig → register_outbounds →
    /// dispatch 域名 dest → hosts 解析 → freedom 拨号 → echo 回显。
    /// 对照组（无 targetStrategy）：OS 无法解析 `.invalid` 域名 → 无回显。
    #[tokio::test]
    async fn target_strategy_end_to_end_json_to_echo() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use xray_buf::io::Reader as _;
        use xray_buf::io::Writer as _;
        use xray_buf::multi::MultiBuffer;

        // echo server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = sock.write_all(&buf[..n]).await;
                    }
                }
            }
        });

        let json = format!(
            r#"{{"outbounds": [{{"protocol": "freedom", "tag": "out", "targetStrategy": "UseIP"}}]}}"#
        );
        let cfg = xray_conf::Config::from_json_str(&json).unwrap();
        let built = cfg.build().unwrap();

        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm, None, Some(hosts_dns_service())).unwrap();
        let handler = ohm.get_handler("out").expect("outbound registered");

        // inbound 侧 link：pipe 双向
        let (up_r, mut up_w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let (mut dn_r, dn_w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let link = xray_transport::link::Link::new(
            Box::new(up_r) as Box<dyn xray_buf::io::Reader>,
            Box::new(dn_w) as Box<dyn xray_buf::io::Writer>,
        );
        let dest = Destination::new(
            Address::Domain("resolve-test.invalid".into()),
            Port::new(echo_port),
            Network::TCP,
        );
        let fut = handler.dispatch(&dest, link);
        tokio::spawn(async move {
            let _ = fut.await;
        });

        // 写上行 → dispatch → UseIP 解析 → 127.0.0.1:echo_port → echo → 读下行
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(b"target-strategy-e2e");
        up_w.write_multi_buffer(mb).await.unwrap();
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), dn_r.read_multi_buffer())
            .await
            .expect("echo should come back via resolved IP")
            .unwrap();
        assert_eq!(resp.to_vec(), b"target-strategy-e2e");

        // 对照组：无 targetStrategy → 域名直连 OS 解析失败（.invalid RFC 6761）→ 无回显
        let plain = xray_conf::Config::from_json_str(
            r#"{"outbounds": [{"protocol": "freedom", "tag": "plain"}]}"#,
        )
        .unwrap()
        .build()
        .unwrap();
        let ohm2 = SimpleOhm::new();
        register_outbounds(&plain, &ohm2, None, Some(hosts_dns_service())).unwrap();
        let h2 = ohm2.get_handler("plain").unwrap();
        let (up_r2, mut up_w2) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let (mut dn_r2, dn_w2) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let link2 = xray_transport::link::Link::new(
            Box::new(up_r2) as Box<dyn xray_buf::io::Reader>,
            Box::new(dn_w2) as Box<dyn xray_buf::io::Writer>,
        );
        let dest2 = Destination::new(
            Address::Domain("resolve-test.invalid".into()),
            Port::new(echo_port),
            Network::TCP,
        );
        let fut2 = h2.dispatch(&dest2, link2);
        tokio::spawn(async move {
            let _ = fut2.await;
        });
        let mut mb2 = MultiBuffer::new();
        mb2.merge_bytes(b"should-not-echo");
        up_w2.write_multi_buffer(mb2).await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(3), dn_r2.read_multi_buffer())
                .await
                .is_err(),
            "AsIs (no strategy) must not resolve domain via DNS service"
        );
    }

    // ===== DialerProxy（bd enk）=====

    /// echo server：原样回显。返回端口。
    async fn spawn_echo() -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { break };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        port
    }

    /// 手工 socks5 服务器：no-auth 握手 + 记录 CONNECT 目标 + 双向桥接。
    /// 记录是「经代理而非直连」的判别器。返回 (端口, 记录)。
    async fn spawn_socks5_recorder() -> (
        u16,
        Arc<Mutex<Vec<(std::net::IpAddr, u16)>>>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let recorded: Arc<Mutex<Vec<(std::net::IpAddr, u16)>>> =
            Arc::new(Mutex::new(Vec::new()));
        let rec = Arc::clone(&recorded);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { break };
                let rec = Arc::clone(&rec);
                tokio::spawn(async move {
                    // 生产版握手（与 SocksClient 交互已验证）→ 记录 CONNECT 目标 → 桥接。
                    // 目标可能是 Domain（协议层不解析，由 socks server 端解析）——
                    // 与真 socks server 行为一致：lookup_host 解析后拨号。
                    let req = xray_proxy_socks::socks5_server_handshake(
                        &mut sock,
                        &xray_proxy_socks::ServerConfig::default(),
                    )
                    .await;
                    let Ok(xray_proxy_socks::server::SocksRequest::TcpConnect(addr)) = req else {
                        return;
                    };
                    let target_addr = match &addr.host {
                        xray_proxy_socks::Host::Domain(d) => tokio::net::lookup_host(format!("{d}:{}", addr.port))
                            .await
                            .ok()
                            .and_then(|mut i| i.next()),
                        h => h.to_socket_addr(addr.port),
                    };
                    let Some(target_addr) = target_addr else {
                        return;
                    };
                    rec.lock().expect("lock").push((target_addr.ip(), target_addr.port()));
                    let Ok(mut target) = tokio::net::TcpStream::connect(target_addr).await
                    else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut sock, &mut target).await;
                });
            }
        });
        (port, recorded)
    }

    /// e2e（bd enk）：transport 层代理——trojan-out 的底层 TCP 拨号经 socks-out
    /// outbound 而非直连（Go dialer.go:270-279 redirect 语义）。
    /// 两阶段：① `sockopt.dialerProxy` 直配 ② `proxySettings.transportLayer`
    /// 配置注入（Go xray.go:316-327）。断言：socks5 服务器记录到
    /// CONNECT = trojan 服务器地址（echo 端口），且 payload 经全链路回显。
    /// 两阶段必须串行（全局钩子，最后注册生效）。
    #[tokio::test]
    async fn dialer_proxy_routes_transport_dial_via_socks_outbound() {
        use xray_buf::multi::MultiBuffer;

        for use_transport_layer in [false, true] {
            let echo_port = spawn_echo().await;
            let (socks_port, recorded) = spawn_socks5_recorder().await;

            let (stream_json, proxy_json) = if use_transport_layer {
                (
                    String::new(),
                    r#", "proxySettings": {"tag": "socks-out", "transportLayer": true }"#.to_string(),
                )
            } else {
                (
                    r#", "streamSettings": {"sockopt": {"dialerProxy": "socks-out"}}"#.to_string(),
                    String::new(),
                )
            };
            let json = format!(
                r#"{{"outbounds": [
                    {{"protocol": "trojan", "tag": "trojan-out",
                      "settings": {{"servers": [{{"address": "127.0.0.1", "port": {echo_port}, "password": "test-pass-12345"}}]}}{stream_json}{proxy_json}}},
                    {{"protocol": "socks", "tag": "socks-out",
                      "settings": {{"servers": [{{"address": "127.0.0.1", "port": {socks_port}}}]}}}}
                ]}}"#
            );
            let cfg = xray_conf::Config::from_json_str(&json).unwrap();
            let built = cfg.build().unwrap();

            let ohm = SimpleOhm::new();
            register_outbounds(&built, &ohm, None, None).unwrap();
            let handler = ohm.get_handler("trojan-out").expect("trojan-out registered");

            let (up_r, mut up_w) =
                xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
            let (mut dn_r, dn_w) =
                xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
            let link = xray_transport::link::Link::new(
                Box::new(up_r) as Box<dyn xray_buf::io::Reader>,
                Box::new(dn_w) as Box<dyn xray_buf::io::Writer>,
            );
            // 最终目标（进入 trojan 头，socks 层不可见——socks 只见 trojan 服务器地址）
            let dest = Destination::new(
                Address::from_ipv4_bytes([127, 0, 0, 1]),
                Port::new(80),
                Network::TCP,
            );
            let fut = handler.dispatch(&dest, link);
            tokio::spawn(async move {
                let _ = fut.await;
            });

            let payload = b"dialer-proxy-e2e";
            let mut mb = MultiBuffer::new();
            mb.merge_bytes(payload);
            up_w.write_multi_buffer(mb).await.unwrap();

            // 读回显：echo 会把 trojan 头 + payload 原样反射回来
            let mut acc: Vec<u8> = Vec::new();
            let echoed = loop {
                if acc.windows(payload.len()).any(|w| w == payload) {
                    break true;
                }
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    dn_r.read_multi_buffer(),
                )
                .await
                {
                    Ok(Ok(chunk)) => acc.extend_from_slice(&chunk.to_vec()),
                    _ => break false,
                }
            };
            assert!(
                echoed,
                "transportLayer={use_transport_layer}: payload should echo via proxy chain"
            );

            // 「经代理而非直连」判别：socks5 服务器必须见到 CONNECT → echo 端口
            let rec = recorded.lock().expect("lock");
            assert!(
                rec.iter().any(|(_, p)| *p == echo_port),
                "transportLayer={use_transport_layer}: socks outbound should see CONNECT to echo:{echo_port}, got {rec:?}"
            );
        }
    }

    // ========== DnsDispatchBridge e2e（bd 8hl） ==========

    /// 构造最小 DNS 查询（Header + Question）。
    fn dns_make_query(id: u16, domain: &str, q_type: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        buf.extend_from_slice(&[0; 6]); // AN/NS/AR
        for label in domain.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf.extend_from_slice(&q_type.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // IN
        buf
    }

    /// mock UDP DNS server：记录收到的原始 query，回固定响应。
    async fn spawn_dns_udp_mock(
        response: Vec<u8>,
        captured: Arc<parking_lot::Mutex<Option<Vec<u8>>>>,
    ) -> std::net::SocketAddr {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            if let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                *captured.lock() = Some(buf[..n].to_vec());
                let _ = sock.send_to(&response, peer).await;
            }
        });
        addr
    }

    /// DnsService（含 fakedns client）——Hijack 动作 e2e 用。
    fn make_fakedns_service(client_tag: &str) -> Arc<xray_app_dns::server::DnsService> {
        use xray_app_dns::fakedns::Holder;
        use xray_app_dns::nameserver::fakedns::FakeDnsServer;
        use xray_app_dns::nameserver::{Client, NameServerConfig, Server};

        let ns = NameServerConfig {
            tag: client_tag.to_string(),
            ..Default::default()
        };
        let fake: Box<dyn Server> =
            Box::new(FakeDnsServer::new(Holder::new_default().unwrap()));
        let client = Client::new(ns, xray_app_dns::config::IpOption::all(), fake).unwrap();
        Arc::new(xray_app_dns::server::DnsService::new(
            xray_app_dns::server::DnsServiceConfig {
                client_ip: Vec::new(),
                query_strategy: xray_app_dns::config::QueryStrategy::UseIp,
                tag: "test-dns".into(),
                hosts: xray_app_dns::hosts::StaticHosts::new(Vec::new()).unwrap(),
                clients: vec![Arc::new(client)],
                disable_fallback: false,
                disable_fallback_if_match: false,
                enable_parallel_query: false,
                disable_cache: false,
                serve_stale: false,
                serve_expired_ttl: 0,
                use_system_hosts: false,
                domain_matcher: None,
                matcher_infos: Vec::new(),
            },
        ))
    }

    /// dispatch bridge 并返回 (up_writer, dn_reader)。
    fn spawn_dns_bridge(
        bridge: &DnsDispatchBridge,
        dest: &Destination,
        access: Option<xray_app_dispatcher::default::AccessContext>,
    ) -> (
        Box<dyn xray_buf::io::Writer>,
        Box<dyn xray_buf::io::Reader>,
    ) {
        let (up_r, up_w) = xray_buf::pipe::new();
        let (dn_r, dn_w) = xray_buf::pipe::new();
        let link = Link::new(
            Box::new(up_r) as Box<dyn xray_buf::io::Reader>,
            Box::new(dn_w) as Box<dyn xray_buf::io::Writer>,
        );
        match access {
            Some(ctx) => {
                let fut = bridge.dispatch_with_access(dest, link, ctx);
                tokio::spawn(async move {
                    let _ = fut.await;
                });
            }
            None => {
                let fut = bridge.dispatch(dest, link);
                tokio::spawn(async move {
                    let _ = fut.await;
                });
            }
        }
        (
            Box::new(up_w) as Box<dyn xray_buf::io::Writer>,
            Box::new(dn_r) as Box<dyn xray_buf::io::Reader>,
        )
    }

    /// e2e：UDP Direct 规则 → 原样 query 转发到上游 → 响应回客户端。
    #[tokio::test]
    async fn dns_udp_direct_forwards_raw_roundtrip() {
        use xray_buf::io::{Reader as _, Writer as _};
        use xray_buf::multi::MultiBuffer;

        let upstream_resp = dns_make_query(0x7777, "example.com", 1); // 原样回显即可
        let captured: Arc<parking_lot::Mutex<Option<Vec<u8>>>> =
            Arc::new(parking_lot::Mutex::new(None));
        let addr =
            spawn_dns_udp_mock(upstream_resp.clone(), captured.clone()).await;

        // Direct 规则（qType A）。
        let handler =
            parse_dns_outbound_config(br#"{"rule":[{"action":"direct","qType":[1]}]}"#)
                .unwrap();
        let bridge = DnsDispatchBridge::new("dns-out", handler, None);
        let dest = Destination::udp(Address::from_ipv4_bytes([127, 0, 0, 1]), Port::new(addr.port()));
        let (mut up_w, mut dn_r) = spawn_dns_bridge(&bridge, &dest, None);

        let query = dns_make_query(0x1234, "example.com", 1);
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&query);
        up_w.write_multi_buffer(mb).await.unwrap();

        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), dn_r.read_multi_buffer())
            .await
            .expect("timeout waiting response")
            .unwrap();
        assert_eq!(resp.to_vec(), upstream_resp);
        // 上游收到原样 query（未重新编码）。
        assert_eq!(captured.lock().clone(), Some(query));
    }

    /// e2e：默认（无规则）A 查询 → Hijack → DnsService(fakedns) → fake IP 响应。
    #[tokio::test]
    async fn dns_udp_default_a_hijacks_via_fakedns() {
        use xray_buf::io::{Reader as _, Writer as _};
        use xray_buf::multi::MultiBuffer;

        let svc = make_fakedns_service("fake-in");
        let handler = parse_dns_outbound_config(b"{}").unwrap();
        let bridge = DnsDispatchBridge::new("dns-out", handler, Some(svc));
        // dest 无所谓（Hijack 不转发）。
        let dest = Destination::udp(Address::from_ipv4_bytes([127, 0, 0, 1]), Port::new(53));
        let (mut up_w, mut dn_r) = spawn_dns_bridge(&bridge, &dest, None);

        let query = dns_make_query(0x4242, "fakedns.example.com", 1); // A
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&query);
        up_w.write_multi_buffer(mb).await.unwrap();

        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), dn_r.read_multi_buffer())
            .await
            .expect("timeout waiting hijack response")
            .unwrap();
        let resp = resp.to_vec();
        // Header：id 回显 + QR=1。
        assert_eq!(&resp[0..2], &0x4242u16.to_be_bytes());
        assert_eq!(resp[2] & 0x80, 0x80, "response bit");
        assert_eq!(resp[3] & 0x0F, 0, "rcode 0");
        // ANCOUNT=1（fake IP 一条）。
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
    }

    /// e2e：ownLink（inbound tag = nameserver client tag）→ 原样转发不劫持。
    #[tokio::test]
    async fn dns_udp_own_link_bypasses_rules() {
        use xray_buf::io::{Reader as _, Writer as _};
        use xray_buf::multi::MultiBuffer;

        let upstream_resp = dns_make_query(0x9999, "upstream.com", 1);
        let captured: Arc<parking_lot::Mutex<Option<Vec<u8>>>> =
            Arc::new(parking_lot::Mutex::new(None));
        let addr =
            spawn_dns_udp_mock(upstream_resp.clone(), captured.clone()).await;

        // 无规则（A 默认 Hijack）+ DnsService 带 client tag "self-loop"。
        let svc = make_fakedns_service("self-loop");
        let handler = parse_dns_outbound_config(b"{}").unwrap();
        let bridge = DnsDispatchBridge::new("dns-out", handler, Some(svc));
        let dest = Destination::udp(Address::from_ipv4_bytes([127, 0, 0, 1]), Port::new(addr.port()));

        let mut access = xray_app_dispatcher::default::AccessContext::default();
        access.inbound_tag = "self-loop".into();
        let (mut up_w, mut dn_r) = spawn_dns_bridge(&bridge, &dest, Some(access));

        let query = dns_make_query(0x5678, "raw.example.com", 1);
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&query);
        up_w.write_multi_buffer(mb).await.unwrap();

        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), dn_r.read_multi_buffer())
            .await
            .expect("timeout waiting own-link response")
            .unwrap();
        // 响应来自 mock（非 fakedns），上游收到原样 query。
        assert_eq!(resp.to_vec(), upstream_resp);
        assert_eq!(captured.lock().clone(), Some(query));
    }

    /// e2e：Return 规则 + rCode 5 + TXT 查询 → REFUSED 响应（Go rejectNonIPQuery）。
    #[tokio::test]
    async fn dns_udp_return_rule_responds_rcode() {
        use xray_buf::io::{Reader as _, Writer as _};
        use xray_buf::multi::MultiBuffer;

        let handler = parse_dns_outbound_config(
            br#"{"rule":[{"action":"return","qType":[16],"rCode":5}]}"#,
        )
        .unwrap();
        let bridge = DnsDispatchBridge::new("dns-out", handler, None);
        let dest = Destination::udp(Address::from_ipv4_bytes([127, 0, 0, 1]), Port::new(53));
        let (mut up_w, mut dn_r) = spawn_dns_bridge(&bridge, &dest, None);

        let query = dns_make_query(0x3141, "txt.example.com", 16); // TXT
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&query);
        up_w.write_multi_buffer(mb).await.unwrap();

        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), dn_r.read_multi_buffer())
            .await
            .expect("timeout waiting reject response")
            .unwrap();
        let resp = resp.to_vec();
        assert_eq!(&resp[0..2], &0x3141u16.to_be_bytes());
        assert_eq!(resp[2] & 0x80, 0x80, "response bit");
        assert_eq!(resp[3] & 0x0F, 5, "rcode REFUSED");
    }

    /// e2e：TCP 双路 loop——Direct 规则经 TCP 上游多查询 pipeline 往返。
    #[tokio::test]
    async fn dns_tcp_direct_dual_loop_pipeline() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use xray_buf::io::{Reader as _, Writer as _};
        use xray_buf::multi::MultiBuffer;

        // mock TCP DNS server：帧循环回显（改 id 尾字节区分）。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut pending = Vec::new();
            loop {
                let n = match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                pending.extend_from_slice(&buf[..n]);
                // 解帧回显。
                while pending.len() >= 2 {
                    let len = u16::from_be_bytes([pending[0], pending[1]]) as usize;
                    if pending.len() < 2 + len {
                        break;
                    }
                    let mut frame = pending[2..2 + len].to_vec();
                    // 标记响应位，证明来自 mock 而非客户端反射。
                    frame[2] |= 0x80;
                    sock.write_all(&(frame.len() as u16).to_be_bytes()).await.unwrap();
                    sock.write_all(&frame).await.unwrap();
                    pending.drain(..2 + len);
                }
            }
        });

        let handler =
            parse_dns_outbound_config(br#"{"rule":[{"action":"direct","qType":[1]}]}"#)
                .unwrap();
        let bridge = DnsDispatchBridge::new("dns-out", handler, None);
        let dest = Destination::tcp(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(upstream_port),
        );
        let (mut up_w, mut dn_r) = spawn_dns_bridge(&bridge, &dest, None);

        // 连发两帧（pipeline，不等第一响应）。
        let q1 = dns_make_query(0x1111, "first.example.com", 1);
        let q2 = dns_make_query(0x2222, "second.example.com", 1);
        let mut all = Vec::new();
        for q in [&q1, &q2] {
            let framed = xray_proxy_dns::encode_tcp_dns_message(q).unwrap();
            all.extend_from_slice(&framed);
        }
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&all);
        up_w.write_multi_buffer(mb).await.unwrap();
        // 不 shutdown——shutdown 触发 request loop EOF 退出（Go task.Run 同语义），
        // 真实 TCP DNS 客户端等响应期间保持连接不关写侧。

        // 读回两帧响应。
        let mut acc = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while acc.len() < q1.len() + q2.len() + 4 && std::time::Instant::now() < deadline {
            match tokio::time::timeout(
                std::time::Duration::from_millis(1500),
                dn_r.read_multi_buffer(),
            )
            .await
            {
                Ok(Ok(chunk)) => acc.extend_from_slice(&chunk.to_vec()),
                _ => break,
            }
        }
        assert!(
            acc.len() >= q1.len() + q2.len() + 4,
            "two framed responses expected, got {} bytes: {:02x?}",
            acc.len(),
            acc
        );
        // 首帧 id 回显 + QR 位（来自 mock）。
        let l1 = u16::from_be_bytes([acc[0], acc[1]]) as usize;
        assert_eq!(&acc[2..4], &0x1111u16.to_be_bytes());
        assert_eq!(acc[4] & 0x80, 0x80, "QR from mock");
        let off = 2 + l1;
        let l2 = u16::from_be_bytes([acc[off], acc[off + 1]]) as usize;
        assert_eq!(&acc[off + 2..off + 4], &0x2222u16.to_be_bytes());
        assert_eq!(l1, q1.len(), "frame1 length");
        assert_eq!(l2, q2.len(), "frame2 length");
    }
}

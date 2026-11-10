//! inbound 协议臂构造函数（T4.2 phase 1 抽臂）。
//!
//! 每个 [`crate::inbound::spawn_one_inbound`] match 臂的构造逻辑原样搬迁至此。
//! UDS 形态（T4.2 W2 / bd 7y07s）同样在此：`UnixInboundCtx`/`UnixTransportCtx`
//! 两类 ctx + 每协议一个构造器，由 [`crate::arm_builders::INBOUND_CTORS`] 的
//! `uds_stream`/`uds_transport` 槽登记——「协议 → 可构造监听形态」单源，入口不再
//! 有内联 match 或手写白名单。

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use skeleton_infra::fx::FxScope;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use xray_app_dispatcher::{OutboundHandlerManager, default::SimpleOhm};
use xray_common::net::network::Network;
use xray_conf::BuiltInbound;
// InboundHandler trait：anytls/naive/tuic/wireguard/hysteria/blackhole/freedom
// 构造函数尾部的 `.start()` 方法来源（与拆分前 spawn_one_inbound 同一 trait 面）。
use xray_features::inbound::InboundHandler as _;
use xray_proxy_blackhole::BlackholeInboundHandler;
use xray_proxy_dns::DnsInbound;
use xray_proxy_freedom::FreedomInboundHandler;
use xray_proxy_loopback::LoopbackHandler;
use xray_proxy_trojan::serve_trojan;
use xray_proxy_vless::{Validator as VlessValidator, VlessInboundOptions, serve_vless};
use xray_proxy_vmess::serve_vmess;
// Connection trait：UDS 臂的 per-conn 闭包要调 `conn.remote_addr()`（trait 方法）。
use xray_transport::{connection::Connection as _, system_listener::InboundTcpListener};

use crate::{
    inbound::{
        DokodemoTcpOptions, HysteriaTcpDispatch, InboundRuntime, PeekAhead, SsInboundMode,
        bind_ss_udp, build_tls_acceptor, build_trojan_fallbacks, build_trojan_users,
        build_trojan_validator_shared, build_vless_decryption, build_vless_fallbacks,
        build_vless_validator, build_vmess_validator, handshake_timeout_for, inbound_tcpmask,
        inbound_udpmask, is_transport_listener_protocol, parse_anytls_tls_acceptor,
        parse_blackhole_inbound_response, parse_dns_inbound_config, parse_dokodemo_settings,
        parse_freedom_inbound_dest, parse_http_config, parse_hysteria_inbound_config,
        parse_loopback_config, parse_naive_inbound_settings, parse_reality_config,
        parse_socks_http_configs, parse_socks_server_config, parse_ss_inbound_config,
        parse_tuic_inbound_config, parse_wireguard_inbound_config, register_hysteria_user_manager,
        register_ss_user_manager, register_trojan_user_manager, register_vless_user_manager,
        register_vmess_user_manager, register_wg_user_manager, serve_dns, serve_dokodemo,
        serve_dokodemo_udp_on, serve_http, serve_mixed, serve_mixed_conn, serve_reality_trojan,
        serve_reality_vless, serve_ss, serve_unix_listener, spawn_inbound_serve,
        spawn_transport_listener_inbound, ss_legacy_pipeline, ss_mode_conn_pipeline,
        transport_conn_addrs,
    },
    outbound::dns_idle_timeout_for,
};

// e7le：入站 sockopt（streamSettings.sockopt JSON；缺省 tcp_nodelay=true）
// 统一喂给 InboundTcpListener——此前 9 处裸 bind+accept 无 nodelay，
// 与 Go net 默认（NoDelay=true）相反，流式下行每 chunk 受 Nagle 拖累。
// finalmask.tcp（bd dppv）：裸 TCP 入站统一在 accept 后套 mask（Go hub.go
// WrapListener）；未配 → None，accept 路径零包装。
// （原 spawn_one_inbound 前置注释随构造逻辑一并迁移；各构造函数内
// `settings.socket_options()` 与拆分前预计算值逐字段一致。）

pub(crate) async fn build_socks_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    policy: Option<Arc<dyn xray_features::policy::PolicyManager>>,
    shutdown_token: CancellationToken,
    addr: &str,
    settings: &xray_transport::dialer::StreamSettings,
    plugin_ctx: std::sync::Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let inbound_sockopts = settings.socket_options();
    let listener = InboundTcpListener::bind(addr, inbound_sockopts.clone())
        .await?
        .with_tcpmask_manager(inbound_tcpmask(settings)?);
    // Go `proxy/socks/server.go:38-43`：socks 端口的 Server **无条件**构造一个
    // httpServer，首字节 ∉ {0x05,0x04} 即转 `httpServer.ProcessWithFirstbyte`
    // （`:87-90`）——即 Go 的 socks 端口同时服务 SOCKS5 与 HTTP 代理。故这里复用
    // mixed 的 serve 栈（同一 listener 上 socks + http），不另造一份 HTTP 实现。
    // 双配置构造与 UDS 路径共用 `parse_socks_http_configs`（同一份语义）。
    let (config, http_cfg) = parse_socks_http_configs(&ib.entry.data)?;
    let config = Arc::new(config);
    let http_cfg = Arc::new(http_cfg);
    // 握手限时（Go proxy/socks：SetReadDeadline(policy().Timeouts.Handshake)）
    let handshake_timeout = handshake_timeout_for(&policy, config.user_level);
    // UDP associate 空闲时限（Go server.go:171-175 `SetTimeout(
    // plcy.Timeouts.ConnectionIdle)`，ForLevel 按 userLevel 查档）。
    let udp_idle = policy
        .as_ref()
        .map(|pm| pm.policy_for_level(config.user_level).timeout.connection_idle)
        .unwrap_or(xray_features::policy::TimeoutPolicy::default().connection_idle);
    tracing::info!(tag = %ib.tag, addr = %addr, auth = ?config.auth_type, udp = config.udp_enabled, "socks5 inbound listening (http proxy fallback on non-SOCKS first byte)");
    Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, {
        let plugin_ctx = Arc::clone(&plugin_ctx);
        async move {
            serve_mixed(
                listener,
                ohm,
                config,
                http_cfg,
                Some(handshake_timeout),
                udp_idle,
                plugin_ctx,
            )
            .await
        }
    })))
}

pub(crate) async fn build_mixed_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    policy: Option<Arc<dyn xray_features::policy::PolicyManager>>,
    shutdown_token: CancellationToken,
    addr: &str,
    settings: &xray_transport::dialer::StreamSettings,
    plugin_ctx: std::sync::Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let inbound_sockopts = settings.socket_options();
    // V2RayN / Go xray mixed 协议 = socks + http 复合 listener。
    // 单 listener peek 首字节嗅探:0x05 → socks;ASCII 字母开头 → http。
    let socks_cfg = Arc::new(parse_socks_server_config(&ib.entry.data)?);
    let http_cfg = Arc::new(parse_http_config(&ib.entry.data)?);
    // 嗅探/socks/http 三段握手读共用一个限时；对齐 Go mixed mux 的两个
    // handler（socks/http 均按 policy().Timeouts.Handshake 限时）。
    let handshake_timeout = handshake_timeout_for(&policy, http_cfg.user_level);
    // mixed socks 分支 UDP relay 空闲时限（同 socks inbound 的 policy 查询，
    // Go server.go:171-175 ConnectionIdle；UDP 属 socks 域故用 socks_cfg 档）
    let udp_idle = policy
        .as_ref()
        .map(|pm| pm.policy_for_level(socks_cfg.user_level).timeout.connection_idle)
        .unwrap_or(xray_features::policy::TimeoutPolicy::default().connection_idle);
    let listener = InboundTcpListener::bind(addr, inbound_sockopts.clone())
        .await?
        .with_tcpmask_manager(inbound_tcpmask(settings)?);
    tracing::info!(tag = %ib.tag, addr = %addr, "mixed (socks+http) inbound listening");
    Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, {
        let plugin_ctx = Arc::clone(&plugin_ctx);
        async move {
            serve_mixed(
                listener,
                ohm,
                socks_cfg,
                http_cfg,
                Some(handshake_timeout),
                udp_idle,
                plugin_ctx,
            )
            .await
        }
    })))
}

/// portal 侧反向接入选项（bd nip4p）：settings 里的 user `reverse.tag` →
/// `enable_reverse` + registry（tag → `v1.rvs.cool`）+ 出站解析面 `ohm`。
///
/// 对应 Go `proxy/vless/inbound/inbound.go:191-215 GetReverse`：portal 侧的
/// portal outbound handler 由反向装配（[`crate::reverse`]）登记进 ohm，本函数
/// 只做入站侧三个开关的赋值；handler 不在场即拒启（配置声明了 reverse、
/// 却无人接 Rvs 的静默失效形态必须消失）。
fn apply_vless_reverse(
    options: &mut VlessInboundOptions,
    settings: &[u8],
    ohm: &Arc<SimpleOhm>,
) -> std::io::Result<()> {
    let tags = crate::reverse::vless_inbound_reverse_tags(settings);
    if tags.is_empty() {
        return Ok(());
    }
    let registry = xray_proxy_vless::ReverseRegistry::new();
    for tag in &tags {
        registry
            .add_reverse(xray_proxy_vless::PortalConfig::new(tag.clone()))
            .map_err(|e| std::io::Error::other(format!("vless reverse tag `{tag}`: {e}")))?;
        if ohm.get_handler(tag).is_none() {
            return Err(std::io::Error::other(format!(
                "vless reverse tag `{tag}`: portal outbound handler not registered \
                 (reverse assembly missing)"
            )));
        }
    }
    options.enable_reverse = true;
    options.reverse_registry = Some(Arc::new(registry));
    options.reverse_ohm = Some(Arc::clone(ohm));
    Ok(())
}

pub(crate) async fn build_vless_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    policy: Option<Arc<dyn xray_features::policy::PolicyManager>>,
    shutdown_token: CancellationToken,
    addr: &str,
    api: Option<&InboundRuntime>,
    plugin_ctx: std::sync::Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let validator: Arc<dyn VlessValidator> = build_vless_validator(&ib.entry.data)?;
    // bd hl8q6：用户热更接线（validator 与 serve loop 共享同一 Arc）
    register_vless_user_manager(api, &ib.tag, &validator);
    // ENC decryption（Go inbound.go:104-114 handler.decryption）：settings
    // 级 "mlkem768x25519plus.*" 字符串 → handler 级共享 ServerInstance。
    let decryption = build_vless_decryption(&ib.entry.data, Arc::clone(&plugin_ctx))?;
    let mut options = VlessInboundOptions {
        decryption: decryption.clone(),
        // sm80④：policy Timeouts.Handshake 下传（Go inbound.go:281-284）
        handshake_timeout: Some(handshake_timeout_for(&policy, 0)),
        ..Default::default()
    };
    // portal 侧反向接入（bd nip4p）：用户 `reverse.tag` 即 portal tag（Go
    // `inbound.go:191-215 GetReverse`）。三件缺一即拒启——配置写了 reverse 却
    // 收 Rvs 时只 warn+close 的静默失效形态必须消失。
    apply_vless_reverse(&mut options, &ib.entry.data, &ohm)?;
    let settings =
        xray_transport::dialer::StreamSettings::from_json(ib.stream_settings_json.as_ref());
    // splithttp 入站 AllowedNetwork（Go proxyman inbound.go:177-179）
    if settings.protocol == "splithttp" {
        options.allowed_network = Some(Network::UDP);
    }
    if is_transport_listener_protocol(&settings.protocol) {
        // transport 分支（ws/grpc/kcp/httpupgrade/splithttp）：listener_registry
        // 承载监听，TLS/security 在 transport hub 内部终结——勿再叠
        // build_tls_acceptor（双重握手）。
        let bind_addr: std::net::SocketAddr = addr.parse().map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("parse addr: {e}"))
        })?;
        let on_conn = vless_transport_on_conn(
            ib,
            &ohm,
            &settings,
            validator,
            options,
            bind_addr,
            addr,
            &plugin_ctx,
        )?;
        return spawn_transport_listener_inbound(
            &plugin_ctx,
            &ib.tag,
            bind_addr,
            settings,
            shutdown_token,
            on_conn,
        )
        .await;
    } else if settings.security == "reality" {
        // REALITY：server_tls 验证 → Verified 走 VLESS；Invalid fallback 到 dest
        let listener = InboundTcpListener::bind(addr, settings.socket_options())
            .await?
            // tcpSettings.header 伪装头（Go hub.go:85-95 authConfig；无 header
            // → None 零开销；serve 层在 reality 解包后应用，hub.go:106-120）。
            .with_header_auth(xray_transport::headers::conn::auth_from_json(
                settings.transport_json.as_ref(),
            )?)
            // finalmask.tcp（Go hub.go WrapListener；wire 最外层，reality 之前）
            .with_tcpmask_manager(inbound_tcpmask(&settings)?);
        let reality = parse_reality_config(&settings)?;
        tracing::info!(tag = %ib.tag, addr = %addr, users = validator.get_uuid_count(), fallback = %reality.fallback_dest, "vless+reality inbound listening");
        Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, {
            let task_ctx = Arc::clone(&plugin_ctx);
            async move {
                serve_reality_vless(listener, ohm, validator, reality, Some(options), task_ctx)
                    .await
            }
        })))
    } else {
        let tls = build_tls_acceptor(ib.stream_settings_json.as_ref())?;
        // VLESS fallbacks：Go napfb（name→alpn→path→dest+xver）
        let fallbacks = build_vless_fallbacks(&ib.entry.data)?;
        // tcpSettings.header 伪装头（Go hub.go:85-95；无 header → None 零开销）。
        let listener = InboundTcpListener::bind(addr, settings.socket_options())
            .await?
            .with_header_auth(xray_transport::headers::conn::auth_from_json(
                settings.transport_json.as_ref(),
            )?)
            // finalmask.tcp（Go hub.go WrapListener；wire 最外层，TLS 之前）
            .with_tcpmask_manager(inbound_tcpmask(&settings)?);
        tracing::info!(tag = %ib.tag, addr = %addr, users = validator.get_uuid_count(), tls = tls.is_some(), fallbacks = fallbacks.as_ref().map_or(0, |f| f.len()), enc = decryption.is_some(), "vless inbound listening");
        Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, {
            // spawn 面与任务体各持一份，避免 borrow-then-move 冲突。
            let task_ctx = Arc::clone(&plugin_ctx);
            async move {
                serve_vless(listener, ohm, validator, tls, fallbacks, Some(options), task_ctx).await
            }
        })))
    }
}

pub(crate) async fn build_trojan_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    policy: Option<Arc<dyn xray_features::policy::PolicyManager>>,
    shutdown_token: CancellationToken,
    addr: &str,
    api: Option<&InboundRuntime>,
    plugin_ctx: std::sync::Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let users = build_trojan_users(&ib.entry.data)?;
    // bd hl8q6：trojan 用户热更——validator 由 builder 造、与 serve 循环共享。
    let validator: Arc<xray_proxy_trojan::Validator> =
        build_trojan_validator_shared(&users).map_err(std::io::Error::other)?;
    register_trojan_user_manager(api, &ib.tag, &validator);
    // Trojan fallback：解析 JSON fallbacks 数组构建决策树
    // （dest 数字/缺失对齐 Go trojan.go:151-198，解析失败即启动失败）
    let fallbacks = build_trojan_fallbacks(&ib.entry.data)?;
    let settings =
        xray_transport::dialer::StreamSettings::from_json(ib.stream_settings_json.as_ref());
    if is_transport_listener_protocol(&settings.protocol) {
        // transport 分支：listener_registry 承载，TLS 在 hub 内终结。
        let bind_addr: std::net::SocketAddr = addr.parse().map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("parse addr: {e}"))
        })?;
        let on_conn = trojan_transport_on_conn(
            ib,
            &ohm,
            &policy,
            &settings,
            validator,
            fallbacks,
            bind_addr,
            addr,
            &plugin_ctx,
        )?;
        return spawn_transport_listener_inbound(
            &plugin_ctx,
            &ib.tag,
            bind_addr,
            settings,
            shutdown_token,
            on_conn,
        )
        .await;
    } else if settings.security == "reality" {
        // REALITY：server_tls 验证 → Verified 走 Trojan；Invalid fallback 到 dest。
        // （39436 修复：此前误走 build_tls_acceptor 标准 rustls——客户端
        // REALITY 证书校验必败，trojan header 永远读不到。对齐 Go：
        // trojan inbound 收到的 iConn 已是 *reality.Conn。）
        let reality = parse_reality_config(&settings)?;
        let listener = InboundTcpListener::bind(addr, settings.socket_options())
            .await?
            // tcpSettings.header 伪装头（Go hub.go:85-95 authConfig；无 header
            // → None 零开销；serve 层在 reality 解包后应用，hub.go:106-120）。
            .with_header_auth(xray_transport::headers::conn::auth_from_json(
                settings.transport_json.as_ref(),
            )?)
            // finalmask.tcp（Go hub.go WrapListener；wire 最外层，reality 之前）
            .with_tcpmask_manager(inbound_tcpmask(&settings)?);
        tracing::info!(tag = %ib.tag, addr = %addr, users = validator.get_key_count(), fallback = %reality.fallback_dest, "trojan+reality inbound listening");
        Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, {
            let validator = Arc::clone(&validator);
            async move {
                serve_reality_trojan(
                    listener,
                    ohm,
                    validator,
                    fallbacks,
                    reality,
                    handshake_timeout_for(&policy, 0),
                )
                .await
            }
        })))
    } else {
        let tls = build_tls_acceptor(ib.stream_settings_json.as_ref())?;
        let listener = InboundTcpListener::bind(addr, settings.socket_options())
            .await?
            .with_header_auth(xray_transport::headers::conn::auth_from_json(
                settings.transport_json.as_ref(),
            )?)
            // finalmask.tcp（Go hub.go WrapListener；wire 最外层，TLS 之前）
            .with_tcpmask_manager(inbound_tcpmask(&settings)?);
        tracing::info!(tag = %ib.tag, addr = %addr, users = validator.get_key_count(), tls = tls.is_some(), "trojan inbound listening");
        Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, {
            let plugin_ctx = Arc::clone(&plugin_ctx);
            async move {
                serve_trojan(
                    plugin_ctx,
                    listener,
                    ohm,
                    validator,
                    fallbacks,
                    tls,
                    handshake_timeout_for(&policy, 0),
                )
                .await
            }
        })))
    }
}

pub(crate) async fn build_vmess_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    policy: Option<Arc<dyn xray_features::policy::PolicyManager>>,
    shutdown_token: CancellationToken,
    addr: &str,
    api: Option<&InboundRuntime>,
    plugin_ctx: std::sync::Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let validator = build_vmess_validator(&ib.entry.data)?;
    // bd hl8q6：用户热更接线（validator 与 serve loop 共享同一 Arc）
    register_vmess_user_manager(api, &ib.tag, &validator, &ib.entry.data);
    let settings =
        xray_transport::dialer::StreamSettings::from_json(ib.stream_settings_json.as_ref());
    if is_transport_listener_protocol(&settings.protocol) {
        // transport 分支：listener_registry 承载，TLS 在 hub 内终结。
        let bind_addr: std::net::SocketAddr = addr.parse().map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("parse addr: {e}"))
        })?;
        let on_conn = vmess_transport_on_conn(
            ib,
            &ohm,
            &policy,
            &settings,
            validator,
            bind_addr,
            addr,
            &plugin_ctx,
        )?;
        return spawn_transport_listener_inbound(
            &plugin_ctx,
            &ib.tag,
            bind_addr,
            settings,
            shutdown_token,
            on_conn,
        )
        .await;
    } else {
        let tls = build_tls_acceptor(ib.stream_settings_json.as_ref())?;
        let listener = InboundTcpListener::bind(addr, settings.socket_options())
            .await?
            .with_header_auth(xray_transport::headers::conn::auth_from_json(
                settings.transport_json.as_ref(),
            )?)
            // finalmask.tcp（Go hub.go WrapListener；wire 最外层，TLS 之前）
            .with_tcpmask_manager(inbound_tcpmask(&settings)?);
        tracing::info!(tag = %ib.tag, addr = %addr, tls = tls.is_some(), "vmess inbound listening");
        Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, {
            let plugin_ctx = Arc::clone(&plugin_ctx);
            async move {
                serve_vmess(
                    plugin_ctx,
                    listener,
                    ohm,
                    validator,
                    tls,
                    handshake_timeout_for(&policy, 0),
                )
                .await
            }
        })))
    }
}

pub(crate) async fn build_http_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    policy: Option<Arc<dyn xray_features::policy::PolicyManager>>,
    shutdown_token: CancellationToken,
    addr: &str,
    settings: &xray_transport::dialer::StreamSettings,
    plugin_ctx: std::sync::Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let inbound_sockopts = settings.socket_options();
    let config = parse_http_config(&ib.entry.data)?;
    // userLevel 生效：policy_for_level(UserLevel).timeout.handshake →
    // serve_http 读首请求超时。对应 Go proxy/http/server.go:47-51 policy()
    // + :112 SetReadDeadline(Timeouts.Handshake)；无 policy manager（如
    // 无 policy 配置块）时对齐 Go SessionDefault 兜底 60s
    // （features/policy/policy.go:130），不再无限时。
    let handshake_timeout = handshake_timeout_for(&policy, config.user_level);
    let listener = InboundTcpListener::bind(addr, inbound_sockopts.clone())
        .await?
        .with_tcpmask_manager(inbound_tcpmask(settings)?);
    tracing::info!(tag = %ib.tag, addr = %addr, "http inbound listening");
    Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, {
        let plugin_ctx = Arc::clone(&plugin_ctx);
        async move {
            serve_http(listener, ohm, Arc::new(config), Some(handshake_timeout), plugin_ctx).await
        }
    })))
}

pub(crate) async fn build_dokodemo_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    shutdown_token: CancellationToken,
    addr: &str,
    settings: &xray_transport::dialer::StreamSettings,
    plugin_ctx: std::sync::Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let inbound_sockopts = settings.socket_options();
    // 先取 finalmask（此处 `settings` 还是 streamSettings，下一行被
    // dokodemo 自身 settings 遮蔽）
    let tcpmask = inbound_tcpmask(settings)?;
    let udp_mask = inbound_udpmask(settings)?;
    let settings = parse_dokodemo_settings(&ib.entry.data)?;
    let dest = settings.dest.clone();
    // TLS（streamSettings security=tls）：对应 Go tls.NewListener 包裹，
    // SNI 在 serve_dokodemo 内用于 follow_redirect 未覆盖时的 dest 改写。
    let tls = build_tls_acceptor(ib.stream_settings_json.as_ref())?;
    // followRedirect 的 SO_ORIGINAL_DST 仅 Linux 可用；非 Linux 拿不到
    // 原始目标 → 连接被拒（Go dokodemo.go:137 unable to get destination）。
    #[cfg(not(target_os = "linux"))]
    if settings.follow_redirect {
        tracing::warn!(
            tag = %ib.tag,
            "dokodemo followRedirect requires Linux (SO_ORIGINAL_DST / UDP TPROXY); connections without original destination will be rejected"
        );
    }
    // B6（bd 39hko 切片1）：listener serve 任务唯一托管口（坑约束 5）。scope 归
    // 底部 serve future 持有：两个 listener task 终局（或 token cancel 时本 future
    // 被 drop → scope drop abort）即收；协作退出仍走任务内 token select（bd jezb）。
    let fx = Arc::new(FxScope::new());
    let mut handles = Vec::new();
    if settings.allow_tcp {
        let listener = InboundTcpListener::bind(addr, inbound_sockopts.clone())
            .await?
            .with_tcpmask_manager(tcpmask);
        tracing::info!(tag = %ib.tag, addr = %addr, dest = ?dest, tls = tls.is_some(), "dokodemo TCP inbound listening");
        let ohm_tcp = Arc::clone(&ohm);
        let opts = DokodemoTcpOptions {
            dest: dest.clone(),
            port_map: settings.port_map,
            follow_redirect: settings.follow_redirect,
            tls,
        };
        // bd jezb：内层 listener task 必须自己感知 shutdown token——旧形态由外层
        // await 持有 JoinHandle，token cancel 时 drop = detach（accept loop 继续跑，
        // RemoveInbound 后端口仍可连）。
        let stop = shutdown_token.clone();
        let tcp_ctx = Arc::clone(&plugin_ctx);
        handles.push(
            fx.spawn_tracked(async move {
                tokio::select! {
                    r = serve_dokodemo(listener, ohm_tcp, opts, tcp_ctx) => {
                        if let Err(e) = r {
                            tracing::error!(error = %e, "dokodemo TCP inbound stopped");
                        }
                    },
                    _ = stop.cancelled() => {},
                }
            })
            .expect("internal FxScope is never closed"),
        );
    }
    if settings.allow_udp {
        let bind_addr: std::net::SocketAddr = addr.parse().map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("parse addr: {e}"))
        })?;
        let dispatch = ohm.get_default_handler().ok_or_else(|| {
            std::io::Error::other("dokodemo UDP inbound requires a default outbound handler")
        })?;
        tracing::info!(tag = %ib.tag, addr = %addr, dest = ?dest, "dokodemo UDP inbound listening");
        let dest_udp = dest.clone();
        let follow_redirect = settings.follow_redirect;
        let stop = shutdown_token.clone();
        let udp_ctx = Arc::clone(&plugin_ctx);
        // bind 提前到 spawn 之前：Go 的 dokodemo 在 handler 构造期同步
        // ListenUDP（proxy/dokodemo/dokodemo.go），端口占用属于「入站创建
        // 失败」→ 启动失败。旧形态把 bind 藏在 spawn 出去的任务里：调用方
        // 返回时端口还没监听（发包早于 bind 会丢包，CI 高负载下必现），且
        // bind 失败只落 tracing::error（无人订阅时静默死亡）。
        let hub = xray_transport::udp::hub::UdpHub::listen(
            bind_addr,
            &[Box::new(xray_transport::udp::hub::ReceiveOriginalDestination(follow_redirect))],
            udp_mask,
        )
        .await?;
        handles.push(
            fx.spawn_tracked(async move {
                tokio::select! {
                    r = serve_dokodemo_udp_on(hub, dispatch, dest_udp, udp_ctx) => {
                        if let Err(e) = r {
                            tracing::error!(error = %e, "dokodemo UDP inbound stopped");
                        }
                    },
                    _ = stop.cancelled() => {},
                }
            })
            .expect("internal FxScope is never closed"),
        );
    }
    if handles.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "dokodemo: no valid network specified (need tcp and/or udp)",
        ));
    }
    // 合并所有 listener handle；token cancel 时 combined 被取消（本 future drop
    // → scope drop abort 子任务，listener socket 随任务体 drop 释放）。
    Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, async move {
        let _scope = fx;
        for h in handles {
            // panic 不得静默（bd 16uis S7）：同 `spawn_inbound_serve` 外层壳的
            // `TaskError::Panicked` 留痕语义——旧实现 `let _` 把 JoinError 丢掉，
            // 任务 panic 后监听静默消失且无任何日志。
            if let Err(e) = h.join().await {
                tracing::error!(error = ?e, "dokodemo inbound task ended abnormally");
            }
        }
        Ok(())
    })))
}

pub(crate) async fn build_shadowsocks_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    policy: Option<Arc<dyn xray_features::policy::PolicyManager>>,
    shutdown_token: CancellationToken,
    addr: &str,
    api: Option<&InboundRuntime>,
    plugin_ctx: std::sync::Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let settings =
        xray_transport::dialer::StreamSettings::from_json(ib.stream_settings_json.as_ref());
    // transport 分支（grpc/kcp/ws hub 承载）：Legacy 与 SS2022（单用户/
    // 多用户/中继）统一接线，对齐 Go proxyman 语义（streamSettings 包好
    // transport 后调用 Process，见 shadowsocks_2022/inbound.go）。
    if is_transport_listener_protocol(&settings.protocol) {
        let bind_addr: std::net::SocketAddr = addr.parse().map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("parse addr: {e}"))
        })?;
        let on_conn = ss_transport_on_conn(ib, &ohm, &policy, api, &settings, addr, &plugin_ctx)?;
        return spawn_transport_listener_inbound(
            &plugin_ctx,
            &ib.tag,
            bind_addr,
            settings,
            shutdown_token,
            on_conn,
        )
        .await;
    }
    let inbound_sockopts = settings.socket_options();
    let listener = InboundTcpListener::bind(addr, inbound_sockopts.clone())
        .await?
        // finalmask.tcp（Go tcp/hub.go:50-54 ListenTCP 语义；wire 最外层，ss 握手之前）
        .with_tcpmask_manager(inbound_tcpmask(&settings)?);
    let inbound = parse_ss_inbound_config(&ib.entry.data)?;
    register_ss_user_manager(api, &ib.tag, &inbound);
    // finalmask.udp（bd 05js，Go udp/hub.go:61-62）：同端口 UDP relay 装配。
    // bd zhjhv：bind + mask 包装在**装配期**完成——地址取 TCP listener 的实际
    // 绑定地址（= 配置 `listen`，Go worker.go:413 `udp.ListenUDP(ctx, w.address,
    // w.port)`），失败即 `?` 拒启（Go udpWorker.Start() 返回 err）。
    let inbound_udp = bind_ss_udp(&listener, inbound_udpmask(&settings)?).await?;
    tracing::info!(tag = %ib.tag, addr = %addr, "shadowsocks inbound listening");
    Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, {
        let plugin_ctx = Arc::clone(&plugin_ctx);
        async move {
            serve_ss(
                listener,
                ohm,
                inbound,
                handshake_timeout_for(&policy, 0),
                Some(inbound_udp),
                plugin_ctx,
            )
            .await
        }
    })))
}

// hysteria inbound：HysteriaInboundHandler impl InboundHandler（rxw：接 dispatcher）
pub(crate) async fn build_hysteria_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    shutdown_token: CancellationToken,
    addr: &str,
    api: Option<&InboundRuntime>,
    plugin_ctx: std::sync::Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let bind_addr: std::net::SocketAddr = addr.parse().map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("parse addr: {e}"))
    })?;
    // bd a3tos：finalmask 必须取 `streamSettings.finalmask` 子对象——此前误传整个
    // streamSettings，`parse_udp_obfs`/`parse_quic_params` 读的顶层 `udp`/
    // `quicParams` 键永不命中 → 配了 obfs 的 hysteria2 入站照样裸 QUIC 收包，
    // 非法混淆配置也不报错。取法与出站侧（`arm_builders/outbound.rs` 的
    // `StreamSettings.finalmask_json`）同源。
    let stream =
        xray_transport::dialer::StreamSettings::from_json(ib.stream_settings_json.as_ref());
    let (config, factory, users) =
        parse_hysteria_inbound_config(&ib.entry.data, bind_addr, stream.finalmask_json.as_ref())?;
    let dispatch = ohm.get_default_handler().ok_or_else(|| {
        std::io::Error::other("hysteria inbound requires a default outbound handler")
    })?;
    // bd ctiwx：users[] 多用户形态——`MultiUserValidator` 与 hub serve loop 共享
    // 同一 Arc 并登记进 gRPC 用户管理面（Go server.go:62-75 UserManager）；单
    // auth 形态不登记（NotUserManager 拒绝，见 register_hysteria_user_manager）。
    let multi = if users.is_empty() {
        None
    } else {
        Some(Arc::new(xray_proxy_hysteria::MultiUserValidator::from_users(&users)))
    };
    if let Some(validator) = &multi {
        register_hysteria_user_manager(api, &ib.tag, validator);
    }
    let handler =
        xray_proxy_hysteria::HysteriaInboundHandler::new(&ib.tag, config, bind_addr, factory)
            .map_err(|e| std::io::Error::other(format!("hysteria inbound: {e}")))?
            .with_multi_validator(multi.clone())
            .with_dispatcher(Some(Arc::new(HysteriaTcpDispatch(Arc::clone(&dispatch)))))
            .with_udp_dispatcher(Some(dispatch));
    tracing::info!(tag = %ib.tag, addr = %addr, users = multi.as_ref().map_or(0, |v| v.count()), "hysteria inbound listening");
    Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, async move {
        handler.start().await.map_err(|e| std::io::Error::other(format!("{e}")))
    })))
}

/// `DispatchHandler` → Go 阻塞语义适配（`Handler.Dispatch(ctx, link)` 契约）。
///
/// 生产 default handler 是 **fire-and-forget**：`InboundDispatchHandler::dispatch`
/// 调 [`xray_app_dispatcher::default::DefaultDispatcher::dispatch_link`]（内部
/// spawn 后立即返回，见 `crate::wiring`），future 立刻 resolve。而 anytls 服务端
/// 把 `dispatch(..).await` 的返回当「连接已结束」——随后 `finish_session` 发 FIN
/// 并关 socket（`xray-proxy-anytls/src/server.rs` 的 `handle_session` /
/// `serve_uot_session`）。两者直接相接 = 出站桥接还没开始会话就被关掉
/// （bd b5e77 e2e 实证：TCP / UoT 均立刻 `early eof`）。
///
/// 本适配器把「link 生命周期结束」翻译成 future 完成：处置任务 drop writer 或
/// 调 `shutdown()`（bridge 收尾的既有动作）时才 resolve，恢复 Go 的阻塞语义。
///
/// shortcut: 信号只挂 writer（bridge 正常收尾必 `shutdown`，异常路径必 drop）；
/// 若将来出现只 drop reader、长期持有 writer 的 handler，需补 reader 侧信号。
/// 通用件——other 协议若同样「dispatch 返回即拆传输」可复用；提炼候选
/// `xray-app-dispatcher`（同族先例：hysteria 的 [`HysteriaTcpDispatch`] 也住在
/// 本 crate 做协议→dispatcher 适配）。
struct DispatchUntilLinkClosed(Arc<dyn xray_app_dispatcher::DispatchHandler>);

impl std::fmt::Debug for DispatchUntilLinkClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DispatchUntilLinkClosed").field("tag", &self.0.tag()).finish()
    }
}

impl xray_app_dispatcher::DispatchHandler for DispatchUntilLinkClosed {
    fn tag(&self) -> &str {
        self.0.tag()
    }

    fn dispatch(
        &self,
        dest: &xray_common::net::destination::Destination,
        link: xray_transport::link::Link,
    ) -> xray_app_dispatcher::default::PinFuture<()> {
        let inner = Arc::clone(&self.0);
        let dest = dest.clone();
        Box::pin(async move {
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            let signal = Arc::new(LinkCloseSignal(parking_lot::Mutex::new(Some(tx))));
            let link = xray_transport::link::Link::new(
                link.reader,
                Box::new(SignalWriter { inner: link.writer, signal }),
            );
            inner.dispatch(&dest, link).await;
            // inner 是 fire-and-forget（已 spawn）；等 link 真正结束再返回。
            let _ = rx.await;
        })
    }
}

/// link 关闭信号闸：一次触发（`shutdown` / `shutdown_flush` / drop 任一先到）。
struct LinkCloseSignal(parking_lot::Mutex<Option<tokio::sync::oneshot::Sender<()>>>);

impl LinkCloseSignal {
    fn fire(&self) {
        if let Some(tx) = self.0.lock().take() {
            let _ = tx.send(());
        }
    }
}

/// writer 包装：转发全部写语义，在关闭/丢弃时触发信号。
struct SignalWriter {
    inner: Box<dyn xray_buf::io::Writer>,
    signal: Arc<LinkCloseSignal>,
}

impl xray_buf::io::Writer for SignalWriter {
    fn write_multi_buffer(
        &mut self,
        mb: xray_buf::multi::MultiBuffer,
    ) -> Pin<Box<dyn Future<Output = xray_buf::io::Result<()>> + Send + '_>> {
        self.inner.write_multi_buffer(mb)
    }

    fn poll_write_multi_buffer(
        &mut self,
        cx: &mut Context<'_>,
        mb: &mut xray_buf::multi::MultiBuffer,
    ) -> Poll<xray_buf::io::Result<()>> {
        self.inner.poll_write_multi_buffer(cx, mb)
    }

    fn shutdown(&self) {
        self.signal.fire();
        self.inner.shutdown();
    }

    fn shutdown_flush(&mut self) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + '_>> {
        self.signal.fire();
        self.inner.shutdown_flush()
    }
}

impl Drop for SignalWriter {
    fn drop(&mut self) {
        self.signal.fire();
    }
}

// anytls inbound：AnytlsInboundHandler impl InboundHandler
pub(crate) async fn build_anytls_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    shutdown_token: CancellationToken,
    addr: &str,
    plugin_ctx: std::sync::Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let bind_addr: std::net::SocketAddr = addr.parse().map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("parse addr: {e}"))
    })?;
    let (tls_acceptor, password) = parse_anytls_tls_acceptor(&ib.entry.data)?;
    // bd b5e77：缺 dispatcher 时 anytls 服务端退回 mock 直连分支——TCP 绕过
    // router（不烘焙 DNS/fake-IP/路由规则），UoT 直接拒会话。故与 hysteria/tuic
    // 同款 fail-visible：无默认出站 = 启动期硬错，禁静默退回直连。
    let dispatch = ohm.get_default_handler().ok_or_else(|| {
        std::io::Error::other("anytls inbound requires a default outbound handler")
    })?;
    let handler = xray_proxy_anytls::AnytlsInboundHandler::new(&ib.tag, bind_addr, tls_acceptor)
        .with_password(password)
        .with_dispatch(Arc::new(DispatchUntilLinkClosed(dispatch)));
    handler.start().await.map_err(|e| std::io::Error::other(format!("{e}")))?;
    // start() 是 spawn-后-返回的短方法：slot.server 持 MockServer stop_tx，
    // handler drop → serve_loop 的 sender-dropped 分支退出 → listener 关闭。
    // 留 pending 保活（同 blackhole/freedom arm），shutdown 时随 task drop 停服。
    Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, async move {
        let _keep = handler;
        std::future::pending::<()>().await;
        Ok(())
    })))
}

// tuic inbound：QUIC listener + auth + Connect → dispatcher/router 分发
pub(crate) async fn build_tuic_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    shutdown_token: CancellationToken,
    addr: &str,
    plugin_ctx: std::sync::Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let dispatch = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("tuic inbound requires a default outbound handler"))?;
    let handler =
        parse_tuic_inbound_config(&ib.entry.data, addr, ib.stream_settings_json.as_ref())?
            .with_dispatch(dispatch);
    Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, async move {
        handler.start().await.map_err(|e| std::io::Error::other(format!("{e}")))
    })))
}

// naive inbound：TLS + h2 CONNECT（naiveproxy 服务端语义，bd 88vp）
pub(crate) async fn build_naive_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    shutdown_token: CancellationToken,
    addr: &str,
    plugin_ctx: std::sync::Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let bind_addr: std::net::SocketAddr = addr.parse().map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("parse addr: {e}"))
    })?;
    let (auth, tls_config) =
        parse_naive_inbound_settings(&ib.entry.data, ib.stream_settings_json.as_ref())?;
    let dispatch = ohm.get_default_handler().ok_or_else(|| {
        std::io::Error::other("naive inbound requires a default outbound handler")
    })?;
    let handler =
        xray_transport_naive::NaiveInboundHandler::new(&ib.tag, bind_addr, tls_config, auth)
            .with_dispatch(dispatch);
    handler.start().await.map_err(|e| std::io::Error::other(format!("{e}")))?;
    // 保活持有（anytls 同款）：`NaiveInboundHandler` 的 Drop impl 显式
    // `accept_task.abort()` 关端口（注意：tokio 里 JoinHandle 丢弃只是 detach，不会中止任务），
    // shutdown 随本 task 被 token cancel 时 abort 生效。
    Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, async move {
        let _keep = handler;
        std::future::pending::<()>().await;
        Ok(())
    })))
}

// wireguard inbound：WireguardInboundHandler impl InboundHandler
pub(crate) async fn build_wireguard_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    shutdown_token: CancellationToken,
    addr: &str,
    api: Option<&InboundRuntime>,
    plugin_ctx: std::sync::Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    // `addr` 未消费（wireguard 自管 UDP 端口，Go 同：listen_port 由 settings 给）；
    // 参数保留与其它 builder 同形。
    let _ = addr;
    let (config, listen_port) = parse_wireguard_inbound_config(&ib.entry.data)?;
    let dispatch = ohm.get_default_handler().ok_or_else(|| {
        std::io::Error::other("wireguard inbound requires a default outbound handler")
    })?;
    let handler =
        xray_proxy_wireguard::WireguardInboundHandler::new(&ib.tag, &config, listen_port, dispatch)
            .await
            .map_err(|e| std::io::Error::other(format!("wireguard inbound: {e}")))?;
    // bd hl8q6：用户热更接线（注册表与 accept loop 共享同一 Arc）。
    let handler = Arc::new(handler);
    register_wg_user_manager(api, &ib.tag, &handler);
    Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, async move {
        handler.start().await.map_err(|e| std::io::Error::other(format!("{e}")))
    })))
}

// dns inbound：UDP+TCP listener → handle_packet/handle_conn
pub(crate) async fn build_dns_inbound(
    ib: &BuiltInbound,
    policy: Option<Arc<dyn xray_features::policy::PolicyManager>>,
    shutdown_token: CancellationToken,
    addr: &str,
    settings: &xray_transport::dialer::StreamSettings,
    plugin_ctx: std::sync::Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let inbound_sockopts = settings.socket_options();
    // G14（Go dns.go:85）：空闲超时取 policy ConnectionIdle；inbound
    // settings JSON 无 userLevel 概念，固定 level 0。无 manager 时
    // dns_idle_timeout_for 内显式回退 SessionDefault 并 warn 一次。
    let dns_idle = dns_idle_timeout_for(policy.as_deref(), 0);
    let (handler, outbound) = parse_dns_inbound_config(&ib.entry.data, &ib.tag, dns_idle)?;
    let inbound = Arc::new(DnsInbound::new(&ib.tag, handler, outbound));
    let udp = xray_transport::udp::bind_udp_no_connreset(addr).await?;
    let tcp = InboundTcpListener::bind(addr, inbound_sockopts.clone())
        .await?
        .with_tcpmask_manager(inbound_tcpmask(settings)?);
    tracing::info!(tag = %ib.tag, addr = %addr, "dns inbound listening (UDP+TCP)");
    Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, {
        let plugin_ctx = Arc::clone(&plugin_ctx);
        async move { serve_dns(udp, tcp, inbound, plugin_ctx).await }
    })))
}

// loopback inbound：LoopbackHandler 注册（outbound-only，start/close no-op）
pub(crate) async fn build_loopback_inbound(
    ib: &BuiltInbound,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let inbound_tag = parse_loopback_config(&ib.entry.data)?;
    let _handler = LoopbackHandler::new(
        &ib.tag,
        xray_proto::xray::proxy::loopback::Config {
            inbound_tag,
            sniffing: None, /* Go tag2；JSON 配置面暂不解析（Go Config.Sniffing 仅 gRPC
                             * 面使用） */
        },
    );
    tracing::info!(tag = %ib.tag, "loopback inbound registered (outbound-only)");
    // LoopbackHandler 的 InboundHandler::start 是 no-op，不 spawn task
    Ok(None)
}

// blackhole inbound：accept 连接后静默关闭/写 403 后关闭
pub(crate) async fn build_blackhole_inbound(
    ib: &BuiltInbound,
    shutdown_token: CancellationToken,
    addr: &str,
    plugin_ctx: Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let response = parse_blackhole_inbound_response(&ib.entry.data)?;
    let handler = BlackholeInboundHandler::new(Arc::clone(&plugin_ctx), &ib.tag, response, addr);
    handler.start().await.map_err(|e| std::io::Error::other(format!("blackhole inbound: {e}")))?;
    // accept 循环在 start() 内部 spawn，此 task 保持 handler 存活并监听 shutdown。
    Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, async move {
        std::future::pending::<()>().await;
        Ok(())
    })))
}

// freedom inbound：accept 连接后 dial 预定义目标并双向转发
pub(crate) async fn build_freedom_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    shutdown_token: CancellationToken,
    addr: &str,
    plugin_ctx: std::sync::Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let dest = parse_freedom_inbound_dest(&ib.entry.data)?;
    let handler = FreedomInboundHandler::new(&ib.tag, addr, dest, Arc::clone(&ohm));
    handler.start().await.map_err(|e| std::io::Error::other(format!("freedom inbound: {e}")))?;
    // accept 循环在 start() 内部 spawn，此 task 保持 handler 存活并监听 shutdown。
    Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, async move {
        std::future::pending::<()>().await;
        Ok(())
    })))
}

// ============ arm scope 闸关拒发观测（bd 9tots） ============
//
// 停机闸关后的新连接丢弃原先逐站 warn（9ka5w §1.2 未改清单的另一半）：统一为
// 「预期丢弃 = DEBUG + 计数；泵逃逸 = 限频 WARN」。计数器 file 级自持
// （AtomicU64）——ArmScope 本体在 `xray-frame/src/scope.rs`（他仓所有，只读），
// 机制不上浮：本文件 4 站共享同一单例。

/// 停机排空竞态判窗：闸关后泵随排空 abort 终止（udf 三段：关闸→abort→等净；
/// 本 crate 排空档 5s），拒发只应落在首拒附近的竞态窗；判窗（10s ≈ 2× 排空
/// 档）过后仍见新拒发 = 泵逃逸（owner 已消失而泵仍在受理）。
const REJECT_ANOMALY_GRACE: Duration = Duration::from_secs(10);

/// 泵逃逸 WARN 限频窗（60s 滚动，首击必报；与 tuic `DROP_LOG_INTERVAL` /
/// fallback `FAIL_LOG_WINDOW` 同档，不新造档位）。
const REJECT_LOG_WINDOW: Duration = Duration::from_secs(60);

/// 一次闸关拒发的分档结论。
#[derive(Debug, Clone, Copy)]
enum RejectVerdict {
    /// 停机排空竞态（预期）→ 站点落 DEBUG。
    DrainRace { rejected: u64 },
    /// 泵逃逸（owner 已消失而泵仍在受理）→ `emit=true` 限频放行一条 WARN
    /// （文案含 `lifecycle anomaly, not shutdown`）；`emit=false` 抑制期落 DEBUG。
    PumpEscaped { rejected: u64, emit: bool },
}

/// 泵逃逸限频闸（窗口内至多一条 WARN；首击必报——`None` = 尚未报过）。
#[derive(Default)]
struct RejectTimeline {
    /// 首次拒发时刻（判窗锚点）。
    first_reject: Option<Instant>,
    /// 上一条泵逃逸 WARN 时刻（限频窗锚点）。
    last_anomaly_log: Option<Instant>,
}

/// arm scope 拒发账本：无条件计数（限频只压日志不压证据）+ 判窗/限频锚。
struct ArmRejectMeter {
    rejected: AtomicU64,
    timeline: parking_lot::Mutex<RejectTimeline>,
}

impl ArmRejectMeter {
    fn new() -> Self {
        Self {
            rejected: AtomicU64::new(0),
            timeline: parking_lot::Mutex::new(RejectTimeline::default()),
        }
    }

    /// 记一次闸关拒发（`now` 由调用方给 `std::time::Instant`；测试用合成时间驱动）。
    fn record(&self, now: Instant) -> RejectVerdict {
        let rejected = self.rejected.fetch_add(1, Ordering::Relaxed) + 1;
        let mut tl = self.timeline.lock();
        let first = tl.first_reject.get_or_insert(now);
        if now.saturating_duration_since(*first) < REJECT_ANOMALY_GRACE {
            return RejectVerdict::DrainRace { rejected };
        }
        let emit = match tl.last_anomaly_log {
            Some(last) => now.saturating_duration_since(last) >= REJECT_LOG_WINDOW,
            None => true,
        };
        if emit {
            tl.last_anomaly_log = Some(now);
        }
        RejectVerdict::PumpEscaped { rejected, emit }
    }

    /// 累计拒发数（聚合读数，禁逐包日志）。测试读数口（生产读数 = 日志行尾
    /// `rejected N`）——非 test 构建无调用方，随 accessor 一起 cfg(test) 门控。
    #[cfg(test)]
    fn rejected_total(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }
}

/// 进程级拒发账本（本文件 4 站共享单例）。
static TRANSPORT_REJECT_METER: LazyLock<ArmRejectMeter> = LazyLock::new(ArmRejectMeter::new);

/// 进程级累计闸关拒发连接数（测试读数口）。生产读数 = 各档位日志行尾
/// `rejected N`（`mod arm_builders` 私有 ⇒ 无外部读口；公开 accessor 需
/// lib.rs re-export，非本票文件面，留待消费方出现时另批）。
#[cfg(test)]
#[must_use]
pub(crate) fn transport_closed_scope_rejected_conns() -> u64 {
    TRANSPORT_REJECT_METER.rejected_total()
}

/// 闸关拒新连接的统一观测口（4 站共用）：计数 + 分档日志。预期（排空竞态）=
/// DEBUG；泵逃逸 = 限频 WARN（文案含 `lifecycle anomaly, not shutdown`）。
/// 时钟：`compat::clock()` 返回裸 `std::time::Instant`（限频诊断信号非 wire 值，
/// 无需可注入时钟；本站闭包无 ctx 形参，此为 ADR-2 面 2 受管口）。
fn record_closed_scope_reject(label: &'static str, peer: Option<std::net::SocketAddr>) {
    let now = xray_frame::compat::clock().now_instant();
    let (warn, line) = match TRANSPORT_REJECT_METER.record(now) {
        RejectVerdict::DrainRace { rejected } => (
            false,
            format!(
                "{label}: arm scope closed at shutdown, dropping connection (drain race, rejected {rejected})"
            ),
        ),
        RejectVerdict::PumpEscaped { rejected, emit: true } => (
            true,
            format!(
                "{label}: arm scope closed at shutdown, dropping connection — lifecycle anomaly, not shutdown (rejected {rejected})"
            ),
        ),
        RejectVerdict::PumpEscaped { rejected, emit: false } => (
            false,
            format!(
                "{label}: arm scope closed at shutdown, dropping connection (lifecycle anomaly, not shutdown; log suppressed, rejected {rejected})"
            ),
        ),
    };
    // `tracing::event!` 的 level 位要求 const（tracing-0.1.44 E0435 实证）→ 字面量宏臂分派。
    match (warn, peer) {
        (true, Some(peer)) => tracing::warn!(peer = %peer, "{line}"),
        (true, None) => tracing::warn!("{line}"),
        (false, Some(peer)) => tracing::debug!(peer = %peer, "{line}"),
        (false, None) => tracing::debug!("{line}"),
    }
}

// ============ transport 分支 ConnHandler 共享构造（bd lfrg） ============
//
// TCP（`spawn_transport_listener_inbound`）与 unix（`spawn_unix_transport_inbound`）
// 两条监听路径共用同一份 per-协议 on_conn 构造——unix 路径禁另写一份。
// `fallback_addr` 作 peer/local 解析兜底：TCP = bind 地址，unix = 0.0.0.0:0
// （对齐 Go UnixConnWrapper.RemoteAddr）。

/// vless transport 分支 ConnHandler（ws/grpc/kcp/httpupgrade/splithttp）。
// 8 参 = TCP/unix 双路径直译签名，打包聚合体属内部 API 变更（同 trojan_transport_on_conn 先例）。
#[allow(clippy::too_many_arguments)]
pub(crate) fn vless_transport_on_conn(
    ib: &BuiltInbound,
    ohm: &Arc<SimpleOhm>,
    settings: &xray_transport::dialer::StreamSettings,
    validator: Arc<dyn VlessValidator>,
    mut options: VlessInboundOptions,
    fallback_addr: std::net::SocketAddr,
    ident: &str,
    plugin_ctx: &Arc<xray_frame::PluginContext>,
) -> std::io::Result<xray_transport::listener_registry::ConnHandler> {
    // splithttp 入站 AllowedNetwork（Go proxyman inbound.go:177-179）
    if settings.protocol == "splithttp" {
        options.allowed_network = Some(Network::UDP);
    }
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;
    let fallbacks = build_vless_fallbacks(&ib.entry.data)?;
    tracing::info!(tag = %ib.tag, addr = %ident, network = %settings.protocol, security = %settings.security, users = validator.get_uuid_count(), "vless transport inbound listening");
    let plugin_ctx = Arc::clone(plugin_ctx);
    Ok(Arc::new(move |conn| {
        let handler = Arc::clone(&handler);
        let validator = Arc::clone(&validator);
        let fallbacks = fallbacks.clone();
        let options = options.clone();
        let (peer, local) = transport_conn_addrs(conn.as_ref(), fallback_addr);
        // 闸关早检（bd 9tots）：预期拒发不经 spawn 口 ⇒ compat 拒发 WARN 不触发
        // （9ka5w 同款早返回）；conn 随闭包返回 drop，对端读 EOF（与 spawn 拒发
        // 同结局）。早检与 spawn 间的 TOCTOU 极小窗走下方 Err 分支，同口径计数。
        if plugin_ctx.arm_scope().is_closed() {
            record_closed_scope_reject("vless transport", Some(peer));
            return;
        }
        // §3.5.6 ①类：连接任务归本 inbound 的 arm scope，停机随 scope 取消。
        // spawn 面与任务体各持一份（闭包是 Fn，不可把捕获值移出）。
        let task_ctx = Arc::clone(&plugin_ctx);
        let spawned = plugin_ctx.spawn(async move {
            // TLS 已在 transport hub 内终结，name/alpn 不可得
            if let Err(e) = xray_proxy_vless::handle_connection_with_fallback(
                conn,
                &handler,
                &validator,
                fallbacks,
                peer,
                local,
                String::new(),
                String::new(),
                Some(options),
                None,
                &task_ctx,
            )
            .await
            {
                // Go vless inbound.go:522：拒绝 AtInfo + RemoteAddr。
                tracing::info!(peer = %peer, error = %e, "vless transport connection ended with error");
            }
        });
        if spawned.is_err() {
            // TOCTOU 极小窗（早检后闸才关）：同口径计数 + 分档日志（预期=DEBUG）。
            record_closed_scope_reject("vless transport", Some(peer));
        }
    }))
}

/// trojan transport 分支 ConnHandler。
#[allow(clippy::too_many_arguments)] // 9 参 = TCP/unix 双路径直译签名，打包聚合体属内部 API 变更
pub(crate) fn trojan_transport_on_conn(
    ib: &BuiltInbound,
    ohm: &Arc<SimpleOhm>,
    policy: &Option<Arc<dyn xray_features::policy::PolicyManager>>,
    settings: &xray_transport::dialer::StreamSettings,
    // bd hl8q6：validator 由装配层构造并共享（用户热更句柄）。
    validator: Arc<xray_proxy_trojan::Validator>,
    fallbacks: Option<Arc<xray_proxy_trojan::fallback::FallbackPolicy>>,
    fallback_addr: std::net::SocketAddr,
    ident: &str,
    plugin_ctx: &Arc<xray_frame::PluginContext>,
) -> std::io::Result<xray_transport::listener_registry::ConnHandler> {
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;
    tracing::info!(tag = %ib.tag, addr = %ident, network = %settings.protocol, security = %settings.security, users = validator.get_key_count(), "trojan transport inbound listening");
    let hs_timeout = handshake_timeout_for(policy, 0);
    let plugin_ctx = Arc::clone(plugin_ctx);
    Ok(Arc::new(move |conn| {
        let validator = Arc::clone(&validator);
        let handler = Arc::clone(&handler);
        let fb_policy = fallbacks.clone();
        let (peer, local) = transport_conn_addrs(conn.as_ref(), fallback_addr);
        // 闸关早检（bd 9tots）：预期拒发不经 spawn 口 ⇒ compat 拒发 WARN 不触发
        // （9ka5w 同款早返回）；conn 随闭包返回 drop，对端读 EOF（与 spawn 拒发
        // 同结局）。早检与 spawn 间的 TOCTOU 极小窗走下方 Err 分支，同口径计数。
        if plugin_ctx.arm_scope().is_closed() {
            record_closed_scope_reject("trojan transport", Some(peer));
            return;
        }
        // §3.5.6 ①类：连接任务归本 inbound 的 arm scope，停机随 scope 取消。
        let spawned = plugin_ctx.spawn(async move {
            xray_proxy_trojan::serve_trojan_conn(
                conn,
                validator,
                handler,
                fb_policy,
                peer,
                local,
                String::new(),
                String::new(),
                hs_timeout,
            )
            .await;
        });
        if spawned.is_err() {
            // TOCTOU 极小窗（早检后闸才关）：同口径计数 + 分档日志（预期=DEBUG）。
            record_closed_scope_reject("trojan transport", Some(peer));
        }
    }))
}

/// vmess transport 分支 ConnHandler。
// 8 参 = TCP/unix 双路径直译签名，打包聚合体属内部 API 变更（同 trojan_transport_on_conn 先例）。
#[allow(clippy::too_many_arguments)]
pub(crate) fn vmess_transport_on_conn(
    ib: &BuiltInbound,
    ohm: &Arc<SimpleOhm>,
    policy: &Option<Arc<dyn xray_features::policy::PolicyManager>>,
    settings: &xray_transport::dialer::StreamSettings,
    validator: Arc<xray_proxy_vmess::TimedUserValidator>,
    fallback_addr: std::net::SocketAddr,
    ident: &str,
    plugin_ctx: &Arc<xray_frame::PluginContext>,
) -> std::io::Result<xray_transport::listener_registry::ConnHandler> {
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;
    let history = Arc::new(xray_proxy_vmess::SessionHistory::new());
    // bd txtpo：反重放历史的 30s 周期清理（Go task.Periodic）。清理任务与本臂同一
    // ctx scope——监听器结束即随 scope 收口，任务不会活得比 inbound 久。
    let history_ctx = Arc::clone(plugin_ctx);
    history.start_cleanup(&history_ctx);
    // transport 层无 TLS 时维持裸 TCP 的 drain 防指纹语义（Go：!isTLS → drain）
    let is_drain = !settings.is_tls();
    tracing::info!(tag = %ib.tag, addr = %ident, network = %settings.protocol, security = %settings.security, "vmess transport inbound listening");
    let hs_timeout = handshake_timeout_for(policy, 0);
    let plugin_ctx = Arc::clone(plugin_ctx);
    Ok(Arc::new(move |conn| {
        let handler = Arc::clone(&handler);
        let validator = Arc::clone(&validator);
        let history = Arc::clone(&history);
        let (peer, _local) = transport_conn_addrs(conn.as_ref(), fallback_addr);
        // 闸关早检（bd 9tots）：预期拒发不经 spawn 口 ⇒ compat 拒发 WARN 不触发
        // （9ka5w 同款早返回）；conn 随闭包返回 drop，对端读 EOF（与 spawn 拒发
        // 同结局）。早检与 spawn 间的 TOCTOU 极小窗走下方 Err 分支，同口径计数。
        if plugin_ctx.arm_scope().is_closed() {
            record_closed_scope_reject("vmess transport", Some(peer));
            return;
        }
        // §3.5.6 ①类：连接任务归本 inbound 的 arm scope，停机随 scope 取消。
        let spawned = plugin_ctx.spawn(async move {
            if let Err(e) = xray_proxy_vmess::handle_vmess_connection(
                conn, &handler, &validator, &history, is_drain, hs_timeout,
            )
            .await
            {
                // Go vmess inbound.go:250：拒绝 AtInfo + RemoteAddr。
                tracing::info!(peer = %peer, error = %e, "vmess transport connection ended with error");
            }
        });
        if spawned.is_err() {
            // TOCTOU 极小窗（早检后闸才关）：同口径计数 + 分档日志（预期=DEBUG）。
            record_closed_scope_reject("vmess transport", Some(peer));
        }
    }))
}

/// shadowsocks transport 分支 ConnHandler（Legacy 与 SS2022 统一；含 gRPC
/// 用户管理面登记，对齐 Go proxyman 语义）。
pub(crate) fn ss_transport_on_conn(
    ib: &BuiltInbound,
    ohm: &Arc<SimpleOhm>,
    policy: &Option<Arc<dyn xray_features::policy::PolicyManager>>,
    api: Option<&crate::inbound::InboundRuntime>,
    settings: &xray_transport::dialer::StreamSettings,
    ident: &str,
    plugin_ctx: &Arc<xray_frame::PluginContext>,
) -> std::io::Result<xray_transport::listener_registry::ConnHandler> {
    let mode = parse_ss_inbound_config(&ib.entry.data)?;
    register_ss_user_manager(api, &ib.tag, &mode);
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;
    tracing::info!(tag = %ib.tag, addr = %ident, network = %settings.protocol, security = %settings.security, "ss transport inbound listening");
    let hs_timeout = handshake_timeout_for(policy, 0);
    let plugin_ctx = Arc::clone(plugin_ctx);
    Ok(Arc::new(move |conn| {
        // 闸关早检（bd 9tots）：预期拒发不经 spawn 口 ⇒ compat 拒发 WARN 不触发
        // （9ka5w 同款早返回）；conn 随闭包返回 drop，对端读 EOF（与 spawn 拒发
        // 同结局）。早检与 spawn 间的 TOCTOU 极小窗走下方 Err 分支，同口径计数。
        // （本臂无 peer 解包面，观测行不带 peer 字段。）
        if plugin_ctx.arm_scope().is_closed() {
            record_closed_scope_reject("ss transport", None);
            return;
        }
        let mode = mode.clone();
        let handler = Arc::clone(&handler);
        // §3.5.6 ①类：连接任务归本 inbound 的 arm scope，停机随 scope 取消。
        let spawned = plugin_ctx.spawn(async move {
            ss_mode_conn_pipeline(mode, handler, conn, hs_timeout).await;
        });
        if spawned.is_err() {
            // TOCTOU 极小窗（早检后闸才关）：同口径计数 + 分档日志（预期=DEBUG）。
            record_closed_scope_reject("ss transport", None);
        }
    }))
}

// ============ T4.2 W2：UDS 形态构造器（同一张表的 uds_stream / uds_transport 槽） ============
//
// 表条目把「协议 → 可构造监听形态」收成单源；本节 9 个构造器就是删除前
// `spawn_unix_inbound` / `spawn_unix_transport_inbound` 内联 match 的逐臂搬迁
// （臂内逻辑、日志文案、错误变体与拆分前逐字一致）。UDS listener / 默认 handler
// 由入口绑定后经 ctx 传入，且 ctx 类型不含平台专属类型（listener 走
// `dyn SystemListener`、连接走 `Box<dyn Connection>`），故本节与非 unix 平台同源
// 编译——非 unix 平台永不调用（`spawn_unix_inbound` 有 Unsupported 拒绝臂）。

/// UDS 无 SocketAddr；对齐 Go `UnixConnWrapper.RemoteAddr` 的 `0.0.0.0:0`
/// （TCP 侧同位置传 bind 地址）。
fn uds_fallback_addr() -> std::net::SocketAddr {
    std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
}

/// socks over UDS：与 TCP 走同一份 mixed 复合栈（bd q2crg：socks 端口的 HTTP
/// fallback 与传输层无关，Go `proxy/socks/server.go:38-43` 无条件挂 httpServer）。
pub(crate) fn unix_socks_serve(ctx: UnixInboundCtx<'_>) -> std::io::Result<UnixServe> {
    let UnixInboundCtx { ib, policy, listen, listener, handler, plugin_ctx, .. } = ctx;
    let (config, http_cfg) = parse_socks_http_configs(&ib.entry.data)?;
    let config = Arc::new(config);
    let http_cfg = Arc::new(http_cfg);
    let handshake_timeout = Some(handshake_timeout_for(policy, config.user_level));
    let udp_idle = policy
        .as_ref()
        .map(|pm| pm.policy_for_level(config.user_level).timeout.connection_idle)
        .unwrap_or(xray_features::policy::TimeoutPolicy::default().connection_idle);
    tracing::info!(
        tag = %ib.tag,
        path = %listen,
        "socks5 (uds) inbound listening (http proxy fallback on non-SOCKS first byte)"
    );
    Ok(Box::pin(serve_unix_listener(listener, {
        let handler = Arc::clone(&handler);
        Arc::new(move |conn| {
            let handler = Arc::clone(&handler);
            let config = Arc::clone(&config);
            let http_cfg = Arc::clone(&http_cfg);
            // scope 生命周期锚：连接任务存活期间 arm scope 不 drop
            let task_ctx = Arc::clone(&plugin_ctx);
            plugin_ctx
                .spawn(async move {
                    let peer = conn.remote_addr().ok().flatten().unwrap_or(uds_fallback_addr());
                    serve_mixed_conn(
                        PeekAhead::new(conn),
                        peer,
                        config,
                        http_cfg,
                        handshake_timeout,
                        udp_idle,
                        handler,
                        task_ctx,
                    )
                    .await;
                })
                .expect("arm FxScope is never closed");
        })
    })))
}

/// vless over UDS（裸流；transport 形态见 [`unix_vless_transport`]）。
pub(crate) fn unix_vless_serve(ctx: UnixInboundCtx<'_>) -> std::io::Result<UnixServe> {
    let UnixInboundCtx { ib, listener, handler, plugin_ctx, .. } = ctx;
    let validator: Arc<dyn VlessValidator> = build_vless_validator(&ib.entry.data)?;
    let decryption = build_vless_decryption(&ib.entry.data, plugin_ctx.clone())?;
    let options = VlessInboundOptions { decryption: decryption.clone(), ..Default::default() };
    let fallbacks = build_vless_fallbacks(&ib.entry.data)?;
    tracing::info!(
        tag = %ib.tag,
        users = validator.get_uuid_count(),
        "vless (uds) inbound listening"
    );
    Ok(Box::pin(serve_unix_listener(listener, {
        let handler = Arc::clone(&handler);
        Arc::new(move |conn| {
            let handler = Arc::clone(&handler);
            let validator = Arc::clone(&validator);
            let fallbacks = fallbacks.clone();
            let options = options.clone();
            // scope 生命周期锚：连接任务存活期间 arm scope 不 drop
            let task_ctx = Arc::clone(&plugin_ctx);
            plugin_ctx
                .spawn(async move {
                    let (peer, local) = transport_conn_addrs(conn.as_ref(), uds_fallback_addr());
                    if let Err(e) = xray_proxy_vless::handle_connection_with_fallback(
                        conn,
                        &handler,
                        &validator,
                        fallbacks,
                        peer,
                        local,
                        String::new(),
                        String::new(),
                        Some(options),
                        None,
                        &task_ctx,
                    )
                    .await
                    {
                        tracing::info!(
                            peer = %peer,
                            error = %e,
                            "vless (uds) connection ended with error"
                        );
                    }
                })
                .expect("arm FxScope is never closed");
        })
    })))
}

/// vmess over UDS（裸流；transport 形态见 [`unix_vmess_transport`]）。
pub(crate) fn unix_vmess_serve(ctx: UnixInboundCtx<'_>) -> std::io::Result<UnixServe> {
    let UnixInboundCtx { ib, policy, settings, listener, handler, plugin_ctx, .. } = ctx;
    let validator = build_vmess_validator(&ib.entry.data)?;
    let history = Arc::new(xray_proxy_vmess::SessionHistory::new());
    // bd txtpo：反重放历史的 30s 周期清理（Go task.Periodic），随本 inbound 停机取消。
    history.start_cleanup(&plugin_ctx);
    // security 已 gate 为 none → 与裸 TCP 分支同为 drain 语义。
    let is_drain = !settings.is_tls();
    tracing::info!(tag = %ib.tag, "vmess (uds) inbound listening");
    let hs_timeout = handshake_timeout_for(policy, 0);
    Ok(Box::pin(serve_unix_listener(listener, {
        let handler = Arc::clone(&handler);
        Arc::new(move |conn| {
            let handler = Arc::clone(&handler);
            let validator = Arc::clone(&validator);
            let history = Arc::clone(&history);
            // scope 生命周期锚：连接任务存活期间 arm scope 不 drop
            let task_ctx = Arc::clone(&plugin_ctx);
            plugin_ctx
                .spawn(async move {
                    let _ctx = task_ctx;
                    let (peer, _local) = transport_conn_addrs(conn.as_ref(), uds_fallback_addr());
                    if let Err(e) = xray_proxy_vmess::handle_vmess_connection(
                        conn, &handler, &validator, &history, is_drain, hs_timeout,
                    )
                    .await
                    {
                        tracing::info!(
                            peer = %peer,
                            error = %e,
                            "vmess (uds) connection ended with error"
                        );
                    }
                })
                .expect("arm FxScope is never closed");
        })
    })))
}

/// trojan over UDS（裸流；transport 形态见 [`unix_trojan_transport`]）。
pub(crate) fn unix_trojan_serve(ctx: UnixInboundCtx<'_>) -> std::io::Result<UnixServe> {
    let UnixInboundCtx { ib, policy, listener, handler, plugin_ctx, .. } = ctx;
    let users = build_trojan_users(&ib.entry.data)?;
    let fallbacks = build_trojan_fallbacks(&ib.entry.data)?;
    let validator = Arc::new(xray_proxy_trojan::Validator::new());
    for (_, user) in users {
        if let Err(e) = validator.add(user) {
            tracing::warn!(error = %e, "skip duplicate user during trojan uds inbound init");
        }
    }
    tracing::info!(tag = %ib.tag, "trojan (uds) inbound listening");
    let hs_timeout = handshake_timeout_for(policy, 0);
    Ok(Box::pin(serve_unix_listener(listener, {
        let handler = Arc::clone(&handler);
        Arc::new(move |conn| {
            let handler = Arc::clone(&handler);
            let validator = Arc::clone(&validator);
            let fallbacks = fallbacks.clone();
            // scope 生命周期锚：连接任务存活期间 arm scope 不 drop
            let task_ctx = Arc::clone(&plugin_ctx);
            plugin_ctx
                .spawn(async move {
                    let _ctx = task_ctx;
                    let (peer, local) = transport_conn_addrs(conn.as_ref(), uds_fallback_addr());
                    xray_proxy_trojan::serve_trojan_conn(
                        conn,
                        validator,
                        handler,
                        fallbacks,
                        peer,
                        local,
                        String::new(),
                        String::new(),
                        hs_timeout,
                    )
                    .await;
                })
                .expect("arm FxScope is never closed");
        })
    })))
}

/// shadowsocks over UDS（裸流；transport 形态见 [`unix_shadowsocks_transport`]）。
///
/// shortcut: 仅 legacy AEAD 模式支持 UDS；ss2022 在 bind 前显式 Unsupported
/// （对齐删除前的臂内拒绝，Go 侧的 UDS 支持面待单独对拍）。
pub(crate) fn unix_shadowsocks_serve(ctx: UnixInboundCtx<'_>) -> std::io::Result<UnixServe> {
    let UnixInboundCtx { ib, policy, listener, handler, plugin_ctx, .. } = ctx;
    let inbound = match parse_ss_inbound_config(&ib.entry.data)? {
        SsInboundMode::Legacy(ss_ib) => ss_ib,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("uds inbound '{}': ss2022 not supported over unix socket", ib.tag),
            ));
        },
    };
    tracing::info!(tag = %ib.tag, "shadowsocks (uds) inbound listening");
    let hs_timeout = handshake_timeout_for(policy, 0);
    Ok(Box::pin(serve_unix_listener(listener, {
        let handler = Arc::clone(&handler);
        Arc::new(move |conn| {
            let handler = Arc::clone(&handler);
            let inbound = Arc::clone(&inbound);
            // scope 生命周期锚：连接任务存活期间 arm scope 不 drop
            let task_ctx = Arc::clone(&plugin_ctx);
            plugin_ctx
                .spawn(async move {
                    let _ctx = Arc::clone(&task_ctx);
                    ss_legacy_pipeline(inbound, handler, conn, hs_timeout).await;
                })
                .expect("arm FxScope is never closed");
        })
    })))
}

// ---- UDS 上的 transport 协议：per-conn 构造（与 TCP 分支同一批 on_conn 构造函数） ----

/// vless + transport 协议 over UDS（ws/grpc/kcp/httpupgrade/splithttp）。
pub(crate) fn unix_vless_transport(
    ctx: UnixTransportCtx<'_>,
) -> std::io::Result<xray_transport::listener_registry::ConnHandler> {
    let validator: Arc<dyn VlessValidator> = build_vless_validator(&ctx.ib.entry.data)?;
    // L2 能力句柄：直接消费 ctx 已构造/已接线的 arm ctx（不再就地造第二份）。
    let decryption = build_vless_decryption(&ctx.ib.entry.data, Arc::clone(&ctx.plugin_ctx))?;
    let mut options = VlessInboundOptions {
        decryption: decryption.clone(),
        handshake_timeout: Some(handshake_timeout_for(ctx.policy, 0)),
        ..Default::default()
    };
    apply_vless_reverse(&mut options, &ctx.ib.entry.data, ctx.ohm)?;
    vless_transport_on_conn(
        ctx.ib,
        ctx.ohm,
        ctx.settings,
        validator,
        options,
        uds_fallback_addr(),
        ctx.ident,
        &ctx.plugin_ctx,
    )
}

/// trojan + transport 协议 over UDS。
pub(crate) fn unix_trojan_transport(
    ctx: UnixTransportCtx<'_>,
) -> std::io::Result<xray_transport::listener_registry::ConnHandler> {
    let users = build_trojan_users(&ctx.ib.entry.data)?;
    let fallbacks = build_trojan_fallbacks(&ctx.ib.entry.data)?;
    // bd hl8q6：validator 由装配层构造并共享（用户热更句柄）。
    let validator = build_trojan_validator_shared(&users).map_err(std::io::Error::other)?;
    trojan_transport_on_conn(
        ctx.ib,
        ctx.ohm,
        ctx.policy,
        ctx.settings,
        validator,
        fallbacks,
        uds_fallback_addr(),
        ctx.ident,
        &ctx.plugin_ctx,
    )
}

/// vmess + transport 协议 over UDS。
pub(crate) fn unix_vmess_transport(
    ctx: UnixTransportCtx<'_>,
) -> std::io::Result<xray_transport::listener_registry::ConnHandler> {
    let validator = build_vmess_validator(&ctx.ib.entry.data)?;
    vmess_transport_on_conn(
        ctx.ib,
        ctx.ohm,
        ctx.policy,
        ctx.settings,
        validator,
        uds_fallback_addr(),
        ctx.ident,
        &ctx.plugin_ctx,
    )
}

/// shadowsocks + transport 协议 over UDS。
pub(crate) fn unix_shadowsocks_transport(
    ctx: UnixTransportCtx<'_>,
) -> std::io::Result<xray_transport::listener_registry::ConnHandler> {
    ss_transport_on_conn(
        ctx.ib,
        ctx.ohm,
        ctx.policy,
        ctx.api,
        ctx.settings,
        ctx.ident,
        &ctx.plugin_ctx,
    )
}

// ---- tun：自管监听面（不消费 TCP 地址，入口见 needs_listen_addr=false 直接分派） ----

/// tun inbound。Windows 侧设备（tun-rs wintun）、netstack（smoltcp）、路由/DNS
/// （sysroute）、WFP 泄漏阻断均已实现并真机验证（bd cv3w/ijn7），故与 Go
/// `tun_windows.go` 对齐开放。
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "windows"
))]
pub(crate) fn tun_entry<'a>(ctx: InboundCtx<'a>) -> InboundBuildFut<'a> {
    Box::pin(async move {
        let options = crate::inbound::parse_tun_inbound_config(&ctx.ib.entry.data)?;
        let dispatch = ctx.ohm.get_default_handler().ok_or_else(|| {
            std::io::Error::other("tun inbound requires a default outbound handler")
        })?;
        let handler = xray_proxy_tun::TunInboundHandler::new(&ctx.ib.tag, options, dispatch)
            .await
            .map_err(|e| std::io::Error::other(format!("tun inbound: {e}")))?;
        tracing::info!(tag = %ctx.ib.tag, "tun inbound listening");
        // W4 面 6 例外登记（方案 §2 面 6「不可迁残余 1」）：本构造对外**返回
        // JoinHandle**（调用方 InboundRuntime 契约），改为 scope 托管 = 改公开
        // 契约 + 4 平台门控臂（linux/android/freebsd/windows），收益（1 处 spawn
        // 记账）远小于风险 → 保留裸 spawn，逐点理由登记。
        #[allow(
            clippy::disallowed_methods,
            reason = "②豁免（bd kwevg · §3.5.6）：tun inbound serve 对外返回 JoinHandle（公开契约 + 4 平台门控），改 scope 托管 = 改公开契约；方案 §2 面 6 不可迁残余 1 已举证保留；公共契约外返（§3.5.6 ②类第三项限本两站之一）：`JoinHandle` 是 tun inbound 装配的公开返回值，改 scope 托管即改公开契约"
        )]
        let handle = tokio::spawn(async move {
            if let Err(e) = handler.start().await {
                tracing::error!(error = ?e, "tun inbound stopped");
            }
        });
        Ok(Some(handle))
    })
}

/// 非 tun 支持平台：拒绝臂（错误变体/文案与删除前 `cfg(not)` 臂逐字一致）。
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "windows"
)))]
pub(crate) fn tun_entry<'a>(_ctx: InboundCtx<'a>) -> InboundBuildFut<'a> {
    Box::pin(async move {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN inbound is only supported on Linux/Android/FreeBSD/Windows",
        ))
    })
}

// ============ T4.2 phase 2：查表入口适配器（表值 → phase 1 同一构造函数） ============
// 适配器只做参数解包转发；两路等价性测试见 arm_builders::tests。

use crate::arm_builders::{
    InboundBuildFut, InboundCtx, UnixInboundCtx, UnixServe, UnixTransportCtx,
};

pub(crate) fn socks_entry<'a>(ctx: InboundCtx<'a>) -> InboundBuildFut<'a> {
    Box::pin(build_socks_inbound(
        ctx.ib,
        ctx.ohm,
        ctx.policy,
        ctx.shutdown_token,
        ctx.addr,
        ctx.settings,
        Arc::new(ctx.plugin_ctx),
    ))
}

pub(crate) fn mixed_entry<'a>(ctx: InboundCtx<'a>) -> InboundBuildFut<'a> {
    Box::pin(build_mixed_inbound(
        ctx.ib,
        ctx.ohm,
        ctx.policy,
        ctx.shutdown_token,
        ctx.addr,
        ctx.settings,
        Arc::new(ctx.plugin_ctx),
    ))
}

pub(crate) fn vless_entry<'a>(ctx: InboundCtx<'a>) -> InboundBuildFut<'a> {
    Box::pin(build_vless_inbound(
        ctx.ib,
        ctx.ohm,
        ctx.policy,
        ctx.shutdown_token,
        ctx.addr,
        ctx.api,
        Arc::new(ctx.plugin_ctx),
    ))
}

pub(crate) fn trojan_entry<'a>(ctx: InboundCtx<'a>) -> InboundBuildFut<'a> {
    Box::pin(build_trojan_inbound(
        ctx.ib,
        ctx.ohm,
        ctx.policy,
        ctx.shutdown_token,
        ctx.addr,
        ctx.api,
        Arc::new(ctx.plugin_ctx),
    ))
}

pub(crate) fn vmess_entry<'a>(ctx: InboundCtx<'a>) -> InboundBuildFut<'a> {
    Box::pin(build_vmess_inbound(
        ctx.ib,
        ctx.ohm,
        ctx.policy,
        ctx.shutdown_token,
        ctx.addr,
        ctx.api,
        Arc::new(ctx.plugin_ctx),
    ))
}

pub(crate) fn http_entry<'a>(ctx: InboundCtx<'a>) -> InboundBuildFut<'a> {
    Box::pin(build_http_inbound(
        ctx.ib,
        ctx.ohm,
        ctx.policy,
        ctx.shutdown_token,
        ctx.addr,
        ctx.settings,
        Arc::new(ctx.plugin_ctx),
    ))
}

pub(crate) fn dokodemo_entry<'a>(ctx: InboundCtx<'a>) -> InboundBuildFut<'a> {
    Box::pin(build_dokodemo_inbound(
        ctx.ib,
        ctx.ohm,
        ctx.shutdown_token,
        ctx.addr,
        ctx.settings,
        Arc::new(ctx.plugin_ctx),
    ))
}

pub(crate) fn shadowsocks_entry<'a>(ctx: InboundCtx<'a>) -> InboundBuildFut<'a> {
    Box::pin(build_shadowsocks_inbound(
        ctx.ib,
        ctx.ohm,
        ctx.policy,
        ctx.shutdown_token,
        ctx.addr,
        ctx.api,
        Arc::new(ctx.plugin_ctx),
    ))
}

pub(crate) fn hysteria_entry<'a>(ctx: InboundCtx<'a>) -> InboundBuildFut<'a> {
    Box::pin(build_hysteria_inbound(
        ctx.ib,
        ctx.ohm,
        ctx.shutdown_token,
        ctx.addr,
        ctx.api,
        Arc::new(ctx.plugin_ctx),
    ))
}

pub(crate) fn anytls_entry<'a>(ctx: InboundCtx<'a>) -> InboundBuildFut<'a> {
    Box::pin(build_anytls_inbound(
        ctx.ib,
        ctx.ohm,
        ctx.shutdown_token,
        ctx.addr,
        Arc::new(ctx.plugin_ctx),
    ))
}

pub(crate) fn tuic_entry<'a>(ctx: InboundCtx<'a>) -> InboundBuildFut<'a> {
    Box::pin(build_tuic_inbound(
        ctx.ib,
        ctx.ohm,
        ctx.shutdown_token,
        ctx.addr,
        Arc::new(ctx.plugin_ctx),
    ))
}

pub(crate) fn naive_entry<'a>(ctx: InboundCtx<'a>) -> InboundBuildFut<'a> {
    Box::pin(build_naive_inbound(
        ctx.ib,
        ctx.ohm,
        ctx.shutdown_token,
        ctx.addr,
        Arc::new(ctx.plugin_ctx),
    ))
}

pub(crate) fn wireguard_entry<'a>(ctx: InboundCtx<'a>) -> InboundBuildFut<'a> {
    Box::pin(build_wireguard_inbound(
        ctx.ib,
        ctx.ohm,
        ctx.shutdown_token,
        ctx.addr,
        ctx.api,
        Arc::new(ctx.plugin_ctx),
    ))
}

pub(crate) fn dns_entry<'a>(ctx: InboundCtx<'a>) -> InboundBuildFut<'a> {
    Box::pin(build_dns_inbound(
        ctx.ib,
        ctx.policy,
        ctx.shutdown_token,
        ctx.addr,
        ctx.settings,
        Arc::new(ctx.plugin_ctx),
    ))
}

pub(crate) fn loopback_entry<'a>(ctx: InboundCtx<'a>) -> InboundBuildFut<'a> {
    Box::pin(build_loopback_inbound(ctx.ib))
}

pub(crate) fn blackhole_entry<'a>(ctx: InboundCtx<'a>) -> InboundBuildFut<'a> {
    Box::pin(build_blackhole_inbound(
        ctx.ib,
        ctx.shutdown_token,
        ctx.addr,
        Arc::new(ctx.plugin_ctx),
    ))
}

pub(crate) fn freedom_entry<'a>(ctx: InboundCtx<'a>) -> InboundBuildFut<'a> {
    Box::pin(build_freedom_inbound(
        ctx.ib,
        ctx.ohm,
        ctx.shutdown_token,
        ctx.addr,
        Arc::new(ctx.plugin_ctx),
    ))
}

#[cfg(test)]
mod socks_http_fallback_tests {
    //! D-S1 回归：Go `proxy/socks/server.go:38-43` 无条件构造 httpServer +
    //! `:87-90` 首字节 ∉ {0x05,0x04} → 按 HTTP 请求解析 —— Go 的 socks 端口
    //! 同时服务 SOCKS5 与 HTTP 代理。本模块直接打生产构造函数
    //! [`build_socks_inbound`]（构造臂是唯一入口），断言 HTTP CONNECT 能被解析、
    //! 回 `200 Connection established`，并把目标交给 dispatch。
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use xray_app_dispatcher::default::{DispatchHandler, PinFuture};
    use xray_conf::{BuiltEntry, BuiltInbound};

    use super::*;

    /// dispatch 桩：只把 dest 回传（不拨号），经 channel 交回测试体。
    #[derive(Debug)]
    struct DestRecorder(tokio::sync::mpsc::UnboundedSender<String>);

    impl DispatchHandler for DestRecorder {
        fn tag(&self) -> &str {
            "dest-recorder"
        }

        fn dispatch(
            &self,
            dest: &xray_common::net::destination::Destination,
            _link: xray_transport::link::Link,
        ) -> PinFuture<()> {
            let _ = self.0.send(format!("{dest:?}"));
            Box::pin(async {})
        }
    }

    fn socks_inbound(port: u16) -> BuiltInbound {
        BuiltInbound {
            entry: BuiltEntry { kind: "socks".into(), data: b"{}".to_vec() },
            tag: "socks-http-fallback".into(),
            port: Some(port),
            listen: Some("127.0.0.1".into()),
            stream_settings_json: None,
            sniffing_json: None,
        }
    }

    #[tokio::test]
    async fn socks_inbound_serves_http_proxy_on_non_socks_first_byte() {
        // 端口先绑 0 取号再释放：bind 由构造函数自己完成（同端口随即复用）。
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let ohm = Arc::new(SimpleOhm::new());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        ohm.set_default(Arc::new(DestRecorder(tx)) as Arc<dyn xray_app_dispatcher::DispatchHandler>);

        let ib = socks_inbound(port);
        let _serve = build_socks_inbound(
            &ib,
            ohm,
            None,
            CancellationToken::new(),
            &format!("127.0.0.1:{port}"),
            &xray_transport::dialer::StreamSettings::default(),
            Arc::new(xray_frame::PluginContext::for_plugin("socks-http-fallback")),
        )
        .await
        .expect("socks inbound must build")
        .expect("socks inbound must spawn");

        // 首字节 'C'(0x43) ∉ {0x05,0x04} → Go 走 HTTP 代理路径
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        // CONNECT 回包固定 39 字节（Go `proxy/http/server.go:177`）
        let mut head = [0u8; 39];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut head))
            .await
            .expect("socks 端口的 HTTP fallback 必须回 CONNECT 响应")
            .unwrap();
        assert_eq!(&head, b"HTTP/1.1 200 Connection established\r\n\r\n");

        let dest = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("HTTP CONNECT 的目标必须交给 dispatch")
            .expect("recorder 通道未关");
        assert!(dest.contains("example.com"), "dispatch 目标须是 CONNECT 目标: {dest}");
    }
}

#[cfg(test)]
mod transport_on_conn_shutdown_tests {
    //! §3.5.6 ①类验收（审计 2026-11-08 code-quality / architecture）：四条
    //! transport on_conn 臂的连接任务改经 `PluginContext::spawn` 托管后，
    //! arm scope 已关时的**新连接必须被拒并留日志**——不静默丢、也不复用
    //! 已关 scope 假装成功。bd 9tots 起日志口径 = 预期丢弃 DEBUG 档 + 计数
    //! （泵逃逸才限频 WARN）。
    use std::time::Duration;

    use tokio::io::AsyncReadExt;
    use xray_app_dispatcher::default::SimpleOhm;
    use xray_conf::{BuiltEntry, BuiltInbound};
    use xray_transport::connection::{Connection, DuplexConnection};

    use super::*;

    fn freedom_ohm() -> Arc<SimpleOhm> {
        let ohm = Arc::new(SimpleOhm::new());
        ohm.set_default(Arc::new(xray_app_dispatcher::default::DialBridge::new(
            "freedom",
            xray_proxy_freedom::make_freedom_dial_fn(),
        )) as Arc<dyn xray_app_dispatcher::DispatchHandler>);
        ohm
    }

    fn trojan_ib() -> BuiltInbound {
        BuiltInbound {
            entry: BuiltEntry {
                kind: "trojan".into(),
                data: br#"{"clients":[{"password":"shutdownpw"}]}"#.to_vec(),
            },
            tag: "trojan-shutdown".into(),
            port: Some(12829),
            listen: Some("127.0.0.1".into()),
            stream_settings_json: None,
            sniffing_json: None,
        }
    }

    /// tracing 事件捕获（同 `inbound.rs` `WarnCapture` 口径：无 tracing-subscriber 依赖）。
    /// bd 9tots 起预期拒发落 DEBUG → 捕获阈值同步降到 DEBUG，行首带级别标记
    /// 供「不得刷 WARN」断言。
    #[derive(Clone, Default)]
    struct WarnCapture(Arc<parking_lot::Mutex<Vec<String>>>);
    impl tracing::Subscriber for WarnCapture {
        fn enabled(&self, meta: &tracing::Metadata<'_>) -> bool {
            meta.level() <= &tracing::Level::DEBUG
        }

        fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            struct Fmt(String);
            impl tracing::field::Visit for Fmt {
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    self.0.push_str(&format!("{}={value} ", field.name()));
                }

                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    self.0.push_str(&format!("{}={value:?} ", field.name()));
                }
            }
            let mut v = Fmt(String::new());
            event.record(&mut v);
            self.0.lock().push(format!("[{}] {}", event.metadata().level(), v.0));
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    #[tokio::test]
    async fn closed_arm_scope_rejects_connection_logs_debug_and_counts() {
        let ohm = freedom_ohm();
        let ib = trojan_ib();
        let arm = Arc::new(xray_frame::PluginContext::for_plugin("trojan"));
        let on_conn = trojan_transport_on_conn(
            &ib,
            &ohm,
            &None,
            &xray_transport::dialer::StreamSettings::default(),
            Arc::new(xray_proxy_trojan::Validator::new()),
            None,
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:12829",
            &arm,
        )
        .expect("on_conn 构造");

        // 停机：arm scope 关闸（同 `Instance::close` 的 arm 级联形态）。
        arm.arm_scope().close();
        assert!(arm.arm_scope().is_closed(), "关闸后 accepting 闸必须为关");

        let before = transport_closed_scope_rejected_conns();
        let capture = WarnCapture::default();
        let (mut peer, server) = tokio::io::duplex(64);
        tracing::subscriber::with_default(capture.clone(), || {
            on_conn(Box::new(DuplexConnection::new(server)) as Box<dyn Connection>);
        });

        let lines = capture.0.lock().join("\n");
        assert!(lines.contains("arm scope closed at shutdown"), "必须留诊断日志: {lines:?}");
        assert!(lines.contains("[DEBUG]"), "预期拒发必须落 DEBUG 档（9tots）: {lines:?}");
        assert!(!lines.contains("[WARN]"), "排空竞态不得刷 WARN（9tots 口径）: {lines:?}");
        assert_eq!(
            transport_closed_scope_rejected_conns(),
            before + 1,
            "闸关拒发必须计数: {lines:?}"
        );
        assert_eq!(arm.arm_scope().fx().in_flight(), 0, "关闸后不得再入 scope");

        // 被拒连接必须 drop（不是静默挂住）：对端读到 EOF。
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), peer.read(&mut buf))
            .await
            .expect("被拒连接必须立即关闭（peer 读不得超时）")
            .expect("read");
        assert_eq!(n, 0, "被拒连接必须 drop（peer 读 EOF）");
    }

    /// 判窗与限频的分类账本（bd 9tots）：合成时间线驱动**本地**实例，
    /// 不触全局单例（防测试间互染）。
    #[test]
    fn reject_meter_classifies_drain_race_and_pump_escape() {
        let meter = ArmRejectMeter::new();
        let t0 = std::time::Instant::now();
        // 判窗内：预期排空竞态
        assert!(matches!(meter.record(t0), RejectVerdict::DrainRace { rejected: 1 }));
        assert!(matches!(
            meter.record(t0 + Duration::from_secs(9)),
            RejectVerdict::DrainRace { rejected: 2 }
        ));
        // 判窗外首条：泵逃逸，首击必报
        assert!(matches!(
            meter.record(t0 + REJECT_ANOMALY_GRACE),
            RejectVerdict::PumpEscaped { rejected: 3, emit: true }
        ));
        // 限频窗内：抑制但计数照记
        assert!(matches!(
            meter.record(t0 + REJECT_ANOMALY_GRACE + Duration::from_secs(1)),
            RejectVerdict::PumpEscaped { rejected: 4, emit: false }
        ));
        // 限频窗过期：重新放行
        assert!(matches!(
            meter.record(t0 + REJECT_ANOMALY_GRACE + Duration::from_secs(1) + REJECT_LOG_WINDOW),
            RejectVerdict::PumpEscaped { rejected: 5, emit: true }
        ));
        assert_eq!(meter.rejected_total(), 5, "累计计数必须覆盖两类");
    }
}

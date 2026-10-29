//! inbound 协议臂构造函数（T4.2 phase 1 抽臂）。
//!
//! 每个 [`crate::inbound::spawn_one_inbound`] match 臂的构造逻辑原样搬迁至此。
//! unix（UDS）变体的 5 个臂（socks/vless/vmess/trojan/shadowsocks）serve 栈不同
//! （`serve_unix_listener` + per-conn closure），无法在行为零变化前提下与 TCP 臂
//! 合并成同一构造函数，维持原状（见报告）；其协议构造逻辑经 `crate::inbound`
//! 同一批具名解析函数与本模块共享，无第二份副本。

use std::sync::Arc;

use skeleton_infra::fx::FxScope;
use tokio::{net::UdpSocket, task::JoinHandle};
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
use xray_transport::system_listener::InboundTcpListener;

use crate::{
    inbound::{
        DokodemoTcpOptions, HysteriaTcpDispatch, InboundRuntime, build_tls_acceptor,
        build_trojan_fallbacks, build_trojan_users, build_vless_decryption, build_vless_fallbacks,
        build_vless_validator, build_vmess_validator, handshake_timeout_for, inbound_tcpmask,
        inbound_udpmask, is_transport_listener_protocol, parse_anytls_tls_acceptor,
        parse_blackhole_inbound_response, parse_dns_inbound_config, parse_dokodemo_settings,
        parse_freedom_inbound_dest, parse_http_config, parse_hysteria_inbound_config,
        parse_loopback_config, parse_naive_inbound_settings, parse_reality_config,
        parse_socks_server_config, parse_ss_inbound_config, parse_tuic_inbound_config,
        parse_wireguard_inbound_config, register_ss_user_manager, serve_dns, serve_dokodemo,
        serve_dokodemo_udp_on, serve_http, serve_mixed, serve_reality_trojan, serve_reality_vless,
        serve_ss, spawn_inbound_serve, spawn_transport_listener_inbound, ss_mode_conn_pipeline,
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
    let config = Arc::new(parse_socks_server_config(&ib.entry.data)?);
    // Go `proxy/socks/server.go:38-43`：socks 端口的 Server **无条件**构造一个
    // httpServer，首字节 ∉ {0x05,0x04} 即转 `httpServer.ProcessWithFirstbyte`
    // （`:87-90`）——即 Go 的 socks 端口同时服务 SOCKS5 与 HTTP 代理。故这里复用
    // mixed 的 serve 栈（同一 listener 上 socks + http），不另造一份 HTTP 实现。
    // HTTP 侧只在 socks 配了 password 认证时继承 accounts（`:47-49`），userLevel
    // 与 socks 同源（同一个 settings JSON）。
    let mut http_cfg = if ib.entry.data.is_empty() {
        // 空 settings = `{}`（Go 零值配置）；`parse_http_config` 不接受空切片。
        parse_http_config(b"{}")?
    } else {
        parse_http_config(&ib.entry.data)?
    };
    if config.auth_type != xray_proxy_socks::config::AuthType::Password {
        http_cfg.accounts.clear();
    }
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

pub(crate) async fn build_vless_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    policy: Option<Arc<dyn xray_features::policy::PolicyManager>>,
    shutdown_token: CancellationToken,
    addr: &str,
    plugin_ctx: std::sync::Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let validator: Arc<dyn VlessValidator> = build_vless_validator(&ib.entry.data)?;
    // ENC decryption（Go inbound.go:104-114 handler.decryption）：settings
    // 级 "mlkem768x25519plus.*" 字符串 → handler 级共享 ServerInstance。
    let decryption = build_vless_decryption(&ib.entry.data, Arc::clone(&plugin_ctx))?;
    let mut options = VlessInboundOptions {
        decryption: decryption.clone(),
        // sm80④：policy Timeouts.Handshake 下传（Go inbound.go:281-284）
        handshake_timeout: Some(handshake_timeout_for(&policy, 0)),
        ..Default::default()
    };
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
        let on_conn =
            vless_transport_on_conn(ib, &ohm, &settings, validator, options, bind_addr, addr)?;
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
        Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, async move {
            serve_reality_vless(listener, ohm, validator, reality, Some(options)).await
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
        Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, async move {
            serve_vless(listener, ohm, validator, tls, fallbacks, Some(options)).await
        })))
    }
}

pub(crate) async fn build_trojan_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    policy: Option<Arc<dyn xray_features::policy::PolicyManager>>,
    shutdown_token: CancellationToken,
    addr: &str,
    plugin_ctx: std::sync::Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let users = build_trojan_users(&ib.entry.data)?;
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
            ib, &ohm, &policy, &settings, users, fallbacks, bind_addr, addr,
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
        tracing::info!(tag = %ib.tag, addr = %addr, users = users.len(), fallback = %reality.fallback_dest, "trojan+reality inbound listening");
        Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, async move {
            serve_reality_trojan(
                listener,
                ohm,
                users,
                fallbacks,
                reality,
                handshake_timeout_for(&policy, 0),
            )
            .await
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
        tracing::info!(tag = %ib.tag, addr = %addr, users = users.len(), tls = tls.is_some(), "trojan inbound listening");
        Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, {
            let plugin_ctx = Arc::clone(&plugin_ctx);
            async move {
                serve_trojan(
                    plugin_ctx,
                    listener,
                    ohm,
                    users,
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
    plugin_ctx: std::sync::Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let validator = build_vmess_validator(&ib.entry.data)?;
    let settings =
        xray_transport::dialer::StreamSettings::from_json(ib.stream_settings_json.as_ref());
    if is_transport_listener_protocol(&settings.protocol) {
        // transport 分支：listener_registry 承载，TLS 在 hub 内终结。
        let bind_addr: std::net::SocketAddr = addr.parse().map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("parse addr: {e}"))
        })?;
        let on_conn =
            vmess_transport_on_conn(ib, &ohm, &policy, &settings, validator, bind_addr, addr)?;
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
            let _ = h.join().await;
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
        let on_conn = ss_transport_on_conn(ib, &ohm, &policy, api, &settings, addr)?;
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
    // finalmask.udp（bd 05js，Go udp/hub.go:61-62）：同端口 UDP relay 装配
    let inbound_udp_mask = inbound_udpmask(&settings)?;
    tracing::info!(tag = %ib.tag, addr = %addr, "shadowsocks inbound listening");
    Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, {
        let plugin_ctx = Arc::clone(&plugin_ctx);
        async move {
            serve_ss(
                listener,
                ohm,
                inbound,
                handshake_timeout_for(&policy, 0),
                inbound_udp_mask,
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
    plugin_ctx: std::sync::Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let bind_addr: std::net::SocketAddr = addr.parse().map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("parse addr: {e}"))
    })?;
    let (config, factory) =
        parse_hysteria_inbound_config(&ib.entry.data, bind_addr, ib.stream_settings_json.as_ref())?;
    let dispatch = ohm.get_default_handler().ok_or_else(|| {
        std::io::Error::other("hysteria inbound requires a default outbound handler")
    })?;
    let handler =
        xray_proxy_hysteria::HysteriaInboundHandler::new(&ib.tag, config, bind_addr, factory)
            .map_err(|e| std::io::Error::other(format!("hysteria inbound: {e}")))?
            .with_dispatcher(Some(Arc::new(HysteriaTcpDispatch(Arc::clone(&dispatch)))))
            .with_udp_dispatcher(Some(dispatch));
    tracing::info!(tag = %ib.tag, addr = %addr, "hysteria inbound listening");
    Ok(Some(spawn_inbound_serve(&plugin_ctx, ib.tag.clone(), shutdown_token, async move {
        handler.start().await.map_err(|e| std::io::Error::other(format!("{e}")))
    })))
}

// anytls inbound：AnytlsInboundHandler impl InboundHandler
pub(crate) async fn build_anytls_inbound(
    ib: &BuiltInbound,
    shutdown_token: CancellationToken,
    addr: &str,
    plugin_ctx: std::sync::Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let bind_addr: std::net::SocketAddr = addr.parse().map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("parse addr: {e}"))
    })?;
    let (tls_acceptor, password) = parse_anytls_tls_acceptor(&ib.entry.data)?;
    let handler = xray_proxy_anytls::AnytlsInboundHandler::new(&ib.tag, bind_addr, tls_acceptor)
        .with_password(password);
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
    // 保活持有（anytls 同款）：handler drop = abort accept loop 关端口，
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
    plugin_ctx: std::sync::Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let (config, listen_port) = parse_wireguard_inbound_config(&ib.entry.data)?;
    let dispatch = ohm.get_default_handler().ok_or_else(|| {
        std::io::Error::other("wireguard inbound requires a default outbound handler")
    })?;
    let handler =
        xray_proxy_wireguard::WireguardInboundHandler::new(&ib.tag, &config, listen_port, dispatch)
            .await
            .map_err(|e| std::io::Error::other(format!("wireguard inbound: {e}")))?;
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
    let udp = UdpSocket::bind(addr).await?;
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
    let response = parse_blackhole_inbound_response(&ib.entry.data);
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

// ============ transport 分支 ConnHandler 共享构造（bd lfrg） ============
//
// TCP（`spawn_transport_listener_inbound`）与 unix（`spawn_unix_transport_inbound`）
// 两条监听路径共用同一份 per-协议 on_conn 构造——unix 路径禁另写一份。
// `fallback_addr` 作 peer/local 解析兜底：TCP = bind 地址，unix = 0.0.0.0:0
// （对齐 Go UnixConnWrapper.RemoteAddr）。

/// vless transport 分支 ConnHandler（ws/grpc/kcp/httpupgrade/splithttp）。
pub(crate) fn vless_transport_on_conn(
    ib: &BuiltInbound,
    ohm: &Arc<SimpleOhm>,
    settings: &xray_transport::dialer::StreamSettings,
    validator: Arc<dyn VlessValidator>,
    mut options: VlessInboundOptions,
    fallback_addr: std::net::SocketAddr,
    ident: &str,
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
    Ok(Arc::new(move |conn| {
        let handler = Arc::clone(&handler);
        let validator = Arc::clone(&validator);
        let fallbacks = fallbacks.clone();
        let options = options.clone();
        #[allow(
            clippy::disallowed_methods,
            reason = "inbound 连接处理任务（vless fallback，每连接）；显式脱管：上游 drain 缺口——FxScope 的 JoinSet 无收割接口，每连接登记一条会无界累积，登记收益为负；句柄随连接任务自然结束（bd hj3jf 裁定）"
        )]
        tokio::spawn(async move {
            let (peer, local) = transport_conn_addrs(conn.as_ref(), fallback_addr);
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
            )
            .await
            {
                // Go vless inbound.go:522：拒绝 AtInfo + RemoteAddr。
                tracing::info!(peer = %peer, error = %e, "vless transport connection ended with error");
            }
        });
    }))
}

/// trojan transport 分支 ConnHandler。
#[allow(clippy::too_many_arguments)] // 8 参 = TCP/unix 双路径直译签名，打包聚合体属内部 API 变更
pub(crate) fn trojan_transport_on_conn(
    ib: &BuiltInbound,
    ohm: &Arc<SimpleOhm>,
    policy: &Option<Arc<dyn xray_features::policy::PolicyManager>>,
    settings: &xray_transport::dialer::StreamSettings,
    users: std::collections::HashMap<String, xray_proxy_trojan::MemoryUser>,
    fallbacks: Option<Arc<xray_proxy_trojan::fallback::FallbackPolicy>>,
    fallback_addr: std::net::SocketAddr,
    ident: &str,
) -> std::io::Result<xray_transport::listener_registry::ConnHandler> {
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;
    let validator = Arc::new(xray_proxy_trojan::Validator::new());
    for (_, user) in users {
        if let Err(e) = validator.add(user) {
            tracing::warn!(error = %e, "skip duplicate user during trojan transport inbound init");
        }
    }
    tracing::info!(tag = %ib.tag, addr = %ident, network = %settings.protocol, security = %settings.security, users = validator.get_key_count(), "trojan transport inbound listening");
    let hs_timeout = handshake_timeout_for(policy, 0);
    Ok(Arc::new(move |conn| {
        let validator = Arc::clone(&validator);
        let handler = Arc::clone(&handler);
        let fb_policy = fallbacks.clone();
        #[allow(
            clippy::disallowed_methods,
            reason = "inbound 连接处理任务（trojan fallback，每连接）；显式脱管：上游 drain 缺口——FxScope 的 JoinSet 无收割接口，每连接登记一条会无界累积，登记收益为负；句柄随连接任务自然结束（bd hj3jf 裁定）"
        )]
        tokio::spawn(async move {
            let (peer, local) = transport_conn_addrs(conn.as_ref(), fallback_addr);
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
    }))
}

/// vmess transport 分支 ConnHandler。
pub(crate) fn vmess_transport_on_conn(
    ib: &BuiltInbound,
    ohm: &Arc<SimpleOhm>,
    policy: &Option<Arc<dyn xray_features::policy::PolicyManager>>,
    settings: &xray_transport::dialer::StreamSettings,
    validator: Arc<xray_proxy_vmess::TimedUserValidator>,
    fallback_addr: std::net::SocketAddr,
    ident: &str,
) -> std::io::Result<xray_transport::listener_registry::ConnHandler> {
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;
    let history = Arc::new(xray_proxy_vmess::SessionHistory::new());
    // transport 层无 TLS 时维持裸 TCP 的 drain 防指纹语义（Go：!isTLS → drain）
    let is_drain = !settings.is_tls();
    tracing::info!(tag = %ib.tag, addr = %ident, network = %settings.protocol, security = %settings.security, "vmess transport inbound listening");
    let hs_timeout = handshake_timeout_for(policy, 0);
    Ok(Arc::new(move |conn| {
        let handler = Arc::clone(&handler);
        let validator = Arc::clone(&validator);
        let history = Arc::clone(&history);
        #[allow(
            clippy::disallowed_methods,
            reason = "inbound 连接处理任务（vmess，每连接）；显式脱管：上游 drain 缺口——FxScope 的 JoinSet 无收割接口，每连接登记一条会无界累积，登记收益为负；句柄随连接任务自然结束（bd hj3jf 裁定）"
        )]
        tokio::spawn(async move {
            let (peer, _local) = transport_conn_addrs(conn.as_ref(), fallback_addr);
            if let Err(e) = xray_proxy_vmess::handle_vmess_connection(
                conn, &handler, &validator, &history, is_drain, hs_timeout,
            )
            .await
            {
                // Go vmess inbound.go:250：拒绝 AtInfo + RemoteAddr。
                tracing::info!(peer = %peer, error = %e, "vmess transport connection ended with error");
            }
        });
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
) -> std::io::Result<xray_transport::listener_registry::ConnHandler> {
    let mode = parse_ss_inbound_config(&ib.entry.data)?;
    register_ss_user_manager(api, &ib.tag, &mode);
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;
    tracing::info!(tag = %ib.tag, addr = %ident, network = %settings.protocol, security = %settings.security, "ss transport inbound listening");
    let hs_timeout = handshake_timeout_for(policy, 0);
    // W4 面 6：SS 泵归每连接 scope——per-conn pipeline 需 arm ctx（就地构造，
    // 与 transport listener inbound 的派发点构造同源）。
    // bd a9xgp：宿主登记表接线（api 缺省 = 独立构造不接线）——停机级联取消
    // ConnScope 泵。
    let mut ctx_builder = crate::arm_builders::arm_plugin_ctx(ib.entry.kind.as_str());
    if let Some(api) = api {
        ctx_builder = ctx_builder.with_arm_registry(Arc::clone(api.arm_scopes()));
    }
    let plugin_ctx = std::sync::Arc::new(ctx_builder);
    Ok(Arc::new(move |conn| {
        let mode = mode.clone();
        let handler = Arc::clone(&handler);
        let pipeline_ctx = Arc::clone(&plugin_ctx);
        #[allow(
            clippy::disallowed_methods,
            reason = "inbound 连接处理任务（ss/ss2022，每连接）；显式脱管：上游 drain 缺口——FxScope 的 JoinSet 无收割接口，每连接登记一条会无界累积，登记收益为负；句柄随连接任务自然结束（bd hj3jf 裁定）"
        )]
        tokio::spawn(async move {
            ss_mode_conn_pipeline(mode, handler, conn, hs_timeout, pipeline_ctx).await;
        });
    }))
}

// ============ T4.2 phase 2：查表入口适配器（表值 → phase 1 同一构造函数） ============
// 适配器只做参数解包转发；两路等价性测试见 arm_builders::tests。

use crate::arm_builders::{InboundBuildFut, InboundCtx};

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
        Arc::new(ctx.plugin_ctx),
    ))
}

pub(crate) fn anytls_entry<'a>(ctx: InboundCtx<'a>) -> InboundBuildFut<'a> {
    Box::pin(build_anytls_inbound(ctx.ib, ctx.shutdown_token, ctx.addr, Arc::new(ctx.plugin_ctx)))
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
    Box::pin(build_wireguard_inbound(ctx.ib, ctx.ohm, ctx.shutdown_token, Arc::new(ctx.plugin_ctx)))
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

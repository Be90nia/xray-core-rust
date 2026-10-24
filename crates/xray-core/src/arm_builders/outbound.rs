//! outbound 协议臂构造函数（T4.2 phase 1 抽臂）。
//!
//! [`crate::outbound::build_protocol_handler`] 的 18 个 match 协议臂构造逻辑
//! 原样搬迁至此：臂前的公共前解析（proxy_chain_tag / targetStrategy /
//! sendThrough / sockopt 硬错）仍留在调用方，各构造函数只承载臂内逻辑。
//! 入参/出参类型、错误变体、日志文案、注册顺序、失败语义与拆分前一致。
//! 非 linux 平台的 `tun` 拒绝臂本就是一行错误字面量，未抽取（维持原状）。

use std::{future::Future, sync::Arc};

use xray_app_dispatcher::{DispatchHandler, default::DialBridge};
use xray_common::net::destination::Destination;
use xray_conf::BuiltOutbound;
use xray_proxy_freedom::DomainStrategy;
use xray_proxy_hysteria::HysteriaConfig;
use xray_proxy_loopback::LoopbackSink;

use crate::outbound::{
    BuildError, DnsDispatchBridge, MuxBridge, SocksUdpDispatch, TuicUdpDispatch, TuicUdpParams,
    build_dns_outbound_config, build_hysteria_tls_config, build_tuic_rustls_config,
    dns_idle_timeout_for, parse_anytls_config, parse_blackhole_response, parse_dokodemo_config,
    parse_freedom_config, parse_hysteria_config, parse_loopback_config, parse_mux_config,
    parse_naive_config, parse_socks_outbound_config, parse_stream_settings, parse_trojan_config,
    parse_tuic_config, parse_vless_config, parse_wireguard_config, wrap_bridge,
    wrap_dial_with_send_through, wrap_dial_with_target_strategy,
};

/// freedom 出站构造（T4.2 phase 1 自 inbound.rs/outbound.rs 臂内原样搬迁；
/// dialerProxy/finalRules/入站默认规则语义见行内注释，行为零变化）。
#[allow(clippy::type_complexity)] // 返回三组件装配形态（与 wrap_bridge 同型）
pub(crate) fn build_freedom_outbound(
    ob: &BuiltOutbound,
    proxy_chain_tag: Option<String>,
    target_strategy: Option<DomainStrategy>,
    dns: Option<&Arc<xray_app_dns::DnsService>>,
    // 入站 tag → 默认 final rule 类型（freedom 默认规则按入站协议名推导，
    // Go getDefaultFinalRule；API 单构建路径传空表 = 无默认规则）
    inbound_default_rules: &std::collections::HashMap<String, xray_proxy_freedom::DefaultRuleType>,
    // sm80③/czwu：session policy manager（Go freedom.go:393/222-225）。
    // freedom 按 settings.userLevel 查档位，其余协议固定 level 0。
    policy_manager: Option<&dyn xray_features::policy::PolicyManager>,
    send_through: Option<&xray_transport::system_dialer::SendThroughSpec>,
) -> std::result::Result<
    (Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>),
    BuildError,
> {
    let config =
        parse_freedom_config(&ob.entry.data).map_err(|e| BuildError::Parse(e.to_string()))?;
    let noises = config.noises.clone();
    let destination_override = config.destination_override.clone();
    let domain_strategy = config.domain_strategy;
    // czwu③：freedom settings.userLevel → 出站腿 policy 档位
    // （Go freedom.go:222-225 policyManager.ForLevel(config.UserLevel)）
    let bridge_policy = policy_manager.map(|pm| {
        xray_features::policy::PolicyManager::policy_for_level(pm, config.user_level).timeout
    });
    // #6742（Go freedom.go:193-198 Init 早退 + :263-265 defaultRule=nil）：
    // dialerProxy（sockopt.dialerProxy，含 transportLayer 注入）或 proxy_chain
    // （proxySettings.tag）时 freedom 非最终出站——finalRules 不构建（配了则
    // warn），入站默认规则不注入（TCP/UDP 的 defaultRule 恒 None）。
    let stream_dialer_proxy = ob
        .stream_settings_json
        .as_ref()
        .and_then(|v| v.get("sockopt"))
        .and_then(|v| v.get("dialerProxy"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let uses_dialer_proxy = proxy_chain_tag.is_some() || !stream_dialer_proxy.is_empty();
    // finalRules 预构建（Go Handler.Init :199-207；构建失败的项跳过）
    let final_rules: Vec<xray_proxy_freedom::FinalRule> = if uses_dialer_proxy {
        if !config.final_rules.is_empty() {
            tracing::warn!(
                tag = %ob.tag,
                "The \"finalRules\" setting is ignored when \"sockopt.dialerProxy\" is set, since freedom is not the final outbound."
            );
        }
        Vec::new()
    } else {
        // Go freedom.go:208-214 Init：规则构建失败硬错拒启（此前 .ok() 静默丢弃）。
        let mut rules = Vec::with_capacity(config.final_rules.len());
        for rc in &config.final_rules {
            rules.push(xray_proxy_freedom::FinalRule::build(rc).map_err(|e| {
                BuildError::Parse(format!("freedom: failed to build final rule: {e}"))
            })?);
        }
        rules
    };
    // sockopt.dialerProxy 下沉拨号层（Go freedom.go:58 + dialer.go:270-279 redirect）
    let dial_fn =
        xray_proxy_freedom::make_freedom_dial_fn_with_sockopt(config, stream_dialer_proxy);
    let dial_fn = match target_strategy {
        Some(s) => wrap_dial_with_target_strategy(dial_fn, s, dns.cloned()),
        None => dial_fn,
    };
    // sendThrough：TCP 分支经 dial_fn 包装（每次拨号设 DIAL_SRC scope）
    let dial_fn = match send_through {
        Some(spec) => wrap_dial_with_send_through(dial_fn, spec.clone()),
        None => dial_fn,
    };
    // TCP 走 DialBridge（fragment/override/proxyProtocol 经 DialFn 消费），UDP 走
    // FreedomDispatchBridge（noises + override + finalRules + 入站默认规则）
    let tcp_bridge = Arc::new(DialBridge::new(ob.tag.clone(), dial_fn));
    if let Some(p) = bridge_policy {
        tcp_bridge.with_policy(p.clone());
    }
    // txno-splice：freedom 是 Go `ob.CanSpliceCopy = 1`（freedom.go:260）
    // 的唯一置 1 点——DialBridge 桥接判定处据此放行 splice 快路径准入。
    tcp_bridge.set_splice_outbound(true);
    let mut bridge =
        xray_proxy_freedom::FreedomDispatchBridge::from_bridge(Arc::clone(&tcp_bridge))
            .with_noises(noises)
            .with_destination_override(destination_override)
            .with_final_rules(final_rules)
            .with_domain_strategy(domain_strategy);
    if !uses_dialer_proxy {
        bridge = bridge.with_inbound_default_rules(inbound_default_rules.clone());
    }
    if let Some(spec) = send_through {
        bridge = bridge.with_send_through(spec.clone());
    }
    let handler = Arc::new(bridge) as Arc<dyn DispatchHandler>;
    let bridge_ref = if proxy_chain_tag.is_some() { Some(tcp_bridge) } else { None };
    Ok((handler, bridge_ref, proxy_chain_tag))
}

#[allow(clippy::type_complexity)] // 返回三组件装配形态（与 wrap_bridge 同型）
pub(crate) fn build_vless_outbound(
    ob: &BuiltOutbound,
    proxy_chain_tag: Option<String>,
    target_strategy: Option<DomainStrategy>,
    dns: Option<&Arc<xray_app_dns::DnsService>>,
    policy_manager: Option<&dyn xray_features::policy::PolicyManager>,
    send_through: Option<&xray_transport::system_dialer::SendThroughSpec>,
) -> std::result::Result<
    (Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>),
    BuildError,
> {
    let config = parse_vless_config(&ob.entry.data)?;
    let config = config.with_stream_settings(parse_stream_settings(&ob.stream_settings_json));
    let dial_fn = xray_proxy_vless::make_vless_dial_fn(Arc::new(config));
    wrap_bridge(
        ob.tag.clone(),
        dial_fn,
        &proxy_chain_tag,
        target_strategy,
        dns,
        send_through,
        policy_manager,
    )
}

#[allow(clippy::type_complexity)] // 返回三组件装配形态（与 wrap_bridge 同型）
pub(crate) fn build_trojan_outbound(
    ob: &BuiltOutbound,
    proxy_chain_tag: Option<String>,
    target_strategy: Option<DomainStrategy>,
    dns: Option<&Arc<xray_app_dns::DnsService>>,
    policy_manager: Option<&dyn xray_features::policy::PolicyManager>,
    send_through: Option<&xray_transport::system_dialer::SendThroughSpec>,
) -> std::result::Result<
    (Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>),
    BuildError,
> {
    let config = parse_trojan_config(&ob.entry.data)?;
    let config = config.with_stream_settings(parse_stream_settings(&ob.stream_settings_json));
    let dial_fn = xray_proxy_trojan::make_trojan_dial_fn(Arc::new(config));
    wrap_bridge(
        ob.tag.clone(),
        dial_fn,
        &proxy_chain_tag,
        target_strategy,
        dns,
        send_through,
        policy_manager,
    )
}

#[allow(clippy::type_complexity)] // 返回三组件装配形态（与 wrap_bridge 同型）
pub(crate) fn build_blackhole_outbound(
    ob: &BuiltOutbound,
) -> std::result::Result<
    (Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>),
    BuildError,
> {
    let response = parse_blackhole_response(&ob.entry.data)?;
    let handler =
        Arc::new(xray_proxy_blackhole::BlackholeHandler::with_response(ob.tag.clone(), response))
            as Arc<dyn DispatchHandler>;
    Ok((handler, None, None))
}

#[allow(clippy::type_complexity)] // 返回三组件装配形态（与 wrap_bridge 同型）
pub(crate) fn build_socks_outbound(
    ob: &BuiltOutbound,
    proxy_chain_tag: Option<String>,
    target_strategy: Option<DomainStrategy>,
    dns: Option<&Arc<xray_app_dns::DnsService>>,
    policy_manager: Option<&dyn xray_features::policy::PolicyManager>,
    send_through: Option<&xray_transport::system_dialer::SendThroughSpec>,
) -> std::result::Result<
    (Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>),
    BuildError,
> {
    let (server_addr, auth) = parse_socks_outbound_config(&ob.entry.data)?;
    let udp_cfg = match auth {
        Some((u, p)) => xray_proxy_socks::ClientConfig::new_with_auth(server_addr.clone(), u, p),
        None => xray_proxy_socks::ClientConfig::new_noauth(server_addr.clone()),
    };
    let client = Arc::new(xray_proxy_socks::SocksClient::new(udp_cfg.clone()));
    let dial_fn = xray_proxy_socks::make_socks_dial_fn(client);
    // UDP 票 ft58 S2：SocksUdpClient ASSOCIATE 会话 + udp::relay 泵，
    // 此前 UDP 目的地被 DialBridge 当 TCP 载荷静默降级。
    let dial_fn = match target_strategy {
        Some(st) => wrap_dial_with_target_strategy(dial_fn, st, dns.cloned()),
        None => dial_fn,
    };
    let dial_fn = match send_through {
        Some(spec) => wrap_dial_with_send_through(dial_fn, spec.clone()),
        None => dial_fn,
    };
    let tcp_bridge = Arc::new(DialBridge::new(ob.tag.clone(), dial_fn));
    if let Some(pm) = policy_manager {
        tcp_bridge
            .with_policy(xray_features::policy::PolicyManager::policy_for_level(pm, 0).timeout);
    }
    let dispatch = SocksUdpDispatch { tag: ob.tag.clone(), tcp: Arc::clone(&tcp_bridge), udp_cfg };
    let handler = Arc::new(dispatch) as Arc<dyn DispatchHandler>;
    let bridge_ref = if proxy_chain_tag.is_some() { Some(tcp_bridge) } else { None };
    Ok((handler, bridge_ref, proxy_chain_tag))
}

#[allow(clippy::type_complexity)] // 返回三组件装配形态（与 wrap_bridge 同型）
pub(crate) fn build_mux_outbound(
    ob: &BuiltOutbound,
    mux_bridges: &mut Vec<(Arc<MuxBridge>, Option<String>)>,
) -> std::result::Result<
    (Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>),
    BuildError,
> {
    let (concurrency, via_tag) = parse_mux_config(&ob.entry.data)?;
    let (bridge, _slot) = MuxBridge::new(ob.tag.clone(), concurrency);
    let bridge = Arc::new(bridge);
    mux_bridges.push((Arc::clone(&bridge), via_tag));
    let handler = bridge as Arc<dyn DispatchHandler>;
    Ok((handler, None, None))
}

#[allow(clippy::type_complexity)] // 返回三组件装配形态（与 wrap_bridge 同型）
pub(crate) fn build_vmess_outbound(
    ob: &BuiltOutbound,
    proxy_chain_tag: Option<String>,
    target_strategy: Option<DomainStrategy>,
    dns: Option<&Arc<xray_app_dns::DnsService>>,
    policy_manager: Option<&dyn xray_features::policy::PolicyManager>,
    send_through: Option<&xray_transport::system_dialer::SendThroughSpec>,
) -> std::result::Result<
    (Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>),
    BuildError,
> {
    let config = xray_proxy_vmess::parse_vmess_config(&ob.entry.data)?;
    let config = config.with_stream_settings(parse_stream_settings(&ob.stream_settings_json));
    let dial_fn = xray_proxy_vmess::make_vmess_dial_fn(Arc::new(config));
    wrap_bridge(
        ob.tag.clone(),
        dial_fn,
        &proxy_chain_tag,
        target_strategy,
        dns,
        send_through,
        policy_manager,
    )
}

#[allow(clippy::type_complexity)] // 返回三组件装配形态（与 wrap_bridge 同型）
pub(crate) fn build_shadowsocks_outbound(
    ob: &BuiltOutbound,
    proxy_chain_tag: Option<String>,
    target_strategy: Option<DomainStrategy>,
    dns: Option<&Arc<xray_app_dns::DnsService>>,
    policy_manager: Option<&dyn xray_features::policy::PolicyManager>,
    send_through: Option<&xray_transport::system_dialer::SendThroughSpec>,
) -> std::result::Result<
    (Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>),
    BuildError,
> {
    let config = xray_proxy_ss::parse_ss_config(&ob.entry.data)?;
    let config = config.with_stream_settings(parse_stream_settings(&ob.stream_settings_json));
    let dial_fn = xray_proxy_ss::make_ss_dial_fn(Arc::new(config));
    wrap_bridge(
        ob.tag.clone(),
        dial_fn,
        &proxy_chain_tag,
        target_strategy,
        dns,
        send_through,
        policy_manager,
    )
}

#[allow(clippy::type_complexity)] // 返回三组件装配形态（与 wrap_bridge 同型）
pub(crate) fn build_hysteria_outbound(
    ob: &BuiltOutbound,
    proxy_chain_tag: Option<String>,
    target_strategy: Option<DomainStrategy>,
    dns: Option<&Arc<xray_app_dns::DnsService>>,
    policy_manager: Option<&dyn xray_features::policy::PolicyManager>,
    send_through: Option<&xray_transport::system_dialer::SendThroughSpec>,
) -> std::result::Result<
    (Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>),
    BuildError,
> {
    let (server_addr, auth, server_name) = parse_hysteria_config(&ob.entry.data)?;
    let stream_settings =
        xray_transport::dialer::StreamSettings::from_json(ob.stream_settings_json.as_ref());
    // Go 客户端 settings 不含 auth：它在 streamSettings.hysteriaSettings.auth
    // （infra/conf/transport_method.go HysteriaConfig）。
    let auth = if auth.is_empty() {
        ob.stream_settings_json
            .as_ref()
            .and_then(|v| v.get("hysteriaSettings"))
            .and_then(|v| v.get("auth"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    } else {
        auth
    };
    // tlsSettings.serverName 覆盖 settings 推导（Go tls.Config ServerName 优先级）。
    let server_name = stream_settings
        .security_json
        .as_ref()
        .and_then(|v| v.get("serverName"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map_or_else(|| server_name, str::to_string);
    let config = HysteriaConfig::new(&server_addr, &auth).with_server_name(&server_name);
    let tls_config = build_hysteria_tls_config(
        &stream_settings.security,
        stream_settings.security_json.as_ref(),
    )
    .map_err(|e| format!("hysteria streamSettings: {e}"))?;
    let obfs = xray_transport_hysteria::salamander_socket::parse_udp_obfs(
        stream_settings.finalmask_json.as_ref(),
    )
    .map_err(|e| format!("hysteria finalmask: {e}"))?;
    // streamSettings.finalmask.quicParams → HysteriaConfig（brutal/CC/windows/keepAlive）
    let quic_params = xray_transport_hysteria::quic_params::parse_quic_params(
        stream_settings.finalmask_json.as_ref(),
    )
    .map_err(|e| format!("hysteria quicParams: {e}"))?
    .unwrap_or_else(xray_transport_hysteria::quic_params::default_hysteria_quic_params);
    let config = config.with_quic_params(quic_params);
    let transport = xray_transport_hysteria::hysteria_transport::QuinnHysteriaTransport::new(
        tls_config,
        "0.0.0.0:0".parse().map_err(|e| format!("bind addr: {e}"))?,
    )
    .map_err(|e| format!("hysteria transport: {e}"))?
    // QUIC 端点缓冲：streamSettings.sockopt（缺省 = 8MB 下限语义）。
    .with_sockopt(stream_settings.socket_options())
    .with_obfs(obfs);
    let dial_fn = xray_proxy_hysteria::make_hysteria_dial_fn(config, Arc::new(transport));
    wrap_bridge(
        ob.tag.clone(),
        dial_fn,
        &proxy_chain_tag,
        target_strategy,
        dns,
        send_through,
        policy_manager,
    )
}

#[allow(clippy::type_complexity)] // 返回三组件装配形态（与 wrap_bridge 同型）
pub(crate) fn build_anytls_outbound(
    ob: &BuiltOutbound,
    proxy_chain_tag: Option<String>,
    target_strategy: Option<DomainStrategy>,
    dns: Option<&Arc<xray_app_dns::DnsService>>,
    policy_manager: Option<&dyn xray_features::policy::PolicyManager>,
    send_through: Option<&xray_transport::system_dialer::SendThroughSpec>,
) -> std::result::Result<
    (Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>),
    BuildError,
> {
    let config = parse_anytls_config(&ob.entry.data)?;
    // streamSettings.sockopt → dial_system（mark/dialerProxy/happyEyeballs/
    // domainStrategy，bd n65u）；network/security 段由 anytls 协议自持
    // TLS，不消费。
    let sockopt =
        xray_transport::dialer::StreamSettings::from_json(ob.stream_settings_json.as_ref())
            .socket_options();
    let client = Arc::new(xray_proxy_anytls::AnytlsClient::new(config.with_sockopt(sockopt)));
    let dial_fn = xray_proxy_anytls::make_anytls_dial_fn(client);
    wrap_bridge(
        ob.tag.clone(),
        dial_fn,
        &proxy_chain_tag,
        target_strategy,
        dns,
        send_through,
        policy_manager,
    )
}

#[allow(clippy::type_complexity)] // 返回三组件装配形态（与 wrap_bridge 同型）
pub(crate) fn build_tuic_outbound(
    ob: &BuiltOutbound,
    proxy_chain_tag: Option<String>,
    target_strategy: Option<DomainStrategy>,
    dns: Option<&Arc<xray_app_dns::DnsService>>,
    policy_manager: Option<&dyn xray_features::policy::PolicyManager>,
    send_through: Option<&xray_transport::system_dialer::SendThroughSpec>,
) -> std::result::Result<
    (Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>),
    BuildError,
> {
    let s = parse_tuic_config(&ob.entry.data)?;
    // streamSettings.tlsSettings.pinnedPeerCertSha256 → 证书钉扎验证器
    // （tuic 自持 QUIC TLS，不经 transport 层 xray-tls 客户端装配，需在
    // 此接线；interop #36：自签服务端以 pin 验证替代 webpki 链验证）。
    let pinned_verifier = if s.insecure {
        None
    } else {
        let tls_json = ob.stream_settings_json.as_ref().and_then(|ss| ss.get("tlsSettings"));
        // 非 string（数组等手误）置 true，让 build_server_cert_verifier →
        // parse_pinned_hashes 报类型错拒启，而非静默丢 pin（bd zl5t）。
        let has_pins = tls_json
            .and_then(|j| j.get("pinnedPeerCertSha256"))
            .is_some_and(|v| !v.is_null() && v.as_str().is_none_or(|s| !s.is_empty()));
        if has_pins {
            xray_tls::client_config::build_server_cert_verifier(tls_json)
                .map_err(|e| format!("tuic pinned verifier: {e}"))?
        } else {
            None
        }
    };
    let rustls_config = build_tuic_rustls_config(
        &s.alpn,
        s.reduce_rtt,
        s.insecure,
        s.certificate.as_deref(),
        pinned_verifier,
    )?;
    let options = xray_proxy_tuic::TuicConnectOptions {
        congestion_control: s.congestion_control,
        heartbeat: s.heartbeat,
        udp_relay_mode: s.udp_relay_mode,
        brutal_up_bps: s.brutal_up_bps,
        // QUIC 端点缓冲：streamSettings.sockopt（缺省 = 8MB 下限语义）。
        sockopt: xray_transport::dialer::StreamSettings::from_json(
            ob.stream_settings_json.as_ref(),
        )
        .socket_options(),
    };
    let dial_fn = xray_proxy_tuic::make_tuic_dial_fn_lazy(
        s.server_addr.clone(),
        s.server_name.clone(),
        s.uuid,
        s.password.clone(),
        Arc::clone(&rustls_config),
        options.clone(),
    );
    // TCP 走 DialBridge（targetStrategy/sendThrough 经 dial_fn 包装）；
    // UDP 票 z9gp：XUDP 帧 ↔ TuicUdpAssoc（quic uni-stream / native datagram
    // 按 udp_relay_mode），对齐 freedom/hysteria 出站 UDP 形态。
    let dial_fn = match target_strategy {
        Some(st) => wrap_dial_with_target_strategy(dial_fn, st, dns.cloned()),
        None => dial_fn,
    };
    let dial_fn = match send_through {
        Some(spec) => wrap_dial_with_send_through(dial_fn, spec.clone()),
        None => dial_fn,
    };
    let tcp_bridge = Arc::new(DialBridge::new(ob.tag.clone(), dial_fn));
    if let Some(pm) = policy_manager {
        tcp_bridge
            .with_policy(xray_features::policy::PolicyManager::policy_for_level(pm, 0).timeout);
    }
    let udp_params = Arc::new(TuicUdpParams {
        server_addr: s.server_addr,
        server_name: s.server_name,
        uuid: s.uuid,
        password: s.password,
        rustls_config,
        options,
    });
    let dispatch =
        TuicUdpDispatch { tag: ob.tag.clone(), tcp: Arc::clone(&tcp_bridge), params: udp_params };
    let handler = Arc::new(dispatch) as Arc<dyn DispatchHandler>;
    let bridge_ref = if proxy_chain_tag.is_some() { Some(tcp_bridge) } else { None };
    Ok((handler, bridge_ref, proxy_chain_tag))
}

#[allow(clippy::type_complexity)] // 返回三组件装配形态（与 wrap_bridge 同型）
pub(crate) fn build_wireguard_outbound(
    ob: &BuiltOutbound,
    proxy_chain_tag: Option<String>,
    target_strategy: Option<DomainStrategy>,
    dns: Option<&Arc<xray_app_dns::DnsService>>,
    policy_manager: Option<&dyn xray_features::policy::PolicyManager>,
    send_through: Option<&xray_transport::system_dialer::SendThroughSpec>,
) -> std::result::Result<
    (Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>),
    BuildError,
> {
    let config = parse_wireguard_config(&ob.entry.data)?;
    // Go handler.go:242 把 Handler 自身作为 internet.Dialer 传给
    // proxy.Process；handler.go:274-302——ProxySettings.Tag 非空时 WG
    // 自身 UDP 经 chained outbound（如 socks）拨号（pipe + Dispatch）。
    // Rust 经 DIALER_PROXY_HOOK 同构管道：sockopt.dialer_proxy=tag →
    // dial_system 重定向到 tag 对应 handler（register_outbounds 注册）。
    let system_dialer: Option<xray_app_dispatcher::default::DialFn> =
        proxy_chain_tag.as_ref().map(|chain_tag| {
            let tag = chain_tag.clone();
            Arc::new(move |dest: &Destination| {
                let dest = dest.clone();
                let tag = tag.clone();
                Box::pin(async move {
                    let sockopt = xray_transport::sockopt::SocketOptions {
                        dialer_proxy: tag,
                        ..Default::default()
                    };
                    xray_transport::system_dialer::dial_system(&dest, &sockopt)
                        .await
                        .map_err(|e| format!("wireguard chain dial: {e}"))
                })
                    as std::pin::Pin<
                        Box<
                            dyn Future<
                                    Output = std::result::Result<
                                        Box<dyn xray_transport::connection::Connection>,
                                        String,
                                    >,
                                > + Send,
                        >,
                    >
            }) as xray_app_dispatcher::default::DialFn
        });
    let dial_fn = xray_proxy_wireguard::make_wireguard_dial_fn(config, dns.cloned(), system_dialer);
    wrap_bridge(
        ob.tag.clone(),
        dial_fn,
        &proxy_chain_tag,
        target_strategy,
        dns,
        send_through,
        policy_manager,
    )
}

#[allow(clippy::type_complexity)] // 返回三组件装配形态（与 wrap_bridge 同型）
pub(crate) fn build_dns_outbound(
    ob: &BuiltOutbound,
    dns: Option<&Arc<xray_app_dns::DnsService>>,
    policy_manager: Option<&dyn xray_features::policy::PolicyManager>,
) -> std::result::Result<
    (Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>),
    BuildError,
> {
    let cfg = build_dns_outbound_config(&ob.entry.data)?;
    // G14（Go dns.go:85）：h.timeout = ForLevel(config.UserLevel)
    // .Timeouts.ConnectionIdle——超时 policy 驱动，无 manager 显式回退 + warn。
    let dns_idle = dns_idle_timeout_for(policy_manager, cfg.user_level);
    let handler = xray_proxy_dns::Handler::init(&cfg, dns_idle);
    let bridge = DnsDispatchBridge::new(ob.tag.clone(), handler, dns.cloned());
    Ok((Arc::new(bridge) as Arc<dyn DispatchHandler>, None, None))
}

#[allow(clippy::type_complexity)] // 返回三组件装配形态（与 wrap_bridge 同型）
pub(crate) fn build_loopback_outbound(
    ob: &BuiltOutbound,
    loopback_sink: Option<Arc<dyn LoopbackSink>>,
) -> std::result::Result<
    (Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>),
    BuildError,
> {
    // Go loopback.go:56-62：sniffing 经 BuildSniffingRequest 注入重分发；
    // sink 由生产装配注入（functions.rs），per-handler sniffing 透传到
    // DispatcherLoopbackSink → dispatch_link。
    let (inbound_tag, sniffing) = parse_loopback_config(&ob.entry.data)?;
    let handler =
        xray_proxy_loopback::LoopbackHandler::with_inbound_tag(ob.tag.clone(), inbound_tag)
            .with_sniffing_request(sniffing);
    let handler = match loopback_sink {
        Some(sink) => handler.with_sink(sink),
        None => handler,
    };
    Ok((Arc::new(handler) as Arc<dyn DispatchHandler>, None, None))
}

#[allow(clippy::type_complexity)] // 返回三组件装配形态（与 wrap_bridge 同型）
pub(crate) fn build_http_outbound(
    ob: &BuiltOutbound,
    proxy_chain_tag: Option<String>,
    target_strategy: Option<DomainStrategy>,
    dns: Option<&Arc<xray_app_dns::DnsService>>,
    policy_manager: Option<&dyn xray_features::policy::PolicyManager>,
    send_through: Option<&xray_transport::system_dialer::SendThroughSpec>,
) -> std::result::Result<
    (Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>),
    BuildError,
> {
    let config = xray_proxy_http::parse_http_config(&ob.entry.data)?;
    let config = config.with_stream_settings(parse_stream_settings(&ob.stream_settings_json));
    let dial_fn = xray_proxy_http::make_http_dial_fn(Arc::new(config));
    wrap_bridge(
        ob.tag.clone(),
        dial_fn,
        &proxy_chain_tag,
        target_strategy,
        dns,
        send_through,
        policy_manager,
    )
}

#[allow(clippy::type_complexity)] // 返回三组件装配形态（与 wrap_bridge 同型）
pub(crate) fn build_naive_outbound(
    ob: &BuiltOutbound,
    proxy_chain_tag: Option<String>,
    target_strategy: Option<DomainStrategy>,
    dns: Option<&Arc<xray_app_dns::DnsService>>,
    policy_manager: Option<&dyn xray_features::policy::PolicyManager>,
    send_through: Option<&xray_transport::system_dialer::SendThroughSpec>,
) -> std::result::Result<
    (Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>),
    BuildError,
> {
    let config = parse_naive_config(&ob.entry.data)?;
    let dial_fn = xray_transport_naive::make_naive_dial_fn(config);
    wrap_bridge(
        ob.tag.clone(),
        dial_fn,
        &proxy_chain_tag,
        target_strategy,
        dns,
        send_through,
        policy_manager,
    )
}

#[allow(clippy::type_complexity)] // 返回三组件装配形态（与 wrap_bridge 同型）
pub(crate) fn build_dokodemo_outbound(
    ob: &BuiltOutbound,
    proxy_chain_tag: Option<String>,
    target_strategy: Option<DomainStrategy>,
    dns: Option<&Arc<xray_app_dns::DnsService>>,
    policy_manager: Option<&dyn xray_features::policy::PolicyManager>,
    send_through: Option<&xray_transport::system_dialer::SendThroughSpec>,
) -> std::result::Result<
    (Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>),
    BuildError,
> {
    let config = parse_dokodemo_config(&ob.entry.data)?;
    let dial_fn = xray_proxy_dokodemo::make_dokodemo_dial_fn(config);
    wrap_bridge(
        ob.tag.clone(),
        dial_fn,
        &proxy_chain_tag,
        target_strategy,
        dns,
        send_through,
        policy_manager,
    )
}

#[allow(clippy::type_complexity)] // 返回三组件装配形态（与 wrap_bridge 同型）
#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
pub(crate) fn build_tun_outbound(
    ob: &BuiltOutbound,
    proxy_chain_tag: Option<String>,
    target_strategy: Option<DomainStrategy>,
    dns: Option<&Arc<xray_app_dns::DnsService>>,
    policy_manager: Option<&dyn xray_features::policy::PolicyManager>,
    send_through: Option<&xray_transport::system_dialer::SendThroughSpec>,
) -> std::result::Result<
    (Arc<dyn DispatchHandler>, Option<Arc<DialBridge>>, Option<String>),
    BuildError,
> {
    let dial_fn = xray_proxy_tun::make_tun_dial_fn();
    wrap_bridge(
        ob.tag.clone(),
        dial_fn,
        &proxy_chain_tag,
        target_strategy,
        dns,
        send_through,
        policy_manager,
    )
}

// ============ T4.2 phase 2：查表入口适配器（表值 → phase 1 同一构造函数） ============
// 适配器只做参数解包转发；两路等价性测试见 arm_builders::tests。

use crate::arm_builders::{OutboundCtx, OutboundResult};

pub(crate) fn freedom_entry<'a, 'b>(ctx: OutboundCtx<'a, 'b>) -> OutboundResult {
    build_freedom_outbound(
        ctx.ob,
        ctx.proxy_chain_tag,
        ctx.target_strategy,
        ctx.dns,
        ctx.inbound_default_rules,
        ctx.policy_manager,
        ctx.send_through,
    )
}

pub(crate) fn vless_entry<'a, 'b>(ctx: OutboundCtx<'a, 'b>) -> OutboundResult {
    build_vless_outbound(
        ctx.ob,
        ctx.proxy_chain_tag,
        ctx.target_strategy,
        ctx.dns,
        ctx.policy_manager,
        ctx.send_through,
    )
}

pub(crate) fn trojan_entry<'a, 'b>(ctx: OutboundCtx<'a, 'b>) -> OutboundResult {
    build_trojan_outbound(
        ctx.ob,
        ctx.proxy_chain_tag,
        ctx.target_strategy,
        ctx.dns,
        ctx.policy_manager,
        ctx.send_through,
    )
}

pub(crate) fn blackhole_entry<'a, 'b>(ctx: OutboundCtx<'a, 'b>) -> OutboundResult {
    build_blackhole_outbound(ctx.ob)
}

pub(crate) fn socks_entry<'a, 'b>(ctx: OutboundCtx<'a, 'b>) -> OutboundResult {
    build_socks_outbound(
        ctx.ob,
        ctx.proxy_chain_tag,
        ctx.target_strategy,
        ctx.dns,
        ctx.policy_manager,
        ctx.send_through,
    )
}

pub(crate) fn mux_entry<'a, 'b>(ctx: OutboundCtx<'a, 'b>) -> OutboundResult {
    build_mux_outbound(ctx.ob, ctx.mux_bridges)
}

pub(crate) fn vmess_entry<'a, 'b>(ctx: OutboundCtx<'a, 'b>) -> OutboundResult {
    build_vmess_outbound(
        ctx.ob,
        ctx.proxy_chain_tag,
        ctx.target_strategy,
        ctx.dns,
        ctx.policy_manager,
        ctx.send_through,
    )
}

pub(crate) fn shadowsocks_entry<'a, 'b>(ctx: OutboundCtx<'a, 'b>) -> OutboundResult {
    build_shadowsocks_outbound(
        ctx.ob,
        ctx.proxy_chain_tag,
        ctx.target_strategy,
        ctx.dns,
        ctx.policy_manager,
        ctx.send_through,
    )
}

pub(crate) fn hysteria_entry<'a, 'b>(ctx: OutboundCtx<'a, 'b>) -> OutboundResult {
    build_hysteria_outbound(
        ctx.ob,
        ctx.proxy_chain_tag,
        ctx.target_strategy,
        ctx.dns,
        ctx.policy_manager,
        ctx.send_through,
    )
}

pub(crate) fn anytls_entry<'a, 'b>(ctx: OutboundCtx<'a, 'b>) -> OutboundResult {
    build_anytls_outbound(
        ctx.ob,
        ctx.proxy_chain_tag,
        ctx.target_strategy,
        ctx.dns,
        ctx.policy_manager,
        ctx.send_through,
    )
}

pub(crate) fn tuic_entry<'a, 'b>(ctx: OutboundCtx<'a, 'b>) -> OutboundResult {
    build_tuic_outbound(
        ctx.ob,
        ctx.proxy_chain_tag,
        ctx.target_strategy,
        ctx.dns,
        ctx.policy_manager,
        ctx.send_through,
    )
}

pub(crate) fn wireguard_entry<'a, 'b>(ctx: OutboundCtx<'a, 'b>) -> OutboundResult {
    build_wireguard_outbound(
        ctx.ob,
        ctx.proxy_chain_tag,
        ctx.target_strategy,
        ctx.dns,
        ctx.policy_manager,
        ctx.send_through,
    )
}

pub(crate) fn dns_entry<'a, 'b>(ctx: OutboundCtx<'a, 'b>) -> OutboundResult {
    build_dns_outbound(ctx.ob, ctx.dns, ctx.policy_manager)
}

pub(crate) fn loopback_entry<'a, 'b>(ctx: OutboundCtx<'a, 'b>) -> OutboundResult {
    build_loopback_outbound(ctx.ob, ctx.loopback_sink)
}

pub(crate) fn http_entry<'a, 'b>(ctx: OutboundCtx<'a, 'b>) -> OutboundResult {
    build_http_outbound(
        ctx.ob,
        ctx.proxy_chain_tag,
        ctx.target_strategy,
        ctx.dns,
        ctx.policy_manager,
        ctx.send_through,
    )
}

pub(crate) fn naive_entry<'a, 'b>(ctx: OutboundCtx<'a, 'b>) -> OutboundResult {
    build_naive_outbound(
        ctx.ob,
        ctx.proxy_chain_tag,
        ctx.target_strategy,
        ctx.dns,
        ctx.policy_manager,
        ctx.send_through,
    )
}

pub(crate) fn dokodemo_entry<'a, 'b>(ctx: OutboundCtx<'a, 'b>) -> OutboundResult {
    build_dokodemo_outbound(
        ctx.ob,
        ctx.proxy_chain_tag,
        ctx.target_strategy,
        ctx.dns,
        ctx.policy_manager,
        ctx.send_through,
    )
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
pub(crate) fn tun_entry<'a, 'b>(ctx: OutboundCtx<'a, 'b>) -> OutboundResult {
    build_tun_outbound(
        ctx.ob,
        ctx.proxy_chain_tag,
        ctx.target_strategy,
        ctx.dns,
        ctx.policy_manager,
        ctx.send_through,
    )
}

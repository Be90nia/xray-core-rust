//! WebSocket transport dialer + listener 注册：
//!
//! 对应 Go `transport/internet/websocket/dialer.go::init()` 中的
//! `internet.RegisterTransportDialer(protocolName, Dial(...))` 和
//! `transport/internet/websocket/hub.go::init()` 中的
//! `internet.RegisterTransportListener(protocolName, ListenWS)`。
//!
//! ## 调用
//!
//! 进程启动时调用一次 [`register_dialer`] 和 [`register_listener`]；
//!
//! 对应 Go `transport/internet/websocket/dialer.go::init()` 中的
//! `internet.RegisterTransportDialer(protocolName, Dial(...))`。
//!
//! ## 调用
//!
//! 进程启动时调用一次 [`register_dialer`]；幂等——重复注册的 `AlreadyExists` 被忽略。

use std::{io, net::SocketAddr, sync::Arc};

use xray_common::net::destination::Destination;
use xray_transport::{
    accept_policy::{AcceptErrorKind, backoff_if_resource, supervise_accept_loop},
    connection::Connection,
    dialer::{StreamSettings, TransportDialFn, register_transport_dialer},
    listener_registry::{
        ConnHandler, TransportListenFn, TransportListener, register_transport_listener,
    },
};

use crate::{
    client::{DelayDialConn, DialFactory, DialParams, dial_with_params},
    config::Config,
    error::WsError,
    pool::{PoolKey, WsConnectionPool, global_pool},
};

/// 注册 WebSocket transport dialer。
///
/// 协议名同时注册 `"ws"` 和 `"websocket"`——Go 端用 `"websocket"`，JSON `network`
/// 字段在客户端配置里常写 `"ws"`，两者都映射到本 dialer。
///
/// 幂等：重复调用忽略 `AlreadyExists`（对齐 Go `init()` 在测试中多次执行的容错）。
pub fn register_dialer() -> io::Result<()> {
    let dialer: TransportDialFn = Arc::new(move |dest, _sockopt, settings| {
        // TransportDialFn 返回 'static future，必须在进入 async block 前拥有数据。
        let dest = dest.clone();
        let settings = settings.clone();
        Box::pin(async move { dial_ws(&dest, &settings).await })
    });
    // ponytail: 重复注册忽略——主代理与测试可能并发触发注册。
    let _ = register_transport_dialer("ws", dialer.clone());
    let _ = register_transport_dialer("websocket", dialer);
    Ok(())
}

/// 注册 WebSocket transport listener。
///
/// 协议名同时注册 `"ws"` 和 `"websocket"`，与 [`register_dialer`] 一致。
///
/// 当前实现：绑定 TCP + spawn accept loop（每个新连接做 WS 握手后调用 ConnHandler）。
/// TLS 包装由 stream settings 的 security 字段决定——`"tls"` 时自动包装 TLS accept。
///
/// 幂等：重复调用忽略 `AlreadyExists`。
pub fn register_listener() -> io::Result<()> {
    let listen_fn: TransportListenFn = Arc::new(move |addr, settings, sockopt, handler| {
        let settings = settings.clone();
        let handler = handler.clone();
        let trusted = sockopt.trusted_x_forwarded_for.clone();
        Box::pin(async move { listen_ws(addr, &settings, &handler, trusted).await })
    });
    // ponytail: 重复注册忽略——主代理与测试可能并发触发注册。
    let _ = register_transport_listener("ws", listen_fn.clone());
    let _ = register_transport_listener("websocket", listen_fn);
    Ok(())
}

/// 注册 WebSocket transport 的 unix 监听（对应 Go hub.go:100-104 `port==0`
/// → `net.UnixAddr` 分支）。
///
/// 协议名同时注册 `"ws"` 和 `"websocket"`，与 [`register_listener`] 一致。
/// 必须在使用 `listener_registry::listen_unix("ws", ...)` 之前调用。
/// 幂等：重复调用忽略 `AlreadyExists`。
#[cfg(unix)]
pub fn register_unix_listener() -> io::Result<()> {
    use xray_transport::listener_registry::{
        UnixTransportListenFn, register_transport_unix_listener,
    };
    let listen_fn: UnixTransportListenFn = Arc::new(move |path, settings, sockopt, handler| {
        Box::pin(async move { listen_unix_ws(path, settings, sockopt, handler).await })
    });
    // ponytail: 重复注册忽略——主代理与测试可能并发触发注册。
    let _ = register_transport_unix_listener("ws", listen_fn.clone());
    let _ = register_transport_unix_listener("websocket", listen_fn);
    Ok(())
}

/// 实际监听：解析 wsSettings → bind WsListener → spawn accept loop。
///
/// `trusted` = `sockopt.trustedXForwardedFor`（Go hub.go:117-121 socketSettings
/// 透传给 requestHandler；空名单 = 永不采纳 XFF）。
async fn listen_ws(
    addr: SocketAddr,
    settings: &StreamSettings,
    handler: &ConnHandler,
    trusted: Vec<String>,
) -> io::Result<Box<dyn TransportListener>> {
    let config = parse_ws_config(settings.transport_json.as_ref())?;
    let ws_config = Arc::new(config);

    let mut ws_listener =
        crate::server::WsListener::bind(addr, ws_config.clone()).await.map_err(io::Error::other)?;
    ws_listener.trusted_x_forwarded_for = trusted;

    // finalmask（bd dppv）：Go hub.go:107 `FinalMask.Listen` 替换底层 listener，
    // TLS/WS 握手跑在 mask 内——由 WsListener 在 ws 握手前 wrap 每条 accept
    // conn（空 manager = 恒等）。
    ws_listener.tcpmask =
        Some(Arc::new(xray_transport::finalmask::build_tcpmask_manager_from_json(
            settings.finalmask_json.as_ref(),
        )?));

    let local_addr = ws_listener.local_addr().map_err(io::Error::other)?;
    let tls_config = build_tls_config(settings)?;
    Ok(spawn_ws_accept_loop(
        ws_listener,
        tls_config,
        handler.clone(),
        "ws",
        local_addr.to_string(),
        local_addr,
    ))
}

/// unix 路径 WS 监听（对应 Go hub.go:100-104 `port == net.Port(0)` 分支：
/// `net.UnixAddr` → `internet.ListenSystem`，TLS/WS 握手层全复用）。
///
/// Go 该分支支持 `FinalMask.Listen(ctx, unixAddr)`；Rust tcpmask 为 TCP 语义
/// 载体，unix 上无对应能力——非空显式拒绝而非静默忽略（对齐 tcp hub unix
/// finalmask 拒绝惯例）。
#[cfg(unix)]
async fn listen_unix_ws(
    path: String,
    settings: StreamSettings,
    sockopt: xray_transport::sockopt::SocketOptions,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    if settings.finalmask_json.as_ref().is_some_and(|v| !v.is_null()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "finalmask is not supported on unix listeners; remove the finalmask key",
        ));
    }
    let config = parse_ws_config(settings.transport_json.as_ref())?;
    // trusted 来自 sockopt（Go socketSettings.TrustedXForwardedFor 同样作用于 unix）。
    let trusted = sockopt.trusted_x_forwarded_for.clone();
    let mut ws_listener =
        crate::server::WsListener::bind_unix(&path, sockopt, vec![Arc::new(config)])
            .await
            .map_err(io::Error::other)?;
    ws_listener.trusted_x_forwarded_for = trusted;

    let local_addr = ws_listener.local_addr().map_err(io::Error::other)?;
    let tls_config = build_tls_config(&settings)?;
    Ok(spawn_ws_accept_loop(ws_listener, tls_config, handler, "ws-unix", path, local_addr))
}

/// 按 security 构造可选 TLS acceptor（TCP 与 unix 监听共用）。
///
/// `build_server_config` 自洽：非 `tls`/`reality`（含 `"none"`/空）返回
/// `Ok(None)`——对应 Go hub.go:126-132 `tls.ConfigFromStreamSettings` 判空，
/// unix listener 同样可包。
fn build_tls_config(
    settings: &StreamSettings,
) -> io::Result<Option<Arc<tokio_rustls::rustls::ServerConfig>>> {
    xray_tls::server_config::build_server_config(
        &settings.security,
        settings.security_json.as_ref(),
    )
}

/// spawn ws accept 循环（TCP 与 unix 监听共用）：TLS 可选 + accept_policy
/// 错误处置（错误永不退出，唯一出口 close_notify）+ 意外退出监控。
///
/// `ident` 进日志标识监听（TCP = local_addr；unix = socket 路径，unix 无有
/// 意义的 local_addr）。
fn spawn_ws_accept_loop(
    ws_listener: crate::server::WsListener,
    tls_config: Option<Arc<tokio_rustls::rustls::ServerConfig>>,
    handler: ConnHandler,
    tag: &'static str,
    ident: String,
    local_addr: SocketAddr,
) -> Box<dyn TransportListener> {
    let close_notify = Arc::new(tokio::sync::Notify::new());
    let close_notify_clone = close_notify.clone();
    let log_ident = ident.clone();
    #[allow(
        clippy::disallowed_methods,
        reason = "数据面连接任务（ws accept 泵）；迁 FxScope 待 bd 39hko"
    )]
    let accept_loop_handle = tokio::spawn(async move {
        let ident = log_ident;
        loop {
            tokio::select! {
                result = async {
                    if let Some(tls_cfg) = &tls_config {
                        ws_listener.accept_tls(tls_cfg.clone()).await
                    } else {
                        ws_listener.accept().await
                    }
                } => {
                    match result {
                        Ok(accepted) => handler(accepted.conn),
                        // 错误永不退出（accept_policy 铁律）：退出唯一来源是
                        // close_notify 分支。生产杀手链：TLS 握手成功后客户端断开 →
                        // rustls PeerClosed（"peer closed connection without sending
                        // TLS alert"）→ tungstenite Error::Io → WsError::Tungstenite，
                        // 文本含小写 "closed" 曾命中旧 contains("closed") => break，
                        // 整个 443 监听静默消失且日志零线索。
                        Err(e) => {
                            match accept_kind(&e) {
                                AcceptErrorKind::Resource => {
                                    crate::LOG.warn(format!("tag={tag} local={ident} error={e} ws inbound: 资源/瞬时类 accept 错误，退避 500ms 后继续"));
                                    if let WsError::Io(io_err) = &e {
                                        backoff_if_resource(io_err).await;
                                    }
                                }
                                AcceptErrorKind::Connection => {
                                    crate::LOG.debug(format!("tag={tag} error={e} ws inbound: 单连接级 accept 错误，继续监听"));
                                }
                                AcceptErrorKind::Unknown => {
                                    crate::LOG.warn(format!("tag={tag} local={ident} error={e} ws inbound: accept 错误（未知类别），继续监听"));
                                }
                            }
                        }
                    }
                }
                _ = close_notify_clone.notified() => break,
            }
        }
    });
    // 意外退出监控：循环只应经 close_notify 分支退出；panic（如 handler 回调
    // panic 沿任务栈炸掉 accept task）会静默杀掉监听——error! 兜底发声。
    #[allow(
        clippy::disallowed_methods,
        reason = "常驻监控任务（accept 循环意外退出监控）；迁 FxScope 待 bd 39hko"
    )]
    tokio::spawn(supervise_accept_loop(tag, ident, accept_loop_handle));

    Box::new(WsTransportListener { local_addr, close_notify })
}

/// WebSocket `TransportListener` wrapper。只持有 local_addr + close 通知。
struct WsTransportListener {
    local_addr: SocketAddr,
    close_notify: Arc<tokio::sync::Notify>,
}

impl TransportListener for WsTransportListener {
    fn close(&self) -> io::Result<()> {
        // notify_one 存 permit：close 落在 accept 循环重新注册 notified() 的窗口内
        // 也不丢失（notify_waiters 只唤醒已注册 waiter，会留下永久 accept 的僵尸）。
        // 底层 TcpListener 在 WsListener drop 时关闭。
        self.close_notify.notify_one();
        Ok(())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

impl Drop for WsTransportListener {
    fn drop(&mut self) {
        // v7nqa：inbound 停机只 drop 监听句柄、不显式调 close——不通知则 accept
        // 循环继续持有 WsListener（含 socket），端口在进程内继续 accept（Go
        // worker.close 显式 hub.Close()，proxyman/inbound/worker.go:151-158；
        // ws 侧 hub.go:154-156 `Close()` = `listener.Close()`）。
        let _ = TransportListener::close(self);
    }
}

/// 实际拨号：解析 wsSettings → tls config → 池查询/拨号 → 包装为 Connection。
async fn dial_ws(dest: &Destination, settings: &StreamSettings) -> io::Result<Box<dyn Connection>> {
    let config = parse_ws_config(settings.transport_json.as_ref())?;

    // 默认 SNI 用 dest 地址（与 Go `serverName = dest address` 一致）。
    let default_sni = dest.address().to_string();
    let mut tls_config = xray_tls::client_config::build_client_config(
        &settings.security,
        settings.security_json.as_ref(),
        &default_sni,
    )?;
    // Go websocket/dialer.go：`tls.WithNextProto("http/1.1")`——WS upgrade 是
    // HTTP/1.1 语义；默认 ALPN 含 "h2" 时 CDN（Cloudflare）会协商 h2，随后
    // tungstenite 发 HTTP/1.1 upgrade 被 h2 帧流打断（httparse: invalid HTTP version）。
    if let Some(cfg) = tls_config.as_mut() {
        if let Some(c) = std::sync::Arc::get_mut(cfg) {
            c.alpn_protocols = vec![b"http/1.1".to_vec()];
        }
    }

    let tls_server_name = security_str(settings, "serverName");
    let fingerprint = security_str(settings, "fingerprint");

    // finalmask（bd dppv）：manager 随 DialParams 进 dial()，在 TLS/WS 握手前套上
    // （Go dialer.go:49-62 NetDial 层序，首字节 = mask 头）；空 manager = 恒等。
    let tcpmask = Arc::new(xray_transport::finalmask::build_tcpmask_manager_from_json(
        settings.finalmask_json.as_ref(),
    )?);

    // Go dialer.go:24-33 + 168-221 delayDialConn：Ed > 0 时拨号推迟到首次
    // Write，首包 ≤ Ed 以 early data 进握手头（0-RTT），Read 阻塞至拨号完成。
    if config.ed > 0 {
        let ed = config.ed;
        let params = DialParams {
            config,
            destination: dest.clone(),
            tls_config,
            tls_server_name,
            fingerprint,
            security_json: settings.security_json.clone(),
            tcpmask: Some(Arc::clone(&tcpmask)),
        };
        let factory: DialFactory = Arc::new(move |ed_bytes| {
            let params = params.clone();
            Box::pin(async move {
                let conn = dial_with_params(params, ed_bytes).await.map_err(io::Error::other)?;
                Ok(Box::new(conn) as Box<dyn Connection>)
            })
        });
        return Ok(Box::new(DelayDialConn::new(ed, factory)));
    }

    // ===== 预连接池（virgin-connection pool，bd k9qg → ss-ws 池票修订）=====
    // 池启用条件：`Config::pool_size > 0`（默认 12，对齐 Chrome 6/host × 多 host
    // burst 上限）。key 必须包含能区分握手细节的字段（host/port/path/sni/
    // fingerprint）——任意字段不同 = 不能复用（TLS 握手 / WS 升级 / SNI 校验
    // 阶段已不同）。
    let pool_key = PoolKey {
        host: dest.address().to_string(),
        port: dest.port().value(),
        path: config.normalized_path(),
        tls_server_name: tls_server_name.clone(),
        fingerprint: fingerprint.clone(),
        mask: !tcpmask.tcpmasks.is_empty(),
    }
    .normalized();
    let pool = global_pool();
    // 首次解析到 wsSettings 时按 Config::pool_size 重新配置全局池；后续 inbound
    // 配置变更不传播（单进程池容量固定）。
    if config.pool_size > 0 && !pool.config_initialized() {
        pool.init_config(config.pool_size as usize);
    }
    let pool_enabled = config.pool_size > 0 && pool.enabled();
    let dial_params = DialParams {
        config,
        destination: dest.clone(),
        tls_config,
        tls_server_name,
        fingerprint,
        security_json: settings.security_json.clone(),
        tcpmask: Some(Arc::clone(&tcpmask)),
    };

    if pool_enabled {
        // 只取预连接（握手完成、零内层字节）；交付即触发后台补拨维持库存。
        if let Some(cached) = pool.try_acquire(&pool_key).await {
            spawn_replenish(&pool, &pool_key, dial_params);
            // finalmask 已在拨号内（TLS/WS 握手前）套上——直接交付，禁二次 wrap。
            return Ok(cached);
        }
    }

    // 预连接未命中 / 池未启用：现拨（finalmask 在 dial 内 TLS/WS 握手前套上，
    // 首字节 = mask 头，Go dialer.go:49-62 层序）。
    let raw_conn = dial_with_params(dial_params.clone(), None).await.map_err(io::Error::other)?;

    // 交付后 burst 补拨：缓存未命中说明池空，burst 触发并行拨号尽快填到
    // `max_idle_per_key`，下一波 dial_ws 即可命中预连接。池未启用时 +
    // 缓存命中后 + delayDial（ED）路径不调用 burst——前者浪费 spawn，后者
    // 由 [`register_dialer`] 后续 dial_ws 触发各自的 replenish。
    if pool_enabled {
        spawn_replenish_burst(&pool, &pool_key, dial_params);
    }
    Ok(Box::new(raw_conn))
}

/// 预连接补拨：spawn 后台拨号（完整 TCP+TLS+ws 握手），成功入池、失败放弃名额。
///
/// 预连接尽力而为：补拨失败不影响交付路径（caller 已拿到连接），失败原因
/// debug 记录；名额在任务内 begin/end 配对，不漏记。
fn spawn_replenish(pool: &Arc<WsConnectionPool>, key: &PoolKey, params: DialParams) {
    let pool = pool.clone();
    let key = key.clone();
    #[allow(
        clippy::disallowed_methods,
        reason = "数据面连接任务（池预连接补拨）；迁 FxScope 待 bd 39hko"
    )]
    tokio::spawn(async move {
        if !pool.begin_preconnect(&key).await {
            return;
        }
        let result = dial_with_params(params, None).await;
        pool.end_preconnect(&key);
        match result {
            Ok(conn) => pool.release(key, Box::new(conn)).await,
            Err(e) => crate::LOG.debug(format!(
                "key={} error={e} ws pool replenish dial failed",
                key.short_label()
            )),
        }
    });
}

/// 预连接 burst 补拨：一次性发起 `BURST_REPLENISH_FANOUT` 个并行拨号，全部由
/// 池的 `begin_preconnect` 名额闸门把关——池满时多余的 spawn 任务立刻被闸门
/// 拒绝，零额外开销。Chrome 整页 burst（>5 个 subresource 同时打开）场景下，
/// 单条 replenish 任务跟不上拨号节拍；fanout=3 让 burst 后第一波后续 dial
/// 拿到预连接的命中率从 ~40% 提升到 ~80%（与池默认 12 容量叠加生效）。
///
/// 设计约束：virgin-only / used 永不回池红线由 [`spawn_replenish`] 内 `release`
/// 路径守住，本函数仅在 `spawn_replenish` 之外多发起若干拨号线——每条仍是
/// 干净拨号 → 握手完成 → 入池（承载 0 字节）。
///
/// ponytail: fanout 选 3 而非更大——burst 实际就是 6-15 并发 dial_ws，每条
/// dial_ws 已自带 1 条 replenish；fanout=3 叠加 → 总并发补拨 ≈ caller 数 × 3，
/// 已能填满 12 的池（实际网关/握手端瓶颈 100-300ms/条，3-4 条并发是甜点）。
/// 上限硬约束由池的 `max_idle_per_key` 兜底，配置改大 fanout 也无需改此处。
const BURST_REPLENISH_FANOUT: usize = 3;

/// 触发一次 burst：除主 [`spawn_replenish`] 外多发起 `BURST_REPLENISH_FANOUT`
/// 条平行补拨——caller 已在缓存未命中分支（或首次现拨后）调一次，池空期一并
/// 填满库存。命名 `replenish_burst` 强调「短时高并发补充」而非持续后台补拨。
fn spawn_replenish_burst(pool: &Arc<WsConnectionPool>, key: &PoolKey, params: DialParams) {
    spawn_replenish(pool, key, params.clone());
    for _ in 1..BURST_REPLENISH_FANOUT {
        spawn_replenish(pool, key, params.clone());
    }
}

/// security_json 顶层字符串字段提取（serverName / fingerprint）。
fn security_str(settings: &StreamSettings, key: &str) -> Option<String> {
    settings
        .security_json
        .as_ref()
        .and_then(|v| v.get(key))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// 从 path 提取 `?ed=N` 早期数据参数。
///
/// 对应 Go `infra/conf/transport_internet.go::WebSocketConfig.Build`：
///
/// ```go
/// if u, err := url.Parse(path); err == nil {
///     if q := u.Query(); q.Get("ed") != "" {
///         Ed, _ := strconv.Atoi(q.Get("ed"))
///         ed = uint32(Ed)
///         q.Del("ed")
///         u.RawQuery = q.Encode()
///         path = u.String()
///     }
/// }
/// ```
///
/// 语义逐条对齐 httpupgrade 的 [`xray_transport_httpupgrade::config::extract_ed_from_path`]：
/// - **提取门**：首个 `ed` query 值为非空字符串才提取（`?ed=`、`?ed` 或首值空 → 整体不动）。
/// - **数值**：`strconv.Atoi` 语法错误 → 0（溢出时 Go 返回钳制值且错误被忽略）； `uint32(Ed)`
///   截断低 32 位，负数回绕。
/// - **删除**：提取触发时删除**全部** `ed` 参数（即使 Atoi 失败）。
/// - **重编码**：剩余参数按 Go `Values.Encode()`——键稳定排序、`QueryEscape`。
/// - **fragment**：`#` 后内容不参与解析，结果原样回接。
/// - **解析失败**：path 部分含非法 `%` 转义时 Go `url.Parse` 报错 → 整体跳过提取。
///
/// 返回 `(清理后 path, 提取的 ed)`；未触发提取时 ed 为 `None`（path 原样返回）。
fn extract_ed_from_path(path: &str) -> (String, Option<u32>) {
    let (before_frag, frag) = match path.split_once('#') {
        Some((b, f)) => (b, Some(f)),
        None => (path, None),
    };
    let Some((base, query)) = before_frag.split_once('?') else {
        return (path.to_string(), None);
    };
    // Go `url.Parse`：path 部分非法 % 转义 → err → 整体不提取。
    if has_invalid_escape(base) {
        return (path.to_string(), None);
    }
    // Go `parseQuery`：`&` 分割、首个 `=` 分 k/v、非法转义跳过该 pair、空 kv 跳过。
    let mut pairs: Vec<(String, String)> = Vec::new();
    for kv in query.split('&') {
        if kv.is_empty() {
            continue;
        }
        let (k, v) = match kv.split_once('=') {
            Some((k, v)) => (k, v),
            None => (kv, ""),
        };
        if let (Some(k), Some(v)) = (query_unescape(k), query_unescape(v)) {
            pairs.push((k, v));
        }
    }
    // Go `Values.Get`：取首个 ed 值；非空字符串才触发提取。
    let Some(ed_value) = pairs.iter().find(|(k, _)| k == "ed").map(|(_, v)| v.clone()) else {
        return (path.to_string(), None);
    };
    if ed_value.is_empty() {
        return (path.to_string(), None);
    }
    let ed = Some(go_atoi_u32(&ed_value));
    // Go `Values.Del("ed")` + `Values.Encode()`：删全部 ed，剩余按键排序 + QueryEscape。
    pairs.retain(|(k, _)| k != "ed");
    let mut out = base.to_string();
    if !pairs.is_empty() {
        pairs.sort_by(|a, b| a.0.cmp(&b.0)); // 稳定排序：同键多值保持插入序
        let encoded: Vec<String> =
            pairs.iter().map(|(k, v)| format!("{}={}", query_escape(k), query_escape(v))).collect();
        out.push('?');
        out.push_str(&encoded.join("&"));
    }
    if let Some(f) = frag {
        out.push('#');
        out.push_str(f);
    }
    (out, ed)
}

/// Go `strconv.Atoi` + `uint32(...)` 转换语义（错误时返回值仍被采用）。
fn go_atoi_u32(s: &str) -> u32 {
    let (neg, digits) = match s.as_bytes().first() {
        Some(b'+') => (false, &s[1..]),
        Some(b'-') => (true, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return 0; // 语法错误 → Go Atoi 返回 0 + err（err 被忽略）
    }
    // 溢出：Go ParseInt ErrRange 返回钳制值（正 → MaxInt64，负 → MinInt64=−2^63）。
    let limit: i128 = if neg { 1i128 << 63 } else { i64::MAX as i128 };
    let mut v: i128 = 0;
    for b in digits.bytes() {
        v = (v * 10 + i128::from(b - b'0')).min(limit);
    }
    (if neg { -v } else { v }) as u32 // 截断低 32 位，负数回绕（同 Go uint32(int)）
}

/// Go `url.QueryUnescape`：`+`→空格、`%XX`（大小写十六进制）解码；非法转义返回 `None`。
fn query_unescape(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            },
            b'%' => {
                if i + 2 >= b.len() {
                    return None;
                }
                let hi = hex_val(b[i + 1])?;
                let lo = hex_val(b[i + 2])?;
                out.push(hi << 4 | lo);
                i += 3;
            },
            c => {
                out.push(c);
                i += 1;
            },
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// Go `url.QueryEscape`：`[A-Za-z0-9-_.~]` 保留，空格→`+`，其余 `%XX` 大写。
fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(c as char)
            },
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{c:02X}")),
        }
    }
    out
}

/// path 部分是否含非法 `%` 转义（Go `unescape(path, encodePath)` 报错场景）。
fn has_invalid_escape(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() || hex_val(b[i + 1]).is_none() || hex_val(b[i + 2]).is_none() {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// 从 `wsSettings` JSON 解析为强类型 [`Config`]。
///
/// 接受的 JSON 字段（对齐 Go proto JSON + 用户配置两种写法）：
/// - `host` / `path`：字符串
/// - `header` 或 `headers`：`map<string,string>`（同时支持两种 key 兼容客户端配置）
/// - `ed`：u32（Early Data 长度）
/// - `heartbeatPeriod`：u32（秒，camelCase 对齐 proto JSON）
/// - `poolSize`：u32（连接池空闲上限，0=关池；缺省沿用 `Config::default` = 3）
///
/// `None` 或非 object 返回 [`Config::default`]。
fn parse_ws_config(json: Option<&serde_json::Value>) -> io::Result<Config> {
    let Some(v) = json else {
        return Ok(Config::default());
    };
    let Some(obj) = v.as_object() else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "wsSettings must be a JSON object"));
    };

    let mut host = obj.get("host").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let mut path = obj.get("path").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let mut ed = obj.get("ed").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    // Bug-B（bd cqyj）：缺省 30s 心跳；显式 0 = 关闭。
    let heartbeat_period =
        obj.get("heartbeatPeriod").and_then(|x| x.as_u64()).map(|v| v as u32).unwrap_or(30);
    // ponytail: poolSize 缺省 → Config::default() 的 12（启用池化）；显式 0 = 关池。
    // 与 `Config::default()` 一致，避免每个 outbound 都要在 JSON 里写 poolSize。
    let pool_size = obj.get("poolSize").and_then(|x| x.as_u64()).unwrap_or(12) as u32;

    // Go `infra/conf/transport_internet.go::WebSocketConfig.Build`：
    // path 中 `?ed=N` 提取为 Ed 字段并从 path 删除（其余 query 参数保留）。
    let (cleaned, path_ed) = extract_ed_from_path(&path);
    path = cleaned;
    if let Some(e) = path_ed {
        ed = e;
    }
    // Go：headers 里的 host（大小写不敏感）提升为 Host 字段并从 headers 删除。
    let mut header = parse_headers(obj.get("header"))
        .or_else(|| parse_headers(obj.get("headers")))
        .unwrap_or_default();

    if let Some(host_key) = header.keys().find(|k| k.eq_ignore_ascii_case("host")).cloned() {
        let v = header.remove(&host_key).unwrap_or_default();
        if host.is_empty() {
            host = v;
        }
    }
    let accept_proxy_protocol =
        obj.get("acceptProxyProtocol").and_then(|x| x.as_bool()).unwrap_or(false);

    Ok(Config { host, path, header, accept_proxy_protocol, ed, heartbeat_period, pool_size })
}

/// 把 JSON 子对象解析为 `HashMap<String, String>`。非 object 或缺失返回 `None`。
fn parse_headers(
    v: Option<&serde_json::Value>,
) -> Option<std::collections::HashMap<String, String>> {
    let obj = v?.as_object()?;
    let mut map = std::collections::HashMap::with_capacity(obj.len());
    for (k, val) in obj {
        if let Some(s) = val.as_str() {
            map.insert(k.clone(), s.to_string());
        }
        // 非 string 值跳过（与 Go proto JSON 解析对未知字段的容忍一致）。
    }
    Some(map)
}

/// [`WsError`] → 共享 accept 分类（`xray_transport::accept_policy`）。
///
/// 非 `Io` 变体都发生在已 accept 的连接上（TLS/WS 握手、升级请求、帧解析——含
/// 生产杀手链「TLS 握手成功后对端断开」的 rustls `UnexpectedEof`/
/// "peer closed ... close_notify" 文本两条落地路径：tungstenite `Error::Io` 包装
/// 与 `HandshakeFailed("tls accept: ...")`），一律单连接级；`Io` 再按 kind 细分。
fn accept_kind(e: &WsError) -> AcceptErrorKind {
    match e {
        WsError::HandshakeFailed(_)
        | WsError::InvalidUpgradeRequest { .. }
        | WsError::InvalidOpcode(_)
        | WsError::FrameTooLarge(_)
        | WsError::Tungstenite(_) => AcceptErrorKind::Connection,
        WsError::Io(io_err) => xray_transport::accept_policy::classify(io_err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ws_config_none_returns_default() {
        let cfg = parse_ws_config(None).unwrap();
        assert!(cfg.host.is_empty());
        assert!(cfg.path.is_empty());
        assert_eq!(cfg.ed, 0);
    }

    #[test]
    fn parse_ws_config_basic_fields() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"host":"h.example.com","path":"/ws","ed":2048,"heartbeatPeriod":30}"#,
        )
        .unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.host, "h.example.com");
        assert_eq!(cfg.path, "/ws");
        assert_eq!(cfg.ed, 2048);
        assert_eq!(cfg.heartbeat_period, 30);
    }

    /// poolSize 默认 12（启用池化；Chrome 6/host × 多 host burst 上限）。
    #[test]
    fn parse_ws_config_pool_size_default_12() {
        let v: serde_json::Value = serde_json::from_str(r#"{"path":"/ws"}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.pool_size, 12);
    }

    /// poolSize=0 显式关池。
    #[test]
    fn parse_ws_config_pool_size_zero_disables() {
        let v: serde_json::Value = serde_json::from_str(r#"{"path":"/ws","poolSize":0}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.pool_size, 0);
    }

    /// poolSize=N 启用 N 条空闲上限。
    #[test]
    fn parse_ws_config_pool_size_custom() {
        let v: serde_json::Value = serde_json::from_str(r#"{"path":"/ws","poolSize":6}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.pool_size, 6);
    }

    #[test]
    fn parse_ws_config_accepts_headers_plural() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"headers":{"X-Forwarded-For":"10.0.0.1"}}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.header.get("X-Forwarded-For").unwrap(), "10.0.0.1");
    }

    #[test]
    fn parse_ws_config_accepts_header_singular() {
        let v: serde_json::Value = serde_json::from_str(r#"{"header":{"X-Custom":"v"}}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.header.get("X-Custom").unwrap(), "v");
    }

    #[test]
    fn parse_ws_config_header_preferred_over_headers() {
        // 同时给两种 key：header（proto）优先于 headers（用户）。
        let v: serde_json::Value =
            serde_json::from_str(r#"{"header":{"K":"from-proto"},"headers":{"K":"from-user"}}"#)
                .unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.header.get("K").unwrap(), "from-proto");
    }

    #[test]
    fn parse_ws_config_non_object_returns_err() {
        let v: serde_json::Value = serde_json::from_str(r#""not-an-object""#).unwrap();
        let r = parse_ws_config(Some(&v));
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn parse_ws_config_skips_non_string_header_values() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"headers":{"good":"v","bad":123}}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.header.len(), 1);
        assert_eq!(cfg.header.get("good").unwrap(), "v");
    }

    /// 对齐 Go `WebSocketConfig.Build`：`path:"/ws?ed=2048"` → ed=2048, path="/ws"。
    #[test]
    fn parse_ws_config_path_ed_extraction() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"path":"/ws?ed=2048","acceptProxyProtocol":true}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.path, "/ws");
        assert_eq!(cfg.ed, 2048);
        assert!(cfg.accept_proxy_protocol);
    }

    /// 其余 query 参数保留，仅剥离 ed。
    #[test]
    fn parse_ws_config_path_ed_keeps_other_params() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"path":"/ws?x=1&ed=1024&y=2"}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.path, "/ws?x=1&y=2");
        assert_eq!(cfg.ed, 1024);
    }

    /// Go 兼容：headers 里的 host 提升为 Host 字段并从 headers 删除。
    #[test]
    fn parse_ws_config_headers_host_promotion() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"headers":{"Host":"h.example.com","X-Foo":"1"}}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.host, "h.example.com");
        assert!(!cfg.header.contains_key("Host"));
        assert_eq!(cfg.header.get("X-Foo").map(String::as_str), Some("1"));
    }

    // ---------------------------------------------------------------------
    // `extract_ed_from_path` Go 语义边界（与 httpupgrade 完整版对齐）
    // ---------------------------------------------------------------------

    /// 键排序：剩余参数按字母序拼成 early data，ed=2048 提取后 path="/ws?x=1&y=2"。
    #[test]
    fn extract_ed_key_sort() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"path":"/ws?y=2&ed=2048&x=1"}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.path, "/ws?x=1&y=2");
        assert_eq!(cfg.ed, 2048);
    }

    /// Atoi 边界 — 超过 u32 上限 (> 65535 区段展示)：截断低 32 位（Go uint32(int) 语义）。
    #[test]
    fn extract_ed_atoi_clamps_overflow() {
        // 4294967297 = 2^32 + 1 → 截断后为 1
        let v: serde_json::Value = serde_json::from_str(r#"{"path":"/ws?ed=4294967297"}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.ed, 1);
        assert_eq!(cfg.path, "/ws");
        // 99999999999999999999 → Go ParseInt ErrRange 钳到 MaxInt64 → uint32 截断 = 0xFFFFFFFF
        let v: serde_json::Value =
            serde_json::from_str(r#"{"path":"/ws?ed=99999999999999999999"}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.ed, u32::MAX);
        assert_eq!(cfg.path, "/ws");
        // -99999999999999999999 → Go ErrRange 钳到 MinInt64 → uint32 截断 = 0
        let v: serde_json::Value =
            serde_json::from_str(r#"{"path":"/ws?ed=-99999999999999999999"}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.ed, 0);
        assert_eq!(cfg.path, "/ws");
    }

    /// Atoi 边界 — 负数回绕（Go `uint32(int)` 截断低 32 位）。
    #[test]
    fn extract_ed_atoi_negative_wraps() {
        let v: serde_json::Value = serde_json::from_str(r#"{"path":"/ws?ed=-1"}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.ed, u32::MAX);
        assert_eq!(cfg.path, "/ws");
    }

    /// Atoi 边界 — 非数字字符串：Go Atoi 返回 err，ed=0，参数仍删除。
    #[test]
    fn extract_ed_atoi_non_numeric_zero() {
        let v: serde_json::Value = serde_json::from_str(r#"{"path":"/ws?ed=abc"}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.ed, 0);
        assert_eq!(cfg.path, "/ws");
    }

    /// 空值门：ed 值缺失 / 空字符串 / 仅 `ed` 无 `=` → 整体不动，cfg.ed 默认 0。
    #[test]
    fn extract_ed_empty_gate_keeps_path() {
        // "?ed=" → 首值空 → 整体不动
        let v: serde_json::Value = serde_json::from_str(r#"{"path":"/ws?ed="}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.path, "/ws?ed=");
        assert_eq!(cfg.ed, 0);
        // "?ed" 无 = → 整体不动
        let v: serde_json::Value = serde_json::from_str(r#"{"path":"/ws?ed"}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.path, "/ws?ed");
        assert_eq!(cfg.ed, 0);
        // "?ed=&ed=2048" → 首值空 → 整体不动（Go Get 取首个，非空才触发）
        let v: serde_json::Value = serde_json::from_str(r#"{"path":"/ws?ed=&ed=2048"}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.path, "/ws?ed=&ed=2048");
        assert_eq!(cfg.ed, 0);
    }

    /// 多 ed 键：Get 取首个，Del 删全部（即使首值空 → 不触发）。
    #[test]
    fn extract_ed_multiple_ed_first_non_empty() {
        let v: serde_json::Value = serde_json::from_str(r#"{"path":"/ws?ed=1&ed=2"}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.ed, 1);
        assert_eq!(cfg.path, "/ws");
    }

    /// 单元测直接测 `extract_ed_from_path` 助手（Go 语义全矩阵）。
    #[test]
    fn extract_ed_from_path_go_semantics() {
        let f = |p: &str| extract_ed_from_path(p);
        // 基本提取 + 删除
        assert_eq!(f("/ws?ed=2048"), ("/ws".to_string(), Some(2048)));
        // 无 query / 无 ed：原样
        assert_eq!(f("/ws"), ("/ws".to_string(), None));
        assert_eq!(f("/ws?x=1"), ("/ws?x=1".to_string(), None));
        // 提取门
        assert_eq!(f("/ws?ed="), ("/ws?ed=".to_string(), None));
        assert_eq!(f("/ws?ed"), ("/ws?ed".to_string(), None));
        // 多 ed 取首
        assert_eq!(f("/ws?ed=1&ed=2"), ("/ws".to_string(), Some(1)));
        // ed=0 仍触发（值非空）+ 删除
        assert_eq!(f("/ws?ed=0"), ("/ws".to_string(), Some(0)));
        // 非法数值 → 0 + 删除
        assert_eq!(f("/ws?ed=abc"), ("/ws".to_string(), Some(0)));
        // 负数 → uint32 回绕
        assert_eq!(f("/ws?ed=-1"), ("/ws".to_string(), Some(u32::MAX)));
        // 溢出钳制
        assert_eq!(f("/ws?ed=99999999999999999999"), ("/ws".to_string(), Some(u32::MAX)));
        assert_eq!(f("/ws?ed=-99999999999999999999"), ("/ws".to_string(), Some(0)));
        // u32 范围内截断低 32 位
        assert_eq!(f("/ws?ed=4294967297"), ("/ws".to_string(), Some(1)));
        // 剩余按键排序 + QueryEscape
        assert_eq!(f("/ws?y=2&ed=1024&x=1"), ("/ws?x=1&y=2".to_string(), Some(1024)));
        // fragment 保留
        assert_eq!(f("/ws?ed=2048#frag"), ("/ws#frag".to_string(), Some(2048)));
        // path 部分非法 % 转义 → 整体不动
        assert_eq!(f("/w%zz?ed=2048"), ("/w%zz?ed=2048".to_string(), None));
    }

    /// ed>0 走 delayDial（Go dialer.go:24-32）：dial_ws 立即返回成功且不拨号。
    #[tokio::test]
    async fn dial_ws_with_ed_defers_dialing() {
        use xray_common::net::{address::Address, network::Network, port::Port};

        // 127.0.0.1:1 不可达：立即拨号会 Err；delayDial 首写前必须成功返回。
        let settings = StreamSettings {
            transport_json: Some(serde_json::json!({"path": "/ws?ed=2048"})),
            ..Default::default()
        };
        let dest = Destination::new(Address::new_domain("127.0.0.1"), Port::new(1), Network::TCP);
        let conn = dial_ws(&dest, &settings).await.expect("delayDial must return without dialing");
        drop(conn);
    }
    /// Tcpmask round-trip（o54c，Go websocket/dialer.go:56-63 + hub.go:132-134）：
    /// dial 与 hub 双端配置 fragment mask 后 e2e echo 收发。
    #[tokio::test]
    #[allow(clippy::field_reassign_with_default)] // 测试/装配逐字段赋值对齐 Go 表意
    async fn ws_dial_hub_tcpmask_roundtrip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use xray_common::net::{address::Address, network::Network, port::Port};

        let finalmask = serde_json::json!({
            "tcp": [{"type": "fragment", "settings": {
                "packets_from": 1, "packets_to": 2,
                "length": {"from": 8, "to": 16}, "interval": {"from": 0, "to": 0}
            }}]
        });
        let mut settings = StreamSettings::default();
        settings.protocol = "websocket".to_string();
        settings.transport_json = Some(serde_json::json!({"path": "/ws"}));
        settings.finalmask_json = Some(finalmask);

        // echo handler：读到什么写回什么。
        let handler: ConnHandler = Arc::new(|conn| {
            #[allow(clippy::disallowed_methods, reason = "测试：echo handler 任务")]
            tokio::spawn(async move {
                let mut conn = conn;
                let mut buf = [0u8; 1024];
                loop {
                    match conn.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        },
                    }
                }
            });
        });
        let listener = listen_ws("127.0.0.1:0".parse().unwrap(), &settings, &handler, Vec::new())
            .await
            .expect("listen_ws");
        let addr = listener.local_addr().expect("local_addr");

        let dest = Destination::new(
            Address::new_domain("127.0.0.1"),
            Port::new(addr.port()),
            Network::TCP,
        );
        let mut conn = dial_ws(&dest, &settings).await.expect("dial_ws");

        conn.write_all(b"hello-ws-tcpmask").await.expect("write");
        // tcpmask 分片 + echo 按 chunk 回写：单次 read 可能只拿到一个分片
        // （8-16B），TCP 拆段即红（与 httpupgrade 同款 flaky，CI ubuntu 实证）。
        // 循环读满 16 字节，总预算 5s。
        let payload = b"hello-ws-tcpmask";
        let mut got = Vec::with_capacity(payload.len());
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while got.len() < payload.len() {
            let mut buf = [0u8; 64];
            let budget = deadline.saturating_duration_since(tokio::time::Instant::now());
            let n = tokio::time::timeout(budget, conn.read(&mut buf))
                .await
                .expect("echo timeout")
                .expect("read ok");
            assert!(n > 0, "echo closed early at {}/{} bytes", got.len(), payload.len());
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(&got, payload);
    }
    /// close() 后 accept 循环退出、socket 释放，新连接被拒（票 n8k8/x6sp 行为面）。
    /// notify_one 的 permit 保证 close 与循环重新注册 notified() 之间的窗口不丢通知；
    /// pre-spawn close 竞态窗锚在 xray-transport tcp/hub.rs。
    #[tokio::test]
    async fn close_rejects_new_connections() {
        let settings = StreamSettings { protocol: "websocket".into(), ..Default::default() };
        let handler: ConnHandler = Arc::new(|_| {});
        let listener = listen_ws("127.0.0.1:0".parse().unwrap(), &settings, &handler, Vec::new())
            .await
            .expect("listen_ws");
        let addr = listener.local_addr().expect("local_addr");

        listener.close().expect("close");

        // 循环退出 → WsListener drop 是异步的：轮询直至 connect 被拒。
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match tokio::net::TcpStream::connect(addr).await {
                Err(_) => break,
                Ok(_) => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "close 后端口仍接受连接（close 通知丢失/循环未退出）"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                },
            }
        }
    }

    /// v7nqa 回归锚：停机只 drop 监听句柄、不显式 close()——无 `Drop → close`
    /// 兜底时 accept 循环继续持有 WsListener（含 socket），端口在进程内继续
    /// accept（改前本测试必挂）。
    #[tokio::test]
    async fn drop_without_close_rejects_new_connections() {
        let settings = StreamSettings { protocol: "websocket".into(), ..Default::default() };
        let handler: ConnHandler = Arc::new(|_| {});
        let listener = listen_ws("127.0.0.1:0".parse().unwrap(), &settings, &handler, Vec::new())
            .await
            .expect("listen_ws");
        let addr = listener.local_addr().expect("local_addr");
        tokio::net::TcpStream::connect(addr).await.expect("drop 前应可连接");

        drop(listener); // 只 drop，不调 close——走 Drop 兜底

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match tokio::net::TcpStream::connect(addr).await {
                Err(_) => break,
                Ok(_) => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "drop 后端口仍接受连接（Drop→close 未生效/循环未退出）"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                },
            }
        }
    }

    /// ③ transport 级 unix 监听 roundtrip（bd lfrg③）：注册 → listen_unix →
    /// UDS 建连 → 真实 WS 握手（tungstenite client_async over UDS）→ 文本帧
    /// echo 往返 → close 后 socket 释放新连接被拒。对应 Go hub.go:100-104
    /// `port == net.Port(0)` 分支。unix-only。
    #[cfg(unix)]
    #[tokio::test]
    async fn listen_unix_ws_roundtrip() {
        use futures_util::{SinkExt, StreamExt};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_tungstenite::tungstenite::Message;

        let _ = register_unix_listener();

        let path = std::env::temp_dir().join(format!(
            "xray-ws-unix-hub-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let path_str = path.to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&path_str);

        // echo 服务端：WsConnection 对 handler 透明为字节流（帧编解码在桥层）；
        // 循环读（单次 read 在桥层缓冲分片下可能拿不全，已验证形态同 tcpmask 测试）。
        let handler: ConnHandler = Arc::new(|mut conn| {
            #[allow(
                clippy::disallowed_methods,
                reason = "测试：echo 服务端任务（unix 门控路径，Windows 不编译）"
            )]
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match conn.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                            let _ = conn.flush().await;
                        },
                    }
                }
            });
        });

        let settings = StreamSettings { protocol: "websocket".into(), ..Default::default() };
        let listener = xray_transport::listener_registry::listen_unix(
            &path_str,
            settings,
            xray_transport::sockopt::SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen_unix(ws) 失败");
        // unix listener 无 SocketAddr：全零占位（对齐 tcp hub unix 契约）。
        assert_eq!(
            listener.local_addr().expect("local_addr 失败"),
            SocketAddr::from(([0, 0, 0, 0], 0))
        );

        // 客户端：UDS 建连 → 真实 WS upgrade 握手 → 文本帧往返。
        let uds = tokio::net::UnixStream::connect(&path_str).await.expect("UDS connect 失败");
        let ws_request = http::Request::builder()
            .method("GET")
            .uri("ws://localhost/")
            .header("Host", "localhost")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(())
            .unwrap();
        let (mut ws_client, resp) =
            tokio_tungstenite::client_async(ws_request, uds).await.expect("WS 握手失败");
        assert_eq!(resp.status(), http::StatusCode::SWITCHING_PROTOCOLS);

        // WsConnection 桥层只支持 binary 帧（Xray WS = 字节流，Go gorilla 同语义）。
        ws_client.send(Message::binary("ping-unix")).await.expect("send 失败");
        let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws_client.next())
            .await
            .expect("echo 超时")
            .expect("流提前结束")
            .expect("帧错误");
        assert_eq!(msg, Message::binary("ping-unix"));

        listener.close().expect("close 失败");
        // close 后 socket 释放，新连接被拒（close_rejects_new_connections 同款轮询）。
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match tokio::net::UnixStream::connect(&path_str).await {
                Err(_) => break,
                Ok(_) => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "close 后 unix socket 仍接受连接（close 通知丢失/循环未退出）"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                },
            }
        }
        let _ = std::fs::remove_file(&path_str);
    }

    /// unix 监听的 finalmask 拒绝路径（对齐 tcp hub unix 惯例：非空显式拒绝，
    /// 不静默忽略）。错误在 bind 前返回，不触 unix API——但被测函数本身
    /// cfg(unix)，测试随行。
    #[cfg(unix)]
    #[tokio::test]
    async fn listen_unix_ws_rejects_finalmask() {
        let settings = StreamSettings {
            protocol: "websocket".into(),
            finalmask_json: Some(serde_json::json!({"enabled": true})),
            ..Default::default()
        };
        let handler: ConnHandler = Arc::new(|_| {});
        let result = listen_unix_ws(
            "/tmp/xray-ws-unix-finalmask-reject.sock".into(),
            settings,
            xray_transport::sockopt::SocketOptions::default(),
            handler,
        )
        .await;
        let Err(e) = result else { panic!("expected finalmask rejection, got a listener") };
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert!(e.to_string().contains("finalmask is not supported on unix listeners"));
    }

    /// 预连接池语义（ss-ws 池复用死会话修复）：dial_ws 交付的连接承载过会话
    /// 数据后 Drop 绝不回池；池里出现的是补拨（replenish）的 virgin 连接。
    /// 服务端给每条 echo 回显附上本连接序号——从池取出的连接 roundtrip 得到的
    /// 序号 ≠ 已用会话的序号，即证明「used 连接不复现」。
    #[tokio::test]
    async fn dial_ws_used_connection_never_returns_and_replenish_fires() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use xray_common::net::{address::Address, network::Network, port::Port};

        let settings = StreamSettings {
            protocol: "websocket".to_string(),
            transport_json: Some(serde_json::json!({"path": "/ws"})),
            ..Default::default()
        };
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_handler = Arc::clone(&accepted);
        let handler: ConnHandler = Arc::new(move |conn| {
            let id = accepted_handler.fetch_add(1, Ordering::SeqCst) as u8;
            #[allow(clippy::disallowed_methods, reason = "测试：echo handler 任务")]
            tokio::spawn(async move {
                let mut conn = conn;
                let mut buf = [0u8; 512];
                loop {
                    match conn.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            // 回显带本连接序号：client 用它识别「哪条连接」。
                            let mut resp = Vec::with_capacity(n + 1);
                            resp.push(id);
                            resp.extend_from_slice(&buf[..n]);
                            if conn.write_all(&resp).await.is_err() {
                                break;
                            }
                        },
                    }
                }
            });
        });
        let listener = listen_ws("127.0.0.1:0".parse().unwrap(), &settings, &handler, Vec::new())
            .await
            .expect("listen_ws");
        let port = listener.local_addr().expect("local_addr").port();
        let dest =
            Destination::new(Address::new_domain("127.0.0.1"), Port::new(port), Network::TCP);

        // key 与 dial_ws 内部同源构造（path 走同一 parse 路径）。
        let key = PoolKey::new(
            "127.0.0.1",
            port,
            parse_ws_config(settings.transport_json.as_ref()).expect("parse").normalized_path(),
            None,
            None,
        )
        .normalized();

        // 写读一轮，返回服务端连接序号。
        async fn roundtrip(conn: &mut Box<dyn Connection>, marker: &[u8]) -> u8 {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            conn.write_all(marker).await.expect("write");
            let mut buf = vec![0u8; marker.len() + 1];
            tokio::time::timeout(std::time::Duration::from_secs(5), conn.read_exact(&mut buf))
                .await
                .expect("echo timeout")
                .expect("read ok");
            buf[0]
        }

        // 轮询等补拨连接入池（后台握手有时延，最多 ~2s）——证明 acquire 后
        // replenish 被触发且池里出现的是 virgin 连接。
        async fn wait_preconnection(key: &PoolKey) -> Box<dyn Connection> {
            for _ in 0..40 {
                if let Some(c) = global_pool().try_acquire(key).await {
                    return c;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            panic!("replenished preconnection never arrived in pool (polled {:?})", key);
        }

        // 会话 #1：池空 → 现拨 → 承载会话数据（服务端序号 0）。
        let mut session = dial_ws(&dest, &settings).await.expect("dial #1");
        let id0 = roundtrip(&mut session, b"one").await;
        assert_eq!(id0, 0, "first dial must land on server connection #0");
        drop(session); // used 连接：结构性不回池（交付侧无归还路径）。

        // 交付触发的补拨入池；直接从池取出的连接必须是 virgin（序号 ≠ 0）。
        let mut preconn = wait_preconnection(&key).await;
        let id1 = roundtrip(&mut preconn, b"two").await;
        assert_ne!(
            id1, id0,
            "pool entry must be a fresh replenished connection, never the used session one"
        );
        drop(preconn); // 预连接被用掉 = used：不回池（不经 dial_ws 交付，无补拨）。

        // 顺序两连发（生产 caller 路径）：#2 命中预连接（补拨来得及）或退化为
        // 现拨——两条路径都必须拿到 virgin 连接。
        let mut session2 = dial_ws(&dest, &settings).await.expect("dial #2");
        let id2 = roundtrip(&mut session2, b"three").await;
        assert_ne!(id2, id0, "second session must never see the first session's connection");
        assert_ne!(id2, id1, "second session must get a distinct virgin connection");
        drop(session2);

        let mut session3 = dial_ws(&dest, &settings).await.expect("dial #3");
        let id3 = roundtrip(&mut session3, b"four").await;
        assert_ne!(id3, id0, "third session must never see any earlier connection");
        assert_ne!(id3, id1);
        assert_ne!(id3, id2);
        drop(session3);
    }

    /// finalmask 套接层位置回归（bd dppv）：mask 在 dial 内 TCP 后、TLS/WS 握手前
    /// 套上（首字节 = mask 头）；补拨连接入池时已含 mask，交付直接用、不再二次
    /// 包装（PoolKey.mask 隔离 masked/unmasked 出站，无 wrap 串台）。
    #[tokio::test]
    async fn dial_ws_finalmask_wrapping_untouched_by_pool() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use xray_common::net::{address::Address, network::Network, port::Port};

        let finalmask = serde_json::json!({
            "tcp": [{"type": "fragment", "settings": {
                "packets_from": 1, "packets_to": 2,
                "length": {"from": 8, "to": 16}, "interval": {"from": 0, "to": 0}
            }}]
        });
        let settings = StreamSettings {
            protocol: "websocket".to_string(),
            transport_json: Some(serde_json::json!({"path": "/ws"})),
            finalmask_json: Some(finalmask),
            ..Default::default()
        };
        let handler: ConnHandler = Arc::new(|conn| {
            #[allow(clippy::disallowed_methods, reason = "测试：echo handler 任务")]
            tokio::spawn(async move {
                let mut conn = conn;
                let mut buf = [0u8; 512];
                loop {
                    match conn.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        },
                    }
                }
            });
        });
        let listener = listen_ws("127.0.0.1:0".parse().unwrap(), &settings, &handler, Vec::new())
            .await
            .expect("listen_ws");
        let port = listener.local_addr().expect("local_addr").port();
        let dest =
            Destination::new(Address::new_domain("127.0.0.1"), Port::new(port), Network::TCP);

        let mut conn = dial_ws(&dest, &settings).await.expect("dial_ws with finalmask");
        conn.write_all(b"fm-roundtrip").await.expect("write");
        // tcpmask 分片 + echo 按 chunk 回写：循环读满，总预算 5s。
        let payload = b"fm-roundtrip";
        let mut got = Vec::with_capacity(payload.len());
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while got.len() < payload.len() {
            let mut buf = [0u8; 64];
            let budget = deadline.saturating_duration_since(tokio::time::Instant::now());
            let n = tokio::time::timeout(budget, conn.read(&mut buf))
                .await
                .expect("echo timeout")
                .expect("read ok");
            assert!(n > 0, "echo closed early at {}/{} bytes", got.len(), payload.len());
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(&got, payload);
    }

    /// bd dppv 大载荷复现床：fragment mask + ws 双端新层序下大 payload echo。
    /// 历史残留已修：`WsConnection::poll_write` 背压语义（bd mvw2）把断流阈值从 16KB
    /// 抬到 64KB，finalmask 桥的头阻塞（bd xuaa，fragment.rs `fragment_bridge` 改双向
    /// 独立 task）把 64KB 以上那段也清掉——本床在 fragment 下 64/128/256/512KB 全 PASS。
    /// 复现：`REPRO_FM=fragment REPRO_LEN=262144 cargo test -p xray-transport-websocket
    /// --lib dial_ws_finalmask_large_payload_roundtrip -- --ignored --nocapture`
    /// （`REPRO_FM=none` / `xmc` 作对照；`REPRO_CHUNK` 调上行分块大小）。
    #[tokio::test]
    #[ignore]
    #[allow(clippy::print_stderr)] // 复现工具：进度/停点诊断输出是本测试的功能
    async fn dial_ws_finalmask_large_payload_roundtrip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use xray_common::net::{address::Address, network::Network, port::Port};

        let fm_type = std::env::var("REPRO_FM").unwrap_or_else(|_| "fragment".into());
        let finalmask = if fm_type == "none" {
            serde_json::Value::Null
        } else if fm_type == "xmc" {
            serde_json::json!({
                "tcp": [{"type": "xmc", "settings": {
                    "hostname": "mc.example.com", "password": "xmc-interop-password-01",
                    "profiles": [{"username": "steve_1",
                                  "uuid": "069a79f4-44e9-4726-a5be-fca90e38aaf5",
                                  "texturesValue": "v", "texturesSignature": "s"}]
                }}]
            })
        } else {
            serde_json::json!({
                "tcp": [{"type": "fragment", "settings": {
                    "packets_from": 1, "packets_to": 2,
                    "length": {"from": 8, "to": 16}, "interval": {"from": 0, "to": 0}
                }}]
            })
        };
        let mut settings = StreamSettings {
            protocol: "websocket".to_string(),
            transport_json: Some(serde_json::json!({"path": "/ws"})),
            ..Default::default()
        };
        if !finalmask.is_null() {
            settings.finalmask_json = Some(finalmask);
        }
        let handler: ConnHandler = Arc::new(|conn| {
            #[allow(clippy::disallowed_methods, reason = "测试：echo handler 任务")]
            tokio::spawn(async move {
                let mut conn = conn;
                let mut buf = vec![0u8; 16384];
                let mut total = 0usize;
                loop {
                    match conn.read(&mut buf).await {
                        Ok(0) | Err(_) => {
                            eprintln!("srv handler end at total={total}");
                            break;
                        },
                        Ok(n) => {
                            total += n;
                            if total % 65536 < n {
                                eprintln!("srv handler recv total={total}");
                            }
                            if conn.write_all(&buf[..n]).await.is_err() {
                                eprintln!("srv handler echo write err at total={total}");
                                break;
                            }
                        },
                    }
                }
            });
        });
        let listener = listen_ws("127.0.0.1:0".parse().unwrap(), &settings, &handler, Vec::new())
            .await
            .expect("listen_ws");
        let port = listener.local_addr().expect("local_addr").port();
        let dest =
            Destination::new(Address::new_domain("127.0.0.1"), Port::new(port), Network::TCP);

        let mut conn = dial_ws(&dest, &settings).await.expect("dial_ws with finalmask");
        let len: usize =
            std::env::var("REPRO_LEN").ok().and_then(|v| v.parse().ok()).unwrap_or(131072);
        let chunk: usize =
            std::env::var("REPRO_CHUNK").ok().and_then(|v| v.parse().ok()).unwrap_or(16384);
        let payload: Vec<u8> = (0..len).map(|i| (i & 0xFF) as u8).collect();
        // 逐块 write 观测上行停点：write_all 是原子的，看不到部分进度。
        let mut sent = 0usize;
        while sent < payload.len() {
            let chunk = &payload[sent..(sent + chunk).min(payload.len())];
            match tokio::time::timeout(std::time::Duration::from_secs(10), conn.write(chunk)).await
            {
                Ok(Ok(n)) => sent += n,
                Ok(Err(e)) => panic!("write error at {sent}: {e}"),
                Err(_) => {
                    panic!("UPSTREAM STALL: write blocked at {sent}/{} bytes", payload.len());
                },
            }
        }
        eprintln!("write complete: {sent} bytes");
        let mut got = Vec::with_capacity(payload.len());
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        while got.len() < payload.len() {
            let mut buf = vec![0u8; 16384];
            let budget = deadline.saturating_duration_since(tokio::time::Instant::now());
            let n = tokio::time::timeout(budget, conn.read(&mut buf))
                .await
                .expect("echo timeout (payload stall)")
                .expect("read ok");
            assert!(n > 0, "echo closed early at {}/{} bytes", got.len(), payload.len());
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got.len(), payload.len());
    }
}

#[cfg(test)]
mod accept_kind_tests {
    use super::*;

    // 生产杀手（443 静默死亡）：两步客户端——TLS 握手成功后立刻断开（≤11 秒即可
    // 打死监听）。rustls PeerClosed 的 Display 含小写 "closed"，旧
    // `contains("closed") => break` 命中即整个 443 监听消失、进程仍活、其余 inbound
    // 正常、日志零线索。以下断言：这类单连接级错误分类为 Connection（debug + 继续）；
    // "退出"不在动作表示域内（accept_policy 铁律 1，退出只来自 close_notify 分支）。

    #[test]
    fn tungstenite_connection_closed_maps_to_connection() {
        let e = WsError::Tungstenite(tokio_tungstenite::tungstenite::Error::ConnectionClosed);
        assert!(e.to_string().contains("closed"), "前置：文本须命中旧触发条件: {e}");
        assert_eq!(accept_kind(&e), AcceptErrorKind::Connection);
    }

    #[test]
    fn rustls_peer_closed_via_tungstenite_io_maps_to_connection() {
        // 生产触发链（本仓 vendored rustls）：TLS 握手成功后对端断开 → conn.rs 的
        // UNEXPECTED_EOF_MESSAGE（"peer closed connection without sending TLS
        // close_notify: ..."，ErrorKind::UnexpectedEof）→ tokio-rustls 透传 →
        // tungstenite Error::Io → WsError::Tungstenite（上游 rustls 同义错误为
        // Error::PeerClosed "peer closed connection without sending TLS alert"；
        // 两者文本都含小写 "closed"）
        let e = WsError::Tungstenite(tokio_tungstenite::tungstenite::Error::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "peer closed connection without sending TLS close_notify",
        )));
        assert!(e.to_string().contains("closed"), "前置：文本须命中旧触发条件: {e}");
        assert_eq!(accept_kind(&e), AcceptErrorKind::Connection);
    }

    #[test]
    fn tls_accept_handshake_failed_path_maps_to_connection() {
        // rustls 错误的另一条落地路径：accept_tls 把失败包装成
        // HandshakeFailed("tls accept: ...")
        let e = WsError::HandshakeFailed(
            "tls accept: IO error: peer closed connection without sending TLS alert".into(),
        );
        assert!(e.to_string().contains("closed"));
        assert_eq!(accept_kind(&e), AcceptErrorKind::Connection);
    }

    #[test]
    fn listener_level_io_errors_classify_resource_with_any_case() {
        // EMFILE/ENFILE：glibc "Too many open files" 大写开头——退避判定大小写不敏感
        let emfile = WsError::Io(io::Error::other("Too many open files"));
        assert_eq!(accept_kind(&emfile), AcceptErrorKind::Resource);
        let lower = WsError::Io(io::Error::other("too many open files"));
        assert_eq!(accept_kind(&lower), AcceptErrorKind::Resource);
    }

    #[test]
    fn connection_dropped_mid_handshake_maps_to_connection() {
        // 客户端在 PROXY protocol / WS 握手读取中途断开 → 继续，绝不杀监听
        for kind in [
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
        ] {
            assert_eq!(
                accept_kind(&WsError::Io(io::Error::from(kind))),
                AcceptErrorKind::Connection
            );
        }
    }
}

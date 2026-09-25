//! VLESS outbound → DialBridge 适配器（阶段 1 切片 1e）。
//!
//! VLESS 协议：拨号到 VLESS 服务器 → 在 TCP 流上写协议头（含目标地址）→ 返回连接。
//! 协议头由 [`encode_request_header`] 写入，之后双向透传——连接本身仍是底层 TCP。
//!
//! ## 范围
//!
//! 当前实现：VLESS over **raw TCP**（用于测试与无 TLS 场景）。
//! 生产场景（VLESS + TLS / REALITY）需在上层注入 TLS-wrapped 拨号闭包，
//! 或扩展 [`VlessOutboundConfig`] 支持 `dial_fn: Option<DialToServerFn>`。
//!
//! [`DialBridge`]: xray_app_dispatcher::default::DialBridge
//! [`DialFn`]: xray_app_dispatcher::default::DialFn
//! [`Connection`]: xray_transport::connection::Connection

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use xray_app_dispatcher::default::DialFn;
use xray_common::{
    net::{address::Address, destination::Destination, network::Network, port::Port},
    uuid::UUID,
};
use xray_proto::xray::proxy::vless::encoding::Addons;
use xray_transport::{
    connection::Connection,
    dialer::{StreamSettings, dial},
    sockopt::SocketOptions,
};

use crate::{
    encoding::{VERSION, VlessCommand, client::encode_request_header, empty_addons},
    encryption::vision_conn::VisionConn,
};

/// VLESS outbound 配置。
#[derive(Debug, Clone)]
pub struct VlessOutboundConfig {
    /// 用户 UUID（远端 VLESS 服务端已注册）。
    pub user_uuid: UUID,
    /// VLESS 服务器地址（IP 优先；Domain 触发 dial_system DNS 解析）。
    pub server_address: Address,
    /// VLESS 服务器端口。
    pub server_port: Port,
    /// 可选 streamSettings（TLS/WS/gRPC/...）。None 走 raw TCP。
    pub stream_settings: Option<StreamSettings>,
    /// Flow 标识（如 `xtls-rprx-vision`）。空串表示无 flow。
    /// 对应 Go `infra/conf` outbound user 的 `flow` 字段。
    pub flow: String,
    /// 加密方式（默认 `none`，对应 VLESS 无加密；其他值交给 encryption 层）。
    pub encryption: String,
    /// ENC 解析后参数（Go `infra/conf/vless.go:333-370` 出站 encryption 校验结果）。
    /// `None` 时按 `encryption == "none"` 处理；`Some` 时 make_dial_fn 在 dial 后
    /// 立即执行 ENC 握手（`ClientInstance::handshake`）并用 [`EncConnectionAdapter`]
    /// 包裹。**目前 vless 配置 path 不传入**——留给 production 调用者显式配置；
    /// inbound 解码 users[].encryption 后通过 builder 注入。
    pub enc_params: Option<crate::encryption::ClientEncParams>,
    /// 用户 level（policy/stats 系统用）。
    pub level: u32,
    /// 用户 email（stats 系统标识用）。
    pub email: String,
    /// 账户级 Vision padding seed（对应 Go `MemoryAccount.Testseed`，json `testseed`）。
    /// 本地配置不上 wire；空/不足 4 元素时运行时用默认 `[900,500,900,256]` 兜底。
    pub testseed: Vec<u32>,
    /// 预连接数（对应 Go `Handler.testpre`，json `testpre`）。0 = 关闭。
    pub testpre: u32,
}

impl VlessOutboundConfig {
    /// 构造（raw TCP，无 streamSettings）。
    pub fn new(user_uuid: UUID, server_address: Address, server_port: Port) -> Self {
        Self {
            user_uuid,
            server_address,
            server_port,
            stream_settings: None,
            flow: String::new(),
            encryption: "none".to_string(),
            enc_params: None,
            level: 0,
            testseed: Vec::new(),
            testpre: 0,
            email: String::new(),
        }
    }

    /// 指定 streamSettings（builder 风格）。
    ///
    /// `Some(ws_settings)` 后拨号走 ws transport；`None` 回退 raw TCP。
    #[must_use]
    pub fn with_stream_settings(mut self, settings: Option<StreamSettings>) -> Self {
        self.stream_settings = settings;
        self
    }

    /// 设置 flow（builder 风格）。
    #[must_use]
    pub fn with_flow(mut self, flow: impl Into<String>) -> Self {
        self.flow = flow.into();
        self
    }

    /// 设置 encryption（builder 风格）。
    #[must_use]
    pub fn with_encryption(mut self, encryption: impl Into<String>) -> Self {
        self.encryption = encryption.into();
        self
    }

    /// 设置 ENC 解析参数（Go `infra/conf/vless.go` 出站 encryption 校验后传入）。
    ///
    /// 调用方需先用 [`crate::encryption::parse_client_encryption`] 把 raw 字符串
    /// 解析成 [`crate::encryption::ClientEncParams`]，再传入。设为 `None` 走明文。
    #[must_use]
    pub fn with_encryption_params(
        mut self,
        params: Option<crate::encryption::ClientEncParams>,
    ) -> Self {
        self.enc_params = params;
        self
    }

    /// 设置账户级 testseed（builder 风格，对应 Go outbound user `testseed`）。
    #[must_use]
    pub fn with_testseed(mut self, seed: Vec<u32>) -> Self {
        self.testseed = seed;
        self
    }

    /// 设置预连接数 testpre（builder 风格，对应 Go outbound settings `testpre`）。
    #[must_use]
    pub fn with_testpre(mut self, count: u32) -> Self {
        self.testpre = count;
        self
    }

    /// 设置用户 level（builder 风格）。
    #[must_use]
    pub fn with_level(mut self, level: u32) -> Self {
        self.level = level;
        self
    }

    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = email.into();
        self
    }

    /// 服务器 Destination（TCP）。
    fn server_destination(&self) -> Destination {
        Destination::new(self.server_address.clone(), self.server_port, Network::TCP)
    }
}

/// ENC 握手（含拨号后全部缓存操作）总超时，对齐 Go SessionDefault
/// Handshake=60s（infra/conf/policy.go:130）。服务端黑洞（accept 后不读不回）
/// 时 handshake 内 read_exact 永久 Pending，60s 后本条拨号报错回收，不悬挂。
const ENC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// testpre 预连接池（对应 Go `outbound.Handler.preConns chan *ConnExpire`）。
///
/// 持有已拨到 VLESS 服务器、**尚未写请求头**的裸连接；消费方照常走 ENC 握手 +
/// 请求头（Go 语义：预连接只省 TCP dial，协议握手每条照做）。Go preConns 是
/// **无缓冲 chan**（outbound.go:161 `make(chan)`）：worker 拨号后 send 阻塞等
/// 消费者到场，空闲时 worker 停在 send 上零新拨号；条目时戳在 send 时生成，
/// 消费时检查过期（worker 排队延迟可致交付即过期）。
struct PreConns {
    ttl: Duration,
    tx: tokio::sync::mpsc::Sender<(Box<dyn Connection>, Instant)>,
    rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<(Box<dyn Connection>, Instant)>>,
}

impl PreConns {
    fn new(ttl: Duration) -> Self {
        // tokio mpsc 无 rendezvous 模式（capacity=0 panic），capacity=1 是最
        // 贴近 Go unbuffered chan（outbound.go:161）的等价：空闲稳态 = 缓冲
        // 1 条 + testpre 个 worker 各挂 1 条阻塞在 send —— 同样零新拨号；
        // 消费时缓冲即刻有货（Go rendezvous 由队头 sender 秒交付）。
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        Self { ttl, tx, rx: tokio::sync::Mutex::new(rx) }
    }

    /// 入池：满则阻塞直到消费者腾位（Go worker 空闲时休息在此）。
    /// 消费端已全部下线（handler 释放）时返回 Err，worker 随之退出。
    async fn push(
        &self,
        conn: Box<dyn Connection>,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<(Box<dyn Connection>, Instant)>> {
        self.tx.send((conn, Instant::now())).await
    }

    /// 取一条未过期预连接；过期条目丢弃后继续等（Go 消费循环
    /// `<-h.preConns` 同语义）。全部 worker 退出后返回 None → 调用方自拨。
    async fn pop(&self) -> Option<Box<dyn Connection>> {
        let mut rx = self.rx.lock().await;
        loop {
            let (conn, at) = rx.recv().await?;
            if Instant::now().duration_since(at) <= self.ttl {
                return Some(conn);
            }
        }
    }
}

/// testpre 预拨号 worker（对应 Go `initpre.Do` 起的 `testpre` 个 goroutine）：
/// 循环拨服务器 → 入池（池满阻塞等消费腾位，空闲零新拨号）→ sleep 200ms
/// （Go TODO: customize & randomize）。拨号失败记日志重试（Go LogWarning +
/// continue）。任务随 handler 存活（Go 同为无退出循环），handler 释放后
/// push 报 Err 退出（Go 是 goroutine 挂在 chan 上泄漏，此处更干净）。
fn spawn_preconn_workers(config: Arc<VlessOutboundConfig>, pool: Arc<PreConns>, count: u32) {
    for _ in 0..count {
        let config = Arc::clone(&config);
        let pool = Arc::clone(&pool);
        tokio::spawn(async move {
            loop {
                match dial_server_conn(&config).await {
                    Ok(conn) => {
                        if pool.push(conn).await.is_err() {
                            break; // handler 已释放，收摊
                        }
                    },
                    Err(e) => tracing::debug!(error = %e, "vless pre-connect failed"),
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });
    }
}

/// 仅拨到 VLESS 服务器（transport 层），不含 ENC/请求头/vision 包装。
async fn dial_server_conn(config: &VlessOutboundConfig) -> Result<Box<dyn Connection>, String> {
    let server_dest = config.server_destination();
    let sockopt = config.stream_settings.as_ref().map(|s| s.socket_options()).unwrap_or_default();
    match &config.stream_settings {
        Some(s) => dial(&server_dest, s, &sockopt)
            .await
            .map_err(|e| format!("vless dial server ({}): {e}", s.protocol)),
        None => xray_transport::system_dialer::dial_system(&server_dest, &sockopt)
            .await
            .map_err(|e| format!("vless dial server (tcp): {e}")),
    }
}

type EstablishFn = Arc<
    dyn Fn(
            &Destination,
        ) -> Pin<Box<dyn Future<Output = Result<Box<dyn Connection>, String>> + Send>>
        + Send
        + Sync,
>;

/// 构造 VLESS 的 DialFn 闭包。
///
/// 闭包捕获 `Arc<VlessOutboundConfig>`，每次调用：
/// 1. dial 到 VLESS 服务器 → `Box<dyn Connection>`
/// 2. （配置 ENC 时）`ClientInstance::handshake` 包装为加密连接
/// 3. `encode_request_header` 写 VLESS 头（含目标地址）
/// 4. ENC 配置下再包一层 [`EncRetryConn`]：0-RTT 票据失效自动重拨一次
///
/// # Panics
///
/// 不会 panic；任何错误以 `Err(String)` 返回。
pub fn make_dial_fn(config: Arc<VlessOutboundConfig>) -> DialFn {
    make_dial_fn_with_handshake_timeout(config, ENC_HANDSHAKE_TIMEOUT)
}

/// 显式指定 ENC 握手超时（测试注入短超时；生产走 [`make_dial_fn`] 的 60s 缺省）。
pub fn make_dial_fn_with_handshake_timeout(
    config: Arc<VlessOutboundConfig>,
    handshake_timeout: Duration,
) -> DialFn {
    // ENC 客户端实例 Handler 级共享（对齐 Go outbound.go:94 `handler.encryption`
    // 是 Handler 字段）：跨连接持有 0-RTT pfs_key/ticket/expire 缓存。缓存本身
    // 是内部 parking_lot RwLock（读写均瞬时），handshake(&self) 锁内无 IO——
    // 对齐 Go client.go 锁粒度（RWMutex 只在读写缓存瞬间持有），无外层互斥。
    let enc_client: Option<Arc<crate::encryption::ClientInstance>> =
        config.enc_params.as_ref().map(|enc| {
            use crate::encryption::ClientInstance;
            let mut client = ClientInstance::new();
            // init 仅在 padding 解析失败时出错；ClientEncParams 已按 Go 规则校验
            // 格式。失败时 keys 为空 → 后续 handshake 显式报 "no nfs_pkeys initialized"。
            let _ = client.init(enc.keys.clone(), enc.xor_mode, enc.seconds, &enc.padding);
            Arc::new(client)
        });
    let establish: EstablishFn = {
        let config = Arc::clone(&config);
        // testpre 预连接（Go `testpre > 0 && reverse == nil`；本 dispatcher 是
        // 普通 outbound 路径，reverse 是独立 outbound 不经此处）。首次拨号时
        // 才起 worker（对齐 Go initpre.Do 惰性初始化）。
        let pre_conns =
            (config.testpre > 0).then(|| Arc::new(PreConns::new(Duration::from_secs(120))));
        let preconn_once = Arc::new(std::sync::Once::new());
        Arc::new(move |dest: &Destination| {
            let config = Arc::clone(&config);
            let enc_client = enc_client.clone();
            let pre_conns = pre_conns.clone();
            let preconn_once = Arc::clone(&preconn_once);
            let target_addr = dest.address().clone();
            let target_port = dest.port();
            Box::pin(async move {
                if let Some(pool) = pre_conns.as_ref() {
                    let pool = Arc::clone(pool);
                    let cfg = Arc::clone(&config);
                    let count = cfg.testpre;
                    preconn_once.call_once(move || spawn_preconn_workers(cfg, pool, count));
                }
                establish_conn(
                    config,
                    enc_client,
                    pre_conns,
                    target_addr,
                    target_port,
                    handshake_timeout,
                )
                .await
            })
        })
    };
    if config.enc_params.is_none() {
        // 无 ENC：不存在票据失效路径，直接返回（不包重试层）。
        return Arc::new(move |dest: &Destination| establish(dest));
    }
    Arc::new(move |dest: &Destination| {
        let establish = Arc::clone(&establish);
        let dest = dest.clone();
        Box::pin(async move {
            let conn = establish(&dest).await?;
            Ok(Box::new(EncRetryConn::new(conn, establish, dest)) as Box<dyn Connection>)
        })
    })
}

/// 建立一条完整 VLESS 出站连接：dial → （可选 ENC 握手，带超时）→ 请求头 →
/// 响应头消费推迟 → （可选 vision 包装）。
async fn establish_conn(
    config: Arc<VlessOutboundConfig>,
    enc_client: Option<Arc<crate::encryption::ClientInstance>>,
    pre_conns: Option<Arc<PreConns>>,
    target_addr: Address,
    target_port: Port,
    handshake_timeout: std::time::Duration,
) -> Result<Box<dyn Connection>, String> {
    // 1. 取连接：testpre 池命中（免 TCP 握手）→ 用预连接。Go testpre>0 时
    //    消费端阻塞等池（outbound.go:174-183 `<-h.preConns`），从不自拨； worker 与消费者同
    //    runtime，await 让出即互不阻塞。pop 返回 None 仅在 pool 的 Sender
    //    全部释放时类型上可能（消费期间 pool 由闭包 持有不会发生），分支保留作防御兜底。
    let mut conn: Box<dyn Connection> = match pre_conns.as_ref() {
        Some(p) => match p.pop().await {
            Some(c) => c,
            None => dial_server_conn(&config).await?,
        },
        None => dial_server_conn(&config).await?,
    };

    // 2a. VLESS ENC 握手（仅当 config.enc_params 已注入时执行）。
    //     对齐 Go `proxy/vless/outbound/outbound.go:211-216`：dial 之后、写请求头
    //     之前执行 `h.encryption.Handshake(conn)`，用加密层 (CommonConn/XorConn)
    //     包装原始连接。timeout 包裹全程：服务端黑洞（accept 后不回握手响应）
    //     时本条拨号超时报错，连接不悬挂。
    if let Some(client) = enc_client {
        let enc_conn = match tokio::time::timeout(handshake_timeout, client.handshake(conn)).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => return Err(format!("vless enc handshake: {e}")),
            Err(_) => {
                return Err(format!(
                    "vless enc handshake timeout after {handshake_timeout:?}: server unresponsive"
                ));
            },
        };
        conn = Box::new(crate::encryption::EncConnectionAdapter::new(enc_conn));
    }

    // 2. 写 VLESS 请求头（version + uuid + addons + command + target addr/port）
    // addons.flow 从 config 取（bd vxk）：flow=xtls-rprx-vision 时服务端启用 Vision。
    let mut addons = empty_addons();
    addons.flow = config.flow.clone();
    encode_request_header(
        &mut conn,
        VERSION,
        &config.user_uuid,
        VlessCommand::Tcp,
        Some(&target_addr),
        Some(target_port.value()),
        &addons,
    )
    .await
    .map_err(|e| format!("vless encode header: {e}"))?;

    // 2b. 响应头消费推迟到读路径（对齐 Go postRequest/getResponse 并发时序：
    //     Go 服务端响应头经 BufferedWriter SetFlushNext 缓冲到首个下行数据
    //     才 flush；dial 阶段同步等待会让上行首包发不出去 → 双向互等 →
    //     服务端超时断开。vision 首块 uuid padding 尤甚，见 #9/#15/#32）。
    conn = Box::new(crate::encoding::client::ResponseHeaderReader::new(conn, VERSION));
    // 3. flow=xtls-rprx-vision（encryption=none）：请求头写出后即包装 VisionConn——padding
    //    从业务数据开始（对齐 Go outbound VisionWriter/ VisionReader 的包装时机，首块 padding
    //    携带本账号 uuid）。 ENC(mlkem768)+vision 组合走 CommonConn，见 bd 4lf/byo。
    if config.flow == crate::FLOW_XRV && config.encryption == "none" {
        let uuid_bytes = config.user_uuid.as_bytes().to_vec();
        // testseed：账户本地 padding 参数注入（对应 Go EncodeBodyAddons →
        // NewVisionWriter(account.Testseed)；不上 wire，len<4 时 builder 内兜底默认）。
        let mut vision = VisionConn::new(conn, uuid_bytes).with_padding_seed(&config.testseed);
        // Go 行为：postRequest 等 500ms 拿首块 client data,若拿不到就手动
        // 发一个空 content 的 padding 块（mb[0]=nil → VisionWriter 强制
        // XtlsPadding(None, CommandPaddingContinue) → 首块只有 uuid + 随机
        // padding,不带 client data）。Rust bridge 双向并发是立刻有 client
        // data,如果直接发首块 padding 会把 client data 当 content 一起塞进
        // uuid 块,导致 server VisionReader 解析失败 → 双向 Alert。
        // 修复:dispatcher 显式调 write_uuid_only_padding 先发 uuid-only
        // padding 块,后续 chunk 才进 vision content。
        vision
            .write_uuid_only_padding()
            .await
            .map_err(|e| format!("vless vision pre-padding: {e}"))?;
        conn = Box::new(vision);
    }

    // conn 现在是 "已握手完成的 TCP"，bridge_link_with_stream 直接用
    Ok(conn)
}

/// 判断错误是否为 0-RTT 票据拒绝（[`crate::encryption::TICKET_REJECTED_MSG`]）。
fn is_ticket_rejected(e: &io::Error) -> bool {
    e.to_string().contains(crate::encryption::TICKET_REJECTED_MSG)
}

/// ENC 0-RTT 票据失效自动恢复连接：首读遇票据拒绝专用错误时，重新执行一次
/// 完整拨号（新 TCP + 1-RTT 握手 + 新请求头，`establish` 内已由 CommonConn
/// 清空失效缓存）并重放读。仅失效路径多一次 dial，happy path 零开销。
/// 写路径不重试：业务写重放有数据完整性风险，失败照旧上抛。
struct EncRetryConn {
    inner: Box<dyn Connection>,
    establish: EstablishFn,
    dest: Destination,
    retried: bool,
    /// Mutex 包装只为 Sync（Connection 要求）：poll 单线程独占，锁无竞争。
    reconnecting: parking_lot::Mutex<
        Option<Pin<Box<dyn Future<Output = Result<Box<dyn Connection>, String>> + Send>>>,
    >,
}

impl EncRetryConn {
    fn new(inner: Box<dyn Connection>, establish: EstablishFn, dest: Destination) -> Self {
        Self { inner, establish, dest, retried: false, reconnecting: parking_lot::Mutex::new(None) }
    }
}

impl AsyncRead for EncRetryConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            {
                let mut slot = this.reconnecting.lock();
                if let Some(fut) = slot.as_mut() {
                    match fut.as_mut().poll(cx) {
                        Poll::Ready(Ok(conn)) => {
                            this.inner = conn;
                            *slot = None;
                            this.retried = true;
                        },
                        Poll::Ready(Err(e)) => {
                            *slot = None;
                            this.retried = true;
                            return Poll::Ready(Err(io::Error::other(format!(
                                "vless enc retry dial: {e}"
                            ))));
                        },
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
            match Pin::new(&mut *this.inner).poll_read(cx, buf) {
                Poll::Ready(Err(e)) if !this.retried && is_ticket_rejected(&e) => {
                    *this.reconnecting.lock() = Some((this.establish)(&this.dest));
                    continue;
                },
                r => return r,
            }
        }
    }
}

impl AsyncWrite for EncRetryConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Connection for EncRetryConn {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.remote_addr()
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }
}

/// 兼容：直接传 Addons（高级用户可注入 flow）。
#[allow(dead_code)]
pub fn make_dial_fn_with_addons(config: Arc<VlessOutboundConfig>, addons: Addons) -> DialFn {
    Arc::new(move |dest: &Destination| {
        let config = Arc::clone(&config);
        let addons = addons.clone();
        let target_addr = dest.address().clone();
        let target_port = dest.port();
        Box::pin(async move {
            let server_dest = config.server_destination();
            let sockopt =
                config.stream_settings.as_ref().map(|s| s.socket_options()).unwrap_or_default();
            let mut conn: Box<dyn Connection> = match &config.stream_settings {
                Some(s) => dial(&server_dest, s, &sockopt)
                    .await
                    .map_err(|e| format!("vless dial server ({}): {e}", s.protocol))?,
                None => xray_transport::system_dialer::dial_system(&server_dest, &sockopt)
                    .await
                    .map_err(|e| format!("vless dial server (tcp): {e}"))?,
            };
            encode_request_header(
                &mut conn,
                VERSION,
                &config.user_uuid,
                VlessCommand::Tcp,
                Some(&target_addr),
                Some(target_port.value()),
                &addons,
            )
            .await
            .map_err(|e| format!("vless encode header: {e}"))?;

            conn = Box::new(crate::encoding::client::ResponseHeaderReader::new(conn, VERSION));
            Ok(conn)
        })
    })
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use xray_common::{net::address::Address, uuid::UUID};

    use super::*;

    /// 读一个 Vision padding 块：`[uuid(16, 仅首块)][command(1)][content_len(2 BE)]
    /// [padding_len(2 BE)][content][padding]`。`has_uuid` = 首块（带 uuid 前缀）。
    /// 返回 (uuid, command, content, padding_len)。
    async fn read_vision_block(
        sock: &mut tokio::net::TcpStream,
        has_uuid: bool,
    ) -> (Option<Vec<u8>>, u8, Vec<u8>, usize) {
        use tokio::io::AsyncReadExt;
        let mut hdr = vec![0u8; if has_uuid { 21 } else { 5 }];
        sock.read_exact(&mut hdr).await.unwrap();
        let (uuid, off) = if has_uuid { (Some(hdr[..16].to_vec()), 16) } else { (None, 0) };
        let content_len = ((hdr[off + 1] as usize) << 8) | hdr[off + 2] as usize;
        let pad_len = ((hdr[off + 3] as usize) << 8) | hdr[off + 4] as usize;
        let mut content = vec![0u8; content_len];
        sock.read_exact(&mut content).await.unwrap();
        let mut pad = vec![0u8; pad_len];
        sock.read_exact(&mut pad).await.unwrap();
        (uuid, hdr[off], content, pad_len)
    }

    #[test]
    fn config_server_destination_roundtrip() {
        let uuid = UUID::new();
        let cfg = VlessOutboundConfig::new(
            uuid,
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(443),
        );
        let dest = cfg.server_destination();
        assert!(dest.is_tcp());
        assert_eq!(dest.port(), Port::new(443));
    }

    #[test]
    fn make_dial_fn_returns_arc_closure() {
        // 仅验证构造不 panic + Arc 计数正确
        let uuid = UUID::new();
        let cfg = Arc::new(VlessOutboundConfig::new(
            uuid,
            Address::new_domain("example.com"),
            Port::new(443),
        ));
        let _dial = make_dial_fn(Arc::clone(&cfg));
        assert_eq!(Arc::strong_count(&cfg), 2);
    }

    /// flow 字段上线验证：config.flow 经 make_dial_fn 写入请求头 addons.flow，
    /// 服务端 decode_request_header 应读到 xtls-rprx-vision。
    #[tokio::test]
    async fn make_dial_fn_sends_flow_in_request_header() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::{TcpListener, TcpStream},
        };
        use xray_proto::xray::proxy::vless::Account as ProtoAccount;

        use crate::{
            MemoryAccount, MemoryUser, MemoryValidator, Validator as _,
            encoding::server::decode_request_header,
        };

        let test_uuid = UUID::parse("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();

        // fake VLESS server：decode 请求头 → 断言 flow → 回响应头
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let validator = MemoryValidator::new();
        let mut proto_account = ProtoAccount::default();
        proto_account.id = "b831381d-6324-4d53-ad4f-8cda48b30811".to_string();
        let account = MemoryAccount::from_proto_account(&proto_account).unwrap();
        validator.add(MemoryUser::new("u", 0, account)).unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let decoded =
                decode_request_header(false, &mut None, &mut sock, &validator).await.unwrap();
            // 回响应头（version + addon_len）
            crate::encoding::server::encode_response_header(&mut sock, VERSION, &empty_addons())
                .await
                .unwrap();
            // drain 剩余（如果有）
            let mut buf = [0u8; 64];
            let _ = sock.read(&mut buf).await;
            decoded.addons.flow
        });

        // client：make_dial_fn（flow=xtls-rprx-vision）
        let cfg = Arc::new(
            VlessOutboundConfig::new(
                test_uuid,
                Address::from_ipv4_bytes([127, 0, 0, 1]),
                Port::new(addr.port()),
            )
            .with_flow("xtls-rprx-vision"),
        );
        let dial = make_dial_fn(cfg);
        let dest = Destination::tcp(Address::new_domain("target.example.com"), Port::new(80));
        let mut conn = dial(&dest).await.expect("dial should succeed");
        let _ = conn.write_all(b"x").await; // 触发服务端 drain

        let flow = server.await.unwrap();
        assert_eq!(flow, "xtls-rprx-vision", "flow must reach server request header");
    }

    /// flow=XRV 时 make_dial_fn 返回的连接必须已包 VisionConn。线上形态：
    /// 首块 = dial 内 write_uuid_only_padding 发出的 uuid-only padding 块
    /// `[uuid(16)][command][content_len=0][padding_len][padding]`；首个业务
    /// 写入 = 第二个 padding 块（uuid 已消费，无前缀）。未包装 → 首字节非
    /// uuid / 业务内容裸奔 → fail。
    #[tokio::test]
    async fn make_dial_fn_wraps_conn_with_vision_when_flow_xrv() {
        use tokio::time::{Duration, timeout};
        use xray_proto::xray::proxy::vless::Account as ProtoAccount;

        use crate::{
            MemoryAccount, MemoryUser, MemoryValidator, Validator as _,
            encoding::server::decode_request_header, encryption::vision::COMMAND_PADDING_CONTINUE,
        };

        let test_uuid = UUID::parse("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let server_uuid = test_uuid.as_bytes().to_vec();

        // fake VLESS server：decode 请求头 → 回响应头 → 读 uuid-only 块 → 读业务块
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let validator = MemoryValidator::new();
        let mut proto_account = ProtoAccount::default();
        proto_account.id = "b831381d-6324-4d53-ad4f-8cda48b30811".to_string();
        let account = MemoryAccount::from_proto_account(&proto_account).unwrap();
        validator.add(MemoryUser::new("u", 0, account)).unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _ = decode_request_header(false, &mut None, &mut sock, &validator).await.unwrap();
            // 注：此处不回 VLESS 响应头——本测试只验证上行 wire 形态，client
            // 不读；若先写响应头，client 关闭时接收队列有未读数据 → Windows
            // 以 RST 代 FIN → server 后续 read_exact 以 10053 中断。
            // 首块：uuid-only padding
            let (uuid1, cmd1, content1, _) = read_vision_block(&mut sock, true).await;
            assert_eq!(
                uuid1.as_deref(),
                Some(server_uuid.as_slice()),
                "first block must start with user uuid"
            );
            assert_eq!(cmd1, COMMAND_PADDING_CONTINUE, "data frame command");
            assert!(content1.is_empty(), "uuid-only block carries no content");
            // 第二块：业务 payload（uuid 写一次后不再出现）
            let (uuid2, cmd2, content2, _) = read_vision_block(&mut sock, false).await;
            assert!(uuid2.is_none(), "uuid must be written exactly once");
            assert_eq!(cmd2, COMMAND_PADDING_CONTINUE, "data frame command");
            content2
        });

        // client：make_dial_fn（flow=xtls-rprx-vision）
        let cfg = Arc::new(
            VlessOutboundConfig::new(
                test_uuid.clone(),
                Address::from_ipv4_bytes([127, 0, 0, 1]),
                Port::new(addr.port()),
            )
            .with_flow("xtls-rprx-vision"),
        );
        let dial = make_dial_fn(cfg);
        let dest = Destination::tcp(Address::new_domain("target.example.com"), Port::new(80));
        let mut conn = dial(&dest).await.expect("dial should succeed");
        conn.write_all(b"vision-payload").await.unwrap();
        conn.flush().await.unwrap();
        drop(conn);

        let payload: &[u8] = b"vision-payload";
        let content = timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
        assert_eq!(content, payload, "business block content must be the payload verbatim");
    }

    /// 回归（#9/#15/#32 early eof 根因）：dial 不得阻塞等待响应头。Go 服务端
    /// 响应头经 SetFlushNext 缓冲到首个下行数据才 flush——mock 服务端模拟该
    /// 时序：读完 uuid-only 块 + 业务块之后才写响应头。旧行为（dial 内同步
    /// decode_response_header）在此死锁 → 本测试超时失败。
    #[tokio::test]
    async fn vision_dial_returns_before_deferred_response_header() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
            time::{Duration, timeout},
        };
        use xray_proto::xray::proxy::vless::Account as ProtoAccount;

        use crate::{
            MemoryAccount, MemoryUser, MemoryValidator, Validator as _,
            encoding::server::decode_request_header,
            encryption::vision::{COMMAND_PADDING_CONTINUE, xtls_padding},
        };

        let test_uuid = UUID::parse("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let server_uuid = test_uuid.as_bytes().to_vec();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let validator = MemoryValidator::new();
        let mut proto_account = ProtoAccount::default();
        proto_account.id = "b831381d-6324-4d53-ad4f-8cda48b30811".to_string();
        let account = MemoryAccount::from_proto_account(&proto_account).unwrap();
        validator.add(MemoryUser::new("u", 0, account)).unwrap();

        // mock Go 服务端时序：请求头 → uuid-only 块 → 业务块 → 此时才回
        // 「响应头 + vision padding 块（echo 业务内容）」
        let payload: Vec<u8> = b"inner-clienthello".to_vec();
        let server_payload = payload.clone();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _ = decode_request_header(false, &mut None, &mut sock, &validator).await.unwrap();
            // 首块：uuid-only padding（此时尚未回响应头——dial 必须已先行返回）
            let (uuid1, cmd1, content1, _) = read_vision_block(&mut sock, true).await;
            assert_eq!(
                uuid1.as_deref(),
                Some(server_uuid.as_slice()),
                "server must see uuid-prefixed block"
            );
            assert_eq!(cmd1, COMMAND_PADDING_CONTINUE);
            assert!(content1.is_empty());
            // 业务块：client 首个 payload
            let (uuid2, _, content2, _) = read_vision_block(&mut sock, false).await;
            assert!(uuid2.is_none());
            assert_eq!(content2, server_payload, "server must receive the business payload");
            // 首块下行数据触发响应头 flush（Go SetFlushNext 语义）
            crate::encoding::server::encode_response_header(&mut sock, VERSION, &empty_addons())
                .await
                .unwrap();
            let mut uuid_opt = Some(server_uuid.clone());
            let mut rng = rand::rngs::StdRng::from_os_rng();
            let block = xtls_padding(
                Some(&content2),
                COMMAND_PADDING_CONTINUE,
                &mut uuid_opt,
                false,
                &crate::encryption::vision::DEFAULT_PADDING_SEED,
                &mut rng,
            );
            sock.write_all(&block).await.unwrap();
            sock.flush().await.unwrap();
            content2
        });

        let cfg = Arc::new(
            VlessOutboundConfig::new(
                test_uuid,
                Address::from_ipv4_bytes([127, 0, 0, 1]),
                Port::new(addr.port()),
            )
            .with_flow("xtls-rprx-vision"),
        );
        let dial = make_dial_fn(cfg);
        let dest = Destination::tcp(Address::new_domain("target.example.com"), Port::new(80));
        // 核心断言：服务端尚未写响应头，dial 必须先行返回（3s 内）
        let mut conn = timeout(Duration::from_secs(3), dial(&dest))
            .await
            .expect("dial must not block on deferred response header")
            .expect("dial ok");

        conn.write_all(&payload).await.unwrap();
        conn.flush().await.unwrap();
        let mut echo = vec![0u8; payload.len()];
        timeout(Duration::from_secs(5), conn.read_exact(&mut echo))
            .await
            .expect("downlink echo within 5s")
            .unwrap();
        assert_eq!(echo, payload, "vision roundtrip: header consumed + unpadded echo");

        let got = timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
        assert_eq!(got, payload);
    }

    /// 修复回归用例：ENC 共享实例的锁跨无超时握手 → 服务端黑洞（accept 后
    /// 不回握手响应）时 outbound 永久挂死。现在握手全程 60s 缺省超时
    /// （对齐 Go SessionDefault Handshake=60s），此处注入 500ms 短超时验证：
    /// dial 必须在超时窗口报错返回，而不是悬挂。
    #[tokio::test]
    async fn enc_handshake_blackhole_times_out() {
        use crate::encryption::ClientEncParams;
        // 黑洞 server：bind 后不 accept、不读、不回
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = Arc::new(
            VlessOutboundConfig::new(
                UUID::new(),
                Address::from_ipv4_bytes([127, 0, 0, 1]),
                Port::new(addr.port()),
            )
            .with_encryption_params(Some(ClientEncParams {
                keys: vec![vec![0xABu8; 32]],
                xor_mode: 0,
                seconds: 600,
                padding: String::new(),
            })),
        );
        let dial = make_dial_fn_with_handshake_timeout(cfg, Duration::from_millis(500));
        let dest = Destination::tcp(Address::new_domain("target.example.com"), Port::new(80));
        let started = std::time::Instant::now();
        let res = tokio::time::timeout(Duration::from_secs(5), dial(&dest))
            .await
            .expect("dial must not hang forever (regression: unbounded handshake)");
        let msg = match res {
            Err(msg) => msg,
            Ok(_) => panic!("black-holed handshake must fail"),
        };
        assert!(msg.contains("timeout"), "实际错误: {msg}");
        assert!(
            started.elapsed() >= Duration::from_millis(450),
            "应在握手超时窗口之后失败，实际 {:?}",
            started.elapsed()
        );
    }

    /// [`EncRetryConn`]：首读遇 0-RTT 票据拒绝专用错误 → 自动重拨一次（新握手）
    /// → 重放读成功；之后再次遇同类错误不再重试（只重试一次）。
    #[tokio::test]
    async fn enc_retry_conn_retries_once_on_ticket_rejection() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use tokio::io::AsyncReadExt as _;

        struct MockErrConn {
            msg: String,
        }
        impl AsyncRead for MockErrConn {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, self.msg.clone())))
            }
        }
        impl AsyncWrite for MockErrConn {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Err(io::Error::other("mock write")))
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        impl Connection for MockErrConn {
            fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }

            fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }
        }

        /// 先吐 9B 数据，读尽后报票据拒绝（模拟重连成功后再次失效）。
        struct MockDataThenErrConn {
            data: Vec<u8>,
            pos: usize,
        }
        impl AsyncRead for MockDataThenErrConn {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let this = self.get_mut();
                if this.pos < this.data.len() {
                    let n = (this.data.len() - this.pos).min(buf.remaining());
                    buf.put_slice(&this.data[this.pos..this.pos + n]);
                    this.pos += n;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    crate::encryption::TICKET_REJECTED_MSG,
                )))
            }
        }
        impl AsyncWrite for MockDataThenErrConn {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Err(io::Error::other("mock write")))
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        impl Connection for MockDataThenErrConn {
            fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }

            fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }
        }

        let dials = Arc::new(AtomicUsize::new(0));
        let establish: EstablishFn = {
            let dials = Arc::clone(&dials);
            Arc::new(move |_dest: &Destination| {
                let dials = Arc::clone(&dials);
                Box::pin(async move {
                    let n = dials.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        Ok(Box::new(MockErrConn {
                            msg: crate::encryption::TICKET_REJECTED_MSG.to_string(),
                        }) as Box<dyn Connection>)
                    } else {
                        Ok(Box::new(MockDataThenErrConn { data: b"recovered".to_vec(), pos: 0 })
                            as Box<dyn Connection>)
                    }
                })
            })
        };
        let dest = Destination::tcp(Address::from_ipv4_bytes([127, 0, 0, 1]), Port::new(443));
        let first = establish(&dest).await.expect("first dial ok");
        assert_eq!(dials.load(Ordering::SeqCst), 1);
        let mut rc = EncRetryConn::new(first, Arc::clone(&establish), dest);

        // 首读：BadConn 报票据拒绝 → 自动重拨 → GoodConn 数据重放成功
        let mut buf = [0u8; 9];
        rc.read_exact(&mut buf).await.expect("read must recover via retry");
        assert_eq!(&buf, b"recovered");
        assert_eq!(dials.load(Ordering::SeqCst), 2, "票据拒绝应恰好重拨一次");

        // 第二次同类错误：retried=true，不再重拨，错误直接上抛
        let mut buf2 = [0u8; 1];
        let err = rc.read_exact(&mut buf2).await.expect_err("second rejection must surface");
        assert!(is_ticket_rejected(&err));
        assert_eq!(dials.load(Ordering::SeqCst), 2, "只重试一次");
    }

    /// 空壳连接 stub：池操作不触碰 IO。
    fn mk_nop_conn() -> Box<dyn Connection> {
        use std::{
            io,
            pin::Pin,
            task::{Context, Poll},
        };

        use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

        struct NopConn;
        impl AsyncRead for NopConn {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }
        impl AsyncWrite for NopConn {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(buf.len()))
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        impl Connection for NopConn {
            fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }

            fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }
        }
        Box::new(NopConn)
    }

    /// 回归（bd ub53）：PreConns = Go unbuffered chan（outbound.go:161）的
    /// capacity=1 等价。池满（缓冲 1 + 无消费者）时 push 阻塞——空闲时
    /// worker 休息在 send 上零新拨号；消费者到场即时腾位交付。
    #[tokio::test]
    async fn preconn_push_blocks_until_consumer_arrives() {
        let pool = Arc::new(PreConns::new(Duration::from_secs(120)));

        // 第 1 条入缓冲即完成；第 2 条挂起（Go worker 休息在 send 上）。
        let p1 = Arc::clone(&pool);
        let push1 = tokio::spawn(async move { p1.push(mk_nop_conn()).await });
        let p2 = Arc::clone(&pool);
        let push2 = tokio::spawn(async move { p2.push(mk_nop_conn()).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(push1.is_finished(), "first push fills the buffer slot");
        assert!(
            !push2.is_finished(),
            "push must block when pool full and no consumer (Go unbuffered chan semantics)"
        );

        // 消费者到场 → 交付缓冲条目、push2 腾位完成。
        let got = pool.pop().await;
        assert!(got.is_some(), "consumer must receive the first conn");
        push1.await.unwrap().unwrap();
        push2.await.unwrap().expect("push2 completes once consumer arrived");
    }

    /// 排队延迟致交付即过期的条目被丢弃跳过（Go ConnExpire 消费检查同语义）。
    #[tokio::test]
    async fn preconn_expired_entry_skipped() {
        let pool = Arc::new(PreConns::new(Duration::from_millis(5)));
        // 第一条挂起在 send 上，50ms（> ttl）后交付即过期 → 弃。
        let p1 = Arc::clone(&pool);
        tokio::spawn(async move { p1.push(mk_nop_conn()).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        // 第二条在消费等待中 push（未过期）→ 被交付。
        let p2 = Arc::clone(&pool);
        let second = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            p2.push(mk_nop_conn()).await
        });
        let got = pool
            .pop()
            .await
            .expect("unexpired second entry must be delivered after skipping expired first");
        drop(got);
        second.await.unwrap().expect("second push delivered");
    }
}

//! `google-drive` 后端——Google Drive API v3 对象读写。对应 Go `drive.go`。
//!
//! 四操作映射：`Put` ≤12000B 走 inline（对象 description = base64 载荷，`create`），
//! 否则走 multipart media（`upload` 端点）；`Get` 先读 body、空体回读 inline
//! description；`List` 按 `name contains 'flat~'` 查询后取首层子级（inline 载荷
//! 从 description 解出）；`Delete` 先删自身再并发（8 路）删 `flat~` 前缀子树。
//!
//! 共享面（Go `driveShared`）：oauth2 refresh_token 流程（SyncTtlCache 单键缓存、
//! 单飞闸、后台预刷新、失败指数退避、`invalid_grant` 族粘滞 auth 错）、
//! 对象 id LRU 缓存（Go 无界 map → [`SyncLruCache`] 4096，miss 只多一次查询）、
//! 全局限流冷却（403 rate-limit/429 → `cool()`，后续请求先等冷却窗）。
//! 会话视图（Go `sessionStorage` → [`Storage::session`]）：走 XMUX 连接池的
//! `SessionTransport`，inflight/reserved 双信号量每会话独立（Go `laneKey`
//! reserved 车道 = 槽位控制面，B5 槽位读写以 `lane=true` 调 [`DriveStorage`] 槽位方法）。
//!
//! 与 Go 的已声明偏差：① 请求取消走任务层（[`Storage`]
//! 契约注释），无 per-call ctx——单飞等待不可提前取消（Go waiter 返回 ctx.Err
//! 的分支不存在）；② SessionTransport 的停滞退役钩子（Go `sessionTransport.stalled`）
//! 未接——client.rs 划归 B2 既有件不在本批领地，attempt 超时只计 `throttle`；
//! 其唯一消费点 `PoolConn::close` 已随 B5 删除（死方法，bd hjtlk 注记：B6 接
//! 钩子时随钩子重加）；
//! ③ announce 读取的 1MiB body cap（Go `maxBodyKey`）无上层注入面，恒 32MiB
//! cap 兜底；④ 子树删除并发 8 路以 8 分片 join 实现（Go goroutine + chan 信号量
//! 等价面，first-error 语义保留）。

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use http::{Method, StatusCode, Uri};
use std_ext::{
    cache::{SyncLruCache, SyncTtlCache},
    encode::{Base64Alphabet, base64_decode, base64_encode},
    id::RandomId,
};
use tokio::sync::Semaphore;
use xray_transport::dialer::StreamSettings;

use crate::{
    client::{
        ClientCore, ConnPool, DRIVE_INITIAL_BACKOFF_MS, DRIVE_MAX_ATTEMPTS, DRIVE_MAX_INFLIGHT,
        DRIVE_TIMEOUT, OutRequest, SessionTransport, UnitClient, build_unit_client,
        xdrive_xmux_config,
    },
    config::Config,
    storage::{Entry, SlotStore, Storage, is_not_found, not_found},
};

/// 单飞 token 缓存键（Go 单 token 字段；SyncTtlCache 单键承载过期判定）。
const TOKEN_KEY: &str = "token";

/// multipart 边界（Go `driveBoundary`）。
const DRIVE_BOUNDARY: &str = "xdrive-boundary";
/// files.list 单页条数（Go `drivePageSize`）。
const DRIVE_PAGE_SIZE: u32 = 1000;
/// reserved 车道并发（Go `driveReservedInflight`，槽位控制面）。
const DRIVE_RESERVED_INFLIGHT: usize = 8;
/// inline 上限（Go `driveInlineLimit`）：≤ 此值 Put 走 description 内联；环槽
/// announce 的 `first` 内嵌也受此约束（Go Dial 同款）。
pub(crate) const DRIVE_INLINE_LIMIT: usize = 12000;
/// 单尝试退避上限（Go `driveMaxBackoff`）。
const DRIVE_MAX_BACKOFF: Duration = Duration::from_secs(8);
/// 重试初始退避（Go `driveInitialBackoff`，client.rs 常量为毫秒）。
const DRIVE_INITIAL_BACKOFF: Duration = Duration::from_millis(DRIVE_INITIAL_BACKOFF_MS);
/// 限流冷却窗（Go `driveCooldown`，实际取 jitter 后值）。
const DRIVE_COOLDOWN: Duration = Duration::from_secs(2);
/// 槽位读尝试上限（Go `driveSlotRead`）。
const DRIVE_SLOT_READ: Duration = Duration::from_secs(3);
/// 槽位写尝试上限（Go `driveSlotWrite`，仅无 body 的 description 更新；
/// B5 经 [`SlotStore::set_slot`] 消费）。
const DRIVE_SLOT_WRITE: Duration = Duration::from_secs(5);
/// token 失败退避起点（Go `tokenRefreshBackoff`）。
const TOKEN_REFRESH_BACKOFF: Duration = Duration::from_secs(30);
/// token 失败退避封顶（Go `maxTokenBackoff`）。
const MAX_TOKEN_BACKOFF: Duration = Duration::from_secs(300);
/// token 取回超时（Go `accessToken` 的 fetch ctx 30s）。
const TOKEN_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// 响应体上限（Go `driveMaxResponse`）。
const DRIVE_MAX_RESPONSE: u64 = 32 << 20;
/// 对象 id 缓存容量（Go 无界 map；LRU 上限只影响 miss 率不影响正确性）。
const ID_CACHE_CAP: usize = 4096;
/// 子树删除并发分片数（Go `sem := make(chan struct{}, 8)`）。
const DELETE_SHARDS: usize = 8;

/// 一条 Drive API 请求的入参面（Go `do(ctx, method, target, contentType, body)`
/// 的 ctx 携带项展开为字段）。
struct DriveCall {
    method: Method,
    target: String,
    /// 空 = 不设 Content-Type（Go 空串判定）。
    content_type: &'static str,
    body: Option<Bytes>,
    /// reserved 车道（Go `laneKey`；槽位控制面请求为 true）。
    lane: bool,
    /// 单尝试时长上限（Go `attemptKey`）。
    attempt_timeout: Option<Duration>,
    /// 响应体上限（Go `maxBodyKey`；默认 [`DRIVE_MAX_RESPONSE`]）。
    body_cap: u64,
}

impl DriveCall {
    fn new(method: Method, target: String) -> Self {
        Self {
            method,
            target,
            content_type: "",
            body: None,
            lane: false,
            attempt_timeout: None,
            body_cap: DRIVE_MAX_RESPONSE,
        }
    }
}

/// 认证被拒（Go `authError`）：refresh_token 已失效族错误，粘滞到实例退役。
#[derive(Debug)]
struct AuthError(String);

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Google rejected the OAuth credentials ({}); create a new refresh token, see the XDRIVE setup guide",
            self.0
        )
    }
}

impl std::error::Error for AuthError {}

fn auth_error(code: &str) -> io::Error {
    io::Error::other(AuthError(code.to_string()))
}

pub(crate) fn is_auth_error(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|r| r.is::<AuthError>())
}

fn auth_code_of(e: &io::Error) -> Option<String> {
    e.get_ref().and_then(|r| r.downcast_ref::<AuthError>()).map(|a| a.0.clone())
}

/// API 端点三元组（Go 包级变量 `driveTokenURL`/`driveFilesURL`/`driveUploadURL`
/// → 实例字段；生产值见 [`Endpoints::prod`]，测试经 [`DriveStorage::with_base_url`] 注入）。
#[derive(Debug, Clone)]
struct Endpoints {
    token: String,
    files: String,
    upload: String,
}

impl Endpoints {
    fn prod() -> Self {
        Self {
            token: "https://oauth2.googleapis.com/token".to_string(),
            files: "https://www.googleapis.com/drive/v3/files".to_string(),
            upload:
                "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name"
                    .to_string(),
        }
    }

    /// mock 布局（Go fakeDrive 路径约定）：`{base}/token`、`{base}/files`、`{base}/upload`。
    fn with_base(base: &str) -> Self {
        Self {
            token: format!("{base}/token"),
            files: format!("{base}/files"),
            upload: format!("{base}/upload"),
        }
    }
}

/// token 状态（Go `tokenMu` 保护的一组字段；SyncTtlCache 单键承载 token 过期）。
struct TokenState {
    cache: SyncTtlCache<&'static str, String>,
    /// 原始寿命（Go `tokenLifetime`，预刷新窗口 = lifetime/5 的基数）。
    lifetime: Duration,
    /// 当前 token 的到期时刻（Go `tokenExpiry`，缓存 TTL 与此一致）。
    expires_at: std::time::Instant,
    refreshing: bool,
    /// 粘滞认证错误码（Go `authErr`；置位后恒拒绝直到实例退役）。
    auth_err: Option<String>,
    /// 退避到点前不再触碰端点（Go `tokenRetryAt`）。
    retry_at: Option<std::time::Instant>,
    backoff: Duration,
    last_err: Option<String>,
}

impl TokenState {
    fn new() -> Self {
        Self {
            cache: SyncTtlCache::new(xray_frame::compat::clock(), 1),
            lifetime: Duration::ZERO,
            expires_at: xray_frame::compat::clock().now_instant(),
            refreshing: false,
            auth_err: None,
            retry_at: None,
            backoff: Duration::ZERO,
            last_err: None,
        }
    }

    /// 失败退避推进（Go `noteTokenFailure`：30s 起、×2、封顶 5min；调用方持锁）。
    fn note_failure(&mut self, now: std::time::Instant) {
        self.backoff = if self.backoff.is_zero() {
            TOKEN_REFRESH_BACKOFF
        } else {
            (self.backoff * 2).min(MAX_TOKEN_BACKOFF)
        };
        self.retry_at = Some(now + self.backoff);
    }

    /// 存 token（Go `storeToken`：TTL = lifetime，>60s 扣 60s 提前量）。
    fn store(&mut self, token: String, lifetime: Duration, now: std::time::Instant) {
        self.lifetime = lifetime;
        let ttl = if lifetime > Duration::from_secs(60) {
            lifetime - Duration::from_secs(60)
        } else {
            lifetime
        };
        self.expires_at = now + ttl;
        self.cache.insert(TOKEN_KEY, token, ttl);
    }
}

/// 会话间共享面（Go `driveShared`）：池、凭据、端点、token/id 状态、冷却窗。
struct DriveShared {
    pool: Arc<ConnPool>,
    folder: String,
    client_id: String,
    client_secret: String,
    refresh_token: String,
    /// token 端点独立客户端（Go `tokenClient`）。
    token_client: UnitClient,
    endpoints: Endpoints,
    token: parking_lot::Mutex<TokenState>,
    /// 取 token 单飞闸（Go `tokenMu` 持锁跨取 token 流程的 async 对应）。
    token_gate: tokio::sync::Mutex<()>,
    /// 对象名 → 文件 id（Go `ids` map → LRU）。
    ids: SyncLruCache<String, String>,
    /// 限流冷却截止（Go `coolUntil`）。
    cool_until: parking_lot::Mutex<std::time::Instant>,
    /// 触发限流/尝试超时的累计次数（Go `throttle`）。
    throttle: AtomicU64,
}

/// `google-drive` 对象存储后端。基座实例（`Sink::Base`）用独立客户端；
/// 会话视图（`Sink::Session`，[`Storage::session`]）走 XMUX 连接池。
pub struct DriveStorage {
    shared: Arc<DriveShared>,
    sink: Sink,
    inflight: Arc<Semaphore>,
    reserved: Arc<Semaphore>,
}

#[allow(
    clippy::large_enum_variant,
    reason = "基座独立 hyper 客户端 vs 会话传输句柄是 Go driveStorage 双形态的固有尺寸；单存储仅两实例，不装箱"
)]
enum Sink {
    Base(UnitClient),
    Session(SessionTransport),
}

impl DriveStorage {
    /// 按流设置 + 配置构造（Go `newDriveStorage`）。
    ///
    /// 直接构造**不进**共享实例表（生产路径走 [`crate::storage::new_storage`] 的
    /// `shared_storage` 去重；测试注入口见 [`Self::with_base_url`]）。
    ///
    /// # Errors
    /// remoteFolder 为空、secrets 不是 3 元或含空值。
    pub fn new(settings: &StreamSettings, config: &Config) -> io::Result<Self> {
        Self::build(settings, config, Endpoints::prod())
    }

    /// 测试注入口（Go fakeDrive 换包级 URL 的等价面）：端点指向 `base`
    /// （`{base}/token|files|upload`）。非承诺公共 API。
    #[doc(hidden)]
    pub fn with_base_url(self, base: &str) -> Self {
        let mut rebuilt = Self::build_parts(
            Arc::clone(&self.shared.pool),
            self.shared.folder.clone(),
            self.shared.client_id.clone(),
            self.shared.client_secret.clone(),
            self.shared.refresh_token.clone(),
            shared_token_client_of(&self.shared),
            Endpoints::with_base(base),
        );
        rebuilt.sink = self.sink;
        rebuilt.inflight = Arc::clone(&self.inflight);
        rebuilt.reserved = Arc::clone(&self.reserved);
        rebuilt
    }

    fn build(settings: &StreamSettings, config: &Config, endpoints: Endpoints) -> io::Result<Self> {
        if config.remote_folder.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                r#"empty "remoteFolder", it must be a Google Drive folder id"#,
            ));
        }
        if config.secrets.len() != 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Google Drive needs 3 secrets in order of ClientID, ClientSecret, RefreshToken",
            ));
        }
        for (i, secret) in config.secrets.iter().enumerate() {
            if secret.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Google Drive secret {i} is empty"),
                ));
            }
        }

        let pool = Arc::new(ConnPool::new(settings, config)?);
        let keepalive = xdrive_xmux_config(config.xmux.as_ref(), &config.service, config.h3)?
            .h_keep_alive_period;
        let core = ClientCore::from_settings(settings, keepalive, config.h3)?;
        let base_client = build_unit_client(&core)?;
        Ok(Self::build_parts(
            pool,
            config.remote_folder.clone(),
            config.secrets[0].clone(),
            config.secrets[1].clone(),
            config.secrets[2].clone(),
            base_client,
            endpoints,
        ))
    }

    fn build_parts(
        pool: Arc<ConnPool>,
        folder: String,
        client_id: String,
        client_secret: String,
        refresh_token: String,
        token_client: UnitClient,
        endpoints: Endpoints,
    ) -> Self {
        let now = xray_frame::compat::clock().now_instant();
        Self {
            shared: Arc::new(DriveShared {
                pool,
                folder,
                client_id,
                client_secret,
                refresh_token,
                token_client: token_client.clone(),
                endpoints,
                token: parking_lot::Mutex::new(TokenState::new()),
                token_gate: tokio::sync::Mutex::new(()),
                ids: SyncLruCache::new(ID_CACHE_CAP),
                cool_until: parking_lot::Mutex::new(now),
                throttle: AtomicU64::new(0),
            }),
            sink: Sink::Base(token_client),
            inflight: Arc::new(Semaphore::new(DRIVE_MAX_INFLIGHT)),
            reserved: Arc::new(Semaphore::new(DRIVE_RESERVED_INFLIGHT)),
        }
    }

    /// 单次带认证发送（基座直连 / 会话走 XMUX 池），停滞上限 = [`DRIVE_TIMEOUT`]。
    async fn send_authenticated(
        &self,
        token: &str,
        call: &DriveCall,
    ) -> io::Result<(StatusCode, Bytes)> {
        let uri: Uri = call
            .target
            .parse()
            .map_err(|e| io::Error::other(format!("failed to build a Drive request: {e}")))?;
        let mut headers = Vec::with_capacity(2);
        headers.push(("Authorization".to_string(), format!("Bearer {token}")));
        if !call.content_type.is_empty() {
            headers.push(("Content-Type".to_string(), call.content_type.to_string()));
        }
        let req = OutRequest { method: call.method.clone(), uri, headers, body: call.body.clone() };
        match &self.sink {
            Sink::Base(client) => client.round_trip(req, DRIVE_TIMEOUT).await,
            Sink::Session(session) => session.round_trip(req, DRIVE_TIMEOUT).await,
        }
    }

    /// 带重试/冷却/双车道闸的请求执行（Go `do`：8 次、200ms 起倍增封顶 8s、
    /// 401 换 token、403 rate-limit 与 429 进冷却、429/500/502/503/504 可重试）。
    async fn do_request(&self, call: &DriveCall) -> io::Result<(u16, Vec<u8>)> {
        let mut backoff = DRIVE_INITIAL_BACKOFF;
        let mut last_err: Option<io::Error> = None;

        for attempt in 0..DRIVE_MAX_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(jitter(backoff)).await;
                backoff = (backoff * 2).min(DRIVE_MAX_BACKOFF);
            }
            self.wait_cool().await;

            let token = match self.access_token().await {
                Ok(token) => token,
                Err(e) => {
                    if is_auth_error(&e) {
                        return Err(e);
                    }
                    last_err = Some(e);
                    continue;
                },
            };

            let pool = if call.lane { &self.reserved } else { &self.inflight };
            let permit = match pool.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(e) => {
                    return Err(io::Error::other(format!("inflight semaphore closed: {e}")));
                },
            };
            let send = self.send_authenticated(&token, call);
            let round = match call.attempt_timeout {
                Some(limit) => match tokio::time::timeout(limit, send).await {
                    Ok(round) => round,
                    Err(_elapsed) => {
                        // 尝试超时（Go attemptCtx DeadlineExceeded）：计限流并重试。
                        self.shared.throttle.fetch_add(1, Ordering::Relaxed);
                        drop(permit);
                        last_err = Some(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("the attempt exceeded its {}s limit", limit.as_secs()),
                        ));
                        continue;
                    },
                },
                None => send.await,
            };
            drop(permit);

            let (status, payload) = match round {
                Ok(round) => round,
                Err(e) => {
                    last_err = Some(io::Error::other(format!("Drive request failed: {e}")));
                    continue;
                },
            };
            if u64::try_from(payload.len()).unwrap_or(u64::MAX) > call.body_cap {
                return Err(io::Error::other(format!(
                    "Drive response exceeds the {} byte cap",
                    call.body_cap
                )));
            }

            let code = status.as_u16();
            if status == StatusCode::UNAUTHORIZED {
                self.invalidate_token(&token);
                last_err = Some(io::Error::other("Drive rejected the access token"));
                continue;
            }
            if status == StatusCode::FORBIDDEN && rate_limited(&payload) {
                last_err = Some(io::Error::other(format!(
                    "Drive is rate limiting: {}",
                    String::from_utf8_lossy(&payload)
                )));
                self.cool();
                continue;
            }
            if retryable_status(code) {
                last_err = Some(io::Error::other(format!(
                    "Drive answered {code}: {}",
                    String::from_utf8_lossy(&payload)
                )));
                if code == 429 {
                    self.cool();
                }
                continue;
            }
            return Ok((code, payload.into()));
        }

        Err(last_err.unwrap_or_else(|| io::Error::other("Drive request exhausted its retries")))
    }

    /// 冷却窗等待（Go `waitCool`：截止在未来就睡到点）。
    async fn wait_cool(&self) {
        let until = *self.shared.cool_until.lock();
        let now = xray_frame::compat::clock().now_instant();
        if until > now {
            tokio::time::sleep(until - now).await;
        }
    }

    /// 进入冷却（Go `cool`：计限流 + 截止 = now + jitter(cooldown)）。
    fn cool(&self) {
        self.shared.throttle.fetch_add(1, Ordering::Relaxed);
        *self.shared.cool_until.lock() =
            xray_frame::compat::clock().now_instant() + jitter(DRIVE_COOLDOWN);
    }

    /// 限流累计次数（Go `throttled`；观测面，B5 槽位健康判定消费）。
    #[must_use]
    pub fn throttled(&self) -> u64 {
        self.shared.throttle.load(Ordering::Relaxed)
    }

    /// 取 oauth2 token（Go `accessToken`）：粘滞 auth 错短路 → 缓存命中（顺带
    /// 触发后台预刷新：剩余 < lifetime/5）→ 单飞闸内取回。
    async fn access_token(&self) -> io::Result<String> {
        let clock = xray_frame::compat::clock();
        let mut background = false;
        let cached = {
            let mut st = self.shared.token.lock();
            if let Some(code) = st.auth_err.clone() {
                return Err(auth_error(&code));
            }
            let now = clock.now_instant();
            match st.cache.get(&TOKEN_KEY) {
                Some(token) => {
                    let remaining = st.expires_at.saturating_duration_since(now);
                    if st.lifetime > Duration::ZERO
                        && remaining < st.lifetime / 5
                        && !st.refreshing
                        && st.retry_at.is_none_or(|at| now >= at)
                    {
                        st.refreshing = true;
                        background = true;
                    }
                    Some(token)
                },
                None => {
                    if st.retry_at.is_some_and(|at| now < at) {
                        if let Some(err) = st.last_err.clone() {
                            return Err(io::Error::other(err));
                        }
                    }
                    None
                },
            }
        };
        if let Some(token) = cached {
            if background {
                self.spawn_background_refresh();
            }
            return Ok(token);
        }

        // 单飞闸：排队者拿到闸后 double-check（Go flight 等待的等价面）。
        let _gate = self.shared.token_gate.lock().await;
        let cached = {
            let st = self.shared.token.lock();
            if let Some(code) = st.auth_err.clone() {
                return Err(auth_error(&code));
            }
            let now = clock.now_instant();
            match st.cache.get(&TOKEN_KEY) {
                Some(token) => Some(token),
                None => {
                    if st.retry_at.is_some_and(|at| now < at) {
                        if let Some(err) = st.last_err.clone() {
                            return Err(io::Error::other(err));
                        }
                    }
                    None
                },
            }
        };
        if let Some(token) = cached {
            return Ok(token);
        }

        let outcome = tokio::time::timeout(TOKEN_FETCH_TIMEOUT, self.fetch_token()).await;
        let mut st = self.shared.token.lock();
        let now = clock.now_instant();
        match outcome {
            Ok(Ok((token, lifetime))) => {
                st.store(token.clone(), lifetime, now);
                st.backoff = Duration::ZERO;
                st.retry_at = None;
                st.last_err = None;
                drop(st);
                drop(_gate);
                Ok(token)
            },
            Ok(Err(e)) => {
                let msg = e.to_string();
                if let Some(code) = auth_code_of(&e) {
                    if st.auth_err.is_none() {
                        st.auth_err = Some(code);
                    }
                }
                st.last_err = Some(msg.clone());
                st.note_failure(now);
                drop(st);
                drop(_gate);
                Err(io::Error::other(msg))
            },
            Err(_elapsed) => {
                let msg = "the token fetch timed out".to_string();
                st.last_err = Some(msg.clone());
                st.note_failure(now);
                drop(st);
                drop(_gate);
                Err(io::Error::other(msg))
            },
        }
    }

    /// 向 token 端点取新 token（Go `fetchToken`）：表单 QueryEscape 拼接
    /// （Go `url.Values.Encode` 同规则）。
    async fn fetch_token(&self) -> io::Result<(String, Duration)> {
        fetch_token_via(
            &self.shared.token_client,
            &self.shared.endpoints.token,
            &self.shared.client_id,
            &self.shared.client_secret,
            &self.shared.refresh_token,
        )
        .await
    }

    /// 后台预刷新（Go `refreshTokenBackground`）：一次性任务自带 30s 超时终点。
    fn spawn_background_refresh(&self) {
        let shared = Arc::clone(&self.shared);
        let spawn_res = xray_frame::compat::spawn(async move {
            let outcome = tokio::time::timeout(
                TOKEN_FETCH_TIMEOUT,
                fetch_token_via(
                    &shared.token_client,
                    &shared.endpoints.token,
                    &shared.client_id,
                    &shared.client_secret,
                    &shared.refresh_token,
                ),
            )
            .await;
            let mut st = shared.token.lock();
            st.refreshing = false;
            let now = xray_frame::compat::clock().now_instant();
            match outcome {
                Ok(Ok((token, lifetime))) => {
                    if st.auth_err.is_none() {
                        st.store(token, lifetime, now);
                        st.backoff = Duration::ZERO;
                        st.retry_at = None;
                        st.last_err = None;
                    }
                },
                Ok(Err(e)) => {
                    if let Some(code) = auth_code_of(&e) {
                        if st.auth_err.is_none() {
                            st.auth_err = Some(code);
                        }
                    }
                    st.last_err = Some(e.to_string());
                    st.note_failure(now);
                },
                Err(_elapsed) => {
                    st.last_err = Some("the background token refresh timed out".to_string());
                    st.note_failure(now);
                },
            }
        });
        if spawn_res.is_err() {
            self.shared.token.lock().refreshing = false;
            crate::LOG.warn("xdrive drive: background token refresh spawn rejected");
        }
    }

    /// 失效当前 token（Go `invalidateToken`：仅当仍是取回时用的那个）。
    fn invalidate_token(&self, used: &str) {
        let st = self.shared.token.lock();
        if st.cache.get(&TOKEN_KEY).is_some_and(|current| current == used) {
            let _ = st.cache.remove(&TOKEN_KEY);
        }
    }

    fn remember_id(&self, name: &str, id: &str) {
        self.shared.ids.insert(name.to_string(), id.to_string());
    }

    fn forget_id(&self, name: &str) {
        let _ = self.shared.ids.remove(&name.to_string());
    }

    /// 分页查询（Go `query`）：folder 过滤 + 调用方条件，条目名 → (id, description)
    /// 并顺带刷新 id 缓存。
    async fn query(
        &self,
        condition: &str,
    ) -> io::Result<std::collections::HashMap<String, (String, String)>> {
        let mut found = std::collections::HashMap::new();
        let mut page_token = String::new();
        let q = format!(
            "'{}' in parents and trashed = false and {condition}",
            quote_drive_value(&self.shared.folder)
        );
        loop {
            // Go url.Values.Encode 按键字典序输出。
            let mut target = format!(
                "{}?fields={}&includeItemsFromAllDrives=true&pageSize={}&q={}&supportsAllDrives=true",
                self.shared.endpoints.files,
                query_escape("nextPageToken,files(id,name,description)"),
                DRIVE_PAGE_SIZE,
                query_escape(&q),
            );
            if !page_token.is_empty() {
                target.push_str(&format!("&pageToken={}", query_escape(&page_token)));
            }
            let call = DriveCall::new(Method::GET, target);
            let (status, payload) = self.do_request(&call).await?;
            if status != StatusCode::OK.as_u16() {
                return Err(io::Error::other(format!(
                    "Drive listing answered {status}: {}",
                    String::from_utf8_lossy(&payload)
                )));
            }

            let parsed: serde_json::Value = serde_json::from_slice(&payload)
                .map_err(|e| io::Error::other(format!("failed to parse the Drive listing: {e}")))?;
            if let Some(files) = parsed.get("files").and_then(|v| v.as_array()) {
                for file in files {
                    let name = file.get("name").and_then(|v| v.as_str()).unwrap_or_default();
                    let id = file.get("id").and_then(|v| v.as_str()).unwrap_or_default();
                    let description =
                        file.get("description").and_then(|v| v.as_str()).unwrap_or_default();
                    if name.is_empty() || id.is_empty() {
                        continue;
                    }
                    self.remember_id(name, id);
                    found.insert(name.to_string(), (id.to_string(), description.to_string()));
                }
            }
            page_token = parsed
                .get("nextPageToken")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if page_token.is_empty() {
                return Ok(found);
            }
        }
    }

    /// 对象名 → 文件 id（Go `resolveID`）：缓存命中即返，否则按精确名查询。
    async fn resolve_id(&self, flat: &str) -> io::Result<String> {
        if let Some(id) = self.shared.ids.get(&flat.to_string()) {
            return Ok(id);
        }
        let found = self.query(&format!("name = '{}'", quote_drive_value(flat))).await?;
        found.get(flat).map(|(id, _)| id.clone()).ok_or_else(not_found)
    }

    /// inline 创建（Go `create`）：对象无 body，description 携带 base64 载荷。
    async fn create(&self, name: &str, description: &str) -> io::Result<String> {
        let flat = flatten(name);
        let metadata = serde_json::json!({"name": flat, "parents": [self.shared.folder], "description": description});
        let call = DriveCall {
            content_type: "application/json; charset=UTF-8",
            body: Some(Bytes::from(metadata.to_string())),
            target: format!("{}?fields=id", self.shared.endpoints.files),
            ..DriveCall::new(Method::POST, String::new())
        };
        let (status, payload) = self.do_request(&call).await?;
        if status != StatusCode::OK.as_u16() {
            return Err(io::Error::other(format!(
                "Drive rejected the inline upload of {name} with {status}: {}",
                String::from_utf8_lossy(&payload)
            )));
        }
        let id = parse_upload_id(&payload)?;
        if !id.is_empty() {
            self.remember_id(&flat, &id);
        }
        Ok(id)
    }

    /// multipart 上传（Go `putMedia`）：metadata + data 一请求（`upload` 端点）。
    async fn put_media(&self, name: &str, data: &[u8]) -> io::Result<()> {
        let flat = flatten(name);
        let metadata = serde_json::json!({"name": flat, "parents": [self.shared.folder]});
        let call = DriveCall {
            content_type: "multipart/related; boundary=xdrive-boundary",
            body: Some(Bytes::from(multipart_body(metadata.to_string().as_bytes(), data))),
            target: self.shared.endpoints.upload.clone(),
            ..DriveCall::new(Method::POST, String::new())
        };
        let (status, payload) = self.do_request(&call).await?;
        if status != StatusCode::OK.as_u16() {
            return Err(io::Error::other(format!(
                "Drive upload of {name} answered {status}: {}",
                String::from_utf8_lossy(&payload)
            )));
        }
        let id = parse_upload_id(&payload)?;
        if !id.is_empty() {
            self.remember_id(&flat, &id);
        }
        Ok(())
    }

    /// inline 读回（Go `getInline`）：description 的 base64 解码。
    async fn get_inline(&self, id: &str) -> io::Result<Vec<u8>> {
        let description = SlotStore::read_description(self, id, false).await?;
        if description.is_empty() {
            return Ok(Vec::new());
        }
        base64_decode(&description, Base64Alphabet::Std)
            .map_err(|e| io::Error::other(format!("the inline data is not valid base64: {e}")))
    }

    /// 删单对象（Go `deleteID`）：404 视为已删（幂等）。
    async fn delete_id(&self, flat: &str, id: &str) -> io::Result<()> {
        let call = DriveCall::new(
            Method::DELETE,
            format!("{}/{}?supportsAllDrives=true", self.shared.endpoints.files, path_escape(id)),
        );
        let (status, payload) = self.do_request(&call).await?;
        self.forget_id(flat);
        if matches!(status, 200 | 204 | 404) {
            return Ok(());
        }
        Err(io::Error::other(format!(
            "Drive deletion of {flat} answered {status}: {}",
            String::from_utf8_lossy(&payload)
        )))
    }

    /// 子树删除分片（[`Storage::delete`] 的 8 路并发臂）：串行删本分片，
    /// 返回首个错误。
    async fn delete_shard(&self, items: Vec<(String, String)>) -> Option<io::Error> {
        let mut first: Option<io::Error> = None;
        for (child, id) in items {
            if let Err(e) = self.delete_id(&child, &id).await {
                if first.is_none() {
                    first = Some(e);
                }
            }
        }
        first
    }

    /// 槽位体读（Go `readBody`，`slotStore`）。404 → NotFound。
    pub(crate) async fn read_body_by_id(&self, id: &str) -> io::Result<Vec<u8>> {
        let call = DriveCall::new(
            Method::GET,
            format!(
                "{}/{}?alt=media&supportsAllDrives=true",
                self.shared.endpoints.files,
                path_escape(id)
            ),
        );
        let (status, payload) = self.do_request(&call).await?;
        match status {
            404 => Err(not_found()),
            200 => Ok(payload),
            other => Err(io::Error::other(format!(
                "Drive answered {other} for the body of {id}: {}",
                String::from_utf8_lossy(&payload)
            ))),
        }
    }
}

/// 上传应答的 id 解析（Go create/putMedia 共用面）。
fn parse_upload_id(payload: &[u8]) -> io::Result<String> {
    let parsed: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|e| io::Error::other(format!("failed to parse the Drive upload response: {e}")))?;
    Ok(parsed.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string())
}

/// token 端点一次取回（Go `fetchToken` 的自由函数面：前台与后台任务共用）。
async fn fetch_token_via(
    client: &UnitClient,
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> io::Result<(String, Duration)> {
    let form = format!(
        "client_id={}&client_secret={}&refresh_token={}&grant_type=refresh_token",
        query_escape(client_id),
        query_escape(client_secret),
        query_escape(refresh_token),
    );
    let uri: Uri = token_url
        .parse()
        .map_err(|e| io::Error::other(format!("failed to build the token request: {e}")))?;
    let (status, payload) = client
        .round_trip(
            OutRequest {
                method: Method::POST,
                uri,
                headers: vec![(
                    "Content-Type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                )],
                body: Some(form.into()),
            },
            DRIVE_TIMEOUT,
        )
        .await
        .map_err(|e| io::Error::other(format!("failed to refresh the access token: {e}")))?;

    if status != StatusCode::OK {
        let text = String::from_utf8_lossy(&payload);
        if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&payload) {
            if let Some(code) = parsed.get("error").and_then(|e| e.as_str()) {
                if matches!(code, "invalid_grant" | "invalid_client" | "unauthorized_client") {
                    return Err(auth_error(code));
                }
            }
        }
        return Err(io::Error::other(format!(
            "the token endpoint answered {}: {text}",
            status.as_u16()
        )));
    }

    let parsed: serde_json::Value = serde_json::from_slice(&payload)
        .map_err(|e| io::Error::other(format!("failed to parse the token response: {e}")))?;
    let token = parsed.get("access_token").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    if token.is_empty() {
        return Err(io::Error::other("the token endpoint returned no access token"));
    }
    let lifetime = Duration::from_secs(
        u64::try_from(parsed.get("expires_in").and_then(|v| v.as_i64()).unwrap_or_default().max(0))
            .unwrap_or(u64::MAX),
    );
    Ok((token, lifetime))
}

/// `with_base_url` 需要的 token 客户端克隆面（hyper 客户端 Clone 廉价）。
fn shared_token_client_of(shared: &DriveShared) -> UnitClient {
    shared.token_client.clone()
}

/// 退避抖动（Go `jitter`）：纳秒粒度均匀取 [half, backoff)；过半截断退避恒原值。
fn jitter(backoff: Duration) -> Duration {
    let half = backoff / 2;
    if half.is_zero() {
        return backoff;
    }
    let mut buf = [0u8; 8];
    let _ = RandomId::fill(&mut buf);
    // half ≤ maxTokenBackoff(5min) ⇒ as_nanos 恒装得进 u64。
    let pick = u64::from_le_bytes(buf) % half.as_nanos() as u64;
    half + Duration::from_nanos(pick)
}

/// 403 响应体的限流判定（Go `rateLimited`）：reason 三命中或 status =
/// RESOURCE_EXHAUSTED。
fn rate_limited(payload: &[u8]) -> bool {
    let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(payload) else {
        return false;
    };
    let Some(error) = parsed.get("error") else { return false };
    if let Some(errors) = error.get("errors").and_then(|v| v.as_array()) {
        for item in errors {
            if let Some(reason) = item.get("reason").and_then(|v| v.as_str()) {
                if matches!(
                    reason,
                    "rateLimitExceeded" | "userRateLimitExceeded" | "sharingRateLimitExceeded"
                ) {
                    return true;
                }
            }
        }
    }
    error.get("status").and_then(|v| v.as_str()) == Some("RESOURCE_EXHAUSTED")
}

/// 可重试状态码（Go `retryableStatus`）：429/500/502/503/504。
fn retryable_status(status: u16) -> bool {
    matches!(status, 429 | 500 | 502 | 503 | 504)
}

/// Go `url.QueryEscape` 同规则：保留 `A-Za-z0-9-_.~`，空格 → `+`，其余 %XX。
fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            },
            b' ' => out.push('+'),
            other => out.extend(format!("%{other:02X}").chars()),
        }
    }
    out
}

/// Go `url.PathEscape` 同规则（文件 id 段；空格 → %20，与 query 面不同）。
fn path_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            },
            other => out.extend(format!("%{other:02X}").chars()),
        }
    }
    out
}

/// multipart 上传体（Go `multipartBody`）：metadata + data 两段，边界
/// `xdrive-boundary`，字节级对齐 Go（单元测试断言边界）。
fn multipart_body(metadata: &[u8], data: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(metadata.len() + data.len() + 128);
    body.extend_from_slice(
        format!("--{DRIVE_BOUNDARY}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(metadata);
    body.extend_from_slice(
        format!("\r\n--{DRIVE_BOUNDARY}\r\nContent-Type: application/octet-stream\r\n\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(data);
    body.extend_from_slice(format!("\r\n--{DRIVE_BOUNDARY}--\r\n").as_bytes());
    body
}

/// 对象名展平（Go `flatten`）：`/` → `~`。
fn flatten(name: &str) -> String {
    name.replace('/', "~")
}

/// 查询值转义（Go `quoteDriveValue`）：`\` → `\\`、`'` → `\'`。
fn quote_drive_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

#[async_trait]
impl Storage for DriveStorage {
    async fn put(&self, name: &str, data: &[u8]) -> io::Result<()> {
        if data.len() <= DRIVE_INLINE_LIMIT {
            let description = base64_encode(data, Base64Alphabet::Std, true);
            self.create(name, &description).await.map(|_| ())
        } else {
            self.put_media(name, data).await
        }
    }

    async fn get(&self, name: &str) -> io::Result<Vec<u8>> {
        let flat = flatten(name);
        let id = self.resolve_id(&flat).await?;
        match self.read_body_by_id(&id).await {
            Ok(payload) if !payload.is_empty() => Ok(payload),
            Ok(_) => self.get_inline(&id).await,
            Err(e) => {
                if is_not_found(&e) {
                    self.forget_id(&flat);
                }
                Err(e)
            },
        }
    }

    async fn delete(&self, name: &str) -> io::Result<()> {
        let flat = flatten(name);
        match self.resolve_id(&flat).await {
            Ok(id) => self.delete_id(&flat, &id).await?,
            Err(e) if is_not_found(&e) => {},
            Err(e) => return Err(e),
        }

        let children = self
            .query(&format!("name contains '{}'", quote_drive_value(&format!("{flat}~"))))
            .await?;
        if children.is_empty() {
            return Ok(());
        }

        // 并发 8 路（Go goroutine + chan 信号量 → 固定 8 分片 join!；first-error 保留）。
        let mut order: Vec<(String, String)> =
            children.into_iter().map(|(name, (id, _))| (name, id)).collect();
        order.sort_by(|a, b| a.0.cmp(&b.0));
        let mut shards: [Vec<(String, String)>; DELETE_SHARDS] = Default::default();
        for (i, item) in order.into_iter().enumerate() {
            shards[i % DELETE_SHARDS].push(item);
        }
        let [s0, s1, s2, s3, s4, s5, s6, s7] = shards;
        let (r0, r1, r2, r3, r4, r5, r6, r7) = tokio::join!(
            self.delete_shard(s0),
            self.delete_shard(s1),
            self.delete_shard(s2),
            self.delete_shard(s3),
            self.delete_shard(s4),
            self.delete_shard(s5),
            self.delete_shard(s6),
            self.delete_shard(s7),
        );
        let first_err = [r0, r1, r2, r3, r4, r5, r6, r7].into_iter().flatten().next();
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    async fn list(&self, prefix: &str) -> io::Result<Vec<Entry>> {
        let flat = format!("{}~", flatten(prefix));
        let found = self.query(&format!("name contains '{}'", quote_drive_value(&flat))).await?;

        let mut seen = std::collections::HashSet::with_capacity(found.len());
        let mut entries = Vec::with_capacity(found.len());
        for (name, (_id, description)) in found {
            let Some(rest) = name.strip_prefix(&flat) else { continue };
            if rest.is_empty() {
                continue;
            }
            let direct = !rest.contains('~');
            let rest = match rest.split_once('~') {
                Some((first, _)) => first.to_string(),
                None => rest.to_string(),
            };
            if !seen.insert(rest.clone()) {
                continue;
            }
            let inline = if direct && !description.is_empty() {
                base64_decode(&description, Base64Alphabet::Std).ok()
            } else {
                None
            };
            entries.push(Entry { name: rest, inline });
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    async fn close(&self) -> io::Result<()> {
        if let Sink::Session(session) = &self.sink {
            session.close();
        }
        Ok(())
    }

    fn session(&self) -> Option<Arc<dyn Storage>> {
        Some(Arc::new(DriveStorage {
            shared: Arc::clone(&self.shared),
            sink: Sink::Session(SessionTransport::new(Arc::clone(&self.shared.pool.xmux))),
            inflight: Arc::new(Semaphore::new(DRIVE_MAX_INFLIGHT)),
            reserved: Arc::new(Semaphore::new(DRIVE_RESERVED_INFLIGHT)),
        }))
    }

    /// 仅 google-drive 有槽位能力（Go `storage.(slotStore)` 断言的等价口）。
    fn as_slot_store(&self) -> Option<&dyn SlotStore> {
        Some(self)
    }

    fn slot_store(self: Arc<Self>) -> Option<Arc<dyn SlotStore>> {
        Some(self)
    }
}

/// 槽位四方法（Go `slotStore` 接口的 Rust 实现；B4 落请求面、B5 上收 trait 并
/// 由 `slots.rs` 环形槽位消费）。`lane` 进 reserved 车道（Go `laneKey`）。
#[async_trait]
impl SlotStore for DriveStorage {
    async fn make_slot(&self, name: &str, lane: bool) -> io::Result<String> {
        let metadata = serde_json::json!({
            "name": flatten(name),
            "parents": [self.shared.folder],
            "description": "",
        });
        let call = DriveCall {
            content_type: "application/json; charset=UTF-8",
            body: Some(Bytes::from(metadata.to_string())),
            target: format!("{}?fields=id", self.shared.endpoints.files),
            lane,
            ..DriveCall::new(Method::POST, String::new())
        };
        let (status, payload) = self.do_request(&call).await?;
        if status != StatusCode::OK.as_u16() {
            return Err(io::Error::other(format!(
                "Drive rejected the slot creation of {name} with {status}: {}",
                String::from_utf8_lossy(&payload)
            )));
        }
        let id = parse_upload_id(&payload)?;
        if id.is_empty() {
            return Err(io::Error::other(format!("Drive returned no id for {name}")));
        }
        self.remember_id(&flatten(name), &id);
        Ok(id)
    }

    async fn set_slot(
        &self,
        id: &str,
        description: &str,
        body: Option<&[u8]>,
        lane: bool,
    ) -> io::Result<()> {
        let mut call = DriveCall::new(Method::PATCH, String::new());
        if body.is_none() {
            call.attempt_timeout = Some(DRIVE_SLOT_WRITE);
        }
        call.lane = lane;
        let metadata = serde_json::json!({ "description": description }).to_string();
        if let Some(data) = body {
            call.content_type = "multipart/related; boundary=xdrive-boundary";
            call.body = Some(Bytes::from(multipart_body(metadata.as_bytes(), data)));
            call.target = format!(
                "{}/{}?uploadType=multipart&fields=id&supportsAllDrives=true",
                self.shared.endpoints.upload,
                path_escape(id)
            );
        } else {
            call.content_type = "application/json; charset=UTF-8";
            call.body = Some(Bytes::from(metadata));
            call.target = format!(
                "{}/{}?fields=id&supportsAllDrives=true",
                self.shared.endpoints.files,
                path_escape(id)
            );
        }
        let (status, payload) = self.do_request(&call).await?;
        match status {
            404 => Err(not_found()),
            200 => Ok(()),
            other => Err(io::Error::other(format!(
                "Drive answered {other} for the update of {id}: {}",
                String::from_utf8_lossy(&payload)
            ))),
        }
    }

    async fn read_description(&self, id: &str, lane: bool) -> io::Result<String> {
        let mut call = DriveCall::new(
            Method::GET,
            format!(
                "{}/{}?fields=description&supportsAllDrives=true",
                self.shared.endpoints.files,
                path_escape(id)
            ),
        );
        call.attempt_timeout = Some(DRIVE_SLOT_READ);
        call.lane = lane;
        let (status, payload) = self.do_request(&call).await?;
        match status {
            404 => Err(not_found()),
            200 => {
                let parsed: serde_json::Value = serde_json::from_slice(&payload).map_err(|e| {
                    io::Error::other(format!("failed to parse the description of {id}: {e}"))
                })?;
                Ok(parsed
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string())
            },
            other => Err(io::Error::other(format!(
                "Drive answered {other} for the description of {id}: {}",
                String::from_utf8_lossy(&payload)
            ))),
        }
    }

    async fn read_body(&self, id: &str) -> io::Result<Vec<u8>> {
        self.read_body_by_id(id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flatten_replaces_slashes() {
        assert_eq!(flatten("streams/abc/c2s/0.seg"), "streams~abc~c2s~0.seg");
        assert_eq!(flatten("plain"), "plain");
    }

    #[test]
    fn quote_escapes_backslash_and_quote() {
        assert_eq!(quote_drive_value("a'b\\c"), "a\\'b\\\\c");
    }

    #[test]
    fn query_escape_matches_go_rules() {
        assert_eq!(query_escape("a b+c~d.e_f-g"), "a+b%2Bc~d.e_f-g");
        assert_eq!(query_escape("'x'"), "%27x%27");
        assert_eq!(query_escape("ф"), "%D1%84");
        assert_eq!(path_escape("a b"), "a%20b");
    }

    #[test]
    fn multipart_body_boundary_layout() {
        let body = multipart_body(b"{meta}", b"payload");
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "--xdrive-boundary\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n\
             {meta}\r\n--xdrive-boundary\r\nContent-Type: application/octet-stream\r\n\r\n\
             payload\r\n--xdrive-boundary--\r\n"
        );
    }

    #[test]
    fn rate_limit_reasons_and_status() {
        assert!(rate_limited(
            br#"{"error":{"code":403,"errors":[{"reason":"userRateLimitExceeded"}]}}"#
        ));
        assert!(rate_limited(
            br#"{"error":{"code":403,"errors":[{"reason":"rateLimitExceeded"}]}}"#
        ));
        assert!(rate_limited(
            br#"{"error":{"code":403,"errors":[{"reason":"sharingRateLimitExceeded"}]}}"#
        ));
        assert!(rate_limited(br#"{"error":{"status":"RESOURCE_EXHAUSTED"}}"#));
        assert!(!rate_limited(br#"{"error":{"code":403,"errors":[{"reason":"forbidden"}]}}"#));
        assert!(!rate_limited(b"not json"));
        assert!(!rate_limited(br#"{"other":1}"#));
    }

    #[test]
    fn retryable_statuses() {
        for code in [429, 500, 502, 503, 504] {
            assert!(retryable_status(code), "{code} must be retryable");
        }
        for code in [400, 401, 403, 404, 418] {
            assert!(!retryable_status(code), "{code} must not be retryable");
        }
    }

    #[test]
    fn jitter_stays_within_backoff() {
        for base in [200, 400, 8000] {
            let backoff = Duration::from_millis(base);
            for _ in 0..50 {
                let j = jitter(backoff);
                assert!(j >= backoff / 2 && j < backoff, "jitter {j:?} out of [half, {backoff:?})");
            }
        }
        // 亚毫秒退避也保持 [half, backoff)（Go 纳秒粒度）。
        for _ in 0..20 {
            let j = jitter(Duration::from_millis(1));
            assert!(
                j >= Duration::from_micros(500) && j <= Duration::from_millis(1),
                "jitter {j:?} out of [500µs, 1ms]"
            );
        }
    }

    #[test]
    fn auth_error_display_and_detect() {
        let err = auth_error("invalid_grant");
        assert!(is_auth_error(&err));
        assert!(err.to_string().starts_with(
            "Google rejected the OAuth credentials (invalid_grant); create a new refresh token"
        ));
        assert_eq!(auth_code_of(&err).as_deref(), Some("invalid_grant"));
        assert!(!is_auth_error(&io::Error::other("plain")));
    }
}

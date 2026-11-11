//! Dial/Serve/Listener。对应 Go `xdrive.go`（B1 落 WAL 分段路径；B5 补环形槽位
//! announce 路与 `spareBox` 预热点池）。

use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::{Duration, Instant},
};

use std_ext::{
    encode::{HexCase, hex_encode},
    id::RandomId,
};
use xray_common::net::destination::Destination;
use xray_transport::{
    connection::Connection,
    dialer::StreamSettings,
    listener_registry::{ConnHandler, TransportListener},
    sockopt::SocketOptions,
};

use crate::{
    LOG,
    config::Config,
    conn::{Conn, SessionTasks},
    drive::DRIVE_INLINE_LIMIT,
    params::Params,
    slots::{
        DEFAULT_TUNING, Ring, SLOT_INLINE_LIMIT, SlotWriter, decode_ring, encode_ring, make_ring,
        new_slot_reader, new_slot_writer,
    },
    storage::{Storage, new_storage, session_storage, share_key},
};

pub(crate) const PROTOCOL_NAME: &str = "xdrive";
const SESSIONS_DIR: &str = "sessions";
const STREAMS_DIR: &str = "streams";
const UPLINK_DIR: &str = "c2s";
const DOWNLINK_DIR: &str = "s2c";

/// 会话 ID（Go `newSessionID`：16 随机字节 hex；RandomId 内核同为 getrandom
/// 16 字节 CSPRNG，无弱熵回退）。
pub(crate) fn new_session_id() -> io::Result<String> {
    let id = RandomId::new()
        .map_err(|e| io::Error::other(format!("failed to generate session id: {e}")))?;
    Ok(hex_encode(&id.as_u128().to_be_bytes(), HexCase::Lower))
}

/// announce 对象名（Go `announceName`）：`sessions/<unixNano>-<session>`。
pub(crate) fn announce_name(session: &str, unix_nanos: i64) -> String {
    format!("{SESSIONS_DIR}/{unix_nanos}-{session}")
}

/// announce 条目 → (会话, 时间戳)（Go `parseAnnounce`）。
#[must_use]
pub(crate) fn parse_announce(entry: &str) -> Option<(String, i64)> {
    let dash = entry.find('-')?;
    if dash == 0 || dash == entry.len() - 1 {
        return None;
    }
    let nanos = entry[..dash].parse::<i64>().ok()?;
    Some((entry[dash + 1..].to_string(), nanos))
}

pub(crate) fn session_prefix(session: &str) -> String {
    format!("{STREAMS_DIR}/{session}")
}

pub(crate) fn uplink_prefix(session: &str) -> String {
    format!("{}/{}", session_prefix(session), UPLINK_DIR)
}

pub(crate) fn downlink_prefix(session: &str) -> String {
    format!("{}/{}", session_prefix(session), DOWNLINK_DIR)
}

fn unix_nanos_now(clock: &std::sync::Arc<dyn skeleton::clock::Clock>) -> i64 {
    // Go UnixNano 无失败面；早于 epoch（仅 MockClock 误配置可达）钳到 0。
    clock
        .now_system()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

// ── 预热点池（Go spareBox）───────────────────────────────────────────────────

/// 预热环：一只已建好槽位的会话（Go `spareRing`）。
struct SpareRing {
    storage: Arc<dyn Storage>,
    session: String,
    ring: Ring,
    at: Instant,
}

/// 每配置一只预热箱（Go `spareBox`）。Go 的 `stop` 标志生产恒 false（无置位点）
/// ——不移植死参数。
struct SpareBox {
    rings: parking_lot::Mutex<VecDeque<SpareRing>>,
    busy: AtomicBool,
    last: AtomicI64,
}

/// 每箱容量（Go `spareCount`）。
const SPARE_COUNT: usize = 2;
/// 最近拨号窗（Go `spareIdleStop`）：窗内才续填。
const SPARE_IDLE_STOP: Duration = Duration::from_secs(600);

static SPARE_BOXES: std::sync::LazyLock<parking_lot::Mutex<HashMap<String, Arc<SpareBox>>>> =
    std::sync::LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

fn spare_box_for(config: &Config) -> Arc<SpareBox> {
    let key = share_key(None, config);
    let mut boxes = SPARE_BOXES.lock();
    boxes
        .entry(key)
        .or_insert_with(|| {
            Arc::new(SpareBox {
                rings: parking_lot::Mutex::new(VecDeque::new()),
                busy: AtomicBool::new(false),
                last: AtomicI64::new(0),
            })
        })
        .clone()
}

/// 泄放一只预热环（Go `dropSpare`）：删会话前缀对象 + 关连接面。
async fn drop_spare_of(storage: Arc<dyn Storage>, session: String) {
    let _ = storage.delete(&session_prefix(&session)).await;
    let _ = storage.close().await;
}

/// 后台投递（Go `go fn()`）：有 reactor 走托管 spawn；无 reactor（同步调用方/
/// 纯结构测试）就地跑完。
///
/// `compat::spawn` 落到 `FxScope::spawn_tracked` 的 `JoinSet::spawn`——无
/// reactor 时**非返回 Err 而是 panic**（"must be called from the context of a
/// Tokio 1.x runtime"）。凭空派任务是实现层选择，不是调用方契约，故无 runtime
/// 的调用方必须能安全走完：`Drop` 走的是取消兜底（见 `conn::Drop`）。
fn spawn_bg(label: &str, fut: impl Future<Output = ()> + Send + 'static) {
    if tokio::runtime::Handle::try_current().is_ok() {
        if let Err(e) = xray_frame::compat::spawn(fut) {
            LOG.warn(format!("xdrive: failed to spawn {label}: {e}"));
        }
        return;
    }
    // shortcut: 无 reactor 时自建单线程 runtime 阻塞跑完（生产调用方全在 async
    // 面上，只有同步调用方/纯结构测试走到这里）。出现同步调用方且后端是网络件
    // ⇒ 这里会阻塞该线程，届时改成显式要求 runtime 并 fail-visible。
    match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt.block_on(fut),
        Err(e) => LOG.warn(format!("xdrive: {label} needs a tokio runtime: {e}")),
    }
}

/// 后台泄放（Go `go dropSpare(...)`；进程级清理任务，经 [`spawn_bg`] 投递）。
fn spawn_drop_spare(storage: Arc<dyn Storage>, session: String) {
    spawn_bg("the spare drop task", drop_spare_of(storage, session));
}

/// 取预热环（Go `takeSpare`）：过期件后台泄放，只交新鲜件（< 2/3 TTL）。
fn take_spare(config: &Config, p: &Params) -> Option<SpareRing> {
    let box_ = spare_box_for(config);
    let clock = xray_frame::compat::clock();
    loop {
        let spare = box_.rings.lock().pop_front()?;
        if clock.now_instant().duration_since(spare.at) < p.session_ttl * 2 / 3 {
            return Some(spare);
        }
        spawn_drop_spare(spare.storage, spare.session);
    }
}

/// 记最近拨号时刻并续填（Go `warmSpares`）。
fn warm_spares(settings: &StreamSettings, config: &Config, p: &Params) {
    let box_ = spare_box_for(config);
    let clock = xray_frame::compat::clock();
    box_.last.store(
        clock
            .now_system()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
            .unwrap_or(0),
        Ordering::SeqCst,
    );
    fill_spares(settings, config, p);
}

/// 续填预热箱（Go `fillSpares`）：busy 单飞；清过期、填缺口、按 TTL/4 续武装。
fn fill_spares(settings: &StreamSettings, config: &Config, p: &Params) {
    let box_ = spare_box_for(config);
    if box_.busy.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return;
    }
    let task = fill_spares_task(settings.clone(), config.clone(), *p, Arc::clone(&box_));
    if let Err(e) = xray_frame::compat::spawn(task) {
        box_.busy.store(false, Ordering::SeqCst);
        LOG.warn(format!("xdrive: failed to spawn the spare fill task: {e}"));
    }
}

async fn fill_spares_task(
    settings: StreamSettings,
    config: Config,
    p: Params,
    box_: Arc<SpareBox>,
) {
    let clock = xray_frame::compat::clock();
    // 清过期件、新鲜件塞回（Go：把 ch 里过期的 drop）。
    {
        let mut rings = box_.rings.lock();
        for _ in 0..rings.len() {
            let Some(spare) = rings.pop_front() else { break };
            if clock.now_instant().duration_since(spare.at) < p.session_ttl / 3 {
                rings.push_back(spare);
            } else {
                spawn_drop_spare(spare.storage, spare.session);
            }
        }
    }
    while box_.rings.lock().len() < SPARE_COUNT {
        // Go：2s 放缓（40×50ms）再填，给 Dial 留消费窗口。
        tokio::time::sleep(Duration::from_secs(2)).await;
        let Ok(storage) = new_storage(&settings) else {
            box_.busy.store(false, Ordering::SeqCst);
            return;
        };
        let storage = session_storage(storage);
        let Some(store) = Arc::clone(&storage).slot_store() else {
            let _ = storage.close().await;
            box_.busy.store(false, Ordering::SeqCst);
            return;
        };
        let Ok(session) = new_session_id() else {
            let _ = storage.close().await;
            box_.busy.store(false, Ordering::SeqCst);
            return;
        };
        let Ok(ring) = make_ring(store, &session, &p).await else {
            spawn_drop_spare(Arc::clone(&storage), session);
            box_.busy.store(false, Ordering::SeqCst);
            return;
        };
        // 满箱判据先出锁再 await（guard 恒不跨 await；Go defer busy.Store 同序）。
        let full = {
            let mut rings = box_.rings.lock();
            if rings.len() < SPARE_COUNT {
                rings.push_back(SpareRing {
                    storage: Arc::clone(&storage),
                    session,
                    ring,
                    at: clock.now_instant(),
                });
                false
            } else {
                true
            }
        };
        if full {
            let _ = storage.close().await;
            box_.busy.store(false, Ordering::SeqCst);
            return;
        }
    }
    // 续武装（Go time.AfterFunc(sessionTTL/4)）：近窗内有拨号才续。
    let rearm_box = Arc::clone(&box_);
    let rearm = async move {
        tokio::time::sleep(p.session_ttl / 4).await;
        let last_nanos = rearm_box.last.load(Ordering::SeqCst);
        let now_nanos = xray_frame::compat::clock()
            .now_system()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
            .unwrap_or(0);
        let recent = now_nanos
            .checked_sub(last_nanos)
            .and_then(|d| u64::try_from(d).ok())
            .map(|nanos| Duration::from_nanos(nanos) < SPARE_IDLE_STOP)
            .unwrap_or(false);
        if recent {
            fill_spares(&settings, &config, &p);
        }
    };
    let _ = xray_frame::compat::spawn(rearm);
    box_.busy.store(false, Ordering::SeqCst);
}

/// announce 任务（Go Dial 的后台 goroutine）：等首段 ≤25ms，`first` 可内嵌则
/// 换带 first 的环；投递失败把连接写读两侧都判死（下次 Write/Read 浮出）。
async fn announce_slot_session(
    storage: Arc<dyn Storage>,
    writer: Arc<SlotWriter>,
    reader: std::sync::Arc<crate::slots::ReaderShared>,
    session: String,
    ring: Ring,
    mut first_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) {
    let first =
        tokio::time::timeout(Duration::from_millis(25), first_rx.recv()).await.ok().flatten();
    let mut announce = encode_ring(&ring);
    if let Some(first) = first.filter(|f| !f.is_empty() && f.len() <= SLOT_INLINE_LIMIT) {
        let mut with_first = ring;
        with_first.first = first;
        let encoded = encode_ring(&with_first);
        if encoded.len() <= DRIVE_INLINE_LIMIT {
            announce = encoded;
        }
    }
    let clock = xray_frame::compat::clock();
    let name = announce_name(&session, unix_nanos_now(&clock));
    if let Err(e) = storage.put(&name, &announce).await {
        let err = io::Error::other(format!("failed to announce session {session}: {e}"));
        writer.fail(err.to_string());
        reader.set_err(err.to_string());
    }
}

/// 出站拨号（Go `Dial`）：槽位后端走环形槽位 announce 路（带预热取件），其余
/// 走 WAL 分段路。`dest`/`sockopt` 对 xdrive 无效（介质是对象存储），保留形参
/// 以满足注册签名。
///
/// # Errors
/// 配置缺失、后端不可用、announce 落盘失败。
pub async fn dial(
    dest: &Destination,
    sockopt: &SocketOptions,
    settings: &StreamSettings,
) -> io::Result<Box<dyn Connection>> {
    let _ = (dest, sockopt);
    let config = Config::from_settings(settings)?;
    let warm_probe = Params::from_config(&config);

    // 预热取件（Go takeSpare，用 config 级 params 判鲜）；未命中走冷路径。
    let (storage, session, warm_ring) = match take_spare(&config, &warm_probe) {
        Some(spare) => (spare.storage, spare.session, Some(spare.ring)),
        None => {
            let storage = session_storage(new_storage(settings)?);
            let session = new_session_id()?;
            (storage, session, None)
        },
    };
    let params = Params::for_storage(&config, storage.as_ref());

    let slots = Arc::clone(&storage).slot_store();
    let mut ring = warm_ring;
    if ring.is_none() {
        // `as_ref` + clone：槽位存储建环后**后面还要用**（写/读两侧都要），
        // 取走即让 `(Some(store), Some(ring))` 恒不成立 → 环白建、静默退回 WAL。
        if let Some(store) = slots.as_ref() {
            match make_ring(Arc::clone(store), &session, &params).await {
                Ok(r) => ring = Some(r),
                Err(e) => {
                    LOG.warn(format!(
                        "failed to make the slots of session {session}, it goes in segments: {e}"
                    ));
                },
            }
        }
    }

    if let (Some(store), Some(ring)) = (slots, ring) {
        warm_spares(settings, &config, &params);
        LOG.info(format!("opened session {session} in {} slots", ring.up.slots.len()));
        let (first_tx, first_rx) = tokio::sync::mpsc::channel(1);
        let tasks = SessionTasks::new(&format!("{PROTOCOL_NAME}-dialer:{session}"));
        let writer = new_slot_writer(
            Arc::clone(&store),
            ring.up.clone(),
            &params,
            DEFAULT_TUNING,
            tasks.clone(),
            Some(first_tx),
        );
        let reader = new_slot_reader(
            Arc::clone(&store),
            ring.down.clone(),
            &params,
            DEFAULT_TUNING,
            tasks.clone(),
            None,
        );
        let announce = announce_slot_session(
            Arc::clone(&storage),
            Arc::clone(&writer),
            reader.shared_handle(),
            session.clone(),
            ring,
            first_rx,
        );
        if let Err(e) = tasks.spawn(announce) {
            LOG.warn(format!("xdrive: announce task spawn rejected: {e}"));
        }
        return Ok(Box::new(Conn::new_slot_parts(writer, reader, storage, tasks, None)));
    }

    let clock = xray_frame::compat::clock();
    storage
        .put(&announce_name(&session, unix_nanos_now(&clock)), &[])
        .await
        .map_err(|e| io::Error::other(format!("failed to announce session {session}: {e}")))?;
    LOG.info(format!("opened session {session}"));

    Ok(Box::new(Conn::new_wal(
        storage,
        &uplink_prefix(&session),
        &downlink_prefix(&session),
        &params,
        &format!("{PROTOCOL_NAME}-dialer:{session}"),
        None,
    )))
}

/// xdrive 监听器（Go `Listener`）：轮询 claim announce、按会话建 Conn、
/// TTL 回收废弃会话。不 bind 任何 socket（Go 同款；`local_addr` 返回配置的
/// 监听地址以满足 trait）。
pub struct Listener {
    storage: Arc<dyn Storage>,
    params: Params,
    handler: ConnHandler,
    tasks: SessionTasks,
    state: parking_lot::Mutex<ListenerState>,
}

#[derive(Default)]
struct ListenerState {
    /// 已 claim 且连接未关（Go `active`；Conn 的 on_close 回调摘除）。
    active: HashSet<String>,
    /// 已处理过（防重复 accept；Go `handled`）。
    handled: HashMap<String, std::time::Instant>,
    /// 非 active 会话的空闲起点（collector 判据；Go `idleSince`）。
    idle_since: HashMap<String, std::time::Instant>,
    /// announce 首见时刻（staleness 判定；Go `firstSeen`）。
    first_seen: HashMap<String, std::time::Instant>,
    /// announce 读回失败告警去过重（Go `announceWarned`；随 handled 收敛）。
    announce_warned: HashSet<String>,
}

/// 入站监听（Go `Serve`）。忽略 bind 地址（xdrive 介质是对象存储）。
///
/// # Errors
/// 配置缺失、后端不可用、accept/collect 循环 spawn 被拒。
pub async fn serve(
    addr: SocketAddr,
    settings: StreamSettings,
    sockopt: SocketOptions,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    let _ = sockopt;
    let config = Config::from_settings(&settings)?;
    let storage = new_storage(&settings)?;
    let params = Params::for_storage(&config, storage.as_ref());

    let tasks = SessionTasks::new(&format!("{PROTOCOL_NAME}-listener:{addr}"));
    let listener = Arc::new(Listener {
        storage: Arc::clone(&storage),
        params,
        handler,
        tasks: tasks.clone(),
        state: parking_lot::Mutex::new(ListenerState::default()),
    });

    // Go：go acceptLoop / go collectLoop（§3.5.6 ①类：组件任务挂托管口）。
    tasks
        .spawn(accept_loop(Arc::clone(&listener)))
        .map_err(|e| io::Error::other(format!("xdrive accept loop spawn rejected: {e}")))?;
    tasks
        .spawn(collect_loop(Arc::clone(&listener)))
        .map_err(|e| io::Error::other(format!("xdrive collect loop spawn rejected: {e}")))?;

    Ok(Box::new(ListenerHandle { addr, storage, tasks }))
}

/// 轮询 accept 循环（Go `acceptLoop`）：活跃窗内满频，空闲期指数退避。
async fn accept_loop(listener: Arc<Listener>) {
    let clock = xray_frame::compat::clock();
    let mut delay = listener.params.min_poll_interval;
    let mut active = clock.now_instant();
    loop {
        let accepted = match listener.accept_pending().await {
            Ok(accepted) => accepted,
            Err(e) => {
                // List 失败告警继续（存储暂不可达不终止监听，Go 同款）。
                LOG.warn(format!("xdrive: failed to list sessions: {e}"));
                false
            },
        };
        let now = clock.now_instant();
        if accepted {
            active = now;
            delay = listener.params.min_poll_interval;
        } else if now - active < listener.params.eager_window {
            delay = listener.params.min_poll_interval;
        } else {
            delay = (delay * 2).min(listener.params.max_poll_interval);
        }
        if listener.tasks.token.run_until_cancelled(tokio::time::sleep(delay)).await.is_none() {
            return;
        }
    }
}

impl Listener {
    /// 一轮 accept（Go `acceptPending`）：列表 → 首见簿记 → 过期丢 announce →
    /// claim → 丢 announce → 交付连接。B1 announce 载荷恒空（无槽位后端）。
    async fn accept_pending(self: &Arc<Self>) -> io::Result<bool> {
        let sessions = self.storage.list(SESSIONS_DIR).await?;
        let clock = xray_frame::compat::clock();
        let now = clock.now_instant();

        // 首见簿记：新条目录入、已消失条目剔除（Go firstSeen 维护段）。
        {
            let mut state = self.state.lock();
            let listed: HashSet<&str> = sessions.iter().map(|e| e.name.as_str()).collect();
            for entry in &sessions {
                state.first_seen.entry(entry.name.clone()).or_insert(now);
            }
            state.first_seen.retain(|entry, _| listed.contains(entry.as_str()));
        }

        let mut accepted = false;
        for listed in &sessions {
            let entry = listed.name.as_str();
            let Some((session, _)) = parse_announce(entry) else {
                self.drop_object(&format!("{SESSIONS_DIR}/{entry}")).await;
                continue;
            };
            // 超过 TTL 的陈旧 announce：丢弃；无活连接且从未处理过的流也一并清。
            let age = {
                let state = self.state.lock();
                now.duration_since(*state.first_seen.get(entry).unwrap_or(&now))
            };
            if age > self.params.session_ttl {
                LOG.info(format!("dropping the stale announcement of session {session}"));
                self.drop_object(&format!("{SESSIONS_DIR}/{entry}")).await;
                let protected = {
                    let state = self.state.lock();
                    state.active.contains(&session) || state.handled.contains_key(&session)
                };
                if !protected {
                    self.drop_object(&session_prefix(&session)).await;
                }
                continue;
            }
            if !self.claim(&session, now) {
                continue;
            }
            // announce 载荷（Go `newSessionConn`）：Inline 直取；槽位后端补一次
            // Get 回读（1MiB cap 面 B4 偏差③已声明：Rust 恒 32MiB 兜底）。
            let mut announce = listed.inline.clone().unwrap_or_default();
            if announce.is_empty()
                && session_storage(Arc::clone(&self.storage)).slot_store().is_some()
            {
                let full = format!("{SESSIONS_DIR}/{entry}");
                match self.storage.get(&full).await {
                    Ok(data) => announce = data,
                    Err(e) => {
                        // 撤 claim（下轮可重试）；每会话只告警一次（Go 同款）。
                        {
                            let mut state = self.state.lock();
                            state.active.remove(&session);
                            state.handled.remove(&session);
                        }
                        let warn = {
                            let mut state = self.state.lock();
                            state.announce_warned.insert(session.clone())
                        };
                        if warn {
                            LOG.warn(format!(
                                "failed to read the announcement of session {session}: {e}"
                            ));
                        }
                        continue;
                    },
                }
            }
            self.drop_object(&format!("{SESSIONS_DIR}/{entry}")).await;
            accepted = true;
            // 环槽优先（Go `newSessionConn`）：解码成功即槽位会话，否则回退 WAL。
            let session_view = session_storage(Arc::clone(&self.storage));
            let slot_view = Arc::clone(&session_view).slot_store();
            let label = format!("{PROTOCOL_NAME}-acceptor:{}", &session[..session.len().min(8)]);
            let on_close = self.on_conn_close(Arc::clone(self), session.clone());
            let conn = match slot_view.filter(|_| !announce.is_empty()) {
                Some(store) => match decode_ring(&announce) {
                    Some(r) => {
                        LOG.info(format!(
                            "accepted session {session} in {} slots",
                            r.down.slots.len()
                        ));
                        let first = (!r.first.is_empty()).then_some(r.first);
                        Conn::new_slots(
                            store,
                            session_view,
                            r.down,
                            r.up,
                            &self.params,
                            DEFAULT_TUNING,
                            first,
                            &label,
                            Some(on_close),
                        )
                    },
                    None => Conn::new_wal(
                        session_view,
                        &downlink_prefix(&session),
                        &uplink_prefix(&session),
                        &self.params,
                        &label,
                        Some(on_close),
                    ),
                },
                None => Conn::new_wal(
                    session_view,
                    &downlink_prefix(&session),
                    &uplink_prefix(&session),
                    &self.params,
                    &label,
                    Some(on_close),
                ),
            };
            (self.handler)(Box::new(conn));
        }
        Ok(accepted)
    }

    /// 连接关闭回调（Go `onClose` 摘 active 的 Rust 对应）。
    fn on_conn_close(
        &self,
        listener: Arc<Listener>,
        session: String,
    ) -> Arc<dyn Fn() + Send + Sync> {
        Arc::new(move || {
            listener.state.lock().active.remove(&session);
        })
    }

    /// claim（Go `claim`）：active/handled 已见即拒；否则登记双表。
    fn claim(&self, session: &str, now: std::time::Instant) -> bool {
        let mut state = self.state.lock();
        if state.active.contains(session) || state.handled.contains_key(session) {
            return false;
        }
        state.active.insert(session.to_string());
        state.handled.insert(session.to_string(), now);
        true
    }

    /// 删除对象（Go `drop`；失败告警不中断——残留由 collector 兜底）。
    async fn drop_object(&self, name: &str) {
        if let Err(e) = self.storage.delete(name).await {
            LOG.warn(format!("xdrive: failed to drop {name}: {e}"));
        }
    }

    /// 回收废弃会话（Go `collect`）：streams 下非 active 且空闲 ≥ TTL 的会话
    /// 整前缀删除；handled/idle_since 簿记同步收敛。
    async fn collect(&self) -> io::Result<()> {
        let sessions = self.storage.list(STREAMS_DIR).await?;
        let clock = xray_frame::compat::clock();
        let now = clock.now_instant();

        let mut expired = Vec::new();
        {
            let mut state = self.state.lock();
            let present: HashSet<&str> = sessions.iter().map(|e| e.name.as_str()).collect();
            for listed in &sessions {
                let session = listed.name.as_str();
                if state.active.contains(session) {
                    state.idle_since.remove(session);
                    continue;
                }
                match state.idle_since.get(session) {
                    None => {
                        state.idle_since.insert(session.to_string(), now);
                    },
                    Some(since) => {
                        if now - *since >= self.params.session_ttl {
                            expired.push(session.to_string());
                            state.idle_since.remove(session);
                        }
                    },
                }
            }
            state.idle_since.retain(|session, _| present.contains(session.as_str()));
            let stale: Vec<String> = state
                .handled
                .iter()
                .filter(|(session, at)| {
                    !state.active.contains(*session)
                        && now.saturating_duration_since(**at) >= self.params.session_ttl
                })
                .map(|(session, _)| session.clone())
                .collect();
            for session in stale {
                state.handled.remove(&session);
                state.announce_warned.remove(&session);
            }
        }

        let mut first_err = None;
        for session in expired {
            if let Err(e) = self.storage.delete(&session_prefix(&session)).await {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

/// collector 循环（Go `collectLoop`）：每 sessionTTL/2 一轮。
async fn collect_loop(listener: Arc<Listener>) {
    let interval = listener.params.session_ttl / 2;
    loop {
        if listener.tasks.token.run_until_cancelled(tokio::time::sleep(interval)).await.is_none() {
            return;
        }
        if let Err(e) = listener.collect().await {
            LOG.warn(format!("xdrive: failed to collect abandoned sessions: {e}"));
        }
    }
}

/// `TransportListener` 句柄：close 通知 + 配置地址（xdrive 无真实 bind）。
struct ListenerHandle {
    addr: SocketAddr,
    storage: Arc<dyn Storage>,
    tasks: SessionTasks,
}

impl TransportListener for ListenerHandle {
    fn close(&self) -> io::Result<()> {
        self.tasks.close();
        // storage 收尾异步化（云后端 B2+ 有连接池泄放；local 是 no-op）。
        let storage = Arc::clone(&self.storage);
        if let Err(e) = xray_frame::compat::spawn(async move {
            if let Err(e) = storage.close().await {
                LOG.warn(format!("xdrive: listener storage close failed: {e}"));
            }
        }) {
            LOG.warn(format!("xdrive: listener close spawn rejected: {e}"));
        }
        Ok(())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_is_32_hex_chars_and_unique() {
        let a = new_session_id().unwrap();
        let b = new_session_id().unwrap();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn announce_roundtrip_matches_go() {
        // announce_name 仅用于 Put 的对象名；parse_announce 消费的是 sessions/
        // 目录下的裸条目名（Go acceptPending 的 listed.Name），不含目录前缀。
        assert_eq!(
            announce_name("cafe1234", 1_700_000_000_123_456_789),
            "sessions/1700000000123456789-cafe1234"
        );
        let (session, nanos) = parse_announce("1700000000123456789-cafe1234").unwrap();
        assert_eq!(session, "cafe1234");
        assert_eq!(nanos, 1_700_000_000_123_456_789);

        // 非法形态：无连字符 / 连字符在头尾 / 纳秒非数字
        assert!(parse_announce("nodash").is_none());
        assert!(parse_announce("-lead").is_none());
        assert!(parse_announce("trail-").is_none());
        assert!(parse_announce("notanum-cafe").is_none());
    }

    #[test]
    fn prefixes_match_go_layout() {
        assert_eq!(session_prefix("s1"), "streams/s1");
        assert_eq!(uplink_prefix("s1"), "streams/s1/c2s");
        assert_eq!(downlink_prefix("s1"), "streams/s1/s2c");
    }

    /// 旧预热件泄放、只交新鲜件（Go TestTakeSpareSkipsStale）。
    #[test]
    fn take_spare_skips_stale() {
        let dir1 = std::env::temp_dir().join(format!("xdrive-spare1-{}", std::process::id()));
        let dir2 = std::env::temp_dir().join(format!("xdrive-spare2-{}", std::process::id()));
        let st1: Arc<dyn Storage> =
            Arc::new(crate::local::LocalStorage::new(&dir1.to_string_lossy()).unwrap());
        let st2: Arc<dyn Storage> =
            Arc::new(crate::local::LocalStorage::new(&dir2.to_string_lossy()).unwrap());
        let config = Config {
            service: "local".to_string(),
            remote_folder: format!("/tmp/xdrive-spare-{}", std::process::id()),
            ..Config::default()
        };
        let mut p = Params::from_config(&config);
        p.session_ttl = Duration::from_secs(300);
        let box_ = spare_box_for(&config);
        let clock = xray_frame::compat::clock();
        box_.rings.lock().push_back(SpareRing {
            storage: st1,
            session: "old".to_string(),
            ring: Ring::default(),
            at: clock.now_instant() - Duration::from_secs(3600),
        });
        box_.rings.lock().push_back(SpareRing {
            storage: st2,
            session: "new".to_string(),
            ring: Ring::default(),
            at: clock.now_instant(),
        });
        let got = take_spare(&config, &p).expect("takeSpare gave nothing");
        assert_eq!(got.session, "new");
        assert!(take_spare(&config, &p).is_none(), "takeSpare returned a second spare");
        let _ = std::fs::remove_dir_all(dir1);
        let _ = std::fs::remove_dir_all(dir2);
    }

    /// 泄放预热件删净会话前缀对象（Go TestDropSpareDeletesSession）。
    #[tokio::test]
    async fn drop_spare_deletes_session() {
        let dir = std::env::temp_dir().join(format!("xdrive-spare-drop-{}", std::process::id()));
        let storage = Arc::new(crate::local::LocalStorage::new(&dir.to_string_lossy()).unwrap())
            as Arc<dyn Storage>;
        let name = format!("{}/s0", uplink_prefix("gone"));
        storage.put(&name, b"x").await.unwrap();
        drop_spare_of(Arc::clone(&storage), "gone".to_string()).await;
        let left = storage.list(&session_prefix("gone")).await.unwrap();
        assert!(left.is_empty(), "{} entries left of a dropped spare", left.len());
        let _ = std::fs::remove_dir_all(dir);
    }
}

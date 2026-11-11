//! Dial/Serve/Listener。对应 Go `xdrive.go`（B1：WAL 分段路径；`spareBox`
//! 预热点池与环形槽位属 B5，`takeSpare` 恒未命中、announce 载荷恒空）。

use std::{
    collections::{HashMap, HashSet},
    io,
    net::SocketAddr,
    sync::Arc,
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
    params::Params,
    storage::{Storage, new_storage, session_storage},
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

/// 出站拨号（Go `Dial` 的 WAL 路径）：announce 空载荷投递后返回 WAL Conn。
/// `dest`/`sockopt` 对 xdrive 无效（介质是对象存储；fronting 语义属 B2 的
/// HTTP 客户端栈），保留形参以满足注册签名。
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
    let storage = session_storage(new_storage(settings)?);
    let params = Params::for_storage(&config, storage.as_ref());

    let session = new_session_id()?;
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
            // B1：announce Inline 恒空、无 slotStore——不读载荷，直接 WAL Conn。
            // 存储取会话视图（Go `newSessionConn` 的 sessionStorage：XMUX 连接池
            // 会话面，close 归还池记账）。
            self.drop_object(&format!("{SESSIONS_DIR}/{entry}")).await;
            accepted = true;
            let conn = Conn::new_wal(
                session_storage(Arc::clone(&self.storage)),
                &downlink_prefix(&session),
                &uplink_prefix(&session),
                &self.params,
                &format!("{PROTOCOL_NAME}-acceptor:{}", &session[..session.len().min(8)]),
                Some(self.on_conn_close(Arc::clone(self), session)),
            );
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
}

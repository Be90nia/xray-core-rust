//! 分段 WAL：writer（缓冲/切段/并发上传）+ reader（轮询/取段/丢弃）。
//! 对应 Go `wal.go`。
//!
//! 对象布局：`{prefix}/{seq:09}.seg`（数据段）、`.end`（正常结尾）、`.err`
//! （对端存储失败标记）。reader 按 seq 连续取段，水位线 = 本地 seq。
//!
//! Go→Rust 对应：goroutine/ctx → `SessionTasks`（`ComponentScope` 托管 +
//! `CancelToken` 取消，§3.5.6 ①类）；`chan` → `tokio::sync`（mpsc/Notify/watch）。

use std::{
    collections::HashMap,
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use parking_lot::Mutex;
use skeleton_infra::fx::CancelToken;

use crate::{
    LOG,
    params::Params,
    storage::{Entry, Storage, is_not_found},
};

/// 写缓冲切段前的合并 tick 数上限（Go `maxCoalescedTicks`）。
const MAX_COALESCED_TICKS: u32 = 8;

pub(crate) const SEG_SUFFIX: &str = ".seg";
pub(crate) const END_SUFFIX: &str = ".end";
pub(crate) const ERR_SUFFIX: &str = ".err";

/// 段对象名（Go `objectName`）：`{prefix}/{seq:09}{suffix}`。
#[must_use]
pub fn object_name(prefix: &str, seq: i64, suffix: &str) -> String {
    format!("{prefix}/{seq:09}{suffix}")
}

/// 条目名 → 段序号（Go `parseEntry`）：后缀必须是 seg/end/err，序号非负整数。
#[must_use]
pub fn parse_entry(name: &str) -> Option<i64> {
    let dot = name.rfind('.')?;
    let suffix = &name[dot..];
    if suffix != SEG_SUFFIX && suffix != END_SUFFIX && suffix != ERR_SUFFIX {
        return None;
    }
    name[..dot].parse::<i64>().ok().filter(|seq| *seq >= 0)
}

// ── WalWriter ────────────────────────────────────────────────────────────────

#[derive(Default)]
struct WriterState {
    buf: Vec<u8>,
    seq: i64,
    last_size: usize,
    held: u32,
    closed: bool,
    /// 首个失败原因（io::Error 不可克隆，存消息重建）。
    err: Option<String>,
}

/// writer 的跨任务共享核：上传任务/flush 循环与句柄共用同一 Arc。
struct WalWriterShared {
    storage: Arc<dyn Storage>,
    prefix: String,
    sem: Arc<tokio::sync::Semaphore>,
    tasks: crate::conn::SessionTasks,
    state: Mutex<WriterState>,
    /// 已交由上传任务、尚未落定的段数（Go `wg`）；`watch` 是 await 侧唤醒源。
    inflight: Arc<(AtomicUsize, tokio::sync::watch::Sender<usize>)>,
}

impl WalWriterShared {
    fn finish_upload(&self) {
        let remaining = self.inflight.0.fetch_sub(1, Ordering::SeqCst) - 1;
        // `send_replace` 而非 `send`：无订阅者时 tokio `send` 回 Err 且不落值
        // （关闭序订阅之前全程无订阅者），计数停在初值 0 → 提前落 `.end` 丢段。
        self.inflight.1.send_replace(remaining);
    }
}

/// 分段 WAL 写侧（Go `walWriter`）：缓冲、按段切分、并发上传、定时 flush、
/// 关闭时冲净 + 落 `.end`。
pub struct WalWriter {
    shared: Arc<WalWriterShared>,
    segment_bytes: usize,
    flush_interval: Duration,
}

impl WalWriter {
    /// 构造并启动 flush 循环（Go `newWALWriter` + `go w.flushLoop()`）。
    pub(crate) fn new(
        storage: Arc<dyn Storage>,
        prefix: &str,
        params: &Params,
        tasks: crate::conn::SessionTasks,
    ) -> Arc<Self> {
        let shared = Arc::new(WalWriterShared {
            storage,
            prefix: prefix.to_string(),
            sem: Arc::new(tokio::sync::Semaphore::new(params.concurrency)),
            tasks,
            state: Mutex::new(WriterState::default()),
            inflight: Arc::new((AtomicUsize::new(0), tokio::sync::watch::channel(0_usize).0)),
        });
        let writer = Arc::new(Self {
            shared: Arc::clone(&shared),
            segment_bytes: params.segment_bytes,
            flush_interval: params.flush_interval,
        });
        if let Err(e) = shared.tasks.spawn(wal_writer_flush_loop(Arc::clone(&writer))) {
            LOG.warn(format!("xdrive wal: writer flush loop spawn rejected: {e}"));
        }
        writer
    }

    /// 追加数据（Go `Write`）：满段即同步切段上传；错误在后续写上浮。
    ///
    /// # Errors
    /// 已有存储失败、或连接已关闭（Go `io.ErrClosedPipe`）。
    pub fn write(&self, data: &[u8]) -> io::Result<usize> {
        let mut state = self.shared.state.lock();
        if let Some(err) = &state.err {
            return Err(io::Error::other(err.clone()));
        }
        if state.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "io.ErrClosedPipe: wal writer closed",
            ));
        }
        state.buf.extend_from_slice(data);
        while state.buf.len() >= self.segment_bytes {
            self.flush_locked(&mut state)?;
        }
        Ok(data.len())
    }

    /// 冲净 + 等在飞上传收净 + 落 `.end`（Go `Close`）。幂等（二次关闭恒
    /// `Ok(())`）。
    ///
    /// # Errors
    /// 任一段上传失败、或 `.end` 落盘失败。
    pub async fn close(&self) -> io::Result<()> {
        {
            let mut state = self.shared.state.lock();
            if state.closed {
                return Ok(());
            }
            state.closed = true;
            while !state.buf.is_empty() && state.err.is_none() {
                self.flush_locked(&mut state)?;
            }
        }
        // 等在飞上传收净（Go wg.Wait；watch 变更唤醒，无轮询）。计数以原子为准。
        let mut inflight_rx = self.shared.inflight.1.subscribe();
        while self.shared.inflight.0.load(Ordering::SeqCst) > 0 {
            if inflight_rx.changed().await.is_err() {
                break; // 发送端已亡——防御性退出（本 writer 存活时不发生）
            }
        }
        {
            let state = self.shared.state.lock();
            if let Some(err) = &state.err {
                return Err(io::Error::other(err.clone()));
            }
        }
        let seq = self.shared.state.lock().seq;
        let name = object_name(&self.shared.prefix, seq, END_SUFFIX);
        self.shared.storage.put(&name, &[]).await
    }

    /// 切段交上传（调用方须已持 `state` 锁；Go `flushLocked`）。
    fn flush_locked(&self, state: &mut WriterState) -> io::Result<()> {
        if state.buf.is_empty() {
            return Ok(());
        }
        if let Some(err) = &state.err {
            return Err(io::Error::other(err.clone()));
        }
        let n = state.buf.len().min(self.segment_bytes);
        let chunk = state.buf[..n].to_vec();
        let seq = state.seq;
        state.seq += 1;
        state.buf.drain(..n);
        state.last_size = state.buf.len();
        state.held = 0;

        self.shared.inflight.0.fetch_add(1, Ordering::SeqCst);
        self.shared.inflight.1.send_replace(self.shared.inflight.0.load(Ordering::SeqCst));
        let upload = wal_writer_upload(Arc::clone(&self.shared), seq, chunk);
        if let Err(e) = self.shared.tasks.spawn(upload) {
            // 托管口拒绝（scope 已关）：连接已在拆除，段不会落盘——按存储失败记账。
            self.shared.finish_upload();
            if state.err.is_none() {
                state.err = Some(format!("failed to store segment: {e}"));
            }
        }
        Ok(())
    }

    /// 合并判定（Go `readyToFlush`）：有增长时最多 held 8 拍再切，防碎片段。
    fn ready_to_flush(&self, state: &mut WriterState) -> bool {
        let grew = state.buf.len() > state.last_size;
        state.last_size = state.buf.len();
        if grew && state.held < MAX_COALESCED_TICKS {
            state.held += 1;
            return false;
        }
        state.held = 0;
        true
    }
}

async fn wal_writer_flush_loop(writer: Arc<WalWriter>) {
    let mut ticker = tokio::time::interval(writer.flush_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // tokio 首拍即时——丢弃，对齐 Go NewTicker 首拍按周期
    loop {
        let Some(_tick) = writer.shared.tasks.token.run_until_cancelled(ticker.tick()).await else {
            return;
        };
        let done = {
            let mut state = writer.shared.state.lock();
            if !state.closed
                && state.err.is_none()
                && !state.buf.is_empty()
                && writer.ready_to_flush(&mut state)
            {
                if let Err(e) = writer.flush_locked(&mut state) {
                    // 失败即记账（此后条件短路不再进入，单条告警）。
                    LOG.warn(format!("xdrive wal: flush failed: {e}"));
                }
            }
            state.closed || state.err.is_some()
        };
        if done {
            return;
        }
    }
}

async fn wal_writer_upload(shared: Arc<WalWriterShared>, seq: i64, chunk: Vec<u8>) {
    let token = shared.tasks.token.clone();
    let sem = Arc::clone(&shared.sem);
    // 并发闸（Go sem chan）；取消即放弃本段（Go select ctx.Done）。
    let Some(permit) = token.run_until_cancelled(sem.acquire_owned()).await else {
        shared.finish_upload();
        return;
    };
    let name = object_name(&shared.prefix, seq, SEG_SUFFIX);
    if let Err(e) = shared.storage.put(&name, &chunk).await {
        {
            let mut state = shared.state.lock();
            if state.err.is_none() {
                state.err = Some(format!("failed to store segment: {e}"));
            }
        }
        // 失败标记让对端立刻判错而非等空洞超时（Go 同款；标记自身失败不可恢复）。
        let err_name = object_name(&shared.prefix, seq, ERR_SUFFIX);
        if let Err(e) = shared.storage.put(&err_name, &[]).await {
            LOG.warn(format!("xdrive wal: failed to store error marker {err_name}: {e}"));
        }
    }
    drop(permit);
    shared.finish_upload();
}

// ── WalReader ────────────────────────────────────────────────────────────────

/// 分段 WAL 读侧句柄（Go `walReader`）：轮询 `list` → 连续取段 → 推给消费者。
pub struct WalReader {
    receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
    err: Arc<Mutex<Option<String>>>,
    wake: Arc<tokio::sync::Notify>,
}

impl WalReader {
    /// 构造并启动 poll 循环 + discard 循环（Go `newWALReader` 的两个 goroutine）。
    pub(crate) fn new(
        storage: Arc<dyn Storage>,
        prefix: &str,
        params: &Params,
        tasks: crate::conn::SessionTasks,
    ) -> Self {
        let (tx, receiver) = tokio::sync::mpsc::channel(params.concurrency);
        let (discards_tx, discards_rx) =
            tokio::sync::mpsc::channel(params.concurrency.saturating_mul(4));
        let err = Arc::new(Mutex::new(None));
        let wake = Arc::new(tokio::sync::Notify::new());
        let runner = WalReaderRun {
            storage: Arc::clone(&storage),
            prefix: prefix.to_string(),
            concurrency: params.concurrency,
            min_poll_interval: params.min_poll_interval,
            max_poll_interval: params.max_poll_interval,
            eager_window: params.eager_window,
            hole_timeout: params.hole_timeout,
            token: tasks.token.clone(),
            tx,
            discards_tx,
            wake: Arc::clone(&wake),
            err: Arc::clone(&err),
        };
        if let Err(e) = tasks.spawn(wal_reader_run(runner)) {
            LOG.warn(format!("xdrive wal: reader poll loop spawn rejected: {e}"));
            *err.lock() = Some(format!("reader loop spawn rejected: {e}"));
        }
        let discard_runner = WalReaderDiscard { storage, discards_rx, token: tasks.token.clone() };
        if let Err(e) = tasks.spawn(wal_reader_discard_loop(discard_runner)) {
            LOG.warn(format!("xdrive wal: reader discard loop spawn rejected: {e}"));
        }
        Self { receiver, err, wake }
    }

    /// 取下一段（poll 原语，供 `Conn` 的 `AsyncRead` 集成）。
    pub(crate) fn poll_chunk(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Vec<u8>>> {
        self.receiver.poll_recv(cx)
    }

    /// 消费者侧错误快照（Go `Err()`：存储失败/空洞超时；EOF 不在此）。
    pub(crate) fn take_err(&self) -> Option<io::Error> {
        self.err.lock().take().map(io::Error::other)
    }

    /// 有进展信号（Go `Wake`；本地写后调用以提速轮询节拍外的自身复核）。
    pub(crate) fn wake(&self) {
        self.wake.notify_one();
    }
}

struct WalReaderRun {
    storage: Arc<dyn Storage>,
    prefix: String,
    concurrency: usize,
    min_poll_interval: Duration,
    max_poll_interval: Duration,
    eager_window: Duration,
    hole_timeout: Duration,
    token: CancelToken,
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    discards_tx: tokio::sync::mpsc::Sender<String>,
    wake: Arc<tokio::sync::Notify>,
    err: Arc<Mutex<Option<String>>>,
}

async fn wal_reader_run(runner: WalReaderRun) {
    let clock = xray_frame::compat::clock();
    let mut delay = runner.min_poll_interval;
    let mut active = clock.now_instant();
    let mut seq: i64 = 0;
    let mut hole_since: Option<std::time::Instant> = None;

    loop {
        let polled = clock.now_instant();
        let outcome = wal_reader_poll(&runner, &clock, &mut seq, &mut hole_since).await;
        match outcome {
            Err(msg) => {
                *runner.err.lock() = Some(msg);
                return;
            },
            Ok((_advanced, true)) => return, // EOF（对端 .end 或本侧取消）
            Ok((advanced, false)) => {
                let now = clock.now_instant();
                if advanced {
                    active = now;
                    delay = runner.min_poll_interval;
                } else if now - active < runner.eager_window {
                    delay = runner.min_poll_interval;
                } else {
                    delay = (delay * 2).min(runner.max_poll_interval);
                }
            },
        }

        // 等待：定时 / 唤醒 / 取消（Go timer + wake + ctx.Done）。
        let wait = async {
            tokio::select! {
                _ = tokio::time::sleep(delay) => false,
                _ = runner.wake.notified() => true,
            }
        };
        let Some(woke) = runner.token.run_until_cancelled(wait).await else {
            return;
        };
        if woke {
            let now = clock.now_instant();
            delay = runner.min_poll_interval;
            active = now;
            // 唤醒后仍尊重最小轮询间隔（Go rest 语义）。
            let rest = runner.min_poll_interval.saturating_sub(now - polled);
            if !rest.is_zero()
                && runner.token.run_until_cancelled(tokio::time::sleep(rest)).await.is_none()
            {
                return;
            }
        }
    }
}

/// 单轮轮询（Go `poll`）：列目录 → 连续批量取段 → 投递 → 丢弃已消费段。
/// 返回 `(本轮是否有进展, 是否结束)`。
async fn wal_reader_poll(
    runner: &WalReaderRun,
    clock: &std::sync::Arc<dyn skeleton::clock::Clock>,
    seq: &mut i64,
    hole_since: &mut Option<std::time::Instant>,
) -> Result<(bool, bool), String> {
    let listed = runner
        .storage
        .list(&runner.prefix)
        .await
        .map_err(|e| format!("failed to list {}: {e}", runner.prefix))?;
    if listed.is_empty() {
        return Ok((false, false));
    }

    let mut pending: HashMap<i64, Entry> = HashMap::with_capacity(listed.len());
    let mut ahead = false;
    for entry in listed {
        if let Some(entry_seq) = parse_entry(&entry.name) {
            if entry_seq > *seq {
                ahead = true;
            }
            pending.insert(entry_seq, entry);
        }
    }

    // 空洞：期望段缺席而后段已到——超时判对端丢段（Go holeTimeout）。
    if !pending.contains_key(seq) && ahead {
        match hole_since {
            None => *hole_since = Some(clock.now_instant()),
            Some(since) => {
                if clock.now_instant() - *since >= runner.hole_timeout {
                    return Err(format!(
                        "segment {seq} never arrived while later ones did, the peer lost it"
                    ));
                }
            },
        }
    } else {
        *hole_since = None;
    }

    let mut advanced = false;
    loop {
        // 对端存储失败标记：立刻判错（Go errSuffix 分支）。
        if let Some(entry) = pending.get(seq) {
            if entry.name.ends_with(ERR_SUFFIX) {
                let _ = runner.discards_tx.try_send(format!("{}/{}", runner.prefix, entry.name));
                return Err(format!("the peer could not store segment {seq}"));
            }
        }

        // 连续段批量（Go nextBatch）：≤ concurrency；期望位是 .end 即正常收尾。
        let mut batch: Vec<Entry> = Vec::new();
        let mut done = false;
        for i in 0..runner.concurrency {
            let expected = *seq + i64::try_from(i).unwrap_or(i64::MAX);
            let Some(entry) = pending.get(&expected) else {
                break;
            };
            if !entry.name.ends_with(SEG_SUFFIX) {
                if i == 0 && entry.name.ends_with(END_SUFFIX) {
                    let _ =
                        runner.discards_tx.try_send(format!("{}/{}", runner.prefix, entry.name));
                    done = true;
                }
                break;
            }
            batch.push(entry.clone());
        }
        if done {
            return Ok((advanced, true));
        }
        if batch.is_empty() {
            return Ok((advanced, false));
        }

        // 取段（Go fetch：inline 直用；缺失按「还没出现」回到轮询）。
        let mut chunks = Vec::with_capacity(batch.len());
        for entry in &batch {
            if let Some(inline) = &entry.inline {
                chunks.push(inline.clone());
                continue;
            }
            match runner.storage.get(&format!("{}/{}", runner.prefix, entry.name)).await {
                Ok(data) => chunks.push(data),
                Err(e) if is_not_found(&e) => return Ok((advanced, false)),
                Err(e) => return Err(format!("failed to fetch segment {}: {e}", entry.name)),
            }
        }

        for (i, chunk) in chunks.into_iter().enumerate() {
            let Some(send_result) = runner.token.run_until_cancelled(runner.tx.send(chunk)).await
            else {
                return Ok((advanced, true)); // 消费者取消
            };
            if send_result.is_err() {
                return Ok((advanced, true)); // 消费者已亡
            }
            *seq += 1;
            advanced = true;
            let _ = runner.discards_tx.try_send(format!("{}/{}", runner.prefix, batch[i].name));
        }
    }
}

struct WalReaderDiscard {
    storage: Arc<dyn Storage>,
    discards_rx: tokio::sync::mpsc::Receiver<String>,
    token: CancelToken,
}

async fn wal_reader_discard_loop(mut runner: WalReaderDiscard) {
    loop {
        // 通道闭（读循环退出）或取消 → 结束。删除尽力而为：残留由 listener
        // collector 按 TTL 回收（Go discardLoop 同口径，不重试）。
        let Some(Some(name)) = runner.token.run_until_cancelled(runner.discards_rx.recv()).await
        else {
            return;
        };
        if let Err(e) = runner.storage.delete(&name).await {
            LOG.warn(format!("xdrive wal: failed to discard {name}: {e}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_name_roundtrip_parse_entry() {
        assert_eq!(object_name("streams/s/c2s", 0, SEG_SUFFIX), "streams/s/c2s/000000000.seg");
        assert_eq!(object_name("sessions", 1_234_567_890, END_SUFFIX), "sessions/1234567890.end");

        assert_eq!(parse_entry("000000000.seg"), Some(0));
        assert_eq!(parse_entry("1234567890.end"), Some(1_234_567_890));
        assert_eq!(parse_entry("000000007.err"), Some(7));
        assert_eq!(parse_entry("000000008.seg"), Some(8));
        // 非法形态：无后缀 / 错后缀 / 负数 / 非数字 / 多点
        assert_eq!(parse_entry("000000008"), None);
        assert_eq!(parse_entry("000000008.txt"), None);
        assert_eq!(parse_entry("-1.seg"), None);
        assert_eq!(parse_entry("abc.seg"), None);
        assert_eq!(parse_entry("1.2.seg"), None);
        assert_eq!(parse_entry(""), None);
    }
}

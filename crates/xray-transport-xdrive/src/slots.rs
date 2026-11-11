//! 会话环形槽位：每方向一圈按 id 直读直写的对象，段 n 写入/读出槽 n % depth，
//! 无 list、无索引等待；读侧以水位线（watermark）记账已读进度，写侧仅在水位线
//! 表明上一圈内容已被取走后才复用槽位。对应 Go `slots.go` @ `676eaf66`。
//!
//! 语义锚（bd hjtlk B5）：环槽不是池——udf ObjectPool 的独占借还模型套环槽是
//! §3.5.4 假同构（B0 已举证），本文件按 Go slots.go 直译槽位状态机/轮转/回收。
//!
//! Go→Rust 对应：goroutine → `SessionTasks` 托管 spawn（§3.5.6 ①类）；reader
//! 专属的 runCtx 停机面 → 本地 `cancel_pair`（stop）；`chan` → mpsc/`Notify`/
//! `watch`；slotWriter 阻塞等 slot 的 token → `Semaphore` try-acquire + 写侧
//! waker（poll_write Pending 回压，读者落后即握住 Write）。
//!
//! 对 Go 的两处已声明偏差：① `drained` 的水位线读取不跨 await 持锁（Go ackMu
//! 串行化两次读取；TTL 100ms 下并发重复读一次，结局一致）；② 逐段 Debug 日志
//! 不落（goese to LOG.debug 面，本 crate 未接 Debug 通道）。

use std::{
    collections::HashMap,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use parking_lot::Mutex;
use skeleton_infra::fx::{CancelSource, CancelToken, cancel_pair};
use std_ext::encode::{Base64Alphabet, base64_decode, base64_encode};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch};

use crate::{
    LOG,
    conn::SessionTasks,
    drive::is_auth_error,
    params::Params,
    storage::{SlotStore, is_not_found},
    xdrive::{downlink_prefix, uplink_prefix},
};

/// 槽位描述魔数（Go `slotMagic`）。
const SLOT_MAGIC: &[u8; 8] = b"XDRVSL01";
/// 描述头长：魔数 8 + seq 8 + mode 1 + size 4 + crc 4（Go `slotHeaderLen`）。
const SLOT_HEADER_LEN: usize = 8 + 8 + 1 + 4 + 4;
/// 段内联上限：≤ 此值随 description 一请求送达，省一次 body 读（Go `slotInlineLimit`）。
pub(crate) const SLOT_INLINE_LIMIT: usize = 14 << 10;
/// 同尺寸连续段数达此值即倍增段大小，从内联上限涨到 segmentBytes（Go `inlineRampSegments`）。
const INLINE_RAMP_SEGMENTS: u32 = 8;

const SLOT_INLINE: u8 = 1;
const SLOT_MEDIA: u8 = 2;
const SLOT_END: u8 = 3;
const SLOT_ERR: u8 = 4;

/// 对端槽位/水位线 id 的长度上限（Go `maxSlotIDLen`）。
const MAX_SLOT_ID_LEN: usize = 128;
/// 环槽深度上限（Go `maxConcurrency`，params 已封顶；decodeRing 复核）。
const MAX_CONCURRENCY: usize = 256;
/// 合并 tick 上限（Go `maxCoalescedTicks`，与 wal 同值）。
const MAX_COALESCED_TICKS: u32 = 8;

/// 环槽节拍（Go 包级变量的快照形态；测试以字段覆盖替代 Go 的全局换置）。
#[derive(Debug, Clone, Copy)]
pub(crate) struct SlotTuning {
    /// 头段轮询下限（Go `slotHuntFloor`）。
    pub(crate) hunt_floor: Duration,
    /// 头段轮询上限（Go `slotHuntCeiling`）。
    pub(crate) hunt_ceiling: Duration,
    /// 尾随段首等下限（Go `slotTailMin`）。
    pub(crate) tail_min: Duration,
    /// 尾随段首等上限（Go `slotTailMax`）。
    pub(crate) tail_max: Duration,
    /// 头之外同时取的段数（Go `slotFetchAhead`）。
    pub(crate) fetch_ahead: i64,
    /// 预取窗口内即刻起跑的段数（Go `slotReadAhead`）。
    pub(crate) read_ahead: i64,
    /// 突发窗内预取段的重询周期（Go `slotReadAheadPoll`）。
    pub(crate) read_ahead_poll: Duration,
    /// 突发窗：段间空闲 ≤ 此值仍按突发节拍取段（Go `slotReadAheadBurst`）。
    pub(crate) read_ahead_burst: Duration,
    /// 水位线写重试起点（Go `slotAckRetry`）。
    pub(crate) ack_retry: Duration,
    /// 水位线缓存 TTL（Go `slotWatermarkTTL`）。
    pub(crate) watermark_ttl: Duration,
    /// 无进展判停（Go `slotStallTimeout`）。
    pub(crate) stall_timeout: Duration,
    /// 写侧关闭后的收尾宽限（Go `slotCloseGrace`）。
    pub(crate) close_grace: Duration,
    /// 槽位消失判停（Go `slotGoneTimeout`）。
    pub(crate) gone_timeout: Duration,
    /// body 读对冲延迟（Go `slotBodyHedge`）。
    pub(crate) body_hedge: Duration,
    /// 段间节奏下限（Go pace 的 300ms）。
    pub(crate) pace_floor: Duration,
    /// 段间节奏上限（Go pace 的 3s）。
    pub(crate) pace_ceiling: Duration,
    /// 在飞段上传上限（Go `slotWriteInflight`）。
    pub(crate) write_inflight: usize,
}

/// 生产缺省（Go 包级变量初值）。
pub(crate) const DEFAULT_TUNING: SlotTuning = SlotTuning {
    hunt_floor: Duration::from_millis(10),
    hunt_ceiling: Duration::from_millis(25),
    tail_min: Duration::from_millis(150),
    tail_max: Duration::from_millis(800),
    fetch_ahead: 12,
    read_ahead: 3,
    read_ahead_poll: Duration::from_millis(40),
    read_ahead_burst: Duration::from_millis(500),
    ack_retry: Duration::from_millis(30),
    watermark_ttl: Duration::from_millis(100),
    stall_timeout: Duration::from_secs(60),
    close_grace: Duration::from_secs(10),
    gone_timeout: Duration::from_secs(60),
    body_hedge: Duration::from_secs(2),
    pace_floor: Duration::from_millis(300),
    pace_ceiling: Duration::from_secs(3),
    write_inflight: 12,
};

// ── 槽位描述帧（Go slotFrame）───────────────────────────────────────────────

/// 槽位 description 的内容：持有哪一段，以及段本体（内联）或其大小与校验和（media）。
#[derive(Debug, Clone, Default)]
pub(crate) struct SlotFrame {
    seq: i64,
    mode: u8,
    size: usize,
    crc: u32,
    /// 仅 `mode == SLOT_INLINE` 非空（Go 同款：media 帧不携带数据）。
    data: Vec<u8>,
}

impl SlotFrame {
    pub(crate) fn new(seq: i64, mode: u8, data: &[u8]) -> Self {
        let mut f =
            Self { seq, mode, size: data.len(), crc: crc32fast::hash(data), data: Vec::new() };
        if mode == SLOT_INLINE {
            f.data = data.to_vec();
        }
        f
    }

    /// base64(std, padding) 编码（Go `encode`）。
    pub(crate) fn encode(&self) -> String {
        let mut b = Vec::with_capacity(SLOT_HEADER_LEN + self.data.len());
        b.extend_from_slice(SLOT_MAGIC);
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.push(self.mode);
        b.extend_from_slice(&(u32::try_from(self.size).unwrap_or(u32::MAX)).to_be_bytes());
        b.extend_from_slice(&self.crc.to_be_bytes());
        b.extend_from_slice(&self.data);
        base64_encode(&b, Base64Alphabet::Std, true)
    }

    /// body 是否就是本帧所描述的段——描述读紧接着的 body 读可能还未到位（Go `holds`）。
    pub(crate) fn holds(&self, body: &[u8]) -> bool {
        body.len() == self.size && crc32fast::hash(body) == self.crc
    }
}

/// 解码槽位描述（Go `decodeSlot`）：魔数/长度不符、内联帧校验和不匹配 → `None`。
pub(crate) fn decode_slot(description: &str) -> Option<SlotFrame> {
    let b = base64_decode(description, Base64Alphabet::Std).ok()?;
    if b.len() < SLOT_HEADER_LEN || b[..SLOT_MAGIC.len()] != *SLOT_MAGIC {
        return None;
    }
    let f = SlotFrame {
        seq: i64::from_be_bytes(b[8..16].try_into().ok()?),
        mode: b[16],
        size: u32::from_be_bytes(b[17..21].try_into().ok()?) as usize,
        crc: u32::from_be_bytes(b[21..25].try_into().ok()?),
        data: Vec::new(),
    };
    if f.mode == SLOT_INLINE {
        let data = b[SLOT_HEADER_LEN..].to_vec();
        let intact = data.len() == f.size && crc32fast::hash(&data) == f.crc;
        return intact.then_some(SlotFrame { data, ..f });
    }
    Some(f)
}

// ── 环（Go slotTable / ring）────────────────────────────────────────────────

/// 单方向一圈：槽位 id 序列 + 读侧水位线对象 id（Go `slotTable`）。
#[derive(Debug, Clone, Default)]
pub(crate) struct SlotTable {
    pub(crate) slots: Vec<String>,
    pub(crate) watermark: String,
}

/// 会话环：客户端 announce 的内容；表名以客户端视角命名（Go `ring`）。
#[derive(Debug, Clone, Default)]
pub(crate) struct Ring {
    pub(crate) up: SlotTable,
    pub(crate) down: SlotTable,
    /// Go `json:"first,omitempty"`：首段经 announce 内嵌（[]byte → JSON base64 串）。
    pub(crate) first: Vec<u8>,
}

fn slot_table_json(t: &SlotTable) -> serde_json::Value {
    serde_json::json!({ "s": t.slots, "w": t.watermark })
}

/// 编码环（Go `json.Marshal(ring)` 的 wire 形态：`u`/`d` 表 + 可选 `first`）。
pub(crate) fn encode_ring(r: &Ring) -> Vec<u8> {
    let mut obj = serde_json::Map::new();
    obj.insert("u".to_string(), slot_table_json(&r.up));
    obj.insert("d".to_string(), slot_table_json(&r.down));
    if !r.first.is_empty() {
        obj.insert(
            "first".to_string(),
            serde_json::Value::String(base64_encode(&r.first, Base64Alphabet::Std, true)),
        );
    }
    serde_json::Value::Object(obj).to_string().into_bytes()
}

fn decode_slot_table(v: &serde_json::Value) -> Option<SlotTable> {
    let slots = v.get("s")?.as_array()?;
    let mut out = Vec::with_capacity(slots.len());
    for item in slots {
        out.push(item.as_str()?.to_string());
    }
    let watermark = v.get("w")?.as_str()?.to_string();
    Some(SlotTable { slots: out, watermark })
}

/// 解码环并复核对端声明的合法性（Go `decodeRing`）：双表非空、水位线非空、
/// 槽数 ≤ 上限、全部 id ∈ (0, 128] 字符。
pub(crate) fn decode_ring(b: &[u8]) -> Option<Ring> {
    let v: serde_json::Value = serde_json::from_slice(b).ok()?;
    let up = decode_slot_table(v.get("u")?)?;
    let down = decode_slot_table(v.get("d")?)?;
    if up.slots.is_empty()
        || down.slots.is_empty()
        || up.watermark.is_empty()
        || down.watermark.is_empty()
    {
        return None;
    }
    if up.slots.len() > MAX_CONCURRENCY || down.slots.len() > MAX_CONCURRENCY {
        return None;
    }
    for t in [&up, &down] {
        if t.watermark.len() > MAX_SLOT_ID_LEN {
            return None;
        }
        for id in &t.slots {
            if id.is_empty() || id.len() > MAX_SLOT_ID_LEN {
                return None;
            }
        }
    }
    let first = match v.get("first") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::String(s)) => base64_decode(s, Base64Alphabet::Std).ok()?,
        Some(_) => return None,
    };
    Some(Ring { up, down, first })
}

/// 一次建齐会话的全部槽位与水位线（Go `makeRing`）：2×depth+2 个对象并发创建，
/// 任一失败（首个错误）整体失败。Go 的 wg 并发 → `JoinSet` 内联收敛（任务寿命
/// 被本函数 await 界定，非逃逸任务）。
pub(crate) async fn make_ring(
    store: Arc<dyn SlotStore>,
    session: &str,
    p: &Params,
) -> io::Result<Ring> {
    let depth = p.concurrency.max(2);
    let mut jobs: Vec<(usize, String)> = Vec::with_capacity(depth * 2 + 2);
    for i in 0..depth {
        jobs.push((i, format!("{}/s{i}", uplink_prefix(session))));
    }
    for i in 0..depth {
        jobs.push((depth + i, format!("{}/s{i}", downlink_prefix(session))));
    }
    let (up_wm, down_wm) = (depth * 2, depth * 2 + 1);
    jobs.push((up_wm, format!("{}/w", uplink_prefix(session))));
    jobs.push((down_wm, format!("{}/w", downlink_prefix(session))));

    let mut set = tokio::task::JoinSet::new();
    for (idx, name) in &jobs {
        let store = Arc::clone(&store);
        let idx = *idx;
        let name = name.clone();
        set.spawn(async move { (idx, store.make_slot(&name, false).await) });
    }
    let mut ids: Vec<Option<String>> = vec![None; jobs.len()];
    let mut first_err: Option<io::Error> = None;
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok((idx, Ok(id))) => ids[idx] = Some(id),
            Ok((_, Err(e))) => {
                first_err.get_or_insert(e);
            },
            Err(e) => {
                first_err
                    .get_or_insert(io::Error::other(format!("slot creation task failed: {e}")));
            },
        }
    }
    if let Some(e) = first_err {
        return Err(e);
    }
    let all: Vec<String> = ids
        .into_iter()
        .map(|id| id.ok_or_else(|| io::Error::other("slot creation returned no id")))
        .collect::<io::Result<_>>()?;
    Ok(Ring {
        up: SlotTable { slots: all[..depth].to_vec(), watermark: all[up_wm].clone() },
        down: SlotTable { slots: all[depth..depth * 2].to_vec(), watermark: all[down_wm].clone() },
        first: Vec::new(),
    })
}

/// 读水位线（Go `readWatermark`；reserved 车道）。空 description = 尚无进度 → -1。
pub(crate) async fn read_watermark(store: &dyn SlotStore, id: &str) -> io::Result<i64> {
    let d = store.read_description(id, true).await?;
    if d.is_empty() {
        return Ok(-1);
    }
    d.parse::<i64>().map_err(|e| io::Error::other(format!("watermark {id} is not a number: {e}")))
}

/// 段号 → 槽位 id（Go `slotID`）。
fn slot_id_of(table: &SlotTable, seq: i64) -> String {
    let depth = table.slots.len().max(1) as i64;
    let idx = seq.rem_euclid(depth) as usize;
    table.slots.get(idx).cloned().unwrap_or_default()
}

// ── 写侧（Go slotWriter）────────────────────────────────────────────────────

#[derive(Default)]
struct WriterState {
    buf: Vec<u8>,
    seq: i64,
    /// 当前切段大小（内联上限起、按突发倍增到 segmentBytes；Go `size`）。
    size: usize,
    /// 同尺寸连续段计数（Go `full`）。
    full: u32,
    last_size: usize,
    held: u32,
    closed: bool,
    /// 首个失败原因（io::Error 不可克隆，存消息重建）。
    err: Option<String>,
}

/// 水位线面（Go ackMu 保护字段；Rust 不跨 await 持锁——偏差①）。
#[derive(Clone, Copy)]
struct AckState {
    acked: i64,
    acked_at: Instant,
    progress: Instant,
}

struct WriterShared {
    store: Arc<dyn SlotStore>,
    table: SlotTable,
    tuning: SlotTuning,
    segment_bytes: usize,
    flush_interval: Duration,
    /// 在飞段闸（Go `slots` chan，容量 min(depth, slotWriteInflight)）。
    sem: Arc<Semaphore>,
    slot_cap: usize,
    tasks: SessionTasks,
    state: Mutex<WriterState>,
    /// 首段捕获钩子（Go `w.first`；Dial 的 announce 任务消费）。
    first: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    ack: Mutex<AckState>,
    /// poll_write 的回压 waker（permit 释放侧唤醒）。
    write_wake: Mutex<Option<Waker>>,
    /// 已交上传未落定的段数（Go `wg`）；watch 是 await 侧唤醒源。
    inflight: Arc<(AtomicUsize, watch::Sender<usize>)>,
}

impl WriterShared {
    fn finish_upload(&self) {
        let remaining = self.inflight.0.fetch_sub(1, Ordering::SeqCst) - 1;
        // `send_replace` 而非 `send`：无订阅者时 tokio `send` 回 Err 且**不落值**
        // （close 之前的整个写入期都没有订阅者），计数会永远停在初值 0 ——
        // 关闭序会据此误判「在飞已收净」而提前落 `.end`（丢段）。
        self.inflight.1.send_replace(remaining);
        // 槽位已空：唤醒等在 poll_write 上的写侧（Go token 释放即放行 Write）。
        if let Some(w) = self.write_wake.lock().take() {
            w.wake();
        }
    }

    fn fail(&self, msg: String) {
        let mut state = self.state.lock();
        if state.err.is_none() {
            state.err = Some(msg);
        }
    }
}

/// 环槽写侧（Go `slotWriter`）：缓冲、切段、水位线授权后上传、关闭冲净 + `.end`。
pub(crate) struct SlotWriter {
    shared: Arc<WriterShared>,
}

pub(crate) fn new_slot_writer(
    store: Arc<dyn SlotStore>,
    table: SlotTable,
    p: &Params,
    tuning: SlotTuning,
    tasks: SessionTasks,
    first: Option<mpsc::Sender<Vec<u8>>>,
) -> Arc<SlotWriter> {
    let clock = xray_frame::compat::clock();
    let slot_cap = table.slots.len().min(tuning.write_inflight);
    let shared = Arc::new(WriterShared {
        store,
        table,
        tuning,
        segment_bytes: p.segment_bytes,
        flush_interval: p.flush_interval,
        sem: Arc::new(Semaphore::new(slot_cap)),
        slot_cap,
        tasks: tasks.clone(),
        state: Mutex::new(WriterState {
            size: SLOT_INLINE_LIMIT.min(p.segment_bytes),
            ..WriterState::default()
        }),
        first: Mutex::new(first),
        ack: Mutex::new(AckState {
            acked: -1,
            acked_at: clock.now_instant(),
            progress: clock.now_instant(),
        }),
        write_wake: Mutex::new(None),
        inflight: Arc::new((AtomicUsize::new(0), watch::channel(0_usize).0)),
    });
    let writer = Arc::new(SlotWriter { shared: Arc::clone(&shared) });
    if let Err(e) = tasks.spawn(slot_writer_flush_loop(Arc::clone(&writer))) {
        LOG.warn(format!("xdrive slots: writer flush loop spawn rejected: {e}"));
    }
    writer
}

impl SlotWriter {
    /// 追加数据（Go `Write`）的 poll 形态：无空闲槽位时不吞新字节（Pending +
    /// 登记 waker），读者落后即回压写侧。重入安全：Pending 返回时 `data` 未入缓冲。
    pub(crate) fn poll_write(&self, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let mut state = self.shared.state.lock();
        if let Some(err) = &state.err {
            return Poll::Ready(Err(io::Error::other(err.clone())));
        }
        if state.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "io.ErrClosedPipe: slot writer closed",
            )));
        }
        loop {
            if state.buf.len() >= state.size {
                if !self.flush_locked(&mut state, Some(cx.waker()))? {
                    return Poll::Pending;
                }
                continue;
            }
            break;
        }
        state.buf.extend_from_slice(data);
        Poll::Ready(Ok(data.len()))
    }

    /// 关闭（Go `Close`）：冲净缓冲 + 等在飞收净 + 等读者排干 + 落 `slotEnd`。
    /// 幂等（二次关闭恒 `Ok(())`）。
    ///
    /// # Errors
    /// 段上传失败、读者排干等待判停、`.end` 写入失败、任务取消。
    pub(crate) async fn close(&self) -> io::Result<()> {
        let mut marked = false;
        let seq = loop {
            // 同步段：标记 + 冲净一刀（guard 不跨 await——rustc Send 分析保守）。
            let (seq_now, blocked) = {
                let mut state = self.shared.state.lock();
                if !marked {
                    if state.closed {
                        return Ok(());
                    }
                    state.closed = true;
                    marked = true;
                }
                if !state.buf.is_empty() && state.err.is_none() {
                    let flushed = self.flush_locked(&mut state, None)?;
                    if flushed {
                        continue; // 锁内循环，无 await 点
                    }
                    // 切不动（无空闲槽位）：等一个（Go flushLocked 阻塞等 token）。
                    (state.seq, true)
                } else {
                    (state.seq, false)
                }
            };
            if !blocked {
                break seq_now;
            }
            match self.shared.tasks.token.run_until_cancelled(self.shared.sem.acquire()).await {
                None => return Err(io::Error::other("context canceled")),
                Some(Err(e)) => return Err(io::Error::other(e.to_string())),
                Some(Ok(permit)) => drop(permit),
            }
        };
        // 收尾宽限从此刻起算（Go：progress = time.Now()）。
        self.shared.ack.lock().progress = xray_frame::compat::clock().now_instant();
        // 等在飞上传收净（Go wg.Wait；watch 唤醒，无轮询）。计数以原子为准、
        // watch 只作唤醒源——订阅前的唤醒一律不可靠，唯有原子是真相。
        let mut inflight_rx = self.shared.inflight.1.subscribe();
        while self.shared.inflight.0.load(Ordering::SeqCst) > 0 {
            if inflight_rx.changed().await.is_err() {
                break; // 发送端已亡——防御性退出（本 writer 存活时不发生）
            }
        }
        if let Some(err) = &self.shared.state.lock().err {
            return Err(io::Error::other(err.clone()));
        }
        self.await_drained(seq).await?;
        let end = SlotFrame::new(seq, SLOT_END, &[]);
        let id = slot_id_of(&self.shared.table, seq);
        self.shared.store.set_slot(&id, &end.encode(), None, false).await
    }

    /// 切段交上传（调用方须已持 `state` 锁；Go `flushLocked`）。返回 `false` =
    /// 无空闲槽位（waker 已登记，data 未消费——调用方以 Pending 回压）。
    fn flush_locked(&self, state: &mut WriterState, waker: Option<&Waker>) -> io::Result<bool> {
        if let Some(err) = &state.err {
            return Err(io::Error::other(err.clone()));
        }
        if state.buf.is_empty() {
            return Ok(true);
        }
        // 取槽位 token（Go `w.slots <- struct{}{}` 的非阻塞形态）。
        let permit = match self.shared.sem.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                if let Some(w) = waker {
                    *self.shared.write_wake.lock() = Some(w.clone());
                }
                // 关窗重查：waker 登记与 permit 释放的竞态闭窗（防丢唤醒）。
                match self.shared.sem.clone().try_acquire_owned() {
                    Ok(permit) => {
                        self.shared.write_wake.lock().take();
                        permit
                    },
                    Err(_) => return Ok(false),
                }
            },
        };
        // 段大小自适应（Go 同序：token 已取后的 len(slots) 判定）。
        if state.size < self.shared.segment_bytes
            && state.buf.len() >= state.size
            && self.shared.sem.available_permits() * 4 > self.shared.slot_cap * 3
        {
            state.size = self.shared.segment_bytes;
            state.full = 0;
        }
        let mut n = state.buf.len().min(state.size);
        if state.buf.len() > 4 * SLOT_INLINE_LIMIT {
            // 突发直接按全尺寸切（Go 同款）。
            n = state.buf.len().min(self.shared.segment_bytes);
        }
        if n > SLOT_INLINE_LIMIT && state.buf.len() <= 2 * self.shared.slot_cap * SLOT_INLINE_LIMIT
        {
            n = SLOT_INLINE_LIMIT;
        }
        if n == state.size && state.size < self.shared.segment_bytes {
            state.full += 1;
            if state.full == INLINE_RAMP_SEGMENTS {
                state.full = 0;
                state.size = (state.size * 2).min(self.shared.segment_bytes);
            }
        }

        let chunk = state.buf[..n].to_vec();
        state.buf.drain(..n);
        let seq = state.seq;
        state.seq += 1;
        if seq == 0 {
            if let Some(first) = self.shared.first.lock().take() {
                let _ = first.try_send(chunk.clone());
            }
        }
        state.last_size = state.buf.len();
        state.held = 0;

        self.shared.inflight.0.fetch_add(1, Ordering::SeqCst);
        self.shared.inflight.1.send_replace(self.shared.inflight.0.load(Ordering::SeqCst));
        let upload = slot_writer_upload(Arc::clone(&self.shared), seq, chunk, permit);
        let spawned = self.shared.tasks.spawn(upload);
        if let Err(e) = spawned {
            // 托管口拒绝（scope 已关）：连接已在拆除，段不会落盘——按存储失败记账。
            self.shared.finish_upload();
            if state.err.is_none() {
                state.err = Some(format!("failed to store segment: {e}"));
            }
        }
        Ok(true)
    }

    /// 合并判定（Go `readyToFlush` 的槽位版）：槽位有余且缓冲过半则再合并一拍。
    fn ready_to_flush(&self, state: &mut WriterState) -> bool {
        let grew = state.buf.len() > state.last_size;
        state.last_size = state.buf.len();
        if self.shared.sem.available_permits() > 0
            && state.held < MAX_COALESCED_TICKS
            && state.buf.len() < state.size / 2
        {
            state.held += 1;
            return false;
        }
        if grew && state.held < MAX_COALESCED_TICKS {
            state.held += 1;
            return false;
        }
        state.held = 0;
        true
    }

    /// 记首个失败（Go `fail`）。
    pub(crate) fn fail(&self, msg: String) {
        self.shared.fail(msg);
    }

    /// 等读者排干（Go `await`）：水位线到齐 / 判停 / 关闭宽限 / 取消。
    async fn await_drained(&self, seq: i64) -> io::Result<()> {
        await_drained(&self.shared, seq).await
    }
}

async fn slot_writer_flush_loop(writer: Arc<SlotWriter>) {
    // sleep 轮（每次新建 sleep）而非 `Interval`：Go `time.NewTicker` 首拍即在
    // period 后、错过的拍不补——sleep 轮天然同语义；且实测 `Interval` 的第二拍
    // 在本仓测试 runtime 下死等不返回（sleep 模式可靠），顺带去掉 Interval 状态机。
    loop {
        let slept = writer
            .shared
            .tasks
            .token
            .run_until_cancelled(tokio::time::sleep(writer.shared.flush_interval));
        if slept.await.is_none() {
            return;
        }
        let done = {
            let mut state = writer.shared.state.lock();
            if !state.closed
                && state.err.is_none()
                && !state.buf.is_empty()
                && writer.ready_to_flush(&mut state)
            {
                // 无空闲槽位则本拍跳过（Go 阻塞等 token；此处持锁不可等——写侧
                // waker 会在槽位空出时推进）。失败即记账（此后条件短路）。
                let _ = writer.flush_locked(&mut state, None);
            }
            state.closed || state.err.is_some()
        };
        if done {
            return;
        }
    }
}

async fn slot_writer_upload(
    shared: Arc<WriterShared>,
    seq: i64,
    chunk: Vec<u8>,
    permit: OwnedSemaphorePermit,
) {
    let mode = if chunk.len() <= SLOT_INLINE_LIMIT { SLOT_INLINE } else { SLOT_MEDIA };
    if let Err(e) = await_drained(&shared, seq).await {
        shared.fail(format!("failed to store segment {seq}: {e}"));
    } else {
        let id = slot_id_of(&shared.table, seq);
        let frame = SlotFrame::new(seq, mode, &chunk);
        let body = if mode == SLOT_MEDIA { Some(chunk.as_slice()) } else { None };
        if let Err(e) = shared.store.set_slot(&id, &frame.encode(), body, false).await {
            shared.fail(format!("failed to store segment {seq}: {e}"));
            // 槽位已空，读端经 slotErr 学到结局（标记自身失败不可恢复，Go 同款）。
            let err_frame = SlotFrame::new(seq, SLOT_ERR, &[]);
            if let Err(e2) = shared.store.set_slot(&id, &err_frame.encode(), None, false).await {
                LOG.warn(format!(
                    "xdrive slots: failed to store the error marker of segment {seq}: {e2}"
                ));
            }
        }
    }
    drop(permit); // Go defer ①：token 先释放
    shared.finish_upload(); // Go defer ②：wg.Done
}

/// 水位线判定（Go `drained`）：seq 上一圈的内容是否已被读者取走。TTL 内复用缓存。
/// 持锁不跨 await——并发重复读一次（偏差①，结局一致）。
async fn drained(
    shared: &WriterShared,
    seq: i64,
    clock: &Arc<dyn skeleton::clock::Clock>,
) -> (bool, Option<io::Error>) {
    let before = seq - shared.table.slots.len() as i64;
    {
        let ack = shared.ack.lock();
        if ack.acked >= before {
            return (true, None);
        }
        if clock.now_instant().duration_since(ack.acked_at) < shared.tuning.watermark_ttl {
            return (false, None);
        }
    }
    let acked = match read_watermark(shared.store.as_ref(), &shared.table.watermark).await {
        Ok(v) => v,
        Err(e) => return (false, Some(e)),
    };
    let now = clock.now_instant();
    let mut ack = shared.ack.lock();
    ack.acked_at = now;
    if acked > ack.acked {
        ack.acked = acked;
        ack.progress = now;
    }
    (ack.acked >= before, None)
}

/// 等排干（Go `await`）：判停 / 关闭宽限 / 水位线错误退避重试。
async fn await_drained(shared: &WriterShared, seq: i64) -> io::Result<()> {
    let clock = xray_frame::compat::clock();
    let began = clock.now_instant();
    let mut wait = shared.tuning.ack_retry;
    loop {
        let (ok, poll_err) = drained(shared, seq, &clock).await;
        if ok {
            return Ok(());
        }
        let closed = shared.state.lock().closed;
        let still = clock.now_instant().duration_since(shared.ack.lock().progress);
        if began.elapsed().min(still) > shared.tuning.stall_timeout
            || (closed && still > shared.tuning.close_grace)
        {
            let base = poll_err.map(|e| format!(": {e}")).unwrap_or_default();
            return Err(io::Error::other(format!(
                "the reader took nothing from slot {} for {:?}{base}",
                slot_id_of(&shared.table, seq),
                still
            )));
        }
        wait = if poll_err.is_some() {
            (wait * 2).min(Duration::from_secs(2))
        } else {
            shared.tuning.ack_retry
        };
        let slept = tokio::time::sleep(wait);
        tokio::pin!(slept);
        tokio::select! {
            _ = shared.tasks.token.cancelled() => {
                return Err(io::Error::other("context canceled"));
            },
            _ = &mut slept => {},
        }
    }
}

// ── 读侧（Go slotReader）────────────────────────────────────────────────────

/// 单段取件（Go `slotFetch` 直译）：promoted/near 双信号 + 结果槽/ready 通知。
/// 结果存共享槽由 run 消化（Go `f.body`/`f.ready` 同构）——不经中转通道，
/// 无容量、无丢弃；head 的结果对 run 恒可见。
struct FetchSignal {
    promoted: AtomicBool,
    promoted_notify: Notify,
    near: AtomicBool,
    near_notify: Notify,
    ready_notify: Notify,
    slot: Mutex<Option<FetchOutcome>>,
}

impl FetchSignal {
    fn new() -> Self {
        Self {
            promoted: AtomicBool::new(false),
            promoted_notify: Notify::new(),
            near: AtomicBool::new(false),
            near_notify: Notify::new(),
            ready_notify: Notify::new(),
            slot: Mutex::new(None),
        }
    }

    /// 预取起跑（Go `enter`）：near 置位后该段的重询不再等首等节拍。
    fn enter(&self) {
        self.near.store(true, Ordering::SeqCst);
        self.near_notify.notify_one();
    }

    /// 升为头段（Go `close(next.promoted)`）。
    fn promote(&self) {
        self.promoted.store(true, Ordering::SeqCst);
        self.promoted_notify.notify_one();
    }

    fn is_near(&self) -> bool {
        self.near.load(Ordering::SeqCst)
    }

    /// 存结果并通知 run（Go `close(f.ready)`；槽内已置值）。
    fn complete(&self, outcome: FetchOutcome) {
        *self.slot.lock() = Some(outcome);
        self.ready_notify.notify_one();
    }

    /// run 取头段结果（调用方保证已 complete；None = 尚未）。
    fn take(&self) -> Option<FetchOutcome> {
        self.slot.lock().take()
    }
}

enum FetchOutcome {
    Body(Vec<u8>),
    End,
    Err(String),
}

struct ReaderState {
    head: i64,
    started: bool,
    /// 本会话见过的最大段号（窗口扩张依据；Go `frontier`）。
    frontier: i64,
    hit_at: Instant,
    /// 段间间隔的指数平滑（0 = 未测；Go `gap`）。
    gap: Duration,
    active_at: Instant,
    err: Option<String>,
    /// body 读速率的指数平滑（字节/秒；Go `bodyRate`）。
    body_rate: f64,
}

/// 环槽读侧共享核（`SlotReader.shared`；announce 失败等外部错误面经它注入）。
pub(crate) struct ReaderShared {
    store: Arc<dyn SlotStore>,
    table: SlotTable,
    tuning: SlotTuning,
    eager_window: Duration,
    max_poll_interval: Duration,
    state: Mutex<ReaderState>,
    /// 有段到了/ Wake（Go `r.wake`）。
    wake: Notify,
    /// frontier 前移（Go `r.grow`）。
    grow: Notify,
    /// 头部推进 → 水位线写（Go `r.acks`）。
    acks: Notify,
    /// idle→active 转换代次（Go close(active) 的广播等价面）。
    active_gen: watch::Sender<u64>,
    /// 读侧专属停机（Go reader runCtx + setErr 的 stop）。
    stop: CancelSource,
    stop_token: CancelToken,
}

impl ReaderShared {
    fn idle(&self, st: &ReaderState, now: Instant) -> bool {
        now.duration_since(st.active_at) > self.eager_window
    }
}

/// 环槽读侧句柄（Go `slotReader`）：run/fetch/ack 任务族 + 消费通道。
pub(crate) struct SlotReader {
    shared: Arc<ReaderShared>,
    receiver: mpsc::Receiver<Vec<u8>>,
}

pub(crate) fn new_slot_reader(
    store: Arc<dyn SlotStore>,
    table: SlotTable,
    p: &Params,
    tuning: SlotTuning,
    tasks: SessionTasks,
    first: Option<Vec<u8>>,
) -> SlotReader {
    let clock = xray_frame::compat::clock();
    let now = clock.now_instant();
    let primed = first.as_ref().is_some_and(|f| !f.is_empty());
    let (tx, receiver) = mpsc::channel(p.concurrency.max(1));
    let (stop, stop_token) = cancel_pair();
    let (active_gen, _) = watch::channel(0_u64);
    let shared = Arc::new(ReaderShared {
        store,
        table,
        tuning,
        eager_window: p.eager_window,
        max_poll_interval: p.max_poll_interval,
        state: Mutex::new(ReaderState {
            head: i64::from(primed),
            started: primed,
            frontier: 0,
            hit_at: now,
            gap: Duration::ZERO,
            active_at: now,
            err: None,
            body_rate: 0.0,
        }),
        wake: Notify::new(),
        grow: Notify::new(),
        acks: Notify::new(),
        active_gen,
        stop,
        stop_token: stop_token.clone(),
    });
    if let Some(first) = first.filter(|f| !f.is_empty()) {
        // 容量 ≥ 1 且通道全新：try_send 恒成功（Go `r.ch <- first` 的等价面）。
        let _ = tx.try_send(first);
        shared.acks.notify_one();
    }
    if let Err(e) = tasks.spawn(slot_reader_run(Arc::clone(&shared), tasks.clone(), tx)) {
        LOG.warn(format!("xdrive slots: reader run loop spawn rejected: {e}"));
        set_err_msg(&shared, format!("reader loop spawn rejected: {e}"));
    }
    if let Err(e) = tasks.spawn(slot_reader_ack_loop(Arc::clone(&shared), tasks.token.clone())) {
        LOG.warn(format!("xdrive slots: reader ack loop spawn rejected: {e}"));
    }
    SlotReader { shared, receiver }
}

impl SlotReader {
    /// 取下一段（poll 原语，供 `Conn` 的 `AsyncRead` 集成）。
    pub(crate) fn poll_chunk(&mut self, cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
        self.receiver.poll_recv(cx)
    }

    /// 消费者侧错误快照（Go `Err()`：EOF 不在此——通道闭且无错误即 EOF）。
    pub(crate) fn take_err(&self) -> Option<io::Error> {
        self.shared.state.lock().err.take().map(io::Error::other)
    }

    /// 头段即刻起询（Go `Wake`）：有段很可能要来。
    pub(crate) fn wake(&self) {
        {
            let clock = xray_frame::compat::clock();
            let mut st = self.shared.state.lock();
            touch(&self.shared, &mut st, clock.now_instant());
        }
        self.shared.wake.notify_one();
    }

    /// 共享核句柄（announce 失败等外部错误面注入用；Go `reader.setErr` 的
    /// 所有权转移形态——外部持有人经 [`ReaderShared::set_err`] 注入）。
    pub(crate) fn shared_handle(&self) -> Arc<ReaderShared> {
        Arc::clone(&self.shared)
    }
}

/// 记错误 + 停读侧任务族（Go `setErr`）。
fn set_err_msg(shared: &ReaderShared, msg: String) {
    {
        let mut st = shared.state.lock();
        if st.err.is_none() {
            st.err = Some(msg);
        }
    }
    shared.stop.cancel();
}

impl ReaderShared {
    /// 外部错误注入面（Go `reader.setErr`；announce 失败等共享核持有人调用）。
    pub(crate) fn set_err(&self, msg: String) {
        set_err_msg(self, msg);
    }
}

/// idle→active 转换记录（Go `touch`）：跨过 eager 窗即广播新一代次唤醒等在
/// active 上的取件任务。调用方须已持 state 锁。
fn touch(shared: &ReaderShared, st: &mut ReaderState, now: Instant) {
    if now.duration_since(st.active_at) > shared.eager_window {
        let next = *shared.active_gen.borrow() + 1;
        // `send_replace`：订阅者只在 idle 分支临时出现，`send` 在无订阅者时
        // 回 Err 且不落值 → 代次永远停在 0，空闲 fetch 的 active 等待永不唤醒。
        shared.active_gen.send_replace(next);
    }
    st.active_at = now;
}

/// 段到达记账（Go `hit`）：段间间隔指数平滑 + touch。
fn hit(shared: &ReaderShared, st: &mut ReaderState, now: Instant) {
    let gap = now.duration_since(st.hit_at);
    st.gap = if st.gap.is_zero() { gap } else { (st.gap + gap) / 2 };
    st.hit_at = now;
    touch(shared, st, now);
}

/// 段间节奏（Go `pace`）：平滑间隔钳到 [300ms, 3s]。
fn pace(shared: &ReaderShared) -> Duration {
    let st = shared.state.lock();
    if st.gap < shared.tuning.pace_floor {
        shared.tuning.pace_floor
    } else if st.gap > shared.tuning.pace_ceiling {
        shared.tuning.pace_ceiling
    } else {
        st.gap
    }
}

/// 突发窗判定（Go `bursting`）：距上段到达 ≤ 500ms。
fn bursting(shared: &ReaderShared) -> bool {
    let clock = xray_frame::compat::clock();
    let st = shared.state.lock();
    clock.now_instant().duration_since(st.hit_at) <= shared.tuning.read_ahead_burst
}

/// frontier 前移 + 唤醒 run 扩窗（Go `reach`）。
fn reach(shared: &ReaderShared, seq: i64) {
    let grown = {
        let mut st = shared.state.lock();
        if seq > st.frontier {
            st.frontier = seq;
            true
        } else {
            false
        }
    };
    if grown {
        shared.grow.notify_one();
    }
}

fn is_head(shared: &ReaderShared, seq: i64) -> bool {
    shared.state.lock().head == seq
}

/// 段取件结果（Go `slotFetch` 的 ready 载荷）。
async fn slot_fetch(
    shared: Arc<ReaderShared>,
    tasks: CancelToken,
    seq: i64,
    offset: usize,
    signal: Arc<FetchSignal>,
) {
    let Some(outcome) = fetch_inner(&shared, &tasks, seq, offset, &signal).await else {
        return; // 取消（Go 经 defer 关 ready 由 run 的退出分支吸收）
    };
    signal.complete(outcome); // Go `close(f.ready)`：结果已存槽，run 专候
}

/// hold 的 b 侧（Go hold(ctx, d, a, b) 的 b 通道）。
enum HoldB<'a> {
    None,
    Near(&'a Notify),
    /// (代次接收端, 捕获代次)：代次前进即唤醒（Go 持有 active chan 等 close）。
    Active(watch::Receiver<u64>, u64),
}

/// 等 d（0 = 不限时）/ a / b / 取消（Go `hold`）。`false` = 已取消。
async fn hold(
    tasks: &CancelToken,
    stop: &CancelToken,
    d: Option<Duration>,
    a: Option<&Notify>,
    b: HoldB<'_>,
) -> bool {
    let timer = async {
        match d {
            Some(d) => tokio::time::sleep(d).await,
            None => std::future::pending::<()>().await,
        }
    };
    let a_fut = async {
        match a {
            Some(n) => n.notified().await,
            None => std::future::pending::<()>().await,
        }
    };
    let b_fut = async {
        match b {
            HoldB::None => std::future::pending::<()>().await,
            HoldB::Near(n) => n.notified().await,
            HoldB::Active(mut rx, seen_gen) => {
                if *rx.borrow_and_update() != seen_gen {
                    return;
                }
                let _ = rx.changed().await;
            },
        }
    };
    tokio::select! {
        _ = tasks.cancelled() => false,
        _ = stop.cancelled() => false,
        _ = a_fut => true,
        _ = b_fut => true,
        _ = timer => true,
    }
}

/// 取件循环（Go `fetch`）：头段勤询、尾随段按节拍、空闲期只询头段，直到槽位
/// 持有本段。返回 `None` = 取消。
async fn fetch_inner(
    shared: &Arc<ReaderShared>,
    tasks: &CancelToken,
    seq: i64,
    offset: usize,
    signal: &FetchSignal,
) -> Option<FetchOutcome> {
    let clock = xray_frame::compat::clock();
    if offset > 0
        && !hold(
            tasks,
            &shared.stop_token,
            Some(shared.tuning.tail_min),
            Some(&signal.promoted_notify),
            HoldB::Near(&signal.near_notify),
        )
        .await
    {
        return None;
    }

    let mut backoff = shared.tuning.hunt_floor;
    let mut gone_since: Option<Instant> = None;
    let mut warned_at: Option<Instant> = None;
    let mut visible_since: Option<Instant> = None;
    loop {
        let now = clock.now_instant();
        // 热度判定（active 代次在节拍段的同锁窗口再捕——Go `r.mu` 同窗）。
        let hot = {
            let st = shared.state.lock();
            !shared.idle(&st, now)
        };
        let id = slot_id_of(&shared.table, seq);
        let (description, read_err) = if hot && is_head(shared, seq) {
            let (d, e) = read_head(shared, tasks, &id, seq).await;
            (d, e)
        } else {
            match shared.store.read_description(&id, false).await {
                Ok(d) => (d, None),
                Err(e) => (String::new(), Some(e)),
            }
        };
        let frame = decode_slot(&description);
        let absent = read_err.as_ref().map(is_not_found).unwrap_or(false)
            || (read_err.is_none() && description.is_empty());
        if absent {
            // 空槽/缺失是空闲，不是失败（Go：visibleSince 清零）。
            visible_since = None;
        }

        let mut finish: Option<FetchOutcome> = None;
        let matched = match (&read_err, frame.as_ref()) {
            (None, Some(f)) if f.seq == seq => Some(f),
            _ => None,
        };
        if let Some(f) = matched {
            {
                let mut st = shared.state.lock();
                touch(shared, &mut st, clock.now_instant());
            }
            reach(shared, seq);
            match f.mode {
                SLOT_END => finish = Some(FetchOutcome::End),
                SLOT_ERR => {
                    finish =
                        Some(FetchOutcome::Err(format!("the peer could not store segment {seq}")));
                },
                SLOT_INLINE => {
                    finish = Some(FetchOutcome::Body(f.data.clone()));
                    let mut st = shared.state.lock();
                    hit(shared, &mut st, clock.now_instant());
                },
                SLOT_MEDIA => match read_body_hedged(shared, tasks, &id, f.size).await {
                    Ok(body) if f.holds(&body) => {
                        finish = Some(FetchOutcome::Body(body));
                        let mut st = shared.state.lock();
                        hit(shared, &mut st, clock.now_instant());
                    },
                    res => {
                        let body_err = res.err();
                        if !tasks.is_cancelled()
                            && !shared.stop_token.is_cancelled()
                            && warned_at.is_none_or_stale(clock.now_instant())
                        {
                            warned_at = Some(clock.now_instant());
                            match &body_err {
                                Some(e) => LOG.warn(format!(
                                    "xdrive slots: failed to read body of slot {id}: {e}"
                                )),
                                None => LOG.warn(format!(
                                    "xdrive slots: body of slot {id} does not match segment {seq}"
                                )),
                            }
                        }
                        if visible_since.is_none() {
                            visible_since = Some(clock.now_instant());
                        }
                        let since = visible_since.unwrap_or_else(|| clock.now_instant());
                        if clock.now_instant().duration_since(since) > shared.tuning.stall_timeout {
                            let base = body_err.map(|e| format!(": {e}")).unwrap_or_default();
                            finish = Some(FetchOutcome::Err(format!(
                                "segment {seq} has no usable body after {:?}{base}",
                                shared.tuning.stall_timeout
                            )));
                        }
                    },
                },
                _ => {}, // 未知 mode：视为持有但不可识别，按节拍重询（Go 同款 fallthrough）
            }
        } else if read_err.is_none() && frame.is_none() && !description.is_empty() {
            // 在场但不可解码的 description 不是空闲：越过判停即失败。
            let since = visible_since.get_or_insert(clock.now_instant());
            if clock.now_instant().duration_since(*since) > shared.tuning.stall_timeout {
                finish = Some(FetchOutcome::Err(format!(
                    "slot {id} of segment {seq} holds an invalid frame"
                )));
            }
        } else if read_err.as_ref().map(is_not_found).unwrap_or(false) {
            match gone_since {
                None => gone_since = Some(clock.now_instant()),
                Some(since) => {
                    if clock.now_instant().duration_since(since) > shared.tuning.gone_timeout
                        && is_head(shared, seq)
                    {
                        let why = read_err.as_ref().map(|e| e.to_string()).unwrap_or_default();
                        finish = Some(FetchOutcome::Err(format!(
                            "slot {id} of segment {seq} is gone: {why}"
                        )));
                    }
                },
            }
        } else if let Some(err) = &read_err {
            if is_auth_error(err) {
                finish = Some(FetchOutcome::Err(err.to_string()));
            } else {
                gone_since = None;
                if !tasks.is_cancelled()
                    && !shared.stop_token.is_cancelled()
                    && warned_at.is_none_or_stale(clock.now_instant())
                {
                    warned_at = Some(clock.now_instant());
                    LOG.warn(format!("xdrive slots: failed to read slot {id}: {err}"));
                }
            }
        }
        if let Some(o) = finish {
            return Some(o);
        }

        // 节拍决策（Go 同款：wait 取更新前的 backoff；idle 只询头段）。
        let (head_here, idle, active_gen) = {
            let st = shared.state.lock();
            let idle = shared.idle(&st, clock.now_instant());
            (st.head == seq, idle, *shared.active_gen.borrow())
        };
        let mut wait: Option<Duration>;
        let a: Option<&Notify>;
        let b: HoldB;
        if head_here {
            wait = Some(backoff);
            let ceiling = if idle {
                shared.tuning.hunt_ceiling.max(shared.max_poll_interval)
            } else {
                shared.tuning.hunt_ceiling
            };
            backoff = (backoff * 2).min(ceiling);
            a = Some(&shared.wake);
            b = HoldB::None;
        } else if idle {
            wait = None;
            a = Some(&signal.promoted_notify);
            b = HoldB::Active(shared.active_gen.subscribe(), active_gen);
            backoff = shared.tuning.hunt_floor;
        } else {
            wait = Some(pace(shared).max(shared.tuning.tail_min).min(shared.tuning.tail_max));
            a = Some(&signal.promoted_notify);
            backoff = shared.tuning.hunt_floor;
            if signal.is_near() {
                b = HoldB::None;
                if bursting(shared) {
                    wait = Some(shared.tuning.read_ahead_poll);
                }
            } else {
                b = HoldB::Near(&signal.near_notify);
            }
        }
        if !hold(tasks, &shared.stop_token, wait, a, b).await {
            return None;
        }
    }
}

/// 告警限频（Go `time.Since(warnedAt) > 10*time.Second`；None = 从未告警）。
trait WarnClock {
    fn is_none_or_stale(&self, now: Instant) -> bool;
}
impl WarnClock for Option<Instant> {
    fn is_none_or_stale(&self, now: Instant) -> bool {
        match self {
            None => true,
            Some(at) => now.duration_since(*at) > Duration::from_secs(10),
        }
    }
}

/// 头段对冲读（Go `readHead`）：至多 3 路在飞抢答，返回首个持有本段的描述；
/// 空闲且见过旧答案则交旧答案；JoinSet drop 即撤在途（Go child ctx cancel）。
async fn read_head(
    shared: &Arc<ReaderShared>,
    tasks: &CancelToken,
    id: &str,
    seq: i64,
) -> (String, Option<io::Error>) {
    let clock = xray_frame::compat::clock();
    let mut set = tokio::task::JoinSet::new();
    let mut outstanding = 0usize;
    {
        let store = Arc::clone(&shared.store);
        let id = id.to_string();
        set.spawn(async move { store.read_description(&id, true).await });
        outstanding += 1;
    }
    let mut ticker = tokio::time::interval(shared.tuning.hunt_ceiling);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // 丢首拍（对齐 Go NewTicker）
    let mut last = String::new();
    let mut seen = false;
    loop {
        let next = async {
            if outstanding == 0 {
                std::future::pending::<
                    Option<std::result::Result<io::Result<String>, tokio::task::JoinError>>,
                >()
                .await
            } else {
                set.join_next().await
            }
        };
        tokio::select! {
            res = next => {
                match res {
                    Some(Ok(Ok(description))) => {
                        outstanding -= 1;
                        if decode_slot(&description).is_some_and(|f| f.seq == seq) {
                            return (description, None);
                        }
                        last = description;
                        seen = true;
                    },
                    Some(Ok(Err(e))) => return (String::new(), Some(e)),
                    Some(Err(e)) => {
                        return (String::new(), Some(io::Error::other(format!("hedged head read failed: {e}"))));
                    },
                    None => {},
                }
            },
            _ = ticker.tick() => {
                let idle = {
                    let st = shared.state.lock();
                    shared.idle(&st, clock.now_instant())
                };
                if idle && seen {
                    return (last, None);
                } else if !idle && outstanding < 3 {
                    let store = Arc::clone(&shared.store);
                    let id = id.to_string();
                    set.spawn(async move { store.read_description(&id, true).await });
                    outstanding += 1;
                }
            },
            _ = shared.wake.notified() => {
                if outstanding < 3 {
                    let store = Arc::clone(&shared.store);
                    let id = id.to_string();
                    set.spawn(async move { store.read_description(&id, true).await });
                    outstanding += 1;
                }
            },
            _ = tasks.cancelled() => return (String::new(), Some(io::Error::other("context canceled"))),
            _ = shared.stop_token.cancelled() => return (String::new(), Some(io::Error::other("context canceled"))),
        }
    }
}

/// body 对冲读（Go `readBodyHedged`）：首路超 `bodyHedge`（按已学速率放行更大段）
/// 未归即起第二路；成功读回即更新速率的指数平滑。
async fn read_body_hedged(
    shared: &Arc<ReaderShared>,
    tasks: &CancelToken,
    id: &str,
    size: usize,
) -> io::Result<Vec<u8>> {
    if shared.tuning.body_hedge.is_zero() {
        return shared.store.read_body(id).await;
    }
    let mut delay = shared.tuning.body_hedge;
    let rate = shared.state.lock().body_rate;
    if rate > 0.0 && size > 0 {
        let scaled = Duration::from_secs_f64(
            2.0 * f64::from(u32::try_from(size).unwrap_or(u32::MAX)) / rate,
        );
        if scaled > delay {
            delay = scaled;
        }
    }
    let clock = xray_frame::compat::clock();
    let began = clock.now_instant();
    let mut set = tokio::task::JoinSet::new();
    let launch = |set: &mut tokio::task::JoinSet<io::Result<Vec<u8>>>| {
        let store = Arc::clone(&shared.store);
        let id = id.to_string();
        set.spawn(async move { store.read_body(&id).await });
    };
    launch(&mut set);
    let mut outstanding = 1usize;
    let timer = tokio::time::sleep(delay);
    tokio::pin!(timer);
    loop {
        tokio::select! {
            res = set.join_next() => {
                match res {
                    Some(Ok(Ok(body))) => {
                        let elapsed = began.elapsed();
                        if !elapsed.is_zero() && !body.is_empty() {
                            let instant = body.len() as f64 / elapsed.as_secs_f64();
                            let mut st = shared.state.lock();
                            st.body_rate = if st.body_rate == 0.0 { instant } else { (st.body_rate + instant) / 2.0 };
                        }
                        return Ok(body);
                    },
                    Some(Ok(Err(e))) => {
                        outstanding -= 1;
                        if outstanding == 0 {
                            return Err(e);
                        }
                    },
                    Some(Err(e)) => {
                        outstanding -= 1;
                        let err = io::Error::other(format!("hedged body read failed: {e}"));
                        if outstanding == 0 {
                            return Err(err);
                        }
                    },
                    None => return Err(io::Error::other("hedged body read lost its tasks")),
                }
            },
            _ = &mut timer => {
                if outstanding == 1 {
                    launch(&mut set);
                    outstanding += 1;
                }
            },
            _ = tasks.cancelled() => return Err(io::Error::other("context canceled")),
            _ = shared.stop_token.cancelled() => return Err(io::Error::other("context canceled")),
        }
    }
}

/// run 主循环（Go `run`）：按窗口起取件任务、按序交付段体、推进水位线信号；
/// 结束（end/err/取消）即撤全部取件任务并闭消费通道。
async fn slot_reader_run(
    shared: Arc<ReaderShared>,
    tasks: SessionTasks,
    tx: mpsc::Sender<Vec<u8>>,
) {
    let token = tasks.token.clone();
    let mut signals: HashMap<i64, Arc<FetchSignal>> = HashMap::new();
    loop {
        // 窗口 spawn（Go：window = clamp(frontier-head+fetchAhead, ≥fetchAhead, ≤depth)）。
        let head = {
            let st = shared.state.lock();
            let (head, started, frontier) = (st.head, st.started, st.frontier);
            let depth = shared.table.slots.len();
            let window = if started {
                (((frontier - head + shared.tuning.fetch_ahead).max(shared.tuning.fetch_ahead))
                    as usize)
                    .min(depth)
            } else {
                1
            };
            for i in 0..window {
                let seq = head + i as i64;
                if signals.contains_key(&seq) {
                    continue;
                }
                let signal = Arc::new(FetchSignal::new());
                if (i as i64) <= shared.tuning.read_ahead {
                    signal.enter();
                }
                let fut =
                    slot_fetch(Arc::clone(&shared), token.clone(), seq, i, Arc::clone(&signal));
                if tasks.spawn(fut).is_err() {
                    // 托管口拒绝（scope 已关）：读侧拆除中。
                    set_err_msg(&shared, "reader loop is being torn down".to_string());
                    return;
                }
                signals.insert(seq, signal);
            }
            head
        };
        // 只候头段结果（Go `f := fetches[head]; select f.ready`）；非头结果存槽
        // 不打扰（Go 同构）——无中转通道、无容量、无丢弃。
        let head_sig = signals.get(&head).cloned();
        tokio::select! {
            _ = async {
                match head_sig {
                    Some(sig) => sig.ready_notify.notified().await,
                    None => std::future::pending::<()>().await,
                }
            } => {},
            _ = shared.grow.notified() => continue,
            _ = token.cancelled() => break,
            _ = shared.stop_token.cancelled() => break,
        };
        // 按序消化连续头段（Go 每轮消化一个再扩窗；此处连吃后统一扩窗，序不变）。
        let mut head_now = head;
        while let Some(outcome) = signals.get(&head_now).and_then(|sig| sig.take()) {
            signals.remove(&head_now); // 已消费（Go delete(fetches, head)）
            match outcome {
                FetchOutcome::Err(msg) => {
                    set_err_msg(&shared, msg);
                    return;
                },
                FetchOutcome::End => {
                    return;
                },
                FetchOutcome::Body(body) => {
                    head_now += 1;
                    {
                        let mut st = shared.state.lock();
                        st.head = head_now;
                        st.started = true;
                    }
                    signals.remove(&(head_now - 1)); // 已消费（Go delete(fetches, head)）
                    // 段体到位即释放槽位，后一段即刻起询（Go promote + enter）。
                    if let Some(sig) = signals.get(&head_now) {
                        sig.promote();
                    }
                    if let Some(sig) = signals.get(&(head_now + shared.tuning.read_ahead)) {
                        sig.enter();
                    }
                    shared.acks.notify_one();
                    // 段体一旦到手槽位即空：交付不过闸（Go `ch <- f.body` 同款）。
                    let send = tx.send(body);
                    let sent = token.run_until_cancelled(send).await;
                    let lost = sent.is_none_or(|r| r.is_err());
                    if lost {
                        return; // 消费者取消/已亡
                    }
                },
            }
        }
    }
    shared.stop.cancel(); // Go defer cancel：连带停掉 fetch/ack 任务族
}

/// 水位线写循环（Go `ackLoop`）：头部推进即写，期间头部只写最新值。
async fn slot_reader_ack_loop(shared: Arc<ReaderShared>, token: CancelToken) {
    let mut acked: i64 = -1;
    let mut wait = shared.tuning.ack_retry;
    loop {
        tokio::select! {
            _ = token.cancelled() => return,
            _ = shared.stop_token.cancelled() => return,
            _ = shared.acks.notified() => {},
        }
        loop {
            let want = shared.state.lock().head - 1;
            if want <= acked {
                break;
            }
            let id = shared.table.watermark.clone();
            match shared.store.set_slot(&id, &want.to_string(), None, true).await {
                Ok(()) => {
                    acked = want;
                    wait = shared.tuning.ack_retry;
                    continue;
                },
                Err(_) => {
                    wait = (wait * 2).min(Duration::from_secs(5));
                },
            }
            let slept = tokio::time::sleep(wait);
            tokio::pin!(slept);
            tokio::select! {
                _ = token.cancelled() => return,
                _ = shared.stop_token.cancelled() => return,
                _ = &mut slept => {},
            }
        }
    }
}

// ── 测试（Go slots_test.go / slots_stall_test.go 的行为锚直译）─────────────

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use xray_transport::connection::Connection;

    use super::*;
    use crate::{
        config::Config,
        conn::Conn,
        drive::DRIVE_INLINE_LIMIT,
        storage::{Entry, Storage},
    };

    /// Windows 默认计时器分辨率 ~15.6ms：Go runtime 在 Windows 主动
    /// timeBeginPeriod(1)，tokio 不做——快节拍单测（1ms flush tick / 2ms hunt）
    /// 须显式提分辨率，否则节拍全部量化到 15ms（语义正确、节拍塌方）。
    /// 仅本测试进程内生效；timeBeginPeriod 幂等。
    #[cfg(windows)]
    fn boost_timer_resolution() {
        // SAFETY: winmm 时器分辨率提升，进程级全局副作用，测试进程内可接受。
        #[link(name = "winmm")]
        unsafe extern "system" {
            fn timeBeginPeriod(period: u32) -> u32;
        }
        unsafe { timeBeginPeriod(1) };
    }
    #[cfg(not(windows))]
    fn boost_timer_resolution() {}

    /// Go slots_test.go init()：全部测试走快节拍。
    fn fast_tuning() -> SlotTuning {
        boost_timer_resolution();
        SlotTuning {
            hunt_floor: Duration::from_millis(2),
            hunt_ceiling: Duration::from_millis(10),
            tail_min: Duration::from_millis(5),
            tail_max: Duration::from_millis(20),
            ack_retry: Duration::from_millis(2),
            watermark_ttl: Duration::from_millis(2),
            ..DEFAULT_TUNING
        }
    }

    /// 内存槽位后端（Go memSlots 及其测试变形的并集：旋钮按需置位）。
    struct MemSlots {
        state: Mutex<MemState>,
        /// 段帧写恒败（Go failingSlots）。
        fail_segment_writes: bool,
        /// readBody 首次按 id 给旧值（Go staleSlots）。
        stale_body_once: bool,
        /// readDescription 恒定延迟（Go lagSlots）。
        desc_lag: Option<Duration>,
        /// 段帧写恒定延迟（Go lagSlots）。
        write_lag: Option<Duration>,
        /// 写该 id 的 set_slot 挂起直至放行（Go holdSlots）。
        hold_target: Mutex<Option<String>>,
        hold_gate: Notify,
        /// 段帧写的并发峰值记账（Go countSlots）。
        frame_write_delay: Duration,
        write_inflight: AtomicUsize,
        write_peak: AtomicUsize,
        /// 首次 readDescription/readBody 挂起（Go stuckHeadSlots/stuckBodySlots）。
        desc_hang_first: AtomicBool,
        body_hang_first: AtomicBool,
        desc_calls: AtomicUsize,
        body_calls: AtomicUsize,
        /// readBody 恒定延迟并回 1000B（Go timedBodySlots）。
        body_delay: Mutex<Option<Duration>>,
    }

    #[derive(Default)]
    struct MemState {
        next: usize,
        descs: HashMap<String, String>,
        bodies: HashMap<String, Vec<u8>>,
        reads: usize,
        served_stale: HashSet<String>,
        polled: HashSet<String>,
    }

    impl MemSlots {
        fn new() -> Self {
            Self {
                state: Mutex::new(MemState::default()),
                fail_segment_writes: false,
                stale_body_once: false,
                desc_lag: None,
                write_lag: None,
                hold_target: Mutex::new(None),
                hold_gate: Notify::new(),
                frame_write_delay: Duration::ZERO,
                write_inflight: AtomicUsize::new(0),
                write_peak: AtomicUsize::new(0),
                desc_hang_first: AtomicBool::new(false),
                body_hang_first: AtomicBool::new(false),
                desc_calls: AtomicUsize::new(0),
                body_calls: AtomicUsize::new(0),
                body_delay: Mutex::new(None),
            }
        }

        fn release_frame(&self) {
            self.write_inflight.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl SlotStore for MemSlots {
        async fn make_slot(&self, _name: &str, _lane: bool) -> io::Result<String> {
            let mut st = self.state.lock();
            st.next += 1;
            let id = format!("slot-{}", st.next);
            st.descs.insert(id.clone(), String::new());
            Ok(id)
        }

        async fn set_slot(
            &self,
            id: &str,
            description: &str,
            body: Option<&[u8]>,
            _lane: bool,
        ) -> io::Result<()> {
            if self.hold_target.lock().as_deref() == Some(id) {
                self.hold_gate.notified().await;
            }
            let is_frame = decode_slot(description).is_some();
            if is_frame {
                let n = self.write_inflight.fetch_add(1, Ordering::SeqCst) + 1;
                loop {
                    let peak = self.write_peak.load(Ordering::SeqCst);
                    if n <= peak
                        || self
                            .write_peak
                            .compare_exchange(peak, n, Ordering::SeqCst, Ordering::SeqCst)
                            .is_ok()
                    {
                        break;
                    }
                }
                if !self.frame_write_delay.is_zero() {
                    tokio::time::sleep(self.frame_write_delay).await;
                }
                if let Some(lag) = self.write_lag.filter(|lag| !lag.is_zero()) {
                    tokio::time::sleep(lag).await;
                }
            }
            if self.fail_segment_writes
                && decode_slot(description)
                    .is_some_and(|f| f.mode == SLOT_INLINE || f.mode == SLOT_MEDIA)
            {
                self.release_frame();
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "io.ErrUnexpectedEOF"));
            }
            let outcome = {
                let mut st = self.state.lock();
                match st.descs.get_mut(id) {
                    Some(desc) => {
                        *desc = description.to_string();
                        if let Some(body) = body {
                            st.bodies.insert(id.to_string(), body.to_vec());
                        }
                        Ok(())
                    },
                    None => Err(crate::storage::not_found()),
                }
            };
            if is_frame {
                self.release_frame();
            }
            outcome
        }

        async fn read_description(&self, id: &str, _lane: bool) -> io::Result<String> {
            if self.desc_calls.fetch_add(1, Ordering::SeqCst) == 0
                && self.desc_hang_first.load(Ordering::SeqCst)
            {
                std::future::pending::<()>().await;
            }
            if let Some(lag) = self.desc_lag {
                tokio::time::sleep(lag).await;
            }
            let mut st = self.state.lock();
            st.reads += 1;
            st.polled.insert(id.to_string());
            st.descs.get(id).cloned().ok_or_else(crate::storage::not_found)
        }

        async fn read_body(&self, id: &str) -> io::Result<Vec<u8>> {
            if self.body_calls.fetch_add(1, Ordering::SeqCst) == 0
                && self.body_hang_first.load(Ordering::SeqCst)
            {
                std::future::pending::<()>().await;
            }
            if self.stale_body_once {
                let mut st = self.state.lock();
                if st.served_stale.insert(id.to_string()) {
                    return Ok(b"stale".to_vec());
                }
            }
            let delay = *self.body_delay.lock();
            if let Some(delay) = delay.filter(|d| !d.is_zero()) {
                tokio::time::sleep(delay).await;
                return Ok(vec![0u8; 1000]);
            }
            let st = self.state.lock();
            Ok(st.bodies.get(id).cloned().unwrap_or_default())
        }
    }

    /// Storage 收尾面（环槽单测里 Conn 只用 close）。
    #[async_trait]
    impl Storage for MemSlots {
        async fn put(&self, _name: &str, _data: &[u8]) -> io::Result<()> {
            Ok(())
        }

        async fn get(&self, _name: &str) -> io::Result<Vec<u8>> {
            Ok(Vec::new())
        }

        async fn delete(&self, _name: &str) -> io::Result<()> {
            Ok(())
        }

        async fn list(&self, _prefix: &str) -> io::Result<Vec<Entry>> {
            Ok(Vec::new())
        }

        async fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// 恒给 media 帧但 body 校验和不匹配（Go badBodySlots）。
    struct BadBodySlots;

    #[async_trait]
    impl SlotStore for BadBodySlots {
        async fn make_slot(&self, name: &str, _lane: bool) -> io::Result<String> {
            Ok(name.to_string())
        }

        async fn set_slot(
            &self,
            _id: &str,
            _d: &str,
            _b: Option<&[u8]>,
            _l: bool,
        ) -> io::Result<()> {
            Ok(())
        }

        async fn read_description(&self, _id: &str, _lane: bool) -> io::Result<String> {
            Ok(SlotFrame::new(0, SLOT_MEDIA, &[0u8; 64]).encode())
        }

        async fn read_body(&self, _id: &str) -> io::Result<Vec<u8>> {
            Ok(vec![1u8; 64])
        }
    }

    /// 恒空 description（Go emptySlots）：空闲槽，不是失败。
    struct EmptySlots;

    #[async_trait]
    impl SlotStore for EmptySlots {
        async fn make_slot(&self, name: &str, _lane: bool) -> io::Result<String> {
            Ok(name.to_string())
        }

        async fn set_slot(
            &self,
            _id: &str,
            _d: &str,
            _b: Option<&[u8]>,
            _l: bool,
        ) -> io::Result<()> {
            Ok(())
        }

        async fn read_description(&self, _id: &str, _lane: bool) -> io::Result<String> {
            Ok(String::new())
        }

        async fn read_body(&self, _id: &str) -> io::Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    /// 恒 NotFound（过槽消失判停用）。
    struct GoneSlots;

    #[async_trait]
    impl SlotStore for GoneSlots {
        async fn make_slot(&self, name: &str, _lane: bool) -> io::Result<String> {
            Ok(name.to_string())
        }

        async fn set_slot(
            &self,
            _id: &str,
            _d: &str,
            _b: Option<&[u8]>,
            _l: bool,
        ) -> io::Result<()> {
            Ok(())
        }

        async fn read_description(&self, _id: &str, _lane: bool) -> io::Result<String> {
            Err(crate::storage::not_found())
        }

        async fn read_body(&self, _id: &str) -> io::Result<Vec<u8>> {
            Err(crate::storage::not_found())
        }
    }

    fn slot_params(concurrency: u32, segment_bytes: u32) -> Params {
        Params::from_config(&Config {
            segment_bytes,
            flush_interval_ms: 1,
            poll_interval_ms: 1,
            max_poll_interval_ms: 20,
            eager_window_ms: 50,
            concurrency,
            session_ttl_seconds: 60,
            ..Config::default()
        })
    }

    async fn slot_pair(
        store: Arc<MemSlots>,
        concurrency: u32,
        segment_bytes: u32,
    ) -> (Box<dyn Connection>, Box<dyn Connection>) {
        slot_pair_with(store, concurrency, segment_bytes, fast_tuning()).await
    }

    async fn slot_pair_with(
        store: Arc<MemSlots>,
        concurrency: u32,
        segment_bytes: u32,
        tuning: SlotTuning,
    ) -> (Box<dyn Connection>, Box<dyn Connection>) {
        let p = slot_params(concurrency, segment_bytes);
        let ring =
            make_ring(Arc::clone(&store) as Arc<dyn SlotStore>, "session", &p).await.unwrap();
        let store_storage = Arc::clone(&store) as Arc<dyn Storage>;
        let client = Conn::new_slots(
            Arc::clone(&store) as Arc<dyn SlotStore>,
            store_storage,
            ring.up.clone(),
            ring.down.clone(),
            &p,
            tuning,
            None,
            "slots-test-client",
            None,
        );
        let server_store = Arc::clone(&store) as Arc<dyn Storage>;
        let server = Conn::new_slots(
            store,
            server_store,
            ring.down,
            ring.up,
            &p,
            tuning,
            None,
            "slots-test-server",
            None,
        );
        (Box::new(client), Box::new(server))
    }

    fn random_payload(n: usize) -> Vec<u8> {
        let mut payload = Vec::with_capacity(n);
        let mut x: u64 = (n as u64) | 1;
        for _ in 0..n {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            payload.push((x >> 33) as u8);
        }
        payload
    }

    /// 随机分片写（Go writeAll 的写半边）。
    async fn write_pieces(conn: &mut Box<dyn Connection>, mut payload: &[u8]) -> io::Result<()> {
        let mut seed: u64 = 1;
        while !payload.is_empty() {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let n = ((seed >> 33) as usize % (40 << 10)).max(1).min(payload.len());
            conn.write_all(&payload[..n]).await?;
            payload = &payload[n..];
        }
        Ok(())
    }

    async fn read_exact_timed(conn: &mut Box<dyn Connection>, out: &mut [u8]) -> io::Result<()> {
        let read = conn.read_exact(out);
        tokio::time::timeout(Duration::from_secs(30), read).await.expect("read timed out")?;
        Ok(())
    }

    async fn read_to_end_timed(conn: &mut Box<dyn Connection>) -> io::Result<Vec<u8>> {
        let mut got = Vec::new();
        let read = conn.read_to_end(&mut got);
        tokio::time::timeout(Duration::from_secs(30), read).await.expect("read timed out")?;
        Ok(got)
    }

    #[test]
    fn slot_frame_roundtrip_and_corruption() {
        let data = b"hello".to_vec();
        let f = decode_slot(&SlotFrame::new(7, SLOT_INLINE, &data).encode()).unwrap();
        assert_eq!(f.seq, 7);
        assert_eq!(f.mode, SLOT_INLINE);
        assert_eq!(f.data, data);

        let body = random_payload(100);
        let f = decode_slot(&SlotFrame::new(8, SLOT_MEDIA, &body).encode()).unwrap();
        assert_eq!(f.seq, 8);
        assert_eq!(f.mode, SLOT_MEDIA);
        assert!(f.data.is_empty());
        assert!(f.holds(&body));
        assert!(!f.holds(&body[1..]));

        let mut corrupt =
            base64_decode(&SlotFrame::new(1, SLOT_INLINE, &data).encode(), Base64Alphabet::Std)
                .unwrap();
        let last = corrupt.len() - 1;
        corrupt[last] += 1;
        let broken = [
            String::new(),
            "not base64".to_string(),
            SlotFrame::new(1, SLOT_INLINE, &data).encode()[..20].to_string(),
            "WERSVlNMMDE=".to_string(),
            base64_encode(&corrupt, Base64Alphabet::Std, true),
        ];
        for b in broken {
            assert!(decode_slot(&b).is_none(), "{b:?} decoded");
        }
    }

    #[test]
    fn ring_roundtrip_validation_and_first_compat() {
        let r = Ring {
            up: SlotTable {
                slots: vec!["u1".to_string(), "u2".to_string()],
                watermark: "uw".to_string(),
            },
            down: SlotTable { slots: vec!["d1".to_string()], watermark: "dw".to_string() },
            first: b"hello".to_vec(),
        };
        let decoded = decode_ring(&encode_ring(&r)).unwrap();
        assert_eq!(decoded.up.slots, r.up.slots);
        assert_eq!(decoded.up.watermark, "uw");
        assert_eq!(decoded.down.slots, r.down.slots);
        assert_eq!(decoded.first, b"hello");

        // 旧端 announce（无 first 键）干净解码（Go TestSlotRingFirstCompatibility）。
        let decoded = decode_ring(&encode_ring(&Ring { first: Vec::new(), ..r.clone() })).unwrap();
        assert!(decoded.first.is_empty());

        // 非法形态：空水位线 / 超长 id / 空 id / first 非法 base64。
        let missing = serde_json::json!({
            "u": {"s": ["a"], "w": ""},
            "d": {"s": ["b"], "w": "w"},
        });
        assert!(decode_ring(missing.to_string().as_bytes()).is_none());
        let long_id = "x".repeat(MAX_SLOT_ID_LEN + 1);
        let over = serde_json::json!({
            "u": {"s": [long_id], "w": "w"},
            "d": {"s": ["b"], "w": "w"},
        });
        assert!(decode_ring(over.to_string().as_bytes()).is_none());
        let empty_id = serde_json::json!({
            "u": {"s": [""], "w": "w"},
            "d": {"s": ["b"], "w": "w"},
        });
        assert!(decode_ring(empty_id.to_string().as_bytes()).is_none());
        let bad_first = "{\"u\":{\"s\":[\"a\"],\"w\":\"w\"},\"d\":{\"s\":[\"b\"],\"w\":\"w\"},\"first\":\"!!\"}".to_string();
        assert!(decode_ring(bad_first.as_bytes()).is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn make_ring_depth_follows_concurrency() {
        for (set, want) in [(100u32, 100usize), (256, 256), (300, 256)] {
            let p = Params::from_config(&Config { concurrency: set, ..Config::default() });
            let ring = make_ring(Arc::new(MemSlots::new()), "session", &p).await.unwrap();
            assert_eq!(ring.up.slots.len(), want, "concurrency {set} made the wrong depth");
            assert_eq!(ring.down.slots.len(), want);
        }
        // concurrency 0 → 缺省 8；concurrency 1 → 下限 2（Go max(p.concurrency, 2)）。
        let p = Params::from_config(&Config::default());
        let ring = make_ring(Arc::new(MemSlots::new()), "s", &p).await.unwrap();
        assert_eq!(ring.up.slots.len(), 8);
        let p = Params::from_config(&Config { concurrency: 1, ..Config::default() });
        let ring = make_ring(Arc::new(MemSlots::new()), "s", &p).await.unwrap();
        assert_eq!(ring.up.slots.len(), 2);
    }

    #[tokio::test]
    async fn watermark_empty_is_negative_one_and_roundtrips() {
        let store = Arc::new(MemSlots::new());
        let id = store.make_slot("w", true).await.unwrap();
        assert_eq!(read_watermark(store.as_ref(), &id).await.unwrap(), -1);
        store.set_slot(&id, "42", None, true).await.unwrap();
        assert_eq!(read_watermark(store.as_ref(), &id).await.unwrap(), 42);
    }

    /// 双向超圈往返 + 一侧关闭 → 另一侧 EOF（Go TestSlotConnRoundTrip）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slot_conn_roundtrip_both_directions_and_eof() {
        let (mut client, mut server) = slot_pair(Arc::new(MemSlots::new()), 4, 64 << 10).await;
        let up = random_payload(1 << 20);
        let down = random_payload(300 << 10);
        let (up_len, down_len) = (up.len(), down.len());
        let up_for_main = up.clone();
        let down_for_main = down.clone();

        let writer = tokio::spawn(async move {
            write_pieces(&mut client, &up).await.unwrap();
            let mut got = vec![0u8; down_len];
            read_exact_timed(&mut client, &mut got).await.unwrap();
            assert_eq!(got, down, "downlink bytes changed");
            client
        });

        let mut got_up = vec![0u8; up_len];
        read_exact_timed(&mut server, &mut got_up).await.unwrap();
        assert_eq!(got_up, up_for_main, "uplink bytes changed");

        // 下行回写（上行写已在子任务先行）。
        write_pieces(&mut server, &down_for_main).await.unwrap();
        let mut client = writer.await.unwrap();
        client.shutdown().await.unwrap();
        let rest = read_to_end_timed(&mut server).await.unwrap();
        assert!(rest.is_empty(), "closed writer must surface EOF, got {} bytes", rest.len());
        server.shutdown().await.unwrap();
    }

    /// 不读的读者握住写侧而不是丢掉会被覆写的圈（Go TestSlotConnSlowReader）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slot_conn_slow_reader_holds_writer() {
        let (mut client, mut server) = slot_pair(Arc::new(MemSlots::new()), 2, 16 << 10).await;
        let payload = random_payload(400 << 10);
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            write_pieces(&mut client, &payload).await.unwrap();
            client.shutdown().await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        let got = read_to_end_timed(&mut server).await.unwrap();
        assert_eq!(got, expected);
        writer.await.unwrap();
    }

    /// 10 轮 ping-pong < 2s（Go TestSlotLatency）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slot_latency_ping_pong() {
        let (mut client, mut server) = slot_pair(Arc::new(MemSlots::new()), 8, 64 << 10).await;
        let began = Instant::now();
        for _ in 0..10 {
            for round in 0..2 {
                let (writer, reader) = if round == 0 {
                    (&mut client, &mut server)
                } else {
                    (&mut server, &mut client)
                };
                writer.write_all(b"ping").await.unwrap();
                let mut buf = [0u8; 4];
                read_exact_timed(reader, &mut buf).await.unwrap();
            }
        }
        assert!(
            began.elapsed() < Duration::from_secs(2),
            "10 round trips took {:?}",
            began.elapsed()
        );
    }

    /// 写侧失败经 slotErr 即刻浮给读侧，随后的写也失败（Go TestSlotWriterFailure）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slot_writer_failure_surfaces_to_reader_and_writer() {
        let mut store = MemSlots::new();
        store.fail_segment_writes = true;
        let store = Arc::new(store);
        let (mut client, mut server) = slot_pair(store, 2, 16 << 10).await;
        client.write_all(b"lost").await.unwrap();

        let mut buf = [0u8; 10];
        let read = server.read(&mut buf);
        let err = tokio::time::timeout(Duration::from_secs(5), read).await.unwrap().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("could not store segment"),
            "the reader got {msg}, not the failure of the writer"
        );

        let mut failed = false;
        for _ in 0..5000 {
            tokio::time::sleep(Duration::from_millis(1)).await;
            if client.write_all(b"more").await.is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed, "Write did not fail");
    }

    /// 旧 body 读回一次后读者按校验和重取（Go TestSlotStaleBody）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slot_stale_body_recovery() {
        let mut store = MemSlots::new();
        store.stale_body_once = true;
        let store = Arc::new(store);
        let (mut client, mut server) = slot_pair(store, 2, 64 << 10).await;
        let payload = random_payload(200 << 10);
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            write_pieces(&mut client, &payload).await.unwrap();
            client.shutdown().await.unwrap();
        });
        let got = read_to_end_timed(&mut server).await.unwrap();
        assert_eq!(got, expected);
        writer.await.unwrap();
    }

    /// 90KiB 突发全走内联零 body（Go TestSlotBurstSplitsInline）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slot_burst_splits_inline() {
        let store = Arc::new(MemSlots::new());
        let (mut client, mut server) = slot_pair(Arc::clone(&store), 8, 512 << 10).await;
        let payload = random_payload(90 << 10);
        let writer = tokio::spawn(async move {
            write_pieces(&mut client, &payload).await.unwrap();
            client.shutdown().await.unwrap();
        });
        let got = read_to_end_timed(&mut server).await.unwrap();
        assert_eq!(got.len(), 90 << 10);
        writer.await.unwrap();
        let bodies = store.state.lock().bodies.len();
        assert_eq!(bodies, 0, "a burst of 90 KiB went in {bodies} bodies, want none");
    }

    /// 卡死的 body 读被对冲救回（Go TestSlotBodyHedge）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slot_body_hedge_rescues_stuck_read() {
        let store = MemSlots::new();
        store.body_hang_first.store(true, Ordering::SeqCst);
        let store = Arc::new(store);
        let tuning = SlotTuning { body_hedge: Duration::from_millis(50), ..fast_tuning() };
        let (mut client, mut server) = slot_pair_with(store.clone(), 2, 64 << 10, tuning).await;
        let payload = random_payload(200 << 10);
        let payload_len = payload.len();
        let writer = tokio::spawn(async move {
            // 单次全量写：close drain 的 burst 路径（buf > 4×inline）确定性产出
            // >14KiB 的 media 段（随机分片在该参数组合下会全 inline、永不触 body 读）。
            client.write_all(&payload).await.unwrap();
            client.shutdown().await.unwrap();
        });
        let got = read_to_end_timed(&mut server).await.unwrap();
        assert_eq!(got.len(), payload_len);
        writer.await.unwrap();
        assert!(store.body_calls.load(Ordering::SeqCst) >= 2, "the stuck body read was not hedged");
    }

    /// body 读速率学习：慢读不浪发对冲、粘滞读按速对冲（Go TestSlotBodyHedgeRate）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slot_body_hedge_rate_learning() {
        let store = Arc::new(MemSlots::new());
        *store.body_delay.lock() = Some(Duration::from_millis(60));
        let tuning = SlotTuning { body_hedge: Duration::from_millis(20), ..fast_tuning() };
        let p = slot_params(1, 64 << 10);
        let tasks = SessionTasks::new("hedge-rate-test");
        let reader = new_slot_reader(
            Arc::clone(&store) as Arc<dyn SlotStore>,
            SlotTable { slots: vec!["id".to_string()], watermark: "w".to_string() },
            &p,
            tuning,
            tasks,
            None,
        );
        let (_cancel, token) = cancel_pair();

        // 首读建立速率。
        read_body_hedged(&reader.shared, &token, "id", 1000).await.unwrap();
        store.body_calls.store(0, Ordering::SeqCst);
        let began = Instant::now();
        read_body_hedged(&reader.shared, &token, "id", 1000).await.unwrap();
        assert!(
            began.elapsed() >= Duration::from_millis(60),
            "the progressing read returned in {:?}, before its body was ready",
            began.elapsed()
        );
        assert_eq!(store.body_calls.load(Ordering::SeqCst), 1, "a slow-rate read hedged");

        let rate = reader.shared.state.lock().body_rate;
        assert!(rate > 0.0, "no body read rate was learned");

        // 粘滞读按已学速率对冲。
        store.body_hang_first.store(true, Ordering::SeqCst);
        store.body_calls.store(0, Ordering::SeqCst);
        let began = Instant::now();
        read_body_hedged(&reader.shared, &token, "id", 1000).await.unwrap();
        assert!(store.body_calls.load(Ordering::SeqCst) >= 2, "a stuck read was not hedged");
        assert!(began.elapsed() >= Duration::from_millis(60), "the hedge came too late");

        // 全新 reader（无速率）：对冲至少等满 bodyHedge。
        let fresh = Arc::new(MemSlots::new());
        fresh.body_hang_first.store(true, Ordering::SeqCst);
        let fresh_reader = new_slot_reader(
            fresh,
            SlotTable { slots: vec!["id".to_string()], watermark: "w".to_string() },
            &p,
            tuning,
            SessionTasks::new("hedge-fresh-test"),
            None,
        );
        let began = Instant::now();
        read_body_hedged(&fresh_reader.shared, &token, "id", 1000).await.unwrap();
        assert!(
            began.elapsed() >= Duration::from_millis(20),
            "with no learned rate the hedge came after {:?}",
            began.elapsed()
        );
    }

    /// 首次头读挂死被对冲救回（Go TestSlotHeadReadOverlaps）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slot_head_read_overlaps() {
        let store = Arc::new(MemSlots::new());
        store.desc_hang_first.store(true, Ordering::SeqCst);
        let (mut client, mut server) = slot_pair(store, 4, 64 << 10).await;
        for round in 0..2 {
            if round == 0 {
                client.write_all(b"ping").await.unwrap();
                let mut buf = [0u8; 4];
                read_exact_timed(&mut server, &mut buf).await.unwrap();
            } else {
                server.write_all(b"ping").await.unwrap();
                let mut buf = [0u8; 4];
                read_exact_timed(&mut client, &mut buf).await.unwrap();
            }
        }
    }

    /// 读写双迟滞下 8 段突发仍按窗并发（Go TestSlotReadAheadBurst）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slot_read_ahead_burst_beats_the_lag() {
        let mut store = MemSlots::new();
        store.desc_lag = Some(Duration::from_millis(200));
        store.write_lag = Some(Duration::from_millis(600));
        let store = Arc::new(store);
        let tuning = SlotTuning {
            tail_min: Duration::from_millis(150),
            tail_max: Duration::from_millis(800),
            ..fast_tuning()
        };
        let (mut client, mut server) = slot_pair_with(store, 16, 512 << 10, tuning).await;
        let payload = random_payload(8 * SLOT_INLINE_LIMIT);
        let began = Instant::now();
        let writer = tokio::spawn(async move {
            write_pieces(&mut client, &payload).await.unwrap();
        });
        let mut got = vec![0u8; 8 * SLOT_INLINE_LIMIT];
        read_exact_timed(&mut server, &mut got).await.unwrap();
        writer.await.unwrap();
        assert!(
            began.elapsed() < Duration::from_millis(1700),
            "a burst of 8 segments took {:?} to read",
            began.elapsed()
        );
    }

    /// 140KiB 突发零 body（Go TestSlotLargeBurstInline）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slot_large_burst_inline() {
        let store = Arc::new(MemSlots::new());
        let (mut client, mut server) = slot_pair(Arc::clone(&store), 16, 512 << 10).await;
        let payload = random_payload(10 * SLOT_INLINE_LIMIT);
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            write_pieces(&mut client, &payload).await.unwrap();
        });
        let mut got = vec![0u8; 10 * SLOT_INLINE_LIMIT];
        read_exact_timed(&mut server, &mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, expected);
        let bodies = store.state.lock().bodies.len();
        assert_eq!(bodies, 0, "a burst of 140 KiB went in {bodies} bodies, want none");
    }

    /// 深环（32 槽）768KiB 往返（Go TestSlotDeepRingRoundTrip 参数降载版）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slot_deep_ring_roundtrip() {
        let (mut client, mut server) = slot_pair(Arc::new(MemSlots::new()), 32, 64 << 10).await;
        let payload = random_payload(768 << 10);
        let writer = tokio::spawn(async move {
            write_pieces(&mut client, &payload).await.unwrap();
            client.shutdown().await.unwrap();
        });
        let got = read_to_end_timed(&mut server).await.unwrap();
        assert_eq!(got.len(), 768 << 10);
        writer.await.unwrap();
    }

    /// 缺 1 时窗口仍够到 40（Go TestSlotReaderReachesPastWindow）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slot_reader_reaches_past_window() {
        let store = Arc::new(MemSlots::new());
        let p = slot_params(64, 512 << 10);
        let ring =
            make_ring(Arc::clone(&store) as Arc<dyn SlotStore>, "session", &p).await.unwrap();
        let mut reader = new_slot_reader(
            Arc::clone(&store) as Arc<dyn SlotStore>,
            ring.down.clone(),
            &p,
            fast_tuning(),
            SessionTasks::new("reach-test"),
            None,
        );
        async fn next_chunk(reader: &mut SlotReader) -> Vec<u8> {
            let recv = reader.receiver.recv();
            tokio::time::timeout(Duration::from_secs(10), recv)
                .await
                .expect("no segment came")
                .expect("reader channel closed")
        }
        let put = |store: Arc<MemSlots>, seq: i64| {
            let slot = ring.down.slots[(seq as usize) % ring.down.slots.len()].clone();
            async move {
                store
                    .set_slot(
                        &slot,
                        &SlotFrame::new(seq, SLOT_INLINE, &[seq as u8]).encode(),
                        None,
                        false,
                    )
                    .await
                    .unwrap();
            }
        };
        put(Arc::clone(&store), 0).await;
        assert_eq!(next_chunk(&mut reader).await, vec![0]);
        for seq in 2..=40i64 {
            put(Arc::clone(&store), seq).await;
        }
        let last = ring.down.slots[40 % ring.down.slots.len()].clone();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            reader.wake();
            if store.state.lock().polled.contains(&last) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "segment 40 was never asked for while segment 1 was missing"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        put(store, 1).await;
        for seq in 1..=40i64 {
            assert_eq!(
                next_chunk(&mut reader).await,
                vec![seq as u8],
                "segment {seq} came out of order"
            );
        }
    }

    /// 在飞段写峰值 ≤ slotWriteInflight（Go TestSlotWriteInflightCap）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slot_write_inflight_cap() {
        let mut store = MemSlots::new();
        store.frame_write_delay = Duration::from_millis(20);
        let store = Arc::new(store);
        let (mut client, mut server) = slot_pair(store.clone(), 48, 512 << 10).await;
        let payload = random_payload(60 * SLOT_INLINE_LIMIT);
        let writer = tokio::spawn(async move {
            write_pieces(&mut client, &payload).await.unwrap();
        });
        let mut got = vec![0u8; 60 * SLOT_INLINE_LIMIT];
        read_exact_timed(&mut server, &mut got).await.unwrap();
        writer.await.unwrap();
        let peak = store.write_peak.load(Ordering::SeqCst);
        assert!(
            peak <= DEFAULT_TUNING.write_inflight,
            "{peak} segments were written at once, want at most {}",
            DEFAULT_TUNING.write_inflight
        );
    }

    /// 首段经 announce 内嵌先行，圈写放行后余量按序续（Go TestSlotFirstAnnouncement）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slot_first_announcement_primes_the_stream() {
        let store = Arc::new(MemSlots::new());
        let p = Params::from_config(&Config {
            concurrency: 2,
            segment_bytes: 4096,
            flush_interval_ms: 1,
            poll_interval_ms: 1,
            max_poll_interval_ms: 5,
            session_ttl_seconds: 60,
            ..Config::default()
        });
        let ring = make_ring(Arc::clone(&store) as Arc<dyn SlotStore>, "first", &p).await.unwrap();
        *store.hold_target.lock() = Some(ring.up.slots[0].clone());

        let (first_tx, mut first_rx) = tokio::sync::mpsc::channel(1);
        let client_tasks = SessionTasks::new("first-ann-client");
        let writer = new_slot_writer(
            Arc::clone(&store) as Arc<dyn SlotStore>,
            ring.up.clone(),
            &p,
            fast_tuning(),
            client_tasks.clone(),
            Some(first_tx),
        );
        let client_reader = new_slot_reader(
            Arc::clone(&store) as Arc<dyn SlotStore>,
            ring.down.clone(),
            &p,
            fast_tuning(),
            client_tasks.clone(),
            None,
        );
        let mut client = Conn::new_slot_parts(
            writer,
            client_reader,
            Arc::clone(&store) as Arc<dyn Storage>,
            client_tasks,
            None,
        );

        let payload = random_payload(10_000);
        let payload_expected = payload.clone();
        let write_task = tokio::spawn(async move {
            client.write_all(&payload).await.unwrap();
            client.shutdown().await.unwrap();
        });
        let first = tokio::time::timeout(Duration::from_secs(5), first_rx.recv())
            .await
            .expect("the writer never flushed seq 0")
            .expect("first channel closed");
        assert_eq!(first.len(), 4096);

        let mut announced = ring.clone();
        announced.first = first.clone();
        let encoded = encode_ring(&announced);
        assert!(
            encoded.len() <= DRIVE_INLINE_LIMIT,
            "the test announcement is {} bytes, want the inline path",
            encoded.len()
        );
        let decoded = decode_ring(&encoded).unwrap();

        // 服务端写 decoded.Down、读 decoded.Up（Go newSlotConn(decoded.Down, decoded.Up)）。
        let server_tasks = SessionTasks::new("first-ann-server");
        let server_reader = new_slot_reader(
            Arc::clone(&store) as Arc<dyn SlotStore>,
            decoded.up.clone(),
            &p,
            fast_tuning(),
            server_tasks.clone(),
            Some(decoded.first.clone()),
        );
        let server_writer = new_slot_writer(
            Arc::clone(&store) as Arc<dyn SlotStore>,
            decoded.down.clone(),
            &p,
            fast_tuning(),
            server_tasks.clone(),
            None,
        );
        let mut server: Box<dyn Connection> = Box::new(Conn::new_slot_parts(
            server_writer,
            server_reader,
            Arc::clone(&store) as Arc<dyn Storage>,
            server_tasks,
            None,
        ));

        let mut got_first = vec![0u8; first.len()];
        read_exact_timed(&mut server, &mut got_first).await.unwrap();
        assert_eq!(got_first, first, "the primed first bytes changed");

        // 放行槽 0 写，圈写续齐余量。
        *store.hold_target.lock() = None;
        store.hold_gate.notify_waiters();
        let mut rest = vec![0u8; payload_expected.len() - first.len()];
        read_exact_timed(&mut server, &mut rest).await.unwrap();
        let mut whole = got_first;
        whole.extend_from_slice(&rest);
        assert_eq!(whole, payload_expected, "the stream was duplicated or changed");
        write_task.await.unwrap();
    }

    /// 过大的首段塞不进 announce（Go TestSlotFirstAnnouncementTooLarge）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slot_first_announcement_too_large_falls_back() {
        let store = Arc::new(MemSlots::new());
        let p = Params::from_config(&Config {
            concurrency: 2,
            segment_bytes: 256 << 10,
            flush_interval_ms: 1,
            session_ttl_seconds: 60,
            ..Config::default()
        });
        let ring =
            make_ring(Arc::clone(&store) as Arc<dyn SlotStore>, "large-first", &p).await.unwrap();
        let (first_tx, mut first_rx) = tokio::sync::mpsc::channel(1);
        let tasks = SessionTasks::new("large-first-client");
        let writer = new_slot_writer(
            Arc::clone(&store) as Arc<dyn SlotStore>,
            ring.up.clone(),
            &p,
            fast_tuning(),
            tasks.clone(),
            Some(first_tx),
        );
        let reader = new_slot_reader(
            Arc::clone(&store) as Arc<dyn SlotStore>,
            ring.down.clone(),
            &p,
            fast_tuning(),
            tasks.clone(),
            None,
        );
        let mut client = Conn::new_slot_parts(
            writer,
            reader,
            Arc::clone(&store) as Arc<dyn Storage>,
            tasks,
            None,
        );
        let payload = random_payload(300 << 10);
        let write_task = tokio::spawn(async move {
            client.write_all(&payload).await.unwrap();
        });
        write_task.await.unwrap();
        let first = tokio::time::timeout(Duration::from_secs(5), first_rx.recv())
            .await
            .expect("the writer never flushed seq 0")
            .expect("first channel closed");
        assert!(
            first.len() > SLOT_INLINE_LIMIT,
            "the first segment is {} bytes, want a media segment",
            first.len()
        );
        let mut with_first = ring.clone();
        with_first.first = first;
        assert!(encode_ring(&with_first).len() > DRIVE_INLINE_LIMIT);
        // Go TestSlotFirstAnnouncementTooLarge 不 close（无读端的 close 会等满
        // close_grace）；测试目标只有 first 捕获与编码体积，conn 随 task 结束丢弃。
    }

    /// 持续的 body 校验和不匹配在判停内判死（Go TestHeadBodyChecksumMismatchFails）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn head_body_checksum_mismatch_fails() {
        let tuning = SlotTuning {
            stall_timeout: Duration::from_millis(100),
            body_hedge: Duration::from_millis(50),
            ..fast_tuning()
        };
        let p = Params::from_config(&Config {
            concurrency: 1,
            eager_window_ms: 50,
            max_poll_interval_ms: 5,
            ..Config::default()
        });
        let mut reader = new_slot_reader(
            Arc::new(BadBodySlots),
            SlotTable { slots: vec!["id".to_string()], watermark: "w".to_string() },
            &p,
            tuning,
            SessionTasks::new("mismatch-test"),
            None,
        );
        let began = Instant::now();
        let recv = reader.receiver.recv();
        match tokio::time::timeout(Duration::from_secs(3), recv).await {
            Err(_) => panic!("a persistent checksum mismatch retried forever"),
            Ok(None) => {},
            Ok(Some(_)) => panic!("a mismatched body was delivered"),
        }
        assert!(began.elapsed() < Duration::from_secs(3));
        let err = reader.take_err().expect("reader ended without an error").to_string();
        assert!(err.contains("no usable body"), "reader ended with {err}");
    }

    /// 空槽持续空闲而非失败（Go TestEmptySlotStaysIdle）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn empty_slot_stays_idle() {
        let tuning = SlotTuning { stall_timeout: Duration::from_millis(100), ..fast_tuning() };
        let p = Params::from_config(&Config {
            concurrency: 1,
            eager_window_ms: 50,
            max_poll_interval_ms: 5,
            ..Config::default()
        });
        let mut reader = new_slot_reader(
            Arc::new(EmptySlots),
            SlotTable { slots: vec!["id".to_string()], watermark: "w".to_string() },
            &p,
            tuning,
            SessionTasks::new("idle-test"),
            None,
        );
        let recv = reader.receiver.recv();
        let outcome = tokio::time::timeout(Duration::from_millis(300), recv).await;
        assert!(outcome.is_err(), "an empty slot failed the reader instead of staying idle");
    }

    /// 槽位持续消失越过判停 → 读侧报 is gone（B5 验收「过期槽」锚）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gone_slot_fails_reader() {
        let tuning = SlotTuning { gone_timeout: Duration::from_millis(200), ..fast_tuning() };
        let p = Params::from_config(&Config {
            concurrency: 1,
            eager_window_ms: 50,
            max_poll_interval_ms: 5,
            ..Config::default()
        });
        let mut reader = new_slot_reader(
            Arc::new(GoneSlots),
            SlotTable { slots: vec!["id".to_string()], watermark: "w".to_string() },
            &p,
            tuning,
            SessionTasks::new("gone-test"),
            None,
        );
        let began = Instant::now();
        let recv = reader.receiver.recv();
        match tokio::time::timeout(Duration::from_secs(3), recv).await {
            Err(_) => panic!("a gone slot kept the reader alive forever"),
            Ok(None) => {},
            Ok(Some(_)) => panic!("a gone slot delivered data"),
        }
        assert!(began.elapsed() >= Duration::from_millis(200));
        let err = reader.take_err().expect("reader ended without an error").to_string();
        assert!(err.contains("is gone"), "reader ended with {err}");
    }
}

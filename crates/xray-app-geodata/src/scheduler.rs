//! Cron 调度器。
//!
//! 对应 Go `app/geodata/geodata.go` 的 `cron.Cron` + `tasker.AddFunc`。
//! 手写最小 5-field cron parser（分 时 日 月 周），支持 `*` / `数字` / `*/n` / `,` 列表。
//! 执行面 = udf `std_ext::scheduler::Scheduler`（bd bf92）：`after` 延迟排程 +
//! 单驱动线程（condvar park 零自旋）+ 回调 panic 隔离（`panic_count`）+ `close`
//! 优雅关闸；cron 解析与「下一次触发」计算留仓（`parse_cron` /
//! `compute_next_fire_at`）。每条 cron 是一条 after 重臂链：点火 → 重算下一槽
//! → 再 after；cancel 置闸 + 取消当前挂账；活跃链归零自动 close（驱动线程
//! 退出，对齐旧「cancel 即线程退出」），close 后再 schedule 自动重建。
//!
//! ponytail: 不引入 `tokio-cron-scheduler` / `cron` crate。
//! ponytail: cron 最小粒度 1 分钟（对齐 Go robfig/cron 5-field 默认）。

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use parking_lot::Mutex;
use skeleton::clock::SystemClock;
use std_ext::scheduler::{Closed, Scheduler as UdfScheduler, TaskHandle, WorkerHandle};

use crate::{
    error::GeodataError,
    instance::{ScheduleHandle, Scheduler},
};

/// Cron 调度器实例。
///
/// 执行面为共享的 udf [`UdfScheduler`]：首次 `schedule` 惰性起驱动线程
/// （无 cron = 零线程）；cancel 使活跃链归零时 `close` 执行面（驱动线程
/// 退出，对齐旧「cancel 即线程退出」）；close 后再 `schedule` 重建执行面。
pub struct CronScheduler {
    /// udf 执行面：`after` 排程 + 驱动线程 + panic 隔离（`close`/`panic_count`）。
    inner: Mutex<Arc<UdfScheduler>>,
    /// 驱动线程句柄（惰性；Drop = detach，线程退出由 close 语义承担）。
    worker: Mutex<Option<WorkerHandle>>,
    /// 活跃 cron 链计数：归零 → close 执行面。
    active: Arc<AtomicUsize>,
}

impl CronScheduler {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Arc::new(UdfScheduler::new(Arc::new(SystemClock)))),
            worker: Mutex::new(None),
            active: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// 解析 cron 表达式并返回距当前时间下一次触发的 Duration。
    ///
    /// 只认尚未越过的整分界（恰在分界瞬间返回 0）——已越过的分界不补发，
    /// 对齐 Go robfig/cron Next 语义。失败原因：字段数 !=5 / 字段超范围 /
    /// token 无效。
    pub fn next_fire_in(&self, expr: &str) -> Result<Duration, GeodataError> {
        let sched = parse_cron(expr)?;
        compute_next_fire(&sched)
    }

    /// 校验 cron 表达式（只解析，不计算触发时间）。
    ///
    /// 对应 Go `cron.ParseStandard`（infra/conf/geodata.go:52 Build 期校验）。
    pub fn validate(expr: &str) -> Result<(), GeodataError> {
        parse_cron(expr).map(|_| ())
    }

    /// 解析失败返回 `GeodataError::InvalidCron`；与「活跃归零 close」并发时
    /// 执行面已关闸则返回 `ScheduleFailed`（fail-visible，不留死链句柄）。
    pub fn schedule(
        &self,
        expr: &str,
        callback: Box<dyn Fn() + Send + Sync>,
    ) -> Result<ScheduleHandle, GeodataError> {
        let table = parse_cron(expr)?;
        let inner = self.ensure_worker();
        self.active.fetch_add(1, Ordering::SeqCst);
        let task = Arc::new(CronTask {
            inner,
            table,
            cb: Arc::new(callback),
            gate: AtomicBool::new(false),
            current: Mutex::new(None),
            ended: AtomicBool::new(false),
            active: Arc::clone(&self.active),
        });
        match task.arm() {
            Ok(()) => Ok(ScheduleHandle::new(move || task.cancel())),
            Err(_) => Err(GeodataError::ScheduleFailed(
                "udf scheduler closed by concurrent cancel".into(),
            )),
        }
    }

    /// test-only：注册 callback + 不起真实触发（避免 wall-clock 依赖）。
    /// 返回的 handle 可 `fire_for_test` 主动驱动 callback。
    ///
    /// 任务挂到 udf 执行面 `after` 60s 挂账（驱动线程未起则仅入堆不点火
    /// ——与旧「sleep 60s 线程」同形，测试从不依赖它）。
    pub fn schedule_for_test(
        &self,
        expr: &str,
        callback: Box<dyn Fn() + Send + Sync>,
    ) -> Result<TestScheduleHandle, GeodataError> {
        parse_cron(expr)?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let cb: Arc<dyn Fn() + Send + Sync> = Arc::new(callback);
        let cb_task = Arc::clone(&cb);
        let task = self.inner.lock().after(Duration::from_secs(60), move || cb_task()).ok();
        Ok(TestScheduleHandle { cancelled, callback: cb, _task: task })
    }

    /// 取执行面：驱动线程未起则起；已被 close（活跃归零后重启）则重建。
    /// 锁序恒为 inner → worker（`end` 只锁 inner，无反向获取）。
    fn ensure_worker(&self) -> Arc<UdfScheduler> {
        let mut inner = self.inner.lock();
        let mut worker = self.worker.lock();
        if inner.is_closed() || worker.is_none() {
            if inner.is_closed() {
                *inner = Arc::new(UdfScheduler::new(Arc::new(SystemClock)));
            }
            *worker = Some(inner.spawn_worker());
        }
        Arc::clone(&inner)
    }
}

impl Default for CronScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Scheduler trait 适配 —— delegate 到 inherent `schedule` 方法。
impl Scheduler for CronScheduler {
    fn schedule(
        &self,
        expr: &str,
        callback: Box<dyn Fn() + Send + Sync>,
    ) -> Result<ScheduleHandle, GeodataError> {
        Self::schedule(self, expr, callback)
    }
}

/// 一条 cron 的 after 重臂链状态（cancel 线性化点 = `gate`）。
struct CronTask {
    inner: Arc<UdfScheduler>,
    table: CronSchedule,
    cb: Arc<dyn Fn() + Send + Sync>,
    /// cancel 闸：置位后点火不执行、不再重臂。
    gate: AtomicBool,
    /// 当前挂账的 udf 句柄（cancel 时同步取消，免等到期幽灵点火）。
    current: Mutex<Option<TaskHandle>>,
    /// 链终态幂等闸：cancel / 关闸竞态下 `end` 只生效一次。
    ended: AtomicBool,
    /// 共享活跃计数（归零 → close 执行面）。
    active: Arc<AtomicUsize>,
}

impl CronTask {
    /// 重臂：算下一槽 → udf `after` 挂起；点火后自续。执行面已关闸 → Err。
    fn arm(self: &Arc<Self>) -> Result<(), Closed> {
        if self.gate.load(Ordering::Acquire) {
            return Ok(());
        }
        let Ok(delay) = compute_next_fire(&self.table) else {
            // parse 已验证过，实际不可达；防御性终止链（对齐旧线程 `return`）。
            self.end();
            return Ok(());
        };
        let next = Arc::clone(self);
        match self.inner.after(delay, move || {
            if next.gate.load(Ordering::Acquire) {
                return; // cancel 后的幽灵点火：不执行、不重臂
            }
            (next.cb)();
            // 重臂失败只会是执行面已关闸（活跃归零后重启重建，见 ensure_worker），
            // 幽灵链直接终止（end 幂等，不重复计数）。
            let _ = next.arm();
        }) {
            Ok(handle) => {
                *self.current.lock() = Some(handle);
                Ok(())
            },
            Err(err) => {
                self.end();
                Err(err)
            },
        }
    }

    fn cancel(&self) {
        self.gate.store(true, Ordering::Release);
        if let Some(handle) = self.current.lock().take() {
            handle.cancel();
        }
        self.end();
    }

    /// 链终止（cancel / 不可重臂 / 关闸）：活跃归零时 close 执行面
    /// （驱动线程退出，对齐旧「cancel 即线程退出」）。
    fn end(&self) {
        if self.ended.swap(true, Ordering::AcqRel) {
            return;
        }
        if self.active.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.inner.close();
        }
    }
}

/// Test-only handle：可主动驱动 callback，不依赖 wall-clock。
pub struct TestScheduleHandle {
    cancelled: Arc<AtomicBool>,
    callback: Arc<dyn Fn() + Send + Sync>,
    /// udf 执行面挂账句柄：Drop/cancel 同步取消挂账（RAII 兜底）。
    _task: Option<TaskHandle>,
}

impl TestScheduleHandle {
    /// 主动触发一次 callback（忽略 cron 表达式和实际时间）。
    /// cancel 之后调用是 no-op。
    pub fn fire_for_test(&self) {
        if !self.cancelled.load(Ordering::Acquire) {
            (self.callback)();
        }
    }

    /// 取消：等价于 `ScheduleHandle::cancel()`。
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

/// 纯函数核：从给定 `now` 找下一个触发的整分界，返回距 `now` 的 Duration。
///
/// 搜索起点 = **注入 `now` 的整分界**（不读真实挂钟，纯函数可测）。只认尚未
/// 越过的分界（`t >= now`，恰在分界瞬间返回 0）——当前分界已越过不补发，
/// 对齐 Go robfig/cron Next 语义；同时根除旧实现「当前分界命中 → delay=0 →
/// 同分界内连环补发自旋」（bd bf92 换 udf 执行面时修复：udf `after`
/// 链继承旧计算会把自旋变成 condvar 连醒）。
fn compute_next_fire_at(sched: &CronSchedule, now: SystemTime) -> Result<Duration, GeodataError> {
    let dur = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    let mut t = UNIX_EPOCH + Duration::from_secs(secs - secs % 60);
    // cron 周=任意 + 日=任意 → 最长间隔 1 年 1 天，搜索上限取 1 年的分界数。
    for _ in 0..(60 * 24 * 366) {
        if sched.matches(t) {
            if let Ok(delay) = t.duration_since(now) {
                return Ok(delay);
            }
        }
        t += Duration::from_secs(60);
    }
    Err(GeodataError::InvalidCron("no fire within 1 year".into()))
}

fn compute_next_fire(sched: &CronSchedule) -> Result<Duration, GeodataError> {
    compute_next_fire_at(sched, SystemTime::now())
}

/// days since 1970-01-01 → 公历 `(year, month, day)`。
///
/// Howard Hinnant `civil_from_days`（public domain 算法）。Go robfig/cron
/// 按真日历匹配（geodata.go:43-47），day/month 字段必须用真日历而非
/// 30 天月近似（bd issue Xray-core-rust-hxrn）。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (y + i64::from(m <= 2), m, d)
}

/// 解析后的 cron 调度表（5 field: 分 时 日 月 周）。
struct CronSchedule {
    minute: Field,
    hour: Field,
    day: Field,
    month: Field,
    weekday: Field,
}

impl CronSchedule {
    fn matches(&self, t: SystemTime) -> bool {
        let dur = t.duration_since(UNIX_EPOCH).unwrap_or_default();
        let secs = dur.as_secs();
        let minute = ((secs / 60) % 60) as u32;
        let hour = ((secs / 3600) % 24) as u32;
        let days = (secs / 86400) as i64;
        let (_, month, day) = civil_from_days(days);
        let weekday = (days + 4).rem_euclid(7) as u32; // 1970-01-01 是周四，0=周日
        self.minute.contains(minute)
            && self.hour.contains(hour)
            && self.day.contains(day)
            && self.month.contains(month)
            && self.weekday.contains(weekday)
    }
}

/// 字段值集合：`lo..=hi` 的原始值映射到 0-based 位图。
///
/// `lo` 由 [`Field::new`] 持有——day/month 下界为 1，set/contains 必须用
/// 同一偏移，否则错位 1（bd issue Xray-core-rust-hxrn 连带发现）。
struct Field {
    lo: u32,
    values: Vec<bool>,
}

impl Field {
    fn new(lo: u32, hi: u32) -> Self {
        Self { lo, values: vec![false; (hi - lo + 1) as usize] }
    }

    fn index(&self, v: u32) -> Option<usize> {
        let i = v.checked_sub(self.lo)? as usize;
        (i < self.values.len()).then_some(i)
    }

    fn contains(&self, v: u32) -> bool {
        self.index(v).is_some_and(|i| self.values[i])
    }

    fn set(&mut self, v: u32) {
        if let Some(i) = self.index(v) {
            self.values[i] = true;
        }
    }

    fn set_step(&mut self, start: u32, step: u32) {
        let mut v = start;
        while v >= self.lo && (v - self.lo) < self.values.len() as u32 {
            self.values[(v - self.lo) as usize] = true;
            v += step;
        }
    }
}

fn parse_cron(expr: &str) -> Result<CronSchedule, GeodataError> {
    let expr = expr.trim();
    if expr.is_empty() {
        return Err(GeodataError::InvalidCron("empty expression".into()));
    }
    let parts: Vec<&str> = expr.split_whitespace().collect();
    if parts.len() != 5 {
        return Err(GeodataError::InvalidCron(format!("expected 5 fields, got {}", parts.len())));
    }

    let minute = parse_field(parts[0], 0, 59)?;
    let hour = parse_field(parts[1], 0, 23)?;
    let day = parse_field(parts[2], 1, 31)?;
    let month = parse_field(parts[3], 1, 12)?;
    let weekday = parse_field(parts[4], 0, 6)?;

    Ok(CronSchedule { minute, hour, day, month, weekday })
}

fn parse_field(s: &str, lo: u32, hi: u32) -> Result<Field, GeodataError> {
    let mut field = Field::new(lo, hi);
    for part in s.split(',') {
        if let Some((start_s, step_s)) = part.split_once('/') {
            // */n or m-n/n or n
            let step: u32 = step_s
                .parse()
                .map_err(|_| GeodataError::InvalidCron(format!("bad step: {step_s}")))?;
            if step == 0 {
                return Err(GeodataError::InvalidCron("step must be > 0".into()));
            }
            let start = if start_s == "*" {
                lo
            } else {
                let v: u32 = start_s
                    .parse()
                    .map_err(|_| GeodataError::InvalidCron(format!("bad value: {start_s}")))?;
                if v < lo || v > hi {
                    return Err(GeodataError::InvalidCron(format!(
                        "value {v} out of range [{lo},{hi}]"
                    )));
                }
                v
            };
            field.set_step(start, step);
        } else if part == "*" {
            field.set_step(lo, 1);
        } else {
            // 数字 或 数字-数字
            if let Some((a_s, b_s)) = part.split_once('-') {
                let a: u32 = a_s
                    .parse()
                    .map_err(|_| GeodataError::InvalidCron(format!("bad range start: {a_s}")))?;
                let b: u32 = b_s
                    .parse()
                    .map_err(|_| GeodataError::InvalidCron(format!("bad range end: {b_s}")))?;
                if a < lo || b > hi || a > b {
                    return Err(GeodataError::InvalidCron(format!("bad range {a}-{b}")));
                }
                for v in a..=b {
                    field.set(v);
                }
            } else {
                let v: u32 = part
                    .parse()
                    .map_err(|_| GeodataError::InvalidCron(format!("bad value: {part}")))?;
                if v < lo || v > hi {
                    return Err(GeodataError::InvalidCron(format!(
                        "value {v} out of range [{lo},{hi}]"
                    )));
                }
                field.set(v);
            }
        }
    }
    // ponytail: 不检查"全空"（如 "* *"）—— 容忍，反正 caller 用不到。
    Ok(field)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_star_all() {
        let s = parse_cron("* * * * *").unwrap();
        assert!(s.minute.contains(0));
        assert!(s.minute.contains(30));
        assert!(s.minute.contains(59));
        assert!(s.hour.contains(0));
        assert!(s.hour.contains(23));
    }

    #[test]
    fn parse_step() {
        let s = parse_cron("*/15 * * * *").unwrap();
        assert!(s.minute.contains(0));
        assert!(s.minute.contains(15));
        assert!(s.minute.contains(30));
        assert!(s.minute.contains(45));
        assert!(!s.minute.contains(7));
    }

    #[test]
    fn parse_list() {
        let s = parse_cron("0,30 * * * *").unwrap();
        assert!(s.minute.contains(0));
        assert!(s.minute.contains(30));
        assert!(!s.minute.contains(15));
    }

    #[test]
    fn civil_from_days_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19723), (2024, 1, 1));
        assert_eq!(civil_from_days(19782), (2024, 2, 29)); // 闰日
        assert_eq!(civil_from_days(11016), (2000, 2, 29)); // 400 年闰
        assert_eq!(civil_from_days(47541), (2100, 3, 1)); // 世纪非闰次日
        assert_eq!(civil_from_days(20707), (2026, 9, 11));
    }

    /// 独立 oracle 对拍：朴素逐日推进（月份长度表 + 闰年规则）与
    /// civil_from_days 在 ~130 年区间逐日一致。
    #[test]
    fn civil_from_days_matches_naive_calendar_oracle() {
        fn is_leap(y: i64) -> bool {
            (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
        }
        fn days_in_month(y: i64, m: u32) -> u32 {
            match m {
                1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
                4 | 6 | 9 | 11 => 30,
                _ if is_leap(y) => 29,
                _ => 28,
            }
        }
        let (mut y, mut m, mut d) = (1970i64, 1u32, 1u32);
        for days in 0..47_500i64 {
            assert_eq!(civil_from_days(days), (y, m, d), "day offset {days}");
            d += 1;
            if d > days_in_month(y, m) {
                d = 1;
                m += 1;
                if m > 12 {
                    m = 1;
                    y += 1;
                }
            }
        }
    }

    /// bd issue Xray-core-rust-hxrn 反例：2026-09-11（周五）必须按真日历
    /// 落在 day=11/month=9。旧 30 天月近似把它算成 month=7/day=31，
    /// cron `0 0 11 9 *` 永不命中。
    #[test]
    fn cron_matches_real_calendar_dates() {
        let t = |days: i64| UNIX_EPOCH + Duration::from_secs(days as u64 * 86400);
        let s = parse_cron("0 0 11 9 *").unwrap();
        assert!(s.matches(t(20707)), "2026-09-11 must match `0 0 11 9 *`");
        assert!(!s.matches(t(20706)), "2026-09-10 must not match");
        let fri = parse_cron("0 0 * * 5").unwrap();
        assert!(fri.matches(t(20707)), "2026-09-11 is a Friday");
        // 跨月边界：3 月 1 日命中 3 月字段，2 月末日不命中
        let mar = parse_cron("0 0 1 3 *").unwrap();
        assert!(mar.matches(t(20513)), "2026-03-01 must match `0 0 1 3 *`");
        assert!(!mar.matches(t(20512)), "2026-02-28 must not match March");
    }

    #[test]
    fn parse_range() {
        let s = parse_cron("0 9-17 * * *").unwrap();
        assert!(s.hour.contains(9));
        assert!(s.hour.contains(17));
        assert!(!s.hour.contains(8));
        assert!(!s.hour.contains(18));
    }

    #[test]
    fn reject_out_of_range() {
        assert!(parse_cron("60 * * * *").is_err());
        assert!(parse_cron("* 24 * * *").is_err());
        assert!(parse_cron("* * 0 * *").is_err());
        assert!(parse_cron("* * 32 * *").is_err());
        assert!(parse_cron("* * * 0 *").is_err());
        assert!(parse_cron("* * * 13 *").is_err());
        assert!(parse_cron("* * * * 7").is_err());
    }

    #[test]
    fn reject_wrong_field_count() {
        assert!(parse_cron("* * * *").is_err());
        assert!(parse_cron("* * * * * *").is_err());
    }

    // ---- bd bf92：执行面换 udf Scheduler + 严格未来分界语义 ----

    /// 纯函数测试锚点：2026-09-11 12:00:00 UTC + 偏移秒（不依赖真实挂钟）。
    fn at(offset_secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(20_707 * 86_400 + 12 * 3_600 + offset_secs)
    }

    #[test]
    fn next_fire_mid_minute_skips_passed_boundary() {
        let s = parse_cron("* * * * *").unwrap();
        // 12:00:30 → 当前分界 12:00:00 已越过，不补发；下一槽 12:01:00 = 30s。
        // 旧实现此处返回 0（同分界内连环补发自旋）。
        assert_eq!(compute_next_fire_at(&s, at(30)).unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn next_fire_zero_only_at_exact_boundary() {
        let s = parse_cron("* * * * *").unwrap();
        // 恰在分界瞬间（12:00:00.000）→ 立即触发一次（Go robfig Next 同形），
        // 点火后重臂越过该分界，不会连环。
        assert_eq!(compute_next_fire_at(&s, at(0)).unwrap(), Duration::from_secs(0));
    }

    #[test]
    fn next_fire_specific_minute_skips_passed_slot() {
        let s = parse_cron("30 * * * *").unwrap();
        // 12:00:30 → 12:30:00 = 1770s；12:30:30 → 12:30 已越过 → 13:30:00 = 3570s。
        assert_eq!(compute_next_fire_at(&s, at(30)).unwrap(), Duration::from_secs(1770));
        assert_eq!(compute_next_fire_at(&s, at(30 * 60 + 30)).unwrap(), Duration::from_secs(3570));
    }

    #[test]
    fn schedule_restart_after_cancel_rebuilds_execution_face() {
        let sched = CronScheduler::new();
        let h1 = sched.schedule("* * * * *", Box::new(|| {})).expect("first schedule");
        h1.cancel(); // 活跃归零 → close 执行面（驱动线程退出）
        let h2 = sched
            .schedule("*/5 * * * *", Box::new(|| {}))
            .expect("reschedule after close must rebuild execution face");
        h2.cancel();
    }
}

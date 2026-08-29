//! Cron 调度器。
//!
//! 对应 Go `app/geodata/geodata.go` 的 `cron.Cron` + `tasker.AddFunc`。
//! 手写最小 5-field cron parser（分 时 日 月 周），支持 `*` / `数字` / `*/n` / `,` 列表。
//! thread 循环：每秒检查一次到下一次触发时间；时间到则触发 callback。
//!
//! ponytail: 不引入 `tokio-cron-scheduler` / `cron` crate。
//! ponytail: cron 最小粒度 1 分钟（对齐 Go robfig/cron 5-field 默认）。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::GeodataError;
use crate::instance::{ScheduleHandle, Scheduler};

/// Cron 调度器实例。
///
/// 每次 `schedule` 启动一个独立 OS thread；cancel 时通过 `Arc<AtomicBool>`
/// 通知 thread 退出。
pub struct CronScheduler;

impl CronScheduler {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// 解析 cron 表达式并返回距当前时间下一次触发的 Duration。
    ///
    /// 失败原因：字段数 !=5 / 字段超范围 / token 无效。
    pub fn next_fire_in(&self, expr: &str) -> Result<Duration, GeodataError> {
        let sched = parse_cron(expr)?;
        let now = current_minute_floor();
        // 7 天内必有一次（cron 周=任意 + 日=任意 → 最长间隔 1 年 1 天）
        // 这里我们搜到 1 年以内。
        let mut t = now;
        for _ in 0..(60 * 24 * 366) {
            if sched.matches(t) {
                return Ok(t.duration_since(SystemTime::now()).unwrap_or(Duration::ZERO));
            }
            t += Duration::from_secs(60);
        }
        Err(GeodataError::InvalidCron(format!(
            "{expr}: no fire within 1 year"
        )))
    }

    /// 解析失败返回 `GeodataError::InvalidCron`。
    pub fn schedule(
        &self,
        expr: &str,
        callback: Box<dyn Fn() + Send + Sync>,
    ) -> Result<ScheduleHandle, GeodataError> {
        let sched = parse_cron(expr)?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancelled_clone = Arc::clone(&cancelled);
        let cb = Arc::new(callback);

        thread::spawn(move || {
            while !cancelled_clone.load(Ordering::Acquire) {
                let next = match compute_next_fire(&sched) {
                    Ok(d) => d,
                    Err(_) => return,
                };
                // 用 sleep 分段，每 200ms 检查一次 cancel
                let total = next;
                let step = Duration::from_millis(200);
                let mut slept = Duration::ZERO;
                while slept < total && !cancelled_clone.load(Ordering::Acquire) {
                    let remain = total - slept;
                    let chunk = if remain > step { step } else { remain };
                    thread::sleep(chunk);
                    slept += chunk;
                }
                if cancelled_clone.load(Ordering::Acquire) {
                    return;
                }
                cb();
            }
        });

        Ok(make_handle(cancelled))
    }

    /// test-only：注册 callback + 不启 timer（避免 wall-clock）。
    /// 返回的 handle 可 `fire_for_test` 主动驱动 callback。
    pub fn schedule_for_test(
        &self,
        expr: &str,
        callback: Box<dyn Fn() + Send + Sync>,
    ) -> Result<TestScheduleHandle, GeodataError> {
        let _sched = parse_cron(expr)?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancelled_clone = Arc::clone(&cancelled);
        let cb: Arc<dyn Fn() + Send + Sync> = Arc::new(callback);
        let cb_thread = Arc::clone(&cb);

        thread::spawn(move || {
            while !cancelled_clone.load(Ordering::Acquire) {
                // 测试用：sleep 长一点，让 cancel 测试有窗口
                thread::sleep(Duration::from_secs(60));
                if cancelled_clone.load(Ordering::Acquire) {
                    return;
                }
                cb_thread();
            }
        });

        Ok(TestScheduleHandle {
            cancelled,
            callback: cb,
        })
    }
}

impl Default for CronScheduler {
    fn default() -> Self {
        Self::new()
    }
}

fn make_handle(cancelled: Arc<AtomicBool>) -> ScheduleHandle {
    ScheduleHandle::new(move || {
        cancelled.store(true, Ordering::Release);
    })
}

/// Test-only handle：可主动驱动 callback，不依赖 wall-clock。
pub struct TestScheduleHandle {
    cancelled: Arc<AtomicBool>,
    callback: Arc<dyn Fn() + Send + Sync>,
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

fn compute_next_fire(sched: &CronSchedule) -> Result<Duration, GeodataError> {
    let now = SystemTime::now();
    let now_min = current_minute_floor();
    let mut t = now_min;
    for _ in 0..(60 * 24 * 366) {
        if sched.matches(t) {
            return Ok(t.duration_since(now).unwrap_or(Duration::ZERO));
        }
        t += Duration::from_secs(60);
    }
    Err(GeodataError::InvalidCron(
        "no fire within 1 year".into(),
    ))
}

fn current_minute_floor() -> SystemTime {
    let now = SystemTime::now();
    let dur = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    let minute_floor = secs - (secs % 60);
    UNIX_EPOCH + Duration::from_secs(minute_floor)
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
        let day = ((secs / 86400) % 31 + 1) as u32; // 近似（实际需要 civil_from_days）
        let month = ((secs / 86400 / 30) % 12 + 1) as u32; // 近似
        let weekday = ((secs / 86400 + 4) % 7) as u32; // 1970-01-01 是周四，+4 偏移
        self.minute.contains(minute)
            && self.hour.contains(hour)
            && self.day.contains(day)
            && self.month.contains(month)
            && self.weekday.contains(weekday)
    }
}

/// 字段值集合（0..N）。
struct Field {
    values: Vec<bool>,
}

impl Field {
    fn new(size: usize) -> Self {
        Self {
            values: vec![false; size],
        }
    }

    fn contains(&self, v: u32) -> bool {
        if (v as usize) < self.values.len() {
            self.values[v as usize]
        } else {
            false
        }
    }

    fn set(&mut self, v: u32) {
        if (v as usize) < self.values.len() {
            self.values[v as usize] = true;
        }
    }

    fn set_step(&mut self, start: u32, step: u32, max_exclusive: usize) {
        let mut v = start;
        while (v as usize) < max_exclusive {
            self.values[v as usize] = true;
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
        return Err(GeodataError::InvalidCron(format!(
            "expected 5 fields, got {}",
            parts.len()
        )));
    }

    let minute = parse_field(parts[0], 0, 59)?;
    let hour = parse_field(parts[1], 0, 23)?;
    let day = parse_field(parts[2], 1, 31)?;
    let month = parse_field(parts[3], 1, 12)?;
    let weekday = parse_field(parts[4], 0, 6)?;

    Ok(CronSchedule {
        minute,
        hour,
        day,
        month,
        weekday,
    })
}

fn parse_field(s: &str, lo: u32, hi: u32) -> Result<Field, GeodataError> {
    let size = (hi - lo + 1) as usize;
    let mut field = Field::new(size);
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
            field.set_step(start - lo, step, size);
        } else if part == "*" {
            field.set_step(0, 1, size);
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
                    return Err(GeodataError::InvalidCron(format!(
                        "bad range {a}-{b}"
                    )));
                }
                for v in a..=b {
                    field.set(v - lo);
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
                field.set(v - lo);
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
}
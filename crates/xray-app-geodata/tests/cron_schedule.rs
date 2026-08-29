//! CronScheduler 单元测试。
//!
//! 手写最小 cron parser（5-field standard：分 时 日 月 周）+ thread sleep 调度。
//!
//! 注：因 cron 最小粒度 1 分钟（对齐 Go `robfig/cron` 5-field），
//! 真实 timer 触发测试用 `fire_for_test` 主动驱动 callback，避免 wall-clock 依赖。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use xray_app_geodata::CronScheduler;
use xray_app_geodata::instance::Scheduler;

#[test]
fn cron_parses_star_form() {
    let sched = CronScheduler::new();
    let handle = sched
        .schedule("* * * * *", Box::new(|| {}))
        .expect("schedule ok");
    handle.cancel();
}

#[test]
fn cron_next_fire_in_every_minute_is_within_60s() {
    let sched = CronScheduler::new();
    let secs = sched.next_fire_in("* * * * *").expect("parse");
    assert!(
        secs <= Duration::from_secs(60),
        "every-minute next fire should be <= 60s, got {secs:?}"
    );
}

#[test]
fn cron_next_fire_in_step_form() {
    let sched = CronScheduler::new();
    let secs = sched.next_fire_in("*/2 * * * *").expect("parse");
    assert!(secs <= Duration::from_secs(120));
}

#[test]
fn cron_next_fire_in_specific_minute() {
    let sched = CronScheduler::new();
    let secs = sched.next_fire_in("30 * * * *").expect("parse");
    assert!(secs <= Duration::from_secs(3600));
}

#[test]
fn cron_rejects_invalid() {
    let sched = CronScheduler::new();
    assert!(sched.next_fire_in("not a cron").is_err());
    assert!(sched.next_fire_in("60 * * * *").is_err());
    assert!(sched.next_fire_in("* 25 * * *").is_err());
    assert!(sched.next_fire_in("* * * 13 *").is_err());
}

#[test]
fn cron_rejects_empty() {
    let sched = CronScheduler::new();
    assert!(sched.next_fire_in("").is_err());
}

#[test]
fn cron_rejects_too_few_fields() {
    let sched = CronScheduler::new();
    assert!(sched.next_fire_in("* * * *").is_err());
    assert!(sched.next_fire_in("* *").is_err());
}

#[test]
fn cron_schedule_handle_cancel_does_not_panic() {
    let sched = CronScheduler::new();
    let handle = sched
        .schedule("* * * * *", Box::new(|| {}))
        .expect("schedule ok");
    handle.cancel();
}

#[test]
fn cron_fire_for_test_invokes_callback() {
    let sched = CronScheduler::new();
    let counter = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&counter);
    let handle = sched
        .schedule_for_test("* * * * *", Box::new(move || {
            c.fetch_add(1, Ordering::SeqCst);
        }))
        .expect("schedule ok");

    handle.fire_for_test();
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    handle.fire_for_test();
    assert_eq!(counter.load(Ordering::SeqCst), 2);

    handle.cancel();
}

#[test]
fn cron_cancel_stops_callback_invocation() {
    let sched = CronScheduler::new();
    let counter = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&counter);
    let handle = sched
        .schedule_for_test("* * * * *", Box::new(move || {
            c.fetch_add(1, Ordering::SeqCst);
        }))
        .expect("schedule ok");

    handle.fire_for_test();
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    handle.cancel();
    handle.fire_for_test();
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

#[test]
fn cron_real_timer_thread_does_not_panic_on_cancel() {
    let sched = CronScheduler::new();
    let counter = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&counter);
    let handle = sched
        .schedule("* * * * *", Box::new(move || {
            c.fetch_add(1, Ordering::SeqCst);
        }))
        .expect("schedule ok");
    std::thread::sleep(Duration::from_millis(50));
    handle.cancel();
    std::thread::sleep(Duration::from_millis(50));
}
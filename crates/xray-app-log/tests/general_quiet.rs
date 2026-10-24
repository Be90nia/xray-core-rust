//! ③ 未启用 logging 配置：散装 general 消息静默丢弃，且缺装配首次 emit 告警一行
//! （fail-visible，bd 8zs12）。
//!
//! 独立测试二进制（进程内从未创建 `LogInstance`）：global General 槽从未注册，
//! udf `ChannelRegistry` 对未注册通道静默返回——不输出消息/不 panic/不计数；
//! `xray_common::log::log` 内置缺装配首次告警一行（tracing）。

mod common;

use common::capture;

#[test]
fn no_log_features_started_means_silent_with_one_setup_warning() {
    let buf = capture();
    buf.clear();

    xray_common::log::debug("[test] quiet debug");
    xray_common::log::info("[test] quiet info");
    xray_common::log::warning("[test] quiet warn");
    xray_common::log::error("[test] quiet error");

    let text = buf.text();
    // 消息本体仍静默丢弃（udf 装配期纪律不变）。
    assert!(!text.contains("[test] quiet"), "未启用 logging 仍输出消息: {text}");
    // 缺装配首次 emit 告警一行（bd 8zs12），恰一次。
    assert_eq!(text.matches("no sink registered").count(), 1, "缺装配告警应恰一行: {text}");
    // 未注册通道的 emit 连丢弃计数都不加（udf 静默纪律）。
    assert_eq!(xray_common::log::channels().dropped_total(), 0);
}

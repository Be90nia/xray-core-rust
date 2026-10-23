//! ③ 未启用 logging 配置：散装 general 消息无可观测输出且零 panic。
//!
//! 独立测试二进制（进程内从未创建 `LogInstance`）：global General 槽从未注册，
//! udf `ChannelRegistry` 对未注册通道静默返回——不输出/不 panic/不计数。

mod common;

use common::capture;

#[test]
fn no_log_features_started_means_no_output() {
    let buf = capture();
    buf.clear();

    xray_common::log::debug("[test] quiet debug");
    xray_common::log::info("[test] quiet info");
    xray_common::log::warning("[test] quiet warn");
    xray_common::log::error("[test] quiet error");

    let text = buf.text();
    assert!(text.is_empty(), "未启用 logging 仍输出: {text}");
    // 未注册通道的 emit 连丢弃计数都不加（udf 静默纪律）。
    assert_eq!(xray_common::log::channels().dropped_total(), 0);
}

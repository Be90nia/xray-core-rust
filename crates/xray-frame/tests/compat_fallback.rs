//! 面 2 验收（补 G3 的"兜底语义"半边）：**未安装**时全局能力 = 兜底那份
//! （系统钟 + 自持 scope + 默认日志门面）= 迁移前行为。
//!
//! **为何独立成文件**：进程级单槽的"未安装"状态只能在一个**永不安装**的
//! 进程里确定性观测（`tests/compat_caps.rs` 的永久安装用例会改写永久槽）。
//! Cargo 的每个 integration test 文件 = 独立二进制 = 独立进程 → 本文件天然
//! 满足隔离（方案 §2 面 2 "测试隔离"表的"显式注入/隔离"要求）。

// 时钟禁令只约束生产路径；集成测试为独立编译单元，lib.rs 的 cfg_attr(test) 豁免不覆盖，
// 文件顶显式豁免（惯例同 xray-app-router/tests/router_parallel_build.rs）。
#![allow(clippy::disallowed_methods)]

use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use xray_frame::compat::{caps, fallback_caps, installed_caps};

#[test]
fn global_caps_fall_back_to_system_clock() {
    assert!(installed_caps().is_none(), "本进程不安装任何能力集（纯净观测）");
    let fallback = fallback_caps();
    assert!(Arc::ptr_eq(caps().clock(), fallback.clock()), "未安装 → 全局读到兜底那份");
    // 兜底 = 系统钟（挂钟展示面 ≈ 真实现在；`MockClock` 会返回 UNIX_EPOCH 面
    // → 两者可区分）。
    let now = caps().clock().now_system();
    let real = SystemTime::now();
    let delta = now.duration_since(real).or_else(|_| real.duration_since(now)).expect("两时刻可比");
    assert!(delta < Duration::from_secs(1), "兜底时钟 = 系统钟");
}

#[tokio::test]
async fn fallback_scope_can_spawn() {
    // 兜底 scope 自持（不依赖任何安装）→ 站点在 install 前也有托管口。
    let handle = xray_frame::compat::spawn(async { 3u32 }).expect("兜底 scope 可 spawn");
    assert_eq!(handle.join().await.expect("join"), 3);
}

//! bd w5krw（T-8）：UDP dispatch 会话上限的**执行点**必须有回归门。
//!
//! 记账侧（预算门把本档装得下的条数写进 `plan::set_effective_max_udp_sessions`）
//! 已有测试（`xray-core::memory_budget` 的 `udp_sessions_*` 三条）。本文件钉的是
//! **执行点**：`UdpDispatchSession::establish` 读同一份值，超限 **fail-visible 拒建**
//! （返回 `io::Error`，不静默丢包）——`crates/xray-app-dispatcher/src/udp_session.rs`
//! 的 `session_cap()` / `establish()`。
//!
//! 本文件只有一个测试 ⇒ **独占进程**（同 `crates/xray-core/tests/conn_gate_ledger_cap.rs`
//! 的理由）：会话上限与存活会话数都是**进程级全局**（`EFFECTIVE_MAX_UDP_SESSIONS` /
//! `LIVE_SESSIONS`），同进程内并行测试会互相干扰（别的测试可能正占着会话槽）。
//! 独立测试进程 ⇒ 上限值与槽位账本只被本测试触碰，断言确定性可复现。

use std::sync::{Arc, Mutex};

use xray_app_dispatcher::{DispatchHandler, UdpDispatchSession, default::PinFuture};
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_transport::link::Link;

/// 不做任何拨号的 stub handler：会话上限的判定发生在 dispatch **之前**，
/// 故本测试只关心 `establish` 的准入结果。
///
/// 收到的 link 必须**留活**（存进 handler 自身）——它是 duplex 的读半边；一旦
/// 释放，写半边的 `write_all` 会 broken pipe，让 `send_packet` 误报失败。
#[derive(Debug, Default)]
struct NoopHandler {
    link: Mutex<Option<Link>>,
}

impl DispatchHandler for NoopHandler {
    fn tag(&self) -> &str {
        "noop"
    }

    fn dispatch(&self, _dest: &Destination, link: Link) -> PinFuture<()> {
        *self.link.lock().expect("link slot lock") = Some(link);
        Box::pin(async {})
    }
}

fn dest() -> Destination {
    Destination::new(Address::IPv4(std::net::Ipv4Addr::LOCALHOST), Port::new(53), Network::UDP)
}

#[tokio::test]
async fn establish_refuses_when_live_sessions_exceed_effective_cap() {
    // 预算门写入的生效上限 = 1 条（本测试自造：执行点读的就是这个全局）。
    assert_eq!(
        xray_frame::budget::plan::set_effective_max_udp_sessions(1),
        1,
        "写 1 必须原样生效（执行点读同一份值）"
    );

    let mut first = UdpDispatchSession::new(Arc::new(NoopHandler::default()));
    first.send_packet(&dest(), b"first").await.expect("第 1 条会话必须在上限内建立");

    // 第 2 条超出生效上限 ⇒ fail-visible 拒建（不是静默丢包）。
    let mut second = UdpDispatchSession::new(Arc::new(NoopHandler::default()));
    let err = second
        .send_packet(&dest(), b"second")
        .await
        .expect_err("超出生效上限必须拒建（fail-visible）");
    let msg = err.to_string();
    assert!(msg.contains("exceeded"), "错误必须点名超限：{msg}");
    assert!(msg.contains('1'), "错误必须带上生效上限值：{msg}");

    // 第 1 条会话释放后槽位归还 ⇒ 新会话可再建立（不泄漏计数）。
    drop(first);
    let mut third = UdpDispatchSession::new(Arc::new(NoopHandler::default()));
    third
        .send_packet(&dest(), b"third")
        .await
        .expect("槽位归还后必须能再建会话（LIVE_SESSIONS 记账不得泄漏）");
}

//! 审计探针（2026-11-06 perf-memory 轮，PM-01/PM-03 取证）：xdns client 的
//! **任务生命周期**实测。
//!
//! # 被测对象
//!
//! `crates/xray-transport/src/finalmask/xdns/client.rs` 的 `XdnsConnClient`：
//! 构造时 `tokio::spawn` 三个泵任务（`recv_loop` / `doh_recv_loop` / `send_loop`，
//! `client.rs:167/178/183`，句柄全丢弃），且该类型**无 `impl Drop`**、
//! `closed: Arc<AtomicBool>` **全仓无 `store(true)`**（xdns 目录 grep 0 命中）。
//!
//! # 预期（缺陷指纹）
//!
//! | 阶段 | 存活任务数 |
//! |---|---|
//! | baseline（未 wrap） | `base` |
//! | wrap 后（UDP resolver） | `base + 3`（三个泵任务） |
//! | **drop 后** | **`base + 1`**（`recv_loop` 永不退出）——正常实现应回到 `base` |
//!
//! `send_loop` 能退（`write_tx` drop ⇒ `write_rx.recv()` 返 `None` ⇒ `return`，
//! `client.rs:426-431`）；`doh_recv_loop` 在**无 DoH resolver**时也能退
//! （`doh_tx` 在构造末尾被显式 `drop`，`client.rs:144`）。
//! 唯独 `recv_loop`：它的唯一"出口"是 `inner.recv_from()` 返回 `Err`，
//! 但那里写的是 `continue` 不是 `return`（`client.rs:263-266`）⇒ 它永远阻塞在
//! recv 上，**并且持有 `inner: Arc<dyn UdpIo>`** ⇒ 底层 UDP socket fd 也不释放。
//!
//! # 为什么这条探针有价值
//!
//! 静态推导（PM-03 的 E2 链）说「drop ⇒ 任务与 fd 永久泄漏」；本探针把它变成
//! **可复现的数字**：tokio runtime 的 `num_alive_tasks()` 直接读存活任务数。
//!
//! # 跑法
//!
//! ```text
//! cargo test -p xray-transport --test audit_perfmemaudit_probe -- --nocapture
//! ```
//!
//! ⚠️ **本测试断言的是当前（缺陷）行为**：修复泄漏后本断言会红 —— 那是
//! 「修复生效」的信号，届时应把断言改成 `after_drop == base`（反向自检锚点）。

use std::time::Duration;

use xray_transport::finalmask::build_udpmask_manager_from_json;

/// 存活任务数（tokio runtime 指标；`Handle::metrics()` 返回 owned `RuntimeMetrics`）。
fn alive_tasks() -> usize {
    tokio::runtime::Handle::current().metrics().num_alive_tasks()
}

/// 让 spawn 出去的任务真正被调度起来（并给退出留时间）。
async fn settle() {
    tokio::time::sleep(Duration::from_millis(120)).await;
}

/// xdns 客户端（UDP resolver 形态）：drop 后应只剩 `recv_loop` 存活。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xdns_client_drop_leaves_recv_task_alive() {
    let mgr = build_udpmask_manager_from_json(Some(&serde_json::json!({
        "udp": [{
            "type": "xdns",
            "settings": {
                "domains": [{ "names": ["example.com"] }],
                "resolvers": [{ "addrs": ["127.0.0.1:53"] }]
            }
        }]
    })))
    .expect("xdns manager 必须可构造");

    // 真 UDP socket（`impl UdpIo for tokio::net::UdpSocket` 已存在，finalmask/mod.rs:77）
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind");

    let base = alive_tasks();
    let wrapped = mgr.wrap_packet_conn_client(Box::new(sock)).expect("wrap 必须成功");
    settle().await;
    let after_wrap = alive_tasks();
    drop(wrapped);
    settle().await;
    let after_drop = alive_tasks();

    #[allow(clippy::print_stdout)]
    {
        println!(
            "xdns(udp resolver) alive_tasks: base={base} after_wrap={after_wrap} after_drop={after_drop} \
             (leaked={})",
            after_drop.saturating_sub(base)
        );
    }

    assert!(after_wrap > base, "wrap 必须起 pump 任务（after_wrap={after_wrap} base={base}）");
    assert!(
        after_drop > base,
        "PM-03 缺陷指纹：drop 后仍有 pump 任务存活（recv_loop 持 inner ⇒ 永不退出 ⇒ \
         底层 UDP socket fd 也不释放）。after_drop={after_drop} base={base} —— \
         本断言在修复后应改为 after_drop == base"
    );
}

/// xdns 客户端（**DoH resolver** 形态）：`worker` 缺省 32 ⇒ 32 个 DoH worker 任务
/// + 3 个泵任务；且 `doh_recv_loop` 因 worker 持 `resp_tx` 也无法退出。
///
/// ⇒ drop 后应存活 `base + 1(recv_loop) + 1(doh_recv_loop) + worker(32)` = `base + 34`。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xdns_client_drop_leaks_doh_worker_tasks() {
    let mgr = build_udpmask_manager_from_json(Some(&serde_json::json!({
        "udp": [{
            "type": "xdns",
            "settings": {
                "domains": [{ "names": ["example.com"] }],
                // Go 形态 https resolver（worker 缺省 32，见 infra/conf/transport_finalmask.go:860-862）
                "resolvers": [{ "addrs": ["https://127.0.0.1:8443/dns-query"] }]
            }
        }]
    })))
    .expect("xdns manager 必须可构造");

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind");

    let base = alive_tasks();
    let wrapped = mgr.wrap_packet_conn_client(Box::new(sock)).expect("wrap 必须成功");
    settle().await;
    let after_wrap = alive_tasks();
    drop(wrapped);
    settle().await;
    let after_drop = alive_tasks();

    #[allow(clippy::print_stdout)]
    {
        println!(
            "xdns(doh resolver) alive_tasks: base={base} after_wrap={after_wrap} \
             after_drop={after_drop} (leaked={})",
            after_drop.saturating_sub(base)
        );
    }

    assert!(
        after_wrap >= base + 32,
        "DoH resolver 必须起 worker(缺省 32) 个任务（after_wrap={after_wrap} base={base}）"
    );
    assert!(
        after_drop > base + 1,
        "PM-03 缺陷指纹：drop 后 DoH worker 任务（worker=32）全部存活 —— \
         `tx`（在 `Arc<ClientState>` 里，被永不退出的 recv_loop 持有）永不 drop ⇒ \
         worker 的 `rx.recv()` 永不返 None（doh.rs:483）。after_drop={after_drop} base={base}"
    );
}

//! jf1wv：UDP TPROXY 收包链最小断言（Linux-only 生产数据面，此前整条链零断言）。
//!
//! ## 背景：本套件曾抓到并倒逼修复一个 P0（hub.rs 收包循环热自旋）
//!
//! 旧 `start_recv_loop_tproxy_linux` 是 `readable().await` + 借 `SockRef` 直调
//! `recvmsg`，不经 `try_io` 清 readiness 缓存 → 收到首包后每轮恒 Ready + 恒
//! WouldBlock = 热自旋。真 Linux root 实测：`/usr/bin/time` 下 wall 10s 烧
//! `user=8.09 sys=1.90`（整核 100%），且整个测试进程挂死；多线程生产 runtime
//! 不挂死但持续烧满一核（dokodemo UDP `followRedirect` 是 Linux VPS 唯一的
//! UDP 透明代理路径）。修复：`try_io(READABLE, recvmsg)` + WouldBlock 后才
//! `readable().await`（hub.rs，PM 专项授权）。
//!
//! ## 现在的断言面（5 条全启用，特权+非特权两种身份各跑一遍才算覆盖）
//!
//! 1. `tproxy_bind_is_privilege_gated_and_binds_requested_port`——特权 bind 成功
//!    且绑到请求地址；非特权必须 `PermissionDenied`（syscall 裁决，非编译裁剪）；
//! 2. `plain_hub_roundtrip_delivers_packet`——不开 TPROXY 的对照组：hub 本体能 收发、`target ==
//!    None`（开关的判别力）；
//! 3. `tproxy_v4_chain_reports_original_destination`——`IP_RECVORIGDSTADDR` cmsg →
//!    `parse_orig_dst_from_cmsg` v4 臂，`target == Some(绑定地址)`；
//! 4. `tproxy_v6_chain_reports_original_destination`——v6 臂
//!    （`IPV6_TRANSPARENT`/`IPV6_RECVORIGDSTADDR`/`is_ipv6_origdst_cmsg`）；
//! 5. `tproxy_recv_loop_must_not_starve_current_thread_runtime`——首包之后循环 必须让出
//!    runtime（current_thread 上 `sleep(20ms)` ≤200ms 必须醒）。 这条就是热自旋的**回归门**：把
//!    hub.rs 改回旧形态，它挂死（CI 超时即红）。
//!
//! 特权态：`sudo -E cargo test -p xray-transport --test udp_tproxy_chain`；
//! 非特权态：`setpriv --reuid=65534 --regid=65534 --clear-groups <test-bin>`。

#![cfg(target_os = "linux")]

use std::{io, net::SocketAddr, time::Duration};

use xray_transport::udp::hub::{HubOption, ReceiveOriginalDestination, UdpHub, UdpPacket};

const RECV_TIMEOUT: Duration = Duration::from_secs(2);
const PROBE: &[u8] = b"tproxy-probe";

fn options(recv_orig_dest: bool) -> Vec<Box<dyn HubOption>> {
    vec![Box::new(ReceiveOriginalDestination(recv_orig_dest))]
}

/// 非特权（CI runner 常态）的唯一合法失败 = 权限门；不是权限门就还有别的缺陷。
fn assert_unprivileged_gate(err: io::Error) {
    assert_eq!(
        err.kind(),
        io::ErrorKind::PermissionDenied,
        "非特权下 TPROXY bind 必须因 IP_TRANSPARENT 权限被拒: {err}"
    );
}

/// TPROXY bind 面（**可跑**）：特权 → 成功且 `local_addr` 可读；非特权 → `PermissionDenied`。
///
/// 覆盖 `bind_udp_tproxy_linux` 的 `IP_TRANSPARENT` + `IP_RECVORIGDSTADDR` + `bind`
/// 三个 setopt/bind 点，且**不投递任何数据**（避开收包循环的热自旋，见文件头）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tproxy_bind_is_privilege_gated_and_binds_requested_addr() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    match UdpHub::listen(addr, &options(true), None).await {
        Ok(hub) => {
            let bound = hub.local_addr().expect("TPROXY socket 必须有 local_addr");
            assert_eq!(bound.ip(), addr.ip(), "IP_TRANSPARENT 必须绑到请求的地址");
            assert_ne!(bound.port(), 0, "端口 0 必须由内核分配成真实端口");
            hub.close().expect("close 必须可调（幂等闸）");
        },
        Err(e) => assert_unprivileged_gate(e),
    }
}

/// 对照组（**可跑**）：不开 `ReceiveOriginalDestination` 时走普通 `recv_from` 循环，
/// 同一形态必须能收发（证明 hub 本体没坏；也证明上面的失败不是夹具引起的）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_hub_roundtrip_delivers_packet() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let hub = UdpHub::listen(addr, &options(false), None).await.expect("普通 bind 不得需要特权");
    let bound = hub.local_addr().expect("local_addr");
    let (mut rx, _shared) = hub.split();

    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("sender bind");
    let sender_addr = sender.local_addr().expect("sender addr");
    sender.send_to(PROBE, bound).await.expect("probe send");

    let pkt = tokio::time::timeout(RECV_TIMEOUT, rx.recv())
        .await
        .expect("普通 hub 收包超时（recv 链断）")
        .expect("hub channel 未关闭");
    assert_eq!(pkt.payload, PROBE);
    assert_eq!(pkt.source, sender_addr, "source 取自 recv_from 的 from 地址");
    assert_eq!(pkt.target, None, "未开 ReceiveOriginalDestination 时不得报原始目标");
}

/// 起 TPROXY hub → 打一发 → 收一发。`Err` 只可能来自 bind（非特权 = PermissionDenied）。
async fn tproxy_roundtrip(
    hub_addr: SocketAddr,
    sender_bind: &str,
) -> io::Result<(UdpPacket, SocketAddr)> {
    let hub = UdpHub::listen(hub_addr, &options(true), None).await?;
    let bound = hub.local_addr()?;
    let (mut rx, _shared) = hub.split();

    let sender = tokio::net::UdpSocket::bind(sender_bind).await.expect("sender bind");
    let sender_addr = sender.local_addr().expect("sender addr");
    sender.send_to(PROBE, bound).await.expect("probe send");

    let pkt = tokio::time::timeout(RECV_TIMEOUT, rx.recv())
        .await
        .expect("TPROXY 收包链必须在墙钟上限内交付一个包（超时 = recvmsg 链断）")
        .expect("hub channel 未关闭");
    assert_eq!(pkt.source, sender_addr, "source 取自 recvmsg 的 msg_name");
    Ok((pkt, bound))
}

/// v4 链断言（**修复后启用**）：`IP_RECVORIGDSTADDR` cmsg 必须解析出原始目标。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tproxy_v4_chain_reports_original_destination() {
    let (pkt, bound) =
        match tproxy_roundtrip(SocketAddr::from(([127, 0, 0, 1], 0)), "127.0.0.1:0").await {
            Ok(v) => v,
            Err(e) => return assert_unprivileged_gate(e),
        };
    assert_eq!(pkt.payload, PROBE, "payload 必须原样交付");
    assert_eq!(
        pkt.target,
        Some(bound),
        "IP_RECVORIGDSTADDR cmsg 必须解析出原始目标（= 本 socket 绑定地址）"
    );
}

/// v6 臂（**修复后启用**）：`IPV6_TRANSPARENT` + `IPV6_RECVORIGDSTADDR` +
/// `is_ipv6_origdst_cmsg` 的 v6 分支。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tproxy_v6_chain_reports_original_destination() {
    let addr = SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 1], 0));
    let (pkt, bound) = match tproxy_roundtrip(addr, "[::1]:0").await {
        Ok(v) => v,
        Err(e) => return assert_unprivileged_gate(e),
    };
    assert_eq!(pkt.payload, PROBE);
    assert!(bound.ip().is_ipv6(), "v6 hub 必须绑在 ::1，实际 {bound}");
    assert_eq!(pkt.target, Some(bound), "v6 cmsg 必须解析出原始目标");
}

/// 缺陷取证（**修复后启用**）：首包之后收包循环必须让出 runtime。
///
/// 单线程 runtime 上若循环热自旋，这次 `sleep` 永远不醒（本用例修复前挂死）——
/// 变成「当前线程被饿死」的**可断言**形式，而不只是「某个用例挂住」。
#[tokio::test]
async fn tproxy_recv_loop_must_not_starve_current_thread_runtime() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let hub = match UdpHub::listen(addr, &options(true), None).await {
        Ok(hub) => hub,
        Err(e) => return assert_unprivileged_gate(e),
    };
    let bound = hub.local_addr().expect("local_addr");
    let (mut rx, _shared) = hub.split();
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("sender bind");
    sender.send_to(PROBE, bound).await.expect("probe send");
    let _ = tokio::time::timeout(RECV_TIMEOUT, rx.recv()).await.expect("首包必须交付");

    tokio::time::timeout(Duration::from_millis(200), tokio::time::sleep(Duration::from_millis(20)))
        .await
        .expect("收包循环让出 runtime 失败（热自旋：readiness 未清除）——产品缺陷");
}

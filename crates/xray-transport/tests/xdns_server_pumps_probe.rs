//! bd quznp / ej1nn 探针：xdns **服务端** recv 错误分类与泵生命周期。
//!
//! # 被测对象
//!
//! `crates/xray-transport/src/finalmask/xdns/server.rs` 的 `XdnsConnServer`。
//!
//! | 测试 | 断言的东西 | 反向自检（把修复改回去 ⇒ 必红） |
//! |---|---|---|
//! | `connreset_keeps_recv_pump_alive` | `ConnectionReset` 是噪音，泵继续处理后续报文 | 该分支改成 `return` ⇒ 后续报文永不被处理 |
//! | `fatal_error_stops_recv_pump` | 其它错误 ⇒ 退泵（不再紧循环） | 改回无分类 `Err(_) => continue` ⇒ 继续吃脚本里那一条报文 |
//! | `windows_bind_suppresses_icmp_unreachable` | L1 socket 层：关掉 ICMP unreachable 上报 | 去掉 `bind_udp_no_connreset` 的 WSAIoctl ⇒ 对照组/实验组一致 |
//! | `drop_releases_pumps_and_port` | conn drop ⇒ 泵全退 + UDP fd 释放 | 三泵改回 `spawn_detached` ⇒ 存活任务数不回落、端口不可重绑 |
//!
//! 「泵存活」的正向信号用**内层 `send_to` 被调用**（`dr` 通道的即时错误响应）：
//! 脚本交出一个 opcode=1 的 DNS 报文 ⇒ 服务端 `server_read` 走 `decref` ⇒
//! `dr_loop` 把它写回内层。这样无需构造合法 xdns 查询名（base32 域名）就能观测
//! 「recv 泵是否还活着」。
//!
//! # 跑法
//!
//! ```text
//! cargo test -p xray-transport --test xdns_server_pumps_probe -- --nocapture
//! ```

use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use xray_transport::finalmask::{UdpIo, UdpmaskManager, build_udpmask_manager_from_json};

/// 可编排的内层 `UdpIo`。
///
/// `recv_from` 的第 n 次调用：`n < errors.len()` ⇒ 交出 `errors[n]`；`n ==
/// errors.len()` ⇒ 交出一个 opcode=1 的 DNS 报文；再往后永不就绪（等价空闲
/// socket）。`send_to` 只记账（服务端 `dr` 通道的落点）。
#[derive(Clone)]
struct ScriptedInner {
    errors: Arc<Vec<io::ErrorKind>>,
    calls: Arc<AtomicUsize>,
    answers: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl ScriptedInner {
    fn new(errors: Vec<io::ErrorKind>) -> Self {
        Self {
            errors: Arc::new(errors),
            calls: Arc::new(AtomicUsize::new(0)),
            answers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn answered(&self) -> bool {
        !self.answers.lock().expect("answers poisoned").is_empty()
    }
}

/// 最小 DNS 报文：`opcode = 1`、所有 count 为 0 ⇒ `server_read` 的
/// `opcode != 0` 分支（`decref` 即时错误响应），与 xdns 域名/分片语义无关。
fn opcode1_query() -> Vec<u8> {
    let mut q = vec![0u8; 12];
    q[0..2].copy_from_slice(&0x1234u16.to_be_bytes()); // id
    q[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // QR=0 + OPCODE=1
    q
}

#[async_trait::async_trait]
impl UdpIo for ScriptedInner {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(kind) = self.errors.get(n) {
            return Err(io::Error::from(*kind));
        }
        if n == self.errors.len() {
            let q = opcode1_query();
            buf[..q.len()].copy_from_slice(&q);
            return Ok((q.len(), SocketAddr::from(([127, 0, 0, 1], 5353))));
        }
        std::future::pending().await
    }

    async fn send_to(&self, buf: &[u8], _addr: SocketAddr) -> io::Result<usize> {
        self.answers.lock().expect("answers poisoned").push(buf.to_vec());
        Ok(buf.len())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::from(([127, 0, 0, 1], 5353)))
    }
}

/// 服务端侧 xdns 掩码管理器（单域）。
fn server_mgr() -> UdpmaskManager {
    build_udpmask_manager_from_json(Some(&serde_json::json!({
        "udp": [{ "type": "xdns", "settings": { "domains": [{ "names": ["example.com"] }] } }]
    })))
    .expect("xdns manager 必须可构造")
}

fn wrap(inner: &ScriptedInner) -> Box<dyn UdpIo> {
    server_mgr().wrap_packet_conn_server(Box::new(inner.clone())).expect("wrap 必须成功")
}

/// 轮询内层是否收到应答（给泵留调度时间，最多 `ms` 毫秒）。
async fn answered_within(inner: &ScriptedInner, ms: u64) -> bool {
    // 时钟唯一源（禁裸 `Instant::now`）：`compat::clock()` = 进程级 Clock 句柄。
    let clock = xray_frame::compat::clock();
    let deadline = clock.now_instant() + Duration::from_millis(ms);
    while clock.now_instant() < deadline {
        if inner.answered() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    inner.answered()
}

/// 存活任务数（tokio runtime 指标）。
fn alive_tasks() -> usize {
    tokio::runtime::Handle::current().metrics().num_alive_tasks()
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(200)).await;
}

// ===== quznp L2：错误分类 =====

/// `ConnectionReset` 是噪音（Windows ICMP unreachable 的旧投递路径）⇒ 泵必须活着
/// 继续处理后续报文，而不是退泵（也不能紧循环）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connreset_keeps_recv_pump_alive() {
    let inner = ScriptedInner::new(vec![io::ErrorKind::ConnectionReset; 3]);
    let _server = wrap(&inner);
    assert!(
        answered_within(&inner, 2000).await,
        "3 次 ConnectionReset 之后 recv 泵必须仍存活并处理脚本里那条报文\
         （calls={}）",
        inner.calls()
    );
}

/// 其它错误 ⇒ 退泵（对齐 Go `server.go:255-260` 的 `return`）。
///
/// 旧代码无分类 `Err(_) => continue` ⇒ 泵会继续把脚本里那条报文吃掉 ⇒ 本测试红。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fatal_error_stops_recv_pump() {
    let inner = ScriptedInner::new(vec![io::ErrorKind::Other]);
    let _server = wrap(&inner);
    settle().await;
    assert!(
        !inner.answered(),
        "致命错误后 recv 泵必须停止，不得再处理后续报文（旧 `Err(_) => continue` 会吃掉它）"
    );
    assert_eq!(
        inner.calls(),
        1,
        "recv 泵必须在第一次致命错误后返回 ⇒ recv_from 只被调用 1 次（calls={}）",
        inner.calls()
    );
}

// ===== quznp L1：Windows socket 层根治 =====

/// 往一个刚关闭的本地 UDP 端口发一包（触发 ICMP Port Unreachable），返回下一次
/// `recv_from` 在 500ms 内交出的错误；超时（= 上报已关闭）返回 `None`。
#[cfg(windows)]
async fn icmp_unreachable_error(sock: &tokio::net::UdpSocket) -> Option<io::Error> {
    let dead = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind dead");
    let addr = dead.local_addr().expect("dead addr");
    drop(dead); // 端口无人监听 ⇒ 后续 ICMP Port Unreachable
    sock.send_to(b"x", addr).await.expect("send_to");
    let mut buf = [0u8; 32];
    match tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await {
        Ok(Err(e)) => Some(e),
        // 收到数据报不可能（本端从未被寻址）⇒ 视作"没有错误"即可
        Ok(Ok(_)) | Err(_) => None,
    }
}

/// L1：`bind_udp_no_connreset` 之后 `recv_from` 不再交出 `WSAECONNRESET(10054)`。
///
/// 对照组用裸 `UdpSocket::bind` 证明本机确实会投递这个错误（否则探针无意义）。
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn windows_bind_suppresses_icmp_unreachable() {
    let plain = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let plain_err = icmp_unreachable_error(&plain)
        .await
        .expect("对照组：裸 bind 的 recv_from 必须交回 10054（否则探针失效，本机不复现）");
    assert_eq!(
        plain_err.kind(),
        io::ErrorKind::ConnectionReset,
        "对照组：ICMP Port Unreachable 必须以 ConnectionReset 投递"
    );

    let fixed = xray_transport::udp::bind_udp_no_connreset("127.0.0.1:0").await.expect("bind");
    assert!(
        icmp_unreachable_error(&fixed).await.is_none(),
        "SIO_UDP_CONNRESET/SIO_UDP_NETRESET 生效后 recv_from 不得再交出 10054"
    );
}

// ===== ej1nn：泵生命周期 =====

/// conn drop ⇒ 四个循环全退 + 底层 UDP fd 释放（原端口可立即重新 bind）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drop_releases_pumps_and_port() {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let port = sock.local_addr().expect("addr").port();
    let base = alive_tasks();

    let server = server_mgr().wrap_packet_conn_server(Box::new(sock)).expect("wrap 必须成功");
    settle().await;
    let after_wrap = alive_tasks();
    assert!(
        after_wrap >= base + 4,
        "wrap 必须起 4 个循环任务（recv/send/dr/maintain）：after_wrap={after_wrap} base={base}"
    );

    drop(server);
    settle().await;
    let after_drop = alive_tasks();
    assert_eq!(
        after_drop, base,
        "conn drop 后四个循环必须全部结束（三泵走 spawn_detached ⇒ 存活任务不回落）"
    );

    tokio::net::UdpSocket::bind(("127.0.0.1", port))
        .await
        .expect("conn drop 后底层 UDP fd 必须已释放（同端口可重新 bind）");
}

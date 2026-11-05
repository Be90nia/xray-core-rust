//! bd r5j96 运行时取证：缺省路径**不下发** `setsockopt(SO_RCVBUF)`（两平台同语义）。
//!
//! ## 为什么用「对照差值」而不是绝对阈值
//!
//! `SO_RCVBUF` 的回读值是**平台记账口径**下的数字，不是请求值：
//!
//! - **Windows**：原样回显（请求 4MB → 回读 4194304；请求 1MB → 回读 1048576）。
//! - **Linux**：静默钳到 `net.core.rmem_max`（stock 212992）并按内核记账翻倍 （请求 4MB → 回读
//!   425984 = 2×212992；请求 1MB → 同样回读 425984）。
//!
//! 故「回读 < 4MB」这类绝对断言在 Linux 上**恒真**（425984 < 4194304），根本
//! 区分不出「我们没设」与「我们设了 4MB 但被内核钳制」。本文件因此用**对照差值**：
//! 同一进程内另建 socket 显式设 4MB 取其回读值，断言缺省路径回读与之**不同**，
//! 且等于**未下发 setsockopt 的内核缺省回读**。
//!
//! 显式路径（`sockopt.receiveBufferSize > 0`）另有一组断言：回读须等于**同平台
//! 同数值的直调 setsockopt 回读**（Windows 1048576 / Linux 425984），且**不同于**
//! 缺省路径回读——后者证明该值确实被下发（没被常量 0 吞掉）。
//!
//! 覆盖面：`apply_outbound_socket_options`（出站）、`apply_inbound_socket_options`
//! （入站）、`dial_system`（生产出站拨号真实落点，freedom / 各协议出站共用）。

use socket2::{Domain, Protocol, Socket, Type};
use xray_common::net::{address::Address, destination::Destination, port::Port};
use xray_transport::sockopt::{
    SocketOptions, apply_inbound_socket_options, apply_outbound_socket_options,
};

/// 新建裸 TCP socket（未连接）——`SO_RCVBUF` 是 socket 层选项，与连接状态无关。
fn bare_tcp_socket() -> Socket {
    Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).expect("新建裸 TCP socket")
}

/// 该 socket 的 `SO_RCVBUF` 回读值（平台记账口径）。
fn rcvbuf_of(socket: &Socket) -> usize {
    socket.recv_buffer_size().expect("getsockopt(SO_RCVBUF)")
}

/// 对照值：显式下发 `setsockopt(SO_RCVBUF, bytes)` 后的回读。
/// `bytes == 0` 表示**不下发**该选项 → 回读即内核缺省量级。
fn control_rcvbuf(bytes: usize) -> usize {
    let socket = bare_tcp_socket();
    if bytes > 0 {
        socket.set_recv_buffer_size(bytes).expect("setsockopt(SO_RCVBUF)");
    }
    rcvbuf_of(&socket)
}

/// 缺省路径的通用判据（出站 / 入站共用）。
///
/// - 回读 == 未下发 setsockopt 的内核缺省对照值 ⇒ 落在内核缺省量级；
/// - 回读 != 显式 4MB 的对照值 ⇒ 排除「设了 4MB 但被内核钳制仍看着像缺省」。
fn assert_default_path_not_pinned(label: &str, got: usize) {
    let kernel_default = control_rcvbuf(0);
    let explicit_4mb = control_rcvbuf(4 * 1024 * 1024);
    assert_eq!(
        got, kernel_default,
        "{label}: 缺省路径回读须等于内核缺省量级（未下发 setsockopt）: got={got} kernel_default={kernel_default}"
    );
    assert_ne!(
        got, explicit_4mb,
        "{label}: 缺省路径回读不得等于「显式设 4MB」的对照值（否则说明 4MB 仍被下发）: got={got} explicit_4mb={explicit_4mb}"
    );
}

/// 出站缺省路径：`apply_outbound_socket_options` 不得下发 4MB 的 `SO_RCVBUF`。
///
/// 取证数字（Windows 本机）：缺省回读 **65536** / 显式 4MB 对照 **4194304**。
#[test]
fn default_outbound_path_does_not_pin_so_rcvbuf() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let stream = std::net::TcpStream::connect(addr).expect("connect");
    let socket = Socket::from(stream);
    let before = rcvbuf_of(&socket);
    apply_outbound_socket_options(&socket, &SocketOptions::default(), None)
        .expect("apply_outbound_socket_options");
    let after = rcvbuf_of(&socket);

    assert_eq!(
        before, after,
        "缺省出站不得改动 SO_RCVBUF（未下发 setsockopt）: before={before} after={after}"
    );
    assert_default_path_not_pinned("缺省出站", after);

    let explicit_4mb = control_rcvbuf(4 * 1024 * 1024);
    #[allow(clippy::print_stdout)]
    {
        println!(
            "bd r5j96 出站缺省 SO_RCVBUF 回读 = {after} B；显式设 4MB 对照 = {explicit_4mb} B"
        );
    }
}

/// 入站缺省路径：`apply_inbound_socket_options` 不得下发 4MB 的 `SO_RCVBUF`。
#[test]
fn default_inbound_path_does_not_pin_so_rcvbuf() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let stream = std::net::TcpStream::connect(addr).expect("connect");
    let socket = Socket::from(stream);
    let before = rcvbuf_of(&socket);
    apply_inbound_socket_options(&socket, &SocketOptions::default())
        .expect("apply_inbound_socket_options");
    let after = rcvbuf_of(&socket);

    assert_eq!(
        before, after,
        "缺省入站不得改动 SO_RCVBUF（未下发 setsockopt）: before={before} after={after}"
    );
    assert_default_path_not_pinned("缺省入站", after);
}

/// 显式路径不回归：`sockopt.receiveBufferSize = 1MB` 仍照旧下发（没被常量 0 吞掉）。
///
/// 回读须等于**同平台同数值的直调 setsockopt 回读**——Windows 1048576、
/// Linux 425984（rmem_max 钳制 + 内核翻倍记账），且**不同于**缺省路径回读。
#[test]
fn explicit_receive_buffer_size_still_applies() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let stream = std::net::TcpStream::connect(addr).expect("connect");
    let socket = Socket::from(stream);
    let opts = SocketOptions { receive_buffer_size: 1024 * 1024, ..SocketOptions::default() };
    apply_outbound_socket_options(&socket, &opts, None).expect("apply_outbound_socket_options");
    let got = rcvbuf_of(&socket);

    let explicit_1mb = control_rcvbuf(1024 * 1024);
    let kernel_default = control_rcvbuf(0);
    assert_eq!(
        got, explicit_1mb,
        "显式 1MB 须按平台记账口径生效: got={got} explicit_1mb={explicit_1mb}"
    );
    assert_ne!(
        got, kernel_default,
        "显式 1MB 不得被缺省常量 0 吞掉（回读须区别于内核缺省）: got={got} kernel_default={kernel_default}"
    );
}

/// 生产出站拨号真实落点：`dial_system` 走完后的 socket 仍留在内核缺省量级。
///
/// `dial_system` 是 freedom / 各协议出站共用的拨号入口，其 sockopt 消费点正是
/// `apply_outbound_socket_options`——本测试把「入口 → socket」整条链钉住，
/// 证明缺省常量 0 在**真实拨号**上同样没下发 4MB。
#[tokio::test]
async fn production_dial_leaves_so_rcvbuf_at_kernel_default() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    #[allow(clippy::disallowed_methods, reason = "测试：accept 任务")]
    let accept_task = tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let dest = Destination::tcp(Address::IPv4(std::net::Ipv4Addr::LOCALHOST), Port::new(port));
    let conn = xray_transport::system_dialer::dial_system(&dest, &SocketOptions::default())
        .await
        .expect("dial_system");
    // 经 raw_tcp_clone 拿到底层 socket（同一内核 socket 的 dup handle）。
    let tcp = conn.raw_tcp_clone().expect("TcpConnection 应可克隆裸 socket");
    let got = socket2::SockRef::from(&tcp).recv_buffer_size().expect("getsockopt(SO_RCVBUF)");
    accept_task.await.expect("accept 任务收场");

    assert_default_path_not_pinned("生产拨号", got);
    let explicit_4mb = control_rcvbuf(4 * 1024 * 1024);
    #[allow(clippy::print_stdout)]
    {
        println!("bd r5j96 生产拨号 SO_RCVBUF 回读 = {got} B；显式设 4MB 对照 = {explicit_4mb} B");
    }
}

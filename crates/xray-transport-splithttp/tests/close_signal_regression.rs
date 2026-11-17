//! ServerConnCloseSignal AtomicWaker 重构回归测试（issue #22）。
//!
//! 覆盖作者拍板的五个确定性场景；全部手动驱动 `poll_read`/`Context`，零 sleep、
//! 零时序竞态：
//!
//! 1. `close_before_register_eof_on_first_poll` —— close 先于任何注册：首 poll 即 EOF；
//! 2. `close_after_pending_wakes_waker_and_close_is_idempotent` —— 注册后 close： 已注册 waker
//!    必被唤醒，且重复 close 幂等（不重复唤醒）；
//! 3. `close_while_parked_between_register_and_recheck_no_lost_wakeup` —— close 落在
//!    注册完成与下次观测之间的 parked 区间：不丢唤醒（旧 `Notify` 实现在此丢）； 注：register
//!    与同次 poll 内二次检查间隔亚微秒，外部无法注入，此场景在 API
//!    边界的确定性等价物就是「注册完成、poller 停泊期间 close 落地」，用 mpsc latch 协议严格定序；
//! 4. `eof_sticky_across_repeated_polls_and_takes_precedence_over_data` —— EOF 后 重复 poll 恒
//!    Ready/0 字节，且粘滞 EOF 优先于底层 reader 的在库数据；
//! 5. `clone_halves_share_close_state_and_both_observers_see_eof` —— Clone 两半共享 状态：guard 半
//!    close，conn 半及其 clone 出的观察者全部看到 EOF。
//!
//! 驱动路径与生产同源：`ServerConn::poll_read` 首查 `close_signal` 注入 EOF。

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    task::{Context, Poll, Wake, Waker},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xray_transport_splithttp::hub::{ServerConn, ServerConnCloseSignal};

/// 永不就绪的 reader：底层上行无数据（poll 恒 Pending）。
struct NeverReader;

impl AsyncRead for NeverReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

/// 单字节 reader：首 poll 给一个字节，其后 Ready(()) 空读——用于验证粘滞 EOF
/// 优先于底层数据。
struct OnceByteReader(AtomicBool);

impl AsyncRead for OnceByteReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.0.swap(true, Ordering::SeqCst) {
            buf.put_slice(b"X");
        }
        Poll::Ready(Ok(()))
    }
}

/// 恒接受的 writer（ServerConn 构造必需；本套测试不走写路径）。
struct AcceptWriter;

impl AsyncWrite for AcceptWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// 计数 waker：每次唤醒 +1（`std::task::Wake`，无第三方依赖）。
struct CountingWake(Arc<AtomicUsize>);

impl Wake for CountingWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn counting_waker(count: &Arc<AtomicUsize>) -> Waker {
    Waker::from(Arc::new(CountingWake(Arc::clone(count))))
}

fn test_conn(
    reader: Box<dyn AsyncRead + Unpin + Send + Sync>,
    signal: ServerConnCloseSignal,
) -> ServerConn {
    ServerConn {
        reader,
        writer: Box::new(AcceptWriter),
        remote_addr: SocketAddr::from(([127, 0, 0, 1], 1)),
        local_addr: SocketAddr::from(([127, 0, 0, 1], 2)),
        close_signal: signal,
    }
}

/// 手动驱动一次 poll_read：Ready 时返回读出的字节数（EOF = 0）。
fn drive_poll(conn: &mut ServerConn, waker: &Waker) -> Poll<io::Result<usize>> {
    let mut buf = [0u8; 16];
    let mut rb = ReadBuf::new(&mut buf);
    let mut cx = Context::from_waker(waker);
    match Pin::new(conn).poll_read(&mut cx, &mut rb) {
        Poll::Ready(Ok(())) => Poll::Ready(Ok(rb.filled().len())),
        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        Poll::Pending => Poll::Pending,
    }
}

/// 场景 1：close 先于任何注册——首 poll 即 EOF（粘滞标志第一检命中），
/// waker 全程不被触碰。
#[test]
fn close_before_register_eof_on_first_poll() {
    let (guard, observe) = ServerConnCloseSignal::new();
    let mut conn = test_conn(Box::new(NeverReader), observe);
    guard.close();

    let count = Arc::new(AtomicUsize::new(0));
    let waker = counting_waker(&count);
    match drive_poll(&mut conn, &waker) {
        Poll::Ready(Ok(n)) => assert_eq!(n, 0, "close 注入 EOF = 0 字节"),
        other => panic!("预期 Ready(Ok(0))，得到 {:?}", other),
    }
    assert_eq!(count.load(Ordering::SeqCst), 0, "close 先于注册 ⇒ 不应触碰 waker");
}

/// 场景 2：先 poll 到 Pending（注册完成），close 必须唤醒已注册 waker；
/// 重复 close 幂等（唤醒计数不涨），随后 poll 恒 Ready/EOF。
#[test]
fn close_after_pending_wakes_waker_and_close_is_idempotent() {
    let (guard, observe) = ServerConnCloseSignal::new();
    let mut conn = test_conn(Box::new(NeverReader), observe);

    let count = Arc::new(AtomicUsize::new(0));
    let waker = counting_waker(&count);
    assert!(
        matches!(drive_poll(&mut conn, &waker), Poll::Pending),
        "未 close 且底层无数据 ⇒ Pending"
    );
    assert_eq!(count.load(Ordering::SeqCst), 0);

    guard.close();
    assert_eq!(count.load(Ordering::SeqCst), 1, "close 必须唤醒已注册的读侧");

    guard.close();
    assert_eq!(count.load(Ordering::SeqCst), 1, "重复 close 幂等：不得重复唤醒");

    match drive_poll(&mut conn, &waker) {
        Poll::Ready(Ok(n)) => assert_eq!(n, 0),
        other => panic!("close 后重复 poll 必须 Ready/EOF，得到 {:?}", other),
    }
}

/// 场景 3：close 落在 parked 区间（注册完成、读侧停泊期间）——不丢唤醒。
/// mpsc latch 协议定序：读侧先注册并通知 close 线程，close 线程完成后再放行
/// 断言；无 sleep，两线程先后关系由通道保证。
#[test]
fn close_while_parked_between_register_and_recheck_no_lost_wakeup() {
    let (guard, observe) = ServerConnCloseSignal::new();
    let mut conn = test_conn(Box::new(NeverReader), observe);

    let count = Arc::new(AtomicUsize::new(0));
    let waker = counting_waker(&count);

    let (parked_tx, parked_rx) = mpsc::channel::<()>();
    let (closed_tx, closed_rx) = mpsc::channel::<()>();
    // 逐点脱管登记（clippy.toml 禁 std::thread::spawn）：本测试需要真实并发线程
    // 承载 latch 定序协议——集成测试无 FxScope/PluginContext 注入面，tokio 运行时
    // 反而引入时序不确定性；线程寿命被下方 join() 钉在本测试函数内。
    #[allow(clippy::disallowed_methods)]
    let closer = std::thread::spawn(move || {
        if parked_rx.recv().is_err() {
            panic!("未收到读侧 parked 通知即退出");
        }
        guard.close();
        // 主线程已 panic 时 send 落空 = 测试已在失败路径上，就地结束不重抛。
        let _ = closed_tx.send(());
    });

    assert!(matches!(drive_poll(&mut conn, &waker), Poll::Pending), "注册阶段应 Pending");
    if parked_tx.send(()).is_err() {
        panic!("close 线程提前退出，无法通知 parked");
    }
    if closed_rx.recv().is_err() {
        panic!("close 线程未完成 close 即退出");
    }
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "parked 区间 close 必须唤醒读侧（旧 Notify 实现在此丢唤醒）"
    );

    match drive_poll(&mut conn, &waker) {
        Poll::Ready(Ok(n)) => assert_eq!(n, 0),
        other => panic!("唤醒后重 poll 必须 Ready/EOF，得到 {:?}", other),
    }
    if closer.join().is_err() {
        panic!("close 线程异常终止");
    }
}

/// 场景 4：EOF 粘滞——close 后重复 poll 恒 Ready/0 字节，且即使底层 reader
/// 有在库数据（OnceByteReader 会给出一个字节），粘滞 EOF 仍然优先。
#[test]
fn eof_sticky_across_repeated_polls_and_takes_precedence_over_data() {
    let (guard, observe) = ServerConnCloseSignal::new();
    let mut conn = test_conn(Box::new(OnceByteReader(AtomicBool::new(false))), observe);
    guard.close();

    let count = Arc::new(AtomicUsize::new(0));
    let waker = counting_waker(&count);
    for i in 0..3 {
        match drive_poll(&mut conn, &waker) {
            Poll::Ready(Ok(n)) => {
                assert_eq!(n, 0, "第 {} 次 poll：粘滞 EOF 优先于底层数据，注入 0 字节", i);
            },
            other => panic!("第 {} 次 poll 预期 Ready(Ok(0))，得到 {:?}", i, other),
        }
    }
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

/// 场景 5：Clone 两半共享同一份（flag, waker）——guard 半 close，conn 半注册的
/// waker 被唤醒，conn 半与其 clone 出的观察者全部看到 EOF。
#[test]
fn clone_halves_share_close_state_and_both_observers_see_eof() {
    let (guard, observe) = ServerConnCloseSignal::new();
    let observe2 = observe.clone();
    let mut conn = test_conn(Box::new(NeverReader), observe);
    let mut conn2 = test_conn(Box::new(NeverReader), observe2);

    let count = Arc::new(AtomicUsize::new(0));
    let waker = counting_waker(&count);
    assert!(matches!(drive_poll(&mut conn, &waker), Poll::Pending));

    guard.close();
    assert_eq!(count.load(Ordering::SeqCst), 1, "guard 半 close 必须唤醒 conn 半注册的读侧");

    for (i, c) in [&mut conn, &mut conn2].into_iter().enumerate() {
        match drive_poll(c, &waker) {
            Poll::Ready(Ok(n)) => assert_eq!(n, 0, "观察者 {} 必须看到 EOF", i),
            other => panic!("观察者 {} 预期 Ready(Ok(0))，得到 {:?}", i, other),
        }
    }
}

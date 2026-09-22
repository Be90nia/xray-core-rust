//! 连接双向桥接——dispatch 链路的基础组件。
//!
//! 对应 Go `transport/pipe.New` + `cnc.NewConnection` 的双向 copy 语义。
//! 把两个 [`Connection`] 的读写半部交叉连接，任一方向 EOF 或出错时整体返回。
//!
//! ## 使用场景
//!
//! dispatcher 在 `dispatch_link` 中：
//! 1. inbound handler 接受客户端连接 → `inbound_conn`
//! 2. outbound handler 拨号到目标 → `outbound_conn`
//! 3. `bridge_connections(inbound_conn, outbound_conn)` 双向转发字节流
//!
//! 客户端发的数据流向 outbound（→ 目标服务器），目标服务器的响应流向 inbound（→ 客户端）。

use std::io;

use tokio::io::{AsyncRead, AsyncWrite};
use xray_features::policy::TimeoutPolicy;

use crate::connection::Connection;
#[cfg(test)]
use crate::connection::DuplexConnection;
use crate::link::Link;

/// 双向桥接两个 [`Connection`]。
///
/// 内部用 [`tokio::io::split`] 拆分每个连接的读写半部，然后用
/// **xray-buf 分层池**（8KB 默认）双向异步复制。任一方向完成（EOF）或出错时，
/// `select!` 返回，函数返回首个错误（若两端都成功则返回 `Ok`）。
///
/// **注意**：连接在桥接期间被 `split` 持有，桥接结束后两个半部被 drop，
/// 底层 TCP 连接随之关闭。调用方无需手动 close。
///
/// # 参数
///
/// - `a`：连接 A（通常是 inbound 客户端连接）。
/// - `b`：连接 B（通常是 outbound 目标连接）。
///
/// # 返回
///
/// - `Ok(())`：两个方向都正常 EOF。
/// - `Err(e)`：至少一个方向出错，返回首个遇到的 IO 错误。
///
/// ponytail: 池化读循环（8KB `xray_buf::alloc`）替代 `tokio::io::copy` 的
/// 内部 8KB Vec，连接结束后回池——避免长连接/大流量时反复 alloc 大块堆。
pub async fn bridge_connections(
    a: Box<dyn Connection>,
    b: Box<dyn Connection>,
) -> io::Result<()> {
    // Go `CanSpliceCopy` 零值 0（session.go:75-77）＝信号未挂出，永入回退泵——
    // 既有调用方行为跨平台零变化；只有 freedom 出站 TCP 场景显式传
    // `(1, &[1])`（freedom.go:260 唯一置 1 点）。
    bridge_connections_with_splice(a, b, 0, &[]).await
}

/// 带信号闸门的 [`bridge_connections`]：Go `proxy.CopyRawConnIfExist`
/// （proxy/proxy.go:718-792）等价入口。
///
/// splice(2) 零拷贝双向泵的准入 = [`xray_common::platform::splice::splice_allowed`]
/// （env `xray.buf.splice` + 平台 Linux/Android + CanSpliceCopy 全 1 信号）
/// 且两端均 [`Connection::is_raw_tcp`]（Go `IsRAWTransportWithoutSecurity`；
/// TLS/REALITY/fragment 包装层缺省拒绝）。任一条件不满足 → 回退下方既有
/// 池化泵（对应 Go 回退 readV，proxy.go:722-741；Windows/包装连接现状零变化）。
pub async fn bridge_connections_with_splice(
    a: Box<dyn Connection>,
    b: Box<dyn Connection>,
    inbound_can: i32,
    outbounds_can: &[i32],
) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some((ra, rb)) = crate::splice::plan(&*a, &*b, inbound_can, outbounds_can) {
        tracing::debug!("CopyRawConn splice");
        crate::splice::bridge_with(ra, rb).await?;
        return Ok(());
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = (inbound_can, outbounds_can);

    use tokio::io::AsyncReadExt;

    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);

    // 池化读循环：替代 tokio::io::copy 的内置 Vec，每次循环取一次池化缓冲，
    // 读后整段 write_all 到底层（无中间 merge_bytes 拷贝，bd etks 同源优化）。
    async fn copy_pooled<R, W>(mut reader: R, mut writer: W) -> io::Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;
        let mut buf = xray_buf::alloc::alloc(xray_buf::alloc::DEFAULT_SIZE);
        buf.resize(xray_buf::alloc::DEFAULT_SIZE, 0);
        loop {
            let n = match reader.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    xray_buf::alloc::release(buf);
                    return Err(e);
                }
            };
            if n == 0 {
                break;
            }
            if writer.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        xray_buf::alloc::release(buf);
        let _ = writer.shutdown().await;
        Ok(())
    }

    let a_to_b = copy_pooled(&mut a_read, &mut b_write);
    let b_to_a = copy_pooled(&mut b_read, &mut a_write);

    tokio::pin!(a_to_b, b_to_a);

    // 任一方向 EOF/出错就返回（对应 Go pipe 在一端关闭时另一端也关闭的行为）。
    // 另一个方向的 copy future 被 drop 取消，底层连接随后关闭。
    let result = tokio::select! {
        res = &mut a_to_b => res,
        res = &mut b_to_a => res,
    };

    result
}

/// 单向桥接：从 `reader` 复制到 `writer`，EOF 或出错时返回。
///
/// 比 [`bridge_connections`] 更简单，用于只需要单向转发的场景（如 UDP 中继的
/// 单向 copy）。通用泛型版，接受任何 `AsyncRead` + `AsyncWrite`。
pub async fn copy_one_way<R, W>(mut reader: R, mut writer: W) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    tokio::io::copy(&mut reader, &mut writer).await
}

/// 双向桥接 dispatcher [`Link`]（xray-buf Reader/Writer）与 AsyncRead+AsyncWrite stream。
///
/// 上行：`link.reader` 读到的 MultiBuffer → 转 bytes → `stream` 写出。
/// 下行：`stream` 读到的数据 → 转 MultiBuffer → `link.writer` 写出。
///
/// 两个方向独立运行到都完成（`join!` 语义）——任一方向 EOF/出错不会取消另一方向。
/// 适配 VMess 这种请求方向提前 EOF（body chunk 终止符）但响应方向仍需续传的场景。
/// 调用方无需手动关闭——stream 在桥接结束后被 drop。
pub async fn bridge_link_with_stream<S>(link: Link, stream: S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use xray_buf::io::{Reader, Writer};
    use xray_buf::multi::MultiBuffer;

    let Link { mut reader, mut writer } = link;
    let (mut s_read, mut s_write) = tokio::io::split(stream);

    // 上行：link.reader → stream
    let up = async move {
        loop {
            let mb = match reader.read_multi_buffer().await {
                Ok(mb) => mb,
                Err(_) => break,
            };
            if mb.is_empty() {
                break;
            }
            if write_all_mb(&mut s_write, &mb).await.is_err() {
                break;
            }
        }
        let _ = s_write.shutdown().await;
        io::Result::Ok(())
    };

    // 下行：stream → link.writer
    let down = async move {
        // 池化读缓冲（xray-buf 分层池，对应 Go sync.Pool）；resize 置满长度供 read 覆写
        let mut buf = xray_buf::alloc::alloc(xray_buf::alloc::DEFAULT_SIZE);
        buf.resize(xray_buf::alloc::DEFAULT_SIZE, 0);
        loop {
            let n = match s_read.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    xray_buf::alloc::release(buf);
                    return Err(e);
                }
            };
            if n == 0 {
                break;
            }
            let mut mb = MultiBuffer::new();
            mb.merge_bytes(&buf[..n]);
            if writer.write_multi_buffer(mb).await.is_err() {
                break;
            }
        }
        xray_buf::alloc::release(buf);
        // bridge 结束前通知读端 EOF（pipe.Writer.close）
        writer.shutdown();
        io::Result::Ok(())
    };
    tokio::pin!(up, down);
    let result = tokio::select! {
        res = &mut up => res,
        res = &mut down => res,
    };
    result
}

/// 逐 MultiBuffer 聚合写出（零拷贝，Buffer Drop 自动回池）。
///
/// vectored 写半部（y1yx）：`is_write_vectored` 为真时把 mb 内全部 Buffer
/// 组 IoSlice 栈数组（每批 ≤8，对齐 Go readv 上界）经 `write_all_vectored`
/// 单/少次 syscall 摊销；非 vectored 半部（TLS/wrapper 等）降级逐 Buffer
/// `write_all`。两条路径均零数据拷贝、零堆分配。
async fn write_all_mb<W>(w: &mut W, mb: &xray_buf::multi::MultiBuffer) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    /// 单批 iovec 数量上界（对齐 Go `allocStrategy` 的 readv 最大缓冲数）。
    const VECTORED_BATCH: usize = 8;

    if w.is_write_vectored() {
        let mut iter = mb.iter().filter(|b| !b.bytes().is_empty());
        loop {
            let mut slices = [io::IoSlice::new(&[]); VECTORED_BATCH];
            let mut n = 0;
            while n < VECTORED_BATCH {
                match iter.next() {
                    Some(b) => {
                        slices[n] = io::IoSlice::new(b.bytes());
                        n += 1;
                    }
                    None => break,
                }
            }
            if n == 0 {
                break;
            }
            // 推进循环写尽整批（tokio write_vectored 是单次 attempt，可能部分写）。
            let mut pending: &mut [io::IoSlice<'_>] = &mut slices[..n];
            while !pending.is_empty() {
                let written = w.write_vectored(pending).await?;
                if written == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write_vectored returned 0",
                    ));
                }
                io::IoSlice::advance_slices(&mut pending, written);
            }
        }
        return Ok(());
    }

    for b in mb.iter() {
        let bytes = b.bytes();
        if !bytes.is_empty() {
            w.write_all(bytes).await?;
        }
    }
    Ok(())
}


/// 双向桥接 dispatcher [`Link`] 与 AsyncRead+AsyncWrite stream。
///
/// 与 [`bridge_link_with_stream`] 区别：两个方向独立运行到都完成，任一方向 EOF/出错不会取消另一方向。
/// 适配 VMess 这种请求方向提前 EOF（body chunk 终止符）但响应方向仍需续传的场景。
///
/// **8sum 解耦（方案 A）**：每方向 reader（只读）与 writer（只写）拆为独立
/// async block，经 bounded mpsc（64 条 MultiBuffer ≈ 512KiB，对齐 Go
/// `defaultBufferSize`）解耦背压——writer 写背压时 reader 继续排空接收侧
/// （串行泵「读 8KB→写→循环」两腿锁步曾致服务端 TCP 接收窗不增长、全链
/// 1 窗/RTT 步进，up 3.1 vs Go 19.8 Mbps）。级联退出：任一 writer 死 →
/// mpsc rx drop → 对应 reader `send` 失败退出 → done watch 把 half_window
/// 传给对向腿，无静默半断；写错误只关本向写半部，绝不 shutdown 对向
/// （50074b2 教训：瞬时写错 shutdown link.writer = 下行永久断）。
///
/// 接收 `&TimeoutPolicy` 把 connIdle / uplinkOnly / downlinkOnly 三个超时下放到
/// 桥接层（Go `policy.Timeout` 语义，bd 4-6 修复：之前硬编码 DEFAULT_* 常量，
/// dispatcher 取出的 per-user Policy 不生效）。
pub async fn bridge_link_with_stream_full<S>(
    link: Link,
    stream: S,
    policy: &TimeoutPolicy,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Connection + 'static,
{
    use tokio::io::AsyncWriteExt;
    use tokio::time::timeout;
    use xray_buf::io::{new_reader, Reader, Writer};

    let conn_idle = policy.connection_idle;
    let uplink_only = policy.uplink_only;
    let downlink_only = policy.downlink_only;

    let Link { mut reader, mut writer } = link;
    // tokio::io::split（out_f1 33Mbps 实证拓扑，无锁）。自研 BiLock 轮转锁在
    // join! 固定轮询顺序下被 up 大流量系统性抢占（50074b2 同源塌陷：VPS 实测
    // up 1.58Mbps + strace「突发排空→恰 1 RTT 停顿」锁步签名），已整体删除。
    // WriteHalf 转发 poll_write_vectored/is_write_vectored（y1yx 聚合写保持）；
    // 下行顺序读（readv 重接属 bd 2o9l 专项，勿混入本票）。
    let (s_read, mut s_write) = tokio::io::split(stream);
    let mut s_read = new_reader(s_read);

    // 512KiB bounded mpsc ×2：容量按条目计（Go pipe 按字节软限，这里
    // 64 条 × 1-8 buffer × 8KiB，常态 ≥512KiB，只影响内存上限不影响正确性）。
    const PIPE_BUF_CAP: usize = 64;
    let (up_tx, mut up_rx) =
        tokio::sync::mpsc::channel::<xray_buf::multi::MultiBuffer>(PIPE_BUF_CAP);
    let (down_tx, mut down_rx) =
        tokio::sync::mpsc::channel::<xray_buf::multi::MultiBuffer>(PIPE_BUF_CAP);

    // 半关闭限窗（对应 Go policy Timeout.UplinkOnly/DownlinkOnly，proxy 层
    // `defer timer.SetTimeout(...)` 语义）：一方向读侧结束后，另一方向在窗口
    // 内无新数据则断开，防止单方向停滞连接永久挂起。窗口按 activity 重置
    // （读到新数据即续窗）。up 读侧结束 → down 剩余窗口 = uplink_only；
    // down 读侧结束 → up 剩余窗口 = downlink_only。
    let (up_done_tx, up_done_rx) = tokio::sync::watch::channel(None::<std::time::Duration>);
    let (down_done_tx, down_done_rx) = tokio::sync::watch::channel(None::<std::time::Duration>);

    // 上行 reader：link.reader → up_tx。超时语义与串行版逐行等价：
    // conn_idle 双向存活空闲断开；对向读侧结束后本向仅剩 half_window 宽限。
    let up_reader = async move {
        let mut down_done = down_done_rx;
        let mut window: Option<std::time::Duration> = None;
        loop {
            // 读 future 每轮重建是 cancel-safe 的：select!/timeout 丢弃的 future
            // 只可能处于 Pending（poll 到 Ready 的分支必被采用），无数据丢失。
            let mb = match window {
                None => tokio::select! {
                    // 空闲 deadline（Go ConnectionIdle / CancelAfterInactivity）
                    res = timeout(conn_idle, reader.read_multi_buffer()) => match res {
                        Ok(r) => r,
                        Err(_) => {
                            tracing::debug!("LEAKPROBE up_reader idle-break");
                            break;
                        }
                    },
                    _ = down_done.changed() => {
                        window = *down_done.borrow();
                        continue;
                    }
                },
                Some(d) => match timeout(d, reader.read_multi_buffer()).await {
                    Ok(r) => r,
                    Err(_) => {
                        tracing::debug!("LEAKPROBE up_reader half-window-break");
                        break; // downlink_only 窗口内无数据
                    }
                },
            };
            match mb {
                Ok(mb) if !mb.is_empty() => {
                    // channel 满阻塞在此（不抢对向时间片）；writer task 已死时
                    // send 立即 Err → 本向级联退出，绝不静默吞数据。
                    if up_tx.send(mb).await.is_err() {
                        tracing::debug!("LEAKPROBE up_reader send-fail-break");
                        break;
                    }
                }
                _ => {
                    tracing::debug!("LEAKPROBE up_reader eof-break");
                    break;
                }
            }
        }
        let _ = up_done_tx.send(Some(uplink_only));
        tracing::debug!("LEAKPROBE up_reader done");
        io::Result::Ok(())
    };
    // 上行 writer：up_rx → stream 写半部聚合写（vectored 批写，y1yx）。只写不读。
    let up_writer = async move {
        while let Some(mb) = up_rx.recv().await {
            if write_all_mb(&mut s_write, &mb).await.is_err() {
                break;
            }
        }
        // 无条件 shutdown（EOF 排空收尾与写错误收尾同路径），只关本向写半部。
        // 级联：本 task 退出即 drop up_rx → 上行 reader send 失败 → up_done
        // 传播 half_window，对向不静默半断。
        let _ = s_write.shutdown().await;
        tracing::debug!("LEAKPROBE up_writer done");
        io::Result::Ok(())
    };
    // 下行 reader：xray_buf 顺序读（池化 Buffer，对应 Go 无 vectored 源的
    // SingleReader 路径）→ down_tx。超时同构上行。
    let down_reader = async move {
        let mut up_done = up_done_rx;
        let mut window: Option<std::time::Duration> = None;
        loop {
            let mb = match window {
                None => tokio::select! {
                    // 空闲 deadline（Go ConnectionIdle / CancelAfterInactivity）
                    res = timeout(conn_idle, s_read.read_multi_buffer()) => match res {
                        Ok(r) => r,
                        Err(_) => break,
                    },
                    _ = up_done.changed() => {
                        window = *up_done.borrow();
                        continue;
                    }
                },
                Some(d) => match timeout(d, s_read.read_multi_buffer()).await {
                    Ok(r) => r,
                    Err(_) => break, // uplink_only 窗口内无数据
                },
            };
            match mb {
                Ok(mb) if !mb.is_empty() => {
                    if down_tx.send(mb).await.is_err() {
                        break;
                    }
                }
                _ => break, // EOF / 读错误
            }
        }
        let _ = down_done_tx.send(Some(downlink_only));
        tracing::debug!("LEAKPROBE down_reader done");
        io::Result::Ok(())
    };

    // 下行 writer：down_rx → link.writer（xray_buf Writer 管线，自带池化）。
    let down_writer = async move {
        while let Some(mb) = down_rx.recv().await {
            if writer.write_multi_buffer(mb).await.is_err() {
                break;
            }
        }
        // 桥结束确保下游 reader 收到 EOF；同样只关本向，不碰 stream 写半部。
        writer.shutdown();
        tracing::debug!("LEAKPROBE down_writer done");
        io::Result::Ok(())
    };

    // join! 语义：四块被并发轮询（读等待不阻塞写推进），全部完成后返回。
    let (up_r, up_w, down_r, down_w) =
        tokio::join!(up_reader, up_writer, down_reader, down_writer);
    up_r.and(up_w).and(down_r).and(down_w)
}

/// 默认策略的便捷包装（保留旧 API 兼容调用方）。
pub async fn bridge_link_with_stream_full_default<S>(link: Link, stream: S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Connection + 'static,
{
    let policy = TimeoutPolicy::default();
    bridge_link_with_stream_full(link, stream, &policy).await
}

/// 下行 splice 快路径桥（txno-splice；Go freedom responseDone 的
/// `proxy.CopyRawConnIfExist` splice 分支等价物，freedom.go:428-436）。
///
/// 上行保持既有用户态泵（Go `buf.Copy(input, writer)`——上行源是 dispatcher
/// 管道，本就不可 splice）；下行改走内核零拷贝：出站裸 socket → pipe → 入站
/// 裸 socket（Go `tc.ReadFrom(readerConn)`，proxy.go:768）。调用方须先用
/// [`xray_common::platform::splice::bridge_splice_admission`] 准入（env + 平台
/// + CanSpliceCopy 信号 + 双端 raw）；本函数不重复判定。
///
/// 平台：splice(2)/pipe2 仅 Linux/Android 编译；其余平台调用方
/// （DialBridge）在准入判定处已被平台闸门拦截，永不抵达本函数。
#[cfg(any(target_os = "linux", target_os = "android"))]
pub async fn bridge_link_with_stream_downlink_splice<S>(
    link: Link,
    stream: S,
    write_raw: std::sync::Arc<tokio::net::TcpStream>,
    policy: &TimeoutPolicy,
    down_counters: (
        Option<std::sync::Arc<dyn xray_features::stats::Counter>>,
        Option<std::sync::Arc<dyn xray_features::stats::Counter>>,
    ),
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Connection,
{
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use xray_buf::io::{Reader, Writer};

    let conn_idle = policy.connection_idle;
    let uplink_only = policy.uplink_only;
    let downlink_only = policy.downlink_only;

    // 准入已要求出站 raw；克隆失败（理论不可达）时下行退化为立即结束，
    // 上行照常泵完（连接可用性不受影响）。
    let down_from = stream.raw_tcp_clone();
    let Link { mut reader, mut writer } = link;
    let (_s_read, mut s_write) = tokio::io::split(stream); // 下行走 splice，读半部不再需要
    let (up_done_tx, _up_done_rx) = tokio::sync::watch::channel(None::<std::time::Duration>);
    let (down_done_tx, down_done_rx) = tokio::sync::watch::channel(None::<std::time::Duration>);

    // 上行 = Go buf.Copy(input, writer)（freedom.go:421）：link.reader → 出站，
    // ConnectionIdle 空闲窗 + 下行结束后的 UplinkOnly 半关闭窗，语义同
    // [`bridge_link_with_stream_full`] 的上行。
    let up = async move {
        let mut down_done = down_done_rx;
        let mut window: Option<std::time::Duration> = None;
        loop {
            let mb = match window {
                None => tokio::select! {
                    res = tokio::time::timeout(conn_idle, reader.read_multi_buffer()) => {
                        match res {
                            Ok(r) => r,
                            Err(_) => break,
                        }
                    }
                    _ = down_done.changed() => {
                        window = *down_done.borrow();
                        continue;
                    }
                },
                Some(d) => match tokio::time::timeout(d, reader.read_multi_buffer()).await {
                    Ok(r) => r,
                    Err(_) => break,
                },
            };
            match mb {
                Ok(mb) if !mb.is_empty() => {
                    if write_all_mb(&mut s_write, &mb).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = s_write.shutdown().await;
        let _ = up_done_tx.send(Some(uplink_only));
        io::Result::Ok(())
    };

    // 下行 = Go tc.ReadFrom(readerConn)（proxy.go:768）：出站裸 socket 经内核
    // pipe splice 进入站裸 socket，直到对端 EOF/错误。Go 在进入 splice 时把
    // 双端 timer 提到 24h（proxy.go:764-767）——即下行无空闲超时，EOF 即终。
    let down = async move {
        // Go proxy.go:760-766：splice 直达 raw fd 绕过 link 端 SizeStat 包装，
        // 经 splice_copy_counted 每 chunk 实时回填两级 downlink 计数器
        // （readCounter=出站 / writeCounter=入站），否则 Linux splice 路径
        // per-tag 流量统计恒 0（CI 首跑实证）。
        let counters = match (
            down_counters.0.as_deref(),
            down_counters.1.as_deref(),
        ) {
            (Some(o), Some(i)) => Some((o, i)),
            _ => None,
        };
        let res = match down_from {
            Some(from) => crate::splice::splice_copy_counted(&from, &write_raw, counters).await,
            None => Ok(0),
        };
        writer.shutdown();
        let _ = down_done_tx.send(Some(downlink_only));
        res.map(|_| ())
    };

    let (up_res, down_res) = tokio::join!(up, down);
    up_res.and(down_res)
}

/// 双向桥接两个 dispatcher [`Link`]（xray-buf Reader/Writer）。
///
/// 上行：`link_a.reader` → `link_b.writer`。
/// 下行：`link_b.reader` → `link_a.writer`。
///
/// 两个方向独立运行到都完成（`join!` 语义）——任一方向 EOF/出错不会取消另一方向。
/// 用于代理链场景：原始 link ↔ client link ↔ chained handler。
///
/// 接收 `&TimeoutPolicy` 同 [`bridge_link_with_stream_full`]。代理链目前
/// 走 dispatcher 默认 policy（与原语义一致——Go 链路上每个 outbound 自己的
/// policy 仍在该 outbound 内部生效；本层只控制连接级超时）。
pub async fn bridge_link_with_link(
    link_a: Link,
    link_b: Link,
    policy: &TimeoutPolicy,
) -> io::Result<()> {
    use xray_buf::io::{Reader, Writer};

    let conn_idle = policy.connection_idle;
    let uplink_only = policy.uplink_only;
    let downlink_only = policy.downlink_only;

    let Link { reader: mut a_reader, writer: mut a_writer } = link_a;
    let Link { reader: mut b_reader, writer: mut b_writer } = link_b;

    // 半关闭限窗语义同 bridge_link_with_stream_full（Go UplinkOnly/DownlinkOnly）。
    let (up_done_tx, up_done_rx) = tokio::sync::watch::channel(None::<std::time::Duration>);
    let (down_done_tx, down_done_rx) = tokio::sync::watch::channel(None::<std::time::Duration>);

    // 上行：a → b
    let up = async move {
        let mut down_done = down_done_rx;
        let mut window: Option<std::time::Duration> = None;
        loop {
            let mb = match window {
                None => tokio::select! {
                    // 空闲 deadline 语义同 bridge_link_with_stream_full（ConnectionIdle）
                    res = tokio::time::timeout(
                        conn_idle,
                        a_reader.read_multi_buffer(),
                    ) => match res {
                        Ok(r) => r,
                        Err(_) => break,
                    },
                    _ = down_done.changed() => {
                        window = *down_done.borrow();
                        continue;
                    }
                },
                Some(d) => match tokio::time::timeout(d, a_reader.read_multi_buffer()).await {
                    Ok(r) => r,
                    Err(_) => break,
                },
            };
            match mb {
                Ok(mb) if !mb.is_empty() => {
                    if b_writer.write_multi_buffer(mb).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        b_writer.shutdown();
        let _ = up_done_tx.send(Some(uplink_only));
        io::Result::Ok(())
    };

    // 下行：b → a
    let down = async move {
        let mut up_done = up_done_rx;
        let mut window: Option<std::time::Duration> = None;
        loop {
            let mb = match window {
                None => tokio::select! {
                    // 空闲 deadline 语义同 bridge_link_with_stream_full（ConnectionIdle）
                    res = tokio::time::timeout(
                        conn_idle,
                        b_reader.read_multi_buffer(),
                    ) => match res {
                        Ok(r) => r,
                        Err(_) => break,
                    },
                    _ = up_done.changed() => {
                        window = *up_done.borrow();
                        continue;
                    }
                },
                Some(d) => match tokio::time::timeout(d, b_reader.read_multi_buffer()).await {
                    Ok(r) => r,
                    Err(_) => break,
                },
            };
            match mb {
                Ok(mb) if !mb.is_empty() => {
                    if a_writer.write_multi_buffer(mb).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        a_writer.shutdown();
        let _ = down_done_tx.send(Some(downlink_only));
        io::Result::Ok(())
    };

    let (up_res, down_res) = tokio::join!(up, down);
    up_res.and(down_res)
}

/// 默认策略的便捷包装（保留旧 API 兼容调用方）。
pub async fn bridge_link_with_link_default(link_a: Link, link_b: Link) -> io::Result<()> {
    let policy = TimeoutPolicy::default();
    bridge_link_with_link(link_a, link_b, &policy).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::TcpConnection;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::task::Poll;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 创建两对 loopback TCP 连接：(client_a ↔ server_a) 和 (client_b ↔ server_b)。
    /// bridge(server_a, server_b) 后：
    /// - client_a 发的数据 → server_a 读 → bridge → server_b 写 → client_b 读
    /// - client_b 发的数据 → server_b 读 → bridge → server_a 写 → client_a 读
    async fn setup_two_pairs() -> (
        TcpStream, // client_a
        TcpStream, // client_b
        Box<dyn Connection>, // server_a (传入 bridge)
        Box<dyn Connection>, // server_b (传入 bridge)
    ) {
        let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_a = listener_a.local_addr().unwrap();
        let addr_b = listener_b.local_addr().unwrap();

        let (client_a_task, client_b_task, server_a_task, server_b_task) = tokio::join!(
            async { TcpStream::connect(addr_a).await.unwrap() },
            async { TcpStream::connect(addr_b).await.unwrap() },
            async { listener_a.accept().await.unwrap().0 },
            async { listener_b.accept().await.unwrap().0 },
        );

        let server_a: Box<dyn Connection> = Box::new(TcpConnection::new(server_a_task));
        let server_b: Box<dyn Connection> = Box::new(TcpConnection::new(server_b_task));

        (client_a_task, client_b_task, server_a, server_b)
    }

    #[tokio::test]
    async fn bridge_bidirectional_data_flow() {
        let (mut client_a, mut client_b, server_a, server_b) = setup_two_pairs().await;

        // 启动 bridge
        let bridge = tokio::spawn(async move {
            bridge_connections(server_a, server_b).await
        });

        // client_a → bridge → client_b
        client_a.write_all(b"hello from A").await.unwrap();
        let mut buf = [0u8; 12];
        client_b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello from A");

        // client_b → bridge → client_a
        client_b.write_all(b"hello from B").await.unwrap();
        let mut buf = [0u8; 12];
        client_a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello from B");

        // 关闭 client 触发 bridge EOF
        drop(client_a);
        drop(client_b);

        // bridge 应正常返回
        let _ = bridge.await;
    }

    #[tokio::test]
    async fn bridge_returns_on_either_side_eof() {
        let (mut client_a, _client_b, server_a, server_b) = setup_two_pairs().await;

        let bridge = tokio::spawn(async move {
            bridge_connections(server_a, server_b).await
        });

        // client_a 发数据后关闭
        client_a.write_all(b"final").await.unwrap();
        drop(client_a);

        // bridge 应在 client_a 关闭后返回（EOF）
        // client_b 可能还没读到数据（取决于时序），但 bridge 必须返回
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), bridge).await;
        assert!(result.is_ok(), "bridge should return within timeout");
    }

    #[tokio::test]
    async fn bridge_large_payload_roundtrip() {
        let (mut client_a, mut client_b, server_a, server_b) = setup_two_pairs().await;

        let bridge = tokio::spawn(bridge_connections(server_a, server_b));

        // 发送较大 payload (64 KiB)
        let payload: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
        client_a.write_all(&payload).await.unwrap();

        let mut received = vec![0u8; payload.len()];
        client_b.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload);

        drop(client_a);
        drop(client_b);
        let _ = bridge.await;
    }

    /// gated 入口全绿信号（freedom 场景 `1, &[1]`，freedom.go:260）：裸 TCP 双端
    /// 数据双向互达。Linux 走 splice 泵；Windows/非 linux 平台闸门（平台+编译
    /// 门控）回退池化泵——两平台断言相同，证明入口语义一致。
    #[tokio::test]
    async fn bridge_with_splice_plain_tcp_bidirectional() {
        let (mut client_a, mut client_b, server_a, server_b) = setup_two_pairs().await;

        let bridge = tokio::spawn(bridge_connections_with_splice(server_a, server_b, 1, &[1]));

        client_a.write_all(b"up-splice").await.unwrap();
        let mut buf = [0u8; 9];
        client_b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"up-splice");

        client_b.write_all(b"down-splice").await.unwrap();
        let mut buf = [0u8; 11];
        client_a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"down-splice");

        drop(client_a);
        drop(client_b);
        let _ = bridge.await;
    }

    /// 包装连接不启用（Go `IsRAWTransportWithoutSecurity` 对 tls.Conn 为
    /// false）：`raw_tcp_clone` 缺省 `None` + `is_raw_tcp` 缺省 `false` 的
    /// 包装层即使信号全绿也必须回退既有泵，数据照常流通。
    #[tokio::test]
    async fn bridge_with_splice_wrapped_conn_falls_back() {
        struct WrappedConn(TcpStream);
        impl tokio::io::AsyncRead for WrappedConn {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
            }
        }
        impl tokio::io::AsyncWrite for WrappedConn {
            fn poll_write(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<io::Result<usize>> {
                std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
            }
            fn poll_flush(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::pin::Pin::new(&mut self.0).poll_flush(cx)
            }
            fn poll_shutdown(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
            }
        }
        impl Connection for WrappedConn {
            fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(Some(self.0.peer_addr()?))
            }
            fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(Some(self.0.local_addr()?))
            }
        }

        // 自建一对拿裸 TcpStream（setup_two_pairs 已装箱为 dyn Connection），
        // 一端包成 is_raw_tcp=false 的包装层，另一端保持裸 TCP。
        let lsn_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client_a = TcpStream::connect(lsn_a.local_addr().unwrap()).await.unwrap();
        let wrapped_a: Box<dyn Connection> = Box::new(WrappedConn(lsn_a.accept().await.unwrap().0));
        assert!(!wrapped_a.is_raw_tcp());

        let lsn_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client_b = TcpStream::connect(lsn_b.local_addr().unwrap()).await.unwrap();
        let bare_b: Box<dyn Connection> = Box::new(TcpConnection::new(lsn_b.accept().await.unwrap().0));

        let bridge =
            tokio::spawn(bridge_connections_with_splice(wrapped_a, bare_b, 1, &[1]));

        client_a.write_all(b"fallback").await.unwrap();
        let mut buf = [0u8; 8];
        client_b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"fallback");

        drop(client_a);
        drop(client_b);
        let _ = bridge.await;
    }

    #[tokio::test]
    async fn copy_one_way_transfers_data() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (client, server) = tokio::join!(
            async { TcpStream::connect(addr).await.unwrap() },
            async { listener.accept().await.unwrap().0 },
        );

        let mut client = client;
        let server: Box<dyn Connection> = Box::new(TcpConnection::new(server));

        let (mut read, _write) = tokio::io::split(server);

        client.write_all(b"one-way data").await.unwrap();
        drop(client);

        let mut buf = Vec::new();
        copy_one_way(&mut read, &mut buf).await.unwrap();
        assert_eq!(&buf, b"one-way data");
    }

    #[tokio::test]
    async fn bridge_link_uplink_only() {
        // 最小上行测试：pipe.Writer 写 → bridge up reader 读 → duplex server 端收
        use crate::link::Link;
        use tokio::io::AsyncReadExt;
        use xray_buf::io::{Reader, Writer};
        use xray_buf::multi::MultiBuffer;

        let (mut server, client) = tokio::io::duplex(8192);
        let (up_r, up_w) = xray_buf::pipe::new();
        let (_dn_r, dn_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(up_r), Box::new(dn_w));

        let (recv, _) = tokio::join!(
            async {
                let mut w = up_w;
                let mut mb = MultiBuffer::new();
                mb.merge_bytes(b"uplink ok");
                w.write_multi_buffer(mb).await.unwrap();
                w.shutdown(); // pipe.Writer.close → bridge up reader EOF
                let mut buf = vec![0u8; 64];
                let n = server.read(&mut buf).await.unwrap();
                buf[..n].to_vec()
            },
            bridge_link_with_stream(link, client),
        );
        assert_eq!(&recv, b"uplink ok");
    }

    #[tokio::test]
    async fn bridge_link_downlink_only() {
        // 最小下行测试：duplex server 端写 → bridge down reader 读 → pipe.Reader 收
        use crate::link::Link;
        use tokio::io::AsyncWriteExt;
        use xray_buf::io::{Reader, Writer};

        let (mut server, client) = tokio::io::duplex(8192);
        // dn pipe：bridge 写下行数据到这里，主线程从 dn_r 读
        let (dn_r, dn_w) = xray_buf::pipe::new();
        // up pipe 占位：bridge 的上行 reader 在这里读，但本测试不写上行数据
        let (dummy_r, _dummy_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(dummy_r), Box::new(dn_w));

        let (recv, _) = tokio::join!(
            async {
                server.write_all(b"downlink ok").await.unwrap();
                drop(server); // 关闭触发 bridge down reader EOF
                let mut r = dn_r;
                r.read_multi_buffer().await.unwrap().to_vec()
            },
            bridge_link_with_stream(link, client),
        );
        assert_eq!(&recv, b"downlink ok");
    }

    // ---- 半关闭限窗（policy UplinkOnly/DownlinkOnly，6bg）----

    #[tokio::test]
    async fn bridge_stream_full_halfclose_linger_then_close() {
        use crate::link::Link;
        use xray_buf::io::{Reader, Writer};
        use xray_buf::multi::MultiBuffer;

        let (up_r, up_w) = xray_buf::pipe::new();
        let (dn_r, dn_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(up_r), Box::new(dn_w));
        let (mut stream_peer, stream) = tokio::io::duplex(8192);

        let bridge = tokio::spawn(bridge_link_with_stream_full_default(
            link,
            Box::new(DuplexConnection::new(stream)) as Box<dyn Connection>,
        ));

        // 上游写完即 EOF → bridge down 进入 uplink_only（1s）窗口
        let mut producer = up_w;
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(b"req");
        producer.write_multi_buffer(mb).await.unwrap();
        producer.shutdown();

        // 窗口内 stream 端送来响应 → 下行续传（activity 重置窗口）
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        stream_peer.write_all(b"resp").await.unwrap();

        let mut consumer = dn_r;
        let mb = consumer
            .read_multi_buffer_timeout(std::time::Duration::from_secs(1))
            .await
            .expect("downlink should deliver within half-close window");
        assert_eq!(mb.to_vec(), b"resp");

        // 之后无数据 → 窗口耗尽 → bridge 结束（不永久挂起）
        let res = tokio::time::timeout(std::time::Duration::from_secs(5), bridge)
            .await
            .expect("bridge must finish after window expires")
            .expect("join error");
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn bridge_stream_full_halfclose_timeout_disconnects() {
        use crate::link::Link;
        use xray_buf::io::Writer;

        let (up_r, up_w) = xray_buf::pipe::new();
        let (dn_r, dn_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(up_r), Box::new(dn_w));
        // peer 保留不 drop：drop 会让 stream EOF 走正常结束而非超时路径
        let (_stream_peer, stream) = tokio::io::duplex(8192);

        let start = std::time::Instant::now();
        // 上游立即 EOF（无数据）→ down 只能靠 uplink_only 窗口超时断开
        up_w.shutdown();
        let res = bridge_link_with_stream_full_default(
            link,
            Box::new(DuplexConnection::new(stream)) as Box<dyn Connection>,
        )
        .await;
        assert!(res.is_ok());
        assert!(
            start.elapsed() >= std::time::Duration::from_millis(900),
            "half-close window should elapse before disconnect"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "should not hang forever"
        );
        let _ = dn_r;
    }

    // ---- bd 4-6: per-dispatch policy 下放到 bridge 数据面 ----

    /// 极短 conn_idle 验证：bridge 200ms 内无活动必须断开（替代默认 300s）。
    /// 这一条断言即可证明：传入的 `&TimeoutPolicy` 真的进了 conn_idle 计算，
    /// 而非被忽略/被默认常量覆盖。
    #[tokio::test]
    async fn bridge_stream_full_uses_injected_connection_idle() {
        use crate::link::Link;
        use xray_features::policy::TimeoutPolicy;
        use std::time::Duration;

        let (up_r, up_w) = xray_buf::pipe::new();
        let (dn_r, dn_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(up_r), Box::new(dn_w));
        let (_stream_peer, stream) = tokio::io::duplex(8192);

        // 关键：短 conn_idle = 200ms，远小于默认 300s。
        // uplink_only / downlink_only 留默认 1s（不影响 conn_idle 路径）。
        let policy = TimeoutPolicy {
            connection_idle: Duration::from_millis(200),
            ..TimeoutPolicy::default()
        };

        let start = std::time::Instant::now();
        // 上行 writer 保留不写、不 shutdown → 双方向均无活动 → conn_idle 触发断开。
        let _keep_up = up_w;
        let res = bridge_link_with_stream_full(
            link,
            Box::new(DuplexConnection::new(stream)) as Box<dyn Connection>,
            &policy,
        )
        .await;
        let elapsed = start.elapsed();
        assert!(res.is_ok(), "bridge must return Ok on conn_idle break");
        assert!(
            elapsed >= Duration::from_millis(180),
            "must respect injected conn_idle (elapsed {elapsed:?} < 200ms)"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "conn_idle too long, possibly fell back to default 300s (elapsed {elapsed:?})"
        );
        let _ = dn_r;
    }

    /// bridge_connections 池化路径：两端双向 8KB 流量必须无丢失、按时返回。
    /// ponytail: 8KB 池化缓冲替代 tokio::io::copy 的内置 Vec——大流量下不至于
    /// 反复 alloc 8KB Vec。但行为正确性必须验证（防止 alloc/release 配对错误）。
    #[tokio::test]
    async fn bridge_connections_bidirectional_pooled_8kb() {
        use crate::connection::TcpConnection;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        // 两对 loopback：(client_a ↔ server_a), (client_b ↔ server_b)
        let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_a = listener_a.local_addr().unwrap();
        let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_b = listener_b.local_addr().unwrap();

        let client_a = TcpStream::connect(addr_a).await.unwrap();
        let server_a = listener_a.accept().await.unwrap().0;
        let client_b = TcpStream::connect(addr_b).await.unwrap();
        let server_b = listener_b.accept().await.unwrap().0;

        // 启动 bridge(server_a, server_b)
        let bridge_handle = tokio::spawn(bridge_connections(
            Box::new(TcpConnection::new(server_a)) as Box<dyn Connection>,
            Box::new(TcpConnection::new(server_b)) as Box<dyn Connection>,
        ));

        // 单方向 8KB 数据：client_a → bridge → client_b
        let payload = vec![0xA5u8; 8 * 1024];
        let payload_for_read = payload.clone();
        let mut client_a = TcpConnection::new(client_a);
        let mut client_b = TcpConnection::new(client_b);
        let writer = tokio::spawn(async move {
            client_a.write_all(&payload).await.unwrap();
            client_a.shutdown().await.ok();
        });
        let mut recv_buf = vec![0u8; payload_for_read.len()];
        client_b.read_exact(&mut recv_buf).await.unwrap();
        assert_eq!(
            recv_buf, payload_for_read,
            "pooled bridge must not lose/corrupt bytes"
        );
        writer.await.unwrap();
        // 读端 drop → bridge 一方向 EOF → 整体退出
        drop(client_b);
        let _res = tokio::time::timeout(std::time::Duration::from_secs(5), bridge_handle)
            .await
            .expect("bridge must finish after EOF")
            .expect("bridge join");
    }

    // ---- 8sum 方案 A：解耦泵回归门 + 瞬时写错不断向 + vectored 写（y1yx）----

    /// 解耦回归门（HANDOFF `bridge_stream_full_uplink_survives_slow_remote` 重建）：
    /// stream 对端永不读（duplex 8192 缓冲即背压），上游写 64KB + shutdown。
    /// 解耦版 up reader 把数据吸进 512KiB mpsc 后照常读到 EOF → up_done →
    /// down 腿 uplink_only 窗口耗尽收尾 → dn_r 读到关闭；串行泵会卡在
    /// 写 duplex 的锁步里永远读不到上游 EOF，dn_r 5s 内等不到关闭。
    #[tokio::test]
    async fn bridge_stream_full_uplink_survives_slow_remote() {
        use crate::link::Link;
        use xray_buf::io::{Reader, Writer};
        use xray_buf::multi::MultiBuffer;

        let (up_r, mut up_w) = xray_buf::pipe::new();
        let (dn_r, dn_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(up_r), Box::new(dn_w));
        let (_peer, stream) = tokio::io::duplex(8192);

        let bridge = tokio::spawn(bridge_link_with_stream_full_default(
            link,
            Box::new(DuplexConnection::new(stream)) as Box<dyn Connection>,
        ));

        // 64KB = 8 × duplex 缓冲：解耦后被 mpsc（64×8KiB）全量吸收
        for _ in 0..8 {
            let mut mb = MultiBuffer::new();
            mb.merge_bytes(&vec![0x5Au8; 8 * 1024]);
            up_w.write_multi_buffer(mb).await.unwrap();
        }
        up_w.shutdown();

        // 上游 EOF 传播 + half-close 窗口耗尽 → bridge 收尾 → dn_r 关闭。
        let mut consumer = dn_r;
        let res = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match consumer.read_multi_buffer().await {
                    Ok(mb) if !mb.is_empty() => continue,
                    _ => return,
                }
            }
        })
        .await
        .expect("bridge must close dn_r after upstream EOF + window expiry (decoupled)");
        drop(res);
        // 对端不读，up_writer 停在写背压——由 abort 收尾，非本测试断言对象。
        bridge.abort();
    }

    /// 瞬时写错误不永久断向（验收 5；50074b2 头号嫌疑回归门）：上行 writer 写
    /// stream 恒错时仅上行收敛，下行数据照常送达 link.writer，桥在有限时间
    /// 整体退出——绝不 shutdown 对向（写错 shutdown link.writer = 下行永久断）。
    #[tokio::test]
    async fn bridge_stream_full_up_write_err_keeps_downlink() {
        use crate::link::Link;
        use std::pin::Pin;
        use std::task::Poll;
        use xray_buf::io::{Reader, Writer};

        /// 写半恒错的 mock：读半转发真 duplex（下行数据源）。
        struct UpWriteErrConn(tokio::io::DuplexStream);
        impl tokio::io::AsyncRead for UpWriteErrConn {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.0).poll_read(cx, buf)
            }
        }
        impl tokio::io::AsyncWrite for UpWriteErrConn {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "transient write err",
                )))
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        impl Connection for UpWriteErrConn {
            fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }
            fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }
        }

        let (up_r, mut up_w) = xray_buf::pipe::new();
        let (mut dn_r, dn_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(up_r), Box::new(dn_w));
        let (mut peer, stream) = tokio::io::duplex(8192);

        let bridge = tokio::spawn(bridge_link_with_stream_full_default(
            link,
            Box::new(UpWriteErrConn(stream)) as Box<dyn Connection>,
        ));

        // 上行数据触发 up_writer 写错 → 仅上行收敛
        let mut mb = xray_buf::multi::MultiBuffer::new();
        mb.merge_bytes(b"req");
        up_w.write_multi_buffer(mb).await.unwrap();
        up_w.shutdown();

        // 下行不受写错影响：窗口内送达 link.writer
        use tokio::io::AsyncWriteExt;
        peer.write_all(b"resp").await.unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(2), dn_r.read_multi_buffer())
            .await
            .expect("downlink must survive up-write error (no cross-direction shutdown)")
            .unwrap();
        assert_eq!(got.to_vec(), b"resp");

        // 全桥有限时间收敛（half-close 窗口耗尽后退出，不挂死）
        drop(peer);
        drop(up_w);
        let res = tokio::time::timeout(std::time::Duration::from_secs(5), bridge)
            .await
            .expect("bridge must finish after window expiry")
            .expect("bridge join");
        assert!(res.is_ok());
    }

    /// 对称回归门：下行 writer 写 link.writer 恒错时仅下行收敛，上行数据
    /// 照常送达 stream，桥有限时间退出。
    #[tokio::test]
    async fn bridge_stream_full_down_write_err_keeps_uplink() {
        use crate::link::Link;
        use std::pin::Pin;
        use xray_buf::io::{Error as BufError, Result as BufResult, Writer};
        use xray_buf::multi::MultiBuffer;

        /// 写恒错的 mock link.writer。
        struct ErrLinkWriter;
        impl Writer for ErrLinkWriter {
            fn write_multi_buffer(
                &mut self,
                _mb: MultiBuffer,
            ) -> Pin<Box<dyn Future<Output = BufResult<()>> + Send + '_>> {
                Box::pin(async {
                    Err(BufError::WriteError("link writer broken".into()))
                })
            }
        }

        let (up_r, mut up_w) = xray_buf::pipe::new();
        let (dn_r, dn_w) = xray_buf::pipe::new();
        let link = Link::new(Box::new(up_r), Box::new(ErrLinkWriter));
        let (mut peer, stream) = tokio::io::duplex(8192);

        let bridge = tokio::spawn(bridge_link_with_stream_full_default(
            link,
            Box::new(DuplexConnection::new(stream)) as Box<dyn Connection>,
        ));
        let _ = dn_r; // 下行已断，仅防 unused

        // 下行数据触发 down_writer 写错 → 仅下行收敛
        use tokio::io::AsyncWriteExt;
        peer.write_all(b"resp").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 上行不受写错影响：数据照常穿过桥抵达 stream 对端
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(b"req");
        up_w.write_multi_buffer(mb).await.unwrap();
        up_w.shutdown();

        let mut got = vec![0u8; 3];
        tokio::time::timeout(std::time::Duration::from_secs(2), peer.read_exact(&mut got))
            .await
            .expect("uplink must survive down-write error")
            .unwrap();
        assert_eq!(&got, b"req");

        // 全桥有限时间收敛
        drop(peer);
        drop(up_w);
        let res = tokio::time::timeout(std::time::Duration::from_secs(5), bridge)
            .await
            .expect("bridge must finish")
            .expect("bridge join");
        assert!(res.is_ok());
    }

    /// `write_all_mb` vectored 批写（y1yx）：vectored mock 聚合 3 buffer 为
    /// 1 次 `poll_write_vectored`（生产经 tokio WriteHalf 透传到 TCP writev）。
    #[tokio::test]
    async fn write_all_mb_vectored_batch_write() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use parking_lot::Mutex;

        struct VectoredMock {
            sink: Arc<Mutex<Vec<u8>>>,
            vectored_calls: Arc<AtomicUsize>,
        }
        impl tokio::io::AsyncWrite for VectoredMock {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.sink.lock().extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
            }
            fn poll_write_vectored(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                bufs: &[io::IoSlice<'_>],
            ) -> Poll<io::Result<usize>> {
                self.vectored_calls.fetch_add(1, Ordering::SeqCst);
                let mut sink = self.sink.lock();
                let mut total = 0;
                for b in bufs {
                    sink.extend_from_slice(b);
                    total += b.len();
                }
                Poll::Ready(Ok(total))
            }
            fn is_write_vectored(&self) -> bool {
                true
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let sink = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut s_write = VectoredMock { sink: Arc::clone(&sink), vectored_calls: Arc::clone(&calls) };
        assert!(s_write.is_write_vectored());

        let mb = xray_buf::multi::MultiBuffer::from_buffers(vec![
            xray_buf::buffer::Buffer::from_vec(b"abc".to_vec()),
            xray_buf::buffer::Buffer::from_vec(b"def".to_vec()),
            xray_buf::buffer::Buffer::from_vec(b"ghi".to_vec()),
        ]);
        write_all_mb(&mut s_write, &mb).await.unwrap();
        assert_eq!(*sink.lock(), b"abcdefghi");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "3 buffers must aggregate into a single poll_write_vectored"
        );
    }

    /// `write_all_mb` 非 vectored 回退（y1yx）：`is_write_vectored=false` 的
    /// 底层（TLS wrapper 等）逐 Buffer `write_all`，空 Buffer 不产生 syscall，
    /// 字节序不变。
    #[tokio::test]
    async fn write_all_mb_non_vectored_fallback_per_buffer() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use parking_lot::Mutex;

        struct NonVectoredMock {
            sink: Arc<Mutex<Vec<u8>>>,
            write_calls: Arc<AtomicUsize>,
        }
        impl tokio::io::AsyncWrite for NonVectoredMock {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.write_calls.fetch_add(1, Ordering::SeqCst);
                self.sink.lock().extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let sink = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut s_write =
            NonVectoredMock { sink: Arc::clone(&sink), write_calls: Arc::clone(&calls) };
        assert!(!s_write.is_write_vectored());

        let mb = xray_buf::multi::MultiBuffer::from_buffers(vec![
            xray_buf::buffer::Buffer::from_vec(b"abc".to_vec()),
            xray_buf::buffer::Buffer::from_vec(Vec::new()),
            xray_buf::buffer::Buffer::from_vec(b"def".to_vec()),
            xray_buf::buffer::Buffer::from_vec(b"ghi".to_vec()),
        ]);
        write_all_mb(&mut s_write, &mb).await.unwrap();
        assert_eq!(*sink.lock(), b"abcdefghi");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "non-vectored fallback: one write per non-empty buffer, empty skipped"
        );
    }

    /// 生产 split 形态透传（y1yx）：`bridge_link_with_stream_full` 经
    /// `tokio::io::split` 后以 `WriteHalf` 为 W——split 时缓存 inner 的
    /// `is_write_vectored`（tokio split.rs:36），`poll_write_vectored` 真透传，
    /// vectored 聚合在生产接线不退化为逐段写。
    #[tokio::test]
    async fn write_all_mb_via_split_writehalf_forwards_vectored() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use parking_lot::Mutex;

        struct VectoredMock {
            sink: Arc<Mutex<Vec<u8>>>,
            vectored_calls: Arc<AtomicUsize>,
        }
        impl tokio::io::AsyncWrite for VectoredMock {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.sink.lock().extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
            }
            fn poll_write_vectored(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                bufs: &[io::IoSlice<'_>],
            ) -> Poll<io::Result<usize>> {
                self.vectored_calls.fetch_add(1, Ordering::SeqCst);
                let mut sink = self.sink.lock();
                let mut total = 0;
                for b in bufs {
                    sink.extend_from_slice(b);
                    total += b.len();
                }
                Poll::Ready(Ok(total))
            }
            fn is_write_vectored(&self) -> bool {
                true
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        // split 要求 AsyncRead；此测试只写不读，EOF 桩即可。
        impl tokio::io::AsyncRead for VectoredMock {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let sink = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let mock = VectoredMock { sink: Arc::clone(&sink), vectored_calls: Arc::clone(&calls) };
        let (_s_read, mut s_write) = tokio::io::split(mock);
        assert!(
            s_write.is_write_vectored(),
            "WriteHalf must cache inner is_write_vectored at split time"
        );

        let mb = xray_buf::multi::MultiBuffer::from_buffers(vec![
            xray_buf::buffer::Buffer::from_vec(b"abc".to_vec()),
            xray_buf::buffer::Buffer::from_vec(b"def".to_vec()),
            xray_buf::buffer::Buffer::from_vec(b"ghi".to_vec()),
        ]);
        write_all_mb(&mut s_write, &mb).await.unwrap();
        assert_eq!(*sink.lock(), b"abcdefghi");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "vectored aggregation must survive the split(WriteHalf) indirection"
        );
    }

}

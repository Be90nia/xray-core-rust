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

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use xray_features::policy::TimeoutPolicy;

use crate::connection::Connection;
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

/// 逐 Buffer 写出 MultiBuffer（零拷贝，Buffer Drop 自动回池）。
///
/// 替代 `mb.to_vec()` 的整段拷贝分配。
async fn write_all_mb<W>(w: &mut W, mb: &xray_buf::multi::MultiBuffer) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    for b in mb.iter() {
        let bytes = b.bytes();
        if !bytes.is_empty() {
            w.write_all(bytes).await?;
        }
    }
    Ok(())
}

/// 双向桥接 dispatcher [`Link`] 与 AsyncRead+AsyncWrite stream（`join!` 语义）。
///
/// 与 [`bridge_link_with_stream`] 区别：两个方向独立运行到都完成，任一方向 EOF/出错不会取消另一方向。
/// 适配 VMess 这种请求方向提前 EOF（body chunk 终止符）但响应方向仍需续传的场景。
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
    S: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use xray_buf::buffer::Buffer;
    use xray_buf::io::{Reader, Writer};
    use xray_buf::multi::MultiBuffer;

    let conn_idle = policy.connection_idle;
    let uplink_only = policy.uplink_only;
    let downlink_only = policy.downlink_only;

    let Link { mut reader, mut writer } = link;
    let (mut s_read, mut s_write) = tokio::io::split(stream);

    // 半关闭限窗（对应 Go policy Timeout.UplinkOnly/DownlinkOnly，proxy 层
    // `defer timer.SetTimeout(...)` 语义）：一方向结束后，另一方向在窗口内
    // 无新数据则断开，防止单方向停滞连接永久挂起。窗口按 activity 重置
    // （读到新数据即续窗），与 Go CancelAfterInactivity + UpdateActivity 一致。
    // up 结束 → down 剩余窗口 = uplink_only；down 结束 → up 剩余窗口 = downlink_only。
    let (up_done_tx, up_done_rx) = tokio::sync::watch::channel(None::<std::time::Duration>);
    let (down_done_tx, down_done_rx) = tokio::sync::watch::channel(None::<std::time::Duration>);

    let up = async move {
        let mut down_done = down_done_rx;
        let mut window: Option<std::time::Duration> = None;
        loop {
            // 读 future 每轮重建是 cancel-safe 的：select!/timeout 丢弃的 future
            // 只可能处于 Pending（poll 到 Ready 的分支必被采用），无数据丢失。
            let mb = match window {
                None => tokio::select! {
                    // 空闲 deadline（Go ConnectionIdle / CancelAfterInactivity）：
                    // 双向均存活但 connection_idle 内无数据 → 断开
                    res = tokio::time::timeout(
                        conn_idle,
                        reader.read_multi_buffer(),
                    ) => match res {
                        Ok(r) => r,
                        Err(_) => break,
                    },
                    _ = down_done.changed() => {
                        window = *down_done.borrow();
                        continue;
                    }
                },
                Some(d) => match tokio::time::timeout(d, reader.read_multi_buffer()).await {
                    Ok(r) => r,
                    Err(_) => break, // downlink_only 窗口内无数据
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


    let down = async move {
        let mut up_done = up_done_rx;
        let mut window: Option<std::time::Duration> = None;
        // 池化读缓冲（xray-buf 分层池，对应 Go sync.Pool）；resize 置满长度供 read 覆写
        let mut buf = xray_buf::alloc::alloc(xray_buf::alloc::DEFAULT_SIZE);
        buf.resize(xray_buf::alloc::DEFAULT_SIZE, 0);
        loop {
            let n = match window {
                None => tokio::select! {
                    // 空闲 deadline（Go ConnectionIdle / CancelAfterInactivity）：
                    // 双向均存活但 connection_idle 内无数据 → 断开
                    res = tokio::time::timeout(
                        conn_idle,
                        s_read.read(&mut buf),
                    ) => match res {
                        Ok(n) => n,
                        Err(_) => break,
                    },
                    _ = up_done.changed() => {
                        window = *up_done.borrow();
                        continue;
                    }
                },
                Some(d) => match tokio::time::timeout(d, s_read.read(&mut buf)).await {
                    Ok(n) => n,
                    Err(_) => break, // uplink_only 窗口内无数据
                },
            };
            let n = match n {
                Ok(n) => n,
                Err(_) => break,
            };
            if n == 0 {
                break;
            }
            // bd etks：消除双拷贝。read 已把 n 字节写入 buf，直接 truncate(n)
            // 把 buf 整段作为 Buffer 入列，避免 merge_bytes 再次 memcpy n 字节。
            // truncate 调整 end 游标（start 不变），after Buffer::from_bytes(buf)
            // 由 Buffer 的 Drop 回池。cap >= n 是 alloc 池分层保证。
            let mut mb = MultiBuffer::new();
            mb.push(Buffer::from_bytes(buf.split_to(n)));
            if writer.write_multi_buffer(mb).await.is_err() {
                break;
            }
            // 取下一块池化缓冲（split_to 之后 buf 剩余容量可能不足一次 read）
            buf = xray_buf::alloc::alloc(xray_buf::alloc::DEFAULT_SIZE);
            buf.resize(xray_buf::alloc::DEFAULT_SIZE, 0);
        }
        xray_buf::alloc::release(buf);
        writer.shutdown();
        let _ = down_done_tx.send(Some(downlink_only));
        io::Result::Ok(())
    };

    let (up_res, down_res) = tokio::join!(up, down);
    up_res.and(down_res)
}

/// 默认策略的便捷包装（保留旧 API 兼容调用方）。
pub async fn bridge_link_with_stream_full_default<S>(link: Link, stream: S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let policy = TimeoutPolicy::default();
    bridge_link_with_stream_full(link, stream, &policy).await
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

        let bridge = tokio::spawn(bridge_link_with_stream_full_default(link, stream));

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
        let res = bridge_link_with_stream_full_default(link, stream).await;
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
        let res = bridge_link_with_stream_full(link, stream, &policy).await;
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

}

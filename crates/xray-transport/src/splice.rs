//! libc splice(2) 零拷贝泵 —— Go `proxy.CopyRawConnIfExist` splice 分支等价物。
//!
//! Go 证据：`proxy/proxy.go:743-774`（`tc.ReadFrom(readerConn)` 内核内部 splice +
//! 运行时 pipe 池 + 计数器）、`:722-724`（非 linux/android 回退 readV）、
//! `:802-809`（IsRAWTransportWithoutSecurity 判定；注意 Go CopyRawConnIfExist
//! 在 :725 还要求 writerConn 为 `*net.TCPConn`，故实际 splice 准入是 TCP-only，
//! UnixConnWrapper 在 Go 也会落到 readV——本模块 `is_raw_tcp` 口径与之等效）。
//!
//! Rust 形态：[`crate::connection::Connection::raw_tcp_clone`] 取两端裸 TCP 克隆 +
//! 自建 `O_NONBLOCK` pipe 中转，双向各一条 splice 流水线（票 4qjw 第 3 项
//! 「双向零拷贝泵」）。决策面（env/平台/CanSpliceCopy）在
//! [`xray_common::platform::splice`]；本模块只做 syscall 与搬运。
//!
//! 平台：splice(2)/pipe2 仅 Linux/Android 编译；其余平台本文件整体 cfg 出空
//! 模块，闸门恒回退既有泵（Windows/包装连接现状零变化）。
//!
//! EAGAIN 取舍（票 4qjw 第 4 项）：`raw_tcp_clone` 返回的 tokio TcpStream 已在
//! reactor 注册，`readable()/writable()` 提供真实 waker——故采用 readiness 驱动
//! 重试而非「阻塞 + 短期轮询」；pipe 自身 `O_NONBLOCK` 保证 executor 线程绝不
//! 在 pipe 满/空时阻塞。`splice` 返回 0 = EOF（写端有序关闭）。

#![cfg(any(target_os = "linux", target_os = "android"))]

pub use imp::{bridge_with, plan, splice_copy};

mod imp {
    use std::io;
    use std::net::SocketAddr;
    use std::os::unix::io::AsRawFd;
    use tokio::net::TcpStream;

    use crate::connection::Connection;
    use xray_common::platform::splice::splice_allowed;

    /// Linux 默认 pipe 容量（16 × 4KiB）。仅在 `pending < PIPE_CAP` 时尝试
    /// fill，规避 pipe 满导致的 EAGAIN 空转（内核容量被调小到低于此值时，
    /// fill 的 EAGAIN 也会在同一轮触发 drain，不产生热循环）。
    const PIPE_CAP: usize = 64 * 1024;

    /// SAFETY：两个 fd 均为调用方持有且存活的打开描述符；偏移传 NULL
    /// （socket/pipe 不可定位，内核取当前位移），`SPLICE_F_MOVE` 页 stealing。
    fn splice_raw(fd_in: i32, fd_out: i32, len: usize) -> isize {
        unsafe {
            libc::splice(
                fd_in,
                std::ptr::null_mut(),
                fd_out,
                std::ptr::null_mut(),
                len,
                libc::SPLICE_F_MOVE,
            )
        }
    }

    fn is_eagain(err: &io::Error) -> bool {
        err.kind() == io::ErrorKind::WouldBlock
    }

    /// 单向 splice 泵：`from` → pipe → `to`（Go `TCPConn.ReadFrom` 等价）。
    ///
    /// 循环不变量：`pending` = pipe 中在途字节；`pending < PIPE_CAP` 时 pipe
    /// 必有空间，fill 返回 0 只能是 `from` EOF；`pending > 0` 时 pipe 必有
    /// 数据，drain 不会因空 pipe 假 EAGAIN。任一端 IO 错误原样上抛。
    pub async fn splice_copy(from: &TcpStream, to: &TcpStream) -> io::Result<u64> {
        let mut fds: [libc::c_int; 2] = [0; 2];
        // O_NONBLOCK：socket 侧本就非阻塞；pipe 侧非阻塞使满/空均 EAGAIN，
        // 交由下方 readiness 等待，绝不阻塞 executor 线程。
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK) } != 0 {
            return Err(io::Error::last_os_error());
        }
        struct PipeFds([libc::c_int; 2]);
        impl Drop for PipeFds {
            fn drop(&mut self) {
                // SAFETY：构造成功后两个 fd 均有效，各关一次。
                unsafe {
                    libc::close(self.0[0]);
                    libc::close(self.0[1]);
                }
            }
        }
        let pipe = PipeFds(fds);
        let (pr, pw) = (pipe.0[0], pipe.0[1]);

        let (from_fd, to_fd) = (from.as_raw_fd(), to.as_raw_fd());
        let mut pending: usize = 0;
        let mut eof = false;
        let mut total: u64 = 0;

        while pending > 0 || !eof {
            if !eof && pending < PIPE_CAP {
                match splice_raw(from_fd, pw, PIPE_CAP - pending) {
                    n if n > 0 => {
                        pending += n as usize;
                        total += n as u64;
                    }
                    0 => eof = true,
                    n if n < 0 => {
                        let err = io::Error::last_os_error();
                        if is_eagain(&err) {
                            from.readable().await?; let _ = from.try_read(&mut []);
                        } else {
                            return Err(err);
                        }
                    }
                    _ => unreachable!(),
                }
            }
            if pending > 0 {
                match splice_raw(pr, to_fd, pending) {
                    n if n > 0 => pending -= n as usize,
                    n if n < 0 => {
                        let err = io::Error::last_os_error();
                        if is_eagain(&err) {
                            to.writable().await?; let _ = to.try_write(&mut []);
                        } else {
                            return Err(err);
                        }
                    }
                    // pending>0 且 pipe 读端非阻塞：0 不可达。万一命中（内核态
                    // 异常），大声报错终止而非静默原地空转。
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "splice: pipe underflow (pending>0 but drain returned 0)",
                        ));
                    }
                }
            }
        }
        Ok(total)
    }

    /// 闸门 + 取裸克隆（Go proxy.go:722-741 前置条件串）。返回 `None` =
    /// 任一条件不满足，调用方回退既有泵（对应 Go 回退 readV）。
    pub fn plan(
        a: &dyn Connection,
        b: &dyn Connection,
        inbound_can: i32,
        outbounds_can: &[i32],
    ) -> Option<(TcpStream, TcpStream)> {
        if !splice_allowed(inbound_can, outbounds_can) {
            return None; // env 未启用 / 非 Linux·Android / CanSpliceCopy 信号不足
        }
        if !a.is_raw_tcp() || !b.is_raw_tcp() {
            return None; // 包装连接不启用（Go IsRAWTransportWithoutSecurity）
        }
        Some((a.raw_tcp_clone()?, b.raw_tcp_clone()?))
    }

    /// 双向 splice 桥：两方向独立流水线，任一方向 EOF/错误即整体返回
    /// （与 [`crate::bridge::bridge_connections`] 的 select! 语义一致；
    /// Go 是单向下行 splice + 上行独立 buf.Copy 并行，此处合并为同一泵）。
    pub async fn bridge_with(a_raw: TcpStream, b_raw: TcpStream) -> io::Result<u64> {
        let up = splice_copy(&a_raw, &b_raw);
        let down = splice_copy(&b_raw, &a_raw);
        tokio::pin!(up, down);
        tokio::select! { res = &mut up => res, res = &mut down => res }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use std::net::SocketAddr;
    use std::io;
    use super::imp::{bridge_with, plan, splice_copy};
    use crate::connection::{Connection, TcpConnection};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// 起一对回环连接：(本端持有 socket, 其对端 socket)。
    async fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    /// 回环 echo：splice_copy(client, server) 把 client 发来的数据从
    /// client 收包队列内核直搬到 server 发包队列 → 回到 client。
    /// 泵运行在 dup 出的独立 handle 上，原 socket 留给 IO 半部。
    #[tokio::test]
    async fn splice_copy_moves_payload_kernel_side() {
        // 双腿拓扑：泵桥接两条独立回环连接的服务端腿（sa_RX -> sb_TX）。
        // 单对 socket 自泵 = 输出回灌输入（TX 经内核回到本对 RX），拓扑上
        // 必然自循环——splice 泵的最小合法通路必须两条独立腿。
        let (a, sa) = loopback_pair().await;
        let (b, sb) = loopback_pair().await;
        let sa_for_pump = crate::connection::dup_tcp_stream(&sa).unwrap();
        let sb_for_pump = crate::connection::dup_tcp_stream(&sb).unwrap();
        // 256KiB > PIPE_CAP(64KiB)，强制多轮 fill/drain
        let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
        let expect = payload.clone();

        let pump = tokio::spawn(async move {
            splice_copy(&sa_for_pump, &sb_for_pump).await.unwrap()
        });

        // A 端独立任务写满并关写端（EOF 驱动泵退出）；B 端 read_exact 逐字节校验。
        let writer = tokio::spawn(async move {
            let (_ar, mut aw) = a.into_split();
            aw.write_all(&payload).await.unwrap();
            aw.shutdown().await.unwrap();
        });

        let mut got = vec![0u8; expect.len()];
        {
            let (mut br, _bw) = tokio::io::split(b);
            br.read_exact(&mut got).await.unwrap();
        }
        writer.await.unwrap();
        let moved = pump.await.unwrap();
        assert_eq!(got, expect, "内容逐字节一致");
        assert_eq!(moved, expect.len() as u64, "泵计数应等于载荷");
    }

    /// 双向桥 + 闸门全绿：两端各写各读，内容互达。
    #[tokio::test]
    async fn bridge_with_moves_both_directions() {
        let (c1, s1) = loopback_pair().await;
        let (c2, s2) = loopback_pair().await;

        let bridge = tokio::spawn(async move { bridge_with(s1, s2).await.unwrap() });

        let left = tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(c1);
            w.write_all(b"ping-from-left").await.unwrap();
            let mut buf = [0u8; 14];
            r.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong-from-righ");
        });
        let right = tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(c2);
            let mut buf = [0u8; 14];
            r.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping-from-left");
            w.write_all(b"pong-from-righ").await.unwrap();
        });
        left.await.unwrap();
        right.await.unwrap();
        bridge.await.unwrap();
    }

    /// 闸门判定：信号不足 → None；裸 TCP + freedom 信号（freedom.go:260 置 1）
    /// → Some（测试进程未设 xray.buf.splice → env 缺省开）。
    #[tokio::test]
    async fn plan_gate_conditions() {
        let (a, b) = loopback_pair().await;
        let ca = TcpConnection::new(a);
        let cb = TcpConnection::new(b);

        // CanSpliceCopy 信号不足（Go 零值 0 / vless 2 / 3）→ 不启用
        assert!(plan(&ca, &cb, 0, &[]).is_none());
        assert!(plan(&ca, &cb, 1, &[0]).is_none());
        assert!(plan(&ca, &cb, 2, &[1]).is_none());
        assert!(plan(&ca, &cb, 1, &[1]).is_some());
    }

    /// 包装连接不启用：raw_tcp_clone 穿透返回 Some 也必须被 is_raw_tcp 拒绝
    /// （Go IsRAWTransportWithoutSecurity 对 tls.Conn 为 false 的等价保护——
    /// 否则 splice 会把明文搬进密文通道，协议流损坏）。
    #[tokio::test]
    async fn plan_rejects_wrapped_connection() {
        struct TlsLookalike(TcpStream);
        impl tokio::io::AsyncRead for TlsLookalike {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
            }
        }
        impl tokio::io::AsyncWrite for TlsLookalike {
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
        impl Connection for TlsLookalike {
            fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
                self.0.peer_addr().map(Some)
            }
            fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
                self.0.local_addr().map(Some)
            }
            // raw_tcp_clone 穿透（TLS 包装层的真实形态），但 is_raw_tcp 保持
            // 默认 false —— splice 准入必须拒绝。
            fn raw_tcp_clone(&self) -> Option<TcpStream> {
                crate::connection::dup_tcp_stream(&self.0)
            }
        }

        let (a, b) = loopback_pair().await;
        let wrapped = TlsLookalike(a);
        let bare = TcpConnection::new(b);
        assert!(!wrapped.is_raw_tcp());
        assert!(wrapped.raw_tcp_clone().is_some());
        assert!(plan(&wrapped, &bare, 1, &[1]).is_none());
        assert!(plan(&bare, &wrapped, 1, &[1]).is_none());
    }
}

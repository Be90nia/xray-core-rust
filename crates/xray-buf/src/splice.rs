//! Linux splice(2) 零拷贝桥接。
//!
//! 仅 Linux/Android 可用。其他平台 fallback 到 `tokio::io::copy`。
//!
//! ponytail: socket→pipe→socket 仍有一次内核内拷贝（pipe buffer），
//! 但避免了 user↔kernel 拷贝。升级路径：用 AsyncFd 做事件驱动等待。

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::os::fd::{AsFd, BorrowedFd};
    use std::time::Duration;

    use nix::fcntl::{splice, SpliceFFlags};
    use nix::unistd::pipe2;

    const SPLICE_CHUNK: usize = 64 * 1024;
    const BACKOFF: Duration = Duration::from_millis(1);

    fn splice_one_way(
        fd_in: BorrowedFd<'_>, fd_out: BorrowedFd<'_>,
        pipe_read: BorrowedFd<'_>, pipe_write: BorrowedFd<'_>,
    ) -> io::Result<u64> {
        let flags = SpliceFFlags::SPLICE_F_NONBLOCK;
        let mut total: u64 = 0;
        loop {
            match splice(fd_in, None, &pipe_write, None, SPLICE_CHUNK, flags) {
                Ok(0) => return Ok(total),
                Ok(n) => {
                    let mut rem = n;
                    while rem > 0 {
                        match splice(&pipe_read, None, fd_out, None, rem, flags) {
                            Ok(w) => { rem -= w; total += w as u64; }
                            Err(nix::errno::Errno::EAGAIN) => std::thread::sleep(BACKOFF),
                            Err(e) => return Err(io::Error::from_raw_os_error(e as i32)),
                        }
                    }
                }
                Err(nix::errno::Errno::EAGAIN) => std::thread::sleep(BACKOFF),
                Err(nix::errno::Errno::EPIPE) => return Ok(total),
                Err(e) => return Err(io::Error::from_raw_os_error(e as i32)),
            }
        }
    }

    pub async fn splice_copy_bidirectional<A, B>(a: A, b: B) -> io::Result<(u64, u64)>
    where
        A: AsFd + Send + 'static,
        B: AsFd + Send + 'static,
    {
        tokio::task::spawn_blocking(move || {
            let a_fd = a.as_fd();
            let b_fd = b.as_fd();
            let (pr, pw) = pipe2(nix::fcntl::OFlag::O_NONBLOCK)
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            let a2b = splice_one_way(a_fd, b_fd, pr.as_fd(), pw.as_fd())?;
            let b2a = splice_one_way(b_fd, a_fd, pr.as_fd(), pw.as_fd())?;
            Ok((a2b, b2a))
        })
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
    }
}

#[cfg(target_os = "linux")]
pub use linux::splice_copy_bidirectional;

#[cfg(not(target_os = "linux"))]
mod fallback {
    use std::io;
    use tokio::io::{AsyncRead, AsyncWrite};

    pub async fn splice_copy_bidirectional<A, B>(mut a: A, mut b: B) -> io::Result<(u64, u64)>
    where
        A: AsyncRead + AsyncWrite + Unpin,
        B: AsyncRead + AsyncWrite + Unpin,
    {
        tokio::io::copy_bidirectional(&mut a, &mut b).await
    }
}

#[cfg(not(target_os = "linux"))]
pub use fallback::splice_copy_bidirectional;

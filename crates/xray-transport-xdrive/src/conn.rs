//! `Conn`——xdrive 连接抽象：写侧 WAL + 读侧 WAL 的会话封装。
//! 对应 Go `conn.go`（`newConn`；`newSlotConn` 属 B5）。
//!
//! 与 Go `net.Conn` 的接口差：Rust `Connection` trait 无 SetDeadline 族——
//! 读阻塞由 WAL 空洞超时/会话 TTL 兜底，语义等价于 Go 未设 deadline 的调用面。
//!
//! 关闭序（Go `Close`）：writer 冲净 + `.end` → 取消任务 → storage 收尾。
//! `poll_shutdown` 驱动完整序；裸 `Drop` 兜底走同一 future（compat 托管口）。

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use skeleton_infra::fx::{CancelSource, CancelToken, ScopeClosed, cancel_pair};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xray_frame::scope::ComponentScope;
use xray_transport::connection::Connection;

use crate::{
    LOG,
    params::Params,
    storage::Storage,
    wal::{WalReader, WalWriter},
};

/// 每会话任务面（Go `context.WithCancel` 的 Rust 对应）：`ComponentScope`
/// 托管账本 + 显式取消对。连接/监听器共用同一形态（§3.5.6 ①类）。
#[derive(Clone)]
pub(crate) struct SessionTasks {
    pub(crate) scope: ComponentScope,
    pub(crate) cancel: Arc<CancelSource>,
    pub(crate) token: CancelToken,
}

impl SessionTasks {
    pub(crate) fn new(label: &str) -> Self {
        let (cancel, token) = cancel_pair();
        Self { scope: ComponentScope::new(label.to_string()), cancel: Arc::new(cancel), token }
    }

    /// 托管 spawn（唯一口；取消语义由任务体经 `token` 自查）。
    pub(crate) fn spawn(
        &self,
        fut: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), ScopeClosed> {
        self.scope.spawn(fut).map(|_| ())
    }

    /// 关闭（Go `cancel()`）：取消 + 关闸，双档一次到位。
    pub(crate) fn close(&self) {
        self.cancel.cancel();
        self.scope.close_gate();
    }
}

/// 关闭序 future 类型（`poll_shutdown` 与裸 Drop 兜底共用；`Connection: Sync`
/// 由外层 `parking_lot::Mutex` 保证，future 本体只需 Send）。
type ShutdownFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

/// xdrive 连接（Go `Conn` 的 WAL 路径）。
pub struct Conn {
    writer: Arc<WalWriter>,
    reader: WalReader,
    storage: Arc<dyn Storage>,
    tasks: SessionTasks,
    /// 关闭回调（Go `onClose`：listener 摘 active 簿记；shutdown/Drop 恰一次）。
    on_close: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
    /// 上次读未消费完的段残余（Go `readBuf`）。
    read_buf: Vec<u8>,
    /// `poll_shutdown` 的驱动状态（Go `Close` 的 async 化载体；Mutex 供
    /// `Connection: Sync`——关闭 future 本体只需 Send）。
    shutdown: parking_lot::Mutex<Option<ShutdownFuture>>,
}

impl Conn {
    /// WAL 路径构造（Go `newConn`）并启动双侧 WAL 循环。
    #[must_use]
    pub(crate) fn new_wal(
        storage: Arc<dyn Storage>,
        write_prefix: &str,
        read_prefix: &str,
        params: &Params,
        label: &str,
        on_close: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
    ) -> Self {
        let tasks = SessionTasks::new(label);
        let writer = WalWriter::new(Arc::clone(&storage), write_prefix, params, tasks.clone());
        let reader = WalReader::new(Arc::clone(&storage), read_prefix, params, tasks.clone());
        Self {
            writer,
            reader,
            storage,
            tasks,
            on_close,
            read_buf: Vec::new(),
            shutdown: parking_lot::Mutex::new(None),
        }
    }

    /// Go `Close` 的关闭序 future（poll_shutdown 与裸 Drop 共用；`on_close` 被
    /// take——关闭序恰触发一次）。
    fn build_shutdown_future(&mut self) -> ShutdownFuture {
        let writer = Arc::clone(&self.writer);
        let storage = Arc::clone(&self.storage);
        let tasks = self.tasks.clone();
        let on_close = self.on_close.take();
        Box::pin(async move {
            let close_result = writer.close().await;
            tasks.close();
            if let Some(on_close) = on_close {
                on_close();
            }
            let storage_result = storage.close().await;
            match close_result {
                Ok(()) => storage_result,
                Err(e) => Err(e),
            }
        })
    }
}

impl AsyncRead for Conn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.read_buf.is_empty() {
            match this.reader.poll_chunk(cx) {
                Poll::Ready(Some(chunk)) => this.read_buf = chunk,
                Poll::Ready(None) => {
                    return match this.reader.take_err() {
                        Some(e) => Poll::Ready(Err(e)),
                        // 通道闭且无错误 = 对端 `.end`（Go io.EOF）
                        None => Poll::Ready(Ok(())),
                    };
                },
                Poll::Pending => return Poll::Pending,
            }
        }
        let n = buf.remaining().min(this.read_buf.len());
        buf.put_slice(&this.read_buf[..n]);
        this.read_buf.drain(..n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // 写是同步入缓冲（切段上传在后台；背压由上传闸+读端节流承载，Go 同款）。
        match this.writer.write(buf) {
            Ok(n) => {
                this.reader.wake();
                Poll::Ready(Ok(n))
            },
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // 实际落盘由 writer flush 循环按周期/满段推进；无本地半成品可推。
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // 先判断再独占构建（build 需要独占 self，须在持锁窗口外完成）。
        let has = this.shutdown.lock().is_some();
        if !has {
            let built = this.build_shutdown_future();
            *this.shutdown.lock() = Some(built);
        }
        let mut slot = this.shutdown.lock();
        match slot.as_mut() {
            Some(fut) => fut.as_mut().poll(cx),
            None => Poll::Ready(Err(io::Error::other("xdrive conn: shutdown slot vanished"))),
        }
    }
}

impl Connection for Conn {
    fn remote_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        // Go placeholderAddr：127.0.0.1:0（xdrive 无真实 socket）。
        Ok(Some(std::net::SocketAddr::from(([127, 0, 0, 1], 0))))
    }

    fn local_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        Ok(Some(std::net::SocketAddr::from(([127, 0, 0, 1], 0))))
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        // 裸丢弃（未经 poll_shutdown）：关闭序兜底——尽力冲净并落 `.end`
        //（Go 侧未调 Close 的丢弃连冲净都没有，此处更好）。runtime 已拆
        //（进程停机尾段）时跳过：循环任务已随之消亡，无从冲净。
        self.tasks.close();
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let fut = self.build_shutdown_future();
        if let Err(e) = xray_frame::compat::spawn(async move {
            let _ = fut.await;
        }) {
            LOG.warn(format!("xdrive conn: shutdown on drop rejected: {e}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;
    use crate::{config::Config, local::LocalStorage};

    fn test_params() -> Params {
        Params::from_config(&Config {
            service: "local".to_string(),
            poll_interval_ms: 5,
            flush_interval_ms: 5,
            segment_bytes: 4096,
            session_ttl_seconds: 60,
            ..Config::default()
        })
    }

    /// 同进程双 Conn 经 LocalStorage 往返：写侧 c2s → 读侧 c2s；EOF 经 `.end`。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn conn_wal_roundtrip_between_two_conns() {
        let root = std::env::temp_dir().join(format!("xdrive-conn-{}", std::process::id()));
        let storage: Arc<dyn Storage> =
            Arc::new(LocalStorage::new(root.to_string_lossy().as_ref()).unwrap());
        let params = test_params();

        let mut writer_conn = Conn::new_wal(
            Arc::clone(&storage),
            "streams/t1/c2s",
            "streams/t1/s2c",
            &params,
            "xdrive-test-writer",
            None,
        );
        let mut reader_conn = Conn::new_wal(
            Arc::clone(&storage),
            "streams/t1/s2c",
            "streams/t1/c2s",
            &params,
            "xdrive-test-reader",
            None,
        );

        // 写侧写入（跨段：>1 个 segment_bytes），读侧读出全部。
        let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        writer_conn.write_all(&payload).await.unwrap();

        let mut received = Vec::new();
        let mut chunk = [0u8; 1024];
        while received.len() < payload.len() {
            let n = reader_conn.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(received.len(), payload.len());
        assert_eq!(received, payload);

        // 关闭写侧 → `.end` → 读侧 EOF。
        writer_conn.shutdown().await.unwrap();
        let n = reader_conn.read(&mut chunk).await.unwrap();
        assert_eq!(n, 0, "closed writer must surface EOF");
        reader_conn.shutdown().await.unwrap();

        let _ = std::fs::remove_dir_all(root);
    }
}

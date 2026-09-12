//! Scatter/gather (readv) 缓冲区读取
//!
//! 对应 Go `common/buf/readv_reader.go` + `readv_posix.go` + `readv_windows.go`。
//!
//! 真实现路径（bd 2o9l）：TCP socket 读半部用 tokio `readable()` + `try_read_vectored`
//! ——Unix 走 `readv(2)`，Windows 走 `WSARecv`——一次系统调用把数据分散填入多个
//! 池化 Buffer（[`AllocStrategy`] 对齐 Go allocStrategy，≤8 缓冲按需扩容）。
//! 非 TCP 源未覆写 `poll_read_vectored` 时走 tokio 默认实现（顺序填充首缓冲），
//! 行为等价 Go `NewReader` 无 `syscall.Conn` 时退回 `SingleReader`（io.go:124-145）。
//!
//! env 闸门 `xray.buf.readv`（alt `XRAY_BUF_READV`）语义对齐 Go
//! readv_reader.go:153-163：未设置 / `auto` / `enable` → 启用；其他任何值 → 禁用。

use std::future::Future;
use std::io::{ErrorKind, IoSliceMut};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::net::tcp::OwnedReadHalf;

use crate::buffer::Buffer;
use crate::io::{self, Reader, Result};
use crate::multi::MultiBuffer;

// ========== env 闸门（Go readv_reader.go:147-163） ==========

static USE_READV: AtomicBool = AtomicBool::new(true);

/// 读取 `xray.buf.readv` 环境闸门当前值。
///
/// 语义对齐 Go `useReadV()`：未设置（默认）/ `auto` / `enable` → 启用；
/// 其他任何值 → 禁用（顺序读）。
#[inline]
pub fn use_readv() -> bool {
    USE_READV.load(Ordering::Relaxed)
}

/// 重新解析 env 闸门。对应 Go `reloadEnvSettings`（经 platform.RegisterEnvReload
/// 注册；我们无注册机制，进程启动后环境变更需显式调用）。
pub fn reload_env_settings() {
    let v = std::env::var("xray.buf.readv")
        .or_else(|_| std::env::var("XRAY_BUF_READV"))
        .ok();
    USE_READV.store(parse_readv_flag(v.as_deref()), Ordering::Relaxed);
}

/// Go readv_reader.go:154-160 的 switch 翻译：env 未设置 / auto / enable → 启用。
fn parse_readv_flag(v: Option<&str>) -> bool {
    match v {
        None => true,
        Some(s) => matches!(s, "auto" | "enable"),
    }
}

// ========== AllocStrategy（Go readv_reader.go:15-45） ==========

/// readv 读取的缓冲区数量自适应策略。对应 Go `allocStrategy`。
///
/// 语义：`current` 从 1 开始；[`Self::adjust`] 按"填满的缓冲数 ≥ current 则翻倍，
/// 否则收敛到填满数"调整，上界 8、下界 1。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocStrategy {
    current: u32,
}

impl Default for AllocStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl AllocStrategy {
    /// 对应 Go `allocStrategy{current: 1}`。
    #[must_use]
    pub const fn new() -> Self {
        Self { current: 1 }
    }

    /// 对应 Go `Current()`。
    #[must_use]
    pub const fn current(&self) -> u32 {
        self.current
    }

    /// 对应 Go `Adjust(n)`（readv_reader.go:23-37）。
    pub fn adjust(&mut self, n: u32) {
        self.current = if n >= self.current {
            self.current * 2
        } else {
            n
        };
        if self.current > 8 {
            self.current = 8;
        }
        if self.current == 0 {
            self.current = 1;
        }
    }

    /// 分配 `current` 个池化空 Buffer。对应 Go `Alloc()`。
    #[must_use]
    pub fn alloc(&self) -> Vec<Buffer> {
        (0..self.current).map(|_| Buffer::new()).collect()
    }
}

// ========== iovec 构建 + 字节分发（对应 Go posixReader.Init / readMulti 尾部循环） ==========

/// 把每个 Buffer 的可写区拼成 `read_vectored` 的 iovec 数组。
///
/// 返回 `(slices, lens)`：`lens[i]` 是第 i 个 iovec 的长度（分发起始容量），
/// 供 [`distribute`] 按序分配读取到的字节数。Buffer 内存由池提供（8KB 分层），
/// readv 直写池化内存，无每段堆分配（对应 Go 直写 `bs[nBuf].v`）。
pub fn buffer_iovecs(bufs: &mut [Buffer]) -> (Vec<IoSliceMut<'_>>, Vec<usize>) {
    let mut slices = Vec::with_capacity(bufs.len());
    let mut lens = Vec::with_capacity(bufs.len());
    for b in bufs.iter_mut() {
        let w = b.writable_bytes();
        lens.push(w.len());
        slices.push(IoSliceMut::new(w));
    }
    (slices, lens)
}

/// 把一次读取的 `n` 字节按序分配进各 Buffer，产出 `MultiBuffer`。
///
/// 对应 Go readv_reader.go:101-118：前 `nBuf` 个缓冲按 `min(remaining, Size)` 推进
/// 写游标，其余释放回池。`bufs` 被消费置空，无数据的段不进入结果。
pub fn distribute(n: usize, bufs: &mut Vec<Buffer>, lens: &[usize]) -> MultiBuffer {
    let mut remaining = n;
    let mut mb = MultiBuffer::with_capacity(bufs.len());
    for (i, mut buf) in std::mem::take(bufs).into_iter().enumerate() {
        if remaining == 0 {
            buf.release();
            continue;
        }
        let take = remaining.min(lens[i]);
        buf.advance_write(take);
        remaining -= take;
        mb.push(buf);
    }
    mb
}

/// 全部缓冲释放回池（EOF / 错误路径）。对应 Go `ReleaseMulti`。
fn release_all(bufs: &mut Vec<Buffer>) {
    for mut b in std::mem::take(bufs) {
        b.release();
    }
}

// ========== ReadVReader（Go readv_reader.go:53-145） ==========

/// Scatter-gather 读取器，对应 Go `ReadVReader`。
///
/// 持有 TCP 读半部（Rust 侧等价 Go 的 `io.Reader + syscall.RawConn` 对）：
/// `current == 1` 时单缓冲读（Go ReadBuffer 分支），填满即扩容到 2；
/// `current >= 2` 时一次 `readv` 填多缓冲，按实填数调整策略。
pub struct ReadVReader {
    src: OwnedReadHalf,
    alloc: AllocStrategy,
}

impl ReadVReader {
    /// 对应 Go `NewReadVReader`。
    #[must_use]
    pub fn new(src: OwnedReadHalf) -> Self {
        Self {
            src,
            alloc: AllocStrategy::new(),
        }
    }

    /// 当前分配策略（测试与观测用）。
    #[must_use]
    pub const fn alloc_strategy(&self) -> &AllocStrategy {
        &self.alloc
    }

    /// 就绪等待 + 非阻塞 `readv` 循环。
    ///
    /// tokio 语义：`try_read_vectored` 返回 `WouldBlock` 时已消费 readiness，
    /// 回到 `readable()` 重新注册 waker，不空转。
    async fn read_vectored_ready(&self, slices: &mut [IoSliceMut<'_>]) -> std::io::Result<usize> {
        loop {
            self.src.readable().await?;
            match self.src.try_read_vectored(slices) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// 对应 Go `ReadVReader.ReadMultiBuffer`（readv_reader.go:124-145）。
    pub async fn read_multi(&mut self) -> Result<MultiBuffer> {
        // Go 以 current==1 分流：单缓冲读（填满才扩容）vs 多缓冲 readv（按实填数调整）。
        // 分支判定在入口取快照，读后按各自分支调整一次（对齐 Go :127-129 / :143）。
        let single = self.alloc.current() == 1;

        let mut bufs = self.alloc.alloc();
        let (mut slices, lens) = buffer_iovecs(&mut bufs);
        let n = self.read_vectored_ready(&mut slices).await.map_err(|e| {
            release_all(&mut bufs);
            io::classify_io_error(e, true)
        })?;

        if n == 0 {
            // 对应 Go `nBytes == 0 → io.EOF`；本 crate 约定：空 MultiBuffer 表示 EOF。
            release_all(&mut bufs);
            return Ok(MultiBuffer::new());
        }

        let mb = distribute(n, &mut bufs, &lens);
        if single {
            // Go :127-129：单缓冲读填满（IsFull）→ Adjust(1) → 扩到 2，下次起用 readv。
            if n >= lens[0] {
                self.alloc.adjust(1);
            }
        } else {
            // Go :143：多缓冲读按实填缓冲数调整。
            self.alloc.adjust(mb.buffer_count() as u32);
        }
        Ok(mb)
    }
}

impl Reader for ReadVReader {
    fn read_multi_buffer(&mut self) -> Pin<Box<dyn Future<Output = Result<MultiBuffer>> + Send + '_>>
    {
        Box::pin(self.read_multi())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// env 相关测试（含全局 AtomicBool 翻转）串行化，避免并行互踩。
    static ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[test]
    fn readv_flag_parsing_go_semantics() {
        // Go readv_reader.go:154-160：默认值 / auto / enable → true，其余 → false。
        assert!(parse_readv_flag(None));
        assert!(parse_readv_flag(Some("auto")));
        assert!(parse_readv_flag(Some("enable")));
        assert!(!parse_readv_flag(Some("disable")));
        assert!(!parse_readv_flag(Some("false")));
        assert!(!parse_readv_flag(Some("0")));
        assert!(!parse_readv_flag(Some("")));
        assert!(!parse_readv_flag(Some("enabled"))); // 精确匹配，无前缀语义
    }

    #[test]
    fn alloc_strategy_go_adjust_sequence() {
        // 逐步复刻 Go allocStrategy.Adjust 的扩容/收敛序列。
        let mut s = AllocStrategy::new();
        assert_eq!(s.current(), 1);

        // 单缓冲填满 → Adjust(1)：1>=1 翻倍 → 2
        s.adjust(1);
        assert_eq!(s.current(), 2);
        // 2 缓冲全填 → Adjust(2)：2>=2 翻倍 → 4
        s.adjust(2);
        assert_eq!(s.current(), 4);
        s.adjust(4);
        assert_eq!(s.current(), 8);
        // 顶格：8>=8 翻倍 16 → 钳 8
        s.adjust(8);
        assert_eq!(s.current(), 8);
        // 收敛：填满数小于 current → 取填满数
        s.adjust(3);
        assert_eq!(s.current(), 3);
        s.adjust(1);
        assert_eq!(s.current(), 1);
        // 再满 → 升 2
        s.adjust(1);
        assert_eq!(s.current(), 2);
        // 下界保护：n=0 不会钳出 0
        s.adjust(0);
        assert_eq!(s.current(), 1);
    }

    #[test]
    fn distribute_byte_conservation_and_release() {
        // 分发守恒：n 字节按 iovec 容量切进各 Buffer，尾部空缓冲释放。
        let mut bufs: Vec<Buffer> = (0..4).map(|_| Buffer::new()).collect();
        let lens: Vec<usize> = bufs.iter().map(|b| b.capacity()).collect();
        let cap = lens[0];

        // 恰好 2.5 个缓冲的量
        let n = cap * 2 + cap / 2;
        let mb = distribute(n, &mut bufs, &lens);
        assert_eq!(mb.len(), n);
        assert_eq!(mb.buffer_count(), 3);
        assert!(bufs.is_empty()); // 全部被消费（尾部释放）

        // n=0：全部释放，空 MultiBuffer
        let mut bufs: Vec<Buffer> = (0..2).map(|_| Buffer::new()).collect();
        let lens2: Vec<usize> = bufs.iter().map(|b| b.capacity()).collect();
        let mb = distribute(0, &mut bufs, &lens2);
        assert!(mb.is_empty());
        assert!(bufs.is_empty());
    }

    /// 端到端：32KB 分块写入 → ReadVReader 一次聚合读多缓冲 → 字节守恒。
    #[tokio::test]
    async fn tcp_aggregation_byte_conservation() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // 模式化载荷：可逐字节校验。
        let payload: Vec<u8> = (0..32_768u32).map(|i| (i % 251) as u8).collect();
        let expect = payload.clone();

        let writer = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            use tokio::io::AsyncWriteExt;
            s.write_all(&payload).await.unwrap();
            s.flush().await.unwrap();
            s.shutdown().await.unwrap();
        });

        let (sock, _) = listener.accept().await.unwrap();
        let (rd, _wr) = sock.into_split();
        let mut reader = ReadVReader::new(rd);

        // 写端先行完成，保证首读时 32KB 已在接收队列 → 首次 readv 必聚合 >8KB。
        tokio::time::timeout(std::time::Duration::from_secs(5), writer)
            .await
            .expect("writer finished")
            .unwrap();

        let mut got: Vec<u8> = Vec::with_capacity(32_768);
        let mut saw_multi = false;
        loop {
            let mb = tokio::time::timeout(std::time::Duration::from_secs(5), reader.read_multi())
                .await
                .expect("read timeout")
                .expect("read ok");
            if mb.is_empty() {
                break; // EOF 约定
            }
            if mb.buffer_count() > 1 {
                saw_multi = true;
            }
            got.extend_from_slice(&mb.to_vec());
        }

        assert_eq!(got.len(), expect.len(), "字节守恒");
        assert_eq!(got, expect, "内容逐字节一致");
        assert!(saw_multi, "32KB 队列下首次 readv 应聚合多缓冲");
    }

    #[tokio::test]
    async fn single_full_promotes_then_eof() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let writer = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            use tokio::io::AsyncWriteExt;
            // 3 个满缓冲：单缓冲阶段 readv 的 iovec 总量 = 1 个缓冲，队列有剩余数据时
            // 必然读满 8192 → IsFull 扩容分支确定性触发。
            let chunk = vec![0xABu8; 8192 * 3];
            s.write_all(&chunk).await.unwrap();
            s.flush().await.unwrap();
            s.shutdown().await.unwrap();
        });

        let (sock, _) = listener.accept().await.unwrap();
        let (rd, _wr) = sock.into_split();
        let mut reader = ReadVReader::new(rd);
        assert_eq!(reader.alloc_strategy().current(), 1);

        tokio::time::timeout(std::time::Duration::from_secs(5), writer)
            .await
            .expect("writer finished")
            .unwrap();

        let mb = tokio::time::timeout(std::time::Duration::from_secs(5), reader.read_multi())
            .await
            .expect("read timeout")
            .expect("read ok");
        assert_eq!(mb.len(), 8192);
        assert_eq!(
            reader.alloc_strategy().current(),
            2,
            "单缓冲填满后应扩容到 2（Go IsFull → Adjust(1)）"
        );

        // 第二读：current==2，剩余 16KB 恰好聚合进 2 个缓冲。
        let mb = tokio::time::timeout(std::time::Duration::from_secs(5), reader.read_multi())
            .await
            .expect("read timeout")
            .expect("read ok");
        assert_eq!(mb.len(), 16 * 1024);
        assert_eq!(mb.buffer_count(), 2);
        assert_eq!(reader.alloc_strategy().current(), 4, "2 缓冲全填 → 扩到 4");

        // EOF → 空 MultiBuffer
        let mb = tokio::time::timeout(std::time::Duration::from_secs(5), reader.read_multi())
            .await
            .expect("read timeout")
            .expect("read ok");
        assert!(mb.is_empty(), "EOF 应产出空 MultiBuffer");
    }

    #[tokio::test]
    async fn env_off_falls_back_to_sequential_path() {
        let _guard = ENV_LOCK.lock();
        let prev = use_readv();
        USE_READV.store(false, Ordering::Relaxed);
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                USE_READV.store(self.0, Ordering::Relaxed);
            }
        }
        let _restore = Restore(prev);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let writer = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            use tokio::io::AsyncWriteExt;
            s.write_all(&b"hello readv gate".repeat(4)).await.unwrap();
            s.shutdown().await.unwrap();
        });

        let (sock, _) = listener.accept().await.unwrap();
        let (rd, _wr) = sock.into_split();
        // 工厂语义：闸门关 → 不包 ReadVReader，退回顺序读（Go NewReader useReadV()==false）。
        let mut reader = io::new_readv_reader(rd);
        writer.await.unwrap();

        let mut got = Vec::new();
        loop {
            let mb = reader.read_multi_buffer().await.expect("read ok");
            if mb.is_empty() {
                break;
            }
            got.extend_from_slice(&mb.to_vec());
        }
        assert_eq!(got, b"hello readv gate".repeat(4));
    }
}

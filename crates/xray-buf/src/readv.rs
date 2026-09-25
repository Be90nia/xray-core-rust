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

use std::{
    future::Future,
    io::{ErrorKind, IoSliceMut},
    pin::Pin,
    sync::{
        LazyLock,
        atomic::{AtomicBool, Ordering},
    },
};

use tokio::net::tcp::OwnedReadHalf;

use crate::{
    buffer::Buffer,
    io::{self, Reader, Result},
    multi::MultiBuffer,
};

// ========== env 闸门（Go readv_reader.go:147-163） ==========

/// `xray.buf.readv` 解析结果缓存。LazyLock 首调读 env（未设 → true = Go 缺省开），
/// 热路径零 env 查询；`reload_env_settings` 显式刷新。
static USE_READV: LazyLock<AtomicBool> = LazyLock::new(|| AtomicBool::new(parse_readv_env()));

/// 读取 `xray.buf.readv` 环境闸门当前值。
///
/// 唯一事实源：readv 闸门全仓只有本模块的 `USE_READV` AtomicBool 一个判定
/// 存储——生产消费点仅 [`crate::io::new_readv_reader`]；写侧仅
/// [`parse_readv_env`]（首调）+ [`reload_env_settings`]（显式刷新）。
/// `xray-common::platform::env::use_readv` 是指向这里的转发别名（Go
/// `platform.UseReadV` binding 等价入口），不得在别处另建 env 解析。
///
/// 语义对齐 Go `useReadV()`：未设置（默认）/ `auto` / `enable` → 启用；
/// 其他任何值 → 禁用（顺序读）。
#[inline]
pub fn use_readv() -> bool {
    USE_READV.load(Ordering::Relaxed)
}

/// 重新解析 env 闸门。对应 Go `reloadEnvSettings`（经 platform.RegisterEnvReload
/// 注册；我们无注册机制，进程启动后环境变更需显式调用）。LazyLock 首调已
/// 保证启动正确性（bd xag3③），本函数是显式刷新口。
pub fn reload_env_settings() {
    USE_READV.store(parse_readv_env(), Ordering::Relaxed);
}

/// 读 env 并按三态语义解析 `xray.buf.readv`（原名优先，alt 兜底）。
fn parse_readv_env() -> bool {
    let v = std::env::var("xray.buf.readv").or_else(|_| std::env::var("XRAY_BUF_READV")).ok();
    parse_readv_flag(v.as_deref())
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
        self.current = if n >= self.current { self.current * 2 } else { n };
        if self.current > 8 {
            self.current = 8;
        }
        if self.current == 0 {
            self.current = 1;
        }
    }
}

// ========== iovec 构建 + 字节分发 ==========

// 堆分配版 alloc/buffer_iovecs/distribute 已删（wfx8-4：零生产调用方，注释
// 声称 bridge.rs 在用系失实）；零分配栈数组路径见下方 IovecBatch/readv 循环。

// ========== 零分配 readv 路径（bd fwhh：ReadVReader 每读 4 alloc → ~1） ==========

/// readv 单次 read 的最大 iovec 数（= [`AllocStrategy`] 上界，Go readv_reader.go:34）。
const MAX_READV: usize = 8;

/// 栈上 iovec 批：`read_vectored` 切片与容量表，零堆分配构建。
struct IovecBatch<'a> {
    slices: [IoSliceMut<'a>; MAX_READV],
    lens: [usize; MAX_READV],
    n: usize,
}

impl<'a> IovecBatch<'a> {
    /// 从已填缓冲槽构建 iovec。`bufs[i]`（i < n_bufs）由调用方保证已填。
    fn build(bufs: &'a mut [Option<Buffer>; MAX_READV], n_bufs: usize) -> Self {
        // IoSliceMut::new 非 const fn：运行时 from_fn 填空切片，命中槽位时覆盖
        let mut slices = std::array::from_fn(|_| IoSliceMut::new(&mut []));
        let mut lens = [0usize; MAX_READV];
        for (i, slot) in bufs.iter_mut().enumerate().take(n_bufs) {
            let Some(buf) = slot.as_mut() else { continue };
            let w = buf.writable_bytes();
            lens[i] = w.len();
            slices[i] = IoSliceMut::new(w);
        }
        Self { slices, lens, n: n_bufs }
    }
}

/// 数组版分发：n 字节按 iovec 容量切进各槽（原 Vec 版 distribute 的零分配
/// 形态），消费全部槽位；唯一保留分配 = MultiBuffer 内部 `Vec::with_capacity`。
fn distribute_slots(
    n: usize,
    bufs: &mut [Option<Buffer>; MAX_READV],
    lens: &[usize; MAX_READV],
    n_bufs: usize,
) -> MultiBuffer {
    let mut remaining = n;
    let mut mb = MultiBuffer::with_capacity(n_bufs);
    for (i, slot) in bufs.iter_mut().enumerate().take(n_bufs) {
        let Some(mut buf) = slot.take() else { continue };
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

/// 数组版 release_all：全部槽位释放回池（EOF / 错误路径）。
fn release_slots(bufs: &mut [Option<Buffer>; MAX_READV]) {
    for slot in bufs.iter_mut() {
        if let Some(mut b) = slot.take() {
            b.release();
        }
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
        Self { src, alloc: AllocStrategy::new() }
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
    ///
    /// 零分配路径（bd fwhh）：缓冲槽与 iovec 批都在栈上（`[Option<Buffer>; 8]` +
    /// `IovecBatch`），每读唯一堆分配 = 返回值 MultiBuffer 内部 Vec。
    pub async fn read_multi(&mut self) -> Result<MultiBuffer> {
        // Go 以 current==1 分流：单缓冲读（填满才扩容）vs 多缓冲 readv（按实填数调整）。
        // 分支判定在入口取快照，读后按各自分支调整一次（对齐 Go :127-129 / :143）。
        let single = self.alloc.current() == 1;
        let n_bufs = (self.alloc.current() as usize).min(MAX_READV);

        // 栈上构建：填缓冲槽 → 拼 iovec（对应 Go posixReader.Init 直写 bs[nBuf].v）。
        let mut bufs: [Option<Buffer>; MAX_READV] = std::array::from_fn(|_| None);
        for slot in bufs.iter_mut().take(n_bufs) {
            *slot = Some(Buffer::new());
        }
        let mut batch = IovecBatch::build(&mut bufs, n_bufs);

        let read = self.read_vectored_ready(&mut batch.slices[..batch.n]).await;
        // lens/n 是纯数据，先拷出结束 batch 对 bufs 的借用，错误/EOF 路径才能释放槽位。
        let (lens, n_iov) = (batch.lens, batch.n);
        let n = match read {
            Ok(n) => n,
            Err(e) => {
                release_slots(&mut bufs);
                return Err(io::classify_io_error(e, true));
            },
        };

        if n == 0 {
            // 对应 Go `nBytes == 0 → io.EOF`；本 crate 约定：空 MultiBuffer 表示 EOF。
            release_slots(&mut bufs);
            return Ok(MultiBuffer::new());
        }

        let mb = distribute_slots(n, &mut bufs, &lens, n_iov);
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
    fn read_multi_buffer(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<MultiBuffer>> + Send + '_>> {
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
    /// bd xag3③：use_readv 缓存 + reload 行为等价三态（env 进程全局，串行化）。
    #[test]
    fn use_readv_cached_env_three_states() {
        let _guard = ENV_LOCK.lock();

        const NAME: &str = "xray.buf.readv";
        const ALT: &str = "XRAY_BUF_READV";
        let saved_name = std::env::var_os(NAME);
        let saved_alt = std::env::var_os(ALT);
        struct Restore(Option<std::ffi::OsString>, Option<std::ffi::OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                unsafe {
                    match self.0.take() {
                        Some(v) => std::env::set_var(NAME, v),
                        None => std::env::remove_var(NAME),
                    }
                    match self.1.take() {
                        Some(v) => std::env::set_var(ALT, v),
                        None => std::env::remove_var(ALT),
                    }
                }
                super::reload_env_settings();
            }
        }
        unsafe {
            std::env::remove_var(NAME);
            std::env::remove_var(ALT);
        }
        let _restore = Restore(saved_name, saved_alt);

        // ① 不设 → Go 缺省开
        reload_env_settings();
        assert!(use_readv(), "未设置应启用（Go 缺省）");

        // ② 显式启用值
        for on in ["auto", "enable"] {
            unsafe { std::env::set_var(NAME, on) };
            reload_env_settings();
            assert!(use_readv(), "env={on:?} 应启用");
        }

        // ③ 非法值禁用（readv 走 var()：非 UTF-8 与空串同落禁用侧）
        for off in ["disable", "true", "1", ""] {
            unsafe { std::env::set_var(NAME, off) };
            reload_env_settings();
            assert!(!use_readv(), "env={off:?} 应禁用");
        }

        // ④ 缓存语义：env 变更不 reload 不生效
        unsafe { std::env::set_var(NAME, "auto") };
        assert!(!use_readv(), "不 reload 不应翻转（缓存生效）");
        reload_env_settings();
        assert!(use_readv(), "reload 后应翻转");

        // ⑤ alt 名兜底 + 原名优先
        unsafe {
            std::env::remove_var(NAME);
            std::env::set_var(ALT, "enable");
        }
        reload_env_settings();
        assert!(use_readv(), "alt 名应兜底");
        unsafe { std::env::set_var(NAME, "disable") };
        reload_env_settings();
        assert!(!use_readv(), "原名命中时优先于 alt");
    }
    /// bd fwhh：数组版 distribute 与 Vec 版同语义（字节守恒 + 尾部空槽释放）。
    #[test]
    fn distribute_slots_byte_conservation_and_release() {
        let mut lens = [0usize; MAX_READV];
        let fill = |bufs: &mut [Option<Buffer>; MAX_READV],
                    n_bufs: usize,
                    lens: &mut [usize; MAX_READV]| {
            for slot in bufs.iter_mut().take(n_bufs) {
                *slot = Some(Buffer::new());
            }
            for (i, slot) in bufs.iter().enumerate().take(n_bufs) {
                lens[i] = slot.as_ref().map(|b| b.capacity()).unwrap_or(0);
            }
        };

        // 恰好 2.5 个缓冲的量
        let mut bufs: [Option<Buffer>; MAX_READV] = std::array::from_fn(|_| None);
        fill(&mut bufs, 4, &mut lens);
        let cap = lens[0];
        let n = cap * 2 + cap / 2;
        let mb = distribute_slots(n, &mut bufs, &lens, 4);
        assert_eq!(mb.len(), n);
        assert_eq!(mb.buffer_count(), 3);
        assert!(bufs.iter().all(|s| s.is_none()), "全部槽位被消费（尾部释放）");

        // n=0：全部释放，空 MultiBuffer
        let mut bufs: [Option<Buffer>; MAX_READV] = std::array::from_fn(|_| None);
        fill(&mut bufs, 2, &mut lens);
        let mb = distribute_slots(0, &mut bufs, &lens, 2);
        assert!(mb.is_empty());
        assert!(bufs.iter().all(|s| s.is_none()));
    }

    // bd fwhh：IovecBatch::build 的 lens 与被删 Vec 版 buffer_iovecs 同源，
    // 正确性由 distribute_slots_byte_conservation_and_release 覆盖。
}

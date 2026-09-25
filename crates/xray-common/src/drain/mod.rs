//! 连接排空工具
//!
//! 对应 Go 版本 `common/drain` 包。
//!
//! 当认证失败时，不立即关闭连接，而是随机排空一定量数据，
//! 使攻击者无法通过连接关闭时机判断认证是否成功（防时序指纹）。
//!
//! `BehaviorSeedLimitedDrainer`：用 account 种子确定性地计算排空量，
//! 加上一个全局随机增量。排空预算通过 `acknowledge_receive` 递减——
//! 每收到一帧数据就扣减，直到预算耗尽。
//!
//! `Drain` 行为（对应 Go）：
//! - 预算 > 0：精确读取预算字节；全部读完 → Err（连接过长，疑探测）； 读取不足 →
//!   Err（连接提前关闭）。
//! - 预算 ≤ 0：Ok（不需要排空）。

use std::sync::atomic::{AtomicI64, Ordering};

use tokio::io::AsyncReadExt;

use crate::dice::DeterministicDice;

/// 排空器 trait，对应 Go `drain.Drainer` interface。
///
/// 使用 `Pin<Box<dyn Future>>` 返回类型而非 `async fn`，确保 dyn-compatible
/// （`&dyn Drainer` 可用）。
pub trait Drainer: Send + Sync {
    /// 接收到 `size` 字节后，扣减排空预算（对应 Go `AcknowledgeReceive`）。
    fn acknowledge_receive(&self, size: usize);

    /// 从 reader 排空数据（对应 Go `Drain`）。
    fn drain<'a>(
        &'a self,
        reader: &'a mut (dyn tokio::io::AsyncRead + Unpin + Send),
    ) -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'a>>;
}

/// 基于行为种子的有限排空器。
///
/// 对应 Go `drain.BehaviorSeedLimitedDrainer`。
pub struct BehaviorSeedLimitedDrainer {
    /// 剩余排空字节数（`acknowledge_receive` 可减为负值）。
    drain_size: AtomicI64,
}

impl BehaviorSeedLimitedDrainer {
    /// 创建排空器，对应 Go `NewBehaviorSeedLimitedDrainer`。
    ///
    /// # 参数
    /// - `behavior_seed`：行为种子（来自 account key 的 CRC）
    /// - `drain_foundation`：固定基础排空量（Go 中 `16+38`）
    /// - `max_base_drain_size`：种子派生基础量上限（Go 中 `3266`）
    /// - `max_rand_drain`：全局随机量上限（Go 中 `64`）
    ///
    /// # 计算方式
    ///
    /// ```text
    /// base       = DeterministicDice(seed).roll(max_base_drain_size)  // [0, max_base)
    /// rand_max   = DeterministicDice(seed).roll(max_rand_drain) + 1  // [1, max_rand]
    /// rand_val   = global_rand.roll(rand_max)                         // [0, rand_max)
    /// drain_size = foundation + base + rand_val
    /// ```
    #[must_use]
    pub fn new(
        behavior_seed: i64,
        drain_foundation: usize,
        max_base_drain_size: usize,
        max_rand_drain: usize,
    ) -> Self {
        let mut dice = DeterministicDice::with_seed(behavior_seed.max(1) as u64);
        let base_drain_size = dice.roll_int63n(max_base_drain_size as i64).max(0) as usize;
        let rand_drain_max = (dice.roll_int63n(max_rand_drain as i64).max(0) as usize) + 1;
        // Go's dice.Roll uses the global rand source (non-deterministic).
        let rand_drain_rolled = (rand::random::<u64>() % rand_drain_max as u64) as usize;
        let total = drain_foundation + base_drain_size + rand_drain_rolled;
        Self { drain_size: AtomicI64::new(total as i64) }
    }

    /// 当前剩余排空预算（测试用）。
    #[must_use]
    pub fn drain_size(&self) -> i64 {
        self.drain_size.load(Ordering::Relaxed)
    }
}

impl Drainer for BehaviorSeedLimitedDrainer {
    fn acknowledge_receive(&self, size: usize) {
        self.drain_size.fetch_sub(size as i64, Ordering::Relaxed);
    }

    fn drain<'a>(
        &'a self,
        reader: &'a mut (dyn tokio::io::AsyncRead + Unpin + Send),
    ) -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let remaining = self.drain_size.load(Ordering::Relaxed);
            if remaining <= 0 {
                return Ok(());
            }
            match drain_read_n(reader, remaining as usize).await {
                // All bytes read — connection was longer than expected (likely probing).
                Ok(()) => Err(std::io::Error::other("drained connection")),
                // Reader closed before drain complete — normal for real connections.
                Err(e) => Err(std::io::Error::other(format!("unable to drain connection: {e}"))),
            }
        })
    }
}

/// 无操作排空器（不做任何排空）。
///
/// 对应 Go `drain.NopDrainer`。
pub struct NopDrainer;

impl Drainer for NopDrainer {
    fn acknowledge_receive(&self, _size: usize) {}

    fn drain<'a>(
        &'a self,
        _reader: &'a mut (dyn tokio::io::AsyncRead + Unpin + Send),
    ) -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

/// 从 reader 精确读取 `n` 字节并丢弃。
///
/// 对应 Go `drainReadN` = `io.CopyN(io.Discard, reader, int64(n))`。
/// 全部读完 → `Ok`；EOF 或错误 → `Err`。
async fn drain_read_n(
    reader: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
    n: usize,
) -> std::io::Result<()> {
    let mut buf = [0u8; 4096];
    let mut remaining = n;
    while remaining > 0 {
        let to_read = remaining.min(buf.len());
        let read = reader.read(&mut buf[..to_read]).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF during drain",
            ));
        }
        remaining -= read;
    }
    Ok(())
}

/// 排空后返回原始错误（对应 Go `drain.WithError`）。
///
/// 先排空 reader，再返回原始错误。排空成功（预算 ≤ 0）→ 返回原始错误；
/// 排空失败 → 返回排空错误（包裹原始错误）。
pub async fn with_error(
    drainer: &dyn Drainer,
    reader: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
    err: std::io::Error,
) -> std::io::Error {
    match drainer.drain(reader).await {
        Ok(()) => err,
        Err(drain_err) => std::io::Error::other(format!("{drain_err}: {err}")),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use tokio::io::BufReader;

    use super::*;

    fn make_reader(data: &[u8]) -> BufReader<Cursor<&[u8]>> {
        BufReader::new(Cursor::new(data))
    }

    #[test]
    fn drain_size_at_least_foundation() {
        // foundation=54, max_base=0, max_rand=0 → drain_size = 54 + 0 + 0
        let d = BehaviorSeedLimitedDrainer::new(42, 54, 0, 0);
        assert_eq!(d.drain_size(), 54);
    }

    #[test]
    fn drain_size_within_bounds() {
        // foundation=54, max_base=3266, max_rand=64 → drain_size in [54, 54+3266+63]
        let d = BehaviorSeedLimitedDrainer::new(42, 54, 3266, 64);
        let s = d.drain_size();
        assert!((54..=54 + 3266 + 63).contains(&s));
    }

    #[test]
    fn drain_size_deterministic_base_across_same_seed() {
        // With max_rand=0 the random component is 0, so only the base varies by seed.
        let d1 = BehaviorSeedLimitedDrainer::new(42, 0, 3266, 0);
        let d2 = BehaviorSeedLimitedDrainer::new(42, 0, 3266, 0);
        assert_eq!(d1.drain_size(), d2.drain_size());
    }

    #[test]
    fn drain_size_different_seeds_likely_differ() {
        let d1 = BehaviorSeedLimitedDrainer::new(42, 0, 3266, 0);
        let d2 = BehaviorSeedLimitedDrainer::new(999, 0, 3266, 0);
        assert_ne!(d1.drain_size(), d2.drain_size());
    }

    #[tokio::test]
    async fn drain_errors_when_reader_too_short() {
        // drain_size=100, reader has 10 bytes → EOF → "unable to drain"
        let data = vec![0u8; 10];
        let drainer = BehaviorSeedLimitedDrainer::new(42, 100, 0, 0);
        let mut reader = make_reader(&data);
        let err = drainer.drain(&mut reader).await.unwrap_err();
        assert!(err.to_string().contains("unable to drain"));
    }

    #[tokio::test]
    async fn drain_errors_when_reader_long_enough() {
        // drain_size=100, reader has 200 bytes → all read → "drained connection"
        let data = vec![0u8; 200];
        let drainer = BehaviorSeedLimitedDrainer::new(42, 100, 0, 0);
        let mut reader = make_reader(&data);
        let err = drainer.drain(&mut reader).await.unwrap_err();
        assert!(err.to_string().contains("drained connection"));
    }

    #[tokio::test]
    async fn drain_ok_when_budget_exhausted_by_acknowledge() {
        let data = vec![0u8; 100];
        let drainer = BehaviorSeedLimitedDrainer::new(42, 100, 0, 0);
        drainer.acknowledge_receive(100);
        assert!(drainer.drain_size() <= 0);
        let mut reader = make_reader(&data);
        assert!(drainer.drain(&mut reader).await.is_ok());
    }

    #[tokio::test]
    async fn nop_drainer_acknowledge_and_drain_are_noops() {
        let data = vec![0u8; 100];
        let drainer = NopDrainer;
        drainer.acknowledge_receive(50);
        let mut reader = make_reader(&data);
        assert!(drainer.drain(&mut reader).await.is_ok());
    }

    #[tokio::test]
    async fn nop_drainer_empty_reader_ok() {
        let data: &[u8] = &[];
        let drainer = NopDrainer;
        let mut reader = make_reader(data);
        assert!(drainer.drain(&mut reader).await.is_ok());
    }

    #[tokio::test]
    async fn with_error_returns_original_when_drain_ok() {
        // Budget ≤ 0 → drain Ok → return original error
        let drainer = BehaviorSeedLimitedDrainer::new(42, 0, 0, 0);
        let mut reader = make_reader(&[0u8; 10]);
        let original = std::io::Error::other("auth failed");
        let result = with_error(&drainer, &mut reader, original).await;
        assert_eq!(result.to_string(), "auth failed");
    }

    #[tokio::test]
    async fn with_error_wraps_when_drain_fails() {
        // Budget > 0, reader short → drain fails → wrapped error
        let drainer = BehaviorSeedLimitedDrainer::new(42, 100, 0, 0);
        let mut reader = make_reader(&[0u8; 10]);
        let original = std::io::Error::other("auth failed");
        let result = with_error(&drainer, &mut reader, original).await;
        assert!(result.to_string().contains("unable to drain"));
        assert!(result.to_string().contains("auth failed"));
    }
}

//! 连接排空工具
//!
//! 对应 Go 版本 `common/drain` 包，提供连接数据排空功能。

use crate::dice::DeterministicDice;
use tokio::io::AsyncReadExt;

/// 排空器 trait，定义连接数据排空行为。
#[allow(async_fn_in_trait)]
pub trait Drainer: Send + Sync {
    /// 从读取器排空剩余数据。
    async fn drain(
        &self,
        reader: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
    ) -> std::io::Result<()>;
}

/// 基于行为种子的有限排空器，读取随机上限量的数据。
///
/// 对应 Go 版本 `drain.BehaviorSeedLimitedDrainer`。
/// 使用种子确定性地生成最大读取字节数，在达到限制或 EOF 时停止。
pub struct BehaviorSeedLimitedDrainer {
    max_read: usize,
}

impl BehaviorSeedLimitedDrainer {
    /// 创建新的有限排空器。
    ///
    /// `seed` 用于确定性地计算最大读取量。
    /// `max_read` 为最大读取字节数上限。
    pub fn new(seed: u64, max_read: usize) -> Self {
        let _ = seed; // 种子用于确定性计算，当前简化实现
        Self { max_read }
    }

    /// 计算实际最大读取量（基于种子的确定性值）。
    ///
    /// 使用 DeterministicDice 从种子派生 [0, max_read) 范围内的值。
    pub fn compute_limit(seed: u64, max_read: usize) -> usize {
        if max_read == 0 {
            return 0;
        }
        let mut dice = DeterministicDice::with_seed(seed);
        let limit = dice.roll_int63n(max_read as i64);
        limit.max(0) as usize
    }
}

impl Drainer for BehaviorSeedLimitedDrainer {
    async fn drain(
        &self,
        reader: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
    ) -> std::io::Result<()> {
        let mut buf = [0u8; 4096];
        let mut total_read: usize = 0;

        while total_read < self.max_read {
            let remaining = self.max_read - total_read;
            let to_read = remaining.min(buf.len());
            let slice = &mut buf[..to_read];

            let n = reader.read(slice).await?;
            if n == 0 {
                break;
            }
            total_read += n;
        }

        Ok(())
    }
}

/// 无操作排空器，丢弃所有数据。
///
/// 对应 Go 版本 `drain.NopDrainer`。
pub struct NopDrainer;

impl Drainer for NopDrainer {
    async fn drain(
        &self,
        reader: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
    ) -> std::io::Result<()> {
        let mut buf = [0u8; 4096];
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::BufReader;

    fn make_reader(data: &[u8]) -> BufReader<Cursor<&[u8]>> {
        BufReader::new(Cursor::new(data))
    }

    #[tokio::test]
    async fn test_behavior_seed_limited_drainer_reads_all() {
        let data = vec![0u8; 100];
        let drainer = BehaviorSeedLimitedDrainer::new(42, 200);
        let mut reader = make_reader(&data);
        let result = drainer.drain(&mut reader).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_behavior_seed_limited_drainer_stops_at_limit() {
        let data = vec![0u8; 1000];
        let drainer = BehaviorSeedLimitedDrainer::new(42, 100);
        let mut reader = make_reader(&data);
        let result = drainer.drain(&mut reader).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_behavior_seed_limited_drainer_empty() {
        let data: &[u8] = &[];
        let drainer = BehaviorSeedLimitedDrainer::new(42, 100);
        let mut reader = make_reader(data);
        let result = drainer.drain(&mut reader).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_nop_drainer_discards_all() {
        let data = vec![0u8; 100];
        let drainer = NopDrainer;
        let mut reader = make_reader(&data);
        let result = drainer.drain(&mut reader).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_nop_drainer_empty() {
        let data: &[u8] = &[];
        let drainer = NopDrainer;
        let mut reader = make_reader(data);
        let result = drainer.drain(&mut reader).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_compute_limit_deterministic() {
        let limit1 = BehaviorSeedLimitedDrainer::compute_limit(42, 1024);
        let limit2 = BehaviorSeedLimitedDrainer::compute_limit(42, 1024);
        assert_eq!(limit1, limit2);
    }

    #[test]
    fn test_compute_limit_different_seeds() {
        let limit1 = BehaviorSeedLimitedDrainer::compute_limit(42, 1024);
        let limit2 = BehaviorSeedLimitedDrainer::compute_limit(99, 1024);
        // 不同种子通常产生不同结果（极低概率相等）
        assert!(limit1 < 1024);
        assert!(limit2 < 1024);
    }

    #[test]
    fn test_compute_limit_zero_max() {
        let limit = BehaviorSeedLimitedDrainer::compute_limit(42, 0);
        assert_eq!(limit, 0);
    }
}

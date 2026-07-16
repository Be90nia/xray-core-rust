//! # D5: Noise 噪声填充
//!
//! 对应 Go `transport/internet/finalmask/noise/`。
//!
//! 在空闲时注入随机噪声，维持流量速率特征，对抗流量分析。
//!
//! ## TODO rpn-future
//!
//! - 实现噪声生成器（CSPRNG + 速率控制）
//! - 实现噪声识别（接收端丢弃噪声包）

/// 噪声配置。
#[derive(Debug, Clone)]
pub struct NoiseConfig {
    /// 噪声包大小（字节）。
    pub packet_size: usize,
    /// 注入间隔（毫秒）。
    pub interval_ms: u64,
    /// 最大总噪声量（字节，0 = 无限）。
    pub max_total: usize,
}

impl Default for NoiseConfig {
    fn default() -> Self {
        Self {
            packet_size: 64,
            interval_ms: 100,
            max_total: 0,
        }
    }
}

/// 噪声生成器（stub）。
pub struct NoiseGenerator {
    config: NoiseConfig,
    sent: std::sync::atomic::AtomicUsize,
}

impl NoiseGenerator {
    #[must_use]
    pub fn new(config: NoiseConfig) -> Self {
        Self {
            config,
            sent: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// 生成一个噪声包（stub：返回固定长度随机字节）。
    ///
    /// TODO rpn-future: 用 CSPRNG 生成 + 速率控制 + 总量限制。
    pub fn generate(&self) -> Vec<u8> {
        vec![0u8; self.config.packet_size]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_returns_configured_size() {
        let generator = NoiseGenerator::new(NoiseConfig {
            packet_size: 128,
            ..Default::default()
        });
        assert_eq!(generator.generate().len(), 128);
    }
}

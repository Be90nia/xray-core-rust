//! # D2: Fragment TCP 分片
//!
//! 对应 Go `transport/internet/finalmask/fragment/`。
//!
//! 在 TCP 握手后把首包拆成多个小片段，绕过基于首包特征的 DPI 检测。
//!
//! ## TODO rpn-future
//!
//! - 实现 fragment writer（按规则拆包：固定大小 / 随机区间 / TTL）
//! - 实现 fragment reader（透明重组，对上层无感）

/// 分片配置。
#[derive(Debug, Clone)]
pub struct FragmentConfig {
    /// 首包分片大小区间（min, max），字节。
    pub size_range: (usize, usize),
    /// 分片间隔（毫秒）。
    pub interval_ms: u64,
}

impl Default for FragmentConfig {
    fn default() -> Self {
        Self {
            size_range: (1, 64),
            interval_ms: 10,
        }
    }
}

/// 分片器（stub）。
pub struct Fragmenter {
    config: FragmentConfig,
}

impl Fragmenter {
    #[must_use]
    pub fn new(config: FragmentConfig) -> Self {
        Self { config }
    }

    /// 计算给定 payload 的分片边界（stub：返回整个 payload 作为一个分片）。
    ///
    /// TODO rpn-future: 实现实际分片逻辑（随机大小 + 间隔）。
    pub fn split(&self, payload_len: usize) -> Vec<usize> {
        vec![payload_len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_sane() {
        let c = FragmentConfig::default();
        assert!(c.size_range.0 <= c.size_range.1);
    }

    #[test]
    fn split_stub_returns_single_fragment() {
        let f = Fragmenter::new(FragmentConfig::default());
        assert_eq!(f.split(1024), vec![1024]);
    }
}

//! # D8: Sudoku 编码
//!
//! 对应 Go `transport/internet/finalmask/sudoku/`。
//!
//! Sudoku 是一种基于数独谜题的流量编码——用数独格子位置编码字节。
//!
//! ## TODO rpn-future
//!
//! - 实现 sudoku grid 生成（从 seed）
//! - 实现 byte → grid position 映射
//! - 实现 grid position → byte 还原

/// Sudoku 配置。
#[derive(Debug, Clone)]
pub struct SudokuConfig {
    /// 数独大小（默认 9x9）。
    pub grid_size: usize,
    /// 编码 seed。
    pub seed: u64,
}

impl Default for SudokuConfig {
    fn default() -> Self {
        Self {
            grid_size: 9,
            seed: 0,
        }
    }
}

/// Sudoku 编码器（stub）。
pub struct SudokuEncoder {
    config: SudokuConfig,
}

impl SudokuEncoder {
    #[must_use]
    pub fn new(config: SudokuConfig) -> Self {
        Self { config }
    }

    /// 生成数独 grid（stub：返回空 grid）。
    ///
    /// TODO rpn-future: 从 seed 生成有效数独。
    pub fn generate_grid(&self) -> Vec<Vec<u8>> {
        vec![vec![0u8; self.config.grid_size]; self.config.grid_size]
    }

    /// 编码（stub：透传）。
    ///
    /// TODO rpn-future: 实现字节到数独位置的映射。
    pub fn encode(&self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grid_default_9x9() {
        let enc = SudokuEncoder::new(SudokuConfig::default());
        let grid = enc.generate_grid();
        assert_eq!(grid.len(), 9);
        assert_eq!(grid[0].len(), 9);
    }
}

//! 字节位掩码操作工具
//!
//! 对应 Go 版本 `common/bitmask` 包，提供对 u8 位掩码的查询和修改操作。

/// 字节位掩码，封装 u8 值并提供位操作方法。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bitmask(u8);

impl Bitmask {
    /// 创建新的位掩码。
    pub fn new(bits: u8) -> Self {
        Self(bits)
    }

    /// 检查指定位是否被设置。
    pub fn has(&self, bit: u8) -> bool {
        (self.0 & bit) != 0
    }

    /// 设置指定位。
    pub fn set(&mut self, bit: u8) {
        self.0 |= bit;
    }

    /// 清除指定位。
    pub fn clear(&mut self, bit: u8) {
        self.0 &= !bit;
    }

    /// 切换指定位。
    pub fn toggle(&mut self, bit: u8) {
        self.0 ^= bit;
    }

    /// 返回原始位值。
    pub fn bits(&self) -> u8 {
        self.0
    }
}

impl Default for Bitmask {
    fn default() -> Self {
        Self(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let mask = Bitmask::new(0b1010_1010);
        assert_eq!(mask.bits(), 0b1010_1010);
    }

    #[test]
    fn test_default() {
        let mask = Bitmask::default();
        assert_eq!(mask.bits(), 0);
    }

    #[test]
    fn test_has() {
        let mask = Bitmask::new(0b1010);
        assert!(mask.has(0b1000));
        assert!(!mask.has(0b0100));
        assert!(mask.has(0b0010));
        assert!(!mask.has(0b0001));
    }

    #[test]
    fn test_set() {
        let mut mask = Bitmask::new(0);
        mask.set(0b0010);
        assert_eq!(mask.bits(), 0b0010);
        mask.set(0b1000);
        assert_eq!(mask.bits(), 0b1010);
    }

    #[test]
    fn test_clear() {
        let mut mask = Bitmask::new(0b1111);
        mask.clear(0b0010);
        assert_eq!(mask.bits(), 0b1101);
        mask.clear(0b1000);
        assert_eq!(mask.bits(), 0b0101);
    }

    #[test]
    fn test_toggle() {
        let mut mask = Bitmask::new(0b1010);
        mask.toggle(0b0010);
        assert_eq!(mask.bits(), 0b1000);
        mask.toggle(0b0100);
        assert_eq!(mask.bits(), 0b1100);
    }

    #[test]
    fn test_combined_operations() {
        let mut mask = Bitmask::new(0);
        mask.set(0b1111);
        mask.clear(0b0011);
        assert_eq!(mask.bits(), 0b1100);
        mask.toggle(0b1100);
        assert_eq!(mask.bits(), 0);
    }
}

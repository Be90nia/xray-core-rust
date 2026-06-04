//! sing-box 生态桥接模块
//!
//! 对应 Go 版本 `common/singbridge` 包。
//! 此模块为占位实现，sing-box 集成将在后续阶段完成。

/// sing-box 桥接器（占位）
///
/// 用于与 sing-box 生态系统进行互操作。
/// 当前为占位实现，完整功能将在后续阶段添加。
pub struct SingBridge;

impl SingBridge {
    /// 创建新的 sing-box 桥接器实例。
    pub fn new() -> Self {
        Self
    }
}

impl Default for SingBridge {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sing_bridge_new() {
        let _bridge = SingBridge::new();
    }

    #[test]
    fn test_sing_bridge_default() {
        let _bridge = SingBridge::default();
    }
}

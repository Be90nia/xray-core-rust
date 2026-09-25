//! Context keys（对应 Go `datagramKey` / `validatorKey` + `ContextWithDatagram` 等）。
//!
//! Go 源：`transport/internet/hysteria/config.go` 第 54-74 行。
//!
//! Go 端用 `context.Context` 携带运行时元数据。Rust 端没有 `context` 概念，
//! 用 trait 抽象上下文载体。`Arc<dyn ContextValues>` 由上层（commander/dispatcher）
//! 注入，hysteria 内部按需读取。

use std::sync::Arc;

/// Context values trait —— 携带 hysteria 所需的运行时元数据。
///
/// 实现者通常是应用层（`xray-app-dispatcher` / `xray-app-proxyman`）的 context 对象。
/// hysteria 内部不实现此 trait，只读取。
pub trait ContextValues: Send + Sync {
    /// 是否启用 UDP datagram（对应 Go `DatagramFromContext`）。
    fn datagram(&self) -> bool;

    /// 鉴权字符串（对应 Go `ValidatorFromContext` 返回的 validator 内的 secret）。
    ///
    /// 注意：Go 返回 `*account.Validator`，Rust 端简化为返回 auth string 切片，
    /// 上层若需多用户校验可自行扩展。
    fn auth_secret(&self) -> Option<&str>;
}

/// ContextWithDatagram —— 设置 datagram flag 的 builder trait。
pub trait ContextWithDatagram {
    /// 关联的 context 值类型。
    type Ctx: ContextValues;

    /// 返回 datagram = true 的新 context（不可变更新）。
    fn with_datagram(self, v: bool) -> Self::Ctx;
}

/// DatagramFromContext —— 从 context 中读取 datagram flag 的访问器 trait。
pub trait DatagramFromContext {
    fn datagram_from(&self) -> bool;
}

impl<T: ContextValues + ?Sized> DatagramFromContext for T {
    fn datagram_from(&self) -> bool {
        ContextValues::datagram(self)
    }
}

/// ContextWithValidator —— 设置 auth secret 的 builder trait。
pub trait ContextWithValidator {
    /// 关联的 context 值类型。
    type Ctx: ContextValues;

    /// 返回带 auth secret 的新 context（不可变更新）。
    fn with_validator(self, secret: Arc<str>) -> Self::Ctx;
}

#[cfg(test)]
mod tests {
    use parking_lot::RwLock;

    use super::*;

    /// 测试用 context 载体：可变字段用 RwLock 保护。
    struct TestCtx {
        datagram: RwLock<bool>,
        #[allow(dead_code)] // 存量清零批次
        auth: RwLock<Option<Arc<str>>>,
    }

    impl TestCtx {
        fn new() -> Arc<Self> {
            Arc::new(Self { datagram: RwLock::new(false), auth: RwLock::new(None) })
        }
    }

    impl ContextValues for TestCtx {
        fn datagram(&self) -> bool {
            *self.datagram.read()
        }

        fn auth_secret(&self) -> Option<&str> {
            // ponytail: 简化为静态返回，测试不需要这层。
            None
        }
    }

    #[test]
    fn datagram_flag_roundtrip() {
        let ctx = TestCtx::new();
        assert!(!ctx.datagram());
        *ctx.datagram.write() = true;
        assert!(ctx.datagram_from());
    }
}

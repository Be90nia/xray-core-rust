//! L1 类型层：协议插件必选方法集与条款声明词汇（模型 §2.2 L1 行、§2.4 十二条）。
//!
//! 任何插件缺必选方法 = 编译不过；`ClauseId` 是 L4 契约测试夹具的断言锚，
//! `PluginError` 是 L5 装配失败的统一出口。version 兼容语义按 PM 拍板
//! （2026-10-23）：**仅日志留痕，不做 semver 拒载**——插件集编译期静态。

use crate::{context::PluginContext, error::PluginError};

/// 坑约束条款 id（模型 §2.4 十二条的一一映射；L4 夹具按声明集逐条断言）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClauseId {
    /// 坑约束 1：认证/校验失败必须返回统一错误分类，禁静默放行。
    AuthErrorClassified,
    /// 坑约束 2：握手/首包必须带 deadline（唯一入口 = ctx.with_deadline）。
    HandshakeDeadline,
    /// 坑约束 3：每条连接必有 conn_id。
    ConnIdPresent,
    /// 坑约束 4：缓冲必须走 BufferPool 接缝。
    PoolDiscipline,
    /// 坑约束 5：异步任务必须托管（ctx.spawn），禁裸 spawn。
    SpawnManaged,
    /// 坑约束 6：停机必须注册 ShutdownCoordinator。
    StopRegistered,
    /// 坑约束 7：配置必须走 per-plugin 段路由 + ConfigPort。
    ConfigSectionOnly,
    /// 坑约束 8：错误必须归类；panic 不得逃逸 IO 线程。
    ErrorClassifiedNoPanicEscape,
    /// 坑约束 9：资源必须上有界。
    BoundedResources,
    /// 坑约束 10：日志必走 logx + target `xray_frame::<域>` 规范。
    LogDiscipline,
    /// 坑约束 11：密钥必须掩码（mask_secrets 输出面强制）。
    SecretMasking,
    /// 坑约束 12：数据面热路径零改动（review 门 + 装配门）。
    HotPathFreeze,
}

/// 条款声明：适用通用条款集 + 协议专属条款 + N/A 声明（v0.1，PM 拍板
/// 2026-10-23 锁定：枚举可穷举校验，`extra` 自由文本留协议专属空间——mux
/// 域名判据、vmess u16 边界等；后续新增通用条款 = 加枚举变体，可回溯）。
///
/// `not_applicable`（P1-7 加法扩展，拍板 P2.2）：通用条款适用性判定为
/// **不适用**的声明面——`ClauseId` 必须配非空理由（L4 夹具
/// `assert_plugin_contract!` 校验理由非空且与 `clauses` 不重叠）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PluginContract {
    pub clauses: &'static [ClauseId],
    pub extra: &'static [(&'static str, &'static str)],
    /// N/A 声明：`(条款, 理由)`。理由必须非空；条款不得同时出现在 `clauses`。
    pub not_applicable: &'static [(ClauseId, &'static str)],
}

/// 依赖声明（P0-2 注册表拓扑排序的输入）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PluginDep {
    pub name: &'static str,
}

/// 生命周期三相本体（v0.1 最小形态；P0-4 编排器是这些方法的唯一合法调用方，
/// stop 的**注册**由装配门 P0-8 强制，插件只实现 stop 本体）。
pub trait Lifecycle: Send + Sync {
    fn init(&self, ctx: &PluginContext) -> Result<(), PluginError>;
    fn start(&self, ctx: &PluginContext) -> Result<(), PluginError>;
    fn stop(&self) -> Result<(), PluginError>;
}

/// L1 必选方法集（模型 §2.5 v0.1 形态落码）。能力只经
/// [`PluginContext`] 取（L2），build 期不做
/// IO 连接类副作用。
///
/// # 编译期强制（L1）
///
/// 必选方法缺一编译不过（`deps` 有默认实现，可省）：
///
/// ```compile_fail
/// use xray_frame::plugin::Plugin;
///
/// struct Stub;
/// impl Plugin for Stub {
///     fn name(&self) -> &'static str { "stub" }
///     fn version(&self) -> &'static str { "0.0.0" }
///     // contract() / lifecycle() / build() 缺失 → E0046
/// }
/// ```
pub trait Plugin: Send + Sync {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn deps(&self) -> &'static [PluginDep] {
        &[]
    }
    fn contract(&self) -> &PluginContract;
    fn lifecycle(&self) -> &dyn Lifecycle;
    fn build(&self, ctx: &mut PluginContext) -> Result<(), PluginError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubLifecycle;

    impl Lifecycle for StubLifecycle {
        fn init(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
            Ok(())
        }

        fn start(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
            Ok(())
        }

        fn stop(&self) -> Result<(), PluginError> {
            Ok(())
        }
    }

    struct Stub {
        contract: PluginContract,
    }

    impl Stub {
        fn bare() -> Self {
            Self { contract: PluginContract { clauses: &[], extra: &[], not_applicable: &[] } }
        }
    }

    impl Plugin for Stub {
        fn name(&self) -> &'static str {
            "stub"
        }

        fn version(&self) -> &'static str {
            "0.1.0"
        }

        fn contract(&self) -> &PluginContract {
            &self.contract
        }

        fn lifecycle(&self) -> &dyn Lifecycle {
            &StubLifecycle
        }

        fn build(&self, _ctx: &mut PluginContext) -> Result<(), PluginError> {
            Ok(())
        }
    }

    #[test]
    fn deps_default_empty() {
        assert!(Stub::bare().deps().is_empty());
    }

    #[test]
    fn contract_fields_roundtrip() {
        let contract = PluginContract {
            clauses: &[ClauseId::SpawnManaged, ClauseId::LogDiscipline],
            extra: &[("mux_carrier", "destination 域名判据，不校验 command")],
            not_applicable: &[(ClauseId::PoolDiscipline, "桩零缓冲分配")],
        };
        let stub = Stub {
            contract: PluginContract {
                clauses: contract.clauses,
                extra: contract.extra,
                not_applicable: contract.not_applicable,
            },
        };
        assert_eq!(stub.contract().clauses, &[ClauseId::SpawnManaged, ClauseId::LogDiscipline]);
        assert_eq!(stub.contract().extra[0].0, "mux_carrier");
        assert_eq!(stub.contract().not_applicable[0].0, ClauseId::PoolDiscipline);
    }

    #[test]
    fn clause_id_exhaustively_covers_twelve_pitfalls() {
        let all: &[ClauseId] = &[
            ClauseId::AuthErrorClassified,
            ClauseId::HandshakeDeadline,
            ClauseId::ConnIdPresent,
            ClauseId::PoolDiscipline,
            ClauseId::SpawnManaged,
            ClauseId::StopRegistered,
            ClauseId::ConfigSectionOnly,
            ClauseId::ErrorClassifiedNoPanicEscape,
            ClauseId::BoundedResources,
            ClauseId::LogDiscipline,
            ClauseId::SecretMasking,
            ClauseId::HotPathFreeze,
        ];
        assert_eq!(all.len(), 12);
    }

    #[test]
    fn plugin_is_object_safe_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Stub>();
        let p: &dyn Plugin = &Stub::bare();
        assert_eq!(p.name(), "stub");
        assert_eq!(p.version(), "0.1.0");
    }
}

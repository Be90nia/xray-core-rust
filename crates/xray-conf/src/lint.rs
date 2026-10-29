//! 配置后处理 / Lint 阶段的**项目窗口**：编排机制在 udf `skeleton::lint`，
//! 本文件只留 Go 语义那一层（错误文案 + [`ConfError`] 适配 + 测试串行化）。
//!
//! 对应 Go `infra/conf/lint.go`：解析后的 [`Config`] 在使用前必须跑完一张阶段表
//! （默认 `FakeDNS` 自动填充 + `Validation` 校验，见 [`crate::init`]）。
//!
//! ## 机制 vs 内容（CLAUDE.md §3.5）
//!
//! - **机制（udf）**：`skeleton::lint` 提供 `LintStage<C>`（`name()` + `run(&mut C)`）、 锁外执行的
//!   `post_process`、注册/清场/诊断名单（注册表 `TypeId` 键，按配置类型分槽）。
//!   主仓不再自带注册表实现（bd bx7my 上浮，本文件由 335 行降为窗口层）。
//! - **内容（留仓）**：阶段实现（[`crate::init`]）+ Go 错误文案（本文件）。
//!
//! ## 迁移带来的两处语义对齐（bd bx7my 记录，非静默改动）
//!
//! - **执行顺序**：旧本地实现按阶段名**字典序**跑（`BTreeMap` 键为名），udf 按**注册序**跑。
//!   现存阶段只有 `FakeDNS` / `Validation`，注册序与字典序一致（`F` < `V`），且全仓
//!   `register_stage` 调用点仅 [`crate::init::register_builtin_stages`]（无第三方注册） →
//!   行为等效，`init.rs` 测试钉死名单顺序。将来若出现跨 crate 注册，须按注册序复核。
//! - **幂等**：udf `register_stage` 是**追加**（同名不去重），Go 是 `map[k] = v` 同名覆盖。
//!   [`crate::Config::build`] 每次自举一次内置阶段，故幂等责任落在注册点—— 见
//!   [`crate::init::register_builtin_stages`] 的「按名跳过」。

use std::sync::Arc;

/// 阶段 trait：udf 契约层直呼（实现者写 `impl LintStage<Config> for X`）。
pub use skeleton::lint::LintStage;

use crate::{config::Config, error::ConfError};

/// 登记一个阶段到 [`Config`] 的阶段表尾（注册序 = 执行序）。
pub fn register_stage(stage: Arc<dyn LintStage<Config>>) {
    skeleton::lint::register_stage(stage);
}

/// 清空 [`Config`] 的阶段表（仅测试与诊断使用；生产代码无需调用）。
#[doc(hidden)]
pub fn clear_stages() {
    skeleton::lint::clear_stages::<Config>();
}

/// 当前已注册阶段名（注册序）。测试与诊断用。
pub fn registered_stages() -> Vec<&'static str> {
    skeleton::lint::registered_stages::<Config>()
}

/// 顺序执行 [`Config`] 的全部阶段（注册序，首错短路）。
///
/// # Errors
///
/// 任一阶段失败即中止，返回 [`ConfError::Invalid`]，文案对齐 Go
/// `infra/conf/lint.go:21`（`errors.New("Rejected by Postprocessing Stage ", k)` +
/// `.Base(err)`）：`rejected by postprocessing stage <name>: <message>`。
/// 「哪个阶段失败」的归属由 udf 编排器补（`skeleton::lint::LintError::stage`）。
pub fn post_process(cfg: &mut Config) -> Result<(), ConfError> {
    skeleton::lint::post_process(cfg).map_err(|err| {
        ConfError::Invalid(format!(
            "rejected by postprocessing stage {}: {}",
            err.stage().unwrap_or("unknown"),
            err.message()
        ))
    })
}

#[cfg(test)]
pub mod tests {
    //! 阶段表是进程级全局状态：同 crate 所有走 `Config::build()` 的测试必须串行化。
    //! 与 udf 的并行策略（每测试私有 `C` 类型分槽）不同——本项目只有一个 `Config`。

    use std::sync::LazyLock;

    #[doc(hidden)]
    pub static TEST_LOCK: LazyLock<parking_lot::Mutex<()>> =
        LazyLock::new(|| parking_lot::Mutex::new(()));
}

/// 测试作用域守卫（`#[cfg(test)]`）：拿 [`tests::TEST_LOCK`] 并清空阶段表；Drop 时再清
/// 一次并释放锁——无论断言成功/失败阶段表都被复位，不向进程级注册表泄漏测试阶段。
#[cfg(test)]
pub(crate) fn lint_test_guard() -> impl Drop {
    struct Guard {
        _lock: parking_lot::MutexGuard<'static, ()>,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            clear_stages();
        }
    }

    let lock = tests::TEST_LOCK.lock();
    clear_stages();
    Guard { _lock: lock }
}

#[cfg(test)]
mod lint_tests {
    use std::sync::Arc;

    use skeleton::lint::{LintError, LintStage};

    use super::{clear_stages, post_process, register_stage, tests::TEST_LOCK};
    use crate::{config::Config, error::ConfError};

    #[test]
    fn post_process_with_no_stages_is_ok() {
        let _g = TEST_LOCK.lock();
        clear_stages();
        let mut cfg = Config::default();
        post_process(&mut cfg).unwrap();
    }

    /// Go 文案契约（`infra/conf/lint.go:21`）：阶段归属由 udf 编排器补，文案留本层。
    #[test]
    fn stage_failure_formats_go_message_and_stage_name() {
        let _g = TEST_LOCK.lock();
        clear_stages();

        struct Boom;
        impl LintStage<Config> for Boom {
            fn name(&self) -> &'static str {
                "FakeDNS"
            }

            fn run(&self, _cfg: &mut Config) -> Result<(), LintError> {
                Err(LintError::new("boom"))
            }
        }

        register_stage(Arc::new(Boom));
        let err = post_process(&mut Config::default()).unwrap_err();
        let ConfError::Invalid(message) = err else {
            panic!("expected ConfError::Invalid, got {err:?}")
        };
        assert_eq!(message, "rejected by postprocessing stage FakeDNS: boom");
        clear_stages();
    }
}

//! 配置后处理 / Lint 阶段注册器。
//!
//! 对应 Go `infra/conf/lint.go`：解析后的 [`Config`] 在使用前必须经过一组
//! `LintStage` 处理（默认注册 `FakeDNS` 自动填充与嗅探检查，见 [`crate::init`]）。
//!
//! ## 模型（vs Go）
//!
//! Go 用全局 `configureFilePostProcessingStages map[string]ConfigureFilePostProcessingStage`
//! + `func init()` 自动注册（FakeDNS 是 `infra/conf/init.go` 的 `init()` 注册）。
//!
//! Rust 的 lib crate 没有 `init()` 自动注入宿主 crate 状态的概念（每个 crate
//! 的 `init()` 各自独立，无法跨 crate 自动连入）。故采用 Go 等价：
//!
//! - 注册表用 [`std::sync::LazyLock`] 持有（首次访问时建空 map），
//! - 调用方在启动早期调用 [`register_stage`] / [`crate::init::register_builtin_stages`]
//!   注入。
//! - [`post_process`] 顺序跑所有阶段，首错即返回（与 Go 一致）。
//!
//! 跨 crate 复用：各 `xray-app-*` crate 可在自己模块顶层 `pub fn init()` 内
//! 调用 `xray_conf::lint::register_stage(...)`，再由 `xray-core` 启动时
//! 显式调用 `xray_conf::init::register_builtin_stages()` 把核心阶段串起来。

use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};

use parking_lot::Mutex;

use crate::config::Config;
use crate::error::ConfError;

/// Lint 阶段错误。对应 Go `errors.New("Rejected by Postprocessing Stage ", k)`。
///
/// `thiserror` 提供 `Display`，宿主 crate 通过 `?` 转 [`crate::error::ConfError`]
/// 时在 `From` 适配层完成。
#[derive(thiserror::Error, Debug)]
pub enum LintError {
    /// 阶段名 + 内层错误。对应 Go 的 `Rejected by Postprocessing Stage <name>: <err>`。
    #[error("rejected by postprocessing stage {stage}: {message}")]
    Stage { stage: &'static str, message: String },

    /// 配置语义非法（被 lint 规则直接拒绝）。
    #[error("{0}")]
    Invalid(String),
}

impl From<LintError> for ConfError {
    fn from(err: LintError) -> Self {
        ConfError::Invalid(err.to_string())
    }
}

/// 单个后处理阶段。对应 Go `ConfigureFilePostProcessingStage` 接口。
///
/// 实现者通常需要 `&mut Config`（FakeDNS 默认池填充就是写 `cfg.fake_dns`）。
pub trait LintStage: Send + Sync {
    /// 阶段名（用于错误消息与注册去重）。
    fn name(&self) -> &'static str;
    /// 处理配置；返回 `Err` 终止 [`post_process`] 链。
    fn process(&self, cfg: &mut Config) -> Result<(), LintError>;
}

/// 全局注册表。`BTreeMap` 保证阶段按名字字典序执行（Go 是 `map` 随机序，
/// 我们刻意稳态化便于测试断言）。值用 `Arc` 让 `post_process` 可在持锁外
/// 调用阶段回调（避免阶段内部回调 `register_stage` 死锁）。
static REGISTRY: LazyLock<Mutex<BTreeMap<&'static str, Arc<dyn LintStage>>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// 注册一个后处理阶段。同名覆盖——与 Go 的 `map[k] = v` 行为一致。
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use xray_conf::lint::{register_stage, LintStage, post_process};
/// use xray_conf::Config;
///
/// struct Noop;
/// impl LintStage for Noop {
///     fn name(&self) -> &'static str { "noop" }
///     fn process(&self, _cfg: &mut Config) -> Result<(), xray_conf::lint::LintError> { Ok(()) }
/// }
///
/// register_stage(Arc::new(Noop));
/// let mut cfg = Config::default();
/// post_process(&mut cfg).unwrap();
/// ```
pub fn register_stage(stage: Arc<dyn LintStage>) {
    REGISTRY.lock().insert(stage.name(), stage);
}

/// 清空注册表（仅测试使用；生产代码无需调用）。
#[doc(hidden)]
pub fn clear_stages() {
    REGISTRY.lock().clear();
}

/// 当前已注册阶段名（按字典序）。测试与诊断用。
pub fn registered_stages() -> Vec<&'static str> {
    REGISTRY.lock().keys().copied().collect()
}

/// 顺序执行所有已注册阶段。对应 Go `PostProcessConfigureFile`：
/// 任一阶段返回 `Err` 即中止并包装为 `LintError::Stage { stage, message }`。
///
/// # Errors
///
/// - 任一阶段的 [`LintStage::process`] 返回错误时返回该错误；
/// - 阶段名取自 [`LintStage::name`]。
pub fn post_process(cfg: &mut Config) -> Result<(), LintError> {
    // 复制 Arc 后释放锁：避免 process 期间持锁（阶段可能回调注册表）。
    let stages: Vec<Arc<dyn LintStage>> = REGISTRY.lock().values().cloned().collect();
    for stage in stages {
        if let Err(err) = stage.process(cfg) {
            return Err(match err {
                LintError::Stage { .. } => err,
                other => LintError::Stage {
                    stage: stage.name(),
                    message: other.to_string(),
                },
            });
        }
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    //! 测试工具：`TEST_LOCK` 供同 crate 其它测试模块共享（lint_tests + init::tests
    //! 共用一个全局注册表，必须串行化）。

    use std::sync::LazyLock;

    /// 全局注册表测试锁：避免并行测试互相污染注册表。
    #[doc(hidden)]
    pub static TEST_LOCK: LazyLock<parking_lot::Mutex<()>> =
        LazyLock::new(|| parking_lot::Mutex::new(()));
}

#[cfg(test)]
mod lint_tests {
    use super::tests::TEST_LOCK;
    use super::*;
    use crate::app_config::FakeDnsConfig;

    /// 计数器 A：name 不同用于验证多阶段顺序触发。
    struct CounterA {
        hits: std::sync::Arc<parking_lot::Mutex<u32>>,
    }
    impl LintStage for CounterA {
        fn name(&self) -> &'static str {
            "counter-a"
        }
        fn process(&self, _cfg: &mut Config) -> Result<(), LintError> {
            *self.hits.lock() += 1;
            Ok(())
        }
    }

    /// 计数器 B。
    struct CounterB {
        hits: std::sync::Arc<parking_lot::Mutex<u32>>,
    }
    impl LintStage for CounterB {
        fn name(&self) -> &'static str {
            "counter-b"
        }
        fn process(&self, _cfg: &mut Config) -> Result<(), LintError> {
            *self.hits.lock() += 1;
            Ok(())
        }
    }

    /// 故意失败的阶段。
    struct Boom;
    impl LintStage for Boom {
        fn name(&self) -> &'static str {
            "boom"
        }
        fn process(&self, _cfg: &mut Config) -> Result<(), LintError> {
            Err(LintError::Invalid("kaboom".into()))
        }
    }

    #[test]
    fn post_process_with_no_stages_is_ok() {
        let _g = TEST_LOCK.lock();
        super::clear_stages();
        let mut cfg = Config::default();
        super::post_process(&mut cfg).unwrap();
    }

    #[test]
    fn post_process_runs_all_stages_in_order() {
        let _g = TEST_LOCK.lock();
        super::clear_stages();
        let hits_a = std::sync::Arc::new(parking_lot::Mutex::new(0));
        let hits_b = std::sync::Arc::new(parking_lot::Mutex::new(0));
        super::register_stage(Arc::new(CounterA {
            hits: hits_a.clone(),
        }));
        super::register_stage(Arc::new(CounterB {
            hits: hits_b.clone(),
        }));
        let mut cfg = Config::default();
        super::post_process(&mut cfg).unwrap();
        assert_eq!(*hits_a.lock(), 1);
        assert_eq!(*hits_b.lock(), 1);
    }

    #[test]
    fn post_process_short_circuits_on_error() {
        let _g = TEST_LOCK.lock();
        super::clear_stages();
        let hits = std::sync::Arc::new(parking_lot::Mutex::new(0));
        super::register_stage(Arc::new(Boom));
        super::register_stage(Arc::new(CounterA {
            hits: hits.clone(),
        }));
        let mut cfg = Config::default();
        let err = super::post_process(&mut cfg).unwrap_err();
        match err {
            LintError::Stage { stage, .. } => assert_eq!(stage, "boom"),
            _ => panic!("expected Stage error, got {err:?}"),
        }
        // counter-a 阶段未触发
        assert_eq!(*hits.lock(), 0);
    }

    #[test]
    fn register_overrides_same_name() {
        let _g = TEST_LOCK.lock();
        super::clear_stages();
        super::register_stage(Arc::new(Boom));
        // 同名覆盖 — Boom (name="boom") → CounterA (name="counter-a")：不同名，
        // 应并存。改为两次注册 Boom 后断言只剩一个。
        super::register_stage(Arc::new(Boom));
        let names = super::registered_stages();
        assert_eq!(names, vec!["boom"]);
    }

    #[test]
    fn registered_stages_are_sorted() {
        // 与同模块其它 registry 测试同锁——本测试曾漏锁，CI macOS 并行下
        // clear+注册 Boom 与 built.rs 的 cfg.build() 测试竞态（bd 5x41 同族，
        // CI run 35087312070 Workspace lib 步实证）。
        let _g = TEST_LOCK.lock();
        super::clear_stages();
        // 注册乱序 → 应按字典序返回
        super::register_stage(Arc::new(CounterB {
            hits: std::sync::Arc::new(parking_lot::Mutex::new(0)),
        })); // "counter-b"
        super::register_stage(Arc::new(Boom)); // "boom"
        let names = super::registered_stages();
        // boom < counter-b → boom 在前
        assert_eq!(names, vec!["boom", "counter-b"]);
    }

    #[test]
    fn lint_error_display_contains_name() {
        let err = LintError::Stage {
            stage: "fake-dns",
            message: "no fakedns address".into(),
        };
        let s = err.to_string();
        assert!(s.contains("fake-dns"));
        assert!(s.contains("no fakedns address"));
    }

    #[test]
    fn post_process_can_mutate_config() {
        let _g = TEST_LOCK.lock();
        super::clear_stages();
        // 验证 LintStage::process 拿到的确实是 &mut Config（FakeDNS 阶段会写）。
        struct WriteFake;
        impl LintStage for WriteFake {
            fn name(&self) -> &'static str {
                "write-fake"
            }
            fn process(&self, cfg: &mut Config) -> Result<(), LintError> {
                cfg.fake_dns = Some(FakeDnsConfig {
                    ip_pool: Some("198.18.0.0/15".into()),
                    pool_size: Some(65535),
                    pools: None,
                });
                Ok(())
            }
        }
        super::register_stage(Arc::new(WriteFake));
        let mut cfg = Config::default();
        assert!(cfg.fake_dns.is_none());
        super::post_process(&mut cfg).unwrap();
        let fd = cfg.fake_dns.expect("fake_dns should be set");
        assert_eq!(fd.ip_pool.as_deref(), Some("198.18.0.0/15"));
        assert_eq!(fd.pool_size, Some(65535));
    }

    #[test]
    fn lint_error_into_conferror() {
        let lint_err = LintError::Invalid("bad".into());
        let conf_err: ConfError = lint_err.into();
        assert!(conf_err.to_string().contains("bad"));
    }
}
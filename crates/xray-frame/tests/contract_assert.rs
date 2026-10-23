//! P1-7 A 块验收：`assert_plugin_contract!` 宏从集成测试（宏机制意义上的
//! 外部 crate 调用面）可调用，正/负两条验证。
//!
//! - 正：合规桩（条款面合法 + lifecycle 三相直通）→ 宏通过；
//! - 负：N/A 理由为空 → 宏 panic（P1-7 拍板 P2.2：理由必须非空）。

use xray_frame::{
    ClauseId, Lifecycle, Plugin, PluginContext, PluginContract, PluginError, assert_plugin_contract,
};

struct PassThroughLifecycle;

impl Lifecycle for PassThroughLifecycle {
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

/// 合规桩：clauses / extra / not_applicable 三面全合法。
#[derive(Default)]
struct Compliant;

impl Plugin for Compliant {
    fn name(&self) -> &'static str {
        "compliant-stub"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn contract(&self) -> &PluginContract {
        static CONTRACT: PluginContract = PluginContract {
            clauses: &[ClauseId::LogDiscipline, ClauseId::ConfigSectionOnly],
            extra: &[("X-1", "协议专属条款占位")],
            not_applicable: &[(ClauseId::PoolDiscipline, "该桩零缓冲分配")],
        };
        &CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &PassThroughLifecycle
    }

    fn build(&self, _ctx: &mut PluginContext) -> Result<(), PluginError> {
        Ok(())
    }
}

/// 违规桩：N/A 理由为空字符串。
#[derive(Default)]
struct EmptyNaReason;

impl Plugin for EmptyNaReason {
    fn name(&self) -> &'static str {
        "empty-na-reason-stub"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn contract(&self) -> &PluginContract {
        static CONTRACT: PluginContract = PluginContract {
            clauses: &[],
            extra: &[],
            not_applicable: &[(ClauseId::PoolDiscipline, "")],
        };
        &CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &PassThroughLifecycle
    }

    fn build(&self, _ctx: &mut PluginContext) -> Result<(), PluginError> {
        Ok(())
    }
}

#[test]
fn compliant_plugin_passes_contract_macro() {
    assert_plugin_contract!(Compliant);
}

#[test]
#[should_panic(expected = "N/A 但理由为空")]
fn empty_na_reason_fails_contract_macro() {
    assert_plugin_contract!(EmptyNaReason);
}

//! P0-3 PluginContext 集成验收（任务书 2026-10-23 五组用例）：
//! 组装/spawn 托管/with_deadline 真超时/段路由+组合源。
//! handler 登记面测例随 `take_handler` 收回 `pub(crate)` 迁入 src/context.rs 单元测。

use std::{sync::Arc, time::Duration};

use serde_json::json;
use skeleton::{
    clock::{MockClock, SystemClock},
    config::{ConfigError, ConfigPort, EnvSource, MockEnv},
};
use skeleton_infra::fx::{FxScope, ScopeClosed};
use xray_frame::{
    context::{PluginContext, derive_fingerprint},
    error::PluginError,
    logging::LogFacade,
};

const FIXED_ADDR: &str = "127.0.0.1:10808";

/// 组装配方（验收①）：FxScope::new + SystemClock + IdGen(fingerprint, clock)。
fn ctx_at(plugin: &'static str, config: serde_json::Value) -> PluginContext {
    PluginContext::new(
        plugin,
        Arc::new(FxScope::new()),
        Arc::new(SystemClock),
        derive_fingerprint(Some(FIXED_ADDR)),
        Arc::new(MockEnv::new()),
        config,
        LogFacade::new(plugin, vec![]),
    )
}

#[tokio::test]
async fn spawn_joins_value_through_scope() {
    let ctx = ctx_at("stub", json!({}));
    let spawned = ctx.spawn(async { 41 + 1 }).expect("scope accepting");
    assert_eq!(spawned.join().await.expect("task ok"), 42);
}

#[tokio::test]
async fn spawn_after_close_is_scope_closed() {
    let fx = Arc::new(FxScope::new());
    fx.close();
    let ctx = PluginContext::new(
        "stub",
        fx,
        Arc::new(SystemClock),
        derive_fingerprint(None),
        Arc::new(MockEnv::new()),
        json!({}),
        LogFacade::new("stub", vec![]),
    );
    assert!(matches!(
        ctx.spawn(async {}),
        Err(ScopeClosed) // 闸关拒新 spawn（fx.rs:264 契约透传）
    ));
}

#[tokio::test]
async fn with_deadline_times_out_for_real() {
    let ctx = ctx_at("stub", json!({}));
    // 真超时必红原则：10ms deadline + 永不完成的任务，断言 Err(Elapsed)，不放宽。
    let result: Result<(), tokio::time::error::Elapsed> =
        ctx.with_deadline(std::future::pending::<()>(), Duration::from_millis(10)).await;
    assert!(result.is_err(), "10ms deadline 必须真超时");
}

#[tokio::test]
async fn with_deadline_passes_through_value() {
    let ctx = ctx_at("stub", json!({}));
    let value =
        ctx.with_deadline(async { 21 * 2 }, Duration::from_secs(1)).await.expect("within deadline");
    assert_eq!(value, 42);
}

#[test]
fn section_routes_outbounds_by_protocol() {
    let config = json!({
        "outbounds": [
            {"protocol": "dns", "settings": {}},
            {"protocol": "freedom", "settings": {"domainStrategy": "AsIs"}}
        ]
    });
    let ctx = ctx_at("freedom", config);
    let section = ctx.section().expect("outbound section present");
    assert_eq!(section["settings"]["domainStrategy"], "AsIs");
}

#[test]
fn section_falls_back_to_inbounds_by_protocol() {
    let config = json!({
        "inbounds": [
            {"protocol": "dokodemo-door", "settings": {"port": 10808}}
        ]
    });
    let ctx = ctx_at("dokodemo-door", config);
    assert_eq!(ctx.section().expect("inbound section present")["settings"]["port"], 10808);
}

#[test]
fn section_missing_is_fail_fast_error() {
    let ctx = ctx_at("no-such-plugin", json!({"outbounds": [{"protocol": "dns"}]}));
    match ctx.section() {
        Err(PluginError::Config(ConfigError::Missing { key })) => {
            assert!(key.contains("protocol=no-such-plugin"), "{key}");
        },
        other => panic!("expected Config(Missing), got {other:?}"),
    }
}

struct TwoKeysPort;

/// 测试端口用显式映射（EnvError→ConfigError 语义对齐 udf config.rs 文档例）。
fn get_key(env: &dyn EnvSource, key: &str) -> Result<String, ConfigError> {
    match env.get(key) {
        Ok(value) => Ok(value),
        Err(skeleton::config::EnvError::Missing) => {
            Err(ConfigError::Missing { key: key.to_owned() })
        },
        Err(skeleton::config::EnvError::NotUnicode(value)) => {
            Err(ConfigError::NotUnicode { key: key.to_owned(), value })
        },
    }
}

impl ConfigPort for TwoKeysPort {
    type Config = (String, String);

    fn load(&self, env: &dyn EnvSource) -> Result<Self::Config, ConfigError> {
        Ok((get_key(env, "port")?, get_key(env, "log_level")?))
    }
}

#[test]
fn load_config_section_overrides_env_and_env_backfills() {
    let config = json!({
        "outbounds": [
            {"protocol": "freedom", "settings": {"port": "10808"}}
        ]
    });
    let env = Arc::new(MockEnv::new().with("port", "9999").with("log_level", "warn"));
    let ctx = PluginContext::new(
        "freedom",
        Arc::new(FxScope::new()),
        Arc::new(SystemClock),
        derive_fingerprint(Some(FIXED_ADDR)),
        env,
        config,
        LogFacade::new("freedom", vec![]),
    );
    let (port, level) = ctx.load_config(TwoKeysPort).expect("combined source");
    assert_eq!(port, "10808", "段值压过 env 值");
    assert_eq!(level, "warn", "env 兜底生效");
}

#[test]
fn fingerprint_deterministic_per_address() {
    let a = derive_fingerprint(Some(FIXED_ADDR));
    assert_eq!(a, derive_fingerprint(Some(FIXED_ADDR)), "同地址同指纹");
    assert_ne!(a, derive_fingerprint(Some("127.0.0.1:10809")), "异址异指纹");
}

#[test]
fn fingerprint_fallback_without_address_smoke() {
    // pid+启动时刻派生：仅冒烟（值不可断言），确保路径可执行不炸。
    let _ = derive_fingerprint(None);
}

#[test]
fn conn_id_monotonic_under_mock_clock_and_fixed_fingerprint() {
    let clock = Arc::new(MockClock::new());
    let ctx = PluginContext::new(
        "stub",
        Arc::new(FxScope::new()),
        clock.clone(),
        derive_fingerprint(Some(FIXED_ADDR)),
        Arc::new(MockEnv::new()),
        json!({}),
        LogFacade::new("stub", vec![]),
    );
    let first = ctx.next_conn_id();
    clock.advance(Duration::from_millis(1));
    let second = ctx.next_conn_id();
    assert!(second > first, "同指纹 conn_id 严格递增：{first} -> {second}");
}

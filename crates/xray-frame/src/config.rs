//! P3-2 per-plugin 配置段路由（坑约束 7：插件只能取自己那一段）。
//!
//! - [`PluginConfig::section`] 是
//!   [`PluginContext::section`](crate::context::PluginContext::section)
//!   的无实例形态（配置驱动装配/测试用）：同一 `outbounds[]` → `inbounds[]` 扫描序、同一缺段
//!   `Missing` 错误文案——两入口同规，禁分叉。
//! - [`build_plugins_from_config`] 是**配置驱动**的选择性 build：遍历配置条目， `protocol`
//!   命中注册链插件才 build；未插件化协议跳过（双轨共存——旧解析面 仍归
//!   `xray-conf`/`xray-core`，本单不删旧路径，P3 后续批次收敛）。缺段 fail-fast 由插件 build 内
//!   `ctx.section()?` 承担（L5：经
//!   [`FrameworkBuilder::with_config`](crate::assembly::FrameworkBuilder::with_config) 全量 build
//!   管线时，注册链插件无段即整链 `Err`，见 tests/config_routing.rs）。
//! - 已知限制（与 `ctx.section()` 首匹配语义镜像）：同 protocol 多实例条目 v0.1 只 build
//!   首个；按实例 index/tag 路由属 P3 后续批次升级。

use std::sync::Arc;

use skeleton::{
    clock::SystemClock,
    config::{ConfigError, StdEnv},
};

use crate::{
    assembly::guarded_build,
    context::{PluginContext, derive_fingerprint},
    error::PluginError,
    logging::LogFacade,
    plugin::Plugin,
};

/// per-plugin 配置段句柄：只能看到该插件自己的条目（段隔离由构造保证——
/// 拿到 [`PluginConfig`] 就拿不到全局根）。
#[derive(Debug)]
pub struct PluginConfig<'a> {
    section: &'a serde_json::Value,
}

impl<'a> PluginConfig<'a> {
    /// 取 `protocol == name` 的配置段；缺失 = `Err(Missing)`（fail-fast，禁回落
    /// 全局）。扫描序 `outbounds[]` → `inbounds[]`，条目内首匹配——与
    /// `PluginContext::section()` 逐字同规。
    pub fn section(name: &str, root: &'a serde_json::Value) -> Result<Self, ConfigError> {
        for layout in ["outbounds", "inbounds"] {
            let Some(items) = root.get(layout).and_then(|v| v.as_array()) else {
                continue;
            };
            if let Some(found) = items
                .iter()
                .find(|item| item.get("protocol").and_then(|p| p.as_str()) == Some(name))
            {
                return Ok(Self { section: found });
            }
        }
        Err(ConfigError::Missing {
            key: format!("outbounds[]/inbounds[] protocol={name} (section missing)"),
        })
    }

    /// 段本体观察面（对拍/测试用；只读借用）。
    pub fn value(&self) -> &'a serde_json::Value {
        self.section
    }

    /// 反序列化为插件自己的配置类型；serde 错误自带字段路径（坑约束 7 的
    /// 「类型不匹配 → Err 带字段名」由此承担，key 标 `(config)` = udf
    /// `ConfigError::Parse` 整体反序列化约定）。
    pub fn parse<T: serde::de::DeserializeOwned>(&self) -> Result<T, ConfigError> {
        serde_json::from_value(self.section.clone()).map_err(|source| ConfigError::Parse {
            key: "(config)".into(),
            source: Box::new(source),
        })
    }
}

/// 配置驱动装配辅助（P3-2 演示面）：按 `outbounds[]/inbounds[]` 条目序遍历，
/// `protocol` 命中注册链插件的逐个 `build(ctx)`（panic 装甲同装配管线），返回
/// build 完成的插件名名单（配置序）。
///
/// - 配置里注册链没有的 protocol → **跳过**（双轨共存：该条目仍走旧解析面， 本单不接管装配；P3
///   收敛后未注册 = 装配门 `Err`）。
/// - 注册链插件全程无条目 → 不 build、不报错（配置没配该协议 = 合法态； 「插件被 build 但缺段」的
///   fail-fast 在 `ctx.section()?`）。
/// - ctx 构造配方与装配根同款（StdEnv/SystemClock/derive_fingerprint；build 期插件禁
///   spawn——L1——故逐插件短命 scope 无残留）。
pub fn build_plugins_from_config(
    config_root: &serde_json::Value,
    plugins: &[Arc<dyn Plugin>],
) -> Result<Vec<&'static str>, PluginError> {
    let mut built = Vec::new();
    for layout in ["outbounds", "inbounds"] {
        let Some(items) = config_root.get(layout).and_then(|v| v.as_array()) else {
            continue;
        };
        for entry in items {
            let Some(proto) = entry.get("protocol").and_then(|p| p.as_str()) else {
                continue;
            };
            let Some(plugin) = plugins.iter().find(|p| p.name() == proto) else {
                continue;
            };
            if built.contains(&plugin.name()) {
                continue;
            }
            let mut ctx = PluginContext::new(
                plugin.name(),
                Arc::new(skeleton_infra::fx::FxScope::new()),
                Arc::new(SystemClock),
                derive_fingerprint(None),
                Arc::new(StdEnv),
                config_root.clone(),
                LogFacade::new(plugin.name(), vec![]),
            );
            guarded_build(plugin, &mut ctx)?;
            built.push(plugin.name());
        }
    }
    Ok(built)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc as StdArc, OnceLock};

    use serde_json::json;

    use super::*;
    use crate::plugin::{Lifecycle, PluginContract};

    /// 记录 build 期看到的段（段隔离断言锚）。seen 是 build 期运行时写入，
    /// 无声明期初始化值 → OnceLock（非 LazyLock）。
    struct RecordingPlugin {
        seen: OnceLock<serde_json::Value>,
    }

    struct NoopLifecycleImpl;

    impl Lifecycle for NoopLifecycleImpl {
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

    static RECORDING_LIFECYCLE: NoopLifecycleImpl = NoopLifecycleImpl;
    static RECORDING_CONTRACT: PluginContract =
        PluginContract { clauses: &[], extra: &[], not_applicable: &[] };

    impl Plugin for RecordingPlugin {
        fn name(&self) -> &'static str {
            "recorder"
        }

        fn version(&self) -> &'static str {
            "0.0.0"
        }

        fn contract(&self) -> &PluginContract {
            &RECORDING_CONTRACT
        }

        fn lifecycle(&self) -> &dyn Lifecycle {
            &RECORDING_LIFECYCLE
        }

        fn build(&self, ctx: &mut PluginContext) -> Result<(), PluginError> {
            let section = ctx.section()?;
            let _ = self.seen.set(section.clone());
            Ok(())
        }
    }

    #[test]
    fn section_found_in_outbounds_first() {
        let root = json!({
            "outbounds": [{"protocol": "socks", "tag": "out", "settings": {"a": 1}}],
            "inbounds": [{"protocol": "socks", "tag": "in", "settings": {"b": 2}}],
        });
        let cfg = PluginConfig::section("socks", &root).expect("section");
        assert_eq!(cfg.value()["tag"], "out");
    }

    #[test]
    fn section_falls_back_to_inbounds() {
        let root = json!({"inbounds": [{"protocol": "socks", "settings": {"udp": true}}]});
        let cfg = PluginConfig::section("socks", &root).expect("section");
        assert_eq!(cfg.value()["settings"]["udp"], true);
    }

    #[test]
    fn section_missing_is_err_not_global_fallback() {
        let root = json!({"outbounds": [{"protocol": "freedom"}], "other": {"socks": {}}});
        let err = PluginConfig::section("socks", &root).unwrap_err();
        assert!(
            matches!(err, ConfigError::Missing { ref key } if key.contains("protocol=socks")),
            "got: {err:?}"
        );
    }

    #[test]
    fn parse_type_mismatch_carries_field_path() {
        let root =
            json!({"outbounds": [{"protocol": "rec", "settings": {"port": "not-a-number"}}]});
        let cfg = PluginConfig::section("rec", &root).expect("section");
        #[derive(serde::Deserialize, Debug)]
        struct S {
            #[allow(dead_code)]
            port: u16,
        }
        let err = cfg.parse::<S>().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("port"), "field name in error: {msg}");
    }

    #[test]
    fn build_from_config_builds_only_registered_protocols() {
        // 具体型 Arc 在手（不用 downcast），fn 消费的是擦除后的 clone。
        let recorder = StdArc::new(RecordingPlugin { seen: OnceLock::new() });
        let root = json!({
            "outbounds": [
                {"protocol": "recorder", "settings": {"k": "v"}},
                {"protocol": "vless", "settings": {}},
            ],
            "inbounds": [{"protocol": "recorder", "settings": {"k2": "v2"}}],
        });
        let plugins: Vec<Arc<dyn Plugin>> = vec![StdArc::clone(&recorder) as Arc<dyn Plugin>];
        let built = build_plugins_from_config(&root, &plugins).expect("built");
        // 未注册的 vless 跳过（双轨共存）；recorder 只 build 首个条目。
        assert_eq!(built, ["recorder"]);
        let seen = recorder.seen.get().expect("built");
        assert_eq!(seen["settings"]["k"], "v");
    }

    #[test]
    fn build_from_config_without_entry_leaves_plugin_unbuilt() {
        let recorder = StdArc::new(RecordingPlugin { seen: OnceLock::new() });
        let root = json!({"outbounds": [{"protocol": "freedom"}]});
        let plugins: Vec<Arc<dyn Plugin>> = vec![StdArc::clone(&recorder) as Arc<dyn Plugin>];
        let built = build_plugins_from_config(&root, &plugins).expect("no entry");
        assert!(built.is_empty());
        assert!(recorder.seen.get().is_none());
    }

    #[test]
    fn build_panics_are_contained_as_err() {
        struct PanicPlugin;
        impl Plugin for PanicPlugin {
            fn name(&self) -> &'static str {
                "panic"
            }

            fn version(&self) -> &'static str {
                "0.0.0"
            }

            fn contract(&self) -> &PluginContract {
                &RECORDING_CONTRACT
            }

            fn lifecycle(&self) -> &dyn Lifecycle {
                &RECORDING_LIFECYCLE
            }

            fn build(&self, _ctx: &mut PluginContext) -> Result<(), PluginError> {
                panic!("boom");
            }
        }
        let root = json!({"outbounds": [{"protocol": "panic"}]});
        let plugins: Vec<Arc<dyn Plugin>> = vec![StdArc::new(PanicPlugin)];
        let err = build_plugins_from_config(&root, &plugins).unwrap_err();
        assert!(err.to_string().contains("build panicked"), "got: {err}");
    }
}

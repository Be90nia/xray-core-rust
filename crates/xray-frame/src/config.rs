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
use std_ext::json::JsonMode;

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
                crate::scope::ArmScope::new(),
                Arc::new(SystemClock),
                derive_fingerprint(None),
                Arc::new(StdEnv),
                config_root.clone(),
                LogFacade::new(plugin.name(), vec![]),
                // 配置驱动 build 无装配根共享面 → 本次调用共享一份环
                //（nn8os 2a：同一装配动作的事件落同一审计流）。
                Arc::new(crate::audit::AuditHandle::new(crate::audit::DEFAULT_AUDIT_RING_CAP)),
            );
            guarded_build(plugin, &mut ctx)?;
            built.push(plugin.name());
        }
    }
    Ok(built)
}

// =========================================================================
// 配置装配面（面 1 · 能力收敛方案 §2 面 1）：Xray 语义折叠
// =========================================================================
//
// 派生三段式（ADR-1）：
// - **udf 基件**：`std_ext::json::{decode, decode_str, decode_slice}` + `JsonMode` （注释容忍 /
//   strict 双模 + 64MiB 上限 + 行列位置错误）；
//   `skeleton_infra::config::ConfigFile<C>`（层序列的"分层装载"观念）。
// - **派生方式**：**组合包装 + 新类型**。**不包装 `ConfigFile::merge_over`**——
//   其"数组整体替换"是**刻意设计**（fail-visible），与 Xray 的 tag 数组合并
//   语义互斥；包装即语义冲突。本件复用 udf 的**解码件**与**层序观念**，折叠 实现自建（Xray
//   语义属派生层职责）。
// - **主仓消费**：`crates/xray-conf/src/serial.rs`（`merge_configs`）单点调用； YAML/TOML/JSON5
//   **解析器**留 xray-conf（第三方依赖 + Go 格式判定）， 但解成 `Value` 后经
//   [`XrayConfigLayers::push_value`] 进同一折叠语义。

/// 折叠策略：哪些键整体替换、哪些键键级合并、哪些数组按 tag 合并。
#[derive(Debug, Clone, Copy)]
pub struct MergePolicy {
    /// 整体替换键（块级配置：后层出现即整体覆盖前层）。
    pub block_replace_keys: &'static [&'static str],
    /// 键级合并键（两侧皆为对象时逐键合并，后层同键覆盖）。
    pub map_merge_keys: &'static [&'static str],
    /// tag 感知数组合并规格。
    pub tag_arrays: &'static [TagArraySpec],
}

/// tag 感知数组合并规格（键 + tag 字段名 + 未命中策略）。
#[derive(Debug, Clone, Copy)]
pub struct TagArraySpec {
    /// 数组键（如 `"inbounds"` / `"outbounds"`）。
    pub key: &'static str,
    /// tag 字段名（Xray = `"tag"`）。
    pub tag_key: &'static str,
    /// 未命中 tag 时的处置。
    pub unmatched: UnmatchedPolicy,
}

/// 未命中 tag 的处置策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmatchedPolicy {
    /// 追加到尾部（Xray inbound 语义）。
    Append,
    /// 前插到头部（收集后整体前插）。
    Prepend,
    /// 前插到头部；但来源名（source）含指定子串时改为追加到尾部
    /// （Xray outbound 的 `source` 含 `"tail"` 语义）。
    PrependUnlessSourceContains(&'static str),
}

/// Xray 合并语义常量（派生层持有 Xray 语义 = 允许）。
///
/// 键清单对齐 Go `infra/conf.Config.Override`（xray.go:410-497）+ 本仓
/// `crates/xray-conf/src/serial.rs` 的 typed 覆盖面：`log`/`routing`/`dns`/
/// `transport`/`policy`/`api`/`metrics`/`stats`/`reverse`/`fakeDns`/
/// `observatory`/`burstObservatory`/`version`/`geodata` 为块级整体替换；
/// `env` 为键级合并；`inbounds`/`outbounds` 为 tag 感知数组合并。
static XRAY_POLICY: MergePolicy = MergePolicy {
    block_replace_keys: &[
        "log",
        "routing",
        "dns",
        "transport",
        "policy",
        "api",
        "metrics",
        "stats",
        "reverse",
        "fakeDns",
        "observatory",
        "burstObservatory",
        "version",
        "geodata",
    ],
    map_merge_keys: &["env"],
    tag_arrays: &[
        TagArraySpec { key: "inbounds", tag_key: "tag", unmatched: UnmatchedPolicy::Append },
        TagArraySpec {
            key: "outbounds",
            tag_key: "tag",
            unmatched: UnmatchedPolicy::PrependUnlessSourceContains("tail"),
        },
    ],
};

/// Xray 合并策略（主仓只调本函数，不另持一份语义清单）。
pub fn xray_policy() -> &'static MergePolicy {
    &XRAY_POLICY
}

/// 层错误（文件级归属 + 行列位置；主仓侧映射到既有 `ConfError::Parse`，
/// **错误文案逐字不变**）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigLayerError {
    /// 文件读取失败。
    Read {
        /// 源文件路径。
        path: String,
        /// 失败原因。
        message: String,
    },
    /// 解码失败（udf `std_ext::json` 口径：行列位置 + 原因）。
    Parse {
        /// 源文件路径。
        path: String,
        /// 行号（1 起；无位置语义为 0）。
        line: u32,
        /// 列号（1 起；无位置语义为 0）。
        column: u32,
        /// 失败原因。
        message: String,
    },
}

impl std::fmt::Display for ConfigLayerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read { path, message } => write!(f, "read config {path}: {message}"),
            Self::Parse { path, line, column, message } => {
                write!(f, "parse config {path}:{line}:{column}: {message}")
            },
        }
    }
}

impl std::error::Error for ConfigLayerError {}

/// 一层配置（值 + 来源名）。
#[derive(Debug, Clone)]
struct ConfigLayer {
    /// 来源名（文件路径 / 远程配置标识；`source` 判定用）。
    source: String,
    /// 该层的值。
    value: serde_json::Value,
}

/// 层序列：低→高，与 udf `ConfigFile` 的折叠序一致（Xray 语义 = Go 多 `-c`
/// 文件的覆盖序）。
#[derive(Debug, Clone, Default)]
pub struct XrayConfigLayers {
    layers: Vec<ConfigLayer>,
}

impl XrayConfigLayers {
    /// 空层链。
    pub fn new() -> Self {
        Self { layers: Vec::new() }
    }

    /// 注入已解析层（远程配置 / 测试替身；来源名 = 空串 → outbound 未命中
    /// 走"前插"分支）。
    pub fn push_value(&mut self, value: serde_json::Value) -> &mut Self {
        self.push_value_from(value, "")
    }

    /// 注入已解析层 + 来源名（来源名参与 outbound 的 `"tail"` 判定）。
    pub fn push_value_from(
        &mut self,
        value: serde_json::Value,
        source: impl Into<String>,
    ) -> &mut Self {
        self.layers.push(ConfigLayer { source: source.into(), value });
        self
    }

    /// 读文件 + 解码（udf `std_ext::json`：注释容忍/strict 由 mode 定；
    /// 64MiB 上限；行列位置错误）。
    pub fn push_file(
        &mut self,
        path: &std::path::Path,
        mode: JsonMode,
    ) -> Result<&mut Self, ConfigLayerError> {
        let file = std::fs::File::open(path).map_err(|e| ConfigLayerError::Read {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        let value = std_ext::json::decode(file, mode).map_err(|e| ConfigLayerError::Parse {
            path: path.display().to_string(),
            line: e.line,
            column: e.column,
            message: e.message,
        })?;
        self.push_value_from(value, path.display().to_string());
        Ok(self)
    }

    /// 层数。
    pub fn len(&self) -> usize {
        self.layers.len()
    }

    /// 空层链。
    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }

    /// 按策略折叠出最终值（**Xray 语义在此唯一实现**）。
    pub fn merge(&self, policy: &MergePolicy) -> serde_json::Value {
        let mut acc = serde_json::Value::Object(serde_json::Map::new());
        for layer in &self.layers {
            fold_layer(&mut acc, &layer.value, &layer.source, policy);
        }
        acc
    }
}

/// 一层折叠进累加值（层内键序 = JSON 对象序）。
fn fold_layer(
    acc: &mut serde_json::Value,
    incoming: &serde_json::Value,
    source: &str,
    policy: &MergePolicy,
) {
    let Some(incoming_obj) = incoming.as_object() else {
        // 非对象层 = 整体替换（顶层不是对象的配置形态，Xray 无此语义 → 交给
        // 调用方前置校验）。
        *acc = incoming.clone();
        return;
    };
    if !acc.is_object() {
        *acc = serde_json::Value::Object(serde_json::Map::new());
    }
    let Some(acc_obj) = acc.as_object_mut() else {
        return;
    };
    for (key, value) in incoming_obj {
        if policy.block_replace_keys.contains(&key.as_str()) {
            acc_obj.insert(key.clone(), value.clone());
            continue;
        }
        if policy.map_merge_keys.contains(&key.as_str()) {
            merge_map_value(acc_obj, key, value);
            continue;
        }
        if let Some(spec) = policy.tag_arrays.iter().find(|spec| spec.key == key)
            && value.is_array()
        {
            merge_tag_array(acc_obj, key, value, spec, source);
            continue;
        }
        // 其余键：后层整体替换（默认）。
        acc_obj.insert(key.clone(), value.clone());
    }
}

/// 键级合并（两侧皆为对象 → 逐键合并；否则整体替换）。
fn merge_map_value(
    acc: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: &serde_json::Value,
) {
    let Some(incoming) = value.as_object() else {
        acc.insert(key.to_owned(), value.clone());
        return;
    };
    let merged = match acc.get_mut(key).and_then(|v| v.as_object_mut()) {
        Some(existing) => {
            for (k, v) in incoming {
                existing.insert(k.clone(), v.clone());
            }
            serde_json::Value::Object(existing.clone())
        },
        None => serde_json::Value::Object(incoming.clone()),
    };
    acc.insert(key.to_owned(), merged);
}

/// tag 感知数组合并（对齐 Go `Config.Override` 的 inbound/outbound 半边）。
///
/// 语义（逐条对齐 Go xray.go:462-496）：
/// - tag 命中 → **原地替换**该条目；
/// - 未命中 → 按 [`UnmatchedPolicy`] 处置：`Append` 立即追加到尾部； `Prepend` /
///   `PrependUnlessSourceContains` 收集后**整体前插到头部** （Go 的 `prepends.append(&mut
///   self.outbound_configs)` 同款）； `PrependUnlessSourceContains` 在来源名含指定子串（如
///   `"tail"`）时改为 立即追加到尾部。
/// - 缺 tag 字段的条目视同 tag = `""`（Go 的零值语义）。
fn merge_tag_array(
    acc: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    incoming: &serde_json::Value,
    spec: &TagArraySpec,
    source: &str,
) {
    let Some(items) = incoming.as_array() else {
        acc.insert(key.to_owned(), incoming.clone());
        return;
    };
    let mut prepends: Vec<serde_json::Value> = Vec::new();
    {
        let Some(list) = acc.get_mut(key).and_then(|v| v.as_array_mut()) else {
            // 底层无此数组 → 视作空基线（全部条目按未命中处置）。
            let mut list: Vec<serde_json::Value> = Vec::new();
            for item in items {
                list.push(item.clone());
            }
            acc.insert(key.to_owned(), serde_json::Value::Array(list));
            return;
        };
        for item in items {
            let tag = tag_of(item, spec.tag_key);
            match list.iter().position(|c| tag_of(c, spec.tag_key) == tag) {
                Some(idx) => list[idx] = item.clone(),
                None => match spec.unmatched {
                    UnmatchedPolicy::Append => list.push(item.clone()),
                    UnmatchedPolicy::Prepend => prepends.push(item.clone()),
                    UnmatchedPolicy::PrependUnlessSourceContains(needle) => {
                        if source.to_ascii_lowercase().contains(needle) {
                            list.push(item.clone());
                        } else {
                            prepends.push(item.clone());
                        }
                    },
                },
            }
        }
    }
    if !prepends.is_empty() {
        let list = acc.get_mut(key).and_then(|v| v.as_array_mut()).expect("array inserted above");
        prepends.append(list);
        *list = prepends;
    }
}

/// 条目的 tag 值（缺字段 = 空串 = Go 零值语义）。
fn tag_of(item: &serde_json::Value, tag_key: &str) -> String {
    item.get(tag_key).and_then(|v| v.as_str()).unwrap_or_default().to_owned()
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

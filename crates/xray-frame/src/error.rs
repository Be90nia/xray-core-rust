//! 统一插件错误类型（模型 §2.2 L5 装配失败出口；坑约束 #1/#8 的错误分类载体）。
//!
//! 手写 `Display`/`Error`（udf 惯例：thiserror 不入 manifest——见
//! udf skeleton/src/config.rs「thiserror 不入 manifest，零依赖」注释）；
//! 文案纪律对齐 `ConfigError`：Display 含插件名/键名，`source()` 链保源头。

use std::fmt;

use skeleton::config::ConfigError;

/// 生命周期三相标注：`PluginError::Lifecycle` 记录炸点在哪一相。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecyclePhase {
    Init,
    Start,
    Stop,
}

impl fmt::Display for LifecyclePhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Init => "init",
            Self::Start => "start",
            Self::Stop => "stop",
        };
        f.write_str(name)
    }
}

/// 装配框架统一错误。任何插件/装配路径的失败最终收敛到此类型
/// （fail-visible：每变体携带定位信息，禁静默兜底）。
#[derive(Debug)]
pub enum PluginError {
    /// 配置装配失败（透传 udf `ConfigError`，source 链保键名）。
    Config(ConfigError),
    /// 依赖声明了但注册表无此插件。
    MissingDep {
        plugin: String,
        dep: String,
    },
    /// deps 成环（附环路径；P0-2 Kahn 排序残留集派生）。
    CyclicDep {
        cycle: Vec<String>,
    },
    /// 重名注册（对齐 udf shutdown `RegisterError::Duplicate` 语义）。
    Duplicate {
        name: String,
    },
    /// 注册表容量满（fail-closed，对齐 xray-features registry 容量门）。
    Full {
        cap: usize,
    },
    /// 生命周期失败（phase 标注炸点相）。
    Lifecycle {
        plugin: String,
        phase: LifecyclePhase,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// handler 登记冲突 / 未登记 / 类型不匹配。
    Handler(String),
    Io(std::io::Error),
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(source) => write!(f, "plugin config assembly: {source}"),
            Self::MissingDep { plugin, dep } => {
                write!(f, "plugin {plugin} missing dependency {dep}")
            },
            Self::CyclicDep { cycle } => {
                write!(f, "plugin dependency cycle: {}", cycle.join(" -> "))
            },
            Self::Duplicate { name } => write!(f, "duplicate plugin registration: {name}"),
            Self::Full { cap } => write!(f, "plugin registry full (cap {cap})"),
            Self::Lifecycle { plugin, phase, source } => {
                write!(f, "plugin {plugin} failed in {phase} phase: {source}")
            },
            Self::Handler(msg) => write!(f, "plugin handler registry: {msg}"),
            Self::Io(source) => write!(f, "plugin io: {source}"),
            Self::Other(source) => write!(f, "{source}"),
        }
    }
}

impl std::error::Error for PluginError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(source) => Some(source),
            Self::Lifecycle { source, .. } => Some(&**source),
            Self::Io(source) => Some(source),
            Self::Other(source) => Some(&**source),
            _ => None,
        }
    }
}

impl From<std::io::Error> for PluginError {
    fn from(source: std::io::Error) -> Self {
        Self::Io(source)
    }
}

impl From<ConfigError> for PluginError {
    fn from(source: ConfigError) -> Self {
        Self::Config(source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_missing_dep_contains_plugin_and_dep() {
        let e = PluginError::MissingDep { plugin: "vless".into(), dep: "dispatcher".into() };
        let s = e.to_string();
        assert!(s.contains("vless") && s.contains("dispatcher"), "{s}");
    }

    #[test]
    fn display_lifecycle_contains_plugin_and_phase() {
        for (phase, word) in [
            (LifecyclePhase::Init, "init"),
            (LifecyclePhase::Start, "start"),
            (LifecyclePhase::Stop, "stop"),
        ] {
            let e = PluginError::Lifecycle { plugin: "ss".into(), phase, source: "boom".into() };
            let s = e.to_string();
            assert!(s.contains("ss") && s.contains(word), "{s}");
        }
    }

    #[test]
    fn display_cyclic_dep_lists_cycle_path() {
        let e = PluginError::CyclicDep { cycle: vec!["a".into(), "b".into(), "a".into()] };
        let s = e.to_string();
        assert!(s.contains("a -> b -> a"), "{s}");
    }

    #[test]
    fn display_duplicate_and_full_carry_details() {
        let s = PluginError::Duplicate { name: "vmess".into() }.to_string();
        assert!(s.contains("vmess"), "{s}");
        let s = PluginError::Full { cap: 16 }.to_string();
        assert!(s.contains("16"), "{s}");
    }

    #[test]
    fn display_config_carries_key_name() {
        let e =
            PluginError::Config(ConfigError::Missing { key: "outbounds[].protocol=vless".into() });
        assert!(e.to_string().contains("outbounds[].protocol=vless"), "{}", e.to_string());
    }

    #[test]
    fn display_handler_and_other() {
        let s = PluginError::Handler("conn handler taken twice".into()).to_string();
        assert!(s.contains("conn handler taken twice"), "{s}");
        let s = PluginError::Other("misc failure".into()).to_string();
        assert!(s.contains("misc failure"), "{s}");
    }

    #[test]
    fn from_io_error_with_source_chain() {
        let e: PluginError = std::io::Error::other("disk gone").into();
        assert!(matches!(e, PluginError::Io(_)));
        let src = std::error::Error::source(&e).expect("io variant carries source");
        assert!(src.to_string().contains("disk gone"), "{src}");
    }

    #[test]
    fn from_config_error_with_source_chain() {
        let e: PluginError =
            ConfigError::Invalid { key: "port".into(), reason: "zero not bindable".into() }.into();
        assert!(matches!(e, PluginError::Config(_)));
        assert!(std::error::Error::source(&e).is_some());
    }

    #[test]
    fn question_mark_converts_io_error() {
        fn fallible() -> Result<(), PluginError> {
            Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
            Ok(())
        }
        assert!(matches!(fallible(), Err(PluginError::Io(_))));
    }
}

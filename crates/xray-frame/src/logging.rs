//! 装配层日志唯一入口（P0-7；坑约束 #10/#11）。
//!
//! 纪律（udf logx 模块注释同源）：**装配层一次 init，插件层禁调**；插件日志
//! 只经 [`LogFacade`]——target 构造期钉死为 `xray_frame::<域>`，emit 先过
//! `mask_secrets` 再发射，调用方无法绕过掩码或自选 target。
//!
//! # 运行期 target 的分发通路（实现注记）
//!
//! `tracing::event!` 的 callsite 是编译期 const（tracing-0.1.44 macros.rs:885
//! `static __CALLSITE`，target/level 必须常量——E0435 实证），运行期插件域
//! 进不了宏。故 emit 走手工 Metadata 分发：target 泄漏为 `&'static str`，
//! 按 level 泄漏一份 `Metadata<'static>`（每门面 ≤5 份，有界），经
//! `Dispatch::event` 发射——事件 target 真实为 `xray_frame::<域>`，
//! `RUST_LOG=xray_frame::<域>=level` 按域过滤可用。代价：无静态 interest
//! 快路径（每次过 `event_enabled`，由订阅者级别过滤兜底）。
//!
//! B6 取证（2026-10-23 `cargo tree -p xray-frame -i log`）：log v0.4.33 经
//! udf-skeleton-infra（log feature → tracing-log → tracing-subscriber）已在
//! 依赖树内，无新增第三方。init 单例冲突面按 PM 拍板：**装配点由 xray-frame
//! 统一收口**（xray-app-log 后续改为经 logx 初始化，P1-10 联动）。
//! 文件 sink 的路径 resolver 注入随 P3 配置链落地（v0.1 只走 env init，
//! 不触文件 sink，不落包目录）。

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
};

use skeleton_infra::logx::mask_secrets;

/// 手工 FieldSet 的引导 callsite：只贡献一个稳定地址当 Identifier 键
/// （等价 `identify_callsite!(&ANCHOR)`，tracing 未 re-export 该宏，直构
/// Identifier——其字段 pub 是宏静态构造的官方通道）。本 callsite 从不注册，
/// interest/metadata 不会被订阅者查询；真正分发的元数据是各门面按 level
/// 泄漏的运行期 Metadata。
static ANCHOR: AnchorCallsite = AnchorCallsite;
struct AnchorCallsite;

impl tracing::callsite::Callsite for AnchorCallsite {
    fn set_interest(&self, _: tracing::subscriber::Interest) {}

    fn metadata(&self) -> &tracing::Metadata<'static> {
        &ANCHOR_METADATA
    }
}

/// 引导 callsite 的常备元数据（自身字段面，永不分发；只被查询的话才初始化）。
static ANCHOR_METADATA: std::sync::LazyLock<tracing::Metadata<'static>> =
    std::sync::LazyLock::new(|| {
        let fields =
            tracing::field::FieldSet::new(&["message"], tracing::callsite::Identifier(&ANCHOR));
        tracing::Metadata::new(
            "xray_frame_anchor",
            "xray_frame_anchor",
            tracing::Level::TRACE,
            None,
            None,
            None,
            fields,
            tracing::metadata::Kind::EVENT,
        )
    });

/// 域规范日志门面：target = `xray_frame::<域>`（对齐 udf log-embed 纪律
/// `skeleton::<域>`）；域 = 插件名或 infra 域（assembly/registry/context）。
pub struct LogFacade {
    /// 构造期钉死并泄漏为 'static（`Metadata<'static>` 的 target 参数要求）；
    /// 每门面一次，量级 = 插件数。
    target: &'static str,
    /// 装配期注入的掩码表（进出站密钥等）；emit 面强制过滤。
    secrets: Vec<Arc<str>>,
    /// 按 level 缓存的运行期分发元数据（每门面 ≤5 份，有界）。
    metas: Mutex<HashMap<u8, &'static tracing::Metadata<'static>>>,
}

impl LogFacade {
    pub fn new(domain: &str, secrets: Vec<Arc<str>>) -> Self {
        Self {
            target: Box::leak(format!("xray_frame::{domain}").into_boxed_str()),
            secrets,
            metas: Mutex::new(HashMap::new()),
        }
    }

    fn metadata_for(&self, level: tracing::Level) -> &'static tracing::Metadata<'static> {
        let key = match level {
            tracing::Level::ERROR => 0,
            tracing::Level::WARN => 1,
            tracing::Level::INFO => 2,
            tracing::Level::DEBUG => 3,
            tracing::Level::TRACE => 4,
        };
        let mut metas = self.metas.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        metas.entry(key).or_insert_with(|| {
            let fields =
                tracing::field::FieldSet::new(&["message"], tracing::callsite::Identifier(&ANCHOR));
            Box::leak(Box::new(tracing::Metadata::new(
                "xray_frame_emit",
                self.target,
                level,
                None,
                None,
                None,
                fields,
                tracing::metadata::Kind::EVENT,
            )))
        })
    }

    /// 唯一输出面：message 先过 `mask_secrets` 再发射，target 强制覆写。
    pub fn emit(&self, level: tracing::Level, message: impl fmt::Display) {
        let secret_refs: Vec<&str> = self.secrets.iter().map(|s| s.as_ref()).collect();
        let masked = mask_secrets(&message.to_string(), &secret_refs);
        let metadata = self.metadata_for(level);
        let message_field =
            metadata.fields().field("message").expect("message field declared in emit metadata");
        let values = [(&message_field, Some(&masked as &dyn tracing::field::Value))];
        let valueset = metadata.fields().value_set(&values);
        tracing::dispatcher::get_default(|dispatch| {
            dispatch.event(&tracing::Event::new(metadata, &valueset));
        });
    }

    pub fn error(&self, message: impl fmt::Display) {
        self.emit(tracing::Level::ERROR, message);
    }

    pub fn warn(&self, message: impl fmt::Display) {
        self.emit(tracing::Level::WARN, message);
    }

    pub fn info(&self, message: impl fmt::Display) {
        self.emit(tracing::Level::INFO, message);
    }

    pub fn debug(&self, message: impl fmt::Display) {
        self.emit(tracing::Level::DEBUG, message);
    }
}

/// 装配层 init（插件层禁调——udf 纪律「装配层一次 init，插件层禁」）。
/// 兜底恒含 `skeleton=off` 预设；重复调用 `Err(AlreadyInit)`（禁静默覆盖）。
pub fn init_from_env(
    default_level: log::LevelFilter,
) -> Result<(), skeleton_infra::logx::AlreadyInit> {
    skeleton_infra::logx::init_tracing_from_env(default_level)
}

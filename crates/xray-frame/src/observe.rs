//! P1-5 观测字段模板（坑约束 3/10/11 的字段面）。
//!
//! [`ObserveFields`] 是观测事件的**固定四元组**（`conn_id`/`stage`/`peer`/`dest`，
//! 缺一即违约）；构造唯一入口 [`ObserveFields::new`]——conn_id 内部取自
//! [`PluginContext::next_conn_id`]（P0-3 接线的 udf `IdGen`，不另造生成器）。
//! 落点 [`emit`] 统一走 [`PluginContext::log`]（P0-7 `LogFacade`：target 构造期
//! 钉死 `xray_frame::<域>`、发射先过 `mask_secrets`），调用方无法绕过掩码或
//! 自选 target，禁裸 tracing 宏/println。

use std::{fmt, sync::Arc};

use skeleton::clock::SystemClock;
use std_ext::{hash::stable64, id::IdGen};

use crate::{context::PluginContext, logging::LogFacade};

// udf-promotion-candidate: ObserveFields 零 xray 类型可上浮；emit 依赖 PluginContext 留仓

/// 生命周期阶段（机器可读枚举，禁自由文本）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Accept,
    Handshake,
    Authenticate,
    Forward,
    Close,
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Stage::Accept => "Accept",
            Stage::Handshake => "Handshake",
            Stage::Authenticate => "Authenticate",
            Stage::Forward => "Forward",
            Stage::Close => "Close",
        };
        f.write_str(name)
    }
}

/// 观测字段模板（固定四元组，缺一即违约）。
///
/// `peer`/`dest` 字符串化持有（PM 拍板 2026-10-23）：不持连接对象——持有会
/// prolong 生命周期，构成泄漏面。
#[derive(Debug, Clone)]
pub struct ObserveFields {
    /// 连接标识（必填）——唯一来源 `ctx.next_conn_id()`（坑约束 3）。
    pub conn_id: u128,
    /// 生命周期阶段。
    pub stage: Stage,
    /// 对端（IP:port）。
    pub peer: String,
    /// 目标（域名或 IP:port）。
    pub dest: String,
}

impl ObserveFields {
    /// 唯一构造入口：conn_id 从 ctx 取（禁自造 conn_id）。
    pub fn new(ctx: &PluginContext, stage: Stage, peer: String, dest: String) -> Self {
        Self { conn_id: ctx.next_conn_id(), stage, peer, dest }
    }
}

/// 事件单行格式（四元组 + 消息；`conn=` 为短展示 id——u128 短 hex 前 16 位，
/// PM 拍板 2026-10-23；完整 id 留结构化字段 `conn_id`）。
fn format_event(fields: &ObserveFields, msg: &str) -> String {
    format!(
        "conn={:016x} stage={} peer={} dest={} {}",
        (fields.conn_id >> 64) as u64,
        fields.stage,
        fields.peer,
        fields.dest,
        msg
    )
}

/// 观测落点：四元组单行挂 P0-7 门面（info 级）。
pub fn emit(ctx: &PluginContext, fields: &ObserveFields, msg: &str) {
    ctx.log().info(format_event(fields, msg));
}

/// app 面观测事件出口（P3-3 示范）：非 16 族插件的 app 面（observatory /
/// stats / metrics）没有 [`PluginContext`]，经本件复用统一四元组与
/// [`LogFacade`] 落点，禁另起第二套字段模板或裸 tracing。
///
/// conn_id 权威 = udf `IdGen` 进程级注册表：指纹按 `stable64(domain)` 派生，
/// 同 domain 跨句柄共享单一权威（`IdGen::new` 注册表语义，跨句柄严格递增、
/// 零撞 id），与装配根监听地址派生的指纹空间天然分离；生成机制仍是 udf
/// `IdGen` 本体，非第二套生成器（坑约束 3）。
pub struct ObserveSink {
    log: LogFacade,
    ids: IdGen,
}

impl ObserveSink {
    /// `domain` 即 [`LogFacade`] 域（target = `xray_frame::<domain>`）兼
    /// conn_id 指纹命名空间；`secrets` 交给门面掩码表。
    #[must_use]
    pub fn new(domain: &str, secrets: Vec<Arc<str>>) -> Self {
        Self {
            log: LogFacade::new(domain, secrets),
            ids: IdGen::new(stable64(domain.as_bytes()), Arc::new(SystemClock)),
        }
    }

    /// 本出口的 conn_id 权威面（同 domain 跨句柄严格递增）。
    #[must_use]
    pub fn next_conn_id(&self) -> u128 {
        self.ids.r#gen().as_u128()
    }

    /// 发射一条观测事件：conn_id 现取现发（一条事件一个连接身份）。
    pub fn emit(&self, stage: Stage, peer: String, dest: String, msg: &str) {
        let fields = ObserveFields { conn_id: self.ids.r#gen().as_u128(), stage, peer, dest };
        self.log.info(format_event(&fields, msg));
    }
}

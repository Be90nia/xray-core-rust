//! P1-5 观测字段模板（坑约束 3/10/11 的字段面）。
//!
//! [`ObserveFields`] 是观测事件的**固定四元组**（`conn_id`/`stage`/`peer`/`dest`，
//! 缺一即违约）；构造唯一入口 [`ObserveFields::new`]——conn_id 内部取自
//! [`PluginContext::next_conn_id`]（P0-3 接线的 udf `IdGen`，不另造生成器）。
//! 落点 [`emit`] 统一走 [`PluginContext::log`]（P0-7 `LogFacade`：target 构造期
//! 钉死 `xray_frame::<域>`、发射先过 `mask_secrets`），调用方无法绕过掩码或
//! 自选 target，禁裸 tracing 宏/println。

use std::fmt;

use crate::context::PluginContext;

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

/// 观测落点：四元组单行挂 P0-7 门面（info 级）。`conn=` 为短展示 id——u128
/// 短 hex 前 16 位（PM 拍板 2026-10-23；完整 id 留结构化字段 `conn_id`）。
pub fn emit(ctx: &PluginContext, fields: &ObserveFields, msg: &str) {
    ctx.log().info(format!(
        "conn={:016x} stage={} peer={} dest={} {}",
        (fields.conn_id >> 64) as u64,
        fields.stage,
        fields.peer,
        fields.dest,
        msg
    ));
}

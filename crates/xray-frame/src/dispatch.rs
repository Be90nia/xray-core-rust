//! 查表分发面（P3-1 S1 旁路表骨架）。
//!
//! 契约源：`docs/architecture/xray-frame-契约级任务书-P1P4.md` §P3-1
//! 「dispatcher 中央 match 臂 → Registry 查表」。dispatcher 中央 match 臂
//! （`xray-app-dispatcher/src/default.rs` `dispatch_link`）的退役路径按四阶段
//! 迁移：S0 旧臂基线（dispatcher 侧 feature flag `dispatcher-dual-write`）→
//! **S1 本查表面旁路并存** → S2 双写对照差异率必须为 0 → S3 切查表 →
//! S4 删旧臂。本件只落 S1 骨架，不接管任何生产分发路径。
//!
//! **fail-visible 铁律**（L5 / Go `default.go:469-470` DO NOT CHANGE）：查表
//! 未命中 = 配置错配 → [`Lookup::Missing`] 上抛由调用方停机，**禁**回落
//! default——路由指定的 outboundTag 找不到 handler 时静默落默认出站会掩盖
//! 配置错误。
//!
//! 类型边界：契约草案 `Found(Arc<dyn DispatchHandler>)` 中的 `DispatchHandler`
//! 留在 dispatcher crate（xray-frame 零 xray 类型红线，任务书 P3-1 注记），
//! 本面以泛型 [`Lookup<T>`] 承接——消费方 `lookup::<T>` 取回具体型后自行上转型
//! trait 对象；裸 `Lookup`（默认类型参数）即擦除形态。
//!
//! 登记面：P0-3 `register_handler` / `take_handler` 语义零改动，本件只经
//! `context.rs` 的非消费只读半边 `peek_handler_erased` 取数，登记表写权仍归
//! 装配链（P0-8 registry）。

use std::{any::TypeId, sync::Arc};

use crate::context::PluginContext;

/// 查表能力键：型（`TypeId`，对位 P0-3 登记面键）+ 请求 tag（Missing 诊断
/// 回填，对位 Go `default.go:469-470` 报错主体的 outboundTag）。
#[derive(Debug, Clone)]
pub struct HandlerCapability {
    pub(crate) type_id: TypeId,
    /// 请求的出站 tag（forced tag / 路由 outboundTag）；未命中时随
    /// [`Lookup::Missing`] 原样上抛。
    pub tag: String,
}

impl HandlerCapability {
    /// 以登记型 + 请求 tag 构造能力键。
    pub fn of<T: 'static + Send + Sync>(tag: impl Into<String>) -> Self {
        Self { type_id: std::any::TypeId::of::<T>(), tag: tag.into() }
    }
}

/// 分发查表结果（P3-1 契约 `Lookup`）。默认类型参数 = 擦除形态（契约草案
/// `Found(Arc<dyn DispatchHandler>)` 的框架侧等价物——`DispatchHandler` 留
/// dispatcher crate，此处以 `dyn Any + Send + Sync` 承接擦除值）。擦除形态
/// 由消费方从具体型上转型构造（`Lookup::Found(arc_concrete)`）；Any 擦除
/// 无法反向 downcast 成 trait 对象，S3 消费面走「`lookup::<具体型>` →
/// `Arc<具体型>` → 上转型 `Arc<dyn DispatchHandler>`」。
pub enum Lookup<T: ?Sized = dyn std::any::Any + Send + Sync> {
    /// 命中。
    Found(Arc<T>),
    /// 未命中（配置错配 → fail-visible；调用方必须停机，禁回落 default）。
    Missing {
        /// 请求的出站 tag（诊断面）。
        tag: String,
    },
}

/// 查表分发（P3-1 契约签名：替代中央 match 臂的查表骨架）。
///
/// 未命中 → [`Lookup::Missing`]，**禁**静默回落 default。与契约草案的唯一
/// 偏差：`ctx` 取 `&` 而非 `&mut`——查表是**非消费读**，消费半边仍归 P0-3
/// `take_handler`（本项不改 P0-3 登记面语义的边界）；`cap` 的型与消费方视型
/// `T` 不一致按配置错配归类为 `Missing`（fail-visible，与未命中同出口）。
pub fn lookup<T: 'static + Send + Sync>(ctx: &PluginContext, cap: HandlerCapability) -> Lookup<T> {
    let Some(erased) = ctx.peek_handler_erased(&cap.type_id) else {
        return Lookup::Missing { tag: cap.tag };
    };
    // downcast 失败 = 登记型与消费视型错配（配置错配，非内部错误）。
    match erased.downcast::<T>() {
        Ok(typed) => Lookup::Found(typed),
        Err(_) => Lookup::Missing { tag: cap.tag },
    }
}

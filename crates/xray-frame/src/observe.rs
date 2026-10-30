//! P1-5 观测字段模板（坑约束 3/10/11 的字段面）。
//!
//! [`ObserveFields`] 是观测事件的**固定四元组**（`conn_id`/`stage`/`peer`/`dest`，
//! 缺一即违约）；构造唯一入口 [`ObserveFields::new`]——conn_id 内部取自
//! [`PluginContext::next_conn_id`]（P0-3 接线的 udf `IdGen`，不另造生成器）。
//! 落点 [`emit`] 统一走 [`PluginContext::log`]（P0-7 `LogFacade`：target 构造期
//! 钉死 `xray_frame::<域>`、发射先过 `mask_secrets`），调用方无法绕过掩码或
//! 自选 target，禁裸 tracing 宏/println。
//!
//! 存储派生（bd pzuqo，CLAUDE.md §3.5.5「派生 ≠ 复制」）：唯一存储是 udf
//! [`skeleton::fields::FieldBag`]（[`ObserveFields`] 只包一个袋，不另造并行
//! 容器）；Xray 语义（四元组必填、conn_id 全 128 位、[`Stage`] 枚举）留在本层，
//! 由 typed 访问器收敛。udf 只以 `Int(i64)`/`Count(u64)` 承载数值 → `conn_id`
//! 无损拆成高/低两个 `Count`（禁截断）。

use std::{fmt, sync::Arc};

use skeleton::{
    clock::SystemClock,
    fields::{FieldBag, FieldValue},
};
use std_ext::{hash::stable64, id::IdGen};

use crate::{context::PluginContext, logging::LogFacade};

// udf-promotion-candidate: 存储已派生自 udf FieldBag（bd pzuqo）；残余不可上浮
// 面 = Stage 枚举（Xray 生命周期语义）+ emit 的 PluginContext 依赖，留仓。

/// 生命周期阶段（机器可读枚举，禁自由文本）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Accept,
    Handshake,
    Authenticate,
    Forward,
    Close,
}

impl Stage {
    /// 袋内文本形态（也是 [`fmt::Display`] 的字节面）。
    fn as_str(self) -> &'static str {
        match self {
            Stage::Accept => "Accept",
            Stage::Handshake => "Handshake",
            Stage::Authenticate => "Authenticate",
            Stage::Forward => "Forward",
            Stage::Close => "Close",
        }
    }

    /// [`Stage::as_str`] 的逆（袋内只有本枚举写过的名，未命中即内部违约）。
    fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "Accept" => Stage::Accept,
            "Handshake" => Stage::Handshake,
            "Authenticate" => Stage::Authenticate,
            "Forward" => Stage::Forward,
            "Close" => Stage::Close,
            _ => return None,
        })
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 袋内字段名（`&'static str`：udf 名字零分配面）。
const F_CONN_ID_HI: &str = "conn_id_hi";
const F_CONN_ID_LO: &str = "conn_id_lo";
const F_STAGE: &str = "stage";
const F_PEER: &str = "peer";
const F_DEST: &str = "dest";

/// 观测字段模板（固定四元组，缺一即违约）。
///
/// `peer`/`dest` 字符串化持有（PM 拍板 2026-10-23）：不持连接对象——持有会
/// prolong 生命周期，构成泄漏面。
///
/// 存储 = udf [`FieldBag`]（唯一，本层不另存副本）；四元组由构造期一次写满，
/// 之后只读——访问器的不变式由私有构造入口保证。
#[derive(Debug, Clone, PartialEq)]
pub struct ObserveFields {
    bag: FieldBag,
}

impl ObserveFields {
    /// 唯一构造入口：conn_id 从 ctx 取（禁自造 conn_id）。
    pub fn new(ctx: &PluginContext, stage: Stage, peer: String, dest: String) -> Self {
        Self::from_parts(ctx.next_conn_id(), stage, peer, dest)
    }

    /// conn_id 权威已在手时的构造路径（[`ObserveSink`] 自持 `IdGen`）。
    fn from_parts(conn_id: u128, stage: Stage, peer: String, dest: String) -> Self {
        let mut bag = FieldBag::new();
        // 无损：u128 拆高/低两半（udf 数值变体无 u128，截断即丢连接身份）。
        bag.insert(F_CONN_ID_HI, FieldValue::Count((conn_id >> 64) as u64));
        bag.insert(F_CONN_ID_LO, FieldValue::Count(conn_id as u64));
        bag.insert(F_STAGE, FieldValue::Str(stage.to_string()));
        bag.insert(F_PEER, FieldValue::Str(peer));
        bag.insert(F_DEST, FieldValue::Str(dest));
        Self { bag }
    }

    /// 完整 conn_id（两个 `Count` 拼回 u128，无损往返）。
    #[must_use]
    pub fn conn_id(&self) -> u128 {
        (u128::from(self.count(F_CONN_ID_HI)) << 64) | u128::from(self.count(F_CONN_ID_LO))
    }

    /// 生命周期阶段。
    #[must_use]
    pub fn stage(&self) -> Stage {
        let name = self.text(F_STAGE);
        Stage::from_name(name)
            .unwrap_or_else(|| unreachable!("{F_STAGE} 只由 Stage::as_str 写入，实际 {name:?}"))
    }

    /// 对端（IP:port）。
    #[must_use]
    pub fn peer(&self) -> &str {
        self.text(F_PEER)
    }

    /// 目标（域名或 IP:port）。
    #[must_use]
    pub fn dest(&self) -> &str {
        self.text(F_DEST)
    }

    /// 袋面只读视图（结构化消费/并入外部 `FieldBag` 时用；本层不存第二份）。
    #[must_use]
    pub fn as_bag(&self) -> &FieldBag {
        &self.bag
    }

    fn count(&self, name: &'static str) -> u64 {
        match self.bag.get(name) {
            Some(FieldValue::Count(v)) => *v,
            other => unreachable!("{name} 只由构造期写入 Count，实际 {other:?}"),
        }
    }

    fn text(&self, name: &'static str) -> &str {
        match self.bag.get(name) {
            Some(FieldValue::Str(v)) => v,
            other => unreachable!("{name} 只由构造期写入 Str，实际 {other:?}"),
        }
    }
}

/// 事件单行格式（四元组 + 消息；`conn=` 为短展示 id——u128 短 hex 前 16 位，
/// PM 拍板 2026-10-23；完整 id 留结构化字段 `conn_id`）。
fn format_event(fields: &ObserveFields, msg: &str) -> String {
    format!(
        "conn={:016x} stage={} peer={} dest={} {}",
        (fields.conn_id() >> 64) as u64,
        fields.stage(),
        fields.peer(),
        fields.dest(),
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
        let fields = ObserveFields::from_parts(self.ids.r#gen().as_u128(), stage, peer, dest);
        self.log.info(format_event(&fields, msg));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_ID: u128 = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210;

    fn sample() -> ObserveFields {
        ObserveFields::from_parts(
            SAMPLE_ID,
            Stage::Forward,
            "10.0.0.1:443".to_string(),
            "example.com:80".to_string(),
        )
    }

    #[test]
    fn bag_is_single_store_with_pinned_insert_order() {
        let fields = sample();
        let bag = fields.as_bag();
        let names: Vec<&str> = bag.iter().map(|(name, _)| name).collect();
        assert_eq!(names, ["conn_id_hi", "conn_id_lo", "stage", "peer", "dest"]);
        assert_eq!(bag.len(), 5);
        assert_eq!(bag.get("conn_id_hi"), Some(&FieldValue::Count(0x0123_4567_89ab_cdef)));
        assert_eq!(bag.get("conn_id_lo"), Some(&FieldValue::Count(0xfedc_ba98_7654_3210)));
        assert_eq!(bag.get("stage"), Some(&FieldValue::Str("Forward".to_string())));
        assert_eq!(bag.get("peer"), Some(&FieldValue::Str("10.0.0.1:443".to_string())));
        assert_eq!(bag.get("dest"), Some(&FieldValue::Str("example.com:80".to_string())));
    }

    #[test]
    fn conn_id_round_trips_full_u128_without_truncation() {
        for id in [0, 1, u128::from(u64::MAX), SAMPLE_ID, u128::MAX] {
            let fields = ObserveFields::from_parts(id, Stage::Close, String::new(), String::new());
            assert_eq!(fields.conn_id(), id, "u128 无损（禁截断）：{id:#034x}");
        }
    }

    #[test]
    fn clone_is_value_equal() {
        let fields = sample();
        let copy = fields.clone();
        assert_eq!(copy, fields);
        assert_eq!(copy.conn_id(), fields.conn_id());
        assert_eq!(copy.as_bag().len(), fields.as_bag().len());
    }

    #[test]
    fn empty_bag_is_the_derivation_start() {
        assert!(FieldBag::new().is_empty(), "空袋基线：零字段");
        let fields = sample();
        assert!(!fields.as_bag().is_empty(), "构造即写满四元组");
        assert_eq!(fields.as_bag().len(), 5);
    }

    #[test]
    fn every_stage_round_trips_through_the_bag() {
        let all =
            [Stage::Accept, Stage::Handshake, Stage::Authenticate, Stage::Forward, Stage::Close];
        for stage in all {
            let fields = ObserveFields::from_parts(7, stage, String::new(), String::new());
            assert_eq!(fields.stage(), stage);
            assert_eq!(fields.as_bag().get(F_STAGE), Some(&FieldValue::Str(stage.to_string())));
        }
    }

    /// 行为红线：单行输出逐字节钉死（改前 = 改后，位宽/Display/顺序都不动）。
    #[test]
    fn event_line_is_byte_pinned() {
        let cases = [
            (0, "conn=0000000000000000 stage=Forward peer=10.0.0.1:443 dest=example.com:80 hello"),
            (
                SAMPLE_ID,
                "conn=0123456789abcdef stage=Forward peer=10.0.0.1:443 dest=example.com:80 hello",
            ),
            (
                u128::MAX,
                "conn=ffffffffffffffff stage=Forward peer=10.0.0.1:443 dest=example.com:80 hello",
            ),
        ];
        for (id, expect) in cases {
            let fields = ObserveFields::from_parts(
                id,
                Stage::Forward,
                "10.0.0.1:443".to_string(),
                "example.com:80".to_string(),
            );
            assert_eq!(format_event(&fields, "hello"), expect);
        }
    }
}

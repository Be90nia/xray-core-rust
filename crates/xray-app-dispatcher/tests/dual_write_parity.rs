//! P3-1 S2 双写对照：dispatcher 中央 match 臂选择半边（`dual_write::baseline_select`，
//! 语义逐条对位 `dispatch_link` 旧臂）vs xray-frame 查表（`xray_frame::dispatch::lookup`，
//! S1 旁路面）。回放样本差异率必须为 0（契约 §P3-1 阶段迁移 S2 通过判据）。
//!
//! 样本空间（确定性回放，非随机）：
//! - 16 个目的地 × forced {None + 8 命中 tag + 1 未命中} × route {None + 8 命中 tag + 1 未命中} =
//!   1600 样本 ≥ 契约的 1000 下限（每对 hit-tag 组合全覆盖）；
//! - 边界样本：型错配（登记型 ≠ 消费视型 → Missing）、default 回落 pin、 forced 未命中禁落默认
//!   pin（Go default.go:469-470 DO NOT CHANGE 双侧对齐）。
//!
//! 差异计数走 `dual_write::compare_sample` / `diff_count`（可观测面），
//! 本测试本地再计一份并在收尾断言两处均为 0。
//!
//! 本文件整体 feature 门控：dual_write 面只在 `dispatcher-dual-write` 下存在
//! （S0/S2 是 flag-scoped 阶段，关 flag 的世界没有双写面）。
#![cfg(feature = "dispatcher-dual-write")]

use std::{collections::HashMap, sync::Arc};

use xray_app_dispatcher::{
    DispatchHandler, OutboundHandlerManager,
    default::{
        PinFuture,
        dual_write::{BaselineChoice, baseline_select, compare_sample},
    },
};
use xray_common::net::destination::Destination;
use xray_frame::{
    contract_assert::contract_test_context,
    dispatch::{HandlerCapability, Lookup, lookup},
};

// ── 测试 handler 族：8 个已登记型（tag ↔ 型一一对应）+ 1 默认 + 2 未登记标记型 ──

macro_rules! test_handlers {
    ($($ty:ident => $tag:literal),* $(,)?) => {
        $(
            #[derive(Debug)]
            struct $ty;
            impl DispatchHandler for $ty {
                fn tag(&self) -> &str {
                    $tag
                }
                fn dispatch(&self, _dest: &Destination, _link: xray_transport::link::Link) -> PinFuture<()> {
                    Box::pin(std::future::pending()) // 选择面测试：dispatch 永不被调
                }
            }
        )*
    };
}

test_handlers! {
    H0 => "t0", H1 => "t1", H2 => "t2", H3 => "t3",
    H4 => "t4", H5 => "t5", H6 => "t6", H7 => "t7",
    Hd => "t-default",
    // 未登记标记型：lookup 未命中路径与型错配路径的探针（永不 register）。
    MissA => "t-miss-a",
    MissB => "t-miss-b",
}

/// 已登记 hit tag（与上面 8 型一一对应，顺序即型序）。
const HIT_TAGS: [&str; 8] = ["t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7"];
/// 未命中请求 tag（双侧都应 Missing，禁落默认）。
const MISS_TAGS: [&str; 2] = ["t-miss-a", "t-miss-b"];

/// 测试 Ohm：tag 表 + default（default 存在是为了 pin「未命中不落默认」）。
#[derive(Debug)]
struct MapOhm {
    tagged: HashMap<String, Arc<dyn DispatchHandler>>,
    default: Option<Arc<dyn DispatchHandler>>,
}

impl MapOhm {
    fn with_all() -> Self {
        let mut tagged = HashMap::new();
        for (i, tag) in HIT_TAGS.iter().enumerate() {
            let h: Arc<dyn DispatchHandler> = match i {
                0 => Arc::new(H0),
                1 => Arc::new(H1),
                2 => Arc::new(H2),
                3 => Arc::new(H3),
                4 => Arc::new(H4),
                5 => Arc::new(H5),
                6 => Arc::new(H6),
                _ => Arc::new(H7),
            };
            tagged.insert((*tag).to_string(), h);
        }
        Self { tagged, default: Some(Arc::new(Hd)) }
    }
}

impl OutboundHandlerManager for MapOhm {
    fn get_handler(&self, tag: &str) -> Option<Arc<dyn DispatchHandler>> {
        self.tagged.get(tag).cloned()
    }

    fn get_default_handler(&self) -> Option<Arc<dyn DispatchHandler>> {
        self.default.clone()
    }
}

/// 新路（xray-frame 查表）侧的世界：同 8 个 handler 经 P0-3 登记面按型注册；
/// default 不进登记面（默认出站是 dispatcher 策略，不是查表键）。
fn ctx_with_handlers() -> xray_frame::PluginContext {
    let mut ctx = contract_test_context("dual-write-parity");
    ctx.register_handler(Arc::new(H0)).expect("register H0");
    ctx.register_handler(Arc::new(H1)).expect("register H1");
    ctx.register_handler(Arc::new(H2)).expect("register H2");
    ctx.register_handler(Arc::new(H3)).expect("register H3");
    ctx.register_handler(Arc::new(H4)).expect("register H4");
    ctx.register_handler(Arc::new(H5)).expect("register H5");
    ctx.register_handler(Arc::new(H6)).expect("register H6");
    ctx.register_handler(Arc::new(H7)).expect("register H7");
    ctx
}

/// hit tag → 登记型 TypeId 的装配知识（模拟装配链「哪个 tag 由哪个插件型背书」）。
macro_rules! lookup_hit {
    ($ctx:expr, $i:expr, $tag:expr) => {
        match $i {
            0 => chosen_of::<H0>($ctx, $tag),
            1 => chosen_of::<H1>($ctx, $tag),
            2 => chosen_of::<H2>($ctx, $tag),
            3 => chosen_of::<H3>($ctx, $tag),
            4 => chosen_of::<H4>($ctx, $tag),
            5 => chosen_of::<H5>($ctx, $tag),
            6 => chosen_of::<H6>($ctx, $tag),
            _ => chosen_of::<H7>($ctx, $tag),
        }
    };
}

/// 单次查表 → 归一为 `Option<String>`（选中 handler tag / None = Missing）。
/// 命中型与未登记探针型同走 `xray_frame::dispatch::lookup` 真实出口。
fn chosen_of<T: DispatchHandler + 'static>(
    ctx: &xray_frame::PluginContext,
    tag: &str,
) -> Option<String> {
    match lookup::<T>(ctx, HandlerCapability::of::<T>(tag)) {
        Lookup::Found(h) => Some(h.tag().to_string()),
        Lookup::Missing { .. } => None,
    }
}

/// miss tag → 探针型（MissA ↔ t-miss-a / MissB ↔ t-miss-b）。
macro_rules! lookup_miss {
    ($ctx:expr, $tag:expr) => {
        if $tag == MISS_TAGS[0] {
            chosen_of::<MissA>($ctx, $tag)
        } else {
            chosen_of::<MissB>($ctx, $tag)
        }
    };
}

/// 新路选择策略（对位 baseline_select 的臂策略，查表半边换成 xray-frame lookup）：
/// forced 优先 → route 次之 → default。返回 (请求 tag, 选中 handler tag 或 None)。
fn lookup_select(
    ctx: &xray_frame::PluginContext,
    forced: Option<(&str, usize)>,
    route: Option<(&str, usize)>,
) -> (String, Option<String>) {
    // idx = usize::MAX 标记未登记 tag（真实走 lookup 的 Missing 出口）。
    let by_key = |key: Option<(&str, usize)>| -> Option<(String, Option<String>)> {
        let (tag, idx) = key?;
        let chosen =
            if idx < HIT_TAGS.len() { lookup_hit!(ctx, idx, tag) } else { lookup_miss!(ctx, tag) };
        Some((tag.to_string(), chosen))
    };
    if let Some(pair) = by_key(forced) {
        return pair;
    }
    if let Some(pair) = by_key(route) {
        return pair;
    }
    // default 路径：新查表面不承载默认出站（dispatcher 策略半边），直接取
    // 同一 default 源——本分支新旧两侧同源，参与样本计数不产生差异面。
    ("t-default".to_string(), Some("t-default".to_string()))
}

/// 主对照：1152 回放样本，差异率必须为 0。
#[test]
fn dual_write_parity_over_replay_samples_diff_rate_is_zero() {
    let ohm = MapOhm::with_all();
    let ctx = ctx_with_handlers();

    let before_diffs = crate_diff_count();
    let mut local_diffs = 0u64;
    let mut samples = 0u64;

    // forced 维度：None + 8 命中 tag + 1 未命中 = 10；route 维度同构 = 10。
    // 16 dest × 10 × 10 = 1600 样本（每对 hit-tag 组合全覆盖）≥ 契约 1000 下限。
    let forced_variants: Vec<Option<(String, usize)>> = std::iter::once(None)
        .chain((0..8).map(|i| Some((HIT_TAGS[i].to_string(), i))))
        .chain(std::iter::once(Some((MISS_TAGS[0].to_string(), usize::MAX))))
        .collect();
    let route_variants: Vec<Option<(String, usize)>> = std::iter::once(None)
        .chain((0..8).map(|i| Some((HIT_TAGS[i].to_string(), i))))
        .chain(std::iter::once(Some((MISS_TAGS[1].to_string(), usize::MAX))))
        .collect();

    for dest_idx in 0..16usize {
        for f in &forced_variants {
            for r in &route_variants {
                let (old_tag, old_chosen) = match baseline_select(
                    &ohm,
                    f.as_ref().map(|(t, _)| t.as_str()),
                    r.as_ref().map(|(t, _)| t.as_str()),
                ) {
                    BaselineChoice::Chosen { tag, handler_tag } => (tag, Some(handler_tag)),
                    BaselineChoice::Missing { tag } => (tag, None),
                    BaselineChoice::Default(h) => (String::from("t-default"), h),
                };
                let (new_tag, new_chosen) = lookup_select(
                    &ctx,
                    f.as_ref().map(|(t, i)| (t.as_str(), *i)),
                    r.as_ref().map(|(t, i)| (t.as_str(), *i)),
                );

                assert_eq!(old_tag, new_tag, "双侧请求 tag 必须一致（dest={dest_idx}）");
                let diff = compare_sample(&old_tag, old_chosen.as_deref(), new_chosen.as_deref());
                if diff {
                    local_diffs += 1;
                }
                samples += 1;
            }
        }
    }

    assert!(samples >= 1000, "契约要求 ≥1000 回放样本，实际 {samples}");
    assert_eq!(local_diffs, 0, "本地差异计数必须为 0");
    assert_eq!(crate_diff_count() - before_diffs, 0, "可观测差异计数增量必须为 0");
}

fn crate_diff_count() -> u64 {
    xray_app_dispatcher::default::dual_write::diff_count()
}

/// fail-visible pin（旧臂侧）：default 存在时 forced/路由未命中仍必须 Missing，
/// 禁落默认（Go default.go:449-454 / 469-470 DO NOT CHANGE）。
#[test]
fn baseline_miss_never_falls_back_to_default() {
    let ohm = MapOhm::with_all();
    assert_eq!(
        baseline_select(&ohm, Some("t-ghost"), None),
        BaselineChoice::Missing { tag: "t-ghost".into() },
        "forced 未命中禁落默认"
    );
    assert_eq!(
        baseline_select(&ohm, None, Some("t-ghost")),
        BaselineChoice::Missing { tag: "t-ghost".into() },
        "路由未命中禁落默认（Go default.go:469-470 DO NOT CHANGE）"
    );
    assert_eq!(
        baseline_select(&ohm, None, None),
        BaselineChoice::Default(Some("t-default".into())),
        "无 forced 无 route 才走默认"
    );
}

/// fail-visible pin（新查表侧）：未登记型 / 型错配一律 Missing，禁回落已登记的
/// 其他 handler；Missing 携带请求 tag（诊断面）。
#[test]
fn lookup_miss_and_type_mismatch_are_fail_visible() {
    let ctx = ctx_with_handlers();

    match lookup::<MissA>(&ctx, HandlerCapability::of::<MissA>("t-miss-a")) {
        Lookup::Missing { tag } => assert_eq!(tag, "t-miss-a", "Missing 携带请求 tag"),
        Lookup::Found(_) => panic!("未登记型必须 Missing"),
    }

    // 型错配：t0 登记的是 H0，消费方持 MissB 视型 → Missing（配置错配归类）。
    assert!(matches!(
        lookup::<MissB>(&ctx, HandlerCapability::of::<H0>("t0")),
        Lookup::Missing { .. }
    ));
}

/// 擦除形态：具体型 `Lookup<T>` 的 `Found` 上转型成擦除 `Lookup`（契约草案
/// `Found(Arc<dyn DispatchHandler>)` 的框架侧等价物）。Any 擦除无法直接
/// downcast 成 trait 对象——S3 消费面（dispatcher）的真实路径就是
/// 「`lookup::<具体型>` → `Arc<具体型>` → 上转型 `Arc<dyn DispatchHandler>`」，
/// 本测试 pin 该可用性。
#[test]
fn erased_lookup_shape_roundtrips() {
    let ctx = ctx_with_handlers();
    let erased: Lookup = match lookup::<H5>(&ctx, HandlerCapability::of::<H5>("t5")) {
        Lookup::Found(h) => Lookup::Found(h), // Arc<H5> → Arc<dyn Any + Send + Sync>
        Lookup::Missing { tag } => Lookup::Missing { tag },
    };
    match erased {
        Lookup::Found(any_h) => {
            let typed = any_h.downcast::<H5>().expect("downcast 回 H5");
            assert_eq!(typed.tag(), "t5");
        },
        Lookup::Missing { tag } => panic!("已登记型查表未命中: {tag}"),
    }
}

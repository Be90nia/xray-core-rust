//! 双主路装配**差异台账契约测试**（bd zhvi3）。
//!
//! 两条装配路的当前定位（CLAUDE.md §3.5.4）：
//!
//! - **生产主路** = `Config::build()` → `start_full`：出站经 `arm_builders` 构造表 （`arm_registry`
//!   查表 = 唯一构造路径）+ `register_outbounds` 填 `SimpleOhm`； 默认可执行文件走这条。
//! - **目标主路** = `xray-cli` 的 `framework-assembly`：`derive_families → assemble → fill_bridge →
//!   start_full_with_outbound_handlers`；未进默认构建。
//!
//! 两路**当前不等价**，差异归 4 类（bd zhvi3 台账）。本测试把台账固化成契约：
//! 差异逐条打印 + 分类，**已知差异不算失败，未知差异 = 测试失败**——将来任一侧
//! 漂移（新增/删除协议、增删 guard 门）都会被抓住。
//!
//! ## 为什么比的是「两侧数据源」而不是「跑两路再比表」
//!
//! 框架路的装配入口在 `xray-cli`（`pub(crate) fn run_framework`），而 `xray-cli`
//! 依赖本 crate —— 集成测试既跨不过 crate 可见性，也跨不过依赖环。故本测试的
//! 直接观测面是两侧的**权威数据源**：生产 = `arm_builders` 的构造表（纯数据，
//! 唯一构造路径），框架 = `family_catalog` 的协议 arm 表（注册集的派生源）；再
//! 加一条生产侧**运行时**探针把 ② 失败语义差钉死（生产路静默跳过是可直接观测
//! 的行为，正是本票的关键发现）。
//!
//! shortcut: ③ 的框架侧 fail-visible 行为只有源码级证据（数据源层面无键可观测），
//! 真机端到端在 `--features framework-assembly` 的 e2e 里；升级时机 = 框架路转
//! 生产主路由本测试改成跑两路真表。

use std::collections::BTreeSet;

use xray_app_dispatcher::SimpleOhm;
use xray_conf::Config;
use xray_core::outbound::register_outbounds;

/// 生产路构造表源码（`<方向>:<协议>` → 构造器，唯一构造路径的数据源）。
const ARM_TABLE_SRC: &str = include_str!("../src/arm_builders/mod.rs");
/// 框架路协议目录源码（`family_catalog` 的 arm 表 = 框架注册集的派生源）。
/// 跨 crate `include_str!`：本仓不发布，仅用于台账的数据源取证。
const FRAMEWORK_SRC: &str = include_str!("../../xray-cli/src/framework.rs");

// ============ 台账（已知差异，bd zhvi3） ============

/// ① 覆盖差：生产出站表有、框架协议目录无对应族的协议。
const KNOWN_PROD_ONLY_OUTBOUND: &[&str] = &["mux", "naive"];

/// ① 覆盖差：同一协议两侧名称不同源（生产出站键, 框架族名）。
const KNOWN_NAME_ALIASES: &[(&str, &str)] = &[("dokodemo", "dokodemo-door")];

/// ③ 框架路额外门：族转换缝不消费的条目级配置面（在场即拒），生产路无此门。
const KNOWN_FRAMEWORK_GATES: &[&str] = &["DialerProxy", "Mux", "ProxyChainTag", "SendThrough"];

/// ④ 入站同源的证据锚：框架路把出站 handler 灌进生产启动入口。
const INBOUND_SHARED_ENTRY: &str = "start_full_with_outbound_handlers";

// ============ 差异分类（任务书 4 类） ============

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    /// ① 覆盖差：某协议只有一侧有（含两侧名称不同源）。
    Coverage,
    /// ② 失败语义差：坏段/缺段 → fail-visible 的门只在框架路生效。
    FailureSemantics,
    /// ③ 框架路额外门：同 protocol 只转首个 / guard 面拒绝 / 代理链 late-bind。
    FrameworkGate,
    /// ④ 入站同源：入站表由生产 `spawn_inbounds` 独占，天然等价。
    InboundSameOrigin,
}

impl Class {
    fn label(self) -> &'static str {
        match self {
            Class::Coverage => "① 覆盖差",
            Class::FailureSemantics => "② 失败语义差",
            Class::FrameworkGate => "③ 框架路额外门",
            Class::InboundSameOrigin => "④ 入站同源",
        }
    }
}

struct LedgerRow {
    class: Class,
    item: String,
    known: bool,
}

// ============ 数据源解析 ============

/// 从生产构造表源码抽某方向的协议键（`"outbound:vless"` → `vless`）。
///
/// 锚点是**带引号的** `"<方向>:`——表里既有单行条目（`("outbound:tun", ...)`），
/// 也有跨行条目（`(\n    "inbound:vless",\n    ctor(...)`），故不能连带前括号匹配。
fn prod_arm_protocols(src: &str, direction: &str) -> BTreeSet<String> {
    let needle = format!("\"{direction}:");
    let mut out = BTreeSet::new();
    for line in src.lines() {
        let Some(pos) = line.find(&needle) else { continue };
        let rest = &line[pos + needle.len()..];
        let Some(end) = rest.find('"') else { continue };
        out.insert(rest[..end].to_string());
    }
    out
}

/// 从框架 `family_catalog` 的 arm 表抽族名（`"vless" => ...` → `vless`）。
///
/// 只扫 `fn family_catalog` 到 `_ => return None,` 之间的行——该区间之外（探针、
/// 测试模块）的字符串字面量不参与。
fn framework_families(src: &str) -> BTreeSet<String> {
    let body = src
        .split_once("fn family_catalog(")
        .and_then(|(_, rest)| rest.split_once("_ => return None,"))
        .map(|(body, _)| body)
        .expect("framework.rs 必须仍有 family_catalog 协议 arm 表（本台账的数据源）");
    body.lines()
        .filter_map(|line| line.trim_start().strip_prefix('"'))
        .filter_map(|rest| rest.split_once('"').map(|(name, _)| name.to_string()))
        .collect()
}

/// 从框架路 guard 面常量抽被拒的条目级面（`EntryFacet::Mux` → `Mux`）。
fn framework_gates(src: &str, const_name: &str) -> BTreeSet<String> {
    let body = src
        .split_once(&format!("const {const_name}"))
        .and_then(|(_, rest)| rest.split_once("];"))
        .map(|(body, _)| body)
        .unwrap_or_else(|| panic!("framework.rs 必须仍有 `{const_name}` guard 面常量"));
    let mut out = BTreeSet::new();
    for (pos, _) in body.match_indices("EntryFacet::") {
        let rest = &body[pos + "EntryFacet::".len()..];
        let end = rest.find(|c: char| !c.is_alphanumeric()).unwrap_or(rest.len());
        out.insert(rest[..end].to_string());
    }
    out
}

/// 生产出站键 → 框架族名（台账 ① 的名称不同源归一）。
fn framework_name(prod_name: &str) -> &str {
    KNOWN_NAME_ALIASES
        .iter()
        .find(|(prod, _)| *prod == prod_name)
        .map_or(prod_name, |(_, family)| *family)
}

// ============ 台账生成 ============

/// ① 覆盖差：比两侧协议键集（生产侧按名称不同源归一后比）。
fn classify_coverage(prod: &BTreeSet<String>, fw: &BTreeSet<String>) -> Vec<LedgerRow> {
    let mut rows = Vec::new();
    let normalized: BTreeSet<&str> = prod.iter().map(|p| framework_name(p)).collect();

    for name in &normalized {
        if fw.contains(*name) {
            continue;
        }
        rows.push(LedgerRow {
            class: Class::Coverage,
            item: format!("outbound `{name}`：生产路有 / 框架路无"),
            known: KNOWN_PROD_ONLY_OUTBOUND.contains(name),
        });
    }
    for name in fw {
        if normalized.contains(name.as_str()) {
            continue;
        }
        rows.push(LedgerRow {
            class: Class::Coverage,
            item: format!("outbound `{name}`：框架路有 / 生产路无"),
            known: false,
        });
    }
    // 台账条目过期（框架路已补上）：记账不报红——差异消失是收敛，不是漂移。
    for name in KNOWN_PROD_ONLY_OUTBOUND {
        if fw.contains(*name) {
            rows.push(LedgerRow {
                class: Class::Coverage,
                item: format!("outbound `{name}`：框架路已覆盖（台账条目过期，请更新台账）"),
                known: true,
            });
        }
    }
    // 名称不同源：两侧必须各自还有对应键，缺任一侧 = 漂移。
    for (prod_name, fw_name) in KNOWN_NAME_ALIASES {
        rows.push(LedgerRow {
            class: Class::Coverage,
            item: format!("outbound 名称不同源 `{prod_name}` ↔ `{fw_name}`"),
            known: prod.contains(*prod_name) && fw.contains(*fw_name),
        });
    }
    rows
}

/// ③ 框架路额外门：两侧 guard 面常量必须与台账一致（增删门都要更新台账）。
fn classify_gates(src: &str) -> Vec<LedgerRow> {
    let mut observed = framework_gates(src, "PLUGIN_SEAM_UNHANDLED");
    observed.extend(framework_gates(src, "CORE_SINGLE_UNHANDLED"));

    let mut rows: Vec<LedgerRow> = observed
        .iter()
        .map(|facet| LedgerRow {
            class: Class::FrameworkGate,
            item: format!("出站条目级面 `{facet}` 在框架路被拒（生产路消费）"),
            known: KNOWN_FRAMEWORK_GATES.contains(&facet.as_str()),
        })
        .collect();
    for facet in KNOWN_FRAMEWORK_GATES {
        if !observed.contains(*facet) {
            rows.push(LedgerRow {
                class: Class::FrameworkGate,
                item: format!("出站条目级面 `{facet}`：框架路已放行（台账条目过期，请更新台账）"),
                known: true,
            });
        }
    }
    rows
}

/// ④ 入站同源：框架路不自建入站协议表，出站 handler 灌进生产启动入口。
fn classify_inbound(prod_in: &BTreeSet<String>, src: &str) -> LedgerRow {
    let framework_owns_inbound = src.contains("\"inbound:");
    let shares_entry = src.contains(INBOUND_SHARED_ENTRY);
    LedgerRow {
        class: Class::InboundSameOrigin,
        item: format!(
            "入站表 {} 键全部经生产 `spawn_inbounds`（框架路自建入站表={framework_owns_inbound}、\
             共用启动入口={shares_entry}）",
            prod_in.len()
        ),
        known: !prod_in.is_empty() && !framework_owns_inbound && shares_entry,
    }
}

fn print_ledger(
    prod_out: &BTreeSet<String>,
    prod_in: &BTreeSet<String>,
    fw: &BTreeSet<String>,
    rows: &[LedgerRow],
) {
    println!("== 双主路装配差异台账（bd zhvi3） ==");
    println!(
        "生产路 start_full：outbound {} 键 / inbound {} 键；框架路 framework-assembly：{} 族",
        prod_out.len(),
        prod_in.len(),
        fw.len()
    );
    println!("{:<62} | {:<14} | 状态", "差异", "类别");
    println!("{}", "-".repeat(96));
    for row in rows {
        println!(
            "{:<62} | {:<14} | {}",
            row.item,
            row.class.label(),
            if row.known { "已知" } else { "未知(漂移)" }
        );
    }
    let unknown = rows.iter().filter(|r| !r.known).count();
    println!("{}", "-".repeat(96));
    println!("合计 {} 条，其中未知 {} 条", rows.len(), unknown);
}

// ============ 契约测试 ============

/// 台账契约：未知差异 = 失败；已知差异照常打印。
#[test]
fn assembly_path_difference_ledger() {
    let prod_out = prod_arm_protocols(ARM_TABLE_SRC, "outbound");
    let prod_in = prod_arm_protocols(ARM_TABLE_SRC, "inbound");
    let fw = framework_families(FRAMEWORK_SRC);

    // 解析锚点：任一侧解析失效都会让差异集变空 → 假绿，这里先钉死。
    for anchor in ["freedom", "socks", "vmess"] {
        assert!(prod_out.contains(anchor), "生产出站表解析失效：缺 `{anchor}`");
        assert!(fw.contains(anchor), "框架协议目录解析失效：缺 `{anchor}`");
    }
    assert!(prod_in.contains("mixed"), "生产入站表解析失效：缺 `mixed`");
    // 跨行表条目（`(\n  "inbound:vless",\n  ctor(...)`）必须解析得到——单行锚点
    // 只认前括号会静默漏掉这 4 条，入站计数从 20 塌到 16。
    for anchor in ["vless", "trojan", "vmess", "shadowsocks"] {
        assert!(prod_in.contains(anchor), "生产入站表跨行条目解析失效：缺 `{anchor}`");
    }

    let mut rows = classify_coverage(&prod_out, &fw);
    rows.extend(classify_gates(FRAMEWORK_SRC));
    rows.push(classify_inbound(&prod_in, FRAMEWORK_SRC));
    rows.push(LedgerRow {
        class: Class::FailureSemantics,
        item: "坏段/缺段：生产路 warn+skip 静默丢弃 / 框架路整链 Err → fail-visible 门只在框架路"
            .to_string(),
        known: true,
    });

    print_ledger(&prod_out, &prod_in, &fw, &rows);

    let unknown: Vec<String> = rows
        .iter()
        .filter(|r| !r.known)
        .map(|r| format!("\n  - [{}] {}", r.class.label(), r.item))
        .collect();
    assert!(
        unknown.is_empty(),
        "出现台账外的未知装配差异（两路已漂移，更新台账或修一侧）：{}",
        unknown.concat()
    );
}

/// 恒绿防线：多造一条差异必须被判未知（证明台账不是照抄现状的自证）。
#[test]
fn unknown_difference_is_reported_not_absorbed() {
    let prod: BTreeSet<String> =
        ["freedom", "brand-new-proto"].into_iter().map(String::from).collect();
    let fw: BTreeSet<String> = ["freedom"].into_iter().map(String::from).collect();
    let rows = classify_coverage(&prod, &fw);
    assert!(
        rows.iter().any(|r| !r.known && r.item.contains("brand-new-proto")),
        "生产路新增协议必须报未知：{rows:?}",
        rows = rows.iter().map(|r| (&r.item, r.known)).collect::<Vec<_>>()
    );

    // 反向：框架路多一族同样报未知。
    let prod: BTreeSet<String> = ["freedom"].into_iter().map(String::from).collect();
    let fw: BTreeSet<String> =
        ["freedom", "brand-new-family"].into_iter().map(String::from).collect();
    let rows = classify_coverage(&prod, &fw);
    assert!(
        rows.iter().any(|r| !r.known && r.item.contains("brand-new-family")),
        "框架路新增族必须报未知"
    );

    // 名称不同源台账失效（生产键消失）同样报未知。
    let prod: BTreeSet<String> = ["freedom"].into_iter().map(String::from).collect();
    let fw: BTreeSet<String> = ["freedom", "dokodemo-door"].into_iter().map(String::from).collect();
    let rows = classify_coverage(&prod, &fw);
    assert!(
        rows.iter().any(|r| !r.known && r.item.contains("dokodemo-door")),
        "框架族失去生产同名键必须报未知"
    );
}

/// ② 失败语义差的运行时证据：生产路对未支持协议 **warn + skip**，不返回错误。
///
/// 这是本票关键发现：默认可执行文件里没有「缺段/坏段 → 启动前 fail-visible」的
/// 门，该门只在框架路（插件 build 失败 → 整链 Err）生效。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_path_skips_unsupported_outbound_silently() {
    let cfg = Config::from_json_str(
        &serde_json::json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "tag": "in",
                "listen": "127.0.0.1",
                "port": 1080,
                "protocol": "socks",
                "settings": {}
            }],
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "ghost", "protocol": "no-such-protocol"}
            ]
        })
        .to_string(),
    )
    .expect("config json parses");
    let built = cfg.build().expect("config builds");
    assert!(
        built.outbounds.iter().any(|ob| ob.tag == "ghost"),
        "配置层必须保留未知协议条目（否则本测试测不到注册侧语义）"
    );

    let ohm = SimpleOhm::new();
    register_outbounds(&built, &ohm, None, None, None)
        .expect("生产路不因未支持协议返回错误（warn + skip）");

    let tags = ohm.list_tags();
    assert!(tags.iter().any(|t| t == "direct"), "受支持的出站必须注册，实际 {tags:?}");
    assert!(!tags.iter().any(|t| t == "ghost"), "未支持协议必须静默丢弃，实际 {tags:?}");
}

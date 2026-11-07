//! 双主路装配**差异台账契约测试**（bd zhvi3）——行为级（37vjq-c 升级）。
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
//! ## 证据形态（37vjq-c：源码文本 → 运行时行为）
//!
//! 旧版两侧数据源都是 `include_str!` 源码文本（含 warn 文案锚点断言）——测源码
//! 文本是反模式，文案漂移才会红、行为漂移未必红。本版两侧证据全部运行时化：
//!
//! - 生产侧键集 = [`xray_core::arm_protocol_keys`]（arm_registry 注册表键枚举，
//!   唯一构造路径的权威表，只读投影）；
//! - 框架侧 = dev-dep 闭环 `xray_cli::framework`（xray-cli 依赖 xray-core 为 normal dep，Cargo 允许
//!   dev-dep 环）：[`xray_cli::framework:: framework_family_names`] 目录键集 +
//!   [`xray_cli::framework::project_assembly`] （真实复现 `run_framework` ①②③ 段——derive →
//!   assemble/bring_up 插件 build → fill_bridge → shutdown；不起 socket、不灌 listener）。
//!
//! 台账②的语义由**行为断言**钉死：未知协议条目在框架路 = 记入 unregistered +
//! 桥转换失败记账 + **不达 bridge + 不拒启**（对照生产路 `register_outbounds`
//! 硬错拒启，见 [`production_path_rejects_unsupported_outbound`]）；③ 的 guard
//! 面逐面构造在场条目断言「拒 + 点名 reason + 不达桥」；④ 的入站同源断言
//! 「桥对入站不设族门 + 目录键无方向前缀 + 生产注入点存在」。
//!
//! framework-assembly 特性经 dev-dep 进入本 crate 的测试构建（连带启用
//! `xray-core/framework-assembly` 注入点），`cargo test -p xray-core` 默认执行
//! 本测试（bd gjqm7「框架路零 CI 保护」就此收口）；`run_framework` 的真机端到端
//! （bring_up/listener/优雅停机）仍归 xray-cli e2e 与 `--features
//! framework-assembly` 真机验证，CI 门另票 je3u3。

use std::collections::BTreeSet;

use xray_app_dispatcher::SimpleOhm;
use xray_cli::framework::{framework_family_names, project_assembly, project_derivation};
use xray_conf::{BuiltConfig, BuiltEntry, BuiltInbound, BuiltOutbound, Config};
use xray_core::outbound::register_outbounds;

// ============ 台账（已知差异，bd zhvi3） ============

/// ① 覆盖差：生产出站表有、框架协议目录无对应族的协议。
const KNOWN_PROD_ONLY_OUTBOUND: &[&str] = &["mux", "naive"];

/// ① 覆盖差：同一协议两侧名称不同源（生产出站键, 框架族名）。
///
/// `dokodemo` ↔ `dokodemo-door`：框架族名取 Go 注册名；
/// `direct`/`block`：Go outbound 老式别名（`infra/conf/xray.go:42-46`），生产构造表
/// 收（bd pjg6n），框架路的族目录只认规范名 `freedom`/`blackhole` ⇒ 同一条目在
/// 两条路上名称不同源，属已知差异（框架路对 `direct` 走 warn+skip，生产路正常装配）。
const KNOWN_NAME_ALIASES: &[(&str, &str)] =
    &[("dokodemo", "dokodemo-door"), ("direct", "freedom"), ("block", "blackhole")];

/// ③ 框架路额外门：族转换缝不消费的条目级配置面（在场即拒），生产路无此门。
const KNOWN_FRAMEWORK_GATES: &[&str] = &["DialerProxy", "Mux", "ProxyChainTag", "SendThrough"];

// ============ 差异分类（任务书 4 类） ============

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    /// ① 覆盖差：某协议只有一侧有（含两侧名称不同源）。
    Coverage,
    /// ② 失败语义差：坏段/缺段 → 生产路启动前拒启；框架路 warn+skip 继续跑
    /// （未迁移族条目不达 bridge——bd gjqm7 修正，非「仅时机/文案差」）。
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

/// ③ 框架路额外门（行为级）：观测到的被拒面集合必须 ⊆ 台账；台账每面都要
/// 观测到被拒（`gate_projections` 的硬断言保证，缺面直接红在断言处）。
fn classify_gates(observed: &BTreeSet<String>) -> Vec<LedgerRow> {
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

/// 生产出站键 → 框架族名（台账 ① 的名称不同源归一）。
fn framework_name(prod_name: &str) -> &str {
    KNOWN_NAME_ALIASES
        .iter()
        .find(|(prod, _)| *prod == prod_name)
        .map_or(prod_name, |(_, family)| *family)
}

fn print_ledger(
    prod_out: &BTreeSet<String>,
    prod_in: &BTreeSet<String>,
    fw: &BTreeSet<String>,
    rows: &[LedgerRow],
) {
    println!("== 双主路装配差异台账（bd zhvi3，行为级） ==");
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

// ============ 框架路行为探针（project_assembly 消费面） ============

/// 空 settings 出站条目（kind = 协议名；守卫/派生只看条目级字段，不看 settings）。
fn ob(kind: &str, tag: &str) -> BuiltOutbound {
    BuiltOutbound {
        entry: BuiltEntry { kind: kind.to_string(), data: b"{}".to_vec() },
        tag: tag.to_string(),
        send_through: None,
        stream_settings_json: None,
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    }
}

/// 探针段（段路由底座：`protocol == plugin_name` 匹配，缺段 fail-fast 坑约束 7）。
fn section(protocol: &str, settings: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "protocol": protocol, "settings": settings })
}

/// vless 出站面段（vnext 单端点单用户，Go infra/conf/vless.go 同形）——vless
/// 插件 build 解析出站配置存 `built_outbound`，dial_fn 族转换与干净对照消费。
fn vless_out_section() -> serde_json::Value {
    serde_json::json!({
        "vnext": [{
            "address": "example.com",
            "port": 443,
            "users": [{ "id": "f2b3c1d4-1234-4abc-9def-0123456789ab" }]
        }]
    })
}

/// ③ 的 gate 探针：为台账每面构造**在场条目**。vless = 插件缝族
/// （`PLUGIN_SEAM_UNHANDLED`：DialerProxy/Mux/SendThrough），trojan = core 单
/// 构建族（`CORE_SINGLE_UNHANDLED`：ProxyChainTag/DialerProxy）；ProxyChainTag
/// 用 trojan 承载（vless 已解封该面）。返回 (条目, reason 子串)。
fn gate_entry(facet: &str) -> (BuiltOutbound, &'static str) {
    let mut e = ob("vless", &format!("gate-{facet}"));
    let reason = match facet {
        "Mux" => {
            e.mux_json = Some(serde_json::json!({"enabled": true}));
            "mux wrapping"
        },
        "SendThrough" => {
            e.send_through = Some("127.0.0.1".to_string());
            "sendThrough"
        },
        "DialerProxy" => {
            e.stream_settings_json = Some(serde_json::json!({"sockopt": {"dialerProxy": "hop"}}));
            "DIALER_PROXY_HOOK"
        },
        "ProxyChainTag" => {
            e = ob("trojan", &format!("gate-{facet}"));
            e.proxy_settings_json = Some(serde_json::json!({"tag": "hop"}));
            "proxySettings"
        },
        other => panic!("KNOWN_FRAMEWORK_GATES 出现未知面，探针矩阵未覆盖：{other}"),
    };
    (e, reason)
}

// ============ 契约测试 ============

/// 台账契约：未知差异 = 失败；已知差异照常打印。②③④ 证据全部行为级
/// （`project_assembly` 真实复现 run_framework ①②③ 段 + 硬断言），台账描述
/// 漂移直接红。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn assembly_path_difference_ledger() {
    // 两侧键集（运行时权威面）。
    let (prod_in, prod_out) = xray_core::arm_protocol_keys();
    let prod_out: BTreeSet<String> = prod_out.into_iter().collect();
    let prod_in: BTreeSet<String> = prod_in.into_iter().collect();
    let fw: BTreeSet<String> = framework_family_names().into_iter().map(String::from).collect();

    // 键集非空锚点（旧版解析失效自检的运行时对应物）。
    for anchor in ["freedom", "socks", "vmess"] {
        assert!(prod_out.contains(anchor), "生产出站键集异常：缺 `{anchor}`");
        assert!(fw.contains(anchor), "框架目录键集异常：缺 `{anchor}`");
    }
    assert!(prod_in.contains("mixed"), "生产入站键集异常：缺 `mixed`");

    // 目录键全部可派生（族工厂逐个真跑）：目录加了键、工厂坏了 → 这里红。
    let probe_cfg = BuiltConfig {
        outbounds: fw.iter().map(|n| ob(n, &format!("probe-{n}"))).collect(),
        ..BuiltConfig::default()
    };
    let (derived, unreg) = project_derivation(&probe_cfg);
    assert!(unreg.is_empty(), "目录键必须全部可派生（工厂/键漂移）：{unreg:?}");
    for name in &fw {
        assert!(derived.iter().any(|f| f == name), "目录键 `{name}` 未被 derive_families 派生");
    }

    // ── ② 行为级（替代旧 warn 文案 include_str 锚点）：未知协议条目在框架路
    //    = warn+skip——记入 unregistered + 桥转换失败记账 + 不达 bridge +
    //    **不拒启**（project_assembly 正常返回，无 Err 通道）；已知协议条目
    //    真到达 bridge（探针段齐全 ⇒ 插件 build 真跑、freedom 真转换）。
    let mut cfg2 = BuiltConfig::default();
    cfg2.outbounds.push(ob("freedom", "direct"));
    cfg2.outbounds.push(ob("no-such-protocol", "ghost"));
    let root2 = serde_json::json!({ "outbounds": [section("freedom", serde_json::json!({}))] });
    let p2 = project_assembly(&cfg2, root2).await;
    assert_eq!(
        p2.unregistered,
        vec!["no-such-protocol".to_string()],
        "② 未知协议必须记入 unregistered（warn+skip 面）"
    );
    assert!(
        p2.failed.iter().any(|(t, r)| t == "ghost" && r.contains("no-such-protocol")),
        "② 未知协议条目必须入桥转换失败记账：{:?}",
        p2.failed
    );
    assert!(
        !p2.bridge_tags.iter().any(|t| t == "ghost"),
        "② 未知协议条目不得到达 bridge：{:?}",
        p2.bridge_tags
    );
    assert!(
        p2.bridge_tags.iter().any(|t| t == "direct"),
        "② 已知协议条目必须真到达 bridge：桥={:?} 失败面={:?}",
        p2.bridge_tags,
        p2.failed
    );

    // ── ③ 行为级（替代旧 guard 常量源码解析）：台账每面构造在场条目 →
    //    拒 + reason 点名 + 不达桥；无面干净条目必须转成（拒因归面不归族）。
    let mut observed_gates = BTreeSet::new();
    for facet in KNOWN_FRAMEWORK_GATES {
        let (entry, reason_sub) = gate_entry(facet);
        let mut cfg3 = BuiltConfig::default();
        cfg3.outbounds.push(entry);
        let family = if *facet == "ProxyChainTag" { "trojan" } else { "vless" };
        let root3 = serde_json::json!({ "outbounds": [section(family, if family == "trojan" {
            serde_json::json!({})
        } else {
            vless_out_section()
        })] });
        let p3 = project_assembly(&cfg3, root3).await;
        let tag = format!("gate-{facet}");
        assert!(
            p3.failed.iter().any(|(t, r)| t == &tag && r.contains(reason_sub)),
            "③ 面 `{facet}` 在框架路必须被拒且 reason 点名（{reason_sub}）：{:?}",
            p3.failed
        );
        assert!(
            !p3.bridge_tags.iter().any(|t| t == &tag),
            "③ 面 `{facet}` 在场条目不得到达 bridge（静默丢语义 = 假放行）：{:?}",
            p3.bridge_tags
        );
        observed_gates.insert((*facet).to_string());
    }
    let mut clean3 = BuiltConfig::default();
    clean3.outbounds.push(ob("vless", "clean-vless"));
    clean3.outbounds.push(ob("freedom", "clean-freedom"));
    let root_clean = serde_json::json!({
        "outbounds": [
            section("vless", vless_out_section()),
            section("freedom", serde_json::json!({}))
        ]
    });
    let pclean = project_assembly(&clean3, root_clean).await;
    for tag in ["clean-vless", "clean-freedom"] {
        assert!(
            pclean.failed.iter().all(|(t, _)| t != tag),
            "③ 干净条目 `{tag}` 必须无守卫拒绝（拒因必须归面不归族）：{:?}",
            pclean.failed
        );
        assert!(
            pclean.bridge_tags.iter().any(|t| t == tag),
            "③ 干净条目 `{tag}` 必须正常转换入桥：{:?}",
            pclean.bridge_tags
        );
    }

    // ── ④ 行为级（替代旧 `src.contains` 锚点）：框架桥对入站**不设族门**——
    //    未知协议入站也拿到 dispatch 面 handler（listener/accept 面归生产
    //    `spawn_inbounds` 独占，未知协议在那里拒启 bd vdl95）；目录键无方向
    //    前缀（框架路不自建带 `inbound:` 键的入站协议表）；出站 handler 灌
    //    进生产启动入口 = `start_full_with_outbound_handlers`（feature 门控
    //    注入点，本测试构建经 dev-dep 特性统一启用，取 fn 项即编译期存在断言）。
    let mut cfg4 = BuiltConfig::default();
    cfg4.inbounds.push(crate_ib("socks", "socks-in"));
    cfg4.inbounds.push(crate_ib("no-such-protocol", "ghost-in"));
    let root4 = serde_json::json!({ "inbounds": [section("socks", serde_json::json!({}))] });
    let p4 = project_assembly(&cfg4, root4).await;
    for tag in ["socks-in", "ghost-in"] {
        assert!(
            p4.bridge_tags.iter().any(|t| t == tag),
            "④ 入站 dispatch 面不得设族门（`{tag}` 必须在桥）：{:?}",
            p4.bridge_tags
        );
    }
    assert!(
        fw.iter().all(|n| !n.starts_with("inbound:")),
        "④ 框架目录不得自建带方向前缀的入站协议表：{fw:?}"
    );
    let _shared_entry = xray_core::functions::start_full_with_outbound_handlers;

    // ── 台账装配：① 运行时键集对比 + ②③④ 行为断言背书的已知行。
    let mut rows = classify_coverage(&prod_out, &fw);
    rows.extend(classify_gates(&observed_gates));
    rows.push(LedgerRow {
        class: Class::FailureSemantics,
        // bd gjqm7 修正（zhvi3 旧结论「两路均拒启，仅时机/文案差」不成立）：
        // 生产路拒启（bd o91s4，register_outbounds 构造期硬错，运行时探针见下）；
        // 框架路 warn+skip——上方 ② 行为断言背书（unregistered + 不达桥 + 不拒启）。
        item: "坏段/缺段：生产路启动前拒启（register_outbounds 构造期硬错）；\
               框架路 warn+skip（条目不达 bridge，进程照常起）"
            .to_string(),
        known: true,
    });
    rows.push(LedgerRow {
        class: Class::InboundSameOrigin,
        item: format!(
            "入站表 {} 键全部经生产 `spawn_inbounds`（桥不设族门 + 目录无方向键 + \
             注入点 start_full_with_outbound_handlers 在场——行为断言背书）",
            prod_in.len()
        ),
        known: !prod_in.is_empty(),
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

/// 空 settings 入站条目（④ 探针用）。
fn crate_ib(kind: &str, tag: &str) -> BuiltInbound {
    BuiltInbound {
        entry: BuiltEntry { kind: kind.to_string(), data: b"{}".to_vec() },
        tag: tag.to_string(),
        port: None,
        listen: None,
        stream_settings_json: None,
        sniffing_json: None,
    }
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

/// ② 生产侧的运行时证据：生产路对「未知协议」在启动前失败（bd o91s4）。
/// 台账 ② 的框架侧（warn+skip）由 `assembly_path_difference_ledger` 的
/// `project_assembly` 行为断言钉住（bd gjqm7 修正：两路**不**等价——框架路
/// 不拒启，这是语义差，不是时机/文案差）。
///
/// 本票（zhvi3）发现时的原始状态是生产路 warn + skip（默认可执行文件里没有
/// 「缺段/坏段 → 启动前 fail-visible」的门）；o91s4 把该门补上后，此探针改为
/// 断言「生产路必须报错且错误点名条目」。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_path_rejects_unsupported_outbound() {
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
    let err = register_outbounds(&built, &ohm, None, None, None)
        .expect_err("生产路必须对未支持协议拒启（bd o91s4，对齐 Go conf 解码期硬错）");
    assert!(err.to_string().contains("no-such-protocol"), "错误必须点名协议：{err}");
    // 拒启语义：不得留下「部分注册」的假可用表（默认出站前移是本票的原始危害）。
    let tags = ohm.list_tags();
    assert!(!tags.iter().any(|t| t == "ghost"), "未知协议不得注册，实际 {tags:?}");
}

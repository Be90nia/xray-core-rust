//! 票 xiuvr 3c 影子比对：`skeleton_infra::config::ConfigFile`（udf config-json）
//! vs 旧装载路径（`xray_conf::confloader::load_file` / `serial::merge_configs`）。
//!
//! 同一批 Golden 配置双装载器对照，逐字段（递归）diff。判定规则：
//! - 单文件等价组差异必须为 0（值面 + serde 反序列化全链同型对照）；
//! - 分层组差异**预期非 0**（旧 `override_with` 数组按 tag 合并 vs 新 `merge_over`
//!   数组整体替换）——断言差异**只**落在 inbounds/outbounds 数组面，差异展开进对照表报 PM；
//! - 注释容忍是确凿行为差异（旧 std_ext::json Tolerant vs 新裸 serde_json）。
//!
//! 结论（2026-10-26，票 xiuvr）：差异非 0 → **不许切换**，旧路径保留。

use std::path::PathBuf;

use serde_json::Value;
use skeleton_infra::config::ConfigFile;
use xray_conf::Config;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("shadow")
        .join(name)
}

/// 旧装载器：文件 → `Config`（含注释容忍/多格式/strict env 语义）→ 值面。
fn load_old(path: &std::path::Path) -> Result<Value, String> {
    xray_conf::load_file(path)
        .map_err(|e| format!("ConfError: {e}"))?
        .to_json_value()
        .map_err(|e| format!("ConfError(serialize): {e}"))
}

/// 新装载器：`ConfigFile<C>` 单层 file_layer → 折叠 → `Config` → 值面。
fn load_new(path: &std::path::Path) -> Result<Value, String> {
    ConfigFile::<Config>::new()
        .file_layer(path)
        .map_err(|e| format!("ConfigError(file_layer): {e}"))?
        .load()
        .map_err(|e| format!("ConfigError(load): {e}"))?
        .to_json_value()
        .map_err(|e| format!("ConfError(serialize): {e}"))
}

/// 递归逐字段 diff；返回差异路径行（`$` 为根）。
fn diff_json(path: &str, old: &Value, new: &Value, out: &mut Vec<String>) {
    match (old, new) {
        (Value::Object(o), Value::Object(n)) => {
            for (k, ov) in o {
                match n.get(k) {
                    Some(nv) => diff_json(&format!("{path}.{k}"), ov, nv, out),
                    None => out.push(format!("{path}.{k}: 旧={ov} 新=<缺失>")),
                }
            }
            for (k, nv) in n {
                if !o.contains_key(k) {
                    out.push(format!("{path}.{k}: 旧=<缺失> 新={nv}"));
                }
            }
        },
        (Value::Array(o), Value::Array(n)) => {
            if o.len() != n.len() {
                out.push(format!("{path}: 数组长度 旧={} 新={}", o.len(), n.len()));
            }
            for (i, (ov, nv)) in o.iter().zip(n.iter()).enumerate() {
                diff_json(&format!("{path}[{i}]"), ov, nv, out);
            }
        },
        _ => {
            if old != new {
                out.push(format!("{path}: 旧={old} 新={new}"));
            }
        },
    }
}

/// 叶子节点计数（对照表「字段数」列）。
fn count_leaves(v: &Value) -> usize {
    match v {
        Value::Object(m) => m.values().map(count_leaves).sum(),
        Value::Array(a) => a.iter().map(count_leaves).sum(),
        _ => 1,
    }
}

fn shadow_table_row(name: &str, old: &Value, new: &Value) -> Vec<String> {
    let mut diffs = Vec::new();
    diff_json("$", old, new, &mut diffs);
    println!(
        "| {name} | {} / {} | {} | {} |",
        count_leaves(old),
        count_leaves(new),
        if diffs.is_empty() { "相等" } else { "差异" },
        if diffs.is_empty() { "-".to_string() } else { diffs.join("; ") },
    );
    diffs
}

#[test]
fn shadow_single_file_parity() {
    println!("| 配置 | 字段数 旧/新 | 相等 | 差异项 |");
    println!("|---|---|---|---|");
    let mut total_diffs = 0usize;
    for name in [
        "01-minimal.json",
        "02-full-apps.json",
        "03-multi-inbounds.json",
        "04-outbound-chain.json",
        "07-missing-sections.json",
    ] {
        let path = fixture(name);
        let old = load_old(&path).unwrap_or_else(|e| panic!("{name} 旧装载失败: {e}"));
        let new = load_new(&path).unwrap_or_else(|e| panic!("{name} 新装载失败: {e}"));
        total_diffs += shadow_table_row(name, &old, &new).len();
    }
    assert_eq!(total_diffs, 0, "单文件等价组出现差异（见上方对照表）");
}

#[test]
fn shadow_default_layer_parity() {
    // default_layer(Config::default())（serde default 同源空底座）+ file_layer
    // ≡ 旧单文件装载：验证 default_layer 通道不引入值面漂移。
    let path = fixture("01-minimal.json");
    let old = load_old(&path).unwrap();
    let new = ConfigFile::<Config>::new()
        .default_layer(&Config::default())
        .expect("default_layer 序列化")
        .file_layer(&path)
        .expect("file_layer")
        .load()
        .expect("折叠")
        .to_json_value()
        .expect("序列化");
    let mut diffs = Vec::new();
    diff_json("$", &old, &new, &mut diffs);
    println!("default_layer 组差异: {:?}", diffs);
    assert!(diffs.is_empty(), "default_layer 通道引入差异: {diffs:?}");
}

#[test]
fn shadow_layered_merge_diff_report() {
    // 旧：serial.merge_configs（override_with：inbounds 同 tag 替换/新 tag 追加，
    // outbounds 同 tag 替换/新 tag prepend）；新：ConfigFile 双层 merge_over
    //（对象递归合并、数组整体替换）。预期差异**仅**落在两个数组面。
    let base = fixture("base-layer.json");
    let over = fixture("override-layer.json");

    let old = xray_conf::merge_configs(&[base.clone(), over.clone()])
        .expect("旧分层装载")
        .to_json_value()
        .expect("旧序列化");
    let new = ConfigFile::<Config>::new()
        .file_layer(&base)
        .expect("新 base 层")
        .file_layer(&over)
        .expect("新 override 层")
        .load()
        .expect("新折叠")
        .to_json_value()
        .expect("新序列化");

    let diffs = shadow_table_row("base+override（分层）", &old, &new);
    assert!(!diffs.is_empty(), "分层组差异为 0 与已知语义差异（数组合并 vs 整体替换）矛盾");
    let stray: Vec<&String> = diffs
        .iter()
        .filter(|d| !(d.starts_with("$.inbounds") || d.starts_with("$.outbounds")))
        .collect();
    assert!(
        stray.is_empty(),
        "分层组差异越出 inbounds/outbounds 数组面（其余字段应逐字段相等）: {stray:?}"
    );
    println!(
        "根因：旧 override_with 按 tag 合并数组（保留他项+outbounds 新 tag prepend），新 merge_over 数组整体替换。"
    );
}

#[test]
fn shadow_comment_tolerance_gap() {
    // 旧路径 std_ext::json Tolerant 容忍 //、/* */；新路径 file_layer 裸
    // serde_json::from_slice 拒绝注释。带注释配置（.jsonc）是确凿差异点。
    let path = fixture("05-with-comments.jsonc");
    let old = load_old(&path);
    let new = load_new(&path);
    println!("注释组 旧装载: {:?}", old.as_ref().map(count_leaves));
    println!(
        "注释组 新装载: {}",
        match &new {
            Ok(_) => "成功".to_string(),
            Err(e) => e.clone(),
        }
    );
    assert!(old.is_ok(), "旧装载器应容忍注释");
    assert!(
        new.is_err(),
        "新装载器（裸 serde_json）应拒绝注释——若此断言翻转说明 udf 侧语义已变，须重审切换判定"
    );
}

#[test]
fn shadow_failure_injection() {
    // 缺文件：两边都失败，错误面可对照（不要求文案相等，要求失败不静默）。
    let missing = fixture("nonexistent.json");
    assert!(xray_conf::load_file(&missing).is_err());
    assert!(ConfigFile::<Config>::new().file_layer(&missing).is_err());

    // 坏 JSON：两边都失败；旧错误带行列位置（ConfError::Parse{format,line}）。
    let bad = fixture("06-bad-syntax.json");
    let old_err = format!("{:?}", xray_conf::load_file(&bad).unwrap_err());
    let new_err = format!("{:?}", ConfigFile::<Config>::new().file_layer(&bad).unwrap_err());
    println!("坏 JSON 旧错误: {old_err}");
    println!("坏 JSON 新错误: {new_err}");
    assert!(old_err.contains("Parse"), "旧错误应为 Parse 族: {old_err}");
    assert!(new_err.contains("Parse"), "新错误应为 Parse 族: {new_err}");
}

// =========================================================================
// W2 影子三路对照（能力收敛方案 面 1 步 2，2026-10-27）
// =========================================================================
//
// 三路定义：
// - 旧行为：`load_file` + `Config::override_with` 循环 = 切换前 `merge_configs`
//   原文（`override_with` 现存消费者 = xray-cli `convert pb`，此处兼作特征化
//   参照常驻，钉住两实现持续等价）。
// - 新折叠：`serial::merge_configs` → xray-frame `XrayConfigLayers` + `xray_policy()`（W2
//   切换后生产路径）。
// - Go typed 语义：Go `infra/conf/serial.mergeConfigs`（builder.go）→
//   `Config.Override`（xray.go:502-588）→ `MarshalToJson(c, true)`。旧列即其 逐行移植（32/32
//   真机长期背书）；Go 列另由真 Go 内核 `run -dump` 实测， 对照表落
//   reports/audit-2026-10-27/w2-config-shadow.md。
//
// 判定：typed 域（Config 序列化面）差异必须为 0。Value 域唯一预期差异 = 未知
// 键保留（折叠刻意保留；Go typed 丢弃是解析副作用，非合并语义；终态 typed
// 装配两侧一致）——由 `w2_unknown_keys_survive_fold_only` 钉住。
// 「数组整体替换 vs merge_over 语义区分」：merge_over 对数组整体替换（既有
// `shadow_layered_merge_diff_report` 已证差异面），fold 按 tag 合并——由
// `w2_shadow_layered_parity` 的并集断言钉住。

fn w2_fixture(name: &str) -> PathBuf {
    fixture(&format!("w2/{name}"))
}

/// 旧 typed 装配路径（切换前 `merge_configs` 原文形态，特征化参照）。
fn merge_configs_legacy(paths: &[PathBuf]) -> Result<Config, String> {
    let mut merged: Option<Config> = None;
    for path in paths {
        let cfg = xray_conf::load_file(path).map_err(|e| {
            // 切换前生产包装同型：ConfError::Read（Display 前缀 "failed to read config: "）。
            xray_conf::ConfError::Read(format!("failed to read config {}: {e}", path.display()))
                .to_string()
        })?;
        match merged.take() {
            None => merged = Some(cfg),
            Some(mut base) => {
                base.override_with(cfg, &path.display().to_string());
                merged = Some(base);
            },
        }
    }
    merged.ok_or_else(|| xray_conf::ConfError::Read("no config files to merge".into()).to_string())
}

fn merge_old(paths: &[PathBuf]) -> Result<Value, String> {
    merge_configs_legacy(paths)?.to_json_value().map_err(|e| e.to_string())
}

fn merge_new(paths: &[PathBuf]) -> Result<Value, String> {
    xray_conf::merge_configs(paths)
        .map_err(|e| e.to_string())?
        .to_json_value()
        .map_err(|e| e.to_string())
}

/// typed 域逐字段对照（差异表必须为 0），差异展开进输出。
fn assert_typed_parity(name: &str, paths: &[PathBuf]) {
    let old = merge_old(paths).unwrap_or_else(|e| panic!("{name} 旧装载失败: {e}"));
    let new = merge_new(paths).unwrap_or_else(|e| panic!("{name} 新装载失败: {e}"));
    let mut diffs = Vec::new();
    diff_json("$", &old, &new, &mut diffs);
    println!(
        "| {name} | {} / {} | {} |",
        count_leaves(&old),
        count_leaves(&new),
        if diffs.is_empty() { "0 差异".to_string() } else { diffs.join("; ") },
    );
    assert!(diffs.is_empty(), "{name} 影子差异非 0: {diffs:?}");
}

#[test]
fn w2_shadow_single_file_parity() {
    println!("| 配置 | 字段数 旧/新 | 差异 |");
    println!("|---|---|---|");
    for name in [
        "01-minimal.json",
        "02-full-apps.json",
        "03-multi-inbounds.json",
        "04-outbound-chain.json",
        "05-with-comments.jsonc",
        "07-missing-sections.json",
        "w2/base-a.json",
        "w2/override-b.json",
        "w2/mt-base.json",
        "w2/mt-override.json",
        "w2/third-layer.json",
        "w2/zz-tail-append.json",
    ] {
        assert_typed_parity(name, &[fixture(name)]);
    }
}

#[test]
fn w2_shadow_layered_parity() {
    // 分层组：tag 替换+追加 / outbound 前插 / transport 整体替换 / env 键级
    // 合并 / tail 来源追加 / 缺 tag（"" 零值）替换 / 三层链。逐组 0 差异。
    let groups: Vec<(&str, Vec<PathBuf>)> = vec![
        (
            "base+override（tag 命中/前插）",
            vec![fixture("base-layer.json"), fixture("override-layer.json")],
        ),
        (
            "base-a+override-b（transport/env/未知键）",
            vec![w2_fixture("base-a.json"), w2_fixture("override-b.json")],
        ),
        (
            "mt-base+mt-override（缺 tag 零值替换）",
            vec![w2_fixture("mt-base.json"), w2_fixture("mt-override.json")],
        ),
        (
            "三层链 base-a+override-b+third",
            vec![
                w2_fixture("base-a.json"),
                w2_fixture("override-b.json"),
                w2_fixture("third-layer.json"),
            ],
        ),
    ];
    for (name, paths) in &groups {
        assert_typed_parity(name, paths);
    }

    // 数组语义钉住（对照物 = merge_over 的整体替换）：fold 产出两层数组并集。
    let merged = merge_new(&[w2_fixture("base-a.json"), w2_fixture("override-b.json")]).unwrap();
    let in_tags: Vec<&str> = merged["inbounds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["tag"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(
        in_tags,
        vec!["in-a", "in-b", "in-c"],
        "inbound 应为 tag 合并并集（merge_over 会只剩第二层）"
    );
    let out_tags: Vec<&str> = merged["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["tag"].as_str().unwrap_or(""))
        .collect();
    // socks-new 未命中 → 前插头部（Go xray.go:478-496）；block 命中 → 原地替换。
    assert_eq!(out_tags, vec!["socks-new", "direct", "block"], "outbound 未命中应前插头部");
    // transport 块级整体替换（非递归合并；block_replace_keys 含 transport）。
    assert_eq!(merged["transport"], serde_json::json!({ "namen": "grpc-new", "extra": true }));
    // env 键级合并（非整体替换，Go EnvConfig.Override）。
    assert_eq!(merged["env"], serde_json::json!({ "W2_A": "1", "W2_B": "2" }));
}

#[test]
fn w2_shadow_tail_source_appends() {
    // 来源文件名含 "tail"（大小写不敏感）→ outbound 未命中追加尾部
    // （Go xray.go:487-489），而非前插。
    let paths = [w2_fixture("base-a.json"), w2_fixture("zz-tail-append.json")];
    let merged = merge_new(&paths).unwrap();
    let out_tags: Vec<&str> = merged["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["tag"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(out_tags, vec!["direct", "block", "dns-out", "http-out"]);
    assert_typed_parity("base-a+tail", &paths);
}

#[test]
fn w2_unknown_keys_survive_fold_only() {
    // Value 域（W1 已知设计事实）：折叠保留未知键（顶层 / log 块内 / 条目内）。
    // 语义归属 = 折叠层刻意保留；Go typed 丢弃是解析副作用，非合并语义；终态
    // typed 装配丢弃未知键 → 与旧 typed 路径终态一致（各 parity 组已证 0 差异）。
    let raw = std::fs::read_to_string(w2_fixture("base-a.json")).unwrap();
    let value: Value = serde_json::from_str(&raw).unwrap();
    let mut layers = xray_frame::config::XrayConfigLayers::new();
    layers.push_value_from(value, "base-a.json");
    let folded = layers.merge(xray_frame::config::xray_policy());
    assert!(folded.get("unknownTop").is_some(), "折叠层应保留未知顶层键");
    assert_eq!(folded["log"]["unknownInLog"], serde_json::json!("keep-me-at-value-layer"));
    assert_eq!(folded["inbounds"][0]["unknownEntryKey"], serde_json::json!(1));
    // 终态等价：typed 解析后未知键消失。
    let cfg: Config = serde_json::from_value(folded).unwrap();
    let final_value = cfg.to_json_value().unwrap();
    assert!(final_value.get("unknownTop").is_none());
    assert!(final_value["log"].get("unknownInLog").is_none());
    assert!(final_value["inbounds"][0].get("unknownEntryKey").is_none());
}

#[test]
fn w2_shadow_error_parity() {
    // 坏 JSON / 缺文件：两侧同败且错误文案逐字一致（load_value 错误构造与
    // load_file 同型 + merge 包装同串）。
    let bad = fixture("06-bad-syntax.json");
    let old_err = merge_configs_legacy(std::slice::from_ref(&bad)).unwrap_err();
    let new_err = xray_conf::merge_configs(std::slice::from_ref(&bad)).unwrap_err().to_string();
    assert_eq!(old_err, new_err, "坏 JSON 错误文案应逐字一致");

    let missing = fixture("nonexistent.json");
    let old_err = merge_configs_legacy(std::slice::from_ref(&missing)).unwrap_err();
    let new_err = xray_conf::merge_configs(std::slice::from_ref(&missing)).unwrap_err().to_string();
    assert_eq!(old_err, new_err, "缺文件错误文案应逐字一致");

    // 空列表：两侧同败（切换前文案 = "no config files to merge"）。
    assert!(merge_configs_legacy(&[]).is_err());
    assert!(xray_conf::merge_configs(&[]).is_err());
}

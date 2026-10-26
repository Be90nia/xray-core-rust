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

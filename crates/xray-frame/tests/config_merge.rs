//! 面 1 验收：Xray 语义折叠 —— tag 命中替换 / inbound 未命中追加 / outbound
//! 未命中前插 / `source` 含 `"tail"` 追加 / `env` 键级合并 / 块整体替换 /
//! 注释容忍解码 / 错误形态映射（行列位置）。

use std::path::PathBuf;

use serde_json::json;
use std_ext::json::JsonMode;
use xray_frame::config::{ConfigLayerError, XrayConfigLayers, xray_policy};

fn tags(value: &serde_json::Value, key: &str) -> Vec<String> {
    value[key]
        .as_array()
        .expect("array")
        .iter()
        .map(|item| item["tag"].as_str().unwrap_or_default().to_owned())
        .collect()
}

#[test]
fn inbound_tag_hit_replaces_in_place() {
    let mut layers = XrayConfigLayers::new();
    layers.push_value(json!({"inbounds": [{"tag": "a", "port": 1}]}));
    layers.push_value(json!({"inbounds": [{"tag": "a", "port": 2}]}));
    let merged = layers.merge(xray_policy());
    assert_eq!(merged["inbounds"].as_array().expect("array").len(), 1, "tag 命中 → 替换不新增");
    assert_eq!(merged["inbounds"][0]["port"], json!(2), "tag 命中 → 原地替换");
}

#[test]
fn inbound_unmatched_appends_to_tail() {
    let mut layers = XrayConfigLayers::new();
    layers.push_value(json!({"inbounds": [{"tag": "a"}]}));
    layers.push_value(json!({"inbounds": [{"tag": "b"}]}));
    let merged = layers.merge(xray_policy());
    assert_eq!(tags(&merged, "inbounds"), vec!["a", "b"], "inbound 未命中 → 追加尾部");
}

#[test]
fn outbound_unmatched_prepends_to_head() {
    let mut layers = XrayConfigLayers::new();
    layers.push_value(json!({"outbounds": [{"tag": "direct"}]}));
    layers.push_value(json!({"outbounds": [{"tag": "proxy"}]}));
    let merged = layers.merge(xray_policy());
    assert_eq!(tags(&merged, "outbounds"), vec!["proxy", "direct"], "outbound 未命中 → 前插头部");
}

#[test]
fn outbound_unmatched_with_tail_source_appends_to_tail() {
    let mut layers = XrayConfigLayers::new();
    layers.push_value(json!({"outbounds": [{"tag": "direct"}]}));
    layers.push_value_from(json!({"outbounds": [{"tag": "tail-ob"}]}), "99_zz_tail.json");
    let merged = layers.merge(xray_policy());
    assert_eq!(tags(&merged, "outbounds"), vec!["direct", "tail-ob"], "source 含 tail → 追加尾部");
}

#[test]
fn env_merges_by_key_instead_of_replacing() {
    let mut layers = XrayConfigLayers::new();
    layers.push_value(json!({"env": {"A": "1"}}));
    layers.push_value(json!({"env": {"B": "2"}}));
    let merged = layers.merge(xray_policy());
    assert_eq!(merged["env"]["A"], json!("1"), "env 键级合并：旧键保留");
    assert_eq!(merged["env"]["B"], json!("2"), "env 键级合并：新键并入");

    let mut layers = XrayConfigLayers::new();
    layers.push_value(json!({"env": {"A": "1"}}));
    layers.push_value(json!({"env": {"A": "9"}}));
    let merged = layers.merge(xray_policy());
    assert_eq!(merged["env"]["A"], json!("9"), "env 同键 → 后层覆盖");
}

#[test]
fn block_keys_are_replaced_wholesale() {
    let mut layers = XrayConfigLayers::new();
    layers.push_value(json!({"log": {"loglevel": "info"}}));
    layers.push_value(json!({"log": {"access": "none"}}));
    let merged = layers.merge(xray_policy());
    assert_eq!(merged["log"], json!({"access": "none"}), "块级键整体替换（不键级合并）");
}

#[test]
fn comment_tolerant_decode_and_error_shape() {
    let dir = std::env::temp_dir().join("xray_frame_config_merge_test");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path: PathBuf = dir.join("layer.json");
    std::fs::write(&path, "{\n  // 行注释\n  \"log\": { \"loglevel\": \"warning\" }\n}\n")
        .expect("write fixture");

    let mut layers = XrayConfigLayers::new();
    layers.push_file(&path, JsonMode::Tolerant).expect("注释容忍解码");
    let merged = layers.merge(xray_policy());
    assert_eq!(merged["log"]["loglevel"], json!("warning"), "注释容忍层内容生效");

    let err = layers.push_file(&path, JsonMode::Strict).expect_err("strict 模式拒绝注释");
    match err {
        ConfigLayerError::Parse { path: err_path, line, column, message } => {
            assert!(err_path.ends_with("layer.json"), "错误带文件归属: {err_path}");
            assert!(line > 0 && column > 0, "错误带行列位置: {line}:{column}");
            assert!(!message.is_empty(), "错误带原因");
        },
        other => panic!("strict 失败形态 = Parse，实际: {other:?}"),
    }
}

#[test]
fn missing_file_yields_read_error() {
    let mut layers = XrayConfigLayers::new();
    let err = layers
        .push_file(std::path::Path::new("no_such_file_xyz.json"), JsonMode::Strict)
        .expect_err("读不到文件");
    assert!(matches!(err, ConfigLayerError::Read { .. }), "读失败形态 = Read，实际: {err:?}");
}

//! 面 5 验收（G5）：红线受控入口 —— 逃逸口调用集合 ⊆ 台账集合 + 台账条目
//! 完整 + 主仓**生产面**的裸 `tracing::event!` 只出现在红线站点文件内。
//!
//! 扫描口径：仓库根 = `crates/xray-frame` 的上上级；扫描 `crates/**`（跳过
//! `crates/xray-frame` 本体与 `crates/udf-frame` 父仓）；测试面 = 文件内首个
//! `#[cfg(test)]` 标记之后（Rust 单文件惯例：测试模块在文件尾）。

use std::path::{Path, PathBuf};

use xray_frame::redline::{RedlineSite, SITES};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate dir 有上级")
        .parent()
        .expect("crates/ 有上级")
        .to_path_buf()
}

/// 递归收集 `crates/**` 下的 `.rs` 文件（相对仓库根的路径）。
fn scan_crate_sources(root: &Path) -> Vec<(String, String)> {
    let crates_dir = root.join("crates");
    let mut out = Vec::new();
    let mut stack = vec![crates_dir.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.is_dir() {
                // 跳过本仓（逃逸口实现本体）与父仓（udf-frame 工作副本）。
                if name == "xray-frame" || name == "udf-frame" || name == "target" {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            let rel =
                path.strip_prefix(root).expect("在仓库根下").to_string_lossy().replace('\\', "/");
            out.push((rel, content));
        }
    }
    out
}

/// 该行是否落在测试面（文件内首个 `#[cfg(test)]` 之后）。
fn is_test_scope(content: &str, line_idx: usize) -> bool {
    content.lines().take(line_idx).any(|line| line.trim_start().starts_with("#[cfg(test)]"))
}

#[test]
fn ledger_entries_are_complete() {
    assert!(!SITES.is_empty(), "台账非空");
    for site in SITES {
        assert!(!site.id().is_empty(), "站点 id 禁空");
        assert!(!site.reason().is_empty(), "站点 {} 理由禁空", site.id());
        assert!(!site.clause().is_empty(), "站点 {} 条款禁空", site.id());
        assert!(!site.expected_file().is_empty(), "站点 {} 期望文件禁空", site.id());
    }
    assert!(SITES.len() <= 12, "台账规模受上限约束（枚举不随迁移增长）");
}

#[test]
fn escape_hatch_call_sites_are_registered() {
    let root = repo_root();
    let registered: Vec<&str> = SITES.iter().map(|site| site.expected_file()).collect();
    let mut found: Vec<String> = Vec::new();
    for (file, content) in scan_crate_sources(&root) {
        if content.contains("redline::spawn_unchecked") || content.contains("redline::event") {
            found.push(file.clone());
            assert!(
                registered.contains(&file.as_str()),
                "逃逸口调用点未登记台账: {file}（登记集合: {registered:?}）"
            );
        }
    }
    // 已登记的站点若已被迁移，其期望文件必在调用集合内（登记 ≠ 未使用）。
    for site in SITES {
        if found.is_empty() {
            break;
        }
        assert!(
            found.iter().any(|f| f == site.expected_file()),
            "站点 {} 已登记但其期望文件 {} 无逃逸口调用",
            site.id(),
            site.expected_file()
        );
    }
}

#[test]
fn bare_tracing_event_only_exists_in_registered_redline_files() {
    let root = repo_root();
    let registered: Vec<&str> = SITES.iter().map(|site| site.expected_file()).collect();
    for (file, content) in scan_crate_sources(&root) {
        for (idx, line) in content.lines().enumerate() {
            if !line.contains("tracing::event!") {
                continue;
            }
            if is_test_scope(&content, idx) {
                continue;
            }
            assert!(
                registered.contains(&file.as_str()),
                "红线站点外的裸 tracing::event!: {file}:{}",
                idx + 1
            );
        }
    }
}

#[tokio::test]
async fn redline_spawn_is_observable() {
    let before = xray_frame::redline::spawn_count(RedlineSite::VisionSpliceSpawn);
    let handle =
        xray_frame::redline::spawn_unchecked(RedlineSite::VisionSpliceSpawn, async { 5u32 });
    assert_eq!(
        xray_frame::redline::spawn_count(RedlineSite::VisionSpliceSpawn),
        before + 1,
        "逃逸 spawn 计数递增（观测面）"
    );
    assert_eq!(handle.await.expect("join"), 5, "逃逸 spawn 语义 = 裸 tokio::spawn");
}

//! REALITY 工具函数。
//!
//! 翻译自 Go `transport/internet/reality/` 中两个不依赖 uTLS 的纯函数：
//! - `KeyLogWriterFromConfig`：master key log 文件打开
//! - `getPathLocked`：从路径集合中选一条（spider 模式 fallback）

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::path::Path;

/// 打开 master key log 文件。
///
/// 对应 Go `KeyLogWriterFromConfig`。行为：
/// - `path` 为空或 `"none"` → 返回 `None`（不记录）
/// - 否则以「创建/读写/追加」模式打开（Go 端 `O_CREATE|O_RDWR|O_APPEND`，权限 0644）
///
/// 与 Go 端一致：打开失败返回 `None`（Go 端仅记日志不传播错误），调用方
/// 在后续 TLS 握手时仍能正常工作（只是缺少 key log）。
pub fn open_key_log_writer<P: AsRef<Path>>(path: P) -> Option<std::fs::File> {
    let p = path.as_ref();
    let s = p.to_string_lossy();
    if s.is_empty() || s == "none" {
        return None;
    }
    OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(p)
        .ok()
}

/// spider 模式从路径集合中选一条。
///
/// 对应 Go `getPathLocked(paths)`。Go 端用 `crypto.RandBetween(0, len-1)`
/// 随机选 index；本实现不引 `rand` 依赖（避免在配置层加 RNG 源），用
/// `paths.iter().next()` 取 HashMap 迭代序的首项作为确定性 fallback。
///
/// 真正的随机选择等接入 [`xray_crypto`] 的 rand 等价品后替换；当前确定性
/// 选择对 REALITY 握手业务无影响（spider 模式仅在 fallback 路径触发）。
///
/// # 参数
/// - `paths`：已收集的路径集合（由 spider crawler 维护）
///
/// # 返回
/// 选中的路径；集合为空时返回 `"/"`（与 Go 端 fallthrough 一致）
pub fn get_path_locked<'a>(paths: &'a HashMap<String, ()>) -> &'a str {
    // ponytail: deterministic for now; random selection deferred to xray_crypto
    // rand_between once RNG plumbing lands.
    paths.keys().next().map(String::as_str).unwrap_or("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_key_log_writer_empty_returns_none() {
        assert!(open_key_log_writer("").is_none());
    }

    #[test]
    fn open_key_log_writer_none_literal_returns_none() {
        assert!(open_key_log_writer("none").is_none());
    }

    #[test]
    fn open_key_log_writer_creates_file() {
        let path = std::env::temp_dir().join(format!(
            "xray_reality_test_{}.keylog",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let f = open_key_log_writer(&path);
        assert!(f.is_some(), "should create file");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn get_path_locked_empty_returns_root() {
        let paths = HashMap::new();
        assert_eq!(get_path_locked(&paths), "/");
    }

    #[test]
    fn get_path_locked_non_empty_returns_member() {
        let mut paths = HashMap::new();
        paths.insert("/foo".to_string(), ());
        paths.insert("/bar".to_string(), ());
        let p = get_path_locked(&paths);
        // 确定性版本：必在集合内（具体取首项由 HashMap 迭代序决定）
        assert!(p == "/foo" || p == "/bar");
    }
}

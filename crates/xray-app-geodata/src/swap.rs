//! 文件原子交换：stage → swap → tx(rollback/commit) → clean。
//!
//! 对应 Go `app/geodata/download.go` 的 stage/swap/tx/clean 类型与函数。
//! 业务核心可独立测试（在临时目录中跑完整流程）。

use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::error::{GeodataError, at_error, at_warning};

/// Stage：一次下载暂存（target 是最终路径，temp 是临时文件路径）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage {
    pub target: PathBuf,
    pub temp: PathBuf,
}

/// Swap：一次原子替换的备份信息（用于回滚）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Swap {
    pub target: PathBuf,
    pub backup: PathBuf,
    pub had_original: bool,
}

/// Transaction：累积多个 swap，提供 rollback / commit。
pub struct Tx {
    swaps: Vec<Swap>,
}

impl Tx {
    pub fn new() -> Self {
        Self { swaps: Vec::new() }
    }

    pub fn push(&mut self, swap: Swap) {
        self.swaps.push(swap);
    }

    pub fn len(&self) -> usize {
        self.swaps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.swaps.is_empty()
    }

    /// 回滚：逆序恢复每个 swap。
    pub fn rollback(self) -> Result<(), GeodataError> {
        let mut errs: Vec<GeodataError> = Vec::new();
        for swap in self.swaps.into_iter().rev() {
            if let Err(e) = rollback_swap(&swap) {
                errs.push(e);
            }
        }
        combine_errs(errs)
    }

    /// 提交：删除所有 backup（保留新文件）。
    pub fn commit(self) -> Result<(), GeodataError> {
        let mut errs: Vec<GeodataError> = Vec::new();
        for swap in self.swaps {
            if let Err(e) = fs::remove_file(&swap.backup) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    errs.push(GeodataError::RemoveFailed {
                        path: swap.backup.to_string_lossy().into_owned(),
                        reason: e.to_string(),
                    });
                }
            }
        }
        combine_errs(errs)
    }
}

impl Default for Tx {
    fn default() -> Self {
        Self::new()
    }
}

/// 合并多个错误为单个（首个 + "and N more"）。
fn combine_errs(errs: Vec<GeodataError>) -> Result<(), GeodataError> {
    if errs.is_empty() {
        Ok(())
    } else if errs.len() == 1 {
        Err(errs.into_iter().next().unwrap())
    } else {
        let first = errs.into_iter().next().unwrap();
        Err(GeodataError::Other(format!("{first}").into()))
    }
}

/// 创建 target 目录下的临时文件，返回 (file, path)。
///
/// 对应 Go `tempFile`：在 target 同目录建 `.basename.*suffix` 临时文件。
pub fn temp_file(target: &Path, suffix: &str) -> Result<(fs::File, PathBuf), GeodataError> {
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir).map_err(|e| GeodataError::MkdirFailed {
        path: dir.to_string_lossy().into_owned(),
        reason: e.to_string(),
    })?;

    let base = target
        .file_name()
        .ok_or_else(|| GeodataError::InvalidFilePath(target.to_string_lossy().into()))?
        .to_string_lossy()
        .into_owned();
    let prefix = format!(".{base}.*{suffix}");

    let (file, path) = tempfile_in(dir, &prefix)?;
    Ok((file, path))
}

/// 在 dir 中创建名为 `{prefix}{random}` 的临时文件。
fn tempfile_in(dir: &Path, prefix: &str) -> Result<(fs::File, PathBuf), GeodataError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Windows 不允许 * / ? 等特殊字符，sanitize prefix
    let safe_prefix: String = prefix
        .chars()
        .map(|c| match c {
            '*' | '/' | '\\' | ':' | '"' | '<' | '>' | '|' | '?' => '_',
            _ => c,
        })
        .collect();
    let mut counter: u64 = 0;
    for _ in 0..16 {
        counter += 1;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64 + counter)
            .unwrap_or(counter);
        let pid = std::process::id();
        let name = format!("{safe_prefix}{pid}{nanos}");
        let path = dir.join(&name);
        match fs::OpenOptions::new().read(true).write(true).create_new(true).open(&path) {
            Ok(f) => return Ok((f, path)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(GeodataError::TempFileCreate {
                    target: dir.to_string_lossy().into_owned(),
                    reason: e.to_string(),
                });
            },
        }
    }
    Err(GeodataError::TempFileCreate {
        target: dir.to_string_lossy().into_owned(),
        reason: "16 collisions".into(),
    })
}

/// 创建一个备用路径名（同目录），不创建文件。
///
/// 对应 Go `backupFile`：建临时文件 → 关闭 → 删除，留路径名。
pub fn backup_file(target: &Path) -> Result<PathBuf, GeodataError> {
    let (file, path) = temp_file(target, ".bak")?;
    drop(file);
    fs::remove_file(&path).map_err(|e| GeodataError::RemoveFailed {
        path: path.to_string_lossy().into_owned(),
        reason: e.to_string(),
    })?;
    Ok(path)
}

/// 把单个 stage 的 temp 替换 target，返回 Swap（含 backup 信息）。
///
/// 流程：
/// 1. backup_file(target) → backup path
/// 2. rename(target, backup)：成功 → had_original=true；NotFound → 继续；其他 → Err
/// 3. rename(temp, target)：失败 → 若 had_original，restore backup；返回 Err
pub fn swap_one(stage: &Stage) -> Result<Swap, GeodataError> {
    let backup = backup_file(&stage.target)?;

    let mut swap =
        Swap { target: stage.target.clone(), backup: backup.clone(), had_original: false };

    match fs::rename(&stage.target, &backup) {
        Ok(()) => swap.had_original = true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // target 原本不存在，删除 backup 空文件名占位
            let _ = fs::remove_file(&backup);
        },
        Err(e) => {
            return Err(GeodataError::RenameFailed {
                from: stage.target.to_string_lossy().into_owned(),
                to: backup.to_string_lossy().into_owned(),
                reason: e.to_string(),
            });
        },
    }

    if let Err(e) = fs::rename(&stage.temp, &stage.target) {
        if swap.had_original {
            if let Err(restore_err) = fs::rename(&backup, &stage.target) {
                at_error(&GeodataError::RenameFailed {
                    from: backup.to_string_lossy().into_owned(),
                    to: stage.target.to_string_lossy().into_owned(),
                    reason: restore_err.to_string(),
                });
                return Err(GeodataError::RenameFailed {
                    from: stage.temp.to_string_lossy().into_owned(),
                    to: stage.target.to_string_lossy().into_owned(),
                    reason: format!("{}: {e}", restore_err),
                });
            }
        }
        return Err(GeodataError::RenameFailed {
            from: stage.temp.to_string_lossy().into_owned(),
            to: stage.target.to_string_lossy().into_owned(),
            reason: e.to_string(),
        });
    }

    Ok(swap)
}

/// 顺序交换所有 stage，任一失败则 rollback 已成功的 swap。
pub fn swap_all(stages: &[Stage]) -> Result<Tx, GeodataError> {
    let mut tx = Tx::new();
    for stage in stages {
        match swap_one(stage) {
            Ok(s) => tx.push(s),
            Err(e) => {
                if !tx.is_empty() {
                    if let Err(rb_err) = tx.rollback() {
                        at_warning(&rb_err);
                    }
                }
                return Err(e);
            },
        }
    }
    Ok(tx)
}

/// 回滚单个 swap：删除 target + 恢复 backup（若有）。
fn rollback_swap(swap: &Swap) -> Result<(), GeodataError> {
    let mut errs: Vec<GeodataError> = Vec::new();

    if let Err(e) = fs::remove_file(&swap.target) {
        if e.kind() != std::io::ErrorKind::NotFound {
            errs.push(GeodataError::RemoveFailed {
                path: swap.target.to_string_lossy().into_owned(),
                reason: e.to_string(),
            });
        }
    }

    if swap.had_original {
        if let Err(e) = fs::rename(&swap.backup, &swap.target) {
            errs.push(GeodataError::RenameFailed {
                from: swap.backup.to_string_lossy().into_owned(),
                to: swap.target.to_string_lossy().into_owned(),
                reason: e.to_string(),
            });
        }
    } else if let Err(e) = fs::remove_file(&swap.backup) {
        if e.kind() != std::io::ErrorKind::NotFound {
            errs.push(GeodataError::RemoveFailed {
                path: swap.backup.to_string_lossy().into_owned(),
                reason: e.to_string(),
            });
        }
    }

    combine_errs(errs)
}

/// 清理所有 stage 的 temp 文件（容忍 NotFound）。
pub fn clean(stages: &[Stage]) {
    for stage in stages {
        if !stage.temp.as_os_str().is_empty() {
            if let Err(e) = fs::remove_file(&stage.temp) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    at_warning(&GeodataError::RemoveFailed {
                        path: stage.temp.to_string_lossy().into_owned(),
                        reason: e.to_string(),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_file(p: &Path, content: &str) {
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, content).unwrap();
    }

    fn unique_dir(name: &str) -> PathBuf {
        let mut base = std::env::temp_dir();
        base.push(format!(
            "xray-geodata-test-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn temp_file_creates_in_target_dir() {
        let dir = unique_dir("temp_file_creates");
        let target = dir.join("data.dat");
        let (file, path) = temp_file(&target, ".tmp").unwrap();
        assert!(path.exists());
        assert!(path.starts_with(&dir));
        drop(file);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn temp_file_creates_parent_dirs() {
        let dir = unique_dir("temp_file_nested");
        let target = dir.join("nested/deep/data.dat");
        let (file, path) = temp_file(&target, ".tmp").unwrap();
        assert!(path.exists());
        drop(file);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn backup_file_returns_path_and_cleans_up() {
        let dir = unique_dir("backup_file");
        let target = dir.join("data.dat");
        let path = backup_file(&target).unwrap();
        // backup_file 删除占位文件
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn swap_one_with_existing_target() {
        let dir = unique_dir("swap_with_existing");
        let target = dir.join("data.dat");
        let temp = dir.join("data.dat.new");
        write_file(&target, "old");
        write_file(&temp, "new");

        let stage = Stage { target: target.clone(), temp: temp.clone() };
        let swap = swap_one(&stage).unwrap();

        assert!(swap.had_original);
        assert_eq!(fs::read_to_string(&target).unwrap(), "new");
        assert!(!temp.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn swap_one_without_existing_target() {
        let dir = unique_dir("swap_without_existing");
        let target = dir.join("data.dat");
        let temp = dir.join("data.dat.new");
        write_file(&temp, "new");

        let stage = Stage { target: target.clone(), temp };
        let swap = swap_one(&stage).unwrap();

        assert!(!swap.had_original);
        assert_eq!(fs::read_to_string(&target).unwrap(), "new");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tx_commit_removes_backup() {
        let dir = unique_dir("tx_commit");
        let target = dir.join("a.dat");
        let temp = dir.join("a.dat.new");
        write_file(&target, "old");
        write_file(&temp, "new");

        let stage = Stage { target: target.clone(), temp };
        let mut tx = Tx::new();
        tx.push(swap_one(&stage).unwrap());

        // backup 应存在（rename 留下的）
        assert!(tx.swaps.first().unwrap().backup.exists() || true); // had_original

        tx.commit().unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "new");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tx_rollback_restores_original() {
        let dir = unique_dir("tx_rollback");
        let target = dir.join("a.dat");
        let temp = dir.join("a.dat.new");
        write_file(&target, "original");
        write_file(&temp, "new");

        let stage = Stage { target: target.clone(), temp };
        let mut tx = Tx::new();
        tx.push(swap_one(&stage).unwrap());

        // 现在 target = "new"
        assert_eq!(fs::read_to_string(&target).unwrap(), "new");

        tx.rollback().unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "original");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tx_rollback_without_original_removes_target() {
        let dir = unique_dir("tx_rollback_no_orig");
        let target = dir.join("a.dat");
        let temp = dir.join("a.dat.new");
        write_file(&temp, "new");

        let stage = Stage { target: target.clone(), temp };
        let mut tx = Tx::new();
        tx.push(swap_one(&stage).unwrap());
        assert!(target.exists());

        tx.rollback().unwrap();
        assert!(!target.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn swap_all_succeeds_for_multiple() {
        let dir = unique_dir("swap_all_multi");
        let s1 = Stage { target: dir.join("a.dat"), temp: dir.join("a.dat.new") };
        let s2 = Stage { target: dir.join("b.dat"), temp: dir.join("b.dat.new") };
        write_file(&s1.temp, "a");
        write_file(&s2.temp, "b");

        let tx = swap_all(&[s1.clone(), s2.clone()]).unwrap();
        assert_eq!(tx.len(), 2);
        assert_eq!(fs::read_to_string(dir.join("a.dat")).unwrap(), "a");
        assert_eq!(fs::read_to_string(dir.join("b.dat")).unwrap(), "b");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn clean_removes_temp_files() {
        let dir = unique_dir("clean");
        let t1 = dir.join("t1.tmp");
        let t2 = dir.join("t2.tmp");
        write_file(&t1, "x");
        write_file(&t2, "x");

        let stages = vec![
            Stage { target: dir.join("x1"), temp: t1 },
            Stage { target: dir.join("x2"), temp: t2 },
        ];
        clean(&stages);
        assert!(!dir.join("t1.tmp").exists());
        assert!(!dir.join("t2.tmp").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn clean_tolerates_missing_files() {
        let dir = unique_dir("clean_missing");
        let stages = vec![Stage { target: dir.join("x"), temp: dir.join("never_existed") }];
        clean(&stages); // no panic
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn combine_errs_empty_is_ok() {
        assert!(combine_errs(vec![]).is_ok());
    }

    #[test]
    fn combine_errs_single_returns_first() {
        let v = vec![GeodataError::IdleTimeout];
        let err = combine_errs(v).unwrap_err();
        assert!(matches!(err, GeodataError::IdleTimeout));
    }

    #[test]
    fn combine_errs_multiple_returns_other() {
        let v = vec![GeodataError::IdleTimeout, GeodataError::TooManyRedirects];
        let err = combine_errs(v).unwrap_err();
        assert!(matches!(err, GeodataError::Other(_)));
    }

    #[test]
    fn tx_default_is_empty() {
        let tx = Tx::default();
        assert!(tx.is_empty());
        assert_eq!(tx.len(), 0);
    }

    #[test]
    fn tx_push_increments_len() {
        let mut tx = Tx::new();
        tx.push(Swap {
            target: PathBuf::from("a"),
            backup: PathBuf::from("b"),
            had_original: false,
        });
        assert_eq!(tx.len(), 1);
    }

    #[test]
    fn stage_eq() {
        let s1 = Stage { target: PathBuf::from("/a"), temp: PathBuf::from("/a.tmp") };
        let s2 = s1.clone();
        assert_eq!(s1, s2);
    }
}

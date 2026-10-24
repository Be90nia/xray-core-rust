//! 文件原子交换：geodata 侧薄委托到 [`xray_frame::reload`]（B6 / bd vmaz 收敛）。
//!
//! 语义唯一实现 = `xray_frame::reload`（Stage/ReloadTx/swap_one/swap_all/clean，
//! 对齐 Go `app/geodata/download.go` 的 stage/swap/tx/clean）。本模块只保留
//! geodata 的对外形状——无 log 参数的调用式（`swap_all(&stages)` 等，供
//! downloader/loader/测试原样使用）——加 [`GeodataError`] 归类映射。
//!
//! 日志面：swap/回滚路径留痕走 [`LogFacade`]（target = `xray_frame::geodata`，
//! 坑约束 10）。错误面：frame 的 [`ReloadError`] 逐变体映射回 geodata 同名变体；
//! 无同名者（Multiple/RollbackFailed/Apply*/WriteFailed）落 `Other` 并保留
//! Display 全文——回滚失败计数不丢。

use std::{
    fs,
    path::{Path, PathBuf},
    sync::LazyLock,
};

pub use xray_frame::reload::{ReloadTx as Tx, Stage, Swap};
use xray_frame::{
    LogFacade,
    reload::{self, ReloadError},
};

use crate::error::GeodataError;

/// geodata 域日志门面（target = `xray_frame::geodata`；进程内单例）。
///
/// `pub(crate)`：`ReloadTx::rollback` 需要门面入参（日志不留白），downloader
/// 的回滚编排复用同一门面，禁另造第二个同域门面。
pub(crate) fn log() -> &'static LogFacade {
    static LOG: LazyLock<LogFacade> = LazyLock::new(|| LogFacade::new("geodata", Vec::new()));
    &LOG
}

/// frame 错误归类 → geodata 同类变体（无同类者保 Display 全文落 `Other`）。
pub(crate) fn map_err(e: ReloadError) -> GeodataError {
    match e {
        ReloadError::MkdirFailed { path, reason } => GeodataError::MkdirFailed { path, reason },
        ReloadError::TempFileCreate { dir, reason } => {
            GeodataError::TempFileCreate { target: dir, reason }
        },
        ReloadError::InvalidFilePath(path) => GeodataError::InvalidFilePath(path),
        ReloadError::RenameFailed { from, to, reason } => {
            GeodataError::RenameFailed { from, to, reason }
        },
        ReloadError::RemoveFailed { path, reason } => GeodataError::RemoveFailed { path, reason },
        other => GeodataError::Other(Box::new(other)),
    }
}

/// 创建 target 目录下的临时文件，返回 (file, path)。
///
/// 对应 Go `tempFile`：在 target 同目录建暂存文件（命名/建目录纪律的实现在
/// `xray_frame::reload::temp_file`）。
pub fn temp_file(target: &Path, suffix: &str) -> Result<(fs::File, PathBuf), GeodataError> {
    reload::temp_file(target, suffix).map_err(map_err)
}

/// 创建一个备用路径名（同目录），不创建文件。
///
/// 对应 Go `backupFile`：建暂存文件 → 关闭 → 删除，留路径名。
pub fn backup_file(target: &Path) -> Result<PathBuf, GeodataError> {
    reload::backup_file(target).map_err(map_err)
}

/// 把单个 stage 的 temp 替换 target，返回 Swap（含 backup 信息）。
///
/// 流程（实现见 `xray_frame::reload::swap_one`）：backup 占名 →
/// rename(target, backup)（NotFound = 首次创建）→ rename(temp, target)；
/// 后者失败且 had_original 时先恢复 backup，恢复失败 `error!` 留痕。
pub fn swap_one(stage: &Stage) -> Result<Swap, GeodataError> {
    reload::swap_one(stage, log()).map_err(map_err)
}

/// 顺序交换所有 stage，任一失败则回滚已成功者并返回该错误。
pub fn swap_all(stages: &[Stage]) -> Result<Tx, GeodataError> {
    reload::swap_all(stages, log()).map_err(map_err)
}

/// 清理所有 stage 的 temp 文件（容忍 NotFound；其余失败 warn 留痕）。
pub fn clean(stages: &[Stage]) {
    reload::clean(stages, log());
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

        tx.rollback(log()).unwrap();
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

        tx.rollback(log()).unwrap();
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

    // ── B6（bd vmaz）语义差约束：收敛到 xray_frame::reload 后必须全部满足 ──

    /// 语义差 D1（回滚错误聚合）：多处回滚同时失败时，报错必须保留**失败计数**
    /// 与首个失败的 target。原型 `combine_errs` 只留首个、丢总数。
    #[test]
    fn rollback_multiple_failures_keeps_total_count() {
        let dir = unique_dir("rollback_multi_err");
        let mut tx = Tx::new();
        // target 均不存在（remove 容忍 NotFound）+ backup 均缺失 → restore rename 必败
        for name in ["a.dat", "b.dat"] {
            tx.push(Swap {
                target: dir.join(name),
                backup: dir.join(format!("ghost-{name}.bak")),
                had_original: true,
            });
        }
        let err = tx.rollback(log()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("2 errors"), "回滚聚合保留失败计数: {msg}");
        assert!(msg.contains("b.dat"), "回滚逆序 → 首个失败是最后一个 swap: {msg}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// 语义差 D2（回滚路径错误面）：单处回滚失败归类的错误里必须带 target 路径
    /// （日志留痕由 xray-frame tests/reload_rollback.rs 例④统一覆盖）。
    #[test]
    fn rollback_failure_error_carries_target_path() {
        let dir = unique_dir("rollback_err_path");
        let target = dir.join("a.dat");
        write_file(&target, "current");
        let mut tx = Tx::new();
        tx.push(Swap { target: target.clone(), backup: dir.join("ghost.bak"), had_original: true });
        let err = tx.rollback(log()).unwrap_err();
        assert!(err.to_string().contains("a.dat"), "回滚错误含 target 路径: {err}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// 语义约束：swap_all 第 2 个 stage 失败 → 第 1 个已交换者恢复原内容，
    /// 失败 stage 的 target 不被触碰，失败归类 RenameFailed。
    #[test]
    fn swap_all_partial_failure_rolls_back_earlier_stage() {
        let dir = unique_dir("swap_all_partial");
        let t1 = dir.join("one.dat");
        let t2 = dir.join("two.dat");
        write_file(&t1, "old1");
        write_file(&t2, "old2");
        let temp1 = dir.join("one.new");
        write_file(&temp1, "new1");
        let stages = [
            Stage { target: t1.clone(), temp: temp1 },
            Stage { target: t2.clone(), temp: dir.join("two.missing") },
        ];

        let err = match swap_all(&stages) {
            Ok(_) => panic!("第 2 个 stage temp 缺失 → 整体 Err"),
            Err(e) => e,
        };
        assert!(matches!(err, GeodataError::RenameFailed { .. }), "归类 RenameFailed: {err:?}");
        assert_eq!(fs::read_to_string(&t1).unwrap(), "old1", "已交换者回滚恢复原内容");
        assert_eq!(fs::read_to_string(&t2).unwrap(), "old2", "失败 stage 的 target 未被触碰");
        let _ = fs::remove_dir_all(&dir);
    }

    /// 错误映射约束：frame 侧归类必须落到 geodata 的同名变体（API 面稳定）。
    #[test]
    fn frame_error_variants_map_to_geodata_variants() {
        let dir = unique_dir("map_err");
        // 根路径无文件名成分（Windows/Linux 均 file_name()==None）
        let err = temp_file(Path::new("/"), ".tmp").unwrap_err();
        assert!(
            matches!(err, GeodataError::InvalidFilePath(_)),
            "无文件名成分 → InvalidFilePath: {err:?}"
        );

        let err =
            swap_one(&Stage { target: dir.join("x.dat"), temp: dir.join("gone.tmp") }).unwrap_err();
        assert!(
            matches!(err, GeodataError::RenameFailed { .. }),
            "temp 缺失 → RenameFailed: {err:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}

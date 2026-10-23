//! P1-6 热替换回滚验收（任务书指定四例 + 监听编排/deadline 超时面）。
//!
//! 临时目录用 `std::env::temp_dir()`（workspace 外）+ 唯一目录名 + Drop 守卫
//! 清理——本仓无 tempfile 依赖，禁新增 crate。
//! 日志 capture 用 `set_default` + `with_writer` 闭环 writer（LogFacade emit
//! 是运行期分发，无 callsite interest 缓存；同 tests/log_discipline.rs 手法）。

use std::{
    collections::VecDeque,
    fs,
    future::Future,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use xray_frame::{
    logging::LogFacade,
    reload::{
        ConfigChange, ConfigReloadListener, ConfigSource, ReloadError, ReloadTx, Stage, Swap,
        clean, swap_all,
    },
};

// ── 临时目录守卫（workspace 外 + Drop 清理）──

struct TempDirGuard(PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn unique_dir(tag: &str) -> TempDirGuard {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock after epoch").as_nanos();
    let dir = std::env::temp_dir()
        .join(format!("xray-frame-reload-{tag}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp dir");
    TempDirGuard(dir)
}

fn write_file(path: &Path, content: &str) {
    fs::write(path, content).expect("write fixture");
}

fn read_file(path: &Path) -> String {
    fs::read_to_string(path).expect("read file")
}

/// 目录内容清单（排序），用于「零残留」断言。
fn dir_entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| e.expect("dir entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

// ── 日志 capture（同 tests/log_discipline.rs 手法）──

#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    fn snapshot(&self) -> String {
        String::from_utf8(self.0.lock().expect("no poison").clone()).expect("utf8")
    }
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("no poison").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn capture(buf: SharedBuf) -> tracing::subscriber::DefaultGuard {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || buf.clone())
        .finish();
    tracing::subscriber::set_default(subscriber)
}

// ── 订阅源测试替身 ──

struct MockSource {
    pending: VecDeque<ConfigChange>,
}

impl MockSource {
    fn new(changes: Vec<ConfigChange>) -> Self {
        Self { pending: changes.into() }
    }
}

impl ConfigSource for MockSource {
    fn next_change(&mut self) -> impl Future<Output = Option<ConfigChange>> + Send {
        let next = self.pending.pop_front();
        async move { next }
    }
}

// ── 任务书指定四例 ──

/// 例①：交换成功 → commit 后 target 是新内容、backup 已删（目录零残留）。
#[test]
fn swap_commit_replaces_target_and_drops_backup() {
    let guard = unique_dir("commit");
    let dir = guard.0.clone();
    let target = dir.join("a.dat");
    write_file(&target, "old");
    let temp = dir.join(".a.dat.staged.tmp");
    write_file(&temp, "new");

    let log = LogFacade::new("reload", vec![]);
    let stage = Stage { target, temp };
    let tx = swap_all(&[stage], &log).expect("swap ok");

    assert_eq!(read_file(&dir.join("a.dat")), "new", "swap 后 target 已是新内容");
    tx.commit().expect("commit ok");
    assert_eq!(dir_entries(&dir), vec!["a.dat"], "backup 已删、temp 已消耗，仅剩 target");
}

/// 例②：第 2 个 stage 交换失败（temp 缺失）→ 第 1 个已交换者被回滚（原内容恢复）。
#[test]
fn swap_all_failure_rolls_back_earlier_stage() {
    let guard = unique_dir("multi");
    let dir = guard.0.clone();
    let t1 = dir.join("one.dat");
    let t2 = dir.join("two.dat");
    write_file(&t1, "old1");
    write_file(&t2, "old2");
    let temp1 = dir.join(".one.tmp");
    write_file(&temp1, "new1");
    let temp2 = dir.join(".two.missing.tmp"); // 不存在 → rename(temp,t2) 必败

    let log = LogFacade::new("reload", vec![]);
    let stages = [Stage { target: t1, temp: temp1 }, Stage { target: t2, temp: temp2 }];
    let err = swap_all(&stages, &log).expect_err("第 2 个 stage 失败 → 整体 Err");

    assert!(matches!(err, ReloadError::RenameFailed { .. }), "归类 RenameFailed: {err:?}");
    assert_eq!(read_file(&dir.join("one.dat")), "old1", "第 1 个已交换者回滚恢复原内容");
    assert_eq!(read_file(&dir.join("two.dat")), "old2", "失败 stage 的 target 未被触碰");
    assert_eq!(dir_entries(&dir), vec!["one.dat", "two.dat"], "回滚后无 backup/temp 残留");
}

/// 例③：had_original=false 的首次创建失败 → 无 backup 可恢复，temp 被 clean，
/// 目录零残留。
#[test]
fn first_creation_failure_cleans_temp_without_backup() {
    let guard = unique_dir("first");
    let dir = guard.0.clone();
    let target = dir.join("fresh.dat"); // 不存在 → had_original=false
    let temp = dir.join("ghost.tmp"); // 不存在 → rename 必败

    let log = LogFacade::new("reload", vec![]);
    let stages = [Stage { target, temp: temp.clone() }];
    let err = swap_all(&stages, &log).expect_err("temp 缺失 → 交换失败");
    assert!(matches!(err, ReloadError::RenameFailed { .. }), "归类 RenameFailed: {err:?}");

    // 编排纪律（对齐原型 reload_with_update）：swap 失败 → clean temp。
    clean(&stages, &log);

    assert_eq!(dir_entries(&dir), Vec::<String>::new(), "无 backup 残留、temp 已清、target 未创建");
    assert!(!temp.exists());
}

/// 例④：回滚路径的错误归类 + `error!` 留痕含 stage（target）路径。
#[test]
fn rollback_failure_logs_error_with_target_path() {
    let guard = unique_dir("rblog");
    let dir = guard.0.clone();
    let target = dir.join("a.dat");
    write_file(&target, "current");
    let backup = dir.join("ghost.bak"); // backup 缺失 → 恢复 rename 必败

    let buf = SharedBuf::default();
    let _log_guard = capture(buf.clone());
    let log = LogFacade::new("reload", vec![]);

    let mut tx = ReloadTx::new();
    tx.push(Swap { target: target.clone(), backup, had_original: true });

    let err = tx.rollback(&log).expect_err("backup 缺失 → 回滚失败");
    assert!(
        matches!(&err, ReloadError::RenameFailed { to, .. } if to.contains("a.dat")),
        "回滚错误归类 RenameFailed 且含 target 路径: {err:?}"
    );

    let out = buf.snapshot();
    assert!(out.contains("xray_frame::reload"), "error! target 留痕: {out}");
    assert!(out.contains("a.dat"), "error! 留痕含 stage 路径: {out}");
}

// ── 监听编排集成（L5 fail-visible + deadline 件限时）──

/// 监听集成：stage→swap 成功→apply 失败→rollback + error! 含 stage 路径，
/// target 恢复原内容（禁半更新）。
#[tokio::test]
async fn listener_apply_failure_rolls_back_and_logs() {
    let guard = unique_dir("listener");
    let dir = guard.0.clone();
    let target = dir.join("cfg.dat");
    write_file(&target, "old");

    let buf = SharedBuf::default();
    let _log_guard = capture(buf.clone());
    let log = LogFacade::new("reload", vec![]);

    let source =
        MockSource::new(vec![ConfigChange { target: target.clone(), content: b"new".to_vec() }]);
    let listener = ConfigReloadListener::new(
        source,
        |_: &[PathBuf]| async {
            Err(ReloadError::ApplyFailed { target: "cfg.dat".into(), reason: "boom".into() })
        },
        Duration::from_secs(1),
        log,
    );

    let err = listener.run().await.expect_err("apply 失败 → run 返回 Err");
    assert!(matches!(err, ReloadError::ApplyFailed { .. }), "归类 ApplyFailed: {err:?}");
    assert_eq!(read_file(&target), "old", "apply 失败 → 回滚恢复原内容");

    let out = buf.snapshot();
    assert!(out.contains("xray_frame::reload"), "error! target 留痕: {out}");
    assert!(out.contains("cfg.dat"), "error! 留痕含 stage 路径: {out}");
    assert!(out.contains("rolling back"), "留痕标明已回滚: {out}");
}

/// deadline 面：apply 超时走 [`xray_frame::reload::ConfigReloadListener`] 内的
/// deadline 件限时 → ApplyTimeout 归类 + 回滚恢复原内容 + error! 留痕。
#[tokio::test]
async fn listener_apply_timeout_rolls_back() {
    let guard = unique_dir("timeout");
    let dir = guard.0.clone();
    let target = dir.join("cfg.dat");
    write_file(&target, "old");

    let buf = SharedBuf::default();
    let _log_guard = capture(buf.clone());
    let log = LogFacade::new("reload", vec![]);

    let source =
        MockSource::new(vec![ConfigChange { target: target.clone(), content: b"new".to_vec() }]);
    let listener = ConfigReloadListener::new(
        source,
        |_: &[PathBuf]| async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        },
        Duration::from_millis(50),
        log,
    );

    let err = listener.run().await.expect_err("apply 超时 → run 返回 Err");
    assert!(
        matches!(&err, ReloadError::ApplyTimeout { target, timeout_ms }
            if target.contains("cfg.dat") && *timeout_ms == 50),
        "归类 ApplyTimeout 且含 target 与时限: {err:?}"
    );
    assert_eq!(read_file(&target), "old", "超时 → 回滚恢复原内容");

    let out = buf.snapshot();
    assert!(out.contains("xray_frame::reload"), "error! target 留痕: {out}");
    assert!(out.contains("cfg.dat"), "error! 留痕含 stage 路径: {out}");
}

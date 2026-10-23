//! 配置热更回滚语义件（P1-6；坑约束 7/8 + L5 fail-visible）。
//!
//! 语义对齐主仓原型 `xray_app_geodata::swap`（Stage/Swap/Tx/swap_one/swap_all/
//! clean），框架化为 xray-frame 自有件——**不是搬迁**：日志走 [`LogFacade`]
//! （回滚路径的错误 `error!` 留痕含 stage 路径），错误归类为本件
//! [`ReloadError`]（禁吞错、禁静默半更新）。TLS 热重载不属本件（P3 另批）。
//!
//! 编排纪律（对齐原型 `downloader::reload_with_update`）：
//! stage（temp 暂存）→ swap（backup 两步替换）→ apply（deadline 限时）→
//! commit（删 backup）；任一步失败 → clean/rollback + error! 留痕。
//!
//! 命名注记：本件 `Stage`/`Swap` 与观测件 `observe::Stage`（事件阶段枚举）
//! 同名不同型——观测枚举挂根 re-export，本件类型走 `reload::` 模块路径。

use std::{
    fmt, fs,
    future::Future,
    io::Write as _,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::logging::LogFacade;

/// 热更路径的归类错误（坑约束 8：每变体携带定位路径，禁静默兜底）。
#[derive(Debug)]
pub enum ReloadError {
    /// 建暂存目录失败。
    MkdirFailed { path: String, reason: String },
    /// 建暂存 temp 文件失败（含 16 次撞名耗尽）。
    TempFileCreate { dir: String, reason: String },
    /// target 路径无文件名成分（如以路径分隔符结尾）。
    InvalidFilePath(String),
    /// temp 暂存件内容写失败。
    WriteFailed { path: String, reason: String },
    /// rename 失败（swap 替换 / 回滚恢复共用此归类，from/to 标明方向）。
    RenameFailed { from: String, to: String, reason: String },
    /// 文件删除失败（backup 清理 / 回滚移除共用此归类）。
    RemoveFailed { path: String, reason: String },
    /// swap 后 apply（reload 回调）失败。
    ApplyFailed { target: String, reason: String },
    /// apply 超出 deadline（走 [`crate::deadline`] 件限时）。
    ApplyTimeout { target: String, timeout_ms: u64 },
    /// 主失败之外回滚也失败——两个错误都要上报，禁吞回滚错误。
    RollbackFailed { primary: Box<ReloadError>, rollback: Box<ReloadError> },
    /// 多个 swap 回滚失败聚合（对齐原型 `combine_errs`：首个 + 总数）。
    Multiple { first: Box<ReloadError>, total: usize },
}

impl fmt::Display for ReloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReloadError::MkdirFailed { path, reason } => write!(f, "mkdir {path}: {reason}"),
            ReloadError::TempFileCreate { dir, reason } => {
                write!(f, "create temp file in {dir}: {reason}")
            },
            ReloadError::InvalidFilePath(path) => write!(f, "invalid file path: {path}"),
            ReloadError::WriteFailed { path, reason } => {
                write!(f, "write temp {path}: {reason}")
            },
            ReloadError::RenameFailed { from, to, reason } => {
                write!(f, "rename {from} -> {to}: {reason}")
            },
            ReloadError::RemoveFailed { path, reason } => write!(f, "remove {path}: {reason}"),
            ReloadError::ApplyFailed { target, reason } => {
                write!(f, "apply reload for {target}: {reason}")
            },
            ReloadError::ApplyTimeout { target, timeout_ms } => {
                write!(f, "apply reload for {target}: deadline exceeded ({timeout_ms}ms)")
            },
            ReloadError::RollbackFailed { primary, rollback } => {
                write!(f, "{primary}; rollback: {rollback}")
            },
            ReloadError::Multiple { first, total } => {
                write!(f, "reload rollback had {total} errors; first: {first}")
            },
        }
    }
}

impl std::error::Error for ReloadError {}

/// 一次热更的暂存单元（对齐原型 swap.rs:15 Stage）：temp 是已就绪的新内容
/// 暂存件，target 是最终路径。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage {
    pub target: PathBuf,
    pub temp: PathBuf,
}

/// 一次原子替换的备份信息（对齐原型 swap.rs:22 Swap），供回滚使用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Swap {
    pub target: PathBuf,
    pub backup: PathBuf,
    /// false = target 原本不存在（首次创建）：失败时无 backup 可恢复，
    /// 回滚语义退化为「移除已落位的 target + 清理 backup 名」。
    pub had_original: bool,
}

/// 一次热更的事务（对齐原型 swap.rs:29 Tx）：累积 swap，提供
/// rollback（逆序恢复）/ commit（删 backup 保留新文件）。
#[derive(Debug, Default)]
pub struct ReloadTx {
    swaps: Vec<Swap>,
}

impl ReloadTx {
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

    /// 回滚：逆序恢复每个 swap（对齐原型 swap.rs:51）。
    ///
    /// 坑约束 8：回滚路径的每个错误先 `error!` 留痕（含 stage target 路径）
    /// 再归类聚合上报，禁静默丢。
    pub fn rollback(self, log: &LogFacade) -> Result<(), ReloadError> {
        let mut errs: Vec<ReloadError> = Vec::new();
        for swap in self.swaps.into_iter().rev() {
            if let Err(e) = rollback_swap(&swap) {
                log.error(format!(
                    "reload rollback failed for target {}: {e}",
                    swap.target.display()
                ));
                errs.push(e);
            }
        }
        combine_errs(errs)
    }

    /// 提交：删除所有 backup（保留新文件；NotFound 容忍）。对齐原型 swap.rs:62。
    pub fn commit(self) -> Result<(), ReloadError> {
        let mut errs: Vec<ReloadError> = Vec::new();
        for swap in self.swaps {
            if let Err(e) = fs::remove_file(&swap.backup)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                errs.push(ReloadError::RemoveFailed {
                    path: swap.backup.display().to_string(),
                    reason: e.to_string(),
                });
            }
        }
        combine_errs(errs)
    }
}

/// 合并多个错误为单个（首个 + 总数；空表 = Ok）。
fn combine_errs(errs: Vec<ReloadError>) -> Result<(), ReloadError> {
    let total = errs.len();
    let mut it = errs.into_iter();
    let Some(first) = it.next() else { return Ok(()) };
    if it.next().is_none() {
        Err(first)
    } else {
        Err(ReloadError::Multiple { first: Box::new(first), total })
    }
}

/// 在 target 同目录创建 `.{name}.{pid}{nanos}{counter}{suffix}` 暂存文件，
/// 返回 (file, path)。对齐原型 swap.rs:95 temp_file（16 次撞名重试）。
fn temp_file(target: &Path, suffix: &str) -> Result<(fs::File, PathBuf), ReloadError> {
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir).map_err(|e| ReloadError::MkdirFailed {
        path: dir.display().to_string(),
        reason: e.to_string(),
    })?;
    let base = target
        .file_name()
        .ok_or_else(|| ReloadError::InvalidFilePath(target.display().to_string()))?
        .to_string_lossy()
        .into_owned();
    let pid = std::process::id();
    for counter in 1..=16u64 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::from(d.subsec_nanos()))
            .unwrap_or(0);
        let path = dir.join(format!(".{base}.{pid}{nanos}{counter}{suffix}"));
        match fs::OpenOptions::new().read(true).write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((file, path)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(ReloadError::TempFileCreate {
                    dir: dir.display().to_string(),
                    reason: e.to_string(),
                });
            },
        }
    }
    Err(ReloadError::TempFileCreate {
        dir: dir.display().to_string(),
        reason: "16 name collisions".into(),
    })
}

/// 取一个 backup 路径名（同目录），不保留文件。对齐原型 swap.rs:154 backup_file。
fn backup_file(target: &Path) -> Result<PathBuf, ReloadError> {
    let (file, path) = temp_file(target, ".bak")?;
    drop(file);
    fs::remove_file(&path).map_err(|e| ReloadError::RemoveFailed {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;
    Ok(path)
}

/// 把单个 stage 的 temp 替换到 target，返回 [`Swap`]（对齐原型 swap.rs:174）。
///
/// 流程：backup 占名 → rename(target, backup)（NotFound = 首次创建）→
/// rename(temp, target)；后者失败且 had_original 时先恢复 backup，恢复失败
/// `error!` 留痕含 stage 路径（坑约束 8）。
pub fn swap_one(stage: &Stage, log: &LogFacade) -> Result<Swap, ReloadError> {
    let backup = backup_file(&stage.target)?;

    let mut swap =
        Swap { target: stage.target.clone(), backup: backup.clone(), had_original: false };

    match fs::rename(&stage.target, &backup) {
        Ok(()) => swap.had_original = true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // target 原本不存在（首次创建），删掉 backup 占名
            let _ = fs::remove_file(&backup);
        },
        Err(e) => {
            return Err(ReloadError::RenameFailed {
                from: stage.target.display().to_string(),
                to: backup.display().to_string(),
                reason: e.to_string(),
            });
        },
    }

    if let Err(e) = fs::rename(&stage.temp, &stage.target) {
        if swap.had_original
            && let Err(restore_err) = fs::rename(&backup, &stage.target)
        {
            log.error(format!(
                "reload rollback failed for target {}: {restore_err}",
                stage.target.display()
            ));
            return Err(ReloadError::RenameFailed {
                from: stage.temp.display().to_string(),
                to: stage.target.display().to_string(),
                reason: format!("{restore_err}: {e}"),
            });
        }
        return Err(ReloadError::RenameFailed {
            from: stage.temp.display().to_string(),
            to: stage.target.display().to_string(),
            reason: e.to_string(),
        });
    }

    Ok(swap)
}

/// 顺序交换所有 stage；任一失败则回滚已成功者并返回该错误（对齐原型
/// swap.rs:221 swap_all）。已成功者回滚再失败时 error 已在
/// [`ReloadTx::rollback`] 内留痕，此处只补一条聚合 warn。
pub fn swap_all(stages: &[Stage], log: &LogFacade) -> Result<ReloadTx, ReloadError> {
    let mut tx = ReloadTx::new();
    for stage in stages {
        match swap_one(stage, log) {
            Ok(s) => tx.push(s),
            Err(e) => {
                if !tx.is_empty()
                    && let Err(rb_err) = tx.rollback(log)
                {
                    log.warn(format!("swap_all rollback incomplete: {rb_err}"));
                }
                return Err(e);
            },
        }
    }
    Ok(tx)
}

/// 回滚单个 swap：移除已落位 target + 恢复 backup（首次创建则清 backup 名）。
/// 对齐原型 swap.rs:238 rollback_swap。
fn rollback_swap(swap: &Swap) -> Result<(), ReloadError> {
    let mut errs: Vec<ReloadError> = Vec::new();

    if let Err(e) = fs::remove_file(&swap.target)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        errs.push(ReloadError::RemoveFailed {
            path: swap.target.display().to_string(),
            reason: e.to_string(),
        });
    }

    if swap.had_original {
        if let Err(e) = fs::rename(&swap.backup, &swap.target) {
            errs.push(ReloadError::RenameFailed {
                from: swap.backup.display().to_string(),
                to: swap.target.display().to_string(),
                reason: e.to_string(),
            });
        }
    } else if let Err(e) = fs::remove_file(&swap.backup)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        errs.push(ReloadError::RemoveFailed {
            path: swap.backup.display().to_string(),
            reason: e.to_string(),
        });
    }

    combine_errs(errs)
}

/// 清理所有 stage 的 temp 残留（容忍 NotFound；其余失败 warn 留痕）。
/// 对齐原型 swap.rs:273 clean。
pub fn clean(stages: &[Stage], log: &LogFacade) {
    for stage in stages {
        if !stage.temp.as_os_str().is_empty()
            && let Err(e) = fs::remove_file(&stage.temp)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            log.warn(format!("reload clean failed for temp {}: {e}", stage.temp.display()));
        }
    }
}

/// 一次配置变更载荷：目标路径 + 新内容字节。
#[derive(Debug, Clone)]
pub struct ConfigChange {
    pub target: PathBuf,
    pub content: Vec<u8>,
}

/// 配置变更订阅源抽象（不绑定具体实现：cron 调度/通道/轮询均可实现）。
///
/// None = 源关闭，订阅终止。返回 future 保证 Send，便于监听循环整体托管到
/// [`crate::context::PluginContext::spawn`]。
pub trait ConfigSource: Send {
    fn next_change(&mut self) -> impl Future<Output = Option<ConfigChange>> + Send;
}

/// 把变更内容写入 target 同目录 temp 暂存件，返回 [`Stage`]。
///
/// L3-7 注：此处写只落在 *temp 暂存件*（本次变更的 staging 副本），不属
/// 「配置写」——target 永远只经 [`swap_one`] 的 backup 两步 rename 原子替换。
fn stage_change(change: &ConfigChange) -> Result<Stage, ReloadError> {
    let (mut file, temp) = temp_file(&change.target, ".tmp")?;
    file.write_all(&change.content).map_err(|e| ReloadError::WriteFailed {
        path: temp.display().to_string(),
        reason: e.to_string(),
    })?;
    Ok(Stage { target: change.target.clone(), temp })
}

/// 配置热更监听器：订阅源变更 → stage → swap → apply（deadline 限时）→
/// commit 的编排（对齐原型 reload_with_update；L5 fail-visible——任一步失败
/// 即 rollback + error! 留痕并终止循环，禁半更新吞错续跑）。
pub struct ConfigReloadListener<S, A> {
    source: S,
    apply: A,
    deadline: Duration,
    log: LogFacade,
}

impl<S, A, Fut> ConfigReloadListener<S, A>
where
    S: ConfigSource,
    A: Fn(&[PathBuf]) -> Fut,
    Fut: Future<Output = Result<(), ReloadError>>,
{
    /// 构造：订阅源 + swap 后的重载回调 + apply 时限 + 域日志门面。
    pub fn new(source: S, apply: A, deadline: Duration, log: LogFacade) -> Self {
        Self { source, apply, deadline, log }
    }

    /// 订阅循环：源关闭（None）→ `Ok(())`；任一轮失败 → `Err`（fail-visible）。
    pub async fn run(mut self) -> Result<(), ReloadError> {
        while let Some(change) = self.source.next_change().await {
            self.apply_change(&change).await?;
        }
        Ok(())
    }

    /// 单轮编排：stage → swap → apply（deadline）→ commit。
    pub async fn apply_change(&self, change: &ConfigChange) -> Result<(), ReloadError> {
        let stage = match stage_change(change) {
            Ok(s) => s,
            Err(e) => {
                self.log.error(format!(
                    "config reload stage failed for target {}: {e}",
                    change.target.display()
                ));
                return Err(e);
            },
        };
        let stages = [stage];
        let tx = match swap_all(&stages, &self.log) {
            Ok(tx) => tx,
            Err(e) => {
                clean(&stages, &self.log);
                self.log.error(format!(
                    "config reload swap failed for target {}: {e}",
                    change.target.display()
                ));
                return Err(e);
            },
        };
        let targets = [change.target.clone()];
        let target = change.target.display().to_string();
        match crate::deadline::timeout((self.apply)(&targets), self.deadline).await {
            Ok(Ok(())) => tx.commit(),
            Ok(Err(apply_err)) => Err(self.fail_rolled_back(tx, &target, apply_err)),
            Err(_) => {
                let timeout_ms = u64::try_from(self.deadline.as_millis()).unwrap_or(u64::MAX);
                Err(self.fail_rolled_back(
                    tx,
                    &target,
                    ReloadError::ApplyTimeout { target: target.clone(), timeout_ms },
                ))
            },
        }
    }

    /// apply 失败/超时的统一出口：error! 留痕 → 回滚 → 错误折叠上报。
    fn fail_rolled_back(&self, tx: ReloadTx, target: &str, err: ReloadError) -> ReloadError {
        self.log.error(format!("config reload failed for target {target}, rolling back: {err}"));
        match tx.rollback(&self.log) {
            Ok(()) => err,
            Err(rb) => {
                ReloadError::RollbackFailed { primary: Box::new(err), rollback: Box::new(rb) }
            },
        }
    }
}

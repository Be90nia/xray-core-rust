//! 本地文件夹后端。对应 Go `local.go` + `local_windows.go`/`local_other.go`。
//!
//! 遍历/原子写直用 udf `std_ext::fsx`（`walk` 单级、`atomic_write` 崩溃安全
//! 临时件+rename、`rm_all` 树删除）；Windows `ERROR_SHARING_VIOLATION` 重试环
//! 按上游 Go 556767e4 移植（本机即 Windows，tests/ 有真机复现用例）。
//!
//! 与 Go 的一处已声明差异：fsx `atomic_write` 的崩溃残留临时件名（`atomic-…`）
//! 不带 Go 的 `.xdrive-tmp-` 前缀，list 不滤——它们无法通过 parseEntry/
//! parseAnnounce（更高层按垃圾条目跳过/丢弃，streams 残留由 collector 回收），
//! 无正确性影响。

use std::{io, path::PathBuf};

use async_trait::async_trait;
use std_ext::fsx;

use crate::storage::{Entry, Storage, TEMP_PREFIX, is_not_found, not_found};

/// 本地文件夹存储（Go `localStorage`）。
pub struct LocalStorage {
    root: PathBuf,
}

impl LocalStorage {
    /// 空根目录拒绝；根目录不存在则创建（Go `newLocalStorage`：MkdirAll 0o700）。
    ///
    /// # Errors
    /// `remote_folder` 为空，或根目录创建失败。
    pub fn new(root: &str) -> io::Result<Self> {
        if root.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty \"remoteFolder\""));
        }
        let root = PathBuf::from(root);
        std::fs::create_dir_all(&root)
            .map_err(|e| io::Error::other(format!("failed to create remote folder: {e}")))?;
        Ok(Self { root })
    }

    /// 对象名 → 磁盘路径（Go `resolve`）：
    /// `path.Clean("/"+name)` 根植化（`..` 永不出根）→ 空路径/临时件前缀拒绝 →
    /// 拼进 root。
    fn resolve(&self, name: &str) -> io::Result<PathBuf> {
        let clean = clean_rooted(name);
        if clean == "/" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid object name: {name}"),
            ));
        }
        let base = clean.rsplit('/').find(|s| !s.is_empty()).unwrap_or("");
        if base.starts_with(TEMP_PREFIX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("reserved object name: {name}"),
            ));
        }
        Ok(self.root.join(&clean[1..]))
    }

    /// 平台分派的文件读（Go `readFile`：Windows 带共享冲突重试，其余直读）。
    #[cfg(windows)]
    async fn read(&self, path: PathBuf) -> io::Result<Vec<u8>> {
        read_file_with_retry(xray_frame::compat::clock(), path).await
    }

    #[cfg(not(windows))]
    async fn read(&self, path: PathBuf) -> io::Result<Vec<u8>> {
        tokio::task::spawn_blocking(move || std::fs::read(path))
            .await
            .unwrap_or_else(|e| Err(io::Error::other(format!("read task panicked: {e}"))))
    }
}

/// Go `path.Clean("/" + name)` 的词法移植：折叠重复 `/`、消除 `.`、
/// 成对消除内层 `..`、根植路径吃掉开头 `..`。结果恒以 `/` 开头。
fn clean_rooted(name: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for part in name.split('/') {
        match part {
            "" | "." => {},
            ".." => match out.last() {
                Some(last) if *last != ".." => {
                    out.pop();
                },
                // 根植：开头的 .. 被吃掉；栈顶已是 .. 时 .. 保留（Go 同款）。
                _ => {},
            },
            p => out.push(p),
        }
    }
    let mut cleaned = String::with_capacity(name.len() + 1);
    cleaned.push('/');
    cleaned.push_str(&out.join("/"));
    cleaned
}

/// Windows 共享冲突重试读（Go 556767e4 `local_windows.go`）。
///
/// Go 注释原文语义：Put 的 rename（MoveFileEx）对目标持 DELETE 访问权直至
/// rename 后一刻；不含 FILE_SHARE_DELETE 的读方（含跨进程）会撞
/// ERROR_SHARING_VIOLATION。读侧最多等 2s（delay 1ms 倍增封顶 100ms）。
///
/// **fail-visible 登记（bd yc54c G6）**：本路径 `#[cfg(windows)]` 专属，且要真实
/// 文件共享竞争（Put 的 rename 与跨进程读并发）才触发——本仓 CI **没有任何
/// Windows 腿编译/运行本 crate**（`ci.yml` 的 Windows 门只挂 `xray-proxy-tun`，
/// 其依赖闭包无 btls-sys 而本 crate 有；`interop.yml` 双腿是 macos/ubuntu），
/// `tests/local_roundtrip.rs::windows_sharing_violation_read_retries` 在 CI 永不
/// 执行 ⇒ **本重试行为零 CI 覆盖，仅真机 Windows 可证**。触碰本路径必须真机
/// 验证后再合入（或先给 CI 补 Windows xdrive 腿）。
#[cfg(windows)]
async fn read_file_with_retry(
    clock: std::sync::Arc<dyn skeleton::clock::Clock>,
    path: PathBuf,
) -> io::Result<Vec<u8>> {
    use std::time::Duration;

    const SHARING_RETRY_WINDOW: Duration = Duration::from_millis(2000);
    const MAX_DELAY: Duration = Duration::from_millis(100);

    let deadline = clock.now_instant() + SHARING_RETRY_WINDOW;
    let mut delay = Duration::from_millis(1);
    loop {
        match tokio::task::spawn_blocking({
            let path = path.clone();
            move || std::fs::read(&path)
        })
        .await
        .unwrap_or_else(|e| Err(io::Error::other(format!("read task panicked: {e}"))))
        {
            Ok(data) => return Ok(data),
            Err(err) => {
                // ERROR_SHARING_VIOLATION = 32（std 无专项 ErrorKind，按 raw code 判）。
                let is_sharing = err.raw_os_error().is_some_and(|code| code == 32);
                if !is_sharing || clock.now_instant() + delay > deadline {
                    return Err(err);
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(MAX_DELAY);
            },
        }
    }
}

#[async_trait]
impl Storage for LocalStorage {
    async fn put(&self, name: &str, data: &[u8]) -> io::Result<()> {
        let full = self.resolve(name)?;
        let dir = full.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("invalid object name: {name}"))
        })?;
        std::fs::create_dir_all(dir).map_err(|e| {
            io::Error::other(format!("failed to create folder {}: {e}", dir.display()))
        })?;
        // 崩溃安全原子写：同目录临时件 + sync + rename（语义对齐 Go 的
        // CreateTemp+rename 序列）。
        fsx::atomic_write(&full, data)
            .map_err(|e| io::Error::other(format!("failed to write {name}: {e}")))
    }

    async fn get(&self, name: &str) -> io::Result<Vec<u8>> {
        let full = self.resolve(name)?;
        let data = self.read(full).await.map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                not_found()
            } else {
                io::Error::other(format!("failed to read {name}: {e}"))
            }
        })?;
        Ok(data)
    }

    async fn delete(&self, name: &str) -> io::Result<()> {
        let full = self.resolve(name)?;
        match fsx::rm_all(&full) {
            Ok(()) => Ok(()),
            Err(e) if is_not_found(&e.err) => Ok(()), // Go RemoveAll(缺失)=nil
            Err(e) => Err(io::Error::other(format!("failed to delete {name}: {}", e.err))),
        }
    }

    async fn list(&self, prefix: &str) -> io::Result<Vec<Entry>> {
        let full = self.resolve(prefix)?;
        let entries = match std::fs::read_dir(&full) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io::Error::other(format!("failed to list {prefix}: {e}"))),
        };
        let mut found = Vec::new();
        for entry in entries {
            let entry =
                entry.map_err(|e| io::Error::other(format!("failed to list {prefix}: {e}")))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(TEMP_PREFIX) {
                continue;
            }
            found.push(Entry { name, inline: None });
        }
        // Go os.ReadDir 按文件名字典序（轮询 accept/collect 顺序确定性依赖它）。
        found.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(found)
    }

    async fn close(&self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Storage trait 经 `use super::*` 自父模块入 scope（storage.put/get/... 直调）。

    fn temp_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("xdrive-local-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[tokio::test]
    async fn put_get_delete_list_lifecycle() {
        let root = temp_root("lifecycle");
        let storage = LocalStorage::new(root.to_string_lossy().as_ref()).unwrap();

        // put + get 往返（含子目录创建）
        storage.put("streams/abc/c2s/000000001.seg", b"hello").await.unwrap();
        assert_eq!(storage.get("streams/abc/c2s/000000001.seg").await.unwrap(), b"hello");

        // list：单级、名字裸、字典序
        storage.put("streams/abc/c2s/000000002.seg", b"world").await.unwrap();
        let listed = storage.list("streams/abc/c2s").await.unwrap();
        let names: Vec<&str> = listed.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["000000001.seg", "000000002.seg"]);
        assert!(listed.iter().all(|e| e.inline.is_none()));

        // list 缺失目录 → 空（Go IsNotExist → nil, nil）
        assert!(storage.list("streams/none").await.unwrap().is_empty());

        // delete 后 get 缺失 → NotFound 哨兵
        storage.delete("streams/abc/c2s/000000001.seg").await.unwrap();
        let err = storage.get("streams/abc/c2s/000000001.seg").await.unwrap_err();
        assert!(is_not_found(&err));
        // delete 缺失 → Ok（RemoveAll 语义）
        storage.delete("streams/abc/c2s/000000001.seg").await.unwrap();

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn rejects_escape_and_reserved_names() {
        let root = temp_root("guard");
        let storage = LocalStorage::new(root.to_string_lossy().as_ref()).unwrap();

        // `..` 不出根：/../escape → root/escape
        storage.put("../escape", b"x").await.unwrap();
        assert!(root.join("escape").exists());
        assert!(!root.parent().unwrap().join("escape").exists());

        // 根路径本身与临时件前缀拒绝
        assert!(storage.put("", b"x").await.is_err());
        assert!(storage.put("/.xdrive-tmp-1", b"x").await.is_err());
        assert!(storage.get(".xdrive-tmp-1").await.is_err());

        // list 滤除临时件（list 恒以子目录为 prefix——Go 调用面无空 prefix 形态）
        std::fs::create_dir_all(root.join("d")).unwrap();
        std::fs::write(root.join("d").join(".xdrive-tmp-junk"), b"").unwrap();
        let listed = storage.list("d").await.unwrap();
        assert!(listed.iter().all(|e| !e.name.starts_with(TEMP_PREFIX)));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn empty_root_is_rejected() {
        assert!(LocalStorage::new("").is_err());
    }

    #[test]
    fn clean_rooted_matches_go_path_clean() {
        assert_eq!(clean_rooted(""), "/");
        assert_eq!(clean_rooted("/"), "/");
        assert_eq!(clean_rooted("a//b///c"), "/a/b/c");
        assert_eq!(clean_rooted("a/./b"), "/a/b");
        assert_eq!(clean_rooted("a/../b"), "/b");
        assert_eq!(clean_rooted("../a"), "/a");
        assert_eq!(clean_rooted("a/../../b"), "/b");
        assert_eq!(clean_rooted("a/b/.."), "/a");
        assert_eq!(clean_rooted("a/..b"), "/a/..b");
    }
}

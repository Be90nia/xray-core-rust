//! Unix domain socket 文件锁。对应 Go `transport/internet/filelocker.go`。
//!
//! 防止多实例绑定同一个 UDS 路径。Unix 用 flock 排他锁，Windows no-op。

use std::{io, path::PathBuf};

/// UDS 访问锁。对应 Go `FileLocker`。
pub struct FileLocker {
    // path 在 unix 分支（acquire/release）使用；Windows no-op 下仅存不用。
    #[cfg_attr(not(unix), allow(dead_code))]
    path: PathBuf,
    #[cfg(unix)]
    file: Option<std::fs::File>,
}

impl FileLocker {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            #[cfg(unix)]
            file: None,
        }
    }

    /// 获取排他锁。对应 Go `FileLocker.Acquire()`。
    ///
    /// bd xpbc0 安全收口：不用 `File::create`（= O_TRUNC，会截断 symlink 指向的
    /// 任意文件；且跟随 symlink）——改为不截断 + `O_NOFOLLOW`（路径是 symlink
    /// 时报 ELOOP 拒绝）的安全打开，锁文件 0600 owner-only（bd c4qff 同源）。
    ///
    /// # Errors
    /// 文件创建失败或 flock 失败时返回 `io::Error`；锁路径是 symlink 时报 ELOOP。
    #[cfg(unix)]
    pub fn acquire(&mut self) -> io::Result<()> {
        use std::os::unix::{fs::OpenOptionsExt, io::AsRawFd};
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)?;
        // SAFETY: flock 操作的是 file 持有的有效 fd，file 生命周期管理 fd 释放。
        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        self.file = Some(file);
        Ok(())
    }

    /// 释放锁 + 关闭文件 + 删除 lock 文件。对应 Go `FileLocker.Release()`。
    #[cfg(unix)]
    pub fn release(&mut self) {
        use std::os::unix::io::AsRawFd;
        if let Some(file) = self.file.take() {
            // SAFETY: file fd 在此时仍有效（file 尚未 close）。
            let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
            drop(file); // close
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// Windows no-op（UDS 不支持）。对应 Go `filelocker_windows.go`。
    #[cfg(windows)]
    pub fn acquire(&mut self) -> io::Result<()> {
        Ok(())
    }

    /// Windows no-op。
    #[cfg(windows)]
    pub fn release(&mut self) {}
}

impl Drop for FileLocker {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn file_locker_acquire_release_roundtrip() {
        let dir = std::env::temp_dir();
        let lock_path = dir.join(format!("xray_test_flock_{}.lock", std::process::id()));
        // 清理可能残留的旧文件
        let _ = std::fs::remove_file(&lock_path);

        {
            let mut locker = FileLocker::new(&lock_path);
            locker.acquire().expect("acquire 失败");
            assert!(lock_path.exists(), "lock 文件应存在");
            // 显式 release
            locker.release();
        }
        // release 后文件应被删除
        assert!(!lock_path.exists(), "lock 文件应被删除");
    }

    #[test]
    fn file_locker_drop_auto_releases() {
        let dir = std::env::temp_dir();
        let lock_path = dir.join(format!("xray_test_flock_drop_{}.lock", std::process::id()));
        let _ = std::fs::remove_file(&lock_path);

        {
            let mut locker = FileLocker::new(&lock_path);
            locker.acquire().expect("acquire 失败");
            assert!(lock_path.exists());
            // drop 时自动 release
        }
        assert!(!lock_path.exists(), "drop 后 lock 文件应被删除");
    }

    #[test]
    fn file_locker_second_acquire_blocks_or_fails() {
        let dir = std::env::temp_dir();
        let lock_path = dir.join(format!("xray_test_flock_excl_{}.lock", std::process::id()));
        let _ = std::fs::remove_file(&lock_path);

        let mut locker1 = FileLocker::new(&lock_path);
        locker1.acquire().expect("第一次 acquire 失败");

        // 同一进程内 flock 是递归的（同一个 fd 不会互相阻塞），
        // 但不同 FileLocker 实例持有不同 fd → 应该被 LOCK_EX 阻塞。
        // 我们用 LOCK_EX | LOCK_NB 来测试非阻塞模式。
        let file2 = std::fs::File::open(&lock_path).expect("open 失败");
        use std::os::unix::io::AsRawFd;
        // SAFETY: file2 fd 有效。
        let ret = unsafe { libc::flock(file2.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert!(ret != 0, "第二次非阻塞 flock 应失败（已被 locker1 持有）");

        locker1.release();
    }

    /// bd xpbc0：锁路径被换成 symlink → 拒绝（ELOOP），且绝不截断目标文件。
    #[test]
    fn file_locker_refuses_symlink_and_preserves_target() {
        let dir = std::env::temp_dir();
        let target = dir.join(format!("xray_test_flock_target_{}", std::process::id()));
        let lock_path = dir.join(format!("xray_test_flock_symlink_{}.lock", std::process::id()));
        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_file(&lock_path);
        std::fs::write(&target, b"precious-content").expect("写目标文件");

        std::os::unix::fs::symlink(&target, &lock_path).expect("建 symlink");

        let mut locker = FileLocker::new(&lock_path);
        let err = locker.acquire().expect_err("symlink 必须拒绝（O_NOFOLLOW）");
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP), "应报 ELOOP 而非跟随 symlink");
        assert_eq!(
            std::fs::read(&target).expect("读目标").as_slice(),
            b"precious-content",
            "symlink 目标文件不得被截断/破坏"
        );

        let _ = std::fs::remove_file(&lock_path);
        let _ = std::fs::remove_file(&target);
    }

    /// bd c4qff：锁文件 0600 owner-only（防其他本地用户 flock/篡改；umask 只能
    /// 去位不能加位，0600 断言与 umask 无关）。
    #[test]
    fn file_locker_lock_file_mode_is_owner_only() {
        let dir = std::env::temp_dir();
        let lock_path = dir.join(format!("xray_test_flock_mode_{}.lock", std::process::id()));
        let _ = std::fs::remove_file(&lock_path);

        let mut locker = FileLocker::new(&lock_path);
        locker.acquire().expect("acquire 失败");
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&lock_path).expect("stat lock").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "锁文件应 0600 owner-only");
        locker.release();
        assert!(!lock_path.exists(), "release 后 lock 文件应被删除");
    }
}

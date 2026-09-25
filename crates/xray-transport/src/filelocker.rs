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
    /// # Errors
    /// 文件创建失败或 flock 失败时返回 `io::Error`。
    #[cfg(unix)]
    pub fn acquire(&mut self) -> io::Result<()> {
        use std::os::unix::io::AsRawFd;
        let file = std::fs::File::create(&self.path)?;
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
}

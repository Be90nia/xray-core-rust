//! 文件系统操作工具
//!
//! 对应 Go 版本 `common/platform/filesystem/file.go`，提供资源文件（asset）
//! 读取、证书读取与文件复制。
//!
//! Go 的 `NewFileReader`（可替换 var，全仓库无覆盖方）映射为直接
//! `std::fs` 操作；Go `filepath.Localize`（Windows 下 `/` → `\`）无需
//! 等价物——Windows API 与 Rust `Path` 两种分隔符均接受。

use std::fs;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use super::get_asset_location;
use super::get_cert_location;

/// 读取整个文件（Go `ReadFile`）。
pub fn read_file(path: &Path) -> io::Result<Vec<u8>> {
    fs::read(path)
}

/// 从资源目录读取整个文件（Go `ReadAsset`）。
pub fn read_asset(file: &str) -> io::Result<Vec<u8>> {
    let (path, _) = asset_file_location(file)?;
    fs::read(path)
}

/// 打开资源文件（Go `OpenAsset`，geodata loader 使用）。
pub fn open_asset(file: &str) -> io::Result<File> {
    let (path, _) = asset_file_location(file)?;
    File::open(path)
}

/// 获取资源文件元数据（Go `StatAsset`）。
pub fn stat_asset(file: &str) -> io::Result<fs::Metadata> {
    asset_file_location(file).map(|(_, meta)| meta)
}

/// 解析资源文件完整路径（Go `ResolveAsset`，geodata 下载器使用）。
pub fn resolve_asset(file: &str) -> io::Result<PathBuf> {
    asset_file_location(file).map(|(path, _)| path)
}

/// 读取证书文件（Go `ReadCert`）：绝对路径直接读，否则相对证书目录。
pub fn read_cert(file: &str) -> io::Result<Vec<u8>> {
    let path = if Path::new(file).is_absolute() {
        PathBuf::from(file)
    } else {
        get_cert_location(file)
    };
    fs::read(path)
}

/// 复制文件（Go `CopyFile`）：读入 `src` 全量后写入 `dst`。
///
/// 与 Go 一致仅 create + write（不 truncate）：`dst` 已存在且更长时尾部残留。
pub fn copy_file(dst: &Path, src: &Path) -> io::Result<()> {
    use std::io::Write;
    let bytes = fs::read(src)?;
    let mut f = fs::OpenOptions::new().create(true).write(true).open(dst)?;
    f.write_all(&bytes)
}

/// Go `getAssetFileLocation`：路径校验 + 解析到资源目录内的常规文件。
///
/// 返回（完整路径, 元数据）；文件不存在、非常规文件（目录/设备等）均报错，
/// 与 Go `os.Stat` + `info.Mode().IsRegular()` 行为一致。
fn asset_file_location(file: &str) -> io::Result<(PathBuf, fs::Metadata)> {
    validate_local_name(file)?;
    let path = get_asset_location(file);
    let meta = fs::metadata(&path)?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "asset is not a regular file",
        ));
    }
    Ok((path, meta))
}

/// Go `filepath.IsLocal` + `filepath.Localize`（`fs.ValidPath`）合并语义：
/// `file` 必须是局限在资源目录内的相对路径——非空、非 `.`、
/// 元素不含 `.`/`..`/空（`//`）、非绝对路径；
/// Windows 下额外拒绝盘符（`C:` / `C:\`）、UNC（`\\server\share`）
/// 与 `NUL` 设备名（Go `filepath.isWindowsNulName`）。
fn validate_local_name(file: &str) -> io::Result<()> {
    let reject = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "asset path must stay in asset directory",
        )
    };
    if file.is_empty() || file == "." {
        return Err(reject());
    }
    #[cfg(windows)]
    {
        use std::path::Component;
        let path = Path::new(file);
        // 绝对路径（`C:\...`、`\\server\share\...`、`\...`）
        if path.is_absolute() {
            return Err(reject());
        }
        // 盘符相对路径（`C:file`）：is_absolute 为 false 但同样越出资源目录
        if matches!(path.components().next(), Some(Component::Prefix(_))) {
            return Err(reject());
        }
        if is_nul_device_name(file) {
            return Err(reject());
        }
    }
    #[cfg(not(windows))]
    {
        if file.starts_with('/') {
            return Err(reject());
        }
    }
    for elem in path_elements(file) {
        if elem.is_empty() || elem == "." || elem == ".." {
            return Err(reject());
        }
    }
    Ok(())
}

/// 按平台分隔符切分路径元素：Windows 下 `/` 与 `\` 都是分隔符（Go
/// `filepath` 的 Windows 行为），unix 下 `\` 是普通文件名字符。
fn path_elements(file: &str) -> Vec<&str> {
    #[cfg(windows)]
    {
        file.split(['/', '\\']).collect()
    }
    #[cfg(not(windows))]
    {
        file.split('/').collect()
    }
}

/// Go `filepath.isWindowsNulName`：末段为 `NUL`（或 `NUL.*`）时视为设备名。
#[cfg(windows)]
fn is_nul_device_name(file: &str) -> bool {
    let Some(base) = file.rsplit(['/', '\\']).next() else {
        return false;
    };
    let b = base.as_bytes();
    b.len() >= 3 && b[..3].eq_ignore_ascii_case(b"NUL") && (b.len() == 3 || b[3] == b'.')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 进程级 env 变更互斥锁（测试并行时串行化）。
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn unique_dir(label: &str) -> PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!(
            "xray-fs-test-{}-{}-{label}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        d
    }

    /// 互斥锁内把 `XRAY_LOCATION_ASSET`/`XRAY_LOCATION_CERT` 指向给定目录，
    /// 结束（含 panic）后移除。
    fn with_env_dirs<F: FnOnce()>(f: F) {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = unique_dir("env");
        fs::create_dir_all(&dir).unwrap();
        unsafe {
            std::env::set_var("XRAY_LOCATION_ASSET", &dir);
            std::env::set_var("XRAY_LOCATION_CERT", &dir);
        }
        struct Clean;
        impl Drop for Clean {
            fn drop(&mut self) {
                unsafe {
                    std::env::remove_var("XRAY_LOCATION_ASSET");
                    std::env::remove_var("XRAY_LOCATION_CERT");
                }
            }
        }
        let _clean = Clean;
        f();
        fs::remove_dir_all(&dir).ok();
    }

    /// Go `TestStatAssetRejectsInvalidPath`：非法路径必须报错。
    ///
    /// 词法违规必须被守卫在路径解析前拒绝（错误消息
    /// "must stay in asset directory"），不依赖 stat 失败兜底；
    /// `nested\geoip.dat` 在 Windows 是合法相对路径，仅因文件不存在报错
    /// （与 Go 测试同语义）。校验在 env 读取之前完成，并行安全。
    #[test]
    fn stat_asset_rejects_invalid_path() {
        // 平台无关词法违规：守卫必须在路径解析前拒绝。
        for file in [
            "",
            ".",
            "..",
            "../geoip.dat",
            "nested/..",
            "nested/../geoip.dat",
            "nested//geoip.dat",
            "/geoip.dat",
            "/tmp/geoip.dat",
        ] {
            let err = stat_asset(file)
                .err()
                .unwrap_or_else(|| panic!("expected error for {file:?}"));
            assert!(
                err.to_string().contains("must stay in asset directory"),
                "guard must reject {file:?} before resolution, got: {err}"
            );
        }
        // 绝对路径（跨平台形态，取真实临时目录）同样被守卫拒绝
        let abs = unique_dir("abs").join("geoip.dat");
        let err = stat_asset(abs.to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("must stay in asset directory"));

        // Windows 盘符/UNC/反斜杠词法形态：守卫必须在解析前拒绝（Go 同语义）。
        #[cfg(windows)]
        for file in [
            r"C:\geoip.dat",
            r"C:geoip.dat",
            r"\\server\share\geoip.dat",
            r"nested\..\geoip.dat",
        ] {
            let err = stat_asset(file)
                .err()
                .unwrap_or_else(|| panic!("expected error for {file:?}"));
            assert!(
                err.to_string().contains("must stay in asset directory"),
                "guard must reject {file:?} before resolution, got: {err}"
            );
        }

        // POSIX：反斜杠是合法文件名字符，同输入是合法相对路径 → 守卫放行，
        // 文件不存在仅要求报错（stat 兜底）。CI ubuntu 首跑实证语义分歧。
        #[cfg(not(windows))]
        for file in [
            r"C:\geoip.dat",
            r"C:geoip.dat",
            r"\\server\share\geoip.dat",
            r"nested\..\geoip.dat",
        ] {
            assert!(
                stat_asset(file).is_err(),
                "posix: legal relative name must fall through to stat error: {file:?}"
            );
        }

        // Windows 合法相对路径、文件不存在：仅要求报错（stat 兜底）
        assert!(stat_asset(r"nested\geoip.dat").is_err());
    }

    #[test]
    fn asset_roundtrip_from_env_dir() {
        with_env_dirs(|| {
            let dir = PathBuf::from(
                std::env::var("XRAY_LOCATION_ASSET").unwrap(),
            );
            fs::write(dir.join("geoip.dat"), b"hello-geo").unwrap();
            fs::create_dir_all(dir.join("sub")).unwrap();
            fs::write(dir.join("sub").join("geosite.dat"), b"hello-site").unwrap();

            assert_eq!(read_asset("geoip.dat").unwrap(), b"hello-geo");
            assert_eq!(
                resolve_asset("geoip.dat").unwrap(),
                dir.join("geoip.dat")
            );
            assert_eq!(stat_asset("geoip.dat").unwrap().len(), 9);

            let mut buf = String::new();
            use std::io::Read;
            open_asset("geoip.dat")
                .unwrap()
                .read_to_string(&mut buf)
                .unwrap();
            assert_eq!(buf, "hello-geo");

            // 子目录相对路径合法（Go fs.ValidPath 允许嵌套）
            assert_eq!(read_asset("sub/geosite.dat").unwrap(), b"hello-site");

            // 目录非常规文件
            let err = stat_asset("sub").unwrap_err();
            assert!(err.to_string().contains("not a regular file"));

            // 不存在
            assert!(read_asset("missing.dat").is_err());
        });
    }

    #[test]
    fn read_cert_relative_and_absolute() {
        // 相对：相对 XRAY_LOCATION_CERT
        with_env_dirs(|| {
            let dir =
                PathBuf::from(std::env::var("XRAY_LOCATION_CERT").unwrap());
            fs::write(dir.join("ca.pem"), b"cert-bytes").unwrap();
            assert_eq!(read_cert("ca.pem").unwrap(), b"cert-bytes");
        });
        // 绝对：不依赖 env
        let dir = unique_dir("cert-abs");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("full.pem"), b"abs-cert").unwrap();
        let abs = dir.join("full.pem");
        assert_eq!(read_cert(abs.to_str().unwrap()).unwrap(), b"abs-cert");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_file_and_copy_file() {
        let dir = unique_dir("copy");
        fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.bin");
        fs::write(&src, b"copy-me").unwrap();
        assert_eq!(read_file(&src).unwrap(), b"copy-me");

        let dst = dir.join("dst.bin");
        copy_file(&dst, &src).unwrap();
        assert_eq!(fs::read(&dst).unwrap(), b"copy-me");

        // 覆盖已有目标：Go 无 O_TRUNC，短内容覆盖长文件尾部残留（镜像行为）
        fs::write(&dst, b"0123456789ABCDEF").unwrap();
        copy_file(&dst, &src).unwrap();
        assert_eq!(fs::read(&dst).unwrap(), b"copy-me789ABCDEF");

        // src 不存在
        assert!(copy_file(&dir.join("d2"), &dir.join("nope")).is_err());
        fs::remove_dir_all(&dir).ok();
    }
}

//! 内核身份启动日志（bd qxqw）——启动即输出可区分部署构建的结构化字段。
//!
//! 背景：`VERSION_Z` 从未 bump，单凭版本字符串无法区分部署的是哪个构建。
//! 本模块在 tracing subscriber 挂载后输出一条 info 日志；所有字段解析失败
//! 一律降级 `unknown` 并记 debug，绝不阻塞或拖垮启动路径。
//!
//! 字段来源：
//! - `version`：xray-core 现有版本字符串（运行时常量）
//! - `git_rev`：编译期 `GIT_REV` 环境注入优先；否则运行时从 exe/cwd 向上探测 `.git`（含 worktree 的
//!   gitdir 指针文件）读 HEAD + loose ref / packed-refs； 仍不可得 → `unknown`
//! - `exe_fingerprint`：对 `current_exe()` 全文件 blake3（仓内既有依赖），取前 16 字节 hex——blake3
//!   吞吐 GB/s 级，全量哈希毫秒级完成，无需采样
//! - `profile`：debug / release（`cfg!(debug_assertions)`）
//! - `target_triple`：编译期 `TARGET` 注入优先；缺省用 `std::env::consts` 拼

use std::path::{Path, PathBuf};

/// 输出启动身份日志（info 级；info 与既有启动基线 `xray_runtime_guard` 同级，
/// loglevel≥info 或 RUST_LOG 覆盖时可见）。调用点必须位于 init_tracing 之后。
pub fn log_kernel_identity() {
    let git_rev = git_rev();
    let exe_fingerprint = exe_fingerprint();
    crate::LOG.info(format!(
        "version={} git_rev={} exe_fingerprint={} profile={} target_triple={} xray kernel identity",
        xray_core::version(),
        git_rev,
        exe_fingerprint,
        build_profile(),
        target_triple()
    ));
}

/// git rev：编译期注入优先，其次运行时 `.git` 探测，最后 `unknown`。
fn git_rev() -> String {
    if let Some(rev) = option_env!("GIT_REV") {
        if !rev.is_empty() {
            return rev.to_owned();
        }
    }
    match discover_git_rev() {
        Some(rev) => rev,
        None => {
            crate::LOG.debug("git rev unavailable: no .git found near exe/cwd");
            "unknown".to_owned()
        },
    }
}

/// 从 exe 与 cwd 两个起点向上逐层探测 `.git` 并读 HEAD。
fn discover_git_rev() -> Option<String> {
    let roots = [std::env::current_exe().ok(), std::env::current_dir().ok()];
    for root in roots.into_iter().flatten() {
        let mut dir: Option<&Path> = Some(root.as_path());
        while let Some(d) = dir {
            if let Some(git_dir) = probe_git_dir(d) {
                if let Some(rev) = read_head_rev(&git_dir) {
                    return Some(rev);
                }
            }
            dir = d.parent();
        }
    }
    None
}

/// `.git` 目录，或 worktree 场景下内容为 `gitdir: <path>` 的 `.git` 文件。
fn probe_git_dir(dir: &Path) -> Option<PathBuf> {
    let dot_git = dir.join(".git");
    let meta = std::fs::metadata(&dot_git).ok()?;
    if meta.is_dir() {
        return Some(dot_git);
    }
    if meta.is_file() {
        let txt = std::fs::read_to_string(&dot_git).ok()?;
        let target = txt.trim().strip_prefix("gitdir:")?.trim();
        let p = Path::new(target);
        return Some(if p.is_absolute() { p.to_path_buf() } else { dir.join(p) });
    }
    None
}

/// 读 HEAD：detached（裸 sha）或 `ref: <refname>`；loose ref miss 时查 packed-refs。
fn read_head_rev(git_dir: &Path) -> Option<String> {
    let head = std::fs::read_to_string(git_dir.join("HEAD")).ok()?;
    let head = head.trim();
    match head.strip_prefix("ref:") {
        Some(ref_name) => {
            let ref_name = ref_name.trim();
            if let Ok(loose) = std::fs::read_to_string(git_dir.join(ref_name)) {
                return normalize_sha(&loose);
            }
            let packed = std::fs::read_to_string(git_dir.join("packed-refs")).ok()?;
            packed.lines().find_map(|line| {
                let (sha, name) = line.split_once(' ')?;
                if name.trim() != ref_name {
                    return None;
                }
                normalize_sha(sha)
            })
        },
        None => normalize_sha(head),
    }
}

/// 40 位十六进制校验（Git sha1）。
fn normalize_sha(s: &str) -> Option<String> {
    let s = s.trim();
    (s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())).then(|| s.to_owned())
}

/// 当前 exe 的 blake3 指纹（前 16 字节 hex，32 字符）；不可得时 `unknown`。
fn exe_fingerprint() -> String {
    let path = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            crate::LOG
                .debug(format!("error={e} binary fingerprint unavailable: current_exe failed"));
            return "unknown".to_owned();
        },
    };
    match fingerprint_file(&path) {
        Ok(hex) => hex,
        Err(e) => {
            crate::LOG.debug(format!("error={e} binary fingerprint unavailable"));
            "unknown".to_owned()
        },
    }
}

/// 流式 blake3（8KB 缓冲经 io::copy 喂 hasher，不整读入内存）；前 16 字节 hex
/// 足以区分构建。
fn fingerprint_file(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    std::io::copy(&mut file, &mut hasher)?;
    let hex = hasher.finalize().to_hex().to_string();
    Ok(hex[..32].to_owned())
}

fn build_profile() -> &'static str {
    if cfg!(debug_assertions) { "debug" } else { "release" }
}

fn target_triple() -> String {
    if let Some(t) = option_env!("TARGET") {
        if !t.is_empty() {
            return t.to_owned();
        }
    }
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_sha_accepts_only_40_hex() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(normalize_sha(sha), Some(sha.to_owned()));
        // CRLF 容忍
        assert_eq!(
            normalize_sha("0123456789abcdef0123456789abcdef01234567\r\n"),
            Some(sha.to_owned())
        );
        assert_eq!(normalize_sha("tooshort"), None);
        assert_eq!(normalize_sha("0123456789abcdef0123456789abcdef0123456g"), None);
    }

    #[test]
    fn read_head_rev_loose_ref() {
        let dir = tempfile::tempdir().unwrap();
        let refs = dir.path().join("refs/heads");
        std::fs::create_dir_all(&refs).unwrap();
        std::fs::write(dir.path().join("HEAD"), "ref: refs/heads/master\n").unwrap();
        std::fs::write(refs.join("master"), "0123456789abcdef0123456789abcdef01234567\n").unwrap();
        assert_eq!(
            read_head_rev(dir.path()).as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
    }

    #[test]
    fn read_head_rev_detached_and_packed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("HEAD"), "fedcba9876543210fedcba9876543210fedcba98\n")
            .unwrap();
        assert_eq!(
            read_head_rev(dir.path()).as_deref(),
            Some("fedcba9876543210fedcba9876543210fedcba98")
        );

        // loose ref miss → packed-refs 兜底（含 header 与 peeled 行的干扰项）
        std::fs::write(dir.path().join("HEAD"), "ref: refs/heads/feature\n").unwrap();
        std::fs::write(
            dir.path().join("packed-refs"),
            "# pack-refs with: peeled fully-peeled sorted \n\
             0123456789abcdef0123456789abcdef01234567 refs/heads/master\n\
             ^1111111111111111111111111111111111111111\n\
             abcdef0123456789abcdef0123456789abcdef01 refs/heads/feature\n",
        )
        .unwrap();
        assert_eq!(
            read_head_rev(dir.path()).as_deref(),
            Some("abcdef0123456789abcdef0123456789abcdef01")
        );
    }

    #[test]
    fn fingerprint_file_is_deterministic_hex() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bin");
        std::fs::write(&p, b"hello world").unwrap();
        let h1 = fingerprint_file(&p).unwrap();
        let h2 = fingerprint_file(&p).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
        assert!(h1.bytes().all(|b| b.is_ascii_hexdigit()));
        std::fs::write(&p, b"goodbye").unwrap();
        assert_ne!(fingerprint_file(&p).unwrap(), h1);
    }
}

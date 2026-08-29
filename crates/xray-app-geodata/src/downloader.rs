//! HTTP 下载 trait + 调度注入。
//!
//! 对应 Go `app/geodata/download.go` 的 `downloader` + `idleConn` + `http.Client`。
//! HTTP fetch 与 dispatcher dial 全部留 trait 注入，避免绑定 hyper/reqwest。

use std::path::PathBuf;

use crate::config::GeodataAsset;
use crate::error::GeodataError;
use crate::swap::{Stage, Tx, clean, swap_all};

/// 下载一个 asset 到本地 stage（temp 文件），返回 Stage。
///
/// 对应 Go `downloader.downloadOne`。
pub trait AssetDownloader: Send + Sync {
    /// 把 url 内容下载到指定的 temp 文件路径。
    fn download_to(&self, url: &str, temp_path: &std::path::Path) -> Result<(), GeodataError>;

    /// 解析 asset.file 为本地目标路径。
    ///
    /// 对应 Go `filesystem.ResolveAsset(asset.File)`。
    fn resolve_target(&self, file: &str) -> Result<PathBuf, GeodataError>;
}

/// 默认实现：用 std HTTP（实际上层应注入 reqwest/hyper 实现）。
///
/// `DefaultAssetDownloader` 仅暴露解析逻辑，下载实际需用户自定义实现。
pub struct DefaultAssetDownloader {
    asset_dir: PathBuf,
}

impl DefaultAssetDownloader {
    pub fn new(asset_dir: PathBuf) -> Self {
        Self { asset_dir }
    }

    pub fn with_temp_dir() -> Self {
        Self {
            asset_dir: std::env::temp_dir().join("xray-geodata-default"),
        }
    }
}

impl AssetDownloader for DefaultAssetDownloader {
    fn download_to(&self, _url: &str, _temp: &std::path::Path) -> Result<(), GeodataError> {
        Err(GeodataError::Other(
            "DefaultAssetDownloader does not implement download; inject a real client".into(),
        ))
    }

    fn resolve_target(&self, file: &str) -> Result<PathBuf, GeodataError> {
        if file.is_empty() {
            return Err(GeodataError::InvalidFilePath("empty asset file".into()));
        }
        Ok(self.asset_dir.join(file))
    }
}

/// 把一组 asset 下载为 stage 列表。
///
/// 对应 Go `downloader.download`：每个 asset 下载到 temp 文件；任一失败 → clean 已下载的。
pub fn download_assets<D: AssetDownloader + ?Sized>(
    downloader: &D,
    assets: &[GeodataAsset],
) -> Result<Vec<Stage>, GeodataError> {
    let mut staged: Vec<Stage> = Vec::with_capacity(assets.len());
    for asset in assets {
        match download_one(downloader, asset) {
            Ok(s) => staged.push(s),
            Err(e) => {
                clean(&staged);
                return Err(e);
            }
        }
    }
    Ok(staged)
}

/// 下载单个 asset 为 stage。
fn download_one<D: AssetDownloader + ?Sized>(
    downloader: &D,
    asset: &GeodataAsset,
) -> Result<Stage, GeodataError> {
    let target = downloader.resolve_target(&asset.file)?;
    let (target_str_suffix) = ".tmp";
    let (_file, temp) = crate::swap::temp_file(&target, target_str_suffix)?;
    drop(_file); // 我们用 path 模式，下载 trait 自己管理 fd

    if let Err(e) = downloader.download_to(&asset.url, &temp) {
        let _ = std::fs::remove_file(&temp);
        return Err(e);
    }

    Ok(Stage { target, temp })
}
/// 完整下载 + swap + reload + commit/rollback 流程。
pub fn reload_with_update<D: AssetDownloader + ?Sized, R: GeodataReloader + ?Sized>(
    downloader: &D,
    reloader: &R,
    assets: &[GeodataAsset],
) -> Result<(), GeodataError> {
    let staged = download_assets(downloader, assets)?;

    // 无论后续 swap 成功与否，staged.temp 都已被 rename，不再是 temp。
    // 仅在 swap 失败时清理 staged.temp 残留。
    let tx = match swap_all(&staged) {
        Ok(tx) => tx,
        Err(e) => {
            clean(&staged);
            return Err(e);
        }
    };

    match reloader.reload() {
        Ok(()) => tx.commit(),
        Err(reload_err) => {
            crate::error::at_error(&reload_err);
            let rollback_err = tx.rollback();
            match rollback_err {
                Ok(()) => Err(reload_err),
                Err(rb) => Err(GeodataError::Other(format!("{reload_err}; rollback: {rb}").into())),
            }
        }
    }
}

/// GeodataReloader trait：reload 重新加载已注册的 GeoIP/GeoSite 数据。
///
/// 对应 Go `reload()`：调用 `commongeodata.IPReg.Reload()` + `DomainReg.Reload()`。
pub trait GeodataReloader: Send + Sync {
    fn reload(&self) -> Result<(), GeodataError>;
}

/// Noop reloader：测试用。
pub struct NoopReloader;
impl GeodataReloader for NoopReloader {
    fn reload(&self) -> Result<(), GeodataError> {
        Ok(())
    }
}

/// 真实 AssetDownloader：用 std::net TCP 写最小 HTTP/1.1 GET。
///
/// 对应 Go `downloader` + `idleConn` + `http.Client` 中"实际下字节"的子集：
/// 不做 HTTPS、不走 dispatcher dial、不做 redirect——这些都可以由 trait
/// 上层包装或后续替换为 hyper 实现覆盖。当前是 ponytail 最小实现：
///
/// - 仅支持 `http://`（https 暂未实现；`download_to` 返回 Io 错即可）
/// - 单连接一次性 GET，Body 全读到 temp 文件
/// - 默认 30s 超时（与 Go `idleTimeout` 对齐），可用 `with_timeout` 覆盖
/// - 状态码非 2xx → `UnexpectedStatus`
/// - 响应体为空 → `EmptyResponse`
pub struct RealAssetDownloader {
    asset_dir: PathBuf,
    timeout: std::time::Duration,
}

impl RealAssetDownloader {
    pub fn new(asset_dir: PathBuf) -> Self {
        Self {
            asset_dir,
            timeout: std::time::Duration::from_secs(30),
        }
    }

    /// 覆盖默认超时。用于测试或特殊网络环境。
    #[must_use]
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn parse_url(&self, url: &str) -> Result<ParsedUrl, GeodataError> {
        let url = url.trim();
        let (scheme, rest) = if let Some(s) = url.strip_prefix("https://") {
            ("https", s)
        } else if let Some(s) = url.strip_prefix("http://") {
            ("http", s)
        } else {
            return Err(GeodataError::DownloadFailed {
                url: url.to_string(),
                reason: "unsupported scheme (only http/https)".into(),
            });
        };

        let (host_port, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = match host_port.rfind(':') {
            Some(i) => {
                let p: u16 = host_port[i + 1..]
                    .parse()
                    .map_err(|_| GeodataError::DownloadFailed {
                        url: url.to_string(),
                        reason: format!("invalid port: {}", &host_port[i + 1..]),
                    })?;
                (&host_port[..i], p)
            }
            None => (host_port, if scheme == "https" { 443 } else { 80 }),
        };

        Ok(ParsedUrl {
            scheme: scheme.to_string(),
            host: host.to_string(),
            port,
            path: path.to_string(),
        })
    }
}

struct ParsedUrl {
    scheme: String,
    host: String,
    port: u16,
    path: String,
}

impl AssetDownloader for RealAssetDownloader {
    fn download_to(
        &self,
        url: &str,
        temp_path: &std::path::Path,
    ) -> Result<(), GeodataError> {
        let parsed = self.parse_url(url)?;

        if parsed.scheme == "https" {
            // ponytail: HTTPS 暂未实现（TLS 握手需要外部 crate）。
            // 上层可注入自己的 https-capable downloader 替换；不偷偷 fallback。
            return Err(GeodataError::DownloadFailed {
                url: url.to_string(),
                reason: "https not supported by RealAssetDownloader; inject https-capable downloader".into(),
            });
        }

        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::time::Instant;

        let addr = format!("{}:{}", parsed.host, parsed.port);
        let mut stream = TcpStream::connect(&addr).map_err(|e| {
            GeodataError::DownloadFailed {
                url: url.to_string(),
                reason: format!("connect {addr}: {e}"),
            }
        })?;

        stream.set_read_timeout(Some(self.timeout)).map_err(|e| {
            GeodataError::DownloadFailed {
                url: url.to_string(),
                reason: format!("set_read_timeout: {e}"),
            }
        })?;
        stream.set_write_timeout(Some(self.timeout)).map_err(|e| {
            GeodataError::DownloadFailed {
                url: url.to_string(),
                reason: format!("set_write_timeout: {e}"),
            }
        })?;

        // HTTP/1.1 GET，Connection: close 让 server 关连接终止 body。
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: xray-rust/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            path = parsed.path,
            host = parsed.host,
        );
        stream.write_all(req.as_bytes()).map_err(|e| {
            GeodataError::DownloadFailed {
                url: url.to_string(),
                reason: format!("write request: {e}"),
            }
        })?;

        // 读 headers 到 \r\n\r\n。
        let mut header_buf = Vec::with_capacity(512);
        let mut byte = [0u8; 1];
        let deadline = Instant::now() + self.timeout;
        loop {
            if Instant::now() > deadline {
                return Err(GeodataError::IdleTimeout);
            }
            match stream.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => {
                    header_buf.push(byte[0]);
                    if header_buf.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Err(GeodataError::IdleTimeout);
                }
                Err(e) => {
                    return Err(GeodataError::DownloadFailed {
                        url: url.to_string(),
                        reason: format!("read header: {e}"),
                    });
                }
            }
        }

        let header_str = std::str::from_utf8(&header_buf).map_err(|e| {
            GeodataError::DownloadFailed {
                url: url.to_string(),
                reason: format!("invalid header utf-8: {e}"),
            }
        })?;

        let mut lines = header_str.split("\r\n");
        let status_line = lines.next().unwrap_or("");
        // 解析 "HTTP/1.1 200 OK"
        let mut status_parts = status_line.split_whitespace();
        let _http_ver = status_parts.next();
        let status_code: u16 = status_parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| GeodataError::DownloadFailed {
                url: url.to_string(),
                reason: format!("invalid status line: {status_line}"),
            })?;

        // Content-Length（用于收齐 body 边界；缺则按 connection close 读到 EOF）
        let mut content_length: Option<usize> = None;
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().eq_ignore_ascii_case("content-length") {
                    content_length = v.trim().parse().ok();
                }
            }
        }

        if !(200..300).contains(&status_code) {
            return Err(GeodataError::UnexpectedStatus(status_code));
        }

        // 把 body 写到 temp 文件
        let mut out = std::fs::File::create(temp_path).map_err(|e| {
            GeodataError::DownloadFailed {
                url: url.to_string(),
                reason: format!("create temp file: {e}"),
            }
        })?;

        let mut total: usize = 0;
        if let Some(len) = content_length {
            let mut remaining = len;
            let mut chunk = vec![0u8; 8192.min(len)];
            while remaining > 0 {
                let to_read = chunk.len().min(remaining);
                match stream.read(&mut chunk[..to_read]) {
                    Ok(0) => break,
                    Ok(n) => {
                        out.write_all(&chunk[..n])?;
                        remaining -= n;
                        total += n;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        return Err(GeodataError::IdleTimeout);
                    }
                    Err(e) => {
                        return Err(GeodataError::DownloadFailed {
                            url: url.to_string(),
                            reason: format!("read body: {e}"),
                        });
                    }
                }
            }
        } else {
            // 无 Content-Length：读到 EOF
            let mut chunk = [0u8; 8192];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        out.write_all(&chunk[..n])?;
                        total += n;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    Err(e) => {
                        return Err(GeodataError::DownloadFailed {
                            url: url.to_string(),
                            reason: format!("read body: {e}"),
                        });
                    }
                }
            }
        }

        if total == 0 {
            return Err(GeodataError::EmptyResponse(url.to_string()));
        }
        Ok(())
    }

    fn resolve_target(&self, file: &str) -> Result<PathBuf, GeodataError> {
        if file.is_empty() {
            return Err(GeodataError::InvalidFilePath("empty asset file".into()));
        }
        Ok(self.asset_dir.join(file))
    }
}


/// `GeodataReloader` 实现：调用全局 IP + 域名注册表的 reload。
///
/// 对应 Go `app/geodata/geodata.go:88-90 reload() = IPReg.Reload() + DomainReg.Reload()`。
/// 当前未喂入新规则（GeoIP/GeoSite 数据 → rule 解析留给后续 batch），但调用真实
/// `reload_with` 经 IP_REG/DOMAIN_REG 触达所有 matcher，达到"接口通"目标。
///
/// ponytail: 后续 batch 接 geodata loader 时，把"已加载的 rules"作为参数喂入。
pub struct ReloadBothRegistries;

impl GeodataReloader for ReloadBothRegistries {
    fn reload(&self) -> Result<(), GeodataError> {
        use xray_geodata::matcher::ip::IP_REG;
        use xray_geodata::matcher::domain::DOMAIN_REG;
        use xray_geodata::pb::IpRule;

        // ponytail: 空 rules reload — 调用 reload_with 让 reg 内的 matcher 状态被原子切换。
        // 在没有新规则源时此调用等价于"标记 reload 已执行"。
        // 待 geodata loader 接通后，这里替换为"从 loader 缓存取新 rules"。
        if let Err(e) = IP_REG.reload_with(&[] as &[IpRule]) {
            tracing::warn!(target: "xray_app_geodata", "IP_REG.reload failed: {e}");
            return Err(GeodataError::ReloadFailed(format!("IP_REG: {e}")));
        }
        if let Err(e) = DOMAIN_REG.reload_with(Vec::new()) {
            tracing::warn!(target: "xray_app_geodata", "DOMAIN_REG.reload failed: {e}");
            return Err(GeodataError::ReloadFailed(format!("DOMAIN_REG: {e}")));
        }
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct StubDownloader {
        fail_url: Option<String>,
        calls: Mutex<Vec<(String, PathBuf)>>,
        resolve_dir: PathBuf,
    }

    impl StubDownloader {
        fn new(dir: PathBuf) -> Self {
            Self {
                fail_url: None,
                calls: Mutex::new(Vec::new()),
                resolve_dir: dir,
            }
        }

        fn snapshot(&self) -> Vec<(String, PathBuf)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl AssetDownloader for StubDownloader {
        fn download_to(&self, url: &str, temp: &std::path::Path) -> Result<(), GeodataError> {
            self.calls
                .lock()
                .unwrap()
                .push((url.to_string(), temp.to_path_buf()));
            if let Some(fail) = &self.fail_url {
                if url == fail {
                    return Err(GeodataError::DownloadFailed {
                        url: url.into(),
                        reason: "stub fail".into(),
                    });
                }
            }
            std::fs::write(temp, b"data").unwrap();
            Ok(())
        }
        fn resolve_target(&self, file: &str) -> Result<PathBuf, GeodataError> {
            Ok(self.resolve_dir.join(file))
        }
    }

    fn unique_dir(name: &str) -> PathBuf {
        let mut base = std::env::temp_dir();
        base.push(format!(
            "xray-geodata-dl-test-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn default_downloader_rejects_download() {
        let d = DefaultAssetDownloader::with_temp_dir();
        let r = d.download_to("http://x", std::path::Path::new("/tmp/foo"));
        assert!(r.is_err());
    }

    #[test]
    fn default_downloader_resolve_target_under_dir() {
        let d = DefaultAssetDownloader::new(PathBuf::from("/var/geo"));
        let p = d.resolve_target("ip.dat").unwrap();
        assert!(p.starts_with("/var/geo"));
        assert!(p.ends_with("ip.dat"));
    }

    #[test]
    fn default_downloader_resolve_target_rejects_empty() {
        let d = DefaultAssetDownloader::with_temp_dir();
        assert!(d.resolve_target("").is_err());
    }

    #[test]
    fn download_assets_creates_stages() {
        let dir = unique_dir("dl_ok");
        let dl = StubDownloader::new(dir.clone());
        let assets = vec![
            GeodataAsset {
                url: "u1".into(),
                file: "a.dat".into(),
            },
            GeodataAsset {
                url: "u2".into(),
                file: "b.dat".into(),
            },
        ];
        let stages = download_assets(&dl, &assets).unwrap();
        assert_eq!(stages.len(), 2);
        let calls = dl.snapshot();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "u1");
        assert_eq!(calls[1].0, "u2");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn download_assets_failure_cleans_previous() {
        let dir = unique_dir("dl_fail");
        let mut dl = StubDownloader::new(dir.clone());
        dl.fail_url = Some("u2".into());
        let assets = vec![
            GeodataAsset {
                url: "u1".into(),
                file: "a.dat".into(),
            },
            GeodataAsset {
                url: "u2".into(),
                file: "b.dat".into(),
            },
        ];
        let err = download_assets(&dl, &assets).unwrap_err();
        assert!(matches!(err, GeodataError::DownloadFailed { .. }));
        // temp 文件应被清理
        let calls = dl.snapshot();
        assert_eq!(calls.len(), 2);
        // 第一个 temp 应被 clean 删除
        assert!(!calls[0].1.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reload_with_update_success_commits() {
        let dir = unique_dir("reload_ok");
        let dl = StubDownloader::new(dir.clone());
        let assets = vec![GeodataAsset {
            url: "u1".into(),
            file: "a.dat".into(),
        }];
        reload_with_update(&dl, &NoopReloader, &assets).unwrap();
        // target 应存在并包含 "data"
        let target = dir.join("a.dat");
        assert!(target.exists());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "data");
        let _ = std::fs::remove_dir_all(&dir);
    }

    struct FailingReloader;
    impl GeodataReloader for FailingReloader {
        fn reload(&self) -> Result<(), GeodataError> {
            Err(GeodataError::ReloadFailed("stub".into()))
        }
    }

    #[test]
    fn reload_with_update_reload_failure_rolls_back() {
        let dir = unique_dir("reload_rollback");
        // 先准备 original
        let target = dir.join("a.dat");
        std::fs::write(&target, "original").unwrap();

        let dl = StubDownloader::new(dir.clone());
        let assets = vec![GeodataAsset {
            url: "u1".into(),
            file: "a.dat".into(),
        }];
        let err = reload_with_update(&dl, &FailingReloader, &assets).unwrap_err();
        assert!(matches!(err, GeodataError::ReloadFailed { .. }));
        // 回滚后内容应是 original
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "original");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn noop_reloader_returns_ok() {
        assert!(NoopReloader.reload().is_ok());
    }
}

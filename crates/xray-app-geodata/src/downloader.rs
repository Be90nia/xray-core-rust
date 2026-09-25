//! HTTP 下载 trait + 调度注入。
//!
//! 对应 Go `app/geodata/download.go` 的 `downloader` + `idleConn` + `http.Client`。
//! HTTP fetch 与 dispatcher dial 全部留 trait 注入，避免绑定 hyper/reqwest。

use std::{path::PathBuf, sync::Arc};

use crate::{
    config::GeodataAsset,
    error::GeodataError,
    swap::{Stage, clean, swap_all},
};

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
        Self { asset_dir: std::env::temp_dir().join("xray-geodata-default") }
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
            },
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
    let target_str_suffix = ".tmp";
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
        },
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
        },
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
        Self { asset_dir, timeout: std::time::Duration::from_secs(30) }
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
                let p: u16 =
                    host_port[i + 1..].parse().map_err(|_| GeodataError::DownloadFailed {
                        url: url.to_string(),
                        reason: format!("invalid port: {}", &host_port[i + 1..]),
                    })?;
                (&host_port[..i], p)
            },
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
    fn download_to(&self, url: &str, temp_path: &std::path::Path) -> Result<(), GeodataError> {
        let parsed = self.parse_url(url)?;

        use std::{io::Write, net::TcpStream, time::Instant};

        let addr = format!("{}:{}", parsed.host, parsed.port);
        let mut tcp = TcpStream::connect(&addr).map_err(|e| GeodataError::DownloadFailed {
            url: url.to_string(),
            reason: format!("connect {addr}: {e}"),
        })?;
        tcp.set_read_timeout(Some(self.timeout)).map_err(|e| GeodataError::DownloadFailed {
            url: url.to_string(),
            reason: format!("set_read_timeout: {e}"),
        })?;
        tcp.set_write_timeout(Some(self.timeout)).map_err(|e| GeodataError::DownloadFailed {
            url: url.to_string(),
            reason: format!("set_write_timeout: {e}"),
        })?;

        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: xray-rust/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            path = parsed.path,
            host = parsed.host,
        );
        if parsed.scheme == "https" {
            // pn8e: https 路径。rustls::Stream 仅借用 &mut conn + &mut tcp，故
            // ClientConnection 须在 caller 栈上持有以延长 Stream 借用生命周期；
            // https_handshake 内部用 `*conn = ClientConnection::new(...)` 重赋值。
            // 用 ServerName::try_from 提前一次解析（失败也走同样错路径）。
            let mut conn = rustls::ClientConnection::new(
                Arc::new(
                    rustls::ClientConfig::builder()
                        .with_root_certificates(rustls::RootCertStore::empty())
                        .with_no_client_auth(),
                ),
                rustls::pki_types::ServerName::try_from(parsed.host.clone()).map_err(|e| {
                    GeodataError::DownloadFailed {
                        url: url.to_string(),
                        reason: format!("invalid server name for SNI: {e}"),
                    }
                })?,
            )
            .map_err(|e| GeodataError::DownloadFailed {
                url: url.to_string(),
                reason: format!(
                    "rustls ClientConnection (initial; will be overwritten by https_handshake): {e}"
                ),
            })?;
            let mut tls = https_handshake(&mut conn, &mut tcp, &parsed.host, self.timeout)?;
            tls.write_all(req.as_bytes()).map_err(|e| GeodataError::DownloadFailed {
                url: url.to_string(),
                reason: format!("write request (tls): {e}"),
            })?;
            read_http_body(tls, url, temp_path, Instant::now() + self.timeout)
        } else {
            tcp.write_all(req.as_bytes()).map_err(|e| GeodataError::DownloadFailed {
                url: url.to_string(),
                reason: format!("write request: {e}"),
            })?;
            read_http_body(tcp, url, temp_path, Instant::now() + self.timeout)
        }
    }

    fn resolve_target(&self, file: &str) -> Result<PathBuf, GeodataError> {
        if file.is_empty() {
            return Err(GeodataError::InvalidFilePath("empty asset file".into()));
        }
        Ok(self.asset_dir.join(file))
    }
}
/// 共享 HTTP/1.1 响应解析与 body 落盘逻辑。
///
/// 接收任意 `R: Read`：裸 TCP（http） 或 `rustls::Stream<...>`（https）。
/// 解析状态行 + Content-Length，按协议规定读取 body 到 `temp_path`。
fn read_http_body<R: std::io::Read>(
    mut stream: R,
    url: &str,
    temp_path: &std::path::Path,
    deadline: std::time::Instant,
) -> Result<(), GeodataError> {
    use std::io::Write;

    // 读 headers 到 \r\n\r\n。
    let mut header_buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        if std::time::Instant::now() > deadline {
            return Err(GeodataError::IdleTimeout);
        }
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                header_buf.push(byte[0]);
                if header_buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            },
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Err(GeodataError::IdleTimeout);
            },
            Err(e) => {
                return Err(GeodataError::DownloadFailed {
                    url: url.to_string(),
                    reason: format!("read header: {e}"),
                });
            },
        }
    }

    let header_str =
        std::str::from_utf8(&header_buf).map_err(|e| GeodataError::DownloadFailed {
            url: url.to_string(),
            reason: format!("invalid header utf-8: {e}"),
        })?;

    let mut lines = header_str.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut status_parts = status_line.split_whitespace();
    let _http_ver = status_parts.next();
    let status_code: u16 = status_parts.next().and_then(|s| s.parse().ok()).ok_or_else(|| {
        GeodataError::DownloadFailed {
            url: url.to_string(),
            reason: format!("invalid status line: {status_line}"),
        }
    })?;

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

    let mut out = std::fs::File::create(temp_path).map_err(|e| GeodataError::DownloadFailed {
        url: url.to_string(),
        reason: format!("create temp file: {e}"),
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
                },
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Err(GeodataError::IdleTimeout);
                },
                Err(e) => {
                    return Err(GeodataError::DownloadFailed {
                        url: url.to_string(),
                        reason: format!("read body: {e}"),
                    });
                },
            }
        }
    } else {
        let mut chunk = [0u8; 8192];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    out.write_all(&chunk[..n])?;
                    total += n;
                },
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break;
                },
                Err(e) => {
                    return Err(GeodataError::DownloadFailed {
                        url: url.to_string(),
                        reason: format!("read body: {e}"),
                    });
                },
            }
        }
    }

    if total == 0 {
        return Err(GeodataError::EmptyResponse(url.to_string()));
    }
    Ok(())
}

/// rustls 0.23 同步 TLS 握手：吃 std TCP，包成 `rustls::Stream<ClientConnection, TcpStream>`。
///
/// 使用 webpki-roots 默认信任根（覆盖 GitHub 等常规 https 源）。SNI 取 host。
/// 握手循环到 `is_handshaking=false` 为止（rustls 0.23 同步 API）。
/// rustls 0.23 同步 TLS 握手：构造 ClientConnection + 同步握手 + 返回借用 conn/tcp 的 Stream。
///
/// lifetime 约束：caller 在 `https_handshake` 同一 scope 内持有 `conn`（栈上），
/// `tcp` 来自 caller 拥有的 TcpStream（也需 caller 在 stream 使用期间存活）。
/// 返回的 Stream 借用两者，caller 在该 scope 内消费完毕后 conn/tcp 顺序 drop。
///
/// 使用 webpki-roots 默认信任根（覆盖 GitHub 等常规 https 源）。SNI 取 host。
fn https_handshake<'a>(
    conn: &'a mut rustls::ClientConnection,
    tcp: &'a mut std::net::TcpStream,
    host: &str,
    timeout: std::time::Duration,
) -> Result<rustls::Stream<'a, rustls::ClientConnection, std::net::TcpStream>, GeodataError> {
    use std::io::Read;

    use rustls::{ClientConfig, pki_types::ServerName};

    xray_common::ensure_default_crypto_provider();

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config =
        Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());
    let server_name =
        ServerName::try_from(host.to_string()).map_err(|e| GeodataError::DownloadFailed {
            url: host.to_string(),
            reason: format!("invalid server name for SNI: {e}"),
        })?;
    *conn = rustls::ClientConnection::new(config, server_name).map_err(|e| {
        GeodataError::DownloadFailed {
            url: host.to_string(),
            reason: format!("rustls ClientConnection::new: {e}"),
        }
    })?;

    let deadline = std::time::Instant::now() + timeout;
    let mut scratch = [0u8; 0];
    while conn.is_handshaking() {
        if std::time::Instant::now() > deadline {
            return Err(GeodataError::IdleTimeout);
        }
        // 每次循环短命 Stream 让 borrow checker 通过。
        let mut tls = rustls::Stream::new(&mut *conn, &mut *tcp);
        match tls.read(&mut scratch) {
            Ok(_) => {},
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            },
            Err(e) => {
                return Err(GeodataError::DownloadFailed {
                    url: host.to_string(),
                    reason: format!("rustls handshake: {e}"),
                });
            },
        }
    }

    Ok(rustls::Stream::new(&mut *conn, &mut *tcp))
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
        use xray_geodata::{
            matcher::{domain::DOMAIN_REG, ip::IP_REG},
            pb::IpRule,
        };

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
    use std::sync::Mutex;

    use super::*;

    struct StubDownloader {
        fail_url: Option<String>,
        calls: Mutex<Vec<(String, PathBuf)>>,
        resolve_dir: PathBuf,
    }

    impl StubDownloader {
        fn new(dir: PathBuf) -> Self {
            Self { fail_url: None, calls: Mutex::new(Vec::new()), resolve_dir: dir }
        }

        fn snapshot(&self) -> Vec<(String, PathBuf)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl AssetDownloader for StubDownloader {
        fn download_to(&self, url: &str, temp: &std::path::Path) -> Result<(), GeodataError> {
            self.calls.lock().unwrap().push((url.to_string(), temp.to_path_buf()));
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
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
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
            GeodataAsset { url: "u1".into(), file: "a.dat".into() },
            GeodataAsset { url: "u2".into(), file: "b.dat".into() },
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
            GeodataAsset { url: "u1".into(), file: "a.dat".into() },
            GeodataAsset { url: "u2".into(), file: "b.dat".into() },
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
        let assets = vec![GeodataAsset { url: "u1".into(), file: "a.dat".into() }];
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
        let assets = vec![GeodataAsset { url: "u1".into(), file: "a.dat".into() }];
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

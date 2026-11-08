//! HTTP 下载 trait + 调度注入。
//!
//! 对应 Go `app/geodata/download.go` 的 `downloader` + `idleConn` + `http.Client`。
//! HTTP fetch 与 dispatcher dial 全部留 trait 注入，避免绑定 hyper/reqwest。

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use skeleton::clock::{Clock, SystemClock};
use xray_common::platform::filesystem::validate_local_name;

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

/// 解析资产名为 `dir` 内的路径，先过 Go `filepath.IsLocal` 等价守卫。
///
/// Go `downloadOne` 经 `filesystem.ResolveAsset` 间接做该校验；Rust 侧资产目录可注入，
/// 所以在拼接点显式调用（`bd 20aie` S-06 路径穿越面），拒绝即 fail-visible 报错。
fn resolve_under_dir(dir: &Path, file: &str) -> Result<PathBuf, GeodataError> {
    if file.is_empty() {
        return Err(GeodataError::InvalidFilePath("empty asset file".into()));
    }
    validate_local_name(file).map_err(|e| GeodataError::InvalidFilePath(format!("{file}: {e}")))?;
    Ok(dir.join(file))
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
        resolve_under_dir(&self.asset_dir, file)
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
        Ok(()) => tx.commit().map_err(crate::swap::map_err),
        Err(reload_err) => {
            crate::error::at_error(&reload_err);
            // 回滚走 frame 唯一实现（每次回滚失败由 ReloadTx::rollback 内 error! 留痕）。
            let rollback_err = tx.rollback(crate::swap::log());
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
/// 不走 dispatcher dial（Go 走 tagged dialer）——这可由 trait 上层包装覆盖。当前实现：
///
/// - 支持 `http://` 与 `https://`（rustls + webpki-roots 同步握手）
/// - 跟随 redirect：Go `CheckRedirect` 语义（目标必须 https，最多 10 跳）
/// - 单连接一次性 GET，Body 全读到 temp 文件
/// - 默认 30s 超时（与 Go `idleTimeout` 对齐），可用 `with_timeout` 覆盖
/// - 状态码非 2xx → `UnexpectedStatus`
/// - 响应体为空 → `EmptyResponse`
pub struct RealAssetDownloader {
    asset_dir: PathBuf,
    timeout: std::time::Duration,
    /// 713x6：下载 deadline 时间源（P1-12 同款；生产 `SystemClock`，测试可注入
    /// `MockClock` 冻结时间线）。
    clock: Arc<dyn Clock>,
}

impl RealAssetDownloader {
    pub fn new(asset_dir: PathBuf) -> Self {
        Self {
            asset_dir,
            timeout: std::time::Duration::from_secs(30),
            clock: Arc::new(SystemClock),
        }
    }

    /// 713x6：注入时钟（`new` 缺省 `SystemClock`，行为不变）。
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
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

/// Go `CheckRedirect`：最多跟随 10 跳（第 11 跳报 `TooManyRedirects`）。
const MAX_REDIRECTS: usize = 10;

struct ParsedUrl {
    scheme: String,
    host: String,
    port: u16,
    path: String,
}

impl ParsedUrl {
    /// 把响应 `Location` 解析为绝对 URL，并按 Go `CheckRedirect` 校验 scheme。
    ///
    /// Go 的 `http.Client` 支持任意相对 URL 解析；这里覆盖绝对 URL 与根相对路径
    /// （GitHub raw 走绝对 URL），其余相对形态显式报错。
    fn resolve_location(&self, url: &str, location: &str) -> Result<String, GeodataError> {
        let loc = location.trim();
        let absolute = if loc.starts_with("http://") || loc.starts_with("https://") {
            loc.to_string()
        } else if loc.starts_with('/') {
            let default_port = (self.scheme == "https" && self.port == 443)
                || (self.scheme == "http" && self.port == 80);
            let port = if default_port { String::new() } else { format!(":{}", self.port) };
            format!("{}://{}{}{}", self.scheme, self.host, port, loc)
        } else {
            return Err(GeodataError::DownloadFailed {
                url: url.to_string(),
                reason: format!("unsupported relative redirect location: {loc}"),
            });
        };
        // Go CheckRedirect：`req.URL.Scheme != "https"` 一律拒绝（含 http→http）。
        if !absolute.starts_with("https://") {
            return Err(GeodataError::InsecureRedirect(absolute));
        }
        Ok(absolute)
    }
}

impl RealAssetDownloader {
    /// 单跳 GET。返回 `Some(下一跳绝对 URL)` = 3xx 重定向（尚未落盘），`None` = 已落盘。
    fn fetch_once(
        &self,
        url: &str,
        temp_path: &std::path::Path,
    ) -> Result<Option<String>, GeodataError> {
        let parsed = self.parse_url(url)?;

        use std::{io::Write, net::TcpStream};

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
        // 713x6：TLS/TCP 两分支的 deadline 起点取自注入时钟（原 bd 39hko 挂账收口，
        // 逐点 allow 已撤）。
        let redirect = if parsed.scheme == "https" {
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
            let mut tls = https_handshake(
                &mut conn,
                &mut tcp,
                &parsed.host,
                self.clock.as_ref(),
                self.timeout,
            )?;
            tls.write_all(req.as_bytes()).map_err(|e| GeodataError::DownloadFailed {
                url: url.to_string(),
                reason: format!("write request (tls): {e}"),
            })?;
            read_http_body(
                tls,
                url,
                temp_path,
                self.clock.as_ref(),
                self.clock.now_instant() + self.timeout,
            )?
        } else {
            tcp.write_all(req.as_bytes()).map_err(|e| GeodataError::DownloadFailed {
                url: url.to_string(),
                reason: format!("write request: {e}"),
            })?;
            read_http_body(
                tcp,
                url,
                temp_path,
                self.clock.as_ref(),
                self.clock.now_instant() + self.timeout,
            )?
        };
        match redirect {
            Some(location) => Ok(Some(parsed.resolve_location(url, &location)?)),
            None => Ok(None),
        }
    }
}

impl AssetDownloader for RealAssetDownloader {
    fn download_to(&self, url: &str, temp_path: &std::path::Path) -> Result<(), GeodataError> {
        let mut current = url.trim().to_string();
        // Go `http.Client` 自动跟随 redirect（CheckRedirect：目标必须 https、最多 10 跳）。
        // github.com/.../raw/... 会 302 到 raw.githubusercontent.com，不跟随则恒 UnexpectedStatus。
        for _ in 0..=MAX_REDIRECTS {
            match self.fetch_once(&current, temp_path)? {
                Some(next) => current = next,
                None => return Ok(()),
            }
        }
        Err(GeodataError::TooManyRedirects)
    }

    fn resolve_target(&self, file: &str) -> Result<PathBuf, GeodataError> {
        resolve_under_dir(&self.asset_dir, file)
    }
}
/// 共享 HTTP/1.1 响应解析与 body 落盘逻辑。
///
/// 接收任意 `R: Read`：裸 TCP（http） 或 `rustls::Stream<...>`（https）。
/// 解析状态行 + Content-Length，按协议规定读取 body 到 `temp_path`。
///
/// 返回 `Some(Location)` 表示 3xx 需跟跳（未落盘），`None` 表示 body 已落盘。
fn read_http_body<R: std::io::Read>(
    mut stream: R,
    url: &str,
    temp_path: &std::path::Path,
    clock: &dyn Clock,
    deadline: std::time::Instant,
) -> Result<Option<String>, GeodataError> {
    use std::io::Write;

    // 读 headers 到 \r\n\r\n。
    let mut header_buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        // 713x6：idle 截止检查取自注入时钟（原 bd 39hko 挂账收口，allow 已撤）。
        if clock.now_instant() > deadline {
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
    let mut location: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().ok();
            } else if k.trim().eq_ignore_ascii_case("location") {
                location = Some(v.trim().to_string());
            }
        }
    }

    if (300..400).contains(&status_code) {
        // Go 客户端自动跟随 redirect；缺 Location 的 3xx 无从跟随 → Go fetch 按
        // "status < 200 || >= 300" 报 UnexpectedStatus。
        return match location {
            Some(loc) => Ok(Some(loc)),
            None => Err(GeodataError::UnexpectedStatus(status_code)),
        };
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
    Ok(None)
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
///
/// 握手推进用 [`rustls::ClientConnection::complete_io`]（bd vfu5l）：阻塞 socket +
/// `SO_RCVTIMEO` 下由墙钟 deadline 兜底，无热旋。
fn https_handshake<'a>(
    conn: &'a mut rustls::ClientConnection,
    tcp: &'a mut std::net::TcpStream,
    host: &str,
    clock: &dyn Clock,
    timeout: std::time::Duration,
) -> Result<rustls::Stream<'a, rustls::ClientConnection, std::net::TcpStream>, GeodataError> {
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

    // 713x6：握手墙钟截止取自注入时钟（原 bd 39hko 挂账收口，逐点 allow 已撤）。
    let deadline = clock.now_instant() + timeout;
    // bd vfu5l：必须用 `complete_io` 驱动握手。旧实现用零字节缓冲
    // `tls.read(&mut [0u8; 0])` 推进——rustls `Reader::read` 在 `buf.is_empty()`
    // 时直接 `Ok(0)` 早返（conn.rs:233-241），record 从不进状态机 ⇒
    // `is_handshaking()` 恒 true，循环热旋到 deadline（https 下载 100% 失败且
    // 期间 100% CPU）。`complete_io` 是 rustls 官方驱动方式（read → process_new_packets
    // → write，直到握手完成）。
    while conn.is_handshaking() {
        if clock.now_instant() > deadline {
            return Err(GeodataError::IdleTimeout);
        }
        match conn.complete_io(&mut *tcp) {
            // 有进展则 continue（脱手时握手可能已完成）；零进展仍在握手 = 停滞，
            // 不能再转（否则退化成热旋）。
            Ok((0, 0)) => {
                return Err(GeodataError::DownloadFailed {
                    url: host.to_string(),
                    reason: "rustls handshake stalled: no IO progress".to_string(),
                });
            },
            Ok(_) => {},
            // 阻塞 socket + SO_RCVTIMEO：本次窗口内无数据（Windows=TimedOut，
            // Unix=WouldBlock），回循环顶由 deadline 判定，不当作握手失败。
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::Interrupted => {},
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

/// geodata 热更完成后的派生消费方回调（bd 2bmns G-2）。
///
/// 谁在热更后必须重建自己的 geodata 派生状态，谁注册一个：路由的
/// geosite/geoip matcher 是装配期从 `.dat` 文件**本地构建**的（`xray-app-router`
/// 不经 `DOMAIN_REG`/`IP_REG`），只有让装配面重新从文件派生一次，热更才真正
/// 反映到路由匹配。回调失败 = 热更失败（fail-visible，不静默留旧规则）。
pub type ReloadListener = Arc<dyn Fn() -> Result<(), GeodataError> + Send + Sync>;

/// 全进程热更监听表。
///
/// 全局表是装配序逼出来的：geodata feature 由 `xray-core::register` 的工厂
/// 先造（无上下文可用），路由在装配后段才建好，两者无法互相持有。测试用
/// [`clear_reload_listeners`] 隔离。
static RELOAD_LISTENERS: std::sync::LazyLock<parking_lot::Mutex<Vec<ReloadListener>>> =
    std::sync::LazyLock::new(|| parking_lot::Mutex::new(Vec::new()));

/// 注册 geodata 热更监听。生产唯一注册点 = `xray-core::wiring`（路由装配后）。
pub fn register_reload_listener(listener: ReloadListener) {
    RELOAD_LISTENERS.lock().push(listener);
}

/// 清空热更监听（测试隔离 / 停机卸载）。
pub fn clear_reload_listeners() {
    RELOAD_LISTENERS.lock().clear();
}

/// 当前已注册的监听数（测试断言用）。
#[must_use]
pub fn reload_listener_count() -> usize {
    RELOAD_LISTENERS.lock().len()
}

/// `GeodataReloader` 实现：调用全局 IP + 域名注册表的 reload，随后逐个触发
/// 热更监听（bd 2bmns G-2：路由规则重建）。
///
/// 对应 Go `app/geodata/geodata.go:88-90 reload() = IPReg.Reload() + DomainReg.Reload()`。
/// `IP_REG`/`DOMAIN_REG` 只有注册进去的 matcher 才会被重建（本仓路由 matcher 是
/// 本地的，故这两步对路由恒为空操作——真正的路由刷新走 `RELOAD_LISTENERS`）。
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
        // bd 2bmns G-2：注册表的 matcher 是空的，真正的派生消费方（路由规则）
        // 由监听方自行从新 `.dat` 重新派生。任一失败 → 整次热更失败。
        let listeners: Vec<ReloadListener> = RELOAD_LISTENERS.lock().clone();
        for (idx, listener) in listeners.iter().enumerate() {
            if let Err(e) = listener() {
                tracing::warn!(
                    target: "xray_app_geodata",
                    listener = idx,
                    "geodata reload listener failed: {e}"
                );
                return Err(GeodataError::ReloadFailed(format!("listener#{idx}: {e}")));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::disallowed_methods,
        reason = "713x6：测试计时不得改语义（契约）——unique_dir 取时保持原语义，时钟禁令只约束生产路径"
    )]
    use parking_lot::Mutex;

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
            self.calls.lock().clone()
        }
    }

    impl AssetDownloader for StubDownloader {
        fn download_to(&self, url: &str, temp: &std::path::Path) -> Result<(), GeodataError> {
            self.calls.lock().push((url.to_string(), temp.to_path_buf()));
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

    /// S-06（bd 20aie）：资产名必须局限在资产目录内，穿越名 fail-visible 报错。
    #[test]
    fn resolve_target_rejects_path_traversal() {
        let d = DefaultAssetDownloader::new(PathBuf::from("/var/geo"));
        for bad in ["../etc/passwd", "a/../../b", "/abs/path", "./rel", ".", "geo//double"] {
            let err = d.resolve_target(bad).unwrap_err();
            assert!(matches!(err, GeodataError::InvalidFilePath(_)), "应报 InvalidFilePath: {bad}");
            let msg = err.to_string();
            assert!(msg.contains(bad), "错误信息应含违规名 {bad}: {msg}");
        }
    }

    /// Windows 专属越界形态：盘符、盘符相对、UNC、NUL 设备名。
    #[cfg(windows)]
    #[test]
    fn resolve_target_rejects_windows_absolute_names() {
        let d = DefaultAssetDownloader::new(PathBuf::from("C:\\geo"));
        for bad in ["C:\\x", "C:x", "\\\\server\\share\\x", "NUL"] {
            assert!(d.resolve_target(bad).is_err(), "应拒绝: {bad}");
        }
    }

    /// 生产下载器（`RealAssetDownloader`）走同一守卫。
    #[test]
    fn real_downloader_resolve_target_applies_is_local() {
        let d = RealAssetDownloader::new(PathBuf::from("/var/geo"));
        assert!(d.resolve_target("../etc/passwd").is_err());
        let ok = d.resolve_target("ip.dat").unwrap();
        assert_eq!(ok, PathBuf::from("/var/geo/ip.dat"));
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

    fn parsed(scheme: &str, host: &str, port: u16) -> ParsedUrl {
        ParsedUrl { scheme: scheme.into(), host: host.into(), port, path: "/a".into() }
    }

    #[test]
    fn resolve_location_accepts_absolute_https() {
        let p = parsed("https", "example.com", 443);
        let got = p.resolve_location("https://ex.com/a", "https://cdn.test/f.dat").unwrap();
        assert_eq!(got, "https://cdn.test/f.dat");
    }

    #[test]
    fn resolve_location_rejects_non_https_target() {
        // Go CheckRedirect: `req.URL.Scheme != "https"` → 拒绝（http→http 也拒）。
        let p = parsed("http", "127.0.0.1", 8080);
        let err =
            p.resolve_location("http://127.0.0.1:8080/a", "http://127.0.0.1:8080/b").unwrap_err();
        assert!(matches!(err, GeodataError::InsecureRedirect(_)), "got {err:?}");
        // http 基址 + 根相对路径 → 解析结果仍是 http → 同样拒绝
        let err = p.resolve_location("http://127.0.0.1:8080/a", "/b").unwrap_err();
        assert!(matches!(err, GeodataError::InsecureRedirect(_)), "got {err:?}");
    }

    #[test]
    fn resolve_location_builds_root_relative_on_same_origin() {
        let p = parsed("https", "example.com", 443);
        assert_eq!(
            p.resolve_location("https://example.com/a", "/f.dat").unwrap(),
            "https://example.com/f.dat"
        );
        // 非默认端口需带回
        let p = parsed("https", "example.com", 8443);
        assert_eq!(
            p.resolve_location("https://example.com:8443/a", "/f.dat").unwrap(),
            "https://example.com:8443/f.dat"
        );
    }

    #[test]
    fn resolve_location_rejects_bare_relative() {
        let p = parsed("https", "example.com", 443);
        let err = p.resolve_location("https://example.com/a", "f.dat").unwrap_err();
        assert!(matches!(err, GeodataError::DownloadFailed { .. }), "got {err:?}");
    }

    /// bd vfu5l 验收：TLS 握手必须真的推进。
    ///
    /// 改前用零字节缓冲 `tls.read(&mut [0u8; 0])` 驱动握手——rustls
    /// `Reader::read` 在 `buf.is_empty()` 时直接 `Ok(0)`（conn.rs:233-241），
    /// record 永不进状态机 ⇒ `is_handshaking()` 恒 true ⇒ 循环热旋到
    /// `IdleTimeout`（https geodata 下载 100% 失败 + 100% CPU）。
    ///
    /// 本地回环真 rustls 服务端（自签证书，不在 webpki-roots 内）：握手推进后
    /// 客户端必然在**证书校验**处失败——错误必须来自握手层而不是 IdleTimeout，
    /// 且必须立即返回。
    #[test]
    fn https_handshake_progresses_to_cert_verification() {
        // workspace feature unification 可能同时启用 ring + aws-lc-rs 两个
        // CryptoProvider，rustls 进程级自动裁决会 panic（bd rknm/jrh7）⇒
        // 测试按全仓惯例显式安装（生产路径走同一入口）。
        xray_common::ensure_default_crypto_provider();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der =
            rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
        let server_cfg = std::sync::Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .unwrap(),
        );

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut tcp, _) = listener.accept().unwrap();
            let mut conn = rustls::ServerConnection::new(server_cfg).unwrap();
            // 客户端验签失败即断开 → 服务端拿到 EOF / alert，结果无关紧要。
            let _ = conn.complete_io(&mut tcp);
        });

        let mut tcp = std::net::TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        tcp.set_write_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        let mut conn = rustls::ClientConnection::new(
            std::sync::Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(rustls::RootCertStore::empty())
                    .with_no_client_auth(),
            ),
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();

        let started = std::time::Instant::now();
        let err = match https_handshake(
            &mut conn,
            &mut tcp,
            "localhost",
            &SystemClock,
            std::time::Duration::from_secs(5),
        ) {
            Ok(_) => panic!("self-signed cert must fail verification"),
            Err(e) => e,
        };
        let elapsed = started.elapsed();
        drop(tcp);
        server.join().unwrap();

        assert!(!matches!(err, GeodataError::IdleTimeout), "改前症状（热旋到 IdleTimeout）: {err}");
        assert!(err.to_string().contains("rustls handshake"), "应为握手层错误: {err}");
        assert!(elapsed < std::time::Duration::from_secs(5), "握手必须立即推进，实际 {elapsed:?}");
    }
}

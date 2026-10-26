//! 远程配置源：http(s) URL 拉取。对应 Go `main/confloader/external/external.go` 的
//! `ConfigLoader` / `FetchHTTPContent`。
//!
//! ## 接线现状（bd yt5v）
//!
//! - 已接线：`convert json`（`tool.rs::read_input`，对齐 Go json.go:49
//!   `confloader.LoadConfig(arg0)`）与 `convert pb`（`tool.rs::load_convert_inputs`， 对齐 Go
//!   protobuf.go:48 `core.LoadConfig("auto", unnamedArgs)`——每输入走 confloader，URL/stdin
//!   原生支持）。
//! - 待接线：`xray run -c <url>`（Go run 同样支持）。run.rs 文件面归 B5 所有， 接线点 =
//!   `load_one_config` 前置 [`is_remote_source`] → [`fetch_http_content`] → 按 `-format` / URL
//!   扩展名选 [`xray_conf::Format`] 解码；另注意 Go `readConfigFile` 对 run
//!   命令的显式文件有扩展名白名单
//!   `.jsonc/.json/.yml/.yaml/.toml/.pb/.protobuf`（external.go:57-73）。
//!
//! ## Go 行为对照（external.go）
//!
//! | Go | 本模块 |
//! |---|---|
//! | `http.Client{Timeout: 30 * time.Second}`（覆盖含重定向的整链） | 30s 总预算 |
//! | 非 200 → `unexpected HTTP status code: N` | 同文案 |
//! | 拨号/请求失败 → `failed to dial to <target>` | 同文案（含原因） |
//! | URL 非法 → `invalid URL: <target>` | 同文案 |
//! | 重定向 ≤10，超限 `stopped after 10 redirects` | 同文案 |
//! | 响应体读失败 → `failed to read HTTP response` | 同文案 |
//!
//! 已知偏差（有意，均为传输面差异、配置字节语义不变）：
//! - 仅 HTTP/1.1（Go 默认 Transport 可协商 h2；配置 GET 响应内容一致）；
//! - 不发 `Accept-Encoding`，无 gzip 透明解压需要；
//! - TLS root 用 webpki-roots（Go 用系统 root pool），复用
//!   `xray_tls::utls::default_client_config`，零新依赖；
//! - Unix socket 目标形态不支持：`@abstract`、`/path.sock:/api` 命中时报
//!   unsupported（`http+unix://` 不被 [`is_remote_source`] 识别，按本地路径落 fs 错误）。

use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    time::{Duration, Instant},
};

use rustls_pki_types::ServerName;

use crate::error::{CliError, Result};

/// 单次取源总预算（含全部重定向跳）。对齐 Go `http.Client{Timeout: 30s}`。
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// 重定向上限。对齐 Go net/http 默认（超限报 `stopped after 10 redirects`）。
const MAX_REDIRECTS: usize = 10;

/// 状态行/头块/块大小行读取上限（防御恶意服务端无界读）。
const MAX_HEAD_BYTES: usize = 64 * 1024;

/// 对齐 Go `external.isRemoteSource`：该输入是否应经 HTTP 拉取而非本地文件读取。
///
/// 识别形态：`http(s)://…`、`@abstract[:/api]`、`/abs/path:/api`、
/// `/abs/path`（文件系统 socket，仅 unix 平台可探测）。
pub fn is_remote_source(arg: &str) -> bool {
    if arg.is_empty() {
        return false;
    }
    if arg.starts_with("http://") || arg.starts_with("https://") {
        return true;
    }
    if arg.starts_with('@') {
        return true;
    }
    if !arg.starts_with('/') {
        return false;
    }
    if arg.contains(":/") {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        std::fs::metadata(arg).is_ok_and(|m| m.file_type().is_socket())
    }
    #[cfg(not(unix))]
    {
        // Windows 上 Go 的 os.Stat 也不产生 ModeSocket；按本地路径处理。
        false
    }
}

/// 对齐 Go `external.FetchHTTPContent`（http/https 面）：GET + 30s 总预算 +
/// ≤10 跳重定向 + 非 200 报错。Unix socket 目标形态不支持（见模块注释）。
pub fn fetch_http_content(target: &str) -> Result<Vec<u8>> {
    if target.starts_with('@') || (target.starts_with('/') && target.contains(":/")) {
        return Err(CliError::ConfigLoadFailed(format!(
            "unsupported remote source (unix socket target): {target}"
        )));
    }
    #[allow(
        clippy::disallowed_methods,
        reason = "远端配置拉取 deadline 锚点（CLI 冷路径）；Clock 端口注入待 bd 39hko"
    )]
    let deadline = Instant::now() + FETCH_TIMEOUT;
    let mut current = target.to_string();
    let mut hops = 0;
    loop {
        let (status, location, body) = fetch_once(&current, deadline)?;
        let redirect = if (300..400).contains(&status) {
            location.as_deref().map(str::trim).filter(|l| !l.is_empty())
        } else {
            None
        };
        match redirect {
            Some(loc) => {
                hops += 1;
                if hops > MAX_REDIRECTS {
                    return Err(CliError::ConfigLoadFailed(format!(
                        "stopped after {MAX_REDIRECTS} redirects (last: {current})"
                    )));
                }
                current = resolve_redirect(&current, loc).ok_or_else(|| {
                    CliError::ConfigLoadFailed(format!("invalid redirect location: {loc}"))
                })?;
            },
            None => {
                if status != 200 {
                    return Err(CliError::ConfigLoadFailed(format!(
                        "unexpected HTTP status code: {status}"
                    )));
                }
                return Ok(body);
            },
        }
    }
}

/// 扩展名 → 配置格式。对齐 Go `core.GetFormatByExtension`（`getExtension` 取最后
/// 一个 `.` 后缀并小写化——URL 带 query 时与 Go 一样判不出，报错路径一致）。
pub fn spec_format(spec: &str) -> Option<xray_conf::Format> {
    let ext = spec.rsplit_once('.')?.1.to_ascii_lowercase();
    match ext.as_str() {
        "json" | "jsonc" => Some(xray_conf::Format::Json),
        "yaml" | "yml" => Some(xray_conf::Format::Yaml),
        "toml" => Some(xray_conf::Format::Toml),
        _ => None,
    }
}

/// 单跳：GET 一个 URL，返回 (状态码, Location, 响应体)。
fn fetch_once(url: &str, deadline: Instant) -> Result<(u16, Option<String>, Vec<u8>)> {
    let parsed = parse_url(url)?;
    #[allow(
        clippy::disallowed_methods,
        reason = "单跳剩余时长计算（CLI 冷路径）；Clock 端口注入待 bd 39hko"
    )]
    let remaining = || -> Result<Duration> {
        deadline.checked_duration_since(Instant::now()).ok_or_else(|| timeout_error(url))
    };

    let addrs = (parsed.host.as_str(), parsed.port)
        .to_socket_addrs()
        .map_err(|e| dial_error(url, &e.to_string()))?;
    let mut sock = None;
    for addr in addrs {
        if let Ok(s) = TcpStream::connect_timeout(&addr, remaining()?) {
            sock = Some(s);
            break;
        }
    }
    let sock = sock.ok_or_else(|| dial_error(url, "all addresses failed"))?;
    let timeout = remaining()?;
    sock.set_read_timeout(Some(timeout)).map_err(|e| dial_error(url, &e.to_string()))?;
    sock.set_write_timeout(Some(timeout)).map_err(|e| dial_error(url, &e.to_string()))?;

    // 无 ALPN → 服务端按 HTTP/1.1 应答（见模块注释偏差表）。
    let mut stream = HttpStream::connect(sock, parsed.https, &parsed.host)
        .map_err(|e| dial_error(url, &e.to_string()))?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: xray-cli\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        parsed.path, parsed.authority
    );
    stream.write_all(request.as_bytes()).map_err(|e| dial_error(url, &e.to_string()))?;

    let mut reader = BodyReader::new(&mut stream, deadline);
    let status = read_status_line(&mut reader, url)?;
    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let line = reader
            .read_line_crlf(MAX_HEAD_BYTES)
            .map_err(|e| head_error(url, &e.to_string()))?
            .ok_or_else(|| head_error(url, "truncated response head"))?;
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = String::from_utf8_lossy(&line).split_once(':') {
            headers.push((name.to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    let location = headers.iter().find(|(n, _)| n == "location").map(|(_, v)| v.clone());
    let body = read_body(&mut reader, &parse_framing(&headers), url)?;
    Ok((status, location, body))
}

fn dial_error(url: &str, cause: &str) -> CliError {
    CliError::ConfigLoadFailed(format!("failed to dial to {url}: {cause}"))
}

fn head_error(url: &str, cause: &str) -> CliError {
    CliError::ConfigLoadFailed(format!("failed to dial to {url}: {cause}"))
}

fn body_error(_url: &str, cause: &str) -> CliError {
    // Go 文案无 URL（errors.New("failed to read HTTP response").Base(err)）。
    CliError::ConfigLoadFailed(format!("failed to read HTTP response: {cause}"))
}

fn timeout_error(url: &str) -> CliError {
    CliError::ConfigLoadFailed(format!("failed to fetch {url}: timeout after 30s"))
}

struct ParsedUrl {
    https: bool,
    host: String,
    port: u16,
    /// Host 头原文（含显式端口、IPv6 括号）。
    authority: String,
    path: String,
}

fn parse_url(url: &str) -> Result<ParsedUrl> {
    let invalid = || CliError::ConfigLoadFailed(format!("invalid URL: {url}"));
    let (scheme, rest) = url.split_once("://").ok_or_else(invalid)?;
    let https = match scheme.to_ascii_lowercase().as_str() {
        "http" => false,
        "https" => true,
        _ => return Err(invalid()),
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    // 去 userinfo（user:pass@host）——Go url.Parse 支持，这里仅剥离不参与认证。
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if authority.is_empty() {
        return Err(invalid());
    }
    let default_port = if https { 443 } else { 80 };
    let (host, port) = split_host_port(authority, default_port).ok_or_else(invalid)?;
    let path = match path.split_once('#') {
        Some(("", _)) => "/".to_string(),
        Some((p, _)) => p.to_string(),
        None => path.to_string(),
    };
    Ok(ParsedUrl { https, host, port, authority: authority.to_string(), path })
}

fn split_host_port(authority: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = after.strip_prefix(':').and_then(|p| p.parse().ok());
        return Some((host.to_string(), port.unwrap_or(default_port)));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => Some((host.to_string(), port.parse().ok()?)),
        None => Some((authority.to_string(), default_port)),
    }
}

/// 同源相对/绝对 Location → 下一跳 URL（fragment 剥除）。
fn resolve_redirect(base: &str, location: &str) -> Option<String> {
    if location.starts_with("http://") || location.starts_with("https://") {
        return strip_fragment(location);
    }
    let (scheme, rest) = base.split_once("://")?;
    let authority_end = rest.find('/')?;
    let authority = &rest[..authority_end];
    let next = if let Some(stripped) = location.strip_prefix('/') {
        format!("{scheme}://{authority}/{stripped}")
    } else {
        let cur = &rest[authority_end..];
        let cur_path = cur.split(['?', '#']).next().unwrap_or("/");
        let dir = cur_path.rfind('/').map_or("/", |i| &cur_path[..=i]);
        format!("{scheme}://{authority}{dir}{location}")
    };
    strip_fragment(&next)
}

fn strip_fragment(url: &str) -> Option<String> {
    match url.split_once('#') {
        Some(("", _)) => None,
        Some((u, _)) => Some(u.to_string()),
        None => Some(url.to_string()),
    }
}

/// 明文 TCP / TLS（rustls 同步流）统一读写面。
enum HttpStream {
    Plain(TcpStream),
    // Box：StreamOwned 含 ClientConnection（~1KB），Box 抹平变体尺寸差（clippy
    // large_enum_variant）。
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl HttpStream {
    fn connect(sock: TcpStream, https: bool, host: &str) -> std::io::Result<Self> {
        if !https {
            return Ok(Self::Plain(sock));
        }
        let config = xray_tls::utls::default_client_config();
        let name = ServerName::try_from(host.to_string())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{e:?}")))?;
        let conn = rustls::ClientConnection::new(config, name)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(Self::Tls(Box::new(rustls::StreamOwned::new(conn, sock))))
    }

    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.write_all(buf),
            Self::Tls(s) => s.write_all(buf),
        }
    }
}

/// 响应体字节读取器：头块解析后的剩余字节为前缀，按需继续从连接拉取。
struct BodyReader<'a> {
    stream: &'a mut HttpStream,
    buf: Vec<u8>,
    pos: usize,
    eof: bool,
    deadline: Instant,
}

impl<'a> BodyReader<'a> {
    fn new(stream: &'a mut HttpStream, deadline: Instant) -> Self {
        Self { stream, buf: Vec::new(), pos: 0, eof: false, deadline }
    }

    // 尾表达式位不可挂语句属性（E0658），allow 上移 fn 级。
    #[allow(
        clippy::disallowed_methods,
        reason = "响应体读取截止检查（CLI 冷路径）；Clock 端口注入待 bd 39hko"
    )]
    fn ensure_deadline(&self, url: &str) -> Result<()> {
        if self.deadline > Instant::now() { Ok(()) } else { Err(timeout_error(url)) }
    }

    fn fill(&mut self) -> std::io::Result<usize> {
        if self.eof {
            return Ok(0);
        }
        let mut tmp = [0u8; 8192];
        let n = self.stream.read(&mut tmp)?;
        if n == 0 {
            self.eof = true;
        }
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(n)
    }

    fn read_byte(&mut self) -> std::io::Result<Option<u8>> {
        while self.pos >= self.buf.len() {
            self.buf.drain(..self.pos);
            self.pos = 0;
            if self.fill()? == 0 {
                return Ok(None);
            }
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(Some(b))
    }

    /// 读一行（到 `\n` 为止，剥 `\r\n`）。返回 None = 连接已结束且无数据。
    fn read_line_crlf(&mut self, cap: usize) -> std::io::Result<Option<Vec<u8>>> {
        let mut line = Vec::new();
        while let Some(b) = self.read_byte()? {
            if b == b'\n' {
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(Some(line));
            }
            line.push(b);
            if line.len() > cap {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "line too long"));
            }
        }
        if line.is_empty() { Ok(None) } else { Ok(Some(line)) }
    }

    /// 读至多 max 字节（EOF 时返回已收到的部分，可能为空）。
    fn take_at_most(&mut self, max: usize) -> std::io::Result<Vec<u8>> {
        while self.buf.len() - self.pos < max {
            self.buf.drain(..self.pos);
            self.pos = 0;
            if self.fill()? == 0 {
                break;
            }
        }
        let n = (self.buf.len() - self.pos).min(max);
        let out = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(out)
    }

    /// 精确读 n 字节；连接结束而不足 → None。
    fn take_exact(&mut self, n: usize) -> std::io::Result<Option<Vec<u8>>> {
        let out = self.take_at_most(n)?;
        if out.len() < n { Ok(None) } else { Ok(Some(out)) }
    }
}

fn read_status_line(reader: &mut BodyReader<'_>, url: &str) -> Result<u16> {
    let line = reader
        .read_line_crlf(MAX_HEAD_BYTES)
        .map_err(|e| head_error(url, &e.to_string()))?
        .ok_or_else(|| head_error(url, "truncated response head"))?;
    let text = String::from_utf8_lossy(&line);
    let code = text.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok());
    code.ok_or_else(|| head_error(url, &format!("malformed status line: {text}")))
}

/// 头块分帧决策（Go net/http 同序：chunked 优先于 Content-Length）。
enum Framing {
    Chunked,
    Length(usize),
    ToEof,
}

fn parse_framing(headers: &[(String, String)]) -> Framing {
    let chunked = headers
        .iter()
        .any(|(n, v)| n == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked"));
    if chunked {
        return Framing::Chunked;
    }
    match headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
    {
        Some(n) => Framing::Length(n),
        None => Framing::ToEof,
    }
}

fn read_body(reader: &mut BodyReader<'_>, framing: &Framing, url: &str) -> Result<Vec<u8>> {
    reader.ensure_deadline(url)?;
    let mut body = Vec::new();
    match framing {
        Framing::Length(n) => {
            let chunk = reader
                .take_exact(*n)
                .map_err(|e| body_error(url, &e.to_string()))?
                .ok_or_else(|| body_error(url, "truncated body"))?;
            body = chunk;
        },
        Framing::Chunked => loop {
            reader.ensure_deadline(url)?;
            let line = reader
                .read_line_crlf(MAX_HEAD_BYTES)
                .map_err(|e| body_error(url, &e.to_string()))?
                .ok_or_else(|| body_error(url, "truncated chunk size line"))?;
            let size_text = String::from_utf8_lossy(&line);
            let size_hex = size_text.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_hex, 16)
                .map_err(|_| body_error(url, &format!("invalid chunk size: {size_hex}")))?;
            if size == 0 {
                // trailer 段：读到空行为止（连接即将关闭，容忍缺失）。
                while let Some(l) = reader
                    .read_line_crlf(MAX_HEAD_BYTES)
                    .map_err(|e| body_error(url, &e.to_string()))?
                {
                    if l.is_empty() {
                        break;
                    }
                }
                break;
            }
            let chunk = reader
                .take_exact(size)
                .map_err(|e| body_error(url, &e.to_string()))?
                .ok_or_else(|| body_error(url, "truncated chunk"))?;
            body.extend_from_slice(&chunk);
            // chunk 体后随 CRLF。
            let _ = reader
                .read_line_crlf(MAX_HEAD_BYTES)
                .map_err(|e| body_error(url, &e.to_string()))?;
        },
        Framing::ToEof => loop {
            let chunk = reader.take_at_most(8192).map_err(|e| body_error(url, &e.to_string()))?;
            if chunk.is_empty() {
                break;
            }
            body.extend_from_slice(&chunk);
            reader.ensure_deadline(url)?;
        },
    }
    Ok(body)
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_support {
    //! 进程内 mock HTTP server：按序吐出预置响应（供本模块与 tool.rs 集成测试复用）。

    use std::io::{Read, Write};

    /// 起 127.0.0.1 随机口 server，每个连接依次应答 `responses[i]`；读完请求头
    /// 即应答（请求体不消费——本模块请求无体）。返回监听地址。
    pub(crate) fn spawn(responses: Vec<Vec<u8>>) -> std::net::SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        #[allow(clippy::disallowed_methods, reason = "测试：本地 stub HTTP server 线程")]
        std::thread::spawn(move || {
            for (idx, conn) in listener.incoming().enumerate() {
                let Ok(mut sock) = conn else { break };
                if idx >= responses.len() {
                    break;
                }
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    match sock.read(&mut byte) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            head.push(byte[0]);
                            if head.ends_with(b"\r\n\r\n") {
                                break;
                            }
                        },
                    }
                }
                if sock.write_all(&responses[idx]).is_err() {
                    break;
                }
                let _ = sock.flush();
            }
        });
        addr
    }

    /// 拼一条最小 HTTP/1.1 响应。
    pub(crate) fn response(status_line: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
        let mut out = format!("{status_line}\r\n");
        for (name, value) in headers {
            out.push_str(&format!("{name}: {value}\r\n"));
        }
        out.push_str("\r\n");
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(body);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use test_support::{response, spawn};

    use super::*;

    fn http_url(addr: std::net::SocketAddr, path: &str) -> String {
        format!("http://{addr}{path}")
    }

    /// is_remote_source 真值表（Go isRemoteSource 各分支）。
    #[test]
    fn is_remote_source_truth_table() {
        assert!(is_remote_source("http://example.com/config.json"));
        assert!(is_remote_source("https://example.com/c"));
        assert!(is_remote_source("@abstract"));
        assert!(is_remote_source("@"));
        assert!(is_remote_source("/tmp/x.sock:/api"));
        assert!(is_remote_source("/any/path/containing:/slash"));
        assert!(!is_remote_source(""));
        assert!(!is_remote_source("config.json"));
        assert!(!is_remote_source("stdin:"));
        assert!(!is_remote_source("ftp://example.com/c"));
        assert!(!is_remote_source("http:example.com")); // 无 //，非 http:// 前缀
    }

    /// is_remote_source 对 unix socket 文件的探测（Go ModeSocket 分支，仅 unix）。
    #[cfg(unix)]
    #[test]
    fn is_remote_source_detects_unix_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("x.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
        assert!(is_remote_source(sock_path.to_str().unwrap()));
        assert!(!is_remote_source(dir.path().join("plain.txt").to_str().unwrap()));
    }

    /// parse_url：scheme/host/port/authority/path 各形态。
    #[test]
    fn parse_url_forms() {
        let u = parse_url("http://example.com/a/b?q=1#frag").unwrap();
        assert!(!u.https);
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port, 80);
        assert_eq!(u.authority, "example.com");
        assert_eq!(u.path, "/a/b?q=1");

        let u = parse_url("https://[::1]:8443/x").unwrap();
        assert!(u.https);
        assert_eq!(u.host, "::1");
        assert_eq!(u.port, 8443);
        assert_eq!(u.authority, "[::1]:8443");
        assert_eq!(u.path, "/x");

        let u = parse_url("https://host").unwrap();
        assert_eq!(u.port, 443);
        assert_eq!(u.path, "/");

        let u = parse_url("http://u:p@host:81").unwrap();
        assert_eq!(u.host, "host");
        assert_eq!(u.port, 81);

        assert!(parse_url("ftp://x/").is_err());
        assert!(parse_url("example.com/c").is_err());
        assert!(parse_url("http://").is_err());
        assert!(parse_url("http://host#only").is_ok()); // fragment-only path → "/"
    }

    /// 200 + Content-Length：body 原样（Go fetchHTTPContent 正常路径）。
    #[test]
    fn fetch_plain_200_with_content_length() {
        let addr = spawn(vec![response("HTTP/1.1 200 OK", &[("Content-Length", "5")], b"hello")]);
        let got = fetch_http_content(&http_url(addr, "/config.json")).unwrap();
        assert_eq!(got, b"hello");
    }

    /// 200 + chunked：分块重组（Go net/http 透明处理，此处显式解）。
    #[test]
    fn fetch_chunked_body() {
        let addr = spawn(vec![response(
            "HTTP/1.1 200 OK",
            &[("Transfer-Encoding", "chunked")],
            b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
        )]);
        let got = fetch_http_content(&http_url(addr, "/c.json")).unwrap();
        assert_eq!(got, b"Wikipedia");
    }

    /// 200 + 无 Content-Length：读至连接关闭（close-delimited）。
    #[test]
    fn fetch_close_delimited_body() {
        let addr = spawn(vec![response("HTTP/1.1 200 OK", &[], b"tail-body")]);
        let got = fetch_http_content(&http_url(addr, "/c.json")).unwrap();
        assert_eq!(got, b"tail-body");
    }

    /// 非 200 → `unexpected HTTP status code: N`（Go 错误文案逐字）。
    #[test]
    fn fetch_non_200_error_text() {
        let addr = spawn(vec![response("HTTP/1.1 404 Not Found", &[("Content-Length", "0")], b"")]);
        let err = fetch_http_content(&http_url(addr, "/missing.json")).unwrap_err();
        assert!(err.to_string().contains("unexpected HTTP status code: 404"), "{err}");
    }

    /// 302 → Location 相对路径 → 200：跟随一跳后取回 body。
    #[test]
    fn fetch_follows_relative_redirect() {
        let addr = spawn(vec![
            response(
                "HTTP/1.1 302 Found",
                &[("Location", "/real/config.json"), ("Content-Length", "0")],
                b"",
            ),
            response("HTTP/1.1 200 OK", &[("Content-Length", "2")], b"ok"),
        ]);
        let got = fetch_http_content(&http_url(addr, "/old.json")).unwrap();
        assert_eq!(got, b"ok");
    }

    /// 重定向环超限 → `stopped after 10 redirects`（Go net/http 文案）。
    #[test]
    fn fetch_redirect_loop_hits_limit() {
        let responses = (0..=MAX_REDIRECTS)
            .map(|_| {
                response(
                    "HTTP/1.1 302 Found",
                    &[("Location", "/loop"), ("Content-Length", "0")],
                    b"",
                )
            })
            .collect();
        let addr = spawn(responses);
        let err = fetch_http_content(&http_url(addr, "/loop0")).unwrap_err();
        assert!(err.to_string().contains("stopped after 10 redirects"), "{err}");
    }

    /// 拨号失败（端口拒绝）→ `failed to dial to <url>`（Go 错误文案前缀；变体前缀
    /// `failed to load config: ` 来自 CliError::ConfigLoadFailed 的 Display）。
    #[test]
    fn fetch_dial_refused_error_text() {
        let err = fetch_http_content("http://127.0.0.1:1/config.json").unwrap_err();
        assert!(
            err.to_string().contains("failed to dial to http://127.0.0.1:1/config.json"),
            "{err}"
        );
    }

    /// URL 非法 → `invalid URL: <target>`（Go 错误文案逐字）。
    #[test]
    fn fetch_invalid_url_error_text() {
        let err = fetch_http_content("ftp://example.com/config.json").unwrap_err();
        assert!(err.to_string().contains("invalid URL: ftp://example.com/config.json"), "{err}");
    }

    /// Unix socket 目标形态 → 显式 unsupported（本模块不支持的 Go 形态）。
    #[test]
    fn fetch_unix_socket_target_unsupported() {
        for target in ["@abstract", "/tmp/x.sock:/api"] {
            let err = fetch_http_content(target).unwrap_err();
            assert!(err.to_string().contains("unsupported remote source"), "{target}: {err}");
        }
    }

    /// spec_format：扩展名判定对齐 Go GetFormatByExtension（query 形态判不出 → None）。
    #[test]
    fn spec_format_extension_table() {
        assert_eq!(spec_format("http://x/c.json"), Some(xray_conf::Format::Json));
        assert_eq!(spec_format("http://x/c.JSONC"), Some(xray_conf::Format::Json));
        assert_eq!(spec_format("http://x/c.yml"), Some(xray_conf::Format::Yaml));
        assert_eq!(spec_format("http://x/c.yaml"), Some(xray_conf::Format::Yaml));
        assert_eq!(spec_format("http://x/c.toml"), Some(xray_conf::Format::Toml));
        assert_eq!(spec_format("http://x/c"), None);
        assert_eq!(spec_format("http://x/c.json?token=1"), None); // Go 同样判不出
    }
}

//! SplitHTTP dialer——客户端拨号入口（packet-up + stream-up + stream-one mode）。
//!
//! 翻译自 Go `transport/internet/splithttp/dialer.go` 的 `Dial` 函数。

use std::sync::Arc;
use std::time::Duration;

use futures_util::TryStreamExt;
use tokio::io::{AsyncRead as AsyncReadTrait, AsyncReadExt, DuplexStream};
use tokio_util::io::{ReaderStream, StreamReader};
use tracing::debug;
use uuid::Uuid;
use crate::client::DefaultDialerClient;
use crate::config::Config;
use crate::connection::SplitConn;
use crate::error::{Result, SplitHttpError};

/// 统一上传连接类型（packet-up / stream-up / stream-one mode 共用）。
///
/// reader=下载流（`BodyDataStream` 适配后的类型擦除），writer=上传 pipe 写端。
///
/// 用 `Box<dyn AsyncRead + Send + Unpin>` 避免复杂的具体类型名（`BodyDataStream` +
/// `MapErr` + `StreamReader` 嵌套过长）。
pub type PacketUpConn = SplitConn<Box<dyn AsyncReadTrait + Send + Unpin>, DuplexStream>;


/// packet-up mode 端到端拨号。
///
/// 翻译自 Go `dialer.go::Dial` 的 packet-up 分支：
///
/// 1. GET `{base_uri}/{session_id}` 开下载流（SSE）
/// 2. `tokio::io::duplex` 创建上传 pipe
/// 3. spawn 后台任务：循环读 pipe → POST packet
/// 4. 返回 [`PacketUpConn`]（reader=下载流，writer=pipe 写端）
///
/// # 简化点（vs Go 原版）
///
/// - **不做 batching**：每次 POST = 一次 `pipe.read()` 的内容（Go 用 `MultiBuffer`
///   合并多个 `Write` 为单 POST，本切片保留单 read → 单 POST 的 1:1 映射）。
///   后续切片 E（xmux）一起优化。
/// - **不做 sc_min_posts_interval_ms 真随机**：固定 sleep 该值（Go 是范围随机）。
/// - **不做 upload_writer 大小限制**：直接 read pipe（Go 用 `pipe.WithSizeLimit`
///   强制 maxUploadSize 上限）。maxUploadSize 仅作为 POST 切片阈值。
///
/// # 参数
///
/// - `client`: 已配置的 [`DefaultDialerClient`]（多线程共享，[`Arc`] 包）
/// - `base_uri`: 完整 URL（`scheme://host/path`，不含 session_id；由调用方构造）
/// - `session_id`: uuid 字符串（由调用方生成，对应 Go `uuid.New()`）
/// - `sc_max_each_post_bytes`: 单 POST body 最大字节数（packet 切片阈值）
/// - `sc_min_posts_interval_ms`: 两次 POST 最小间隔（毫秒；0 表示不限）
pub async fn dial_packet_up(
    client: Arc<DefaultDialerClient>,
    base_uri: String,
    session_id: String,
    sc_max_each_post_bytes: usize,
    sc_min_posts_interval_ms: u64,
) -> Result<PacketUpConn> {
    // 1. GET 下载流（stream-down）
    let (download_body, remote, local) = client.open_stream(&base_uri, &session_id, None).await?;

    // BodyDataStream<Incoming> → Stream<Item=io::Result<Bytes>> → AsyncRead
    // 用 map_err 把 hyper::Error 转 io::Error，再 StreamReader 把 Stream 转 AsyncRead
    let download_stream = download_body.map_err(map_hyper_err_to_io);
    let download_reader: Box<dyn AsyncReadTrait + Send + Unpin> =
        Box::new(StreamReader::new(download_stream));

    // 2. 创建上传 pipe（buffer 略大于 max_post 以吸收短期 burst）
    let pipe_buf = sc_max_each_post_bytes.saturating_mul(2).max(8192);
    let (pipe_client, mut pipe_server) = tokio::io::duplex(pipe_buf);

    // 3. spawn 后台 POST 任务：循环读 pipe → POST packet
    let base_uri_for_task = base_uri.clone();
    let session_id_for_task = session_id.clone();
    tokio::spawn(async move {
        let mut seq: u64 = 0;
        let mut read_buf = vec![0u8; sc_max_each_post_bytes];
        loop {
            let n = match pipe_server.read(&mut read_buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    debug!(target: "splithttp", error = %e, "upload pipe read failed");
                    break;
                }
            };
            let payload = read_buf[..n].to_vec();
            let seq_str = seq.to_string();
            seq += 1;

            if let Err(e) = client
                .post_packet(&base_uri_for_task, &session_id_for_task, &seq_str, payload)
                .await
            {
                debug!(target: "splithttp", error = %e, seq = seq, "post_packet failed, terminating upload");
                break;
            }

            if sc_min_posts_interval_ms > 0 {
                tokio::time::sleep(Duration::from_millis(sc_min_posts_interval_ms)).await;
            }
        }
    });

    Ok(SplitConn::new(download_reader, pipe_client, remote, local))
}

/// `hyper::Error` → `std::io::Error` 转换函数指针（供 `TryStreamExt::map_err` 使用）。
fn map_hyper_err_to_io(e: hyper::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}


/// stream-up mode 拨号：POST streaming body 上传 + 独立 GET 下载。
///
/// 翻译自 Go `dialer.go::Dial` 的 stream-up 分支：
///
/// 1. `tokio::io::duplex` 创建上传 pipe
/// 2. `pipe_server` → `ReaderStream` → POST streaming body (`upload_only=true`)
/// 3. 独立 GET 下载流 (`body=None`)
/// 4. 返回 [`PacketUpConn`]（reader=下载流，writer=pipe 写端）
///
/// # 与 packet-up 区别
///
/// - packet-up: 分包 POST（pipe→read_exact(max_post_size)→POST 循环）
/// - stream-up: 单次 POST streaming body（pipe 直接作为 HTTP body）
///
/// stream-up 适合 HTTP/2 流式上传，CDN 不支持时分包 packet-up 更稳。
pub async fn dial_stream_up(
    client: Arc<DefaultDialerClient>,
    base_uri: String,
    session_id: String,
) -> Result<PacketUpConn> {
    // 1. 创建上传 pipe
    let (pipe_client, pipe_server) = tokio::io::duplex(8192);
    let upload_stream = ReaderStream::new(pipe_server);

    // 2. POST upload（不等响应）
    let (_, remote, local) = client
        .open_stream_uploading(&base_uri, &session_id, upload_stream, true)
        .await?;

    // 3. 独立 GET 下载流
    let (download_body, _, _) = client.open_stream(&base_uri, &session_id, None).await?;
    let download_stream = download_body.map_err(map_hyper_err_to_io);
    let download_reader: Box<dyn AsyncReadTrait + Send + Unpin> =
        Box::new(StreamReader::new(download_stream));

    Ok(SplitConn::new(download_reader, pipe_client, remote, local))
}

/// stream-one mode 拨号：单 POST streaming body + 同连接响应流（全双工）。
///
/// 翻译自 Go `dialer.go::Dial` 的 stream-one 分支：
///
/// 1. `tokio::io::duplex` 创建上传 pipe
/// 2. `pipe_server` → `ReaderStream` → POST streaming body (`upload_only=false`)
/// 3. 响应流作为下载流
/// 4. 返回 [`PacketUpConn`]（reader=响应流，writer=pipe 写端）
///
/// # 与 stream-up 区别
///
/// - stream-up: 双连接（POST upload + GET download 分离）
/// - stream-one: 单连接全双工（POST + 同一响应流）
///
/// stream-one 是 REALITY 友好模式（单连接看起来像正常 HTTPS）。
pub async fn dial_stream_one(
    client: Arc<DefaultDialerClient>,
    base_uri: String,
    session_id: String,
) -> Result<PacketUpConn> {
    // 1. 创建上传 pipe
    let (pipe_client, pipe_server) = tokio::io::duplex(8192);
    let upload_stream = ReaderStream::new(pipe_server);

    // 2. POST upload（等响应）
    let (response_opt, remote, local) = client
        .open_stream_uploading(&base_uri, &session_id, upload_stream, false)
        .await?;
    let response_body = response_opt.ok_or_else(|| {
        crate::error::SplitHttpError::Hyper(
            "stream-one upload_only=false must return response stream".into(),
        )
    })?;

    // 3. 响应流作为下载流
    let response_stream = response_body.map_err(map_hyper_err_to_io);
    let download_reader: Box<dyn AsyncReadTrait + Send + Unpin> =
        Box::new(StreamReader::new(response_stream));

    Ok(SplitConn::new(download_reader, pipe_client, remote, local))
}
// ===== 切片 F: dial() 统一入口 + dispatch 辅助函数 =====

/// HTTP 版本选择（`\"1.1\"` / `\"2\"` / `\"3\"`）。
///
/// 对应 Go `transport/internet/splithttp/dialer.go::decideHTTPVersion`：
/// - REALITY → 强制 `\"2\"`（H2 多路复用对 REALITY 流量伪装最友好）
/// - 无 TLS → `\"1.1\"`（明文 HTTP/1.1）
/// - TLS ALPN 单值：`\"http/1.1\"` / `\"h3\"` / 其他 → `\"1.1\"` / `\"3\"` / `\"2\"`
/// - TLS ALPN 多值或空 → 默认 `\"2\"`
#[must_use]
pub fn decide_http_version(
    has_tls: bool,
    has_reality: bool,
    next_protocol: &[String],
) -> &'static str {
    if has_reality {
        return "2";
    }
    if !has_tls {
        return "1.1";
    }
    if next_protocol.len() != 1 {
        return "2";
    }
    match next_protocol[0].as_str() {
        "http/1.1" => "1.1",
        "h3" => "3",
        _ => "2",
    }
}

/// 模式推断（`packet-up` / `stream-up` / `stream-one`）。
///
/// 对应 Go `Dial` 函数中 `mode` 默认值推断逻辑：
/// - 显式配置 → 直接返回
/// - `auto` 或空 + REALITY → `stream-one`（有 DownloadSettings 则 `stream-up`）
/// - `auto` 或空 + 无 REALITY → `packet-up`（默认）
#[must_use]
pub fn resolve_mode(
    configured_mode: &str,
    has_reality: bool,
    has_download_settings: bool,
) -> String {
    if configured_mode.is_empty() || configured_mode == "auto" {
        if has_reality {
            if has_download_settings {
                "stream-up".to_string()
            } else {
                "stream-one".to_string()
            }
        } else {
            "packet-up".to_string()
        }
    } else {
        configured_mode.to_string()
    }
}

/// 拼 base URL：`{scheme}://{host}{path}`（query 非空附加 `?{query}`）。
///
/// 对应 Go `Dial` 中 `requestURL` 的拼接逻辑（不含 `browser_dialer` 特殊端口逻辑，
/// 那是 `globalDialerMap` 接入点的事，切片 F 不涉及）。
#[must_use]
pub fn build_request_url(scheme: &str, host: &str, path: &str, query: &str) -> String {
    if query.is_empty() {
        format!("{scheme}://{host}{path}")
    } else {
        format!("{scheme}://{host}{path}?{query}")
    }
}

/// 统一拨号入口。
///
/// 对应 Go `transport/internet/splithttp/dialer.go::Dial`。根据 `mode` 分发到
/// [`dial_packet_up`] / [`dial_stream_up`] / [`dial_stream_one`]。
///
/// # 简化点（vs Go 原版）
///
/// - **REALITY 注入**：通过 `DefaultDialerClient::new(config, tls_config)` 构造时
///   注入 `tls_config`（REALITY 用 watfaq-rustls `with_reality()` patch 注入）。Go
///   在 `dialContext` 闭包里 `reality.UClient(conn, ...)` 包装 TCP conn；Rust 因
///   hyper-rustls 自管 TLS 握手，REALITY 注入点移到 `RustlsClientConfig` 构造阶段。
///   留 VPS REALITY 切片 F2 实际接入验证。
/// - **DownloadSettings**：当前 `has_download_settings=false` 固定（stream-up via
///   DownloadSettings 是 splithttp 高级特性，留切片 F2 接入）。
/// - **浏览器拨号器**：Go `browser_dialer.HasBrowserDialer()` 分支未实现
///   （ponytail: YAGNI，浏览器 JS dialer 与 Rust 客户端场景不匹配）。
/// - **H3**：当前 dispatch 仅支持 H1/H2（`enable_http1` + `enable_http2`）。
///   HTTP/3 需要 quinn + h3 crate 链（~400 行），YAGNI；留待 VPS H3 用例出现时再做。
///
/// # 参数
///
/// - `client`: 已配置的 [`DefaultDialerClient`]（含 TLS 配置，REALITY 也通过此处注入）
/// - `config`: splithttp 主配置（取 `mode` / `host` / `path` 等）
/// - `scheme`: URL scheme（`\"http\"` / `\"https\"`，由调用方根据 tls/reality 决定）
/// - `host`: URL host（含端口，由调用方决定）
/// - `has_reality`: 是否启用 REALITY（影响默认 mode 推断）
///
/// # Errors
///
/// - [`SplitHttpError::InvalidUrl`]：未知 `mode`
/// - 子函数错误透传（[`dial_packet_up`] / [`dial_stream_up`] / [`dial_stream_one`]）
pub async fn dial(
    client: Arc<DefaultDialerClient>,
    config: Arc<Config>,
    scheme: &str,
    host: &str,
    has_reality: bool,
) -> Result<PacketUpConn> {
    // ponytail: has_download_settings=false 固定，DownloadSettings 接入留切片 F2
    let mode = resolve_mode(&config.mode, has_reality, false);
    let session_id = if mode == "stream-one" {
        String::new()
    } else {
        Uuid::new_v4().to_string()
    };
    let base_uri = build_request_url(
        scheme,
        host,
        &config.normalized_path(),
        &config.normalized_query(),
    );

    debug!(target: "splithttp", %mode, %base_uri, "dial dispatch");

    match mode.as_str() {
        "packet-up" => {
            let sc_max = config.normalized_sc_max_each_post_bytes();
            let sc_min = config.normalized_sc_min_posts_interval_ms();
            dial_packet_up(
                client,
                base_uri,
                session_id,
                sc_max.from.max(1) as usize,
                sc_min.from as u64,
            )
            .await
        }
        "stream-up" => dial_stream_up(client, base_uri, session_id).await,
        "stream-one" => dial_stream_one(client, base_uri, session_id).await,
        other => Err(SplitHttpError::InvalidUrl(format!(
            "unknown splithttp mode: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== decide_http_version =====

    #[test]
    fn decide_http_version_reality_forces_h2() {
        assert_eq!(decide_http_version(true, true, &[]), "2");
        // REALITY 优先于一切，即使配置了 h3 ALPN 也强制 h2
        assert_eq!(
            decide_http_version(true, true, &["h3".to_string()]),
            "2"
        );
    }

    #[test]
    fn decide_http_version_no_tls_returns_h1_1() {
        assert_eq!(decide_http_version(false, false, &[]), "1.1");
    }

    #[test]
    fn decide_http_version_alpn_http_1_1() {
        assert_eq!(
            decide_http_version(true, false, &["http/1.1".to_string()]),
            "1.1"
        );
    }

    #[test]
    fn decide_http_version_alpn_h3() {
        assert_eq!(
            decide_http_version(true, false, &["h3".to_string()]),
            "3"
        );
    }

    #[test]
    fn decide_http_version_alpn_unknown_falls_back_to_h2() {
        assert_eq!(
            decide_http_version(true, false, &["h2".to_string()]),
            "2"
        );
    }

    #[test]
    fn decide_http_version_multiple_alpn_falls_back_to_h2() {
        assert_eq!(
            decide_http_version(true, false, &["h2".to_string(), "http/1.1".to_string()]),
            "2"
        );
    }

    // ===== resolve_mode =====

    #[test]
    fn resolve_mode_auto_packet_up_default_no_reality() {
        assert_eq!(resolve_mode("", false, false), "packet-up");
        assert_eq!(resolve_mode("auto", false, false), "packet-up");
    }

    #[test]
    fn resolve_mode_auto_stream_one_with_reality() {
        assert_eq!(resolve_mode("", true, false), "stream-one");
        assert_eq!(resolve_mode("auto", true, false), "stream-one");
    }

    #[test]
    fn resolve_mode_auto_stream_up_with_reality_and_download_settings() {
        assert_eq!(resolve_mode("", true, true), "stream-up");
        assert_eq!(resolve_mode("auto", true, true), "stream-up");
    }

    #[test]
    fn resolve_mode_explicit_passthrough() {
        assert_eq!(resolve_mode("packet-up", true, true), "packet-up");
        assert_eq!(resolve_mode("stream-one", false, false), "stream-one");
        assert_eq!(resolve_mode("stream-up", false, false), "stream-up");
    }

    // ===== build_request_url =====

    #[test]
    fn build_request_url_without_query() {
        assert_eq!(
            build_request_url("https", "example.com:443", "/", ""),
            "https://example.com:443/"
        );
    }

    #[test]
    fn build_request_url_with_query() {
        assert_eq!(
            build_request_url("http", "h", "/p/", "k=v"),
            "http://h/p/?k=v"
        );
    }

    // ===== dial() 未知 mode 错误路径（不发起网络） =====

    #[tokio::test]
    async fn dial_unknown_mode_returns_error() {
        let config = Arc::new(Config {
            mode: "unknown-mode".into(),
            ..Default::default()
        });
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let client = Arc::new(DefaultDialerClient::new(config.clone(), tls.into()));
        let result = dial(client, config, "http", "h", false).await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("unknown mode should fail, got Ok"),
        };
        assert!(matches!(err, SplitHttpError::InvalidUrl(m) if m.contains("unknown splithttp mode")));
    }
}

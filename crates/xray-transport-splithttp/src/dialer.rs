//! SplitHTTP dialer——客户端拨号入口（packet-up + stream-up + stream-one mode）。
//!
//! 翻译自 Go `transport/internet/splithttp/dialer.go` 的 `Dial` 函数。

use std::sync::Arc;
use std::time::Duration;

use futures_util::TryStreamExt;
use tokio::io::{AsyncRead as AsyncReadTrait, AsyncReadExt, DuplexStream};
use tokio_util::io::{ReaderStream, StreamReader};
use tracing::debug;

use crate::client::DefaultDialerClient;
use crate::connection::SplitConn;
use crate::error::Result;

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
mod tests {
    // dialer 的端到端测试在 tests/mock_server.rs 集成测试覆盖。
}

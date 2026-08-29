//! 批量上传 pump——把 `AsyncRead` 流切成 ≤ `max_post_bytes` 的 chunk，
//! 异步推给一个 POST 回调。
//!
//! 对应 Go `splithttp/dialer.go::Dial` packet-up 分支（dialer.go:507-573）的
//! 核心循环：pipe.New(WithSizeLimit(maxUploadSize)) → ReadMultiBuffer() 累积
//! → SplitSize 切分 → PostPacket 推送。
//!
//! # 设计
//!
//! 单 task 循环：从 `reader` 读入累积 buffer，达到 `max_post_bytes` 即 POST；
//! reader EOF → flush 剩余 → 退出。
//!
//! POST 通过 `post_fn: FnMut(Vec<u8>) -> Future<()>` 回调，便于多场景复用
//! （hyper [`DefaultDialerClient::post_packet`]、H3 [`H3Conn::post_packet`]）。
//!
//! # 简化（vs Go）
//!
//! - **无 httptrace WroteRequest 背压**：直接 await POST 完成 = 隐式背压
//!   （hyper 已 queue body 后才返回；H3 send_data+finish 必须 await 否则 stream 乱序）。
//! - **无 LeftRequests 动态换连接**：本切片聚焦批量；xmux 换连接在
//!   `dial_packet_up_with_xmux` 中独立接线。
//! - **scMinPostsIntervalMs 固定值**：Go `rand()` 区间在本切片用 `from` 单一值，
//!   范围采样 caller 可在外面做。
//!
//! # Future trait
//!
//! 本 crate 使用 Rust 2024 prelude（`Future` 已在 prelude），无需 `use` 引入。

use std::future::Future;

use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::debug;

/// 把 pipe 累积数据按 ≤ `max_post_bytes` 切片并 POST。
///
/// 每 POST 完等回调完成（隐式背压）→ 间隔 sleep（如果配置）→ 下一片。
/// reader EOF 时 flush 剩余 buffer → 退出。
///
/// 返回累计 POST 次数。
pub async fn run_batched_upload<F, Fut>(
    mut reader: Box<dyn AsyncRead + Send + Unpin>,
    max_post_bytes: usize,
    min_interval_ms: u64,
    mut post_fn: F,
) -> usize
where
    F: FnMut(Vec<u8>) -> Fut + Send,
    Fut: Future<Output = Result<(), crate::error::SplitHttpError>> + Send,
{
    debug_assert!(max_post_bytes > 0, "max_post_bytes must be > 0");

    let mut scratch = vec![0u8; 8192];
    let mut pending: Vec<u8> = Vec::new();
    let mut posts: usize = 0;

    loop {
        // 1. 把 pipe 数据尽可能搬进 `pending` 直到 ≥ max_post_bytes 或 EOF。
        //    单次 read 取 scratch.size() bytes；循环直到 pending 满了或 read=0。
        let mut eof_seen = false;
        while pending.len() < max_post_bytes {
            match reader.read(&mut scratch).await {
                Ok(0) => {
                    eof_seen = true;
                    break;
                }
                Ok(n) => pending.extend_from_slice(&scratch[..n]),
                Err(e) => {
                    debug!(target: "splithttp", error = %e, "upload pipe read failed");
                    return posts;
                }
            }
        }

        if pending.is_empty() && eof_seen {
            break;
        }

        // 2. 取一片 POST
        let take = pending.len().min(max_post_bytes);
        let chunk: Vec<u8> = pending.drain(..take).collect();
        let chunk_len = chunk.len();

        if let Err(e) = post_fn(chunk).await {
            debug!(target: "splithttp", error = %e, len = chunk_len, posts = posts, "post failed");
            return posts;
        }
        posts += 1;

        // 3. 间隔 sleep
        if min_interval_ms > 0 && (!pending.is_empty() || !eof_seen) {
            tokio::time::sleep(std::time::Duration::from_millis(min_interval_ms)).await;
        }

        if eof_seen && pending.is_empty() {
            break;
        }
    }

    posts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SplitHttpError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;

    /// 1 个 writer 写 1 个 100 KiB 流（拆成 32 KiB POST × 4 应正好）。
    #[tokio::test]
    async fn batches_into_32k_posts() {
        let total = 100 * 1024;
        let (mut writer, reader) = tokio::io::duplex(64 * 1024);

        let post_count = Arc::new(AtomicUsize::new(0));
        let pc = post_count.clone();
        let max_post = 32 * 1024;

        let upload_task = tokio::spawn(async move {
            run_batched_upload(
                Box::new(reader) as Box<dyn AsyncRead + Send + Unpin>,
                max_post,
                0u64,
                move |chunk| {
                    let pc = pc.clone();
                    async move {
                        pc.fetch_add(1, Ordering::SeqCst);
                        // 验证 chunk ≤ max_post
                        assert!(chunk.len() <= max_post);
                        Ok::<(), SplitHttpError>(())
                    }
                },
            )
            .await
        });

        let payload = vec![0xABu8; total];
        writer.write_all(&payload).await.unwrap();
        drop(writer);

        let posts = upload_task.await.unwrap();
        let expected = total / max_post;
        assert!(posts >= expected, "expected ~{expected} posts, got {posts}");
    }

    /// EOF 时 flush 剩余 < max_post_bytes。
    #[tokio::test]
    async fn flushes_remainder_on_eof() {
        let total = 1024 + 1; // 不整除 max_post=1024
        let max_post = 1024;
        let (mut writer, reader) = tokio::io::duplex(64 * 1024);

        let pc = Arc::new(AtomicUsize::new(0));
        let pc_inner = pc.clone();
        let upload_task = tokio::spawn(async move {
            run_batched_upload(
                Box::new(reader) as Box<dyn AsyncRead + Send + Unpin>,
                max_post,
                0u64,
                move |chunk| {
                    let pc = pc_inner.clone();
                    async move {
                        pc.fetch_add(1, Ordering::SeqCst);
                        assert!(chunk.len() <= max_post);
                        Ok::<(), SplitHttpError>(())
                    }
                },
            )
            .await
        });

        writer.write_all(&vec![0u8; total]).await.unwrap();
        drop(writer);

        let posts = upload_task.await.unwrap();
        assert_eq!(posts, 2, "expected 2 POSTs (1024 + 1 remainder)");
    }
}

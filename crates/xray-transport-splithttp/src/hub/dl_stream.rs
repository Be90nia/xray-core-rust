//! 下行 body 流：duplex 读 → h2 DATA 帧，读缓冲池化复用（票 r1693）。
//!
//! 池本身与上行共用（`crate::pool_stream`，票 1fm1l 泛化）：本模块只做
//! 「`Bytes` 块 → `Frame::data`」这一层的包装 + srv 发送站点归因。
//!
//! 帧粒度与原实现一致：一次 `poll_read` 产出一帧（同 `ReaderStream` 的
//! `poll_read_buf` 单次读语义），故 h2 DATA 帧尺寸分布不变。
//!
//! 留主仓（方向件：依赖 `bytes::Bytes::from_owner`）——池化读流只服务 h2 DATA
//! 帧这一网络方向，`bytes` 属方向件非 udf 依赖纪律，不上浮。

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures_util::Stream;
use hyper::body::Frame;
use tokio::io::AsyncRead;
use xray_common::alloc_site;

use crate::pool_stream::PoolStream;

/// duplex → `Frame<Bytes>` 的池化读流（下行响应 body）。
pub(crate) struct DlStream<R> {
    inner: PoolStream<R>,
}

impl<R> DlStream<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self { inner: PoolStream::new(inner, super::handler::DUPLEX_BUF) }
    }
}

impl<R: AsyncRead + Unpin> Stream for DlStream<R> {
    type Item = io::Result<Frame<Bytes>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // 站点归因（z02z8）：本段一次 poll 的分配（含池未命中时的取块）归 srv 发送站点。
        let _site = alloc_site::enter(alloc_site::XHTTP_SRV_SEND);
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_next(cx).map(|opt| opt.map(|r| r.map(Frame::data)))
    }
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test]
    async fn frames_carry_all_bytes_in_order_and_end_with_eof() {
        let (mut tx, rx) = tokio::io::duplex(super::super::handler::DUPLEX_BUF);
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            tx.write_all(&payload).await.expect("duplex 写不失败");
            tx.shutdown().await.expect("duplex 关闭不失败");
        });

        let mut stream = DlStream::new(rx);
        let mut got = Vec::new();
        while let Some(item) = stream.next().await {
            let frame = item.expect("读不失败");
            got.extend_from_slice(frame.data_ref().expect("仅数据帧"));
        }
        writer.await.expect("写任务不 panic");

        assert_eq!(got, expected, "字节内容与顺序必须完整");
    }
}

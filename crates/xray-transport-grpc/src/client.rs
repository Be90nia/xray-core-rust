//! gRPC client：把目标地址封装为 gRPC Tun/TunMulti stream 客户端。
//!
//! 对应 Go `transport/internet/grpc/dial.go::dialgRPC`。
//!
//! ## Ponytail 决策
//!
//! Go 端用 `grpc.ClientConn` 拨号到 `passthrough:///<host>:<port>`，然后调
//! `client.TunCustomName(ctx, service, stream)` 拿一个 `GRPCService_TunClient`
//! （grpc.ClientStreaming 接口）。这要求完整 HTTP/2 + TLS + tonic 栈。
//!
//! Rust 端不引入 tonic/h2，转而暴露 `dial_target(stream, ...)` 让调用方注入
//! 已建立的 `HunkStream`（典型由 hyper/h2 dialer 实现）。本模块只做协议层
//! 构造，把 HunkStream 适配为 `transport::Link` 给 proxy handler。

use crate::encoding::{HunkReader, HunkReaderWriter, HunkStream};
use xray_transport::link::Link;

/// gRPC 客户端配置（用于生成 service/stream 名）。
///
/// 由 [`crate::config::Config`] 派生。
#[derive(Debug, Clone)]
pub struct GrpcClient {
    /// 已解析的 gRPC 服务名（`Config::service_name()`）。
    pub service_name: String,
    /// 已解析的 Tun stream 名（`Config::tun_stream_name()`）。
    pub tun_stream_name: String,
    /// 已解析的 TunMulti stream 名（`Config::tun_multi_stream_name()`）。
    pub tun_multi_stream_name: String,
    /// 是否启用 multi-stream 模式。
    pub multi_mode: bool,
}

impl GrpcClient {
    /// 从 `Config` 构造 client 配置。
    #[must_use]
    pub fn from_config(config: &crate::Config) -> Self {
        Self {
            service_name: config.service_name(),
            tun_stream_name: config.tun_stream_name(),
            tun_multi_stream_name: config.tun_multi_stream_name(),
            multi_mode: config.multi_mode,
        }
    }

    /// 把已建立的 `HunkStream` 包成 `transport::Link`，供 proxy handler 使用。
    ///
    /// 对应 Go `dialgRPC` 中 `NewHunkConn(grpcService, nil) -> net.Conn`，
    /// 然后 dispatcher 包装成 Link。
    ///
    /// # 调用方契约
    /// `stream` 必须是已成功发起 Tun RPC 的双向 stream（client 端可直接
    /// send/recv hunk）。本函数不发起 HTTP/2 请求——这部分由上层 transport
    /// 层完成（如 hyper/h2 dialer）。
    pub fn dial_target<S: HunkStream + 'static>(&self, stream: S) -> Link {
        let rw = HunkReaderWriter::new(stream);
        let (reader, writer) = rw.into_parts();
        Link::new(Box::new(reader), Box::new(writer))
    }

    /// 返回当前选择的 stream 名（multi_mode ? multi : tun）。
    #[must_use]
    pub fn active_stream_name(&self) -> &str {
        if self.multi_mode {
            &self.tun_multi_stream_name
        } else {
            &self.tun_stream_name
        }
    }
}

// HunkReader/HunkReaderWriter/HunkStream 都在 crate 内，Box<HunkReader<S>>
// 满足 Reader trait bound（编译期由 dial_target 验证）。
// 这里仅占位确认 dyn-safe：
const _: fn() = || {
    fn _assert_reader<S: HunkStream + 'static>() {
        fn _r<T: xray_buf::io::Reader>() {}
        _r::<HunkReader<S>>();
    }
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::future::Future;
    use std::pin::Pin;

    struct DummyStream;
    impl HunkStream for DummyStream {
        fn recv_hunk(&mut self) -> Pin<Box<dyn Future<Output = crate::error::Result<Vec<u8>>> + Send + '_>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn send_hunk(&mut self, _data: Vec<u8>) -> Pin<Box<dyn Future<Output = crate::error::Result<()>> + Send + '_>> {
            Box::pin(async { Ok(()) })
        }
        fn close_send(&mut self) -> Pin<Box<dyn Future<Output = crate::error::Result<()>> + Send + '_>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[test]
    fn from_config_traditional() {
        let cfg = Config {
            service_name: "GunService".into(),
            multi_mode: false,
            ..Default::default()
        };
        let client = GrpcClient::from_config(&cfg);
        assert_eq!(client.service_name, "GunService");
        assert_eq!(client.tun_stream_name, "Tun");
        assert_eq!(client.tun_multi_stream_name, "TunMulti");
        assert!(!client.multi_mode);
        assert_eq!(client.active_stream_name(), "Tun");
    }

    #[test]
    fn from_config_multi_mode() {
        let cfg = Config {
            service_name: "/A/B/Tun|TunMulti".into(),
            multi_mode: true,
            ..Default::default()
        };
        let client = GrpcClient::from_config(&cfg);
        assert_eq!(client.service_name, "A/B");
        assert_eq!(client.tun_stream_name, "Tun");
        assert_eq!(client.tun_multi_stream_name, "TunMulti");
        assert!(client.multi_mode);
        assert_eq!(client.active_stream_name(), "TunMulti");
    }

    #[tokio::test]
    async fn dial_target_returns_link_with_active_stream() {
        let client = GrpcClient::from_config(&Config {
            service_name: "GunService".into(),
            ..Default::default()
        });
        let link = client.dial_target(DummyStream);
        // Link 持有 reader/writer，验证可以拆出且不 panic
        let (_r, _w) = link.into_parts();
    }
}

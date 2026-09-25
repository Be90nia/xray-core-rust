//! gRPC server：注册 Tun/TunMulti 服务，接收 inbound stream。
//!
//! 对应 Go `transport/internet/grpc/hub.go`。
//!
//! ## Ponytail 决策
//!
//! Go 端用 `grpc.NewServer` + `RegisterGRPCServiceServerX` 注册服务，
//! 然后 `s.Serve(streamListener)` 接受 HTTP/2 连接。Rust 端不引入 tonic，
//! 转而暴露 `handle_incoming_stream(stream)` 让 dispatcher 在 transport 层
//! 完成 HTTP/2 解码后注入已建立的 `HunkStream`。

use xray_transport::link::Link;

use crate::encoding::{HunkReaderWriter, HunkStream, MultiHunkReaderWriter};

/// gRPC 服务端配置（用于注册 Tun/TunMulti 服务名）。
#[derive(Debug, Clone)]
pub struct GrpcServer {
    /// 已解析的 gRPC 服务名。
    pub service_name: String,
    /// 已解析的 Tun stream 名。
    pub tun_stream_name: String,
    /// 已解析的 TunMulti stream 名。
    pub tun_multi_stream_name: String,
}

impl GrpcServer {
    /// 从 `Config` 构造 server 配置。
    #[must_use]
    pub fn from_config(config: &crate::Config) -> Self {
        Self {
            service_name: config.service_name(),
            tun_stream_name: config.tun_stream_name(),
            tun_multi_stream_name: config.tun_multi_stream_name(),
        }
    }

    /// 处理一条 inbound `HunkStream`：包成 `transport::Link` 给 dispatcher。
    ///
    /// 对应 Go `Listener.Tun/TunMulti(server)`：
    /// 服务端 gRPC handler 收到一个双向 stream，包装为 `net.Conn` 调
    /// `l.handler(conn)`。本函数把 stream 适配为 Link 后返回，由调用方
    /// （transport server / dispatcher）进一步处理。
    ///
    /// `multi` 为 true 时使用 MultiHunkReaderWriter（TunMulti 协议），
    /// 否则使用 HunkReaderWriter（Tun 协议）。
    pub fn handle_incoming_stream<S: HunkStream + 'static>(&self, stream: S, multi: bool) -> Link {
        if multi {
            let rw = MultiHunkReaderWriter::new(stream);
            let (reader, writer) = rw.into_parts();
            Link::new(Box::new(reader), Box::new(writer))
        } else {
            let rw = HunkReaderWriter::new(stream);
            let (reader, writer) = rw.into_parts();
            Link::new(Box::new(reader), Box::new(writer))
        }
    }

    /// 判断 HTTP path 是否匹配本服务（用于服务端路由分发）。
    ///
    /// path 形如 `/A/B/Tun`（service/stream 名分段 escape 后拼接）。
    #[must_use]
    pub fn matches_path(&self, path: &str, multi: bool) -> bool {
        let expected = if multi {
            format!("/{}/{}", self.service_name, self.tun_multi_stream_name)
        } else {
            format!("/{}/{}", self.service_name, self.tun_stream_name)
        };
        path == expected
    }
}

#[cfg(test)]
mod tests {
    use std::{future::Future, pin::Pin};

    use super::*;
    use crate::config::Config;

    struct DummyStream;
    impl HunkStream for DummyStream {
        fn recv_hunk(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = crate::error::Result<Vec<u8>>> + Send + '_>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn send_hunk(
            &mut self,
            _data: Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = crate::error::Result<()>> + Send + '_>> {
            Box::pin(async { Ok(()) })
        }

        fn close_send(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = crate::error::Result<()>> + Send + '_>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[test]
    fn from_config_traditional() {
        let cfg = Config { service_name: "GunService".into(), ..Default::default() };
        let server = GrpcServer::from_config(&cfg);
        assert_eq!(server.service_name, "GunService");
        assert_eq!(server.tun_stream_name, "Tun");
        assert_eq!(server.tun_multi_stream_name, "TunMulti");
    }

    #[test]
    fn matches_path_tun() {
        let server = GrpcServer::from_config(&Config {
            service_name: "GunService".into(),
            ..Default::default()
        });
        assert!(server.matches_path("/GunService/Tun", false));
        assert!(!server.matches_path("/GunService/TunMulti", false));
    }

    #[test]
    fn matches_path_multi() {
        let server = GrpcServer::from_config(&Config {
            service_name: "/A/B/Tun|TunMulti".into(),
            ..Default::default()
        });
        assert!(server.matches_path("/A/B/Tun", false));
        assert!(server.matches_path("/A/B/TunMulti", true));
        assert!(!server.matches_path("/A/B/Tun", true));
    }

    #[tokio::test]
    async fn handle_incoming_stream_returns_link() {
        let server = GrpcServer::from_config(&Config {
            service_name: "GunService".into(),
            ..Default::default()
        });
        let link = server.handle_incoming_stream(DummyStream, false);
        let (_r, _w) = link.into_parts();
    }

    #[tokio::test]
    async fn handle_incoming_stream_multi_returns_link() {
        let server = GrpcServer::from_config(&Config {
            service_name: "GunService".into(),
            ..Default::default()
        });
        let link = server.handle_incoming_stream(DummyStream, true);
        let (_r, _w) = link.into_parts();
    }
}

//! Blackhole dispatcher：把 [`Handler`] 接入 [`DispatchHandler`]。
//!
//! 对应 Go `proxy/blackhole/blackhole.go::Handler.Process(ctx, link, dialer)`。
//!
//! ## 行为
//!
//! 与拨号型 outbound（DialBridge）不同：blackhole **不拨号**，直接接管 link：
//! 1. 把预置 [`ResponseConfig`] 写到 `link.writer`（如果有）；写后 sleep 1s 让客户端读走。
//! 2. 持续 drain `link.reader` 直到 EOF / 出错 / 超时。
//!     - TCP：drain 到 EOF。
//!     - UDP：drain 60s 后退出（Go 行为：UDP 客户端可能持续重发，留时间排空）。
//!
//! [`DispatchHandler`]: xray_app_dispatcher::default::DispatchHandler

use std::{sync::Arc, time::Duration};

use xray_app_dispatcher::default::{DispatchHandler, PinFuture};
use xray_common::net::{destination::Destination, network::Network};
use xray_proto::xray::proxy::blackhole::Config;
use xray_transport::link::Link;

use crate::{
    BlackholeError,
    response::{ResponseConfig, get_internal_response},
};

/// 写完响应后让客户端读走的等待时间（与 Go `time.Sleep(time.Second)` 一致）。
const RESPONSE_SETTLE: Duration = Duration::from_secs(1);

/// UDP drain 空闲超时。Go `signal.CancelAfterInactivity` 是空闲计时器（30+dice.Roll(61)
/// 秒 = 30-90s）；Rust tokio 无内置 inactivity timer，固定上限取中位数 60s。
/// 客户端持续重发时按本上限退出（防单连接无限挂）。
const UDP_DRAIN: Duration = Duration::from_secs(60);

/// TCP drain 上限。Go `Process` 没有超时，靠 `common.Interrupt` defer 关 reader；
/// Rust 用 `Duration::MAX` 与 Go 等价但永远不关易挂——折中给一个保守上限
/// （5min 远超正常 EOF，又不至于真挂死）。客户端主动断 → EOF → 立即返回。
const TCP_DRAIN_MAX: Duration = Duration::from_secs(300);
/// Blackhole 出站 handler，impl [`DispatchHandler`]。
///
/// 对应 Go `proxy/blackhole.Handler`。`tag` 由注册时给出，`response` 来自
/// [`Config`] 解析（None / Http403）。
pub struct BlackholeHandler {
    tag: String,
    response: ResponseConfig,
}

impl BlackholeHandler {
    /// 从 protobuf [`Config`] 构造。
    ///
    /// 对应 Go `New(ctx, config)`——`ctx` 未使用故省略。
    pub fn new(tag: impl Into<String>, config: Config) -> Result<Self, BlackholeError> {
        Ok(Self { tag: tag.into(), response: get_internal_response(&config)? })
    }

    /// 用显式 [`ResponseConfig`] 构造（测试 / 上层 adapter 复用）。
    #[must_use]
    pub fn with_response(tag: impl Into<String>, response: ResponseConfig) -> Self {
        Self { tag: tag.into(), response }
    }

    /// 暴露响应配置（测试用）。
    pub fn response(&self) -> ResponseConfig {
        self.response.clone()
    }
}

impl std::fmt::Debug for BlackholeHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlackholeHandler")
            .field("tag", &self.tag)
            .field("response", &self.response)
            .finish()
    }
}

impl DispatchHandler for BlackholeHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn dispatch(&self, dest: &Destination, link: Link) -> PinFuture<()> {
        let response = self.response.clone();
        // edwo：TCP drain 上限封顶（之前 Duration::MAX 在客户端永不 EOF 时挂死）。
        // 5 分钟上限远超正常 EOF 时间；客户端主动断 / EOF 仍立即返回。
        let drain_timeout = if dest.network() == Network::UDP { UDP_DRAIN } else { TCP_DRAIN_MAX };
        let tag = self.tag.clone();
        Box::pin(async move {
            let mut writer = link.writer;
            let mut reader = link.reader;

            // 1. 写预置响应（若有）
            if !response.is_empty() {
                if let Err(e) = response.write_to(&mut writer).await {
                    tracing::warn!(tag = %tag, "blackhole write response: {e}");
                }
                // ponytail: Go sleep 1s 让客户端把响应读走，再开始 drain
                tokio::time::sleep(RESPONSE_SETTLE).await;
            }
            drop(writer);

            // 2. drain reader（Go Process 里 buf.Copy(link.Reader, buf.Discard)）
            loop {
                match tokio::time::timeout(drain_timeout, reader.read_multi_buffer()).await {
                    Ok(Ok(_)) => {}, // drain 一帧
                    Ok(Err(_)) | Err(_) => break,
                }
            }
        })
    }
}

/// 构造 [`BlackholeHandler`] 的 `Arc<dyn DispatchHandler>`，便于直接注册到 ohm。
///
/// [`DispatchHandler`]: xray_app_dispatcher::default::DispatchHandler
pub fn make_blackhole_handler(
    tag: impl Into<String>,
    config: Config,
) -> Result<Arc<dyn DispatchHandler>, BlackholeError> {
    Ok(Arc::new(BlackholeHandler::new(tag, config)?))
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Instant,
    };

    use xray_buf::{
        io::{self, Reader, Writer},
        multi::MultiBuffer,
    };
    use xray_common::net::{address::Address, port::Port};

    use super::*;

    /// 立即返回错误的 reader（模拟 EOF / 已关闭）。
    struct EofReader;
    impl Reader for EofReader {
        fn read_multi_buffer<'a>(
            &'a mut self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<MultiBuffer>> + Send + 'a>>
        {
            Box::pin(async { Err(io::Error::ReadError("eof".into())) })
        }
    }

    /// 计数所有写入字节数的 writer。
    struct CountingWriter(Arc<AtomicUsize>);
    impl Writer for CountingWriter {
        fn write_multi_buffer<'a>(
            &'a mut self,
            mb: MultiBuffer,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + 'a>>
        {
            let n = mb.iter().map(|b| b.bytes().len()).sum::<usize>();
            self.0.fetch_add(n, Ordering::Relaxed);
            Box::pin(async { Ok(()) })
        }
    }

    fn tcp_dest() -> Destination {
        Destination::new(Address::new_domain("example.com"), Port::new(443), Network::TCP)
    }

    #[tokio::test]
    async fn none_response_with_eof_reader_returns_fast() {
        // None response → 不写、不 sleep；EOF reader → drain 立即 break
        let handler = BlackholeHandler::with_response("bh", ResponseConfig::None);
        let link =
            Link::new(Box::new(EofReader), Box::new(CountingWriter(Arc::new(AtomicUsize::new(0)))));
        let start = Instant::now();
        handler.dispatch(&tcp_dest(), link).await;
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "none response + EOF reader 应立即返回，实际 {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn http_response_writes_403_and_settles_before_drain() {
        use crate::response::HTTP_403_RESPONSE;
        let handler = BlackholeHandler::with_response("bh", ResponseConfig::Http403);
        let counter = Arc::new(AtomicUsize::new(0));
        let link = Link::new(Box::new(EofReader), Box::new(CountingWriter(counter.clone())));
        let start = Instant::now();
        handler.dispatch(&tcp_dest(), link).await;
        assert_eq!(
            counter.load(Ordering::Relaxed),
            HTTP_403_RESPONSE.len(),
            "应写入完整 HTTP 403 响应"
        );
        assert!(
            start.elapsed() >= RESPONSE_SETTLE,
            "写完响应应 sleep RESPONSE_SETTLE，实际 {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn udp_dest_eof_reader_still_returns_fast() {
        // UDP dest 用 60s 超时——但 EOF reader 立即 break，不等超时
        let handler = BlackholeHandler::with_response("bh", ResponseConfig::None);
        let dest =
            Destination::new(Address::new_domain("example.com"), Port::new(443), Network::UDP);
        let link =
            Link::new(Box::new(EofReader), Box::new(CountingWriter(Arc::new(AtomicUsize::new(0)))));
        let start = Instant::now();
        handler.dispatch(&dest, link).await;
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "EOF reader 即使 UDP 也应立即返回（drain 不等待超时）"
        );
    }

    #[test]
    fn new_from_config_accepts_none_response() {
        let config = Config { response: None };
        let h = BlackholeHandler::new("bh", config).unwrap();
        assert_eq!(h.tag(), "bh");
        assert_eq!(h.response(), ResponseConfig::None);
    }

    #[test]
    fn new_from_config_accepts_empty_type() {
        let config =
            Config { response: Some(crate::response::proto_response(String::new(), Vec::new())) };
        let h = BlackholeHandler::new("bh", config).unwrap();
        assert_eq!(h.response(), ResponseConfig::None);
    }

    #[test]
    fn new_from_config_accepts_http_response_type() {
        let config =
            Config { response: Some(crate::response::proto_response("http".into(), Vec::new())) };
        let h = BlackholeHandler::new("bh", config).unwrap();
        assert_eq!(h.response(), ResponseConfig::Http403);
    }

    #[test]
    fn new_rejects_unknown_response_type() {
        let config =
            Config { response: Some(crate::response::proto_response("bogus".into(), Vec::new())) };
        let r = BlackholeHandler::new("bh", config);
        assert!(matches!(r, Err(BlackholeError::UnknownResponseType(_))));
    }

    #[test]
    fn make_handler_returns_arc_dyn() {
        let config = Config { response: None };
        let h = make_blackhole_handler("test", config).unwrap();
        assert_eq!(h.tag(), "test");
    }

    #[test]
    fn debug_includes_tag_and_response() {
        let h = BlackholeHandler::with_response("bh", ResponseConfig::Http403);
        let s = format!("{h:?}");
        assert!(s.contains("bh"));
        assert!(s.contains("Http403"));
    }
}

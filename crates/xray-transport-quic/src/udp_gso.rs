//! QUIC 路径 UDP GSO（UDP_SEGMENT）接线与禁用开关。票 D-6b。
//!
//! ## 票面修正（考古实锤）
//!
//! 票面称 "quinn-udp 0.6 无 GSO API，需自实现"。实际依赖为 **quinn-udp 0.5.15**
//! （quinn 0.11.11 锁定），其 `UdpSocketState::new` 构造时即探测 GSO：
//! 内核 ≥4.18 且 `setsockopt(UDP_SEGMENT)` 成功 → `max_gso_segments = 64`；
//! 失败 → 1（优雅回退，非 panic，unix.rs:817-841）；运行中 sendmsg EINVAL
//! 还会自动降级为 1（unix.rs:352-359）。quinn 默认 socket 路径
//! （`Endpoint::client`/`server`）**在 Linux 上本就默认启用 GSO**。
//!
//! 因此本模块职责收敛为两件事：
//!
//! 1. **禁用开关**：`disableGSO`（Go `QuicParams.disableGSO` parity，默认
//!    false = 启用）。启用路径 = 现状默认路径，零改动。
//! 2. **禁用接线**：quinn 的 tokio socket 实现是私有类型，唯一公共注入点是
//!    `Runtime::wrap_udp_socket → Arc<dyn AsyncUdpSocket>` +
//!    `Endpoint::new_with_abstract_socket`。[`NoGsoSocket`] 薄包装把
//!    `max_transmit_segments()` 钳到 1（quinn 发送端因此不产生多段
//!    Transmit → 不打 UDP_SEGMENT cmsg = 关发送 GSO），其余全部转发。
//!    接收侧 GRO（`max_receive_segments`）不受影响，与 quic-go
//!    `DisableGSO` 只关发送的语义一致。
//!
//! 分段安全：多段打包/stride 递进全部由 quinn/quinn-udp 内部处理，本模块
//! 不碰 Transmit 内容；包装为全平台无 cfg 分叉（非 Linux 平台该值本就为 1，
//! 包装无副作用）。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{
    AsyncUdpSocket, Endpoint, EndpointConfig, Runtime, ServerConfig, TokioRuntime, UdpPoller,
};

/// 禁用发送 GSO 的 socket 薄包装：`max_transmit_segments()` 恒 1，其余全转发。
#[derive(Debug)]
pub(crate) struct NoGsoSocket {
    inner: Arc<dyn AsyncUdpSocket>,
}

impl NoGsoSocket {
    /// 包装一个已探测过能力的 socket（`wrap_udp_socket` 的产物）。
    pub(crate) fn new(inner: Arc<dyn AsyncUdpSocket>) -> Self {
        Self { inner }
    }
}

impl AsyncUdpSocket for NoGsoSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

/// 构造 QUIC endpoint（dial 传 `None`，listen 传 `Some`）。
///
/// socket 统一经 [`xray_transport::sockopt::bind_udp_endpoint`] 创建：bind 前
/// 应用 UDP 端点缓冲（显式 sockopt 值优先，缺省走 Go quic-go `wrapConn` 8MB
/// 下限语义，见 sockopt 模块 doc）。
///
/// `disable_gso = false`（默认）：quinn 默认 wrap 路径——Linux 上
/// quinn-udp 构造时探测 UDP_SEGMENT 并启用 GSO，内核不支持自动回退单段。
/// `disable_gso = true`：经 [`NoGsoSocket`] 注入，钳多段 Transmit。
pub(crate) fn make_endpoint(
    server_config: Option<ServerConfig>,
    local: SocketAddr,
    disable_gso: bool,
    sockopt: &xray_transport::sockopt::SocketOptions,
) -> io::Result<Endpoint> {
    let std_sock = xray_transport::sockopt::bind_udp_endpoint(local, sockopt)?;
    let runtime: Arc<dyn Runtime> = Arc::new(TokioRuntime);
    if !disable_gso {
        return Endpoint::new(EndpointConfig::default(), server_config, std_sock, runtime);
    }
    let inner = runtime.wrap_udp_socket(std_sock)?;
    let socket: Arc<dyn AsyncUdpSocket> = Arc::new(NoGsoSocket::new(inner));
    Endpoint::new_with_abstract_socket(EndpointConfig::default(), server_config, socket, runtime)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrap_local() -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0")?;
        sock.set_nonblocking(true)?;
        TokioRuntime.wrap_udp_socket(sock)
    }

    /// 禁用开关语义：包装后 max_transmit_segments 恒 1，转发方法健全。
    #[tokio::test]
    async fn no_gso_wrapper_clamps_transmit_segments() {
        let inner = wrap_local().unwrap();
        let base = inner.max_transmit_segments();
        assert!(base >= 1, "kernel probe must report >= 1, got {base}");
        let wrapped = NoGsoSocket::new(inner.clone());
        assert_eq!(wrapped.max_transmit_segments(), 1);
        // 其余能力转发不丢：GRO 接收段数与分片语义与底层一致。
        assert_eq!(wrapped.max_receive_segments(), inner.max_receive_segments());
        assert_eq!(wrapped.may_fragment(), inner.may_fragment());
        assert_eq!(
            wrapped.local_addr().unwrap(),
            inner.local_addr().unwrap(),
        );
    }

    /// Linux GSO 默认启用实证：现代内核（≥4.18）探测应报 >1 段。
    /// sing-box #4222 类内核不支持场景由 quinn-udp 构造期回退（1 段）兜底。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn gso_probe_reports_kernel_capability() {
        let inner = wrap_local().unwrap();
        let segs = inner.max_transmit_segments();
        assert!(
            segs > 1,
            "Linux kernel >= 4.18 expected to support UDP_SEGMENT GSO, got {segs} segments"
        );
    }

    /// 禁用路径 endpoint 可构造（全平台：Windows 上 wrap_udp_socket 走
    /// quinn-udp windows.rs，无 UDP_SEGMENT 概念，包装无副作用）。
    #[tokio::test]
    async fn make_endpoint_disabled_gso_binds() {
        let ep = make_endpoint(None, "127.0.0.1:0".parse().unwrap(), true, &Default::default()).unwrap();
        let addr = ep.local_addr().unwrap();
        assert!(addr.port() > 0);
    }
}

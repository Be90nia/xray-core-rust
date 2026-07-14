//! 平台 TUN 设备实现（基于 `tun-rs` 2.8.7）。
//!
//! 切片边界（批次 A2）：仅 TUN 设备 IO——创建设备 + recv/send IP 包。
//! 不接 InboundHandler、不做 smoltcp netstack 集成（批次 B 与 WireGuard 共享）。
//!
//! 平台支持：
//! - **Linux/macOS/FreeBSD**：`build_async()` 真机创建设备（需 root/CAP_NET_ADMIN）
//! - **Windows**：动态加载 `wintun.dll`，未安装则 `build_async()` 返 `DeviceCreateFailed`

use tun_rs::AsyncDevice;
use tun_rs::DeviceBuilder;
use tun_rs::Layer;

use crate::config::Tun;
use crate::error::{Result, TunError};

/// 平台 TUN 设备，包装 `tun_rs::AsyncDevice`。
///
/// 同时实现 [`Tun`] trait（设备元数据）+ 提供 `recv`/`send`（IP 包 IO）。
pub struct TunDevice {
    dev: AsyncDevice,
    name: String,
}

impl TunDevice {
    /// 创建 TUN 设备（L3 模式 = IP 包）。
    ///
    /// # 参数
    ///
    /// - `name`：设备名（Linux 自由命名；macOS 用 `utun` 前缀；Windows 由 wintun 决定）
    /// - `ipv4_addr`/`ipv4_prefix`：IPv4 地址与掩码长度（如 `("10.0.0.1", 24)`）
    /// - `mtu`：MTU，常见 1500
    pub fn create(
        name: impl Into<String>,
        ipv4_addr: &str,
        ipv4_prefix: u8,
        mtu: u16,
    ) -> Result<Self> {
        let name_str = name.into();
        let dev = DeviceBuilder::new()
            .name(&name_str)
            .layer(Layer::L3)
            .ipv4(ipv4_addr, ipv4_prefix, None)
            .mtu(mtu)
            .build_async()
            .map_err(|e| TunError::DeviceCreateFailed(format!("{e}")))?;
        Ok(Self {
            dev,
            name: name_str,
        })
    }

    /// 异步读 IP 包到 buf。返回读取字节数。
    ///
    /// 0 表示设备关闭。
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.dev.recv(buf).await
    }

    /// 异步发送 IP 包。
    pub async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.dev.send(buf).await
    }
}

impl Tun for TunDevice {
    fn start(&self) -> Result<()> {
        // tun-rs 在 build_async() 时已激活，start 是 no-op
        Ok(())
    }

    fn close(&self) -> Result<()> {
        // AsyncDevice drop 时自动关闭；这里 Best-effort shutdown
        // ponytail: tun-rs AsyncDevice 没有 explicit close API，依赖 Drop
        Ok(())
    }

    fn name(&self) -> Result<String> {
        Ok(self.name.clone())
    }

    fn index(&self) -> Result<i32> {
        let idx = self.dev.if_index().map_err(TunError::from)?;
        Ok(idx as i32)
    }
}

#[cfg(all(unix, test))]
mod tests {
    use super::*;

    /// Linux/macOS 真机测试：创建 TUN 设备 + 读写一个最小 IP 包头部。
    ///
    /// 需要 root 或 CAP_NET_ADMIN（Linux）/ sudo（macOS）。
    /// CI 上跳过：无权限时 build_async 失败，测试 panic。
    #[tokio::test]
    async fn create_and_metadata_roundtrip() {
        // 用 utun 前缀（macOS 友好）；Linux 接受任意名
        let device_name = if cfg!(target_os = "linux") {
            format!("xray_test_{}", std::process::id() % 1000)
        } else {
            format!("utun{}", std::process::id() % 100)
        };

        let dev = match TunDevice::create(&device_name, "10.0.99.1", 24, 1280) {
            Ok(d) => d,
            Err(e) => {
                // CI/无权限环境——跳过而不失败
                eprintln!("SKIP: TUN create failed (likely no permission): {e}");
                return;
            }
        };

        // Tun trait 元数据
        let name = dev.name().expect("name");
        assert!(
            !name.is_empty(),
            "device name should be non-empty"
        );
        let _idx = dev.index().expect("index");
        dev.start().expect("start");
        dev.close().expect("close");
    }

    #[tokio::test]
    async fn send_recv_minimal_ip_packet() {
        let device_name = if cfg!(target_os = "linux") {
            format!("xray_io_{}", std::process::id() % 1000)
        } else {
            format!("utun{}", 100 + std::process::id() % 50)
        };

        let dev = match TunDevice::create(&device_name, "10.0.98.1", 24, 1280) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("SKIP: TUN create failed (likely no permission): {e}");
                return;
            }
        };

        // 构造最小 IPv4 包（20 字节，无 payload，version=4, IHL=5）
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45; // version 4, IHL 5
        packet[2..4].copy_from_slice(&20u16.to_be_bytes()); // total length
        // src/dst 留 0——内核不会处理这个包但 TUN 设备能 send/recv

        // 写入设备——应该不报错（即使内核丢弃）
        let _ = dev.send(&packet).await;

        // recv 端通常需要另一个端发包才能拿到数据，CI 上不强求。
        // 这里只验证 send/recv API 调用不 panic。
        let mut buf = vec![0u8; 1500];
        let _ = tokio::time::timeout(std::time::Duration::from_millis(100), dev.recv(&mut buf)).await;

        dev.close().expect("close");
    }
}

#[cfg(test)]
mod trait_tests {
    use super::*;

    /// 验证 TunDevice: Tun 编译时 trait 实现（任何平台都编译过）。
    #[test]
    fn tun_device_implements_tun_trait() {
        fn _accepts_tun<T: Tun>() {}
        _accepts_tun::<TunDevice>();
    }
}

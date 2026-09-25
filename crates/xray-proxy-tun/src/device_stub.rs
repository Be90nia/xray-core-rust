//! android/ios 平台 TUN 设备 stub。
//!
//! 移动端平台本无可直接创建的 TUN fd：Android 生态 = VpnService（宿主 App 建
//! TUN 后注入流量），iOS 生态 = NEPacketTunnelProvider（同理由宿主 App 注入）。
//! tun_rs 在这两个 target 上无 DeviceBuilder/Layer/if_index 导出，因此本 crate
//! 的 tun-rs 依赖按平台门控（见 Cargo.toml），android/ios 编译本 stub——保持
//! [`TunDevice`] 类型签名可编译（`TunInboundHandler` 等下游类型不变），任何
//! create/recv/send 返回 Unsupported 错误并注明宿主注入方案。

use crate::{
    config::Tun,
    error::{Result, TunError},
};

const UNSUPPORTED: &str =
    "tun unsupported on this platform; Android=VpnService / iOS=NEPacketTunnelProvider 宿主注入";

/// 平台 TUN 设备 stub（android/ios）——所有 IO 返回 Unsupported。
#[derive(Debug, Clone, Copy, Default)]
pub struct TunDevice;

impl TunDevice {
    /// 创建 TUN 设备——移动端永远返回 [`TunError::DeviceCreateFailed`]。
    pub fn create(
        _name: impl Into<String>,
        _ipv4_addr: &str,
        _ipv4_prefix: u8,
        _mtu: u16,
    ) -> Result<Self> {
        Err(TunError::DeviceCreateFailed(UNSUPPORTED.into()))
    }

    /// 异步读 IP 包——Unsupported。
    pub async fn recv(&self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, UNSUPPORTED))
    }

    /// 非阻塞读 IP 包——Unsupported。
    pub fn try_recv(&self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, UNSUPPORTED))
    }

    /// 异步发送 IP 包——Unsupported。
    pub async fn send(&self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, UNSUPPORTED))
    }

    /// 非阻塞发送 IP 包——Unsupported。
    pub fn try_send(&self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, UNSUPPORTED))
    }
}

impl Tun for TunDevice {
    fn start(&self) -> Result<()> {
        Err(TunError::DeviceCreateFailed(UNSUPPORTED.into()))
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }

    fn name(&self) -> Result<String> {
        Err(TunError::DeviceNotFound(UNSUPPORTED.into()))
    }

    fn index(&self) -> Result<i32> {
        Err(TunError::DeviceNotFound(UNSUPPORTED.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// stub 的 Tun trait 实现必须在编译期可用（与真实现同签名面）。
    #[test]
    fn tun_device_stub_implements_tun_trait() {
        fn _accepts_tun<T: Tun>() {}
        _accepts_tun::<TunDevice>();
    }

    /// create 必须报 Unsupported 语义（DeviceCreateFailed + 宿主注入提示）。
    #[test]
    fn create_returns_unsupported() {
        let err =
            TunDevice::create("xray0", "10.0.0.1", 24, 1500).err().expect("stub create must fail");
        assert!(format!("{err}").contains("VpnService"), "got: {err}");
    }
}

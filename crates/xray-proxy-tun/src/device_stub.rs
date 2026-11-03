//! android/ios 平台 TUN 设备。
//!
//! 移动端平台本无可直接创建的 TUN fd：Android 生态 = VpnService（宿主 App 建
//! TUN 后注入流量），iOS 生态 = NEPacketTunnelProvider（同理由宿主 App 注入）。
//! tun_rs 在这两个 target 上无 DeviceBuilder/Layer/if_index 导出，因此本 crate
//! 的 tun-rs 依赖按平台门控（见 Cargo.toml），android/ios 编译本 stub——保持
//! [`TunDevice`] 类型签名可编译（`TunInboundHandler` 等下游类型不变）。
//!
//! iOS：宿主注入通道尚未实现 → 全部 IO 返回 Unsupported。
//!
//! Android（bd 2ub2n）：宿主（`VpnService`）建 TUN fd → 按**既有 env 机制**
//! （`xray.tun.fd` / `XRAY_TUN_FD`，见 [`crate::tun_fd`]）把 fd 号告知核心
//! 进程 → 核心校验后**接管 fd 副本**（`F_DUPFD_CLOEXEC`，宿主原 fd 不受影响，
//! 对齐 Go `proxy/tun/tun_android.go`）→ 核心在该 fd 上收发裸 IP 包。
//! env 设置但校验失败 ⇒ **显式报错，绝不回退直开**（与 Linux 路径同一纪律）。
//! Android 无 `/dev/net/tun` 直开路径（应用沙箱内不可创建）⇒ env 未设置即报错。

/// Android 接管 fd 副本后转为 `File`（所有权移交 reactor 注册层）。
#[cfg(target_os = "android")]
use std::os::fd::FromRawFd;

use crate::{
    config::Tun,
    error::{Result, TunError},
};

/// iOS stub 的统一错误文案（Android 面已接管真实 fd，不再用此文案）。
#[cfg(not(target_os = "android"))]
const UNSUPPORTED: &str =
    "tun unsupported on this platform; Android=VpnService / iOS=NEPacketTunnelProvider 宿主注入";

/// 平台 TUN 设备（Android：宿主注入 fd 接管；iOS：恒 Unsupported stub）。
#[cfg_attr(not(target_os = "android"), derive(Debug, Clone, Copy, Default))]
#[cfg_attr(target_os = "android", derive(Debug))]
pub struct TunDevice {
    /// Android：接管后的 fd 副本（`create` 期注册进 reactor，恒有效）。
    #[cfg(target_os = "android")]
    dev: tokio::io::unix::AsyncFd<std::fs::File>,
    /// Android：`TUNGETIFF` 读回的设备实际名（如 `tun0`）——宿主自定，与配置
    /// `name` 无关（对齐 Go `tun_android.go` 的 `Name()`）。
    #[cfg(target_os = "android")]
    name: String,
}

// ---------------------------------------------------------------- Android --

#[cfg(target_os = "android")]
impl TunDevice {
    /// 创建 TUN 设备：接管宿主（`VpnService`）注入的 TUN fd。
    ///
    /// env 契约与 Linux 路径同源（[`crate::tun_fd`]）：env 设置即进入继承路径，
    /// 校验失败即报错；env 未设置时 Android **无直开路径**（应用沙箱内无法
    /// 创建 `/dev/net/tun`）⇒ 显式报错要求宿主注入。
    pub fn create(
        _name: impl Into<String>,
        _ipv4_addr: &str,
        _ipv4_prefix: u8,
        _mtu: u16,
    ) -> Result<Self> {
        let Some(inherited) = crate::tun_fd::inherit_from_env("")? else {
            return Err(TunError::DeviceCreateFailed(
                "Android: no TUN fd injected — the host app (VpnService) must pass the fd \
                 number via xray.tun.fd / XRAY_TUN_FD"
                    .into(),
            ));
        };
        // AsyncFd 注册需要 tokio reactor（runtime 上下文）——缺失时报错而非 panic。
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(TunError::DeviceCreateFailed(
                "Android: adopting the injected TUN fd requires a tokio runtime context".into(),
            ));
        }
        // SAFETY: `inherit_from_env` 在 Android 策略下交付的是 `dup_cloexec`
        // 产出的**副本**（宿主原 fd 不受影响，Go 同）；该副本所有权移交本层，
        // 由 `File` 的 drop 关闭（宿主原 fd 始终不受影响）。
        let file = unsafe { std::fs::File::from_raw_fd(inherited.fd) };
        // SAFETY: file 所有权随 AsyncFd 转移，其 fd 在生命周期内恒有效且不变
        // （tokio 1.54 `AsyncFd::new` 因 I/O safety 废弃，走 `register`）。
        let dev = unsafe { tokio::io::unix::AsyncFd::register(file) }.map_err(|e| {
            TunError::DeviceCreateFailed(format!(
                "xray.tun.fd: register injected fd {} with the async reactor failed: {}",
                inherited.fd,
                e.into_parts().1
            ))
        })?;
        Ok(Self { dev, name: inherited.name })
    }

    /// 读一个裸 IP 包（无 PI 头、无 virtio 头——该旗标在校验期已被拒绝）。
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let dev = &self.dev;
        loop {
            let mut guard = dev.readable().await?;
            match guard.try_io(|inner| {
                let mut file = inner.get_ref();
                std::io::Read::read(&mut file, buf)
            }) {
                Ok(result) => return result,
                // WouldBlock：readiness 已由 try_io 清除 → 重新等可读。
                Err(_would_block) => continue,
            }
        }
    }

    /// 非阻塞读一个裸 IP 包（无包可读即 WouldBlock）。
    pub fn try_recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let dev = &self.dev;
        dev.try_io(tokio::io::Interest::READABLE, |file| {
            let mut file = file;
            std::io::Read::read(&mut file, buf)
        })
    }

    /// 写一个裸 IP 包（注入宿主网络栈）。
    pub async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        let dev = &self.dev;
        loop {
            let mut guard = dev.writable().await?;
            match guard.try_io(|inner| {
                let mut file = inner.get_ref();
                std::io::Write::write(&mut file, buf)
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// 非阻塞写一个裸 IP 包。
    pub fn try_send(&self, buf: &[u8]) -> std::io::Result<usize> {
        let dev = &self.dev;
        dev.try_io(tokio::io::Interest::WRITABLE, |file| {
            let mut file = file;
            std::io::Write::write(&mut file, buf)
        })
    }
}

#[cfg(target_os = "android")]
impl Tun for TunDevice {
    fn start(&self) -> Result<()> {
        // fd 已在 create 期接管并注册进 reactor——start 是 no-op。
        Ok(())
    }

    fn close(&self) -> Result<()> {
        // fd 副本随 `TunDevice` drop 关闭（宿主原 fd 不受影响）。
        Ok(())
    }

    fn name(&self) -> Result<String> {
        Ok(self.name.clone())
    }

    fn index(&self) -> Result<i32> {
        // Go `tun_android.go`：`net.InterfaceByName(name).Index`。
        let iface =
            xray_common::net::interface::interface_by_name(&self.name).map_err(TunError::from)?;
        Ok(iface.index as i32)
    }
}

// -------------------------------------------------------------------- iOS --

#[cfg(not(target_os = "android"))]
impl TunDevice {
    /// 创建 TUN 设备——iOS 宿主注入通道未实现，恒 Unsupported。
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

#[cfg(not(target_os = "android"))]
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

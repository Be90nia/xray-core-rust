//! android/ios 平台 TUN 设备。
//!
//! 移动端平台本无可直接创建的 TUN fd：Android 生态 = VpnService（宿主 App 建
//! TUN 后注入流量），iOS 生态 = NEPacketTunnelProvider（同理由宿主 App 注入）。
//! tun_rs 在这两个 target 上无 DeviceBuilder/Layer/if_index 导出，因此本 crate
//! 的 tun-rs 依赖按平台门控（见 Cargo.toml），android/ios 编译本 stub——保持
//! [`TunDevice`] 类型签名可编译（`TunInboundHandler` 等下游类型不变）。
//!
//! iOS（**Rust 超集 · 无 Go 基线**）：Go 没有任何 iOS TUN 实现
//! （`proxy/tun/tun_default.go` 构建标签覆盖 iOS ⇒ `NewTun` 返回 not supported），
//! 本面设计依据只有 Apple 平台事实：
//! - 宿主 `NEPacketTunnelProvider` 建 utun（`AF_SYSTEM` + `SYSPROTO_CONTROL`， 内核控制
//!   `com.apple.net.utun_control`）→ 同样按**既有 env 机制** （`xray.tun.fd` / `XRAY_TUN_FD`）把 fd
//!   号交给核心 → 核心校验后接管**副本** （见 [`crate::tun_fd`]）。
//! - utun 读写的每个包都带 **4 字节地址族头**（网络序 `AF_INET`=2 / `AF_INET6`=30）：
//!   读时由本层剥、写时前置（编解码在 [`crate::tun_fd::strip_family_header`] /
//!   [`crate::tun_fd::family_header_for`]，平台无关纯函数）。
//! - 写路径用 `write_vectored`（头 + 包两个 iovec，单 syscall、零分配）。
//! - iOS 沙箱同样建不出 TUN ⇒ env 未设置即报错要求宿主注入。
//!
//! Android（bd 2ub2n）：宿主（`VpnService`）建 TUN fd → 按**既有 env 机制**
//! （`xray.tun.fd` / `XRAY_TUN_FD`，见 [`crate::tun_fd`]）把 fd 号告知核心
//! 进程 → 核心校验后**接管 fd 副本**（`F_DUPFD_CLOEXEC`，宿主原 fd 不受影响，
//! 对齐 Go `proxy/tun/tun_android.go`）→ 核心在该 fd 上收发裸 IP 包。
//! env 设置但校验失败 ⇒ **显式报错，绝不回退直开**（与 Linux 路径同一纪律）。
//! Android 无 `/dev/net/tun` 直开路径（应用沙箱内不可创建）⇒ env 未设置即报错。

/// 接管 fd 副本后转为 `File`（所有权移交 reactor 注册层）。
use std::os::fd::FromRawFd;

use crate::{
    config::Tun,
    error::{Result, TunError},
};

/// 移动端 TUN 设备：宿主注入 fd 接管（Android `VpnService` / iOS `NEPacketTunnelProvider`）。
#[derive(Debug)]
pub struct TunDevice {
    /// 接管后的 fd 副本（`create` 期注册进 reactor，恒有效）。
    dev: tokio::io::unix::AsyncFd<std::fs::File>,
    /// 设备实际名（Android：`TUNGETIFF` 的 `tun0`；iOS：`UTUN_OPT_IFNAME` 的 `utunN`）
    /// ——宿主自定，与配置 `name` 无关。
    name: String,
}

// ------------------------------------------------- 移动端（android / ios）--

impl TunDevice {
    /// 创建 TUN 设备：接管宿主注入的 TUN fd。
    ///
    /// env 契约与 Linux 路径同源（[`crate::tun_fd`]）：env 设置即进入继承路径，
    /// 校验失败即报错；env 未设置时移动端**无直开路径**（应用沙箱内无法
    /// 创建 `/dev/net/tun`）⇒ 显式报错要求宿主注入。
    pub fn create(
        _name: impl Into<String>,
        _ipv4_addr: &str,
        _ipv4_prefix: u8,
        _mtu: u16,
        _ipv6_addrs: &[(std::net::Ipv6Addr, u8)],
    ) -> Result<Self> {
        let Some(inherited) = crate::tun_fd::inherit_from_env("")? else {
            return Err(TunError::DeviceCreateFailed(format!(
                "{}: no TUN fd injected — the host app (Android VpnService / iOS \
                 NEPacketTunnelProvider) must pass the fd number via xray.tun.fd / XRAY_TUN_FD",
                std::env::consts::OS
            )));
        };
        // AsyncFd 注册需要 tokio reactor（runtime 上下文）——缺失时报错而非 panic。
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(TunError::DeviceCreateFailed(format!(
                "{}: adopting the injected TUN fd requires a tokio runtime context",
                std::env::consts::OS
            )));
        }
        // SAFETY: `inherit_from_env` 在两平台策略下交付的都是 `dup_cloexec`
        // 产出的**副本**（宿主原 fd 不受影响）；该副本所有权移交本层，
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

    /// 读一个 IP 包。
    ///
    /// Android：裸 IP 包（无 PI 头、无 virtio 头——旗标在校验期已被拒绝）。
    /// iOS：utun 每包前置 4 字节地址族头，本层剥掉后才交给 netstack。
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let dev = &self.dev;
        loop {
            let mut guard = dev.readable().await?;
            match guard.try_io(|inner| {
                let mut file = inner.get_ref();
                std::io::Read::read(&mut file, buf)
            }) {
                Ok(Ok(n)) => return Self::decode(buf, n),
                Ok(Err(e)) => return Err(e),
                // WouldBlock：readiness 已由 try_io 清除 → 重新等可读。
                Err(_would_block) => continue,
            }
        }
    }

    /// 非阻塞读一个 IP 包（无包可读即 WouldBlock）。
    pub fn try_recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let dev = &self.dev;
        let n = dev.try_io(tokio::io::Interest::READABLE, |file| {
            let mut file = file;
            std::io::Read::read(&mut file, buf)
        })?;
        Self::decode(buf, n)
    }

    /// 写一个 IP 包（注入宿主网络栈）。
    ///
    /// iOS：前置 4 字节地址族头（`writev`，见 [`Self::write_pkt`]）。返回值恒为
    /// **IP 包字节数**（不含 iOS 的 4 字节头），两平台语义一致。
    pub async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        let dev = &self.dev;
        loop {
            let mut guard = dev.writable().await?;
            match guard.try_io(|inner| Self::write_pkt(inner.get_ref(), buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// 非阻塞写一个 IP 包。
    pub fn try_send(&self, buf: &[u8]) -> std::io::Result<usize> {
        let dev = &self.dev;
        dev.try_io(tokio::io::Interest::WRITABLE, |file| Self::write_pkt(file, buf))
    }

    /// 读回字节数 → 纯 IP 包长度。
    ///
    /// `n == 0` 是设备关闭语义（调用方据此报 `UnexpectedEof`），原样放行；
    /// 其余 iOS 包剥 utun 的 4 字节地址族头（族值非法即报错，见
    /// [`crate::tun_fd::strip_family_header`]）。Android 无前缀。
    fn decode(buf: &mut [u8], n: usize) -> std::io::Result<usize> {
        // iOS：`IOS_POLICY::has_family_header` 对应的一次剥头。
        #[cfg(target_os = "ios")]
        {
            if n > 0 {
                return crate::tun_fd::strip_family_header(buf, n);
            }
        }
        // Android 无前缀：buf 只为对称签名保留。
        #[cfg(target_os = "android")]
        let _ = buf;
        Ok(n)
    }

    /// 写一个包到设备 fd。
    ///
    /// iOS：utun 要求每包带 4 字节地址族头 ⇒ `write_vectored` 用
    /// `[头 | 包]` 两个 iovec 一次 `writev`（零分配、零拷贝，不需要垫头缓冲池）。
    /// utun 是报文语义，**短写即丢包 ⇒ 报错**，禁按「已发完」返回。
    /// Android：裸 `write`。
    fn write_pkt(file: &std::fs::File, buf: &[u8]) -> std::io::Result<usize> {
        #[cfg(target_os = "ios")]
        {
            use std::io::IoSlice;

            use crate::tun_fd::{FAMILY_HEADER_LEN, family_header_for};

            let header = family_header_for(buf).ok_or_else(|| {
                std::io::Error::other(format!(
                    "cannot write a {} byte packet to utun: first nibble is neither IPv4 nor IPv6",
                    buf.len()
                ))
            })?;
            let mut file = file;
            let written = std::io::Write::write_vectored(
                &mut file,
                &[IoSlice::new(&header), IoSlice::new(buf)],
            )?;
            let total = FAMILY_HEADER_LEN + buf.len();
            if written != total {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    format!("utun short write: {written} of {total} bytes"),
                ));
            }
            Ok(buf.len())
        }
        #[cfg(target_os = "android")]
        {
            let mut file = file;
            std::io::Write::write(&mut file, buf)
        }
    }
}

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
        // Go `tun_android.go`：`net.InterfaceByName(name).Index`（iOS 的 `utunN` 同走
        // `getifaddrs` 数据源，见 xray-common `interface_by_name`）。
        let iface =
            xray_common::net::interface::interface_by_name(&self.name).map_err(TunError::from)?;
        Ok(iface.index as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 移动端 `Tun` trait 实现必须在编译期可用（与真实现同签名面）。
    #[test]
    fn tun_device_stub_implements_tun_trait() {
        fn _accepts_tun<T: Tun>() {}
        _accepts_tun::<TunDevice>();
    }

    /// env 未给 fd 必须显式报错并要求宿主注入（移动端无直开路径）。
    #[test]
    fn create_without_injected_fd_reports_host_injection() {
        let _guard = crate::tun_fd::tests::lock_env();
        for key in crate::tun_fd::TUN_FD_KEYS {
            // SAFETY: 持 `lock_env` 串行，本进程内无并发读写这两个键。
            unsafe { std::env::remove_var(key) }
        }
        let err = TunDevice::create("xray0", "10.0.0.1", 24, 1500, &[])
            .err()
            .expect("无注入 fd 必须报错");
        let msg = format!("{err}");
        assert!(msg.contains("xray.tun.fd"), "got: {msg}");
        assert!(msg.contains("VpnService"), "got: {msg}");
    }

    /// env 值非法必须报配置错误（禁回退到「以为没注入了」的路径）。
    #[test]
    fn create_with_invalid_env_value_fails() {
        let _guard = crate::tun_fd::tests::lock_env();
        // SAFETY: 持 `lock_env` 串行，本进程内无并发读写这两个键。
        unsafe { std::env::set_var(crate::tun_fd::TUN_FD_KEYS[0], "nope") }
        let err =
            TunDevice::create("xray0", "10.0.0.1", 24, 1500, &[]).err().expect("非法 env 必须报错");
        // SAFETY: 同上。
        unsafe { std::env::remove_var(crate::tun_fd::TUN_FD_KEYS[0]) }
        assert!(format!("{err}").contains("is not a file descriptor number"), "got: {err}");
    }
}

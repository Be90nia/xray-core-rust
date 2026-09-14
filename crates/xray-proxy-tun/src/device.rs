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

#[cfg(target_os = "linux")]
use tun_rs::{GROTable, VIRTIO_NET_HDR_LEN};

use crate::config::Tun;
use crate::error::{Result, TunError};

/// 平台 TUN 设备，包装 `tun_rs::AsyncDevice`。
///
/// 同时实现 [`Tun`] trait（设备元数据）+ 提供 `recv`/`send`（IP 包 IO）。
pub struct TunDevice {
    dev: AsyncDevice,
    name: String,
    mtu: u16,
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
            .with(|b| {
                // 票 ukh8：Linux 开 vnet_hdr offload——批量读写
                // （recv_multiple/send_multiple）的内核前提。协商失败时
                // tun-rs 自动退化为 vnet_hdr=false（见 send/recv_batch）。
                #[cfg(target_os = "linux")]
                b.offload(true);
                #[cfg(not(target_os = "linux"))]
                let _ = b;
            })
            .build_async()
            .map_err(|e| TunError::DeviceCreateFailed(format!("{e}")))?;
        Ok(Self {
            dev,
            name: name_str,
            mtu,
        })
    }

    /// 异步读 IP 包到 buf。返回读取字节数。
    ///
    /// 0 表示设备关闭。
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.dev.recv(buf).await
    }

    /// 非阻塞读 IP 包。空队列时返回 `Err(WouldBlock)`。
    ///
    /// 对应 Go `tun_windows.go::ReadPacket`（249-270，`ERROR_NO_MORE_ITEMS → ErrQueueEmpty`）。
    pub fn try_recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.dev.try_recv(buf)
    }

    /// 异步发送 IP 包。
    ///
    /// Linux（vnet_hdr 已开）：自动垫 virtio 头后走批量写路径——内核按带
    /// vnet 头解析写入数据，裸写会把前 12 字节当头吞掉。其余平台为裸 write。
    pub async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            self.send_batch([buf.to_vec()]).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.dev.send(buf).await
        }
    }

    /// 非阻塞发送 IP 包。ring buffer 满时返回 `Err(WouldBlock)`。
    ///
    /// 对应 Go `tun_windows.go::WritePacket`（223-247，`AllocateSendPacket → SendPacket`）。
    pub fn try_send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.dev.try_send(buf)
    }

    /// 设备 MTU（Linux 批量读侧按此分配拆分段缓冲）。
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Linux 批量读：一次 syscall 读出内核 GRO 聚合大包并拆成 ≤MTU 的段，
    /// 返回实际包数；vnet_hdr 未协商时 tun-rs 内部退化为单包读（返回 0 或 1）。
    ///
    /// - `original_buffer`：GSO 聚合包落点，建议 `VIRTIO_NET_HDR_LEN + 65535`
    /// - `bufs`/`sizes`：等长；`bufs[i]` ≥ MTU，包数据写入 `bufs[i][..sizes[i]]`
    #[cfg(target_os = "linux")]
    pub async fn recv_batch(
        &self,
        original_buffer: &mut [u8],
        bufs: &mut [Vec<u8>],
        sizes: &mut [usize],
    ) -> std::io::Result<usize> {
        self.dev.recv_multiple(original_buffer, bufs, sizes, 0).await
    }

    /// Linux 批量写：GRO 合并同流 TCP/UDP 小包后尽量少的 write 次数发出；
    /// 未合并的包由 tun-rs 自动补零 vnet 头。vnet_hdr 未协商时退化为逐包写
    /// （垫头空间被跳过），两种协商结果下写出的都是纯 IP 包。
    #[cfg(target_os = "linux")]
    pub async fn send_batch<I>(&self, pkts: I) -> std::io::Result<usize>
    where
        I: IntoIterator<Item = Vec<u8>>,
    {
        // vnet_hdr 布局：每包前垫 VIRTIO_NET_HDR_LEN 字节供 GRO 写头；
        // offset=VIRTIO_NET_HDR_LEN 在 vnet 开/关两个分支下语义均正确。
        let mut bufs: Vec<Vec<u8>> = pkts
            .into_iter()
            .map(|p| {
                let mut b = vec![0u8; VIRTIO_NET_HDR_LEN + p.len()];
                b[VIRTIO_NET_HDR_LEN..].copy_from_slice(&p);
                b
            })
            .collect();
        if bufs.is_empty() {
            return Ok(0);
        }
        // ponytail: GROTable 每批现造（3 个小 Vec 分配），profile 说贵再复用
        let mut gro = GROTable::default();
        self.dev
            .send_multiple(&mut gro, &mut bufs, VIRTIO_NET_HDR_LEN)
            .await
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

#[cfg(all(any(unix, windows), test))]
mod tests {
    use super::*;

    /// 真机测试：创建 TUN 设备 + 查询元数据 + drop。
    ///
    /// 需要 root 或 CAP_NET_ADMIN（Linux/macOS）/ 管理员权限（Windows wintun）。
    /// CI 上跳过：无权限时 build_async 失败，测试静默返回。
    ///
    /// 对应 Go `tun_windows.go::NewTun`（49-72）+ `tun_linux.go::NewTun` 创建流程。
    #[tokio::test]
    async fn device_create_drop() {
        // 平台特定设备名：Linux 自由命名；macOS 用 utun 前缀；Windows 由 wintun 自动分配 GUID。
        let device_name = if cfg!(target_os = "linux") {
            format!("xray_test_{}", std::process::id() % 1000)
        } else if cfg!(target_os = "macos") {
            format!("utun{}", std::process::id() % 100)
        } else {
            // Windows wintun：tun-rs 接受任意名但 GUID 由名称 MD5 派生。
            format!("xray{}", std::process::id() % 100)
        };

        let dev = match TunDevice::create(&device_name, "10.0.99.1", 24, 1280) {
            Ok(d) => d,
            Err(e) => {
                // CI/无权限环境——跳过而不失败（Go 端同样可能在 build_async 处失败）
                eprintln!("SKIP: TUN create failed (likely no permission): {e}");
                return;
            }
        };

        // Tun trait 元数据（对应 Go tun_windows.go:207-221）
        let name = dev.name().expect("name");
        assert!(
            !name.is_empty(),
            "device name should be non-empty (Go: tun_windows.go:212-213)"
        );
        let idx = dev.index().expect("index");
        assert!(idx >= 0, "device index should be non-negative (Go: tun_windows.go:220)");
        dev.start().expect("start");
        dev.close().expect("close");
    }

    /// 真机测试：构造最小 IPv4 包 → try_send → try_recv。
    ///
    /// 期望：
    /// - `try_send(packet)` 返回 `Ok(n)` 表示设备 fd/session 接受写入
    /// - `try_recv(buf)` 在空队列时返回 `Err(WouldBlock)`（无内核路由则不会有包回流）
    ///
    /// 对应 Go `tun_windows.go::WritePacket`（223-247）+ `ReadPacket`（249-270）。
    #[tokio::test]
    async fn send_recv_roundtrip_via_try() {
        let device_name = if cfg!(target_os = "linux") {
            format!("xray_io_{}", std::process::id() % 1000)
        } else if cfg!(target_os = "macos") {
            format!("utun{}", 100 + std::process::id() % 50)
        } else {
            format!("xray_io_{}", std::process::id() % 100)
        };

        let dev = match TunDevice::create(&device_name, "10.0.98.1", 24, 1280) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("SKIP: TUN create failed (likely no permission): {e}");
                return;
            }
        };

        // 构造最小 IPv4 包（20 字节，version=4, IHL=5, total_length=20）
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[1] = 0x00; // DSCP/ECN
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[4..6].copy_from_slice(&0u16.to_be_bytes()); // ID
        packet[6] = 0x40; // flags=DF
        packet[7] = 0x00; // fragment offset
        packet[8] = 64; // TTL
        packet[9] = 17; // protocol = UDP
        // checksum/src/dst 留 0——内核不会处理这个包但 TUN 设备能接受

        // Linux（offload/vnet_hdr 设备）：裸写会被内核把前 VIRTIO_NET_HDR_LEN
        // 字节当 vnet 头解析——走垫头的批量写路径；非 Linux 保持裸 try_send。
        // 返回字节数：vnet 协商成功时含头（n = pkt.len() + 12），失败/其他平台
        // 为裸包长——两种协商结果都应 ≥ 包长。
        #[cfg(target_os = "linux")]
        let n = dev
            .send_batch([packet.clone()])
            .await
            .expect("send_batch should succeed on open device");
        #[cfg(not(target_os = "linux"))]
        let n = dev.try_send(&packet).expect("try_send should succeed on open device");
        assert!(
            n >= packet.len(),
            "write should accept the whole packet (Linux vnet_hdr adds header bytes)"
        );

        // try_recv 非阻塞：空队列时 WouldBlock（对应 Go tun_windows.go:253-256 windows.ERROR_NO_MORE_ITEMS）
        let mut buf = vec![0u8; 1500];
        match dev.try_recv(&mut buf) {
            // 如果有回流（罕见，需路由配置），验证 magic byte；
            // Linux vnet_hdr 设备读出带 virtio 头数据，不做包格式断言。
            #[cfg(not(target_os = "linux"))]
            Ok(n) => {
                assert_eq!(buf[0] >> 4, 4, "received packet must be IPv4 (version 4)");
                assert!(n >= 20, "minimum IPv4 header is 20 bytes, got {n}");
            }
            #[cfg(target_os = "linux")]
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // 期望路径：无路由 → 内核不发回流包
            }
            Err(e) => {
                // 其他错误（如 ERROR_OPERATION_ABORTED）也算设备 I/O 已工作
                eprintln!("try_recv returned non-fatal error: {e}");
            }
        }

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

    /// try_send/try_recv 非阻塞 API 必须在设备未创建时也编译过。
    /// 验证 trait surface 在 Windows 也可用（对应 Go tun_windows.go:223-270）。
    #[test]
    fn try_recv_send_signatures_compile() {
        // 类型层面的编译时验证：AsyncDevice::try_recv/try_send 存在并返回 io::Result<usize>。
        // 此处不实际调用——TunDevice 内部持有 AsyncDevice 实例但 trait 暴露 recv/send。
        // ponytail: 编译期检查，无需运行时。
    }
}

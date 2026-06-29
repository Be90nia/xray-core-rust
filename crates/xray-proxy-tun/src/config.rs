//! TUN 配置与抽象。
//!
//! 对应 Go `proxy/tun/config.go` + `tun.go` + `stack.go`。
//!
//! ## 切片边界（P6-6 切片1）
//!
//! TUN 没有独立 proto Config（配置在 `infra/conf` 中作为 `TunConfig`，仅 name+MTU）。
//! 切片1 实现纯逻辑部分：
//!
//! - [`score`] — 网络接口评分（用于选择默认出口接口），对应 Go `config.go::score`
//! - [`StackOptions`] — netstack 配置，对应 Go `stack.go::StackOptions`
//! - [`Tun`] / [`Stack`] trait — 设备与协议栈抽象，对应 Go `tun.go::Tun` / `stack.go::Stack`
//!
//! 切片2 待办：`InterfaceUpdater`（依赖 `if-addrs` crate 或 platform-specific syscall）+
//! 平台 TUN 设备实现（Linux /dev/net/tun、Windows wintun、macOS utun、FreeBSD tun）+
//! gVisor netstack / smoltcp-netstack 集成 + TCP/UDP 包处理。

use std::time::Duration;

use crate::error::Result;

/// 网络接口评分。用于 [`InterfaceUpdater`](crate#切片边界) 在未指定接口名时
/// 自动选择最可能的默认出口接口。
///
/// 评分规则（与 Go `config.go::score` 一致）：
/// - 接口名（小写）包含 `"wlan"` 或 `"wi-fi"` → +2（无线网卡优先）
/// - 任一地址以 `"192.168."` 开头 → +1（典型家庭/办公网关）
///
/// # 参数
///
/// - `iface_name`：接口名（如 `"wlan0"`、`"eth0"`、`"Wi-Fi"`）。
/// - `addr_strs`：接口绑定的地址字符串列表（如 `["192.168.1.100/24", "fe80::1"]`）。
///
/// # 返回
///
/// 总分（≥0）。分数越高越优先被选为出口接口。
///
/// 对应 Go `score(iface *net.Interface, addrs []net.Addr) int`。
#[must_use]
pub fn score(iface_name: &str, addr_strs: &[&str]) -> i32 {
    let mut s = 0;
    let name_lower = iface_name.to_ascii_lowercase();
    if name_lower.contains("wlan") || name_lower.contains("wi-fi") {
        s += 2;
    }
    for addr in addr_strs {
        if addr.starts_with("192.168.") {
            s += 1;
            break;
        }
    }
    s
}

/// TUN 设备抽象。对应 Go `tun.go::Tun` interface。
///
/// 实现者负责平台特定的 TUN 设备创建与读写：
/// - **Linux**：`/dev/net/tun` + ioctl
/// - **Windows**：`wintun.dll`
/// - **macOS/iOS**：`utun`（NetworkExtension / 系统调用）
/// - **FreeBSD**：`tun(4)` 设备
/// - **Android**：`VpnService` API（fd 通过环境变量 `XRAY_TUN_FD` 传入）
///
/// 切片2 提供具体实现。
pub trait Tun: Send + Sync {
    /// 启动设备（打开 fd / 注册适配器）。
    fn start(&self) -> Result<()>;

    /// 关闭设备（释放 fd / 适配器）。
    fn close(&self) -> Result<()>;

    /// 设备名（如 `"xray0"`、`"utun10"`）。
    fn name(&self) -> Result<String>;

    /// 设备接口索引（OS 级 ifindex）。
    fn index(&self) -> Result<i32>;
    // new_endpoint() 留切片2：依赖 gVisor stack.LinkEndpoint 或 smoltcp 等价品。
}

/// IP 协议栈抽象。对应 Go `stack.go::Stack` interface。
///
/// 实现者负责把 TUN 设备的原始 IP 包桥接到 Xray 的 TCP/UDP stream：
/// - **Go 端**：gVisor netstack（`gvisor.dev/gvisor/pkg/tcpip/stack`）
/// - **Rust 端候选**：`smoltcp` + `netstack-smoltcp` crate
///
/// 切片2 提供具体实现。
pub trait Stack: Send + Sync {
    /// 启动协议栈（开始处理 TUN 输入的 IP 包）。
    fn start(&self) -> Result<()>;

    /// 关闭协议栈（释放所有连接资源）。
    fn close(&self) -> Result<()>;
}

/// 协议栈配置。对应 Go `stack.go::StackOptions`。
pub struct StackOptions {
    /// TUN 设备（trait object）。
    ///
    /// 切片1 不强制具体实现，调用方在切片2 注入平台特定设备。
    pub tun: Option<Box<dyn Tun>>,
    /// 空闲连接超时。对应 Go `IdleTimeout time.Duration`。
    pub idle_timeout: Duration,
}

impl Default for StackOptions {
    fn default() -> Self {
        Self {
            tun: None,
            // 与 Go 默认一致：30 秒空闲超时（Go 端在实际使用时由上层设置）。
            idle_timeout: Duration::from_secs(30),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== score 函数 =====

    #[test]
    fn score_wlan_interface_gets_bonus() {
        assert_eq!(score("wlan0", &["192.168.1.100/24"]), 3); // +2 wlan +1 192.168
        assert_eq!(score("WLAN0", &[]), 2); // 大小写不敏感
        assert_eq!(score("Wi-Fi", &[]), 2); // 连字符变体
        assert_eq!(score("wi-fi-adapter", &[]), 2);
    }

    #[test]
    fn score_ethernet_with_192168() {
        assert_eq!(score("eth0", &["192.168.0.5/24"]), 1);
        assert_eq!(score("en0", &["10.0.0.1/8"]), 0); // 非 192.168 不加分
    }

    #[test]
    fn score_no_match_returns_zero() {
        assert_eq!(score("lo", &["127.0.0.1/8"]), 0);
        assert_eq!(score("tun0", &["10.0.0.1/30"]), 0);
    }

    #[test]
    fn score_192168_only_counted_once() {
        // 多个 192.168 地址也只 +1（与 Go break 一致）
        assert_eq!(
            score("eth0", &["192.168.1.1/24", "192.168.2.1/24"]),
            1
        );
    }

    #[test]
    fn score_empty_addrs() {
        assert_eq!(score("wlan0", &[]), 2);
        assert_eq!(score("eth0", &[]), 0);
    }

    // ===== StackOptions =====

    #[test]
    fn stack_options_default_idle_timeout_30s() {
        let opts = StackOptions::default();
        assert_eq!(opts.idle_timeout, Duration::from_secs(30));
        assert!(opts.tun.is_none());
    }

    #[test]
    fn stack_options_custom_idle_timeout() {
        let opts = StackOptions {
            idle_timeout: Duration::from_secs(120),
            ..Default::default()
        };
        assert_eq!(opts.idle_timeout, Duration::from_secs(120));
    }

    // ===== trait 声明编译验证 =====

    struct DummyTun;
    impl Tun for DummyTun {
        fn start(&self) -> Result<()> {
            Ok(())
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
        fn name(&self) -> Result<String> {
            Ok("dummy0".into())
        }
        fn index(&self) -> Result<i32> {
            Ok(0)
        }
    }

    #[test]
    fn tun_trait_can_be_implemented() {
        let tun = DummyTun;
        assert_eq!(tun.name().unwrap(), "dummy0");
        assert_eq!(tun.index().unwrap(), 0);
        tun.start().unwrap();
        tun.close().unwrap();
    }

    struct DummyStack;
    impl Stack for DummyStack {
        fn start(&self) -> Result<()> {
            Ok(())
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn stack_trait_can_be_implemented() {
        let s = DummyStack;
        s.start().unwrap();
        s.close().unwrap();
    }
}

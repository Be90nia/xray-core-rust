//! `xray.tun.fd` 继承——对应 Go `proxy/tun/tun_linux.go::openFromEnv`（L246-289）。
//!
//! 语义（逐条对齐 Go）：
//! - env 名原名优先：`xray.tun.fd`，兜底 `XRAY_TUN_FD`（Go `EnvFlag` 双查）。
//! - 值为已打开 TUN 设备的 fd 十进制数，必须 `>= 3`（0/1/2 是标准流）。
//! - **env 设置即进入继承路径**：任何校验失败都报错，绝不回退直开设备。
//! - env 未设置或为空串才直开（Go `GetValue` 空串 → `fdProvided=false`）。
//! - 校验：`TUNGETIFF` 须 `IFF_TUN` + `IFF_NO_PI`，设备名须与配置 `name` 一致。
//! - 末步置非阻塞（Go `unix.SetNonblock`）：tokio `AsyncFd` 的前提。
//!
//! # 平台面（真源——改实现必同步本表）
//!
//! | 平台 | fd 继承 | 校验手段 | 每包垫头 | 策略常量 |
//! |---|---|---|---|---|
//! | Linux | `inherit_from_env` | `TUNGETIFF`（须 `IFF_TUN` + `IFF_NO_PI`）| 无（带 `IFF_VNET_HDR` 时 10B virtio 头，`device.rs` 处理）| [`LINUX_POLICY`] |
//! | Android | `inherit_from_env` | `TUNGETIFF`（同上）| 无 | [`ANDROID_POLICY`] |
//! | iOS | `inherit_from_env` | `getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME)`（无 `TUNGETIFF`）| 4B 地址族头（本模块 [`strip_family_header`] / [`family_header_for`]）| [`IOS_POLICY`] |
//! | Windows / macOS / BSD | 未实现 | — | — | `refuse_unsupported` 显式报错 |
//!
//! - **Linux / Android**：`linux` 子模块 + `inherit_from_env`。两者同为 Linux 内核， `TUNGETIFF` /
//!   `fcntl` 的 ioctl 编码一致。
//! - **iOS**：`apple` 子模块 + `inherit_from_env`（契约见下节，**Rust 超集 · 无 Go 基线**）。
//! - **其他平台**（Windows/macOS/BSD）：env 设置即由 `refuse_unsupported` 显式报错，
//!   禁静默回退直开。
//!
//! Android 注入契约（Go `proxy/tun/tun_android.go::NewTun` 对齐）：
//! - 宿主（App 的 `VpnService`）建 TUN fd → 按**既有 env 机制**把 fd 号交给核心（`xray.tun.fd` /
//!   `XRAY_TUN_FD`）。核心与宿主同进程，fd 可用。
//! - 核心**接管 fd 副本**（`F_DUPFD_CLOEXEC`）：核心只关自己的副本，宿主原 fd 不受影响（Go：`the
//!   descriptor stays with the application`）。
//! - 设备名**不**与配置 `name` 比对（宿主自定接口名，如 `tun0`；Go 同）——策略 `ANDROID_POLICY` 的
//!   `compare_device_name = false` 表达。
//! - **拒绝 `IFF_VNET_HDR`**（`ANDROID_POLICY` 的 `allow_vnet_hdr = false`）：Go Android 走
//!   `newFdTun(fd, 0)`（无 virtio 头路径），Rust 侧照收会**静默错帧** ⇒
//!   显式报错，不静默按裸包解析。
//!
//! iOS 注入契约（**Rust 超集 · 无 Go 基线**）：
//! Go 侧没有任何 iOS TUN 实现——`proxy/tun/tun_default.go` 的构建标签
//! `!linux && !windows && !android && !darwin && !freebsd` 覆盖 iOS，`NewTun` 直接返回
//! `"Tun is not supported on your platform"`。本节与 [`IOS_POLICY`] 的设计依据只有
//! **Apple 平台事实**，没有 Go 可对拍（差异即设计，不是漂移）：
//! - **utun 不是 Linux 的 `IFF_TUN`**：宿主 `NEPacketTunnelProvider` 侧是 `socket(AF_SYSTEM /*32*/,
//!   SOCK_DGRAM, SYSPROTO_CONTROL /*2*/)` 绑定内核控制 `com.apple.net.utun_control`
//!   得到的**控制套接字**⇒ 没有 `TUNGETIFF`， 也没有 `IFF_TUN` / `IFF_NO_PI`
//!   旗标可校验。校验手段改为 `getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME
//!   /*2*/)`：该选项只在绑定到 utun 控制的内核套接字上成功，并返回接口名（`utunN`）⇒
//!   一次调用同时证明「是 utun」 并取到设备名。失败即报错，禁静默回退直开设备（iOS 沙箱内也开不出
//!   `/dev/net/tun`）。
//! - **每包 4 字节地址族头**：utun 读写都是 `[4B 地址族(网络序) | IP 包]`，族值为 `AF_INET`(2) /
//!   `AF_INET6`(30)。读剥写垫走本模块的平台无关纯函数 [`strip_family_header`] /
//!   [`family_header_for`]（Windows 可单测）。
//! - **不复用 vnet_hdr 垫头机制**（判定理由写在 [`family_header_for`] 文档）：语义不同
//!   （族值随包变化 vs 全零 virtio 头）、长度不同（4 vs 10）、且 `device.rs` 的 `hdr_free_list` 在
//!   iOS 不编译（iOS 走 `device_stub.rs`）。
//! - **接管 fd 副本**（[`IOS_POLICY`] `dup_fd = true`）：宿主仍持原 fd，核心只关副本。 Darwin
//!   `F_DUPFD_CLOEXEC` = **67**（Linux = 1030）。
//! - **不比对设备名**（`compare_device_name = false`）：`utunN` 由系统分配，让配置 `name`
//!   去匹配只会造出假匹配面。
//! - 末步置非阻塞：Darwin `O_NONBLOCK` = **`0x0004`**（Linux = `0o4000`）。
//!
//! 平台差异点集中在 [`InheritPolicy`]（Linux / Android / iOS 各一份常量），
//! Linux 策略 = 现网行为逐字不变。
//!
//! vnet_hdr 面（bd y93up，对齐 Go）：带 `IFF_VNET_HDR` 的继承 fd 照常接管。
//! tun-rs 的 `from_fd` 把设备记成裸包模式（读写原语 = 裸 read/write），因此
//! virtio 头的剥除/垫放由 [`crate::device::TunDevice`] 层处理（复用其垫头
//! free list）；`clear_offload` 在接管时清设备级 offload mask，保证继承读
//! 路径只见单包、不会收到内核 GRO 聚合大包。
//!
//! 该面**仅 Linux/Android**（`clear_offload` 是 `TUNSETOFFLOAD`，Apple 无对应 ioctl）；
//! iOS 的每包垫头是 4 字节地址族头，走本模块纯函数，与 virtio 头无关。

use crate::error::{Result, TunError};

/// Go `platform.TunFdKey` + 归一化名（`platform.NormalizeEnvName`）。
pub const TUN_FD_KEYS: [&str; 2] = ["xray.tun.fd", "XRAY_TUN_FD"];

/// 进程间传递的文件描述符编号（Windows 上无此语义，见 `refuse_unsupported`）。
pub type TunFd = i32;

/// 平台 fd 接管策略：Linux / Android / iOS 的语义差异点集中于此。
///
/// Linux 侧保持现网行为逐字不变；Android 侧对齐 Go `proxy/tun/tun_android.go`；
/// iOS 侧是 **Rust 超集**（Go 无 iOS TUN，依据 = Apple 平台事实，见模块头）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InheritPolicy {
    /// 是否比对设备名与配置 `name`（Android / iOS 宿主自定接口名 → 否）。
    pub compare_device_name: bool,
    /// 是否接管 fd 副本（Android / iOS：宿主仍持原 fd → 是，核心只关副本）。
    pub dup_fd: bool,
    /// 是否接受带 `IFF_VNET_HDR` 的 fd（Android 无 virtio 头路径 → 否）。
    pub allow_vnet_hdr: bool,
    /// 读写是否要剥/垫 4 字节地址族头（iOS utun → 是，见 [`family_header_len`]）。
    pub has_family_header: bool,
}

/// Linux 接管策略 = 现网行为（比对名 / 直接接管 / 接受 virtio 头 / 无族头）。
pub const LINUX_POLICY: InheritPolicy = InheritPolicy {
    compare_device_name: true,
    dup_fd: false,
    allow_vnet_hdr: true,
    has_family_header: false,
};

/// Android 接管策略（Go `proxy/tun/tun_android.go`）：不比对名 / 接管副本 / 拒 virtio 头。
pub const ANDROID_POLICY: InheritPolicy = InheritPolicy {
    compare_device_name: false,
    dup_fd: true,
    allow_vnet_hdr: false,
    has_family_header: false,
};

/// iOS utun 接管策略（**Rust 超集 · 无 Go 基线**）：不比对名 / 接管副本 /
/// 不可有 virtio 头 / 每包 4 字节地址族头。
///
/// 依据（Apple 平台事实，非 Go 对拍）：`utunN` 由系统分配（不比对名）；宿主
/// `NEPacketTunnelProvider` 仍持原 fd（接管副本）；utun 不是 tun/tap 设备、
/// 不存在 `IFF_VNET_HDR` 概念（拒）；utun 读写恒带 4 字节地址族头（须剥/垫）。
pub const IOS_POLICY: InheritPolicy = InheritPolicy {
    compare_device_name: false,
    dup_fd: true,
    allow_vnet_hdr: false,
    has_family_header: true,
};

/// 按策略算出应当比对的期望设备名（不比对时返回空串 ⇒ verify 跳过比对）。
#[must_use]
pub fn expected_name_for<'a>(policy: &InheritPolicy, configured: &'a str) -> &'a str {
    if policy.compare_device_name { configured } else { "" }
}

/// 按策略判定设备旗标是否可接管（`None` = 可接管；`Some(reason)` = 拒绝原因）。
///
/// 纯函数：可在任意平台（含 Windows）单测 Android 策略的旗标语义。
#[must_use]
pub fn flags_reject_reason(policy: &InheritPolicy, flags: u16) -> Option<&'static str> {
    // 与 Linux `verify` 的既有判定同源（IFF_TUN / IFF_NO_PI / IFF_VNET_HDR）。
    const IFF_TUN: u16 = 0x0001;
    const IFF_NO_PI: u16 = 0x1000;
    const IFF_VNET_HDR: u16 = 0x4000;

    if flags & IFF_TUN == 0 {
        return Some("is not a TUN device (IFF_TUN unset)");
    }
    if flags & IFF_NO_PI == 0 {
        return Some("TUN device must use IFF_NO_PI");
    }
    if !policy.allow_vnet_hdr && flags & IFF_VNET_HDR != 0 {
        return Some("carries IFF_VNET_HDR which is not supported on this platform");
    }
    None
}

// ------------------------------------------------- iOS 每包 4 字节地址族头 --
// 平台无关纯函数（**不带 cfg** ⇒ 每个平台都编译、Windows 可单测；iOS 侧由
// `device_stub.rs::TunDevice` 消费）。依据 = Apple utun 读写恒带 `[addr family | IP]`
// 前缀（xnu utun 控制套接字语义），不是 Linux tun 的 PI/virtio 头。
//
// 不带 cfg 的理由：带 cfg 会让模块头的 intra-doc 链接在非 iOS 平台的 docs 门
// （`cargo doc` + `deny(warnings)`）变成悬空链接而报硬错。

/// utun 每包前缀长度：4 字节地址族（网络序 32 位）。
pub const FAMILY_HEADER_LEN: usize = 4;

/// `AF_INET`（Darwin `sys/socket.h` = 2）。
const AF_INET: u32 = 2;

/// `AF_INET6`（Darwin = **30**；Linux 的 10 不适用——这是 utun 头里真实写入的族值）。
const AF_INET6: u32 = 30;

/// 按策略给出的每包前缀长度（0 = 无前缀）。
#[must_use]
pub fn family_header_len(policy: &InheritPolicy) -> usize {
    if policy.has_family_header { FAMILY_HEADER_LEN } else { 0 }
}

/// 剥除 utun 的 4 字节地址族头：`buf[..n]` 原地前移，返回 IP 包长度。
///
/// 校验族值（只接受 `AF_INET`(2) / `AF_INET6`(30)）：utun 头是唯一能区分 v4/v6 的
/// 依据，族值非法 = 帧已错位，必须报错而不是把错位数据当 IP 包交给 netstack。
/// `n <= 4`（只有头没有包）同判非法——与 `device.rs::strip_vnet` 的 `<= 头长` 纪律
/// 同型。`n == 0`（设备关闭语义）由调用方先放行，不进本函数。
pub fn strip_family_header(buf: &mut [u8], n: usize) -> std::io::Result<usize> {
    if n <= FAMILY_HEADER_LEN {
        return Err(std::io::Error::other(format!(
            "utun packet of {n} bytes is not longer than the {FAMILY_HEADER_LEN}-byte \
             address family header"
        )));
    }
    let family = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if family != AF_INET && family != AF_INET6 {
        return Err(std::io::Error::other(format!(
            "utun packet carries address family {family}, expected AF_INET({AF_INET}) \
             or AF_INET6({AF_INET6})"
        )));
    }
    buf.copy_within(FAMILY_HEADER_LEN..n, 0);
    Ok(n - FAMILY_HEADER_LEN)
}

/// 由 IP 包首个半字节（版本号）生成 utun 的 4 字节地址族头。
///
/// 发送方向必须前置该头：utun 靠它把包投进 v4/v6 栈，漏垫 = 内核把包首 4 字节
/// 当成族值吞掉。返回 `None` = 首字节既不是 v4 也不是 v6（调用方必须报错，
/// 禁静默发无头包）。
///
/// **为什么不复用 `device.rs` 的 vnet_hdr 垫头机制**（判定，禁翻案时重查）：
/// ① 语义不同——virtio 头恒全零、族值随包变化；② 长度不同（4 vs 10）；
/// ③ `hdr_free_list` 是 `device.rs` 的私有模块，而 iOS 走 `device_stub.rs`，
///    `device.rs` 在 iOS 不编译 ⇒ 复用需搬模块，收益仅为省一次 `writev`。
/// 实际实现走 `write_vectored`（头 + 包两个 iovec，单 syscall、零分配），
/// 不需要垫头缓冲池。
#[must_use]
pub fn family_header_for(pkt: &[u8]) -> Option<[u8; FAMILY_HEADER_LEN]> {
    match pkt.first().map(|b| b >> 4) {
        Some(4) => Some(AF_INET.to_be_bytes()),
        Some(6) => Some(AF_INET6.to_be_bytes()),
        _ => None,
    }
}

fn invalid(msg: String) -> TunError {
    TunError::InvalidConfig(format!("{}: {msg}", TUN_FD_KEYS[0]))
}

/// 继承/接管失败的设备错误（ioctl 类，非配置值类）。
fn device_err(msg: String) -> TunError {
    TunError::DeviceCreateFailed(format!("{}: {msg}", TUN_FD_KEYS[0]))
}

/// env 原值：原名优先、归一化名兜底（Go `EnvFlag.GetValue`）。
///
/// 每次现读不缓存：Go 在 `NewTun` 时读一次，进程启动路径只走一次，缓存无收益
/// 且会让测试无法复读。
#[must_use]
pub fn env_raw() -> Option<String> {
    TUN_FD_KEYS
        .iter()
        .find_map(|key| std::env::var_os(key).map(|v| v.to_string_lossy().into_owned()))
}

/// 解析 env 值 → fd 号（Go `strconv.Atoi` + `fd < 3` 两条检查）。
///
/// `Atoi` 的接受面照搬：可带 `+`/`-` 号，不去空白。
pub fn parse(raw: &str) -> Result<TunFd> {
    let fd = raw
        .parse::<TunFd>()
        .map_err(|_| invalid(format!("{raw:?} is not a file descriptor number")))?;
    if fd < 3 {
        return Err(invalid(format!("file descriptor must be >= 3, got {fd}")));
    }
    Ok(fd)
}

/// 读 env 并解析。
///
/// - `Ok(None)`：env 未设置或为空串 → 调用方直开设备（Go `fdProvided=false`）。
/// - `Ok(Some(fd))`：继承候选 fd（尚未校验是否为 TUN 设备）。
/// - `Err(..)`：env 设置但值非法 → 必须报错，不回退直开。
pub fn from_env() -> Result<Option<TunFd>> {
    match env_raw().as_deref() {
        None | Some("") => Ok(None),
        Some(raw) => parse(raw).map(Some),
    }
}

/// 平台无 fd 继承能力时的门闸：env 设置即显式报错，未设置返回 `Ok(())`（照常直开）。
#[cfg(not(any(target_os = "android", target_os = "linux", target_os = "ios")))]
pub fn refuse_unsupported() -> Result<()> {
    if env_raw().is_none_or(|v| v.is_empty()) {
        return Ok(());
    }
    Err(device_err(format!(
        "inheriting a pre-opened TUN fd is not implemented on {} in this build; \
         unset it so Xray opens the device itself",
        std::env::consts::OS
    )))
}

/// 继承来的 TUN 设备描述（Linux / Android / iOS）。
#[cfg(any(target_os = "linux", target_os = "android", target_os = "ios"))]
#[derive(Debug)]
pub struct InheritedTun {
    /// 已校验为 TUN 设备、且已置非阻塞的 fd。所有权**仍归宿主进程**：本函数不开
    /// 不关，接管方（`AsyncDevice::from_fd` / `AsyncFd::register`）负责关闭——与 Go
    /// 一致（校验失败时 Go 也不关 fd）。
    pub fd: TunFd,
    /// 设备实际接口名（Linux/Android：`TUNGETIFF` 回的 `ifr_name`；iOS：
    /// `getsockopt(UTUN_OPT_IFNAME)` 回的 `utunN`）。
    pub name: String,
    /// fd 携带 `IFF_VNET_HDR`（bd y93up）：接管方须剥头/垫头并先清 offload mask
    /// （`clear_offload`）。iOS 恒 `false`（utun 无 virtio 头，策略在校验期已拒）。
    pub vnet_hdr: bool,
}

/// 继承路径入口（Linux / Android / iOS）：读 env → 解析 → 校验 fd。
///
/// `expected_name` 为空表示配置未指定设备名（不校验）；非空时实际名必须一致
/// （Go `openFromEnv` 末段）。平台差异由 [`InheritPolicy`] 表达：Linux 用
/// [`LINUX_POLICY`]（比对名）；Android 用 [`ANDROID_POLICY`]、iOS 用 [`IOS_POLICY`]
/// （均不比对名，走 [`expected_name_for`] ⇒ 传空串）。
#[cfg(any(target_os = "linux", target_os = "android", target_os = "ios"))]
pub fn inherit_from_env(expected_name: &str) -> Result<Option<InheritedTun>> {
    let Some(fd) = from_env()? else {
        return Ok(None);
    };
    let policy = platform_policy();
    let expected = expected_name_for(&policy, expected_name);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        linux::verify(fd, expected, &policy).map(Some)
    }
    // iOS 无 TUNGETIFF / IFF_* 旗标：校验手段见模块头「iOS 注入契约」。
    #[cfg(target_os = "ios")]
    {
        apple::verify(fd, expected, &policy).map(Some)
    }
}

/// 当前平台的接管策略（Linux = 现网行为；Android = Go `tun_android.go`；
/// iOS = Rust 超集）。
#[cfg(any(target_os = "linux", target_os = "android", target_os = "ios"))]
fn platform_policy() -> InheritPolicy {
    #[cfg(target_os = "android")]
    {
        ANDROID_POLICY
    }
    #[cfg(target_os = "ios")]
    {
        IOS_POLICY
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        LINUX_POLICY
    }
}

/// 清继承 fd 所在 TUN 设备的 offload mask（`TUNSETOFFLOAD(0)`，Linux）。
///
/// 接管带 `IFF_VNET_HDR` 的 fd 时必须在首个读之前调用——见 [`InheritedTun::vnet_hdr`]。
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn clear_offload(fd: TunFd) -> Result<()> {
    linux::clear_offload(fd)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    use std::{
        ffi::{c_int, c_ulong},
        io,
    };

    use super::{TunFd, device_err};
    use crate::error::Result;

    // 本 crate 无 libc 依赖：ioctl 请求号与 ifreq 布局就地声明为 Linux 通用
    // 编码（x86_64/aarch64/riscv64 一致；mips 系不同，本仓不覆盖）。
    // TUNGETIFF = _IOR('T', 210, struct ifreq)。
    const TUNGETIFF: c_ulong = 0x8004_54d2;
    // IFF_TUN / IFF_NO_PI 判定已上移到 `super::flags_reject_reason`（平台策略共用）；
    // 此处只留 verify 自身仍消费的 vnet 头位。
    const IFF_VNET_HDR: u16 = 0x4000;

    const F_GETFL: c_int = 3;
    const F_SETFL: c_int = 4;
    const O_NONBLOCK: c_int = 0o4000;

    // Linux 上这两个符号由 libc（std 已链接）提供。
    unsafe extern "C" {
        fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
        fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    }

    /// `struct ifreq` 的联合体部分（24 字节）：最大成员决定对齐，缺省用 `u64`
    /// 数组保证 8 字节对齐，`ifr_flags` 恰落在偏移 16。
    #[repr(C)]
    union IfReqUnion {
        flags: u16,
        _align: [u64; 3],
    }

    #[repr(C)]
    struct IfReq {
        name: [u8; 16],
        union: IfReqUnion,
    }

    // 内核按 sizeof(struct ifreq) = 40 拷贝；布局漂移即 ioctl 越界写。
    const _: () = assert!(std::mem::size_of::<IfReq>() == 40);
    const _: () = assert!(std::mem::align_of::<IfReq>() == 8);

    pub(super) fn verify(
        fd: TunFd,
        expected_name: &str,
        policy: &super::InheritPolicy,
    ) -> Result<super::InheritedTun> {
        let mut req = IfReq { name: [0; 16], union: IfReqUnion { _align: [0; 3] } };
        // SAFETY: req 是 40 字节的 ifreq（上方 const assert 钉死）；fd 由调用方
        // 交来，TUNGETIFF 只写 ifr_name/ifr_flags，不越过 req 边界。
        let rc = unsafe { ioctl(fd, TUNGETIFF, &mut req as *mut IfReq) };
        if rc < 0 {
            return Err(device_err(format!(
                "fd {fd} TUNGETIFF failed: {} (not an open TUN device?)",
                io::Error::last_os_error()
            )));
        }
        // SAFETY: TUNGETIFF 成功返回即已写入联合体（flags 占前 2 字节）。
        let flags = unsafe { req.union.flags };
        if let Some(reason) = super::flags_reject_reason(policy, flags) {
            return Err(device_err(format!("fd {fd} {reason}")));
        }
        let vnet_hdr = flags & IFF_VNET_HDR != 0;
        let actual = ifreq_name(&req);
        if !expected_name.is_empty() && actual != expected_name {
            return Err(device_err(format!(
                "fd {fd} TUN device name {actual:?} does not match configured name \
                 {expected_name:?}"
            )));
        }
        set_nonblocking(fd)?;
        // Android：宿主仍持原 fd（Go `tun_android.go`「the descriptor stays with
        // the application」）→ 核心接管副本，核心只关副本。
        let fd = if policy.dup_fd { dup_cloexec(fd)? } else { fd };
        Ok(super::InheritedTun { fd, name: actual, vnet_hdr })
    }

    /// `F_DUPFD_CLOEXEC`（Linux/Android 通用值 1030）——复制 fd 副本。
    ///
    /// 副本与原 fd 共享同一 open file description（非阻塞状态随之共享），但
    /// 关闭互不影响：核心只关副本，宿主原 fd 仍可用。
    fn dup_cloexec(fd: TunFd) -> Result<TunFd> {
        const F_DUPFD_CLOEXEC: c_int = 1030;
        // SAFETY: fcntl(F_DUPFD_CLOEXEC) 只读 fd 并返回新 fd 号（不写内存）。
        let dup = unsafe { fcntl(fd, F_DUPFD_CLOEXEC, 0) };
        if dup < 0 {
            return Err(device_err(format!(
                "fd {fd} fcntl(F_DUPFD_CLOEXEC) failed: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(dup)
    }

    /// 清继承 fd 所在 TUN 设备的 offload mask（`TUNSETOFFLOAD(0)`）。
    ///
    /// 内核 offload mask 是设备级状态、跨 detach 残留：前主进程协商过 offload
    /// 时，掩码非零会让继承读路径收到内核 GRO 聚合大包，单包读会把聚合包读坏。
    /// 与 tun-rs 直开路径协商 `offload=false` 时的显式重置行为一致；vnet fd 上
    /// 该 ioctl 恒合法，失败即报错（继承路径禁静默降级）。
    pub(super) fn clear_offload(fd: TunFd) -> Result<()> {
        const TUNSETOFFLOAD: c_ulong = 0x4004_54d0; // _IOW('T', 208, unsigned int)
        // SAFETY: 可变参数为 c_uint（4 字节），与 _IOW 声明的尺寸一致；fd 是已
        // 验证的 vnet TUN 设备，本调用只改设备 offload 掩码，不触用户内存。
        let rc = unsafe { ioctl(fd, TUNSETOFFLOAD, 0u32) };
        if rc < 0 {
            return Err(device_err(format!(
                "fd {fd} TUNSETOFFLOAD(0) failed: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// `ifr_name`（NUL 结尾、最长 16 字节）。
    fn ifreq_name(req: &IfReq) -> String {
        let end = req.name.iter().position(|&b| b == 0).unwrap_or(req.name.len());
        String::from_utf8_lossy(&req.name[..end]).into_owned()
    }

    /// 对齐 Go `unix.SetNonblock(fd, true)`——tokio 的 `AsyncFd` 要求 fd 已非阻塞。
    fn set_nonblocking(fd: TunFd) -> Result<()> {
        // SAFETY: F_GETFL 只读 fd 状态标志，不写内存。
        let flags = unsafe { fcntl(fd, F_GETFL) };
        if flags < 0 {
            return Err(device_err(format!(
                "fd {fd} fcntl(F_GETFL) failed: {}",
                io::Error::last_os_error()
            )));
        }
        // SAFETY: 同一 fd 的有效状态查询结果，F_SETFL 只改标志位。
        if unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) } < 0 {
            return Err(device_err(format!(
                "fd {fd} fcntl(F_SETFL, O_NONBLOCK) failed: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(())
    }
}

// iOS / Darwin：utun 控制套接字的接管校验。**Rust 超集 · 无 Go 基线**（Go 无 iOS TUN，
// 见模块头「iOS 注入契约」）。本模块是 iOS 唯一无法在非 iOS 主机上编译验证的部分。
#[cfg(target_os = "ios")]
mod apple {
    use std::{
        ffi::{c_int, c_void},
        io,
    };

    use super::{TunFd, device_err};
    use crate::error::Result;

    // 本 crate 无 libc 依赖：Darwin 常量就地声明。取值出处 = xnu `bsd/sys/fcntl.h`、
    // `bsd/sys/kern_control.h`、`bsd/net/if_utun.h`。与 Linux 的差异点（踩错即静默
    // 坏标志位）：`O_NONBLOCK` = **0x0004**（Linux 0o4000）、`F_DUPFD_CLOEXEC` = **67**
    // （Linux 1030）；`F_GETFD`/`F_GETFL`/`F_SETFL` 与 Linux 同值。
    const F_GETFD: c_int = 1;
    const F_GETFL: c_int = 3;
    const F_SETFL: c_int = 4;
    const F_DUPFD_CLOEXEC: c_int = 67;
    const O_NONBLOCK: c_int = 0x0004;
    /// `SYSPROTO_CONTROL`——内核控制套接字的 getsockopt 层级。
    const SYSPROTO_CONTROL: c_int = 2;
    /// `UTUN_OPT_IFNAME`——该层级下读 utun 接口名的选项号。
    const UTUN_OPT_IFNAME: c_int = 2;
    /// `IFNAMSIZ`（Darwin = 16，`if_xname` 含 NUL）——按**精确值**传，兼容内核
    /// `*len < IFNAMSIZ` 与 `*len == IFNAMSIZ` 两种入参检查。
    const NAME_BUF_LEN: usize = 16;

    // Darwin libSystem 符号（std 已链接 libc，本 crate 无需额外依赖）。
    unsafe extern "C" {
        fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
        fn getsockopt(
            fd: c_int,
            level: c_int,
            name: c_int,
            value: *mut c_void,
            len: *mut u32,
        ) -> c_int;
    }

    pub(super) fn verify(
        fd: TunFd,
        expected_name: &str,
        policy: &super::InheritPolicy,
    ) -> Result<super::InheritedTun> {
        // 最小校验一：fd 必须是已打开的描述符（坏 fd 上 `F_GETFD` 返回 EBADF）。
        // SAFETY: F_GETFD 只读 fd 的 close-on-exec 标志，不写内存。
        if unsafe { fcntl(fd, F_GETFD) } < 0 {
            return Err(device_err(format!(
                "fd {fd} is not an open descriptor: {}",
                io::Error::last_os_error()
            )));
        }
        // 最小校验二：必须是 utun 控制套接字（utun 不是 IFF_TUN，iOS 无 TUNGETIFF）；
        // 顺带取到接口名，替代 Linux 的 `ifr_name`。
        let name = utun_name(fd)?;
        if !expected_name.is_empty() && name != expected_name {
            return Err(device_err(format!(
                "fd {fd} utun device name {name:?} does not match configured name \
                 {expected_name:?}"
            )));
        }
        set_nonblocking(fd)?;
        // 宿主（NEPacketTunnelProvider）仍持原 fd → 核心接管副本，只关副本。
        let fd = if policy.dup_fd { dup_cloexec(fd)? } else { fd };
        // utun 无 virtio 头概念（策略在校验期已拒 IFF_VNET_HDR），每包前缀是 4 字节
        // 地址族头，由调用方按 `has_family_header` 剥/垫。
        Ok(super::InheritedTun { fd, name, vnet_hdr: false })
    }

    /// 读 utun 接口名（`getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME)`）。
    ///
    /// 该选项只在绑定到内核控制 `com.apple.net.utun_control` 的套接字上成功 ⇒ 一次
    /// 调用同时证明「这是 utun」并取得 `utunN`。失败即报错（禁静默回退直开设备）。
    fn utun_name(fd: TunFd) -> Result<String> {
        let mut buf = [0u8; NAME_BUF_LEN];
        let mut len: u32 = NAME_BUF_LEN as u32;
        // SAFETY: buf/len 都是本栈上的有效内存；内核最多写 `len` 字节并按 NUL 结尾，
        // 成功时把实际长度回填进 len（不会超过入参）。
        let rc = unsafe {
            getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                buf.as_mut_ptr().cast::<c_void>(),
                &mut len,
            )
        };
        if rc < 0 {
            return Err(device_err(format!(
                "fd {fd} is not an open utun control socket \
                 (getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME) failed: {}); the host app \
                 (NEPacketTunnelProvider) must inject a socket bound to \
                 com.apple.net.utun_control",
                io::Error::last_os_error()
            )));
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let name = String::from_utf8_lossy(&buf[..end]).into_owned();
        // utun 控制只会造出 `utunN`（xnu `if_utun.c` 的命名）；别的名字说明该 fd 绑到
        // 了另一个内核控制、UTUN_OPT_IFNAME 只是碰巧有回包 ⇒ 拒（禁错绑）。
        if !name.starts_with("utun") {
            return Err(device_err(format!(
                "fd {fd} reports interface name {name:?}, which is not a utun interface"
            )));
        }
        Ok(name)
    }

    /// 对齐 `SetNonblock(fd, true)`——tokio `AsyncFd` 要求 fd 已非阻塞。
    fn set_nonblocking(fd: TunFd) -> Result<()> {
        // SAFETY: F_GETFL 只读 fd 状态标志，不写内存。
        let flags = unsafe { fcntl(fd, F_GETFL) };
        if flags < 0 {
            return Err(device_err(format!(
                "fd {fd} fcntl(F_GETFL) failed: {}",
                io::Error::last_os_error()
            )));
        }
        // SAFETY: 同一 fd 的有效状态查询结果，F_SETFL 只改标志位。
        if unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) } < 0 {
            return Err(device_err(format!(
                "fd {fd} fcntl(F_SETFL, O_NONBLOCK) failed: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// `F_DUPFD_CLOEXEC`（Darwin = 67）——复制 fd 副本。
    ///
    /// 副本与原 fd 共享同一 open file description（非阻塞状态随之共享），但关闭互不
    /// 影响：核心只关副本，宿主原 fd 仍可用。
    fn dup_cloexec(fd: TunFd) -> Result<TunFd> {
        // SAFETY: fcntl(F_DUPFD_CLOEXEC) 只读 fd 并返回新 fd 号（不写内存）。
        let dup = unsafe { fcntl(fd, F_DUPFD_CLOEXEC, 0) };
        if dup < 0 {
            return Err(device_err(format!(
                "fd {fd} fcntl(F_DUPFD_CLOEXEC) failed: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(dup)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;

    /// 环境变量是进程级共享状态：本模块内所有改 env 的测试串行，避免互相覆盖。
    /// device.rs 的继承集成测试共用此锁（env 设了必须被 create 消费的窗口）。
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    pub(crate) fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// 写 env。调用方必须持 [`ENV_LOCK`]。
    ///
    /// SAFETY（edition 2024 起 set_var 为 unsafe）：本进程内只有本模块的测试读这
    /// 两个键，且改值全部在 `ENV_LOCK` 内串行，无并发读写同一键。
    fn set_env(key: &str, value: &str) {
        unsafe { std::env::set_var(key, value) }
    }

    /// 清 env。调用方必须持 [`ENV_LOCK`]。SAFETY 同上。
    fn clear_env() {
        for key in TUN_FD_KEYS {
            unsafe { std::env::remove_var(key) }
        }
    }

    #[test]
    fn parse_rejects_non_numeric_and_low_fd() {
        let err = parse("nope").expect_err("非数字必须报错");
        assert!(format!("{err}").contains(TUN_FD_KEYS[0]), "got: {err}");

        let err = parse("2").expect_err("fd < 3 必须报错（Go 同）");
        assert!(format!("{err}").contains(">= 3"), "got: {err}");

        assert_eq!(parse("3").unwrap(), 3);
        assert_eq!(parse("+7").unwrap(), 7, "Go strconv.Atoi 接受 + 号");
        assert!(parse(" 7").is_err(), "Go Atoi 不做空白裁剪");
    }

    #[test]
    fn env_unset_or_empty_means_direct_open() {
        let _guard = lock_env();
        clear_env();
        assert_eq!(from_env().unwrap(), None, "未设置 → 直开");

        set_env(TUN_FD_KEYS[0], "");
        assert_eq!(from_env().unwrap(), None, "空串 = 未提供 → 直开（Go GetValue 同形）");
        clear_env();
    }

    #[test]
    fn env_invalid_value_is_explicit_error_not_fallback() {
        let _guard = lock_env();
        clear_env();

        set_env(TUN_FD_KEYS[0], "not-a-fd");
        let err = from_env().expect_err("非法值必须报错，禁回退直开");
        assert!(format!("{err}").contains("xray.tun.fd"), "got: {err}");

        set_env(TUN_FD_KEYS[0], "1");
        let err = from_env().expect_err("标准流 fd 必须报错");
        assert!(format!("{err}").contains(">= 3"), "got: {err}");

        clear_env();
    }

    #[test]
    fn env_original_name_takes_priority_over_normalized() {
        let _guard = lock_env();
        clear_env();

        // 原名非法 + 归一化名合法：Go 只看原名 → 必须报错（不静默落到次要名）。
        set_env(TUN_FD_KEYS[0], "bad");
        set_env(TUN_FD_KEYS[1], "7");
        let err = from_env().expect_err("原名优先，非法即错");
        assert!(format!("{err}").contains("\"bad\""), "got: {err}");

        // 只设归一化名：Go 的 AltName 兜底生效。
        clear_env();
        set_env(TUN_FD_KEYS[1], "7");
        assert_eq!(from_env().unwrap(), Some(7));

        clear_env();
    }

    /// 接线证明：`TunDevice::create` 在平台无继承能力时从 env 直接报错，不回退直开。
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    #[test]
    fn create_wires_env_check_before_device_open() {
        let _guard = lock_env();
        clear_env();
        set_env(TUN_FD_KEYS[0], "7");
        let err = crate::device::TunDevice::create("xrayfd", "10.0.0.1", 24, 1500, &[])
            .err()
            .expect("env 给了 fd 而平台不支持 → 必须显式报错");
        assert!(format!("{err}").contains("xray.tun.fd"), "got: {err}");
        clear_env();
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    #[test]
    fn unsupported_platform_refuses_only_when_env_set() {
        let _guard = lock_env();
        clear_env();
        refuse_unsupported().expect("env 未设置 → 照常直开");

        set_env(TUN_FD_KEYS[0], "5");
        let err = refuse_unsupported().expect_err("平台不支持 → 必须显式报错");
        let msg = format!("{err}");
        assert!(msg.contains("xray.tun.fd"), "got: {msg}");
        assert!(msg.contains("not implemented on"), "got: {msg}");
        clear_env();
    }

    /// Linux：合法 fd 值进入继承校验路径（不是直开）。用 socketpair 伪造"可验证
    /// 的最小对象"——解析通过，`TUNGETIFF` 在非 TUN fd 上必失败，错误来自校验段。
    #[cfg(target_os = "linux")]
    #[test]
    fn valid_fd_value_enters_inheritance_path() {
        use std::os::unix::io::AsRawFd;

        let (fake, _peer) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        let fd = fake.as_raw_fd();
        assert!(fd >= 3, "socketpair fd 应落在 >= 3（got {fd}）");

        let _guard = lock_env();
        set_env(TUN_FD_KEYS[0], &fd.to_string());
        let err = inherit_from_env("").expect_err("非 TUN fd 必须报错（禁回退直开）");
        let msg = format!("{err}");
        assert!(msg.contains("TUNGETIFF"), "错误必须来自继承校验段: {msg}");
        clear_env();
    }

    /// Linux：env 值解析不过关时连 ioctl 都不该发（错误为配置值类）。
    #[cfg(target_os = "linux")]
    #[test]
    fn invalid_env_value_fails_before_ioctl() {
        let _guard = lock_env();
        set_env(TUN_FD_KEYS[0], "-1");
        let err = inherit_from_env("").expect_err("负 fd 必须报错");
        let msg = format!("{err}");
        assert!(msg.contains(">= 3"), "got: {msg}");
        assert!(!msg.contains("TUNGETIFF"), "解析段就该失败: {msg}");
        clear_env();
    }

    // ---- 策略层纯逻辑（任意平台可跑，含 Windows）----

    const IFF_TUN: u16 = 0x0001;
    const IFF_NO_PI: u16 = 0x1000;
    const IFF_VNET_HDR: u16 = 0x4000;

    /// Android 策略下期望设备名恒为空串 ⇒ 校验期不比对设备名（Go 同）。
    #[test]
    fn android_policy_never_compares_device_name() {
        assert_eq!(expected_name_for(&ANDROID_POLICY, "tun0"), "");
        assert_eq!(expected_name_for(&ANDROID_POLICY, ""), "");
        // Linux 策略照旧比对配置名。
        assert_eq!(expected_name_for(&LINUX_POLICY, "xray0"), "xray0");
    }

    /// 旗标校验三种拒绝原因（非 TUN / 缺 IFF_NO_PI / 带 IFF_VNET_HDR）。
    #[test]
    fn flags_reject_reason_covers_three_cases() {
        // 非 TUN。
        let reason = flags_reject_reason(&ANDROID_POLICY, 0).expect("非 TUN 必须拒绝");
        assert!(reason.contains("IFF_TUN"), "got: {reason}");
        // 缺 IFF_NO_PI。
        let reason = flags_reject_reason(&ANDROID_POLICY, IFF_TUN).expect("缺 IFF_NO_PI 必须拒绝");
        assert!(reason.contains("IFF_NO_PI"), "got: {reason}");
        // 带 IFF_VNET_HDR：Android 拒绝（无 virtio 头路径，禁静默错帧）。
        let reason = flags_reject_reason(&ANDROID_POLICY, IFF_TUN | IFF_NO_PI | IFF_VNET_HDR)
            .expect("Android 必须拒绝 IFF_VNET_HDR");
        assert!(reason.contains("IFF_VNET_HDR"), "got: {reason}");
        // 合法旗标组合接受。
        assert_eq!(flags_reject_reason(&ANDROID_POLICY, IFF_TUN | IFF_NO_PI), None);
    }

    /// Linux 策略保留 virtio 头支持（现网行为逐字不变：带 IFF_VNET_HDR 照常接管）。
    #[test]
    fn linux_policy_still_allows_vnet_hdr() {
        assert_eq!(flags_reject_reason(&LINUX_POLICY, IFF_TUN | IFF_NO_PI | IFF_VNET_HDR), None);
    }

    /// 三平台策略的差异点逐条钉死（防漂移）。
    #[test]
    fn policy_differences_are_pinned() {
        assert_eq!(
            LINUX_POLICY,
            InheritPolicy {
                compare_device_name: true,
                dup_fd: false,
                allow_vnet_hdr: true,
                has_family_header: false,
            }
        );
        assert_eq!(
            ANDROID_POLICY,
            InheritPolicy {
                compare_device_name: false,
                dup_fd: true,
                allow_vnet_hdr: false,
                has_family_header: false,
            }
        );
        // iOS：不比对名 / 接管副本 / 拒 virtio 头 / 剥垫 4 字节族头（Rust 超集，无 Go 基线）。
        assert_eq!(
            IOS_POLICY,
            InheritPolicy {
                compare_device_name: false,
                dup_fd: true,
                allow_vnet_hdr: false,
                has_family_header: true,
            }
        );
    }

    /// iOS：期望设备名恒为空串（`utunN` 由系统分配），族头长度按策略给出。
    #[test]
    fn ios_policy_requests_family_header_and_skips_name_check() {
        assert_eq!(expected_name_for(&IOS_POLICY, "xray0"), "");
        assert_eq!(family_header_len(&IOS_POLICY), FAMILY_HEADER_LEN);
        assert_eq!(family_header_len(&LINUX_POLICY), 0);
        assert_eq!(family_header_len(&ANDROID_POLICY), 0);
    }

    /// 剥族头：合法 v4/v6 头原地前移，返回纯 IP 包长。
    #[test]
    fn strip_family_header_moves_payload_to_front() {
        let mut v4 = [0u8, 0, 0, 2, 0x45, 0x00, 0x00, 0x14];
        assert_eq!(strip_family_header(&mut v4, 8).unwrap(), 4);
        assert_eq!(&v4[..4], &[0x45, 0x00, 0x00, 0x14]);

        // AF_INET6 = 30（Darwin 值，不是 Linux 的 10）。
        let mut v6 = [0u8, 0, 0, 30, 0x60, 0x00, 0x00, 0x00];
        assert_eq!(strip_family_header(&mut v6, 8).unwrap(), 4);
        assert_eq!(&v6[..4], &[0x60, 0x00, 0x00, 0x00]);
    }

    /// 剥族头：族值非法 / 长度不足必须报错，禁把错位数据当 IP 包交出去。
    #[test]
    fn strip_family_header_rejects_garbage() {
        let mut wrong_family = [0u8, 0, 0, 10, 0x45, 0x00, 0x00, 0x14]; // AF_INET6 的 Linux 值
        let err = strip_family_header(&mut wrong_family, 8).expect_err("族值 10 必须拒绝");
        assert!(format!("{err}").contains("address family 10"), "got: {err}");

        let mut short = [0u8, 0, 0, 2];
        let err = strip_family_header(&mut short, 4).expect_err("只有头没有包必须拒绝");
        assert!(format!("{err}").contains("not longer than"), "got: {err}");
    }

    /// 垫族头：由 IP 版本号生成 4 字节网络序族值，非法版本返回 None（调用方须报错）。
    #[test]
    fn family_header_for_derives_from_ip_version() {
        assert_eq!(family_header_for(&[0x45, 0x00]), Some([0, 0, 0, 2]), "IPv4 → AF_INET(2)");
        assert_eq!(family_header_for(&[0x60, 0x00]), Some([0, 0, 0, 30]), "IPv6 → AF_INET6(30)");
        assert_eq!(family_header_for(&[0x00]), None, "非 v4/v6 首半字节必须拒");
        assert_eq!(family_header_for(&[]), None, "空包必须拒");
    }

    /// 垫头 ↔ 剥头必须互逆（发送前置的 4 字节被读回时原样剥掉）。
    #[test]
    fn family_header_roundtrip() {
        let pkt = [0x45u8, 0x00, 0x00, 0x14, 0xaa, 0xbb];
        let hdr = family_header_for(&pkt).expect("IPv4 包必须有族头");
        let mut wire = Vec::from(hdr);
        wire.extend_from_slice(&pkt);
        let n = wire.len();
        assert_eq!(strip_family_header(&mut wire, n).unwrap(), pkt.len());
        assert_eq!(&wire[..pkt.len()], &pkt);
    }
}

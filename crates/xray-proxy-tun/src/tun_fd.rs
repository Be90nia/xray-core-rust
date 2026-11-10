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
//! 平台面：
//! - **Linux / Android**：完整实现（`linux` 子模块 + `inherit_from_env`）。两者同为 Linux
//!   内核，`TUNGETIFF` / `fcntl` 的 ioctl 编码一致。
//! - **其他平台**（Windows/macOS/BSD/iOS）：未实现 fd 继承。
//! - 这些平台 env 设置即由 `refuse_unsupported` 显式报错，禁静默回退直开。
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
//! 三个平台差异点集中在 `InheritPolicy`（Linux / Android 各一份常量），
//! Linux 策略 = 现网行为逐字不变。
//!
//! vnet_hdr 面（bd y93up，对齐 Go）：带 `IFF_VNET_HDR` 的继承 fd 照常接管。
//! tun-rs 的 `from_fd` 把设备记成裸包模式（读写原语 = 裸 read/write），因此
//! virtio 头的剥除/垫放由 [`crate::device::TunDevice`] 层处理（复用其垫头
//! free list）；`clear_offload` 在接管时清设备级 offload mask，保证继承读
//! 路径只见单包、不会收到内核 GRO 聚合大包。

use crate::error::{Result, TunError};

/// Go `platform.TunFdKey` + 归一化名（`platform.NormalizeEnvName`）。
pub const TUN_FD_KEYS: [&str; 2] = ["xray.tun.fd", "XRAY_TUN_FD"];

/// 进程间传递的文件描述符编号（Windows 上无此语义，见 `refuse_unsupported`）。
pub type TunFd = i32;

/// 平台 fd 接管策略：Linux / Android 的三个语义差异点集中于此。
///
/// Linux 侧保持现网行为逐字不变；Android 侧对齐 Go `proxy/tun/tun_android.go`。
#[cfg(any(target_os = "linux", target_os = "android", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InheritPolicy {
    /// 是否比对设备名与配置 `name`（Android 宿主自定接口名 → 否）。
    pub compare_device_name: bool,
    /// 是否接管 fd 副本（Android：宿主仍持原 fd → 是，核心只关副本）。
    pub dup_fd: bool,
    /// 是否接受带 `IFF_VNET_HDR` 的 fd（Android 无 virtio 头路径 → 否）。
    pub allow_vnet_hdr: bool,
}

/// Linux 接管策略 = 现网行为（比对名 / 直接接管 / 接受 virtio 头）。
#[cfg(any(target_os = "linux", target_os = "android", test))]
pub const LINUX_POLICY: InheritPolicy =
    InheritPolicy { compare_device_name: true, dup_fd: false, allow_vnet_hdr: true };

/// Android 接管策略（Go `proxy/tun/tun_android.go`）：不比对名 / 接管副本 / 拒 virtio 头。
#[cfg(any(target_os = "linux", target_os = "android", test))]
pub const ANDROID_POLICY: InheritPolicy =
    InheritPolicy { compare_device_name: false, dup_fd: true, allow_vnet_hdr: false };

/// 按策略算出应当比对的期望设备名（不比对时返回空串 ⇒ verify 跳过比对）。
#[cfg(any(target_os = "linux", target_os = "android", test))]
#[must_use]
pub fn expected_name_for<'a>(policy: &InheritPolicy, configured: &'a str) -> &'a str {
    if policy.compare_device_name { configured } else { "" }
}

/// 按策略判定设备旗标是否可接管（`None` = 可接管；`Some(reason)` = 拒绝原因）。
///
/// 纯函数：可在任意平台（含 Windows）单测 Android 策略的旗标语义。
#[cfg(any(target_os = "linux", target_os = "android", test))]
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
#[cfg(not(any(target_os = "android", target_os = "linux")))]
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

/// 继承来的 TUN 设备描述（Linux / Android）。
#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Debug)]
pub struct InheritedTun {
    /// 已校验为 TUN 设备、且已置非阻塞的 fd。所有权**仍归宿主进程**：本函数不开
    /// 不关，接管方（`AsyncDevice::from_fd`）负责关闭——与 Go 一致（校验失败时
    /// Go 也不关 fd）。
    pub fd: TunFd,
    /// 设备实际接口名（`TUNGETIFF` 回的 `ifr_name`）。
    pub name: String,
    /// fd 携带 `IFF_VNET_HDR`（bd y93up）：接管方须剥头/垫头并先清 offload mask
    /// （[`clear_offload`]）。
    pub vnet_hdr: bool,
}

/// 继承路径入口（Linux / Android）：读 env → 解析 → 校验 fd。
///
/// `expected_name` 为空表示配置未指定设备名（不校验）；非空时实际名必须一致
/// （Go `openFromEnv` 末段）。平台差异由 [`InheritPolicy`] 表达：Linux 用
/// [`LINUX_POLICY`]（比对名）；Android 用 [`ANDROID_POLICY`]（不比对名，走
/// [`expected_name_for`] ⇒ 传空串）。
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn inherit_from_env(expected_name: &str) -> Result<Option<InheritedTun>> {
    let Some(fd) = from_env()? else {
        return Ok(None);
    };
    let policy = platform_policy();
    let expected = expected_name_for(&policy, expected_name);
    linux::verify(fd, expected, &policy).map(Some)
}

/// 当前平台的接管策略（Linux = 现网行为；Android = Go `tun_android.go`）。
#[cfg(any(target_os = "linux", target_os = "android"))]
fn platform_policy() -> InheritPolicy {
    #[cfg(target_os = "android")]
    {
        ANDROID_POLICY
    }
    #[cfg(not(target_os = "android"))]
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

    /// 两平台策略的三个差异点逐条钉死（防漂移）。
    #[test]
    fn policy_differences_are_pinned() {
        assert_eq!(
            LINUX_POLICY,
            InheritPolicy { compare_device_name: true, dup_fd: false, allow_vnet_hdr: true }
        );
        assert_eq!(
            ANDROID_POLICY,
            InheritPolicy { compare_device_name: false, dup_fd: true, allow_vnet_hdr: false }
        );
    }
}

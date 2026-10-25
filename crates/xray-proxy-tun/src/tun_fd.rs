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
//! - **Linux**：完整实现（`linux` 子模块 + `inherit_from_env`）。
//! - **其他平台**（Windows/macOS/BSD）：未实现 fd 继承。
//! - 这些平台 env 设置即由 `refuse_unsupported` 显式报错，禁静默回退直开。
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
#[cfg(not(target_os = "linux"))]
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

/// 继承来的 TUN 设备描述（Linux）。
#[cfg(target_os = "linux")]
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

/// 继承路径入口（Linux）：读 env → 解析 → 校验 fd。
///
/// `expected_name` 为空表示配置未指定设备名（不校验）；非空时实际名必须一致
/// （Go `openFromEnv` 末段）。
#[cfg(target_os = "linux")]
pub fn inherit_from_env(expected_name: &str) -> Result<Option<InheritedTun>> {
    let Some(fd) = from_env()? else {
        return Ok(None);
    };
    linux::verify(fd, expected_name).map(Some)
}

/// 清继承 fd 所在 TUN 设备的 offload mask（`TUNSETOFFLOAD(0)`，Linux）。
///
/// 接管带 `IFF_VNET_HDR` 的 fd 时必须在首个读之前调用——见 [`InheritedTun::vnet_hdr`]。
#[cfg(target_os = "linux")]
pub fn clear_offload(fd: TunFd) -> Result<()> {
    linux::clear_offload(fd)
}

#[cfg(target_os = "linux")]
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
    const IFF_TUN: u16 = 0x0001;
    const IFF_NO_PI: u16 = 0x1000;
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

    pub(super) fn verify(fd: TunFd, expected_name: &str) -> Result<super::InheritedTun> {
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
        if flags & IFF_TUN == 0 {
            return Err(device_err(format!("fd {fd} is not a TUN device (IFF_TUN unset)")));
        }
        if flags & IFF_NO_PI == 0 {
            return Err(device_err(format!("fd {fd} TUN device must use IFF_NO_PI")));
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
        Ok(super::InheritedTun { fd, name: actual, vnet_hdr })
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
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn create_wires_env_check_before_device_open() {
        let _guard = lock_env();
        clear_env();
        set_env(TUN_FD_KEYS[0], "7");
        let err = crate::device::TunDevice::create("xrayfd", "10.0.0.1", 24, 1500)
            .err()
            .expect("env 给了 fd 而平台不支持 → 必须显式报错");
        assert!(format!("{err}").contains("xray.tun.fd"), "got: {err}");
        clear_env();
    }

    #[cfg(not(target_os = "linux"))]
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
}

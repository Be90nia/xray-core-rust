//! 平台环境标志
//!
//! 对应 Go 版本 `platform.NewEnvFlag`，提供环境变量读取和类型转换。

use std::sync::{
    LazyLock, OnceLock,
    atomic::{AtomicBool, Ordering},
};

/// 环境标志，首次访问时从环境变量读取值并缓存。
///
/// 对应 Go 版本 `platform.EnvFlag`。
pub struct EnvFlag {
    name: String,
    alt_name: String,
    value: OnceLock<Option<String>>,
}

impl EnvFlag {
    /// 创建新的环境标志。
    ///
    /// `name` 为环境变量名称（Go 点式如 `xray.location.asset`）。读取时先查
    /// 原名，再查归一化大写形式（`XRAY_LOCATION_ASSET`），对应 Go
    /// `platform.NewEnvFlag` 的 Name/AltName 双查。值在首次 `get_value()`
    /// 调用时读取并缓存。
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        let alt_name = name.to_uppercase().replace('.', "_");
        Self { name, alt_name, value: OnceLock::new() }
    }

    /// 获取标志值，首次访问时从环境变量读取。
    ///
    /// 返回环境变量的字符串值引用，未设置时返回 `None`。
    pub fn get_value(&self) -> Option<&str> {
        self.value
            .get_or_init(|| {
                std::env::var(&self.name)
                    .ok()
                    .filter(|v| !v.is_empty())
                    .or_else(|| std::env::var(&self.alt_name).ok().filter(|v| !v.is_empty()))
            })
            .as_deref()
    }

    /// 获取标志值的布尔形式，默认为 `false`。
    ///
    /// 以下值（不区分大小写）视为 `true`：`"1"`、`"true"`、`"yes"`、`"on"`。
    pub fn get_value_as_bool(&self) -> bool {
        self.get_value()
            .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
    }

    /// 获取标志值的整数形式。
    ///
    /// 环境变量未设置或无法解析为整数时返回 `None`。
    pub fn get_value_as_int(&self) -> Option<i64> {
        self.get_value().and_then(|v| v.parse().ok())
    }
}
/// `xray.buf.readv`（alt `XRAY_BUF_READV`）— readv 聚合读闸门。
///
/// 对齐 Go `platform.UseReadV`（common/platform/platform.go:16）等价入口。
///
/// 单一事实源收敛：判定逻辑（env 解析 + 三态 + AtomicBool 缓存）全仓只在
/// `xray-buf::readv`（xray-common 依赖 xray-buf，直接转发）；本 fn 是消费点
/// 别名，热路径一次 atomic load。环境变更走 `xray_buf::readv::reload_env_settings`
/// 刷新（对齐 Go reloadEnvSettings）。
#[must_use]
pub fn use_readv() -> bool {
    xray_buf::readv::use_readv()
}

/// `xray.buf.splice`（alt `XRAY_BUF_SPLICE`）— freedom splice(2) zero-copy 闸门。
///
/// 对应 Go `platform.UseFreedomSplice`（common/platform/platform.go:17）+
/// `reloadEnvSettings`（proxy/freedom/freedom.go:41-51）。语义见
/// [`parse_enabled_env`]。刻意不走 [`EnvFlag`]：其 `get_value` 把空串过滤为
/// 未设置，而 Go 对 `xray.buf.splice=""` 的语义是禁用（LookupEnv 命中空串 →
/// switch 落空）。
///
/// 缓存语义（bd 1n90/xag3②）：LazyLock 首调解析一次，热路径只做 atomic
/// load（零 env 查询/零分配）。环境变更需显式 [`reload_env_settings`] 刷新，
/// 对齐 Go reloadEnvSettings。
#[must_use]
pub fn use_splice() -> bool {
    SPLICE_FLAG.load(Ordering::Relaxed)
}

/// `xray.buf.splice` 解析结果缓存。首调读 env，之后热路径零查询。
static SPLICE_FLAG: LazyLock<AtomicBool> = LazyLock::new(|| AtomicBool::new(parse_splice_env()));

/// 读 env 并按 Go 三态语义解析 `xray.buf.splice`（原名优先，alt 兜底）。
fn parse_splice_env() -> bool {
    let raw = std::env::var_os("xray.buf.splice")
        .or_else(|| std::env::var_os("XRAY_BUF_SPLICE"))
        .map(|v| v.to_string_lossy().into_owned());
    parse_enabled_env(raw.as_deref())
}

/// 重新解析 `xray.buf.splice` 闸门。对应 Go `reloadEnvSettings`
/// （freedom.go:41-51，经 platform.RegisterEnvReload 注册；我们无注册机制，
/// 进程启动后环境变更需显式调用）。生产接线：bin 启动早期调一次。
pub fn reload_env_settings() {
    SPLICE_FLAG.store(parse_splice_env(), Ordering::Relaxed);
}

/// Go 三态启用语义的纯函数形式（freedom.go:45-48 `reloadEnvSettings` 与
/// readv_reader.go:153-163 同形）。
///
/// `None` = 环境变量未设置（Go 的 defaultFlagValue 哨兵）→ 启用；
/// `Some("auto" | "enable")` → 启用；其余一律禁用（大小写敏感，对齐 Go
/// switch 精确匹配，无 trim/小写化，`"true"`/`"1"` 也禁用）。非 UTF-8 值经
/// to_string_lossy 变成非匹配串 → 禁用，与 Go 逐字节比较一致。
#[must_use]
pub fn parse_enabled_env(value: Option<&str>) -> bool {
    match value {
        None => true,
        Some(s) => matches!(s, "auto" | "enable"),
    }
}

/// `xray.vmess.padding`（alt `XRAY_VMESS_PADDING`）— VMess outbound 全局 padding 开关。
///
/// 对应 Go `platform.UseVmessPadding`（proxy/vmess/outbound/outbound.go:240）。
/// 当前 Rust VMess padding 由 per-session `GLOBAL_PADDING` flag 驱动；本 binding 暴露
/// Go 等价 env 入口，便于上层装配或后续 VMess 启用点接入。
pub fn use_vmess_padding() -> bool {
    static FLAG: LazyLock<EnvFlag> = LazyLock::new(|| EnvFlag::new("xray.vmess.padding"));
    FLAG.get_value_as_bool()
}

/// `xray.xudp.show`（alt `XRAY_XUDP_SHOW`）== "true" 时启用 XUDP 协议层日志。
///
/// 对应 Go `platform.XUDPLog`（common/xudp/xudp.go:35）。当前 Rust
/// `xray_xudp::XudpConfig::from_env()` 走 `XUDP_LOG` 环境变量；这里补 Go 等价
/// `xray.xudp.show` 入口。
pub fn xudp_show() -> bool {
    static FLAG: LazyLock<EnvFlag> = LazyLock::new(|| EnvFlag::new("xray.xudp.show"));
    FLAG.get_value_as_bool()
}

/// `xray.xudp.basekey`（alt `XRAY_XUDP_BASEKEY`）— XUDP BaseKey 原始字符串值。
///
/// 对应 Go `platform.XUDPBaseKey`（common/xudp/xudp.go:42）。调用方负责 Base64
/// URL-safe 解码及 32 字节校验。
#[must_use]
pub fn xudp_basekey_raw() -> Option<String> {
    static FLAG: LazyLock<EnvFlag> = LazyLock::new(|| EnvFlag::new("xray.xudp.basekey"));
    FLAG.get_value().map(str::to_owned)
}

/// `xray.cone.disabled`（alt `XRAY_CONE_DISABLED`）== "true" 时禁用 cone 模式。
///
/// 对应 Go `platform.UseCone`（core/xray.go:191：`!= "true"` 决定 cone 是否启用）。
/// 返回值即 Go 「disabled」含义，调用方需取反得到 cone 启用状态。
pub fn cone_disabled() -> bool {
    static FLAG: LazyLock<EnvFlag> = LazyLock::new(|| EnvFlag::new("xray.cone.disabled"));
    FLAG.get_value_as_bool()
}

/// `xray.browser.dialer`（alt `XRAY_BROWSER_DIALER`）— browser dialer 后端地址。
///
/// 对应 Go `platform.BrowserDialerAddress`（transport/internet/browser_dialer/
/// dialer.go:46）。原始字符串由调用方解析（典型值：`ws://127.0.0.1:4321`）。
#[must_use]
pub fn browser_dialer_address() -> Option<String> {
    static FLAG: LazyLock<EnvFlag> = LazyLock::new(|| EnvFlag::new("xray.browser.dialer"));
    FLAG.get_value().map(str::to_owned)
}

/// `xray.tun.fd`（alt `XRAY_TUN_FD`）— Tun Fd 整数字符串。
///
/// 对应 Go `platform.TunFdKey`（proxy/tun/tun_android.go:27 / tun_darwin.go:54）。
/// 未经设置返回 `None`；调用方负责 `str::from_str::<i32>()` 解析。
#[must_use]
pub fn tun_fd_raw() -> Option<String> {
    static FLAG: LazyLock<EnvFlag> = LazyLock::new(|| EnvFlag::new("xray.tun.fd"));
    FLAG.get_value().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_flag_new() {
        let flag = EnvFlag::new("TEST_XRAY_ENV_FLAG_NEW");
        assert_eq!(flag.get_value(), None);
    }

    #[test]
    fn test_env_flag_get_value_as_bool_default_false() {
        let flag = EnvFlag::new("TEST_XRAY_ENV_FLAG_BOOL_UNSET");
        assert!(!flag.get_value_as_bool());
    }

    #[test]
    fn test_env_flag_get_value_as_int_none() {
        let flag = EnvFlag::new("TEST_XRAY_ENV_FLAG_INT_UNSET");
        assert_eq!(flag.get_value_as_int(), None);
    }

    #[test]
    fn test_env_flag_caches_value() {
        let flag = EnvFlag::new("TEST_XRAY_ENV_FLAG_CACHE");
        let v1 = flag.get_value();
        let v2 = flag.get_value();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_use_readv_returns_bool() {
        // 只验证函数可调用且返回布尔值
        let _val = use_readv();
    }

    /// 单一事实源收敛：xray-common 的 `use_readv` 是 `xray_buf::readv` 闸门的
    /// 转发别名，开/关两态 + 缓存语义必须贯穿转发链。env 是进程全局，串行化
    /// （惯例同上方 SPLICE_ENV_LOCK）。
    static READV_ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[test]
    fn use_readv_forwards_to_xray_buf_gate() {
        let _g = READV_ENV_LOCK.lock();

        const NAME: &str = "xray.buf.readv";
        const ALT: &str = "XRAY_BUF_READV";
        let saved_name = std::env::var_os(NAME);
        let saved_alt = std::env::var_os(ALT);
        struct Restore(Option<std::ffi::OsString>, Option<std::ffi::OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                unsafe {
                    match self.0.take() {
                        Some(v) => std::env::set_var(NAME, v),
                        None => std::env::remove_var(NAME),
                    }
                    match self.1.take() {
                        Some(v) => std::env::set_var(ALT, v),
                        None => std::env::remove_var(ALT),
                    }
                }
                // 按恢复后的 env 重解析，不把测试态泄漏给后续测试
                xray_buf::readv::reload_env_settings();
            }
        }
        unsafe {
            std::env::remove_var(NAME);
            std::env::remove_var(ALT);
        }
        let _restore = Restore(saved_name, saved_alt);

        // ① 未设置 → Go 缺省开（readv_reader.go defaultFlagValue，经转发链）
        xray_buf::readv::reload_env_settings();
        assert!(use_readv(), "未设置应启用（Go 缺省，经转发链）");

        // ② 关态：非法值禁用（转发别名与 xray-buf 本地读同源）
        unsafe { std::env::set_var(NAME, "disable") };
        xray_buf::readv::reload_env_settings();
        assert!(!use_readv(), "disable 应经转发链禁用");

        // ③ 缓存语义贯穿转发链：env 变更不 reload 不得翻转
        unsafe { std::env::set_var(NAME, "enable") };
        assert!(!use_readv(), "不 reload 不应翻转（缓存生效）");
        xray_buf::readv::reload_env_settings();
        assert!(use_readv(), "reload 后应翻转");
    }

    // -------- 7 新 EnvFlag bindings --------
    // 仅验证函数可调用 + 返回类型正确；env 未设置时返回 false/None。
    // 设置真实 env 会污染进程全局且不可并行，跨测不可移植，故仅做「callable」检查。

    #[test]
    fn test_use_splice_returns_bool() {
        let _val: bool = use_splice();
    }

    #[test]
    fn test_parse_enabled_env_go_semantics() {
        // freedom.go:45-48 / readv_reader.go:153-163 同形：未设置/auto/enable → 启用。
        assert!(parse_enabled_env(None), "未设置 = Go 缺省开");
        assert!(parse_enabled_env(Some("auto")));
        assert!(parse_enabled_env(Some("enable")));
        // 禁用侧：Go switch 精确匹配，"true"/"1" 也禁用，大小写敏感不 trim。
        for off in ["", "disable", "true", "1", "on", "yes", "AUTO", "Enable", " default "] {
            assert!(!parse_enabled_env(Some(off)), "env={off:?} 应禁用");
        }
    }

    #[test]
    fn test_use_vmess_padding_returns_bool() {
        let _val: bool = use_vmess_padding();
    }

    #[test]
    fn test_xudp_show_returns_bool() {
        let _val: bool = xudp_show();
    }

    #[test]
    fn test_xudp_basekey_raw_returns_option() {
        let _val: Option<String> = xudp_basekey_raw();
    }

    #[test]
    fn test_cone_disabled_returns_bool() {
        let _val: bool = cone_disabled();
    }

    #[test]
    fn test_browser_dialer_address_returns_option() {
        let _val: Option<String> = browser_dialer_address();
    }

    #[test]
    fn test_tun_fd_raw_returns_option() {
        let _val: Option<String> = tun_fd_raw();
    }
    // -------- bd 1n90/xag3②：use_splice 缓存 + reload 行为等价三态 --------

    /// env 是进程全局：三态测试串行化（惯例同 xray-conf common.rs ENV_LOCK）。
    static SPLICE_ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[test]
    fn use_splice_cached_env_three_states() {
        let _g = SPLICE_ENV_LOCK.lock();

        const NAME: &str = "xray.buf.splice";
        const ALT: &str = "XRAY_BUF_SPLICE";
        let saved_name = std::env::var_os(NAME);
        let saved_alt = std::env::var_os(ALT);
        struct Restore(Option<std::ffi::OsString>, Option<std::ffi::OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                unsafe {
                    match self.0.take() {
                        Some(v) => std::env::set_var(NAME, v),
                        None => std::env::remove_var(NAME),
                    }
                    match self.1.take() {
                        Some(v) => std::env::set_var(ALT, v),
                        None => std::env::remove_var(ALT),
                    }
                }
                // 按恢复后的 env 重解析，不把测试态泄漏给后续测试
                super::reload_env_settings();
            }
        }
        unsafe {
            std::env::remove_var(NAME);
            std::env::remove_var(ALT);
        }
        let _restore = Restore(saved_name, saved_alt);

        // ① 不设 → Go 缺省开（freedom.go defaultFlagValue）
        reload_env_settings();
        assert!(use_splice(), "未设置应启用（Go 缺省）");

        // ② 显式启用值（精确匹配）
        for on in ["auto", "enable"] {
            unsafe { std::env::set_var(NAME, on) };
            reload_env_settings();
            assert!(use_splice(), "env={on:?} 应启用");
        }

        // ③ 非法值一律禁用（大小写敏感，空串 = LookupEnv 命中 switch 落空）
        for off in ["disable", "true", "1", "", "AUTO", "Enable"] {
            unsafe { std::env::set_var(NAME, off) };
            reload_env_settings();
            assert!(!use_splice(), "env={off:?} 应禁用");
        }

        // ④ 缓存语义：env 变更不 reload 不生效（热路径零 env 查询的行为证据）
        unsafe { std::env::set_var(NAME, "auto") };
        assert!(!use_splice(), "不 reload 不应翻转（缓存生效）");
        reload_env_settings();
        assert!(use_splice(), "reload 后应翻转");

        // ⑤ alt 名兜底 + 原名优先
        unsafe {
            std::env::remove_var(NAME);
            std::env::set_var(ALT, "auto");
        }
        reload_env_settings();
        assert!(use_splice(), "alt 名应兜底");
        unsafe { std::env::set_var(NAME, "disable") };
        reload_env_settings();
        assert!(!use_splice(), "原名命中时优先于 alt");
    }
}

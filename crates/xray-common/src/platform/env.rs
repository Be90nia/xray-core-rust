//! 平台环境标志
//!
//! 对应 Go 版本 `platform.NewEnvFlag`，提供环境变量读取和类型转换。

use std::sync::{LazyLock, OnceLock};

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
        Self {
            name,
            alt_name,
            value: OnceLock::new(),
        }
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
                    .or_else(|| {
                        std::env::var(&self.alt_name)
                            .ok()
                            .filter(|v| !v.is_empty())
                    })
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
/// USE_READV 环境标志（Go `xray.buf.readv`，alt `XRAY_BUF_READV`）。
static USE_READV_FLAG: LazyLock<EnvFlag> =
    LazyLock::new(|| EnvFlag::new("xray.buf.readv"));

/// 获取 USE_READV 标志的值。
///
/// 对应 Go 版本 `platform.UseReadV`：`xray.buf.readv`（或 `XRAY_BUF_READV`）
/// 设为真值时返回 `true`，未设置默认 `false`。
pub fn use_readv() -> bool {
    USE_READV_FLAG.get_value_as_bool()
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
}

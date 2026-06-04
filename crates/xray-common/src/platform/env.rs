//! 平台环境标志
//!
//! 对应 Go 版本 `platform.NewEnvFlag`，提供环境变量读取和类型转换。

use std::sync::OnceLock;

/// 环境标志，首次访问时从环境变量读取值并缓存。
///
/// 对应 Go 版本 `platform.EnvFlag`。
pub struct EnvFlag {
    name: String,
    value: OnceLock<Option<String>>,
}

impl EnvFlag {
    /// 创建新的环境标志。
    ///
    /// `name` 为环境变量名称，值在首次 `get_value()` 调用时读取。
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: OnceLock::new(),
        }
    }

    /// 获取标志值，首次访问时从环境变量读取。
    ///
    /// 返回环境变量的字符串值引用，未设置时返回 `None`。
    pub fn get_value(&self) -> Option<&str> {
        self.value
            .get_or_init(|| std::env::var(&self.name).ok())
            .as_deref()
    }

    /// 获取标志值的布尔形式，默认为 `false`。
    ///
    /// 以下值（不区分大小写）视为 `true`：`"1"`、`"true"`、`"yes"`、`"on"`。
    pub fn get_value_as_bool(&self) -> bool {
        match self.get_value() {
            Some(v) => matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
            None => false,
        }
    }

    /// 获取标志值的整数形式。
    ///
    /// 环境变量未设置或无法解析为整数时返回 `None`。
    pub fn get_value_as_int(&self) -> Option<i64> {
        self.get_value().and_then(|v| v.parse().ok())
    }
}

/// USE_READV 环境标志的名称
const USE_READV_ENV_NAME: &str = "XRAY_USE_READV";

/// 全局 USE_READV 标志实例
static USE_READV_FLAG: OnceLock<EnvFlag> = OnceLock::new();

/// 获取 USE_READV 标志的值。
///
/// 对应 Go 版本 `platform.UseReadV`。
/// 当环境变量 `XRAY_USE_READV` 设置为 `"1"`、`"true"`、`"yes"` 或 `"on"` 时返回 `true`。
///
/// 在 Linux 平台上默认建议启用 readv，但此函数严格按环境变量判断。
pub fn use_readv() -> bool {
    USE_READV_FLAG
        .get_or_init(|| EnvFlag::new(USE_READV_ENV_NAME))
        .get_value_as_bool()
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

//! # Transport configuration
//!
//! 对应 Go `transport/internet/config.go`。全局传输配置注册表。

use std::collections::HashMap;
use std::io;
use std::sync::Mutex;

static TRANSPORT_CONFIG: std::sync::OnceLock<Mutex<HashMap<String, serde_json::Value>>> = std::sync::OnceLock::new();

/// 全局配置注册表最大条目数。超出返回 CapacityExceeded 错误。
const MAX_CONFIG_ENTRIES: usize = 256;

fn transport_config() -> &'static Mutex<HashMap<String, serde_json::Value>> {
    TRANSPORT_CONFIG.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn register_transport_config(tag: &str, config: serde_json::Value) -> io::Result<()> {
    let mut map = transport_config().lock().unwrap();
    if map.len() >= MAX_CONFIG_ENTRIES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("transport config registry full ({MAX_CONFIG_ENTRIES})"),
        ));
    }
    map.insert(tag.to_string(), config);
    Ok(())
}

pub fn get_transport_config(tag: &str) -> Option<serde_json::Value> {
    transport_config().lock().unwrap().get(tag).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    /// 全局 map 的测试间互斥（并行 clear/register 竞争曾致 flaky）。
    static TEST_LOCK: LazyLock<parking_lot::Mutex<()>> = LazyLock::new(|| parking_lot::Mutex::new(()));

    #[test]
    fn register_and_get() {
        let _g = TEST_LOCK.lock();
        transport_config().lock().unwrap().clear();
        register_transport_config("test-tgg", serde_json::json!({"k":"v"})).unwrap();
        assert_eq!(
            get_transport_config("test-tgg").unwrap(),
            serde_json::json!({"k":"v"})
        );
    }

    #[test]
    fn register_exceeds_capacity() {
        let _g = TEST_LOCK.lock();
        transport_config().lock().unwrap().clear();
        for i in 0..MAX_CONFIG_ENTRIES {
            register_transport_config(&format!("cap-{i}"), serde_json::json!(i)).unwrap();
        }
        let result = register_transport_config("overflow", serde_json::json!(0));
        assert!(result.is_err());
        transport_config().lock().unwrap().clear();
    }
}

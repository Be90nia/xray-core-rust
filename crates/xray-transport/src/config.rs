//! # Transport configuration
//!
//! 对应 Go `transport/internet/config.go`。全局传输配置注册表。

use std::collections::HashMap;
use std::sync::Mutex;

static TRANSPORT_CONFIG: std::sync::OnceLock<Mutex<HashMap<String, serde_json::Value>>> = std::sync::OnceLock::new();
fn transport_config() -> &'static Mutex<HashMap<String, serde_json::Value>> {
    TRANSPORT_CONFIG.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn register_transport_config(tag: &str, config: serde_json::Value) {
    transport_config().lock().unwrap().insert(tag.to_string(), config);
}

pub fn get_transport_config(tag: &str) -> Option<serde_json::Value> {
    transport_config().lock().unwrap().get(tag).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn register_and_get() {
        register_transport_config("test-tgg", serde_json::json!({"k":"v"}));
        assert_eq!(
            get_transport_config("test-tgg").unwrap(),
            serde_json::json!({"k":"v"})
        );
    }
}

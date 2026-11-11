//! JSON 点路径取值。对应 Go `jsonpath.go`（39 行，逐条对齐）。
//!
//! Go 语义：payload 非法 JSON → 全 nil；路径按 `.` 逐键下钻 object
//! （数组不寻址，中途失配 → nil）；[`json_string`] 缺省 `""`、
//! [`json_number`] 缺省 `0`（float 截断）。

use serde_json::Value;

/// 下钻到路径终点后取叶子（Go `jsonWalk` 的闭包形态：免中间 `Value` 克隆）。
fn walk<T>(payload: &[u8], path: &str, leaf: impl for<'a> Fn(&'a Value) -> Option<T>) -> Option<T> {
    let root: Value = serde_json::from_slice(payload).ok()?;
    let mut node = &root;
    for key in path.split('.') {
        node = node.as_object()?.get(key)?;
    }
    leaf(node)
}

/// 点路径取字符串值；缺省 `""`（Go `jsonString`）。
#[must_use]
pub(crate) fn json_string(payload: &[u8], path: &str) -> String {
    walk(payload, path, |v| v.as_str().map(str::to_owned)).unwrap_or_default()
}

/// 点路径取数值（float 截断为 i64）；缺省 `0`（Go `jsonNumber`）。
#[must_use]
pub(crate) fn json_number(payload: &[u8], path: &str) -> i64 {
    walk(payload, path, |v| v.as_f64()).map_or(0, |f| f as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: &str = r#"{"access_token":"tok","expires_in":3600,"nested":{"href":"http://x/y","deep":{"n":7.9}},"list":[1,2]}"#;

    #[test]
    fn string_walks_nested_path() {
        assert_eq!(json_string(PAYLOAD.as_bytes(), "access_token"), "tok");
        assert_eq!(json_string(PAYLOAD.as_bytes(), "nested.href"), "http://x/y");
    }

    #[test]
    fn missing_path_defaults_empty() {
        assert_eq!(json_string(PAYLOAD.as_bytes(), "nope"), "");
        assert_eq!(json_string(PAYLOAD.as_bytes(), "nested.missing"), "");
        assert_eq!(json_string(PAYLOAD.as_bytes(), ""), "");
    }

    #[test]
    fn array_is_not_addressable() {
        // Go map 断言失败 → nil：数组节点与数组下标都取不到。
        assert_eq!(json_string(PAYLOAD.as_bytes(), "list.0"), "");
        assert_eq!(json_number(PAYLOAD.as_bytes(), "list"), 0);
    }

    #[test]
    fn invalid_json_yields_defaults() {
        assert_eq!(json_string(b"not json", "access_token"), "");
        assert_eq!(json_number(b"{", "x"), 0);
    }

    #[test]
    fn number_truncates_float() {
        assert_eq!(json_number(PAYLOAD.as_bytes(), "nested.deep.n"), 7);
        assert_eq!(json_number(PAYLOAD.as_bytes(), "expires_in"), 3600);
        assert_eq!(json_number(PAYLOAD.as_bytes(), "access_token"), 0);
    }
}

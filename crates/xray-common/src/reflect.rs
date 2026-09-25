//! 类型反射与 JSON 序列化工具
//!
//! 对应 Go 版本 `common/reflect` 包，提供带类型信息的 JSON 序列化/反序列化功能。

use serde_json::Value;

use crate::serial::TypedMessage;

/// 反射错误类型
#[derive(Debug, thiserror::Error)]
pub enum ReflectError {
    /// 序列化失败
    #[error("serialization failed: {0}")]
    SerializationError(String),
    /// 反序列化失败
    #[error("deserialization failed: {0}")]
    DeserializationError(String),
    /// 无效的类型 URL
    #[error("invalid type URL: {0}")]
    InvalidTypeUrl(String),
}

impl From<serde_json::Error> for ReflectError {
    fn from(err: serde_json::Error) -> Self {
        ReflectError::SerializationError(err.to_string())
    }
}

/// 将值序列化为 JSON 字符串。
///
/// 对应 Go 版本 `reflect.MarshalToJson`。
pub fn marshal_to_json<T: serde::Serialize>(value: &T) -> Result<String, ReflectError> {
    serde_json::to_string(value).map_err(|e| ReflectError::SerializationError(e.to_string()))
}

/// 将值序列化为格式化的 JSON 字符串。
pub fn marshal_to_json_pretty<T: serde::Serialize>(value: &T) -> Result<String, ReflectError> {
    serde_json::to_string_pretty(value).map_err(|e| ReflectError::SerializationError(e.to_string()))
}

/// 将 TypedMessage 序列化为带类型信息的 JSON 字符串。
///
/// 对应 Go 版本 `reflect.JSONMarshalWithoutEscape`。
/// 输出格式为包含 `@type` 字段的 JSON 对象。
pub fn marshal_typed_message_to_json(msg: &TypedMessage) -> Result<String, ReflectError> {
    let value = typed_message_to_json_value(msg)?;
    serde_json::to_string(&value).map_err(|e| ReflectError::SerializationError(e.to_string()))
}

/// 从 JSON 字符串反序列化为指定类型。
///
/// 对应 Go 版本 `reflect.UnmarshalFromJSON`。
pub fn unmarshal_from_json<T: serde::de::DeserializeOwned>(json: &str) -> Result<T, ReflectError> {
    serde_json::from_str(json).map_err(|e| ReflectError::DeserializationError(e.to_string()))
}

/// 将 TypedMessage 转换为 serde_json::Value。
///
/// 将消息体字节解析为 JSON 值，并注入 `@type` 字段。
/// 如果消息体不是有效的 JSON，则将其包装为包含原始字节的 JSON 对象。
pub fn typed_message_to_json_value(msg: &TypedMessage) -> Result<Value, ReflectError> {
    if msg.type_url.is_empty() {
        return Err(ReflectError::InvalidTypeUrl("type URL must not be empty".into()));
    }

    // 尝试将消息体解析为 JSON
    let mut base_value: Value = if msg.value.is_empty() {
        serde_json::json!({})
    } else {
        match serde_json::from_slice(&msg.value) {
            Ok(v) => v,
            Err(_) => {
                // 消息体不是有效 JSON，将原始字节 base64 编码后放入对象
                serde_json::json!({
                    "value": msg.value,
                })
            },
        }
    };

    // 注入 @type 字段
    if let Some(obj) = base_value.as_object_mut() {
        obj.insert("@type".into(), Value::String(msg.type_url.clone()));
    } else {
        // 基础值不是对象，包装为对象
        base_value = serde_json::json!({
            "@type": msg.type_url,
            "value": base_value,
        });
    }

    Ok(base_value)
}

/// 从 JSON Value 中提取类型 URL。
///
/// 查找 `@type` 字段并返回其字符串值。
pub fn extract_type_url(value: &Value) -> Option<&str> {
    value.as_object()?.get("@type")?.as_str()
}

/// 从 JSON Value 中移除 `@type` 字段，返回剩余内容。
///
/// 用于在反序列化时剥离类型信息。
pub fn strip_type_url(value: &mut Value) -> Option<String> {
    let obj = value.as_object_mut()?;
    obj.remove("@type")?.as_str().map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
    struct TestStruct {
        name: String,
        value: i32,
    }

    #[test]
    fn test_marshal_to_json() {
        let data = TestStruct { name: "test".into(), value: 42 };
        let json = marshal_to_json(&data).expect("marshal should succeed");
        assert!(json.contains("\"name\""));
        assert!(json.contains("\"test\""));
        assert!(json.contains("\"value\""));
        assert!(json.contains("42"));
    }

    #[test]
    fn test_marshal_to_json_pretty() {
        let data = TestStruct { name: "test".into(), value: 42 };
        let json = marshal_to_json_pretty(&data).expect("marshal should succeed");
        assert!(json.contains('\n'));
    }

    #[test]
    fn test_unmarshal_from_json() {
        let json = r#"{"name":"hello","value":99}"#;
        let data: TestStruct = unmarshal_from_json(json).expect("unmarshal should succeed");
        assert_eq!(data.name, "hello");
        assert_eq!(data.value, 99);
    }

    #[test]
    fn test_unmarshal_from_json_invalid() {
        let result = unmarshal_from_json::<TestStruct>("not json");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ReflectError::DeserializationError(_)));
    }

    #[test]
    fn test_marshal_unmarshal_roundtrip() {
        let original = TestStruct { name: "roundtrip".into(), value: 123 };
        let json = marshal_to_json(&original).expect("marshal should succeed");
        let restored: TestStruct = unmarshal_from_json(&json).expect("unmarshal should succeed");
        assert_eq!(original, restored);
    }

    #[test]
    fn test_typed_message_to_json_value_with_json_body() {
        let msg =
            TypedMessage::new("type.googleapis.com/xray.Test", br#"{"field":"hello"}"#.to_vec());
        let value = typed_message_to_json_value(&msg).expect("should succeed");
        assert_eq!(value["@type"], "type.googleapis.com/xray.Test");
        assert_eq!(value["field"], "hello");
    }

    #[test]
    fn test_typed_message_to_json_value_with_non_json_body() {
        let msg = TypedMessage::new("type.googleapis.com/xray.Test", vec![0x01, 0x02, 0x03]);
        let value = typed_message_to_json_value(&msg).expect("should succeed");
        assert_eq!(value["@type"], "type.googleapis.com/xray.Test");
        // 非 JSON 消息体应包含 value 字段
        assert!(value.get("value").is_some());
    }

    #[test]
    fn test_typed_message_to_json_value_empty_body() {
        let msg = TypedMessage::new("type.googleapis.com/xray.Test", vec![]);
        let value = typed_message_to_json_value(&msg).expect("should succeed");
        assert_eq!(value["@type"], "type.googleapis.com/xray.Test");
    }

    #[test]
    fn test_typed_message_to_json_value_empty_type_url() {
        let msg = TypedMessage::new("", vec![1, 2, 3]);
        let result = typed_message_to_json_value(&msg);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ReflectError::InvalidTypeUrl(_)));
    }

    #[test]
    fn test_marshal_typed_message_to_json() {
        let msg =
            TypedMessage::new("type.googleapis.com/xray.Test", br#"{"field":"hello"}"#.to_vec());
        let json = marshal_typed_message_to_json(&msg).expect("should succeed");
        assert!(json.contains("@type"));
        assert!(json.contains("type.googleapis.com/xray.Test"));
    }

    #[test]
    fn test_extract_type_url() {
        let value = serde_json::json!({
            "@type": "type.googleapis.com/xray.Test",
            "field": "hello"
        });
        assert_eq!(extract_type_url(&value), Some("type.googleapis.com/xray.Test"));
    }

    #[test]
    fn test_extract_type_url_missing() {
        let value = serde_json::json!({"field": "hello"});
        assert_eq!(extract_type_url(&value), None);
    }

    #[test]
    fn test_strip_type_url() {
        let mut value = serde_json::json!({
            "@type": "type.googleapis.com/xray.Test",
            "field": "hello"
        });
        let type_url = strip_type_url(&mut value).expect("should extract");
        assert_eq!(type_url, "type.googleapis.com/xray.Test");
        assert!(value.get("@type").is_none());
        assert_eq!(value["field"], "hello");
    }

    #[test]
    fn test_reflect_error_from_serde_json_error() {
        let serde_err = serde_json::from_str::<i32>("not a number").unwrap_err();
        let reflect_err: ReflectError = serde_err.into();
        assert!(matches!(reflect_err, ReflectError::SerializationError(_)));
    }

    #[test]
    fn test_reflect_error_display() {
        let err = ReflectError::InvalidTypeUrl("empty".into());
        assert!(err.to_string().contains("empty"));
    }
}

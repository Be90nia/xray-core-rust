//! 协议账号载荷编解码（Go 线格式对齐，bd c89uy）。
//!
//! # Go 线格式（26.10.17）
//!
//! `xray.common.protocol.User{level: u32, email: string, account: TypedMessage}`，
//! 其中 `account = TypedMessage{Type: "xray.proxy.<proto>.Account", Value: <该协议
//! Account 的 protobuf 字节>}`——Go 各协议 `infra/conf/*.go` 的 `Build()` 产的就是
//! 这个形状（`serial.ToTypedMessage(&vless.Account{Id, Flow, …})`、
//! `&vmess.Account{Id, SecuritySettings}`、`&trojan.Account{Password}`、
//! `&shadowsocks.Account{Password, CipherType}`、`&shadowsocks_2022.Account{Key}`、
//! `&hysteriaaccount.Account{Auth}`）。
//!
//! # Rust 内部契约
//!
//! 入站用户管理器（`inbound.rs` 的 `ApiUserManager` 各实现）消费的是 account 的
//! **JSON 文本**（`{"id":…}` / `{"password":…}` / `{"method":…}` …）。本件在
//! wire(proto Account) ↔ 内部(JSON) 之间做**按 type_url 显式分派**的映射：
//!
//! - 客户端侧（`xray api adu`）：配置 JSON 的用户条目 → proto Account；
//! - 服务端侧（gRPC `AlterInbound` → `add_user`）：proto Account → 内部 JSON。
//!
//! # 判别方式（不做 try-parse 静默回退）
//!
//! 服务端按 `account.type_url` **逐协议显式分派**：命中已知 type_url ⇒ 按该协议解
//! proto，**解失败即报错**（不回落「再试 JSON」）；未知 type_url ⇒ 原样透传
//! （内部契约即原始载荷的协议——如 wireguard——由其管理器自行解释）。
//!
//! 另兼容**旧 Rust 客户端**的历史 JSON 载荷：其 value 以 `'{'`（0x7B）开头；
//! proto Account 的合法首字节不会是 0x7B（各 Account 字段号 ≤ 9），故该判别无歧义，
//! 命中即按 legacy JSON 原样透传——这是**唯一**一条显式的兼容路径，不是兜底回退。

use prost::Message as _;
use serde_json::json;
use xray_proto::xray::common::serial::TypedMessage;

/// vless 账号 type_url（Go `serial.ToTypedMessage(&vless.Account{…})`）。
pub const TYPE_VLESS: &str = "xray.proxy.vless.Account";
/// vmess 账号 type_url。
pub const TYPE_VMESS: &str = "xray.proxy.vmess.Account";
/// trojan 账号 type_url。
pub const TYPE_TROJAN: &str = "xray.proxy.trojan.Account";
/// shadowsocks（legacy AEAD）账号 type_url。
pub const TYPE_SHADOWSOCKS: &str = "xray.proxy.shadowsocks.Account";
/// shadowsocks 2022 账号 type_url（Go `infra/conf/shadowsocks.go:142`）。
pub const TYPE_SHADOWSOCKS_2022: &str = "xray.proxy.shadowsocks_2022.Account";
/// hysteria 账号 type_url（Go `infra/conf/hysteria.go:59`，类型在 account 子包）。
pub const TYPE_HYSTERIA: &str = "xray.proxy.hysteria.account.Account";

/// 账号载荷编解码错误。
#[derive(Debug, thiserror::Error)]
pub enum AccountCodecError {
    /// 协议不支持账号载荷编解码。
    #[error("unsupported account protocol: {0}")]
    UnsupportedProtocol(String),
    /// 必填字段缺失或为空。
    #[error("account field `{0}` missing or empty")]
    MissingField(&'static str),
    /// proto 解码失败。
    #[error("decode account proto: {0}")]
    Decode(String),
    /// JSON 序列化失败。
    #[error("encode account json: {0}")]
    Encode(String),
    /// 加密方式名无法解析（Go `cipherFromString` 同款硬错）。
    #[error("unsupported cipher method: {0}")]
    UnsupportedCipher(String),
}

/// 配置 JSON 用户条目 → Go 线格式的 account TypedMessage（客户端侧）。
///
/// `kind` = 协议名（`vless` / `vmess` / `trojan` / `shadowsocks` /
/// `shadowsocks_2022` / `hysteria`）；`settings` = 该 inbound 的 settings JSON
/// （shadowsocks 需要服务端级 `method` 判 2022 分支，Go `shadowsocks.go:58`）。
pub fn account_typed_message_from_config_json(
    kind: &str,
    settings: &serde_json::Value,
    entry: &serde_json::Value,
) -> Result<TypedMessage, AccountCodecError> {
    let (type_url, value) = match kind {
        "vless" => {
            let acc = xray_proto::xray::proxy::vless::Account {
                id: require_str(entry, "id")?,
                // Go `infra/conf/vless.go:72-77`：用户级 flow 缺省继承 inbound 级 flow。
                flow: entry
                    .get("flow")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .unwrap_or("")
                    .to_string(),
                ..Default::default()
            };
            (TYPE_VLESS, acc.encode_to_vec())
        },
        "vmess" => {
            let acc = xray_proto::xray::proxy::vmess::Account {
                id: require_str(entry, "id")?,
                // Go `infra/conf/vmess.go:33-44`：security 映射 proto SecurityType，
                // 未知值回落 AUTO。
                security_settings: Some(xray_proto::xray::common::protocol::SecurityConfig {
                    r#type: vmess_security_type(
                        entry.get("security").and_then(|v| v.as_str()).unwrap_or(""),
                    ),
                }),
                tests_enabled: String::new(),
            };
            (TYPE_VMESS, acc.encode_to_vec())
        },
        "trojan" => {
            let acc = xray_proto::xray::proxy::trojan::Account {
                password: require_str(entry, "password")?,
            };
            (TYPE_TROJAN, acc.encode_to_vec())
        },
        "shadowsocks" => {
            // Go `infra/conf/shadowsocks.go:58-60`：服务端 method 命中 2022 ⇒ 走
            // `buildShadowsocks2022`（账号 = `shadowsocks_2022.Account{Key}`）；
            // 否则 legacy AEAD（账号 = `shadowsocks.Account{Password, CipherType}`，
            // cipher 取用户级 method，缺省回落服务端级 method）。
            let server_method = settings
                .get("method")
                .or_else(|| settings.get("cipher"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let user_method = entry
                .get("method")
                .or_else(|| entry.get("cipher"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let method = if user_method.is_empty() { server_method } else { user_method };
            let password = require_str(entry, "password")?;
            if is_ss2022_method(method) {
                let acc = xray_proto::xray::proxy::shadowsocks_2022::Account { key: password };
                (TYPE_SHADOWSOCKS_2022, acc.encode_to_vec())
            } else {
                let cipher = xray_proxy_ss::CipherType::from_name(method)
                    .ok_or_else(|| AccountCodecError::UnsupportedCipher(method.to_string()))?;
                let acc = xray_proto::xray::proxy::shadowsocks::Account {
                    password,
                    cipher_type: cipher.as_i32(),
                    iv_check: false,
                };
                (TYPE_SHADOWSOCKS, acc.encode_to_vec())
            }
        },
        "shadowsocks_2022" => {
            // Go `infra/conf/shadowsocks.go:142-144`：ss2022 账号字段名是 `Key`
            // （值与 JSON 的 `password` 同源）。
            let acc = xray_proto::xray::proxy::shadowsocks_2022::Account {
                key: require_str(entry, "password")?,
            };
            (TYPE_SHADOWSOCKS_2022, acc.encode_to_vec())
        },
        "hysteria" => {
            let acc = xray_proto::xray::proxy::hysteria::account::Account {
                auth: require_str(entry, "auth")?,
            };
            (TYPE_HYSTERIA, acc.encode_to_vec())
        },
        other => return Err(AccountCodecError::UnsupportedProtocol(other.to_string())),
    };
    Ok(TypedMessage { r#type: type_url.to_string(), value })
}

/// Go 线格式的 account TypedMessage → 内部 JSON 契约字节（服务端侧）。
///
/// 判别规则见模块文档：按 `type_url` 显式分派；已知 type_url 解 proto 失败即报错；
/// 未知 type_url 原样透传；旧 Rust 客户端的 JSON 载荷（以 `'{'` 开头）原样透传。
pub fn account_internal_json_from_typed_message(
    tm: &TypedMessage,
) -> Result<Vec<u8>, AccountCodecError> {
    // 旧 Rust 客户端的 JSON 载荷（显式判别，非 try-parse 回退）。
    if tm.value.first() == Some(&b'{') {
        return Ok(tm.value.clone());
    }
    let json = match tm.r#type.as_str() {
        TYPE_VLESS => {
            let acc = xray_proto::xray::proxy::vless::Account::decode(tm.value.as_slice())
                .map_err(|e| AccountCodecError::Decode(format!("{TYPE_VLESS}: {e}")))?;
            json!({"id": acc.id, "flow": acc.flow})
        },
        TYPE_VMESS => {
            let acc = xray_proto::xray::proxy::vmess::Account::decode(tm.value.as_slice())
                .map_err(|e| AccountCodecError::Decode(format!("{TYPE_VMESS}: {e}")))?;
            json!({"id": acc.id})
        },
        TYPE_TROJAN => {
            let acc = xray_proto::xray::proxy::trojan::Account::decode(tm.value.as_slice())
                .map_err(|e| AccountCodecError::Decode(format!("{TYPE_TROJAN}: {e}")))?;
            json!({"password": acc.password})
        },
        TYPE_SHADOWSOCKS => {
            let acc = xray_proto::xray::proxy::shadowsocks::Account::decode(tm.value.as_slice())
                .map_err(|e| AccountCodecError::Decode(format!("{TYPE_SHADOWSOCKS}: {e}")))?;
            // 内部契约用 method 名（`inbound.rs` 的 ss 管理器读 "method"/"cipher"）。
            json!({
                "password": acc.password,
                "method": cipher_name(acc.cipher_type).unwrap_or_default(),
            })
        },
        TYPE_SHADOWSOCKS_2022 => {
            let acc =
                xray_proto::xray::proxy::shadowsocks_2022::Account::decode(tm.value.as_slice())
                    .map_err(|e| {
                        AccountCodecError::Decode(format!("{TYPE_SHADOWSOCKS_2022}: {e}"))
                    })?;
            // proto 字段名 `Key` ↔ 内部 JSON 字段名 `password`（同一 base64 PSK）。
            json!({"password": acc.key})
        },
        TYPE_HYSTERIA => {
            let acc =
                xray_proto::xray::proxy::hysteria::account::Account::decode(tm.value.as_slice())
                    .map_err(|e| AccountCodecError::Decode(format!("{TYPE_HYSTERIA}: {e}")))?;
            json!({"auth": acc.auth})
        },
        // 未知 type_url：内部契约即原始载荷的协议（wireguard 等）自行解释。
        _ => return Ok(tm.value.clone()),
    };
    serde_json::to_vec(&json).map_err(|e| AccountCodecError::Encode(e.to_string()))
}

/// 把 `xray.common.protocol.User` 的 account 载荷规范成内部 JSON 契约。
///
/// 服务端 gRPC `AlterInbound(AddUserOperation)` 入口用：wire 上的 proto Account
/// ⇒ 内部 JSON（`inbound.rs` 的用户管理器消费），**不改** type_url 与 email/level。
pub fn normalize_user_account(
    user: &mut xray_proto::xray::common::protocol::User,
) -> Result<(), AccountCodecError> {
    let Some(account) = user.account.as_ref() else {
        return Ok(());
    };
    let normalized = account_internal_json_from_typed_message(account)?;
    user.account = Some(TypedMessage { r#type: account.r#type.clone(), value: normalized });
    Ok(())
}

/// 取必填字符串字段（非空）。
fn require_str(entry: &serde_json::Value, key: &'static str) -> Result<String, AccountCodecError> {
    entry
        .get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or(AccountCodecError::MissingField(key))
}

/// vmess `security` 字符串 → proto `SecurityType`（Go `infra/conf/vmess.go:33-44`）。
///
/// `aes-128-gcm` → AES128_GCM(3)；`chacha20-poly1305` → CHACHA20_POLY1305(4)；
/// 其余（含 `auto`）→ AUTO(2)。
fn vmess_security_type(name: &str) -> i32 {
    match name.to_ascii_lowercase().as_str() {
        "aes-128-gcm" => 3,
        "chacha20-poly1305" => 4,
        _ => 2,
    }
}

/// proto `CipherType` 数值 → method 名（Go `cipherFromString` 的逆映射）。
fn cipher_name(cipher_type: i32) -> Option<&'static str> {
    Some(match cipher_type {
        5 => "aes-128-gcm",
        6 => "aes-256-gcm",
        7 => "chacha20-poly1305",
        8 => "xchacha20-poly1305",
        _ => return None,
    })
}

/// shadowsocks 2022 method 判定（Go `shadowsocks_2022.GetCipherMethod` 的前缀口径）。
fn is_ss2022_method(method: &str) -> bool {
    method.get(..12).is_some_and(|p| p.eq_ignore_ascii_case("2022-blake3-"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> serde_json::Value {
        json!({})
    }

    /// 客户端编码 → 服务端解码 的往返：每个协议都保真关键字段。
    #[test]
    fn vless_account_roundtrip_preserves_id_and_flow() {
        let tm = account_typed_message_from_config_json(
            "vless",
            &settings(),
            &json!({"id": "27848739-7e62-4138-9fd3-098a63964b6b", "flow": "xtls-rprx-vision"}),
        )
        .expect("encode");
        assert_eq!(tm.r#type, TYPE_VLESS);
        let internal = account_internal_json_from_typed_message(&tm).expect("decode");
        let v: serde_json::Value = serde_json::from_slice(&internal).expect("json");
        assert_eq!(v["id"], "27848739-7e62-4138-9fd3-098a63964b6b");
        assert_eq!(v["flow"], "xtls-rprx-vision");
    }

    #[test]
    fn vmess_account_roundtrip_preserves_id() {
        let tm = account_typed_message_from_config_json(
            "vmess",
            &settings(),
            &json!({"id": "e641f5ad-9397-41e3-bf1a-e8740dfed019", "security": "aes-128-gcm"}),
        )
        .expect("encode");
        assert_eq!(tm.r#type, TYPE_VMESS);
        // 编码出的 proto 必须是真正的 protobuf（Go 客户端按 proto 解）。
        let acc = xray_proto::xray::proxy::vmess::Account::decode(tm.value.as_slice())
            .expect("proto decode");
        assert_eq!(acc.id, "e641f5ad-9397-41e3-bf1a-e8740dfed019");
        let internal = account_internal_json_from_typed_message(&tm).expect("decode");
        let v: serde_json::Value = serde_json::from_slice(&internal).expect("json");
        assert_eq!(v["id"], "e641f5ad-9397-41e3-bf1a-e8740dfed019");
    }

    #[test]
    fn trojan_account_roundtrip_preserves_password() {
        let tm = account_typed_message_from_config_json(
            "trojan",
            &settings(),
            &json!({"password": "pw-1"}),
        )
        .expect("encode");
        assert_eq!(tm.r#type, TYPE_TROJAN);
        let internal = account_internal_json_from_typed_message(&tm).expect("decode");
        let v: serde_json::Value = serde_json::from_slice(&internal).expect("json");
        assert_eq!(v["password"], "pw-1");
    }

    #[test]
    fn shadowsocks_account_uses_cipher_method_name() {
        let tm = account_typed_message_from_config_json(
            "shadowsocks",
            &settings(),
            &json!({"password": "pw", "method": "aes-256-gcm"}),
        )
        .expect("encode");
        assert_eq!(tm.r#type, TYPE_SHADOWSOCKS);
        let internal = account_internal_json_from_typed_message(&tm).expect("decode");
        let v: serde_json::Value = serde_json::from_slice(&internal).expect("json");
        assert_eq!(v["password"], "pw");
        assert_eq!(v["method"], "aes-256-gcm");
    }

    #[test]
    fn shadowsocks_2022_method_switches_account_type() {
        // Go `infra/conf/shadowsocks.go:58`：服务端 method 命中 2022 ⇒ 账号是
        // `shadowsocks_2022.Account{Key}`（不是 legacy AEAD 的 Account）。
        let tm = account_typed_message_from_config_json(
            "shadowsocks",
            &json!({"method": "2022-blake3-aes-128-gcm"}),
            &json!({"password": "aGkgZnJvbSBzczIwMjIgc2VydmVyIHByaW1hcnkga2V5IQ=="}),
        )
        .expect("encode");
        assert_eq!(tm.r#type, TYPE_SHADOWSOCKS_2022);
        let acc = xray_proto::xray::proxy::shadowsocks_2022::Account::decode(tm.value.as_slice())
            .expect("proto decode");
        assert_eq!(acc.key, "aGkgZnJvbSBzczIwMjIgc2VydmVyIHByaW1hcnkga2V5IQ==");
        let internal = account_internal_json_from_typed_message(&tm).expect("decode");
        let v: serde_json::Value = serde_json::from_slice(&internal).expect("json");
        assert_eq!(v["password"], "aGkgZnJvbSBzczIwMjIgc2VydmVyIHByaW1hcnkga2V5IQ==");
    }

    #[test]
    fn hysteria_account_roundtrip_preserves_auth() {
        let tm = account_typed_message_from_config_json(
            "hysteria",
            &settings(),
            &json!({"auth": "tok"}),
        )
        .expect("encode");
        assert_eq!(tm.r#type, TYPE_HYSTERIA);
        let internal = account_internal_json_from_typed_message(&tm).expect("decode");
        let v: serde_json::Value = serde_json::from_slice(&internal).expect("json");
        assert_eq!(v["auth"], "tok");
    }

    /// 旧 Rust 客户端的 JSON 载荷（显式判别）原样透传，不被当成 proto 解。
    #[test]
    fn legacy_json_account_passes_through() {
        let legacy = br#"{"id":"uuid-1","flow":""}"#.to_vec();
        let tm = TypedMessage { r#type: TYPE_VLESS.to_string(), value: legacy.clone() };
        let internal = account_internal_json_from_typed_message(&tm).expect("decode");
        assert_eq!(internal, legacy);
    }

    /// 已知 type_url 的载荷解失败 ⇒ 报错（不静默回落 JSON 解析）。
    #[test]
    fn known_type_url_with_broken_proto_is_hard_error() {
        let tm = TypedMessage { r#type: TYPE_VLESS.to_string(), value: vec![0xff, 0xff, 0xff] };
        let err = account_internal_json_from_typed_message(&tm).expect_err("must fail");
        assert!(err.to_string().contains("decode account proto"), "实得: {err}");
    }

    /// 未知 type_url ⇒ 原样透传（wireguard 等「内部契约即原始载荷」的协议）。
    #[test]
    fn unknown_type_url_passes_through() {
        let raw = vec![1u8, 2, 3];
        let tm = TypedMessage {
            r#type: "xray.proxy.wireguard.PeerConfig".to_string(),
            value: raw.clone(),
        };
        let internal = account_internal_json_from_typed_message(&tm).expect("decode");
        assert_eq!(internal, raw);
    }

    /// 缺必填字段 ⇒ 硬错（不产出半个账号）。
    #[test]
    fn missing_required_field_is_hard_error() {
        let err =
            account_typed_message_from_config_json("vless", &settings(), &json!({"flow": "x"}))
                .expect_err("id required");
        assert!(err.to_string().contains("`id`"), "实得: {err}");
    }

    /// 未知协议 ⇒ 硬错。
    #[test]
    fn unknown_protocol_is_hard_error() {
        let err = account_typed_message_from_config_json("socks", &settings(), &json!({}))
            .expect_err("socks has no account proto");
        assert!(err.to_string().contains("unsupported account protocol"), "实得: {err}");
    }

    /// `normalize_user_account` 只改 account 的 value，type_url/email/level 不动。
    #[test]
    fn normalize_user_account_keeps_type_email_level() {
        let tm = account_typed_message_from_config_json(
            "trojan",
            &settings(),
            &json!({"password": "pw-x"}),
        )
        .expect("encode");
        let mut user = xray_proto::xray::common::protocol::User {
            level: 7,
            email: "u@x".to_string(),
            account: Some(tm),
        };
        normalize_user_account(&mut user).expect("normalize");
        let acc = user.account.as_ref().expect("account");
        assert_eq!(acc.r#type, TYPE_TROJAN);
        assert_eq!(user.level, 7);
        assert_eq!(user.email, "u@x");
        let v: serde_json::Value = serde_json::from_slice(&acc.value).expect("json");
        assert_eq!(v["password"], "pw-x");
    }
}

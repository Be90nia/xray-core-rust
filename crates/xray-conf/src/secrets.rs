//! 凭据收集：从已构建配置中提取四族协议凭据字面量（供日志掩码表使用）。
//!
//! 目的：装配期把配置里的凭据字面量装进 udf 通道掩码表
//! （`xray_common::log::set_secrets` → udf `ChannelRegistry::set_secrets`，
//! udf 侧唯一布点），使**任何**经通道落样的日志行中的凭据原文都被打码
//! （坑约束 11「密钥必掩码」）。掩码只作用于日志输出，不改任何 settings 值
//! （转发路径零影响）。
//!
//! 数据来源：既有 [`BuiltConfig`] + [`crate::protocols`] 的入/出站 settings 结构体
//! （`dispatch_inbound_settings` / `dispatch_outbound_settings`）——**不另造协议解析**。
//!
//! 覆盖族（T1.5 契约）：
//! - vmess：客户端 `id`（UUID）
//! - vless：客户端 `id`（UUID）
//! - trojan：客户端/服务端 `password`
//! - shadowsocks：`method` + `password`（SS2022 的 PSK 即 `password` 承载， 见
//!   `xray-core/src/inbound.rs` 的 ss2022 解析口径）

use serde_json::Value;

use crate::{
    BuiltConfig, BuiltEntry,
    protocols::{
        InboundSettings, OutboundSettings, dispatch_inbound_settings, dispatch_outbound_settings,
    },
};

/// 收集配置中的凭据字面量（去重、升序）。
///
/// 返回值直接喂给 udf 通道掩码表（`xray_common::log::set_secrets`）：
/// 命中子串即替换为 `***`，空串不产出条目。
#[must_use]
pub fn collect_secrets(built: &BuiltConfig) -> Vec<String> {
    let mut out = Vec::new();
    for inbound in &built.inbounds {
        collect_inbound(&inbound.entry, &mut out);
    }
    for outbound in &built.outbounds {
        collect_outbound(&outbound.entry, &mut out);
    }
    out.sort();
    out.dedup();
    out
}

/// 入站凭据收集（`clients` / `users` 双读，Go 形 `users` 为旧名别名）。
fn collect_inbound(entry: &BuiltEntry, out: &mut Vec<String>) {
    let Some(value) = parse_settings(entry) else { return };
    let settings = match dispatch_inbound_settings(&entry.kind, value) {
        Ok(Some(settings)) => settings,
        Ok(None) => return,
        Err(e) => {
            tracing::warn!(protocol = %entry.kind, error = %e, "secrets collection: inbound settings unparsable, skipped");
            return;
        },
    };
    match settings {
        InboundSettings::Vmess(s) => {
            for client in &s.clients {
                push_id(client, out);
            }
            for client in s.users.iter().flatten() {
                push_id(client, out);
            }
        },
        InboundSettings::Vless(s) => {
            for client in &s.clients {
                push_id(client, out);
            }
            for client in s.users.iter().flatten() {
                push_id(client, out);
            }
        },
        InboundSettings::Trojan(s) => {
            for user in s.clients.iter().flatten() {
                push_str(&user.password, out);
            }
            for user in s.users.iter().flatten() {
                push_str(&user.password, out);
            }
        },
        InboundSettings::Shadowsocks(s) => {
            push_str(&s.method, out);
            push_opt(s.password.as_deref(), out);
            for user in s.clients.iter().flatten() {
                push_opt(user.method.as_deref(), out);
                push_opt(user.password.as_deref(), out);
            }
            for user in s.users.iter().flatten() {
                push_opt(user.method.as_deref(), out);
                push_opt(user.password.as_deref(), out);
            }
        },
        _ => {},
    }
}

/// 出站凭据收集（服务端点上的 `id` / `password` 与入站同敏感级）。
fn collect_outbound(entry: &BuiltEntry, out: &mut Vec<String>) {
    let Some(value) = parse_settings(entry) else { return };
    let settings = match dispatch_outbound_settings(&entry.kind, value) {
        Ok(Some(settings)) => settings,
        Ok(None) => return,
        Err(e) => {
            tracing::warn!(protocol = %entry.kind, error = %e, "secrets collection: outbound settings unparsable, skipped");
            return;
        },
    };
    match settings {
        OutboundSettings::Vmess(s) => {
            push_opt(s.id.as_deref(), out);
            for target in s.vnext.iter().flatten() {
                for user in target.users.iter().flatten() {
                    push_id(user, out);
                }
            }
        },
        OutboundSettings::Vless(s) => {
            push_opt(s.id.as_deref(), out);
            for target in s.vnext.iter().flatten() {
                for user in target.users.iter().flatten() {
                    push_id(user, out);
                }
            }
        },
        OutboundSettings::Trojan(s) => {
            push_opt(s.password.as_deref(), out);
            for server in s.servers.iter().flatten() {
                push_str(&server.password, out);
            }
        },
        OutboundSettings::Shadowsocks(s) => {
            push_opt(s.method.as_deref(), out);
            push_opt(s.password.as_deref(), out);
            for server in s.servers.iter().flatten() {
                push_opt(server.method.as_deref(), out);
                push_opt(server.password.as_deref(), out);
            }
        },
        _ => {},
    }
}

/// 解析 entry 的 settings JSON；`clients`/`users` 显式 null 时按缺字段处理
/// （settings 结构体对 null 不容忍，Go 形语义为「null → 回退另一名」）。
fn parse_settings(entry: &BuiltEntry) -> Option<Value> {
    let mut value: Value = serde_json::from_slice(&entry.data).ok()?;
    if let Some(object) = value.as_object_mut() {
        for key in ["clients", "users"] {
            if object.get(key).is_some_and(Value::is_null) {
                object.remove(key);
            }
        }
    }
    Some(value)
}

/// 客户端 `id` 字面量（vmess/vless；settings 结构体里客户端条目按 Go
/// `json.RawMessage` 语义原样保留为 `Value`）。
fn push_id(client: &Value, out: &mut Vec<String>) {
    if let Some(id) = client.get("id").and_then(Value::as_str) {
        push_str(id, out);
    }
}

/// 追加一条凭据字面量（空串跳过——udf 掩码表对空串无意义）。
fn push_str(value: &str, out: &mut Vec<String>) {
    if !value.is_empty() {
        out.push(value.to_string());
    }
}

/// 追加一条可选凭据字面量。
fn push_opt(value: Option<&str>, out: &mut Vec<String>) {
    if let Some(value) = value {
        push_str(value, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Format, load_str};

    const VMESS_ID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const VLESS_ID: &str = "66ad4540-b58c-4ad2-9926-ea63445a9b57";
    const TROJAN_PASSWORD: &str = "trojan-pass-1";
    const SS_PASSWORD: &str = "ss-pass-1";
    const SS_METHOD: &str = "aes-256-gcm";

    /// 四族凭据齐备的配置（入站四族 + 出站同族；出站指向回环，避开明文出站禁令）。
    fn four_family_config() -> crate::Config {
        let json = serde_json::json!({
            "inbounds": [
                { "protocol": "vmess", "port": 10001, "tag": "vmess-in",
                  "settings": { "clients": [{ "id": VMESS_ID, "email": "vmess@example.com" }] } },
                { "protocol": "vless", "port": 10002, "tag": "vless-in",
                  "settings": { "decryption": "none", "clients": [{ "id": VLESS_ID }] } },
                { "protocol": "trojan", "port": 10003, "tag": "trojan-in",
                  "settings": { "clients": [{ "password": TROJAN_PASSWORD }] } },
                { "protocol": "shadowsocks", "port": 10004, "tag": "ss-in",
                  "settings": { "method": SS_METHOD, "password": SS_PASSWORD } },
            ],
            "outbounds": [
                { "protocol": "vmess", "tag": "vmess-out",
                  "settings": { "vnext": [{ "address": "127.0.0.1", "port": 443,
                    "users": [{ "id": VMESS_ID, "security": "auto" }] }] } },
                { "protocol": "vless", "tag": "vless-out",
                  "settings": { "vnext": [{ "address": "127.0.0.1", "port": 443,
                    "users": [{ "id": VLESS_ID, "encryption": "none" }] }] } },
                { "protocol": "trojan", "tag": "trojan-out",
                  "settings": { "servers": [{ "address": "127.0.0.1", "port": 443,
                    "password": TROJAN_PASSWORD }] } },
                { "protocol": "shadowsocks", "tag": "ss-out",
                  "settings": { "servers": [{ "address": "127.0.0.1", "port": 8388,
                    "method": SS_METHOD, "password": SS_PASSWORD }] } },
                { "protocol": "freedom", "tag": "direct" },
            ],
        });
        load_str(Format::Json, &serde_json::to_string(&json).unwrap()).expect("config parses")
    }

    /// 契约验收①：四族凭据齐备的配置 → secrets 集非空且含四类值。
    #[test]
    fn collect_secrets_covers_four_credential_families() {
        let built = four_family_config().build().expect("config builds");
        let secrets = collect_secrets(&built);

        assert!(!secrets.is_empty(), "secrets 集不得为空");
        for (family, value) in [
            ("vmess id", VMESS_ID),
            ("vless id", VLESS_ID),
            ("trojan password", TROJAN_PASSWORD),
            ("ss method", SS_METHOD),
            ("ss password", SS_PASSWORD),
        ] {
            assert!(
                secrets.iter().any(|s| s == value),
                "{family} 凭据未进 secrets 集: {secrets:?}"
            );
        }
    }

    /// 无凭据配置 → 空集（掩码表空 = 透传零分配）。
    #[test]
    fn collect_secrets_empty_for_credential_free_config() {
        let json = serde_json::json!({
            "inbounds": [
                { "protocol": "socks", "port": 10005, "tag": "socks-in", "settings": {} },
            ],
            "outbounds": [{ "protocol": "freedom", "tag": "direct" }],
        });
        let config =
            load_str(Format::Json, &serde_json::to_string(&json).unwrap()).expect("parses");
        let built = config.build().expect("config builds");
        assert!(collect_secrets(&built).is_empty());
    }
}

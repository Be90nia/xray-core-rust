//! 凭据收集：从已构建配置中提取四族协议凭据字面量（供日志掩码表使用）。
//!
//! 目的：装配期把配置里的凭据字面量装进 udf 通道掩码表
//! （`xray_common::log::set_secrets` → udf `ChannelRegistry::set_secrets`，
//! udf 侧唯一布点），使**任何**经通道落样的日志行中的凭据原文都被打码
//! （坑约束 11「密钥必掩码」）。掩码只作用于日志输出，不改任何 settings 值
//! （转发路径零影响）。
//!
//! 数据来源：既有 [`BuiltConfig`] 的入/出站 settings **原始 JSON**（`entry.data`）——
//! **不另造协议解析**（conf 层强类型 settings 层已归零：生产解析真源在 `xray-core`
//! 的 raw-JSON 解析器，conf 层那份是重复实现且无生产消费）。
//!
//! 覆盖族（T1.5 契约，键位与协议解析真源逐键对齐）：
//! - vmess：客户端 `id`（UUID）
//! - vless：客户端 `id`（UUID）
//! - trojan：客户端/服务端 `password`
//! - shadowsocks：`method` + `password`（SS2022 的 PSK 即 `password` 承载， 见
//!   `xray-core/src/inbound.rs` 的 ss2022 解析口径）
//!
//! 覆盖族（bd k0hdi 补全，原始 settings JSON 面——这些协议没有 conf 层结构体，
//! 或凭据键藏在 `accounts`/`users`/`servers` 嵌套里，见 `collect_generic`）：
//! anytls / tuic / naive / wireguard / hysteria / socks(含 mixed) / http / masque。

use serde_json::Value;

use crate::{BuiltConfig, BuiltEntry};

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
    // 全部协议统一走原始 JSON 扫描：conf 层强类型 settings 层已归零（生产解析真源在
    // xray-core 的 raw-JSON 解析器），凭据键位与各协议解析真源逐键对齐。
    collect_generic(&entry.kind, &value, out);
    match entry.kind.as_str() {
        "vmess" | "vless" => {
            for key in ["clients", "users"] {
                for_each(&value, key, |client| push_id(client, out));
            }
        },
        "trojan" => {
            for key in ["clients", "users"] {
                for_each(&value, key, |user| push_key(user, "password", out));
            }
        },
        "shadowsocks" => {
            push_key(&value, "method", out);
            push_key(&value, "password", out);
            for key in ["clients", "users"] {
                for_each(&value, key, |user| {
                    push_key(user, "method", out);
                    push_key(user, "password", out);
                });
            }
        },
        _ => {},
    }
}

/// 出站凭据收集（服务端点上的 `id` / `password` 与入站同敏感级）。
fn collect_outbound(entry: &BuiltEntry, out: &mut Vec<String>) {
    let Some(value) = parse_settings(entry) else { return };
    collect_generic(&entry.kind, &value, out);
    match entry.kind.as_str() {
        "vmess" | "vless" => {
            push_key(&value, "id", out);
            for_each(&value, "vnext", |target| {
                for_each(target, "users", |user| push_id(user, out));
            });
        },
        "trojan" => {
            push_key(&value, "password", out);
            for_each(&value, "servers", |server| push_key(server, "password", out));
        },
        "shadowsocks" => {
            push_key(&value, "method", out);
            push_key(&value, "password", out);
            for_each(&value, "servers", |server| {
                push_key(server, "method", out);
                push_key(server, "password", out);
            });
        },
        _ => {},
    }
}

/// 七族凭据键扫描（bd k0hdi）：这些协议在 conf 层没有强类型 settings 结构体
/// （anytls/tuic/naive/wireguard 的解析在 `xray-core`），或凭据键藏在嵌套数组里
/// （socks/http 的 `accounts`/`users`、hysteria 的 `users`、tuic 的 `servers`）。
/// 键名取自各协议权威解析点：
/// - anytls：`password`（`xray-core/src/inbound.rs` `parse_anytls_tls_acceptor`）
/// - tuic：`servers[].uuid` + `servers[].password`
/// - naive：出站 `username`/`password`，入站 `users[].name`/`users[].pass`
/// - wireguard：`secretKey`/`secret_key` + `peers[].preSharedKey`/`pre_shared_key`
///   （两侧公钥是公开材料，不进掩码）
/// - hysteria：`auth` + `users[].auth`（`clients` 旧名）+ `servers[].auth|password`
/// - socks/mixed/http：`user`/`pass`（顶层、`accounts[]`/`users[]`、`servers[].users[]`）
/// - masque：`users[].pass`（`clients` 别名；`email` 是日志面可记身份，不收）
fn collect_generic(protocol: &str, v: &Value, out: &mut Vec<String>) {
    match protocol {
        "anytls" => push_key(v, "password", out),
        "tuic" => for_each(v, "servers", |server| {
            push_key(server, "uuid", out);
            push_key(server, "password", out);
        }),
        "naive" => {
            for key in ["username", "password"] {
                push_key(v, key, out);
            }
            for_each(v, "users", |user| {
                push_key(user, "name", out);
                push_key(user, "pass", out);
            });
        },
        // masque：服务端 `users[].pass`（`clients` 为 Go 别名键）。只收 `pass`——
        // `email` 是日志面刻意可记的身份字段（B4 SecretMasking 口径：401 只记
        // email），不是秘密；Basic 凭据对的秘密半边 = pass。
        "masque" => {
            for key in ["users", "clients"] {
                for_each(v, key, |user| push_key(user, "pass", out));
            }
        },
        "wireguard" => {
            for key in ["secretKey", "secret_key"] {
                push_key(v, key, out);
            }
            for_each(v, "peers", |peer| {
                for key in ["preSharedKey", "pre_shared_key"] {
                    push_key(peer, key, out);
                }
            });
        },
        "hysteria" | "hysteria2" => {
            push_key(v, "auth", out);
            for key in ["users", "clients"] {
                for_each(v, key, |user| push_key(user, "auth", out));
            }
            for_each(v, "servers", |server| {
                push_key(server, "auth", out);
                push_key(server, "password", out);
            });
        },
        "socks" | "mixed" | "http" => {
            for key in ["user", "pass"] {
                push_key(v, key, out);
            }
            for key in ["accounts", "users"] {
                for_each(v, key, |account| {
                    push_key(account, "user", out);
                    push_key(account, "pass", out);
                });
            }
            for_each(v, "servers", |server| {
                for_each(server, "users", |account| {
                    push_key(account, "user", out);
                    push_key(account, "pass", out);
                });
            });
        },
        _ => {},
    }
}

/// 取 `v[key]` 的字符串字面量。掩码是安全侧最努力：缺失/非字符串跳过，
/// 类型异常由各协议解析点 fail-loud 处理。
fn push_key(v: &Value, key: &str, out: &mut Vec<String>) {
    push_opt(v.get(key).and_then(Value::as_str), out);
}

/// 遍历 `v[key]` 的数组元素（缺失或非数组 = 无元素）。
fn for_each(v: &Value, key: &str, mut f: impl FnMut(&Value)) {
    for item in v.get(key).and_then(Value::as_array).into_iter().flatten() {
        f(item);
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
    use crate::{BuiltInbound, BuiltOutbound, Format, load_str};

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
        // build() 会跑 lint 注册表（post_process），必须串行化且不留测试阶段。
        let _guard = crate::lint::lint_test_guard();
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
        let _guard = crate::lint::lint_test_guard();
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

    // ---- bd k0hdi：七族掩码 ----
    //
    // 直接构造 `BuiltConfig`：`collect_secrets` 只读 `entry.{kind,data}`，与
    // `Config::build` 产物同形（`built.rs:192` 把 settings Value 原样 to_vec），
    // 上面两条 load_str 用例已覆盖真实装配路径。

    fn secrets_of(protocol: &str, settings: serde_json::Value, inbound: bool) -> Vec<String> {
        let entry =
            BuiltEntry { kind: protocol.to_string(), data: serde_json::to_vec(&settings).unwrap() };
        let built = if inbound {
            BuiltConfig {
                inbounds: vec![BuiltInbound {
                    entry,
                    tag: "t".to_string(),
                    port: None,
                    listen: None,
                    stream_settings_json: None,
                    sniffing_json: None,
                }],
                ..BuiltConfig::default()
            }
        } else {
            BuiltConfig {
                outbounds: vec![BuiltOutbound {
                    entry,
                    tag: "t".to_string(),
                    send_through: None,
                    stream_settings_json: None,
                    proxy_settings_json: None,
                    mux_json: None,
                    target_strategy: None,
                }],
                ..BuiltConfig::default()
            }
        };
        collect_secrets(&built)
    }

    #[test]
    fn masks_anytls_password() {
        let secrets = secrets_of("anytls", serde_json::json!({ "password": "anytls-pw" }), true);
        assert_eq!(secrets, ["anytls-pw"]);
    }

    // ---- B4 遗留③（bd 55yh7 U4）：masque users[].pass 进掩码收集面 ----

    #[test]
    fn masks_masque_user_pass_and_skips_email() {
        // Go MasqueServerConfig 形：users[].{email,pass}；clients 为 Go 别名键。
        let secrets = secrets_of(
            "masque",
            serde_json::json!({
                "users": [
                    { "email": "u1@example.com", "pass": "masque-secret-1" },
                    { "email": "u2@example.com", "pass": "masque-secret-2" }
                ]
            }),
            true,
        );
        // email 是日志面刻意可记的身份字段（B4 口径），不进掩码表。
        assert_eq!(secrets, ["masque-secret-1", "masque-secret-2"]);
        // clients 别名键同语义。
        let secrets = secrets_of(
            "masque",
            serde_json::json!({
                "clients": [{ "email": "u@example.com", "pass": "masque-pw-alias" }]
            }),
            true,
        );
        assert_eq!(secrets, ["masque-pw-alias"]);
    }

    #[test]
    fn masks_tuic_uuid_and_password() {
        let secrets = secrets_of(
            "tuic",
            serde_json::json!({ "servers": [{ "address": "1.2.3.4", "port": 443,
                "uuid": "4e1a1b3c-9d1f-4a63-9c53-f0f60b7b7a11", "password": "tuic-pw" }] }),
            false,
        );
        assert!(secrets.iter().any(|s| s == "tuic-pw"), "{secrets:?}");
        assert!(secrets.iter().any(|s| s == "4e1a1b3c-9d1f-4a63-9c53-f0f60b7b7a11"), "{secrets:?}");
    }

    #[test]
    fn masks_naive_username_password_both_shapes() {
        // 出站扁平 username/password；入站 users[].name/pass。
        let out = secrets_of(
            "naive",
            serde_json::json!({ "server": "1.2.3.4", "port": 443,
                "username": "naive-user", "password": "naive-pw" }),
            false,
        );
        assert_eq!(out, ["naive-pw", "naive-user"]);
        let inbound = secrets_of(
            "naive",
            serde_json::json!({ "users": [{ "name": "naive-in-user", "pass": "naive-in-pw" }] }),
            true,
        );
        assert_eq!(inbound, ["naive-in-pw", "naive-in-user"]);
    }

    #[test]
    fn masks_wireguard_secret_and_psk_but_not_public_keys() {
        let secret = "aa".repeat(32);
        let public = "bb".repeat(32);
        let psk = "cc".repeat(32);
        let secrets = secrets_of(
            "wireguard",
            serde_json::json!({ "secretKey": secret,
                "peers": [{ "publicKey": public, "endpoint": "e:1",
                    "preSharedKey": psk, "allowedIPs": ["0.0.0.0/0"] }] }),
            false,
        );
        assert!(secrets.contains(&psk), "{secrets:?}");
        assert!(secrets.contains(&secret), "{secrets:?}");
        assert!(!secrets.contains(&public), "公钥是公开材料，不必进掩码表：{secrets:?}");
    }

    #[test]
    fn masks_hysteria_auth_and_users() {
        let inbound = secrets_of(
            "hysteria",
            serde_json::json!({ "version": 2, "auth": "hy-top",
                "users": [{ "auth": "hy-user-1" }], "clients": [{ "auth": "hy-user-2" }] }),
            true,
        );
        for value in ["hy-top", "hy-user-1", "hy-user-2"] {
            assert!(inbound.iter().any(|s| s == value), "{value} 未进掩码表: {inbound:?}");
        }
        let outbound = secrets_of(
            "hysteria2",
            serde_json::json!({ "servers": [{ "address": "1.2.3.4", "port": 443,
                "auth": "hy-out-auth", "password": "hy-out-pw" }] }),
            false,
        );
        assert!(outbound.iter().any(|s| s == "hy-out-auth"), "{outbound:?}");
        assert!(outbound.iter().any(|s| s == "hy-out-pw"), "{outbound:?}");
    }

    #[test]
    fn masks_socks_accounts_and_flat_user_pass() {
        let inbound = secrets_of(
            "socks",
            serde_json::json!({ "accounts": [{ "user": "socks-u", "pass": "socks-p" }] }),
            true,
        );
        assert_eq!(inbound, ["socks-p", "socks-u"]);
        let mixed = secrets_of(
            "mixed",
            serde_json::json!({ "users": [{ "user": "mixed-u", "pass": "mixed-p" }] }),
            true,
        );
        assert_eq!(mixed, ["mixed-p", "mixed-u"]);
        let outbound = secrets_of(
            "socks",
            serde_json::json!({ "servers": [{ "address": "127.0.0.1", "port": 1080,
                "users": [{ "user": "socks-out-u", "pass": "socks-out-p" }] }] }),
            false,
        );
        assert_eq!(outbound, ["socks-out-p", "socks-out-u"]);
    }

    #[test]
    fn masks_http_accounts_and_flat_user_pass() {
        let inbound = secrets_of(
            "http",
            serde_json::json!({ "accounts": [{ "user": "http-u", "pass": "http-p" }] }),
            true,
        );
        assert_eq!(inbound, ["http-p", "http-u"]);
        let outbound = secrets_of(
            "http",
            serde_json::json!({ "address": "127.0.0.1", "port": 8080,
                "user": "http-out-u", "pass": "http-out-p" }),
            false,
        );
        assert_eq!(outbound, ["http-out-p", "http-out-u"]);
    }
}

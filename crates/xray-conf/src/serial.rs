//! # 配置序列化（回 JSON / 构建）
//!
//! 对应 Go `infra/conf/serial`（builder.go + loader.go + serial.go）。
//!
//! | Go（infra/conf/serial） | Rust（本模块） | 说明 |
//! |---|---|---|
//! | `MergeConfigFromFiles` (builder.go:24) | [`merge_config_from_files`] | 多配置合并 → JSON dump 字符串（`-dump` 输出） |
//! | `mergeConfigs` (builder.go:36) | [`merge_configs`] | 逐文件加载，首个整体生效，其余 [`Config::override_with`] |
//! | `BuildConfig` (builder.go:61) | [`build_config`] | 合并 + `Config::build()` |
//! | `Config.Override` (infra/conf/xray.go:411) | [`Config::override_with`] | 字段级覆盖 + in/outbound 按 tag 合并 |
//! | `creflect.MarshalToJson` (common/reflect/marshal.go:15) | [`Config::to_json_value`] / [`Config::to_json_string`] | 见下方格式说明 |
//! | `DecodeJSONConfig` 等（loader.go） | `json` / `yaml` / `toml_config` 模块 | 已有实现 |
//!
//! ## JSON 输出格式（对齐 Go `JSONMarshalWithoutEscape`，marshal.go:24-31）
//!
//! - 4 空格缩进（Go `encoder.SetIndent("", "    ")`）
//! - 不转义 HTML 字符（Go `SetEscapeHTML(false)`；serde_json 默认即不转义）
//! - 末尾带 `\n`（Go `Encoder.Encode` 追加换行）
//! - None 字段跳过（Go `ignoreNullValue=true` + 各字段 `skip_serializing_if`）
//!
//! 与 Go 的已知差异：Go `isNullValue`（marshal.go:60-73）额外跳过**空字符串**字段
//! （如空 `tag`），Rust serde 保留空串字段；两侧再解析结果等价。
//!
//! ## proto 方向（to_proto）
//!
//! Go `BuildConfig` 返回 prost `*core.Config`。Rust 按既定架构（见 `built.rs` 模块
//! 文档）以 [`BuiltConfig`]（kind + JSON 字节）作为 `*core.Config` 等价物，不在
//! xray-conf 引入 prost 依赖。真实 proto 字节编码由消费方对 `xray-proto` 类型调用
//! `prost::Message::encode_to_vec` 完成；`BuiltConfig → TypedMessage` 全量转换需要
//! 逐 app 的 JSON→proto 映射，超出本任务范围（见 bd issue Non-goals）。

use std::path::Path;

use serde_json::Value;

use crate::{
    built::BuiltConfig,
    config::Config,
    error::{ConfError, Result},
};

impl Config {
    /// 用另一份配置覆盖当前配置。对应 Go `infra/conf.Config.Override`
    /// （xray.go:410-497）。
    ///
    /// 语义：
    /// - 所有标量块字段（log/routing/dns/.../transport）：`Some` 才覆盖。
    /// - inbound：按 tag 命中则替换，否则**追加到尾部**。
    /// - outbound：按 tag 命中则替换；未命中时若 `source` 文件名（小写）包含 `"tail"`
    ///   则追加到尾部，否则**前插到头部**（xray.go:478-496）。
    ///
    /// `source` 仅用于 outbound 前插/追加判定与日志，对应 Go 的 `fn` 参数。
    pub fn override_with(&mut self, other: Config, source: &str) {
        // 标量块字段：Some 才覆盖（xray.go:414-460）。
        if other.log.is_some() {
            self.log = other.log;
        }
        if other.routing.is_some() {
            self.routing = other.routing;
        }
        if other.dns.is_some() {
            self.dns = other.dns;
        }
        if other.transport.is_some() {
            self.transport = other.transport;
        }
        if other.policy.is_some() {
            self.policy = other.policy;
        }
        if other.api.is_some() {
            self.api = other.api;
        }
        if other.metrics.is_some() {
            self.metrics = other.metrics;
        }
        if other.stats.is_some() {
            self.stats = other.stats;
        }
        if other.reverse.is_some() {
            self.reverse = other.reverse;
        }
        if other.fake_dns.is_some() {
            self.fake_dns = other.fake_dns;
        }
        if other.observatory.is_some() {
            self.observatory = other.observatory;
        }
        if other.burst_observatory.is_some() {
            self.burst_observatory = other.burst_observatory;
        }
        if other.version.is_some() {
            self.version = other.version;
        }
        if other.geodata.is_some() {
            self.geodata = other.geodata;
        }

        // env：key 级合并而非整体替换（xray.go:452-457 EnvConfig.Override）。
        if let Some(oenv) = other.env {
            self.env.get_or_insert_with(std::collections::HashMap::new).extend(oenv);
        }

        // inbound：tag 命中替换，否则追加（xray.go:462-474）。
        if !other.inbound_configs.is_empty() {
            for ib in other.inbound_configs {
                match self.inbound_configs.iter().position(|c| c.tag == ib.tag) {
                    Some(idx) => {
                        tracing::info!(
                            target: "xray_conf",
                            "[{}] updated inbound with tag: {}", source, ib.tag
                        );
                        self.inbound_configs[idx] = ib;
                    },
                    None => {
                        tracing::info!(
                            target: "xray_conf",
                            "[{}] appended inbound with tag: {}", source, ib.tag
                        );
                        self.inbound_configs.push(ib);
                    },
                }
            }
        }

        // outbound：tag 命中替换；未命中时 tail 文件追加，否则收集后整体前插
        // （xray.go:476-496）。
        if !other.outbound_configs.is_empty() {
            let is_tail = source.to_ascii_lowercase().contains("tail");
            let mut prepends = Vec::new();
            for ob in other.outbound_configs {
                match self.outbound_configs.iter().position(|c| c.tag == ob.tag) {
                    Some(idx) => {
                        tracing::info!(
                            target: "xray_conf",
                            "[{}] updated outbound with tag: {}", source, ob.tag
                        );
                        self.outbound_configs[idx] = ob;
                    },
                    None => {
                        if is_tail {
                            tracing::info!(
                                target: "xray_conf",
                                "[{}] appended outbound with tag: {}", source, ob.tag
                            );
                            self.outbound_configs.push(ob);
                        } else {
                            tracing::info!(
                                target: "xray_conf",
                                "[{}] prepend outbound with tag: {}", source, ob.tag
                            );
                            prepends.push(ob);
                        }
                    },
                }
            }
            if !prepends.is_empty() {
                prepends.append(&mut self.outbound_configs);
                self.outbound_configs = prepends;
            }
        }
    }

    /// 序列化为 [`serde_json::Value`]。对应 Go `creflect.MarshalToJson(c, true)`
    /// 的对象形式（marshal.go:15-22）。
    pub fn to_json_value(&self) -> Result<Value> {
        serde_json::to_value(self).map_err(ConfError::from)
    }

    /// 序列化为 Go `-dump` 格式的 JSON 字符串：4 空格缩进 + 末尾换行，
    /// 对应 `MarshalToJson` → `JSONMarshalWithoutEscape`（marshal.go:15-31）。
    pub fn to_json_string(&self) -> Result<String> {
        let mut buf = Vec::new();
        let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
        let mut serializer = serde_json::Serializer::with_formatter(&mut buf, formatter);
        serde::Serialize::serialize(self, &mut serializer)?;
        let mut out = String::from_utf8(buf)
            .map_err(|e| ConfError::Build { what: "config", message: e.to_string() })?;
        out.push('\n');
        Ok(out)
    }
}

/// 加载并合并多个配置文件。对应 Go `serial.mergeConfigs`（builder.go:36-59）：
/// 首个文件整体生效，其余经 [`Config::override_with`] 逐个覆盖。
pub fn merge_configs(paths: &[std::path::PathBuf]) -> Result<Config> {
    let mut merged: Option<Config> = None;
    for path in paths {
        tracing::info!(target: "xray_conf", "Reading config: {}", path.display());
        let cfg = crate::confloader::load_file(Path::new(path)).map_err(|e| {
            ConfError::Read(format!("failed to read config {}: {e}", path.display()))
        })?;
        match merged.take() {
            None => merged = Some(cfg),
            Some(mut base) => {
                base.override_with(cfg, &path.display().to_string());
                merged = Some(base);
            },
        }
    }
    merged.ok_or_else(|| ConfError::Read("no config files to merge".into()))
}

/// 合并多个配置文件并序列化为 JSON dump 字符串（`xray run -dump` 输出）。
/// 对应 Go `serial.MergeConfigFromFiles`（builder.go:24-34）。
pub fn merge_config_from_files(paths: &[std::path::PathBuf]) -> Result<String> {
    merge_configs(paths)?.to_json_string()
}

/// 合并多个配置文件并构建为 [`BuiltConfig`]（Go `*core.Config` 等价物）。
/// 对应 Go `serial.BuildConfig`（builder.go:61-67）。
pub fn build_config(paths: &[std::path::PathBuf]) -> Result<BuiltConfig> {
    merge_configs(paths)?.build()
}

#[cfg(test)]
mod tests {
    use std::{io::Write, path::PathBuf};

    use serde_json::json;

    use super::*;

    fn write_temp(name: &str, content: &str) -> PathBuf {
        let base = std::env::temp_dir().join("xray-conf-serial-tests");
        std::fs::create_dir_all(&base).unwrap();
        let path = base.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    fn cleanup(path: &PathBuf) {
        std::fs::remove_file(path).ok();
    }

    // ----- override_with -----

    #[test]
    fn override_replaces_some_fields_and_keeps_none() {
        let mut base = Config::from_json_str(
            r#"{ "routing": {"domainStrategy": "AsIs"}, "dns": {"servers": ["1.1.1.1"]} }"#,
        )
        .unwrap();
        let other =
            Config::from_json_str(r#"{ "routing": {"domainStrategy": "IPIfNonMatch"} }"#).unwrap();

        base.override_with(other, "second.json");

        assert_eq!(base.routing.as_ref().unwrap()["domainStrategy"], json!("IPIfNonMatch"));
        // dns 为 None → 保留原值。
        assert_eq!(base.dns.as_ref().unwrap()["servers"], json!(["1.1.1.1"]));
    }

    #[test]
    fn override_inbound_replace_by_tag_else_append() {
        let mut base = Config::from_json_str(
            r#"{ "inbounds": [
                { "protocol": "vless", "port": 443, "tag": "a" },
                { "protocol": "vmess", "port": 1000, "tag": "b" }
            ] }"#,
        )
        .unwrap();
        let other = Config::from_json_str(
            r#"{ "inbounds": [
                { "protocol": "vmess", "port": 2000, "tag": "b" },
                { "protocol": "trojan", "port": 8443, "tag": "c" }
            ] }"#,
        )
        .unwrap();

        base.override_with(other, "override.json");

        let tags: Vec<&str> = base.inbound_configs.iter().map(|i| i.tag.as_str()).collect();
        assert_eq!(tags, vec!["a", "b", "c"]);
        // b 被替换为 port 2000。
        assert_eq!(serde_json::to_value(&base.inbound_configs[1].port).unwrap(), json!(2000));
    }

    #[test]
    fn override_outbound_prepends_by_default_appends_for_tail() {
        let mut base = Config::from_json_str(
            r#"{ "outbounds": [{ "protocol": "freedom", "tag": "direct" }] }"#,
        )
        .unwrap();

        // 普通文件：未命中 tag → 前插。
        let other = Config::from_json_str(
            r#"{ "outbounds": [
                { "protocol": "socks", "tag": "proxy" },
                { "protocol": "blackhole", "tag": "direct" }
            ] }"#,
        )
        .unwrap();
        base.override_with(other, "extra.json");
        let tags: Vec<&str> = base.outbound_configs.iter().map(|o| o.tag.as_str()).collect();
        assert_eq!(tags, vec!["proxy", "direct"]);

        // tail 文件：未命中 tag → 追加。
        let tail =
            Config::from_json_str(r#"{ "outbounds": [{ "protocol": "http", "tag": "tail-ob" }] }"#)
                .unwrap();
        base.override_with(tail, "99_zz_tail.json");
        let tags: Vec<&str> = base.outbound_configs.iter().map(|o| o.tag.as_str()).collect();
        assert_eq!(tags, vec!["proxy", "direct", "tail-ob"]);
    }

    #[test]
    fn override_env_merges_by_key() {
        // Go xray.go:452-457：env 是 key 级合并而非整体替换；o.Env == nil 时保留 base。
        let mut base = Config::from_json_str(r#"{ "env": { "A": "1", "B": "2" } }"#).unwrap();
        let other = Config::from_json_str(r#"{ "env": { "B": "3", "C": "4" } }"#).unwrap();

        base.override_with(other, "second.json");

        let env = base.env.as_ref().unwrap();
        assert_eq!(env.get("A").map(String::as_str), Some("1")); // base 独有保留
        assert_eq!(env.get("B").map(String::as_str), Some("3")); // override 赢
        assert_eq!(env.get("C").map(String::as_str), Some("4")); // override 独有并入

        // override 无 env：base 原样保留。
        let mut base = Config::from_json_str(r#"{ "env": { "A": "1" } }"#).unwrap();
        let other = Config::from_json_str("{}").unwrap();
        base.override_with(other, "third.json");
        assert_eq!(base.env.as_ref().unwrap().get("A").map(String::as_str), Some("1"));

        // base 无 env、override 有：采用 override。
        let mut base = Config::from_json_str("{}").unwrap();
        let other = Config::from_json_str(r#"{ "env": { "D": "5" } }"#).unwrap();
        base.override_with(other, "fourth.json");
        assert_eq!(base.env.as_ref().unwrap().get("D").map(String::as_str), Some("5"));
    }

    // ----- to_json_value / to_json_string -----

    #[test]
    fn to_json_string_go_dump_format() {
        let cfg = Config::from_json_str(r#"{ "inbounds": [] }"#).unwrap();
        let s = cfg.to_json_string().unwrap();
        // 4 空格缩进 + 末尾换行（Go JSONMarshalWithoutEscape）。
        assert!(s.starts_with("{\n    \"inbounds\":"), "got: {s:?}");
        assert!(s.ends_with("}\n"), "got: {s:?}");
    }

    #[test]
    fn to_json_value_covers_all_blocks() {
        let cfg = Config::from_json_str(
            r#"{
                "log": { "loglevel": "warning" },
                "routing": { "domainStrategy": "AsIs" },
                "dns": { "servers": ["localhost"] },
                "inbounds": [{
                    "protocol": "vless", "port": 443, "tag": "in",
                    "listen": "0.0.0.0",
                    "settings": { "clients": [] },
                    "streamSettings": { "network": "tcp" },
                    "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
                }],
                "outbounds": [{
                    "protocol": "freedom", "tag": "direct",
                    "settings": { "domainStrategy": "UseIP" },
                    "mux": { "enabled": false, "concurrency": 8 }
                }]
            }"#,
        )
        .unwrap();

        let v = cfg.to_json_value().unwrap();
        // 各 config 块均出现在序列化输出中。
        assert_eq!(v["log"]["loglevel"], json!("warning"));
        assert_eq!(v["routing"]["domainStrategy"], json!("AsIs"));
        assert_eq!(v["dns"]["servers"], json!(["localhost"]));
        assert_eq!(v["inbounds"][0]["port"], json!(443));
        assert_eq!(v["inbounds"][0]["listen"], json!("0.0.0.0"));
        assert_eq!(v["inbounds"][0]["sniffing"]["destOverride"], json!(["http", "tls"]));
        assert_eq!(v["inbounds"][0]["streamSettings"]["network"], json!("tcp"));
        assert_eq!(v["outbounds"][0]["mux"]["concurrency"], json!(8));
        assert_eq!(v["outbounds"][0]["settings"]["domainStrategy"], json!("UseIP"));
        // 端口列表序列化为 Go dump 形式（单端口 → 数字）。
        assert_eq!(v["inbounds"][0]["port"], json!(443));
    }

    // ----- round-trip -----

    #[test]
    fn round_trip_parse_to_json_parse_is_equal() {
        let original = r#"{
            "log": { "loglevel": "warning", "access": "none" },
            "routing": { "domainStrategy": "IPIfNonMatch", "rules": [
                { "type": "field", "ip": ["geoip:private"], "outboundTag": "blocked" }
            ] },
            "dns": { "servers": ["1.1.1.1", { "address": "8.8.8.8", "domains": ["geosite:google"] }] },
            "policy": { "levels": { "0": { "handshake": 4, "up": 100 } }, "system": { "statsInboundUplink": true } },
            "inbounds": [
                { "protocol": "vless", "port": 443, "tag": "in-1", "listen": "0.0.0.0",
                  "settings": { "decryption": "none", "clients": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811" }] },
                  "streamSettings": { "network": "ws", "wsSettings": { "path": "/ray" } },
                  "sniffing": { "enabled": true, "destOverride": ["http", "tls"], "metadataOnly": false } },
                { "protocol": "dokodemo-door", "port": "1000-2000,3000", "tag": "in-2",
                  "settings": { "followRedirect": true } }
            ],
            "outbounds": [
                { "protocol": "freedom", "tag": "direct", "settings": { "domainStrategy": "UseIPv4" },
                  "sendThrough": "0.0.0.0" },
                { "protocol": "blackhole", "tag": "blocked", "settings": { "response": { "type": "http" } },
                  "mux": { "enabled": false, "concurrency": -1, "xudpConcurrency": 8 } }
            ]
        }"#;

        let first = Config::from_json_str(original).unwrap();
        let dumped = first.to_json_string().unwrap();
        let second = Config::from_json_str(&dumped).unwrap();

        // parse → to_json → parse 应得等值配置。
        assert_eq!(
            first.to_json_value().unwrap(),
            second.to_json_value().unwrap(),
            "round-trip mismatch; dump was:\n{dumped}"
        );
        // 再 dump 一次应与第一次字节一致（幂等）。
        assert_eq!(dumped, second.to_json_string().unwrap());
    }

    #[test]
    fn round_trip_empty_config() {
        let first = Config::default();
        let dumped = first.to_json_string().unwrap();
        let second = Config::from_json_str(&dumped).unwrap();
        assert_eq!(first.to_json_value().unwrap(), second.to_json_value().unwrap());
    }

    // ----- merge_configs / merge_config_from_files / build_config -----

    #[test]
    fn merge_configs_merges_by_override() {
        let p1 = write_temp(
            "merge_base.json",
            r#"{ "log": { "loglevel": "info" },
                "inbounds": [{ "protocol": "vless", "port": 443, "tag": "in" }],
                "outbounds": [{ "protocol": "freedom", "tag": "direct" }] }"#,
        );
        let p2 = write_temp(
            "merge_override.json",
            r#"{ "log": { "loglevel": "warning" },
                "outbounds": [{ "protocol": "socks", "tag": "proxy", "settings": { "servers": [] } }] }"#,
        );

        let merged = merge_configs(&[p1.clone(), p2.clone()]).unwrap();
        cleanup(&p1);
        cleanup(&p2);

        // 标量字段被第二个文件覆盖。
        assert_eq!(merged.log.as_ref().unwrap().loglevel.as_deref(), Some("warning"));
        // inbound 保留；outbound 前插 proxy。
        assert_eq!(merged.inbound_count(), 1);
        let tags: Vec<&str> = merged.outbound_configs.iter().map(|o| o.tag.as_str()).collect();
        assert_eq!(tags, vec!["proxy", "direct"]);
    }

    #[test]
    fn merge_config_from_files_dumps_merged_json() {
        let p1 = write_temp(
            "dump_1.json",
            r#"{ "inbounds": [{ "protocol": "vless", "port": 443, "tag": "in" }] }"#,
        );
        let p2 = write_temp(
            "dump_2.json",
            r#"{ "outbounds": [{ "protocol": "freedom", "tag": "direct" }] }"#,
        );

        let dump = merge_config_from_files(&[p1.clone(), p2.clone()]).unwrap();
        cleanup(&p1);
        cleanup(&p2);

        // dump 本身可再解析，且包含两份文件合并后的内容。
        let reparsed = Config::from_json_str(&dump).unwrap();
        assert_eq!(reparsed.inbound_count(), 1);
        assert_eq!(reparsed.outbound_count(), 1);
        assert!(dump.contains("\"inbounds\""));
        assert!(dump.contains("\"outbounds\""));
    }

    #[test]
    fn build_config_builds_merged_config() {
        // build() 现在自举运行 lint 注册表（bd 5x41）；lint.rs 并行测试会注册
        // Boom 等 junk 阶段，故持 TEST_LOCK 并重置注册表，只留内置阶段。
        let _g = crate::lint::tests::TEST_LOCK.lock();
        crate::lint::clear_stages();
        crate::init::register_builtin_stages();
        let p1 = write_temp(
            "build_1.json",
            r#"{ "inbounds": [{ "protocol": "vless", "port": 443, "tag": "in" }] }"#,
        );
        let p2 = write_temp(
            "build_2.json",
            r#"{ "outbounds": [{ "protocol": "freedom", "tag": "direct" }] }"#,
        );

        let built = build_config(&[p1.clone(), p2.clone()]).unwrap();
        cleanup(&p1);
        cleanup(&p2);

        assert_eq!(built.inbound_count(), 1);
        assert_eq!(built.outbound_count(), 1);
        assert_eq!(built.inbounds[0].tag, "in");
        assert_eq!(built.outbounds[0].tag, "direct");
    }

    #[test]
    fn merge_configs_empty_list_errors() {
        assert!(merge_configs(&[]).is_err());
    }
}

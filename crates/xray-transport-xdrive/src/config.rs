//! xdrive 配置：`xdriveSettings` JSON → [`Config`]（14 字段对齐 proto + h3 派生位）。
//!
//! 对应 Go `transport/internet/xdrive/config.proto::Config`（B0 已整文件同步镜像）
//! 与 `infra/conf/transport_method.go:989-1007 XDriveConfig` 的 JSON 键名
//! （lowerCamelCase，Go proto JSON 同名）。`template`/`s3`/`xmux` 三个子对象 B1
//! 只透传原始 JSON——B2（xmux/template）/B3（s3）各自动-parse（proto 已镜像）。

use std::io;

/// xdrive 协议设置（对齐 Go `Config` proto 字段集 + `h3` 派生位）。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 对象存储根（local 后端 = 文件夹；`""` 由 LocalStorage 拒绝）。
    pub remote_folder: String,
    /// 后端名：`"local"`（B1）/ `"template"`（B2）/ `"s3"`（B3）/
    /// `"google-drive"` 或 `"Google Drive"`（B4）。
    pub service: String,
    /// 后端凭据（B2/B3/B4 消费；B1 不读）。
    pub secrets: Vec<String>,
    /// 分段大小上限（字节；0 = 缺省 512 KiB，上限 16 MiB）。
    pub segment_bytes: u32,
    /// 写缓冲定时 flush 周期（毫秒；0 = 缺省 20ms）。
    pub flush_interval_ms: u32,
    /// 读轮询最小周期（毫秒；0 = 缺省 50ms）。
    pub poll_interval_ms: u32,
    /// 读轮询最大周期（毫秒；0 = 缺省 500ms；小于 min 时被抬到 min）。
    pub max_poll_interval_ms: u32,
    /// 会话空闲回收 TTL（秒；0 = 缺省 5min）。
    pub session_ttl_seconds: u32,
    /// 并发上限（上传/取段/删除的并行度；0 = 缺省 8，上限 256）。
    pub concurrency: u32,
    /// 读轮询「活跃窗」（毫秒；0 = 缺省 2s——窗内不退避）。
    pub eager_window_ms: u32,
    /// 分段空洞容忍（毫秒；0 = 缺省 30s——超时判对端丢段）。
    pub hole_timeout_ms: u32,
    /// `template` 后端配置（B2 parse；B1 透传）。
    pub template: Option<serde_json::Value>,
    /// `s3` 后端配置（B3 parse；B1 透传）。
    pub s3: Option<serde_json::Value>,
    /// xmux 配置（B2 接 XMUX 池；B1 透传）。
    pub xmux: Option<serde_json::Value>,
    /// ALPN = `["h3"]` 派生位（Go XDriveConfig.h3，transport_internet.go `:93-120`
    /// 由 conf Build 注入；Rust 无 Build 层，改在 [`Config::from_settings`] 派生）。
    /// B6 再核对指纹 + `["http/1.1"]` 例外组合；B2/B5 的 xmux 缺省消费此位。
    pub h3: bool,
}

impl Config {
    /// 从 [`xray_transport::dialer::StreamSettings`] 解析：协议设置 JSON + ALPN。
    ///
    /// `transport_json` 缺失/非 object → 硬错（Go `streamConfig` 的
    /// ProtocolSettings 类型断言失败同款「invalid protocol settings」）。
    /// 数字字段非法类型（字符串/负值）→ 硬错（Go proto JSON 解码同款）。
    pub fn from_settings(settings: &xray_transport::dialer::StreamSettings) -> io::Result<Config> {
        let mut config = Self::from_config_json(settings.transport_json.as_ref())?;
        config.h3 = is_h3_alpn(settings.security_json.as_ref());
        Ok(config)
    }

    /// 解析 `xdriveSettings` JSON（协议内字段；不含 ALPN 派生）。
    ///
    /// `None` → 缺设置硬错（xdrive 没有「无设置可用」的退化形态——storage 无法
    /// 定位，静默落缺省会让节点指向空目录）。
    pub fn from_config_json(json: Option<&serde_json::Value>) -> io::Result<Config> {
        let Some(v) = json else {
            return Err(invalid_settings("missing \"xdriveSettings\""));
        };
        let Some(obj) = v.as_object() else {
            return Err(invalid_settings("not an object"));
        };
        let str_field = |key: &str| -> io::Result<String> {
            match obj.get(key) {
                None | Some(serde_json::Value::Null) => Ok(String::new()),
                Some(serde_json::Value::String(s)) => Ok(s.clone()),
                Some(other) => {
                    Err(invalid_settings(&format!("{key} must be a string, got {other}")))
                },
            }
        };
        let u32_field = |key: &str| -> io::Result<u32> {
            match obj.get(key) {
                None | Some(serde_json::Value::Null) => Ok(0),
                Some(n) => {
                    let raw = n.as_u64().ok_or_else(|| {
                        invalid_settings(&format!("{key} must be an unsigned integer, got {n}"))
                    })?;
                    u32::try_from(raw)
                        .map_err(|_| invalid_settings(&format!("{key} exceeds u32: {raw}")))
                },
            }
        };
        let secrets = match obj.get("secrets") {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(serde_json::Value::Array(items)) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    let Some(s) = item.as_str() else {
                        return Err(invalid_settings("secrets must be an array of strings"));
                    };
                    out.push(s.to_string());
                }
                out
            },
            Some(other) => {
                return Err(invalid_settings(&format!(
                    "secrets must be an array of strings, got {other}"
                )));
            },
        };
        Ok(Config {
            remote_folder: str_field("remoteFolder")?,
            service: str_field("service")?,
            secrets,
            segment_bytes: u32_field("segmentBytes")?,
            flush_interval_ms: u32_field("flushIntervalMs")?,
            poll_interval_ms: u32_field("pollIntervalMs")?,
            max_poll_interval_ms: u32_field("maxPollIntervalMs")?,
            session_ttl_seconds: u32_field("sessionTtlSeconds")?,
            concurrency: u32_field("concurrency")?,
            eager_window_ms: u32_field("eagerWindowMs")?,
            hole_timeout_ms: u32_field("holeTimeoutMs")?,
            template: obj.get("template").cloned().filter(|v| !v.is_null()),
            s3: obj.get("s3").cloned().filter(|v| !v.is_null()),
            xmux: obj.get("xmux").cloned().filter(|v| !v.is_null()),
            h3: false,
        })
        .and_then(|config| {
            validate_service_shape(&config)?;
            // xmux 双上限互斥（Go `XDriveConfig.Build:1031-1033`）在**配置装载期**拒：
            // 调用连接期同一解析件（单源判据，禁复制）；旧时点差 = 拖到建池才失败
            // （bd yc54c G4）。缺省填充结果在此丢弃——装配点自会再算一次。
            crate::client::xdrive_xmux_config(config.xmux.as_ref(), &config.service, false)?;
            Ok(config)
        })
    }
}

/// 服务形状配置期校验（Go `XDriveConfig.Build` 的 service switch 直译，文案逐字）。
///
/// Go 在 conf 装载期（Build）即拒：未知 `service` / `google-drive` 缺 3 secrets /
/// `template`·`s3` 对象缺失（`s3` 再过 `ValidateS3Config` 全量校验）。Rust 旧时点差：
/// 这些检查拖延到首连接的 storage 构造，坏配置能启动成功。现经
/// [`Config::from_config_json`] 在每次解析即拒（装配期 xray-conf lint 复用同一入口）。
fn validate_service_shape(config: &Config) -> io::Result<()> {
    match config.service.as_str() {
        "local" => Ok(()),
        "google-drive" | "Google Drive" => {
            if config.secrets.len() != 3 {
                return Err(invalid_settings(
                    "Google Drive needs 3 secrets in order of ClientID, ClientSecret, RefreshToken",
                ));
            }
            Ok(())
        },
        "template" => {
            if config.template.is_none() {
                return Err(invalid_settings(r#"service "template" needs a "template" object"#));
            }
            Ok(())
        },
        "s3" => crate::s3::validate_config(config),
        other => Err(invalid_settings(&format!(
            r#"unknown "service": "{other}", use "google-drive", "template", "s3" or "local""#
        ))),
    }
}

/// ALPN = `["h3"]` 判定（Go transport_internet.go `:93-120` 的 h3 触发键）。
fn is_h3_alpn(security_json: Option<&serde_json::Value>) -> bool {
    security_json
        .and_then(|v| v.get("alpn"))
        .and_then(|a| a.as_array())
        .is_some_and(|alpn| alpn.len() == 1 && alpn[0].as_str() == Some("h3"))
}

fn invalid_settings(why: &str) -> io::Error {
    io::Error::new(std::io::ErrorKind::InvalidInput, format!("invalid protocol settings: {why}"))
}

#[cfg(test)]
mod tests {
    use xray_transport::dialer::StreamSettings;

    use super::*;

    fn settings_from(json: &str) -> StreamSettings {
        StreamSettings::from_json(Some(&serde_json::json!({
            "network": "xdrive",
            "xdriveSettings": serde_json::from_str::<serde_json::Value>(json).unwrap(),
        })))
    }

    #[test]
    fn parses_go_lower_camel_keys() {
        let settings = settings_from(
            r#"{"service":"local","remoteFolder":"/tmp/x","secrets":["a","b"],
                "segmentBytes":65536,"flushIntervalMs":5,"pollIntervalMs":10,
                "maxPollIntervalMs":200,"sessionTtlSeconds":1,"concurrency":16,
                "eagerWindowMs":500,"holeTimeoutMs":1000}"#,
        );
        let c = Config::from_settings(&settings).unwrap();
        assert_eq!(c.service, "local");
        assert_eq!(c.remote_folder, "/tmp/x");
        assert_eq!(c.secrets, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(c.segment_bytes, 65536);
        assert_eq!(c.flush_interval_ms, 5);
        assert_eq!(c.poll_interval_ms, 10);
        assert_eq!(c.max_poll_interval_ms, 200);
        assert_eq!(c.session_ttl_seconds, 1);
        assert_eq!(c.concurrency, 16);
        assert_eq!(c.eager_window_ms, 500);
        assert_eq!(c.hole_timeout_ms, 1000);
        assert!(!c.h3);
    }

    #[test]
    fn missing_settings_is_hard_error() {
        let mut settings = settings_from(r#"{"service":"local"}"#);
        settings.transport_json = None;
        let err = Config::from_settings(&settings).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn non_object_and_bad_types_are_hard_errors() {
        let mut settings = settings_from("null");
        settings.transport_json = Some(serde_json::json!("local"));
        assert!(Config::from_settings(&settings).is_err());
        let settings = settings_from(r#"{"service":42}"#);
        assert!(Config::from_settings(&settings).is_err());
        let settings = settings_from(r#"{"service":"local","concurrency":-1}"#);
        assert!(Config::from_settings(&settings).is_err());
    }

    #[test]
    fn h3_alpn_derives_flag() {
        let json = r#"{"service":"local"}"#;
        let mut settings = settings_from(json);
        settings.security_json = Some(serde_json::json!({"alpn": ["h3"]}));
        assert!(Config::from_settings(&settings).unwrap().h3);
        let mut settings = settings_from(json);
        settings.security_json = Some(serde_json::json!({"alpn": ["h2", "h3"]}));
        assert!(!Config::from_settings(&settings).unwrap().h3);
    }

    // ── G4：服务形状配置期拒启（Go XDriveConfig.Build 同款文案）───────────────

    #[test]
    fn unknown_service_rejected_at_config_time() {
        let err = Config::from_config_json(Some(
            &serde_json::json!({"service": "Dropbox", "remoteFolder": "/tmp/x"}),
        ))
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(r#"unknown "service": "Dropbox""#)
                && msg.contains(r#"use "google-drive", "template", "s3" or "local""#),
            "{msg}"
        );
    }

    #[test]
    fn drive_missing_secrets_rejected_at_config_time() {
        let err = Config::from_config_json(Some(&serde_json::json!(
            {"service": "google-drive", "remoteFolder": "f", "secrets": ["a", "b"]}
        )))
        .unwrap_err();
        assert!(
            err.to_string().contains(
                "Google Drive needs 3 secrets in order of ClientID, ClientSecret, RefreshToken"
            ),
            "{}",
            err
        );
        // 别名 "Google Drive"（Go 弃用警告 + fallthrough 同语义）同样 3 secrets 过闸。
        assert!(
            Config::from_config_json(Some(&serde_json::json!(
                {"service": "Google Drive", "remoteFolder": "f", "secrets": ["a", "b", "c"]}
            )))
            .is_ok()
        );
    }

    #[test]
    fn template_missing_object_rejected_at_config_time() {
        let err = Config::from_config_json(Some(&serde_json::json!({"service": "template"})))
            .unwrap_err();
        assert!(
            err.to_string().contains(r#"service "template" needs a "template" object"#),
            "{}",
            err
        );
    }

    #[test]
    fn s3_missing_object_and_bad_fields_rejected_at_config_time() {
        let err =
            Config::from_config_json(Some(&serde_json::json!({"service": "s3"}))).unwrap_err();
        assert!(err.to_string().contains(r#"service "s3" needs an "s3" object"#), "{}", err);
        // 对象在场但必填字段畸形 → Go ValidateS3Config 同款文案（配置期即拒）。
        let err = Config::from_config_json(Some(&serde_json::json!(
            {"service": "s3", "remoteFolder": "streams", "secrets": ["ak", "sk"],
             "s3": {"region": "us-east-1", "bucket": "b"}}
        )))
        .unwrap_err();
        assert!(
            err.to_string().contains(
                "S3 endpoint must be an http(s) URL without credentials, query or fragment"
            ),
            "{}",
            err
        );
    }

    /// Go `XDriveConfig.Build:1031-1033`：双上限同配在**配置装载期**就拒（旧态 Rust
    /// 拖到建池的 `xdrive_xmux_config`；同一件现被配置期调用，单源判据）。
    #[test]
    fn xmux_double_limit_rejected_at_config_time() {
        let err = Config::from_config_json(Some(&serde_json::json!({
            "service": "local",
            "remoteFolder": "/tmp/x",
            "xmux": {
                "maxConnections": {"from": 1, "to": 1},
                "maxConcurrency": {"from": 1, "to": 1},
            },
        })))
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("maxConnections cannot be specified together with maxConcurrency"),
            "{err}"
        );
        // 只配一个上限（Go `To > 0` 单侧）→ 放行。
        assert!(
            Config::from_config_json(Some(&serde_json::json!({
                "service": "local",
                "remoteFolder": "/tmp/x",
                "xmux": {"maxConnections": {"from": 2, "to": 2}},
            })))
            .is_ok()
        );
    }
}

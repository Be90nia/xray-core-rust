//! 初始化注册器：注册 [`Config`] 后处理阶段。
//!
//! 对应 Go `infra/conf/init.go`：在 `infra/conf` 包 `init()` 时执行
//! `RegisterConfigureFilePostProcessingStage("FakeDNS", &FakeDNSPostProcessingStage{})`。
//!
//! Rust 没有跨 crate 的自动 `init()`，故提供 [`register_builtin_stages`]，
//! 由启动路径（`xray-core`）在早期显式调用一次。
//!
//! 当前内置阶段仅 `FakeDNS` 一项，对应 Go `FakeDNSPostProcessingStage`
//! （Go 源 `infra/conf/fakedns.go:73-134`）：
//!
//! 1. 扫描 `dns.servers[]` —— 含 `fakedns` 地址时视为启用 FakeDNS；
//! 2. 按 `dns.queryStrategy` 推断 IPv4/IPv6 开关；
//! 3. 若启用 FakeDNS 且 `cfg.fake_dns` 缺失，则根据 IPv4/6 开关填充默认 IP 池
//!    （IPv4 = `198.18.0.0/15`，IPv6 = `fc00::/18`，LRU 默认 `32768`，仅 IPv4
//!    或 IPv6 时 LRU = `65535`）；
//! 4. 若启用 FakeDNS 但没有任何 inbound 启用 `destOverride: ["fakedns"|"fakedns+others"]`，
//!    通过 `tracing::warn!` 记录警告（Go 等价物是 `errors.LogWarning(...)`）。
//!
//! 注意：Rust 端 `dns` 字段当前为 `serde_json::Value` 占位（参见 `config.rs`），
//! 本阶段以尽力解析的方式扫描；将来 `xray-app-dns` 强类型化后可改写。
use std::sync::Arc;

use crate::config::Config;
use crate::lint::{register_stage, LintError, LintStage};
/// Go 等价物：`func init() { RegisterConfigureFilePostProcessingStage("FakeDNS", ...) }`
/// 在 `infra/conf` 包初始化时自动执行。
pub fn register_builtin_stages() {
    register_stage(Arc::new(FakeDnsStage));
}

/// FakeDNS 后处理阶段。对应 Go `infra/conf.fakeDNSPostProcessingStage`。
///
/// 阶段名 `FakeDNS` 与 Go `RegisterConfigureFilePostProcessingStage("FakeDNS", ...)` 一致。
pub struct FakeDnsStage;

impl LintStage for FakeDnsStage {
    fn name(&self) -> &'static str {
        "FakeDNS"
    }

    fn process(&self, cfg: &mut Config) -> Result<(), LintError> {
        // 1. 扫 dns.servers：是否存在 `fakedns` 地址。
        let fake_dns_in_use = dns_servers_use_fakedns(cfg);

        if !fake_dns_in_use {
            return Ok(());
        }

        // 2. 推断 IPv4/IPv6 开关（默认双开）。
        let (ipv4, ipv6) = match cfg
            .dns
            .as_ref()
            .and_then(|v| v.get("queryStrategy"))
            .and_then(|v| v.as_str())
        {
            Some(s) if s.eq_ignore_ascii_case("useip4")
                || s.eq_ignore_ascii_case("useipv4")
                || s.eq_ignore_ascii_case("use_ip4")
                || s.eq_ignore_ascii_case("use_ipv4")
                || s.eq_ignore_ascii_case("use_ip_v4")
                || s.eq_ignore_ascii_case("use-ip4")
                || s.eq_ignore_ascii_case("use-ipv4")
                || s.eq_ignore_ascii_case("use-ip-v4") =>
            {
                (true, false)
            }
            Some(s) if s.eq_ignore_ascii_case("useip6")
                || s.eq_ignore_ascii_case("useipv6")
                || s.eq_ignore_ascii_case("use_ip6")
                || s.eq_ignore_ascii_case("use_ipv6")
                || s.eq_ignore_ascii_case("use_ip_v6")
                || s.eq_ignore_ascii_case("use-ip6")
                || s.eq_ignore_ascii_case("use-ipv6")
                || s.eq_ignore_ascii_case("use-ip-v6") =>
            {
                (false, true)
            }
            _ => (true, true),
        };

        // 3. FakeDNS 已配置 → 不覆盖；未配置 → 按 IPv4/6 开关填默认池。
        if cfg.fake_dns.is_none() {
            use crate::app_config::FakeDnsConfig;
            // Rust 占位 fake_dns 当前仅 ip_pool + pool_size（单池），
            // 故 IPv4+IPv6 双开时优先记 IPv4 池；与 Go 多池语义略有差异。
            // 注：Go FakeDNSConfig 同时有 pool[] 和 pools[] 两字段；
            // Rust 当前切片 1 的强类型仅 ip_pool（单 CIDR）+ pool_size，
            // 多池语义待后续 batch 扩展 FakeDnsConfig 时再对齐。
            let ip_pool = if ipv4 {
                "198.18.0.0/15"
            } else {
                // IPv6 default（对应 Go `dns.FakeIPv6Pool`）。
                "fc00::/18"
            };
            let pool_size = if ipv4 && ipv6 { 32768 } else { 65535 };
            cfg.fake_dns = Some(FakeDnsConfig {
                ip_pool: Some(ip_pool.into()),
                pool_size: Some(pool_size),
            });
        }

        // 4. 检查是否有 inbound 启用 `destOverride: ["fakedns"|"fakedns+others"]`。
        let has_dest_override = cfg.inbound_configs.iter().any(|ib| {
            ib.sniffing.as_ref().is_some_and(|sn| {
                sn.enabled
                    && sn.dest_override.0.iter().any(|d| {
                        d.eq_ignore_ascii_case("fakedns") || d.eq_ignore_ascii_case("fakedns+others")
                    })
            })
        });

        if !has_dest_override {
            tracing::warn!(
                target: "xray_conf",
                "Defined FakeDNS but haven't enabled FakeDNS destOverride at any inbound."
            );
        }

        Ok(())
    }
}

/// 扫描 `cfg.dns.servers[]`：任一地址为 `"fakedns"`（domain family）即视为启用。
fn dns_servers_use_fakedns(cfg: &Config) -> bool {
    let Some(dns) = cfg.dns.as_ref() else {
        return false;
    };
    let Some(servers) = dns.get("servers").and_then(|v| v.as_array()) else {
        return false;
    };
    for server in servers {
        // Go dns 配置形态多样：纯字符串（"fakedns"）/对象（{address: "fakedns", port: ...}）。
        let addr = server
            .as_str()
            .map(str::to_owned)
            .or_else(|| {
                server
                    .get("address")
                    .and_then(|a| a.as_str())
                    .map(str::to_owned)
            });
        if let Some(a) = addr {
            // Go FakeDNSPostProcessingStage 判定：address.Family() == Domain
            // 且 domain == "fakedns"（大小写不敏感）。
            if a.eq_ignore_ascii_case("fakedns") {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lint::clear_stages;
    use crate::lint::tests::TEST_LOCK;
    use crate::lint::{post_process, registered_stages};
    use serde_json::json;

    #[test]
    fn register_builtin_stages_records_fakedns() {
        let _g = TEST_LOCK.lock();
        clear_stages();
        register_builtin_stages();
        let names = registered_stages();
        assert!(
            names.contains(&"FakeDNS"),
            "FakeDNS stage should be registered, got {names:?}"
        );
    }

    #[test]
    fn register_is_idempotent() {
        let _g = TEST_LOCK.lock();
        clear_stages();
        register_builtin_stages();
        register_builtin_stages(); // 第二次同名覆盖为同一实例
        let names = registered_stages();
        assert_eq!(names.iter().filter(|n| **n == "FakeDNS").count(), 1);
    }

    #[test]
    fn post_process_no_fakedns_is_noop() {
        let _g = TEST_LOCK.lock();
        clear_stages();
        register_builtin_stages();
        let mut cfg = Config::default();
        post_process(&mut cfg).unwrap();
        assert!(cfg.fake_dns.is_none());
    }

    #[test]
    fn post_process_fills_default_pool_when_fakedns_enabled() {
        let _g = TEST_LOCK.lock();
        clear_stages();
        register_builtin_stages();
        let mut cfg = Config {
            dns: Some(json!({
                "servers": ["fakedns"]
            })),
            ..Default::default()
        };
        post_process(&mut cfg).unwrap();
        let fd = cfg.fake_dns.expect("fake_dns should be auto-filled");
        assert_eq!(fd.ip_pool.as_deref(), Some("198.18.0.0/15"));
        assert_eq!(fd.pool_size, Some(32768)); // 双开 = 32768
    }

    #[test]
    fn post_process_ipv4_only_uses_65535() {
        let _g = TEST_LOCK.lock();
        clear_stages();
        register_builtin_stages();
        let mut cfg = Config {
            dns: Some(json!({
                "servers": ["fakedns"],
                "queryStrategy": "UseIPv4"
            })),
            ..Default::default()
        };
        post_process(&mut cfg).unwrap();
        let fd = cfg.fake_dns.unwrap();
        assert_eq!(fd.ip_pool.as_deref(), Some("198.18.0.0/15"));
        assert_eq!(fd.pool_size, Some(65535)); // 单开 = 65535
    }

    #[test]
    fn post_process_ipv6_only_uses_fc00() {
        let _g = TEST_LOCK.lock();
        clear_stages();
        register_builtin_stages();
        let mut cfg = Config {
            dns: Some(json!({
                "servers": ["fakedns"],
                "queryStrategy": "UseIPv6"
            })),
            ..Default::default()
        };
        post_process(&mut cfg).unwrap();
        let fd = cfg.fake_dns.unwrap();
        assert_eq!(fd.ip_pool.as_deref(), Some("fc00::/18"));
        assert_eq!(fd.pool_size, Some(65535));
    }

    #[test]
    fn post_process_preserves_existing_fakedns() {
        let _g = TEST_LOCK.lock();
        clear_stages();
        register_builtin_stages();
        let mut cfg = Config {
            dns: Some(json!({
                "servers": ["fakedns"]
            })),
            fake_dns: Some(crate::app_config::FakeDnsConfig {
                ip_pool: Some("198.18.0.0/16".into()),
                pool_size: Some(12345),
            }),
            ..Default::default()
        };
        post_process(&mut cfg).unwrap();
        let fd = cfg.fake_dns.unwrap();
        assert_eq!(fd.ip_pool.as_deref(), Some("198.18.0.0/16"));
        assert_eq!(fd.pool_size, Some(12345));
    }

    #[test]
    fn post_process_recognizes_object_form_fakedns_address() {
        let _g = TEST_LOCK.lock();
        clear_stages();
        register_builtin_stages();
        let mut cfg = Config {
            dns: Some(json!({
                "servers": [{"address": "fakedns", "port": 53}]
            })),
            ..Default::default()
        };
        post_process(&mut cfg).unwrap();
        assert!(cfg.fake_dns.is_some(), "fakedns object address should trigger");
    }

    #[test]
    fn post_process_case_insensitive_fakedns() {
        let _g = TEST_LOCK.lock();
        clear_stages();
        register_builtin_stages();
        let mut cfg = Config {
            dns: Some(json!({
                "servers": ["FakeDNS"]
            })),
            ..Default::default()
        };
        post_process(&mut cfg).unwrap();
        assert!(cfg.fake_dns.is_some());
    }

    #[test]
    fn dns_servers_check_accepts_string_and_object_forms() {
        // 内部 helper：字符串形式。
        assert!(dns_servers_use_fakedns(&Config {
            dns: Some(json!({"servers": ["fakedns"]})),
            ..Default::default()
        }));
        // 对象形式。
        assert!(dns_servers_use_fakedns(&Config {
            dns: Some(json!({"servers": [{"address": "fakedns"}]})),
            ..Default::default()
        }));
        // 非 fakedns 地址。
        assert!(!dns_servers_use_fakedns(&Config {
            dns: Some(json!({"servers": ["1.1.1.1"]})),
            ..Default::default()
        }));
        // dns 为空。
        assert!(!dns_servers_use_fakedns(&Config::default()));
    }

    #[test]
    fn post_process_warns_when_no_dest_override_but_keeps_running() {
        let _g = TEST_LOCK.lock();
        clear_stages();
        register_builtin_stages();
        // 即使没有 destOverride，post_process 仍应返回 Ok（仅警告）。
        let mut cfg = Config {
            dns: Some(json!({
                "servers": ["fakedns"]
            })),
            ..Default::default()
        };
        post_process(&mut cfg).unwrap();
        // fake_dns 仍被填充。
        assert!(cfg.fake_dns.is_some());
    }

    #[test]
    fn post_process_succeeds_when_dest_override_present() {
        let _g = TEST_LOCK.lock();
        clear_stages();
        register_builtin_stages();
        // 提供 destOverride: ["fakedns"] 不再触发警告分支。
        let mut cfg = Config {
            dns: Some(json!({"servers": ["fakedns"]})),
            inbound_configs: vec![crate::config::InboundDetourConfig {
                protocol: "vless".into(),
                tag: "in".into(),
                sniffing: Some(crate::config::SniffingConfig {
                    enabled: true,
                    dest_override: crate::common::StringList(vec!["fakedns".into()]),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        post_process(&mut cfg).unwrap();
        assert!(cfg.fake_dns.is_some());
    }
}
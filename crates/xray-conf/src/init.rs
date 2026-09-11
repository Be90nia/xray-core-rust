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
    register_stage(Arc::new(ValidationStage));
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
        // Go fakedns.go:94-118：双开 = pools[198.18.0.0/15 + fc00::/18] 各
        // 32768（两池）；单开 = 单池 65535。
        if cfg.fake_dns.is_none() {
            use crate::app_config::{FakeDnsConfig, FakeDnsPoolElement};
            let v4 = || FakeDnsPoolElement {
                ip_pool: Some("198.18.0.0/15".into()),
                pool_size: Some(32768),
            };
            let v6 = || FakeDnsPoolElement {
                ip_pool: Some("fc00::/18".into()),
                pool_size: Some(32768),
            };
            let single = |pool: &str| FakeDnsConfig {
                ip_pool: Some(pool.into()),
                pool_size: Some(65535),
                pools: None,
            };
            cfg.fake_dns = Some(match (ipv4, ipv6) {
                (true, true) => FakeDnsConfig {
                    ip_pool: None,
                    pool_size: None,
                    pools: Some(vec![v4(), v6()]),
                },
                (false, true) => single("fc00::/18"),
                (true, false) => single("198.18.0.0/15"),
                (false, false) => FakeDnsConfig::default(),
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

/// Build 期校验：捕获三处 Go 硬错 Rust 静默的配置形态（2cq2）。
///
/// 1. `inbounds[].sniffing.destOverride[]` 含未知协议——Go `SniffingConfig.Build`
///    对每个 protocol 做 `switch`，未知值 `errors.New("unknown protocol: ...")`
///    启动期硬拒。Rust 已在 wiring.rs 归一化已知别名（https/ssl→tls 等，va51①），
///    未知值仍由此处硬拒（wiring 归一化对未知值透传保持零行为差）。
/// 2. `outbounds[].mux.xudpProxyUDP443` 非法值（不在 `{reject, allow, skip}`）—
///    Go `MuxConfig.Build` 直接返回错误；Rust `Udp443Policy::from_mux` 返回 None
///    并被 `tracing::warn` 忽略（outbound.rs:516-518），降级为无策略。
/// 3. `burstObservatory` 启用但 `pingConfig` 缺失——Go `BurstObservatoryConfig.Build`
///    必拒；Rust `burst_observatory_factory` 把 None 透传给 feature，启动后跑无
///    配置的观测循环。
///
/// 阶段名 `Validation` 与 Go `RegisterConfigureFilePostProcessingStage` 命名风格一致。
pub struct ValidationStage;

impl LintStage for ValidationStage {
    fn name(&self) -> &'static str {
        "Validation"
    }

    fn process(&self, cfg: &mut Config) -> Result<(), LintError> {
        // 1. destOverride 未知协议（启用 sniffing 才校验）。Go 硬拒 → 这里也硬拒。
        for ib in &cfg.inbound_configs {
            let Some(sn) = ib.sniffing.as_ref() else { continue };
            if !sn.enabled {
                continue;
            }
            for d in &sn.dest_override.0 {
                if !is_known_dest_override(d) {
                    return Err(LintError::Invalid(format!(
                        "inbound '{}' sniffing.destOverride contains unknown protocol '{}' \
                         (Go infra/conf/xray.go:65-79 switch rejects at build time)",
                        ib.tag, d
                    )));
                }
            }
        }

        // 2. xudpProxyUDP443 非法值。Go MuxConfig.Build 硬拒 → 这里也硬拒。
        for ob in &cfg.outbound_configs {
            let Some(mux) = ob.mux.as_ref() else { continue };
            if mux.xudp_proxy_udp_443.is_empty() {
                continue; // 空串规范化为 reject（与 Go MuxConfig.Build 一致）
            }
            if !matches!(mux.xudp_proxy_udp_443.as_str(), "reject" | "allow" | "skip") {
                return Err(LintError::Invalid(format!(
                    "outbound '{}' mux.xudpProxyUDP443='{}' is invalid \
                     (Go MuxConfig.Build rejects; allowed: reject|allow|skip)",
                    ob.tag, mux.xudp_proxy_udp_443
                )));
            }
        }

        // 3. burstObservatory 启用但 pingConfig 缺失。Go 必拒 → 这里也必拒。
        if let Some(b) = cfg.burst_observatory.as_ref() {
            if b.ping_config.is_none() {
                return Err(LintError::Invalid(
                    "burstObservatory enabled but pingConfig is missing \
                     (Go BurstObservatoryConfig.Build rejects at build time)"
                        .to_string(),
                ));
            }
        }

        Ok(())
    }
}

/// destOverride 已知协议集合（与 Go `infra/conf/xray.go:65-79` switch 对齐）。
///
/// 注意：`fakedns+others` 与 `fakedns` 都映射到 fakedns，是同一个嗅探协议的
/// 两种触发写法，故两个都算合法。`https` / `ssl` 映射到 `tls`。
fn is_known_dest_override(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "http" | "tls" | "https" | "ssl" | "quic" | "fakedns" | "fakedns+others"
    )
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
        // Go fakedns.go:97-107：IPv4+IPv6 双开 = pools 两池各 32768。
        let pools = fd.pools.expect("dual-stack default fills pools[]");
        assert_eq!(pools.len(), 2);
        assert_eq!(pools[0].ip_pool.as_deref(), Some("198.18.0.0/15"));
        assert_eq!(pools[0].pool_size, Some(32768));
        assert_eq!(pools[1].ip_pool.as_deref(), Some("fc00::/18"));
        assert_eq!(pools[1].pool_size, Some(32768));
        assert!(fd.ip_pool.is_none(), "dual-stack uses pools[], not single pool");
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
                pools: None,
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

    // ========== ValidationStage tests（2cq2）==========

    #[test]
    fn validation_rejects_unknown_dest_override() {
        let _g = TEST_LOCK.lock();
        clear_stages();
        register_builtin_stages();
        let mut cfg = Config {
            inbound_configs: vec![crate::config::InboundDetourConfig {
                protocol: "vless".into(),
                tag: "in".into(),
                sniffing: Some(crate::config::SniffingConfig {
                    enabled: true,
                    dest_override: crate::common::StringList(vec![
                        "http".into(),
                        "bogus".into(), // 未知 → Go 硬拒
                    ]),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        let err = post_process(&mut cfg).expect_err("unknown destOverride must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("bogus"), "expected error mentioning 'bogus', got: {msg}");
        assert!(msg.contains("destOverride"), "expected error mentioning destOverride, got: {msg}");
    }

    #[test]
    fn validation_accepts_all_known_dest_overrides() {
        // http/tls/https/ssl/quic/fakedns/fakedns+others 都应通过。
        for known in ["http", "tls", "https", "ssl", "quic", "fakedns", "fakedns+others"] {
            assert!(
                is_known_dest_override(known),
                "destOverride protocol {known:?} must be accepted"
            );
        }
        assert!(!is_known_dest_override("bogus"));
        // 大小写不敏感：Go switch 用 strings.ToLower
        assert!(is_known_dest_override("HTTP"));
    }
    #[test]
    fn validation_rejects_bad_xudp_proxy_udp443() {
        let _g = TEST_LOCK.lock();
        clear_stages();
        register_builtin_stages();
        let mut cfg = Config {
            outbound_configs: vec![crate::config::OutboundDetourConfig {
                protocol: "vless".into(),
                tag: "ob".into(),
                mux: Some(crate::config::MuxConfig {
                    enabled: true,
                    xudp_proxy_udp_443: "bogus".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        let err = post_process(&mut cfg).expect_err("invalid xudpProxyUDP443 must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("xudpProxyUDP443"), "got: {msg}");
        assert!(msg.contains("bogus"), "got: {msg}");
    }


    #[test]
    fn validation_silent_on_valid_xudp_proxy_udp443() {
        let _g = TEST_LOCK.lock();
        clear_stages();
        register_builtin_stages();
        let mut cfg = Config {
            outbound_configs: vec![crate::config::OutboundDetourConfig {
                protocol: "vless".into(),
                tag: "ob".into(),
                mux: Some(crate::config::MuxConfig {
                    enabled: true,
                    xudp_proxy_udp_443: "skip".into(),
                    ..Default::default()
                }),
                ..Default::default()
             }],
            ..Default::default()
         };
         post_process(&mut cfg).unwrap();
     }

    #[test]
    fn validation_rejects_burst_missing_ping_config() {
        let _g = TEST_LOCK.lock();
        clear_stages();
        register_builtin_stages();
        let mut cfg = Config {
            burst_observatory: Some(crate::app_config::BurstObservatoryConfig {
                subject_selector: Some(vec!["p1".into()]),
                subject_outbound: None,
                ping_config: None, // 缺失 → Go 硬拒
            }),
            ..Default::default()
        };
        let err = post_process(&mut cfg).expect_err("burstObservatory w/o pingConfig must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("pingConfig"), "got: {msg}");
    }
}
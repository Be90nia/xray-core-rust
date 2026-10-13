#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! # xray-geodata
//!
//! GeoIP and GeoSite protobuf types, data loading, and matching
//! for Xray-core routing.
//!
//! This crate provides:
//! - Protobuf-generated types via prost (`xray.geodata` package)
//! - Convenience methods for constructing and querying GeoIP/GeoSite data
//! - Domain and IP matchers for routing decisions
//!
//! ## Type hierarchy
//!
//! ```text
//! GeoIPList  ──→ GeoIP[]  ──→ CIDR[]
//! GeoSiteList ──→ GeoSite[] ──→ Domain[]
//!                              └→ Domain.Attribute[]
//! ```

/// Protobuf-generated types from `proto/geodat.proto`.
///
/// Re-exports the `xray.geodata` package so callers can use
/// `xray_geodata::pb::Domain`, `xray_geodata::pb::GeoIp`, etc.
pub mod pb {
    pub mod xray {
        pub mod geodata {
            include!(concat!(env!("OUT_DIR"), "/xray.geodata.rs"));
        }
    }

    pub use xray::geodata::*;
}
pub mod geoip;
pub mod geosite;
pub mod loader;
pub mod matcher;
pub mod rule_parser;
pub mod weak_cache;
// Re-export the most commonly used types at crate root for
// convenience.
pub use pb::{
    Cidr, CidrRule, Domain, DomainRule, GeoIp, GeoIpList, GeoIpRule, GeoSite, GeoSiteList,
    GeoSiteRule, IpRule,
};

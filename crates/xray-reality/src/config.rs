//! REALITY 配置层（纯数据结构 + proto 转换）。
//!
//! 翻译自 Go `transport/internet/reality/config.go` 的 `GetREALITYConfig` 与
//! `reality.Config` struct 字段映射。
//!
//! # 范围
//! 本模块只翻译**配置数据结构 + proto 转换**，不含实际 TLS 握手。
//! 实际握手走 uTLS 等价品（Rust 端待生态成熟或自研后再接，
//! 见 [`crate::client`] / [`crate::server`] 占位）。

use std::collections::HashMap;
use std::time::Duration;

use crate::error::RealityError;

/// ShortId 固定 8 字节（对应 Go `*[8]byte`）。
pub const SHORT_ID_LEN: usize = 8;

/// X25519 私钥/公钥固定 32 字节。
pub const X25519_KEY_LEN: usize = 32;

/// ML-DSA-65 种子长度（Go `mldsa65.NewKeyFromSeed(*[32]byte)`）。
pub const MLDSA65_SEED_LEN: usize = 32;

/// REALITY ShortId（固定 8 字节）。
///
/// 对应 Go 端 `*[8]byte`，Rust 端用 newtype 包装以便类型安全区分 `Vec<u8>`。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ShortId(pub [u8; SHORT_ID_LEN]);

impl ShortId {
    /// 从字节切片构造，长度必须为 [`SHORT_ID_LEN`]。
    pub fn from_slice(b: &[u8]) -> Result<Self, RealityError> {
        if b.len() != SHORT_ID_LEN {
            return Err(RealityError::InvalidShortIdLen { actual: b.len() });
        }
        let mut arr = [0u8; SHORT_ID_LEN];
        arr.copy_from_slice(b);
        Ok(Self(arr))
    }
}

impl AsRef<[u8; SHORT_ID_LEN]> for ShortId {
    fn as_ref(&self) -> &[u8; SHORT_ID_LEN] {
        &self.0
    }
}

/// fallback 限速配置。
///
/// 对应 Go `reality.LimitFallback`，与 proto `LimitFallback` 同构。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LimitFallback {
    /// 启用限速前的字节数。
    pub after_bytes: u64,
    /// 限速后的稳态速率（字节/秒）。
    pub bytes_per_sec: u64,
    /// 限速后的突发速率（字节/秒）。
    pub burst_bytes_per_sec: u64,
}

impl LimitFallback {
    /// 从 prost 生成类型转换。
    pub fn from_proto(p: &xray_proto::transport::internet::reality::LimitFallback) -> Self {
        Self {
            after_bytes: p.after_bytes,
            bytes_per_sec: p.bytes_per_sec,
            burst_bytes_per_sec: p.burst_bytes_per_sec,
        }
    }
}

/// REALITY 强类型配置。
///
/// 对应 Go `*reality.Config`（由 `Config.GetREALITYConfig()` 从 proto `Config` 构造）。
/// 字段命名与 Go 端保持一致以方便对照；带「服务端字段」/「客户端字段」注释标注用途。
#[derive(Clone, Debug)]
pub struct RealityConfig {
    pub show: bool,
    pub r#type: String,
    pub dest: String,
    pub xver: u8,

    /// 服务端字段：server_names 白名单（`HashMap` 用 O(1) 查询，对应 Go `map[string]bool`）。
    pub server_names: HashMap<String, bool>,
    /// 服务端字段：private_key（X25519，32 字节）。
    pub private_key: Vec<u8>,
    /// 服务端字段：short_ids 白名单（固定 8 字节的 [`ShortId`] 集）。
    pub short_ids: HashMap<ShortId, bool>,
    pub min_client_ver: Vec<u8>,
    pub max_client_ver: Vec<u8>,
    pub max_time_diff: Duration,

    /// 服务端字段：mldsa65 后量子签名的 seed（可选；32 字节）。
    pub mldsa65_seed: Option<Vec<u8>>,
    /// 服务端字段：由 seed 派生的 mldsa65 key（Go 端在 GetREALITYConfig 中派生，
    /// Rust 端暂不引依赖，留 `None` 等接入 `circl/sign/mldsa65` 后补）。
    pub mldsa65_key: Option<Vec<u8>>,
    pub limit_fallback_upload: Option<LimitFallback>,
    pub limit_fallback_download: Option<LimitFallback>,

    /// 客户端字段：uTLS 指纹名（`chrome`/`firefox`/...，
    /// 由 [`xray_tls::fingerprint::get_fingerprint`] 解析）。
    pub fingerprint: String,
    /// 客户端字段：目标 SNI（覆盖 destination）。
    pub server_name: String,
    /// 客户端字段：服务端公钥（X25519，32 字节）。
    pub public_key: Vec<u8>,
    /// 客户端字段：选择的 short_id（嵌入 ClientHello.SessionId[8..]）。
    pub short_id: Vec<u8>,
    /// 客户端字段：可选的 mldsa65 公钥（用于额外证书验证）。
    pub mldsa65_verify: Vec<u8>,
    /// 客户端字段：spider 模式 fallback URL path 前缀。
    pub spider_x: String,
    /// 客户端字段：spider 模式行为参数（10 元组）。
    ///
    /// 索引含义（与 Go 端 `SpiderY` 字段一致）：
    /// - `[0..1]`：cookie padding 长度区间
    /// - `[2..3]`：并发请求数区间
    /// - `[4..5]`：每轮迭代次数区间
    /// - `[6..7]`：迭代间隔毫秒数区间
    /// - `[8..9]`：总返回延迟毫秒数区间
    pub spider_y: Vec<i64>,

    pub master_key_log: String,

    /// 总是 `None`（Go 端硬编码 `NextProtos: nil`）。
    pub next_protos: Option<Vec<String>>,
    /// 总是 `true`（Go 端硬编码 `SessionTicketsDisabled: true`）。
    pub session_tickets_disabled: bool,
}

impl Default for RealityConfig {
    fn default() -> Self {
        Self {
            show: false,
            r#type: String::new(),
            dest: String::new(),
            xver: 0,
            server_names: HashMap::new(),
            private_key: Vec::new(),
            short_ids: HashMap::new(),
            min_client_ver: Vec::new(),
            max_client_ver: Vec::new(),
            max_time_diff: Duration::ZERO,
            mldsa65_seed: None,
            mldsa65_key: None,
            limit_fallback_upload: None,
            limit_fallback_download: None,
            fingerprint: String::new(),
            server_name: String::new(),
            public_key: Vec::new(),
            short_id: Vec::new(),
            mldsa65_verify: Vec::new(),
            spider_x: String::new(),
            spider_y: Vec::new(),
            master_key_log: String::new(),
            next_protos: None,
            session_tickets_disabled: true,
        }
    }
}

impl RealityConfig {
    /// 从 prost 生成的 proto `Config` 构造强类型 [`RealityConfig`]。
    ///
    /// 对应 Go `(*Config).GetREALITYConfig()`（含 server_names/short_ids map 构造）。
    ///
    /// # 错误
    /// - [`RealityError::InvalidShortIdLen`]：任一 short_id 长度 ≠ 8。
    pub fn from_proto(
        p: &xray_proto::transport::internet::reality::Config,
    ) -> Result<Self, RealityError> {
        let mut cfg = Self::default();
        cfg.show = p.show;
        cfg.r#type = p.r#type.clone();
        cfg.dest = p.dest.clone();
        cfg.xver = p.xver as u8;

        cfg.private_key = p.private_key.clone();
        cfg.min_client_ver = p.min_client_ver.clone();
        cfg.max_client_ver = p.max_client_ver.clone();
        // Go 端: time.Duration(c.MaxTimeDiff) * time.Millisecond
        cfg.max_time_diff = Duration::from_millis(p.max_time_diff);

        // server_names: repeated string → HashMap<String, bool>
        for name in &p.server_names {
            cfg.server_names.insert(name.clone(), true);
        }
        // short_ids: repeated bytes → HashMap<ShortId, bool>，长度校验
        for sid in &p.short_ids {
            let s = ShortId::from_slice(sid)?;
            cfg.short_ids.insert(s, true);
        }

        if !p.mldsa65_seed.is_empty() {
            // Go: (*[32]byte)(c.Mldsa65Seed) —— 长度 != 32 直接 panic，
            // Rust 端在配置期报错（等价的失败时机，更友好的失败方式）。
            if p.mldsa65_seed.len() != MLDSA65_SEED_LEN {
                return Err(RealityError::InvalidMldsa65SeedLen {
                    actual: p.mldsa65_seed.len(),
                });
            }
            cfg.mldsa65_seed = Some(p.mldsa65_seed.clone());
            // Go: _, key := mldsa65.NewKeyFromSeed(...) → config.Mldsa65Key。
            // 签名路径 stub（crate::mitm::generate_reality_ed25519_cert_mldsa65）：
            // rustls 证书选定前拿不到 ServerHello 字节。非 PQC 客户端不受影响
            // （Go 端 mldsa65 变体证书同样携带标准 HMAC 尾部，向后兼容）。
            tracing::warn!(
                "REALITY: mldsa65_seed configured but ML-DSA-65 cert signing is \
                 not yet implemented; serving standard REALITY cert"
            );
        }
        if let Some(lf) = &p.limit_fallback_upload {
            cfg.limit_fallback_upload = Some(LimitFallback::from_proto(lf));
        }
        if let Some(lf) = &p.limit_fallback_download {
            cfg.limit_fallback_download = Some(LimitFallback::from_proto(lf));
        }

        cfg.fingerprint = p.fingerprint.clone();
        cfg.server_name = p.server_name.clone();
        cfg.public_key = p.public_key.clone();
        cfg.short_id = p.short_id.clone();
        cfg.mldsa65_verify = p.mldsa65_verify.clone();
        cfg.spider_x = p.spider_x.clone();
        cfg.spider_y = p.spider_y.clone();
        cfg.master_key_log = p.master_key_log.clone();

        Ok(cfg)
    }

    /// 校验客户端必备字段（public_key 长度、fingerprint 非空）。
    ///
    /// 用于 [`crate::client::u_client`] 在握手前预检，避免半完成握手再失败。
    pub fn validate_client(&self) -> Result<(), RealityError> {
        if self.public_key.len() != X25519_KEY_LEN {
            return Err(RealityError::InvalidPublicKeyLen {
                actual: self.public_key.len(),
            });
        }
        if self.fingerprint.is_empty() {
            return Err(RealityError::FingerprintNotFound);
        }
        Ok(())
    }

    /// 校验服务端必备字段（private_key 长度）。
    pub fn validate_server(&self) -> Result<(), RealityError> {
        if self.private_key.len() != X25519_KEY_LEN {
            return Err(RealityError::InvalidPrivateKeyLen {
                actual: self.private_key.len(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_proto::transport::internet::reality::{Config as ProtoConfig, LimitFallback as ProtoLimitFallback};

    fn proto_fixture() -> ProtoConfig {
        ProtoConfig {
            show: true,
            dest: "example.com:443".into(),
            r#type: "tcp".into(),
            xver: 1,
            server_names: vec!["example.com".into()],
            private_key: vec![0u8; 32],
            min_client_ver: Vec::new(),
            max_client_ver: Vec::new(),
            max_time_diff: 1000,
            short_ids: vec![vec![0u8; 8], vec![0xff; 8]],
            mldsa65_seed: Vec::new(),
            limit_fallback_upload: Some(ProtoLimitFallback {
                after_bytes: 100,
                bytes_per_sec: 50,
                burst_bytes_per_sec: 75,
            }),
            limit_fallback_download: None,
            fingerprint: "chrome".into(),
            server_name: "www.example.com".into(),
            public_key: vec![1u8; 32],
            short_id: vec![2u8; 8],
            mldsa65_verify: Vec::new(),
            spider_x: "/spider".into(),
            spider_y: vec![100, 200, 1, 2, 3, 4, 5, 6, 7, 8],
            master_key_log: String::new(),
        }
    }

    #[test]
    fn from_proto_basic_fields() {
        let cfg = RealityConfig::from_proto(&proto_fixture()).unwrap();
        assert!(cfg.show);
        assert_eq!(cfg.dest, "example.com:443");
        assert_eq!(cfg.r#type, "tcp");
        assert_eq!(cfg.xver, 1);
    }

    #[test]
    fn from_proto_server_names_map() {
        let cfg = RealityConfig::from_proto(&proto_fixture()).unwrap();
        assert!(cfg.server_names.contains_key("example.com"));
        assert_eq!(cfg.server_names.len(), 1);
    }

    #[test]
    fn from_proto_short_ids_map() {
        let cfg = RealityConfig::from_proto(&proto_fixture()).unwrap();
        assert_eq!(cfg.short_ids.len(), 2);
        assert!(cfg.short_ids.contains_key(&ShortId([0u8; 8])));
        assert!(cfg.short_ids.contains_key(&ShortId([0xffu8; 8])));
    }

    #[test]
    fn from_proto_limit_fallback() {
        let cfg = RealityConfig::from_proto(&proto_fixture()).unwrap();
        let lf = cfg.limit_fallback_upload.unwrap();
        assert_eq!(lf.after_bytes, 100);
        assert_eq!(lf.bytes_per_sec, 50);
        assert_eq!(lf.burst_bytes_per_sec, 75);
        assert!(cfg.limit_fallback_download.is_none());
    }

    #[test]
    fn from_proto_invalid_short_id_len() {
        let mut p = proto_fixture();
        p.short_ids = vec![vec![0u8; 7]]; // 长度错
        let err = RealityConfig::from_proto(&p).unwrap_err();
        assert!(matches!(
            err,
            RealityError::InvalidShortIdLen { actual: 7 }
        ));
    }

    #[test]
    fn from_proto_max_time_diff_units_millis() {
        // Go: time.Duration(c.MaxTimeDiff) * time.Millisecond
        let cfg = RealityConfig::from_proto(&proto_fixture()).unwrap();
        assert_eq!(cfg.max_time_diff, Duration::from_millis(1000));
    }

    #[test]
    fn from_proto_mldsa65_seed_preserved() {
        let mut p = proto_fixture();
        p.mldsa65_seed = vec![0xaa; 32];
        let cfg = RealityConfig::from_proto(&p).unwrap();
        assert_eq!(cfg.mldsa65_seed, Some(vec![0xaa; 32]));
        // mldsa65_key 留 None（等接入 circl/sign/mldsa65）
        assert!(cfg.mldsa65_key.is_none());
    }

    /// Go `(*[32]byte)(c.Mldsa65Seed)`：长度 ≠ 32 直接失败
    /// （Go panic → Rust 配置期错误）。
    #[test]
    fn from_proto_rejects_bad_mldsa65_seed_len() {
        let mut p = proto_fixture();
        p.mldsa65_seed = vec![0xaa; 31];
        let err = RealityConfig::from_proto(&p).unwrap_err();
        assert!(matches!(
            err,
            RealityError::InvalidMldsa65SeedLen { actual: 31 }
        ));
    }

    /// 客户端字段 mldsa65_verify（proto field 25）透传。
    #[test]
    fn from_proto_mldsa65_verify_preserved() {
        let mut p = proto_fixture();
        p.mldsa65_verify = vec![0xbb; 1952];
        let cfg = RealityConfig::from_proto(&p).unwrap();
        assert_eq!(cfg.mldsa65_verify.len(), 1952);
        assert_eq!(cfg.mldsa65_verify[0], 0xbb);
    }

    #[test]
    fn validate_client_ok() {
        let cfg = RealityConfig::from_proto(&proto_fixture()).unwrap();
        cfg.validate_client().unwrap();
    }

    #[test]
    fn validate_client_public_key_len() {
        let mut p = proto_fixture();
        p.public_key = vec![0u8; 31];
        let cfg = RealityConfig::from_proto(&p).unwrap();
        let err = cfg.validate_client().unwrap_err();
        assert!(matches!(
            err,
            RealityError::InvalidPublicKeyLen { actual: 31 }
        ));
    }

    #[test]
    fn validate_client_empty_fingerprint() {
        let mut p = proto_fixture();
        p.fingerprint = String::new();
        let cfg = RealityConfig::from_proto(&p).unwrap();
        let err = cfg.validate_client().unwrap_err();
        assert!(matches!(err, RealityError::FingerprintNotFound));
    }

    #[test]
    fn validate_server_ok() {
        let cfg = RealityConfig::from_proto(&proto_fixture()).unwrap();
        cfg.validate_server().unwrap();
    }

    #[test]
    fn validate_server_private_key_len() {
        let mut p = proto_fixture();
        p.private_key = vec![0u8; 16];
        let cfg = RealityConfig::from_proto(&p).unwrap();
        let err = cfg.validate_server().unwrap_err();
        assert!(matches!(
            err,
            RealityError::InvalidPrivateKeyLen { actual: 16 }
        ));
    }

    #[test]
    fn short_id_from_slice_wrong_len() {
        let err = ShortId::from_slice(&[0u8; 7]).unwrap_err();
        assert!(matches!(
            err,
            RealityError::InvalidShortIdLen { actual: 7 }
        ));
    }

    #[test]
    fn short_id_from_slice_correct() {
        let s = ShortId::from_slice(&[0xab; 8]).unwrap();
        assert_eq!(s.0, [0xab; 8]);
    }

    #[test]
    fn session_tickets_disabled_hardcoded_true() {
        // 与 Go 端硬编码一致：session_tickets_disabled=true、next_protos=nil
        let cfg = RealityConfig::default();
        assert!(cfg.session_tickets_disabled);
        assert!(cfg.next_protos.is_none());
    }

    #[test]
    fn spider_y_kept_as_i64() {
        let cfg = RealityConfig::from_proto(&proto_fixture()).unwrap();
        assert_eq!(cfg.spider_y.len(), 10);
        assert_eq!(cfg.spider_y[0], 100);
        assert_eq!(cfg.spider_y[9], 8);
    }

    #[test]
    fn default_max_time_diff_zero() {
        assert_eq!(RealityConfig::default().max_time_diff, Duration::ZERO);
    }
}

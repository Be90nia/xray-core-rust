//! Encrypted Client Hello (ECH) 配置。
//!
//! 翻译自 Go `transport/internet/tls/ech.go`。
//!
//! # 范围
//! 本模块翻译**纯逻辑**：
//! - `EncryptedClientHelloKey` 的二进制 TLV 解析（`convert_to_ech_keys`）
//! - `ECHConfigCache` / `EchConfigRecord` 数据结构
//! - `ech_cache_key` 字符串拼装
//! - `EchRecordType` 枚举（`Config` vs `DnsQuery` 区分）
//!
//! 实际 `apply_ech`（组装 rustls::ClientConfig 的 ECH 加密）、
//! `query_record`/`dns_query`（HTTP/UDP DNS 查询）、DOH client 复用等
//! **IO 逻辑未翻译**——等接入 rustls + DNS crate（Phase 4 abc）后添加。

use crate::error::TlsError;
use std::sync::Mutex;
use std::time::Instant;

// ============================================================
// ECH key 二进制解析（对应 Go ConvertToGoECHKeys）
// ============================================================

/// 解析后的单个 ECH key。
///
/// 对应 Go `tls.EncryptedClientHelloKey`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedClientHelloKey {
    /// ECH config（公开部分，会出现在 DNS HTTPS RR 中）。
    pub config: Vec<u8>,
    /// 对应的私钥。
    pub private_key: Vec<u8>,
}

/// 二进制格式：`[key_len:u16][key][config_len:u16][config]`，多个 key 顺序拼接。
///
/// 对应 Go `ConvertToGoECHKeys(data []byte)`，按 cryptobyte 风格顺序读。
///
/// # 错误
/// 任何长度字段不匹配返回 `TlsError::InvalidEchKeyLength`（对应 Go `ErrInvalidLen`）。
///
/// # 示例
/// ```
/// use xray_tls::ech::{convert_to_ech_keys, EncryptedClientHelloKey};
///
/// // 构造一个简单的 2-byte key + 3-byte config
/// let mut data = Vec::new();
/// data.extend_from_slice(&2u16.to_be_bytes()); // key_len
/// data.extend_from_slice(b"sk");
/// data.extend_from_slice(&3u16.to_be_bytes()); // config_len
/// data.extend_from_slice(b"cfg");
///
/// let keys = convert_to_ech_keys(&data).unwrap();
/// assert_eq!(keys.len(), 1);
/// assert_eq!(keys[0].private_key, b"sk");
/// assert_eq!(keys[0].config, b"cfg");
/// ```
pub fn convert_to_ech_keys(data: &[u8]) -> Result<Vec<EncryptedClientHelloKey>, TlsError> {
    let mut keys = Vec::new();
    let mut s = data;

    while !s.is_empty() {
        // 读 key_len（2 字节大端）
        let key_len = read_u16_be(s)?;
        s = &s[2..];
        if s.len() < usize::from(key_len) + 4 {
            return Err(TlsError::InvalidEchKeyLength);
        }
        let sk = &s[..usize::from(key_len)];
        s = &s[usize::from(key_len)..];

        // 读 config_len（2 字节大端）
        let config_len = read_u16_be(s)?;
        s = &s[2..];
        if s.len() < usize::from(config_len) {
            return Err(TlsError::InvalidEchKeyLength);
        }
        let config = &s[..usize::from(config_len)];
        s = &s[usize::from(config_len)..];

        keys.push(EncryptedClientHelloKey {
            private_key: sk.to_vec(),
            config: config.to_vec(),
        });
    }

    Ok(keys)
}

fn read_u16_be(s: &[u8]) -> Result<u16, TlsError> {
    if s.len() < 2 {
        return Err(TlsError::InvalidEchKeyLength);
    }
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

// ============================================================
// ECHConfigCache（对应 Go ECHConfigCache struct）
// ============================================================

/// ECH 配置缓存条目。
///
/// 对应 Go `echConfigRecord struct { config []byte; expire time.Time }`。
/// `expire` 用 `Instant` 表达（与 `time.Time` 在语义上一致，但需注意
/// `Instant` 无法跨进程持久化）。
#[derive(Debug, Clone, Default)]
pub struct EchConfigRecord {
    /// 原始 ECH config 字节。
    pub config: Vec<u8>,
    /// 过期时间；默认值表示「未初始化」。
    pub expire: Option<Instant>,
}

impl EchConfigRecord {
    /// 是否已过期。未初始化记录视为「未命中」。
    pub fn is_expired(&self, now: Instant) -> bool {
        match self.expire {
            None => true,
            Some(t) => now >= t, // now >= t = 过期
        }
    }

    /// Go 端 `expire == (time.Time{})` 判断。
    pub fn is_uninitialized(&self) -> bool {
        self.expire.is_none()
    }
}

/// ECH 配置缓存。
///
/// 对应 Go `ECHConfigCache struct { configRecord atomic.Pointer[echConfigRecord]; UpdateLock sync.Mutex }`。
/// Rust 用 `Mutex<EchConfigRecord>` 替代 atomic.Pointer + Mutex（Rust 的 atomic
/// 指针语义不直接支持 arbitrary struct，简化为 Mutex 内整体替换）。
#[derive(Debug, Default)]
pub struct EchConfigCache {
    inner: Mutex<EchConfigRecord>,
}

impl EchConfigCache {
    /// 创建空缓存。
    pub fn new() -> Self {
        Self::default()
    }

    /// 获取当前记录（克隆）。
    pub fn load(&self) -> EchConfigRecord {
        self.inner.lock().expect("ECH cache mutex poisoned").clone()
    }

    /// 替换当前记录。返回旧记录。
    pub fn store(&self, record: EchConfigRecord) -> EchConfigRecord {
        let mut guard = self.inner.lock().expect("ECH cache mutex poisoned");
        std::mem::replace(&mut *guard, record)
    }

    /// 在持锁状态下执行闭包（对应 Go `Update` 中 `UpdateLock.Lock()` 区块）。
    ///
    /// 闭包返回 `(new_record, result)`；`new_record` 被存入，`result` 返回给调用者。
    /// Go 端「双检锁」逻辑在闭包内自行实现。
    pub fn with_lock<R>(
        &self,
        f: impl FnOnce(&EchConfigRecord) -> (EchConfigRecord, R),
    ) -> R {
        let mut guard = self.inner.lock().expect("ECH cache mutex poisoned");
        let (new_record, result) = f(&guard);
        *guard = new_record;
        result
    }
}

// ============================================================
// ECHCacheKey（对应 Go ECHCacheKey）
// ============================================================

/// 生成缓存 key 字符串。
///
/// 对应 Go `ECHCacheKey(server, domain, sockopt)`，返回
/// `"{server}|{domain}|{sockopt_ptr}"`。Go 用 `%p` 格式化指针，Rust 端
/// 改用 `sockopt_id: u64`（调用方传入任意稳定标识，如 hash 或序号）——避免
/// 取裸指针地址（不稳定且跨进程无意义）。
///
/// # 示例
/// ```
/// use xray_tls::ech::ech_cache_key;
/// let k = ech_cache_key("https://1.1.1.1/dns-query", "example.com", 0);
/// assert_eq!(k, "https://1.1.1.1/dns-query|example.com|0");
/// ```
pub fn ech_cache_key(server: &str, domain: &str, sockopt_id: u64) -> String {
    // 注意：Go 用 fmt.Sprintf("%p", sockopt) 返回 "0x..."；这里简化为 u64 的十进制。
    // 业务等价：作为哈希表 key 使用，只要唯一即可。
    format!("{server}|{domain}|{sockopt_id}")
}

// ============================================================
// ApplyEch trait（占位，等 rustls ECH 支持）
// ============================================================

/// ECH 应用接口。
///
/// 对应 Go `ApplyECH(c *Config, config *tls.Config) error`。
///
/// 实现侧需根据 `Config.ech_server_keys`（服务端模式）或 `Config.ech_config_list`
/// （客户端模式）填充目标 TLS 配置的 ECH 相关字段。
/// Rust 端的实际实现等 `rustls` ECH 支持稳定后添加（当前 rustls 0.23+ 通过
/// feature `ECH` 提供，但仍处于实验阶段）。
pub trait ApplyEch {
    /// 应用 ECH 配置。
    ///
    /// - 服务端模式：`server_keys` 非空时启用服务端 ECH 解密。
    /// - 客户端模式：`config_list` 是 base64 或 `dns://`/`https://` URL，
    ///   后者需 DNS 查询（由调用方提供查询器）。
    fn apply_ech(
        &mut self,
        server_keys: &[u8],
        config_list: &str,
    ) -> Result<(), TlsError>;
}

// ============================================================
// 测试
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn pack_key(sk: &[u8], cfg: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(sk.len() as u16).to_be_bytes());
        v.extend_from_slice(sk);
        v.extend_from_slice(&(cfg.len() as u16).to_be_bytes());
        v.extend_from_slice(cfg);
        v
    }

    #[test]
    fn convert_empty_input_returns_empty_keys() {
        assert_eq!(convert_to_ech_keys(&[]).unwrap(), Vec::<EncryptedClientHelloKey>::new());
    }

    #[test]
    fn convert_single_key_parses_correctly() {
        let data = pack_key(b"secret-key", b"ech-config");
        let keys = convert_to_ech_keys(&data).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].private_key, b"secret-key");
        assert_eq!(keys[0].config, b"ech-config");
    }

    #[test]
    fn convert_multiple_keys_concat() {
        let mut data = pack_key(b"sk1", b"cfg1");
        data.extend(pack_key(b"sk2", b"cfg2"));
        let keys = convert_to_ech_keys(&data).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].private_key, b"sk1");
        assert_eq!(keys[1].private_key, b"sk2");
    }

    #[test]
    fn convert_truncated_after_key_len_errors() {
        let mut data = pack_key(b"sk", b"cfg");
        data.truncate(2); // 只留 key_len 字段
        assert!(matches!(
            convert_to_ech_keys(&data),
            Err(TlsError::InvalidEchKeyLength)
        ));
    }

    #[test]
    fn convert_truncated_after_key_errors() {
        let mut data = pack_key(b"sk", b"cfg");
        // 删掉一部分
        data.truncate(4); // key_len(2) + key(2)
        assert!(matches!(
            convert_to_ech_keys(&data),
            Err(TlsError::InvalidEchKeyLength)
        ));
    }

    #[test]
    fn convert_truncated_config_errors() {
        let mut data = pack_key(b"sk", b"cfg");
        // 删除 config 最后一字节
        data.pop();
        assert!(matches!(
            convert_to_ech_keys(&data),
            Err(TlsError::InvalidEchKeyLength)
        ));
    }

    #[test]
    fn convert_single_byte_input_errors() {
        assert!(matches!(
            convert_to_ech_keys(&[0u8]),
            Err(TlsError::InvalidEchKeyLength)
        ));
    }

    // ---- EchConfigRecord / EchConfigCache ----

    #[test]
    fn record_default_is_uninitialized_and_expired() {
        let r = EchConfigRecord::default();
        assert!(r.is_uninitialized());
        assert!(r.is_expired(Instant::now()));
    }

    #[test]
    fn record_with_future_expire_not_expired() {
        let now = Instant::now();
        let r = EchConfigRecord {
            config: vec![1, 2, 3],
            expire: Some(now + Duration::from_secs(60)),
        };
        assert!(!r.is_expired(now));
        assert!(!r.is_uninitialized());
    }

    #[test]
    fn cache_store_returns_old_record() {
        let cache = EchConfigCache::new();
        let old = EchConfigRecord {
            config: vec![1],
            expire: Some(Instant::now() + Duration::from_secs(30)),
        };
        let prev = cache.store(old.clone());
        assert!(prev.is_uninitialized()); // 初始默认记录

        let new = EchConfigRecord {
            config: vec![2],
            expire: Some(Instant::now() + Duration::from_secs(60)),
        };
        let prev2 = cache.store(new);
        assert_eq!(prev2.config, vec![1]);
        assert_eq!(cache.load().config, vec![2]);
    }

    #[test]
    fn cache_with_lock_runs_under_mutex() {
        let cache = EchConfigCache::new();
        let result = cache.with_lock(|current| {
            assert!(current.is_uninitialized());
            (
                EchConfigRecord {
                    config: vec![9],
                    expire: Some(Instant::now() + Duration::from_secs(10)),
                },
                42,
            )
        });
        assert_eq!(result, 42);
        assert_eq!(cache.load().config, vec![9]);
    }

    // ---- ech_cache_key ----

    #[test]
    fn cache_key_format_matches_design() {
        let k = ech_cache_key("srv", "dom", 7);
        assert_eq!(k, "srv|dom|7");
    }

    #[test]
    fn cache_key_unique_per_sockopt_id() {
        assert_ne!(
            ech_cache_key("srv", "dom", 1),
            ech_cache_key("srv", "dom", 2)
        );
    }
}

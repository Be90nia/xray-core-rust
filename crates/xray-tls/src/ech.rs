//! Encrypted Client Hello (ECH) 配置。
//!
//! 翻译自 Go `transport/internet/tls/ech.go` + `main/commands/all/tls/ech.go`。
//!
//! # 范围
//! - `EncryptedClientHelloKey` 的二进制 TLV 解析（`convert_to_ech_keys`）
//! - `ECHConfigCache` / `EchConfigRecord` 数据结构 + `ech_cache_key`
//! - ECH keyset 生成（`generate_ech_key_set`，对应 Go CLI `generateECHKeySet`+`marshalBinary`）
//! - 客户端 config list 解析（`resolve_client_ech_config_list`，对应 Go `ApplyECH` client 分支）
//! - JSON 字段解析（`parse_ech_server_keys`/`parse_ech_config_list`，对应 Go infra/conf L728-735）
//! - `ApplyEch` trait 的 btls (BoringSSL) 客户端实装（`Ssl::set_ech_config_list`，
//!   经 `utls::u_client` 接入生产 dial 路径；服务端 keys 注册被 btls 上游导出缺口
//!   阻塞，见 trait 文档）
//!
//! DNS 查询路径（`query_record`/`dns_query`）未翻译：`ech_config_list` 含 `://`
//! 时按 Go「查询失败」语义降级为 invalid config（握手必败），待 DNS 集成后实装。

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
// ECH keyset 生成（对应 Go main/commands/all/tls/ech.go）
// ============================================================

/// ECH 扩展类型（draft-13），ECHConfig 的 version 字段。
///
/// 对应 Go `ExtensionEncryptedClientHello = 0xfe0d`。
pub const EXTENSION_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

/// DHKEM(X25519, HKDF-SHA256)（RFC 9180 KEM ID）。
///
/// 对应 Go `hpke.DHKEM(ecdh.X25519()).ID()`。
pub const KEM_X25519_HKDF_SHA256: u16 = 0x0020;

/// 默认 cipher suite 列表：3 KDF × 3 AEAD 全组合（RFC 9180 ID）。
///
/// 对应 Go `generateECHKeySet` 的 `SymmetricCipherSuite`（顺序一致）。
const DEFAULT_SUITES: &[(u16, u16)] = &[
    (0x0001, 0x0001), // HKDF-SHA256 + AES-128-GCM
    (0x0001, 0x0002), // HKDF-SHA256 + AES-256-GCM
    (0x0001, 0x0003), // HKDF-SHA256 + ChaCha20Poly1305
    (0x0002, 0x0001), // HKDF-SHA384 + AES-128-GCM
    (0x0002, 0x0002), // HKDF-SHA384 + AES-256-GCM
    (0x0002, 0x0003), // HKDF-SHA384 + ChaCha20Poly1305
    (0x0003, 0x0001), // HKDF-SHA512 + AES-128-GCM
    (0x0003, 0x0002), // HKDF-SHA512 + AES-256-GCM
    (0x0003, 0x0003), // HKDF-SHA512 + ChaCha20Poly1305
];

/// 拿不到有效 ECH config 时的降级占位（对齐 Go `[]byte{1, 1, 4, 5, 1, 4}`）。
///
/// Go 语义（ech.go L51-57 defer）：客户端 ECH 获取失败时填入非法 config，
/// **使连接失败**而非静默降级明文 SNI。Rust 端 DNS 查询未实现，`://` 形式
/// 一律走此降级。差异：BoringSSL 对 config list 即时解析，非法 TLV 在
/// `SSL_set1_ech_config_list` 时即报 `INVALID_ECH_CONFIG_LIST`（Go 是握手时
/// 失败）——用户可见结果一致：连接失败。
pub const INVALID_ECH_CONFIG: &[u8] = &[1, 1, 4, 5, 1, 4];

/// 生成一个 ECH keyset：X25519 随机私钥 + 对应 ECHConfig TLV。
///
/// 对应 Go `generateECHKeySet(0, domain, hpke.DHKEM(ecdh.X25519()).ID())` +
/// `marshalBinary`。
///
/// 返回 `(config, private_key)`：
/// - `config`：完整 ECHConfig wire 格式 `[version:u16][u16-len body]`
///   （body = config_id=0 + kem + pub + suites + max_name_len=0 + public_name + 空 extensions）
/// - `private_key`：32 字节 X25519 私钥（未 clamp，运算时按 RFC 7748 clamp）
#[must_use]
pub fn generate_ech_key_set(public_name: &str) -> (Vec<u8>, [u8; 32]) {
    use rand::RngCore;
    use x25519_dalek::{PublicKey, StaticSecret};

    let mut priv_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut priv_bytes);
    let secret = StaticSecret::from(priv_bytes);
    let public = PublicKey::from(&secret);

    // body（u16 长度前缀内的部分）
    let mut body = Vec::with_capacity(8 + public_name.len());
    body.push(0u8); // config_id
    body.extend_from_slice(&KEM_X25519_HKDF_SHA256.to_be_bytes());
    body.extend_from_slice(&(public.as_bytes().len() as u16).to_be_bytes());
    body.extend_from_slice(public.as_bytes());
    body.extend_from_slice(&((DEFAULT_SUITES.len() * 4) as u16).to_be_bytes());
    for &(kdf, aead) in DEFAULT_SUITES {
        body.extend_from_slice(&kdf.to_be_bytes());
        body.extend_from_slice(&aead.to_be_bytes());
    }
    body.push(0u8); // max_name_length
    body.push(public_name.len() as u8);
    body.extend_from_slice(public_name.as_bytes());
    body.extend_from_slice(&0u16.to_be_bytes()); // extensions（空）

    let mut config = Vec::with_capacity(4 + body.len());
    config.extend_from_slice(&EXTENSION_ENCRYPTED_CLIENT_HELLO.to_be_bytes());
    config.extend_from_slice(&(body.len() as u16).to_be_bytes());
    config.extend_from_slice(&body);
    (config, priv_bytes)
}

/// 打包 server keys 二进制：`[key_len:u16][key][config_len:u16][config]`。
///
/// 对应 Go CLI 的 `keyBuffer` 构造（`xray tls ech` 输出的 `ECH server keys`，
/// 即 JSON `echServerKeys` 字段的 base64 内容）。
#[must_use]
pub fn pack_ech_server_keys(key: &[u8], config: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + key.len() + config.len());
    v.extend_from_slice(&(key.len() as u16).to_be_bytes());
    v.extend_from_slice(key);
    v.extend_from_slice(&(config.len() as u16).to_be_bytes());
    v.extend_from_slice(config);
    v
}

/// 打包 config list：每个 config 加 `u16` 长度前缀后顺序拼接。
///
/// 对应 Go CLI 的 `configBuffer` 构造（`xray tls ech` 输出的 `ECH config list`，
/// 即客户端 `echConfigList` 字段的 base64 内容 / btls `set_ech_config_list` 输入）。
#[must_use]
pub fn pack_ech_config_list(configs: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for c in configs {
        v.extend_from_slice(&(c.len() as u16).to_be_bytes());
        v.extend_from_slice(c);
    }
    v
}

/// 从 server keys 二进制提取 config list（每个 config u16 前缀拼接）。
///
/// 对应 Go CLI `-i` 路径：`ConvertToGoECHKeys` 后逐个 `AddUint16LengthPrefixed(config)`。
pub fn ech_config_list_from_server_keys(server_keys: &[u8]) -> Result<Vec<u8>, TlsError> {
    let keys = convert_to_ech_keys(server_keys)?;
    let configs: Vec<&[u8]> = keys.iter().map(|k| k.config.as_slice()).collect();
    Ok(pack_ech_config_list(&configs))
}

// ============================================================
// 客户端 config list 解析（对应 Go ApplyECH client 分支 ech.go L49-85）
// ============================================================

/// 解析客户端 `echConfigList` 字符串为 config list 字节。
///
/// **永不失败**（对齐 Go defer 语义，ech.go L51-57）：只要配置了 ECH 就必有返回值——
/// - base64（标准编码）→ 解码 bytes；
/// - 含 `://` 的 DNS 形式（`https://...` / `domain+https://...`）→ DNS 查询未实现，
///   按 Go「查询失败」降级返回 [`INVALID_ECH_CONFIG`]（握手将失败，不静默明文）；
/// - base64 解码失败 → 同上降级 invalid。
#[must_use]
pub fn resolve_client_ech_config_list(config_list: &str) -> Vec<u8> {
    use base64::Engine as _;
    use tracing::warn;

    if config_list.contains("://") {
        // Go：按 "+" split 校验格式（>2 段报错）→ QueryRecord。查询能力未接入，
        // 一律走 Go 查询失败的 defer 降级路径。
        let parts: Vec<&str> = config_list.split('+').collect();
        if parts.len() > 2 {
            warn!(
                target: "xray_tls::ech",
                config_list,
                "invalid ECH DNS server format"
            );
        } else {
            warn!(
                target: "xray_tls::ech",
                config_list,
                "ECH DNS query not yet implemented; falling back to invalid config (handshake will fail)"
            );
        }
        return INVALID_ECH_CONFIG.to_vec();
    }
    match base64::engine::general_purpose::STANDARD.decode(config_list) {
        Ok(b) => b,
        Err(e) => {
            warn!(
                target: "xray_tls::ech",
                error = %e,
                "failed to base64-decode ECHConfigList; falling back to invalid config"
            );
            INVALID_ECH_CONFIG.to_vec()
        }
    }
}

// ============================================================
// JSON 字段解析（对应 Go infra/conf/transport_internet.go L728-735）
// ============================================================

/// 解析 `tlsSettings.echServerKeys`（base64 → bytes）。
///
/// 缺失/空返回空 `Vec`；base64 非法返回 `Err`（对齐 Go `"invalid ECH Config"`）。
pub fn parse_ech_server_keys(json: &serde_json::Value) -> Result<Vec<u8>, TlsError> {
    use base64::Engine as _;

    let Some(s) = json
        .as_object()
        .and_then(|m| m.get("echServerKeys"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    else {
        return Ok(Vec::new());
    };
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| TlsError::EchApply(format!("invalid ECH Config: {e}")))
}

/// 解析 `tlsSettings.echConfigList`（原样透传，对应 Go `config.EchConfigList = c.ECHConfigList`）。
#[must_use]
pub fn parse_ech_config_list(json: &serde_json::Value) -> String {
    json.as_object()
        .and_then(|m| m.get("echConfigList"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

// ============================================================
// ApplyEch trait + btls (BoringSSL) 客户端实装
// ============================================================

/// ECH 应用接口。
///
/// 对应 Go `ApplyECH(c *Config, config *tls.Config) error`（双分支单函数）：
/// - 客户端：`config_list` 非空 → 提供 ECH config list（加密 ClientHello）。
/// - 服务端：`server_keys` 非空 → 注册 ECH 解密 keys。**当前不可实装**：
///   btls v0.5.6 未公开导出 `SslEchKeys`/`SslEchKeysBuilder`（仅 `SslEchKeysRef`），
///   `SslContextRef::set_ech_keys` 的参数类型在 crate 外不可构造；且生产 inbound
///   TLS 走 rustls（无 btls acceptor、rustls 无 ECH feature），本就没有接线点。
///   待 btls 上游导出修复 + btls server acceptor 集成后补充。
///
/// 已有实装：[`btls::ssl::Ssl`]（客户端，per-connection）→ `SSL_set1_ech_config_list`，
/// 由 [`crate::utls::u_client`] 在握手前调用（`xray-transport-tcp` 生产 dial 路径）。
pub trait ApplyEch {
    /// 应用 ECH 配置。参数与 Go `ApplyECH` 一致：client 实装取 `config_list`，
    /// 空值跳过。
    fn apply_ech(
        &mut self,
        server_keys: &[u8],
        config_list: &str,
    ) -> Result<(), TlsError>;
}

impl ApplyEch for btls::ssl::Ssl {
    /// 客户端：`config_list` 非空 → resolve（含 invalid 降级）→
    /// `SSL_set1_ech_config_list`。须在握手前调用。
    fn apply_ech(
        &mut self,
        _server_keys: &[u8],
        config_list: &str,
    ) -> Result<(), TlsError> {
        if config_list.is_empty() {
            return Ok(());
        }
        let list = resolve_client_ech_config_list(config_list);
        self.set_ech_config_list(&list)
            .map_err(|e| TlsError::EchApply(format!("SSL_set1_ech_config_list: {e}")))
    }
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

    // ---- generate_ech_key_set / pack / extract（对应 Go CLI）----

    #[test]
    fn generate_ech_key_set_tlv_structure_matches_go() {
        let (config, priv_bytes) = generate_ech_key_set("example.com");

        // version + u16 长度前缀
        assert_eq!(
            u16::from_be_bytes([config[0], config[1]]),
            EXTENSION_ENCRYPTED_CLIENT_HELLO
        );
        let body_len = u16::from_be_bytes([config[2], config[3]]) as usize;
        assert_eq!(config.len(), 4 + body_len, "body length prefix must cover rest");
        let body = &config[4..];

        // config_id=0, kem=0x20
        assert_eq!(body[0], 0);
        assert_eq!(
            u16::from_be_bytes([body[1], body[2]]),
            KEM_X25519_HKDF_SHA256
        );
        // pub key 32 字节
        let pub_len = u16::from_be_bytes([body[3], body[4]]) as usize;
        assert_eq!(pub_len, 32);
        let public = &body[5..5 + 32];

        // 公钥可由私钥重新派生（clamp 后一致）
        let secret = x25519_dalek::StaticSecret::from(priv_bytes);
        let expect_pub = x25519_dalek::PublicKey::from(&secret);
        assert_eq!(public, expect_pub.as_bytes());

        // suites：u16 前缀 36 字节 = 9 组 × 4
        let off = 5 + pub_len;
        let suites_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
        assert_eq!(suites_len, 36);

        // max_name_length=0、public_name
        let off = off + 2 + suites_len;
        assert_eq!(body[off], 0);
        assert_eq!(body[off + 1], u8::try_from("example.com".len()).unwrap());
        assert_eq!(&body[off + 2..off + 2 + "example.com".len()], b"example.com");
        // extensions 空（u16 0）
        let off = off + 2 + "example.com".len();
        assert_eq!(&body[off..], &0u16.to_be_bytes());
    }

    #[test]
    fn generate_and_pack_roundtrips_through_convert() {
        let (config, priv_bytes) = generate_ech_key_set("ech.test");
        let server_keys = pack_ech_server_keys(&priv_bytes, &config);

        let parsed = convert_to_ech_keys(&server_keys).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].config, config);
        assert_eq!(parsed[0].private_key, priv_bytes);
    }

    #[test]
    fn config_list_from_server_keys_prefixes_each_config() {
        let (config, priv_bytes) = generate_ech_key_set("a.test");
        let server_keys = pack_ech_server_keys(&priv_bytes, &config);

        let list = ech_config_list_from_server_keys(&server_keys).unwrap();
        assert_eq!(list, pack_ech_config_list(&[&config]));
        // 首个 u16 = config 长度
        assert_eq!(
            u16::from_be_bytes([list[0], list[1]]) as usize,
            config.len()
        );
    }

    #[test]
    fn config_list_from_invalid_server_keys_errors() {
        // 长度字段超界 → ErrInvalidLen 语义透传
        assert!(ech_config_list_from_server_keys(&[0x00, 0xff, 0x01]).is_err());
    }

    // ---- resolve_client_ech_config_list（对应 Go ApplyECH client 分支）----

    #[test]
    fn resolve_valid_base64_returns_bytes() {
        use base64::Engine as _;
        let raw = vec![1, 2, 3, 4, 5];
        let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
        assert_eq!(resolve_client_ech_config_list(&b64), raw);
    }

    #[test]
    fn resolve_invalid_base64_falls_back_to_invalid_config() {
        // Go defer 语义：解码失败 → invalid config（握手必败）
        assert_eq!(resolve_client_ech_config_list("!!!not-base64!!!"), INVALID_ECH_CONFIG);
    }

    #[test]
    fn resolve_dns_form_falls_back_to_invalid_config() {
        // DNS 查询未实现：对齐 Go 查询失败降级
        assert_eq!(
            resolve_client_ech_config_list("https://1.1.1.1/dns-query"),
            INVALID_ECH_CONFIG
        );
        assert_eq!(
            resolve_client_ech_config_list("example.com+https://1.1.1.1/dns-query"),
            INVALID_ECH_CONFIG
        );
    }

    // ---- JSON 解析（对应 Go infra/conf L728-735）----

    #[test]
    fn parse_ech_server_keys_from_json() {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode([9u8, 9, 9]);
        let json = serde_json::json!({"echServerKeys": b64});
        assert_eq!(parse_ech_server_keys(&json).unwrap(), vec![9, 9, 9]);
    }

    #[test]
    fn parse_ech_server_keys_missing_or_empty_ok() {
        assert_eq!(parse_ech_server_keys(&serde_json::json!({})).unwrap(), Vec::<u8>::new());
        assert_eq!(
            parse_ech_server_keys(&serde_json::json!({"echServerKeys": ""})).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn parse_ech_server_keys_invalid_base64_errors() {
        assert!(parse_ech_server_keys(&serde_json::json!({"echServerKeys": "%%"})).is_err());
    }

    #[test]
    fn parse_ech_config_list_passthrough() {
        assert_eq!(
            parse_ech_config_list(&serde_json::json!({"echConfigList": "aGVsbG8="})),
            "aGVsbG8="
        );
        assert_eq!(parse_ech_config_list(&serde_json::json!({})), "");
    }

    // ---- ApplyEch btls 实装（真实 BoringSSL 调用）----

    #[test]
    fn apply_ech_on_btls_ssl_sets_config_list() {
        let ctx = btls::ssl::SslContext::builder(btls::ssl::SslMethod::tls())
            .unwrap()
            .build();
        let mut ssl = btls::ssl::Ssl::new(&ctx).unwrap();

        // base64 形式（真实 SSL_set1_ech_config_list）
        use base64::Engine as _;
        let list = pack_ech_config_list(&[&generate_ech_key_set("x.test").0]);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&list);
        ssl.apply_ech(&[], &b64).unwrap();

        // invalid 降级：BoringSSL 对 config list 即时解析，非法 TLV 在 set 时即被拒
        // （INVALID_ECH_CONFIG_LIST）。与 Go「握手时才失败」用户可见结果一致：连接失败。
        let err = ssl.apply_ech(&[], "https://dns.example/query").unwrap_err();
        assert!(err.to_string().contains("INVALID_ECH_CONFIG_LIST"), "got: {err}");

        // 空配置 no-op
        ssl.apply_ech(&[], "").unwrap();
    }
}

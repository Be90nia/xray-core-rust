//! XUDP 协议实现
//!
//! 对应 Go 版本 common/xudp 包，提供 XUDP GlobalID 生成与配置管理。
//!
//! # 核心功能
//!
//! - [global_id]: 基于入站源地址生成 8 字节 GlobalID（blake3 哈希）
//! - [XudpConfig]: 全局配置（日志开关、基础密钥），从环境变量初始化
//!
//! # 环境变量
//!
//! | 变量 | 格式 | 说明 |
//! |------|------|------|
//! | XUDP_LOG | "1" / "true" / "0" / "false" | 控制日志输出 |
//! | XUDP_BASE_KEY | Base64 URL-safe（无填充），32 字节 | XUDP 流量加密基础密钥 |

pub mod extension;
pub mod packet;

use std::sync::OnceLock;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use blake3::Hasher;
use rand::RngCore;
use xray_common::net::network::Network;

// ========== 环境变量名 ==========

/// XUDP_LOG 环境变量名
const ENV_XUDP_LOG: &str = "XUDP_LOG";

/// XUDP_BASE_KEY 环境变量名
const ENV_XUDP_BASE_KEY: &str = "XUDP_BASE_KEY";

/// GlobalID 字节长度
const GLOBAL_ID_LEN: usize = 8;

/// BaseKey 必须的字节长度
const BASE_KEY_LEN: usize = 32;

// ========== 全局配置 ==========

/// XUDP 全局配置，从环境变量一次性初始化。
///
/// 对应 Go 版本 xudp.Show + xudp.BaseKey。
#[derive(Debug, Clone)]
pub struct XudpConfig {
    /// 是否打印 XUDP 日志
    pub log: bool,
    /// XUDP 流量加密基础密钥（32 字节），未设置时为随机值
    pub base_key: [u8; BASE_KEY_LEN],
}

impl XudpConfig {
    /// 创建新的配置实例。
    ///
    /// 用于编程构造配置（测试或自定义初始化场景）。
    #[must_use]
    pub fn new(log: bool, base_key: [u8; BASE_KEY_LEN]) -> Self {
        Self { log, base_key }
    }

    /// 从环境变量加载配置。
    ///
    /// - XUDP_LOG: 设为 "1" / "true" / "yes" / "on"（不区分大小写）时启用日志
    /// - XUDP_BASE_KEY: Base64 URL-safe 无填充编码的 32 字节密钥；
    ///   未设置或无效时使用随机密钥
    #[must_use]
    pub fn from_env() -> Self {
        let log = parse_env_bool(ENV_XUDP_LOG);

        let base_key = match std::env::var(ENV_XUDP_BASE_KEY) {
            Ok(raw) if !raw.is_empty() => {
                match URL_SAFE_NO_PAD.decode(&raw) {
                    Ok(bytes) if bytes.len() == BASE_KEY_LEN => {
                        let mut key = [0u8; BASE_KEY_LEN];
                        key.copy_from_slice(&bytes);
                        key
                    }
                    Ok(bytes) => {
                        tracing::warn!(
                            "XUDP_BASE_KEY: invalid length {}, expected {} bytes",
                            bytes.len(),
                            BASE_KEY_LEN
                        );
                        random_base_key()
                    }
                    Err(e) => {
                        tracing::warn!("XUDP_BASE_KEY: base64 decode failed: {e}");
                        random_base_key()
                    }
                }
            }
            _ => random_base_key(),
        };

        Self { log, base_key }
    }
}

impl Default for XudpConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

// ========== 全局单例 ==========

/// 全局 XUDP 配置实例
static XUDP_CONFIG: OnceLock<XudpConfig> = OnceLock::new();

/// 获取全局 XUDP 配置。
///
/// 首次调用时从环境变量初始化，后续调用返回缓存实例。
#[must_use]
pub fn config() -> &'static XudpConfig {
    XUDP_CONFIG.get_or_init(XudpConfig::from_env)
}

// ========== GlobalID 生成 ==========

/// 生成 XUDP GlobalID 的输入参数。
///
/// 将 Go 版本 GetGlobalID 中从 context 提取的字段扁平化传入，
/// 避免直接依赖 session/context 类型，保持模块解耦。
#[derive(Debug, Clone)]
pub struct GlobalIdInput {
    /// 入站源地址的字符串表示（inbound.Source.String()）
    pub source: String,
    /// 入站源的网络类型
    pub source_network: Network,
    /// 是否为 cone 模式（来自 ctx.Value("cone")）
    pub cone: bool,
}

/// 基于入站源地址生成 8 字节 GlobalID。
///
/// 对应 Go 版本 GetGlobalID。当 cone 为 alse 或源网络不是 UDP 时，
/// 返回全零 GlobalID。
///
/// # 算法
///
/// lake3(source_string, base_key) → 取前 8 字节
///
/// # 参数
///
/// - input: 入站源信息（地址、网络类型、cone 标志）
///
/// # 返回
///
/// 8 字节 GlobalID，条件不满足时为全零
#[must_use]
pub fn global_id(input: &GlobalIdInput) -> [u8; GLOBAL_ID_LEN] {
    let cfg = config();
    compute_global_id(input, &cfg.base_key, cfg.log)
}

/// 使用指定配置计算 GlobalID（内部实现，可测试）。
///
/// 当 `cone` 为 `false` 或源网络不是 UDP 时返回全零。
fn compute_global_id(
    input: &GlobalIdInput,
    base_key: &[u8; BASE_KEY_LEN],
    log: bool,
) -> [u8; GLOBAL_ID_LEN] {
    if !input.cone {
        return [0u8; GLOBAL_ID_LEN];
    }
    if input.source_network != Network::UDP {
        return [0u8; GLOBAL_ID_LEN];
    }

    let mut hasher = Hasher::new_derive_key("xray-xudp-global-id");
    hasher.update(input.source.as_bytes());
    hasher.update(base_key);

    let mut output = [0u8; GLOBAL_ID_LEN];
    output.copy_from_slice(&hasher.finalize().as_bytes()[..GLOBAL_ID_LEN]);

    if log {
        tracing::info!(
            "XUDP inbound.Source.String(): {}\tglobalID: {:?}",
            input.source,
            output
        );
    }

    output
}

// ========== 内部工具函数 ==========

/// 生成随机 32 字节基础密钥
fn random_base_key() -> [u8; BASE_KEY_LEN] {
    let mut key = [0u8; BASE_KEY_LEN];
    rand::rng().fill_bytes(&mut key);
    key
}

/// 解析布尔型环境变量（"1" / "true" / "yes" / "on" → true）
fn parse_env_bool(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(
            v.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

// ========== 测试 ==========

#[cfg(test)]
mod tests {
    use super::*;

    // ---- XudpConfig 测试 ----

    #[test]
    fn test_xudp_config_new() {
        let key = [42u8; BASE_KEY_LEN];
        let cfg = XudpConfig::new(true, key);
        assert!(cfg.log);
        assert_eq!(cfg.base_key, key);
    }

    #[test]
    fn test_xudp_config_new_default_log_false() {
        let key = [0u8; BASE_KEY_LEN];
        let cfg = XudpConfig::new(false, key);
        assert!(!cfg.log);
    }

    #[test]
    fn test_xudp_config_default_from_env_log_false() {
        let cfg = XudpConfig::from_env();
        if std::env::var(ENV_XUDP_LOG).is_err() {
            assert!(!cfg.log, "log should be false when XUDP_LOG is unset");
        }
    }

    #[test]
    fn test_xudp_config_base_key_random_not_zeros() {
        let cfg = XudpConfig::from_env();
        assert!(
            cfg.base_key.iter().any(|&b| b != 0),
            "base_key should not be all zeros when XUDP_BASE_KEY is unset"
        );
    }

    #[test]
    fn test_parse_env_bool_unset() {
        assert!(
            !parse_env_bool("XUDP_TEST_BOOL_UNSET_12345"),
            "unset env should be false"
        );
    }

    #[test]
    fn test_base64_roundtrip() {
        let key: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
            19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let encoded = URL_SAFE_NO_PAD.encode(key);
        let decoded = URL_SAFE_NO_PAD.decode(&encoded).expect("decode");
        assert_eq!(decoded.len(), 32);
        let mut roundtrip = [0u8; 32];
        roundtrip.copy_from_slice(&decoded);
        assert_eq!(roundtrip, key);
    }

    // ---- global_id / compute_global_id 测试 ----

    #[test]
    fn test_global_id_returns_zero_when_cone_false() {
        let input = GlobalIdInput {
            source: "udp:1.2.3.4:1234".to_string(),
            source_network: Network::UDP,
            cone: false,
        };
        let key = [0u8; BASE_KEY_LEN];
        let id = compute_global_id(&input, &key, false);
        assert_eq!(id, [0u8; GLOBAL_ID_LEN], "should be zeros when cone=false");
    }

    #[test]
    fn test_global_id_returns_zero_when_not_udp() {
        let input = GlobalIdInput {
            source: "tcp:1.2.3.4:1234".to_string(),
            source_network: Network::TCP,
            cone: true,
        };
        let key = [0u8; BASE_KEY_LEN];
        let id = compute_global_id(&input, &key, false);
        assert_eq!(
            id, [0u8; GLOBAL_ID_LEN],
            "should be zeros when source is not UDP"
        );
    }

    #[test]
    fn test_global_id_returns_nonzero_for_valid_input() {
        let input = GlobalIdInput {
            source: "udp:1.2.3.4:1234".to_string(),
            source_network: Network::UDP,
            cone: true,
        };
        let key = [1u8; BASE_KEY_LEN];
        let id = compute_global_id(&input, &key, false);
        assert_ne!(
            id, [0u8; GLOBAL_ID_LEN],
            "should be non-zero for valid UDP cone input"
        );
    }

    #[test]
    fn test_global_id_consistency() {
        let input = GlobalIdInput {
            source: "udp:10.0.0.1:5678".to_string(),
            source_network: Network::UDP,
            cone: true,
        };
        let key = [7u8; BASE_KEY_LEN];
        let id1 = compute_global_id(&input, &key, false);
        let id2 = compute_global_id(&input, &key, false);
        assert_eq!(id1, id2, "same input should produce same GlobalID");
    }

    #[test]
    fn test_global_id_different_sources() {
        let input_a = GlobalIdInput {
            source: "udp:1.1.1.1:1111".to_string(),
            source_network: Network::UDP,
            cone: true,
        };
        let input_b = GlobalIdInput {
            source: "udp:2.2.2.2:2222".to_string(),
            source_network: Network::UDP,
            cone: true,
        };
        let key = [3u8; BASE_KEY_LEN];
        let id_a = compute_global_id(&input_a, &key, false);
        let id_b = compute_global_id(&input_b, &key, false);
        assert_ne!(
            id_a, id_b,
            "different sources should produce different GlobalIDs"
        );
    }

    #[test]
    fn test_global_id_different_keys() {
        let input = GlobalIdInput {
            source: "udp:1.2.3.4:1234".to_string(),
            source_network: Network::UDP,
            cone: true,
        };
        let key_a = [1u8; BASE_KEY_LEN];
        let key_b = [2u8; BASE_KEY_LEN];
        let id_a = compute_global_id(&input, &key_a, false);
        let id_b = compute_global_id(&input, &key_b, false);
        assert_ne!(
            id_a, id_b,
            "different base_keys should produce different GlobalIDs"
        );
    }

    #[test]
    fn test_global_id_length() {
        let input = GlobalIdInput {
            source: "udp:1.2.3.4:1234".to_string(),
            source_network: Network::UDP,
            cone: true,
        };
        let key = [0u8; BASE_KEY_LEN];
        let id = compute_global_id(&input, &key, false);
        assert_eq!(id.len(), GLOBAL_ID_LEN, "GlobalID should be 8 bytes");
    }

    #[test]
    fn test_global_id_cone_false_ignores_network() {
        let input = GlobalIdInput {
            source: "udp:1.2.3.4:1234".to_string(),
            source_network: Network::UDP,
            cone: false,
        };
        let key = [99u8; BASE_KEY_LEN];
        let id = compute_global_id(&input, &key, false);
        assert_eq!(id, [0u8; GLOBAL_ID_LEN]);
    }

    #[test]
    fn test_global_id_deterministic_with_known_input() {
        let input = GlobalIdInput {
            source: "udp:192.168.1.1:8080".to_string(),
            source_network: Network::UDP,
            cone: true,
        };
        let key = [0xAB; BASE_KEY_LEN];
        let id1 = compute_global_id(&input, &key, false);
        let id2 = compute_global_id(&input, &key, false);
        assert_eq!(id1, id2, "deterministic output for same input+key");
    }
}
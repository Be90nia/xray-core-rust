//! Trojan 账户与配置，对应 Go `proxy/trojan/config.go` + `config.proto`。
//!
//! # 切片1 范围
//!
//! - `MemoryAccount`：运行时账户（password + hex_sha224 key），用于协议头校验
//! - `Account`：用户配置（serde 反序列化用，proto 留给 P7-2 core 整合）
//! - `hex_sha224` / `hex_string`：与 Go 字节级对齐
//!
//! 切片2 待办：proto 生成 + `Build`（→ protobuf） + ServerConfig/ClientConfig/Fallback。

use sha2::{Digest, Sha224};

/// HEX 编码后的 SHA-224 字节数长度（SHA-224 输出 28 字节，hex 后 56 字符）。
pub const HEX_KEY_LEN: usize = 56;

/// MemoryAccount：从 Account 转换得到的运行时账户。
///
/// 对应 Go `proxy/trojan/config.go::MemoryAccount`。
#[derive(Debug, Clone)]
pub struct MemoryAccount {
    /// 用户原始密码。
    pub password: String,
    /// `hex(sha224(password))` 的字节表示（固定 56 字节，作为协议头哈希 key）。
    pub key: [u8; HEX_KEY_LEN],
}

impl MemoryAccount {
    /// 从密码构造：计算 `hex(sha224(password))` 作为 key。
    pub fn new(password: impl Into<String>) -> Self {
        let password = password.into();
        let key = hex_sha224(&password);
        Self { password, key }
    }

    /// 比较两个账户是否相等（按 password 字段），对应 Go `Equals`。
    pub fn equals(&self, other: &Self) -> bool {
        self.password == other.password
    }
}

impl PartialEq for MemoryAccount {
    fn eq(&self, other: &Self) -> bool {
        self.equals(other)
    }
}

impl Eq for MemoryAccount {}

/// Account：用户配置（JSON / YAML 反序列化用），对应 Go proto `Account.password`。
///
/// 切片1 用普通 struct 占位，切片2 切换为 prost 生成类型。
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct Account {
    /// Trojan 用户密码（明文存储，运行时转为 hex_sha224 key）。
    pub password: String,
}

impl Account {
    /// 转为运行时 MemoryAccount，对应 Go `AsAccount`。
    pub fn as_account(&self) -> MemoryAccount {
        MemoryAccount::new(&self.password)
    }
}

/// `hex(sha224(password))` 字节序列（56 字节），对应 Go `hexSha224`。
///
/// Trojan 协议头使用 hex 编码后的 SHA-224 作为用户身份标识。
pub fn hex_sha224(password: &str) -> [u8; HEX_KEY_LEN] {
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();
    // SHA-224 输出 28 字节，hex 后正好 56 字节
    let mut out = [0u8; HEX_KEY_LEN];
    hex::encode_to_slice(digest, &mut out).expect("SHA-224 digest is 28 bytes, hex fits 56");
    out
}

/// 把字节数组转为小写 hex 字符串，对应 Go `hexString`。
///
/// Trojan `Validator` 用此函数把 key 转字符串作为 map 索引。
pub fn hex_string(data: &[u8]) -> String {
    hex::encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_sha224_known_vector() {
        // 跨语言验证：Python `hashlib.sha224(b'password').hexdigest()` =
        // "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        // 与 Go `hex.Encode(sha256.New224().Sum(nil))` 字节级一致。
        let key = hex_sha224("password");
        assert_eq!(key.len(), HEX_KEY_LEN);
        // 完整 56 字节 ASCII 比对（不单查前缀，防止巧合匹配）
        let expected: &[u8; HEX_KEY_LEN] =
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01";
        assert_eq!(&key[..], &expected[..], "hex(sha224) must match Python/Go byte-for-byte");
    }

    #[test]
    fn test_memory_account_eq() {
        let a = MemoryAccount::new("pass1");
        let b = MemoryAccount::new("pass1");
        let c = MemoryAccount::new("pass2");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_account_as_account() {
        let acc = Account {
            password: "secret".into(),
        };
        let mem = acc.as_account();
        assert_eq!(mem.password, "secret");
        assert_eq!(mem.key.len(), HEX_KEY_LEN);
    }

    #[test]
    fn test_hex_string_roundtrip() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        let s = hex_string(&data);
        assert_eq!(s, "deadbeef");
        let decoded = hex::decode(s).unwrap();
        assert_eq!(decoded, data);
    }
}

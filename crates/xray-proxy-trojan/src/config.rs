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

use xray_proto::xray::common::protocol::ServerEndpoint;
use xray_proto::xray::proxy::trojan::{
    Account as ProtoAccount, ClientConfig as ProtoClientConfig,
    ServerConfig as ProtoServerConfig,
};

use crate::error::Result;
use crate::fallback::Fallback;
use crate::validator::MemoryUser;

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

    /// 从 proto `Account` 转换为运行时账户，对应 Go `Account.AsAccount()`
    /// （config.go:21-28：password + `hexSha224` key）。
    #[must_use]
    pub fn from_proto_account(a: &ProtoAccount) -> Self {
        Self::new(&a.password)
    }

    /// 序列化为 proto `Account`，对应 Go `MemoryAccount.ToProto()`（config.go:38-42）。
    #[must_use]
    pub fn to_proto(&self) -> ProtoAccount {
        ProtoAccount { password: self.password.clone() }
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

    /// 从 prost `Account` 构造。
    #[must_use]
    pub fn from_proto(p: ProtoAccount) -> Self {
        Self { password: p.password }
    }

    /// 转换为 prost `Account`。
    #[must_use]
    pub fn to_proto(&self) -> ProtoAccount {
        ProtoAccount { password: self.password.clone() }
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

/// `md5(password)` 原始 16 字节摘要（trojan v2 草案的用户身份标识，对应
/// v1 的 `hex(sha224(password))`——见 `protocol` 模块文档 v2 节）。
#[must_use]
pub fn md5_key(password: &str) -> [u8; 16] {
    use md5::{Digest, Md5};
    Md5::digest(password.as_bytes()).into()
}

/// 把字节数组转为小写 hex 字符串，对应 Go `hexString`。
///
/// Trojan `Validator` 用此函数把 key 转字符串作为 map 索引。
pub fn hex_string(data: &[u8]) -> String {
    hex::encode(data)
}

/// Trojan Account 的 proto 类型 URL（Go `serial.ToTypedMessage` 产物，
/// `type.googleapis.com/` + proto 全名）。
pub const ACCOUNT_TYPE_URL: &str = "type.googleapis.com/xray.proxy.trojan.Account";

/// Trojan 客户端配置（proto 镜像），对应 proto `ClientConfig`。
///
/// Go `client.go:30-34`：`server` 缺失即 `no target server found`；
/// 端点经 `protocol.NewServerSpecFromPB` 转为 ServerSpec。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ClientConfig {
    /// Trojan 服务器端点。
    pub server: Option<ServerEndpoint>,
}

impl ClientConfig {
    /// 从 prost `ClientConfig` 构造。
    #[must_use]
    pub fn from_proto(p: ProtoClientConfig) -> Self {
        Self { server: p.server }
    }

    /// 转换为 prost `ClientConfig`。
    #[must_use]
    pub fn to_proto(&self) -> ProtoClientConfig {
        ProtoClientConfig { server: self.server.clone() }
    }
}

/// Trojan 服务端配置（proto 镜像），对应 proto `ServerConfig`（users + fallbacks）。
///
/// Go `server.go:65-74`：users 各经 `ToMemoryUser` 解码入 Validator，
/// fallbacks 建 3 级决策树（→ [`FallbackPolicy::from_list`]）。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ServerConfig {
    /// 用户列表（账户已解码为运行时 [`MemoryAccount`]）。
    pub users: Vec<MemoryUser>,
    /// Fallback 列表。
    pub fallbacks: Vec<Fallback>,
}

impl ServerConfig {
    /// 从 prost `ServerConfig` 构造（users 账户解码 + fallbacks 全字段）。
    ///
    /// # Errors
    /// 任一 user 的 account 缺失/类型不符/解码失败 →
    /// [`TrojanError::InvalidUserAccount`]（对应 Go `server.go:33-35`
    /// `failed to get hysteria user` 同类路径——`User.ToMemoryUser` 出错即整体失败）。
    pub fn from_proto(p: ProtoServerConfig) -> Result<Self> {
        Ok(Self {
            users: p
                .users
                .iter()
                .map(MemoryUser::from_proto_user)
                .collect::<Result<_>>()?,
            fallbacks: p.fallbacks.into_iter().map(Fallback::from_proto).collect(),
        })
    }

    /// 转换为 prost `ServerConfig`（users 账户重编码为 `TypedMessage`）。
    #[must_use]
    pub fn to_proto(&self) -> ProtoServerConfig {
        ProtoServerConfig {
            users: self.users.iter().map(MemoryUser::to_proto_user).collect(),
            fallbacks: self.fallbacks.iter().map(Fallback::to_proto).collect(),
        }
    }
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

    // ===== from_proto/to_proto（bd v5g：对齐 Go config.go + client.go/server.go 消费面） =====

    fn sample_proto_account() -> ProtoAccount {
        ProtoAccount { password: "test-pass-12345".into() }
    }

    #[test]
    fn account_proto_roundtrip() {
        let a = Account::from_proto(sample_proto_account());
        assert_eq!(a.to_proto(), sample_proto_account());
    }

    #[test]
    fn account_json_proto_equivalence() {
        // Go infra/conf JSON `{"password":...}` → proto Account.password 单字段
        let json = br#"{"password":"test-pass-12345"}"#;
        let from_json: Account = serde_json::from_slice(json).unwrap();
        assert_eq!(from_json.to_proto(), sample_proto_account());
        assert_eq!(Account::from_proto(sample_proto_account()), from_json);
    }

    #[test]
    fn memory_account_from_proto_account_matches_as_account() {
        // Go config.go:21-28 AsAccount：password + hexSha224 key
        let p = sample_proto_account();
        let m = MemoryAccount::from_proto_account(&p);
        assert_eq!(m, Account::from_proto(p.clone()).as_account());
        assert_eq!(m.key, hex_sha224("test-pass-12345"));
        // Go config.go:38-42 ToProto 往返
        assert_eq!(m.to_proto(), sample_proto_account());
    }

    #[test]
    fn client_config_proto_roundtrip() {
        use xray_proto::xray::common::net::IpOrDomain;
        let server = xray_proto::xray::common::protocol::ServerEndpoint {
            address: Some(IpOrDomain {
                address: Some(xray_proto::xray::common::net::ip_or_domain::Address::Domain(
                    "example.com".into(),
                )),
            }),
            port: 443,
            user: None,
        };
        let cfg = ClientConfig { server: Some(server) };
        assert_eq!(ClientConfig::from_proto(cfg.to_proto()), cfg);
        // Go client.go:31-33：server 缺失 = "no target server found"（镜像默认值语义）
        assert_eq!(ClientConfig::default().server, None);
    }

    #[test]
    fn server_config_proto_roundtrip_all_fields() {
        // users：email/level/account(password) 全字段（Go server.go:65-74 ToMemoryUser 路径）
        let user = MemoryUser::new("user@a.com", 3, MemoryAccount::new("pw-1"));
        // fallbacks：proto 6 字段全填（Go infra/conf/trojan.go:159-166）
        let fb = Fallback {
            name: "sni.example.com".into(),
            alpn: "h2".into(),
            path: "/ws".into(),
            r#type: "unix".into(),
            dest: "/tmp/srv.sock".into(),
            xver: 2,
        };
        let cfg = ServerConfig { users: vec![user], fallbacks: vec![fb] };
        let p = cfg.to_proto();
        // 字段映射完整性：逐字段断言（防 to/from 恒等式掩盖丢字段）
        assert_eq!(p.users.len(), 1);
        assert_eq!(p.users[0].email, "user@a.com");
        assert_eq!(p.users[0].level, 3);
        let tm = p.users[0].account.as_ref().unwrap();
        assert_eq!(tm.r#type, ACCOUNT_TYPE_URL);
        assert_eq!(p.fallbacks.len(), 1);
        assert_eq!(p.fallbacks[0].name, "sni.example.com");
        assert_eq!(p.fallbacks[0].alpn, "h2");
        assert_eq!(p.fallbacks[0].path, "/ws");
        assert_eq!(p.fallbacks[0].r#type, "unix");
        assert_eq!(p.fallbacks[0].dest, "/tmp/srv.sock");
        assert_eq!(p.fallbacks[0].xver, 2);
        // 双向 round-trip
        assert_eq!(ServerConfig::from_proto(p).unwrap(), cfg);
    }

    #[test]
    fn server_config_from_proto_rejects_bad_user() {
        use xray_proto::xray::common::protocol::User as ProtoUser;
        // 无 account 的 user：Go ToMemoryUser 报错 → NewServer 整体失败
        let p = ProtoServerConfig {
            users: vec![ProtoUser::default()],
            fallbacks: vec![],
        };
        assert!(ServerConfig::from_proto(p).is_err());

        // account type_url 非 trojan Account：同样拒绝
        let mut u = ProtoUser::default();
        u.account = Some(xray_proto::xray::common::serial::TypedMessage {
            r#type: "type.googleapis.com/xray.proxy.vless.Account".into(),
            value: Vec::new(),
        });
        let p = ProtoServerConfig { users: vec![u], fallbacks: vec![] };
        assert!(ServerConfig::from_proto(p).is_err());
    }
}

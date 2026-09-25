//! VMess validator：用户管理与 AuthID 匹配。
//!
//! 对应 Go 版本 `proxy/vmess/validator.go`。

use std::{collections::HashMap, sync::Mutex};

use crate::{account::MemoryAccount, aead::AuthIDDecoderHolder};

/// 本地 MemoryUser：与 VLESS 同理，不复用 `xray_common::protocol::MemoryUser`
/// （后者 account 字段是 `Option<TypedMessage>`，无法持 `MemoryAccount`）。
#[derive(Debug, Clone)]
pub struct MemoryUser {
    /// 邮箱（用于 RemoveUser 查找）。
    pub email: String,
    /// 等级。
    pub level: u32,
    /// 账户。
    pub account: MemoryAccount,
}

impl MemoryUser {
    /// 创建新用户。
    #[must_use]
    pub fn new(email: impl Into<String>, account: MemoryAccount) -> Self {
        Self { email: email.into(), level: 0, account }
    }

    /// 设置等级（builder 风格）。
    #[must_use]
    pub fn with_level(mut self, level: u32) -> Self {
        self.level = level;
        self
    }
}

/// 用户 Validator trait：抽象不同的实现（对应 Go `protocol.UserValidator`）。
pub trait Validator: Send + Sync {
    /// 添加用户。
    fn add(&self, user: MemoryUser) -> Result<(), crate::error::VmessError>;

    /// 通过 email 移除用户。
    fn remove(&self, email: &str) -> bool;

    /// 通过 16B AuthID hash 查找用户。
    fn get_aead(&self, auth_id_hash: &[u8; 16]) -> Result<MemoryUser, crate::error::VmessError>;

    /// 当前用户数。
    fn count(&self) -> usize;

    /// 行为种子（用于 drainer 反 probing）。
    fn behavior_seed(&self) -> u64;
}

/// 基于时间的用户 Validator（对应 Go `TimedUserValidator`）。
///
/// 内部持 `AuthIDDecoderHolder` + users Map + behaviorSeed。
/// `behaviorSeed` 在第一次 `add` 后基于所有用户 ID 的 HMAC 累积派生，
/// 在 `behavior_seed()` 调用后冻结（fused），新加用户不再影响 seed。
pub struct TimedUserValidator {
    inner: Mutex<TimedUserValidatorInner>,
    holder: AuthIDDecoderHolder,
}

struct TimedUserValidatorInner {
    users: HashMap<[u8; 16], MemoryUser>,
    behavior_seed: u64,
    behavior_fused: bool,
}

impl TimedUserValidator {
    /// 创建空 validator。
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(TimedUserValidatorInner {
                users: HashMap::new(),
                behavior_seed: 0,
                behavior_fused: false,
            }),
            holder: AuthIDDecoderHolder::new(),
        }
    }

    /// 访问内部 holder（用于测试或低层访问）。
    pub fn holder(&self) -> &AuthIDDecoderHolder {
        &self.holder
    }
}

/// Go `crc64.Update(crc, MakeTable(crc64.ECMA), data)` 逐位等价实现。
///
/// 多项式 0xC96C5795D7870F42（反射序，Go crc64.ECMA）。
/// 对拍向量：`crc64_ecma_update(0, b"123456789") == 0x995dc9bbdf1939fa`（Go Checksum 一致）。
fn crc64_ecma_update(crc: u64, data: &[u8]) -> u64 {
    const POLY: u64 = 0xC96C_5795_D787_0F42;
    let mut crc = !crc;
    for &v in data {
        crc ^= u64::from(v);
        for _ in 0..8 {
            crc = if crc & 1 == 1 { (crc >> 1) ^ POLY } else { crc >> 1 };
        }
    }
    !crc
}

impl Default for TimedUserValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl Validator for TimedUserValidator {
    fn add(&self, user: MemoryUser) -> Result<(), crate::error::VmessError> {
        let mut inner = self.inner.lock().expect("inner poisoned");
        let cmd_key = user.account.cmd_key();

        // 更新 behavior_seed（如果未冻结）
        if !inner.behavior_fused {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            type HmacSha256 = Hmac<Sha256>;
            let mut h = HmacSha256::new_from_slice(b"VMESSBSKDF").expect("key len ok");
            h.update(user.account.id.uuid().as_bytes());
            let sum = h.finalize().into_bytes();
            // Go `crc64.Update(seed, MakeTable(ECMA), sum)` 的逐位等价实现
            //（多项式 0xC96C5795D7870F42 反射序，与 Go crc64.ECMA 一致）。
            inner.behavior_seed = crc64_ecma_update(inner.behavior_seed, &sum);
        }

        inner.users.insert(cmd_key, user);
        self.holder.add_user(cmd_key);
        Ok(())
    }

    fn remove(&self, email: &str) -> bool {
        let mut inner = self.inner.lock().expect("inner poisoned");
        let target_email = email.to_lowercase();
        let mut found_key: Option<[u8; 16]> = None;
        for (key, user) in inner.users.iter() {
            if user.email.to_lowercase() == target_email {
                found_key = Some(*key);
                break;
            }
        }
        if let Some(key) = found_key {
            inner.users.remove(&key);
            self.holder.remove_user(&key);
            true
        } else {
            false
        }
    }

    fn get_aead(&self, auth_id_hash: &[u8; 16]) -> Result<MemoryUser, crate::error::VmessError> {
        let cmd_key = self.holder.match_auth_id(auth_id_hash).map_err(|e| match e {
            crate::aead::AuthIDMatchError::NotFound => crate::error::VmessError::UserNotFound,
            crate::aead::AuthIDMatchError::NegativeTime => crate::error::VmessError::NegativeTime,
            crate::aead::AuthIDMatchError::InvalidTime => crate::error::VmessError::InvalidTime,
            crate::aead::AuthIDMatchError::Replay => crate::error::VmessError::Replay,
        })?;
        let inner = self.inner.lock().expect("inner poisoned");
        inner.users.get(&cmd_key).cloned().ok_or(crate::error::VmessError::UserNotFound)
    }

    fn count(&self) -> usize {
        self.inner.lock().expect("inner poisoned").users.len()
    }

    fn behavior_seed(&self) -> u64 {
        let mut inner = self.inner.lock().expect("inner poisoned");
        inner.behavior_fused = true;
        if inner.behavior_seed == 0 {
            use rand::RngCore;
            // ponytail: 用 rand 替代 Go 的 dice.RollUint64
            inner.behavior_seed = rand::rng().next_u64();
        }
        inner.behavior_seed
    }
}

#[cfg(test)]
mod tests {
    use xray_common::uuid::UUID;

    use super::*;

    fn sample_user(email: &str, uuid_suffix: u8) -> MemoryUser {
        let mut uuid_str = String::from("66ad4540-b58c-4ad2-9926-ea63445a9b5");
        uuid_str.push(char::from_digit(u32::from(uuid_suffix), 16).expect("hex"));
        let uuid = UUID::parse(&uuid_str).expect("uuid");
        MemoryUser::new(email, MemoryAccount::new(uuid))
    }

    #[test]
    fn new_validator_is_empty() {
        let v = TimedUserValidator::new();
        assert_eq!(v.count(), 0);
    }

    #[test]
    fn add_user_increases_count() {
        let v = TimedUserValidator::new();
        v.add(sample_user("alice@example.com", 0x7)).expect("add");
        assert_eq!(v.count(), 1);
    }

    #[test]
    fn add_multiple_users() {
        let v = TimedUserValidator::new();
        v.add(sample_user("alice@example.com", 0x7)).expect("add");
        v.add(sample_user("bob@example.com", 0x8)).expect("add");
        assert_eq!(v.count(), 2);
    }

    #[test]
    fn remove_user_by_email_case_insensitive() {
        let v = TimedUserValidator::new();
        v.add(sample_user("alice@example.com", 0x7)).expect("add");
        assert!(v.remove("ALICE@example.com"));
        assert_eq!(v.count(), 0);
    }

    #[test]
    fn remove_unknown_user_returns_false() {
        let v = TimedUserValidator::new();
        assert!(!v.remove("nobody@example.com"));
    }

    #[test]
    fn get_aead_returns_user_for_valid_auth_id() {
        let v = TimedUserValidator::new();
        let user = sample_user("alice@example.com", 0x7);
        let cmd_key = user.account.cmd_key();
        v.add(user).expect("add");

        let auth_id = crate::aead::create_auth_id(&cmd_key, now_unix()).expect("auth");
        let matched = v.get_aead(&auth_id).expect("match");
        assert_eq!(matched.email, "alice@example.com");
    }

    #[test]
    fn get_aead_unknown_returns_not_found() {
        let v = TimedUserValidator::new();
        let err = v.get_aead(&[0u8; 16]).unwrap_err();
        assert!(matches!(err, crate::error::VmessError::UserNotFound));
    }

    #[test]
    fn behavior_seed_returns_nonzero_after_add() {
        let v = TimedUserValidator::new();
        v.add(sample_user("alice@example.com", 0x7)).expect("add");
        let seed = v.behavior_seed();
        // 至少非零（因为 add 后有 hash 累积）
        assert_ne!(seed, 0);
    }

    #[test]
    fn behavior_seed_fused_after_call() {
        let v = TimedUserValidator::new();
        v.add(sample_user("alice@example.com", 0x7)).expect("add");
        let s1 = v.behavior_seed();
        // fused 后再加用户不应影响 seed
        v.add(sample_user("bob@example.com", 0x8)).expect("add");
        let s2 = v.behavior_seed();
        assert_eq!(s1, s2);
    }

    #[test]
    fn get_aead_after_remove_fails() {
        let v = TimedUserValidator::new();
        let user = sample_user("alice@example.com", 0x7);
        let cmd_key = user.account.cmd_key();
        v.add(user).expect("add");
        v.remove("alice@example.com");

        let auth_id = crate::aead::create_auth_id(&cmd_key, now_unix()).expect("auth");
        let err = v.get_aead(&auth_id).unwrap_err();
        // holder 已 remove_user，所以 NotFound（不可能是 Replay 因为 holder 内部状态也清了）
        assert!(matches!(err, crate::error::VmessError::UserNotFound));
    }

    /// Go crc64 对拍：向量由 Go 端 `crc64.Update(0, MakeTable(ECMA), hmac_sha256("VMESSBSKDF",
    /// id[16]byte]))` 生成。
    #[test]
    fn behavior_seed_matches_go_crc64_ecma() {
        // 单 user：b831381d-...-8cda48b30811 → 0xa0c5c7e50d3ae3a3
        let v = TimedUserValidator::new();
        v.add(MemoryUser::new(
            "alice",
            MemoryAccount::new(UUID::parse("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap()),
        ))
        .unwrap();
        assert_eq!(v.behavior_seed(), 0xa0c5_c7e5_0d3a_e3a3);

        // 追加第二个 user 66ad4540-...-ea63445a9b57 → 滚动 update 至 0xfb57f36285b06841
        let v2 = TimedUserValidator::new();
        v2.add(MemoryUser::new(
            "a",
            MemoryAccount::new(UUID::parse("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap()),
        ))
        .unwrap();
        v2.add(MemoryUser::new(
            "b",
            MemoryAccount::new(UUID::parse("66ad4540-b58c-4ad2-9926-ea63445a9b57").unwrap()),
        ))
        .unwrap();
        assert_eq!(v2.behavior_seed(), 0xfb57_f362_85b0_6841);
    }

    fn now_unix() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

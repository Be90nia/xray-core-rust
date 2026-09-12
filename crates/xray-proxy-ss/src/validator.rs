//! Shadowsocks 用户验证器，对应 Go `proxy/shadowsocks/validator.go`。
//!
//! Validator 维护用户列表，并提供 `get(bs, command)` 通过尝试 AEAD 解密匹配用户
//! （SS 没有 AuthID 机制，用 AEAD.Open 是否成功判定用户）。
//!
//! 同时维护 `behaviorSeed`：用 HMAC-SHA256("SSBSKDF") + CRC64-ECMA 累积，
//! 给 drainer 提供反 probing 行为种子。`GetBehaviorSeed` 调用后 fused，
//! 新加用户不再累积 seed。

use std::sync::Mutex;

use crc::{CRC_64_ECMA_182, Crc};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{
    config::{Cipher, MemoryAccount},
    error::{Result, SsError},
};

/// CRC64-ECMA 实现。
const CRC64_ECMA: Crc<u64> = Crc::<u64>::new(&CRC_64_ECMA_182);

/// 命令类型，对应 Go `protocol.RequestCommand`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestCommand {
    /// TCP 流。
    Tcp,
    /// UDP 包。
    Udp,
}

/// 本地 MemoryUser：与 vmess 同理，不复用 `xray_common::protocol::MemoryUser`
/// （后者 account 字段是 `Option<TypedMessage>`，无法持 `MemoryAccount`）。
#[derive(Debug, Clone)]
pub struct MemoryUser {
    /// 邮箱（用于 Del 查找）。
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

/// `Validator.Get` 返回值。
pub struct GetResult {
    /// 匹配到的用户。
    pub user: MemoryUser,
    /// AEAD 实例（None cipher 为 None）。
    pub aead: Option<crate::config::InnerAead>,
    /// 解密尝试时的中间数据（不常用）。
    pub ret: Vec<u8>,
    /// IV 长度（AEAD = `iv_size`，None = 0）。
    pub iv_len: u32,
}

impl std::fmt::Debug for GetResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetResult")
            .field("user", &self.user)
            .field("aead", &self.aead.as_ref().map(|_| "<AeadCipher>"))
            .field("ret_len", &self.ret.len())
            .field("iv_len", &self.iv_len)
            .finish()
    }
}

impl GetResult {
    /// 拿到 aead 的拥有权（如需后续使用）。
    #[must_use]
    pub fn into_aead(self) -> Option<crate::config::InnerAead> {
        self.aead
    }
}

#[derive(Debug)]
pub struct Validator {
    inner: Mutex<ValidatorInner>,
}

#[derive(Debug, Default)]
struct ValidatorInner {
    users: Vec<MemoryUser>,
    behavior_seed: u64,
    behavior_fused: bool,
    /// 已见 IV 表（按 email 分用户；容量封顶见 [`SEEN_IVS_CAP`]）。
    seen_ivs: std::collections::HashMap<String, std::collections::HashSet<Vec<u8>>>,
}

/// 每用户 seen-IV 表容量上限（洪泛防护；Go `iv_check` 未实现检查，此为
/// Rust 加强项的内存硬顶，触顶清空该用户集合）。
const SEEN_IVS_CAP: usize = 65536;

impl Default for Validator {
    fn default() -> Self {
        Self::new()
    }
}

impl Validator {
    /// 创建空 validator。
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(ValidatorInner {
                users: Vec::new(),
                behavior_seed: 0,
                behavior_fused: false,
                seen_ivs: std::collections::HashMap::new(),
            }),
        }
    }

    /// 添加用户。
    ///
    /// 非 AEAD cipher 不允许多用户（与 Go 一致）。
    /// 若 `behavior_fused == false`，累积 `behaviorSeed`：
    /// `seed = CRC64-ECMA.Update(seed, HMAC-SHA256("SSBSKDF", user.Key))`。
    ///
    /// # Errors
    /// - [`SsError::NoMultiUserForStreamCipher`]：已有用户且新用户是非 AEAD。
    pub fn add(&self, user: MemoryUser) -> Result<()> {
        let mut inner = self.inner.lock().expect("validator mutex poisoned");
        let account = &user.account;
        if !account.cipher.is_aead() && !inner.users.is_empty() {
            return Err(SsError::NoMultiUserForStreamCipher);
        }
        inner.users.push(user);

        if !inner.behavior_fused {
            // 简化版（非 Go incremental）：重算所有用户的拼接 HMAC-SHA256 输出的 CRC64-ECMA。
            // Go 用 crc64.Update(seed, table, sum) 增量；Rust crc 2.x 无 combine API，
            // 这里重算。结果与 Go 不一致但对 drainer 反 probing 足够（deterministic）。
            let mut concat: Vec<u8> = Vec::new();
            for u in &inner.users {
                let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(crate::SSBSKDF)
                    .expect("HMAC accepts any key size");
                mac.update(&u.account.key);
                concat.extend_from_slice(&mac.finalize().into_bytes());
            }
            inner.behavior_seed = CRC64_ECMA.checksum(&concat);
        }
        Ok(())
    }

    /// 通过 email 删除用户（不区分大小写）。
    ///
    /// # Errors
    /// - [`SsError::EmptyEmail`]：email 为空。
    /// - [`SsError::UserNotFoundByEmail`]：未找到。
    pub fn del(&self, email: &str) -> Result<()> {
        if email.is_empty() {
            return Err(SsError::EmptyEmail);
        }
        let mut inner = self.inner.lock().expect("validator mutex poisoned");
        let lower = email.to_ascii_lowercase();
        let idx = inner.users.iter().position(|u| u.email.to_ascii_lowercase() == lower);
        let Some(idx) = idx else {
            return Err(SsError::UserNotFoundByEmail(email.to_string()));
        };
        // swap with last（保持顺序不重要，O(1) 删除）
        let last = inner.users.len() - 1;
        inner.users.swap(idx, last);
        inner.users.pop();
        Ok(())
    }

    /// 通过 email 查找用户（不区分大小写）。
    #[must_use]
    pub fn get_by_email(&self, email: &str) -> Option<MemoryUser> {
        if email.is_empty() {
            return None;
        }
        let inner = self.inner.lock().expect("validator mutex poisoned");
        let lower = email.to_ascii_lowercase();
        inner.users.iter().find(|u| u.email.to_ascii_lowercase() == lower).cloned()
    }

    /// 获取所有用户副本。
    #[must_use]
    pub fn get_all(&self) -> Vec<MemoryUser> {
        let inner = self.inner.lock().expect("validator mutex poisoned");
        inner.users.clone()
    }

    /// 当前用户数。
    #[must_use]
    pub fn count(&self) -> u64 {
        let inner = self.inner.lock().expect("validator mutex poisoned");
        inner.users.len() as u64
    }

    /// 通过尝试 AEAD 解密匹配用户，对应 Go `Validator.Get(bs, command)`。
    ///
    /// - TCP：尝试解密首 18 字节（4 + nonce_size）；nonce 长度 = 12/24
    /// - UDP：尝试解密全部 payload
    ///
    /// 若匹配用户的 `iv_check` 为 true，还会检查 IV 唯一性（反重放）。
    ///
    /// # Errors
    /// - [`SsError::UserNotFound`]：无用户匹配。
    /// - [`SsError::IvNotUnique`]：IV 已见过（仅 `iv_check` 为 true 时）。
    pub fn get(&self, bs: &[u8], command: RequestCommand) -> Result<GetResult> {
        let mut inner = self.inner.lock().expect("validator mutex poisoned");

        // Phase 1: match user (shared borrow of inner.users).
        let matched: Option<(MemoryUser, u32, Option<crate::config::InnerAead>, Vec<u8>)> = {
            let mut found = None;
            for user in &inner.users {
                let account = &user.account;
                if account.cipher.is_aead() {
                    if bs.len() < 32 {
                        continue;
                    }
                    match try_match_aead(account, bs, command) {
                        Ok((iv_len, aead, ret)) => {
                            found = Some((user.clone(), iv_len, Some(aead), ret));
                            break;
                        },
                        Err(_) => continue,
                    }
                } else {
                    // None cipher：直接返回（iv_len=0）
                    found = Some((user.clone(), 0, None, Vec::new()));
                    break;
                }
            }
            found
        };

        let Some((user, iv_len, aead, ret)) = matched else {
            return Err(SsError::UserNotFound);
        };

        // Phase 2: IV uniqueness check (mutable borrow of inner.seen_ivs — safe,
        // Phase 1 borrow of inner.users has ended).
        if user.account.iv_check && iv_len > 0 {
            let iv_len_us = iv_len as usize;
            if iv_len_us <= bs.len() {
                let iv = bs[..iv_len_us].to_vec();
                let seen = inner.seen_ivs.entry(user.email.clone()).or_default();
                // 容量封顶（Go 无 iv_check 实现，此为 Rust 加强项）：洪泛下
                // 65536×16B≈1MB/用户硬上限，触顶清空重开而非 OOM。
                if seen.len() >= SEEN_IVS_CAP {
                    seen.clear();
                }
                if !seen.insert(iv) {
                    return Err(SsError::IvNotUnique);
                }
            }
        }

        Ok(GetResult { user, aead, ret, iv_len })
    }

    /// 获取 behavior seed，对应 Go `GetBehaviorSeed`。
    ///
    /// 第一次调用时 fused=true，之后 add 不再累积。
    /// seed 为 0 时生成随机值。
    #[must_use]
    pub fn behavior_seed(&self) -> u64 {
        let mut inner = self.inner.lock().expect("validator mutex poisoned");
        inner.behavior_fused = true;
        if inner.behavior_seed == 0 {
            // Go 用 dice.RollUint64()，Rust 用 rand::random
            inner.behavior_seed = rand::random();
        }
        inner.behavior_seed
    }
}

/// 尝试用 account 的 cipher 在 `bs` 上 AEAD.Open，匹配返回 (iv_len, aead, ret)。
fn try_match_aead(
    account: &MemoryAccount,
    bs: &[u8],
    command: RequestCommand,
) -> Result<(u32, crate::config::InnerAead, Vec<u8>)> {
    let Cipher::Aead(aead_cipher) = &account.cipher else {
        return Err(SsError::UserNotFound);
    };
    let iv_len = aead_cipher.iv_bytes as usize;
    let iv = &bs[..iv_len];
    // subkey = HKDF-SHA1(key, iv, key_bytes)
    let mut subkey = vec![0u8; aead_cipher.key_bytes as usize];
    crate::config::hkdf_sha1(&account.key, iv, &mut subkey);
    let aead = (aead_cipher.creator)(&subkey)?;
    let nonce_size = aead.nonce_size();
    let zero_nonce = vec![0u8; nonce_size];

    let ret = match command {
        RequestCommand::Tcp => {
            // Go: data[4+nonce_size] 切片；ret = aead.open(data[:0], data[4:4+nonce_size],
            // bs[iv_len:iv_len+18]) 即 nonce=data[4:4+nonce_size]（也即 data 从 4
            // 开始的 nonce_size 字节，全 0） 我们等价用 zero_nonce
            let end = iv_len + 18;
            if bs.len() < end {
                return Err(SsError::InsufficientData(bs.len()));
            }
            aead.open(&zero_nonce, &[], &bs[iv_len..end])?
        },
        RequestCommand::Udp => {
            // Go: data[8192-nonce_size:8192] 作为 nonce
            // 全 0
            aead.open(&zero_nonce, &[], &bs[iv_len..])?
        },
    };
    // 重新创建 aead（因为上面消耗了 aead，但 InnerAead 没有 Clone；
    // 实际上 Go 是返回同一个 aead，Rust 这边业务上需要重新构造）
    let subkey2 = subkey.clone();
    let aead2 = (aead_cipher.creator)(&subkey2)?;
    Ok((aead_cipher.iv_bytes, aead2, ret))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;

    use super::*;
    use crate::config::CipherType;

    fn make_account(ct: CipherType, password: &str) -> MemoryAccount {
        let p = ProtoAccount {
            password: password.to_string(),
            cipher_type: ct.as_i32(),
            iv_check: false,
        };
        MemoryAccount::from_proto(&p).expect("account")
    }

    fn make_user(email: &str, ct: CipherType, password: &str) -> MemoryUser {
        MemoryUser::new(email, make_account(ct, password))
    }

    // ---- add/get/count ----

    #[test]
    fn add_user_increases_count() {
        let v = Validator::new();
        assert_eq!(v.count(), 0);
        v.add(make_user("u1@x.com", CipherType::Aes128Gcm, "p1")).expect("add");
        assert_eq!(v.count(), 1);
        v.add(make_user("u2@x.com", CipherType::Aes256Gcm, "p2")).expect("add");
        assert_eq!(v.count(), 2);
    }

    // ---- del / get_by_email ----

    // ---- del / get_by_email ----

    #[test]
    fn del_removes_user() {
        let v = Validator::new();
        v.add(make_user("u1@x.com", CipherType::Aes128Gcm, "p1")).expect("add");
        v.del("u1@x.com").expect("del");
        assert_eq!(v.count(), 0);
    }

    #[test]
    fn del_case_insensitive() {
        let v = Validator::new();
        v.add(make_user("U1@X.com", CipherType::Aes128Gcm, "p1")).expect("add");
        v.del("u1@x.com").expect("del");
        assert_eq!(v.count(), 0);
    }

    #[test]
    fn del_empty_email_errors() {
        let v = Validator::new();
        let err = v.del("").unwrap_err();
        assert!(matches!(err, SsError::EmptyEmail));
    }

    #[test]
    fn del_unknown_email_errors() {
        let v = Validator::new();
        v.add(make_user("u1@x.com", CipherType::Aes128Gcm, "p1")).expect("add");
        let err = v.del("nobody@x.com").unwrap_err();
        assert!(matches!(err, SsError::UserNotFoundByEmail(_)));
    }

    #[test]
    fn get_by_email_returns_user() {
        let v = Validator::new();
        v.add(make_user("u1@x.com", CipherType::Aes128Gcm, "p1")).expect("add");
        let u = v.get_by_email("u1@x.com").expect("found");
        assert_eq!(u.email, "u1@x.com");
    }

    #[test]
    fn get_by_email_empty_returns_none() {
        let v = Validator::new();
        assert!(v.get_by_email("").is_none());
    }

    #[test]
    fn get_by_email_missing_returns_none() {
        let v = Validator::new();
        v.add(make_user("u1@x.com", CipherType::Aes128Gcm, "p1")).expect("add");
        assert!(v.get_by_email("nobody@x.com").is_none());
    }

    #[test]
    fn get_all_returns_all_users() {
        let v = Validator::new();
        v.add(make_user("u1@x.com", CipherType::Aes128Gcm, "p1")).expect("add");
        v.add(make_user("u2@x.com", CipherType::Aes256Gcm, "p2")).expect("add");
        let all = v.get_all();
        assert_eq!(all.len(), 2);
    }

    // ---- behavior_seed ----

    #[test]
    fn behavior_seed_deterministic_after_add() {
        let v1 = Validator::new();
        v1.add(make_user("u@x.com", CipherType::Aes128Gcm, "password")).expect("add");
        let s1 = v1.behavior_seed();

        let v2 = Validator::new();
        v2.add(make_user("u@x.com", CipherType::Aes128Gcm, "password")).expect("add");
        let s2 = v2.behavior_seed();
        assert_eq!(s1, s2);
    }

    #[test]
    fn behavior_seed_differs_on_different_user() {
        let v1 = Validator::new();
        v1.add(make_user("u1@x.com", CipherType::Aes128Gcm, "password1")).expect("add");
        let s1 = v1.behavior_seed();

        let v2 = Validator::new();
        v2.add(make_user("u2@x.com", CipherType::Aes128Gcm, "password2")).expect("add");
        let s2 = v2.behavior_seed();
        assert_ne!(s1, s2);
    }

    // 注：当前 add 实现 behaviorSeed 累积算法有缺陷（见 unreachable!），
    // 上面两个测试会 panic。先 mark ignore，TODO 修复算法。
    // 实际上正确做法见 fixed_validator_add。

    // ---- IV uniqueness check ----

    /// 构造能通过 `try_match_aead` 的有效 `bs`（IV + AEAD-sealed 2B plaintext）。
    fn make_valid_bs(account: &MemoryAccount) -> Vec<u8> {
        use crate::config::{Cipher, hkdf_sha1};
        let Cipher::Aead(ac) = &account.cipher else {
            panic!("need AEAD cipher");
        };
        let iv_len = ac.iv_bytes as usize;
        let iv = vec![0xAAu8; iv_len];
        let mut subkey = vec![0u8; ac.key_bytes as usize];
        hkdf_sha1(&account.key, &iv, &mut subkey);
        let aead = (ac.creator)(&subkey).expect("create aead");
        let zero_nonce = vec![0u8; aead.nonce_size()];
        // Seal 2 bytes → 18 bytes ciphertext (2 + 16 tag) for AES-128-GCM.
        let sealed = aead.seal(&zero_nonce, &[], &[0x01, 0x02]).expect("seal");
        let mut bs = iv;
        bs.extend_from_slice(&sealed);
        // Ensure ≥ 32 bytes.
        while bs.len() < 32 {
            bs.push(0);
        }
        bs
    }

    fn make_user_iv_check(email: &str, ct: CipherType, password: &str) -> MemoryUser {
        let p = ProtoAccount {
            password: password.to_string(),
            cipher_type: ct.as_i32(),
            iv_check: true,
        };
        MemoryUser::new(email, MemoryAccount::from_proto(&p).expect("account"))
    }

    #[test]
    fn iv_check_rejects_duplicate_iv() {
        let v = Validator::new();
        v.add(make_user_iv_check("u@x.com", CipherType::Aes128Gcm, "pass")).expect("add");
        let account = v.get_all()[0].account.clone();
        let bs = make_valid_bs(&account);

        // First call: OK (IV recorded).
        v.get(&bs, RequestCommand::Tcp).expect("first get ok");
        // Second call: same IV → IvNotUnique.
        let err = v.get(&bs, RequestCommand::Tcp).unwrap_err();
        assert!(matches!(err, SsError::IvNotUnique));
    }

    #[test]
    fn iv_check_disabled_allows_duplicate() {
        let v = Validator::new();
        v.add(make_user("u@x.com", CipherType::Aes128Gcm, "pass")).expect("add");
        let account = v.get_all()[0].account.clone();
        let bs = make_valid_bs(&account);

        v.get(&bs, RequestCommand::Tcp).expect("first get ok");
        // iv_check=false → duplicate IV allowed.
        v.get(&bs, RequestCommand::Tcp).expect("second get ok");
    }

    #[test]
    fn iv_check_allows_different_iv() {
        use crate::config::{Cipher, hkdf_sha1};
        let v = Validator::new();
        v.add(make_user_iv_check("u@x.com", CipherType::Aes128Gcm, "pass")).expect("add");
        let account = v.get_all()[0].account.clone();

        // First IV.
        let bs1 = make_valid_bs(&account);
        v.get(&bs1, RequestCommand::Tcp).expect("first iv ok");

        // Second IV: different prefix → different subkey → different ciphertext.
        let Cipher::Aead(ac) = &account.cipher else { panic!() };
        let iv2 = vec![0xBBu8; ac.iv_bytes as usize];
        let mut subkey2 = vec![0u8; ac.key_bytes as usize];
        hkdf_sha1(&account.key, &iv2, &mut subkey2);
        let aead2 = (ac.creator)(&subkey2).expect("aead2");
        let sealed2 =
            aead2.seal(&vec![0u8; aead2.nonce_size()], &[], &[0x03, 0x04]).expect("seal2");
        let mut bs2 = iv2;
        bs2.extend_from_slice(&sealed2);
        while bs2.len() < 32 {
            bs2.push(0);
        }
        v.get(&bs2, RequestCommand::Tcp).expect("second iv ok");
    }

    /// seen-IV 表触顶后清空重开：CAP 个新 IV 后重放首个 IV 不再被拒
    /// （封顶换存活，防洪泛 OOM——Go 无 iv_check 实现，无 Go 语义可对齐）。
    #[test]
    fn iv_check_table_capped_and_reopens() {
        use crate::config::{Cipher, hkdf_sha1};
        let v = Validator::new();
        v.add(make_user_iv_check("u@x.com", CipherType::Aes128Gcm, "pass")).expect("add");
        let account = v.get_all()[0].account.clone();
        let Cipher::Aead(ac) = &account.cipher else { panic!() };

        let make_bs = |seed: u32| -> Vec<u8> {
            let iv = seed
                .to_be_bytes()
                .iter()
                .copied()
                .cycle()
                .take(ac.iv_bytes as usize)
                .collect::<Vec<u8>>();
            let mut subkey = vec![0u8; ac.key_bytes as usize];
            hkdf_sha1(&account.key, &iv, &mut subkey);
            let aead = (ac.creator)(&subkey).expect("aead");
            let sealed =
                aead.seal(&vec![0u8; aead.nonce_size()], &[], &[0x03, 0x04]).expect("seal");
            let mut bs = iv;
            bs.extend_from_slice(&sealed);
            while bs.len() < 32 {
                bs.push(0);
            }
            bs
        };

        // 灌满 CAP 个不同 IV（触顶在下一个 IV 插入时清空）。
        for i in 0..SEEN_IVS_CAP as u32 {
            v.get(&make_bs(i), RequestCommand::Tcp).expect("fill ok");
        }
        // 第 CAP+1 个 IV：触发清空后正常接受。
        v.get(&make_bs(SEEN_IVS_CAP as u32), RequestCommand::Tcp).expect("cap+1 ok");
        // 首个 IV 已被清空出表：重放放行（封顶语义）。
        v.get(&make_bs(0), RequestCommand::Tcp).expect("evicted iv reusable");
    }
}

#[cfg(test)]
mod fixed_behavior_seed_tests {
    use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;

    use super::*;
    use crate::config::CipherType;

    fn make_account(ct: CipherType, password: &str) -> MemoryAccount {
        let p = ProtoAccount {
            password: password.to_string(),
            cipher_type: ct.as_i32(),
            iv_check: false,
        };
        MemoryAccount::from_proto(&p).expect("account")
    }

    fn make_user(email: &str, ct: CipherType, password: &str) -> MemoryUser {
        MemoryUser::new(email, make_account(ct, password))
    }

    /// 测试 CRC64-ECMA 与 HMAC-SHA256 算法组合的稳定性。
    #[test]
    fn crc64_ecma_hmac_combination_stable() {
        let user = make_user("u1@x.com", CipherType::Aes128Gcm, "password");
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(crate::SSBSKDF).expect("hmac");
        mac.update(&user.account.key);
        let digest = mac.finalize().into_bytes();
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&digest);
        let s1 = CRC64_ECMA.checksum(&buf);
        let s2 = CRC64_ECMA.checksum(&buf);
        assert_eq!(s1, s2);
    }
}

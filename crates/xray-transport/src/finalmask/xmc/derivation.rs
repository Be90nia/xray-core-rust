//! # RSA 私钥确定性派生（对应 Go `xmc/derivation.go`）
//!
//! 给定相同 password，每次运行得到相同 RSA-1024 私钥。
//! 算法：
//! 1. 用 SHA256(password || "-{counter}") 串联成确定性字节流
//! 2. 生成 512-bit 候选 p（高位 |= 0xc0 保证 p*q 是 1024-bit，末位 |= 0x01 保证奇数）
//! 3. 从候选递增 2 找下一个素数（Miller-Rabin 20 轮）+ gcd(p-1, e)==1
//! 4. 同样方式生成 q（如 q==p 则继续递增）
//! 5. 通过 [`RsaPrivateKey::from_p_q`] 构造完整私钥（自动算 d, n, CRT）

use num_integer::Integer;
use num_traits::One;
use ring::digest::{Context, SHA256};
use rsa::{BigUint, RsaPrivateKey};

/// RSA 公开指数（标准 F4）。
const E: u64 = 65537;
/// Miller-Rabin 测试轮数（与 Go `ProbablyPrime(20)` 一致）。
const MR_ROUNDS: u32 = 20;
/// 素数候选字节数（512 bit，p*q = 1024 bit）。
const PRIME_BYTES: usize = 64;

/// SHA256-based 确定性字节流（对应 Go `sha256Stream`）。
struct Sha256Stream {
    seed: Vec<u8>,
    counter: u64,
    buf: Vec<u8>,
}

impl Sha256Stream {
    fn new(seed: Vec<u8>) -> Self {
        Self {
            seed,
            counter: 0,
            buf: Vec::new(),
        }
    }

    /// 取出恰好 `n` 字节；不足则按 SHA256 计数器扩展。
    fn fill(&mut self, n: usize) -> Vec<u8> {
        while self.buf.len() < n {
            let mut h = Context::new(&SHA256);
            h.update(&self.seed);
            // Go 用 fmt.Sprintf("-%d", counter)，等价于 ASCII `-` + 数字
            h.update(format!("-{}", self.counter).as_bytes());
            self.buf.extend_from_slice(h.finish().as_ref());
            self.counter += 1;
        }
        self.buf.drain(..n).collect()
    }
}

/// Miller-Rabin 素数测试（确定性 witness 来自 SHA256，与 Go 随机 20 轮等价强度）。
fn is_probable_prime(n: &BigUint) -> bool {
    let two = BigUint::from(2u32);
    let three = BigUint::from(3u32);
    if n == &two || n == &three {
        return true;
    }
    if n.is_multiple_of(&two) {
        return false;
    }

    // n-1 = 2^r * d
    let one = BigUint::one();
    let n_minus_1 = n - &one;
    let mut d = n_minus_1.clone();
    let mut r = 0u32;
    while d.is_multiple_of(&two) {
        d /= &two;
        r += 1;
    }

    let n_bytes = n.to_bytes_be();
    for round in 0..MR_ROUNDS {
        // witness a ∈ [2, n-2]
        let a = deterministic_witness(&n_bytes, round, n);
        if a < two || a >= n_minus_1 {
            continue;
        }
        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_1 {
            continue;
        }
        let mut composite = true;
        for _ in 0..(r - 1) {
            x = (&x * &x) % n;
            if x == n_minus_1 {
                composite = false;
                break;
            }
        }
        if composite {
            return false;
        }
    }
    true
}

/// 基于 SHA256(n || round) 派生确定性 witness ∈ [0, n)。
fn deterministic_witness(n_bytes: &[u8], round: u32, n: &BigUint) -> BigUint {
    let mut h = Context::new(&SHA256);
    h.update(n_bytes);
    h.update(&round.to_be_bytes());
    let digest = h.finish();
    BigUint::from_bytes_be(digest.as_ref()) % n
}

/// 从确定性字节流生成一个素数（对应 Go `derivePrime`）。
fn derive_prime(stream: &mut Sha256Stream) -> BigUint {
    let mut p_bytes = stream.fill(PRIME_BYTES);
    p_bytes[0] |= 0xc0;
    p_bytes[PRIME_BYTES - 1] |= 0x01;

    let mut p = BigUint::from_bytes_be(&p_bytes);
    let two = BigUint::from(2u32);
    let e_big = BigUint::from(E);
    loop {
        if is_probable_prime(&p) {
            let p_minus_1 = &p - BigUint::one();
            if (&p_minus_1).gcd(&e_big).is_one() {
                return p;
            }
        }
        p += &two;
    }
}

/// 从 password 确定性派生 1024-bit RSA 私钥。
///
/// # Errors
/// 在内部构造失败（理论不应发生）时返回错误。
pub fn derive_rsa_key(password: &str) -> Result<RsaPrivateKey, &'static str> {
    let seed = password.as_bytes().to_vec();
    let p_seed: Vec<u8> = seed
        .iter()
        .copied()
        .chain(b"-p-prime".iter().copied())
        .collect();
    let q_seed: Vec<u8> = seed
        .iter()
        .copied()
        .chain(b"-q-prime".iter().copied())
        .collect();

    let mut p_stream = Sha256Stream::new(p_seed);
    let mut q_stream = Sha256Stream::new(q_seed);

    let p = derive_prime(&mut p_stream);
    let mut q = derive_prime(&mut q_stream);

    // ensure p != q
    let two = BigUint::from(2u32);
    let e_big = BigUint::from(E);
    while p == q {
        q += &two;
        while !(is_probable_prime(&q) && (&q - BigUint::one()).gcd(&e_big).is_one()) {
            q += &two;
        }
    }

    RsaPrivateKey::from_p_q(p, q, e_big).map_err(|_| "rsa from_p_q failed")
}

#[cfg(test)]
mod tests {
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    use super::*;

    /// 同 password 必须派生出相同私钥。
    #[test]
    fn deterministic_derivation() {
        let pw = "test-password-12345";
        let key1 = derive_rsa_key(pw).expect("derive 1");
        let key2 = derive_rsa_key(pw).expect("derive 2");
        assert_eq!(key1.n(), key2.n(), "modulus must match");
        assert_eq!(key1.d(), key2.d(), "private exponent must match");
    }

    /// 不同 password 必须派生出不同私钥。
    #[test]
    fn different_password_yields_different_keys() {
        let a = derive_rsa_key("password-a").expect("derive a");
        let b = derive_rsa_key("password-b").expect("derive b");
        assert_ne!(a.n(), b.n(), "modulus must differ");
    }

    /// 派生出的 n 必须是 1024 bit。
    #[test]
    fn modulus_is_1024_bit() {
        let key = derive_rsa_key("hello").expect("derive");
        let bits = key.n().bits();
        assert_eq!(bits, 1024, "expected 1024-bit modulus, got {bits}");
    }

    /// 派生出的私钥应能解密自己公钥加密的数据（PKCS1v15 round-trip）。
    #[test]
    fn rsa_encrypt_decrypt_roundtrip() {
        use rsa::pkcs1v15::Pkcs1v15Encrypt;
        use rsa::RsaPublicKey;
        let key = derive_rsa_key("roundtrip-test").expect("derive");
        let public = RsaPublicKey::from(&key);
        let msg = b"xmc derivation roundtrip";
        let ciphertext = public
            .encrypt(&mut rsa::rand_core::OsRng, Pkcs1v15Encrypt, msg)
            .expect("enc");
        let plaintext = key.decrypt(Pkcs1v15Encrypt, &ciphertext).expect("dec");
        assert_eq!(&plaintext, msg);
    }
}

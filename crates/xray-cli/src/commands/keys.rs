//! # 密钥生成子命令
//!
//! 对应 Go `main/commands/all/` 的 `x25519` / `wg` / `mldsa65` / `mlkem768` / `vlessenc`。
//! Go 端 `curve25519.go` 仅提供 `Curve25519Genkey` 实现（x25519 与 wg 共用，差别只在
//! 编码与 `-i` 语义），Rust 端 `xray x25519` 以 clap alias `curve25519` 提供双别名。

use base64::{
    Engine,
    engine::general_purpose::{GeneralPurpose, STANDARD, URL_SAFE_NO_PAD},
};
use clap::Args;

use crate::error::CliError;

// ---------------------------------------------------------------------------
// 参数结构
// ---------------------------------------------------------------------------

/// `xray x25519`（别名 curve25519）- X25519 密钥对（REALITY / VLESS Encryption）。
#[derive(Args, Debug, Clone)]
pub struct X25519Args {
    /// 私钥（base64.RawURLEncoding；--std-encoding 时 StdEncoding）
    #[arg(short = 'i')]
    pub input: Option<String>,

    /// 输入/输出使用 base64.StdEncoding（默认 RawURLEncoding）
    #[arg(long)]
    pub std_encoding: bool,
}

/// `xray wg` - X25519 密钥对（WireGuard，固定 StdEncoding）。
#[derive(Args, Debug, Clone)]
pub struct WgArgs {
    /// 私钥（base64.StdEncoding）
    #[arg(short = 'i')]
    pub input: Option<String>,
}

/// `xray mldsa65` - ML-DSA-65 后量子签名密钥对（REALITY）。
#[derive(Args, Debug, Clone)]
pub struct Mldsa65Args {
    /// 种子（base64.RawURLEncoding，解码后须 32 字节）
    #[arg(short = 'i')]
    pub input: Option<String>,
}

/// `xray mlkem768` - ML-KEM-768 后量子密钥封装密钥对（VLESS Encryption）。
#[derive(Args, Debug, Clone)]
pub struct Mlkem768Args {
    /// 种子（base64.RawURLEncoding，解码后须 64 字节）
    #[arg(short = 'i')]
    pub input: Option<String>,
}

// ---------------------------------------------------------------------------
// 密钥生成核心（对齐 Go genCurve25519 / genMLKEM768 / mldsa65.NewKeyFromSeed）
// ---------------------------------------------------------------------------

/// X25519 密钥对：clamp（https://cr.yp.to/ecdh.html）后基点乘，
/// `hash32 = blake3(public)`。返回 `(私钥, 公钥, hash32)`。
#[must_use]
pub fn gen_curve25519(input: Option<[u8; 32]>) -> ([u8; 32], [u8; 32], [u8; 32]) {
    use rand::RngCore;
    let mut private = input.unwrap_or_else(|| {
        let mut k = [0u8; 32];
        rand::rng().fill_bytes(&mut k);
        k
    });
    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;

    let secret = x25519_dalek::StaticSecret::from(private);
    let public = x25519_dalek::PublicKey::from(&secret);
    let hash32 = blake3::hash(public.as_bytes());
    (private, *public.as_bytes(), *hash32.as_bytes())
}

/// ML-KEM-768：`from_seed` 派生解封装密钥 → 封装公钥（1184 字节），
/// `hash32 = blake3(ek)`。返回 `(seed, 封装公钥, hash32)`。
#[must_use]
pub fn gen_mlkem768(input: Option<[u8; 64]>) -> ([u8; 64], [u8; 1184], [u8; 32]) {
    use ml_kem::KeyExport;
    use rand::RngCore;
    let seed = input.unwrap_or_else(|| {
        let mut s = [0u8; 64];
        rand::rng().fill_bytes(&mut s);
        s
    });
    let dk = ml_kem::DecapsulationKey768::from_seed(ml_kem::Seed::from(seed));
    let mut client = [0u8; 1184];
    client.copy_from_slice(&dk.encapsulation_key().to_bytes());
    let hash32 = blake3::hash(&client);
    (seed, client, *hash32.as_bytes())
}

/// ML-DSA-65：32 字节种子确定性派生签名密钥，返回验证公钥（1952 字节）。
#[must_use]
pub fn gen_mldsa65(seed: [u8; 32]) -> [u8; 1952] {
    use ml_dsa::{KeyExport, MlDsa65, Seed, SigningKey};
    let sk = SigningKey::<MlDsa65>::from_seed(&Seed::from(seed));
    let mut verify = [0u8; 1952];
    verify.copy_from_slice(sk.as_ref().to_bytes().as_slice());
    verify
}

// ---------------------------------------------------------------------------
// execute（薄层：解码 → 调核心 → 打印，输出格式逐行对齐 Go）
// ---------------------------------------------------------------------------

/// x25519 / curve25519 execute。
pub fn execute_x25519(args: &X25519Args) -> Result<(), CliError> {
    let enc: &GeneralPurpose = if args.std_encoding { &STANDARD } else { &URL_SAFE_NO_PAD };
    curve25519_genkey_print(non_empty(args.input.as_deref()), enc);
    Ok(())
}

/// wg execute（固定 StdEncoding）。
pub fn execute_wg(args: &WgArgs) -> Result<(), CliError> {
    curve25519_genkey_print(non_empty(args.input.as_deref()), &STANDARD);
    Ok(())
}

/// mldsa65 execute。
pub fn execute_mldsa65(args: &Mldsa65Args) -> Result<(), CliError> {
    let Some(seed) = decode_seed::<32>(non_empty(args.input.as_deref()), "ML-DSA-65") else {
        return Ok(());
    };
    let verify = gen_mldsa65(seed);
    println!("Seed: {}", URL_SAFE_NO_PAD.encode(seed));
    println!("Verify: {}", URL_SAFE_NO_PAD.encode(verify));
    Ok(())
}

/// mlkem768 execute。
pub fn execute_mlkem768(args: &Mlkem768Args) -> Result<(), CliError> {
    let Some(seed) = decode_seed::<64>(non_empty(args.input.as_deref()), "ML-KEM-768") else {
        return Ok(());
    };
    let (seed, client, hash32) = gen_mlkem768(Some(seed));
    println!("Seed: {}", URL_SAFE_NO_PAD.encode(seed));
    println!("Client: {}", URL_SAFE_NO_PAD.encode(client));
    println!("Hash32: {}", URL_SAFE_NO_PAD.encode(hash32));
    Ok(())
}

/// vlessenc execute：X25519 对 + ML-KEM-768 对，生成 decryption/encryption 配置。
pub fn execute_vlessenc() -> Result<(), CliError> {
    let (x_private, x_public, _) = gen_curve25519(None);
    let (seed, client, _) = gen_mlkem768(None);
    // Go generateDotConfig("mlkem768x25519plus", "native", "600s"|"0rtt", key)：
    // 四段以 "." join
    let dot = |mode: &str, key: &str| format!("mlkem768x25519plus.native.{mode}.{key}");

    println!(
        "Choose one Authentication to use, do not mix them. Ephemeral key exchange is Post-Quantum safe anyway.\n"
    );
    println!("Authentication: X25519, not Post-Quantum");
    println!("\"decryption\": \"{}\"", dot("600s", &URL_SAFE_NO_PAD.encode(x_private)));
    println!("\"encryption\": \"{}\"", dot("0rtt", &URL_SAFE_NO_PAD.encode(x_public)));
    println!();
    println!("Authentication: ML-KEM-768, Post-Quantum");
    println!("\"decryption\": \"{}\"", dot("600s", &URL_SAFE_NO_PAD.encode(seed)));
    println!("\"encryption\": \"{}\"", dot("0rtt", &URL_SAFE_NO_PAD.encode(client)));
    Ok(())
}

/// 对应 Go `Curve25519Genkey`：按 enc 解码输入（None → 随机）→ 生成 → 打印三行。
/// 解码失败或长度 ≠32 打印 `Invalid length of X25519 private key.`（Go 同款，exit 0）。
fn curve25519_genkey_print(input: Option<&str>, enc: &GeneralPurpose) {
    let input_key = match input {
        None => None,
        Some(s) => match decode_fixed::<32>(enc, s) {
            Some(k) => Some(k),
            None => {
                println!("Invalid length of X25519 private key.");
                return;
            },
        },
    };
    let (private, public, hash32) = gen_curve25519(input_key);
    println!("PrivateKey: {}", enc.encode(private));
    println!("Password (PublicKey): {}", enc.encode(public));
    println!("Hash32: {}", enc.encode(hash32));
}

/// 种子输入：None/空 → 随机 N 字节；解码失败或长度 ≠N → 打印
/// `Invalid length of {name} seed.`（Go 同款）并返回 None。
fn decode_seed<const N: usize>(input: Option<&str>, name: &str) -> Option<[u8; N]> {
    use rand::RngCore;
    match input {
        None => {
            let mut seed = [0u8; N];
            rand::rng().fill_bytes(&mut seed);
            Some(seed)
        },
        Some(s) => match decode_fixed::<N>(&URL_SAFE_NO_PAD, s) {
            Some(seed) => Some(seed),
            None => {
                println!("Invalid length of {name} seed.");
                None
            },
        },
    }
}

/// 解码为定长字节数组（解码失败/长度不符返回 None）。
fn decode_fixed<const N: usize>(enc: &GeneralPurpose, s: &str) -> Option<[u8; N]> {
    let decoded = enc.decode(s).ok()?;
    <[u8; N]>::try_from(decoded).ok()
}

/// 空串视作未提供（Go `len(input) > 0` 语义）。
fn non_empty(input: Option<&str>) -> Option<&str> {
    input.filter(|s| !s.is_empty())
}

// ---------------------------------------------------------------------------
// 测试（Go 黄金值对拍，来源：go run ./main ... 于 Xray-core v26.6.1 基线）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod keys_tests {
    use super::*;

    /// Go 对拍：`xray x25519 -i AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8`
    /// （私钥 0x00..=0x1f，clamp 后末字节 0x1f→0x5f）。
    #[test]
    fn curve25519_matches_go_golden() {
        let input: [u8; 32] = core::array::from_fn(|i| i as u8);
        let (private, public, hash32) = gen_curve25519(Some(input));
        assert_eq!(URL_SAFE_NO_PAD.encode(private), "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHl8");
        assert_eq!(URL_SAFE_NO_PAD.encode(public), "j0DFrbaPJWJK5bIU6nZ6bslNgp09e14a0bpvPiE4KF8");
        assert_eq!(URL_SAFE_NO_PAD.encode(hash32), "wzCTZNjYhKndYN54x2fTYV8lSnpIYocwiNdA50-jmiw");
    }

    /// clamp（RFC 7748）：全 0xFF 输入 → priv[0]=0xF8、priv[31]=0x7F。
    #[test]
    fn curve25519_clamps_bits() {
        let (private, _, _) = gen_curve25519(Some([0xFF; 32]));
        assert_eq!(private[0], 0xF8);
        assert_eq!(private[31], 0x7F);
    }

    /// Go 对拍：`xray mlkem768 -i <0x00..=0x3f>`（crypto/mlkem FIPS 203）。
    #[test]
    fn mlkem768_matches_go_golden() {
        let seed: [u8; 64] = core::array::from_fn(|i| i as u8);
        let (_, client, hash32) = gen_mlkem768(Some(seed));
        assert_eq!(URL_SAFE_NO_PAD.encode(client), GOLDEN_MLKEM768_CLIENT);
        assert_eq!(URL_SAFE_NO_PAD.encode(hash32), "zEsgfXtp_IkVT8_G8LlvmJk5hzORlpvB_i7qA-bziao");
    }

    /// Go 对拍：`xray mldsa65 -i <0x00..=0x1f>`（circl ML-DSA-65 FIPS 204）。
    #[test]
    fn mldsa65_matches_go_golden() {
        let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
        let verify = gen_mldsa65(seed);
        assert_eq!(URL_SAFE_NO_PAD.encode(verify), GOLDEN_MLDSA65_VERIFY);
    }

    /// 确定性：同 seed 同输出。
    #[test]
    fn keygen_deterministic() {
        assert_eq!(gen_mldsa65([7; 32]), gen_mldsa65([7; 32]));
        let (_, c1, h1) = gen_mlkem768(Some([9; 64]));
        let (_, c2, h2) = gen_mlkem768(Some([9; 64]));
        assert_eq!((c1, h1), (c2, h2));
    }

    /// Go 对拍黄金值（完整封装公钥 1184B / 验证公钥 1952B 的 base64）。
    const GOLDEN_MLKEM768_CLIENT: &str = "KYqhDUI8jdoGnQK8WebN8DoJa4s9pMq5uAykoUkHZyzO8exPryNKC8W36dRz8rMTOzsmodF1y2engFkZaZwC92UxuZxfiRgHBLtMpFNcW4lyZ5xmCgfF5RS4cAnIYuuPUVdpXvs_xAqd72uBwcwCokmuTwlK0Nm9NIXBwcaAgFIKfIxjIDLO5zgVTlxRdsB9pWAkd2pDD-durPZlo_e4MhAiFbyC8Qk5yDVXBDNqj6wdgeS7BIWqXXx01rWbvlxelyoNi6xBG1W11VV81oChqPcbTrhrxIyaBQlzGlS9nXKQsnlj5DctybGZz9ysCwGs0opiOVES5MQ2SNYixIyCNNAUQOjMN2ySfyOlr8msBHTGYidOQkUlyFUuzjs_4mUW3pAbx9UVveiVWOYmyVyAuTNC-AEABPOebGyUhxxeNEyrOWbINfmpalmv0xxAKGs4scGnhHC6uUdRiTRFPOhnNqkZ8fWm1RCob1RU_DmAy1x2W9K9X3s2sUENZjXIzrR8TdoNdqKOrJOcccMCSASGbHFiZlhEIWPCwiEX5QrO_OY3iphWUjAqTvDCzgzHFrd5bitrLjd336GsPaJZoxtam1MPjLY4qBpirDAYSauvlacwG9owBokJv9t-Z9vMuzilVRolsaOg9oV0itV1PYiA8AFsYnSGFmOExVcf4jZZADZNA4MR4th12zZmhpMrXsYCQwo2noem71wzh4ZleCW9TAV6zrkj6wk15pBeY7TO1_gIV6dz3WSxUNJmEuqawSBS2yAXvxhDzLSzKBtpDccorfqFwAKBuOPAkoczX4VrT8KJL2mi9XkhraAZFMQJiGYtV3aWYqeGNRubZkk9q3lZTZht4hANZboP9OpYuBU40kpENaJY-sJUBKp_QfZYsThQZeFY3LYBFXMnIPQEWaqsFeQGlTqQrFKZfRzNBwBg78ZdueZTNURn-tVuxxPIbnVAxCOs8mafUvpvSsaIjYce8-hHwCmoqvu5LheySqB5sfQZumF1tEKvsRkJ1KVrcKAzWyhzkhiqfJNI4sPC8-s9FaQeZBfA3ZS_6yFBmzEae7E6GAu-gzIYqaaxdEfMhfIlhZWHpzB3BJrLz9RNDwJUOOFdFTgnDVhuG_gxkqlFnPY8DpcvhSl2eYMezxIVCYUcuDQPbxB7D6Gg79GzaoGJvAhcT1y3hOVT9BuRj4A5fOGVb3hb7jd8qaqL5pmK2jDCa3w9jGtVJUzJYgOyDEKu4KxOHrtAjkmp4_h50KsHhetwJUJdEwWiKZwBXhINFjsOGUlM5XJT0CRtGCdFy4GXq3Q4s8G7eXK-xaMG66NWeFXAFGmf72WuVMdwoNhcGEAM9kKu3GYHd7pLE4UCvVp4EvYh-EpIKWuY3UMitvFYKLio8OAKi6RKU8OosUNXGwdAq9Vn2vHN6cecIEttXiWdF2ajG7vLTmoFz0UCF2swHBwvQSR3UBV7zshegJswpNYNd0fN0PW5mqjIJph1F3k6qoCAoLEkqFWN9yu-N7dfTtu2voIW1sYz-ysigOJRE9hpXkNIHD7rOX6xklBSKbZ6IB6ok8PiyzLai8NC-k3qBXg";
    const GOLDEN_MLDSA65_VERIFY: &str = "SGg9kZeOMes93biwRzSC0riKX2JZSf2PWKVh5pa9TCfQWzjbsu3wHmZO_YG-HqiTaIzmiqLVHFlY-LvG606J7mfSwDIJVNVyEsrHIp_x1urwOSi9UVEfjYjYR3NsfeJzDVl45UEHExYJeIZ3Eb9VOaC_xMNQwr5XK68O4uL7Fsz-oIAo2ZrEmuu3WTfdzhEc2rYv_zzqi6IjPR5W-8XFoecm3mP63SrwFrEZF3-j2XGi2Sdxc_zlW2d0WvC3wh1Zfb65Pmoy80HEmlqL6eglCI0fKqRRVdbIrhU2fk6wA7j994UQcZSXOfn_8JAj6vRRBNKoSkWQbu1GcaRNwo0nmHu1XfaenoVh9hqApyaZUDhl_tm37nKo4XoZxAgUT0spr-9wMcOm2FcWELQsn0ISRaiPGX4WgSsDEVm2W5aH5bPpNMUiWumKebpz0rOZ1zUQ7_rRnlO4RQ8LqPzhAS_ZjSYKdKqqE_riSaAGscNPW6C4gvJjeCIvs28ig8JD8P_rXxu0FKCnDVXj1ApWtsvIiuHwO3sogtmN7qKOFFyd7f2OrxzvLtlKiwUPiWT0bR6g0MKkPg3aYYKtv09u0XW2dCJXhZvyLzpBfs8fnYkxe15TnVh68WueExPgRRT_pkuos_8rgyH4gRyz-wIsj2ROcKS4Ci-_7mBKu3N5CR6o5sXHTfwCg2ZrQMB5OHACggShNr9dqVaOt5jTSQOL2wwR4DRF54R8tQacdc8orGAcd5nZWCEN28siblGv758d5HsHOHPW0_l0Vr7eCFCC50opiyzUj0swkxVfNmyPpgHGr4WN-jLAhJGyopiH-QM1lJpdbtqmeYgqOpXWv22XCiIfS509jL84SvgarJXisylOBHiayDcnpdwEVZ-Wr0HYoFNRb-7uvFJ0brarKBngkQhxDYNfAR-mMGWHKtM01c3_srIxBQfpL8mTrjF9qX9PMJza8PZ-2Z2QIVV2CDhJ-VOyRtf-2z_bZ2eYUKWtQE5kFH-3z09q7d0Fr7S4NJaNH-iAFJYNzl2UIjZSbhKkeNaeX75pcDELMIwGhFAYz8eyq0MKE6axrHuwLMy7PZEawvEQaGE_vgKb_c4Cz1zTiVDtcsg5RO37x1YVr4f4ZMBR88VUVsVBKGOkDAbR2rVivf8FcbjTw5F7vTAIgLul6Zgjm5X6kbfWQW1POYs6280wmD7TWStNnvfUI2_QD1DZiqU6I1rEFycg932WFyZymAz-j_elpwJ4PtwroxsiWQFaES_H9GipwvlGQDkALTDvZ4tMt5i8EWIWv3qafBi6A7e1j9B1FdMRUEnTYUvnoH50QwB1DfHSxYdTOJBZ6vw9eFzN0xwHZIvtwDpcO4rUbQZNWcE9VzdHKfxOKVNi4qUZEgRTBCi8FSKvoo_1_hZV4wTKW8jCetDgxqOd1N8olWwUs4zJNoLO_kArvV6C0pxGTkTrXTe0j8Vo3-DMbo4WuuoF5RNVkPGSlOc-g2ewIW27gVAwud5VkT8IA5xCNRxZ5VFd1a-OCJoV5iXo9t7mOThsRkl9eiYyiHdN5YGn3pYptBtEJBQfl4-4MxII797DxuDeObxXBj89zWxHA3PAiJHqKcvHzG1kg7iIkIOs6GqntRscLP5uKtGNl842-8VupC-ul-anrBFIZEeMNm3x67HnsRqQmFBP1Zdb3x9J3HAAK2PBc5qdJj-61Ac_ap9sK4r0tMMyoQOgz_pd7rLQYso8IV_TYAJr58UWT0pEJO90lIgE1m9GSHcyyCAseVR4ZHtOpx1ifAhgJMyjVKQfCHezjxmzd0rSCVyNpTsGniHHauLSAH4WcZ7UAIDTNPfaUun1pZkEOcrwg6lbgz8CrRCgjBptDyYMAHKFvUovR3A6Wu9GUofSU7GKwiUUMWIQ_1ZoFLEPh6KT1vGZ08OVmZDQwSaLT1DV-fzvu_I3vQwouAGC1mWXQfFPEL-7IbuhKrYgqiOW9WwGhrTqkBeZAiQhay_orXbEqRSO75qGo2Naaqd7wdz7b7pZp339qbdTDcDKhkjI2XNzjgG6uPCLSQXoSqRkG9YCQQzZdSAmXy8jHys14V6y-gTSvZTVp3q68eDhYQEKmQCH9bRuqYiyvAUS_aD6kj2t1sRcUwHQlINnMmW1qy4Q9LpSD2u61WSlw9Xie9sID30g4TKWoxgZVMOcZJyUPr4X31wfeq4Kj-EmxHdYWl1NZIoNAItq9ejNMb5pqSltTz_SXthvIh5Lk_ZfWSmWdTNiS5I1dQwwcHVQtYU20QmnExxaW75KVxVWfBJTSux2YHYe67n64okcd0WJuA5WatVX3e9zZxlrcifqmHDvCd3-x51rkxmmh5tSBddr96ulrPM6-1nRf8VOaDg9a-Wgjptm2lPc3gCLspS4WCvRMs3MSZWf28IeUnIYgMitA1LHnwOkO72ExM39xsUpAF4efNmjSacWijVWm6XeqBiWjVqRRmvW5k4gv2JBcZivxOgcKN137UAoIyOYtS-96GvIT0dbkBZxDOKqvBGga026yQHsFs82XKPy1TgTlIppOg-T55xGyl1abco9KMpQrRi9E_ylUFndmxhfefnEcZak6BshBLxGCgUeAvLoRE8";
}

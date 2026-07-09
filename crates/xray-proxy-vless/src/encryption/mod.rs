//! VLESS XTLS Vision 加密层。
//!
//! 对应 Go 版本 `proxy/vless/encryption/`。该层提供：
//!
//! - 客户端 [`ClientInstance`]：发起加密握手，0-RTT 数据，X25519/ML-KEM-768 + AES-CTR
//! - 服务端 [`ServerInstance`]：解密握手，replay 防护
//! - [`EncryptionConn`] trait：封装后的加密连接（实现 [`tokio::io::AsyncRead`] +
//!   [`tokio::io::AsyncWrite`]）
//!
//! # 当前状态（trait + stub）
//!
//! Go 端实现依赖以下 Rust 生态尚不完整的组件：
//!
//! 1. **`mlkem-768`**：后量子密钥封装（`crypto/mlkem`，Rust 标准/常用 crate 缺失）。
//! 2. **`unsafe.Pointer` 提取 TLS conn 私有字段**：Go 用反射拿 `tls.Conn.input/rawInput`
//!    做 splice copy，Rust 没有等价物（也不应做）。
//! 3. **TLS 1.3 record header 伪装**：需要可注入的 fake-write，依赖完整 transport 链路。
//!
//! 因此本模块仅声明 trait + 数据结构骨架，所有 IO 操作返回
//! [`VlessError::NotImplemented`]。等上层 transport 链路 + Rust 加密 crate 接入后
//! 再注入实现。

use crate::error::{Result, VlessError};

use crate::encryption::xor::CtrXor;
use ml_kem::KeyExport;

// rand_core trait bounds for build_relaychain RNG
use rand_core::{CryptoRng, RngCore};

pub mod aead;

pub mod common_conn;

pub mod client;
pub mod common;
pub mod server;
pub mod xor;

/// XTLS Vision 加密会话包装的连接 trait。
///
/// 实现者承担：
/// - 异步读 / 写（自动加密/解密）
/// - 0-RTT 早期数据
/// - AEAD 自动轮换（Nonce 达到 `MaxNonce` 时重新派生）
///
/// 对应 Go 的 `encryption.CommonConn`。
pub trait EncryptionConn: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {
    /// 关闭连接，刷新内部缓冲。
    fn close(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>>;
}

/// 客户端加密实例（对应 Go `ClientInstance`）。
///
/// 持有 X25519 静态公钥 + ML-KEM-768 封装密钥数组。
/// [`ClientInstance::init`] 解析公钥并算 blake3 hash + relay 长度；
/// [`ClientInstance::handshake`] 与服务端协商会话密钥（阶段 A stub）。
#[derive(Debug, Default)]
pub struct ClientInstance {
    /// 远端公钥数组（每个元素：32B=X25519 pub，1184B=ML-KEM-768 encap key）。
    pub nfs_pkeys: Vec<Vec<u8>>,
    /// 扁平化公钥字节（CTR XOR 用，对应 Go `NfsPKeysBytes`）。
    pub nfs_pkeys_flat: Vec<u8>,
    /// 每个公钥的 blake3 hash（对应 Go `Hash32s`）。
    pub hash32s: Vec<[u8; 32]>,
    /// relay chain 总长度（对应 Go `RelaysLength`）。
    pub relays_length: usize,
    /// XOR 模式（0=off, 1=XOR relays, 2=XorConn）。
    pub xor_mode: u32,
    /// 0-RTT ticket 有效秒数。
    pub seconds: u32,
    /// padding 配置（阶段 A 简化，默认空）。
    pub padding_lens: Vec<common::PaddingTriple>,
    pub padding_gaps: Vec<common::PaddingTriple>,
}

impl ClientInstance {
    /// 创建空实例。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 初始化：解析公钥数组，算 blake3 hash，计算 relay 长度。
    ///
    /// 对应 Go `ClientInstance.Init(nfsPKeysBytes, xorMode, seconds, padding)`：
    /// 每个公钥按长度分类——32B→X25519 pub（relay += 32+32），
    /// 其他→ML-KEM-768 encap key（relay += 1088+32）。末尾 `RelaysLength -= 32`。
    ///
    /// # Errors
    /// padding 配置解析失败（阶段 A 不会，`parse_padding` 始终返回空）返回 [`VlessError`]。
    pub fn init(
        &mut self,
        nfs_pkeys: Vec<Vec<u8>>,
        xor_mode: u32,
        seconds: u32,
        padding: &str,
    ) -> Result<()> {
        self.xor_mode = xor_mode;
        self.seconds = seconds;
        let (padding_lens, padding_gaps) = common::parse_padding(padding)?;
        self.padding_lens = padding_lens;
        self.padding_gaps = padding_gaps;

        self.nfs_pkeys_flat.clear();
        self.hash32s.clear();
        let mut relays: i64 = 0;
        for pk in &nfs_pkeys {
            let hash = blake3::hash(pk);
            self.hash32s.push(*hash.as_bytes());
            self.nfs_pkeys_flat.extend_from_slice(pk);
            if pk.len() == 32 {
                relays += 32 + 32; // X25519 pub(32) + hash32 slot
            } else {
                relays += 1088 + 32; // ML-KEM-768 ct(1088) + hash32 slot
            }
        }
        relays -= 32; // Go: 末尾减（最后一段无下段 hash）
        self.relays_length = relays.max(0) as usize;
        self.nfs_pkeys = nfs_pkeys;
        Ok(())
    }

    /// 构造 relay chain（同步核心，对齐 Go `Handshake` relay 循环）。
    ///
    /// 填充 `client_hello[16..16+relays_length]`，返回最终 `nfs_key`（最后一段协商密钥）。
    ///
    /// # Errors
    /// 公钥长度非法 / `client_hello` 过小 / CTR 初始化失败返回 [`VlessError`]。
    fn build_relay_chain<R>(&self, client_hello: &mut [u8], rng: &mut R) -> Result<[u8; 32]>
    where
        R: CryptoRng + RngCore,
    {
        if client_hello.len() < 16 + self.relays_length {
            return Err(VlessError::Other("client_hello too small for relays".into()));
        }
        if self.nfs_pkeys.is_empty() {
            return Err(VlessError::Other("no nfs_pkeys initialized".into()));
        }

        let iv: [u8; 16] = client_hello[..16].try_into().expect("iv is 16 bytes");
        let mut nfs_key = [0u8; 32];
        let mut last_ctr: Option<CtrXor> = None;
        let mut pos = 16;
        let last_idx = self.nfs_pkeys.len() - 1;

        for (j, pk) in self.nfs_pkeys.iter().enumerate() {
            let index;
            if pk.len() == 32 {
                // X25519
                let peer_pub_bytes: [u8; 32] = pk[..]
                    .try_into()
                    .map_err(|_| VlessError::Other("x25519 pub key not 32 bytes".into()))?;
                let peer_pub = x25519_dalek::PublicKey::from(peer_pub_bytes);
                // 手动生成随机字节→StaticSecret（避开 x25519-dalek 锁定 rand_core 0.6）
                let mut ephemeral_priv = [0u8; 32];
                rng.fill_bytes(&mut ephemeral_priv);
                let ephemeral = x25519_dalek::StaticSecret::from(ephemeral_priv);
                let ephemeral_pub = x25519_dalek::PublicKey::from(&ephemeral);
                let shared = ephemeral.diffie_hellman(&peer_pub);
                client_hello[pos..pos + 32].copy_from_slice(ephemeral_pub.as_bytes());
                nfs_key.copy_from_slice(shared.as_bytes());
                index = 32;
            } else {
                // ML-KEM-768
                let ek_bytes: ml_kem::Key<ml_kem::EncapsulationKey768> =
                    ml_kem::array::Array::try_from(&pk[..])
                        .map_err(|_| VlessError::Other("ml-kem encap key length".into()))?;
                let ek = ml_kem::EncapsulationKey768::new(&ek_bytes)
                    .map_err(|_| VlessError::Other("ml-kem ek parse".into()))?;
                // encapsulate_deterministic(m)：手动 m 避开 ml-kem 锁定 rand_core 0.10
                let mut m = [0u8; 32];
                rng.fill_bytes(&mut m);
                let (ct, ss) = ek.encapsulate_deterministic(&ml_kem::B32::from(m));
                client_hello[pos..pos + 1088].copy_from_slice(&ct[..]);
                nfs_key.copy_from_slice(&ss[..]);
                index = 1088;
            }

            // XorMode>0: NewCTR(NfsPKeysBytes[j], iv) XOR 公钥/密文段
            if self.xor_mode > 0 {
                let mut ctr = CtrXor::new(pk, &iv)?;
                ctr.apply(&mut client_hello[pos..pos + index]);
            }

            // lastCTR: XOR 当前段前32字节（防 relay 替换）
            if let Some(mut ctr) = last_ctr.take() {
                ctr.apply(&mut client_hello[pos..pos + 32]);
            }

            if j == last_idx {
                break;
            }

            // lastCTR = NewCTR(nfsKey, iv)；写下段 hash32（CTR XOR）
            let mut new_ctr = CtrXor::new(&nfs_key, &iv)?;
            new_ctr.xor_into(
                &mut client_hello[pos + index..pos + index + 32],
                &self.hash32s[j + 1],
            );
            last_ctr = Some(new_ctr);
            pos += index + 32;
        }

        Ok(nfs_key)
    }

    /// 构造 pfsKeyExchange 段（同步核心，对齐 Go `Handshake` pfsKeyExchange 构造）。
    ///
    /// 生成客户端临时 ML-KEM-768 + X25519 密钥对，构造 `pfs_public_key`(1216)，
    /// 用 `nfs_aead` 加密写入 `client_hello[offset..offset+1250]`。
    ///
    /// # Errors
    /// `client_hello` 过小 / AEAD 加密失败返回 [`VlessError`]。
    fn build_pfs_key_exchange<R>(
        &self,
        client_hello: &mut [u8],
        offset: usize,
        nfs_aead: &mut crate::encryption::aead::Aead,
        rng: &mut R,
    ) -> Result<PfsKeyExchange>
    where
        R: CryptoRng + RngCore,
    {
        const PFS_LEN: usize = 1250; // 18 + 1184 + 32 + 16

        if client_hello.len() < offset + PFS_LEN {
            return Err(VlessError::Other("client_hello too small for pfsKeyExchange".into()));
        }

        // 客户端临时 ML-KEM-768 密钥对（via from_seed 避开 rand_core 0.10 锁定）
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed);
        let mlkem_dk = ml_kem::DecapsulationKey768::from_seed(ml_kem::Seed::from(seed));
        let mlkem_ek = mlkem_dk.encapsulation_key();

        // 客户端临时 X25519 密钥对
        let mut x25519_priv_bytes = [0u8; 32];
        rng.fill_bytes(&mut x25519_priv_bytes);
        let x25519_priv = x25519_dalek::StaticSecret::from(x25519_priv_bytes);
        let x25519_pub = x25519_dalek::PublicKey::from(&x25519_priv);

        // pfs_public_key = mlkem encap key(1184) + x25519 pub(32) = 1216
        let mlkem_ek_bytes = mlkem_ek.to_bytes();
        let mut pfs_public_key = Vec::with_capacity(1216);
        pfs_public_key.extend_from_slice(&mlkem_ek_bytes);
        pfs_public_key.extend_from_slice(x25519_pub.as_bytes());

        // Seal EncodeLength(PFS_LEN-18=1232) → [offset..offset+18]
        let len_bytes = ((PFS_LEN - 18) as u16).to_be_bytes();
        let mut tmp = Vec::with_capacity(18);
        nfs_aead.seal(&mut tmp, None, &len_bytes, &[])?;
        client_hello[offset..offset + 18].copy_from_slice(&tmp);

        // Seal pfs_public_key(1216) → [offset+18..offset+1250]（1216+16tag=1232）
        let mut tmp2 = Vec::with_capacity(1232);
        nfs_aead.seal(&mut tmp2, None, &pfs_public_key, &[])?;
        client_hello[offset + 18..offset + PFS_LEN].copy_from_slice(&tmp2);

        Ok(PfsKeyExchange { mlkem_dk, x25519_priv, pfs_public_key })
    }

    /// 与服务端 1-RTT 握手（对齐 Go `client.go Handshake`）。
    ///
    /// 完整流程：relay chain → pfsKeyExchange → 发送 clientHello → 读服务端响应 →
    /// 派生 UnitedKey → 构造加密 CommonConn。
    ///
    /// # 阶段 A 限制
    /// - `xor_mode == 2`（XorConn）：未实现
    /// - `seconds > 0`（0-RTT）：未实现
    /// - padding：最小 34 字节（不分段发送）
    ///
    /// # Errors
    /// IO / 解密 / 协议错误返回 [`VlessError`]。
    pub async fn handshake<C>(
        &mut self,
        conn: C,
    ) -> Result<Box<dyn EncryptionConn>>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        use ml_kem::kem::TryDecapsulate;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        if self.nfs_pkeys.is_empty() {
            return Err(VlessError::Other("ClientInstance not initialized".into()));
        }
        if self.xor_mode == 2 {
            return Err(VlessError::NotImplemented(
                "xor_mode==2 (XorConn) 阶段 A 未实现".into(),
            ));
        }
        if self.seconds > 0 {
            return Err(VlessError::NotImplemented(
                "0-RTT (seconds>0) 阶段 A 未实现".into(),
            ));
        }

        let mut conn = conn;
        let mut rng = rand::rng();
        // 阶段 A：假设 AES 硬件支持（x86_64 常见）
        let use_aes = true;

        // 1. 构造 clientHello = iv(16) + relays + pfsKeyExchange(1250) + padding(34)
        let iv_and_relays_len = 16 + self.relays_length;
        const PFS_LEN: usize = 1250;
        const PADDING_LEN: usize = 34;
        let client_hello_len = iv_and_relays_len + PFS_LEN + PADDING_LEN;
        let mut client_hello = vec![0u8; client_hello_len];

        // iv 随机
        rng.fill_bytes(&mut client_hello[..16]);
        let iv: [u8; 16] = client_hello[..16].try_into().expect("iv is 16 bytes");

        // 2. relay chain → nfs_key
        let nfs_key = self.build_relay_chain(&mut client_hello, &mut rng)?;

        // 3. nfs_aead
        let mut nfs_aead = crate::encryption::aead::Aead::new(&iv, &nfs_key, use_aes);

        // 4. pfsKeyExchange
        let pfs = self.build_pfs_key_exchange(
            &mut client_hello,
            iv_and_relays_len,
            &mut nfs_aead,
            &mut rng,
        )?;

        // 5. padding（最小 34：EncodeLength(16) + 空 plaintext tag）
        let pad_offset = iv_and_relays_len + PFS_LEN;
        let pad_len_bytes = ((PADDING_LEN - 18) as u16).to_be_bytes();
        let mut pad_tmp = Vec::with_capacity(18);
        nfs_aead.seal(&mut pad_tmp, None, &pad_len_bytes, &[])?;
        client_hello[pad_offset..pad_offset + 18].copy_from_slice(&pad_tmp);
        let mut pad_tmp2 = Vec::with_capacity(16);
        nfs_aead.seal(&mut pad_tmp2, None, &[], &[])?;
        client_hello[pad_offset + 18..pad_offset + PADDING_LEN].copy_from_slice(&pad_tmp2);

        // 6. 发送 clientHello（阶段 A 不分段）
        conn.write_all(&client_hello).await?;
        conn.flush().await?;

        // 7. 读服务端 encryptedPfsPublicKey(1088+32+16=1136)，nfs_aead.open(MaxNonce)
        let mut encrypted_pfs = vec![0u8; 1088 + 32 + 16];
        conn.read_exact(&mut encrypted_pfs).await?;
        let mut decrypted_pfs = Vec::with_capacity(1120);
        nfs_aead.open(
            &mut decrypted_pfs,
            Some(&crate::encryption::aead::MAX_NONCE),
            &encrypted_pfs,
            &[],
        )?;

        // 8. 派生 pfs_key：mlkem768Key + x25519Key
        let mlkem_ct: ml_kem::Ciphertext<ml_kem::MlKem768> =
            ml_kem::array::Array::try_from(&decrypted_pfs[..1088])
                .map_err(|_| VlessError::Other("ml-kem ct length".into()))?;
        let mlkem768_key = pfs
            .mlkem_dk
            .try_decapsulate(&mlkem_ct)
            .map_err(|_| VlessError::Other("ml-kem decapsulate failed".into()))?;

        let peer_x25519_pub_bytes: [u8; 32] = decrypted_pfs[1088..1120]
            .try_into()
            .map_err(|_| VlessError::Other("peer x25519 pub length".into()))?;
        let peer_x25519_pub = x25519_dalek::PublicKey::from(peer_x25519_pub_bytes);
        let x25519_key = pfs.x25519_priv.diffie_hellman(&peer_x25519_pub);

        // pfs_key = mlkem768_key(32) + x25519_key(32)；united_key = pfs_key + nfs_key
        let mut pfs_key = Vec::with_capacity(64);
        pfs_key.extend_from_slice(&mlkem768_key[..]);
        pfs_key.extend_from_slice(x25519_key.as_bytes());
        let mut united_key = Vec::with_capacity(96);
        united_key.extend_from_slice(&pfs_key);
        united_key.extend_from_slice(&nfs_key);

        // 9. aead / peer_aead（context 对齐 Go：pfs_public_key / decrypted_pfs[..1120]）
        let aead =
            crate::encryption::aead::Aead::new(&pfs.pfs_public_key, &united_key, use_aes);
        let mut peer_aead = crate::encryption::aead::Aead::new(
            &decrypted_pfs[..1120],
            &united_key,
            use_aes,
        );

        // 10. 读 encryptedTicket(32) → seconds
        let mut encrypted_ticket = vec![0u8; 32];
        conn.read_exact(&mut encrypted_ticket).await?;
        let mut ticket_pt = Vec::with_capacity(16);
        peer_aead.open(&mut ticket_pt, None, &encrypted_ticket, &[])?;
        let _seconds = u16::from_be_bytes([ticket_pt[0], ticket_pt[1]]) as u32;

        // 11. 读 encryptedLength(18) → padding length
        let mut encrypted_length = vec![0u8; 18];
        conn.read_exact(&mut encrypted_length).await?;
        let mut length_pt = Vec::with_capacity(2);
        peer_aead.open(&mut length_pt, None, &encrypted_length, &[])?;
        let _peer_padding_len = u16::from_be_bytes([length_pt[0], length_pt[1]]) as usize;

        // 12. 构造 CommonConn（peer_aead nonce 已递增到 ...002，CommonConn 继续）
        let conn_wrapper = crate::encryption::common_conn::CommonConn::new(
            conn,
            aead,
            peer_aead,
            use_aes,
            united_key,
        );
        Ok(Box::new(conn_wrapper))
    }
}

/// `pfsKeyExchange` 构造结果（handshake 保存用于派生 UnitedKey + AEAD context）。
struct PfsKeyExchange {
    /// 客户端临时 ML-KEM-768 解封装密钥（解密服务端 ct → mlkem768Key）。
    mlkem_dk: ml_kem::DecapsulationKey768,
    /// 客户端临时 X25519 私钥（ECDH 服务端 pub → x25519Key）。
    x25519_priv: x25519_dalek::StaticSecret,
    /// 客户端 pfsPublicKey = mlkem encap key(1184) + x25519 pub(32)，用于 AEAD context。
    pfs_public_key: Vec<u8>,
}

/// 服务端加密实例（对应 Go 的 `ServerInstance`）。
#[derive(Debug, Default)]
pub struct ServerInstance {
    /// X25519 私钥。
    pub private_key: Vec<u8>,
    /// ML-KEM-768 解封装密钥。
    pub decap_key: Vec<u8>,
}

impl ServerInstance {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn init(&mut self) -> Result<()> {
        Err(VlessError::NotImplemented(
            "ServerInstance::init requires X25519+ML-KEM-768".into(),
        ))
    }

    pub async fn handshake<C>(
        &mut self,
        _conn: C,
    ) -> Result<Box<dyn EncryptionConn>>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let _ = _conn;
        Err(VlessError::NotImplemented(
            "ServerInstance::handshake requires full encryption stack".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_init_parses_keys_and_relay_length() {
        let mut c = ClientInstance::new();
        // 一个 X25519 pub (32B) + 一个 ML-KEM-768 encap key (1184B)
        let pkeys = vec![vec![0xABu8; 32], vec![0xCDu8; 1184]];
        c.init(pkeys, 1, 300, "").unwrap();
        assert_eq!(c.hash32s.len(), 2);
        // (32+32) + (1088+32) - 32 = 1152
        assert_eq!(c.relays_length, 1152);
        assert_eq!(c.xor_mode, 1);
        assert_eq!(c.seconds, 300);
        assert_eq!(c.nfs_pkeys_flat.len(), 32 + 1184);
    }

    #[tokio::test]
    async fn server_init_not_implemented() {
        let mut s = ServerInstance::new();
        let err = s.init().await.unwrap_err();
        assert!(matches!(err, VlessError::NotImplemented(_)));
    }

    #[test]
    fn client_default_xor_mode_off() {
        let c = ClientInstance::default();
        assert_eq!(c.xor_mode, 0);
    }

    // === build_relay_chain 测试 ===
    use rand_core::RngCore;
    use ml_kem::KeyExport;

    /// 单 X25519 pub：relays_length = (32+32)-32 = 32。验证 ephemeral pub 写入 + nfs_key 非零。
    #[test]
    fn build_relay_chain_single_x25519() {
        let mut c = ClientInstance::new();
        c.init(vec![vec![0xABu8; 32]], 0, 0, "").unwrap();
        assert_eq!(c.relays_length, 32);

        let mut client_hello = vec![0u8; 16 + 32];
        rand::rng().fill_bytes(&mut client_hello[..16]);
        let iv_copy = client_hello[..16].to_vec();

        let mut rng = rand::rng();
        let nfs_key = c.build_relay_chain(&mut client_hello, &mut rng).unwrap();

        // nfs_key 非零（ECDH 结果）
        assert!(nfs_key.iter().any(|&b| b != 0));
        // iv 未被 relay chain 修改
        assert_eq!(&client_hello[..16], &iv_copy[..]);
        // relays[0..32] = ephemeral pub（非零，随机）
        assert!(client_hello[16..48].iter().any(|&b| b != 0));
    }

    /// 双 X25519 pub：relays = (32+32)*2 - 32 = 96。验证多段 + hash32 链 + lastCTR XOR。
    #[test]
    fn build_relay_chain_dual_x25519() {
        let mut c = ClientInstance::new();
        c.init(vec![vec![0x11u8; 32], vec![0x22u8; 32]], 0, 0, "").unwrap();
        assert_eq!(c.relays_length, 96);

        let mut client_hello = vec![0u8; 16 + 96];
        rand::rng().fill_bytes(&mut client_hello[..16]);

        let mut rng = rand::rng();
        let nfs_key = c.build_relay_chain(&mut client_hello, &mut rng).unwrap();

        // 段1[16..48]=ephemeral pub1；hash32[48..80]=hash32s[1] XOR keystream；段2[80..112]=pub2 XOR'd
        assert!(nfs_key.iter().any(|&b| b != 0));
        assert!(client_hello[16..48].iter().any(|&b| b != 0));
        assert!(client_hello[48..80].iter().any(|&b| b != 0)); // hash32 XOR'd（与 hash32s[1] 不同）
        assert!(client_hello[80..112].iter().any(|&b| b != 0)); // pub2 被 lastCTR XOR
    }

    /// X25519 + valid ML-KEM-768 ek：relays = (32+32)+(1088+32)-32 = 1152。验证 ML-KEM 路径。
    #[test]
    fn build_relay_chain_x25519_plus_mlkem() {
        // 生成 valid ML-KEM-768 ek（via from_seed，避开 rand_core 0.10 RNG 依赖）
        let mut seed = [0u8; 64];
        rand::rng().fill_bytes(&mut seed);
        let dk = ml_kem::DecapsulationKey768::from_seed(ml_kem::Seed::from(seed));
        let ek = dk.encapsulation_key();
        let ek_bytes = ek.to_bytes();

        let mut c = ClientInstance::new();
        let pkeys = vec![vec![0xABu8; 32], ek_bytes.to_vec()];
        c.init(pkeys, 0, 0, "").unwrap();
        assert_eq!(c.relays_length, 1152);

        let mut client_hello = vec![0u8; 16 + 1152];
        rand::rng().fill_bytes(&mut client_hello[..16]);

        let mut rng = rand::rng();
        let nfs_key = c.build_relay_chain(&mut client_hello, &mut rng).unwrap();

        // nfs_key 来自 ML-KEM encapsulate shared（最后段）
        assert!(nfs_key.iter().any(|&b| b != 0));
        // 段1 X25519 ephemeral pub [16..48]
        assert!(client_hello[16..48].iter().any(|&b| b != 0));
        // 段2 ML-KEM ciphertext：pos = 16 + (32+32) = 80，ct[80..80+1088]
        assert!(client_hello[80..80 + 1088].iter().any(|&b| b != 0));
    }

    /// build_pfs_key_exchange：验证 seal 结构 + round-trip 解密 + pfs_public_key(1216)。
    #[test]
    fn build_pfs_key_exchange_structure() {
        let mut c = ClientInstance::new();
        c.init(vec![vec![0xABu8; 32]], 0, 0, "").unwrap();

        let mut client_hello = vec![0u8; 16 + 32 + 1250]; // iv + relays + pfsKeyExchange
        rand::rng().fill_bytes(&mut client_hello[..16]);
        let iv: [u8; 16] = client_hello[..16].try_into().unwrap();

        let mut rng = rand::rng();
        // relay chain 拿 nfs_key（不用 nfs_aead，nonce 不递增）
        let nfs_key = c.build_relay_chain(&mut client_hello, &mut rng).unwrap();
        let mut nfs_aead = crate::encryption::aead::Aead::new(&iv, &nfs_key, true);

        let pfs_offset = 16 + 32;
        let pfs = c
            .build_pfs_key_exchange(&mut client_hello, pfs_offset, &mut nfs_aead, &mut rng)
            .unwrap();

        // pfs_public_key = 1216 字节（mlkem encap key 1184 + x25519 pub 32）
        assert_eq!(pfs.pfs_public_key.len(), 1216);
        // pfsKeyExchange 段被写入
        assert!(client_hello[pfs_offset..pfs_offset + 1250].iter().any(|&b| b != 0));

        // round-trip：用重建 nfs_aead（nonce=初始）解密验证结构与 pfs_public_key 一致
        let mut dec_aead = crate::encryption::aead::Aead::new(&iv, &nfs_key, true);
        let mut len_pt = Vec::new();
        dec_aead
            .open(&mut len_pt, None, &client_hello[pfs_offset..pfs_offset + 18], &[])
            .unwrap();
        assert_eq!(len_pt, 1232u16.to_be_bytes());

        let mut pk_pt = Vec::new();
        dec_aead
            .open(
                &mut pk_pt,
                None,
                &client_hello[pfs_offset + 18..pfs_offset + 1250],
                &[],
            )
            .unwrap();
        assert_eq!(pk_pt.len(), 1216);
        assert_eq!(pk_pt, pfs.pfs_public_key);
    }
}

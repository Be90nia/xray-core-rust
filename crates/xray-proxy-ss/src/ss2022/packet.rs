//! SS-2022 UDP 帧编解码（SIP022 UDP）。
//!
//! 对齐 Go `proxy/shadowsocks_2022/packet.go`（v26.9.30 终态，65e853ed+00863626
//! 去 sing 重写后的 `UDPCodec`/`ClientUDPSession`/`ServerUDPSession`）。
//!
//! # 帧格式（AES cipher，支持 n 层 PSK；chacha 见下）
//!
//! client → server（多用户 n 层 PSK，单用户 n=1）：
//! ```text
//! [0:16]             AES-ECB(psk_list[0], sessionId_be8 || packetId_be8)
//! [16:16+(n-1)*16]   EIH[i] = AES-ECB(psk_list[i],
//!                                psk_identity(psk_list[i+1]) XOR (sessionId||packetId))
//! [16+(n-1)*16:]     AEAD(SessionKey(psk_list[n-1], sessionId_be8),
//!                          nonce=(sessionId||packetId)[4..16])
//!                      .seal(type=0 || ts_be8 || padLen_be2 || padding || addr || payload)
//! ```
//!
//! server → client（无 EIH，回包恒 padding=0）：
//! ```text
//! [0:16]   AES-ECB(psk, serverSessionId_be8 || serverPacketId_be8)
//! [16:]    AEAD(SessionKey(psk, serverSessionId_be8),
//!               nonce=(serverSessionId||serverPacketId)[4..16])
//!              .seal(type=1 || ts_be8 || clientSessionId_be8 || padLen_be2 || padding || addr || payload)
//! ```
//!
//! # chacha20-poly1305（SIP022 §4，仅单 PSK）
//!
//! 无 ECB 包头、无 EIH、无 session subkey 派生：24B 随机 nonce 明文前缀 +
//! XChaCha20-Poly1305(finalPSK) 直 seal，sessionId/packetId 在 AEAD 明文头：
//! ```text
//! [0:24]  nonce（明文随机）
//! [24:]   XChaCha20Poly1305(psk).seal(sessionId || packetId || type || ts
//!                                        || [clientSessionId] || padLen || padding || addr || payload)
//! ```
//! 多 PSK + chacha 出站/codec 构造即硬错（Go outbound.go:48-50 /
//! packet.go NewUDPPacketCodec）。
//!
//! 与 TCP EIH 的差异：UDP EIH 用 **raw iPSK** 直接作 ECB 密钥（TCP 用
//! salt 派生的 identity subkey），且明文是与包头头的 XOR。

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use parking_lot::Mutex;
use xray_common::net::address::Address;
use xray_crypto::aead::{AeadCipher, Aes128Gcm, Aes256Gcm, XChaCha20Poly1305Aead};

use crate::{
    error::{Result, SsError},
    protocol::{read_address_port_ss, write_address_port_ss},
    ss2022::key::{CipherKind2022, derive_psk, derive_session_subkey, ecb_block, psk_identity},
};

/// client 帧类型字节。
pub const HEADER_TYPE_CLIENT: u8 = 0;
/// server 帧类型字节。
pub const HEADER_TYPE_SERVER: u8 = 1;
/// 最大 padding 长度（Go `MaxPaddingLength`）。
pub const MAX_PADDING_LENGTH: usize = 900;
/// 时间戳容忍窗口（秒，Go ±30s）。
pub const TIMESTAMP_TOLERANCE_SECS: i64 = 30;

/// 包头长度（sessionId 8B + packetId 8B）。
const PACKET_HEADER_LEN: usize = 16;
/// chacha UDP nonce 长度（XChaCha20-Poly1305，SIP022 §4 / Go PacketNonceSize）。
const UDP_CHACHA_NONCE_SIZE: usize = 24;
/// AEAD 最小明文：type(1) + ts(8) + 2/8 + padLen(2) + addr(7) 。
const MIN_PLAINTEXT: usize = 1 + 8 + 2 + 7;

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// chacha + 多 PSK 硬错（Go outbound.go:48-50 / packet.go NewUDPPacketCodec）。
fn ensure_psk_list_len(kind: CipherKind2022, psk_list: &[Vec<u8>]) -> Result<()> {
    if kind == CipherKind2022::ChaCha20Poly1305 && psk_list.len() > 1 {
        return Err(SsError::Ss2022UnsupportedMethod(
            "multi-key is not supported for chacha20-poly1305".to_string(),
        ));
    }
    Ok(())
}

/// UDP 会话 AEAD（Go `newUDPCodec`/`NewClientSession`/`EnsureServerState`）：
/// AES → `SessionKey(psk, session_salt)` 派生后 AES-GCM；
/// chacha → XChaCha20-Poly1305 以 raw PSK 直作 key（SIP022 §4，24B nonce）。
fn udp_aead(
    kind: CipherKind2022,
    psk: &[u8],
    session_salt: &[u8],
) -> Result<Box<dyn AeadCipher + Send + Sync>> {
    match kind {
        CipherKind2022::Aes128Gcm => {
            let subkey = derive_session_subkey(psk, session_salt, kind);
            Ok(Box::new(Aes128Gcm::new(&subkey)?))
        },
        CipherKind2022::Aes256Gcm => {
            let subkey = derive_session_subkey(psk, session_salt, kind);
            Ok(Box::new(Aes256Gcm::new(&subkey)?))
        },
        CipherKind2022::ChaCha20Poly1305 => Ok(Box::new(XChaCha20Poly1305Aead::new(psk)?)),
    }
}

// ============================================================================
// 重放窗口
// ============================================================================

/// packetId 重放窗口，sing `slidingwindow.go` 同构翻译：
/// `last`（最高已见 counter）+ 128 块 × 64 bit ring，窗口宽 127×64=8128。
///
/// Check 语义：超前（> last）接受；落后窗口（last-counter > 8128）**直接拒绝**
/// （淘汰后旧 id 不可能重新接受，对齐 Go bitmap；此前 BTreeSet 淘汰最小 id
/// 后旧 id 会重新放行，弱于 Go）；窗口内查 bit。
#[derive(Debug)]
pub struct SlidingWindow {
    last: u64,
    ring: [u64; SW_RING_BLOCKS],
}

impl Default for SlidingWindow {
    fn default() -> Self {
        Self { last: 0, ring: [0u64; SW_RING_BLOCKS] }
    }
}

const SW_BLOCK_BIT_LOG: u64 = 6; // 1<<6 == 64 bits
const SW_BLOCK_BITS: u64 = 1 << SW_BLOCK_BIT_LOG; // must be power of 2
const SW_RING_BLOCKS: usize = 1 << 7; // must be power of 2
const SW_BLOCK_MASK: u64 = (SW_RING_BLOCKS - 1) as u64;
const SW_BIT_MASK: u64 = SW_BLOCK_BITS - 1;
const SW_SIZE: u64 = ((SW_RING_BLOCKS - 1) as u64) * SW_BLOCK_BITS;

impl SlidingWindow {
    /// id 未见过（可接受）返回 true（sing `SlidingWindow.Check`）。
    #[must_use]
    pub fn check(&self, counter: u64) -> bool {
        if counter > self.last {
            return true; // ahead of window
        }
        if self.last - counter > SW_SIZE {
            return false; // behind window
        }
        // In window. Check bit.
        let block_index = (counter >> SW_BLOCK_BIT_LOG) & SW_BLOCK_MASK;
        let bit_index = counter & SW_BIT_MASK;
        (self.ring[block_index as usize] >> bit_index) & 1 == 0
    }

    /// 记录 id（sing `SlidingWindow.Add`；超前时推进 last 并清空跳过的块）。
    pub fn add(&mut self, counter: u64) {
        let block_index = counter >> SW_BLOCK_BIT_LOG;
        if counter > self.last {
            let mut last_block_index = self.last >> SW_BLOCK_BIT_LOG;
            let mut diff = block_index - last_block_index;
            if diff > SW_RING_BLOCKS as u64 {
                diff = SW_RING_BLOCKS as u64;
            }
            for _ in 0..diff {
                last_block_index = (last_block_index + 1) & SW_BLOCK_MASK;
                self.ring[last_block_index as usize] = 0;
            }
            self.last = counter;
        }
        let block_index = block_index & SW_BLOCK_MASK;
        let bit_index = counter & SW_BIT_MASK;
        self.ring[block_index as usize] |= 1 << bit_index;
    }
}

// ============================================================================
// 内部：帧明文区解析/构造
// ============================================================================

/// DNS(53) 且 payload 较短时加随机 padding（对齐 Go WritePacket）。
fn padding_len_for(port: u16, payload_len: usize) -> usize {
    if port == 53 && payload_len < MAX_PADDING_LENGTH {
        rand::random::<u32>() as usize % (MAX_PADDING_LENGTH - payload_len) + 1
    } else {
        0
    }
}

/// 构造 client 帧明文区：type || ts || padLen || padding || addr || payload。
fn build_client_plaintext(addr: &Address, port: u16, payload: &[u8]) -> Vec<u8> {
    let pad = padding_len_for(port, payload.len());
    let mut out = Vec::with_capacity(MIN_PLAINTEXT + pad + payload.len() + 4);
    out.push(HEADER_TYPE_CLIENT);
    out.extend_from_slice(&now_unix().to_be_bytes());
    out.extend_from_slice(&(pad as u16).to_be_bytes());
    out.resize(out.len() + pad, 0);
    write_address_port_ss(&mut out, addr, port);
    out.extend_from_slice(payload);
    out
}

/// 构造 server 帧明文区：type || ts || clientSessionId || padLen || padding || addr || payload。
/// Go `EncodeServerPacket` 回包恒 padding=0（两种 cipher 均如此），此处对齐。
fn build_server_plaintext(
    client_session_id: u64,
    addr: &Address,
    port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(MIN_PLAINTEXT + 8 + payload.len() + 4);
    out.push(HEADER_TYPE_SERVER);
    out.extend_from_slice(&now_unix().to_be_bytes());
    out.extend_from_slice(&client_session_id.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    write_address_port_ss(&mut out, addr, port);
    out.extend_from_slice(payload);
    out
}

/// 解析 client 帧明文区（server 侧）：type/ts/pad/addr/payload。
fn parse_client_plaintext(mut plain: &[u8]) -> Result<(Address, u16, Vec<u8>)> {
    if plain.len() < MIN_PLAINTEXT {
        return Err(SsError::InsufficientData(plain.len()));
    }
    let ty = plain[0];
    if ty != HEADER_TYPE_CLIENT {
        return Err(SsError::Ss2022InvalidHeaderType(ty));
    }
    let ts = i64::from_be_bytes(plain[1..9].try_into().unwrap());
    let diff = (now_unix() - ts).abs();
    if diff > TIMESTAMP_TOLERANCE_SECS {
        return Err(SsError::Ss2022TimestampCheck(format!("diff {diff}s")));
    }
    let pad = u16::from_be_bytes(plain[9..11].try_into().unwrap()) as usize;
    plain = &plain[11..];
    if plain.len() < pad {
        return Err(SsError::InsufficientData(plain.len()));
    }
    plain = &plain[pad..];
    let (addr, port, used) = read_address_port_ss(plain)?;
    let payload = plain[used..].to_vec();
    Ok((addr, port, payload))
}

/// 解析 server 帧明文区（client 侧）：type/ts/clientSessionId/pad/addr/payload。
fn parse_server_plaintext(
    mut plain: &[u8],
    expect_client_session_id: u64,
) -> Result<(Address, u16, Vec<u8>)> {
    if plain.len() < MIN_PLAINTEXT + 8 {
        return Err(SsError::InsufficientData(plain.len()));
    }
    let ty = plain[0];
    if ty != HEADER_TYPE_SERVER {
        return Err(SsError::Ss2022InvalidHeaderType(ty));
    }
    let ts = i64::from_be_bytes(plain[1..9].try_into().unwrap());
    let diff = (now_unix() - ts).abs();
    if diff > TIMESTAMP_TOLERANCE_SECS {
        return Err(SsError::Ss2022TimestampCheck(format!("diff {diff}s")));
    }
    let csid = u64::from_be_bytes(plain[9..17].try_into().unwrap());
    if csid != expect_client_session_id {
        return Err(SsError::Ss2022BadClientSessionId);
    }
    let pad = u16::from_be_bytes(plain[17..19].try_into().unwrap()) as usize;
    plain = &plain[19..];
    if plain.len() < pad {
        return Err(SsError::InsufficientData(plain.len()));
    }
    plain = &plain[pad..];
    let (addr, port, used) = read_address_port_ss(plain)?;
    let payload = plain[used..].to_vec();
    Ok((addr, port, payload))
}

// ============================================================================
// Client 侧会话
// ============================================================================

/// SS-2022 UDP client 会话（对齐 Go `udpSession` + `clientPacketConn`）。
///
/// 一个 UDP 出站连接持有一个：随机 sessionId + 递增 packetId +
/// 按 sessionId 派生的 AEAD。服务端回包的 remote session 最多保留
/// 当前 + 上一代两代（Go 语义，server 重绑定后旧会话仍可收尾包）。
pub struct ClientUdpSession2022 {
    kind: CipherKind2022,
    /// PSK 链（单用户 [psk]；多用户 [iPSK, uPSK]）。
    psk_list: Vec<Vec<u8>>,
    session_id: u64,
    packet_id: AtomicU64,
    cipher: Box<dyn AeadCipher + Send + Sync>,
    remote: Mutex<RemoteState>,
}

struct RemoteState {
    remote_session_id: u64,
    remote_cipher: Option<Box<dyn AeadCipher + Send + Sync>>,
    last_remote_session_id: u64,
    last_remote_cipher: Option<Box<dyn AeadCipher + Send + Sync>>,
    /// 上次 last 代收包/轮换的 unix 秒（sing `lastRemoteSeen`，轮换时限基准）。
    last_remote_seen: i64,
    window: SlidingWindow,
    last_window: SlidingWindow,
}

impl ClientUdpSession2022 {
    /// 构造 client 会话。sessionId 随机，首个 packetId = 0（Go `packetId--` 后自增）。
    ///
    /// chacha 仅接受单 PSK（多 PSK 硬错，Go `NewUDPPacketCodec`）；AES 的
    /// session AEAD 从 final PSK + sessionId 派生（chacha 用 raw PSK 直作 key）。
    ///
    /// # Errors
    /// - [`SsError::Ss2022UnsupportedMethod`]：chacha + 多 PSK。
    /// - [`SsError::InvalidPassword`]：PSK 长度不匹配。
    pub fn new(kind: CipherKind2022, psk_list: Vec<Vec<u8>>) -> Result<Self> {
        if psk_list.is_empty() {
            return Err(SsError::Ss2022MissingKey);
        }
        let psk_list: Vec<Vec<u8>> =
            psk_list.into_iter().map(|p| derive_psk(&p, kind)).collect::<Result<Vec<_>>>()?;
        ensure_psk_list_len(kind, &psk_list)?;
        let session_id = rand::random::<u64>();
        let cipher = udp_aead(kind, &psk_list[psk_list.len() - 1], &session_id.to_be_bytes())?;
        Ok(Self {
            kind,
            cipher,
            psk_list,
            session_id,
            packet_id: AtomicU64::new(u64::MAX),
            remote: Mutex::new(RemoteState {
                remote_session_id: 0,
                remote_cipher: None,
                last_remote_session_id: 0,
                last_remote_cipher: None,
                last_remote_seen: 0,
                window: SlidingWindow::default(),
                last_window: SlidingWindow::default(),
            }),
        })
    }

    /// 本会话 sessionId。
    #[must_use]
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// 编码一个 client → server UDP 帧。
    ///
    /// # Errors
    /// - [`SsError::AeadSeal`]：AEAD 加密失败。
    pub fn encode(&self, addr: &Address, port: u16, payload: &[u8]) -> Result<Vec<u8>> {
        // atomic fetch_add 溢出 wrap：u64::MAX + 1 → 0（首包 id=0）
        let packet_id = self.packet_id.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let hdr = pk_header(self.session_id, packet_id);
        let plain = build_client_plaintext(addr, port, payload);

        // chacha（SIP022 §4）：无 ECB 头、无 EIH；24B 随机 nonce 明文前缀 +
        // XChaCha(finalPSK) 直 seal，sessionId/packetId 在 AEAD 明文头
        //（Go EncodePacket chacha 分支）。
        if self.kind == CipherKind2022::ChaCha20Poly1305 {
            let nonce: [u8; UDP_CHACHA_NONCE_SIZE] = rand::random();
            let mut sealed_plain = Vec::with_capacity(PACKET_HEADER_LEN + plain.len());
            sealed_plain.extend_from_slice(&hdr);
            sealed_plain.extend_from_slice(&plain);
            let sealed = self
                .cipher
                .seal(&nonce, b"", &sealed_plain)
                .map_err(|e| SsError::AeadSeal(e.to_string()))?;
            let mut out = Vec::with_capacity(UDP_CHACHA_NONCE_SIZE + sealed.len());
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&sealed);
            return Ok(out);
        }

        let eih_count = self.psk_list.len().saturating_sub(1);
        let sealed = self
            .cipher
            .seal(&hdr[4..16], b"", &plain)
            .map_err(|e| SsError::AeadSeal(e.to_string()))?;
        let mut out = Vec::with_capacity(PACKET_HEADER_LEN + eih_count * 16 + sealed.len());
        // EIH：raw iPSK 直接作 ECB key（与 TCP 的 salt 派生不同）
        for i in 0..eih_count {
            let mut pt = psk_identity(&self.psk_list[i + 1]);
            for (b, h) in pt.iter_mut().zip(hdr.iter()) {
                *b ^= h;
            }
            out.extend_from_slice(&ecb_block(self.kind, &self.psk_list[i], &pt, true)?);
        }
        // AEAD 密文体
        out.extend_from_slice(&sealed);
        // 包头 ECB 加密放最后（nonce 用明文头）
        let enc_hdr = ecb_block(self.kind, &self.psk_list[0], &hdr, true)?;
        let mut frame = enc_hdr.to_vec();
        frame.append(&mut out);
        Ok(frame)
    }

    /// 解码一个 server → client UDP 帧，返回 (来源地址, 端口, payload)。
    ///
    /// 服务端 remote session 最多保留两代（server 重绑定后旧会话仍可收尾包）。
    ///
    /// # Errors
    /// - [`SsError::InsufficientData`]：包过短。
    /// - [`SsError::Ss2022PacketIdNotUnique`]：重放。
    /// - [`SsError::AeadOpen`]：解密失败。
    /// - [`SsError::Ss2022BadClientSessionId`]：clientSessionId 不匹配。
    /// - [`SsError::Ss2022TooManyServerSessions`]：60s 内第二次 server 会话轮换。
    pub fn decode(&self, pkt: &[u8]) -> Result<(Address, u16, Vec<u8>)> {
        if self.kind == CipherKind2022::ChaCha20Poly1305 {
            return self.decode_chacha(pkt);
        }
        if pkt.len() < PACKET_HEADER_LEN + MIN_PLAINTEXT {
            return Err(SsError::InsufficientData(pkt.len()));
        }
        let last = &self.psk_list[self.psk_list.len() - 1];
        let hdr = ecb_block(self.kind, last, pkt[..16].try_into().unwrap(), false)?;
        let session_id = u64::from_be_bytes(hdr[..8].try_into().unwrap());
        let packet_id = u64::from_be_bytes(hdr[8..].try_into().unwrap());

        let mut st = self.remote.lock();
        let slot = route_remote_generation(&mut st, session_id)?;
        if slot == RemoteSlot::New {
            // 新 server session：AES body cipher 从 finalPSK + 新 sessionId 派生
            st.remote_cipher = Some(udp_aead(self.kind, last, &hdr[..8])?);
        }
        decode_server_frame(
            &mut st,
            slot,
            &hdr[4..16],
            packet_id,
            &pkt[PACKET_HEADER_LEN..],
            self.session_id,
        )
    }

    /// chacha 分支：整包一次 XChaCha(finalPSK) 解开，sessionId/packetId 在明文头
    /// （Go `ClientUDPSession.DecodePacket` chacha 分支；两代会话状态机与 AES 共用）。
    fn decode_chacha(&self, pkt: &[u8]) -> Result<(Address, u16, Vec<u8>)> {
        if pkt.len() < UDP_CHACHA_NONCE_SIZE + PACKET_HEADER_LEN + MIN_PLAINTEXT {
            return Err(SsError::InsufficientData(pkt.len()));
        }
        let plain = self
            .cipher
            .open(&pkt[..UDP_CHACHA_NONCE_SIZE], b"", &pkt[UDP_CHACHA_NONCE_SIZE..])
            .map_err(|e| SsError::AeadOpen(e.to_string()))?;
        if plain.len() < PACKET_HEADER_LEN + MIN_PLAINTEXT {
            return Err(SsError::InsufficientData(plain.len()));
        }
        let session_id = u64::from_be_bytes(plain[..8].try_into().unwrap());
        let packet_id = u64::from_be_bytes(plain[8..16].try_into().unwrap());

        let mut st = self.remote.lock();
        let slot = route_remote_generation(&mut st, session_id)?;
        decode_server_frame(
            &mut st,
            slot,
            &[],
            packet_id,
            &plain[PACKET_HEADER_LEN..],
            self.session_id,
        )
    }
}

/// server → client 帧解码收尾：重放窗口 check → 解密（chacha 传空 nonce，明文已
/// 在调用方整包解开）→ 解析 → add（Go DecodePacket 两分支共用次序）。
fn decode_server_frame(
    st: &mut RemoteState,
    slot: RemoteSlot,
    nonce: &[u8],
    packet_id: u64,
    body: &[u8],
    expect_client_session_id: u64,
) -> Result<(Address, u16, Vec<u8>)> {
    {
        let window = slot_window(st, slot);
        if !window.check(packet_id) {
            return Err(SsError::Ss2022PacketIdNotUnique);
        }
    }
    let plain = if nonce.is_empty() {
        body.to_vec()
    } else {
        let cipher = match slot {
            RemoteSlot::Previous => st.last_remote_cipher.as_deref(),
            RemoteSlot::Current | RemoteSlot::New => st.remote_cipher.as_deref(),
        };
        let Some(cipher) = cipher else {
            return Err(SsError::AeadOpen("remote cipher missing".into()));
        };
        cipher.open(nonce, b"", body).map_err(|e| SsError::AeadOpen(e.to_string()))?
    };
    let decoded = parse_server_plaintext(&plain, expect_client_session_id)?;
    slot_window(st, slot).add(packet_id);
    Ok(decoded)
}

fn slot_window(st: &mut RemoteState, slot: RemoteSlot) -> &mut SlidingWindow {
    if slot == RemoteSlot::Previous { &mut st.last_window } else { &mut st.window }
}

/// client 侧两代 server session 的归属判定 + 轮换（sing protocol.go:643-653 语义）。
///
/// - 命中当前/上一代 → 原位返回（上一代收包刷新 `last_remote_seen`）
/// - 新 sessionId：上一代收包 < 60s 拒绝轮换；否则当前代降级为上一代、
///   登记新 sessionId（[`RemoteSlot::New`]，调用方按需派生 cipher）
fn route_remote_generation(st: &mut RemoteState, session_id: u64) -> Result<RemoteSlot> {
    if session_id != 0 && session_id == st.remote_session_id {
        return Ok(RemoteSlot::Current);
    }
    if session_id != 0 && session_id == st.last_remote_session_id {
        st.last_remote_seen = now_unix();
        return Ok(RemoteSlot::Previous);
    }
    if st.remote_session_id != 0 {
        if now_unix() - st.last_remote_seen < 60 {
            return Err(SsError::Ss2022TooManyServerSessions);
        }
        st.last_remote_session_id = st.remote_session_id;
        st.last_remote_cipher = st.remote_cipher.take();
        st.last_window = std::mem::take(&mut st.window);
        st.last_remote_seen = now_unix();
    }
    st.remote_session_id = session_id;
    Ok(RemoteSlot::New)
}

/// [`route_remote_generation`] 的归属结果。
#[derive(Clone, Copy, PartialEq, Eq)]
enum RemoteSlot {
    Current,
    Previous,
    New,
}

fn pk_header(session_id: u64, packet_id: u64) -> [u8; 16] {
    let mut hdr = [0u8; 16];
    hdr[..8].copy_from_slice(&session_id.to_be_bytes());
    hdr[8..].copy_from_slice(&packet_id.to_be_bytes());
    hdr
}

// ============================================================================
// Server 侧解包 + 会话
// ============================================================================

/// server 侧解出的 client 包头（借用 users 的 PSK 供 AEAD 派生）。
#[derive(Debug)]
pub struct DecodedClientHeader<'a> {
    /// client sessionId。
    pub session_id: u64,
    /// client packetId。
    pub packet_id: u64,
    /// 已 ECB 解密的明文包头（nonce/派生材料）；chacha 模式恒零（不用）。
    pub hdr: [u8; 16],
    /// EIH 块字节数（multi = (n-1)*16，single = 0）。
    pub eih_len: usize,
    /// AEAD 派生 PSK（single→server_psk；multi→匹配用户 uPSK）。
    pub aead_psk: &'a [u8],
    /// chacha 模式：整包解出的明文体（sessionId/packetId 之后），
    /// 供 [`ServerUdpSession2022::decode_chacha_body`] 做窗口检查 + 解析。
    pub chacha_plain: Option<Vec<u8>>,
}

/// server 侧解 client 包第一步：ECB 解包头 + EIH 识别用户。
///
/// `users`：多用户 (identity, psk) 列表（identity = `psk_identity(psk)`，
/// 可由 [`crate::ss2022::key::psk_identity`] 预计算）。空 = 单用户模式。
///
/// # Errors
/// - [`SsError::InsufficientData`]：包过短。
/// - [`SsError::Ss2022NoUserMatched`]：EIH 无用户匹配。
pub fn server_decode_header<'a>(
    kind: CipherKind2022,
    server_psk: &'a [u8],
    users: &'a [([u8; 16], Vec<u8>)],
    pkt: &[u8],
) -> Result<DecodedClientHeader<'a>> {
    // chacha：整包一次 XChaCha(psk) 解开（无 ECB 头、无 EIH、无用户识别），
    // sessionId/packetId 在明文头；body 明文随 hdr.chacha_plain 交付，
    // 调用方建 session 后用 `decode_chacha_body` 做重放窗口 + 解析
    //（Go `UDPCodec.DecodePacket` chacha 分支）。
    if kind == CipherKind2022::ChaCha20Poly1305 {
        if pkt.len() < UDP_CHACHA_NONCE_SIZE + PACKET_HEADER_LEN + MIN_PLAINTEXT {
            return Err(SsError::InsufficientData(pkt.len()));
        }
        let aead = XChaCha20Poly1305Aead::new(server_psk)?;
        let plain = aead
            .open(&pkt[..UDP_CHACHA_NONCE_SIZE], b"", &pkt[UDP_CHACHA_NONCE_SIZE..])
            .map_err(|e| SsError::AeadOpen(e.to_string()))?;
        if plain.len() < PACKET_HEADER_LEN + MIN_PLAINTEXT {
            return Err(SsError::InsufficientData(plain.len()));
        }
        return Ok(DecodedClientHeader {
            session_id: u64::from_be_bytes(plain[..8].try_into().unwrap()),
            packet_id: u64::from_be_bytes(plain[8..16].try_into().unwrap()),
            hdr: [0u8; 16],
            eih_len: 0,
            aead_psk: server_psk,
            chacha_plain: Some(plain[PACKET_HEADER_LEN..].to_vec()),
        });
    }

    let eih_len = if users.is_empty() { 0 } else { 16 };
    if pkt.len() < PACKET_HEADER_LEN + eih_len + MIN_PLAINTEXT {
        return Err(SsError::InsufficientData(pkt.len()));
    }
    let hdr = ecb_block(kind, server_psk, pkt[..16].try_into().unwrap(), false)?;
    let session_id = u64::from_be_bytes(hdr[..8].try_into().unwrap());
    let packet_id = u64::from_be_bytes(hdr[8..].try_into().unwrap());

    let aead_psk = if users.is_empty() {
        server_psk
    } else {
        // EIH 块：ECB(iPSK) 解密后 XOR 明文包头 → 用户 PSK identity
        let eih = ecb_block(kind, server_psk, pkt[16..32].try_into().unwrap(), false)?;
        let mut ident = eih;
        for (b, h) in ident.iter_mut().zip(hdr.iter()) {
            *b ^= h;
        }
        let (_, psk) = users
            .iter()
            .find(|(identity, _)| identity == &ident)
            .ok_or(SsError::Ss2022NoUserMatched)?;
        psk.as_slice()
    };

    Ok(DecodedClientHeader { session_id, packet_id, hdr, eih_len, aead_psk, chacha_plain: None })
}

/// SS-2022 UDP server 会话（per client sessionId 的 NAT entry，
/// 对齐 Go `serverUDPSession`）。
pub struct ServerUdpSession2022 {
    kind: CipherKind2022,
    psk: Vec<u8>,
    /// server 自身随机 sessionId（回包 AEAD 派生 + client 校验）。
    session_id: u64,
    packet_id: AtomicU64,
    /// 回包 AEAD：SessionKey(psk, server_session_id)。
    cipher: Box<dyn AeadCipher + Send + Sync>,
    /// client sessionId（回包头里回填）。
    client_session_id: u64,
    /// 解包 AEAD：SessionKey(psk, client_session_id)。
    remote_cipher: Box<dyn AeadCipher + Send + Sync>,
    window: Mutex<SlidingWindow>,
}

impl ServerUdpSession2022 {
    /// 构造 server 会话（首包时按解出的 client sessionId + 匹配 PSK）。
    ///
    /// AES：回包 AEAD 从 server sessionId 派生、解包 AEAD 从 client sessionId 派生；
    /// chacha：两者同为一个 XChaCha(rawPSK)（SIP022 §4，无 subkey 派生）。
    ///
    /// # Errors
    /// - 透传 AEAD 初始化错误。
    pub fn new(kind: CipherKind2022, psk: Vec<u8>, client_session_id: u64) -> Result<Self> {
        let session_id = rand::random::<u64>();
        let (cipher, remote_cipher) = if kind == CipherKind2022::ChaCha20Poly1305 {
            // chacha：raw PSK 直作 key，回包/解包同 key（SIP022 §4）
            let c = udp_aead(kind, &psk, &[])?;
            let rc = udp_aead(kind, &psk, &[])?;
            (c, rc)
        } else {
            let c = udp_aead(kind, &psk, &session_id.to_be_bytes())?;
            let rc = udp_aead(kind, &psk, &client_session_id.to_be_bytes())?;
            (c, rc)
        };
        Ok(Self {
            kind,
            psk,
            session_id,
            packet_id: AtomicU64::new(u64::MAX),
            cipher,
            client_session_id,
            remote_cipher,
            window: Mutex::new(SlidingWindow::default()),
        })
    }

    /// server 会话第二步（AES）：AEAD 解密 body + 解析 client 帧明文区。
    ///
    /// `hdr` = [`server_decode_header`] 解出的明文包头；
    /// `body` = `pkt[16 + eih_len ..]`。
    ///
    /// # Errors
    /// - [`SsError::Ss2022PacketIdNotUnique`]：重放。
    /// - [`SsError::AeadOpen`]：解密失败。
    pub fn decode_body(
        &self,
        hdr: &[u8; 16],
        packet_id: u64,
        body: &[u8],
    ) -> Result<(Address, u16, Vec<u8>)> {
        {
            let mut w = self.window.lock();
            if !w.check(packet_id) {
                return Err(SsError::Ss2022PacketIdNotUnique);
            }
            let plain = self
                .remote_cipher
                .open(&hdr[4..16], b"", body)
                .map_err(|e| SsError::AeadOpen(e.to_string()))?;
            let r = parse_client_plaintext(&plain)?;
            w.add(packet_id);
            Ok(r)
        }
    }

    /// server 会话第二步（chacha）：`hdr.chacha_plain` 已整包解开，这里只做
    /// 重放窗口 check → 解析 → add（Go chacha 分支的 CheckPacketID/parse/Add 次序）。
    ///
    /// # Errors
    /// - [`SsError::Ss2022PacketIdNotUnique`]：重放。
    pub fn decode_chacha_body(
        &self,
        plain: &[u8],
        packet_id: u64,
    ) -> Result<(Address, u16, Vec<u8>)> {
        let mut w = self.window.lock();
        if !w.check(packet_id) {
            return Err(SsError::Ss2022PacketIdNotUnique);
        }
        let r = parse_client_plaintext(plain)?;
        w.add(packet_id);
        Ok(r)
    }

    /// 编码 server → client 回包帧。
    ///
    /// # Errors
    /// - [`SsError::AeadSeal`]：AEAD 加密失败。
    pub fn encode(&self, addr: &Address, port: u16, payload: &[u8]) -> Result<Vec<u8>> {
        let packet_id = self.packet_id.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let hdr = pk_header(self.session_id, packet_id);
        let plain = build_server_plaintext(self.client_session_id, addr, port, payload);

        // chacha：24B 随机 nonce 明文前缀 + XChaCha 直 seal，
        // serverSessionId/serverPacketId 在 AEAD 明文头（Go EncodeServerPacket）。
        if self.kind == CipherKind2022::ChaCha20Poly1305 {
            let nonce: [u8; UDP_CHACHA_NONCE_SIZE] = rand::random();
            let mut sealed_plain = Vec::with_capacity(PACKET_HEADER_LEN + plain.len());
            sealed_plain.extend_from_slice(&hdr);
            sealed_plain.extend_from_slice(&plain);
            let sealed = self
                .cipher
                .seal(&nonce, b"", &sealed_plain)
                .map_err(|e| SsError::AeadSeal(e.to_string()))?;
            let mut out = Vec::with_capacity(UDP_CHACHA_NONCE_SIZE + sealed.len());
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&sealed);
            return Ok(out);
        }

        let sealed = self
            .cipher
            .seal(&hdr[4..16], b"", &plain)
            .map_err(|e| SsError::AeadSeal(e.to_string()))?;
        let enc_hdr = ecb_block(self.kind, &self.psk, &hdr, true)?;
        let mut frame = enc_hdr.to_vec();
        frame.extend_from_slice(&sealed);
        Ok(frame)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ss2022::key::psk_identity;

    fn psk16() -> Vec<u8> {
        (0..16u8).collect()
    }
    fn psk16b() -> Vec<u8> {
        (16..32u8).collect()
    }

    /// client encode → server decode（单用户）roundtrip。
    #[test]
    fn client_to_server_roundtrip_single() {
        let kind = CipherKind2022::Aes128Gcm;
        let psk = psk16();
        let client = ClientUdpSession2022::new(kind, vec![psk.clone()]).unwrap();

        let frame =
            client.encode(&Address::Domain("example.com".into()), 443, b"hello udp").unwrap();
        let hdr = server_decode_header(kind, &psk, &[], &frame).unwrap();
        assert_eq!(hdr.session_id, client.session_id());
        assert_eq!(hdr.packet_id, 0); // 首包 id=0
        assert_eq!(hdr.eih_len, 0);

        let session =
            ServerUdpSession2022::new(kind, hdr.aead_psk.to_vec(), hdr.session_id).unwrap();
        let (addr, port, payload) =
            session.decode_body(&hdr.hdr, hdr.packet_id, &frame[16 + hdr.eih_len..]).unwrap();
        assert_eq!(addr, Address::Domain("example.com".into()));
        assert_eq!(port, 443);
        assert_eq!(payload, b"hello udp");
    }

    /// client encode → server decode（多用户 EIH）roundtrip。
    #[test]
    fn client_to_server_roundtrip_multi() {
        let kind = CipherKind2022::Aes256Gcm;
        let ipsk = (0..32u8).collect::<Vec<u8>>();
        let upsk = (32..64u8).collect::<Vec<u8>>();
        let client = ClientUdpSession2022::new(kind, vec![ipsk.clone(), upsk.clone()]).unwrap();

        let frame = client
            .encode(&Address::IPv4(std::net::Ipv4Addr::new(192, 168, 1, 1)), 53, b"dns-q")
            .unwrap();
        let users = vec![(psk_identity(&upsk), upsk.clone())];
        let hdr = server_decode_header(kind, &ipsk, &users, &frame).unwrap();
        assert_eq!(hdr.eih_len, 16);
        assert_eq!(hdr.session_id, client.session_id());

        let session =
            ServerUdpSession2022::new(kind, hdr.aead_psk.to_vec(), hdr.session_id).unwrap();
        let (addr, port, payload) =
            session.decode_body(&hdr.hdr, hdr.packet_id, &frame[16 + hdr.eih_len..]).unwrap();
        assert_eq!(addr, Address::IPv4(std::net::Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(port, 53);
        assert_eq!(payload, b"dns-q");
    }

    /// 多用户 EIH：错误用户集合不匹配。
    #[test]
    fn multi_eih_wrong_user_rejected() {
        let kind = CipherKind2022::Aes128Gcm;
        let ipsk = psk16();
        let upsk = psk16b();
        let client = ClientUdpSession2022::new(kind, vec![ipsk.clone(), upsk]).unwrap();
        let frame =
            client.encode(&Address::IPv4(std::net::Ipv4Addr::new(1, 1, 1, 1)), 80, b"x").unwrap();
        let wrong = vec![(
            psk_identity(&(100..116u8).collect::<Vec<u8>>()),
            (100..116u8).collect::<Vec<u8>>(),
        )];
        let err = server_decode_header(kind, &ipsk, &wrong, &frame).unwrap_err();
        assert!(matches!(err, SsError::Ss2022NoUserMatched));
    }

    /// server encode → client decode roundtrip（单/多用户 client 均可解）。
    #[test]
    fn server_to_client_roundtrip() {
        let kind = CipherKind2022::Aes128Gcm;
        let psk = psk16();
        let client = ClientUdpSession2022::new(kind, vec![psk.clone()]).unwrap();
        let server = ServerUdpSession2022::new(kind, psk, client.session_id()).unwrap();

        let frame =
            server.encode(&Address::IPv6(std::net::Ipv6Addr::LOCALHOST), 853, b"resp").unwrap();
        let (addr, port, payload) = client.decode(&frame).unwrap();
        assert!(matches!(addr, Address::IPv6(_)));
        assert_eq!(port, 853);
        assert_eq!(payload, b"resp");
    }

    /// server 回包 clientSessionId 不匹配被拒。
    #[test]
    fn server_packet_bad_client_session_rejected() {
        let kind = CipherKind2022::Aes128Gcm;
        let psk = psk16();
        let client = ClientUdpSession2022::new(kind, vec![psk.clone()]).unwrap();
        let server = ServerUdpSession2022::new(kind, psk, 0xdead).unwrap();
        let frame =
            server.encode(&Address::IPv4(std::net::Ipv4Addr::new(8, 8, 8, 8)), 53, b"r").unwrap();
        let err = client.decode(&frame).unwrap_err();
        assert!(matches!(err, SsError::Ss2022BadClientSessionId));
    }

    /// packetId 重放被拒（client→server 方向）。
    #[test]
    fn client_packet_replay_rejected() {
        let kind = CipherKind2022::Aes128Gcm;
        let psk = psk16();
        let client = ClientUdpSession2022::new(kind, vec![psk.clone()]).unwrap();
        let frame =
            client.encode(&Address::IPv4(std::net::Ipv4Addr::new(9, 9, 9, 9)), 80, b"p").unwrap();
        let hdr = server_decode_header(kind, &psk, &[], &frame).unwrap();
        let session =
            ServerUdpSession2022::new(kind, hdr.aead_psk.to_vec(), hdr.session_id).unwrap();
        let body = &frame[16 + hdr.eih_len..];
        assert!(session.decode_body(&hdr.hdr, hdr.packet_id, body).is_ok());
        let err = session.decode_body(&hdr.hdr, hdr.packet_id, body).unwrap_err();
        assert!(matches!(err, SsError::Ss2022PacketIdNotUnique));
    }

    /// packetId 递增 + server session 重绑定（两代轮换）。
    #[test]
    fn packet_id_increments_and_server_rebind() {
        let kind = CipherKind2022::Aes128Gcm;
        let psk = psk16();
        let client = ClientUdpSession2022::new(kind, vec![psk.clone()]).unwrap();

        // server 会话 1
        let s1 = ServerUdpSession2022::new(kind, psk.clone(), client.session_id()).unwrap();
        let f1 = s1.encode(&Address::IPv4(std::net::Ipv4Addr::new(1, 2, 3, 4)), 80, b"a").unwrap();
        let f2 = s1.encode(&Address::IPv4(std::net::Ipv4Addr::new(1, 2, 3, 4)), 80, b"b").unwrap();
        let (.., p1) = client.decode(&f1).unwrap();
        let (.., p2) = client.decode(&f2).unwrap();
        assert_eq!((p1, p2), (b"a".to_vec(), b"b".to_vec()));

        // server 重绑定（新 server session）：client 自动轮换两代窗口
        let s2 = ServerUdpSession2022::new(kind, psk, client.session_id()).unwrap();
        let f3 = s2.encode(&Address::IPv4(std::net::Ipv4Addr::new(5, 6, 7, 8)), 99, b"c").unwrap();
        let (addr, port, p3) = client.decode(&f3).unwrap();
        assert_eq!(addr, Address::IPv4(std::net::Ipv4Addr::new(5, 6, 7, 8)));
        assert_eq!((port, p3), (99, b"c".to_vec()));
    }

    /// 窗口推进后 behind-window 的旧 id 必须拒绝（sing SlidingWindow.Check 语义；
    /// 旧 BTreeSet 实现容量淘汰后旧 id 会重新放行，弱于 Go bitmap）。
    #[test]
    fn sliding_window_rejects_ids_behind_window() {
        let mut w = SlidingWindow::default();
        assert!(w.check(0)); // 首次可接受
        w.add(0);
        assert!(!w.check(0), "replay within window rejected");
        // 大幅推进 last（跨整个 ring），旧块被清零
        w.add(10000);
        assert!(!w.check(0), "id 8128+ behind window must be rejected");
        assert!(!w.check(1871), "just outside window (diff 8129) rejected");
        assert!(w.check(5000), "inside window unseen id accepted");
    }

    /// server session 轮换 60s 限速（sing protocol.go:643-653
    /// ErrTooManyServerSessions）：首包建代 + 一次轮换 free，第二次轮换拒绝。
    #[test]
    fn server_session_rebind_rate_limited_to_once_per_60s() {
        let kind = CipherKind2022::Aes128Gcm;
        let psk = psk16();
        let client = ClientUdpSession2022::new(kind, vec![psk.clone()]).unwrap();
        let mk_server =
            || ServerUdpSession2022::new(kind, psk.clone(), client.session_id()).unwrap();
        let addr = Address::IPv4(std::net::Ipv4Addr::new(1, 2, 3, 4));
        // 首包：建立当前代
        let s1 = mk_server();
        let f1 = s1.encode(&addr, 80, b"a").unwrap();
        client.decode(&f1).unwrap();
        // 第一次轮换：允许（sing lastRemoteSeen=0 初始）
        let s2 = mk_server();
        let f2 = s2.encode(&addr, 80, b"b").unwrap();
        client.decode(&f2).unwrap();
        // 第二次轮换（60s 内）：拒绝
        let s3 = mk_server();
        let f3 = s3.encode(&addr, 80, b"c").unwrap();
        let err = client.decode(&f3).unwrap_err();
        assert!(matches!(err, SsError::Ss2022TooManyServerSessions));
    }

    /// 包损坏（翻转密文体字节）解密失败。
    #[test]
    fn corrupted_packet_rejected() {
        let kind = CipherKind2022::Aes128Gcm;
        let psk = psk16();
        let client = ClientUdpSession2022::new(kind, vec![psk.clone()]).unwrap();
        let server = ServerUdpSession2022::new(kind, psk, client.session_id()).unwrap();
        let mut frame =
            server.encode(&Address::IPv4(std::net::Ipv4Addr::new(1, 1, 1, 1)), 80, b"zz").unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 0xff;
        assert!(client.decode(&frame).is_err());
    }

    /// chacha 单用户 UDP：client ↔ server 双向 roundtrip（XChaCha 24B nonce，
    /// 无 ECB 头/EIH；Go EncodePacket/EncodeServerPacket chacha 分支对齐）。
    #[test]
    fn chacha_udp_roundtrip() {
        let kind = CipherKind2022::ChaCha20Poly1305;
        let psk = (0..32u8).collect::<Vec<u8>>();
        let client = ClientUdpSession2022::new(kind, vec![psk.clone()]).unwrap();

        // client → server
        let frame = client.encode(&Address::Domain("c.example".into()), 443, b"up").unwrap();
        let hdr = server_decode_header(kind, &psk, &[], &frame).unwrap();
        assert_eq!(hdr.session_id, client.session_id());
        assert_eq!(hdr.packet_id, 0);
        assert_eq!(hdr.eih_len, 0);
        let plain = hdr.chacha_plain.clone().expect("chacha plain");
        let session =
            ServerUdpSession2022::new(kind, hdr.aead_psk.to_vec(), hdr.session_id).unwrap();
        let (addr, port, payload) = session.decode_chacha_body(&plain, hdr.packet_id).unwrap();
        assert_eq!(addr, Address::Domain("c.example".into()));
        assert_eq!(port, 443);
        assert_eq!(payload, b"up");

        // server → client（回包 padding 恒 0）
        let reply = session
            .encode(&Address::IPv4(std::net::Ipv4Addr::new(1, 1, 1, 1)), 443, b"down")
            .unwrap();
        let (addr, port, payload) = client.decode(&reply).unwrap();
        assert_eq!(addr, Address::IPv4(std::net::Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(port, 443);
        assert_eq!(payload, b"down");
    }

    /// chacha + 多 PSK：codec 构造硬错（Go NewUDPPacketCodec / outbound.go:48-50）。
    #[test]
    fn chacha_udp_multi_psk_rejected() {
        let kind = CipherKind2022::ChaCha20Poly1305;
        let err = match ClientUdpSession2022::new(
            kind,
            vec![(0..32u8).collect(), (32..64u8).collect()],
        ) {
            Err(e) => e,
            Ok(_) => panic!("chacha multi-psk must be rejected"),
        };
        assert!(matches!(err, SsError::Ss2022UnsupportedMethod(_)));
    }

    /// chacha UDP 重放（同 packetId 二次）被拒。
    #[test]
    fn chacha_udp_replay_rejected() {
        let kind = CipherKind2022::ChaCha20Poly1305;
        let psk = (0..32u8).collect::<Vec<u8>>();
        let client = ClientUdpSession2022::new(kind, vec![psk.clone()]).unwrap();
        let frame =
            client.encode(&Address::IPv4(std::net::Ipv4Addr::new(2, 2, 2, 2)), 80, b"p").unwrap();
        let hdr = server_decode_header(kind, &psk, &[], &frame).unwrap();
        let plain = hdr.chacha_plain.expect("chacha plain");
        let session =
            ServerUdpSession2022::new(kind, hdr.aead_psk.to_vec(), hdr.session_id).unwrap();
        assert!(session.decode_chacha_body(&plain, hdr.packet_id).is_ok());
        let err = session.decode_chacha_body(&plain, hdr.packet_id).unwrap_err();
        assert!(matches!(err, SsError::Ss2022PacketIdNotUnique));
    }

    /// DNS(53) 包带 padding 也能正确 roundtrip（padding 剥离）。
    #[test]
    fn dns_padding_stripped() {
        let kind = CipherKind2022::Aes128Gcm;
        let psk = psk16();
        let client = ClientUdpSession2022::new(kind, vec![psk.clone()]).unwrap();
        let payload = vec![7u8; 64];
        let frame = client.encode(&Address::Domain("dns.example".into()), 53, &payload).unwrap();
        let hdr = server_decode_header(kind, &psk, &[], &frame).unwrap();
        let session =
            ServerUdpSession2022::new(kind, hdr.aead_psk.to_vec(), hdr.session_id).unwrap();
        let (_, port, out) =
            session.decode_body(&hdr.hdr, hdr.packet_id, &frame[16 + hdr.eih_len..]).unwrap();
        assert_eq!(port, 53);
        assert_eq!(out, payload);
    }

    /// 真实 UDP socket 回环 e2e：client encode → socket → server 解包 →
    /// 回包 encode → socket → client decode（多用户 EIH 全路径）。
    #[tokio::test]
    async fn udp_socket_roundtrip_e2e() {
        use std::net::SocketAddr;

        use tokio::net::UdpSocket;

        let kind = CipherKind2022::Aes256Gcm;
        let ipsk: Vec<u8> = (0..32u8).collect();
        let upsk: Vec<u8> = (32..64u8).collect();
        let users = vec![(psk_identity(&upsk), upsk.clone())];

        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr: SocketAddr = server_sock.local_addr().unwrap();
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client_sock.connect(server_addr).await.unwrap();

        let client = ClientUdpSession2022::new(kind, vec![ipsk.clone(), upsk.clone()]).unwrap();

        // server 侧：收包 → 解头/解体 → 回包 encode → send_to
        let server = tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            let (n, peer) = server_sock.recv_from(&mut buf).await.unwrap();
            let hdr = server_decode_header(kind, &ipsk, &users, &buf[..n]).unwrap();
            let session =
                ServerUdpSession2022::new(kind, hdr.aead_psk.to_vec(), hdr.session_id).unwrap();
            let (addr, port, payload) =
                session.decode_body(&hdr.hdr, hdr.packet_id, &buf[16 + hdr.eih_len..n]).unwrap();
            // echo 回包（来源 = 解出的目标）
            let enc = session.encode(&addr, port, &payload).unwrap();
            server_sock.send_to(&enc, peer).await.unwrap();
        });

        // client 侧：发帧 → 收回包 → decode
        let payload = b"ss2022 udp e2e payload".to_vec();
        let frame = client.encode(&Address::Domain("echo.local".into()), 5353, &payload).unwrap();
        client_sock.send(&frame).await.unwrap();

        let mut rbuf = vec![0u8; 65_535];
        let n =
            tokio::time::timeout(std::time::Duration::from_secs(5), client_sock.recv(&mut rbuf))
                .await
                .expect("recv timeout")
                .expect("recv");
        let (addr, port, echoed) = client.decode(&rbuf[..n]).unwrap();
        assert_eq!(addr, Address::Domain("echo.local".into()));
        assert_eq!(port, 5353);
        assert_eq!(echoed, payload);

        server.await.unwrap();
    }
}

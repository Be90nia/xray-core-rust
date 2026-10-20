//! # 客户端/服务端握手 + TCP bridge（对应 Go `xmc/client.go` + `xmc/server.go` + `xmc/stream.go` + `xmc/packet_stream.go`）
//!
//! 握手流程（Minecraft Login，state=2）：
//! 1. C → S：Handshake (0x00)：proto=775, hostname, port, next=2
//! 2. C → S：Login Start (0x00)：username + uuid（来自配置 profile）
//! 3. S → C：Encryption Request (0x01)：serverId="", publicKey, verifyToken(4B), shouldAuth=1
//! 4. C → S：Encryption Response (0x01)：RSA-enc(sharedSecret 16B), RSA-enc(verifyToken+password)
//! 5. 双方启用 AES-128-CFB8（key=iv=sharedSecret）
//! 6. S → C：Login Success (0x02)：uuid + username + textures property（1 项，signed）
//!    （密码错/非白名单 → Disconnect (0x00)，加密流上发送）
//! 7. C → S：Login Acknowledged (0x03)：空 payload；其 wire 长度并入 padding 第一轮
//! 8. 双方跑 2612 padding 调度（首轮前缀 = Login Acknowledged wire 长度）
//!
//! 数据面（对应 Go `packetStream`）：代理字节流装在 configuration 状态的
//! custom payload 包（channel `xmc:data`，单包 ≤24KiB）里双向传输；服务端每
//! 15s 发 configuration Keep Alive (0x04)，客户端收到后原样回写。
//!
//! 握手 + padding 整体受 2 分钟 deadline（对应 Go `deadline.go` handshakeTimeout）。

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use rand::{Rng, RngCore};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePublicKey;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::mpsc;

use super::super::AsyncIo;
use super::cfb8::{Cfb8Dec, Cfb8Enc};
use super::{Config, Profile, UDP_SIZE, protocol};

type DynIo = Box<dyn AsyncIo>;

/// 共享密钥长度（AES-128 key，同时也是 IV）。
pub const SHARED_SECRET_SIZE: usize = 16;
/// MC 协议版本（1.17.x，对应 Go `775`）。
pub const PROTOCOL_VERSION: i32 = 775;
/// 单包 payload 上限。
const PACKET_DATA_MAX: i32 = 32 * 1024;
/// 握手整体 deadline（对应 Go `deadline.go` `handshakeTimeout`）。
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(120);

// packetStream 常量（对应 Go `packet_stream.go`）。
const CONFIGURATION_CLIENTBOUND_CUSTOM_PAYLOAD: i32 = 0x01;
const CONFIGURATION_SERVERBOUND_CUSTOM_PAYLOAD: i32 = 0x02;
const CONFIGURATION_KEEP_ALIVE: i32 = 0x04;
const PACKET_CHANNEL: &str = "xmc:data";
const MAX_PACKET_DATA: usize = 24 * 1024;
const KEEP_ALIVE_PERIOD: Duration = Duration::from_secs(15);

fn io_err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// 异步读 Minecraft VarInt（int32，7-bit 编码，最多 5 字节）。
async fn read_varint_async<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<i32> {
    let mut value: i32 = 0;
    let mut position: i32 = 0;
    let mut buf = [0u8; 1];
    for _ in 0..5 {
        r.read_exact(&mut buf).await?;
        let b = buf[0];
        value |= i32::from(b & 0x7F) << position;
        if b & 0x80 == 0 {
            return Ok(value);
        }
        position += 7;
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "xmc varint too large"))
}

/// 异步读完整 packet：返回 `(packet_id, payload)`。
async fn read_packet_async<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<(i32, Vec<u8>)> {
    let (id, data, _) = read_packet_with_length_async(r).await?;
    Ok((id, data))
}

/// 异步读完整 packet，附带完整 wire 长度（长度前缀字节 + 包体，对应 Go
/// `readPacketWithLength` 返回值）。
async fn read_packet_with_length_async<R: AsyncRead + Unpin>(
    r: &mut R,
) -> io::Result<(i32, Vec<u8>, i32)> {
    let packet_length = read_varint_async(r).await?;
    let packet_id = read_varint_async(r).await?;
    let id_size = protocol::varint_size(packet_id) as i32;
    let data_length = packet_length
        .checked_sub(id_size)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "xmc packet length underflow"))?;
    if !(0..=PACKET_DATA_MAX).contains(&data_length) {
        return Err(io_err(format!("xmc packet bad data length: {data_length}")));
    }
    let mut data = vec![0u8; data_length as usize];
    r.read_exact(&mut data).await?;
    let wire_len = protocol::varint_size(packet_length) as i32 + packet_length;
    Ok((packet_id, data, wire_len))
}

/// 异步写完整 packet，返回完整 wire 长度（对应 Go `writePacketWithLength`）。
async fn write_packet_with_length_async<W: AsyncWrite + Unpin>(
    w: &mut W,
    packet_id: i32,
    payload: &[u8],
) -> io::Result<i32> {
    let buf = encode_packet(packet_id, payload)?;
    w.write_all(&buf).await?;
    Ok(buf.len() as i32)
}

/// 编码完整 packet 字节（VarInt 总长 + VarInt ID + payload）。
fn encode_packet(packet_id: i32, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(payload.len() + 10);
    protocol::write_packet(&mut buf, packet_id, payload)?;
    Ok(buf)
}

/// 编码 custom payload 包字节：channel string 前缀 + 裸数据（对应 Go `RestBytes`，
/// 数据无长度前缀）。
fn encode_custom_payload(packet_id: i32, data: &[u8]) -> io::Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(data.len() + PACKET_CHANNEL.len() + 5);
    protocol::write_string(&mut payload, PACKET_CHANNEL)?;
    payload.extend_from_slice(data);
    encode_packet(packet_id, &payload)
}

/// CFB8 解密流包装：实现 AsyncRead（对应 Go `cryptoStream` 读侧）。
struct DecryptReader<R> {
    inner: R,
    dec: Option<Cfb8Dec>,
    buf: Box<[u8]>,
}

impl<R: AsyncRead + Unpin> DecryptReader<R> {
    fn new(inner: R, dec: Cfb8Dec) -> Self {
        Self { inner, dec: Some(dec), buf: vec![0u8; UDP_SIZE * 4].into_boxed_slice() }
    }

    /// 取回底层流与解密流状态（CFB8 IV 状态必须延续，不得重建）。
    fn into_parts(self) -> (R, Cfb8Dec) {
        match self.dec {
            Some(dec) => (self.inner, dec),
            None => unreachable!("dec present until into_parts"),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for DecryptReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let Some(dec) = this.dec.as_mut() else {
            return Poll::Ready(Err(io::Error::other("xmc decrypt reader consumed")));
        };
        // 单次读入量不得超过 caller 缓冲剩余容量（poll_read 契约）。
        let cap = out.remaining().min(this.buf.len());
        let mut inner_buf = ReadBuf::new(&mut this.buf[..cap]);
        match Pin::new(&mut this.inner).poll_read(cx, &mut inner_buf)? {
            Poll::Ready(()) => {
                let n = inner_buf.filled().len();
                dec.decrypt(&mut this.buf[..n]);
                out.initialize_unfilled_to(n).copy_from_slice(&this.buf[..n]);
                out.advance(n);
                Poll::Ready(Ok(()))
            },
            Poll::Pending => Poll::Pending,
        }
    }
}

/// CFB8 加密写包装（借用写 half 与加密流状态）：padding 阶段把字节直通加密写
/// raw（对应 Go `cryptoStream` 写侧）。
struct EncryptSink<'a, W> {
    inner: &'a mut W,
    enc: &'a mut Cfb8Enc,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for EncryptSink<'_, W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut owned = buf.to_vec();
        this.enc.encrypt(&mut owned);
        match Pin::new(&mut *this.inner).poll_write(cx, &owned) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

/// 在加密流上写完整 packet，返回完整 wire 长度（明文态编码后整体加密）。
async fn write_encrypted_packet_len<W: AsyncWrite + Unpin>(
    w: &mut W,
    enc: &mut Cfb8Enc,
    packet_id: i32,
    payload: &[u8],
) -> io::Result<i32> {
    let mut buf = encode_packet(packet_id, payload)?;
    let wire_len = buf.len() as i32;
    enc.encrypt(&mut buf);
    w.write_all(&buf).await?;
    Ok(wire_len)
}

/// 加密流上写 Disconnect（单 String 字段，对应 Go `writeDisconnectPacket`）。
async fn write_encrypted_disconnect<W: AsyncWrite + Unpin>(
    w: &mut W,
    enc: &mut Cfb8Enc,
    reason: &str,
) -> io::Result<()> {
    let mut payload = Vec::with_capacity(reason.len() + 5);
    protocol::write_string(&mut payload, reason)?;
    write_encrypted_packet_len(w, enc, 0x00, &payload).await?;
    Ok(())
}

/// 握手产物：共享密钥 + Login Acknowledged wire 长度 + 延续到数据面的 CFB8 流
/// 状态（写侧状态含 Login Success/Acknowledged 字节，读侧同理——对应 Go 把
/// `cryptoStream` 挂在 conn 上全程复用）。
struct HandshakeDone {
    login_ack_wire_len: i32,
    dec: Cfb8Dec,
    enc: Cfb8Enc,
}

/// 服务端写 Login Success（0x02）：uuid + username + 1 项 signed textures 属性
/// （对应 Go `server.go` login finished 段）。
async fn write_login_success<W: AsyncWrite + Unpin>(
    w: &mut W,
    enc: &mut Cfb8Enc,
    profile: &Profile,
) -> io::Result<()> {
    let mut p = Vec::new();
    protocol::write_uuid(&mut p, &profile.uuid)?;
    protocol::write_string(&mut p, &profile.username)?;
    protocol::write_varint(&mut p, 1)?;
    protocol::write_string(&mut p, "textures")?;
    protocol::write_string(&mut p, &profile.textures_value)?;
    protocol::write_bool(&mut p, true)?;
    protocol::write_string(&mut p, &profile.textures_signature)?;
    write_encrypted_packet_len(w, enc, 0x02, &p).await?;
    Ok(())
}

/// 客户端读 + 校验 Login Success（对应 Go `readLoginSuccess` + profile 全等比较）。
fn read_login_success(data: &[u8], expected: &Profile) -> io::Result<()> {
    let mut cur = io::Cursor::new(data);
    let uuid = protocol::read_uuid(&mut cur)?;
    let username = protocol::read_string(&mut cur)?;
    let property_count = protocol::read_varint(&mut cur)?;
    let property_name = protocol::read_string(&mut cur)?;
    let value = protocol::read_string(&mut cur)?;
    let signed = protocol::read_bool(&mut cur)?;
    let signature = protocol::read_string(&mut cur)?;
    if property_count != 1 || property_name != "textures" || !signed {
        return Err(io_err("invalid login profile properties"));
    }
    let received = Profile { username, uuid, textures_value: value, textures_signature: signature };
    if received != *expected {
        return Err(io_err("login profile mismatch"));
    }
    Ok(())
}

/// 白名单查找（对应 Go `findProfile`：username + uuid 双匹配）。
fn find_profile<'a>(
    profiles: &'a [Profile],
    username: &str,
    uuid: &[u8; 16],
) -> Option<&'a Profile> {
    profiles.iter().find(|p| p.username == username && p.uuid == *uuid)
}

/// 客户端握手。成功返回 sharedSecret + Login Acknowledged wire 长度 + CFB8 流状态。
async fn client_handshake<RW>(
    raw: &mut RW,
    hostname: &str,
    profiles: &[Profile],
    rsa_public_key_der: &[u8],
    password: &str,
) -> io::Result<HandshakeDone>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    if profiles.is_empty() {
        return Err(io_err("empty profiles"));
    }
    let rsa_public_key =
        rsa::RsaPublicKey::from_public_key_der(rsa_public_key_der).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("parse rsa public key: {e}"))
        })?;

    // 1. Handshake (0x00)。端口与 Go 缺省一致用 25565（服务端不校验该字段；
    //    Go 会用 RemoteAddr 实际端口覆盖，Rust 的 Tcpmask 接口拿不到 dest 端口）。
    let mut p = Vec::new();
    protocol::write_varint(&mut p, PROTOCOL_VERSION)?;
    protocol::write_string(&mut p, hostname)?;
    protocol::write_u16_be(&mut p, 25565)?;
    protocol::write_varint(&mut p, 2)?; // nextState = Login
    write_packet_with_length_async(raw, 0x00, &p).await?;

    // 2. Login Start (0x00)：随机选一个 profile（对应 Go rand.Int 选 profile）。
    let idx = rand::rng().random_range(0..profiles.len());
    let selected = &profiles[idx];
    let mut p = Vec::new();
    protocol::write_string(&mut p, &selected.username)?;
    protocol::write_uuid(&mut p, &selected.uuid)?;
    write_packet_with_length_async(raw, 0x00, &p).await?;

    // 3. 读 Encryption Request (0x01)
    let (packet_id, data) = read_packet_async(raw).await?;
    if packet_id != 0x01 {
        return Err(io_err(format!("expected encryption request 0x01, got {packet_id:#x}")));
    }
    let mut cursor = io::Cursor::new(data);
    let _server_id = protocol::read_string(&mut cursor)?;
    let server_public_key = protocol::read_bytes(&mut cursor)?;
    let verify_token = protocol::read_bytes(&mut cursor)?;
    // shouldAuthenticate 字段客户端不使用，跳过

    if server_public_key != rsa_public_key_der {
        return Err(io_err("server public key mismatch"));
    }

    // 4. 生成 sharedSecret + RSA 加密
    let mut shared_secret = [0u8; SHARED_SECRET_SIZE];
    rand::rng().fill_bytes(&mut shared_secret);

    let mut rng = rsa::rand_core::OsRng;
    let enc_shared = rsa_public_key
        .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, &shared_secret)
        .map_err(|e| io::Error::other(format!("rsa encrypt shared: {e}")))?;

    let mut verify_with_pw = verify_token.clone();
    verify_with_pw.extend_from_slice(password.as_bytes());
    let enc_verify = rsa_public_key
        .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, &verify_with_pw)
        .map_err(|e| io::Error::other(format!("rsa encrypt verify: {e}")))?;

    // 5. 写 Encryption Response (0x01)
    let mut p = Vec::new();
    protocol::write_bytes(&mut p, &enc_shared)?;
    protocol::write_bytes(&mut p, &enc_verify)?;
    write_packet_with_length_async(raw, 0x01, &p).await?;

    // 6. 启用加密流：读 Login Success (0x02) 或 Disconnect (0x00)
    let mut enc = Cfb8Enc::new(&shared_secret, &shared_secret);
    let mut dec_reader =
        DecryptReader::new(&mut *raw, Cfb8Dec::new(&shared_secret, &shared_secret));
    let (packet_id, data) = read_packet_async(&mut dec_reader).await?;
    if packet_id == 0x00 {
        let mut cursor = io::Cursor::new(data);
        let reason = protocol::read_string(&mut cursor)?;
        return Err(io_err(format!("authentication rejected: {reason}")));
    }
    if packet_id != 0x02 {
        return Err(io_err(format!("bad login finished packet id: {packet_id}")));
    }
    read_login_success(&data, selected)?;
    let (_, dec) = dec_reader.into_parts();

    // 7. 写 Login Acknowledged (0x03)：空 payload，wire 长度并入 padding 首轮。
    let login_ack_wire_len = write_encrypted_packet_len(raw, &mut enc, 0x03, &[]).await?;

    Ok(HandshakeDone { login_ack_wire_len, dec, enc })
}

/// 服务端握手。成功返回 sharedSecret + Login Acknowledged wire 长度 + CFB8 流状态。
async fn server_handshake<RW>(
    raw: &mut RW,
    profiles: &[Profile],
    rsa_private_key_der: &[u8],
    rsa_public_key_der: &[u8],
    password: &str,
) -> io::Result<HandshakeDone>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    if profiles.is_empty() {
        return Err(io_err("empty profiles"));
    }
    let rsa_private_key = rsa::RsaPrivateKey::from_pkcs1_der(rsa_private_key_der).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("parse rsa private key: {e}"))
    })?;

    // 1. 读 Handshake (0x00)。nextState=1 的 status ping 伪装（Go 支持）Rust 未实现，
    //    明确拒绝——不做静默降级。
    let (packet_id, data) = read_packet_async(raw).await?;
    if packet_id != 0x00 {
        return Err(io_err(format!("bad handshake packet id: {packet_id}")));
    }
    let mut cursor = io::Cursor::new(data);
    let _proto = protocol::read_varint(&mut cursor)?;
    let _addr = protocol::read_string(&mut cursor)?;
    let _port = protocol::read_u16_be(&mut cursor)?;
    let next_state = protocol::read_varint(&mut cursor)?;
    if next_state != 2 {
        return Err(io_err(format!(
            "unsupported next state: {next_state} (status ping masquerade not implemented)"
        )));
    }

    // 2. 读 Login Start (0x00)
    let (packet_id, data) = read_packet_async(raw).await?;
    if packet_id != 0x00 {
        return Err(io_err(format!("bad login start packet id: {packet_id}")));
    }
    let mut cursor = io::Cursor::new(data);
    let username = protocol::read_string(&mut cursor)?;
    let uuid = protocol::read_uuid(&mut cursor)?;

    // 3. 写 Encryption Request (0x01)
    let mut verify_token = [0u8; 4];
    rand::rng().fill_bytes(&mut verify_token);

    let mut p = Vec::new();
    protocol::write_string(&mut p, "")?;
    protocol::write_bytes(&mut p, rsa_public_key_der)?;
    protocol::write_bytes(&mut p, &verify_token)?;
    protocol::write_varint(&mut p, 1)?; // shouldAuthenticate
    write_packet_with_length_async(raw, 0x01, &p).await?;

    // 4. 读 Encryption Response (0x01)
    let (packet_id, data) = read_packet_async(raw).await?;
    if packet_id != 0x01 {
        return Err(io_err(format!("bad encryption response packet id: {packet_id}")));
    }
    let mut cursor = io::Cursor::new(data);
    let enc_shared = protocol::read_bytes(&mut cursor)?;
    let enc_verify = protocol::read_bytes(&mut cursor)?;

    // 5. RSA 解密 + verifyToken 校验（明文流上，与 Go 顺序一致）
    let shared_secret = rsa_private_key
        .decrypt(rsa::Pkcs1v15Encrypt, &enc_shared)
        .map_err(|e| io::Error::other(format!("rsa decrypt shared: {e}")))?;
    let decrypted_verify = rsa_private_key
        .decrypt(rsa::Pkcs1v15Encrypt, &enc_verify)
        .map_err(|e| io::Error::other(format!("rsa decrypt verify: {e}")))?;

    if decrypted_verify.len() < 4 || decrypted_verify[..4] != verify_token {
        return Err(io_err("verify token mismatch"));
    }
    if shared_secret.len() != SHARED_SECRET_SIZE {
        return Err(io_err(format!("bad shared secret length: {}", shared_secret.len())));
    }
    let secret16: [u8; SHARED_SECRET_SIZE] =
        shared_secret.as_slice().try_into().expect("length checked above");

    // 6. 启用加密流。密码/白名单校验失败都在加密流上回 Disconnect（对应 Go
    //    cryptoWriter 启用后的 writeDisconnectPacket）。
    let mut enc = Cfb8Enc::new(&secret16, &secret16);

    let received_pw = &decrypted_verify[4..];
    if received_pw != password.as_bytes() {
        write_encrypted_disconnect(
            raw,
            &mut enc,
            r#"{"type":"translatable","translate":"multiplayer.disconnect.authservers_down"}"#,
        )
        .await?;
        return Err(io_err("bad password"));
    }

    let profile = match find_profile(profiles, &username, &uuid) {
        Some(p) => p,
        None => {
            write_encrypted_disconnect(
                raw,
                &mut enc,
                r#"{"text":"You are not white-listed on this server!"}"#,
            )
            .await?;
            return Err(io_err(format!("unknown login profile: {username}")));
        },
    };

    // 7. 写 Login Success (0x02)
    write_login_success(raw, &mut enc, profile).await?;

    // 8. 读 Login Acknowledged (0x03)：空 payload，记录完整 wire 长度。
    let mut dec_reader = DecryptReader::new(&mut *raw, Cfb8Dec::new(&secret16, &secret16));
    let (packet_id, data, wire_len) = read_packet_with_length_async(&mut dec_reader).await?;
    if packet_id != 0x03 {
        return Err(io_err(format!("bad login acknowledged packet id: {packet_id}")));
    }
    if !data.is_empty() {
        return Err(io_err(format!("bad login acknowledged packet data length: {}", data.len())));
    }
    let (_, dec) = dec_reader.into_parts();

    Ok(HandshakeDone { login_ack_wire_len: wire_len, dec, enc })
}

/// 握手 + padding 阶段（受 2 分钟整体 deadline，对应 Go `beginHandshake`/
/// `endHandshake` 包住的整段）。成功返回数据面所需的读半（含解密流状态）、
/// 写半与加密流状态。
async fn handshake_phase(
    mut raw: DynIo,
    is_client: bool,
    config: &Config,
) -> io::Result<(DecryptReader<ReadHalf<DynIo>>, WriteHalf<DynIo>, Cfb8Enc)> {
    let phase = async {
        let done = if is_client {
            client_handshake(
                &mut raw,
                &config.hostname,
                &config.profiles,
                &config.rsa_public_key,
                &config.password,
            )
            .await?
        } else {
            server_handshake(
                &mut raw,
                &config.profiles,
                &config.rsa_private_key,
                &config.rsa_public_key,
                &config.password,
            )
            .await?
        };

        let (rr, mut ww) = tokio::io::split(raw);
        let mut dec_reader = DecryptReader::new(rr, done.dec);
        let mut enc = done.enc;

        // padding 跑在加密流上（对应 Go cryptoWriter 启用后的 runPaddingSchedule），
        // 首轮前缀 = Login Acknowledged 完整 wire 长度。
        if !config.padding_disabled {
            let schedule = if is_client {
                super::padding_preset::new_client_padding_schedule_2612()?
            } else {
                super::padding_preset::new_server_padding_schedule_2612()?
            };
            super::padding::run_padding_schedule(
                &mut dec_reader,
                &mut EncryptSink { inner: &mut ww, enc: &mut enc },
                is_client,
                done.login_ack_wire_len,
                &schedule,
            )
            .await?;
        }

        Ok::<_, io::Error>((dec_reader, ww, enc))
    };

    match tokio::time::timeout(HANDSHAKE_TIMEOUT, phase).await {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("xmc handshake timeout after {HANDSHAKE_TIMEOUT:?}"),
        )),
    }
}

/// TCP bridge task：握手 + padding（2 分钟 deadline），随后进入 packetStream 数据面。
pub(super) async fn tcp_bridge(
    raw: DynIo,
    pipe: tokio::io::DuplexStream,
    is_client: bool,
    config: Config,
) {
    let (mut dec_reader, ww, mut enc) = match handshake_phase(raw, is_client, &config).await {
        Ok(v) => v,
        Err(_) => return, // 握手失败/超时：断开 pipe（对端读到 EOF）
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // 唯一写者任务：明文 MC 包字节 → CFB8 加密 → raw（对应 Go cryptoStream 写侧）。
    tokio::spawn(async move {
        let mut ww = ww;
        while let Some(mut pkt) = rx.recv().await {
            enc.encrypt(&mut pkt);
            if ww.write_all(&pkt).await.is_err() {
                break;
            }
        }
    });

    let local_cp_id = if is_client {
        CONFIGURATION_SERVERBOUND_CUSTOM_PAYLOAD
    } else {
        CONFIGURATION_CLIENTBOUND_CUSTOM_PAYLOAD
    };
    let remote_cp_id = if is_client {
        CONFIGURATION_CLIENTBOUND_CUSTOM_PAYLOAD
    } else {
        CONFIGURATION_SERVERBOUND_CUSTOM_PAYLOAD
    };

    let (mut pipe_r, mut pipe_w) = tokio::io::split(pipe);

    // pipe → raw：代理字节读出，≤24KiB 分块装进 xmc:data custom payload 包
    // （对应 Go packetStream.Write）。
    let tx_data = tx.clone();
    let tx_ka = tx.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_PACKET_DATA];
        loop {
            match pipe_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => match encode_custom_payload(local_cp_id, &buf[..n]) {
                    Ok(pkt) => {
                        if tx_data.send(pkt).is_err() {
                            break;
                        }
                    },
                    Err(_) => break,
                },
            }
        }
    });

    // raw → pipe：解密读 MC 包循环，xmc:data payload 写回 pipe（对应 Go
    // packetStream.Read）；keep alive 客户端回显，其余包吞掉。任务退出（drop
    // pipe_w / tx）即向对端传导断连。
    let tx_read = tx;
    tokio::spawn(async move {
        let tx = tx_read;
        loop {
            let (id, data) = match read_packet_async(&mut dec_reader).await {
                Ok(v) => v,
                Err(_) => break,
            };
            if id == remote_cp_id {
                let mut cur = io::Cursor::new(&data);
                let channel = match protocol::read_string(&mut cur) {
                    Ok(c) => c,
                    Err(_) => break,
                };
                if channel != PACKET_CHANNEL {
                    continue;
                }
                let pos = cur.position() as usize;
                if pos >= data.len() {
                    continue;
                }
                if pipe_w.write_all(&data[pos..]).await.is_err() {
                    break;
                }
            } else if id == CONFIGURATION_KEEP_ALIVE && is_client {
                // 客户端收到 keep alive 原样回写（对应 Go packetStream.Read 回显）。
                match encode_packet(CONFIGURATION_KEEP_ALIVE, &data) {
                    Ok(pkt) => {
                        if tx.send(pkt).is_err() {
                            break;
                        }
                    },
                    Err(_) => break,
                }
            }
        }
    });

    // 服务端 keep alive 循环：每 15s 发递增 id（对应 Go keepAliveLoop，仅 server）。
    if !is_client {
        tokio::spawn(async move {
            let tx = tx_ka;
            let mut id: i64 = 0;
            loop {
                tokio::time::sleep(KEEP_ALIVE_PERIOD).await;
                id += 1;
                let mut p = Vec::with_capacity(9);
                if protocol::write_i64_be(&mut p, id).is_err() {
                    break;
                }
                match encode_packet(CONFIGURATION_KEEP_ALIVE, &p) {
                    Ok(pkt) => {
                        if tx.send(pkt).is_err() {
                            break;
                        }
                    },
                    Err(_) => break,
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::Tcpmask;
    use super::*;

    fn test_config() -> Config {
        let password = "super-secure-shared-key-12345";
        let private_key = super::super::derivation::derive_rsa_key(password).expect("derive");
        let private_der = rsa::pkcs1::EncodeRsaPrivateKey::to_pkcs1_der(&private_key)
            .expect("der")
            .as_bytes()
            .to_vec();
        let public_key = <rsa::RsaPublicKey as From<&rsa::RsaPrivateKey>>::from(&private_key);
        let public_der = rsa::pkcs8::EncodePublicKey::to_public_key_der(&public_key)
            .expect("der")
            .as_bytes()
            .to_vec();
        Config {
            profiles: vec![Profile {
                username: "test_user".into(),
                uuid: [0x42; 16],
                textures_value: "tv".into(),
                textures_signature: "ts".into(),
            }],
            password: password.into(),
            rsa_private_key: private_der,
            rsa_public_key: public_der,
            hostname: "localhost".into(),
            padding_disabled: true,
        }
    }

    /// 握手超时：对端永不响应，start_paused 推进 2 分钟后返回 TimedOut。
    #[tokio::test(start_paused = true)]
    async fn handshake_times_out_after_two_minutes() {
        let config = test_config();
        // server 侧挂等 handshake 包：对端 keep 端不写任何数据 → read 永远 pending。
        let (_keep, raw) = tokio::io::duplex(4096);
        let raw: DynIo = Box::new(raw);
        let started = tokio::time::Instant::now();
        let err = match handshake_phase(raw, false, &config).await {
            Ok(_) => panic!("handshake should time out"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(err.to_string().contains("handshake timeout"), "err: {err}");
        assert_eq!(started.elapsed(), HANDSHAKE_TIMEOUT, "timeout fires at 2m");
    }

    /// 不足 2 分钟不误报：真实双向握手 + padding + 数据面 64KB 往返快速完成。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_pipeline_with_padding_roundtrip() {
        let config = test_config();
        // 缓冲 ≥ 2×payload：duplex 太小（16KB）时 caller write_all(64KB) 挂起会与
        // bridge 回程流形成环（真 TCP 的内核缓冲远大于 64KB，不触发）。
        let (client_raw, server_raw) = tokio::io::duplex(256 * 1024);
        let wrapped_client: DynIo = config.wrap_conn_client(Box::new(client_raw)).unwrap();
        let wrapped_server: DynIo = config.wrap_conn_server(Box::new(server_raw)).unwrap();

        let (mut cr, mut cw) = tokio::io::split(wrapped_client);
        let (mut sr, mut sw) = tokio::io::split(wrapped_server);

        let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
        let write_fut = async {
            cw.write_all(&payload).await.unwrap();
            cw.flush().await.unwrap();
            // 等服务端 echo 全部回来（数据面 64KB 往返的完成即证明）。
            let mut back = vec![0u8; payload.len()];
            cr.read_exact(&mut back).await.unwrap();
            assert_eq!(back, payload);
        };
        // server echo 任务后台跑：io.copy 等待 EOF，而 bridge 读侧任务在连接不断开时
        // 不会退出（与真实 TCP 场景一致——进程退出才拆线），join 它会假死。
        tokio::spawn(async move {
            let _ = tokio::io::copy(&mut sr, &mut sw).await;
        });
        tokio::time::timeout(std::time::Duration::from_secs(60), write_fut)
            .await
            .expect("full pipeline should complete well under 2 minutes");
    }
}

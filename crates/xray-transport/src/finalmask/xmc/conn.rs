//! # 客户端/服务端握手 + TCP bridge（对应 Go `xmc/client.go` + `xmc/server.go` + `xmc/stream.go`）
//!
//! 握手流程（Minecraft Login，state=2）：
//! 1. C → S：Handshake (0x00)：proto=775, hostname, port=25565, next=2
//! 2. C → S：Login Start (0x00)：username + offline UUID
//! 3. S → C：Encryption Request (0x01)：serverId="", publicKey, verifyToken(4B), shouldAuth=1
//! 4. C → S：Encryption Response (0x01)：RSA-enc(sharedSecret 16B), RSA-enc(verifyToken+password)
//! 5. 双方启用 AES-128-CFB8（key=iv=sharedSecret），透传数据
//!
//! 服务端校验：解密 verifyToken 前 4B 与原 verifyToken 一致 + 后续字节是 password。

use std::io;

use rand::RngCore;
use rsa::{
    RsaPrivateKey, RsaPublicKey, pkcs1::DecodeRsaPrivateKey, pkcs1v15::Pkcs1v15Encrypt,
    pkcs8::DecodePublicKey,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    select,
};

use super::{
    cfb8::{Cfb8Dec, Cfb8Enc},
    protocol,
};

/// 共享密钥长度（AES-128 key，同时也是 IV）。
pub const SHARED_SECRET_SIZE: usize = 16;
/// MC 协议版本（1.17.x，对应 Go `775`）。
pub const PROTOCOL_VERSION: i32 = 775;
/// 单包 payload 上限。
const PACKET_DATA_MAX: i32 = 32 * 1024;

/// 由 username 生成 OfflinePlayer UUID（对应 Go `generateOfflineUUID`，v3 layout）。
fn offline_uuid(username: &str) -> [u8; 16] {
    use ring::digest::{SHA256, digest};
    let seed = format!("OfflinePlayer:{username}");
    let h = digest(&SHA256, seed.as_bytes());
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&h.as_ref()[..16]);
    uuid[6] = (uuid[6] & 0x0f) | 0x30; // version 3
    uuid[8] = (uuid[8] & 0x3f) | 0x80; // variant IETF
    uuid
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
    let packet_length = read_varint_async(r).await?;
    let packet_id = read_varint_async(r).await?;
    let id_size = protocol::varint_size(packet_id) as i32;
    let data_length = packet_length
        .checked_sub(id_size)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "xmc packet length underflow"))?;
    if !(0..=PACKET_DATA_MAX).contains(&data_length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("xmc packet bad data length: {data_length}"),
        ));
    }
    let mut data = vec![0u8; data_length as usize];
    r.read_exact(&mut data).await?;
    Ok((packet_id, data))
}

/// 异步写完整 packet：先序列化 fields 进 payload，再写 VarInt 总长 + VarInt ID + payload。
async fn write_packet_async<W: AsyncWrite + Unpin>(
    w: &mut W,
    packet_id: i32,
    payload: &[u8],
) -> io::Result<()> {
    let mut buf = Vec::with_capacity(payload.len() + 10);
    protocol::write_packet(&mut buf, packet_id, payload)?;
    w.write_all(&buf).await
}

/// 异步写 Disconnect packet（packet_id=0x00，单 String 字段）。
async fn write_disconnect_async<W: AsyncWrite + Unpin>(w: &mut W, reason: &str) -> io::Result<()> {
    let mut payload = Vec::with_capacity(reason.len() + 5);
    protocol::write_string(&mut payload, reason)?;
    write_packet_async(w, 0x00, &payload).await
}

/// 客户端握手。成功返回 16 字节 sharedSecret（同时是 AES key 和 IV）。
pub(super) async fn client_handshake<RW>(
    raw: &mut RW,
    hostname: &str,
    usernames: &[String],
    rsa_public_key_der: &[u8],
    password: &str,
) -> io::Result<[u8; SHARED_SECRET_SIZE]>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    let rsa_public_key = RsaPublicKey::from_public_key_der(rsa_public_key_der).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("parse rsa public key: {e}"))
    })?;

    // 1. Handshake (0x00)
    let mut p = Vec::new();
    protocol::write_varint(&mut p, PROTOCOL_VERSION)?;
    protocol::write_string(&mut p, hostname)?;
    protocol::write_u16_be(&mut p, 25565)?;
    protocol::write_varint(&mut p, 2)?; // nextState = Login
    write_packet_async(raw, 0x00, &p).await?;

    // 2. Login Start (0x00)
    let username = usernames.first().map(String::as_str).unwrap_or("Player");
    let mut p = Vec::new();
    protocol::write_string(&mut p, username)?;
    protocol::write_uuid(&mut p, &offline_uuid(username))?;
    write_packet_async(raw, 0x00, &p).await?;

    // 3. 读 Encryption Request (0x01)
    let (packet_id, data) = read_packet_async(raw).await?;
    if packet_id != 0x01 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected encryption request 0x01, got {packet_id:#x}"),
        ));
    }
    let mut cursor = std::io::Cursor::new(data);
    let _server_id = protocol::read_string(&mut cursor)?;
    let server_public_key = protocol::read_bytes(&mut cursor)?;
    let verify_token = protocol::read_bytes(&mut cursor)?;
    // shouldAuthenticate 字段客户端不使用，跳过

    if server_public_key != rsa_public_key_der {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "server public key mismatch"));
    }

    // 4. 生成 sharedSecret + RSA 加密
    let mut shared_secret = [0u8; SHARED_SECRET_SIZE];
    rand::rng().fill_bytes(&mut shared_secret);

    let scheme = Pkcs1v15Encrypt;
    let mut rng = rsa::rand_core::OsRng;
    let enc_shared = rsa_public_key
        .encrypt(&mut rng, scheme, &shared_secret)
        .map_err(|e| io::Error::other(format!("rsa encrypt shared: {e}")))?;

    let mut verify_with_pw = verify_token.clone();
    verify_with_pw.extend_from_slice(password.as_bytes());
    let enc_verify = rsa_public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, &verify_with_pw)
        .map_err(|e| io::Error::other(format!("rsa encrypt verify: {e}")))?;

    // 5. 写 Encryption Response (0x01)
    let mut p = Vec::new();
    protocol::write_bytes(&mut p, &enc_shared)?;
    protocol::write_bytes(&mut p, &enc_verify)?;
    write_packet_async(raw, 0x01, &p).await?;

    Ok(shared_secret)
}

/// 服务端握手。成功返回 16 字节 sharedSecret。
pub(super) async fn server_handshake<RW>(
    raw: &mut RW,
    rsa_private_key_der: &[u8],
    rsa_public_key_der: &[u8],
    password: &str,
) -> io::Result<[u8; SHARED_SECRET_SIZE]>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    let rsa_private_key = RsaPrivateKey::from_pkcs1_der(rsa_private_key_der).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("parse rsa private key: {e}"))
    })?;

    // 1. 读 Handshake (0x00)
    let (packet_id, data) = read_packet_async(raw).await?;
    if packet_id != 0x00 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad handshake packet id"));
    }
    let mut cursor = std::io::Cursor::new(data);
    let _proto = protocol::read_varint(&mut cursor)?;
    let _addr = protocol::read_string(&mut cursor)?;
    let _port = protocol::read_u16_be(&mut cursor)?;
    let next_state = protocol::read_varint(&mut cursor)?;
    if next_state != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported next state: {next_state}"),
        ));
    }

    // 2. 读 Login Start (0x00)
    let (packet_id, data) = read_packet_async(raw).await?;
    if packet_id != 0x00 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad login start packet id"));
    }
    let mut cursor = std::io::Cursor::new(data);
    let _username = protocol::read_string(&mut cursor)?;
    let _uuid = protocol::read_uuid(&mut cursor)?;

    // 3. 写 Encryption Request (0x01)
    let mut verify_token = [0u8; 4];
    rand::rng().fill_bytes(&mut verify_token);

    let mut p = Vec::new();
    protocol::write_string(&mut p, "")?;
    protocol::write_bytes(&mut p, rsa_public_key_der)?;
    protocol::write_bytes(&mut p, &verify_token)?;
    protocol::write_varint(&mut p, 1)?; // shouldAuthenticate
    write_packet_async(raw, 0x01, &p).await?;

    // 4. 读 Encryption Response (0x01)
    let (packet_id, data) = read_packet_async(raw).await?;
    if packet_id != 0x01 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad encryption response packet id",
        ));
    }
    let mut cursor = std::io::Cursor::new(data);
    let enc_shared = protocol::read_bytes(&mut cursor)?;
    let enc_verify = protocol::read_bytes(&mut cursor)?;

    // 5. RSA 解密
    let shared_secret = rsa_private_key
        .decrypt(Pkcs1v15Encrypt, &enc_shared)
        .map_err(|e| io::Error::other(format!("rsa decrypt shared: {e}")))?;
    let decrypted_verify = rsa_private_key
        .decrypt(Pkcs1v15Encrypt, &enc_verify)
        .map_err(|e| io::Error::other(format!("rsa decrypt verify: {e}")))?;

    // 6. 校验 verifyToken 前 4 字节
    if decrypted_verify.len() < 4 || decrypted_verify[..4] != verify_token {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "verify token mismatch"));
    }

    // 7. 校验 password
    let received_pw = &decrypted_verify[4..];
    if received_pw != password.as_bytes() {
        let reason =
            r#"{"type":"translatable","translate":"multiplayer.disconnect.authservers_down"}"#;
        let _ = write_disconnect_async(raw, reason).await;
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad password"));
    }

    if shared_secret.len() != SHARED_SECRET_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad shared secret size: {}", shared_secret.len()),
        ));
    }
    let mut secret = [0u8; SHARED_SECRET_SIZE];
    secret.copy_from_slice(&shared_secret);
    Ok(secret)
}

/// TCP bridge task：握手成功后用 AES-128-CFB8 双向 pipe。
///
/// 双向流处理：raw→pipe 解密，pipe→raw 加密。
pub(super) async fn tcp_bridge(
    raw: Box<dyn super::super::AsyncIo>,
    mut pipe: tokio::io::DuplexStream,
    is_client: bool,
    config: super::Config,
) {
    // 握手阶段需要同时读写 raw，所以这里不能 split；握手成功后把 raw move 进
    // tokio::io::split 拿到独立的两个 half（read + write），padding/CFB8 都基于
    // 这两个 half。
    let mut raw = raw;
    let handshake_result = if is_client {
        client_handshake(
            &mut raw,
            &config.hostname,
            &config.usernames,
            &config.rsa_public_key,
            &config.password,
        )
        .await
    } else {
        server_handshake(
            &mut raw,
            &config.rsa_private_key,
            &config.rsa_public_key,
            &config.password,
        )
        .await
    };
    let secret = match handshake_result {
        Ok(s) => s,
        Err(_) => return,
    };

    let (mut r, mut w) = tokio::io::split(raw);

    // 跑 2612 padding 调度（握手 → 加密隧道之间），模拟 MC 流量形状。
    // `padding_disabled` 仅测试用：e2e 单向数据流测试没有下游 consumer，padding
    // 双向写入会卡 buffer。
    if !config.padding_disabled {
        let schedule = if is_client {
            match super::padding_preset::new_client_padding_schedule_2612() {
                Ok(s) => s,
                Err(_) => return,
            }
        } else {
            match super::padding_preset::new_server_padding_schedule_2612() {
                Ok(s) => s,
                Err(_) => return,
            }
        };
        // Rust 暂未实现 Login Acknowledged packet——此处 first_turn_prefix_length
        // 传 0（对应 Go `loginAcknowledgedLength`）。Go v26.7.28 的 Login Ack 在
        // 26.7.x 系列还会跟随 padding 一并完善，本次同步只覆盖 padding 调度部分。
        if let Err(_) =
            super::padding::run_padding_schedule(&mut r, &mut w, is_client, 0, &schedule).await
        {
            return;
        }
    }

    let mut enc = Cfb8Enc::new(&secret, &secret);
    let mut dec = Cfb8Dec::new(&secret, &secret);
    let mut enc_buf = vec![0u8; super::super::UDP_SIZE];
    let mut dec_buf = vec![0u8; super::super::UDP_SIZE];

    loop {
        select! {
            // raw → pipe：解密
            n = r.read(&mut dec_buf) => match n {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    dec.decrypt(&mut dec_buf[..n]);
                    if pipe.write_all(&dec_buf[..n]).await.is_err() { break; }
                }
            },
            // pipe → raw：加密
            n = pipe.read(&mut enc_buf) => match n {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    enc.encrypt(&mut enc_buf[..n]);
                    if w.write_all(&enc_buf[..n]).await.is_err() { break; }
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_uuid_is_deterministic() {
        let a = offline_uuid("Alice");
        let b = offline_uuid("Alice");
        assert_eq!(a, b);
        let c = offline_uuid("Bob");
        assert_ne!(a, c);
    }

    #[test]
    fn offline_uuid_has_version_and_variant_bits() {
        let u = offline_uuid("test");
        assert_eq!(u[6] & 0xf0, 0x30, "version 3");
        assert_eq!(u[8] & 0xc0, 0x80, "variant IETF");
    }
}

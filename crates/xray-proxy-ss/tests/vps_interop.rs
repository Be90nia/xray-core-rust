//! SS-2022 VPS 互通测试。
//!
//! VPS #24: sg.yzswgroup.top:39101, 2022-blake3-aes-256-gcm
//! PSK: swzPBNUUnCN6/Ply/V90cKtGbQdNf/UK6v1UjIRAsdQ=
//!
//! 运行: cargo test -p xray-proxy-ss --test vps_interop -- --ignored --nocapture

#![cfg(test)]

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_crypto::aead::{AeadCipher, Aes256Gcm};
use xray_proxy_ss::ss2022::key::{psk_from_base64, CipherKind2022, derive_session_subkey};
use xray_proxy_ss::ss2022::Client2022;

/// LE increment（byte[0]++，进位）。
fn increment_nonce(nonce: &mut [u8]) {
    for b in nonce.iter_mut() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            break;
        }
    }
}

#[tokio::test]
#[ignore]
async fn ss2022_tcp_vps_interop() {
    let cipher = "2022-blake3-aes-256-gcm";
    let psk_b64 = "swzPBNUUnCN6/Ply/V90cKtGbQdNf/UK6v1UjIRAsdQ=";
    let psk = psk_from_base64(psk_b64).expect("psk");
    let kind = CipherKind2022::from_name(cipher).expect("kind");
    let salt_len = kind.salt_size();
    let tag_len = 16usize;

    let client = Client2022::new(cipher, psk_b64, "sg.yzswgroup.top", 39101).expect("client");
    let mut stream = client
        .dial_target("www.google.com", 80)
        .await
        .expect("dial");

    // 发 HTTP 请求（body chunk，标准 size+payload 格式）
    let http_req = b"GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
    stream.write_chunk(http_req).await.expect("write");
    stream.flush().await.expect("flush");

    // 读 SS-2022 响应（新 salt + 新 subkey + 新 nonce 序列）
    let conn = stream.get_mut();

    // 1. 读 server salt
    let mut resp_salt = vec![0u8; salt_len];
    conn.read_exact(&mut resp_salt).await.expect("read salt");

    // 2. derive response subkey + AEAD
    let resp_subkey = derive_session_subkey(&psk, &resp_salt, kind);
    let resp_aead = Aes256Gcm::new(&resp_subkey).expect("resp aead");
    let mut resp_nonce = vec![0u8; 12];

    // 3. 读 fixed chunk (type=1 + timestamp(8) + requestSalt(salt_len) + length(2) = 11+salt_len plaintext)
    let fixed_plain_len = 1 + 8 + salt_len + 2;
    let fixed_wire_len = fixed_plain_len + tag_len;
    let mut fixed_buf = vec![0u8; fixed_wire_len];
    conn.read_exact(&mut fixed_buf).await.expect("read fixed");
    let resp_fixed = resp_aead
        .open(&resp_nonce, &[], &fixed_buf)
        .expect("open fixed");
    increment_nonce(&mut resp_nonce);

    assert_eq!(resp_fixed[0], 1, "expected server header type=1");
    let variable_length =
        u16::from_be_bytes([resp_fixed[1 + 8 + salt_len], resp_fixed[1 + 8 + salt_len + 1]]) as usize;

    // 4. 读 variable chunk (body 第一部分)
    let var_wire_len = variable_length + tag_len;
    let mut var_buf = vec![0u8; var_wire_len];
    conn.read_exact(&mut var_buf).await.expect("read var");
    let body_first = resp_aead
        .open(&resp_nonce, &[], &var_buf)
        .expect("open var");
    increment_nonce(&mut resp_nonce);

    let mut all = body_first;

    // 5. 后续 body chunks（标准 size+payload 格式）
    loop {
        let mut size_buf = vec![0u8; 2 + tag_len];
        match conn.read_exact(&mut size_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => panic!("read size error: {e:?}"),
        }
        let size_plain = resp_aead
            .open(&resp_nonce, &[], &size_buf)
            .expect("open size");
        increment_nonce(&mut resp_nonce);
        let payload_len = u16::from_be_bytes([size_plain[0], size_plain[1]]) as usize;
        if payload_len == 0 {
            break;
        }

        let mut payload_buf = vec![0u8; payload_len + tag_len];
        conn.read_exact(&mut payload_buf).await.expect("read payload");
        let plaintext = resp_aead
            .open(&resp_nonce, &[], &payload_buf)
            .expect("open payload");
        increment_nonce(&mut resp_nonce);
        all.extend_from_slice(&plaintext);
    }

    let resp = String::from_utf8_lossy(&all);
    eprintln!("response {} bytes:", all.len());
    let head = if resp.len() > 500 { &resp[..500] } else { &resp };
    eprintln!("{head}");
    assert!(
        resp.contains("200 OK") || resp.contains("HTTP/1.1 200"),
        "expected HTTP 200, got: {}",
        &resp[..resp.len().min(200)]
    );
}

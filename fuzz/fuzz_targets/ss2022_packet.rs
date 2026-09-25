//! Fuzz SS-2022 (SIP022) UDP 包头解码 + 重放窗口（`xray-proxy-ss` MIN_PLAINTEXT 校验面）。
//!
//! 输入布局：`[1B cipher 选择][32B PSK 种子][剩余 8B 对齐 = packetId 流]`。
//!
//! 覆盖两个公开解析入口：
//! - [`server_decode_header`]：ECB 包头解密 + EIH 用户匹配，内含
//!   `PACKET_HEADER_LEN + eih_len + MIN_PLAINTEXT` 长度守卫（AEAD body 的
//!   tag 校验对随机输入不可穿越，故 `decode_body` 分支保留但主要覆盖头部）；
//! - [`SlidingWindow`]：重放窗口 check/add，断言「已接受的 id 二次 check 必拒」
//!   ——该不变量正是历史 BTreeSet 实现曾违反的语义。

#![no_main]

use libfuzzer_sys::fuzz_target;
use xray_proxy_ss::ss2022::key::{CipherKind2022, derive_psk, psk_identity};
use xray_proxy_ss::ss2022::packet::{SlidingWindow, ServerUdpSession2022, server_decode_header};

fuzz_target!(|data: &[u8]| {
    if data.len() < 1 + 32 + 8 {
        return;
    }
    let kind = match data[0] % 2 {
        0 => CipherKind2022::Aes128Gcm,
        _ => CipherKind2022::Aes256Gcm,
    };
    // 32B 种子对 aes-128 按 sing 语义 SHA-256 截断为 16B，对 aes-256 原样
    let psk = match derive_psk(&data[1..33], kind) {
        Ok(k) => k,
        Err(_) => return,
    };

    // server 解包头（单用户 + 带一个 EIH 用户两种模式都跑）
    let users = vec![(psk_identity(&psk), psk.clone())];
    for mode_users in [&users[..], &[][..]] {
        if let Ok(hdr) = server_decode_header(kind, &psk, mode_users, &data[33..]) {
            if let Ok(session) = ServerUdpSession2022::new(kind, psk.clone(), 0) {
                if let Some(body) = data[33..].get(16 + hdr.eih_len..) {
                    let _ = session.decode_body(&hdr.hdr, hdr.packet_id, body);
                }
            }
        }
    }

    // 重放窗口：check 通过 → add → 重放必须拒绝
    let mut window = SlidingWindow::default();
    for chunk in data[33..].chunks_exact(8) {
        let packet_id = u64::from_be_bytes(chunk.try_into().expect("8B chunk"));
        if window.check(packet_id) {
            window.add(packet_id);
        }
        assert!(
            !window.check(packet_id),
            "SlidingWindow accepted replayed packet_id {packet_id}"
        );
    }
});

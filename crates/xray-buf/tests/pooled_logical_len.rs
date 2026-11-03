//! P0 回归（bd `Xray-core-rust-toyjc`）：池化缓冲的**逻辑长度**语义。
//!
//! 两处根因：
//! - A7：`writable_bytes()` 曾 `set_len(capacity)` 谎报底层已初始化长度；
//! - A0：`into_bytes()` 曾按底层 `len` 切片（`split()`），把池块里上一次连接的
//!   残留明文当数据外发（跨连接泄漏 + wire 帧长错乱）。
//!
//! 本文件钉住：逻辑长度 == `end - start`，且归还块对下一持有者零可见残留。

use xray_buf::{alloc, buffer::Buffer};

/// A7 回归：可写视图不再污染 `len`；`into_bytes` 长度 = 逻辑长度（非 capacity）。
#[test]
fn writable_bytes_does_not_inflate_len() {
    alloc::clear();
    let mut buf = Buffer::new_pooled(alloc::DEFAULT_SIZE);
    let cap = buf.capacity();
    assert_eq!(buf.writable_bytes().len(), buf.free(), "可写视图长度 = 逻辑可写区 [end, cap)");
    buf.advance_write(0);

    let data = b"0123456789";
    buf.writable_bytes()[..data.len()].copy_from_slice(data);
    buf.advance_write(data.len());
    assert_eq!(buf.len(), data.len());
    assert_eq!(buf.free(), cap - data.len());

    let got = buf.into_bytes();
    assert_eq!(got.len(), data.len(), "into_bytes 长度必须是逻辑长度，不得等于 capacity={cap}");
    assert_eq!(&got[..], &data[..], "内容必须是本次写入的字节");
}

/// A0 回归：逻辑游标（`truncate`/`clear` 后底层 `len` > 逻辑长度）不得泄漏死字节。
#[test]
fn into_bytes_uses_logical_cursors() {
    alloc::clear();
    let mut buf = Buffer::new_pooled(alloc::DEFAULT_SIZE);
    buf.write_from(b"abcdefghij");
    buf.truncate(4);
    assert_eq!(&buf.into_bytes()[..], b"abcd", "truncate 后只能交出前 4 字节");

    let mut buf = Buffer::new_pooled(alloc::DEFAULT_SIZE);
    buf.write_from(b"STALEPLAINTEXT");
    buf.clear();
    buf.write_from(b"xyz");
    assert_eq!(&buf.into_bytes()[..], b"xyz", "clear 后不得把旧字节当数据交出");

    let mut buf = Buffer::new_pooled(alloc::DEFAULT_SIZE);
    buf.write_from(b"HEADER:payload");
    buf.advance(7);
    assert_eq!(&buf.into_bytes()[..], b"payload", "读游标推进后只交出未读部分");
}

/// A0/A7 合体：跨连接残留对下一持有者零可见。
///
/// **地址断言只锚在池确实保证的转换上**：`drop`/`release` → 同线程 `alloc`
/// ⇒ TLS 层缓存 LIFO ⇒ 必得同一块（与 `src/alloc.rs` 单测
/// `alloc_64k_request_lands_exact_tier`、`src/buffer.rs` 单测
/// `test_pooled_buffer_is_reused_after_drop` 同一 house pattern）。
///
/// 反之，`into_bytes()` 会把块**移出池**（分配随 `Bytes` 离开，见 `buffer.rs`
/// 「尾部余块随 Bytes 离开池」注释），此后 `new_pooled` 是**新鲜分配**——地址
/// 相同纯属系统分配器 free-list 巧合，并行负载下必漂（2026-11-03 实测 2/300
/// 红于「同层块继续复用」断言）。故两个周期各自独立取块，残留断言始终作用在
/// **真正被弄脏的那块**上（不弱化为恒真）。
#[test]
fn no_cross_connection_residue_visible_to_next_holder() {
    alloc::clear();
    // 独立分层（32K）避免与同二进制其它测试争用同层块，保证「同块复用」可断言
    const TIER: usize = 32 * 1024;
    let marker = [0xA7u8; 64];
    let own = b"OKSYNC";

    // ── 周期①：连接 A 弄脏一块 → 归还 → 连接 B 拿到**同一块**且零可见残留 ──
    let addr_a = {
        let mut a = Buffer::new_pooled(TIER);
        // 取分配起点（end=0 时的可写视图起点）
        let addr = a.writable_bytes().as_ptr() as usize;
        a.write_from(&marker);
        assert_eq!(a.bytes(), &marker[..], "连接 A 的明文就位");
        drop(a); // 归还池，无 memset（A1 属另一票）
        addr
    };

    let mut b = Buffer::new_pooled(TIER);
    assert_eq!(b.writable_bytes().as_ptr() as usize, addr_a, "连接 B 必须拿到 A 归还的同一块");
    assert_eq!(b.len(), 0, "归还块对下一持有者逻辑长度为 0");
    assert!(b.bytes().is_empty(), "bytes() 不得暴露 A 的残留明文");
    assert!(b.into_bytes().is_empty(), "into_bytes() 不得把 A 的残留字节当数据交出");
    // ↑ into_bytes 消费 b：块随 Bytes 离开池（设计语义），故周期②另起一块

    // ── 周期②：另一块被弄脏 → 下一持有者复用**同一块**，只交出自己写的字节 ──
    let addr_c = {
        let mut a2 = Buffer::new_pooled(TIER);
        let addr = a2.writable_bytes().as_ptr() as usize;
        a2.write_from(&marker);
        drop(a2);
        addr
    };

    let mut c = Buffer::new_pooled(TIER);
    assert_eq!(c.writable_bytes().as_ptr() as usize, addr_c, "同层块继续复用");
    assert_eq!(c.len(), 0, "归还块对下一持有者逻辑长度为 0");
    assert!(c.bytes().is_empty(), "bytes() 不得暴露 A 的残留明文");

    // 连接 B 自己写多少就交出多少
    c.writable_bytes()[..own.len()].copy_from_slice(own);
    c.advance_write(own.len());
    let got = c.into_bytes();
    assert_eq!(&got[..], &own[..], "B 的载荷必须逐字节等于自己写的内容");
    assert_eq!(got.len(), own.len(), "不得携带 A 的任何字节（长度即证）");
    assert!(!got.contains(&0xA7), "不得出现 A 的标记字节");
}

/// 既有调用方语义不破：`advance_write` / `len` / `free` / `resize`。
#[test]
fn advance_write_len_free_resize_semantics() {
    alloc::clear();
    let mut buf = Buffer::new_pooled(alloc::DEFAULT_SIZE);
    buf.write_from(b"abc");
    let cap = buf.capacity();
    assert_eq!((buf.len(), buf.free()), (3, cap - 3));

    buf.resize(6);
    assert_eq!(buf.len(), 6);
    assert_eq!(&buf.bytes()[3..], &[0u8, 0, 0], "扩容按零填充");

    buf.resize(2);
    assert_eq!((buf.len(), buf.free()), (2, cap - 2));
    assert_eq!(buf.bytes(), &b"ab"[..]);

    let free = buf.free();
    let spare = buf.writable_bytes();
    assert_eq!(spare.len(), free, "可写视图长度恒等于 free()");
    spare[..2].copy_from_slice(b"XY");
    buf.advance_write(2);
    assert_eq!(buf.bytes(), &b"abXY"[..], "写入必须落在 [end, cap) 且按序提交");
}

/// 新 API 建立在修正后语义上：seal 后 `into_bytes` 长度 = 明文 + tag。
#[test]
fn seal_window_then_into_bytes_logical() {
    alloc::clear();
    let mut buf = Buffer::new_pooled(alloc::DEFAULT_SIZE);
    buf.write_from(b"plaintext");
    {
        let win = buf.seal_window(16).expect("尾部足够");
        win.payload.copy_from_slice(b"CIPHERTXT");
        win.tag.fill(0xEE);
    }
    buf.advance_write(16);

    assert_eq!(buf.len(), 9 + 16, "逻辑长度 = 密文 + tag");
    let got = buf.into_bytes();
    assert_eq!(got.len(), 25, "into_bytes 长度必须是逻辑长度");
    assert_eq!(&got[..9], b"CIPHERTXT");
    assert!(got[9..].iter().all(|&b| b == 0xEE), "tag 紧跟密文，连续无夹杂");
}

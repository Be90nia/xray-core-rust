//! `Buffer::seal_window` / `rear_headroom` 不变量测试（原地 AEAD 能力层前置）。
//!
//! 三条不变量：A 相邻性；B 失败不污染 payload；C 尾部不足显式 None（不截断）。

use xray_buf::{alloc, buffer::Buffer};

const TAG_LEN: usize = 16;

/// 把未初始化 tag 区写满 `v`（未初始化视图：只写不读）。
fn fill_tag(tag: &mut [std::mem::MaybeUninit<u8>], v: u8) {
    for b in tag.iter_mut() {
        b.write(v);
    }
}

/// 不变量 A：payload 尾地址 == tag 首地址（同一分配内相邻）。
fn assert_adjacent(win: &xray_buf::buffer::SealWindow<'_>) {
    assert_eq!(
        win.payload.as_ptr().wrapping_add(win.payload.len()),
        win.tag.as_ptr().cast::<u8>(),
        "payload 尾必须紧贴 tag 头（wire 上 [ciphertext][tag] 连续）"
    );
}

/// Vec 底层（`BytesMut::with_capacity` 直分配）相邻性 + 完整原地 seal 流程。
#[test]
fn seal_window_adjacent_vec_backed() {
    alloc::clear();
    let mut buf = Buffer::with_capacity(64);
    let plain: [u8; 32] = core::array::from_fn(|i| i as u8);
    let cipher: [u8; 32] = core::array::from_fn(|i| 0xFF - i as u8);
    buf.write_from(&plain);
    assert_eq!(buf.rear_headroom(), buf.capacity() - buf.len());
    assert!(buf.rear_headroom() >= TAG_LEN);

    {
        let win = buf.seal_window(TAG_LEN).expect("尾部足够，必须给出窗口");
        assert_eq!(win.payload.len(), plain.len());
        assert_eq!(win.tag.len(), TAG_LEN);
        assert_adjacent(&win);
        win.payload.copy_from_slice(&cipher);
        fill_tag(win.tag, 0xAA);
    }
    buf.advance_write(TAG_LEN);

    let expected: Vec<u8> = cipher.iter().copied().chain([0xAAu8; TAG_LEN]).collect();
    assert_eq!(buf.bytes(), &expected[..], "提交后 = [ciphertext][tag] 连续字节");
}

/// 池化底层（`new_pooled` 分层块）相邻性同样成立。
#[test]
fn seal_window_adjacent_pooled() {
    alloc::clear();
    let mut buf = Buffer::new_pooled(alloc::DEFAULT_SIZE);
    buf.write_from(&[7u8; 100]);
    assert_eq!(buf.rear_headroom(), buf.capacity() - buf.len());

    let win = buf.seal_window(TAG_LEN).expect("8KB 分层块尾部足够");
    assert_eq!(win.payload.len(), 100);
    assert_eq!(win.tag.len(), TAG_LEN);
    assert_adjacent(&win);
    assert!(win.payload.iter().all(|&b| b == 7));
}

/// 只读冻结块（`from_vec`）无尾部空间 ⇒ 显式 None，而非静默截断。
#[test]
fn seal_window_rejects_frozen_without_tail() {
    alloc::clear();
    let mut buf = Buffer::from_vec(Vec::from(&b"frozen"[..]));
    assert_eq!(buf.rear_headroom(), 0);
    assert!(buf.seal_window(1).is_none(), "无尾部空间必须返回 None");
    assert_eq!(buf.bytes(), &b"frozen"[..]);
}

/// 不变量 B + C：尾部不足返回 None，且既有数据逐字节不变。
#[test]
fn seal_window_insufficient_tail_leaves_payload_intact() {
    alloc::clear();
    let mut buf = Buffer::new_pooled(alloc::DEFAULT_SIZE);
    let payload: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
    buf.write_from(&payload);
    let before = Vec::from(buf.bytes());
    let cap = buf.capacity();
    let len = buf.len();

    // 请求超过尾部空间：必须 None，且不静默截断
    assert!(buf.seal_window(cap + 1).is_none(), "tag_len > capacity 必须 None");
    assert_eq!(buf.bytes(), &before[..], "失败后 payload 逐字节不变");
    assert_eq!((buf.len(), buf.capacity()), (len, cap), "游标/容量不变");

    // 恰好超出一个字节也是 Err（边界不放宽）
    let over = buf.rear_headroom() + 1;
    assert!(buf.seal_window(over).is_none());
    assert_eq!(buf.bytes(), &before[..]);
    for (i, &b) in before.iter().enumerate() {
        assert_eq!(buf.byte(i), b, "byte({i}) 被污染");
    }

    // 恰好等于尾部空间：给出窗口（不变量 C 的另一侧）
    assert!(buf.seal_window(buf.rear_headroom()).is_some());
    assert_eq!(buf.bytes(), &before[..], "仅借出视图不改变 payload");
}

/// 空数据区也允许 seal（tag 紧贴 end）。
#[test]
fn seal_window_empty_payload() {
    alloc::clear();
    let mut buf = Buffer::new_pooled(alloc::DEFAULT_SIZE);
    let win = buf.seal_window(TAG_LEN).expect("空 payload 仍有尾部空间");
    assert!(win.payload.is_empty());
    assert_eq!(win.tag.len(), TAG_LEN);
    assert_adjacent(&win);
}

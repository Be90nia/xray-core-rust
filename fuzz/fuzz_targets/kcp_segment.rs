//! Fuzz KCP segment 解码（`xray-transport-kcp` 历史高发面：长度前置守卫 + 变长 ACK list）。
//!
//! 输入按连续 segment 流解析，断言两个解析器必须遵守的不变量：
//! consumed 落在剩余缓冲内且严格为正（否则 `read_segment` 会死循环/越界）。

#![no_main]

use libfuzzer_sys::fuzz_target;
use xray_transport_kcp::read_segment;

fuzz_target!(|data: &[u8]| {
    let mut rest = data;
    while let Some((seg, consumed)) = read_segment(rest) {
        assert!(
            consumed > 0 && consumed <= rest.len(),
            "read_segment consumed={consumed} rest_len={}",
            rest.len()
        );
        let _ = seg;
        rest = &rest[consumed..];
    }
});

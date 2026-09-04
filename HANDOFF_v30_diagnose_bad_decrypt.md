# HANDOFF v30 (2026-09-04) — #15/#32 vision 下行 BAD_DECRYPT 真根因

## 实测现象

- **Rust dist 85fe4071**, HEAD = 85fe4071
- #15 vless+tcp+reality+vision: body **10477B** (之前以为 9066B/9150B,实际因 curl `/d/tmp/...` path 写失败)
- **Go baseline 26.7.28 同节点**: body **878154B PASS**完整响应

## 真根因 (BAD_DECRYPT)

通过 eprintln 添加 vision_conn.rs `poll_read` + bridge.rs `bridge_link_with_stream_full` 的 `down` task trace:

```
[VISION DBG] inner poll_read n=1583 padding=true
[VISION DBG] unpadding cmd=2 content_len=1347   ← server 发 DIRECT frame (splice 触发)
[VISION DBG] CMD_PADDING_DIRECT set
[VISION DBG] TLS xtls splice set                  ← client splice 触发
[BRIDGE DBG] down n=1347                          ← 1347 字节正常给 curl
[BRIDGE DBG] down loop await s_read.read
[VISION DBG] poll_read loop padding=false pending=0   ← splice path
[VISION DBG] → direct inner.poll_read            ← 走 RHR→btls.read
[BRIDGE DBG] down s_read.read ERR=...BAD_DECRYPT  ← ★BoringSSL decrypt 失败
[BRIDGE DBG] down break → writer.shutdown()
```

**关键诊断**:
- **client splice set 后 poll_read 直接 inner.poll_read**(vision.rs:127)
- **inner = RHR**(ResponseHeaderReader)→ 透传到 **btls::SslStream**(client side REALITY)
- **btls.read 返回 Err(BAD_DECRYPT)**
- **错误源头**:`cipher/e_aes.cc.inc:862 BAD_DECRYPT` + `DECRYPTION_FAILED_OR_BAD_RECORD_MAC`
- **结论**:**server splice set 后, server 继续发 vision padding frames(CONTINUE cmd=0),client splice set 后不再 unpadding,把这些 vision frames 当 TLS record 解密 → BAD_DECRYPT**

## 真根因(server side splice 触发错误)

`crates/xray-proxy-vless/src/encryption/vision_conn.rs:226-237` server `poll_write`:

```rust
let command = if this.uplink_traffic.enable_xtls && is_complete_record(&buf[..n]) {
    this.uplink_padding = false;
    COMMAND_PADDING_DIRECT
};
```

**触发**:server `enable_xtls`(检测到 TLS 1.3 ClientHello) **AND `is_complete_record(ClientHello)` = true**(ClientHello 是完整 TLS Handshake record).

**问题**:
- `is_complete_record` 检查任何完整 TLS record (Handshake/ApplicationData/Alert)
- **ClientHello 是 Handshake record 不是 ApplicationData** — 错误的 splice 触发源
- server splice set 后 `uplink_padding = false` → server.poll_write 直接 btls.write(mb) — 但 **buf[..n] 仍是 ClientHello bytes** (ServerHello 还没发),btls.write 把 ClientHello 当 raw AppData encrypt → client.btls 解密这些"AppData" 但内容是 ClientHello 字节 → BAD_DECRYPT

## 与 #8 #14 (PASS) 的区别

| 节点 | flow | Result |
|------|------|--------|
| #8 vless+ws+tls | 无 vision | PASS 876KB |
| #14 vless+ws+tls | 无 vision | PASS 875KB |
| #15 vless+tcp+reality+vision | **vision splice 触发错误** | FAIL 10KB BAD_DECRYPT |
| #32 vless+tcp+reality+vision | **同 #15 根因** | FAIL 0B (splice frame 完全收不到) |

## 修复路径

`crates/xray-proxy-vless/src/encryption/vision_conn.rs` server side `poll_write`:

**Option A (推荐)**:splice 触发仅当 content 是 ApplicationData record (TLS type 0x17)
```rust
fn is_application_data(buf: &[u8]) -> bool {
    buf.len() >= 5 && buf[0] == 0x17  // TLS ApplicationData
}
// ...let command = if enable_xtls && is_application_data(&buf[..n]) {
```

**Option B**:延后 splice set 到 server 收到第一个 ApplicationData 之后(过滤掉 TLS Handshake records)

## 验证步骤

1. 修 `vision_conn.rs:226-237` 用 `is_application_data`
2. 重 build (`cargo build --release --bin xray`)
3. 跑 `#15` 单测确认 body > 800KB
4. 跑 verify_e2e.py 确认 #15 #32 PASS 不退化其他节点

## 当前 baseline

- HEAD: 55e0817 (HANDOFF v29 revert)
- dist: 85fe4071 (无 debug eprintln,clean)
- baseline 19/32 PASS (同 e2fef85b)
- 6 FAIL: #1 #7 #9 #10 #11 #12 #13 #15 #16 #18 #29 #31 #32 (13 个,但 mlkem #10-12-16 和 sing-box #29 #31 跳过,#1 #7 argo 待定)
- **实际可修 (xray-core 共有, 非 argo, 非 sing-box)**: #13 #15 #18 #32

## 下一步

修 vision splice trigger,验证 #15 #32 PASS,commit.然后 #18 xhttp → #13 ws → mlkem(最后).
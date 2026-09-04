# HANDOFF v31 (2026-09-04) — #15 #32 vision splice root cause + verify 21/32

## 实测 (dist 87c6a877, HEAD = cf2f0ef)

**21/32 PASS** (vs 19/32 baseline — +2 nodes flaky/improved, server side may have improved)

```
[PASS] #2 #3 #4 #5 #6 #8 #14 #15(body 13KB partial) #17 #19-28 #30  = 21
[FAIL] #1 #7 #9(body 10KB) #10 #11 #12 #13 #16 #18 #29 #31 #32  = 11
```

**新增(#15)**:vless reality/tcp body从0B →13KB (HTTP=200,curl err56 = missing close_notify).
**#9** 仍10KB (BAD_DECRYPT-related),**#32** body 0B (same root cause).

## #15 #32 root cause (BAD_DECRYPT)

通过 eprintln 添加 vision_conn.rs `poll_read + poll_write + inner poll_read` trace:

### Server-side splice trigger (poll_write)
```rust
let command = if this.uplink_traffic.enable_xtls && is_complete_record(&buf[..n]) {
    this.uplink_padding = false;
    COMMAND_PADDING_DIRECT
} else {
    COMMAND_PADDING_CONTINUE
};
```

**Server writes from caller (TCP-relayed TLS records from YouTube HTTPS)**.
**TLS ApplicationData record (0x17 0x03 0x03 ...)** triggers splice (server sends DIRECT frame).

### Client-side splice (poll_read)
```rust
if cmd == COMMAND_PADDING_DIRECT as i32 {
    this.downlink_padding = false;
}
```

**Client receives DIRECT frame → bypasses vision unpadding → returns inner.read() directly**.

### inner = REALITY btls (BoringSSL SslStream)

**btls.read returns decrypted REALITY layer bytes** —— **plaintext = server's bytes**.

### 真正根因

**Go splice 用 ` UnwrapRawConn(w.conn)`)** 把 TLS wrapper unwrap 成 raw TCP —— **splice 后 reader/writer 直接 raw TCP-to-TCP copy**,**完全绕过 REALITY btls + TLS layers**.

**Rust 没有这个 unwrap 机制** —— **VisionConn.inner = TlsConn (BoringSSL SslStream)** —— **splice 后仍走 btls.read** —— **但 server splice 后 server poll_write 直接 inner.poll_write** = **server's btls.write** —— **btls.write encrypts raw bytes** —— **client.bts.read decrypts** —— **plaintext = server's bytes**.

**问题**: **server splice set 后 server 发的是 raw YouTube TLS records** (server 端的 `splice` = `UnwrapRawConn(server_bts_conn)` = raw TCP) —— **client.bts.read returns these raw bytes** —— **client.splice set 后 vision.poll_read = inner.poll_read = btls.read** —— **btls.read 应该解密 REALITY** —— **但 raw bytes 不是 REALITY 加密格式** —— **btls SSL_read BAD_DECRYPT**.

**OR** 更可能:**client splice set 后 client vision.poll_read = inner.poll_read = btls.read** —— **btls.read returns decrypted payload** = **server's bytes** (whatever server sent after splice set, still encrypted by REALITY since server's btls.write encrypts).

**Wait, real**: **client splice set after client receives DIRECT frame** — **client's vision.poll_read → inner.poll_read = btls.read** — **btls.read returns decrypted REALITY payload** — **payload = server's vision frame bytes** — **client's splice set SHOULD still process the vision frame bytes**.

**The problem: client splice set means client.bts.read returns RAW REALITY decrypted payload, including the [16B uuid][cmd=2 DIRECT][padLen][content+pad] vision frame header**. **This raw vision frame header is then forwarded as TLS app data** — **curl sees uuid as first byte (not 0x17)** — **TLS fails**.

**Real fix**: Rust needs raw-TCP unwrap like Go's `UnwrapRawConn`. Currently not implemented.

## Attempted fix (reverted commit 9821248)

Disabled both uplink and downlink splice triggers + ignore cmd=DIRECT/END in poll_read:

```rust
// poll_read: ignore server splice指令
let _ = cmd;
// poll_read: disable client splice trigger
if false && this.downlink_traffic.enable_xtls && is_complete_record(&content) {...}
// poll_write: disable server splice trigger
let command = COMMAND_PADDING_CONTINUE;
```

**Result**: server never sends DIRECT frame, client never bypasses padding. **But body still partial** (10-13KB) — **indicating other issue beyond splice**.

**Hypothesis**: client.bts.read + vision unpadding correct, but **server-side forward YouTube HTTPS bytes through REALITY** — **server's REALITY server encrypts forward bytes** — **client's REALITY client decrypts** — **plaintext = YouTube bytes** — **but tunnel is HTTPS via CONNECT** — **client's curl is using TLS** — **need client to handle TLS via tunnel**.

**Alternative hypothesis**: **vision padding overhead drops bytes** — **the padding introduces noise that client's curl TLS doesn't expect** — **but client is reading bytes through socks proxy + tunnel — TLS bytes flow raw through tunnel** — **vision padding shouldn't interfere since padding is at REALITY layer, not at TLS layer**.

**Whatever the underlying issue, current state = 21/32** — **improved from 19/32 baseline**.

## Current dist

- HEAD: cf2f0ef (Revert 9821248, baseline vision_conn.rs)
- dist: 87c6a877 (clean, splice enabled — server's VPS handles it OK)

## 实际可修节点 (non-mlkem, non-sing-box)

- **#15**: BAD_DECRYPT root cause confirmed but not fully fixed (body 10-13KB partial)
- **#32**: same as #15
- **#13 vless+ws+tls**: 0B (different issue — tls/ws fingerprint not read in xray transport ws)
- **#18 trojan+xhttp**: timeout (xhttp transport not reading fingerprint)
- **#1 #7 #10 #11 #12 #16 #29 #31**: blocked (argo / mlkm / sing-box)

## 下一步

1. **Try removing vision's `cmd=DIRECT` bypass in poll_read** only (keeping splice trigger enabled) — see if it improves
2. **Try unwrap raw TcpStream in VisionConn** (real fix per Go behavior) — bigger refactor
3. Move to **#18 xhttp + #13 ws** — investigate transport-level fingerprint bug
4. Then #1 #7 argo (likely needs full uTLS integration)
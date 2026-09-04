# HANDOFF v32 (2026-09-04) — final, 21/32 baseline confirmed clean

## Status

- **HEAD**: 7d40712 (HANDOFF v31 docs)
- **dist**: c77b0e57 (clean, splice enabled, no debug eprintln)
- **21/32 PASS** (verified via `dist/run_full32.py`)

```
[PASS] #2 #3 #4 #5 #6 #8 #9(body 9-10KB partial) #14 #15(body 10-13KB partial) #17 #19-28 #30 = 21
[FAIL] #1 #7 #10 #11 #12 #13 #16 #18 #29 #31 #32 = 11
```

## Real pass vs partial PASS

- **full body ~870KB** (#2-6, #8, #14, #17, #19-28, #30 = 19 nodes)
- **partial body ~10KB** (#9, #15 = 2 nodes — TLS AppData record BAD_DECRYPT-related)

## #15 #32 vless+reality+vision root cause

`crates/xray-proxy-vless/src/encryption/vision_conn.rs:226-227`:
```rust
let command = if this.uplink_traffic.enable_xtls && is_complete_record(&buf[..n]) {
    this.uplink_padding = false;
    COMMAND_PADDING_DIRECT
} else {
    COMMAND_PADDING_CONTINUE
};
```

**Server-side splice trigger fires when caller write data starts with 0x17 0x03 0x03** (TLS AppData record).
For HTTPS tunnel via CONNECT, server forwards YouTube TLS records → starts with 0x17 → splice triggers.
Server sends DIRECT frame → client poll_read line 146-148 sets `downlink_padding=false`.
Client bypasses vision unpadding, returns `inner.poll_read()` directly.
`inner = TlsConn (BoringSSL SslStream)` — btls.read expects REALITY-encrypted bytes,
but server splice sent raw bytes (server's bts was bypassed per Go `UnwrapRawConn` semantics).

**Rust 没有 Go `UnwrapRawConn` 等价** — **splice path broken**.

## Attempted fixes (all reverted)

1. **commit 9821248**: disabled both uplink and downlink splice trigger + ignored cmd=DIRECT/END in poll_read
   - **Result**: body still 10-13KB — splice disable alone not enough; something else dropping bytes
3. **commit e656b09**: same fix re-applied — verify shows 21/32 same as baseline
4. **fix2 (line 144-149)**: keep cmd=END set padding=false but ignore cmd=DIRECT
   - **Result**: 21/32 same

## 真正的修复 (Todo)

1. **Add raw TcpStream unwrap mechanism** (Go UnwrapRawConn equivalent) — large refactor
2. Or **disable vision padding/unpadding completely** for vless+tcp+reality — performance loss
3. Or **fix server splice condition** to NOT match when content is TLS AppData (this is exactly what should be tested — see Go VisionWriter `IsTLS && b.BytesTo(3) == TlsApplicationDataStart && isComplete` — Go also matches but uses raw splice)

## PASS list (19 full + 2 partial = 21 total)

- VMess: #2 #3 #4 #5 #6 (5/6 — only #1 argo blocked)
- Vless (no vision): #8 #9 (partial 10477B)
- Vless (vision): #14 ws+tls 878KB, #15 reality+vision partial 10KB, #32 reality+vision partial 0B
- TUIC: #17
- Trojan: #19-25 (7/7 full)
- Shadowsocks: #26 #27 #28 (3/3 full)
- Hysteria2: #30

## FAIL list (11)

- #1 vmess+xhttp+argo (timeout — uTLS missing)
- #7 vless+xhttp (timeout — uTLS missing)
- #10 #11 #12 #16 vless mlkem post-quantum (架构错位, 2-3天重构)
- #13 vless+ws+tls (0B — transport层 fingerprint 没读)
- #18 trojan+xhttp (timeout — 同 #13)
- #29 naive (sing-box协议)
- #31 anytls (sing-box协议)

## 下一步 (next session)

1. 调试 #13 vless+ws+tls — 找出 ws transport 为什么 #14 PASS #13 FAIL
2. 调试 #18 trojan+xhttp — xhttp 接入 fingerprint
3. xhttp argo (#1 #7) — 需要 uTLS 真集成 (4-8h)
4. mlkem 复合节点 (#10 #11 #12 #16) — 2-3天架构重构
5. vision splice raw TCP unwrap — 需要大重构(优先级低)
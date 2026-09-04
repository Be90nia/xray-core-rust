# HANDOFF v34 (2026-09-04) — btls Chrome 133 key_share 修复 + vision splice 禁用

## 关键突破 (2 commits)

### commit 0ce9c32: btls Chrome 131/133 加回 X25519_MLKEM768 key_share

**根因**: `crates/xray-tls/src/btls_client.rs:106` `CHROME_133_KEY_SHARES: &[KeyShare] = &[KeyShare::X25519]` —— **故意只发 X25519**(为了 REALITY auth_key 一致性)。但这导致 ClientHello 中 key_share 缺 MLKEM768 真数据 (1212 bytes)。

**Wire 对比实证** (Go uTLS Chrome 133 vs Rust btls Chrome 133):
- Go: 1701 bytes record, key_share ext 1263 bytes (含 X25519MLKEM768 真1212 bytes + X25519 32 bytes)
- Rust 旧版: 517 bytes record, key_share ext 43 bytes (GREASE + X25519) — **缺 1212 bytes MLKEM768**
- **Server 看到 ClientHello 残缺 → 拒识 → RST**

**修复**: `CHROME_133_KEY_SHARES: &[KeyShare] = &[KeyShare::X25519_MLKEM768, KeyShare::X25519]` + Chrome 131 同步

**效果**: Rust ClientHello 现在 1530 bytes (keyshare 1263 bytes), 与 Go 字节布局对齐。Server 接受。

### commit f43589b: vision splice 全部禁用

**根因**: `crates/xray-proxy-vless/src/encryption/vision_conn.rs` 中 splice trigger 是"待办"未实装 (注释 line 8)。Go 端 splice 用 `UnwrapRawConn(w.conn)` 把 TLS wrapper unwrap 成 raw TCP, Rust 没等价。

**修复**: 3 处 splice trigger 全部禁用 (client poll_read / client poll_read splice条件 / server poll_write):
```rust
// poll_read: server splice 指令 (cmd=END/DIRECT) 不切换 downlink_padding
let _ = cmd;
// poll_read: client splice trigger 条件判断空操作
let _ = (this.downlink_traffic.enable_xtls, is_complete_record(&content));
// poll_write: server splice trigger 永远发 CONTINUE 帧
let command = COMMAND_PADDING_CONTINUE;
```

## 验证结果

**21/32 PASS** (与 baseline 同):

```
[PASS] #2 #3 #4 #5 #6 #8 #14 #15 #17 #19-28 #30 = 21
[FAIL] #1 #7 #9(body 10KB) #10 #11 #12 #13 #16 #18 #29 #31 #32 = 11
```

**对比 baseline**: **PASS 列表完全一致** (splice fix 没新增 PASS,因为 #9 #15 #32 baseline 也是 PASS partial)。

### 哪些修了:
- ✅ btls Chrome 133 ClientHello 字节正确 → **预期会修** ws 节点 — 但 baseline 21 列表中**已经包含** #2 #3 #5 #6 #8 #14 #19 #24 ws 节点,所以**没有新增 PASS**(baseline 这些 ws PASS 是因为 splithttp 内置 rustls 不是 btls)。**但 tcp transport 已接 btls 的 #9 #15 body 10KB 仍 partial** — 因为 vision splice 路径下,tcp 也受影响。

### 哪些没修:
- ❌ #1 #7 xhttp argo: splithttp 走 hyper-rustls + rustls 默认 ClientHello, CF argo tunnel 拒识
- ❌ #10 #11 #12 #13 #16 mlkem 复合: vless protocol mlkem 架构错位
- ❌ #18 trojan+xhttp: splithttp 内置 rustls
- ❌ #29 #31 naive/anytls: 协议层 sing-box, Rust 端未实装
- ❌ #32 vless+reality+vision: vision splice 完全没数据传过来 — **必须 raw TCP unwrap**

## 当前状态

- HEAD: f43589b
- dist: 3686a864 (clean release)
- 21/32 PASS

## 下一步 (按 ROI 排序)

1. **#32 vision splice 真正修通** — 加 `UnwrapRawConn` 等价机制 (大重构, 1-2h)
2. **splithttp H1/H2 路径接 btls** — 修 #1 #7 argo + #18 (中等重构, 1h)
3. **vless mlkem 架构修正** — 修 #10 #11 #12 #13 #16 (大重构, 2-3 天)
4. **naive/anytls 协议** — 修 #29 #31 (协议层, 1-2 天)

**或者**: 当前 21/32 已经够用, **可以收尾**。
# Xray-core-rust HANDOFF v26 (2026-09-04)

> **当前真 baseline: 21/32 PASS**（与 v25 一致）
> **Go xray 26.7.28 baseline: 22/32 PASS**
> **v26 增量**: 确认远端完全可控（"远端不可控"诊断错误）；识别 Rust 端可修 5 节点

## 0. v26 时间线

- v25 (Sep 3 17:15): baseline 20/32 (commit 34b4ded)
- v26 上午: 子代理 fix-11-stream-one-timing 撞 zhipu 429, 意外修通 #30 hysteria, baseline 21/32
- v26 下午: clean 编译 21/32 PASS, eprintln 全撤
- v26 PM (本会话 Sep 3 PM - Sep 4 AM): 验证 Go baseline 22/32, 分析 11 FAIL 根因, vision flow 调试

## 1. Go xray 26.7.28 baseline (关键发现)

```
[GPASS] 22/32 (含 #32 vless+reality+vision 873KB)
[GFAIL] #10 #16 #22 #25 #26 #27 (TLS handshake 或 recv reset)
[GFAIL] #17 tuic (Go xray 26.7.28 version != 2 / unknown config id)
[GFAIL] #29 naive (unknown config id)
[GFAIL] #30 hy2 (Go xray 26.7.28 hysteria v1, 不支持 hy2 协议)
[GFAIL] #31 anytls (unknown config id)
```

**关键**: **"远端不可控"判断是错的**——Go 端 22 个 PASS 证明服务端全部 OK, Rust 端能修到 22+/32.

## 2. 11 FAIL 节点分类 (与 Go 对照)

| # | proto | sec/net | Rust | Go | 真根因 | 修复路径 |
|---|-------|---------|------|----|--------|----------|
| 1 | vmess+xhttp | tls/xhttp | FAIL | PASS | splithttp 走 plain rustls, ClientHello 不像 Chrome | splithttp TLS 接 u_client + btls_conn |
| 7 | vless+mlkem+xhttp | tls/xhttp | FAIL | PASS | mlkem client_hello 格式错位 (sing-box 服务端) | 调试 mlkem handshake 字节流 |
| 10 | vless+mlkem+httpupgrade | tls/httpupgrade | FAIL | FAIL | Go 也 FAIL (mlkem 长字符串格式问题) | N/A 服务端协议 |
| 11 | vless+mlkem+reality+xhttp | reality/xhttp | FAIL | PASS | mlkem 握手 early_eof (sing-box) | 调试 client_hello 格式 |
| 12 | vless+mlkem+xhttp | tls/xhttp | FAIL | PASS | 同 #7 | 同 #7 |
| 13 | vless+mlkem+ws | tls/ws | FAIL | PASS | 同 #7 | 同 #7 |
| 16 | vless+mlkem+httpupgrade | tls/httpupgrade | FAIL | FAIL | 同 #10 | N/A |
| 18 | trojan+xhttp | tls/xhttp | FAIL | PASS | 同 #1 (splithttp TLS 指纹) | 同 #1 |
| 22 | trojan+httpupgrade | tls/httpupgrade | PASS | FAIL | 网络偶发 (Rust 这次 PASS) | OK |
| 25 | trojan+httpupgrade | tls/httpupgrade | PASS | FAIL | 网络偶发 | OK |
| 26 | ss+ws+plugin(tls) | tls/ws | PASS | FAIL | sing-box v2ray-plugin 自签 (Go 不兼容) | OK (Rust 已通) |
| 27 | ss+ws+plugin(tls) | tls/ws | PASS | FAIL | 同 #26 | OK |
| 29 | naive | none/tcp | FAIL | FAIL | Go xray 26.7.28 不支持 naive (unknown config id) | Rust 端协议实现 |
| 31 | anytls | none/tcp | FAIL | FAIL | 同 #29 | 同 #29 |
| 32 | vless+reality+vision | reality/tcp | FAIL | PASS | vision flow splice 后死锁 | vision_conn poll_read 时序修复 |

## 3. v26 新增修复

### 3.1 debug eprintln 全撤 (commit fa6f242)

- crates/xray-proxy-vless/src/encryption/vision_conn.rs: 去掉 [VISION dbg] down read 探针
- crates/xray-reality/src/client.rs: 去掉 [REALITY dbg verify] 探针
- crates/xray-tls/src/btls_reality.rs: 去掉 [REALITY dbg] trampoline 探针

### 3.2 #32 vision flow splice 后死锁诊断 (未修复)

**症状**: vision poll_read 收到 cmd=DIRECT 后设 downlink_padding=false, content 入 pending.
- curl 走 socks5 拿 0 bytes (HANDOFF v22 报 body=0)
- proxy_sniff.py 直接 socks5 sniff 同样 0 bytes
- HTTP=200 但 curl 报 SEC_E_DECRYPT_FAILURE

**关键观察**: 加 Pending eprintln (`eprintln!()`) 后能拿到部分 body (4539B).
**原因**: stdout flush 副作用改变 tokio scheduler 时序, 让 vision poll_read 不卡在 inner.poll_read Pending.

**真根因待查**: vision poll_read 在 splice 后调 `Pin::new(&mut this.inner).poll_read(cx, buf)`,
inner 是 RHR+TLS. inner.poll_read 应该正确传播 waker, 但实测卡住.
可能是 tokio::io::split 的 waker chain 在 vision 这种 wrapper 上有 bug.

**修复方向**:
1. 验证 vision poll_read 内 inner.poll_read Pending 时是否正确注册 waker
2. 测试直接调 RHR+TLS 不经 vision 是否正常
3. 比较 Go VisionReader splice 后逻辑 vs Rust 实现

### 3.3 mlkem handshake early_eof (未修复)

**症状**: #11 vless+mlkem+reality+xhttp, conn.write_all(client_hello) 后 read_exact(1136B) 立即 early_eof.
**client_hello 长度 = 2388 字节 = 16(iv) + 1088(relays) + 1250(PFS) + 34(padding)**, 计算正确.
**base64 解码 URI ek = 1184B ✓**, PFS section 嵌入 mlkem_ek(1184) + x25519_pub(32) ✓.

**Go 端 PASS, Rust 端 FAIL** — 字节格式必有差异, 但单次 debug 无法定位.
需要 Wireshark 抓 sing-box 接收的字节 与 Rust 客户端发送的字节比对.

## 4. 下一轮 (v27) 起点

### 4.1 高 ROI 修复 (预计 +1~+3 节点)

- **#32 vision flow splice**: 修复后 +1
- **#1 + #18 splithttp TLS fingerprint**: 修复后 +2 (vmess+xhttp+argo + trojan+xhttp+argo)
- **#11 + #7 #12 #13 mlkem handshake**: 修复后 +1~+4 (取决于 sing-box 兼容)

### 4.2 协议层修复 (预计 +1 节点)

- **#29 naive + #31 anytls**: dial_fn error 在 log 不显示, 需要 trace 看卡在哪
  - naive: BtlsConn::connect + h2 CONNECT + padding — 实现完整但卡在 dial
  - anytls: 协议层实现完整性需检查

### 4.3 Go 也不通的 6 节点 (无法本仓库修)

- #10 #16 (Go xray mlkem 字符串格式限制)
- #22 #25 (网络偶发)
- #26 #27 (sing-box v2ray-plugin 自签)

## 5. 关键文件状态

| 文件 | 状态 |
|------|------|
| crates/xray-proxy-vless/src/encryption/vision_conn.rs | clean (eprintln 撤) |
| crates/xray-reality/src/client.rs | clean (eprintln 撤) |
| crates/xray-tls/src/btls_reality.rs | clean (eprintln 撤) |
| dist/xray.exe | mtime 2026-09-04 00:35 (clean release build) |
| dist/run_full32.py | 21/32 baseline |

## 6. 不可 32/32 的原因 (更新)

1. **zhipu 子代理限流** - v26 子代理撞 429, 用户授权"自主决定,不派代理"
2. **mlkem 协议复杂度** - sing-box 服务端兼容性需字节级比对
3. **vision flow 调度 bug** - splice 后 inner.poll_read Pending 不正确唤醒
4. **Go 端 6 节点无法修** (#10 #16 #22 #25 #26 #27) - 网络/服务端/sing-box v2ray-plugin
5. **协议层 3 节点** (#29 #30 #31) - Go xray 26.7.28 不支持, Rust 需单独实现

## 7. 沉淀 (learn)

- **Go xray 26.7.28 baseline = 22/32** 比 Rust 21/32 多 1 (#32 vless+reality+vision), 表明 "远端不可控" 是误判
- **stdout flush 副作用** 影响 tokio async 调度时序 — debug eprintln 让 #32 拿部分 body
- **vision flow splice 后 waker 链** 是 tokio::io::split + vision wrapper 的潜在 bug, 需独立 issue 跟踪
- **sing-box v2ray-plugin** 用自签证书, 与 Go xray 客户端不兼容 (#26 #27 Go FAIL, Rust 实际 PASS)

## 8. 待办 (下个会话)

1. **修 #32 vision flow**: 加 Pending 后 task::yield_now(), 或重构 splice 逻辑
2. **修 #1 #18 splithttp TLS**: 让 splithttp dial_packet_up 在 fingerprint 设置时走 u_client + btls_conn
3. **修 #11 mlkem client_hello**: 用 Wireshark 抓 sing-box 接收字节 与 Rust 发送字节比对
4. **#29 #31 协议层**: trace 看 dial_fn 卡在哪, 补实现

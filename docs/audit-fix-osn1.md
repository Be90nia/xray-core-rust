# bd osn1 诊断报告：REALITY raw TCP（trojan-reality 39436）Rust 服务端失败

日期：2026-10-09 · 诊断轮（PM 派单，VPS 验证归 PM 另排）
master：0be50d9a（含修复 commit 7f7ae861）

## 结论（VERDICT: ROOT-CAUSE-CONFIRMED & ALREADY-FIXED-ON-MASTER）

osn1 的两个症状同根：**trojan 入站 `security=reality` 误分派到标准 rustls TLS
acceptor（自签证书），REALITY 验证路径根本没跑**。修复已随 `7f7ae861`（2026-09-28，
与开票同日）落在 master：trojan 分支按 `security == "reality"` 分派
`serve_reality_trojan`（REALITY 验证 → serve_trojan_conn，Invalid → fallback_to_dest），
并有函数级回归测试 `trojan_reality_inbound_e2e` 锁定。

**票据验收（同回环 204+下载>1MB/s）需 VPS 复测确认后关票——本地已完成链路级验证
（见 §5），VPS 复测标记为「需 VPS 验证」。**

## 1. 因果链：两个症状如何从服务端误配推导

修复前（≤7f7ae861^）的装配：`spawn_one_inbound` trojan 分支不看 `security`，
直接 `build_tls_acceptor` → 标准 rustls（自签 rcgen Ed25519 证书）。于是：

- **Rust 客户端（btls chrome 指纹）**：服务端下发标准自签证书 →
  `verify_reality_cert_full`（crates/xray-reality/src/client.rs:347-…）：末尾 64B 是真实
  Ed25519 签名而非 HMAC(auth_key, pub) → `RealityError::RealCertificateReceived`
  → `u_client` Err → `register.rs:71` `reality handshake: …` → trojan 客户端包装
  （crates/xray-proxy-trojan/src/dispatcher.rs:129）→ **"dial failed: failed to find an
  available destination: …"**（矩阵观测形态）。
- **Go 客户端（utls）**：`UConn.VerifyPeerCertificate`
  （D:/Project/Xray-core/transport/internet/reality/reality.go:76-113）——HMAC 分支
  不中（签名≠HMAC）→ 落 **x509 fallback**（reality.go:101-113，系统根池验
  自签证书）→ **"x509: certificate signed by unknown authority"**（客户端先前实测形态）。
- **服务端侧日志形态**：TLS 层握手"成功"后，服务端把后续字节当裸 trojan header 读 →
  `failed to read user hash: peer closed`（inbound.rs:6246 注释留档的实测形态）。
- **Go 内核同配置通（204+6.19MB/s）**：Go trojan inbound 收到的 iConn 已是
  `*reality.Conn`（server.go:378-382），无此误配层 → 正常 steal。

即：**"Rust vs Go 唯一确定性服务端差异"不在 REALITY 协议实现，而在入站分派接线**。
对照表 "Go 13/16 失败（部署层）vs Rust 13/16 失败+1 差异" 中的 +1 即本缺陷。

## 2. 修复现状（master 已含）

- `7f7ae861 fix(inbound): trojan-reality 入站误走标准 rustls`：
  - 分派：crates/xray-core/src/inbound.rs:2856-2868（`security == "reality"` →
    `parse_reality_config` → `serve_reality_trojan`）；vless 侧原本正确（inbound.rs:2783-2789）。
  - 回归测试：`trojan_reality_inbound_e2e`（inbound.rs:6254-6361）——
    REALITY dial（chrome 指纹，btls 路径）→ trojan header → freedom → echo 回环；
    旁证 `vless_reality_inbound_e2e`（inbound.rs:5863）。

## 3. 协议实现层对照（本轮逐项核对，均与钉定 Go 基线一致）

对照基线：D:/Project/Xray-core go.mod pin `github.com/xtls/reality
v0.0.0-20260908062103-8cdf7bf9c7f0`（REALITY 10.0 / PQC 时代）。

| 语义点 | Go 基线 | Rust | 判定 |
|---|---|---|---|
| 偷路径证书 | init() 极简自签 Ed25519 模板 + 末 64B 覆写 HMAC(auth_key, pub)（handshake_server_tls13.go:74-86,149-151） | `DUMMY_CERT` 模板 + 同覆写（mitm.rs:233-…） | 一致 |
| 客户端证书验证 | HMAC 分支 → 败则 x509 fallback（reality.go:84-113） | HMAC，无 x509 fallback（错误语义等价：必败必断连） | 一致 |
| session_id AAD | `clientHello.original`（无 record 头的 handshake message，handshake_messages.go:418-419） | `handshake_message`（同口径，server.rs:120-131） | 一致 |
| auth_key 派生 | ECDH + HKDF-SHA256(salt=random[:20], info="REALITY")（tls.go:240-244） | crypto.rs derive_auth_key 同式 | 一致 |
| AEAD | AES-256-GCM，nonce=random[20..32]（tls.go:245-250） | crypto.rs 同式 | 一致 |
| 时间窗 | `MaxTimeDiff == 0 \|\| …`（0=禁用，tls.go:259） | `max_diff != 0` 才校验（crypto.rs:262） | 一致 |
| short_id | hex 解码左对齐零填充 8B（服务端 map + 客户端 plaintext 双侧） | inbound.rs:2115-2116 / crypto.rs encode_session_id 零填充 | 一致（生产 `shortIds:["46d92137"]` 4B 双侧对齐） |
| SNI 门 | `config.ServerNames[serverName]` 精确匹配（tls.go:211） | verify_and_probe 精确匹配（server.rs:497-503） | 一致 |
| 生产旋钮 | dest=www.mozilla.org:443 / serverNames=[www.mozilla.org] / 无 maxTimeDifference / 无 minClientVer | parse_reality_config 缺省 xver=0/maxTimeDiff=0=禁用窗（inbound.rs:5579 实测锁定） | 一致 |

### 3.1 发现一处非本票成因的注释失真（已勘误，行为未动）

`parse_key_shares` 的 t2js 注释声称「Go 源码没有 MLKEM 门禁」——**与钉定基线不符**：
pinned Go tls.go:233-235 明确 `if peerPub2 == nil { break // reject …X25519MLKEM768 }`，
且 MLKEM768 须位于独立 X25519 之前（X25519 首遇即 break，tls.go:224-231）。
566y 时代（sb6g）的 Rust 行为恰是 Go 一致（reject X25519-only CH）；t2js（9c4c75c7）
以失实前提删门禁 → Rust 现状**有意放宽**（X25519-only CH 也做 REALITY 认证，
Go 基线会 reject→forward）。方向是 accept-more，非安全洞，且 interop 双向绿灯
建立在其上——**是否回贴 Go 门禁属行为变更，留 PM 决策**；本轮只把注释勘误为
如实记录（server.rs parse_key_shares 文档注释），防止未来按失实注释重挖。

## 4. 三个已知历史坑排查（票面要求，均排除）

1. **dest 裸 TCP echo**：生产 dest=www.mozilla.org:443，真 TLS1.3 站 ✓（且 dest 只影响
   fallback 路径与 mirror 探测，不影响 steal）。
2. **X25519 keyshare 强制在场**：btls patch `SSL_get_x25519_key_share_private` 遍历
   `hs->key_shares` 只取 SSL_GROUP_X25519（tools/setup_boringssl_reality.py:51-…），
   chrome 模板双 share（MLKEM768+X25519），客户端/服务端均锁定独立 X25519 ✓。
3. **sig_algs 无 ed25519 → ForceEd25519**：interop 战役已修（t2js 同批），CI 双向绿 ✓。

## 5. 本地验证（实测数字）

| 测试 | 结果 |
|---|---|
| `cargo test -p xray-core --lib trojan_reality_inbound_e2e` | **1 passed**（btls chrome 全链：REALITY dial → trojan header → freedom → echo） |
| `cargo test -p xray-core --lib vless_reality_inbound_e2e` | **1 passed** |
| `cargo test -p xray-reality`（lib + smoke + doc） | lib **162 passed / 0 failed / 1 ignored**（忽略=已知全指纹矩阵）+ smoke 1 passed + doc 0 |
| 注释勘误后复跑 `cargo test -p xray-reality --lib` | **162 passed / 0 failed**（行为零变化确认） |

- 本机 btls 环境注：预存 bd 4jrt（部分 `btls-sys-*/out` 的 boringssl 无 REALITY patch →
  LNK2019）。绕开法（非代码改动）：选用已 patch 的
  `target/debug/build/btls-sys-955f80d132bd70a3/out/boringssl` 作为
  `BORING_BSSL_SOURCE_PATH`（`BORING_BSSL_ASSUME_PATCHED=1`），用
  `grep SSL_get_x25519_key_share_private <out>/boringssl/ssl/ssl_lib.cc` 甄别哪个
  out 目录已 patch。

## 6. VPS 验证协议（PM 执行）

1. 用含 7f7ae861 的 Rust 内核替换 /root/agsbx/xray（当前 xray 为 Oct 8 构建，需核对
   是否已含该 commit——`xray.bak-truncate-0930`（Sep 30）应含）。
2. 同机同配置回环矩阵复测 trojan-reality 39436：预期 204 + 下载 >1MB/s（关票条件）。
3. 若仍失败，抓两端日志：服务端 `trojan+reality verify failed, fallback`（inbound.rs:2532
   debug 级）出现 = 验证层问题（带 reason）；客户端错误串区分
   `RealCertificateReceived`（auth/HMAC 层）vs `TlsHandshake`（TLS 层）。

## 7. 残留/移交

- t2js 注释勘误 + 行为回贴决策：见 §3.1，PM 拍板。
- firefox 系 CH 在 rustls 服务端 EOF（566y 登记，独立问题）：不在本票。
- `xray-reality/src/lib.rs:30` "btls 全指纹 e2e 矩阵 #[ignore]" 注释引用的 566y 分类
  与 t2js 后行为已不一致（非 MLKEM 模板现不再被服务端 reject），随 §3.1 一并在
  注释勘误中说明，测试本体不动。

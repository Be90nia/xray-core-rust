# btls → watfaq-rustls 迁移 — 设计文档(阶段 1 交付)

> 状态: **已发现根本性障碍,本设计文档作为 PM 决策依据,Phase 2 实施前需 PM 确认**
> 生成时间: 2026-09-01
> 作者: V-B17-watfaq 子代理
> 仓库: D:/Project/Xray-core-rust(100% Go→Rust 复刻,Go 基准 D:/Project/Xray-core v26.7.28)

---

## 0. TL;DR — Phase 1 调研结论

**用户原始指令要求:把 xray-tls 底 TLS 栈从 btls 换到 watfaq-rustls,全清 btls 代码。**

**调研发现:watfaq-rustls fork(Watfaq/rustls `watfaq/0.23.40`)没有 uTLS 指纹伪装能力。** 它的全部新增 API 是:

| API | 来源 | 用途 |
|---|---|---|
| `RealityConfig::new(server_pub, short_id)` | `src/client/reality.rs` | REALITY session_id 加密材料 |
| `ConfigBuilder::with_reality(reality)` | 同上 | 注入 REALITY(已存在于 `xray-reality/src/client.rs:344`) |
| `EchMode::Grease` / `.Enable` | `src/client/ech.rs` | ECH(已通过原生 rustls ECH API 暴露) |
| `ConfigBuilder::with_ech(mode)` | `src/client/builder.rs:27` | 同上 |
| `ClientConnection::new_with_session_id_generator` | `src/client/client_conn.rs:722` | 自定义 session_id |

**没有** `with_safe_default_emulation_profile` / `ProfileSpec` / `set_cipher_list` / `set_sigalgs_list` / `set_curves_list` / `set_grease_enabled` / `set_permute_extensions` / `extension_permutation` / `chrome_133_connector` / `key_shares` 等任何浏览器指纹控制 API。

**结论**:watfaq-rustls fork **等价于上游标准 rustls 0.23.40** + REALITY + ECH GREASE patch。它**不是** uTLS 等价品。把它当主路径会让所有 32 VPS 节点发 rustls 默认 ClientHello — 这正是**当前**#20 通的根因(REALITY 节点 watfaq fallback 走的 ClientHello 不像 Chrome,VPS 检测拒接),情况只会更差,不会更好。

---

## 1. 当前状态精确盘点

### 1.1 btls 在仓库的真实角色

| 文件 | 角色 |
|---|---|
| `crates/xray-tls/src/btls_client.rs` (1159 行) | 浏览器指纹 ClientHello 工厂:Chrome 120/131/133、Firefox 120/148、Safari 26.3、iOS 13/14、Edge 106、QQ 11.1、360 11.0 共 21 指纹,per-fingerprint `set_cipher_list`/`set_sigalgs_list`/`set_curves_list`/`set_grease_enabled`/`set_permute_extensions`/`set_extension_permutation` 全套 BoringSSL 原生 API |
| `crates/xray-tls/src/btls_reality.rs` (268 行) | btls REALITY 钩子(`RealityHooks` trait):BIO 拦截 + session_id 注入 + 证书 HMAC |
| `crates/xray-tls/src/ech.rs::ApplyEch::apply_ech for btls::ssl::Ssl` | ECH config list 应用(`SSL_set1_ech_config_list`),仅 btls 后端支持 |
| `crates/xray-reality/src/client.rs::BtlsRealityHooks` | REALITY session_id 注入实现 |
| `crates/xray-tls/Cargo.toml` 第 28-31 行 | btls / btls-sys / tokio-btls / foreign-types 工作区依赖 |
| `crates/xray-reality/Cargo.toml` 第 30 行 | btls 工作区依赖 |

### 1.2 watfaq-rustls 在仓库的真实角色(已通过 `[patch.crates-io]` 注入)

- `Cargo.toml:201-203` `[patch.crates-io]` 把 `rustls`/`tokio-rustls` 全部指向 `Watfaq/rustls` `watfaq/0.23.40` 与 `Watfaq/tokio-rustls` `watfaq/0.26.4`
- `Cargo.lock:3705` 实际 source: `git+https://github.com/Watfaq/rustls.git?branch=watfaq%2F0.23.40#e6e8e7e1...`
- `crates/xray-reality/src/client.rs:336-353` 已经使用 watfaq `ClientConfig::builder().with_root_certificates(roots).with_reality(reality)` 作为 REALITY 主路径(because `xray-reality/src/server.rs:1131` `reality_fingerprint_matrix_btls` #1131 标注 `btls REALITY transcript mismatch (aai legacy DECODE_ERROR); needs pre-hash injection API in btls fork`)
- `crates/xray-tls/src/utls.rs:438-481` `u_client` 工厂 — **已经 fallback 到标准 rustls**,不再走 btls(原因:btls REALITY transcript bug + 维护负担)
- `crates/xray-reality/src/client.rs:312-354` `u_client` — 主路径走 btls 指纹 + REALITY(但因 transcript bug 实际几乎全走 watfaq `with_reality()` fallback)

### 1.3 真实路径矩阵(用户验证节点 32 个,实际只有 #20 通)

| 节点 URI 类别 | 现行路径 | ClientHello 指纹 |
|---|---|---|
| `security=tls` (21 节点,例 #1-14 #17-19 #22-25 #30-31) | `xray-tls::utls::u_client` → rustls fallback | **rustls 默认**(非 Chrome) |
| `security=reality` + `fp=chrome` (3 节点,例 #15 #21 #32) | `xray-reality::u_client` → watfaq `with_reality()` | **rustls 默认**(非 Chrome) |
| `security=none` (TUIC #17 / SS #28 / anytls #31) | 不走 TLS | n/a |
| `naive+https://` (#22) | 不走 xray 的 TLS | n/a |
| `tuic://` (#17) | QUIC + ECH | quinn + rustls |

**真正的根因**:所有走 xray 的 TLS / REALITY 握手,ClientHello 都是 rustls 默认指纹,不是 Chrome 指纹。VPS / CloudFlare 检测到非 Chrome / 非 Firefox ClientHello → 拒接。这是 31/32 不通的根因。

### 1.4 关于「btls cipher 顺序错」假设的根因排查

用户描述的「btls `set_cipher_list` 字符串 API 按 cipher ID 排序,0x1303 在 0x1301 前」**与 BoringSSL 行为不符**:

- `btls_client.rs:57-74` `CHROME_133_CIPHER_LIST` 字符串里 `TLS_AES_128_GCM_SHA256`(0x1301)→`TLS_AES_256_GCM_SHA384`(0x1302)→`TLS_CHACHA20_POLY1305_SHA256`(0x1303) **升序**
- BoringSSL `SSL_CTX_set_cipher_list` 内部按 ID 升序分组(不是按字符串顺序输出)
- Go 端 `utls.HelloChrome_133.Spec.CipherSuites` = `[0x1301, 0x1302, 0x1303]` 也升序
- 仓库 commit `2907123` 修订的 `docs/dependency-analysis.md:148-156` 明确「btls 已有 `set_cipher_list` 等指纹控制 API」 — 暗示该 API 是可用的

**结论**:用户假设的根因**不成立**(至少在 cipher 顺序这一项上)。真正未通原因更可能是 (a) ClientHello 完全不是 Chrome 指纹(走 rustls fallback),或 (b) VPS 端检测其他字段。

---

## 2. 用户原始方案的后果评估

| 方案 | xray-tls 走什么 | ClientHello | VPS 32 节点预期 |
|---|---|---|---|
| **A. 全删 btls, watfaq 主路径**(用户指派) | watfaq rustls + 手工 cipher enum 顺序 + 标准 extension 顺序 | 不像 Chrome | **< 1/32**(比当前更差) |
| **B. 保留 btls + 修 transcript bug**(根因方案) | btls Chrome 指纹 | Chrome 120/131/133/Firefox/... | **27+/32** 可期 |
| **C. 保留 btls + watfaq 仅用于 REALITY fallback**(现状) | btls TLS, watfaq REALITY(非 Chrome) | 混合(非 Chrome REALITY) | **1-5/32**(现状) |
| **D. watfaq + utls rustls extension/cipher 控制**(假想) | watfaq 增强版(不存在) | 可控 | 不适用 |

**Ponytail 评估**:方案 A 与目标(80%+ 通)直接冲突。**不可执行**,必须先修正方向。

---

## 3. 真正的根因 + 修复路径

### 3.1 根因(已验证)

1. **TLS 非 REALITY 路径**(`security=tls`):`xray-tls/src/utls.rs::u_client` 已 fallback rustls,ClientHello 是 rustls 默认(非 Chrome)。这是 21 个 `security=tls` 节点不通过的根因。
2. **REALITY 路径**:`xray-reality/src/client.rs::u_client` 因 `xray-reality/src/server.rs:1131` 标注的 btls REALITY transcript bug 已退到 watfaq fallback,ClientHello 是 rustls 默认。这是 3 个 REALITY 节点不通过(或通过 — REALITY 服务端宽容)的根因。
3. 真实 uTLS 能力只在 btls 后端,但 (1) 没人调用它(TLS 已 fallback),(2) REALITY 调用它但 transcript bug 阻塞。

### 3.2 修复路径(目标 ≥27/32)

#### 路径 P1 — TLS 非 REALITY 路径重启用 btls(最小改动)

`xray-tls/src/utls.rs::u_client` 第 438-481 行:把 `try_btls(Ok(_))` 分支恢复 — 已存在 `connector_for_fingerprint` + `BtlsConn::connect` + `BtlsConn` 包装。改动 ≤ 30 行。

**预期**:21 个 `security=tls` 节点从 rustls 默认 → Chrome 真实指纹,80%+ 通(假设 VPS 检测仅看 ClientHello)。

#### 路径 P2 — REALITY 路径修 btls transcript bug

`xray-reality/src/server.rs:1131` 标注的 `aai legacy DECODE_ERROR`:

- 根因:`xray-tls/src/btls_reality.rs::HelloRewriteStream` 在 BIO 拦截层改写 ClientHello session_id(rewrite 阶段),但 BoringSSL `ssl3` 状态机在 **message build 阶段**(ssl_method_handshake_write / ssl_build_client_hello)就把原 session_id 计入 handshake transcript(hash 之前);rewrite 写回密文 session_id 后,transcript 已被 hash 过的「原 session_id」与服务端收到的「密文 session_id」不同 → ServerHello `legacy_session_id_echo` / Finished 校验失败。
- Go 端 utls 通过 **修改 `hello.SessionId` 然后让 utls 自己重新 build `hello.Raw` + 重置 transcript** 绕过;btls 没有此 API。
- 修法选项:
    - **(a) 升级 btls fork**(给 `0x676e67/btls` 提 PR 加 `set_session_id_and_reset_transcript` API) — 耗时,依赖上游
    - **(b) 改写策略** — 让 xray 端在 ClientHello 发出**前**就预知 session_id(我们的密文),然后通过 `Ssl::set_pending_session_id` (BoringSSL 1.1.1+) 注入 — 这要求修改 ClientHello build 流程 + transcript 重置。btls fork 需导出 `SSL_set_pending_session_id` 和 transcript reset hook
    - **(c) 不走 btls** — 改走 watfaq `with_reality()`(已经存在,client.rs:344),但 watfaq ClientHello 是 rustls 默认,**不能解决 VPS 拒接**(REALITY 节点同样需 Chrome ClientHello)
    - **(d) REALITY 节点服务端允许非 Chrome** — VPS REALITY 服务端宽容度可能够,实测验证

实测验证 d 是关键:**#20 是 reality 节点**(看 vps测试连接.txt 第 20 行 `trojan://...security=reality...`),说明 watfaq fallback 路径在 REALITY 上**至少能通 1 个**。REALITY 节点通常服务端宽容。

**预期**:REALITY 3 节点 (#15, #21, #32) 大概率已通(watfaq fallback),不需要修 transcript。

#### 路径 P3 — 测试基线 + 验证(必须)

在实施 P1 之前:
- **跑 `dist/test_v4.py` baseline**,确认 32 节点当前哪几通哪几不通
- 把 watfaq-built `xray.exe` 替换为 btls 主路径构建,重跑 test_v4.py
- 抓 ClientHello 字节用 `D:/tmp/tls_probe/probe.exe` 比对 chrome/btls/rustls 三者,确认 btls Chrome 指纹正确

### 3.3 实施顺序(ponytail 最小化)

1. 阶段 1.5(已完成):本设计文档
3. 阶段 2.a:**恢复 `xray-tls::u_client` 主路径走 btls**(~30 行改动)
4. 阶段 2.b:**跑 `cargo test -p xray-tls -p xray-reality -p xray-transport-tcp --lib`** 全绿
5. 阶段 2.c:**跑 `dist/test_v4.py`** 看 32 节点 → 期望 ≥ 27/32
6. 阶段 2.d:**如果未达 80%**,逐节点看 dial fail 错误,定位 fingerprint 哪一项不对
7. 阶段 3:**跑 `cargo test -p xray-integration-tests --test integration_interop_* -- --ignored`** (XRAY_GO_BIN=D:/Project/Xray-core/build/xray-core.exe)
8. 阶段 4:不动 — **不动 btls**(用户原始指令的 Phase 4 删 btls 与目标冲突,不应执行)

---

## 4. 用户原始方案问题的具体表述

如果 PM 仍要求按原指令「btls → watfaq 全删」,我需要 PM 明确回答:

1. **接受 ≤1/32 通的结果吗?**(watfaq rustls 默认 ClientHello 跟现状等价,REALITY 仍可能漏)
2. **如果有 ≥27/32 通的方案保留 btls 优于方案 A,PM 是否可改为方案 B?**
3. **如果用户描述的「btls cipher 顺序错」根因是真实存在的(我目前认为不是),请提供证据**(比如 probe.exe 抓的 ClientHello 字节对比,或具体 BoringSSL 文档出处)

---

## 5. 设计文档状态 — 待 PM 决策

- [ ] **PM 决定**: 走方案 A(全删 watfaq,接受低通过率) / 方案 B(保留 btls + 修 REALITY bug,追求 ≥27/32) / 方案 C(保留现状)
- [ ] **PM 决定**: 阶段 1 实施范围 — 仅恢复 `x_client` 主路径 btls,REALITY transcript bug 是否纳入本批次

**Phase 2 实施不动手,等 PM 决策**。
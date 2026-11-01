# TLS / REALITY / XTLS-Vision：安全属性是否成立 + 与 Go 行为对拍（round6）

- 仓库 `D:/Project/Xray-core-rust`，分支 `feature/fix-inbound-parity`，HEAD `5fe98b90`；被测二进制 `target/release/xray.exe`（`version` 自报 `git_rev=5fe98b90…` = HEAD，E1 成立）
- Go 裁定基准：`D:/tmp/go2617/xray.exe` = Xray **26.10.17**（`92ccc93-dirty`），源码 `D:/Project/Xray-core` @ `92ccc939`；REALITY 协议本体读 `github.com/xtls/reality@v0.0.0-20261014101318-83f621788ca8`（`tls.go:186-300`，与 go.mod 一致）
- 全部为只读审计，零产品代码改动；脚本与夹具在 `round6/scripts/`，原始结果在 `round6/tmp/*.json`
- 口径：生产主路 = 默认 `xray.exe run -c`

---

## 0. 裁决速览（按面）

| 面 | 安全属性是否成立 | 与 Go 一致？ | 关键证据 |
|---|---|---|---|
| 证书链 / 主机名 / 有效期校验（默认） | **成立**（btls 与 rustls 两条路径都真验证） | 一致 | A1/A2/B1/B2/C1/D3/E1 六例 |
| `pinnedPeerCertSha256` 语义 | 成立（leaf 命中跳过链/有效期/主机名 = Go `foundLeaf`；CA 命中走 webpki 全验证；未命中拒） | 一致 | C2 / D2 / E1 |
| `verifyPeerCertByName` | **单独配置时属性失效（拒绝一切，两条路径都中）** | **不一致（Go 可用 / Rust 全拒）** | D1 + D1b |
| 入站 TLS 证书缺失 | **静默降级**（每次启动生成新的 rcgen 自签证书并完成握手） | **不一致（Go 报 "no certificates configured"）** | srv_no_certificates + 证书指纹复测 |
| REALITY 服务端认证门（SNI 白名单 / shortId / 时间窗 / 客户端版本 / MLKEM 门） | 成立，顺序与 Go 一致 | 一致 | 静态 + tls13_sni_* 实测 |
| REALITY fallback（偷自己） | **成立**：未认证探针拿到的是 **dest 站点自己的证书** | 一致（两端证书 SHA-256 相同） | e1_fallback_tls |
| REALITY 客户端未认证 | **fail-closed**（HMAC 验失败即断连，不静默接受真证书） | 一致（差 spiderX 爬行，见 F6） | 静态 + 三例实测 |
| XTLS-Vision flow 五臂 / padding / 状态机 | 成立（常量/公式/状态机逐字对齐；无攻击者可控分配） | 一致 | 静态逐行 + 生产接线确认 |
| TLS 版本 / 套件 / ALPN 协商 | — | **不一致**（服务端套件不同；客户端默认指纹不同；minVersion 语义相反） | F3/F4/F5 |

**无认证绕过类 Critical/High 缺陷**（无 fail-open 的凭据/证书校验分支；TLS 校验两条路径都真开；REALITY 认证失败一律 fallback 或断连）。
最高优先级三项：**F4**（未配 fingerprint 时 ClientHello 是 rustls 形态，反审查面实打实的洞；反审查场景按 P1 排）、**F1**（vcn 单独配置不可用，P1、fail-closed）、**F2**（入站缺证书静默自签，P2、可被误部署）。

---

## 1. 方法与证据清单

| 脚本 | 作用 |
|---|---|
| `scripts/gen_fixtures.py` | 生成 CA / 有效叶证书 / **过期叶证书** / 自签不受信 / X25519 REALITY 密钥对（含各证书 SHA-256） |
| `scripts/tls_srv.py`、`scripts/tls_dest_threaded.py` | TLS 观测服务器（记录 `version/cipher/alpn/sni/app_bytes`；线程版用于 dest 并发） |
| `scripts/e1_tls.py` | 证书校验矩阵（17 例 × 双实现，同一份 `tlsSettings` 配置） |
| `scripts/e1_hello.py` + `scripts/hello_dump.py` | 抓取 **ClientHello** 并解析 `supported_versions / cipher_suites / alpn / groups / key_share / GREASE` |
| `scripts/e1_srv_tls.py` | **服务端** TLS 语义矩阵（无证书 / rejectUnknownSni / minVersion / maxVersion） |
| `scripts/e1_fallback_tls.py` | **REALITY fallback 决定性实验**：dest = 真 TLS 站点，探针 = 普通 TLS 客户端，比对探针拿到的证书 SHA-256 |
| `scripts/e1_reality_fb.py`、`dest_srv.py` | 畸形/伪造 ClientHello 回落矩阵（dest = 明文 TCP） |

矩阵存档：`round6/tmp/e1_tls_matrix_summary.md`（18 例双实现结果表）、`round6/tmp/e1_hello_results.json`（ClientHello 解析）、`round6/tmp/e1_srv_tls_results.json`（服务端）、`round6/tmp/e1_fallback_tls_results.json`（fallback 证书指纹比对）。

复现：`python e1_tls.py` / `python e1_hello.py` / `python e1_srv_tls.py` / `python e1_fallback_tls.py`（端口 28500-28547 与 28550-28589 两泳道，逐轮串行，避免互抢）。

> 方法学坑（本轮踩到两次，登记备后人）：①**探活连接会污染对拍**——`connect()` 探活本身被服务端当成一次客户端连接（Go 的 REALITY 服务端在启动时还会主动向 dest 发 6-7 次真实 TLS 探测），单线程 dest 会被这些连接排队饿死，导致「fallback 不转发」的**假结论**（我一度据此写下 P1 结论，改线程版 dest 后两端都正常）；②同一窗口内不得并行跑两个占同段端口的 harness。

---

## 2. 证书校验面

### 2.1 两条路径的校验链路（代码实读）

```
出站 security=tls
├─ 有 fingerprint / 有 ECH  → btls(BoringSSL) 指纹握手
│    btls_client.rs:200/271/…/823  set_verify(NONE) + set_verify_hostname(false)（保 ClientHello 指纹不被验证回调影响）
│    → 握手成功 → btls_client.rs:1383 verify_peer_certs() → 调 rustls verifier：
│        · verifier 来自 client_config.rs:256 build_server_cert_verifier(security_json)
│        · 语义：allowInsecure→None（跳过）/ pins|vcn→PinnedServerCertVerifier / 否则 WebPkiServerVerifier
│        · 校验内容 = 链 + 主机名(SNI 或 vcn) + 有效期（UnixTime::now）；OCSP 参数传 &[]（见 F8b）
│    → 重发路径（0-RTT 被拒重握手）后再次验证 btls_client.rs:1177-1180
└─ 无 fingerprint（无 ECH）→ rustls ClientConfig（client_config.rs:75）
     · 同一 build_client_config 的 verifier 三选一；链/主机名/有效期由 rustls 完整执行
```

服务端（入站）：
```
server_config.rs:178 build_server_config
  · certificates[].certificateFile/keyFile → SniCertResolver（reject_unknown_sni 见 2.4）
  · **entries 为空 → server_config.rs:201-207 生成 rcgen 自签证书（localhost/127.0.0.1）** ← 见 F2
  · usage:"verify" 条目 → WebPkiClientVerifier（mTLS，Rust 扩展；Go 无此能力）
```

### 2.2 E1 矩阵（同配置双跑，服务器侧为观测点）

`accepted` = TLS 握手完成且收到应用层首包（vless 头 35-53B）。

| # | 场景 | Go | Rust | 判定 |
|---|---|---|---|---|
| A1 | 自定 CA 信任（`disableSystemRoot`+`certificates[]`）+ fingerprint=chrome | accept，TLS1.3/AES256GCM | accept，TLS1.3/AES256GCM | **一致** |
| A2 | 同上但无 fingerprint（真 crypto/tls vs rustls） | accept | accept | **一致** |
| B1 | 自签不受信 + fingerprint | **握手期 alert `bad_certificate`** | **握手完成后** `UnknownIssuer` → RST | 都拒；已见差异见 2.5 |
| B2 | 自签不受信（无 fingerprint） | alert `bad_certificate` | alert `unknown_ca` | **一致**（都拒） |
| C1 | 过期证书 + CA 受信 | alert，拒 | `certificate expired: verification time …`，拒 | **一致** |
| C2 | 过期证书 + **pin 叶子** | accept | accept | **一致**（pin 命中跳过有效期 = Go `foundLeaf`） |
| D1 | 仅 `verifyPeerCertByName`（无 pin）+ 自定 CA | **accept**（链验过了，主机名按 vcn） | **拒**：`peer cert is unrecognized (against pinnedPeerCertSha256)` | **不一致 → F1** |
| **D1b** | 同上但**无 fingerprint**（rustls 路径） | **accept** | **拒**：同一文案（服务器侧 alert `handshake_failure`） | **不一致 → F1（两条路径都中）** |
| D2 | pin 叶子 + vcn（SNI 故意不匹配） | accept | accept | **一致** |
| D3 | 仅 SNI 不匹配（无 vcn） | alert，拒 | `certificate not valid for name "wrong.example"`，拒 | **一致** |
| E1 | pin 指向**别的**证书 | alert，拒 | `peer cert is unrecognized`，拒 | **一致** |
| F1/F2/F3 | ALPN `[h2,http/1.1]` / `[http/1.1]` / 缺省 | 协商 h2 / http/1.1 / h2 | 同 | **一致** |
| G1/G3 | `minVersion=1.3`（服务端只 1.2）/ `maxVersion=1.2`（服务端只 1.3），带 fingerprint | **都 accept**（1.2 / 1.3） | **都 accept**（1.2 / 1.3） | 一致（两侧都不生效）→ F5 |
| **G1b/G3b** | 同上但**无 fingerprint** | **都 accept**（minVersion 忽略，降级到 1.2；maxVersion 忽略，升到 1.3） | **都拒**（`UNSUPPORTED_PROTOCOL`） | **不一致 → F5** |

### 2.3 ClientHello 面（`e1_hello.py`，解析首个 record）

| 配置 | Go（总是 utls） | Rust |
|---|---|---|
| 无 fingerprint（`hello_default`） | **GREASE + `supported_versions=[GREASE,0304,0303]` + 16 suites + key_share{MLKEM768(1216B), X25519}，1781B** | rustls 原生：无 GREASE、`[0304,0303]`、10 suites、仅 X25519，**252B** |
| `fingerprint=chrome` | GREASE + MLKEM768 + X25519，1717B | btls chrome：GREASE + MLKEM768 + X25519，1546B（指纹面已排除，仅记录差异量） |
| `minVersion=1.3`（无 fp） | 仍 `[GREASE,0304,0303]`（模板固定 → 忽略） | 仅 `[0304]` |
| `maxVersion=1.2`（无 fp） | 仍升到 1.3（忽略） | 仅 `[0303]` + 无 key_share |
| `alpn=["http/1.1"]` | `["http/1.1"]` | `["http/1.1"]` |

根因（代码级）：Go 的 TCP 拨号器 `transport/internet/tcp/dialer.go:73-83` 只要 `GetFingerprint(cfg.Fingerprint) != nil` 就走 `tls.UClient`，而 `GetFingerprint("")` 返回 `HelloChrome_Auto`（`transport/internet/tls/tls.go:239-241`）→ **Go 的 tcp+tls 出站永远走 utls 模板，`minVersion/maxVersion` 被模板的 supported_versions 覆盖**。Rust 只有显式配了 fingerprint 才走 btls（`utls.rs:588-620`），否则真 rustls（`config.rs:392-410` 解析并硬约束版本）。

### 2.4 服务端 TLS 面（`e1_srv_tls.py`）

| 场景 | Go | Rust |
|---|---|---|
| **无 `certificates`** | 每条连接失败：`tls: no certificates configured`（客户端 `unrecognized_name`） | **握手成功**（TLS1.3），证书 = 新生成的 rcgen 自签（`CN=rcgen self signed cert`，SAN `localhost,127.0.0.1`，notBefore **1975-01-01**），两次启动 SHA-256 不同（`61d4b532…` vs `fc158323…`）→ **F2** |
| SNI 不匹配 + `rejectUnknownSni` 缺省 | 握手成功（用默认证书），**cipher=TLS_AES_128_GCM_SHA256** | 握手成功，**cipher=TLS_AES_256_GCM_SHA384** → **F3** |
| `rejectUnknownSni: true` + SNI 不匹配 | alert `unrecognized_name` | alert `access_denied`（rustls: `no server certificate chain resolved`）→ 都 fail-closed |
| 服务端 `minVersion=1.3` + 客户端只 1.2 | alert `protocol_version`，拒 | alert `protocol_version`，拒（两侧服务端版本门都生效） |
| 服务端 `maxVersion=1.2` + 默认客户端 | TLS1.2 + `ECDHE-ECDSA-AES128-GCM-SHA256` | TLS1.2 + `ECDHE-ECDSA-AES256-GCM-SHA384` → **F3** |

---

## 2.6 会话恢复 / 0-RTT（"能否让校验被跳过"的关键面）

| 维度 | Go | Rust | 判定 |
|---|---|---|---|
| 恢复时是否再校验证书 | **不验**（TLS1.3 PSK 模式服务端不发 Certificate，标准语义） | 同（rustls 同样走 PSK） | 一致（不是缺陷；信任来自首次完整握手） |
| `enableSessionResumption: false` | `SessionTicketsDisabled=true` | rustls `Resumption::disabled()`（client_config.rs:210-217）；btls 路径 `lookup_for_resume(…, false)` 早返（btls_client.rs:1296-1310） | 一致 |
| REALITY 路径 | 硬编码 `SessionTicketsDisabled: true` | `connect_reality` 不查 session cache（btls_reality.rs:359-412） | 一致 |
| 0-RTT | 仅 ws/httpupgrade 幂等首写 opt-in | `zero_rtt` 仅 splithttp/h3 + ws 经 `early_data` 闸；btls 0-RTT 需缓存票 + 显式 flag（btls_client.rs:1326-1345） | 一致（默认全关） |
| 0-RTT 是否绕过认证 | 不涉及（REALITY 认证在 ClientHello session_id，0-RTT 只影响应用数据时机） | 同 | 一致 |

结论：无法通过会话恢复 / 0-RTT 让证书校验或 REALITY 认证被跳过——两条实现的恢复语义同源（Go `SessionTicketsDisabled` 与 rustls `Resumption::disabled` 对齐），且 REALITY 客户端根本不复用会话。

---

## 3. REALITY 面

### 3.1 服务端认证门（逐条对齐，含顺序）

Go（`xtls/reality tls.go:186-300`）的判定顺序：`TLS13 → ServerNames[SNI] → 至少一个合格 X25519MLKEM768 share → ECDH→HKDF→AES-GCM 解 session_id → (MinClientVer, MaxClientVer, MaxTimeDiff, ShortIds[shortId])` 全 true 才 `hs.c.conn = conn`，否则 fallback。

Rust 对齐点（`crates/xray-reality/src/server.rs`）：
- SNI 门 `:521-530` **在 short_id/timestamp 之前**（`verify_and_probe`）→ 与 Go `:211` 同序。
- MLKEM 门 `:387-392`：`!key_share_mlkem768 → NoKeyShareX25519`（= Go `peerPub2 == nil → break`，即 X25519-only 的 ClientHello 不进入认证、直接 forward）。
- AAD 口径 `:390-406`（zero-session-id 版 handshake message）、nonce = `random[20..32]`、`auth_key = HKDF(ECDH, random[..20], "REALITY")`。
- 时间窗 `crypto.rs:258-271`：`max_diff == 0 → 跳过`（Go `MaxTimeDiff == 0 || …`）；`diff > max_diff → 拒`。
- shortId `crypto.rs:273-276`：白名单 `contains`（Go `config.ShortIds[ClientShortId]` map 查找；空表恒 false = 恒 fallback，与 Rust 空表恒拒等价，且两侧配置层都**拒启空 shortIds**）。
- 配置门（xray-core/src/inbound.rs:3450-3660）：空 `serverNames` / 空 `shortIds` / 空或非法 `privateKey` / `shortIds[i]>16` / 奇数位 hex / `xver∉{0,1,2}` **全部硬错拒启**，逐条对齐 `infra/conf/transport_security.go:94-147`。
- `maxTimeDiff` 单位：Go = `time.Duration(maxTimeDiff) * time.Millisecond`（config.go:31）；Rust = `max_diff = maxTimeDiff/1000` 秒（floor，inbound.rs:3570-3580）→ 语义等价，仅亚秒边界差（**F7**）。
- 未实现项一律**硬错**而非静默：`mldsa65Seed`（PQC 签名）、`limitFallbackUpload/Download`（限速）、`type!=tcp`、unix target、`show`、`masterKeyLog`。

### 3.2 fallback（偷自己）—— E1 决定性实验

配置：两实现同一份 `realitySettings`（`target=本地 28570+`、`serverNames=["test.example"]`、`shortIds=[""]`、同一私钥）。dest = **真 TLS 站点**（自签 `test.example`）。探针 = 普通 python TLS 客户端（**不做任何 REALITY 认证**），SNI 分别取白名单内/外。

| 探针 | Go | Rust |
|---|---|---|
| SNI=test.example（在名单） | 握手 **OK**，TLS1.3，对端证书 SHA-256 `a4578265…` = **dest 自己的证书** | 握手 **OK**，TLS1.3，同一 SHA-256 `a4578265…` |
| SNI=other.example（不在名单） | 握手 **OK**，同一 dest 证书 | 握手 **OK**，同一 dest 证书 |

**结论**：REALITY 的「未认证流量看起来就是那个真站点」这一核心反探测属性在 Rust 侧**成立**，且与 Go 完全一致（dest 侧看到的是原始 ClientHello 转发、dest 的 ServerHello 被回传）。

非 TLS 垃圾探针（`GET / HTTP/1.0`、3 字节、随机 64 字节）：两端**都**不回任何字节（Go 日志 `REALITY: processed invalid connection … failed to read client hello`，Rust `reality tls handshake error … read ClientHello: early eof`）——行为一致（dest 是 TLS 站点时，明文垃圾在 dest 侧同样被关掉，所以"无响应"是正确语义）。

### 3.3 客户端

- 认证失败 **fail-closed**：`btls_reality.rs:405-412` → `hooks.verify_handshake(ssl)?` 失败即断连；**没有**「验 HMAC 失败就退回标准链验证并接受真证书」的接受路径（Go 的 `VerifyPeerCertificate` 在链验证成功时返回 nil，但 `Verified` 仍 false，客户端随后 `return error` —— 两者最终都是拒绝）。
- 会话复用：Go 硬编码 `SessionTicketsDisabled: true`；Rust `connect_reality` **不查 session cache**（普通 TLS 的 `btls_client` 才查），等价。
- 0-RTT：REALITY 路径不 arm early data（`connect_reality` 无 early_data 参数），等价。
- 差异：**spiderX 爬行未实现**（`xray-reality/src/lib.rs:43` 自述；`util.rs:26-40` 只有确定性选 path）→ **F6**。

---

## 4. XTLS-Vision 面

| 项 | Go | Rust | 判定 |
|---|---|---|---|
| command 常量 | `Continue=0x00 / End=0x01 / Direct=0x02`（proxy/proxy.go） | `vision.rs:37-42` 同值 | 一致 |
| padding 块格式 | `[uuid16?][cmd1][clen2BE][plen2BE][content][pad]` | 同 | 一致 |
| `XtlsPadding` 公式 | `clen<seed[0] && long → rand(0..seed[1])+seed[2]-clen`，else `rand(0..seed[3])`；`cap = buf.Size-21-clen` | `vision.rs:150-187` 同式；`BUF_SIZE=2048`（`vision.rs:44`） | 一致 |
| 默认 seed | `[900,500,900,256]` | `DEFAULT_PADDING_SEED` 同 | 一致 |
| `XtlsUnpadding` 状态机 | 初始判 `len>=21 && prefix==uuid`；`remCmd 5/4/3/2/1` 逐字节；`remContent` 用 `|=`（case 3）而 case 4 用 `=`；块完成判 `cmd==0→continue else reset` | `vision.rs:199-269` 逐行同构 | 一致 |
| 攻击者可控分配 | Go 侧无（`newbuffer` 只 append 已收字节） | Rust 侧 `out.extend/pos` 全部 `min(remaining, buf.len()-pos)` 截断，**无 length 驱动的预分配** | 一致（无放大面） |
| flow 五臂（生产路） | `vless/inbound.go:552-598` | `xray-proxy-vless/src/inbound/server.rs:464-500`（`validate_flow`）+ 生产接线 `arm_builders/inbound.rs:220 serve_vless` | 一致 |
| 五臂内容 | XRV 需账号 flow=XRV / 拒 UDP / 需外层 TLS1.3 或 REALITY / 空 flow + XRV 账号 + TCP 拒 / 未知 flow 拒 | 同五臂，文案逐字对齐；`outer_tls13` 由「rustls 协商版本==1.3」或「REALITY Verified」注入（`server.rs:174`、`inbound.rs:3825`） | 一致 |
| `transfer_type` | VLESS 侧只用于 mux/vmess 分块（`common/mux/*`、`vmess/encoding/*`），vision 面用 command 字节 | Rust 同（command 语义），无独立 transfer_type 消费 | 与历史结论一致（Go 侧 vision 不读 transfer_type） |

结论：Vision 层未发现安全缺陷（无未校验长度、无 fail-open、flow 门在响应头之前失败即断连且**不走 fallback**——与 Go「已认证客户端发畸形 flow ≠ 非 VLESS 流量」语义一致）。

---

## 5. 发现表

> 严重度：P1 = 用户可见功能/安全属性失效但 fail-closed；P2 = 行为不一致或静默降级；P3 = 低危/观察项。

| 场景 | 类型 | Go 行为 | Rust 行为 | 位置 file:line | 用户可见后果 | 严重度 | 建议 |
|---|---|---|---|---|---|---|---|
| **F1** 只配 `verifyPeerCertByName`（无 `pinnedPeerCertSha256`） | 证书校验语义 | 用 CA 根 + vcn 名做**完整链验证**（`verifyPeerCert`：`certs[0].Verify(Roots=CAs, DNSName=vcn)`；`PinnedPeerCertSha256=nil` 时不进 pin 分支） | 构造 `PinnedServerCertVerifier{pins=[], vcn}` → `verify_chain([])` 返回 `CertNotFound` → 落到 `_ => Err("peer cert is unrecognized (against pinnedPeerCertSha256)")`，**任何证书都拒** | `crates/xray-tls/src/client_config.rs:175-180`（构造）、`:428-437`（pin 未命中即 Err）、`crates/xray-tls/src/config.rs:470-474`（`verify_chain` 空 pin → CertNotFound） | vcn 只能与 pin 搭配用；单独用 = 全节点连不上，且错误文案误导（说 pinned 而用户没配 pin）。E1：D1（btls 路径）与 D1b（rustls 路径）**两条路径都拒**，Go 都 accept | **P1** | `verify_chain` 返回 `CertNotFound` 且 **pins 为空**时，改为走 `WebPkiServerVerifier` + `effective_name=vcn`（等价 Go 的 `Roots=CAs` 分支）；文案区分「not found (pinned)」与「invalid (roots/vcn)」 |
| **F2** 入站 TLS 未配 `certificates` | 静默降级 | 每条连接硬失败 `tls: no certificates configured`（配置错误**立即可见**） | `build_server_config` 回退生成 **rcgen 自签证书**（`CN=rcgen self signed cert`，SAN localhost/127.0.0.1，notBefore 1975-01-01），**每次启动重新生成**，握手照常成功 | `crates/xray-tls/src/server_config.rs:201-207`（注释自述「保证 TLS 服务端总能启动」） | 漏配证书的 TLS 入站"看起来是通的"：进程起、监听在、握手成功；但没有任何客户端能信任该证书（pin 也不可能：每启动都换），排障时只看到客户端侧晦涩错误。同时向任意探测者暴露"1975 年自签 rcgen 证书"，是极明显的指纹 | **P2** | 与 Go 对齐：无证书 → 启动期 `Err`（fail-visible）。若需保留本地测试便利，改为显式配置键（如 `insecureSelfSigned: true`）并 `warn`，缺省禁止 |
| **F3** 服务端 TLS 套件协商 | 协商结果不一致 | TLS1.3 选 **TLS_AES_128_GCM_SHA256**；TLS1.2 选 **ECDHE-ECDSA-AES128-GCM-SHA256**（Go server 偏好序） | TLS1.3 选 **TLS_AES_256_GCM_SHA384**；TLS1.2 选 **ECDHE-ECDSA-AES256-GCM-SHA384**（ring 默认序） | `crates/xray-tls/src/config.rs:332-390`（`security_params` 用 ring 默认套件序，未按 Go 偏好重排）；服务端 `server_config.rs:209-233` | 同一客户端对 Go 版与 Rust 版服务端会协商出**不同的 cipher**（ServerHello 可见）→ 被动 DPI 可区分两实现；两侧都是 AEAD 强套件，**无强度损失** | P2 | 在 `security_params` 里按 Go 的偏好序重排 TLS1.3/1.2 套件（仅服务端生效时），或明确登记为"已知协商差异"并进对拍豁免表 |
| **F4** 客户端未配 `fingerprint` | wire 指纹 | `GetFingerprint("")` = `HelloChrome_Auto` → tcp+tls **永远走 utls**：GREASE + X25519MLKEM768 + 16 suites，1781B | 无 fingerprint → 真 rustls：**无 GREASE、无 MLKEM、10 suites、X25519-only，252B** | `crates/xray-transport-tcp/src/register.rs:112-152`（仅 `!fp_name.is_empty()` 走 `u_client`）vs Go `transport/internet/tcp/dialer.go:73-83` + `tls/tls.go:239-241` | 手写/工具生成但没写 `fingerprint` 的 Rust 客户端 = 教科书式 rustls 指纹，DPI 可一眼判定「非浏览器」；Go 同配置是 Chrome 指纹。反审查属性出现**实打实的洞**（此条与既有排除项「指纹不回退 rustls」不冲突：那是"配了指纹不会降级"，本条是"没配指纹时默认行为不同"） | **P2（反审查场景应视 P1）** | 与 Go 对齐：`fingerprint` 缺省按 `chrome` 走 btls（`GetFingerprint` 的缺省语义），或至少启动期 `warn`「未配 fingerprint，ClientHello 为 rustls 形态」 |
| **F5** `minVersion` / `maxVersion` | 版本门语义 | **客户端完全不生效**（utls 模板固定 supported_versions）：E1 中 `minVersion=1.3` 仍降到 TLS1.2、`maxVersion=1.2` 仍升到 TLS1.3；服务端**生效** | rustls 路径**真生效**（无 fp 时两侧都拒 `UNSUPPORTED_PROTOCOL`）；btls 指纹路径同样不生效 | Rust `crates/xray-tls/src/config.rs:392-410`；Go `tls/config.go:430-449`（设置）+ `tcp/dialer.go:73`（被 utls 覆盖） | ①带 fingerprint 时两侧都忽略（一致，但"写 minVersion 就安全"是幻觉）；②无 fingerprint 时 **Go 能连的配置 Rust 连不上**（兼容性反向差异）；③安全上 Rust 更严（fail-closed） | P2 | 决策题（交 PM）：要么 Rust 对齐 Go 的"忽略"（放弃版本门），要么保留硬门并在文档/迁移说明中写清"Rust 版 minVersion 是硬门"。**建议保留硬门**（安全侧），但必须在报错文案里点明 `minVersion/maxVersion` |
| **F6** REALITY 客户端「收到真证书」时的行为 | 反探测 | 未通过 REALITY 认证 → 先按 spiderX 参数发起 HTTP/2 爬行（伪装成浏览器访问真站点，随机 cookie padding/并发/间隔），再 `return error` | 直接断开（spider 爬行**未实现**，`lib.rs:43` 自述；`util.rs:26-40` 仅保留 path 选择） | `crates/xray-reality/src/client.rs:463-500`（无 spider 调用）；对照 Go `reality.go:201-300` | 被动/主动探测者对被 MITM 或错配的 Rust 客户端只看到"连接立刻断"；Go 会先产生一组像浏览器的请求。**不改变 fail-closed 语义**，但破坏「客户端也参与对抗」的设计意图 | P3（反审查场景 P2） | 若要补：复用 `xray-transport` 的 h2 客户端 + spiderY 参数实现 crawl；否则在文档写明「spiderX 仅解析不消费」并登记为差异 |
| **F7** `maxTimeDiff` 亚秒边界 | 边界 | `|Δt| <= N ms`（`time.Since` 含小数） | `diff === floor(N/1000)` 秒，整秒比较 | `crates/xray-core/src/inbound.rs:3570-3580`；`crates/xray-reality/src/crypto.rs:258-271` | N 非 1000 整数倍时，Rust 在最后不足 1 秒的窗口比 Go 多放行（如 43200ms：Go 只有 Δt≤43.2s 通过，Rust 放行到 43s 整——差异 ≤1s，且**方向是更宽**）。对 REALITY 重放窗口的影响量级 ~2%，可忽略但应登记 | P3 | 传 `Duration`/毫秒而非秒进 `verify_session_payload`，用毫秒比较即可逐位对齐 |
| **F8a**（交叉引用，不新开票）`useSystemCA` | 信任根来源 | 被消费：Windows `UseSystemCa && 无证书` → `RootCAs=nil`（用系统库）；Unix `loadCA(UseSystemCa)` | 全仓**零读取**（`grep useSystemCA` 无命中），恒用 webpki-roots 或 `certificates[]` | Rust `crates/xray-tls/src/client_config.rs:231-249`；Go `transport/internet/tls/config_windows.go:17-28`、`config_other.go:17-22` | 企业/私有 CA 装在系统信任库时：Go 验得过，Rust 验不过（fail-closed）。属既有票 `1avs1` 面，此处仅补**行为**证据 | P3（票已存在） | 归 `1avs1`：接线 `useSystemCA`（Windows 走系统库 / 其它平台编译期选择） |
| **F8b**（交叉引用，**非差异**）OCSP 装订 | 吊销检查 | **不校验**：Go 走 utls 的 `verifyServerCertificate`，函数体内只有链验证，**没有** OCSP 分支（`utls@v1.8.3…/handshake_client.go:1122-1229` 全函数无 `ocspResponse` 消费；Go 标准库同样只把装订响应存进 `ConnectionState` 不验） | **不校验**：btls 回接验证恒传 `ocsp_response: &[]`；rustls 路径同样不消费 | `crates/xray-tls/src/btls_client.rs:1445-1452`（对照 utls `handshake_client.go:1122-1229`） | 无差异（两侧吊销检查都形同虚设）。**结论修正**：吊销不是本项目的防御面，信任锚应靠 `pinnedPeerCertSha256`；此条仅登记，**不建票** | —（仅存档） | 无需改；若要引入吊销检查须两侧同时做（否则破坏对拍） |
| **F8c**（交叉引用）证书错误可见性 | 线上可观测差异 | 校验失败在**握手期**发 alert（`bad_certificate` / `unknown_ca`） | btls 路径是**握手完成后**回接验证 → 线上表现是"握手成功后 RST"，无 alert | `crates/xray-tls/src/btls_client.rs:1383-1385` | MITM 侧可区分（Rust 会与 MITM 完成一次握手但不发任何应用数据）；对用户/安全属性无影响 | P3 | 无需改；仅登记（这是"保指纹"的代价） |

---

## 6. 与既有票的关系（未重报）

- **不重报**：`allowInsecure` 配置期硬错（`5x41`，实测 `xray-conf/src/init.rs:297-314` 对 `security=tls` 的 `tlsSettings.allowInsecure` 拒启——本报告所有 allowInsecure 用例仅作为**对照/构造夹具**，不主张缺陷）；指纹配置后不回退 rustls（实测 `utls.rs:588-620` 硬错）；vision flow 非法值硬错（`plugin.rs:397-433`）；rustls record 拷贝（`slv4n`）；`useSystemCA` 键面（`1avs1`，本报告补行为证据）。
- **可并入既有族**：F2 属「静默降级」族（`vaye2`/`o91s4` 同根：装配期该 fail-visible 的地方 fail-silent），并与 `0bzcd`（Go↔Rust 配置面 fail-open 差异 13 例）相邻但**不同层**——`0bzcd` 是"Go 拒启 / Rust 放行"，F2 是"两侧都启动，但 Go 每条连接失败、Rust 握手成功"；建议并入 `0bzcd` 或单开一张 P2。
- **建议新开票**：F1（`verifyPeerCertByName` 单独配置 → 全拒，P1，两条路径）；F4（未配 fingerprint → rustls 形态 ClientHello，反审查 P1/P2）；F3（服务端套件协商可区分）；F5（客户端版本门语义相反，需 PM 拍板"对齐 Go 忽略"还是"保留硬门 + 文案"）；F6（REALITY 客户端 spiderX 未实现）；F7（maxTimeDiff 毫秒→秒 floor）。

---

## 6.5 影响范围（沿调用链）

```
F1 vcn-only 全拒
  xray-transport-tcp/register.rs:148 | websocket/client.rs:155 | grpc/transport.rs:250
  | httpupgrade/register.rs:527 | splithttp/register.rs:130+（同一 build_client_config）
    → 全部经 xray_tls::utls::u_client / utls::client
    → build_client_config(client_config.rs:175) / build_server_cert_verifier(client_config.rs:279)
    → PinnedServerCertVerifier(client_config.rs:406-470) → verify_chain(config.rs:127-160) = CertNotFound → Err
  ⇒ 任何「只写 verifyPeerCertByName、不写 pinnedPeerCertSha256」的出站全部连不上（两条路径）

F2 入站无证书静默自签
  xray_core::start_full → arm_builders/inbound.rs（build_tls_acceptor）
    → xray_tls::server_config::build_server_config(server_config.rs:178-207)
  ⇒ 所有 security=tls 入站（vless/vmess/trojan/http/socks/…）；security=reality 不走此分支

F3 服务端套件序
  build_server_config(server_config.rs:209-233) → config::security_params(config.rs:332-390)
  ⇒ security=tls 服务端走 server_config.rs；security=reality 服务端走 xray_reality::mitm::build_server_config(:121-132，同一 ring provider 默认序) → **两类服务端同样可区分**

F4/F5 客户端默认指纹与版本门
  xray-transport-tcp/register.rs:112-152（fingerprint 空 → utls::client=rustls）
  xray-transport-websocket|grpc|httpupgrade|splithttp 同构
  ⇒ 所有 security=tls 出站；security=reality 恒走 btls 指纹（不受影响）

F6 spiderX 缺失 / F7 maxTimeDiff 亚秒
  xray-reality::client::u_client(client.rs:463) / server::verify_and_probe(server.rs:511)
  ⇒ REALITY 客户端（反探测面）/ REALITY 服务端时间窗
```

工具说明：本轮以 `grep` 工具（结构化命中）+ 定点 `read` 做符号级定位，未启用 serena-cli/LSP——理由是同一结论需要在 Go 仓（`D:/Project/Xray-core`、`xtls/reality` 模块缓存、`utls` 模块缓存）与 Rust 仓两侧逐行对照，LSP 不覆盖前两者；所有引用均给出 file:line，可按行号复核。

---

## 7. 未覆盖面（查了什么 / 没查什么 / 置信度）

**已实测（E1）**
1. 客户端证书校验 12 个场景 × 双实现（含过期证书、pin 语义、vcn、SNI 不匹配、自定 CA）。
2. 服务端 TLS 5 个场景 × 双实现（无证书 / SNI 不匹配 / rejectUnknownSni / minVersion / maxVersion），含 rcgen 证书指纹与"每次启动不同"复测。
3. ClientHello 抓取解析 7 组配置 × 双实现（supported_versions / cipher_suites / ALPN / groups / key_share / GREASE / record 长度）。
4. REALITY fallback 决定性实验：探针拿到的证书 SHA-256 与 dest 自身证书一致（4/4 组合）。
5. REALITY 畸形/伪造输入回落 8 组（明文 HTTP、3 字节、随机字节、TLS1.3 列内/列外 SNI、无 SNI、TLS1.2、h2 ALPN）+ dest 收到字节比对。
6. 生产接线核对：`serve_vless` / `validate_flow` / `outer_tls13` / `VisionConn` 装配点。

**未查（明确缺口）**
- 指纹面逐字节等同性（明文 ClientHello 与真浏览器 diff）——前置结论已排除，本轮未复议（只记录 Go/Rust 差异量级）。
- TLS 1.3 session resumption / 0-RTT 在 REALITY 与 vision 组合下的端到端实测（静态等价已核对：Go `SessionTicketsDisabled=true`，Rust REALITY 路径无 session cache；Rust 普通 TLS 的 0-RTT 仅 ws/httpupgrade opt-in）。
- mTLS（`usage:"verify"`，Rust 私有扩展）的真实生效（未测）；OCSP 装订**已查清**：Go（utls `verifyServerCertificate` 无 OCSP 分支）与 Rust 两侧都不校验 → 非差异（F8b）。
- 服务端 `curvePreferences`/`cipherSuites` 的非法值降级路径（只读代码：warn + 跳过，不硬错）。
- WSL tcpdump/scapy 抓包：本轮改用「应用层可观测点（dest 侧字节 + ClientHello 解析 + 证书 SHA-256）+ 双实现同输入」取证，未做 pcap 级抓包。

**置信度**
- F1 / F2 / F3 / F4 / F5 / fallback 一致 / Vision 一致：**E1 高**（真实双二进制 + 同输入 + 双向对照）。
- F6（spider 未实现）：E1 高（代码 + lib.rs 自述；未构造 MITM 端到端场景）。
- F7 / F8a / F8b / F8c：E2（代码逐行 + Go 对照），未做端到端。

---

## 8. 结论

1. **安全属性层面成立**：证书链/主机名/有效期在两条客户端路径都真验证（无静默跳过）；REALITY 服务端认证门顺序与判据逐条对齐，且**未认证流量被原样转给真站点**（探针拿到 dest 自己的证书，与 Go 逐字节同构）；REALITY 客户端未认证即断连（fail-closed）；Vision 的常量/公式/状态机/flow 五臂与 Go 逐行对齐，热路径无攻击者可控分配。
2. **需要修的不是"被攻破"，而是"与基准不一致"**：F1（vcn 单独不可用，P1）、F2（无证书静默自签，P2、可被误部署）、F4（默认无 fingerprint → rustls 指纹，反审查面 P2/P1）、F3（服务端套件可区分）、F5（版本门语义相反）。
3. 建议修复顺序：F1 → F4 → F2 → F3 → F5 → F6 → F7。F1/F2/F4 都应在装配期或校验层一处收口，改动面小、可由 fullstack 一次落地并配「E1 复测脚本」回归（本轮 harness 可直接当验收工具）。

*（本报告为只读审计，未改任何产品代码；所有结论附命令/产物路径可复现。）*

# 第三轮审计：加解密与协议字节级正确性（crypto.md）

- 日期：2026-09-06　|　审计对象：Xray-core-rust（D:/Project/Xray-core-rust）
- Go 基准：D:/Project/Xray-core（v26.7.28）；REALITY 服务端语义对照 github.com/xtls/reality@v0.0.0-20260322125925（本机 go mod cache 实源核验）
- 方法：只读代码，逐域对照 Go 逐字节抽查（每域 ≥3 个字节级抽查点），证据均给 file:line。
- 已知勿重复（前两轮 38 项）：socks 认证绕过、http 握手无界、tuic 帧长、vless dispatcher.rs:178、xor_mode 0/1/2、btls_reality hooks、ss2022 server_sessions 泄漏/SlidingWindow 淘汰/恒时比较、MacNonce 不对称、hysteria protocol.rs:105 等，本报告均不重复。

---

## 一、发现汇总

严重度统计：P0×0　P1×1　P2×3　P3×5（另记录"不可触发偏差"1 项、代码自认妥协/负优化 5 项）

---

### [P1] VLESS ENC 客户端缺失 0-RTT 票据失效恢复路径（服务端重启后持续黑洞至票据自然过期）
- 位置：`crates/xray-proxy-vless/src/encryption/common_conn.rs:185-188`；`crates/xray-proxy-vless/src/dispatcher.rs:183-187`
- 证据（Go）：`proxy/vless/encryption/common.go` Read() 中 `DecodeHeader` 失败且 `Client != nil && bytes.HasPrefix(c.UnitedKey, c.Client.PfsKey)` 时：置 `c.Client.Expire = time.Now()`（立即作废缓存票据）并返回 `"new handshake needed"`，Go 源码注释明确 **"DO NOT CHANGE: relied by client's Read()"**——该错误消息是客户端恢复机制的协议约定。下次连接 `time.Now().Before(i.Expire)` 为假 → 走全新 1-RTT 握手拿到新票据，**一次失败即自愈**。
- 证据（Rust）：`common_conn.rs:185-188` 对 `decode_tls_record_header` 错误直接 `Poll::Ready(Err(InvalidData))`；全仓 grep 无任何"invalid header → 作废 expire_cache → 重新握手"逻辑（`expire_cache` 仅在 init() 清空与握手成功时写入 mod.rs:532）；`dispatcher.rs:183-187` 握手失败直接把错误上抛，不重试。
- 触发与影响：Go 服务端对 miss/过期票据写 1279~2279B 噪声（`encryption/server.go:213-220`），噪声经 Rust 客户端 CommonConn 被当作 16B serverRandom + TLS record 解析 → 必然 invalid header → 连接失败。**服务端重启/换实例**（0-RTT Sessions 全丢）或票据被 60s 清理任务先于客户端过期剔除时，客户端在 `expire` 缓存到期前（= 票据有效期，典型 3600×[50%,100%)，即数十分钟）**每次重连都重复 0-RTT→噪声→失败**，业务表现为该出站长时间不可用；Go 基线仅损失 1 个连接。
- 修复建议：在 `CommonConn::poll_read` 的 `decode_tls_record_header` 失败分支：若构造时携带客户端 PfsKey 前缀比较（`united_key.starts_with(pfs_key_cache)`），清空 `pfs_key_cache/ticket_cache/expire_cache` 并返回专门的 `NewHandshakeNeeded` 错误；`dispatcher.rs` dial 侧识别该错误后**重试一次**全新握手。
- 负优化自查：恢复路径只在"票据确已失效"时多一次 dial+握手，happy path 零开销；不加轮询、不加状态——正优化。

### [P2] REALITY maxTimeDiff 语义三重偏差：默认值、单位（ms vs s）、0=禁用语义
- 位置：`crates/xray-core/src/inbound.rs:1477-1480`；同模式复制于 `crates/xray-transport-splithttp/src/transport.rs:314-317`
- 证据（Go）：`infra/conf/transport_security.go:38` `MaxTimeDiff uint64 json:"maxTimeDiff"`（**未配置默认 0**）→ `transport/internet/reality/config.go` `MaxTimeDiff: time.Duration(c.MaxTimeDiff) * time.Millisecond`（**单位毫秒**）→ xtls/reality `tls.go:259`：`config.MaxTimeDiff == 0 || time.Since(ClientTime).Abs() <= MaxTimeDiff`——**0 表示完全不校验时间窗**。
- 证据（Rust）：`inbound.rs:1477-1480` `json.get("maxTimeDiff").unwrap_or(43200) as u32`（**缺省注入 43200 且按秒解释**）；`crypto.rs:281-287` `diff > max_diff` 即拒——显式配 0 时变成"任何非零偏差都拒绝"。
- 影响：①缺省行为不同：Go 无时间窗校验，Rust 强加 ±12h 窗（Go 语义下合法的远偏差客户端被拒）；②单位错 1000 倍：运维按 Go 文档配 `maxTimeDiff=30000`（30s 防重放收紧），Rust 解释为 30000s≈8.3h——**防重放窗口被放大三个数量级**；③显式 0 从"禁用"变"全拒"。
- 修复建议：`let ms = json.get("maxTimeDiff").and_then(as_u64).unwrap_or(0)`；`max_diff_secs = (ms/1000) as u32`；`verify_session_payload` 增加 `if max_diff == 0 { 跳过时间窗校验 }`（等价 Go `MaxTimeDiff == 0 ||` 短路）。
- 负优化自查：纯语义对齐，无性能影响——正优化。

### [P2] VLESS ENC 服务端缺失 AES→ChaCha 硬件回退：无 AES-NI 客户端握手必败
- 位置：`crates/xray-proxy-vless/src/encryption/mod.rs:894`（1-RTT）、`mod.rs:1093`（0-RTT）、客户端侧 `mod.rs:332`
- 证据（Go）：`encryption/server.go:176-183`：首个 encryptedLength Open 失败后 `c.UseAES = !c.UseAES; nfsAEAD = NewAEAD(iv, nfsKey, c.UseAES)` 重试——Go 服务端自动兼容 `HasAESGCMHardwareSupport=false` 的客户端（Go 客户端按 CPU 选 AES-256-GCM 或 ChaCha20-Poly1305，`client.go:70` + `common/protocol` GetSecurityType 同源逻辑）。
- 证据（Rust）：三处硬编码 `let use_aes = true;`（注释自认"阶段 B：假设 AES 硬件支持"），Open 失败无回退分支。
- 影响：跑在无 AES 硬件加速环境（部分 ARM VPS/老虚拟机）的 Go/其他实现客户端对 Rust 服务端握手必败；Rust↔Rust 自洽、x86_64↔x86_64 互操作测不出（现网 32 节点均为带 AES-NI 环境）。
- 修复建议：在 1-RTT 分支读 encryptedLength 的首次 `nfs_aead.open` 失败处，翻转 `use_aes` 重建 `Aead::new(&iv, &nfs_key, false)` 重试一次；成功后沿用该 flag 贯穿本连接（含 0-RTT 分支与后续 CommonConn）。
- 负优化自查：仅在解密失败路径多一次 blake3 派生 + ChaCha 实例化，常规路径零变化——正优化。

### [P2] ss2022 客户端未校验响应头 request-salt 回显（SIP022 MUST 项）
- 位置：`crates/xray-proxy-ss/src/ss2022/client.rs:259-264`
- 证据（Go/规范）：SIP022 规定服务端响应 fixed chunk 明文 = `[type=1][timestamp 8B][request_salt salt_len B][len 2B]`，客户端 **MUST** 比对回显 salt 与己方请求 salt，不符即断开（sing-shadowsocks `clientConn.readResponse` 同行为）。该绑定使"捕获的旧响应重放进新连接"必然因 salt 不匹配被拒。
- 证据（Rust）：解密 fixed_plain 后仅校验 `fixed_plain[0]==1` 与 `|ts-now|>60s`，`client.rs:259-260` 注释自认"Go 比较但客户端 outbound 仅记录不强制"，随后直接跳到 `payload_len` 解析——`fixed_plain[9..9+salt_size]` 从未与请求 `salt` 比对。
- 影响：活跃攻击者可将 30s 时间窗内捕获的"服务端→客户端"响应（resp_salt+fixed+var 整段）重放到同用户的新连接；响应 subkey 只依赖 psk 与重放包自带的 resp_salt，解密必过，客户端把旧响应当作新请求的应答消费。跨连接应答重放防线缺失。
- 修复建议：在 ts 校验后加 `if fixed_plain[9..9+salt_size] != salt[..] { return Err(Ss2022ResponseSaltMismatch) }`（`salt` 即本函数 L119 生成的请求 salt，作用域内可用）。
- 负优化自查：一次 `salt_len`（16/32B）memcmp，无回退风险——正优化。

### [P3] vmess 服务端接受线上 security=AUTO(0x02) 并本地解析，Go 服务端拒绝
- 位置：`crates/xray-proxy-vmess/src/encoding/server.rs:252-263`
- Go：`encoding/server.go` `parseSecurityType` 把 0(UNKNOWN)→AUTO 后，显式 `if Security == UNKNOWN || Security == AUTO { return "unknown security type" }`——线上 0/2 一律拒收（客户端侧 `GetSecurityType()` 已在配置期解析，从不上线 AUTO 字节）。Rust 服务端 `SecurityType::Auto` 分支按 CPU 硬件解析成 GCM/ChaCha 继续处理。影响：Rust 服务端比 Go 宽容（非安全漏洞——解析结果仍是真加密），属行为面偏差，可被用于服务端指纹区分。

### [P3] vmess 客户端 ChunkMasking/GlobalPadding 依据未解析的 config.security 判定，auto 档流量形态偏离 Go
- 位置：`crates/xray-proxy-vmess/src/dispatcher.rs:231-245`
- Go outbound 先 `request.Security = account.Security`（GetSecurityType 已把 auto→GCM/ChaCha）再按**解析后**值置 `ChunkMasking`（+GlobalPadding）。Rust `use_masking` 匹配的是 `config.security`（原始值）：auto→GCM 时不置 0x04/0x08，上线明文 size 前缀、无 padding。wire 自描述故功能互通，但 chunk masking 是 Go AEAD 档的常态流量特征，缺失即形成可 DPI 识别的指纹差。建议改用已解析的 `security` 变量判定。

### [P3] VLESS ENC 服务端未认证客户端 padding 段
- 位置：`crates/xray-proxy-vless/src/encryption/mod.rs:1037-1038`
- Go `server.go:312-317` 读客户端 padding 后 `nfsAEAD.Open` 校验、失败即断；Rust 仅 `read_exact` 截断丢弃（无 `nfs_aead.open`）。长度字段本身已认证（18B encryptedLength 有 Open），故影响限于"padding 内容可被中间人任意篡改而不被发现"，无密钥/数据后果——认证覆盖面与 Go 不一致。

### [P3] REALITY 服务端未实现 MinClientVer/MaxClientVer 版本门
- 位置：`crates/xray-core/src/inbound.rs:1425-1431`（`RealityInboundConfig` 无该两字段）；`crates/xray-reality/src/crypto.rs:265-287`（`verify_session_payload` 解析出 version 但无人比对）
- Go：xtls/reality `tls.go:257-258` 用 `Value(ClientVer) >= MinClientVer && <= MaxClientVer` 参与会话放行判定。配置字段在 `xray-reality/src/config.rs:90-91` 存在但生产 inbound 不解析不传递。影响：运营者用版本门做抗封锁指纹管控的特性失效（缺省不设门时两者等价）。

### [P3] Hysteria auth 响应头两处硬编码，偏离 Go 流量形态
- 位置：`crates/xray-transport-hysteria/src/quinn_adapter.rs:634-638`
- Go `hub.go:51,103-105`：`Hysteria-Padding: AuthResponsePadding.String()`（="256-2048"）、`Hysteria-UDP: strconv.FormatBool(h.validator != nil)`。Rust 恒 `"0"` 与恒 `"true"`。Go 客户端不解析这两头（dialer.go 仅读 CC-RX），无功能影响；但固定值对已知 Go 响应形态的 DPI 属稳定指纹。

### [记录] VLESS ENC MaxNonce 换钥语义偏差（当前代数下不可触发，仅留档）
- `common_conn.rs:300-304`：Rust 在 `is_max()` 时**先换钥**（ctx=5B header）再以新钥 nonce=1 封装；Go `common.go:52-59/114-120` 用旧钥（IncreaseNonce(MaxNonce) 回绕 nonce=0）封装最后一帧后**再换钥**，ctx=整帧 `header+ct+tag`，读侧对称。触发需单方向 2^96 个 record（约 10^21 TB），物理不可达；两端各自自洽，不影响现网互通。不做修复。

---

## 二、代码自认妥协/负优化专项记录（任务要求单独记录）

1. **ss2022 UDP server session 轮换无 60s 限频**（`crates/xray-proxy-ss/src/ss2022/packet.rs:374-377` ponytail 注释）：Go 对 server sessionId 频繁切换有 `ErrTooManyServerSessions`（60s 一次）防 DoS；Rust 保留两代轮换但不限时，作者自认"防 DoS 语义弱化"。建议补一个 `last_rotate: Instant` 上限即可，成本一行。
2. **ss2022 UDP SlidingWindow BTreeSet 近似**（packet.rs:100-115）：容量 64，淘汰最小 id；作者注明"窗口边界外极旧 id 重放可能重新接受"（属已知 P2 淘汰问题的实现形态，勿重复报，此处仅留档）。
3. **VLESS ENC padding 分段发送简化为一次性发送**（mod.rs:648 注释"padding 分段发送：简化为一次发送"）：Go `paddingLens/paddingGaps` 按段写+sleep 制造可变流量形态；Rust 字节等价但流量整形（fragmentation+gaps）缺失，对抗面退化，无正确性影响。
4. **vmess `NO_TERMINATION_SIGNAL=0x80`**（`crates/xray-common/src/protocol/mod.rs:297-298`）：Go 中 NoTerminationSignal 是账号级配置（`account.TestsEnabled`），**从不上线**；Rust 定义为请求 option 位并据以跳过终止 chunk。Go 对端忽略未知位故互通无损，但这是 Go 不存在的自造 wire 位，建议降级为本地配置开关避免线上歧义。
5. **vmess 服务端响应缺 Go 死代码 CFB 层**：Go `EncodeResponseHeader` 设置的 AES-CFB CryptionWriter 在 AEAD 路径实际不被使用（inbound.go:189-191 直接把 raw output 传给 EncodeResponseBody；客户端对称不读）——Rust 未实现该层**与线上字节一致**，确认为正确取舍（若未来有人"补全"该层反而制造不兼容，特此留档防误修）。

---

## 三、确认干净项清单（逐域字节级抽查点）

### ① vmess 请求头编解码 — 抽查 10 点全部一致
| 抽查点 | Rust | Go | 结论 |
|---|---|---|---|
| AuthID 布局：8B time BE + 4B rand + CRC32-IEEE(前12B) BE，AES-128 单块加密，key=KDF16(cmdKey,"AES Auth ID Encryption") | aead/mod.rs:204-223 | aead/authid.go:20-38 | ✓ 一致 |
| 认证时间窗 ±120s + t<0 拒绝 + 120 条反重放（先时间后重放序） | aead/mod.rs:571-598 | aead/authid.go:101-116 | ✓ 一致 |
| AEAD 头 KDF 路径序 `[salt, authID, nonce]`；布局 `[16 authID][18 len][8 nonce][payload]`；AAD=authID；len 为 2B BE | aead/mod.rs:263-476 | aead/encrypt.go:12-133 | ✓ 一致 |
| KDF 嵌套 HMAC（hash2 语义：内层 HMAC 作外层哈希），Go authid_test 向量对拍 | aead/mod.rs:69-186（测试 :713-717） | aead/kdf.go:10-30 | ✓ 一致（含向量） |
| 38B 头偏移：0=ver,1-16 IV,17-32 key,33 respV,34 option,35 pad<<4\|sec,36 rsv,37 cmd | encoding/server.rs:181-200 | encoding/server.go:199-217 | ✓ 一致 |
| FNV1a-32（0x01000193），头尾 4B BE 比对 | encoding/mod.rs:41-48、server.rs:246-254 | server.go:253-262、auth.go:16-22 | ✓ 一致 |
| option 位 0x01/0x04/0x08/0x10；padding 高 4 位 dice[0,16) | xray-common/protocol/mod.rs:290-296、client.rs:113-117 | headers.go:33-42、client.go:74-76 | ✓ 一致 |
| 地址：PortThenAddress + ATYP 1/2/3 | encoding/mod.rs:239-262 | encoding.go:14-19 | ✓ 一致 |
| Command 值 TCP=1/UDP=2/Mux=3（v26 现行值） | lib.rs:56-83 | headers.go:14-18 | ✓ 一致 |
| ChunkNonce counter 写 `c[0..2]` BE（v26 新语义）；chunk size=ct+pad；SHAKE 消费序两端 padding→size；终止 chunk=seal(空)含 padding；body key/iv=SHA256[:16]；响应 AEAD len/payload KDF；AES-CFB 响应层为 Go 死代码（见二.5） | body_chunk.rs:251-311/368-404、client.rs:60-90、server.rs:348-384 | auth.go:119-135/246-276、client.go:294-303、server.go:267-334 | ✓ 一致 |

### ② VLESS ENC（xor_mode 除外）— 抽查 9 点一致（发现 P1/P2×2/P3 见上）
- relays 长度公式 `Σ(32+32 | 1088+32) − 32`、hash32=blake3(pub)、XorMode CTR 应用序、lastCTR 前 32B 防替换、X25519 MSB=0 校验：mod.rs:180-264 / 790-860 ↔ Go client.go:50-99 / server.go:117-160 ✓
- PFS_LEN=1250=18+1184+32+16、长度字段 EncodeLength(1232)、pfsPublicKey=mlkem ek(1184)+x25519(32)：mod.rs:267-330 ↔ Go client.go:133-147 ✓
- blake3 NewAEAD 上下文/密钥参数序、nonce 小端自增、AES-256-GCM/ChaCha 分支：aead.rs:39-133 ↔ Go common.go:158-183 ✓
- UnitedKey=pfs(32+32)+nfs(32)；AEAD ctx 四组（pfsPublicKey 明文 / 对端密文[:1120] / 0-RTT 上=encTicket32 / 下=PreWrite16）逐组对上（含 Go in-place Open 后取明文字节的细节）：mod.rs:477-490 ↔ Go client.go:172-177 / server.go:254-261 ✓
- 0-RTT 快路径：`seconds>0 && now<Expire` 条件、PreWrite 布局 iv+relays+18+32、ticket 16B=2B seconds+14B rand、expire=now+seconds：mod.rs:340-410 / 523-537 ↔ Go client.go:113-129/186-194 ✓
- 服务端 0-RTT：未启用拒、ticket miss 写 1279~2279 噪声（重生成至非 TLS 头）、`insert()=false` 等价 LoadOrStore 防重放：mod.rs:1093-1170 ↔ Go server.go:198-235 ✓
- 票据签发：seconds=From×RandBetween(50,100)/100 | RandBetween(From,To)、`Lasts[(now+max)/60+2]`、60s 清理含 minute-1 保险：mod.rs:984-1023 / 617-631 ↔ Go server.go:264-284/88-106 ✓（±1 分钟桶差被 +2 余量吸收，核算无窗口漏洞）

### ③ ss2022 — 抽查 8 点一致（发现 P2×1 见上；已知三项不重复）
- 子密钥 `blake3("shadowsocks 2022 session subkey", psk‖salt)[:key_len]`、identity subkey 同构：ss2022/key.rs:60-95 ↔ sing SessionKey/KDFIdentitySubkey 常量 ✓
- salt 长度=key_size（读侧 read_exact(key_size) 即校验；写侧 random(key_size)）：inbound.rs:419-422/516-519、client.rs:75-79 ✓（任务点"salt 长度校验"确认无缺陷）
- TCP fixed chunk 11B=type(0)+ts8+len2；±30s 双向；type≠0 拒：inbound.rs:433-464/620-631 ↔ SIP022 ✓
- 多用户 TCP EIH：ECB(identitySubkey(iPSK,salt)) 解密 → psk_identity(uPSK) 查表 → uPSK 派生 session key：inbound.rs:508-559 ↔ sing SIP023 ✓
- UDP：包头 ECB(psk, sessionId‖packetId)、EIH=ECB(raw iPSK, identity⊕hdr)、sessionKey(psk, sid_be8)、nonce=hdr[4..16]、回包两代 remote、clientSessionId 回填校验：packet.rs:275-403 ↔ sing UDP 语义 ✓（配置面 n≤2，eih_len 硬编码 16 无歧义）
- UDP 时间戳 ±30s（任务点"墙钟回退"：两端同为墙钟 ±30s，回退>30s 双双全拒，语义一致）：packet.rs:156-161/186-190 ✓
- 响应头 type=1+ts8+echo_salt+len2（测试含手工解密逐字节断言）：inbound.rs(测试):1259-1282 ✓
- PSK 规整（等长/SHA256 截断/过短报错）、nonce 从 0 起 LE 自增：key.rs:136-160、client.rs:295-300 ✓

### ④ Hysteria 混淆层 — 抽查 5 点一致（发现 P3×1 见上）
- salamander 密钥派生 `BLAKE2b-256(PSK‖8B salt)`、keystream `i%32` 循环 XOR、包格式 `[8B salt][payload]`、PSK≥4：finalmask/salamander.rs:36-98 ↔ Go salamander/salamander.go:20-70 ✓（逐字节一致，含 config 密码 `[]byte(password)` 直用）
- gecko 分片头/短头透传结构与 Go conn.go 对应（reassembly TTL 8s / max 4096 / per-source 8）✓
- auth 帧：POST `https://hysteria/auth`、`Hysteria-Auth`/`CC-RX`（请求带 BrutalDown）/`Hysteria-Padding`、StatusAuthOK=233：hysteria_transport.rs:30-32/185-191 ↔ hub.go:43-56/198-200 ✓
- padding 范围常量 256-2048 / 64-512 / 128-1024：config.rs:96-106 ↔ Go 同名包级 var ✓
- TCP/UDP 帧结构（varint addr、status+msg+padding、UDP session/pkt/frag 头）：protocol.rs:99-290 ↔ proxy/hysteria/protocol.go ✓

### ⑤ REALITY — 抽查 7 点一致（发现 P2/P3 见上；btls hooks 已知不重复）
- session_id 明文布局 `[ver(3)][0][ts u32 BE][shortId 8B 零填充]`，版本声明 [26,7,28]：crypto.rs:69-98、client.rs:56-58 ↔ reality.go:143-152 ✓
- auth_key=X25519(ecdhe,serverPub)→HKDF-SHA256(salt=random[:20], info="REALITY", 32B)：crypto.rs:101-135 ↔ reality.go:170-173 及 xtls/reality tls.go:230-234（实源核验）✓
- AES-256-GCM 加密 sid[:16]，nonce=random[20:32]，AAD=**zero-session-id 版 handshake**（client 置零先于加密、server 解密前重置零，实源 tls.go:241-248 `original` 语义）：crypto.rs:138-232、server.rs:217-268 ↔ reality.go:174-179 ✓
- 时间窗 `abs(diff)<=max` 双向方向与实源 tls.go:259 `time.Since().Abs()` 一致 ✓
- shortId 8B 零填充白名单匹配：crypto.rs:289-291 ↔ tls.go:260 ✓
- 证书 HMAC-SHA512(auth_key, ed25519 pub) 恒时验证 / 服务端 sign_reality_certificate 对偶：crypto.rs:311-360 ↔ reality.go:85-97 ✓
- 验证失败 → fallback dest + PROXY protocol（xver 0/1/2）：server.rs:330-344 ✓

### ⑥ Trojan — 抽查 5 点一致
- `hex_sha224`：SHA-224 → **小写** hex → 56B（已知向量 d63dc919… 对拍）；Go `hex.Encode` 同为小写 56B：config.rs:100-111 ↔ trojan/config.go:41-46 ✓（任务点"大小写/长度"确认一致）
- TCP 头 `[56B key][CRLF][cmd 1|3][SOCKS5 addr][CRLF]`：protocol.rs:174-230 ↔ protocol.go writeHeader/ParseHeader ✓
- UDP 包 `[addr][2B BE len][CRLF][payload]`，len≤8192：protocol.rs:233-305 ↔ PacketWriter/PacketReader ✓
- 地址 ATYP 0x01/0x03/0x04 + port-after-address（SOCKS 序）：protocol.rs:63-100 ↔ addrParser(AddressFamilyByte 1/3/4) ✓
- Validator hex 字符串双索引（email + hex(key)），hex 小写一致：validator.rs:79-171 ↔ validator.go ✓

---

## 四、结论

六个域中 **trojan、hysteria 混淆层全绿**；vmess、ss2022、REALITY 主体字节级一致，仅边界行为/语义档位偏差（P2/P3）；**唯一高危是 VLESS ENC 客户端 0-RTT 失效恢复缺失（P1）**——Go 用错误消息约定的恢复协议在 Rust 端断链，服务端重启即触发分钟级黑洞。全部修复建议均为纯语义对齐/补校验，无一引入性能回退（P1 修复多一次 dial，P2×3 均为 O(1) 常量开销或仅失败路径）。

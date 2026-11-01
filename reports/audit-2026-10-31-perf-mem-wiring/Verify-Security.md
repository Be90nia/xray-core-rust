# Verify-Security — 安全面第二轮对抗复核（空口令 fail-open 可利用性）

- 目标仓：`D:/Project/Xray-core-rust` @ `feature/fix-inbound-parity` HEAD **`5fe98b90`**
- 被测二进制：`target/release/xray.exe`，`version` 自报 `git_rev=5fe98b907c7b550d4a70202abb475e26ee89013d` → **与 HEAD 一致，E1 成立**
- Go 对照：`D:/tmp/go2617/xray.exe` = **Xray 26.10.17** `92ccc93-dirty (go1.27.0)`，源码 `D:/Project/Xray-core` @ `92ccc939`
- 客户端：**手写协议客户端**（不用任何一款 xray 当客户端）——模拟「攻击者只知道口令是空串这一公开常量」，自己算 KDF/sha224 接入
- 脚本：`scripts/verify_empty_password_e1.py`（E1 数据面）、`scripts/verify_credential_defaults_matrix.py`（12 协议 × 双实现启动矩阵）

---

## 0. 裁决速览

| 编号 | 原断言 | 裁决 |
|---|---|---|
| F11 | ss `users[].password` 缺省 `""` → 公开常量凭据 | **成立，且比原断言更宽**：不只 `users[]`，单用户 `"password": ""` 同样放行；E1 打通数据 |
| F12 | trojan `clients[].password` 缺省 `""` → 公开常量凭据 | **可利用性成立（E1）**，但**「Go 拒启」对照是错的**：Go 26.10.17 的 trojan **入站**同样接受空口令并打通数据；拒启只存在于**出站客户端**配置 |
| F03 | splithttp `downloadSettings` 解析但只 `is_some()` | **成立**；附带发现解析错误被 `.ok()` 静默吞掉 |
| F02 | quic `quicParams.udpHop` 零消费 + 口径与 Go 相反 | **成立**（Go 的 `QuicParamsConfig` 根本没有该字段 → 完全忽略；Rust 解析+校验，`interval<5` 硬拒启，且无人消费） |
| F09 | hysteria `masquerade: proxy` 恒 503 | **成立**，代码内有显式 `ponytail:` 自述；`url`/`rewriteHost`/`insecure` 丢弃 |
| **N1（新）** | — | **ss legacy 多用户入站只认 `users[0]`**，第 2..N 个用户永远连不上（Go 两用户皆通）；代码注释自述「当前以 validator 中第一个用户…多用户场景 dispatcher 应自行遍历」 |
| **N2（新）** | — | **anytls 无/空 password = 完全不校验认证帧 = 开放代理**（比 F11/F12 更严重）；Rust 独有协议，Go 26.10.17 无此协议 |

---

## 1. 裁决表

| 编号 | 原断言 | 裁决 | E1 命令与输出 | 可利用性等级 | Go 对照 file:line | 校准严重度 | 一句话修法 |
|---|---|---|---|---|---|---|---|
| F11 | ss 入站 `users[].password` 缺省 `""` → `KDF("")` 公开常量（`inbound.rs:5084`）；Go `shadowsocks.go:71-73` 拒启 | **成立（E1）**。Rust 启动+监听，空口令客户端打通数据；错误口令被拒（负向对照）；真实口令服务器的空口令被拒（证明是真认证而非放行）。**另**：单用户 `"password": ""` 也放行（`inbound.rs:5109` 只查键在场，不查非空），Go 该形态亦拒启 | `python scripts/verify_empty_password_e1.py rust`<br>`[STARTED] 空口令配置: alive=True listen=True`<br>`[DATA-FLOWED] ss 空口令客户端: b'BANNER-EMPTY-PW-OK\n'`<br>`[EXPECTED-FAIL] 负向对照(错误口令): Timeout`<br>`[EXPECTED-FAIL] 真实口令时空口令应失败: Timeout`<br>`[DATA-FLOWED] 正控(真实口令): b'BANNER-...'`<br>Go 同一配置：<br>`[REFUSED] rc=23 ... Shadowsocks password is not specified.` | **远程无需凭据**（只要知道端口+协议；口令是公开常量 `KDF("")`） | Go **有**校验：`infra/conf/shadowsocks.go:71-73`（users 分支）、`:95-97`（单用户分支）、`:225-226`（出站） | **P1（确认）**。Rust 独有回归；两条装配路径同时 fail-open（生产 `parse_ss_inbound_config` 与框架 `xray-proxy-ss/src/plugin.rs:232`） | 两处各加一行 `if password.is_empty() { return Err("ss password is not specified") }`（users 分支 + 单用户分支），文案照抄 Go；插件面同步（`plugin.rs:232`、`plugin.rs` 单用户键为空串分支） |
| F12 | trojan `clients[].password` 缺省 `""` → `hex(sha224(""))` 公开常量（`inbound.rs:4727`）；Go `infra/conf/trojan.go:70-71` 拒启 | **可利用性成立（E1），Go 对照错误**。Rust 启动+监听、空口令客户端打通数据；**Go 26.10.17 trojan 入站同样启动+监听+打通数据**（`accepted tcp:... email: c1`）。`trojan.go:70-71` 是 **`TrojanClientConfig`（出站）**，不是入站；入站 `TrojanServerConfig.Build`（`trojan.go:121-149`）无空口令校验，且 `proxy/trojan/config.go` 的 `AsAccount()` 对 `""` 直接算 `hexSha224("")` 入表 | `python scripts/verify_empty_password_e1.py rust` → `[DATA-FLOWED] trojan 空口令客户端: b'BANNER-...'`；`... go`（trojan-only 隔离配置）→ `alive=True listen=True`，空口令 `-> b'BANNER-EMPTY-PW-OK\n'`，错误口令 `-> b''` 被拒 | **远程需已知端口+协议，凭据为公开常量**。客户端门槛实测：Go 出站 `password:""`/缺键 **均拒启**（`trojan.go:70-71`、`shadowsocks.go:225-226`）；**Rust 出站 `"password": ""` 反而接受**（缺键才报 `missing servers[0].password` 并 skip）→ **攻击者可直接拿 Rust 版二进制当空口令客户端**，无需自写 | Go 入站**无校验**：`infra/conf/trojan.go:121-149`；空口令落到 `proxy/trojan/config.go:23-31` 的 `hexSha224("")`；`validator.go:24-28` 照常入表。Go **出站**才有 `trojan.go:70-71` | **P2（下调）**：上游入站同款行为，不是 Rust 回归；但「空口令=公开凭据」本身是真弱点，且 Rust 客户端比 Go 更宽松（这一半是 Rust 独有） | 若要修，必须**显式承认与 Go 分叉**（Go 入站接受该配置，Rust 拒启 = 配置不可移植）；建议入站先只加 `warn`（fail-visible 不 fail-shut），拒启与否交用户拍板。出站侧可直接对齐 Go（`""` 也拒），无分叉风险 |
| F03 | splithttp `downloadSettings` 完整解析（`register.rs:409-411`）但 `dialer.rs:386` 只用 `is_some()` | **成立**。`config.download_settings` 全仓仅两处读：`resolve_mode` 的 bool 与测试；下行传输的 host/path/headers **从不生效**。另：`register.rs:410` 用 `.ok()`，`downloadSettings.splithttpSettings` 解析失败**静默变 None**；`config.rs:457`/`:493` 的 proto 双向转换直接写死 `None`（注释「切片2 接入」）→ 经 proto 的配置连 key 都丢 | `grep download_settings crates/xray-transport-splithttp/src` → 仅 `config.rs:182/457/493`、`dialer.rs:386-387`、`register.rs:409-506`、测试。运行期无第二套 StreamConfig 构造、无日志 | **不可利用**（无认证/数据面影响）；属**配置静默失效** | Go **全量生效**：`transport/internet/splithttp/dialer.go:355-362` 起用 `DownloadSettings` 造第二套 memory stream config（TLS/REALITY/httpVersion/config2）驱动下行 | **P2（维持）**，配「无日志」+`+`.ok()` 吞错」应升 P2 上半 | 短期：`download_settings.is_some()` 且无消费时打 `warn`（禁静默）；把 `.ok()` 换成 `?`（坏配置 fail-visible）。长期：按 Go 建第二套下行配置 |
| F02 | quic `quicParams.udpHop` 解析并校验却零消费；真开关是 `finalmask.udp[udphop]`；Go 忽略该键而 Rust 因 `interval<5` 拒启 | **成立，且已证实 Go 侧「根本没有这个键」**。Go 26.10.17 `QuicParamsConfig`（`infra/conf/transport_finalmask.go:1177-1195`）字段表**无 udpHop**；全仓 `.go`（除 `config.pb.go`）对 `udphop` 的引用只有 `finalmask` 注册表（`transport_finalmask.go:30/92/1098-1143`）。Rust `quic_params.rs:88-103` 解析 + `:98` 硬拒 `interval<5`，`udp_hop` 写进 `QuicParams` 后**无任何运行期读者**（仅 `dialer.rs:119` 默认值 + 测试） | `python - <<` 全仓 Go 扫描 → 23 处命中，无一处 `quicParams.udpHop`；`QuicParamsConfig struct` 字段清单直读（见上）。Rust：`grep udp_hop crates/xray-transport-hysteria/src` → 仅 `quic_params.rs`（解析+测试）与 `dialer.rs:119`（默认值） | **不可利用**；属**配置可移植性向坏方向破**：Go 能起的配置 Rust 拒启，而该键两边都不做端口跳变 | Go：键不存在 → 忽略（`encoding/json` 未知字段不报错）；真开关 `finalmask.udp[type=udphop]`（`transport_finalmask.go:92` + `transport/internet/finalmask/udphop/conn.go`） | **P2（维持）**；Rust 侧「拒启」这条可以单列 P3（多余严格） | 删掉 `quic_params.rs:88-103` 的 `udpHop` 解析与 `UdpHop` 字段（零消费者 + 与 Go 口径相反），端口跳变只留 `finalmask.udp[udphop]`（Rust 侧已有 `crates/xray-transport/src/finalmask/udphop.rs`） |
| F09 | hysteria `masquerade: proxy` 的 url/rewriteHost/insecure 被丢（`hub.rs:104`）→ 恒 503 | **成立**。`hub.rs:104` `Self::Proxy { .. } => ProxyMasqHandler`；`:309-335` 硬编码返回 `503 Service Unavailable` + `text/plain`。`hub.rs:100-103` 注释自述「url/rewrite_host/insecure 暂不消费（ponytail: 接入 hyper 反代时再扩展）」 | 代码直读 + `grep` 命中；启动/运行无任何告警（`masquerade` 解析成功即静默降级）。未做外部探测抓包（无 `masquerade:proxy` 的 Go 侧实测对照可用，Go 侧为 `httputil.ReverseProxy`） | **不可利用**（不泄凭据/不放大权限）；属**反审查面被拆**：`masquerade:proxy` 是「把服务伪装成真站点」的唯一手段，恒 503 = 主动探测一眼可辨（Go 会真反代） | Go `transport/internet/hysteria/hub.go:210-254` 真 `httputil.ReverseProxy`（Rust 注释自述对应位置） | **P2（维持）**；对抗审查场景应视为 P1（伪装=该协议的存在理由） | 要么接 hyper 反代（正解），要么解析期对 `type:proxy` 打 `warn`（「proxy 伪装未实现，将恒 503」）并写进文档——禁止静默 |

---

## 1.5 「是否静默」逐条判定（F03 / F02 / F09 + 两个新项）

| 项 | 配置期报错？ | 运行期日志？ | 用户可见后果 |
|---|---|---|---|
| F03 downloadSettings | **否**（解析成功；`downloadSettings.splithttpSettings` 坏形态被 `.ok()` 吞成 `None` 也不报） | **无**（`dial` 只打 `mode=... base_uri=...`，不含 downloadSettings） | 下行仍走主配置。若主/下行本应不同 host/path（CDN 前置、双域名），表现为「连得上但下行不对」或直接失败；配置意图 100% 丢失且无任何线索 |
| F02 quicParams.udpHop | 只有 `interval<5`/坏形态 **硬拒启**（比 Go 严格）；合法值**静默** | **无** | 合法的 `udpHop` 完全不跳端口（零消费者）。反直觉地：写对了不生效，写「错」了才报错 |
| F09 hysteria masquerade:proxy | **否**（`type:proxy` 解析通过，`url` 等字段被 `{ .. }` 丢） | **无** | 所有非 auth 探测请求拿 `503 Service Unavailable`；Go 会反代到真站点。伪装目标失效，指纹明显 |
| F11 ss 空口令 | **否** | **无**（且实测连 `shadowsocks inbound listening` 这条 info 都不出现——`arm_builders/inbound.rs:549` 有该行、同文件 trojan `:292` 在同样 loglevel 下正常打出；两次复现，**原因未定位**，仅记为日志债线索） | 开放代理，管理员完全无感 |
| F12 trojan 空口令 | **否** | **无**（只有 `trojan inbound listening users=1`，不提示该用户凭据为空） | 开放代理；Go 同款，但「users=1」给了虚假的「已配置 1 个有效用户」暗示 |
| N2 anytls 无口令 | **否** | **无** | **完全无认证的开放代理**，且无任何提示 |
| N1 ss 多用户 | **否** | **无**（第 2 用户连接失败静默；无 `user not found` 类日志） | 管理员以为 N 个用户都在用，实际只有第 1 个能连 |

共性：**这 7 项全部「配置期零报错 + 运行期零日志」**。任何一项都符合坑约束 ①「认证失败统一错误分类禁静默放行」的反面——静默的不是失败分类，而是「配置根本没生效」。

---

## 2. F11/F12 真实暴露面（谁会被坑 + 坑到什么程度）

**结论：F11 是「任何人可代理上网」；F12 同（且 Go 同样如此）。均不是「仅可探测」。**

E1 已证明数据面真通：攻击者请求经 ss/trojan 入站 → 出站 → 打到目标 TCP 服务并取回 banner。**没有**「只能探测、不能代理」的限定。

具体配置在什么前提下会出现空口令（按可能性排序）：

1. **多用户数组里漏填某个 `password`**：`users:[{"method":"aes-128-gcm","email":"user3"}]`。Rust 无任何校验、无日志；管理员以为「加了个用户」，实际加了个**公开凭据**。⚠️ 因 N1（只认 `users[0]`），空口令用户**只有排在第一位才可利用**——但「排第一位」恰是最常见的写法（复制粘贴模板后改第一个）。
2. **GUI/面板/生成器输出 `"password": ""`**：这类工具对未填字段常输出空串而非省略键。Rust 单用户路径 `:5109` 只查「键在场」→ 空串放行（Go `:95-97` 拒）。
3. **手工从模板删字段**：删掉一整行 `"password": "xxx"` 后忘了补。
4. **本仓自身不产生**：全仓扫描 `"password": ""` 仅命中我本次新写的探针脚本（3 处），**无示例/模板/fixture 带空口令** → 不是「模板缺字段」导致的系统性问题。

后果精确化（不是模糊的「安全问题」）：

- ss/trojan 入站 → 出站默认 `freedom`，其**默认 final rule 对 ss/trojan 入站拦 RFC1918/loopback**（`xray-proxy-freedom/src/config.rs:966-976` `get_default_rule_type` → `BlockPrivate`；E1 首轮实测 `freedom: target blocked by final rule, blackholing connection`）。因此攻击者**打不到内网**，但**可以任意代理到公网**——这就是标准的开放代理：免费带宽 + 以你的 IP 做坏事（滥用投诉、封 IP/ASN、法律责任落到服务器主人）。
- 该默认拦截是 Go 同款（`getDefaultFinalRule`），属**正向防线**，本次不作为缺陷；但它把 F11/F12 的爆炸半径从「打内网」收到「公网开放代理」。
- 凭据完全可算：ss = `EVP_BytesToKey("")` + `HKDF-SHA1(salt,"","ss-subkey")`；trojan = `hex(sha224(""))`。两者都是**公开常量**，不需要任何泄露。

**F12 的严重度校准（重要）**：这不是 Rust 引入的回归，而是 **Go 26.10.17 同款**行为。原断言的 Go 对照抓错了字段（出站 vs 入站），会误导修复方向——照断言「对齐 Go 拒启」实际会**造出与 Go 不一致的拒启**，与项目「32/32 + Go 对拍」铁律冲突。建议：先只加 `warn`（fail-visible），拒启与否交 PM 拍板并登记分叉。

**客户端侧不对称（本轮实测补充，影响攻击门槛）**：

| 客户端 | `password` 缺键 | `"password": ""` |
|---|---|---|
| Go ss / trojan 出站 | 拒启 | **拒启**（`shadowsocks.go:225-226`、`trojan.go:70-71`） |
| Rust ss / trojan 出站 | 报 `missing servers[0].password` → **outbound 被 skip**（warn，进程仍起，后续 `outbound handler not found: default`） | **接受并拨号** |

含义：Go 客户端拿不到「空口令」这个形态（必须自写客户端），**Rust 版二进制可直接当空口令客户端用**。这让 F11/F12 的实战门槛从「写个协议实现」降到「会写 JSON」——对 Rust→Rust 组合是「远程无需凭据」级。同时再次暴露生产路 `warn + skip` 的 fail-open 特征（CLAUDE.md §3.5.4 zhvi3 已登记）：出站配置写错不拒启，只在首个连接时报 `outbound handler not found`。

---

## 3. 凭据缺省空串横向清单

方法：`scripts/verify_credential_defaults_matrix.py` —— 12 组「凭据缺省/空串」最小配置，同一份 JSON 分别喂 Rust 与 Go，判「启动 + 监听」。启动即监听 = 该凭据面运行期生效（E1 级）；拒启 = fail-closed。

| 协议 | 字段 | 缺省 | 后果（Rust 实测） | Go 行为（实测并列 file:line） | 是否生产可达 |
|---|---|---|---|---|---|
| **shadowsocks (legacy)** | `users[].password` / 单用户 `password` | `""` | **`STARTED+LISTEN`**；空口令客户端打通数据（E1）；**仅 `users[0]` 被认**（N1） | **`REFUSED`**：`Shadowsocks password is not specified.`（`infra/conf/shadowsocks.go:71-73` / `:95-97`） | **是**（P1，Rust 独有） |
| **shadowsocks 2022** | `password`(PSK) | `""` | `REFUSED`：`PSK length 0 < key_size 16` ✔fail-closed | `REFUSED`：`proxy/shadowsocks_2022: bad key` | 不可达（两侧都拒） |
| **trojan** | `clients[].password` | `""` | **`STARTED+LISTEN`**；空口令打通数据（E1） | **`STARTED+LISTEN`**；冒测空口令打通数据（**入站无校验**：`infra/conf/trojan.go:121-149`；出站才有 `:70-71`） | **是**（P2，上游同款） |
| **vless** | `clients[].id` | `""` | `REFUSED`：`vless account parse: failed to parse ID` ✔ | `REFUSED`：`common/uuid: invalid UUID` （`infra/conf/vless.go:66-69` `uuid.ParseString`） | 不可达 |
| **vmess** | `clients[].id` | `""` | `REFUSED`：`vmess invalid uuid (0 bytes)` ✔ | `REFUSED`：`common/uuid: invalid UUID` | 不可达 |
| **socks** | `accounts[].user`/`pass` | `""`/`""` | `STARTED+LISTEN`：`accounts[""]=""` 入表，空 user+pass 即通过（`inbound.rs:4522-4524`） | `STARTED+LISTEN`：`infra/conf/socks.go:51-55` 无校验、直接 `Accounts[Username]=Password` | 是（但**需 `auth:"password"` 且真配了空账号**；默认 `noauth` 本就无认证，通常只绑 127.0.0.1。低危/同上游） |
| **http** | `accounts[].user` | `""` | `STARTED+LISTEN`；但 `inbound.rs:4920` `if !user.is_empty()` → 空 user **不入表**，等价「无账号」 | `STARTED+LISTEN`（`infra/conf/http.go:43-45` 无校验；账号表空 = 不校验） | 是（两侧等价；「无账号」= 无认证，属 http 入站的既有公开语义） |
| **anytls** ⚠️ | `password` | 缺省/`""` → `None` | **`STARTED+LISTEN`**，且 `None` = **不校验认证帧**（`inbound.rs:5366`、`xray-proxy-anytls/src/inbound.rs:48-50`；既有测试 `handler_without_password_allows_connection` 直接断言「无口令连接放行」）→ **开放代理** | **无此协议**（`unknown config id: anytls`；`D:/Project/Xray-core/proxy/` 无 anytls） | **是（若 anytls 入站进生产）**——**最严重**，见 N2 |
| **tuic** | `password` | `""` | `STARTED`（UDP 监听）；`uuid` 仍是必需且需可解析（`inbound.rs:5570-5578`）→ 空口令只是部分弱化 | **无此协议**（`unknown config id: tuic`） | 是但需同时知道 `uuid`（uuid 不可缺省/不可为空）→ **中低危** |
| **wireguard** | `secretKey` | 缺失 | `REFUSED`：`missing secretKey` ✔ | `REFUSED`：`invalid WireGuard secret key` | 不可达 |
| **hysteria** | `auth` | 缺省 `""` | `STARTED`（UDP 监听）；但**运行期 fail-closed**：`xray-transport-hysteria/src/quinn_adapter.rs:869-876` 「validator 与 static_auth 皆无 → `false`（安全侧：拒绝）」。⚠️ 副作用是**可用性陷阱**（起来但谁都连不上，无告警） | 无同形状配置（Go 入站只有 `users[].auth`，`infra/conf/hysteria.go:42-72` 本身也无非空校验）；本矩阵的 Go 对照因缺 hysteria transport 段而拒启，**不构成有效对照** | 不可达（fail-closed） |

**N2（anytls，本轮最高危横向发现）**：`settings.password` 缺省或空串 → `parse_anytls_tls_acceptor` 返回 `None` → `AnytlsInboundHandler::with_password(None)` → 明文「不校验客户端认证帧」。这是**完全无认证**，比 F11/F12（需猜公开口令）更糟：连口令都不用了。且 anytls 是 Rust 独有协议，**没有 Go 行为可赖**，只能是本仓自己的安全责任。仓库里已有测试把这个行为**当作期望固化**（`handler_without_password_allows_connection`）——意味着它不是「忘了写校验」，而是被写成了契约。

**N1（ss 多用户，本轮最高危功能发现）**：`crates/xray-proxy-ss/src/inbound.rs:74-87` `handle_conn` 取 `validator.get_all().into_iter().next()`，即**永远只用第一个用户的 account 解密**；注释自述「多用户场景 dispatcher 应自行遍历 validator 匹配 account」（生产路径没有这个遍历）。E1 三组实测：

| 配置 | Rust | Go |
|---|---|---|
| `users=[{pw:""},{pw:"REAL"}]` | 空口令通、REAL 不通 | — |
| `users=[{pw:"REAL"},{pw:""}]` | REAL 通、空口令不通 | — |
| `users=[{pw:"P1"},{pw:"P2"}]` | **P1 通、P2 不通** | **P1 通、P2 通** |

影响：多用户 ss（含按用户限速/统计/计费）实际退化为单用户，第 2..N 个用户**静默连不上**（无日志、无配置错误）。对 F11 的含义：空口令用户只有排第一时才可被利用——**这既是可利用性的限定条件，也是 N1 独立成立的证据**（同一根因）。

---

## 4. 影响范围（沿调用链）

```
inbound 配置解析（两条装配路径，均 fail-open）
├─ 生产主路  crates/xray-core/src/inbound.rs:5084（users[]）/ :5109（单用户键在场）
│            → arm_builders/inbound.rs:545 parse_ss_inbound_config
└─ 框架主路  crates/xray-proxy-ss/src/plugin.rs:203 parse_inbound
             → :231 parse_legacy_user（:232 缺省 ""）
             → SsInbound::with_users → Server::with_users → Validator::add
             → 运行期 inbound.rs:74-87 handle_conn 只取 get_all()[0]（N1）
             → read_request → SSStream（KDF("") 派生的 key 生效）

trojan 同构：inbound.rs:4727 / xray-proxy-trojan/src/plugin.rs:195
             → TrojanMemoryAccount::new("") → hex(sha224("")) → validator 入表 → 认证通过

anytls（N2）：inbound.rs:5366 → None → arm_builders/inbound.rs:603-605
             → AnytlsInboundHandler::with_password(None) → 不校验认证帧
```

`freedom` 默认 final rule（`xray-proxy-freedom/src/config.rs:966-976`）是唯一拦住的横向移动面：ss/trojan 入站 → 私有地址被黑洞。**公网目标不受限**。

---

## 5. 未覆盖面（查了什么 / 没查什么 / 置信度）

**已查（E1 实测）**
1. F11/F12 数据面打通 + 三条负向对照（错误口令、真实口令服务器配空口令、Go 同配置）。
2. 12 组凭据缺省配置的 Rust vs Go 启动/监听矩阵（含 E1 进程实测，非纯静态）。
3. ss 多用户顺序三组对照 + Go 两用户对照（N1）。
4. 全仓 Go 扫描 `udphop`（23 命中，无 `quicParams.udpHop`）+ Go `QuicParamsConfig` 字段表直读（F02）。
5. splithttp `download_settings` 全仓消费者清点 + Go `dialer.go:355-362` 对照（F03）。
6. hysteria masquerade 三处代码直读 + 内联 `ponytail:` 自述（F09）。
7. hysteria 运行期 auth 判定读 `quinn_adapter.rs:869-876`（结论：fail-closed，纠正「起来=开放」的直觉）。
8. 本仓 `"password": ""` 全仓扫描（仅命中我新写的探针，无模板/fixture 带空口令）。

**未查（明确缺口）**
- **anytls 无口令的端到端抓包实测**：只到「代码 `None`=不校验 + 仓库既有测试断言放行 + 启动监听」层级（E2+）。要升 E1 需手写 anytls 客户端（TLS + padding 帧），本轮未做。
- **N1 的 UDP 面**：只测 TCP；`serve_ss_udp` 走 `validator.get(payload)`（`protocol.rs:240`，会遍历用户），UDP 侧可能反而是多用户正确的 → **TCP/UDP 多用户能力不一致**，未实测确认。
- **F09 的外部探测取证**：未构造 `masquerade:proxy` 的 Go 侧对照抓包（Go 侧需 hysteria transport 完整段），503 结论来自代码直读。
- **tuic 空口令的密码学后果**：未验「uuid 公开+password 空」时 token 是否可离线算出；只确认 uuid 仍是必需项。
- **F03 的运行期行为差异**：未构造 `downloadSettings` 指向不同 host 的真实两跳（需 CDN/双域名），结论为代码级（`is_some()` 是唯一消费者）。
- 未审性能/内存（不在本轮范围）；未重报已收口的 TLS 指纹面。

**置信度**
- F11 / F12 / N1：**E1，高**（真实二进制 + 手写客户端 + 双向对照）。
- N2 / F02 / F03 / F09：**E2（代码直读 + 仓库既有自述/测试）+ 启动实测**，高；缺端到端抓包。

---

## 6. 架构建议（seam 硬化，非本轮实施）

1. **凭据非空是 trust boundary，应在解析层统一收口**，而不是逐协议 `unwrap_or("")`。当前 12 个入站解析函数各写各的（`inbound.rs:4522/4591/4727/4918/5030/5084/5109/5139/5147/5187/5224/5279/5577`），同一个「空凭据」策略会反复漂移——这正是 F11 与 F12 一个拒一个放的原因。
   建议在 `xray-frame` 落一个 `credential::require_non_empty(field, value, policy)` 句柄（`policy = Reject | Warn`），由 `PluginContext` 暴露；各协议只声明字段策略。**Go 与 Rust 行为不同的协议（trojan）用 `Warn` 策略显式登记分叉**，避免「静默对齐」再犯。
2. **`Option<String>` 表示「可选凭据」= 危险默认**：anytls（N2）与 hysteria 都把 `None` 读成「不校验」。若语义真是「不校验」，必须让配置显式写 `"password": null` 并打 `warn`；`Type` 层面用 `enum Auth { Required(String), ExplicitlyDisabled }` 强制二选一，禁止「缺省即关校验」。
3. **多用户路径必须有「非首用户可用」的契约测试**（N1）：`users=[{P1},{P2}]` → 两把 key 都能通，缺则 CI 红。当前所有 ss 测试都是单用户 + 一个「多用户解析」测试，没人断言第 2 个用户能连。
4. **配置键的「有解析无消费者」应 CI 可查**：F02/F03 都是「解析写全了、消费没接」——`+`.ok()`/`is_some()` 正好是这类债的典型指纹。建议加一条静态门：新增配置字段必须同时出现「解析点 + 消费点 + 断言测试」三处，否则 CI 红。

---

## 7. 5 维自评

| 维度 | 分 | 依据 |
|---|---|---|
| 证据强度 | 4.5/5 | 主要断言都有真实二进制 + 手写协议客户端 + 双向对照；扣分在 anytls/udphop 只到 E2、未抓包 |
| 断言校准 | 4.5/5 | 纠正了 F12 的 Go 对照错误与 F02 的「Go 忽略」细节，避免误导修复方向；均附 file:line |
| 横向覆盖 | 4/5 | 12 组协议 × 双实现启动矩阵；anytls 数据面未实测、tuic 密码学后果未验证 |
| 可执行性 | 4/5 | 每条给一句话修法且都最小；F12 的分叉需要用户拍板（已显式标注，不擅自定） |
| 边界纪律 | 5/5 | 零代码改动、未审性能/内存、未重报 TLS 指纹面；只出报告与建议 |

**VERDICT 一句话**：F11 与 N1/N2 是 Rust 独有且可远程无凭据利用/破坏的实打实缺陷（P1）；F12 可被利用但上游同款（P2 校准），F02/F03/F09 是不可利用的配置静默失效（P2）。

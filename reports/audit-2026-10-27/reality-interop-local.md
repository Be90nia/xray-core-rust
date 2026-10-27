# REALITY 本地双向 wire 互操作（vless+reality+裸 TCP）

VERDICT: PASS — 两方向 `python dist/interop_reality.py` 2/2 PASS，复跑 1 次仍 2/2，无残留进程。

- 脚本：`dist/interop_reality.py`（新增，不动 `dist/interop_matrix.py` 6 协议矩阵）
- 协议：vless + reality + 裸 TCP（trojan+reality Go 侧已 deprecate，不用；无 splithttp/grpc，无 ML-DSA65）
- 方向 A：Rust client（26.10.11, target/release/xray.exe）↔ Go server（26.7.28, D:/Project/Xray-core/target/xray-go.exe）
- 方向 B：Go client ↔ Rust server
- 判据：本地源站 `http://127.0.0.1:<p>/`（200014B，`INTEROP_MARKER`）经 socks5h 隧道 curl 拉取，`HTTP:200 + body>5000B + marker 命中`，且两侧日志无 `reality` 类错误行（白名单两条 Go 配置期建议告警）
- 密钥：每方向服务端密钥由**对端体系自己的** `xray x25519` 生成（A 用 Go binary 生成、B 用 Rust binary 生成，输出 `PrivateKey:` / `Password (PublicKey):`）；shortId `0123456789abcdef`（8B hex）

## 运行输出（两次完整）

**Run 1**
```
origin http://127.0.0.1:10893/ body=200014B; dest=Go xray vless+tls 127.0.0.1:10894 (CN=localhost)
== A: Rust client -> Go server ==
[PASS] #01 Rust->Go     vless+reality/tcp  HTTP=HTTP:200 body= 200014B marker=True
== B: Go client -> Rust server ==
[PASS] #02 Go->Rust     vless+reality/tcp  HTTP=HTTP:200 body= 200014B marker=True

=== reality 互操作: 2/2 PASS ===
```

**Run 2（复跑）**
```
origin http://127.0.0.1:10924/ body=200014B; dest=Go xray vless+tls 127.0.0.1:10925 (CN=localhost)
== A: Rust client -> Go server ==
[PASS] #01 Rust->Go     vless+reality/tcp  HTTP=HTTP:200 body= 200014B marker=True
== B: Go client -> Rust server ==
[PASS] #02 Go->Rust     vless+reality/tcp  HTTP=HTTP:200 body= 200014B marker=True

=== reality 互操作: 2/2 PASS ===
```

两方向均**单连接单次握手**成功（服务端各只有一条 `accepted` 记录，客户端无重试），200KB 全量过隧道。

## reality 配置字段表

**Server inbound（两方向同形；仅 privateKey 换各自 x25519 私钥）**

| 字段 | 值 | 说明 |
|---|---|---|
| `protocol` | `vless` | |
| `settings.decryption` | `"none"` | Go 必需 |
| `settings.clients[].id` | 测试 UUID | |
| `streamSettings.network` | `"tcp"` | 裸 TCP |
| `streamSettings.security` | `"reality"` | Rust 侧 arm_builders 走 `serve_reality_vless` |
| `realitySettings.dest` | `127.0.0.1:<dest端口>` | 回退站点；Go reality 每连必先 TLS 连 dest 完成 steal（xtls/reality tls.go:168） |
| `realitySettings.serverNames` | `["localhost"]` | SNI 白名单（Rust 侧空值拒启，Go transport_security.go:94 同语义） |
| `realitySettings.privateKey` | x25519 输出 | base64url 32B |
| `realitySettings.shortIds` | `["0123456789abcdef"]` | hex ≤8B |
| （缺省未设） | `xver=0`，`maxTimeDiff=0`（禁用时间窗），`maxUselessRecords`（Rust 默认 Disabled），`serverAcceptor`（Rust 默认 rustls） | |

**Client outbound（两方向同形；publicKey 指向对端服务端公钥）**

| 字段 | 值 | 说明 |
|---|---|---|
| `protocol` / `settings.vnext[0].users[0].encryption` | `vless` / `"none"` | |
| `streamSettings.network` / `security` | `tcp` / `reality` | |
| `realitySettings.serverName` | `"localhost"` | SNI，须在服务端 serverNames 白名单内 |
| `realitySettings.publicKey` | 对端 x25519 公钥 | base64url 32B（Rust 侧非 32B 配置期硬错） |
| `realitySettings.shortId` | `0123456789abcdef` | 与服务端一致 |
| `realitySettings.fingerprint` | `chrome` | **必须 MLKEM-capable**：Go REALITY 服务端只接受带 X25519MLKEM768 key share 的 ClientHello（chrome = CHROME_133 模板双 share）；Rust 客户端走 btls 主路径 |

**通用外壳**：server 端 outbound `freedom + finalRules [{"action":"allow"}]`（对齐 interop_matrix 口径）；client 端 inbound `socks`（127.0.0.1, udp）。

## dest 回退站点做法

Go xray（与被测 Go 同一二进制副本）起一个独立 `vless + tls` 实例：证书/私钥用 `D:/tmp/interop_cert.pem` / `interop_key.pem`（CN=localhost，与 `serverNames` 一致），outbound freedom，日志 `dest.log`。

- Go 侧 steal 语义：`xtls/reality` `Server()` **每条连接**先 `config.DialContext(config.Dest)` 建 TLS 连接并把 ClientHello 转发完成握手（tls.go:168 失败即 `conn.Close()`）→ dest 必须是稳态 TLS 服务。
- Rust 侧 verified 路径不连 dest（`server_tls` 直接出示由 auth_key 派生的 HMAC-ed25519 模板证书，Go init() 同语义）；dest 只在 Invalid fallback 与 probe 用 → 与 Go 客户端互通经 HMAC 证书校验（`UConn.VerifyPeerCertificate` 同一算法），无 PKI 依赖。

### 排障记录（第一版 dest 用 Python HTTPS → 间歇失败，非产品缺陷）

首版 dest 用 Python `ThreadingHTTPServer + ssl` 包 listening socket。现象：方向 A 仍拿到 200014B/marker（curl 靠客户端重试救回），但 Rust 客户端日志连续 3 次 `WARN REALITY SslStream::connect failed ... ConnectionAborted (10053)` 后第 4 次才成功；Go 服务端无任何 error 行。根因链：Go reality steal 要求 dest 完整 TLS 握手，Python 线程版 HTTPS 站点对该 relay 握手间歇中止 → Go 中止客户端连接。**处置：dest 换成 Go xray vless+tls 实例后两方向首次即 PASS，重试风暴消失**——判定为测试工装 artifact，非 xray 两侧产品代码缺陷，未改 `crates/**`。

（另一处自扰已消除：初版对 reality 端口做 TCP 探活，会制造 Rust 服务端 `read ClientHello: early eof` 噪声警告，改为服务端固定 2s 宽限。）

## 两方向日志摘要（Run 1，Run 2 同形）

- **A 服务端（Go, s1.log）**：读配置 → 2 条配置期建议告警（`REALITY: The default minimal client version is Xray-core v26.3.27…` / `Listening on non-443 ports…`，白名单内）→ `core: Xray 26.7.28 started` → 启动后 2.7s 单条 `from 127.0.0.1:10906 accepted tcp:127.0.0.1:10893`（源站请求）。零握手错误。
- **A 客户端（Rust, c1.log）**：identity → `system dialer initialized` → 一次 dest 域名解析。零 WARN（无重试）。
- **B 服务端（Rust, s2.log）**：identity → dialer init。**零警告**（Go 客户端 ClientHello 验签通过，verified 路径自持 HMAC 证书）。
- **B 客户端（Go, c2.log）**：started → 单条 `from tcp:127.0.0.1:10917 accepted tcp:127.0.0.1:10893`。零错误。
- **dest（dest.log）**：started 后静默（steal 握手全成功，无 fallback 发生）。

## 进程卫生（验收 #3）

- 两轮运行后 `tasklist` 检索 `xray` **零命中**（当前 v2rayN 核心也未在运行，无任何残留）。
- 脚本从不起 `xray.exe`/`xray-go.exe` 全名杀手：被测二进制先拷贝为唯一映像名 `D:/tmp/interop_reality/xray-reality-it{,-go}.exe`，清理只 `terminate` 自持 PID（`taskkill /T /F /PID`）+ 按唯一映像名 sweep + atexit 兜底；结束已删除二进制与 body 副本，保留 s*/c*/dest 的 json+log（KB 级审计留档于 `D:/tmp/interop_reality/`）。

## 结论

`32-32-acceptance.md` §7 所列「REALITY 双向本地 wire 互通缺口」已闭合：A（Rust client↔Go server）与 B（Go client↔Rust server）本地双通道例均稳定 2/2。产品代码零改动。

## 5 维自评

| 维度 | 分 | 理由 |
|---|---|---|
| 正确性 | 4.5 | 两方向 wire 真通（200KB+marker），判据含字节数+marker+日志扫描三重；配置字段全部经源码核实（Go conf/Rust parse/arm_builders）；扣 0.5：maxTimeDiff/xver 等缺省路径未逐项变体覆盖 |
| 性能 | 4 | 单轮 ~9.4s（含 2×2s 启动宽限）；本地回环无网络变量；未做吞吐测量（非本任务目标） |
| 可维护性 | 4.5 | 与 interop_matrix.py 同风格（build/run_one/主循环），10 行注释定位坑源；复跑零参数 |
| 风格 | 4.5 | 契约全守：禁全名杀手、禁 youtube marker、不改 crates/** 与矩阵脚本、日志落指定目录 |
| 测试 | 4 | 2 轮独立运行均 2/2 + 末态进程清点；扣分：未叠加负向用例（错 key 必败路径未纳入脚本） |

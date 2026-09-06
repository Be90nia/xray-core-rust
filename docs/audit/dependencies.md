# 依赖健康度审计（第三轮切面 · dependencies）

- 审计对象: D:/Project/Xray-core-rust @ 4e6c1fe (2026-09-06)
- 审计人: DepsAudit（第三轮依赖切面）。只读审计，未改任何代码。
- 方法: `cargo metadata --offline` + `cargo tree -d/-i` + Cargo.lock（6971 行 / 622 包 / 54 成员）jq 交叉统计 + 全仓 grep 用点验证 + **cargo-deny 0.20.2 实拉 RUSTSEC advisory DB（2026-09-06）**跑 advisories/bans/sources。所有结论均附 file:line 或命令输出证据；无证据的怀疑不列。
- 已知勿重复: windows-sys 死依赖（readv.rs P3，前轮已报）。

## 严重度统计与 TOP3

| 级别 | 数量 |
|---|---|
| P0 | 0 |
| P1 | 1 |
| P2 | 6 |
| P3 | 11 |

**TOP3**:
1. **[P1] h2 0.4.15 命中 RUSTSEC-2026-0258**（无界空 DATA 帧→内存耗尽/panic），`cargo update -p h2` 一行可修，semver 兼容补丁位。
2. **[P2] anytls 以 default features 拉起 rustls fork 的 `aws_lc_rs` + `prefer-post-quantum`**，AWS-LC（第 4 套 crypto 栈）被编译进产物（aws_lc_sys rlib 9.8MB 实证），且 fork 私有 PQ 偏好 feature 全局激活。
3. **[P2] deny.toml 审计门整体失效**——schema 与 cargo-deny 0.20.2 不兼容（CI audit job 必红）+ `allow-git=[]` 与锁内 5 个 git 源冲突，h2/anyhow 等通告此前无门禁可拦。

---

## ① workspace 依赖清单（用途 / 可替代性 / 重复功能）

### 1.1 分组判定（Cargo.toml:89-199 workspace.dependencies）

| 组 | 依赖 | 用途（Go 对应） | 重复/替代判定 |
|---|---|---|---|
| 运行时 | tokio(:91)、tokio-util、futures(-util) | Go runtime/net | 唯一异步运行时，无重复 ✓ |
| 序列化 | serde/serde_json/serde_yaml(:96)/toml(:97) | infra/conf json/yaml/toml 三格式解码 | json 仅 1 库 ✓；yaml/toml 各 1 且真实使用（xray-conf/src/yaml.rs:15、toml_config.rs:22）✓ |
| TLS×2 | rustls(:160, watfaq fork)+tokio-rustls(:161) 与 btls/tokio-btls/btls-sys(:196-198) | Go crypto/tls + uTLS | 双栈为**刻意设计**（btls=BoringSSL 原生指纹 API 替代 uTLS，注释 :159/:195 明示）✓ |
| QUIC/H3 | quinn(:132)/quinn-proto/h3/h3-quinn | DoQ/splithttp H3/hysteria/tuic | 唯一 QUIC 栈 ✓ |
| HTTP | hyper(:123)/hyper-util/hyper-rustls(:126)/h2(:129)/http/http-body-util/httparse(:192) | Go net/http | 分层合理：hyper=客户端/服务器，h2=DoH(xray-app-dns)+grpc 直用，httparse=嗅探零拷贝解析；reqwest（xray-transport:31）仅 finalmask realm 控制面（src/finalmask/realm/http.rs:26,129），非重复 ✓ |
| WS | tokio-tungstenite(:165) + soketto(xray-transport-websocket:21) | Go websocket | **重复**：soketto 为未接线脚手架（见 P2-5） |
| 代理协议库 | anytls(:151)、boringtun(:157)、smoltcp(:116)、tun-rs(:154)、yamux(:112)、shadowsocks(:147) | AnyTLS/WireGuard/TUN netstack/反向代理 bridge/SS 原语 | 前 5 项真实使用 ✓；**shadowsocks 为死声明**（见 P3-5） |
| 加密原语 | ring、RustCrypto 家族（aes/aes-gcm/chacha20poly1305/hkdf/hmac/sha1/sha2/sha3/md-5/ctr/cfb-mode/blake2/blake3/x25519-dalek/ml-kem/ml-dsa/subtle）、rcgen、rsa、num-traits/num-integer | 各协议算法 | 多库并存但**每库有对应协议需求**（见 1.2）；唯 num-bigint 直依赖死亡（P3-6） |
| gRPC/protobuf | tonic(:186)/tonic-prost/tonic-reflection/prost*/prost-build/tonic*-build | google.golang.org/grpc | 唯一 gRPC 栈 ✓ |
| DNS | hickory-proto(:118)/hickory-resolver(:120) | miekg/dns | 唯一 DNS wire/resolver ✓ |
| 工具 | once_cell(:181)/parking_lot(:182)/dashmap(:183)/clap(:178)/uuid/rand/bytes/socket2/sysinfo(:190)/lru | — | once_cell 仅剩 1 用点可换 std::sync::LazyLock（P3-8）；其余无重复 |
| OCSP | ocsp-stapler(:194) | Go ocsp | 唯一实现；代价=拉入整个 reqwest HTTP 客户端栈（hyper-rustls 0.27.9），属第三方库内在依赖，替换库本身代价更高，接受并留档 |

### 1.2 多 crypto 库并存判定

二进制内共 4 套 crypto 栈，逐一定性:
1. **ring**（rustls provider + dispatcher/xray-crypto 直用）— 必要。
2. **RustCrypto 家族**（aes-gcm 0.11-rc.4/chacha20poly1305 0.11-rc.3/aead 0.6-rc/cipher 0.5 等）— vmess/ss/vless/reality 各协议算法，rc 注释证实刻意对齐（xray-proxy-ss/Cargo.toml:55-58"都用 aead 0.6"）。
3. **BoringSSL（btls-sys）** — uTLS 指纹需求，设计注释明示（Cargo.toml:195-198）。
4. **AWS-LC（aws-lc-rs 1.17.1 + aws-lc-sys 0.42.0）** — **非预期**，anytls default features 经 feature 统一拉起（见 P2），是本轮唯一"不该在场的 crypto"。

大数库双并存: num-bigint（直依赖，死）+ num-bigint-dig（经 rsa 传入，活），见 P3-6。

CRC 双库非重复: `crc`（CRC_64_ECMA_182，xray-proxy-ss/src/validator.rs:12）与 `crc32fast`（CRC32，xray-proxy-vmess/src/aead/mod.rs:212）多项式不同、各司其职 ✓。

哈希多库判定: blake2（finalmask salamander，xray-transport/src/finalmask/salamander.rs:13）、blake3（ss subkey/vless/xudp/cli）、sha1+md-5（common/vmess/ss）、sha3（vmess）、fnv（vmess 头）、ring::digest（xmc witness）——逐库有协议出处，无单一可替代项 ✓。

---

## ② Cargo.lock: 多版本共存 + 安全版本

### 2.1 同 crate 多版本共存（共 ~53 组，仅列关键）

`cargo tree -d` / metadata group_by 统计: 622 包中 53 个名字存在多版本。绝大多数为跨 target（windows/wasi）与多上游生态现实，逐个消除无收益。**可收敛子集**:

| crate | 版本 | 来源 | 收敛路径 | 负优化自查 |
|---|---|---|---|---|
| rcgen | 0.13.2 + 0.14.8 | 0.13=12 个成员直依赖；0.14.8=anytls | 成员统一升 0.14（12 处 manifest+API 小改） | rcgen 仅用于自签证书生成路径，非数据面，回归容易；可做但不紧迫 |
| webpki-roots | 0.26.11 + 1.0.8 | 0.26=tokio-tungstenite 0.26.2；1.0=成员 | 需 tokio-tungstenite 0.28+ | **ws 握手属 u_client 指纹硬禁触面**（大版本升级可能改握手行为），已知勿动清单相邻——仅留档缓行 |
| num-bigint 族 | num-bigint + num-bigint-dig | 前者死依赖；后者经 rsa | 删直依赖（P3-6） | 无风险 |
| getrandom/rand/rand_core/hashbrown/syn/thiserror/windows-sys/windows… | 2-3 版本并存 | 生态现实 | 不动 | 强行统一需驱动上游，负优化 |
| yasna/aead/cipher/digest 等 crypto trait 0.x/RC 并存 | — | RustCrypto 0.5/0.6-rc 双线 | 等 RC 线转正自然合并 | 见 P3-9 |

体积影响: 名义重复包多为小 crate；实证大块头是 windows 元 crate（rlib 106MB，链接后裁剪）与四套 crypto（见 P2），不是上表小 crate。

### 2.2 关键安全依赖版本 vs RUSTSEC（2026-09-06 DB 实拉，非猜测）

| crate | 锁定版本 | 通告命中 | 结论 |
|---|---|---|---|
| tokio | 1.52.3 | 0 | 未落后已知修复 ✓ |
| rustls(watfaq fork) | 0.23.40 (e6e8e7e) | 0 | ✓（fork 与上游同版号；fork 私有改动风险见 P2） |
| quinn / quinn-proto | 0.11.11 / 0.11.16 | 0 | ✓ |
| ring | 0.17.14 | 0 | ✓ |
| aws-lc-rs / aws-lc-sys | 1.17.1 / 0.42.0 | 0 | ✓（但本身不该在场，见 P2） |
| **h2** | **0.4.15** | **RUSTSEC-2026-0258（vulnerability）** | **fix >=0.4.16 → P1** |
| **anyhow** | **1.0.102** | **RUSTSEC-2026-0190（unsound, downcast_mut UB）** | fix >=1.0.103 → P2 |
| **lru** | **0.12.5** | **RUSTSEC-2026-0002 + RUSTSEC-2026-0253（双 unsound）** | → P2 |
| **rsa** | **0.9.10** | **RUSTSEC-2023-0071（vulnerability, Marvin Attack, 无修复）** | → P2 |
| rustls-pemfile | 2.2.0 | RUSTSEC-2025-0134（unmaintained） | → P3 |
| paste | 1.0.15 | RUSTSEC-2024-0436（unmaintained, 传递经 netlink→netconfig-rs） | 无动作，留档 |
| chacha20 | 0.10.0 | **yanked**（cargo-deny warning） | → P3 |
| spin | 0.9.8 | **yanked**（传递经 lazy_static，0.9.x 末版无法 update） | 留档 |

完整通告清单可复现: 临时最小配置跑 `cargo deny check advisories`（1294 行输出，6 error + 2 yanked warning）。注: 仓库自带 deny.toml 目前无法解析（见 P2），需临时配置替代。

---

## ③ feature flag 审计

### 3.1 过剩/未用 feature（证据）

| 项 | 位置 | 证据 | 处置 |
|---|---|---|---|
| reqwest `blocking` 未用 | crates/xray-transport/Cargo.toml:31 | 全仓 grep `reqwest::blocking` 零命中；realm client 全 async（realm/http.rs:26 reqwest::Client） | 删 `"blocking"` |
| tracing-subscriber `json` 未用 | Cargo.toml:105 | 全仓唯一初始化 xray-cli/src/bin/xray.rs:189-192 `fmt()+EnvFilter`，零 `.json()` | 去 `"json"` |
| xray-core 死声明 tracing-subscriber | crates/xray-core/Cargo.toml:75 | xray-core/src 零 `tracing_subscriber` 引用（订阅器只在 cli 初始化） | 删 :75 |
| tokio `full` 中 process/io-std 未用 | Cargo.toml:91 | 全仓: `tokio::fs` 1 处（hysteria hub.rs:269）、`tokio::signal` 1 处（cli run.rs:140-147）、`tokio::process` 零命中 | **可选**改显式 feature 列表；tokio 单 crate 编译增量小，维持 full 亦可接受（负优化自查: 显式清单日后漏加反而添维护，保持现状+留档即可） |
| 成员级 tokio feature 冗余叠加 | 各成员（如 xray-app-commander `feat=full,io-util,sync,rt,net`） | full 已包含 io-util/sync/rt/net/macros/time | 纯卫生，无编译收益，可不改 |
| anytls default features 破口 | Cargo.toml:151 | metadata: `uses_default_features: true` → 拉起 fork rustls `aws_lc_rs`+`prefer-post-quantum` | **见 P2（本轮最重要 feature 发现）** |

### 3.2 做得对的（确认干净）

quinn/hickory-proto/hickory-resolver/smoltcp/tun-rs/boringtun/hyper-rustls/ocsp-stapler 全部 `default-features = false` + 精确 feature 白名单；smoltcp feature 集恰为 netstack 所需（:116）；ml-dsa `alloc`、h2 `stream` 按需。除 anytls 泄入外无 default 大杂烩 ✓。

---

## ④ git 依赖与 [patch] 段

锁内 5 个 git 源包（Cargo.lock:505/517/4448/3705/4468）:

| 包 | 源 | 锁定 rev |
|---|---|---|
| btls / tokio-btls / btls-sys | github.com/0x676e67/btls `branch=main` | ab7f522c（三者同 rev，一致） |
| rustls | github.com/Watfaq/rustls `branch=watfaq/0.23.40` | e6e8e7e1 |
| tokio-rustls | github.com/Watfaq/tokio-rustls `branch=watfaq/0.26.4` | b26e3e2b |

风险与判定:
1. **branch=main 是移动目标**: `cargo update` 即漂移；当前 lock 已锁 rev（构建可复现）。btls 三包同仓库同 rev，无版本劈叉。缓解: HANDOFF 留档 rev↔日期；可选改 `rev=` 语法钉死（同 rev 不改 lock 图、不触发 btls-sys 4min 重建；但改动无即时收益，建议仅留档）。
2. **[patch.crates-io]（Cargo.toml:202-204）是全局替换**: 所有传递 rustls 消费者（anytls/reqwest/hyper-rustls/quinn/tokio-tungstenite…）统一走 watfaq fork——这是 REALITY `with_reality()` API 的前提，也是 P2 feature 泄入的机制通道。
3. **供应链**: git 依赖无 crates.io 审计层；deny.toml `allow-git=[]` 未放行它们（见 P2）。watfaq 分支名自带版本号（watfaq/0.23.40），漂移风险低于裸 main。
4. **fork 落后上游修复**: RUSTSEC 扫描对 rustls 0.23.40 / tokio-rustls 0.26.4 零命中，当前无落后证据（需联网持续核实 fork 对上游 0.23.x 修补的跟随度）。

---

## ⑤ 编译时长大头（默认 `cargo build --release --bin xray` 路径）

| 排名 | 大头 | 证据 | 备注 |
|---|---|---|---|
| 1 | **btls-sys（BoringSSL 全量 C/C++ + bindgen）** | 已知 ~4min 冷构建（HANDOFF v54 / 项目记忆；xray-transport-tcp/register.rs 触碰即冷重建）；target/release/deps 下 bindgen rlib 17.4MB + clang-sys 16.0MB（构建依赖） | 勿动清单 |
| 2 | **aws-lc-sys（AWS-LC C 构建）** | 当前处于激活态（见 P2）；libaws_lc_sys rlib 9.8MB | **可消除**: ring-only 统一后从默认构建消失（未实测时长，量级应为分钟级） |
| 3 | criterion | 仅 benches 成员（Cargo.toml:78），不进 xray bin 构建路径；`--workspace` 才拖入 | 保留合理 |
| 4 | prost-build/tonic-build | 仅 proto 变更时代码生成 | 正常 |
| 5 | rustls fork + ring asm | 常规量级 | — |

---

## 发现清单

### [P1] h2 0.4.15 命中 RUSTSEC-2026-0258（无界空 DATA 帧）| Cargo.lock:156
证据: cargo-deny advisories 实拉 DB 命中 `error[vulnerability]`，Advisory GHSA-q83h-524g-xf6h，Solution `Upgrade to >=0.4.16`；消费面: hyper 1.10.1（reqwest→finalmask realm client、ocsp-stapler）、h2 直依赖（xray-app-dns DoH、xray-transport-grpc）、naive/splithttp 的 hyper 栈。
影响: 面向恶意/被劫持的 HTTP/2 对端（DoH 上游、realm 控制面、naive 服务器入站）可造成无界内存增长或 panic——代理进程常驻内存场景直接相关。
修复: `cargo update -p h2`（0.4.x 内补丁位）。负优化自查: semver 兼容补丁、无 API 变化，修后复跑 naive/splithttp/DoH/grpc 相关节点即可，无回退风险。

### [P2] anytls default features 经 feature 统一拉起 AWS-LC（第 4 套 crypto 栈编入产物）| Cargo.toml:151,160 / Cargo.lock:3704-3708
证据: ① metadata `anytls→rustls uses_default_features=true`；② watfaq fork rustls/Cargo.toml: `default = ["aws_lc_rs", "logging", "prefer-post-quantum", "std", "tls12"]`，`aws_lc_rs = ["dep:aws-lc-rs", "webpki/aws-lc-rs", "aws-lc-rs/aws-lc-sys", "aws-lc-rs/prebuilt-nasm"]`；③ `cargo tree -i aws-lc-rs`: rustls fork + rustls-webpki 两条激活边；④ target/release/deps 实存 libaws_lc_sys rlib 9,848,672B + libaws_lc_rs 2,712,126B（release profile 实编译）。
影响: ring+RustCrypto+BoringSSL+AWS-LC 四栈并存——额外 C 构建时长（编译大头第 2 名）、二进制体积、供应链面；且 fork 私有 `prefer-post-quantum` 随 default 一并全局激活（对 rustls 出站 ClientHello 组偏好的实际影响需另行核验，标注: 需核验）。
修复: 优先上游路径——给 anytls 提 feature（rustls default-features=false）/升级 anytls；不可行再评估自维护 patch。**负优化自查**: 顺手从 fork 删 `aws_lc_rs` default 属中风险——若 anytls 运行时未显式安装 provider，rustls 双 provider 语义改动可能 panic（仓库已有 ring provider install 先例可复用，但需全 TLS 链路回归）；不建议无回归预算地顺手做，先留档。

### [P2] rsa 0.9.10 Marvin Attack 命中 xmc PKCS1v15 解密路径 | Cargo.lock:347 / crates/xray-transport/src/finalmask/xmc/conn.rs:245-250
证据: cargo-deny `RUSTSEC-2023-0071`（vulnerability，Solution: **No safe upgrade is available**）；conn.rs:246-249 `rsa_private_key.decrypt(Pkcs1v15Encrypt, &enc_shared/&enc_verify)` 对**对端提供的密文**做解密；Cargo.toml:34 注释明示 RSA-1024 PKCS1v15（协议对齐 Go finalmask xmc）。
影响: xmc server 角色对攻击者密文非常数时解密 = 时序侧信道（Marvin）可回收 RSA 私钥；RustCrypto rsa 无 Go crypto/rsa 的 blinding 缓解。finalmask 为实验特性，实际暴露取决于 xmc 入站是否公网可达。
修复: 上游无修复 → ①deny.toml `advisories.ignore` 留档+注记理由；②收缩暴露面（xmc 仅可信网段/限流）；③跟进 RustCrypto/rsa 重写进展（需联网核实）。负优化自查: 换 ring（无 RSA 私钥解密 API）或引入 openssl（新重量级依赖+新攻击面）均负优化；自实现 blinding 风险更高，均不做。

### [P2] lru 0.12.5 双 unsound 通告 | Cargo.lock:228
证据: `RUSTSEC-2026-0002`（IterMut 违反 Stacked Borrows，fix>=0.16.3）+ `RUSTSEC-2026-0253`（pop() 非 panic-safe UAF，fix>=0.18.2）；用点: xray-app-dns/src/fakedns/mod.rs:12,50,59,102（FakeDNS LRU）+ xray-proxy-vmess/src/aead/mod.rs:518-546（Go LRU-120 反重放）。
影响: 全仓 grep 未发现对 LruCache 的 `.iter_mut()`/`.pop()` 调用 → **当前实际暴露低**；但版本停在通告区间。
修复: 先在 deny.toml ignore 留档，随后小步升级 0.18.2+（major，需核对 `new/unbounded` 签名；两处调用面小回归容易）。负优化自查: 升级仅触及两处构造/读写，可控。

### [P2] anyhow 1.0.102 unsound（downcast_mut UB）| Cargo.lock:16
证据: `RUSTSEC-2026-0190`，fix>=1.0.103（patch bump）；全仓 grep 零 `downcast_mut` 调用 → 实际暴露≈0。
影响: 低，但属已知 UB 通告且一行可清。
修复: `cargo update -p anyhow`。负优化自查: 1.0.103 为 patch 版，无。

### [P2] deny.toml 审计门整体失效（schema 不兼容 + git 源白名单缺失）| deny.toml:7-8,40-45 / .github/workflows/ci.yml:71-77
证据: 本机 cargo-deny 0.20.2 解析 deny.toml 报 2 处 `error[unexpected-value]`（`unmaintained`/`unsound` 在新 schema 已改为 scope 数组）**拒绝加载**；`[sources] allow-git=[]` 与锁内 5 个 git 源冲突（实测 `check sources` 报 `warning[source-not-allowed]`：btls 0.5.6 等）；CI `audit` job 直接用 cargo-deny-action@v2。
影响: advisories/licenses/sources 三门空转——h2/anyhow 等 vulnerability 此前无门禁可拦，CI audit job 必红或形同虚设。
修复: ①deny.toml 迁移到 0.20 schema；②`allow-git` 放行 btls/watfaq 两域三仓库；③`advisories.ignore` 留档无修复项（rsa/paste/rustls-pemfile/lru×2/spin/chacha20）后恢复 `vulnerability = "deny"` 门禁。负优化自查: 放行 git 源表面上是"降低门禁"，实为如实反映既定架构决策（patch 段），配合 rev 锁定可接受；先修 h2/anyhow 再开门，避免开门即红。

### [P2] soketto 为未接线的脚手架依赖（permessage-deflate 未启用）| crates/xray-transport-websocket/Cargo.toml:21 / src/deflate.rs:15-46
证据: deflate.rs 三个公开 helper（`create_deflate_extension`/`add_deflate_request`/`server_accepted_deflate`）仅被同文件 `#[cfg(test)]` 引用；全仓 grep `::deflate::`/`create_deflate_extension` 零外部消费者；实际 WS 帧路径全走 tokio-tungstenite（xray-transport/browser_dialer.rs:16-17 等 5 处用点）；文件头 ponytail 注释自认"当前实现提供…辅助，完整替换可逐步进行"（deflate.rs:11-13）。
影响: soketto（+deflate 系传递依赖）纯编译/供应链成本，零运行时功能。
修复: 删 Cargo.toml:21 与 deflate.rs。负优化自查: 仅当未来对端强制 permessage-deflate 才需重引（Go xray WS 同无强制 deflate），删除不破坏对等性；若团队认定 deflate 路线图在即，则改为"接线"而非删除——二选一，现状最差。

### [P3] rustls-pemfile 2.2.0 unmaintained（RUSTSEC-2025-0134）| Cargo.lock:354
直接依赖 4 crate（cli/core/tls/websocket）。官方去向= rustls-pki-types 内置 PEM 解析。无漏洞，属计划性迁移；涉及证书加载路径，需回归 certificates 集成测试，不急。

### [P3] shadowsocks workspace 死声明 | Cargo.toml:146-147
54 个成员零引用（metadata 反查为空），Cargo.lock 无该包；:146 注释宣称"对应 go-shadowsocks2"但 ss 协议实际自实现（RustCrypto 家族直编）。删两行即可，负优化: 无（本就不在编译图）。

### [P3] num-bigint 死依赖 | crates/xray-transport/Cargo.toml:37
全仓零 `num_bigint` 引用；derivation.rs:14 实际 `use rsa::{BigUint, ...}`（rsa 再导出 num-bigint-dig 类型）；:38-39 num-traits/num-integer 有真实 use（derivation.rs:11-12），保留。删 :37 一行。负优化: 无。

### [P3] reqwest `blocking` feature 未用 | crates/xray-transport/Cargo.toml:31
见 ③ 表。删 `"blocking"`，无风险。

### [P3] tracing-subscriber `json` 未用 + xray-core 死声明 | Cargo.toml:105 / crates/xray-core/Cargo.toml:75
见 ③ 表。去 `"json"`、删 core:75，无风险。

### [P3] once_cell 仅剩 1 用点，可换 std::sync::LazyLock | Cargo.toml:181 / crates/xray-app-log/src/mask.rs:5
全仓唯一 `use once_cell::sync::Lazy`；rust-version 1.85 ≥ 1.80（LazyLock stable）。替换后删 workspace 声明。负优化: 无。

### [P3] workspace members 重复条目 | Cargo.toml:27,32（splithttp）75,79（tests）
cargo 静默容忍（metadata 实际 54 成员），纯清单卫生。删 2 行重复。

### [P3] aead 0.6-rc 线为刻意选择，连带 chacha20 0.10.0 yanked | crates/xray-crypto/Cargo.toml:16-17 / xray-proxy-ss/Cargo.toml:55-58 / Cargo.lock:58
注释证实刻意对齐 aead 0.6（"都用 aead 0.6"）；后果: chacha20 0.10.0 在 RUSTSEC yanked 名单（cargo-deny warning[yanked]）。处置: `cargo update -p chacha20` 尝试解决（需联网核实 0.10.x 是否存在非 yanked 版本）；RC 线本身留档，待 0.11 正式版发布再切。负优化自查: 强退回 aead 0.5 线需跨 8+ crate 重写，明确负优化，不做。

### [P3] spin 0.9.8 yanked（传递，无动作空间）| Cargo.lock:397
路径 lazy_static←num-bigint-dig/x509-parser/sharded-slab；0.9.x 末版即 0.9.8，semver 内无法 update。yanked=warn 不挡 CI，留档。

### [P3] paste 1.0.15 unmaintained（RUSTSEC-2024-0436，传递）| Cargo.lock:281
路径 netlink-packet-core→netconfig-rs（tun-rs 侧 Linux 网络配置），上游无替代，无动作，留档。

### [P3] 同名多版本共存可收敛子集 | Cargo.lock
rcgen 0.13/0.14（见 2.1 表，可做不紧迫）、webpki-roots 0.26/1.0（负优化自查: 需动 tokio-tungstenite 大版本，撞 ws 指纹硬禁触面，仅留档缓行）、其余 ~49 组为生态现实不动。

---

## 确认干净项清单（抽查证据）

1. **rustls/quinn/tokio/ring/aws-lc 安全版本**: RUSTSEC 2026-09-06 DB 扫描零命中，未落后已知修复（表 2.2）。
2. **无多个 JSON 库**: 仅 serde_json；serde_yaml/toml 各一且真实使用（xray-conf yaml.rs:15 / toml_config.rs:22）。
3. **CRC 双库非重复**: CRC64-ECMA182（ss validator.rs:12）vs CRC32（vmess aead mod.rs:212），不同多项式。
4. **哈希多库均有协议出处**: blake2=salamander、blake3=ss2022 subkey/vless/xudp、sha1/md-5=vmess/ss、fnv=vmess 头、ring digest=xmc witness（1.2 节）。
5. **双 TLS 栈（rustls+btls）为 uTLS 指纹刻意设计**: Cargo.toml:159/195 注释明示，非失控重复。
6. **tungstenite 真实使用**: browser_dialer（xray-transport/src/browser_dialer.rs:16-17,335）+ trojan/vless/vmess/websocket 传递。
7. **subtle 常时比较**（xray-tls/config.rs:16,169 ct_eq_slices）与 foreign-types（btls_reality.rs:40）小依赖均有真实用途。
8. **HTTP 分层合理**: hyper（客户端+服务器）/h2（DoH、grpc 直用）/httparse（嗅探）/reqwest（仅 finalmask realm 控制面），无同层重复。
9. **no-default-features 纪律良好**: quinn/hickory/smoltcp/tun-rs/boringtun/hyper-rustls/ocsp-stapler 全部精确裁剪，唯一破口=anytls（P2）。
10. **git 依赖 rev 已锁**: 5 个 git 包 lock 均有完整 commit hash，构建可复现；btls 三包同仓库同 rev 无劈叉。
11. **criterion 不在 xray bin 编译路径**: 仅 benches 成员（`--workspace` 才拖入）。
12. **anyhow/lru 通告的当前实际暴露**: downcast_mut 全仓零调用；LruCache 的 iter_mut/pop 全仓零调用（grep 证据）。

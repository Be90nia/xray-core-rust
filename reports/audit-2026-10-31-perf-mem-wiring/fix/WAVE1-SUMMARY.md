# 波 1 收尾报告（G2 / G3 / G4）

- 基线 `5fe98b90`，分支 `feature/fix-inbound-parity`
- 三组并行（端口段 29000-29049 / 29050-29099 / 29100-29149），CARGO_TARGET_DIR 共用 `target-WAVE1`
- 未 commit（等波次收尾统一提交）

## 状态总览

| 组 | 裁决 | 票数 | 完成 | 关键缺口 |
|---|---|---|---|---|
| **G2 inbound** | CONDITIONAL | 9 | 9 票代码全改 | **零测试、零端到端**（预算耗尽）；ss listening 日志项未定位 |
| **G3 UDP 隧道** | CONDITIONAL | 7 | 6 票（tuic 未做） | **`interop_udp_tunnel.py` 未建**（t0ls1 无真机字节级验收）；anytls 单测超时未验证 |
| **G4 splithttp** | **PASS** | 4 | 4 票全绿 | 会话上限取值待拍板；h3/stream-one 既有缺陷（非本轮引入） |

## 合并后验证（PM 亲自跑）

| 项 | 结果 |
|---|---|
| `cargo check --workspace --all-targets` | **绿**（28.01s，含 `xray-integration-tests`） |
| 受影响 crate `cargo test --lib` | 待（后台 bg_579） |
| 树状态 | 34 改 + 3 新，无未跟踪的临时产物 |

PM 修复的跨组断点：`tests/integration/interop_trojan_test.rs` 因 `serve_trojan` 签名变更（G2 的 `hl8q6`）未同步 → 已改为共享 `Validator` 形态（3 处小修，单文件）。

## G2 交付明细（代码已落地，验证待补）

| 票 | 状态 | 证据 |
|---|---|---|
| `u4efe` P0 | DONE | 空口令拒启 + 多用户逐个匹配（+2 新测试） |
| `zmpxy` P0 | DONE（代码） | dokodemo UDP 容量门（809→上限；测试未写） |
| `ym0z8` P1 | DONE（代码） | insert+spawn 同锁（并发测试未写） |
| `bz800` P1 | DONE | anytls 空口令拒启 + 测试期望反转 |
| `hl8q6` P1 | DONE | vless/vmess/trojan/ss2022-multi/wg 用户热更；hysteria 记账 |
| `vdl95` P1 | DONE | 未知协议拒启 + sniffing 排除表 fail-fast（2 处测试反转） |
| `9c8k6` P2 | DONE（3/4） | should_append/AddRule 载荷/register_user_manager；④属 G1 |
| `il9lh` TPROXY 段 | DONE（代码） | 256 上界 + LRU（Windows 不可测） |
| `p45qd` P2 | DONE | ss2022 容差收敛为单一常量 |

**扩面批准记录**：`arm_builders/inbound.rs`（register_* 调用行）、`xray-proxy-trojan/src/server.rs`（serve_trojan 共享 Validator）。

## G3 交付明细

| 票 | 状态 | 关键 |
|---|---|---|
| `t0ls1` P0 | DONE（代码级） | 四处契约同改：出站剥帧/回程裹帧、mux client data 段裸载荷、mux server `handle_xudp_new` 双向、入站 plain UDP 保持零改动。共享件 `XudpUnframer`/`XudpReframer`/`XudpWireConn` 落 `udp_session.rs`，`advance+split_to` 原地剥头零额外拷贝 |
| `zu7tk` P1 | DONE | 根因 `xray-xudp MAX_DATA_LEN=7526`（误抄 Go wire 侧常量）→ 改 `u16::MAX`，8000B 往返测试 |
| `tini5` P1 | DONE | 读缓冲 64KiB→8KiB；`MAX_UDP_SESSIONS=4096` fail-visible |
| `yfcnr` P1 | DONE（单目标形态） | UoT v2 实现（magic 目标 + Request 头 + XudpWireConn） |
| `j7de2` P2 | **未做** | tuic UDP 零改动 |
| `1fm1l` UDP 半 | DONE 3/4 | udp_session/freedom/socks 去每包分配；`packet.rs` 记遗留 |
| `1ksxu` D3/D6 | DONE | freedom 域名按 socket 族择优；FRAG 已有计数 |

## G4 交付明细（PASS，含真机取证）

| 票 | 状态 | 真机数字 |
|---|---|---|
| `dct2d` P0 | DONE | 推 2048MiB：RSS **3656MB → 15.2MB**，且 413 拒收（chunked 4304MB → 17.7MB） |
| `3zbwx` P1 | DONE | 1100 伪造 id：`{200:1100}` → `{200:1024, 429:76}` |
| `1fm1l` xhttp 半 | DONE | alloc/MB **2.583→1.291**、alloc_n −78%、上行 **84→243 MB/s** |
| `2xgln` P2 | DONE | SETTINGS=250，第 251 流 RST_STREAM(REFUSED_STREAM) |

## 遗留项（进入波 2 前必须处理）

1. **G3 的 `interop_udp_tunnel.py` 未建** —— `t0ls1` 目前只有单元级证据，**不得宣称 UDP 隧道已修好**。这是波 2 合并前的第一优先验证项。
2. **G2 零测试零端到端** —— 9 票代码需要跑：ss 空口令/双用户、anytls 拒启、未知协议拒启、并发 AddInbound、三协议 add-user 真握手。
3. `anytls` 单测 1200s 超时无结果 —— 疑似挂死，需短超时点名定位。
4. `j7de2`（tuic UDP）未做 —— 顺延波 2 或单列。
5. `1fm1l` 的 `packet.rs` 载荷 Vec 未改（API 面）—— 顺延。
6. G4 待拍板：会话上限 1024 是否合理；`h3/stream-one` 既有缺陷单独立票。
7. G2 交接：`functions.rs:612-619` NotFound→ExistingTag 映射（属 G1 面）已挂 `ym0z8` 票注。

## 磁盘卫生

- 已清理：`D:/tmp/g4/tree`（worktree）+ `D:/tmp/g4/target-base`（62G）
- 保留：`target-WAVE1`（波 1 共用，波次结束统一清理）

---

## 附录：G3 追加轮（PM 打回后）

### 1) 红测试修复（根因=测试期望错，非实现 bug）
`cargo test -p xray-proxy-trojan --lib` 曾红：`udp_framed_conn_roundtrip` 断言 `left: []`。
根因：`TrojanUdpFramedConn::poll_read` 按 `AsyncRead` 契约**分段交付**（先 `hdr` 后 `rview`，dispatcher.rs:280-292），测试只调一次 `read` 就按整帧算偏移。
修法：测试改累积读（`read_until` 三段式），`poll_read` 交付粒度**零改动**。重跑全绿。

### 2) `dist/interop_udp_tunnel.py` 建成并实跑（t0ls1 正式验收）

Rust=`target-WAVE1/debug/xray.exe`（含改动），Go=`D:/tmp/go2617/xray.exe`；载荷 29B 裸 DNS，上游记录 peer/len/hex 并回 45B 合法应答；判据=上游 hex 逐字节等于 29B + 包数==1 + 客户端 txid 回显。

| 分组 | 结果 |
|---|---|
| **cone=off（plain UDP 隧道）** | **36/36 PASS**：vless/vmess/trojan × {rust→go, go→rust, rust→rust, go→go} × {53,443,29090}，上游全部收到 `123401000001…00010001` 29B 逐字节一致 |
| cone=on，dest=53/29090 | PASS（除 rust→rust） |
| cone=on，dest=443 | FAIL，但 **go↔go 控制组同样 FAIL** ⇒ 非本仓缺陷（Go 客户端 mux + UDP:443 口径） |
| cone=on，**rust→rust（全端口）** | **FAIL（上游 0 字节）** ⇒ 新缺陷票 `sgdkj`（Rust mux 服务端 XUDP 会话面） |
| dokodemo UDP 经隧道 | rust→go **PASS（修复前是 53B 废）**；go→go PASS；go→rust / rust→rust FAIL（同 `sgdkj`） |
| DNS over UDP 经隧道 | rust→go / go→rust / go↔go PASS；rust→rust FAIL（同 `sgdkj`） |

**结论**：`t0ls1` **可以宣称修好，附条件**——cone 关（plain UDP 隧道，任意端口）36/36 字节级 PASS，覆盖修复前双向皆废的三条路径（rust→go 53B、go→rust 上游 0 字节、rust↔rust 双层裹帧）。**cone 开 + Rust↔Rust** 仍红，属四处契约之外的新缺陷（`sgdkj`）。

harness 自身两处假红已修：dokodemo 只监听 UDP 却用 TCP 探活；用例名含 `->`/`=` 导致配置文件名 Windows 非法。

---

## 附录 B：G2 追加轮（端到端补齐）

PM 打回后 G2 补完 6 项端到端 → **8/8 PASS**（`target-WAVE1/debug/xray.exe`，端口 29000-29049）：

| # | 项 | 证据 |
|---|---|---|
| 1 | ss 空口令 | `exit=1`：`ss account parse: Shadowsocks password is not specified.` |
| 2 | ss 双用户 | 两用户均真回显（socks→ss 出站→ss 入站→freedom→echo） |
| 3 | anytls 无口令 | `exit=1`：`anytls inbound requires settings.password` |
| 4 | 未知协议 | `exit=1`：`unknown inbound protocol: no-such-proto` |
| 5 | 并发 AddInbound 同 tag | 20 并发 → `ok=1 already=19 other=0`；`rmi` 后 `port_closed_after_rm=True`（无孤儿） |
| 6 | 用户热更真握手 | vless/vmess/trojan 各 `adu` 后**新凭据真回显** |

补测：`zmpxy` dokodemo UDP 容量门测试、`ym0z8` 并发 AddInbound 测试，均绿。
排障要点（可复用）：freedom 必须显式 `finalRules:[{action:"allow"}]`，否则 `target blocked by final rule` 把数据面全黑；`adi/adu` 配置文件是位置参数（无 `-c`），inbound 必须带非空 `settings`。

## 最终门禁（波 1 收口，PM 亲自跑）

| 门 | 结果 |
|---|---|
| `cargo fmt -p <我方 14 crate> -- --check` | **0 diff** |
| `cargo check --workspace --all-targets` | **绿**（27.7s） |
| `cargo clippy --workspace --all-targets -- -D warnings` | **绿**（27.3s） |
| `cargo test`（受影响 crate lib） | dispatcher 147 / mux 143 / xudp 97 / freedom 97 / socks 86 / ss 185 / splithttp 267 / grpc 94 / trojan 88 — 全 0 failed |

注：`cargo fmt --all --check` 在 `crates/udf-frame/**` 仍有 diff（外部工作副本，不在我方维护面，未触碰）。

## 波 1 遗留（已建票，进后续波次）

| 票 | 级 | 内容 |
|---|---|---|
| `sgdkj` | P1 | cone 开 + Rust↔Rust UDP 仍 0 字节（Rust mux 服务端 XUDP 会话面） |
| `1xfap` | P2 | splithttp h3/stream-one Rust 服务端回空（既有缺陷） |
| `33ll3` | P2 | anytls `--lib` 单测疑似挂死 |
| `c89uy` | P2 | 用户管理 API 载荷 JSON vs Go protobuf Account |
| `j7de2` | P2 | tuic UDP（G3 未做，顺延） |



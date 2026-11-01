# 第二轮对抗复核 · 性能/内存接线 5 条断言

VERDICT: CONDITIONAL

- 复核对象：W1 / Q1 / W5 / W3（+ W2 顺带）
- 基线：`feature/fix-inbound-parity` @ `5fe98b90`，`target/release/xray.exe` 自报 `git_rev=5fe98b907c7b...`（= HEAD，非陈旧产物）
- E1 实跑：W1（见 §W1）、Q1（E1 只作旁证，见 §Q1）；W2/W5/W3 = E2 代码级复核
- 不重开已 CLOSED 票；未改任何生产代码/vendor（本报告只出裁决）
- 复核独立于第一轮推理：先跑数、再读码，最后才看第一轮结论

---

## §W1 rustls 逐 record 明文拷贝

### E1 复现（命令与输出）

```
python tools/loopback_alloc_bench_variants.py --variant tcp-tls \
    --xray target/release/xray.exe --runs 3 --alloc-stats --tag vperf-w1
```

```
[tcp-tls] #1: speed=452143916.0 B/s (452.1 MB/s) size=209715200 time=0.463855s
[tcp-tls] #3: speed=499187599.0 B/s (499.2 MB/s) size=209715200 time=0.420203s
transferred=629145600 bytes (600.0 MiB)
alloc/MB[srv] = 1.094 (...)
sites[srv]: tls_read d_bytes=0 d_n=0 ; (untagged) share=98.3%
alloc/MB[cli] = 1.167 (Δalloc_bytes=700286328, Δalloc_n=194598, 600.0 MiB)
sites[cli]:
  site=tls_read         d_bytes=   629301741 d_n=    38723 share=89.9%
  site=buf_read         d_bytes=    57534024 d_n=    39064 share=8.2%
  site=tls_write        d_bytes=         468 d_n=        6 share=0.0%
  site=(untagged)       d_bytes=    13450095 share=1.9%
```

换算（脚本 `alloc/MB` 口径是 `bytes / MiB数 / 1e6`，相对 bytes/bytes 偏高 4.86%，下表统一按 **bytes/bytes**）：

| 指标 | 实测 | 第一轮断言 | 差 |
|---|---|---|---|
| cli `tls_read` | 629,301,741 / 629,145,600 = **1.00025 MB/MB** | 1.0003 | 4 位有效数字吻合 |
| 每 record 分配字节 | 629,145,600 / 38,723 = **16,247 B** | 16.2 KB | 吻合 |
| 分配次数 | 38,723 / 600 MiB ⇒ **12,908 / 200 MiB** | 12,903 / 200 MiB | 0.04% 差（= 末条零头 record） |
| 占 cli 分配字节 | **89.9%** | 84.2% | 差 5.7pt，原因是本轮 untagged 仅 1.9%（首轮该拓扑环境噪声更高）；不影响结论 |
| cli 总量 | 700,286,328 / 629,145,600 = 1.113 MB/MB | — | 新增基线数 |

→ **量化断言 CONFIRMED（E1，一键复现）**。

### 机制链（E2，代码级唯一匹配）

1. `vendor/rustls/src/crypto/ring/tls13.rs` `Tls13MessageDecrypter::decrypt`：`dec_key.open_in_place(nonce, aad, payload)` → **就地解密在 `msg.payload`（Vec）里**，`truncate` 后 `into_tls13_unpadded_message()` ⇒ `InboundPlainMessage.payload = Payload::Borrowed`（借用 deframer 缓冲）。
2. `vendor/rustls/src/common_state.rs:483-486`：
   ```rust
   pub(crate) fn take_received_plaintext(&mut self, bytes: Payload<'_>) {
       self.received_plaintext.append(bytes.into_vec());   // ← 486
   ```
3. `vendor/rustls/src/msgs/base.rs:41-45` `Payload::into_vec()`：`Borrowed(bytes) => bytes.to_vec()` ← **每次 record 一次新 Vec + memcpy**（正是 16,247 B/次）。
4. `ChunkVecBuffer::append(Vec)`（`vecbuf.rs:76-83`）只 `push_back`，**不再拷贝**；`ChunkVecBuffer.received_plaintext` 类型确认（`common_state.rs:52`）。
5. tokio-rustls 侧 `reader().into_first_chunk()` / `consume` 直接取走 chunk（`vendor/tokio-rustls/src/common/mod.rs:212-248`），无二次分配。

→ 分配次数（1/record）、单次大小（= record 明文长）、归属站点（rustls 读路径）三者同时唯一匹配 `base.rs:43`。**归因 CONFIRMED**（残余不确定性：未做 stack 级堆采样，本仓无 dhat/jemalloc profiling 件；但 16,247 B ≈ 明文长的整数匹配排除其它候选）。

### 第一轮断言的哪一步不成立

| 原话 | 复核结果 |
|---|---|
| "AES-GCM 已就地解密，随后整段复制**纯多余**" | **成立但需限定**。在 buffered API 内该拷贝是**必需**：明文借用的是 deframer 的复用缓冲，`received_plaintext` 要跨 poll 持有，无法交出所有权。只有换成 unbuffered 调用形态，这个拷贝才成为多余 |
| "收敛路径 = rustls unbuffered API（`conn/unbuffered.rs` 在树内）" | **路径存在且是对的**（`pub mod unbuffered` 导出 `UnbufferedConnectionCommon` / `AppDataRecord`，`unbuffered.rs:1-63` 用 `DeframerSliceBuffer::new(incoming_tls)` 全程只推偏移）。但**不等于 vendor 一行改动** |
| "需 `vendor` 红线授权" | **不需要**。真正的改动落**调用侧**：要自写 rustls unbuffered 的 `AsyncRead/AsyncWrite` 驱动替掉 tokio-rustls（`ConnectionState` 状态机 + `EncodeTlsData`/`TransmitTlsData`）。vendor/rustls 一行不用改 |
| 先例 `8b5453ef` | 先例是**vendor 侧补丁**（deframer `prepare_read` 去 `used==0` 缩容），不是 unbuffered 迁移先例；两者只共享"TLS 读写路径可改而 wire 不变"这条经验 |

### 授权/先例/成本

- **授权**：无需红线授权（改 `crates/xray-tls` 侧适配层）。仅当退化成"vendor 侧回收 chunk 减少 malloc 但仍 memcpy"的补丁才需 vendor 授权——而那种补丁按 bbuh7 的实测（分配不是瓶颈）**收益≈0，不建议**。
- **先例**：`8b5453ef`（bbuh7，vendor/rustls，tls_read 4.76→1.00、吞吐 +21.7%、wire 逐字节 MATCH、32/32 + interop 12/12 绿）；**unbuffered 迁移无先例**。另：`reports/audit-2026-10-26/bbuh7-upstream-research.md` 独立得出同一结论（"0.23.45 上不动源码的唯一解是 unbuffered，tokio-rustls 不暴露"；`SliceInput/TlsInputBuffer` 仅在 main 未发布）——我的复核与之独立吻合。
- **成本**：高。新 TLS 驱动 ≈ 一个模块（握手各态 + 出站缓冲 + close_notify/key_update + REALITY 兼容），且必须保留 btls 路径不动。
- **风险**：中高（TLS 全栈读写面）。**32/32 与 interop 预判依据**：
  - wire 不变（仍是 rustls 记录的逐字节同构）——8b5453ef 已实证"改读写路径可以做到 tshark record 数与字节全等"；
  - REALITY patch 的钩子住在 `client/hs.rs::start_handshake`（`UnbufferedClientConnection::new` 同样走该状态机，`client_conn.rs:950-957`），config 侧 `reality_config` 在 `ClientConfig`——**大概率可复用**（`[INFERENCE]`，需一次 unbuffered+REALITY 对 Go 的互通探针实证）；
  - 唯一确定受影响面 = 服务端 TLS 入站 + 无指纹的 rustls 出站；指纹（btls）路径零变化；
  - 已知缺口：`UnbufferedClientConnection::new` 不接受 session_id_generator（tokio-rustls fork API），本仓该 API 现无调用方（Cargo.toml 注释），不阻塞。

### 严重度校准：P1 → **P2**

依据（都是实测，不是推断）：
1. bbuh7 记录：**削掉 46% 分配（我方侧）→ 吞吐 397.4→393.0，区间完全重叠** ⇒ 分配在该路径不是吞吐瓶颈；
2. 残余量级 = 每 record 一次 16KB memcpy；按本轮 450-500 MB/s 计 ≈ 单核 3–5%，远小于已消除的 61.5KB/record realloc churn（那次 +21.7% 主要来自 realloc，不是 alloc 次数）；
3. 修复面是适配层重写，与收益（个位数 % CPU）明显不成比例。

**第一步（若要动）**：先在 `xray-tls` 做单点实验（独立模块 + 仅 tcp-tls 一条路径），量 **CPU（非只吞吐）+ alloc/MB**，再决定是否全域替换。当前建议：**不排期**，保持 P2 记录在册（本条当前**无 bd 票**——bbuh7 已关且只覆盖 churn 面）。

---

## §Q1 BufferPool 接缝整族未接线

### 事实复核（E1 旁证 + E2 全文检索）

| 断言 | 复核 |
|---|---|
| trait / `ManagedBufferPool` / `XrayBufPool` 存在 | ✅ `crates/xray-frame/src/pool.rs`，`lib.rs:93` 导出 |
| `with_pool` 注入面未接线 | ✅ 全仓 `with_pool(` 仅 2 处：`assembly.rs:222` 定义、`assembly.rs:475` 测试。生产零调用 |
| 目标主路 `xray-cli/src/framework.rs:746` 没调 `.with_pool(...)` | ✅ 精确到行：`assemble()` = `framework.rs:733-749`，746 行就是 `builder.build()`；链上只有 `with_config` + `register`，**无 `.with_pool(...)`**。**且 `framework-assembly` 是非默认 feature**（`crates/xray-cli/Cargo.toml:80`）——框架主路连默认二进制都不在 |
| `ctx.pool()` 无生产消费 | ✅ 仅 `xray-frame` 自带测试 + **13 个** proxy crate 的 L4 夹具（`grep ManagedBufferPool::new` 命中 anytls/dns/dokodemo/freedom/hysteria/loopback/socks/ss/trojan/tuic/tun/vless/vmess 的 `tests/plugin_contract.rs`；夹具是**每测试自建一个池**直接断言借还配平，从不经 `ctx.pool()` 取） |
| clippy L3 闸 | ❌ **不存在**：全仓 clippy.toml 无 `xray_buf::alloc` 的 `disallowed-methods` 条目（只有 `slice::to_vec` / `MultiBuffer::to_vec`）。`pool.rs:16`、`context.rs:322` 自己在注释里写"归 P2 批次落地" |
| 生产实际用 `xray_buf::alloc` 分层池 | ✅ 且**无绕过者**：`xray_buf::alloc::alloc` 生产调用点 = `xray-buf/buffer.rs:54`（池本体）、`xray-frame/pool.rs:181`（接缝适配器）、`xray-transport/bridge.rs:93/184`（池化读循环）。vless/freedom/trojan 等协议 crate **零直接调用** ⇒ 没有"违反接缝"的现场 |

E1 旁证：默认二进制 `tcp-tls` 全链路跑通（§W1 那次 600 MiB、452-499 MB/s），说明该族未接线**零运行期影响**（无消费方，故无 fail-visible 触发）。

### 是"缺陷"还是"已规划未落地"？→ **已规划未落地，且 PM 已裁定降格**

- bd `nn8os`（**CLOSED**，P1，2026-10-28）笔记原文：
  > "**DOD 六柄里 pool / ids / audit 零生产消费**（仅机制 + L4 契约夹具）… **需接线，或由 PM 降格 DOD 措辞为「机制就绪 + 有接入口即算达」**"
  > 同票 10-29 收口核账把"2a 面"判为 ✅（`PluginContext` 持八项 + 装配根注入面存在），战役 epic `99ifi` 按"机制就绪"口径关票。
- `crates/xray-proxy-loopback/src/plugin.rs:8` 注释自陈："池纪律条款按'全适用'声明、**能力暂不消费**"。
- **当前无 open bd 票跟踪接线**：`bd list --status open` 仅 3 张（`zg6eg` / `23vrp` / `a5pe6`），无池化相关；`bd search pool|udp|分配` 在 schema skew（db v65 vs bin v53）下检索受限，故另以全量导出（`bd list --status all/closed`）交叉核过，亦无 BufferPool 接线票。

⇒ 裁决：**Q1 事实 CONFIRMED，定性 ADJUSTED——不是缺陷，是"已规划未落地 + 已拍板降格"**。校准严重度 **P3（治理/文档）**，非性能项。

### 文档漂移点（这是本条唯一需要动手的地方）

1. **`docs/architecture/xray-frame-强约束插件模型-2026-10-23.md`**：§2.4 坑约束表第 4 行把"缓冲必须走 BufferPool 接缝"写作**已强约束**（机制 = "L3-10 + 池审计断言"），§2.3 能力表也写 `ctx.pool()` 为唯一取池口、禁直接 `xray_buf::alloc`。实际：零消费 + 无 clippy 闸 ⇒ 该条款处于"**声明未执行**"。同文档 §2.4 第 10 行又标"归 P2 批次落地"——**文档内自相矛盾**（一处当已生效，一处当待办）。
2. **`crates/xray-frame/src/pool.rs:15-16` / `context.rs:322-323`**：注释口径**正确**（明确写 L3-10 待 P2 落地），但**没有对应 bd 票** ⇒ 待办悬空，只活在代码注释里。
3. **CLAUDE.md §3.5.4 归一化面台账**：**没有池化行**（现行七行 = JSON 工具壳 / 配置 lint / 日志 Handler / 配置装配 / 注册表族 / 中央 match 臂 / 任务托管）。因此"台账 vs 实际"**不矛盾**；缺口是**手册层缺登记**——已知待办（接缝未接线 + L3 闸未落）在 §3.5.2/§3.5.4 里一个字都没有。若补一行，建议写成：
   > `池化接缝（xray-frame::pool）：机制就绪（BufferPool/ManagedBufferPool/XrayBufPool + ctx.pool() 装配注入面 + L4 夹具）；生产零消费、L3 clippy 闸未落；接线待建票（bd nn8os 已按"机制就绪"口径关闭）`

**第一步**：建一张接线票 **或** 把上面那行写进 CLAUDE.md §3.5.4（二选一，别两头空）。零成本，改文档即可。

---

## §W2 xhttp 上行逐块新分配

**裁决：CONFIRMED（E2）**，第一轮机制描述有一处不精确。

- 5 处站点全部在 stream-up / stream-one（h2 3 处、h3 2 处）：`dialer.rs:230/270/513/547/688`；packet-up 不走 `ReaderStream`（独立 `read_exact` 循环）。
- tokio-util **0.7.18** 源码（`Cargo.lock` + registry `reader_stream.rs:92-121`）：
  ```rust
  if this.buf.capacity() == 0 { this.buf.reserve(*this.capacity); }   // capacity = 4096
  match poll_read_buf(reader, cx, &mut this.buf) { ... Ok(_) => { let chunk = this.buf.split(); ... } }
  ```
  `BytesMut::split()` = `split_to(len)`（bytes 1.12.1 `bytes_mut.rs:375-378`），self 保留 `[len, cap)`；**4 KiB 管道被读满时 cap 归零 → 下一 chunk 必然 reserve 一块新 4 KiB**。
- **第一轮措辞校准**："`buf.split()` → 下次必新分配"不精确——真正触发是 `capacity()==0`；未读满时会复用剩余容量（4 KiB `tokio::io::duplex` 下稳态基本都读满，观测行为与断言一致）。
- 量级：上行 1 MB ≈ 256 次 4 KiB 分配 + **256 个 h2 DATA 帧**（4 KiB/帧）。这条路径就是基线拓扑（xhttp `mode=auto` + REALITY → stream-one）的上行**实际**路径，只是基线只测下行所以看不见。
- 先例/成本：**已有成品可复用**——`hub/dl_stream.rs` 的 `BufPool` + `PooledBuf` + `Bytes::from_owner` 就是下行孪生面（r1693 → 9eu4a 修复，实测 srv alloc/MB 1.758→1.145）。把该流泛化成"输出 `Result<Bytes>`"即可替换 5 处 `ReaderStream::new`，顺带把 4 KiB 提到 64 KiB（帧粒度改善）。改动 ≈ 60-100 行 + 1 个 h2/h3 上行 e2e。**风险低**（仅上行 body 流，wire 不变）。**授权：无需**（主仓；`bytes` 方向件纪律已由 dl_stream.rs 注释确立）。**注意**：容量策略要按 9eu4a 的自适应峰值，别照抄 r1693 的固定容量（那是被 9eu4a 判失效的原因）。
- 严重度：**P2**（维持）。第一步：泛化 dl_stream → 先只改 h2 stream-one，量上传吞吐 + alloc/MB。

---

## §W5 UDP 每数据报 2–4 次分配

**裁决：CONFIRMED（E2），并给出比第一轮更具体的定位。**

以 `crates/xray-proxy-freedom/src/udp.rs:508` 与 `crates/xray-proxy-socks/src/udp.rs:~382`（响应向）为例，每数据报实测开销：

| # | 分配点 | 规模 |
|---|---|---|
| 1 | `let mut frame = Vec::with_capacity(n + 64)` | n+64 |
| 2 | `PacketWriter::new(...)` → `scratch: Vec::with_capacity(64)`（`xudp/packet.rs:305`） | 64 |
| 3 | `MultiBuffer::new()`（`Vec::new()`）→ 首次 `push` | 1 槽 |
| 4 | `mb.merge_bytes(&frame)`（`multi.rs:202-224`）→ `Buffer::new()` + `write_from`（**再拷一次**） | ≥n |

⇒ **4 次分配 + 2 次全量拷贝**，约 2 MB/MB（响应向）。`udp_session.rs:95` 发送向 `Vec::with_capacity(payload+666)` 每报 1 次。

**第一轮是否夸大**：次数上不夸大（"2–4 次"成立）。但**漏了一条更便宜的**：`PacketWriter` 自带 `scratch` 复用字段，却被"每包重建 PacketWriter"打败（`packet.rs:305` 构造即分配）——这属于"设计已存在、调用形态把它废掉"，比抽象级重构便宜得多。
**正确范式在树内**：`mux/writer.rs:239-260` 用 `FrameMetadata::write_bytes_into(scratch)` 直写池化 `Buffer` 的 spare + `MultiBuffer::with_capacity`，一次落地。
**成本**：低（每站点 ~15 行）。**风险**：低（UDP 面 e2e：socks UDP ASSOC / freedom UDP / XUDP）。**授权**：无。**先例**：wfx8-3（mux 直序）、`43dh`（in-place AEAD 收口批）。
**严重度**：**P2**（维持；限定 UDP 面，TCP 大流量路径无关）。第一步：挑 `freedom/udp.rs` 单点按 mux 范式改，量 u64→freedom UDP 的 alloc/MB。

---

## §W3 每次 read/write 一次装箱 future

**裁决：ADJUSTED（方向成立，量级被夸大；"不建议重做"结论维持但理由要换）。**

- 事实 ✅：热循环 `crates/xray-transport/src/bridge.rs:166` `reader.read_multi_buffer().await`；trait 声明处 `io.rs:81`/`io.rs:148`（`Pin<Box<dyn Future>>`）。每次读操作 1 次 `Box::pin`（~48-96 B），**不是每 poll、不是每字节**。
- 第三处引用漂移：`multi.rs:36` 现为 `from_buffer` 的 `vec![buf]`（一次分配），与"装箱 future"无关。
- 已有部分 poll 化（`34nk` 丢唤醒修复引入）：`poll_read_multi_buffer`/`poll_write_multi_buffer` 在 trait 上带默认实现（默认实现仍建 boxed future），`pipe.rs:344/474`、`dispatcher/stats.rs`、`splithttp/connection.rs:306` 已覆写；未覆写的实现走默认（又回到装箱）。
- 量级校准：按 8 KiB/读操作 ≈ **0.01 MB/MB 量级**，字节维度可忽略；CPU 维度只有一次 dyn 派发，无实测证据。
- 历史 ✅（负优化警示成立，并已精确定位）：`git log -S "poll_read_multi_buffer" -- crates/xray-buf/src/io.rs` 三行即全史——
  1. `76feeba3` **引入**（"io.rs trait poll 化 … 消全链 `Pin<Box<dyn Future>>` 装箱税"，+32 文件）；
  2. `d820547f` **回退**（逐字还原 `547200b3` 基线；另一分支线孪生回退 = `c56b442d`，还原 `1aeb929a`），理由原文含"**dispatcher 130/130 复绿（waker 死锁随回退消失）**"+"性能优化与架构改形分离裁定"；
  3. `12824544`（bd 34nk 丢唤醒修复）**窄面重引入**——只加 trait 的 `poll_*` 入口 + 默认实现 + 逐 impl 覆写，活到今天。
  ⇒ **全家 poll 化 = 两次证伪；窄面重引入 = 已存活先例**。这正是本条允许的唯一形态。
- 严重度：**P3 / 不排期**。若真要动，只能做窄面（bridge 热循环单点 + 具体 impl 覆写），且**先给 CPU 证据**；全家 poll 化禁重做。

---

## 裁决表

| 编号 | 原断言 | 我的裁决 | 复现命令与输出 | 成本/风险/授权/先例 | 校准后严重度 | 若修复的第一步 | 反证或支持点 |
|---|---|---|---|---|---|---|---|
| W1 | rustls 逐 record 全量明文拷贝（`common_state.rs:483` ← `base.rs:43` to_vec），1.0003 MB/MB·84.2%·12903/200MiB；"已就地解密，复制纯多余"；收敛 = unbuffered，需 vendor 授权，先例 8b5453ef | **CONFIRMED（量化+机制）／ADJUSTED（"纯多余"须限定；改动在调用侧不涉红线；P1→P2）** | `python tools/loopback_alloc_bench_variants.py --variant tcp-tls --xray target/release/xray.exe --runs 3 --alloc-stats --tag vperf-w1` → `site=tls_read d_bytes=629301741 d_n=38723 share=89.9%`（=1.00025 MB/MB，16,247 B/次，12,908/200MiB；吞吐 452-499 MB/s） | 成本**高**（重写 TLS 适配层 ≈ 1 模块）/风险中高（TLS 全栈读面；btls 不动）/授权**无需红线**（改 xray-tls 侧）/先例 8b5453ef（vendor 侧，非同面）；unbuffered 迁移无先例 | **P2**（原 P1） | 不排期；若动则先做 xray-tls 单点 unbuffered 实验，量 **CPU**+alloc/MB 再定 | 支持：E1 三项同时吻合 + 机制链唯一匹配（`open_in_place`→`Payload::Borrowed`→`into_vec/to_vec`→`append` 不拷）。反证：buffered API 内该拷贝**必需**（deframer 缓冲复用），"多余"只在 unbuffered 形态成立；bbuh7 实测"削 46% 分配 → 吞吐零变化"否定其吞吐价值 |
| Q1 | BufferPool 接缝整族两条主路都未接线，框架路 `framework.rs:746` 也没 `.with_pool(...)`；生产用 `xray_buf::alloc` 分层池 | **CONFIRMED（事实）／ADJUSTED（定性：已规划未落地+已拍板降格，非缺陷）** | `with_pool(` 全仓仅 `assembly.rs:222/475`（定义+测试）；`ctx.pool()` 生产零调用；clippy.toml 无 `xray_buf::alloc` 禁令；`framework-assembly` 非默认 feature（`xray-cli/Cargo.toml:80`）；E1 旁证：默认二进制全链路正常 | 成本**极低**（改文档/建票）/风险无（无消费方）/授权无/先例 nn8os 笔记已明确"零生产消费…需接线或降格" | **P3**（治理/文档） | 建接线票 **或** 在 CLAUDE.md §3.5.4 补"池化接缝：机制就绪、零消费、L3 闸未落"一行 | 支持：bd `nn8os`（CLOSED）+`99ifi` 按"机制就绪"口径关票；`loopback/plugin.rs:8` 自陈"能力暂不消费"。反证：**无 open 票**跟踪接线（open 仅 3 张，`bd search` 在 v65/v53 skew 下受限，已用全量导出交叉核） |
| W2 | xhttp 客户端上行逐块新分配（`ReaderStream::new` ×5），`9eu4a` 的孪生面 | **CONFIRMED（E2）**（机制措辞校准：触发是 `capacity()==0`，非 split 本身） | tokio-util **0.7.18** `reader_stream.rs:92-121` + bytes 1.12.1 `bytes_mut.rs:375-378`（`split()=split_to(len)`）；站点 `dialer.rs:230/270/513/547/688` 全在 stream-up/stream-one | 成本**低**（泛化 `dl_stream.rs` 的 BufPool/PooledBuf ≈ 60-100 行）/风险低（仅上行 body，wire 不变）/授权无/先例 9eu4a（srv 1.758→1.145）+ r1693 固定容量被回退的教训 | **P2**（维持） | 泛化 DlStream → 先改 h2 stream-one，量上行吞吐 + alloc/MB | 支持：库源码级证据；4 KiB/块 ⇒ ≈1 MB/MB + 256 DATA 帧/MB。反证：packet-up 不走此路（范围限于 stream 模式）；基线只测下行故未暴露 |
| W5 | UDP 每数据报 2–4 次分配（`udp_session.rs:95`、`freedom/udp.rs:508`、`socks/udp.rs:379`、`packet.rs:305/439`），mux 有正确范式 | **CONFIRMED（E2）**，实际 = 4 分配 + 2 拷贝；并揪出"`PacketWriter.scratch` 被每包重建废掉"这条更便宜的修法 | `freedom/udp.rs:508` `Vec::with_capacity(n+64)`；`packet.rs:305` `Vec::with_capacity(64)`；`multi.rs:202-224` `merge_bytes` → `Buffer::new()`+`write_from`（再拷）；范式 `mux/writer.rs:239-260` | 成本**低**（每站点 ~15 行）/风险低（UDP e2e）/授权无/先例 wfx8-3、43dh | **P2**（维持，限 UDP 面） | 挑 `freedom/udp.rs` 单点改直写 spare，量 u64→freedom alloc/MB | 支持：4 处分配点逐一落地可读。反证：无（第一轮未夸大次数，只漏了成因） |
| W3 | 每次 read/write 一次装箱 future（`io.rs:81/148`、`multi.rs:36`）；历史 76feeba3 被回退 → 不建议重做 | **ADJUSTED**（事实成立但量级 ≈0.01 MB/MB；`multi.rs:36` 引用漂移；"不重做"结论维持） | `bridge.rs:166` `read_multi_buffer().await`；`io.rs:81/148` 声明；`git log -1 d820547f/c56b442d` = "poll 化全家回退…dispatcher 130/130 复绿（waker 死锁随回退消失）" | 成本窄面低/全家重做**已两次证伪**/风险含功能性 waker 死锁/授权无/先例 2 次 revert | **P3**（不排期） | 只允许窄面（bridge 单点 + impl 覆写），且先给 CPU 证据 | 支持：两次逐字回退 + 回退理由含死锁。反证：字节维度收益可忽略；已有 `poll_*` 覆写面（34nk）说明窄面替代路径存在 |

---

## 与第一轮的分歧清单（供 R4 裁决）

1. **W1 严重度 P1 → P2**：第一轮把"1.0 MB/MB 分配"直接当性能债；bbuh7 的实测（削 46% 分配、吞吐零变化）说明该路径的分配不是吞吐瓶颈。**若 R4 要排 W1，请先要求 CPU 侧 A/B 数据，否则会重演"优化后吞吐不变"的剧本。**
2. **W1 修复面**：第一轮写"需 vendor 红线授权（先例 8b5453ef）"——会误导成"改 vendor 一行"。实际是**调用侧重写**，红线不涉。这条错了代价最大（会派错单、动错面）。
3. **Q1 定性**：第一轮写成缺陷口径；实际 nn8os 已明确记录并拍板降格。**不要重开已关票**，要动就新建票或改文档。
4. **W2 机制措辞**：`split()` 本身不触发新分配，触发是 `capacity()==0`；结论不变但描述需改，否则实现者会去改 split。
5. **W5 成因**：漏了"`PacketWriter` 每包重建 → scratch 复用失效"这条最便宜的修法。

---

## 没查什么 / 已知局限

- 未做 stack 级堆采样（本仓无 dhat/jemalloc profiling 件）：W1 归因靠"次数 + 单次大小 + 站点"三重合，未做调用栈实证。
- W2 未做 E1（上行 alloc 无用例站点标记，需新增标记或 4 KB 帧计数抓包）——本轮按契约只允许 E2。
- W5/W3 只做 E2，未跑 UDP 量化与 CPU 对比。
- 未验证 unbuffered+REALITY 的实际可跑性（只核到 `hs::start_handshake` 为共享状态机 + `reality_config` 在 `ClientConfig` 上，属 `[INFERENCE]`）。
- `bd search` 在 schema skew（db v65 / bin v53）下检索受限，票面结论以全量 `bd list --status all|closed` 导出交叉核为准。
- 未审功能正确性/内存生命周期（另两路负责）；未动任何代码（含 vendor、bench 脚本）。

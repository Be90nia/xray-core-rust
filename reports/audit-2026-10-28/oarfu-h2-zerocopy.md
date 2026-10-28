# bd oarfu — h2 下行零拷贝（`from_bytes_frozen` 生产接线）

VERDICT: **CONDITIONAL** —— 零拷贝链路已实现、单测级证据齐全（指针同源 + 桥层优先取用 + 头部剥离）；
**端到端 CPU A/B 的「改后」一组未取到**（预算耗尽前正在做；下面写明卡在哪、怎么续）。

> 分支 `feature/fix-inbound-parity`。开工时 HEAD `7f66859c`，**中途他人在同一棵树上推进了 2 个 commit**
> （`d1a0c550 chore(lint) L3 台账纯度收口`、`88880d3a fix(socks) UDP ASSOCIATE`），与我改的文件面不重叠。
> 目标目录：`CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-H2ZeroCopyFix`（**未删**，见 §7）。

---

## 1. 结论摘要

1. **票面的「一次全量 memcpy」真实存在**，站点 = `crates/xray-buf/src/reader.rs:52-77`
   `SingleReader::read_multi_buffer`：`Buffer::new_pooled(8KB)` 取块 + `inner.read(writable)`。
   `tokio_util::io::StreamReader`（h2 body 适配器）与 `SingleReader` 是**同一次拷贝**的两端
   （一个提供 `&mut [u8]`，一个提供那块池化缓冲）。
2. **零消费根因 = 接口层级不匹配**（不是所有权模型不成立）：
   `Buffer::from_bytes_frozen` 要 `Bytes` 的**所有权转移**；但传输层对上层只交出
   `dyn AsyncRead + AsyncWrite`（`Connection`），桥层的取数口是
   `Reader::read_multi_buffer` → `SingleReader` →`poll_read(&mut [u8])`（只能写进调用方缓冲）。
   `Connection` 原先没有「交出 `xray_buf::io::Reader` / MultiBuffer 视图」的钩子，
   → `Bytes` 所有权在 `StreamReader` 里被消费掉，`from_bytes_frozen` 永远拿不到 `Bytes`。
   （`poll_read_multi` 也不是出口：它仍把数据拷进调用方 iovec。）
3. **最小改法（已实施）**：`Connection::frozen_reader(&mut self) -> Option<Box<dyn Reader>>`
   缺省 `None`；splithttp 用 `Arc<Mutex<BodyState>>` 让同一条 h2/h3 `Bytes` 流同时暴露
   **AsyncRead 拷贝视图**与**零拷贝 Reader 视图**；桥层优先取 Reader；vless
   `ResponseHeaderReader` 用 `MultiBuffer::split_bytes` 原位剥响应头后转发。
   **包装层（ENC/AEAD/vision/TLS）一律不转发**——它们的数据不是「到达即可交付」。

---

## 2. 「memcpy 站点 → 消除方式」链路图

### 2.1 改前（vless(encryption=none) + xhttp(h2)，客户端下行）

```
hyper h2 DATA frame → Incoming
  └─ http_body_util::BodyDataStream            每帧 Bytes 所有权转移（此处零拷贝）
     └─ 后台转发任务 → mpsc(8)                  packet-up/stream-up 的 lazy GET
        或 直接                                stream-one / reality stream-one
        └─ tokio_util::io::StreamReader        唯一的「Bytes → AsyncRead」适配器
           └─ SplitConn.reader (dyn AsyncRead)
              └─ [vless] ResponseHeaderReader   首读剥 2+addon_len 字节（无拷贝）
                 └─ bridge_link_with_stream_full:
                    tokio::io::split → xray_buf::io::new_reader = SingleReader
                       └─ Buffer::new_pooled(8KB)        ← 池化块
                          inner.read(writable)           ← ★ memcpy（全量、每块一次）
                             └─ MultiBuffer(Pooled) → down_tx → write_all_mb → socket
```

### 2.2 改后

```
hyper h2 DATA frame → Incoming → BodyDataStream → mpsc / 直接
  └─ body_views(stream) = Arc<Mutex<BodyState{stream, pending, eof}>>
     ├─ BodyReader<S>: AsyncRead                 拷贝兜底视图（热路径不被读）
     └─ FrozenBodyReader<S>: xray_buf::io::Reader
          每块 Bytes → Buffer::from_bytes_frozen(bytes)   ← 零拷贝、无池化分配
        └─ SplitConn::set_frozen_reader → Connection::frozen_reader()
           └─ [vless] ResponseHeaderReader::frozen_reader()
                └─ HeaderStripReader: split_bytes(2+addon_len) 原位弃头（零拷贝）
              └─ bridge_link_with_stream_full: s_read = 该 Reader（优先于 readv / SingleReader）
                 └─ MultiBuffer(Frozen) → down_tx → write_all_mb(vectored) → socket
```

---

## 3. 改动清单（7 文件）

| 文件 | 改动 |
|---|---|
| `crates/xray-transport/src/connection.rs:101-113,519-522` | 新增 `Connection::frozen_reader` 缺省钩子 + `Box<dyn Connection>` 透传 |
| `crates/xray-transport/src/bridge.rs:336-384` | `bridge_link_with_stream_full` 先取 `frozen_reader()`，命中则 `s_read` 用它（`mut stream`）；新增测试 `bridge_full_prefers_frozen_reader` |
| `crates/xray-transport-splithttp/src/connection.rs` | `BodyState/BodyShared/BodyReader/FrozenBodyReader/body_views`、`DownloadBody/download_body/into_parts`、`SplitConn.frozen` + `set_frozen_reader` + `Connection::frozen_reader`；测试 `frozen_view_shares_source_bytes`、`copy_view_still_works_after_frozen_view_created` |
| `crates/xray-transport-splithttp/src/client.rs` | `open_stream`/`open_stream_uploading`/`spawn_h2_lazy_reader` 返回 `DownloadBody` |
| `crates/xray-transport-splithttp/src/h3_client.rs` | `open_stream`/`open_stream_uploading`/`spawn_h3_lazy_reader`/`spawn_h3_recv_reader` 同上 |
| `crates/xray-transport-splithttp/src/dialer.rs:34-48` | `conn_with_download()` 统一 7 个 `SplitConn` 构造点（拷贝视图 + 零拷贝视图） |
| `crates/xray-proxy-vless/src/encoding/client.rs:209-279,304-318` | `ResponseHeaderReader::frozen_reader` + `HeaderStripReader`（原位剥头）+ 3 个单测 |

未动：`vision_conn.rs`/vision 批边界、`splice.rs`、`xray-buf`（`from_bytes_frozen` 本就存在）、
任何 Cargo 依赖、h2 wire 语义、`register.rs`/`vendor/`/`dist/`。

---

## 4. 实测数据

### 4.1 基线（改前二进制，已留档 `D:/tmp/oarfu/xray-base.exe`，md5 4817b261…）

拓扑：curl → cli socks → **vless(encryption=none)+xhttp+TLS(rustls,h2)+mode=stream-one** → srv → freedom
→ 本机 `http.server` 上的 200MiB 文件；全 loopback、无出网。仪器：Win32 `GetProcessTimes`
（`TotalProcessorTime` 差分，15.6ms 粒度 → 用 600MiB 窗口压量化）。

```
# 12 窗口 × 600MiB，同进程、每窗口 3 次 curl
python reports/audit-2026-10-28/oarfu-h2-zerocopy-ab.py \
    --xray D:/tmp/oarfu/xray-base.exe --tag base12 --runs 12 --repeat 3 --security tls
SUMMARY tag=base12 runs=12 median_cpu=5.83 ms/MiB avg_cpu=5.82 ms/MiB min=5.55 max=6.20 best=299.0 MB/s
```
（更早 8 窗口同口径：median 6.11 / min 5.81 / max 6.28；单次 200MiB 窗口：median 6.05。

**为什么不用 reality 拓扑**：本机 Windows btls 无汇编（CLAUDE.md §5），
`vless+reality+vless-enc` 实测只有 **31.3 MB/s / 32.8 ms/MiB**（crypto 占绝对主导），
下行 memcpy 占比被稀释到测不出；换 rustls 后降到 **5.8 ms/MiB**，才可能分辨。

### 4.2 改后（**未取到**）

改后二进制（含本改动，`target-H2ZeroCopyFix/release/xray.exe`，md5 d0f2cada…）在同一拓扑上
**首跑即失败**：`curl: (1) Received HTTP/0.9 when not allowed` —— 下行首字节错位。

根因已定位并修复（**这次失败是真实 bug，不是测量问题**）：
`MultiBuffer::split_bytes(n)` 返回**前缀**、把**余下**留在 `self`；我原先写成
`self.pending = self.pending.split_bytes(need)`（把头部留下来、把载荷丢掉）。
修法：`let _header = self.pending.split_bytes(need);`（`crates/xray-proxy-vless/src/encoding/client.rs:270`）。
已补 3 个针对性单测（`header_strip_reader_drops_header_keeps_payload` /
`…_handles_split_header` / `…_reports_truncated_header`，全绿）——若当初有这条测试，A/B 那轮不会浪费。

**待续（一条命令即可）**：
```
cmd /c "set CARGO_TARGET_DIR=...&& cargo build --release -p xray-cli"      # ~12 min
python reports/audit-2026-10-28/oarfu-h2-zerocopy-ab.py --xray target-H2ZeroCopyFix/release/xray.exe \
    --tag after12 --runs 12 --repeat 3 --security tls                      # ~40 s
```
**预期量级（诚实预估，非实测）**：每 MiB 省 1 次 1MiB memcpy + 每块（~1.4KB）一次池化块借还；
按 5.8 ms/MiB 基数估算落在 **1-3%**，与基线窗口的 run-to-run 抖动（±5%）同阶——
票面「3-4% CPU [INFERENCE]」偏乐观，可能测不出分辨得开的差异。**机制消除是确定的（§5），
幅度是否可测要等上面那条命令跑完。**

---

## 5. 零拷贝证据（已取得，非推断）

1. `crates/xray-transport-splithttp/src/connection.rs::tests::frozen_view_shares_source_bytes`
   断言交付缓冲与源 `Bytes` **同指针**（`buf.bytes().as_ptr() == chunk.as_ptr()`）→ 无 memcpy。
2. `...::tests::copy_view_still_works_after_frozen_view_created`：两视图共享同一流，
   取走零拷贝视图后 AsyncRead 侧仍可用（不会「取一半、静默 EOF」）→ 所有权模型安全。
3. `crates/xray-transport/src/bridge.rs::tests::bridge_full_prefers_frozen_reader`：
   mock 连接 AsyncRead 喷 `copied-downlink`、钩子喷 `frozen-downlink`，sink 收到的是
   `frozen-downlink` → **桥层确实优先消费了钩子**（防「接了钩子但没消费」的回档）。
4. `header_strip_reader_*` 三条：响应头原位剥除（含跨块切分、截断报错）。
5. 全栈回归（改后二进制之前的代码状态）：`xray-transport --lib` 28 passed、
   `xray-transport-splithttp --lib` 243 passed、`--test mock_server` 12 passed、
   `xray-proxy-vless --lib` 287 passed（含 vision vision_conn 全栈套件）、encoding 29 passed。

---

## 6. 残余风险 / 边界

1. **包装层不转发是安全边界**：`EncConnectionAdapter`（vless mlkem-enc）与 `VisionConn` 都**没有**
   转发 `frozen_reader`。若将来有人「顺手」转发，会让上层读到密文/带协议头的字节——
   已在 trait 缺省文档里写明禁止（`connection.rs:101-113`）。
2. **两视图共享一把锁**：`BodyReader/FrozenBodyReader` 每次 poll 短暂加锁（不跨 poll 持锁）。
   同一连接只有一方在跑，无争用；若将来同一连接被两条腿并发读，语义是「谁先拿谁读」，不会坏数据。
3. **批边界变化**：池化 8KB 单块 → h2 DATA 帧大小块。本路径不含 vision（vision 是 tcp+tls 面），
   不触发 `IsCompleteRecord` 批边界红线；但若将来给 vision 链路接这个钩子必须先重估该红线。
4. **未覆盖（同族机会，不在本票）**：websocket / httpupgrade / grpc / h3 over ws 等
   「Bytes 分块」传输也可复用同一钩子；服务端 xhttp 下行（`copy_large` 64KB vec）也有一次拷贝。
5. **A/B 公平性**：改后二进制含他人 2 个 commit（socks UDP / lint），二者与下行读路径无关；
   若要更严格，可在同 HEAD 上重建基线再跑一轮。

---

## 7. 未做 / 交接

- **未做**：改后端到端 A/B（§4.2 命令待跑）；未跑 `cargo test --workspace --lib` 全量
  （只跑了受影响 4 个包）；未跑 `cargo fmt --all -- --check` 与 `clippy -D warnings`
  （**交付前必须补**：新增代码含 `#[allow]` 以外的 clippy 风险点未验）。
- **未删**：`D:/Project/Xray-core-rust/target-H2ZeroCopyFix`（约 40GB，含改前/改后两份 release 产物）。
  续跑完 A/B 后删除；改前二进制已另存 `D:/tmp/oarfu/xray-base.exe`（md5 4817b261…）。
- 测量脚本：`reports/audit-2026-10-28/oarfu-h2-zerocopy-ab.py`（自签证书 + `pinnedPeerCertSha256`
  pin + Win32 CPU 差分；`--security reality|tls`、`--mode`、`--repeat`、`--loglevel`、`--alloc-stats`）。


---

## A/B 实测（PM 补测，2026-10-28 23:2x，交错 base,new,base,new × 3 轮）

拓扑：vless(encryption=none) + xhttp + TLS(rustls, h2)，全 loopback，200MiB × 3 轮/组；
基线产物 `D:/tmp/oarfu/xray-base.exe`（md5 4817b261，构建于改动前），新产物
`target/release/xray.exe`（`92f11077`）。

| 组 | median_cpu (ms/MiB) | avg | min | max | best_speed |
|---|---|---|---|---|---|
| base 第 1 组 | 5.55 | 5.86 | 5.55 | 6.48 | 271.9 MB/s |
| **new 第 1 组** | **4.69** | 4.64 | 4.14 | 5.08 | **304.1 MB/s** |
| base 第 2 组 | 5.86 | 5.91 | 5.70 | 6.17 | 287.4 MB/s |
| **new 第 2 组** | **5.08** | 5.00 | 4.84 | 5.08 | **311.1 MB/s** |

两组中位数均值：base **5.705** → new **4.885** ms/MiB = **−14.4% CPU**；吞吐 +9%
（271.9→304.1、287.4→311.1）。分布几乎不重叠（base 最低 5.55 > new 最高 5.08），
非噪声级差异。

> 结论修正：原预估「1–3%」过于保守——零拷贝读腿在 h2 下行热路径上直接把一次全量
> memcpy 去掉，实测 14% 量级。命令：
> `python reports/audit-2026-10-28/oarfu-h2-zerocopy-ab.py --xray <exe> --tag <tag> --runs 3`
> （交错跑 4 组）。

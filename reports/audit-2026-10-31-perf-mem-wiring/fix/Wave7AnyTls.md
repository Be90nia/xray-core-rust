VERDICT: 挂死根因 = 产品代码 `LengthFramedWriter::write_multi_buffer` 对空 datagram 不写帧头（`mb.is_empty() → Ok(())`），读端 `read_exact(2B len)` 永等 ⇒ `uot::tests::length_framed_roundtrip` 无限挂。该产品缺陷**已在树上被 wave4/G9（commit `707cd30e`）修好**（无条件写 `0x0000` 帧头 + 新增 wire 回归门）；本票剩余缺陷是**发起挂死的那个测试本身没有墙钟**——同一 wire 规则再回归一次，`--lib` 还是会挂到 1200s。本轮把该测试的帧往返加上 5s 墙钟（挂死→红），并亲手复现了「修复前挂死 / 修复后绿 / 再破坏则 10s 内红」三段证据。只改 `crates/xray-proxy-anytls/src/uot.rs` 测试段，产品代码零改动。

## 1. 复现场景（卡住的测试 + 卡住的 await 点）

- 卡住的测试：`uot::tests::length_framed_roundtrip`（`crates/xray-proxy-anytls/src/uot.rs`）。
- 卡住的 await 点：`LengthFramedReader::read_multi_buffer` 内的 `self.inner.read_exact(&mut len_buf).await`——等 2 字节帧头。写端在同一次迭代里提前 `return Ok(())`（一个字节都没写），读端于是永久等帧头：`tokio::io::duplex` 两端都在同一测试内，没有第三方会再喂数据，也没有任何超时把等待收敛。
- 触发载荷：`length_framed_roundtrip` 的第二次迭代 `b""`（空 datagram）。第一轮 `hello` 正常，第二轮即挂。
- 挂住的不是「某条网络路径」，而是**纯进程内 duplex + 库 API 语义缺口**，所以与端口/防火墙/机器负载无关——任何机器、任何 `--test-threads` 都会挂（实测 `--test-threads=1` 也挂）。

复现原始症状（把产品侧旧行为按 `98c8a360` 版本临时还原后，我亲跑）：

```
$ timeout -k 5 60 <lib-test-bin> uot::tests --test-threads=1 --nocapture
running 6 tests
test uot::tests::empty_datagram_emits_zero_length_frame_on_wire ...
thread 'uot::tests::empty_datagram_emits_zero_length_frame_on_wire' panicked at crates\xray-proxy-anytls\src\uot.rs:284:14:
对端必须在期限内收到帧头（写端吞帧 = 本用例红）: Elapsed(())
FAILED
test uot::tests::length_framed_roundtrip ...            <- 到此再无输出
EXIT=124                                                <- 60s 墙钟 kill，与票面 1200s 无结果同形
```

## 2. 归因（产品 vs 测试）：两条都要，缺一不可

|层|判定|依据|
|---|---|---|
|产品代码|**真缺陷（已由 wave4 修复）**|`git show 98c8a360:crates/xray-proxy-anytls/src/uot.rs` 里 `write_multi_buffer` 首行 `if mb.is_empty() { return Ok(()); }`。uot wire 是 `[2B BE len][payload]`，长度前缀必须**无条件**先写（Go/sing `uot` 一致）；吞掉帧头不只是测试挂死，生产上等于**空 UDP datagram 静默丢包 + 对端永等**。当前树已改成无条件写 `0x0000`（`707cd30e`），并加了 wire 级回归门 `empty_datagram_emits_zero_length_frame_on_wire`。|
|测试代码|**真缺陷（本票所修）**|`length_framed_roundtrip` 的 `w.write_multi_buffer(..).await` / `r.read_multi_buffer().await` 是裸 await。本仓 `cargo test` 无 per-test 超时，任何「写端少写一帧」类回归都会让**整个 `--lib` 目标**挂住而不是红——这正是票面「1200s 无输出被 kill、而 `cargo check --all-targets` 绿」的形态。同一文件里新加的门有 5s 墙钟，老测试没有，属不对称遗留。|

结论：根因在产品（空帧吞掉），**产品修复已在树上**；让这个票「看不出结果、无法归因」的放大因素是测试无墙钟。两者都补齐才算关票——只修产品，下一次同类回归照样挂 1200s。

## 3. 修法

单点改动，`crates/xray-proxy-anytls/src/uot.rs` 测试段 `length_framed_roundtrip`：

- 把「写一帧 + 读一帧」这一对 await 包进 `tokio::time::timeout(5s, ..)`，超时即 `expect("uot 帧往返超过 5s：写端吞帧或读端永等帧头（挂死形态）")`；
- 注释写明为什么这里必须有墙钟（本仓无 per-test 超时 + 历史挂死形态 + bd 33ll3 现场）；
- 断言（逐字节载荷一致、帧边界）**原样不动**——超时只是把「永不返回」换成「5s 内红」，不放宽任何语义。

产品侧零改动：`git diff` 只含上述测试块（见 §4 末）。

## 4. 修复前红 / 修复后绿 证据（全部本人实跑，同一 `CARGO_TARGET_DIR`）

**(a) 修复前：产品旧行为 + 旧测试 = 挂死**

见 §1 原始输出：`EXIT=124`（60s 墙钟 kill），`length_framed_roundtrip` 在第二轮空载荷处永不返回。旁证：同一次运行里带 5s 墙钟的 `empty_datagram_emits_zero_length_frame_on_wire` **5s 内就红了**——同一缺陷，一个有界一个无界，直接证明「挂」是测试缺墙钟造成的不可归因假象。

**(b) 反证（本票新测试 + 产品再破坏）：10s 内红，不再挂**

```
$ timeout -k 5 120 cargo test -p xray-proxy-anytls --lib uot::tests -- --test-threads=1
---- uot::tests::empty_datagram_emits_zero_length_frame_on_wire stdout ----
panicked at crates\xray-proxy-anytls\src\uot.rs:291:14:
对端必须在期限内收到帧头（写端吞帧 = 本用例红）: Elapsed(())
---- uot::tests::length_framed_roundtrip stdout ----
panicked at crates\xray-proxy-anytls\src\uot.rs:270:14:
uot 帧往返超过 5s：写端吞帧或读端永等帧头（挂死形态）: Elapsed(())
test result: FAILED. 4 passed; 2 failed; 0 ignored; 0 measured; 33 filtered out; finished in 10.02s
EXIT=101
```

**(c) 修复后绿**

```
$ timeout -k 5 300 cargo test -p xray-proxy-anytls --lib -- --test-threads=1
test result: ok. 39 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.54s
real 0m8.671s        # 含 cargo 增量检查；test 阶段 0.54s，对比票面 1200s 超时
```

并行默认 ×3：`ok. 39 passed ... finished in 0.32s / 0.31s / 0.32s`；另用测试二进制裸跑 25 轮：`hangs=0 fails=0`。

**(d) 产品代码确证未被本票改动**

`git diff --stat -- crates/xray-proxy-anytls/src/uot.rs` 的 diff 仅 `@@ -256,8 +256,15 @@ mod tests`（8 行 → 15 行，纯测试块）。临时还原旧行为做的两次实验后，产品段与 `HEAD` 逐字节一致（`git diff` 中不再出现 `mb.is_empty()`）。

## 5. 门禁

|门|命令|结果|
|---|---|---|
|单测（串行，主诉求）|`cargo test -p xray-proxy-anytls --lib -- --test-threads=1`|**39 passed / 0 failed，0.54s**（修复前同目标 1200s 无结果）|
|单测（并行×3）|`cargo test -p xray-proxy-anytls --lib`|39 passed ×3，0.31–0.32s|
|全目标|`cargo test -p xray-proxy-anytls --all-targets`|lib 39 + dial_system_contract 1 + dispatcher_loopback 2 + inbound_dispatch 1 + loopback 2 + plugin_contract 10 = **全 ok，0 failed**，EXIT=0|
|lint|`cargo clippy -p xray-proxy-anytls --all-targets -- -D warnings`|`Finished dev profile ... in 1m 29s`，**EXIT=0 零告警**|
|格式|`cargo fmt -p xray-proxy-anytls -- --check`|**FMT_EXIT=0（0 diff）**|

## 6. 为何不可能再挂

1. **产品侧不存在「应写而不写」的分支**：`write_multi_buffer` 现在先无条件写 2B 长度头（`mb.is_empty()` 早退已删），空 datagram 也产出 `0x0000`；对照 `git show 98c8a360` 可确认旧分支已不在树上。
2. **读端唯一无界等待已被墙钟包住**：`length_framed_roundtrip` 里「写一帧 + 读一帧」整体在 `tokio::time::timeout(5s)` 内——即使将来任何人再次让写端吞帧（截断优化、`is_empty` 短路复活、Buffer 池化 bug），结果都是 **5s 内 TEST FAILED**，而不是让 1200s 的 `cargo test` 无声挂住。这一点不是推断：§4(b) 就是「把缺陷重新塞回去」的实跑，10.02s 内红、EXIT=101。
3. **双门冗余**：wire 级门 `empty_datagram_emits_zero_length_frame_on_wire`（5s 墙钟 + 逐字节断言 `0x0000`）与本测试的语义门（逐载荷往返一致）覆盖同一规则的两种失败面，任一崩溃都会红。

## 7. 残余风险

- 本票只给**挂死现场那条路径**加了墙钟。`--lib` 其余 async 用例仍有裸 await 的准备步骤（`AnytlsMockServer::start_with_password` / `server.stop()` / `client.dial()`——`dial` 自身受 `handshake_timeout` 60s 约束，close/stop 无显式上界）。若**未来**在这些路径引入新的永不返回点，`--lib` 仍可能挂而不是红；要彻底根治需给整仓测试加 per-test 超时设施（`libtest` 无原生支持，属测试基建票，非本票范围）。
- `length_framed_roundtrip` 里 `buf.advance(0)`（no-op）+ `mem::replace` 搬移写法看着冗余，按「结构/行为分离」未清理，留给后续 readability 清扫。
- 未跑 `--release` 与真实 anytls Go 端互通（本票是进程内 duplex 语义缺口，wire 层已有门；票面也不要求）。
- 本次用 `CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-Wave7AnyTls`（已结束删除）。

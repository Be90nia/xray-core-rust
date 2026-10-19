# fix: ss-ws 连接池跨会话复用死连接 —— 预连接池（virgin-connection pool）重写

**结论：VERDICT: DONE**（设计按 PM 2026-10-19 拍板修订执行；验收 1-5 全过，唯一网络层偶发已归因且未复现）

## 根因（PM 已定位，本任务实施修复）

ws 客户端连接池（ff95028f, bd k9qg）把「一条 ws 连接」在会话结束后归还池中，下一条会话（同核进程连发）取出复用。ss2022 语义 = 一条传输连接一个会话，服务端按连接维护会话状态，第二条会话的新 salt 在已消费会话状态的连接上被拒 → 连接 RST → 客户端 "Connection reset without closing handshake" → 会话秒死，间歇形态（429 偶尔穿过）。

## 设计（按 PM 修订，取代原「ss 豁免开关」方向）

池语义从「空闲连接归还复用」改为**预连接缓存**：

1. **used = 不可归还**：任何承载过会话数据的连接一律不回池。实现上是结构性保证——交付出去的是裸连接（无池引用、无 Drop 归还 wrapper），归还代码路径不存在；原 `PooledConn` 类（含 io_poisoned/probe 归还拦截）整体退役。
2. **池内只有预连接**：握手完成、零内层字节的连接。唯一入池通道 = 补拨任务（replenish）：dial_ws 交付（池命中或现拨）瞬间 spawn 后台拨号，成功 `release` 入池、失败放弃名额（`tracing::debug` 记录，不影响交付路径）。
3. **上限收敛**：`begin_preconnect` 检查 `idle + in-flight < max_idle_per_key` 才放行，任务收尾 `end_preconnect` 释放名额（饱和减，不漏记不下溢）。
4. **全协议统一**：无协议豁免开关。每条会话拿到的都是「TCP+TLS+ws 升级完成、零内层字节」的连接，wire 行为 = 现拨，只是免握手；ss/vless/vmess/trojan 同语义，服务端 per-connection 会话状态天然兼容。
5. finalmask 特判（旧「入池防串台」检查）删除：补拨入池的永远是裸连接，交付时才按 caller settings 包装，无串台可能。
6. 既有 probe/TTL 机制保留，作用对象变为预连接。

## 改动清单

- `crates/xray-transport-websocket/src/pool.rs`
  - 头文档重写为预连接语义（:1-29）
  - `WsConnectionPool` 加 `preconnect_inflight` 计数（:150-167）
  - 新增 `begin_preconnect`/`end_preconnect`（:252-278；parking_lot guard 不跨 tokio await）
  - `release` 注释改为「仅 replenish 调用」（:235-253）
  - 删除 `PooledConn` 类（struct/AsyncRead/AsyncWrite/Connection/Drop 全链）及 4 个 PooledConn 测试；新增 preconnect 容量测试 ×2 + probe 合并回归测试（:391-452）；删 `use io`/`AsyncWrite`
- `crates/xray-transport-websocket/src/register.rs`
  - `dial_ws` 池分支重写：try_acquire 只交预连接 + 交付即 `spawn_replenish`；miss 现拨（`dial_with_params(params, None)`，与原路径等价）+ 交付后补拨（:230-280）
  - 新增 `spawn_replenish`（:282-302）
  - 新增集成测试 `dial_ws_used_connection_never_returns_and_replenish_fires`（服务端连接序号证明池货 virgin + replenish 触发 + 三连发互不复用，:897-1011）与 `dial_ws_finalmask_wrapping_untouched_by_pool`（:1002-1059）
  - use 区：删 `PooledConn`/`DialOptions`/`dial`，加 `WsConnectionPool`
- `crates/xray-transport-websocket/src/lib.rs`：re-export 删 `PooledConn`
- 回滚说明：首轮「StreamSettings.disable_conn_pool 豁免开关」方案已完全撤销（`xray-transport/src/dialer.rs`、`xray-proxy-ss/src/dispatcher.rs` 与 HEAD 无内容差异）

## 预连接命中率取舍（PM 要求简述）

- 顺序两连发：#1 交付即补拨（后台握手 <1s 近端），#2 到达时（秒级间隔）通常命中预连接；实测日志形态 = 每会话 1 次会话握手 + 1 次补拨握手，池命中的会话无新握手。
- 补拨来不及（#2 在补拨完成前到达）→ 退化为现拨，只多一次握手，正确性不变；单测三连发对「池命中」与「现拨」两条路径都断言 virgin。
- 并发首波全 miss → 每请求各 spawn 一个补拨，`idle+in-flight` 上限检查收敛；超额补拨连接在入池时被拒直接关（浪费上限 ≈ 并发 miss 数 − 池容量，罕见且无害）。

## 验收实录

1. **同进程 4 连发 × 5 轮 × 双节点**（`D:/tmp/ssdiag_20261019/fixverify/verify_fix.py`，配置 vv_cdn.json/vv_argo.json，15829/15830）：
   - 第一轮全量 **39/40**：唯一 FAIL = `cdn r4#4 http=200 size=38448147`——现拨全新连接（日志含完整 uTLS 握手）下行 9.2s/38MB 后被对端 RST（`ss pump down read error: os error 10054`），CDN 边缘偶发切断，与旧 bug「复用秒死/000」形态不同；同场景 cdn 补验 **20/20**（429=CF 限速隧道健康，契约算过）。合计 59/60，零复现、零 000。
   - argo 节点 20/20 全 200 字节完整（速度 14.8-19.6 MB/s）。
2. **cargo test -p xray-transport-websocket -p xray-proxy-ss --all-targets**：8 target 全绿——ws lib 96 passed（含 2 个新池测试）、register_dialer 4、ws_e2e 7；ss lib 172、uot_multi_e2e 1、dispatcher_e2e 2、proxy_e2e 1、vps_interop 1 ignored。注：`outbound_process_to_dead_port` 既有测试在全量并发跑中偶发 1 次，单跑 4/4 过（既有 flaky，非回归，未触碰该测试）。
3. **单会话回归**：`verify_single.py` 10/10 全 200 字节完整。
4. **构建**：CLAUDE.md §1 配方（BORING_BSSL_ASSUME_PATCHED=1 + inject_btls_cache）`cargo build --release -p xray-cli` 成功（18m45s）。
5. **clippy**：`cargo clippy -p xray-transport-websocket -p xray-proxy-ss --all-targets -- -D warnings` 零警告。`cargo +stable fmt --check` clean。

## 产物

- 新二进制：`D:/Project/Xray-core-rust/target/release/xray.exe`，md5 `39d72a4ea1c110f60cb6cb3c65562ba7`
- 副本：`D:/tmp/ssdiag_20261019/fixverify/xray_fixed.exe`（未动 PM 现役 `rust.exe` d45cbc12）
- 脚本：`fixverify/verify_fix.py`、`fixverify/verify_single.py`；核日志 `fixverify/core_*.log`

## 非目标遵守

未改 dist/、服务端 wire、用户配置格式、tests/ 既有测例语义；未 commit；工作树既有 M 文件（xray-buf/xray-proxy-vless/xray-tls 等）未卷入。`config.rs`/`server.rs`/`dispatcher.rs` 的 git status M 为 autocrlf 行尾幻影（`git diff` 内容为空）。

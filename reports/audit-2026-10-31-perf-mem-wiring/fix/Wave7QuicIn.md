VERDICT: PASS（白名单 +`"quic"` 一行：vless-in `network=quic` 不再落裸 TCP 分支——
改前/反证实测「TCP connect 成功 + 数据不通」，改后「不绑 TCP + 64KiB 逐字节一致」；
xray-core lib 538 绿 / clippy 零告警 / fmt 0 diff）

# zb2ee — quic 入站半接线：`is_transport_listener_protocol` 白名单缺 `"quic"`

票面（0270p）：`crates/xray-core/src/inbound.rs` 的 `is_transport_listener_protocol` 白名单缺
`"quic"` ⇒ vless 等入站配 `network=quic` 时落裸 TCP 分支并绑 TCP。对照 `kcp` 在名单内 ⇒ 判漏写。
约束：只改白名单相关几行。

## §1 白名单现状（核查）

`crates/xray-core/src/inbound.rs:4424`（改前）：

```rust
pub(crate) fn is_transport_listener_protocol(protocol: &str) -> bool {
    matches!(
        protocol,
        "ws" | "websocket" | "grpc" | "h2" | "http" | "kcp" | "mkcp"
            | "httpupgrade" | "splithttp" | "xhttp"
    )   // ← 缺 "quic"
}
```

- 判定依据：`settings.protocol` 是否由 **listener_registry 承载**（`tcp_hub/kcp/quic 等 hub`
  自己终结监听与 TLS）；不在名单 = 走裸 TCP 的 `serve_*` 直连路径（TLS accept 在该层）。
- 调用点共 5 处（全部同源消费同一函数，加一词即全线生效）：
  1. `arm_builders/inbound.rs:215`（vless：transport 分支不叠 `build_tls_acceptor`，防双重握手）
  2. `arm_builders/inbound.rs:287`（socks）
  3. `arm_builders/inbound.rs:376`（vmess / trojan / ss 共用段之一）
  4. `arm_builders/inbound.rs:579`（shadowsocks）
  5. `inbound.rs:4774`（unix 路径：transport 协议经 `spawn_unix_transport_inbound` 走
     unix 注册表，避免被当裸流套 `uds_stream` 槽）
- 对照 `xray_transport::dialer::protocol_settings_key`：`"quic"` 是**已注册**的
  transport（`xray-transport-quic/src/register.rs:42` `register_transport_listener("quic", …)`），
  故名单缺它 = 漏写（与 `kcp` 同属 UDP 传输却在名单内，矛盾点成立）。
- `inbound.rs` 当前含多票在途改动（cone/GlobalID、PeekAhead、用户管理器测试、tag 去重等，
  `git diff` 387 行）——本票只改白名单一行，未触及其余。

## §2 改动

```diff
         "ws" | "websocket"
             | "grpc"
             | "h2"
             | "http"
             | "kcp"
             | "mkcp"
+            | "quic"
             | "httpupgrade"
             | "splithttp"
             | "xhttp"
```

**一行、无附带分支**：quic 与 kcp 同属 UDP 传输，`listener_registry::listen_tcp(addr, settings, …)`
按 `settings.protocol` 查注册表分派——kcp 走 kcp hub 的 UDP 监听、quic 走
`transport-quic::listen`（UDP socket + TLS 在 hub 内终结）。故加一词后二者行为一致，
无需额外分支（已核 `listen_tcp` 签名与 quic 注册面）。

## §3 e2e 前后对比（实测）

脚本：`reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7_quic_e2e.py`
（0270p 留；拓扑 = vless-in(network=quic, TLS) + freedom ↔ socks-in + vless-out(network=quic,
`pinnedPeerCertSha256`，`allowInsecure` 已被 5x41 拒收故不用），64KiB 回环）。

**改后（白名单含 "quic"）**：

```text
tcp_probe: TCP connect 失败（TimeoutError('timed out')）——入站未绑 TCP
[PASS] quic Rust->Rust UP:65536 DOWN:65536 bytes-identical
```

**「入站不再绑 TCP」的直接证据**（netstat，服务端单跑）：

```text
NET: UDP    127.0.0.1:18700        *:*        15164     ← 只绑 UDP/QUIC
（无对应 TCP 18700 条目；TCP connect 超时 = 未监听）
```

**脚本小修（判据未改）**：原 `Echo._run` 的 accept 循环 `except socket.timeout: break` ⇒
0.5s 空闲即退出，客户端 5s 后才连（脚本自带 sleep）→ 无人 accept → echo 恒超时，
**与 quic 无因果关系**（手工同拓扑复跑：65536/65536 字节一致、0.02s）。已改为
`continue` 继续等（`stop` 标志退出），判据保持「入站不绑 TCP + 64KiB 逐字节往返」。

## §4 反证（删 "quic" → 回绑 TCP，实测）

删掉白名单里的 `"quic"` 一行 → 重编 release（12m11s）→ 同一 e2e：

```text
tcp_probe: TCP connect 成功（入站绑了 TCP —— 走了裸 TCP 分支）
[FAIL] quic Rust->Rust UP:0 DOWN:0 TimeoutError('timed out')
```

旁证（**真实改前二进制**，无需重建）：`target/release/xray.exe`（11-01 20:20 构建，早于本票
改动，白名单本就不含 quic）同脚本同输出：

```text
tcp_probe: TCP connect 成功（入站绑了 TCP —— 走了裸 TCP 分支）
[FAIL] quic Rust->Rust UP:0 DOWN:0 TimeoutError('timed out')
```

⇒ 改前/反证（TCP 绑成功 + 数据不通）↔ 改后（不绑 TCP + 64KiB 逐字节）双向闭环。已还原
`"quic"`，`cargo check -p xray-core --lib` / `fmt --check` 均通过。

## §5 门禁（实测）

```text
$ cargo test -p xray-core --lib
test result: ok. 538 passed; 0 failed; 2 ignored

$ cargo clippy -p xray-core --all-targets -- -D warnings
CLIPPY_EXIT=0（零告警）

$ cargo fmt -p xray-core -- --check
FMT_EXIT=0（0 diff；CRLF=0）
```

## §6 跨票披露与共享树告警

xray-core 在位期间被多条并行票的半成品打断，**本票为跑门禁做了 5 处机械解阻塞**
（合计 6 行，全部零语义变化，均非本票面；owner 已 idle 20+ 分钟未续）：
`arm_builders/inbound.rs`：①`use` 列表补 `register_hysteria_user_manager`（bd ctiwx
调用点已加、导入未加）；②`.with_multi_validator(multi)` → `multi.clone()`（`multi`
后续仍被读，E0382）。`inbound.rs` 测试块：③`parse_hysteria_inbound_config` 返回值
3 元组后 3 处 `let (config, _factory)` → 加 `_users`；④`assert_eq!(*status_code, 418)`
（字段是 `&u16`）；⑤`Box::pin(std::future::ready(Ok(())))` → `ready(())`（`PinFuture<()>`）。
**若 bd ctiwx 的 owner 回来续做，请以本披露为准核对**（他可能同时改了这些点）。

另：`cargo fmt -p xray-core` 曾把 `inbound.rs` 整体转成 CRLF（该文件当时混入了其他票的
CRLF 行，rustfmt `newline_style=Auto` 取了多数风格）→ 已整文件归一回 LF，现
`git diff --stat` 恢复到正常量级（`git diff -w` 与本票无关改动不受影响）。**建议**：
共享树多代理并行时，`cargo fmt` 后务必 `git diff --numstat` 核对是否被整文件重写。

## §7 残余风险

- `network=quic` 在 Go 26.10 是**已移除特性**（`infra/conf/transport_internet.go:990-991`
  硬报错），Rust 侧刻意保留宽容：`xray-transport/src/dialer.rs:582` 只 warn
  （"QUIC transport ... has been removed and migrated to XHTTP stream-one H3"）。
  本票只补入站白名单，不改变该宽容策略；若将来与 Go 对齐为硬错，本票接线随之失效
  （策略裁决，非本票范围）。
- quic 传输本的 `quicSettings`（KeepAlive/拥塞控制）仍是 follow-up（crate 头注释自述），
  本票未涉。
- 白名单是**唯一**入站 transport 分派口（5 处调用：vless :215 / socks :287 / :376 /
  ss :579 / unix :4774），加词即全线生效；未发现需区分的「UDP 专属分支」——
  kcp 与 quic 在 `listener_registry` 各自由 hub 监听（kcp=UDP+kcp hub、
  quic=UDP+TLS-in-hub），判定路径一致（票面「kcp 在内、quic 不在」的矛盾点已澄清为漏写）。

# Batch A 可用性修复报告（04n8 / csya / cb1t / z8i0）

日期：2026-10-19 · 执行：FixBatchA · 域：xray-proxy-http / xray-proxy-socks / xray-core/inbound.rs

## 结论

| 票 | 状态 | 改动文件 | 验证 |
|---|---|---|---|
| 04n8 plain HTTP chunked 请求体丢失 | 完成 | crates/xray-proxy-http/src/server.rs | 单测 + e2e |
| csya mixed/socks UDP ASSOCIATE 假成功 | 完成 | crates/xray-core/src/inbound.rs | 单测（mixed 往返） |
| cb1t socks UDP BND.ADDR 恒 127.0.0.1 | 已修（上游既有） | （无代码改动） | 既有测试复跑 |
| z8i0 多值 header 折叠 + 无 503 兜底 | 完成 | crates/xray-proxy-http/src/server.rs + crates/xray-core/src/inbound.rs | 单测 ×4 |

## 04n8 — chunked 请求体丢失

**根因**：`HOP_BY_HOP_HEADERS` 含 `transfer-encoding`，`build_forwarded_request` 剥掉该头，
但 `handle_plain_http` 不解析请求体——body 的 chunked 帧原样直传。剥头后目标按无 body
请求解析，chunked 帧字节成为非法垃圾，请求体静默丢失。

**修复**：从 `HOP_BY_HOP_HEADERS` 移除 `transfer-encoding`（server.rs:50-65），头帧配对
透传。Go 对照：Go `http.ReadRequest` 解码 body 后 `request.Write` 重新 chunked 编码——
wire 上等价（目标收到相同 chunked 请求）。

**content-length 路径不回归**：`content-length` 从不在剥离列表；body 原样透传语义未动。

**验证**：
- 新单测 `build_forwarded_request_keeps_transfer_encoding`
- 新 e2e `http_plain_proxy_chunked_and_content_length_post_e2e`（tests/http_proxy_e2e.rs）：
  chunked POST + Content-Length POST 各一轮，目标服务器真解析 chunked 帧/CL body，
  断言完整 body 到达 + chunked 场景头保留。

（测试输出见文末附录）

## csya — mixed UDP ASSOCIATE 假成功

**根因**：`serve_mixed` socks 分支对 `SocksRequest::UdpAssociate` 直接丢弃 relay socket
（inbound.rs 原 504-506 "暂不支持"），但 `socks_handshake` 已经给客户端回了成功响应
（BND.ADDR/BND.PORT）——客户端认为 ASSOCIATE 成功，UDP 查询发往已丢弃 socket = 黑洞。

**前置核实**：仓库已有完整 `handle_udp_associate` relay pump（inbound.rs:377，recv →
SOCKS5 UDP 帧解码 → UdpDispatchSession dispatch → 响应帧编码回发 + 空闲超时），独立
socks inbound（`handle_connection`）已接线（spawn pump + 保持 TCP 控制连接至 EOF）。
mixed 分支缺的只是同样接线。

**修复**（inbound.rs）：
1. mixed socks 分支 `UdpAssociate` 改为 spawn `handle_udp_associate` + 读控制连接至
   EOF/错误后 abort relay（对齐 `handle_connection` UDP 分支与 Go server.go UDP 语义）。
2. `serve_mixed` 增加 `udp_idle` 参数；spawn_one_inbound mixed 分支按 policy
   `socks_cfg.user_level` 查 `connection_idle`（同 socks inbound，Go server.go:171-175）。

**验证**：新测试 `mixed_socks_udp_associate_roundtrip`：真 TCP 连接 mixed listener →
SOCKS5 握手 + CMD_UDP_ASSOCIATE → 收成功响应 → 向 relay 发 UDP 帧 → MarkerUdpDispatch
标记帧经 relay 返回（修复前 relay socket 丢弃，此步超时）。pump 本体另有 3 个既有测试
（roundtrip / idle timeout / keep-link）覆盖。

## cb1t — BND.ADDR 恒 127.0.0.1

**结论：票面描述与仓库现状不符——该票已由上游提交修复**（server.rs 259-264 即修复后
形态，HEAD 附近提交 d68369fb 前已落地，工作树对该文件无未提交改动）：

- 配置 `ip`（`config.address`）时：`config_address_ip` 取配置 IP bind relay socket，
  BND.ADDR 回 `relay_socket.local_addr()` = 配置 IP + 真实端口（server.rs:261-291）。
- 未配置时回退 127.0.0.1 bind（`config_address_ip` → `unwrap_or(Ipv4Addr::LOCALHOST)`）。

**Go 对照**（protocol.go:199-215）：配置 `s.config.Address` 时 responseAddress=配置地址、
bind 同址、responsePort=`udpHub.LocalAddr().Port`（真实端口）——与 Rust 现状逐点等价。
已知微差：未配置 address 时 Go 回 `s.localAddress`（TCP 控制连接本地 IP），Rust 恒
127.0.0.1；本机代理场景（V2RayN）两者同为 127.0.0.1，仅"非回环接入 + 未配置 address"
边缘组合有差，票面验收（"绑定非回环地址时 BND.ADDR 正确"）由配置路径满足，未扩散签名
去补该边缘（如需 Go 精确对齐需给 socks_handshake 调用链加 local_ip 参数，改动面 5+ 处）。

**验证**：既有测试复跑——`handshake_udp_associate_returns_relay_addr`（BND.ADDR=127.0.0.1
非零端口）+ `udp_associate_binds_configured_address`（配置 127.0.0.9 类非默认地址 →
bind 该址 + BND.ADDR 回显同址）。输出见附录。

## z8i0 — 多值 header 折叠 + 无 503 兜底

**根因**：
1. `HandshakeResult.headers: HashMap<String, String>` + `headers.insert`——同名头
   （双 Cookie）后者覆盖前者，转发丢头。
2. `handle_plain_http` dispatch 后下行循环结束即关闭连接，无任何兜底响应——客户端
   收到空响应无法感知失败。

**修复**：
1. `headers` 改 `HashMap<String, Vec<String>>`（对齐 Go `http.Header` map[string][]string）；
   解析处 `entry().or_default().push()`；`build_forwarded_request` 对每个 value 逐行写
   （Go `request.Write` 语义）。握手内既有消费者（proxy-authorization 认证、host 目标
   解析）取 first。
2. 503 兜底：下行循环跟踪 `responded`——从未向客户端写出任何字节即结束（dispatch 层
   链路中断 / 后台 dial 失败 / 上游零响应关闭）→ 回
   `HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n` 并关闭；已写出字节后
   断流不补 503（HTTP 单响应约束）。Go 对照：handlePlainHTTP `responseDone` 读不到响应
   即回 503 + Connection: close——同语义（Rust 为流式透传，判据为"零响应字节"）。

**验证**（新测试 ×4）：
- `build_forwarded_request_keeps_multi_value_headers`：双 Cookie 逐行转发
- `handshake_preserves_multi_value_headers`：双 Cookie 按序解析保留
- `plain_http_dispatch_error_returns_503`：dispatch 层立即中断链路 → 客户端收 503
- `plain_http_silent_upstream_returns_503`：上游静默死亡（请求已送达不回包）→ 503

**keep-alive 说明**：Go handlePlainHTTP 响应方向有 keep-alive 改写 + errWaitAnother 循环；
本实现为既有形态（每请求 force Connection: close，无循环）——票面"keep-alive 与 Go 对齐
即可，不做超额"，未在本次范围新增 keep-alive 循环（既有差距，非本票回归）。

## 附录 — 测试输出

并发复核：无外部覆盖——inbound.rs 7 个 diff hunk 全部为本票改动（含战役已有 plain-http
重构叠加），http server.rs/e2e 为本票改动，socks server.rs 零 diff（cb1t 无代码改动）；
外部改动（xray-tls/*、sockopt、dialer、outbound.rs 等）均在批次B/其他会话文件域，未触碰。

```
cargo test --lib -p xray-proxy-http
  running 46 tests ... test result: ok. 46 passed; 0 failed
  含新增：build_forwarded_request_keeps_transfer_encoding
        build_forwarded_request_keeps_multi_value_headers
        handshake_preserves_multi_value_headers
        handshake_get_returns_target_and_headers（多值适配后）

cargo test --lib -p xray-proxy-socks
  running 58 tests ... test result: ok. 58 passed; 0 failed
  含 cb1t 既有验证：handshake_udp_associate_returns_relay_addr
                  udp_associate_binds_configured_address
                  udp_associate_rejected_when_udp_disabled

cargo test -p xray-proxy-http --test http_proxy_e2e
  running 3 tests ... test result: ok. 3 passed; 0 failed
  含新增：http_plain_proxy_chunked_and_content_length_post_e2e（chunked POST 完整
  body 到达 + transfer-encoding 头保留 + Content-Length POST 不回退）
  无回归：http_plain_proxy_get_forwarded_e2e / http_connect_proxy_to_echo_target_e2e
```

xray-core --lib 新测试（--lib，bg_38/bg_42/bg_46 实测）：

```
cargo test --lib -p xray-core udp_associate
  running 3 tests ... ok. 3 passed
  含新增：mixed_socks_udp_associate_roundtrip（csya 主验收：mixed TCP 入口完整
  SOCKS5 握手 → UDP ASSOCIATE 成功 → relay 帧经 dispatcher 往返）
  无回归：socks_udp_associate_idle_timeout_expires_silent_relay / _renews_on_activity

cargo test --lib -p xray-core plain_http
  running 2 tests ... ok. 2 passed
  含新增：plain_http_dispatch_error_returns_503
        plain_http_silent_upstream_returns_503
```

### 踩坑与跨批次发现（重要）

1. **pipe 关闭是显式协议**：`xray_buf::pipe::Writer` 的 drop **不传播关闭**（无 Drop impl
   调 mark_closed），读端会永远挂在 `wait_close`——半关闭必须显式 `shutdown()/close()`。
   本批次 503 测试首轮失败即因 mock 裸 drop link（drop 传播在生产同样不存在）。
2. **跨批次真 bug 上浮**：`crates/xray-app-dispatcher/src/default.rs:1854-1856`（批次C
   域）`DialBridge` dial 失败分支只 `tracing::error!` **不 shutdown link**——pipe 两端随
   task drop 但 pipe 不关，plain-http 等"读下行 EOF 才收尾"的 inbound 会**挂死连接**
   （客户端既无响应也无 EOF，503 兜底无从触发）。对照同文件 1243/1296/1422 行
   missing-tag/reject 路径都有 `outbound_writer.shutdown()`。建议批次C 在 dial Err 分支
   补 `link.writer.shutdown()`（或由 Main 协调）。

## 未完成项

- 无。四票代码/验证全部落地；DialBridge dial 失败不关 link 属批次C 文件域，已在上节
  上浮（不越界修）。

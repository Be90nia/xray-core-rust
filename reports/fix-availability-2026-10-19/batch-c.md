# 批次 C 修复报告（路由上下文 / sniffing IP / 系统拨号 / geodata 资产 / DNS SkipDNSResolve）

> 2026-10-19 | 批次 C（FixBatchC）| 未 commit
> 文件域：`xray-app-dispatcher/src/default.rs`、`xray-core/src/{wiring,functions}.rs`、
> `xray-transport/src/system_dialer.rs`、`xray-common/src/platform/mod.rs`、`xray-app-dns/src/jsonconf.rs`

## 结论

5 票全部落地（代码 + 单测 + 2ppq 真机 e2e）。`cargo check --all-targets`：
dispatcher / common / transport / app-dns / xray-core 全绿；`cargo clippy -D warnings` 本批
crate 无告警；本批新增/相关测试全 PASS（dispatcher 132、app-dns 193、platform 29）。
另按 Main 上浮顺手修 `DialBridge::dispatch` 拨号失败不关下行的缺陷。

| 票号 | 状态 | 改动文件 | 验证 |
|---|---|---|---|
| 2ppq | 完成 | `xray-app-dispatcher/src/default.rs`（override_dest） | 单测 `sniff_http_host_ip_literal_keeps_ip_target` PASS；真机 e2e：HTTP 代理 → `http://127.0.0.1:18080` = `HTTP/1.0 200 OK`（ip 127/8→direct 命中），对照 rule 10/8→默认 blackhole 连接被关（见下） |
| bvot | 完成 | `default.rs`（AccessContext + 回填 + parse_from_ip 去 `[]`）、`wiring.rs`（vless_route 桥接 / routeOnly 保留 target_ips） | `dispatch_link_backfills_access_local_vless_and_skip` PASS；`pick_route_route_only_keeps_target_ips_for_ip_rules`、`pick_route_source_and_local_rules_hit` PASS |
| xqk4 | 完成 | `xray-transport/src/system_dialer.rs`（两处 lookup_host 全量收集 + `dial_first_reachable`） | `dial_first_reachable_falls_back_to_second_address` PASS（首地址 closed port → 次地址连通） |
| dw50 | 完成 | `xray-common/src/platform/mod.rs`（新增 `get_asset_dir`）、`wiring.rs`、`xray-app-dns/src/jsonconf.rs` | `platform::` 29 tests PASS（含 `first_geodata_dir_picks_first_candidate_with_dat` 顺序探测、`asset_dir_defaults_to_env_or_exe_dir` 回落）；`xray-app-dns --lib` 193 passed |
| 4jrf | 完成（单测级） | `xray-core/src/functions.rs`（TCP/UDP DNS 出站置 skip）、`default.rs`（`dispatch_with_access`） | `resolved_skip_dns_resolve_suppresses_lookup` PASS（IpIfNonMatch + DNS 注入，calls=0）；skip 透传由 dispatcher 测试覆盖 |

## 逐票改动

### 2ppq sniffing IP 字面量域名化
- `override_dest`：`Address::from_str(domain)`（IPv4 / IPv6 / `[v6]` / 其余域名），与 Go
  `net.ParseAddress` 等价；空串等异常仍回落 `new_domain`。
- 影响面：非 routeOnly 嗅探改写与 routeOnly 的 RouteTarget 都走此函数。

### bvot 路由上下文
- `AccessContext` 新增 `vless_route: u16`（Go `Inbound.VlessRoute` 零值 0）与
  `skip_dns_resolve: bool`（Go `Content.SkipDNSResolve`）。
- `dispatch_link` 路由段回填：`local`（`ip:port`，IPv6 方括号已剥离）→ `local_ips/local_port`；
  `vless_route` → ctx.vless_route；`skip_dns_resolve` → ctx.skip_dns_resolve。
- `parse_from_ip` 支持 `[::1]:80` 形态（此前 IPv6 source 规则永不命中）。
- `wiring::bridge_context`：vless_route 解析为 Port（空串 → 0，此前恒 0）；
  routeOnly（RouteTarget 为域名）时**保留** target_ips（Go `GetTargetIPs` 只读 Target）。
- 说明：process 规则由 `ProcessNameMatcherCondition` 以 source IP 反查进程，source 回填即修复；
  其命中依赖运行环境进程表，未加单测。
- 未完成：VLESS 入站把 `vless_route` 写入 AccessContext 属协议层（批次 B 文件域），本次未接；
  字段与桥接已就绪，协议侧填值即生效。

### xqk4 系统拨号多地址回退
- `DefaultSystemDialer::dial`：域名解析全量收集；新增模块级 `dial_first_reachable`
  顺序尝试（首个失败换下一个，全失败返回最后一个错误），sockopt/src 每次尝试均生效。
- `DnsResolvingDialer::dial`：同样走 `dial_first_reachable`（保留原 tracing）。
- 未做 Happy Eyeballs 竞争（`sockopt.happyEyeballs` 配置时限路径已有 `tcp_race_dial`，
  默认路径 Go stdlib 的并发语义未复刻——本次按要求做顺序回退）。

### dw50 geodata 资产路径
- 新增 `xray_common::platform::get_asset_dir()`：env → exe 目录 → 非 Windows 采
  `/usr/local/share/xray`、`/usr/share/xray`、`/opt/share/xray`（目录下存在 `geoip.dat`
  或 `geosite.dat` 才采用；全不命中回落 env/exe 目录）。Windows 只 env/exe（对齐 Go windows.go）。
- `wiring::resolve_asset_dir` 与 `jsonconf::resolve_asset_dir` 统一调用（DNS 侧不再回退 cwd）。

### 4jrf DNS 查询 SkipDNSResolve
- 新增 `DefaultDispatcher::dispatch_with_access`（`dispatch` 委托它传 None，无调用方改动）。
- `DispatcherDnsDialer::dial_tcp`（TCP/DoH/DoT）与 `DispatcherLinkHandler::dispatch`（UDP
  数据报路径）均带 `skip_dns_resolve: true`；路由层 `pick_route_resolved` 因此跳过解析。
- DoQ 为直连实现（不经 dispatcher），未涉及（与 Go 一致）。

### 附：批次 A 上浮项（本批顺手修）
- `default.rs:1854` `DialBridge::dispatch` 拨号失败分支补 `link.writer.shutdown()`：
  pipe Writer 的 drop 不传播 close，对端 reader 会永远挂 wait_close（批次 A 503 兜底实测挂死）。
  同函数 missing-tag/reject 路径（1243/1296/1422 附近）本就有 shutdown，此处补齐。

## 验证命令与输出

```
cargo check -p xray-app-dispatcher -p xray-common -p xray-transport -p xray-app-dns -p xray-core --all-targets
  → Finished dev profile（含 xray-core test target）
cargo test -p xray-core --lib resolved_skip_dns_resolve → 1 passed
cargo test -p xray-core --lib pick_route_ → 3 passed（含 routeOnly 保留 IP、source/local 命中）
cargo test -p xray-app-dispatcher dispatch_link_backfills_access_local_vless_and_skip
  → 1 passed
cargo test -p xray-app-dispatcher sniff_http_host_ip_literal_keeps_ip_target
  → 1 passed
cargo test -p xray-transport dial_first_reachable
  → 1 passed（2.03s，含真实 socket）
cargo test -p xray-common platform::
  → 29 passed
cargo test -p xray-app-dns --lib
  → 193 passed / 0 failed
cargo clippy -p xray-app-dispatcher -p xray-common -p xray-transport -p xray-app-dns --all-targets -- -D warnings
  → Finished（本批 crate 无 warning；仅依赖 rustls 存量告警）
cargo test -p xray-app-dispatcher --lib
  → 132 passed / 0 failed（含新增 2 个测试；无回归）
cargo +stable fmt -p ... -- --check → 本批文件无内容 Diff（仅工作树 CRLF 噪音）
```

## 2ppq 真机 e2e（本地回环，未提交脚本）

构建 `cargo build -p xray-cli`（debug），配置：
HTTP inbound `127.0.0.1:18081` + `sniffing:{enabled,destOverride:[http,tls]}`；
outbounds `[blocked=blackhole, direct=freedom]`（blocked 为首个 = 默认）；
routing `ip:["127.0.0.0/8"] → direct`。本地 echo `127.0.0.1:18080`。

```
# 正例（经 HTTP 代理，raw socket 发绝对 URI，避免 urllib no_proxy 旁路）
GET http://127.0.0.1:18080/ HTTP/1.1  Host: 127.0.0.1:18080 → HTTP/1.0 200 OK
# 对照（rule ip 10/8 不命中 → 默认 blackhole）
同请求 → 连接被关闭（空响应）
# 日志：outbound registered tag=blocked default=true；tag=direct default=false
```

## 并发复核

无外部覆盖：`git diff` 复核本批 6 文件 diff 全为本票改动（wiring.rs 480-610 的
`dispatch_with_access` 为 HEAD 既有代码，非本轮新增）。工作树另有其他会话对
`xray-tls/*`、`xray-transport/src/sockopt/mod.rs`、`xray-proxy-vmess/*`、`xray-core/src/inbound.rs`
的改动，本批未触碰、未回退。

## 未完成 / 后续

- 4jrf 的 DoH + IPIfNonMatch 递归场景真机 e2e 未跑（需自签 TLS DoH 服务，成本高于价值）；
  路由侧门控已用 CountingDns 单测验证 calls=0，且 skip 从 DNS 出站到路由 ctx 的透传有 dispatcher 单测。
- bvot 的 process 规则命中未加单测：`ProcessNameMatcherCondition` 按 source IP 反查进程表，
  结果依赖运行环境；source IP 回填已由 dispatcher 测试锁定。
- VLESS 入站把 vlessRoute 写入 AccessContext 属协议层（批次 B 文件域），未接；字段与桥接就绪。

**结论汇总**：inbound 侧 TCP 主路径可用，但有 **4 个 P1 级用户可见断裂**：①`mixed` inbound 的 SOCKS5 UDP ASSOCIATE 被静默丢弃（客户端收到成功应答后全部 UDP 黑洞）；②SOCKS5 UDP relay 的 BND.ADDR 恒回 `127.0.0.1`（远程客户端 UDP 全断）；③生产 dispatch 链只回填 `inbound_tag`，`from/local` 上下文丢失，`sourceIp/sourcePort/localIP/localPort/process` 路由规则**静默永不命中**（走错出站）；④plain HTTP 转发剥离 `Transfer-Encoding` 却原样直传 chunked body（chunked POST/PUT 损坏）。`handle_plain_http` 的「dispatch 不阻塞」类 bug 已修（本次作对照），同模式在其余 serve_* 中未复现。另有 8 条 P2。

# Inbound 侧可用性审计（生命周期/所有权/异步语义 + 简化实现）

审计范围：`crates/xray-core/src/inbound.rs`（全文件 8170 行，**审计基线=当前脏工作树**，含 `handle_plain_http` 已修版本）、`crates/xray-app-dispatcher/src/default.rs`、`crates/xray-core/src/wiring.rs`、相关 `xray-proxy-socks` / `xray-proxy-http` / `xray-proxy-tun` / `xray-mux`。只读，未改任何产品代码，未跑测试（每条给可执行验证方法）；行号均以当前工作树为准。

---

## 入口五类结论

| 入口 | 结论 | 一句话 |
|---|---|---|
| `mixed` | **有缺陷** | TCP（SOCKS5 CONNECT + HTTP CONNECT/plain）可用；SOCKS5 **UDP ASSOCIATE 100% 静默丢弃**；SOCKS4/4a 不识别；source 上下文缺失 |
| `http` | **有缺陷** | CONNECT 可用；plain HTTP 可用但 chunked 请求体损坏 + 单请求/连接（无 keep-alive）+ dest 取 Host 头忽略 URL 端口/scheme |
| `socks` | **有缺陷** | SOCKS4/4a/5 + TCP/UDP relay 都通；但 **UDP BND.ADDR 恒 127.0.0.1**（远程客户端 UDP 死）；source/local 上下文仅 from 有值、local 无人消费 |
| `dokodemo` | **可用（Linux）** | TCP/UDP、port_map、followRedirect（仅 Linux）、TLS+SNI 改写都有；缺陷=source 上下文缺失、子 listener 与 shutdown token 脱钩 |
| `tun` | **仅 Linux/Android/FreeBSD** | Windows/macOS 启动硬错（Go 五平台，参见 bd b8i non-goal）；Linux 需 CAP_NET_ADMIN；TCP 走 smoltcp 按 dst 惰性建 listen（无通配端口）；UDP full-cone 有 60s 空闲淘汰；**不接受 shutdown token，优雅关闭不停 TUN** |

---

## Findings（按严重度）

### P1-1 | `mixed` inbound 的 SOCKS5 UDP ASSOCIATE 静默丢弃（UDP 全黑洞）

- **现象**：`mixed` inbound 配置 `"udp": true`（否则握手阶段就回 CMD not supported）后，客户端（v2rayN / Clash / 任意 SOCKS5 UDP 应用）做 UDP ASSOCIATE 时，**服务端已回 `0x05 0x00` 成功应答**，随后该 TCP 控制连接被直接关闭，relay socket 随 task 死亡；客户端后续所有 DNS/QUIC/UDP 报文发到刚拿到的 BND 端点全部超时，日志里只有一行 debug。
- **根因**：`crates/xray-core/src/inbound.rs:504-506`
  ```rust
  Ok(SocksRequest::UdpAssociate(_, _)) => {
      // UDP associate 简化:暂不支持(mixed UDP 罕见,跟 socks5 UDP 等价)
      tracing::debug!("mixed: udp associate not supported in mixed mode");
  },
  ```
  `socks_handshake` 在 `udp: true` 时已经 bind 好 relay socket、写好成功应答并返回 `UdpAssociate(addr, socket)`（`crates/xray-proxy-socks/src/server.rs:256-300`），此处把 socket 直接丢弃 → 客户端视角是"协商成功但服务不可用"。
- **与 Go 差异**：Go 的 `mixed` 就是 `SocksServerConfig`（`infra/conf/xray.go:33`），socks server 对 UDP ASSOCIATE 与 socks 端口完全同能力：`proxy/socks/server.go::processTCP` 的 `request.Command == protocol.RequestCommandUDP` 分支建 `TempUDPConn` 并跑 `handleUDPPayload`。Go 不存在"mixed 不支 UDP"的概念。
- **快速验证**：
  ```bash
  # 服务端 inbound: {"protocol":"mixed","port":1080,"settings":{"udp":true}}
  # 客户端（同机即可）
  curl -x socks5h://127.0.0.1:1080 https://1.1.1.1/ -I          # TCP 通
  python - <<'PY'
  # 或用任意 socks5 UDP 客户端；也可直接抓包看 relay socket 收到首包后无响应
  PY
  # 判定：握手回包 BND.ADDR 存在 → 之后无任何 UDP 回包，服务端仅 debug 日志
  ```
  同配置换 Go `xray.exe` 作服务端 → UDP 立即通，形成对照。

### P1-2 | SOCKS5 UDP relay 的 BND.ADDR 恒为 `127.0.0.1`（远程客户端 UDP 全断）

- **现象**：socks inbound 监听 `0.0.0.0:1080`（或 VPS 公网 IP）时，**远程**客户端做 UDP ASSOCIATE 收到的 `BND.ADDR` 是 `127.0.0.1:<port>`；客户端把 UDP 发给自己的回环 → 永远收不到响应。TCP 一切正常，只有 UDP 死。
- **根因**：`crates/xray-proxy-socks/src/server.rs:259-264` + `:312-327`
  ```rust
  let bind_ip = config_address_ip(config);
  let relay_socket =
      tokio::net::UdpSocket::bind((bind_ip, 0)).await.map_err(SocksError::Io)?;
  let relay_addr = relay_socket.local_addr().map_err(SocksError::Io)?;
  ...
  .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
  ```
  未配 `settings.ip` 时 `config_address_ip` 回退 `127.0.0.1`，BND.ADDR 直接回 relay 的实际 bind 地址（`server.rs:266-296`）。
- **与 Go 差异**：`proxy/socks/protocol.go:200-205`
  ```go
  // Use conn.LocalAddr() IP as remote address in the response by default
  responseAddress = s.localAddress      // = conn.LocalAddr() 的 IP
  ```
  Go 用**该 TCP 连接的本地地址 IP**（即客户端实际连上的服务端地址）报告 BND，同时按该 IP 监听 UDP。远程 socks UDP 因此在 Go 上可用，在 Rust 上不可用。
- **快速验证**：
  ```bash
  # VPS 上跑 server: {"protocol":"socks","port":1080,"settings":{"udp":true}}
  # 从另一台机器用 socks5 UDP 客户端：观察 ASSOCIATE 回包 BND.ADDR
  #   127.0.0.1 → 本条命中；Go 同配置回 VPS 公网 IP
  # 也可用 tshark 抓 1080 端口的 ASSOCIATE 应答（ATYP/IP 字段）
  ```
  Linux 下 `0.0.0.0` 作为发送目标会被内核视为本机，所以**同机测试会假通过**——必须跨机验证。

### P1-3 | 生产 dispatch 链丢失 `from/local` 上下文 → sourceIp/sourcePort/localIP/localPort/process 规则静默永不命中

- **现象**：路由规则里写 `source`/`sourcePort`/`localIP`/`localPort`/`process` 时不报错、不通告，规则**永不命中**，流量按后续规则或默认出站走 → "走错出站"且 access log 的 `from` 为空，排障无抓手。受影响入口：`mixed`、`http`、`dokodemo`、`shadowsocks`（含 UDP relay），以及 mux 子会话（mux 子会话走同一 `handler.dispatch`）。
- **根因 A（入口不给 access）**：`inbound.rs:501,534`（mixed 两处）、`:609`（http CONNECT）、`:643`（handle_plain_http）、`:891,912`（dokodemo TLS/plain）、`:1204`（ss pump）、`:1384`（ss2022 relay）均为
  ```rust
  let _ = handler.dispatch(&dest, link).await;      // 无 AccessContext
  ```
  → `InboundDispatchHandler::dispatch` 只补 `inbound_tag`（`wiring.rs:584-600`），`from` 恒空。mux 子会话同样走裸 `handler.dispatch`（`crates/xray-mux/src/worker.rs:87-96`），故 mux 用户也丢 source。
- **根因 B（dispatcher 不消费 local）**：即便入口给了 `AccessContext.local`（如 socks `inbound.rs:266-268`），`default.rs::build_routing_context` 也从不写入：
  ```rust
  fn build_routing_context(dest, sniffed_protocol) -> DispatcherContext {
      let mut ctx = DispatcherContext::new().with_target_port(dest.port()).with_network(dest.network());
      ...
      // 没有 with_local / source 缺省注入
  }
  ```
  （`crates/xray-app-dispatcher/src/default.rs:761-779`；`AccessContext.local` 全仓只出现在 Debug impl，无消费点）
- **根因 C（vlessRoute 恒 0）**：`crates/xray-core/src/wiring.rs:88-92`
  ```rust
  local_ips: ctx.get_local_ips().to_vec(),
  local_port: ctx.get_local_port(),
  // dispatcher 端 vless route id 未填充，用 0 占位
  vless_route: Port::new(0),
  ```
  → `vlessRoute` 规则（`wiring.rs:895` 已解析进 proto、`rule.rs:176` 已编进 matcher）在生产路径永不命中。
- **与 Go 差异**：Go 每个 inbound 在 proxyman 层就填好 `Source`/`Local`：`app/proxyman/inbound/worker.go:111-116`（TCP）、`:352-356`（UDP）、`:496-501`（UDS）；`features/routing/session/context.go:31-66` 直接读它们实现 `GetSourceIPs/GetSourcePort/GetLocalIPs/GetLocalPort`。**没有任何 inbound 缺来源地址。**
- **快速验证**：
  ```jsonc
  // routing: {"rules":[{"type":"field","source":["127.0.0.1"],"outboundTag":"blackhole"}]}
  // inbound: {"protocol":"mixed","port":1080}
  curl -x http://127.0.0.1:1080 http://example.com    # Go: 被 blackhole；Rust: 正常直连
  ```
  access log 同窗观察 `from` 字段：Rust 为空串，Go 为 `127.0.0.1:xxxxx`。

### P1-4 | plain HTTP 转发剥离 `Transfer-Encoding` 但原样直传 chunked body（POST/PUT 损坏）

- **现象**：经 `http` / `mixed` 的 plain HTTP 路径发 chunked 请求（`Transfer-Encoding: chunked` 的 POST/PUT，gRPC-Web/流式上传常见），上游收到的是"没有 TE 头、body 却是 chunk-size 行"的畸形请求 → 上游 400、挂起或把 chunk-size 当正文。
- **根因**：`crates/xray-proxy-http/src/server.rs:49-60`（hop-by-hop 列表含 `"transfer-encoding"`）+ `crates/xray-core/src/inbound.rs:644-676`
  ```rust
  let request_head = build_forwarded_request(&hs.method, &path, &hs.headers);
  ...
  loop {
      match client_read.read(&mut buf).await {
          Ok(n) => { let mut mb = MultiBuffer::new(); mb.merge_bytes(&buf[..n]); ...
  ```
  头部重建丢 TE，正文却是原始字节流（不做 chunk 重编码/解码头）。
- **与 Go 差异**：Go 用 `request.Write(requestWriter)`（`proxy/http/server.go::handlePlainHTTP` 的 `requestDone`）→ 由 net/http 按 `ContentLength/TransferEncoding` **重新编码**，chunked 请求体在 Go 上是正确的。
- **快速验证**：
  ```bash
  # 上游起一个 nc/python http server 打印原始请求
  printf 'POST http://127.0.0.1:18080/x HTTP/1.1\r\nHost: 127.0.0.1:18080\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n' \
    | nc 127.0.0.1 1080            # mixed/http inbound 端口
  # 上游看到：无 Transfer-Encoding，其后直接 "5\r\nhello..." → 畸形
  ```

---

### 建议级（P2）

### P2-1 | plain HTTP 每连接只服务一个请求（Go 有 keep-alive 续用循环）+ 读响应失败无 503 兜底
- **现象**：客户端带 `Proxy-Connection: keep-alive` 复用一个 TCP 连接发第 2 个请求时，连接已被服务端关闭（浏览器表现为重试/偶发 `ERR_CONNECTION_CLOSED`）；上游读响应失败时客户端只看到连接断开，Go 会回 503。
- **根因**：`inbound.rs:700-706`
  ```rust
  read_resp.await;
  write_task.abort();
  up_w_ctl.shutdown();
  }   // 函数返回 → client stream drop → 连接关闭
  ```
- **Go 差异**：`proxy/http/server.go:159-166`（`keepAlive` + `errWaitAnother` → `goto Start` 处理下一请求）、`:282-292`（读响应失败构造 503 回写给客户端）。
- **快速验证**：`printf 'GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\n'` 连发两次同一 socket，第二次必失败；Go 同配置第二次成功。

### P2-2 | plain HTTP 的 dest 取自 Host 头，忽略绝对 URL 的端口与 scheme 默认端口
- **现象**：`GET http://host:8080/path` 而 `Host: host`（无端口）时拨号到 80；`https://` 绝对 URL 也按 80（Go 按 443）。透明代理下 `Host` 头缺失直接 400。
- **根因**：`crates/xray-proxy-http/src/server.rs:270-281`
  ```rust
  let dest = if method == "CONNECT" { parse_host_port(&target, 443)? } else {
      let host = headers.get("host").ok_or_else(|| ...missing Host header)?;
      parse_host_port(host, 80)?
  };
  ```
- **Go 差异**：`proxy/http/server.go:136-145`：`defaultPort` 先按 scheme 取 443/80，`host := request.Host; if host == "" { host = request.URL.Host }`（net/http 对 absolute-form 会把 URL.Host 填进 request.Host，天然带端口）。
- **快速验证**：`curl -x http://127.0.0.1:1080 -H 'Host: example.com' 'http://example.com:8080/'` → 观察服务端出站目标端口（freedom 日志/tshark）。

### P2-3 | `mixed` 不识别 SOCKS4/4a（首字节 0x04 落 unknown）
- **现象**：老客户端/脚本用 SOCKS4 连 mixed 端口立刻被关，无日志（debug 级）。
- **根因**：`inbound.rs:481-483` 只判 `sniff[0] == 0x05`，`:537-539` 其余非字母首字节一律 close。
- **Go 差异**：`proxy/socks/server.go:87`：`if firstbyte[0] != 5 && firstbyte[0] != 4 { ...http... }` —— 4/4a 走 socks 握手。
- **快速验证**：`curl --socks4 127.0.0.1:1080 ...`（mixed 端口）。

### P2-4 | SS UDP relay 硬编码绑定 `0.0.0.0`，忽略 listen 地址
- **现象**：`listen: "::"` 的 SS 入站 IPv6 客户端 UDP 完全不可达（只绑了 v4 通配）；`listen: "127.0.0.1"` 的入站则把 UDP 中继暴露到所有网卡（越权面）。bind 失败只 warn，UDP 静默降级。
- **根因**：`crates/xray-core/src/inbound.rs:1278-1291`
  ```rust
  let port = listener.local_addr()?.port();
  match tokio::net::UdpSocket::bind(("0.0.0.0", port)).await {
      Ok(sock) => { ... }
      Err(e) => tracing::warn!(error = %e, port, "ss udp bind failed, udp relay disabled"),
  }
  ```
- **Go 差异**：`proxy/shadowsocks/server.go` 的 `Network()` 返回 TCP+UDP，由 proxyman worker 按 **inbound gateway/listen 地址**监听 UDP（`app/proxyman/inbound/worker.go:352-356` 同地址族），不存在硬编码通配。
- **快速验证**：`listen":"::"` 起 ss inbound，`ss -lunp | grep <port>`：Rust 只有 `0.0.0.0`，Go 有 `::`。

### P2-5 | transport 模式 inbound 忽略 `streamSettings.sockopt`
- **现象**：`ws/grpc/kcp/splithttp/httpupgrade` 入站上的 `acceptProxyProtocol`、`tcpFastOpen`、`mark`、`tcpMptcp` 等配置解析通过但静默无效（PROXY protocol 场景会被当成协议首字节 → 握手失败）。
- **根因**：`inbound.rs:2643`
  ```rust
  let listener = xray_transport::listener_registry::listen_tcp(
      bind_addr, settings,
      xray_transport::sockopt::SocketOptions::default(),   // ← 未用 inbound_sockopts
      on_conn,
  ).await?;
  ```
  对比同文件裸 TCP 分支均传 `inbound_sockopts.clone()`（`:2743`、`:2766`、`:2842`、`:3016` 等）。
- **Go 差异**：Go 在 `proxyman` 层把 listener 的 `SocketSetting` 统一交给 `internet.ListenTCP`，与 protocol 名无关。
- **快速验证**：vless+ws inbound 加 `"sockopt":{"acceptProxyProtocol":true}`，前面挂一层发 PROXY v2 头的 LB → Rust 握手必败，Go 正常。

### P2-6 | 部分子 listener 与 shutdown token 脱钩（优雅关闭只停 accept 主循环）
- **现象**：`dokodemo` 的 TCP/UDP 子 task、`ss` 的 UDP relay、`dns` 的 UDP 任务、`tun` 的 driver 均为裸 `tokio::spawn`，`spawn_inbound_serve` 的 cancel 只影响外层 future；`JoinHandle` 被 drop 时是 detach 而非 abort → 端口/设备不释放，进程不退净。
- **根因**：`inbound.rs:3048-3052`、`:3070-3075`（dokodemo 两个 `tokio::spawn`）、`:1282-1289`（ss udp）、`:1769-1772`（dns udp）、`:2696-2699`（tun 分支根本不 select shutdown_token）：
  ```rust
  handles.push(tokio::spawn(async move {
      if let Err(e) = serve_dokodemo(listener, ohm_tcp, opts).await { ... }
  }));
  ...
  Ok(Some(spawn_inbound_serve(..., async move {
      for h in handles { let _ = h.await; }     // cancel 时 h 被 drop = detach
      Ok(())
  })))
  ```
- **Go 差异**：Go `proxyman` 会 `SetStopping`/`Close` 每个 listener 与 UDP hub（proxyman/inbound `close` 链），不会留活 listener。
- **快速验证**：起 dokodemo（network: tcp,udp）+ 触发 shutdown（SIGTERM/API），`ss -lntu` 观察端口是否仍被占；同配置 Go 干净释放。

### P2-7 | plain HTTP 请求头被 HashMap 折叠（重复头丢失）
- **现象**：客户端发多条同名头（多条 `Cookie`、`Accept`，或 `X-Forwarded-*` 多条）时只剩最后一条 → 上游鉴权/会话失败。
- **根因**：`crates/xray-proxy-http/src/server.rs` 的 header 收集为 `HashMap<String,String>` 覆盖写（`headers.insert(k, v)`），`build_forwarded_request` 按 map 逐条重发。
- **Go 差异**：Go `http.Header` 是 `map[string][]string`，多值原样保留。
- **快速验证**：发两条 `Cookie: a=1` / `Cookie: b=2`，上游打印只看到一条。

### P2-8 | mux 拦截的端口判定不一致（socks/http 侧要求 port==9527）
- **现象**：本地 socks/http 入口收到 `v1.mux.cool` 但端口非 9527 时不会被 mux 接管，转而去"拨号域名 v1.mux.cool"→ 解析失败/超时。`wiring.rs` 的通用装饰器只按域名判定（与 Go 一致），本路径不一致。
- **根因**：`inbound.rs:297-300`（`is_mux_destination` 要求 port == `MUX_COOL_PORT`）被 `:498`、`:531`、`:604` 使用；而 `wiring.rs::is_mux_carrier` 只看域名。
- **Go 差异**：`app/proxyman/inbound/always.go` 的 `mux.NewServer` 装饰器只比较地址（domain == v1.mux.cool），不看端口。
- **快速验证**：socks 入口 CONNECT `v1.mux.cool:0` → Rust 尝试直连，Go 走 mux ServerWorker。

---

## 已核对、本次判为"无问题"（避免后续复报）

1. **`dispatch_link` 的 spawn 语义**（原 P0 模板）：`default.rs:1117-1430` 确实在 `spawn_tracked` 后同步返回；`handle_plain_http` 已按此改写（`inbound.rs:634-643` 注释 + 只等下行），与 Go 的 `go routedDispatch(...)` 语义一致。其余 serve_* 也都只把 link 交出去、不依赖返回值收尾。
2. **sniffing / CachedReader 回灌**：`sniff_connection`（`default.rs:564-728`）200ms 递减预算、`ErrNoClue` 计数上限 2、失败回退原 dest，`CachedReader` 回放已读字节 → 不丢首包；`metadataOnly` 早退、fakedns 兜底、`override_dest` 的 routeOnly 分支与 Go `default.go:232-320` 对齐。
3. **per-inbound ohm 快照**：`inbound.rs:2016-2028` 每个 inbound 一份 snapshot，default 被替换为 `MuxCarrierHandler(InboundDispatchHandler)`；master ohm 的 default 保持真实出站，无递归；snapshot 为浅拷贝（`default.rs:1921-1926`），互不污染。
4. **MuxCarrierHandler 接线**：vless/trojan/vmess/ss 的 transport 与裸 TCP 分支都通过 `ohm.get_default_handler()` 取到包装链；vless splithttp 的 `allowed_network=UDP`（`inbound.rs:2786-2788`）经 `AccessContext.allowed_network` 传到 `handle_mux_inbound_link`。
5. **UdpDispatchSession 无 idle 超时**：`udp_session.rs` 顶部 ponytail 注释显式声明由调用方生命周期兜底；socks/dokodemo/tun 各自都有 idle 淘汰（`inbound.rs:388-393`、`:977`/`:1018`、tun 的 60s sweep），当前唯一裸用点都没有长控无连接场景。
6. **dokodemo followRedirect 的 `original == local` 过滤**：`inbound.rs:852-866` 已注释说明为何必须过滤（否则普通连接被误判为透明流量，CI 实证），行为与 Go 普通 listener 可观测等价。

## 未覆盖范围

- 协议密码学（VLESS/REALITY/Trojan/VMess 的加解密与握手细节）按非目标排除，只审了它们的入口接线与 dispatch 调用方式。
- `xray-app-router` 内部匹配器语义、`xray-proxy-hysteria` / `tuic` / `anytls` / `naive` / `wireguard` inbound 的协议内行为只做了入口级抽查（naive/hysteria 的 dispatch 生命周期已抽查，未见同类断裂）。
- 未运行任何测试/二进制；所有"可用/不可用"结论来源于静态代码 + Go 源码对照，标注为 [INFERENCE] 的条目未实测。

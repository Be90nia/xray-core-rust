VERDICT: PASS（hysteria masquerade=proxy 从「恒 503 兜底」实装为真反代：Go `httputil.ReverseProxy` 语义逐条对齐；
Rust↔Rust 与 **Go 26.10.17** 两侧上游观测逐项一致；反证（改回 503）→ 上游收不到请求、用例红）

# 4zcki — hysteria masquerade=proxy 未实现

分支 feature/fix-inbound-parity｜改动仅 `crates/xray-transport-hysteria/**`
（新增 `src/masq_proxy.rs`；改 `src/hub.rs`、`src/quinn_adapter.rs`、`src/lib.rs`、`Cargo.toml`）

## 1. Go 规格表（`transport/internet/hysteria/hub.go` @ 92ccc939 + `infra/conf/`）

Go 的伪装配置**不是**平铺字段，而是 `streamSettings.hysteriaSettings.masquerade.*`
（`infra/conf/transport_method.go:747-767` 的 `Masquerade` 结构 → `HysteriaConfig.Build()`
映射到 proto 的 `Masq*` 字段）；本仓 JSON 侧已同形（`proto_config.rs::apply_masquerade_json`）✔。

| 字段（JSON `masquerade.*`） | proto 字段 | Go 语义（hub.go:219-265） | 本实现 |
|---|---|---|---|
| `type: "proxy"` | `MasqType` | 走 `httputil.ReverseProxy` 分支 | `MasqType::Proxy` → `ProxyMasqHandler` |
| `url` | `MasqUrl` | `url.Parse`；`http`/`https` → 普通反代；`""`/`unix` → unix socket 上游；其它 scheme → Listen 报错 | 同（`parse_masq_target`）；unix scheme **未实现** → 构造期报错（fail-visible） |
| `rewriteHost` | `MasqUrlRewriteHost` | **`false`（默认）→ `r.Out.Host = r.In.Host`：上游 Host 头保留客户端原始 Host**；`true` → `r.Out.Host=""` → Host 头 = 上游 `URL.Host`（含显式端口） | 同（`rewrite_host` 分支） |
| `insecure` | `MasqUrlInsecure` | 仅 http/https：上游 TLS `InsecureSkipVerify`（**跳过证书校验**，非别的） | 同（本地 `NoVerify` 校验器） |
| `xForwarded` | `MasqUrlXForwarded` | `r.SetXForwarded()` → 注入 X-Forwarded-For/Proto/Host | 本仓配置层**硬错拒启**（`proto_config.rs` 票 037f：该字段无运行时消费点）→ 不会出现「配了不生效」 |
| — | — | Rewrite 前**剥除**客户端自带 `Forwarded`/`X-Forwarded-*` | 同（`strip_forwarded_headers`） |
| — | — | hop-by-hop 头不转发（Connection/TE/Trailer/Upgrade/…） | 同（`HOP_BY_HOP`） |
| method/path/query/body | — | method 透传；path = `joinURLPath(MasqUrl.path, 入站 path)`；query = `MasqUrl.query` + "&" + 入站 query；body 透传 | 同（`join_url_path` / `join_query` 逐字照 Go `singleJoiningSlash` / `rewriteRequestURL`） |
| 响应 | — | 状态码 + 头（去 hop-by-hop）+ 体回传 | 同 |
| 错误 | — | `ErrorHandler` → **502 Bad Gateway** | 同（旧 Rust 是 503 → 已改 502） |
| 缓冲/超时 | — | `BufferPool` 32KB；`MaxIdleConns=100`；默认 transport **无响应头超时**（等上游到天荒地老） | 无池化（每请求一条连接）；**同样不设响应超时**（照 Go，不擅自加） |
| — | — | scheme `unix` → `DialContext` 走 unix socket、30s dial 超时 | 未实现（Windows 无 unix socket 面） |

> 配置面补充（Go `infra/conf/hysteria.go` / `transport_method.go`）：入站级 `settings.version=2`
> 与 `streamSettings.hysteriaSettings.version=2` 均为必填；伪装参数位于
> `streamSettings.hysteriaSettings.masquerade.*`。

## 2. Rust 现状（修前）

`crates/xray-transport-hysteria/src/hub.rs`：
- `MasqType::Proxy { url, rewrite_host, insecure }` **只解析不用**；
- `build_handler()` 对 Proxy 分支返回 `ProxyMasqHandler`（一个零字段 unit struct），
  其 `serve()` 恒回 **503 Service Unavailable**；
- 注释自认：「Go 用 httputil.ReverseProxy 真反代（ErrorHandler 502）；本实现保持 503 类兜底
  响应（任务授权 "proxy 503 类"），url/rewrite_host/insecure 暂不消费」。
- 另一个形态缺陷：`MasqueradeHandler::serve(method, path, headers)` **没有 query / Host /
  body** → 反代面天然拿不到上游 URL 拼接所需的 query、也拿不到 `r.In.Host`。

## 3. 实现与复用说明

**复用**：仓内已有 `hyper` / `hyper-util` / `http-body-util` / `tokio-rustls` / `webpki-roots`
（均为 workspace 既有依赖，**未引入任何新外部 crate**）；HTTP/1.1 客户端用
`hyper::client::conn::http1::handshake`（仓内 xray-transport-naive / websocket 已在用同款 API），
`hyper_util::rt::TokioIo` 作 IO 适配。**仓内无可直接复用的反代实现**（`hyper_util::client::legacy`
只出现在 splithttp，而 splithttp 在本轮红线内不可动），故按 Go 语义新写最小反代面。

**改动**：
1. `hub.rs`：
   - 新增 `MasqRequest { method, path(含 query), headers, host, body }` 与
     `MasqResponse` 别名；
   - `MasqueradeHandler` 增 `serve_request(req)`（**默认实现退化为 `serve()`** → 既有
     404/file/string handler 零改动、零行为变化）；proxy 分支覆写它做真反代；
   - `MasqType::build_handler()` 的 Proxy 分支改为构造 `ProxyMasqHandler::new(url, rewrite_host, insecure)`；
   - 旧的 503 stub 删除。
2. 新增 `src/masq_proxy.rs`：`parse_masq_target` / `join_url_path` / `join_query` /
   `strip_forwarded_headers` / `tls_connector`（insecure 跳过校验）/ `ProxyMasqHandler`。
3. `quinn_adapter.rs`：两处 masquerade 调用点改用 `serve_request`，并把 **path+query**
   （`Uri::path_and_query()`）、**:authority → host**、**h3 数据帧 → body** 一并传入
   （第二处调用点原先把 headers 传成空 HashMap，本轮一并修正）。
4. `Cargo.toml`：+hyper/+hyper-util/+http-body-util/+tokio-rustls/+webpki-roots（全为
   workspace 既有）。

## 4. Rust ↔ Go 上游观测对照（同一请求形状）

请求：`POST /probe?x=1`，h3 authority = `localhost`，无 body；目标 `MasqUrl` =
`http://127.0.0.1:<upstream>/base`，`rewriteHost=false`。

**Rust 侧**（`masquerade_proxy_forwards_to_upstream`，本仓上游记录器）：

| 字段 | 值 |
|---|---|
| method | POST |
| path | /base/probe |
| query | x=1 |
| Host | localhost |
| body | （空） |

**Go 侧**（Go 26.10.17 hysteria 服务端，`masquerade.type=proxy` + 同款上游记录器
`D:/tmp/go-upstream-seen.json`）：

```json
[ { "method": "POST", "path": "/base/probe", "query": "x=1", "host": "localhost", "body": "" } ]
```

→ **method / path / query / Host / body 五项逐项一致** ✔（Go 侧用例
`go_masq_proxy_roundtrip` 亦 PASS：Go 反代把上游 200 + `upstream-ok` 原样回传）。
`rewriteHost=true` 的对照（Rust 侧）：Host 头 = 上游 authority `127.0.0.1:<port>` ✔。

## 5. 反证（改回 503 兜底 → 上游收不到请求）

```text
# 临时把 ProxyMasqHandler::serve_request 换成旧 503 兜底：
test quinn_adapter::tests::masquerade_proxy_forwards_to_upstream ... FAILED
thread 'masquerade_proxy_forwards_to_upstream' panicked at quinn_adapter.rs:2240:
assertion `left == right` failed: 上游 200 必须经反代回传
  left: 503
 right: 200
test result: FAILED. 0 passed; 1 failed
```

（上游记录器在该态下观测到 0 个请求；还原后同一用例 PASS。）

## 6. 门禁

```text
$ cargo test -p xray-transport-hysteria --all-targets
  lib: 123 passed; 0 failed; 2 ignored（含新增：上游观测 3 例 / 阈值与解析 2 例 /
        502 与静默上游 2 例 / e2e 反代 1 例 / Go 对照 1 例[ignored，需外部 Go 端]）
$ cargo clippy -p xray-transport-hysteria --all-targets -- -D warnings → Finished（零告警）
$ cargo fmt -p xray-transport-hysteria -- --check → 0
```

新增用例（`masq_proxy::tests` + `quinn_adapter::tests`）：
- `proxy_forwards_request_to_upstream_keeping_client_host`：上游确实收到请求 +
  method/path/query/Host/body 断言；
- `proxy_rewrites_host_when_rewrite_host_enabled`：rewriteHost=true → Host = 上游 authority；
- `proxy_upstream_unreachable_returns_502` / `proxy_invalid_target_returns_502`：
  上游不可达 / URL 非法 → 502（Go ErrorHandler / fail-visible）；
- `proxy_silent_upstream_does_not_early_return`：上游沉默时**不早退**（Go 默认 transport
  无响应头超时，本实现不擅自加超时）；
- `go_path_and_query_join_semantics` / `masq_target_parsing`：Go path/query 拼接与
  URL 解析语义；
- `masquerade_proxy_forwards_to_upstream`：h3 客户端 → Rust 服务端 masquerade → 本地上游
  的**全链路 e2e**；
- `go_masq_proxy_roundtrip`（`#[ignore]`）：连 Go 26.10.17 服务端的对照用例。

## 7. 残余 / 未做

- **`unix` scheme 上游未实现**（Go 支持 unix socket 反代；Rust 侧无 unix socket 上游面，
  构造期报错而非静默）。
- **连接池未做**（Go `MaxIdleConns=100`；本实现每请求一条 TCP/TLS 连接）——伪装面低频可接受，
  未做池化以免引入额外状态。
- **`MasqUrlXForwarded` 未实现**：本仓配置层已对该字段**硬错拒启**（票 037f），故不会出现
  「配了不生效」；Go 的 `SetXForwarded` 语义待后续单独实现。
- **Go 的 `cleanQueryParams`**（丢弃不可解析的 query 参数）未复刻。
- 上游 body **全量缓冲**（Go 是流式转发）——伪装面请求体量级小，未做流式。
- 未碰红线文件：`xray-transport-splithttp/**`、`xray-app-commander/src/grpc.rs`、
  `xray-cli/src/commands/api_exec.rs`、`xray-xudp/src/packet.rs`、
  `xray-proxy-freedom/src/udp.rs`、`xray-proxy-socks/src/udp.rs`、
  `xray-app-dispatcher/src/udp_session.rs`、`xray-core/src/{inbound,outbound}.rs`、
  `xray-mux/**` ✔。未 commit。
- 代码图谱重索引两次均被并行改树打断（`aborted_previous_preserved`，前版图谱完好仍服务）
  —— 建议整波落地后由 PM 统一重索引。

## 8. 收尾

- 构建目录 `D:/Project/Xray-core-rust/target-Wave7Masq`（本任务独占）任务结束删除。
- 对照脚本（仓库外）：`D:/tmp/go_masq_proxy.py`（起 Go hysteria + 上游记录器）、
  `D:/tmp/upstream_recorder.py`、`D:/tmp/hy-cert.pem`/`hy-key.pem`（openssl 自签）。

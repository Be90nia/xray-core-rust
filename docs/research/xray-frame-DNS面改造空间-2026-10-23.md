# xray-frame 视角：主仓 DNS 面改造空间（2026-10-23）

> 任务 B 底料 · 只读深盘，零产品文件改动，未 commit。
> 范围：`crates/xray-app-dns`（server.rs / cache_controller.rs / hosts.rs / fakedns / nameserver/*）· `crates/xray-proxy-dns`（handler.rs / dns_message.rs / inbound.rs / outbound.rs）· `crates/xray-features/src/dns.rs`（DnsClient 契约）· 主仓其他 DNS 触点（app-router / app-dispatcher / core 装配 / observatory）只做清单。
> 工具声明：`serena-cli` 尝试 4 次全部 `LS_TERMINATED`（rust LS 启动即退，`stop-all` 后重试同错）→ 降级 `read`/`grep` 直取 file:line；cbm 知识图谱未用（跨文件批量声明行扫描场景，grep 直出证据更省）。Go 侧对照全部实读 Xray-core `main` 原文（app/dns/*.go、infra/conf/dns.go、features/dns/client.go、common/utils/probe_routes.go）。

---

## 1. 结论（首行）

**DNS 面是主仓里"上游件最齐、但托管/时钟/并发三处基础面欠账最多"的一域**：功能面（hosts 索引、缓存 TTL、fakedns 池、上游 6 协议、并行/串行编排、错误分类）已与 Go 逐条对齐且有测试锚，**改造空间不在"补功能"而在"补基础面"**——①所有后台任务（每 NS 一条 cleanup task + serveStale pull + DoH h2 conn）裸 spawn 无停机托管；②时间源直取 `Instant::now()`，TTL/stale 测试只能真等；③fakedns 的 IP↔域名双向查找是 **O(n) 线性扫描**（Go 是 O(1)），而反查在 **dispatcher 每连接路径**上被调用（`app-dispatcher/src/default.rs:592`）；④缓存控制器的手写收缩分支是**空操作**（`cache_controller.rs:196` take 后立即还原），Go 的 dirtyips 后台迁移未实现。

**依托 udf 的最大障碍不是 API 缺失，而是接线形态**：udf-frame 是**独立 git 仓、不在主仓版本库**（`.git/info/exclude:10` + `crates/udf-frame/Cargo.toml` 自带 `[workspace]`），且 udf-frame **根目录无 `[package]`** → cargo git 依赖无法指向其子包；主仓 `crates/` 下 **零 udf 依赖**（grep `udf-frame|std-ext|skeleton-infra` 全无命中）。所有"A 类接线"项的前置闸 = 单独 commit 的 CI 变更（`.github/workflows` 属 CLAUDE.md §4 红线）→ 需 PM 拍板（详见 §7 未决点 U1）。

**热路径判定**：DNS 查询链**不触碰**数据面热路径（xray-buf alloc/copy/pipe、bridge splice、poll/waker 语义），本报告全部改造项**均可动**；唯一需"禁额外分配"约束的是 fakedns 反查（每连接路径）。DNS 面**不存在**"必须走 udf 才能做"的项，也不存在"必须留在主仓"的项——除 §5 不能动清单（Go 对齐面）。

---

## 2. 现状结构：DNS 请求路径（每段 file:line + 线程/异步模型）

### 2.1 入口一：DNS inbound（`proxy/dns` 作为 inbound 协议）

| 段 | file:line | 说明 |
|---|---|---|
| 装配 | `xray-core/src/inbound.rs:4497-4511` | `"dns"` 分支 → `parse_dns_inbound_config`（`inbound.rs:5826-5859`）→ `DnsInbound::new` |
| 监听 | `xray-core/src/inbound.rs:2520-2558` | `serve_dns`：UDP task + TCP accept loop（各 `tokio::spawn`） |
| 收包 | `inbound.rs:2576-2644`（Linux recvmmsg 批收）/ `2647-2669`（其他平台单收） | `dns_udp_recv_loop` → `DnsInbound::handle_packet` |
| 决策 | `xray-proxy-dns/src/inbound.rs:48-51` → `handler.rs:183-207` | `Handler::process` → `parse_dns_query`（`dns_message.rs:88-120`）→ `match_rules`（`handler.rs:137-146`）/ `decide_action`（`handler.rs:273-275`） |
| 路由 | `proxy-dns/src/inbound.rs:103-113` | `route_outcome`：Forward/Hijack → `DnsOutbound::process`（`outbound.rs:73-99`，**hickory `TokioResolver`**）；Respond → 直接回写；Drop → 不回包 |
| TCP 变体 | `proxy-dns/src/inbound.rs:61-100` | `decode_tcp_dns_message`（`handler.rs:247-256`）2B 长度前缀帧循环 + `ActivityTimer` 空闲窗 |

### 2.2 入口二：dispatcher 分发的 DNS outbound（`xray-core/src/outbound.rs`）

| 段 | file:line | 说明 |
|---|---|---|
| 桥 | `outbound.rs:1963-1980`（`DnsDispatchBridge`）→ `2070-2099`（`dispatch` / `dispatch_with_access`） | own_link 判定 → `DnsService::is_own_link`（`app-dns/server.rs:124-130`） |
| 主体 | `outbound.rs:2103-2140+`（`dispatch_dns_link`） | UDP 单请求-响应 / TCP 双路帧循环 |
| Hijack | `outbound.rs:2036-2066`（`handle_ip_query`） | `DnsService::lookup_ip` → `xray_proxy_dns::build_ip_response`（`dns_message.rs:211-256`） |

### 2.3 app-dns 服务内部（`xray-app-dns/src/server.rs`）

```
DnsService::lookup_ip (server.rs:208-280)
├─ 域名规范化：strip_suffix('.') + 空判 (213-219)
├─ query_strategy 钳制 (224-243)  ← UseSys 分支走 check_routes()
├─ hosts 查询 (250-266) → hosts.rs:120 lookup → hosts.rs:128 lookup_inner
│     ├─ matcher.match_domain (hosts.rs:136)   ← 预建 MPH 索引，非线性扫描
│     ├─ RCode 优先 (144-149) / 单域名递归 unwrap max_depth=5 (152-166)
│     └─ filter_ip_entries (hosts.rs:230-243)
│   命中 → to_net_ip (config.rs:112-125) → return (ips, 10)   ← Go "Hosts ttl is 10"
├─ sort_clients (server.rs:136-203)  ← per-NS 域名规则 matcher + fallback 顺序
└─ serial_query (server.rs:310-336) | parallel_query (server.rs:397-470)
      ├─ make_groups (server.rs:354-376)  ← 按相邻 policy_id 分组
      ├─ advance_groups (server.rs:486-517) ← 组内 race / 组间串行
      └─ merge_query_errors (server.rs:564-608)
```

### 2.4 每 client → 上游（`xray-app-dns/src/nameserver/`）

```
Client::query_ip (nameserver/mod.rs:209-278)
├─ option 钳制（check_system → check_routes / 否则与 ip_option AND）(216-231)
├─ expected/unexpected IP 四分支过滤 (233-277)
└─ Server::query_ip → cached::query_ip (cached.rs:105-146)
      ├─ 缓存命中：cache.find_records (cache_controller.rs:117-119)
      │     + merge_records (dnscommon.rs:178-231)
      ├─ serveStale 路径：stale_result (cached.rs:149-176) + pull (cached.rs:290-294)
      └─ fetch (cached.rs:194-283)
            ├─ singleflight（key = fqdn + v4/v6 族标志，cached.rs:200）
            ├─ send_query（udp.rs:281 / tcp.rs:238 / doh.rs:353 / dot.rs:256 / quic.rs:216 / local.rs / fakedns.rs:145）
            │     └─ query_once → dial.rs connect_stream → build_dns_query (dnscommon.rs:268-297)
            │          → 上游 → parse_dns_response (dnscommon.rs:322-364) → parsed_to_ip_record (dnscommon.rs:372-383)
            └─ 回写：cache.upsert (cache_controller.rs:124-136) + CacheEvent 广播 (cached.rs:241-253)
```

### 2.5 线程 / 异步模型现状

| 项 | 现状 | file:line |
|---|---|---|
| 运行时 | tokio 多线程 runtime；DNS 查询链全程 async | 全仓 |
| 缓存容器 | `parking_lot::RwLock<HashMap<String, Arc<Record>>>`（无容量上界） | `cache_controller.rs:47` |
| singleflight | `tokio::sync::Mutex<HashMap<(String,bool,bool), broadcast::Sender<QueryOutcome>>>` | `cache_controller.rs:54-56` |
| 并行查询 | 每 client 一个 task（`JoinSet`，`abort_all` 收尾） | `server.rs:397-470` |
| 后台 cleanup | **每 NS 一条** `tokio::time::interval` task，JoinHandle 丢弃 | `cache_controller.rs:241-266`；调用点 `udp.rs:125` `tcp.rs:117` `doh.rs:159,189` `dot.rs:138` `quic.rs:113` |
| 后台 pull | **裸 `tokio::spawn` fire-and-forget** | `cached.rs:290-294` |
| DoH h2 连接 | **裸 `tokio::spawn`** | `doh.rs:261` |
| 全局共享槽 | `LazyLock<RwLock<Option<Arc<..>>>>` 两处（dialer / fakedns） | `dial.rs:126` `fakedns/mod.rs:29-31` |
| 时间源 | 一律 `Instant::now()` / `SystemTime::now()`，**无注入** | `cache_controller.rs:252` `cached.rs:117,235` `fakedns/mod.rs:300-303` |

---

## 3. 七个具体核查面 · 逐个结论

### 3.1 缓存控制（cache_controller）：策略与失效模型，能否换 std_ext::cache 的 LRU/TTL

**现状策略**：每 NS 一个 `CacheController`，键 = fqdn（含尾点），值 = `Record { a: Option<IpRecord>, aaaa: Option<IpRecord> }`，每族各自持有 `expire: Instant`（`dnscommon.rs:58-67`）。失效 = 惰性（读时算剩余 TTL）+ 300s 周期全表扫描清理（`cache_controller.rs:143-161` 收集、`:163-221` 清理+收缩）。`serve_stale` 走"时间回拨"技巧：`effective_now = now - serve_expired_ttl`（`cache_controller.rs:281-289`），使宽限窗内的过期记录仍可读；stale 命中时 `pull()` 后台刷新（`cached.rs:126-134`）。**与 Go 对齐**：`merge_records` 的"失败家族 TTL 参与 min"（`dnscommon.rs:200-203`，Go `nameserver_cached.go:88-92`）、负缓存命中带正 TTL（Go `nameserver_cached.go:31`）、上游失败不写缓存（`cached.rs:237-239`）。

**能否换 std_ext::cache 的 LRU/TTL —— 结论：不能整体换，但可白拿三样。**
- **不可整体换 TtlCache**：TtlCache 是"每键单 TTL、expire-after-write、过期即删"（`std-ext/src/cache.rs:438-560`），而 DNS 缓存语义是**A/AAAA 两族各自独立 TTL** + **stale 宽限窗内过期条目仍需可读** + **负缓存（rcode=3 空答案）TTL**。TtlCache 过期即删会把 serveStale 的可读窗口直接删掉 → 语义不等价。
- **可白拿 ①：时钟注入**。`TtlCache::new(Arc<dyn Clock>, cap)`（`cache.rs:470`）的白拿价值在 `skeleton::clock::Clock` 契约本身：主仓当前 TTL/stale 判定直取 `Instant::now()`（`cache_controller.rs:252`、`cached.rs:117,235`），测试只能真等（`cache_controller.rs:439-458` 用 `tokio::time::sleep(200ms)`）。注入 `Arc<dyn Clock>` 后换 `MockClock::advance` → TTL/过期/stale 三条路径零真实等待可断言。
- **可白拿 ②：容量上界语义**。`LruCache::new(cap)`（`cache.rs:346`，cap 必填、满时逐 LRU 尾且**被逐者静默丢弃**、需 `pop_lru` 才看得见）可给当前无上界的 `HashMap` 一个有界语义；但 DNS 缓存要 Go 对齐就**不能**加 LRU 淘汰（Go 的 `CacheController.ips` 是无界 map，只在收缩时缩容）→ 结论：**容量上界不接**，除非 Go 侧也改。
- **可白拿 ③：`expired()` 计数**（`cache.rs:590`，fail-visible 过期计数）可替代当前"清理了多少"只有 debug 日志（`cache_controller.rs:254-259`）的观测缺口。

**失效模型缺陷（与 Go 对齐角度）**：收缩分支是**空操作**——`let old = std::mem::take(&mut *ips); *ips = old;`（`cache_controller.rs:196-197`，take 后立即还原），真正生效的只有 `ips.shrink_to_fit()`（:198）；Go 是**换新 map（1.1× 容量）+ `dirtyips` 后台分批迁移**（`app/dns/cache_controller.go:130-215`），Rust 无 dirtyips、无后台迁移、`high_watermark` 收缩后不重置（Go `:158` 重置为 `lenAfter`）。

### 3.2 缓存键设计（qname + qtype + 策略）是否正确

**结论：键设计与 Go 等价且正确，不需要改；但"每 NS 一个 cache"这一前提要写清楚，否则未来重构易踩。**

- 键 = **fqdn（含尾点）**，值内用 `Record.a` / `Record.aaaa` 两槽表达 qtype（`cache_controller.rs:47` + `dnscommon.rs:121-127`）→ 等价 Go 的 `map[string]*record`（`app/dns/cache_controller.go:38`）。**qtype 不进键**在 Go 与 Rust 一致，不是缺陷。
- "策略"维度不进键，靠**每 nameserver 独立 `CacheController`** 隔离（`udp.rs:118`、`tcp.rs:110`、`doh.rs:152` 等各 new 一个）→ 等价 Go "Create a new server for each client for now"（`app/dns/nameserver.go:112`）。Rust 侧同理（`nameserver/mod.rs:310` 每次 `new_server_with_config` 新建）。
- 读路径键一致性已核：`cached.rs:107` `fqdn(domain)` 加尾点 → `find_records(fqdn_owned)`；写路径 `cached.rs:242` `cache.upsert(fqdn, ...)` 同一带尾点键 → 一致。
- expectedIPs/unexpectedIPs 过滤在**缓存之外**、查询结果之上（`nameserver/mod.rs:233-277`），Go 同（`app/dns/nameserver.go:180-225`）→ 缓存里存的是**未过滤**记录，行为一致。
- 唯一偏差（不影响键设计但影响语义）：`negative_ttl_secs` 配置项**全仓无消费方**（`cache_controller.rs:44-46` 自述"本字段暂无行为消费方"；`jsonconf.rs:138,467` 透传）→ 配置存在但**静默无效**（违反本仓 `alwc` "未知/无效配置不得静默"纪律）。

### 3.3 hosts 静态匹配：每次线性扫描还是预建索引

**结论：已是预建索引（MPH），不是每次线性扫描——但有两处实质问题。**

- 索引：启动期 `MphDomainMatcher::build(&rules)`（`hosts.rs:107-118`），查询期 `matcher.match_domain(&lower)`（`hosts.rs:136`）→ O(1)-ish 哈希匹配。Go 同款（`geodata.DomainReg.BuildDomainMatcher`，`app/dns/hosts.go:52-56`）。
- **问题 A（语义偏差，必须修）**：**系统 hosts** 走 `read_system_hosts` → `parse_system_hosts`（`hosts.rs:201-227`）产出 `matcher_rules: Vec::new()` → `StaticHosts::new` 回退分支注册 **`DomainRule::domain`（后缀匹配）**（`hosts.rs:103-106`）；Go 的 `readSystemHostsFrom` 明确用 `geodata.ParseDomainRule(domain, geodata.Domain_Full)`（**精确匹配**，`infra/conf/dns.go:456`）。⇒ **Rust 的系统 hosts 会命中子域，Go 不会**。这条落在"hosts 匹配语义"红线区，**唯一允许的方向是向 Go 对齐（改 Full）**，不得反向。
- **问题 B（启动期 CPU 集中）**：规则量大的场景（`geosite:` 展开 + per-NS `domains` 规则）构建集中在 `jsonconf.rs:299`（`MphDomainMatcher::build(&all_rules)`）与 `hosts.rs:107`，启动期同步占用 → 命中规划 §2.3 的 **PooledThreadPool 互喂**候选（worker 内借缓冲跑 → RAII 还）。
- 附带：`lookup_inner` 每次调用 `domain.to_lowercase()` 分配一份 String（`hosts.rs:135`）+ `entries` Vec 分配（`:138`）→ 每查询 2 次小分配，非热路径但可记。

### 3.4 fakedns 的 IP 分配与回收（与 xray-buf 无关，涉有界性）

**结论：池有界性 OK，但分配与反查都是 O(n) 线性扫描，其中反查在 dispatcher 每连接路径上——这是 DNS 面最大的性能缺陷。**

- **有界性**：池 CIDR + `lru_size` 双约束（`fakedns/mod.rs:102-133`），并校验 `lru_size < 2^rooms`（`:115-118`）；LRU 容量来自 `LruCache::new(NonZeroUsize)`（`:129`）→ 域→IP 映射有界。Go 同约束（`app/dns/fakedns/fake.go:104-113`，`math.Log2(lruSize) >= rooms` 报错）。
- **缺陷 1（分配 O(n)）**：冲突探测 `while inner.domain_to_ip.iter().any(|(_, v)| *v == ip)`（`fakedns/mod.rs:153`）全表线性扫；Go 用 `PeekKeyFromValue(ip)` **O(1)**（`fake.go:127`，其 `common/cache.Lru` 带值→键反向索引）。
- **缺陷 2（反查 O(n)，且在每连接路径）**：`get_domain_from_fake_dns` = `domain_to_ip.iter().find(...)`（`fakedns/mod.rs:184`）全表扫；调用点 `xray-app-dispatcher/src/default.rs:592` —— **dispatcher 每条连接的 fakedns metadata 嗅探都会走它**（池满 65535 时每连接 O(65535) 扫）。Go 对应路径 `GetKeyFromValue` O(1)（`fake.go:145`）。这是"每连接 CPU 放大"，不是数据面 buf 热路径，但真实影响连接建立延迟。
- **缺陷 3（容器是第三方件）**：`use lru::LruCache`（`fakedns/mod.rs:17`、`Cargo.toml` `lru = "0.18"`），且 `with_config` 初始建的是 `LruCache::unbounded()`（`:80`，unbounded 窗口）、`initialize_with` 才换成有界（`:129`）→ 存在一个"无界"中间态；Go `NewFakeDNSHolderConfigOnly` 留 nil（`fake.go:83`），无界中间态不存在。
- **回收语义**：LRU 淘汰即回收（Rust `lru` crate 与 Go `cache.Lru` 一致），无独立 GC 任务 → **无"定时回收"需求**（结论：**不接 udf scheduler 做 fakedns 回收**，见 §6 步骤 3 的取舍）。

### 3.5 上游失败 / 超时 / 重试的当前实现

**结论：超时分段、无整查询 deadline、client 级 timeout 是死字段、重试是手写一次 —— 四个问题叠加，且 udf 的 retry 件形态不匹配（同步 vs 异步）。**

| 维度 | 现状（file:line） | Go 对照 |
|---|---|---|
| 整查询 deadline | **无**。`Client.timeout`（`nameserver/mod.rs:72`）在 `:176-180` 赋值后**查询路径从不读取**（死字段） | `ctx, cancel := context.WithTimeout(ctx, c.timeoutMs)` 包住整查询（`app/dns/nameserver.go:167`）；DoH 另有 5s 兜底 deadline（`nameserver_doh.go:166-172`） |
| 分段超时 | 每段独立 `timeout(self.query_timeout, ..)`：dial / TLS / h2 / ready / response / body 各一段（`doh.rs:96-101` `effective_query_timeout`，`doh.rs:221-345`）→ **总时长可达 5× 单段超时** | Go 是单 deadline 贯穿 |
| 重试 | DoT/TCP 手写"失败→丢弃连接→重连→再试一次"（`dot.rs:225-250`、`tcp.rs:205-231`），**无退避、无次数上限、无预算、无错误分类** | Go 同样只做一次重连（`nameserver_doh.go` 依赖 http2 自身重试） |
| UDP 截断 | ~~TC=1 → 走 TCP 重试~~ **已改(2026-10-30, bd a42ht)**：TC=1 → **同一 UDP 通道追加 EDNS0 OPT(1350,DO=1) + 新 ID 重发一次**（`udp.rs` `should_retry_with_edns0` / `edns0_retry_wire`，共享同一 deadline，**不建 TCP 连接**）；原 TCP fallback(`tcp_fallback_query`)已删。TCP 能力改由独立 `tcp://` nameserver(`TcpNameServer`,对应 Go `NewTCPNameServer`)提供 | Go：带 EDNS0(1350) 重发 UDP（`nameserver_udp.go:118-137`）—— **现已同构**；Go classic UDP NS **无** TCP fallback 分支 |
| 错误分类 | `DnsError` 细分 RecordNotFound / EmptyResponse / RCodeError / SkipDnsServer / SystemResolve（`error.rs:14-83`），跨层映射 `From<DnsError> for features::DnsError`（`error.rs:104-116`） | Go `errors.Combine` 语义等价（`server.rs:564-608` 已对齐） |

**udf 依托判定（关键）**：`std_ext::retry::retry/retry_if`（`std-ext/src/retry.rs:220,245`）是**同步件**（`op: FnMut() -> Result` + `Sleeper: Clock` 阻塞 `thread::sleep`），**DNS 上游是 async，不能直接用**；`std_ext::backoff::backoff_delay(attempt, base, max)`（`std-ext/src/backoff.rs:32`）是**纯函数**，可直接用于异步退避计算；`RetryPolicy`（`retry.rs:89-131`：`max_attempts`/`base`/`max_delay`/`with_budget`）可作**参数面**复用，但执行环要么主仓自写 async 版，要么向 udf 提"async retry"需求。主仓已有两套自造重试（`xray-common/src/retry.rs:74` `retry_timed`、`xray-transport/src/retry.rs:47` `exponential_backoff`）→ **重复实现，方向上应收敛**。

### 3.6 DNS 响应解码与解析的可测边界（纯函数化空间）

**结论：纯函数化边界已经良好，不需要重构；真正缺的是 wire 级 Go 对拍 fixture。**

- app-dns 侧全部纯函数：`build_dns_query`（`dnscommon.rs:268-297`，EDNS0 subnet /24 /96 掩码按 Go `dnscommon.go:91-107`）、`parse_dns_response`（`dnscommon.rs:322-364`，req_id 校验 + 全 answer TTL 参与 min，按 Go `dnscommon.go:212-227`）、`parsed_to_ip_record`（`dnscommon.rs:372-383`）、`merge_records`（`dnscommon.rs:178-231`）。
- proxy-dns 侧亦纯函数：`parse_dns_query`（`dns_message.rs:88-120`，手写最小解析：12B header + 第一个 question，**不支持压缩指针 0xC0**——question 段本无压缩指针，与 Go `dnsmessage` 行为等价）、`build_dns_response`（`:169-205`，flag 组合 QR/AA/RA + 回显 RD）、`build_ip_response`（`:211-256`，answer name 用 0xC00C 压缩指针）。
- **缺口**：两侧**没有共享一套 wire 解析/编码器**——app-dns 用 hickory-proto，proxy-dns 手写最小实现（`dns_message.rs` 文件头自述"workspace 无 DNS 解析 crate，手写最小解析"）→ 同一 wire 语义两套代码；且**无 Go 字节级对拍 fixture**（当前测试都是 Rust 自造响应，见 `dns_e2e.rs:37-56`）。可测边界本身够，缺的是跨实现回归资产。

### 3.7 观测面：是否统一走 logx / 埋点、是否有指标

**结论：DNS 侧没有任何结构化 DNS 日志生产方，也没有任何 DNS 指标——现有 `DnsLog`/`DnsStatus` 是死件。**

- **死件证据**：`xray-app-log/src/instance.rs:92-109`（`DnsStatus`：Queried / CacheHit / CacheOptimiste）、`:117-130`（`DnsLog{query,domain,result,status,elapsed,error}`）、`:205-209`（`LogEntry::Dns`）、`:536-540`（掩码包装）、`:685-691`（`enable_dns_log` 分发）全部齐备，但 **grep 全仓 `LogEntry::Dns\(` / `DnsLog \{` 的构造点只在 `xray-app-log` 自身与其测试内**，`xray-app-dns` **零生产方** → Go `app/dns/nameserver_cached.go:36,42,117`（cache HIT / cache OPTIMISTE / got answer 三态 + Elapsed）在 Rust 侧**完全缺失**。
- **指标**：`xray-app-metrics/src/metrics.rs` 全仓 grep `dns` **零命中**；`xray-app-stats` 同样零命中 → DNS 查询量 / 命中率 / 上游错误率**不可见**。
- **日志 target 不统一**：`xray.dns`（`server.rs:254,325,505,621`）/ `xray.dns.doh`（`doh.rs:221-341`）/ `xray_proxy_dns::handler`（`handler.rs:100`）/ `xray_proxy_dns::config`（`config.rs:210,217`）四套 target，跨 crate 无统一 `xray_frame::dns` 规范（udf 埋点规范为 `skeleton::<域>[::<段>]`，主仓对应 `xray_frame::dns`）。
- **udf 依托**：`skeleton_infra::logx`（唯一日志入口 + `mask_secrets`）+ `embed_event!` 字段化纪律可作 target/字段规范源；但 `logx` 落地本身受 §7 U1 接线形态闸。

---

## 4. 改造空间清单（19 行）

> 列含义：**面** | **现状 file:line** | **问题（性能/正确性/可测性/耦合/重复/历史坑）** | **改造方案** | **依托 udf 件（白拿功能，具体 API）** | **能否动热路径** | **批次** | **规模**
> 批次口径沿用 impl-plan：P1 通用件+A 类接线 · P2 协议/域迁移 · P3 app 层收口 · P4 持续提炼。

| # | 面 | 现状 file:line | 问题 | 改造方案 | 依托 udf 件（白拿 API） | 动热路径 | 批次 | 规模 |
|---|---|---|---|---|---|---|---|---|
| 1 | 缓存控制-时间源 | `cache_controller.rs:252`、`cached.rs:117,235` | TTL/stale 判定直取 `Instant::now()`，过期路径测试只能真等（`cache_controller.rs:439-458` sleep 200ms） | 缓存与 stale 判定改注入 `Arc<dyn Clock>`，测试换 `MockClock::advance` 零等待断言 | `skeleton::clock::{Clock(:56), SystemClock(:82), MockClock(:128)}` —— `now_instant()` / `advance()` | 可动（非数据面） | P1 | S |
| 2 | 缓存控制-后台清理托管 | `cache_controller.rs:241-266` + 6 处调用点（`udp.rs:125` `tcp.rs:117` `doh.rs:159,189` `dot.rs:138` `quic.rs:113`） | 每 NS 一条 interval task，JoinHandle 丢弃 → **无 join、无停机、无泄漏可见**；且在**配置期**就起（`from_config` 内） | 清理周期改 `Scheduler::every` 或 `FxScope::spawn`，并把启动时机挪到 feature `start()` | `std_ext::scheduler::Scheduler::{new(:221), every(:269), tick(:327), close(:428), panic_count(:462), worker_passes(:467)}`（`tick` 确定性驱动 + `worker_passes` 零自旋证据）；`skeleton_infra::fx::FxScope::{spawn(:264), shutdown(:297), in_flight(:258)}` + `expect_idle(:368)`；`skeleton_infra::shutdown::ShutdownCoordinator::{register(:298), shutdown(:348)}` | 可动 | P1 | M |
| 3 | 缓存控制-失效模型收缩 | `cache_controller.rs:196-198` | `take` 后立即还原 → 收缩是**空操作**，只剩 `shrink_to_fit`；Go 的 dirtyips 后台分批迁移（`cache_controller.go:130-215`）缺失；`high_watermark` 收缩后不重置（Go `:158`） | 收缩改真换 map + 后台分批迁移（或先只修 `high_watermark` 重置 + 去空操作）；迁移批借用池化域 | `skeleton_infra::pool::PooledThreadPool::{new(:84), mem_pool(:114), threads(:119), borrow_timeout}`（worker 内借缓冲跑 → RAII 还）；`PoolBase::{metrics(:161), subscribe_audit(:236)}` 做水位/审计 | 可动 | P3 | M |
| 4 | 缓存控制-容量/TTL 替件 | `cache_controller.rs:47` | 无容量上界的 `HashMap`（Go 同样无界 → **不得**改 LRU 淘汰以免破坏 Go 对齐）；`TtlCache` 单 TTL+过期即删，与"A/AAAA 双族独立 TTL + stale 宽限 + 负缓存"不等价 | **不整体换**；只借容量语义与 `expired()` 计数；过期策略留主仓自持 | `std_ext::cache::LruCache::{new(:346), insert(:354), get(:361), peek(:367), pop_lru(:391), capacity(:411)}`（满逐 LRU 尾、**被逐者静默丢弃**需 `pop_lru` 才可见）+ `TtlCache::expired(:590)` fail-visible 计数 | 可动 | P3 | S |
| 5 | hosts 匹配-系统 hosts 语义 | `hosts.rs:103-106`（回退 `DomainRule::domain`）+ `hosts.rs:201-227`（`matcher_rules` 空） | **与 Go 不一致**：Go `readSystemHostsFrom` 用 `Domain_Full` 精确匹配（`infra/conf/dns.go:456`），Rust 系统 hosts 走后缀匹配 → 子域误命中 | 系统 hosts 也注册 `Full`（向 Go 对齐）；配置 hosts 已由 `jsonconf.rs:625` 走 `Domain_Full`，无需动 | 无需 udf（Go 对齐面） | **不可动语义，只能向 Go 对齐** | P2 | S |
| 6 | hosts 匹配-启动期构建 | `hosts.rs:107-118`、`jsonconf.rs:299` | MPH 构建集中启动期，规则量（geosite 展开）大时启动 CPU 高 | 构建移入线程池互喂（worker 内借缓冲跑 → RAII 还）；复用 `MphDomainMatcherFactory` 共享缓存（`xray-geodata/src/matcher/domain.rs:348`）避免重复构建 | `skeleton_infra::pool::PooledThreadPool`（同上）；`skeleton_infra::memgov::MemoryPool::{acquire(:487), metrics(:562)}` 做缓冲池 | 可动（启动期） | P2 | M |
| 7 | hosts 匹配-查询期分配 | `hosts.rs:135`（`to_lowercase` 分配）、`hosts.rs:138`（`entries` Vec） | 每查询 2 次小分配 | 复用一个 scratch buffer / 免分配 lower（`to_ascii_lowercase`） | 无需 udf | 可动 | P3 | S |
| 8 | fakedns 反查（每连接路径） | `fakedns/mod.rs:184`（`iter().find` 全表扫）→ 调用点 `xray-app-dispatcher/src/default.rs:592` | **O(n)**；池满 65535 时每连接 O(65535) 扫；Go `GetKeyFromValue` O(1)（`fake.go:145`） | 增 `ip → domain` 反向索引（域→IP LRU 与反向表同生命周期淘汰）；查询期零额外分配（禁每连接 String 分配） | **udf 无对应件**：`std_ext::cache::LruCache` 只有键→值、无值→键反向索引 → 自建双索引或向 udf 提需求（§7 U3） | **可动但禁引入额外分配**（每连接路径） | P2 | M |
| 9 | fakedns 分配冲突探测 | `fakedns/mod.rs:153`（`iter().any` 全表扫） | O(n) 分配；Go `PeekKeyFromValue` O(1)（`fake.go:127`） | 同 #8 的反向索引直接复用（探测即查反向表） | 同 #8（udf 无件） | 可动 | P2 | M |
| 10 | fakedns 容器替换 | `fakedns/mod.rs:17,72,80,129`（第三方 `lru` crate 0.18；`with_config` 先建 unbounded） | 第三方件 + 无界中间态窗口 | 换 `std_ext::cache::LruCache`（cap 必填、满逐尾），并去掉 unbounded 中间态 | `std_ext::cache::LruCache::{new(:346), insert(:354), get(:361), peek(:367), pop_lru(:391), len, capacity(:411)}`（**并发面**：`&mut self` 单线程，须落在既有 `Mutex<HolderInner>` 内） | 可动 | P3 | S |
| 11 | fakedns 时间源 | `fakedns/mod.rs:300-303`（`SystemTime::now()`） | 时间源直读（IP 派生依赖墙钟，与 Go `UnixMilli` 同语义，**不可改派生算法**） | 仅把"取当前时间"抽出可注入点（派生算法逐字不动） | `skeleton::clock::Clock::now_system()`（`skeleton/src/clock.rs:67`，挂钟面） | 可动 | P3 | S |
| 12 | 上游超时-整查询 deadline | `nameserver/mod.rs:72,176-180`（`Client.timeout` 死字段） | 查询路径无整体 deadline；分段超时叠加（`doh.rs:221-345` 五段）总时长可达 5× 单段；Go 是单 deadline（`nameserver.go:167`）+ DoH 5s 兜底（`nameserver_doh.go:166-172`） | 让 `Client.timeout` 真正生效（查询级 deadline 贯穿到各 `query_once`）；DoH 兜底 5s 与 Go 对齐 | `skeleton::clock::Clock`（deadline 计算基准）；**不能用** `std_ext::retry`（同步件，§3.5） | 可动 | P1 | M |
| 13 | 上游重试 | `dot.rs:225-250`、`tcp.rs:205-231` | 手写"重连再试一次"：无退避、无次数上限、无预算、无错误分类（超时/连接失败/协议错一视同仁） | 收敛为统一 async 重试：退避计算用 `backoff_delay`，策略面（次数/预算）取 `RetryPolicy` 语义，错误分类复用 `DnsError` 现有变体 | `std_ext::backoff::backoff_delay(attempt, base, max)`（`std-ext/src/backoff.rs:32`，纯函数，可直接用于 async）；`std_ext::retry::RetryPolicy::{new(:106), with_budget(:129)}` 仅取参数语义（`retry/retry_if` 是同步件不可直接用）→ 执行环保留主仓 async 版，或向 udf 提 async 需求（§7 U3） | 可动 | P1 | M |
| 14 | 重试件重复实现 | `xray-common/src/retry.rs:74`、`xray-transport/src/retry.rs:47` | 主仓两套自造重试 + DNS 手写重连重试 = 三套，语义不一 | 收敛为一套（退避算式统一走 `backoff_delay`；预算/次数统一走 `RetryPolicy` 语义） | `std_ext::backoff::backoff_delay`；`std_ext::retry::RetryPolicy` | 可动 | P3 | M |
| 15 | 观测-结构化 DNS 日志 | `app-log/src/instance.rs:92-130,205-209,536-540,685-691`（`DnsLog`/`DnsStatus` 齐备）；`app-dns` 侧**零生产方** | Go `nameserver_cached.go:36,42,117` 的 cache HIT / OPTIMISTE / queried 三态 + Elapsed 全缺；`enable_dns_log` 开关形同虚设 | app-dns 在命中/过期/上游失败三处产 `DnsLog` → 走 app-log `LogEntry::Dns`；target 统一 `xray_frame::dns` | `skeleton_infra::logx`（唯一入口 + `mask_secrets(:157)`）；`embed_event!` 字段化禁格式化纪律（target 规范源） | 可动 | P2 | M |
| 16 | 观测-指标 | `xray-app-metrics/src/metrics.rs`（零 `dns` 命中）、`xray-app-stats`（零 `dns` 命中） | DNS 查询量/命中率/上游错误率不可见 | 加 DNS counter（query / cache hit / upstream error），经 app-stats 注册后由 app-metrics 暴露 | `xray_features::stats::Counter`（`features/src/stats.rs:46`）+ `get_or_register_counter(:257)`；`xray-app-stats`；埋点用 `embed_event!` | 可动 | P3 | S |
| 17 | 装配-全局共享槽 | `dial.rs:126`、`fakedns/mod.rs:29-31`（`LazyLock<RwLock<Option<Arc<..>>>>` 两处） | 进程级全局单槽 + 惰性取用 → 装配顺序隐式耦合；测试需全局串行锁（`dial.rs:136-137` `DIER_SLOT_LOCK`） | 装配集中化：显式依赖注入（能力句柄），去全局槽 | `skeleton_infra::fx::FxScope` 的能力句柄思路；`skeleton::config::ConfigPort` 装配口（`skeleton/src/config.rs:259`） | 可动 | P3 | L |
| 18 | DNS 出口双路径 | `core/outbound.rs:2036-2066`（走 `DnsService` 全套：缓存/hosts/fakedns）vs `proxy-dns/src/outbound.rs:73-99`（走 hickory `TokioResolver` 直连上游） | 同为 DNS 转发，能力不对等（一条有缓存/hosts/fakedns，一条裸 hickory）；hickory 自带缓存与重试，与主仓缓存语义叠加不可控 | 收敛为单一上游路径（统一经 `DnsService`），或明确标注 proxy-dns 路径为"裸透传"并关闭其自带缓存 | 无需 udf（属装配语义） | 可动（需 PM 决策） | P3 | L |
| 19 | 次要触点清单 | `app-router/src/router.rs:208`（IpOnDemand/IpIfNonMatch 解析）、`app-dispatcher/src/default.rs:590-599`（fakedns 嗅探）、`core/functions.rs:257-262`（router 注入 dns client）、`:302-304`（dispatcher 注入 fdns）、`:327-329`（注入 shared dialer）、`core/register.rs:299-308`（dns factory）、`:784-798`（fakeDns factory）、`xray-app-observatory/src/observer.rs:49`（`now_unix_secs` 直取 `SystemTime`）、`xray-common/src/signal/mod.rs:225`（`PubSubTopic::DnsStats` 无发布/订阅方）、`xray-transport/src/dns_skip.rs:31-81`（上游拒拨） | 观测器时间源散点；DnsStats 主题空挂；其余为功能接线点 | 观测器换 `Clock::now_system()`；DnsStats 主题若不接线则删 | `skeleton::clock::Clock::now_system()`；`xray-common/src/signal/mod.rs:225` 悬空主题清理 | 可动 | P3 | S |

---

## 5. 不能动清单（逐条理由）

| # | 不能动项 | 理由 |
|---|---|---|
| N1 | **DNS wire 语义**：`build_dns_query` 的 EDNS0 subnet 掩码（IPv4 /24、IPv6 /96，`dnscommon.rs:290-295`）、`parse_dns_response` 的 req_id 校验与"全 answer TTL 参与 min"（`:322-364`）、TTL=0→1s 提升（`:337`）、`build_dns_response` 的 QR/AA/RA + 回显 RD 组合（`dns_message.rs:176-181`）、`build_ip_response` 的 0xC00C 压缩指针（`:236-239`） | 与 Go 逐字节对拍（Go `app/dns/dnscommon.go:91-107,212-227`、`common/protocol/dns`）；改动即破互通。**只允许加对拍 fixture，不允许改字节** |
| N2 | **hosts 匹配语义**：Full/Domain/Substr/Regex 前缀族 + `geosite:` 展开 + 配置 hosts 的 `Domain_Full` 默认 | Go `infra/conf/dns.go:254-266` + `app/dns/hosts.go:34-56`；语义族与默认值是兼容契约。§3.3 的系统 hosts 偏差**唯一允许方向是改成 Full**，不得反向扩展 |
| N3 | **fakedns 的 Go 对齐行为**：IP 池 CIDR 语义、`lru_size < 2^rooms` 约束（`fakedns/mod.rs:115-118` ↔ `fake.go:107-111`）、IP 派生算法（`ts_to_ip` + 墙钟毫秒派生，`fakedns/mod.rs:206-220`）、fake IP TTL=1（`nameserver/fakedns.rs:157` ↔ Go `fake.go` FakeDNSServer）、`fakedns`/`fakedns+others` 协议名与 dispatcher 兜底改写（`app-dispatcher/src/default.rs:549,595`） | 客户端/服务端双向依赖：fake IP 池两端必须一致；派生算法改动会让既有 fake IP 语义漂移。**只允许加索引/换容器，不改派生** |
| N4 | **DoH/DoT/DoQ 兼容面**：scheme→端口默认（https/h2c 443、tls/quic 853，`nameserver/mod.rs:342-350`）、`+local` 强制直连（`:334-340` ↔ Go `nameserver.go:51-61`）、DoH 强制 ALPN h2（`nameserver/mod.rs:363-369`）、DoQ ALPN doq（`nameserver/quic.rs:127`） | 真实公共 DoH/DoT 服务端的握手要求；改则连不上（历史：bd ypsl 4s 超时回落系统 DNS） |
| N5 | **数据面热路径**：`xray-buf` 分层 alloc/copy/pipe、`xray-transport/src/bridge.rs` splice 泵、poll/waker 语义 | CLAUDE.md §4/§5：性能锚 154-167 MB/s、vision 双 revert 史实。本报告全部 DNS 改造项**不触碰**这些文件 |
| N6 | **上游查询的防污染绕行**：`xray-transport/src/dns_skip.rs:79-81`（TUN 场景拒拨自身上游）+ `dial.rs` 的 `+local` 强制直连 | Go `localdns/client.go:99-103` 同语义；绕开会让 DNS 查询绕回自身 |
| N7 | **错误分类语义**：`DnsError` 变体集与跨层 `From` 映射（`error.rs:14-83,104-116`）、`merge_query_errors` 的 errRecordNotFound 忽略 + 同类取首 + 异类合并（`server.rs:564-608` ↔ Go `dns.go:339-361`） | Go `errors.Is`/`errors.Combine` 语义，跨层消费方（router / dispatcher / proxy-dns）依赖其分类 |
| N8 | **单飞与 stale 回源语义**：singleflight key（fqdn+族标志，`cached.rs:200`）、stale 命中即回源（`cached.rs:126-134`）、上游失败不写缓存（`cached.rs:237-239`） | Go `nameserver_cached.go:24-49` 同款；改 key 或改 stale 行为会改重复查询/命中率语义 |

---

## 6. 建议顺序与验收方式

> 每步 = 一个可独立验证的改动包；括号内是**该步的验收命令/度量**（主仓未获授权执行，此处仅给验收口径）。

**Step 0（闸门，PM 决策，非代码）**：定 udf 接线形态（§7 U1）。未过闸门的 Step 1/2/4/5/10/12/13 的"依托 udf"部分**降级为主仓自建**（结论不变，只是白拿 API 变成"参考实现"）。验收：PM 书面拍板 + 决定是否允许改 `.github/workflows`（红线）。

**Step 1 — 零风险语义/常量对齐（先做，因为不依赖 udf）**
- 修系统 hosts 匹配语义为 `Full`（§3.3 / 行 5）；核对并统一 TTL 默认常量口径（Go `features/dns/client.go:37` = 300 vs `app/dns/dnscommon.go` 兜底 600 —— **两处不同是 Go 现状，Rust 现为 `features/src/dns.rs:57`=300 与 `dnscommon.rs:184,374`=600，须按 Go 逐处对齐，不是统一成一个值**）。
- 处置 `negative_ttl_secs` 死配置：实现负缓存 TTL，或从 config 拒绝（禁静默）。
验收：`cargo test -p xray-app-dns -p xray-proxy-dns`；新增断言"系统 hosts 命中 `foo.localhost` **不**返回条目（Go 对齐）"；`cargo clippy -p xray-app-dns --all-targets -- -D warnings`。

**Step 2 — 观测面补齐（先有度量再优化）**
- app-dns 产 `DnsLog` 三态（queried / cache HIT / cache OPTIMISTE）+ Elapsed → app-log `LogEntry::Dns`；target 统一 `xray_frame::dns`；加 DNS counter（query / cache_hit / upstream_error）。
验收：端到端跑一次 DNS 查询，`access log` 出现 `cache HIT:` / `got answer:` 行且 `elapsed_ms` 非零；`enable_dns_log=true` 生效；Prometheus 端点能读到 3 个 DNS counter 增量。

**Step 3 — 死代码与重复清理（低风险，减小后续面）**
- 删/收敛 `xray-common/src/cache/mod.rs` 自造 `LruCache`（**当前无消费者**，grep 零命中）；统一两套自造重试（行 14）；`PubSubTopic::DnsStats` 悬空主题二选一（接线或删）。
验收：`cargo clippy --workspace --all-targets -- -D warnings` 绿；`cargo test --workspace --all-targets` 无回归。

**Step 4 — fakedns 性能（每连接路径，收益最大）**
- 建 `ip → domain` 反向索引，替换 `fakedns/mod.rs:184` 与 `:153` 的线性扫（行 8/9）。
验收：构造 65535 条目的池，测 `get_domain_from_fake_dns` 与 `get_fake_ip_for_domain` 的 p99（改造前后对比，目标是 O(n)→O(1)）；dispatcher 每连接路径**不得新增堆分配**（用 `alloc_counter` 或 allocation-count 断言）；`cargo test -p xray-app-dns -p xray-app-dispatcher` 全绿。

**Step 5 — 时间源注入（为 Step 6/7 铺路，且让 TTL 测试可确定）**
- 缓存/stale/fakedns 时间改注入 `Arc<dyn Clock>`（行 1/11）。
验收：TTL 过期、stale 宽限命中、stale 回源三条路径改为 `MockClock::advance` 驱动，**零真实 sleep**；旧的真等测试（`cache_controller.rs:439-458`）改为确定性断言后删除时间依赖。

**Step 6 — 后台任务托管与停机（接 udf 的最大白拿面）**
- cleanup task / serveStale pull / DoH h2 conn 三处裸 spawn 收进托管口；cleanup 启动时机从配置期挪到 feature `start()`（行 2）。
验收：停机后 `in_flight == 0`（`FxScope::expect_idle`）；重复 `start/close` 幂等；`panic_count()==0`；`worker_passes()` 在 idle 期静止（零自旋证据）。

**Step 7 — 上游 deadline 与重试收敛（正确性 + 延迟）**
- `Client.timeout` 生效为查询级 deadline；DoH 5s 兜底对齐 Go；手写"重连再试一次"收敛为带退避/预算/错误分类的统一 async 重试（行 12/13）。
验收：注入慢上游，测**整查询**墙钟 ≤ 配置 timeout（改造前分段叠加会超）；退避时间线用 `MockClock`/可控时钟断言（不真等）；非重试类错误（NXDOMAIN / RCODE）**不得**触发重试（计数断言）。

**Step 8 — 缓存结构与容量（最后做，Go 对齐约束最强）**
- 修收缩空操作 + `high_watermark` 重置 + dirtyips 风格后台迁移（行 3）；容量上界**不接**（Go 无界，N1 语义约束）。
验收：构造"峰值 20000 → 清理后 500"的缓存，断言内存回落且**热点键不被误删**（迁移期读不丢）；Go 对拍：同查询序列下缓存命中/未命中判定一致。

**Step 9 — 装配与出口路径收敛（PM 决策项，最后）**
- 全局共享槽去全局化（行 17）；DNS 双出口路径二选一（行 18）。
验收：多实例并行装配测试不再需要全局串行锁；两条 DNS 出口的行为差异有明确文档与对拍测试。

---

## 7. 未决点（需 PM / 用户裁决，非工程可自决）

- **U1（最高优先，闸门）udf 接线形态**：udf-frame 是独立 git 仓、不在主仓版本库（`.git/info/exclude:10`；`crates/udf-frame/Cargo.toml` 自带 `[workspace]`），且 **udf-frame 根无 `[package]`** → cargo git 依赖无法指向其子包（memory 铁律）。主仓 `crates/` 零 udf 依赖、CI 无 udf 克隆步骤。可选形态：(a) 主仓 `Cargo.toml` path 依赖到 `crates/udf-frame/{std-ext,skeleton,skeleton-infra}` + CI 克隆 udf 到该路径（**动 `.github/workflows` = CLAUDE.md §4 红线，须单独 commit + 全量验证报告**）；(b) 先按 `udf-frame/docs/PUBLISHING.md` 发布到 crates.io，主仓改 version 依赖（发布动作归用户，且 `udf-std-ext`→`udf-skeleton` 有索引可见性时序）；(c) 单 crate 门面改造。**在 U1 落地前，所有"A 类接线"只能按"参考实现"用，主仓自建等价物。**
- **U2 udf cache 的并发面缺口**：`std_ext::cache::{LruCache,TtlCache}` 是 `&mut self` 单线程（`std-ext/src/cache.rs:437` 明示"并发另批"）；主仓 DNS 缓存被多线程共享（`RwLock<HashMap>`）。选型：(a) 主仓自包 `RwLock<Mutex<TtlCache>>`（读并发退化为串行，DNS 查询面可能不划算）；(b) 向 udf 申请并发批（RwLock 化 cache）；(c) 维持主仓容器、只借 Clock。**建议 (c)**（DNS 读路径并发度比"统一件"更重要）。
- **U3 async 重试与反向索引缺件**：`std_ext::retry` 是同步件（`Sleeper` 阻塞），DNS 上游是 async → 需要"async retry"新件；`std_ext::cache::LruCache` 无值→键反向索引 → fakedns O(1) 反查需"反向索引"新件。是否向 udf 提这两个需求（提需求 vs 主仓自建）待 PM 定。
- **U4 TTL 默认值口径**：Go 侧 `features/dns/client.go:37` = 300、`app/dns/dnscommon.go` 兜底 = 600 是**两处不同值**（非笔误）。Rust 现为 `features/src/dns.rs:57`=300、`dnscommon.rs:184,374`=600（已对齐 Go）。**勿"统一成一个值"**，需确认是否维持 Go 的双值现状。
- **U5 DNS 双出口路径**：`core/outbound.rs:2036`（走 DnsService）与 `proxy-dns/src/outbound.rs:73`（走 hickory 直连）能力不对等；收敛到哪条属产品语义（proxy/dns 协议是否应享受缓存/hosts/fakedns）→ PM 裁决。
- **U6 `negative_ttl_secs` 死配置**：实现负缓存 TTL（Go `main` 无此字段，属 Rust 扩展）还是从 config 拒绝 → 二选一。
- **U7 系统 hosts 语义修正的回归面**：改为 `Full` 后，`useSystemHosts` 用户若有依赖子域命中的配置会行为变化（当前行为偏离 Go）→ 修正方向已定（对齐 Go），但需 PM 确认可作为"行为修复"合入。

---

## 8. 附：取证覆盖与未取证声明

- 实读文件：`xray-app-dns/src/{server.rs, cache_controller.rs, hosts.rs, dnscommon.rs, config.rs, error.rs, dial.rs, jsonconf.rs, fakedns/mod.rs, nameserver/{mod.rs,cached.rs,udp.rs,tcp.rs,dot.rs,doh.rs,quic.rs,local.rs,fakedns.rs}}`；`xray-proxy-dns/src/{lib.rs,handler.rs,dns_message.rs,inbound.rs,outbound.rs,config.rs}`；`xray-features/src/{dns.rs,stats.rs,feature.rs}`；`xray-app-log/src/{instance.rs,config.rs}`；`xray-app-metrics/src/metrics.rs`；`xray-app-dispatcher/src/default.rs`；`xray-app-router/src/router.rs`；`xray-app-observatory/src/observer.rs`；`xray-core/src/{functions.rs,inbound.rs,outbound.rs,register.rs}`；`xray-transport/src/{dns_skip.rs,retry.rs}`；`xray-common/src/{cache/mod.rs,retry.rs,signal/mod.rs}`；`crates/udf-frame/{std-ext/src/{cache.rs,retry.rs,scheduler.rs,clock.rs,backoff.rs,id.rs,lib.rs}, skeleton/src/{clock.rs,config.rs,pool.rs,lib.rs}, skeleton-infra/src/{fx.rs,memgov.rs,pool.rs,pooled_thread_pool.rs,shutdown.rs,journal.rs,logx.rs,audit.rs}}`。
- Go 侧原文实读：`app/dns/{dns.go,cache_controller.go,nameserver_cached.go,nameserver.go,nameserver_udp.go,nameserver_doh.go,dnscommon.go,hosts.go,fakedns/fake.go}`、`infra/conf/dns.go`、`features/dns/client.go`、`common/utils/probe_routes.go`。
- **未取证**：(1) `xray-app-dns` 之外的 DNS 触点未穷举（仅按目标清单 + grep 命中列了 §4 行 19）；(2) 未运行任何构建/测试（本任务只读）；(3) udf 三 crate 的 `examples/`、`tests/` 形态未逐个读（仅读公开 API 与文档注释）；(4) `xray-app-dns/src/nameserver/local.rs` 与 `quic.rs` 只读关键片段（DoQ 细节未逐行核）。

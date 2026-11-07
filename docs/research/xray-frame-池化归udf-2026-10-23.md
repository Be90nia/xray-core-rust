# xray-frame 视角：主仓池/缓存/有界表全量盘点 → 依托 udf 池化域（2026-10-23）

> 任务：主仓**所有池 / 缓存 / 有界表 / 连接表**逐一判定依托映射。只读深盘，零代码改动，未 commit。
> 定调依据：PM 2026-10-23 口供「连接池我们有池化管理的基本类..你可以拿去用..里面已经写好很多功能的」——判定基调 = **直接拿来用，白拿哪些功能**，不另造接缝、不另写管理面。
> udf API 全部经一手读源码核对（本次实读：`skeleton/src/pool.rs` 全文、`skeleton-infra/src/pool.rs:1-263`（PoolBase 面）、`skeleton-infra/src/memgov.rs:441-663`（MemoryPool 面）、`skeleton-infra/src/pooled_thread_pool.rs:1-133`）；ThreadPool/RejectPolicy/BoundedRegistry 面引用 PM 一手核对结论 + 机制差距文档行号。
> 红线基线：CLAUDE.md §4 十三条红线 + §5 踩坑；数据面热路径（xray-buf 分配/copy/pipe、bridge splice、btls、wire 编解码本体）**分配路径一行不动**。

## 0. 结论（首行）

主仓共盘点 **33 处池/缓存/表/有界结构**：**真·借还池 6 处**（xray-buf 分层池、ws WsConnectionPool、tuic QuinnConnectionPool、splithttp XmuxManager+ManagerPool、vless PreConnectPool、hyper-util 内置池）全部可分级接入 udf 池化域（1 处红线除外）；**注册表/缓存 15 处**多数为"注册表模型非借还模型"——不硬套 PoolManaged，改接 BoundedRegistry（fail-closed 上界）或自留+借审计面；**wire 安全反重放/原语 10 处不能动**；另纠正两处任务书预期：`xray-common cache::LruCache` **零生产调用点**（死重候选），`xray-crypto KeyCache` **不是缓存**（无状态工厂）。最高价值三步：①fakedns 占位 unbounded 收口（S）②ws/tuic 两池 PoolBase 组合白拿管理面（M）③PooledThreadPool 互喂试点 geodata 启动期加载（M）——三步全部不碰热路径。

---

## 1. 取证口径与方法

| 项 | 值 |
|---|---|
| 范围 | 任务书 15 族候选 + 自查补漏（fakedns/observatory/antireplay/SessionHistory/ReverseRegistry/commander/signal Semaphore/hyper-util 等） |
| 工具声明 | read/grep 直读约 25 个一手文件（逐池读实现体非仅声明）；serena 不适用（跨 crate 批量结构盘点，非单符号导航）；cbm 图谱未用于池实现体（需一手行号） |
| udf 侧 | skeleton/pool.rs 全文 + infra pool.rs/memgov.rs/pooled_thread_pool.rs 关键面一手实读；ThreadPool/RejectPolicy 引 PM 一手核对（机制差距文档 §1.2.3 行号互证） |
| 未取证 | stats channel blocking 重试的 spawn 失败路径；XmuxClient open_usage 全量读路径；均标注于 §10 |
| 判定三选一（PM 定调） | ①直接 `impl PoolManaged`（管理面三挂点白拿，池体自留）②`PoolBase` 组合（公共逻辑写一次）+ 自留特化面 ③不能动（红线） |

---

## 2. 现状结构总览（谁调谁）

```
数据面热路径（红线）
  xray-buf/alloc.rs ──(alloc/release)──> copy.rs:59 / pipe.rs:953 / readv.rs:658
        ↑                                   ↑
        └── mux reader.rs(P1-1 直读测试 :369-387 钉死 payload 落 8KB 层)
  transport/bridge.rs:45 bridge_connections（splice 泵，1967 行）——三轮挂死战场

客户端连接池族（拨号面，非每-buffer 路径）
  ws register.rs:284-330 ──> WsConnectionPool(global_pool, pool.rs:161) + replenish burst(fanout=3 :330)
  tuic dispatcher ──> QuinnConnectionPool(pool.rs:97, single-flight dial_locks :101-103)
  vless outbound/preconnect.rs:73 PreConnectPool ──> 拨号前预热（FIFO Vec）
  splithttp mux.rs:267 ManagerPool ──> XmuxManager(mux.rs:146) ──> xmux_clients Vec<Arc<XmuxClient>>
  splithttp h1_conn.rs:23 ──> hyper-util 内置池（第三方）

注册表/缓存族（管理面/观测面）
  proxyman inbound/mod.rs:67 InboundManager / outbound/mod.rs:77 OutboundManager（配置面 tag→handler）
  proxyman worker.rs:498 UdpWorker.active_sessions（运行时，reclaim :649）
  app-dns cache_controller.rs:46 CacheController（TTL+收缩 :20-27 常量）+ fakedns/mod.rs:80 Holder(lru crate)
  app-stats online_map.rs:40 / counter.rs:20 / channel.rs:70 / manager.rs:27（观测面三表+通道）
  geodata weak_cache.rs:38 WeakCacheMap（Weak 注册表）
  tls tls_session_cache.rs:63 进程单例（btls 邻接）

wire 安全/原语族（不能动）
  xray-common antireplay MapFilter（双池轮换）<── vmess aead/mod.rs:534 + ss2022 replay.rs:25-27
  vmess validator.rs:61 TimedUserValidator / encoding/server.rs:57 SessionHistory
  vless validator.rs:75 MemoryValidator / encryption/mod.rs:691-696 ServerSession 表
  ss validator.rs:91 Validator(seen_ivs 已封顶 :100-102)；trojan validator.rs:82 Validator(DashMap)
  mux session.rs:112-132 SessionManager（HashMap<u16, Arc<Session>> + size 原子镜像）
  common drain/mod.rs:41 / dice.rs:11 / uuid/mod.rs:14 / signal/mod.rs:360 Semaphore
```

---

## 3. 改造空间清单表（主表）

> 列：面 | 现状（file:line）｜并发与容量语义｜已知历史坑｜依托 udf 件（**白拿功能**加粗）｜接法｜热路径？｜批次｜规模

### 3.1 借还模型池（真池）

| # | 面 | 现状 | 并发/容量语义 | 历史坑 | 依托 udf 件（白拿） | 接法 | 热路径 | 批次 | 规模 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | xray-buf 分层池 | buf/alloc.rs:26 TIER_SIZES[2K,8K,32K,128K]、:31 TLS_MAX_PER_TIER=8、:34 SHARD_COUNT=8、:38 SHARD_MAX_PER_TIER=64、:41 SWEEP 60s；alloc :122 / release :167 | TLS thread_local + 8 分片 parking_lot Mutex；有界（每分片每层 64）；溢出直丢；清零归还 | **from_vec 假池污染**（假块标 Pooled 回池粘死 worker 线程→Frozen 语义修复）；性能锚 154-167 MB/s | ——管理面只读侧挂是唯一接口：**PoolBase 只读水位**（不碰分配） | ③不能动（分配路径）；管理面侧挂另裁（§6.1） | **是（红线）** | P3+ 单独裁决 | — |
| 2 | ws WsConnectionPool | ws/pool.rs:161 struct；HashMap<PoolKey,VecDeque<PoolEntry>>（tokio Mutex 全锁）；config :119-132（max_idle_per_key=12/TTL 10s）；probe :145（noop-waker poll_read 活性探测）；try_acquire :217；release :249（池满静默 drop）；begin/end_preconnect :266-285；global 单例 :289；一次性 init_config :205 | 每 key FIFO 上限 12 + in-flight 记账；TTL 10s 头部扫除；**无归还路径**（预连接池：只有 replenish 存入） | 2026-10-16 复用死连接事故（CF idle 切断，TTL 30s 不够→10s+probe 双保险）——事故不可观测（无计数无审计） | `PoolBase` 组合（接法②）：**resize 事前校验**（init_config 一次性→动态化）、**水位线 O(1) Copy**（idle+inflight=borrowed）、**OverflowDropped 计数**（release 池满 drop 从静默变留痕）、**审计 seq 环**（借出/归还/溢出/调参全事件） | ② | 否（拨号面） | P1 | M |
| 3 | tuic QuinnConnectionPool | tuic/pool.rs:39-56 PoolKey=(addr,sni,alpn)；:97 struct（parking_lot RwLock<HashMap<PoolKey,PooledConnection>>+single-flight dial_locks）；get_or_connect :134（快路径读锁 clone→锁外 is_alive :70-73→double-check→timeout 拨号）；remove :216 / clear :221 | **每 key 单条**（注册表+老化，非 N 条借还）；无 key 数上限；AtomicBool is_closed（wfx8-2） | **bd 4zjf**：alive 检查持锁跨 await→pool-wide stall，已修（临界区零 await）；**bd 5poj**：N-1 孤儿连接，已修（single-flight） | `PoolBase` 管理面（接法②）+ key 上限用 `BoundedRegistry` 思路（**fail-closed 插入**、**确定序迭代**）；白拿 **resize 校验**、**审计**、**溢出计数**（clear 驱逐留痕） | ②（结构性冲突说明见 §4.1） | 否（拨号面） | P1 | M |
| 4 | splithttp XmuxManager | mux.rs:146 struct（Mutex<Vec<Arc<XmuxClient>>>）；get_xmux_client 4 分支 :230（retain 清理→空则建→connections 配额→concurrency 过滤+随机选）；is_unreusable :121 | 容量=connections rand 采样（构造期冻结，0=无限）；复用度=left_usage 原子 | 无在案事故；Go 1:1 翻译 | 自留池体；可借 **审计事件流**（PoolAuditEvent 形态参考）但收益低 | ③不值得（resize 与构造期 rand 冻结语义冲突） | 否（拨号面） | — | — |
| 5 | splithttp ManagerPool | mux.rs:267-312（PMutex<HashMap<String, Arc<XmuxManager<C>>>>；get_or 无界 insert） | 进程级 per-dialerConf 缓存；**key 空间无界**（String key，Go globalDialerMap 同构但 Go 依赖配置有界） | 潜在：多 outbound 动态 dest 时条目只增不减 | `BoundedRegistry<K,V>` 直换（接法①）：**fail-closed 插入**（max 封顶）、**iter 升序确定序**（诊断友好）；白拿 **Eviction 拒绝显式化** | ① | 否 | P2 | S |
| 6 | vless PreConnectPool | vless/outbound/preconnect.rs:73-76（Mutex<PoolInner>；Vec FIFO :81；count/ttl config :54-56 默认 0=关）；acquired_total :204 已有计数 | FIFO 有界（count）；TTL 30s | 无在案事故 | `PoolBase` 组合（接法②，最小版）：白拿 **溢出计数**+**水位线**；acquired_total 对齐 PoolMetrics.borrowed 语义 | ② | 否 | P2 | S |
| 7 | hyper-util 内置 H1/H2 池 | splithttp/h1_conn.rs:23-24（pool_idle_timeout/pool_max_idle_per_host 配置透传） | 第三方内部管理 | — | 无（第三方件） | ③不能动（外部 crate 内部） | 否 | — | — |

### 3.2 注册表 / 缓存（非借还模型）

| # | 面 | 现状 | 并发/容量语义 | 历史坑 | 依托 udf 件（白拿） | 接法 | 热路径 | 批次 | 规模 |
|---|---|---|---|---|---|---|---|---|---|
| 8 | proxyman InboundManager / OutboundManager | inbound/mod.rs:67-76（RwLock<ManagerState{tagged HashMap, untagged Vec}>）；outbound/mod.rs:77-87（+default_handler）；重名显式错 | 配置面注册表：量=配置条目数（个位数）；无淘汰语义（handler 生命周期=配置生命周期） | 无 | `BoundedRegistry` 的 **fail-closed 插入纪律**仅作参照；实际不值得换（量太小，换件无收益） | ③不值得 | 否 | — | — |
| 9 | proxyman UdpWorker.active_sessions | worker.rs:498（RwLock<HashMap<SocketAddr,Arc<UdpSession>>>）；reclaim_inactive_sessions :649（TTL 扫除已有） | 运行时表：TTL 有界但**无并发条目硬上界**（扫除周期内可堆积） | 洪水面：UDP 源地址伪造可堆条目（有 TTL 缓解） | `BoundedRegistry` 容量界 + 外挂 TTL reclaim（接法②）：白拿 **fail-closed 插入**（拒绝显式计数）、**iter 确定序** | ② | 否（UDP 会话面，非 buf 热路径） | P2-P3 | S |
| 10 | app-dns CacheController | cache_controller.rs:46-73（ips: RwLock<HashMap<String,Arc<Record>>> + high_watermark :51-52 + broadcast 256 + single_flight tokio Mutex<HashMap>）；收缩常量 :20-27（512/10240/0.65，Go 对齐）；cleanup task :438 | TTL 缓存+双记录（A/AAAA）合并+COW（Arc::make_mut）；serve_stale 语义；后台 300s 清理 | 无在案事故 | 自留（Go 对齐收缩算法是业务语义）；white-list：**high_watermark 读数已对齐 PoolMetrics.watermark 精神**，可后续统一读数形状 | ③不值得（resize/TTL/serve_stale 与 PoolManaged 模型结构性不同） | 否 | — | — |
| 11 | app-dns fakedns Holder | fakedns/mod.rs:80（**占位 `lru::LruCache::unbounded()`**）→ initialize() :121 换成有界 `LruCache::new(NonZeroUsize)`；pool 初始化路径 :233-236 必调 initialize | LRU 有界（lru crate，O(1)）；但**构造→initialize 窗口内无界** | 风险窗小但真实：若新增构造路径漏调 initialize 即回无界 | 无需 udf 件——收口即可：cap 前移到构造参数（S 级）；纪律对齐 udf **构造期 panic fail-fast**（恒不合法配置必是 bug） | ③不值得换件（lru crate 已 O(1)）；做占位收口 | 否 | **P1（最便宜的安全修）** | S |
| 12 | xray-common cache::LruCache | cache/mod.rs:11-15（HashMap+Vec order；**get 是 O(n) retain** :30-34） | 单线程 &mut；容量淘汰 while 循环（order.remove(0) O(n)） | **零生产调用点**（grep 全仓 `LruCache::new|unbounded` 仅命中本文件 tests :109-227 与 fakedns 的 lru crate）——死重 | 若未来需要：`std_ext::cache::LruCache`（cache.rs:339，O(1) arena 双向链零 unsafe，同为单线程 &mut，API 同构）直接覆盖，**删本地副本**；今日最佳动作=删 | ①换件/删 | 否 | P1（顺手） | XS |
| 13 | xray-crypto KeyCache | key_cache.rs:19-23（`_private: ()` 无状态；create_* 纯工厂） | 无状态（**不是缓存**——任务书预期纠正） | — | 无依托点 | — | 否 | — | — |
| 14 | geodata WeakCacheMap | weak_cache.rs:38-40（Mutex<HashMap<K,Weak<V>>>；load 时惰性清 slot :62-70；cleanup_expired :115） | Weak 注册表：容量由外部 Arc 存活决定（自清理，无显式上限）；全局单锁 | 作者自注 :26-28：热点可升级 arc_swap/dashmap shards（现 hit 每路由一次 lock 可接受） | 模型特异（弱引用生命周期≠借还/注册表）——BoundedRegistry/PoolManaged 均不适配 | ③不能套（模型冲突）；保持自观察 | 路由查表（一次 lock/查询，可接受） | — | — |
| 15 | tls tls_session_cache | tls_session_cache.rs:63-66（LazyLock 进程单例；StdMutex<HashMap<String,CacheEntry>>；TTL 24h :46-48 惰性清）；写入走 B2 修复的 NST 回调（:13-40 根因史） | 进程单表；**无条目上限**（server_name 空间驱动，实际小）；同 key 后写覆盖 | bd 0kj 系（handshake session 无 ticket 陷阱）——已修，写入点=唯一正确时机 | **btls 邻接红线**：逻辑一行不动（SSL_SESSION 句柄/回调时机是根因修复产物）；可选只挂**条目计数读数** | ③不能动（逻辑） | 否（lookup 极少） | — | — |
| 16 | app-stats OnlineMap / Counter / StatsChannel / Manager | online_map.rs:40-43（Mutex<HashMap> refcount + AtomicI64 count）；counter.rs:20-22（AtomicI64）；channel.rs:70-92（订阅 Vec + mpsc buffer_size :55-58 至少 1，blocking 模式 spawn 重试 :121+）；manager.rs:27-32（三张 RwLock<HashMap>） | 注册表/通道；观测面 | lib.rs:31 自注「Channel 简化版，等价语义更少抽象」 | observe 件设计输入（P4 提炼候选）；SyncStore 快照态候选（盘点已判 A，P3）——**不是池，不接池化域** | ③（观测域另有归属） | 否 | P3 | — |
| 17 | observatory healthping 环形采样 | healthping_stats.rs:42-43（rtts Vec+idx 固定 cap 环） | 有界环形，自管 | 无 | 无（采样环语义简单自洽） | ③不值得 | 否 | — | — |
| 18 | commander listener 队列 | server.rs:52（Mutex<VecDeque> + Notify，LISTENER_BUFFER 有界） | 有界队列 | 无 | 无（量极小） | ③不值得 | 否 | — | — |

### 3.3 wire 安全反重放 / 协议认证表（不能动）

| # | 面 | 现状 | 语义 | 接法 |
|---|---|---|---|---|
| 19 | xray-common antireplay MapFilter | antireplay/mod.rs（双池轮换；默认 120s :79-81；**区间内无容量淘汰是特性** :110-117 测试钉死） | 反重放窗口，Go `antireplay.NewMapFilter` 对齐 | ③不能动（wire 安全语义） |
| 20 | vmess AuthIDDecoderHolder + replay_filter | aead/mod.rs:512-515（Mutex<HashMap<[u8;16],Item>> + MapFilter::new(120) :534） | AuthID 反重放（认证安全） | ③不能动 |
| 21 | vmess TimedUserValidator | validator.rs:61-68（Mutex<HashMap>+behavior_seed/fused 冻结语义） | 认证凭据表（配置面但含 fuse 语义） | ③自留 |
| 22 | vmess SessionHistory | encoding/server.rs:57-60（Mutex<HashMap>，TTL 180s :73） | 会话去重（重放防护） | ③不能动 |
| 23 | vless MemoryValidator | validator.rs:75-78（双 HashMap：email_index+uuid_index，parking_lot RwLock） | 认证凭据表 | ③自留（配置面） |
| 24 | vless encryption ServerSession 表 | encryption/mod.rs:691-696（sessions HashMap + tickets Vec FIFO + lasts HashMap，后台清理 task） | 0-RTT ticket 滚动生命周期（安全状态机） | ③不能动 |
| 25 | ss Validator seen_ivs | validator.rs:91-102（Mutex<Inner>；users Vec + seen_ivs HashMap，**SEEN_IVS_CAP 已封顶** :100-104） | IV 重放防护（洪泛面已有界） | ③不能动 |
| 26 | ss2022 replay pool_a/pool_b | ss2022/replay.rs:25-27（Mutex 双 HashMap 60s 轮换，Go `NewMapFilter[[32]byte](60)` 对齐 :30） | salt 重放窗口 | ③不能动 |
| 27 | trojan Validator | validator.rs:82-85（DashMap×2） | 认证凭据表 | ③自留 |
| 28 | mux SessionManager | session.rs:112-132（tokio RwLock<HashMap<u16,Arc<Session>>> + **size 原子镜像** :130-132 + count u16）；is_full=活跃数语义（bd 4uuo，client.rs:319/:1449-1476 测试钉死）；ClientStrategy max_concurrency/max_connection :65-68 | wire 会话表（u16 id 配额） | ③不能动（mux.cool wire+carrier 判据铁律）；注意其 **size 镜像就是水位线读数的手工雏形**——P2 壳迁移时若挂审计，读数形状对齐 PoolMetrics 即可，不改表本体 |
| 29 | drain / dice / uuid | drain/mod.rs:41-43（AtomicI64 剩余排空）；dice.rs:11-13（u64 确定性骰子）；uuid/mod.rs:14（[u8;16]，Debug 脱敏 :16-17） | wire 语义原语（防时序指纹/负载均衡/认证凭据） | ③不能动（memory 铁律：认证凭据实现不可换） |
| 30 | signal Semaphore | signal/mod.rs:360-398（tokio Semaphore 包装；acquire 无超时 :373-381，closed 时 `.expect` panic） | 并发原语（非池） | ③自留（tokio 成熟件）；**纪律点名**：`acquire` 无超时+expect panic 是新代码反模式——新代码按 udf D21 纪律走显式超时路径（acquire_timeout 或 try_acquire+deadline） |
| 31 | vless ReverseRegistry | reverse.rs:55-57（Arc<RwLock<HashMap<String,PortalConfig>>>） | 配置面注册表 | ③自留 |
| 32 | transport/features 注册表族 | dialer.rs:35/:76、listener_registry.rs:35/:80/:118、features/registry.rs:63（type_url 工厂） | 装配面静态注册表 | ③自留（盘点已判 C，plugin 件原型） |
| 33 | reverse Portal/Bridge 16KiB pipes | worker.rs:134（PIPE_LIMIT=16*1024）、:136-138、:177-178、:531-532、:558-559 | **Go `WithSizeLimit(16*1024)` 1:1 尺寸语义**（wire 邻接） | ③不能动（尺寸=协议行为）；pipe 本体属 xray-buf 数据面 |

---

## 4. 接法三选一：结构性冲突说明

### 4.1 tuic QuinnConnectionPool —— 借还模型 vs 注册表模型（接法②的特化面缺口）

- **冲突点**：PoolManaged 契约假设「N 个同类对象借还」（Tuning=max/idle_cap，RAII 归还裁决）。tuic 池实际是 **HashMap<PoolKey, 单条 PooledConnection>**：每 key 至多 1 条、无归还（连接断开=失效条目被下一次 get_or_connect 原地替换）、生命周期由 quinn 句柄决定（close_reason 判断在锁外，bd 4zjf）。
- **替代接法**：不硬实现借还语义。①挂 `PoolBase` 作**只读账本+审计**（借出≈复用次数、溢出≈clear 驱逐数），`resize` 的 max 解释为 **key 空间上界**（插入前 fail-closed 检查，超限拒绝+计数——行为对齐 BoundedRegistry::insert :73 fail-closed）；②若未来一条 key 需要 N 条连接（QUIC 连接迁移/多路径），届时才值得真正 `impl PoolManaged`。
- **特化面还差什么**：dial_locks single-flight 记账并账本（in-flight 计数对齐 ws 池 begin/end_preconnect 形态）；clear() 驱逐的审计事件（现在 clear 静默关连接 :221-225）。

### 4.2 ws WsConnectionPool —— 模型兼容，特化面缺口清单（接法②）

- **兼容性**：预连接池天然是借还模型（acquire=try_acquire，return=replenish 存入，池满 drop=OverflowDropped）。唯一错位：**归还方向不对称**（会话用过的连接永不回池，只有补拨任务入池）——PoolBase 的 note_return 语义照用（replenish 存入即「新建后入闲」，非「归还」），账本口径在文档写死即可。
- **白拿明细**：`init_config` 一次性语义（:205-212「首个生效，后续 no-op」）→ 换 **resize 事前校验**后变运行时动态调参（PoolResizeError 拒绝路径零状态变更）；`release` 池满静默 drop（:259-261）→ **OverflowDropped 计数**；2026-10-16 死连接事故形态（probe 丢弃死连接 try_acquire :231-241）→ **审计事件**（探针丢弃亦可入环留痕）。
- **特化面自留**：PoolKey 结构、VecDeque+TTL 头扫、probe_conn_alive、preconnect in-flight 双界（idle+inflight≤max）。

### 4.3 注册表族（#8/#9/#31）—— BoundedRegistry 适配判据

`BoundedRegistry`（memgov.rs:50-118，new :58 max==0 panic、insert :73 fail-closed、iter :116 升序确定序）适配条件 =「**key 空间可能被运行时输入撑大 + 需要显式拒绝而非静默淘汰**」。#9 UDP active_sessions 满足（源地址空间无界）；#8/#31 不满足（配置面量小）——不换。

---

## 5. udf 池化域白拿能力 → 主仓对应池映射表

> 每行：能力 | udf 出处 | 主仓受益池 | 受益形态

| 能力 | udf 出处（file:line） | 主仓受益池 | 受益形态 |
|---|---|---|---|
| resize 事前校验两档出口（构造 panic fail-fast / 运行时显式 Err，禁静默钳位） | skeleton/pool.rs:64-76（PoolResizeError Copy+Display 带现场）+ infra/pool.rs:51-60（validate 纯函数零锁零分配） | ws 池（init_config 一次性→动态化）、tuic 池（key 上界调参）、vless PreConnectPool | 校验 |
| 水位线 O(1) Copy 读数（watermark=borrowed/max，>1.0 合法中间态不钳位） | skeleton/pool.rs:42-54（PoolMetrics 核心形）+ infra/pool.rs:170-183（单次取锁+Copy） | ws/tuic/preconnect 全部 B 类池；对照：mux size 镜像（session.rs:130-132）、dns high_watermark（cache_controller.rs:51-52,88-91）已是手工雏形 | 读数 |
| 审计 seq 单调环（Borrowed/Returned/OverflowDropped/Resized/ResizeRejected；空洞=溢出显式证据） | skeleton/pool.rs:104-136（Kind/Event/Ticket #[must_use] Drop=关流）+ infra/pool.rs:38（AUDIT_RING_DEFAULT_CAP=1024）/:235-262（gate 快路径+环+seq，热路径禁格式化） | ws（死连接事故可观测化）、tuic（clear 驱逐留痕）、PooledThreadPool 试点 | 审计 |
| 溢出丢弃计数（禁静默：池满=丢弃+dropped_overflow+1） | infra/pool.rs:216-234（note_return 返回留存/丢弃裁决，借出 0 时归还=记账 bug fail-fast） | ws release 静默 drop（:259-261）、MemoryPool 采纳 | 溢出 |
| RAII 归还裁决（Drop 即还；归还永不阻塞永不报错） | memgov.rs:609-660（PoolGuard Deref/DerefMut+Drop：槽满=析构+配额回吐+notify） | 装配层新池；PooledThreadPool 任务闭包 | 归还 |
| 工厂锁外构造 + panic 配额回滚 + 唤醒等待者 | memgov.rs:487-520（catch_unwind→created-=1→notify_one→resume_unwind） | ws replenish 拨号任务记账（begin/end_preconnect 同构）、MemoryPool 采纳 | 纪律 |
| 借出超时必填（D21：无默认无限等） | memgov.rs:487（acquire(timeout) 逐调用必填，condvar 零自旋 park 到期限）+ pooled_thread_pool.rs:84（borrow_timeout 构造期必填） | 反模式矫正：signal Semaphore::acquire 无超时（signal/mod.rs:373-381） | 纪律 |
| 拒绝策略四件套（Abort/CallerRuns/Discard/DiscardOldest；on_reject 锁外；PoolHandle 不暴露 execute 封死自指递归） | infra/pool.rs:403-459 + PM 一手核对 | ThreadPool 承载 geodata/规则匹配 | 拒绝 |
| 优雅缩容（退出令牌，手上有任务必跑完，零空转自灭；resize 补建即生效） | infra/pool.rs ThreadPool（PM 一手核对；契约语义 skeleton/pool.rs:137-168「缩容不夺借出」） | ThreadPool/PooledThreadPool；对照：ws 池缩容时在池连接自然 TTL 老化 | 缩容 |
| 借空=Discard 等价（任务体丢弃+borrow_rejected 计数，与提交侧 rejected 两本账不混） | pooled_thread_pool.rs:36-44（模块文档钉死四策略边界分析）/:118-124 | PooledThreadPool 互喂试点 | 溢出 |
| fail-closed 插入 + 确定序迭代 + max==0 panic | memgov.rs:50-118（BoundedRegistry；Eviction Reject/PopFirst :18-29） | tuic key 上界、xmux ManagerPool、proxyman UDP active_sessions | 上界 |
| 停机注册编排（注册窗/编排窗互斥、串行序、panic 隔离、超时=放弃等待） | infra/shutdown.rs:257+（ShutdownCoordinator，PM 一手核对） | 各池 clear()/close() 收口（tuic clear :221、ws 全局池、stats Manager Close） | 停机 |

---

## 6. 双池互喂专章

### 6.1 分工边界：数据面池 ↔ 装配层池

| | 数据面池 | 装配层池 |
|---|---|---|
| 成员 | xray-buf/alloc.rs 分层池（TLS_CACHE+8 分片+60s sweep）；pipe（有界 PipeOption） | udf `MemoryPool<T,F>`（memgov.rs:441）、`BoundedRegistry`（memgov.rs:50）、`ThreadPool`（pool.rs:570）、`PooledThreadPool`（pooled_thread_pool.rs:67） |
| 消费方 | copy.rs:59 / pipe.rs:953 / readv.rs:658 / mux reader 直读（P1-1 测试 :369-387 钉死 payload 落 8KB 层） | 连接表/会话缓存/插件态/geodata 启动期 CPU 密集 |
| 红线 | **分配路径一行不动**：性能锚 154-167 MB/s；from_vec 假池污染史实（非池来源块标 Pooled 回池→TLS_CACHE thread-local LIFO 粘死 worker→per-node 选择性死，Frozen 语义才修掉）；vision gate 双 revert（d8562b56+a427613b） | 无红线；白拿 PoolBase 全套管理面 |
| 互喂方向 | → 装配层：**只读**（管理面侧挂：PoolBase 账本读水位/审计，P3+ 单独裁决）。装配层 → 数据面：**禁止**——「把 xray-buf 池搬进 udf 再换回来」= 伪装热路径改动（盘点文档 §4.1-1 已点名） | ↔ 装配层内部自由互喂（PooledThreadPool 借 MemoryPool 跑 CPU 任务） |

### 6.2 PooledThreadPool 与 ThreadPool 分工（谁跑什么）

| | ThreadPool（裸） | PooledThreadPool（MemoryPool×ThreadPool） |
|---|---|---|
| 任务形态 | `FnOnce()` 闭包：自带工作记忆、无需大缓冲 | `FnOnce(&mut T)`：**worker 认领任务后**从 MemoryPool 借缓冲→跑→guard Drop RAII 还 |
| 拒绝语义 | 提交侧：RejectPolicy 四件套（队列满/shutdown→RejectedTask 退还调用方） | 提交侧透传 ThreadPool 四件套；**执行侧**借空=Discard 等价+borrow_rejected 计数（**两本账不得混**，pooled_thread_pool.rs:36-44） |
| 缩容语义 | 优雅缩容（退出令牌+任务跑完） | 同 ThreadPool（threads() 面透传） |
| **适合承载**（主仓实测点位） | config 装配期散件、metrics 快照格式化、观测聚合等轻 CPU 段 | ①**geodata dat 加载/解析**（`xray-geodata/src/loader.rs:170 GeoDataLoader`、`rule_parser.rs:665`——启动期重活，解析要大 Vec）②**路由规则匹配预热**（app-router condition.rs:1735 geoip/geosite、strategy_leastload.rs:825）③**DNS 启动期规则聚合**（app-dns jsonconf.rs:215-218 all_rules/matcher_infos 构造）④批量假定解析（若未来做 fakedns 推演批处理） |
| **绝不能进** | **数据面 IO 路径**（copy/pipe/readv/bridge pump——poll/waker 语义禁改，v49/v50/v52 三轮战役）；**协议握手热路径**（TLS 握手/wire 编解码——时序敏感）；**任何借 xray-buf Buffer 的代码**（两套内存池域混用=from_vec 假池同族风险：udf 池出的 Vec 若被误标回 xray-buf 池即假块） |

### 6.3 互喂纪律三项

1. **谁借谁还**：借还只发生在任务闭包内（worker 线程栈上）——PoolGuard 持池借用引用**不是 'static**，构造上不可能跨任务 move（pooled_thread_pool.rs:7-17 模块文档钉死）；panic unwind 路径照常 Drop 归还（`tests/pooled_thread_pool.rs::task_panic_returns_buffer_and_pool_stays_usable` 钉死）。提交线程永不持缓冲。
2. **超时必填**：borrow_timeout 构造期必填无默认（:84，D21 同源）；MemoryPool::acquire 逐调用必填（memgov.rs:487）；等待 condvar 零自旋、期限到显式 Err。**禁**任何新池出现无默认无限等（signal Semaphore::acquire 是存量反模式，新代码不得模仿）。
3. **溢出可见**：三本计数各归各位——提交侧拒绝=RejectPolicy 计数；执行侧借空=borrow_rejected；归还槽满=dropped_overflow（note_return）。全部 fail-visible 禁静默丢弃。数据面池的只读侧挂**只读不写**：管理面读数可进，反向（装配层往 xray-buf 池写任何状态）禁止。

---

## 7. 不能动的清单（即便想依托 udf 也不能动）

| # | 条目 | 理由 |
|---|---|---|
| 1 | xray-buf/alloc.rs 全部（TIER_SIZES :26 / TLS_CACHE :31 / SHARDS :34 / sweep :41；alloc :122 / release :167） | 数据面热路径红线：性能锚 154-167 MB/s 不可回退；from_vec 假池污染史实；任何「搬运进 udf 再换回来」都是伪装热路径改动。唯一合法接口=P3+ 管理面**只读**侧挂（PoolBase 账本对账），且需单独裁决 |
| 2 | xray-buf copy.rs:59 / pipe.rs:953 / readv.rs:658 | 同上（pipe 有界 limit 是数据面语义，reverse 16KiB 尺寸是 Go WithSizeLimit 对齐，动=协议行为变） |
| 3 | transport/bridge.rs:45 splice 泵全路径（1967 行） | v49 丢唤醒/v50 WakerBug/v52 Windows loopback 病理三轮战役战场；poll/waker 语义禁改 |
| 4 | btls 族（btls_client.rs / btls_reality.rs）+ tls_session_cache 逻辑（tls_session_cache.rs:63-100） | 冷编红线（BORING_BSSL_ASSUME_PATCHED+5-10min）；tls_session_cache 的写入点（NST 回调）是 bd 0kj 根因修复产物，动=复用回归；udf CI 无 btls，派生即传染构建债 |
| 5 | ws/httpupgrade 握手指纹形态 | 指纹红线（池管理面可动，握手字节形态不可动——两回事，勿混淆） |
| 6 | wire 编解码本体 + 全部反重放表（§3.3 #19-#28） | Rust↔Go 互通铁律 wire 不变；反重放窗口/容量语义（如 MapFilter 区间内无容量淘汰）是**安全特性不是缺陷**，PoolManaged 的 resize/淘汰语义与之结构性冲突 |
| 7 | mux SessionManager 表本体 + u16 id + carrier 判据 | mux.cool wire + destination 域名判据铁律（memory 实测：改 carrier 形态两度证伪）；is_full 活跃数语义是 bd 4uuo 修复，勿动 |
| 8 | vision splice gate / DIRECT 切换 | 双 revert 史实（d8562b56+a427613b）；池化改造禁碰 vision gate（CLAUDE.md §5） |
| 9 | uuid/dice/drain/signal Semaphore 本体 | wire 语义原语；认证凭据实现不可换（memory 铁律）；Semaphore 是 tokio 成熟件包装，重写无收益——只借 D21 超时纪律给**新代码** |
| 10 | hyper-util 内置 H1/H2 池（splithttp h1_conn.rs:23-24） | 第三方 crate 内部，配置透传已是唯一合法接口 |
| 11 | xray-transport-tcp/register.rs | CLAUDE.md §4 红线（4 维不动） |

---

## 8. 优先级排序的改造序列（每步带验收）

| 步 | 内容 | 为什么先做 | 验收方式 | 规模 |
|---|---|---|---|---|
| **0a** | fakedns 占位收口：`LruCache::unbounded()` 占位（fakedns/mod.rs:80）改为构造期即有界（cap 前移或构造传参），消灭「构造→initialize 窗口无界」 | 全序列最便宜的安全修（S）；不碰 wire 行为（initialize 的 cap 逻辑原样） | ①新增单测：未经 initialize 的 Holder 插入超 cap 条目被淘汰；②`cargo test -p xray-app-dns` 全绿；③grep 确认 fakedns 内无 `unbounded` 残留 | XS |
| **0b** | xray-common cache::LruCache 处置：删（零生产调用点实锤）或换 `std_ext::cache::LruCache`（若 PM 保留公共 API 面） | 死重/劣质实现（get O(n)）二选一，都属白拿判据「通用件直接用 udf」 | 删路线：`cargo build --workspace` + grep 全仓无 `cache::LruCache` 生产引用；换路线：`cargo test -p xray-common` 全绿 + get/put 语义与现测试对齐 | XS |
| **1** | ws WsConnectionPool 接 PoolBase（接法②）：内嵌 PoolBase 账本，init_config→resize 动态化，release 池满 drop→OverflowDropped 计数，probe 丢弃→审计环 | 唯一有生产事故史（2026-10-16 死连接）的池——可观测化收益最直接；拨号面非热路径 | ①单测：resize 非法参数拒绝（ZeroMax/IdleCapGtMax）、metrics() 水位线断言、池满 release 后 dropped_overflow=1、审计环含 Borrowed/OverflowDropped 事件且 seq 单调；②既有 pool.rs 测试 + integration 全绿；③`cargo clippy -p xray-transport-websocket --all-targets -- -D warnings` | M |
| **2** | tuic QuinnConnectionPool 接管理面（接法②变体）：PoolBase 账本 + key 上界 fail-closed + clear() 驱逐审计；保 bd 4zjf 纪律（临界区零 await）为评审门 | 第二个真连接池；4zjf/5poj 修复在案，管理面挂账不碰锁结构 | ①单测：key 上界拒绝+计数、metrics()、clear 审计事件；②既有 pool 测试（含 dial timeout/single-flight 用例）全绿；③评审 checklist：get_or_connect 临界区无 await（对照 pool.rs:100-102 注释）；④`cargo test -p xray-proxy-tuic` | M |
| **3** | PooledThreadPool 互喂试点：geodata 加载/规则匹配（`xray-geodata/src/loader.rs:170 GeoDataLoader`、`rule_parser.rs:665`、router condition 预热）迁入 `PooledThreadPool<Vec<u8>>`（或 BytesMut 形状，**非 xray-buf Buffer**） | 启动期 CPU 密集是 PM 点名的互喂首发场景；启动期不在 IO 线程，风险最低 | ①借还配平：停机后 `mem_pool().metrics().idle+borrowed` 对账 + udf `expect_empty`/LeakGuard 断言；②正常负载 borrow_rejected=0（超时参数标定记录）；③加载耗时前后对照（同机同 dat）；④全套 32/32 零回归 + `cargo test -p xray-geodata -p xray-app-router` | M |
| **4** | 注册表上界补位：xmux ManagerPool→BoundedRegistry 直换（mux.rs:267）；proxyman UDP active_sessions 加容量界（worker.rs:498 + BoundedRegistry fail-closed，保留 reclaim） | 防御性：两处 key 空间运行时无界 | ①ManagerPool：超限插入返回显式错/拒绝计数单测；②UDP：容量界拒绝+reclaim 共存单测（reclaim 后可再插）；③`cargo test -p xray-transport-splithttp -p xray-app-proxyman` | S+S |
| **5** | 池审计接线 observe 件（P2-P3 随插件迁移）：ws/tuic/试点池的 PoolAuditTicket 接 app-metrics/observe 件，暴露 dropped_overflow/watermark | 审计环只有接进观测面才闭环 | metrics 导出面含各池 watermark/dropped_overflow 快照；集成测试断言事件到达 | M |
| **6**（另行裁决） | xray-buf 管理面只读侧挂（PoolBase 账本对账，分配路径零触碰） | 数据面唯一合法接口；收益=池水位可观测，风险=任何实现失手即热路径回归，**必须单独派单+性能锚复测** | 分配路径 diff=0 评审 + loopback_alloc_bench（§CLAUDE.md 工作流）数字不低于 baseline 154-167 MB/s；32/32 | M（高风险门槛） |

**排序理由**：0a/0b 是零风险安全/死重清理（P1 内顺手）；1/2 是「白拿功能」定调的直接兑现且各自有事故史/修复史背书；3 是 PM 点名的互喂首发、启动期隔离风险；4 防御性补位；5 依赖 observe 件成型；6 红线邻接必须最后且单独裁决。

---

## 9. 与既定判据的对账（依托 udf 判据三态复核）

| 判据 | 落到本报告 |
|---|---|
| 能直接换 udf 件 | #5 ManagerPool→BoundedRegistry（步 4）；#12 LruCache→std_ext cache 或删（步 0b） |
| 只能管理面继承（PoolBase 水位+审计+resize，分配/借还路径不动） | #2 ws 池（步 1）、#3 tuic 池（步 2）、#6 vless PreConnectPool（P2，S）、#9 UDP 表（步 4）；#1 xray-buf 只读侧挂（步 6，另行裁决） |
| 不能动（列理由） | §7 全表 11 条 |

---

## 10. 未决点

1. **xray-buf 只读侧挂的账本口径**：PoolBase 的 note_borrow/note_return 是借还记账语义，xray-buf alloc/release 若侧挂需先定「alloc=借、release=还」映射是否引入计数开销（两个原子加）——热路径红线下需 PM 单独裁决是否接受（步 6 前置）。
2. **tuic key 上界的 max 初值**：多 outbound 场景 key 数上限取多少（建议=config outbound 数×2 起步，运行时 resize 调），需真实部署数据。
3. **stats Channel blocking 重试的 spawn 失败路径**未取证（channel.rs:121+ blocking 分支 spawn 失败行为）；observe 件设计时补。
4. **XmuxClient open_usage 增减点全量读路径**未逐行（mux.rs:121 is_unreusable 已读，配额消费点在 dispatch 侧）——若步 4 后做 xmux 审计需补读。
5. **fakedns 占位窗**：生产路径 initialize 必达（:233-236）已证实，但是否存在测试/未来代码路径绕过 initialize——步 0a 的构造期有界化直接消灭该问题，无需再查。
6. udf 侧 ThreadPool `join()` 语义（PM 核对提过 shutdown+join）在主仓宿主停机序中的编排位置——步 3 落地时对齐 skeleton-infra shutdown 三段式。

---

*盘点人：PoolSurvey（代码语境搜索岗，只读）· 2026-10-23 · 全部行号一手实读（udf ThreadPool/RejectPolicy/shutdown 面引 PM 一手核对+机制差距文档互证）*

### 5 维自评

| 维度 | 分 | 说明 |
|---|---|---|
| 完整性 | 4.5 | 任务书 15 族候选全覆盖 + 自查补漏 8 处（fakedns/observatory/antireplay/SessionHistory/ReverseRegistry/commander/Semaphore/hyper-util），33 项逐个有 file:line；ThreadPool 全文未逐行（引 PM 一手核对，已在 §1 声明） |
| 准确性 | 4.5 | udf API 面一手实读核对（PoolBase/MemoryPool/PooledThreadPool 签名）；纠正任务书两处预期（KeyCache 非缓存、LruCache 零调用点） |
| 可执行性 | 4 | 步 0-5 可直接派单（验收命令具体）；步 6 依赖 PM 单独裁决（如实标注） |
| 红线遵守 | 5 | 零文件改动（仅本报告落盘）；热路径/红线逐条点名「即便想依托也不能动」+理由 |
| 诚实度 | 4.5 | 6 处未决点显式列出，无「应该/大概」断言；推断处标 [推断] 共 0 处遗漏（tuic PoolKey 构造已实证 :51-55） |

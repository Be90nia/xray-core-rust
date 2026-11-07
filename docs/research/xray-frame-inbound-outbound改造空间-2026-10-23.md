# xray-frame 视角：主仓 inbound / outbound / 分发 三面改造空间（2026-10-23）

> **结论首行**：三面的真实形态是「**四套注册表并存 + 两个巨文件承载全部装配 + proxyman 管理面整体未接入生产**」——生产 inbound 注册表 = xray-core `InboundRuntime`（`slots: RwLock<Vec>`，O(n) 线性扫），生产 outbound 注册表 = dispatcher `SimpleOhm`（parking_lot RwLock<HashMap>），proxyman 的 `InboundManager`/`OutboundManager`/`TcpWorker`/`UdpWorker` 只有自测消费；改造收益最大的不是"把 HashMap 换成 udf 件"，而是①中央 match 臂（inbound.rs:3898 / outbound.rs:672）迁 builder 注册表（P3-1，可分 5 阶段回滚）②dispatcher 自拼任务托管（`background_tasks` + 收割债）与各处自拼停机（notify/abort/select 三风格并存）换 udf `FxScope`/`ShutdownCoordinator` ③两套巨文件按 serve/parse/build 三层拆文件。**全部改造均不碰数据面热路径**（splice 准入、pipe/SizeStat poll 语义、serve 循环本体零改动）。

> **任务**：只读深盘（任务 C），产出可执行改造清单。零代码改动，未 commit。
> **取证口径**：read/glob/grep 直读一手文件并给 file:line；udf API 全部核对源码真实签名（skeleton/src/pool.rs、skeleton-infra/{memgov,shutdown,fx,pool}.rs、std-ext/src/id.rs）。行号均来自本次实读；未读到的标「未取证」。
> **必读输入**：强约束插件模型（§引用其 L2 能力层/坑约束 12 条）、主仓能力盘点（53 crate 行号依据直接复用）、udf 机制差距（32 机制域全集）。

---

## 1. 三面现状结构

### 1.0 注册面总览：四套注册表并存（本报告最重要的事实）

| # | 注册表 | 位置 | 容器 | 谁在用 |
|---|---|---|---|---|
| R1 | FeatureFactory 全局表（app 级 feature） | `xray-features/src/registry.rs:39`（`OnceLock<RwLock<HashMap<&'static str, FeatureFactory>>>`），注册 `:63 register_feature`，上限 `MAX_FEATURE_ENTRIES=1024` `:55` | std RwLock+HashMap，**已有 fail-closed**（`:57-60` 满时 Err） | `instance.rs:107 new_from_built` 逐 app kind 调 `create_feature :92` |
| R2 | 生产 outbound 表 = `SimpleOhm` | `xray-app-dispatcher/src/default.rs:1953`（`default: parking_lot::RwLock<Option<…>>` + `tagged: parking_lot::RwLock<HashMap<String, Arc<dyn DispatchHandler>>>`） | parking_lot RwLock+HashMap，**无上限/无审计** | `functions.rs:196` 生产装配唯一实例；gRPC `ApiOutboundRuntime`（outbound.rs:471） |
| R3 | 生产 inbound 表 = `InboundRuntime` | `xray-core/src/inbound.rs:~2960`（`slots: parking_lot::RwLock<Vec<InboundSlot>>`，slot={tag,proxy_type_url,cancel,users} `:~2940`） | **Vec 线性扫**：`contains :2931`、`remove position` 均 O(n) | `functions.rs:393`；gRPC AddInbound 共用同路径 |
| R4 | proxyman 管理面（InboundManager/OutboundManager） | `xray-app-proxyman/src/inbound/mod.rs:67-76`、`outbound/mod.rs:77-87`（`RwLock<ManagerState>`：tagged HashMap + untagged Vec + default Option） | RwLock(ManagerState) | **生产零消费**——全仓 `xray_app_proxyman::` 引用只有 command trait / ProxymanError / outbound::OutboundHandler trait（commander.rs:274/:99、grpc.rs:88-99、functions.rs:25/:468）；proxyman 自身 tests + tests/lifecycle_e2e.rs |

> proxyman `lib.rs:13` 文档仍自称「管理入站/出站 handler 生命周期…InboundManager/OutboundManager — handler 注册表」，`inbound.rs:7` 注释称「多 inbound 注册管理（由 proxyman::InboundManager 负责）」——**与生产事实相反，属文档漂移**。`outbound/mod.rs:29-31` 自己也注了 parking_lot 简化说明，但无人调用。

### 1.1 inbound 生产路径（谁注册 / 谁构建 / 谁停）

- 启动序：`functions.rs:187 start_full_dispatched` → `register_all_features :192`（`register.rs:32`，app 13 kinds + proxy stub 工厂）→ `register_all_transports :193`（`register.rs:76`）→ `Instance::new_from_built :194`（`instance.rs:106`）→ `SimpleOhm::new :196` → `DefaultDispatcher` 装配 `:269` → `register_outbounds :339` → **`InboundRuntime::new :393`（注入 `instance.shutdown_token().clone() :396`）** → commander 注入 `:416` → `instance.start() :422`（instance.rs:264，按注册序 feature.start）→ `spawn_inbounds :423`。
- `spawn_inbounds`（inbound.rs:2754）：循环 `built.inbounds` → `InboundRuntime::start_inbound :2927`：`contains` 查重 `:2931`（O(n)）→ `shutdown.child_token()` `:2934` → write 锁内 push slot `:2935-2940` → `per_inbound_ohm :2942`（per-inbound ohm 快照：嗅探配置 + tag 包 `InboundDispatchHandler`（wiring.rs:530）再包 `MuxCarrierHandler`（wiring.rs:458），master ohm default 不动防递归，注释 `inbound.rs:2780-2786`）→ **锁外** await `spawn_one_inbound :2944` → 失败回滚 slot（重新 write+retain）`:2946-2948`。
- 中央 match：`spawn_one_inbound :3821`，`match ib.entry.kind.as_str() :3898`。臂清单（TCP 路径）：`socks:3899`｜`mixed:3917`｜`vless:3940`｜`trojan:4043`｜`vmess:4148`｜`http:4210`｜`dokodemo:4226`｜`shadowsocks:4329`｜`anytls:4411`｜`tuic:4430`｜`naive:4442`｜`wireguard:4465`｜`dns:4483`｜`loopback:4500`｜`blackhole:4515`｜`freedom:4529`（hysteria/tun 在 cfg 区）；**unix 变体 `spawn_unix_inbound :4623` 独立第二份 match `:4678`**（socks/vless/vmess/trojan/shadowsocks，`_ => unreachable! :4848`）。
- 每-inbound 停机：`spawn_inbound_serve :3047`——外层 task spawn 内层 serve future，`tokio::select! { fut, shutdown_token.cancelled() }`，**panic 转 error! 留痕**（防 wsiq 型「端口静默不再 listen」）`:3055-3072`。`remove_inbound`（单停一个）= 摘 slot + `cancel.cancel()`。
- 巨文件账本：inbound.rs 共 **11,388 行**，`#[cfg(test)] mod tests :6093` 起 ≈ **5,300 行测试与产品代码同文件**；产品区 6,000 行 = serve 循环族（socks :108 / mixed :614 / http :758 / dokodemo :1542 / ss :1974 / ss2022-udp :2319 / dns :2520 / reality :3359-3552）+ 中央 match ×2 + **约 30 个 `parse_*`/`build_*` 配置解析函数**（:4877-6080）+ InboundRuntime + proto 转换。

### 1.2 outbound 生产路径

- `register_outbounds`（outbound.rs:148）：`try_build_handler :543` → `build_protocol_handler :647`，`match ob.entry.kind.as_str() :672`，臂：freedom:673｜vless:754｜trojan:769｜blackhole:784｜socks:792｜mux:825｜vmess:833｜shadowsocks:848｜hysteria:863｜anytls:912｜tuic:933｜wireguard:1015｜dns:1061｜loopback:1070｜http:1084｜naive:1099｜dokodemo:1112｜tun:1126/1139（平台分叉）｜`_ => Err(Unsupported) :1142`。
- **default 出站 = 首个注册成功者，绝不覆盖**（`:185-191`，注释点名史实：旧 `i==0||tag=="direct"` 覆盖 bug = 32 节点 YouTube 全挂根因）——**此语义红线，任何注册表替换必须保序保语义**。
- 查表：`SimpleOhm.get_handler :2026` / `get_default_handler`；写侧 `set_default :1967`、`add`。注册错误处理：`BuildError::Unsupported/Parse` → **warn skip 不 fail**（`:199-211`）——与 inbound「bind 失败 fatal abort」（inbound.rs:2760-2762，bd 0z7u）**不对称**。
- outbound.rs **6,888 行**：中央 match + 约 30 个 parse/build + `DialBridge :1622`/`MuxBridge :1151`/XUDP 装配 + DNS 出站桥（`dispatch_dns_link :2103` 族约 700 行）+ `ApiOutboundRuntime :471`。
- `OhmRef`（outbound.rs:106-108）：`inner: *const SimpleOhm` **裸指针别名**（注释辩称 RwLock 内部指针稳定）——unsafe 面待审计（deref 位置未取证）。

### 1.3 分发路径（谁查表 / 谁统计 / splice 准入）

- `DefaultDispatcher`（default.rs:871-894）：字段 ohm/router/policy_manager/default_policy/stats/fdns/`udp443_policies: Arc<HashMap>`/access_sink/`background_tasks`。
- 入口链：`dispatch :982` → `dispatch_with_access :1003`：policy 查询（user_level 固定 0）:1006 → pipe 选项（limit = policy.buffer.connection，512KiB 背压）:1010 → **4 个 per-tag 计数器懒注册，受 `ForSystem().Stats` 四门门控** `:1033-1076`（计数名手写 format! `"inbound>>>{tag}>>>traffic>>>uplink"` 等 `:1041/:1051/:1061/:1071`）→ `maybe_wrap_writer/reader`（SizeStat 包装）`:1080-1084` → `dispatch_link :1089`。
- `dispatch_link`（~:1195）：forced tag 预检（无效同步 Err 不落默认，Go DO NOT CHANGE 对齐）:1206 → 无 router 无 default 同步 Err + rejected access `:1214` → 克隆进 spawn 闭包 `:1230` → Phase1 sniffing（`CachedReader :1474` 首包缓存回灌）:1264 → Phase2 forced / routing（`pick_route_resolved`）:1280 → access log → `spawn_tracked(handler.dispatch)`。
- **任务托管自拼**：`BackgroundTasks = Arc<tokio::sync::Mutex<JoinSet<()>>>` `:850`；`spawn_tracked :857-864`：**每次 spawn 先抢同一把 async Mutex、锁内 `try_join_next` 收割再入队**——收割时机 = 下一次 spawn（`:853-856` 自注 wfx8-5「周期 reaper 为后续项」）：空闲期已完成句柄滞留；并发 dispatch 在单锁上排队。
- **splice 准入面（红线邻接，禁改）**：`INBOUND_SPLICE` thread_local `:1679`（scope 语义）+ `SPLICE_ADMISSIONS: AtomicUsize :1687`；`DialBridge::dispatch` 准入判定 `:1812-1823`（`bridge_splice_admission` + 计数）。freedom 装配 `set_splice_outbound :1726`。
- 嗅探：`sniffer.rs` `Sniffer :46`（`Vec<Box<dyn ProtocolSniffer>>`）+ `new_default_sniffer_set :995`（HTTP:239/TLS:331/QUIC:578/BT:492/uTP:929）；`should_override`（default.rs:509）。
- 统计包装：`stats.rs` `SizeStatWriter :23`（async + **poll 双形态**，bd d881⑤ poll 就地转发防丢数据 `:52-63`）/ `SizeStatReader :90+`；在线 IP：`OnlineIpGuard :834`（Drop=remove_ip）。

### 1.4 proxyman worker 面（已实现、未接线）

- `worker.rs`：`Worker trait :81`（`start(self: Arc<Self>)`）/`ProxyInbound trait :52`；`TcpWorker :223`（listener `Mutex<Option<…>> :235`、close_notify `:236`）；`UdpWorker :486`（**`active_sessions: RwLock<HashMap<SocketAddr, Arc<UdpSession>>> :498`**、hub `Mutex<Option<UdpHub>> :497`、recv/cleanup `Mutex<Option<JoinHandle>> :501-502`）；`DsWorker :798` stub。
- 裸 spawn：TcpWorker `spawn_conn :292`（timer :323 + conn task :335 两处 `tokio::spawn`）；UdpWorker `:604/:623/:716/:737` 四处。
- close 风格：TcpWorker `:461` = closed+notify_waiters；UdpWorker `:757-783` = closed+notify → hub.close → **abort 两个 handle** → `set_inactive` 遍历（**不清 active_sessions 表**）。三种停机风格（notify/abort/token-select）并存。
- audit 79ma/ojcy 测试打穿 accept（:1292/:1328）——worker 本身是活的、可用的，只是生产没接。

### 1.5 停机序现状（自拼清单）

| 层 | 停机方式 | 位置 |
|---|---|---|
| Instance | cancel shutdown_token → **逆序** feature.close()，聚合错误，不可重启 | instance.rs:296-323 |
| app feature 工厂表 | 无停机概念（进程级 OnceLock） | registry.rs:39 |
| inbound accept | per-inbound child token + select | inbound.rs:3047-3072 |
| 存量连接 | **无统一令牌**：serve 内连接任务 fire-and-forget（socks 每连接 spawn 于 inbound.rs:136-145，错误仅 log）；靠宿主 JoinSet drop/runtime 退出兜底 | inbound.rs:136-145 |
| dispatcher 后台 | JoinSet 宿主 drop abort（注释 :892-894）；`close()` 空操作 :973 | default.rs:850/:973 |
| proxyman worker | notify（Tcp）+ abort（Udp）+ set_inactive | worker.rs:461/:757-783 |
| app-stats | close 清空 online_maps + 关 channels | manager.rs:222-226 |

### 1.6 并发模型与锁审计（跨 await 持锁纪律 bd 4zjf）

| 锁 | 类型 | 粒度 | 跨 await? |
|---|---|---|---|
| `InboundManager.state` | RwLock<ManagerState> | 整表 | **无**——add/start/close 均「锁内收集 clone、锁外 await」（inbound/mod.rs:103-115/:172-181/:187-199），纪律正确 |
| `OutboundManager.state` | 同上 | 整表 | 无（outbound/mod.rs:189-197/:204-216） |
| `SimpleOhm.default/tagged` | 两把独立 parking_lot RwLock | 单槽/整表 | 无；**但 dispatch_link 预检与闭包内二次查表之间注册表可变**（非持锁跨 await，是 TOCTOU 窗，Go 同样存在） |
| `InboundRuntime.slots` | parking_lot RwLock<Vec> | 整表 | 无——start_inbound push 后锁释放再 await（inbound.rs:2935-2944） |
| Instance.state_lock | parking_lot Mutex<()> | 实例级互斥 | **持锁调 `feature.start()`**（instance.rs:99-105/:222-226/:297）——start 是同步签名故无跨 await，但「锁内做外部回调」违反锁外纪律精神；feature.start 若未来改 async 即成跨 await 持锁 |
| dispatcher.background_tasks | **tokio async Mutex** | 全局单把 | spawn 路径锁内无 await（lock 后同步收割+入队，default.rs:857-864）——但所有并发 dispatch 的 spawn 在单锁上串行 |
| UdpWorker.active_sessions | RwLock<HashMap> | 整表 | cleanup retain 在锁内（:737 循环内），无 await |
| app-stats 三表 | parking_lot RwLock×3 | 单表 | get 在读锁回调（manager.rs:96-99） |
| registry（R1） | std RwLock | 全局 | register/create 均短临界区（registry.rs:63-76/:92-101） |

**结论：未发现跨 await 持锁实锤；风险点是 ①Instance 持锁调 start（纪律精神）②background_tasks 单锁串行 ③SimpleOhm 双查表 TOCTOU。**

---

## 2. 六个核查面逐个结论

### 2.1 巨文件职责边界：能否按「注册/构建/分发/统计」拆？

**能，且拆分本身是 P3-1 迁移的阶段 0**。两文件实际是四层职责压实：
- **serve 层**（inbound.rs:88-2750）：socks/mixed/http/dokodemo/ss/ss2022/dns 的 accept 循环与协议泵——**wire/IO 语义，只搬不改**；
- **构建层**（中央 match + ~30 个 parse/build）：`spawn_one_inbound` 与 `build_protocol_handler` 就是 xray-frame 装配层件（builder）的原型——每臂 = 「parse settings JSON → 构造协议 handler → 包 transport/bridge → 返回 spawn future」三步，与 `ProtocolPlugin.build(ctx)` 形状同构（强约束插件模型 §2.5）；
- **注册表层**：`InboundRuntime`/`SimpleOhm`——容器语义，可换 udf 件；
- **统计/观测接入**：已在 dispatcher/wiring，不在巨文件里（无需拆出）。
- inbound.rs **5,300 行测试与产品同文件**（:6093 起）——拆测试到 tests/ 目录是零风险第一步。
- outbound.rs 特有：DNS 出站桥（:1959-2103）、TUIC/SOCKS UDP dispatch 补丁类（TuicUdpDispatch :3012 / SocksUdpDispatch :3206）——这些是「协议特化 dispatch 面」，未来应随协议插件走，拆出为独立模块文件即可。
- **拆法**：`inbound/{serving,builders,registry,parsing}.rs` 文件化 + builder trait，纯移动零语义变化；unix 变体第二份 match（:4623-4856）合并进 builder 注册表后自然消亡。

### 2.2 Handler 注册 HashMap+RwLock → udf BoundedRegistry：收益/代价

现状（SimpleOhm tagged、InboundRuntime slots、proxyman 双 Manager、app-stats 三表、R1）：HashMap/Vec + RwLock——**无容量上限、无溢出可见性、无审计**（PM 口供三缺）。

**BoundedRegistry 白拿三件**（memgov.rs:50-127，签名已核）：
- **fail-closed 插入** `insert :73`：满→`Err(BoundError)`，原内容不动——「动态 AddInbound/AddOutbound 灌爆注册表」从无界变显式拒绝（现 R1 已有 1024 上限但错误冒名 `FeatureError::NotFound`，registry.rs:59——同一诉求）；gRPC 动态注册面（ApiHandlerService/ApiOutboundRuntime）正是 DoS 面。
- **泄漏断言面** `is_empty :106`/`len :101`：停机后注册表应清空——现无任何一处做此断言。
- **确定序迭代** `iter :116`（BTreeMap 升序）：`list_tags`/`list_handlers`/`list()` 现在的顺序 = HashMap 随机或 Vec 插入序，gRPC ListInbounds 输出稳定化。

**代价三条**：
- **容量语义**：`new(max, evict) :58` 构造期必填、max==0 panic——需为每表选上限（outbound ≤ 几十、inbound 同量级、1024 兜底均可）；`Eviction::Reject`（注册表禁淘汰，PopFirst 语义不适格）。
- **动态增删需求**：gRPC Add/Remove 是常态操作——BoundedRegistry `insert/remove :96` 均支持，无阻碍；但 **`&mut self`** 要求锁外仍在（现有 RwLock 外壳保留、registry 放锁内，锁纪律不变）。
- **顺序语义变化**：InboundRuntime slots 现为 **Vec=注册序**，ListInbounds 注释明言「保持注册顺序」（inbound.rs:2956）；换 BTreeMap 变 **tag 字典序**——gRPC 观察者可见的行为变化，**需 PM 拍板**（保留注册序则退路=Vec + 并行 tag 去重集，BoundedRegistry 只用于去重面）。
- O(log n) vs O(1)：tag 数量级 ≤ 10²，无感。

**逐容器判定**（见 §4 表）：SimpleOhm tagged → BoundedRegistry ③；InboundRuntime slots → ③（顺序语义待拍板）；app-stats counters → ③；Instance feature_typed → **④ 不动**（TypeId 有限集、进程级、无动态灌入面）；proxyman 双 Manager → **先裁决去留**（§4 行 6）。

### 2.3 中央 match → Registry 查表迁移（P3-1）：分阶段可回滚草案

```text
阶段 0  纯拆文件（inbound.rs → inbound/{serving,builders,registry}.rs；测试外移 tests/）
        验收：cargo test --workspace 全绿 + 32/32 + fmt/clippy/doc 四门 + git diff 无语义变化（函数逐个 move）
阶段 1  建 InboundBuilderRegistry 旁路表（BoundedRegistry<&'static str, Box<dyn InboundBuilder>>，
        builder = 现 match 臂的 parse+spawn 封装），spawn_one_inbound 改为：先查表，未命中 fallthrough 旧 match。
        试点协议 = blackhole + socks（最简、e2e 已有）。
        验收：新协议走 builder、旧协议走 match，行为逐字节一致；未知协议仍 Err(Unsupported) 原文案；
              每迁一臂跑该协议 integration（functions.rs 内 vless/vmess/trojan/ss/socks 全套已有）
阶段 2  双写对照（cfg(debug_assertions) 或 feature flag）：同请求同时走 builder 与 match，
        比较 {listener 绑定结果, bind 端口, spawn 成败, handler tag}——差异率必须为 0；
        e2e 请求级对照：旧 match 臂与新查表结果逐请求比对（连接建立+echo 往返+关闭语义）。
        验收：对照器在 CI 跑满全部已迁协议，差异 0 才进阶段 3；差异 ≠0 即回阶段 1 逐臂修
阶段 3  切查表：match 降级为空壳 + unreachable（或直接只剩 fallback 臂），builder 为主路径。
        验收：全套 32/32 + 本地互操作矩阵 12/12（dist/interop_matrix.py）+ 抓包验收族协议按 memory 纪律
        回滚点：恢复 = 单 commit revert（match 未删）
阶段 4  删 match 臂 + unix 变体第二份 match 合并消亡；builder 注册集中化（core 显式注册表，
        或协议 crate 自注册——与强约束插件模型 L5 装配门对齐）。
        验收：clippy dead_code 零命中（残留臂应被检出）+ 全套回归
outbound.rs 的 build_protocol_handler（match :672）同构同节奏跟进（依赖 inbound 侧先趟平）。
```

**回滚性保障**：阶段 1-3 之间旧 match 始终在场；每阶段独立 commit；唯一不可回滚点是阶段 4 删臂——前置条件 = 阶段 3 在主网跑满一个观察窗（对照器零差异 + 32/32）。

### 2.4 连接生命周期：谁创建/销毁、谁管 idle、泄漏面

- **创建**：inbound 侧每 accept 一 task（serve_* 内 spawn；proxyman worker 是 spawn_conn :292）；dispatcher 侧每 dispatch 一 task（spawn_tracked）；outbound 侧无常驻连接（mux carrier worker 由 `MuxBridge :1151` 内部管理，MaxConnection=128 硬编码滚动退役，outbound.rs:1173-1177）。
- **销毁**：三条互不相通的路径——①Instance shutdown_token 广播 → accept 停（**存量连接不随停**，靠 runtime drop）②dispatcher background_tasks JoinSet 宿主 drop abort ③proxyman worker notify/abort（未接线）。
- **idle 回收**：socks UDP relay sleep_until 每包续期（inbound.rs:529-535）；dokodemo UDP peers retain + `DOKODEMO_UDP_IDLE`（:1745-1748）；proxyman UdpWorker 60s interval 清扫（worker.rs:737）；dispatcher pipe idle_timeout 来自 policy.timeout.connection_idle（default.rs:1012）。
- **泄漏面清单**：①**spawn_tracked 收割债**（只在下一次 spawn 时收割，低流量长尾期已完成句柄滞留——default.rs:853-856 自注）②**UdpWorker.close 不清 active_sessions**（worker.rs:775-783 只 set_inactive）③存量连接无令牌（停机语义=「先停 accept，connection drain 留后续」，inbound.rs:3046 自认未完）④`BoundedRegistry::is_empty` 类断言全仓为零——泄漏无从发现。**均非当前生产事故，但都是 xray-frame 坑约束 #5（任务必托管）/#9（资源必有界）的存量反例。**

### 2.5 停机序：自拼 vs ShutdownCoordinator 差距

| udf ShutdownCoordinator 白拿（shutdown.rs:257-360，签名已核） | 主仓现状 |
|---|---|
| 注册窗/编排窗互斥（`register :298`，Closed/Duplicate 显式 Err） | Instance 无注册窗——close 时才遍历 features，晚注册 feature 的停机闭包无处挂 |
| **串行按注册序 + 逐组件超时**（`register_with_timeout :306`；超时=放弃等待非中断） | 逆序 close 无超时——任一 feature.close 挂死则全停机挂死 |
| **panic 隔离**（组件闭包 panic → Failed 记报告，重入装甲） | 各自拼：spawn_inbound_serve 的 panic 转 error!（:3060-3070）是好样板，但仅 inbound 一处 |
| **幂等 + 报告**（`shutdown :348` 返回 ShutdownReport，is_clean :101） | close 聚合 Vec<FeatureError>，无 per-组件超时/结果报告 |
| Mutex+Condvar 短临界区 | — |

**能替掉的**：①Instance.close 的 features 逆序遍历（每 feature 一个 register(name, close)）②spawn_inbound_serve 的 token-select（保留 token 语义，外挂 coordinator 做「带超时的等 accept 退出」）③worker abort/notify 两风格 ④app-stats close。**替不掉/不需替**：shutdown_token 本身（取消广播与编排是正交的两件事：token=让任务自己退，coordinator=等它们退完）；MuxBridge carrier 滚动退役（自有 monitor 语义，塞进 coordinator 注册即可）。

### 2.6 统计接入与漂移风险

- 接点全图：dispatch_with_access 四计数（default.rs:1033-1076，**ForSystem 四门门控，默认全 false 不注册不计数** sm80①）→ SizeStat 包装（stats.rs:23/:90）→ app-stats Manager（manager.rs:27-32，三 RwLock<HashMap>）→ metrics 导出（app-metrics）。splice 旁路回填：`splice_down_out/splice_down_in`（default.rs:381-388，CI 实证恒 0 后补）。在线 IP：OnlineIpGuard Drop 对称（:834-845）。
- **漂移风险四处**：
  1. **计数名双处手写**：proxyman `counter_name :49`（`"{kind}>>>{tag}>>>traffic>>>{direction}"`）与 dispatcher 四处 format!（:1041/:1051/:1061/:1071）+ wiring inbound_counter（wiring.rs:547-560）——**同一规范三处独立实现**，改一处漏两处即 stats 键名分叉；
  2. **懒注册时序**：`get_or_register_counter_opt :813` 首次 dispatch 才注册——零流量 tag 查询返回 None（manager.rs:96），stats API 消费方无法区分「无此 tag」与「有 tag 无流量」；
  3. **门控静默**：ForSystem 关门时不注册（oz1t 测试：default.rs:3075-3081）——配置开了 stats app 但 policy 门关，计数器缺席无告警；
  4. **旁路计数**：splice 直达 fd 绕过 SizeStat——已打补丁但模式上「新增快路径必须记得回填计数」无机制保证（正是 observe 件/审计挂点要约束的）。
- Counter 语义四份重复：`xray_features::stats::Counter :46`、`proxyman::stats::Counter :80`（注释自认「避免循环依赖」的本地重复）、app-stats impl、features 侧 trait——**P3 统计收口时收敛为单一词汇**。

---

## 3. 改造空间清单表

> 批次对齐 impl-plan P0-P4（本三面主体 = P3 app 层收口；小修可前置）。依托判定：①=impl PoolManaged ②=PoolBase 组合+特化 ③=BoundedRegistry ④=不能动 ⑤=FxScope/ShutdownCoordinator/std-ext 接线。

| # | 面 | 现状 file:line | 问题 | 改造方案 | 依托 udf 件 | 动热路径? | 批次 | 规模 |
|---|---|---|---|---|---|---|---|---|
| 1 | 巨文件拆分 | inbound.rs 11,388 行（测试 :6093 起）；outbound.rs 6,888 行 | 四层职责压实单文件；5,300 行测试同文件；unix 变体第二份 match :4623 | 按 serving/builders/registry/parsing 文件化 + 测试外移，纯移动 | —（装配层件原型） | 否 | **P3-1 阶段 0** | L |
| 2 | 中央 match → 查表 | inbound.rs:3898（16+ 臂）；outbound.rs:672（18 臂） | 每新增协议改两处巨文件；unix 变体第三份；扩展成本 = 巨文件合并冲突面 | builder 注册表（BoundedRegistry<&str, Box<dyn InboundBuilder>>）+ 分阶段迁移（§2.3 五阶段） | skeleton_infra::memgov::BoundedRegistry | 否（builder 内部不碰 serve 语义） | **P3-1** | L |
| 3 | outbound 注册表 | SimpleOhm default.rs:1953-1956 | 无上限/无审计/确定序无 | tagged 换 BoundedRegistry（Reject）；**default=首个语义原样保留**（outbound.rs:185-191 红线） | memgov::BoundedRegistry：白拿 insert fail-closed :73、iter 确定序 :116、is_empty 断言 :106 | 否（查表在 spawn 前，锁内 O(log n)） | P3 | S |
| 4 | inbound 注册表 | InboundRuntime slots inbound.rs:~2960（Vec O(n)：contains :2931 / remove position） | 线性扫 + 无上限 + 无断言 | BoundedRegistry<String, InboundSlot>；**注册序→字典序需 PM 拍板**（§2.2） | 同上 | 否 | P3 | S（语义拍板后） |
| 5 | proxyman 管理面去留 | InboundManager/OutboundManager/TcpWorker/UdpWorker 生产零消费（§1.0 R4） | 死重 + 文档漂移（lib.rs:13、inbound.rs:7 声称与事实相反） | 裁决：a) 删（保守）b) 保留为 xray-frame 插件宿主原型（P0 设计输入）。**裁决前不动** | — | 否 | P3 前置决策 | S（决策）/ M（处置） |
| 6 | dispatcher 任务托管 | BackgroundTasks default.rs:850 + spawn_tracked :857 | 单把 async Mutex 串行 + 收割债（wfx8-5 自认） | FxScope 替换：close/abort_all/shutdown_timeout + **in_flight 归零断言白拿**（fx.rs:258/:297/:304） | skeleton_infra::fx::FxScope（spawn :264 唯一口） | 否（spawn 动作非数据面） | P3 | S |
| 7 | worker 裸 spawn | TcpWorker :323/:335；UdpWorker :604/:623/:716/:737 | 706 处裸 spawn 家族成员；停机 notify/abort 风格自拼 | 随 #5 裁决：接 FxScope 或随插件迁移 | fx::FxScope | 否 | P3（随 #5） | M |
| 8 | 停机编排 | instance.rs:296-323（逆序无超时）+ 各处自拼（§1.5 表） | 无超时/无报告/三风格并存 | features+worker+inbound accept 注册进 coordinator；token 广播保留 | skeleton_infra::shutdown::ShutdownCoordinator（register :298 / register_with_timeout :306 / shutdown :348） | 否 | P3 | M |
| 9 | 统计键名收敛 | counter_name proxyman stats.rs:49 ≈ dispatcher :1041-1071 ≈ wiring.rs:547 | 三处手写同一规范，分叉即漂移 | 单一常量/函数（dispatcher 侧引 proxyman 或下沉 common）；计数器**预注册**（配置期把 4×tag 全注册，消懒注册时序漂移） | —（纯收敛）；审计挂点可接 PoolAudit 同款 seq 单调形态 | 否 | **可前置** | S |
| 10 | FeatureFactory 满表错误 | registry.rs:57-60 满 → `FeatureError::NotFound` | 错误冒名（容量满 ≠ 未注册），排障误导 | 专用 `RegistryFull` 变体 | — | 否 | **可前置** | S |
| 11 | Instance 持锁调 start | instance.rs:99-105/:222-226 | 锁内做外部回调（start 同步故无跨 await，但纪律精神違反；start 改 async 即成 4zjf 反例） | state_lock 内只做登记，start 移锁外（running 判定用快照） | — | 否 | P3 | S |
| 12 | handler 契约三套 | xray-features inbound.rs:14 / proxyman inbound::InboundHandler / dispatcher DispatchHandler :313 | 三 trait 语义重叠（tag/start/close vs dispatch），proxyman 版为 Go 完整语义版 | xray-frame P0-1 plugin 契约统一（trait 集已定，本报告只供证据） | xray-frame plugin.rs（未建） | 否 | P0-P1（契约）/ P3（切换） | L |
| 13 | UDP 会话表有界化 | proxyman UdpWorker active_sessions :498；dokodemo peers inbound.rs:1745 | 无上限 HashMap + 60s 清扫（未接线故低危） | 随 #5；若接：BoundedRegistry + Reject（拒绝新会话+计数）或 PoolBase 借还（**不选**，会话非借还模型） | memgov::BoundedRegistry | 否 | P3（随 #5） | S |
| 14 | OhmRef 裸指针 | outbound.rs:106-108 | `*const SimpleOhm` 别名安全性依赖注释 | 审计 deref 位置，换 Weak/Arc | — | 否 | 可前置 | S |
| 15 | 注册表/表类统一审计挂点 | 现 R1-R4 均无审计 | 增删无留痕（gRPC 动态操作不可追溯） | 各注册表挂 PoolAudit 同款事件流（Resized/InsertRejected）——**结构性冲突见 §4** | skeleton::pool::PoolManaged 仅当模型同构；纯注册表用 BoundedRegistry+手挂 audit | 否 | P3-P4 | M |

**「白拿功能」点名**（PM 要求逐挂点，不写笼统「用 PoolManaged」）：
- BoundedRegistry 路线（#3/#4/#13）：白拿 `insert` fail-closed（:73）、`get` 不 panic 读（:91）、`remove` 收缩唯一口（:96）、`len/is_empty` 泄漏断言（:101/:106）、`capacity` 上界（:111）、`iter` 确定序（:116）、`Eviction::Reject` 二态（memgov.rs:18）+ `new` max==0 panic fail-fast（:58）。
- FxScope 路线（#6/#7）：白拿 `spawn` 闸关显式拒（:264 返回 Result<_, ScopeClosed>）、`close` CAS 关闸（:245）、`shutdown/shutdown_timeout` 三段收拢（:297/:304，锁内 abort_all + mem::take、**锁外 await** 的现成写法）、`in_flight` 归零锚（:258）+ `Spawned` abort 面（:330-362）。
- ShutdownCoordinator 路线（#8）：白拿注册窗互斥（:298 Closed/Duplicate）、串行编排（:348）、逐组件超时（:306）、panic→Failed 隔离、幂等 + `ShutdownReport::is_clean`（:101）。
- PoolManaged 三挂点（#15 仅限真池）：`resize(&self)` 事前校验（skeleton/pool.rs:246）、`metrics` O(1) Copy 核心形（:249 + PoolMetrics {max,idle,borrowed,dropped_overflow,watermark} :42）、`subscribe_audit` seq 单调+容量环+票据 Drop 关流（:253，`#[must_use]` :132）。

**结构性冲突（PM 特别问）**：PoolManaged 是「**池深 + 借还**」模型——metrics 核心形的 idle/borrowed/watermark、resize 的「缩容不夺借出」、note_return 的归还裁决，全部预设「对象会归还复用」。而本三面的容器绝大多数是「**注册表**」模型（插入后不归还、只增删查）：SimpleOhm tagged、InboundRuntime slots、app-stats counters、FeatureFactory。**判据**：
- 插入后对象被取出使用且最终归还复用（连接池、缓冲、worker 线程、hub 槽位）→ **PoolBase 组合（②）或 impl PoolManaged（①）**——主仓现对应物：UdpHub Capacity(256)（worker.rs:691）、ws/splithttp/tuic 连接池（能力盘点 §2.2 已列）、MuxBridge worker 池（outbound.rs:1151）；
- 插入后常驻、按 key 查找、生命周期由显式 remove 结束 → **BoundedRegistry（③）**——借还挂点对它无意义（没有「借出」，borrowed 恒 0，PoolManaged 是假同构）；
- 数据面缓冲 → MemoryPool（但 xray-buf 红线不动，管理面侧挂已由任务 A 拍板）。
- 本三面清单里 **没有任何一行该用 ①整面 impl PoolManaged**；②的组合件用途在 mux/hub/transport 池（属任务 A/其他面）；本报告的 udf 依托主力是 **③⑤ + audit 形态**——这是诚实判定，不是回避。

---

## 4. 依托映射表

| udf 件（crate::路径） | 主仓对应物 | 接法 | 阻碍 |
|---|---|---|---|
| `skeleton_infra::memgov::BoundedRegistry<K:Ord,V>`（memgov.rs:50） | SimpleOhm.tagged（default.rs:1955）；InboundRuntime.slots（inbound.rs:~2960）；app-stats counters（manager.rs:28） | 锁内替换容器字段；insert 的 Err 在 gRPC 动态注册面转显式拒绝响应 | InboundRuntime 顺序语义（注册序→字典序）需拍板；gRPC 拒绝语义要对齐 Go（Go 无上限——行为变化需记档） |
| `skeleton_infra::fx::FxScope`（fx.rs:199） | dispatcher background_tasks（default.rs:850/:894）；worker conn tasks（未接线） | `background_tasks` 整体换 `Arc<FxScope>`：spawn_tracked→scope.spawn；收割债消失（JoinSet 托管内建） | Spawned 句柄语义与现「fire-and-forget」差异：FxScope::spawn 返回 Result（闸关显式拒），dispatch 错误路径要接 |
| `skeleton_infra::shutdown::ShutdownCoordinator`（shutdown.rs:257） | Instance.close features 遍历（instance.rs:296）；spawn_inbound_serve（:3047）；worker close | feature 逐个 register；accept 退出等待用 register_with_timeout；报告落日志 | feature.close 现为同步签名（与 register 的 FnOnce()+Send+'static 匹配，无阻碍）；Instance 不可重启语义保留 |
| `skeleton::pool::PoolManaged`（skeleton/pool.rs:237）+ `skeleton_infra::pool::PoolBase`（infra/pool.rs:99） | UdpHub 槽位（worker.rs:691 Capacity(256)）、MuxBridge worker 池（outbound.rs:1151）、（他面的 ws/tuic/splithttp 池） | **②PoolBase 组合**：借还记账 note_borrow/note_return（:207/:232）+ 水位线 + 审计环白拿 | 不在本三面热区（属任务 A 池化域）；MuxBridge 的滚动退役 monitor 语义要映射进 note_return 裁决 |
| `std_ext::id::IdGen`（id.rs:236-332） | conn_id 观测（现无统一 conn_id：serve 层仅 peer 地址可追溯） | 每连接 `gen()` 注入 Session/日志字段（坑约束 #3） | Session 结构变更跨全仓——只在新观测面用，不改存量 wire/日志格式 |
| `std_ext::clock` / `skeleton::clock::MockClock` | 各处 `tokio::time::sleep_until`/`SystemTime::now`（worker.rs:155 UdpSession::update_activity 等） | 新代码走 clock 契约；存量不动 | 数据面 timeout 语义禁改（pipe idle 语义红线邻接） |
| logx / log-embed（logx.rs:885; embed_event!） | 全仓散装 tracing（642 处存量） | 本三面仅装配层日志（bind summary/停机报告）先行 | P2 logx 存量迁移统一节奏，不单独提前 |

---

## 5. 不能动的清单（附理由）

| 项 | 位置 | 理由 |
|---|---|---|
| splice 准入面全路径 | default.rs:1679-1688（INBOUND_SPLICE/SPLICE_ADMISSIONS）、:1812-1823（DialBridge 准入判定）、wiring/freedom 装配置位点 | vision 双 revert 史实 + bridge.rs 三轮战役红线邻接；SPLICE_ADMISSIONS 计数语义与 txno-splice 生产观测绑定 |
| pipe/SizeStat poll 语义 | stats.rs:52-63/:110+（d881⑤ poll 就地转发）；xray-buf pipe/copy | 数据面热路径；poll 语义修正是挂死战役成果（v51），包装层任何「重构」= 重复 v49/v50/v52 |
| default=首个出站语义 | outbound.rs:185-191 | bd 史实：回改即 32 节点故障复现 |
| MuxCarrierHandler 判据 | wiring.rs:448-460 | mux carrier = destination 域名 v1.mux.cool（memory 铁律，禁改 VLESS command 形态） |
| forced-tag 不落默认语义 | default.rs:1206-1211/:1282-1294 | Go DO NOT CHANGE 对齐；迁移时原样搬进 builder/查表层 |
| serve 循环本体与 wire 编解码 | inbound.rs serve_* 各函数内部；各协议 parse_* 语义 | 数据面 + 互操作铁律；拆分只做文件移动 |
| spawn_inbound_serve 的「先停 accept」select 语义 | inbound.rs:3047-3072 | 有序停机正确语义；只允许换编排外壳（coordinator 等待），token-select 本体不动 |
| transport 粘性代码 | xray-transport-tcp/register.rs 等（CLAUDE.md §4） | 13 红线 |
| InboundRuntime start_inbound 的 bind 失败 fatal 语义 | inbound.rs:2754-2765（bd 0z7u） | 监管方按 stdout 判活的现场修正；builder 化后保留 |
| 存量连接不随停（drain 留后续）现状 | inbound.rs:3046 注释 | 未完成项如实保留为未决点（§7-3），禁止在改造中顺手「修好」改变停机行为 |

---

## 6. 建议顺序与验收

| 序 | 事项 | 验收方式 |
|---|---|---|
| 0（可前置小修） | #9 统计键名收敛 + #10 RegistryFull 错误 + #14 OhmRef 审计 | 键名收敛后 `grep -rn "traffic>>>" crates/` 仅单一出处；错误类型单测；审计报告落档 |
| 1 | P3 前置决策：#5 proxyman 管理面去留（PM 拍板）+ #4 顺序语义拍板 | 决策记录进 bd 票 |
| 2 | P3-1 阶段 0 拆文件（#1） | 全套 32/32 + fmt/clippy/doc + 互操作矩阵 12/12 |
| 3 | #6 dispatcher background_tasks → FxScope（独立、低风险、白拿 in_flight 断言） | 现有 dispatch 系测试全绿 + 新增停机后 in_flight==0 断言测试 |
| 4 | P3-1 阶段 1-2（旁路表 + 双写对照，试点 blackhole/socks） | 对照差异率 0（硬门槛）；未知协议错误文案不变 |
| 5 | #3 SimpleOhm tagged → BoundedRegistry（先于 #4 全量切表，因为查表层共享此容器） | gRPC add/remove/list 单测 + 满表拒绝测试 + list_tags 确定序测试 |
| 6 | P3-1 阶段 3-4（切查表 → 删臂，inbound 先行） | 32/32 + 矩阵 12/12 + 抓包族按协议验收纪律 |
| 7 | #4 InboundRuntime slots → BoundedRegistry + #15 审计挂点 | ListInbounds 语义按拍板结果验收 + 注册/注销审计事件测试 |
| 8 | #8 ShutdownCoordinator 编排收口 | 停机测试：feature.close 挂死场景下报告 Timeout 且进程可退；panic 组件 Failed 隔离 |
| 9 | outbound.rs builder 化（复用 inbound 蹩平的模式） | 同 4-6 验收 + default=首个语义回归专项（[proxy,direct] 配置 default 必须是 proxy） |

**依赖链**：1→2→(3∥4)→5→6→7→8→9；每步独立 commit 独立可回滚；全程 32/32 为底线门。

---

## 7. 未决点

1. **InboundRuntime 顺序语义**：ListInbounds 注册序（Vec）→ tag 字典序（BTreeMap）是否可接受？观察者可见行为变化。
2. **proxyman 管理面去留**：删 or 留作 xray-frame 插件宿主原型——影响 #7/#13 节奏；proxyman worker 的 accept 实现质量不差（audit 79ma/ojcy 打穿），删前建议评估搬运价值。
3. **存量连接停机 drain**：主仓自认未完成（inbound.rs:3046）——是纳入 #8 coordinator 范围还是保持现状，需 PM 定（涉及长连接用户语义）。
4. **counter 预注册 vs 懒注册**：预注册消漂移但改 Go 对齐语义（Go 也是 GetOrRegister 懒语义）——漂移治理与 Go 对齐二选一。
5. **gRPC 动态注册的上限值与拒绝行为对齐**：Go 无上限；fail-closed 引入后 AddInbound/AddOutbound 的错误码语义要定（现 Go 侧无对应错误可对齐）。
6. **巨文件拆分的 commit 粒度**：11,388 行文件纯移动是否单 commit（review 负担大）还是分批（中间态编译失败风险）——建议按模块分 3-4 个 commit、每 commit 全绿。

---

*盘点人：InOutSurvey（代码语境搜索岗，只读）· 2026-10-23 · 全部行号一手实读；udf 签名核对源码：skeleton/src/pool.rs、skeleton-infra/{memgov,shutdown,fx,pool}.rs、std-ext/src/id.rs*

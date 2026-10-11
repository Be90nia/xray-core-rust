# 裁决 v2：数据面模式之争 —— 连接框架 + 有状态 Filter（深度嵌入）

- 日期：2026-10-11 ｜ 角色：FramingArch（只读顾问） ｜ 前序：`D:/tmp/oracle-framing-arch.md`（v1）
- 触发：项目所有者方向性质疑——"血肉全部依托骨架：log、内存、线程、new 对象都由骨架管理调度"；"架构+血肉 1+1>2"
- 证据基础：本轮新增泵所有权普查（file:line 实测）+ v1 全部实测结论；〔mem〕标注记忆库战役结论

---

## 0. 心证摘要

| 问题 | 裁决 |
|---|---|
| Q1 数据面切不切 Filter 模式 | **切。** 心证：这不是推翻现有架构，是把已经存在但分裂在 5+ 处的"框架泵"统一成一个引擎，并把协议代码从"泵的主人"降级为"被泵驱动的回调"。附三个硬条件（§2.4）。 |
| Q2 边界 | 三种嵌入形态（WireCodec / HeaderFilter / SessionService），**全部深度嵌入、无一挂在框架外**；硬边界只有一条：引擎自有 IO 的组件（quinn/hyper/tungstenite）不做 onData 化改造——代价声明见 §3.3，由所有者定夺。 |
| Q3 性能护栏 | 零 box 继承 v1 poll-based 结论；**每 chunk 禁令靠 API 结构成立**：Filter 拿到的是 `&mut MultiBuffer`，API 层面不存在返回裸分配的入口（§4）。 |
| Q4 Go diff | 所有者愿景优先。诚实账本：迁移期一次性成本 ≈ 每流式协议 +1 天（header 块翻译），持续维护成本**下降**（泵修复从 N 次变 1 次）；对齐损失被限制在 header 薄层，wirecodec 层（Go 耦合大头）零变化（§5）。 |
| Q5 迁移 | 引擎 = DialBridge 泛化（非推倒重写）；首迁 vmess inbound（现状最乱、收益最大）；新协议强制 Filter；存量分批；v1 P0 护栏全部存活且升级为 Filter 禁令的执法者（§6）。 |
| Q6 log/new | ConnCtx 提供一切（span/日志/统计/池/scratch/dial/唤醒/水位/受监督 spawn）；Filter 看不见 socket/runtime——**不可见即禁令**；对象构造=工厂注册表（build_x 模式转正）（§7）。 |

---

## 1. 事实基础（本轮新增：泵所有权普查）

v1 说"数据面是库模式"，本轮普查给出精确得多的图景——**现状是三种模式并存，其中深嵌入已经有成功先例**：

1. **框架泵已存在且久经战斗**：`DialBridge`（xray-app-dispatcher/default.rs:1117 `dispatch_link` 起）拥有 TCP 双向泵、超时（300s idle / 1s 半关闭窗〔mem：6bg/bw7〕）、splice 准入闸（default.rs:1768）、SizeStat 计数装饰。**vless inbound 已经是深嵌入样板**：server.rs accept → `decode_request_header` → `finish_vless_dispatch` → `handler.dispatch(dest, link)` 后协议退出，泵全归 dispatcher（server.rs:1-19 注释明示 dispatch 语义对齐 Go DispatchLink）。
2. **wirecodec 层已经是 poll-based 深嵌入**：vision_conn.rs / xor_conn.rs / common_conn.rs 全部实现为 `AsyncRead+AsyncWrite` 包装连接，内部是 `poll_read/poll_write` 状态机（vision_conn.rs:284-461 的 `let this = self.get_mut(); loop {...}` poll 形态）。**协议从未碰 socket、从未 spawn、从未自带日志——框架泵穿过它们。** 这正是所有者要的形态，且它扛住了 vision/enc 全部生产流量。
3. **分裂的是 relay/帧层**——同型工作至少 5 处各写各的泵：
   - vmess inbound：自带 duplex 泵（server.rs:391-394 `tokio::join!(pump_a, pump_b, dispatch_fut)`）+ 自带 UDP 泵（pump_udp_session，server.rs:357），代码里留着"空明文 chunk 转发即死锁"的自救注释（server.rs:620-622）；
   - vmess outbound：`make_vmess_dial_fn` 内部 `tokio::spawn` 双泵（dispatcher.rs:342-346）；
   - vless inbound UDP：自带长度前缀包循环（handler.rs:480）；
   - TUIC UDP：独立帧泵（xray-core/src/outbound.rs:2536-2598）；
   - socks/dokodemo UDP：各自会话泵（inbound.rs:223, 972）。
   每处都是独立的超时/半关闭/背压/EOF 语义拷贝——**vmess UDP 4s drainer、TUIC-UDP-走-TCP 静默错发（z9gp）这类 bug 全部诞生在这个分裂层**〔mem〕。这是"血肉没有依托骨架"的真实代价，也是 1+1>2 论证的主战场。
4. outbound 侧早已是钩子形态：`DialFn` 闭包 = "协议填函数、框架调用"，vless outbound 的 dial_fn 拨号+写头+返回包装连接（dispatcher.rs:28）后即退出。

**推论**：所有者要的"深度嵌入"不是从库模式起步的革命，是把 #1/#2 的成功模式（框架泵 + poll 状态机包装）推广到 #3 的分裂地带。工程路径存在且已被本仓自己验证过两次。

---

## 2. Q1：切换裁决与 Filter 形态

### 2.1 心证：切

理由三点：
1. **分裂层已经在付出真金白银的 bug 税**（§1.3 的五处泵与它们的 bug 史）——统一不是审美偏好，是止损。
2. **本仓已有两个深嵌入样板**（DialBridge、wirecodec poll 包装），v2 只是把"个别协议走了运"变成"制度"。
3. 所有者愿景与工程事实在这一点上**不冲突**：流式协议的 relay 语义（背压/半关闭/空闲/错误分类）本来就该只有一份。

### 2.2 Filter trait 精确形态（签名草图）

引擎两个半泵（up：client→server；down：server→client），每侧一个 Filter，Filter 有读/写两个 poll 回调：

```rust
pub enum Action {
    Continue,                    // 本 buffer 消费完毕，继续泵
    Parked,                      // Filter 等待外部事件（dial 完成/握手回包），引擎挂起本方向
    PauseRead,                   // 背压：本侧暂停读（水位，envoy watermark 语义）
    Close(RelayClose),           // 关闭；可携带 staged 回复字节（socks 拒绝回包等）
}

pub enum FilterEvent { UpEof, DownEof, UpError(Arc<RelayError>), DownError(Arc<RelayError>), DialDone, Timer }

/// 每连接一个实例（工厂创建，&mut self 独占状态，无锁）
pub trait RelayFilter: Send {
    /// up 方向：客户端字节进来，解码为 payload（推入 ctx.up_stage）
    fn poll_decode(&mut self, cx: &mut Context<'_>, ctx: &mut ConnCtx<'_>,
                   data: &mut MultiBuffer, eos: bool) -> Poll<Action>;
    /// down 方向：服务端字节进来，编码为客户端协议帧（推入 ctx.down_stage）
    fn poll_encode(&mut self, cx: &mut Context<'_>, ctx: &mut ConnCtx<'_>,
                   data: &mut MultiBuffer, eos: bool) -> Poll<Action>;
    fn on_event(&mut self, ctx: &mut ConnCtx<'_>, ev: FilterEvent) -> Action { Action::Continue }
}
```

**运行剖面（以 vless inbound 为例）**：
- Phase 0（header）：引擎只跑 `poll_decode`，喂首块；Filter 解出 UUID/目标后调 `ctx.dial(Destination, opts)` 返回 `Parked`——引擎挂起、用**现有 dial_fn** 拨号（出站协议的 header 编码发生在 dial_fn 内或 outbound Filter 的首次 poll_encode，两形态都合法）；
- Phase 1（relay）：dial 完成 → `on_event(DialDone)` → 引擎进入双半泵，up 侧客户端 payload 直接过（vless 头之后是裸 payload，Filter 变恒等）；down 侧首块下行触发 `poll_encode` 发 vless 响应头 + vision padding（对齐现状 finish_vless_dispatch 行为，server.rs:478-484）。

**关键语义决定**：

| 维度 | 语义 | 依据 |
|---|---|---|
| 状态归属 | Filter 独占（`&mut self`），会话级共享态经 ctx 句柄（validator/统计/限额） | 对齐 wirecodec 层现有 get_mut 状态机形态；无锁 |
| filter 间交接 | **所有权链**：data: &mut MultiBuffer 就地消费（split/freeze），产出只能推入 ctx 提供的 staging MultiBuffer——**Filter 之间不传引用、不传所有权，交接点在引擎的 staging**，链深起步=1（嗅探/统计是引擎服务不是 Filter），未来加深用 tuple combinator 单态化，**永不用 `Vec<Box<dyn Filter>>`** | 零 box 红线 |
| 半关闭 | eos 标志进回调 + `on_event(UpEof/DownEof)`；eos 后 Filter 可继续产帧（终帧/填充），引擎沿用 bridge 的 1s 半关闭窗；双向 eos 或 Close 才拆除 | 6bg/bw7 已验证语义原样继承 |
| 错误传播 | `RelayError { Up(io)/Down(io)/Protocol{reason, reply} }`；on_event(Error) 里 Filter 可向 ctx.down_stage 塞协议错误回包再 Close——引擎保证回包送达后才断 | socks/vless fallback 的"先回包再断"现状需求 |
| 挂起恢复 | `Parked` **不存 boxed future**：引擎把 waker 存进 ctx 槽，外部完成方（dial 完成/定时器）调 `ctx.wake()`——这是 bridge 现有 watch-channel 半关闭机制的泛化，不是新状态机 | 每 dial 一次 box 已在边界（v1 已接受），per-chunk 永不 box |

### 2.3 与 wirecodec 层的关系（重要：不是替代）

vision/xor/enc 等 `Connection` 包装**原样保留**，继续作为引擎的 wire 侧。它们已经就是"被框架驱动的有状态回调"，v2 不动它们一字——这同时是 Go 对齐保留最大的部分（逐文件镜像 Go）。

### 2.4 切换的三个硬条件（不满足不切）

1. **引擎必须是 DialBridge 泛化，不是重写**：旧路径 feature flag 并行一个过渡期；300s/1s/水位语义逐项继承。理由：bridge 是全仓战斗测试最充分的组件之一（6bg/bw7、splice 五闸），推倒=把已关的票重新打开。
2. **首迁协议必须是最乱的 vmess inbound**（duplex 泵+UDP 泵+join 全塌缩进引擎）：最乱处迁移成功才证明模型；最干净处（vless）先迁只证明样板戏。
3. **每个迁移闸门 = 32/32 integration + 计数分配器稳态 0 alloc/chunk + loopback ≥ 基线 154-167MB/s + 真实端点同窗 A/B**；同一协议迁移连续两次 A/B 回归 → 停手诊断（对齐 CI flake 铁律纪律〔mem〕）。

---

## 3. Q2：边界——三种嵌入形态，无一是"挂在外面"

| 形态 | 覆盖 | 回调形态 | 深嵌入契约（四给四禁） |
|---|---|---|---|
| **WireCodec**（连接包装） | vision/xor/enc/TLS/未来安全层 | poll_read/poll_write 状态机（现状即此） | 给：被引擎泵驱动的地位、池、ctx 级日志。禁：socket/spawn/直配 |
| **HeaderFilter**（本次新增） | vless/vmess/trojan/ss/http/socks/dokodemo/loopback/blackhole 的 header+relay 阶段 | poll_decode/poll_encode/on_event | 同上 + 禁自带泵 |
| **SessionService**（嵌入式例外） | QUIC/H3 族（quinn 自有事件循环）、h2/ws（hyper/tungstenite 自有）、kcp、XUDP/mux 会话机、UDP 会话表 | 引擎自有 IO → 服务回调（session/stream 粒度） | 同上，另加：**spawn 只能 `ctx.spawn_supervised()`**（框架 spawn+登记+会话结束回收）——这直接封掉 s9/s10 类 fd/RSS 泄漏的成因类〔mem：压测泄漏票〕 |

**硬边界（诚实声明，需所有者拍板）**：quinn/hyper/tungstenite **不做 onData 化**。让 QUIC 进 onData 回调链=抛弃 quinn 自研 QUIC 栈（年级别工程量+interop 全部重打），让 h2 进 onData=抛弃 hyper。这三家的协议逻辑（tuic/hysteria/splithttp/grpc/naive/ws）以 SessionService 形态嵌入——它们不拥有 socket、不自管日志统计、不自定超时策略，但保留引擎自有 IO。**若所有者要求连这也统一，代价是重写三个 IO 引擎，我的建议是明确拒绝**；除此之外的"统一"，全仓 32 协议全部落在三种嵌入形态内。

---

## 4. Q3：性能护栏——禁令的结构性成立

1. **零 box（继承 v1）**：trait 全 poll-based；引擎 `RelayEngine<I: RelayFilter, O: RelayFilter>` 按 filter 类型单态化；`Box<dyn>` 只允许出现在工厂边界（每连接一次）。
2. **每 chunk 禁令结构性成立——API 不给入口**：
   - 回调签名只有 `&mut MultiBuffer` 与 ctx staging：Filter **无法返回**新分配的所有权；产出=push 池化 Buffer；
   - 零拷贝进料只有一条路：`Buffer::from_bytes_frozen(Bytes)`（v1 已裁决的入口），Bytes 只从引擎侧（hyper/池）流入；
   - 协议 crate clippy `disallowed_methods`（to_vec/to_owned/Vec::new 白名单制）+ `disallowed_types`（禁 tokio::net 直接引用类型）——**协议代码想犯规都编译不过**，这才是"结构性"。
3. **验收口径（新增）**：计数分配器证明 relay 稳态每 chunk 分配数 = 0（v1 只要求"下降"）；UDP 小包路径同样 0。这是引擎合入的硬闸门。
4. 已知性能前科全部继承：readv opt-in、splice 准入闸保留在引擎（就是 v1 的逃逸舱条款，落点从 dispatcher 挪进引擎，语义不变）。

---

## 5. Q4：Go 上游 diff 重估（诚实账本）

| 成本项 | 评估 |
|---|---|
| wirecodec 层（vision/enc/xor/各协议加密编码——Go 耦合大头） | **零变化**。逐文件镜像关系保持（代码里 Go file:line 注释即映射表），上游同步照旧 |
| header 阶段 | Go `Process()` 的 header 块 → `poll_decode` 翻译。**一次性**成本 ≈ 每流式协议 +0.5~1 天（块小、机械、golden corpus=现有 32/32 integration 护航） |
| relay 阶段 | Go 本来就是 buf.Copy 框架泵，Rust 引擎与之同位——**对齐性反而更好**（现状 5 处私泵才是 diff） |
| 无 Go 对应物的新面 | RelayFilter trait 本身。缓解：trait 最小化（3 方法起步）；映射表扩展一栏"Go Process 段落 ↔ Filter 方法"；porting note 字段保留并加 header 映射义务 |
| 持续维护 | **下降**：上游 buf.Copy 语义变更 → 引擎单点改；泵类 bug（半关闭/背压/EOF）从"每个协议修一遍"变"修一次" |

结论：愿景优先可行，且**比 v1 的保守形态更省长期成本**；代价集中在一次性的 header 翻译，被 integration 全套兜底。所有者需要接受的永久性让步只有 §3.3 硬边界一项。

---

## 6. Q5：迁移策略

**次序**（与 v1 P0-P4 合并）：

1. **P0 护栏（进行中，AllocGuard 实施）**：全部存活且升级——计数分配器从"对比工具"升为"Filter 硬闸门执法者"；clippy 禁令清单扩展 disallowed_types/macros；基线照旧。**v2 不引入任何新护栏体系。**
2. **P1（不变，先行）**：to_vec 清零等 transport 层修复照做——**不与迁移捆绑**（一次改动只背一类风险）；引擎 RFC 并行起草。
3. **P2（不变）**：accept 框架——它本来就是框架模式，与引擎无耦合，并行推进。
4. **P2.5（新，v2 核心）**：RelayEngine 落地（DialBridge 泛化）→ 首迁 **vmess inbound**（闸门见 §2.4）→ vless → socks/http/trojan/ss 批量 → UDP 族（XUDP/socks-udp/dokodemo）以 SessionService 收编 → TUIC/H3/h2/ws/kcp 适配层核对四给四禁契约（多数已达标，补 spawn_supervised）。
5. **P3（不变+落点更新）**：水位/积压观测天然落在引擎（一次埋点全协议受益——1+1>2 直接兑现）。
6. **P4（改写）**：recipe=Filter recipe；新协议强制 Filter；转正门槛（≥3 用户 + A/B 数字）不变。

**过渡期双轨**：旧 Process 路径与引擎并行一个协议批次的周期（feature flag），禁止长期双轨——每个协议迁移合入即删旧泵，不留第二真相源。

---

## 7. Q6：log / new 归属

**ConnCtx 提供一切，不可见即禁令**：

```rust
pub struct ConnCtx<'a> {
    // 观测
    pub fn event(&self, level: Level, msg: &'static str, fields: &[(&'static str, &dyn Value)]);
    pub fn counter(&self) -> StatHandle;             // 上下行计数（SizeStat 语义挪进 ctx）
    // 资源
    pub fn alloc(&self) -> Buffer;                   // 池化
    pub fn scratch(&self) -> &mut ScratchPool;       // 每连接 scratch（vision caller-scratch 模式转正）
    // 控制面
    pub fn dial(&mut self, dest: Destination, opts: DialOpts) -> DialTicket;
    pub fn wake(&mut self);                          // Parked 恢复
    pub fn set_idle(&mut self, d: Duration);         // 活动计时（ActivityTimer 语义）
    pub fn spawn_supervised(&self, name: &'static str, fut: TaskFut) -> TaskHandle;
    // 访问信息（accept 时注入，header 后补全）
    pub access: AccessContext,                       // from/email/level/inbound_tag
}
```

- **Filter 可见**：上述句柄。**不可见**：socket 类型、runtime handle、SocketAddr 以外的任何 IO 原语、tokio::time——不提供即不可能用（编译期隔离，比 lint 更硬）。
- **log 归属**：span 由引擎在 accept 时创建（inbound tag/user/target 全量注入），协议只 `ctx.event(...)`；协议 crate 用 clippy `disallowed_macros` 禁 `tracing::*` 直接宏（自定义 lint 兜底）。所有者点名的"log 归骨架"逐字满足。
- **new 归属**：配置对象=工厂注册表（现有 build_x/try_build_handler 模式转正，〔mem：interop 批次惯例〕）：`register(tag, factory)`，factory 解析自己的 json 配置（协议自己的类型没问题——配置不是资源）；**资源对象**（连接/缓冲/任务/定时器）只能来自 ctx；per-conn Filter 实例由工厂 new（每连接一次分配，豁免并记录）。"线程管理"=`spawn_supervised`：协议请求、框架 spawn、会话表登记、会话终局回收——s9/s10 泄漏类结构性封死。

---

## 8. 1+1>2 的机制论证（结构性成立，不靠纪律）

1. **正交组合**：组合矩阵 = transport(握手) × wirecodec(加密) × HeaderFilter(协议语义) × routing。现状缝隙的全在 header/relay 分裂层：vmess UDP 空 chunk 死锁（server.rs:620）、mux carrier 拦截做在 dispatcher 装饰器（server.rs:11 被迫注释"carrier 拦截在生产 dispatcher"）、TUIC UDP 曾被当 TCP 载荷静默发出（z9gp〔mem〕）——**三个反例都是"协议语义洇进泵"**。引擎把 relay 语义定义一次，Filter 只表达协议语义，组合缝隙从结构上消失。
2. **单点优化全局放大**：杠杆比=嵌入协议数。现状已有正例：bridge 泵一次优化全部 TCP relay 受益（378ab889 那次失败也只失败一次）；io.rs 去 box 一次全体受益（v1）。v2 把同样的杠杆延伸到 header/relay 层：水位、readv、splice、半关闭调优全部变成单点。
3. **故障域统一**：同型 bug 五处各自修（§1.3）→ 一处修。4s drainer、空 chunk 死锁、TUIC 错发——这三类修复在引擎里是**同一处代码**。
4. **观测面免费**：引擎埋一次水位/chunk 计时/积压，32 协议同时获得——P3 观测面从"每协议埋点"变"引擎一次埋点"，这本身是 1+1>2 的可测量形态。

---

## 9. 诚实的代价与反模式警告（必须让所有者读到的部分）

1. **回调状态机的工效学代价**：线性 `async fn` 变成 poll 状态机后，"在循环里 .await"的直觉失效，新 bug 形态从"泵死锁"变成"Parked 后忘记 wake/在 eos 后多产帧"。缓解：协议接入测试 harness（引擎自带：脚本化 buffer 喂入 + 确定性断言，无需 socket）；wirecodec 层已证明本仓团队写得好这种代码（vision/enc 复杂度远超 header）。
2. **迁移期风险集中在 wire 格式解析**：header 块是 interop 血战赢来的最金贵代码（REALITY/utls 系列教训〔mem〕）。缓解铁律：**迁移=代码搬家不是重写**（parse 函数体原样进 poll_decode，只改借用形态）；golden corpus=现有 integration 全套；一批一个协议。
3. **引擎自身成为新单点**：引擎 bug = 全协议 bug（杠杆的反面）。缓解：旧 DialBridge 泛化而非重写 + 并行 flag 过渡 + §2.4 闸门。
4. **硬边界的政治成本**：QUIC/h2/ws 不 onData 化（§3.3）——统一度天花板由外部引擎决定，所有者需明确接受。

## 10. 可证伪条件与置信度

| 信号 | 推翻什么 |
|---|---|
| vmess inbound 首迁后同窗 A/B 回归，两轮修不平 | 引擎拓扑错（Parked 机制或 staging 交接），回到 v1 库模式+统一禁令的保守形态 |
| 稳态 0 alloc/chunk 无法达成（引擎自身泄漏分配） | API 设计有洞，停后续迁移先修 API |
| ≥3 个协议需要 SessionService 之外的自有异步能力 | Action::Parked 模型不足，trait 需要修订（升级前全停） |
| header 翻译单个协议 >3 天 | "机械翻译"判断错，重估 §5 账本 |
| quinn/hyper 版本升级反复破坏 SessionService 契约 | 适配层太薄，加隔离垫片或降级该族为"库模式白名单" |

**置信度**：切换方向与 Filter 形态——**高**（本仓两个深嵌入样板 + 分裂层 bug 税实证）；Parked/交接所有权细节——**中**（首迁 vmess 前属设计草案，允许 RFC 微调）；Go diff 账本——**中高**（header 翻译工作量是推断，golden corpus 兜底）；硬边界判断——**高**（重写 quinn/hyper 的代价数量级无争议）。

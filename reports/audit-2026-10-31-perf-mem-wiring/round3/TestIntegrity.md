# 第三轮 · 测试完整性审计（TestIntegrity）

- 仓库 `D:/Project/Xray-core-rust`，分支 `feature/fix-inbound-parity`，HEAD `5fe98b90`
- 口径：**生产主路** = 默认 `xray.exe run -c`（`xray_conf::Config::build()` → `xray_core::start_full`）
- 零产品代码改动（只读审计）；不与前两轮 30 条重复（那 30 条是**行为缺陷**，本轮是**为什么这些缺陷能一路绿灯**）
- 工具：serena-cli 未用（本轮全为跨文件模式统计，正则+脚本比符号检索更合适）；全量 `grep`/`read` + Python 脚本统计

---

## 0 一句话结论

**「写了一半能一路绿灯」不是偶然，是测试套件的结构性缺陷。** 三条独立的机制共同造成：

1. **L4 契约夹具验的是框架，不是插件**（55/56 条 `l4_*` 测试的函数体里根本没有插件类型）→ 声明了 12 条条款的插件，只要框架原语本身没坏，就永远绿；
2. **契约宏的断言面比它的文档承诺小得多**（`deps()` 结果被丢弃、`build()` 从不被调用、16/16 插件的 lifecycle 全是 `Ok(())`）→ 宏只验「插件不崩」，不验「插件做了什么」；
3. **CI 10 门全部可以在「协议层完全没接线」的前提下全绿**——因为没有一门跑「配置 → 生产主路 → 真实协议握手 → 数据面字节」的全链 e2e，只有 HTTP/SOCKS 解析器的差分门。

补一句第三层的量化：**仓库有 7938 个测试函数，但生产主路上「配置写错 → 启动即报」这句话只在框架路成立**（前两轮已证）。本轮找到了为什么这条差异能长期不被测出来：**差异台账契约测试（`assembly_path_equivalence.rs`）比对的是两侧的「数据源源码文本」，不是两侧的运行时行为**。

---

## 1 假绿清单（17 条）

严重度定义：**S1** = 保护的是安全/凭据/数据面正确性，缺陷可逃逸到生产；**S2** = 保护的是「装配/协议/错误路径」语义，缺陷会变成静默降级；**S3** = 命名/覆盖面误导，不直接放行缺陷。

### 1.1 L4 契约夹具「验框架不验插件」（元问题，最大宗）

| # | 位置 | 假绿类型 | 证据（为什么恒真/同错） | 应改成什么断言 | 严重度 |
|---|---|---|---|---|---|
| F1 | `crates/xray-proxy-{anytls,blackhole,dns,dokodemo,freedom,http,hysteria,loopback,socks,ss,trojan,tuic,tun,vless,vmess,wireguard}/tests/plugin_contract.rs`（56 条 `l4_*`） | **测夹具不测被测**（mock 自洽） | 逐条统计：**56 条 `l4_*` 中 55 条的函数体里没有插件类型名**（唯一例外是 ss 的 `l4_real_instance_...`）。例：`l4_pool_discipline_balances` 只 `ManagedBufferPool::new(XrayBufPool::new(8,8),8,8)` 后借还 4 块——池是夹具自造的，插件的池消费点从未出场。`l4_log_fields_quadruple_masked` 只断言「`LogFacade::new("vmess")` 拼出的 target 前缀对」——插件真实的 `LogFacade::new("vmess", vec![])` 静态量是否被正确调用，四元组是否真的进了生产日志，无人验。 | 夹具必须接受**插件实例**或**插件产出的资源**作为入参：pool 夹具应借插件自己的池（经 `ctx.pool()`），log 夹具应捕获插件真实 `emit` 的事件并断言四元组来自插件真实字段而非夹具字面量 | **S1** |
| F2 | 同上（16 个 crate 各一条 `l4_conn_id_present*`） | **测夹具不测被测** | `ctx.next_conn_id()` 全仓**只有 xray-frame 自己和这 16 条测试在调**（`grep next_conn_id` 全仓 23 处命中，生产 `xray-proxy-*/src/` 命中数 = **0**）。即：坑约束 3「每连接必有 conn_id」在 16 个协议的生产代码里**从未实现**，而 16 个 crate 各自的契约测试都宣称覆盖该条款。 | 要么补生产侧 `ctx.next_conn_id()` 调用并让夹具断言插件产出的连接带 id，要么把条款 3 从「全适用」降级为 N/A（带理由）——现状是**声明与实现两头都空** | **S1** |
| F3 | 同上（16 条 `l4_deadline_effective`） | **测夹具不测被测** | 夹具体是 `assert_deadline_effective!(100ms, \|\| async {})` / `\|\| async { yield_now().await }`——**work 闭包是空的或只 yield 一次**，测的是「框架的 `with_deadline` 能掐断一个永不完成的 future」，与插件的握手时限无关。anytls 甚至明确把条款 2 声明为 N/A 并跳过该夹具。 | work 闭包应是**插件真实的握手步骤**（读首包 → 校验 → 建链），且断言「首包未在 d 内到达 → 插件拒连」，不是断言框架原语 | **S2** |
| F4 | `crates/xray-frame/src/contract_assert.rs:146-190`（`assert_contract_for`） | **断言面小于承诺** | 文档头承诺「逐条断言 ①必选方法集 ②clauses/N-A ③extra ④lifecycle 三相」。实际：① 中 `let _ = plugin.deps();`——**deps 的返回值被直接丢弃**（deps 拓扑门因此对插件零鉴别力）；④ 只验 lifecycle 不返 `Err`，而**16/16 协议的 lifecycle 三相全是 `Ok(())`**（实测逐个 `impl Lifecycle for` 扫过：`Ok(())` ×3 各 crate），即「三相可调且不 panic」退化为「三相是空函数」恒真。**`plugin.build()` 从未被调用**（grep 确认 `build(` 不在宏体内）——条款 7「配置段路由」在宏层零覆盖。 | 宏应：断言 `deps()` 非空时每个 dep 名在注册表中可解析；断言 `build()` 在缺段时返回 `Err`（条款 7 的执行面）；或明确文档「本宏只验声明面 + lifecycle 不崩」，并把执行面责任指派到各 crate 的真实实例夹具 | **S1** |
| F5 | 16 个 crate 的 `contract_surface_declares_*` | **只验声明文本** | 这批测试断言的是 `contract.clauses.len() == 12` 与 `contract.clauses.contains(clause)`——即「插件声明了 12 条条款」。**声明 ≠ 实现**。条款 1（AuthErrorClassified）、5（SpawnManaged）、8（ErrorClassifiedNoPanicEscape）、12（HotPathFreeze）在 `contract_assert.rs` 自己的「条款声明态」表里就写着**「仅声明」**（无任何执行断言面），但每个 crate 的契约测试文件头仍写「12 条全适用」。 | 契约测试应断言**行为**（如条款 8：注入一个 panic 的 handler → 断言不逃逸 IO 线程 + 错误被归类），而不是断言条款列表长度 | **S1** |

### 1.2 恒真 / 无断言 / 命名承诺落空

| # | 位置 | 假绿类型 | 证据 | 应改成什么断言 | 严重度 |
|---|---|---|---|---|---|
| F6 | `crates/xray-transport-quic/src/config.rs:343` `build_transport_config_default_is_cubic` | **命名承诺 ≠ 体断言** | 函数名承诺「default is cubic」，体只有 `let _t = cfg.build_transport_config();`——**零断言**。既不验 cubic 也不验任何值。旁边的 `build_transport_config_case_insensitive`（:349）同型：注释自己承认「不 panic 即可——quinn TransportConfig 内部不暴露已设的 congestion 类型」。 | 用 `format!("{:?}", cfg.build_transport_config())` 回读字段（该文件 `:357` 的 idle_timeout 测试就是这么做的），断言 Debug 输出含 `congestion` 期望值；做不到就改名 `build_transport_config_does_not_panic` | **S3** |
| F7 | `crates/xray-transport-quic/src/config.rs:349` `build_transport_config_case_insensitive` | 同上 | 体零断言。 | 同上 | **S3** |
| F8 | `crates/xray-proxy-vless/src/encryption/mod.rs:2187` `ml_kem_768_try_decapsulate_default_ciphertext` | **只测「不崩」** | 体：`let _ = dk.try_decapsulate(&default_ct);` + 注释「返回 Ok 或 Err 都合法——只要不 panic」。密文解封装失败与成功在同一断言下不可区分。 | 断言 `Err` 且错误类型为 ML-KEM 规定的隐式拒绝（implicit rejection）——这正是 ML-KEM 的安全性质所在，「Err 或 Ok 都行」把安全性质删了 | **S2** |
| F9 | `crates/xray-core/src/instance.rs:416` `panic_hook_install_is_idempotent` | **只测「不崩」+ 命名无据** | 体：两次 `install_panic_hook();`，零断言。「幂等」的判据是「hook 只装一次」，而体只证明「装两次不崩」。 | 断言 hook 的全局状态计数不变（需要暴露一个可观测计数），或改名 | **S3** |
| F10 | `crates/xray-app-dns/src/error.rs:130` `from_rcode_nonzero_is_rcode_error` | **断言等价于体**（正则漏检） | 体用 `match { DnsError::RCodeError(3) => {}, other => panic!(...) }`——**有真断言**（我第一版正则把它误判成无断言，已手验改正）。保留在此是为了记录「match-arm 形式断言」不在 `assert!` 家族里，**任何自动化假绿扫描必须同时认 `match`+`panic!` 形式**，否则会误报/漏报 | 无需改（记录扫描器口径） | — |
| F11 | `crates/xray-proxy-anytls/src/inbound.rs:340` `handler_without_password_allows_connection` | **把失败路径固化为期望** | 测试名与注释「未配密码（None）时保持旧语义：任意/无校验连接可用」+ 体断言「客户端用任意密码 `whatever` 能建连并 echo 通」。这**把「无口令 = 零认证 = 开放代理」写成了期望行为**。Go 26.10.17 的 anytls 入站无口令是 fail-closed。测试的存在使未来修这个洞会「弄红测试」，从而**反向保护缺陷**。 | 改成负向断言：段无 `password` 时，`build` 返 `Err`（或服务端拒绝任意密码连接）。当前形态应登记为「已知 fail-open，修复时同步改此测试」 | **S1** |
| F12 | `crates/xray-core/src/outbound.rs:3647` `register_vless_invalid_uuid_skipped` | **把失败路径固化为期望** | 体：注入坏 UUID → `register_outbounds(...).unwrap()`（不 Err）→ 断言 `ohm.get_handler("bad-vless").is_none()`。即：**配置写错 → 出站被静默丢弃 → 以为在代理实际直连**，被写成「预期」。同族 `:4716 register_socks_missing_servers_skipped`、`:3633 tun_outbound_skipped_on_unsupported_platform`。 | 改成断言 `register_outbounds` 返回 `Err`（或至少断言 `ohm` 中**不存在任何** default handler，即不会被前一条出站顶替成直连）。当前形态即前一轮 `o91s4` P0 票的「为什么它一路绿灯」的答案 | **S1** |
| F13 | `crates/xray-core/src/functions.rs:1085` `start_from_built_skips_unregistered_kind` | **把失败路径固化为期望** | 体：注入未知 app kind → `start_from_built(&built).expect(...)`（成功）→ 断言 `feature_count() == 4`（默认 4 + 未知被跳过）。注释明写「Go 行为：factory 失败时跳过该 feature，继续启动其余」（`:1117`）。同族 `:1116 start_from_built_factory_error_skipped`。 | 若 Go 26.10.17 确实是 skip 语义，则该测试是**正确的**——但需在测试里写明「Go v26.10.17 `app/start.go` 对应行为 + 出处」，否则下一个人会误以为这是本仓发明的宽容 | **S2** |
| F14 | `crates/xray-core/src/wiring.rs:2425` `sniffing_exclusions_bad_rule_skipped_others_kept` | **把失败路径固化为期望 + 注释自认降级** | 注释自陈：「**Go 为 Build 期硬错**；本函数签名无 Result 且调用方在票外，**降级为可见告警**」。测试断言「坏规则被跳过、好规则保留」。前一轮 `vdl95` P1（sniffing 排除表整表失效）的根因即此。 | 修正后（Go 对齐硬错）该测试应断言 build 返 `Err`；当前形态应显式标注「已知口径差异，Go=硬错 / Rust=跳过」并绑定 bd 票号 | **S2** |
| F15 | `crates/xray-core/src/router.rs:453` `pattern_router_skips_rule_without_outbound_tag` | **把失败路径固化为期望** | 体：注入 `{"domain":["x.com"]}`（无 `outboundTag`）→ 断言 `rules_len_for_test() == 0`（整条规则被丢弃）。前一轮 `vaye2` P0（路由解析失败静默降级 PatternRouter，屏蔽规则失效）的行为面。 | 对齐 Go：规则缺 `outboundTag` 属配置错误 → 应 fail-visible 或至少保留规则 + 走 catch-all，而不是静默丢整条 | **S1** |
| F16 | `crates/xray-app-proxyman/src/command/mod.rs:895` `add_inbound_always_returns_other_todo` | **把未实现固化为期望（字面 todo）** | 测试名里的 `todo` 是生产代码的 `ProxymanError::Other(...)`（gRPC `AddInbound` 未实现）。断言「永远返回 Other」= 把未实现功能锁死成契约。 | 改成 `#[ignore]` + `todo!` 标记，或直接断言生产代码里的 `todo` 语义在有朝一日被移除时该测试会红（即把断言绑到「此 API 尚未接线」这一可观测事实） | **S3** |
| F17 | 27 条 `*_no_panic` / `*_does_not_panic` / `*_compile` 形态测试 | **只测「不崩」** | 例：`crates/xray-app-metrics/src/error.rs:124 at_error_does_not_panic`、`crates/xray-app-reverse/src/error.rs:122 at_error_no_panic`、`crates/xray-proxy-wireguard/src/netstack.rs:847 ingest_rx_does_not_panic`、`crates/xray-proxy-tun/src/netstack.rs:936 ingest_rx_does_not_panic`（**两个 netstack 的 `ingest_rx_does_not_panic` 都是零断言**）。这类测试**无法区分「处理正确」与「吞掉了输入」**——对 `ingest_rx` 这种数据面入口尤其危险：吞输入 = 静默黑洞。 | 对数据面入口类（`ingest_rx`）必须断言**可观测副作用**（包被投递到对端 / 计数增加 / 错误被分类），而不是「没崩」 | **S2** |

### 1.3 统计口径（可复算）

| 指标 | 值 | 复算方法 |
|---|---|---|
| 全仓 `#[test]` / `#[tokio::test]` 属性 | 7941 | 正则 `#\[(?:tokio::)?test\]` 扫 `crates/**/*.rs`（排除 `crates/udf-frame/`） |
| 测试函数（解析出函数体的） | 7938 | 配对属性 + `fn` + 花括号配平 |
| **零断言测试**（体与属性均无 `assert*!`/`panic!`/`expect(`/`unwrap()`/`matches!`/`.is_ok()`/`.is_err()`） | **135**（1.7%） | 同上；**注意**：`match`+`panic!` 形式的断言（如 F10）会被此口径误判为「零断言」，需人工过一遍 |
| 「命名承诺一个值/行为但体无断言」 | **25** | 名称含 `is_`/`_is`/`equals`/`has_`/`default_is`/`case_insensitive`/`correct`/`exact` 且体零断言 |
| 「只测不崩」形态（`*_no_panic` / `*_compile` / `*_implements_*` / `*_satisfies_traits` / `*_construct*` / `*_is_callable`） | **67**，其中 **27 条零断言** | 名称正则 + 体扫描 |
| **L4 契约夹具中不含插件类型的** | **55 / 56（98%）** | 逐条取函数体，正则搜插件类型名（如 `SsPlugin`） |
| **协议 crate 中 `next_conn_id` 的生产调用点** | **0**（16/16 crate） | `grep next_conn_id` 全仓，生产 `xray-proxy-*/src/` 命中 0 |
| **协议 crate 的 lifecycle 三相全为 `Ok(())`** | **16 / 16** | 逐个 `impl Lifecycle for` 扫 `Ok(())` 计数 = 3 |
| 构造但**从未在任何测试中被提及**的错误变体 | **56 个**（14 crate） | 见 §2 清单 |
| `#[ignore]` 测试 | **17 / 7941（0.21%）** | 属性块扫描（`#[ignore]` 可在 `#[test]` 前后两处，需双向扫） |

---

## 2 无覆盖生产路径清单

判定口径：**生产主路上会跑、且失败时用户可见（启动失败 / 连接被拒 / 数据错误 / 静默降级），但当前没有任何测试触达该分支**。给出最小补测建议（不写测试）。

### 2.1 协议握手 / 鉴权失败路径（最高优先）

| 路径 | 为何重要 | 未覆盖证据 | 最小补测建议 |
|---|---|---|---|
| `crates/xray-proxy-ss/src/ss2022/key.rs:192,201` `SsError::InvalidPassword`（PSK base64 解码失败 / 长度不匹配） | ss2022 的**唯一凭据校验点**。错 PSK 若被放行 = 任何人都能连上 | `SsError::InvalidPassword` 在全仓**任何测试中都未被提及**（只在 doc 注释与生产构造点出现） | 单测：给定 16/32 字节 PSK 与错误长度 → 断言 `Err(InvalidPassword)` 且错误文案含期望长度 |
| `crates/xray-proxy-ss/src/ss2022/inbound.rs:551,666` `SsError::Ss2022SaltNotUnique` | 2022 协议的 salt 唯一性 = 防重放的核心。静默放过 = 重放窗口打开 | 该变体零测试提及 | 单测：构造两个用户共用 salt → 断言 `Err(Ss2022SaltNotUnique)` |
| `crates/xray-proxy-ss/src/ss2022/inbound.rs:686,689` + `packet.rs:235,270` `SsError::Ss2022TimestampCheck` | 时间戳窗口 = 重放防护 | 零测试提及 | 单测：构造时间戳偏移超窗的包 → 断言 `Err(Ss2022TimestampCheck)` 且**窗口边界值**（恰好 = 窗 / 窗+1s）分别通过/拒绝 |
| `crates/xray-proxy-ss/src/ss2022/inbound.rs` `SsError::Ss2022InvalidHeaderType` / `Ss2022MissingKey` | 畸形帧/缺密钥字段 = 解析边界 | 零测试提及 | 单测：改写 header type 字节 / 截短 key 字段 → 断言对应变体 |
| `crates/xray-proxy-vmess/src/encoding/server.rs:264` `VmessError::InvalidAuth` | **vmess 的 auth id 校验 = 凭据校验本体**（`expected_auth != actual_auth`） | 零测试提及。注意 VMESS-U16 条款在 `plugin.rs` 里被声明为「适用」，但没有任何测试触碰 u16 溢出的**报错**路径（`body_chunk.rs:312`、`dispatcher.rs:996`、`inbound/server.rs:521,552,599` 五处 `u16::try_from(...).map_err(...)` 全零覆盖） | ① 单测：篡改 auth id 4 字节 → 断言 `Err(InvalidAuth)` 且连接被断；② 单测：构造 >64KiB chunk → 断言 `Err("vmess chunk size exceeds u16")`（**这条是 VMESS-U16 条款的唯一执行面，现在条款是空的**） |
| `crates/xray-proxy-vmess/src/encoding/server.rs:241` `VmessError::UnknownCommand` | 命令字节白名单 = 协议边界 | 零测试提及 | 单测：command = 0xFF → 断言 `Err(UnknownCommand)` |
| `crates/xray-proxy-vmess/src/validator.rs:160` `VmessError::InvalidTime` | auth id 的时间校验 = 重放防护 | 零测试提及 | 单测：注入偏移时间 → 断言 `Err(InvalidTime)` |
| `crates/xray-proxy-socks/src/server.rs:267,487,509` `SocksError::AuthFailed` | **SOCKS 服务端鉴权三处失败点**（无匹配方法 / 非法 auth 版本 / 用户名密码错）。当前 `:509` 是「密码错」的唯一闸 | `SocksError::AuthFailed` 零测试提及（client 侧 `:186-233` 有构造但也无断言） | e2e：SOCKS5 用户名密码模式下送错密码 → 断言服务端**不发** auth-success（0x01）且连接关闭 |
| `crates/xray-proxy-trojan/src/validator.rs:52,54,57` `TrojanError::InvalidUserAccount` | trojan 入站的**唯一用户校验点**（无 account / 非法 uuid） | 零测试提及 | 单测：用户条目缺 `account` / account 非 uuid → 断言 `Err(InvalidUserAccount)` |
| `crates/xray-proxy-trojan/src/server.rs` `ReadUserHash`/`ReadPayloadLength`/`ReadCrlf`/`ReadCommand`/`ReadAddressPort` | trojan 请求帧解析的 5 个字节级边界（各自独立的截断点） | 5 个变体全零覆盖 | 参数化单测：每个截断长度（0..N）→ 断言对应变体（**当前这 5 个截断点的行为完全无保护**） |
| `crates/xray-proxy-anytls/src/inbound.rs` `AnytlsError::InvalidSocksAddr` | anytls 地址解析边界 | 零测试提及 | 单测：非法 SocksAddr → 断言 `Err` |
| `crates/xray-proxy-http/src/server.rs:669,752,931,1037,1244,1280` `HttpProxyError::InvalidRequest` | HTTP 畸形请求的 6 个拒绝点（Content-Length / status line / chunk size / 头解析 / IPv6 / 空 host） | 变体零覆盖，但**行为**被 `tests/http_proxy_e2e.rs` 的 `assert_rejected_without_response` 覆盖（`crates/xray-proxy-http/tests/http_proxy_e2e.rs:542`）——**这是唯一一处「行为覆盖到位」的协议解析族，可作范式** | 把 e2e 的畸形用例表镜像到 unit 层，断言具体变体（e2e 只断言「无响应」，不区分拒绝原因） |
| `crates/xray-proxy-tuic/src` `TuicError::ProtocolParse` / `QuinnRead` / `QuinnSendDatagram` / `UdpTimeout` / `KeyingMaterialExport` | TUIC 的协议解析 + quinn 适配层错误映射（**错误映射 = 用户看到的错误类型**） | 5 个变体零覆盖 | 单测：错误映射表逐项断言（哪类底层错误 → 哪个 tuic 变体） |
| `crates/xray-proxy-wireguard/src` `WgError::HandshakeFailed` / `NetStack` | wg 握手失败 = 用户看不到原因 | 零覆盖 | 单测：错误路径断言变体 |
| `crates/xray-proxy-tun/src` `TunError::TcpListenFailed` / `UdpBindFailed` | tun 监听失败 = 权限/端口问题的唯一诊断信号 | 零覆盖 | 单测：占用端口 → 断言变体 |
| `crates/xray-proxy-dns/src` `DnsProxyError::UpstreamForwardFailed` | DNS 上游转发失败 | 零覆盖 | 单测：上游不可达 → 断言变体 |
| `crates/xray-transport-websocket/src` `WsError::FrameTooLarge` / `InvalidUpgradeRequest` | WS 帧长上限 = 内存上限；upgrade 校验 | 零覆盖 | 单测：超长帧 / 非法 upgrade → 断言变体 |
| `crates/xray-transport-splithttp/src` `SplitHttpError::InvalidPlacement` / `ListenFailed` / `Hyper` | splithttp 的 header placement（Go 兼容关键）+ 监听失败 | 零覆盖 | 单测：错 placement → 断言变体 |
| `crates/xray-transport-grpc/src` `GrpcError::Decompression` / `InvalidConfig` | gRPC 解压炸弹 / 配置非法 | 零覆盖 | 单测：压缩炸弹 → 断言变体 |

> 小计：**56 个错误变体在生产路径上构造、但从未被任何测试触及**（14 个 crate 有未覆盖变体；16 个 crate 全查）。这些正是「写了一半」的载体——代码写了错误分支，但没人验证它对不对。

### 2.2 装配期 warn+skip 分支（生产主路）

| 路径 | 为何重要 | 未覆盖证据 | 最小补测建议 |
|---|---|---|---|
| `crates/xray-core/src/outbound.rs:230-245` `register_outbounds` 的 `Err(BuildError::Unsupported)` / `Err(BuildError::Parse)` 两个 warn+skip 臂 | **生产主路唯一的出站失败语义**。skip 后「以为在代理实际直连」= 前一轮 `o91s4` P0 | 有测试但**断言方向相反**（见 F12）——测的是「被跳过」而非「应失败」 | 断言 `register_outbounds` 返回 `Err`；或断言 skip 后 `ohm` 无 default handler（不能静默落到前一条出站） |
| `crates/xray-core/src/outbound.rs` Phase 2 `mux via tag not found, fallback default`（`~:296`） | 代理链指向不存在的 tag → 静默回落到 default（可能直连） | 该分支零覆盖 | 单测：mux via = 不存在的 tag → 断言行为是 `Err` 而非回落 default |
| `crates/xray-core/src/inbound.rs:3891` trojan 重复用户 skip / `:4621` vless 重复用户 skip / `:5056` vmess 重复用户 skip | 重复用户 = 同 email 覆盖 = 凭据面歧义 | 三处 warn 文案在测试中**从未被断言**（只在生产与 plugin.rs 注释里出现） | 单测：两条同 email 用户 → 断言 skip 行为 + 断言 **warn 不含凭据原文**（trojan 侧已有 `duplicate_user_warn_carries_no_password` 做密码掩码，但 vless/vmess 无对应测试） |
| `crates/xray-core/src/functions.rs:1085` 未知 app kind skip / `:1116` factory 错误 skip | app 面失败 = 功能静默缺失 | 行为被断言为「跳过」（F13），但**无「未知 kind 应启动失败」的对照** | 补一条与 Go `app/start.go` 对齐的对照断言 |
| `crates/xray-core/src/arm_registry.rs:187` `reg.start_order().expect("arm registry: deps 门（当前无 deps 声明）")` | **生产 deps 拓扑门是空跑**——所有 16 个协议插件 `deps()` 都返回 `&[]`（实测逐个扫过），所以「缺依赖/成环 → 启动前 fail-visible」这条 L5 门在生产主路上**永远不可能触发** | 无插件声明 deps，故该门在生产侧零覆盖 | 加一个声明 deps 的真实插件（或让 loopback 声明对 dispatcher 的依赖）以让该门在生产路径上可被触发；否则应把 L5 的「deps 门」从生产保证降级为「框架机制已实现」 |

### 2.3 框架主路 / 装配链

| 路径 | 为何重要 | 未覆盖证据 | 最小补测建议 |
|---|---|---|---|
| `crates/xray-core/tests/assembly_path_equivalence.rs` **比对的是两侧数据源的源码文本**（`include_str!("../src/arm_builders/mod.rs")` + `include_str!("../../xray-cli/src/framework.rs")`），不是运行时行为 | 这是「生产主路 vs 框架主路」的**唯一**契约测试，也是前两轮反复引用的「差异台账」 | 文件头自陈：`shortcut: ③ 的框架侧 fail-visible 行为只有源码级证据…真机端到端在 --features framework-assembly 的 e2e 里`。**该 e2e 是否存在且默认构建？** 需核实；若不在默认构建，则整个框架主路**零端到端覆盖** | 把台账从「源码文本比对」升级为「两条路各跑一遍同一份配置，比对观测到的 handler 表 / 失败语义」；至少加一条「同一份坏配置在两路上的失败语义对比」 |
| `crates/xray-core/src/arm_builders/inbound.rs` UDS 9 变体（`uds_tests.rs:65`） | UDS 形态覆盖已收进同一张表 | 有覆盖（该测试逐变体建连）——**这是本仓少数「行为覆盖到位」的装配测试，可作范式** | 无需补；可作其他装配面的范式 |
| `crates/xray-cli/src/framework.rs` 框架路整体 | 目标主路（`framework-assembly`）**未进默认构建** | `crates/xray-core/tests/assembly_path_equivalence.rs` 是唯一引用它的测试 | 框架路至少一条 e2e 进默认 CI（见 §3 建议） |

---

## 3 契约测试的真实性评估

### 3.1 `assert_plugin_contract!` 夹具到底断言了什么

**结论：它断言的是「插件的声明面自洽 + lifecycle 不返 `Err`」，不是「插件的行为符合条款」。**

逐条对账（`crates/xray-frame/src/contract_assert.rs:146-190`）：

| 文档承诺 | 实际断言 | 判别力 |
|---|---|---|
| ① 必选方法集可调，name 非空且稳定、version 非空 | 真断言 | ✅ 有（name 空 / version 空 / name 不稳定会红） |
| ① deps 可调 | `let _ = plugin.deps();` —— **返回值丢弃** | ❌ **零判别力** |
| ② clauses 与 not_applicable 不重叠、N/A 理由非空 | 真断言 | ✅ 有 |
| ③ extra 键值非空 | 真断言 | ✅ 有 |
| ④ lifecycle 三相可调且不 panic | 真断言，但 **16/16 协议的 lifecycle 全是 `Ok(())`** → 退化为恒真 | ⚠️ **形式有、实质零** |
| （未承诺）build 路径 | **`plugin.build()` 从不被调用** | ❌ 条款 7 在宏层零覆盖 |
| （未承诺）条款行为 | 无 | ❌ 条款 1/5/8/12 官方标注「仅声明」 |

### 3.2 16 个协议夹具对最关键条款的覆盖

| 条款 | 官方声明态 | 16 crate 的实际执行面 | 评价 |
|---|---|---|---|
| 1 AuthErrorClassified | **仅声明** | 零 | ❌ 认证失败分类无任何执行断言——**这正是 anytls/ss 空口令能绿灯的原因** |
| 2 HandshakeDeadline | 已实现 | 夹具 work 闭包为空/只 yield（框架原语） | ⚠️ 验框架不验插件（F3） |
| 3 ConnIdPresent | 已实现 | 夹具用框架 ctx；**生产代码零调用 `next_conn_id()`** | ❌ 声明与实现两头空（F2） |
| 4 PoolDiscipline | 部分 | 夹具用夹具自造的池 | ⚠️ 验夹具不验插件（F1） |
| 5 SpawnManaged | **仅声明** | 零 | ❌ |
| 6 StopRegistered | 已实现 | **15/16 crate 真断言 `stopped == ["<crate>"]`**（blackhole 缺） | ✅ 唯一判别力扎实的一条 |
| 7 ConfigSectionOnly | 部分 | 各 crate 自写缺段负向（不统一） | ⚠️ 覆盖不统一 |
| 8 ErrorClassifiedNoPanicEscape | **仅声明** | 零 | ❌ |
| 9 BoundedResources | 部分 | 仅经池借还账面 | ⚠️ 「资源上有界」本身无断言 |
| 10 LogDiscipline | 已实现 | 夹具验框架 LogFacade 的 target 拼接 | ⚠️ 验框架不验插件（F1） |
| 11 SecretMasking | 已实现 | 夹具验框架掩码表；**插件自己的 secrets 表未验**（如 anytls 的 password 是否进掩码表） | ⚠️ 验框架不验插件 |
| 12 HotPathFreeze | **仅声明** | 零 | ❌ |

**统计**：12 条条款中，**执行面判别力为「零」的有 5 条（1/3/5/8/12）、为「验框架不验插件」的有 4 条（2/4/10/11）、仅 3 条有真实判别力（6/7 部分/9 部分）**。而每个 crate 的契约测试文件头普遍写着「12 条全适用」。

### 3.3 夹具的「真实实例」覆盖：3/16

只有 `ss`、`trojan`、`vless` 三个 crate 有 `l4_real_instance_contract_lifecycle_and_stop_registered`（真插件实例 → `bring_up` → `shutdown` → 断言 `stopped == ["<crate>"]` → `face()` 产物判别）。其余 13 个 crate 的契约测试**止步于声明面 + 框架原语**。

> 注：`crates/xray-frame/src/contract_assert.rs` 模块文档声称「16 个协议 crate 的 tests/plugin_contract.rs **全部**接真实插件实例夹具…16 夹具实跑全绿」（D4 复核 2026-10-31）——**该文档陈述与代码不符**（实测 3/16）。这本身是一条「文档谎称覆盖」的假绿。

---

## 4 CI 门强度评估

### 4.1 10 门逐门拆解

`.github/workflows/ci.yml` 的 10 个 job（+ `interop.yml` 独立 workflow）：

| # | 门 | 跑什么 | 单测通过的前提下还能放过什么真缺陷 | 强度 |
|---|---|---|---|---|
| 1 | **Format** | 逐 workspace 成员 `cargo fmt -p <c> -- --check` | 排版。**零行为覆盖** | 弱（但必要） |
| 2 | **Clippy** | `cargo clippy --workspace --all-targets -- -D warnings` | 静态。`disallowed-methods` lint 能抓裸 spawn/裸 tracing/println 等——**这是唯一能抓住「裸能力逃逸」的门**。但抓不到「协议没接线」「认证被跳过」 | 中（覆盖面最广，判别力最浅） |
| 3 | **Build**（3 平台矩阵） | `cargo build --workspace --release` + `cargo build --workspace` | 只证明编译过。**协议逻辑写错一半也编译过** | 弱 |
| 4 | **Test** | `cargo test --workspace` + `cargo test --workspace --release` | 抓「单测红」，但**抓不到「没写测试的那一半」**——这是本轮的核心：7938 个测试里，协议层的 56 个错误变体、全部鉴权失败路径都无人写测试 | **中（本仓最高的行为覆盖门）** |
| 5 | **Test (windows, xray-proxy-tun)** | `cargo test -p xray-proxy-tun --all-targets` | 只一个 crate 的 Windows 面 | 弱（窄） |
| 6 | **Parser Parity (Go v26.9.9 vs Rust)** | 57 例（HTTP 38 + SOCKS 19），同一原始字节打 Go 与 Rust，比对**接受/拒绝 + 响应字节 + 连接关闭方式** | **覆盖 2 个协议（HTTP/SOCKS）的解析器**。**13 个其余协议入站（vless/vmess/trojan/ss/anytls/tuic/hysteria/dokodemo/dns/…）的握手解析器零差分覆盖**。且 Go 基线是 **v26.9.9**，而本仓的**裁定基准是 v26.10.17**（CLAUDE.md §0）——差分门在比一个**已被裁定作废的 Go 版本** | **强（唯一真差分门），但覆盖面窄 + 基线版本过时** |
| 7 | **Security & License** | `cargo-deny` + `osv-scanner`（**`continue-on-error: true`** = 告警级不阻断） | 供应链 CVE。`osv-scanner` 当前是基线告警，**任何新 CVE 不阻断合入** | 弱（当前配置下） |
| 8 | **Docs** | `cargo doc --workspace --no-deps` + `RUSTDOCFLAGS=-D warnings` | 文档编译。零行为覆盖 | 弱 |
| 9 | **Fuzz Smoke** | `cargo fuzz build` + 3 靶（`kcp_segment`/`ss2022_packet`/`vless_inbound`）各 30s | **只跑 `workflow_dispatch`（手动触发）**——PR/push **完全不跑**。且只 3 靶、30s。**这是本仓唯一能抓「畸形字节打崩」的门，却是手动门** | 弱（配置上等于不存在） |
| 10 | **Proto Drift** | `tools/check_proto_drift.py --manifest` | proto 镜像漂移。零行为覆盖 | 弱（但防一类真问题） |
| 11 | **Asset Gate** | `tools/check_geo_assets.py` | geo 资产缺失。零行为覆盖 | 弱 |
| （+） | **Interop**（`interop.yml`，独立 workflow） | `python3 dist/interop_ci.py --rust ... --go ...`，12 协议 × 3 方向 = 54 测 | **最强的一道行为门**（真二进制、真握手、真字节）。**但**：① 只在 `push` 到 `master/main/dev/feature/**` 触发，**`pull_request` 不触发** → **PR 上完全没有互通门**；② 协议覆盖 12（vmess/vless-vision-tls/trojan-tls/vless-ws/ss/ss2022/splithttp/grpc/reality/hysteria2/anytls/tuic + naive），**缺 socks/http/dokodemo/dns/blackhole/loopback/wireguard/tun/mux/kcp/quic/httpupgrade**；③ Go 基线同样是 **v26.9.9** | **强（覆盖面最广的真行为门），但 PR 不跑 + 协议覆盖不全 + 基线过时** |

### 4.2 关键量化

| 指标 | 值 | 含义 |
|---|---|---|
| CI 门总数 | 11（ci.yml 10 + interop.yml 1） | — |
| 其中对**协议线协议语义**有真行为覆盖的 | **1**（Parser Parity，限 HTTP/SOCKS） | 其余 10 门全是编译/排版/静态/资产/proto |
| 其中跑**真二进制互通**的 | **1**（Interop），**且 PR 不触发** | 「写了一半」在 PR 阶段完全无阻 |
| `dist/interop_*.py` 共 11 个脚本，**进 CI 的只有 1 个** | 10 个脚本（`interop_kcp`/`interop_grpc`/`interop_httpupgrade`/`interop_splithttp`/`interop_matrix`/`interop_reality`/`interop_hysteria`/`interop_enc`/`interop_ext`/`interop_gogo`）**未被任何 CI 门调用** | 已写好的互通验证躺在仓库里不跑 |
| `dist/run_full32.py`（32 节点真机矩阵） | **未被任何 CI 门调用** | 32/32 只在本地/夜间跑 |
| Go 基线版本 | CI 两门都用 **v26.9.9**；裁定基准是 **v26.10.17** | 差分门在比作废版本 |
| `#[ignore]` 测试 | 17（0.21%） | 数量健康，但含 5 个 vps_interop（真实 VPS 互通）与 2 个 Go 互通 |
| 会被 `cargo test --workspace` 跑到吗 | **否**（`#[ignore]` 默认跳过） | 6 个真互通测试永远不跑 |

### 4.3 「最该加的 3 门」建议

按「能挡住多少真缺陷 / 成本」排序：

#### 建议 1 —— **把 Interop 门挂上 `pull_request`**（成本最低、收益最高）

- **理由**：这是本仓**唯一**跑真二进制真握手的门，但它只在 push 到特定分支时跑。**PR 阶段 = 零互通覆盖**——这正是「写了一半能一路绿灯」的 CI 侧根因。改动量 = `interop.yml` 的 `on:` 加两行 `pull_request: branches: [main, master, 'feature/**']`，零新增脚本、零新增基建。
- **成本**：复用现有 job（`pull_request` 触发不涉及 secret），CI 时长不变（同一 job）。唯一顾虑是 fork PR 不该跑（避免用仓库 secret），但本仓是私有仓，无此问题。
- **附带的最小增量**（可选，同 job 内加一步）：把 `dist/interop_matrix.py` / `interop_kcp.py` / `interop_httpupgrade.py` 三个**已存在但未接 CI** 的脚本挂进同一 job——它们覆盖 kcp/httpupgrade/splithttp 家族，脚本已写好，接线成本 ≈ 0。

#### 建议 2 —— **Parser Parity 门扩到「协议握手解析器」，并把 Go 基线提到 v26.10.17**

- **理由**：Parser Parity 是**唯一**能做「Go↔Rust 逐字节差分」的门，且它的判据设计（接受/拒绝 + 响应字节 + 关闭方式）质量很高——但它只覆盖 HTTP/SOCKS 两个协议的**入站解析器**。协议层 13 个入站（vless/vmess/trojan/ss2022/anytls/tuic/hysteria/dokodemo/dns…）的**握手帧解析**——也就是「写了一半」最容易出错的那些字节级边界——**零差分覆盖**。同时它和 Interop 门都比 **v26.9.9**，而本仓裁定基准已是 **v26.10.17**（CLAUDE.md §0 明文），意味着**这两道差分门在用一个已被作废的 Go 版本做基准**——v26.10.x 的上游修复它们一条都测不到。
- **成本**：`parity.py` 已有 `build_cases()` 表驱动结构（57 例 = HTTP 38 + SOCKS 19），加协议 = 加一组 `add(...)` 用例。Go 基线升级 = 换下载 URL + 换 sha256（CI 里已是 sha256-pinned 写法）。**不需要新造基建**。
- **注意**：升级 Go 基线到 26.10.17 会让现有 57 例产生**预期差异**（26.10.x 有上游修复），需一次性跑出差异台账并逐条登记放行——否则这道门会立刻变红。这是一次性成本。

#### 建议 3 —— **一条「协议握手失败路径」的表驱动单测门（新增，形态最轻）**

- **理由**：本轮最刺眼的数字是 **56 个生产错误变体从未被任何测试触及**，其中包括 ss2022 的 PSK/盐/时间戳三道重放防护、vmess 的 auth id 校验、socks 的服务端密码校验、trojan 的用户校验——**全是凭据面**。这些不需要 e2e、不需要 fuzz、不需要 Go 对照：它们是**纯函数级的错误映射**，一张表驱动的单测就能覆盖（输入畸形字节 → 期望错误变体）。形态与 `parity.py` 的 `add()` 表同构，只是纯 Rust、无外部依赖，成本极低。
- **成本**：16 个 crate × 每个 crate 3-8 个变体 ≈ 60-80 条单测。全部是 `assert!(matches!(err, XxxError::Variant))` 形态，无 fixture、无网络、无 sleep。可按 crate 拆给多个子代理并行（同 crate 单人独占）。
- **门位**：新增 job 或并入现有 Test job；**关键是把「每个生产错误变体必须至少被一条测试提及」变成可机器检查的门**——例如加一个 meta-test：遍历各 crate 的错误枚举，断言每个变体名在测试源码中至少出现一次（**这正是本轮 §1.3 用的那套扫描，可以直接做成 CI 门**）。这条 meta 门成本极低，却能防止缺口再次扩大。

> 附带的第四个（成本最低，可与上面任一合并）：**Fuzz Smoke 从 `workflow_dispatch` 改为 PR/push 触发**（或至少对 3 靶跑 30s）。本仓已有 fuzz 工作区与 3 个靶，只差触发条件——而畸形字节打崩正是本轮 §2.1 想覆盖的那类缺陷的天然发现手段。

---

## 5 与前两轮 30 条的关系

本轮**未重报**任何前两轮已登记的缺陷（`vaye2`/`o91s4`/`5w5z0`/`u4efe`/`bz800`/`vdl95`/… 30 条）。本轮报告的是**这些缺陷能一路绿灯的机制**：

| 前两轮的缺陷 | 本轮定位的「绿灯成因」 |
|---|---|
| `bz800` anytls 无口令 = 零认证 | **F11**：测试 `handler_without_password_allows_connection` 把 fail-open 写成了期望 |
| `o91s4` 出站 warn+skip → 默认出站前移 | **F12**：`register_vless_invalid_uuid_skipped` 把「被跳过」写成了期望 |
| `vaye2` 路由解析失败静默降级 | **F15**：`pattern_router_skips_rule_without_outbound_tag` 把「整条规则被丢」写成了期望 |
| `vdl95` sniffing 排除表整表失效 | **F14**：测试注释自陈「Go 为 Build 期硬错；本仓降级为可见告警」 |
| `u4efe` ss 空口令 open proxy | **§2.1**：`SsError::InvalidPassword` 零测试覆盖（无认证失败测试面） |

---

## 6 未覆盖面（本轮没做）

- 未跑测试套件（本轮为只读静态审计，未执行 `cargo test`；所有结论基于源码扫描 + 人工手验 ≥ 15 个可疑测试）
- 未做运行时变异测试（把生产代码改坏看测试是否红）——非目标要求「不改任何代码」
- 未做覆盖率百分比统计（无工具支持，按任务要求不编造数字）
- 未审 `crates/udf-frame/`（外部仓工作副本，且 `crates/xray-frame/tests/l4_fixtures.rs` 对其有覆盖）
- 未审 `fuzz/` 目录内的靶覆盖面质量（只统计了 CI 触发条件与靶数）
- 未审 `mobile.yml` / `release.yml` / `stress.yml` / `musl-probe.yml` 四条 workflow 的门强度（不在「ci.yml 10 门」范围）
- 未审 32 节点真机矩阵 `dist/run_full32.py` 的用例质量（只确认它未被 CI 调用）
- 未验证「框架路 `framework-assembly` 的 e2e 是否存在于默认构建」——§2.3 中该条标注为「需核实」

---

## 7 附：方法与可复算性

| 手段 | 用法 | 次数/规模 |
|---|---|---|
| Python 脚本（`bash` 内 heredoc） | 7941 个测试属性的属性块扫描、零断言判定、函数体花括号配平、错误变体提取、夹具体插件类型检索、夹具体归一化哈希（跨 crate 重复检测） | 11 次扫描，全仓 960 个 `.rs` |
| `grep`（工具） | `next_conn_id` 全仓、`LogFacade::new` 站点、warn+skip 分支、`assert_plugin_contract` 16 crate 分布 | 6 次 |
| `read` | 手验可疑测试 ≥ 15 个：anytls 无口令、http e2e 拒绝助手、ss/trojan/vmess 契约测试、contract_assert.rs 全文、6 个零断言测试体、3 个 warn+skip 测试体、blackhole 契约测试全文、l4_fixtures.rs | 18 处 |
| 未用 | serena-cli（本轮为跨文件模式统计，正则脚本优于符号检索）；codebase-memory-mcp 图谱（同上，且本轮需全文扫而非按名寻址） | — |

**手验样本（≥15，逐条结论）**：
1. `xray-proxy-anytls/src/inbound.rs:340` → F11（S1）
2. `xray-proxy-http/tests/http_proxy_e2e.rs:606/620/633/646` → 误报，实为 `assert_rejected_without_response` 助手内断言 → **真覆盖到位**
3. `xray-proxy-vless/src/inbound/server.rs:2071-2089` → 误报，实为 `assert_flow_rejected` 助手 → **真覆盖到位**
4. `xray-proxy-tuic/src/protocol/address.rs:174/179/184` → 误报，实为 `roundtrip()` 助手内 4 条断言 → **真覆盖到位**
5. `xray-proxy-ss/src/protocol.rs:554-564` → 同上 → **真覆盖到位**
6. `xray-proxy-tuic/src/protocol/command.rs:157-174` → 同上 → **真覆盖到位**
7. `xray-transport-quic/src/config.rs:343/349` → **F6/F7 成立**（零断言）
8. `xray-core/src/version.rs:78` → 误报（编译期常量，`let _ = BUILD;` 是有意的 lint 规避，注释自陈）→ 不报
9. `xray-core/src/instance.rs:416` → **F9 成立**
10. `xray-app-dns/src/error.rs:130` → 误报（`match`+`panic!` 形式）→ **F10 记录口径**
11. `xray-frame/tests/l4_fixtures.rs:158` → 误报（`#[should_panic(expected=...)]` 属性承担断言）→ 不报
12. `xray-proxy-vless/src/encryption/mod.rs:2187` → **F8 成立**
13. `xray-core/src/outbound.rs:3647` → **F12 成立**
14. `xray-core/src/functions.rs:1085/1116` → **F13 成立**（Go 语义待核，测试方向本身有据）
15. `xray-core/src/router.rs:453` → **F15 成立**
16. `xray-core/src/wiring.rs:2425` → **F14 成立**（注释自陈降级）
17. `xray-app-proxyman/src/command/mod.rs:895` → **F16 成立**
18. `xray-proxy-blackhole/tests/plugin_contract.rs` 全文 → **无 stop 注册断言**（15/16 有）+ 全部 `l4_*` 验框架不验插件
19. `crates/xray-frame/src/contract_assert.rs:146-190` → **F4 成立**（deps 丢弃 / build 未调 / lifecycle 全 Ok(())）
20. `crates/xray-core/src/arm_registry.rs:187` → **§2.2 deps 门空跑**成立

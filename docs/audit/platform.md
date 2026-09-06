# 全平台对称完整性审计（Linux / Windows / macOS / FreeBSD，对照 Go Xray-core v26.7.28 基准）

- 审计代理：WinAudit（第二轮补漏，只读代码，唯一写动作 = 本文件）
- 范围（按 Main 纠正）：**全平台对称**——Linux 与 Windows 均在生产使用，另有 freebsd/darwin/linux-gnu 交叉编译目标。双向核查：① Linux 专属点（libc/linux syscall）在 Windows/macOS/FreeBSD 的缺口；② `cfg(unix)` 假设点在 Windows 的缺口。③ 重点识别「功能因平台静默缺失/静默降级」同族模式。④ 平台 API（dup / epoll·kqueue·IOCP / 信号 / 路径）各自完整性。
- 方法：全仓扫描 `cfg(unix)` / `cfg(target_os=…)` / `cfg(windows)` / `cfg(not(unix))` / `libc::` / `nix::` 全部命中点，逐点核对四个平台侧行为；Go 基准逐文件对照。第一轮已报位置不重复。

## 0. 扫描概览

- **cfg 特化点分布**：`cfg(unix)` 14 个 crate 区域（UDS/flock/SIGTERM/abstract）；`cfg(target_os)` 集中于 transport sockopt 四平台模块、udp-hub TPROXY、MPTCP、buf splice、router find_process（四平台各一）、dokodemo fakeudp、xicmp。
- **IO 多路复用完整性**：全库异步 IO 走 tokio/mio（Linux=epoll、macOS/FreeBSD=kqueue、Windows=IOCP），**无任何裸 epoll/kqueue syscall**；直接 syscall 全部在门控内（splice 仅 Linux、cmsg 仅 Linux、flock 仅 unix）。四平台 IO 层无不对称缺口。
- **dup 双向**：`dup_tcp_stream`（xray-transport/src/connection.rs:69-96）unix=`libc::dup`、Windows=`ManuallyDrop` 视图 + `try_clone`(DuplicateHandle)、其余目标=`None`。vision splice 链路（`raw_tcp_clone` 穿透链）Linux/Windows 均可用——第一轮清单所提「Windows 返回 None 同族」现状已闭合，本表登记为 ✅。
- **setrlimit 类资源控制**：Go 基准全仓 `Rlimit|setrlimit` **零命中**，Rust 亦无 —— 四平台均无此控制，无「缺失后行为」差异；fd 上限依赖进程外部环境（与 Go 一致）。**无缺口**。
- **反向对称（Windows 独有功能在 Linux 缺失？）**：全部 `cfg(windows)` 分支均为对应 unix 分支的功能子集（sockopt Windows 模块仅 TFO/UNICAST_IF，对照 Go sockopt_windows.go 同形），不存在 Windows-only 功能在 Linux 静默缺失。
- **交叉编译目标**：freebsd/darwin 走 `cfg(unix)` 门控覆盖；`target_env = "uclibc"` 缺失常量已有处理分支（udp/hub.rs:465-475）；无 glibc 假设外溢到 unix 通用门控。

## 1. 平台特化点对称清单（位置 / 功能 / Linux / Windows / macOS·FreeBSD / 影响）

| # | 位置 | 功能 | Linux | Windows | macOS·FreeBSD | 影响 |
|---|---|---|---|---|---|---|
| 1 | xray-transport/src/connection.rs:69-96 | `dup_tcp_stream`（裸 socket 克隆） | `libc::dup` ✅ | DuplicateHandle(try_clone) ✅ | unix 门控=`libc::dup` ✅ | 无 |
| 2 | connection.rs:162-184 | `close_read/close_write` 半关闭 | `libc::shutdown` ✅ | **恒 `Ok(())` 静默 no-op** | unix 门控=`libc::shutdown` ✅ | ⚠️ F4（当前无生产调用方，潜伏） |
| 3 | sockopt/mod.rs:389-536 + 各平台模块 | 出/入站 sockopt 分发 | 全集（TFO_CONNECT/tproxy/congestion/SO_MARK/BINDTODEVICE/WINDOW_CLAMP/USER_TIMEOUT/MAXSEG） | 仅 TFO=15 + bind_if_index；mark/tproxy/congestion 等不设 | darwin：TFO 位/SO_REUSEPORT/IP_BOUND_IF；freebsd：TFO clamp/SO_USER_COOKIE(mark)/REUSEPORT_LB→回退 | ✅ 逐平台对照 Go（Go 各平台文件同形：mark 仅 linux+freebsd 有，darwin/windows 无） |
| 4 | sockopt/mod.rs:444-453、513-534 | 出/入站分支 v4/v6 判定 | 不需要（per-fd） | `is_ipv4: true` **硬编码** | darwin `is_ipv6: false` **硬编码** | ⚠️ F8（潜伏，随 F1 接通激活） |
| 5 | sockopt/mod.rs:570-620 | CustomSockopt | int+str ✅ | int ✅ / `str` 显式报错（对齐 Go :113） | int+str ✅；**freebsd 无 custom 循环**（`cfg(not(freebsd))`，对齐 Go sockopt_freebsd.go 无此循环） | ✅ |
| 6 | system_listener.rs:110-191 | 监听前 TFO backlog / REUSEPORT | TCP_FASTOPEN backlog+SO_REUSEPORT ✅ | TFO=15 生效；reuse_port no-op（Go windows 同） | darwin REUSEPORT+TFO；freebsd REUSEPORT_LB→REUSEPORT+TFO ✅ | 无 |
| 7 | system_listener.rs:199-236 | MPTCP 监听 | `TCP_MPTCP` 真实绑定，失败回退普通 TCP | 普通 bind | 普通 bind | ✅ 对齐 Go（SetMultipathTCP 仅 Linux 生效） |
| 8 | udp/hub.rs:219-317 | UDP TPROXY recv_orig_dest | tproxy 绑定+cmsg 解析 ✅ | 普通 bind（Go 同 Linux-only） | 普通 bind（同） | ✅ 非 Linux 无透明代理场景，语义一致 |
| 9 | xray-proxy-dokodemo/src/fakeudp.rs:14-27 | fake UDP（IP_TRANSPARENT+SO_MARK） | 真实实现 | **显式 `Err("fakeudp: !linux")`** | 显式 `Err`（同分支） | ✅ 对齐 Go fakeudp_other.go，显式非静默 |
| 10 | xray-core/src/inbound.rs:649-659 | dokodemo followRedirect 取原始目的 | getsockopt SO_ORIGINAL_DST ✅ | **恒 `None`，无告警**（启动日志仍打印 follow_redirect=true） | 恒 `None`，无告警（同 cfg 分支） | ❌ F7（三平台静默） |
| 11 | inbound.rs:2181-2200 | HAProxy fallback dest abstract 填充 | `@@`→NUL+padding | 原样返回（测试 4229-4231 钉死） | 原样返回（abstract 分支仅 linux/android） | ✅ |
| 12 | xray-transport/src/system_listener.rs:404-707 | UDS 监听（FileLocker+权限+abstract） | ✅（flock，darwin/freebsd 同 unix 门控） | **类型不存在**（tokio UDS 无 Windows 实现） | ✅ | Windows 上 UDS 监听不可用——见 F5（commander） |
| 13 | xray-transport/src/filelocker.rs:53-61 | UDS 防多实例锁 | flock ✅ | no-op（对齐 Go filelocker_windows.go；且 Windows UDS 不可达，无实际路径） | flock ✅ | ✅ |
| 14 | xray-app-commander/src/commander.rs:476-506 | API gRPC UDS listen | ✅ | **显式 `InvalidListenAddr` 报错**（Go AF_UNIX 在 Win10 1803+ 可用） | ✅ | ⚠️ F5 |
| 15 | xray-cli/src/run.rs:59-61、138-165 | `--unix` 标志；信号 | `--unix` **声明但零消费（静默 no-op）**；SIGTERM+Ctrl-C ✅ | 字段编译期不存在（clap 拒绝，正确）；Ctrl-C（Go SIGTERM 同样不投递）✅ | `--unix` 同样零消费（unix 门控覆盖 darwin/freebsd）；SIGTERM ✅ | ❌ F2（unix 全系）；信号 ✅ |
| 16 | xray-transport-splithttp/src/transport.rs:42-79、94-153 | XHTTP UDS 监听（Go hub.go:472-480） | 生产入口只分 h3/TCP，**unix 分支死代码无调用方** | 不支持（Go windows 也需 Win10+，Rust 无路径） | 同 Linux（死代码） | ❌ F3（unix 全系） |
| 17 | xray-buf/src/splice.rs | 内核 splice 加速 | nix splice ✅ | tokio `copy_bidirectional` 回退 | 同回退 | ✅ 仅性能降级，语义不变 |
| 18 | xray-buf/src/readv.rs:178-200 | readv scatter-gather | **顺序读取回退**（doc 声称 nix readv 失实） | 顺序回退（doc 声称 WSARecv 失实） | 顺序回退 | ⚠️ F6（三平台均无快路径，功能无损） |
| 19 | xray-app-router/src/condition.rs:438-1024 | 按进程名路由 | `/proc` 解析 ✅ | iphelper+sysinfo ✅ | macOS=lsof shell-out、freebsd=libprocstat ✅（**超集**：Go find_process_others.go 在这两平台明确「不支持」） | ✅ |
| 20 | system_dialer.rs:708-738 | 非阻塞 connect EINPROGRESS | 115 ✅ | WSAEWOULDBLOCK(10035) ✅ | 36（darwin/freebsd 各自分支）✅ | 无 |
| 21 | xray-common/src/platform/mod.rs:81-96 | asset 资源目录 | 多目录探测（对齐 Go others.go） | 直接 `env_dir.join(file)`（对齐 Go windows.go:13） | unix 分支=多目录探测 ✅ | ✅ |
| 22 | platform/filesystem.rs:79-137 | asset 路径校验 | 拒绝绝对/`..`/`//` | 额外拒绝盘符/UNC/NUL（对齐 isWindowsNulName） | unix 分支同 Linux | ✅（Windows 特化校验完备） |
| 23 | finalmask/xicmp.rs:528-559 | xicmp raw ICMP | 占位（第一轮已报 linux_impl 占位本身） | **显式 `Unsupported`** | 显式 `Unsupported`（同分支） | 显式失败，非静默 |
| 24 | dialer.rs:163-172 | sockopt JSON 解析 `interface` | **无 JSON 入口，静默丢弃** | 同（绑网卡是 Windows 多网卡场景刚需，损失最大） | 同（darwin IP_BOUND_IF 同样接不上） | ❌ F1（全平台） |
| 25 | xray-app-router/src/webhook.rs:225-237 | unix socket webhook | ✅ | 显式 Err | ✅ | ✅ Rust 扩展功能，显式失败 |

**「静默缺失/静默降级」同族模式全列表**（用户点名重点）：F1（sockopt.interface 全平台静默丢弃）、F2（`--unix` unix 全系静默 no-op）、F3（splithttp UDS 监听 unix 全系生产不可达）、F4（半关闭 Windows 静默 no-op，潜伏）、F6（readv 三平台实为顺序回退但文档宣称平台快路径）、F7（followRedirect 非 Linux 静默 None）。splice 性能回退（#17）与 fakeudp/xicmp（#9/#23）为显式失败或纯性能语义不变，不入缺陷列。

## 2. 发现

**[P2] F1 `sockopt.interface`（出站绑定网卡名）配置被静默丢弃，全平台失效（Windows 多网卡场景损失最大）** | crates/xray-transport/src/dialer.rs:163-172
证据：支持字段清单（`mark`/`tcpFastOpen`/…/`customSockopt`）无 `interface`；注释自认「Go `interface`（接口名字符串）JSON 暂不解析（`SocketOptions::bind_if_index` 字段已备，尚无 JSON 入口）」。`socket_options()` 逐字段解析无 `"interface"` 分支 → `bind_if_index` 恒 0。Go 侧 sockopt_windows.go:35-66 / sockopt_linux.go / sockopt_darwin.go 均消费 `config.Interface`（`net.InterfaceByName` 解析失败还会报错）。
影响：四平台用户从 Go 迁移含 `"sockopt": {"interface": "..."}` 的配置均被忽略且无 warning，流量走默认路由；Windows（多出口网卡选择）与 macOS/FreeBSD（IP_BOUND_IF 策略路由）场景直接受影响。
修复建议：`socket_options()` 增加 `"interface"` 分支，接口名→index（Windows `if_nametoindex` 对应 API；darwin/freebsd `if_nametoindex`；linux SO_BINDTODEVICE 也可直接用接口名）；解析失败按 Go 语义报错而非忽略。

**[P2] F2 CLI `--unix` 标志声明后零消费，unix 全系（linux/darwin/freebsd）静默 no-op** | crates/xray-cli/src/run.rs:59-61
证据：`#[cfg(unix)] #[arg(long = "unix", value_name = "PATH")] pub unix_socket: Option<String>`，文档声称「启用 splithttp unix domain socket 监听（Go hub.go:472-480）」。全仓 grep `unix_socket` 仅字段声明 + 单测（run.rs:518-525），`execute()` 不读取。Go 基准 main/ 无此标志（属 Rust 扩展，扩展做了一半）。
影响：三个 unix 目标上传 `--unix /tmp/xh.sock` 后进程正常启动、无任何提示，XHTTP 并未监听 UDS；Windows 上字段不存在、clap 报未知参数（行为反而正确）。
修复建议：接上消费链（传入 splithttp listen 分发，见 F3）或删除该 flag。

**[P2] F3 splithttp unix 监听无生产入口，`listen_splithttp_unix` 是死代码（linux/darwin/freebsd 同缺）** | crates/xray-transport-splithttp/src/transport.rs:42-79
证据：生产入口 `listen_splithttp`（register.rs:24 导入的唯一起点）只二分 `is_h3 → listen_h3` / `listen_tcp`；`#[cfg(unix)] listen_splithttp_unix`（transport.rs:94-153）全仓唯一调用方是同文件 810 行测试。Go hub.go:472-480 `port == 0` 走 `ListenUnix`。
影响：Go 可用 `port: 0` + unix path 监听 UDS 的 XHTTP 服务端形态在 Rust 全部 unix 目标不可达（配置地址不会以 unix 形式到达 `SocketAddr` 参数）。
修复建议：`listen_splithttp` 增加 unix 地址分发（commander.rs:476-494 同模式，非 unix 显式报错），或删死代码并声明不支持。

**[P3] F4 `TcpConnection::close_read/close_write` Windows 恒 no-op，半关闭语义平台分叉（潜伏）** | crates/xray-transport/src/connection.rs:162-184
证据：方法体内 `#[cfg(unix)] { libc::shutdown(fd, SHUT_RD/SHUT_WR) }`，cfg 外直接 `Ok(())`，Windows 空实现无错误无日志。
影响：当前 `dyn Connection` 半关闭生产调用方仅 headers/conn.rs:237-242 转发（无上游），潜伏；半关闭链路接通后 Windows 对端读不到 EOF，静默语义丢失难排查。
修复建议：Windows 用 `TcpStream::shutdown(Shutdown::Read/Write)`（Winsock SD_RECEIVE/SD_SEND 支持）；至少返回 `Err(Unsupported)` 或 debug 日志。

**[P3] F5 commander UDS listen Windows 显式不可用，Go AF_UNIX（Win10 1803+）可用** | crates/xray-app-commander/src/commander.rs:502-506
证据：`#[cfg(not(unix))] … Err(…"unix socket listen requires unix platform (tokio UDS unavailable on Windows)")`。Go commander.go:81-91 `net.Listen("unix", path)` 在 Win10 1803+ 受支持。
影响：显式失败非静默，危害有限；Windows 上比 Go 少一种本机 API 接入方式。根因是 tokio UDS 无 Windows 实现（std::os::windows::net 有）。
修复建议：错误文案写明 TCP 替代；或基于 std Windows UDS + tokio 适配补齐。

**[P3] F6 readv 平台文档失实 + `windows-sys` 死依赖 + mark 字段注释与 freebsd 实现矛盾** | crates/xray-buf/src/readv.rs:4、178-200；crates/xray-buf/Cargo.toml:18-19；sockopt/mod.rs:225-227
证据：readv.rs:4 声称「Unix 使用 nix readv，Windows 使用 WSARecv」，三个 cfg 分支实际全部 `readv_sequential`；Cargo.toml `windows-sys`（WinSock feature）在 src 零引用；SocketOptions::mark 注释「仅 Linux 有效，其他平台忽略」但 freebsd.rs:78-80 实际以 SO_USER_COOKIE 应用 mark（且这正是 Go freebsd 对齐行为）。
影响：无功能损失，但三处文档/依赖失实误导后续维护与审计（以为有平台快路径/以为 freebsd 无 mark）。
修复建议：删 windows-sys 依赖或实装 WSARecv；doc 改为「三平台均顺序回退」；mark 注释改为「Linux SO_MARK、FreeBSD SO_USER_COOKIE，其余平台忽略」。

**[P3] F7 dokodemo `followRedirect` 非 Linux（Windows/macOS/FreeBSD）静默降级为 None，无告警** | crates/xray-core/src/inbound.rs:649-659
证据：`#[cfg(not(target_os = "linux"))] let original_dst: Option<SocketAddr> = None;`，而启动日志（inbound.rs:637-642）仍打印 `follow_redirect=true`。
影响：三个平台配置被接受、日志宣称启用，运行期恒按 None 回落预定义 dest/local_port，静默且难察觉。Go getOriginalDst 亦 Linux-only，但 Go 对应 tproxy 配置在非 Linux 本就走不通；Rust 这里是「配置可用性假象」。
修复建议：非 Linux 且 `follow_redirect=true` 时启动 warn 或配置校验拒绝。

**[P3] F8 出站分支 v4/v6 判定硬编码（Windows `is_ipv4:true`、darwin `is_ipv6:false`），偏离 Go 按目标地址判定（潜伏，随 F1 激活）** | crates/xray-transport/src/sockopt/mod.rs:444-453、513-520
证据：Windows 分支 `is_ipv4: true`、darwin 出/入站分支 `is_ipv6: false` 均为常量；windows.rs:81-83 注释自述「Go :41 按地址字符串含 \".\" 判定，Rust 由调用方给定」——调用方给的是常量。
影响：当前因 F1（interface 无 JSON 入口）不可达；F1 接通后 IPv6 目标会设错选项族（Windows 误设 IP_UNICAST_IF、darwin 误设 IP_BOUND_IF），接口绑定失效。
修复建议：F1 实施时同步——apply 点传入目标地址做 v4/v6 判定（Go :40-42 同款），出/入站调用点都要改。

## 3. 平台 API 完整性核销（双向）

1. **dup**：unix(libc::dup，含 darwin/freebsd)/Windows(DuplicateHandle)/其余 None —— 双向已闭合，无缺口。
2. **epoll/kqueue/IOCP**：全部经 tokio/mio，无裸多路复用 syscall；直接 syscall（splice/cmsg/tproxy）全部 Linux 门控且非 Linux 有回退或显式错误。**无缺口**。
3. **信号**：SIGTERM 分支 `cfg(unix)` 覆盖 linux/darwin/freebsd；Windows Ctrl-C = Go os.Interrupt 等价（Go 的 SIGTERM 在 Windows 不投递）。无 no-op 信号 crate。**无缺口**。
4. **路径处理**：全程 PathBuf/OsString，生产无 `to_str().unwrap()` 硬断言（仅测试）；filesystem.rs Windows 特化校验（盘符/UNC/NUL）完备、unix 分支对齐 Go；中文路径经 std UTF-16 层透明；confdir/配置解析纯 PathBuf。**无发现**。
5. **socket 选项对称性**：四平台模块与 Go 各平台文件逐项对照（§1 表 3-9）；TCP_NODELAY socket2 跨平台（mod.rs:390-391）；SO_REUSEADDR 四平台均不设（Windows EXCLUSIVEADDRUSE 语义=Go no-op）；REUSEPORT Linux/Darwin/FreeBSD 实现、Windows no-op=Go。缺口仅 F1/F8（interface 链路）。
6. **资源控制（setrlimit 类）**：Go/Rust 均无，四平台一致。**无缺口**。

## 4. 严重度统计与 TOP3

| 严重度 | 数量 | 编号 |
|---|---|---|
| P0 | 0 | — |
| P1 | 0 | — |
| P2 | 3 | F1（sockopt.interface 全平台静默丢弃）、F2（--unix 死标志）、F3（splithttp UDS 监听断线） |
| P3 | 5 | F4-F8 |

**TOP3**：① F1 —— 唯一影响**全部四个平台**的静默丢弃点，Windows 多网卡绑定是生产刚需，Go 迁移配置兼容性直接受损；② F3 —— Go 明确支持（hub.go:472-480）的 UDS 监听在全部 unix 目标生产不可达，且配套死代码+`--unix` 假 CLI 面（F2）三处互相印证同一断线；③ F7 —— 「配置被接受+日志宣称启用+运行期静默失效」三重假象，非 Linux 三平台均中。

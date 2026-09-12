# Xray-core Rust 完整重写开发计划

> 基于 Go 源码 1:1 映射 + 依赖库调研（9006 节点 · 15210 边 · 715 社区知识图谱）
> 生成日期：2026-06-04

---

## 设计原则

1. **源码 1:1 映射**：每个 Go package 对应一个 Rust crate 或子模块，保持代码组织完全一致
2. **依赖驱动**：严格按依赖方向自底向上开发，每层可独立编译测试
3. **生态优先**：直接依赖成熟 crate（A级）> 参考重构（B级）> 自研（C级），预计节省 75% 代码量
4. **入站对等**：所有协议必须同时实现入站（服务端）和出站（客户端），这是 Xray-core 与 clash-rs 的核心区别
5. **零 fork 依赖**：避免 patched 依赖，长期维护成本不可接受

---

## Go → Rust 模块完整映射

### 源码目录对照表

```
Go (github.com/xtls/xray-core)     Rust (xray-core-rust/crates/)
─────────────────────────────────────────────────────────────────
common/buf/                         xray-buf/
common/net/                         xray-common/src/net/
common/protocol/                    xray-common/src/protocol/
common/serial/                      xray-common/src/serial/
common/session/                     xray-common/src/session/
common/crypto/                      xray-crypto/
common/geodata/                     xray-geodata/
common/mux/                         xray-mux/
common/xudp/                        xray-xudp/
common/log/                         xray-common/src/log/
common/errors/                      xray-common/src/errors/
common/signal/                      xray-common/src/signal/
common/task/                        xray-common/src/task/
common/platform/                    xray-common/src/platform/
common/uuid/                        xray-common/src/uuid/
common/dice/                        xray-common/src/dice/
common/units/                       xray-common/src/units/
common/retry/                       xray-common/src/retry/
common/reflect/                     xray-common/src/reflect/
common/ctx/                         xray-common/src/ctx/
common/cache/                       xray-common/src/cache/
common/bitmask/                     xray-common/src/bitmask/
common/ocsp/                        xray-common/src/ocsp/
common/peer/                        xray-common/src/peer/
common/draine/                      xray-common/src/drain/
common/antireplay/                  xray-common/src/antireplay/
common/singbridge/                  xray-common/src/singbridge/
common/cmdarg/                      xray-common/src/cmdarg/
bytespool/                          xray-common/src/bytespool/
features/                           xray-features/
app/dns/                            xray-app-dns/
app/router/                         xray-app-router/
app/dispatcher/                     xray-app-dispatcher/
app/proxyman/inbound/               xray-app-proxyman/src/inbound/
app/proxyman/outbound/              xray-app-proxyman/src/outbound/
app/stats/                          xray-app-stats/
app/log/                            xray-app-log/
app/commander/                      xray-app-commander/
app/observatory/                    xray-app-observatory/
app/policy/                         xray-app-policy/
app/reverse/                        xray-app-reverse/
app/metrics/                        xray-app-metrics/
app/geodata/                        xray-app-geodata/
app/version/                        xray-app-version/
transport/internet/                  xray-transport/
transport/internet/tls/             xray-tls/
transport/internet/kcp/             xray-transport-kcp/
transport/internet/hysteria/        xray-transport-hysteria/
transport/internet/splithttp/       xray-transport-splithttp/
transport/internet/grpc/            xray-transport-grpc/
transport/internet/websocket/       xray-transport-websocket/
transport/internet/httpupgrade/     xray-transport-httpupgrade/
transport/internet/tcp/             xray-transport/src/tcp/
transport/internet/udp/             xray-transport/src/udp/
transport/internet/headers/         xray-transport/src/headers/
transport/internet/reality/         xray-reality/
transport/internet/finalmask/       xray-transport/src/finalmask/
transport/pipe/                     xray-transport/src/pipe/
proxy/vless/                        xray-proxy-vless/
proxy/vmess/                        xray-proxy-vmess/
proxy/shadowsocks/                  xray-proxy-ss/
proxy/shadowsocks_2022/             xray-proxy-ss-2022/
proxy/trojan/                       xray-proxy-trojan/
proxy/socks/                        xray-proxy-socks/
proxy/http/                         xray-proxy-http/
proxy/dns/                          xray-proxy-dns/
proxy/blackhole/                    xray-proxy-blackhole/
proxy/freedom/                      xray-proxy-freedom/
proxy/dokodemo/                     xray-proxy-dokodemo/
proxy/loopback/                     xray-proxy-loopback/
proxy/tun/                          xray-proxy-tun/
proxy/wireguard/                    xray-proxy-wireguard/
proxy/hysteria/                     xray-proxy-hysteria/
infra/conf/                         xray-conf/
infra/vprotogen/                    (构建脚本，无需 crate)
infra/vformat/                      xray-conf/src/vformat/
core/                               xray-core/
main/                               xray-cli/
```

---

## 依赖拓扑图

```
Layer 7  CLI 与入口         main/*, core/*
  ↑
Layer 6  配置系统           infra/conf/*
  ↑
Layer 5  代理协议           proxy/vless, proxy/vmess, proxy/ss, proxy/trojan,
                             proxy/socks, proxy/http, proxy/dns, proxy/blackhole,
                             proxy/freedom, proxy/dokodemo, proxy/loopback,
                             proxy/tun, proxy/wireguard, proxy/hysteria
  ↑
Layer 4  应用服务           app/router, app/dns, app/dispatcher, app/proxyman,
                             app/stats, app/log, app/commander, app/observatory,
                             app/policy, app/reverse, app/metrics, app/version
  ↑
Layer 3  传输协议           internet/kcp, internet/hysteria, internet/splithttp,
                             internet/grpc, internet/websocket, internet/httpupgrade,
                             internet/tcp, internet/udp, internet/headers,
                             internet/reality, internet/finalmask, transport/pipe
  ↑
Layer 2  传输基础设施       transport/internet (核心), internet/tls, internet/sockopt,
                             internet/system_dialer, internet/system_listener,
                             cert/*, internet/tls/ech
  ↑
Layer 1  加密与数据引擎     common/crypto, common/geodata, common/mux,
                             common/xudp, bytespool, common/antireplay
  ↑
Layer 0  基础类型与抽象     common/buf, common/net, common/protocol, common/serial,
                             common/session, common/log, common/errors, common/signal,
                             common/task, common/uuid, features/*
```

---

## Cargo Workspace 结构

```toml
# Cargo.toml (workspace root)
[workspace]
resolver = "3"
members = [
    # Layer 0 - 基础类型
    "crates/xray-buf",
    "crates/xray-common",
    "crates/xray-features",

    # Layer 1 - 加密与数据引擎
    "crates/xray-crypto",
    "crates/xray-geodata",
    "crates/xray-mux",
    "crates/xray-xudp",

    # Layer 2 - 传输基础设施
    "crates/xray-transport",
    "crates/xray-tls",
    "crates/xray-reality",

    # Layer 3 - 传输协议
    "crates/xray-transport-kcp",
    "crates/xray-transport-hysteria",
    "crates/xray-transport-splithttp",
    "crates/xray-transport-grpc",
    "crates/xray-transport-websocket",
    "crates/xray-transport-httpupgrade",

    # Layer 4 - 应用服务
    "crates/xray-app-dns",
    "crates/xray-app-router",
    "crates/xray-app-dispatcher",
    "crates/xray-app-proxyman",
    "crates/xray-app-stats",
    "crates/xray-app-log",
    "crates/xray-app-commander",
    "crates/xray-app-observatory",
    "crates/xray-app-policy",
    "crates/xray-app-reverse",
    "crates/xray-app-metrics",
    "crates/xray-app-version",

    # Layer 5 - 代理协议
    "crates/xray-proxy-vless",
    "crates/xray-proxy-vmess",
    "crates/xray-proxy-ss",
    "crates/xray-proxy-trojan",
    "crates/xray-proxy-socks",
    "crates/xray-proxy-http",
    "crates/xray-proxy-dns",
    "crates/xray-proxy-blackhole",
    "crates/xray-proxy-freedom",
    "crates/xray-proxy-dokodemo",
    "crates/xray-proxy-loopback",
    "crates/xray-proxy-tun",
    "crates/xray-proxy-wireguard",

    # Layer 6 - 配置
    "crates/xray-conf",

    # Layer 7 - 核心与 CLI
    "crates/xray-core",
    "crates/xray-cli",
]
```

### 目录树

```
xray-core-rust/
├── Cargo.toml                          # workspace 根
├── clippy.toml                         # clippy 配置
├── rustfmt.toml                        # 格式化配置
├── deny.toml                           # cargo-deny 许可证/安全配置
├── .github/
│   └── workflows/
│       ├── ci.yml                      # fmt + clippy + test + bench
│       └── release.yml                 # 多平台构建发布
├── proto/                              # protobuf 定义（从 Go 版本复用）
│   ├── app/
│   ├── common/
│   ├── core/
│   ├── proxy/
│   └── transport/
├── crates/
│   ├── xray-buf/                       # Layer 0: 缓冲区
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 buf.go
│   │       ├── buffer.rs               # 对应 buffer.go — Buffer 分配/释放
│   │       ├── multi.rs                # 对应 multi_buffer.go — MultiBuffer
│   │       ├── copy.rs                 # 对应 copy.go — Reader→Writer
│   │       ├── io.rs                   # 对应 io.go — Reader/Writer 统一
│   │       ├── reader.rs               # 对应 reader.go — BufferedReader
│   │       ├── writer.rs               # 对应 writer.go — BufferedWriter
│   │       ├── readv.rs                # 对应 readv_*.go — scatter-gather IO
│   │       ├── alloc.rs                # 对应 readv_reader.go — 分配策略
│   │       └── timeout.rs              # 对应 (buf包内) — 超时读取
│   │
│   ├── xray-common/                    # Layer 0: 基础类型
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── net/                    # 对应 common/net/
│   │       │   ├── mod.rs              # Address, Port, Destination, IPOrDomain
│   │       │   ├── address.rs
│   │       │   ├── destination.rs
│   │       │   └── port.rs
│   │       ├── protocol/              # 对应 common/protocol/
│   │       │   ├── mod.rs              # ServerEndpoint, User, AddressParser
│   │       │   ├── user.rs
│   │       │   ├── server_spec.rs
│   │       │   └── address_parser.rs
│   │       ├── serial/                 # 对应 common/serial/
│   │       │   └── mod.rs              # TypedMessage 序列化
│   │       ├── session/               # 对应 common/session/
│   │       │   └── mod.rs              # Inbound/Outbound/Sniffing 上下文
│   │       ├── log/                    # 对应 common/log/
│   │       │   └── mod.rs              # 日志系统 (tracing)
│   │       ├── errors/                 # 对应 common/errors/
│   │       │   └── mod.rs              # 统一错误类型
│   │       ├── signal/                 # 对应 common/signal/
│   │       │   └── mod.rs              # Pub/Sub 信号
│   │       ├── task/                   # 对应 common/task/
│   │       │   └── mod.rs              # 任务管理
│   │       ├── uuid/                   # 对应 common/uuid/
│   │       │   └── mod.rs              # UUID 生成
│   │       ├── platform/              # 对应 common/platform/
│   │       │   ├── mod.rs              # 资源路径、环境变量
│   │       │   └── env.rs
│   │       ├── ctx/                    # 对应 common/ctx/
│   │       │   └── mod.rs
│   │       ├── cache/                  # 对应 common/cache/
│   │       │   └── mod.rs
│   │       ├── bitmask/               # 对应 common/bitmask/
│   │       │   └── mod.rs
│   │       ├── ocsp/                   # 对应 common/ocsp/
│   │       │   └── mod.rs
│   │       ├── peer/                   # 对应 common/peer/
│   │       │   └── mod.rs
│   │       ├── drain/                  # 对应 common/drain/
│   │       │   └── mod.rs
│   │       ├── antireplay/            # 对应 common/antireplay/
│   │       │   └── mod.rs
│   │       ├── singbridge/            # 对应 common/singbridge/
│   │       │   └── mod.rs
│   │       ├── cmdarg/                # 对应 common/cmdarg/
│   │       │   └── mod.rs
│   │       ├── dice.rs                 # 对应 common/dice/
│   │       ├── units.rs               # 对应 common/units/
│   │       ├── retry.rs               # 对应 common/retry/
│   │       ├── reflect.rs             # 对应 common/reflect/
│   │       └── bytespool.rs           # 对应 bytespool/
│   │
│   ├── xray-features/                  # Layer 0: Feature Trait
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 features/feature.go
│   │       ├── dns.rs                  # 对应 features/dns/
│   │       ├── routing.rs             # 对应 features/routing/
│   │       ├── inbound.rs             # 对应 features/inbound/
│   │       ├── outbound.rs            # 对应 features/outbound/
│   │       ├── policy.rs              # 对应 features/policy/
│   │       ├── stats.rs               # 对应 features/stats/
│   │       └── extension.rs           # 对应 features/extension/
│   │
│   ├── xray-crypto/                    # Layer 1: 加密引擎
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 common/crypto/
│   │       ├── aead.rs                 # AES-GCM, ChaCha20-Poly1305
│   │       ├── authenticator.rs        # 对应 crypto/aeadauthenticator
│   │       ├── auth_reader.rs          # AuthenticationReader
│   │       ├── auth_writer.rs          # AuthenticationWriter
│   │       ├── chunk.rs                # AEAD 块加密
│   │       └── key_cache.rs            # 密钥缓存
│   │
│   ├── xray-geodata/                   # Layer 1: 地理数据引擎
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── geoip.rs                # 对应 common/geodata (IP)
│   │       ├── geosite.rs             # 对应 common/geodata (域名)
│   │       ├── matcher/               # 匹配引擎
│   │       │   ├── mod.rs
│   │       │   ├── domain.rs           # 域名匹配（全匹配/子串/正则/AC自动机/MPH）
│   │       │   ├── ip.rs               # IP 匹配（CIDR/MPH）
│   │       │   └── attributes.rs       # 对应 router/attributematcher
│   │       └── loader.rs              # geoip.dat/geosite.dat 加载
│   │
│   ├── xray-mux/                       # Layer 1: 多路复用
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 common/mux/
│   │       ├── session.rs              # Session 管理
│   │       ├── frame.rs                # Frame 编解码
│   │       ├── worker.rs               # Worker 处理
│   │       └── client.rs              # MuxClient/Server
│   │
│   ├── xray-xudp/                      # Layer 1: XUDP
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 common/xudp/
│   │       ├── packet.rs               # XUDP 数据包读写
│   │       └── extension.rs            # XUDP 扩展
│   │
│   ├── xray-transport/                 # Layer 2: 传输核心
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 transport/internet/internet.go
│   │       ├── dialer.rs               # 对应 system_dialer.go
│   │       ├── listener.rs             # 对应 system_listener.go
│   │       ├── sockopt/               # 对应 internet/sockopt_*.go
│   │       │   ├── mod.rs
│   │       │   ├── linux.rs            # Linux 特有
│   │       │   ├── windows.rs          # Windows 特有
│   │       │   ├── darwin.rs           # macOS 特有
│   │       │   └── freebsd.rs          # FreeBSD 特有
│   │       ├── tcp/                    # 对应 internet/tcp/
│   │       │   ├── mod.rs              # TCP Hub/连接
│   │       │   └── hub.rs              # 对应 tcp_hub.go
│   │       ├── udp/                    # 对应 internet/udp/
│   │       │   ├── mod.rs
│   │       │   └── hub.rs
│   │       ├── headers/               # 对应 internet/headers/
│   │       │   ├── mod.rs
│   │       │   ├── srtp.rs             # SRTP 头伪装
│   │       │   ├── utp.rs              # uTP 头伪装
│   │       │   ├── wechat.rs           # 微信头伪装
│   │       │   ├── dtls.rs             # DTLS 头伪装
│   │       │   └── wireguard.rs        # WireGuard 头伪装
│   │       ├── finalmask/             # 对应 internet/finalmask/
│   │       │   └── mod.rs              # TCP/UDP 掩码
│   │       ├── pipe/                   # 对应 transport/pipe/
│   │       │   └── mod.rs
│   │       ├── config.rs              # 对应 internet/config.go + config.proto
│   │       ├── connection.rs          # 连接抽象
│   │       ├── filelocker.rs          # 对应 filelocker.go
│   │       ├── happy_eyeballs.rs      # 对应 happy_eyeballs.go
│   │       ├── browser_dialer.rs      # 对应 browser_dialer/
│   │       ├── tagged.rs              # 对应 tagged/
│   │       ├── stat.rs                # 对应 stat/
│   │       └── memory_settings.rs     # 对应 memory_settings.go
│   │
│   ├── xray-tls/                       # Layer 2: TLS 系统
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 transport/internet/tls/tls.go
│   │       ├── config.rs              # 对应 tls/config.go — TLS 配置
│   │       ├── certificate.rs         # 对应 tls/certificate — 证书类型
│   │       ├── ech.rs                  # 对应 tls/ech.go — ECH 支持
│   │       ├── pin.rs                  # 对应 tls/pin.go — 证书固定
│   │       ├── utls.rs                # uTLS 指纹伪装 (btls + wreq-util)
│   │       ├── grpc.rs                # 对应 tls/grpc.go — gRPC TLS
│   │       └── unsafe_conn.rs         # 对应 tls/unsafe.go — unsafe TLS 操作
│   │
│   ├── xray-reality/                   # Layer 2: REALITY 协议
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 transport/internet/reality/
│   │       ├── server.rs              # REALITY 服务端
│   │       ├── client.rs              # REALITY 客户端
│   │       └── config.rs              # REALITY 配置
│   │
│   ├── xray-transport-kcp/             # Layer 3: KCP 传输
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 transport/internet/kcp/kcp.go
│   │       ├── connection.rs          # 对应 kcp/connection.go
│   │       ├── dialer.rs              # 对应 kcp/dialer.go
│   │       ├── listener.rs            # 对应 kcp/listener.go
│   │       ├── segment.rs             # 对应 kcp/segment.go
│   │       ├── sending.rs             # 对应 kcp/sending.go
│   │       ├── receiving.rs           # 对应 kcp/receiving.go
│   │       ├── output.rs              # 对应 kcp/output.go
│   │       ├── io.rs                  # 对应 kcp/io.go
│   │       └── config.rs             # 对应 kcp/config.go + config.proto
│   │
│   ├── xray-transport-hysteria/        # Layer 3: Hysteria 传输
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 transport/internet/hysteria/
│   │       ├── conn.rs                # 对应 hysteria/conn.go
│   │       ├── dialer.rs              # 对应 hysteria/dialer.go
│   │       ├── hub.rs                 # 对应 hysteria/hub.go
│   │       ├── udphop/               # 对应 hysteria/udphop/
│   │       │   └── mod.rs
│   │       ├── congestion/            # 对应 hysteria/congestion/
│   │       │   ├── mod.rs
│   │       │   ├── brutal.rs          # Brutal 拥塞控制
│   │       │   └── bbr.rs             # BBR 拥塞控制
│   │       └── config.rs
│   │
│   ├── xray-transport-splithttp/       # Layer 3: SplitHTTP 传输
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 transport/internet/splithttp/
│   │       ├── client.rs              # 对应 splithttp/client.go
│   │       ├── hub.rs                 # 对应 splithttp/hub.go
│   │       ├── connection.rs          # 对应 splithttp/connection.go
│   │       ├── dialer.rs              # 对应 splithttp/dialer.go
│   │       ├── mux.rs                 # 对应 splithttp/mux.go — xmux
│   │       ├── upload_queue.rs        # 对应 splithttp/upload_queue.go
│   │       ├── xpadding.rs            # 对应 splithttp/xpadding.go
│   │       ├── h1_conn.rs             # 对应 splithttp/h1_conn.go
│   │       ├── browser_client.rs      # 对应 splithttp/browser_client.go
│   │       └── config.rs
│   │
│   ├── xray-transport-grpc/            # Layer 3: gRPC 传输
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 transport/internet/grpc/
│   │       ├── client.rs
│   │       ├── server.rs
│   │       └── config.rs
│   │
│   ├── xray-transport-websocket/       # Layer 3: WebSocket 传输
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 transport/internet/websocket/
│   │       ├── client.rs
│   │       ├── server.rs
│   │       └── config.rs
│   │
│   ├── xray-transport-httpupgrade/     # Layer 3: HTTPUpgrade 传输
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 transport/internet/httpupgrade/
│   │       ├── client.rs
│   │       ├── server.rs
│   │       └── config.rs
│   │
│   ├── xray-app-dns/                   # Layer 4: DNS 服务
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 app/dns/dns.go
│   │       ├── nameserver/            # 对应 app/dns/nameserver*.go
│   │       │   ├── mod.rs              # NameServer 接口
│   │       │   ├── udp.rs              # 对应 nameserver_udp.go
│   │       │   ├── tcp.rs              # 对应 nameserver_tcp.go
│   │       │   ├── doh.rs              # 对应 nameserver_doh.go
│   │       │   ├── quic.rs             # 对应 nameserver_quic.go
│   │       │   ├── local.rs            # 对应 nameserver_local.go
│   │       │   ├── fakedns.rs          # 对应 nameserver_fakedns.go
│   │       │   └── cached.rs           # 对应 nameserver_cached.go
│   │       ├── fakedns/               # 对应 app/dns/fakedns/
│   │       │   └── mod.rs              # FakeDNS 引擎 + LRU
│   │       ├── hosts.rs               # 对应 app/dns/hosts.go
│   │       ├── cache_controller.rs    # 对应 app/dns/cache_controller.go
│   │       ├── dnscommon.rs           # 对应 app/dns/dnscommon.go
│   │       └── config.rs
│   │
│   ├── xray-app-router/                # Layer 4: 路由引擎
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 app/router/router.go
│   │       ├── condition.rs           # 对应 app/router/condition.go
│   │       ├── rule.rs                # 路由规则解析
│   │       ├── balancing.rs           # 对应 app/router/balancing.go
│   │       ├── strategy_leastload.rs  # 对应 app/router/strategy_leastload.go
│   │       ├── strategy_leastping.rs  # 对应 app/router/strategy_leastping.go
│   │       ├── strategy_random.rs     # 对应 app/router/strategy_random.go
│   │       ├── weight.rs              # 对应 app/router/weight.go
│   │       ├── webhook.rs             # 对应 app/router/webhook.go
│   │       ├── command/              # 对应 app/router/command/
│   │       │   └── mod.rs              # gRPC 命令
│   │       └── config.rs
│   │
│   ├── xray-app-dispatcher/            # Layer 4: 调度器
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 app/dispatcher/dispatcher.go
│   │       ├── default.rs             # 对应 app/dispatcher/default.go
│   │       ├── sniffer.rs             # 对应 app/dispatcher/sniffer.go
│   │       ├── fakednssniffer.rs      # 对应 app/dispatcher/fakednssniffer.go
│   │       ├── stats.rs               # 对应 app/dispatcher/stats.go
│   │       └── config.rs
│   │
│   ├── xray-app-proxyman/              # Layer 4: 代理管理
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 app/proxyman/
│   │       ├── inbound/               # 对应 app/proxyman/inbound/
│   │       │   └── mod.rs
│   │       ├── outbound/              # 对应 app/proxyman/outbound/
│   │       │   └── mod.rs
│   │       └── config.rs
│   │
│   ├── xray-app-stats/                 # Layer 4: 统计
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs                  # 对应 app/stats/
│   │
│   ├── xray-app-log/                   # Layer 4: 日志实例
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs                  # 对应 app/log/
│   │
│   ├── xray-app-commander/             # Layer 4: gRPC 命令
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs                  # 对应 app/commander/
│   │
│   ├── xray-app-observatory/           # Layer 4: 观测
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs                  # 对应 app/observatory/
│   │
│   ├── xray-app-policy/                # Layer 4: 策略
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs                  # 对应 app/policy/
│   │
│   ├── xray-app-reverse/               # Layer 4: 反向代理
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs                  # 对应 app/reverse/
│   │
│   ├── xray-app-metrics/               # Layer 4: 指标
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs                  # 对应 app/metrics/
│   │
│   ├── xray-app-version/               # Layer 4: 版本
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs                  # 对应 app/version/
│   │
│   ├── xray-proxy-vless/               # Layer 5: VLESS 协议
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 proxy/vless/vless.go
│   │       ├── account.rs             # 对应 proxy/vless/account.go
│   │       ├── validator.rs           # 对应 proxy/vless/validator.go
│   │       ├── inbound/               # 对应 proxy/vless/inbound/
│   │       │   ├── mod.rs
│   │       │   └── handler.rs
│   │       ├── outbound/              # 对应 proxy/vless/outbound/
│   │       │   ├── mod.rs
│   │       │   └── handler.rs
│   │       ├── encoding/              # 对应 proxy/vless/encoding/
│   │       │   ├── mod.rs              # VLESS 协议编解码
│   │       │   ├── client.rs
│   │       │   └── server.rs
│   │       └── encryption/            # 对应 proxy/vless/encryption/
│   │           └── mod.rs              # XTLS Vision 加密
│   │
│   ├── xray-proxy-vmess/               # Layer 5: VMess 协议
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 proxy/vmess/vmess.go
│   │       ├── account.rs             # 对应 proxy/vmess/account.go
│   │       ├── validator.rs           # 对应 proxy/vmess/validator.go
│   │       ├── inbound/               # 对应 proxy/vmess/inbound/
│   │       │   ├── mod.rs
│   │       │   └── handler.rs
│   │       ├── outbound/              # 对应 proxy/vmess/outbound/
│   │       │   ├── mod.rs
│   │       │   └── handler.rs
│   │       ├── encoding/              # 对应 proxy/vmess/encoding/
│   │       │   ├── mod.rs
│   │       │   ├── client.rs
│   │       │   └── server.rs
│   │       └── aead/                  # 对应 proxy/vmess/aead/
│   │           └── mod.rs              # VMess AEAD 加密
│   │
│   ├── xray-proxy-ss/                  # Layer 5: Shadowsocks
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 proxy/shadowsocks/shadowsocks.go
│   │       ├── client.rs              # 对应 proxy/shadowsocks/client.go
│   │       ├── server.rs              # 对应 proxy/shadowsocks/server.go
│   │       ├── protocol.rs            # 对应 proxy/shadowsocks/protocol.go
│   │       ├── config.rs              # 对应 proxy/shadowsocks/config.go
│   │       └── validator.rs           # 对应 proxy/shadowsocks/validator.go
│   │
│   ├── xray-proxy-trojan/              # Layer 5: Trojan
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 proxy/trojan/trojan.go
│   │       ├── client.rs              # 对应 proxy/trojan/client.go
│   │       ├── server.rs              # 对应 proxy/trojan/server.go
│   │       ├── protocol.rs            # 对应 proxy/trojan/protocol.go
│   │       ├── config.rs              # 对应 proxy/trojan/config.go
│   │       └── validator.rs           # 对应 proxy/trojan/validator.go
│   │
│   ├── xray-proxy-socks/               # Layer 5: SOCKS5
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 proxy/socks/
│   │       ├── client.rs
│   │       ├── server.rs
│   │       └── config.rs
│   │
│   ├── xray-proxy-http/                # Layer 5: HTTP 代理
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 proxy/http/
│   │       ├── client.rs
│   │       ├── server.rs
│   │       └── config.rs
│   │
│   ├── xray-proxy-dns/                 # Layer 5: DNS 出站
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs                  # 对应 proxy/dns/
│   │
│   ├── xray-proxy-blackhole/           # Layer 5: 黑洞
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs                  # 对应 proxy/blackhole/
│   │
│   ├── xray-proxy-freedom/             # Layer 5: 直连
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs                  # 对应 proxy/freedom/
│   │
│   ├── xray-proxy-dokodemo/            # Layer 5: 任意门
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs                  # 对应 proxy/dokodemo/
│   │
│   ├── xray-proxy-loopback/            # Layer 5: 回环
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs                  # 对应 proxy/loopback/
│   │
│   ├── xray-proxy-tun/                 # Layer 5: TUN 设备
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs                  # 对应 proxy/tun/
│   │
│   ├── xray-proxy-wireguard/           # Layer 5: WireGuard
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs                  # 对应 proxy/wireguard/
│   │
│   ├── xray-conf/                      # Layer 6: 配置
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 infra/conf/
│   │       ├── json.rs                 # 对应 main/json/
│   │       ├── yaml.rs                 # 对应 main/yaml/
│   │       ├── toml.rs                 # 对应 main/toml/
│   │       ├── vformat/               # 对应 infra/vformat/
│   │       │   └── mod.rs
│   │       └── confloader.rs          # 对应 main/confloader/
│   │
│   ├── xray-core/                      # Layer 7: 核心实例
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # 对应 core/xray.go
│   │       ├── core.rs                # 对应 core/core.go
│   │       ├── instance.rs            # Feature 注册/生命周期
│   │       ├── config.rs              # 对应 core/config.go
│   │       ├── context.rs             # 对应 core/context.go
│   │       ├── functions.rs           # 对应 core/functions.go
│   │       ├── format.rs              # 对应 core/format.go
│   │       ├── proto.rs               # 对应 core/proto.go
│   │       └── annotations.rs         # 对应 core/annotations.go
│   │
│   └── xray-cli/                       # Layer 7: CLI
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs                 # 对应 main/main.go
│           ├── run.rs                  # 对应 main/run.go
│           ├── version.rs             # 对应 main/version.go
│           ├── commands/              # 对应 main/commands/
│           │   └── mod.rs
│           └── distro/                # 对应 main/distro/
│               └── mod.rs
│
├── benches/                            # 性能基准测试
│   ├── buf_bench.rs                    # Buffer 性能
│   ├── crypto_bench.rs                 # 加密性能
│   ├── router_bench.rs                # 路由匹配性能
│   └── transport_bench.rs             # 传输性能
│
└── tests/                              # 集成测试
    └── integration/
        ├── vless_test.rs
        ├── vmess_test.rs
        ├── ss_test.rs
        ├── trojan_test.rs
        └── compatibility_test.rs       # Go vs Rust 兼容性测试
```

---

## Phase 0：项目脚手架（1 周）

**目标**：搭建完整项目结构、CI/CD、protobuf 代码生成

### 任务清单

| # | 任务 | 说明 | 工具 |
|---|------|------|------|
| 1 | Cargo workspace 初始化 | 创建所有 crate 骨架，空 `lib.rs` | — |
| 2 | CI/CD 流水线 | GitHub Actions: `fmt` + `clippy` + `test` + `bench` | GitHub Actions |
| 3 | protobuf 代码生成 | 从 Go 版 71 个 `.proto` 生成 Rust 类型 | `prost-build` |
| 4 | 基准测试框架 | Go vs Rust 性能对比基准 | `criterion` |
| 5 | 代码规范配置 | `rustfmt.toml` + `clippy.toml` + `deny.toml` | — |
| 6 | 许可证声明 | 与 Go 版保持一致 (MPL-2.0) | — |

### 关键依赖

```toml
# 构建依赖
prost-build = "0.14"
tonic-build = "0.14"
```

**里程碑**：`cargo build --workspace` 编译通过，`cargo test --workspace` 运行成功（空测试）

---

## Phase 1：基础类型与抽象层（3-4 周）

> Rust 生态成熟度：✅ 全部有成熟替代

### 1.1 缓冲区系统 `xray-buf`

**Go 源码映射**：`common/buf/` → `crates/xray-buf/src/`

| Go 文件 | Rust 文件 | 核心功能 | Rust 实现 | 预估行数 |
|---------|----------|---------|----------|---------|
| `buf.go` | `lib.rs` | Buffer 池 + 全局函数 | `bytes::BytesMut` 池化 | ~200 |
| `buffer.go` | `buffer.rs` | Buffer 分配/释放/所有权 | 基于 `bytes::BytesMut` 封装 | ~500 |
| `multi_buffer.go` | `multi.rs` | MultiBuffer 拼接/拆分 | `Vec<BytesMut>` + 零拷贝 | ~800 |
| `copy.go` | `copy.rs` | Reader→Writer 数据拷贝 | `tokio::io::copy` + 自定义 | ~600 |
| `io.go` | `io.rs` | Reader/Writer trait | `tokio::io` + 自定义 trait | ~500 |
| `reader.go` | `reader.rs` | BufferedReader | `BufReader<BytesMut>` | ~300 |
| `writer.go` | `writer.rs` | BufferedWriter | `BufWriter<BytesMut>` | ~300 |
| `readv_*.go` | `readv.rs` | scatter-gather IO | tokio `try_read_vectored`（readv/WSARecv）+ `AllocStrategy` | ~480 |
| `readv_reader.go` | `readv.rs` | ReadVReader + 分配策略 | 池化 Buffer + `AllocStrategy`（Go allocStrategy 对齐） | （同上） |
| — | `timeout.rs` | 超时读取 | `tokio::time::timeout` | ~200 |

**核心 crate 依赖**：
```toml
bytes = "1.11"
bytes-utils = "0.1"
tokio = { version = "1", features = ["io-util", "time"] }
```

**性能收益**：零拷贝 + 无 GC，预期 30-50% 吞吐提升

### 1.2 基础类型 `xray-common`

**Go 源码映射**：`common/` 下 30+ 子包 → `crates/xray-common/src/` 下模块

| Go 包 | Rust 模块 | 核心功能 | Rust 实现 | 预估行数 |
|-------|----------|---------|----------|---------|
| `common/net` | `net/` | Address, Port, Destination, IPOrDomain | `std::net` + 自定义类型 | ~1200 |
| `common/protocol` | `protocol/` | ServerEndpoint, User, AddressParser | `serde` 结构体 | ~1500 |
| `common/serial` | `serial/` | TypedMessage 序列化 | `prost::Any` | ~300 |
| `common/session` | `session/` | Inbound/Outbound/Sniffing 上下文 | `tokio::task::LocalKey` | ~400 |
| `common/log` | `log/` | 日志系统 | `tracing` + `tracing-subscriber` | ~500 |
| `common/errors` | `errors/` | 统一错误类型 | `thiserror` + `anyhow` | ~300 |
| `common/signal` | `signal/` | Pub/Sub 信号 | `tokio::sync::broadcast` | ~300 |
| `common/task` | `task/` | 任务管理 | `tokio::spawn` + `JoinSet` | ~200 |
| `common/uuid` | `uuid/` | UUID 生成 | `uuid` crate | ~100 |
| `common/platform` | `platform/` | 资源路径、环境变量 | `dirs` + `std::env` | ~400 |
| `common/dice` | `dice.rs` | 随机数 | `rand` crate | ~100 |
| `common/units` | `units.rs` | 字节单位 | 常量定义 | ~100 |
| `common/retry` | `retry.rs` | 重试策略 | `tokio-retry` 或自研 | ~200 |
| `common/reflect` | `reflect.rs` | JSON 反射 | `serde_json` | ~600 |
| `common/ctx` | `ctx/` | 上下文工具 | — | ~200 |
| `common/cache` | `cache/` | 缓存 | `moka` 或 `lru` | ~200 |
| `common/bitmask` | `bitmask.rs` | 位掩码 | — | ~100 |
| `common/ocsp` | `ocsp.rs` | OCSP | `rustls` OCSP | ~200 |
| `common/peer` | `peer.rs` | 对端信息 | — | ~100 |
| `common/drain` | `drain.rs` | 连接排空 | — | ~150 |
| `common/antireplay` | `antireplay.rs` | 防重放 | bloom filter | ~300 |
| `common/cmdarg` | `cmdarg.rs` | 命令行参数类型 | `clap` 类型 | ~100 |
| `bytespool` | `bytespool.rs` | 字节池 | `buddy-alloc` 或自研 | ~200 |
| `common/common.go` | `lib.rs` | Must(), XrayKey, ActivityTimer | `anyhow::ensure` | ~300 |

**核心 crate 依赖**：
```toml
serde = { version = "1", features = ["derive"] }
serde_json = "1"
prost = "0.14"
thiserror = "2"
anyhow = "1"
tracing = "0.1"
tracing-subscriber = "0.3"
tokio = { version = "1", features = ["full"] }
uuid = { version = "1", features = ["v4"] }
rand = "0.9"
```

### 1.3 Feature Trait `xray-features`

**Go 源码映射**：`features/` → `crates/xray-features/src/`

| Go 文件 | Rust 文件 | 核心功能 | Rust trait |
|---------|----------|---------|-----------|
| `features/feature.go` | `lib.rs` | Feature 基础 | `trait Feature: Send + Sync + 'static` |
| `features/routing/` | `routing.rs` | Router, Route | `trait Router: Feature` |
| `features/dns/` | `dns.rs` | DNS Client | `trait DnsClient: Feature` |
| `features/inbound/` | `inbound.rs` | Inbound Handler | `trait InboundHandler: Feature` |
| `features/outbound/` | `outbound.rs` | Outbound Handler | `trait OutboundHandler: Feature` |
| `features/policy/` | `policy.rs` | Policy Manager | `trait PolicyManager: Feature` |
| `features/stats/` | `stats.rs` | Stats Manager | `trait StatsManager: Feature` |
| `features/extension/` | `extension.rs` | 扩展 | `trait Extension: Feature` |

**里程碑**：所有基础 trait 编译通过，buf 性能基准测试 ≥ Go 版本 130%

---

## Phase 2：加密与数据引擎（4-5 周）

> Rust 生态成熟度：✅ 加密库成熟 | 🟡 geodata/mux/xudp 需自研

### 2.1 加密引擎 `xray-crypto`

**Go 源码映射**：`common/crypto/` → `crates/xray-crypto/src/`

| Go 模块 | Rust 文件 | 核心功能 | Rust 实现 | 预估行数 |
|---------|----------|---------|----------|---------|
| `common/crypto` | `aead.rs` | AES-GCM, ChaCha20-Poly1305 | `ring` + RustCrypto 双引擎 | ~800 |
| `crypto/aeadauthenticator` | `authenticator.rs` | AuthenticationHeader | 自研 | ~400 |
| — | `auth_reader.rs` | AuthenticationReader | 自研 | ~300 |
| — | `auth_writer.rs` | AuthenticationWriter | 自研 | ~300 |
| `encryption/aead` | `chunk.rs` | AEAD 块加密 | RustCrypto stream cipher | ~500 |

**双引擎策略**（来自依赖分析决策）：
```toml
ring = "0.17"                    # 热路径：TLS 握手、大批量加密 (AES-GCM 3393 MB/s)
aes-gcm = "0.10"                 # 协议层：VMess AEAD 流式加密
chacha20-poly1305 = "0.9"        # 协议层：VMess/SS ChaCha20 流式加密
```

**性能收益**：ring 性能（3393 MB/s AES-GCM）远超 Go crypto

### 2.2 地理数据引擎 `xray-geodata`

**Go 源码映射**：`common/geodata/` → `crates/xray-geodata/src/`

| Go 模块 | Rust 文件 | 核心功能 | 预估行数 | 策略 |
|---------|----------|---------|---------|------|
| `common/geodata` (域名) | `matcher/domain.rs` | 全匹配/子串/正则/AC自动机/MPH | ~1500 | C-自研 |
| `common/geodata` (IP) | `matcher/ip.rs` | CIDR/MPH/启发式 | ~800 | C-自研 |
| `common/geodata` (加载) | `loader.rs` | geoip.dat/geosite.dat protobuf 解析 | ~800 | prost 解析 |
| — | `matcher/attributes.rs` | 属性匹配器 | ~500 | C-自研 |

**核心 crate 依赖**：
```toml
prost = "0.14"                   # protobuf 解析
boomphf = "0.6"                  # MPH 最小完美哈希
regex = "1"                       # 正则匹配
```

**性能收益**：紧凑内存布局 + MPH 算法，路由匹配提速 20-40%

### 2.3 多路复用 `xray-mux`

**Go 源码映射**：`common/mux/` → `crates/xray-mux/src/`

| Go 模块 | Rust 文件 | 核心功能 | 预估行数 | 策略 |
|---------|----------|---------|---------|------|
| `common/mux` | `session.rs` | Session 管理 | ~1000 | C-自研 |
| `common/mux` | `frame.rs` | Frame 编解码 | ~1000 | C-自研 |
| `common/mux` | `worker.rs` | Worker 处理 | ~800 | C-自研 |
| `common/mux` | `client.rs` | MuxClient/Server | ~500 | C-自研 |

### 2.4 XUDP `xray-xudp`

**Go 源码映射**：`common/xudp/` → `crates/xray-xudp/src/`

| Go 模块 | Rust 文件 | 核心功能 | 预估行数 | 策略 |
|---------|----------|---------|---------|------|
| `common/xudp` | `packet.rs` | XUDP 数据包读写 | ~800 | C-自研 |
| `common/xudp` | `extension.rs` | XUDP 扩展 | ~500 | C-自研 |

**里程碑**：加密基准测试通过，geodata 匹配正确性测试通过

---

## Phase 3：传输基础设施（4-5 周）

> Rust 生态成熟度：✅ TLS(btls)成熟 | ✅ 指纹伪装(btls+wreq)可用

### 3.1 传输核心 `xray-transport`

**Go 源码映射**：`transport/internet/` → `crates/xray-transport/src/`

| Go 文件 | Rust 文件 | 核心功能 | Rust 实现 | 预估行数 |
|---------|----------|---------|----------|---------|
| `internet.go` | `lib.rs` | 核心传输抽象 | `tokio::net` + trait | ~800 |
| `system_dialer.go` | `dialer.rs` | 系统拨号器 | `tokio::net::TcpStream` | ~800 |
| `system_listener.go` | `listener.rs` | 系统监听器 | `tokio::net::TcpListener` | ~600 |
| `config.go` | `config.rs` | 传输配置 | prost 生成 + 自定义 | ~500 |
| `sockopt_*.go` | `sockopt/*.rs` | 跨平台 socket 选项 | `socket2` 平台特定 | ~1500 |
| `tcp_hub.go` | `tcp/hub.rs` | TCP Hub | 自研 | ~800 |
| `happy_eyeballs.go` | `happy_eyeballs.rs` | Happy Eyeballs | `tokio` + 自研 | ~300 |
| `filelocker.go` | `filelocker.rs` | 文件锁 | `fs4` | ~200 |
| `header.go` | `headers/mod.rs` | 协议头抽象 | — | ~200 |
| `headers/*.go` | `headers/*.rs` | srtp/utp/wechat/dtls/wireguard 伪装 | 自研 | ~1500 |
| `finalmask/` | `finalmask/` | TCP/UDP 掩码 | 自研 | ~1000 |
| `pipe/` | `pipe/` | 内存管道 | `tokio::sync::mpsc` | ~300 |
| `browser_dialer/` | `browser_dialer.rs` | 浏览器拨号器 | 自研 | ~500 |
| `tagged/` | `tagged.rs` | 标记连接 | — | ~200 |
| `stat/` | `stat.rs` | 传输统计 | — | ~200 |
| `memory_settings.go` | `memory_settings.rs` | 内存设置 | — | ~100 |

**核心 crate 依赖**：
```toml
tokio = { version = "1", features = ["net", "io-util", "time", "sync"] }
socket2 = { version = "0.6", features = ["all"] }
```

### 3.2 TLS 系统 `xray-tls`

**Go 源码映射**：`transport/internet/tls/` → `crates/xray-tls/src/`

| Go 文件 | Rust 文件 | 核心功能 | Rust 实现 | 预估行数 | 策略 |
|---------|----------|---------|----------|---------|------|
| `tls.go` | `lib.rs` | TLS 入口 | — | ~200 | — |
| `config.go` | `config.rs` | TLS 配置/证书解析 | `btls` 配置 | ~1500 | ⚠️ 适配 |
| `config.proto` | `config.rs` | protobuf 配置 | `prost` 生成 | ~300 | ✅ |
| `certificate` | `certificate.rs` | 证书类型 | `btls` 类型 | ~400 | ✅ |
| `ech.go` | `ech.rs` | ECH 支持 | DoH 查询 + ECH | ~1500 | 🟡 部分自研 |
| `pin.go` | `pin.rs` | 证书固定 | — | ~300 | ✅ |
| `grpc.go` | `grpc.rs` | gRPC TLS | `tonic` TLS | ~300 | ✅ |
| `unsafe.go` | `unsafe_conn.rs` | 不安全 TLS 操作 | btls 底层 | ~500 | ⚠️ |
| uTLS (Go: `utls` 库) | `utls.rs` | **TLS 指纹伪装** | `btls` + `wreq-util` | ~800 | ⭐ 关键改进 |

**✅ 关键改进（vs 原计划）**：uTLS 指纹伪装不再需要 8000 行自研或 FFI-to-Go。

**btls + wreq-util 方案**：
```toml
btls = "0.1"                     # BoringSSL 绑定，含指纹控制 API
wreq = "0.2"                     # HTTP client + 100+ 浏览器配置
wreq-util = "0.1"                # Chrome/Firefox/Safari 指纹配置库
tokio-btls = "0.1"               # async TLS stream
```

**btls 已有的指纹控制 API**：
- `set_grease_enabled` — GREASE 扩展
- `set_permute_extensions` — 扩展排列
- `set_cipher_list` — 密码套件选择
- 完全等价于 Go `utls`，**无需 FFI**

### 3.3 REALITY 协议 `xray-reality`

**Go 源码映射**：`transport/internet/reality/` → `crates/xray-reality/src/`

| Go 模块 | Rust 文件 | 核心功能 | 预估行数 | 策略 |
|---------|----------|---------|---------|------|
| `reality/` (服务端) | `server.rs` | REALITY TLS 伪装 | ~1500 | B-参考 shoes |
| `reality/` (客户端) | `client.rs` | REALITY 客户端 | ~1500 | B-参考 shoes |
| `reality/config` | `config.rs` | 配置 | ~300 | — |

**参考来源**：shoes (cfal, 1112⭐) — 最完整的 REALITY Rust 实现
**TLS 后端**：btls（非 patched rustls），长期维护无风险

**里程碑**：TCP/UDP 传输可用，TLS 连接可建立，uTLS 指纹伪装可用

---

## Phase 4：应用服务层（4-5 周）

> Rust 生态成熟度：✅ 异步/缓存成熟 | 🟡 路由引擎需自研

### 4.1 DNS 服务 `xray-app-dns`

**Go 源码映射**：`app/dns/` → `crates/xray-app-dns/src/`

| Go 文件 | Rust 文件 | 核心功能 | Rust 实现 | 预估行数 |
|---------|----------|---------|----------|---------|
| `dns.go` | `lib.rs` | DNS 解析器核心 | — | ~500 |
| `dnscommon.go` | `dnscommon.rs` | DNS 公共逻辑 | `hickory-resolver` | ~800 |
| `nameserver_udp.go` | `nameserver/udp.rs` | UDP DNS | `hickory-client` | ~300 |
| `nameserver_tcp.go` | `nameserver/tcp.rs` | TCP DNS | `hickory-client` | ~300 |
| `nameserver_doh.go` | `nameserver/doh.rs` | DNS-over-HTTPS | `hickory-client` | ~500 |
| `nameserver_quic.go` | `nameserver/quic.rs` | DNS-over-QUIC | `hickory-client` + `quinn` | ~600 |
| `nameserver_local.go` | `nameserver/local.rs` | 本地 DNS | `hickory-resolver` | ~200 |
| `nameserver_fakedns.go` | `nameserver/fakedns.rs` | FakeDNS Nameserver | 自研 | ~300 |
| `nameserver_cached.go` | `nameserver/cached.rs` | 缓存 Nameserver | `moka` 缓存 | ~200 |
| `fakedns/` | `fakedns/` | FakeDNS 引擎 + LRU | 参考 leaf 实现 | ~500 |
| `hosts.go` | `hosts.rs` | Hosts 解析 | — | ~300 |
| `cache_controller.go` | `cache_controller.rs` | 缓存控制 | — | ~200 |

**核心 crate 依赖**：
```toml
hickory-resolver = "0.26"        # DoT/DoH/DoQ/DoH3 全协议
hickory-client = "0.26"
quinn = "0.11"                    # DoQ
moka = { version = "0.12", features = ["future"] }  # 缓存
```

### 4.2 路由引擎 `xray-app-router`

**Go 源码映射**：`app/router/` → `crates/xray-app-router/src/`

| Go 文件 | Rust 文件 | 核心功能 | 预估行数 | 策略 |
|---------|----------|---------|---------|------|
| `router.go` | `lib.rs` | 路由核心 | ~1500 | C-自研 |
| `condition.go` | `condition.rs` | 条件匹配 | ~2000 | C-自研 |
| `balancing.go` | `balancing.rs` | 负载均衡规则 | ~800 | C-自研 |
| `strategy_leastload.go` | `strategy_leastload.rs` | 最小负载策略 | ~800 | C-自研 |
| `strategy_leastping.go` | `strategy_leastping.rs` | 最小延迟策略 | ~500 | C-自研 |
| `strategy_random.go` | `strategy_random.rs` | 随机策略 | ~300 | C-自研 |
| `weight.go` | `weight.rs` | 权重 | ~300 | C-自研 |
| `webhook.go` | `webhook.rs` | Webhook | `reqwest` | ~300 |
| `command/` | `command/` | gRPC 命令 | `tonic` | ~500 |
| `config.go` + `config.proto` | `config.rs` | 配置 | prost 生成 | ~300 |

### 4.3 调度器 `xray-app-dispatcher`

**Go 源码映射**：`app/dispatcher/` → `crates/xray-app-dispatcher/src/`

| Go 文件 | Rust 文件 | 核心功能 | 预估行数 |
|---------|----------|---------|---------|
| `dispatcher.go` | `lib.rs` | 调度器接口 | ~500 |
| `default.go` | `default.rs` | 默认调度器 | ~2000 |
| `sniffer.go` | `sniffer.rs` | 协议嗅探 | ~800 |
| `fakednssniffer.go` | `fakednssniffer.rs` | FakeDNS 嗅探 | ~300 |
| `stats.go` | `stats.rs` | 连接统计 | ~400 |

### 4.4 其他应用服务

| crate | Go 包 | 核心功能 | 预估行数 |
|-------|-------|---------|---------|
| `xray-app-proxyman` | `app/proxyman/` | 入站/出站管理 | ~3000 |
| `xray-app-stats` | `app/stats/` | 统计计数器/通道 | ~1500 |
| `xray-app-log` | `app/log/` | 日志实例 | ~800 |
| `xray-app-commander` | `app/commander/` | gRPC 命令服务 | ~800 |
| `xray-app-observatory` | `app/observatory/` | 出站观测/健康探测 | ~1500 |
| `xray-app-policy` | `app/policy/` | 策略管理 | ~600 |
| `xray-app-reverse` | `app/reverse/` | 反向代理 | ~1500 |
| `xray-app-metrics` | `app/metrics/` | Prometheus 指标 | ~800 |
| `xray-app-version` | `app/version/` | 版本信息 | ~200 |

**里程碑**：DNS 解析可用，路由规则匹配正确，调度器可转发连接

---

## Phase 5：传输协议层（5-7 周）

> Rust 生态成熟度：✅ QUIC/HTTP/WS 可用 | 🟡 KCP 有参考 | 🔴 SplitHTTP 自研

### 5.1 KCP 传输 `xray-transport-kcp`

**Go 源码映射**：`transport/internet/kcp/` → `crates/xray-transport-kcp/src/`

| Go 文件 | Rust 文件 | 核心功能 | 预估行数 | 策略 |
|---------|----------|---------|---------|------|
| `kcp.go` | `lib.rs` | KCP 核心 | ~800 | B-参考 kcp-tokio |
| `connection.go` | `connection.rs` | KCP 连接 | ~1500 | B-参考 kcp-tokio |
| `dialer.go` | `dialer.rs` | KCP 拨号器 | ~600 | — |
| `listener.go` | `listener.rs` | KCP 监听器 | ~800 | — |
| `segment.go` | `segment.rs` | KCP 数据段 | ~500 | B-参考 kcp-tokio |
| `sending.go` | `sending.rs` | 发送窗口 | ~800 | B-参考 kcp-tokio |
| `receiving.go` | `receiving.rs` | 接收窗口 | ~800 | B-参考 kcp-tokio |
| `output.go` | `output.rs` | 输出处理 | ~300 | — |
| `io.go` | `io.rs` | IO 处理 | ~400 | — |

**核心依赖**：`kcp-tokio`（核心 KCP 协议）+ `kcp2`（加密层参考），预计省 ~4500 行

### 5.2 Hysteria 传输 `xray-transport-hysteria`

**Go 源码映射**：`transport/internet/hysteria/` → `crates/xray-transport-hysteria/src/`

| Go 文件/目录 | Rust 文件 | 核心功能 | 预估行数 | 策略 |
|-------------|----------|---------|---------|------|
| `conn.go` | `conn.rs` | Hysteria 连接 | ~1500 | B-参考 clash-rs |
| `dialer.go` | `dialer.rs` | 拨号器 | ~500 | — |
| `hub.go` | `hub.rs` | 服务端 Hub | ~800 | — |
| `congestion/` | `congestion/` | Brutal + BBR 拥塞控制 | ~2000 | B-参考 clash-rs |
| `udphop/` | `udphop/` | UDP Hop | ~500 | — |

**核心依赖**：`quinn` (QUIC) + `h3` (HTTP/3)，参考 clash-rs Hysteria2 实现

### 5.3 SplitHTTP 传输 `xray-transport-splithttp`

**Go 源码映射**：`transport/internet/splithttp/` → `crates/xray-transport-splithttp/src/`

| Go 文件 | Rust 文件 | 核心功能 | 预估行数 | 策略 |
|---------|----------|---------|---------|------|
| `splithttp.go` | `lib.rs` | SplitHTTP 核心 | ~800 | C-自研 |
| `client.go` | `client.rs` | HTTP 分片客户端 | ~800 | C-自研 |
| `hub.go` | `hub.rs` | 服务端 | ~800 | C-自研 |
| `connection.go` | `connection.rs` | 连接管理 | ~500 | C-自研 |
| `mux.go` | `mux.rs` | xmux 多路复用 | ~600 | C-自研 |
| `upload_queue.go` | `upload_queue.rs` | 上传队列 | ~400 | C-自研 |
| `xpadding.go` | `xpadding.rs` | 填充混淆 | ~200 | C-自研 |
| `h1_conn.go` | `h1_conn.rs` | HTTP/1.1 连接 | ~300 | C-自研 |
| `browser_client.go` | `browser_client.rs` | 浏览器客户端 | ~200 | — |

**核心依赖**：`hyper` (HTTP/1.1+2) + `h3` (HTTP/3) + `quinn`

### 5.4 gRPC 传输 `xray-transport-grpc`

**Go 源码映射**：`transport/internet/grpc/` → `crates/xray-transport-grpc/src/`

| 预估行数 | 策略 |
|---------|------|
| ~2000 | A-直接使用 `tonic` |

### 5.5 WebSocket 传输 `xray-transport-websocket`

**Go 源码映射**：`transport/internet/websocket/` → `crates/xray-transport-websocket/src/`

| 预估行数 | 策略 |
|---------|------|
| ~2000 | A-直接使用 `tokio-tungstenite` |

### 5.6 HTTPUpgrade 传输 `xray-transport-httpupgrade`

**Go 源码映射**：`transport/internet/httpupgrade/` → `crates/xray-transport-httpupgrade/src/`

| 预估行数 | 策略 |
|---------|------|
| ~1500 | B-自研（基于 `hyper` HTTP 升级机制） |

**里程碑**：KCP 传输可用，Hysteria 客户端可连接，gRPC/WebSocket 传输可用

---

## Phase 6：代理协议层（6-8 周）🔥 最核心阶段

> Rust 生态成熟度：🟡 SS/WG 有直接依赖 | 🔴 VLESS/VMess/Trojan 参考+自研入站

### 6.1 基础代理协议（2-3 周）

| crate | Go 包 | 核心功能 | 预估行数 | 策略 |
|-------|-------|---------|---------|------|
| `xray-proxy-socks` | `proxy/socks/` | SOCKS5 入站+出站 | ~2000 | B-参考 clash-rs |
| `xray-proxy-http` | `proxy/http/` | HTTP CONNECT 代理 | ~1500 | A-`hyper` 适配 |
| `xray-proxy-blackhole` | `proxy/blackhole/` | 黑洞出站 | ~300 | C-极简 |
| `xray-proxy-freedom` | `proxy/freedom/` | 直连出站 | ~1500 | ✅ `tokio::net` |
| `xray-proxy-dns` | `proxy/dns/` | DNS 出站 | ~800 | ✅ `hickory` |
| `xray-proxy-dokodemo` | `proxy/dokodemo/` | 任意门入站 | ~1200 | C-自研 |
| `xray-proxy-loopback` | `proxy/loopback/` | 回环 | ~400 | C-极简 |

### 6.2 核心代理协议（4-6 周）🔴 重点

#### VLESS `xray-proxy-vless`

**Go 源码映射**：`proxy/vless/` → `crates/xray-proxy-vless/src/`

| Go 文件/目录 | Rust 文件 | 核心功能 | 预估行数 | 策略 |
|-------------|----------|---------|---------|------|
| `vless.go` | `lib.rs` | VLESS 注册 | ~200 | — |
| `account.go` + `account.proto` | `account.rs` | 账户 | ~200 | prost 生成 |
| `validator.go` | `validator.rs` | 用户验证 | ~400 | C-自研 |
| `inbound/` | `inbound/` | **入站（服务端）** | ~1200 | 🔴 **完全自研** |
| `outbound/` | `outbound/` | 出站（客户端） | ~800 | B-参考 clash-rs |
| `encoding/` | `encoding/` | 协议编解码 | ~1500 | B-参考 clash-rs/shoes |
| `encryption/` | `encryption/` | XTLS Vision | ~800 | B-参考 shoes |

**参考来源**：
- 出站/编码：clash-rs (VLESS 出站) + shoes (XTLS Vision)
- **入站**：完全自研，参考 Go 源码 `proxy/vless/inbound/`

#### VMess `xray-proxy-vmess`

**Go 源码映射**：`proxy/vmess/` → `crates/xray-proxy-vmess/src/`

| Go 文件/目录 | Rust 文件 | 核心功能 | 预估行数 | 策略 |
|-------------|----------|---------|---------|------|
| `vmess.go` | `lib.rs` | VMess 注册 | ~200 | — |
| `account.go` + `account.proto` | `account.rs` | 账户 | ~200 | prost 生成 |
| `validator.go` | `validator.rs` | 用户验证 | ~500 | C-自研 |
| `inbound/` | `inbound/` | **入站（服务端）** | ~1500 | 🔴 **完全自研** |
| `outbound/` | `outbound/` | 出站（客户端） | ~1000 | B-参考 clash-rs |
| `encoding/` | `encoding/` | 协议编解码 (AEAD/KDF) | ~2000 | B-参考 clash-rs |
| `aead/` | `aead/` | VMess AEAD 加密 | ~1000 | B-参考 clash-rs |

**参考来源**：
- 出站/编码/AEAD：clash-rs (VMess 完整 AEAD + KDF)
- **入站**：完全自研，参考 Go 源码 `proxy/vmess/inbound/`

#### Shadowsocks `xray-proxy-ss`

**Go 源码映射**：`proxy/shadowsocks/` → `crates/xray-proxy-ss/src/`

| Go 文件 | Rust 文件 | 核心功能 | 预估行数 | 策略 |
|---------|----------|---------|---------|------|
| `shadowsocks.go` | `lib.rs` | 注册 | ~100 | — |
| `client.go` | `client.rs` | 客户端 | ~500 | A-`shadowsocks` crate |
| `server.go` | `server.rs` | 服务端 | ~500 | A-`shadowsocks-service` crate |
| `protocol.go` | `protocol.rs` | 协议处理 | ~400 | A-直接依赖 |
| `config.go` + `config.proto` | `config.rs` | 配置 | ~300 | — |
| `validator.go` | `validator.rs` | 用户验证 | ~200 | — |

**核心依赖**：`shadowsocks = "1.24"` + `shadowsocks-service = "1.24"` — **A 级直接依赖**
⚠️ 注意：Go 版还有 `proxy/shadowsocks_2022/`，SS2022 扩展也包含在 shadowsocks crate 中

#### Trojan `xray-proxy-trojan`

**Go 源码映射**：`proxy/trojan/` → `crates/xray-proxy-trojan/src/`

| Go 文件 | Rust 文件 | 核心功能 | 预估行数 | 策略 |
|---------|----------|---------|---------|------|
| `trojan.go` | `lib.rs` | 注册 | ~100 | — |
| `client.go` | `client.rs` | 客户端 | ~600 | B-参考 clash-rs |
| `server.go` | `server.rs` | **服务端** | ~600 | 🔴 自研 |
| `protocol.go` | `protocol.rs` | 协议处理 + Fallback | ~500 | B-参考 clash-rs |
| `config.go` + `config.proto` | `config.rs` | 配置 | ~200 | — |
| `validator.go` | `validator.rs` | 用户验证 | ~200 | — |

### 6.3 高难度代理协议（2-3 周）

| crate | Go 包 | 核心功能 | 预估行数 | 策略 | 风险 |
|-------|-------|---------|---------|------|------|
| `xray-proxy-tun` | `proxy/tun/` | TUN 设备代理 | ~3000 | B-`tun-rs` + `netstack-smoltcp` | 🟡 中 |
| `xray-proxy-wireguard` | `proxy/wireguard/` | WireGuard VPN | ~2000 | A-`boringtun` 直接依赖 | 🟢 低 |

**TUN 技术方案**：
```toml
tun-rs = "2.8"                    # TUN 设备 (70.6 Gbps)
smoltcp = "0.13"                  # 底层 TCP/IP 栈
netstack-smoltcp = "0.3"          # 用户态网络栈 (替代 gVisor)
```

**WireGuard 技术方案**：
```toml
boringtun = "0.7"                 # Cloudflare 官方，BSD-3 许可
```

**里程碑**：SOCKS5/HTTP 代理可用，VLESS 客户端可连接，VMess 基础加密可用

---

## Phase 7：配置与入口层（3-4 周）

> Rust 生态成熟度：✅ serde/tonic 成熟

### 7.1 配置系统 `xray-conf`

**Go 源码映射**：`infra/conf/` + `main/json/` + `main/yaml/` + `main/toml/` → `crates/xray-conf/src/`

| Go 包 | Rust 文件 | 核心功能 | Rust 实现 | 预估行数 |
|-------|----------|---------|----------|---------|
| `infra/conf` | `lib.rs` | 配置合并/构建 | `serde` builder | ~3000 |
| `main/json` | `json.rs` | JSON 配置 | `serde_json` | ~500 |
| `main/yaml` | `yaml.rs` | YAML 配置 | `serde_yaml` | ~500 |
| `main/toml` | `toml.rs` | TOML 配置 | `toml` | ~500 |
| `infra/vformat` | `vformat/` | 格式验证 | — | ~300 |
| `main/confloader` | `confloader.rs` | 配置加载 | — | ~400 |

**核心 crate 依赖**：
```toml
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
toml = "0.8"
```

### 7.2 核心实例 `xray-core`

**Go 源码映射**：`core/` → `crates/xray-core/src/`

| Go 文件 | Rust 文件 | 核心功能 | 预估行数 |
|---------|----------|---------|---------|
| `xray.go` | `lib.rs` | Xray 核心入口 | ~500 |
| `core.go` | `core.rs` | Feature 注册/生命周期 | ~1500 |
| `config.go` + `config.proto` | `config.rs` | 配置加载/解码 | ~800 |
| `context.go` | `context.rs` | 上下文管理 | ~500 |
| `functions.go` | `functions.rs` | Dial/StartInstance 等 | ~800 |
| `format.go` | `format.rs` | 格式化工具 | ~200 |
| `proto.go` | `proto.rs` | protobuf 工具 | ~200 |
| `annotations.go` | `annotations.rs` | 注解 | ~100 |

### 7.3 CLI 入口 `xray-cli`

**Go 源码映射**：`main/` → `crates/xray-cli/src/`

| Go 文件 | Rust 文件 | 核心功能 | Rust 实现 | 预估行数 |
|---------|----------|---------|----------|---------|
| `main.go` | `main.rs` | 入口 | `clap` derive | ~200 |
| `run.go` | `run.rs` | run 命令 | `clap` 子命令 | ~800 |
| `version.go` | `version.rs` | 版本信息 | `clap` | ~200 |
| `commands/` | `commands/` | API/version/uuid 等子命令 | `clap` derive | ~1000 |
| `distro/` | `distro/` | 发行版特定 | — | ~300 |

**里程碑**：配置文件可解析，Xray 完整实例可启动，CLI 命令可用

---

## 推荐依赖总表

### A 级 — 直接依赖（crates.io 发布，无需修改）

| crate | 版本 | 用途 | 替代 Go 库 |
|-------|------|------|-----------|
| `tokio` | 1.x | 异步运行时 | goroutine |
| `bytes` | 1.11 | 零拷贝缓冲区 | `[]byte` |
| `prost` | 0.14 | Protobuf | `google.golang.org/protobuf` |
| `tonic` | 0.14 | gRPC | `google.golang.org/grpc` |
| `ring` | 0.17 | 加密引擎(热路径) | `crypto/*` |
| `aes-gcm` | 0.10 | AEAD 流式加密 | `crypto/aes` |
| `chacha20-poly1305` | 0.9 | ChaCha20 流式加密 | `crypto/chacha20` |
| `btls` | 0.1 | TLS + 指纹伪装 | `utls` + `crypto/tls` |
| `wreq` | 0.2 | 浏览器指纹配置 | — |
| `tokio-btls` | 0.1 | async TLS | — |
| `quinn` | 0.11 | QUIC | `quic-go` |
| `h3` | latest | HTTP/3 | `quic-go/http3` |
| `hyper` | 1.10 | HTTP/1.1+2 | `net/http` |
| `tokio-tungstenite` | 0.29 | WebSocket | `gorilla/websocket` |
| `hickory-resolver` | 0.26 | DNS 解析 | `miekg/dns` |
| `shadowsocks` | 1.24 | SS 协议 | `sing-shadowsocks` |
| `boringtun` | 0.7 | WireGuard | `wireguard-go` |
| `tun-rs` | 2.8 | TUN 设备 | `wintun`/`tun` |
| `netstack-smoltcp` | 0.3 | 用户态网络栈 | `gvisor` |
| `socket2` | 0.6 | Socket 控制 | `syscall` |
| `tracing` | 0.1 | 日志追踪 | `log` |
| `serde` | 1 | 序列化 | `json`/`yaml` |
| `thiserror` | 2 | 错误定义 | `errors.New` |
| `anyhow` | 1 | 错误处理 | `fmt.Errorf` |
| `clap` | 4 | CLI | `flag` |
| `boomphf` | 0.6 | MPH 哈希 | 自研 |
| `uuid` | 1 | UUID | `crypto/rand` UUID |
| `reqwest` | 0.12 | HTTP 客户端 | `net/http` Client |

### B 级 — 参考重构（提取并模块化）

| 来源 | 提取内容 | 目标 crate |
|------|---------|-----------|
| clash-rs | VMess AEAD/KDF/编码 | `xray-proxy-vmess` |
| clash-rs | VLESS 出站 | `xray-proxy-vless` |
| clash-rs | Trojan 出站 | `xray-proxy-trojan` |
| clash-rs | Hysteria2 Brutal/Salamander | `xray-transport-hysteria` |
| clash-rs | SOCKS5 | `xray-proxy-socks` |
| shoes | REALITY 完整实现 | `xray-reality` |
| shoes | XTLS Vision | `xray-proxy-vless/encryption/` |
| kcp-tokio | KCP 核心协议 | `xray-transport-kcp` |
| leaf | FakeDNS 实现 | `xray-app-dns/fakedns/` |

### C 级 — 自研（无现成实现）

| 模块 | 预估行数 | 说明 |
|------|---------|------|
| 所有协议入站（服务端） | ~8000 | clash-rs 无入站，必须自研 |
| SplitHTTP | ~3000 | 无现成 Rust 实现 |
| GeoSite 匹配引擎 | ~1500 | boomphf MPH + 规则匹配 |
| 路由引擎 | ~6000 | 条件匹配 + 负载均衡 |
| 调度器 | ~4000 | 协议嗅探 + 连接管理 |

---

## 时间线总览

```
月份    M1     M2     M3     M4     M5     M6     M7     M8     M9
Phase  [0][1       ][2          ][3          ][4          ][5             ][6            ][7   ]
        ↑                                                                                      ↑
        脚手架+基础层                                                                    配置+CLI 入口
```

| Phase | 内容 | 时间 | 累计 | 自研量 | Rust 生态 |
|-------|------|------|------|--------|----------|
| 0 | 项目脚手架 | 1 周 | 1 周 | — | ✅ |
| 1 | 基础类型与抽象 | 3-4 周 | 5 周 | ~6,000 行 | ✅ 全部成熟 |
| 2 | 加密与数据引擎 | 4-5 周 | 10 周 | ~12,000 行 | ✅🟡 |
| 3 | 传输基础设施 | 4-5 周 | 15 周 | ~10,000 行 | ✅ btls 方案 |
| 4 | 应用服务层 | 4-5 周 | 20 周 | ~18,000 行 | ✅🟡 路由自研 |
| 5 | 传输协议层 | 5-7 周 | 27 周 | ~20,000 行 | 🟡 大量参考 |
| 6 | 代理协议层 | 6-8 周 | 35 周 | ~22,000 行 | 🟡 入站自研 |
| 7 | 配置与入口 | 3-4 周 | 39 周 | ~10,000 行 | ✅ serde 成熟 |

**预估总工期**：~39 周（约 10 个月），3-5 人团队

**代码量对比**：

| 指标 | 值 |
|------|------|
| Go 原始代码量（估算） | ~150,000 行 |
| Rust 依赖库节省 | ~69,000 行 → ~13,300 行（75% 节省） |
| Rust 预估自研量 | ~98,000 行 |
| 利用现有 crate 后实际编写量 | ~42,000 行 |

---

## 风险矩阵

| 风险 | 影响 | 概率 | 缓解措施 |
|------|------|------|---------|
| btls 维护中断 | 🟡 中 | 低 | rustls 作为 fallback，牺牲指纹伪装功能 |
| 入站支持自研复杂度 | 🟡 中 | 中 | 严格参考 Go 源码 1:1 移植，保证正确性 |
| quinn BBR v1 性能不足 | 🟢 低 | 低 | TQUIC BBRv3 移植（~1500 行备选） |
| h2 流式延迟 | 🟡 中 | 中 | 监控 p95，必要时优化或替换 |
| KCP 性能不达预期 | 🟢 低 | 低 | kcp-tokio 已验证 |
| REALITY 协议变更 | 🟡 中 | 低 | shoes 活跃维护，及时同步 |
| 团队 Rust 经验不足 | 🟡 中 | 高 | Phase 1-3 简单模块练手 |
| 跨平台 TUN 兼容性 | 🟡 中 | 中 | 分平台逐个实现：Linux → Windows → macOS |

---

## 并行开发策略

### 并行组 A（Phase 1 期间，3 条线）
- `xray-buf`（缓冲区）‖ `xray-common`（基础类型）‖ `xray-features`（trait 定义）

### 并行组 B（Phase 2 期间，4 条线）
- `xray-crypto`（加密）‖ `xray-geodata`（地理数据）‖ `xray-mux`（多路复用）‖ `xray-xudp`

### 并行组 C（Phase 3 期间，3 条线）
- `xray-transport`（传输核心）‖ `xray-tls`（TLS/uTLS）‖ `xray-reality`

### 并行组 D（Phase 4 期间，3 条线）
- `xray-app-dns`（DNS）‖ `xray-app-router`（路由）‖ `xray-app-dispatcher`（调度器）

### 并行组 E（Phase 5 期间，4 条线）
- KCP ‖ Hysteria ‖ SplitHTTP ‖ gRPC+WebSocket+HTTPUpgrade

### 并行组 F（Phase 6 期间，5 条线）
- VLESS ‖ VMess ‖ Shadowsocks ‖ Trojan ‖ 基础代理（SOCKS/HTTP/Blackhole/Freedom）
- TUN + WireGuard 作为独立线并行

---

## 验收标准

### 每个 Phase 完成时

1. ✅ 所有单元测试通过（覆盖率 ≥ 80%）
2. ✅ 与 Go 版本的集成测试对比通过
3. ✅ 性能基准测试不劣于 Go 版本
4. ✅ `cargo clippy --workspace -- -D warnings` 无警告
5. ✅ `cargo fmt --check` 格式统一
6. ✅ `cargo deny check` 无许可证/安全问题

### 项目整体完成标准

1. Go 源码所有模块均有 Rust 对应实现
2. 配置文件 100% 兼容 Go 版本
3. 全部代理协议功能对等（入站+出站）
4. P99 延迟 ≤ Go 版本的 60%
5. 内存占用 ≤ Go 版本的 60%
6. 连接密度 ≥ Go 版本的 2 倍
7. 支持 Linux / Windows / macOS / FreeBSD 四平台

---

## 与原计划的关键差异

| 项目 | 原计划 | 新计划 | 改进原因 |
|------|--------|--------|---------|
| uTLS | 8000 行自研 / FFI-to-Go | btls + wreq-util (~800 行) | 依赖分析发现 btls 已有指纹控制 API |
| REALITY | fork rustls (风险极高) | 参考 shoes + btls | shoes 活跃维护，btls 比 fork rustls 更安全 |
| TLS 后端 | rustls（无指纹支持） | btls（BoringSSL 绑定） | rustls 明确拒绝指纹功能 |
| Shadowsocks | 参考实现 | A 级直接依赖 crate | shadowsocks crate 1.24 完整覆盖 |
| WireGuard | 参考 boringtun | A 级直接依赖 | boringtun v0.7 生产验证 |
| KCP | 完全自研 | 参考 kcp-tokio | 节省 ~4500 行 |
| Hysteria2 | 完全自研 | 参考 clash-rs | 节省 ~7000 行 |
| gVisor | 自研/替代 | netstack-smoltcp | 已被多项目验证 |
| 入站支持 | 未明确 | 明确为自研重点 | Xray-core 是全功能代理，入站是核心需求 |
| 模块映射 | 按功能分组 | 按源码 1:1 映射 | 完全复刻 Go 代码组织 |

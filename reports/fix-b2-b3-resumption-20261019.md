# B2-B3 修复报告：TLS 1.3 会话复用失败根因与修复 + TCP_RCVBUF 回退

日期：2026-10-19 ｜ 分派：B2B3Dig ｜ 分支工作树（未 commit）

---

## VERDICT

DONE

## 任务 1：TCP_RCVBUF_DEFAULT 16MB → 4MB 回退

`crates/xray-transport/src/sockopt/mod.rs:409` 常量 `16 * 1024 * 1024` → `4 * 1024 * 1024`（对 fb789348 中该常量变更的回退，其余内容保留）。同步 11 处注释/断言消息中的 16MB 文本：

- `sockopt/mod.rs`：常量 doc（sysctl 提示改 8388608/8MB）、`SocketOptions::receive_buffer_size` 字段 doc、`apply_outbound_socket_options` doc 与分支注释、`apply_inbound_socket_options` 注释、4 个测试的注释与断言消息
- `dialer.rs:274`：receiveBufferSize 解析注释

**验证**：`cargo test -p xray-transport --all-targets` → **529 passed; 0 failed**。

## 任务 2：TLS 1.3 会话复用失败（B2）——根因与修复

### 结论（一句话）

**PM 头号假设（指纹 connector 扩展重排破坏 PSK/binder）被证伪**；真根因是**写入时机**：客户端在握手完成点取 `SSL_get_session()` 存 cache，此时 session 是**无 ticket 的 handshake session**，BoringSSL 将「TLS 1.3 + 空 ticket」判为 `kNotResumable`，`should_offer_psk` 直接拒绝 → ClientHello 从不发 PSK 扩展 → 服务端无从复用，`session_reused=false` 稳定 100% 复现（47/47 命中全 false）。

### 假设证伪证据（a/b/c 步）

**a) PSK 扩展不受指纹模板影响**——btls fork 的 `ssl_setup_extension_order`（`btls-sys/patches/boringssl.patch:488-547`）只重排 `kExtensions` 表内扩展，而 BoringSSL 的 `kExtensions` 表**不含 pre_shared_key**（`ssl/extensions.cc:3527-3727`，28 个条目逐一核对无 TLSEXT_TYPE_pre_shared_key）。PSK 扩展由 `ssl_add_clienthello_tlsext` 在扩展循环+GREASE+padding 之后**最后追加**（`extensions.cc:3873-3882`："The PSK extension must be last. It is never compressed."）。binder 也在整个消息构建完成后计算（`handshake_client.cc:236-246`），重排/GREASE/key_share 重写全部发生在 binder 计算之前，不可能破坏 PSK/binder。

**b) ext_perm 列表伪号的真实影响（记录非修复）**——`chrome_131/133_ext_perm` 确有伪号（`0x0039` 注释 pre_shared_key 真实号是 0x0029；`0x0038` 注释 supported_groups 真实号 0x000a；`0xfe0d` 标注 application_settings 实为 ECH，ALPS 真实号 0x4469）。按 patch 语义「未知 id 跳过、未列出扩展按原序追加+随机洗」，这些伪号只导致部分扩展顺序偏离 Chrome 模板（伪装保真度瑕疵），与 resumption 无关。**扩展号属于指纹范畴（红线禁碰），未动**。

**c) session 类型判定链**（无指纹路径同样失败，证明与指纹无关）：
- `ssl/extensions.cc:1858-1880` `should_offer_psk`：要求 `ssl_session_get_type == kPreSharedKey`
- `ssl/ssl_session.cc:444-462` `ssl_session_get_type`：TLS 1.3 分支 `session->ticket.empty() ? kNotResumable : kPreSharedKey`
- 握手完成点 `SSL_get_session()` 返回 `established_session`（`handshake_client.cc:1788-1798` dup 自 `new_session`，**NST 尚未到达**，ticket 为空）
- 带 ticket 的 resumption session 只在 NST 到达时产生：`tls13_client.cc:1180-1241` `tls13_create_session_with_ticket`（`ticket_age_add_valid = true; not_resumable = false;`），并经 `SSL_CTX_sess_set_new_cb` 回调交付（`tls13_client.cc:1151-1156`）

### 修复

对齐 Go `tls.Config.ClientSessionCache`（Go 的 key 本就是 host:port、不分指纹）：

1. `crates/xray-tls/src/btls_client.rs:45-65` 新增 `install_session_cache_hook()`：`set_session_cache_mode(CLIENT)`（new_cb 触发前提，tls13_client.cc:1151 位测试；BoringSSL 客户端内部缓存为 no-op 无副作用）+ `set_new_session_callback`（NST 到达 → 取 SNI server_name → `store_session`）。全部 8 个 connector builder（chrome133/131、firefox148/120、safari、edge、360、qq）安装。
2. `crates/xray-tls/src/btls_client.rs` `connect_with_alpn`：删除握手完成点的 `store_session` 调用（错误时机，存的是无票 session）；保留 lookup + `SSL_set_session`。
3. `crates/xray-tls/src/tls_session_cache.rs`：cache key `(String, Fingerprint)` → `String`（server_name-only）；`store_session` 改签名接受 owned `SslSession`（回调入口，无需 enable flag——CTX 级回调拿不到 per-connection 配置，读取侧 `lookup_for_resume` 已按 `enableSessionResumption` 门控，false 时只存不读行为正确）；模块头文档重写根因史。

### 验证（e 步，端到端）

harness（`D:/tmp/plat-b-verify/harness.py`，本地回环 wss，3 轮 × 15 并发 SOCKS burst = 45 dials，服务端为本仓 rustls + ticketer）：

```
total btls uTLS 握手开始: 48
cache hit (session resume: 命中 cache): 47
session_reused=true (server confirmed resume): 47
rounds: R1=6.450s R2=7.375s R3=10.378s
```

**`session_reused=true` 47 次**（修复前 0 次）——BoringSSL 客户端 `SSL_session_reused()` 置位要求服务端真实接受 PSK（rustls 解 ticket + 验 binder 成功才会走 resumption 路径），47/45 dials 即首轮 full handshake 后全部 dial 复用成功（多出的计数来自 ws 重连型握手，同样复用）。R1→R3 wall time 受 freedom outbound 拨公网目的地干扰，不作为握手耗时指标；单 dial 握手路径证据以 reuse 计数为准。

## 产物

- `D:/tmp/wsplat/xray_r3.exe` md5 = `417b1daa82961667006fe4374f377e15`（含任务1回退 + 任务2修复，release + `-C target-cpu=x86-64` non-native 构建）
- 同二进制已复制 `D:/tmp/wsplat/xray_b1b2.exe` 供 harness 复跑（md5 一致）

## 质量门

- `cargo test -p xray-tls --all-targets`：**194 passed; 0 failed; 3 ignored**（ignored 为既有真实服务器测试，非新增；指纹测试全过）
- `cargo test -p xray-transport --all-targets`：**529 passed; 0 failed**
- `cargo +stable clippy -p xray-tls -p xray-transport --all-targets -- -D warnings`：**通过**（余下 warning 全部为 vendor rustls 既有 + clippy.toml 自身配置警告，与本次改动无关）
- `cargo +stable fmt -- --check`：**无 "Diff in" 真违规**（本地 CRLF checkout 的 "Incorrect newline style" 为已知噪音，CI stable/Linux checkout 不存在）
- `cargo build --release -p xray-cli`：Finished release profile

## 红线核查

未触碰：用户配置/mux/服务端内核 CC/tests/.github/.gitignore/docs\/refs/protos/dist/vendor（btls fork 仅只读引用，未改）/xray-transport-tcp\/register.rs/指纹（ext_perm 伪号属指纹范畴，记录未改）/.cargo\/config.toml。未 commit。

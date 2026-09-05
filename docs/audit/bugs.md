# 功能 Bug + 静默失败审计报告（bugs.md）

- **审计人**: BugAudit（功能 bug / 静默失败维度）
- **日期**: 2026-09-06
- **对象**: Xray-core-rust（对照 Go 基准 D:/Project/Xray-core, Xray v26.7.28）
- **方法**: 高信号模式全量 grep（`let _ =` / `.ok()` / `unwrap_or(` / `read_exact` / `vec![0u8; n as usize]` / `ErrorKind` 空匹配）→ 密度文件人工精读 → 与 Go 基准逐点对照。只读代码,零改动。

## 发现统计

| 严重度 | 数量 |
|---|---|
| P0（可致崩溃/挂死/安全） | 1 |
| P1（明确缺陷） | 1 |
| P2（改进机会） | 2 |

---

## 发现列表

### [P0] TUIC H3 帧负载长度取自网络且无上限校验 → 单帧头即可触发进程级 OOM abort

- **位置**: `crates/xray-proxy-tuic/src/h3.rs:182-190`（调用方 `recv_settings` h3.rs:203-208; 长度来源 `read_frame_header` h3.rs:163-179 → `decode_varint` h3.rs:324-347）
- **证据**:
  ```rust
  // h3.rs:163-179：QUIC varint 上限 2^62，直接作为 len 返回
  pub async fn read_frame_header(recv: &mut quinn::RecvStream) -> Result<(u8, u64)> {
      ...
      let (len, _bytes_read) = decode_varint(first_byte, &mut len_buf[1..], recv).await?;
      Ok((frame_type, len))
  }
  // h3.rs:185-189：无任何上限检查，直接按网络值分配
  pub async fn read_frame_payload(recv: &mut quinn::RecvStream, len: u64) -> Result<Vec<u8>> {
      let mut buf = vec![0u8; len as usize];
      recv.read_exact(&mut buf).await.map_err(TuicError::QuinnReadExact)?;
  ```
  对照：hysteria 同类解析有界（`xray-proxy-hysteria/src/protocol.rs:18-27` `MAX_ADDRESS_LENGTH=2048` 等三常量 + 逐项检查）；finalmask/xmc 也有界（`protocol.rs:97-99` `BYTES_MAX` 检查）；TUIC 是全库唯一未设界者。
- **影响**: `vec![0u8; len as usize]` 中 `len` 可达 2^62，分配在读取发生**之前**；Rust 堆分配失败走 `handle_alloc_error` → **abort 整个进程**（非 unwind），所有在跑连接全部死亡。对端只需 8 字节帧头，无需发送任何负载。
- **触发条件与复现思路**: TUIC 控制流 SETTINGS 读取发生在认证**之前**（`recv_settings` 先于 AUTHENTICATE），未认证 QUIC 对端即可触发。复现：用 quinn 客户端连接 Rust TUIC server（自签证书即可），打开 bi stream，写 `[SETTINGS 类型字节][0xC0 前缀 varint, len≈2^40]` 后挂起——server 在 `recv_settings` 内立即尝试 1TB 分配 → abort。反向同理（恶意 server 打 client）。
- **修复建议**: `read_frame_payload` 入口加硬上限（如 `len > 1<<20` 返回 `TuicError::FrameTooLarge`，或按帧类型分别限幅），所有 `read_frame_header` 调用点逐一设界。

### [P1] Trojan 客户端 UDP 分帧读侧吞掉致命解析错误 → rbuf 无界增长直至 OOM，会话永不终止

- **位置**: `crates/xray-proxy-trojan/src/dispatcher.rs:223-245`（对照同 crate 入站侧正确实现 `server.rs:522-536`）
- **证据**:
  ```rust
  // dispatcher.rs:223-231（outbound TrojanUdpFramedConn::poll_read）
  if !self.rbuf.is_empty() {
      let parsed = crate::protocol::parse_udp_packet(&self.rbuf);
      if let Ok((_addr, _port, payload, consumed)) = parsed {
          ...
      }
      // ← parse 出 Err 时无 else 分支，直接落入下方 inner 读循环
  }
  let mut tmp = [0u8; 8192];
  ... self.rbuf.extend_from_slice(filled);   // 每轮再追加 8KB，永不清理、永不报错
  ```
  对照入站侧对同一协议帧的正确处理（`server.rs:532-536`）：`Err(e) => { warn!(...); fatal = true; break; }`。Go 基准 `proxy/trojan/client.go` PacketReader 解析失败同样以错误终止会话。
- **影响**: 一旦 rbuf 前端落入永久非法状态（如首个 ATYP 字节非法），每轮 `poll_read` 都解析失败→追加→再解析，`rbuf` 以 ~8KB/轮 无界增长；恶意/被入侵的 Trojan server 可持续推送垃圾字节直至客户端进程 OOM。同时错误被吞，日志无任何痕迹（错误传播链断裂 + 静默失败双重问题）。
- **触发条件与复现思路**: Rust 作为 Trojan 客户端，握手完成后 server 返回以非法 ATYP（如 `0x09`）开头的持续字节流即可。复现：duplex 对端先回合法响应头，随后灌 `vec![0x09; 1MB]`，观察客户端内存线性上涨且连接不终止。
- **修复建议**: 与入站侧对齐——`Err(e)` 分支 `return Poll::Ready(Err(io::Error::new(InvalidData, e)))` 终止会话（可直接复用 `parse_udp_packet_stream` 的 Ok(None)/Err 区分语义）。

### [P2] Policy level-1 的 ConnectionIdle 被无条件强制 600s，覆盖用户显式配置，偏离 Go 配置优先语义

- **位置**: `crates/xray-app-policy/src/manager.rs:55-62`
- **证据**:
  ```rust
  // manager.rs:57-62：先取用户配置，再无条件覆盖 level==1
  fn policy_for_level(&self, level: u32) -> Policy {
      let mut p = self.levels.get(&level).cloned().unwrap_or_default();
      if level == 1 {
          p.timeout.connection_idle = std::time::Duration::from_secs(600);
      }
      p
  }
  ```
  Go 基准配置驱动管理器 `app/policy/manager.go:35-39`：**配置优先，无 level-1 特判**
  ```go
  func (m *Instance) ForLevel(level uint32) policy.Session {
      if p, ok := m.levels[level]; ok {
          return p.ToCorePolicy()   // 用户配置原样生效
      }
      return policy.SessionDefault()
  }
  ```
  600s 特判仅存在于非配置路径 `features/policy/default.go:17-21`（`DefaultManager.ForLevel`，该实现不承载用户配置）。
- **影响**: ① 用户配置 `policy.levels["1"].timeouts.connectionIdle`（如 7200s）在 Rust 端被静默覆盖为 600s；② 用户未配置 policy 时，level-1 连接空闲超时 Rust=600s vs Go=300s，空闲连接存活行为翻倍，行为对齐破坏。
- **触发条件与复现思路**: 配置 `"policy": {"levels": {"1": {"timeouts": {"connectionIdle": 7200}}}}`，用 level-1 用户建连后静置，观察 600s 即被断（Go 端 7200s 才断）。
- **修复建议**: 命中 `self.levels` 时直接返回用户配置；仅在 miss 分支且 level==1 时应用 600s 特判（与 Go `app/policy` 完全同构）。

### [P2] plain HTTP 代理上行桥静默吞掉读写错误，错误上下文丢失（Ok(0)/Err 同路无日志）

- **位置**: `crates/xray-core/src/inbound.rs:488-505`（`handle_plain_http` 上行 copy 循环）
- **证据**:
  ```rust
  // inbound.rs:489 请求头写入结果直接丢弃
  let _ = up_w.write_multi_buffer(mb).await;
  ...
  // inbound.rs:492-501 读错误与干净 EOF 同路 break，无区分无日志
  match client_read.read(&mut buf).await {
      Ok(0) | Err(_) => break,
      Ok(n) => {
          ...
          if up_w.write_multi_buffer(mb).await.is_err() {
              break;                       // 写错误同样静默
          }
      }
  }
  ```
  对照：同文件体系 `xray-transport/src/bridge.rs:117-122` 的桥接循环对 `Err(e)` 显式 `return Err(e)` 保留错误；Go 基准 `proxy/http/server.go handlePlainHTTP` 的 transfer 错误经 log.Record 可观测。
- **影响**: 上行目标写失败 / 客户端读异常被伪装成正常 EOF，排障时「为什么 plain HTTP 代理没有响应」在日志层零痕迹（功能结果正确——`dn_w.shutdown()` 兜底解除阻塞——但可观测性缺口符合本项目 silent-failure 前科画像）。
- **触发条件与复现思路**: 配置 plain HTTP 入站，向后端目标发起请求并在 target 侧 RST；客户端挂起感知 EOF，日志无任何上行错误记录。
- **修复建议**: `Err(e)` 与写失败分支加 `tracing::debug!/warn!`（带 dest 与错误体），保持行为不变仅补错误上下文；`let _ =` 请求头写至少留 debug 级日志。

---

## 已抽查对齐项（≥5 个高风险点，均与 Go 基准核对无缺陷）

| # | 抽查点 | Rust 位置 | Go 对照 | 结论 |
|---|---|---|---|---|
| 1 | vmess 请求头解析（version/option/padding/security、FNV1a、命令枚举、SessionHistory 反重放三元组） | `xray-proxy-vmess/src/encoding/server.rs:157-277` | `proxy/vmess/encoding/server.go:186-244`（Go 同样不校验 version 字节；UNKNOWN/AUTO 拒绝路径、padding 高 4bit、command 枚举一致） | ✅ 对齐。Auto 在 Go server 侧拒绝、Rust 侧按 CPU 重映射接收——permissive 方向差异，非缺陷 |
| 2 | vmess body chunk 尺寸解析（Plain/SHAKE128/AuthLen 三解析器、nonce 递增、chunk 边界 EOF 语义） | `xray-proxy-vmess/src/encoding/body_chunk.rs` + `inbound/server.rs`（生产路径逐 chunk 流式，非一次性 Vec） | `proxy/vmess/encoding/server.go DecodeRequestBody`（AES-GCM/ChaCha-only switch，none/legacy 均拒——Rust 相同） | ✅ 对齐；chunk 尺寸 u16 上界 64KB，无分配炸弹 |
| 3 | mux 帧元数据上限与 v26 扩展（GlobalID/Keep-UDP target/PortThenAddress） | `xray-mux/src/frame.rs:35,470-478,519-548` | `common/mux/frame.go:131-133`（metaLen>512 拒）、`WriteTo`（GlobalID 仅 UDP+New 写、source/local 互斥写） | ✅ 对齐（worker.rs:391/client.rs:549 均用 512 常量）。注记：`reader.rs:117` 硬编码 1024 门，但随后 `read_from_bytes` 内层 512 检查兜底，实际行为仍拒 >512，仅属风格性死 slack，不构成缺陷 |
| 4 | KCP segment 解析（conv/cmd/opt 4B 头、Data 14B 变长体边界、ACK count≤128 上限、CmdOnly 12B） | `xray-transport-kcp/src/segment.rs:431-453,222-240` | `transport/internet/kcp/segment.go`（insufficient data / count too large 同语义） | ✅ 对齐，长度校验完整（`body.len() < 14 + data_len` 拒绝） |
| 5 | socks5 请求/地址解析（ATYP switch、域名 1B 长度、v4/v6 定长、UDP ASSOCIATE 回包） | `xray-proxy-socks/src/server.rs:224-279,424-452`; `protocol.rs:183-235` | `proxy/socks/` addrParser（同 ATYP 值域、同定长） | ✅ 对齐，截断输入返回 InvalidFrame |
| 6 | Trojan UDP 帧（`[addr][2B BE len][CRLF][payload]`、maxLength=8192、流式 Ok(None)/Err 区分） | `xray-proxy-trojan/src/protocol.rs:243-320`; `server.rs:522-553` | `proxy/trojan/protocol.go PacketWriter/PacketReader` | ✅ 入站侧对齐（outbound 读侧缺陷见 P1） |
| 7 | hysteria TCP 请求/响应帧与 varint（三常量限幅 2048/2048/4096） | `xray-proxy-hysteria/src/protocol.rs:18-27,88-171` | Go `MaxAddressLength/MaxMessageLength/MaxPaddingLength` 同值 | ✅ 对齐，无分配炸弹 |
| 8 | Policy 默认值（handshake 60s / idle 300s / uplink 1s / downlink 1s） | `xray-features/src/policy.rs:17-35` | `features/policy/policy.go:127-134` 逐值一致 | ✅ 数值对齐（特判位置问题见 P2） |
| 9 | DNS 消息解析边界（<12B 拒、label≤63、压缩指针拒、>127 label 拒、QNAME 截断拒） | `xray-proxy-dns/src/dns_message.rs:88-181` | RFC 1035 语义（Go dns 代理同规则族） | ✅ 边界完整 |

**其它排查记录**（防重复排查）：
1. `xray-app-dispatcher/src/default.rs:1023` `let _ = fut.await` 的 future 类型为 `PinFuture<()>`（unit），并非吞 Result，非缺陷；
2. `xray-buf` 池化缓冲假 EOF 前科防线完好——现存全部 `alloc()` 调用点（`xray-core/src/inbound.rs:490-491`、`xray-transport/src/bridge.rs:114-115`）均先 `resize(size,0)`；
3. `ss2022` salt 长度派生自本端 cipher 常量而非网络（`xray-proxy-ss/src/ss2022/inbound.rs:359`），无受控分配；
4. `finalmask/xmc` varint→分配有 `PACKET_DATA_MAX`/`BYTES_MAX` 双重设界；
5. TCP DNS inbound `read_exact` 无显式超时，但由 dispatcher 桥 idle-timeout 兜底，不构成挂死；
6. `reverse/relay.rs:59` `TcpStream::connect` 无显式超时（OS 默认 SYN 重试有限时长），与 Go `net.Dialer` 默认行为同级，未列为缺陷。

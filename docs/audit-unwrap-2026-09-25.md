# 生产代码 unwrap()/expect() 系统性分类审计（2026-09-25）

## 统计

| 类别 | 数量 | 说明 |
|---|---|---|
| ①infallible | 203 | 构造后不变量 / 标准库恒成功 / 毒锁 panic 惯例 / 对齐 Go panic 语义的 API 契约 |
| ②有前置守卫 | 90 | 上方 if/match guard/读循环/配置层校验已保证不可达 panic |
| ③远程可达真风险 | 2（均已修复） | 恶意/并发输入可触发 panic，已改显式错误 |
| **总计** | **295** | 生产代码（非测试）`.unwrap()`/`.expect(` 全量 |

### 枚举口径

全仓 `.rs` 文件共匹配 `.unwrap()/.expect(` 1371 处，剔除以下后得生产代码 295 处：
- `crates/*/tests/` 集成测试目录（1004 处）
- 外部测试模块文件（`#[cfg(test)] mod x;` 声明指向的 `x.rs`，如 `xray-tls/src/stress_tests.rs` 15 处）
- 文件内嵌测试模块（`#[cfg(test)]` 复合形式 + 裸 `mod tests`，如 `xray-proxy-wireguard/src/users.rs` 21 处、`xray-proxy-tun/src/device.rs`、`xray-transport/src/filelocker.rs`、`xray-transport-kcp` 内嵌 tests）
- 整行注释

> 任务口径 368 = 本表 295 + 上述内嵌测试模块约 73 处。测试代码不属生产代码，不计入本表。

### 改动清单（③类，2 处）

1. **`crates/xray-mux/src/frame.rs:218`** `write_target_to_vec`
   - 修复前：`TargetNetwork::from_network(target.network()).expect("target network must be TCP or UDP for mux frames")`
   - 风险：`Network` 枚举含 `Unix` 变体（xray-common/src/network.rs:9-12），Unix 入站目标经 mux 转发时 `from_network` 返回 `None` → 远程可达 panic。
   - Go 基线：Go mux 写帧直接编码 network string（frame.go 无 panic 路径）；对端 parse 失败报错而非崩溃。
   - 修复后：`.ok_or_else(|| MuxError::Io(format!("unsupported mux target network: {:?}", ...)))?` 显式拒绝（+5/-2 行）。

2. **`crates/xray-proxy-vless/src/encryption/mod.rs:1261`** `handshake_zero_rtt`
   - 修复前：`store.sessions.get_mut(&ticket).expect("session checked above")`
   - 风险：TOCTOU——:1233 的 hit 检查（短暂持锁读 `pfs_key` 后释放）与 :1257 重新加锁之间存在无锁间隙，`SessionStore` 过期清理（mod.rs:720 `sessions.remove`）可并发移除条目 → 有效 ticket 的并发 0-RTT 连接 panic。
   - Go 基线：Go server.go:210-222 用 sync.Map Load，miss → 写噪声 + 返回错误，无 panic 路径。
   - 修复后：`let Some(session) = ... else { return Err(VlessError::Other("expired ticket".into())) }`，错误语义与 miss 路径（:1247）一致（+6/-4 行）。

## 逐处分类表

| # | 位置 | 类别 | 代码 | 理由/证据 |
|---|---|---|---|---|
| 1 | `xray-app-dispatcher/src/default.rs:1723` | ①infallible | `*self.policy.write().expect("DialBridge policy lock poisoned") = Some(p);` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 2 | `xray-app-dispatcher/src/default.rs:1730` | ①infallible | `.expect("DialBridge policy lock poisoned")` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 3 | `xray-app-dispatcher/src/default.rs:1747` | ①infallible | `let mut guard = self.proxy_chain.write().expect("DialBridge proxy_chain lock poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 4 | `xray-app-dispatcher/src/default.rs:1755` | ①infallible | `self.proxy_chain.read().expect("DialBridge proxy_chain lock poisoned").chain_tag.is_some()` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 5 | `xray-app-dispatcher/src/default.rs:1760` | ①infallible | `let guard = self.proxy_chain.read().expect("DialBridge proxy_chain lock poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 6 | `xray-app-dispatcher/src/default.rs:1947` | ①infallible | `*self.default.write().unwrap() = Some(handler);` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 7 | `xray-app-dispatcher/src/default.rs:1960` | ①infallible | `default: std::sync::RwLock::new(self.default.read().unwrap().clone()),` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 8 | `xray-app-dispatcher/src/default.rs:1961` | ①infallible | `tagged: std::sync::RwLock::new(self.tagged.read().unwrap().clone()),` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 9 | `xray-app-dispatcher/src/default.rs:1967` | ①infallible | `self.tagged.write().unwrap().insert(tag.to_string(), handler);` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 10 | `xray-app-dispatcher/src/default.rs:1974` | ①infallible | `let Some(_old) = self.tagged.write().unwrap().remove(tag) else {` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 11 | `xray-app-dispatcher/src/default.rs:1980` | ①infallible | `.unwrap()` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 12 | `xray-app-dispatcher/src/default.rs:1984` | ①infallible | `*self.default.write().unwrap() = None;` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 13 | `xray-app-dispatcher/src/default.rs:1991` | ①infallible | `self.tagged.read().unwrap().keys().cloned().collect()` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 14 | `xray-app-dispatcher/src/default.rs:2009` | ①infallible | `self.tagged.read().unwrap().get(tag).cloned()` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 15 | `xray-app-dispatcher/src/default.rs:2013` | ①infallible | `self.default.read().unwrap().clone()` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 16 | `xray-app-dispatcher/src/udp_session.rs:94` | ②有前置守卫 | `let inner = self.inner.as_mut().expect("established above");` | 上方 if inner.is_none() { establish() } 守卫(84-87)后 as_mut 必 Some |
| 17 | `xray-app-dns/src/fakedns/mod.rs:85` | ①infallible | `ip_range: "0.0.0.0/32".parse().unwrap(),` | 字面常量解析（IP/端口/header/正则），恒成功 |
| 18 | `xray-app-dns/src/fakedns/mod.rs:127` | ①infallible | `std::num::NonZeroUsize::new(1).unwrap()` | NonZeroUsize::new(1) 常量恒 Some |
| 19 | `xray-app-dns/src/nameserver/dot.rs:219` | ②有前置守卫 | `match self.try_query(conn_guard.as_mut().unwrap(), &len_be, &payload, req_id, record_type).await {` | 上方 if conn_guard.is_none() { connect } 守卫(214-215) |
| 20 | `xray-app-dns/src/nameserver/dot.rs:226` | ②有前置守卫 | `self.try_query(conn_guard.as_mut().unwrap(), &len_be, &payload, req_id, record_type).await` | 重连后刚赋值 Some(224-225) |
| 21 | `xray-app-dns/src/nameserver/tcp.rs:200` | ②有前置守卫 | `match self.try_query(conn_guard.as_mut().unwrap(), &len_be, &payload, req_id, record_type).await {` | 上方 if conn_guard.is_none() { connect } 守卫(195-199) |
| 22 | `xray-app-dns/src/nameserver/tcp.rs:207` | ②有前置守卫 | `self.try_query(conn_guard.as_mut().unwrap(), &len_be, &payload, req_id, record_type).await` | 重连后刚赋值 Some(205-206) |
| 23 | `xray-app-geodata/src/swap.rs:87` | ②有前置守卫 | `Err(errs.into_iter().next().unwrap())` | errs.len()==1 分支保证非空(86-88) |
| 24 | `xray-app-geodata/src/swap.rs:89` | ②有前置守卫 | `let first = errs.into_iter().next().unwrap();` | else 分支 len>1 保证非空(90) |
| 25 | `xray-app-log/src/mask.rs:67` | ①infallible | `LazyLock::new(\|\| Regex::new(r"(\d{1,3}\.){3}\d{1,3}").unwrap());` | 编译期常量正则 |
| 26 | `xray-app-log/src/mask.rs:70` | ①infallible | `LazyLock::new(\|\| Regex::new(r"(?:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}){2,7}").unwrap());` | 编译期常量正则 |
| 27 | `xray-app-observatory/src/config.rs:70` | ②有前置守卫 | `p.health_ping.as_ref().unwrap(),` | 同表达式上方 is_some() 分支守卫(69) |
| 28 | `xray-app-proxyman/src/outbound/handler.rs:418` | ②有前置守卫 | `let handler = manager.get_handler(&tag).unwrap();` | match arm guard get_handler().is_some()(417) |
| 29 | `xray-app-router/src/strategy_leastload.rs:342` | ①infallible | `let ring = self.hash_ring.as_ref().expect("hash_ring set for ConsistentHashing");` | 构造后不变量：ConsistentHashing 构建时 set hash_ring |
| 30 | `xray-app-router/src/strategy_leastping.rs:59` | ②有前置守卫 | `if best_rtt.is_none() \|\| rtt < best_rtt.unwrap() {` | 短路求值：is_none()\|\|…，右侧仅在 Some 时求值 |
| 31 | `xray-app-router/src/strategy_random.rs:36` | ②有前置守卫 | `Ok(outs.choose(&mut rng).expect("non-empty checked").clone())` | 上方 is_empty() 早返回 Err(33-34) |
| 32 | `xray-app-router/src/weight.rs:105` | ①infallible | `Regex::new(r"(\d+(\.\d+)?)").expect("number regex compiles")` | 编译期常量正则 |
| 33 | `xray-buf/src/alloc.rs:132` | ②有前置守卫 | `let mut buf = cache[tier].pop().expect("已检查 len > 0");` | 上方 if cache[tier].len()>0 守卫(131) |
| 34 | `xray-buf/src/alloc.rs:148` | ②有前置守卫 | `let mut buf = shard.tiers[tier].pop().expect("已检查 len > 0");` | 上方 if shard.tiers[tier].len()>0 守卫(147) |
| 35 | `xray-buf/src/alloc.rs:179` | ①infallible | `cache[tier].push(buf.take().expect("buf 只被 take 一次"));` | release 所有权语义：buf 只被 take 一次 |
| 36 | `xray-buf/src/alloc.rs:185` | ②有前置守卫 | `let buf = buf.expect("is_none 已处理");` | 上方 if buf.is_none() 早返回(183-184) |
| 37 | `xray-buf/src/pipe.rs:182` | ①infallible | `let mut inner = self.0.inner.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 38 | `xray-buf/src/pipe.rs:198` | ①infallible | `let inner = self.0.inner.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 39 | `xray-buf/src/pipe.rs:210` | ①infallible | `let mut slot = self.0.err_slot.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 40 | `xray-buf/src/pipe.rs:251` | ①infallible | `let mut inner = shared.inner.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 41 | `xray-buf/src/pipe.rs:268` | ①infallible | `let mut slot = self.0.err_slot.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 42 | `xray-buf/src/pipe.rs:274` | ①infallible | `self.0.err_slot.lock().unwrap().take()` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 43 | `xray-buf/src/pipe.rs:279` | ①infallible | `self.0.inner.lock().unwrap().data.len()` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 44 | `xray-buf/src/pipe.rs:328` | ①infallible | `let mut inner = self.0.inner.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 45 | `xray-buf/src/pipe.rs:340` | ①infallible | `let m = mb_slot.take().expect("mb consumed twice");` | 消费语义不变量：mb slot 只消费一次 |
| 46 | `xray-buf/src/pipe.rs:379` | ①infallible | `let mut inner = self.0.inner.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 47 | `xray-buf/src/pipe.rs:399` | ①infallible | `self.0.inner.lock().unwrap().data.len()` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 48 | `xray-cli/src/commands/tool.rs:367` | ②有前置守卫 | `let out = args.out.as_deref().expect("out/debug checked above");` | 上方 early return 守卫(365-366) |
| 49 | `xray-cli/src/commands/tool.rs:825` | ①infallible | `out.push_str(std::str::from_utf8(chunk).unwrap());` | base64 输出必 ASCII，from_utf8 恒成功 |
| 50 | `xray-common/src/retry.rs:96` | ①infallible | `Err(last_err.expect("max_attempts > 0 guarantees at least one error"))` | API 契约不变量 max_attempts>0，违反=调用方 bug |
| 51 | `xray-common/src/signal/mod.rs:387` | ①infallible | `.expect("semaphore acquire should not fail unless closed");` | semaphore 全仓无 .close() 调用，acquire_owned Err 不可达 |
| 52 | `xray-common/src/task/mod.rs:165` | ②有前置守卫 | `Err(slot.take().expect("checked"))` | 上方 slot.is_some() 检查(164) |
| 53 | `xray-common/src/task/mod.rs:222` | ②有前置守卫 | `Err(slot.take().expect("checked"))` | 上方 slot.is_some() 检查(221) |
| 54 | `xray-common/src/uuid/mod.rs:75` | ①infallible | `let mut u: [u8; 16] = sum[..16].try_into().expect("sha1 sum >= 16");` | SHA1 输出 20B，[..16] 定长切片 try_into 恒成功 |
| 55 | `xray-conf/src/built.rs:364` | ②有前置守卫 | `let obj = ss.as_object_mut().expect("guarded to object");` | 上方 match 保证 is_object(361-363) |
| 56 | `xray-core/src/context.rs:64` | ①infallible | `current().expect("Instance is not in task-local context; wrap the call with xray_core::context::scope")` | 设计性 panic API（must_current，文档声明；对齐 Go MustXxx 惯例） |
| 57 | `xray-core/src/instance.rs:316` | ②有前置守卫 | `Err(errors.into_iter().next().expect("non-empty errors"))` | 上方 errors.is_empty() 早返回 Ok(310-311) |
| 58 | `xray-core/src/outbound.rs:1245` | ②有前置守卫 | `let user = users.first().unwrap();` | 上方 users.len()!=1 早返回 Err(1243-1244) |
| 59 | `xray-core/src/outbound.rs:2698` | ②有前置守卫 | `std::time::Duration::from_secs(v.as_u64().unwrap())` | match guard v.as_u64().is_some()(2697) |
| 60 | `xray-crypto/src/authenticator.rs:44` | ①infallible | `let mut current = state.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 61 | `xray-geodata/src/weak_cache.rs:62` | ①infallible | `let mut guard = self.inner.lock().expect("WeakCacheMap poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 62 | `xray-geodata/src/weak_cache.rs:76` | ①infallible | `let mut guard = self.inner.lock().expect("WeakCacheMap poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 63 | `xray-geodata/src/weak_cache.rs:103` | ①infallible | `self.inner.lock().expect("WeakCacheMap poisoned").len()` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 64 | `xray-geodata/src/weak_cache.rs:117` | ①infallible | `let mut guard = self.inner.lock().expect("WeakCacheMap poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 65 | `xray-geodata/src/matcher/domain.rs:517` | ①infallible | `*self.rules.lock().unwrap() = rules;` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 66 | `xray-geodata/src/matcher/domain.rs:518` | ①infallible | `*self.state.write().unwrap() = Some(matcher);` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 67 | `xray-geodata/src/matcher/domain.rs:524` | ①infallible | `*self.state.write().unwrap() = Some(matcher);` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 68 | `xray-geodata/src/matcher/domain.rs:536` | ①infallible | `let guard = self.state.read().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 69 | `xray-geodata/src/matcher/domain.rs:544` | ①infallible | `let guard = self.state.read().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 70 | `xray-geodata/src/matcher/domain.rs:554` | ①infallible | `let has_state = self.state.read().unwrap().is_some();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 71 | `xray-geodata/src/matcher/domain.rs:589` | ①infallible | `let mut matchers = self.matchers.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 72 | `xray-geodata/src/matcher/domain.rs:596` | ①infallible | `let guard = self.matchers.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 73 | `xray-geodata/src/matcher/domain.rs:611` | ①infallible | `self.matchers.lock().unwrap().len()` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 74 | `xray-geodata/src/matcher/domain.rs:630` | ①infallible | `let g = self.matchers.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 75 | `xray-geodata/src/matcher/domain.rs:662` | ①infallible | `let guard = self.registry.matchers.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 76 | `xray-geodata/src/matcher/domain.rs:668` | ①infallible | `let guard = self.registry.matchers.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 77 | `xray-geodata/src/matcher/ip.rs:598` | ①infallible | `let cache = self.cache.lock().expect("IPSetFactory lock poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 78 | `xray-geodata/src/matcher/ip.rs:605` | ①infallible | `let mut cache = self.cache.lock().expect("IPSetFactory lock poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 79 | `xray-geodata/src/matcher/ip.rs:682` | ②有前置守卫 | `let matcher = subs.pop().expect("len==1 guaranteed");` | 上方 subs.len()==1 检查(681) |
| 80 | `xray-geodata/src/matcher/ip.rs:1278` | ①infallible | `let mut g = self.inner.write().expect("IpRegistry poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 81 | `xray-geodata/src/matcher/ip.rs:1295` | ①infallible | `let g = self.inner.read().expect("IpRegistry poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 82 | `xray-geodata/src/matcher/ip.rs:1310` | ①infallible | `self.inner.read().expect("IpRegistry poisoned").entries.len()` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 83 | `xray-geodata/src/matcher/ip.rs:1354` | ①infallible | `let mut g = self.state.write().expect("DynamicIPMatcher state poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 84 | `xray-geodata/src/matcher/ip.rs:1362` | ①infallible | `let mut g = self.state.write().expect("DynamicIPMatcher state poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 85 | `xray-geodata/src/matcher/ip.rs:1370` | ①infallible | `let mut g = self.state.write().expect("DynamicIPMatcher state poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 86 | `xray-geodata/src/matcher/ip.rs:1381` | ①infallible | `let g = self.state.read().expect("DynamicIPMatcher state poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 87 | `xray-geodata/src/matcher/matcher_groups.rs:653` | ①infallible | `.expect("rule_infos \u{5e94}\u{5728}\u{6784}\u{5efa}\u{524d}\u{53ef}\u{7528}");` | 构造后不变量：rule_infos 构建期初始化 |
| 88 | `xray-mux/src/frame.rs:218` | ③真风险→已修复 | `.expect("target network must be TCP or UDP for mux frames");` | 已修复：Network::Unix 远程可达 panic → MuxError::Io 显式拒绝（Go 写 string 无 panic） |
| 89 | `xray-mux/src/worker.rs:570` | ②有前置守卫 | `let gid = *meta.global_id().unwrap();` | 同表达式上方 global_id().is_some() 守卫(569) |
| 90 | `xray-proxy-anytls/src/server.rs:211` | ①infallible | `.expect("anytls kill_tx cell poisoned")` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 91 | `xray-proxy-dokodemo/src/server.rs:167` | ①infallible | `let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();` | 常量解析 |
| 92 | `xray-proxy-freedom/src/fragment.rs:256` | ②有前置守卫 | `let (data, off, _) = this.current.as_mut().expect("current set");` | 循环顶部 if current.is_none{pop\|return} 守卫(246-254) |
| 93 | `xray-proxy-freedom/src/fragment.rs:267` | ②有前置守卫 | `let (_, _, sleep_after) = this.current.take().expect("current set");` | 同上守卫，take 前已保证 Some |
| 94 | `xray-proxy-freedom/src/udp.rs:184` | ②有前置守卫 | `return Ok(SocketAddr::new(*ips.choose(&mut rand::rng()).expect("non-empty"), port));` | match arm guard !ips.is_empty()(182) |
| 95 | `xray-proxy-ss/src/config.rs:215` | ②有前置守卫 | `let aead = self.create_aead(key, &iv)?.expect("aead for Aead variant");` | if let Self::Aead 分支，create_aead 对 Aead variant 恒 Some |
| 96 | `xray-proxy-ss/src/config.rs:241` | ②有前置守卫 | `let aead = self.create_aead(key, &iv)?.expect("aead for Aead variant");` | 同上 |
| 97 | `xray-proxy-ss/src/config.rs:288` | ①infallible | `hk.expand(crate::SS_SUBKEY, out).expect("hkdf expand should not fail for valid output size");` | hkdf expand 仅 out>255*hash_len 时 Err，out 为固定 16/32B |
| 98 | `xray-proxy-ss/src/server.rs:81` | ②有前置守卫 | `validator.add(user).expect("add user");` | 构造期配置校验路径：add 仅在多用户混流式 cipher 失败(validator.rs:140-141)，远程流量不经此路径 |
| 99 | `xray-proxy-ss/src/stream.rs:524` | ②有前置守卫 | `u64::from_be_bytes(plain[1..9].try_into().expect("epoch slice is 8 bytes"));` | 上方 plain.len()!=fixed_plain(>=11) 早返回 Err(515-516) |
| 100 | `xray-proxy-ss/src/validator.rs:138` | ①infallible | `let mut inner = self.inner.lock().expect("validator mutex poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 101 | `xray-proxy-ss/src/validator.rs:152` | ①infallible | `.expect("HMAC accepts any key size");` | HMAC new_from_slice 任意 key 长度恒成功 |
| 102 | `xray-proxy-ss/src/validator.rs:170` | ①infallible | `let mut inner = self.inner.lock().expect("validator mutex poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 103 | `xray-proxy-ss/src/validator.rs:189` | ①infallible | `let inner = self.inner.lock().expect("validator mutex poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 104 | `xray-proxy-ss/src/validator.rs:197` | ①infallible | `let inner = self.inner.lock().expect("validator mutex poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 105 | `xray-proxy-ss/src/validator.rs:204` | ①infallible | `let inner = self.inner.lock().expect("validator mutex poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 106 | `xray-proxy-ss/src/validator.rs:219` | ①infallible | `let mut inner = self.inner.lock().expect("validator mutex poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 107 | `xray-proxy-ss/src/validator.rs:277` | ①infallible | `let mut inner = self.inner.lock().expect("validator mutex poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 108 | `xray-proxy-ss/src/ss2022/key.rs:94` | ①infallible | `h.as_bytes()[..IDENTITY_HEADER_LEN].try_into().unwrap()` | blake3 输出 32B，[..16] 定长切片 |
| 109 | `xray-proxy-ss/src/ss2022/key.rs:132` | ②有前置守卫 | `let k: [u8; 16] = key[..16].try_into().unwrap();` | 全部调用链经 derive_psk(key.rs:175-187) 长度=key_size∈{16,32} |
| 110 | `xray-proxy-ss/src/ss2022/key.rs:139` | ②有前置守卫 | `let k: [u8; 16] = key[..16].try_into().unwrap();` | 同上 |
| 111 | `xray-proxy-ss/src/ss2022/key.rs:146` | ②有前置守卫 | `let k: [u8; 32] = key[..32].try_into().unwrap();` | 同上 |
| 112 | `xray-proxy-ss/src/ss2022/key.rs:153` | ②有前置守卫 | `let k: [u8; 32] = key[..32].try_into().unwrap();` | 同上 |
| 113 | `xray-proxy-ss/src/ss2022/packet.rs:203` | ②有前置守卫 | `let ts = i64::from_be_bytes(plain[1..9].try_into().unwrap());` | 上方 plain.len()>=MIN_PLAINTEXT=18 守卫(196) |
| 114 | `xray-proxy-ss/src/ss2022/packet.rs:208` | ②有前置守卫 | `let pad = u16::from_be_bytes(plain[9..11].try_into().unwrap()) as usize;` | 同上守卫，[9..11] 安全 |
| 115 | `xray-proxy-ss/src/ss2022/packet.rs:231` | ②有前置守卫 | `let ts = i64::from_be_bytes(plain[1..9].try_into().unwrap());` | 上方 plain.len()>=MIN_PLAINTEXT+8=26 守卫(224) |
| 116 | `xray-proxy-ss/src/ss2022/packet.rs:236` | ②有前置守卫 | `let csid = u64::from_be_bytes(plain[9..17].try_into().unwrap());` | 同上守卫，[9..17] 安全 |
| 117 | `xray-proxy-ss/src/ss2022/packet.rs:240` | ②有前置守卫 | `let pad = u16::from_be_bytes(plain[17..19].try_into().unwrap()) as usize;` | 同上守卫，[17..19] 安全 |
| 118 | `xray-proxy-ss/src/ss2022/packet.rs:369` | ②有前置守卫 | `let hdr = ecb_block(self.kind, last, pkt[..16].try_into().unwrap(), false)?;` | 上方 pkt.len()>=PACKET_HEADER_LEN+MIN_PLAINTEXT=34 守卫(365) |
| 119 | `xray-proxy-ss/src/ss2022/packet.rs:370` | ①infallible | `let session_id = u64::from_be_bytes(hdr[..8].try_into().unwrap());` | hdr 为 ecb_block 返回的 [u8;16] 定长数组切片 |
| 120 | `xray-proxy-ss/src/ss2022/packet.rs:371` | ①infallible | `let packet_id = u64::from_be_bytes(hdr[8..].try_into().unwrap());` | 同上 |
| 121 | `xray-proxy-ss/src/ss2022/packet.rs:463` | ②有前置守卫 | `let hdr = ecb_block(kind, server_psk, pkt[..16].try_into().unwrap(), false)?;` | 上方 pkt.len()>=16+eih_len+18 守卫(460-461) |
| 122 | `xray-proxy-ss/src/ss2022/packet.rs:464` | ①infallible | `let session_id = u64::from_be_bytes(hdr[..8].try_into().unwrap());` | hdr [u8;16] 定长 |
| 123 | `xray-proxy-ss/src/ss2022/packet.rs:465` | ①infallible | `let packet_id = u64::from_be_bytes(hdr[8..].try_into().unwrap());` | hdr [u8;16] 定长 |
| 124 | `xray-proxy-ss/src/ss2022/packet.rs:471` | ②有前置守卫 | `let eih = ecb_block(kind, server_psk, pkt[16..32].try_into().unwrap(), false)?;` | users 非空时 eih_len=16→pkt.len()>=50 守卫；users 空时不执行(459-467) |
| 125 | `xray-proxy-trojan/src/config.rs:109` | ①infallible | `hex::encode_to_slice(digest, &mut out).expect("SHA-224 digest is 28 bytes, hex fits 56");` | SHA-224 28B→hex 56B 定长，encode_to_slice 恒成功 |
| 126 | `xray-proxy-tuic/src/client.rs:312` | ①infallible | `"[::]:0".parse().unwrap()` | 字面常量解析（IP/端口/header/正则），恒成功 |
| 127 | `xray-proxy-tuic/src/client.rs:314` | ①infallible | `"0.0.0.0:0".parse().unwrap()` | 字面常量解析（IP/端口/header/正则），恒成功 |
| 128 | `xray-proxy-tuic/src/inbound.rs:112` | ①infallible | `self.cert_der.lock().unwrap().clone()` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 129 | `xray-proxy-tuic/src/inbound.rs:138` | ①infallible | `*self.cert_der.lock().unwrap() = Some(tls.cert_der.clone());` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 130 | `xray-proxy-tuic/src/server.rs:117` | ②有前置守卫 | `self.endpoint.local_addr().expect("local_addr")` | QUIC listener bind 成功后 local_addr 恒成功 |
| 131 | `xray-proxy-vless/src/encoding/server.rs:125` | ①infallible | `VlessCommand::Mux.fixed_domain().unwrap().to_string(),` | fixed_domain 对 Mux 恒 Some(enc/mod.rs:86-89)，match arm 自身保证 |
| 132 | `xray-proxy-vless/src/encoding/server.rs:130` | ①infallible | `VlessCommand::Rvs.fixed_domain().unwrap().to_string(),` | fixed_domain 对 Rvs 恒 Some(enc/mod.rs:86-89) |
| 133 | `xray-proxy-vless/src/encryption/common_conn.rs:186` | ②有前置守卫 | `.expect("16B server random");` | 上方 while raw<16 读循环填满守卫(165-182)，EOF 早返回 |
| 134 | `xray-proxy-vless/src/encryption/common_conn.rs:215` | ②有前置守卫 | `.expect("header slice len");` | 上方 if avail>=TLS_RECORD_HEADER_LEN(5) 守卫(210) |
| 135 | `xray-proxy-vless/src/encryption/common_conn.rs:250` | ②有前置守卫 | `.expect("peer_aead established at loop top");` | 循环顶部 if peer_aead.is_none 先建立(164-194) |
| 136 | `xray-proxy-vless/src/encryption/common_conn.rs:351` | ①infallible | `let payload_len = u16::try_from(n + TAG_LEN).expect("segment + tag fits in u16");` | n<=MAX_SEGMENT(8192)+TAG_LEN(16)<65536，try_from 恒成功 |
| 137 | `xray-proxy-vless/src/encryption/mod.rs:160` | ②有前置守卫 | `*lens.last_mut().expect("creat_padding lens 非空：默认或 parse 首段保证") +=` | creat_padding 构造保证 lens 非空(默认或 parse 首段) |
| 138 | `xray-proxy-vless/src/encryption/mod.rs:264` | ①infallible | `let iv: [u8; 16] = client_hello[..16].try_into().expect("iv is 16 bytes");` | 本方构造 client_hello 长度>=16 |
| 139 | `xray-proxy-vless/src/encryption/mod.rs:433` | ①infallible | `let iv: [u8; 16] = pre_write[..16].try_into().expect("iv 16");` | pre_write 为本方随机填充缓冲 |
| 140 | `xray-proxy-vless/src/encryption/mod.rs:520` | ①infallible | `iv = client_hello[..16].try_into().expect("iv is 16 bytes");` | 本方构造 client_hello 长度>=16 |
| 141 | `xray-proxy-vless/src/encryption/mod.rs:1003` | ①infallible | `iv_and_relays[..16].try_into().expect("iv is 16 bytes");` | read_exact 填满 iv_and_relays 后定长切片 |
| 142 | `xray-proxy-vless/src/encryption/mod.rs:1240` | ①infallible | `let hdr: [u8; 5] = noises[..5].try_into().expect("noise >= 5 bytes");` | noises vec 长度 1279-2279>=5 |
| 143 | `xray-proxy-vless/src/encryption/mod.rs:1261` | ③真风险→已修复 | `.expect("session checked above");` | 已修复：TOCTOU——1233 hit 检查与本次加锁间隙内过期清理可 remove→panic；改显式 Err(expired ticket)（Go sync.Map 无 panic） |
| 144 | `xray-proxy-vless/src/encryption/xor_conn.rs:201` | ①infallible | `.expect("read ctr set at construction or derived from first 16 bytes")` | 构造或首读 16B 派生时设置 read_ctr（状态机不变量） |
| 145 | `xray-proxy-vmess/src/dispatcher.rs:184` | ②有前置守卫 | `let user = users.first().unwrap();` | 上方 users.len()!=1 早返回 Err(182-183) |
| 146 | `xray-proxy-vmess/src/validator.rs:121` | ①infallible | `let mut inner = self.inner.lock().expect("inner poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 147 | `xray-proxy-vmess/src/validator.rs:129` | ①infallible | `let mut h = HmacSha256::new_from_slice(b"VMESSBSKDF").expect("key len ok");` | HMAC 常量 key |
| 148 | `xray-proxy-vmess/src/validator.rs:143` | ①infallible | `let mut inner = self.inner.lock().expect("inner poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 149 | `xray-proxy-vmess/src/validator.rs:174` | ①infallible | `let inner = self.inner.lock().expect("inner poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 150 | `xray-proxy-vmess/src/validator.rs:183` | ①infallible | `self.inner.lock().expect("inner poisoned").users.len()` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 151 | `xray-proxy-vmess/src/validator.rs:187` | ①infallible | `let mut inner = self.inner.lock().expect("inner poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 152 | `xray-proxy-vmess/src/aead/mod.rs:74` | ①infallible | `.expect("HMAC key length");` | HMAC 常量 key 恒合法 |
| 153 | `xray-proxy-vmess/src/aead/mod.rs:553` | ①infallible | `.expect("items poisoned")` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 154 | `xray-proxy-vmess/src/aead/mod.rs:559` | ①infallible | `self.items.lock().expect("items poisoned").remove(key);` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 155 | `xray-proxy-vmess/src/aead/mod.rs:565` | ①infallible | `self.items.lock().expect("items poisoned").len()` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 156 | `xray-proxy-vmess/src/aead/mod.rs:580` | ①infallible | `let items = self.items.lock().expect("items poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 157 | `xray-proxy-vmess/src/aead/mod.rs:599` | ①infallible | `let mut filter = self.replay_filter.lock().expect("replay poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 158 | `xray-proxy-vmess/src/encoding/body_chunk.rs:224` | ①infallible | `Box::new(move \|\| nonce_gen.lock().expect("nonce gen poisoned").next())` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 159 | `xray-proxy-vmess/src/encoding/client.rs:308` | ②有前置守卫 | `let ip = <[u8; 4]>::try_from(&data[1..5]).unwrap();` | 上方 data.len()<5 早返回(307) |
| 160 | `xray-proxy-vmess/src/encoding/client.rs:322` | ②有前置守卫 | `let ip = <[u8; 16]>::try_from(&data[1..17]).unwrap();` | 上方 data.len()<17 早返回(321) |
| 161 | `xray-proxy-vmess/src/encoding/server.rs:81` | ①infallible | `let mut inner = self.inner.lock().expect("history poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 162 | `xray-proxy-vmess/src/encoding/server.rs:101` | ①infallible | `self.inner.lock().expect("history poisoned").len()` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 163 | `xray-proxy-vmess/src/encoding/server.rs:107` | ①infallible | `self.inner.lock().expect("history poisoned").is_empty()` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 164 | `xray-reality/src/crypto.rs:427` | ②有前置守卫 | `let sk = SigningKey::<MlDsa65>::from_seed(&Seed::from(<[u8; 32]>::try_from(seed).unwrap()));` | 函数开头 seed.len()!=32 早返回 Err(421-423) |
| 165 | `xray-reality/src/crypto.rs:462` | ②有前置守卫 | `let sk = SigningKey::<MlDsa65>::from_seed(&Seed::from(<[u8; 32]>::try_from(seed).unwrap()));` | 函数开头 seed.len()!=32 早返回 Err(456-458) |
| 166 | `xray-reality/src/mitm.rs:153` | ①infallible | `LazyLock::new(\|\| build_dummy_cert().expect("REALITY dummy cert template"));` | 内部 dummy cert 模板构造失败=编程错误（内部常量） |
| 167 | `xray-stress/src/quic_loop.rs:66` | ①infallible | `format!("127.0.0.1:{quic_port}").parse().unwrap(),` | u16 端口插值的 loopback 地址解析恒成功 |
| 168 | `xray-stress/src/quic_loop.rs:147` | ①infallible | `QuinnHysteriaTransport::new(client_tls, "0.0.0.0:0".parse().unwrap())` | 常量解析 |
| 169 | `xray-stress/src/quic_loop.rs:148` | ①infallible | `.expect("quic transport"),` | harness 基础设施：transport 创建失败=环境不可恢复 |
| 170 | `xray-stress/src/topology.rs:35` | ①infallible | `let probe = TcpListener::bind("127.0.0.1:0").await.expect("pick port");` | harness：127.0.0.1:0 bind 失败=环境不可恢复，非恶意输入可达 |
| 171 | `xray-stress/src/topology.rs:36` | ①infallible | `let port = probe.local_addr().expect("probe addr").port();` | bind 成功后 local_addr 恒成功 |
| 172 | `xray-stress/src/topology.rs:48` | ①infallible | `let listener = TcpListener::bind(("127.0.0.1", echo_port)).await.expect("bind echo");` | harness 同上 |
| 173 | `xray-stress/src/topology.rs:49` | ①infallible | `let addr = listener.local_addr().expect("echo addr");` | bind 成功后恒成功 |
| 174 | `xray-tls/src/ech.rs:150` | ①infallible | `self.inner.lock().expect("ECH cache mutex poisoned").clone()` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 175 | `xray-tls/src/ech.rs:155` | ①infallible | `let mut guard = self.inner.lock().expect("ECH cache mutex poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 176 | `xray-tls/src/ech.rs:167` | ①infallible | `let mut guard = self.inner.lock().expect("ECH cache mutex poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 177 | `xray-transport/src/config.rs:19` | ①infallible | `let mut map = transport_config().lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 178 | `xray-transport/src/config.rs:31` | ①infallible | `transport_config().lock().unwrap().get(tag).cloned()` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 179 | `xray-transport/src/happy_eyeballs.rs:141` | ②有前置守卫 | `return Ok(winner.take().expect("winner checked above"));` | 上方 winner.is_some() 守卫(139) |
| 180 | `xray-transport/src/system_dialer.rs:294` | ①infallible | `*DIALER_PROXY_HOOK.write().expect("DIALER_PROXY_HOOK lock poisoned") = Some(hook);` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 181 | `xray-transport/src/system_dialer.rs:299` | ①infallible | `*DIALER_PROXY_HOOK.write().expect("DIALER_PROXY_HOOK lock poisoned") = None;` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 182 | `xray-transport/src/system_dialer.rs:313` | ①infallible | `*DNS_CLIENT.write().expect("DNS_CLIENT lock poisoned") = client;` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 183 | `xray-transport/src/system_dialer.rs:317` | ①infallible | `DNS_CLIENT.read().expect("DNS_CLIENT lock poisoned").clone()` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 184 | `xray-transport/src/system_dialer.rs:671` | ①infallible | `.expect("DIALER_PROXY_HOOK lock poisoned")` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 185 | `xray-transport/src/finalmask/mod.rs:313` | ①infallible | `Ok(Box::new(PacketIoConn::new(udpio, "0.0.0.0:0".parse().unwrap())))` | 字面常量解析（IP/端口/header/正则），恒成功 |
| 186 | `xray-transport/src/finalmask/mod.rs:1015` | ②有前置守卫 | `transform.expect("kinds==1 且前置分支未命中，transform 必为 Some"),` | kinds==1 分支结构保证 transform=Some |
| 187 | `xray-transport/src/finalmask/salamander.rs:78` | ①infallible | `let mut hasher = Blake2bVar::new(SM_KEY_LEN).expect("32 is valid blake2b output size");` | SM_KEY_LEN=32 为 blake2b 合法输出长度 |
| 188 | `xray-transport/src/finalmask/salamander.rs:82` | ①infallible | `hasher.finalize_variable(&mut key).expect("finalize_variable");` | finalize_variable out 恰 key 长度 |
| 189 | `xray-transport/src/finalmask/salamander_gecko.rs:343` | ②有前置守卫 | `let entry = state.reassembly.get_mut(key).unwrap();` | 上方 contains_key 检查/insert 守卫(321-337)，HashMap 键一致性保证 get_mut Some |
| 190 | `xray-transport/src/finalmask/sudoku/table.rs:234` | ②有前置守卫 | `x_bits: x_bits.try_into().unwrap(),` | normalize_custom_table 校验恰 2x/2p/4v(453-476)保证计数 |
| 191 | `xray-transport/src/finalmask/sudoku/table.rs:235` | ②有前置守卫 | `p_bits: p_bits.try_into().unwrap(),` | 同上 |
| 192 | `xray-transport/src/finalmask/sudoku/table.rs:236` | ②有前置守卫 | `v_bits: v_bits.try_into().unwrap(),` | 同上 |
| 193 | `xray-transport/src/finalmask/sudoku/table.rs:406` | ②有前置守卫 | `Ok(BASE_PATTERNS.get().expect("BASE_PATTERNS just set"))` | 上方刚 BASE_PATTERNS.set(405) |
| 194 | `xray-transport/src/finalmask/sudoku/table.rs:510` | ①infallible | `let seed = i64::from_be_bytes(hash_ref[..8].try_into().unwrap());` | SHA256 输出 32B，[..8] 定长切片 |
| 195 | `xray-transport/src/finalmask/xdns/record_transport.rs:196` | ①infallible | `.expect("max length name should be valid");` | 内部常量 max name 构造 |
| 196 | `xray-transport/src/headers/conn.rs:110` | ②有前置守卫 | `let data = this.replay.take().expect("checked");` | 上方 if replay.is_some() 守卫(108) |
| 197 | `xray-transport/src/headers/conn.rs:360` | ②有前置守卫 | `let map = hj.as_object().expect("checked is_object");` | 上方 filter(is_object) 守卫(358) |
| 198 | `xray-transport/src/udp/hub.rs:175` | ①infallible | `self.rx.take().expect("receive() called twice")` | 消费型 API 契约：receive() 只可调用一次，违反=调用方 bug |
| 199 | `xray-transport/src/udp/hub.rs:185` | ①infallible | `let rx = self.rx.take().expect("split() called after receive()");` | 消费型 API 契约：split() 须在 receive() 前 |
| 200 | `xray-transport-grpc/src/transport.rs:395` | ①infallible | `let r=http::Response::builder().status(404).body(()).unwrap();` | http builder 静态 status/body 恒合法 |
| 201 | `xray-transport-grpc/src/transport.rs:407` | ①infallible | `let r = http::Response::builder().status(415).body(()).unwrap();` | 同上 |
| 202 | `xray-transport-grpc/src/transport.rs:423` | ①infallible | `.body(()).unwrap();` | 静态 header+body 构造 |
| 203 | `xray-transport-grpc/src/transport.rs:432` | ①infallible | `.header("content-type", "application/grpc").body(()).unwrap(),` | 静态 header+body 构造 |
| 204 | `xray-transport-hysteria/src/conn.rs:416` | ②有前置守卫 | `let fut = state.as_mut().unwrap();` | 上方 if state.is_none { *state=Some(...) } 守卫(404-413) |
| 205 | `xray-transport-hysteria/src/conn.rs:461` | ②有前置守卫 | `match state.as_mut().unwrap().as_mut().poll(cx) {` | 上一行刚赋值 *state=Some(460) |
| 206 | `xray-transport-hysteria/src/conn.rs:494` | ②有前置守卫 | `let fut = state.as_mut().unwrap();` | 同模式守卫(488-493) |
| 207 | `xray-transport-hysteria/src/hysteria_transport.rs:246` | ①infallible | `.expect("static request build");` | 静态 request 构造 |
| 208 | `xray-transport-hysteria/src/quinn_adapter.rs:994` | ①infallible | `.unwrap();` | builder 静态构造 |
| 209 | `xray-transport-hysteria/src/quinn_adapter.rs:1006` | ①infallible | `let resp = builder.body(()).unwrap();` | 程序内构造 headers（auth_resp），非远程字符串 |
| 210 | `xray-transport-hysteria/src/salamander_socket.rs:266` | ②有前置守卫 | `let result = this.fut.as_mut().unwrap().as_mut().poll(cx);` | 上方 if fut.is_none { fut=Some } 守卫(263-265) |
| 211 | `xray-transport-hysteria/src/udphop.rs:277` | ①infallible | `Ok((n, addr.unwrap_or_else(\|\| "0.0.0.0:0".parse().unwrap())))` | 字面常量解析（IP/端口/header/正则），恒成功 |
| 212 | `xray-transport-kcp/src/connection.rs:702` | ②有前置守卫 | `if state.as_mut().unwrap().as_mut().poll(cx).is_pending() {` | 上方 if state.is_none { state=Some } 守卫 |
| 213 | `xray-transport-kcp/src/connection.rs:736` | ②有前置守卫 | `if state.as_mut().unwrap().as_mut().poll(cx).is_pending() {` | 同上 |
| 214 | `xray-transport-kcp/src/segment.rs:204` | ②有前置守卫 | `self.timestamp = u32::from_be_bytes(body[0..4].try_into().unwrap());` | 上方 body.len()<14 守卫(202-203) |
| 215 | `xray-transport-kcp/src/segment.rs:205` | ②有前置守卫 | `self.number = u32::from_be_bytes(body[4..8].try_into().unwrap());` | 同上 |
| 216 | `xray-transport-kcp/src/segment.rs:206` | ②有前置守卫 | `self.sending_next = u32::from_be_bytes(body[8..12].try_into().unwrap());` | 同上 |
| 217 | `xray-transport-kcp/src/segment.rs:207` | ②有前置守卫 | `let data_len = u16::from_be_bytes(body[12..14].try_into().unwrap()) as usize;` | 同上，[12..14] 安全 |
| 218 | `xray-transport-kcp/src/segment.rs:324` | ②有前置守卫 | `self.receiving_window = u32::from_be_bytes(body[0..4].try_into().unwrap());` | 上方 body.len()<13 守卫(321-322) |
| 219 | `xray-transport-kcp/src/segment.rs:325` | ②有前置守卫 | `self.receiving_next = u32::from_be_bytes(body[4..8].try_into().unwrap());` | 同上 |
| 220 | `xray-transport-kcp/src/segment.rs:326` | ②有前置守卫 | `self.timestamp = u32::from_be_bytes(body[8..12].try_into().unwrap());` | 同上 |
| 221 | `xray-transport-kcp/src/segment.rs:336` | ②有前置守卫 | `.push(u32::from_be_bytes(body[off..off + 4].try_into().unwrap()));` | 上方 count 按 body.len() 校验(327-329)后索引安全 |
| 222 | `xray-transport-kcp/src/segment.rs:420` | ②有前置守卫 | `self.sending_next = u32::from_be_bytes(body[0..4].try_into().unwrap());` | 上方 body.len()<12 守卫(419-420) |
| 223 | `xray-transport-kcp/src/segment.rs:421` | ②有前置守卫 | `self.receiving_next = u32::from_be_bytes(body[4..8].try_into().unwrap());` | 同上 |
| 224 | `xray-transport-kcp/src/segment.rs:422` | ②有前置守卫 | `self.peer_rto = u32::from_be_bytes(body[8..12].try_into().unwrap());` | 同上 |
| 225 | `xray-transport-kcp/src/sending.rs:62` | ②有前置守卫 | `let mut seg = self.cache.pop_front().unwrap();` | 循环内 front() 非空守卫(59-61) |
| 226 | `xray-transport-kcp/src/sending.rs:87` | ②有前置守卫 | `let mut seg = self.cache.remove(idx).unwrap();` | idx 来自 position() 同步块内 remove(84-86) |
| 227 | `xray-transport-naive/src/dial.rs:79` | ②有前置守卫 | `.expect("non-insecure config yields a verifier"),` | security_json 恒不含 allowInsecure(67-70)，build_server_cert_verifier None 仅当 allowInsecure(client_config.rs:266-267) |
| 228 | `xray-transport-quic/src/transport.rs:88` | ①infallible | `"0.0.0.0:0".parse().unwrap(),` | 字面常量解析（IP/端口/header/正则），恒成功 |
| 229 | `xray-transport-quic/src/congestion_swappable/brutal.rs:55` | ①infallible | `let inner = self.inner.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 230 | `xray-transport-quic/src/congestion_swappable/brutal.rs:75` | ①infallible | `let rate = *ar_for_closure.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 231 | `xray-transport-quic/src/congestion_swappable/brutal.rs:96` | ①infallible | `self.inner.lock().unwrap().ack_rate` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 232 | `xray-transport-quic/src/congestion_swappable/brutal.rs:101` | ①infallible | `self.inner.lock().unwrap().bps` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 233 | `xray-transport-quic/src/congestion_swappable/brutal.rs:137` | ①infallible | `self.inner.lock().unwrap().rtt_stats = Some(provider);` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 234 | `xray-transport-quic/src/congestion_swappable/brutal.rs:145` | ①infallible | `let mds = self.inner.lock().unwrap().max_datagram_size;` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 235 | `xray-transport-quic/src/congestion_swappable/brutal.rs:154` | ①infallible | `let inner = self.inner.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 236 | `xray-transport-quic/src/congestion_swappable/brutal.rs:208` | ①infallible | `let mut inner = self.inner.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 237 | `xray-transport-quic/src/congestion_swappable/brutal.rs:220` | ①infallible | `*self.shared_ack_rate.lock().unwrap() = new_rate;` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 238 | `xray-transport-quic/src/congestion_swappable/brutal.rs:225` | ①infallible | `let mut inner = self.inner.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 239 | `xray-transport-quic/src/congestion_swappable/pacer.rs:32` | ①infallible | `let inner = self.inner.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 240 | `xray-transport-quic/src/congestion_swappable/pacer.rs:58` | ①infallible | `let mut inner = self.inner.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 241 | `xray-transport-quic/src/congestion_swappable/pacer.rs:71` | ①infallible | `let inner = self.inner.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 242 | `xray-transport-quic/src/congestion_swappable/pacer.rs:80` | ①infallible | `let inner = self.inner.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 243 | `xray-transport-quic/src/congestion_swappable/pacer.rs:98` | ①infallible | `let mut inner = self.inner.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 244 | `xray-transport-quic/src/congestion_swappable/bbr/bbr_sender.rs:199` | ①infallible | `let inner = self.inner.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 245 | `xray-transport-quic/src/congestion_swappable/bbr/bbr_sender.rs:228` | ①infallible | `let (rate, gain) = *bw_for_closure.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 246 | `xray-transport-quic/src/congestion_swappable/bbr/bbr_sender.rs:285` | ①infallible | `*bw_state.lock().unwrap() = (inner.pacing_rate, inner.pacing_gain);` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 247 | `xray-transport-quic/src/congestion_swappable/bbr/bbr_sender.rs:316` | ①infallible | `self.inner.lock().unwrap().mode` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 248 | `xray-transport-quic/src/congestion_swappable/bbr/bbr_sender.rs:321` | ①infallible | `self.inner.lock().unwrap().profile` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 249 | `xray-transport-quic/src/congestion_swappable/bbr/bbr_sender.rs:326` | ①infallible | `self.inner.lock().unwrap().pacing_rate` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 250 | `xray-transport-quic/src/congestion_swappable/bbr/bbr_sender.rs:332` | ①infallible | `self.inner.lock().unwrap().rtt_stats = Some(provider);` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 251 | `xray-transport-quic/src/congestion_swappable/bbr/bbr_sender.rs:340` | ①infallible | `let mds = self.inner.lock().unwrap().max_datagram_size;` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 252 | `xray-transport-quic/src/congestion_swappable/bbr/bbr_sender.rs:349` | ①infallible | `let inner = self.inner.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 253 | `xray-transport-quic/src/congestion_swappable/bbr/bbr_sender.rs:368` | ①infallible | `let mut inner = self.inner.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 254 | `xray-transport-quic/src/congestion_swappable/bbr/bbr_sender.rs:412` | ①infallible | `let mut inner = self.inner.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 255 | `xray-transport-quic/src/congestion_swappable/bbr/bbr_sender.rs:433` | ①infallible | `let mut inner = self.inner.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 256 | `xray-transport-quic/src/congestion_swappable/bbr/bbr_sender.rs:470` | ①infallible | `self.inner.lock().unwrap().mode == BbrMode::Startup` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 257 | `xray-transport-quic/src/congestion_swappable/bbr/bbr_sender.rs:474` | ①infallible | `self.inner.lock().unwrap().recovery_state != BbrRecoveryState::NotInRecovery` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 258 | `xray-transport-quic/src/congestion_swappable/bbr/ringbuffer.rs:51` | ①infallible | `self.inner.pop_front().expect("RingBuffer::pop_front on empty queue")` | API 契约对齐 Go quic-go ringbuffer（文档声明空时 panic，Go 同形） |
| 259 | `xray-transport-quic/src/congestion_swappable/bbr/ringbuffer.rs:56` | ①infallible | `self.inner.front().expect("RingBuffer::front on empty queue")` | 同上 |
| 260 | `xray-transport-quic/src/congestion_swappable/bbr/ringbuffer.rs:61` | ①infallible | `self.inner.front_mut().expect("RingBuffer::front_mut on empty queue")` | 同上 |
| 261 | `xray-transport-quic/src/congestion_swappable/bbr/ringbuffer.rs:66` | ①infallible | `self.inner.back().expect("RingBuffer::back on empty queue")` | 同上 |
| 262 | `xray-transport-quic/src/congestion_swappable/bbr/ringbuffer.rs:71` | ①infallible | `self.inner.get(index).expect("RingBuffer::offset index out of range")` | 同上（越界 panic，Go Offset 同形） |
| 263 | `xray-transport-quic/src/congestion_swappable/bbr/ringbuffer.rs:76` | ①infallible | `self.inner.get_mut(index).expect("RingBuffer::offset_mut index out of range")` | 同上 |
| 264 | `xray-transport-splithttp/src/connection.rs:62` | ①infallible | `let mut guard = self.on_close.lock().expect("on_close mutex poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 265 | `xray-transport-splithttp/src/connection.rs:68` | ①infallible | `if let Some(f) = self.on_close.lock().expect("on_close mutex poisoned").take() {` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 266 | `xray-transport-splithttp/src/connection.rs:90` | ①infallible | `let on_close = this.on_close.lock().expect("on_close mutex poisoned").take();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 267 | `xray-transport-splithttp/src/connection.rs:134` | ①infallible | `if let Some(f) = self.on_close.lock().expect("on_close mutex poisoned").take() {` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 268 | `xray-transport-splithttp/src/connection.rs:169` | ①infallible | `let mut guard = this.inner.lock().expect("MutexReader poisoned");` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 269 | `xray-transport-splithttp/src/h3_client.rs:221` | ①infallible | `"0.0.0.0:0".parse().expect("valid bind addr")` | 字面常量解析（IP/端口/header/正则），恒成功 |
| 270 | `xray-transport-splithttp/src/h3_client.rs:223` | ①infallible | `"[::]:0".parse().expect("valid bind addr")` | 字面常量解析（IP/端口/header/正则），恒成功 |
| 271 | `xray-transport-splithttp/src/mux.rs:122` | ①infallible | `if let Some(t) = *self.unreusable_at.lock().unwrap() {` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 272 | `xray-transport-splithttp/src/mux.rs:191` | ①infallible | `*client.unreusable_at.lock().unwrap() =` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 273 | `xray-transport-splithttp/src/mux.rs:198` | ①infallible | `.unwrap()` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 274 | `xray-transport-splithttp/src/mux.rs:213` | ①infallible | `let mut clients = self.xmux_clients.lock().unwrap();` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 275 | `xray-transport-splithttp/src/mux.rs:257` | ①infallible | `self.xmux_clients.lock().unwrap().len()` | std 同步锁毒锁：对方线程持锁 panic=并发不变量已破，panic 为 Rust 惯例（Go 无毒锁语义） |
| 276 | `xray-transport-splithttp/src/register.rs:211` | ①infallible | `let remote = remote_addr.unwrap_or_else(\|\| "0.0.0.0:0".parse().unwrap());` | 字面常量解析（IP/端口/header/正则），恒成功 |
| 277 | `xray-transport-splithttp/src/register.rs:212` | ①infallible | `let local = local_addr.unwrap_or_else(\|\| "0.0.0.0:0".parse().unwrap());` | 字面常量解析（IP/端口/header/正则），恒成功 |
| 278 | `xray-transport-splithttp/src/transport.rs:66` | ②有前置守卫 | `let tls = tls_cfg.expect("is_h3 implies Some");` | is_h3 推导自 tls_cfg.is_some()(61-65) |
| 279 | `xray-transport-splithttp/src/upload_queue.rs:185` | ②有前置守卫 | `let packet = inner.heap.pop().unwrap().1;` | peek() 命中后同步 pop()(183-184) |
| 280 | `xray-transport-splithttp/src/hub/handler.rs:366` | ①infallible | `.insert("X-Accel-Buffering", "no".parse().unwrap());` | 静态 HeaderValue "no" 常量 parse |
| 281 | `xray-transport-splithttp/src/hub/handler.rs:368` | ①infallible | `.insert("Cache-Control", "no-store".parse().unwrap());` | 静态 HeaderValue "no-store" |
| 282 | `xray-transport-splithttp/src/hub/handler.rs:440` | ①infallible | `let headers = resp.headers_mut().unwrap();` | builder 未出错状态 headers_mut 恒 Some（status 静态合法） |
| 283 | `xray-transport-splithttp/src/hub/handler.rs:441` | ①infallible | `headers.insert("X-Accel-Buffering", "no".parse().unwrap());` | 静态 HeaderValue |
| 284 | `xray-transport-splithttp/src/hub/handler.rs:442` | ①infallible | `headers.insert("Cache-Control", "no-store".parse().unwrap());` | 静态 HeaderValue |
| 285 | `xray-transport-splithttp/src/hub/handler.rs:446` | ①infallible | `"text/event-stream".parse().unwrap(),` | 静态 HeaderValue "text/event-stream" |
| 286 | `xray-transport-splithttp/src/hub/handler.rs:449` | ①infallible | `resp.body(body).unwrap()` | builder 静态构造 body 恒成功 |
| 287 | `xray-transport-splithttp/src/hub/handler.rs:680` | ②有前置守卫 | `let v: [u8; 4] = [vals[0].unwrap(), vals[1].unwrap(), vals[2].unwrap(), vals[3].unwrap()];` | 同一表达式上方 vals.any(is_none) 早返回守卫(679)×4 处同行 |
| 288 | `xray-transport-splithttp/src/hub/handler.rs:680` | ②有前置守卫 | `let v: [u8; 4] = [vals[0].unwrap(), vals[1].unwrap(), vals[2].unwrap(), vals[3].unwrap()];` | 同一表达式上方 vals.any(is_none) 早返回守卫(679)×4 处同行 |
| 289 | `xray-transport-splithttp/src/hub/handler.rs:680` | ②有前置守卫 | `let v: [u8; 4] = [vals[0].unwrap(), vals[1].unwrap(), vals[2].unwrap(), vals[3].unwrap()];` | 同一表达式上方 vals.any(is_none) 早返回守卫(679)×4 处同行 |
| 290 | `xray-transport-splithttp/src/hub/handler.rs:680` | ②有前置守卫 | `let v: [u8; 4] = [vals[0].unwrap(), vals[1].unwrap(), vals[2].unwrap(), vals[3].unwrap()];` | 同一表达式上方 vals.any(is_none) 早返回守卫(679)×4 处同行 |
| 291 | `xray-transport-splithttp/src/hub/handler.rs:706` | ①infallible | `.unwrap()` | builder 静态构造 |
| 292 | `xray-transport-websocket/src/client.rs:264` | ②有前置守卫 | `Pin::new(this.conn.as_mut().expect("dial completed")).poll_read(cx, buf)` | 上方 ready!(poll_dial) 完成保证 conn=Some(261-263) |
| 293 | `xray-transport-websocket/src/client.rs:291` | ②有前置守卫 | `this.first_write.take().expect("recorded when dial was triggered");` | poll_dial 触发时记录 first_write（内部不变量） |
| 294 | `xray-transport-websocket/src/client.rs:298` | ②有前置守卫 | `Pin::new(this.conn.as_mut().expect("dial completed")).poll_write(cx, buf)` | 同 264 守卫 |
| 295 | `xray-transport-websocket/src/server.rs:184` | ①infallible | `.unwrap();` | 静态 builder 404 响应 |

# bd onx4 修复报告：Instance::new_from_built 配置硬错误用 stub 通道静默跳过

日期：2026-10-09 · 状态：VERDICT: PASS · 分支工作树（未 commit，归 PM）

## 结论

`Instance::new_from_built`（instance.rs）将真实配置硬错（commander API tag empty 等）
与 stub 未实现共用 `FeatureError::StartFailed` 通道，一律 warn+跳过——配置硬错被静默降级，
失败推迟到 connect 期（commander gRPC server 永不启动）。

修复：新增 `FeatureError::ConfigInvalid` 变体；工厂期配置硬错归该变体，
`new_from_built` 对其**致命**（Instance 构造失败）；stub 未实现维持 `StartFailed` warn+跳过。
对齐 Go：config Build 硬错 → `initInstanceWithConfig` 返回错误 → InstanceStart 失败。

## Go 基线验证（每票先 grep 基线）

| 位置 | 语义 |
|---|---|
| `infra/conf/api.go:23-25` | `API tag can't be empty.`（Build 硬错） |
| `core/xray.go:196-210` | app 循环 `GetInstance()`/`CreateObject()` 错误 → `return true, err`（致命，InstanceStart 失败） |
| `infra/conf/metrics.go:15` | `Metrics must have a tag or listen address.`（Build 硬错） |
| `app/version/version.go:24,33` | 版本约束不满足（app New 硬错） |
| `infra/conf/geodata.go:20,23,37,53` | asset url/file/cron 校验（Build 硬错） |
| `infra/conf/fakedns.go:45,68` | invalid fakedns config（Build 硬错） |

## 改动清单

1. **`crates/xray-features/src/feature.rs:35-40`** — 新增 `ConfigInvalid { name: &'static str, message: String }`
   变体（Display：`invalid config for feature {name}: {message}`），文档注明致命语义与 stub 区别。
2. **`crates/xray-core/src/instance.rs:149-158`** — `new_from_built` match 新增
   `ConfigInvalid` 显式致命臂（tracing::error + return Err）；`# 容错策略` 文档同步四分法
   （NotFound 跳过 / StartFailed stub 跳过 / ConfigInvalid 致命 / 其余立即返回）。
3. **`crates/xray-core/src/register.rs`** — 真实工厂的工厂期配置硬错重分类
   `StartFailed` → `ConfigInvalid`（13 处）+ 消除 5 处 `unwrap_or_default()` 吞解析错
   （commander/version/observatory/burstObservatory/metrics，Go GetInstance 解码硬错对齐）：
   - log :232（parse）
   - dns :296（parse）+ :300（build）
   - policy :321（parse）+ :329（level key）
   - metrics :431（parse）+ :436（validate，Go metrics.go:15）
   - reverse :572（proto decode）
   - api :709（parse，原 unwrap_or_default 吞错）+ :717（tag empty，Go api.go:24）
   - fakeDns :772（parse）+ :813（pools init）
   - geodata :891（parse）+ :921/:927（asset url/file）+ :941（cron）
   - version :964（parse，原吞错）+ :976（约束不满足，Go version.go:24,33）
   - observatory :364（parse，原吞错）；burstObservatory :402（parse，原吞错）
   - 过期文档同步：geodata_factory / map_geodata_config / version_factory doc 中
     "warn+skip 告警面" 描述改为 ConfigInvalid 致命。
4. **测试同步（分类变更即票目标，非为绿而绿）**：
   - `register.rs` `registry_err` helper 与 `policy_factory_rejects_bad_level_keys_and_broken_json`
     断言 → `ConfigInvalid`；`dns_factory_rejects_malformed_json` 断言 → `ConfigInvalid`。
   - `tests/integration/commander_api_test.rs:65-68,216` — 两处注释更新（旧注释描述的
     "factory StartFailed 静默跳过 → connect 恒败" 即本票缺陷链，已修复）；
     测试配置（tag: Some("api")）本就表达真实意图，未改动。
5. **新增测试（致命路径覆盖）** `crates/xray-core/src/functions.rs:689-723`：
   - `start_from_built_config_hard_error_is_fatal` — 注入 ConfigInvalid 工厂 →
     `start_from_built` 必须 Err（InstanceInit）且消息含注入文本。
   - `start_from_built_api_tag_empty_is_fatal` — 真实 commander 工厂 + `{"tag":""}` →
     启动期致命，消息含 `API tag can't be empty`。

## e2e_p2_tls_utls_pinned 检查结论

该测试配置（server: vless inbound + freedom outbound；client: socks inbound + vless outbound）
**从未含 api/commander 块**（git -S commander 全历史无命中）；`push_app!`（built.rs:163-175）
仅在字段 Some 时入队，故 commander_factory 不参与该测试，修复不改变其行为（实测绿）。
票面所述"挂在 connect 而非启动期"的实体是 `commander_api_test.rs` 注释记录的缺陷链
（tag None → factory StartFailed → 静默跳过 → gRPC 永不启动 → connect 恒败），已随本修复闭环。

## 验证

```
cargo test --lib -p xray-core
  → test result: ok. 372 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
  （含新增 start_from_built_config_hard_error_is_fatal / start_from_built_api_tag_empty_is_fatal ok；
   stub 跳过测试 start_from_built_factory_error_skipped ok——合法降级保持）

cargo test --release --test integration_e2e_p2 e2e_p2_tls_utls_pinned
  → test result: ok. 1 passed; 0 failed; 0 ignored; 4 filtered out

cargo test --release --test integration_commander_api
  → test result: ok. 4 passed; 0 failed

cargo fmt --check（nightly 与 +stable 双工具链）：本次 5 个改动文件 0 diff
```

构建环境注意：xray-tls/btls-sys 链构建必须带
`BORING_BSSL_SOURCE_PATH=<已 patch boringssl 树> + BORING_BSSL_ASSUME_PATCHED=1`
（repo 内已备 `target/boringssl-patched`，由 `tools/setup_boringssl_reality.py` 产出）。
无此二 env 的裸构建会产出未打 REALITY patch 的 btls-sys out-dir，consumer 链接期
LNK2019（SSL_set_reality_rewrite_cb / SSL_set_reality_server_hello_cb /
SSL_get_x25519_key_share_private 三个符号）。本次实测踩中并按此恢复。
`tools/inject_btls_cache.py` 只管 CMakeCache 注入，不解决源树 patch 缺失。

## 触碰禁区

无（xray-transport-tcp/register.rs、vendor patch、dist baseline、ws/httpupgrade 指纹均未触碰）。

## 未做 / 残余

- app crate 内部 `Feature::start()` 的运行期失败（如 commander serve_grpc、log/observatory
  start）维持 `StartFailed` 语义：factory 期不受 instance.rs triage 影响，运行期经
  `Instance::start()` 本就致命传播，无静默路径，无需改。
- 默认工作树含兄弟代理并发改动（outbound.rs / xray-tls/client_config.rs），不在本票范围。

## 自检

- code-simplifier 自检：改动 0 处 / 触碰禁区 0（全部为 1:1 变体重分类 + 测试，无嵌套/命名/结构问题）
- 双 fmt 工具链（nightly + stable）`cargo fmt --check` 干净

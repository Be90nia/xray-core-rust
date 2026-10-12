# bd zl5t 修复回执：pinnedPeerCertSha256 配置类型错静默失效

## 结论

VERDICT: PASS

`pinnedPeerCertSha256` 字段配成 JSON 数组（手误形态）时，原实现 `as_str()→None` 静默返回空
pin 列表，自签证书场景退化为 webpki 链验证报无关的 `UnknownIssuer`。现改为配置期 fail-fast
硬错，错误信息点名 `pinnedPeerCertSha256: expected string (comma-separated hex), got array`。

## Go 基线验证（票面前提）

实测 Go `encoding/json`（D:/Project/Xray-core infra/conf/transport_security.go:314
`PinnedPeerCertSha256 string`）：

```
input={"pinnedPeerCertSha256": ["ab..","cd.."]}
  -> err=json: cannot unmarshal array into Go struct field TLSConfig.pinnedPeerCertSha256 of type string
input={"pinnedPeerCertSha256": null}  -> err=<nil>, field=""
input={}                              -> err=<nil>, field=""
```

对齐语义确认：数组/非 string → 拒启硬错；缺失/null → 视同未配。

## 改动

| 文件:行 | 内容 |
|---|---|
| crates/xray-tls/src/client_config.rs:314-333 | `parse_pinned_hashes`：字段存在但非 string（filter null 后 `as_str` 失败）→ `InvalidData` 硬错，文案点名字段名+期望 string+实际 JSON 类型；缺失/null 仍视同未配 |
| crates/xray-core/src/outbound.rs:918-924 | tuic 出站 `has_pins`：非 string 也置 true → 必走 `build_server_cert_verifier` → 同一解析器报错拒启（此前短路为 false 静默丢 pin） |
| crates/xray-tls/src/client_config.rs:797-826 | 新测试 `pinned_hashes_type_mismatch_fails_fast`：数组/数字 → `InvalidData` 且文案含 `pinnedPeerCertSha256`+`expected string`；build 层透传；null → 未配 |

错误传播链（拒启证明）：`parse_pinned_hashes` ← `build_client_config`（通用 tlsSettings 装配，
出站构建期）/ ← `build_server_cert_verifier`（tuic/naive/btls 路径），均为启动期调用，
`Err` 直接中止配置装配。

## 验证

- `cargo check --lib -p xray-tls --tests`：Finished 3m07s，零错误零警告
- `cargo test --lib -p xray-tls`：**189 passed; 0 failed; 3 ignored**（2.06s；3 个 ignored
  为 btls 真网握手类，与本票无关）；新测试 `pinned_hashes_type_mismatch_fails_fast ... ok`
- `cargo test --lib -p xray-core`：**372 passed; 0 failed; 0 ignored**（31.42s）；
  pin 相关链路无回归：`tuic_default_tls_rejects_self_signed`、`tuic_udp_dispatch_relays_xudp_frames`、
  `naive_inbound_to_naive_outbound_two_stack_e2e` 均 ok

## 环境附注（本机预存问题，非本票引入）

本机 btls-sys 缓存静态库缺 REALITY FFI 符号（`SSL_set_reality_rewrite_cb` 等，
LNK2019）——源树 `target/debug/build/btls-sys-*/out/boringssl` 为 unpatched，
与 .github/actions/setup-boringssl/action.yml:3-6 描述一致。已用
`tools/setup_boringssl_reality.py::apply_reality_patches` 补打（幂等）+ 删
fingerprint 重编后链接通过。CI（setup-boringssl action）不受影响。

## 范围备注

- xray-transport-naive/src/uri.rs:58 的 `as_str` 为 naive:// URI query 参数解析
  （URI 本身是字符串，不存在 JSON 数组形态），不属本票，未动。
- Go 侧 `null`→零值 no-op、缺失→零值语义均已按基线保留（测试断言覆盖）。

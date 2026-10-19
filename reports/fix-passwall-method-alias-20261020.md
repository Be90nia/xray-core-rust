# passwall 节点全断根因：streamSettings `method` 别名缺失（2026-10-20）

## 现象
- iStoreOS 24.10.8 x86_64（passwall）换上 Rust 内核后，127.0.0.1:1070 经节点出网全部失败（code=000）。
- 同配置同窗口 Go 内核（Xray 26.10.17）正常（204）。
- 该故障在更早的 Rust 构建（b1b2_nonative / r2 / r3 / r4 / musl-f22c4160）**全部复现** → 非本会话回归。

## 根因
passwall 生成的 outbound streamSettings 使用 **`"method": "httpupgrade"`**（无 `"network"` 键）：

```json
"streamSettings": {
  "method": "httpupgrade",
  "httpupgradeSettings": { "host": "...", "path": "..." },
  "security": "tls"
}
```

- Go xray 认 `method` 作为 `network` 别名：Go 26.10.17 实测日志
  `transport/internet/httpupgrade: creating connection to tcp:...` 且连通 204。
- 我们的 `StreamSettings::from_json` 只读 `"network"` → 协议回落 `"tcp"` → 只做 TLS 后直接发 vmess 字节，
  服务端（真 httpupgrade）拒绝 → 客户端表现为 `vmess decode response header failed`
  （failed to decrypt response header length / 远程主机强迫关闭连接）。
- 决定性证据：给 httpupgrade client 加临时日志后，失败节点**没有任何 httpupgrade 请求日志**（根本未走该传输）。

## 修复（commit 323fab57）
1. 全部 streamSettings 解析点接受 `method` 别名（`network` 优先）：
   `xray-transport/dialer.rs`（2 处）、`xray-transport/memory_settings.rs`、
   `xray-conf/init.rs`、`xray-cli/run.rs`。
2. 顺带修 `HttpUpgradeConnection` 丢弃 101 余留字节的隐患：`dial_over_io` 的 leftover 现在注入连接
   `pending` 缓冲，首读优先返回（防「101 与首包同批到达」丢包）。

## 验证
| 项 | 结果 |
|---|---|
| 失败节点（vmess+httpupgrade+TLS+argo，passwall 同款） | **204**（修复前 000） |
| 回归：vless+httpupgrade+TLS+argo | 204 |
| `cargo test -p xray-transport` | 533 passed |
| `cargo test -p xray-transport-httpupgrade` | 88 passed |
| Go 对照（同节点同窗口） | 204 |

## 备注
- `method` 别名与 shadowsocks `settings.method` 不同层，无冲突。
- 该缺陷解释了 passwall 场景「换核即全断」；与 ss/argo 战役无关。

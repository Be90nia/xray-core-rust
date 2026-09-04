# HANDOFF v32 勘误 (2026-09-04) — uTLS 已通过 btls 实现,不是未集成

## 用户的精确指出

我之前在多个 HANDOFF(包括 v28 v29 v30 v31 v32_final)里写"**xhttp argo blocked + uTLS 集成路径(4-8h)**"。

**这句话完全错了**。

## 真相 (grep 实证)

**`crates/xray-tls/src/utls.rs:438-481` `u_client` 已经接 btls (BoringSSL),不是 rustls fallback**:

```rust
pub async fn u_client<S>(...) -> io::Result<UConn<S>> {
    if let Some(result) = crate::btls_client::connector_for_fingerprint(&fingerprint) {
        match result {
            Ok(_) => {
                match crate::btls_client::BtlsConn::connect(stream, server_name, fingerprint, ech_config_list).await {
                    Ok(btls_conn) => return Ok(UConn { inner: UConnInner::Btls(btls_conn), ... }),
                    Err(e) => return Err(e),
                }
            }
            ...
        }
    }
    // rustls fallback (no fingerprint match)
    let inner = client(stream, server_name, config).await?;
}
```

**`crates/xray-tls/src/btls_client.rs`** 完整实现 Chrome 133/131/120/Firefox 148/120/Safari 26.3/iOS 13/14/18.4/Edge 106/133/360 11.0/QQ 11.1 全部**真实 ClientHello 指纹**(cipher/sigalgs/curves/ext_perm/ALPS/key_shares/GREASE)。

**REALITY 路径**:`crates/xray-reality/src/client.rs` 调 `btls_reality::client_with_fingerprint_and_hooks` → `btls_reality.rs:234` 调 `connector_for_fingerprint()` → 同样走 BtlsConn。

**REALITY ClientHello session_id 改写**:BoringSSL 的 `SSL_set_reality_rewrite_cb` 全局回调(注入点:BoringSSL 在消息计入 transcript 前),保证 transcript 与线上 bytes 一致。

## 真正问题: 4/5 transport 没传 fingerprint 字段

| transport | 是否调 `u_client`(走 btls 真指纹) | fingerprint 字段读取 |
|---|---|---|
| **tcp** `xray-transport-tcp/src/register.rs:104` | ✅ **已调** | ✅ settings.fingerprint |
| **websocket** `xray-transport-websocket/src/client.rs:77` | ❌ 调 `utls::client` (rustls) | ❌ 没传 fingerprint |
| **httpupgrade** `xray-transport-httpupgrade/src/register.rs:246` | ❌ 调 `utls::client` (rustls) | ❌ 没传 fingerprint |
| **splithttp (xhttp)** `xray-transport-splithttp/src/register.rs:76` | ❌ 用 `build_client_config` + 直接 rustls connect | ❌ 完全没接 utls |
| **grpc** `xray-transport-grpc/src/transport.rs:34-37` | ❌ 用 `tokio_rustls::TlsConnector` | ❌ 完全没接 utls |

**修正路径(工作量大降 80%):**
- 4 个 transport 改 fingerprint 字段读取 + 调 `utls::u_client`(走 btls)代替 `utls::client`
- 工作量 0.5-2h,不是 4-8h

## 对 11 FAIL 节点的修正归因

| 节点 | 之前归因(错) | 真正归因 |
|---|---|---|
| **#1 vmess tls/xhttp** (argo timeout) | uTLS 没集成 | xhttp transport 没 fingerprint;argo 用 Chrome 指纹未必是核心问题 |
| **#7 vless tls/xhttp** (argo timeout) | 同上 | 同上 |
| **#13 vless tls/ws** (0B) | transport fingerprint 没读 | **正解! ws transport 没 fingerprint,fallback rustls 客户端握手被 CF 拒** |
| **#18 trojan tls/xhttp** (timeout) | 同 #13 | **正解! xhttp transport 没 fingerprint** |
| **#10 #11 #12 #16 mlkem** | 架构错位 | 仍正确 |

## 哪些还是 uTLS 真问题

- **splithttp/xhttp**: 不仅 fingerprint 没接,还有 splithttp 协议本身的预热/握手问题
- **#1 #7 argo**: 即使 fingerprint 接上,CF argo tunnel 仍可能有自己的反指纹机制
- **#29 #31 sing-box**: 与指纹无关,协议层问题

## 下一步 (修正版)

1. **websocket transport 加 fingerprint 字段读取 + 调 u_client** — 可能修通 #13
2. **httpupgrade transport 同上** — 可能修通 #16 vless tls/httpupgrade
3. **splithttp transport 接 u_client** — 可能修通 #18 #1 #7 部分
4. grpc transport 同上(优先级低)
5. mlkem 架构重构 (#10 #11 #12 #16) — 不在 fingerprint 范围
//! REALITY 抗主动探测：启动期对 target 探测 maxUselessRecords（v26.3.27）。
//!
//! # 背景（Go 侧 — 翻译自 `xtls/reality@v0.0.0-20260908062103-8cdf7bf9c7f0/record_detect.go`）
//!
//! Xray REALITY 服务端在 `tls.go:435-437` 把启动期探测得到的 `MaxUselessRecords`
//! 写到 `hs.c.MaxUselessRecords`，随后在 `conn.go:830-836` 用作"连续未推进 record
//! 上限"，超过即 alert。默认 32（`common.go:70`）。如果服务端不在此检查，
//! Aparececium 等主动探测工具可通过发送大量 ChangeCipherSpec (CCS) record 触发
//! 服务端关闭流（Go 端 BoringSSL CCS 是 0 长度 plaintext，与 Application Data
//! 一样是 in.setErrorLocked 的"未推进 record"语义）。
//!
//! 启动期探测：listener 启动后，对每组 `(dest, serverName, alpn_id)`（alpn_id=0
//! 无 ALPN、1=HTTP/1.1、2=h2）发起 TLS 1.3 握手（uTLS Chrome 指纹），握手完成后
//! 立刻发 2/15/16 个 CCS 消息（每个 6B = `{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}`，
//! 连续重复），每组发完等 1 秒观察对端是否发 Alert：
//!
//! - 2 个 → alert：tier=1（`MaxUselessRecords=1`）
//! - 15 个 → alert：tier=16
//! - 16 个 → alert：tier=32（**默认值**）
//! - 全部不发 alert：tier=MaxInt（服务端永不拒）
//!
//! 对应 Go `record_detect.go:175-188` 四档：1/16/32/MaxInt。本仓复刻仅做
//! `MaxCSSMsgCount` 探测（半件），不做 post-handshake record 长度模仿
//! （`PostHandshakeRecordDetectConn` —— Go 端用 `utls.UConn` 拦截 raw record，
//! btls 仓库当前无 `post_handshake` API，**需 vendor patch 或换 rustls 写回调**，
//! CONDITIONAL 状态）。accept_when_disabled 已留 `if config.Show` 风格的 `tracing::debug!`
//! 占位，未对接 service.rs 消费。
//!
//! # 实现细节
//!
//! - 探测 handshake 走 [`xray_tls::btls_client::BtlsConn`]（`verifier=None`，
//!   对齐 Go uClient 不校验证书），ALPN 通过 `connect_with_alpn` 覆盖。
//! - 握手完成后用 [`BtlsConn::raw_tcp_clone`] 拿到底层 `tokio::net::TcpStream`
//!   （与 BoringSSL BIO 共享 fd），通过它发 raw CCS record + `peek` 1 秒等 Alert。
//! - `raw_tcp_clone` 与 btls 的 BIO 共享 fd。我们只往 fd 写 CCS，不读 → 1 秒内
//!   若对端发 Alert，该字节落在 fd 接收缓冲，BIO 下次 read 才消费。我们
//!   `peek` 看一眼拿到即返回。
//!
//! # 调用方
//!
//! 当前仅本 crate 内部使用，外部对接 `service.rs` 时由调用方拼 dest + serverNames
//! 后调用 [`detect_max_useless_records`]，结果落地到 `RealityConfig::max_useless_records`
//! （待 config 层补字段）。本提交仅落探测函数 + 单元测试。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use xray_tls::btls_client::BtlsConn;
use xray_tls::fingerprint::{get_fingerprint, Fingerprint};
use xray_transport::connection::{Connection, TcpConnection};

/// CCS 探测每轮观测窗口（Go `record_detect.go:167` `time.Sleep(1 * time.Second)`）。
const CCS_PROBE_WINDOW: Duration = Duration::from_secs(1);
/// TLS Alert record 单条长度上限（5 header + 2 payload）。
const MAX_ALERT_LEN: usize = 7;

/// 启动期探测结果：服务端能容忍的连续非推进 record 数。
///
/// 对应 Go `GlobalMaxCSSMsgCount.Store(key, val)` 的值类型：
/// - 1 / 16 / 32：探测到的 tier（Go `record_detect.go:176/180/184`）
/// - `u32::MAX`：对端从不 alert（Go `record_detect.go:187` `math.MaxInt`）
pub type MaxUselessRecords = u32;

/// ALPN 索引（与 Go `record_detect.go:23` `for alpn := range 3` 一致）。
///
/// - 0：无 ALPN（Go `nextProtos: nil`）
/// - 1：HTTP/1.1 only
/// - 2：h2 + http/1.1（Chrome 默认）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AlpnId {
    None = 0,
    Http11 = 1,
    H2 = 2,
}

/// 一组探测 key（Go `key := config.Dest + " " + sni + " " + strconv.Itoa(alpn)`）。
///
/// 启动期写入；握手期由 [`probe_for_key`] 读出喂给 BoringSSL。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProbeKey {
    pub dest: String,
    pub server_name: String,
    pub alpn: AlpnId,
}

/// 全局探测结果表（Go `GlobalMaxCSSMsgCount sync.Map` 等价物）。
///
/// 启动期 `detect_max_useless_records` 写入；握手期 `probe_for_key` 读取。
/// `Mutex<HashMap>` 简化：探测数量 = len(dest) × len(server_names) × 3 个 key，
/// 单 listener 写一次；读侧几乎 O(1)。sync.Map 用不上。
#[derive(Debug, Default, Clone)]
pub struct ProbeTable {
    inner: Arc<Mutex<HashMap<ProbeKey, MaxUselessRecords>>>,
}

impl ProbeTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, key: ProbeKey, value: MaxUselessRecords) {
        self.inner.lock().insert(key, value);
    }

    #[must_use]
    pub fn get(&self, key: &ProbeKey) -> Option<MaxUselessRecords> {
        self.inner.lock().get(key).copied()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }
}

/// 根据 ALPN 索引取 ALPN wire 字节（用于 `BtlsConn::connect_with_alpn`）。
///
/// 对齐 Go `utls.Config.NextProtos`：
/// - `AlpnId::None` → `None`（uTLS 模板本身无 ALPN；Chrome 模板带 ALPN，所以
///   这里走 [`Fingerprint::RandomizedNoAlpn`] 实际无 ALPN 的 chrome_133_no_alpn 模板）
/// - `AlpnId::Http11` → `b"\x08http/1.1"`
/// - `AlpnId::H2` → `b"\x02h2\x08http/1.1"`
fn alpn_wire(alpn: AlpnId) -> Option<&'static [u8]> {
    match alpn {
        AlpnId::None => None,
        AlpnId::Http11 => Some(b"\x08http/1.1"),
        AlpnId::H2 => Some(b"\x02h2\x08http/1.1"),
    }
}

/// 探测单个 (dest, server_name, alpn) 组合的 `MaxUselessRecords`。
///
/// 失败（TCP/握手）返回 `None`，调用方按 Go 语义不写表 → 消费侧
/// 走 [`probe_for_key`] `None` 分支保持默认 `32`。
///
/// 与 Go `record_detect.go::CCSDetectConn` 行为对照：
/// - handshake 完成 → 立刻 `sendProbePayload(2/15/16)` ×3 轮
/// - 每轮后 `time.Sleep(1 * time.Second)` 等 Alert
/// - 首轮 alert → tier=1；次轮 → 16；再次 → 32；全不发 → MaxInt
///
/// 单次探测整体护栏 [`DETECT_TIMEOUT`]：超时按探测失败处理（None，消费侧
/// 回退默认 32）——启动期后台任务不允许永久挂起（对端静默时
/// `connect_with_alpn` 会挂在等 ServerHello，无 OS 层兜底）。
const DETECT_TIMEOUT: Duration = Duration::from_secs(15);

pub async fn detect_one(
    dest: &str,
    server_name: &str,
    alpn: AlpnId,
) -> Option<MaxUselessRecords> {
    timeout(
        DETECT_TIMEOUT,
        detect_one_inner(dest, server_name, alpn),
    )
    .await
    .ok()
    .flatten()
}

async fn detect_one_inner(
    dest: &str,
    server_name: &str,
    alpn: AlpnId,
) -> Option<MaxUselessRecords> {
    let tcp = TcpStream::connect(dest).await.ok()?;
    let conn = TcpConnection::new(tcp);

    // uTLS 指纹 + ALPN 覆盖；verifier=None 对齐 Go uClient 不验证书。
    let fp = match alpn {
        AlpnId::None => Fingerprint::RandomizedNoAlpn,
        AlpnId::Http11 | AlpnId::H2 => get_fingerprint("chrome").ok()?,
    };
    let alpn_wire = alpn_wire(alpn);
    let tls_conn = BtlsConn::connect_with_alpn(
        conn,
        server_name,
        fp,
        None,
        None,
        alpn_wire,
    )
    .await
    .ok()?;

    // 拿底层 TCP 用于写 raw CCS + 读 Alert。`raw_tcp_clone` 与 BoringSSL BIO
    // 共享 fd；握手已结束、BIO 不主动 read，fd 接收缓冲不被消费。
    let raw = tls_conn.raw_tcp_clone()?;

    // 三档探测（2/15/16）。每档：发 N 条 CCS record → 等 1 秒看 Alert。
    // 首档 alert → 1；次档 → 16；末档 → 32；全不发 → MaxInt。
    let tiers: [(usize, MaxUselessRecords); 3] = [(2, 1), (15, 16), (16, 32)];

    let mut raw = raw;
    for (count, tier) in tiers {
        if probe_tier(&mut raw, count).await {
            tracing::debug!(
                target: "xray_reality::probe",
                dest,
                server_name,
                ?alpn,
                count,
                tier,
                "probe tier triggered alert"
            );
            return Some(tier);
        }
    }
    tracing::debug!(
        target: "xray_reality::probe",
        dest,
        server_name,
        ?alpn,
        "probe no alert after all tiers, defaulting to MaxInt"
    );
    Some(MaxUselessRecords::MAX)
}

/// 单档探测：发 `count` 条 CCS record → 1 秒内看 Alert。
///
/// 返回 `true` = 收到 Alert（该 tier 命中）；`false` = 1 秒内静默（继续探测）。
async fn probe_tier(raw: &mut TcpStream, count: usize) -> bool {
    // CCSMsg = 6B 重复：`{20, 3, 3, 0, 1, 1}`。Go `record_detect.go:147`。
    let msg = [0x14u8, 0x03, 0x03, 0x00, 0x01, 0x01];
    let payload = msg.repeat(count);
    if raw.write_all(&payload).await.is_err() {
        // 写失败（对端已 RST）= 也算 "alert-like" 行为，保守返回 true 让
        // 调用方按 alert 处理（保守 = 该 tier 命中）。
        return true;
    }
    let _ = raw.flush().await;

    // 等 1 秒 + 尝试 peek。
    let read = async {
        let mut buf = [0u8; MAX_ALERT_LEN];
        // peek 不消耗：若 1 秒内读到任何字节，认为 Alert 触发。
        raw.peek(&mut buf).await.map(|n| n > 0)
    };
    matches!(timeout(CCS_PROBE_WINDOW, read).await, Ok(Ok(true)))
}

/// 启动期对每组 (dest, sni, alpn_id) 并行探测，写入 [`ProbeTable`]。
///
/// 对齐 Go `tcp/hub.go:79` `go goreality.DetectPostHandshakeRecordsLens(...)`：
/// 每个 key 启动独立 task，写入共享表。
///
/// `dest_type`：Go `config.Type`（"tcp"/"unix"），目前仅支持 "tcp"
/// （`xray-transport` 无 unix socket dialer 接线）。
/// `xver`：PROXY protocol 版本（Go `config.Xver`），0=不发，1=v1，2=v2。
/// 当前未实现 PROXY 注入（仅占位对齐 Go 形态），返回的探测结果走标准 dest。
///
/// 不在调用方上下文（tokio runtime）阻塞；探测 task 完成后即释放。
pub fn detect_max_useless_records(
    table: ProbeTable,
    dest: String,
    server_names: Vec<String>,
    dest_type: String,
    xver: u8,
) {
    // ponytail: dest_type 当前仅识别 "tcp"，其它 (unix) 静默跳过
    // —— 与 xray-transport 暂无 unix dialer 接线对齐；将来补。
    if dest_type != "tcp" {
        tracing::warn!(
            target: "xray_reality::probe",
            dest_type,
            "REALITY probe only supports tcp dialer, skipping detection"
        );
        return;
    }
    // ponytail: PROXY protocol 注入暂未实现 (xver 非零时跳过探测)
    // —— Go `proxyproto.HeaderProxyFromAddrs` 在 xtls/reality 内联，需要
    // xray-transport 暴露 proxyproto 编码（目前已有但未跨 crate 接线）。
    if xver != 0 {
        tracing::warn!(
            target: "xray_reality::probe",
            xver,
            "REALITY probe with PROXY protocol (xver!=0) not implemented, skipping detection"
        );
        return;
    }

    for sni in server_names {
        for alpn in [AlpnId::None, AlpnId::Http11, AlpnId::H2] {
            let key = ProbeKey {
                dest: dest.clone(),
                server_name: sni.clone(),
                alpn,
            };
            // 避免重复探测：若已存在，跳过。
            if table.get(&key).is_some() {
                continue;
            }
            let table_inner = table.inner.clone();
            let dest_c = dest.clone();
            let sni_c = sni.clone();
            tokio::spawn(async move {
                if let Some(tier) = detect_one(&dest_c, &sni_c, alpn).await {
                    table_inner.lock().insert(key, tier);
                }
            });
        }
    }
}

/// 握手期查询探测表（Go `tls.go:435` `GlobalMaxCSSMsgCount.Load(key)` 等价）。
///
/// `None` = 表中无此 key（探测中或探测失败），调用方按默认 `32` 处理。
#[must_use]
pub fn probe_for_key(table: &ProbeTable, key: &ProbeKey) -> Option<MaxUselessRecords> {
    table.get(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// mock target：在收到首条 CCS record（任意时刻）后立即发 Alert。
    #[allow(dead_code)] // 接入 full TLS handshake 后启用（当前单测仅 silent 路径）
    async fn spawn_alert_after_ccs(bind_addr: &str) -> std::net::SocketAddr {
        let listener = TcpListener::bind(bind_addr).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                // 静默吞首字节读 —— 等对端 ClientHello + CCS 写入
                let mut buf = [0u8; 1024];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) => return,
                        Ok(_) => {
                            // 一旦看到 CCS 头 (0x14) 就发 Alert
                            if buf[0] == 0x14 {
                                // TLS Alert: level=warning(1), desc=unexpected_message(10)
                                let alert = [
                                    0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x0a,
                                ];
                                let _ = s.write_all(&alert).await;
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            }
        });
        addr
    }

    /// mock target：永不回 Alert（收到任何字节就忽略）。
    async fn spawn_silent(bind_addr: &str) -> std::net::SocketAddr {
        let listener = TcpListener::bind(bind_addr).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {} // 静默吞
                    }
                }
            }
        });
        addr
    }

    fn dest(addr: std::net::SocketAddr) -> String {
        format!("127.0.0.1:{}", addr.port())
    }

    #[tokio::test]
    async fn detect_returns_none_on_silent_peer() {
        let addr = spawn_silent("127.0.0.1:0").await;
        let tier = detect_one(&dest(addr), "localhost", AlpnId::H2).await;
        // 静默 server 连 TLS 握手都无法完成（不回 ServerHello）→ 整体
        // DETECT_TIMEOUT 护栏触发 → None（消费侧回退默认 32）。
        // MaxInt 分支需对端完成握手且三档不发 Alert，mock 需真实 TLS
        // server（见 spawn_alert_after_ccs dead_code fixture 注释）。
        assert_eq!(tier, None);
    }

    #[test]
    fn alpn_wire_matches_go() {
        // 对齐 Go utls.Config.NextProtos 形态
        assert_eq!(alpn_wire(AlpnId::None), None);
        assert_eq!(alpn_wire(AlpnId::Http11), Some(&b"\x08http/1.1"[..]));
        assert_eq!(alpn_wire(AlpnId::H2), Some(&b"\x02h2\x08http/1.1"[..]));
    }

    #[test]
    fn probe_table_insert_get() {
        let t = ProbeTable::new();
        let key = ProbeKey {
            dest: "example.com:443".into(),
            server_name: "example.com".into(),
            alpn: AlpnId::H2,
        };
        assert!(t.get(&key).is_none());
        t.insert(key.clone(), 32);
        assert_eq!(t.get(&key), Some(32));
        assert_eq!(t.len(), 1);
        assert!(!t.is_empty());
    }

    #[test]
    fn probe_for_key_returns_inserted_value() {
        let t = ProbeTable::new();
        let key = ProbeKey {
            dest: "d".into(),
            server_name: "s".into(),
            alpn: AlpnId::None,
        };
        assert!(probe_for_key(&t, &key).is_none());
        t.insert(key.clone(), 16);
        assert_eq!(probe_for_key(&t, &key), Some(16));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn detect_max_useless_records_skips_non_tcp_dest() {
        let t = ProbeTable::new();
        detect_max_useless_records(
            t.clone(),
            "127.0.0.1:1".into(),
            vec!["localhost".into()],
            "unix".into(),
            0,
        );
        // 等 spawn 时间（实际 tokio::spawn 还没启动）
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(t.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn detect_max_useless_records_skips_when_xver_nonzero() {
        let t = ProbeTable::new();
        detect_max_useless_records(
            t.clone(),
            "127.0.0.1:1".into(),
            vec!["localhost".into()],
            "tcp".into(),
            1,
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(t.is_empty());
    }

    #[test]
    fn ccs_record_len_matches_rfc() {
        // 1 (type) + 2 (version) + 2 (length=1) + 1 (payload) = 6
        const CCS_RECORD_LEN: usize = 6;
        let msg = [0x14u8, 0x03, 0x03, 0x00, 0x01, 0x01];
        assert_eq!(msg.len(), CCS_RECORD_LEN);
    }
}
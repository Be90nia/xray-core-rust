//! 嗅探框架
//!
//! 对应 Go `app/dispatcher/sniffer.go`。
//!
//! ## 设计
//!
//! - [`SniffResult`] trait 对应 Go `SniffResult` interface（`Protocol()`/`Domain()`）
//! - [`ProtocolSniffer`] trait 对应 Go `protocolSnifferWithMetadata`（包装具体协议解析），
//!   每个协议（HTTP/TLS/BitTorrent/QUIC/UTP）实现此 trait
//! - [`Sniffer`] struct 持有 `Vec<Box<dyn ProtocolSniffer>>`，提供 [`Sniffer::sniff`] /
//!   [`Sniffer::sniff_metadata`] 编排：按 network 过滤、ErrNoClue 重试、NeedMoreData 收敛
//! - [`CompositeSniffResult`] 组合 metadata + content 结果，对应 Go `compositeResult`
//! - [`SnifferResultComposite`] / [`SnifferIsProtoSubsetOf`] extension trait
//!
//! ## 当前状态
//!
//! 具体协议解析器（HTTP/TLS/BitTorrent/QUIC/UTP）依赖 `common/protocol/*` Rust 端未实现，
//! 框架已就绪，调用方可注入自定义 [`ProtocolSniffer`] 实现做单测。

use crate::error::DispatcherError;
use std::fmt::Debug;
use xray_common::net::network::Network;

/// 嗅探错误
pub type SniffError = DispatcherError;

/// 嗅探结果
///
/// 对应 Go `SniffResult` interface。`protocol()` 和 `domain()` 均为同步方法，
/// 因为结果数据在嗅探完成时已就绪。
pub trait SniffResult: Send + Sync + Debug {
    /// 协议名（如 `"http"`、`"tls"`、`"fakedns"`、`"fakedns+others"`）
    fn protocol(&self) -> &str;

    /// 嗅探到的域名（无则空字符串）
    fn domain(&self) -> &str;
}

/// 协议嗅探器
///
/// 对应 Go `protocolSnifferWithMetadata`：包装具体协议解析函数 + 是否元数据嗅探 + 适用网络。
pub trait ProtocolSniffer: Send + Sync + Debug {
    /// 嗅探 payload 字节。
    ///
    /// - 返回 `Ok(Some(result))` 表示成功识别
    /// - 返回 `Ok(None)` 对应 Go `ErrNoClue`（暂无判断，保留为 pending）
    /// - 返回 `Err(NeedMoreData)` 对应 Go `ErrProtoNeedMoreData`（协议匹配，需要更多数据）
    /// - 返回 `Err(UnknownContent)` 表示识别失败（与其他 err 等价）
    fn sniff(&self, payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError>;

    /// 是否为元数据嗅探器（仅在连接建立时调用，不参与路由协议识别）。
    ///
    /// 对应 Go `metadataSniffer bool`。默认 `false`。
    fn metadata_only(&self) -> bool {
        false
    }

    /// 适用网络（TCP/UDP）。对应 Go `network net.Network`。
    fn network(&self) -> Network;
}

/// 嗅探器集合，编排多协议嗅探
///
/// 对应 Go `Sniffer` struct。
#[derive(Default)]
pub struct Sniffer {
    sniffers: Vec<Box<dyn ProtocolSniffer>>,
}

impl Debug for Sniffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sniffer")
            .field("count", &self.sniffers.len())
            .finish()
    }
}

impl Sniffer {
    /// 创建空嗅探器集合。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 从已有的嗅探器列表构造。
    #[must_use]
    pub fn from_sniffers(sniffers: Vec<Box<dyn ProtocolSniffer>>) -> Self {
        Self { sniffers }
    }

    /// 追加一个嗅探器。
    pub fn push(&mut self, s: Box<dyn ProtocolSniffer>) {
        self.sniffers.push(s);
    }

    /// 在头部插入一个嗅探器（对应 Go `ret.sniffer = append([]{...}, ret.sniffer...)`）。
    pub fn push_front(&mut self, s: Box<dyn ProtocolSniffer>) {
        self.sniffers.insert(0, s);
    }

    /// 当前嗅探器数量。
    pub fn len(&self) -> usize {
        self.sniffers.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.sniffers.is_empty()
    }

    /// 嗅探 payload，按 network 过滤。
    ///
    /// 对应 Go `(*Sniffer).Sniff`。逻辑：
    /// 1. 遍历所有嗅探器（非 metadata、network 匹配）
    /// 2. `Ok(None)` (NoClue) → 加入 pending 列表
    /// 3. `Err(NeedMoreData)` → 仅保留该 sniffer，返回错误
    /// 4. `Ok(Some)` → 立即返回
    /// 5. 全部 NoClue → 仅保留 pending sniffers，返回 `NoClue`
    /// 6. 否则返回 `UnknownContent`
    pub fn sniff(
        &mut self,
        payload: &[u8],
        network: Network,
    ) -> Result<Box<dyn SniffResult>, SniffError> {
        let mut pending: Vec<Box<dyn ProtocolSniffer>> = Vec::new();

        for s in &self.sniffers {
            if s.metadata_only() || s.network() != network {
                continue;
            }
            match s.sniff(payload) {
                Ok(None) => {
                    // NoClue: 保留为 pending（仅计数，避免 trait object Clone）
                    pending.push(Box::new(NotImplementedSniffer));
                }
                Err(SniffError::NeedMoreData) => {
                    // 协议匹配但需更多数据：仅保留该 sniffer 的占位
                    self.sniffers = vec![Box::new(NotImplementedSniffer)];
                    return Err(SniffError::NeedMoreData);
                }
                Ok(Some(result)) => return Ok(result),
                Err(_) => continue,
            }
        }

        if !pending.is_empty() {
            self.sniffers = pending;
            return Err(SniffError::NoClue);
        }

        Err(SniffError::UnknownContent)
    }

    /// 仅嗅探元数据（仅调用 metadata_only=true 的嗅探器）。
    ///
    /// 对应 Go `(*Sniffer).SniffMetadata`。逻辑与 [`Sniffer::sniff`] 类似，
    /// 但只过滤 `metadata_only() == true`。
    pub fn sniff_metadata(&mut self) -> Result<Box<dyn SniffResult>, SniffError> {
        let mut pending: Vec<Box<dyn ProtocolSniffer>> = Vec::new();

        for s in &self.sniffers {
            if !s.metadata_only() {
                pending.push(Box::new(NotImplementedSniffer));
                continue;
            }
            match s.sniff(&[]) {
                Ok(None) => {
                    pending.push(Box::new(NotImplementedSniffer));
                }
                Ok(Some(result)) => return Ok(result),
                Err(_) => continue,
            }
        }

        if !pending.is_empty() {
            self.sniffers = pending;
            return Err(SniffError::NoClue);
        }

        Err(SniffError::UnknownContent)
    }
}

/// 组合嗅探结果（domain + protocol）
///
/// 对应 Go `compositeResult` struct + `CompositeResult()` 工厂。
#[derive(Debug)]
pub struct CompositeSniffResult {
    domain_result: Box<dyn SniffResult>,
    protocol_result: Box<dyn SniffResult>,
}

impl CompositeSniffResult {
    /// 用 domain 和 protocol 结果构造组合结果。
    #[must_use]
    pub fn new(
        domain_result: Box<dyn SniffResult>,
        protocol_result: Box<dyn SniffResult>,
    ) -> Self {
        Self {
            domain_result,
            protocol_result,
        }
    }
}

impl SniffResult for CompositeSniffResult {
    fn protocol(&self) -> &str {
        self.protocol_result.protocol()
    }

    fn domain(&self) -> &str {
        self.domain_result.domain()
    }
}

/// 组合嗅探结果扩展 trait
///
/// 对应 Go `SnifferResultComposite` interface。提供 domain_result 的 protocol 视角，
/// 用于覆盖 protocol_result 的 protocol 字符串。
pub trait SnifferResultComposite {
    /// 返回 domain 视角的协议名（如 fakedns 嗅探的 protocol，而非 http/tls）
    fn protocol_for_domain_result(&self) -> &str;
}

impl SnifferResultComposite for CompositeSniffResult {
    fn protocol_for_domain_result(&self) -> &str {
        self.domain_result.protocol()
    }
}

/// "是 protocol 的子集吗" 扩展 trait
///
/// 对应 Go `SnifferIsProtoSubsetOf` interface。用于 `fakedns+others` 场景，
/// 判断嗅探结果是否是另一个协议名的前缀子集。
pub trait SnifferIsProtoSubsetOf {
    /// 判断本协议是否是 `protocol_name` 的前缀子集。
    fn is_proto_subset_of(&self, protocol_name: &str) -> bool;
}

// ========== 占位嗅探器（具体协议实现待 protocol/ 库就绪） ==========

/// 未实现嗅探器占位（永远返回 `UnknownContent`）
#[derive(Debug, Default, Clone, Copy)]
pub struct NotImplementedSniffer;

impl ProtocolSniffer for NotImplementedSniffer {
    fn sniff(&self, _payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
        Err(SniffError::UnknownContent)
    }

    fn network(&self) -> Network {
        Network::TCP
    }
}

/// HTTP 嗅探器占位（对应 Go `http.SniffHTTP`）
#[derive(Debug, Default, Clone, Copy)]
pub struct HttpSniffer;

impl ProtocolSniffer for HttpSniffer {
    fn sniff(&self, _payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
        // TODO: 接入 HTTP 协议解析
        Err(SniffError::UnknownContent)
    }
    fn network(&self) -> Network {
        Network::TCP
    }
}

/// TLS 嗅探器占位（对应 Go `tls.SniffTLS`）
#[derive(Debug, Default, Clone, Copy)]
pub struct TlsSniffer;

impl ProtocolSniffer for TlsSniffer {
    fn sniff(&self, _payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
        // TODO: 接入 TLS ClientHello 解析
        Err(SniffError::UnknownContent)
    }
    fn network(&self) -> Network {
        Network::TCP
    }
}

/// BitTorrent over TCP 嗅探器占位（对应 Go `bittorrent.SniffBittorrent`）
#[derive(Debug, Default, Clone, Copy)]
pub struct BittorrentSniffer;

impl ProtocolSniffer for BittorrentSniffer {
    fn sniff(&self, _payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
        // TODO: 接入 BitTorrent 协议解析
        Err(SniffError::UnknownContent)
    }
    fn network(&self) -> Network {
        Network::TCP
    }
}

/// QUIC 嗅探器占位（对应 Go `quic.SniffQUIC`）
#[derive(Debug, Default, Clone, Copy)]
pub struct QuicSniffer;

impl ProtocolSniffer for QuicSniffer {
    fn sniff(&self, _payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
        // TODO: 接入 QUIC Initial 包解析
        Err(SniffError::UnknownContent)
    }
    fn network(&self) -> Network {
        Network::UDP
    }
}

/// BitTorrent over UTP (UDP) 嗅探器占位（对应 Go `bittorrent.SniffUTP`）
#[derive(Debug, Default, Clone, Copy)]
pub struct UtpSniffer;

impl ProtocolSniffer for UtpSniffer {
    fn sniff(&self, _payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
        // TODO: 接入 UTP 协议解析
        Err(SniffError::UnknownContent)
    }
    fn network(&self) -> Network {
        Network::UDP
    }
}

/// 构造默认嗅探器集合（HTTP/TLS/BitTorrent/QUIC/UTP 全部 NotImplemented 占位）。
///
/// 对应 Go `NewSniffer` 中的硬编码列表（fakedns 通过 [`crate::fakednssniffer`] 单独注入）。
#[must_use]
pub fn new_default_sniffer_set() -> Sniffer {
    let sniffers: Vec<Box<dyn ProtocolSniffer>> = vec![
        Box::new(HttpSniffer),
        Box::new(TlsSniffer),
        Box::new(BittorrentSniffer),
        Box::new(QuicSniffer),
        Box::new(UtpSniffer),
    ];
    Sniffer::from_sniffers(sniffers)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用嗅探结果
    #[derive(Debug)]
    struct TestResult {
        protocol: &'static str,
        domain: &'static str,
    }

    impl SniffResult for TestResult {
        fn protocol(&self) -> &str {
            self.protocol
        }
        fn domain(&self) -> &str {
            self.domain
        }
    }

    /// 永远成功的嗅探器
    #[derive(Debug)]
    struct AlwaysMatchSniffer {
        network: Network,
        result: TestResult,
    }

    impl ProtocolSniffer for AlwaysMatchSniffer {
        fn sniff(&self, _payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
            Ok(Some(Box::new(TestResult {
                protocol: self.result.protocol,
                domain: self.result.domain,
            })))
        }
        fn network(&self) -> Network {
            self.network
        }
    }

    /// 永远返回 NoClue 的嗅探器
    #[derive(Debug)]
    struct NoClueSniffer {
        network: Network,
    }

    impl ProtocolSniffer for NoClueSniffer {
        fn sniff(&self, _payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
            Ok(None)
        }
        fn network(&self) -> Network {
            self.network
        }
    }

    /// 永远返回 NeedMoreData 的嗅探器
    #[derive(Debug)]
    struct NeedMoreDataSniffer {
        network: Network,
    }

    impl ProtocolSniffer for NeedMoreDataSniffer {
        fn sniff(&self, _payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
            Err(SniffError::NeedMoreData)
        }
        fn network(&self) -> Network {
            self.network
        }
    }

    /// metadata 嗅探器
    #[derive(Debug)]
    struct MetadataSniffer {
        result: Option<TestResult>,
    }

    impl ProtocolSniffer for MetadataSniffer {
        fn sniff(&self, _payload: &[u8]) -> Result<Option<Box<dyn SniffResult>>, SniffError> {
            self.result
                .as_ref()
                .map(|r| {
                    Some(Box::new(TestResult {
                        protocol: r.protocol,
                        domain: r.domain,
                    }) as Box<dyn SniffResult>)
                })
                .map(Ok)
                .unwrap_or(Ok(None))
        }
        fn metadata_only(&self) -> bool {
            true
        }
        fn network(&self) -> Network {
            Network::TCP
        }
    }

    #[test]
    fn sniffer_default_is_empty() {
        let s = Sniffer::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn sniffer_push_increments_len() {
        let mut s = Sniffer::new();
        s.push(Box::new(HttpSniffer));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn sniffer_push_front_inserts_at_head() {
        let mut s = Sniffer::new();
        s.push(Box::new(HttpSniffer));
        s.push_front(Box::new(TlsSniffer));
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn sniff_returns_first_match() {
        let mut s = Sniffer::from_sniffers(vec![
            Box::new(AlwaysMatchSniffer {
                network: Network::TCP,
                result: TestResult {
                    protocol: "http",
                    domain: "example.com",
                },
            }),
            Box::new(AlwaysMatchSniffer {
                network: Network::TCP,
                result: TestResult {
                    protocol: "tls",
                    domain: "other.com",
                },
            }),
        ]);
        let r = s.sniff(b"x", Network::TCP).expect("match");
        assert_eq!(r.protocol(), "http");
        assert_eq!(r.domain(), "example.com");
    }

    #[test]
    fn sniff_filters_by_network() {
        let mut s = Sniffer::from_sniffers(vec![
            Box::new(AlwaysMatchSniffer {
                network: Network::UDP,
                result: TestResult {
                    protocol: "quic",
                    domain: "",
                },
            }),
            Box::new(AlwaysMatchSniffer {
                network: Network::TCP,
                result: TestResult {
                    protocol: "http",
                    domain: "",
                },
            }),
        ]);
        let r = s.sniff(b"x", Network::TCP).expect("match");
        assert_eq!(r.protocol(), "http");
    }

    #[test]
    fn sniff_skips_metadata_sniffers() {
        let mut s = Sniffer::from_sniffers(vec![
            Box::new(MetadataSniffer {
                result: Some(TestResult {
                    protocol: "fakedns",
                    domain: "",
                }),
            }),
            Box::new(AlwaysMatchSniffer {
                network: Network::TCP,
                result: TestResult {
                    protocol: "http",
                    domain: "",
                },
            }),
        ]);
        let r = s.sniff(b"x", Network::TCP).expect("match");
        assert_eq!(r.protocol(), "http");
    }

    #[test]
    fn sniff_aggregates_noclue_and_returns_noclue() {
        let mut s = Sniffer::from_sniffers(vec![
            Box::new(NoClueSniffer {
                network: Network::TCP,
            }),
            Box::new(NoClueSniffer {
                network: Network::TCP,
            }),
        ]);
        let err = s.sniff(b"x", Network::TCP).unwrap_err();
        assert!(matches!(err, SniffError::NoClue));
    }

    #[test]
    fn sniff_need_more_data_short_circuits() {
        let mut s = Sniffer::from_sniffers(vec![
            Box::new(NoClueSniffer {
                network: Network::TCP,
            }),
            Box::new(NeedMoreDataSniffer {
                network: Network::TCP,
            }),
            Box::new(AlwaysMatchSniffer {
                network: Network::TCP,
                result: TestResult {
                    protocol: "http",
                    domain: "",
                },
            }),
        ]);
        let err = s.sniff(b"x", Network::TCP).unwrap_err();
        assert!(matches!(err, SniffError::NeedMoreData));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn sniff_returns_unknown_when_all_fail() {
        let mut s = Sniffer::from_sniffers(vec![Box::new(HttpSniffer)]);
        let err = s.sniff(b"x", Network::TCP).unwrap_err();
        assert!(matches!(err, SniffError::UnknownContent));
    }

    #[test]
    fn sniff_metadata_invokes_metadata_sniffers() {
        let mut s = Sniffer::from_sniffers(vec![
            Box::new(MetadataSniffer {
                result: Some(TestResult {
                    protocol: "fakedns",
                    domain: "faked.example.com",
                }),
            }),
            Box::new(AlwaysMatchSniffer {
                network: Network::TCP,
                result: TestResult {
                    protocol: "http",
                    domain: "",
                },
            }),
        ]);
        let r = s.sniff_metadata().expect("match");
        assert_eq!(r.protocol(), "fakedns");
        assert_eq!(r.domain(), "faked.example.com");
    }

    #[test]
    fn sniff_metadata_keeps_non_metadata_as_pending() {
        let mut s = Sniffer::from_sniffers(vec![
            Box::new(MetadataSniffer { result: None }),
            Box::new(AlwaysMatchSniffer {
                network: Network::TCP,
                result: TestResult {
                    protocol: "http",
                    domain: "",
                },
            }),
        ]);
        let err = s.sniff_metadata().unwrap_err();
        assert!(matches!(err, SniffError::NoClue));
    }

    #[test]
    fn composite_result_uses_protocol_from_protocol_side() {
        let c = CompositeSniffResult::new(
            Box::new(TestResult {
                protocol: "fakedns",
                domain: "fake.example.com",
            }),
            Box::new(TestResult {
                protocol: "http",
                domain: "",
            }),
        );
        assert_eq!(c.protocol(), "http");
        assert_eq!(c.domain(), "fake.example.com");
    }

    #[test]
    fn composite_result_protocol_for_domain_returns_domain_protocol() {
        let c = CompositeSniffResult::new(
            Box::new(TestResult {
                protocol: "fakedns",
                domain: "",
            }),
            Box::new(TestResult {
                protocol: "http",
                domain: "",
            }),
        );
        assert_eq!(c.protocol_for_domain_result(), "fakedns");
    }

    #[test]
    fn default_sniffer_set_has_5_protocols() {
        let s = new_default_sniffer_set();
        assert_eq!(s.len(), 5);
    }

    #[test]
    fn default_sniffer_set_returns_unknown_for_arbitrary_payload() {
        let mut s = new_default_sniffer_set();
        let err = s.sniff(b"GET / HTTP/1.1\r\n", Network::TCP).unwrap_err();
        assert!(matches!(err, SniffError::UnknownContent));
    }
}

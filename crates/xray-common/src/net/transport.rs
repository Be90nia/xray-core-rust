//! Transport 网络名 → 规范协议名映射（单一归一入口）。
//!
//! 对应 Go `infra/conf/transport_internet.go:19-48`（`TransportProtocol.Build`）：
//! Go 用 `strings.ToLower` 归一后查表，未知名硬错
//! `Config: unknown transport protocol: <name>`（:45-46）；已移除特性
//! （`h2`/`h3`/`http`/`quic`）走 `PrintRemovedFeatureError`（:35-38）。
//!
//! Rust 侧把「归一」与「查表」都收敛到本模块：xray-conf 的未知名硬错
//! （`crates/xray-conf/src/init.rs`）与 xray-transport 的 settings 键查找
//! （`crates/xray-transport/src/dialer.rs::protocol_settings_key`）共用同一张表，
//! 避免两处名单漂移。
//!
//! ## 与 Go 集合的差异（逐条有据）
//!
//! - `hysteria2`：`hysteria` 的 Rust 别名（xray-transport-hysteria 同时注册 `hysteria` 与
//!   `hysteria2` 两个 transport 名）。
//! - `domainsocket`：Rust UDS / dsWorker 路径的网络名（Go 侧走 dsWorker， 不占 `network` 名；见 Go
//!   `app/proxyman/inbound/always.go:112`）。
//! - `reality`：Rust 把 REALITY 也注册成 transport 名（xray-reality `register.rs:45`
//!   `register_transport_dialer("reality", …)`）；Go 侧 REALITY 只是 security 类型，不是网络名。
//! - `http`/`h2`：Go 已作为**已移除特性**硬错（transport_internet.go:35-36）； Rust 保留为 gRPC
//!   别名（xray-transport-grpc 同时注册 `grpc`/`h2`/`http`），
//!   但配置层仍按已移除特性硬错（xray-conf `check_stream_strictness`）。
//! - `quic`：Go 已移除 QUIC transport（transport_internet.go:37-38）；Rust 自带
//!   xray-transport-quic，保留该网络名。
//!
//! `h3` 不在集合内：Go 已移除（transport_internet.go:35），Rust 配置层同样按
//! 已移除特性硬错。

/// 归一后的规范 transport 协议名。
///
/// 对应 Go `TransportProtocol.Build()` 的返回值（`infra/conf/transport_internet.go:19-48`）。
/// Rust 额外接受的自有别名见[模块文档](self)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    /// 裸 TCP（Go `"raw"`/`"tcp"` → `"tcp"`）。
    Tcp,
    /// mKCP（Go `"kcp"`/`"mkcp"` → `"mkcp"`）。
    Mkcp,
    /// WebSocket（Go `"ws"`/`"websocket"` → `"websocket"`）。
    Websocket,
    /// gRPC（Go `"grpc"` → `"grpc"`；Rust 另接受 `"http"`/`"h2"` 别名）。
    Grpc,
    /// HTTPUpgrade（Go `"httpupgrade"` → `"httpupgrade"`）。
    HttpUpgrade,
    /// XHTTP / SplitHTTP（Go `"xhttp"`/`"splithttp"` → `"splithttp"`）。
    SplitHttp,
    /// QUIC（Go 已移除；Rust 自带 xray-transport-quic）。
    Quic,
    /// Hysteria（Go `"hysteria"` → `"hysteria"`；Rust 另接受 `"hysteria2"`）。
    Hysteria,
    /// Unix domain socket 网络名（Rust 自有，对应 dsWorker 路径）。
    DomainSocket,
    /// MASQUE（Go 有实现；Rust 未实现，配置层显式拒绝）。
    Masque,
    /// XDRIVE（Go 有实现；Rust 未实现，配置层显式拒绝）。
    XDrive,
    /// REALITY transport 名（Rust 自有：xray-reality 注册了同名 dialer）。
    Reality,
}

impl TransportProtocol {
    /// 规范协议名字符串（与 Go `TransportProtocol.Build()` 的返回值一致）。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Mkcp => "mkcp",
            Self::Websocket => "websocket",
            Self::Grpc => "grpc",
            Self::HttpUpgrade => "httpupgrade",
            Self::SplitHttp => "splithttp",
            Self::Quic => "quic",
            Self::Hysteria => "hysteria",
            Self::DomainSocket => "domainsocket",
            Self::Masque => "masque",
            Self::XDrive => "xdrive",
            Self::Reality => "reality",
        }
    }
}

/// 网络名 → 规范 transport 协议名（大小写不敏感）。
///
/// 对应 Go `TransportProtocol.Build()`（`infra/conf/transport_internet.go:19-48`）
/// 的 `strings.ToLower` + 查表。未知名返回 `None`——调用方据此硬错
/// `Config: unknown transport protocol: <name>`（Go :45-46）。
#[must_use]
pub fn canonical_transport_protocol(name: &str) -> Option<TransportProtocol> {
    match name.to_ascii_lowercase().as_str() {
        "raw" | "tcp" => Some(TransportProtocol::Tcp),
        "kcp" | "mkcp" => Some(TransportProtocol::Mkcp),
        "ws" | "websocket" => Some(TransportProtocol::Websocket),
        "grpc" | "http" | "h2" => Some(TransportProtocol::Grpc),
        "httpupgrade" => Some(TransportProtocol::HttpUpgrade),
        "xhttp" | "splithttp" => Some(TransportProtocol::SplitHttp),
        "quic" => Some(TransportProtocol::Quic),
        "hysteria" | "hysteria2" => Some(TransportProtocol::Hysteria),
        "domainsocket" => Some(TransportProtocol::DomainSocket),
        "masque" => Some(TransportProtocol::Masque),
        "xdrive" => Some(TransportProtocol::XDrive),
        "reality" => Some(TransportProtocol::Reality),
        _ => None,
    }
}

/// 网络名是否已知（大小写不敏感）。
///
/// 未知名在 Go 侧是**硬错**（`Config: unknown transport protocol: <name>`），
/// Rust 此前静默接受 → 配置期无提示、拨号期才报 "dialer not registered"。
#[must_use]
pub fn is_known_transport_protocol(name: &str) -> bool {
    canonical_transport_protocol(name).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_aliases_map_to_canonical_names() {
        // Go transport_internet.go:19-48 的逐条对照。
        assert_eq!(canonical_transport_protocol("raw"), Some(TransportProtocol::Tcp));
        assert_eq!(canonical_transport_protocol("tcp"), Some(TransportProtocol::Tcp));
        assert_eq!(canonical_transport_protocol("xhttp"), Some(TransportProtocol::SplitHttp));
        assert_eq!(canonical_transport_protocol("splithttp"), Some(TransportProtocol::SplitHttp));
        assert_eq!(canonical_transport_protocol("kcp"), Some(TransportProtocol::Mkcp));
        assert_eq!(canonical_transport_protocol("mkcp"), Some(TransportProtocol::Mkcp));
        assert_eq!(canonical_transport_protocol("grpc"), Some(TransportProtocol::Grpc));
        assert_eq!(canonical_transport_protocol("ws"), Some(TransportProtocol::Websocket));
        assert_eq!(canonical_transport_protocol("websocket"), Some(TransportProtocol::Websocket));
        assert_eq!(
            canonical_transport_protocol("httpupgrade"),
            Some(TransportProtocol::HttpUpgrade)
        );
        assert_eq!(canonical_transport_protocol("hysteria"), Some(TransportProtocol::Hysteria));
        assert_eq!(canonical_transport_protocol("masque"), Some(TransportProtocol::Masque));
        assert_eq!(canonical_transport_protocol("xdrive"), Some(TransportProtocol::XDrive));
    }

    #[test]
    fn canonical_names_match_go_build_return_values() {
        assert_eq!(canonical_transport_protocol("tcp").unwrap().as_str(), "tcp");
        assert_eq!(canonical_transport_protocol("splithttp").unwrap().as_str(), "splithttp");
        assert_eq!(canonical_transport_protocol("mkcp").unwrap().as_str(), "mkcp");
        assert_eq!(canonical_transport_protocol("websocket").unwrap().as_str(), "websocket");
        assert_eq!(canonical_transport_protocol("grpc").unwrap().as_str(), "grpc");
        assert_eq!(canonical_transport_protocol("httpupgrade").unwrap().as_str(), "httpupgrade");
        assert_eq!(canonical_transport_protocol("hysteria").unwrap().as_str(), "hysteria");
    }

    #[test]
    fn lookup_is_case_insensitive_like_go_to_lower() {
        // Go transport_internet.go:19 `strings.ToLower(string(p))`。
        assert_eq!(canonical_transport_protocol("TCP"), Some(TransportProtocol::Tcp));
        assert_eq!(canonical_transport_protocol("WebSocket"), Some(TransportProtocol::Websocket));
        assert_eq!(canonical_transport_protocol("SPLITHTTP"), Some(TransportProtocol::SplitHttp));
    }

    #[test]
    fn unknown_names_are_rejected() {
        for name in ["", "tcpx", "ws2", "nope", "h3"] {
            assert!(
                !is_known_transport_protocol(name),
                "name={name:?} must be unknown (Go hard-errors unknown transport protocol)"
            );
        }
    }

    #[test]
    fn rust_own_aliases_are_known() {
        // Rust 自有别名（模块文档逐条列了依据）。
        assert_eq!(canonical_transport_protocol("hysteria2"), Some(TransportProtocol::Hysteria));
        assert_eq!(
            canonical_transport_protocol("domainsocket"),
            Some(TransportProtocol::DomainSocket)
        );
        assert_eq!(canonical_transport_protocol("reality"), Some(TransportProtocol::Reality));
        assert_eq!(canonical_transport_protocol("quic"), Some(TransportProtocol::Quic));
    }
}

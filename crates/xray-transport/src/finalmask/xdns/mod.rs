//! # xdns：DNS-over-UDP 隧道伪装（对应 Go `transport/internet/finalmask/xdns/`，v26.9.30）
//!
//! payload 编码进 DNS 查询名（base32 前缀 label + 伪装域名后缀）；服务端解码
//! payload 并按 clientID（fd::/8 派生地址）路由；响应按 qtype 编码为 answer
//! 段（A/CNAME/TXT/AAAA），经 [len2|0xC0] 帧聚合下发。
//!
//! ## 子模块
//!
//! - `dns`：DNS wire format 编解码（RFC1035，CNAME rdata 归一化）
//! - `domain`：伪装域名容量模型（Go `domain.go`）
//! - `frag`：分片重组（Go `frag.go`）
//! - `resp`：响应编解码 + SendManager（Go `resp.go`）
//! - `client`：`XdnsConnClient` 实现 [`super::UdpIo`]（Go `client.go`）
//! - `server`：`XdnsConnServer` 实现 [`super::UdpIo`]（Go `server.go`）
//! - `base32`：RFC4648 base32（无 padding）
//!
//! bd 2ktp ④：协议对齐 Xray-core fc8f8a45（v26.9.30）。Rust finalmask 栈为
//! UDP-only：TCP/DOH resolver 配置期显式报错（Go 侧按 `ResolverProto.type`
//! 分派 tcp/udp/https，见 `resolver.go NewResolver`）。

pub(crate) mod base32;
mod client;
mod dns;
mod domain;
mod frag;
mod resp;
mod server;

use std::{io, sync::Arc};

use super::{UdpIo, Udpmask};
use xray_proto::xray::transport::internet::finalmask::xdns::ResolverProto;
use xray_proto::xray::transport::internet::{QuicParams, tls::Config as TlsConfig};

/// poll 通知队列深度（Go `pollLimit`）。
pub(crate) const POLL_LIMIT: usize = 16;

/// 伪装域名配置（对应 Go `DomainProto`）。
#[derive(Debug, Clone)]
pub struct DomainConfig {
    pub(crate) name: String,
    pub(crate) len_limit: i32,
    pub(crate) label_limit: i32,
    pub(crate) types: Vec<u16>,
    pub(crate) edns0: i32,
}

/// resolver 分派类型（Go `resolver.go NewResolver` 按 `ResolverProto.type` 分派）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverKind {
    Udp,
    Tcp,
}

/// resolver 配置（对应 Go `ResolverProto`：type/addr/worker/tls_config/quic_config）。
///
/// `worker`/`tls_config`/`quic_config` 对 udp/tcp 在 Go 运行时同样不读
/// （`resolver_udp.go`/`resolver_tcp.go` 只取 Addr，仅 DOH 读 worker/tls/quic），
/// 此处无损承载以对齐 wire；真正做不到的形态（DOH）在 [`ResolverConfig::from_proto`]
/// 配置期显式报错。
#[derive(Clone)]
pub struct ResolverConfig {
    pub kind: ResolverKind,
    pub addr: String,
    pub worker: i32,
    pub tls_config: Option<TlsConfig>,
    pub quic_config: Option<QuicParams>,
}

impl std::fmt::Debug for ResolverConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // proto 生成类型无 Debug，只打字段存在性
        f.debug_struct("ResolverConfig")
            .field("kind", &self.kind)
            .field("addr", &self.addr)
            .field("worker", &self.worker)
            .field("tls_config", &self.tls_config.is_some())
            .field("quic_config", &self.quic_config.is_some())
            .finish()
    }
}

impl ResolverConfig {
    /// Go `NewResolver`（resolver.go:17-27）的 `type` 分派：udp/tcp 照常构造；
    /// https（DOH）Rust 栈未实现 → 配置期显式报错；未知 type 同 Go 报
    /// "unknown type"。
    pub fn from_proto(p: &ResolverProto) -> io::Result<Self> {
        let kind = match p.r#type.as_str() {
            "udp" => ResolverKind::Udp,
            "tcp" => ResolverKind::Tcp,
            "https" => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "xdns: DOH (https) resolver not supported (UDP-only stack)",
                ));
            },
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("xdns: unknown resolver type {other:?}"),
                ));
            },
        };
        Ok(Self {
            kind,
            addr: p.addr.clone(),
            worker: p.worker,
            tls_config: p.tls_config.clone(),
            quic_config: p.quic_config.clone(),
        })
    }
}

/// xdns 配置（对应 Go `xdns.Config` protobuf）。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 服务端：伪装域名（结构与默认值见 `build_domain_config()`）。
    pub domains: Vec<DomainConfig>,
    /// 客户端：resolver 列表（经隧道直连服务端伪装出口）。
    pub resolvers: Vec<ResolverConfig>,
    /// 真实包后追加的空 poll 数（0-3）。
    pub extra_poll: i32,
}

impl Udpmask for Config {
    fn wrap_packet_conn_client(
        &self,
        raw: Box<dyn UdpIo>,
        _level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        let inner: Arc<dyn UdpIo> = Arc::from(raw);
        let client = client::XdnsConnClient::new(inner, self)?;
        Ok(Box::new(client))
    }

    fn wrap_packet_conn_server(
        &self,
        raw: Box<dyn UdpIo>,
        _level: usize,
        _level_count: usize,
    ) -> io::Result<Box<dyn UdpIo>> {
        let inner: Arc<dyn UdpIo> = Arc::from(raw);
        let server = server::XdnsConnServer::new(inner, self)?;
        Ok(Box::new(server))
    }
}

/// JSON 域名对象 → [`DomainConfig`]（默认值对齐 Go conf：lenLimit 0→255、
/// labelLimit 0→63；域名校验在 wrap 期 `Domain::new`）。
pub(crate) fn build_domain_config(v: &serde_json::Value) -> io::Result<DomainConfig> {
    let Some(obj) = v.as_object() else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "xdns: domain must be an object"));
    };
    let Some(name) = obj.get("name").and_then(|x| x.as_str()) else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "xdns: domain missing name"));
    };
    let len_limit = match obj.get("lenLimit") {
        Some(x) if !x.is_null() => x
            .as_i64()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "xdns: invalid lenLimit"))?
            as i32,
        _ => 255,
    };
    let label_limit = match obj.get("labelLimit") {
        Some(x) if !x.is_null() => x
            .as_i64()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "xdns: invalid labelLimit"))?
            as i32,
        _ => 63,
    };
    let mut types = Vec::new();
    match obj.get("types") {
        Some(serde_json::Value::Array(arr)) => {
            for t in arr {
                let t = t.as_i64().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "xdns: invalid type")
                })? as i32;
                types.push(u16::try_from(t).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "xdns: type out of u16 range")
                })?);
            }
        },
        _ => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "xdns: domain missing types"));
        },
    }
    let edns0 = match obj.get("edns0") {
        Some(x) if !x.is_null() => x
            .as_i64()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "xdns: invalid edns0"))?
            as i32,
        _ => 0,
    };
    Ok(DomainConfig { name: name.to_string(), len_limit, label_limit, types, edns0 })
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::Duration};

    use super::*;

    #[test]
    fn domain_config_defaults_len_and_label_limits() {
        let cfg = build_domain_config(&serde_json::json!({"name": "a.example.com", "types": [16]}))
            .unwrap();
        assert_eq!(cfg.len_limit, 255);
        assert_eq!(cfg.label_limit, 63);
        assert_eq!(cfg.types, vec![16]);
        assert_eq!(cfg.edns0, 0);
    }

    #[test]
    fn domain_config_rejects_malformed() {
        assert!(build_domain_config(&serde_json::json!("a.com")).is_err());
        assert!(build_domain_config(&serde_json::json!({"types": [16]})).is_err());
        assert!(build_domain_config(&serde_json::json!({"name": "a.com"})).is_err());
        assert!(
            build_domain_config(&serde_json::json!({"name": "a.com", "types": "txt"})).is_err()
        );
    }

    /// Go 侧 fixture（Go xray-core config.pb.go proto.Marshal 真实输出，
    /// protoc v6.33.5 --encode 字节一致交叉锚定）。生成命令：
    /// `reports/night-run-2026-10-20/tmp/xdnsprobe` 内 `go run . encode`，
    /// 输入 `xdns.Config{Resolvers: [{Type: "tcp", Addr: "1.1.1.1:53", Worker: 2}]}`。
    const GO_WIRE_RESOLVERS_TCP_HEX: &str = "12130a03746370120a312e312e312e313a35331802";

    /// Go↔Rust wire 互通（bd o7ns D4）：Go Marshal 字节 → prost 解码逐字段断言
    /// （type/addr/worker），Rust 重编码必须字节一致（双向同 fixture）。
    #[test]
    fn go_wire_fixture_decode_and_roundtrip() {
        use prost::Message as _;
        use xray_proto::xray::transport::internet::finalmask::xdns as proto_xdns;

        let bytes = hex::decode(GO_WIRE_RESOLVERS_TCP_HEX).unwrap();
        let cfg = proto_xdns::Config::decode(&bytes[..]).unwrap();
        assert!(cfg.domains.is_empty());
        assert_eq!(cfg.extra_poll, 0);
        assert_eq!(cfg.resolvers.len(), 1);
        let r = &cfg.resolvers[0];
        assert_eq!(r.r#type, "tcp");
        assert_eq!(r.addr, "1.1.1.1:53");
        assert_eq!(r.worker, 2);
        assert!(r.tls_config.is_none());
        assert!(r.quic_config.is_none());

        let re_encoded = cfg.encode_to_vec();
        eprintln!("rust_encoded_hex: {}", hex::encode(&re_encoded));
        assert_eq!(re_encoded, bytes);

        let rc = ResolverConfig::from_proto(r).unwrap();
        assert_eq!(rc.kind, ResolverKind::Tcp);
        assert_eq!(rc.addr, "1.1.1.1:53");
        assert_eq!(rc.worker, 2);
    }

    /// `from_proto` 按 Go `resolver.go NewResolver` 分派：udp/tcp 构造，
    /// https 显式报错（Rust 栈未实现），未知 type 报 "unknown"。
    #[test]
    fn from_proto_dispatches_and_rejects() {
        let p = |t: &str| ResolverProto {
            r#type: t.into(),
            addr: "1.1.1.1:53".into(),
            ..Default::default()
        };
        assert_eq!(ResolverConfig::from_proto(&p("udp")).unwrap().kind, ResolverKind::Udp);
        assert_eq!(ResolverConfig::from_proto(&p("tcp")).unwrap().kind, ResolverKind::Tcp);
        assert!(ResolverConfig::from_proto(&p("https")).is_err());
        assert!(ResolverConfig::from_proto(&p("quic")).is_err());
    }

    /// worker/tls_config/quic_config 无损承载（udp 上 Go 运行时同样不读，
    /// 不得丢弃；对齐 Go conf 缺省 worker=32 的真实形态）。
    #[test]
    fn from_proto_carries_worker_tls_quic() {
        let p = ResolverProto {
            r#type: "udp".into(),
            addr: "9.9.9.9:53".into(),
            worker: 32,
            tls_config: Some(TlsConfig::default()),
            quic_config: Some(QuicParams::default()),
        };
        let rc = ResolverConfig::from_proto(&p).unwrap();
        assert_eq!(rc.kind, ResolverKind::Udp);
        assert_eq!(rc.worker, 32);
        assert!(rc.tls_config.is_some());
        assert!(rc.quic_config.is_some());
    }

    /// 双端互通的内存 UDP 管道（模拟 finalmask 隧道），供 loopback e2e 使用。
    struct PipeEnd {
        peer: tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>,
        inbox: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    }

    #[async_trait::async_trait]
    impl UdpIo for PipeEnd {
        async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
            self.peer
                .send((buf.to_vec(), addr))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "pipe peer closed"))?;
            Ok(buf.len())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let (data, addr) = self
                .inbox
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed"))?;
            let n = data.len().min(buf.len());
            buf[..n].copy_from_slice(&data[..n]);
            Ok((n, addr))
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from(([127u8, 0, 0, 1], 0)))
        }
    }

    fn test_config() -> Config {
        Config {
            domains: vec![DomainConfig {
                name: "t.example.com".into(),
                len_limit: 255,
                label_limit: 63,
                types: vec![16, 1], // TXT + A（随机域/类型覆盖）
                edns0: 0,
            }],
            resolvers: vec![ResolverConfig {
                kind: ResolverKind::Udp,
                addr: "127.0.0.1:53".into(),
                worker: 0,
                tls_config: None,
                quic_config: None,
            }],
            extra_poll: 0,
        }
    }

    /// loopback e2e：client ↔ server 经内存管道全链路互通（上行小包 + 下行响应）。
    #[tokio::test]
    async fn loopback_client_server_exchange_payloads() {
        let (ca, sa) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(256);
        let (sb, ab) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(256);
        // ca: → client inbox（sender）；sa: client inbox（receiver）
        // sb: → server inbox（sender）；ab: server inbox（receiver）
        let client_pipe: Arc<dyn UdpIo> =
            Arc::new(PipeEnd { peer: sb, inbox: tokio::sync::Mutex::new(sa) });
        let server_pipe: Arc<dyn UdpIo> =
            Arc::new(PipeEnd { peer: ca, inbox: tokio::sync::Mutex::new(ab) });

        let cfg = test_config();
        let client = client::XdnsConnClient::new(client_pipe, &cfg).unwrap();
        let server = server::XdnsConnServer::new(server_pipe, &cfg).unwrap();

        // 上行：payload → client.send_to → 查询 → server.recv_from 解出
        client.send_to(b"hello xdns", "127.0.0.1:53".parse().unwrap()).await.unwrap();
        let mut buf = [0u8; 4096];
        let (n, up_addr) = tokio::time::timeout(Duration::from_secs(5), server.recv_from(&mut buf))
            .await
            .expect("uplink timeout")
            .unwrap();
        assert_eq!(&buf[..n], b"hello xdns");
        // server 侧 addr 必须是 clientID 派生的 fd::/8 IPv6 地址
        assert!(up_addr.is_ipv6());
        assert_eq!(up_addr.ip().to_string().as_bytes()[0], b'f'); // "fd.."

        // 下行：server.send_to → 响应 → client.recv_from 解出
        server.send_to(b"pong", up_addr).await.unwrap();
        let mut cbuf = [0u8; 4096];
        let (cn, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut cbuf))
            .await
            .expect("downlink timeout")
            .unwrap();
        assert_eq!(&cbuf[..cn], b"pong");
    }
}

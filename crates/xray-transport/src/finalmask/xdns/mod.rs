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
//! UDP-only：TCP resolver 配置期显式报错（Go 侧为 TypedMessage 分发）。

pub(crate) mod base32;
mod client;
mod dns;
mod domain;
mod frag;
mod resp;
mod server;

use std::{io, sync::Arc};

use super::{UdpIo, Udpmask};

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

/// resolver 配置（对应 Go `UDPResolverProto`/`TCPResolverProto`）。
#[derive(Debug, Clone)]
pub enum ResolverConfig {
    Udp { addr: String },
    Tcp { addr: String },
}

/// xdns 配置（对应 Go `xdns.Config` protobuf）。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 服务端：伪装域名（结构与默认值见 [`build_domain_config`]）。
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
            resolvers: vec![ResolverConfig::Udp { addr: "127.0.0.1:53".into() }],
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

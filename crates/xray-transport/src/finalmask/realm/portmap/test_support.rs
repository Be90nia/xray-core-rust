//! 端口映射协议层单测替身（仅 `cfg(test)`）：NAT-PMP UDP stub / SSDP stub /
//! 最小 HTTP/1.1 stub（device description + SOAP）。
//!
//! 断言口径 = 逐字段检查**收到的请求字节**，因此 stub 只记录原始报文，
//! 不做任何「语义化」解释（解释留给被测代码）。

use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Mutex},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

/// SSDP M-SEARCH 请求读取缓冲。
const SSDP_REQUEST_BUF_LEN: usize = 1024;

/// IGD device description 夹具：三个 service，只有 WANIPConnection 是端口映射面
/// （Layer3Forwarding / WANCommonInterfaceConfig 必须先被跳过）。
pub const DESCRIPTION_XML: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Stub IGD</friendlyName>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
        <controlURL>/ctl/L3F</controlURL>
      </service>
    </serviceList>
    <deviceList>
      <device>
        <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
        <serviceList>
          <service>
            <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
            <controlURL>/ctl/WANCfg</controlURL>
          </service>
        </serviceList>
        <deviceList>
          <device>
            <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <controlURL>/ctl/IPConn</controlURL>
              </service>
            </serviceList>
          </device>
        </deviceList>
      </device>
    </deviceList>
  </device>
</root>"#;

/// NAT-PMP 网关替身：记录每个请求报文；`respond` 返回 `None` = 不回（模拟丢包）。
pub struct NatPmpStub {
    pub addr: SocketAddrV4,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    peers: Arc<Mutex<Vec<SocketAddr>>>,
}

impl NatPmpStub {
    pub async fn spawn(respond: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static) -> Self {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind natpmp stub");
        let addr = match sock.local_addr().expect("natpmp stub addr") {
            SocketAddr::V4(v4) => v4,
            SocketAddr::V6(_) => unreachable!("stub binds IPv4"),
        };
        let requests = Arc::new(Mutex::new(Vec::new()));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        let froms = Arc::clone(&peers);
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                let packet = buf[..n].to_vec();
                seen.lock().expect("natpmp stub lock").push(packet.clone());
                froms.lock().expect("natpmp stub lock").push(peer);
                if let Some(response) = respond(&packet) {
                    let _ = sock.send_to(&response, peer).await;
                }
            }
        });
        Self { addr, requests, peers }
    }

    pub fn requests(&self) -> Vec<Vec<u8>> {
        self.requests.lock().expect("natpmp stub lock").clone()
    }

    /// 客户端源地址（伪造应答用例据此把包投向真实源端口）。
    pub fn peers(&self) -> Vec<SocketAddr> {
        self.peers.lock().expect("natpmp stub lock").clone()
    }

    pub fn request_count(&self) -> usize {
        self.requests.lock().expect("natpmp stub lock").len()
    }
}

/// 收到的 HTTP 请求（方法 / 路径 / 头 / body）。
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl HttpRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// 最小 HTTP/1.1 服务替身（只支持 Content-Length body + keep-alive）。
pub struct HttpStub {
    pub addr: SocketAddr,
    requests: Arc<Mutex<Vec<HttpRequest>>>,
}

impl HttpStub {
    pub async fn spawn(
        respond: impl Fn(&HttpRequest) -> (u16, String) + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind http stub");
        let addr = listener.local_addr().expect("http stub addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        let respond = Arc::new(respond);
        tokio::spawn(async move {
            loop {
                let Ok((sock, _peer)) = listener.accept().await else {
                    return;
                };
                let seen = Arc::clone(&seen);
                let respond = Arc::clone(&respond);
                tokio::spawn(async move { serve_connection(sock, seen, respond).await });
            }
        });
        Self { addr, requests }
    }

    pub fn requests(&self) -> Vec<HttpRequest> {
        self.requests.lock().expect("http stub lock").clone()
    }
}

async fn serve_connection(
    mut sock: TcpStream,
    seen: Arc<Mutex<Vec<HttpRequest>>>,
    respond: Arc<impl Fn(&HttpRequest) -> (u16, String) + Send + Sync>,
) {
    while let Ok(Some(request)) = read_request(&mut sock).await {
        seen.lock().expect("http stub lock").push(request.clone());
        let (status, body) = respond(&request);
        let response = format!(
            "HTTP/1.1 {status} {}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
            status_text(status),
            body.len()
        );
        if sock.write_all(response.as_bytes()).await.is_err() {
            return;
        }
    }
}

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Status",
    }
}

async fn read_request(sock: &mut TcpStream) -> io::Result<Option<HttpRequest>> {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        let n = sock.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split_whitespace();
    let method = request_line.next().unwrap_or_default().to_string();
    let path = request_line.next().unwrap_or_default().to_string();
    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    let content_length: usize = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        let n = sock.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Ok(Some(HttpRequest {
        method,
        path,
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    }))
}

/// SSDP 应答替身：记录收到的 M-SEARCH 原文，回一条带 `LOCATION` 的 200。
pub struct SsdpStub {
    pub addr: SocketAddrV4,
    requests: Arc<Mutex<Vec<String>>>,
}

impl SsdpStub {
    /// `location` = 网关 description URL（指向 [`HttpStub`]）。
    pub async fn spawn(location: String) -> Self {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind ssdp stub");
        let addr = match sock.local_addr().expect("ssdp stub addr") {
            SocketAddr::V4(v4) => v4,
            SocketAddr::V6(_) => unreachable!("stub binds IPv4"),
        };
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        tokio::spawn(async move {
            let response = format!(
                "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nEXT:\r\nLOCATION: {location}\r\n\
                 SERVER: stub/1.0 UPnP/1.1 test/1.0\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                 USN: uuid:stub::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
            );
            let mut buf = [0u8; SSDP_REQUEST_BUF_LEN];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                seen.lock()
                    .expect("ssdp stub lock")
                    .push(String::from_utf8_lossy(&buf[..n]).to_string());
                let _ = sock.send_to(response.as_bytes(), peer).await;
            }
        });
        Self { addr, requests }
    }

    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("ssdp stub lock").clone()
    }
}

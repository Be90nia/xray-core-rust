//! gRPC transport: h2 client/server tunnel.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use h2::client;
use h2::server;
use http::Request;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use xray_common::net::destination::Destination;
use xray_transport::connection::Connection;
use xray_transport::dialer::StreamSettings;
use xray_transport::listener_registry::{ConnHandler, TransportListener};

use crate::config::Config;

pub async fn dial(dest: &Destination, settings: &StreamSettings) -> io::Result<Box<dyn Connection>> {
    let addr = format!("{}:{}", dest.address(), dest.port().value());
    let tcp = TcpStream::connect(&addr).await?;
    tcp.set_nodelay(true).ok();
    let cfg = parse_config(settings)?;
    // gRPC path：`/{service}/{stream}`（Go grpc URI 契约；无前导 '/' 的裸服务名
    // 是非法 h2 URI → RST_STREAM）。防御性规整：service/stream 段为空或缺前导 '/'
    // 时补默认（Go `TunCustomName` 等价但上游 service_name 对 "/foo" 返回空串）。
    let path = normalize_grpc_path(&cfg);

    let conn = if !settings.security.is_empty() && settings.security != "none" {
        let sni = dest.address().to_string();
        let tls_cfg = xray_tls::client_config::build_client_config(
            &settings.security, settings.security_json.as_ref(), &sni,
        )?.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TLS config None"))?;
        let connector = tokio_rustls::TlsConnector::from(tls_cfg);
        let dns = tokio_rustls::rustls::pki_types::ServerName::try_from(sni).map_err(io_err)?;
        let tls = connector.connect(dns, tcp).await.map_err(io_err)?;
        dial_h2(tls, &path).await
    } else {
        dial_h2(tcp, &path).await
    }?;
    // Tcpmask（Go grpc/dial.go:129-135：`TcpmaskManager.WrapConnClient`，
    // security/protocol 栈建立后链式应用 finalmask_json.tcp[]）。
    xray_transport::finalmask::wrap_conn_client_from_settings(settings, conn)
}

async fn dial_h2<T>(conn: T, path: &str) -> io::Result<Box<dyn Connection>>
where T: AsyncRead + AsyncWrite + Send + Unpin + 'static {
    let (mut send_req, h2_conn) = client::handshake(conn).await.map_err(io_err)?;
    tokio::spawn(async move { let _ = h2_conn.await; });
    let req = Request::builder()
        .method("POST").uri(path)
        .header("content-type", "application/grpc").header("te", "trailers")
        .body(()).map_err(io_err)?;
    let (resp_fut, mut send_stream) = send_req.send_request(req, false).map_err(io_err)?;
    // Go grpc-gun 语义：HEADERS 发出后立即泵上行 DATA，不等待响应头——
    // grpc server 收满一个完整 message 才回 :status 200；若先等响应头，
    // 双方互等 → 服务端超时 RST（interop 实测 wire 证据）。
    let (client, server) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let (mut rd, mut wr) = tokio::io::split(server);
        let up = async {
            let mut buf = vec![0u8; 32*1024];
            loop {
                let n = rd.read(&mut buf).await?;
                if n==0 { let _=send_stream.send_data(Bytes::new(),true); break; }
                // 每个 read chunk 一帧 gRPC message（hunk 载体，边界对上游流协议透明）
                let frame = crate::encoding::encode_hunk_frame(&buf[..n]);
                send_stream.send_data(Bytes::from(frame),false).map_err(io_err)?;
            }
            Ok::<_,io::Error>(())
        };
        let down = async {
            let resp = resp_fut.await.map_err(io_err)?;
            let mut recv_stream = resp.into_body();
            let mut acc: Vec<u8> = Vec::new();
            while let Some(d)=recv_stream.data().await {
                let d=d.map_err(io_err)?;
                let _=recv_stream.flow_control().release_capacity(d.len());
                acc.extend_from_slice(&d);
                // DATA 流是连续 gRPC frames，逐帧解出 Hunk payload 下发
                loop {
                    match crate::encoding::decode_hunk_frame(&acc, None).map_err(io_err)? {
                        Some((used, data)) => { acc.drain(..used); wr.write_all(&data).await?; }
                        None => break,
                    }
                }
            }
            Ok::<_,io::Error>(())
        };
        let _=tokio::try_join!(up,down);
    });
    Ok(Box::new(DuplexConn(client)))
}

pub async fn listen(addr: SocketAddr, settings: &StreamSettings, handler: ConnHandler) -> io::Result<Box<dyn TransportListener>> {
    let cfg = parse_config(settings)?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let tls_cfg = if !settings.security.is_empty() && settings.security != "none" {
        Some(xray_tls::server_config::build_server_config(&settings.security, settings.security_json.as_ref())?.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TLS server config None"))?)
    } else { None };
    // Tcpmask（Go grpc/hub.go:123-125：`TcpmaskManager.WrapListener` → 每条
    // accept conn 过 `WrapConnServer`；空 manager = 恒等）。
    let tcpmask = Arc::new(
        xray_transport::finalmask::build_tcpmask_manager_from_json(
            settings.finalmask_json.as_ref(),
        )?,
    );
    tokio::spawn(async move { loop {
        let (tcp,_) = match listener.accept().await { Ok(v)=>v, Err(_)=>continue };
        tcp.set_nodelay(true).ok();
        let h=handler.clone(); let tls=tls_cfg.clone(); let m=Some(tcpmask.clone());
        tokio::spawn(async move {
            if let Some(tc)=tls {
                let acc=tokio_rustls::TlsAcceptor::from(tc);
                match acc.accept(tcp).await { Ok(c)=>accept_h2(c,h,m).await, Err(_)=>{} }
            } else { accept_h2(tcp,h,m).await; }
        });
    }});
    Ok(Box::new(GrpcListener{local}))
}

async fn accept_h2<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    conn: T,
    handler: ConnHandler,
    tcpmask: Option<Arc<xray_transport::finalmask::TcpmaskManager>>,
) {
    let mut h2_srv = match server::handshake(conn).await { Ok(s)=>s, Err(_)=>return };
    while let Some(r)=h2_srv.accept().await {
        let (req,mut respond) = match r { Ok(v)=>v, Err(_)=>continue };
        if req.method()!="POST" {
            let r=http::Response::builder().status(404).body(()).unwrap();
            let _=respond.send_response(r,true); continue;
        }
        let mut recv_body=req.into_body();
        let mut send_resp=match respond.send_response(http::Response::builder().status(200).body(()).unwrap(),false){Ok(s)=>s,Err(_)=>continue};
        let (client,server)=tokio::io::duplex(64*1024);
        let h2=handler.clone();
        tokio::spawn(async move {
            let (mut rd,mut wr)=tokio::io::split(server);
            let s=async{let mut buf=vec![0u8;32*1024];loop{let n=rd.read(&mut buf).await?;if n==0{let _=send_resp.send_data(Bytes::new(),true);break;}send_resp.send_data(Bytes::copy_from_slice(&buf[..n]),false).map_err(io_err)?;}Ok::<_,io::Error>(())};
            let r=async{while let Some(d)=recv_body.data().await{let d=d.map_err(io_err)?;wr.write_all(&d).await?;let _=recv_body.flow_control().release_capacity(d.len());}Ok::<_,io::Error>(())};
            let _=tokio::try_join!(s,r);
        });
        let conn: Box<dyn Connection> = match tcpmask.as_ref() {
            Some(m) => match xray_transport::finalmask::wrap_conn_server_into_connection(
                m, Box::new(DuplexConn(client)),
            ) {
                Ok(c) => c,
                Err(e) => { tracing::debug!("grpc tcpmask wrap failed: {e}"); continue; }
            },
            None => Box::new(DuplexConn(client)),
        };
        h2(conn);
    }
}

fn parse_config(s:&StreamSettings)->io::Result<Config>{
    crate::config::parse_grpc_config(s.transport_json.as_ref())
}
fn io_err<E:std::fmt::Display>(e:E)->io::Error{io::Error::new(io::ErrorKind::Other,e.to_string())}

struct DuplexConn(tokio::io::DuplexStream);
impl AsyncRead for DuplexConn{fn poll_read(mut self:Pin<&mut Self>,cx:&mut Context<'_>,buf:&mut ReadBuf<'_>)->Poll<io::Result<()>>{Pin::new(&mut self.0).poll_read(cx,buf)}}
impl AsyncWrite for DuplexConn{
    fn poll_write(mut self:Pin<&mut Self>,cx:&mut Context<'_>,buf:&[u8])->Poll<io::Result<usize>>{Pin::new(&mut self.0).poll_write(cx,buf)}
    fn poll_flush(mut self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>>{Pin::new(&mut self.0).poll_flush(cx)}
    fn poll_shutdown(mut self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>>{Pin::new(&mut self.0).poll_shutdown(cx)}
}
impl Connection for DuplexConn{fn remote_addr(&self)->io::Result<Option<SocketAddr>>{Ok(None)}fn local_addr(&self)->io::Result<Option<SocketAddr>>{Ok(None)}}

struct GrpcListener{local:SocketAddr}

impl xray_transport::listener_registry::TransportListener for GrpcListener {
    fn close(&self) -> io::Result<()> { Ok(()) }
    fn local_addr(&self) -> io::Result<SocketAddr> { Ok(self.local) }
}

/// gRPC 路径规整：`/{service}/{stream}`（Go `TunCustomName` 等价）。
pub(crate) fn normalize_grpc_path(cfg: &Config) -> String {
    let (raw_service, raw_stream) = if cfg.multi_mode {
        (cfg.service_name(), cfg.tun_multi_stream_name())
    } else {
        (cfg.service_name(), cfg.tun_stream_name())
    };
    let service = if raw_service.is_empty() {
        "/GunService".to_string()
    } else if raw_service.starts_with('/') {
        raw_service
    } else {
        format!("/{raw_service}")
    };
    let stream = if raw_stream.is_empty() {
        if cfg.multi_mode { "TunMulti".to_string() } else { "Tun".to_string() }
    } else if raw_stream.starts_with('/') {
        raw_stream
    } else {
        format!("/{raw_stream}")
    };
    format!("{service}{stream}")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cfg_single(name: &str) -> Config {
        let mut c = Config::default();
        c.service_name = name.to_string();
        c
    }
    fn cfg_multi(name: &str) -> Config {
        let mut c = cfg_single(name);
        c.multi_mode = true;
        c
    }
    #[test]
    fn normalize_old_school_single() {
        assert_eq!(normalize_grpc_path(&cfg_single("GunService")), "/GunService/Tun");
    }
    #[test]
    fn normalize_old_school_multi() {
        assert_eq!(normalize_grpc_path(&cfg_multi("GunService")), "/GunService/TunMulti");
    }
    #[test]
    fn normalize_custom_path() {
        assert_eq!(normalize_grpc_path(&cfg_single("/A/B/Tun")), "/A/B/Tun");
    }
    #[test]
    fn normalize_empty_service_fallback() {
        assert_eq!(normalize_grpc_path(&cfg_single("")), "/GunService/Tun");
    }
    #[test]
    fn normalize_degenerate_service_fallback() {
        // serviceName="/foo" → service_name()=""（Go 退化），tun="foo"。
        assert_eq!(normalize_grpc_path(&cfg_single("/foo")), "/GunService/foo");
    }
}
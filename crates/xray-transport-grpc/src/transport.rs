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
    let path = cfg.service_name();

    if !settings.security.is_empty() && settings.security != "none" {
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
    }
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
    let resp = resp_fut.await.map_err(io_err)?;
    let mut recv_stream = resp.into_body();
    let (client, server) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let (mut rd, mut wr) = tokio::io::split(server);
        let s = async { let mut buf = vec![0u8; 32*1024]; loop {
            let n = rd.read(&mut buf).await?;
            if n==0 { let _=send_stream.send_data(Bytes::new(),true); break; }
            send_stream.send_data(Bytes::copy_from_slice(&buf[..n]),false).map_err(io_err)?;
        } Ok::<_,io::Error>(()) };
        let r = async { while let Some(d)=recv_stream.data().await {
            let d=d.map_err(io_err)?; wr.write_all(&d).await?;
            let _=recv_stream.flow_control().release_capacity(d.len());
        } Ok::<_,io::Error>(()) };
        let _=tokio::try_join!(s,r);
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
    tokio::spawn(async move { loop {
        let (tcp,_) = match listener.accept().await { Ok(v)=>v, Err(_)=>continue };
        tcp.set_nodelay(true).ok();
        let h=handler.clone(); let tls=tls_cfg.clone();
        tokio::spawn(async move {
            if let Some(tc)=tls {
                let acc=tokio_rustls::TlsAcceptor::from(tc);
                match acc.accept(tcp).await { Ok(c)=>accept_h2(c,h).await, Err(_)=>{} }
            } else { accept_h2(tcp,h).await; }
        });
    }});
    Ok(Box::new(GrpcListener{local}))
}

async fn accept_h2<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(conn: T, handler: ConnHandler) {
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
        h2(Box::new(DuplexConn(client)));
    }
}

fn parse_config(s:&StreamSettings)->io::Result<Config>{
    let Some(v)=s.transport_json.as_ref() else {return Ok(Config::default())};
    let Some(o)=v.as_object() else {return Err(io::Error::new(io::ErrorKind::InvalidData,"grpcSettings not object"))};
    Ok(Config{authority:o.get("authority").and_then(|x|x.as_str()).unwrap_or("").into(),service_name:o.get("serviceName").and_then(|x|x.as_str()).unwrap_or("").into(),multi_mode:o.get("multiMode").and_then(|x|x.as_bool()).unwrap_or(false),idle_timeout:o.get("idleTimeout").and_then(|x|x.as_i64()).unwrap_or(0) as i32,health_check_timeout:o.get("healthCheckTimeout").and_then(|x|x.as_i64()).unwrap_or(0) as i32,permit_without_stream:o.get("permitWithoutStream").and_then(|x|x.as_bool()).unwrap_or(false),initial_windows_size:o.get("initialWindowSize").and_then(|x|x.as_i64()).unwrap_or(0) as i32,user_agent:o.get("userAgent").and_then(|x|x.as_str()).unwrap_or("").into()})
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
impl TransportListener for GrpcListener{fn local_addr(&self)->io::Result<SocketAddr>{Ok(self.local)}fn close(&self)->io::Result<()>{tracing::info!("gRPC listener close addr={}",self.local);Ok(())}}
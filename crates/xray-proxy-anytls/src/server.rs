//! AnyTLS 服务端 mock 实现。
//!
//! 用途：本地 loopback 测试。生产 server inbound 需要 dispatcher 接入后才能做。
//!
//! 协议要求：服务端接到新 session 后，从 session 首帧读 SOCKS5 目标地址 → 拨号 →
//! 双向桥接（与 client 端对称）。

use std::net::SocketAddr;
use std::sync::Arc;

use anytls::proxy::session::{Session, new_server_session};
use anytls::runtime::DefaultPaddingFactory;
use anytls::AsyncReadWrite;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tracing::debug;

use crate::error::Result;
use crate::socks::SocksAddr;

/// AnyTLS mock 服务端句柄，`stop()` 后 listener 关闭。
pub struct AnytlsMockServer {
    pub local_addr: SocketAddr,
    join: tokio::task::JoinHandle<()>,
    stop_tx: tokio::sync::oneshot::Sender<()>,
}

impl AnytlsMockServer {
    /// 启动 mock server。`tls_acceptor` 决定证书；listener 绑定到 `bind_addr`。
    pub async fn start(bind_addr: SocketAddr, tls_acceptor: TlsAcceptor) -> Result<Self> {
        let listener = TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let join = tokio::spawn(serve_loop(listener, tls_acceptor, stop_rx));
        Ok(Self {
            local_addr,
            join,
            stop_tx,
        })
    }

    /// 停止 server 并等待 task 结束。
    pub async fn stop(self) {
        let _ = self.stop_tx.send(());
        let _ = self.join.await;
    }
}

async fn serve_loop(
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    mut stop_rx: tokio::sync::oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut stop_rx => break,
            res = listener.accept() => {
                let Ok((tcp, _peer)) = res else { continue };
                let tls_acceptor = tls_acceptor.clone();
                tokio::spawn(handle_conn(tcp, tls_acceptor));
            }
        }
    }
}

async fn handle_conn(tcp: TcpStream, tls_acceptor: TlsAcceptor) {
    let tls: TlsStream<TcpStream> = match tls_acceptor.accept(tcp).await {
        Ok(t) => t,
        Err(e) => {
            debug!("anytls mock server TLS accept failed: {e}");
            return;
        }
    };
    let padding = DefaultPaddingFactory::load();
    let on_new_session: Box<dyn Fn(Arc<Session>) + Send + Sync> = Box::new(|session| {
        tokio::spawn(handle_session(session));
    });
    let session = Arc::new(
        new_server_session(Box::new(tls) as Box<dyn AsyncReadWrite>, on_new_session, padding).await,
    );
    if let Err(e) = session.ensure_started().await {
        debug!("anytls mock server: session ensure_started failed: {e}");
        return;
    }
    // spawn run 循环——主循环结束后 session 自然清理
    let session_run = session.clone();
    tokio::spawn(async move {
        let _ = session_run.run().await;
    });
}

/// 处理一个 incoming session：读 SOCKS5 target → dial → 双向桥接。
async fn handle_session(session: Arc<Session>) {
    // 1. 读 SOCKS5 target（首帧 application data）
    let mut buf = vec![0u8; 1024];
    let n = match session.read(&mut buf).await {
        Ok(n) => n,
        Err(e) => {
            debug!("anytls mock server: read socks5 target failed: {e}");
            return;
        }
    };
    if n == 0 {
        debug!("anytls mock server: empty first read");
        return;
    }

    let (target, consumed) = match SocksAddr::decode(&buf[..n]) {
        Ok(v) => v,
        Err(e) => {
            debug!("anytls mock server: decode socks5 failed: {e}");
            return;
        }
    };

    // 2. dial target
    let target_str = match &target {
        SocksAddr::Domain(h, p) => format!("{h}:{p}"),
        SocksAddr::Ipv4(a) => a.to_string(),
        SocksAddr::Ipv6(a) => a.to_string(),
    };
    let mut outbound = match TcpStream::connect(&target_str).await {
        Ok(s) => s,
        Err(e) => {
            debug!("anytls mock server: dial target {target_str} failed: {e}");
            return;
        }
    };

    // 3. 多读的 application data（n > consumed）先 forward 给 outbound
    if n > consumed {
        if let Err(e) = outbound.write_all(&buf[consumed..n]).await {
            debug!("anytls mock server: forward extra failed: {e}");
            return;
        }
    }

    // 4. 双向桥接
    if let Err(e) = bridge(session, outbound).await {
        debug!("anytls mock server: bridge ended: {e}");
    }
}

/// 双向桥接 anytls Session 与 TcpStream。
async fn bridge(session: Arc<Session>, outbound: TcpStream) -> std::io::Result<()> {
    let (mut rd, mut wr) = outbound.into_split();
    let session_down = session.clone();
    let down = async move {
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            match session_down.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => wr.write_all(&buf[..n]).await?,
                Err(e) => return Err(e),
            }
        }
        let _ = wr.shutdown().await;
        Ok::<_, std::io::Error>(())
    };
    let up = async move {
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => { let _ = session.write(&buf[..n]).await?; }
                Err(e) => return Err(e),
            }
        }
        let _ = session.terminate().await;
        Ok::<_, std::io::Error>(())
    };
    tokio::try_join!(down, up)?;
    Ok(())
}

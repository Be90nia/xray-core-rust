//! # Happy Eyeballs 双栈拨号
//!
//! RFC 8305——IPv4/IPv6 并发拨号，先连上的赢。对应 Go `transport/internet/happy_eyeballs.go`。

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::mpsc;

const DEFAULT_DELAY: Duration = Duration::from_millis(100);

pub async fn dial_happy_eyeballs(
    v4_addr: Option<SocketAddr>,
    v6_addr: Option<SocketAddr>,
) -> std::io::Result<TcpStream> {
    match (v4_addr, v6_addr) {
        (Some(v4), Some(v6)) => race_dial(v4, v6).await,
        (Some(v4), None) => TcpStream::connect(v4).await,
        (None, Some(v6)) => TcpStream::connect(v6).await,
        (None, None) => Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "happy eyeballs: no address to dial",
        )),
    }
}

async fn race_dial(v4: SocketAddr, v6: SocketAddr) -> std::io::Result<TcpStream> {
    let (tx, mut rx) = mpsc::channel::<std::io::Result<TcpStream>>(2);
    let tx6 = tx.clone();
    tokio::spawn(async move {
        let _ = tx6.send(TcpStream::connect(v6).await).await;
    });
    let tx4 = tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(DEFAULT_DELAY).await;
        let _ = tx4.send(TcpStream::connect(v4).await).await;
    });
    drop(tx);
    loop {
        match rx.recv().await {
            Some(Ok(s)) => return Ok(s),
            Some(Err(_)) => continue,
            None => return Err(std::io::Error::other("happy eyeballs: both attempts failed")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn both_none_returns_error() {
        assert!(dial_happy_eyeballs(None, None).await.is_err());
    }
}

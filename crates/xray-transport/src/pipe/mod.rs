//! # Pipe for data relay
//!
//! 内存双向管道。对应 Go `transport/pipe.go`。
//!
//! TODO tgg-future: 完整双向 pipe 实现。

/// 创建一对内存双向 pipe endpoint。
///
/// 返回 (a, b)：写入 a 的数据可从 b 读出，反之亦然。
pub fn pipe() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
    tokio::io::duplex(64 * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn pipe_relays_data() {
        let (mut a, mut b) = pipe();
        a.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }
}

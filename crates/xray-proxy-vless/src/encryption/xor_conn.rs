//! XorConn（xor_mode==2）— 对应 Go `proxy/vless/encryption/xor.go` 的 `XorConn`。
//!
//! 只对每条 TLS record 的 5 字节 header 做 CTR XOR；record body 透传且不消耗
//! keystream。状态机：跳过上一条 record 的 body 长度（skip），对接下来凑齐的
//! 5B header 施加 XOR，再解码长度字段作为下一个 skip（Go `XorConn.Write/Read`）。
//! header prefix 非 23/3/3 时长度字段按 0 处理（Go `DecodeHeader` 返回 err 时
//! 调用方忽略 err 只取 l 的语义）。
//!
//! skip 初值（Go 握手末段 `NewXorConn` 调用点）：
//! - client 1-RTT：`(0, 0)`（下行 padding 已在握手期被 client 消费）
//! - server 1-RTT：`(0, 0)`
//! - client 0-RTT：`(0, 16)`，读侧 CTR 延迟建立（iv = 下行头 16B serverRandom，
//!   Go common.go:90-92 回填 PeerCTR）
//! - server 0-RTT：`(16, 0)`（首写 16B PreWrite 透传，写 CTR iv = PreWrite）

use std::io;
use std::pin::Pin;
use std::task::ready;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::encryption::xor::CtrXor;
use crate::encryption::{EncryptionConn, Result};

const RECORD_HEADER_LEN: usize = 5;


pub struct XorConn<IO> {
    inner: IO,
    write_ctr: CtrXor,
    write_skip: usize,
    write_header: [u8; RECORD_HEADER_LEN],
    write_header_len: usize,
    /// 已 XOR 未写完的密文残余 `(bytes, sent)`（部分写后 Pending 时产生）。
    write_pending: Option<(Vec<u8>, usize)>,
    read_ctr: Option<CtrXor>,
    /// Some = client 0-RTT：读侧 CTR 延迟建立，iv 取下行头 16B（透传时缓存于
    /// `read_iv`）。Go common.go:84-93。
    deferred_read_key: Option<Vec<u8>>,
    read_skip: usize,
    read_header: [u8; RECORD_HEADER_LEN],
    read_header_len: usize,
    read_iv: [u8; 16],
    read_iv_len: usize,
}

impl<IO> XorConn<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// 创建 XorConn（Go `NewXorConn(conn, ctr, peerCTR, outSkip, inSkip)`）。
    pub fn new(
        inner: IO,
        read_ctr: CtrXor,
        write_ctr: CtrXor,
        out_skip: usize,
        in_skip: usize,
    ) -> Self {
        Self {
            inner,
            write_ctr,
            write_skip: out_skip,
            write_header: [0; RECORD_HEADER_LEN],
            write_header_len: 0,
            write_pending: None,
            read_ctr: Some(read_ctr),
            deferred_read_key: None,
            read_skip: in_skip,
            read_header: [0; RECORD_HEADER_LEN],
            read_header_len: 0,
            read_iv: [0; 16],
            read_iv_len: 0,
        }
    }

    /// client 0-RTT 构造：读侧 CTR 延迟到下行头 16B serverRandom 到达后建立
    /// （Go client.go:124 传 nil PeerCTR + in_skip=16，common.go:90-92 回填）。
    pub fn new_deferred_read(
        inner: IO,
        write_ctr: CtrXor,
        out_skip: usize,
        in_skip: usize,
        deferred_read_key: Vec<u8>,
    ) -> Self {
        Self {
            deferred_read_key: Some(deferred_read_key),
            read_ctr: None,
            inner,
            write_ctr,
            write_skip: out_skip,
            write_header: [0; RECORD_HEADER_LEN],
            write_header_len: 0,
            write_pending: None,
            read_skip: in_skip,
            read_header: [0; RECORD_HEADER_LEN],
            read_header_len: 0,
            read_iv: [0; 16],
            read_iv_len: 0,
        }
    }

    /// Go `XorConn.Write` 的 XOR 状态机：header 段原地 XOR，body 透传。
    fn xor_write(&mut self, data: &mut [u8]) {
        let mut pos = 0usize;
        loop {
            let avail = data.len() - pos;
            if avail <= self.write_skip {
                self.write_skip -= avail;
                return;
            }
            pos += std::mem::take(&mut self.write_skip);
            let need = RECORD_HEADER_LEN - self.write_header_len;
            let rest = data.len() - pos;
            if rest < need {
                // Go：OutHeader 缓存明文（XOR 前），随后才对 p 施加 XOR。
                self.write_header[self.write_header_len..self.write_header_len + rest]
                    .copy_from_slice(&data[pos..]);
                self.write_header_len += rest;
                self.write_ctr.apply(&mut data[pos..]);
                return;
            }
            // Go Write 顺序：先 DecodeHeader（明文 header）后 XORKeyStream——
            // 读侧 XOR 即解密，解码必须在 XOR 之前（还原后才能看到 23/3/3 前缀）。
            self.write_header[self.write_header_len..RECORD_HEADER_LEN]
                .copy_from_slice(&data[pos..pos + need]);
            self.write_skip = header_len_field(&self.write_header);
            self.write_header_len = 0;
            self.write_ctr.apply(&mut data[pos..pos + need]);
            pos += need;
        }
    }

    /// Go `XorConn.Read` 的 XOR 状态机：header 段原地 XOR，body 透传。
    fn xor_read(&mut self, data: &mut [u8]) {
        let mut pos = 0usize;
        loop {
            let avail = data.len() - pos;
            if avail <= self.read_skip {
                self.cache_read_iv(&data[pos..pos + avail]);
                self.read_skip -= avail;
                return;
            }
            self.cache_read_iv(&data[pos..pos + self.read_skip]);
            pos += std::mem::take(&mut self.read_skip);
            let need = RECORD_HEADER_LEN - self.read_header_len;
            let rest = data.len() - pos;
            if rest < need {
                self.ensure_read_ctr().apply(&mut data[pos..]);
                self.read_header[self.read_header_len..self.read_header_len + rest]
                    .copy_from_slice(&data[pos..]);
                self.read_header_len += rest;
                return;
            }
            self.ensure_read_ctr().apply(&mut data[pos..pos + need]);
            self.read_header[self.read_header_len..RECORD_HEADER_LEN]
                .copy_from_slice(&data[pos..pos + need]);
            self.read_header_len = 0;
            self.read_skip = header_len_field(&self.read_header);
            pos += need;
        }
    }

    fn cache_read_iv(&mut self, passthrough: &[u8]) {
        if self.deferred_read_key.is_none() || self.read_iv_len >= 16 {
            return;
        }
        let take = (16 - self.read_iv_len).min(passthrough.len());
        self.read_iv[self.read_iv_len..self.read_iv_len + take]
            .copy_from_slice(&passthrough[..take]);
        self.read_iv_len += take;
    }

    fn ensure_read_ctr(&mut self) -> &mut CtrXor {
        if self.read_ctr.is_none() {
            if let Some(key) = self.deferred_read_key.as_deref() {
                debug_assert_eq!(self.read_iv_len, 16, "deferred iv requires in_skip >= 16");
                if let Ok(ctr) = CtrXor::new(key, &self.read_iv) {
                    self.read_ctr = Some(ctr);
                }
            }
        }
        self.read_ctr
            .as_mut()
            .expect("read ctr set at construction or derived from first 16 bytes")
    }

    /// 写出密文残余。Poll 语义与标准 AsyncWrite 一致。
    fn drain_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some((ct, sent)) = self.write_pending.as_mut() {
            match Pin::new(&mut self.inner).poll_write(cx, &ct[*sent..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "inner conn accepted 0 bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    *sent += n;
                    if *sent == ct.len() {
                        self.write_pending = None;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

}

fn header_len_field(h: &[u8; RECORD_HEADER_LEN]) -> usize {
    if h[0] == 23 && h[1] == 3 && h[2] == 3 {
        (usize::from(h[3]) << 8) | usize::from(h[4])
    } else {
        0
    }
}

impl<IO> AsyncRead for XorConn<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // 请求写完后上层必转等响应：读侧顺带推进写残余（best-effort，读优先），
        // 避免部分写 Pending 产生的密文滞留。
        if this.write_pending.is_some() {
            let _ = this.drain_pending(cx);
        }
        let filled_before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let filled_after = buf.filled().len();
                if filled_after > filled_before {
                    this.xor_read(&mut buf.filled_mut()[filled_before..filled_after]);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<IO> AsyncWrite for XorConn<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.drain_pending(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // XOR 必须先于写入施加，且 CTR 状态推进不可回退，因此「接受即缓冲」：
        // XOR 整段后尽力写，未写完的密文挂 write_pending，返回 Ok(len)（上层
        // 视为已接受，不会重发同段明文 → 无双重 XOR）。残余由 poll_write 开头 /
        // poll_read 开头（上层写完必转等响应）/ poll_flush / poll_shutdown 清写。
        // ponytail: 每写一次一次分配；XOR 型 wrapper 必须先变换后写，无零分配写法。
        let mut enc = buf.to_vec();
        this.xor_write(&mut enc);
        let mut sent = 0usize;
        loop {
            match Pin::new(&mut this.inner).poll_write(cx, &enc[sent..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "inner conn accepted 0 bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    sent += n;
                    if sent == enc.len() {
                        return Poll::Ready(Ok(buf.len()));
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                // 部分写/零写后 Pending：inner 已用当前 cx 注册写 waker，残余密文
                // 由后续 poll_read / poll_flush / 下次 poll_write 清出。
                Poll::Pending => {
                    this.write_pending = Some((enc[sent..].to_vec(), 0));
                    return Poll::Ready(Ok(buf.len()));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain_pending(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain_pending(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<IO> EncryptionConn for XorConn<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    fn close(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            use tokio::io::AsyncWriteExt;
            self.flush().await?;
            self.inner.shutdown().await?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    const KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f,
    ];

    /// 三条 record（body 27×0x01 / 300×0x02 / 16×0x03）拼成的明文流。
    fn record_stream() -> Vec<u8> {
        let mut v = Vec::new();
        for (n, b) in [(27u16, 0x01u8), (300u16, 0x02u8), (16u16, 0x03u8)] {
            v.extend_from_slice(&[23, 3, 3, (n >> 8) as u8, n as u8]);
            v.extend(std::iter::repeat(b).take(usize::from(n)));
        }
        v
    }


    /// Go 真值 fixture（D:/tmp/goenc/main.go 生成：lukechampine.com/blake3
    /// DeriveKey("VLESS") + crypto/aes-256-CTR，与 Go proxy/vless/encryption/xor.go
    /// 完全同链路）。每行：
    /// `name out_skip in_skip write_iv_hex read_iv_hex plain_hex wire_hex`，
    /// `read_iv = DEFERRED` 表示 client 0-RTT 形态（读侧 CTR 从流头 16B 延迟建立）。
    /// split_skip 场景覆盖跨片 header 缓存；zero_rtt 场景覆盖 skip 初值 + deferred。
    #[test]
    fn go_fixture_write_and_read() {
        fn unhex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
        let data = include_str!("testdata/xor_conn_go_fixture.txt");
        for line in data.lines().filter(|l| !l.is_empty()) {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (name, out_skip, in_skip, write_iv, read_iv, plain, wire) =
                (f[0], f[1].parse::<usize>().unwrap(), f[2].parse::<usize>().unwrap(), unhex(f[3]), f[4], unhex(f[5]), unhex(f[6]));
            let key: &[u8] = &KEY;

            // 写侧：按 fixture 的 skip 初值，整条流一次 XOR 后与 Go wire 逐字节比对。
            let mut w = XorConn::new(
                tokio::io::duplex(64).0,
                CtrXor::new(key, &write_iv).unwrap(),
                CtrXor::new(key, &write_iv).unwrap(),
                out_skip,
                in_skip,
            );
            let mut out = plain.clone();
            w.xor_write(&mut out);
            assert_eq!(out, wire, "{name}: write side must match Go byte-for-byte");

            // 读侧：还原明文（DEFERRED = 从流头 16B 建立读 CTR）。
            let mut out = wire.clone();
            if read_iv == "DEFERRED" {
                // client 0-RTT 形态固定 (0, 16)：写侧无前缀，下行头 16B serverRandom
                // 透传并作为读 CTR 的 iv（Go client.go:124 + common.go:84-92）。
                let mut r = XorConn::new_deferred_read(
                    tokio::io::duplex(64).0,
                    CtrXor::new(key, &write_iv).unwrap(),
                    0,
                    16,
                    key.to_vec(),
                );
                r.xor_read(&mut out);
            } else {
                let iv = unhex(read_iv);
                let mut r = XorConn::new(
                    tokio::io::duplex(64).0,
                    CtrXor::new(key, &iv).unwrap(),
                    CtrXor::new(key, &write_iv).unwrap(),
                    out_skip,
                    in_skip,
                );
                r.xor_read(&mut out);
            }
            assert_eq!(out, plain, "{name}: read side must restore plaintext");
        }
    }

    /// Go fixture 分片形态补充：split_skip 场景的明文分 3 次 Write（2 / 7 / 剩余）、
    /// wire 分 3 次 Read（4 / 5 / 剩余），覆盖跨调用部分 header 缓存。
    #[test]
    fn go_fixture_fragmented_split_skip() {
        fn unhex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
        let line = include_str!("testdata/xor_conn_go_fixture.txt")
            .lines()
            .find(|l| l.starts_with("split_skip "))
            .expect("split_skip fixture line");
        let f: Vec<&str> = line.split_whitespace().collect();
        let (write_iv, plain, wire) = (unhex(f[3]), unhex(f[5]), unhex(f[6]));
        let key: &[u8] = &KEY;

        let mut w = XorConn::new(
            tokio::io::duplex(64).0,
            CtrXor::new(key, &write_iv).unwrap(),
            CtrXor::new(key, &write_iv).unwrap(),
            7,
            7,
        );
        let mut wire_out = plain.clone();
        let (a, rest) = wire_out.split_at_mut(2);
        w.xor_write(a);
        let (b, c) = rest.split_at_mut(7);
        w.xor_write(b);
        w.xor_write(c);
        assert_eq!(wire_out, wire, "split writes must match Go byte-for-byte");

        let mut r = XorConn::new(
            tokio::io::duplex(64).0,
            CtrXor::new(key, &write_iv).unwrap(),
            CtrXor::new(key, &write_iv).unwrap(),
            7,
            7,
        );
        let mut back = wire.clone();
        let (a, rest) = back.split_at_mut(4);
        r.xor_read(a);
        let (b, c) = rest.split_at_mut(5);
        r.xor_read(b);
        r.xor_read(c);
        assert_eq!(back, plain, "split reads must restore");
    }

    /// 非 23/3/3 prefix 的 header：长度字段按 0 → 下一 5B 立即再当 header
    /// （Go DecodeHeader 忽略 err 的语义）。
    #[test]
    fn invalid_header_prefix_advances_zero_skip() {
        let mut r = XorConn::new(
            tokio::io::duplex(64).0,
            CtrXor::new(&KEY, &[0xAA; 16]).unwrap(),
            CtrXor::new(&KEY, &[0xAA; 16]).unwrap(),
            0,
            0,
        );
        let mut data = [0u8; 10];
        r.xor_read(&mut data);
        // 两个连续 5B 段都被 XOR（skip 恒 0）
        let mut ks = [0u8; 10];
        CtrXor::new(&KEY, &[0xAA; 16]).unwrap().apply(&mut ks);
        assert_eq!(data, ks, "both segments XORed: invalid prefix means skip 0");
    }

    /// 异步全路径：record 流经 duplex 上两个 XorConn 双向往返。
    #[tokio::test]
    async fn duplex_roundtrip_bidirectional() {
        let (client_io, server_io) = duplex(64 * 1024);
        let mut client = XorConn::new(
            client_io,
            CtrXor::new(&KEY, &[0xBB; 16]).unwrap(),
            CtrXor::new(&KEY, &[0xAA; 16]).unwrap(),
            0,
            0,
        );
        let mut server = XorConn::new(
            server_io,
            CtrXor::new(&KEY, &[0xAA; 16]).unwrap(),
            CtrXor::new(&KEY, &[0xBB; 16]).unwrap(),
            0,
            0,
        );
        let plain = record_stream();
        client.write_all(&plain).await.unwrap();
        client.flush().await.unwrap();
        let mut buf = vec![0u8; plain.len()];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, plain, "server restores client records");

        // 反向
        let reply = [0x07u8; 100];
        server.write_all(&reply).await.unwrap();
        server.flush().await.unwrap();
        let mut buf = [0u8; 100];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, reply);
    }

    /// 异步跨 poll_read 分片：写侧分小片写，读侧小 buf 逐段读（header 缓存跨调用）。
    #[tokio::test]
    async fn fragmented_reads_across_header_boundary() {
        let (client_io, server_io) = duplex(4096);
        let mut client = XorConn::new(
            client_io,
            CtrXor::new(&KEY, &[0x22; 16]).unwrap(),
            CtrXor::new(&KEY, &[0x11; 16]).unwrap(),
            0,
            0,
        );
        let mut server = XorConn::new(
            server_io,
            CtrXor::new(&KEY, &[0x11; 16]).unwrap(),
            CtrXor::new(&KEY, &[0x22; 16]).unwrap(),
            0,
            0,
        );
        let plain = record_stream();
        for chunk in plain.chunks(7) {
            client.write_all(chunk).await.unwrap();
            client.flush().await.unwrap();
        }
        let mut got = vec![0u8; plain.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, plain);
    }
}

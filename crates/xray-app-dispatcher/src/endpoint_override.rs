//! XUDP 帧端点改写（bd g35）。
//!
//! 对应 Go `common/buf/override.go` 的 `EndpointOverrideReader/Writer` +
//! `app/proxyman/outbound/handler.go:206-209` 的挂接：当 dispatcher 将
//! OriginalTarget 改写为 Target（sniffing/fakedns 覆盖等）后，改写 link 中
//! XUDP 帧携带的逐包目标地址——
//! - Reader（上行）：帧目标 `from`(original) → `to`(override)，outbound 按改写后目标发送
//! - Writer（下行）：帧来源 `from`(override) → `to`(original)，客户端看到原始地址
//!
//! Go 版操作 `buf.Buffer.UDP` 元数据（逐包原子）；Rust 的 link 语义是 XUDP
//! 字节流（bd b2e 约定），故此处解析帧边界做改写，跨读/写的半帧累积在 `pending`。

use std::future::Future;
use std::pin::Pin;
use xray_buf::io::{Reader, Result as IoResult, Writer};
use xray_buf::multi::MultiBuffer;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_xudp::packet::FrameMetadata;

/// 改写 `buf` 前缀所有完整 XUDP 帧：目标地址 == `from` 的帧改写为 `to`
/// （端口保留，GlobalID 保留）。返回 `(改写后字节, 已消费字节数)`；
/// 尾部不完整帧不消费，由调用方保留。
fn rewrite_complete_frames(buf: &[u8], from: &Address, to: &Address) -> (Vec<u8>, usize) {
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        let rest = &buf[pos..];
        if rest.is_empty() {
            break;
        }
        let Ok((meta, consumed)) = FrameMetadata::from_bytes(rest) else {
            break; // 帧头不完整
        };
        let data_len = if meta.has_data() {
            if rest.len() < consumed + 2 {
                break; // data_len 字段不完整
            }
            let dl = u16::from_be_bytes([rest[consumed], rest[consumed + 1]]) as usize;
            if rest.len() < consumed + 2 + dl {
                break; // data 不完整
            }
            dl
        } else {
            0
        };
        let frame_end = consumed + if meta.has_data() { 2 + data_len } else { 0 };

        // 改写命中的帧目标；未命中/无目标帧原样拷贝（Go override.go 只改写相等地址）
        let rewritten = meta
            .target()
            .filter(|t| t.network() == Network::UDP && t.address() == from)
            .map(|t| {
                let mut m = meta.clone();
                m.set_target(Destination::udp(to.clone(), t.port()));
                m
            });
        match rewritten {
            Some(m) => out.extend_from_slice(&m.to_bytes()),
            None => out.extend_from_slice(&rest[..consumed]),
        }
        if meta.has_data() {
            out.extend_from_slice(&rest[consumed..frame_end]);
        }
        pos += frame_end;
    }
    (out, pos)
}

/// 上行帧目标改写 Reader（original → override）。
///
/// 读内部流累积到 `pending`，重写所有完整帧后返回；未凑成完整帧时继续读
/// （不返回空 MultiBuffer——那会伪报 EOF）。内部 EOF（Ok 空）时残帧原样冲出；
/// 内部 Err（pipe 的 `Error::Eof`）原样传播，为下游统一 EOF 信号。
pub struct EndpointOverrideReader {
    inner: Box<dyn Reader>,
    from: Address,
    to: Address,
    pending: Vec<u8>,
}

impl EndpointOverrideReader {
    /// 构造：`from` = 原始地址，`to` = 改写后地址。
    pub fn new(inner: Box<dyn Reader>, from: Address, to: Address) -> Self {
        Self { inner, from, to, pending: Vec::new() }
    }
}

impl Reader for EndpointOverrideReader {
    fn read_multi_buffer(&mut self) -> Pin<Box<dyn Future<Output = IoResult<MultiBuffer>> + Send + '_>> {
        Box::pin(async move {
            loop {
                let mb = self.inner.read_multi_buffer().await?;
                let eof = mb.is_empty();
                // 逐 buffer extend：mb.to_vec() 会先堆分配扁平 Vec 再拷一次
                for b in mb.iter() {
                    self.pending.extend_from_slice(b.bytes());
                }
                let (out, consumed) = rewrite_complete_frames(&self.pending, &self.from, &self.to);
                self.pending.drain(..consumed);
                if eof {
                    // EOF：残帧原样冲出（尽力而为）；无残帧时返回空 = EOF 传播
                    let mut mb_out = MultiBuffer::new();
                    mb_out.merge_bytes(&out);
                    let tail = std::mem::take(&mut self.pending);
                    mb_out.merge_bytes(&tail);
                    return Ok(mb_out);
                }
                if consumed > 0 {
                    let mut mb_out = MultiBuffer::new();
                    mb_out.merge_bytes(&out);
                    return Ok(mb_out);
                }
                // 非空读但无完整帧 → 继续读
            }
        })
    }
}

/// 下行帧来源改写 Writer（override → original）。
///
/// 写入累积到 `pending`，重写完整帧后转发；不完整帧保留到下次写入
/// （正常流每次写均为完整帧）。残帧随 Drop 丢弃。
pub struct EndpointOverrideWriter {
    inner: Box<dyn Writer>,
    from: Address,
    to: Address,
    pending: Vec<u8>,
}

impl EndpointOverrideWriter {
    /// 构造：`from` = 改写后地址，`to` = 原始地址。
    pub fn new(inner: Box<dyn Writer>, from: Address, to: Address) -> Self {
        Self { inner, from, to, pending: Vec::new() }
    }
}

impl Writer for EndpointOverrideWriter {
    fn write_multi_buffer(&mut self, mb: MultiBuffer) -> Pin<Box<dyn Future<Output = IoResult<()>> + Send + '_>> {
        Box::pin(async move {
            // 逐 buffer extend：mb.to_vec() 会先堆分配扁平 Vec 再拷一次
            for b in mb.iter() {
                self.pending.extend_from_slice(b.bytes());
            }
            let (out, consumed) = rewrite_complete_frames(&self.pending, &self.from, &self.to);
            self.pending.drain(..consumed);
            if out.is_empty() {
                return Ok(());
            }
            let mut mb_out = MultiBuffer::new();
            mb_out.merge_bytes(&out);
            self.inner.write_multi_buffer(mb_out).await
        })
    }

    fn shutdown(&self) {
        self.inner.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use xray_buf::io::new_reader;
    use xray_common::net::port::Port;
    use xray_xudp::packet::{PacketReader, PacketWriter};

    fn addr_v4(octets: [u8; 4]) -> Address {
        Address::from_ipv4_bytes(octets)
    }

    /// 构造 New + Keep 两个帧（目标均为 target:port），返回字节。
    fn two_frames(target: &Address, port: u16) -> Vec<u8> {
        let global_id = [9, 8, 7, 6, 5, 4, 3, 2];
        let dest = Destination::udp(target.clone(), Port::new(port));
        let mut buf = Vec::new();
        {
            let mut pw = PacketWriter::new(&mut buf, dest, global_id);
            pw.write_packet(b"first-payload").unwrap();
            pw.write_packet(b"second").unwrap();
        }
        buf
    }

    #[test]
    fn rewrite_changes_matching_target_keeps_payload_and_global_id() {
        let from = addr_v4([198, 51, 100, 7]);
        let to = Address::new_domain(String::from("sniffed.example.com"));
        let buf = two_frames(&from, 53);

        let (out, consumed) = rewrite_complete_frames(&buf, &from, &to);
        assert_eq!(consumed, buf.len(), "all bytes consumed");

        // 逐帧验证：目标地址改写为 domain，端口/载荷/顺序保留
        let mut pr = PacketReader::new(std::io::Cursor::new(&out[..]));
        let p1 = pr.read_packet().unwrap().expect("frame 1");
        assert_eq!(p1.data(), b"first-payload");
        let t1 = p1.udp_target().expect("target present");
        assert_eq!(t1.address(), &to);
        assert_eq!(t1.port().value(), 53);

        let p2 = pr.read_packet().unwrap().expect("frame 2");
        assert_eq!(p2.data(), b"second");
        assert_eq!(p2.udp_target().unwrap().address(), &to);
    }

    #[test]
    fn rewrite_leaves_non_matching_target_bytes_untouched() {
        let from = addr_v4([198, 51, 100, 7]);
        let to = Address::new_domain(String::from("sniffed.example.com"));
        let buf = two_frames(&addr_v4([1, 2, 3, 4]), 80);

        let (out, consumed) = rewrite_complete_frames(&buf, &from, &to);
        assert_eq!(consumed, buf.len());
        assert_eq!(out, buf, "non-matching frames pass through byte-identical");
    }

    #[test]
    fn rewrite_holds_incomplete_frame() {
        let from = addr_v4([198, 51, 100, 7]);
        let to = Address::new_domain(String::from("sniffed.example.com"));
        let buf = two_frames(&from, 53);

        // 只给前 5 字节（帧头都不完整）
        let (out, consumed) = rewrite_complete_frames(&buf[..5], &from, &to);
        assert_eq!(consumed, 0);
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn reader_rewrites_split_frames_across_reads() {
        let from = addr_v4([198, 51, 100, 7]);
        let to = Address::new_domain(String::from("sniffed.example.com"));
        let frame = two_frames(&from, 53);

        // duplex：分两半写，验证 reader 累积半帧后正确改写
        let (up_r, mut up_w) = tokio::io::duplex(8192);
        let mut reader = EndpointOverrideReader::new(new_reader(up_r), from, to);

        let half = frame.len() / 2;
        up_w.write_all(&frame[..half]).await.unwrap();
        up_w.write_all(&frame[half..]).await.unwrap();

        let mb = tokio::time::timeout(std::time::Duration::from_secs(5), reader.read_multi_buffer())
            .await
            .expect("timeout")
            .expect("read ok");
        let out = mb.to_vec();

        let mut pr = PacketReader::new(std::io::Cursor::new(&out[..]));
        let p1 = pr.read_packet().unwrap().expect("frame 1");
        assert_eq!(p1.data(), b"first-payload");
        assert_eq!(
            p1.udp_target().unwrap().address().as_domain(),
            Some("sniffed.example.com")
        );
    }

    #[tokio::test]
    async fn writer_rewrites_frames_and_propagates_shutdown() {
        let from = Address::new_domain(String::from("sniffed.example.com"));
        let to = addr_v4([198, 51, 100, 7]);
        let frame = two_frames(&from, 53);

        let (dn_r, dn_w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption::default());
        let mut writer = EndpointOverrideWriter::new(Box::new(dn_w) as Box<dyn Writer>, from, to);

        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&frame);
        writer.write_multi_buffer(mb).await.unwrap();

        let mut raw_reader = Box::new(dn_r) as Box<dyn Reader>;
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            raw_reader.read_multi_buffer(),
        )
        .await
        .expect("timeout")
        .expect("read ok");

        let resp_bytes = resp.to_vec();
        let mut pr = PacketReader::new(std::io::Cursor::new(&resp_bytes[..]));
        let p1 = pr.read_packet().unwrap().expect("frame 1");
        assert_eq!(
            p1.udp_target().unwrap().address(),
            &addr_v4([198, 51, 100, 7]),
            "downlink frame source rewritten back to original IP"
        );

        // shutdown 传播：读端应收到 EOF（pipe 约定：Err(Error::Eof)）
        writer.shutdown();
        let eof = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            raw_reader.read_multi_buffer(),
        )
        .await
        .expect("timeout");
        assert!(
            matches!(eof, Err(xray_buf::io::Error::Eof)),
            "reader should see EOF after shutdown, got: {eof:?}"
        );
    }
}

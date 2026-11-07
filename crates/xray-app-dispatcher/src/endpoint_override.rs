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

use std::{future::Future, pin::Pin};

use xray_buf::{
    alloc::DEFAULT_SIZE,
    buffer::Buffer,
    io::{Reader, Result as IoResult, Writer},
    multi::MultiBuffer,
};
use xray_common::net::{address::Address, destination::Destination, network::Network};
use xray_xudp::packet::FrameMetadata;

/// 改写 `buf` 前缀所有完整 XUDP 帧：目标地址 == `from` 的帧改写为 `to`
/// （端口保留，GlobalID 保留）。输出**直写池化块链**（bd cmtcc：旧实现先把
/// 改写结果攒进临时 `Vec`、再 `merge_bytes` 拷进池块 = 每事件整载二次拷贝；
/// 对比台 `D:/tmp/cmtcc-sim`（真实帧流 + 逐事件字节级不变断言，7 轮中位）
/// 实测：每事件堆分配 14→9、拷贝字节 −33%、吞吐 +22~39%）。返回
/// `(改写后字节块, 已消费字节数)`；尾部不完整帧不消费，由调用方保留。
fn rewrite_complete_frames(buf: &[u8], from: &Address, to: &Address) -> (MultiBuffer, usize) {
    // 段写入块链：块满则收块开新块（单帧 ≤ 64KiB+，块链覆盖任意事件长）。
    fn push_seg(blocks: &mut Vec<Buffer>, cur: &mut Option<Buffer>, mut seg: &[u8]) {
        while !seg.is_empty() {
            if cur.as_ref().is_none_or(|b| b.len() >= b.capacity()) {
                if let Some(b) = cur.take() {
                    blocks.push(b);
                }
                *cur = Some(Buffer::new_pooled(DEFAULT_SIZE));
            }
            let b = cur.as_mut().expect("block present");
            let wrote = b.write_from(seg);
            seg = &seg[wrote..];
        }
    }

    let mut blocks = Vec::with_capacity(2);
    let mut cur: Option<Buffer> = None;
    let mut pos = 0;
    loop {
        let rest = &buf[pos..];
        if rest.is_empty() {
            break;
        }
        let Ok((meta, consumed)) = FrameMetadata::from_bytes(rest) else {
            // 解析失败有两种：字节不够（等下一批）与畸形（这段永远出不来帧）。
            // 若 2B 长度前缀已声明整帧都在缓冲内、却仍解析失败 = 畸形 ⇒ 丢弃整帧
            // 继续；否则 Reader 循环会停在 `consumed == 0` 上反复读 ⇒ pending
            // 无界累积 + 读忙旋（bd 2cfqo，与 xdns「Err 不 drain」同族）。
            if rest.len() >= 2 {
                let body_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
                if rest.len() >= 2 + body_len {
                    pos += 2 + body_len;
                    continue;
                }
            }
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
        let rewritten =
            meta.target().filter(|t| t.network() == Network::UDP && t.address() == from).map(|t| {
                let mut m = meta.clone();
                m.set_target(Destination::udp(to.clone(), t.port()));
                m
            });
        match &rewritten {
            Some(m) => push_seg(&mut blocks, &mut cur, &m.to_bytes()),
            None => push_seg(&mut blocks, &mut cur, &rest[..consumed]),
        }
        if meta.has_data() {
            push_seg(&mut blocks, &mut cur, &rest[consumed..frame_end]);
        }
        pos += frame_end;
    }
    if let Some(b) = cur.take() {
        blocks.push(b);
    }
    (MultiBuffer::from_buffers(blocks), pos)
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
    fn read_multi_buffer(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = IoResult<MultiBuffer>> + Send + '_>> {
        Box::pin(async move {
            loop {
                let mb = self.inner.read_multi_buffer().await?;
                let eof = mb.is_empty();
                // 逐 buffer extend：mb.to_vec() 会先堆分配扁平 Vec 再拷一次
                for b in mb.iter() {
                    self.pending.extend_from_slice(b.bytes());
                }
                let (mut mb_out, consumed) =
                    rewrite_complete_frames(&self.pending, &self.from, &self.to);
                self.pending.drain(..consumed);
                if eof {
                    // EOF：残帧原样冲出（尽力而为）；无残帧时返回空 = EOF 传播
                    let tail = std::mem::take(&mut self.pending);
                    if !tail.is_empty() {
                        // 零拷贝接管 Vec 分配（Frozen 面：读零拷贝，写路径 COW）
                        mb_out.push(Buffer::from_vec(tail));
                    }
                    return Ok(mb_out);
                }
                if consumed > 0 && !mb_out.is_empty() {
                    return Ok(mb_out);
                }
                // 非空读但无完整帧（或全是被丢弃的畸形段）→ 继续读：空
                // MultiBuffer 返回给下游等于伪报 EOF。
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
    fn write_multi_buffer(
        &mut self,
        mb: MultiBuffer,
    ) -> Pin<Box<dyn Future<Output = IoResult<()>> + Send + '_>> {
        Box::pin(async move {
            // 逐 buffer extend：mb.to_vec() 会先堆分配扁平 Vec 再拷一次
            for b in mb.iter() {
                self.pending.extend_from_slice(b.bytes());
            }
            let (mb_out, consumed) = rewrite_complete_frames(&self.pending, &self.from, &self.to);
            self.pending.drain(..consumed);
            if mb_out.is_empty() {
                return Ok(());
            }
            self.inner.write_multi_buffer(mb_out).await
        })
    }

    fn shutdown(&self) {
        self.inner.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;
    use xray_buf::io::new_reader;
    use xray_common::net::port::Port;
    use xray_xudp::packet::{PacketReader, PacketWriter};

    use super::*;

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
        let out = flat_bytes(&out);
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
        assert_eq!(flat_bytes(&out), buf, "non-matching frames pass through byte-identical");
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

    /// bd 2cfqo：畸形帧（长度前缀声明整帧都在、但状态字节非法）必须丢弃并
    /// 继续解析后续合法帧，而不是当「半帧」留在 pending ⇒ 无界累积 + 读忙旋。
    #[test]
    fn rewrite_discards_malformed_frame_and_resyncs() {
        let from = addr_v4([198, 51, 100, 7]);
        let to = Address::new_domain(String::from("sniffed.example.com"));
        let good = two_frames(&from, 53);

        // 2B length=4 + 4B body，body[2] 状态字节 0xFF 非法 → 必然解析失败
        let mut buf = vec![0x00, 0x04, 0xFF, 0x00, 0x00, 0x00];
        buf.extend_from_slice(&good);

        let (out, consumed) = rewrite_complete_frames(&buf, &from, &to);
        assert_eq!(consumed, buf.len(), "畸形段与后续合法帧都必须消费掉");

        let flat = flat_bytes(&out);
        // 改写会把 IP 目标换成域名（帧变长），故只断言帧内容与顺序
        let mut pr = PacketReader::new(std::io::Cursor::new(&flat[..]));
        let p1 = pr.read_packet().unwrap().expect("frame 1");
        assert_eq!(p1.data(), b"first-payload");
        assert_eq!(p1.udp_target().unwrap().address(), &to);
        let p2 = pr.read_packet().unwrap().expect("frame 2");
        assert_eq!(p2.data(), b"second");
        assert!(pr.read_packet().unwrap().is_none(), "畸形段不得混进输出");
    }

    /// MultiBuffer 摊平为字节（块序拼接）。
    fn flat_bytes(mb: &MultiBuffer) -> Vec<u8> {
        mb.iter().flat_map(|b| b.bytes().iter().copied()).collect()
    }

    /// bd cmtcc 块链覆盖：单事件 > 8KiB（跨多个池块）时逐帧完整、
    /// 字节与单块路径等价（对比台同款字节级不变断言的产品侧锚）。
    #[test]
    fn rewrite_spans_multiple_pool_blocks() {
        let from = addr_v4([198, 51, 100, 7]);
        let to = addr_v4([203, 0, 113, 9]);
        // 12 × 1400B ≈ 17KiB > DEFAULT_SIZE(8KiB) ⇒ 必然跨块
        let mut buf = Vec::new();
        let mut pw =
            PacketWriter::new(&mut buf, Destination::udp(from.clone(), Port::new(53)), [1; 8]);
        for _ in 0..12 {
            pw.write_packet_with_udp_target(
                &vec![b'x'; 1400],
                &Destination::udp(from.clone(), Port::new(53)),
            )
            .unwrap();
        }
        let (out, consumed) = rewrite_complete_frames(&buf, &from, &to);
        assert_eq!(consumed, buf.len());
        let flat = flat_bytes(&out);
        assert!(out.buffer_count() >= 2, "必须跨池块：got {} blocks", out.buffer_count());
        let mut pr = PacketReader::new(std::io::Cursor::new(&flat[..]));
        for i in 0..12 {
            let p = pr.read_packet().unwrap().expect("frame");
            assert_eq!(p.data().len(), 1400, "frame {i}");
            assert_eq!(p.udp_target().unwrap().address(), &to);
        }
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

        let mb =
            tokio::time::timeout(std::time::Duration::from_secs(5), reader.read_multi_buffer())
                .await
                .expect("timeout")
                .expect("read ok");
        let out = mb.to_vec();

        let mut pr = PacketReader::new(std::io::Cursor::new(&out[..]));
        let p1 = pr.read_packet().unwrap().expect("frame 1");
        assert_eq!(p1.data(), b"first-payload");
        assert_eq!(p1.udp_target().unwrap().address().as_domain(), Some("sniffed.example.com"));
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
        let resp =
            tokio::time::timeout(std::time::Duration::from_secs(5), raw_reader.read_multi_buffer())
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
        let eof =
            tokio::time::timeout(std::time::Duration::from_secs(5), raw_reader.read_multi_buffer())
                .await
                .expect("timeout");
        assert!(
            matches!(eof, Err(xray_buf::io::Error::Eof)),
            "reader should see EOF after shutdown, got: {eof:?}"
        );
    }
}

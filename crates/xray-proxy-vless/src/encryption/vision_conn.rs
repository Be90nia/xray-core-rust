//! XTLS-Vision 连接包装（对应 Go `proxy/proxy.go` 的 VisionReader/VisionWriter）。
//!
//! 在 [`CommonConn`]（AEAD 加密层）之上提供 Vision padding：
//! - [`VisionConn::poll_write`]: 明文 padding 包装 → 底层 conn（CommonConn AEAD 或 TLS 直传）
//! - [`VisionConn::poll_read`]: 底层 conn 读取 → unpadding → 返回明文
//!
//! 切片 2a：padding 模式完整（Continue/End）。
//! 切片 2b：splice（command=Direct 触发，绕过 Vision padding，仍走底层 conn）。

use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use rand::{SeedableRng, rngs::StdRng};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use xray_transport::connection::Connection;

use crate::encryption::{
    common_conn::CommonConn,
    vision::{
        COMMAND_PADDING_CONTINUE, COMMAND_PADDING_DIRECT, COMMAND_PADDING_END,
        DEFAULT_PADDING_SEED, DirectionState, TrafficState, is_complete_record_slices,
        xtls_filter_tls, xtls_padding, xtls_unpadding,
    },
};

/// padding 块 content 上限（对齐 Go ReshapeMultiBuffer 的 `Size-21` 拆分上限：
/// BUF_SIZE(2048) - header(5) - uuid(16) = 2027）。必须与 vision::BUF_SIZE
/// 同步：xtls_padding 的 cap = BUF_SIZE-21-content_len，content 超过该值会
/// 使 cap 变负。
const MAX_PADDING_CONTENT: usize = 2027;
/// 内层裸 TCP 克隆入口（vision splice 用）。
///
/// 生产链内层是 `Box<dyn Connection>`（实现 [`Connection`]，穿透到最底层
/// `TcpConnection::raw_tcp_clone`）；tests/inbound 的内层（`CommonConn<DuplexStream>`、
/// `tokio::io::Join`）无裸 TCP 可克隆，走默认 `None`。
#[allow(private_bounds)] // trait 有意 crate 内私有，公开类型 bound 泄露为既定设计
pub(crate) trait InnerRawClone {
    fn inner_raw_tcp_clone(&self) -> Option<TcpStream> {
        None
    }
}

impl InnerRawClone for Box<dyn Connection> {
    fn inner_raw_tcp_clone(&self) -> Option<TcpStream> {
        (**self).raw_tcp_clone()
    }
}

impl<A: AsyncRead, B: AsyncWrite> InnerRawClone for tokio::io::Join<A, B> {}

impl InnerRawClone for CommonConn<tokio::net::TcpStream> {
    fn inner_raw_tcp_clone(&self) -> Option<TcpStream> {
        xray_transport::connection::dup_tcp_stream(self.inner_conn())
    }
}

impl InnerRawClone for CommonConn<tokio::io::DuplexStream> {}
/// Vision 连接：包装 [`CommonConn`]，提供 XTLS-Vision padding。
///
/// 对应 Go 的 VisionReader/VisionWriter。padding 模式下每个读写都包装/解包
/// Vision padding 块，直到 command=End（关闭 padding）或 command=Direct（splice，待办）。
pub struct VisionConn<C> {
    inner: C,
    /// user_uuid（始终保留，downlink unpadding 匹配首块用）。
    user_uuid: Vec<u8>,
    /// uplink 首次 padding 附带的 uuid（take 后 None）。
    uplink_uuid_pending: Option<Vec<u8>>,
    /// uplink（writer）方向状态。
    #[allow(dead_code)] // 写路径经 inner conn 承载，字段保留与 downlink_state 对称
    uplink_state: DirectionState,
    /// downlink（reader）方向状态。
    downlink_state: DirectionState,
    /// unpadding 后待返回的 content。
    downlink_pending: Vec<u8>,
    downlink_pending_pos: usize,
    /// padding 块待写入底层（padded, sent_in_padded, original_buf_len）。
    uplink_pending: VecDeque<UpFrame>,
    /// padding 模式标志（command=End 后关闭）。
    uplink_padding: bool,
    downlink_padding: bool,
    rng: StdRng,
    /// 账户级 padding seed（testseed，归一化后 4 元素；上/下行 padding 共用）。
    padding_seed: [u32; 4],
    /// uplink TLS 过滤状态（检测 TLS 1.3 → enable_xtls → splice）。
    uplink_traffic: TrafficState,
    /// downlink TLS 过滤状态（检测服务器 TLS 1.3 → enable_xtls → splice）。
    downlink_traffic: TrafficState,
    /// splice 后的裸 TCP 读直通道（DIRECT 帧后启用：取 raw_tcp 或克隆内层）。
    raw_fallback: Option<TcpStream>,
    /// server 模式注入的裸 TCP 克隆（accept 层 dup，DIRECT 前不启用）。
    raw_tcp: Option<TcpStream>,
    /// poll_read 阶段 16KB 临时缓冲提升为堆字段，避免握手/首请求期高频
    /// poll_read 时的 16KB 栈帧占用（栈帧不被编译器复用）。Vec 容量在
    /// new/new_server 中按 16KB 预分配后稳态复用。
    read_tmp: Vec<u8>,
    /// 写侧 DIRECT 已判定、待「当前 write 完成」才激活 raw_fallback 的挂起标志。
    /// 对齐 Go f926ee4a（issue #4878）：激活提前于 in-flight 写时，第二个
    /// writer（splice 泵/half-close）会与安全层写并发触碰同一 TCP fd →
    /// SSL out-of-order。判定时仅置位；poll_write 把 pending 帧写完返回
    /// Ok 时经 [`Self::arm_splice_raw`] 真正启用。
    splice_armed: bool,
    /// End 提交闸（bd VISIONMAC）：End 帧已入队/写完但 inner flush 尚未确认
    /// 上线。commit（flush Ready → `uplink_padding=false`）之前 branch 2
    /// 不可达——未成帧明文永不逃逸，switch 帧绝不丢失。
    end_commit: bool,
    /// 角色标记（new=client / new_server=server），预留诊断。
    #[allow(dead_code)]
    is_server: bool,
    /// raw 写入起步闸：arm 后首个 raw 写延迟 RAW_WRITE_ARM_DELAY，等对端
    /// 读完 DIRECT 帧（其 rustls 的同 recv 过读会把紧随的 raw 字节当隧道
    /// 记录解密 → BadRecordMac fatal alert → 双端皆死，macOS #08 实测）。
    /// 定时器到期后清 None，后续 raw 写零开销。
    raw_write_gate: Option<Pin<Box<tokio::time::Sleep>>>,
    /// [VISIONMAC 诊断] XRAY_FRDBG 读路径轮询计数（临时埋点）。
    frdbg_polls: u64,
}

fn frdbg_micros() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() % 1_000_000_000)
        .unwrap_or(0)
}

/// 上行待写帧：padded 帧字节 + 已写偏移 + 该帧对应的 caller 消费量 + 提交闸类别。
/// 多帧队列 = GO MultiBuffer 批语义（批内 Continue，末帧 End/Direct）。
#[derive(Default)]
struct UpFrame {
    padded: Vec<u8>,
    sent: usize,
    orig_len: usize,
    gate: UpGate,
}

/// 尾帧提交闸类别。
#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum UpGate {
    #[default]
    None,
    /// Direct 帧写完 → poll_arm_gate（arm raw + commit 翻转）。
    DirectArm,
    /// End 帧写完 → inner flush Ready（commit 翻转）。
    EndCommit,
}
/// raw 起步闸延迟：覆盖对端「收 DIRECT 帧 → 处理 → 切 raw 读」的调度
/// 延迟。实测恶性窗口 ~1.5ms（loopback 合流），50ms=30x 余量；每次
/// splice 切换仅首个上游写承担一次，对吞吐无影响。
const RAW_WRITE_ARM_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

#[allow(private_interfaces)] // InnerRawClone 为 crate 内实现细节，随公开方法泄露属刻意
impl<C> VisionConn<C>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// 创建 Vision 连接，包装一个已建立的底层连接。
    ///
    /// `conn` 可以是 `CommonConn`（encryption=mlkem768 场景）或 TLS conn
    /// （encryption=none + flow=xtls-rprx-vision 场景）。
    /// `user_uuid` 为首块 padding 附带的 UUID（Vision 协议要求）。
    #[must_use]
    pub fn new(conn: C, user_uuid: Vec<u8>) -> Self {
        let uplink_uuid_pending = Some(user_uuid.clone());
        Self {
            inner: conn,
            user_uuid: user_uuid.clone(),
            uplink_uuid_pending,
            uplink_state: DirectionState::default(),
            downlink_state: DirectionState::default(),
            downlink_pending: Vec::new(),
            downlink_pending_pos: 0,
            uplink_pending: VecDeque::new(),
            uplink_padding: true,
            downlink_padding: true,
            rng: StdRng::from_os_rng(),
            padding_seed: DEFAULT_PADDING_SEED,
            uplink_traffic: TrafficState::new(user_uuid.clone()),
            downlink_traffic: TrafficState::new(user_uuid.clone()),
            raw_fallback: None,
            raw_tcp: None,
            read_tmp: Vec::with_capacity(16 * 1024),
            splice_armed: false,
            end_commit: false,
            is_server: false,
            raw_write_gate: None,
            frdbg_polls: 0,
        }
    }

    /// 注入账户级 padding seed（对应 Go `MemoryAccount.Testseed`，经
    /// `normalize_padding_seed` 归一化：<4 用默认兜底，≥4 取前 4）。
    ///
    /// 不调用时走 [`DEFAULT_PADDING_SEED`]，与 Go `len(testseed)<4` 兜底一致。
    #[must_use]
    pub fn with_padding_seed(mut self, seed: &[u32]) -> Self {
        self.padding_seed = crate::encryption::vision::normalize_padding_seed(seed);
        self
    }

    /// server 模式构造（vision splice）：accept 层在 TLS accept 消费 socket 前
    /// dup 出的裸 TCP 克隆。仅 DIRECT 帧（双向都切裸流）后启用；END 只关
    /// padding 不切 raw——对端仍在安全层内说话，提前直通裸流会读到密文。
    #[must_use]
    pub fn new_server(conn: C, user_uuid: Vec<u8>, raw_tcp: TcpStream) -> Self {
        let uplink_uuid_pending = Some(user_uuid.clone());
        Self {
            inner: conn,
            user_uuid: user_uuid.clone(),
            uplink_uuid_pending,
            uplink_state: DirectionState::default(),
            downlink_state: DirectionState::default(),
            downlink_pending: Vec::new(),
            downlink_pending_pos: 0,
            uplink_pending: VecDeque::new(),
            uplink_padding: true,
            downlink_padding: true,
            rng: StdRng::from_os_rng(),
            padding_seed: DEFAULT_PADDING_SEED,
            uplink_traffic: TrafficState::new(user_uuid.clone()),
            downlink_traffic: TrafficState::new(user_uuid.clone()),
            raw_fallback: None,
            raw_tcp: Some(raw_tcp),
            read_tmp: Vec::with_capacity(16 * 1024),
            splice_armed: false,
            end_commit: false,
            is_server: true,
            raw_write_gate: None,
            frdbg_polls: 0,
        }
    }

    /// dial 同步阶段主动发 uuid-only padding 块,后续 chunk 进 vision content。
    /// 对齐 Go outbound VisionWriter `mb[0]=nil` → XtlsPadding(None, CommandPaddingContinue)。
    pub async fn write_uuid_only_padding(&mut self) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        use crate::encryption::vision::{COMMAND_PADDING_CONTINUE, xtls_padding};
        let padded = xtls_padding(
            None,
            COMMAND_PADDING_CONTINUE,
            &mut self.uplink_uuid_pending,
            true,
            &self.padding_seed,
            &mut self.rng,
        );
        self.inner.write_all(&padded).await?;
        Ok(())
    }
}

impl<C> AsyncRead for VisionConn<C>
where
    C: AsyncRead + AsyncWrite + Unpin + InnerRawClone,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // 1. pending 优先返回
            if this.downlink_pending_pos < this.downlink_pending.len() {
                let avail = &this.downlink_pending[this.downlink_pending_pos..];
                let n = avail.len().min(buf.remaining());
                buf.put_slice(&avail[..n]);
                this.downlink_pending_pos += n;
                if this.downlink_pending_pos >= this.downlink_pending.len() {
                    this.downlink_pending.clear();
                    this.downlink_pending_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // 2. padding 关闭 → 优先裸 TCP 直读；raw 通道不可用（无 TLS 或 非生产链内层）才退
            //    inner。splice 后读 inner 会把对端在裸 TCP 上发的明文 TLS records 当外层密文解密 →
            //    永远解不开。
            if !this.downlink_padding {
                if let Some(raw) = this.raw_fallback.as_mut() {
                    return Pin::new(raw).poll_read(cx, buf);
                }
                let res = Pin::new(&mut this.inner).poll_read(cx, buf);
                if std::env::var("XRAY_FRDBG").is_ok() {
                    this.frdbg_polls += 1;
                    match &res {
                        Poll::Pending => {
                            if this.frdbg_polls % 4096 == 0 {
                                eprintln!(
                                    "[VCDBG:{}MS] raw-inner Pending polls={}",
                                    frdbg_micros(),
                                    this.frdbg_polls
                                );
                            }
                        },
                        Poll::Ready(Ok(())) => {
                            let n = buf.filled().len();
                            if n == 0 {
                                eprintln!(
                                    "[VCDBG:{}MS] raw-inner EOF polls={}",
                                    frdbg_micros(),
                                    this.frdbg_polls
                                );
                            }
                        },
                        Poll::Ready(Err(e)) => {
                            eprintln!("[VCDBG:{}MS] raw-inner ERR {e}", frdbg_micros());
                        },
                    }
                }
                return res;
            }
            // 3. padding 模式 → CommonConn read + unpadding。临时缓冲提升为 struct
            //    字段（read_tmp）避免每 poll_read 16KB 栈帧；栈帧不被 编译器复用 →
            //    握手/首请求期高频 poll_read 时栈占膨胀。 容量稳态复用：len
            //    不足才补零扩容（仅首次），此前 clear+resize(16K,0) 每 poll 16KB memset
            //    已免（wfx8-1）。 有效字节以 rb.filled().len() 为界，旧数据不会被读出。
            if this.read_tmp.len() < 16 * 1024 {
                this.read_tmp.resize(16 * 1024, 0);
            }
            // ReadBuf::new 接收可变借用，poll_read 期间独占 read_tmp 切片。
            // borrow 结束后 n = rb.filled().len() 可读回已填充字节。
            let mut rb = ReadBuf::new(&mut this.read_tmp[..]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    let content = xtls_unpadding(
                        &this.read_tmp[..n],
                        &mut this.downlink_state,
                        &this.user_uuid,
                    );
                    let cmd = this.downlink_state.current_command;
                    // server 关闭下行 padding：END=只关 padding（继续读 TLS 层），
                    // DIRECT=splice——server 已 UnwrapRawConn，此后在裸 TCP 上
                    // 收发端到端 TLS records。本帧 content 先入 pending 返回给
                    // caller，再克隆裸 socket 切换读通道（对齐 Go XtlsRead）。
                    // 对齐 Go VisionReader（proxy.go L244-253）：仅当当前帧
                    // 完成（content/padding 无残留）时 END/DIRECT 才生效；
                    // End/Direct 帧可能跨块，帧未完成就切 raw 会跳过帧尾字节
                    // 并把外层 TLS 密文当裸流转发 → curl 解密失败。
                    let frames_done = this.downlink_state.remaining_content <= 0
                        && this.downlink_state.remaining_padding <= 0
                        && cmd != 0;
                    if frames_done {
                        if std::env::var("XRAY_FRDBG").is_ok() {
                            eprintln!("[VCDBG:{}MS] frame done cmd={}", frdbg_micros(), cmd);
                        }
                        if cmd == COMMAND_PADDING_END as i32 {
                            this.downlink_padding = false;
                        } else if cmd == COMMAND_PADDING_DIRECT as i32 {
                            this.downlink_padding = false;
                            if this.raw_fallback.is_none() {
                                this.raw_fallback = this
                                    .raw_tcp
                                    .take()
                                    .or_else(|| this.inner.inner_raw_tcp_clone());
                            }
                            // 切换后**禁止再读 inner**（txno-splice 终版语义，
                            // 取代 dbe9f49 的 drain 循环）：DIRECT 是对端安全层
                            // 的最后一条隧道记录（其 writer 同步切裸流），TCP 字
                            // 节流全序保证此帧之前的字节已按序交付，inner 的
                            // received_plaintext 此刻必空。此后 inner 上的任何额
                            // 外 poll_read 都是对 socket 的一次 recv：把对端已切
                            // 裸流的端到端明文字节拉进 rustls deframer——
                            // - 完整记录：用隧道密钥解密 → DecryptError → 字节 被 TLS
                            //   层吞掉（静默数据丢失）；
                            // - 半条记录：Pending 滞留 opaque 缓冲，切 raw dup
                            //   后该前缀永久不可达（字节流断裂）。
                            // dbe9f49 的 drain 恰好制造第一种丢失（其 Err 吞掉
                            // 分支），且对真实 TLS 层永远回收不到东西（DIRECT
                            // 帧之后不存在可解密记录）。Go 无此坑：crypto/tls
                            // readFromUntil 按当前记录精确读取不过读，且
                            // UnwrapRawConn 前经 unsafe 反射抓私有 input/
                            // rawInput 清空（inbound.go:583-586 + proxy.go
                            // L259-270）。rustls 无公开 API 触达 deframer 内部
                            // 缓冲，唯一安全解 = DIRECT 帧交付后封读 inner。
                            // 已知残余边界（读侧过读窗口）：若对端 raw 字节与
                            // DIRECT 帧同段合流、在同一次 recv 进入 deframer，
                            // 该尾段仍不可达——需 record-framer 级改造（对齐 Go
                            // readFromUntil 精确读形态）方可根治，概率远低于
                            // 写侧激活竞态（本轮 macOS #08 实测定罪为写侧）。
                        }
                    }
                    if !content.is_empty() {
                        // downlink TLS 过滤：检测下行 TLS 1.3 → enable_xtls
                        // 对齐 Go VisionReader 的 xtls_filter_tls 调用
                        if this.downlink_traffic.number_of_packet_to_filter > 0 {
                            xtls_filter_tls(&[&content], &mut this.downlink_traffic);
                        }
                        this.downlink_pending = content;
                        this.downlink_pending_pos = 0;
                    }
                    // content 空（纯 padding 块）或已存 pending → continue
                },
                Poll::Ready(Err(e)) => {
                    // 结构化观测：TLS 层 fatal（如对端安全层误解 raw 流的
                    // BadRecordMac）是 splice 边界问题的第一现场。
                    tracing::warn!(error = %e, "vision inner read error");
                    return Poll::Ready(Err(e));
                },
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<C> AsyncWrite for VisionConn<C>
where
    C: AsyncRead + AsyncWrite + Unpin + InnerRawClone,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // 单片批：与 poll_write_vectored 共用整批判定状态机（bd VISIONMAC）。
        self.poll_write_vectored(cx, &[io::IoSlice::new(buf)])
    }

    fn is_write_vectored(&self) -> bool {
        // 写侧整批判定依赖 vectored 入口拿到完整批次（Go WriteMultiBuffer 的
        // 整 mb 语义）；bridge write_all_mb 据此选择聚合路径。
        true
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            // 1. 先写完 pending 队首（switch 帧在途时，caller 后续写入在此串行化）
            if let Some(frame) = this.uplink_pending.front_mut() {
                if frame.sent < frame.padded.len() {
                    match Pin::new(&mut this.inner).poll_write(cx, &frame.padded[frame.sent..]) {
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "inner conn accepted 0 bytes",
                            )));
                        },
                        Poll::Ready(Ok(n)) => {
                            frame.sent += n;
                            if frame.sent < frame.padded.len() {
                                // 底层 Ready，continue 继续写剩余
                                continue;
                            }
                        },
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                // 帧已全量写入：过提交闸（尾帧 gate）或直接完成
                let (orig_len, gate) = (frame.orig_len, frame.gate);
                match gate {
                    UpGate::None => {
                        this.uplink_pending.pop_front();
                        return Poll::Ready(Ok(orig_len));
                    },
                    UpGate::DirectArm => match this.poll_arm_gate(cx) {
                        Poll::Ready(Ok(())) => {
                            this.uplink_pending.pop_front();
                            return Poll::Ready(Ok(orig_len));
                        },
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    },
                    UpGate::EndCommit => match Pin::new(&mut this.inner).poll_flush(cx) {
                        Poll::Ready(Ok(())) => {
                            this.uplink_padding = false;
                            this.end_commit = false;
                            this.uplink_pending.pop_front();
                            return Poll::Ready(Ok(orig_len));
                        },
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    },
                }
            }

            // 2. padding 关闭 → 裸 TCP 直写（Direct commit 后）或 inner 直写 （End commit 后，无
            //    raw 通道不 splice）。vectored 聚合直透。
            if !this.uplink_padding {
                if let Some(raw) = this.raw_fallback.as_mut() {
                    // raw 起步闸：等对端消费 DIRECT 帧（见 raw_write_gate 注释）。
                    if let Some(sleep) = this.raw_write_gate.as_mut() {
                        if sleep.as_mut().poll(cx).is_pending() {
                            return Poll::Pending;
                        }
                        this.raw_write_gate = None;
                    }
                    return Pin::new(raw).poll_write_vectored(cx, bufs);
                }
                return Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
            }

            // 3. padding 模式 → 批级 TLS 检测 + 整批分帧入队（GO MultiBuffer 批语义：整批 = 完整
            //    0x17 record 组才升格；末帧携 End/Direct， 其余帧 Continue。整批 = 整个 vectored
            //    批（对齐 Go 对整个 MultiBuffer 做 IsCompleteRecord），8KB 单缓冲粒度判定是 Direct
            //    触发不足的写侧半边（bd VISIONMAC）。
            let total: usize = bufs.iter().map(|s| s.len()).sum();
            if total == 0 {
                return Poll::Ready(Ok(0));
            }
            // TLS filter（过滤窗口内；探针取批首 ≤2KB，跨片拷贝，对齐 GO 按缓冲计数）
            let probe_end = total.min(MAX_PADDING_CONTENT);
            let mut probe = [0u8; MAX_PADDING_CONTENT];
            copy_io_slice_span(bufs, 0, probe_end, &mut probe[..probe_end]);
            if this.uplink_traffic.number_of_packet_to_filter > 0 {
                xtls_filter_tls(&[&probe[..probe_end]], &mut this.uplink_traffic);
            }
            let write_side =
                if this.is_server { &this.uplink_traffic } else { &this.downlink_traffic };
            let is_app_data =
                total >= 3 && probe[0] == 0x17 && probe[1] == 0x03 && probe[2] == 0x03;
            let whole_complete =
                is_app_data && write_side.is_tls && is_complete_record_slices(bufs);
            let is_early_end =
                !write_side.is_tls12_or_above && write_side.number_of_packet_to_filter <= 1;
            let batch_command = if whole_complete && write_side.enable_xtls {
                COMMAND_PADDING_DIRECT
            } else if whole_complete || is_early_end {
                COMMAND_PADDING_END
            } else {
                COMMAND_PADDING_CONTINUE
            };
            let long_padding = if whole_complete {
                true
            } else {
                this.uplink_traffic.is_tls || this.downlink_traffic.is_tls
            };
            // 整批分帧：≤MAX_PADDING_CONTENT 逐片 Continue；末片携 End/Direct。
            // early_end 时末片即 End 帧，commit 后 caller 余量经 branch 2 inner
            // 直写（= GO break 后剩余缓冲 unpadded 的等价时序）。跨片片段
            // 拷入栈缓冲（xtls_padding 随后仍要拷入 padded 帧，双拷贝仅跨片
            // 发生）。
            let mut off = 0usize;
            while off < total {
                let end = (off + MAX_PADDING_CONTENT).min(total);
                let is_last = end == total;
                let (piece_cmd, piece_gate) = if is_last {
                    match batch_command {
                        COMMAND_PADDING_DIRECT => (COMMAND_PADDING_DIRECT, UpGate::DirectArm),
                        COMMAND_PADDING_END => (COMMAND_PADDING_END, UpGate::EndCommit),
                        _ => (COMMAND_PADDING_CONTINUE, UpGate::None),
                    }
                } else {
                    (COMMAND_PADDING_CONTINUE, UpGate::None)
                };
                let plen = end - off;
                let mut piece = [0u8; MAX_PADDING_CONTENT];
                copy_io_slice_span(bufs, off, end, &mut piece[..plen]);
                let padded = xtls_padding(
                    Some(&piece[..plen]),
                    piece_cmd,
                    &mut this.uplink_uuid_pending,
                    long_padding,
                    &this.padding_seed,
                    &mut this.rng,
                );
                let orig = end - off;
                this.uplink_pending.push_back(UpFrame {
                    padded,
                    sent: 0,
                    orig_len: orig,
                    gate: piece_gate,
                });
                off = end;
            }
            // 尾帧 Direct/End 的模式翻转推迟到提交（commit-record）
            match batch_command {
                COMMAND_PADDING_DIRECT => this.splice_armed = true,
                COMMAND_PADDING_END => this.end_commit = true,
                _ => {},
            }
            // continue → branch 1 从队首开始写
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(raw) = this.raw_fallback.as_mut() {
            return Pin::new(raw).poll_flush(cx);
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(raw) = this.raw_fallback.as_mut() {
            // splice 后对端已拆外层 TLS：半关闭通知必须走裸 TCP（inner 的
            // TLS close_notify 会被对端当 raw bytes 转发污染下游流）。
            return Pin::new(raw).poll_shutdown(cx);
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// 从 IoSlice 批中拷出逻辑区间 `[start, end)`（跨片拼接，片内直接拷贝）。
/// 批语义下片段跨片的场景仅 8KB 缓冲边界一处（片长 ≥ 片段上限 2027B 的
/// 整数倍边界），双拷贝开销可忽略。
fn copy_io_slice_span(bufs: &[io::IoSlice<'_>], start: usize, end: usize, out: &mut [u8]) {
    debug_assert!(end >= start && out.len() >= end - start);
    let mut pos = 0usize;
    let mut oi = 0usize;
    for s in bufs {
        let (sbegin, send) = (pos, pos + s.len());
        pos = send;
        if send <= start {
            continue;
        }
        if sbegin >= end {
            break;
        }
        let lo = start.max(sbegin) - sbegin;
        let hi = end.min(send) - sbegin;
        let n = hi - lo;
        out[oi..oi + n].copy_from_slice(&s[lo..hi]);
        oi += n;
    }
    debug_assert_eq!(oi, end - start);
}

#[allow(private_bounds)] // InnerRawClone 有意 crate 内私有；bound 泄露为既定设计（rustc private-bounds）
impl<C> VisionConn<C>
where
    C: InnerRawClone + AsyncWrite + Unpin,
{
    /// 写侧 splice 激活闸门：DIRECT 帧写完 → 先确认 inner 安全层密文全部
    /// 落 socket → 才 arm raw。返回 `Ready(Ok(()))` = 已（或无需）激活。
    ///
    /// 为什么必须 flush：tokio-rustls 的 `poll_write` 是 BufWriter 语义
    /// （common/mod.rs poll_write 的 `(n, true) => Poll::Ready(Ok(n))` 分支）
    /// ——`Ok(len)` 只保证密文进入内部 sendable_tls 缓冲，write_io 撞
    /// WouldBlock 时尾巴仍滞留缓冲。若看到 Ok(len) 就 arm raw：
    /// - 尾巴滞留时激活后 `poll_flush`/`poll_shutdown` 已改道 raw_fallback， TLS
    ///   记录尾巴**永久出不去**——对端 deframer 停在半条记录上永久 Pending（双方零 error
    ///   静默停摆，macOS Interop #08 r2 实测形态）；
    /// - 尾巴随后被下一次 inner 写带出时，后续 raw 字节已先上线——线序 颠倒，对端把 raw 明文当隧道
    ///   TLS 记录解析 → DecryptError 级联。
    ///
    /// Go 无此坑：crypto/tls.Conn.Write 从不虚报写完。
    fn poll_arm_gate(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.splice_armed {
            match Pin::new(&mut self.inner).poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    self.arm_splice_raw();
                    Poll::Ready(Ok(()))
                },
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        } else if self.end_commit {
            // End 提交闸：End 帧（含密文尾巴）确认全部上线，才放行未成帧直写
            match Pin::new(&mut self.inner).poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    self.uplink_padding = false;
                    self.end_commit = false;
                    Poll::Ready(Ok(()))
                },
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    /// 写侧 splice 激活收口：pending DIRECT 帧完整写入底层后才调用。
    /// 对齐 Go f926ee4a "Enable splice only after this write has completed"
    /// （proxy.go WriteMultiBuffer 尾段）：激活只允许发生在 in-flight 写
    /// 完成之后，防第二个 writer 并发触碰同一 TCP fd（issue #4878）。
    fn arm_splice_raw(&mut self) {
        if self.splice_armed {
            self.splice_armed = false;
            // Direct commit：switch 帧已确认上线，此后 caller 写入走裸流
            self.uplink_padding = false;
            self.raw_write_gate = Some(Box::pin(tokio::time::sleep(RAW_WRITE_ARM_DELAY)));
            if self.raw_fallback.is_none() {
                self.raw_fallback =
                    self.raw_tcp.take().or_else(|| self.inner.inner_raw_tcp_clone());
            }
        }
    }
}

/// `Connection` 转发（地址信息透传内层，padding 层不改变连接属性），
/// 让 `VisionConn<Box<dyn Connection>>` 可作为 `Box<dyn Connection>` 返回生产路径。
impl<C> xray_transport::connection::Connection for VisionConn<C>
where
    C: xray_transport::connection::Connection + InnerRawClone,
{
    fn remote_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        self.inner.remote_addr()
    }

    fn local_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::encryption::aead::Aead;

    /// 构造 TCP 回环 socket 对 + 各自的裸克隆件（server splice 测试）。
    async fn make_tcp_pair() -> (
        (tokio::net::TcpStream, tokio::net::TcpStream),
        (tokio::net::TcpStream, tokio::net::TcpStream),
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (s, _) = listener.accept().await.unwrap();
        let c2 = xray_transport::connection::dup_tcp_stream(&c).unwrap();
        let s2 = xray_transport::connection::dup_tcp_stream(&s).unwrap();
        ((c, c2), (s, s2))
    }

    /// 构造一对互连的 VisionConn（共享相同 AEAD key，模拟 handshake 后状态）。
    fn make_pair() -> (
        VisionConn<CommonConn<tokio::io::DuplexStream>>,
        VisionConn<CommonConn<tokio::io::DuplexStream>>,
    ) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let uuid = vec![0xABu8; 16];
        let key = b"united-key".to_vec();
        let ctx = b"ctx";
        let common_a = CommonConn::new(
            a,
            Aead::new(ctx, &key, true),
            Aead::new(ctx, &key, true),
            true,
            key.clone(),
        );
        let common_b = CommonConn::new(
            b,
            Aead::new(ctx, &key, true),
            Aead::new(ctx, &key, true),
            true,
            key.clone(),
        );
        (VisionConn::new(common_a, uuid.clone()), VisionConn::new(common_b, uuid.clone()))
    }

    #[tokio::test]
    async fn round_trip_basic() {
        let (mut a, mut b) = make_pair();
        a.write_all(b"hello vision").await.unwrap();
        a.flush().await.unwrap();

        let mut buf = [0u8; 12];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello vision");
    }

    #[tokio::test]
    async fn round_trip_bidirectional() {
        let (mut a, mut b) = make_pair();
        a.write_all(b"c2s-hello").await.unwrap();
        a.flush().await.unwrap();
        b.write_all(b"s2c-world").await.unwrap();
        b.flush().await.unwrap();

        let mut buf = [0u8; 9];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"c2s-hello");
        a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"s2c-world");
    }

    #[tokio::test]
    async fn multiple_writes() {
        let (mut a, mut b) = make_pair();
        a.write_all(b"msg1-").await.unwrap();
        a.write_all(b"msg2-").await.unwrap();
        a.write_all(b"msg3").await.unwrap();
        a.flush().await.unwrap();

        let mut buf = [0u8; 14];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"msg1-msg2-msg3");
    }

    #[tokio::test]
    async fn medium_write() {
        // 100 字节（一个 CommonConn record），验证基本 padding/unpadding。
        let (mut a, mut b) = make_pair();
        let payload: Vec<u8> = (0u8..=255).cycle().take(100).collect();
        a.write_all(&payload).await.unwrap();
        a.flush().await.unwrap();

        let mut buf = vec![0u8; 100];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, payload);
    }
    #[tokio::test]
    async fn large_write() {
        // 跨多个 CommonConn record（每段 ≤8192）验证 unpadding 跨 record 累积。
        // 用 join! 并发 write+read，避免顺序死锁（write 缓冲满时需 read 消费）。
        let (mut a, mut b) = make_pair();
        let payload: Vec<u8> = (0u8..=255).cycle().take(16_384).collect();
        let payload_clone = payload.clone();

        tokio::join!(
            async {
                a.write_all(&payload).await.unwrap();
                a.flush().await.unwrap();
            },
            async {
                let mut buf = vec![0u8; 16_384];
                b.read_exact(&mut buf).await.unwrap();
                assert_eq!(buf, payload_clone);
            }
        );
    }

    /// 构造 TLS 1.3 ServerHello record（触发 xtls_filter_tls enable_xtls）。
    fn build_tls13_server_hello_record() -> Vec<u8> {
        let mut buf = Vec::new();
        // record header placeholder (len 填后补)
        buf.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x00]);
        let hs_start = buf.len();
        buf.push(0x02); // ServerHello
        buf.extend_from_slice(&[0x00, 0x00, 0x00]); // handshake len placeholder
        let hs_body_start = buf.len();
        buf.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
        buf.extend_from_slice(&[0xAB; 32]); // random
        buf.push(32); // session_id_len
        buf.extend_from_slice(&[0xCD; 32]); // session_id
        buf.extend_from_slice(&[0x13, 0x01]); // cipher TLS_AES_128_GCM_SHA256
        buf.push(0x00); // compression null
        let ext_start = buf.len();
        buf.extend_from_slice(&[0x00, 0x00]); // ext len placeholder
        // supported_versions: type=0x002b + len=2 + 0x0304 (TLS 1.3)
        buf.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        let ext_len = buf.len() - ext_start - 2;
        buf[ext_start..ext_start + 2].copy_from_slice(&(ext_len as u16).to_be_bytes());
        let hs_len = buf.len() - hs_body_start;
        buf[hs_start + 1..hs_start + 4].copy_from_slice(&(hs_len as u32).to_be_bytes()[1..]);
        let rec_len = buf.len() - 5;
        buf[3..5].copy_from_slice(&(rec_len as u16).to_be_bytes());
        buf
    }

    /// 构造 TLS ApplicationData record。
    fn build_tls_app_data(payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x17, 0x03, 0x03]);
        buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    #[tokio::test]
    async fn splice_uplink_on_tls13() {
        let (mut a, mut b) = make_pair();
        // 1. TLS 1.3 ServerHello → xtls_filter_tls enable_xtls
        let sh = build_tls13_server_hello_record();
        a.write_all(&sh).await.unwrap();
        a.flush().await.unwrap();
        // 2. TLS ApplicationData → enable_xtls + is_complete_record → Direct + splice
        let app = build_tls_app_data(b"GET / HTTP/1.1\r\n\r\n");
        a.write_all(&app).await.unwrap();
        a.flush().await.unwrap();
        // 3. splice 后明文直写（绕过 padding）
        a.write_all(b"post-splice").await.unwrap();
        a.flush().await.unwrap();
        // reader b: sh（Continue padding）+ app（Direct padding content）+ post-splice（splice
        // 后直读）
        let mut buf = vec![0u8; sh.len() + app.len() + 11];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf[..sh.len()], &sh);
        assert_eq!(&buf[sh.len()..sh.len() + app.len()], &app);
        assert_eq!(&buf[sh.len() + app.len()..], b"post-splice");
    }

    #[tokio::test]
    async fn splice_bidirectional() {
        // 双向独立 splice：a uplink + b uplink 各自触发
        let (mut a, mut b) = make_pair();
        let sh = build_tls13_server_hello_record();
        let app = build_tls_app_data(b"data");
        // a → b: sh + app（触发 a uplink splice）
        a.write_all(&sh).await.unwrap();
        a.write_all(&app).await.unwrap();
        a.flush().await.unwrap();
        // b → a: sh + app（触发 b uplink splice）
        b.write_all(&sh).await.unwrap();
        b.write_all(&app).await.unwrap();
        b.flush().await.unwrap();
        // 并发读验证双向
        let total = sh.len() + app.len();
        let mut buf_a = vec![0u8; total];
        let mut buf_b = vec![0u8; total];
        tokio::join!(
            async {
                a.read_exact(&mut buf_a).await.unwrap();
            },
            async {
                b.read_exact(&mut buf_b).await.unwrap();
            }
        );
        let mut expected = sh.clone();
        expected.extend_from_slice(&app);
        assert_eq!(buf_a, expected);
        assert_eq!(buf_b, expected);
    }
    /// 跨缓冲窗口流式压力：512KB 经 64KB duplex 窗口（读侧=server 角色）。
    /// 内置 timeout 防挂死整个套件；超时打印两侧进度。
    #[tokio::test]
    async fn server_mode_uplink_stream_stress() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let (mut a, mut b) = make_pair();
        const TOTAL: usize = 512 * 1024;
        let payload: Vec<u8> = (0u8..=255).cycle().take(TOTAL).collect();
        let payload_clone = payload.clone();
        let wrote = Arc::new(AtomicUsize::new(0));
        let read = Arc::new(AtomicUsize::new(0));
        let (w, r) = (wrote.clone(), read.clone());
        let work = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            tokio::join!(
                async move {
                    let mut off = 0;
                    while off < payload.len() {
                        let n = a.write(&payload[off..]).await.unwrap();
                        off += n;
                        w.store(off, Ordering::Relaxed);
                    }
                    a.flush().await.unwrap();
                },
                async move {
                    let mut got = vec![0u8; TOTAL];
                    let mut off = 0;
                    while off < TOTAL {
                        let n = b.read(&mut got[off..]).await.unwrap();
                        if n == 0 {
                            panic!("EOF at {off}");
                        }
                        off += n;
                        r.store(off, Ordering::Relaxed);
                    }
                    assert_eq!(got, payload_clone);
                }
            )
        })
        .await;
        if work.is_err() {
            panic!(
                "stress timeout: wrote={} read={}",
                wrote.load(Ordering::Relaxed),
                read.load(Ordering::Relaxed)
            );
        }
    }

    /// server 下行 splice：enable_xtls + 完整 app-data record → 发 DIRECT 帧 +
    /// 自身写切裸 TCP。对端经安全层收到 DIRECT 帧 content，随后在裸 socket
    /// 上直收后续明文。
    #[tokio::test]
    async fn server_splice_downlink_direct_and_raw_write() {
        let ((c, _c2), (s, s2)) = make_tcp_pair().await;
        let uuid = vec![0xABu8; 16];
        let key = b"united-key".to_vec();
        let mut server = VisionConn::new_server(
            CommonConn::new(
                s,
                Aead::new(b"ctx", &key, true),
                Aead::new(b"ctx", &key, true),
                true,
                key.clone(),
            ),
            uuid,
            s2,
        );
        // 白盒置位（39824 修 C：服务端写侧判定读写方向实例——生产由
        // 下行 ServerHello 流经 poll_write 被 uplink_traffic 的 filter 置位）
        server.uplink_traffic.enable_xtls = true;
        server.uplink_traffic.is_tls = true;
        server.uplink_traffic.is_tls12_or_above = true;
        let app = build_tls_app_data(b"GET / HTTP/1.1\r\n\r\n");
        server.write_all(&app).await.unwrap();
        server.flush().await.unwrap();
        let mut peer = CommonConn::new(
            c,
            Aead::new(b"ctx", &key, true),
            Aead::new(b"ctx", &key, true),
            true,
            key.clone(),
        );

        let frame_len = 16 + 5 + app.len();
        let mut frame = vec![0u8; frame_len];
        peer.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame[..16], &vec![0xABu8; 16][..], "首帧带 uuid 前缀");
        assert_eq!(frame[16], COMMAND_PADDING_DIRECT);
        let clen = u16::from_be_bytes([frame[17], frame[18]]) as usize;
        assert_eq!(clen, app.len());
        assert_eq!(&frame[21..], &app);
        // splice 后 server 直写裸 TCP：对端裸 socket 直收（无 AEAD 包装）
        server.write_all(b"raw-after-splice").await.unwrap();
        server.flush().await.unwrap();
        let mut raw = [0u8; 16];
        peer.inner_conn_mut().read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, b"raw-after-splice");
    }

    /// server 读侧 splice：收 client DIRECT 帧 → 自身读切裸 TCP。
    #[allow(dead_code)] // 存量清零批次
    async fn server_splice_read_switch_on_client_direct() {
        let ((c, mut c2), (s, s2)) = make_tcp_pair().await;
        let uuid = vec![0xABu8; 16];
        let key = b"united-key".to_vec();
        let mut server = VisionConn::new_server(
            CommonConn::new(
                s,
                Aead::new(b"ctx", &key, true),
                Aead::new(b"ctx", &key, true),
                true,
                key.clone(),
            ),
            uuid.clone(),
            s2,
        );
        // client 发 DIRECT padding 帧（content=app record），经安全层
        let app = build_tls_app_data(b"hello-direct");
        let padded = xtls_padding(
            Some(&app),
            COMMAND_PADDING_DIRECT,
            &mut Some(uuid.clone()),
            false,
            &DEFAULT_PADDING_SEED,
            &mut StdRng::from_os_rng(),
        );
        let mut client = CommonConn::new(
            c,
            Aead::new(b"ctx", &key, true),
            Aead::new(b"ctx", &key, true),
            true,
            key.clone(),
        );
        client.write_all(&padded).await.unwrap();
        client.flush().await.unwrap();

        // server 读：unpadding 提取 content + 切 raw
        let mut got = vec![0u8; app.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, app);

        // client 此后在裸 socket 上发明文：server 直收
        c2.write_all(b"raw-upstream").await.unwrap();
        c2.flush().await.unwrap();
        let mut raw = [0u8; 12];
        server.read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, b"raw-upstream");
    }
    /// [reg L1/L2] 泵压中途 DIRECT（bd VISIONMAC 回归）：8KB 块 = [rec 8098][rec 84]，
    /// 尾写 = 完整小 0x17 record → DIRECT 在尾帧触发；BufSim 提供 BufWriter 语义 +
    /// drip 背压 flush（gate Pending 路径）。客户端 sim 字节流式解帧，cmd>2 = 断裂。
    #[tokio::test]
    async fn reg_midpump_direct_frame_chain() {
        use std::time::Duration;

        fn rec(payload: &[u8]) -> Vec<u8> {
            let mut v = vec![0x17, 0x03, 0x03, (payload.len() >> 8) as u8, payload.len() as u8];
            v.extend_from_slice(payload);
            v
        }

        /// tokio-rustls BufWriter 语义模拟：poll_write 只缓冲（Ok），flush 每轮
        /// 至多吐一条 record + 1ms drip 背压——逼出 poll_arm_gate 的 Pending 路径。
        struct BufSim {
            inner: CommonConn<tokio::net::TcpStream>,
            pending: Vec<Vec<u8>>,
            drip: Pin<Box<tokio::time::Sleep>>,
        }
        impl AsyncRead for BufSim {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
            }
        }
        impl AsyncWrite for BufSim {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                let this = self.get_mut();
                this.pending.push(buf.to_vec());
                Poll::Ready(Ok(buf.len()))
            }

            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                let this = self.get_mut();
                loop {
                    if this.pending.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    let rec = this.pending.remove(0);
                    match Pin::new(&mut this.inner).poll_write(cx, &rec) {
                        Poll::Ready(Ok(n)) if n == rec.len() => {},
                        Poll::Ready(Ok(_)) => {
                            return Poll::Ready(Err(io::Error::other("bufsim short write")));
                        },
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => {
                            this.pending.insert(0, rec);
                            return Poll::Pending;
                        },
                    }
                    this.drip
                        .as_mut()
                        .reset(tokio::time::Instant::now() + std::time::Duration::from_millis(1));
                    if this.drip.as_mut().poll(cx).is_pending() {
                        return Poll::Pending;
                    }
                }
            }

            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
            }
        }
        impl InnerRawClone for BufSim {
            fn inner_raw_tcp_clone(&self) -> Option<TcpStream> {
                self.inner.inner_raw_tcp_clone()
            }
        }

        let ((c, mut c2), (s, s2)) = make_tcp_pair().await;
        let uuid = vec![0xABu8; 16];
        let key = b"united-key".to_vec();
        let mut server = VisionConn::new_server(
            BufSim {
                inner: CommonConn::new(
                    s,
                    Aead::new(b"ctx", &key, true),
                    Aead::new(b"ctx", &key, true),
                    true,
                    key.clone(),
                ),
                pending: Vec::new(),
                drip: Box::pin(tokio::time::sleep(std::time::Duration::from_millis(1))),
            },
            uuid.clone(),
            s2,
        );
        server.uplink_traffic.enable_xtls = true;
        server.uplink_traffic.is_tls = true;
        server.uplink_traffic.is_tls12_or_above = true;

        let mut chunk = rec(&vec![0xA0u8; 8103]);
        chunk.extend_from_slice(&rec(&[0xB7u8; 79]));
        assert_eq!(chunk.len(), 8192);
        let pump = tokio::spawn(async move {
            for _ in 0..6u8 {
                server.write_all(&chunk).await.expect("pump write");
                server.flush().await.expect("pump flush");
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let mut client = CommonConn::new(
            c,
            Aead::new(b"ctx", &key, true),
            Aead::new(b"ctx", &key, true),
            true,
            key.clone(),
        );
        let mut pending: Vec<u8> = Vec::new();
        let mut phase = 0u8; // 0=uuid,1=hdr,2=content,3=pad
        let mut hdr_pos = 0u8;
        let mut cmd = 0i32;
        let mut content_left = 0i32;
        let mut pad_left = 0i32;
        let mut saw_direct = false;
        let mut frames = 0usize;
        let mut buf = [0u8; 16384];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "deadline; frames={frames} saw_direct={saw_direct} pending={}",
                    pending.len()
                );
            }
            if saw_direct {
                let n = tokio::time::timeout(Duration::from_secs(10), c2.read(&mut buf))
                    .await
                    .expect("raw read deadline")
                    .expect("raw read io");
                assert!(n > 0, "raw stream must flow after DIRECT");
                assert_eq!(buf[0], 0x17, "raw stream must start with the next chunk record header");
                pump.abort();
                return;
            }
            let n = tokio::time::timeout(Duration::from_secs(10), client.read(&mut buf))
                .await
                .expect("frame read deadline")
                .expect("frame read io");
            if n == 0 {
                panic!(
                    "EOF before DIRECT; frames={frames} pending={:?}",
                    &pending[..pending.len().min(24)]
                );
            }
            pending.extend_from_slice(&buf[..n]);
            let mut pos = 0usize;
            loop {
                if phase == 0 {
                    if pending.len() - pos < 21 {
                        break;
                    }
                    assert_eq!(&pending[pos..pos + 16], &uuid[..], "UUID mismatch");
                    pos += 16;
                    phase = 1;
                    hdr_pos = 0;
                }
                while phase == 1 {
                    if pos >= pending.len() {
                        break;
                    }
                    let b = pending[pos] as i32;
                    pos += 1;
                    match hdr_pos {
                        0 => cmd = b,
                        1 => content_left = b << 8,
                        2 => content_left |= b,
                        3 => pad_left = b << 8,
                        _ => pad_left |= b,
                    }
                    hdr_pos += 1;
                    if hdr_pos == 5 {
                        frames += 1;
                        if cmd > 2 || content_left > 2047 || pad_left > 1943 {
                            panic!(
                                "FRAME ANOMALY at frame #{frames}: cmd={cmd} content={content_left} pad={pad_left}"
                            );
                        }
                        if cmd == 2 {
                            saw_direct = true;
                        }
                        phase = if content_left > 0 {
                            2
                        } else if pad_left > 0 {
                            3
                        } else {
                            1
                        };
                        hdr_pos = 0;
                    }
                }
                if phase == 2 {
                    let take = (content_left as usize).min(pending.len() - pos);
                    pos += take;
                    content_left -= take as i32;
                    if content_left == 0 {
                        phase = if pad_left > 0 { 3 } else { 1 };
                        hdr_pos = 0;
                    }
                }
                if phase == 3 {
                    let take = (pad_left as usize).min(pending.len() - pos);
                    pos += take;
                    pad_left -= take as i32;
                    if pad_left == 0 {
                        phase = 1;
                        hdr_pos = 0;
                    }
                }
                if pos >= pending.len() && phase != 0 {
                    break;
                }
                if phase == 0 && pending.len() - pos < 21 {
                    break;
                }
            }
            pending.drain(..pos);
        }
    }

    /// [reg End-commit] commit-record 契约（bd VISIONMAC :39057 间歇死亡回归）：
    /// End 帧判定后、inner flush 确认上线前——① `uplink_padding` 必须保持 true、
    /// ② 重入 poll_write 不得产生任何未成帧字节（帧只入队一次）、③ flush 解除后
    /// commit 翻转，后续写入走 inner 直写且严格排在 End 帧之后。
    #[tokio::test]
    async fn reg_end_commit_pending_flush_reentry() {
        use std::task::{Context, Poll, Waker};

        /// 内层模拟：镜像 tokio-rustls 语义——poll_write 消费即封帧入 send
        /// 缓冲；socket 阻塞期间（blocked）重入 poll_write 一律 Pending 且
        /// 不重复消费；flush 在 unblock 前 Pending，unblock 后把 send 缓冲
        /// 全量上线。
        struct GateMock {
            sealed: Vec<u8>,
            wire: Vec<u8>,
            blocked: bool,
            unblock: bool,
        }
        impl AsyncRead for GateMock {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }
        impl AsyncWrite for GateMock {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                let this = self.get_mut();
                if this.blocked {
                    return Poll::Pending;
                }
                this.sealed.extend_from_slice(buf);
                this.blocked = true; // 首推即撞背压（真实栈：write_io WouldBlock）
                Poll::Ready(Ok(buf.len()))
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                let this = self.get_mut();
                if this.unblock {
                    this.wire.extend_from_slice(&this.sealed);
                    this.sealed.clear();
                    this.blocked = false;
                    Poll::Ready(Ok(()))
                } else {
                    this.blocked = true;
                    Poll::Pending
                }
            }

            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.poll_flush(cx)
            }
        }
        impl InnerRawClone for GateMock {
            fn inner_raw_tcp_clone(&self) -> Option<TcpStream> {
                None
            }
        }

        let (_raw_peer, raw_own) = make_std_tcp_pair();
        let uuid = vec![0xABu8; 16];
        let mut server = VisionConn::new_server(
            GateMock { sealed: Vec::new(), wire: Vec::new(), blocked: false, unblock: false },
            uuid.clone(),
            raw_own,
        );
        // 白盒：非 TLS12+ 流量 + 过滤窗口将尽 → 首写即 is_early_end（Go proxy.go:382-386）
        server.uplink_traffic.number_of_packet_to_filter = 1;
        server.uplink_traffic.is_tls12_or_above = false;
        server.uplink_traffic.is_tls = true;

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        let block1 = vec![0x11u8; 1000];
        let block2 = vec![0x22u8; 700];

        // 写 #1：End 判定 → End 帧入 mock send 缓冲 → flush Pending → 写 Pending
        //（Pending = 背压窗口开启：commit 闸持有中）
        match Pin::new(&mut server).poll_write(&mut cx, &block1) {
            Poll::Pending => {},
            other => panic!("write#1 unexpected: {other:?}"),
        }
        assert!(server.end_commit, "End 帧在途，commit 闸必须持有");
        assert!(server.uplink_padding, "commit 前 padding 必须未翻转");
        assert!(server.raw_fallback.is_none());
        // End 帧已在 send 缓冲（未上线）：cmd=End，content=block1，长 pad ∈ [0,255]
        let sealed_len = server.inner.sealed.len();
        // 首帧携带 UUID 前缀（16B）+ 5B 帧头
        assert_eq!(&server.inner.sealed[..16], &uuid[..], "UUID 前缀");
        assert_eq!(server.inner.sealed[16], COMMAND_PADDING_END);
        // 帧几何契约：unpadding 必须精确还原 block1（pad 随机值无关；内容
        // 截断/长度场损坏在此暴露）
        {
            let mut st = crate::encryption::vision::DirectionState::default();
            let content =
                crate::encryption::vision::xtls_unpadding(&server.inner.sealed, &mut st, &uuid);
            assert_eq!(
                content,
                block1,
                "End 帧 content 必须精确还原 block1: got={}B cmd={}",
                content.len(),
                st.current_command
            );
            assert_eq!(st.current_command, COMMAND_PADDING_END as i32);
        }
        assert!(server.inner.wire.is_empty(), "flush 未解除不得上线");

        // 写 #2（重入，同一 flush 窗口）：必须 Pending 且不产生任何新字节
        match Pin::new(&mut server).poll_write(&mut cx, &block2) {
            Poll::Pending => {},
            other => panic!("commit 前重入必须 Pending 且零逃逸: {other:?}"),
        }
        assert!(server.uplink_padding, "重入后 padding 仍须未翻转");
        assert_eq!(server.inner.sealed.len(), sealed_len, "重入不得追加任何字节");
        assert!(server.inner.wire.is_empty());

        // 解除背压：重入驱动 → flush Ready → commit → 写 #1 完成
        server.inner.unblock = true;
        let n = loop {
            match Pin::new(&mut server).poll_write(&mut cx, &block1) {
                Poll::Ready(Ok(done)) => break done,
                Poll::Pending => continue,
                other => panic!("write#1 retry unexpected: {other:?}"),
            }
        };
        assert_eq!(n, block1.len());
        assert!(!server.end_commit, "commit 后闸必须复位");
        assert!(!server.uplink_padding, "commit 后 padding 必须关闭");
        // End 帧已上线
        assert_eq!(server.inner.wire[16], COMMAND_PADDING_END);
        assert_eq!(server.inner.wire.len(), sealed_len); // End 帧 + pad 全量上线

        // commit 后写入走 inner 直写（无帧），严格排在 End 帧之后
        server.write_all(&block2).await.unwrap();
        server.flush().await.unwrap();
        assert_eq!(
            &server.inner.wire[sealed_len..],
            &block2[..],
            "unframed bytes must follow End frame"
        );

        // 线上帧链可被 Go 语义解帧验证：End 帧 content == block1
        let mut st = crate::encryption::vision::DirectionState::default();
        let content = crate::encryption::vision::xtls_unpadding(
            &server.inner.wire[..sealed_len],
            &mut st,
            &uuid,
        );
        assert_eq!(content, block1);
        assert_eq!(st.current_command, COMMAND_PADDING_END as i32);
    }

    /// [reg L3/L4] DIRECT 提交窗口过读吞流（bd VISIONMAC 终局）：背压暂停跨过
    /// RAW_WRITE_ARM_DELAY 窗口时，对端 raw 字节与 DIRECT 帧同段落入 rustls 一次
    /// recv —— 无记录钳制时 raw 前缀被 deframer 当半条隧道记录扣留，切 raw 后
    /// 永久不可达（下游字节流断 2921B → 永久停滞）。修复形态 = 读侧记录对齐
    /// （RecordFramer 垫在 rustls 之下，等价 Go readFromUntil 精确读形态）。
    /// 客户端 csock 的 framer 包装镜像生产 dial_tcp 的 security=tls 钳制。
    #[tokio::test]
    async fn reg_direct_switch_coalesce_swallow_backpressure() {
        use std::sync::Arc;

        use rustls::{
            DigitallySignedStruct, SignatureScheme,
            client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
            pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
        };
        use tokio_rustls::TlsConnector;
        use xray_transport::{
            TlsAcceptor,
            connection::dup_tcp_stream,
            rustls::{ClientConfig, ServerConfig},
        };

        fn rec(payload: &[u8]) -> Vec<u8> {
            let mut v = vec![0x17, 0x03, 0x03, (payload.len() >> 8) as u8, payload.len() as u8];
            v.extend_from_slice(payload);
            v
        }

        fn make_chunk(tag: u8) -> Vec<u8> {
            let mut p1 = vec![0xA0u8; 8103];
            p1[0] = tag;
            let mut chunk = rec(&p1);
            let mut p2 = vec![0xB7u8; 79];
            p2[0] = tag.wrapping_add(1);
            chunk.extend_from_slice(&rec(&p2));
            assert_eq!(chunk.len(), 8192);
            chunk
        }

        #[derive(Debug)]
        struct NoVerify;
        impl ServerCertVerifier for NoVerify {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![SignatureScheme::RSA_PKCS1_SHA256, SignatureScheme::ECDSA_NISTP256_SHA256]
            }
        }

        let _ = rustls::crypto::ring::default_provider().install_default();

        let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();
        let key = PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(cert_der.clone())], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let mut client_cfg = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let uuid = vec![0xABu8; 16];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let uuid_srv = uuid.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let raw = dup_tcp_stream(&stream).unwrap();
            let framer = xray_transport::record_framer::RecordFramer::new(stream);
            let tls = acceptor.accept_with(framer, |_| ()).await.expect("server tls accept");
            let (r, w) = tokio::io::split(tls);
            let mut vision = VisionConn::new_server(tokio::io::join(r, w), uuid_srv, raw);
            vision.uplink_traffic.enable_xtls = true;
            vision.uplink_traffic.is_tls = true;
            vision.uplink_traffic.is_tls12_or_above = true;
            let (mut _sr, mut sw) = tokio::io::split(vision);
            // chunk 0：padded 批，末帧 Direct → arm（50ms raw 起步闸在写侧）
            let chunk = make_chunk(0);
            sw.write_all(&chunk).await.expect("srv chunk0 write");
            sw.flush().await.expect("srv chunk0 flush");
            eprintln!("[tap3][srv] chunk0 (direct batch) written, gate 50ms");
            // t≈50ms：gate 到期，第一段 raw 只发 2921B（半条记录），随后静默
            // 300ms——客户端背压暂停跨过 arm 窗口，recv 必然把 DIRECT 帧 + 该
            // 前缀合流拉进 deframer。
            let chunk1 = make_chunk(1);
            sw.write_all(&chunk1[..2921]).await.expect("srv raw piece-a write");
            sw.flush().await.expect("srv raw piece-a flush");
            eprintln!("[tap3][srv] raw piece-a (2921B) written, pausing 300ms");
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            // t≈350ms：发剩余 raw 流（piece-b + chunks 2..5）
            sw.write_all(&chunk1[2921..]).await.expect("srv raw piece-b write");
            for i in 2..6u8 {
                let c = make_chunk(i);
                sw.write_all(&c).await.expect("srv raw tail write");
            }
            sw.flush().await.expect("srv raw tail flush");
            eprintln!("[tap3][srv] raw tail written, parking 30s");
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        });

        let csock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let craw = dup_tcp_stream(&csock).unwrap();
        // 镜像生产 dial_tcp（security=tls）：记录对齐钳制垫在 rustls 客户端之下。
        let framer = xray_transport::record_framer::RecordFramer::new(csock);
        let tls = connector
            .connect(ServerName::try_from("localhost".to_string()).unwrap(), framer)
            .await
            .expect("client tls connect");
        let (r, w) = tokio::io::split(tls);
        let mut cvision = VisionConn::new_server(tokio::io::join(r, w), uuid.clone(), craw);
        cvision.downlink_traffic.enable_xtls = true;
        cvision.downlink_traffic.is_tls = true;
        cvision.downlink_traffic.is_tls12_or_above = true;

        let (mut cr, _cw) = tokio::io::split(cvision);
        // 背压暂停 60ms > 50ms arm 闸：DIRECT 帧 + piece-a 同段 recv 的窗口。
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        let mut got: Vec<u8> = Vec::new();
        let mut buf = [0u8; 16384];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
        while got.len() < 6 * 8192 {
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "deadline: got={} (expected {}); swallow signature = {} bytes",
                    got.len(),
                    6 * 8192,
                    6 * 8192 - got.len()
                );
            }
            let read =
                tokio::time::timeout(std::time::Duration::from_secs(10), cr.read(&mut buf)).await;
            let n = match read {
                Ok(Ok(n)) if n > 0 => n,
                Ok(Ok(_)) => panic!("EOF at {}", got.len()),
                Ok(Err(e)) => panic!("cli read io at {}: {e}", got.len()),
                Err(_) => panic!("cli read deadline at {} bytes received", got.len()),
            };
            got.extend_from_slice(&buf[..n]);
            eprintln!("[tap3][cli] progress: {} bytes (+{n})", got.len());
        }
        let mut rebuilt: Vec<u8> = Vec::new();
        for i in 0..6u8 {
            rebuilt.extend_from_slice(&make_chunk(i));
        }
        assert_eq!(got.len(), rebuilt.len(), "downlink content length mismatch");
        assert_eq!(got, rebuilt, "downlink content stream corrupted");
        server.abort();
    }

    /// [reg L3/L4] 全栈实验室（bd VISIONMAC 回归）：真 rustls 双端 + RecordFramer +
    /// 双向并发 8KB record 形态泵 + 双向 DIRECT（对齐生产 :39057 拓扑）+ 读侧背压。
    /// 下行输出流做字节级连续性验证。
    #[tokio::test]
    async fn reg_fullstack_direct_backpressure() {
        use std::sync::Arc;

        use rustls::{
            DigitallySignedStruct, SignatureScheme,
            client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
            pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
        };
        use tokio_rustls::TlsConnector;
        use xray_transport::{
            TlsAcceptor,
            connection::dup_tcp_stream,
            rustls::{ClientConfig, ServerConfig},
        };

        fn rec(payload: &[u8]) -> Vec<u8> {
            let mut v = vec![0x17, 0x03, 0x03, (payload.len() >> 8) as u8, payload.len() as u8];
            v.extend_from_slice(payload);
            v
        }

        fn make_chunk(tag: u8) -> Vec<u8> {
            let mut p1 = vec![0xA0u8; 8103];
            p1[0] = tag;
            let mut chunk = rec(&p1);
            let mut p2 = vec![0xB7u8; 79];
            p2[0] = tag.wrapping_add(1);
            chunk.extend_from_slice(&rec(&p2));
            assert_eq!(chunk.len(), 8192);
            chunk
        }

        #[derive(Debug)]
        struct NoVerify;
        impl ServerCertVerifier for NoVerify {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![SignatureScheme::RSA_PKCS1_SHA256, SignatureScheme::ECDSA_NISTP256_SHA256]
            }
        }

        let _ = rustls::crypto::ring::default_provider().install_default();

        let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();
        let key = PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(cert_der.clone())], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let mut client_cfg = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let uuid = vec![0xABu8; 16];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let uuid_srv = uuid.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let raw = dup_tcp_stream(&stream).unwrap();
            let framer = xray_transport::record_framer::RecordFramer::new(stream);
            let tls = acceptor.accept_with(framer, |_| ()).await.expect("server tls accept");
            let (r, w) = tokio::io::split(tls);
            let mut vision = VisionConn::new_server(tokio::io::join(r, w), uuid_srv, raw);
            vision.uplink_traffic.enable_xtls = true;
            vision.uplink_traffic.is_tls = true;
            vision.uplink_traffic.is_tls12_or_above = true;
            let (mut sr, mut sw) = tokio::io::split(vision);
            // 上行汇：并发读 VisionConn 读半（含 DIRECT 后 raw 切换），防止客户端
            // 上行无汇导致的缓冲填满假死
            let sink = tokio::spawn(async move {
                let mut tmp = [0u8; 16384];
                let mut total = 0usize;
                let dl = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
                while tokio::time::Instant::now() < dl {
                    match tokio::time::timeout(std::time::Duration::from_secs(5), sr.read(&mut tmp))
                        .await
                    {
                        Ok(Ok(0)) => break,
                        Ok(Ok(n)) => total += n,
                        _ => break,
                    }
                }
                eprintln!("[tap2][srv] uplink sink total={total}");
            });
            for i in 0..6u8 {
                let chunk = make_chunk(i);
                sw.write_all(&chunk).await.expect("srv pump write");
                sw.flush().await.expect("srv pump flush");
                eprintln!("[tap2][srv] chunk {i} written");
            }
            eprintln!("[tap2][srv] pump done, parking 60s");
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let _ = sink.await;
        });

        let csock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let craw = dup_tcp_stream(&csock).unwrap();
        let tls = connector
            .connect(ServerName::try_from("localhost".to_string()).unwrap(), csock)
            .await
            .expect("client tls connect");
        let (r, w) = tokio::io::split(tls);
        let mut cvision = VisionConn::new_server(tokio::io::join(r, w), uuid.clone(), craw);
        cvision.downlink_traffic.enable_xtls = true;
        cvision.downlink_traffic.is_tls = true;
        cvision.downlink_traffic.is_tls12_or_above = true;

        let (mut cr, mut cw) = tokio::io::split(cvision);
        let upump = tokio::spawn(async move {
            for _ in 0..3u8 {
                let chunk = make_chunk(0x40);
                cw.write_all(&chunk).await.expect("cli uplink write");
                cw.flush().await.expect("cli uplink flush");
            }
        });

        let mut got: Vec<u8> = Vec::new();
        let mut buf = [0u8; 16384];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        while got.len() < 6 * 8192 {
            if tokio::time::Instant::now() >= deadline {
                panic!("deadline: got={}", got.len());
            }
            // 读侧 3ms 停顿：逼服务端 rustls write_io 撞 WouldBlock（背压路径）
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            let read =
                tokio::time::timeout(std::time::Duration::from_secs(30), cr.read(&mut buf)).await;
            let n = match read {
                Ok(Ok(n)) if n > 0 => n,
                Ok(Ok(_)) => panic!("EOF at {}", got.len()),
                Ok(Err(e)) => panic!("cli read io at {}: {e}", got.len()),
                Err(_) => panic!("cli read deadline at {} bytes received", got.len()),
            };
            got.extend_from_slice(&buf[..n]);
            if got.len() % 65536 < n {
                eprintln!("[tap2][cli] downlink progress: {} bytes", got.len());
            }
        }
        let mut rebuilt: Vec<u8> = Vec::new();
        for i in 0..6u8 {
            rebuilt.extend_from_slice(&make_chunk(i));
        }
        assert_eq!(got.len(), rebuilt.len(), "downlink content length mismatch");
        assert_eq!(got, rebuilt, "downlink content stream corrupted");
        upump.await.ok();
        server.abort();
    }

    /// [VISIONMAC 截断] End 模式（内层明文，无 DIRECT）+ 客户端线缆切碎器：
    /// 服务端早发 End 后整流为裸 payload TLS records；切碎器把服务端→客户端
    /// 密文按随机小片（200-3000B）+ 微停顿重发，强制「单条 TLS 记录跨多个
    /// TCP 段」。镜像 VPS :39058 netem 截断签名：服务端全量写出、内核全量
    /// 送达、客户端 userspace 读路径停止消费。字节级连续性验证。
    #[tokio::test]
    async fn tmp_end_mode_segmented_stall_repro() {
        use std::sync::Arc;

        use rand::{Rng, SeedableRng};
        use rustls::{
            DigitallySignedStruct, SignatureScheme,
            client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
            pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
        };
        use tokio_rustls::TlsConnector;
        use xray_transport::{
            TlsAcceptor,
            connection::dup_tcp_stream,
            rustls::{ClientConfig, ServerConfig},
        };

        const CHUNKS: usize = 640;
        const CHUNK: usize = 8192;
        const TOTAL: usize = CHUNKS * CHUNK;

        #[derive(Debug)]
        struct NoVerify;
        impl ServerCertVerifier for NoVerify {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![SignatureScheme::RSA_PKCS1_SHA256, SignatureScheme::ECDSA_NISTP256_SHA256]
            }
        }

        let _ = rustls::crypto::ring::default_provider().install_default();

        let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let key = PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(cert_der.clone())], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let mut client_cfg = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let uuid = vec![0xABu8; 16];
        let front = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        let back = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let back_addr = back.local_addr().unwrap();

        // 真 TLS 服务端：End 模式（plain content，写侧早 End 后裸 payload 直出）。
        let uuid_srv = uuid.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = back.accept().await.unwrap();
            let raw = dup_tcp_stream(&stream).unwrap();
            let framer = xray_transport::record_framer::RecordFramer::new(stream);
            let tls = acceptor.accept_with(framer, |_| ()).await.expect("server tls accept");
            let (r, w) = tokio::io::split(tls);
            let mut vision = VisionConn::new_server(tokio::io::join(r, w), uuid_srv, raw);
            // 白盒：plain content（非 TLS12+）+ 过滤窗将尽 → 首批即 End（Go proxy.go:382-386）。
            vision.uplink_traffic.is_tls = false;
            vision.uplink_traffic.is_tls12_or_above = false;
            vision.uplink_traffic.number_of_packet_to_filter = 1;
            let (_sr, mut sw) = tokio::io::split(vision);
            for i in 0..CHUNKS {
                let mut chunk = vec![0u8; CHUNK];
                chunk[0] = (i & 0xff) as u8;
                chunk[1..9].copy_from_slice(&(i as u64).to_be_bytes());
                sw.write_all(&chunk).await.expect("srv pump write");
                sw.flush().await.expect("srv pump flush");
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            eprintln!("[chop][srv] pump done ({TOTAL}B), parking 30s");
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        });

        // 切碎器：front←accept / back←connect 裸字节搬运。上行直通；下行随机小片 + 微停顿。
        let front_conn = tokio::spawn(async move {
            let (sock_front, _) = front.accept().await.unwrap();
            let sock_back = tokio::net::TcpStream::connect(back_addr).await.unwrap();
            let (mut fr, mut fw) = tokio::io::split(sock_front);
            let (mut br, mut bw) = tokio::io::split(sock_back);
            // 上行直通
            tokio::spawn(async move {
                let _ = tokio::io::copy(&mut fr, &mut bw).await;
            });
            // 下行切碎
            let mut rng = StdRng::seed_from_u64(0xC0FFEE);
            let mut buf = vec![0u8; 65536];
            loop {
                let n = match br.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let mut off = 0;
                while off < n {
                    let piece = rng.random_range(200..=3000).min(n - off);
                    if fw.write_all(&buf[off..off + piece]).await.is_err() {
                        return;
                    }
                    let _ = fw.flush().await;
                    tokio::time::sleep(std::time::Duration::from_micros(
                        rng.random_range(80..=400),
                    ))
                    .await;
                    off += piece;
                }
            }
        });

        let csock = tokio::net::TcpStream::connect(front_addr).await.unwrap();
        // 等 TLS 服务端就绪：chopper 已把 front↔back 桥好，直连 back_addr 的
        // 握手会绕过切碎器——此处必须连 front，让握手字节也走切碎器。
        let _ = back_addr;
        let craw = dup_tcp_stream(&csock).unwrap();
        let framer = xray_transport::record_framer::RecordFramer::new(csock);
        let tls = connector
            .connect(ServerName::try_from("localhost".to_string()).unwrap(), framer)
            .await
            .expect("client tls connect");
        let (r, w) = tokio::io::split(tls);
        let mut cvision = VisionConn::new_server(tokio::io::join(r, w), uuid.clone(), craw);
        cvision.downlink_traffic.is_tls = false;
        cvision.downlink_traffic.is_tls12_or_above = false;

        // 生产形态客户端读路径：curl 侧 duplex + 真 bridge（mpsc 64 + 超时窗 +
        // BiLock split）——手工读循环换下，复刻 VPS 停摆的调用形态。
        let (mut fake_client, curl_io) = tokio::io::duplex(64 * 1024);
        let (curl_rd, curl_wr) = tokio::io::split(curl_io);
        let link = xray_transport::link::Link::new(
            xray_buf::io::new_reader(curl_rd),
            xray_buf::io::new_writer(curl_wr),
        );
        // Join<ReadHalf,WriteHalf> 不实现 Connection（VisionConn<C: Connection>
        // 约束）——测试侧薄 shim 透传 AsyncRead/Write，语义与生产 Box<dyn> 路径一致。
        struct ConnShim<V>(V);
        impl<V: AsyncRead + Unpin> AsyncRead for ConnShim<V> {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.0).poll_read(cx, buf)
            }
        }
        impl<V: AsyncWrite + Unpin> AsyncWrite for ConnShim<V> {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.0).poll_write(cx, buf)
            }
            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.0).poll_flush(cx)
            }
            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.0).poll_shutdown(cx)
            }
        }
        use std::net::SocketAddr;
        impl<V: AsyncRead + AsyncWrite + Send + Sync + Unpin> xray_transport::connection::Connection
            for ConnShim<V>
        {
            fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }
            fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }
        }
        impl<V> crate::encryption::vision_conn::InnerRawClone for ConnShim<V> {}
        let cvision_box: Box<dyn xray_transport::connection::Connection> =
            Box::new(ConnShim(cvision));
        // 桥任务独立运行，测试以读侧进度判定，JoinHandle 即弃（detached）。
        tokio::spawn(async move {
            let policy = xray_features::policy::TimeoutPolicy::default();
            xray_transport::bridge::bridge_link_with_stream_full(link, cvision_box, &policy).await
        });

        let mut got: Vec<u8> = Vec::with_capacity(TOTAL);
        let mut buf = [0u8; 16384];
        let mut reads = 0usize;
        let macro_every: usize = std::env::var("XRAY_STALL_MACRO_EVERY")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(40);
        let macro_ms: u64 = std::env::var("XRAY_STALL_MACRO_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(150);
        let macro_seed: u64 = std::env::var("XRAY_STALL_SEED")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let macro_seed = if macro_seed == 0 {
            let s = (std::process::id() as u64) << 32
                | std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos() as u64)
                    .unwrap_or(0);
            eprintln!("[chop][cli] macro seed (time-derived) = {s}");
            s
        } else {
            macro_seed
        };
        let mut macro_rng = StdRng::seed_from_u64(macro_seed);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(90);
        while got.len() < TOTAL {
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "[chop][cli] STALL: got={}/{} (missing {}), eof_signature=none",
                    got.len(),
                    TOTAL,
                    TOTAL - got.len()
                );
            }
            reads += 1;
            // 宏背压：周期性停读——对齐 VPS netem RTT 窗口效应
            //（接收窗关闭 → 服务端 write_io 撞 WouldBlock → 单条记录被
            // 分段写出 → 客户端线缆出现跨段半记录）。
            // 88m0 复现加压旋钮（缺省=原 40/150 行为）：XRAY_STALL_MACRO_EVERY
            // 控制停读周期，XRAY_STALL_MACRO_MS 控制停读基准时长（±50% 抖动），
            // XRAY_STALL_SEED 固定抖动种子（0=时间+pid 每轮独立抽样，启动时打印）。
            if reads % macro_every == 0 {
                let ms = macro_rng.random_range(macro_ms / 2..=macro_ms + macro_ms / 2);
                tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
            }
            let read = tokio::time::timeout(
                std::time::Duration::from_secs(15),
                fake_client.read(&mut buf),
            )
            .await;
            let n = match read {
                Ok(Ok(n)) if n > 0 => n,
                Ok(Ok(_)) => panic!("[chop][cli] premature EOF at {}/{}", got.len(), TOTAL),
                Ok(Err(e)) => panic!("[chop][cli] io error at {}: {e}", got.len()),
                Err(_) => panic!("[chop][cli] single-read 15s deadline at {}/{}", got.len(), TOTAL),
            };
            got.extend_from_slice(&buf[..n]);
        }
        eprintln!("[chop][cli] full {TOTAL}B received");
        // 字节级连续性
        for i in 0..CHUNKS {
            let off = i * CHUNK;
            assert_eq!(got[off], (i & 0xff) as u8, "chunk {i} tag mismatch");
            assert_eq!(&got[off + 1..off + 9], &(i as u64).to_be_bytes(), "chunk {i} seq");
        }
        front_conn.abort();
        server.abort();
    }

    /// 造 std 回环 socket 对并转 tokio（#[test] 无 runtime 场景用）。
    fn make_std_tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let c = std::net::TcpStream::connect(addr).unwrap();
        let (s, _) = listener.accept().unwrap();
        let mut pair = [(c, true), (s, false)];
        for (stream, _) in pair.iter_mut() {
            stream.set_nonblocking(true).unwrap();
        }
        let [c, s] = pair;
        (
            tokio::net::TcpStream::from_std(c.0).unwrap(),
            tokio::net::TcpStream::from_std(s.0).unwrap(),
        )
    }

    /// 6odi（Go f926ee4a / issue #4878）：DIRECT 帧仍 in-flight 时，写侧
    /// splice 通道不得激活——poll_shutdown 探针必须走 inner，raw 腿零触碰。
    /// 激活只允许发生在 pending 帧完整写入之后。
    #[tokio::test]
    async fn splice_activation_deferred_until_write_completes() {
        let (raw_peer, raw_own) = make_std_tcp_pair();
        let (inner, _inner_peer) = tokio::io::duplex(1);
        let key = b"united-key".to_vec();
        let mut server = VisionConn::new_server(
            CommonConn::new(
                inner,
                Aead::new(b"ctx", &key, true),
                Aead::new(b"ctx", &key, true),
                true,
                key.clone(),
            ),
            vec![0xABu8; 16],
            raw_own,
        );
        // 白盒置位（39824 修 C：服务端写侧判定读 uplink_traffic——生产由
        // 下行 ServerHello 流经 poll_write 被 filter 置位）
        server.uplink_traffic.enable_xtls = true;
        server.uplink_traffic.is_tls = true;
        server.uplink_traffic.is_tls12_or_above = true;
        let app = build_tls_app_data(b"GET / HTTP/1.1\r\n\r\n");

        let mut cx = Context::from_waker(std::task::Waker::noop());
        // 首次 poll_write：判 DIRECT → 置 armed → pending 帧写 inner 撞 1 字节
        // duplex 背压 → Pending 返回。此刻帧 in-flight。
        let poll = Pin::new(&mut server).poll_write(&mut cx, &app);
        assert!(matches!(poll, Poll::Pending), "expected in-flight Pending, got {poll:?}");
        // 判定已完成但写未完成：raw 通道必须仍未激活（f926ee4a 契约本体）
        assert!(server.splice_armed, "DIRECT judged but not armed");
        assert!(server.raw_fallback.is_none(), "raw must stay unactivated while write in-flight");
        // 探针：in-flight 期间 half-close 必须走 inner；激活提前则此处会
        // shutdown raw → 对端读到 EOF → 红票
        let poll = Pin::new(&mut server).poll_shutdown(&mut cx);
        assert!(matches!(poll, Poll::Ready(Ok(()))), "shutdown via inner should be ready");
        let mut probe = [0u8; 1];
        match raw_peer.try_read(&mut probe) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {},
            Ok(0) => panic!("raw peer saw EOF: shutdown leaked to raw while write in-flight"),
            other => panic!("raw peer unexpectedly readable while write in-flight: {other:?}"),
        }
    }

    /// 6odi 写序契约：DIRECT 帧完整写完的那一刻 raw 通道才激活，其后写全走
    /// raw 直传明文（判定期零激活 → 写完激活 → raw 明文可收）。
    #[tokio::test]
    async fn splice_raw_write_only_after_direct_completes() {
        #[allow(unused_mut)] // 存量清零批次
        let ((mut c, _c2), (s, s2)) = make_tcp_pair().await;
        let key = b"united-key".to_vec();
        let mut server = VisionConn::new_server(
            CommonConn::new(
                s,
                Aead::new(b"ctx", &key, true),
                Aead::new(b"ctx", &key, true),
                true,
                key.clone(),
            ),
            vec![0xABu8; 16],
            s2,
        );
        server.uplink_traffic.enable_xtls = true;
        server.uplink_traffic.is_tls = true;
        server.uplink_traffic.is_tls12_or_above = true;
        assert!(server.raw_fallback.is_none(), "pre-judgement must not activate raw");
        let app = build_tls_app_data(b"GET / HTTP/1.1\r\n\r\n");
        server.write_all(&app).await.unwrap();
        server.flush().await.unwrap();
        // 写完成点激活（armed 已消费）
        assert!(!server.splice_armed, "armed flag consumed at write completion");
        assert!(server.raw_fallback.is_some(), "raw activated right after write completes");
        // 其后写全走 raw：对端先用 CommonConn 解密收 DIRECT 帧（dup 克隆
        // 共对端，帧经 inner TLS 层），再切裸 socket 直收 raw 明文
        let mut peer = CommonConn::new(
            c,
            Aead::new(b"ctx", &key, true),
            Aead::new(b"ctx", &key, true),
            true,
            key.clone(),
        );
        let mut frame = vec![0u8; 16 + 5 + app.len()];
        peer.read_exact(&mut frame).await.unwrap();
        assert_eq!(frame[16], COMMAND_PADDING_DIRECT, "frame went through inner");
        server.write_all(b"raw-after-splice").await.unwrap();
        server.flush().await.unwrap();
        let mut raw = [0u8; 16];
        peer.inner_conn_mut().read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, b"raw-after-splice");
    }

    /// SslStream 语义替身：模拟外层 TLS 流的「过读 + opaque 缓冲」——单次
    /// 底层 recv 把「DIRECT 记录 + 其后裸字节」一起吞进内部缓冲，但只吐出
    /// 第一段（DIRECT 记录明文）。真实 SslStream/rustls 现状：裸尾滞留
    /// opaque 缓冲永不浮现，DIRECT 切换后不可再从 inner 回收。`reads` 记
    /// 录 poll_read 调用次数，用于断言「DIRECT 帧交付后封读 inner」契约。
    struct SslSwallowMock {
        first: Vec<u8>,
        swallowed: Vec<u8>,
        delivered: bool,
        reads: usize,
    }
    impl AsyncRead for SslSwallowMock {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            this.reads += 1;
            if !this.delivered {
                this.delivered = true;
                let n = this.first.len().min(buf.remaining());
                buf.put_slice(&this.first[..n]);
                return Poll::Ready(Ok(()));
            }
            if !this.swallowed.is_empty() {
                let n = this.swallowed.len().min(buf.remaining());
                buf.put_slice(&this.swallowed[..n]);
                this.swallowed.clear();
                return Poll::Ready(Ok(()));
            }
            Poll::Pending
        }
    }
    impl AsyncWrite for SslSwallowMock {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl InnerRawClone for SslSwallowMock {}

    /// txno-splice 终版读侧契约（macOS Interop #08 r2 定罪链，取代
    /// dbe9f49 的 drain 契约）：DIRECT 帧交付后 VisionConn **不得再读
    /// inner**。对端 writer 在 DIRECT 帧后已切裸流，inner（TLS 层）此后的
    /// 每次 recv 都会把端到端明文拉进 deframer：完整记录被 DecryptError
    /// 吞掉（dbe9f49 drain 的 Err 分支恰在制造这种静默丢失），半条记录
    /// 滞留 opaque 缓冲切 raw dup 后永久不可达。两种都是字节流断裂。
    /// 契约本体 = 读计数实锤：DIRECT 帧消费后 inner poll_read 次数停在
    /// 消费该帧的那一次，后续数据必须全部经 raw 通道。
    #[tokio::test]
    async fn direct_switch_never_reads_inner_again() {
        let uuid = vec![0xABu8; 16];
        let app = build_tls_app_data(b"hello-direct");
        let frame = xtls_padding(
            Some(&app),
            COMMAND_PADDING_DIRECT,
            &mut Some(uuid.clone()),
            false,
            &DEFAULT_PADDING_SEED,
            &mut StdRng::from_os_rng(),
        );
        let (_raw_peer, raw_own) = make_std_tcp_pair();
        let mut rx = VisionConn::new_server(
            SslSwallowMock {
                first: frame,
                swallowed: b"COALESCED-RAW-TAIL".to_vec(),
                delivered: false,
                reads: 0,
            },
            uuid,
            raw_own,
        );
        rx.downlink_traffic.enable_xtls = true;

        // 读 #1：DIRECT 帧 content 正常解出（基线）
        let mut got = vec![0u8; app.len()];
        rx.read_exact(&mut got).await.unwrap();
        assert_eq!(got, app, "DIRECT content must decode");

        // 契约本体：DIRECT 帧交付后不得再读 inner（防把裸流字节拉进
        // deframer 被 DecryptError 吞掉/滞留）。读计数必须停在 1。
        assert_eq!(
            rx.inner.reads, 1,
            "inner must never be polled again after the DIRECT frame is delivered"
        );

        // raw 通道接管：对端裸发明文必须直达 caller，且 inner 读计数不动
        #[allow(unused_mut)] // 存量清零批次
        let (mut raw_peer, mut raw_own2) = make_std_tcp_pair();
        rx.raw_fallback = Some(raw_own2);
        raw_peer.write_all(b"raw-downlink").await.unwrap();
        let mut tail = [0u8; 12];
        tokio::time::timeout(std::time::Duration::from_secs(2), rx.read_exact(&mut tail))
            .await
            .expect("raw downlink bytes must flow after the switch")
            .unwrap();
        assert_eq!(&tail, b"raw-downlink");
        assert_eq!(rx.inner.reads, 1, "raw-path reads must not touch the inner TLS layer");
    }

    /// 写侧激活闸门实锤（macOS Interop #08 r2 定罪，本轮修复本体）：
    /// tokio-rustls `poll_write` 是 BufWriter 语义——`Ok(len)` 只代表密文
    /// 进入内部 sendable_tls 缓冲，write_io 撞 WouldBlock 时尾巴滞留缓冲
    /// （common/mod.rs poll_write 的 `(n, true) => Ok(n)` 分支）。旧实现见
    /// Ok(len) 即 arm raw：激活后 poll_flush/poll_shutdown 改道 raw，TLS
    /// 记录尾巴**永久出不去** → 对端 deframer 停在半条记录上永久 Pending
    /// （双方零 error 静默停摆，run 35207920919 c8/s8 形态）；或尾巴被
    /// 下次 inner 写带出时后续 raw 字节已先上线（线序颠倒 → DecryptError
    /// 级联 → curl "HTTP2 framing layer"）。契约：DIRECT 帧写完后，raw
    /// 通道必须等 inner flush Ready 才激活；flush Pending 期间 poll_write
    /// 不得虚报写完成、raw_fallback 必须保持 None。
    struct DeferredFlushMock {
        flush_polls: usize,
    }
    impl AsyncRead for DeferredFlushMock {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }
    impl AsyncWrite for DeferredFlushMock {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            // BufWriter 语义：无条件虚报「全部写完」（尾巴留在内部缓冲）
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            this.flush_polls += 1;
            if this.flush_polls == 1 {
                Poll::Pending // write_io 撞 WouldBlock，尾巴滞留
            } else {
                Poll::Ready(Ok(())) // 尾巴落 socket
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl InnerRawClone for DeferredFlushMock {
        fn inner_raw_tcp_clone(&self) -> Option<TcpStream> {
            Some(make_std_tcp_pair().1)
        }
    }

    #[tokio::test]
    async fn splice_raw_activation_waits_for_inner_flush() {
        let mock = DeferredFlushMock { flush_polls: 0 };
        let mut client = VisionConn::new(mock, vec![0xABu8; 16]);
        // 白盒置位（生产由读侧 xtls_filter_tls 检测 ServerHello 置位；
        // 39824 修 C 分支 1 新增 IsTLS 前提，白盒同步补齐）
        client.downlink_traffic.enable_xtls = true;
        client.downlink_traffic.is_tls = true;
        client.downlink_traffic.is_tls12_or_above = true;
        let app = build_tls_app_data(b"GET / HTTP/1.1\r\n\r\n");

        let mut cx = Context::from_waker(std::task::Waker::noop());
        // poll_write #1：判 DIRECT → 帧写入 inner（虚报 Ok）→ 激活闸门
        // flush #1 Pending → poll_write 必须返回 Pending，raw 保持未激活
        let poll = Pin::new(&mut client).poll_write(&mut cx, &app);
        assert!(
            matches!(poll, Poll::Pending),
            "must not report write completion while inner flush pending, got {poll:?}"
        );
        assert!(client.splice_armed, "gate engaged");
        assert!(
            client.raw_fallback.is_none(),
            "raw must stay unactivated while inner flush pending"
        );

        // poll_write #2（桥重试）：闸门 flush #2 Ready → arm raw → 写完成
        let poll = Pin::new(&mut client).poll_write(&mut cx, &app);
        assert!(
            matches!(poll, Poll::Ready(Ok(n)) if n == app.len()),
            "write completes only after inner flush, got {poll:?}"
        );
        assert!(!client.splice_armed, "armed flag consumed");
        assert!(client.raw_fallback.is_some(), "raw activates exactly after inner flush completes");
        assert_eq!(client.inner.flush_polls, 2, "gate drove exactly two flush polls");
    }

    /// 帧感知读取对端 CommonConn 流上的 vision 帧，返回 (command, content)。
    /// 帧布局 `[uuid?][cmd][content_len 2B][padding_len 2B][content][padding]`；
    /// `first_frame` = true 时帧带 16B uuid 前缀（writeOnceUserUUID 语义）。
    /// 定长读「16+5+content」会因随机 padding 与后续帧无 uuid 而错位，必须
    /// 按 content_len+padding_len 消费整帧。
    async fn read_vision_frame<R: tokio::io::AsyncRead + Unpin>(
        peer: &mut R,
        first_frame: bool,
    ) -> (u8, Vec<u8>) {
        let head_len = if first_frame { 21 } else { 5 };
        let mut head = vec![0u8; head_len];
        peer.read_exact(&mut head).await.unwrap();
        let off = usize::from(first_frame) * 16;
        let cmd = head[off];
        let clen = u16::from_be_bytes([head[off + 1], head[off + 2]]) as usize;
        let plen = u16::from_be_bytes([head[off + 3], head[off + 4]]) as usize;
        let mut rest = vec![0u8; clen + plen];
        peer.read_exact(&mut rest).await.unwrap();
        rest.truncate(clen);
        (cmd, rest)
    }

    /// 构造最小 TLS 1.3 ServerHello record（85B：触发 filter 的 b.len()>=79
    /// + session_id 解析 + supported_versions 扫描，cipher = AES_128_GCM）。
    fn build_server_hello() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x00]); // record header（len 回填）
        buf.push(0x02); // handshake_type = ServerHello
        buf.extend_from_slice(&[0x00, 0x00, 0x00]); // handshake length（占位）
        buf.extend_from_slice(&[0x03, 0x03]); // server_version
        buf.extend_from_slice(&[0u8; 32]); // random
        buf.push(0x20); // session_id_len = 32
        buf.extend_from_slice(&[0u8; 32]); // session_id
        buf.extend_from_slice(&[0x13, 0x01]); // cipher = TLS_AES_128_GCM_SHA256
        buf.push(0x00); // compression_method
        buf.extend_from_slice(&crate::encryption::vision::TLS13_SUPPORTED_VERSIONS);
        let record_payload_len = buf.len() - 5;
        buf[3] = (record_payload_len >> 8) as u8;
        buf[4] = record_payload_len as u8;
        buf
    }

    /// 39824 修 C 回归：服务端下行 splice 判定必须读**本写方向**的 filter
    /// 实例。Go TrafficState 单实例共享（proxy.go WriteMultiBuffer）：下行
    /// ServerHello 经服务端 poll_write 被 filter 捕获置位 EnableXtls，写侧
    /// 判定读同一状态。Rust 双实例下服务端写方向 = uplink_traffic；此前判
    /// 定恒读 downlink_traffic（客户端角色实例）→ 服务端下行永远发不出
    /// Direct，Go 客户端永不 splice。
    /// 生产装配形态（非白盒）：ServerHello 字节真实流经 poll_write →
    /// xtls_filter_tls 置位 → 首个完整 0x17 批次触发 DIRECT。
    #[tokio::test]
    async fn server_write_path_direct_on_write_side_server_hello() {
        let ((c, _c2), (s, s2)) = make_tcp_pair().await;
        let uuid = vec![0xABu8; 16];
        let key = b"united-key".to_vec();
        let mut server = VisionConn::new_server(
            CommonConn::new(
                s,
                Aead::new(b"ctx", &key, true),
                Aead::new(b"ctx", &key, true),
                true,
                key.clone(),
            ),
            uuid.clone(),
            s2,
        );
        // ServerHello 流经写路径（生产 = 网站下行 TLS 流），filter 真实置位
        let server_hello = build_server_hello();
        server.write_all(&server_hello).await.unwrap();
        assert!(
            server.uplink_traffic.enable_xtls,
            "ServerHello through the write path must arm uplink xtls"
        );

        // 对端消费 SH 的 Continue 帧（帧感知读取：uuid 头 + 随机 padding）
        let mut peer = CommonConn::new(
            c,
            Aead::new(b"ctx", &key, true),
            Aead::new(b"ctx", &key, true),
            true,
            key.clone(),
        );
        let (cmd, sh_content) = read_vision_frame(&mut peer, true).await;
        assert_eq!(cmd, COMMAND_PADDING_CONTINUE, "ServerHello batch is not an app-data frame");
        assert_eq!(sh_content, server_hello);

        // 首个完整 0x17 app-data 批次 → 必须 DIRECT（修复前恒 Continue）
        let app = build_tls_app_data(b"GET / HTTP/1.1\r\n\r\n");
        server.write_all(&app).await.unwrap();
        server.flush().await.unwrap();
        let (cmd, content) = read_vision_frame(&mut peer, false).await;
        assert_eq!(content, app, "app-data batch content must round-trip");
        assert_eq!(
            cmd, COMMAND_PADDING_DIRECT,
            "server downlink must splice on write-side ServerHello"
        );
        assert!(!server.uplink_padding, "padding must end after DIRECT");
    }

    /// 39824 修 C End 分支（Go proxy.go:382-386）：非 TLS12+ 流量过滤窗口
    /// 将尽（NumberOfPacketToFilter <= 1）→ 提前发 End 结束 padding，不再
    /// 无限 Continue（此前写路径无 End 分支）。
    #[tokio::test]
    async fn server_write_path_early_end_for_non_tls_traffic() {
        let ((c, _c2), (s, s2)) = make_tcp_pair().await;
        let uuid = vec![0xABu8; 16];
        let key = b"united-key".to_vec();
        let mut server = VisionConn::new_server(
            CommonConn::new(
                s,
                Aead::new(b"ctx", &key, true),
                Aead::new(b"ctx", &key, true),
                true,
                key.clone(),
            ),
            uuid.clone(),
            s2,
        );
        let mut peer = CommonConn::new(
            c,
            Aead::new(b"ctx", &key, true),
            Aead::new(b"ctx", &key, true),
            true,
            key.clone(),
        );
        // 非 TLS 明文写 7 块：filter 窗口 8 → 逐块递减，块 6 递减后 counter=1
        // 命中 Go `NumberOfPacketToFilter <= 1`（proxy.go:382-386）→ 该帧 End；
        // 前 6 帧 Continue。第 8 块在 padding 关闭后走 inner 直写（无帧包装）。
        for i in 0..7u32 {
            let block = format!("GET /plain/{i} HTTP/1.1\r\n\r\n");
            server.write_all(block.as_bytes()).await.unwrap();
            server.flush().await.unwrap();
            let (cmd, content) = read_vision_frame(&mut peer, i == 0).await;
            assert_eq!(content, block.as_bytes(), "block {i} content must round-trip");
            let expect = if i < 6 { COMMAND_PADDING_CONTINUE } else { COMMAND_PADDING_END };
            assert_eq!(
                cmd, expect,
                "block {i}: non-TLS traffic must end padding at filter-window exhaustion"
            );
        }
        assert!(!server.uplink_padding, "padding must end after the early End frame");
        // End 后 caller 数据不再 padding：直写明文（无帧头），对端裸收
        let tail = b"plain after end";
        server.write_all(tail).await.unwrap();
        server.flush().await.unwrap();
        let mut raw = vec![0u8; tail.len()];
        peer.read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, tail, "post-End writes must bypass padding");
    }
}

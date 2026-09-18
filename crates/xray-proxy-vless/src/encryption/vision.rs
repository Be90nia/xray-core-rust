//! XTLS Vision 协议纯逻辑层（对应 Go `proxy/proxy.go` Vision 部分）。
//!
//! Vision 在 VLESS 加密层（[`crate::encryption::common_conn::CommonConn`]）之上提供：
//! - padding/unpadding：每块 `[uuid16?][cmd1][contentLen2 BE][padLen2 BE][content][pad]`
//! - TLS 1.3 检测：过滤前几个包识别 TLS 1.3 + 合适 cipher → 触发 splice
//! - command：`Continue(0)` / `End(1)` / `Direct(2，触发 splice)`
//!
//! 本切片仅实现纯逻辑（无 IO），splice 集成（切换 rawConn 绕过 TLS）见后续切片。

use rand::Rng;

// === TLS 魔数常量（对齐 Go proxy/proxy.go line 37-59）===

/// TLS handshake record 前缀（ServerHello 用 3 字节判定）。
pub const TLS_SERVER_HANDSHAKE_START: [u8; 3] = [0x16, 0x03, 0x03];
/// TLS handshake record 前缀（ClientHello 用 2 字节判定）。
pub const TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
/// TLS application_data record 前缀（splice 触发标志）。
pub const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];
/// supported_versions extension 内容（type 0x002b + len 2 + TLS1.3=0x0304）。
pub const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];

/// TLS handshake message 类型
pub const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
pub const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;

/// Vision padding command
pub const COMMAND_PADDING_CONTINUE: u8 = 0x00;
pub const COMMAND_PADDING_END: u8 = 0x01;
pub const COMMAND_PADDING_DIRECT: u8 = 0x02;

/// Go `buf.Size` 上限（padding 长度封顶用；对齐 Go common/buf buf.go 2048）。
const BUF_SIZE: i32 = 2048;

/// Vision 默认 padding seed（对齐 Go `NewVisionWriter` testseed 默认值）。
pub const DEFAULT_PADDING_SEED: [u32; 4] = [900, 500, 900, 256];

/// 账户级 testseed 归一化（对齐 Go `NewVisionWriter`：`len(testseed) < 4` 时
/// 用默认值 `[900, 500, 900, 256]` 兜底；≥4 时只取前 4 个，Go 只索引 `[0..3]`）。
///
/// 对应 Go `proxy/vless/infra/conf` 的 `testseed` 字段：账户本地配置，**不上
/// wire**——client 上行 padding 用自己账号的 seed，server 下行 padding 用服务端
/// 账号的 seed，两侧独立无需协商。
#[must_use]
pub fn normalize_padding_seed(seed: &[u32]) -> [u32; 4] {
    if seed.len() < 4 {
        DEFAULT_PADDING_SEED
    } else {
        [seed[0], seed[1], seed[2], seed[3]]
    }
}

/// TLS 1.3 cipher suite 名称查询（对齐 Go `Tls13CipherSuiteDic`）。
///
/// 返回 `None` 表示未知 cipher。`TLS_AES_128_CCM_8_SHA256` 不触发 splice（Go 语义）。
#[must_use]
pub fn tls13_cipher_suite_name(cipher: u16) -> Option<&'static str> {
    match cipher {
        0x1301 => Some("TLS_AES_128_GCM_SHA256"),
        0x1302 => Some("TLS_AES_256_GCM_SHA384"),
        0x1303 => Some("TLS_CHACHA20_POLY1305_SHA256"),
        0x1304 => Some("TLS_AES_128_CCM_SHA256"),
        0x1305 => Some("TLS_AES_128_CCM_8_SHA256"),
        _ => None,
    }
}

/// 单向（inbound 或 outbound）Vision 状态（对齐 Go `InboundState`/`OutboundState`）。
///
/// Go 的 `InboundState` 与 `OutboundState` 字段名略有差异（`UplinkReaderDirectCopy` vs
/// `DownlinkReaderDirectCopy`），语义一致；Rust 统一为 `reader_direct_copy`/`writer_direct_copy`，
/// 方向由 `TrafficState.inbound`/`outbound` 区分。
#[derive(Clone, Debug)]
pub struct DirectionState {
    /// reader: 是否仍处于 padding buffer 模式
    pub within_padding_buffers: bool,
    /// reader: 是否切换到直接拷贝（splice，绕过 TLS）
    pub reader_direct_copy: bool,
    /// reader: 当前块剩余未解析的 command header 字节数（初始 -1）
    pub remaining_command: i32,
    /// reader: 当前块剩余 content 字节数
    pub remaining_content: i32,
    /// reader: 当前块剩余 padding 字节数
    pub remaining_padding: i32,
    /// reader: 当前块的 command 值（0=Continue/1=End/2=Direct）
    pub current_command: i32,
    /// writer: 是否仍处于 padding 输出模式
    pub is_padding: bool,
    /// writer: 是否切换到直接写入（splice）
    pub writer_direct_copy: bool,
}

impl Default for DirectionState {
    fn default() -> Self {
        Self {
            within_padding_buffers: false,
            reader_direct_copy: false,
            remaining_command: -1,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
            is_padding: true,
            writer_direct_copy: false,
        }
    }
}

/// Vision 连接级状态（对齐 Go `TrafficState`）。
#[derive(Clone, Debug)]
pub struct TrafficState {
    pub user_uuid: Vec<u8>,
    pub number_of_packet_to_filter: i32,
    pub enable_xtls: bool,
    pub is_tls12_or_above: bool,
    pub is_tls: bool,
    pub cipher: u16,
    pub remaining_server_hello: i32,
    pub inbound: DirectionState,
    pub outbound: DirectionState,
}

impl TrafficState {
    /// 创建 TrafficState。`number_of_packet_to_filter` 默认 8（Vision 过滤窗口）。
    #[must_use]
    pub fn new(user_uuid: Vec<u8>) -> Self {
        Self {
            user_uuid,
            number_of_packet_to_filter: 8,
            enable_xtls: false,
            is_tls12_or_above: false,
            is_tls: false,
            cipher: 0,
            remaining_server_hello: 0,
            inbound: DirectionState::default(),
            outbound: DirectionState::default(),
        }
    }
}

/// Vision padding 编码（对齐 Go `XtlsPadding`）。
///
/// 输出格式：`[user_uuid(16, 仅首块)][command(1)][content_len(2 BE)][padding_len(2 BE)][content][padding]`。
/// `user_uuid` 被消费后置 `None`（Go `writeOnceUserUUID` 语义）。
///
/// # 参数
/// - `content`：明文内容（`None` 表示纯 padding keepalive）
/// - `command`：Vision command（[`COMMAND_PADDING_CONTINUE`]/[`COMMAND_PADDING_END`]/[`COMMAND_PADDING_DIRECT`]）
/// - `user_uuid`：首块写入后置 `None`
/// - `long_padding`：是否生成长 padding（隐藏 VLESS header）
/// - `seed`：padding 长度种子 `[短阈值, 长上限, 长基准, 短上限]`
/// - `rng`：随机数生成器
#[must_use]
pub fn xtls_padding<R: Rng>(
    content: Option<&[u8]>,
    command: u8,
    user_uuid: &mut Option<Vec<u8>>,
    long_padding: bool,
    seed: &[u32; 4],
    rng: &mut R,
) -> Vec<u8> {
    let content_len = content.map_or(0_i32, |c| c.len() as i32);
    let mut padding_len = if content_len < seed[0] as i32 && long_padding {
        rng.random_range(0..seed[1]) as i32 + seed[2] as i32 - content_len
    } else {
        rng.random_range(0..seed[3]) as i32
    };
    let cap = BUF_SIZE - 21 - content_len;
    if padding_len > cap {
        padding_len = cap;
    }
    if padding_len < 0 {
        padding_len = 0;
    }

    let mut out = Vec::new();
    if let Some(uuid) = user_uuid.take() {
        out.extend_from_slice(&uuid);
    }
    out.push(command);
    out.push((content_len >> 8) as u8);
    out.push(content_len as u8);
    out.push((padding_len >> 8) as u8);
    out.push(padding_len as u8);
    if let Some(c) = content {
        out.extend_from_slice(c);
    }
    // padding 用零填充（对齐 Go `buf.Buffer.Extend` 行为）
    out.resize(out.len() + padding_len as usize, 0);
    out
}

/// Vision unpadding 解码（对齐 Go `XtlsUnpadding`）。
///
/// 状态机解析 padding 块，提取 content。`state` 跨调用保持解析进度。
///
/// 初始状态（`remaining_command == remaining_content == remaining_padding == -1`）：
/// - 匹配 `user_uuid` 前 16 字节 → 跳过 uuid，进入解析
/// - 不匹配 → 原样返回（非 Vision 块）
///
/// # 返回
/// 提取出的 content 字节（padding 被丢弃）。
#[must_use]
pub fn xtls_unpadding(buf: &[u8], state: &mut DirectionState, user_uuid: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pos = 0;

    // 初始状态：等待 user_uuid（16 字节 + 5 header = 21 最小）
    if state.remaining_command == -1
        && state.remaining_content == -1
        && state.remaining_padding == -1
    {
        if buf.len() >= 21 && user_uuid.len() == 16 && buf[..16] == user_uuid[..] {
            pos = 16;
            state.remaining_command = 5;
        } else {
            // 非 Vision 块，原样返回
            return buf.to_vec();
        }
    }

    while pos < buf.len() {
        if state.remaining_command > 0 {
            let data = buf[pos];
            pos += 1;
            match state.remaining_command {
                5 => state.current_command = data as i32,
                4 => state.remaining_content = (data as i32) << 8,
                3 => state.remaining_content |= data as i32,
                2 => state.remaining_padding = (data as i32) << 8,
                1 => state.remaining_padding |= data as i32,
                _ => {}
            }
            state.remaining_command -= 1;
        } else if state.remaining_content > 0 {
            let len = state
                .remaining_content
                .min((buf.len() - pos) as i32) as usize;
            out.extend_from_slice(&buf[pos..pos + len]);
            pos += len;
            state.remaining_content -= len as i32;
        } else {
            // remaining_padding > 0
            let len = state
                .remaining_padding
                .min((buf.len() - pos) as i32) as usize;
            pos += len;
            state.remaining_padding -= len as i32;
        }

        // 块完成检查
        if state.remaining_command <= 0
            && state.remaining_content <= 0
            && state.remaining_padding <= 0
        {
            if state.current_command == COMMAND_PADDING_CONTINUE as i32 {
                // Continue: 读下一块 header
                state.remaining_command = 5;
            } else {
                // End/Direct: 回初始状态
                state.remaining_command = -1;
                state.remaining_content = -1;
                state.remaining_padding = -1;
                // 残余字节（不应出现）追加到输出
                if pos < buf.len() {
                    out.extend_from_slice(&buf[pos..]);
                }
                break;
            }
        }
    }
    out
}

/// TLS 1.3 检测（对齐 Go `XtlsFilterTls`）。
///
/// 遍历 buffers，识别 TLS ServerHello/ClientHello，检测 TLS 1.3 + 合适 cipher。
/// 命中 TLS 1.3 → `state.enable_xtls = true`（触发后续 splice）。
///
/// # 参数
/// - `buffers`：明文 buffer 切片（`xtls_unpadding` 后的 content）
/// - `state`：连接级状态（修改 `number_of_packet_to_filter` / `enable_xtls` 等）
pub fn xtls_filter_tls(buffers: &[&[u8]], state: &mut TrafficState) {
    for &b in buffers {
        if state.number_of_packet_to_filter <= 0 {
            return;
        }
        state.number_of_packet_to_filter -= 1;
        if b.len() < 6 {
            continue;
        }
        let starts = &b[..6];

        if starts.starts_with(&TLS_SERVER_HANDSHAKE_START) && starts[5] == TLS_HANDSHAKE_TYPE_SERVER_HELLO {
            state.remaining_server_hello = ((starts[3] as i32) << 8 | starts[4] as i32) + 5;
            state.is_tls12_or_above = true;
            state.is_tls = true;
            if b.len() >= 79 && state.remaining_server_hello >= 79 {
                let session_id_len = b[43] as usize;
                let cipher_off = 44 + session_id_len;
                if cipher_off + 2 <= b.len() {
                    state.cipher = ((b[cipher_off] as u16) << 8) | b[cipher_off + 1] as u16;
                }
            }
        } else if starts.starts_with(&TLS_CLIENT_HANDSHAKE_START) && starts[5] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
            state.is_tls = true;
        }

        if state.remaining_server_hello > 0 {
            let end = (state.remaining_server_hello.min(b.len() as i32)) as usize;
            state.remaining_server_hello -= b.len() as i32;
            if end >= TLS13_SUPPORTED_VERSIONS.len()
                && b[..end]
                    .windows(TLS13_SUPPORTED_VERSIONS.len())
                    .any(|w| w == &TLS13_SUPPORTED_VERSIONS)
            {
                if let Some(v) = tls13_cipher_suite_name(state.cipher) {
                    if v != "TLS_AES_128_CCM_8_SHA256" {
                        state.enable_xtls = true;
                    }
                }
                state.number_of_packet_to_filter = 0;
                return;
            }
            if state.remaining_server_hello <= 0 {
                state.number_of_packet_to_filter = 0;
                return;
            }
        }
        if state.number_of_packet_to_filter <= 0 {
            return;
        }
    }
}

/// 检查 buffer 是否由完整的 TLS application_data record 组成（对齐 Go `IsCompleteRecord`）。
///
/// 每个 record：`[0x17][0x03][0x03][len_hi][len_lo][payload(len)]`。
#[must_use]
pub fn is_complete_record(buf: &[u8]) -> bool {
    let mut i = 0;
    let total = buf.len();
    while i < total {
        // record header（5 字节）
        if i + 5 > total {
            return false;
        }
        if buf[i] != 0x17 || buf[i + 1] != 0x03 || buf[i + 2] != 0x03 {
            return false;
        }
        let record_len = ((buf[i + 3] as usize) << 8) | buf[i + 4] as usize;
        i += 5;
        let remaining = total - i;
        if remaining < record_len {
            return false;
        }
        i += record_len;
    }
    i == total
}

// === XRV -udp443 流控（对齐 Go `proxy/vless/encryption/vision.go` udp443 逻辑）===

/// QUIC initial packet 类型（对齐 Go ` pktTypeUDP443` 常量）。
///
/// Go vision.go 对目标端口 443（QUIC/UDP）的流量做特殊处理：
/// 识别 QUIC Initial 包类型，用于触发或抑制 splice（直接拷贝）。
/// 仅在 splice 判定时使用，不影响加密层。
pub const PKT_TYPE_UDP443_INITIAL: u8 = 0;
pub const PKT_TYPE_UDP443_OTHER: u8 = 1;
pub const PKT_TYPE_NOT_UDP443: u8 = 2;

/// 判断 UDP 包是否目标端口 443（QUIC 流量）。
///
/// 对应 Go vision.go 中 `isUDP443` 判定：splice 决策时，如果目标端口
/// 是 443 且 transport 是 UDP（QUIC），则走 udp443 流控路径而非 TLS
/// 检测路径。普通 TCP 443（HTTPS over TCP）仍走 TLS 检测。
///
/// # 参数
/// - `port`：目标端口（大端无关，已解析的 u16）
/// - `is_udp`：传输层是否 UDP
#[must_use]
pub fn is_udp443(port: u16, is_udp: bool) -> bool {
    is_udp && port == 443
}

/// 分类 UDP 443 包类型（QUIC Initial vs 其他）。
///
/// 对应 Go vision.go 中对 udp443 流量的分类逻辑：
/// - QUIC Initial 包（第一个 UDP 数据包，携带 ClientHello）→ [`PKT_TYPE_UDP443_INITIAL`]
/// - 其他 udp443 包（后续 QUIC 帧）→ [`PKT_TYPE_UDP443_OTHER`]
/// - 非 udp443 → [`PKT_TYPE_NOT_UDP443`]
///
/// QUIC Initial 包检测：前 2 字节（header form bit + fixed bit + long header）
/// 首字节高 2 bit = 0b11 表示 Long Header（Initial/0-RTT/Handshake/Retry）。
/// 更精确的 Initial 判定需查 QUIC version + packet type 字段。
///
/// # 参数
/// - `buf`：UDP 数据包内容
/// - `port`：目标端口
/// - `is_udp`：传输层是否 UDP
#[must_use]
pub fn classify_udp443_packet(buf: &[u8], port: u16, is_udp: bool) -> u8 {
    if !is_udp443(port, is_udp) {
        return PKT_TYPE_NOT_UDP443;
    }
    // QUIC Long Header 检测：首字节 bit 7 (header form) = 1, bit 6 (fixed) = 1
    // Long Header: 0b11xx_xxxx；Initial 包 type = 00（bit 4-3）
    if buf.len() >= 1 {
        let first = buf[0];
        if (first & 0b1100_0000) == 0b1100_0000 {
            // Long Header; Initial packet type bits = 00 (bits 4-3)
            let pkt_type = (first >> 4) & 0b11;
            if pkt_type == 0b00 {
                return PKT_TYPE_UDP443_INITIAL;
            }
        }
    }
    PKT_TYPE_UDP443_OTHER
}

/// UDP 443 流控决策：是否允许 splice（直接拷贝）。
///
/// 对应 Go vision.go 中 udp443 的 splice 决策：
/// - 非 udp443 → 由上层 TLS 检测决定（返回 `None`，让调用方继续走 TLS 路径）
/// - udp443 Initial 包（QUIC 握手）→ **不允许 splice**（需过滤 TLS）
/// - udp443 后续包 → 允许 splice
///
/// 返回 `Some(true)` = 允许 splice，`Some(false)` = 禁止 splice，`None` = 非
/// udp443，调用方应走 TLS 检测路径。
#[must_use]
pub fn udp443_splice_decision(buf: &[u8], port: u16, is_udp: bool) -> Option<bool> {
    let pkt_type = classify_udp443_packet(buf, port, is_udp);
    match pkt_type {
        PKT_TYPE_NOT_UDP443 => None,
        PKT_TYPE_UDP443_INITIAL => Some(false), // 握手包需过滤，不能 splice
        PKT_TYPE_UDP443_OTHER => Some(true),
        _ => None,
    }
}

// === CanSpliceCopy 检测（对齐 Go vision.go `CanSpliceCopy`）===

/// Splice 检测结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpliceDecision {
    /// 允许 splice（直接拷贝底层流，绕过加密/解密）。
    Splice,
    /// 禁止 splice，继续走加密层。
    NoSplice,
    /// 需要继续过滤更多包才能判定（返回缓冲区状态给调用方）。
    Pending,
}

/// 检测当前状态是否满足 splice 条件。
///
/// 对应 Go vision.go `CanSpliceCopy`（实际在 outbound.go 的 splice 决策中调用）。
///
/// Splice 条件（全部满足）：
/// 1. `state.enable_xtls`：已检测到 TLS 1.3 + 合适 cipher
/// 2. `number_of_packet_to_filter <= 0`：过滤窗口已耗尽（确认是 TLS 流量）
/// 3. 非 udp443 流量（udp443 有独立决策路径）
///
/// # 参数
/// - `state`：连接级 TrafficState（来自 `xtls_filter_tls` 的累积结果）
/// - `port`：目标端口
/// - `is_udp`：传输层是否 UDP
///
/// # Returns
/// - [`SpliceDecision::Splice`]：满足全部条件，可切换到直接拷贝
/// - [`SpliceDecision::NoSplice`]：明确不满足（enable_xtls=false）
/// - [`SpliceDecision::Pending`]：过滤窗口未耗尽，需更多包
///
/// # Ponytail / 平台限制
/// 实际的 splice（绕过 TLS 直接拷贝底层 TCP）在 Go 端用 `unsafe.Pointer` 提取
/// `tls.Conn` 内部的 raw TCP 连接，Rust 端没有等价物。本函数只做决策判定，
/// 返回 `Splice` 时调用方应切换到 splice copy 路径（实际实现留 TODO）。
#[must_use]
pub fn can_splice_copy(state: &TrafficState, port: u16, is_udp: bool) -> SpliceDecision {
    // udp443 走独立决策路径
    if is_udp443(port, is_udp) {
        // udp443 的 splice 决策不依赖 TLS 检测，直接交由 udp443_splice_decision
        // 但 can_splice_copy 是连接级判定，需要包级决策在调用方逐包执行。
        // 这里返回 NoSplice，让调用方走 udp443 逐包决策路径。
        return SpliceDecision::NoSplice;
    }

    if !state.enable_xtls {
        return SpliceDecision::NoSplice;
    }

    if state.number_of_packet_to_filter > 0 {
        return SpliceDecision::Pending;
    }

    SpliceDecision::Splice
}
// splice copy 实际数据搬运：生产路径已由 `VisionConn` 通过 `raw_tcp_clone`
// （accept 层 dup / `Connection::raw_tcp_clone`）实装——见 vision_conn.rs::DIRECT
// 帧切换读通道到 `raw_fallback: Option<TcpStream>`，TLS 半关闭走裸 TCP。
// 本模块只保留 `can_splice_copy`（决策 + udp443 分流），不重复提供 IO stub。

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rng;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn padding_basic_format_with_uuid() {
        let mut rng = rng();
        let user_uuid = vec![0xABu8; 16];
        let mut write_uuid = Some(user_uuid.clone());
        let content = b"hello";

        let padded = xtls_padding(
            Some(content),
            COMMAND_PADDING_END,
            &mut write_uuid,
            false,
            &DEFAULT_PADDING_SEED,
            &mut rng,
        );

        // uuid 被消费
        assert!(write_uuid.is_none());
        // [uuid16][cmd1][contentLen2][padLen2][content][pad]
        assert_eq!(&padded[..16], &user_uuid);
        assert_eq!(padded[16], COMMAND_PADDING_END);
        let content_len = ((padded[17] as usize) << 8) | padded[18] as usize;
        let pad_len = ((padded[19] as usize) << 8) | padded[20] as usize;
        assert_eq!(content_len, 5);
        assert_eq!(&padded[21..21 + content_len], content);
        assert_eq!(padded.len(), 21 + content_len + pad_len);
        // padding 区域全零
        assert!(padded[21 + content_len..].iter().all(|&b| b == 0));
    }

    #[test]
    fn padding_no_uuid_second_block() {
        let mut rng = rng();
        let mut write_uuid: Option<Vec<u8>> = None; // 已消费
        let padded = xtls_padding(
            Some(b"data"),
            COMMAND_PADDING_CONTINUE,
            &mut write_uuid,
            false,
            &DEFAULT_PADDING_SEED,
            &mut rng,
        );
        // 无 uuid 前缀，直接从 command 开始
        assert_eq!(padded[0], COMMAND_PADDING_CONTINUE);
    }

    #[test]
    fn padding_long_padding_generates_larger_pad() {
        let mut rng = rng();
        let mut write_uuid = Some(vec![0u8; 16]);
        // 短 content + long_padding → padding_len = rand(0..500) + 900 - content_len
        let short = xtls_padding(
            Some(b"hi"),
            COMMAND_PADDING_END,
            &mut write_uuid,
            true,
            &DEFAULT_PADDING_SEED,
            &mut rng,
        );
        let pad_len = ((short[19] as usize) << 8) | short[20] as usize;
        // long padding 至少 900 - 2 - 500 = 398 起（rand 下限 0）
        assert!(pad_len >= 398, "long padding too small: {pad_len}");

        let mut write_uuid2 = Some(vec![0u8; 16]);
        let _short2 = xtls_padding(
            Some(b"hi"),
            COMMAND_PADDING_END,
            &mut write_uuid2,
            false,
            &DEFAULT_PADDING_SEED,
            &mut rng,
        );
    }

    #[test]
    fn unpadding_roundtrip_single_block() {
        let mut rng = rng();
        let user_uuid = vec![0x11u8; 16];
        let mut write_uuid = Some(user_uuid.clone());
        let content = b"hello vision world";

        let padded = xtls_padding(
            Some(content),
            COMMAND_PADDING_END,
            &mut write_uuid,
            false,
            &DEFAULT_PADDING_SEED,
            &mut rng,
        );

        let mut state = DirectionState::default();
        let unpadded = xtls_unpadding(&padded, &mut state, &user_uuid);
        assert_eq!(unpadded, content);
        // End 后回初始状态
        assert_eq!(state.remaining_command, -1);
    }

    #[test]
    fn unpadding_roundtrip_multi_block_continue_then_end() {
        let mut rng = rng();
        let user_uuid = vec![0x22u8; 16];
        let mut write_uuid = Some(user_uuid.clone());

        // 块1: Continue + content1
        let mut buf = xtls_padding(
            Some(b"part1"),
            COMMAND_PADDING_CONTINUE,
            &mut write_uuid,
            false,
            &DEFAULT_PADDING_SEED,
            &mut rng,
        );
        // 块2: End + content2（无 uuid）
        let block2 = xtls_padding(
            Some(b"part2"),
            COMMAND_PADDING_END,
            &mut write_uuid,
            false,
            &DEFAULT_PADDING_SEED,
            &mut rng,
        );
        buf.extend_from_slice(&block2);

        let mut state = DirectionState::default();
        let unpadded = xtls_unpadding(&buf, &mut state, &user_uuid);
        assert_eq!(unpadded, b"part1part2");
    }

    #[test]
    fn unpadding_non_vision_block_passthrough() {
        let mut state = DirectionState::default();
        let user_uuid = vec![0u8; 16];
        let raw = b"not a vision block, just raw data";
        let out = xtls_unpadding(raw, &mut state, &user_uuid);
        assert_eq!(out, raw);
    }


    #[test]
    fn filter_tls_detects_tls13_server_hello() {
        // 构造最小 TLS 1.3 ServerHello record
        // record: [0x16][0x03][0x03][len_hi][len_lo][handshake(0x02)][hlen(3)][ver(2)][random(32)][sid_len(1)][cipher(2)][comp(1)][ext: supported_versions]
        let mut buf = Vec::new();
        // 预留 record header 位置
        buf.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x00]); // len 填后面
        buf.push(0x02); // handshake_type = ServerHello
        buf.extend_from_slice(&[0x00, 0x00, 0x00]); // handshake length（填后面，占位）
        buf.extend_from_slice(&[0x03, 0x03]); // server_version
        buf.extend_from_slice(&[0u8; 32]); // random
        buf.push(0x20); // session_id_len = 32（使 buf >= 79，Go 硬编码阈值）
        buf.extend_from_slice(&[0u8; 32]); // session_id
        buf.extend_from_slice(&[0x13, 0x01]); // cipher = TLS_AES_128_GCM_SHA256
        buf.push(0x00); // compression_method
        // extensions: supported_versions
        buf.extend_from_slice(&TLS13_SUPPORTED_VERSIONS); // [0x00,0x2b,0x00,0x02,0x03,0x04]

        // 回填 record length
        let record_payload_len = buf.len() - 5;
        buf[3] = (record_payload_len >> 8) as u8;
        buf[4] = record_payload_len as u8;

        let mut state = TrafficState::new(vec![0u8; 16]);
        xtls_filter_tls(&[&buf], &mut state);
        assert!(state.is_tls);
        assert!(state.is_tls12_or_above);
        assert!(state.enable_xtls, "should enable xtls for TLS 1.3");
        assert_eq!(state.cipher, 0x1301);
    }

    #[test]
    fn filter_tls_ccm8_does_not_enable_xtls() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x00]);
        buf.push(0x02);
        buf.extend_from_slice(&[0x00, 0x00, 0x00]);
        buf.extend_from_slice(&[0x03, 0x03]);
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(0x20); // session_id_len = 32
        buf.extend_from_slice(&[0u8; 32]); // session_id
        buf.extend_from_slice(&[0x13, 0x05]); // TLS_AES_128_CCM_8_SHA256
        buf.push(0x00);
        buf.extend_from_slice(&TLS13_SUPPORTED_VERSIONS);
        let record_payload_len = buf.len() - 5;
        buf[3] = (record_payload_len >> 8) as u8;
        buf[4] = record_payload_len as u8;

        let mut state = TrafficState::new(vec![0u8; 16]);
        xtls_filter_tls(&[&buf], &mut state);
        assert!(state.is_tls);
        assert!(!state.enable_xtls, "CCM_8 must not enable xtls");
    }

    #[test]
    fn filter_tls_short_buffer_skipped() {
        let mut state = TrafficState::new(vec![0u8; 16]);
        xtls_filter_tls(&[&[0x16, 0x03]], &mut state); // len < 6
        assert!(!state.is_tls);
    }

    #[test]
    fn is_complete_record_valid_single() {
        // [0x17 0x03 0x03][len=5][payload 5B]
        let buf = [0x17u8, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5];
        assert!(is_complete_record(&buf));
    }

    #[test]
    fn is_complete_record_valid_multi() {
        let mut buf = vec![0x17, 0x03, 0x03, 0x00, 0x02, 0xAA, 0xBB];
        buf.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x01, 0xCC]);
        assert!(is_complete_record(&buf));
    }

    #[test]
    fn is_complete_record_truncated() {
        let buf = [0x17u8, 0x03, 0x03, 0x00, 0x05, 1, 2]; // payload 不足
        assert!(!is_complete_record(&buf));
    }

    #[test]
    fn is_complete_record_wrong_type() {
        let buf = [0x16u8, 0x03, 0x03, 0x00, 0x01, 0x00]; // handshake 非 application_data
        assert!(!is_complete_record(&buf));
    }

    #[test]
    fn is_complete_record_empty() {
        assert!(is_complete_record(&[]));
    }

    // === XRV -udp443 + CanSpliceCopy 测试 ===

    #[test]
    fn is_udp443_true_for_udp_443() {
        assert!(is_udp443(443, true));
        assert!(!is_udp443(443, false)); // TCP 443 不是 udp443
        assert!(!is_udp443(8443, true)); // 非 443
        assert!(!is_udp443(80, true));
    }

    #[test]
    fn classify_udp443_non_udp443() {
        assert_eq!(
            classify_udp443_packet(&[0xC0], 80, true),
            PKT_TYPE_NOT_UDP443
        );
        assert_eq!(
            classify_udp443_packet(&[0xC0], 443, false),
            PKT_TYPE_NOT_UDP443
        );
    }

    #[test]
    fn classify_udp443_quic_initial() {
        // QUIC Initial Long Header: 0b11_00_0000 = 0xC0
        // header form=1, fixed=1, long=1, type=00(Initial)
        let pkt = [0xC0u8, 0x00, 0x00, 0x00, 0x01]; // version + packet
        assert_eq!(
            classify_udp443_packet(&pkt, 443, true),
            PKT_TYPE_UDP443_INITIAL
        );
    }

    #[test]
    fn classify_udp443_quic_handshake_not_initial() {
        // QUIC Handshake Long Header: 0b11_10_0000 = 0xE0 (type=10)
        let pkt = [0xE0u8, 0x00];
        assert_eq!(
            classify_udp443_packet(&pkt, 443, true),
            PKT_TYPE_UDP443_OTHER
        );
    }

    #[test]
    fn classify_udp443_short_header() {
        // Short Header: 0b01_000000 = 0x40 (header form=0)
        let pkt = [0x40u8, 0x00];
        assert_eq!(
            classify_udp443_packet(&pkt, 443, true),
            PKT_TYPE_UDP443_OTHER
        );
    }

    #[test]
    fn classify_udp443_empty_buf() {
        assert_eq!(
            classify_udp443_packet(&[], 443, true),
            PKT_TYPE_UDP443_OTHER
        );
    }

    #[test]
    fn udp443_splice_initial_blocks() {
        let pkt = [0xC0u8];
        assert_eq!(udp443_splice_decision(&pkt, 443, true), Some(false));
    }

    #[test]
    fn udp443_splice_other_allows() {
        let pkt = [0x40u8]; // short header
        assert_eq!(udp443_splice_decision(&pkt, 443, true), Some(true));
    }

    #[test]
    fn udp443_splice_non_udp443_none() {
        assert_eq!(udp443_splice_decision(&[0xC0], 443, false), None);
        assert_eq!(udp443_splice_decision(&[0xC0], 80, true), None);
    }

    #[test]
    fn can_splice_no_xtls() {
        let state = TrafficState::new(vec![0u8; 16]);
        assert_eq!(
            can_splice_copy(&state, 443, false),
            SpliceDecision::NoSplice
        );
    }

    #[test]
    fn can_splice_pending_when_filtering() {
        let mut state = TrafficState::new(vec![0u8; 16]);
        state.enable_xtls = true;
        state.number_of_packet_to_filter = 3; // 仍在过滤窗口内
        assert_eq!(
            can_splice_copy(&state, 443, false),
            SpliceDecision::Pending
        );
    }

    #[test]
    fn can_splice_ready_when_xtls_and_filtered() {
        let mut state = TrafficState::new(vec![0u8; 16]);
        state.enable_xtls = true;
        state.number_of_packet_to_filter = 0; // 过滤窗口已耗尽
        assert_eq!(
            can_splice_copy(&state, 443, false),
            SpliceDecision::Splice
        );
    }

    #[test]
    fn can_splice_udp443_returns_no_splice() {
        let mut state = TrafficState::new(vec![0u8; 16]);
        state.enable_xtls = true;
        state.number_of_packet_to_filter = 0;
        // udp443 走独立路径，can_splice_copy 返回 NoSplice
        assert_eq!(
            can_splice_copy(&state, 443, true),
            SpliceDecision::NoSplice
        );
    }

    #[test]
    fn splice_decision_enum_equality() {
        assert_eq!(SpliceDecision::Splice, SpliceDecision::Splice);
        assert_ne!(SpliceDecision::Splice, SpliceDecision::NoSplice);
        assert_ne!(SpliceDecision::Splice, SpliceDecision::Pending);
    }

    #[test]
    fn normalize_padding_seed_fallback_and_truncate() {
        // 空 / 不足 4 → 默认（Go NewVisionWriter len<4 兜底）
        assert_eq!(normalize_padding_seed(&[]), DEFAULT_PADDING_SEED);
        assert_eq!(normalize_padding_seed(&[1, 2, 3]), DEFAULT_PADDING_SEED);
        // 恰 4 → 原样；超 4 → 前 4（Go 只索引 [0..3]）
        assert_eq!(normalize_padding_seed(&[7, 8, 9, 10]), [7, 8, 9, 10]);
        assert_eq!(normalize_padding_seed(&[7, 8, 9, 10, 99]), [7, 8, 9, 10]);
    }

    /// testseed 注入只改 padding 长度分布，不改帧格式：固定 rng 下
    /// 逐字节断言 `[uuid][command][content_len][padding_len][content][padding]`。
    #[test]
    fn xtls_padding_seed_changes_pad_len_not_frame_layout() {
        let uuid = vec![0xABu8; 16];
        let content = [0x11u8; 4];
        // 同一 rng 状态分别以默认 seed 与自定义 seed 编码（对齐 Go XtlsPadding 公式）
        let mk = |seed: &[u32; 4]| {
            let mut rng = StdRng::from_seed([42u8; 32]);
            let mut u = Some(uuid.clone());
            xtls_padding(Some(&content), COMMAND_PADDING_CONTINUE, &mut u, true, seed, &mut rng)
        };
        let with_default = mk(&DEFAULT_PADDING_SEED);
        let with_custom = mk(&[10, 20, 30, 40]);

        for block in [&with_default, &with_custom] {
            // 帧头逐字节：uuid(16) + command(1) + content_len(2)=4 + padding_len(2)
            assert_eq!(&block[..16], &[0xABu8; 16], "uuid prefix");
            assert_eq!(block[16], COMMAND_PADDING_CONTINUE);
            assert_eq!(&block[17..19], &[0x00, 0x04], "content_len BE");
            let pad_len = u16::from_be_bytes([block[19], block[20]]) as usize;
            assert_eq!(block.len(), 16 + 1 + 2 + 2 + 4 + pad_len, "total layout");
            // content 原样在 padding 前
            assert_eq!(&block[21..25], &content);
            assert!(block[25..].iter().all(|&b| b == 0), "zero padding");
        }
        // long_padding：pad = rng(20) + 30 - 4 ≥ 26（seed[1]=20, seed[2]=30）
        let pad_custom = u16::from_be_bytes([with_custom[19], with_custom[20]]) as usize;
        assert!(pad_custom >= 26, "custom long pad {pad_custom} should be >= 30-4");
        // seed 不同 → 长度分布不同（自定义 seed 长基准 30 vs 默认 900，此处必不同）
        let pad_default = u16::from_be_bytes([with_default[19], with_default[20]]) as usize;
        assert_ne!(pad_default, pad_custom, "different seeds → different pad length");
    }
}

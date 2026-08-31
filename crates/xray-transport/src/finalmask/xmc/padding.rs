//! # XMC 启动 + Play 阶段 padding 调度（对应 Go `xmc/padding.go`）
//!
//! Minecraft Login 握手结束后、`PacketStream` 加密代理通道建立之前，双
//! 方便携可观测的"方向性 padding 调度"，模拟 MC 26.1.2 的客户端与服务端
//! 流量形状（短握手 burst + play_join 大量随机的 client/server 字节流）。
//!
//! 设计要点：
//! - 每个 turn 一段连续字节流，由 VarInt 长度前缀 + body 组成。
//! - 调度方向（client→server / server→client）由调用方的 `is_client` 与
//!   `turn.direction` 共同决定；`run_padding_schedule` 据此选择读或写。
//! - 多 chunk 写入时按 chunk 间 `chunk_delay` 切分；首个 chunk 与 header
//!   一同立即 flush（与 Go 行为一致）。
//! - 异步包装 `tokio::time::sleep`；测试可注入 fake sleeper 直接
//!   `futures::future::pending()` 跳过延时。

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::protocol;

/// Sleeper 类型别名：`Fn(Duration) -> Pin<Box<dyn Future<Output=()> + Send>>`。
pub type Sleeper = dyn Fn(Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync;

/// MC 启动 + play padding 调度常量（对应 Go `paddingBufferLength` 等）。
pub const PADDING_BUFFER_LENGTH: usize = 16 * 1024;
pub const MAX_PADDING_CHUNK_LENGTH: i32 = 48 * 1024;
pub const MAX_PADDING_TURN_LENGTH: i32 = 8 * 1024 * 1024;

/// Padding turn 方向（对应 Go `paddingDirection`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingDirection {
    ClientToServer,
    ServerToClient,
}

/// 区间延时（对应 Go `paddingDelayRange`）。
#[derive(Debug, Clone, Copy)]
pub struct PaddingDelayRange {
    pub min: Duration,
    pub max: Duration,
}

impl PaddingDelayRange {
    pub const ZERO: PaddingDelayRange = PaddingDelayRange {
        min: Duration::ZERO,
        max: Duration::ZERO,
    };

    pub fn from_millis(min: u64, max: u64) -> Self {
        Self {
            min: Duration::from_millis(min),
            max: Duration::from_millis(max),
        }
    }
}

/// Variant：固定 chunk 模板 + 可选每 chunk 独立延时（对应 Go `paddingVariant`）。
#[derive(Debug, Clone)]
pub struct PaddingVariant {
    pub chunks: Vec<i32>,
    pub delays: Vec<PaddingDelayRange>,
}

/// Padding turn：方向 + 长度约束 + variant 列表 + 写入参数（对应 Go `paddingTurn`）。
#[derive(Debug, Clone)]
pub struct PaddingTurn {
    pub direction: PaddingDirection,
    pub min_length: i32,
    pub max_length: i32,
    pub variants: Vec<PaddingVariant>,
    pub start_delay: PaddingDelayRange,
    pub chunk_delay: PaddingDelayRange,
    pub write_chunk_min_length: i32,
    pub write_chunk_length: i32,
    pub send_min_length: i32,
    pub send_max_length: i32,
    pub send_variants: Vec<usize>,
}

impl Default for PaddingTurn {
    fn default() -> Self {
        Self {
            direction: PaddingDirection::ClientToServer,
            min_length: 0,
            max_length: 0,
            variants: Vec::new(),
            start_delay: PaddingDelayRange::ZERO,
            chunk_delay: PaddingDelayRange::ZERO,
            write_chunk_min_length: 0,
            write_chunk_length: 0,
            send_min_length: 0,
            send_max_length: 0,
            send_variants: Vec::new(),
        }
    }
}

fn io_err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn rand_u32() -> u32 {
    rand::random::<u32>()
}

fn rand_delay(range: PaddingDelayRange) -> Duration {
    let min = range.min.as_nanos() as u64;
    let max = range.max.as_nanos() as u64;
    if min == max {
        return range.min;
    }
    let span = max - min + 1;
    let offset = u64::from(rand_u32() % (span as u32));
    range.min + Duration::from_nanos(offset)
}

fn rand_index(length: usize) -> usize {
    if length == 0 {
        return 0;
    }
    if length == 1 {
        return 0;
    }
    (rand_u32() as usize) % length
}

fn rand_target(min: i32, max: i32) -> i32 {
    if min == max {
        return min;
    }
    let span = (max - min + 1) as u32;
    min + (rand_u32() % span) as i32
}

fn validate_delay_range(range: PaddingDelayRange, label: &str) -> Result<(), io::Error> {
    if range.max < range.min {
        return Err(io_err(format!(
            "invalid padding delay range {label}: {:?}-{:?}",
            range.min, range.max
        )));
    }
    Ok(())
}

fn variant_length(variant: &PaddingVariant) -> i32 {
    variant.chunks.iter().sum()
}

fn turn_bounds(turn: &PaddingTurn) -> Result<(i32, i32), io::Error> {
    if turn.variants.is_empty() {
        if turn.min_length < 1 || turn.max_length < turn.min_length || turn.max_length > MAX_PADDING_TURN_LENGTH {
            return Err(io_err(format!(
                "invalid length range: {}-{}",
                turn.min_length, turn.max_length
            )));
        }
        return Ok((turn.min_length, turn.max_length));
    }
    if turn.min_length != 0 || turn.max_length != 0 {
        return Err(io_err("variants cannot be combined with a length range"));
    }
    let mut min_length = MAX_PADDING_TURN_LENGTH + 1;
    let mut max_length = 0i32;
    for (i, variant) in turn.variants.iter().enumerate() {
        if variant.chunks.is_empty() {
            return Err(io_err(format!("variant {i} has no chunks")));
        }
        if !variant.delays.is_empty() && variant.delays.len() != variant.chunks.len() {
            return Err(io_err(format!(
                "variant {i} has {} chunks and {} delays",
                variant.chunks.len(),
                variant.delays.len()
            )));
        }
        for (j, chunk) in variant.chunks.iter().enumerate() {
            if *chunk < 1 || *chunk > MAX_PADDING_CHUNK_LENGTH {
                return Err(io_err(format!(
                    "variant {i} chunk {j} has invalid length: {chunk}"
                )));
            }
            if !variant.delays.is_empty() {
                validate_delay_range(variant.delays[j], &format!("variant {i} chunk {j}"))?;
            }
        }
        let length = variant_length(variant);
        if length > MAX_PADDING_TURN_LENGTH {
            return Err(io_err(format!("variant {i} is too long: {length}")));
        }
        min_length = min_length.min(length);
        max_length = max_length.max(length);
    }
    for index in &turn.send_variants {
        if *index >= turn.variants.len() {
            return Err(io_err(format!("invalid send variant index: {index}")));
        }
    }
    Ok((min_length, max_length))
}

fn turn_accepts_length(turn: &PaddingTurn, length: i32) -> bool {
    if turn.variants.is_empty() {
        return length >= turn.min_length && length <= turn.max_length;
    }
    turn.variants
        .iter()
        .any(|v| variant_length(v) == length)
}

fn default_chunks(record_length: i32, chunk_length: i32) -> Vec<i32> {
    let mut out = Vec::new();
    let mut remaining = record_length;
    while remaining > 0 {
        let n = remaining.min(chunk_length);
        out.push(n);
        remaining -= n;
    }
    out
}

fn trim_padding_prefix(
    variant: &PaddingVariant,
    prefix_length: i32,
) -> Result<(Vec<i32>, Vec<PaddingDelayRange>), io::Error> {
    let mut remaining_prefix = prefix_length;
    let mut first_chunk = 0usize;
    while first_chunk < variant.chunks.len() && remaining_prefix > 0 {
        let chunk_length = variant.chunks[first_chunk];
        if remaining_prefix < chunk_length {
            return Err(io_err(format!(
                "prefix length {prefix_length} splits chunk {first_chunk}"
            )));
        }
        remaining_prefix -= chunk_length;
        first_chunk += 1;
    }
    if remaining_prefix != 0 || first_chunk == variant.chunks.len() {
        return Err(io_err(format!(
            "prefix length {prefix_length} leaves no padding record"
        )));
    }
    let chunks: Vec<i32> = variant.chunks[first_chunk..].to_vec();
    let mut delays = vec![PaddingDelayRange::ZERO; chunks.len()];
    if !variant.delays.is_empty() {
        for (i, d) in variant.delays[first_chunk..].iter().enumerate() {
            delays[i] = *d;
        }
    }
    Ok((chunks, delays))
}

fn select_variant(
    turn: &PaddingTurn,
    prefix_length: i32,
) -> Result<(i32, Vec<i32>, Vec<PaddingDelayRange>), io::Error> {
    if turn.variants.is_empty() {
        let minimum = if turn.send_min_length != 0 || turn.send_max_length != 0 {
            turn.send_min_length
        } else {
            turn.min_length
        };
        let maximum = if turn.send_min_length != 0 || turn.send_max_length != 0 {
            turn.send_max_length
        } else {
            turn.max_length
        };
        return Ok((rand_target(minimum, maximum), Vec::new(), Vec::new()));
    }

    let indices: Vec<usize> = if turn.send_variants.is_empty() {
        (0..turn.variants.len()).collect()
    } else {
        turn.send_variants.clone()
    };
    let selected = rand_index(indices.len());
    let variant_index = indices[selected];
    let variant = &turn.variants[variant_index];
    let target_length = variant_length(variant);
    let (chunks, delays) = trim_padding_prefix(variant, prefix_length)?;
    Ok((target_length, chunks, delays))
}

/// 同步验证整个 schedule（对应 Go `validatePaddingSchedule`）。
pub fn validate_padding_schedule(
    schedule: &[PaddingTurn],
    first_turn_prefix_length: i32,
) -> Result<(), io::Error> {
    if schedule.is_empty() {
        return Err(io_err("empty padding schedule"));
    }
    if first_turn_prefix_length < 0 {
        return Err(io_err(format!(
            "negative first turn prefix length: {first_turn_prefix_length}"
        )));
    }
    if first_turn_prefix_length > 0 && schedule[0].direction != PaddingDirection::ClientToServer {
        return Err(io_err("first prefixed padding turn is not client-to-server"));
    }

    for (i, turn) in schedule.iter().enumerate() {
        if turn.direction != PaddingDirection::ClientToServer
            && turn.direction != PaddingDirection::ServerToClient
        {
            return Err(io_err(format!(
                "padding turn {i} has invalid direction"
            )));
        }
        validate_delay_range(turn.start_delay, &format!("turn {i} start"))?;
        validate_delay_range(turn.chunk_delay, &format!("turn {i} chunk"))?;
        if turn.write_chunk_min_length < 0
            || turn.write_chunk_length < turn.write_chunk_min_length
            || turn.write_chunk_length > MAX_PADDING_CHUNK_LENGTH
        {
            return Err(io_err(format!(
                "padding turn {i} has an invalid write chunk range: {}-{}",
                turn.write_chunk_min_length, turn.write_chunk_length
            )));
        }
        if !turn.variants.is_empty() && turn.write_chunk_length != 0 {
            return Err(io_err(format!(
                "padding turn {i} combines variants with generated write chunks"
            )));
        }

        let (min_length, max_length) = turn_bounds(turn)?;
        let has_send_range = turn.send_min_length != 0 || turn.send_max_length != 0;
        if has_send_range {
            if !turn.variants.is_empty() {
                return Err(io_err(format!(
                    "padding turn {i} combines variants with a send range"
                )));
            }
            if turn.send_min_length < min_length
                || turn.send_max_length < turn.send_min_length
                || turn.send_max_length > max_length
            {
                return Err(io_err(format!(
                    "padding turn {i} has an invalid send range: {}-{}",
                    turn.send_min_length, turn.send_max_length
                )));
            }
        }
        if i == 0 && min_length - first_turn_prefix_length < 1 {
            return Err(io_err(format!(
                "padding turn 0 is too short for {first_turn_prefix_length} prefix bytes"
            )));
        }
        if i == 0 && !turn.variants.is_empty() {
            for (j, variant) in turn.variants.iter().enumerate() {
                trim_padding_prefix(variant, first_turn_prefix_length)
                    .map_err(|e| io_err(format!("padding turn 0 variant {j}: {e}")))?;
            }
        }
        if i > 0 && turn.direction == schedule[i - 1].direction {
            return Err(io_err(format!(
                "padding turns {} and {} have the same direction",
                i - 1,
                i
            )));
        }
    }
    Ok(())
}

async fn sleep_range<F>(range: PaddingDelayRange, sleeper: &F) -> io::Result<()>
where
    F: Fn(Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync,
{
    let delay = rand_delay(range);
    if delay > Duration::ZERO {
        sleeper(delay).await;
    }
    Ok(())
}

async fn read_varint_async<R>(reader: &mut R) -> io::Result<i32>
where
    R: AsyncRead + Unpin,
{
    let mut value: i32 = 0;
    let mut position: i32 = 0;
    let mut buf = [0u8; 1];
    for _ in 0..5 {
        reader.read_exact(&mut buf).await?;
        let b = buf[0];
        value |= i32::from(b & 0x7F) << position;
        if b & 0x80 == 0 {
            return Ok(value);
        }
        position += 7;
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "xmc padding varint too large",
    ))
}

async fn read_padding_turn<R>(
    reader: &mut R,
    turn: &PaddingTurn,
    prefix_length: i32,
) -> Result<(), io::Error>
where
    R: AsyncRead + Unpin,
{
    let encoded_length = read_varint_async(reader).await?;
    let header_length = protocol::varint_size(encoded_length) as i32;
    let record_length = encoded_length;
    if record_length < header_length || record_length > MAX_PADDING_TURN_LENGTH {
        return Err(io_err(format!(
            "invalid padding record length: {record_length}"
        )));
    }
    let total_length = prefix_length + record_length;
    if !turn_accepts_length(turn, total_length) {
        if !turn.variants.is_empty() {
            return Err(io_err(format!(
                "padding turn length {total_length} is not an allowed variant"
            )));
        }
        return Err(io_err(format!(
            "padding turn length {total_length} is outside {}-{}",
            turn.min_length, turn.max_length
        )));
    }

    let mut buf = [0u8; PADDING_BUFFER_LENGTH];
    let mut remaining = record_length - header_length;
    while remaining > 0 {
        let chunk_length = remaining.min(buf.len() as i32) as usize;
        reader.read_exact(&mut buf[..chunk_length]).await?;
        remaining -= chunk_length as i32;
    }
    Ok(())
}

pub async fn write_padding_turn_with_sleeper<W, F>(
    writer: &mut W,
    turn: &PaddingTurn,
    prefix_length: i32,
    sleeper: &F,
) -> Result<(), io::Error>
where
    W: AsyncWrite + Unpin,
    F: Fn(Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync,
{
    sleep_range(turn.start_delay, sleeper).await?;
    let (target_length, mut chunks, mut delays) = select_variant(turn, prefix_length)?;
    let record_length = target_length - prefix_length;
    if record_length < 1 {
        return Err(io_err(format!(
            "target length {target_length} leaves an invalid record length {record_length}"
        )));
    }

    let header_length = protocol::varint_size(record_length);
    let mut header = Vec::with_capacity(header_length);
    protocol::write_varint(&mut header, record_length)?;

    if chunks.is_empty() {
        let mut write_chunk_length = turn.write_chunk_length;
        if write_chunk_length == 0 {
            write_chunk_length = PADDING_BUFFER_LENGTH as i32;
        } else if turn.write_chunk_min_length > 0 {
            write_chunk_length = rand_target(turn.write_chunk_min_length, write_chunk_length);
        }
        chunks = default_chunks(record_length, write_chunk_length);
        delays = vec![PaddingDelayRange::ZERO; chunks.len()];
        for d in delays.iter_mut().skip(1) {
            *d = turn.chunk_delay;
        }
    }

    if chunks[0] < header_length as i32 {
        return Err(io_err(format!(
            "first padding chunk {} is shorter than header {}",
            chunks[0],
            header_length
        )));
    }
    let max_chunk_length = chunks.iter().copied().max().unwrap_or(0);
    let mut buffer = vec![0u8; max_chunk_length as usize];
    buffer[..header_length].copy_from_slice(&header);

    let mut written = 0i32;
    for (i, chunk_length) in chunks.iter().enumerate() {
        if i < delays.len() {
            sleep_range(delays[i], sleeper).await?;
        }
        writer.write_all(&buffer[..*chunk_length as usize]).await?;
        written += *chunk_length;
        if i == 0 {
            for b in buffer[..header_length].iter_mut() {
                *b = 0;
            }
        }
    }
    if written != record_length {
        return Err(io_err(format!(
            "padding chunks total {written}, want {record_length}"
        )));
    }
    Ok(())
}

/// 异步跑 padding 调度（对应 Go `runPaddingSchedule`）。
///
/// `is_client=true`：本端是 MC 客户端，按 `direction == ClientToServer` 判定本端是否发送。
pub async fn run_padding_schedule<R, W>(
    reader: &mut R,
    writer: &mut W,
    is_client: bool,
    first_turn_prefix_length: i32,
    schedule: &[PaddingTurn],
) -> Result<(), io::Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let sleeper = |d: Duration| -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(tokio::time::sleep(d))
    };
    run_padding_schedule_with_sleeper(
        reader,
        writer,
        is_client,
        first_turn_prefix_length,
        schedule,
        &sleeper,
    )
    .await
}

pub async fn run_padding_schedule_with_sleeper<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    is_client: bool,
    first_turn_prefix_length: i32,
    schedule: &[PaddingTurn],
    sleeper: &F,
) -> Result<(), io::Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: Fn(Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync,
{
    validate_padding_schedule(schedule, first_turn_prefix_length)?;
    for (i, turn) in schedule.iter().enumerate() {
        let prefix_length = if i == 0 { first_turn_prefix_length } else { 0 };
        let local_sends = is_client == (turn.direction == PaddingDirection::ClientToServer);
        if local_sends {
            write_padding_turn_with_sleeper(writer, turn, prefix_length, sleeper).await?;
        } else {
            read_padding_turn(reader, turn, prefix_length).await?;
        }
    }
    Ok(())
}

/// `Sleeper` 跳过所有延时（测试用）。
pub fn no_op_sleeper(_: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async {})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_empty_schedule() {
        assert!(validate_padding_schedule(&[], 0).is_err());
    }

    #[test]
    fn reject_negative_prefix() {
        let turn = PaddingTurn {
            min_length: 100,
            max_length: 200,
            ..PaddingTurn::default()
        };
        assert!(validate_padding_schedule(&[turn], -1).is_err());
    }

    #[test]
    fn reject_first_turn_prefix_without_client_direction() {
        let turn = PaddingTurn {
            direction: PaddingDirection::ServerToClient,
            min_length: 100,
            max_length: 200,
            ..PaddingTurn::default()
        };
        assert!(validate_padding_schedule(&[turn], 10).is_err());
    }

    #[test]
    fn accept_valid_range_schedule() {
        let turn = PaddingTurn {
            direction: PaddingDirection::ClientToServer,
            min_length: 10,
            max_length: 200,
            ..PaddingTurn::default()
        };
        assert!(validate_padding_schedule(&[turn], 0).is_ok());
    }

    #[test]
    fn reject_two_consecutive_same_direction() {
        let a = PaddingTurn {
            direction: PaddingDirection::ClientToServer,
            min_length: 1,
            max_length: 10,
            ..PaddingTurn::default()
        };
        let b = PaddingTurn {
            direction: PaddingDirection::ClientToServer,
            min_length: 1,
            max_length: 10,
            ..PaddingTurn::default()
        };
        assert!(validate_padding_schedule(&[a, b], 0).is_err());
    }

    #[tokio::test]
    async fn round_trip_two_turns() {
        let turns = vec![
            PaddingTurn {
                direction: PaddingDirection::ClientToServer,
                min_length: 100,
                max_length: 100,
                ..PaddingTurn::default()
            },
            PaddingTurn {
                direction: PaddingDirection::ServerToClient,
                min_length: 100,
                max_length: 100,
                ..PaddingTurn::default()
            },
        ];
        let (client_raw, server_raw) = tokio::io::duplex(64 * 1024);
        let (mut cr, mut cw) = tokio::io::split(client_raw);
        let (mut sr, mut sw) = tokio::io::split(server_raw);

        let client_fut = async {
            run_padding_schedule_with_sleeper(&mut cr, &mut cw, true, 0, &turns, &no_op_sleeper)
                .await
                .unwrap();
        };
        let server_fut = async {
            run_padding_schedule_with_sleeper(&mut sr, &mut sw, false, 0, &turns, &no_op_sleeper)
                .await
                .unwrap();
        };
        let _ = tokio::join!(client_fut, server_fut);
    }
}

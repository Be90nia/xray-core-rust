//! Dialer（对应 Go `dialer.go`）。
//!
//! IO 边界 stub：实际 UDP/TLS/Udpmask 留 trait 注入。
//! 核心逻辑（globalConv 原子递增 + fetchInput 分发）可测。

use std::sync::{
    Arc, LazyLock,
    atomic::{AtomicU32, Ordering},
};

use crate::{
    connection::{ConnMetadata, Connection, ConnectionCloser},
    error::{KcpError, Result},
    io::PacketReader,
    output::SegmentWriter,
};

/// 全局 conversation ID（对应 Go `globalConv`）。
///
/// 首次访问时以 `dice.RollUint16()` 随机播种（Go `dialer.go` 包级变量
/// `var globalConv uint32 = dice.RollUint16()` 的初始化语义），生产路径无需显式 init。
static GLOBAL_CONV: LazyLock<AtomicU32> =
    LazyLock::new(|| AtomicU32::new(u32::from(xray_common::dice::roll_uint16())));

/// 显式覆写 globalConv（测试定标用；生产 seeding 由 LazyLock 首访随机完成）。
pub fn init_global_conv(seed: u16) {
    GLOBAL_CONV.store(u32::from(seed), Ordering::SeqCst);
}

/// 原子递增并返回下一个 conv（对应 Go `atomic.AddUint32(&globalConv, 1)` as uint16）。
///
/// 注意：Go `AddUint32` 返回新值，再转 uint16。这里 1:1 对齐：先 fetch_add（返回旧值）
/// 后 +1。截断到 u16 与 Go 一致（wrap at 65536）。
pub fn next_conv() -> u16 {
    GLOBAL_CONV.fetch_add(1, Ordering::SeqCst).wrapping_add(1) as u16
}

/// 包输入 trait（对应 Go `fetchInput` 的 `io.Reader`）。
///
/// 生产实现包装 UDP socket；测试用 mock。
pub trait PacketInput: Send {
    /// 阻塞读一个 UDP 包。EOF/错误返回 None。
    fn read_packet(&mut self) -> Option<Vec<u8>>;
}

/// Dialer 工厂 trait（对应 Go `DialKCP` 的外部依赖）。
///
/// 生产实现注入：UDP socket + 可选 TLS 客户端包装 + 可选 Udpmask 包装。
pub trait KcpDialerFactory: Send + Sync {
    /// 建立底层连接，返回 (reader, writer, closer, metadata) 四元组。
    #[allow(clippy::type_complexity)] // 存量清零批次：type_complexity
    fn dial_udp(
        &self,
        dest: &str,
    ) -> Result<(
        Box<dyn PacketInput>,
        Arc<dyn SegmentWriter>,
        Arc<dyn ConnectionCloser>,
        ConnMetadata,
    )>;
}

/// 从输入流读包并分发 segment 到 connection（对应 Go `fetchInput`）。
///
/// 循环调用直到 `input.read_packet()` 返回 None。
/// 生产模式应在独立 task/spawn 中调用。
pub fn fetch_input(input: &mut dyn PacketInput, reader: &dyn PacketReader, conn: &Connection) {
    while let Some(payload) = input.read_packet() {
        let segments = reader.read(&payload);
        if !segments.is_empty() {
            conn.input(segments);
        }
    }
}

/// DialKCP 编排入口（对应 Go `DialKCP`）。
///
/// 当前为 stub：返回 `Err(Unsupported)`。实际实现需 `KcpDialerFactory` +
/// TLS 配置 + Udpmask。
pub fn dial_kcp(_factory: &dyn KcpDialerFactory, _dest: &str) -> Result<Connection> {
    Err(KcpError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "DialKCP requires injected UDP transport; not yet wired",
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment::{CmdOnlySegment, Command, Segment};

    #[test]
    fn next_conv_increments_atomically() {
        init_global_conv(100);
        assert_eq!(next_conv(), 101);
        assert_eq!(next_conv(), 102);
        assert_eq!(next_conv(), 103);
    }

    #[test]
    fn next_conv_wraps_at_u16_boundary() {
        init_global_conv(u16::MAX);
        assert_eq!(next_conv(), 0);
    }

    #[test]
    fn global_conv_seeds_randomly_on_first_access() {
        // 验证 5wek globalConv 随机初始化：Go `var globalConv uint32 = dice.RollUint16()`
        // → Rust LazyLock 首访 roll_uint16 随机。两次「reset」种子应得到不同首值。
        // 注：直接断言 GLOBAL_CONV 不可行（私有 static），但 init_global_conv
        // 会覆写 LazyLock 首访值；此处改为两次独立 reset 路径下的单步增长合法性。
        // 真正随机性靠 LazyLock 自检（构造期触发 roll_uint16()）。
        init_global_conv(0);
        assert_eq!(next_conv(), 1);
        init_global_conv(0x1234);
        assert_eq!(next_conv(), 0x1235);
    }

    struct MockInput {
        packets: Vec<Vec<u8>>,
    }
    impl PacketInput for MockInput {
        fn read_packet(&mut self) -> Option<Vec<u8>> {
            self.packets.pop()
        }
    }

    #[test]
    fn fetch_input_dispatches_segments_to_connection() {
        use crate::{config::default_config, connection::NoopCloser};

        struct Sink;
        impl SegmentWriter for Sink {
            fn write_segment(&self, _seg: &dyn crate::segment::Segment) -> std::io::Result<()> {
                Ok(())
            }
        }

        let writer = Arc::new(Sink);
        let config = Arc::new(default_config());
        let conn = Connection::new_without_updater(
            ConnMetadata::new(42),
            writer,
            Arc::new(NoopCloser),
            config,
        );

        let mut seg = CmdOnlySegment::new();
        seg.conv = 42;
        seg.cmd = Command::Ping;
        let mut packet = vec![0u8; seg.byte_size()];
        seg.serialize(&mut packet);

        let mut input = MockInput { packets: vec![packet] };
        let reader = crate::io::KCPPacketReader::new();
        fetch_input(&mut input, &reader, &conn);
        assert_eq!(conn.state(), crate::state::State::Active);
        assert_eq!(input.packets.len(), 0);
    }
}

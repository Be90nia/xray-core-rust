use crate::frame::Reason;
use crate::proto::{WindowSize, MAX_WINDOW_SIZE};

use std::fmt;

// We don't want to send WINDOW_UPDATE frames for tiny changes, but instead
// aggregate them when the changes are significant. Many implementations do
// this by keeping a "ratio" of the update version the allowed window size.
//
// While some may wish to represent this ratio as percentage, using a f32,
// we skip having to deal with float math and stick to integers. To do so,
// the "ratio" is represented by 2 i32s, split into the numerator and
// denominator. For example, a 50% ratio is simply represented as 1/2.
//
// An example applying this ratio: If a stream has an allowed window size of
// 100 bytes, WINDOW_UPDATE frames are scheduled when the unclaimed change
// becomes greater than 1/2, or 50 bytes.
const UNCLAIMED_NUMERATOR: i32 = 1;
const UNCLAIMED_DENOMINATOR: i32 = 2;

// [本仓 patch · 唯一 patch 面] WINDOW_UPDATE 回填粒度。
//
// 上游缺省按「窗口的一半」回填（threshold = window/2）⇒ 稳态在飞只有半窗
// ⇒ 高 RTT 路径带宽被砍半。仓内实测（reports/2026-11-13-readonly-threeaxis-audit.md
// §11-§13）：同一份代码只改注入 RTT，RTT 170ms → 69.8-70.1 MB/s、RTT 400ms →
// 35.6-35.8 MB/s（恰好一半）；反算在飞量仅为标称窗的 36-43%。
//
// Go x/net/http2 的粒度是「消费满 4KiB 就补」（inflowMinRefresh = 4 << 10，
// http2/flow.go:12-14）：WINDOW_UPDATE 在未发信用累计到 4KiB、或足以让对端
// 可用窗翻倍时就发。此处把阈值取 min(window/2, 4KiB) ⇒ 大窗下按 4KiB 回填，
// 与 Go 对齐；小窗（window/2 < 4KiB）仍保留上游的半窗下限，避免窗口过小时
// 频繁发帧。
//
// vendor 锚点：基线 = crates.io h2 0.4.20 原版；本仓 patch 面 = 本文件这一处
// （阈值表达式 + 本常量 + 同文件内的钉桩单测）。
const INFLOW_MIN_REFRESH: i32 = 4 * 1024;

/// [本仓 patch · 唯一 patch 面] WINDOW_UPDATE 回填阈值。
///
/// 上游语义 = 窗口的一半（`window/2`）；本仓改为 `min(window/2, 4KiB)`，与 Go
/// x/net/http2 的 `inflowMinRefresh`（4<<10，http2/flow.go:12-14）同粒度。
/// 单独抽成函数，使阈值可被同文件内的钉桩单测直接断言（防上游升级/误改静默回档）。
fn window_update_threshold(window_size: i32) -> i32 {
    (window_size / UNCLAIMED_DENOMINATOR * UNCLAIMED_NUMERATOR).min(INFLOW_MIN_REFRESH)
}

/// [本仓 patch 钉桩] 回填阈值必须是 `min(window/2, 4KiB)`，不能是上游的纯 `window/2`。
///
/// 若本仓 patch 被误删、或被上游升级覆盖（回档到 window/2），稳态在飞会掉回半窗，
/// 高 RTT 路径带宽再次减半——本测试必须在此刻变红。
#[cfg(test)]
mod tests {
    use super::{window_update_threshold, INFLOW_MIN_REFRESH};

    #[test]
    fn window_update_threshold_is_min_of_half_window_and_4kib() {
        // 大窗：一律按 4KiB 回填（上游会是 16MiB / 32MiB 级别）。
        assert_eq!(window_update_threshold(32 * 1024 * 1024), 4096);
        assert_eq!(window_update_threshold(64 * 1024), 4096);
        // 小窗：window/2 < 4KiB 时保留上游的半窗下限，避免窗口过小时频繁发帧。
        assert_eq!(window_update_threshold(4 * 1024), 2048);
        assert_eq!(window_update_threshold(8 * 1024), 4096);
        // 边界：8KiB-1 窗 ⇒ 半窗 4095 < 4KiB ⇒ 取半窗。
        assert_eq!(window_update_threshold(8 * 1024 - 1), 4095);
        // 常量本身即 Go x/net/http2 的 inflowMinRefresh = 4 << 10。
        assert_eq!(INFLOW_MIN_REFRESH, 4 * 1024);
    }
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn sanity_unclaimed_ratio() {
    assert!(UNCLAIMED_NUMERATOR < UNCLAIMED_DENOMINATOR);
    assert!(UNCLAIMED_NUMERATOR >= 0);
    assert!(UNCLAIMED_DENOMINATOR > 0);
}

#[derive(Copy, Clone, Debug)]
pub struct FlowControl {
    /// Window the peer knows about.
    ///
    /// This can go negative if a SETTINGS_INITIAL_WINDOW_SIZE is received.
    ///
    /// For example, say the peer sends a request and uses 32kb of the window.
    /// We send a SETTINGS_INITIAL_WINDOW_SIZE of 16kb. The peer has to adjust
    /// its understanding of the capacity of the window, and that would be:
    ///
    /// ```notrust
    /// default (64kb) - used (32kb) - settings_diff (64kb - 16kb): -16kb
    /// ```
    window_size: Window,

    /// Window that we know about.
    ///
    /// This can go negative if a user declares a smaller target window than
    /// the peer knows about.
    available: Window,
}

impl FlowControl {
    pub fn new() -> FlowControl {
        FlowControl {
            window_size: Window(0),
            available: Window(0),
        }
    }

    /// Returns the window size as known by the peer
    pub fn window_size(&self) -> WindowSize {
        self.window_size.as_size()
    }

    /// Returns the window size available to the consumer
    pub fn available(&self) -> Window {
        self.available
    }

    /// Returns true if there is unavailable window capacity
    pub fn has_unavailable(&self) -> bool {
        if self.window_size < 0 {
            return false;
        }

        self.window_size > self.available
    }

    pub fn claim_capacity(&mut self, capacity: WindowSize) -> Result<(), Reason> {
        self.available.decrease_by(capacity)
    }

    pub fn assign_capacity(&mut self, capacity: WindowSize) -> Result<(), Reason> {
        self.available.increase_by(capacity)
    }

    /// If a WINDOW_UPDATE frame should be sent, returns a positive number
    /// representing the increment to be used.
    ///
    /// If there is no available bytes to be reclaimed, or the number of
    /// available bytes does not reach the threshold, this returns `None`.
    ///
    /// This represents pending outbound WINDOW_UPDATE frames.
    pub fn unclaimed_capacity(&self) -> Option<WindowSize> {
        let available = self.available;

        if self.window_size >= available {
            return None;
        }

        let unclaimed = available.0 - self.window_size.0;
        let threshold = window_update_threshold(self.window_size.0);

        if unclaimed < threshold {
            None
        } else {
            Some(unclaimed as WindowSize)
        }
    }

    /// Increase the window size.
    ///
    /// This is called after receiving a WINDOW_UPDATE frame
    pub fn inc_window(&mut self, sz: WindowSize) -> Result<(), Reason> {
        let (val, overflow) = self.window_size.0.overflowing_add(sz as i32);

        if overflow {
            return Err(Reason::FLOW_CONTROL_ERROR);
        }

        if val > MAX_WINDOW_SIZE as i32 {
            return Err(Reason::FLOW_CONTROL_ERROR);
        }

        tracing::trace!(
            "inc_window; sz={}; old={}; new={}",
            sz,
            self.window_size,
            val
        );

        self.window_size = Window(val);
        Ok(())
    }

    /// Decrement the send-side window size.
    ///
    /// This is called after receiving a SETTINGS frame with a lower
    /// INITIAL_WINDOW_SIZE value.
    pub fn dec_send_window(&mut self, sz: WindowSize) -> Result<(), Reason> {
        tracing::trace!(
            "dec_window; sz={}; window={}, available={}",
            sz,
            self.window_size,
            self.available
        );
        // ~~This should not be able to overflow `window_size` from the bottom.~~ wrong. it can.
        self.window_size.decrease_by(sz)?;
        Ok(())
    }

    /// Decrement the recv-side window size.
    ///
    /// This is called after receiving a SETTINGS ACK frame with a lower
    /// INITIAL_WINDOW_SIZE value.
    pub fn dec_recv_window(&mut self, sz: WindowSize) -> Result<(), Reason> {
        tracing::trace!(
            "dec_recv_window; sz={}; window={}, available={}",
            sz,
            self.window_size,
            self.available
        );
        // This should not be able to overflow `window_size` from the bottom.
        self.window_size.decrease_by(sz)?;
        self.available.decrease_by(sz)?;
        Ok(())
    }

    /// Decrements the window reflecting data has actually been sent. The caller
    /// must ensure that the window has capacity.
    pub fn send_data(&mut self, sz: WindowSize) -> Result<(), Reason> {
        tracing::trace!(
            "send_data; sz={}; window={}; available={}",
            sz,
            self.window_size,
            self.available
        );

        // If send size is zero it's meaningless to update flow control window
        if sz > 0 {
            // Ensure that the argument is correct
            assert!(self.window_size.0 >= sz as i32);

            // Update values
            self.window_size.decrease_by(sz)?;
            self.available.decrease_by(sz)?;
        }
        Ok(())
    }
}

/// The current capacity of a flow-controlled Window.
///
/// This number can go negative when either side has used a certain amount
/// of capacity when the other side advertises a reduction in size.
///
/// This type tries to centralize the knowledge of addition and subtraction
/// to this capacity, instead of having integer casts throughout the source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd)]
pub struct Window(i32);

impl Window {
    pub fn as_size(&self) -> WindowSize {
        if self.0 < 0 {
            0
        } else {
            self.0 as WindowSize
        }
    }

    pub fn checked_size(&self) -> WindowSize {
        assert!(self.0 >= 0, "negative Window");
        self.0 as WindowSize
    }

    pub fn decrease_by(&mut self, other: WindowSize) -> Result<(), Reason> {
        if let Some(v) = self.0.checked_sub(other as i32) {
            self.0 = v;
            Ok(())
        } else {
            Err(Reason::FLOW_CONTROL_ERROR)
        }
    }

    pub fn increase_by(&mut self, other: WindowSize) -> Result<(), Reason> {
        let other = self.add(other)?;
        self.0 = other.0;
        Ok(())
    }

    pub fn add(&self, other: WindowSize) -> Result<Self, Reason> {
        if let Some(v) = self.0.checked_add(other as i32) {
            Ok(Self(v))
        } else {
            Err(Reason::FLOW_CONTROL_ERROR)
        }
    }
}

impl PartialEq<usize> for Window {
    fn eq(&self, other: &usize) -> bool {
        if self.0 < 0 {
            false
        } else {
            (self.0 as usize).eq(other)
        }
    }
}

impl PartialOrd<usize> for Window {
    fn partial_cmp(&self, other: &usize) -> Option<::std::cmp::Ordering> {
        if self.0 < 0 {
            Some(::std::cmp::Ordering::Less)
        } else {
            (self.0 as usize).partial_cmp(other)
        }
    }
}

impl fmt::Display for Window {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl From<Window> for isize {
    fn from(w: Window) -> isize {
        w.0 as isize
    }
}

//! Config wrapper（对应 Go `config.go` + proto 生成的 Config）。
//!
//! Go 的 `Config` 来自 prost 生成的 proto struct，本 crate 重新导出 prost 生成的
//! 类型并附加 3 个派生计算 helper（`get_sending_in_flight_size` 等）。
//!
//! Prost 路径：`xray_proto::xray::transport::internet::kcp::Config`。

use xray_proto::xray::transport::internet::kcp::Config as ProtoConfig;

/// prost 生成的 Config 别名（语义化导出）。
pub type Config = ProtoConfig;

/// 默认配置（对应 Go `init()` 中注册的 default Config）。
#[must_use]
pub fn default_config() -> Config {
    Config {
        mtu: 1350,
        tti: 50,
        uplink_capacity: 5,
        downlink_capacity: 20,
        cwnd_multiplier: 1,
        max_sending_window: 2 * 1024 * 1024,
    }
}

/// Config 派生计算（对应 Go `Config.GetXxx()`）。
pub trait ConfigExt {
    /// 发送 in-flight 大小（对应 Go `GetSendingInFlightSize`）。下限 8。
    fn get_sending_in_flight_size(&self) -> u32;

    /// 发送缓冲区大小（对应 Go `GetSendingBufferSize`）。
    fn get_sending_buffer_size(&self) -> u32;

    /// 接收 in-flight 大小（对应 Go `GetReceivingInFlightSize`）。下限 8。
    fn get_receiving_in_flight_size(&self) -> u32;
}

impl ConfigExt for Config {
    fn get_sending_in_flight_size(&self) -> u32 {
        let mtu = self.mtu.max(1);
        let tti = self.tti.max(1).min(1000);
        let mut size = self.uplink_capacity * 1024 * 1024 / mtu / (1000 / tti);
        if size < 8 {
            size = 8;
        }
        size
    }

    fn get_sending_buffer_size(&self) -> u32 {
        self.max_sending_window / self.mtu.max(1)
    }

    fn get_receiving_in_flight_size(&self) -> u32 {
        let mtu = self.mtu.max(1);
        let tti = self.tti.max(1).min(1000);
        let mut size = self.downlink_capacity * 1024 * 1024 / mtu / (1000 / tti);
        if size < 8 {
            size = 8;
        }
        size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            mtu: 1350,
            tti: 50,
            uplink_capacity: 5,
            downlink_capacity: 20,
            cwnd_multiplier: 20,
            max_sending_window: 2 * 1024 * 1024,
        }
    }

    #[test]
    fn default_config_matches_go_init() {
        let c = default_config();
        assert_eq!(c.mtu, 1350);
        assert_eq!(c.tti, 50);
        assert_eq!(c.uplink_capacity, 5);
        assert_eq!(c.downlink_capacity, 20);
        assert_eq!(c.cwnd_multiplier, 1);
        assert_eq!(c.max_sending_window, 2 * 1024 * 1024);
    }

    #[test]
    fn sending_in_flight_size_default() {
        // 5 × 1MB / 1350 / 20 = 194
        let c = test_config();
        assert_eq!(c.get_sending_in_flight_size(), 194);
    }

    #[test]
    fn sending_in_flight_size_min_clamp_8() {
        let mut c = test_config();
        c.uplink_capacity = 0;
        assert_eq!(c.get_sending_in_flight_size(), 8);
    }

    #[test]
    fn sending_buffer_size_default() {
        let c = test_config();
        assert_eq!(c.get_sending_buffer_size(), 2 * 1024 * 1024 / 1350);
    }

    #[test]
    fn receiving_in_flight_size_default() {
        let c = test_config();
        assert_eq!(c.get_receiving_in_flight_size(), 776);
    }

    #[test]
    fn receiving_in_flight_size_min_clamp_8() {
        let mut c = test_config();
        c.downlink_capacity = 0;
        assert_eq!(c.get_receiving_in_flight_size(), 8);
    }

    #[test]
    fn helpers_safe_for_zero_mtu() {
        let mut c = test_config();
        c.mtu = 0;
        let _ = c.get_sending_in_flight_size();
        let _ = c.get_sending_buffer_size();
        let _ = c.get_receiving_in_flight_size();
    }

    #[test]
    fn helpers_safe_for_zero_tti() {
        let mut c = test_config();
        c.tti = 0;
        let _ = c.get_sending_in_flight_size();
        let _ = c.get_receiving_in_flight_size();
    }
}

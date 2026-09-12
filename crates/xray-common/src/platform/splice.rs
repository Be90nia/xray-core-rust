//! splice(2) zero-copy 转发的**决策面**（Go `proxy.CopyRawConnIfExist` 语义）。
//!
//! Go 证据：`proxy/proxy.go:715-809`（CopyRawConnIfExist / IsRAWTransportWithoutSecurity /
//! readV fallback）、`proxy/freedom/freedom.go:260`（`ob.CanSpliceCopy = 1`）、
//! `:428-436`（responseDone 闸门）。syscall 泵本体在 `xray-transport::splice`
//! （libc 依赖在彼处；本 crate Cargo.toml 冻结不加依赖），本模块承载纯决策：
//! 环境闸门 + 平台闸门 + CanSpliceCopy 信号。
//!
//! 配置面说明（票 4qjw 第 1 项）：Go freedom Config 无 use_splice 字段
//! （proto/json 均无），Rust 侧全仓 grep 同样无此配置字段——无需删除，配置里
//! 写了该键会被 `parse_freedom_config`（xray-core/src/outbound.rs）的已知键
//! 白名单解析自然忽略，与 Go 未识别字段行为一致。

use super::env::use_splice;

/// Go `session.CanSpliceCopy`（session.go:75-77）：1=可 splice。
pub const CAN_SPLICE_COPY_YES: i32 = 1;
/// Go `session.CanSpliceCopy`：2=处理后可行（vless 用；本实现不等待翻转，
/// 直接回退既有泵，见 [`signals_allow_splice`] 注释）。
pub const CAN_SPLICE_COPY_AFTER_PROCESS: i32 = 2;
/// Go `session.CanSpliceCopy`：3=不可。
pub const CAN_SPLICE_COPY_NEVER: i32 = 3;

/// 平台闸门：Linux/Android。Go `runtime.GOOS != "linux" && != "android"` 时
/// 直接走 readV（proxy.go:722-724），Windows/macOS 同样不启用。
#[must_use]
pub fn platform_supported() -> bool {
    cfg!(any(target_os = "linux", target_os = "android"))
}

/// CanSpliceCopy 信号判定（Go proxy.go:746-750）。
///
/// splice 分支要求 inbound == 1 且**所有** outbound == 1；非 freedom 出站
/// 保持 Go 零值 0（freedom.go:260 是唯一置 1 点）→ 天然不启用，与 Go 同。
/// Go 对 ==3 的前置检查（proxy.go:730,738）用于区分「立即 readV」与
/// 「泵缓冲等信号翻转」，本实现按票 4qjw 第 4 项简化：无翻转器即回退既有
/// 泵，故 `==1` 全称量词已蕴含 ≠3。
#[must_use]
pub fn signals_allow_splice(inbound_can: i32, outbounds_can: &[i32]) -> bool {
    inbound_can == CAN_SPLICE_COPY_YES
        && outbounds_can.iter().all(|&c| c == CAN_SPLICE_COPY_YES)
}

/// 总闸门（Go freedom.go:428 + proxy.go:722-751 的前置条件并集）。
#[must_use]
pub fn splice_allowed(inbound_can: i32, outbounds_can: &[i32]) -> bool {
    platform_supported() && use_splice() && signals_allow_splice(inbound_can, outbounds_can)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signals_allow_splice() {
        assert!(signals_allow_splice(1, &[]), "无出站链（freedom 本身）");
        assert!(signals_allow_splice(1, &[1]));
        assert!(signals_allow_splice(1, &[1, 1]), "代理链全 freedom");
        // 非 freedom 出站 = Go 零值 0 → 不启用
        assert!(!signals_allow_splice(0, &[]));
        assert!(!signals_allow_splice(1, &[0]));
        // vless 2（处理后可行）与 3（不可）均不进入 splice 分支
        assert!(!signals_allow_splice(2, &[1]));
        assert!(!signals_allow_splice(1, &[1, 3]));
        assert!(!signals_allow_splice(3, &[]));
    }

    #[test]
    fn test_platform_gate_excludes_non_linux() {
        // Windows/macOS 等平台总闸门恒关（泵本体未编译），不依赖 env。
        if !platform_supported() {
            assert!(!splice_allowed(1, &[1]));
        }
    }
}

//! Xray 版本三元组（`X.Y.Z`）的唯一字面量来源。
//!
//! 对应 Go `core/core.go` 的 `Version_x/y/z`。住在 `xray-common`（依赖图最低层）
//! 是因为两个消费方之间无依赖边：`xray-core::version` 对外 re-export 本处常量，
//! `xray-reality` 的 REALITY ClientHello `session_id` 版本头（Go `reality.go:168-170`
//! 读 `core.Version_x/y/z`）直接取本处——升级基准只改这里一处（bd 4w092 f）。

/// 主版本号。对应 Go `Version_x`。
pub const VERSION_X: u8 = 26;

/// 次版本号。对应 Go `Version_y`。
pub const VERSION_Y: u8 = 11;

/// 修订号。对应 Go `Version_z`。
///
/// 对拍基准是 Go v26.11.9（CLAUDE.md §0）。版本三元组整体必须 **≥ 基准**：
/// 本端版本低于 `"min": "26.10.17"` 这类 Go 侧合法配置的下限时，配置会在装配期
/// 被本端版本门判为不满足而拒启（bd 5uhaj）。比较是逐段数值比较
/// （`xray_app_version::compare_versions`），不是字符串字典序。
pub const VERSION_Z: u8 = 9;

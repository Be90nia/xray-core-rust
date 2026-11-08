//! Xray 版本三元组（`X.Y.Z`）的唯一字面量来源。
//!
//! 对应 Go `core/core.go` 的 `Version_x/y/z`。住在 `xray-common`（依赖图最低层）
//! 是因为两个消费方之间无依赖边：`xray-core::version` 对外 re-export 本处常量，
//! `xray-reality` 的 REALITY ClientHello `session_id` 版本头（Go `reality.go:168-170`
//! 读 `core.Version_x/y/z`）直接取本处——升级基准只改这里一处（bd 4w092 f）。

/// 主版本号。对应 Go `Version_x`。
pub const VERSION_X: u8 = 26;

/// 次版本号。对应 Go `Version_y`。
pub const VERSION_Y: u8 = 10;

/// 修订号。对应 Go `Version_z`。
///
/// 对拍基准是 Go v26.10.17（CLAUDE.md §0）；写成 11 会让 `"min": "26.10.17"`
/// 这类 Go 侧合法配置在装配期被自己判为不满足而拒启（bd 5uhaj）。
pub const VERSION_Z: u8 = 17;

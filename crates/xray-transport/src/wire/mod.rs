//! 协议线格式散件（wire helpers）。
//!
//! 归属口径（规划 `docs/architecture/xray-frame-masque-实施计划-2026-11-11.md` §4.1）：
//! 本模块只收**零 xray 语义、多协议共用**的线格式编解码散件；零 xray 语义但单消费方的
//! 机制不进（ponytail），协议方向件（含 Xray/Go 兼容语义）不进。

pub mod varint;

#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)] // 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
pub mod antireplay;
pub mod bitmask;
pub mod browser;
pub mod cmdarg;
pub mod crypto_provider;
pub mod ctx;
pub mod dice;
pub mod drain;
pub mod errors;
pub mod log;
pub mod net;
pub mod ocsp;
pub mod padding;
pub mod peer;
pub mod platform;
pub mod protocol;
pub mod reflect;
pub mod runtime_guard;
pub mod serial;
pub mod session;
pub mod signal;
pub mod singbridge;
pub mod testing;
pub mod units;
pub mod uuid;

/// rustls 进程级 CryptoProvider 唯一生产安装入口（bd jrh7，见
/// [`crypto_provider::ensure_default_crypto_provider`]）。
pub use crypto_provider::ensure_default_crypto_provider;

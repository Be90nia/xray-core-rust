pub mod antireplay;
pub mod bitmask;
pub mod browser;
pub mod bytespool;
pub mod cache;
pub mod cmdarg;
pub mod crypto_provider;
pub mod ctx;
pub mod dice;
pub mod drain;
pub mod errors;
pub mod log;
pub mod net;
pub mod ocsp;
pub mod peer;
pub mod platform;
pub mod protocol;
pub mod reflect;
pub mod retry;
pub mod runtime_guard;
pub mod serial;
pub mod session;
pub mod signal;
pub mod singbridge;
pub mod task;
pub mod units;
pub mod uuid;

/// rustls 进程级 CryptoProvider 唯一生产安装入口（bd jrh7，见
/// [`crypto_provider::ensure_default_crypto_provider`]）。
pub use crypto_provider::ensure_default_crypto_provider;

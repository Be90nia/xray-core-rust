pub mod browser;
pub mod net;
pub mod protocol;
pub mod serial;
pub mod session;
pub mod log;
pub mod errors;
pub mod signal;
pub mod task;
pub mod uuid;
pub mod platform;
pub mod ctx;
pub mod cache;
pub mod bitmask;
pub mod ocsp;
pub mod peer;
pub mod drain;
pub mod antireplay;
pub mod singbridge;
pub mod cmdarg;
pub mod dice;
pub mod units;
pub mod retry;
pub mod reflect;
pub mod bytespool;
pub mod crypto_provider;
pub mod runtime_guard;

/// rustls 进程级 CryptoProvider 唯一生产安装入口（bd jrh7，见
/// [`crypto_provider::ensure_default_crypto_provider`]）。
pub use crypto_provider::ensure_default_crypto_provider;

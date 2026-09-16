//! rustls 进程级 CryptoProvider 单一安装入口（bd jrh7）。

use std::sync::Once;

static INSTALL: Once = Once::new();

/// 安装 rustls 进程级默认 CryptoProvider（ring）——全仓生产路径唯一入口。
///
/// rustls 0.23 裸 `ClientConfig::builder()` 依赖进程级 provider 或 crate
/// feature 自动裁决；workspace 多 crate feature unification 出现双 provider
/// 时自动裁决 panic（bd rknm/jrh7）。生产代码一律先调本函数，禁止散装
/// `install_default`。幂等：重复与并发调用安全（Once，已装则忽略）。
/// 测试代码内各自 `install_default` 属并行测试惯例，不在此列。
pub fn ensure_default_crypto_provider() {
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
mod tests {
    // 红测试：集中入口必须存在且可从 crate 根访问（单一来源契约）。
    #[test]
    fn ensure_default_crypto_provider_is_idempotent_and_installs() {
        crate::ensure_default_crypto_provider();
        // 幂等：重复调用不 panic（Once，已装忽略）。
        crate::ensure_default_crypto_provider();
        // 进程级 provider 已就绪：rustls 不再依赖 crate feature 自动裁决。
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_some(),
            "process-level CryptoProvider must be installed"
        );
        // 裸 builder()（不显式指定 provider）必须不再 panic——双 provider
        // feature unification 时（bd rknm）此处即历史炸点。
        let _ = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
    }
}

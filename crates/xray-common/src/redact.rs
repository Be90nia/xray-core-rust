//! 错误/日志文本脱敏（坑约束 11：凭据不得进日志）。
//!
//! 与 [`crate::log::mask_text`] 的分工：那是「按已知密钥字面量打码」，本模块是
//! **结构脱敏**——即使不知道具体密钥，URL 形态里的 userinfo（`token@`）与
//! query/fragment（常带签名）也不许原样出现在错误链里（bd dqxy3）。

/// 把 URL 压成 `scheme://host[:port]/path`：剥掉 userinfo、query、fragment。
///
/// 畸形输入（无 `://`、scheme 或 host 为空）**不猜**，直接返回 `"<redacted>"`
/// ——「认不出就别打印」，因为认不出的串最可能是被截断/拼接坏的凭据。
#[must_use]
pub fn redact_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return "<redacted>".to_string();
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    // `user:pass@host` → `host`（userinfo 是凭据主体）。
    let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    let path_end = tail.find(['?', '#']).unwrap_or(tail.len());
    if scheme.is_empty() || host.is_empty() {
        return "<redacted>".to_string();
    }
    format!("{scheme}://{host}{}", &tail[..path_end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_userinfo_and_query() {
        assert_eq!(
            redact_url("https://token@example.com/a/b?sign=abc#frag"),
            "https://example.com/a/b"
        );
        assert_eq!(redact_url("realm://user:pass@host:8443"), "realm://host:8443");
    }

    #[test]
    fn keeps_clean_urls() {
        assert_eq!(redact_url("https://example.com"), "https://example.com");
        assert_eq!(redact_url("https://example.com/"), "https://example.com/");
    }

    /// 认不出的串一律占位——这是「无 `://` 的畸形串」那条真实泄露路径的封堵。
    #[test]
    fn malformed_is_placeholder() {
        assert_eq!(redact_url("token@host:443/nothing"), "<redacted>");
        assert_eq!(redact_url("https://"), "<redacted>");
        assert_eq!(redact_url(""), "<redacted>");
    }
}

//! 错误/日志文本脱敏（坑约束 11：凭据不得进日志）。
//!
//! 与 [`crate::log::mask_text`] 的分工：那是「按已知密钥字面量打码」，本模块是
//! **结构脱敏**——即使不知道具体密钥，URL 形态里的 userinfo（`token@`）与
//! query/fragment（常带签名）也不许原样出现在错误链里（bd dqxy3）。
//!
//! ## 归属判定（CLAUDE.md §3.5.5 三判据，bd c4d1s A-06 举证）
//!
//! 判据 1（零 Xray 语义）**命中**，故归属 **udf**（提炼回路）：本件是纯字符串结构脱敏，
//! 剥 userinfo / query / fragment，畸形输入回落 `<redacted>`；不涉任何 Xray 协议或配置
//! 语义，也不复制 Go 行为（Go 上游无对等件，上游仓 `redact` 字面量仅 `common/lua` 的
//! `redactMemoryAddresses`，语义无关）。落点为 udf `std_ext` 文本/脱敏族，与既有
//! `skeleton_infra::logx::mask_secrets`（按**已知字面量**打码）互补而不重复：后者掩
//! 已知密钥，前者剥 URL 结构。
//!
//! 判据 2（否则归 xray-frame）**不适用**：判据 1 已命中，派生层不是目标态。
//!
//! 判据 3（留主仓）**不成立**：留仓须逐条举证（反向依赖 / 破坏 udf 零依赖 / 第三方栈
//! 驱动契约 / 红线文件 / 平台门控公开契约），本件一条不占，「留仓无举证」即评审打回项。
//!
//! **结论 + 提炼候选**：目标态是上浮 udf（`udf-promotion-candidate`）。本单不迁移
//! （提炼回路 = 独立 PR + 三平台 CI 绿 + 主仓换依赖删本地副本 + 32/32 复测，属大改，
//! 另议），故**过渡期留 xray-common**：唯一消费方是 xray-core 的配置期错误文案
//! （geodata 资产 URL 校验，见 `crates/xray-core/src/register.rs`）；本 crate 的
//! `log::mask_text` 是同一条「凭据不进日志」链上的**分工面**（按已知字面量打码），
//! **并非调用方**。迁移时主仓换依赖并**删本地副本**，禁留双份实现。
//!
//! 同族但不同语义（**不构成重复造轮子**，迁移时勿强行合并）：本件产出
//! `scheme://host[:port]/path`，**保留 path**；而 `xray-transport` 的
//! `finalmask::redact_urls`（文本内扫多个 URL、丢弃 path）与 `xdns::doh::url_label`
//! （单 URL、丢弃 path）语义各异。

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

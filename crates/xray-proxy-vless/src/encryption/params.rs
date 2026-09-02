//! 客户端 VLESS ENC 字符串解析。
//!
//! 对齐 Go `infra/conf/vless.go` 出站 encryption 字段校验（vless.go:333-370）：
//! `mlkem768x25519plus.<mode>.<rtt>.<parts...>`，mode ∈ {native, xorpub, random}，
//! rtt ∈ {1rtt, 0rtt}（0rtt→Seconds=1），其余 part 必须 base64url 解码 32B
//! (X25519 公钥) 或 1184B (ML-KEM-768 封装公钥)；短 part（<20 字符）计 padding。
//!
//! ENC 服务端私钥格式见 `infra/conf/vless.go:104-150`（inbound 端）：
//! s[2] 必须可 SplitN "-" 解析为 `<from>[-<to>]`，结尾无 's'（vless.go:121）；
//! 每 part 解码后 32B 或 64B。
//!
//! 出站仅需解析客户端 encryption；server-side 仅 server.rs 涉及。
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

/// ENC 出站参数（解析后等价于 Go conf.Build 之后的 `account` 字段集合）。
///
/// - `keys`：`base64url-decoded` 公钥（X25519 pub 32B 或 ML-KEM-768 ek 1184B）
/// - `xor_mode`：native=0 / xorpub=1 / random=2
/// - `seconds`：0rtt=1 / 1rtt=0
/// - `padding`：见 Go `account.Padding`（短 part 累加，原始字符串段）
///
/// 注：`account.Encryption` 剥离前缀后保留 keys 段（vless.go:364）；解析时
/// 不保留剥离后的字符串，`keys` 已是解码字节数组。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientEncParams {
    pub keys: Vec<Vec<u8>>,
    pub xor_mode: u32,
    pub seconds: u32,
    pub padding: String,
}

/// 校验 + 解析客户端 encryption 字符串。
///
/// 返回 `Some(_)` 仅当字符串是合法 `mlkem768x25519plus.*` 格式；
/// 返回 `None` 时调用方按 `encryption == "none"` 处理（不报错，向下兼容 Go）。
pub fn parse_client_encryption(raw: &str) -> Option<ClientEncParams> {
    if raw.is_empty() || raw == "none" {
        return None;
    }
    let s: Vec<&str> = raw.split('.').collect();
    if s.len() < 4 || s[0] != "mlkem768x25519plus" {
        return None;
    }
    // mode
    let xor_mode = match s[1] {
        "native" => 0,
        "xorpub" => 1,
        "random" => 2,
        _ => return None,
    };
    // rtt
    let seconds = match s[2] {
        "1rtt" => 0,
        "0rtt" => 1,
        _ => return None,
    };
    // padding 与 keys
    let mut padding_len: usize = 0;
    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(s.len().saturating_sub(3));
    for part in &s[3..] {
        if part.len() < 20 {
            padding_len += part.len() + 1;
            continue;
        }
        let bytes = URL_SAFE_NO_PAD.decode(part.as_bytes()).ok()?;
        if bytes.len() != 32 && bytes.len() != 1184 {
            return None;
        }
        keys.push(bytes);
    }
    if keys.is_empty() {
        return None;
    }
    // padding 字符串：Go 在 stripped Encryption[..padding-1] 取——这里直接从
    // 剥离的 keys 段拼回。keys 之间以 '.' 分隔；padding 是 prefix 部分，需
    // 重新从原始字符串抠出。简化：直接以相同规则重建 prefix 字符串。
    let padding = if padding_len > 0 {
        // raw 中：mlkem768x25519plus.X.Y.<rest>
        // 27 = len("mlkem768x25519plus") + 1 + len(mode) + 1 + len(rtt) = 19+1+mode+1+rtt
        //     此处逐 part 累加 padding 字符。
        let mut out = String::with_capacity(padding_len);
        // Go 的 padding 取自 stripped Encryption 前 padding-1 字节；
        // stripped Encryption = raw[27+len(rtt)..]，即「<prefix_keys>.<key1>.<key2>...」
        // 短 part 拼在 keys 之前。所以前缀部分 = raw[27+len(rtt)..27+len(rtt)+padding-1]
        let prefix_len = 27 + s[2].len(); // 起始位置
        let end = prefix_len + padding_len.saturating_sub(1);
        if end > raw.len() {
            return None;
        }
        out.push_str(&raw[prefix_len..end]);
        out
    } else {
        String::new()
    };
    Some(ClientEncParams { keys, xor_mode, seconds, padding })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_none() {
        assert!(parse_client_encryption("").is_none());
        assert!(parse_client_encryption("none").is_none());
    }

    #[test]
    fn rejects_non_mlkem_prefix() {
        assert!(parse_client_encryption("plain.foo.bar.baz").is_none());
    }

    #[test]
    fn rejects_unknown_mode() {
        assert!(parse_client_encryption("mlkem768x25519plus.foo.0rtt.abc").is_none());
    }

    #[test]
    fn rejects_unknown_rtt() {
        assert!(parse_client_encryption("mlkem768x25519plus.native.5rtt.abc").is_none());
    }

    #[test]
    fn parses_x25519_pub() {
        // 32B X25519 pub = 43 chars base64url no-pad
        let b64x: String = (0..32).map(|i| "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            .as_bytes()[i as usize % 64] as char).collect();
        assert_eq!(b64x.len(), 32); // < 20 字符触发 padding 分支 → 不行
        // 重新生成 ≥20 字符
        let b64x: String = "PZ-YRaLJBZ84xZ5zB0nIBK7wkVVWMUOjapustH_MPHg".into(); // 43 chars
        let raw = format!("mlkem768x25519plus.native.0rtt.{b64x}");
        let p = parse_client_encryption(&raw).expect("parse");
        assert_eq!(p.xor_mode, 0);
        assert_eq!(p.seconds, 1);
        assert_eq!(p.keys.len(), 1);
        assert_eq!(p.keys[0].len(), 32);
    }

    #[test]
    fn parses_mlkem768_pub() {
        // 1184B ML-KEM ek = 1578 chars base64url no-pad（ceil(1184*4/3) = 1579, no-pad ≈ 1578）
        let b64ml: String = "A".repeat(1578);
        let raw = format!("mlkem768x25519plus.native.0rtt.{b64ml}");
        let p = parse_client_encryption(&raw).expect("parse");
        assert_eq!(p.keys.len(), 1);
        assert_eq!(p.keys[0].len(), 1184);
    }

    #[test]
    fn rejects_bad_key_length() {
        // 64 chars base64url no-pad decodes to 48B — not 32 nor 1184
        let bad: String = "B".repeat(64);
        let raw = format!("mlkem768x25519plus.native.0rtt.{bad}");
        assert!(parse_client_encryption(&raw).is_none());
    }

    #[test]
    fn parses_real_vps_link() {
        // 实际 VPS 节点 #10 mlkem 链接
        let raw = "mlkem768x25519plus.native.0rtt.nOBcbXEFa0hjb-hGAfGBK5g96NmCpWA4nrtKRESyvsu8Gtl0LYLAEphydgeiNzlxOoYmt3tHBKkl68W3fEwlYfh8ZQtDvGl7K6IV1MVDQBtLieGbVkiVXYvFcpLEYFlO3LIxsOwHwGAy4umunqOGQOmDfbBOtAltcLWHInkLzqR7uEfGcXIDV2RvC1YD20oPuNmKZRO_s0vI9wbBzmxmCcwpk5ZiO2eNBekwu3xC42lZ8St05IlVcFFDfbkJk5SM8qqy1QpFMvhHBSW_78NQzMxOdkcjwMfKTqnHqacZ2cGmWZer2iGSBCU0UZSG6RyQA_YaCMmXr-OzDEdZ6sBQshsjmMOD91geV5JQdzQmHyULQhqkdhtLQYiOpalba9a0yWOFmFsAPgw3rujFN7CLbiF1LgEXqEWOtEUYu7uDzgKw_OyTk9LDsZsSZgZh6MoaQeY_wIa7jotBB8pEz7O-nQpwSnI-5HxVxfuqFzYTOwULZ2dfjVQ_MSc-cHJA0uY_hPYkrXx6IQNa3qB88mLOw_hP7CJgP4gZYTuWOxtAVarEeRJkwIV9e0hPpquzJIuFvMu0CUqeewsAabptsqBfp4soxWEcOUNZBGNJdbBAEZsfqfvOnrYgDOKSrstswxOeYlckdVix5BUHMQmuz4tJp-IKZ-e59xGyHAYp-KYxSknErbUgnjIJ1wFVb-Ms7AKjQ3gh_-KyB";
        let p = parse_client_encryption(raw).expect("parse real link");
        // VPS 公钥应是 ML-KEM-768 (1184B)
        assert!(p.keys.iter().any(|k| k.len() == 1184), "expected 1184B ML-KEM ek, got lens {:?}", p.keys.iter().map(|k| k.len()).collect::<Vec<_>>());
        assert_eq!(p.xor_mode, 0); // native
        assert_eq!(p.seconds, 1); // 0rtt
    }
}

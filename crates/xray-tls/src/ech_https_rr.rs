//! ECH DNS HTTPS RR (RFC 9460) wire-format 解析。
//!
//! 对应 Go `transport/internet/tls/ech.go` `dnsQuery` 解析阶段：
//! 构造 `dns.Msg.SetQuestion(fqdn, dns.TypeHTTPS)` → DoH/UDP 发送 →
//! 解 `*dns.HTTPS` → 遍历 SvcParams 取 `*dns.SVCBECHConfig`（key=5）→
//! `.ECH` 字节。
//!
//! Rust 端用 `hickory-proto` 等价物：`Message::from_vec(&bytes)` →
//! `RecordType::HTTPS` → `RData::HTTPS(SVCB)` → `svc_params` 里
//! `(SvcParamKey::EchConfigList, SvcParamValue::EchConfigList(Vec<u8>))` →
//! `.0` 即 ECH config list 字节。
//!
//! # 边界
//! - 只解 Answer 区第一条匹配 fqdn 的 HTTPS RR；多 RR 取首个（对齐 Go `for _, answer := range
//!   respMsg.Answer` 取首个 ECH）。
//! - 解析失败的 RR 跳过（Go 等价物是 return error，但 Rust API 难精确还原 这一段 hickory-proto
//!   错误——下游 caller 按 wire 校验再做）。

use hickory_proto::{
    op::Message,
    rr::{
        RData, RecordType,
        rdata::svcb::{SvcParamKey, SvcParamValue},
    },
};

use crate::error::TlsError;

/// 从 DNS message wire bytes 提取首个匹配 `fqdn` 的 HTTPS RR 中的 ECHConfigList。
///
/// 对齐 Go：
/// ```go
/// for _, answer := range respMsg.Answer {
///     if https, ok := answer.(*dns.HTTPS); ok && https.Hdr.Name == dns.Fqdn(domain) {
///         for _, v := range https.Value {
///             if echConfig, ok := v.(*dns.SVCBECHConfig); ok {
///                 return echConfig.ECH, answer.Header().Ttl, nil
///             }
///         }
///     }
/// }
/// return nil, 0, errors.New("no valid ECH config found in DNS response")
/// ```
///
/// # 参数
/// - `wire`：完整 DNS response bytes（含 header）
/// - `fqdn`：查询的域名（小写即可；hickory-proto 内部规范化）
///
/// # 返回
/// 首个 ECHConfigList 字节（ECH config 列表，与 `set_ech_config_list` 入参同构）。
/// `Err(TlsError::NoEchConfig)` 表示无有效 ECH RR（Go 等价物）。
pub fn extract_ech_from_dns_response(wire: &[u8], fqdn: &str) -> Result<Vec<u8>, TlsError> {
    extract_ech_and_ttl_from_dns_response(wire, fqdn).map(|(config, _ttl)| config)
}

/// [`extract_ech_from_dns_response`] 的带 TTL 版（Go `dnsQuery` 返回
/// `(ech, ttl, err)`，TTL 供 [`crate::ech_doh`] 缓存过期用）。
pub fn extract_ech_and_ttl_from_dns_response(
    wire: &[u8],
    fqdn: &str,
) -> Result<(Vec<u8>, u32), TlsError> {
    let msg = Message::from_vec(wire)
        .map_err(|e| TlsError::EchApply(format!("unpack dns response: {e}")))?;

    // Go: dns.Fqdn(domain) 加尾点；hickory-proto 内部 Name::from_ascii 规范化。
    // 比较时用原始 fqdn（也可能已带尾点）+ 加尾点两种形态兜底。
    let fqdn_dot = if fqdn.ends_with('.') { fqdn.to_string() } else { format!("{fqdn}.") };

    for rec in &msg.answers {
        if rec.record_type() != RecordType::HTTPS {
            continue;
        }
        // owner name 匹配（小写 + 尾点规范化）
        if rec.name.to_string().to_lowercase() != fqdn_dot.to_lowercase() {
            continue;
        }
        let RData::HTTPS(svcb) = &rec.data else {
            continue;
        };
        for (key, value) in &svcb.svc_params {
            if *key == SvcParamKey::EchConfigList {
                if let SvcParamValue::EchConfigList(list) = value {
                    return Ok((list.0.clone(), rec.ttl));
                }
            }
        }
        // 找到 HTTPS RR 但无 ech param → 继续看下一条
    }
    Err(TlsError::NoEchConfig)
}

/// 从单个 HTTPS RR 的 RDATA bytes 提取 ECHConfigList（用于直接构造 RR 测试）。
///
/// `rdata` 是 RFC 9460 §2.2 wire 格式：`SvcPriority(u16) + TargetName(name) + SvcParams`。
/// 不含 owner name / TTL / class（那是 RR 完整结构）。
///
/// hickory-proto 0.26 的 `RecordDataDecodable`（`HTTPS::read_data`）是
/// `pub(crate)`，crate 外无法反序列化 rdata——SvcParams 段（key u16 + len u16
/// + value bytes）按 RFC 9460 手解，TargetName 复用 hickory 公开的
/// `BinDecodable for Name`。ECH 的 SvcParamKey=5（IANA 注册表）。
pub fn extract_ech_from_https_rdata(rdata: &[u8]) -> Result<Vec<u8>, TlsError> {
    use hickory_proto::{
        rr::Name,
        serialize::binary::{BinDecodable, BinDecoder},
    };

    let ech_key = u16::from(SvcParamKey::EchConfigList);
    let mut decoder = BinDecoder::new(rdata);
    let _svc_priority = decoder
        .read_u16()
        .map_err(|e| TlsError::EchApply(format!("decode svc priority: {e}")))?
        .unverified(/* 仅排序用，提取场景跳过 */);
    Name::read(&mut decoder).map_err(|e| TlsError::EchApply(format!("decode target name: {e}")))?;
    while decoder.peek().is_some() {
        let key = decoder
            .read_u16()
            .map_err(|e| TlsError::EchApply(format!("decode param key: {e}")))?
            .unverified(/* 未知 key 跳过即可 */);
        let len = decoder
            .read_u16()
            .map_err(|e| TlsError::EchApply(format!("decode param len: {e}")))?
            .unverified(/* 越界由 read_slice 边界检查 */);
        let value = decoder
            .read_slice(usize::from(len))
            .map_err(|e| TlsError::EchApply(format!("decode param value: {e}")))?
            .unverified(/* 原样透传给 ECH 消费方 */);
        if key == ech_key {
            return Ok(value.to_vec());
        }
    }
    Err(TlsError::NoEchConfig)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use hickory_proto::{
        op::{MessageType, OpCode},
        rr::{
            Name, Record,
            rdata::{
                HTTPS,
                svcb::{EchConfigList, SVCB},
            },
        },
    };

    use super::*;

    /// 真实字节向量：RFC 9460 §2.2 SVCB/HTTPS RDATA 手工构造——
    /// `priority=1 (00 01) + target "." (00) + param ech key=5 (00 05) len=2 (00 02) value 01 02`。
    const RDATA_ECH_KEY5: &[u8] = &[0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x02, 0x01, 0x02];

    fn mock_dns_response_with_ech(fqdn: &str, ech_b64: &str) -> Vec<u8> {
        let ech_bytes = base64::engine::general_purpose::STANDARD
            .decode(ech_b64)
            .expect("test base64 must be valid");

        let owner = Name::from_ascii(fqdn).expect("ascii name");
        let svcb = SVCB::new(
            1,
            Name::from_ascii(".").unwrap(),
            vec![(
                SvcParamKey::EchConfigList,
                SvcParamValue::EchConfigList(EchConfigList(ech_bytes.clone())),
            )],
        );
        let record = Record::from_rdata(owner, 3600, RData::HTTPS(HTTPS(svcb)));

        let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
        msg.add_answer(record);
        msg.to_vec().expect("emit dns message")
    }

    #[test]
    fn extract_ech_from_well_formed_dns_response() {
        // ech 参数 2 字节最小内容（任意非空 bytes，BoringSSL 会拒；
        // 这里只测解析层，验证 wire→bytes 透传正确）
        let ech_b64 = base64::engine::general_purpose::STANDARD.encode([0x01u8, 0x02]);
        let wire = mock_dns_response_with_ech("cloudflare.com.", &ech_b64);
        let got = extract_ech_from_dns_response(&wire, "cloudflare.com").unwrap();
        assert_eq!(got, vec![0x01, 0x02], "ECH bytes must round-trip exactly");
    }

    #[test]
    fn extract_ech_fqdn_with_trailing_dot_also_works() {
        let ech_b64 = base64::engine::general_purpose::STANDARD.encode([0xAAu8, 0xBB]);
        let wire = mock_dns_response_with_ech("example.com.", &ech_b64);
        let got = extract_ech_from_dns_response(&wire, "example.com.").unwrap();
        assert_eq!(got, vec![0xAA, 0xBB]);
    }

    #[test]
    fn extract_ech_rdata_real_wire_vector() {
        // 真实字节向量 → ECHConfigList bytes → b64（配置面形态）全链路
        let got = extract_ech_from_https_rdata(RDATA_ECH_KEY5).unwrap();
        assert_eq!(got, vec![0x01, 0x02]);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&got);
        assert_eq!(b64, "AQI=");
    }

    #[test]
    fn extract_ech_rdata_skips_other_params_before_ech() {
        // priority=1 + "." + alpn(key=1,len=2,h2) + ech(key=5,len=2)——
        // ech 在 alpn 之后，验证遍历不取首个参数
        let rdata = &[
            0x00, 0x01, // priority
            0x00, // target "."
            0x00, 0x01, 0x00, 0x02, b'h', b'2', // alpn = "h2"
            0x00, 0x05, 0x00, 0x02, 0xAA, 0xBB, // ech
        ];
        let got = extract_ech_from_https_rdata(rdata).unwrap();
        assert_eq!(got, vec![0xAA, 0xBB]);
    }

    #[test]
    fn extract_ech_rdata_no_ech_param_errors() {
        // priority=1 + "." + alpn(key=1,len=2,h2)
        let rdata = &[0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x02, b'h', b'2'];
        let err = extract_ech_from_https_rdata(rdata).unwrap_err();
        assert!(matches!(err, TlsError::NoEchConfig), "got: {err:?}");
    }

    #[test]
    fn extract_ech_rdata_truncated_param_errors() {
        // ech 声明 len=8 但只剩 1 字节 → read_slice 越界报错
        let rdata = &[0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x08, 0xAA];
        let err = extract_ech_from_https_rdata(rdata).unwrap_err();
        assert!(matches!(err, TlsError::EchApply(_)), "got: {err:?}");
    }

    #[test]
    fn extract_ech_no_https_record_errors() {
        let msg = Message::new(1, MessageType::Response, OpCode::Query);
        let buf = msg.to_vec().unwrap();
        let err = extract_ech_from_dns_response(&buf, "any.com").unwrap_err();
        assert!(matches!(err, TlsError::NoEchConfig), "got: {err:?}");
    }

    #[test]
    fn extract_ech_https_record_without_ech_param_errors() {
        use hickory_proto::rr::rdata::svcb::Alpn;
        let owner = Name::from_ascii("noech.com.").unwrap();
        let svcb = SVCB::new(
            1,
            Name::from_ascii(".").unwrap(),
            vec![(SvcParamKey::Alpn, SvcParamValue::Alpn(Alpn(vec!["h2".into()])))],
        );
        let record = Record::from_rdata(owner, 60, RData::HTTPS(HTTPS(svcb)));
        let mut msg = Message::new(2, MessageType::Response, OpCode::Query);
        msg.add_answer(record);

        let buf = msg.to_vec().unwrap();
        let err = extract_ech_from_dns_response(&buf, "noech.com").unwrap_err();
        assert!(matches!(err, TlsError::NoEchConfig));
    }

    #[test]
    fn extract_ech_malformed_wire_errors() {
        // 4 字节垃圾
        let err = extract_ech_from_dns_response(&[0xde, 0xad, 0xbe, 0xef], "x.com").unwrap_err();
        // unpack 失败或无 record；具体错误形态不限
        assert!(matches!(err, TlsError::EchApply(_)) || matches!(err, TlsError::NoEchConfig));
    }
}

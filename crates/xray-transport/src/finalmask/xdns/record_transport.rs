//! # DNS 记录载体（对应 Go `xdns/record_transport.go`）
//!
//! 把 payload 字节流编码到 DNS response 的 answer section，反之亦然。
//! 支持 TXT / A / AAAA 三种 RR 类型：
//! - TXT：1 条记录，RDATA 是 `<length><bytes>` 串联（≤255 字节/段）。
//! - A / AAAA：N 条记录（≤256），每条 4/16 字节，前 2 字节 = (idx, n)。

use std::io;
use std::sync::OnceLock;

use super::dns::{
    decode_rdata_txt, encode_rdata_txt, Name, Question, RR, RR_TYPE_A, RR_TYPE_AAAA, RR_TYPE_TXT,
};
use super::spec::DomainSpec;

/// A/AAAA 记录的 payload header 大小（idx + n 两字节）。
const IP_RECORD_HEADER_SIZE: usize = 2;

/// 服务端响应 TTL（与 Go `responseTTL` 一致）。
pub const RESPONSE_TTL: u32 = 60;

/// UDP 最大 payload（IPv6 MTU 1280 - 40 IPv6 头 - 8 UDP 头）。
pub const MAX_UDP_PAYLOAD: usize = 1280 - 40 - 8;

static MAX_TXT: OnceLock<usize> = OnceLock::new();
static MAX_A: OnceLock<usize> = OnceLock::new();
static MAX_AAAA: OnceLock<usize> = OnceLock::new();

/// 返回某 rrType 下，单次响应可编码的最大 payload 字节数（lazy 计算并缓存）。
///
/// 对应 Go `maxEncodedPayloadForType`。
pub fn max_encoded_payload_for_type(rr_type: u16) -> usize {
    match rr_type {
        RR_TYPE_A => max_encoded_payload_a(),
        RR_TYPE_AAAA => max_encoded_payload_aaaa(),
        _ => max_encoded_payload_txt(),
    }
}

/// TXT 类型在 MAX_UDP_PAYLOAD 限制下的最大 payload（lazy init）。
pub fn max_encoded_payload_txt() -> usize {
    *MAX_TXT.get_or_init(|| compute_max_encoded_payload_for_type(MAX_UDP_PAYLOAD, RR_TYPE_TXT))
}

/// A 类型在 MAX_UDP_PAYLOAD 限制下的最大 payload（lazy init）。
pub fn max_encoded_payload_a() -> usize {
    *MAX_A.get_or_init(|| compute_max_encoded_payload_for_type(MAX_UDP_PAYLOAD, RR_TYPE_A))
}

/// AAAA 类型在 MAX_UDP_PAYLOAD 限制下的最大 payload（lazy init）。
pub fn max_encoded_payload_aaaa() -> usize {
    *MAX_AAAA.get_or_init(|| compute_max_encoded_payload_for_type(MAX_UDP_PAYLOAD, RR_TYPE_AAAA))
}

/// 某 rrType 下每条 RR 的 RDATA 长度（A=4、AAAA=16、TXT=0 表示无固定上限）。
///
/// 对应 Go `rrDataSizeForType`。
pub fn rr_data_size_for_type(rr_type: u16) -> usize {
    match rr_type {
        RR_TYPE_A => 4,
        RR_TYPE_AAAA => 16,
        _ => 0,
    }
}

/// 每 chunk 在 IP 记录里的有效 payload 字节数 = rrDataSize - 2(idx+n)。
///
/// 对应 Go `payloadChunkSizeForType`。TXT 返回 0。
pub fn payload_chunk_size_for_type(rr_type: u16) -> usize {
    let size = rr_data_size_for_type(rr_type);
    size.saturating_sub(IP_RECORD_HEADER_SIZE)
}

/// 按 question.qtype 把 payload 编码到 RR answers 列表。
///
/// 对应 Go `answersForPayload`。
pub fn answers_for_payload(question: &Question, ttl: u32, payload: &[u8]) -> io::Result<Vec<RR>> {
    match question.qtype {
        RR_TYPE_TXT => Ok(vec![RR {
            name: question.name.clone(),
            rtype: question.qtype,
            rclass: question.qclass,
            ttl,
            data: encode_rdata_txt(payload),
        }]),
        RR_TYPE_A | RR_TYPE_AAAA => ip_answers_for_payload(question, ttl, payload),
        _ => Err(invalid_data("unsupported rr type")),
    }
}

/// 把 payload 编码到 N 条 A/AAAA 记录。
///
/// 对应 Go `ipAnswersForPayload`。每条 data = [idx, n, payload_chunk]。
fn ip_answers_for_payload(question: &Question, ttl: u32, payload: &[u8]) -> io::Result<Vec<RR>> {
    let chunk_size = payload_chunk_size_for_type(question.qtype);
    let rr_data_size = rr_data_size_for_type(question.qtype);
    if chunk_size == 0 || rr_data_size == 0 {
        return Err(invalid_data("unsupported ip rr type"));
    }
    let num_records = if payload.is_empty() {
        1
    } else {
        payload.len().div_ceil(chunk_size)
    };
    if num_records > 256 {
        return Err(invalid_data("payload too large for ip rr type"));
    }

    let mut answers = Vec::with_capacity(num_records);
    for i in 0..num_records {
        let offset = i * chunk_size;
        let n = (payload.len().saturating_sub(offset)).min(chunk_size);
        let mut data = vec![0u8; rr_data_size];
        data[0] = i as u8;
        data[1] = n as u8;
        data[IP_RECORD_HEADER_SIZE..IP_RECORD_HEADER_SIZE + n]
            .copy_from_slice(&payload[offset..offset + n]);
        answers.push(RR {
            name: question.name.clone(),
            rtype: question.qtype,
            rclass: question.qclass,
            ttl,
            data,
        });
    }
    Ok(answers)
}

/// 从响应 answers 中解码 payload。
///
/// 对应 Go `decodeResponsePayload`。
pub fn decode_response_payload(answers: &[RR]) -> Option<Vec<u8>> {
    let first = answers.first()?;
    match first.rtype {
        RR_TYPE_TXT => {
            if answers.len() != 1 {
                return None;
            }
            decode_rdata_txt(&first.data).ok()
        }
        RR_TYPE_A | RR_TYPE_AAAA => decode_ip_answer_payload(answers, first.rtype),
        _ => None,
    }
}

/// 从 N 条 A/AAAA 记录重组 payload。
///
/// 对应 Go `decodeIPAnswerPayload`。
fn decode_ip_answer_payload(answers: &[RR], rr_type: u16) -> Option<Vec<u8>> {
    let chunk_size = payload_chunk_size_for_type(rr_type);
    let rr_data_size = rr_data_size_for_type(rr_type);
    if chunk_size == 0 || rr_data_size == 0 || answers.len() > 256 {
        return None;
    }

    let mut parts: Vec<Option<Vec<u8>>> = vec![None; answers.len()];
    for answer in answers {
        if answer.rtype != rr_type || answer.data.len() != rr_data_size {
            return None;
        }
        let idx = answer.data[0] as usize;
        let n = answer.data[1] as usize;
        if idx >= answers.len() || n > chunk_size || parts[idx].is_some() {
            return None;
        }
        let part = answer.data[IP_RECORD_HEADER_SIZE..IP_RECORD_HEADER_SIZE + n].to_vec();
        parts[idx] = Some(part);
    }

    let mut payload = Vec::new();
    for part in parts {
        payload.extend_from_slice(&part?);
    }
    Some(payload)
}

/// 计算 TXT 类型在 limit 字节响应限制下的最大 payload 字节数。
///
/// 对应 Go `computeMaxEncodedPayload`。
#[allow(dead_code)] // 公用 API wrapper（对应 Go computeMaxEncodedPayload），保留作 API 完整性
pub fn compute_max_encoded_payload(limit: usize) -> usize {
    compute_max_encoded_payload_for_type(limit, RR_TYPE_TXT)
}

/// 二分查找：在 ≤limit 字节响应中能放下的最大 payload。
///
/// 对应 Go `computeMaxEncodedPayloadForType`。调用 server::response_for 模拟响应。
pub fn compute_max_encoded_payload_for_type(limit: usize, rr_type: u16) -> usize {
    // 构造最长合法 Name（4 个 label：63+63+63+61 = 250 字节，加 4 个长度字节 + 1 终止 = 255）
    let max_length_name = Name::new(vec![
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec(),
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec(),
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec(),
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec(),
    ])
    .expect("max length name should be valid");

    let query_limit = u16::try_from(limit).unwrap_or(u16::MAX);
    let query = super::dns::Message {
        id: 0,
        flags: 0,
        question: vec![Question {
            name: max_length_name,
            qtype: rr_type,
            qclass: super::dns::CLASS_IN,
        }],
        answer: vec![],
        authority: vec![],
        additional: vec![RR {
            name: Name::default(),
            rtype: super::dns::RR_TYPE_OPT,
            rclass: query_limit,
            ttl: 0,
            data: vec![],
        }],
    };

    let resp = super::server::response_for(
        &query,
        &[DomainSpec {
            name: Name { labels: vec![vec![]] },
            rr_type: 0,
        }],
    );
    let mut resp = match resp {
        Some(r) => r,
        None => return 0,
    };

    let mut low = 0usize;
    let mut high = if payload_chunk_size_for_type(rr_type) > 0 {
        256 * payload_chunk_size_for_type(rr_type) + 1
    } else {
        32768
    };

    while low + 1 < high {
        let mid = (low + high) / 2;
        resp.answer = match answers_for_payload(&query.question[0], RESPONSE_TTL, &vec![0u8; mid]) {
            Ok(a) => a,
            Err(_) => {
                high = mid;
                continue;
            }
        };
        let buf = match resp.wire_format() {
            Ok(b) => b,
            Err(_) => {
                high = mid;
                continue;
            }
        };
        if buf.len() <= limit {
            low = mid;
        } else {
            high = mid;
        }
    }
    low
}

fn invalid_data(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(txt: u16) -> Question {
        Question {
            name: Name::parse("t.example.com").unwrap(),
            qtype: txt,
            qclass: super::super::dns::CLASS_IN,
        }
    }

    #[test]
    fn txt_answers_roundtrip() {
        let payload = b"hello world payload";
        let answers = answers_for_payload(&q(RR_TYPE_TXT), RESPONSE_TTL, payload).unwrap();
        assert_eq!(answers.len(), 1);
        let decoded = decode_response_payload(&answers).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn empty_payload_txt_one_record() {
        let answers = answers_for_payload(&q(RR_TYPE_TXT), RESPONSE_TTL, &[]).unwrap();
        assert_eq!(answers.len(), 1);
        let decoded = decode_response_payload(&answers).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn ip_chunk_size_correct() {
        // A: 4 - 2 = 2
        assert_eq!(payload_chunk_size_for_type(RR_TYPE_A), 2);
        // AAAA: 16 - 2 = 14
        assert_eq!(payload_chunk_size_for_type(RR_TYPE_AAAA), 14);
        // TXT: 0
        assert_eq!(payload_chunk_size_for_type(RR_TYPE_TXT), 0);
    }

    #[test]
    fn a_record_roundtrip_small_payload() {
        // 5 字节 payload → 需要 3 条 A 记录（chunks of 2 = 3 chunks: 2+2+1）
        let payload = b"hello";
        let answers = answers_for_payload(&q(RR_TYPE_A), RESPONSE_TTL, payload).unwrap();
        assert_eq!(answers.len(), 3);
        let decoded = decode_response_payload(&answers).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn aaaa_record_roundtrip_large_payload() {
        // 30 字节 payload → AAAA chunk=14 → 3 chunks (14+14+2)
        let payload: Vec<u8> = (0..30).collect();
        let answers = answers_for_payload(&q(RR_TYPE_AAAA), RESPONSE_TTL, &payload).unwrap();
        assert_eq!(answers.len(), 3);
        let decoded = decode_response_payload(&answers).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn empty_payload_a_one_record() {
        // 空 payload → 1 条记录（idx=0 n=0）
        let answers = answers_for_payload(&q(RR_TYPE_A), RESPONSE_TTL, &[]).unwrap();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].data, vec![0, 0, 0, 0]);
        let decoded = decode_response_payload(&answers).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn txt_payload_too_large_one_record_ok() {
        // TXT 类型下，即使 payload > 255 也不会触发 answersForPayload 报错
        // （Go 的 EncodeRDataTXT 不检查上限，由上层 caller 控）
        let big: Vec<u8> = (0..300).map(|i| (i & 0xff) as u8).collect();
        let answers = answers_for_payload(&q(RR_TYPE_TXT), RESPONSE_TTL, &big).unwrap();
        assert_eq!(answers.len(), 1);
        let decoded = decode_response_payload(&answers).unwrap();
        assert_eq!(decoded, big);
    }

    #[test]
    fn unsupported_rr_type_errors() {
        // 不支持的 qtype（如 CNAME=5）应报错
        let result = answers_for_payload(&q(5), RESPONSE_TTL, b"x");
        assert!(result.is_err());
    }
}

//! Geo data loader
//!
//! 对应 Go 版本 `common/geodata/geodat_loader`，提供 GeoIP/GeoSite
//! dat 文件的流式查找和加载功能。

use std::io::{self, Read, Seek, SeekFrom};

use crate::pb::{Domain, GeoIp, GeoSite};

// ── 错误类型 ────────────────────────────────────────────────────

/// GeoData 加载错误类型。
#[derive(Debug, thiserror::Error)]
pub enum LoaderError {
    /// IO 错误
    #[error("IO 错误: {0}")]
    Io(#[from] io::Error),

    /// 未找到指定代码的条目
    #[error("未找到代码: {code}")]
    NotFound {
        code: String,
    },

    /// Protobuf 解码错误
    #[error("protobuf 解码错误: {0}")]
    Decode(#[from] prost::DecodeError),

    /// Varint 溢出
    #[error("varint 溢出")]
    VarintOverflow,
}

// ── Varint 解码 ─────────────────────────────────────────────────

/// 从读取器解码 protobuf varint。
///
/// 对应 Go 版本 `decodeVarint`，读取变长整数，
/// 当移位超过 64 位时返回溢出错误。
fn decode_varint<R: Read>(reader: &mut R) -> Result<u64, LoaderError> {
    let mut x: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        let b = buf[0];
        if shift >= 64 {
            return Err(LoaderError::VarintOverflow);
        }
        x |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if (b & 0x80) == 0 {
            return Ok(x);
        }
    }
}

// ── find() 流式查找 ─────────────────────────────────────────────

/// 在 dat 文件中流式查找指定代码的条目。
///
/// 对应 Go 版本 `find()` 函数，逐条扫描 protobuf 编码的 dat 文件，
/// 匹配目标 code 后返回条目的 protobuf 字节。
///
/// # 参数
///
/// - `reader` - 支持 Seek 的读取器（dat 文件）
/// - `code` - 目标国家/地区代码
/// - `read_body` - 是否读取条目体（false 时仅验证存在性）
///
/// # 返回
///
/// - `read_body=true` 时返回条目的 protobuf 字节
/// - `read_body=false` 时返回空 Vec（仅验证存在性）
/// - 未找到时返回 `NotFound` 错误
pub fn find<R: Read + Seek>(
    reader: &mut R,
    code: &str,
    read_body: bool,
) -> Result<Vec<u8>, LoaderError> {
    let code_bytes = code.as_bytes();
    let code_len = code_bytes.len();

    // 前缀长度：1 byte tag + 1 byte code_len + code_bytes
    let prefix_len = 2 + code_len;

    loop {
        // 读取 tag byte
        let mut tag_buf = [0u8; 1];
        match reader.read_exact(&mut tag_buf) {
            Ok(()) => {}
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(LoaderError::NotFound {
                    code: code.to_string(),
                });
            }
            Err(e) => return Err(LoaderError::Io(e)),
        }

        // 解码 body 长度
        let body_len = decode_varint(reader)? as usize;

        if body_len < prefix_len {
            // body 太短，跳过
            let skip = body_len as u64;
            reader.seek(SeekFrom::Current(skip as i64))?;
            continue;
        }

        // 读取前缀部分
        let mut prefix = vec![0u8; prefix_len];
        reader.read_exact(&mut prefix)?;

        // 检查前缀是否匹配
        // prefix[0] 是 code 字段的 tag byte
        // prefix[1] 是 code 字符串的长度
        // prefix[2..] 是 code 字符串内容
        let matched = prefix.len() > 1
            && prefix[1] as usize == code_len
            && prefix[2..] == code_bytes[..];

        let remain_len = body_len - prefix_len;

        if matched {
            if read_body {
                // 返回完整的 body 字节（prefix + remain）
                // prost::Message::decode 期望 body 内容，不含外层 tag+varint
                let mut body = Vec::with_capacity(body_len);
                body.extend_from_slice(&prefix);
                if remain_len > 0 {
                    let mut remain = vec![0u8; remain_len];
                    reader.read_exact(&mut remain)?;
                    body.extend_from_slice(&remain);
                }
                return Ok(body);
            } else {
                // 仅验证存在性，跳过剩余
                if remain_len > 0 {
                    reader.seek(SeekFrom::Current(remain_len as i64))?;
                }
                return Ok(Vec::new());
            }
        } else {
            // 不匹配，跳过剩余
            if remain_len > 0 {
                reader.seek(SeekFrom::Current(remain_len as i64))?;
            }
        }
    }
}

/// 编码 varint 到缓冲区。
#[allow(dead_code)]
fn encode_varint(value: u64, buf: &mut Vec<u8>) {
    let mut v = value;
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        buf.push(b);
        if v == 0 {
            break;
        }
    }
}

// ── GeoDataLoader ───────────────────────────────────────────────

/// GeoData 文件加载器。
///
/// 对应 Go 版本的 `checkFile/loadFile/loadIP/loadSite` 系列函数，
/// 从指定目录加载 GeoIP/GeoSite dat 文件。
pub struct GeoDataLoader {
    datadir: std::path::PathBuf,
}

impl GeoDataLoader {
    /// 创建新的加载器，指定 dat 文件目录。
    pub fn new(datadir: std::path::PathBuf) -> Self {
        Self { datadir }
    }

    /// 检查 dat 文件中是否存在指定代码的条目。
    ///
    /// 对应 Go 版本 `checkFile`。
    pub fn check_file(
        &self,
        filename: &str,
        code: &str,
    ) -> Result<(), LoaderError> {
        let path = self.datadir.join(filename);
        let mut file = std::fs::File::open(&path)?;
        find(&mut file, code, false)?;
        Ok(())
    }

    /// 加载 dat 文件中指定代码的条目原始字节。
    ///
    /// 对应 Go 版本 `loadFile`。
    pub fn load_file(
        &self,
        filename: &str,
        code: &str,
    ) -> Result<Vec<u8>, LoaderError> {
        let path = self.datadir.join(filename);
        let mut file = std::fs::File::open(&path)?;
        find(&mut file, code, true)
    }

    /// 加载 GeoIP 条目。
    ///
    /// 对应 Go 版本 `loadIP`，从 dat 文件中查找并解码 GeoIP。
    pub fn load_ip(
        &self,
        filename: &str,
        code: &str,
    ) -> Result<GeoIp, LoaderError> {
        let bytes = self.load_file(filename, code)?;
        let geo_ip = prost::Message::decode(bytes.as_slice())?;
        Ok(geo_ip)
    }

    /// 加载 GeoSite 条目。
    ///
    /// 对应 Go 版本 `loadSite`，从 dat 文件中查找并解码 GeoSite。
    pub fn load_site(
        &self,
        filename: &str,
        code: &str,
    ) -> Result<GeoSite, LoaderError> {
        let bytes = self.load_file(filename, code)?;
        let geo_site = prost::Message::decode(bytes.as_slice())?;
        Ok(geo_site)
    }

    /// 加载带属性过滤的 GeoSite 条目。
    ///
    /// 对应 Go 版本 `loadSiteWithAttrs`，加载 GeoSite 后
    /// 使用属性匹配器过滤域名。
    pub fn load_site_with_attrs(
        &self,
        filename: &str,
        code: &str,
        attrs: &str,
    ) -> Result<GeoSite, LoaderError> {
        let mut geo_site = self.load_site(filename, code)?;
        if attrs.is_empty() {
            return Ok(geo_site);
        }
        let matcher = AllAttrsMatcher::new(attrs);
        geo_site.domain.retain(|d| matcher.match_domain(d));
        Ok(geo_site)
    }
}

// ── AttributeMatcher ────────────────────────────────────────────

/// 属性匹配器 trait。
///
/// 对应 Go 版本 `AttributeMatcher`，检查 Domain 的属性是否匹配。
pub trait AttributeMatcher: Send + Sync {
    /// 判断 Domain 是否满足属性匹配条件。
    #[must_use]
    fn match_domain(&self, domain: &Domain) -> bool;
}

/// 单属性匹配器。
///
/// 对应 Go 版本 `HasAttrMatcher`，检查 Domain 的 Attribute 列表中
/// 是否存在指定 key 的属性。
pub struct HasAttrMatcher {
    key: String,
}

impl HasAttrMatcher {
    /// 创建新的单属性匹配器。
    pub fn new(key: &str) -> Self {
        Self { key: key.to_string() }
    }
}

impl AttributeMatcher for HasAttrMatcher {
    fn match_domain(&self, domain: &Domain) -> bool {
        domain.attribute.iter().any(|attr| attr.key == self.key)
    }
}

/// 全属性匹配器。
///
/// 对应 Go 版本 `AllAttrsMatcher`，要求 Domain 满足所有指定属性。
/// attrs 字符串以 "@" 分隔各属性 key。
pub struct AllAttrsMatcher {
    matchers: Vec<HasAttrMatcher>,
}

impl AllAttrsMatcher {
    /// 从 "@" 分隔的属性字符串创建全属性匹配器。
    ///
    /// 对应 Go 版本 `NewAllAttrsMatcher`。
    pub fn new(attrs: &str) -> Self {
        let matchers = attrs
            .split('@')
            .filter(|s| !s.is_empty())
            .map(|s| HasAttrMatcher::new(s))
            .collect();
        Self { matchers }
    }
}

impl AttributeMatcher for AllAttrsMatcher {
    fn match_domain(&self, domain: &Domain) -> bool {
        self.matchers.iter().all(|m| m.match_domain(domain))
    }
}

// ── 辅助函数 ────────────────────────────────────────────────────

/// 从内存中的 protobuf 字节查找并解码 GeoIP。
///
/// 不需要文件系统，直接在内存中操作。
pub fn find_geo_ip(
    data: &[u8],
    code: &str,
) -> Result<GeoIp, LoaderError> {
    let mut cursor = io::Cursor::new(data);
    let bytes = find(&mut cursor, code, true)?;
    let geo_ip = prost::Message::decode(bytes.as_slice())?;
    Ok(geo_ip)
}

/// 从内存中的 protobuf 字节查找并解码 GeoSite。
pub fn find_geo_site(
    data: &[u8],
    code: &str,
) -> Result<GeoSite, LoaderError> {
    let mut cursor = io::Cursor::new(data);
    let bytes = find(&mut cursor, code, true)?;
    let geo_site = prost::Message::decode(bytes.as_slice())?;
    Ok(geo_site)
}

/// 从内存中的 protobuf 字节检查代码是否存在。
pub fn check_code(data: &[u8], code: &str) -> Result<bool, LoaderError> {
    let mut cursor = io::Cursor::new(data);
    match find(&mut cursor, code, false) {
        Ok(_) => Ok(true),
        Err(LoaderError::NotFound { .. }) => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geosite::DomainAttribute;
    use crate::pb::{Cidr, GeoIpList, GeoSiteList};

    // ── varint 编解码测试 ────────────────────────────────────

    #[test]
    fn decode_varint_single_byte() {
        let data = [0x01];
        let mut cursor = io::Cursor::new(&data[..]);
        let val = decode_varint(&mut cursor).unwrap();
        assert_eq!(val, 1);
    }

    #[test]
    fn decode_varint_multi_byte() {
        // 150 = 0x96 = 10010110
        // 编码为: 10010110 00000001 = 0x96 0x01
        let data = [0x96, 0x01];
        let mut cursor = io::Cursor::new(&data[..]);
        let val = decode_varint(&mut cursor).unwrap();
        assert_eq!(val, 150);
    }

    #[test]
    fn decode_varint_max_u64() {
        // u64::MAX = 0xFFFFFFFFFFFFFFFF
        // 编码: 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0x01
        let data = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        let mut cursor = io::Cursor::new(&data[..]);
        let val = decode_varint(&mut cursor).unwrap();
        assert_eq!(val, u64::MAX);
    }

    // ── find() 测试 ─────────────────────────────────────────

    #[test]
    fn find_geo_ip_in_list() {
        let geo_ip = GeoIp::new("CN")
            .with_cidr(Cidr::new(vec![10, 0, 0, 0], 8))
            .with_cidr(Cidr::new(vec![192, 168, 0, 0], 16));
        let list = GeoIpList::new()
            .with_entry(geo_ip)
            .with_entry(GeoIp::new("US")
                .with_cidr(Cidr::new(vec![172, 16, 0, 0], 12)));

        let data = prost::Message::encode_to_vec(&list);
        let result = find_geo_ip(&data, "CN").unwrap();
        assert_eq!(result.code, "CN");
        assert_eq!(result.cidr.len(), 2);
    }

    #[test]
    fn find_geo_site_in_list() {
        let geo_site = GeoSite::new("CN")
            .with_domain(Domain::full("baidu.com"))
            .with_domain(Domain::domain("qq"));
        let list = GeoSiteList::new()
            .with_entry(geo_site)
            .with_entry(GeoSite::new("US")
                .with_domain(Domain::full("google.com")));

        let data = prost::Message::encode_to_vec(&list);
        let result = find_geo_site(&data, "US").unwrap();
        assert_eq!(result.code, "US");
        assert_eq!(result.domain.len(), 1);
    }

    #[test]
    fn find_code_not_found() {
        let list = GeoIpList::new()
            .with_entry(GeoIp::new("CN"));

        let data = prost::Message::encode_to_vec(&list);
        let result = check_code(&data, "JP");
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn check_code_exists() {
        let list = GeoIpList::new()
            .with_entry(GeoIp::new("CN"));

        let data = prost::Message::encode_to_vec(&list);
        let result = check_code(&data, "CN");
        assert_eq!(result.unwrap(), true);
    }

    // ── AttributeMatcher 测试 ────────────────────────────────

    #[test]
    fn has_attr_matcher() {
        let domain = Domain::full("example.com")
            .with_attribute(DomainAttribute::bool_attr("tls", true))
            .with_attribute(DomainAttribute::int_attr("port", 443));

        let matcher = HasAttrMatcher::new("tls");
        assert!(matcher.match_domain(&domain));

        let matcher2 = HasAttrMatcher::new("http");
        assert!(!matcher2.match_domain(&domain));
    }

    #[test]
    fn all_attrs_matcher() {
        let domain = Domain::full("example.com")
            .with_attribute(DomainAttribute::bool_attr("tls", true))
            .with_attribute(DomainAttribute::int_attr("port", 443));

        // "@tls@port" - 两个属性都有
        let matcher = AllAttrsMatcher::new("@tls@port");
        assert!(matcher.match_domain(&domain));

        // "@tls@http" - 缺少 http
        let matcher2 = AllAttrsMatcher::new("@tls@http");
        assert!(!matcher2.match_domain(&domain));

        // 空字符串 - 匹配所有
        let matcher3 = AllAttrsMatcher::new("");
        assert!(matcher3.match_domain(&domain));
    }

    // ── encode_varint 测试 ───────────────────────────────────

    #[test]
    fn encode_varint_small() {
        let mut buf = Vec::new();
        encode_varint(1, &mut buf);
        assert_eq!(buf, vec![0x01]);
    }

    #[test]
    fn encode_varint_150() {
        let mut buf = Vec::new();
        encode_varint(150, &mut buf);
        assert_eq!(buf, vec![0x96, 0x01]);
    }
}

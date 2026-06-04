//! 数据大小单位类型
//!
//! 对应 Go 版本 `common/units` 包，提供字节大小的格式化和转换。

use std::fmt;
use std::str::FromStr;

const KB: u64 = 1024;
const MB: u64 = 1024 * KB;
const GB: u64 = 1024 * MB;
const TB: u64 = 1024 * GB;

/// 字节大小类型，封装 u64 字节数并提供单位转换和格式化。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteSize(pub u64);

impl ByteSize {
    /// 返回原始字节数。
    pub fn as_bytes(&self) -> u64 {
        self.0
    }

    /// 返回千字节数（向下取整）。
    pub fn as_kb(&self) -> u64 {
        self.0 / KB
    }

    /// 返回兆字节数（向下取整）。
    pub fn as_mb(&self) -> u64 {
        self.0 / MB
    }

    /// 返回吉字节数（向下取整）。
    pub fn as_gb(&self) -> u64 {
        self.0 / GB
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 >= TB {
            write!(f, "{:.1} TB", self.0 as f64 / TB as f64)
        } else if self.0 >= GB {
            write!(f, "{:.1} GB", self.0 as f64 / GB as f64)
        } else if self.0 >= MB {
            write!(f, "{:.1} MB", self.0 as f64 / MB as f64)
        } else if self.0 >= KB {
            write!(f, "{:.1} KB", self.0 as f64 / KB as f64)
        } else {
            write!(f, "{} B", self.0)
        }
    }
}

impl fmt::Debug for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// 字节大小解析错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseByteSizeError(String);

impl std::fmt::Display for ParseByteSizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid byte size: {}", self.0)
    }
}

impl std::error::Error for ParseByteSizeError {}

impl FromStr for ByteSize {
    type Err = ParseByteSizeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Err(ParseByteSizeError("empty string".to_string()));
        }

        // 分离数字和单位后缀
        let num_end = s
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(s.len());
        let num_str = &s[..num_end];
        let unit_str = s[num_end..].trim().to_uppercase();

        let value: f64 = num_str
            .parse()
            .map_err(|_| ParseByteSizeError(format!("invalid number: {num_str}")))?;

        let bytes = match unit_str.as_str() {
            "" | "B" => value,
            "KB" | "K" => value * KB as f64,
            "MB" | "M" => value * MB as f64,
            "GB" | "G" => value * GB as f64,
            "TB" | "T" => value * TB as f64,
            _ => return Err(ParseByteSizeError(format!("unknown unit: {unit_str}"))),
        };

        Ok(ByteSize(bytes as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_as_bytes() {
        let size = ByteSize(2048);
        assert_eq!(size.as_bytes(), 2048);
    }

    #[test]
    fn test_as_kb() {
        assert_eq!(ByteSize(2048).as_kb(), 2);
        assert_eq!(ByteSize(1023).as_kb(), 0);
    }

    #[test]
    fn test_as_mb() {
        assert_eq!(ByteSize(2 * 1024 * 1024).as_mb(), 2);
        assert_eq!(ByteSize(1024 * 1024 - 1).as_mb(), 0);
    }

    #[test]
    fn test_as_gb() {
        assert_eq!(ByteSize(3 * 1024 * 1024 * 1024).as_gb(), 3);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", ByteSize(500)), "500 B");
        assert_eq!(format!("{}", ByteSize(1024)), "1.0 KB");
        assert_eq!(format!("{}", ByteSize(1536)), "1.5 KB");
        assert_eq!(format!("{}", ByteSize(1024 * 1024)), "1.0 MB");
        assert_eq!(format!("{}", ByteSize(1024 * 1024 * 1024)), "1.0 GB");
        assert_eq!(format!("{}", ByteSize(1024 * 1024 * 1024 * 1024)), "1.0 TB");
    }

    #[test]
    fn test_debug_same_as_display() {
        assert_eq!(format!("{:?}", ByteSize(1024)), format!("{}", ByteSize(1024)));
    }

    #[test]
    fn test_from_str() {
        assert_eq!("1024".parse::<ByteSize>().expect("parse"), ByteSize(1024));
        assert_eq!("1KB".parse::<ByteSize>().expect("parse"), ByteSize(1024));
        assert_eq!("2MB".parse::<ByteSize>().expect("parse"), ByteSize(2 * 1024 * 1024));
        assert_eq!("1GB".parse::<ByteSize>().expect("parse"), ByteSize(1024 * 1024 * 1024));
        assert_eq!("1.5KB".parse::<ByteSize>().expect("parse"), ByteSize(1536));
    }

    #[test]
    fn test_from_str_case_insensitive() {
        assert_eq!("1kb".parse::<ByteSize>().expect("parse"), ByteSize(1024));
        assert_eq!("2mb".parse::<ByteSize>().expect("parse"), ByteSize(2 * 1024 * 1024));
    }

    #[test]
    fn test_from_str_errors() {
        assert!("".parse::<ByteSize>().is_err());
        assert!("abc".parse::<ByteSize>().is_err());
        assert!("1XB".parse::<ByteSize>().is_err());
    }

    #[test]
    fn test_ordering() {
        assert!(ByteSize(100) < ByteSize(200));
        assert!(ByteSize(1024) > ByteSize(512));
    }
}

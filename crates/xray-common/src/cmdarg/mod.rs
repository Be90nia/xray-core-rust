//! 命令行参数类型
//!
//! 对应 Go 版本 `common/cmdarg` 包，提供命令行参数的封装。

/// 命令行参数封装。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Arg(Vec<String>);

impl Arg {
    /// 创建新的参数列表。
    pub fn new(args: Vec<String>) -> Self {
        Self(args)
    }

    /// 返回参数字符串切片。
    pub fn strings(&self) -> &[String] {
        &self.0
    }

    /// 设置新的参数列表。
    pub fn set(&mut self, args: Vec<String>) {
        self.0 = args;
    }
}

impl std::fmt::Display for Arg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let arg = Arg::new(vec!["hello".to_string(), "world".to_string()]);
        assert_eq!(arg.strings(), &["hello", "world"]);
    }

    #[test]
    fn test_default() {
        let arg = Arg::default();
        assert!(arg.strings().is_empty());
    }

    #[test]
    fn test_set() {
        let mut arg = Arg::new(vec!["a".to_string()]);
        arg.set(vec!["b".to_string(), "c".to_string()]);
        assert_eq!(arg.strings(), &["b", "c"]);
    }

    #[test]
    fn test_display() {
        let arg = Arg::new(vec!["run".to_string(), "--flag".to_string(), "value".to_string()]);
        assert_eq!(format!("{arg}"), "run --flag value");
    }

    #[test]
    fn test_display_empty() {
        let arg = Arg::default();
        assert_eq!(format!("{arg}"), "");
    }
}

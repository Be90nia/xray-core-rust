//! 字符串匹配器基础接口与实现
//!
//! 对应 Go 版本 `common/geodata/strmatcher` 包，提供字符串匹配的
//! 核心接口与4种基础匹配器。
//!
//! # 接口层级
//!
//! - [`Matcher`] - 基础匹配器：判断字符串是否匹配模式
//! - [`MatcherGroup`] - 匹配器组：批量匹配，返回匹配的规则ID列表
//! - [`MatcherSet`] - 匹配器集合：存在性检查
//!
//! # 匹配器类型
//!
//! - [`FullMatcher`] - 精确全匹配
//! - [`DomainMatcher`] - 域名后缀匹配
//! - [`SubstrMatcher`] - 子串包含匹配
//! - [`RegexMatcher`] - 正则表达式匹配

pub mod matchers;
pub mod matcher_groups;

pub use matchers::{
    DomainMatcher, FullMatcher, RegexMatcher, SubstrMatcher,
};

pub use matcher_groups::{
    ACMatcherGroup, ACMatcherGroupError, DomainMatcherGroup,
    FullMatcherGroup, MPHMatcherGroup, MPHMatcherGroupError,
    SimpleMatcherGroup, SubstrMatcherGroup,
};

/// 匹配器类型枚举。
///
/// 对应 Go 版本 `strmatcher.Type`，表示匹配器的语义类型。
/// 优先级顺序：Full > Domain > Substr > Regex。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MatcherType {
    /// 精确全匹配：输入字符串必须与模式完全相等
    Full = 0,
    /// 域名后缀匹配：输入字符串必须是模式的子域名或自身
    Domain = 1,
    /// 子串包含匹配：输入字符串必须包含模式作为子串
    Substr = 2,
    /// 正则表达式匹配：输入字符串必须匹配正则表达式
    Regex = 3,
}

impl MatcherType {
    /// 根据模式创建对应的匹配器。
    ///
    /// # 错误
    ///
    /// - 正则表达式编译失败时返回错误
    /// - 未知匹配器类型时返回错误
    pub fn new_matcher(
        self,
        pattern: &str,
    ) -> Result<Box<dyn Matcher>, MatcherError> {
        match self {
            MatcherType::Full => {
                Ok(Box::new(FullMatcher::new(pattern)))
            }
            MatcherType::Domain => {
                Ok(Box::new(DomainMatcher::new(pattern)))
            }
            MatcherType::Substr => {
                Ok(Box::new(SubstrMatcher::new(pattern)))
            }
            MatcherType::Regex => {
                let matcher = RegexMatcher::new(pattern)?;
                Ok(Box::new(matcher))
            }
        }
    }
}

impl std::fmt::Display for MatcherType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MatcherType::Full => write!(f, "full"),
            MatcherType::Domain => write!(f, "domain"),
            MatcherType::Substr => write!(f, "keyword"),
            MatcherType::Regex => write!(f, "regexp"),
        }
    }
}

/// 匹配器错误类型。
#[derive(Debug, thiserror::Error)]
pub enum MatcherError {
    /// 正则表达式编译失败
    #[error("正则表达式编译失败: {0}")]
    RegexCompile(#[from] regex::Error),

    /// 未知的匹配器类型
    #[error("未知的匹配器类型")]
    UnknownMatcherType,
}

/// 基础匹配器 trait。
///
/// 对应 Go 版本 `strmatcher.Matcher`，表示一个具体的匹配语义
/// （全匹配、域名匹配、子串匹配或正则匹配）。
///
/// # 性能说明
///
/// 单个 Matcher 的 `match_str` 方法通常不直接用于高性能场景，
/// 实际使用中由对应的 `MatcherGroup` 接管以获得更好的性能。
pub trait Matcher: Send + Sync {
    /// 返回匹配器类型。
    fn matcher_type(&self) -> MatcherType;

    /// 返回匹配器的原始模式字符串。
    fn pattern(&self) -> &str;

    /// 判断输入字符串是否匹配预设模式。
    #[must_use]
    fn match_str(&self, input: &str) -> bool;
}

/// 为所有实现 `Matcher` 的类型提供默认的 `Display` 实现。
impl std::fmt::Display for dyn Matcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.matcher_type(), self.pattern())
    }
}

/// 匹配器组 trait。
///
/// 对应 Go 版本 `strmatcher.MatcherGroup`，接受一批特定类型的
/// 基础匹配器，并使用优化的数据结构加速查找。
///
/// 例如：
/// - `FullMatcherGroup` 使用哈希表加速查找
/// - `DomainMatcherGroup` 使用字典树优化内存和查找速度
pub trait MatcherGroup: Send + Sync {
    /// 返回所有匹配的规则ID列表。
    ///
    /// 对应 Go 版本 `MatcherGroup.Match`，返回空列表表示无匹配。
    #[must_use]
    fn match_str(&self, input: &str) -> Vec<u16>;

    /// 只要有一个匹配器匹配就返回 `true`。
    #[must_use]
    fn match_any(&self, input: &str) -> bool;
}

/// 匹配器集合 trait。
///
/// 对应 Go 版本 `strmatcher.MatcherSet`，仅提供存在性检查。
pub trait MatcherSet: Send + Sync {
    /// 只要有一个匹配器匹配就返回 `true`。
    #[must_use]
    fn match_any(&self, input: &str) -> bool;
}

pub mod domain;
pub mod ip;
pub mod attributes;

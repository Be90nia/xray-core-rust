//! 域名匹配器
//!
//! 对应 Go 版本 `common/geodata/domain_matcher` 和 `domain_registry`，
//! 提供基于规则的域名匹配能力。
//!
//! # 核心类型
//!
//! - [`DomainType`] - 域名规则类型（Full/Domain/Substr/Regex）
//! - [`DomainRule`] - 域名规则（类型 + 值 + 规则ID）
//! - [`DomainMatcher`] - 域名匹配器 trait
//! - [`MphDomainMatcher`] - 基于 MPH 的高性能域名匹配器
//! - [`CompactDomainMatcher`] - 组合匹配器（custom + geosite）
//!
//! # 工厂模式
//!
//! - [`DomainMatcherFactory`] - 域名匹配器工厂 trait
use std::sync::{Arc, Mutex};

use super::{
    DomainMatcher as DomainMatcherImpl, FullMatcher, Matcher, MatcherError, MatcherGroup,
    MatcherSet, MatcherType,
    matcher_groups::{MPHMatcherGroup, SimpleMatcherGroup},
};
use crate::weak_cache::WeakCacheMap;

/// 域名规则类型。
///
/// 区别于 protobuf 的 `DomainType`，这是匹配器层面的类型枚举，
/// 直接对应 Go 版本 `Domain.Type` 枚举值。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DomainType {
    /// 精确全匹配
    Full = 0,
    /// 域名后缀匹配
    Domain = 1,
    /// 子串包含匹配
    Substr = 2,
    /// 正则表达式匹配
    Regex = 3,
}

impl DomainType {
    /// 从 i32 值转换为 DomainType。
    ///
    /// 对应 protobuf `Domain.Type` 的整数值。
    /// 未知值返回 `None`。
    #[must_use]
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Full),
            1 => Some(Self::Domain),
            2 => Some(Self::Substr),
            3 => Some(Self::Regex),
            _ => None,
        }
    }

    /// 转换为基础匹配器类型。
    #[must_use]
    pub fn to_matcher_type(self) -> MatcherType {
        match self {
            Self::Full => MatcherType::Full,
            Self::Domain => MatcherType::Domain,
            Self::Substr => MatcherType::Substr,
            Self::Regex => MatcherType::Regex,
        }
    }
}

impl std::fmt::Display for DomainType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => write!(f, "full"),
            Self::Domain => write!(f, "domain"),
            Self::Substr => write!(f, "substr"),
            Self::Regex => write!(f, "regex"),
        }
    }
}

// ===== DomainRule =====

/// 域名规则。
///
/// 对应 Go 版本 `DomainRule`，包含匹配模式和规则ID。
/// 规则ID 用于标识匹配结果对应哪条规则。
#[derive(Debug, Clone)]
pub struct DomainRule {
    /// 域名类型
    pub domain_type: DomainType,
    /// 匹配值
    pub value: String,
    /// 规则ID（用户指定）
    pub rule_id: u32,
}

impl DomainRule {
    /// 创建新的域名规则。
    #[must_use]
    pub fn new(domain_type: DomainType, value: impl Into<String>, rule_id: u32) -> Self {
        Self { domain_type, value: value.into(), rule_id }
    }

    /// 创建精确全匹配规则。
    #[must_use]
    pub fn full(value: impl Into<String>, rule_id: u32) -> Self {
        Self::new(DomainType::Full, value, rule_id)
    }

    /// 创建域名后缀匹配规则。
    #[must_use]
    pub fn domain(value: impl Into<String>, rule_id: u32) -> Self {
        Self::new(DomainType::Domain, value, rule_id)
    }

    /// 创建子串包含匹配规则。
    #[must_use]
    pub fn substr(value: impl Into<String>, rule_id: u32) -> Self {
        Self::new(DomainType::Substr, value, rule_id)
    }

    /// 创建正则表达式匹配规则。
    #[must_use]
    pub fn regex(value: impl Into<String>, rule_id: u32) -> Self {
        Self::new(DomainType::Regex, value, rule_id)
    }
}

impl std::fmt::Display for DomainRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.domain_type, self.value)
    }
}

// ===== parse_domain =====

/// 根据域名规则创建对应的基础 Matcher。
///
/// 对应 Go 版本 `parseDomain`，根据 `DomainRule.domain_type` 创建
/// 对应类型的匹配器。
///
/// - `Full` / `Domain` / `Substr`: 值转为小写
/// - `Regex`: 原样使用
///
/// # 错误
///
/// - 正则表达式编译失败时返回 `MatcherError::RegexCompile`
pub fn parse_domain(rule: &DomainRule) -> Result<Box<dyn Matcher>, MatcherError> {
    match rule.domain_type {
        DomainType::Full => Ok(Box::new(FullMatcher::new(rule.value.to_lowercase()))),
        DomainType::Domain => Ok(Box::new(DomainMatcherImpl::new(rule.value.to_lowercase()))),
        DomainType::Substr => Ok(Box::new(super::SubstrMatcher::new(rule.value.to_lowercase()))),
        DomainType::Regex => {
            let matcher = super::RegexMatcher::new(&rule.value)?;
            Ok(Box::new(matcher))
        },
    }
}

// ===== DomainMatcher trait =====

/// 域名匹配器 trait。
///
/// 对应 Go 版本 `DomainMatcher`，提供域名匹配的核心接口。
/// 返回匹配的规则ID列表（u32）。
pub trait DomainMatcher: Send + Sync {
    /// 返回所有匹配的规则ID列表。
    #[must_use]
    fn match_domain(&self, input: &str) -> Vec<u32>;

    /// 只要有一个匹配就返回 `true`。
    #[must_use]
    fn match_any(&self, input: &str) -> bool;
}

// ===== MphDomainMatcher =====

/// 基于 MPH（最小完美哈希）的域名匹配器。
///
/// 对应 Go 版本 `MphDomainMatcher`，使用 `MPHMatcherGroup` 实现
/// Full 和 Domain 类型规则的高性能匹配。
///
/// Substr 和 Regex 类型规则由 `SimpleMatcherGroup` 处理。
///
/// # 构建
///
/// 通过 [`MphDomainMatcherFactory`] 构建实例，或直接调用 [`MphDomainMatcher::build`]。
pub struct MphDomainMatcher {
    mph: MPHMatcherGroup,
    simple: SimpleMatcherGroup,
}

impl MphDomainMatcher {
    /// 从规则列表构建 MPH 域名匹配器。
    ///
    /// Full 和 Domain 规则添加到 MPH 匹配器，
    /// Substr 和 Regex 规则添加到 Simple 匹配器。
    ///
    /// # 错误
    ///
    /// 正则表达式编译失败时返回 `MatcherError::RegexCompile`。
    pub fn build(rules: &[DomainRule]) -> Result<Self, MatcherError> {
        let mut mph = MPHMatcherGroup::new();
        let mut simple = SimpleMatcherGroup::new();

        for rule in rules {
            match rule.domain_type {
                DomainType::Full => {
                    mph.add_full_matcher(&rule.value.to_lowercase(), rule.rule_id);
                },
                DomainType::Domain => {
                    mph.add_domain_matcher(&rule.value.to_lowercase(), rule.rule_id);
                },
                DomainType::Substr => {
                    let matcher = super::SubstrMatcher::new(rule.value.to_lowercase());
                    simple.add(Box::new(matcher), rule.rule_id);
                },
                DomainType::Regex => {
                    let matcher = super::RegexMatcher::new(&rule.value)?;
                    simple.add(Box::new(matcher), rule.rule_id);
                },
            }
        }

        // MPH 构建可能失败（空规则等），忽略错误
        // 空 MPH 在 match_str/match_any 中安全返回空结果
        let _ = mph.build();

        Ok(Self { mph, simple })
    }
}

impl DomainMatcher for MphDomainMatcher {
    fn match_domain(&self, input: &str) -> Vec<u32> {
        let mut results = self.mph.match_str(input);
        results.extend(self.simple.match_str(input));
        results
    }

    fn match_any(&self, input: &str) -> bool {
        self.mph.match_any(input) || self.simple.match_any(input)
    }
}

impl std::fmt::Debug for MphDomainMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MphDomainMatcher").field("mph_built", &self.mph.is_built()).finish()
    }
}

// ===== ValueMatcher =====

/// 值匹配器 trait（返回 u32 值）。
///
/// 用于 CompactDomainMatcher 中的自定义匹配器部分。
pub trait ValueMatcher: Send + Sync {
    /// 返回所有匹配的值列表。
    #[must_use]
    fn match_str(&self, input: &str) -> Vec<u32>;
}

// ===== CompactDomainMatcher =====

/// 组合域名匹配器。
///
/// 对应 Go 版本 `CompactDomainMatcher`，组合自定义匹配器和
/// 多个 geosite 匹配器集合。
///
/// 匹配顺序：先检查 custom 匹配器，再检查各 geosite 匹配器集合。
pub struct CompactDomainMatcher {
    custom: Box<dyn ValueMatcher>,
    matchers: Vec<Box<dyn MatcherSet>>,
    values: Vec<u32>,
}

impl CompactDomainMatcher {
    /// 创建新的组合域名匹配器。
    pub fn new(
        custom: Box<dyn ValueMatcher>,
        matchers: Vec<Box<dyn MatcherSet>>,
        values: Vec<u32>,
    ) -> Self {
        Self { custom, matchers, values }
    }

    /// 返回 geosite 关联的值列表。
    #[must_use]
    pub fn values(&self) -> &[u32] {
        &self.values
    }
}

impl DomainMatcher for CompactDomainMatcher {
    fn match_domain(&self, input: &str) -> Vec<u32> {
        let mut results = self.custom.match_str(input);

        for matcher in &self.matchers {
            if matcher.match_any(input) {
                results.extend_from_slice(&self.values);
            }
        }

        results
    }

    fn match_any(&self, input: &str) -> bool {
        if !self.custom.match_str(input).is_empty() {
            return true;
        }
        self.matchers.iter().any(|m| m.match_any(input))
    }
}

impl std::fmt::Debug for CompactDomainMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompactDomainMatcher")
            .field("matcher_count", &self.matchers.len())
            .field("values", &self.values)
            .finish()
    }
}

// ===== DomainMatcherFactory =====

/// 域名匹配器工厂 trait。
///
/// 对应 Go 版本 `DomainMatcherFactory`，根据规则列表构建匹配器。
pub trait DomainMatcherFactory: Send + Sync {
    /// 构建域名匹配器。
    fn build_matcher(&self, rules: &[DomainRule]) -> Result<Box<dyn DomainMatcher>, MatcherError>;
}

// ===== MphDomainMatcherFactory =====

/// MPH 域名匹配器工厂。
///
/// 对应 Go 版本 `MphDomainMatcherFactory`，使用 `MPHMatcherGroup`
/// 构建高性能域名匹配器。
///
/// 内置 [`WeakCacheMap`] 缓存（rules key → matcher 弱引用）：
/// 内置 [`WeakCacheMap`] 缓存（rules key → matcher 弱引用）：
/// 同一份 rules 重复 `build_matcher` 时直接返回缓存的 `Arc`，
/// 避免重复构造昂贵的 trie/MPH。缓存条目在外部 Arc 全部释放后
/// 由 `WeakCacheMap::load` 自动清理（无需后台线程）。
pub struct MphDomainMatcherFactory {
    /// 共享缓存。键为 `rules` 的稳定 hash（见 [`build_domain_rules_key`]）。
    shared: WeakCacheMap<String, MphDomainMatcher>,
}

impl MphDomainMatcherFactory {
    /// 创建新的 MPH 匹配器工厂。
    #[must_use]
    pub fn new() -> Self {
        Self { shared: WeakCacheMap::new() }
    }
}

impl Default for MphDomainMatcherFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MphDomainMatcherFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MphDomainMatcherFactory").field("cached", &self.shared.len()).finish()
    }
}

impl DomainMatcherFactory for MphDomainMatcherFactory {
    fn build_matcher(&self, rules: &[DomainRule]) -> Result<Box<dyn DomainMatcher>, MatcherError> {
        let key = build_domain_rules_key(rules);
        // 先构造 matcher（可能失败），再包装成 Arc 存入缓存。
        let matcher = MphDomainMatcher::build(rules)?;
        let arc: Arc<MphDomainMatcher> = self.shared.get_or_insert_with(key, || Arc::new(matcher));
        Ok(Box::new(ArcCloneMatcher(arc)))
    }
}

// ===== CompactDomainMatcherFactory =====
/// Compact 域名匹配器工厂。
///
/// 对应 Go 版本 `CompactDomainMatcherFactory`，使用 `SimpleMatcherGroup`
/// 构建线性扫描匹配器。
///
/// 与 [`MphDomainMatcherFactory`] 同样带 [`WeakCacheMap`] 缓存：
/// 同一份 rules 重复 `build_matcher` 时返回缓存的 `Arc<CompactDomainMatcher>`，
/// 避免重复构造 trie 链。缓存条目在外部 Arc 全部释放后
/// 由 `WeakCacheMap::load` 自动清理。
pub struct CompactDomainMatcherFactory {
    shared: WeakCacheMap<String, CompactDomainMatcher>,
}

impl CompactDomainMatcherFactory {
    /// 创建新的 Compact 匹配器工厂。
    #[must_use]
    pub fn new() -> Self {
        Self { shared: WeakCacheMap::new() }
    }
}

impl Default for CompactDomainMatcherFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CompactDomainMatcherFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompactDomainMatcherFactory").field("cached", &self.shared.len()).finish()
    }
}

impl DomainMatcherFactory for CompactDomainMatcherFactory {
    fn build_matcher(&self, rules: &[DomainRule]) -> Result<Box<dyn DomainMatcher>, MatcherError> {
        let key = build_domain_rules_key(rules);
        // 闭包不能直接用 `?`（返回类型固定 Arc），先构造再插入。
        let matcher = build_compact_inner(rules)?;
        let arc: Arc<CompactDomainMatcher> =
            self.shared.get_or_insert_with(key, || Arc::new(matcher));
        Ok(Box::new(ArcCloneMatcher(arc)))
    }
}

/// 构造 `CompactDomainMatcher` 内部结构。
fn build_compact_inner(rules: &[DomainRule]) -> Result<CompactDomainMatcher, MatcherError> {
    let mut simple = SimpleMatcherGroup::new();
    for rule in rules {
        let matcher = parse_domain(rule)?;
        simple.add(matcher, rule.rule_id);
    }
    struct SimpleValueMatcher(SimpleMatcherGroup);
    impl ValueMatcher for SimpleValueMatcher {
        fn match_str(&self, input: &str) -> Vec<u32> {
            self.0.match_str(input)
        }
    }
    let custom: Box<dyn ValueMatcher> = Box::new(SimpleValueMatcher(simple));
    Ok(CompactDomainMatcher::new(custom, vec![], vec![]))
}

// ===== DynamicDomainMatcher =====

/// 动态域名匹配器。
///
/// 对应 Go 版本 `DynamicDomainMatcher`，支持运行时更新规则
pub struct DynamicDomainMatcher {
    state: std::sync::RwLock<Option<Box<dyn DomainMatcher>>>,
    rules: Mutex<Vec<DomainRule>>,
}

impl DynamicDomainMatcher {
    /// 创建新的动态域名匹配器。
    #[must_use]
    pub fn new() -> Self {
        Self { state: std::sync::RwLock::new(None), rules: Mutex::new(Vec::new()) }
    }

    /// 设置规则并重建匹配器。
    pub fn set_rules(
        &self,
        rules: Vec<DomainRule>,
        factory: &dyn DomainMatcherFactory,
    ) -> Result<(), MatcherError> {
        let matcher = factory.build_matcher(&rules)?;
        *self.rules.lock().unwrap() = rules;
        *self.state.write().unwrap() = Some(matcher);
        Ok(())
    }

    /// 更新匹配器状态。
    pub fn update(&self, matcher: Box<dyn DomainMatcher>) {
        *self.state.write().unwrap() = Some(matcher);
    }
}

impl Default for DynamicDomainMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainMatcher for DynamicDomainMatcher {
    fn match_domain(&self, input: &str) -> Vec<u32> {
        let guard = self.state.read().unwrap();
        match guard.as_ref() {
            Some(m) => m.match_domain(input),
            None => Vec::new(),
        }
    }

    fn match_any(&self, input: &str) -> bool {
        let guard = self.state.read().unwrap();
        match guard.as_ref() {
            Some(m) => m.match_any(input),
            None => false,
        }
    }
}

impl std::fmt::Debug for DynamicDomainMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let has_state = self.state.read().unwrap().is_some();
        f.debug_struct("DynamicDomainMatcher").field("has_state", &has_state).finish()
    }
}

// ===== DomainRegistry =====

/// 域名匹配器注册表。
///
/// 对应 Go 版本 `DomainRegistry`，管理多个动态域名匹配器。
pub struct DomainRegistry {
    factory: Box<dyn DomainMatcherFactory>,
    matchers: Mutex<Vec<Arc<DynamicDomainMatcher>>>,
}

impl DomainRegistry {
    /// 创建新的域名匹配器注册表。
    pub fn new(factory: Box<dyn DomainMatcherFactory>) -> Self {
        Self { factory, matchers: Mutex::new(Vec::new()) }
    }

    /// 添加规则并创建新的动态匹配器。
    ///
    /// 返回新匹配器的 Arc 引用（用于 reload 时触达同一实例）。
    pub fn add_rules(
        &self,
        rules: Vec<DomainRule>,
    ) -> Result<Arc<DynamicDomainMatcher>, MatcherError> {
        let matcher = Arc::new(DynamicDomainMatcher::new());
        matcher.set_rules(rules, self.factory.as_ref())?;
        let mut matchers = self.matchers.lock().unwrap();
        matchers.push(Arc::clone(&matcher));
        Ok(matcher)
    }

    /// 查询指定索引的匹配器。
    pub fn get_matcher(&self, idx: usize) -> Option<DomainRegistryGuard<'_>> {
        let guard = self.matchers.lock().unwrap();
        if idx < guard.len() {
            drop(guard);
            Some(DomainRegistryGuard { registry: self, index: idx })
        } else {
            None
        }
    }

    /// 返回匹配器数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.matchers.lock().unwrap().len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 用新规则重建所有匹配器（原子热切换）。
    ///
    /// 对应 Go `DomainRegistry.Reload`：每个 entry 用 new_rules 重建。
    pub fn reload_with(&self, new_rules: Vec<DomainRule>) -> Result<(), MatcherError> {
        let factory = self.factory.as_ref();
        // 拷出 matcher 引用，避免长持锁。
        let matchers: Vec<Arc<DynamicDomainMatcher>> = {
            let g = self.matchers.lock().unwrap();
            g.iter().cloned().collect()
        };

        for m in &matchers {
            m.set_rules(new_rules.clone(), factory)?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for DomainRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DomainRegistry").field("matcher_count", &self.len()).finish()
    }
}

/// 域名注册表匹配器守卫。
///
/// 提供对注册表中指定索引匹配器的访问。
pub struct DomainRegistryGuard<'a> {
    registry: &'a DomainRegistry,
    index: usize,
}

impl<'a> DomainRegistryGuard<'a> {
    /// 使用匹配器执行匹配。
    pub fn match_domain(&self, input: &str) -> Vec<u32> {
        let guard = self.registry.matchers.lock().unwrap();
        guard[self.index].match_domain(input)
    }

    /// 使用匹配器执行存在性检查。
    pub fn match_any(&self, input: &str) -> bool {
        let guard = self.registry.matchers.lock().unwrap();
        guard[self.index].match_any(input)
    }
}

/// 全局域名注册表实例。
///
/// 对应 Go `commongeodata.DomainReg`。Routing 层在 reload 时通过此处
/// 触达所有已注册的域名 matcher。如需 per-instance registry，优先本地 `new()`。
pub static DOMAIN_REG: std::sync::LazyLock<DomainRegistry> =
    std::sync::LazyLock::new(|| DomainRegistry::new(Box::new(MphDomainMatcherFactory::new())));
// ===== 工厂辅助：WeakCacheMap 缓存键 + Arc→Box 包装 =====

/// 由 [`DomainRule`] 列表派生稳定的字符串缓存键。
///
/// 对齐 Go `common/geodata/domain_matcher.go:buildDomainRulesKey`：
/// - `type:value@rule_id` 拼接（规则顺序敏感——同规则不同顺序视为不同匹配器）
/// - 空规则列表返回空字符串（调用方应视为不可缓存，跳过缓存写入）
fn build_domain_rules_key(rules: &[DomainRule]) -> String {
    if rules.is_empty() {
        return String::new();
    }
    let mut buf = String::with_capacity(rules.len() * 16);
    for r in rules {
        buf.push_str(match r.domain_type {
            DomainType::Full => "full",
            DomainType::Domain => "domain",
            DomainType::Substr => "substr",
            DomainType::Regex => "regex",
        });
        buf.push(':');
        buf.push_str(&r.value);
        buf.push('@');
        buf.push_str(&r.rule_id.to_string());
        buf.push(',');
    }
    buf
}

/// `Arc<T>` → `Box<dyn Trait>` 的零拷贝包装（通过 `Arc::clone`，仅增引用计数）。
///
/// 工厂 [`DomainMatcherFactory::build_matcher`] 要求返回 `Box<dyn DomainMatcher>`，
/// 而 [`WeakCacheMap`] 的值类型是 `Arc<MphDomainMatcher>` / `Arc<CompactDomainMatcher>`
/// （具体类型，避免 trait object 二次装箱）。`ArcCloneMatcher` 实现 `DomainMatcher`
/// trait 时内部 `Arc::clone` 出一个新 owned Arc——这与 Go `runtime.AddCleanup` 的
/// 自动清理兼容：调用方 `Box::new(ArcCloneMatcher)` 持有 Arc 副本，工厂缓存的 Arc
/// 可在本次调用返回后被释放，不影响调用方持有。
struct ArcCloneMatcher<T: DomainMatcher + Send + Sync + 'static>(Arc<T>);

impl<T: DomainMatcher + Send + Sync + 'static> DomainMatcher for ArcCloneMatcher<T> {
    fn match_domain(&self, input: &str) -> Vec<u32> {
        self.0.match_domain(input)
    }

    fn match_any(&self, input: &str) -> bool {
        self.0.match_any(input)
    }
}

// ===== 单元测试 =====
#[cfg(test)]
mod tests {
    use super::*;

    // ----- DomainType 测试 -----

    #[test]
    fn test_domain_type_from_i32() {
        assert_eq!(DomainType::from_i32(0), Some(DomainType::Full));
        assert_eq!(DomainType::from_i32(1), Some(DomainType::Domain));
        assert_eq!(DomainType::from_i32(2), Some(DomainType::Substr));
        assert_eq!(DomainType::from_i32(3), Some(DomainType::Regex));
        assert_eq!(DomainType::from_i32(4), None);
        assert_eq!(DomainType::from_i32(-1), None);
    }

    #[test]
    fn test_domain_type_to_matcher_type() {
        assert_eq!(DomainType::Full.to_matcher_type(), MatcherType::Full);
        assert_eq!(DomainType::Domain.to_matcher_type(), MatcherType::Domain);
        assert_eq!(DomainType::Substr.to_matcher_type(), MatcherType::Substr);
        assert_eq!(DomainType::Regex.to_matcher_type(), MatcherType::Regex);
    }

    #[test]
    fn test_domain_type_display() {
        assert_eq!(format!("{}", DomainType::Full), "full");
        assert_eq!(format!("{}", DomainType::Domain), "domain");
        assert_eq!(format!("{}", DomainType::Substr), "substr");
        assert_eq!(format!("{}", DomainType::Regex), "regex");
    }

    // ----- DomainRule 测试 -----

    #[test]
    fn test_domain_rule_constructors() {
        let r1 = DomainRule::full("example.com", 1);
        assert_eq!(r1.domain_type, DomainType::Full);
        assert_eq!(r1.value, "example.com");
        assert_eq!(r1.rule_id, 1);

        let r2 = DomainRule::domain("example.com", 2);
        assert_eq!(r2.domain_type, DomainType::Domain);

        let r3 = DomainRule::substr("evil", 3);
        assert_eq!(r3.domain_type, DomainType::Substr);

        let r4 = DomainRule::regex(r"evil\..*", 4);
        assert_eq!(r4.domain_type, DomainType::Regex);
    }

    #[test]
    fn test_domain_rule_display() {
        let rule = DomainRule::full("example.com", 1);
        assert_eq!(format!("{}", rule), "full:example.com");
    }

    // ----- parse_domain 测试 -----

    #[test]
    fn test_parse_domain_full() {
        let rule = DomainRule::full("Example.COM", 1);
        let matcher = parse_domain(&rule).unwrap();
        assert_eq!(matcher.matcher_type(), MatcherType::Full);
        assert!(matcher.match_str("example.com"));
        assert!(!matcher.match_str("sub.example.com"));
    }

    #[test]
    fn test_parse_domain_domain() {
        let rule = DomainRule::domain("Example.COM", 1);
        let matcher = parse_domain(&rule).unwrap();
        assert_eq!(matcher.matcher_type(), MatcherType::Domain);
        assert!(matcher.match_str("sub.example.com"));
    }

    #[test]
    fn test_parse_domain_substr() {
        let rule = DomainRule::substr("Evil", 1);
        let matcher = parse_domain(&rule).unwrap();
        assert_eq!(matcher.matcher_type(), MatcherType::Substr);
        // 值转为小写
        assert!(matcher.match_str("evil.com"));
    }

    #[test]
    fn test_parse_domain_regex() {
        let rule = DomainRule::regex(r"evil\..*", 1);
        let matcher = parse_domain(&rule).unwrap();
        assert_eq!(matcher.matcher_type(), MatcherType::Regex);
        assert!(matcher.match_str("evil.com"));
    }

    #[test]
    fn test_parse_domain_regex_invalid() {
        let rule = DomainRule::regex(r"[invalid", 1);
        assert!(parse_domain(&rule).is_err());
    }

    // ----- MphDomainMatcher 测试 -----

    #[test]
    fn test_mph_domain_matcher_full() {
        let rules = vec![DomainRule::full("example.com", 1)];
        let matcher = MphDomainMatcher::build(&rules).unwrap();
        assert_eq!(matcher.match_domain("example.com"), vec![1u32]);
        assert!(matcher.match_any("example.com"));
        assert!(!matcher.match_any("other.com"));
    }

    #[test]
    fn test_mph_domain_matcher_domain() {
        let rules = vec![DomainRule::domain("example.com", 2)];
        let matcher = MphDomainMatcher::build(&rules).unwrap();
        assert_eq!(matcher.match_domain("sub.example.com"), vec![2u32]);
        assert!(matcher.match_any("example.com"));
    }

    #[test]
    fn test_mph_domain_matcher_mixed() {
        let rules = vec![
            DomainRule::full("exact.com", 1),
            DomainRule::domain("domain.com", 2),
            DomainRule::substr("evil", 3),
        ];
        let matcher = MphDomainMatcher::build(&rules).unwrap();
        assert_eq!(matcher.match_domain("exact.com"), vec![1u32]);
        assert_eq!(matcher.match_domain("sub.domain.com"), vec![2u32]);
        assert_eq!(matcher.match_domain("evil-site.com"), vec![3u32]);
    }

    #[test]
    fn test_mph_domain_matcher_empty_rules() {
        let matcher = MphDomainMatcher::build(&[]).unwrap();
        assert!(matcher.match_domain("anything.com").is_empty());
        assert!(!matcher.match_any("anything.com"));
    }

    #[test]
    fn test_mph_domain_matcher_case_insensitive() {
        let rules = vec![DomainRule::full("Example.COM", 1)];
        let matcher = MphDomainMatcher::build(&rules).unwrap();
        assert!(matcher.match_any("example.com"));
        assert!(matcher.match_any("EXAMPLE.COM"));
    }

    // ----- CompactDomainMatcher 测试 -----

    #[test]
    fn test_compact_domain_matcher_custom_only() {
        struct TestValueMatcher;
        impl ValueMatcher for TestValueMatcher {
            fn match_str(&self, input: &str) -> Vec<u32> {
                if input == "example.com" { vec![1] } else { vec![] }
            }
        }

        let matcher = CompactDomainMatcher::new(Box::new(TestValueMatcher), vec![], vec![]);
        assert_eq!(matcher.match_domain("example.com"), vec![1u32]);
        assert!(matcher.match_any("example.com"));
        assert!(!matcher.match_any("other.com"));
    }

    #[test]
    fn test_compact_domain_matcher_with_matcher_set() {
        struct TestValueMatcher;
        impl ValueMatcher for TestValueMatcher {
            fn match_str(&self, _input: &str) -> Vec<u32> {
                vec![]
            }
        }

        struct TestMatcherSet;
        impl MatcherSet for TestMatcherSet {
            fn match_any(&self, input: &str) -> bool {
                input.contains("geosite")
            }
        }

        let matcher = CompactDomainMatcher::new(
            Box::new(TestValueMatcher),
            vec![Box::new(TestMatcherSet)],
            vec![10u32, 20u32],
        );
        assert_eq!(matcher.match_domain("geosite.com"), vec![10u32, 20u32]);
        assert!(matcher.match_any("geosite.com"));
        assert!(!matcher.match_any("other.com"));
        assert_eq!(matcher.values(), &[10u32, 20u32]);
    }

    // ----- Factory 测试 -----

    #[test]
    fn test_mph_factory_build() {
        let factory = MphDomainMatcherFactory::new();
        let rules = vec![DomainRule::full("example.com", 1), DomainRule::domain("test.org", 2)];
        let matcher = factory.build_matcher(&rules).unwrap();
        assert!(matcher.match_any("example.com"));
        assert!(matcher.match_any("sub.test.org"));
    }

    #[test]
    fn test_compact_factory_build() {
        let factory = CompactDomainMatcherFactory::new();
        let rules = vec![DomainRule::full("example.com", 1), DomainRule::domain("test.org", 2)];
        let matcher = factory.build_matcher(&rules).unwrap();
        assert!(matcher.match_any("example.com"));
        assert!(matcher.match_any("sub.test.org"));
    }

    // ----- DynamicDomainMatcher 测试 -----

    #[test]
    fn test_dynamic_matcher_initial_state() {
        let dm = DynamicDomainMatcher::new();
        assert!(!dm.match_any("anything.com"));
        assert!(dm.match_domain("anything.com").is_empty());
    }

    #[test]
    fn test_dynamic_matcher_set_rules() {
        let dm = DynamicDomainMatcher::new();
        let factory = MphDomainMatcherFactory::new();
        let rules = vec![DomainRule::full("example.com", 1)];
        dm.set_rules(rules, &factory).unwrap();
        assert!(dm.match_any("example.com"));
        assert!(!dm.match_any("other.com"));
    }

    #[test]
    fn test_dynamic_matcher_update() {
        let dm = DynamicDomainMatcher::new();
        let matcher = MphDomainMatcher::build(&[DomainRule::domain("test.org", 5)]).unwrap();
        dm.update(Box::new(matcher));
        assert!(dm.match_any("sub.test.org"));
        assert_eq!(dm.match_domain("sub.test.org"), vec![5u32]);
    }

    // ----- DomainRegistry 测试 -----

    #[test]
    fn test_domain_registry_add_and_match() {
        let registry = DomainRegistry::new(Box::new(MphDomainMatcherFactory::new()));
        let _idx = registry.add_rules(vec![DomainRule::full("example.com", 1)]).unwrap();
        assert_eq!(registry.len(), 1);

        let guard = registry.get_matcher(0).unwrap();
        assert!(guard.match_any("example.com"));
        assert!(!guard.match_any("other.com"));
    }

    #[test]
    fn test_domain_registry_multiple_matchers() {
        let registry = DomainRegistry::new(Box::new(MphDomainMatcherFactory::new()));
        registry.add_rules(vec![DomainRule::full("a.com", 1)]).unwrap();
        registry.add_rules(vec![DomainRule::domain("b.org", 2)]).unwrap();
        assert_eq!(registry.len(), 2);

        let g0 = registry.get_matcher(0).unwrap();
        assert!(g0.match_any("a.com"));

        let g1 = registry.get_matcher(1).unwrap();
        assert!(g1.match_any("sub.b.org"));
    }

    #[test]
    fn test_domain_registry_out_of_bounds() {
        let registry = DomainRegistry::new(Box::new(MphDomainMatcherFactory::new()));
        assert!(registry.get_matcher(0).is_none());
    }
}

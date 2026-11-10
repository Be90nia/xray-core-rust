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
//!
//! # ⚠️ 同名异型警告（两个 `DomainType`）
//!
//! 仓里有**两个**都叫 `DomainType` 的枚举，编号**不同序**，混用即静默错位：
//!
//! |枚举|路径|编号|
//! |---|---|---|
//! |protobuf `Domain.Type`|`xray_proto::xray::common::geodata::domain::Type`<br>`xray_geodata::pb::domain::Type`（`geosite::DomainType` 亦是它）|`Substr=0 / Regex=1 / Domain=2 / Full=3`|
//! |matcher [`DomainType`]|`xray_geodata::matcher::domain::DomainType`（本模块）|`Full=0 / Domain=1 / Substr=2 / Regex=3`|
//!
//! 规则：
//! - 读配置 / `.dat` 里的 `Domain.type`（pb 值）→ [`from_proto_type`]；写回 pb →
//!   [`to_proto_type`]。
//! - [`DomainType::from_i32`] 是**matcher 自编号**解析器，**不要**喂 pb 值。
//! - 禁在两套编号间 `as i32` 互转；pb 枚举的 `as i32`（如 `Type::Full as i32` = 3）是 pb 编号，
//!   只用于构造 pb 消息。
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, Ordering},
    },
};

use parking_lot::Mutex;
use xray_frame::HotSlot;

use super::{
    DomainMatcher as DomainMatcherImpl, FullMatcher, Matcher, MatcherError, MatcherGroup,
    MatcherSet, MatcherType,
    matcher_groups::{MPHMatcherGroup, SimpleMatcherGroup},
};
use crate::{
    loader::{GeoDataLoader, LoaderError},
    rule_parser::DEFAULT_GEOSITE_DAT,
    weak_cache::WeakCacheMap,
};

/// 域名规则类型。
///
/// 这是**匹配器层面**的类型枚举，编号 `Full=0/Domain=1/Substr=2/Regex=3`，
/// 与 protobuf `Domain.Type`（`Substr=0/Regex=1/Domain=2/Full=3`）**不同序**。
/// 从 pb 值转换一律走 [`from_proto_type`]，禁 `as i32` 互转。
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
    /// 从 **matcher 自编号** 解析：`Full=0/Domain=1/Substr=2/Regex=3`。
    ///
    /// ⚠️ 这**不是** protobuf `Domain.Type` 的编号（pb 是
    /// `Substr=0/Regex=1/Domain=2/Full=3`）。拿 pb 值调本函数会整体错位，
    /// 想解析配置里的 `Domain.Type` 请用 [`from_proto_type`]。
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

/// protobuf `Domain.Type` 编号 → matcher [`DomainType`]。
///
/// pb: `Substr=0 / Regex=1 / Domain=2 / Full=3`
/// （`protos/common/geodata/geodat.proto`）；matcher:
/// `Full=0 / Domain=1 / Substr=2 / Regex=3`——两套编号**不同序**，
/// `as i32` 互转必然错位。
///
/// 这是全仓唯一的 pb→matcher 映射来源；各 crate 的本地映射表一律转调此处。
/// 未知值返回 `None`。
#[must_use]
pub fn from_proto_type(value: i32) -> Option<DomainType> {
    match value {
        0 => Some(DomainType::Substr),
        1 => Some(DomainType::Regex),
        2 => Some(DomainType::Domain),
        3 => Some(DomainType::Full),
        _ => None,
    }
}

/// matcher [`DomainType`] → protobuf `Domain.Type` 编号（[`from_proto_type`] 的逆）。
#[must_use]
pub fn to_proto_type(t: DomainType) -> i32 {
    match t {
        DomainType::Substr => 0,
        DomainType::Regex => 1,
        DomainType::Domain => 2,
        DomainType::Full => 3,
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

/// 动态域名匹配器的当前快照。
///
/// 对应 Go `domainMatcherState`：快照整体原子换，没有部分更新。
struct DomainMatcherState {
    matcher: Box<dyn DomainMatcher>,
}

/// 动态域名匹配器。
///
/// 对应 Go `DynamicDomainMatcher`（`domain_registry.go:75-105`）：`state` 是当前
/// 快照，匹配只做一次原子读（零锁）；`rules` / `datadir` 是重建原料——
/// [`DomainRegistry::reload`] 按**每个 matcher 自己的**规则与资产目录重建。
pub struct DynamicDomainMatcher {
    /// 构建时的 pb 规则（`Geosite` 变体原样保留：展开推迟到每次重建，Go `d.rules`）。
    rules: Vec<crate::pb::DomainRule>,
    datadir: PathBuf,
    state: HotSlot<DomainMatcherState>,
    /// 控制面写互斥（Go 无显式锁：`state.Store` 原子；这里串行化快照替换）。
    sync: Mutex<()>,
}

impl DynamicDomainMatcher {
    fn new(
        rules: Vec<crate::pb::DomainRule>,
        initial: Box<dyn DomainMatcher>,
        datadir: PathBuf,
    ) -> Self {
        Self {
            rules,
            datadir,
            state: HotSlot::new(Arc::new(DomainMatcherState { matcher: initial })),
            sync: Mutex::new(()),
        }
    }

    /// 热替换内部快照（Go `DynamicDomainMatcher.Reload`）。
    fn replace(&self, fresh: Box<dyn DomainMatcher>) {
        let _guard = self.sync.lock();
        self.state.replace(Arc::new(DomainMatcherState { matcher: fresh }));
    }
}

impl DomainMatcher for DynamicDomainMatcher {
    // per-match 读走 `HotSlot::with`（一次纯原子 load、无 refcount），与 Go
    // `d.state.Load()` 同成本。
    fn match_domain(&self, input: &str) -> Vec<u32> {
        self.state.with(|s| s.matcher.match_domain(input))
    }

    fn match_any(&self, input: &str) -> bool {
        self.state.with(|s| s.matcher.match_any(input))
    }
}

impl std::fmt::Debug for DynamicDomainMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicDomainMatcher")
            .field("rules", &self.rules.len())
            .field("datadir", &self.datadir)
            .finish()
    }
}

// ===== DomainRegistry =====

/// 域名匹配器构建错误。
#[derive(Debug, thiserror::Error)]
pub enum BuildDomainMatcherError {
    /// 规则列表为空 / 展开后无可编译条目（Go `BuildMatcher` 的 `empty domain rule list`）
    #[error("empty domain rule list")]
    EmptyRules,

    /// 资产文件 / 代号加载失败（`geosite:` 代号不存在、dat 缺失）
    #[error("load geosite: {0}")]
    Loader(#[from] LoaderError),

    /// 未知 pb `Domain.Type`
    #[error("unknown domain type: {0}")]
    UnknownType(i32),

    /// 规则编译失败（正则）
    #[error("matcher: {0}")]
    Matcher(#[from] MatcherError),
}

/// 域名匹配器注册表（世代热换 + 弱表登记）。
///
/// 对应 Go `DomainRegistry`（`common/geodata/domain_registry.go:13-73`）：
/// - [`Self::build_domain_matcher`] 吃 pb `DomainRule`（含 `Geosite`），**构造期** 展开 + 编译（Go
///   `DomainReg.BuildDomainMatcher`），产物登记进弱表；
/// - [`Self::reload`] 换新世代工厂 + 逐 matcher 用**自己的**规则重建 + 原子换快照； 任一条失败 ⇒
///   整体 `Err`，不半切（Go `DomainReg.Reload`）；
/// - 消费方丢 `Arc` 即从弱表回收（无后台线程）。
pub struct DomainRegistry {
    /// 默认资产目录（[`Self::build_domain_matcher`] 用）。
    datadir: PathBuf,
    /// 当前世代工厂：`reload` 换世代 ⇒ 工厂内弱缓存失效、matcher 全量重建。
    factory: HotSlot<MphDomainMatcherFactory>,
    /// 弱引用登记簿（Go `WeakCacheMap[uuid, *DynamicDomainMatcher]`）。
    matchers: WeakCacheMap<u64, DynamicDomainMatcher>,
    /// 登记序号（单调 `u64` 代替 Go 的 `uuid.New()`）。
    next_id: AtomicU64,
    /// 登记 / 热换互斥（Go `mu`）。
    sync: Mutex<()>,
}

impl DomainRegistry {
    /// 默认资产目录 = [`xray_common::platform::get_asset_dir`]。
    #[must_use]
    pub fn new() -> Self {
        Self::with_datadir(xray_common::platform::get_asset_dir())
    }

    /// 指定 geodata 资产目录（自定义资产 / 测试注入）。
    #[must_use]
    pub fn with_datadir(datadir: PathBuf) -> Self {
        Self {
            factory: HotSlot::new(Arc::new(MphDomainMatcherFactory::new())),
            datadir,
            matchers: WeakCacheMap::new(),
            next_id: AtomicU64::new(0),
            sync: Mutex::new(()),
        }
    }

    /// 构建并登记一个动态域名匹配器（Go `DomainRegistry.BuildDomainMatcher`）。
    ///
    /// 构造期读资产 / 展开 geosite 失败 ⇒ `Err`（不登记）；消费方持 `Arc`，
    /// drop 即从弱表回收。
    pub fn build_domain_matcher(
        &self,
        rules: &[crate::pb::DomainRule],
    ) -> Result<Arc<DynamicDomainMatcher>, BuildDomainMatcherError> {
        self.build_domain_matcher_in(rules, &self.datadir)
    }

    /// 同 [`Self::build_domain_matcher`]，资产目录显式给定。
    ///
    /// 消费方自持 loader（如 router 的注入 datadir）时用；登记后 [`Self::reload`]
    /// 仍用同一目录重建。
    pub fn build_domain_matcher_in(
        &self,
        rules: &[crate::pb::DomainRule],
        datadir: &Path,
    ) -> Result<Arc<DynamicDomainMatcher>, BuildDomainMatcherError> {
        let _guard = self.sync.lock();
        let factory = self.factory.current();
        let initial = build_with_factory(&factory, rules, datadir)?;

        let matcher =
            Arc::new(DynamicDomainMatcher::new(rules.to_vec(), initial, datadir.to_path_buf()));
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.matchers.store(id, Arc::clone(&matcher));
        Ok(matcher)
    }

    /// 逐 matcher 用**自己的**规则与资产目录重建（Go `DomainRegistry.Reload`）。
    ///
    /// 失败语义：任一 matcher 重建失败 ⇒ 立即 `Err`，**不切换**任何快照与世代
    /// （Go 同：错误在切换循环之前返回）。
    pub fn reload(&self) -> Result<(), BuildDomainMatcherError> {
        let _guard = self.sync.lock();
        let registered = self.matchers.upgrade_all();

        let factory = MphDomainMatcherFactory::new();
        let mut reloaded = Vec::with_capacity(registered.len());
        for matcher in &registered {
            reloaded.push((
                Arc::clone(matcher),
                build_with_factory(&factory, &matcher.rules, &matcher.datadir)?,
            ));
        }
        for (matcher, fresh) in reloaded {
            matcher.replace(fresh);
        }
        self.factory.replace(Arc::new(factory));
        Ok(())
    }

    /// 本注册表的默认资产目录（消费方解析 `geosite:` 时须与构造 matcher 的目录一致）。
    #[must_use]
    pub fn datadir(&self) -> &Path {
        &self.datadir
    }

    /// 当前登记的 matcher 数量（含尚未清理的失效弱引用）。
    #[must_use]
    pub fn len(&self) -> usize {
        self.matchers.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for DomainRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for DomainRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DomainRegistry").field("matcher_count", &self.len()).finish()
    }
}

/// pb `DomainRule`（含 `Geosite`）→ 匹配器，经给定世代工厂编译。
///
/// 对应 Go `MphDomainMatcherFactory.BuildMatcher`（`domain_matcher.go:60-99`）：
/// - `Custom` → 编译一条，规则 ID = 该条在列表中的下标（Go `uint32(i)`）；
/// - `Geosite` → 经 dat 展开，**同一 tag 的所有域名共用该条下标**（Go 同）；
/// - `Geosite` 代号 / 文件缺失 ⇒ `Err`（Go `loadSite` err ⇒ BuildMatcher err ⇒ 拒启）；
/// - dat 内单条目类型未知或正则非法 ⇒ 跳过该条并留痕（Go `loadSiteMatchers`
///   log-and-skip：资产里的坏条目不该让整份配置拒启）。
fn build_with_factory(
    factory: &MphDomainMatcherFactory,
    rules: &[crate::pb::DomainRule],
    datadir: &Path,
) -> Result<Box<dyn DomainMatcher>, BuildDomainMatcherError> {
    use crate::pb::domain_rule::Value as PbValue;

    if rules.is_empty() {
        return Err(BuildDomainMatcherError::EmptyRules);
    }
    let loader = GeoDataLoader::new(datadir.to_path_buf());
    let mut expanded: Vec<DomainRule> = Vec::with_capacity(rules.len());
    for (i, rule) in rules.iter().enumerate() {
        let rule_id = i as u32;
        match rule.value.as_ref() {
            Some(PbValue::Custom(d)) => {
                let domain_type = from_proto_type(d.r#type)
                    .ok_or(BuildDomainMatcherError::UnknownType(d.r#type))?;
                expanded.push(DomainRule::new(domain_type, d.value.clone(), rule_id));
            },
            Some(PbValue::Geosite(g)) => {
                let file = if g.file.is_empty() { DEFAULT_GEOSITE_DAT } else { g.file.as_str() };
                // dat 内 code 全大写、attribute key 全小写；配置路径（pb 直填）未必
                // 归一（Go 只在 `ParseDomainRule` 归一），故注册表自己归一一次。
                let code = g.code.to_uppercase();
                let attrs = g.attrs.to_lowercase();
                let site = if attrs.is_empty() {
                    loader.load_site(file, &code)?
                } else {
                    loader.load_site_with_attrs(file, &code, &attrs)?
                };
                for d in &site.domain {
                    let Some(domain_type) = from_proto_type(d.r#type) else {
                        xray_common::log::warning(format!(
                            "geodata: ignore invalid geosite entry, unknown type {}, {file}:{code} value={}",
                            d.r#type, d.value
                        ));
                        continue;
                    };
                    let candidate = DomainRule::new(domain_type, d.value.clone(), rule_id);
                    // 预校验一次：正则条目编译失败即跳过该条（Go 同粒度），
                    // Custom 条目仍由 `build_matcher` 硬错。
                    if let Err(e) = parse_domain(&candidate) {
                        xray_common::log::warning(format!(
                            "geodata: ignore invalid geosite entry, {file}:{code} value={} error={e}",
                            d.value
                        ));
                        continue;
                    }
                    expanded.push(candidate);
                }
            },
            // Go 对 nil value 直接 panic；这里跳过并留痕（配置解析产物不会走到）。
            None => xray_common::log::warning(format!("geodata: domain rule #{i} has no value")),
        }
    }
    if expanded.is_empty() {
        return Err(BuildDomainMatcherError::EmptyRules);
    }
    Ok(factory.build_matcher(&expanded)?)
}

/// 全局域名注册表实例。
///
/// 对应 Go `commongeodata.DomainReg`：资产目录 = [`xray_common::platform::get_asset_dir`]，
/// 热更落盘后由 `xray-app-geodata` 的 `ReloadBothRegistries` 触发
/// [`DomainRegistry::reload`]。如需独立资产目录（测试/多实例），用
/// [`DomainRegistry::with_datadir`]。
pub static DOMAIN_REG: LazyLock<DomainRegistry> = LazyLock::new(DomainRegistry::new);
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
        // matcher 自编号（非 pb）
        assert_eq!(DomainType::from_i32(0), Some(DomainType::Full));
        assert_eq!(DomainType::from_i32(1), Some(DomainType::Domain));
        assert_eq!(DomainType::from_i32(2), Some(DomainType::Substr));
        assert_eq!(DomainType::from_i32(3), Some(DomainType::Regex));
        assert_eq!(DomainType::from_i32(4), None);
        assert_eq!(DomainType::from_i32(-1), None);
    }

    #[test]
    fn test_from_proto_type_mapping_table() {
        // pb: Substr=0/Regex=1/Domain=2/Full=3
        let table = [
            (0, DomainType::Substr),
            (1, DomainType::Regex),
            (2, DomainType::Domain),
            (3, DomainType::Full),
        ];
        for (pb, dt) in table {
            assert_eq!(from_proto_type(pb), Some(dt));
            assert_eq!(to_proto_type(dt), pb);
        }
        assert_eq!(from_proto_type(4), None);
        assert_eq!(from_proto_type(-1), None);
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
    fn test_mph_domain_matcher_lowercases_pattern_not_input() {
        let rules = vec![DomainRule::full("Example.COM", 1)];
        let matcher = MphDomainMatcher::build(&rules).unwrap();
        assert!(matcher.match_any("example.com"));
        assert!(!matcher.match_any("EXAMPLE.COM"));
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

    // ----- DomainRegistry 测试 -----

    /// 合成一条 `Custom` pb 规则。
    fn pb_custom(domain_type: crate::pb::domain::Type, value: &str) -> crate::pb::DomainRule {
        crate::pb::DomainRule {
            value: Some(crate::pb::domain_rule::Value::Custom(crate::pb::Domain::new(
                domain_type as i32,
                value,
            ))),
        }
    }

    fn temp_datadir(label: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("xray_geodata_domain_{label}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 写一份只含 `HOT` 条目的 `geosite.dat`。
    fn write_geosite_dat(dir: &Path, domains: Vec<crate::pb::Domain>) {
        use prost::Message;
        let list = crate::pb::GeoSiteList {
            entry: vec![crate::pb::GeoSite { code: "HOT".to_string(), domain: domains }],
        };
        std::fs::write(dir.join(DEFAULT_GEOSITE_DAT), list.encode_to_vec()).unwrap();
    }

    #[test]
    fn test_domain_registry_build_and_match() {
        let registry = DomainRegistry::new();
        let matcher = registry
            .build_domain_matcher(&[pb_custom(crate::pb::domain::Type::Full, "example.com")])
            .unwrap();
        assert_eq!(registry.len(), 1);
        assert!(matcher.match_any("example.com"));
        assert!(!matcher.match_any("other.com"));
        // 规则 ID = pb 列表下标（Go `uint32(i)`）
        assert_eq!(matcher.match_domain("example.com"), vec![0u32]);
    }

    #[test]
    fn test_domain_registry_missing_geosite_is_error() {
        let dir = temp_datadir("missing");
        let registry = DomainRegistry::with_datadir(dir.clone());
        let rules = [crate::pb::DomainRule {
            value: Some(crate::pb::domain_rule::Value::Geosite(crate::pb::GeoSiteRule {
                file: DEFAULT_GEOSITE_DAT.to_string(),
                code: "HOT".to_string(),
                attrs: String::new(),
            })),
        }];
        // 资产缺失 ⇒ 构造期 Err（Go `loadSite` err ⇒ 拒启），不是静默空集
        assert!(matches!(
            registry.build_domain_matcher(&rules),
            Err(BuildDomainMatcherError::Loader(_))
        ));
        // 资产在但代号不存在 ⇒ 同样 Err
        write_geosite_dat(&dir, vec![crate::pb::Domain::full("a.example")]);
        assert!(registry.build_domain_matcher(&rules).is_ok());
        let missing_code = [crate::pb::DomainRule {
            value: Some(crate::pb::domain_rule::Value::Geosite(crate::pb::GeoSiteRule {
                file: DEFAULT_GEOSITE_DAT.to_string(),
                code: "NOPE".to_string(),
                attrs: String::new(),
            })),
        }];
        assert!(matches!(
            registry.build_domain_matcher(&missing_code),
            Err(BuildDomainMatcherError::Loader(_))
        ));
    }

    #[test]
    fn test_domain_registry_empty_rules_is_error() {
        let registry = DomainRegistry::new();
        assert!(matches!(
            registry.build_domain_matcher(&[]),
            Err(BuildDomainMatcherError::EmptyRules)
        ));
    }

    /// geosite 展开：同 tag 的所有域名共用该条规则的下标（Go `loadSiteMatchers`），
    /// dat 内非法条目跳过而非整份拒启。
    #[test]
    fn test_domain_registry_expands_geosite_with_shared_rule_id() {
        let dir = temp_datadir("expand");
        write_geosite_dat(
            &dir,
            vec![
                crate::pb::Domain::new(crate::pb::domain::Type::Full, "a.example"),
                crate::pb::Domain::new(crate::pb::domain::Type::Domain, "b.example"),
                // 未知类型 99 → 跳过该条（非致命）
                crate::pb::Domain::new(99i32, "skip.example"),
                // 正则非法 → 跳过该条（非致命）
                crate::pb::Domain::new(crate::pb::domain::Type::Regex, "a(b"),
            ],
        );
        let registry = DomainRegistry::with_datadir(dir.clone());
        let matcher = registry
            .build_domain_matcher(&[
                crate::pb::DomainRule {
                    value: Some(crate::pb::domain_rule::Value::Geosite(crate::pb::GeoSiteRule {
                        file: DEFAULT_GEOSITE_DAT.to_string(),
                        code: "HOT".to_string(),
                        attrs: String::new(),
                    })),
                },
                pb_custom(crate::pb::domain::Type::Full, "custom.example"),
            ])
            .unwrap();

        assert_eq!(matcher.match_domain("a.example"), vec![0u32]);
        assert_eq!(matcher.match_domain("sub.b.example"), vec![0u32]);
        assert_eq!(matcher.match_domain("custom.example"), vec![1u32]);
        assert!(matcher.match_domain("skip.example").is_empty(), "非法条目必须跳过");
    }
}

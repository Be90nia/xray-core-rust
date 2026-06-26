//! 权重管理（WeightManager）。
//!
//! 翻译自 `app/router/weight.go`。
//!
//! 为 `LeastLoadStrategy` 提供每个出站 tag 的权重调节：
//! - proto `StrategyWeight { regexp: bool, match: string, value: float }`
//! - `regexp==true`：`match` 作为正则模式，`is_match(tag)`
//! - `regexp==false`：`match` 作为字面 tag，严格相等
//! - 命中即缓存
//! - 未命中返回默认权重

use std::sync::OnceLock;

use parking_lot::Mutex;
use regex::Regex;
use xray_proto::xray::app::router::StrategyWeight;

/// 权重管理器：按 tag 查权重，支持字面/正则匹配。
///
/// 对应 Go `router.WeightManager`。线程安全（内部 `Mutex<HashMap>`）。
#[derive(Debug)]
pub struct WeightManager {
    /// 配置项。
    settings: Vec<WeightSetting>,
    /// 命中缓存（tag -> weight）。
    cache: Mutex<std::collections::HashMap<String, f64>>,
    /// 默认权重。
    default_weight: f64,
}

/// 单条权重配置（从 proto `StrategyWeight` 解析）。
#[derive(Debug)]
enum WeightSetting {
    /// 字面 tag 严格相等。
    Literal { tag: String, value: f64 },
    /// 正则匹配（`regexp==true`）。
    Regex { regex: Regex, value: f64 },
}

impl WeightManager {
    /// 从 proto `StrategyWeight` 列表构造。
    ///
    /// `default_weight`：未匹配任何规则时的返回值。
    pub fn new(weights: &[StrategyWeight], default_weight: f64) -> Result<Self, regex::Error> {
        let mut settings = Vec::with_capacity(weights.len());
        for w in weights {
            let value = f64::from(w.value);
            if w.regexp {
                let regex = Regex::new(&w.r#match)?;
                settings.push(WeightSetting::Regex { regex, value });
            } else {
                settings.push(WeightSetting::Literal {
                    tag: w.r#match.clone(),
                    value,
                });
            }
        }
        Ok(Self {
            settings,
            cache: Mutex::new(std::collections::HashMap::new()),
            default_weight,
        })
    }

    /// 取 tag 的权重。命中规则返回规则值，否则返回默认值。
    ///
    /// 对应 Go `(*WeightManager).Get`。
    pub fn get(&self, tag: &str) -> f64 {
        if let Some(v) = self.cache.lock().get(tag) {
            return *v;
        }
        let v = self.find_value(tag);
        self.cache.lock().insert(tag.to_string(), v);
        v
    }

    /// 对一组 tag 应用权重，返回 (tag, weight) 列表。
    ///
    /// 对应 Go `(*WeightManager).Apply`。
    pub fn apply<'a>(&self, tags: &'a [String]) -> Vec<(&'a str, f64)> {
        tags.iter().map(|t| (t.as_str(), self.get(t))).collect()
    }

    fn find_value(&self, tag: &str) -> f64 {
        for s in &self.settings {
            let hit = match s {
                WeightSetting::Literal { tag: t, .. } => t == tag,
                WeightSetting::Regex { regex, .. } => regex.is_match(tag),
            };
            if hit {
                return match s {
                    WeightSetting::Literal { value, .. } => *value,
                    WeightSetting::Regex { value, .. } => *value,
                };
            }
        }
        self.default_weight
    }
}

/// 从字符串中提取第一个数字（Go `numberFinder`，为调用者保留工具）。
pub fn number_finder(s: &str) -> Option<f64> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"(\d+(\.\d+)?)").expect("number regex compiles")
    });
    re.captures(s)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse::<f64>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sw(regexp: bool, r#match: &str, value: f32) -> StrategyWeight {
        StrategyWeight {
            regexp,
            r#match: r#match.into(),
            value,
        }
    }

    #[test]
    fn test_default_weight_when_no_settings() {
        let wm = WeightManager::new(&[], 1.0).unwrap();
        assert_eq!(wm.get("anytag"), 1.0);
    }

    #[test]
    fn test_literal_match_returns_value() {
        let wm = WeightManager::new(&[sw(false, "us-east", 100.0)], 1.0).unwrap();
        assert_eq!(wm.get("us-east"), 100.0);
        // 不相等 → 默认
        assert_eq!(wm.get("us-west"), 1.0);
        assert_eq!(wm.get("prefix-us-east"), 1.0); // 严格相等
    }

    #[test]
    fn test_regex_match() {
        let wm = WeightManager::new(&[sw(true, "us\\d+", 50.0)], 1.0).unwrap();
        assert_eq!(wm.get("us1"), 50.0);
        assert_eq!(wm.get("us99"), 50.0);
        // substring：is_match 任意位置
        assert_eq!(wm.get("prefix-us1-suffix"), 50.0);
        assert_eq!(wm.get("hk1"), 1.0);
    }

    #[test]
    fn test_caches_results() {
        let wm = WeightManager::new(&[sw(false, "tag1", 100.0)], 1.0).unwrap();
        let _ = wm.get("tag1");
        let cache = wm.cache.lock();
        assert!(cache.contains_key("tag1"));
    }

    #[test]
    fn test_apply_to_list() {
        let wm = WeightManager::new(&[sw(false, "us1", 100.0)], 1.0).unwrap();
        let tags = vec!["us1".to_string(), "hk1".to_string()];
        let applied = wm.apply(&tags);
        assert_eq!(applied.len(), 2);
        assert_eq!(applied[0], ("us1", 100.0));
        assert_eq!(applied[1], ("hk1", 1.0));
    }

    #[test]
    fn test_value_zero_used_as_is() {
        // proto value=0 是合法值（不同于 Go 中的“未指定”）
        let wm = WeightManager::new(&[sw(false, "zero", 0.0)], 1.0).unwrap();
        assert_eq!(wm.get("zero"), 0.0);
    }

    #[test]
    fn test_number_finder_basic() {
        assert_eq!(number_finder("abc123def"), Some(123.0));
        assert_eq!(number_finder("abc"), None);
        assert_eq!(number_finder("3.14"), Some(3.14));
    }
}

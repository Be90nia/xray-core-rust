//! # Trojan Fallback 决策树
//!
//! 对应 Go `proxy/trojan/fallback.go`。
//!
//! 3 级匹配树：SNI → ALPN → Path。
//! 每级先精确匹配，回退到通配（空字符串）。

use std::collections::HashMap;
use std::sync::Arc;

/// 单个 Fallback 配置。对应 proto `Fallback`。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Fallback {
    /// SNI 匹配（空 = 通配）。
    pub name: String,
    /// ALPN 匹配（空 = 通配）。
    pub alpn: String,
    /// HTTP path 匹配（空 = 通配）。
    pub path: String,
    /// 拨号网络类型（`"tcp"` / `"unix"`，空 = 未指定）。
    ///
    /// 对应 proto `Fallback.type`；Go `server.go:457` `dialer.DialContext(ctx, fb.Type, fb.Dest)`。
    pub r#type: String,
    /// 目标地址（host:port 或 Unix socket 路径）。
    pub dest: String,
    /// PROXY protocol 版本（0=禁用，1/2=启用）。
    pub xver: u64,
}

impl Fallback {
    /// 从 prost `Fallback` 构造（全 6 字段）。
    ///
    /// 对应 Go `infra/conf/trojan.go:159-166` JSON→proto 的 proto 侧入口。
    #[must_use]
    pub fn from_proto(p: xray_proto::xray::proxy::trojan::Fallback) -> Self {
        Self {
            name: p.name,
            alpn: p.alpn,
            path: p.path,
            r#type: p.r#type,
            dest: p.dest,
            xver: p.xver,
        }
    }

    /// 转换为 prost `Fallback`。
    #[must_use]
    pub fn to_proto(&self) -> xray_proto::xray::proxy::trojan::Fallback {
        xray_proto::xray::proxy::trojan::Fallback {
            name: self.name.clone(),
            alpn: self.alpn.clone(),
            path: self.path.clone(),
            r#type: self.r#type.clone(),
            dest: self.dest.clone(),
            xver: self.xver,
        }
    }
}

/// Path 层：`path → Fallback`，含通配。
#[derive(Debug, Default)]
struct PathNode {
    /// 精确 path 匹配。
    exact: HashMap<String, Fallback>,
    /// 通配 path（空字符串 key）。
    wildcard: Option<Fallback>,
}

impl PathNode {
    fn get(&self, path: &str) -> Option<&Fallback> {
        // 精确优先，回退通配
        if let Some(f) = self.exact.get(path) {
            return Some(f);
        }
        self.wildcard.as_ref()
    }
}

/// ALPN 层：`alpn → PathNode`，含通配。
#[derive(Debug, Default)]
struct AlpnNode {
    /// 精确 ALPN 匹配。
    exact: HashMap<String, PathNode>,
    /// 通配 ALPN（空字符串 key）。
    wildcard: Option<PathNode>,
}

impl AlpnNode {
    fn get(&self, alpn: &str, path: &str) -> Option<&Fallback> {
        // 精确 ALPN 优先
        if let Some(p) = self.exact.get(alpn) {
            if let Some(f) = p.get(path) {
                return Some(f);
            }
        }
        // 通配 ALPN
        self.wildcard.as_ref().and_then(|p| p.get(path))
    }
}

/// SNI 层：`sni → AlpnNode`，含通配。
#[derive(Debug, Default)]
struct SniNode {
    /// 精确 SNI 匹配。
    exact: HashMap<String, AlpnNode>,
    /// 通配 SNI（空字符串 key）。
    wildcard: Option<AlpnNode>,
}

impl SniNode {
    fn get(&self, sni: &str, alpn: &str, path: &str) -> Option<&Fallback> {
        // 精确 SNI 优先
        if let Some(a) = self.exact.get(sni) {
            if let Some(f) = a.get(alpn, path) {
                return Some(f);
            }
        }
        // Go server.go:388-398：多规则或无默认规则时（len(napfb) > 1 ||
        // napfb[""] == nil），SNI 精确 miss → contains 子串最长匹配。u88f。
        let name_count = self.exact.len() + usize::from(self.wildcard.is_some());
        if (name_count > 1 || self.wildcard.is_none())
            && !sni.is_empty()
            && !self.exact.contains_key(sni)
        {
            if let Some(f) = self.fuzzy_longest_match(sni, alpn, path) {
                return Some(f);
            }
        }
        // 通配 SNI（Go server.go:400-402：napfb[name] == nil → name = ""）
        self.wildcard.as_ref().and_then(|a| a.get(alpn, path))
    }

    /// contains 子串最长匹配：客户端 SNI 包含某规则 name（如配置
    /// "example.com" 命中 "sub.example.com"），取最长 name 的规则。
    /// 对应 Go server.go:390-396 的 `strings.Contains(name, n) && len(n) > len(match)`。
    fn fuzzy_longest_match(&self, sni: &str, alpn: &str, path: &str) -> Option<&Fallback> {
        let mut matched: Option<&String> = None;
        for n in self.exact.keys() {
            if sni.contains(n.as_str()) && matched.map_or(true, |m| n.len() > m.len()) {
                matched = Some(n);
            }
        }
        self.exact.get(matched?).and_then(|a| a.get(alpn, path))
    }
}

/// Fallback 决策策略。对应 Go `FallbackConfig`。
#[derive(Debug, Default)]
pub struct FallbackPolicy {
    /// 3 级匹配树根节点。
    root: SniNode,
}

impl FallbackPolicy {
    /// 从 proto `Fallback` 列表构建决策树。
    #[must_use]
    pub fn from_list(list: &[Fallback]) -> Arc<Self> {
        let mut policy = Self::default();
        for fb in list {
            policy.insert(fb.clone());
        }
        Arc::new(policy)
    }

    /// 插入一条 fallback 规则。
    fn insert(&mut self, fb: Fallback) {
        // SNI 层
        if fb.name.is_empty() {
            // 通配 SNI
            let node = self.root.wildcard.get_or_insert_with(AlpnNode::default);
            Self::insert_alpn(node, fb);
        } else {
            let node = self.root.exact.entry(fb.name.clone()).or_insert_with(AlpnNode::default);
            Self::insert_alpn(node, fb);
        }
    }

    fn insert_alpn(node: &mut AlpnNode, fb: Fallback) {
        if fb.alpn.is_empty() {
            let path_node = node.wildcard.get_or_insert_with(PathNode::default);
            Self::insert_path(path_node, fb);
        } else {
            let path_node = node.exact.entry(fb.alpn.clone()).or_insert_with(PathNode::default);
            Self::insert_path(path_node, fb);
        }
    }

    fn insert_path(node: &mut PathNode, fb: Fallback) {
        if fb.path.is_empty() {
            node.wildcard = Some(fb);
        } else {
            node.exact.insert(fb.path.clone(), fb);
        }
    }

    /// 查找 fallback：SNI → ALPN → Path，每级精确优先回退通配。
    ///
    /// 查询侧 lowercase 对齐 Go `server.go:385-386`
    /// `name = strings.ToLower(name); alpn = strings.ToLower(alpn)`
    /// （SNI RFC 6066 不区分大小写；恶意大写 SNI 不得绕过精确规则）。
    #[must_use]
    pub fn decide(&self, sni: &str, alpn: &str, path: &str) -> Option<&Fallback> {
        let sni = &sni.to_lowercase();
        let alpn = &alpn.to_lowercase();
        self.root.get(sni, alpn, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fb(name: &str, alpn: &str, path: &str, dest: &str) -> Fallback {
        Fallback {
            name: name.into(),
            alpn: alpn.into(),
            path: path.into(),
            r#type: String::new(),
            dest: dest.into(),
            xver: 0,
        }
    }

    #[test]
    fn exact_match_wins_over_wildcard() {
        let policy = FallbackPolicy::from_list(&[
            fb("", "", "", "default"),       // 通配
            fb("a.com", "", "", "a.com"),    // SNI 精确
        ]);
        assert_eq!(policy.decide("a.com", "", "").unwrap().dest, "a.com");
        assert_eq!(policy.decide("b.com", "", "").unwrap().dest, "default");
    }

    #[test]
    fn alpn_exact_wins_over_wildcard() {
        let policy = FallbackPolicy::from_list(&[
            fb("a.com", "", "", "a.com:any"),
            fb("a.com", "h2", "", "a.com:h2"),
        ]);
        assert_eq!(policy.decide("a.com", "h2", "").unwrap().dest, "a.com:h2");
        assert_eq!(policy.decide("a.com", "http/1.1", "").unwrap().dest, "a.com:any");
    }

    #[test]
    fn path_exact_wins_over_wildcard() {
        let policy = FallbackPolicy::from_list(&[
            fb("a.com", "h2", "", "a.com:h2:any"),
            fb("a.com", "h2", "/ws", "a.com:h2:/ws"),
        ]);
        assert_eq!(policy.decide("a.com", "h2", "/ws").unwrap().dest, "a.com:h2:/ws");
        assert_eq!(policy.decide("a.com", "h2", "/api").unwrap().dest, "a.com:h2:any");
    }

    #[test]
    fn no_match_returns_none() {
        let policy = FallbackPolicy::from_list(&[fb("a.com", "", "", "a.com")]);
        assert!(policy.decide("b.com", "", "").is_none());
    }

    #[test]
    fn empty_policy_returns_none() {
        let policy = FallbackPolicy::default();
        assert!(policy.decide("a.com", "h2", "/").is_none());
    }

    // ==== u88f：Go server.go:385-398 lowercase + 模糊 contains 匹配契约 ====

    /// 查询侧 lowercase：恶意大写 SNI 不得绕过精确规则（Go server.go:385-386）。
    #[test]
    fn sni_lowercase_matches_case_insensitively() {
        let policy = FallbackPolicy::from_list(&[
            fb("", "", "", "default"),
            fb("a.com", "", "", "a.com"),
        ]);
        assert_eq!(policy.decide("A.COM", "", "").unwrap().dest, "a.com");
        assert_eq!(policy.decide("a.Com", "", "").unwrap().dest, "a.com");
    }

    /// 模糊 contains 匹配：多规则配置下子域命中主域规则（Go server.go:388-398）。
    /// 修复前：SNI "sub.example.com" 精确 miss → 直落通配，专用规则静默降级。
    #[test]
    fn sni_fuzzy_contains_matches_subdomain() {
        let policy = FallbackPolicy::from_list(&[
            fb("", "", "", "default"),
            fb("example.com", "", "", "example.com"),
            fb("other.org", "", "", "other.org"),
        ]);
        assert_eq!(
            policy.decide("sub.example.com", "", "").unwrap().dest,
            "example.com"
        );
    }

    /// 模糊匹配取最长 contains 命中（Go server.go:392-394 `len(n) > len(match)`）。
    #[test]
    fn sni_fuzzy_longest_match_wins() {
        let policy = FallbackPolicy::from_list(&[
            fb("", "", "", "default"),
            fb("example.com", "", "", "example.com"),
            fb("a.example.com", "", "", "a.example.com"),
        ]);
        assert_eq!(
            policy.decide("x.a.example.com", "", "").unwrap().dest,
            "a.example.com"
        );
    }
}

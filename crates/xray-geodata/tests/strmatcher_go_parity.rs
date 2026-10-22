//! Go 参考实现对拍（golden 锚点）：`MphMatcherGroup` 匹配结果必须与 Go 逐输入一致。
//!
//! 锚点由 Go 参考仓产出（`D:/Project/Xray-core/common/geodata/strmatcher`，同样的
//! 5 条规则 + 16 条输入，见本文件 `GO_GOLDEN`）。重建锚点的方式：在参考仓外建临时
//! module（`require github.com/xtls/xray-core` + `replace` 指向参考仓），用
//! `MphMatcherGroup.AddDomainMatcher/AddFullMatcher/Build/Match` 打印 JSON。
//!
//! 覆盖 Go 语义要点：域名后缀匹配 + 边界（`notexample.com`/`example.com.evil` 不匹）、
//! Full 精确匹配（`sub.full.test` 不匹）、大小写敏感（`EXACT.CASE`/`EXAMPLE.COM` 不匹）。

use xray_geodata::matcher::{MPHMatcherGroup, MatcherGroup};

/// Go `MphMatcherGroup` 输出（id 升序）：(input, matched rule ids)。
const GO_GOLDEN: &[(&str, &[u32])] = &[
    ("example.com", &[0]),
    ("www.example.com", &[0]),
    ("a.b.example.com", &[0]),
    ("notexample.com", &[]),
    ("example.com.evil", &[]),
    ("google.com", &[1]),
    ("mail.google.com", &[1]),
    ("a.b.test", &[2]),
    ("x.a.b.test", &[2]),
    ("full.test", &[3]),
    ("sub.full.test", &[]),
    ("exact.case", &[4]),
    ("", &[]),
    ("unrelated.net", &[]),
];

fn build_group() -> MPHMatcherGroup {
    let mut g = MPHMatcherGroup::new();
    // 规则 id 与 Go 侧添加顺序一致（domain 0/1/2 + full 3/4）。
    g.add_domain_matcher("example.com", 0);
    g.add_domain_matcher("google.com", 1);
    g.add_domain_matcher("a.b.test", 2);
    g.add_full_matcher("full.test", 3);
    g.add_full_matcher("exact.case", 4);
    g.build().expect("mph build");
    g
}

#[test]
fn mph_group_matches_go_golden() {
    let g = build_group();
    for (input, want) in GO_GOLDEN {
        let mut got = g.match_str(input);
        got.sort_unstable();
        assert_eq!(&got[..], *want, "input {input:?} 与 Go 参考实现不一致");
    }
}

/// 大小写与 Go 一致：Go 只在 Add 侧 lowercase 模式（`matchergroup_mph.go:84`），
/// `Match` 是纯字节比较（`DomainMatcher.Match`，matchers.go:50-57）→ 混合大小写输入不命中。
/// 上游 lowercase 由调用方负责（Go `router/condition.go:60`、`dns/hosts.go:98`）。
#[test]
fn mph_group_is_case_sensitive_like_go() {
    let g = build_group();
    assert!(g.match_str("EXACT.CASE").is_empty());
    assert!(g.match_str("EXAMPLE.COM").is_empty());
    assert!(!g.match_any("EXAMPLE.COM"));
}

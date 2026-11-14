//! VLESS inbound handler。
//!
//! 对应 Go 版本 `proxy/vless/inbound/inbound.go`。入站方向：服务端从客户端连接
//! 接收 VLESS 请求头，解码后桥接到 dispatcher。当客户端发起的是非 VLESS 流量
//! （比如错误路径上的 HTTPS 请求），fallback 路由会把流量转发到指定的备用目标。
//!
//! # 当前状态
//!
//! - **完整实现**：[`FallbackPolicy`]（`napfb[name][alpn][path]` 三级 map）+
//!   [`extract_path_from_first_bytes`]（从 first buffer 字节 4 位置提取 path）。
//!   这两个是纯算法，可独立单元测试。
//!
//! 入站主流程的实装在 [`crate::inbound::server`]；本模块只留 fallback 策略。

use std::collections::HashMap;

/// Fallback 路由策略：`name → alpn → path → FallbackDest` 三级 map。
///
/// 对应 Go 端 `napfb` 字典：SNI 名字（或空）→ ALPN（或空）→ HTTP path → 目标。
/// `name=""` 表示通配，`alpn=""` 同理。
#[derive(Debug, Default, Clone)]
pub struct FallbackPolicy {
    /// name → (alpn → (path → dest))
    entries: HashMap<String, HashMap<String, HashMap<String, FallbackDest>>>,
}

/// 一条 fallback 目标：`dest`（"host:port"）+ PROXY protocol `xver`（0/1/2）。
#[derive(Debug, Clone)]
pub struct FallbackDest {
    /// 目标地址字符串（`xray_transport::fallback::fallback_to_dest` 拨，可含域名）。
    pub dest: String,
    /// PROXY protocol 版本（0=无，1=v1 文本，2=v2 二进制）。
    pub xver: u8,
}

impl FallbackDest {
    #[must_use]
    pub fn new(dest: impl Into<String>, xver: u8) -> Self {
        Self { dest: dest.into(), xver }
    }
}

impl FallbackPolicy {
    /// 创建空策略。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 添加一条 fallback 规则。
    pub fn add(
        &mut self,
        name: impl Into<String>,
        alpn: impl Into<String>,
        path: impl Into<String>,
        dest: FallbackDest,
    ) {
        self.entries
            .entry(name.into())
            .or_default()
            .entry(alpn.into())
            .or_default()
            .insert(path.into(), dest);
    }

    /// 精确匹配（不做通配）。
    #[must_use]
    pub fn find(&self, name: &str, alpn: &str, path: &str) -> Option<&FallbackDest> {
        self.entries.get(name).and_then(|m| m.get(alpn)).and_then(|m| m.get(path))
    }

    /// 按 Go 端 fallback 语义查找：先精确，再降级到空 name/alpn/path。
    ///
    /// Go 实际逻辑（`inbound.go` 内 `napfb[name][alpn][path]`）会按如下优先级：
    /// 1. (name, alpn, path) 精确
    /// 2. (name, alpn, "")
    /// 3. (name, "", path)
    /// 4. (name, "", "")
    /// 5. ("", alpn, path)
    /// 6. ("", alpn, "")
    /// 7. ("", "", path)
    /// 8. ("", "", "")
    #[must_use]
    pub fn find_with_fallback(&self, name: &str, alpn: &str, path: &str) -> Option<&FallbackDest> {
        for (n, a, p) in [
            (name, alpn, path),
            (name, alpn, ""),
            (name, "", path),
            (name, "", ""),
            ("", alpn, path),
            ("", alpn, ""),
            ("", "", path),
            ("", "", ""),
        ] {
            if let Some(d) = self.find(n, a, p) {
                return Some(d);
            }
        }
        None
    }

    /// 总规则数（所有 name × alpn × path 组合）。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.values().flat_map(|m| m.values()).map(|m| m.len()).sum()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 从 first buffer 提取 HTTP path（已上移 `xray_transport::fallback`，re-export 保持模块
/// API）。
pub use xray_transport::fallback::extract_path_from_first_bytes;

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_dest(host: &str, port: u16) -> FallbackDest {
        FallbackDest::new(format!("{host}:{port}"), 0)
    }

    #[test]
    fn fallback_policy_add_and_find_exact() {
        let mut p = FallbackPolicy::new();
        p.add("example.com", "h2", "/api", sample_dest("backend.local", 8080));
        let d = p.find("example.com", "h2", "/api");
        assert!(d.is_some());
        let d = d.unwrap();
        assert_eq!(d.dest, "backend.local:8080");
    }

    #[test]
    fn fallback_policy_find_miss() {
        let mut p = FallbackPolicy::new();
        p.add("example.com", "h2", "/api", sample_dest("backend.local", 8080));
        assert!(p.find("other.com", "h2", "/api").is_none());
        assert!(p.find("example.com", "h3", "/api").is_none());
        assert!(p.find("example.com", "h2", "/other").is_none());
    }

    #[test]
    fn fallback_policy_wildcard_name_match() {
        let mut p = FallbackPolicy::new();
        // 精确条目
        p.add("example.com", "h2", "/api", sample_dest("api.local", 9000));
        // 通配 name 条目
        p.add("", "h2", "/default", sample_dest("default.local", 80));

        // 精确命中
        let d = p.find_with_fallback("example.com", "h2", "/api").unwrap();
        assert_eq!(d.dest, "api.local:9000");

        // 未注册的 name 走通配
        let d = p.find_with_fallback("unknown.com", "h2", "/default").unwrap();
        assert_eq!(d.dest, "default.local:80");
    }

    #[test]
    fn fallback_policy_empty_alpn_match() {
        let mut p = FallbackPolicy::new();
        p.add("example.com", "", "/catchall", sample_dest("catch.local", 9090));

        // alpn 未匹配具体条目，降级到 alpn=""
        let d = p.find_with_fallback("example.com", "h2", "/catchall").unwrap();
        assert_eq!(d.dest, "catch.local:9090");
    }

    #[test]
    fn fallback_policy_total_miss() {
        let p = FallbackPolicy::new();
        assert!(p.find_with_fallback("a", "b", "c").is_none());
    }

    #[test]
    fn fallback_policy_len_and_is_empty() {
        let mut p = FallbackPolicy::new();
        assert!(p.is_empty());
        p.add("a", "b", "c", sample_dest("h", 1));
        p.add("a", "b", "d", sample_dest("h", 2));
        p.add("x", "y", "z", sample_dest("h", 3));
        assert_eq!(p.len(), 3);
        assert!(!p.is_empty());
    }

    #[test]
    fn extract_path_simple_get() {
        // "GET /api HTTP/1.1\r\n..."
        let bytes = b"GET /api HTTP/1.1\r\nHost: x";
        let path = extract_path_from_first_bytes(bytes).unwrap();
        assert_eq!(path, "/api");
    }

    #[test]
    fn extract_path_post() {
        let bytes = b"POST /submit HTTP/1.1\r\n";
        let path = extract_path_from_first_bytes(bytes).unwrap();
        assert_eq!(path, "/submit");
    }

    #[test]
    fn extract_path_no_slash_returns_none() {
        // 没有任何 '/' 字节
        let bytes = b"GET  HTTPl"; // 无 '/'
        assert!(extract_path_from_first_bytes(bytes).is_none());
    }

    #[test]
    fn extract_path_too_short() {
        assert!(extract_path_from_first_bytes(b"abc").is_none());
    }

    #[test]
    fn extract_path_terminator_newline() {
        let bytes = b"GET /api\n";
        let path = extract_path_from_first_bytes(bytes).unwrap();
        assert_eq!(path, "/api");
    }

    #[test]
    fn extract_path_no_terminator_returns_full() {
        // 没有 ' ' 或 '\r'，返回到末尾
        let bytes = b"GET /longpath";
        let path = extract_path_from_first_bytes(bytes).unwrap();
        assert_eq!(path, "/longpath");
    }
}

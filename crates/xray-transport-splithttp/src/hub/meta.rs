//! 从 HTTP 请求中提取 session/seq 元数据。
//!
//! 对应 Go `Config.ExtractMetaFromRequest(req, path) -> (sessionId, seqStr)`。
//! 纯函数：输入 `&hyper::Request`（或等效的 header/path/query 视图），输出元数据。
//! 不依赖任何 IO，便于单元测试。

use http::Request;

use crate::config::{Config, PLACEMENT_COOKIE, PLACEMENT_HEADER, PLACEMENT_PATH, PLACEMENT_QUERY};

/// 解析出的请求元数据：session ID + seq 字符串。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestMetaInfo {
    /// 会话 ID（可能为空：stream-one 模式）。
    pub session_id: String,
    /// 序号字符串（可能为空：stream-up / stream-down）。
    pub seq_str: String,
}

/// 从 path 中提取的单个值（header / cookie 等）。
type HeaderMap<'a> = &'a http::HeaderMap;

/// 从 `http::Request` 的 headers 中按名称取值。
fn header_get(headers: HeaderMap<'_>, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// 从 `Cookie:` header 中按名称提取 cookie 值。
fn cookie_get(headers: HeaderMap<'_>, name: &str) -> String {
    for value in headers.get_all("cookie").iter() {
        if let Ok(s) = value.to_str() {
            for pair in s.split(';') {
                let pair = pair.trim();
                if let Some(eq_pos) = pair.find('=') {
                    let (k, v) = pair.split_at(eq_pos);
                    if k == name {
                        return v[1..].to_string();
                    }
                }
            }
        }
    }
    String::new()
}

/// 从 URL query string 中按 key 提取值。
fn query_get(query: &str, key: &str) -> String {
    for pair in query.split('&') {
        if let Some(eq_pos) = pair.find('=') {
            let (k, v) = pair.split_at(eq_pos);
            if k == key {
                return v[1..].to_string();
            }
        } else if pair == key {
            return String::new();
        }
    }
    String::new()
}

/// 从 `http::Request<B>` 提取 `(session_id, seq_str)`。对应 Go `ExtractMetaFromRequest`。
///
/// `base_path` 是 `Config::normalized_path()` 的结果（已含首尾 `/`）。
/// 当 placement 为 path 时，session/seq 从 `request.uri().path()` 在 `base_path` 之后的部分提取。
pub fn extract_meta<B>(req: &Request<B>, config: &Config, base_path: &str) -> RequestMetaInfo {
    let session_placement = config.normalized_session_placement();
    let seq_placement = config.normalized_seq_placement();
    let session_key = config.normalized_session_key();
    let seq_key = config.normalized_seq_key();
    let headers = req.headers();

    // path placement 需要拆分 URL path 的子段。
    let subpath: Vec<&str> = if session_placement == PLACEMENT_PATH || seq_placement == PLACEMENT_PATH {
        let full_path = req.uri().path();
        let after_base = full_path.strip_prefix(base_path).unwrap_or(full_path);
        after_base.split('/').filter(|s| !s.is_empty()).collect()
    } else {
        Vec::new()
    };

    let mut path_part = 0usize;
    let mut session_id = String::new();
    let mut seq_str = String::new();

    // session
    match session_placement {
        PLACEMENT_PATH => {
            if path_part < subpath.len() {
                session_id = subpath[path_part].to_string();
                path_part += 1;
            }
        }
        PLACEMENT_QUERY => {
            session_id = query_get(req.uri().query().unwrap_or(""), session_key);
        }
        PLACEMENT_HEADER => {
            session_id = header_get(headers, session_key);
        }
        PLACEMENT_COOKIE => {
            session_id = cookie_get(headers, session_key);
        }
        _ => {}
    }

    // seq
    match seq_placement {
        PLACEMENT_PATH => {
            if path_part < subpath.len() {
                seq_str = subpath[path_part].to_string();
                let _ = path_part;
            }
        }
        PLACEMENT_QUERY => {
            seq_str = query_get(req.uri().query().unwrap_or(""), seq_key);
        }
        PLACEMENT_HEADER => {
            seq_str = header_get(headers, seq_key);
        }
        PLACEMENT_COOKIE => {
            seq_str = cookie_get(headers, seq_key);
        }
        _ => {}
    }

    RequestMetaInfo { session_id, seq_str }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use http::Request;

    fn make_request(uri: &str, headers: &[(&str, &str)]) -> Request<()> {
        let mut builder = Request::builder().uri(uri);
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        builder.body(()).unwrap()
    }

    #[test]
    fn extract_path_path_placement() {
        let cfg = Config::default(); // session/seq both in path
        let req = make_request("/ws/sess123/5", &[]);
        let meta = extract_meta(&req, &cfg, "/ws/");
        assert_eq!(meta.session_id, "sess123");
        assert_eq!(meta.seq_str, "5");
    }

    #[test]
    fn extract_query_query_placement() {
        let cfg = Config {
            session_placement: "query".into(),
            seq_placement: "query".into(),
            ..Default::default()
        };
        let req = make_request("/ws?x_session=aaa&x_seq=3", &[]);
        let meta = extract_meta(&req, &cfg, "/ws/");
        assert_eq!(meta.session_id, "aaa");
        assert_eq!(meta.seq_str, "3");
    }

    #[test]
    fn extract_header_header_placement() {
        let cfg = Config {
            session_placement: "header".into(),
            seq_placement: "header".into(),
            ..Default::default()
        };
        let req = make_request(
            "/ws",
            &[("X-Session", "hdr-sess"), ("X-Seq", "9")],
        );
        let meta = extract_meta(&req, &cfg, "/ws/");
        assert_eq!(meta.session_id, "hdr-sess");
        assert_eq!(meta.seq_str, "9");
    }

    #[test]
    fn extract_cookie_cookie_placement() {
        let cfg = Config {
            session_placement: "cookie".into(),
            seq_placement: "cookie".into(),
            ..Default::default()
        };
        let req = make_request(
            "/ws",
            &[("Cookie", "x_session=ck-sess; x_seq=7")],
        );
        let meta = extract_meta(&req, &cfg, "/ws/");
        assert_eq!(meta.session_id, "ck-sess");
        assert_eq!(meta.seq_str, "7");
    }

    #[test]
    fn extract_mixed_path_and_query() {
        let cfg = Config {
            session_placement: "path".into(),
            seq_placement: "query".into(),
            ..Default::default()
        };
        let req = make_request("/ws/mixed-sess?x_seq=42", &[]);
        let meta = extract_meta(&req, &cfg, "/ws/");
        assert_eq!(meta.session_id, "mixed-sess");
        assert_eq!(meta.seq_str, "42");
    }

    #[test]
    fn extract_empty_when_no_values() {
        let cfg = Config::default();
        let req = make_request("/ws/", &[]);
        let meta = extract_meta(&req, &cfg, "/ws/");
        assert_eq!(meta.session_id, "");
        assert_eq!(meta.seq_str, "");
    }

    #[test]
    fn extract_custom_keys() {
        let cfg = Config {
            session_placement: "header".into(),
            session_key: "X-Custom-S".into(),
            seq_placement: "query".into(),
            seq_key: "custom_seq".into(),
            ..Default::default()
        };
        let req = make_request(
            "/ws?custom_seq=10",
            &[("X-Custom-S", "my-session")],
        );
        let meta = extract_meta(&req, &cfg, "/ws/");
        assert_eq!(meta.session_id, "my-session");
        assert_eq!(meta.seq_str, "10");
    }

    #[test]
    fn cookie_get_handles_multiple_cookies() {
        let cfg = Config {
            session_placement: "cookie".into(),
            session_key: "token".into(),
            ..Default::default()
        };
        let req = make_request("/ws", &[("Cookie", "foo=bar; token=abc123; baz=qux")]);
        let meta = extract_meta(&req, &cfg, "/ws/");
        assert_eq!(meta.session_id, "abc123");
    }

    #[test]
    fn path_with_base_not_ending_slash_still_works() {
        // base_path is always normalized to end with '/', but the request
        // path may have additional segments after it.
        let cfg = Config::default();
        let req = make_request("/ws/a/b/c", &[]);
        let meta = extract_meta(&req, &cfg, "/ws/");
        assert_eq!(meta.session_id, "a");
        assert_eq!(meta.seq_str, "b");
        // "c" is unused extra path segment
    }
}

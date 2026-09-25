//! 浏览器伪装默认请求头（对齐 Go `common/utils/browser.go`，xray-core v26.7.28）。
//!
//! Go 各传输的 `GetRequestHeader()` 在 UA 未配置时调用
//! `utils.TryDefaultHeadersWith(header, variant)`，生成整套浏览器伪装头
//! （UA + Sec-CH-UA GREASE + Sec-Fetch-* + Accept 系）。缺省脚本 UA 是
//! 典型非浏览器特征，会被 CDN/WAF bot 检测拒绝（403）。
//!
//! 本模块原在 xray-transport-splithttp，因 ws/httpupgrade 出站同样需要
//! （票 mzte/yz8n）且二者不能反向依赖 splithttp，下沉到 xray-common 共享。
//!
//! variant：`fetch`（splithttp/xhttp）、`nav`（http CONNECT 出站）、
//! `ws`（websocket/httpupgrade 握手）。

use rand::Rng;

/// HTTP header 列表的 Set 语义：替换首个同名（大小写不敏感），否则追加。
///
/// pub：httpupgrade `build_upgrade_request` 对 Connection/Upgrade 用同样的
/// Set 语义（Go `req.Header.Set`，dialer.go:100-101）。
pub fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    if let Some(slot) = headers.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(name)) {
        slot.1 = value.to_string();
    } else {
        headers.push((name.to_string(), value.to_string()));
    }
}

fn get_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

/// UTC 当天秒数 → epoch 天数（对齐 Go `time.Now().Unix() / 86400`）。
fn today_unix_days() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64 / 86400)
        .unwrap_or(0)
}

/// 当前 UTC 年份。
fn current_utc_year() -> i64 {
    civil_from_days(today_unix_days()).0
}

/// Howard Hinnant `days_from_civil`：公历日期 → epoch 天数。
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// epoch 天数 → (年, 月, 日)。Howard Hinnant `civil_from_days`。
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn rng_f64() -> f64 {
    rand::rng().random::<f64>()
}

/// Chrome 版本（偏态分布，对齐 Go `ChromeVersion`）。
#[must_use]
pub fn chrome_version() -> i64 {
    // Chrome 144 发布于 2026-01-13。
    let start_version: i64 = 144;
    let time_start: i64 = days_from_civil(2026, 1, 13);
    let time_current: i64 = today_unix_days();
    let time_diff = (time_current - time_start - 35) - (rng_f64().powi(2) * 105.0).floor() as i64;
    start_version + time_diff / 35
}

/// Firefox 版本（对齐 Go `FirefoxVersion`，含其 2024-07-29 锚点）。
#[must_use]
pub fn firefox_version() -> i64 {
    // Firefox 128 ESR：Go 代码锚点为 2024-07-29。
    let time_start: i64 = days_from_civil(2024, 7, 29);
    let time_current: i64 = today_unix_days();
    let time_diff = time_current - time_start - 25 - (rng_f64().powi(2) * 50.0).floor() as i64;
    time_diff / 30 + 128
}

/// curl 版本字符串（对齐 Go `CurlVersion`）。
#[must_use]
pub fn curl_version() -> String {
    // curl 8.0.0 发布于 2023-03-20。
    let time_start: i64 = days_from_civil(2023, 3, 20);
    let time_current: i64 = today_unix_days();
    let time_diff = (time_current - time_start - 60) - (rng_f64().powi(2) * 165.0).floor() as i64;
    format!("8.{}.0", time_diff / 57)
}

/// Safari 版本字符串（对齐 Go `SafariVersion`；索引钳位避免 Go 潜在越界）。
#[must_use]
pub fn safari_version() -> String {
    const SAFARI_MINOR_MAP: [i64; 25] =
        [0, 0, 0, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 5, 5, 6, 6, 6, 6];
    let now_secs: i64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let delayed_days = (rng_f64().powi(3) * 75.0).floor() as i64;
    let mut release_year = current_utc_year();
    let mut split_point = days_from_civil(release_year, 9, 23) + delayed_days;
    if now_secs < split_point * 86400 {
        release_year -= 1;
        split_point = days_from_civil(release_year, 9, 23) + delayed_days;
    }
    let idx = (((now_secs / 86400) - split_point) / 15).max(0) as usize; // 1296000s = 15 天
    let idx = idx.min(SAFARI_MINOR_MAP.len() - 1);
    format!("{}.{}", release_year - 1999, SAFARI_MINOR_MAP[idx])
}

// ===== Chromium 品牌 GREASE（对齐 Go clientHint* 常量）=====

const CLIENT_HINT_GREASE_NA: [&str; 11] = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];
const CLIENT_HINT_VERSION_NA: [&str; 3] = ["8", "99", "24"];
const CLIENT_HINT_SHUFFLE3: [[usize; 3]; 6] =
    [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
const CLIENT_HINT_SHUFFLE4: [[usize; 4]; 24] = [
    [0, 1, 2, 3],
    [0, 1, 3, 2],
    [0, 2, 1, 3],
    [0, 2, 3, 1],
    [0, 3, 1, 2],
    [0, 3, 2, 1],
    [1, 0, 2, 3],
    [1, 0, 3, 2],
    [1, 2, 0, 3],
    [1, 2, 3, 0],
    [1, 3, 0, 2],
    [1, 3, 2, 0],
    [2, 0, 1, 3],
    [2, 0, 3, 1],
    [2, 1, 0, 3],
    [2, 1, 3, 0],
    [2, 3, 0, 1],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [3, 0, 2, 1],
    [3, 1, 0, 2],
    [3, 1, 2, 0],
    [3, 2, 0, 1],
    [3, 2, 1, 0],
];

fn get_greased_ch_invalid_brand(seed: i64) -> String {
    let n = CLIENT_HINT_GREASE_NA.len() as i64;
    let vn = CLIENT_HINT_VERSION_NA.len() as i64;
    format!(
        "\"Not{}A{}Brand\";v=\"{}\"",
        CLIENT_HINT_GREASE_NA[(seed % n) as usize],
        CLIENT_HINT_GREASE_NA[((seed + 1) % n) as usize],
        CLIENT_HINT_VERSION_NA[(seed % vn) as usize],
    )
}

fn get_ungreased_ch_ua(major_version: i64, fork_name: &str) -> Vec<String> {
    let mut base = vec![
        get_greased_ch_invalid_brand(major_version),
        format!("\"Chromium\";v=\"{major_version}\""),
    ];
    match fork_name {
        "chrome" => base.push(format!("\"Google Chrome\";v=\"{major_version}\"")),
        "edge" => base.push(format!("\"Microsoft Edge\";v=\"{major_version}\"")),
        _ => {},
    }
    base
}

fn get_greased_ch_ua(major_version: i64, fork_name: &str) -> String {
    let ungreased = get_ungreased_ch_ua(major_version, fork_name);
    let shuffled: Vec<String> = match ungreased.len() {
        1 => vec![ungreased[0].clone()],
        2 => {
            let mut v = vec![String::new(); 2];
            v[0] = ungreased[1].clone();
            v[1] = ungreased[0].clone();
            v
        },
        3 => {
            let order = CLIENT_HINT_SHUFFLE3[(major_version % 6) as usize];
            let mut v = vec![String::new(); 3];
            for (i, e) in order.iter().enumerate() {
                v[*e] = ungreased[i].clone();
            }
            v
        },
        _ => {
            let order = CLIENT_HINT_SHUFFLE4[(major_version % 24) as usize];
            let mut v = vec![String::new(); 4];
            for (i, e) in order.iter().enumerate() {
                v[*e] = ungreased[i].clone();
            }
            v
        },
    };
    shuffled.join(", ")
}

/// 浏览器 UA 生成结果（对齐 Go var 块的每请求随机版本）。
struct BrowserUA {
    user_agent: &'static str,
}

/// 按浏览器名生成动态版本 UA（H8：grpc 与 ws/xhttp 共享同一实现，
/// 避免同进程 UA 版本自相矛盾）。
pub fn build_user_agent(browser: &str) -> String {
    match browser {
        "chrome" => {
            let v = chrome_version();
            format!(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36"
            )
        },
        "edge" => {
            let v = chrome_version();
            format!(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36 Edg/{v}.0.0.0"
            )
        },
        "firefox" => {
            let v = firefox_version();
            format!(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{v}.0) Gecko/20100101 Firefox/{v}.0"
            )
        },
        "safari" => {
            let v = safari_version();
            format!(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{v} Safari/605.1.15"
            )
        },
        "curl" => format!("curl/{}", curl_version()),
        _ => String::new(),
    }
}

/// 对齐 Go `applyMasqueradedHeaders(header, browser, variant)`。
///
/// `BrowserUA`/`variant` 语义与 Go 完全一致：browser 决定 UA/CH-UA 系，
/// variant 决定 Sec-Fetch/Priority/Cache-Control 上下文头。curl/golang
/// 分支只动 UA（或删 UA）后返回。
pub fn apply_masqueraded_headers(
    headers: &mut Vec<(String, String)>,
    browser: &str,
    variant: &str,
) {
    let ch_major;
    match browser {
        "chrome" | "edge" => {
            let v = chrome_version();
            ch_major = v;
            let fork = if browser == "chrome" { "chrome" } else { "edge" };
            set_header(headers, "Sec-CH-UA", &get_greased_ch_ua(v, fork));
            set_header(headers, "Sec-CH-UA-Mobile", "?0");
            set_header(headers, "Sec-CH-UA-Platform", "\"Windows\"");
            set_header(headers, "DNT", "1");
            set_header(headers, "User-Agent", &build_user_agent(browser));
            set_header(headers, "Accept-Language", "en-US,en;q=0.9");
        },
        "firefox" => {
            set_header(headers, "User-Agent", &build_user_agent("firefox"));
            set_header(headers, "DNT", "1");
            set_header(headers, "Accept-Language", "en-US,en;q=0.5");
            ch_major = 0;
        },
        "safari" => {
            set_header(headers, "User-Agent", &build_user_agent("safari"));
            set_header(headers, "Accept-Language", "en-US,en;q=0.9");
            ch_major = 0;
        },
        "golang" => {
            // 暴露 Go net/http 默认 UA：删除 User-Agent。
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case("User-Agent"));
            return;
        },
        "curl" => {
            set_header(headers, "User-Agent", &build_user_agent("curl"));
            return;
        },
        _ => {
            ch_major = 0;
        },
    }
    let _ = ch_major;

    // Context-specific（variant）。nav：浏览器导航场景（Go browser.go nav case，
    // http CONNECT 出站在用）；fetch：splithttp/xhttp 场景；ws：WebSocket 握手。
    if variant == "nav" {
        if get_header(headers, "Cache-Control").is_none() {
            if browser == "chrome" || browser == "edge" {
                set_header(headers, "Cache-Control", "max-age=0");
            }
        }
        set_header(headers, "Upgrade-Insecure-Requests", "1");
        if get_header(headers, "Accept").is_none() {
            if browser == "chrome" || browser == "edge" {
                set_header(
                    headers,
                    "Accept",
                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                );
            } else if browser == "firefox" || browser == "safari" {
                set_header(
                    headers,
                    "Accept",
                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                );
            }
        }
        set_header(headers, "Sec-Fetch-Site", "none");
        set_header(headers, "Sec-Fetch-Mode", "navigate");
        if browser != "safari" {
            set_header(headers, "Sec-Fetch-User", "?1");
        }
        set_header(headers, "Sec-Fetch-Dest", "document");
        set_header(headers, "Priority", "u=0, i");
    } else if variant == "fetch" {
        set_header(headers, "Sec-Fetch-Mode", "cors");
        set_header(headers, "Sec-Fetch-Dest", "empty");
        set_header(headers, "Sec-Fetch-Site", "same-origin");
        if get_header(headers, "Priority").is_none() {
            let priority = match browser {
                "chrome" | "edge" => Some("u=1, i"),
                "firefox" => Some("u=4"),
                "safari" => Some("u=3, i"),
                _ => None,
            };
            if let Some(p) = priority {
                set_header(headers, "Priority", p);
            }
        }
        if get_header(headers, "Cache-Control").is_none() {
            set_header(headers, "Cache-Control", "no-cache");
        }
        if get_header(headers, "Pragma").is_none() {
            set_header(headers, "Pragma", "no-cache");
        }
        if get_header(headers, "Accept").is_none() {
            set_header(headers, "Accept", "*/*");
        }
    } else if variant == "ws" {
        // ws：WebSocket 握手场景（Go browser.go:221-239）。
        set_header(headers, "Sec-Fetch-Mode", "websocket");
        if browser == "safari" {
            // Safari 在此不遵循 web 标准（Go 原注释）。
            set_header(headers, "Sec-Fetch-Dest", "websocket");
        } else {
            set_header(headers, "Sec-Fetch-Dest", "empty");
        }
        set_header(headers, "Sec-Fetch-Site", "same-origin");
        if get_header(headers, "Cache-Control").is_none() {
            set_header(headers, "Cache-Control", "no-cache");
        }
        if get_header(headers, "Pragma").is_none() {
            set_header(headers, "Pragma", "no-cache");
        }
        if get_header(headers, "Accept").is_none() {
            set_header(headers, "Accept", "*/*");
        }
    }
}

/// 对齐 Go `utils.TryDefaultHeadersWith(header, variant)`：
/// UA 缺省 → chrome 伪装；UA 为浏览器枚举值 → 对应伪装；其他 → 不动。
pub fn try_default_headers_with(headers: &mut Vec<(String, String)>, variant: &str) {
    if get_header(headers, "User-Agent").is_none() {
        apply_masqueraded_headers(headers, "chrome", variant);
    } else {
        let ua = get_header(headers, "User-Agent").unwrap_or_default().to_string();
        match ua.as_str() {
            "chrome" => apply_masqueraded_headers(headers, "chrome", variant),
            "firefox" => apply_masqueraded_headers(headers, "firefox", variant),
            "safari" => apply_masqueraded_headers(headers, "safari", variant),
            "edge" => apply_masqueraded_headers(headers, "edge", variant),
            "curl" => apply_masqueraded_headers(headers, "curl", variant),
            "golang" => apply_masqueraded_headers(headers, "golang", variant),
            _ => {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        get_header(headers, name)
    }

    #[test]
    fn default_headers_use_chrome_fetch_masquerade() {
        let mut h: Vec<(String, String)> = Vec::new();
        try_default_headers_with(&mut h, "fetch");
        let ua = get(&h, "User-Agent").expect("UA must be set");
        assert!(
            ua.starts_with("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/")
                && ua.ends_with(" Safari/537.36"),
            "UA must masquerade as Chrome, got: {ua}"
        );
        assert_eq!(get(&h, "Sec-CH-UA-Mobile"), Some("?0"));
        assert_eq!(get(&h, "Sec-CH-UA-Platform"), Some("\"Windows\""));
        assert_eq!(get(&h, "DNT"), Some("1"));
        assert_eq!(get(&h, "Accept-Language"), Some("en-US,en;q=0.9"));
        assert_eq!(get(&h, "Sec-Fetch-Mode"), Some("cors"));
        assert_eq!(get(&h, "Sec-Fetch-Dest"), Some("empty"));
        assert_eq!(get(&h, "Sec-Fetch-Site"), Some("same-origin"));
        assert_eq!(get(&h, "Priority"), Some("u=1, i"));
        assert_eq!(get(&h, "Cache-Control"), Some("no-cache"));
        assert_eq!(get(&h, "Pragma"), Some("no-cache"));
        assert_eq!(get(&h, "Accept"), Some("*/*"));
        let ch = get(&h, "Sec-CH-UA").expect("Sec-CH-UA must be set");
        assert_eq!(ch.matches(',').count() + 1, 3, "3 brands, got: {ch}");
        assert!(ch.contains("Chromium"), "got: {ch}");
        assert!(ch.contains("Google Chrome"), "got: {ch}");
        assert!(ch.contains("Not"), "GREASE brand present, got: {ch}");
    }

    #[test]
    fn firefox_enum_value_gets_firefox_masquerade() {
        let mut h = vec![("User-Agent".to_string(), "firefox".to_string())];
        try_default_headers_with(&mut h, "fetch");
        let ua = get(&h, "User-Agent").expect("UA");
        assert!(ua.contains("Firefox/"), "got: {ua}");
        assert!(ua.contains("rv:"), "got: {ua}");
        assert_eq!(get(&h, "Accept-Language"), Some("en-US,en;q=0.5"));
        assert!(get(&h, "Sec-CH-UA").is_none(), "firefox has no CH-UA");
        assert_eq!(get(&h, "Priority"), Some("u=4"));
        assert_eq!(get(&h, "Sec-Fetch-Mode"), Some("cors"));
    }

    #[test]
    fn custom_user_agent_is_left_untouched() {
        let mut h = vec![
            ("User-Agent".to_string(), "my-agent/1.2".to_string()),
            ("X-Foo".to_string(), "bar".to_string()),
        ];
        try_default_headers_with(&mut h, "fetch");
        assert_eq!(get(&h, "User-Agent"), Some("my-agent/1.2"));
        assert!(get(&h, "Sec-Fetch-Mode").is_none(), "no variant headers for custom UA");
        assert!(get(&h, "Accept").is_none());
        assert_eq!(get(&h, "X-Foo"), Some("bar"));
    }

    #[test]
    fn golang_enum_value_removes_user_agent() {
        let mut h = vec![("User-Agent".to_string(), "golang".to_string())];
        try_default_headers_with(&mut h, "fetch");
        assert!(get(&h, "User-Agent").is_none());
        assert!(get(&h, "Sec-Fetch-Mode").is_none(), "golang returns before variant");
    }

    #[test]
    fn chrome_version_in_plausible_range() {
        let v = chrome_version();
        assert!((144..=200).contains(&v), "chrome version {v}");
    }

    #[test]
    fn curl_version_shape() {
        let v = curl_version();
        assert!(v.starts_with("8.") && v.ends_with(".0"), "got: {v}");
    }

    #[test]
    fn ws_variant_sets_websocket_fetch_family() {
        let mut h: Vec<(String, String)> = Vec::new();
        try_default_headers_with(&mut h, "ws");
        let ua = get(&h, "User-Agent").expect("UA must be set");
        assert!(
            ua.starts_with("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/")
                && ua.ends_with(" Safari/537.36"),
            "UA must masquerade as Chrome, got: {ua}"
        );
        assert_eq!(get(&h, "Sec-Fetch-Mode"), Some("websocket"));
        assert_eq!(get(&h, "Sec-Fetch-Dest"), Some("empty"));
        assert_eq!(get(&h, "Sec-Fetch-Site"), Some("same-origin"));
        assert_eq!(get(&h, "Cache-Control"), Some("no-cache"));
        assert_eq!(get(&h, "Pragma"), Some("no-cache"));
        assert_eq!(get(&h, "Accept"), Some("*/*"));
        let ch = get(&h, "Sec-CH-UA").expect("Sec-CH-UA must be set");
        assert!(ch.contains("Google Chrome"), "got: {ch}");
    }

    #[test]
    fn ws_variant_respects_existing_context_headers() {
        let mut h = vec![
            ("Cache-Control".to_string(), "max-age=3600".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ];
        try_default_headers_with(&mut h, "ws");
        assert_eq!(get(&h, "Cache-Control"), Some("max-age=3600"));
        assert_eq!(get(&h, "Accept"), Some("application/json"));
        assert_eq!(get(&h, "Pragma"), Some("no-cache"), "only absent ones injected");
    }

    #[test]
    fn set_header_replaces_case_insensitively() {
        let mut h = vec![("connection".to_string(), "keep-alive".to_string())];
        set_header(&mut h, "Connection", "Upgrade");
        assert_eq!(h.len(), 1);
        assert_eq!(get(&h, "Connection"), Some("Upgrade"));
    }
}

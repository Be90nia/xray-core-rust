//! Hysteria 出站服务器选择（Go 扁平形态 + `servers[]` 数组形态统一收口）。
//!
//! 行为参照 = 生产面 `xray-core/src/outbound.rs` `parse_hysteria_config`（选择/回退
//! 语义的唯一事实源），本模块为其**唯一共享实现**：
//! - `version` 在场且 != 2 → 硬错（Go `infra/conf/hysteria.go:20-22` 镜像）；
//! - `servers[]` 在场 → 取 `servers[0]`（空数组硬错）；缺席 → 根对象即扁平形态 （Go
//!   `address`+`port` 原生形态）；两形态并存时 `servers[]` 优先（生产同序）；
//! - `auth`|`password`、`serverName`|`server_name`|`sni` 别名解析，SNI 缺省 = address 原值（host
//!   部分）；
//! - 错误文案与生产面逐字一致（对拍口径，禁二度措辞）。
//!
//! 生产面函数为 `pub(crate)` 不可跨 crate 复用；收口接线时生产面改调此处
//! 删本地副本，保持单一实现（禁第二份语义分叉）。

/// [`select_server`] 产物：拨号目标 + 鉴权 + SNI。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HysteriaServerSelection {
    /// 拨号目标 `host:port`（address 与独立 port 合成，Go `TCPDestination` 语义）。
    pub server_addr: String,
    /// 鉴权 token（`auth`|`password` 别名，缺省空串）。
    pub auth: String,
    /// TLS SNI（`serverName`|`server_name`|`sni` 别名，缺省 = address 原值）。
    pub server_name: String,
}

/// 出站 settings（JSON 对象）→ 服务器选择。
///
/// 缺字段 / 空 `servers[]` / `version` 非法 → `Err`（fail-visible，文案与生产面
/// `parse_hysteria_config` 逐字一致）。
pub fn select_server(settings: &serde_json::Value) -> Result<HysteriaServerSelection, String> {
    if let Some(ver) = settings.get("version").and_then(|x| x.as_i64()) {
        if ver != 2 {
            return Err(format!("hysteria version {ver} not supported (only version 2)"));
        }
    }
    let first = match settings.get("servers").and_then(|v| v.as_array()) {
        Some(servers) => servers.first().ok_or_else(|| "servers array is empty".to_string())?,
        None => settings,
    };
    let address =
        first.get("address").and_then(|v| v.as_str()).ok_or("missing servers[0].address")?;
    let port = first.get("port").and_then(|v| v.as_u64()).ok_or("missing servers[0].port")?;
    let auth =
        first.get("auth").or_else(|| first.get("password")).and_then(|v| v.as_str()).unwrap_or("");
    let server_name = first
        .get("serverName")
        .or_else(|| first.get("server_name"))
        .or_else(|| first.get("sni"))
        .and_then(|v| v.as_str())
        .unwrap_or(address);
    Ok(HysteriaServerSelection {
        server_addr: format!("{address}:{port}"),
        auth: auth.to_owned(),
        server_name: server_name.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// 生产面 `parse_hysteria_config_accepts_go_flat_shape` 同款向量：扁平形态。
    #[test]
    fn flat_shape_matches_production_vectors() {
        let sel = select_server(&json!({
            "address": "example.com", "port": 39622, "version": 2
        }))
        .expect("flat parse");
        assert_eq!(sel.server_addr, "example.com:39622");
        assert_eq!(sel.auth, "", "扁平原生不带 auth（生产由 streamSettings 注入）");
        assert_eq!(sel.server_name, "example.com", "SNI 缺省 = address 原值");
    }

    /// `servers[]` 多服务器 → 取 `servers[0]`（选择行为与生产面一致）。
    #[test]
    fn servers_array_selects_first_of_many() {
        let sel = select_server(&json!({
            "servers": [
                { "address": "a.com", "port": 443, "auth": "pw", "sni": "b.com" },
                { "address": "c.com", "port": 8443, "auth": "other" }
            ]
        }))
        .expect("servers parse");
        assert_eq!(
            (sel.server_addr.as_str(), sel.auth.as_str(), sel.server_name.as_str()),
            ("a.com:443", "pw", "b.com"),
            "servers[0] 选择 + sni 别名（生产同款向量）"
        );
    }

    /// `password` / `server_name` 别名与显式 `serverName` 覆盖。
    #[test]
    fn aliases_resolve_like_production() {
        let sel = select_server(&json!({
            "servers": [
                { "address": "d.com", "port": 443, "password": "pwd", "server_name": "dn.com" }
            ]
        }))
        .expect("alias parse");
        assert_eq!((sel.auth.as_str(), sel.server_name.as_str()), ("pwd", "dn.com"));

        let sel = select_server(&json!({
            "servers": [{ "address": "e.com", "port": 443, "serverName": "en.com" }]
        }))
        .expect("serverName parse");
        assert_eq!(sel.server_name, "en.com", "serverName 别名优先于缺省");
    }

    /// 空数组 / 缺字段 / version 非法 → 硬错，文案与生产面逐字一致。
    #[test]
    fn invalid_inputs_fail_visible_with_production_messages() {
        assert_eq!(select_server(&json!({ "servers": [] })).unwrap_err(), "servers array is empty");
        assert_eq!(
            select_server(&json!({ "servers": [{ "port": 443 }] })).unwrap_err(),
            "missing servers[0].address"
        );
        assert_eq!(
            select_server(&json!({ "servers": [{ "address": "a.com" }] })).unwrap_err(),
            "missing servers[0].port"
        );
        assert_eq!(
            select_server(&json!({ "address": "a.com", "port": 443, "version": 1 })).unwrap_err(),
            "hysteria version 1 not supported (only version 2)"
        );
    }

    /// 两形态并存时 `servers[]` 优先（生产 match 序：servers 先查）。
    #[test]
    fn servers_array_takes_priority_over_flat() {
        let sel = select_server(&json!({
            "address": "flat.com", "port": 1,
            "servers": [{ "address": "arr.com", "port": 2 }]
        }))
        .expect("priority parse");
        assert_eq!(sel.server_addr, "arr.com:2");
    }
}

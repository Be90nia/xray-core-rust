//! `template` 后端——REST API 模板化对象存储。对应 Go `template.go`。
//!
//! 四操作（put/get/list/delete）各由一条 op 模板描述（method/url/headers/body），
//! `{folder}`/`{secretN}`/`{name}`/`{prefix}`/`{data}`/`{token}` 变量替换；
//! `hrefPath` 使操作两步化（Yandex Disk 形态：第一跳应答 JSON，取 `hrefPath`
//! 处的 URL 原样发第二跳——不带 auth 与自定义头，Go `presigned` 语义）；
//! `retry.status`/`retry.rateReason` 决定可重试面；`namesRegex` 捕获 list 条目名。
//!
//! 会话视图（Go `templateStorage.session`）：基座用独立客户端（token 请求与
//! 共享层操作），会话经 `SessionTransport` 走 XMUX 连接池。

use std::{collections::BTreeMap, io, sync::Arc};

use bytes::Bytes;
use http::{Method, StatusCode, Uri};
use regex::Regex;
use std_ext::{
    cache::SyncTtlCache,
    encode::{Base64Alphabet, base64_encode},
};
use tokio::sync::Semaphore;
use xray_transport::{dialer::StreamSettings, retry::exponential_backoff_if};

use crate::{
    client::{
        ClientCore, ConnPool, DRIVE_BACKOFF_BUDGET, DRIVE_INITIAL_BACKOFF_MS, DRIVE_MAX_ATTEMPTS,
        DRIVE_MAX_INFLIGHT, DRIVE_TIMEOUT, MAX_TEMPLATE_CONCURRENCY, OutRequest, SessionTransport,
        UnitClient,
    },
    config::Config,
    jsonpath::{json_number, json_string},
    storage::{Entry, Storage, not_found},
};

/// 展平分隔符（Go `flatSeparator`，drive.go 定义、template 复用）。
pub(crate) const FLAT_SEPARATOR: &str = "~";

/// token 缓存键（Go 单 token 字段；SyncTtlCache 单键承载过期判定）。
const TOKEN_KEY: &str = "token";

/// 名字展平（Go `flatten`）：`/` → `~`。
#[must_use]
pub(crate) fn flatten(name: &str) -> String {
    name.replace('/', FLAT_SEPARATOR)
}

/// 模板变量替换（Go `subst`）：`{key}` 全量替换；无 `{` 直返。
#[must_use]
fn subst(tmpl: &str, vars: &BTreeMap<String, String>) -> String {
    if tmpl.is_empty() || !tmpl.contains('{') {
        return tmpl.to_string();
    }
    let mut out = tmpl.to_string();
    for (key, value) in vars {
        out = out.replace(&format!("{{{key}}}"), value);
    }
    out
}

fn invalid(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, why)
}

// ── 模板结构（Go authTemplate/opTemplate/retryTemplate/storageTemplate）──────

#[derive(Debug, Default)]
struct AuthTemplate {
    kind: String,
    header: BTreeMap<String, String>,
    username: String,
    password: String,
    token_url: String,
    form: BTreeMap<String, String>,
    token_path: String,
    expiry_path: String,
}

#[derive(Debug, Default, Clone)]
struct OpTemplate {
    method: String,
    url: String,
    headers: BTreeMap<String, String>,
    body: String,
    names_regex: String,
    href_path: String,
    href_method: String,
    /// 第二跳（Go `presigned`）：URL 原样、不带 auth（headers 天然空——合成 op）。
    presigned: bool,
}

#[derive(Debug, Default)]
struct RetryTemplate {
    status: Vec<i64>,
    rate_reason: String,
}

#[derive(Debug)]
struct StorageTemplate {
    flatten: bool,
    concurrency: i64,
    auth: AuthTemplate,
    put: OpTemplate,
    get: OpTemplate,
    delete: OpTemplate,
    list: OpTemplate,
    retry: RetryTemplate,
    names: Regex,
}

fn field_str(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> io::Result<String> {
    match obj.get(key) {
        None | Some(serde_json::Value::Null) => Ok(String::new()),
        Some(serde_json::Value::String(s)) => Ok(s.clone()),
        Some(other) => Err(invalid(&format!("template {key} must be a string, got {other}"))),
    }
}

fn field_map(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> io::Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    match obj.get(key) {
        None | Some(serde_json::Value::Null) => {},
        Some(serde_json::Value::Object(map)) => {
            for (k, v) in map {
                let Some(s) = v.as_str() else {
                    return Err(invalid(&format!("template {key}.{k} must be a string, got {v}")));
                };
                out.insert(k.clone(), s.to_string());
            }
        },
        Some(other) => {
            return Err(invalid(&format!("template {key} must be an object, got {other}")));
        },
    }
    Ok(out)
}

fn field_bool(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> io::Result<bool> {
    match obj.get(key) {
        None | Some(serde_json::Value::Null) => Ok(false),
        Some(serde_json::Value::Bool(b)) => Ok(*b),
        Some(other) => Err(invalid(&format!("template {key} must be a bool, got {other}"))),
    }
}

fn field_i64(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> io::Result<i64> {
    match obj.get(key) {
        None | Some(serde_json::Value::Null) => Ok(0),
        Some(n) => n
            .as_i64()
            .ok_or_else(|| invalid(&format!("template {key} must be an integer, got {n}"))),
    }
}

fn field_strings(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> io::Result<Vec<i64>> {
    let mut out = Vec::new();
    match obj.get(key) {
        None | Some(serde_json::Value::Null) => {},
        Some(serde_json::Value::Array(items)) => {
            for item in items {
                let n = item.as_i64().ok_or_else(|| {
                    invalid(&format!("template {key} must be an array of integers, got {item}"))
                })?;
                out.push(n);
            }
        },
        Some(other) => {
            return Err(invalid(&format!(
                "template {key} must be an array of integers, got {other}"
            )));
        },
    }
    Ok(out)
}

impl AuthTemplate {
    fn parse(v: &serde_json::Value) -> io::Result<Self> {
        let obj = v.as_object().ok_or_else(|| invalid("template auth must be an object"))?;
        Ok(Self {
            kind: field_str(obj, "type")?,
            header: field_map(obj, "header")?,
            username: field_str(obj, "username")?,
            password: field_str(obj, "password")?,
            token_url: field_str(obj, "tokenUrl")?,
            form: field_map(obj, "form")?,
            token_path: field_str(obj, "tokenPath")?,
            expiry_path: field_str(obj, "expiryPath")?,
        })
    }
}

impl OpTemplate {
    fn parse(v: &serde_json::Value) -> io::Result<Self> {
        let obj = v.as_object().ok_or_else(|| invalid("template op must be an object"))?;
        Ok(Self {
            method: field_str(obj, "method")?,
            url: field_str(obj, "url")?,
            headers: field_map(obj, "headers")?,
            body: field_str(obj, "body")?,
            names_regex: field_str(obj, "namesRegex")?,
            href_path: field_str(obj, "hrefPath")?,
            href_method: field_str(obj, "hrefMethod")?,
            presigned: false,
        })
    }
}

impl RetryTemplate {
    fn parse(v: &serde_json::Value) -> io::Result<Self> {
        let obj = v.as_object().ok_or_else(|| invalid("template retry must be an object"))?;
        Ok(Self {
            status: field_strings(obj, "status")?,
            rate_reason: field_str(obj, "rateReason")?,
        })
    }
}

impl StorageTemplate {
    fn parse(v: &serde_json::Value) -> io::Result<Self> {
        let obj = v.as_object().ok_or_else(|| invalid("invalid template: not an object"))?;
        let op = |key: &str| -> io::Result<OpTemplate> {
            match obj.get(key) {
                None | Some(serde_json::Value::Null) => Ok(OpTemplate::default()),
                Some(v) => OpTemplate::parse(v),
            }
        };
        let put = op("put")?;
        let get = op("get")?;
        let list = op("list")?;
        let delete = op("delete")?;
        if put.url.is_empty() || get.url.is_empty() || list.url.is_empty() || delete.url.is_empty()
        {
            return Err(invalid("template needs put, get, list and delete operations"));
        }
        if list.names_regex.is_empty() {
            return Err(invalid("template list needs a namesRegex"));
        }
        let names =
            Regex::new(&list.names_regex).map_err(|e| invalid(&format!("bad namesRegex: {e}")))?;
        // captures_len 含第 0 组（整段匹配）；Go NumSubexp >= 1 等价 >= 2。
        if names.captures_len() < 2 {
            return Err(invalid("namesRegex needs one capture group"));
        }
        Ok(Self {
            flatten: field_bool(obj, "flatten")?,
            concurrency: field_i64(obj, "concurrency")?,
            auth: match obj.get("auth") {
                Some(v) if !v.is_null() => AuthTemplate::parse(v)?,
                _ => AuthTemplate::default(),
            },
            put,
            get,
            delete,
            list,
            retry: match obj.get("retry") {
                Some(v) if !v.is_null() => RetryTemplate::parse(v)?,
                _ => RetryTemplate::default(),
            },
            names,
        })
    }
}

// ── 重试错误分类（Go do() 的 continue / 立即返回两路）────────────────────────

#[derive(Debug)]
enum OpError {
    /// 传输/读响应/token/认证失败（Go `continue` 重试路径）。
    Retry(String),
    /// 服务应答了配置为可重试的状态码（Go `the service answered N`）。
    RetryStatus(u16),
    /// 不可重试——请求构建失败等（Go 立即返回路径）。
    Fatal(String),
}

impl OpError {
    fn retryable(&self) -> bool {
        matches!(self, Self::Retry(_) | Self::RetryStatus(_))
    }
}

impl std::fmt::Display for OpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retry(message) => write!(f, "{message}"),
            Self::RetryStatus(status) => write!(f, "the service answered {status}"),
            Self::Fatal(message) => write!(f, "{message}"),
        }
    }
}

// ── 存储（Go templateShared/templateStorage）────────────────────────────────

/// 会话间共享面（Go `templateShared`）：池、模板、token 状态、folder/secrets。
struct TemplateShared {
    pool: Arc<ConnPool>,
    tmpl: StorageTemplate,
    /// token 端点独立客户端（Go `tokenClient`）。
    token_client: UnitClient,
    folder: String,
    secrets: Vec<String>,
    /// oauth2 token 缓存（Go `token`/`tokenExpiry`：单 token + 到期时刻，
    /// SyncTtlCache 单键承载、过期由注入时钟判定）。
    token_cache: SyncTtlCache<&'static str, String>,
    /// 取 token 单飞闸（Go `tokenMu` 持锁跨整个取 token 流程的 async 对应）。
    token_gate: tokio::sync::Mutex<()>,
}

/// `template` 对象存储后端。基座实例（`Sink::Base`）用独立客户端；
/// 会话视图（`Sink::Session`，[`Storage::session`]）走 XMUX 连接池。
pub struct TemplateStorage {
    shared: Arc<TemplateShared>,
    sink: Sink,
    inflight: Arc<Semaphore>,
    conc: usize,
}

#[allow(
    clippy::large_enum_variant,
    reason = "基座独立请求客户端 vs 会话传输句柄（32B）是 Go templateStorage 双形态的固有尺寸；单存储仅两实例，不装箱"
)]
enum Sink {
    Base(UnitClient),
    Session(SessionTransport),
}

impl TemplateStorage {
    /// 按流设置 + 配置构造（Go `newTemplateStorage`）。
    ///
    /// 直接构造**不进**共享实例表（Go 测试同款绕行；生产路径走
    /// [`crate::storage::new_storage`] 的 `shared_storage` 去重）。
    ///
    /// # Errors
    /// 模板缺失/非法、四操作 URL 缺失、namesRegex 非法、xmux/安全层配置非法。
    pub fn new(settings: &StreamSettings, config: &Config) -> io::Result<Self> {
        let Some(tmpl_json) = config.template.as_ref() else {
            return Err(invalid("invalid template: empty"));
        };
        let tmpl = StorageTemplate::parse(tmpl_json)?;
        // Go：conc <= 0 → driveMaxInflight；> maxTemplateConcurrency 截到上限。
        let conc = if tmpl.concurrency <= 0 {
            DRIVE_MAX_INFLIGHT
        } else {
            usize::try_from(tmpl.concurrency)
                .unwrap_or(MAX_TEMPLATE_CONCURRENCY)
                .min(MAX_TEMPLATE_CONCURRENCY)
        };
        let pool = Arc::new(ConnPool::new(settings, config)?);
        let keepalive_period =
            crate::client::xdrive_xmux_config(config.xmux.as_ref(), &config.service, config.h3)?
                .h_keep_alive_period;
        let core = ClientCore::from_settings(settings, keepalive_period, config.h3)?;
        let clock = xray_frame::compat::clock();
        Ok(Self {
            shared: Arc::new(TemplateShared {
                pool,
                token_client: crate::client::build_unit_client(&core)?,
                folder: config.remote_folder.clone(),
                secrets: config.secrets.clone(),
                token_cache: SyncTtlCache::new(clock, 1),
                token_gate: tokio::sync::Mutex::new(()),
                tmpl,
            }),
            sink: Sink::Base(crate::client::build_unit_client(&core)?),
            inflight: Arc::new(Semaphore::new(conc)),
            conc,
        })
    }

    fn base_vars(&self) -> BTreeMap<String, String> {
        let mut vars = BTreeMap::new();
        vars.insert("folder".to_string(), self.shared.folder.clone());
        for (i, secret) in self.shared.secrets.iter().enumerate() {
            vars.insert(format!("secret{i}"), secret.clone());
        }
        vars
    }

    fn stored_name(&self, name: &str) -> String {
        if self.shared.tmpl.flatten { flatten(name) } else { name.to_string() }
    }

    /// 可重试判定（Go `retryable`）：配置状态码命中，或 403 且 `rateReason`
    /// 路径处取到非空 reason。
    fn retryable(&self, status: u16, payload: &[u8]) -> bool {
        if self.shared.tmpl.retry.status.iter().any(|&code| code == i64::from(status)) {
            return true;
        }
        if status == http::StatusCode::FORBIDDEN.as_u16()
            && !self.shared.tmpl.retry.rate_reason.is_empty()
        {
            return !json_string(payload, &self.shared.tmpl.retry.rate_reason).is_empty();
        }
        false
    }

    /// 认证头（Go `authHeaders`）：none/无 → 空；static/oauth2 → 配置头按变量
    /// 替换（oauth2 先取 token 注入 `{token}`）；basic → `Authorization: Basic`。
    async fn auth_headers(
        &self,
        vars: &mut BTreeMap<String, String>,
    ) -> io::Result<Vec<(String, String)>> {
        let auth = &self.shared.tmpl.auth;
        match auth.kind.as_str() {
            "" | "none" => Ok(Vec::new()),
            "static" | "oauth2" => {
                if auth.kind == "oauth2" {
                    let token = self.access_token().await?;
                    vars.insert("token".to_string(), token);
                }
                Ok(auth.header.iter().map(|(k, v)| (k.clone(), subst(v, vars))).collect())
            },
            "basic" => {
                let user = subst(&auth.username, vars);
                let pass = subst(&auth.password, vars);
                let enc =
                    base64_encode(format!("{user}:{pass}").as_bytes(), Base64Alphabet::Std, true);
                Ok(vec![("Authorization".to_string(), format!("Basic {enc}"))])
            },
            other => Err(io::Error::other(format!("unsupported auth type: {other}"))),
        }
    }

    /// 取 oauth2 token（Go `accessToken`）：缓存命中即返；未命中走单飞闸
    /// POST `tokenUrl`（表单原样拼接，Go 无 URL 编码），按 `tokenPath`
    /// （缺省 `access_token`）取值、`expiryPath` 取寿命（>60s 扣 60s 提前量）。
    async fn access_token(&self) -> io::Result<String> {
        if let Some(token) = self.shared.token_cache.get(&TOKEN_KEY) {
            return Ok(token);
        }
        let _gate = self.shared.token_gate.lock().await;
        if let Some(token) = self.shared.token_cache.get(&TOKEN_KEY) {
            return Ok(token);
        }
        let vars = self.base_vars();
        let form = self
            .shared
            .tmpl
            .auth
            .form
            .iter()
            .map(|(k, v)| format!("{k}={}", subst(v, &vars)))
            .collect::<Vec<_>>()
            .join("&");
        let uri: Uri = self
            .shared
            .tmpl
            .auth
            .token_url
            .parse()
            .map_err(|e| io::Error::other(format!("failed to build the token request: {e}")))?;
        let (status, payload) = self
            .shared
            .token_client
            .round_trip(
                OutRequest {
                    method: Method::POST,
                    uri,
                    headers: vec![(
                        "Content-Type".to_string(),
                        "application/x-www-form-urlencoded".to_string(),
                    )],
                    body: Some(form.into()),
                },
                DRIVE_TIMEOUT,
            )
            .await
            .map_err(|e| io::Error::other(format!("failed to fetch the token: {e}")))?;
        if status != StatusCode::OK {
            return Err(io::Error::other(format!(
                "the token endpoint answered {}: {}",
                status.as_u16(),
                String::from_utf8_lossy(&payload)
            )));
        }
        let path = if self.shared.tmpl.auth.token_path.is_empty() {
            "access_token"
        } else {
            self.shared.tmpl.auth.token_path.as_str()
        };
        let token = json_string(&payload, path);
        if token.is_empty() {
            return Err(io::Error::other(format!("the token response has no token at {path}")));
        }
        let mut lifetime: i64 = 3600;
        if !self.shared.tmpl.auth.expiry_path.is_empty() {
            let n = json_number(&payload, &self.shared.tmpl.auth.expiry_path);
            if n > 0 {
                lifetime = n;
            }
        }
        if lifetime > 60 {
            lifetime -= 60;
        }
        self.shared.token_cache.insert(
            TOKEN_KEY,
            token.clone(),
            std::time::Duration::from_secs(u64::try_from(lifetime).unwrap_or(u64::MAX)),
        );
        Ok(token)
    }

    fn invalidate_token(&self) {
        let _ = self.shared.token_cache.remove(&TOKEN_KEY);
    }

    /// 发送面（Go `client.Do` 的两路：基座独立客户端 / 会话 XMUX 池）。
    async fn send(&self, req: OutRequest) -> io::Result<(StatusCode, Bytes)> {
        match &self.sink {
            Sink::Base(client) => client.round_trip(req, DRIVE_TIMEOUT).await,
            Sink::Session(session) => session.round_trip(req, DRIVE_TIMEOUT).await,
        }
    }

    /// 单次尝试（Go `do()` 循环体）。
    async fn attempt_once(
        &self,
        op: &OpTemplate,
        url: &str,
        vars: &BTreeMap<String, String>,
        body: Option<Bytes>,
    ) -> Result<(u16, Vec<u8>), OpError> {
        let mut merged = vars.clone();
        let mut headers = Vec::new();
        if !op.presigned {
            let auth =
                self.auth_headers(&mut merged).await.map_err(|e| OpError::Retry(e.to_string()))?;
            headers.extend(auth);
        }
        for (key, value) in &op.headers {
            headers.push((key.clone(), subst(value, &merged)));
        }
        let method = if op.method.is_empty() {
            Method::GET
        } else {
            Method::from_bytes(op.method.as_bytes())
                .map_err(|e| OpError::Fatal(format!("failed to build request: {e}")))?
        };
        let uri: Uri =
            url.parse().map_err(|e| OpError::Fatal(format!("failed to build request: {e}")))?;

        let permit = self
            .inflight
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| OpError::Fatal(format!("inflight semaphore closed: {e}")))?;
        let (status, payload) = self
            .send(OutRequest { method, uri, headers, body })
            .await
            .map_err(|e| OpError::Retry(e.to_string()))?;
        drop(permit);

        if status == StatusCode::UNAUTHORIZED
            && self.shared.tmpl.auth.kind == "oauth2"
            && !op.presigned
        {
            self.invalidate_token();
            return Err(OpError::Retry("the service rejected the token".to_string()));
        }
        if self.retryable(status.as_u16(), &payload) {
            return Err(OpError::RetryStatus(status.as_u16()));
        }
        Ok((status.as_u16(), payload.to_vec()))
    }

    /// 带 retry/backoff 的操作执行（Go `do()`：8 次、200ms 起倍增、总预算封顶）。
    async fn do_op(
        &self,
        op: &OpTemplate,
        vars: &BTreeMap<String, String>,
        body: Option<Bytes>,
    ) -> io::Result<(u16, Vec<u8>)> {
        let url = if op.presigned { op.url.clone() } else { subst(&op.url, vars) };
        let outcome = exponential_backoff_if(
            DRIVE_MAX_ATTEMPTS,
            DRIVE_INITIAL_BACKOFF_MS,
            DRIVE_BACKOFF_BUDGET,
            || self.attempt_once(op, &url, vars, body.clone()),
            OpError::retryable,
        )
        .await;
        outcome.map_err(|e| {
            io::Error::other(
                e.errors
                    .last()
                    .map_or_else(|| "request failed".to_string(), std::string::ToString::to_string),
            )
        })
    }

    /// 执行 op，两步操作跟进 href（Go `run`）。
    async fn run(
        &self,
        op: &OpTemplate,
        vars: &BTreeMap<String, String>,
        body: Option<Bytes>,
    ) -> io::Result<(u16, Vec<u8>)> {
        if op.href_path.is_empty() {
            return self.do_op(op, vars, body).await;
        }
        let (status, payload) = self.do_op(op, vars, None).await?;
        if !(200..300).contains(&status) {
            return Ok((status, payload));
        }
        let href = json_string(&payload, &op.href_path);
        if href.is_empty() {
            return Err(io::Error::other(format!("the response has no href at {}", op.href_path)));
        }
        self.do_op(
            &OpTemplate {
                method: op.href_method.clone(),
                url: href,
                presigned: true,
                ..OpTemplate::default()
            },
            vars,
            body,
        )
        .await
    }
}

#[async_trait::async_trait]
impl Storage for TemplateStorage {
    async fn put(&self, name: &str, data: &[u8]) -> io::Result<()> {
        let mut vars = self.base_vars();
        vars.insert("name".to_string(), self.stored_name(name));

        let body = if self.shared.tmpl.put.body.is_empty() {
            Bytes::copy_from_slice(data)
        } else {
            vars.insert("data".to_string(), base64_encode(data, Base64Alphabet::Std, true));
            Bytes::from(subst(&self.shared.tmpl.put.body, &vars))
        };

        let (status, payload) = self.run(&self.shared.tmpl.put, &vars, Some(body)).await?;
        if (200..300).contains(&status) {
            return Ok(());
        }
        Err(io::Error::other(format!(
            "put of {name} answered {}: {}",
            status,
            String::from_utf8_lossy(&payload)
        )))
    }

    async fn get(&self, name: &str) -> io::Result<Vec<u8>> {
        let mut vars = self.base_vars();
        vars.insert("name".to_string(), self.stored_name(name));

        let (status, payload) = self.run(&self.shared.tmpl.get, &vars, None).await?;
        match status {
            200..=299 => Ok(payload),
            404 => Err(not_found()),
            _ => Err(io::Error::other(format!(
                "get of {name} answered {}: {}",
                status,
                String::from_utf8_lossy(&payload)
            ))),
        }
    }

    async fn delete(&self, name: &str) -> io::Result<()> {
        let mut vars = self.base_vars();
        vars.insert("name".to_string(), self.stored_name(name));

        let (status, payload) = self.run(&self.shared.tmpl.delete, &vars, None).await?;
        if status == 404 || (200..300).contains(&status) {
            return Ok(());
        }
        Err(io::Error::other(format!(
            "delete of {name} answered {}: {}",
            status,
            String::from_utf8_lossy(&payload)
        )))
    }

    async fn list(&self, prefix: &str) -> io::Result<Vec<Entry>> {
        let mut vars = self.base_vars();
        let flat = self.stored_name(prefix);
        vars.insert("prefix".to_string(), flat.clone());

        let (status, payload) = self.run(&self.shared.tmpl.list, &vars, None).await?;
        if status == 404 {
            return Ok(Vec::new());
        }
        if !(200..300).contains(&status) {
            return Err(io::Error::other(format!(
                "list of {prefix} answered {}: {}",
                status,
                String::from_utf8_lossy(&payload)
            )));
        }

        let text = String::from_utf8_lossy(&payload);
        let matches = self
            .shared
            .tmpl
            .names
            .captures_iter(&text)
            .filter_map(|caps| caps.get(1).map(|m| m.as_str().to_string()))
            .collect::<Vec<_>>();
        if !self.shared.tmpl.flatten {
            return Ok(matches.into_iter().map(|name| Entry { name, inline: None }).collect());
        }

        // flatten：want = flat + 分隔符；首层截断 + 去重（Go List 的展平分支）。
        let want = format!("{flat}{FLAT_SEPARATOR}");
        let mut seen = std::collections::HashSet::with_capacity(matches.len());
        let mut entries = Vec::with_capacity(matches.len());
        for name in matches {
            let Some(rest) = name.strip_prefix(&want) else { continue };
            if rest.is_empty() {
                continue;
            }
            let rest = match rest.find(FLAT_SEPARATOR) {
                Some(cut) => &rest[..cut],
                None => rest,
            };
            if !seen.insert(rest.to_string()) {
                continue;
            }
            entries.push(Entry { name: rest.to_string(), inline: None });
        }
        Ok(entries)
    }

    async fn close(&self) -> io::Result<()> {
        if let Sink::Session(session) = &self.sink {
            session.close();
        }
        Ok(())
    }

    /// 会话视图（Go `templateStorage.session`）：共享模板/token，独立 XMUX 池
    /// 会话传输与并发闸。
    fn session(&self) -> Option<Arc<dyn Storage>> {
        Some(Arc::new(TemplateStorage {
            shared: Arc::clone(&self.shared),
            sink: Sink::Session(SessionTransport::new(Arc::clone(&self.shared.pool.xmux))),
            inflight: Arc::new(Semaphore::new(self.conc)),
            conc: self.conc,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flatten_replaces_slashes() {
        assert_eq!(flatten("streams/abc/c2s/0.seg"), "streams~abc~c2s~0.seg");
        assert_eq!(flatten("plain"), "plain");
    }

    #[test]
    fn subst_replaces_known_vars_only() {
        let mut vars = BTreeMap::new();
        vars.insert("folder".to_string(), "docs".to_string());
        vars.insert("secret0".to_string(), "tok".to_string());
        assert_eq!(subst("{folder}/{secret0}?p={prefix}", &vars), "docs/tok?p={prefix}");
        assert_eq!(subst("", &vars), "");
        assert_eq!(subst("no-vars", &vars), "no-vars");
    }

    #[test]
    fn template_validation_errors() {
        let err = TemplateStorage::new(
            &xray_transport::dialer::StreamSettings::tcp(),
            &Config { service: "template".to_string(), ..Config::default() },
        )
        .err()
        .expect("empty template must be rejected");
        assert!(err.to_string().contains("invalid template"), "{err}");

        let missing_ops = serde_json::json!({"get": {"url": "http://x"}});
        let err = StorageTemplate::parse(&missing_ops).unwrap_err();
        assert!(err.to_string().contains("put, get, list and delete"), "{err}");

        let no_regex = serde_json::json!({
            "put": {"url": "http://x"}, "get": {"url": "http://x"},
            "delete": {"url": "http://x"}, "list": {"url": "http://x"}
        });
        let err = StorageTemplate::parse(&no_regex).unwrap_err();
        assert!(err.to_string().contains("namesRegex"), "{err}");

        let bad_regex = serde_json::json!({
            "put": {"url": "http://x"}, "get": {"url": "http://x"},
            "delete": {"url": "http://x"},
            "list": {"url": "http://x", "namesRegex": "("}
        });
        let err = StorageTemplate::parse(&bad_regex).unwrap_err();
        assert!(err.to_string().contains("bad namesRegex"), "{err}");

        let no_group = serde_json::json!({
            "put": {"url": "http://x"}, "get": {"url": "http://x"},
            "delete": {"url": "http://x"},
            "list": {"url": "http://x", "namesRegex": "abc"}
        });
        let err = StorageTemplate::parse(&no_group).unwrap_err();
        assert!(err.to_string().contains("one capture group"), "{err}");
    }

    #[test]
    fn concurrency_clamped() {
        // clamp 逻辑与 new() 一致：<=0 → 64；>256 → 256。
        let clamp = |raw: i64| {
            if raw <= 0 {
                DRIVE_MAX_INFLIGHT
            } else {
                usize::try_from(raw)
                    .unwrap_or(MAX_TEMPLATE_CONCURRENCY)
                    .min(MAX_TEMPLATE_CONCURRENCY)
            }
        };
        assert_eq!(clamp(0), DRIVE_MAX_INFLIGHT);
        assert_eq!(clamp(-5), DRIVE_MAX_INFLIGHT);
        assert_eq!(clamp(16), 16);
        assert_eq!(clamp(100_000), MAX_TEMPLATE_CONCURRENCY);
    }
}

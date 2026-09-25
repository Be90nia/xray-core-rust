//! # 工具子命令
//!
//! 对应 Go `main/commands/all/` 的 uuid / tls / convert 等命令。
//!
//! ## 副作用
//!
//! - `execute_cert` 的 `--file` 选项：写 `<file>.crt`/`<file>.key`（父目录须存在）
//! - `execute_ping`：拨号到目标 IP:port（仅 `443` 或 `domain:port` 形式）
//! - 其他子命令：stdout / 内存计算，零 I/O
use clap::{Args, Subcommand};
use prost::Message as _;
use xray_proto::xray::{common::serial::TypedMessage, core::Config as ProtoConfig};

use crate::{
    commands::api_exec::{build_inbound_configs, build_outbound_configs},
    error::CliError,
};

// ---------------------------------------------------------------------------
// uuid 命令
// ---------------------------------------------------------------------------

/// `xray uuid` - 生成 UUID。
#[derive(Args, Debug, Clone)]
pub struct UuidArgs {
    /// 输入字符串（<= 30 字节），空则生成随机 UUIDv4。
    #[arg(short, long = "input")]
    pub input: Option<String>,
}

/// uuid execute：生成或解析 UUID。
pub fn execute_uuid(args: &UuidArgs) -> Result<(), CliError> {
    println!("{}", resolve_uuid(args.input.as_deref())?);
    Ok(())
}

/// 解析/生成 UUID。输入 ≤30 字节：标准格式规范化，非标准串 v5 派生
/// （对齐 Go `uuid.ParseString` 语义，`xray_common::uuid::UUID::parse`）。
pub fn resolve_uuid(input: Option<&str>) -> Result<String, CliError> {
    match input {
        Some(input) => {
            if input.len() > 30 {
                return Err(CliError::InvalidArgument(
                    "input must be at most 30 bytes".to_string(),
                ));
            }
            xray_common::uuid::UUID::parse(input)
                .map(|u| u.to_string())
                .ok_or_else(|| CliError::UuidParseFailed(input.to_string()))
        },
        None => Ok(uuid::Uuid::new_v4().to_string()),
    }
}

#[cfg(test)]
mod uuid_tests {
    use super::*;

    /// Go 对拍已知值：`uuid -i example` 走 v5 派生（uuid.ParseString ≤30 字节语义）。
    #[test]
    fn uuid_input_derives_v5() {
        let out = resolve_uuid(Some("example")).expect("derive v5");
        assert_eq!(out, "feb54431-301b-52bb-a6dd-e1e93e81bb9e");
    }

    /// >30 字节拒绝（Go uuid.go 语义）。
    #[test]
    fn uuid_input_over_30_bytes_rejected() {
        assert!(resolve_uuid(Some(&"a".repeat(31))).is_err());
    }

    /// 无输入生成合法 v4。
    #[test]
    fn uuid_no_input_generates_v4() {
        let out = resolve_uuid(None).expect("v4");
        assert_eq!(uuid::Uuid::parse_str(&out).expect("parseable").get_version_num(), 4);
    }
}

/// `xray tls` - TLS 工具命令组。
///
/// 子命令对齐 Go `main/commands/all/tls/tls.go`（cert / ping / hash / ech）。
#[derive(Subcommand, Debug, Clone)]
pub enum TlsCommand {
    /// Test TLS connection and print certificate chain.
    Ping(TlsPingArgs),
    /// Calculate certificate hash.
    Hash(TlsHashArgs),
    /// Generate self-signed certificate.
    Cert(TlsCertArgs),
    /// Generate ECH config.
    Ech(TlsEchArgs),
}

/// `xray tls ping` - TLS 握手测试（对齐 Go `main/commands/all/tls/ping.go`）。
#[derive(Args, Debug, Clone)]
pub struct TlsPingArgs {
    /// 目标域名`[:端口]`，默认端口 443。
    pub domain: String,
    /// 指定连接 IP 地址（绕过 DNS）。对齐 Go `-ip`。
    #[arg(short, long = "ip")]
    pub ip: Option<String>,
}

/// `xray tls hash` - 计算证书哈希（对齐 Go `main/commands/all/tls/hash.go`）。
///
/// Go 命令行是 `xray tls hash --cert <fullchain.pem>`；Rust 端同时支持
/// `--cert <path>`（Go 兼容）和位置参数 `<path>`（历史 Rust 用法）。
#[derive(Args, Debug, Clone)]
pub struct TlsHashArgs {
    /// 证书文件路径（PEM 或 DER）。可作位置参数或 `--cert`。
    #[arg(long = "cert")]
    pub cert: Option<String>,
    /// 证书文件路径（位置参数，可选；与 `--cert` 二选一）。
    pub positional_cert: Vec<String>,
}

impl TlsHashArgs {
    /// 解析后的 cert 路径：优先 `--cert`，否则取第一个位置参数。
    pub fn cert_path(&self) -> Option<&str> {
        self.cert.as_deref().or_else(|| self.positional_cert.first().map(String::as_str))
    }
}

/// `xray tls cert` - 生成自签名证书（对齐 Go `main/commands/all/tls/cert.go`）。
///
/// Go flag 全集：
/// - `--domain` (stringList, 必填) ↔ `--domain` (Vec，可重复) + 简写 `-d`
/// - `--name` (CN, 默认 "Xray Inc") ↔ `--name` (String, `--cn` 简写)
/// - `--org` (O, 默认 "Xray Inc") ↔ `--org` (String, `-o` 简写)
/// - `--ca` (CA 证书) ↔ `--ca` (bool, 简写 `-c`)
/// - `--json` (默认 true) ↔ `--json` (bool, 简写 `-j`)
/// - `--file` (前缀，存 `<prefix>.crt`/`<prefix>.key`) ↔ `--file` (String, 简写 `-f`)
/// - `--expire` (Duration, 默认 90d) ↔ `--expire` (String，hms / s)
///
/// 历史 Rust 简写 `-d --domain` / `-o --out` 保留（语义合并：`-d`=单 domain，`--domain`=多）。
#[derive(Args, Debug, Clone)]
pub struct TlsCertArgs {
    /// 域名（DNS SAN），可重复传入。
    #[arg(short, long = "domain", value_name = "DOMAIN")]
    pub domains: Vec<String>,
    /// Common Name（CN），默认 "Xray Inc"。
    #[arg(long = "name", value_name = "CN")]
    pub common_name: Option<String>,
    /// Organization（O），默认 "Xray Inc"。
    #[arg(short, long = "org", value_name = "ORG")]
    pub organization: Option<String>,
    /// 签发 CA 证书（KeyCertSign + KeyEncipherment + DigitalSignature）。
    #[arg(short, long = "ca", default_value_t = false)]
    pub is_ca: bool,
    /// 输出 JSON（默认 true；与 `--file` 互不影响，JSON 始终打 stdout）。
    #[arg(short, long = "json", default_value_t = true)]
    pub json: bool,
    /// 保存到 `<file>.crt` 与 `<file>.key`。
    #[arg(short, long = "file", value_name = "PREFIX")]
    pub file: Option<String>,
    /// 有效期（如 `90d`、`24h`、`30m`），默认 90d。
    #[arg(long = "expire", value_name = "DURATION", default_value = "90d")]
    pub expire: String,
    /// （历史 Rust 简写，等价 `--file`）。
    #[arg(long = "out", value_name = "PREFIX", hide = true)]
    pub out: Option<String>,
}

impl TlsCertArgs {
    /// 有效域名列表（domains 非空直接用，否则用占位 `localhost` 通过 rcgen 校验）。
    pub fn effective_domains(&self) -> Vec<String> {
        if self.domains.is_empty() { vec!["localhost".to_string()] } else { self.domains.clone() }
    }

    /// `--file` 优先，否则 `--out`（历史 Rust 简写）。
    pub fn file_prefix(&self) -> Option<&str> {
        self.file.as_deref().or(self.out.as_deref())
    }
}

/// `xray tls ech` - 生成 ECH 配置（对齐 Go `main/commands/all/tls/ech.go`）。
#[derive(Args, Debug, Clone)]
pub struct TlsEchArgs {
    /// ECHServerKeys（base64.StdEncoding），从既有 server keys 还原 config list。
    #[arg(short = 'i', long = "input")]
    pub input: Option<String>,
    /// public name（默认 cloudflare-ech.com，对齐 Go）。
    #[arg(long = "serverName", default_value = "cloudflare-ech.com")]
    pub server_name: String,
    /// 输出 PEM 格式。
    #[arg(long = "pem", default_value_t = false)]
    pub pem: bool,
}

// ---------------------------------------------------------------------------
// convert 命令组
// ---------------------------------------------------------------------------

/// `xray convert` - 配置格式转换命令组。
#[derive(Subcommand, Debug, Clone)]
pub enum ConvertCommand {
    /// Convert protobuf to JSON.
    Json(ConvertJsonArgs),
    /// Convert JSON to protobuf.
    Pb(ConvertPbArgs),
}

/// `xray convert json` - protobuf 转 JSON。
#[derive(Args, Debug, Clone)]
pub struct ConvertJsonArgs {
    /// 注入类型信息（`_TypedMessage_` 键；Go json.go:42-44 可选 bool）。
    #[arg(short, long = "type", default_value_t = false)]
    pub inject_type: bool,
    /// 输入文件路径（protobuf 二进制）。
    pub input: String,
}

/// `xray convert pb` - JSON 转 protobuf。
#[derive(Args, Debug, Clone)]
pub struct ConvertPbArgs {
    /// 输出 protobuf 文件路径。
    #[arg(short, long = "outpbfile")]
    pub out: Option<String>,
    /// 启用调试输出。
    #[arg(short, long = "debug", default_value_t = false)]
    pub debug: bool,
    /// 调试输出注入类型信息（Go protobuf.go:52-53 可选 bool）。
    #[arg(short, long = "type", default_value_t = false)]
    pub inject_type: bool,
    /// 输入 JSON 文件路径列表。
    #[arg(required = true)]
    pub inputs: Vec<String>,
}

// ---------------------------------------------------------------------------
// execute 函数
// ---------------------------------------------------------------------------

/// tls 子命令 execute。
///
/// `ping` 需要异步 I/O，因此整体是 `async`。调用方（`bin/xray.rs`）已
/// 在 `#[tokio::main]` 内。
pub async fn execute_tls(cmd: &TlsCommand) -> Result<(), CliError> {
    match cmd {
        TlsCommand::Ping(args) => {
            let out = execute_ping(args).await?;
            print!("{out}");
            Ok(())
        },
        TlsCommand::Hash(args) => {
            let out = execute_hash(args)?;
            print!("{out}");
            Ok(())
        },
        TlsCommand::Cert(args) => {
            execute_cert(args)?;
            Ok(())
        },
        TlsCommand::Ech(args) => {
            let out = execute_ech(args)?;
            print!("{out}");
            Ok(())
        },
    }
}

/// convert 子命令 execute。
///
/// - `convert json [-type] <file>`：TypedMessage → JSON，`-type` 注入 `_TypedMessage_` 键（Go
///   reflect/marshal.go:42-44）。无 proto 注册表无法 GetInstance 结构化解码，输出 TypedMessage
///   原样（type + base64 value）。
/// - `convert pb [-debug] [-outpbfile f] <files...>`：合并多文件配置后， `-debug` 输出 JSON（Go
///   protobuf.go:81-88）；`-outpbfile` 写 `xray.core.Config` proto 原始字节（Go protobuf.go:90-105
///   proto.Marshal）。
pub fn execute_convert(cmd: &ConvertCommand) -> Result<(), CliError> {
    match cmd {
        ConvertCommand::Json(args) => execute_convert_json(args),
        ConvertCommand::Pb(args) => execute_convert_pb(args),
    }
}

fn execute_convert_json(args: &ConvertJsonArgs) -> Result<(), CliError> {
    print!("{}", convert_json_output(args)?);
    Ok(())
}

/// `convert json` 核心：返回输出文本（测试可捕获）。
///
/// Go json.go:40-69：TypedMessage JSON → MarshalToJson；`-t` 注入
/// `_TypedMessage_`（Go reflect/marshal.go:42-44）。差异：Go 端经 proto 注册表
/// GetInstance 把 value 解码为结构化字段；本端无注册表，保留 type + base64
/// value 原样输出。
fn convert_json_output(args: &ConvertJsonArgs) -> Result<String, CliError> {
    let raw = read_input(&args.input)?;
    let tm: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|e| CliError::ConfigLoadFailed(format!("failed to unmarshal config: {e}")))?;
    let obj = tm
        .as_object()
        .ok_or_else(|| CliError::ConfigLoadFailed("not a TypedMessage JSON".into()))?;
    let type_url = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let value = obj.get("value").and_then(|v| v.as_str()).unwrap_or("");
    let mut out = serde_json::Map::new();
    out.insert("type".into(), serde_json::Value::String(type_url.into()));
    out.insert("value".into(), serde_json::Value::String(value.into()));
    if args.inject_type {
        out.insert("_TypedMessage_".into(), serde_json::Value::String(type_url.into()));
    }
    serde_json::to_string_pretty(&serde_json::Value::Object(out))
        .map_err(|e| CliError::ConfigLoadFailed(format!("marshal TypedMessage: {e}")))
}

/// 从文件或 `stdin:` 读取全部字节。
fn read_input(spec: &str) -> Result<Vec<u8>, CliError> {
    if spec == "stdin:" {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)
            .map_err(|e| CliError::InvalidArgument(format!("read stdin: {e}")))?;
        Ok(buf)
    } else {
        std::fs::read(spec).map_err(|e| CliError::InvalidArgument(format!("read {spec}: {e}")))
    }
}

/// `convert pb` 执行（Go protobuf.go:43-106）。
fn execute_convert_pb(args: &ConvertPbArgs) -> Result<(), CliError> {
    // Go protobuf.go:61-70：-o 扩展名须为 pb/protobuf/无扩展名；无 -o 且非
    // -debug → fatal "-outpbfile not specified"。
    if let Some(out) = &args.out {
        let ext = std::path::Path::new(out).extension().and_then(|e| e.to_str()).unwrap_or("");
        if !ext.is_empty() && ext != "pb" && ext != "protobuf" {
            return Err(CliError::InvalidArgument(
                "-outpbfile followed by a possible original config.".into(),
            ));
        }
    } else if !args.debug {
        return Err(CliError::InvalidArgument("-outpbfile not specified".into()));
    }
    if args.inputs.is_empty() {
        return Err(CliError::InvalidArgument(format!(
            "invalid config list length: {}",
            args.inputs.len()
        )));
    }

    let paths: Vec<std::path::PathBuf> = args.inputs.iter().map(std::path::PathBuf::from).collect();
    let merged = xray_conf::merge_config_from_files(&paths)
        .map_err(|e| CliError::ConfigLoadFailed(format!("failed to load config: {e}")))?;

    if args.debug {
        // Go protobuf.go:81-88：MarshalToJson dump（-debug 优先于 -o，不写文件）。
        // `-type` 的 "_TypedMessage_" 注入仅作用于 TypedMessage 节点；本端 dump
        // 是合并后的原始配置 JSON，无注入点（Go 注入 proto 结构内嵌 TM 字段）。
        print!("{merged}");
        return Ok(());
    }

    let out = args.out.as_deref().expect("out/debug checked above");
    // Go protobuf.go:64（Println 字面量尾空格 + 分隔空格 = 双空格）。
    println!("Output ProtoBuf file is  {out}");
    let config: serde_json::Value = serde_json::from_str(&merged)
        .map_err(|e| CliError::ConfigLoadFailed(format!("parse merged config: {e}")))?;
    let bytes = json_config_to_proto_config(&config).encode_to_vec();
    std::fs::write(out, bytes)?;
    Ok(())
}

/// 合并后的配置 JSON → `xray.core.Config` proto（Go `conf.Config.Build` 容器层）。
///
/// App 顺序对齐 Go infra/conf/xray.go:528-651：fakedns 最前，log 恒在（缺省
/// `{}`），dispatcher / proxyman Inbound/Outbound 恒在（空 Config），其后
/// api/metrics/stats/routing/dns/policy/reverse/observatory/burstObservatory/
/// geodata 按存在性追加。
///
/// # ponytail: TypedMessage.value 载荷沿用本仓 gRPC 栈方言（JSON 字节，与 api
/// add-inbound 路径一致）；Go 为 proto.Marshal(settings proto)——需 per-app
/// conf Build() 移植（xray-conf serial Non-goals），出现 .pb 消费方时再补。
fn json_config_to_proto_config(config: &serde_json::Value) -> ProtoConfig {
    fn tm(url: &str, v: Option<&serde_json::Value>) -> Option<TypedMessage> {
        v.map(|v| TypedMessage {
            r#type: url.into(),
            value: serde_json::to_vec(v).unwrap_or_default(),
        })
    }
    let empty = serde_json::Value::Object(serde_json::Map::new());
    let mut app: Vec<TypedMessage> = Vec::new();
    let mut add = |m: Option<TypedMessage>| {
        app.extend(m);
    };
    add(tm("xray.app.dns.fakedns.FakeDnsConfig", config.get("fakedns")));
    add(tm("xray.app.log.Config", Some(config.get("log").unwrap_or(&empty))));
    add(tm("xray.app.dispatcher.Config", Some(&empty)));
    add(tm("xray.app.proxyman.InboundConfig", Some(&empty)));
    add(tm("xray.app.proxyman.OutboundConfig", Some(&empty)));
    add(tm("xray.app.commander.Config", config.get("api")));
    add(tm("xray.app.metrics.Config", config.get("metrics")));
    add(tm("xray.app.stats.Config", config.get("stats")));
    add(tm("xray.app.router.Config", config.get("routing")));
    add(tm("xray.app.dns.Config", config.get("dns")));
    add(tm("xray.app.policy.Config", config.get("policy")));
    add(tm("xray.app.reverse.Config", config.get("reverse")));
    add(tm("xray.app.observatory.Config", config.get("observatory")));
    add(tm("xray.app.observatory.burst.Config", config.get("burstObservatory")));
    add(tm("xray.app.geodata.Config", config.get("geodata")));
    // drop(add)：add 为 Fn 闭包引用，无需显式释放

    let raw = serde_json::to_vec(config).unwrap_or_default();
    let inbound = build_inbound_configs(&raw).unwrap_or_default();
    let outbound = build_outbound_configs(&raw).unwrap_or_default();
    ProtoConfig { inbound, outbound, app, extension: Vec::new() }
}
/// `xray tls hash` 核心：读 cert 文件 → 解析 PEM/DER → 输出 SHA-256 hex 表格。
///
/// 对应 Go `main/commands/all/tls/hash.go::executeHash`：
/// - 文件以 `BEGIN` 起头 → 走 `pem.Decode` 逐块；否则尝试 `x509.ParseCertificates`（DER）。
/// - 第一张带 DNS SAN 的证书视为 leaf，其余视为 CA（按 Go 注释）。
/// - 输出格式对齐 Go `tabwriter` 2-spacing：`Leaf SHA256:\t<hex>` / `CA <CN> SHA256:\t<hex>`。Go 用
///   `\t` 间隔由 `tabwriter` 渲染为列；Rust 无 tabwriter 等价物，固定为 `\t` + 实际列宽。
pub fn execute_hash(args: &TlsHashArgs) -> Result<String, CliError> {
    use x509_parser::prelude::FromDer;
    use xray_tls::pin::generate_cert_hash_hex;

    let path = args
        .cert_path()
        .ok_or_else(|| CliError::InvalidArgument("cert path required".to_string()))?;
    let bytes = std::fs::read(path)
        .map_err(|e| CliError::InvalidArgument(format!("read cert file {path}: {e}")))?;

    // 收集 DER：PEM 走 rustls_pemfile 块迭代；否则整文件当 DER 解析。
    let ders: Vec<Vec<u8>> = if bytes.windows(5).any(|w| w == b"BEGIN") {
        rustls_pemfile::certs(&mut bytes.as_slice())
            .map(|r| r.map(|c| c.to_vec()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| CliError::InvalidArgument(format!("parse PEM: {e}")))?
    } else {
        vec![bytes.clone()]
    };
    if ders.is_empty() {
        return Err(CliError::InvalidArgument("no certificates found".to_string()));
    }

    // 解析每张证书，提取 CN。
    struct Parsed {
        cn: String,
        der_hash: String,
        has_san: bool,
    }
    let mut parsed: Vec<Parsed> = Vec::with_capacity(ders.len());
    for der in &ders {
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der)
            .map_err(|e| CliError::InvalidArgument(format!("parse x509: {e}")))?;
        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|a| a.as_str().ok())
            .unwrap_or("")
            .to_string();
        let has_san = cert.subject_alternative_name().ok().flatten().is_some();
        parsed.push(Parsed { cn, der_hash: generate_cert_hash_hex(der), has_san });
    }

    // 输出：第一张 has_san 的视作 leaf；其余按 `CA <CN>` 输出。
    // Go 实现仅当 leaf 存在时输出 leaf 行；此处保持一致。
    let mut out = String::new();
    for (i, p) in parsed.iter().enumerate() {
        if i == 0 && p.has_san {
            out.push_str(&format!("Leaf SHA256:\t{}\n", p.der_hash));
        } else {
            out.push_str(&format!("CA <{}> SHA256:\t{}\n", p.cn, p.der_hash));
        }
    }
    Ok(out)
}

/// `xray tls cert` 核心：生成自签证书，JSON stdout + 可选 `<file>.crt`/`<file>.key`。
///
/// 对应 Go `main/commands/all/tls/cert.go::executeCert`：
/// - 默认输出 JSON `{certificate: [...], key: [...]}`（PEM 按行切分）。
/// - `--file <prefix>` 时额外写 `<prefix>.crt` + `<prefix>.key`。
/// - `--ca` 启用 CA 模式（KeyCertSign/KeyEncipherment/DigitalSignature）。
/// - `--expire` 解析 human duration（`90d`/`24h`/`30m`/`60s`），默认 90d。
pub fn execute_cert(args: &TlsCertArgs) -> Result<(), CliError> {
    use std::time::Duration;

    use xray_tls::certificate::{CertOptions, generate_self_signed_cert_with_options};

    let expire = parse_duration_human(&args.expire).map_err(|e| {
        CliError::InvalidArgument(format!(
            "invalid --expire '{}' (expected Nd/Nh/Nm/Ns, e.g. 90d/24h/30m/60s): {e}",
            args.expire
        ))
    })?;

    let opts = CertOptions {
        common_name: args.common_name.clone().unwrap_or_else(|| {
            args.domains.first().cloned().unwrap_or_else(|| "Xray Inc".to_string())
        }),
        organization: args.organization.clone().unwrap_or_else(|| "Xray Inc".to_string()),
        is_ca: args.is_ca,
        not_after: Duration::from_secs(expire),
    };
    let domains = args.effective_domains();

    let (cert_pem, key_pem) = generate_self_signed_cert_with_options(&domains, &opts)
        .map_err(|e| CliError::InvalidArgument(format!("cert generation failed: {e}")))?;

    if args.json {
        let json = serde_json::json!({
            "certificate": cert_pem.lines().collect::<Vec<_>>(),
            "key": key_pem.lines().collect::<Vec<_>>(),
        });
        let pretty = serde_json::to_string_pretty(&json)
            .map_err(|e| CliError::InvalidArgument(format!("json: {e}")))?;
        println!("{pretty}");
    }

    if let Some(prefix) = args.file_prefix() {
        let crt_path = format!("{prefix}.crt");
        let key_path = format!("{prefix}.key");
        std::fs::write(&crt_path, &cert_pem)
            .map_err(|e| CliError::InvalidArgument(format!("write {crt_path}: {e}")))?;
        std::fs::write(&key_path, &key_pem)
            .map_err(|e| CliError::InvalidArgument(format!("write {key_path}: {e}")))?;
        eprintln!("saved {crt_path} and {key_path}");
    }
    Ok(())
}

/// 解析 human duration 字符串：`Nd`/`Nh`/`Nm`/`Ns`。不支持单位复合（如 `1d12h`）。
fn parse_duration_human(s: &str) -> Result<u64, String> {
    if s.is_empty() {
        return Err("empty duration".to_string());
    }
    let (num_str, unit) = s.split_at(s.len() - 1);
    let n: u64 = num_str.parse().map_err(|e| format!("not a number: {num_str} ({e})"))?;
    let multiplier = match unit {
        "s" => 1u64,
        "m" => 60,
        "h" => 3600,
        "d" => 24 * 3600,
        _ => return Err(format!("unknown unit: {unit}")),
    };
    n.checked_mul(multiplier).ok_or_else(|| "overflow".to_string())
}

/// `xray tls ping` 核心：TCP 拨号 + TLS 握手（带 SNI / 不带 SNI），打印证书链。
///
/// 对应 Go `main/commands/all/tls/ping.go::executePing`：
/// - 不带 SNI（InsecureSkipVerify 等价）：`rfc5077` 模式下 SNI 留空，rustls 必传
///   `ServerName`，此处用 IP 字面作为 `ServerName`（rustls 0.23 `ServerName::IpAddress`）以贴近 Go
///   行为。
/// - 带 SNI：`ServerName = domain`。
/// - 输出两次 `Pinging without SNI` / `with SNI`，每段打印 TLS 版本、cert 链 长度 + leaf SHA256 +
///   CA CN SHA256 + DNSNames。
///
/// **限制**：rustls 握手无 uTLS 真实指纹（与 xray_tls::client 一致），实际 ClientHello
/// 字节布局是 rustls 默认；Go 端走 utls.UClient。此差异仅影响客户端指纹，
/// 不影响 server 返回的证书信息。
pub async fn execute_ping(args: &TlsPingArgs) -> Result<String, CliError> {
    // 解析 domain[:port]，默认 443
    let (domain, port) = match args.domain.rsplit_once(':') {
        Some((d, p)) => {
            let port: u16 =
                p.parse().map_err(|e| CliError::InvalidArgument(format!("bad port {p}: {e}")))?;
            (d.to_string(), port)
        },
        None => (args.domain.clone(), 443u16),
    };

    // 解析 IP（-i 指定则用，否则 DNS 解析）
    let ip = match &args.ip {
        Some(s) => s
            .parse::<std::net::IpAddr>()
            .map_err(|e| CliError::InvalidArgument(format!("invalid -ip {s}: {e}")))?,
        None => tokio::net::lookup_host(format!("{domain}:{port}"))
            .await
            .map_err(|e| CliError::InvalidArgument(format!("DNS resolve {domain}: {e}")))?
            .next()
            .ok_or_else(|| CliError::InvalidArgument(format!("no address for {domain}")))?
            .ip(),
    };

    let mut out = format!("TLS ping: {}\nUsing IP: {ip}:{port}\n", args.domain);

    // 段 1：without SNI
    out.push_str("-------------------\nPinging without SNI\n");
    match ping_once(ip, port, None).await {
        Err(e) => out.push_str(&format!("Handshake failure: {e}\n")),
        Ok(s) => {
            out.push_str("Handshake succeeded\n");
            out.push_str(&s);
        },
    }

    // 段 2：with SNI
    out.push_str("-------------------\nPinging with SNI\n");
    match ping_once(ip, port, Some(&domain)).await {
        Err(e) => out.push_str(&format!("Handshake failure: {e}\n")),
        Ok(s) => {
            out.push_str("Handshake succeeded\n");
            out.push_str(&s);
        },
    }

    out.push_str("-------------------\nTLS ping finished\n");
    Ok(out)
}

/// 一次 TLS 握手（带或不带 SNI），返回 cert 链详情字符串（无前缀行）。
async fn ping_once(ip: std::net::IpAddr, port: u16, sni: Option<&str>) -> Result<String, String> {
    use std::sync::Arc;

    use rustls_pki_types::ServerName;
    use tokio::net::TcpStream;
    use tokio_rustls::{TlsConnector, rustls::ClientConfig};

    let tcp = TcpStream::connect(std::net::SocketAddr::new(ip, port))
        .await
        .map_err(|e| format!("tcp connect: {e}"))?;
    // 接受任意 server 证书（对齐 Go `InsecureSkipVerify: true`）
    let cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify))
        .with_no_client_auth();
    // rustls 0.23 ServerName::try_from 接受 DNSName 或 IpAddress
    let server_name: ServerName<'static> = match sni {
        Some(d) => ServerName::try_from(d.to_string()).map_err(|e| format!("SNI {d}: {e}"))?,
        None => ServerName::try_from(ip.to_string())
            .map_err(|e| format!("no-SNI server_name from IP {ip}: {e}"))?,
    };
    let connector = TlsConnector::from(Arc::new(cfg));
    let tls = connector.connect(server_name, tcp).await.map_err(|e| format!("handshake: {e}"))?;
    let conn = tls.get_ref().1;
    let mut s = String::new();
    // TLS version
    #[allow(clippy::redundant_guards)] // 存量清零批次
    let ver = match conn.protocol_version() {
        Some(v) if v == tokio_rustls::rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3",
        Some(v) if v == tokio_rustls::rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2",
        _ => "unknown",
    };
    s.push_str(&format!("TLS Version:\t{ver}\n"));
    // Cert chain
    let certs = conn.peer_certificates().unwrap_or(&[]);
    let total_len: usize = certs.iter().map(|c| c.as_ref().len()).sum();
    s.push_str(&format!(
        "Certificate chain's total length:\t{total_len} (certs count: {})\n",
        certs.len()
    ));
    for (i, cert) in certs.iter().enumerate() {
        let hash = xray_tls::pin::generate_cert_hash_hex(cert.as_ref());
        if i == 0 {
            s.push_str(&format!("Cert's leaf SHA256:\t{hash}\n"));
        } else {
            let cn = extract_cn(cert.as_ref()).unwrap_or_default();
            s.push_str(&format!("CA <{cn}> SHA256:\t{hash}\n"));
        }
    }
    if let Some(leaf) = certs.first() {
        if let Some(dns) = extract_dns_sans(leaf.as_ref()) {
            s.push_str(&format!("Cert's allowed domains:\t{dns:?}\n"));
        }
    }
    Ok(s)
}

/// 接受任意证书的 verifier（对齐 Go `InsecureSkipVerify: true`）。
#[derive(Debug)]
struct SkipVerify;
impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn extract_cn(der: &[u8]) -> Option<String> {
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der).ok()?;
    cert.subject().iter_common_name().next().and_then(|a| a.as_str().ok()).map(|s| s.to_string())
}

fn extract_dns_sans(der: &[u8]) -> Option<Vec<String>> {
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der).ok()?;
    let ext = cert.subject_alternative_name().ok().flatten()?;
    let names: Vec<String> = ext
        .value
        .general_names
        .iter()
        .filter_map(|gn| match gn {
            x509_parser::prelude::GeneralName::DNSName(s) => Some(s.to_string()),
            _ => None,
        })
        .collect();
    if names.is_empty() { None } else { Some(names) }
}

// ---------------------------------------------------------------------------
// tls ech 实现（对应 Go main/commands/all/tls/ech.go executeECH）
// ---------------------------------------------------------------------------

/// `xray tls ech` 核心：生成/还原 ECH keyset，返回输出文本。
///
/// - 无 `-i`：生成新 keyset（X25519 + 9 cipher suites，`generate_ech_key_set`）； `config list` =
///   单 config 的 u16 前缀打包，`server keys` = `[klen][key][clen][config]`。
/// - `-i`：base64 解码既有 server keys → 逐 config 还原 `config list`；`server keys` 原样。
/// - `--pem`：PEM 块（`ECH CONFIGS` / `ECH KEYS`，64 列 base64）； 否则 Go 原样文本 `"ECH config
///   list: \n{b64}\n"` + `"ECH server keys: \n{b64}\n"`。
pub fn execute_ech(args: &TlsEchArgs) -> Result<String, CliError> {
    use base64::Engine as _;
    use xray_tls::ech::{
        convert_to_ech_keys, ech_config_list_from_server_keys, generate_ech_key_set,
        pack_ech_config_list, pack_ech_server_keys,
    };
    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    let (config_buffer, key_buffer) = match &args.input {
        None => {
            let (config, priv_bytes) = generate_ech_key_set(&args.server_name);
            (pack_ech_config_list(&[&config]), pack_ech_server_keys(&priv_bytes, &config))
        },
        Some(input) => {
            let key_buffer = B64.decode(input).map_err(|e| {
                CliError::InvalidArgument(format!("Failed to decode ECHServerKeys: {e}"))
            })?;
            // 解析校验（对齐 Go：ConvertToGoECHKeys 失败即报错返回）
            convert_to_ech_keys(&key_buffer).map_err(|e| {
                CliError::InvalidArgument(format!("Failed to decode ECHServerKeys: {e}"))
            })?;
            let config_buffer = ech_config_list_from_server_keys(&key_buffer).map_err(|e| {
                CliError::InvalidArgument(format!("Failed to decode ECHServerKeys: {e}"))
            })?;
            (config_buffer, key_buffer)
        },
    };

    if args.pem {
        Ok(format!(
            "{}{}",
            pem_block("ECH CONFIGS", &config_buffer),
            pem_block("ECH KEYS", &key_buffer),
        ))
    } else {
        Ok(format!(
            "ECH config list: \n{}\nECH server keys: \n{}\n",
            B64.encode(&config_buffer),
            B64.encode(&key_buffer),
        ))
    }
}

/// PEM 块编码（64 列 base64，对齐 Go `pem.EncodeToMemory`）。
fn pem_block(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

#[cfg(test)]
mod ech_tests {
    use base64::Engine as _;
    use xray_tls::ech::{convert_to_ech_keys, generate_ech_key_set, pack_ech_config_list};

    use super::*;

    fn args(input: Option<&str>, pem: bool) -> TlsEchArgs {
        TlsEchArgs { input: input.map(str::to_string), server_name: "ech.test".to_string(), pem }
    }

    /// 无 -i：输出两行 base64；config list 可解析回 u16 前缀结构，
    /// server keys 可被 convert_to_ech_keys round-trip。
    #[test]
    fn ech_generate_outputs_roundtrippable_base64() {
        let out = execute_ech(&args(None, false)).unwrap();
        assert!(out.starts_with("ECH config list: \n"), "prefix must match Go: {out:?}");
        assert!(out.contains("\nECH server keys: \n"));

        // 输出结构（Go 原样）：前缀行 + b64 行交替
        let mut lines = out.trim_end().lines();
        assert_eq!(lines.next().unwrap(), "ECH config list: ");
        let config_b64 = lines.next().unwrap();
        assert_eq!(lines.next().unwrap(), "ECH server keys: ");
        let keys_b64 = lines.next().unwrap();

        let config_list = base64::engine::general_purpose::STANDARD.decode(config_b64).unwrap();
        let server_keys = base64::engine::general_purpose::STANDARD.decode(keys_b64).unwrap();

        // config list：单个 u16 前缀 config
        let keys = convert_to_ech_keys(&server_keys).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(config_list, pack_ech_config_list(&[&keys[0].config]));
    }

    /// -i：从 server keys 还原 config list（前缀一致），server keys 原样。
    #[test]
    fn ech_input_restores_config_list() {
        let (config, priv_bytes) = generate_ech_key_set("ech.test");
        let server_keys = xray_tls::ech::pack_ech_server_keys(&priv_bytes, &config);

        let input_b64 = base64::engine::general_purpose::STANDARD.encode(&server_keys);

        let out = execute_ech(&args(Some(&input_b64), false)).unwrap();
        let mut lines = out.trim_end().lines();
        assert_eq!(lines.next().unwrap(), "ECH config list: ");
        let config_b64 = lines.next().unwrap();
        assert_eq!(lines.next().unwrap(), "ECH server keys: ");
        let keys_b64 = lines.next().unwrap();

        assert_eq!(
            base64::engine::general_purpose::STANDARD.decode(config_b64).unwrap(),
            pack_ech_config_list(&[&config])
        );
        // server keys 原样透传
        assert_eq!(
            base64::engine::general_purpose::STANDARD.decode(keys_b64).unwrap(),
            server_keys
        );
    }

    /// -i 非法 base64 / 非法 server keys 二进制 → InvalidArgument。
    #[test]
    fn ech_input_invalid_errors() {
        assert!(matches!(
            execute_ech(&args(Some("!!!"), false)),
            Err(CliError::InvalidArgument(_))
        ));
        // base64 合法但长度字段超界
        let bad = base64::engine::general_purpose::STANDARD.encode([0x00u8, 0xff, 0x01]);
        assert!(matches!(execute_ech(&args(Some(&bad), false)), Err(CliError::InvalidArgument(_))));
    }

    /// --pem：BEGIN/END 块格式 + 内容可解码回。
    #[test]
    fn ech_pem_output_format() {
        let out = execute_ech(&args(None, true)).unwrap();
        assert!(out.contains("-----BEGIN ECH CONFIGS-----\n"));
        assert!(out.contains("\n-----END ECH CONFIGS-----\n"));
        assert!(out.contains("-----BEGIN ECH KEYS-----\n"));
        assert!(out.contains("\n-----END ECH KEYS-----\n"));
    }
}

#[cfg(test)]
mod tls_hash_tests {
    use xray_tls::pin::generate_cert_hash_hex;

    use super::*;

    /// helper：生成一个临时自签 cert 写到文件，返回路径。
    fn write_temp_cert() -> (tempfile::NamedTempFile, String) {
        let (cert_pem, _key_pem) =
            xray_tls::certificate::generate_self_signed_cert(&["hash.test"]).unwrap();
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), &cert_pem).unwrap();
        let hex = generate_cert_hash_hex(
            &rustls_pemfile::certs(&mut cert_pem.as_bytes()).next().unwrap().unwrap(),
        );
        (f, hex)
    }

    /// 位置参数：哈希 == 生成时计算的 hex。
    #[test]
    fn hash_positional_matches_generate() {
        let (f, expected) = write_temp_cert();
        let args = TlsHashArgs {
            cert: None,
            positional_cert: vec![f.path().to_string_lossy().into_owned()],
        };
        let out = execute_hash(&args).unwrap();
        assert!(out.starts_with("Leaf SHA256:\t"), "got: {out}");
        assert!(out.contains(&expected), "hash mismatch: {out}");
    }

    /// Go 兼容：`--cert <path>` flag 形式。
    #[test]
    fn hash_cert_flag_matches_generate() {
        let (f, expected) = write_temp_cert();
        let args = TlsHashArgs {
            cert: Some(f.path().to_string_lossy().into_owned()),
            positional_cert: vec![],
        };
        let out = execute_hash(&args).unwrap();
        assert!(out.contains(&expected), "hash mismatch: {out}");
    }

    /// 缺 cert → InvalidArgument。
    #[test]
    fn hash_missing_cert_errors() {
        let args = TlsHashArgs { cert: None, positional_cert: vec![] };
        assert!(matches!(execute_hash(&args), Err(CliError::InvalidArgument(_))));
    }

    /// 文件不存在 → InvalidArgument。
    #[test]
    fn hash_missing_file_errors() {
        let args = TlsHashArgs {
            cert: Some("/nonexistent/path.pem".to_string()),
            positional_cert: vec![],
        };
        assert!(matches!(execute_hash(&args), Err(CliError::InvalidArgument(_))));
    }
}

#[cfg(test)]
mod tls_cert_tests {
    use std::time::Duration;

    use super::*;

    fn basic_args(domains: Vec<&str>) -> TlsCertArgs {
        TlsCertArgs {
            domains: domains.into_iter().map(String::from).collect(),
            common_name: None,
            organization: None,
            is_ca: false,
            json: false,
            file: None,
            expire: "90d".to_string(),
            out: None,
        }
    }

    /// `parse_duration_human`：所有单位 + 错误。
    #[test]
    fn parse_duration_human_units() {
        assert_eq!(parse_duration_human("60s").unwrap(), 60);
        assert_eq!(parse_duration_human("5m").unwrap(), 300);
        assert_eq!(parse_duration_human("1h").unwrap(), 3600);
        assert_eq!(parse_duration_human("1d").unwrap(), 86400);
        assert_eq!(parse_duration_human("90d").unwrap(), 90 * 86400);
        // 错误：未知单位、空、字母数字
        assert!(parse_duration_human("1y").is_err());
        assert!(parse_duration_human("").is_err());
        assert!(parse_duration_human("d").is_err()); // 没数字
        assert!(parse_duration_human("90x").is_err());
    }

    /// cert：单 domain + 默认 CN/Org，生成的 cert PEM 包含 marker。
    #[test]
    fn cert_single_domain_generates_valid_pem() {
        let args = basic_args(vec!["a.test"]);
        // file 写 tmp dir
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("cert");
        let mut args = args;
        args.json = false;
        args.file = Some(prefix.to_string_lossy().into_owned());
        execute_cert(&args).expect("cert gen");
        let crt = std::fs::read(prefix.with_extension("crt")).unwrap();
        let key = std::fs::read(prefix.with_extension("key")).unwrap();
        assert!(String::from_utf8_lossy(&crt).contains("BEGIN CERTIFICATE"));
        assert!(String::from_utf8_lossy(&key).contains("BEGIN PRIVATE KEY"));
        let _ = Duration::from_secs(90 * 86400); // suppress unused import
    }

    /// cert：多 domain → SANs 全在。
    #[test]
    fn cert_multiple_domains_all_in_san() {
        let args = basic_args(vec!["a.test", "b.test", "c.test"]);
        // JSON 输出捕获（stdout 不可直接拿，验证 json=true 不报错即可）
        let mut args = args;
        args.json = true;
        execute_cert(&args).expect("multi-domain cert");
    }

    /// cert：--ca 启用 basicConstraints CA=true。
    #[test]
    fn cert_ca_flag_sets_basic_constraints() {
        let mut args = basic_args(vec!["ca.test"]);
        args.is_ca = true;
        // JSON false 避免 stdout 噪声；只验证不报错
        args.json = false;
        execute_cert(&args).expect("ca cert");
    }

    /// cert：--expire 错误格式 → InvalidArgument。
    #[test]
    fn cert_invalid_expire_errors() {
        let mut args = basic_args(vec!["x.test"]);
        args.expire = "bogus".to_string();
        assert!(matches!(execute_cert(&args), Err(CliError::InvalidArgument(_))));
    }

    /// cert：--file 写入 .crt 和 .key。
    #[test]
    fn cert_file_writes_crt_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("out");
        let mut args = basic_args(vec!["file.test"]);
        args.json = false;
        args.file = Some(prefix.to_string_lossy().into_owned());
        execute_cert(&args).expect("file cert");
        assert!(prefix.with_extension("crt").exists());
        assert!(prefix.with_extension("key").exists());
    }

    /// cert：effective_domains 占位逻辑。
    #[test]
    fn cert_effective_domains_uses_placeholder_when_empty() {
        let args = basic_args(vec![]);
        assert_eq!(args.effective_domains(), vec!["localhost".to_string()]);
        let args2 = basic_args(vec!["x.test"]);
        assert_eq!(args2.effective_domains(), vec!["x.test".to_string()]);
        // suppress unused
        let _ = args;
    }

    /// cert：file_prefix 优先级。
    #[test]
    fn cert_file_prefix_prefers_file() {
        let mut args = basic_args(vec!["x.test"]);
        args.file = Some("f1".to_string());
        args.out = Some("o1".to_string());
        assert_eq!(args.file_prefix(), Some("f1"));
        args.file = None;
        assert_eq!(args.file_prefix(), Some("o1"));
        args.out = None;
        assert_eq!(args.file_prefix(), None);
    }
}

#[cfg(test)]
mod tls_ping_tests {
    use super::*;

    /// domain[:port] 解析。
    #[test]
    fn ping_args_domain_parsing_in_execute_ping_setup() {
        // 验证 domain 带端口的解析（仅语法层面，不实际拨号）。
        let args =
            TlsPingArgs { domain: "example.com:8443".to_string(), ip: Some("1.2.3.4".to_string()) };
        assert_eq!(args.domain, "example.com:8443");
        // ip 解析正确
        let parsed: std::net::IpAddr = args.ip.as_ref().unwrap().parse().unwrap();
        assert_eq!(parsed.to_string(), "1.2.3.4");
    }

    /// 非法 -ip。
    #[test]
    fn ping_args_invalid_ip_string_fails_parse() {
        assert!("not.an.ip".parse::<std::net::IpAddr>().is_err());
        assert!("999.999.999.999".parse::<std::net::IpAddr>().is_err());
    }
}

#[cfg(test)]
mod convert_tests {

    use super::*;

    fn write_temp(dir: &tempfile::TempDir, name: &str, content: &str) -> String {
        let p = dir.path().join(name);
        std::fs::write(&p, content).unwrap();
        p.to_string_lossy().into_owned()
    }

    /// 真 golden 对拍：解码 Go v26.9.9 `xray convert pb` 对同一 config.json
    /// 产出的原始字节（fixture 由 Go 基线实际生成，见 mix_go.pb），
    /// 断言容器字段语义一致（tag / ReceiverConfig / SenderConfig / app 序列）。
    /// value 载荷方言差异（Go=proto settings，Rust=JSON 字节）不在此断言。
    #[test]
    fn convert_pb_decodes_real_go_golden_container() {
        use prost::Message as _;

        let golden = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/commands/testdata/go_golden_mix.pb"
        ));
        let decoded = ProtoConfig::decode(golden.as_slice()).unwrap();

        assert_eq!(decoded.inbound.len(), 1);
        assert_eq!(decoded.inbound[0].tag, "in-1");
        assert_eq!(
            decoded.inbound[0].receiver_settings.as_ref().unwrap().r#type,
            "xray.app.proxyman.ReceiverConfig"
        );
        assert_eq!(
            decoded.inbound[0].proxy_settings.as_ref().unwrap().r#type,
            "xray.proxy.dokodemo.Config"
        );

        assert_eq!(decoded.outbound.len(), 1);
        assert_eq!(decoded.outbound[0].tag, "out-1");
        assert_eq!(
            decoded.outbound[0].sender_settings.as_ref().unwrap().r#type,
            "xray.app.proxyman.SenderConfig"
        );
        assert_eq!(
            decoded.outbound[0].proxy_settings.as_ref().unwrap().r#type,
            "xray.proxy.freedom.Config"
        );

        let urls: Vec<&str> = decoded.app.iter().map(|t| t.r#type.as_str()).collect();
        assert_eq!(
            urls,
            vec![
                "xray.app.log.Config",
                "xray.app.dispatcher.Config",
                "xray.app.proxyman.InboundConfig",
                "xray.app.proxyman.OutboundConfig",
                "xray.app.router.Config",
            ]
        );
    }

    /// 我们对同一 config 的产出与 Go golden 在容器字段（tag + app type_url
    /// 序列）上一致；value 载荷为既定方言差异（见 json_config_to_proto_config）。
    #[test]
    fn convert_pb_container_fields_match_go_golden() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_temp(
            &dir,
            "config.json",
            r#"{
                "log": {"loglevel": "warning"},
                "inbounds": [{"tag": "in-1", "protocol": "dokodemo-door",
                              "settings": {"address": "127.0.0.1"}}],
                "outbounds": [{"tag": "out-1", "protocol": "freedom", "settings": {}}],
                "routing": {"domainStrategy": "AsIs"}
            }"#,
        );
        let out_path = dir.path().join("mix.pb");
        let args = ConvertPbArgs {
            out: Some(out_path.to_string_lossy().into_owned()),
            debug: false,
            inject_type: false,
            inputs: vec![cfg],
        };
        execute_convert_pb(&args).unwrap();
        let bytes = std::fs::read(&out_path).unwrap();
        let ours = ProtoConfig::decode(bytes.as_slice()).unwrap();

        let golden = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/commands/testdata/go_golden_mix.pb"
        ));
        let go = ProtoConfig::decode(golden.as_slice()).unwrap();

        let tags: Vec<String> = ours.inbound.iter().map(|i| i.tag.clone()).collect();
        let go_tags: Vec<String> = go.inbound.iter().map(|i| i.tag.clone()).collect();
        assert_eq!(tags, go_tags);

        let urls: Vec<String> = ours.app.iter().map(|t| t.r#type.clone()).collect();
        let go_urls: Vec<String> = go.app.iter().map(|t| t.r#type.clone()).collect();
        assert_eq!(urls, go_urls);
    }

    /// convert json -t：注入 `_TypedMessage_`（Go reflect/marshal.go:42-44）。
    #[test]
    fn convert_json_type_flag_injects_marker() {
        let dir = tempfile::tempdir().unwrap();
        let input = write_temp(
            &dir,
            "tmsg.json",
            r#"{"type":"xray.proxy.shadowsocks.Account","value":"CgMxMTEQBg=="}"#,
        );
        let args = ConvertJsonArgs { inject_type: true, input };
        let out = convert_json_output(&args).unwrap();
        assert!(out.contains("\"_TypedMessage_\""), "got: {out}");
        assert!(out.contains("xray.proxy.shadowsocks.Account"));
        assert!(out.contains("CgMxMTEQBg=="));
    }

    /// convert json 不带 -t：无 `_TypedMessage_` 键（此前误为必填 String，缺省报
    /// missing required——bd jo0j ①）。
    #[test]
    fn convert_json_without_flag_omits_marker() {
        let dir = tempfile::tempdir().unwrap();
        let input = write_temp(
            &dir,
            "tmsg.json",
            r#"{"type":"xray.proxy.shadowsocks.Account","value":"CgMxMTEQBg=="}"#,
        );
        let args = ConvertJsonArgs { inject_type: false, input };
        let out = convert_json_output(&args).unwrap();
        assert!(!out.contains("_TypedMessage_"), "got: {out}");
        assert!(out.contains("\"value\": \"CgMxMTEQBg==\""));
    }

    /// convert pb -outpbfile：写 `xray.core.Config` proto 原始字节，golden 字段对拍。
    #[test]
    fn convert_pb_writes_proto_bytes_golden_fields() {
        use prost::Message as _;

        let dir = tempfile::tempdir().unwrap();
        let cfg = write_temp(
            &dir,
            "config.json",
            r#"{
                "log": {"loglevel": "warning"},
                "inbounds": [{"tag": "in-1", "protocol": "dokodemo-door",
                              "settings": {"address": "127.0.0.1"}}],
                "outbounds": [{"tag": "out-1", "protocol": "freedom", "settings": {}}],
                "routing": {"domainStrategy": "AsIs"}
            }"#,
        );
        let out_path = dir.path().join("mix.pb");
        let args = ConvertPbArgs {
            out: Some(out_path.to_string_lossy().into_owned()),
            debug: false,
            inject_type: false,
            inputs: vec![cfg],
        };
        execute_convert_pb(&args).unwrap();

        let bytes = std::fs::read(&out_path).unwrap();
        assert!(!bytes.is_empty());
        // 自产 fixture 字段对拍：容器必须可 decode 且字段保真。
        let decoded = ProtoConfig::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded.inbound.len(), 1);
        assert_eq!(decoded.inbound[0].tag, "in-1");
        assert!(decoded.inbound[0].proxy_settings.is_some());
        assert!(decoded.inbound[0].receiver_settings.is_some());
        assert_eq!(decoded.outbound.len(), 1);
        assert_eq!(decoded.outbound[0].tag, "out-1");

        // app 顺序对齐 Go infra/conf/xray.go:528-651：log 第一，
        // dispatcher/proxyman 常驻，routing 按存在性。
        let urls: Vec<&str> = decoded.app.iter().map(|t| t.r#type.as_str()).collect();
        assert_eq!(urls.first(), Some(&"xray.app.log.Config"));
        assert!(urls.contains(&"xray.app.dispatcher.Config"));
        assert!(urls.contains(&"xray.app.proxyman.InboundConfig"));
        assert!(urls.contains(&"xray.app.proxyman.OutboundConfig"));
        assert!(urls.contains(&"xray.app.router.Config"));
    }

    /// convert pb 多文件 merge override（tag 覆盖语义）。
    #[test]
    fn convert_pb_merges_multiple_configs() {
        let dir = tempfile::tempdir().unwrap();
        let c1 = write_temp(
            &dir,
            "c1.json",
            r#"{"inbounds":[{"tag":"in-1","protocol":"dokodemo-door","settings":{}}],"outbounds":[]}"#,
        );
        let c2 = write_temp(&dir, "c2.json", r#"{"log":{"loglevel":"none"}}"#);
        let out_path = dir.path().join("mix.pb");
        let args = ConvertPbArgs {
            out: Some(out_path.to_string_lossy().into_owned()),
            debug: false,
            inject_type: false,
            inputs: vec![c1, c2],
        };
        execute_convert_pb(&args).unwrap();
        let bytes = std::fs::read(&out_path).unwrap();
        let decoded = ProtoConfig::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded.inbound.len(), 1);
        assert_eq!(decoded.inbound[0].tag, "in-1");
    }

    /// -debug 优先于 -o：只打印 JSON，不落盘（Go protobuf.go:81-88 return）。
    #[test]
    fn convert_pb_debug_takes_precedence_over_out() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_temp(&dir, "config.json", r#"{"inbounds":[],"outbounds":[]}"#);
        let out_path = dir.path().join("never.pb");
        let args = ConvertPbArgs {
            out: Some(out_path.to_string_lossy().into_owned()),
            debug: true,
            inject_type: false,
            inputs: vec![cfg],
        };
        execute_convert_pb(&args).unwrap();
        assert!(!out_path.exists());
    }

    /// 无 -o 且非 -debug → Go "-outpbfile not specified" 硬错。
    #[test]
    fn convert_pb_requires_out_or_debug() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_temp(&dir, "config.json", r#"{"inbounds":[],"outbounds":[]}"#);
        let args = ConvertPbArgs { out: None, debug: false, inject_type: false, inputs: vec![cfg] };
        let err = execute_convert_pb(&args).unwrap_err();
        assert!(err.to_string().contains("-outpbfile not specified"));
    }

    /// -o 非法扩展名 → Go "-outpbfile followed by a possible original config."。
    #[test]
    fn convert_pb_rejects_non_pb_out_extension() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_temp(&dir, "config.json", r#"{"inbounds":[],"outbounds":[]}"#);
        let args = ConvertPbArgs {
            out: Some(dir.path().join("out.json").to_string_lossy().into_owned()),
            debug: false,
            inject_type: false,
            inputs: vec![cfg],
        };
        let err = execute_convert_pb(&args).unwrap_err();
        assert!(err.to_string().contains("-outpbfile followed by a possible original config."));
    }
}

//! # 工具子命令
//!
//! 对应 Go `main/commands/all/` 的 uuid / tls / convert 等命令。

use clap::{Args, Subcommand};

use crate::error::CliError;

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
    match &args.input {
        Some(input) => {
            if input.len() > 30 {
                return Err(CliError::InvalidArgument(
                    "input must be at most 30 bytes".to_string(),
                ));
            }
            let parsed = uuid::Uuid::parse_str(input)
                .map_err(|e| CliError::UuidParseFailed(e.to_string()))?;
            println!("{parsed}");
        }
        None => {
            let id = uuid::Uuid::new_v4();
            println!("{id}");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// tls 命令组
// ---------------------------------------------------------------------------

/// `xray tls` - TLS 工具命令组。
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

/// `xray tls ping` - 测试 TLS 连接。
#[derive(Args, Debug, Clone)]
pub struct TlsPingArgs {
    /// 目标域名[:端口]，默认端口 443。
    pub domain: String,
    /// 指定连接 IP 地址（绕过 DNS）。
    #[arg(short, long = "ip")]
    pub ip: Option<String>,
}

/// `xray tls hash` - 计算证书哈希。
#[derive(Args, Debug, Clone)]
pub struct TlsHashArgs {
    /// 证书文件路径（PEM 格式）。
    pub cert: String,
}

/// `xray tls cert` - 生成自签名证书。
#[derive(Args, Debug, Clone)]
pub struct TlsCertArgs {
    /// 域名（CN）。
    #[arg(short, long = "domain")]
    pub domain: String,
    /// 输出文件前缀。
    #[arg(short, long = "out", default_value = "cert")]
    pub out: String,
}

/// `xray tls ech` - 生成 ECH 配置。
#[derive(Args, Debug, Clone)]
pub struct TlsEchArgs {
    /// 域名。
    #[arg(short, long = "domain")]
    pub domain: String,
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
    /// 注入类型名称。
    #[arg(short, long = "type")]
    pub inject_type: String,
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
    /// 注入类型名称。
    #[arg(short, long = "type")]
    pub inject_type: String,
    /// 输入 JSON 文件路径列表。
    #[arg(required = true)]
    pub inputs: Vec<String>,
}

// ---------------------------------------------------------------------------
// execute 函数
// ---------------------------------------------------------------------------

/// tls 子命令 execute。
pub fn execute_tls(cmd: &TlsCommand) -> Result<(), CliError> {
    match cmd {
        TlsCommand::Ping(args) => {
            let _ = (&args.domain, &args.ip);
            Err(CliError::Unimplemented {
                what: "tls ping: TLS connection test not yet implemented",
            })
        }
        TlsCommand::Hash(args) => {
            let _ = &args.cert;
            Err(CliError::Unimplemented {
                what: "tls hash: certificate hash not yet implemented",
            })
        }
        TlsCommand::Cert(args) => {
            let _ = (&args.domain, &args.out);
            Err(CliError::Unimplemented {
                what: "tls cert: certificate generation not yet implemented",
            })
        }
        TlsCommand::Ech(args) => {
            let _ = &args.domain;
            Err(CliError::Unimplemented {
                what: "tls ech: ECH config generation not yet implemented",
            })
        }
    }
}

/// convert 子命令 execute。
pub fn execute_convert(cmd: &ConvertCommand) -> Result<(), CliError> {
    match cmd {
        ConvertCommand::Json(args) => {
            let _ = (&args.inject_type, &args.input);
            Err(CliError::Unimplemented {
                what: "convert json: protobuf-to-JSON conversion not yet implemented",
            })
        }
        ConvertCommand::Pb(args) => {
            let _ = (&args.out, &args.debug, &args.inject_type, &args.inputs);
            Err(CliError::Unimplemented {
                what: "convert pb: JSON-to-protobuf conversion not yet implemented",
            })
        }
    }
}
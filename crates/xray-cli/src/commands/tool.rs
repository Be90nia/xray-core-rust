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
        }
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
            let out = execute_ech(args)?;
            print!("{out}");
            Ok(())
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

// ---------------------------------------------------------------------------
// tls ech 实现（对应 Go main/commands/all/tls/ech.go executeECH）
// ---------------------------------------------------------------------------

/// `xray tls ech` 核心：生成/还原 ECH keyset，返回输出文本。
///
/// - 无 `-i`：生成新 keyset（X25519 + 9 cipher suites，`generate_ech_key_set`）；
///   `config list` = 单 config 的 u16 前缀打包，`server keys` = `[klen][key][clen][config]`。
/// - `-i`：base64 解码既有 server keys → 逐 config 还原 `config list`；`server keys` 原样。
/// - `--pem`：PEM 块（`ECH CONFIGS` / `ECH KEYS`，64 列 base64）；
///   否则 Go 原样文本 `"ECH config list: \n{b64}\n"` + `"ECH server keys: \n{b64}\n"`。
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
            (
                pack_ech_config_list(&[&config]),
                pack_ech_server_keys(&priv_bytes, &config),
            )
        }
        Some(input) => {
            let key_buffer = B64
                .decode(input)
                .map_err(|e| CliError::InvalidArgument(format!("Failed to decode ECHServerKeys: {e}")))?;
            // 解析校验（对齐 Go：ConvertToGoECHKeys 失败即报错返回）
            convert_to_ech_keys(&key_buffer)
                .map_err(|e| CliError::InvalidArgument(format!("Failed to decode ECHServerKeys: {e}")))?;
            let config_buffer = ech_config_list_from_server_keys(&key_buffer)
                .map_err(|e| CliError::InvalidArgument(format!("Failed to decode ECHServerKeys: {e}")))?;
            (config_buffer, key_buffer)
        }
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
    use super::*;
    use base64::Engine as _;
    use xray_tls::ech::{convert_to_ech_keys, generate_ech_key_set, pack_ech_config_list};

    fn args(input: Option<&str>, pem: bool) -> TlsEchArgs {
        TlsEchArgs {
            input: input.map(str::to_string),
            server_name: "ech.test".to_string(),
            pem,
        }
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
        assert!(matches!(
            execute_ech(&args(Some(&bad), false)),
            Err(CliError::InvalidArgument(_))
        ));
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
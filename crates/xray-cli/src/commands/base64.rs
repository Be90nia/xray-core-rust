#![allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr)] // CLI base64 子命令：编码/解码结果打印即产品接口
//! `xray base64 encode/decode` 子命令。
//!
//! 对应 Go `main/commands/all/base64/{base64,encode,decode}.go` +
//! `common/base64`（前缀 `base64:` / `base64+gzip:`，gzip BestCompression）。

use std::io::{Read, Write};

use base64::Engine as _;
use clap::{Args, Subcommand};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};

use crate::error::CliError;

/// Go `common/base64.Prefix`。
pub const PREFIX: &str = "base64:";
/// Go `common/base64.GzipPrefix`。
pub const GZIP_PREFIX: &str = "base64+gzip:";

/// `xray base64` 子命令组（help 文案对齐 Go `CmdBase64`；组 Long 见 bin 层 variant attr）。
#[derive(Subcommand, Debug)]
pub enum Base64Command {
    /// Encode as Base64.
    ///
    /// Go `cmdEncode`：UsageLine/Long 原文见 attrs。attr 必须挂变体：clap_derive 对
    /// newtype 变体在 `augment_args` 之后再应用变体 doc 派生的 `.long_about(None)`，
    /// struct 层 `long_about` 会被清掉（clap_derive-4.6.1 subcommand.rs:315-321）。
    #[command(
        override_usage = "xray base64 encode [-gzip] <input-file | - | stdin:>",
        long_about = "\
Encode input-file as Base64 with the base64: prefix.
Pass \"-\" or \"stdin:\" to read stdin.
Use -gzip to compress and output base64+gzip:.

Examples:

\txray base64 encode input.bin
\txray base64 encode -gzip input.bin"
    )]
    Encode(EncodeArgs),

    /// Decode Base64.
    ///
    /// Go `cmdDecode`：UsageLine/Long 原文见 attrs（挂变体原因同上）。
    #[command(
        override_usage = "xray base64 decode [-gzip] <value | - | stdin:> [output-file]",
        long_about = "\
Decode a Base64 value, or pass \"-\" or \"stdin:\" to read stdin.
Write to output-file, or stdout if omitted.
Accepts base64:, base64+gzip:, or no prefix; gzip is enabled by base64+gzip: or -gzip.

Examples:

\txray base64 decode eA== out.bin
\txray base64 decode -gzip H4sIAAAAAAAC/6sAAIMW3IwBAAAA out.bin"
    )]
    Decode(DecodeArgs),
}

/// `xray base64 encode` 参数：`<input-file | - | stdin:>`，`-gzip` 开关。
///
/// 帮助文案由 `Base64Command::Encode` 变体 attrs 承载（见其注释）。
#[derive(Args, Debug)]
pub struct EncodeArgs {
    /// Input file, or `-`/`stdin:` to read stdin.
    pub input: String,

    /// Compress the input with gzip.
    #[arg(long = "gzip")]
    pub gzip: bool,
}

/// `xray base64 decode` 参数：`<value | - | stdin:>` 与可选 `[output-file]`。
///
/// 帮助文案由 `Base64Command::Decode` 变体 attrs 承载（见其注释）。
#[derive(Args, Debug)]
pub struct DecodeArgs {
    /// Base64 value (with optional `base64:`/`base64+gzip:` prefix), or `-`/`stdin:`.
    pub value: String,

    /// Write to output-file instead of stdout.
    pub output: Option<String>,

    /// Decompress the decoded bytes with gzip.
    #[arg(long = "gzip")]
    pub gzip: bool,
}

/// base64 子命令 dispatch。
pub fn execute_base64(command: &Base64Command) -> Result<(), CliError> {
    match command {
        Base64Command::Encode(args) => execute_encode(args),
        Base64Command::Decode(args) => execute_decode(args),
    }
}

fn execute_encode(args: &EncodeArgs) -> Result<(), CliError> {
    let data = read_input(&args.input)?;
    let value = encode_bytes(&data, args.gzip)
        .map_err(|e| CliError::Fatal(format!("failed to encode input: {e}")))?;
    // Go Fprintln 后显式查错（BrokenPipe 等 Fatalf exit 1，而非 Rust panic exit 101）。
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{value}")
        .map_err(|e| CliError::Fatal(format!("failed to write encoded output: {e}")))?;
    Ok(())
}

fn execute_decode(args: &DecodeArgs) -> Result<(), CliError> {
    let raw = if args.value == "-" || args.value == "stdin:" {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| CliError::Fatal(format!("failed to read input: {e}")))?;
        // Go string 按字节承载：非法 UTF-8 不在读取层失败，留给 base64 解码报错（同 Go 归宿）。
        String::from_utf8_lossy(&buf).into_owned()
    } else {
        args.value.clone()
    };
    // Go decode.go：先 TrimSpace，再按需补 gzip 前缀。
    let value = raw.trim();
    let prefixed = if args.gzip && !value.starts_with(GZIP_PREFIX) {
        format!("{GZIP_PREFIX}{}", value.strip_prefix(PREFIX).unwrap_or(value))
    } else {
        value.to_string()
    };
    let data = decode_value(&prefixed)
        .map_err(|e| CliError::Fatal(format!("failed to decode input: {e}")))?;
    let written = match args.output.as_deref() {
        Some(out) if out != "-" => std::fs::write(out, data),
        _ => std::io::stdout().write_all(&data),
    };
    written.map_err(|e| CliError::Fatal(format!("failed to write decoded output: {e}")))?;
    Ok(())
}

/// 对齐 Go `common/base64.Encode`：前缀 + StdEncoding，gzip 用 BestCompression。
pub fn encode_bytes(data: &[u8], zip: bool) -> std::io::Result<String> {
    let engine = base64::engine::general_purpose::STANDARD;
    if !zip {
        return Ok(format!("{PREFIX}{}", engine.encode(data)));
    }
    let mut buf = Vec::new();
    GzEncoder::new(&mut buf, Compression::best()).write_all(data)?;
    Ok(format!("{GZIP_PREFIX}{}", engine.encode(&buf)))
}

/// 对齐 Go `common/base64.Decode`：剥 `base64+gzip:` / `base64:` 前缀 →
/// StdEncoding 解码 → 按前缀决定是否 gunzip。
pub fn decode_value(value: &str) -> std::io::Result<Vec<u8>> {
    let (value, zip) = match value.strip_prefix(GZIP_PREFIX) {
        Some(rest) => (rest, true),
        None => (value.strip_prefix(PREFIX).unwrap_or(value), false),
    };
    let data = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if !zip {
        return Ok(data);
    }
    let mut out = Vec::new();
    GzDecoder::new(data.as_slice()).read_to_end(&mut out)?;
    Ok(out)
}

/// 对齐 Go encode.go/decode.go：`-` 与 `stdin:` 均读 stdin，否则当文件路径。
fn read_input(spec: &str) -> Result<Vec<u8>, CliError> {
    if spec == "-" || spec == "stdin:" {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| CliError::Fatal(format!("failed to read input: {e}")))?;
        Ok(buf)
    } else {
        std::fs::read(spec).map_err(|e| CliError::Fatal(format!("failed to read input: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go 对拍：`echo -n x | xray base64 encode` → `base64:eA==`。
    #[test]
    fn encode_plain_matches_go_prefix_form() {
        assert_eq!(encode_bytes(b"x", false).unwrap(), "base64:eA==");
        assert_eq!(encode_bytes(b"", false).unwrap(), "base64:");
    }

    /// Go 常量逐字拷贝核对（common/base64/base64.go Prefix/GzipPrefix）。
    #[test]
    fn prefixes_match_go_constants_verbatim() {
        assert_eq!(PREFIX, "base64:");
        assert_eq!(GZIP_PREFIX, "base64+gzip:");
    }

    /// 纯文本往返：encode("hello\n") → decode 还原（Go Encode/Decode 对称语义）。
    #[test]
    fn plain_roundtrip_hello_newline() {
        let value = encode_bytes(b"hello\n", false).unwrap();
        assert_eq!(value, "base64:aGVsbG8K");
        assert_eq!(decode_value(&value).unwrap(), b"hello\n");
    }

    /// gzip 编码带 `base64+gzip:` 前缀且可解回原文（Go Encode(data, true) 语义）。
    #[test]
    fn encode_gzip_roundtrip() {
        let value = encode_bytes(b"hello world", true).unwrap();
        assert!(value.starts_with(GZIP_PREFIX));
        assert_eq!(decode_value(&value).unwrap(), b"hello world");
    }

    /// decode：接受前缀、无前缀；两侧空白由命令层 TrimSpace（Go decode.go 分层，
    /// codec 层严格不 trim），此处按命令层行为 trim 后喂入。
    #[test]
    fn decode_accepts_prefix_plain_and_padded_whitespace() {
        assert_eq!(decode_value("base64:eA==").unwrap(), b"x");
        assert_eq!(decode_value("eA==").unwrap(), b"x");
        assert_eq!(decode_value("  eA==\n".trim()).unwrap(), b"x");
        assert!(decode_value("!!!").is_err());
    }

    /// decode `-gzip` 强制路径：无前缀值按 gzip 解（Go executeDecode 补前缀逻辑）。
    #[test]
    fn decode_forced_gzip_prefix_equivalent() {
        let gzipped = encode_bytes(b"payload", true).unwrap();
        let bare = gzipped.strip_prefix(GZIP_PREFIX).unwrap();
        let forced = format!("{GZIP_PREFIX}{bare}");
        assert_eq!(decode_value(&forced).unwrap(), b"payload");
        // 已带 GzipPrefix 时 -gzip 不重复加前缀：等价于直接解。
        assert_eq!(decode_value(&gzipped).unwrap(), b"payload");
    }
}

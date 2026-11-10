//! 生成 ECH 服务端可用的 keyset（入站 `tlsSettings.echServerKeys` + 客户端 config list）。
//!
//! 为什么不用 `xray tls ech`：Go CLI 产 9 套件（含 HKDF-SHA384/512），而 BoringSSL
//! 服务端只接受 HKDF-SHA256（`SSL_ECH_KEYS_add` 直接拒，见
//! `reports/2026-11-10-fixes/5t1zj.md` §底层能力举证 3）。CLI 补 SHA256-only 选项前，
//! 用本 example 生成可用材料。
//!
//! ```text
//! cargo run -p xray-tls --example ech_keys -- inner.example
//! ECH_CONFIG_LIST <base64>   # 客户端 EncryptedClientHelloConfigList
//! ECH_SERVER_KEYS <base64>   # 服务端 inbound tlsSettings.echServerKeys
//! ```
//!
//! 外层名（= config 里的 `public_name`）取 `public.<inner>`：服务端证书签内层名，
//! 客户端 wire 上只出现外层名。

use std::io::{self, Write as _};

use base64::Engine as _;
use xray_tls::ech::{generate_ech_key_set_sha256, pack_ech_config_list, pack_ech_server_keys};

fn main() -> io::Result<()> {
    let inner = std::env::args().nth(1).unwrap_or_else(|| "inner.example".to_string());
    let public_name = format!("public.{inner}");

    let (config, priv_bytes) = generate_ech_key_set_sha256(&public_name);
    let server_keys = pack_ech_server_keys(&priv_bytes, &config);
    let config_list = pack_ech_config_list(&[config.as_slice()]);

    let b64 = base64::engine::general_purpose::STANDARD;
    println!("ECH_CONFIG_LIST {}", b64.encode(&config_list));
    println!("ECH_SERVER_KEYS {}", b64.encode(&server_keys));
    println!("INNER_NAME {inner}");
    println!("PUBLIC_NAME {public_name}");
    std::io::stdout().flush()
}

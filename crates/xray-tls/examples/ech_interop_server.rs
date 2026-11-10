//! 手动互通探针（不进 CI）：BoringSSL 服务端 ECH ↔ Go `crypto/tls` 客户端。
//!
//! 自动化 E2E 证据是 `btls_server::tests::btls_server_ech_hides_inner_sni`（BoringSSL
//! 双端真握手）。本 example 用于跨实现核对：起一个真 TCP 监听，把地址与 ECHConfigList
//! 打给调用方，等一个 ECH 客户端（Go 探针见 `reports/2026-11-10-fixes/5t1zj.md`）连上，
//! 回显 4 字节并打印服务端观测到的 SNI 与 ECH 状态。
//!
//! ```text
//! cargo run -p xray-tls --example ech_interop_server
//! ADDR 127.0.0.1:PORT
//! ECH_CONFIG_LIST <base64>
//! SERVER_OK ech_accepted=true sni=Some("inner.example")
//! ```

use std::io::{self, Write as _};

use base64::Engine as _;
use foreign_types::ForeignType as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_btls::SslStream;
use xray_tls::{
    btls_server::build_server_ssl_context_with_ech,
    ech::{generate_ech_key_set_sha256, pack_ech_config_list, pack_ech_server_keys},
};

const PUBLIC_NAME: &str = "public.example";
const INNER_NAME: &str = "inner.example";

#[tokio::main]
async fn main() -> io::Result<()> {
    let (config, priv_bytes) = generate_ech_key_set_sha256(PUBLIC_NAME);
    let server_keys = pack_ech_server_keys(&priv_bytes, &config);
    let config_list = pack_ech_config_list(&[config.as_slice()]);

    let params =
        rcgen::CertificateParams::new(vec![INNER_NAME.to_string()]).map_err(io::Error::other)?;
    let key_pair = rcgen::KeyPair::generate().map_err(io::Error::other)?;
    let cert = params.self_signed(&key_pair).map_err(io::Error::other)?;
    let ctx =
        build_server_ssl_context_with_ech(cert.der(), &key_pair.serialize_der(), &server_keys)
            .map_err(io::Error::other)?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    println!("ADDR {}", listener.local_addr()?);
    println!("ECH_CONFIG_LIST {}", base64::engine::general_purpose::STANDARD.encode(&config_list));
    std::io::stdout().flush()?;

    let (tcp, peer) = listener.accept().await?;
    let ssl = btls::ssl::Ssl::new(&ctx).map_err(io::Error::other)?;
    // SAFETY: 新建 SSL，仅标记服务端角色（与 btls_server::accept 同款）。
    unsafe { btls_sys::SSL_set_accept_state(ssl.as_ptr()) };
    let mut tls = Box::pin(SslStream::new(ssl, tcp).map_err(io::Error::other)?);
    tls.as_mut().accept().await.map_err(io::Error::other)?;

    let ech_accepted = tls.ssl().ech_accepted();
    let sni = tls.ssl().servername(btls::ssl::NameType::HOST_NAME).map(str::to_string);
    let mut buf = [0u8; 4];
    tls.read_exact(&mut buf).await?;
    tls.write_all(&buf).await?;
    tls.flush().await?;
    println!("SERVER_OK peer={peer} ech_accepted={ech_accepted} sni={sni:?}");
    Ok(())
}

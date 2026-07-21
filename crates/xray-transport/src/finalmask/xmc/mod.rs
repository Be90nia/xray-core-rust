//! # XMC Minecraft 协议伪装（对应 Go `transport/internet/finalmask/xmc/`）
//!
//! 把代理流量伪装成 Minecraft Java Edition 1.17+ 的 Login 握手——客户端发起
//! MC Login Start，服务端发 Encryption Request，双方用 RSA + AES-128-CFB8
//! 协商出对称密钥后透传数据。共享密码通过 RSA 加密的 verify token 验证。
//!
//! 本模块只支持 TCP（与 Go 一致——`xmc/config.go` 只有 `TCP()` 方法）。
//!
//! ## 子模块
//!
//! - [`protocol`]：MC 协议原语（VarInt / String / Bytes / UnsignedShort / Long / UUID + packet IO）
//! - [`cfb8`]：AES-128-CFB8 流加密（1 字节 feedback）
//! - [`derivation`]：从 password 确定性派生 RSA-1024 私钥
//! - [`conn`]：客户端/服务端握手流程 + TCP bridge

pub mod cfb8;
pub mod conn;
pub mod derivation;
pub mod protocol;

use std::io;

use super::{AsyncIo, Tcpmask, UDP_SIZE};

/// XMC 配置（对应 Go `xmc/Config` protobuf）。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 候选用户名列表（客户端随机选一个）。
    pub usernames: Vec<String>,
    /// 共享密码（写入 verifyToken 后段，服务端校验）。
    pub password: String,
    /// RSA 私钥（PKCS#1 DER）。服务端握手必需；客户端可省略。
    pub rsa_private_key: Vec<u8>,
    /// RSA 公钥（PKIX DER）。客户端 + 服务端均需（客户端校验服务端公钥匹配）。
    pub rsa_public_key: Vec<u8>,
    /// 伪装连接的主机名（写入 Handshake packet 的 serverAddress 字段）。
    pub hostname: String,
}

impl Tcpmask for Config {
    fn wrap_conn_client(&self, raw: Box<dyn AsyncIo>) -> io::Result<Box<dyn AsyncIo>> {
        let (client, server) = tokio::io::duplex(UDP_SIZE * 2);
        let config = self.clone();
        tokio::spawn(conn::tcp_bridge(raw, server, true, config));
        Ok(Box::new(client))
    }

    fn wrap_conn_server(&self, raw: Box<dyn AsyncIo>) -> io::Result<Box<dyn AsyncIo>> {
        let (client, server) = tokio::io::duplex(UDP_SIZE * 2);
        let config = self.clone();
        tokio::spawn(conn::tcp_bridge(raw, server, false, config));
        Ok(Box::new(client))
    }
}

#[cfg(test)]
mod tests {
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::EncodePublicKey;
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 单向：client → server（握手 + CFB8 加密）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_to_server_roundtrip() {
        let password = "super-secure-shared-key-12345";
        let private_key = derivation::derive_rsa_key(password).expect("derive rsa key");
        let private_der = private_key.to_pkcs1_der().expect("to_pkcs1_der").as_bytes().to_vec();
        let public_key = <rsa::RsaPublicKey as From<&rsa::RsaPrivateKey>>::from(&private_key);
        let public_der = public_key
            .to_public_key_der()
            .expect("to_public_key_der")
            .as_bytes()
            .to_vec();

        let config = Config {
            usernames: vec!["test_user".into()],
            password: password.into(),
            rsa_private_key: private_der,
            rsa_public_key: public_der,
            hostname: "localhost".into(),
        };

        let (client_raw, server_raw) = tokio::io::duplex(UDP_SIZE * 4);
        let wrapped_client: Box<dyn AsyncIo> =
            config.wrap_conn_client(Box::new(client_raw)).unwrap();
        let wrapped_server: Box<dyn AsyncIo> =
            config.wrap_conn_server(Box::new(server_raw)).unwrap();

        use tokio::io::split;
        let (_cr, mut cw) = split(wrapped_client);
        let (mut sr, _sw) = split(wrapped_server);

        let msg = b"hello from client via xmc handshake";
        let write_fut = async {
            cw.write_all(msg).await.unwrap();
            cw.shutdown().await.ok();
        };
        let read_fut = async {
            let mut got = Vec::new();
            sr.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, msg);
        };
        tokio::join!(write_fut, read_fut);
    }

    /// 单向：server → client（握手 + CFB8 加密）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_to_client_roundtrip() {
        let password = "super-secure-shared-key-12345";
        let private_key = derivation::derive_rsa_key(password).expect("derive rsa key");
        let private_der = private_key.to_pkcs1_der().expect("to_pkcs1_der").as_bytes().to_vec();
        let public_key = <rsa::RsaPublicKey as From<&rsa::RsaPrivateKey>>::from(&private_key);
        let public_der = public_key
            .to_public_key_der()
            .expect("to_public_key_der")
            .as_bytes()
            .to_vec();

        let config = Config {
            usernames: vec!["test_user".into()],
            password: password.into(),
            rsa_private_key: private_der,
            rsa_public_key: public_der,
            hostname: "localhost".into(),
        };

        let (client_raw, server_raw) = tokio::io::duplex(UDP_SIZE * 4);
        let wrapped_client: Box<dyn AsyncIo> =
            config.wrap_conn_client(Box::new(client_raw)).unwrap();
        let wrapped_server: Box<dyn AsyncIo> =
            config.wrap_conn_server(Box::new(server_raw)).unwrap();

        use tokio::io::split;
        let (mut cr, _cw) = split(wrapped_client);
        let (_sr, mut sw) = split(wrapped_server);

        let msg = b"hello from server via xmc handshake";
        let write_fut = async {
            sw.write_all(msg).await.unwrap();
            sw.shutdown().await.ok();
        };
        let read_fut = async {
            let mut got = Vec::new();
            cr.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, msg);
        };
        tokio::join!(write_fut, read_fut);
    }

    /// 密码不匹配应导致握手失败（双方 bridge 提前退出，pipe EOF）。
    #[tokio::test]
    async fn password_mismatch_breaks_pipe() {
        let pw_server = "server-secret-123";
        let pw_client = "client-secret-456";

        let private_key = derivation::derive_rsa_key(pw_server).expect("derive rsa key");
        let private_der = private_key.to_pkcs1_der().unwrap().as_bytes().to_vec();
        let public_key = <rsa::RsaPublicKey as From<&rsa::RsaPrivateKey>>::from(&private_key);
        let public_der = public_key.to_public_key_der().unwrap().as_bytes().to_vec();

        let server_cfg = Config {
            usernames: vec!["test_user".into()],
            password: pw_server.into(),
            rsa_private_key: private_der.clone(),
            rsa_public_key: public_der.clone(),
            hostname: "localhost".into(),
        };
        let client_cfg = Config {
            usernames: vec!["test_user".into()],
            password: pw_client.into(),
            rsa_private_key: vec![],
            rsa_public_key: public_der,
            hostname: "localhost".into(),
        };

        let (client_raw, server_raw) = tokio::io::duplex(UDP_SIZE * 4);
        let wrapped_client: Box<dyn AsyncIo> =
            client_cfg.wrap_conn_client(Box::new(client_raw)).unwrap();
        let wrapped_server: Box<dyn AsyncIo> =
            server_cfg.wrap_conn_server(Box::new(server_raw)).unwrap();

        let (mut cr, _cw) = tokio::io::split(wrapped_client);
        let (_sr, mut sw) = tokio::io::split(wrapped_server);

        sw.write_all(b"data that should not arrive").await.ok();
        sw.shutdown().await.ok();

        let mut got = Vec::new();
        let _ = cr.read_to_end(&mut got).await;
        // 握手失败后 client bridge 可能收到 server 写的 disconnect packet（明文），
        // 被 client bridge 错误解密成垃圾。重要的是：sw 写的明文不会原样到达 client。
        assert_ne!(
            got, b"data that should not arrive".to_vec(),
            "plaintext should not pass through on handshake failure"
        );
    }
}

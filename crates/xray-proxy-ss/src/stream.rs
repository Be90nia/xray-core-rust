//! SS 流式 AEAD body，对应 Go `common/crypto/auth.go` 的 AuthenticationWriter/Reader。
//!
//! # Wire format
//!
//! 每个 chunk = `[sealed_size(2+tag)][sealed_payload(len+tag)]`
//! - size chunk 明文 = `BE u16 (payload.len + tag_size)`
//! - nonce 序列：`[0xFF;n]` → increment → `[0;n]`（首帧 size）→ `[1,0,...]`（首帧 payload）
//!   → `[2,0,...]`（body size）→ `[3,0,...]`（body payload）...
//!
//! # 设计
//!
//! 不实现 `AsyncRead`/`AsyncWrite` trait（Pin 复杂，SS chunk 天然是分帧语义）。
//! 提供 `write_chunk`/`read_chunk`/`flush`/`shutdown` 四个 async 方法，桥接时用循环。

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::MemoryAccount;
use crate::error::{Result, SsError};

/// SS 流式 AEAD 读写器（**读/写双方向独立 AEAD+nonce**）。
///
/// 持有底层连接（`AsyncRead + AsyncWrite`）+ 两个独立的 AEAD cipher + 两个独立的
/// nonce 状态（分别服务走 / 读侧）。SS wire 上每方向 AEAD 计数器独立递增——
/// 与 sing `shadowaead.Reader`/`Writer` 一致。本结构之前读写共享 AEAD+nonce，
/// 在 legacy IV rekey 和 SS-2022 response rekey 后会造成写方向 nonce 错乱。
pub struct SSStream<C> {
    inner: C,
    write_aead: std::sync::Arc<dyn xray_crypto::aead::AeadCipher + Send + Sync>,
    write_nonce: Vec<u8>,
    read_aead: std::sync::Arc<dyn xray_crypto::aead::AeadCipher + Send + Sync>,
    read_nonce: Vec<u8>,
    tag_size: usize,
    /// 非空 = 下次 `read_chunk` 前先读 server response 的新 IV 并 rekey 读侧 AEAD
    /// （legacy Go `WriteTCPResponse` 模式）。见 [`Client::dial_target_for_proxy`]。
    response_rekey: Option<MemoryAccount>,
    /// 非空 = 下次 `try_open_chunk` 推进 SS-2022 响应头分阶段解析
    ///（sing `clientConn.readResponse`：salt→subkey→fixed chunk→variable chunk）。
    /// 见 [`Client2022::dial_target_on`]。
    response_rekey_2022: Option<Rekey2022>,
    /// 半帧状态：size chunk 已解、payload 未收齐时的 wire 长度（`try_open_chunk` 用）。
    pending_payload: Option<usize>,
    /// SS-2022 服务端响应懒写头状态（`mark_server_response_2022` 设置）。
    pending_server_2022: Option<PendingServer2022>,
    /// 已解密待交付的请求首段明文（SS-2022 variable chunk 尾部 payload，
    /// 对应 sing `serverConn` reader 的 cached 语义）。
    plain_prefix: Vec<u8>,
}

/// SS-2022 响应头分阶段解析（读侧 lazy rekey，缓冲版）。
///
/// 响应 wire：`[salt(salt_size)][sealed fixed_header(1+8+salt_size+2 + tag)]
///            [sealed variable_header(var_len + tag)]<body chunks...>`
///
/// sing `clientConn.readResponse`：salt → blake3 重派生 subkey → 用新 AEAD 解
/// fixed header（type=1 + timestamp + echoed salt + variable length）→ 解
/// variable header（padding，丢弃）→ 后续 body chunks 标准 size+payload。
/// 各阶段都可能因缓冲字节不够而回退等待；drained 字节不可恢复。
enum Rekey2022 {
    /// 等待 response salt（salt_size 字节），随后派生读侧 AEAD。
    Salt {
        psk: Vec<u8>,
        kind: crate::ss2022::CipherKind2022,
        request_salt: Vec<u8>,
    },
    /// 等待 fixed header chunk wire 字节（fixed_plain + tag）。
    Fixed {
        fixed_plain: usize,
        request_salt: Vec<u8>,
    },
    /// 等待 variable header chunk wire 字节（var_len + tag，内容验证后丢弃）。
    Var { var_len: usize },
}

/// SS-2022 服务端响应头懒写出输入（sing `serverConn.writeResponse` 所需）。
struct PendingServer2022 {
    psk: Vec<u8>,
    kind: crate::ss2022::CipherKind2022,
    request_salt: Vec<u8>,
}

/// LE increment（byte[0]++，进位），对应 Go `GenerateIncreasingNonce`。
fn increment_nonce_bytes(nonce: &mut [u8]) {
    for b in nonce.iter_mut() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            break;
        }
    }
}

/// 由 account 的 cipher 类型返回 aead nonce 大小。
///
/// - AES-128/256-GCM、ChaCha20-Poly1305：12
/// - XChaCha20-Poly1305：24
fn ss_nonce_size(account: &MemoryAccount) -> usize {
    use crate::config::CipherType;
    match account.cipher_type {
        CipherType::XChaCha20Poly1305 => 24,
        _ => 12,
    }
}

impl<C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> SSStream<C> {
    /// 通用构造：传入初始 nonce 状态。
    ///
    /// # Errors
    pub fn new(inner: C, account: &MemoryAccount, iv: &[u8], initial_nonce: Vec<u8>) -> Result<Self> {
        let write_aead = account
            .cipher
            .create_aead(&account.key, iv)?
            .ok_or(SsError::UnsupportedCipher)?;
        // 读写两方向需要独立的 AEAD 实例（AeadCipher 非 Clone）；构造同 key/iv。
        let read_aead = account
            .cipher
            .create_aead(&account.key, iv)?
            .ok_or(SsError::UnsupportedCipher)?;
        let tag_size = write_aead.tag_size();
        Ok(Self {
            inner,
            write_aead: std::sync::Arc::from(write_aead),
            write_nonce: initial_nonce.clone(),
            read_aead: std::sync::Arc::from(read_aead),
            read_nonce: initial_nonce,
            tag_size,
            response_rekey: None,
            response_rekey_2022: None,
            pending_payload: None,
            pending_server_2022: None,
            plain_prefix: Vec::new(),
        })
    }

    /// client 端构造：读写 nonce 均从 `[0xFF;n]` 开始。
    ///
    /// 第一次 `write_chunk` 前 increment → `[0;n]`（首帧 size）→ `[1,0,...]`（首帧 payload）。
    /// 首帧 plaintext 应为 addr+port（SS 地址格式）。
    /// # Errors
    /// - 透传 [`Self::new`] 错误。
    pub fn new_client(inner: C, account: &MemoryAccount, iv: &[u8]) -> Result<Self> {
        let nonce_size = ss_nonce_size(account);
        Self::new(inner, account, iv, vec![0xFFu8; nonce_size])
    }

    /// server body 构造：读写 nonce 均从 `[1,0,...]` 开始
    /// （首帧 `[0;n]`+`[1,0,...]` 已由 `decode_tcp_request_header` 消耗，
    /// 下一次 increment = `[2,0,...]` 进入 body）。
    /// # Errors
    /// - 透传 [`Self::new`] 错误。
    pub fn new_server_body(inner: C, account: &MemoryAccount, iv: &[u8]) -> Result<Self> {
        let nonce_size = ss_nonce_size(account);
        let mut initial = vec![0u8; nonce_size];
        if nonce_size > 0 {
            initial[0] = 1;
        }
        Self::new(inner, account, iv, initial)
    }

    /// SS-2022 通用构造：传入已派生的 AEAD + nonce_size（读写同 nonce 起 `[0xFF;n]`）。
    ///
    /// 调用方负责把读侧 rekey 触发条件设上（`mark_response_rekey_2022`）——
    /// 此构造函数本身读侧是占位 aead；首次 `try_open_chunk` 先跑 rekey 状态机
    /// 才会替换读侧 AEAD。
    #[must_use]
    pub fn new_with_aead(
        inner: C,
        aead: Box<dyn xray_crypto::aead::AeadCipher + Send + Sync>,
        nonce_size: usize,
    ) -> Self {
        let tag_size = aead.tag_size();
        // 读写共享同一 Arc；读侧 aead 会被 rekey 替换（独立 Arc swap）。
        let arc = std::sync::Arc::from(aead);
        Self {
            inner,
            write_aead: std::sync::Arc::clone(&arc),
            write_nonce: vec![0xFFu8; nonce_size],
            read_aead: arc,
            read_nonce: vec![0xFFu8; nonce_size],
            tag_size,
            response_rekey: None,
            response_rekey_2022: None,
            pending_payload: None,
            pending_server_2022: None,
            plain_prefix: Vec::new(),
        }
    }

    /// 写一个 SS chunk：`[sealed_size(2+tag)][sealed_payload(len+tag)]`。
    ///
    /// plaintext 通常是一段应用层数据（HTTP 请求、TLS record 等）。
    /// 客户端的**第一个** `write_chunk` 应传 addr+port（SS 地址格式），作为首帧。
    ///
    /// 超过单块上限时自动分块（对应 Go `AuthenticationWriter.writeStream` 按
    /// `buf.Size(8192) - tag - 2` 分块），调用方无需关心大小。
    /// 空输入不产生任何 chunk（size=0 是流结束标记，不能由本方法发出）。
    ///
    /// # Errors
    /// - [`SsError::AeadSeal`]：AEAD 加密失败。
    /// - [`SsError::Io`]：底层写失败。
    pub async fn write_chunk(&mut self, plaintext: &[u8]) -> Result<()> {
        if plaintext.is_empty() {
            return Ok(());
        }
        // SS-2022 服务端响应懒写头（sing `serverConn.writeResponse`，service.go:261）：
        // [resp_salt][AEAD(fixed: type=1|epoch|echo_salt|payload_len)][AEAD(首段数据)]。
        // 响应握手 chunk **无 2B size 前缀**（sing Writer.WriteChunk 直 seal，客户端
        // Reader.ReadWithLength 定长读），fixed 用 nonce [0]、首段数据 [1]；之后
        // body 才走 [2B size+tag][payload+tag] 常规 chunk（nonce [2] 起）。
        let mut rest = plaintext;
        if let Some(p) = self.pending_server_2022.take() {
            let salt: Vec<u8> = (0..p.kind.salt_size()).map(|_| rand::random::<u8>()).collect();
            let subkey = crate::ss2022::derive_session_subkey(&p.psk, &salt, p.kind);
            let aead = crate::ss2022::key::build_aead(p.kind, &subkey)
                .map_err(|e| SsError::InitDecode(e.to_string()))?;
            self.tag_size = aead.tag_size();
            self.write_nonce = vec![0xFFu8; aead.nonce_size()];
            self.write_aead = std::sync::Arc::from(aead);
            let first_len = plaintext.len().min(8192 - self.tag_size - 2);
            let epoch = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| SsError::GetCipher(e.to_string()))?
                .as_secs();
            let mut fixed = Vec::with_capacity(11 + p.request_salt.len());
            fixed.push(1u8); // HeaderTypeServer
            fixed.extend_from_slice(&epoch.to_be_bytes());
            fixed.extend_from_slice(&p.request_salt);
            fixed.extend_from_slice(
                &u16::try_from(first_len)
                    .map_err(|_| SsError::InsufficientData(first_len))?
                    .to_be_bytes(),
            );
            self.inner.write_all(&salt).await?;
            increment_nonce_bytes(&mut self.write_nonce);
            let sealed_fixed = self
                .write_aead
                .seal(&self.write_nonce, &[], &fixed)
                .map_err(|e| SsError::AeadSeal(e.to_string()))?;
            self.inner.write_all(&sealed_fixed).await?;
            increment_nonce_bytes(&mut self.write_nonce);
            let sealed_first = self
                .write_aead
                .seal(&self.write_nonce, &[], &plaintext[..first_len])
                .map_err(|e| SsError::AeadSeal(e.to_string()))?;
            self.inner.write_all(&sealed_first).await?;
            rest = &plaintext[first_len..];
        }
        // 8192 = Go buf.Size；tag_size+2 是 size chunk 的 wire 开销。
        let max_payload = 8192 - self.tag_size - 2;
        for part in rest.chunks(max_payload.max(1)) {
            self.write_single_chunk(part).await?;
        }
        Ok(())
    }

    /// 写单个（已保证 ≤ 块上限的）chunk。
    async fn write_single_chunk(&mut self, plaintext: &[u8]) -> Result<()> {
        // seal size chunk
        increment_nonce_bytes(&mut self.write_nonce);
        let plain_size = u16::try_from(plaintext.len())
            .map_err(|_| SsError::InsufficientData(plaintext.len()))?;
        let sealed_size = self
            .write_aead
            .seal(&self.write_nonce, &[], &plain_size.to_be_bytes())
            .map_err(|e| SsError::AeadSeal(e.to_string()))?;

        // seal payload chunk
        increment_nonce_bytes(&mut self.write_nonce);
        let sealed_payload = self
            .write_aead
            .seal(&self.write_nonce, &[], plaintext)
            .map_err(|e| SsError::AeadSeal(e.to_string()))?;

        self.inner.write_all(&sealed_size).await?;
        self.inner.write_all(&sealed_payload).await?;
        Ok(())
    }

    /// 写一个 raw chunk（直接 seal，无 size prefix）。
    ///
    /// 用于 SS-2022 header chunk（fixed-header + variable-header），
    /// 对应 Go `shadowaead.Writer.WriteChunk`。
    ///
    /// 与 `write_chunk` 的区别：只 seal 一次（不分 size/payload），nonce 只 increment 一次。
    pub async fn write_raw_chunk(&mut self, plaintext: &[u8]) -> Result<()> {
        increment_nonce_bytes(&mut self.write_nonce);
        let sealed = self
            .write_aead
            .seal(&self.write_nonce, &[], plaintext)
            .map_err(|e| SsError::AeadSeal(e.to_string()))?;
        self.inner.write_all(&sealed).await?;
        Ok(())
    }

    /// flush 底层连接。
    /// # Errors
    /// - 透传 IO 错误。
    pub async fn flush(&mut self) -> Result<()> {
        self.inner.flush().await?;
        Ok(())
    }

    /// 关闭写方向（发送 TCP FIN）。
    /// # Errors
    /// - 透传 IO 错误。
    pub async fn shutdown(&mut self) -> Result<()> {
        self.inner.shutdown().await?;
        Ok(())
    }
    /// SS-2022 通用构造：传入已派生的 AEAD + 初始 nonce（写侧用）。
    ///
    /// 写侧 aead = 入参 aead；写侧 nonce = `initial_nonce`。读侧 aead 占位同源
    #[must_use]
    pub fn new_with_aead_and_nonce(
        inner: C,


        aead: Box<dyn xray_crypto::aead::AeadCipher + Send + Sync>,
        initial_nonce: Vec<u8>,
    ) -> Self {
        let tag_size = aead.tag_size();
        let nonce_size = aead.nonce_size();
        // 读写共享同一 Arc（写侧+占位读侧同实例）；读侧 aead 将在 SS-2022
        // rekey 时被替换为独立 response subkey Arc。rekey 前不应被读侧调用，
        // 生产路径总是先 `mark_response_rekey_2022` 再驱动 `try_open_chunk`。
        let arc = std::sync::Arc::from(aead);
        Self {
            inner,
            write_aead: std::sync::Arc::clone(&arc),
            write_nonce: initial_nonce,
            read_aead: arc,
            read_nonce: vec![0xFFu8; nonce_size],
            tag_size,
            response_rekey: None,
            response_rekey_2022: None,
            pending_payload: None,
            pending_server_2022: None,
            plain_prefix: Vec::new(),
        }
    }

    /// 读一个 SS chunk，返回 plaintext（legacy 路径；SS-2022 走 `try_open_chunk`）。
    ///
    /// 返回 `Ok(None)` 表示流结束（inner EOF 或读到 0 长度 chunk）。
    ///
    /// # Errors
    /// - [`SsError::AeadOpen`]：AEAD 解密失败（tag 不匹配 / 数据损坏）。
    /// - [`SsError::Io`]：底层读失败（含 UnexpectedEof）。
    pub async fn read_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        // SS-2022 服务端：variable chunk 尾部携带的请求首段 payload
        //（sing reader.cached 语义）先于 body chunk 交付。
        if !self.plain_prefix.is_empty() {
            return Ok(Some(std::mem::take(&mut self.plain_prefix)));
        }
        // lazy rekey：Go server response 以新 IV 开头（`WriteTCPResponse`），且只在
        // server 有响应数据时才发出。dial 后立即读 IV 会与「server 等 client body、
        // client 等 server IV」互等死锁，故延迟到第一次 read_chunk 时读取。
        if let Some(account) = self.response_rekey.take() {
            self.rekey_for_response(&account).await?;
        }

        // 读 size chunk（2 + tag_size = 18B for AES-GCM/ChaCha20）
        let size_wire_len = 2 + self.tag_size;
        let mut size_buf = vec![0u8; size_wire_len];
        match self.inner.read_exact(&mut size_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(SsError::from(e)),
        }

        // open size chunk
        increment_nonce_bytes(&mut self.read_nonce);
        let size_plain = self
            .read_aead
            .open(&self.read_nonce, &[], &size_buf)
            .map_err(|e| SsError::AeadOpen(e.to_string()))?;
        if size_plain.len() < 2 {
            return Err(SsError::InsufficientData(size_plain.len()));
        }
        let payload_len = u16::from_be_bytes([size_plain[0], size_plain[1]]) as usize;

        // 0 长度 = 流结束标记
        if payload_len == 0 {
            return Ok(None);
        }

        // 读 payload chunk：wire = payload_len (ciphertext) + tag_size
        let wire_len = payload_len + self.tag_size;
        let mut payload_buf = vec![0u8; wire_len];
        self.inner.read_exact(&mut payload_buf).await?;

        // open payload
        increment_nonce_bytes(&mut self.read_nonce);
        let plaintext = self
            .read_aead
            .open(&self.read_nonce, &[], &payload_buf)
            .map_err(|e| SsError::AeadOpen(e.to_string()))?;

        Ok(Some(plaintext))
    }

    /// 从应用层缓冲 `pending` 解出一个完整 SS chunk（`try_open_chunk` 返回态）。
    ///
    /// - `NeedMore`：数据不足（不推进 nonce、不改缓冲语义之外的状态）
    /// - `Message`：解出一帧明文（nonce 推进，wire 字节从 pending drain）
    /// - `End`：0 长度 chunk = 流结束标记
    ///
    /// 与 [`Self::read_chunk`] 的区别：读来源是调用方维护的缓冲而非直接 IO，
    /// 使 pump 层可以用 cancel-safe 的单次底层 read 喂数据（`Box<dyn Connection>`
    /// 无 TcpStream::readable）。半帧状态存 [`Self::pending_payload`]。
    pub fn try_open_chunk(&mut self, pending: &mut Vec<u8>) -> Result<ChunkOut> {
        if !self.plain_prefix.is_empty() {
            return Ok(ChunkOut::Message(std::mem::take(&mut self.plain_prefix)));
        }
        // SS-2022 响应分阶段 rekey（缓冲版）—— sing clientConn.readResponse。
        // 必须在 legacy rekey 前推进：salt 已 drained 字节不可恢复，状态机需顺序消费。
        if self.response_rekey_2022.is_some() {
            return self.drive_2022_rekey(pending);
        }
        // legacy IV rekey（缓冲版）：IV 不够时原样放回等待
        if let Some(account) = self.response_rekey.take() {
            let iv_size = account.cipher.iv_size() as usize;
            if pending.len() < iv_size {
                self.response_rekey = Some(account);
                return Ok(ChunkOut::NeedMore);
            }
            let iv: Vec<u8> = pending.drain(..iv_size).collect();
            let aead = account
                .cipher
                .create_aead(&account.key, &iv)?
                .ok_or(SsError::UnsupportedCipher)?;
            self.tag_size = aead.tag_size();
            self.read_nonce = vec![0xFFu8; aead.nonce_size()];
            self.read_aead = std::sync::Arc::from(aead);
        }

        // 半帧恢复：size chunk 已解，直接等 payload
        let wire_len = if let Some(n) = self.pending_payload {
            n
        } else {
            let size_wire_len = 2 + self.tag_size;
            if pending.len() < size_wire_len {
                return Ok(ChunkOut::NeedMore);
            }
            let size_buf: Vec<u8> = pending.drain(..size_wire_len).collect();
            increment_nonce_bytes(&mut self.read_nonce);
            let size_plain = self
                .read_aead
                .open(&self.read_nonce, &[], &size_buf)
                .map_err(|e| SsError::AeadOpen(e.to_string()))?;
            if size_plain.len() < 2 {
                return Err(SsError::InsufficientData(size_plain.len()));
            }
            let payload_len = u16::from_be_bytes([size_plain[0], size_plain[1]]) as usize;
            if payload_len == 0 {
                return Ok(ChunkOut::End);
            }
            let wire = payload_len + self.tag_size;
            self.pending_payload = Some(wire);
            wire
        };

        if pending.len() < wire_len {
            return Ok(ChunkOut::NeedMore);
        }
        let payload_buf: Vec<u8> = pending.drain(..wire_len).collect();
        self.pending_payload = None;
        increment_nonce_bytes(&mut self.read_nonce);
        let plaintext = self
            .read_aead
            .open(&self.read_nonce, &[], &payload_buf)
            .map_err(|e| SsError::AeadOpen(e.to_string()))?;
        Ok(ChunkOut::Message(plaintext))
    }

    /// SS-2022 响应 rekey 状态机：salt → fixed → var（sing `readResponse` 缓冲版）。
    fn drive_2022_rekey(&mut self, pending: &mut Vec<u8>) -> Result<ChunkOut> {
        // 循环推进各阶段；任一阶段需更多字节 → NeedMore（状态保留）。
        loop {
            let stage = match self.response_rekey_2022.take() {
                Some(s) => s,
                None => break, // rekey 完成，落到下面的 half-frame / body loop。
            };
            match stage {
                Rekey2022::Salt { psk, kind, request_salt } => {
                    let salt_size = kind.salt_size();
                    if pending.len() < salt_size {
                        self.response_rekey_2022 = Some(Rekey2022::Salt { psk, kind, request_salt });
                        return Ok(ChunkOut::NeedMore);
                    }
                    let salt: Vec<u8> = pending.drain(..salt_size).collect();
                    let subkey = crate::ss2022::derive_session_subkey(&psk, &salt, kind);
                    let aead = crate::ss2022::key::build_aead(kind, &subkey)
                        .map_err(|e| SsError::InitDecode(e.to_string()))?;
                    self.tag_size = aead.tag_size();
                    self.read_nonce = vec![0xFFu8; aead.nonce_size()];
                    self.read_aead = std::sync::Arc::from(aead);
                    let fixed_plain = 1 + 8 + salt_size + 2;
                    self.response_rekey_2022 = Some(Rekey2022::Fixed { fixed_plain, request_salt });
                    // 立即进入下一阶段
                }
                Rekey2022::Fixed { fixed_plain, request_salt } => {
                    let wire = fixed_plain + self.tag_size;
                    if pending.len() < wire {
                        self.response_rekey_2022 = Some(Rekey2022::Fixed { fixed_plain, request_salt });
                        return Ok(ChunkOut::NeedMore);
                    }
                    let buf: Vec<u8> = pending.drain(..wire).collect();
                    increment_nonce_bytes(&mut self.read_nonce);
                    let plain = self
                        .read_aead
                        .open(&self.read_nonce, &[], &buf)
                        .map_err(|e| SsError::AeadOpen(e.to_string()))?;
                    if plain.len() != fixed_plain {
                        return Err(SsError::InsufficientData(plain.len()));
                    }
                    // headerType(1) + epoch(8) + echo_salt(salt_len) + var_len(2)
                    let header_type = plain[0];
                    if header_type != 1 {
                        return Err(SsError::Ss2022InvalidHeaderType(header_type));
                    }
                    let epoch = u64::from_be_bytes(
                        plain[1..9].try_into().expect("epoch slice is 8 bytes"),
                    );
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|e| SsError::GetCipher(e.to_string()))?
                        .as_secs();
                    if now.abs_diff(epoch) > 30 {
                        return Err(SsError::Ss2022TimestampCheck(format!(
                            "epoch {epoch} vs now {now}"
                        )));
                    }
                    let salt_len = fixed_plain - 11;
                    let echo = &plain[9..9 + salt_len];
                    // sing: reject if echoed salt > sent salt (lexicographic).
                    if echo.cmp(request_salt.as_slice()) == std::cmp::Ordering::Greater {
                        return Err(SsError::Ss2022BadRequestSalt);
                    }
                    let var_len = u16::from_be_bytes(
                        [plain[9 + salt_len], plain[10 + salt_len]],
                    ) as usize;
                    self.response_rekey_2022 = Some(Rekey2022::Var { var_len });
                }
                Rekey2022::Var { var_len } => {
                    // sing server writeResponse（service.go:294-296）payload_len>0 时
                    // WriteChunk(header, payload[:payloadLen]) 把 payload 字节直接 seal
                    // 进 var chunk——**var chunk 就是 first body 字节**，不是单独的
                    // "variable header"！sing client readResponse（protocol.go:392）
                    // reader.ReadWithLength(length) 把 var_len 字节 open 后**缓存**在
                    // reader.cached，下一次 Read() 返给用户。所以 Rust 之前把 var 当
                    // `_plain` 丢弃是错的——那是真实响应体第一段。
                    //
                    // 修复：drain var_len+tag → increment nonce → open → 返 Message。
                    // nonce 序列：Fixed 已 increment → [0,0,...n]，Var 再 increment →
                    // [1,0,...n]（对齐 sing cached 时的 nonce）。Body 后续 size/payload
                    // chunk 在 try_open_chunk_body 解，nonce 序列对齐 sing
                    // ReadWithLengthChunk。
                    //
                    // payload_len=0 时 sing server 不写 var chunk（service.go:294 if），
                    // 但 wire 上 sing client 仍 reader.ReadWithLength(0) 读 16B sealed
                    // zero——这是 sing client+server 配对 bug；**实际 sing-box 服务端
                    // 始终发 payload>0**（HTTP body 第一块），var_len=0 走"无 var chunk"
                    // fast path（不进 Var phase 状态机），由 Fixed 完成后直接进 body。
                    let wire = var_len + self.tag_size;
                    if pending.len() < wire {
                        self.response_rekey_2022 = Some(Rekey2022::Var { var_len });
                        return Ok(ChunkOut::NeedMore);
                    }
                    let buf: Vec<u8> = pending.drain(..wire).collect();
                    increment_nonce_bytes(&mut self.read_nonce);
                    let plain = self
                        .read_aead
                        .open(&self.read_nonce, &[], &buf)
                        .map_err(|e| SsError::AeadOpen(e.to_string()))?;
                    return Ok(ChunkOut::Message(plain));
                }
            }
        }
        // rekey 完成；进入正常 body 解帧（沿用下方 half-frame + size/payload 路径）。
        // 重新进入 try_open_chunk 本体后半（跳过本轮 rekey 块直接到 body loop）。
        // 这里通过递归调用 try_open_chunk 自身避免代码重复；pending 不含被本函数消耗字节。
        self.try_open_chunk_body(pending)
    }

    /// `try_open_chunk` 的 size/payload 解帧主体（在 SS-2022 rekey 完成后调用）。
    fn try_open_chunk_body(&mut self, pending: &mut Vec<u8>) -> Result<ChunkOut> {
        let wire_len = if let Some(n) = self.pending_payload {
            n
        } else {
            let size_wire_len = 2 + self.tag_size;
            if pending.len() < size_wire_len {
                return Ok(ChunkOut::NeedMore);
            }
            let size_buf: Vec<u8> = pending.drain(..size_wire_len).collect();
            increment_nonce_bytes(&mut self.read_nonce);
            let size_plain = self
                .read_aead
                .open(&self.read_nonce, &[], &size_buf)
                .map_err(|e| SsError::AeadOpen(e.to_string()))?;
            if size_plain.len() < 2 {
                return Err(SsError::InsufficientData(size_plain.len()));
            }
            let payload_len = u16::from_be_bytes([size_plain[0], size_plain[1]]) as usize;
            if payload_len == 0 {
                return Ok(ChunkOut::End);
            }
            let wire = payload_len + self.tag_size;
            self.pending_payload = Some(wire);
            wire
        };

        if pending.len() < wire_len {
            return Ok(ChunkOut::NeedMore);
        }
        let payload_buf: Vec<u8> = pending.drain(..wire_len).collect();
        self.pending_payload = None;
        increment_nonce_bytes(&mut self.read_nonce);
        let plaintext = self
            .read_aead
            .open(&self.read_nonce, &[], &payload_buf)
            .map_err(|e| SsError::AeadOpen(e.to_string()))?;
        Ok(ChunkOut::Message(plaintext))
    }

    /// 读一个 raw chunk（直接 open，无 size prefix），指定 wire 长度。
    ///
    /// 用于 SS-2022 响应的 header chunk（fixed + variable），
    /// 对应 Go `shadowaead.Reader.ReadWithLength`。
    pub async fn read_raw_chunk(&mut self, wire_len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; wire_len];
        self.inner.read_exact(&mut buf).await?;
        increment_nonce_bytes(&mut self.read_nonce);
        let plaintext = self
            .read_aead
            .open(&self.read_nonce, &[], &buf)
            .map_err(|e| SsError::AeadOpen(e.to_string()))?;
        Ok(plaintext)
    }

    /// 获取底层连接的不可变引用。
    #[must_use]
    pub fn get_ref(&self) -> &C {
        &self.inner
    }

    /// 获取底层连接的可变引用。
    #[must_use]
    pub fn get_mut(&mut self) -> &mut C {
        &mut self.inner
    }

    /// 消费 SSStream，返回底层连接。
    #[must_use]
    pub fn into_inner(self) -> C {
        self.inner
    }

    /// server 侧预设读侧 nonce 续接请求 header 序列（sing 无方向独立 reset）：
    /// `read_ss2022_request*` 已按 [0;12]/[1,0..] 消费 fixed/var 两个 chunk，
    /// body 首帧在 [2,0..] 解——读侧起点须与写侧相同（[1,0..]，首个
    /// increment 后对齐）。client 流读侧恒被 response rekey 覆盖，不受影响。
    pub(crate) fn continue_read_nonce(&mut self) {
        self.read_nonce = self.write_nonce.clone();
    }

    /// 标记流为「读 Go 风格 server response」（legacy IV rekey）：
    /// 第一次 `read_chunk` 前先读 IV 并 rekey 读侧 AEAD。
    ///
    /// 对应 [`Client::dial_target_for_proxy`] 的 lazy rekey 模式。
    pub fn mark_response_rekey(&mut self, account: MemoryAccount) {
        self.response_rekey = Some(account);
    }

    /// 标记流为「读 SS-2022 server response」（响应头分阶段解析）：
    /// 第一次 `try_open_chunk` 前先按 sing `readResponse` 格式消费 salt →
    /// fixed header chunk → variable header chunk，然后切到 body chunks。
    pub fn mark_response_rekey_2022(
        &mut self,
        psk: Vec<u8>,
        kind: crate::ss2022::CipherKind2022,
        request_salt: Vec<u8>,
    ) {
        self.response_rekey_2022 = Some(Rekey2022::Salt { psk, kind, request_salt });
    }

    /// 服务端模式：标记下行首写时发 SS-2022 响应头（sing `writeResponse`）。
    /// `psk` 为已规整的 server/user PSK；`request_salt` 为客户端请求 salt（回显用）。
    pub(crate) fn mark_server_response_2022(
        &mut self,
        psk: Vec<u8>,
        kind: crate::ss2022::CipherKind2022,
        request_salt: Vec<u8>,
    ) {
        self.pending_server_2022 = Some(PendingServer2022 { psk, kind, request_salt });
    }

    /// 预置已解密明文（SS-2022 variable chunk 尾部的请求首段 payload），
    /// 下次 `read_chunk`/`try_open_chunk` 先于 wire chunk 交付。
    pub(crate) fn push_plain_prefix(&mut self, data: &[u8]) {
        self.plain_prefix.extend_from_slice(data);
    }

    /// 读 server response 的 IV + 用新 IV 派生新 aead + 重置读侧 nonce 到 `[0xFF;n]`。
    ///
    /// 对应 Go `proxy/shadowsocks/protocol.go::ReadTCPResponse`（行165-189）。
    ///
    /// # Errors
    /// - [`SsError::Io`]：底层读 IV 失败。
    /// - 透传 AEAD 派生错误。
    pub async fn rekey_for_response(&mut self, account: &MemoryAccount) -> Result<()> {
        let iv_size = account.cipher.iv_size() as usize;
        let mut iv = vec![0u8; iv_size];
        self.inner.read_exact(&mut iv).await?;
        let aead = account
            .cipher
            .create_aead(&account.key, &iv)?
            .ok_or(SsError::UnsupportedCipher)?;
        self.tag_size = aead.tag_size();
        self.read_nonce = vec![0xFFu8; aead.nonce_size()];
        self.read_aead = std::sync::Arc::from(aead);
        Ok(())
    }

    /// server 端响应方向 rekey，对应 Go `WriteTCPResponse`
    /// （proxy/shadowsocks/protocol.go:191-204）：生成新随机 IV **先行明文写出**，
    /// 写侧 AEAD 用新 IV 重派生（HKDF-SHA1 `"ss-subkey"`），write_nonce 重置
    /// `[0xFF;n]`（首写 increment → `[0;n]`，与 client `rekey_for_response`
    /// 的读侧序列对称）。
    ///
    /// 必须在响应数据写出前恰好调用一次；读侧不动（请求方向 AEAD 继续用）。
    ///
    /// # Errors
    /// - [`SsError::Io`]：底层写 IV 失败。
    /// - 透传 AEAD 派生错误。
    pub async fn begin_server_response(&mut self, account: &MemoryAccount) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        let iv_size = account.cipher.iv_size() as usize;
        let iv: Vec<u8> = (0..iv_size).map(|_| rand::random::<u8>()).collect();
        if iv_size > 0 {
            self.inner.write_all(&iv).await?;
            self.inner.flush().await?;
        }
        let aead = account
            .cipher
            .create_aead(&account.key, &iv)?
            .ok_or(SsError::UnsupportedCipher)?;
        let nonce_size = aead.nonce_size();
        self.write_aead = std::sync::Arc::from(aead);
        self.write_nonce = vec![0xFFu8; nonce_size];
        Ok(())
    }
}
/// [`SSStream::try_open_chunk`] 的返回态。
pub enum ChunkOut {
    /// 缓冲数据不足，等待更多 wire 字节。
    NeedMore,
    /// 解出一帧明文。
    Message(Vec<u8>),
    /// 0 长度 chunk = 流结束标记。
    End,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CipherType;
    use tokio::io::duplex;
    use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;

    fn make_account(ct: CipherType, password: &str) -> MemoryAccount {
        let p = ProtoAccount {
            password: password.to_string(),
            cipher_type: ct.as_i32(),
            iv_check: false,
        };
        MemoryAccount::from_proto(&p).expect("account")
    }

    /// 生成随机 IV（长度 = cipher.iv_size()）。
    fn random_iv(account: &MemoryAccount) -> Vec<u8> {
        let n = account.cipher.iv_size() as usize;
        (0..n).map(|_| rand::random()).collect()
    }

    /// client ↔ server 回环：创建一对 SSStream（共享 aead key/iv），互写互读。
    async fn roundtrip_pair(
        ct: CipherType,
    ) -> (SSStream<tokio::io::DuplexStream>, SSStream<tokio::io::DuplexStream>) {
        let account = make_account(ct, "test-password");
        let iv = random_iv(&account);

        // duplex：client_half ↔ server_half（tokio 内部连接）
        let (client_half, server_half) = duplex(8 * 1024);

        // client 端：nonce 从 [0xFF;n] 开始
        let client_stream = SSStream::new_client(client_half, &account, &iv).expect("client");
        // server 端：模拟 decode_tcp_request_header 已消耗首帧 nonce
        // 但这里我们测试 body roundtrip，server 从 [0xFF;n] 开始（双向独立）
        let server_account = make_account(ct, "test-password");
        let server_stream = SSStream::new_client(server_half, &server_account, &iv).expect("server");

        (client_stream, server_stream)
    }

    #[tokio::test]
    async fn write_read_single_chunk_aes_128() {
        let (mut client, mut server) = roundtrip_pair(CipherType::Aes128Gcm).await;

        let payload = b"hello shadowsocks stream";
        client.write_chunk(payload).await.expect("write");
        client.flush().await.expect("flush");

        let received = server.read_chunk().await.expect("read");
        assert_eq!(received.as_deref(), Some(payload.as_slice()));
    }

    #[tokio::test]
    async fn write_read_single_chunk_aes_256() {
        let (mut client, mut server) = roundtrip_pair(CipherType::Aes256Gcm).await;

        let payload = b"aes-256-gcm stream test payload";
        client.write_chunk(payload).await.expect("write");
        client.flush().await.expect("flush");

        let received = server.read_chunk().await.expect("read");
        assert_eq!(received.as_deref(), Some(payload.as_slice()));
    }

    #[tokio::test]
    async fn write_read_single_chunk_chacha20() {
        let (mut client, mut server) = roundtrip_pair(CipherType::ChaCha20Poly1305).await;

        let payload = b"chacha20-poly1305 stream payload";
        client.write_chunk(payload).await.expect("write");
        client.flush().await.expect("flush");

        let received = server.read_chunk().await.expect("read");
        assert_eq!(received.as_deref(), Some(payload.as_slice()));
    }

    #[tokio::test]
    async fn write_read_single_chunk_xchacha20() {
        let (mut client, mut server) = roundtrip_pair(CipherType::XChaCha20Poly1305).await;

        let payload = b"xchacha20-poly1305 stream payload";
        client.write_chunk(payload).await.expect("write");
        client.flush().await.expect("flush");

        let received = server.read_chunk().await.expect("read");
        assert_eq!(received.as_deref(), Some(payload.as_slice()));
    }

    #[tokio::test]
    async fn multiple_chunks_roundtrip() {
        let (mut client, mut server) = roundtrip_pair(CipherType::Aes128Gcm).await;

        let chunks: &[&[u8]] = &[
            b"first chunk",
            b"second chunk with more data",
            b"third",
        ];

        for chunk in chunks {
            client.write_chunk(chunk).await.expect("write");
        }
        client.flush().await.expect("flush");

        for expected in chunks {
            let received = server.read_chunk().await.expect("read");
            assert_eq!(received.as_deref(), Some(*expected));
        }
    }

    #[tokio::test]
    async fn bidirectional_roundtrip() {
        // client → server + server → client
        let (mut client, mut server) = roundtrip_pair(CipherType::Aes256Gcm).await;

        // client 写
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        client.write_chunk(req).await.expect("client write");
        client.flush().await.expect("client flush");

        // server 读
        let received = server.read_chunk().await.expect("server read");
        assert_eq!(received.as_deref(), Some(req.as_slice()));

        // server 写响应
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        server.write_chunk(resp).await.expect("server write");
        server.flush().await.expect("server flush");

        // client 读响应
        let received = client.read_chunk().await.expect("client read");
        assert_eq!(received.as_deref(), Some(resp.as_slice()));
    }

    #[tokio::test]
    async fn large_payload_roundtrip() {
        let (mut client, mut server) = roundtrip_pair(CipherType::Aes128Gcm).await;

        // 4KB payload（单 chunk）
        let payload = vec![0xABu8; 4096];
        client.write_chunk(&payload).await.expect("write");
        client.flush().await.expect("flush");

        let received = server.read_chunk().await.expect("read");
        assert_eq!(received.as_deref(), Some(payload.as_slice()));
    }

    /// 单块上限 = 8192 - tag(16) - 2 = 8174。跨块 payload 自动分块，读侧多 chunk 重组。
    /// 注意：duplex 缓冲仅 8KB，写端 20KB 会阻塞，读端必须 spawn 并发收。
    #[tokio::test]
    async fn multi_chunk_split_roundtrip() {
        let (mut client, mut server) = roundtrip_pair(CipherType::Aes128Gcm).await;

        let reader = tokio::spawn(async move {
            let mut received = Vec::new();
            for _ in 0..3 {
                let chunk = server.read_chunk().await.expect("read").expect("chunk");
                received.extend_from_slice(&chunk);
            }
            received
        });

        // 20000 = 3 块（8174 + 8174 + 3652）
        let payload = vec![0xCDu8; 20_000];
        client.write_chunk(&payload).await.expect("write");
        client.flush().await.expect("flush");

        assert_eq!(reader.await.expect("reader task"), payload);
    }

    #[tokio::test]
    async fn eof_on_close_returns_none() {
        let (mut client, mut server) = roundtrip_pair(CipherType::Aes128Gcm).await;

        // client 关闭写方向
        client.shutdown().await.expect("shutdown");

        // server 读到 EOF → None
        let received = server.read_chunk().await.expect("read");
        assert!(received.is_none());
    }

    #[test]
    fn server_body_initial_nonce_state() {
        // new_server_body 初始 nonce = [1,0,...]（读写同 initial）；
        // 模拟 decode_tcp_request_header 已消耗首帧 nonce [0;n]+[1,0,...]，
        // 下一次 increment = [2,0,...] 进入 body 首个 size chunk。
        let account = make_account(CipherType::Aes128Gcm, "password");
        let iv = random_iv(&account);
        let (_a, b) = tokio::io::duplex(64);
        let mut stream = SSStream::new_server_body(b, &account, &iv).expect("server body");

        assert_eq!(stream.write_nonce[0], 1);
        assert_eq!(stream.write_nonce[1..], vec![0u8; 11]);
        assert_eq!(stream.read_nonce[0], 1);

        increment_nonce_bytes(&mut stream.write_nonce);
        assert_eq!(stream.write_nonce[0], 2);
        assert_eq!(stream.write_nonce[1..], vec![0u8; 11]);
    }

    #[test]
    fn nonce_increment_le_carry() {
        // LE increment 进位语义（Go GenerateIncreasingNonce 对齐）
        let mut n = vec![0xFFu8; 12];
        increment_nonce_bytes(&mut n);
        assert_eq!(n, vec![0u8; 12]);

        increment_nonce_bytes(&mut n);
        assert_eq!(n[0], 1);
        assert_eq!(n[1..], vec![0u8; 11]);

        n[0] = 0xFF;
        increment_nonce_bytes(&mut n);
        assert_eq!(n[0], 0);
        assert_eq!(n[1], 1);
        assert_eq!(n[2..], vec![0u8; 10]);
    }

    /// 模拟 Go `WriteTCPResponse`：server 生成新 IV 并写入 wire，后跟加密 chunks。
    /// 对应 Go `proxy/shadowsocks/protocol.go::WriteTCPResponse` (行191-205) + `auth.go::seal`。
    ///
    /// 写入 `[新 IV (iv_size 字节)][size_chunk (2+tag)][payload_chunk (plain_len+tag)]`。
    async fn write_go_style_response(
        writer: &'_ mut tokio::io::DuplexStream,
        account: &MemoryAccount,
        plaintext: &[u8],
    ) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        let iv_size = account.cipher.iv_size() as usize;
        let new_iv: Vec<u8> = (0..iv_size).map(|_| rand::random()).collect();
        writer.write_all(&new_iv).await?;

        let aead = account
            .cipher
            .create_aead(&account.key, &new_iv)
            .expect("aead")
            .expect("aead");
        let tag_size = aead.tag_size();

        // nonce: [0xFF;n] increment → [0;n] (size)
        let mut nonce = vec![0xFFu8; aead.nonce_size()];
        for b in &mut nonce {
            *b = b.wrapping_add(1);
            if *b != 0 { break; }
        }
        let plain_size = u16::try_from(plaintext.len()).unwrap();
        let sealed_size = aead.seal(&nonce, &[], &plain_size.to_be_bytes()).unwrap();
        writer.write_all(&sealed_size).await?;

        // nonce increment → [1, 0, ...] (payload)
        for b in &mut nonce {
            *b = b.wrapping_add(1);
            if *b != 0 { break; }
        }
        let sealed_payload = aead.seal(&nonce, &[], plaintext).unwrap();
        writer.write_all(&sealed_payload).await?;
        writer.flush().await?;
        let _ = tag_size; // suppress unused if branches
        Ok(())
    }

    /// **RED 失败测试**：模拟 Go server→client wire (IV + chunk)，
    /// 验证 client 必须 rekey 后才能解密 server response。
    ///
    /// Root cause: Go `ReadTCPResponse` (proxy/shadowsocks/protocol.go:165-189)
    /// 读 IV + 用 IV 派生新 aead + 起始 nonce `[0xFF;n]`。Rust `SSStream` 当前
    /// 直接 read size chunk，没读 IV — wire format 不兼容。
    #[tokio::test]
    async fn read_chunk_after_rekey_decrypts_go_style_response() {
        let account = make_account(CipherType::Aes128Gcm, "interop-ss-password");
        let iv = random_iv(&account);

        let (client_half, mut server_half) = duplex(8 * 1024);
        // client: write first frame (addr+port) 占位
        let mut client = SSStream::new_client(client_half, &account, &iv).expect("client");
        let header = vec![0x01u8, 127, 0, 0, 1, 0, 80];
        client.write_chunk(&header).await.expect("write header");
        client.flush().await.expect("flush header");

        // 模拟 Go server：写 response (IV + chunk) 到 server_half → client_half 读
        let payload = b"hello ss interop test!";
        write_go_style_response(&mut server_half, &account, payload).await.expect("write resp");

        // **修复点**：client 必须先 rekey (读 IV + 派生新 aead + 重置 nonce)
        // 后才能 read_chunk 解密 server response。
        client.rekey_for_response(&account).await.expect("rekey");

        let got = client.read_chunk().await.expect("read_chunk");
        let got = got.expect("non-empty chunk");
        assert_eq!(got, payload, "decrypted response should match original payload");
    }

    /// **辅助**：多个 cipher 的 wire compat sanity（防止 AES-128 修好后 ChaCha/AES-256 又坏）。
    #[tokio::test]
    async fn read_response_rekey_all_ciphers() {
        for ct in [
            CipherType::Aes128Gcm,
            CipherType::Aes256Gcm,
            CipherType::ChaCha20Poly1305,
        ] {
            let account = make_account(ct, "interop-ss-password");
            let iv = random_iv(&account);

            let (client_half, mut server_half) = duplex(8 * 1024);
            let mut client = SSStream::new_client(client_half, &account, &iv).expect("client");
            client.write_chunk(&[0x01, 127, 0, 0, 1, 0, 80]).await.expect("write");
            client.flush().await.expect("flush");

            write_go_style_response(&mut server_half, &account, b"PING").await.expect("write resp");
            client.rekey_for_response(&account).await.expect("rekey");

            let got = client.read_chunk().await.expect("read").expect("non-empty");
            assert_eq!(got, b"PING", "{:?}: roundtrip mismatch", ct);
        }
    }
}



#!/usr/bin/env python3
"""向 boringssl 源码树幂等注入 SSL_send_post_handshake_record 原语（bd mygg）。

REALITY 后握手记录模仿的发送原语：在已完成握手的 SSL 连接上，以单条
TLS 1.3 application-data record（type 23，AEAD sealed）发出 |payload_len|
字节——wire 形态与 Go xtls/reality 服务端 dest 模仿发送一致
（tls.go:414-424：AEAD seal 后 hs.c.write，记录类型恒 23）。

注入点（三处，全部幂等）：
  1. ssl/ssl_post_handshake.cc        —— 新文件（实现）
  2. include/openssl/ssl.h            —— 函数声明（bindgen 无 allowlist，
                                         声明入 header 即自动生成 Rust 绑定，
                                         btls-sys `pub use generated::*` 导出）
  3. gen/sources.cmake                —— SSL_SOURCES 列表追加源文件
                                         （boringssl 由 go generate 重生成此
                                         文件，上游更新会冲掉注入——重跑本
                                         脚本即可恢复）

REBASE（与 btls 上游的耦合点）：
  - btls git 依赖（github.com/0x676e67/btls）的 build 流程 ensure_patches_applied
    不感知本注入；上游若升级 boringssl pin：
    a) struct ssl_st::max_send_fragment 字段（ssl/internal.h）若改名/移位，
       ssl_post_handshake.cc 的单记录长度检查需同步改写；
    b) gen/sources.cmake 会被上游重新生成，注入丢失，重跑本脚本；
    c) include/openssl/ssl.h 的声明块以 `bd mygg` 标记，git apply 类 patch
       冲突时人工保留该块。
  - 禁改 btls 上游仓库：本脚本只在消费侧（boringssl 源码树）注入。

用法：
  python3 tools/inject_btls_post_handshake.py <boringssl-src-dir>
  # 本地典型：C:/Users/Begonia/AppData/Local/Temp/boringssl-fv
  # CI：.github/actions/setup-boringssl 在 patch 步骤后调用
"""

import sys
from pathlib import Path

# bd mygg：声明块（插在 SSL_in_init 声明之后）
SSL_H_ANCHOR = "OPENSSL_EXPORT int SSL_in_init(const SSL *ssl);"
SSL_H_DECL = """
// bd mygg: SSL_send_post_handshake_record sends |payload_len| bytes from
// |payload| as a single post-handshake application-data record on |ssl|,
// mirroring the post-handshake record behavior that REALITY detects on the
// destination server (record type 23, AEAD-sealed under the current write
// key, one record per call). It fails if the handshake is not complete or if
// |payload_len| exceeds the maximum send fragment (which would cause
// |SSL_write| to fragment the payload across multiple records). It returns
// one on success and zero on error.
OPENSSL_EXPORT int SSL_send_post_handshake_record(SSL *ssl,
                                                  const uint8_t *payload,
                                                  size_t payload_len);
"""

# bd mygg：实现文件（REBASE 耦合点见文件内注释与模块 docstring）
POST_HANDSHAKE_CC = r"""// bd mygg: injected by tools/inject_btls_post_handshake.py — REALITY
// post-handshake record mirroring primitive (see module docstring there for
// REBASE coupling notes). Do not edit in place; re-run the injector.
//
// Wire-form parity with Go xtls/reality dest mirroring (tls.go:414-424):
// the server seals |payload_len| bytes under the current TLS 1.3 write key
// and emits exactly one type-23 record per call.

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "../ssl/internal.h"


int SSL_send_post_handshake_record(SSL *ssl, const uint8_t *payload,
                                   size_t payload_len) {
  if (ssl == nullptr || payload == nullptr || payload_len == 0) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  // Go mirrors inside the post-client-Finished window; on standard BoringSSL
  // that window is collapsed into accept(), so callers invoke this right
  // after the handshake completes.
  if (SSL_in_init(ssl)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_HANDSHAKE_NOT_COMPLETE);
    return 0;
  }

  // Single-record semantics: SSL_write fragments payloads above
  // max_send_fragment into multiple records, which would break the exact
  // record-length mirroring REALITY relies on.
  // REBASE: ssl_st::max_send_fragment is an internal field; rename/move on
  // boringssl upgrades must be mirrored here.
  if (payload_len > static_cast<size_t>(ssl->max_send_fragment)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DATA_LENGTH_TOO_LONG);
    return 0;
  }

  int ret = SSL_write(ssl, payload, static_cast<int>(payload_len));
  return ret == static_cast<int>(payload_len) ? 1 : 0;
}
"""

# bd mygg：SSL_SOURCES 列表锚点（字母序紧邻项）
SOURCES_CMAKE_ANCHOR = "  ssl/ssl_privkey.cc\n"
SOURCES_CMAKE_LINE = "  ssl/ssl_post_handshake.cc\n"

# bd z32z：声明块（插在 mygg 声明块尾部之后）
MIRROR_SEAL_H_ANCHOR = "                                                  size_t payload_len);\n"
MIRROR_SEAL_H_DECL = """
// bd z32z: SSL_seal_raw_tls13_record seals |inner_len| bytes from |inner| —
// the complete AEAD input plaintext, including the inner content type, with
// nothing appended — as exactly one TLS 1.3 type-23 record under the current
// write key, writing the wire bytes (5-byte header || ciphertext || tag) to
// |out| (capacity |out_cap|, bytes written to |*out_len|). AAD, nonce
// derivation and the write sequence counter are shared with the standard
// write path (nonce = static write IV XOR seq_be64, AAD = the record header,
// sequence incremented on success). The BIO is untouched: the caller
// transmits the record itself, mirroring Go xtls/reality tls.go:417-426
// (raw aead.Seal followed by hs.c.write). It fails if the handshake is not
// complete, the negotiated protocol is below TLS 1.3, or |inner_len| exceeds
// SSL3_RT_MAX_PLAIN_LENGTH + 1 (the largest single-record mirror plaintext).
// Returns one on success and zero on error.
OPENSSL_EXPORT int SSL_seal_raw_tls13_record(SSL *ssl, const uint8_t *inner,
                                             size_t inner_len, uint8_t *out,
                                             size_t out_cap, size_t *out_len);
"""

# bd z32z：实现（追加到 ssl_post_handshake.cc 文件尾；include 与 do_seal_record
# 同款骨架，差异仅在明文不追加 inner type——|inner| 已是完整 AEAD 输入）
MIRROR_SEAL_CC_APPEND = r"""

// bd z32z: injected by tools/inject_btls_post_handshake.py — REALITY
// byte-level-equivalent mirror primitive. Do not edit in place; re-run the
// injector.
using namespace bssl;  // SSLAEADContext/ssl_protocol_version/Span 等（同
                       // tls_record.cc C 导出函数段形态）
int SSL_seal_raw_tls13_record(SSL *ssl, const uint8_t *inner,
                              size_t inner_len, uint8_t *out, size_t out_cap,
                              size_t *out_len) {
  if (ssl == nullptr || inner == nullptr || out == nullptr ||
      out_len == nullptr || inner_len == 0) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }
  if (SSL_in_init(ssl)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_HANDSHAKE_NOT_COMPLETE);
    return 0;
  }

  SSLAEADContext *aead = ssl->s3->aead_write_ctx.get();
  if (aead->is_null_cipher() || ssl_protocol_version(ssl) < TLS1_3_VERSION) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_SSL_VERSION);
    return 0;
  }

  // Single-record bound: |inner| is content + inner type, so the largest
  // Go-equivalent mirror plaintext is SSL3_RT_MAX_PLAIN_LENGTH + 1 bytes
  // (wire 16406 = 5 + 16385 + 16).
  if (inner_len > SSL3_RT_MAX_PLAIN_LENGTH + 1) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DATA_LENGTH_TOO_LONG);
    return 0;
  }

  size_t suffix_len = 0;
  if (!aead->SuffixLen(&suffix_len, inner_len, 0)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_RECORD_TOO_LARGE);
    return 0;
  }
  const size_t wire_len = SSL3_RT_HEADER_LENGTH + inner_len + suffix_len;
  if (wire_len > out_cap) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_BUFFER_TOO_SMALL);
    return 0;
  }
  assert(!buffers_alias(inner, inner_len, out, wire_len));

  // Same overflow guard as do_seal_record: never wrap write_sequence.
  if (ssl->s3->write_sequence + 1 == 0) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_OVERFLOW);
    return 0;
  }

  // Record version (tls_record_version is static in tls_record.cc; inline the
  // same mapping): TLS 1.3 freezes the record version at TLS 1.2, versionless
  // connections use TLS 1.0, previous versions use the version itself.
  uint16_t record_version = ssl_protocol_version(ssl) >= TLS1_3_VERSION
                                ? TLS1_2_VERSION
                                : (ssl->s3->version == 0 ? TLS1_VERSION
                                                         : ssl->s3->version);
  out[0] = SSL3_RT_APPLICATION_DATA;
  out[1] = record_version >> 8;
  out[2] = record_version & 0xff;
  const size_t ciphertext_len = inner_len + suffix_len;
  out[3] = static_cast<uint8_t>(ciphertext_len >> 8);
  out[4] = static_cast<uint8_t>(ciphertext_len & 0xff);

  // SSLAEADContext::Seal appends nothing: |inner| is sealed as-is (unlike
  // do_seal_record, which passes the inner content type via extra_in).
  size_t sealed_len = 0;
  if (!aead->Seal(out + SSL3_RT_HEADER_LENGTH, &sealed_len,
                  out_cap - SSL3_RT_HEADER_LENGTH, out[0], record_version,
                  ssl->s3->write_sequence, Span(out, SSL3_RT_HEADER_LENGTH),
                  inner, inner_len)) {
    return 0;
  }
  ssl->s3->write_sequence++;
  *out_len = SSL3_RT_HEADER_LENGTH + sealed_len;
  return 1;
}
"""


def inject(boringssl: Path) -> int:
    """执行三处注入；返回实际落盘的改动数（幂等跳过不计）。"""
    changed = 0

    ssl_dir = boringssl / "ssl"
    if not ssl_dir.is_dir():
        raise SystemExit(f"not a boringssl source tree: {boringssl}")

    # 1. ssl/ssl_post_handshake.cc
    cc_path = ssl_dir / "ssl_post_handshake.cc"
    if cc_path.exists() and "SSL_send_post_handshake_record" in cc_path.read_text(encoding="utf-8"):
        print("post-handshake already present: ssl_post_handshake.cc (skip)")
    else:
        cc_path.write_text(POST_HANDSHAKE_CC, encoding="utf-8", newline="\n")
        changed += 1
        print(f"injected: {cc_path}")

    # 2. include/openssl/ssl.h 声明
    ssl_h = boringssl / "include" / "openssl" / "ssl.h"
    text = ssl_h.read_text(encoding="utf-8")
    if "SSL_send_post_handshake_record" in text:
        print("post-handshake already present: ssl.h decl (skip)")
    else:
        idx = text.find(SSL_H_ANCHOR)
        if idx < 0:
            raise SystemExit(f"anchor not found in ssl.h: {SSL_H_ANCHOR!r}")
        end = idx + len(SSL_H_ANCHOR)
        ssl_h.write_text(text[:end] + SSL_H_DECL + text[end:], encoding="utf-8", newline="\n")
        changed += 1
        print(f"injected: {ssl_h} (decl)")

    # 3. gen/sources.cmake SSL_SOURCES
    sources = boringssl / "gen" / "sources.cmake"
    if not sources.exists():
        raise SystemExit(
            f"missing {sources} — gen/sources.cmake is generated upstream; "
            "this injector targets the checked-in copy"
        )
    text = sources.read_text(encoding="utf-8")
    if "ssl/ssl_post_handshake.cc" in text:
        print("post-handshake already present: sources.cmake (skip)")
    else:
        if SOURCES_CMAKE_ANCHOR not in text:
            raise SystemExit(f"anchor not found in sources.cmake: {SOURCES_CMAKE_ANCHOR!r}")
        text = text.replace(
            SOURCES_CMAKE_ANCHOR, SOURCES_CMAKE_ANCHOR + SOURCES_CMAKE_LINE, 1
        )
        sources.write_text(text, encoding="utf-8", newline="\n")
        changed += 1
        print(f"injected: {sources}")

    # 4 (bd z32z). ssl/ssl_post_handshake.cc 追加 mirror seal 原语实现
    cc_text = cc_path.read_text(encoding="utf-8")
    if "SSL_seal_raw_tls13_record" in cc_text:
        print("mirror-seal already present: ssl_post_handshake.cc (skip)")
    else:
        cc_path.write_text(cc_text + MIRROR_SEAL_CC_APPEND, encoding="utf-8", newline="\n")
        changed += 1
        print(f"injected: {cc_path} (mirror-seal impl)")

    # 5 (bd z32z). include/openssl/ssl.h 追加 mirror seal 声明
    text = ssl_h.read_text(encoding="utf-8")
    if "SSL_seal_raw_tls13_record" in text:
        print("mirror-seal already present: ssl.h decl (skip)")
    else:
        if MIRROR_SEAL_H_ANCHOR not in text:
            raise SystemExit(f"anchor not found in ssl.h: {MIRROR_SEAL_H_ANCHOR!r}")
        idx = text.find(MIRROR_SEAL_H_ANCHOR) + len(MIRROR_SEAL_H_ANCHOR)
        ssl_h.write_text(text[:idx] + MIRROR_SEAL_H_DECL + text[idx:], encoding="utf-8", newline="\n")
        changed += 1
        print(f"injected: {ssl_h} (mirror-seal decl)")

    return changed


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <boringssl-src-dir>")
    changed = inject(Path(sys.argv[1]))
    print(f"done ({changed} change(s) written; skipped steps were already injected)")


if __name__ == "__main__":
    main()

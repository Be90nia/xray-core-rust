#!/usr/bin/env python3
"""重建 target/boringssl-patched（btls vendor + btls patch 集 + REALITY patch 集）。

btls-sys 走 BORING_BSSL_SOURCE_PATH + BORING_BSSL_ASSUME_PATCHED=1 构建时
要求该目录已含全部 patch（vendor boringssl 原样不含）。本脚本幂等：

1. 定位 cargo git checkout 里的 btls-sys（deps/boringssl + patches/）
2. rm -rf target/boringssl-patched && 复制 vendor boringssl
3. git init + 按 btls-sys build/main.rs 相同顺序应用 patch：
   boring-pq → boringssl → loongarch → windows（btls ab7f522 补丁集）
4. 应用 REALITY patch 集（HANDOFF_FINAL_PUSH.md §6.1，7 步）：
   - SSL_get_x25519_key_share_private（ssl.h + ssl_lib.cc）
   - SSL_set_reality_rewrite_cb 全局回调（ssl.h + ssl_lib.cc）
   - ssl_reality_rewrite_maybe（internal.h 声明 + handshake.cc /
     handshake_client.cc 两处调用点）
   - tls13_client.cc 删 session_id 回显比对（服务端 v26.3.27+ 必需）

首次 cmake configure 失败后由 tools/inject_btls_cache.py 注入 CMakeCache
（OPENSSL_NO_ASM + TrackFileAccess），与本脚本无关。

用法：python tools/setup_boringssl_reality.py [--dest PATH] [--btls-sys PATH]
"""

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

# 与 btls-sys build/main.rs ensure_patches_applied 非 fips 顺序一致
BTLS_BASE_PATCHES = [
    "boring-pq.patch",
    "boringssl.patch",
    "boringssl-loongarch.patch",
    "boringssl-windows.patch",
]

REPO_ROOT = Path(__file__).resolve().parent.parent

# ============================================================
# REALITY patch 集（HANDOFF_FINAL_PUSH.md §6.1）
# ============================================================

REALITY_SSL_H_DECL = """
OPENSSL_EXPORT int SSL_get_x25519_key_share_private(const SSL *ssl,
                                                    uint8_t out_priv[32]);
"""

REALITY_SSL_LIB_IMPL = """
int SSL_get_x25519_key_share_private(const SSL *ssl, uint8_t out_priv[32]) {
  if (ssl == nullptr || ssl->s3 == nullptr || ssl->s3->hs == nullptr) {
    return 0;
  }
  const SSL_HANDSHAKE *hs = ssl->s3->hs.get();
  for (const auto &share : hs->key_shares) {
    if (share->GroupID() == SSL_GROUP_X25519) {
      // |SerializePrivateKey| is logically const (raw 32-byte scalar for
      // X25519) but is not declared const on the virtual interface.
      SSLKeyShare *mutable_share = const_cast<SSLKeyShare *>(share.get());
      ScopedCBB cbb;
      static const size_t kX25519PrivLen = 32;
      if (!CBB_init(cbb.get(), kX25519PrivLen) ||
          !mutable_share->SerializePrivateKey(cbb.get()) ||
          CBB_len(cbb.get()) != kX25519PrivLen) {
        return 0;
      }
      OPENSSL_memcpy(out_priv, CBB_data(cbb.get()), kX25519PrivLen);
      return 1;
    }
  }
  return 0;
}
"""

REALITY_REWRITE_SSL_H_DECL = """
OPENSSL_EXPORT void SSL_set_reality_rewrite_cb(
    int (*cb)(SSL *ssl, uint8_t *msg, size_t msg_len));
"""

REALITY_SERVER_HELLO_SSL_H_DECL = """
OPENSSL_EXPORT void SSL_set_reality_server_hello_cb(
    int (*cb)(SSL *ssl, const uint8_t *msg, size_t msg_len));
"""

REALITY_REWRITE_SSL_LIB_IMPL = """
int (*g_reality_rewrite_cb)(SSL *ssl, uint8_t *msg, size_t msg_len) = nullptr;
void SSL_set_reality_rewrite_cb(int (*cb)(SSL *ssl, uint8_t *msg, size_t msg_len)) {
  g_reality_rewrite_cb = cb;
}

namespace bssl {
bool ssl_reality_rewrite_maybe(SSL *ssl, Array<uint8_t> *msg) {
  if (g_reality_rewrite_cb == nullptr || (*msg).empty() ||
      (*msg)[0] != SSL3_MT_CLIENT_HELLO) {
    return true;
  }
  return g_reality_rewrite_cb(ssl, (*msg).data(), (*msg).size()) != 0;
}
}  // namespace bssl
"""

REALITY_SERVER_HELLO_SSL_LIB_IMPL = """
int (*g_reality_server_hello_cb)(SSL *ssl, const uint8_t *msg, size_t msg_len) = nullptr;
void SSL_set_reality_server_hello_cb(
    int (*cb)(SSL *ssl, const uint8_t *msg, size_t msg_len)) {
  g_reality_server_hello_cb = cb;
}

namespace bssl {
bool ssl_reality_server_hello_maybe(SSL *ssl, const SSLMessage &msg) {
  if (g_reality_server_hello_cb == nullptr || CBS_len(&msg.raw) == 0) {
    return true;
  }
  return g_reality_server_hello_cb(ssl, CBS_data(&msg.raw), CBS_len(&msg.raw)) != 0;
}
}  // namespace bssl
"""

# handshake.cc / handshake_client.cc：finish_message 后、add_message 前注入
HANDSHAKE_CBB_OLD = """bool ssl_add_message_cbb(SSL *ssl, CBB *cbb) {
  Array<uint8_t> msg;
  if (!ssl->method->finish_message(ssl, cbb, &msg) ||
      !ssl->method->add_message(ssl, std::move(msg))) {
"""

HANDSHAKE_CBB_NEW = """bool ssl_add_message_cbb(SSL *ssl, CBB *cbb) {
  Array<uint8_t> msg;
  if (!ssl->method->finish_message(ssl, cbb, &msg) ||
      !ssl_reality_rewrite_maybe(ssl, &msg) ||
      !ssl->method->add_message(ssl, std::move(msg))) {
"""

CLIENT_HELLO_OLD = """      !ssl->method->finish_message(ssl, cbb.get(), &msg)) {
    return false;
  }

  // Now that the length prefixes have been computed, fill in the placeholder
  // PSK binder.
"""

CLIENT_HELLO_NEW = """      !ssl->method->finish_message(ssl, cbb.get(), &msg)) {
    return false;
  }

  if (!ssl_reality_rewrite_maybe(ssl, &msg)) {
    return false;
  }

  // Now that the length prefixes have been computed, fill in the placeholder
  // PSK binder.
"""

# tls13_client.cc：删 session_id 回显（服务端 v26.3.27+ 拒绝明文 sid 回显）
TLS13_SID_DECL_OLD = """  Span<const uint8_t> expected_session_id =
      SSL_is_dtls(hs->ssl) ? Span<const uint8_t>() : Span(hs->session_id);

"""

# TLS 1.3 客户端 ServerHello 处理：key schedule 前挂 ServerHello 捕获
# （与 ClientHello patch 同型——transcript 计入前窗口，拿到线上原始字节；
#  HRR 走 do_read_hello_retry_request 独立路径，不会触发本挂点）
TLS13_SH_HOOK_OLD = """  if (!tls13_advance_key_schedule(hs, shared_secret) ||  //
      !ssl_hash_message(hs, msg) ||                      //
      !tls13_derive_handshake_secrets(hs)) {
    return ssl_hs_error;
  }
"""

TLS13_SH_HOOK_NEW = """  if (!ssl_reality_server_hello_maybe(ssl, msg) ||
      !tls13_advance_key_schedule(hs, shared_secret) ||  //
      !ssl_hash_message(hs, msg) ||                      //
      !tls13_derive_handshake_secrets(hs)) {
    return ssl_hs_error;
  }
"""

TLS13_SID_CMP_OLD = """      Span<const uint8_t>(out->session_id) != expected_session_id ||
"""


def find_btls_sys() -> Path:
    """定位 cargo git checkout 的 btls-sys 目录（deps/boringssl 在其下）。

    多个 rev 共存时优先选 Cargo.lock 锁定的 rev——误选其他 checkout 会拿到
    错误的 boringssl pin 与不匹配的 patch 集。
    """
    base = Path.home() / ".cargo" / "git" / "checkouts"
    candidates = []
    for btls_dir in base.glob("btls-*"):
        for rev in btls_dir.iterdir():
            candidate = rev / "btls-sys"
            if (candidate / "deps" / "boringssl" / "ssl" / "ssl_lib.cc").exists():
                candidates.append(candidate)
    if not candidates:
        raise SystemExit("btls-sys checkout not found under " + str(base))
    locked = None
    lock = REPO_ROOT / "Cargo.lock"
    if lock.exists():
        m = re.search(r'name = "btls-sys"[\s\S]{0,200}?source = "git\+[^"]+#([0-9a-f]{40})"',
                      lock.read_text(encoding="utf-8"))
        if m:
            locked = m.group(1)[:7]
    if locked:
        for c in candidates:
            if c.parent.name.startswith(locked):
                print(f"using Cargo.lock-pinned checkout: {c}")
                return c
        raise SystemExit(f"Cargo.lock pins btls-sys {locked} but no populated checkout found")
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    print(f"multiple checkouts found, using newest: {candidates[0]}")
    return candidates[0]


def run(cmd: list[str], cwd: Path | None = None) -> None:
    print(f"+ {' '.join(cmd)}" + (f"  (cwd={cwd})" if cwd else ""))
    r = subprocess.run(cmd, cwd=cwd)
    if r.returncode != 0:
        raise SystemExit(f"command failed ({r.returncode}): {' '.join(cmd)}")


def _force_remove(func, path, _exc):
    """rmtree onexc：git pack 文件只读，chmod 后重删。"""
    import os
    import stat
    os.chmod(path, stat.S_IWRITE)
    func(path)


def insert_after(text: str, anchor: str, insertion: str) -> str:
    idx = text.find(anchor)
    if idx < 0:
        raise SystemExit(f"reality patch anchor not found: {anchor[:60]!r}")
    end = idx + len(anchor)
    return text[:end] + insertion + text[end:]


def replace_exact(text: str, old: str, new: str, what: str) -> str:
    n = text.count(old)
    if n != 1:
        raise SystemExit(f"{what}: anchor count {n} != 1 (already applied?)")
    return text.replace(old, new)


def apply_reality_patches(dest: Path) -> None:
    """应用 REALITY patch 集（锚点式插入/替换，幂等）。"""
    # ---- 1/2. ssl.h 声明 ----
    ssl_h = dest / "include" / "openssl" / "ssl.h"
    text = ssl_h.read_text(encoding="utf-8")
    add = []
    if "SSL_get_x25519_key_share_private" not in text:
        add.append(REALITY_SSL_H_DECL)
    if "SSL_set_reality_rewrite_cb" not in text:
        add.append(REALITY_REWRITE_SSL_H_DECL)
    if "SSL_set_reality_server_hello_cb" not in text:
        add.append(REALITY_SERVER_HELLO_SSL_H_DECL)
    if add:
        anchor = (
            "OPENSSL_EXPORT int SSL_set1_client_key_shares(SSL *ssl,\n"
            "                                              const uint16_t *group_ids,\n"
            "                                              size_t num_group_ids);\n"
        )
        text = insert_after(text, anchor, "\n" + "\n".join(add))
        ssl_h.write_text(text, encoding="utf-8", newline="\n")
        print("applied reality patch: ssl.h")
    else:
        print("reality patch already present: ssl.h (skip)")

    # ---- 3. ssl_lib.cc 实现（全局区：C linkage + bssl helper）----
    ssl_lib = dest / "ssl" / "ssl_lib.cc"
    text = ssl_lib.read_text(encoding="utf-8")
    add = []
    if "SSL_get_x25519_key_share_private" not in text:
        add.append(REALITY_SSL_LIB_IMPL)
    if "SSL_set_reality_rewrite_cb" not in text:
        add.append(REALITY_REWRITE_SSL_LIB_IMPL)
    if "SSL_set_reality_server_hello_cb" not in text:
        add.append(REALITY_SERVER_HELLO_SSL_LIB_IMPL)
    if add:
        anchor = (
            "int SSL_set1_client_key_shares(SSL *ssl, const uint16_t *group_ids,\n"
            "                               size_t num_group_ids) {"
        )
        idx = text.find(anchor)
        if idx < 0:
            raise SystemExit("reality patch anchor not found in ssl_lib.cc")
        close = text.find("\n}\n", idx)
        if close < 0:
            raise SystemExit("SSL_set1_client_key_shares impl end not found")
        end = close + len("\n}\n")
        text = text[:end] + "\n" + "\n".join(add) + text[end:]
        ssl_lib.write_text(text, encoding="utf-8", newline="\n")
        print("applied reality patch: ssl_lib.cc")
    else:
        print("reality patch already present: ssl_lib.cc (skip)")

    # ---- 4. internal.h 声明 ----
    internal_h = dest / "ssl" / "internal.h"
    text = internal_h.read_text(encoding="utf-8")
    changed = False
    if "ssl_reality_rewrite_maybe" not in text:
        anchor = "bool ssl_add_message_cbb(SSL *ssl, CBB *cbb);\n"
        text = insert_after(
            text, anchor, "\nbool ssl_reality_rewrite_maybe(SSL *ssl, Array<uint8_t> *msg);\n"
        )
        changed = True
    if "ssl_reality_server_hello_maybe" not in text:
        anchor = "bool ssl_reality_rewrite_maybe(SSL *ssl, Array<uint8_t> *msg);\n"
        text = insert_after(
            text, anchor,
            "\n// REALITY (cert PQC): ServerHello 捕获（tls13_client.cc key schedule 前）。\n"
            "bool ssl_reality_server_hello_maybe(SSL *ssl, const SSLMessage &msg);\n",
        )
        changed = True
    if changed:
        internal_h.write_text(text, encoding="utf-8", newline="\n")
        print("applied reality patch: internal.h")
    else:
        print("reality patch already present: internal.h (skip)")

    # ---- 5. handshake.cc ssl_add_message_cbb 调用点 ----
    handshake_cc = dest / "ssl" / "handshake.cc"
    text = handshake_cc.read_text(encoding="utf-8")
    if "ssl_reality_rewrite_maybe" not in text:
        text = replace_exact(text, HANDSHAKE_CBB_OLD, HANDSHAKE_CBB_NEW, "handshake.cc")
        handshake_cc.write_text(text, encoding="utf-8", newline="\n")
        print("applied reality patch: handshake.cc")
    else:
        print("reality patch already present: handshake.cc (skip)")

    # ---- 6. handshake_client.cc ssl_add_client_hello 调用点（关键）----
    client_cc = dest / "ssl" / "handshake_client.cc"
    text = client_cc.read_text(encoding="utf-8")
    if "ssl_reality_rewrite_maybe" not in text:
        text = replace_exact(text, CLIENT_HELLO_OLD, CLIENT_HELLO_NEW, "handshake_client.cc")
        client_cc.write_text(text, encoding="utf-8", newline="\n")
        print("applied reality patch: handshake_client.cc")
    else:
        print("reality patch already present: handshake_client.cc (skip)")

    # ---- 7. tls13_client.cc 删 session_id 回显 + ServerHello 捕获挂点 ----
    tls13_cc = dest / "ssl" / "tls13_client.cc"
    text = tls13_cc.read_text(encoding="utf-8")
    if "expected_session_id" in text:
        if text.count(TLS13_SID_DECL_OLD) != 1 or text.count(TLS13_SID_CMP_OLD) != 1:
            raise SystemExit("tls13_client.cc: session_id anchors drifted; re-derive")
        text = text.replace(TLS13_SID_DECL_OLD, "")
        text = text.replace(TLS13_SID_CMP_OLD, "")
        if "expected_session_id" in text:
            raise SystemExit("tls13_client.cc: expected_session_id residue after removal")
        tls13_cc.write_text(text, encoding="utf-8", newline="\n")
        print("applied reality patch: tls13_client.cc (session_id echo removed)")
    else:
        print("reality patch already present: tls13_client.cc (session_id echo removed, skip)")

    # ---- 8. tls13_client.cc ServerHello 捕获挂点（transcript 计入前）----
    if "ssl_reality_server_hello_maybe" not in text:
        text = replace_exact(text, TLS13_SH_HOOK_OLD, TLS13_SH_HOOK_NEW, "tls13_client.cc SH hook")
        tls13_cc.write_text(text, encoding="utf-8", newline="\n")
        print("applied reality patch: tls13_client.cc (server hello hook)")
    else:
        print("reality patch already present: tls13_client.cc (server hello hook, skip)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", default=str(REPO_ROOT / "target" / "boringssl-patched"))
    ap.add_argument("--btls-sys", default=None, help="btls-sys checkout dir override")
    args = ap.parse_args()
    btls_sys = Path(args.btls_sys) if args.btls_sys else find_btls_sys()
    src = btls_sys / "deps" / "boringssl"
    dest = Path(args.dest)

    if not (src / "ssl" / "ssl_lib.cc").exists():
        raise SystemExit(f"vendor boringssl not found: {src}")

    print(f"rebuilding {dest} from {src}")
    if dest.exists():
        shutil.rmtree(dest, onexc=_force_remove)
    shutil.copytree(src, dest)

    # btls patch 应用需要 git repo（与 build/main.rs 行为一致）
    run(["git", "init"], cwd=dest)
    run(["git", "add", "-A"], cwd=dest)

    patches_dir = btls_sys / "patches"
    for name in BTLS_BASE_PATCHES:
        patch = patches_dir / name
        if not patch.exists():
            raise SystemExit(f"btls patch missing: {patch}")
        run(["git", "apply", "--whitespace=fix", str(patch)], cwd=dest)
        print(f"applied {name}")

    apply_reality_patches(dest)

    print(f"\ndone: {dest}")
    print("next: cargo build with BORING_BSSL_SOURCE_PATH=<dest> + "
          "BORING_BSSL_ASSUME_PATCHED=1; on first cmake configure failure run "
          "tools/inject_btls_cache.py then rebuild")


if __name__ == "__main__":
    main()

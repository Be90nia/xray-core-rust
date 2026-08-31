#!/usr/bin/env python3
"""重建 target/boringssl-patched（btls vendor + btls patch 集 + REALITY patch）。

btls-sys 走 BORING_BSSL_SOURCE_PATH + BORING_BSSL_ASSUME_PATCHED=1 构建时
要求该目录已含全部 patch（vendor boringssl 原样不含）。本脚本幂等：

1. 定位 cargo git checkout 里的 btls-sys（deps/boringssl + patches/）
2. rm -rf target/boringssl-patched && 复制 vendor boringssl
3. git init + 按 btls-sys build/main.rs 相同顺序应用 patch：
   boring-pq → 0001..0010（非 fips）→ boringssl-loongarch
4. 应用 tools/reality-boringssl.patch（SSL_get_x25519_key_share_private，
   REALITY 客户端 X25519 key share 私钥导出，aai）

首次 cmake configure 失败后由 tools/inject_btls_cache.py 注入 CMakeCache
（OPENSSL_NO_ASM + TrackFileAccess），与本脚本无关。

用法：python tools/setup_boringssl_reality.py [--dest PATH] [--btls-sys PATH]
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

# 与 btls-sys build/main.rs ensure_patches_applied 非 fips 顺序一致
BTLS_BASE_PATCHES = [
    "boring-pq.patch",
    "0001-boringssl-ffdhe.patch",
    "0002-boringssl-legacy-ciphers.patch",
    "0003-boringssl-tls-options.patch",
    "0004-boringssl-extension-order.patch",
    "0005-record-size-limit.patch",
    "0006-delegated-credentials.patch",
    "0007-boringssl-cipher-preferences.patch",
    "0008-boringssl-sigalgs.patch",
    "0009-boringssl-zstd-cert-compression.patch",
    "0010-boringssl-build-compat.patch",
    "boringssl-loongarch.patch",
]

REPO_ROOT = Path(__file__).resolve().parent.parent
REALITY_PATCH = REPO_ROOT / "tools" / "reality-boringssl.patch"


def find_btls_sys() -> Path:
    """定位 cargo git checkout 的 btls-sys 目录（deps/boringssl 在其下）。"""
    cargo_git = Path.home() / ".cargo" / "git" / "checkouts"
    if not cargo_git.exists():
        raise SystemExit(f"no cargo git checkouts at {cargo_git}")
    candidates = []
    for d in cargo_git.glob("btls-*/*/btls-sys"):
        if (d / "deps" / "boringssl" / "ssl" / "ssl_lib.cc").exists() and (
            d / "patches"
        ).is_dir():
            candidates.append(d)
    if not candidates:
        raise SystemExit("btls-sys checkout not found under ~/.cargo/git/checkouts")
    # 最新 mtime 的 checkout（当前 lock 使用的）
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    if len(candidates) > 1:
        print(f"multiple checkouts found, using newest: {candidates[0]}")
        for c in candidates[1:]:
            print(f"  ignored: {c}")
    return candidates[0]


def run(cmd: list[str], cwd: Path | None = None) -> None:
    print(f"+ {' '.join(cmd)}" + (f"  (cwd={cwd})" if cwd else ""))
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stdout.write(r.stdout)
        sys.stderr.write(r.stderr)
        raise SystemExit(f"command failed ({r.returncode}): {' '.join(cmd)}")


def _force_remove(func, path, _exc):
    """rmtree onexc：git pack 文件只读，chmod 后重删。"""
    import os
    os.chmod(path, 0o666)
    func(path)

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

    apply_reality_patch(dest)

    print(f"\ndone: {dest}")
    print("next: cargo build with BORING_BSSL_SOURCE_PATH=<dest> + "
          "BORING_BSSL_ASSUME_PATCHED=1; on first cmake configure failure run "
          "tools/inject_btls_cache.py then rebuild")

REALITY_SSL_LIB_IMPL = """
int SSL_get_x25519_key_share_private(const SSL *ssl, uint8_t out_priv[32]) {
  const auto *ssl_impl = FromOpaque(ssl);
  if (ssl_impl == nullptr || ssl_impl->s3 == nullptr ||
      ssl_impl->s3->hs == nullptr) {
    return 0;
  }
  const SSL_HANDSHAKE *hs = ssl_impl->s3->hs.get();
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


def insert_after(text: str, anchor: str, insertion: str) -> str:
    idx = text.find(anchor)
    if idx < 0:
        raise SystemExit(f"reality patch anchor not found: {anchor[:60]!r}")
    end = idx + len(anchor)
    return text[:end] + insertion + text[end:]


def apply_reality_patch(dest: Path) -> None:
    """插入 SSL_get_x25519_key_share_private（REALITY 客户端 X25519 私钥导出）。

    锚点式文本插入（行号漂移免疫）；已存在则跳过（幂等）。
    """
    marker = "SSL_get_x25519_key_share_private"

    ssl_h = dest / "include" / "openssl" / "ssl.h"
    text = ssl_h.read_text(encoding="utf-8")
    if marker not in text:
        # 锚点：SSL_set1_client_key_shares 声明（3 行）结尾
        anchor = (
            "OPENSSL_EXPORT int SSL_set1_client_key_shares(SSL *ssl,\n"
            "                                              const uint16_t *group_ids,\n"
            "                                              size_t num_group_ids);\n"
        )
        text = insert_after(text, anchor, "\n" + REALITY_SSL_H_DECL)
        ssl_h.write_text(text, encoding="utf-8", newline="\n")
        print("applied reality patch: ssl.h")
    else:
        print("reality patch already present: ssl.h (skip)")

    ssl_lib = dest / "ssl" / "ssl_lib.cc"
    text = ssl_lib.read_text(encoding="utf-8")
    if marker not in text:
        # 锚点：SSL_set1_client_key_shares 实现块结尾（return 1; 后的 }）
        anchor = (
            "int SSL_set1_client_key_shares(SSL *ssl, const uint16_t *group_ids,\n"
            "                               size_t num_group_ids) {"
        )
        idx = text.find(anchor)
        if idx < 0:
            raise SystemExit("reality patch anchor not found in ssl_lib.cc")
        # 实现块末尾：从锚点起找第一个 "\n}\n"
        close = text.find("\n}\n", idx)
        if close < 0:
            raise SystemExit("SSL_set1_client_key_shares impl end not found")
        end = close + len("\n}\n")
        text = text[:end] + "\n" + REALITY_SSL_LIB_IMPL + text[end:]
        ssl_lib.write_text(text, encoding="utf-8", newline="\n")
        print("applied reality patch: ssl_lib.cc")
    else:
        print("reality patch already present: ssl_lib.cc (skip)")


if __name__ == "__main__":
    main()

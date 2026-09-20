#!/usr/bin/env bash
# setup_boringssl.sh — .github/actions/setup-boringssl composite action 的容器内等价物。
# 前置：仓库根为 cwd（Cargo.lock / tools/ 可用），git/python3/cargo 已安装。
# 产出：已补丁 boringssl 源码树于 $BORING_BSSL_SOURCE_PATH，并 export 两个 env。
set -euo pipefail

workdir="${BORINGSSL_WORKDIR:-/tmp/boringssl-stress}"

# 1. 取 btls-sys checkout（cargo fetch 已完成）
# rust 官方镜像 CARGO_HOME=/usr/local/cargo（非 $HOME/.cargo，CI runner 才是后者）
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
rev=$(awk '/^name = "btls-sys"/{f=1;next} f&&/^source/{print;exit}' Cargo.lock \
  | sed 's/.*#\([0-9a-f]\{40\}\)".*/\1/')
btls_co=$(ls -d "$cargo_home"/git/checkouts/btls-*/"${rev:0:7}"* | head -1)
patches_dir="$btls_co/btls-sys/patches"

# 2. boringssl pin（btls 仓 submodule gitlink，btls rev 变更自动跟随）
bssl_rev=$(git -C "$btls_co" ls-tree HEAD btls-sys/deps/boringssl | awk '{print $3}')
bssl="$workdir/boringssl"
rm -rf "$bssl"
git init -q "$bssl"
git -C "$bssl" remote add origin https://github.com/google/boringssl.git
git -C "$bssl" fetch -q --depth 1 origin "$bssl_rev"
git -C "$bssl" checkout -q FETCH_HEAD
git -C "$bssl" apply -v --whitespace=fix "$patches_dir/boring-pq.patch"
git -C "$bssl" apply -v --whitespace=fix "$patches_dir/boringssl.patch"
git -C "$bssl" apply -v --whitespace=fix "$patches_dir/boringssl-loongarch.patch"
git -C "$bssl" apply -v --whitespace=fix "$patches_dir/boringssl-windows.patch"

# 3. REALITY 补丁集 + 后握手原语注入（与 CI 同源脚本）
python3 -c "import sys, pathlib; sys.path.insert(0, 'tools'); from setup_boringssl_reality import apply_reality_patches; apply_reality_patches(pathlib.Path('$bssl'))"
python3 tools/inject_btls_post_handshake.py "$bssl"

# 4. env（调用方消费；本脚本 source 后 $BORING_BSSL_* 可用）
export BORING_BSSL_ASSUME_PATCHED=1
export BORING_BSSL_SOURCE_PATH="$bssl"
echo "boringssl ready: $bssl (rev $bssl_rev)"

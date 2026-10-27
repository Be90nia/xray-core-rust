#!/usr/bin/env bash
# C 面 R1a 端到端吞吐 A/B（紧交错：两态各建一次二进制，测量窗内零构建）
#
# 用法：sh reports/audit-2026-10-27/tmp/ab_loopback.sh
# 前置：bench 用私有端口副本（19453/12081/19501），避免与 18100 段 interop / 18453 段默认 bench 撞。
# 判据：6 个窗（A,B,A,B,A,B）内 `tasklist` cargo/rustc = 0；比较 best-of-3 而非绝对值
#      （同一份 A 二进制在 19:5x 测 ~172 MB/s、20:30 测 ~140 MB/s——跨窗绝对值不可比）。
set -u
cd /d/Project/Xray-core-rust || exit 1
export CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-CR1aC
export BORING_BSSL_ASSUME_PATCHED=1
export BORING_BSSL_SOURCE_PATH='D:\Project\Xray-core-rust\target\boringssl-patched'
export PROTOC='D:/Project/tools/bin/protoc.exe'
export LIBCLANG_PATH='D:\Program Files\llvm\bin'
export BORING_BSSL_PATH='D:\Project\Xray-core-rust\target\boringssl-asm\prebuilt'
F=crates/xray-app-dispatcher/src/default.rs
BENCH=D:/tmp/cr1ac/loopback_bench_r1a.py

# 1) B 态（当前树）二进制另存
cargo build --release -p xray-cli -j 8 2>&1 | tail -1
cp target-CR1aC/release/xray.exe D:/tmp/cr1ac/xray-B.exe
# 2) A 态（回退 SimpleOhm 实现）二进制另存
git show HEAD:$F > $F
cargo build --release -p xray-cli -j 8 2>&1 | tail -1
cp target-CR1aC/release/xray.exe D:/tmp/cr1ac/xray-A.exe
# 3) 恢复 B 态源码
git checkout -- $F 2>/dev/null || echo "注意：本步需手工恢复 B 态 default.rs（源备份见 D:/tmp/cr1ac/default_B.rs）"
[ -f D:/tmp/cr1ac/default_B.rs ] && cp D:/tmp/cr1ac/default_B.rs $F

# 4) 紧交错 3 轮（每轮 A→B 背靠背，全程无构建）
for i in 1 2 3; do
  for s in A B; do
    echo "== round $i · $s ==  procs=$(tasklist | grep -icE '^(cargo|rustc)')"
    python $BENCH --tag ti$s$i --xray D:/tmp/cr1ac/xray-$s.exe --runs 3 --alloc-stats 2>&1 \
      | grep -E "via-enc-chain|alloc/MB"
  done
done

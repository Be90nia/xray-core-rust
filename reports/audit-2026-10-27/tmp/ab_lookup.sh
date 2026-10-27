#!/usr/bin/env bash
# C 面 R1a 查表面 A/B 采集（同窗 3 轮交错；A 态 = 仅回退 SimpleOhm hunk，B 态 = 本波）
#
# A 态构造：`git show HEAD:crates/xray-app-dispatcher/src/default.rs`（回退整文件——该文件
# 本波唯一 diff 就是 SimpleOhm 块，`git diff --stat` 可核对），Cargo.toml 的 udf 依赖
# 保留不动（未使用依赖零影响）⇒ 两态差异收敛为一个 hunk。
# 取证：每轮前后 tasklist 快照（cargo/rustc 进程），确保测量期无并发编译。
set -u
cd /d/Project/Xray-core-rust || exit 1
FILE=crates/xray-app-dispatcher/src/default.rs
BK=D:/tmp/cr1ac/default_B.rs
export CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-CR1aC
export BORING_BSSL_ASSUME_PATCHED=1
export BORING_BSSL_SOURCE_PATH='D:\Project\Xray-core-rust\target\boringssl-patched'
export PROTOC='D:/Project/tools/bin/protoc.exe'
export LIBCLANG_PATH='D:\Program Files\llvm\bin'
export BORING_BSSL_PATH='D:\Project\Xray-core-rust\target\boringssl-asm\prebuilt'

snap() { tasklist | grep -icE 'cargo|rustc' || true; }

run_state() {
  cargo build --release -p xray-app-dispatcher --example ohm_lookup_ab -j 8 2>&1 | tail -2
  local i
  for i in 1 2 3; do
    ./target-CR1aC/release/examples/ohm_lookup_ab.exe | grep -E 'MEDIAN|MIN'
  done
}

for r in 1 2 3; do
  echo "===== round $r · A (HEAD HashMap) ====="
  git show HEAD:$FILE > $FILE
  echo "procs_before_build=$(snap)"
  run_state
  echo "procs_at_measure=$(snap)"
  echo "===== round $r · B (udf BoundedRegistry) ====="
  cp $BK $FILE
  echo "procs_before_build=$(snap)"
  run_state
  echo "procs_at_measure=$(snap)"
done
cp $BK $FILE
echo "restored B: $(md5sum $FILE)"

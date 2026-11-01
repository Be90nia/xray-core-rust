#!/usr/bin/env bash
# bd hl8q6 收尾：等同箱代理的在途 crate 恢复编译 → 单测 → release → E1 → clippy → fmt。
set -uo pipefail
cd /d/Project/Xray-core-rust || exit 2
export BORING_BSSL_PATH=D:/Project/Xray-core-rust/target/boringssl-asm/prebuilt
export BORING_BSSL_ASSUME_PATCHED=1
export PROTOC=D:/Project/tools/bin/protoc.exe
export LIBCLANG_PATH="D:/Program Files/llvm/bin"
export CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-Wave7Um
export CARGO_INCREMENTAL=0

LOG=reports/audit-2026-10-31-perf-mem-wiring/fix/tmp/um_e2e
mkdir -p "$LOG"

echo "=== WAIT: 同箱在途 crate 恢复编译 ==="
green=0
for i in $(seq 1 80); do
  if cargo check -p xray-transport-splithttp --lib -p xray-proxy-freedom --lib \
      -p xray-transport-hysteria --lib >/dev/null 2>&1; then
    echo "deps green (attempt $i)"
    green=1
    break
  fi
  sleep 30
done
if [ "$green" != 1 ]; then
  echo "FATAL: 同箱 crate 35 分钟内未恢复编译"
  exit 2
fi

echo "=== UNIT: xray-core user_manager ==="
cargo test -p xray-core --lib -- user_manager > "$LOG/unit_tests.log" 2>&1
echo "unit exit=$?"
grep -E "^test |^test result" "$LOG/unit_tests.log"

echo "=== UNIT: xray-core lib 全量 ==="
cargo test -p xray-core --lib > "$LOG/unit_full.log" 2>&1
echo "full exit=$?"
grep -E "^test result|FAILED" "$LOG/unit_full.log"

echo "=== RELEASE BUILD ==="
cargo build --release -p xray-cli 2>&1 | tail -2

echo "=== E1 ==="
python reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7um_user_hotupdate_e2e.py \
  > "$LOG/after_fix.log" 2>&1
echo "e2e exit=$?"
grep -E "^==> |^=== " "$LOG/after_fix.log"

echo "=== CLIPPY (workspace) ==="
cargo clippy --workspace --all-targets -- -D warnings > "$LOG/clippy.log" 2>&1
echo "clippy exit=$?"
tail -3 "$LOG/clippy.log"

echo "=== FMT (all) ==="
cargo fmt --all -- --check > "$LOG/fmt.log" 2>&1
echo "fmt exit=$?"
head -20 "$LOG/fmt.log"

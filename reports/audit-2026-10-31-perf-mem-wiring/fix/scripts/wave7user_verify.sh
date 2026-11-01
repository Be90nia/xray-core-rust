#!/usr/bin/env bash
# bd c89uy 收尾：release 重编 → 双向互通 → 相关 crate 全量测试。
set -uo pipefail
cd /d/Project/Xray-core-rust || exit 2
export BORING_BSSL_PATH=D:/Project/Xray-core-rust/target/boringssl-asm/prebuilt
export BORING_BSSL_ASSUME_PATCHED=1
export PROTOC=D:/Project/tools/bin/protoc.exe
export LIBCLANG_PATH="D:/Program Files/llvm/bin"
export CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-Wave7User
export CARGO_INCREMENTAL=0

LOG_DIR=reports/audit-2026-10-31-perf-mem-wiring/fix/tmp/api_user_interop
mkdir -p "$LOG_DIR"

echo "=== RELEASE BUILD ==="
cargo build --release -p xray-cli 2>&1 | tail -2

echo "=== INTEROP (release, both directions) ==="
python reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7user_api_user_interop.py \
  > "$LOG_DIR/after_fix.log" 2>&1
echo "interop exit=$?"
grep -E "^==> |^=== |^FAIL" "$LOG_DIR/after_fix.log"

echo "=== xray-core lib tests ==="
cargo test -p xray-core --lib 2>&1 | grep -E "^test result|FAILED"

echo "=== commander + cli tests ==="
cargo test -p xray-app-commander -p xray-cli --all-targets 2>&1 | grep -E "^test result|FAILED"

echo "=== clippy ==="
cargo clippy -p xray-app-commander -p xray-cli --all-targets -- -D warnings 2>&1 | tail -2

echo "=== fmt ==="
cargo fmt -p xray-core -p xray-cli -p xray-app-commander -- --check && echo "fmt clean"

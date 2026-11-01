#!/usr/bin/env bash
# bd 9c8k6 收尾验证：release 构建 → AddRule 真互通 → 相关 crate 全量测试。
set -uo pipefail
cd /d/Project/Xray-core-rust || exit 2
export BORING_BSSL_PATH=D:/Project/Xray-core-rust/target/boringssl-asm/prebuilt
export BORING_BSSL_ASSUME_PATCHED=1
export PROTOC=D:/Project/tools/bin/protoc.exe
export LIBCLANG_PATH="D:/Program Files/llvm/bin"
export CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-Wave7Dyn
export CARGO_INCREMENTAL=0

LOG_DIR=reports/audit-2026-10-31-perf-mem-wiring/fix/tmp/api_interop
mkdir -p "$LOG_DIR"

echo "=== RELEASE BUILD ==="
cargo build --release -p xray-cli 2>&1 | tail -2

echo "=== INTEROP (release, both directions) ==="
python reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7dyn_api_addrule_interop.py \
  > "$LOG_DIR/after_fix.log" 2>&1
echo "interop exit=$?"
grep -E "^==> |^=== |^FAIL" "$LOG_DIR/after_fix.log"

echo "=== xray-core lib tests ==="
cargo test -p xray-core --lib 2>&1 | grep -E "^test result|^error|FAILED" | tail -8

echo "=== xray-app-dispatcher all-targets ==="
cargo test -p xray-app-dispatcher --all-targets 2>&1 | grep -E "^test result|^error|FAILED" | tail -8

echo "=== xray-app-router all-targets ==="
cargo test -p xray-app-router --all-targets 2>&1 | grep -E "^test result|^error|FAILED" | tail -8

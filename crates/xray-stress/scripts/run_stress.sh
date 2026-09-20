#!/usr/bin/env bash
# xray-stress 长跑启动脚本（Linux/Docker 宿主或本机）。
# 用法: ./run_stress.sh <conservative|standard|aggressive> [duration_hours] [out_dir]
set -euo pipefail

TIER="${1:?usage: $0 <conservative|standard|aggressive> [duration_hours] [out_dir]}"
DURATION_HOURS="${2:-48}"
OUT_DIR="${3:-stress-out}"

case "$TIER" in
  conservative) CONCURRENCY=4;  S2_CONNS=2;  INTERVAL=60; DELAY_MS=300 ;;
  standard)     CONCURRENCY=8;  S2_CONNS=4;  INTERVAL=30; DELAY_MS=150 ;;
  aggressive)   CONCURRENCY=32; S2_CONNS=16; INTERVAL=15; DELAY_MS=40 ;;
  *) echo "unknown tier: $TIER" >&2; exit 2 ;;
esac
DURATION_SEC=$(awk -v h="$DURATION_HOURS" 'BEGIN { printf "%d", h * 3600 }')

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXE="$SCRIPT_DIR/../../target/release/xray-stress"

# Linux 长跑防睡眠：检测 systemd logind idle-action（容器内无 systemd 则跳过）
if command -v systemctl >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1; then
  IDLE=$(systemctl show sleep.target -p ActiveState 2>/dev/null || true)
  echo "[sleep-check] systemd sleep.target: ${IDLE:-unknown} (host suspend 会截断长跑，需 loginctl 抑制)"
fi

echo "[run] $EXE --duration $DURATION_SEC --concurrency $CONCURRENCY --s2-conns $S2_CONNS --s1-delay-ms $DELAY_MS --scenarios s1,s2,s3,s4 --sample-interval $INTERVAL --out-dir $OUT_DIR"
exec "$EXE" \
  --duration "$DURATION_SEC" \
  --concurrency "$CONCURRENCY" \
  --s2-conns "$S2_CONNS" \
  --s1-delay-ms "$DELAY_MS" \
  --scenarios "s1,s2,s3,s4" \
  --sample-interval "$INTERVAL" \
  --out-dir "$OUT_DIR"

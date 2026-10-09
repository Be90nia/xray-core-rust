#!/bin/bash
# xhttp_strace.sh —— 跟踪 xray 进程对指定 xhttp 端口的 syscall
# 用途: 饿死定位（88m0 战役脉络：DRS 钉窗 / per-flow 64KB 收侧）—— 看 sys 侧
#       是否出现 read/poll 长时阻塞、write 间歇性积压、connect 重试
# 短时延：本机 strace 开销 5-10%，长轮 90s 起采样
# 用法: xhttp_strace.sh <xray_pid> <xhttp_port> [duration_sec]
# 缺省: 30s 采样
set -euo pipefail
PID="${1:?usage: $0 <xray_pid> <xhttp_port> [duration_sec]}"
PORT="${2:?usage: $0 <xray_pid> <xhttp_port> [duration_sec]}"
DUR="${3:-30}"
OUT="${XHTTP_STRACE_OUT:-/tmp/xhttp-strace-$(date +%s)}"
mkdir -p "$OUT"
echo "xhttp_strace: pid=$PID port=$PORT dur=${DUR}s out=$OUT"

# 过滤: 关注 connect/read/write/poll/recv/send + TCP-only fd
# -tt 时间戳 + -T 调内耗时 + -f 追 fork
strace -f -tt -T \
  -e trace='connect,read,write,recvfrom,sendto,recvmsg,sendmsg,poll,ppoll,epoll_wait' \
  -p "$PID" \
  -o "$OUT/strace.log" &
STRACE_PID=$!
trap 'kill "$STRACE_PID" 2>/dev/null || true' EXIT

sleep "$DUR"
kill "$STRACE_PID" 2>/dev/null || true
wait "$STRACE_PID" 2>/dev/null || true

# 摘要: 每 syscall 计数 + 总耗时 ms（饿死特征：read/poll 长尾）
echo "=== syscall 计数 ==="
awk '
  /[0-9]+\.[0-9]+ ([a-z_]+)\(/ {
    name=$2; sub(/\(.*/, "", name)
    cnt[name]++; tot[name]+=$(NF-1)+0
  }
  END { for (k in cnt) printf "%-15s %6d  total=%8.2fms\n", k, cnt[k], tot[k] }
' "$OUT/strace.log" | sort -k2 -nr | head -20

echo "=== 长 read/poll 顶部 (饿死的 syscall 签名) ==="
# rt_sigreturn/clone/futex 等基础设施跳过; 单条 >100ms 算可疑
awk '
  $2 ~ /read|recvfrom|recvmsg|poll|ppoll|epoll_wait/ {
    dur=$(NF-1)+0
    if (dur > 0.1) printf "%-30s %s ms=%.2f\n", $1, $2, dur
  }
' "$OUT/strace.log" | head -20

echo "raw: $OUT/strace.log"

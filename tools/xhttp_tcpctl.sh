#!/bin/bash
# xhttp_tcpctl.sh —— 周期 ss -tin 采样 DRS / rcv_space 钉窗
# 用途: 88m0 战役确定签名：per-flow 64KB 收窗 (rcv_space ≈ 65495) 亚稳态
#       150ms RTT 下 ~40KB/s；健康流 458-835KB/s
# 关键指标: rcv_space, cwnd, rtt, ssthresh, retrans
# 用法: xhttp_tcpctl.sh <xray_pid> [duration_sec] [interval_sec]
# 缺省: 90s / 0.5s 间隔（与原 bench7p1m 一致）
set -euo pipefail
PID="${1:?usage: $0 <xray_pid> [duration_sec] [interval_sec]}"
DUR="${2:-90}"
INT="${3:-0.5}"
OUT="${XHTTP_TCPCTL_OUT:-/tmp/xhttp-tcpctl-$(date +%s)}"
mkdir -p "$OUT"
LOG="$OUT/ss-tin.log"
echo "xhttp_tcpctl: pid=$PID dur=${DUR}s int=${INT}s out=$OUT"

# 抓 xray 的 TCP fd 集合（一次，pid 稳定后）
echo "# ss-tin 采样, 间隔 ${INT}s, pid=$PID" > "$LOG"
END=$((SECONDS + DUR))
while [ $SECONDS -lt $END ]; do
  # 关联 xray 的 TCP 4 元组 → ss 抓全部 inbound/outbound
  FD_LIST=$(ls -la /proc/"$PID"/fd/ 2>/dev/null \
    | awk '/socket:/ {print $NF}' | tr -d '[]' || true)
  echo "--- $(date +%H:%M:%S.%N) ---" >> "$LOG"
  if [ -n "$FD_LIST" ]; then
    # ss -tin 全连接，pid 过滤 xray
    ss -tin -p 2>/dev/null | awk -v p="$PID" '
      $0 ~ "pid=" p { print }
    ' >> "$LOG" || true
  fi
  sleep "$INT"
done

# 分析: 检出 rcv_space<阈值（DRS 钉窗 ≈ 64KB ≈ 65535 附近）
THRESH="${XHTTP_RCV_THRESH:-131072}"  # < 128KB 算可疑
echo "=== rcv_space < ${THRESH} 的采样 ==="
awk -v t="$THRESH" '
  /rcv_space:/ {
    n=split($0, a, /[: ]+/); for (i=1;i<=n;i++) if (a[i]=="rcv_space") break
    v=a[i+1]+0
    if (v < t) print $0
  }
' "$LOG" | head -30

# 摘要: 各连接 rcv_space 时序最小/最大
echo "=== 各流 rcv_space 范围 ==="
awk '
  /tcp / { peer=$6; ts=NR }
  /rcv_space:/ {
    n=split($0, a, /[: ]+/); for (i=1;i<=n;i++) if (a[i]=="rcv_space") break
    v=a[i+1]+0
    if (peer != "") { lo[peer]=v; hi[peer]=v }
  }
' "$LOG" | head -10

# 全连接表（每个 peer 最后一次 rcv_space）
awk '
  /tcp / { peer=$6 }
  /rcv_space:/ {
    n=split($0, a, /[: ]+/); for (i=i;i<=n;i++) if (a[i]=="rcv_space") break
    val=a[i+1]+0
    if (peer != "") { last[peer]=val }
  }
  END { for (p in last) printf "%-30s rcv_space=%s\n", p, last[p] }
' "$LOG"

echo "raw: $LOG"

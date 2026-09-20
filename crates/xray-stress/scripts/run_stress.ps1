# xray-stress 长跑启动脚本（Windows）。
# 用法: .\run_stress.ps1 -Tier standard -DurationHours 48 [-OutDir stress-out]
# 档位: conservative / standard / aggressive（标准档 = 任务钦定基线：8 并发 S1 + 4 条 S2 + S3 + S4；激进 x4）
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("conservative", "standard", "aggressive")]
    [string]$Tier,
    [double]$DurationHours = 48,
    [string]$OutDir = "stress-out"
)

$ErrorActionPreference = "Stop"

# --- 防睡眠检测：AC 睡眠超时非 0 即警告（长跑中途系统睡眠会截断采样） ---
$raw = powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Warning "powercfg query failed; cannot verify sleep settings."
} else {
    $acLine = ($raw | Select-String "Current AC Power Setting Index")
    if ($null -ne $acLine -and $acLine.ToString() -match "0x([0-9a-fA-F]+)") {
        $acSeconds = [Convert]::ToInt64($Matches[1], 16)
        if ($acSeconds -gt 0) {
            Write-Warning "System AC sleep timeout = $acSeconds s (non-zero). Run is $DurationHours h - disable sleep or use powercfg /change standby-timeout-ac 0"
        } else {
            Write-Host "[sleep-check] OK: AC sleep disabled"
        }
    }
}

# --- 三档参数 ---
switch ($Tier) {
    "conservative" { $concurrency = 4; $s2Conns = 2; $interval = 60; $delayMs = 300 }
    "standard"     { $concurrency = 8; $s2Conns = 4; $interval = 30; $delayMs = 150 }
    "aggressive"   { $concurrency = 32; $s2Conns = 16; $interval = 15; $delayMs = 40 }
}
$durationSec = [int]($DurationHours * 3600)

# --- 短连接风暴的 OS 约束：动态端口 ~16K / TIME_WAIT 240s ≈ 68 conn/s ---
# 激进档（32 并发 x 40ms ≈ 200 conn/s）需扩动态端口（管理员）：
#   netsh int ipv4 set dynamicport tcp start=1025 num=64510
if ($Tier -eq "aggressive") {
    $dyn = netsh int ipv4 show dynamicport tcp 2>$null | Select-String "Number of dynamically reserved ports|动态保留端口的数目"
    Write-Warning "aggressive tier exceeds default Windows dynamic-port budget (~68 conn/s). Consider (admin): netsh int ipv4 set dynamicport tcp start=1025 num=64510; current: $dyn"
}

# --- 长跑启动命令 ---
$exe = Join-Path $PSScriptRoot "..\..\..\target\release\xray-stress.exe"
Write-Host "[run] $exe --duration $durationSec --concurrency $concurrency --s2-conns $s2Conns --s1-delay-ms $delayMs --scenarios s1,s2,s3,s4 --sample-interval $interval --out-dir $OutDir"
& $exe `
    --duration $durationSec `
    --concurrency $concurrency `
    --s2-conns $s2Conns `
    --s1-delay-ms $delayMs `
    --scenarios "s1,s2,s3,s4" `
    --sample-interval $interval `
    --out-dir $OutDir
exit $LASTEXITCODE

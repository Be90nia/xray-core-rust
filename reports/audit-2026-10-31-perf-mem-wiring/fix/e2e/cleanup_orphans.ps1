Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
  Where-Object { $_.CommandLine -match 'dest_srv' -or $_.CommandLine -match 'tls_srv' -or $_.CommandLine -match 'hello_dump' } |
  ForEach-Object {
    Write-Output ("PID=" + $_.ProcessId + " CMD=" + $_.CommandLine)
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
  }
Get-CimInstance Win32_Process -Filter "Name='xray.exe'" |
  ForEach-Object {
    Write-Output ("XRAY PID=" + $_.ProcessId + " CMD=" + $_.CommandLine)
    if ($_.CommandLine -match 'round6') { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  }

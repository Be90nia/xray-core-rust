@echo off
REM 抓包脚本:管理员右键运行
REM 用法:capture_node.cmd 1  (抓 #1 节点)
set NODE=%1
if "%NODE%"=="" set NODE=1
set TSHARK=D:\Project\tools\Wireshark\tshark.exe
set OUT=D:\tmp\capture_node%NODE%.pcapng
echo Capturing node #%NODE% to %OUT% ...
echo Start xray now and curl the test
"%TSHARK%" -i 1 -w "%OUT%" -a duration:30 -f "tcp port 443"
echo Done. Open with: D:\Project\tools\Wireshark\Wireshark.exe "%OUT%"
pause

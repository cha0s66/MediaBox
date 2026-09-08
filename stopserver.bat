@echo off
setlocal

echo Stopping MediaBox on port 8000...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$processes = Get-CimInstance Win32_Process | Where-Object { $_.Name -in @('python.exe', 'pythonw.exe') -and $_.CommandLine -match 'server\.py' -and $_.CommandLine -match '--port\s+8000' }; if (-not $processes) { Write-Host 'MediaBox is not running.'; exit 0 }; $processes | ForEach-Object { Stop-Process -Id $_.ProcessId -Force; Write-Host ('Stopped process ' + $_.ProcessId) }"

endlocal

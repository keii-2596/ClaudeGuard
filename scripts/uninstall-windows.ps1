$ErrorActionPreference = 'Stop'
$InstallRoot = Join-Path $env:LOCALAPPDATA 'ClaudeGuard'
$Python = Join-Path $InstallRoot 'venv\Scripts\python.exe'
$Entry = Join-Path $InstallRoot 'portable\main.py'
if ((Test-Path $Python) -and (Test-Path $Entry)) {
    & $Python $Entry autostart disable
    if ($LASTEXITCODE -ne 0) { throw '关闭自启动失败，已停止卸载。' }
    & $Python $Entry stop
    if ($LASTEXITCODE -ne 0) { throw '停止守护失败，已停止卸载。' }
    & $Python $Entry network remove
    if ($LASTEXITCODE -ne 0) { throw '系统网络助手卸载失败，已停止卸载。' }
}
Remove-Item (Join-Path ([Environment]::GetFolderPath('Desktop')) 'ClaudeGuard.lnk') -ErrorAction SilentlyContinue
Remove-Item $InstallRoot -Recurse -Force
Write-Host '程序已卸载，IP 白名单配置已保留。'

$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw '此脚本仅适用于 Windows。' }
$SourceRoot = Split-Path $PSScriptRoot -Parent
$InstallRoot = Join-Path $env:LOCALAPPDATA 'ClaudeGuard'
New-Item -ItemType Directory -Force $InstallRoot | Out-Null
if ([IO.Path]::GetFullPath($SourceRoot) -eq [IO.Path]::GetFullPath($InstallRoot)) { throw '请从源码目录运行安装器。' }
py -3 -m venv (Join-Path $InstallRoot 'venv')
if ($LASTEXITCODE -ne 0) { throw '创建虚拟环境失败，请先安装 Python 3.10 或更新版本。' }
$Python = Join-Path $InstallRoot 'venv\Scripts\python.exe'
& $Python -m pip install -r (Join-Path $SourceRoot 'portable\requirements.txt')
if ($LASTEXITCODE -ne 0) { throw '依赖安装失败。' }
foreach ($Name in @('portable', 'src', 'native', 'scripts')) {
    $Destination = Join-Path $InstallRoot $Name
    New-Item -ItemType Directory -Force $Destination | Out-Null
    Copy-Item (Join-Path $SourceRoot "$Name\*") $Destination -Recurse -Force
}
$Entry = Join-Path $InstallRoot 'portable\main.py'
$Pythonw = Join-Path $InstallRoot 'venv\Scripts\pythonw.exe'
$Shell = New-Object -ComObject WScript.Shell
$Shortcut = $Shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) 'ClaudeGuard.lnk'))
$Shortcut.TargetPath = $Pythonw
$Shortcut.Arguments = '"' + $Entry + '" gui'
$Shortcut.WorkingDirectory = $InstallRoot
$Shortcut.Save()
Write-Host "安装完成。双击桌面上的 ClaudeGuard 设置白名单和程序路径。"
Write-Host "命令行入口：& `"$Python`" `"$Entry`" status"
Write-Host '登录自启动可在设置窗口开启。'

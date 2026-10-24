param([Parameter(Mandatory=$true)][string]$Config, [switch]$Remove)
$ErrorActionPreference = 'Stop'
$Admin = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $Admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw '请以管理员权限运行网络助手安装器。' }
Add-Type -Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'native\windows_wfp.cs')
$Config = [IO.Path]::GetFullPath($Config)
if (Test-Path -LiteralPath $Config) { $Config = [ClaudeGuardWfp]::Canonical($Config) } elseif ($Remove) { $Config = $Config.ToLowerInvariant() } else { throw '配置文件不存在。' }
$Hash = [Security.Cryptography.SHA256]::Create()
try { $Id = ([BitConverter]::ToString($Hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($Config)))).Replace('-', '').Substring(0,16).ToLowerInvariant() } finally { $Hash.Dispose() }
$Base = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ClaudeGuardNetwork'
$Root = Join-Path $Base $Id
$Manifest = Join-Path $Root 'manifest.json'
$TaskName = 'ClaudeGuardNetwork-' + $Id
$PowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
foreach ($Directory in @($Base, $Root)) {
    if ((Test-Path -LiteralPath $Directory) -and ((Get-Item -LiteralPath $Directory).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw '网络助手目录不能是重解析点。' }
    New-Item -ItemType Directory -Path $Directory -Force | Out-Null
}
# Only SYSTEM/administrators can replace privileged code or manifest. Users read status.
$Acl = New-Object Security.AccessControl.DirectorySecurity
$Acl.SetAccessRuleProtection($true, $false)
$Acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
foreach ($Sid in @('S-1-5-18','S-1-5-32-544')) {
    $Acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($Sid)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
$Acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
Set-Acl -LiteralPath $Base -AclObject $Acl
Set-Acl -LiteralPath $Root -AclObject $Acl
$Native = Join-Path (Split-Path $PSScriptRoot -Parent) 'native'
foreach ($File in @('windows_wfp.cs','windows_network_helper.ps1')) {
    $Destination = Join-Path $Root $File
    if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Force }
    Copy-Item -LiteralPath (Join-Path $Native $File) -Destination $Root -Force }

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName
    $Deadline = (Get-Date).AddSeconds(10)
    while ((Get-ScheduledTask -TaskName $TaskName).State -eq 'Running') {
        if ((Get-Date) -gt $Deadline) { throw '网络助手未停止，取消规则清理。' }
        Start-Sleep -Milliseconds 100
    }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
if (Test-Path $Manifest) {
    & $PowerShell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'windows_network_helper.ps1') -Manifest $Manifest -Remove
    if ($LASTEXITCODE -ne 0) { throw '清理旧网络规则失败，已停止安装/卸载。' }
}
if ($Remove) { Remove-Item -LiteralPath $Root -Recurse -Force; Write-Host '系统网络助手和专用 WFP 规则已移除。'; return }

$Data = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
$Paths = @(@($Data.cli_path, $Data.desktop_path) | Where-Object { $_ } | ForEach-Object { [ClaudeGuardWfp]::Canonical([IO.Path]::GetFullPath($_)) } | Sort-Object -Unique)
if (-not $Paths.Count) { throw '请先配置 Claude 原生程序路径。' }
foreach ($Path in $Paths) { if (-not (Test-Path -LiteralPath $Path -PathType Leaf) -or [IO.Path]::GetExtension($Path) -ne '.exe') { throw '需要有效的原生 exe 程序路径。' } }
$Programs = @($Paths)
# Electron helpers live below the configured desktop executable directory.
if ($Data.desktop_path) {
    $DesktopRoot = Split-Path ([ClaudeGuardWfp]::Canonical([IO.Path]::GetFullPath($Data.desktop_path))) -Parent
    $Programs += @(Get-ChildItem -LiteralPath $DesktopRoot -File -Recurse -Filter '*.exe' | Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } | ForEach-Object { [ClaudeGuardWfp]::Canonical($_.FullName) })
}
$Programs = @($Programs | Sort-Object -Unique)
if ($Programs.Count -gt 256) { throw '桌面程序目录过大，请准确选择 Claude 安装目录中的 exe。' }
$ManifestData = @{id=$Id; paths=$Paths; programs=$Programs; request=(Join-Path (Split-Path $Config -Parent) 'network-request.json')}
if (Test-Path -LiteralPath $Manifest) { Remove-Item -LiteralPath $Manifest -Force }
foreach ($File in @('status.json','status.tmp')) { Remove-Item -LiteralPath (Join-Path $Root $File) -Force -ErrorAction SilentlyContinue }
[IO.File]::WriteAllText($Manifest, ($ManifestData | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))
& $PowerShell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'windows_network_helper.ps1') -Manifest $Manifest -Block
if ($LASTEXITCODE -ne 0) { throw 'WFP 初始化失败，未启用网络助手。' }
$Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $Root 'windows_network_helper.ps1') + '" -Manifest "' + $Manifest + '"'
$Action = New-ScheduledTaskAction -Execute $PowerShell -Argument $Arguments
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Host 'WFP 网络助手已安装，当前默认阻断。请启用 network_guard_enabled 并启动守护。'

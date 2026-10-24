$ErrorActionPreference = 'Stop'
$Source = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$Temp = Join-Path $env:RUNNER_TEMP ('claudeguard-wfp-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $Temp | Out-Null
$Probe = Join-Path $Temp 'network-probe.exe'
Add-Type -TypeDefinition @'
using System;
using System.Net.Sockets;
public class Probe {
 public static int Main(string[] args) {
  try { using(var c=new TcpClient(args.Length>1 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork)) { var task=c.ConnectAsync(args.Length>1 ? "::1" : "127.0.0.1",Int32.Parse(args[0])); if(!task.Wait(1000)) return 2; task.GetAwaiter().GetResult(); return 0; } }
  catch { return 1; }
 }
}
'@ -OutputAssembly $Probe -OutputType ConsoleApplication
$Listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$Listener.Start()
$Listener6 = [Net.Sockets.TcpListener]::new([Net.IPAddress]::IPv6Loopback, 0)
$Listener6.Start()
$Port6 = $Listener6.LocalEndpoint.Port
$Port = $Listener.LocalEndpoint.Port
$Id = [Guid]::NewGuid().ToString('N').Substring(0,16)
$Manifest = Join-Path $Temp 'manifest.json'
$Request = Join-Path $Temp 'network-request.json'
@{id=$Id; paths=@($Probe.ToLowerInvariant()); programs=@($Probe); request=$Request} | ConvertTo-Json | Set-Content $Manifest -Encoding UTF8
$Helper = Join-Path $Source 'native\windows_network_helper.ps1'
$PowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
try {
    & $Probe $Port
    if ($LASTEXITCODE -ne 0) { throw 'Baseline loopback probe failed' }
    & $PowerShell -NoProfile -ExecutionPolicy Bypass -File $Helper -Manifest $Manifest -Once
    if ($LASTEXITCODE -ne 0) { throw 'WFP block setup failed' }
    & $Probe $Port
    if ($LASTEXITCODE -eq 0) { throw 'WFP failed to block loopback connection' }
    & $Probe $Port6 ipv6
    if ($LASTEXITCODE -eq 0) { throw 'WFP failed to block IPv6 loopback connection' }
    $Producer = Start-Process $PowerShell -WindowStyle Hidden -ArgumentList '-NoProfile -Command Start-Sleep -Seconds 120' -PassThru
    @{schema=2; producer_pid=$Producer.Id; producer_start=(([DateTimeOffset]$Producer.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds()/1000.0); allowed=$true; expires_at=([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()+60); configured_paths=@($Probe.ToLowerInvariant())} | ConvertTo-Json | Set-Content $Request -Encoding UTF8
    & $PowerShell -NoProfile -ExecutionPolicy Bypass -File $Helper -Manifest $Manifest -Once
    if ($LASTEXITCODE -ne 0) { throw 'WFP allow setup failed' }
    & $Probe $Port
    if ($LASTEXITCODE -ne 0) { throw 'WFP failed to release own filter' }
    & $Probe $Port6 ipv6
    if ($LASTEXITCODE -ne 0) { throw 'WFP failed to release IPv6 filter' }
    Stop-Process -Id $Producer.Id -Force
    $Producer.WaitForExit()
    & $PowerShell -NoProfile -ExecutionPolicy Bypass -File $Helper -Manifest $Manifest -Once
    if ($LASTEXITCODE -ne 0) { throw 'WFP stale-lease setup failed' }
    & $Probe $Port
    if ($LASTEXITCODE -eq 0) { throw 'WFP failed to block after lease removal' }
    Write-Host 'Windows WFP blocked/allowed/reblocked IPv4 and IPv6 loopback connection'
    & $PowerShell -NoProfile -ExecutionPolicy Bypass -File $Helper -Manifest $Manifest -Remove
    if ($LASTEXITCODE -ne 0) { throw 'Direct test filter cleanup failed' }
    $Config = Join-Path $Temp 'config.json'
    @{cli_path=$Probe; desktop_path=''} | ConvertTo-Json | Set-Content $Config -Encoding UTF8
    $Setup = Join-Path $Source 'scripts\setup-network-windows.ps1'
    & $PowerShell -NoProfile -ExecutionPolicy Bypass -File $Setup -Config $Config
    if ($LASTEXITCODE -ne 0) { throw 'Privileged installation failed' }
    try {
        $CanonicalConfig = [IO.Path]::GetFullPath($Config).ToLowerInvariant()
        $Hash = [Security.Cryptography.SHA256]::Create()
        try { $InstallId = ([BitConverter]::ToString($Hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($CanonicalConfig)))).Replace('-', '').Substring(0,16).ToLowerInvariant() } finally { $Hash.Dispose() }
        $Status = Join-Path $env:ProgramData ('ClaudeGuardNetwork\' + $InstallId + '\status.json')
        $Deadline = (Get-Date).AddSeconds(30)
        do {
            Start-Sleep -Milliseconds 250
            $State = $null
            if(Test-Path $Status) { $State=Get-Content $Status -Raw | ConvertFrom-Json }
            if((Get-Date) -gt $Deadline) { throw 'Installed SYSTEM task did not become ready' }
        } while(-not $State.ready)
        if($State.applied_state -ne 'blocked') { throw 'Installed helper did not default to blocked' }
    } finally {
        & $PowerShell -NoProfile -ExecutionPolicy Bypass -File $Setup -Config $Config -Remove
        if ($LASTEXITCODE -ne 0) { throw 'Privileged uninstall failed' }
    }
    # Already removed; avoid trying to delete the direct test sublayer twice.
    $Manifest = $null
} finally {
    if ($Producer -and -not $Producer.HasExited) { $Producer.Kill() }
    if ($Manifest) { & $PowerShell -NoProfile -ExecutionPolicy Bypass -File $Helper -Manifest $Manifest -Remove }
    $Listener.Stop()
    $Listener6.Stop()
    Remove-Item -LiteralPath $Temp -Recurse -Force
}

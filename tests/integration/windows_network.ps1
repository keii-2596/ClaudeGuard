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
  try { using(var c=new TcpClient()) { var task=c.ConnectAsync("127.0.0.1",Int32.Parse(args[0])); if(!task.Wait(1000)) return 2; task.GetAwaiter().GetResult(); return 0; } }
  catch { return 1; }
 }
}
'@ -OutputAssembly $Probe -OutputType ConsoleApplication
$Listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$Listener.Start()
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
    @{schema=1; allowed=$true; expires_at=([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()+60); configured_paths=@($Probe.ToLowerInvariant())} | ConvertTo-Json | Set-Content $Request -Encoding UTF8
    & $PowerShell -NoProfile -ExecutionPolicy Bypass -File $Helper -Manifest $Manifest -Once
    if ($LASTEXITCODE -ne 0) { throw 'WFP allow setup failed' }
    & $Probe $Port
    if ($LASTEXITCODE -ne 0) { throw 'WFP failed to release own filter' }
    Remove-Item $Request
    & $PowerShell -NoProfile -ExecutionPolicy Bypass -File $Helper -Manifest $Manifest -Once
    if ($LASTEXITCODE -ne 0) { throw 'WFP stale-lease setup failed' }
    & $Probe $Port
    if ($LASTEXITCODE -eq 0) { throw 'WFP failed to block after lease removal' }
    Write-Host 'Windows WFP blocked/allowed/reblocked loopback connection for configured exe'
} finally {
    & $PowerShell -NoProfile -ExecutionPolicy Bypass -File $Helper -Manifest $Manifest -Remove
    $Listener.Stop()
    Remove-Item -LiteralPath $Temp -Recurse -Force
}

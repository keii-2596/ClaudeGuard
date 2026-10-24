param([Parameter(Mandatory=$true)][string]$Manifest, [switch]$Remove, [switch]$Once, [switch]$Block)
$ErrorActionPreference = 'Stop'
Add-Type -Path (Join-Path $PSScriptRoot 'windows_wfp.cs')
$Config = Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json
$Root = Split-Path $Manifest -Parent
$Wfp = [ClaudeGuardWfp]::new([string]$Config.id)
$Programs = [string[]]$Config.programs
function Read-SharedJson([string]$Path) {
    $File = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        if ($File.Length -gt 65536) { throw 'Request too large' }
        $Reader = New-Object IO.StreamReader($File)
        try { return ($Reader.ReadToEnd() | ConvertFrom-Json) } finally { $Reader.Dispose() }
    } finally { $File.Dispose() }
}
function Write-Status($Value) {
    $Temp = Join-Path $Root 'status.tmp'
    [IO.File]::WriteAllText($Temp, ($Value | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $Temp -Destination (Join-Path $Root 'status.json') -Force
}
try {
    if ($Remove) { $Wfp.Remove($Programs); return }
    $Wfp.SetBlocked($Programs, $true)
    if ($Block) { return }
    do {
        $Allowed = $false
        $Now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0
        try {
            $Request = Read-SharedJson $Config.request
            $SamePaths = (($Request.configured_paths | ConvertTo-Json -Compress) -ceq ($Config.paths | ConvertTo-Json -Compress))
            $Producer = Get-Process -Id $Request.producer_pid -ErrorAction Stop
            $Created = ([DateTimeOffset]$Producer.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds() / 1000.0
            $Alive = [Math]::Abs($Created - [double]$Request.producer_start) -lt 0.01
            $Allowed = ($Request.schema -eq 2 -and $Alive -and $Request.allowed -is [bool] -and $Request.allowed -eq $true -and
                $Request.expires_at -is [ValueType] -and $Request.expires_at -isnot [bool] -and
                $Request.expires_at -gt $Now -and $Request.expires_at -le ($Now + 90) -and $SamePaths)
        } catch { $Allowed = $false }
        try {
            $Wfp.SetBlocked($Programs, (-not $Allowed))
            Write-Status @{ready=$true; updated_at=$Now; applied_state=$(if($Allowed){'allowed'}else{'blocked'}); configured_paths=@($Config.paths); backend='windows-wfp-ale'; enrolled=@{}}
        } catch {
            try { $Wfp.SetBlocked($Programs, $true) } catch {}
            Write-Status @{ready=$false; updated_at=$Now; error=$_.Exception.Message}
        }
        if (-not $Once) { Start-Sleep -Milliseconds 250 }
    } while (-not $Once)
} finally { $Wfp.Dispose() }

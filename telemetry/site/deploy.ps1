# deploy.ps1 - build the stats site, back up what is live, swap the new files in, restart "Strata Telemetry",
# verify it, and roll back automatically if anything is wrong.
#
#   powershell -ExecutionPolicy Bypass -File <install folder>\telemetry\site\deploy.ps1
#   ... -TelemetryPy <path>     also install a new telemetry.py (first deploy of the hardened service)
#
# Downtime is the few seconds the service needs to restart. Backups go to backups\telemetry-<timestamp> (next to the install folder).
param([string]$TelemetryPy = '')
$ErrorActionPreference = 'Stop'

$site    = $PSScriptRoot
$tele    = Split-Path $site -Parent                               # <install folder>\telemetry
$static  = Join-Path $tele 'static'
$backups = Join-Path (Split-Path (Split-Path $tele -Parent) -Parent) 'backups'
$task    = 'Strata Telemetry'
$local   = 'http://127.0.0.1:8082'
$py      = (Get-Command python -ErrorAction Stop).Source

function Get-Code($url) { try { (Invoke-WebRequest $url -UseBasicParsing -TimeoutSec 5).StatusCode } catch { if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 } } }
function Restart-Telemetry {
    Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    for ($i = 0; $i -lt 20; $i++) { if (-not (Get-NetTCPConnection -LocalPort 8082 -State Listen -ErrorAction SilentlyContinue)) { break }; Start-Sleep -Milliseconds 500 }
    Start-ScheduledTask -TaskName $task
    for ($i = 0; $i -lt 40; $i++) { Start-Sleep -Milliseconds 500; if ((Get-Code "$local/") -eq 200) { return $true } }
    return $false
}
function Test-Live {
    $r = Invoke-WebRequest "$local/" -UseBasicParsing -TimeoutSec 5
    if ($r.StatusCode -ne 200) { return "GET / returned $($r.StatusCode)" }
    if (-not $r.Headers['Content-Security-Policy']) { return 'no Content-Security-Policy header' }
    $assets = (Get-Content (Join-Path $static 'manifest.json') -Raw | ConvertFrom-Json).assets
    foreach ($a in $assets) {
        if ($r.Content -notmatch [regex]::Escape($a) -and $a -notlike 'fonts/*') { return "index.html does not reference $a" }
        $c = Get-Code "$local/$a"; if ($c -ne 200) { return "/$a returned $c" }
    }
    foreach ($p in '/api/live', '/api/stats?range=24h') { $c = Get-Code "$local$p"; if ($c -ne 200) { return "$p returned $c" } }
    return $null
}

Write-Host '1/5 building'
& $py (Join-Path $site 'build.py'); if ($LASTEXITCODE -ne 0) { throw 'build failed' }

Write-Host '2/5 backing up what is live'
$bk = Join-Path $backups ('telemetry-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Force $bk | Out-Null
Copy-Item (Join-Path $tele 'telemetry.py') $bk
Copy-Item $static (Join-Path $bk 'static') -Recurse
Write-Host "    $bk"

Write-Host '3/5 installing'
if ($TelemetryPy) { Copy-Item $TelemetryPy (Join-Path $tele 'telemetry.py') -Force }
Copy-Item (Join-Path $site 'dist\*') $static -Recurse -Force
$keep = @('index.html', 'favicon.ico', 'manifest.json') + ((Get-Content (Join-Path $static 'manifest.json') -Raw | ConvertFrom-Json).assets | ForEach-Object { $_ -replace '/', '\' })
Get-ChildItem $static -Recurse -File | ForEach-Object {
    $rel = $_.FullName.Substring($static.Length + 1)
    if ($keep -notcontains $rel) { Remove-Item -LiteralPath $_.FullName -Force }   # old app.js / styles.css / older hashes (all in the backup)
}

Write-Host '4/5 restarting the service'
$up = Restart-Telemetry
$problem = if ($up) { Test-Live } else { 'service did not come back within 20 s' }

if ($problem) {
    Write-Host "5/5 FAILED: $problem - rolling back" -ForegroundColor Red
    Copy-Item (Join-Path $bk 'telemetry.py') (Join-Path $tele 'telemetry.py') -Force
    Get-ChildItem $static -Recurse -File | Remove-Item -Force
    Copy-Item (Join-Path $bk 'static\*') $static -Recurse -Force
    if (Restart-Telemetry) { Write-Host 'rolled back; the previous version is live again.' -ForegroundColor Yellow } else { Write-Host 'ROLLBACK DID NOT COME UP - restore manually from' $bk -ForegroundColor Red }
    exit 1
}
Write-Host '5/5 OK - the new version is live on 127.0.0.1:8082' -ForegroundColor Green

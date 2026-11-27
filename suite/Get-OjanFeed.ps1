param([ValidateSet('central','unified','ua','ip')]$Feed='central',
      [ValidateSet('live','demo')]$Mode='live',
      [string]$OutFile='ojan-lookup.csv')
$ErrorActionPreference='Stop'
if (-not $env:OJAN_SIEM_TOKEN) { throw 'Set OJAN_SIEM_TOKEN in the importer environment.' }
$headers=@{Authorization="Bearer $env:OJAN_SIEM_TOKEN"}
$base="http://127.0.0.1:18747/api/v1/feeds/$Feed/snapshots"
$m=Invoke-RestMethod -Uri "$base/latest?mode=$Mode" -Headers $headers
$dest=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
$tmp="$dest.$([guid]::NewGuid().ToString('N')).tmp"
try {
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$($m.version)/downloads/lookup.csv?mode=$Mode" -Headers $headers -OutFile $tmp
    if ((Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash -ne $m.sha256.'lookup.csv') { throw 'Publication checksum mismatch' }
    python -c "import os,sys; os.replace(sys.argv[1],sys.argv[2])" $tmp $dest
    if ($LASTEXITCODE) { throw 'Could not install verified lookup' }
    Write-Output "$Feed $Mode $($m.version) $dest"
} finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp } }

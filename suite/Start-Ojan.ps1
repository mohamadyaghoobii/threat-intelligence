param([int]$Port=18746,[int]$ApiPort=18747,[switch]$Background)
Push-Location $PSScriptRoot
try {
    $state = python suite.py status | ConvertFrom-Json
    foreach ($name in 'unified','central','ua','ip') {
        if (-not $state.$name.manifest.version) {
            python suite.py run --feed $name
            if ($LASTEXITCODE) { throw "Fixture collection failed for $name" }
        }
    }
    Write-Host "Ojan console http://127.0.0.1:$Port/"
    if (-not $env:OJAN_SIEM_TOKEN) {
        $env:OJAN_SIEM_TOKEN=[Guid]::NewGuid().ToString('N')+[Guid]::NewGuid().ToString('N')
    }
    if ($Background) {
        Start-Process python -ArgumentList 'suite.py','serve','--port',$Port,'--api-port',$ApiPort -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -PassThru
    } else {
        python suite.py serve --port $Port --api-port $ApiPort
    }
} finally { Pop-Location }

[CmdletBinding()]
param(
    [string]$BaseUrl = 'http://127.0.0.1:18080',
    [string]$ForgePath,
    [ValidateSet('direct-core', 'transport-quota', 'safe-rejection', 'lifecycle', 'resilience', 'full')]
    [string]$Profile = 'full',
    [ValidateRange(1, 1000)]
    [int]$Repeat = 1,
    [switch]$Build
)

$ErrorActionPreference = 'Stop'

function Fail([string]$Message) { throw $Message }

function Write-CoverageMarkdown([object]$Report, [string]$Path) {
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('# FQDN Lens Forge coverage')
    $lines.Add('')
    $lines.Add("Status: $($Report.status)")
    $lines.Add('')
    $lines.Add("Profile: $($Report.profile)")
    $lines.Add('')
    $lines.Add("Runs: $($Report.scenario_count)")
    $lines.Add('')
    $lines.Add('## Classification')
    $lines.Add('')
    $lines.Add('| Classification | Count |')
    $lines.Add('|---|---:|')
    foreach ($property in $Report.classification_counts.PSObject.Properties) {
        $lines.Add("| $($property.Name) | $($property.Value) |")
    }
    $lines.Add('')
    $lines.Add('## Scenario results')
    $lines.Add('')
    $lines.Add('| Scenario | Classification | Seed | Status | Forge run | Lens run | Runtime ms | Failure / deferred reason |')
    $lines.Add('|---|---|---:|---|---|---|---:|---|')
    foreach ($scenario in $Report.scenarios) {
        $detail = if ($scenario.failure) { $scenario.failure } elseif ($scenario.deferred_reason) { $scenario.deferred_reason } else { '' }
        $detail = $detail.Replace('|', '\|').Replace("`r", ' ').Replace("`n", ' ')
        $seed = if ($null -eq $scenario.seed) { '-' } else { $scenario.seed }
        $forgeRun = if ($scenario.forge_run_id) { $scenario.forge_run_id } else { '-' }
        $lensRun = if ($scenario.lens_run_id) { $scenario.lens_run_id } else { '-' }
        $lines.Add("| $($scenario.id) | $($scenario.classification) | $seed | $($scenario.status) | $forgeRun | $lensRun | $($scenario.runtime_ms) | $detail |")
    }
    [IO.File]::WriteAllText($Path, ($lines -join [Environment]::NewLine) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

try {
    $uri = [Uri]$BaseUrl
} catch {
    Fail 'BaseUrl must be a valid URL.'
}
if ($uri.Scheme -ne 'http' -or $uri.Host -ne '127.0.0.1' -or $uri.Port -le 0 -or $uri.UserInfo) {
    Fail 'FQDN Forge verification accepts only numeric loopback HTTP without URL userinfo.'
}

$lensRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$matrixPath = Join-Path $lensRoot 'docs\forge-coverage-matrix.yaml'
$matrix = Get-Content -Raw -LiteralPath $matrixPath | ConvertFrom-Json
if (@($matrix.scenarios).Count -ne 114) { Fail 'Coverage registry must contain exactly 114 scenarios.' }
$classification = @($matrix.scenarios | Group-Object classification)
$safe = ($classification | Where-Object Name -eq 'safe-rejection').Count
$forgeOwned = ($classification | Where-Object Name -eq 'forge-owned').Count
$supported = ($classification | Where-Object { $_.Name -in @('supported-forge-pass', 'supported-lens-local') } | Measure-Object Count -Sum).Sum
if ($safe -ne 12 -or $forgeOwned -ne 1 -or $supported -ne 101) {
    Fail 'Coverage registry classification count does not satisfy the V0.2 101/12/1 target.'
}

if ([string]::IsNullOrWhiteSpace($ForgePath)) { $ForgePath = Join-Path $PSScriptRoot '..\..\fqdn-forge' }
$forgeRoot = (Resolve-Path $ForgePath).Path
$binary = Join-Path $lensRoot 'target\debug\fqdn-lens.exe'
$artifacts = Join-Path $lensRoot 'artifacts'
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('fqdn-lens-forge-' + [Guid]::NewGuid().ToString('N'))
$forgeProcess = $null
$startedForge = $false

try {
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $artifacts -Force | Out-Null
    if ($Build -or -not (Test-Path -LiteralPath $binary)) {
        & cargo build -p lens-cli --locked
        if ($LASTEXITCODE -ne 0) { Fail 'lens-cli build failed.' }
    }

    $listener = Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort $uri.Port -State Listen -ErrorAction SilentlyContinue
    if (-not $listener) {
        $forgeProcess = Start-Process -FilePath 'cargo' -ArgumentList @('run', '-p', 'lab-cli', '--locked', '--', 'serve', '--port', $uri.Port) -WorkingDirectory $forgeRoot -PassThru -WindowStyle Hidden
        $startedForge = $true
        $ready = $false
        for ($attempt = 0; $attempt -lt 80; $attempt++) {
            Start-Sleep -Milliseconds 250
            if (Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort $uri.Port -State Listen -ErrorAction SilentlyContinue) {
                $ready = $true
                break
            }
        }
        if (-not $ready) { Fail 'FQDN Forge did not become available on the requested loopback port.' }
    }

    $database = Join-Path $tempRoot 'coverage.db'
    $temporaryReport = Join-Path $tempRoot 'forge-coverage.json'
    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $cliOutput = (& $binary '--database' $database 'lab' 'verify' '--base-url' $BaseUrl '--profile' $Profile '--repeat' $Repeat '--output' $temporaryReport 2>$null | Out-String).Trim()
        $cliExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
    if (-not (Test-Path -LiteralPath $temporaryReport)) {
        Fail "Lens did not produce a coverage report: $cliOutput"
    }
    $report = Get-Content -Raw -LiteralPath $temporaryReport | ConvertFrom-Json
    $jsonOutput = Join-Path $artifacts 'forge-coverage.json'
    $markdownOutput = Join-Path $artifacts 'forge-coverage.md'
    Copy-Item -LiteralPath $temporaryReport -Destination $jsonOutput -Force
    Write-CoverageMarkdown $report $markdownOutput

    [pscustomobject]@{
        schema_version = 'fqdn-lens.forge-matrix.v2'
        status = $report.status
        profile = $Profile
        repeat = $Repeat
        scenario_count = $report.scenario_count
        artifacts = [pscustomobject]@{ json = $jsonOutput; markdown = $markdownOutput }
        first_failure = @($report.scenarios | Where-Object status -eq 'failed' | Select-Object -First 1)
    } | ConvertTo-Json -Depth 8

    if ($cliExit -ne 0 -or $report.status -ne 'passed') { exit 1 }
} catch {
    [pscustomobject]@{
        schema_version = 'fqdn-lens.forge-matrix.v2'
        status = 'failed'
        profile = $Profile
        repeat = $Repeat
        error = $_.Exception.Message
    } | ConvertTo-Json -Depth 8
    exit 1
} finally {
    if ($forgeProcess -and $startedForge) {
        Stop-Process -Id $forgeProcess.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $forgeProcess.Id -Timeout 5 -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

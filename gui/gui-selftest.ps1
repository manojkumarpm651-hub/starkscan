<#
.SYNOPSIS
    Tests the pure helper functions inside starkscan-gui.ps1.

.DESCRIPTION
    The interface itself needs a window and a person, but the logic that
    decides what to display does not. This extracts the standalone functions
    and exercises them directly, under the same Set-StrictMode the real script
    uses, because that setting is what turns a benign-looking property read
    into a runtime error.

    It exists because a clean scan - the outcome a user most wants - crashed
    the interface with "The property 'Name' cannot be found on this object",
    and nothing caught it before a human did.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\gui-selftest.ps1
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:Failed = 0
$script:Ran = 0

function Check {
    param([string]$Name, [scriptblock]$Body)
    $script:Ran++
    try {
        $result = & $Body
        if ($result) {
            Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor Green
        } else {
            Write-Host ("  FAIL  {0}" -f $Name) -ForegroundColor Red
            $script:Failed++
        }
    } catch {
        Write-Host ("  FAIL  {0} -- threw: {1}" -f $Name, $_.Exception.Message) -ForegroundColor Red
        $script:Failed++
    }
}

# Pull the standalone functions out of the interface script. Dot-sourcing the
# whole file would build a window and block.
$guiPath = Join-Path (Split-Path -Parent $PSCommandPath) "starkscan-gui.ps1"
if (-not (Test-Path -LiteralPath $guiPath)) { throw "starkscan-gui.ps1 not found beside this test" }
$src = Get-Content -LiteralPath $guiPath -Raw

foreach ($fn in @("Get-Prop", "Test-Prop", "ConvertTo-ArgumentString")) {
    $m = [regex]::Match($src, "(?ms)^function $fn \{.*?^\}")
    if (-not $m.Success) { throw "could not extract $fn from starkscan-gui.ps1" }
    Invoke-Expression $m.Value
}

Write-Host "starkscan GUI self-test" -ForegroundColor Cyan
Write-Host ("-" * 58)

# --- the regression that reached a user ------------------------------------
# A scan with no findings serialises counts_by_severity as {} and findings as
# null. Reading .PSObject.Properties.Name off the empty object throws.
$cleanReport = '{"findings":null,"counts_by_severity":{},"stats":{"files_scanned":1}}' | ConvertFrom-Json

Check "clean report: summary loop does not throw" {
    $counts = @()
    foreach ($sev in @("CRITICAL","HIGH","MEDIUM","LOW","INFO")) {
        $n = Get-Prop $cleanReport.counts_by_severity $sev
        if ($null -ne $n) { $counts += "$n $sev" }
    }
    $counts.Count -eq 0
}

Check "clean report: findings absent is reported as absent" {
    (Test-Prop $cleanReport 'findings') -eq $false
}

# --- the populated case still behaves --------------------------------------
$fullReport = '{"findings":[{"rule_id":"SEC001","severity":"CRITICAL","path":"a.yml","line":3,"evidence":"AKIA****"}],"counts_by_severity":{"CRITICAL":1},"stats":{"files_scanned":2}}' | ConvertFrom-Json

Check "populated report: findings detected" { Test-Prop $fullReport 'findings' }
Check "populated report: severity count read back" {
    (Get-Prop $fullReport.counts_by_severity 'CRITICAL') -eq 1
}
Check "populated report: absent severity yields null" {
    $null -eq (Get-Prop $fullReport.counts_by_severity 'HIGH')
}

$finding = @($fullReport.findings)[0]
Check "finding: line present"        { Test-Prop $finding 'line' }
Check "finding: evidence present"    { Test-Prop $finding 'evidence' }
Check "finding: detail absent"       { (Test-Prop $finding 'detail') -eq $false }
Check "finding: unknown field absent" { (Test-Prop $finding 'nope') -eq $false }

# --- null and empty inputs must never throw --------------------------------
Check "null object is handled"        { $null -eq (Get-Prop $null 'anything') }
Check "empty string counts as absent" {
    $o = '{"evidence":""}' | ConvertFrom-Json
    (Test-Prop $o 'evidence') -eq $false
}
Check "empty array counts as absent" {
    $o = '{"findings":[]}' | ConvertFrom-Json
    (Test-Prop $o 'findings') -eq $false
}
Check "zero is a real value, not absence" {
    $o = '{"line":0}' | ConvertFrom-Json
    (Get-Prop $o 'line') -eq 0
}

# --- argument quoting, which reaches the engine ----------------------------
Check "plain argument is not quoted" { (ConvertTo-ArgumentString @("simple")) -eq "simple" }
Check "path with spaces is quoted"   { (ConvertTo-ArgumentString @("C:\Project Stark\x")) -eq '"C:\Project Stark\x"' }
Check "several arguments joined"     { (ConvertTo-ArgumentString @("-out","a b.json")) -eq '-out "a b.json"' }

# --- source guard ----------------------------------------------------------
# The helpers above only protect the interface if the interface actually uses
# them. This checks the source directly, so reintroducing the unsafe pattern
# fails the build rather than waiting for a user to hit a clean scan.
Check "source contains no unguarded property probes" {
    -not ($src -match [regex]::Escape("PSObject.Properties.Name"))
}

Check "source sets StrictMode (these guards assume it)" {
    $src -match "Set-StrictMode"
}

Write-Host ("-" * 58)
if ($script:Failed -eq 0) {
    Write-Host ("{0} checks passed" -f $script:Ran) -ForegroundColor Green
    exit 0
} else {
    Write-Host ("{0} of {1} checks FAILED" -f $script:Failed, $script:Ran) -ForegroundColor Red
    exit 1
}

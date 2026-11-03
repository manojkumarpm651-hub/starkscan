<#
.SYNOPSIS
    Builds starkscan and packages it for distribution to other machines.

.DESCRIPTION
    Produces one self-contained archive per platform in dist/. Each archive
    unpacks to a single folder holding the binary, the documentation a
    recipient needs, and checksums for its own contents. Nothing inside
    depends on Go, on a C toolchain, or on this source tree.

    Build flags used, and why:
      -trimpath   strips the build machine's absolute paths out of the binary.
                  Without it, "C:\Users\<you>\..." is embedded in every panic
                  trace and shipped to whoever receives the binary.
      -s -w       drops the symbol table and DWARF debug info, roughly halving
                  the binary. Panic stack traces still name functions.
      -X main...  stamps the version and build date so a report can identify
                  exactly which build produced it.
      CGO_ENABLED=0  keeps the result a genuinely static binary with no libc
                  dependency, so it runs on any machine of that OS/arch.

.PARAMETER Version
    Version string to stamp in and to name the archives with.

.PARAMETER All
    Also cross-compile for Linux and macOS. Go cross-compiles without any
    additional toolchain, so this needs nothing installed.

.PARAMETER NoArchive
    Leave the staged folders in place and skip archive creation. Useful when
    you only want a local build.

.PARAMETER ShareDir
    Also publish the archives, their checksums, and a sender's note into this
    folder, removing any older starkscan packages found there first. Shipping
    a stale build of a security tool is worse than shipping none, so the two
    are kept in step by the build rather than by hand.

.EXAMPLE
    .\build.ps1
    .\build.ps1 -Version 1.2.1 -All
#>
[CmdletBinding()]
param(
    [string]$Version = "1.2.1",
    [switch]$All,
    [switch]$NoArchive,

    # Copy the finished archives into a folder you can hand to someone,
    # replacing any older packages already sitting there.
    [string]$ShareDir = ""
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

# Find Go even when it is not on PATH for this shell.
$go = "go"
if (-not (Get-Command $go -ErrorAction SilentlyContinue)) {
    $candidate = "C:\Program Files\Go\bin\go.exe"
    if (Test-Path -LiteralPath $candidate) {
        $go = $candidate
    } else {
        throw "Go toolchain not found. Install it from https://go.dev/dl/ or add go to PATH."
    }
}

$buildDate = (Get-Date -Format "yyyy-MM-dd")
$ldflags = "-s -w -X main.version=$Version -X main.buildDate=$buildDate"
$dist = Join-Path $PSScriptRoot "dist"
$docs = Join-Path $PSScriptRoot "packaging"

if (Test-Path -LiteralPath $dist) { Remove-Item -LiteralPath $dist -Recurse -Force }
New-Item -ItemType Directory -Path $dist -Force | Out-Null

Write-Host "starkscan $Version  ($buildDate)" -ForegroundColor Cyan
Write-Host ("-" * 58)

# Gate the release on the checks passing. A security tool that ships without
# its own tests passing is not worth the trust it asks for.
Write-Host "vet   ... " -NoNewline
& $go vet ./...
if ($LASTEXITCODE -ne 0) { throw "go vet failed; not building a release." }
Write-Host "ok" -ForegroundColor Green

Write-Host "test  ... " -NoNewline
& $go test ./... | Out-Null
if ($LASTEXITCODE -ne 0) { throw "tests failed; not building a release." }
Write-Host "ok" -ForegroundColor Green

# The interface has its own checks. They gate the release too: a fault there
# reaches a user just as surely as a fault in the engine.
$selftest = Join-Path $PSScriptRoot "gui\gui-selftest.ps1"
if (Test-Path -LiteralPath $selftest) {
    Write-Host "gui   ... " -NoNewline
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $selftest | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "GUI self-test failed; not building a release." }
    Write-Host "ok" -ForegroundColor Green
}

$targets = @(
    @{ OS = "windows"; Arch = "amd64"; Ext = ".exe" }
)
if ($All) {
    $targets += @{ OS = "linux";  Arch = "amd64"; Ext = "" }
    $targets += @{ OS = "linux";  Arch = "arm64"; Ext = "" }
    $targets += @{ OS = "darwin"; Arch = "arm64"; Ext = "" }
}

# Documentation is templated so a package can never claim a version or a build
# date other than the one it actually contains.
#
# Written without a byte-order mark: PowerShell's utf8 encoding adds one, and
# on Linux and macOS that renders as stray characters at the top of the file.
# Line endings follow the target platform.
function Copy-Doc {
    param([string]$Name, [string]$Destination, [string]$TargetOS)
    $src = Join-Path $docs $Name
    if (-not (Test-Path -LiteralPath $src)) { throw "missing packaging doc: $src" }

    $text = (Get-Content -LiteralPath $src -Raw).
        Replace("__VERSION__", $Version).
        Replace("__BUILDDATE__", $buildDate)

    $text = $text.Replace("`r`n", "`n")
    if ($TargetOS -eq "windows") { $text = $text.Replace("`n", "`r`n") }

    $noBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText((Join-Path $Destination $Name), $text, $noBom)
}

$stageRoot = Join-Path $dist "_stage"
New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null
$made = @()

$env:CGO_ENABLED = "0"
foreach ($t in $targets) {
    $name  = "starkscan-$Version-$($t.OS)-$($t.Arch)"
    $stage = Join-Path $stageRoot $name
    New-Item -ItemType Directory -Path $stage -Force | Out-Null

    Write-Host "build ... $name " -NoNewline
    $env:GOOS = $t.OS
    $env:GOARCH = $t.Arch
    # The binary keeps the plain name inside the package; the platform is
    # already in the archive name, and scripts should not have to care.
    & $go build -trimpath -ldflags $ldflags -o (Join-Path $stage "starkscan$($t.Ext)") ./cmd/starkscan
    if ($LASTEXITCODE -ne 0) { throw "build failed for $($t.OS)/$($t.Arch)" }

    Copy-Doc "README.txt"      $stage $t.OS
    Copy-Doc "LIMITATIONS.txt" $stage $t.OS

    # The desktop interface is Windows-only. It stays a separate process
    # driving the same engine, so a fault in it cannot change what a scan
    # reads - but the launcher sits at the top of the package, because that
    # is what someone opening the folder will click.
    if ($t.OS -eq "windows") {
        $guiSrc = Join-Path $PSScriptRoot "gui"
        if (Test-Path -LiteralPath $guiSrc) {
            Write-Host "+gui " -NoNewline
            # -H windowsgui gives the launcher no console, so opening the app
            # does not flash a black window first.
            & $go build -trimpath -ldflags "$ldflags -H windowsgui" `
                        -o (Join-Path $stage "starkscan-gui.exe") ./cmd/starkscan-gui
            if ($LASTEXITCODE -ne 0) { throw "GUI launcher build failed" }

            $guiDst = Join-Path $stage "gui"
            New-Item -ItemType Directory -Path $guiDst -Force | Out-Null
            Copy-Item -LiteralPath (Join-Path $guiSrc "starkscan-gui.ps1") -Destination $guiDst -Force
            Copy-Item -LiteralPath (Join-Path $guiSrc "starkscan-gui.cmd") -Destination $guiDst -Force
            # No second copy of the engine: the interface resolves it one
            # directory up, which is where the package already puts it.
        }
    }

    # Checksums of this package's own payload, so a recipient can verify the
    # contents after extracting, not just the archive they downloaded.
    $inner = Join-Path $stage "SHA256SUMS.txt"
    $sums = @()
    Get-ChildItem -LiteralPath $stage -File -Recurse |
        Where-Object { $_.Name -ne "SHA256SUMS.txt" } |
        ForEach-Object {
            "{0}  {1}" -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower(),
                          $_.FullName.Substring($stage.Length + 1).Replace('\', '/')
        } | ForEach-Object { $sums += $_ }
    $sumText = ($sums -join "`n") + "`n"
    if ($t.OS -eq "windows") { $sumText = $sumText.Replace("`n", "`r`n") }
    [System.IO.File]::WriteAllText($inner, $sumText, (New-Object System.Text.UTF8Encoding($false)))

    $sizeMB = [math]::Round(((Get-ChildItem -LiteralPath $stage -File -Recurse | Measure-Object Length -Sum).Sum) / 1MB, 1)
    Write-Host "ok (${sizeMB} MB)" -ForegroundColor Green
    $made += @{ Name = $name; Stage = $stage; OS = $t.OS }
}
Remove-Item Env:\GOOS, Env:\GOARCH, Env:\CGO_ENABLED -ErrorAction SilentlyContinue

if (-not $NoArchive) {
    foreach ($m in $made) {
        Write-Host "pack  ... $($m.Name) " -NoNewline
        if ($m.OS -eq "windows") {
            # Zip is what a Windows recipient can open with no extra tool.
            $out = Join-Path $dist "$($m.Name).zip"
            Compress-Archive -Path $m.Stage -DestinationPath $out -CompressionLevel Optimal -Force
        } else {
            # The tar bundled with Windows cannot set entry modes, which would
            # ship a non-executable binary. tools/mktarball sets 0755 on the
            # binary, 0644 on the docs, and fixes ownership and timestamps so
            # the archive is reproducible.
            $out = Join-Path $dist "$($m.Name).tar.gz"
            & $go run ./tools/mktarball -out $out -root $stageRoot -name $m.Name -exec "starkscan"
            if ($LASTEXITCODE -ne 0) { throw "mktarball failed for $($m.Name)" }
        }
        $mb = [math]::Round((Get-Item -LiteralPath $out).Length / 1MB, 1)
        Write-Host "ok (${mb} MB)" -ForegroundColor Green
    }
    Remove-Item -LiteralPath $stageRoot -Recurse -Force
}

# Checksums of the archives themselves, for the transfer.
#
# Written LF-terminated and without a byte-order mark, because this file is
# meant to be consumed by "sha256sum -c" on the receiving machine. A BOM makes
# the first line unparseable and CRLF appends a stray carriage return to every
# filename, which makes the verification a recipient is asked to perform fail
# on every entry.
$sumFile = Join-Path $dist "SHA256SUMS.txt"
$outerSums = @()
Get-ChildItem -LiteralPath $dist -File |
    Where-Object { $_.Name -ne "SHA256SUMS.txt" } |
    ForEach-Object { $outerSums += "{0}  {1}" -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name }
[System.IO.File]::WriteAllText($sumFile, (($outerSums -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))

Write-Host ("-" * 58)
Write-Host "Output: $dist" -ForegroundColor Cyan
Get-Content -LiteralPath $sumFile | ForEach-Object { Write-Host "  $_" }
if ($ShareDir -and -not $NoArchive) {
    $share = $ShareDir
    if (-not [System.IO.Path]::IsPathRooted($share)) { $share = Join-Path $PSScriptRoot $share }
    New-Item -ItemType Directory -Path $share -Force | Out-Null

    # Clear only this tool's own packages. An older archive left beside a new
    # one is a real hazard: the wrong version gets sent, and its version
    # string will not match the fixes the sender believes are in it.
    Get-ChildItem -LiteralPath $share -File |
        Where-Object { $_.Name -like "starkscan-*.zip" -or $_.Name -like "starkscan-*.tar.gz" } |
        Remove-Item -Force

    Get-ChildItem -LiteralPath $dist -File |
        Where-Object { $_.Name -like "starkscan-*" -or $_.Name -eq "SHA256SUMS.txt" } |
        Copy-Item -Destination $share -Force

    Copy-Doc "READ-ME-FIRST.txt" $share "windows"

    Write-Host ""
    Write-Host "Published to: $share" -ForegroundColor Cyan
    Get-ChildItem -LiteralPath $share -File | ForEach-Object { Write-Host ("  {0}" -f $_.Name) }
}

Write-Host ""
Write-Host "Unsigned builds. On the receiving machine:" -ForegroundColor Yellow
Write-Host "  Windows  Get-ChildItem -Recurse | Unblock-File" -ForegroundColor Yellow
Write-Host "  macOS    xattr -d com.apple.quarantine ./starkscan; chmod +x ./starkscan" -ForegroundColor Yellow
Write-Host "  Linux    chmod +x ./starkscan" -ForegroundColor Yellow

<#
.SYNOPSIS
    Pull the Argus crates from the private dev workspace into this publish repo.

.DESCRIPTION
    Development continues in D:\mcp-src. This repo is a downstream snapshot.
    Run this before cutting a release, review `git diff`, then commit.

    Only the crates listed in $Crates are copied. ghydra-rs, mcp-common,
    docs/, reports/, scripts/ and every other dev-only directory stay private.

.PARAMETER DevRoot
    Path to the private dev workspace. Defaults to D:\mcp-src.

.PARAMETER DryRun
    Show what would change without writing anything.
#>
[CmdletBinding()]
param(
    [string]$DevRoot = 'D:\mcp-src',
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$PublishRoot = $PSScriptRoot

$Crates = @(
    'argus-router',
    'argus-rs',
    'argus-engine',
    'argus-scan',
    'argus-winmem',
    'evidence-core'
)

if (-not (Test-Path "$DevRoot\crates")) {
    throw "Dev workspace not found: $DevRoot\crates"
}

foreach ($crate in $Crates) {
    $from = Join-Path $DevRoot "crates\$crate"
    $to   = Join-Path $PublishRoot "crates\$crate"

    if (-not (Test-Path $from)) {
        Write-Warning "missing in dev workspace, skipped: $crate"
        continue
    }

    if ($DryRun) {
        Write-Output "would sync: $crate"
        continue
    }

    if (Test-Path $to) { Remove-Item $to -Recurse -Force }
    Copy-Item $from -Destination $to -Recurse -Force

    # Dev-only leftovers must never reach the public repo.
    Get-ChildItem $to -Recurse -File -Include '*.bak', '*.bak-*', '*.orig', '*.rej' `
        -ErrorAction SilentlyContinue | Remove-Item -Force

    Write-Output "synced: $crate"
}

if ($DryRun) { return }

Write-Output ''
Write-Output 'Done. Next:'
Write-Output '  1. Check nothing private leaked:'
Write-Output '       git diff'
Write-Output '  2. Re-run the target-name scan (no game-specific defaults):'
Write-Output '       git grep -nEi "TW[0-9]{8}|Lin\.bin"'
Write-Output '  3. Build both architectures:'
Write-Output '       cargo build --release --target x86_64-pc-windows-msvc'
Write-Output '       cargo build --release --target i686-pc-windows-msvc'

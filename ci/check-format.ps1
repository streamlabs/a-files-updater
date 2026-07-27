#!/usr/bin/env pwsh
#requires -Version 7.0
<#
.SYNOPSIS
    Reformats the codebase in place with clang-format (Windows version).
    Based on the original bash script but adapted for Windows/PowerShell.

    This script only formats. Run ci/check-changes.ps1 afterwards to detect
    whether any files changed (that script exits 1 on a dirty working tree).

    Return codes:
    - 1 clang-format is missing or older than the required version
    - 0 formatting ran

    Usage:
    ./ci/check-format.ps1          # normal
    ./ci/check-format.ps1 -Verbose # passes --verbose to clang-format
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# Discover clang-format.
# GitHub Windows runners provide it via the Visual Studio "VC.Llvm.Clang" component (usually ~20.x).
# We accept any reasonably recent version (19+).
$CLANG_FORMAT = $null
$candidates = @('clang-format-19', 'clang-format-20', 'clang-format')

foreach ($cand in $candidates) {
    if (Get-Command $cand -ErrorAction SilentlyContinue) {
        $CLANG_FORMAT = $cand
        break
    }
}

if (-not $CLANG_FORMAT -and (Get-Command clang-format -ErrorAction SilentlyContinue)) {
    $CLANG_FORMAT = 'clang-format'
}

if (-not $CLANG_FORMAT) {
    Write-Error "No clang-format found in PATH. The GitHub Windows runner should provide it via VS LLVM tools."
    exit 1
}

$versionOutput = & $CLANG_FORMAT --version 2>&1 | Out-String
if ($versionOutput -notmatch 'version (19|20|2[0-9])\.') {
    Write-Error "clang-format 19 or later is required (got: $($versionOutput.Trim())). See .clang-format."
    exit 1
}

Write-Host "Using clang-format: $CLANG_FORMAT (version: $($versionOutput.Trim()))"

# Collect source files, pruning excluded directories.
# We search only under src/ and resources/ to avoid build/ trees, root cmake, etc.
$sourceFiles = Get-ChildItem -Path src, resources -Recurse -File -Include *.h,*.hpp,*.c,*.cpp,*.m,*.mm |
    Where-Object {
        $fullPath = $_.FullName
        # Skip vendored subdirectories
        if ($fullPath -match '\\(argtable|fmt\\fmt|iostreams)\\') { return $false }
        # Skip anything under build/ or cmake/ dirs
        if ($fullPath -match '\\(build|cmake)\\') { return $false }
        return $true
    } |
    Select-Object -ExpandProperty FullName

if (-not $sourceFiles) {
    Write-Host "No source files found to format."
    exit 0
}

Write-Host "Formatting $($sourceFiles.Count) files..."

$formatArgs = @('-i', '-style=file', '-fallback-style=none')
if ($VerbosePreference -ne 'SilentlyContinue') {
    $formatArgs += '--verbose'
}

# Run in parallel (pwsh 7+). A parallel runspace does not inherit
# $ErrorActionPreference, and a native non-zero exit does not throw, so collect
# the files clang-format failed on and fail the script if there were any.
$failures = $sourceFiles | ForEach-Object -Parallel {
    $cf = $using:CLANG_FORMAT
    $args = $using:formatArgs
    & $cf @args $_
    if ($LASTEXITCODE -ne 0) { $_ }
} -ThrottleLimit ([Environment]::ProcessorCount)

if ($failures) {
    Write-Error "clang-format failed on: $($failures -join ', ')"
    exit 1
}

Write-Host "Formatting complete. Run ci/check-changes.ps1 to verify the working tree is clean."
exit 0

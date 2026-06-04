#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Runs clang-format on the codebase (Windows version).
    Based on the original bash script but adapted for Windows/PowerShell.

    Return codes:
    - 1 there are files that needed formatting (or were reformatted and dirty)
    - 0 everything looks fine

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
    Write-Warning "clang-format version may be older than expected (got: $($versionOutput.Trim())). Proceeding anyway."
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

# Run in parallel (pwsh 7+)
$sourceFiles | ForEach-Object -Parallel {
    $cf = $using:CLANG_FORMAT
    $args = $using:formatArgs
    & $cf @args $_
} -ThrottleLimit ([Environment]::ProcessorCount)

# After formatting, check if the working tree is dirty and report diffs for CI visibility
$dirty = git ls-files --modified
if ($dirty) {
    Write-Host "================================="
    Write-Host "Files were not formatted properly:"
    $dirty
    Write-Host "================================="
    Write-Host "Diffs (these are the changes that clang-format made or would make):"
    git --no-pager diff --no-color -- $dirty
    Write-Host "================================="
    exit 1
}

Write-Host "All files are properly formatted."
exit 0

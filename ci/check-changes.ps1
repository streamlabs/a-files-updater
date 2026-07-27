#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Checks whether any files are modified (typically after running a formatter).
    If dirty files are found, prints them + the diff and exits 1.
#>

$ErrorActionPreference = 'Stop'

$dirty = git ls-files --modified

if ($dirty) {
    Write-Host "================================="
    Write-Host "Files were not formatted properly:"
    $dirty
    Write-Host "================================="
    Write-Host "Formatting changes required (see diff below):"
    git --no-pager diff --no-color
    Write-Host "================================="
    exit 1
}

exit 0

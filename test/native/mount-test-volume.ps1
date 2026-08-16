<#
.SYNOPSIS
Mounts a scratch volume whose root carries the ACE that broke the trust check
on real machines, so hook-dir-tests can cover the drive root without anyone
re-permissioning C:.

.DESCRIPTION
Every drive root grants Authenticated Users modify through an inherit-only ACE.
Materialise it onto the root itself - icacls /reset, a permissions repair tool,
an imaging step - and the inherit-only flag is lost, leaving DELETE granted to
Authenticated Users on the root. Harmless, since a volume root cannot be
renamed, but counting it against the path rejected machines that were fine.

This builds that exact shape on a small VHD. Run elevated.

.EXAMPLE
powershell -File mount-test-volume.ps1
build\Debug\hook-dir-tests.exe --volume-root X:\
powershell -File mount-test-volume.ps1 -Remove
#>

param(
    [string] $VhdPath = "$env:ProgramData\slobs-hook-tests\hook-test-volume.vhdx",
    [char]   $Letter  = 'X',
    [switch] $Remove
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Mounting a VHD and rewriting its root ACL needs an elevated terminal.'
}

if ($Remove) {
    if (Test-Path $VhdPath) {
        Dismount-DiskImage -ImagePath $VhdPath | Out-Null
        Remove-Item $VhdPath -Force
    }
    Write-Host "Removed $VhdPath"
    return
}

New-Item -ItemType Directory -Force (Split-Path $VhdPath) | Out-Null

if (Test-Path $VhdPath) {
    throw "$VhdPath already exists; pass -Remove first."
}

$disk = New-VHD -Path $VhdPath -SizeBytes 64MB -Dynamic |
        Mount-VHD -Passthru |
        Initialize-Disk -PartitionStyle GPT -PassThru

$disk | New-Partition -UseMaximumSize -DriveLetter $Letter |
        Format-Volume -FileSystem NTFS -NewFileSystemLabel 'hook-tests' -Confirm:$false | Out-Null

$root = "${Letter}:\"

# The default root ACE, minus the inherit-only flag that makes it harmless.
icacls $root /grant '*S-1-5-11:(OI)(CI)(M)' | Out-Null

Write-Host "Mounted $root"
Write-Host "Run: build\Debug\hook-dir-tests.exe --volume-root $root"

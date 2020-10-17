<#

.SYNOPSIS
This packages up all code and binaries needed to create a VPack package to
ingest into the Windows OS build.

.EXAMPLE
    prepare-package.ps1

#>

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Artifacts directory.
$ArtifactsDir = Join-Path $RootDir "artifacts"

# Output directory for all package files.
$PackageDir = Join-Path $ArtifactsDir "package"

function Force-Copy($Source, $Destination) {
    New-Item -Path $Destination -ItemType Directory -Force | Out-Null
    Copy-Item $Source $Destination -Force | Out-Null
}

# Package up all necessary header and manifest files.
$IncFiles = "cxplat.h", "cxplatp.h", "cxplat_winkernel.h", "cxplat_winuser.h"
foreach ($File in $IncFiles) {
    Force-Copy (Join-Path $RootDir "src/inc/$File") $PackageDir
}
Force-Copy (Join-Path $RootDir "src/tools/etwlib/CxPlatEventCollection.h") $PackageDir
Force-Copy (Join-Path $RootDir "src/manifest/CxPlat.wprp") $PackageDir
Force-Copy (Join-Path $RootDir "src/manifest/CxPlatEtw.man") $PackageDir

# Package up all the user mode binary files.
$Configs = [System.Tuple]::Create("Debug","chk"), [System.Tuple]::Create("Release","fre")
$Archs = [System.Tuple]::Create("arm","arm","arm"), [System.Tuple]::Create("arm64","arm64","arm64"), `
         [System.Tuple]::Create("x86","x86","i386"), [System.Tuple]::Create("x64","amd64","amd64")
foreach ($Config in $Configs) {
    foreach ($Arch in $Archs) {
        $InputDir = Join-Path $ArtifactsDir "bin/windows/$($Arch.Item1)_$($Config.Item1)_schannel"
        Force-Copy (Join-Path $InputDir "cxplat.lib") (Join-Path $PackageDir "lib/$($Arch.Item2)$($Config.Item2)/user")
        Force-Copy (Join-Path $InputDir "cxplat.dll") (Join-Path $PackageDir "bin/$($Arch.Item3)$($Config.Item2)/user")
        Force-Copy (Join-Path $InputDir "cxplat.pdb") (Join-Path $PackageDir "bin/$($Arch.Item3)$($Config.Item2)/user")
        Force-Copy (Join-Path $InputDir "cxplattest.exe") (Join-Path $PackageDir "bin/$($Arch.Item3)$($Config.Item2)/user")
        Force-Copy (Join-Path $InputDir "cxplattest.pdb") (Join-Path $PackageDir "bin/$($Arch.Item3)$($Config.Item2)/user")
    }
}

# Package up all the kernel mode binary files.
$Configs = [System.Tuple]::Create("Debug","chk"), [System.Tuple]::Create("Release","fre")
$Archs = [System.Tuple]::Create("ARM","arm","arm"), [System.Tuple]::Create("ARM64","arm64","arm64"), `
         [System.Tuple]::Create("Win32","x86","i386"), [System.Tuple]::Create("x64","amd64","amd64")
foreach ($Config in $Configs) {
    foreach ($Arch in $Archs) {
        $InputDir = Join-Path $ArtifactsDir "bin/winkernel/$($Arch.Item1)_$($Config.Item1)_schannel"
        Force-Copy (Join-Path $InputDir "cxplat.lib") (Join-Path $PackageDir "lib/$($Arch.Item2)$($Config.Item2)/kernel")
        Force-Copy (Join-Path $InputDir "cxplat.sys") (Join-Path $PackageDir "bin/$($Arch.Item3)$($Config.Item2)/kernel")
        Force-Copy (Join-Path $InputDir "cxplattest.sys") (Join-Path $PackageDir "bin/$($Arch.Item3)$($Config.Item2)/kernel")
        Force-Copy (Join-Path $InputDir "cxplat.pdb") (Join-Path $PackageDir "bin/$($Arch.Item3)$($Config.Item2)/kernel")
        Force-Copy (Join-Path $InputDir "cxplattest.pdb") (Join-Path $PackageDir "bin/$($Arch.Item3)$($Config.Item2)/kernel")
    }
}

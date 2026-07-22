[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,

    [Parameter(Mandatory)]
    [string]$ReleaseUrl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PublishedHash {
    param(
        [Parameter(Mandatory)] [string]$ChecksumText,
        [Parameter(Mandatory)] [string]$FileName
    )

    $pattern = "(?im)^([0-9a-f]{64})\s+\*?$([regex]::Escape($FileName))\s*$"
    $match = [regex]::Match($ChecksumText, $pattern)
    if (-not $match.Success) {
        throw "checksums.txt does not contain an SHA-256 entry for $FileName."
    }
    return $match.Groups[1].Value.ToUpperInvariant()
}

function Assert-PortableArchive {
    param([Parameter(Mandatory)] [string]$Path)

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $entryNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $credentialExecutables = 0
        $executableExtensions = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]@('.exe', '.com', '.bat', '.cmd', '.ps1', '.msi', '.msix', '.scr'),
            [System.StringComparer]::OrdinalIgnoreCase
        )

        foreach ($entry in $archive.Entries) {
            $entryName = $entry.FullName
            $normalizedName = $entryName.Replace('\', '/')
            if ([string]::IsNullOrWhiteSpace($entryName)) {
                throw "Archive contains an empty entry name: $Path"
            }
            if ($entryName.StartsWith('/') -or $entryName.StartsWith('\') -or $entryName -match '^[A-Za-z]:[\\/]') {
                throw "Archive contains an absolute path entry '$entryName': $Path"
            }

            $components = @($entryName -split '[\\/]')
            if ($components -contains '..') {
                throw "Archive contains a traversal entry '$entryName': $Path"
            }
            if (-not $entryNames.Add($normalizedName)) {
                throw "Archive contains a duplicate entry name '$entryName': $Path"
            }

            $leafName = $components[-1]
            if ($leafName -ieq 'credscope.exe') {
                $credentialExecutables++
                if ($normalizedName -cne 'credscope.exe') {
                    throw "credscope.exe must be the single root archive executable: $Path"
                }
            }

            $extension = [System.IO.Path]::GetExtension($leafName)
            if ($executableExtensions.Contains($extension) -and $normalizedName -cne 'credscope.exe') {
                throw "Archive contains an unexpected executable entry '$entryName': $Path"
            }
        }

        if ($credentialExecutables -ne 1) {
            throw "Archive must contain exactly one root credscope.exe entry: $Path"
        }
    } finally {
        $archive.Dispose()
    }
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$releaseBase = "https://github.com/Bavlik/CredScope/releases/download/v$Version"
if ($ReleaseUrl -cne $releaseBase) {
    throw "ReleaseUrl must be exactly '$releaseBase'."
}
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("credscope-winget-" + [guid]::NewGuid().ToString('N'))
$manifestDirectory = Join-Path $repositoryRoot "packaging/winget/Bavlik.CredScope/$Version"

$artifacts = @(
    [pscustomobject]@{ Architecture = 'x64'; FileName = "credscope_${Version}_windows_amd64.zip"; Url = ''; Path = ''; Hash = '' },
    [pscustomobject]@{ Architecture = 'arm64'; FileName = "credscope_${Version}_windows_arm64.zip"; Url = ''; Path = ''; Hash = '' }
)

New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
try {
    $checksumPath = Join-Path $temporaryRoot 'checksums.txt'
    Invoke-WebRequest -Uri "$releaseBase/checksums.txt" -OutFile $checksumPath -UseBasicParsing
    $checksumText = Get-Content -LiteralPath $checksumPath -Raw

    foreach ($artifact in $artifacts) {
        $artifact.Url = "$releaseBase/$($artifact.FileName)"
        $artifact.Path = Join-Path $temporaryRoot $artifact.FileName
        Invoke-WebRequest -Uri $artifact.Url -OutFile $artifact.Path -UseBasicParsing
        Assert-PortableArchive -Path $artifact.Path

        $artifact.Hash = (Get-FileHash -LiteralPath $artifact.Path -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($artifact.Hash -notmatch '^[0-9A-F]{64}$') {
            throw "Could not calculate a valid SHA-256 hash for $($artifact.FileName)."
        }
        $publishedHash = Get-PublishedHash -ChecksumText $checksumText -FileName $artifact.FileName
        if ($artifact.Hash -ne $publishedHash) {
            throw "Downloaded artifact hash does not match checksums.txt: $($artifact.FileName)"
        }
    }

    $x64 = $artifacts | Where-Object Architecture -eq 'x64'
    $arm64 = $artifacts | Where-Object Architecture -eq 'arm64'
    $stagedDirectory = Join-Path $temporaryRoot 'manifests'
    New-Item -ItemType Directory -Path $stagedDirectory | Out-Null

    $versionManifest = @"
# yaml-language-server: `$schema=https://aka.ms/winget-manifest.version.1.12.0.schema.json

PackageIdentifier: Bavlik.CredScope
PackageVersion: $Version
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.12.0
"@

    $installerManifest = @"
# yaml-language-server: `$schema=https://aka.ms/winget-manifest.installer.1.12.0.schema.json

PackageIdentifier: Bavlik.CredScope
PackageVersion: $Version
InstallerType: zip
NestedInstallerType: portable
Commands:
  - credscope
Installers:
  - Architecture: x64
    NestedInstallerFiles:
      - RelativeFilePath: credscope.exe
        PortableCommandAlias: credscope
    InstallerUrl: $($x64.Url)
    InstallerSha256: $($x64.Hash)
  - Architecture: arm64
    NestedInstallerFiles:
      - RelativeFilePath: credscope.exe
        PortableCommandAlias: credscope
    InstallerUrl: $($arm64.Url)
    InstallerSha256: $($arm64.Hash)
ManifestType: installer
ManifestVersion: 1.12.0
"@

    $localeManifest = @"
# yaml-language-server: `$schema=https://aka.ms/winget-manifest.defaultLocale.1.12.0.schema.json

PackageIdentifier: Bavlik.CredScope
PackageVersion: $Version
PackageLocale: en-US
Publisher: Abdallah Alotaibi
PublisherUrl: https://github.com/Bavlik
PublisherSupportUrl: https://github.com/Bavlik/CredScope/security/advisories/new
Author: Abdallah Alotaibi
PackageName: CredScope
PackageUrl: https://github.com/Bavlik/CredScope
License: Apache-2.0
LicenseUrl: https://github.com/Bavlik/CredScope/blob/main/LICENSE
Copyright: Copyright 2026 Abdallah Alotaibi
ShortDescription: CredScope is a deterministic, offline-first static credential exposure and reachability analyzer for Docker Compose and GitHub Actions.
Description: CredScope analyzes Docker Compose and GitHub Actions configuration and imported Gitleaks findings without executing repository content or validating credentials.
Moniker: credscope
Tags:
  - cli
  - docker-compose
  - github-actions
  - security
  - static-analysis
InstallationNotes: CredScope v$Version is unsigned. Verify published SHA-256 checksums and do not disable Windows security controls.
ManifestType: defaultLocale
ManifestVersion: 1.12.0
"@

    $utf8 = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText((Join-Path $stagedDirectory 'Bavlik.CredScope.yaml'), $versionManifest.Replace("`r`n", "`n"), $utf8)
    [System.IO.File]::WriteAllText((Join-Path $stagedDirectory 'Bavlik.CredScope.installer.yaml'), $installerManifest.Replace("`r`n", "`n"), $utf8)
    [System.IO.File]::WriteAllText((Join-Path $stagedDirectory 'Bavlik.CredScope.locale.en-US.yaml'), $localeManifest.Replace("`r`n", "`n"), $utf8)

    New-Item -ItemType Directory -Force -Path $manifestDirectory | Out-Null
    foreach ($file in Get-ChildItem -LiteralPath $stagedDirectory -File) {
        Move-Item -LiteralPath $file.FullName -Destination (Join-Path $manifestDirectory $file.Name) -Force
    }

    Write-Host "WinGet manifests updated in $manifestDirectory"
    Write-Host "Validate locally: winget validate --manifest `"$manifestDirectory`""
    Write-Host 'No WinGet submission or pull request was performed.'
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        $resolvedTemp = (Resolve-Path -LiteralPath $temporaryRoot).Path
        $systemTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
        $tempPrefix = $systemTemp + [System.IO.Path]::DirectorySeparatorChar
        if (-not $resolvedTemp.StartsWith($tempPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to clean unexpected temporary path: $resolvedTemp"
        }
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
    }
}

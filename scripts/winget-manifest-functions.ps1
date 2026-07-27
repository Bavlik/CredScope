# Shared, side-effect-free helper functions for WinGet manifest preparation.
# This file intentionally has no top-level parameters so it can be dot-sourced
# safely by scripts/update-winget-manifest.ps1 and by tests, without
# triggering interactive prompts or network access.

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

# Resolve-PortableExecutableRelativePath inspects a portable ZIP archive and
# returns the forward-slash archive-relative path of the single credscope.exe
# entry it contains. It does not assume any particular archive layout: the
# executable may sit at the archive root (historical flat archives) or inside
# a wrapping directory (archives produced after the GoReleaser
# wrap_in_directory change introduced in CHANGELOG [0.2.1]).
function Resolve-PortableExecutableRelativePath {
    param(
        [Parameter(Mandatory)] [string]$Path
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem

    try {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
    } catch {
        throw "Archive could not be opened or validated: $Path ($($_.Exception.Message))"
    }

    try {
        $entryNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $executableExtensions = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]@('.exe', '.com', '.bat', '.cmd', '.ps1', '.msi', '.msix', '.scr'),
            [System.StringComparer]::OrdinalIgnoreCase
        )
        $executablePath = $null

        foreach ($entry in $archive.Entries) {
            $entryName = $entry.FullName
            if ([string]::IsNullOrWhiteSpace($entryName)) {
                throw "Archive contains an empty entry name: $Path"
            }

            $normalizedName = $entryName.Replace('\', '/')
            if ($normalizedName.StartsWith('/') -or $normalizedName -match '^[A-Za-z]:/') {
                throw "Archive contains an absolute path entry '$entryName': $Path"
            }

            $components = @($normalizedName -split '/')
            if ($components -contains '..') {
                throw "Archive contains a traversal entry '$entryName': $Path"
            }

            if (-not $entryNames.Add($normalizedName)) {
                throw "Archive contains a duplicate entry name '$entryName': $Path"
            }

            $leafName = $components[-1]
            $isCredscopeExe = $leafName -ieq 'credscope.exe'
            if ($isCredscopeExe) {
                if ($executablePath) {
                    throw "Archive contains more than one credscope.exe entry: $Path"
                }
                $executablePath = $normalizedName
            }

            $extension = [System.IO.Path]::GetExtension($leafName)
            if ($executableExtensions.Contains($extension) -and -not $isCredscopeExe) {
                throw "Archive contains an unexpected executable entry '$entryName': $Path"
            }
        }

        if (-not $executablePath) {
            throw "Archive does not contain credscope.exe: $Path"
        }
        if ($executablePath.StartsWith('/') -or $executablePath -match '^[A-Za-z]:/') {
            throw "Resolved credscope.exe path is absolute: $Path"
        }
        if (@($executablePath -split '/') -contains '..') {
            throw "Resolved credscope.exe path contains path traversal: $Path"
        }

        return $executablePath
    } finally {
        $archive.Dispose()
    }
}

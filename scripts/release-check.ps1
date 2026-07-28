[CmdletBinding()]
param(
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version = '0.2.3',

    [ValidateNotNullOrEmpty()]
    [string]$ExpectedBranch = 'main',

    [string]$GoReleaserPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string[]]$ArgumentList
    )

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($ArgumentList -join ' ')"
    }
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $repositoryRoot
try {
    $gitRoot = (& git rev-parse --show-toplevel).Trim()
    if ($LASTEXITCODE -ne 0 -or (Resolve-Path $gitRoot).Path -ne $repositoryRoot) {
        throw 'The script must run from the CredScope repository.'
    }

    $worktree = & git status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not inspect the Git working tree.'
    }
    if ($worktree) {
        throw "The Git working tree is not clean:`n$($worktree -join "`n")"
    }

    $branch = (& git branch --show-current).Trim()
    if ($LASTEXITCODE -ne 0 -or $branch -ne $ExpectedBranch) {
        throw "Expected branch '$ExpectedBranch', found '$branch'."
    }

    $versionFile = (Get-Content -LiteralPath 'VERSION' -Raw).Trim()
    if ($versionFile -ne $Version) {
        throw "VERSION contains '$versionFile'; expected '$Version'."
    }

    # WinGet manifests are deliberately NOT required here. They can only be
    # generated after this version's GitHub Release archives are published
    # and their real SHA-256 checksums exist (scripts/update-winget-manifest.ps1
    # downloads them), which happens after tagging -- not before. Requiring
    # packaging/winget/Bavlik.CredScope/$Version/*.yaml at this pre-tag stage
    # made it impossible to ever pass this check for a version that hasn't
    # been released yet. See docs/RELEASING.md for the full release order.
    $requiredFiles = @(
        'LICENSE',
        'NOTICE',
        'README.md',
        'SECURITY.md',
        'CHANGELOG.md',
        'docs/ARCHITECTURE.md',
        'docs/CONFIGURATION.md',
        'docs/RELEASING.md',
        'docs/RULES.md',
        'docs/SCORING.md',
        'docs/THREAT_MODEL.md'
    )
    foreach ($requiredFile in $requiredFiles) {
        if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
            throw "Required release file is missing: $requiredFile"
        }
    }

    # CHANGELOG.md headings use the plain semantic version ("## [0.2.3] -
    # 2026-07-27"), never a "v"-prefixed form, so the check must match that
    # real heading shape instead of looking for the literal text "v0.2.3".
    if ((Get-Content -LiteralPath 'CHANGELOG.md' -Raw) -notmatch "(?m)^## \[$([regex]::Escape($Version))\] - \d{4}-\d{2}-\d{2}\s*$") {
        throw "CHANGELOG.md does not contain a '## [$Version] - YYYY-MM-DD' heading."
    }

    & git show-ref --verify --quiet "refs/tags/v$Version"
    if ($LASTEXITCODE -eq 0) {
        throw "Local tag v$Version already exists."
    }
    if ($LASTEXITCODE -ne 1) {
        throw 'Could not inspect local tags.'
    }

    & git ls-remote --exit-code --tags origin "refs/tags/v$Version" | Out-Null
    if ($LASTEXITCODE -eq 0) {
        throw "Remote tag v$Version already exists."
    }
    if ($LASTEXITCODE -ne 2) {
        throw 'Could not verify the intended tag against origin.'
    }

    if ($GoReleaserPath) {
        $resolvedGoReleaser = (Resolve-Path -LiteralPath $GoReleaserPath).Path
    } else {
        $command = Get-Command goreleaser -ErrorAction SilentlyContinue
        if (-not $command) {
            throw 'GoReleaser is not on PATH. Install the free GoReleaser CLI or pass -GoReleaserPath.'
        }
        $resolvedGoReleaser = $command.Source
    }

    Invoke-CheckedCommand -FilePath 'go' -ArgumentList @('test', './...')
    Invoke-CheckedCommand -FilePath 'go' -ArgumentList @('vet', './...')
    Invoke-CheckedCommand -FilePath $resolvedGoReleaser -ArgumentList @('check')

    Write-Host "Release checks passed for v$Version on branch $ExpectedBranch."
    Write-Host 'No tag, release, package submission, or other remote mutation was performed.'
} finally {
    Pop-Location
}

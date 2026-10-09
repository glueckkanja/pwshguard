# Proposes updates of the PowerShell Gallery modules pinned in src/RequiredModules.psd1, which
# Dependabot cannot do. For every module whose newest stable release has been public for at
# least -CooldownDays, it commits the new pins to a branch through the GitHub API (no git
# credentials in the job), opens a pull request and starts CI on the branch.
#
# A pull request opened with the job's GITHUB_TOKEN does not trigger `pull_request` workflows;
# a `workflow_dispatch` is the exception, so CI is dispatched on the branch and reports its
# checks on the pull request's head commit.
#
# Needs GH_TOKEN and GH_REPO. -DryRun prints the planned change and touches nothing.

[CmdletBinding()]
param(
    [string]$ManifestPath = 'src/RequiredModules.psd1',
    # Days a release must have been public before it is proposed, like Dependabot's cooldown:
    # a broken or compromised release is usually pulled within that time.
    [int]$CooldownDays = 7,
    [string]$Workflow = 'ci.yml',
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

$pinned = Import-PowerShellDataFile -LiteralPath $ManifestPath
$text = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $ManifestPath).Path)
$cutoff = [DateTime]::UtcNow.AddDays(-$CooldownDays)

$updates = @(foreach ($name in @($pinned.Keys | Sort-Object)) {
        $current = [version]$pinned[$name]
        # Stable releases only (Find-Module leaves out prereleases unless asked).
        $candidate = Find-Module -Name $name -Repository PSGallery -AllVersions |
            Where-Object { $_.PublishedDate -and $_.PublishedDate.ToUniversalTime() -le $cutoff } |
            Sort-Object { [version]$_.Version } -Descending |
            Select-Object -First 1
        if (-not $candidate) { Write-Host "${name}: no release older than $CooldownDays days."; continue }
        if ([version]$candidate.Version -le $current) { Write-Host "$name $current is current."; continue }
        Write-Host "$name $current -> $($candidate.Version) (published $($candidate.PublishedDate.ToString('yyyy-MM-dd')))."
        [pscustomobject]@{
            Name      = $name
            From      = "$current"
            To        = "$($candidate.Version)"
            Published = $candidate.PublishedDate.ToString('yyyy-MM-dd')
        }
    })
if (-not $updates) {
    Write-Host 'All modules are current.'
    return
}

foreach ($u in $updates) {
    $pattern = '(?m)^(\s*{0}\s*=\s*'')[^'']*('')' -f [regex]::Escape($u.Name)
    if (-not [regex]::IsMatch($text, $pattern)) { throw "No line '$($u.Name) = '...'' in $ManifestPath." }
    $text = [regex]::Replace($text, $pattern, "`${1}$($u.To)`${2}")
}

$branch = 'update-modules/' + (($updates | ForEach-Object { "$($_.Name)-$($_.To)" }) -join '_').ToLowerInvariant()
$title = 'Update PowerShell modules: ' + (($updates | ForEach-Object { "$($_.Name) $($_.To)" }) -join ', ')
$body = @(
    "Updates the modules pinned in ``$ManifestPath``. Each release has been on the PowerShell Gallery for at least $CooldownDays days."
    ''
    '| Module | From | To | Published |'
    '| --- | --- | --- | --- |'
    $updates | ForEach-Object { "| [$($_.Name)](https://www.powershellgallery.com/packages/$($_.Name)/$($_.To)) | $($_.From) | $($_.To) | $($_.Published) |" }
    ''
    "Opened by ``update-modules.yml``. CI was started on this branch by ``workflow_dispatch``, since a pull request opened with ``GITHUB_TOKEN`` does not trigger it. A major version can change behaviour: check the release notes and the test results before merging."
) -join "`n"

if ($DryRun) {
    Write-Host "Would push branch $branch and open: $title"
    Write-Host $body
    Write-Host '--- new manifest ---'
    Write-Host $text
    return
}

$repo = $env:GH_REPO
if (-not $repo) { throw 'GH_REPO is not set.' }

# An open or closed proposal for exactly these versions already exists: nothing to do.
$existing = gh api "repos/$repo/git/matching-refs/heads/$branch" --jq "[.[] | select(.ref == `"refs/heads/$branch`")] | length"
if ($LASTEXITCODE -ne 0) { throw 'Listing branches failed.' }
if ([int]$existing -gt 0) {
    Write-Host "Branch $branch exists already; not proposing again."
    return
}

$base = gh api "repos/$repo" --jq .default_branch
if ($LASTEXITCODE -ne 0) { throw 'Reading the default branch failed.' }
$baseSha = gh api "repos/$repo/git/ref/heads/$base" --jq .object.sha
if ($LASTEXITCODE -ne 0) { throw "Reading $base failed." }
$apiPath = $ManifestPath -replace '\\', '/'
$blobSha = gh api "repos/$repo/contents/${apiPath}?ref=$base" --jq .sha
if ($LASTEXITCODE -ne 0) { throw "Reading $apiPath on $base failed." }

gh api "repos/$repo/git/refs" -f "ref=refs/heads/$branch" -f "sha=$baseSha" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Creating branch $branch failed." }
$content = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($text))
gh api -X PUT "repos/$repo/contents/$apiPath" -f "message=$title" -f "content=$content" -f "sha=$blobSha" -f "branch=$branch" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Committing $apiPath to $branch failed." }

$url = gh pr create --repo $repo --base $base --head $branch --title $title --body $body
if ($LASTEXITCODE -ne 0) { throw 'Opening the pull request failed. Is "Allow GitHub Actions to create and approve pull requests" enabled?' }
Write-Host "Opened $url"

gh workflow run $Workflow --repo $repo --ref $branch
if ($LASTEXITCODE -ne 0) { throw "Starting $Workflow on $branch failed." }
Write-Host "Started $Workflow on $branch."

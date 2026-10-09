# The PowerShell Gallery modules PwshGuard depends on, pinned to exact versions. This is the
# only place their versions are set: Invoke-PwshGuard.ps1 installs the PSScriptAnalyzer version
# below, CI installs both, and .github/workflows/update-modules.yml proposes updates.
@{
    # Runs the analysis (action and local use).
    PSScriptAnalyzer = '1.25.0'
    # Runs the tests under tests/ (CI only).
    Pester           = '6.2.0'
}

# Default PSScriptAnalyzer settings for PwshGuard. Pass your own with the action's `settings`
# input (or Invoke-PwshGuard.ps1 -Settings); the PwshGuard rules are added either way.
@{
    IncludeDefaultRules = $true

    # Style rules that do not fit CI tooling: Write-Host is how scripts emit workflow commands
    # (::group::, ::warning::), and the files are plain UTF-8. Style findings are only listed in
    # the job log; a security rule named here is not reported at all.
    ExcludeRules        = @(
        'PSAvoidUsingWriteHost'
        'PSUseBOMForUnicodeEncodedFile'
        'PSUseSingularNouns'
        'PSUseApprovedVerbs'
        'PSAvoidUsingPositionalParameters'
    )
}

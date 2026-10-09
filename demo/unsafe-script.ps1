# PwshGuard demo: deliberately unsafe PowerShell. Never executed; CI scans it to show the report.

param(
    [string]$Branch,
    [string]$Text,
    [string]$Template,
    [string]$Root,
    [string]$Name
)

# PwshGuardFailOpenScript: no $ErrorActionPreference = 'Stop' in this entry-point script.

# PwshGuardUncheckedNativeCommand: the exit code of git is never checked.
git push
Write-Host 'pushed'

# PwshGuardUnsafeWorkflowCommandFile: an outside value changes every later step,
# and a fixed delimiter lets the value end the block early.
"BRANCH=$Branch" >> $env:GITHUB_ENV
"body<<EOF`n$Text`nEOF" >> $env:GITHUB_OUTPUT

# PwshGuardSecretInOutput: a token obtained at run time is printed unmasked.
$token = az account get-access-token --query accessToken -o tsv
if ($LASTEXITCODE -ne 0) { throw 'az failed' }
Write-Host "Token: $token"

# PwshGuardDynamicCodeExecution: code built from data.
$block = [scriptblock]::Create($Template)
& $block

# PwshGuardUnpinnedModuleInstall: whatever the gallery serves today.
Install-Module Az.Accounts -Force

# PwshGuardInsecureTransport: TLS validation off, plain HTTP.
Invoke-RestMethod -Uri 'https://example.com/api' -SkipCertificateCheck
Invoke-WebRequest -Uri 'http://example.com/file.zip' -OutFile file.zip

# PwshGuardUnsafeRecursiveDelete: an empty $Name deletes all of $Root.
Remove-Item -Path "$Root/$Name" -Recurse -Force

# PSAvoidUsingConvertToSecureStringWithPlainText (built-in): a plain-text secret in the script.
$password = ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force

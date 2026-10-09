# PwshGuard

Security checks for PowerShell that runs in GitHub Actions, built on
[PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer).

PSScriptAnalyzer's own security rules cover interactive Windows administration (plain-text
password parameters, hard-coded computer names). PowerShell in a pipeline is exposed in other
ways. It holds OIDC tokens and cloud credentials, reads untrusted input (pull request text,
inputs, API and model output), writes workflow command files, and gates deployments.
[zizmor](https://github.com/zizmorcore/zizmor) checks the workflow YAML but treats a `run:`
script as text. PwshGuard parses that script as PowerShell.

> **Status:** extracted from [Workplace Foundation](https://github.com/Workplace-Foundation/workplace-foundation)
> for testing. This repository is not its final home.

## Usage

```yaml
permissions:
  contents: read
  pull-requests: write # sticky findings comment

jobs:
  pwshguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: false
      - uses: hcoberdalhoff/pwshguard@main
```

The action scans every tracked `*.ps1`, `*.psm1` and `*.psd1` file, and every `run:` block of a
`shell: pwsh` step in the repository's workflows and composite actions. It writes the report to
the job summary and, on a pull request, keeps one comment up to date. That comment lists
findings in changed files in full and collapses the rest. Findings do not fail the job unless
you set `fail-on`.

| Input | Default | Description |
| --- | --- | --- |
| `path` | all tracked PowerShell | Files or folders to scan, comma- or newline-separated |
| `workflow-path` | all tracked YAML when `path` is empty | Workflows and actions whose `shell: pwsh` steps to scan |
| `settings` | bundled | Your PSScriptAnalyzer settings file (`ExcludeRules` ...); the PwshGuard rules are added to it |
| `comment` | `true` | Post or update the pull request comment |
| `fail-on` | `none` | `none`, `changed` (findings in changed files) or `all` |
| `github-token` | `github.token` | Token used to list the pull request's files and post the comment |

Outputs: `findings`, `findings-in-changed`, `report-path`.

## Rules

| Rule | Severity | Reports |
| --- | --- | --- |
| `PwshGuardExpressionInScript` | High | A `${{ }}` expression with outside content in a `shell: pwsh` step. The runner pastes its value in before PowerShell parses the script, so pass the value through `env:` instead. Fixed contexts and `boolean`/`choice`/`number` inputs are exempt. |
| `PwshGuardUnsafeWorkflowCommandFile` | High | Writes to `$GITHUB_ENV`/`$GITHUB_PATH`, and multi-line outputs with a fixed delimiter |
| `PwshGuardDynamicCodeExecution` | High | `[scriptblock]::Create`, `ExpandString`, `AddScript`, `Add-Type` with built-up source, `bash -c`/`pwsh -Command` with data, interpolated `Start-Process` arguments |
| `PwshGuardSecretInOutput` | High | Run-time tokens that are not masked, secret-named values that are printed or thrown, transcripts |
| `PwshGuardInsecureTransport` | Medium | `-SkipCertificateCheck`, custom certificate callbacks, obsolete TLS, `http://`, `curl -k` and similar switches |
| `PwshGuardUnpinnedModuleInstall` | Medium | `Install-Module`/`Install-PSResource` without a pinned version, or with publisher checks off |
| `PwshGuardUncheckedNativeCommand` | Low | A native command (`git`, `gh`, `az`, `terraform` ...) whose exit code is never checked |
| `PwshGuardFailOpenScript` | Low | An entry-point script without `$ErrorActionPreference = 'Stop'` |
| `PwshGuardUnsafeRecursiveDelete` | Low | `Remove-Item -Recurse` on a path built from variables |

PSScriptAnalyzer's built-in security rules and any Error-severity finding are reported as well.
Style findings appear only in the job log.

### Suppressing a finding

Put the attribute on the enclosing function or the script's `param()` block:

```powershell
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PwshGuardUncheckedNativeCommand', '', Justification = 'a failed git rev-parse prints nothing, and .Trim() throws')]
param()
```

An inline step cannot open with `param()`, so it takes a comment instead. The comment covers
that rule for the whole step:

```powershell
# SuppressMessage PwshGuardUncheckedNativeCommand: gh label create fails when the label exists, which is fine
```

The pull request comment still lists a suppressed finding in a changed file, together with its
justification. To turn a rule off entirely, list it in `ExcludeRules` in your settings file.

## Local use

```powershell
Install-Module PSScriptAnalyzer -RequiredVersion 1.24.0 -Scope CurrentUser
# from the root of the repository to scan:
/path/to/pwshguard/src/Invoke-PwshGuard.ps1
```

It prints the findings and fails when there are any.

## Development

```powershell
Invoke-Pester -Path tests -Output Detailed
```

- `src/PwshGuard.psm1`: the rules. Each `Measure-PwshGuard*` function gets the file's root AST
  once.
- `src/Invoke-PwshGuard.ps1`: the runner. It extracts inline steps, applies
  `PwshGuardExpressionInScript` and writes the report.
- `tests/`: positive and negative cases for every rule, and the runner's YAML handling.
- `demo/`: deliberately unsafe code. CI scans it to show the report.

Every heuristic and every bypass found later starts as a test. CI runs the tests, scans this
repository with its own action (`fail-on: all`), and scans `demo/`.

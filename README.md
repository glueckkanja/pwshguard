# PwshGuard

Security checks for PowerShell that runs in GitHub Actions, built on
[PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer).

PSScriptAnalyzer's own security rules cover interactive Windows administration (plain-text
password parameters, hard-coded computer names). PowerShell in a pipeline is exposed in other
ways. It holds OIDC tokens and cloud credentials, reads untrusted input (pull request text,
inputs, API and model output), writes workflow command files, and gates deployments.
[zizmor](https://github.com/zizmorcore/zizmor) checks the workflow YAML but treats a `run:`
script as text. PwshGuard parses that script as PowerShell.

## What it is, and what it is not

PwshGuard helps script authors and repository maintainers. It finds the mistakes that people
writing in good faith make, for example an exit code nobody checks, a token printed to the log,
or a pull request title pasted into a script.

It does **not** protect you from malicious code. Static analysis relies on heuristics, and an
author who wants to get past them can. A command can be built from string pieces, a script can
be downloaded and run, and code can be shaped to slip past a rule. A clean report therefore says
nothing about the intent of a change. Code from untrusted contributors still needs review, and
your workflows still need their usual protections:

- least-privilege `permissions:`
- actions pinned to a commit SHA
- no secrets for pull requests from forks
- environment protection rules for deployments

For the same reason, findings do not block a merge by default. The report is meant to inform
the review, not to replace it.

To report a vulnerability in PwshGuard itself, see [SECURITY.md](SECURITY.md).

## Usage

```yaml
permissions:
  contents: read
  pull-requests: write # sticky findings comment

jobs:
  pwshguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: glueckkanja/pwshguard@v0.2.0
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

Permissions: `contents: read`. On pull requests the job also needs `pull-requests: read` to list
the changed files, or `pull-requests: write` when `comment` is on. A public repository can
list the files without it, a private one cannot.

### Limitations

- **Linux and macOS.** CI runs the action on `ubuntu-latest`. The tests and the runner also pass
  on macOS, run locally rather than as an action on a macOS runner. The rules assume a Unix
  system; for example, `ls`, `rm` and `cat` count as native programs. On Windows these are
  PowerShell aliases, so the findings differ there.
- **PowerShell Gallery access.** The action installs the pinned PSScriptAnalyzer version from the
  PowerShell Gallery when the runner does not have it. Self-hosted runners need access to it.
- **No `pull_request_target`.** Run the action under `pull_request`. Under `pull_request_target`, a
  workflow that checks out the pull request's code runs it with write access.
- **Custom rules run.** A `CustomRulePath` in your settings file is loaded by PSScriptAnalyzer,
  which executes those modules. Anyone who can change the settings file in a pull request can
  therefore run code in the scan job, just as with any CI that runs code from a pull request.
  Pull requests from forks get a read-only token.

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
# from the root of the repository to scan:
/path/to/pwshguard/src/Invoke-PwshGuard.ps1
```

It installs the pinned PSScriptAnalyzer version (`src/RequiredModules.psd1`) when it is missing,
prints the findings, and fails when there are any.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for the layout, how to make a change, what counts as the
public interface, and how versions and releases work.

## License

[MIT](LICENSE)

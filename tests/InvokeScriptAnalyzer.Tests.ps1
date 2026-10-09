#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }, PSScriptAnalyzer
# Run: pwsh -NoProfile -Command 'Invoke-Pester -Path tests -Output Detailed'
#
# Covers the runner (Invoke-PwshGuard.ps1): inline workflow scripts, the report's
# changed/elsewhere split, and the listing of suppressed findings.

BeforeAll {
    # Report paths are relative to the working directory, so run from the repository root.
    $script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $script:Runner = Join-Path $script:RepoRoot 'src/Invoke-PwshGuard.ps1'
    Push-Location $script:RepoRoot

    # The runner reads the repository settings, so the expectations follow its ExcludeRules: a rule
    # excluded there must not be reported at all, one that is not must be reported as usual.
    $script:Excluded = @((Import-PowerShellDataFile (Join-Path $script:RepoRoot 'src/PSScriptAnalyzerSettings.psd1')).ExcludeRules)
    function Assert-Finding([string]$Text, [string]$Rule, [string]$Pattern) {
        if ($Rule -in $script:Excluded) { $Text | Should -Not -Match "``$Rule``" }
        else { $Text | Should -Match $Pattern }
    }

    $script:Scripts = Join-Path $TestDrive 'scripts'
    $script:Workflow = Join-Path $TestDrive 'ci.yml'
    New-Item -ItemType Directory $script:Scripts | Out-Null

    [System.IO.File]::WriteAllText((Join-Path $script:Scripts 'push.ps1'), @'
$ErrorActionPreference = 'Stop'
git push
Write-Host done
'@)
    [System.IO.File]::WriteAllText((Join-Path $script:Scripts 'show.ps1'), @'
function Show-Password {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PwshGuardSecretInOutput', '', Justification = 'shown once on purpose')]
    param($accessToken)
    Write-Host $accessToken
}
'@)
    # Line numbers matter: the assertions below name them.
    [System.IO.File]::WriteAllText($script:Workflow, @'
jobs:
  build:
    steps:
      - name: Bash is not scanned
        run: |
          rm -rf "$a/$b"
          echo "X=1" >> $GITHUB_ENV

      - name: Shell after run
        run: |
          $v = '${{ inputs.value }}'

          "X=$v" | Add-Content $env:GITHUB_ENV
          git push
        shell: pwsh

      - name: Shell before run
        shell: pwsh
        env:
          A: b
        run: |
          git fetch
          git status --short

      - shell: pwsh
        run: git status

      - name: Expression from a fixed context
        shell: pwsh
        run: Write-Host '${{ github.repository }}' "${{ format('{0}/x', github.server_url) }}"
'@)

    # The unsuppressed findings in the files above, before ExcludeRules.
    $script:Expected = @(
        [pscustomobject]@{ File = 'push.ps1'; Rule = 'PwshGuardUncheckedNativeCommand' }
        [pscustomobject]@{ File = 'ci.yml'; Rule = 'PwshGuardExpressionInScript' }
        [pscustomobject]@{ File = 'ci.yml'; Rule = 'PwshGuardUnsafeWorkflowCommandFile' }
        [pscustomobject]@{ File = 'ci.yml'; Rule = 'PwshGuardUncheckedNativeCommand' }
    ) | Where-Object { $_.Rule -notin $script:Excluded }

    function Get-Relative([string]$Path) {
        [System.IO.Path]::GetRelativePath($script:RepoRoot, $Path) -replace '\\', '/'
    }
    function Invoke-Runner {
        param([string[]]$ChangedFile = @(), [switch]$NoWorkflow)
        $report = Join-Path $TestDrive 'report.md'
        $arguments = @{ Path = $script:Scripts; ReportPath = $report; ChangedFile = $ChangedFile }
        if (-not $NoWorkflow) { $arguments.WorkflowPath = $script:Workflow }
        & $script:Runner @arguments 6>$null | Out-Null
        [System.IO.File]::ReadAllText($report)
    }
}

AfterAll {
    Pop-Location
}

Describe 'Invoke-PwshGuard.ps1' {
    Context 'inline workflow scripts' {
        BeforeAll {
            $script:Report = Invoke-Runner
            $script:WorkflowFile = [regex]::Escape((Get-Relative $script:Workflow))
        }
        It 'reports a finding on its line in the workflow file' {
            Assert-Finding $script:Report PwshGuardUnsafeWorkflowCommandFile "$($script:WorkflowFile):13 \| ``PwshGuardUnsafeWorkflowCommandFile``"
        }
        It 'finds the shell key before and after the run key' {
            Assert-Finding $script:Report PwshGuardUncheckedNativeCommand "$($script:WorkflowFile):22 \| ``PwshGuardUncheckedNativeCommand``"
        }
        It 'treats the last native command of a step as checked by the runner' {
            $script:Report | Should -Not -Match "$($script:WorkflowFile):(14|26) \|"
        }
        It 'does not report a pwsh step as failing open' {
            $script:Report | Should -Not -Match "$($script:WorkflowFile):\d+ \| ``PwshGuardFailOpenScript``"
        }
        It 'skips steps that run under another shell' {
            $script:Report | Should -Not -Match "$($script:WorkflowFile):[5-7] \|"
        }
        It 'reports an expression from an untrusted context on its line' {
            Assert-Finding $script:Report PwshGuardExpressionInScript "$($script:WorkflowFile):11 \| ``PwshGuardExpressionInScript`` \| \$\{\{ inputs.value \}\} is pasted"
        }
        It 'does not report an expression that reads only fixed contexts' {
            $script:Report | Should -Not -Match "$($script:WorkflowFile):30 \|"
        }
        It 'scans no workflow when only -Path is given' {
            Invoke-Runner -NoWorkflow | Should -Not -Match $script:WorkflowFile
        }
    }

    Context 'report' {
        It 'lists findings in changed files first and collapses the rest' {
            $report = Invoke-Runner -ChangedFile (Get-Relative (Join-Path $script:Scripts 'push.ps1'))
            $changed = @($script:Expected | Where-Object File -EQ 'push.ps1').Count
            $elsewhere = $script:Expected.Count - $changed
            if ($changed) { $report | Should -Match "$changed finding\(s\) in PowerShell changed by this pull request" }
            if ($elsewhere) { $report | Should -Match "<details><summary>$elsewhere finding\(s\) elsewhere in the repository</summary>" }
            if ($changed -and $elsewhere) { $report.IndexOf('push.ps1:2') | Should -BeLessThan $report.IndexOf('<details>') }
        }
        It 'accepts changed files as one comma-separated string' {
            $files = (Get-Relative (Join-Path $script:Scripts 'push.ps1')), (Get-Relative $script:Workflow) -join ','
            Invoke-Runner -ChangedFile $files | Should -Match "$($script:Expected.Count) finding\(s\) in PowerShell changed by this pull request"
        }
        It 'lists a suppressed finding in a changed file with its justification' {
            $report = Invoke-Runner -ChangedFile (Get-Relative (Join-Path $script:Scripts 'show.ps1'))
            $report | Should -Match 'No security findings in PowerShell changed by this pull request'
            $report | Should -Match '1 suppressed finding\(s\) in files changed by this pull request'
            $report | Should -Match 'show.ps1:4 \| `PwshGuardSecretInOutput` \| shown once on purpose'
        }
        It 'does not list suppressed findings of unchanged files' {
            Invoke-Runner | Should -Not -Match 'suppressed finding'
        }
    }

    Context 'quoted run scalars' {
        It 'analyses a quoted one-line run as the unquoted script the runner executes' {
            $workflow = Join-Path $TestDrive 'quoted.yml'
            $empty = Join-Path $TestDrive 'empty'
            New-Item -ItemType Directory $empty -Force | Out-Null
            [System.IO.File]::WriteAllText($workflow, @'
jobs:
  build:
    steps:
      - shell: pwsh
        run: 'Write-Host "$accessToken"' # comment
      - shell: pwsh
        run: "Write-Host \"#$secretValue\""
      - shell: pwsh
        run: 'Write-Host ''# not a comment'''
'@)
            $report = Join-Path $TestDrive 'quoted.md'
            & $script:Runner -Path $empty -WorkflowPath $workflow -ReportPath $report 6>$null | Out-Null
            $text = [System.IO.File]::ReadAllText($report)
            $file = [regex]::Escape((Get-Relative $workflow))
            $text | Should -Match "$($file):5 \| ``PwshGuardSecretInOutput``"
            $text | Should -Match "$($file):7 \| ``PwshGuardSecretInOutput``"
            $text | Should -Not -Match "$($file):9 \|"
        }
    }

    Context 'YAML scalar forms' {
        BeforeAll {
            function Invoke-Workflow([string]$Name, [string]$Yaml) {
                $workflow = Join-Path $TestDrive "$Name.yml"
                $empty = Join-Path $TestDrive 'empty'
                New-Item -ItemType Directory $empty -Force | Out-Null
                [System.IO.File]::WriteAllText($workflow, $Yaml)
                $report = Join-Path $TestDrive "$Name.md"
                & $script:Runner -Path $empty -WorkflowPath $workflow -ReportPath $report -ChangedFile (Get-Relative $workflow) 6>$null | Out-Null
                [pscustomobject]@{ Text = [System.IO.File]::ReadAllText($report); File = [regex]::Escape((Get-Relative $workflow)) }
            }
        }
        It 'folds a > block the way YAML does before analysing it' {
            $r = Invoke-Workflow 'folded' @'
jobs:
  build:
    steps:
      - shell: pwsh
        run: >
          bash -c
          "git checkout $branch"
'@
            $r.Text | Should -Match "$($r.File):6 \| ``PwshGuardDynamicCodeExecution``"
        }
        It 'reports an expression split across lines where it opens and keeps later lines in place' {
            $r = Invoke-Workflow 'multiline' @'
jobs:
  build:
    steps:
      - shell: pwsh
        run: |
          $v = '${{
            inputs.value }}'
          git push
          git status --short
'@
            Assert-Finding $r.Text PwshGuardExpressionInScript "$($r.File):6 \| ``PwshGuardExpressionInScript`` \| \$\{\{ inputs.value \}\} is pasted"
            Assert-Finding $r.Text PwshGuardUncheckedNativeCommand "$($r.File):8 \| ``PwshGuardUncheckedNativeCommand``"
        }
        It 'accepts inputs whose type fixes the value, in every trigger that declares them' {
            # Line numbers matter: the assertions name the run lines.
            $r = Invoke-Workflow 'typed' @'
on:
  workflow_dispatch:
    inputs:
      mode:
        type: choice
        options: [a, b]
      dry_run:
        type: boolean
      count:
        type: 'number'
      label:
        description: no type, so a string
      shared:
        type: boolean
  workflow_call:
    inputs:
      shared:
        type: string
      depth:
        type: number
jobs:
  build:
    steps:
      - shell: pwsh
        run: Write-Host '${{ inputs.mode }} ${{ github.event.inputs.dry_run }} ${{ inputs.count }} ${{ !inputs.dry_run && 'x' || '' }}'
      - shell: pwsh
        run: Write-Host '${{ inputs.depth }}'
      - shell: pwsh
        run: Write-Host '${{ inputs.label }}'
      - shell: pwsh
        run: Write-Host '${{ inputs.shared }}'
'@
            $r.Text | Should -Not -Match "$($r.File):(25|27) \|"
            Assert-Finding $r.Text PwshGuardExpressionInScript "$($r.File):29 \| ``PwshGuardExpressionInScript`` \| \$\{\{ inputs.label \}\}"
            Assert-Finding $r.Text PwshGuardExpressionInScript "$($r.File):31 \| ``PwshGuardExpressionInScript`` \| \$\{\{ inputs.shared \}\}"
        }
        It 'decodes \x and \u escapes in a double-quoted run' {
            $r = Invoke-Workflow 'escaped' @'
jobs:
  build:
    steps:
      - shell: pwsh
        run: "Write-Host \x24accessToken \u0024secretValue"
'@
            $r.Text | Should -Match "$($r.File):5 \| ``PwshGuardSecretInOutput``"
        }
        It 'honours a SuppressMessage comment in an inline step and lists its justification' {
            $r = Invoke-Workflow 'suppressed' @'
jobs:
  build:
    steps:
      - shell: pwsh
        run: |
          # SuppressMessage PwshGuardExpressionInScript: the value is a fixed choice list
          Write-Host '${{ inputs.mode }}'
'@
            $r.Text | Should -Match 'No security findings in PowerShell changed by this pull request'
            Assert-Finding $r.Text PwshGuardExpressionInScript "$($r.File):7 \| ``PwshGuardExpressionInScript`` \| the value is a fixed choice list"
        }
    }

    Context 'local use' {
        It 'fails when there are findings, and only then' {
            $count = @($script:Expected | Where-Object File -Like '*.ps1').Count
            if ($count) { { & $script:Runner -Path $script:Scripts 6>$null | Out-Null } | Should -Throw "*$count security finding*" }
            else { { & $script:Runner -Path $script:Scripts 6>$null | Out-Null } | Should -Not -Throw }
        }
        It 'succeeds when the only finding is suppressed' {
            { & $script:Runner -Path (Join-Path $script:Scripts 'show.ps1') 6>$null | Out-Null } | Should -Not -Throw
        }
    }
}

#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }, PSScriptAnalyzer
# Run: pwsh -NoProfile -Command 'Invoke-Pester -Path tests -Output Detailed'

BeforeAll {
    $script:RulePath = Join-Path $PSScriptRoot '../src/PwshGuard.psm1'

    function Get-PwshGuardFinding {
        param([string]$Code, [string]$Rule)
        @(Invoke-ScriptAnalyzer -ScriptDefinition $Code -CustomRulePath $script:RulePath |
                Where-Object RuleName -EQ $Rule)
    }
}

Describe 'PwshGuardFailOpenScript' {
    It 'treats an if that only sets preferences as preamble' {
        $code = "param([switch]`$Detail)`nif (`$Detail) { `$DebugPreference = 'Continue' } else { `$VerbosePreference = 'SilentlyContinue' }`n`$ErrorActionPreference = 'Stop'`nGet-Item x"
        Get-PwshGuardFinding -Rule PwshGuardFailOpenScript -Code $code | Should -BeNullOrEmpty
    }
    It 'treats an if that runs a command as work' {
        $code = "if (Test-Path x) { `$a = 1 }`n`$ErrorActionPreference = 'Stop'`nGet-Item x"
        Get-PwshGuardFinding -Rule PwshGuardFailOpenScript -Code $code | Should -HaveCount 1
    }
    It 'accepts a script that sets -ErrorAction on every cmdlet call' {
        $code = "Remove-Item a -Recurse -ErrorAction SilentlyContinue`nGet-Item b -EA Stop`ngit status"
        Get-PwshGuardFinding -Rule PwshGuardFailOpenScript -Code $code | Should -BeNullOrEmpty
    }
    It 'flags a script where one cmdlet call leaves -ErrorAction out' {
        Get-PwshGuardFinding -Rule PwshGuardFailOpenScript -Code "Remove-Item a -ErrorAction SilentlyContinue`nGet-Item b" | Should -HaveCount 1
        Get-PwshGuardFinding -Rule PwshGuardFailOpenScript -Code "Remove-Item a -ErrorAction SilentlyContinue`n& `$block" | Should -HaveCount 1
    }
    It 'ignores a script that runs only native commands' {
        Get-PwshGuardFinding -Rule PwshGuardFailOpenScript -Code "git fetch origin`nif (`$LASTEXITCODE) { exit 1 }`ntofu fmt -check" | Should -BeNullOrEmpty
    }
    It 'flags a native-only script that relies on $PSNativeCommandUseErrorActionPreference without Stop' {
        Get-PwshGuardFinding -Rule PwshGuardFailOpenScript -Code "`$PSNativeCommandUseErrorActionPreference = `$true`ngit push" | Should -HaveCount 1
        Get-PwshGuardFinding -Rule PwshGuardFailOpenScript -Code "`$ErrorActionPreference = 'Stop'`n`$PSNativeCommandUseErrorActionPreference = `$true`ngit push" | Should -BeNullOrEmpty
    }
    It 'flags a native-only script that also calls a .NET method' {
        Get-PwshGuardFinding -Rule PwshGuardFailOpenScript -Code "`$text = [IO.File]::ReadAllText('x')`ngit apply x" | Should -HaveCount 1
    }
    It 'flags a script that does work without Stop' {
        Get-PwshGuardFinding -Rule PwshGuardFailOpenScript -Code 'param($x) Get-Item $x' | Should -HaveCount 1
    }
    It 'accepts a script that sets Stop' {
        Get-PwshGuardFinding -Rule PwshGuardFailOpenScript -Code "param(`$x)`n`$ErrorActionPreference = 'Stop'`nGet-Item `$x" | Should -BeNullOrEmpty
    }
    It 'ignores a library that only defines functions' {
        Get-PwshGuardFinding -Rule PwshGuardFailOpenScript -Code 'function Get-Thing { Get-Item . }' | Should -BeNullOrEmpty
    }
    It 'treats an assignment that runs a command as work' {
        Get-PwshGuardFinding -Rule PwshGuardFailOpenScript -Code '$r = Invoke-RestMethod https://example.com' | Should -HaveCount 1
    }
    It 'flags Stop set only after work has started' {
        Get-PwshGuardFinding -Rule PwshGuardFailOpenScript -Code "Get-Item `$p`n`$ErrorActionPreference = 'Stop'" | Should -HaveCount 1
    }
    It 'accepts Stop given as the enum value' {
        Get-PwshGuardFinding -Rule PwshGuardFailOpenScript -Code "`$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop`nGet-Item ." | Should -BeNullOrEmpty
    }
    It 'accepts Stop set on the script scope' {
        Get-PwshGuardFinding -Rule PwshGuardFailOpenScript -Code "`$script:ErrorActionPreference = 'Stop'`nGet-Item ." | Should -BeNullOrEmpty
    }
    It 'honours SuppressMessageAttribute' {
        $code = "[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PwshGuardFailOpenScript', '', Justification = 'test')]`nparam(`$x)`nGet-Item `$x"
        Get-PwshGuardFinding -Rule PwshGuardFailOpenScript -Code $code | Should -BeNullOrEmpty
    }
}

Describe 'PwshGuardUncheckedNativeCommand' {
    It 'flags a native call with no exit-code check' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "git push`nWrite-Host done" | Should -HaveCount 1
    }
    It 'accepts $LASTEXITCODE in the next statement' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "git push`nif (`$LASTEXITCODE) { throw 'x' }" | Should -BeNullOrEmpty
    }
    It 'accepts a captured exit code that a later statement reacts to' {
        $code = "`$l = @(tofu state list)`n`$c = `$LASTEXITCODE`nWrite-Host `$l`nif (`$c -ne 0) { throw 'x' }"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -BeNullOrEmpty
    }
    It 'accepts a capture inside try that is checked after it' {
        $code = "try { `$o = gh api x; `$e = `$LASTEXITCODE } finally { Write-Host done }`nif (`$e -ne 0) { throw 'x' }"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -BeNullOrEmpty
    }
    It 'accepts an exit code returned from a script block and checked' {
        $code = "`$e = & { gh run download 1; `$LASTEXITCODE }`nif (`$e -ne 0) { Write-Host 'none' }"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -BeNullOrEmpty
    }
    It 'flags a captured exit code overwritten before the check' {
        $code = "git push`n`$c = `$LASTEXITCODE`n`$c = 0`nif (`$c) { throw 'x' }"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -HaveCount 1
    }
    It 'accepts a captured exit code checked before it is reused' {
        $code = "git push`n`$c = `$LASTEXITCODE`nif (`$c) { throw 'x' }`n`$c = 0"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -BeNullOrEmpty
    }
    It 'accepts an exit-code check after statements that leave the exit code alone' {
        $code = "git push`nWrite-Host 'pushed'`n'done' | Out-File log.txt`nif (`$LASTEXITCODE -ne 0) { throw 'x' }"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -BeNullOrEmpty
    }
    It 'flags a $? check after a statement that resets it' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "git push`nWrite-Host 'pushed'`nif (-not `$?) { throw 'x' }" | Should -HaveCount 1
    }
    It 'flags an exit-code check after a command that may run another program' {
        $code = "git push`nInvoke-Build`nif (`$LASTEXITCODE -ne 0) { throw 'x' }`ngit push`nsort x.txt`nif (`$LASTEXITCODE -ne 0) { throw 'y' }"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -HaveCount 2
    }
    It 'accepts output that a guard stops on when it is empty' {
        $code = "`$state = terragrunt state pull | ConvertFrom-Json`nif (-not `$state) { throw 'no state' }`n`$o = gh api x`nif ([string]::IsNullOrWhiteSpace(`$o)) { exit 1 }"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -BeNullOrEmpty
    }
    It 'flags an empty-output guard that does not stop, comes too late or tests something else' {
        $code = @(
            "`$a = gh api x`nif (-not `$a) { exit 0 }"
            "`$b = gh api x`n`$b = 'fallback'`nif (-not `$b) { throw 'x' }"
            "`$c = `"id: `$(gh api x)`"`nif (-not `$c) { throw 'x' }"
            "`$d = gh api x`nif (-not `$d.id) { throw 'x' }"
        ) -join "`n"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -HaveCount 4
    }
    It 'does not credit a call with the check that a later native command gets' {
        $code = "git fetch`nforeach (`$b in `$branches) { git push origin `$b; if (`$LASTEXITCODE -ne 0) { throw 'x' } }"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -HaveCount 1
        $code = "git fetch`n`$n = 1`nif (`$n) { git push; if (`$LASTEXITCODE -ne 0) { throw 'x' } }"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -HaveCount 1
    }
    It 'flags a captured exit code that nothing reacts to' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "`$l = @(tofu state list)`n`$c = `$LASTEXITCODE" | Should -HaveCount 1
    }
    It 'ignores a check inside a function that is only defined' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "git push`nfunction Later { if (`$LASTEXITCODE) { throw 'x' } }" | Should -HaveCount 1
    }
    It 'ignores a check inside a stored script block' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "git push`n`$later = { if (`$LASTEXITCODE) { throw 'x' } }" | Should -HaveCount 1
    }
    It 'ignores a check on a captured exit code inside an uncalled function' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "git push`n`$c = `$LASTEXITCODE`nfunction Test-C { if (`$c) { throw 'x' } }" | Should -HaveCount 1
    }
    It 'flags a tool that no list names' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "python build.py`nWrite-Host done" | Should -HaveCount 1
    }
    It 'flags a program run by path' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "/usr/bin/git push`n./deploy.sh`nWrite-Host done" | Should -HaveCount 2
    }
    It 'flags a program run through a variable' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "param([string]`$Tool = 'tofu')`n& `$Tool apply`nWrite-Host done" | Should -HaveCount 1
    }
    It 'ignores a script block run through a variable' {
        $code = "`$check = { Get-Item . }`n& `$check`nfunction Invoke-It([scriptblock]`$Action) { & `$Action; Write-Host done }"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -BeNullOrEmpty
    }
    It 'ignores a script run through a variable or by path' {
        $code = "`$script = Join-Path `$PSScriptRoot 'other.ps1'`n& `$script -X 1`n./other.ps1`nWrite-Host done"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -BeNullOrEmpty
    }
    It 'ignores a variable of unknown origin' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "foreach (`$c in `$checks) { & `$c; Write-Host done }" | Should -BeNullOrEmpty
    }
    It 'ignores cmdlets, aliases, functions of the file and Pester keywords' {
        $code = "function build { Get-Item . }`nbuild`nGet-ChildItem | select Name | foreach { `$_ }`nDescribe 'x' { It 'y' { 1 | Should -Be 1 } }`nWrite-Host done"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -BeNullOrEmpty
    }
    It 'flags a name that is an alias on Windows only' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "rm -rf build`nWrite-Host done" | Should -HaveCount 1
    }
    It 'accepts a check that follows the try statement the call ends' {
        $code = "try { git push } finally { Pop-Location }`nif (`$LASTEXITCODE) { throw 'x' }"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -BeNullOrEmpty
    }
    It 'accepts a check that follows the if statement whose branches end in the call' {
        $code = "if (`$id) { gh api a | Out-Null } else { gh api b | Out-Null }`nif (`$LASTEXITCODE) { throw 'x' }"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -BeNullOrEmpty
    }
    It 'flags a call inside try that is not its last statement' {
        $code = "try { git add .; git push } finally { Pop-Location }`nif (`$LASTEXITCODE) { throw 'x' }"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -HaveCount 1
    }
    It 'accepts an exit code returned to the caller' {
        $code = "function Invoke-Native([string]`$FilePath) { `$o = & `$FilePath 2>&1; return [pscustomobject]@{ ExitCode = `$LASTEXITCODE; Lines = `$o } }"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -BeNullOrEmpty
    }
    It 'flags an exit code that is only printed' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "git push`nWrite-Host `$LASTEXITCODE" | Should -HaveCount 1
    }
    It 'accepts exit with the exit code' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "git push`nexit `$LASTEXITCODE" | Should -BeNullOrEmpty
    }
    It 'accepts a || throw chain' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "tofu init || throw 'init failed'" | Should -BeNullOrEmpty
    }
    It 'accepts a || exit chain' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "tofu init || exit 1" | Should -BeNullOrEmpty
    }
    It 'flags an && chain with no check' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "git push && Write-Host ok`nWrite-Host done" | Should -HaveCount 1
    }
    It 'flags a || chain that does not stop' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "git push || Write-Host failed`nWrite-Host done" | Should -HaveCount 1
    }
    It 'accepts an && chain checked by the next statement' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "git add . && git commit -m x`nif (`$LASTEXITCODE) { throw 'x' }" | Should -BeNullOrEmpty
    }
    It 'accepts a script block handed to a wrapper that checks the exit code' {
        $code = "function Invoke-Checked([scriptblock]`$c) { & `$c; if (`$LASTEXITCODE) { throw 'x' } }`nInvoke-Checked { git fetch }"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -BeNullOrEmpty
    }
    It 'flags a script block handed to a wrapper that does not check' {
        $code = "function Invoke-Quiet([scriptblock]`$c) { & `$c }`nInvoke-Quiet { git fetch }"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -HaveCount 1
    }
    It 'flags a script block handed to an unknown command' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "Invoke-Elsewhere { git fetch }" | Should -HaveCount 1
    }
    It 'accepts a function whose every caller checks the exit code' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "function Publish { git push }`nPublish`nif (`$LASTEXITCODE) { throw 'x' }" | Should -BeNullOrEmpty
    }
    It 'flags a function whose caller ignores the exit code' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "function Publish { git push }`nPublish`nWrite-Host done" | Should -HaveCount 1
    }
    It 'accepts $PSNativeCommandUseErrorActionPreference set before the call' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "`$PSNativeCommandUseErrorActionPreference = `$true`ngit push" | Should -BeNullOrEmpty
    }
    It 'honours a later $false over an earlier $true' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "`$PSNativeCommandUseErrorActionPreference = `$true`n`$PSNativeCommandUseErrorActionPreference = `$false`ngit push" | Should -HaveCount 1
    }
    It 'lets a function-level $false override the script-level $true' {
        $code = "`$PSNativeCommandUseErrorActionPreference = `$true`nfunction Publish { `$PSNativeCommandUseErrorActionPreference = `$false; git push; git status }"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -HaveCount 1
    }
    It 'applies the script-level $true inside a function' {
        $code = "`$PSNativeCommandUseErrorActionPreference = `$true`nfunction Publish { git push; Write-Host done }"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -BeNullOrEmpty
    }
    It 'flags a call before $PSNativeCommandUseErrorActionPreference is set' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "git push`n`$PSNativeCommandUseErrorActionPreference = `$true" | Should -HaveCount 1
    }
    It 'flags a call outside the function that sets $PSNativeCommandUseErrorActionPreference' {
        $code = "function Set-Strict { `$PSNativeCommandUseErrorActionPreference = `$true }`nSet-Strict`ngit push"
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code | Should -HaveCount 1
    }
    It 'uses the assignment in effect at the call, not a later one' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "`$tool = 'git'`n& `$tool push`nWrite-Host done`n`$tool = './helper.ps1'" | Should -HaveCount 1
    }
    It 'flags an earlier native call inside @(...) that only the last one hands on' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "`$x = @(git fetch; git push)`nif (`$LASTEXITCODE) { throw 'x' }" | Should -HaveCount 1
    }
    It 'accepts a native call inside @(...) checked within the block' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "`$x = @(git fetch; if (`$LASTEXITCODE) { throw 'f' }; git push)`nif (`$LASTEXITCODE) { throw 'x' }" | Should -BeNullOrEmpty
    }
    It 'flags a returned exit code that the caller ignores' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "function Invoke-Git { git push; return `$LASTEXITCODE }`nInvoke-Git`nWrite-Host done" | Should -HaveCount 1
    }
    It 'accepts a returned exit code the caller checks through a variable' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "function Invoke-Git { git push; return `$LASTEXITCODE }`n`$c = Invoke-Git`nif (`$c -ne 0) { throw 'x' }" | Should -BeNullOrEmpty
    }
    It 'accepts a returned exit code the caller checks in a condition' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "function Invoke-Git { git push; return `$LASTEXITCODE }`nif ((Invoke-Git) -ne 0) { throw 'x' }" | Should -BeNullOrEmpty
    }
    It 'flags || exit 0, which turns the failure into success' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "git push || exit 0`nWrite-Host done" | Should -HaveCount 1
    }
    It 'accepts || exit $LASTEXITCODE' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "git push || exit `$LASTEXITCODE`nWrite-Host done" | Should -BeNullOrEmpty
    }
    It 'flags an exit-code check after Select-Object -First, which stops the program first' {
        $code = "`$i = gh issue list | Select-Object -First 1`nif (`$LASTEXITCODE -ne 0) { throw 'x' }"
        $finding = Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code $code
        $finding | Should -HaveCount 1
        $finding.Message | Should -BeLike '*Select-Object -First/-Index*'
    }
    It 'flags -Index, an abbreviation, and a filter in between' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "`$i = gh issue list | Select-String x | select -f 1`nif (`$LASTEXITCODE) { throw 'x' }" | Should -HaveCount 1
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "`$i = git log | Select-Object -Index 0`nif (`$LASTEXITCODE) { throw 'x' }" | Should -HaveCount 1
    }
    It 'flags a splatted -First and a disabled or splatted-off -Wait' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "`$p = @{ First = 1 }`n`$i = git log | Select-Object @p`nif (`$LASTEXITCODE) { throw 'x' }" | Should -HaveCount 1
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "`$i = git log | Select-Object -First 1 -Wait:`$false`nif (`$LASTEXITCODE) { throw 'x' }" | Should -HaveCount 1
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "`$p = @{ First = 1; Wait = `$false }`n`$i = git log | Select-Object @p`nif (`$LASTEXITCODE) { throw 'x' }" | Should -HaveCount 1
    }
    It 'accepts a splatted -Wait' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "`$p = @{ First = 1; Wait = `$true }`n`$i = git log | Select-Object @p`nif (`$LASTEXITCODE) { throw 'x' }" | Should -BeNullOrEmpty
    }
    It 'flags a truncated call even with $PSNativeCommandUseErrorActionPreference' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "`$PSNativeCommandUseErrorActionPreference = `$true`n`$i = gh issue list | Select-Object -First 1" | Should -HaveCount 1
    }
    It 'accepts Select-Object -First -Wait, -Last, and selecting after the check' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "`$i = gh issue list | Select-Object -First 1 -Wait`nif (`$LASTEXITCODE) { throw 'x' }" | Should -BeNullOrEmpty
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "`$i = gh issue list | Select-Object -Last 1`nif (`$LASTEXITCODE) { throw 'x' }" | Should -BeNullOrEmpty
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "`$all = gh issue list`nif (`$LASTEXITCODE) { throw 'x' }`n`$i = `$all | Select-Object -First 1" | Should -BeNullOrEmpty
    }
    It 'accepts an empty-output guard on a truncated call' {
        Get-PwshGuardFinding -Rule PwshGuardUncheckedNativeCommand -Code "`$i = gh issue list | Select-Object -First 1`nif (-not `$i) { throw 'x' }" | Should -BeNullOrEmpty
    }
}

Describe 'PwshGuardUnsafeWorkflowCommandFile' {
    It 'flags a write to GITHUB_ENV' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code '"X=$v" | Add-Content $env:GITHUB_ENV' | Should -HaveCount 1
    }
    It 'flags a write to GITHUB_PATH' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code 'Add-Content -Path $env:GITHUB_PATH -Value $dir' | Should -HaveCount 1
    }
    It 'ignores read-only uses of GITHUB_ENV' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code "Test-Path `$env:GITHUB_ENV`nWrite-Host `"env file: `$env:GITHUB_ENV`"" | Should -BeNullOrEmpty
    }
    It 'flags a redirection to GITHUB_ENV' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code '"X=1" >> $env:GITHUB_ENV' | Should -HaveCount 1
    }
    It 'flags a File write method on GITHUB_PATH' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code '[IO.File]::AppendAllText($env:GITHUB_PATH, $dir)' | Should -HaveCount 1
    }
    It 'flags a write through a copy of GITHUB_ENV' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code "`$f = `$env:GITHUB_ENV`nAdd-Content -Path `$f -Value `"X=`$v`"" | Should -HaveCount 1
    }
    It 'ignores read-only uses such as IsNullOrEmpty and a copy that is never written' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code "if ([string]::IsNullOrEmpty(`$env:GITHUB_ENV)) { return }`n`$p = `$env:GITHUB_PATH`nWrite-Host `$p" | Should -BeNullOrEmpty
    }
    It 'flags a write to a quoted GITHUB_ENV path' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code 'Add-Content -Path "$env:GITHUB_ENV" -Value "X=$v"' | Should -HaveCount 1
    }
    It 'flags a write to GITHUB_ENV read through GetEnvironmentVariable' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code 'Add-Content -Path ([Environment]::GetEnvironmentVariable("GITHUB_ENV")) -Value "X=$v"' | Should -HaveCount 1
    }
    It 'flags a fixed delimiter behind a variable output name' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code '@("$name<<EOF", $v, "EOF") | Add-Content $env:GITHUB_OUTPUT' | Should -HaveCount 1
    }
    It 'flags a fixed delimiter in a format string' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code '("{0}<<EOF" -f $name), $v, "EOF" | Add-Content $env:GITHUB_OUTPUT' | Should -HaveCount 1
    }
    It 'accepts a generated delimiter appended by concatenation' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code '$d = [guid]::NewGuid(); @(("body<<" + $d), $v, $d) | Add-Content $env:GITHUB_OUTPUT' | Should -BeNullOrEmpty
    }
    It 'accepts a generated delimiter passed to a format string' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code '$d = [guid]::NewGuid(); @(("body<<{0}" -f $d), $v, $d) | Add-Content $env:GITHUB_OUTPUT' | Should -BeNullOrEmpty
    }
    It 'ignores a presence test' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code 'if ($env:GITHUB_ENV) { "local" }' | Should -BeNullOrEmpty
    }
    It 'flags a fixed heredoc delimiter' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code '@("body<<EOF", $v, "EOF") | Add-Content $env:GITHUB_OUTPUT' | Should -HaveCount 1
    }
    It 'flags a delimiter variable that is not random' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code '$d = ''EOF''; @("body<<$d", $v, $d) | Add-Content $env:GITHUB_OUTPUT' | Should -HaveCount 1
    }
    It 'ignores a heredoc-like string that never reaches a command file' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code '$doc = "body<<EOF"; Write-Host $doc' | Should -BeNullOrEmpty
    }
    It 'flags a fixed delimiter written through a variable' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code ('$block = @("body<<EOF", $v, "EOF")' + "`n" + 'Add-Content -Path $env:GITHUB_OUTPUT -Value $block') | Should -HaveCount 1
    }
    It 'flags a delimiter whose literal value merely mentions NewGuid' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code '$d = ''NewGuid''; @("body<<$d", $v, $d) | Add-Content $env:GITHUB_OUTPUT' | Should -HaveCount 1
    }
    It 'flags a random delimiter assigned only after the heredoc' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code ('$d = ''EOF''; @("body<<$d", $v, $d) | Add-Content $env:GITHUB_OUTPUT' + "`n" + '$d = [guid]::NewGuid()') | Should -HaveCount 1
    }
    It 'flags a random delimiter assigned in another branch of the same if' {
        $code = '$d = ''EOF''; if ($x) { $d = [guid]::NewGuid() } else { @("body<<$d", $v, $d) | Add-Content $env:GITHUB_OUTPUT }'
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code $code | Should -HaveCount 1
    }
    It 'accepts a random delimiter assigned in the same branch' {
        $code = 'if ($x) { $d = [guid]::NewGuid(); @("body<<$d", $v, $d) | Add-Content $env:GITHUB_OUTPUT }'
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code $code | Should -BeNullOrEmpty
    }
    It 'flags a random delimiter assigned in another function' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code ('function Set-D { $d = [guid]::NewGuid() }' + "`n" + '@("body<<$d", $v, $d) | Add-Content $env:GITHUB_OUTPUT') | Should -HaveCount 1
    }
    It 'accepts an inline New-Guid delimiter' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code '@("body<<$(New-Guid)", $v) | Add-Content $env:GITHUB_OUTPUT' | Should -BeNullOrEmpty
    }
    It 'accepts a generated delimiter' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code '$d = [guid]::NewGuid(); @("body<<$d", $v, $d) | Add-Content $env:GITHUB_OUTPUT' | Should -BeNullOrEmpty
    }
    It 'ignores GITHUB_ENV used as content of another file' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code "Add-Content local.log -Value `$env:GITHUB_ENV`n[IO.File]::AppendAllText('local.log', `$env:GITHUB_PATH)" | Should -BeNullOrEmpty
    }
    It 'flags GITHUB_ENV as the positional path of Add-Content' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code 'Add-Content $env:GITHUB_ENV "X=$v"' | Should -HaveCount 1
    }
    It 'flags a delimiter from [RandomNumberGenerator]::Create()' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code '$d = [System.Security.Cryptography.RandomNumberGenerator]::Create(); @("body<<$d", $v, $d) | Add-Content $env:GITHUB_OUTPUT' | Should -HaveCount 1
    }
    It 'accepts a delimiter from RandomNumberGenerator::GetHexString' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code '$d = [System.Security.Cryptography.RandomNumberGenerator]::GetHexString(32); @("body<<$d", $v, $d) | Add-Content $env:GITHUB_OUTPUT' | Should -BeNullOrEmpty
    }
    It 'flags a fixed delimiter written through a copy of the GITHUB_OUTPUT path' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code ('$out = $env:GITHUB_OUTPUT' + "`n" + '@("body<<EOF", $value, "EOF") | Add-Content $out') | Should -HaveCount 1
    }
    It 'flags a fixed delimiter written through GetEnvironmentVariable' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code ('$out = [Environment]::GetEnvironmentVariable(''GITHUB_OUTPUT'')' + "`n" + '@("body<<EOF", $value, "EOF") | Add-Content $out') | Should -HaveCount 1
    }
    It 'does not trust a random delimiter assigned only in a branch' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code '$d = ''EOF''; if ($x) { $d = New-Guid }; @("body<<$d", $value, $d) | Add-Content $env:GITHUB_OUTPUT' | Should -HaveCount 1
    }
    It 'trusts a random delimiter assigned in a try body' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeWorkflowCommandFile -Code 'try { $d = New-Guid } catch { throw }; @("body<<$d", $value, $d) | Add-Content $env:GITHUB_OUTPUT' | Should -BeNullOrEmpty
    }
}

Describe 'PwshGuardSecretInOutput' {
    It 'flags printing a secret-named variable' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code 'Write-Host "token: $accessToken"' | Should -HaveCount 1
    }
    It 'flags printing a secret environment variable' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code 'Write-Output $env:ARM_CLIENT_SECRET' | Should -HaveCount 1
    }
    It 'ignores a derived value passed to Write-Host' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code 'Write-Host $accessToken.Length' | Should -BeNullOrEmpty
    }
    It 'ignores masking a secret-named value' {
        $code = "Write-Host `"::add-mask::`$accessToken`"`nWrite-Output ('::add-mask::' + `$env:ARM_CLIENT_SECRET)`n`"::add-mask::`$clientSecret`"`necho ('::add-mask::{0}' -f `$token)"
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code $code | Should -BeNullOrEmpty
    }
    It 'still flags printing the secret next to a mask' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code "Write-Host `"::add-mask::`$accessToken`"`nWrite-Host `"token: `$accessToken`"" | Should -HaveCount 1
    }
    It 'ignores a comparison with a secret' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code "Write-Host (`$accessToken -eq `$null)`n`$accessToken -match '^ey'`nWrite-Output (`$clientSecret -like 'x*')" | Should -BeNullOrEmpty
    }
    It 'flags a secret passed through formatting or -replace' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code "Write-Host ('{0}' -f `$accessToken)`nWrite-Output (`$clientSecret -replace 'a', 'b')" | Should -HaveCount 2
    }
    It 'flags a secret concatenated into a Write-Host argument' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code 'Write-Host ("token " + $accessToken)' | Should -HaveCount 1
    }
    It 'ignores names that only describe a secret' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code 'Write-Host "tokens used: $tokenCount, file $secretPath"' | Should -BeNullOrEmpty
    }
    It 'flags a secret whose name contains an excluded word' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code "Write-Host `$adminPassword`nWrite-Host `$env:ADMIN_PASSWORD`nWrite-Host `$profileToken" | Should -HaveCount 3
    }
    It 'flags an all-lowercase secret name' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code 'Write-Host $accesstoken' | Should -HaveCount 1
    }
    It 'flags compound secret names' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code "Write-Host `$apiKey`nWrite-Host `$env:STORAGE_CONNECTION_STRING`nWrite-Host `$sasUrl`nWrite-Host `$tokenValue" | Should -HaveCount 4
    }
    It 'ignores names that merely contain the letters of a secret word' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code 'Write-Host "$hasAssignments $tokenizer $secretary $maxTokens $hasToken $tokenResponse $tokenExpiresOn"' | Should -BeNullOrEmpty
    }
    It 'flags a secret-named property' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code "Write-Host `$resp.access_token`nWrite-Host `"x `$(`$tokenResponse.access_token)`"" | Should -HaveCount 2
    }
    It 'flags a secret in a subexpression once' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code 'Write-Host "t: $($accessToken)"' | Should -HaveCount 1
    }
    It 'flags Write-Error' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code 'Write-Error "bad $accessToken"' | Should -HaveCount 1
    }
    It 'flags a secret piped to a writer' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code '$accessToken | Write-Host' | Should -HaveCount 1
    }
    It 'flags a Key Vault secret and a SecureString turned into plain text' {
        $code = "`$s = az keyvault secret show --name x --query value -o tsv`n`$p = ConvertFrom-SecureString `$secure -AsPlainText`n`$k = Get-AzKeyVaultSecret -VaultName v -Name n -AsPlainText"
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code $code | Should -HaveCount 3
    }
    It 'accepts ConvertFrom-SecureString without -AsPlainText' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code '$p = ConvertFrom-SecureString $secure' | Should -BeNullOrEmpty
    }
    It 'accepts a mask built by concatenation or format' {
        $code = "`$t = gh auth token`nWrite-Host ('::add-mask::' + `$t)`n`$u = gh auth token`nWrite-Host ('::add-mask::{0}' -f `$u)"
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code $code | Where-Object { $_.Message -match 'add-mask' } | Should -BeNullOrEmpty
    }
    It 'flags a bare secret variable at script level' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code '$accessToken' | Should -HaveCount 1
    }
    It 'flags a secret in an expandable string at script level' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code '"token: $accessToken"' | Should -HaveCount 1
    }
    It 'flags a secret returned at script level' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code 'return $accessToken' | Should -HaveCount 1
    }
    It 'ignores a secret returned from a function with return' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code 'function Get-Token { return $accessToken }' | Should -BeNullOrEmpty
    }
    It 'accepts a mask of a plain-text value derived from the token' {
        $code = "`$tok = Get-AzAccessToken -ResourceUrl x`n`$plain = if (`$tok.Token -is [securestring]) { ConvertFrom-SecureString `$tok.Token -AsPlainText } else { `$tok.Token }`nWrite-Host `"::add-mask::`$plain`""
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code $code | Should -BeNullOrEmpty
    }
    It 'flags a derived value printed before its mask, and a token used before the copy is masked' {
        $code = "`$t = gh auth token`n`$p = `$t.Trim()`nWrite-Output `$p`nWrite-Host `"::add-mask::`$p`""
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code $code | Should -HaveCount 1
        $code = "`$t = gh auth token`nWrite-Output `$t`n`$p = `$t.Trim()`nWrite-Host `"::add-mask::`$p`""
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code $code | Where-Object { $_.Message -match 'add-mask' } | Should -HaveCount 1
    }
    It 'ignores a secret returned from a function' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code 'function Get-Token { $accessToken }' | Should -BeNullOrEmpty
    }
    It 'ignores a derived value' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code '"length: $($accessToken.Length)"' | Should -BeNullOrEmpty
    }
    It 'flags a throw carrying a secret' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code 'throw "bad token $accessToken"' | Should -HaveCount 1
    }
    It 'flags Start-Transcript' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code 'Start-Transcript -Path log.txt' | Should -HaveCount 1
    }
    It 'flags a runtime token without add-mask' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code '$t = az account get-access-token --query accessToken -o tsv' | Should -HaveCount 1
    }
    It 'accepts a runtime token that is masked' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code "`$t = gh auth token`nWrite-Host `"::add-mask::`$(`$t)`"" |
            Where-Object { $_.Message -match 'add-mask' } | Should -BeNullOrEmpty
    }
    It 'flags a runtime token when only another value is masked' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code "`$t = gh auth token`nWrite-Host `"::add-mask::`$(`$other)`"" |
            Where-Object { $_.Message -match 'add-mask' } | Should -HaveCount 1
    }
    It 'flags a mask string that is never emitted' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code "`$t = gh auth token`n`$template = `"::add-mask::`$t`"" |
            Where-Object { $_.Message -match 'add-mask' } | Should -HaveCount 1
    }
    It 'flags a mask emitted in another scope' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code "`$t = gh auth token`nfunction Hide { Write-Host `"::add-mask::`$t`" }" |
            Where-Object { $_.Message -match 'add-mask' } | Should -HaveCount 1
    }
    It 'accepts a mask emitted as bare output' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code "`$t = gh auth token`n`"::add-mask::`$t`"" |
            Where-Object { $_.Message -match 'add-mask' } | Should -BeNullOrEmpty
    }
    It 'flags a mask registered before the token is obtained' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code "Write-Host `"::add-mask::`$t`"`n`$t = gh auth token" |
            Where-Object { $_.Message -match 'add-mask' } | Should -HaveCount 1
    }
    It 'flags -AsSecureString:$false' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code '$t = Get-AzAccessToken -AsSecureString:$false' | Should -HaveCount 1
    }
    It 'accepts a SecureString token' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code '$t = Get-AzAccessToken -AsSecureString -ResourceUrl https://graph.microsoft.com/' | Should -BeNullOrEmpty
    }
    It 'flags a secret piped through an output-preserving command' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code '$accessToken | Out-String' | Should -HaveCount 1
    }
    It 'ignores a secret piped into a command that consumes it' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code '$accessToken | Set-Content token.txt' | Should -BeNullOrEmpty
    }
    It 'flags a mask registered only after the token was printed' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code "`$t = gh auth token`nWrite-Output `$t`nWrite-Host `"::add-mask::`$t`"" |
            Where-Object { $_.Message -match 'add-mask' } | Should -HaveCount 1
    }
    It 'accepts a presence test before the mask' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code "`$t = gh auth token`nif (-not `$t) { throw 'no token' }`nWrite-Host `"::add-mask::`$t`"" |
            Where-Object { $_.Message -match 'add-mask' } | Should -BeNullOrEmpty
    }
    It 'traces a secret through pass-through commands into a writer' {
        Get-PwshGuardFinding -Rule PwshGuardSecretInOutput -Code '$accessToken | Out-String | Write-Host' | Should -HaveCount 1
    }
}

Describe 'PwshGuardDynamicCodeExecution' {
    It 'flags [scriptblock]::Create on data' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code '& ([scriptblock]::Create($body))' | Should -HaveCount 1
    }
    It 'accepts [scriptblock]::Create on a constant' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code '[scriptblock]::Create(''Get-Date'')' | Should -BeNullOrEmpty
    }
    It 'flags bash -c with an interpolated command line' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code 'bash -c "git checkout $branch"' | Should -HaveCount 1
    }
    It 'flags a shell called by path' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code "/bin/bash -c `"git checkout `$branch`"`n/usr/bin/pwsh -Command `"Get-Item `$p`"" | Should -HaveCount 2
    }
    It 'flags -c inside a flag cluster' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code 'bash -lc "git checkout $branch"' | Should -HaveCount 1
    }
    It 'flags abbreviated -Command and -EncodedCommand' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code "pwsh -NoProfile -Com `"Get-Item `$p`"`npwsh -ec `$encoded`ncmd /c `"dir `$p`"" | Should -HaveCount 3
    }
    It 'ignores other pwsh parameters that take a value' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code 'pwsh -NoProfile -File $script -ExecutionPolicy $policy' | Should -BeNullOrEmpty
    }
    It 'flags the call operator on an interpolated name' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code '& "$tool-$version" --help' | Should -HaveCount 1
    }
    It 'accepts a path rooted at $PSScriptRoot' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code '. $PSScriptRoot/lib.ps1' | Should -BeNullOrEmpty
    }
    It 'flags Start-Process with an abbreviated -ArgumentList' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code 'Start-Process tofu -Arg "plan -var x=$v"' | Should -HaveCount 1
    }
    It 'flags Start-Process with a positional interpolated argument string' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code 'Start-Process tofu "plan -var x=$v"' | Should -HaveCount 1
    }
    It 'flags Start-Process with a named file path and positional arguments' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code 'Start-Process -FilePath tofu -Wait "plan -var x=$v"' | Should -HaveCount 1
    }
    It 'flags an interpolated element of an argument array' {
        # Start-Process joins the array into one command line, which the target re-splits.
        $code = "Start-Process tofu @('plan', `"-var=x=`$v`")`nStart-Process tofu -ArgumentList 'plan', `"-var=x=`$v`""
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code $code | Should -HaveCount 2
    }
    It 'accepts Start-Process with constant arguments' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code 'Start-Process tofu @(''plan'', ''-input=false'') -Wait' | Should -BeNullOrEmpty
    }
    It 'flags Start-Process with one interpolated argument string' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code 'Start-Process tofu -ArgumentList "plan -var x=$v"' | Should -HaveCount 1
    }
    It 'flags Add-Type on built-up source' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code 'Add-Type -TypeDefinition $source' | Should -HaveCount 1
    }
    It 'flags Add-Type with positional source' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code 'Add-Type $source' | Should -HaveCount 1
    }
    It 'flags Add-Type with positional member definition' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code 'Add-Type Win32 $members' | Should -HaveCount 1
    }
    It 'ignores Add-Type -Path and -AssemblyName' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code "Add-Type -Path `$dll`nAdd-Type -AssemblyName System.Web" | Should -BeNullOrEmpty
    }
    It 'ignores Add-Type with a constant positional source' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code 'Add-Type -PassThru ''public class A {}''' | Should -BeNullOrEmpty
    }
    It 'follows a Start-Process argument variable to its assignment' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code "`$a = `"plan -var x=`$value`"`nStart-Process tofu -ArgumentList `$a" | Should -HaveCount 1
    }
    It 'follows array elements held in variables' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code "`$x = `"-var=x=`$value`"`nStart-Process tofu -ArgumentList @('plan', `$x)" | Should -HaveCount 1
    }
    It 'flags a quoted shell flag' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code 'bash ''-c'' "git checkout $branch"' | Should -HaveCount 1
    }
    It 'flags a $PSScriptRoot path with another interpolation' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code '& "$PSScriptRoot/$tool"' | Should -HaveCount 1
    }
    It 'accepts a path rooted at $PSScriptRoot with a constant rest' {
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code '& "$PSScriptRoot/helper.ps1"' | Should -BeNullOrEmpty
    }
    It 'flags ExpandString on data' {
        $code = "`$ExecutionContext.InvokeCommand.ExpandString(`$template)`n`$ExecutionContext.SessionState.InvokeCommand.ExpandString(`"x `$v`")"
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code $code | Should -HaveCount 2
    }
    It 'accepts ExpandString on a constant and an unrelated ExpandString method' {
        $code = "`$ExecutionContext.InvokeCommand.ExpandString('`$env:HOME')`n`$expander.ExpandString(`$template)"
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code $code | Should -BeNullOrEmpty
    }
    It 'flags AddScript and CreateNestedPipeline on data' {
        $code = "[powershell]::Create().AddScript(`$body).Invoke()`n`$ps.AddScript(`"Get-Item `$p`", `$true)`n`$runspace.CreateNestedPipeline(`$body, `$false)"
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code $code | Should -HaveCount 3
    }
    It 'accepts AddScript on a constant and AddCommand with a data parameter' {
        $code = "`$ps.AddScript('Get-Date', `$useLocalScope)`n`$ps.AddCommand('Get-Item').AddParameter('Path', `$p)"
        Get-PwshGuardFinding -Rule PwshGuardDynamicCodeExecution -Code $code | Should -BeNullOrEmpty
    }
}

Describe 'PwshGuardUnpinnedModuleInstall' {
    It 'flags an unpinned Install-Module' {
        Get-PwshGuardFinding -Rule PwshGuardUnpinnedModuleInstall -Code 'Install-Module Az.Accounts -Force' | Should -HaveCount 1
    }
    It 'accepts a pinned Install-Module' {
        Get-PwshGuardFinding -Rule PwshGuardUnpinnedModuleInstall -Code 'Install-Module Az.Accounts -RequiredVersion 3.0.0 -Force' | Should -BeNullOrEmpty
    }
    It 'accepts an abbreviated -RequiredVersion' {
        Get-PwshGuardFinding -Rule PwshGuardUnpinnedModuleInstall -Code 'Install-Module Az.Accounts -RequiredV 3.0.0' | Should -BeNullOrEmpty
    }
    It 'flags Install-Module -V, which binds to -Verbose' {
        Get-PwshGuardFinding -Rule PwshGuardUnpinnedModuleInstall -Code 'Install-Module Foo -V' | Should -HaveCount 1
    }
    It 'accepts Install-PSResource -Version' {
        Get-PwshGuardFinding -Rule PwshGuardUnpinnedModuleInstall -Code 'Install-PSResource Foo -Version 1.0.0' | Should -BeNullOrEmpty
    }
    It 'flags a wildcard or range given as the version' {
        $code = "Install-PSResource Foo -Version '*'`nInstall-PSResource Foo -Version '[1.0,2.0)'`nInstall-Module Foo -RequiredVersion '2.*'`n`$p = @{ Name = 'Foo'; Version = '*' }`nInstall-PSResource @p"
        Get-PwshGuardFinding -Rule PwshGuardUnpinnedModuleInstall -Code $code | Should -HaveCount 4
    }
    It 'accepts a version from a variable or a pinned splat' {
        $code = "Install-Module Foo -RequiredVersion `$env:FOO_VERSION`n`$p = @{ Name = 'Foo'; Version = '1.2.3' }`nInstall-PSResource @p"
        Get-PwshGuardFinding -Rule PwshGuardUnpinnedModuleInstall -Code $code | Should -BeNullOrEmpty
    }
    It 'flags Install-PSResource -RequiredVersion, which it does not have' {
        Get-PwshGuardFinding -Rule PwshGuardUnpinnedModuleInstall -Code 'Install-PSResource Foo -RequiredVersion 1.0.0' | Should -HaveCount 1
    }
    It 'flags Update-Module and Install-Script without a version' {
        Get-PwshGuardFinding -Rule PwshGuardUnpinnedModuleInstall -Code "Update-Module Az -Force`nInstall-Script Foo -Force" | Should -HaveCount 2
    }
    It 'accepts a version pinned through a splat' {
        Get-PwshGuardFinding -Rule PwshGuardUnpinnedModuleInstall -Code '$p = @{ Name = ''X''; RequiredVersion = ''1.0'' }; Install-Module @p' | Should -BeNullOrEmpty
    }
    It 'flags a splat without a version' {
        Get-PwshGuardFinding -Rule PwshGuardUnpinnedModuleInstall -Code '$p = @{ Name = ''X''; Force = $true }; Install-Module @p' | Should -HaveCount 1
    }
    It 'leaves a splat it cannot resolve alone' {
        Get-PwshGuardFinding -Rule PwshGuardUnpinnedModuleInstall -Code 'Install-Module @InstallParameters' | Should -BeNullOrEmpty
    }
    It 'flags -SkipPublisherCheck' {
        Get-PwshGuardFinding -Rule PwshGuardUnpinnedModuleInstall -Code 'Install-Module Pester -RequiredVersion 5.7.1 -SkipPublisherCheck' | Should -HaveCount 1
    }
    It 'ignores -SkipPublisherCheck:$false and a false splat entry' {
        Get-PwshGuardFinding -Rule PwshGuardUnpinnedModuleInstall -Code "Install-Module Pester -RequiredVersion 5.7.1 -SkipPublisherCheck:`$false`n`$p = @{ Name = 'Pester'; RequiredVersion = '5.7.1'; SkipPublisherCheck = `$false }`nInstall-Module @p" | Should -BeNullOrEmpty
    }
    It 'flags a true splat entry' {
        Get-PwshGuardFinding -Rule PwshGuardUnpinnedModuleInstall -Code "`$p = @{ Name = 'Pester'; RequiredVersion = '5.7.1'; SkipPublisherCheck = `$true }`nInstall-Module @p" | Should -HaveCount 1
    }
}

Describe 'PwshGuardInsecureTransport' {
    It 'flags -SkipCertificateCheck' {
        Get-PwshGuardFinding -Rule PwshGuardInsecureTransport -Code 'Invoke-RestMethod https://x -SkipCertificateCheck' | Should -HaveCount 1
    }
    It 'flags an abbreviated -SkipCertificateCheck' {
        Get-PwshGuardFinding -Rule PwshGuardInsecureTransport -Code 'Invoke-WebRequest https://x -SkipCert' | Should -HaveCount 1
    }
    It 'ignores Select-Object -Skip' {
        Get-PwshGuardFinding -Rule PwshGuardInsecureTransport -Code '1..5 | Select-Object -Skip 1' | Should -BeNullOrEmpty
    }
    It 'flags a certificate validation callback' {
        Get-PwshGuardFinding -Rule PwshGuardInsecureTransport -Code '[Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }' | Should -HaveCount 1
    }
    It 'ignores restoring the validation callback to $null' {
        Get-PwshGuardFinding -Rule PwshGuardInsecureTransport -Code '[Net.ServicePointManager]::ServerCertificateValidationCallback = $null' | Should -BeNullOrEmpty
    }
    It 'ignores reading the validation callback' {
        Get-PwshGuardFinding -Rule PwshGuardInsecureTransport -Code '$current = [Net.ServicePointManager]::ServerCertificateValidationCallback' | Should -BeNullOrEmpty
    }
    It 'flags plain HTTP' {
        Get-PwshGuardFinding -Rule PwshGuardInsecureTransport -Code 'Invoke-WebRequest -Uri "http://example.com/a.zip"' | Should -HaveCount 1
    }
    It 'flags plain HTTP passed through a variable' {
        Get-PwshGuardFinding -Rule PwshGuardInsecureTransport -Code "`$u = 'http://example.com/a.zip'`nInvoke-WebRequest -Uri `$u" | Should -HaveCount 1
    }
    It 'flags curl, wget and git with certificate checks off' {
        $code = "curl -sk https://x/y`ncurl --insecure https://x/y`nwget --no-check-certificate https://x/y`ngit -c http.sslVerify=false clone https://x"
        Get-PwshGuardFinding -Rule PwshGuardInsecureTransport -Code $code | Should -HaveCount 4
    }
    It 'ignores curl flags that only resemble -k' {
        Get-PwshGuardFinding -Rule PwshGuardInsecureTransport -Code "curl -sSL https://x/y`ncurl -K config.txt https://x/y" | Should -BeNullOrEmpty
    }
    It 'flags environment switches that turn validation off' {
        Get-PwshGuardFinding -Rule PwshGuardInsecureTransport -Code "`$env:GIT_SSL_NO_VERIFY = 'true'`n`$env:NODE_TLS_REJECT_UNAUTHORIZED = '0'" | Should -HaveCount 2
    }
    It 'ignores unsetting GIT_SSL_NO_VERIFY' {
        Get-PwshGuardFinding -Rule PwshGuardInsecureTransport -Code "`$env:GIT_SSL_NO_VERIFY = `$null`n`$env:GIT_SSL_NO_VERIFY = ''" | Should -BeNullOrEmpty
    }
    It 'flags GIT_SSL_NO_VERIFY set from a variable' {
        Get-PwshGuardFinding -Rule PwshGuardInsecureTransport -Code '$env:GIT_SSL_NO_VERIFY = $value' | Should -HaveCount 1
    }
    It 'accepts loopback HTTP' {
        Get-PwshGuardFinding -Rule PwshGuardInsecureTransport -Code 'Invoke-RestMethod http://localhost:8080/health' | Should -BeNullOrEmpty
    }
    It 'flags quoted native flags' {
        Get-PwshGuardFinding -Rule PwshGuardInsecureTransport -Code "curl '--insecure' https://x`nwget '--no-check-certificate' https://x" | Should -HaveCount 2
    }
    It 'ignores -SkipCertificateCheck:$false' {
        Get-PwshGuardFinding -Rule PwshGuardInsecureTransport -Code 'Invoke-RestMethod https://x -SkipCertificateCheck:$false' | Should -BeNullOrEmpty
    }
    It 'ignores an http string that is not the request URL' {
        Get-PwshGuardFinding -Rule PwshGuardInsecureTransport -Code "Invoke-WebRequest -Uri https://safe -UserAgent 'http://example.com'`ncurl -A 'http://example.com' https://safe" | Should -BeNullOrEmpty
    }
    It 'flags plain HTTP assembled by concatenation' {
        Get-PwshGuardFinding -Rule PwshGuardInsecureTransport -Code "`$url = 'http://' + `$server + '/a.zip'`nInvoke-WebRequest `$url`nInvoke-RestMethod ('http://' + `$server)" | Should -HaveCount 2
    }
    It 'accepts HTTPS assembled by concatenation' {
        Get-PwshGuardFinding -Rule PwshGuardInsecureTransport -Code "`$url = 'https://' + `$server`nInvoke-WebRequest `$url" | Should -BeNullOrEmpty
    }
    It 'flags plain HTTP passed to wget' {
        Get-PwshGuardFinding -Rule PwshGuardInsecureTransport -Code "wget http://example.com/a.zip`nwget -O out.zip http://example.com/a.zip" | Should -HaveCount 2
    }
    It 'ignores a wget option value that is not the request URL' {
        Get-PwshGuardFinding -Rule PwshGuardInsecureTransport -Code "wget --referer 'http://example.com' https://safe`nwget -U 'http://example.com' https://safe" | Should -BeNullOrEmpty
    }
    It 'flags a positional plain-HTTP URL after a switch' {
        Get-PwshGuardFinding -Rule PwshGuardInsecureTransport -Code 'Invoke-WebRequest -UseBasicParsing http://example.com/a.zip' | Should -HaveCount 1
    }
}

Describe 'PwshGuardUnsafeRecursiveDelete' {
    It 'accepts segments that are parameters PowerShell refuses to bind empty' {
        $code = @(
            'param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory = $true)][string]$Other,'
            '    [ValidateNotNullOrEmpty()][string]$Name, [ValidateSet(''a'', ''b'')][string]$Kind)'
            'Remove-Item "$Root/cache" -Recurse -Force'
            'Remove-Item "$Other/$Name/$Kind" -Recurse'
            'Remove-Item (Join-Path $Root $Name) -Recurse'
        ) -join "`n"
        Get-PwshGuardFinding -Rule PwshGuardUnsafeRecursiveDelete -Code $code | Should -BeNullOrEmpty
    }
    It 'flags a parameter that can be empty or is reassigned' {
        $code = @(
            'param([string]$A, [Parameter(Mandatory)][AllowEmptyString()][string]$B,'
            '    [Parameter(Mandatory, ParameterSetName = ''x'')][string]$C, [Parameter(Mandatory)][string]$D,'
            '    [ValidateSet(''a'', '''')][string]$E)'
            '$D = $env:TARGET'
            'Remove-Item "$A/x" -Recurse'
            'Remove-Item "$B/x" -Recurse'
            'Remove-Item "$C/x" -Recurse'
            'Remove-Item "$D/x" -Recurse'
            'Remove-Item "$E/x" -Recurse'
        ) -join "`n"
        Get-PwshGuardFinding -Rule PwshGuardUnsafeRecursiveDelete -Code $code | Should -HaveCount 5
    }
    It 'flags a recursive delete of an interpolated path' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeRecursiveDelete -Code 'Remove-Item -Recurse -Force -Path $root/$name' | Should -HaveCount 1
    }
    It 'flags Join-Path with a variable child segment' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeRecursiveDelete -Code 'Remove-Item -Recurse -Force -Path (Join-Path $root $name)' | Should -HaveCount 1
    }
    It 'accepts Join-Path with a constant child segment' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeRecursiveDelete -Code 'Remove-Item -Recurse -Force -Path (Join-Path $root ''cache'')' | Should -BeNullOrEmpty
    }
    It 'finds the positional path behind a named parameter value' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeRecursiveDelete -Code 'Remove-Item -Filter ''*.tmp'' -Recurse "$root/$name"' | Should -HaveCount 1
    }
    It 'flags abbreviated parameters' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeRecursiveDelete -Code 'Remove-Item -Rec -Pa "$root/$name"' | Should -HaveCount 1
    }
    It 'flags the native rm with clustered flags' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeRecursiveDelete -Code "rm -rf `"`$root/`$name`"`nrm --recursive `"`$root/`$name`"" | Should -HaveCount 2
    }
    It 'ignores the native rm without a recursive flag' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeRecursiveDelete -Code 'rm -f "$root/$name"' | Should -BeNullOrEmpty
    }
    It 'follows a path held in a variable' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeRecursiveDelete -Code "`$p = `"`$root/`$name`"`nRemove-Item -Recurse -Force `$p" | Should -HaveCount 1
    }
    It 'flags an interpolated path inside a list of paths' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeRecursiveDelete -Code 'Remove-Item -Recurse -Force ''fixed'', "$root/$b"' | Should -HaveCount 1
    }
    It 'flags an interpolated path inside an array expression' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeRecursiveDelete -Code 'Remove-Item -Recurse -Path @("$root/$name")' | Should -HaveCount 1
    }
    It 'flags an interpolated path inside an array held in a variable' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeRecursiveDelete -Code "`$paths = @(`"`$root/`$name`")`nRemove-Item -Recurse -Path `$paths`n`$list = 'fixed', `"`$root/`$b`"`nRemove-Item -Recurse `$list" | Should -HaveCount 2
    }
    It 'accepts an array of constant paths held in a variable' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeRecursiveDelete -Code "`$paths = @('./out', './tmp')`nRemove-Item -Recurse -Path `$paths" | Should -BeNullOrEmpty
    }
    It 'accepts an array expression of constant paths' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeRecursiveDelete -Code 'Remove-Item -Recurse -Path @(''./out'', ''./tmp'')' | Should -BeNullOrEmpty
    }
    It 'flags Directory.Delete with the recursive argument' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeRecursiveDelete -Code '[IO.Directory]::Delete("$root/$name", $true)' | Should -HaveCount 1
    }
    It 'accepts a constant child of $PSScriptRoot' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeRecursiveDelete -Code 'Remove-Item -Recurse -Force "$PSScriptRoot/cache"' | Should -BeNullOrEmpty
    }
    It 'ignores a delete with recursion switched off' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeRecursiveDelete -Code "Remove-Item -Recurse:`$false `"`$root/`$name`"`nRemove-Item -Recurse:0 -Path `"`$root/`$name`"" | Should -BeNullOrEmpty
    }
    It 'ignores a non-recursive delete' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeRecursiveDelete -Code 'Remove-Item -Path "$root/$name"' | Should -BeNullOrEmpty
    }
    It 'follows a typed assignment' {
        Get-PwshGuardFinding -Rule PwshGuardUnsafeRecursiveDelete -Code "[string]`$path = `"`$root/`$name`"`nRemove-Item -Recurse `$path" | Should -HaveCount 1
    }
}

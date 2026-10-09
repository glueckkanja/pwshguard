# Runs PSScriptAnalyzer, with the PwshGuard security rules (PwshGuard.psm1 next to this
# script), over a repository's PowerShell: the script files, and the `run:` blocks of
# workflows and composite actions whose step sets `shell: pwsh`. Run it from the root of the
# repository to scan.
#
# Reported: every PwshGuard* rule, PSScriptAnalyzer's own security rules, and any Error-severity
# finding. Style findings are listed in the log only. One rule lives here rather than in the
# rule module, because it needs the workflow text: PwshGuardExpressionInScript, a `${{ }}`
# expression in an inline pwsh step (see Get-InlineScript). A rule named in the settings'
# ExcludeRules, PwshGuard* or built-in, is not reported at all.
#
# With -ReportPath (CI) the reported findings are written as a Markdown report for the
# pull request comment: findings in -ChangedFile in full, the rest of the repository
# collapsed. The script then always succeeds, so findings never block a merge. Without it
# (local use) the findings are printed and the script fails when there are any.
# Either way it returns the counts ({Reported, InChanged, SuppressedInChanged}) for the caller.
#
# To accept a finding deliberately, put
# [Diagnostics.CodeAnalysis.SuppressMessageAttribute('<RuleName>', '', Justification = '...')]
# on the enclosing function or on the script's param() block (it cannot precede a single command).
# An inline `shell: pwsh` step cannot open with a param() block, so it takes a comment instead,
# which covers the rule for the whole step: # SuppressMessage <RuleName>: <justification>
# The findings never block, so a suppression is not silent either: those in -ChangedFile are
# listed in the report with their justification.

param(
    # Default: every PowerShell file tracked in the repository, so the scan covers whatever
    # the workflow's path filter triggers on.
    [string[]]$Path,
    # Workflow and action files to scan for inline PowerShell. Default: every tracked YAML
    # file when -Path is not given, none when it is.
    [string[]]$WorkflowPath,
    # PSScriptAnalyzer settings (ExcludeRules, IncludeDefaultRules ...). The PwshGuard rules are
    # added to its CustomRulePath, so a settings file does not need to know where they live.
    [string]$Settings = (Join-Path $PSScriptRoot 'PSScriptAnalyzerSettings.psd1'),
    # PSScriptAnalyzer version to install and load. Default: the pin in RequiredModules.psd1.
    [string]$RequiredVersion = (Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'RequiredModules.psd1')).PSScriptAnalyzer,
    [string]$ReportPath,
    # Repository-relative paths changed by the pull request.
    [string[]]$ChangedFile = @(),
    # Base for links to findings, e.g. https://github.com/<owner>/<repo>/blob/<sha>.
    [string]$BlobUrl,
    # Where the report's footer points readers for the rules.
    [string]$RulesUrl = 'https://github.com/glueckkanja/pwshguard#rules'
)

$ErrorActionPreference = 'Stop'

$settingsTable = Import-PowerShellDataFile -LiteralPath $Settings
$settingsTable.CustomRulePath = [string[]]@(@($settingsTable.CustomRulePath | Where-Object { $_ }) + (Join-Path $PSScriptRoot 'PwshGuard.psm1'))
if (-not $settingsTable.ContainsKey('IncludeDefaultRules')) { $settingsTable.IncludeDefaultRules = $true }

# Severity of the reported rules; anything else that is reported is Error severity.
$ruleSeverity = @{
    PwshGuardUnsafeWorkflowCommandFile             = 'High'
    PwshGuardDynamicCodeExecution                  = 'High'
    PwshGuardExpressionInScript                    = 'High'
    PSAvoidUsingInvokeExpression                   = 'High'
    PwshGuardSecretInOutput                        = 'High'
    PwshGuardInsecureTransport                     = 'Medium'
    PwshGuardUnpinnedModuleInstall                 = 'Medium'
    PSAvoidUsingPlainTextForPassword               = 'Medium'
    PSAvoidUsingConvertToSecureStringWithPlainText = 'Medium'
    PSAvoidUsingUsernameAndPasswordParams          = 'Medium'
    PSAvoidUsingAllowUnencryptedAuthentication     = 'Medium'
    PSUsePSCredentialType                          = 'Low'
    PSAvoidUsingBrokenHashAlgorithms               = 'Low'
    PwshGuardUncheckedNativeCommand                = 'Low'
    PwshGuardFailOpenScript                        = 'Low'
    PwshGuardUnsafeRecursiveDelete                 = 'Low'
}
$severityOrder = @{ High = 0; Medium = 1; Low = 2 }

if (-not (Get-Module -ListAvailable PSScriptAnalyzer | Where-Object Version -EQ $RequiredVersion)) {
    Install-Module PSScriptAnalyzer -RequiredVersion $RequiredVersion -Scope CurrentUser -Force
}
Import-Module PSScriptAnalyzer -RequiredVersion $RequiredVersion

if (-not $Path) {
    $tracked = @(git ls-files -- '*.ps1' '*.psm1' '*.psd1')
    if ($LASTEXITCODE -ne 0) { throw 'git ls-files failed; pass -Path explicitly outside a repository.' }
    # One recursive run per top-level entry is much faster than one run per file.
    $Path = @($tracked | ForEach-Object { ($_ -split '/')[0] } | Sort-Object -Unique)
    if (-not $PSBoundParameters.ContainsKey('WorkflowPath')) {
        $WorkflowPath = @(git ls-files -- '*.yml' '*.yaml')
        if ($LASTEXITCODE -ne 0) { throw 'git ls-files failed.' }
    }
}

# Contexts whose values the workflow's author or GitHub fixes, never the text of a pull
# request, an issue, a branch name or a dispatch input.
$safeExpressionContext = '^(github\.(repository|repository_owner|repository_id|repository_owner_id|server_url|api_url|graphql_url|' +
'run_id|run_number|run_attempt|sha|workflow_sha|event_name|job|action_path|workspace)|runner\.(os|arch|temp|tool_cache)|true|false|null)$'

# True when every context a `${{ }}` expression reads is in $safeExpressionContext, or is an
# input named in $SafeInput (see Get-TypedInput). String literals and function names (format,
# toJSON) are not contexts.
function Test-SafeExpression([string]$Expression, [string[]]$SafeInput = @()) {
    $inner = ($Expression -replace '^\$\{\{|\}\}$') -replace "'(?:[^']|'')*'", "''"
    $references = [regex]::Matches($inner, '(?<![\w.\]-])(?>[A-Za-z_][\w-]*(?:\.[\w*-]+|\[[^\]]*\])*)(?!\s*\()') | ForEach-Object Value
    -not ($references | Where-Object {
            $_ -notmatch $safeExpressionContext -and
            -not ($_ -match '^(github\.event\.)?inputs\.(?<name>[\w-]+)$' -and $Matches.name -in $SafeInput)
        })
}

# Names of the workflow's inputs whose value GitHub restricts to a fixed set: type boolean,
# choice or number, in every trigger that declares the input (workflow_dispatch,
# workflow_call). A string or environment input, or one declared without a type (string for
# workflow_dispatch), can hold any text. A composite action has no `on:` and so no such input.
# Read line by line like Get-InlineScript: on: > trigger > inputs: > name > type:.
function Get-TypedInput([string[]]$Lines) {
    $indentOf = { param($Line) ($Line -replace '\S.*$').Length }
    $types = @{}
    $inOn = $false
    $trigger = $null; $inputsIndent = -1; $name = $null; $nameIndent = -1
    foreach ($line in $Lines) {
        if ($line -match '^\s*(#|$)') { continue }
        $indent = & $indentOf $line
        if ($indent -eq 0) {
            $inOn = $line -match '^(on|"on"|''on''):\s*(#.*)?$'
            $trigger = $null; $inputsIndent = -1; $name = $null
            continue
        }
        if (-not $inOn) { continue }
        if ($name -and $indent -le $nameIndent) { $name = $null }
        if ($inputsIndent -ge 0 -and $indent -le $inputsIndent) { $inputsIndent = -1 }
        if ($trigger -and $indent -le $trigger.Indent) { $trigger = $null }
        $key = if ($line -match '^\s*([\w-]+|"[^"]*"|''[^'']*''):') { $Matches[1].Trim('"', "'") }
        if (-not $trigger) {
            if ($key -in 'workflow_dispatch', 'workflow_call') { $trigger = @{ Name = $key; Indent = $indent } }
            continue
        }
        if ($inputsIndent -lt 0) {
            if ($key -eq 'inputs') { $inputsIndent = $indent }
            continue
        }
        if (-not $name -or $indent -le $nameIndent) {
            # A new input; without a type: it is a string.
            $name = $key; $nameIndent = $indent
            $types["$($trigger.Name)/$name"] = 'string'
            continue
        }
        if ($indent -gt $nameIndent -and $line -match '^\s*type:\s*["'']?(\w+)') { $types["$($trigger.Name)/$name"] = $Matches[1].ToLowerInvariant() }
    }
    $byName = @{}
    foreach ($k in $types.Keys) { $byName[($k -split '/', 2)[1]] += @($types[$k]) }
    @($byName.Keys | Where-Object { -not ($byName[$_] | Where-Object { $_ -notin 'boolean', 'choice', 'number' }) })
}

# A YAML double-quoted scalar's text with its escapes decoded (\n, \t, \", \\, \x24, \u0024, ...).
function ConvertFrom-YamlDoubleQuoted([string]$Text) {
    [regex]::Replace($Text, '\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|.)', {
            param($m)
            $e = $m.Groups[1].Value
            if ($e.Length -gt 1) { return [char]::ConvertFromUtf32([Convert]::ToInt32($e.Substring(1), 16)) }
            switch -CaseSensitive ($e) {
                '0' { [string][char]0 } 'a' { [string][char]7 } 'b' { [string][char]8 } 't' { "`t" } 'n' { "`n" }
                'v' { [string][char]11 } 'f' { [string][char]12 } 'r' { "`r" } 'e' { [string][char]27 }
                'N' { [string][char]0x85 } '_' { [string][char]0xA0 } 'L' { [string][char]0x2028 } 'P' { [string][char]0x2029 }
                default { $e }
            }
        })
}

# Folds the lines of a `>` block scalar the way YAML does: a line break between two lines of
# text becomes a space, an empty line stands for one line break, and lines indented further
# keep their breaks. Returns the folded lines, each with the source line it starts on.
function Get-FoldedLine([string[]]$Body, [int[]]$Source) {
    $out = [System.Collections.Generic.List[object]]::new()
    $previous = $null
    $empty = 0
    for ($k = 0; $k -lt $Body.Count; $k++) {
        $line = $Body[$k]
        if ($line -eq '') { $empty++; continue }
        $more = $line -match '^[ \t]'
        if (-not $previous) {
            for ($n = 0; $n -lt $empty; $n++) { $out.Add([pscustomobject]@{ Text = ''; Line = $Source[$k] }) }
            $out.Add([pscustomobject]@{ Text = $line; Line = $Source[$k] })
        }
        elseif ($empty -eq 0 -and -not $previous.More -and -not $more) {
            $out[$out.Count - 1].Text += ' ' + $line
        }
        else {
            # Between two text lines, the first break of a run of empty lines is folded away.
            $breaks = if (-not $previous.More -and -not $more) { $empty } else { $empty + 1 }
            for ($n = 1; $n -lt $breaks; $n++) { $out.Add([pscustomobject]@{ Text = ''; Line = $Source[$k] }) }
            $out.Add([pscustomobject]@{ Text = $line; Line = $Source[$k] })
        }
        $previous = [pscustomobject]@{ More = $more }
        $empty = 0
    }
    $out
}

# The `run:` blocks of a workflow or composite action that run under `shell: pwsh`, each as
# the script GitHub executes and the line of the file its body starts on, plus the `${{ }}`
# expressions in it that read a context outside $safeExpressionContext. The runner pastes an
# expression's value into the script before PowerShell parses it, so a value with a quote in
# it becomes code; such a value belongs in the step's `env:`.
# Read line by line rather than parsed: the two keys of a step sit at the same indentation, and
# that is all the structure needed. A `defaults.run.shell` is not followed (the repository sets
# the shell per step).
function Get-InlineScript([string]$File) {
    $lines = [System.IO.File]::ReadAllLines((Resolve-Path -LiteralPath $File).ProviderPath)
    $typedInput = @(Get-TypedInput $lines)
    # Column of a line's first key: its indentation, plus the "- " of a list item.
    $keyColumn = { param($Line) if ($Line -match '^(\s*(?:-\s+)?)\S') { $Matches[1].Length } else { -1 } }
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -notmatch '^(?<lead>\s*(?:-\s+)?)run:\s*(?<rest>.*)$') { continue }
        $column = $Matches.lead.Length
        $rest = $Matches.rest
        $end = $i + 1
        $folded = $rest -match '^>'
        if ($rest -match '^[|>][+-]?\d*\s*(#.*)?$') {
            while ($end -lt $lines.Count -and ($lines[$end].Trim() -eq '' -or ($lines[$end] -replace '\S.*$').Length -gt $column)) { $end++ }
            $body = @($lines[($i + 1)..($end - 1)])
            $indent = ($body | Where-Object { $_.Trim() } | ForEach-Object { ($_ -replace '\S.*$').Length } | Measure-Object -Minimum).Minimum
            $body = @($body | ForEach-Object { if ($_.Length -ge $indent) { $_.Substring($indent) } else { '' } })
            $startLine = $i + 2
        }
        else {
            # A quoted scalar is unquoted by YAML before the runner sees it: run: 'Write-Host "$x"'
            # runs Write-Host "$x", not a single-quoted string.
            # A trailing comment can only follow the closing quote.
            if ($rest -match "^'((?:[^']|'')*)'\s*(#.*)?$") { $value = $Matches[1] -replace "''", "'" }
            elseif ($rest -match '^"((?:[^"\\]|\\.)*)"\s*(#.*)?$') { $value = ConvertFrom-YamlDoubleQuoted $Matches[1] }
            else { $value = $rest }
            $body = @($value -split "`n")
            $startLine = $i + 1
        }

        # The step's other keys: lines at the same column, up to the list item that opens the
        # step and down to the first line indented less.
        $shell = $null
        for ($j = $i - 1; $j -ge 0 -and -not $shell -and $lines[$i] -notmatch '^\s*-\s'; $j--) {
            if ($lines[$j] -match '^\s*(#|$)') { continue }
            $c = & $keyColumn $lines[$j]
            if ($c -eq $column -and $lines[$j] -match '^\s*(?:-\s+)?shell:\s*(\S+)') { $shell = $Matches[1] }
            if ($c -lt $column -or $lines[$j] -match '^\s*-\s') { break }
        }
        for ($j = $end; $j -lt $lines.Count -and -not $shell; $j++) {
            if ($lines[$j] -match '^\s*(#|$)') { continue }
            if (($lines[$j] -replace '\S.*$').Length -lt $column) { break }
            if ($lines[$j] -match '^\s*shell:\s*(\S+)' -and (& $keyColumn $lines[$j]) -eq $column) { $shell = $Matches[1] }
        }
        if ($shell -notmatch '^[''"]?pwsh[''"]?$') { continue }

        # An expression may span lines (${{ / inputs.value / }}); the runner substitutes it all the
        # same. It is reported on the line where it opens.
        $joined = $body -join "`n"
        $expressions = foreach ($m in [regex]::Matches($joined, '\$\{\{.*?\}\}', 'Singleline')) {
            $text = $m.Value -replace '\s+', ' '
            if (-not (Test-SafeExpression $text $typedInput)) {
                [pscustomobject]@{ Line = $startLine + ([regex]::Matches($joined.Substring(0, $m.Index), "`n")).Count; Text = $text }
            }
        }
        # A step cannot carry SuppressMessageAttribute: the runner puts a statement in front of the
        # script, so it cannot open with a param() block. A comment in the step takes its place:
        #   # SuppressMessage <RuleName>: <justification>
        # It covers that rule for the whole step.
        $suppress = @{}
        foreach ($line in $body) {
            if ($line -match '^\s*#\s*SuppressMessage\s+(?<rule>\w+)\s*:\s*(?<why>\S.*)$') { $suppress[$Matches.rule] = $Matches.why.Trim() }
        }

        # The source line of each body line; folding joins lines, so it keeps where each starts.
        $lineMap = @(for ($k = 0; $k -lt $body.Count; $k++) { $startLine + $k })
        if ($folded) {
            $fold = @(Get-FoldedLine $body $lineMap)
            $body = @($fold.Text)
            $lineMap = @($fold.Line)
        }

        # For the analysis, an expression is replaced by a variable of the same length, so the
        # script parses and the columns stay put; the unsafe ones are reported above. A multiline
        # expression keeps its line breaks, its later lines blanked, so the line numbers stay put too.
        $text = [regex]::Replace(($body -join "`n"), '\$\{\{.*?\}\}', {
                param($m)
                $parts = $m.Value -split "`n"
                (@('$' + ('_' * ($parts[0].Length - 1))) + @($parts | Select-Object -Skip 1 | ForEach-Object { ' ' * $_.Length })) -join "`n"
            }, 'Singleline')
        # What the runner wraps around a pwsh step: errors stop it, and the exit code of its
        # last native command becomes the step's result.
        [pscustomobject]@{
            StartLine   = $startLine
            LineMap     = $lineMap
            Suppress    = $suppress
            Expressions = @($expressions)
            Script      = "`$ErrorActionPreference = 'stop'`n$text`nif ((Test-Path -LiteralPath variable:\LASTEXITCODE)) { exit `$LASTEXITCODE }"
        }
    }
}

$root = (Get-Location).Path
function Get-RelativePath([string]$FullPath) {
    [System.IO.Path]::GetRelativePath($root, $FullPath) -replace '\\', '/'
}

# Every finding as File/Line/RuleName/Severity/Message, plus Suppression for a suppressed one.
function Invoke-Analysis {
    foreach ($p in $Path) {
        if (-not (Test-Path $p)) { continue }
        Invoke-ScriptAnalyzer -Path $p -Recurse -Settings $settingsTable -IncludeSuppressed |
            Select-Object @{ n = 'File'; e = { Get-RelativePath $_.ScriptPath } }, Line, RuleName, Severity, Message, Suppression
    }
    foreach ($w in $WorkflowPath) {
        if (-not (Test-Path $w)) { continue }
        $file = Get-RelativePath (Resolve-Path -LiteralPath $w).ProviderPath
        foreach ($block in Get-InlineScript $w) {
            foreach ($e in $block.Expressions) {
                $why = $block.Suppress['PwshGuardExpressionInScript']
                [pscustomobject]@{
                    File = $file; Line = $e.Line; RuleName = 'PwshGuardExpressionInScript'; Severity = 'Warning'
                    Suppression = if ($why) { [pscustomobject]@{ Justification = $why } }
                    Message = "$($e.Text) is pasted into the script before PowerShell parses it, so a value with a quote in it runs as code; " +
                    'pass it through the step''s env: and read $env:NAME instead.'
                }
            }
            $map = $block.LineMap
            Invoke-ScriptAnalyzer -ScriptDefinition $block.Script -Settings $settingsTable -IncludeSuppressed |
                # Line 1 of the analysed script is the runner's prefix; the line map leads back to the file.
                Select-Object @{ n = 'File'; e = { $file } },
                @{ n = 'Line'; e = { $map[[Math]::Min([Math]::Max($_.Line - 2, 0), $map.Count - 1)] } },
                RuleName, Severity, Message,
                @{ n = 'Suppression'; e = {
                        if ($_.Suppression) { $_.Suppression }
                        elseif ($block.Suppress[$_.RuleName]) { [pscustomobject]@{ Justification = $block.Suppress[$_.RuleName] } }
                    }
                }
        }
    }
}
# Retried once: a first run that loads the custom rules has been seen to fail with a
# NullReferenceException inside PSScriptAnalyzer that did not reproduce on the next run.
try {
    $all = @(Invoke-Analysis)
}
catch {
    Write-Host "::warning title=PSScriptAnalyzer::Analysis failed ($($_.Exception.Message)); retrying once."
    $all = @(Invoke-Analysis)
}

# A rule listed in the settings' ExcludeRules is not reported. PSScriptAnalyzer applies the list to
# its own rules; the filter here also covers PwshGuardExpressionInScript, which this script raises itself.
$excluded = @($settingsTable.ExcludeRules)
$all = @($all | Where-Object { $_.RuleName -notin $excluded })

$isSecurity = { param($f) "$($f.Severity)" -in 'Error', 'ParseError' -or $ruleSeverity.ContainsKey($f.RuleName) }
function ConvertTo-Finding {
    process {
        [pscustomobject]@{
            File          = $_.File
            Line          = $_.Line
            Rule          = $_.RuleName
            Severity      = if ($ruleSeverity.ContainsKey($_.RuleName)) { $ruleSeverity[$_.RuleName] } else { 'High' }
            Message       = ($_.Message -replace '[\r\n]+', ' ')
            Justification = (@($_.Suppression.Justification | Where-Object { $_ }) -join '; ') -replace '[\r\n]+', ' '
        }
    }
}
$findings = @($all | Where-Object { -not $_.Suppression })
$reported = @($findings | Where-Object { & $isSecurity $_ } | ConvertTo-Finding | Sort-Object { $severityOrder[$_.Severity] }, File, Line)
$suppressed = @($all | Where-Object { $_.Suppression -and (& $isSecurity $_) } | ConvertTo-Finding | Sort-Object File, Line)
# Inline workflow scripts are scanned for security only; their style is not this scan's business.
$style = @($findings | Where-Object { -not (& $isSecurity $_) -and $_.File -notmatch '\.ya?ml$' })

if ($style) {
    Write-Host "::group::Style findings, not reported ($($style.Count))"
    $style | Sort-Object File, Line | Format-Table File, Line, Severity, RuleName -AutoSize | Out-String -Width 250 | Write-Host
    Write-Host '::endgroup::'
}
if ($suppressed) {
    Write-Host "::group::Suppressed security findings ($($suppressed.Count))"
    $suppressed | Format-Table File, Line, Rule, Justification -Wrap | Out-String -Width 250 | Write-Host
    Write-Host '::endgroup::'
}
if ($reported) {
    Write-Host "::group::Security findings ($($reported.Count))"
    $reported | Format-Table Severity, File, Line, Rule, Message -Wrap | Out-String -Width 250 | Write-Host
    Write-Host '::endgroup::'
}

if (-not $ReportPath) {
    if ($reported) { throw "PSScriptAnalyzer: $($reported.Count) security finding(s)." }
    Write-Host "PSScriptAnalyzer: no security findings ($($style.Count) style, $($suppressed.Count) suppressed)."
    return [pscustomobject]@{ Reported = 0; InChanged = 0; SuppressedInChanged = 0 }
}

$rules = '[PwshGuard rules]({0})' -f $RulesUrl
$icon = @{ High = '🔴'; Medium = '🟠'; Low = '🟡' }

function ConvertTo-TableRow($Finding, [switch]$Suppressed) {
    $location = '{0}:{1}' -f $Finding.File, $Finding.Line
    if ($BlobUrl) { $location = '[{0}]({1}/{2}#L{3})' -f $location, $BlobUrl.TrimEnd('/'), $Finding.File, $Finding.Line }
    if ($Suppressed) {
        $justification = if ($Finding.Justification) { $Finding.Justification -replace '\|', '\|' } else { '_none given_' }
        return '| {0} | `{1}` | {2} |' -f $location, $Finding.Rule, $justification
    }
    $message = $Finding.Message -replace '\|', '\|'
    '| {0} {1} | {2} | `{3}` | {4} |' -f $icon[$Finding.Severity], $Finding.Severity, $location, $Finding.Rule, $message
}

$tableHeader = @('| Severity | Location | Rule | Finding |', '| --- | --- | --- | --- |')
# pwsh -File passes a list as one string, so accept comma- or newline-separated paths too.
$changed = @($ChangedFile -split '[,\r\n]+' | Where-Object { $_ } | ForEach-Object { $_.Trim() -replace '\\', '/' })
$inChanged = @($reported | Where-Object File -In $changed)
$elsewhere = @($reported | Where-Object File -NotIn $changed)
$suppressedInChanged = @($suppressed | Where-Object File -In $changed)

# A comment holds at most 65536 characters. The budget covers the whole report (changed-file
# findings first), leaving room for the headings and footer; rows past it stay in the job log.
$budget = 60000
$footer = ("<sub>Findings do not block the merge. {0} · accept a deliberate case with " +
    "<code>[Diagnostics.CodeAnalysis.SuppressMessageAttribute('&lt;Rule&gt;', '', Justification = '...')]</code> " +
    "on the enclosing function or the script's <code>param()</code> block.</sub>") -f $rules
$used = 1000 + $footer.Length
function Add-Rows($Findings, $Lines, [switch]$Suppressed) {
    $shown = 0
    foreach ($f in $Findings) {
        $row = ConvertTo-TableRow $f -Suppressed:$Suppressed
        if ($script:used + $row.Length + 1 -gt $budget) { break }
        $Lines.Add($row)
        $script:used += $row.Length + 1
        $shown++
    }
    if ($shown -lt @($Findings).Count) { $Lines.Add(''); $Lines.Add("_$(@($Findings).Count - $shown) more in the job log (comment size limit)._") }
}

$md = [System.Collections.Generic.List[string]]::new()
$md.Add('<!-- pwshguard-findings-report -->')
$md.Add('## 🛡️ PwshGuard: PowerShell security scan')
$md.Add('')
if ($inChanged) {
    $md.Add("⚠️ $($inChanged.Count) finding(s) in PowerShell changed by this pull request.")
    $md.Add('')
    $tableHeader | ForEach-Object { $md.Add($_) }
    Add-Rows $inChanged $md
}
else {
    $md.Add('✅ No security findings in PowerShell changed by this pull request.')
}

# A suppression takes a finding out of this report for good, so the pull request that touches
# the file shows it once more, with the reason given.
if ($suppressedInChanged) {
    $md.Add('')
    $md.Add("🔕 $($suppressedInChanged.Count) suppressed finding(s) in files changed by this pull request. Check that each justification holds.")
    $md.Add('')
    $md.Add('| Location | Rule | Justification |')
    $md.Add('| --- | --- | --- |')
    Add-Rows $suppressedInChanged $md -Suppressed
}

if ($elsewhere) {
    $md.Add('')
    $md.Add("<details><summary>$($elsewhere.Count) finding(s) elsewhere in the repository</summary>")
    $md.Add('')
    $tableHeader | ForEach-Object { $md.Add($_) }
    Add-Rows $elsewhere $md
    $md.Add('')
    $md.Add('</details>')
}

$md.Add('')
$md.Add($footer)

[System.IO.File]::WriteAllText($ReportPath, ($md -join "`n") + "`n")
Write-Host "PSScriptAnalyzer: $($reported.Count) security finding(s), $($inChanged.Count) in changed files, $($suppressedInChanged.Count) suppressed in changed files; report written to $ReportPath."
[pscustomobject]@{ Reported = $reported.Count; InChanged = $inChanged.Count; SuppressedInChanged = $suppressedInChanged.Count }

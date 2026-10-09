# PwshGuard: security rules for PowerShell that runs in GitHub Actions, for PSScriptAnalyzer.
#
# PSScriptAnalyzer's built-in security rules target interactive Windows administration
# (plain-text password parameters, hardcoded computer names). PowerShell in a pipeline
# runs in GitHub Actions instead: it holds OIDC credentials and state access, reads
# untrusted input (PR text, plan JSON, Graph data, model output), writes workflow command
# files, and gates deployments. These rules cover that surface.
#
# Loaded through CustomRulePath (Invoke-PwshGuard.ps1 adds it to the settings). Every rule inspects the
# whole file once (root ScriptBlockAst) and reports under the rule name below, which is
# also the name to use in [Diagnostics.CodeAnalysis.SuppressMessageAttribute()].

using namespace System.Management.Automation.Language

# Native tools are recognised by shape (Test-PwshGuardNativeCommand): a name without a hyphen that is
# not a function, an alias or a keyword. A hyphenated tool looks like a cmdlet, so those are
# listed here, together with the tools the repository relies on most.
$script:NativeTools = @(
    'tofu', 'terraform', 'terragrunt', 'statebridge', 'gh', 'az', 'git', 'jq', 'curl',
    'node', 'npm', 'npx', 'dotnet', 'docker', 'pre-commit', 'terraform-docs', 'tar', 'zip', 'unzip',
    'apt-get', 'docker-compose', 'ssh-keygen'
)
# Aliases that exist on Windows only. The scripts run on Linux runners, where these names
# start the native program.
$script:UnixNative = @('cat', 'clear', 'cp', 'diff', 'kill', 'ls', 'man', 'mount', 'mv', 'ps', 'rm', 'rmdir', 'sleep', 'sort', 'tee')
# Hyphen-less names that are PowerShell commands all the same: the aliases, the built-in
# functions, Pester's keywords, and the keywords that parse as a command after || or &&.
$script:NotNative = @(
    (Get-Alias).Name | Where-Object { $_ -notin $script:UnixNative }
    'throw', 'exit', 'return', 'break', 'continue'
    'help', 'oss', 'pause', 'prompt', 'tabexpansion2'
    'describe', 'context', 'it', 'should', 'mock', 'beforeall', 'beforeeach', 'afterall', 'aftereach',
    'beforediscovery', 'inmodulescope'
)

# A name is split into words (accessToken, ARM_CLIENT_SECRET) and judged by its last words: the
# secret is what the name ends in. $tokenCount, $secretPath and $tokenResponse describe something
# about a secret; $adminPassword and $profileToken are one.
$script:SecretWord = '^(\w*(token|secret|password|passwd|bearer|credential|apikey|privatekey|connectionstring|accesskey)|sas)$'
$script:SecretPair = @('api key', 'private key', 'connection string', 'access key', 'account key', 'sas url', 'sas uri')
# Words that may follow the secret word without changing what the variable holds.
$script:SecretSuffix = @('value', 'text', 'string', 'plain', 'plaintext', 'raw')
# Leading words that make the name a quantity or a flag ($maxTokens is plural anyway; $hasToken).
$script:NotSecretLead = @('max', 'min', 'total', 'num', 'has', 'is', 'use', 'uses', 'no', 'skip', 'need', 'needs', 'with', 'include')

function New-PwshGuardRecord {
    param(
        [Parameter(Mandatory)][Ast]$Ast,
        [Parameter(Mandatory)][string]$RuleName,
        [Parameter(Mandatory)][string]$Message,
        [string]$Severity = 'Warning'
    )
    [Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord]@{
        Message  = $Message
        Extent   = $Ast.Extent
        RuleName = $RuleName
        Severity = $Severity
    }
}

function Find-PwshGuardAst {
    param([Ast]$Root, [scriptblock]$Predicate)
    $Root.FindAll($Predicate, $true)
}

function Get-PwshGuardCommandName {
    param([CommandAst]$Command)
    $name = $Command.GetCommandName()
    if (-not $name) { return $null }
    ($name -replace '\.exe$', '').ToLowerInvariant()
}

# True when $Ast is something an attacker-influenced value can flow through: anything but
# a constant string or number.
function Test-PwshGuardNonConstant {
    param([Ast]$Ast)
    if ($Ast -is [CommandParameterAst]) { return $false }
    if ($Ast -is [StringConstantExpressionAst] -or $Ast -is [ConstantExpressionAst]) { return $false }
    if ($Ast -is [ExpandableStringExpressionAst]) { return $Ast.NestedExpressions.Count -gt 0 }
    $true
}

# True when the parameter as typed binds to one of $Name. PowerShell accepts any unambiguous
# prefix (-Rec for -Recurse, -SkipCert for -SkipCertificateCheck); an ambiguous one fails to
# bind at run time, so treating every prefix as a match cannot hide a working call.
# $MinLength keeps short prefixes that are full parameters of other commands
# (Select-Object -Skip) from matching.
function Test-PwshGuardParameterName {
    param([string]$Typed, [string[]]$Name, [int]$MinLength = 1)
    if (-not $Typed) { return $false }
    foreach ($n in $Name) {
        if ($Typed -eq $n) { return $true }
        if ($Typed.Length -ge $MinLength -and $n.StartsWith($Typed, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    $false
}

# Returns the argument bound to -Name (exact, alias, or unambiguous prefix) or $null; a switch
# returns the CommandParameterAst itself.
function Get-PwshGuardParameter {
    param([CommandAst]$Command, [string[]]$Name)
    $elements = $Command.CommandElements
    for ($i = 1; $i -lt $elements.Count; $i++) {
        $e = $elements[$i]
        if ($e -isnot [CommandParameterAst] -or -not (Test-PwshGuardParameterName $e.ParameterName $Name)) { continue }
        if ($e.Argument) { return $e.Argument }
        if ($i + 1 -lt $elements.Count -and $elements[$i + 1] -isnot [CommandParameterAst]) { return $elements[$i + 1] }
        return $e
    }
    $null
}

# Arguments bound by position: elements that are neither a parameter nor the value of one.
# $Switch lists the command's switch parameters, which take no value.
function Get-PwshGuardPositional {
    param([CommandAst]$Command, [string[]]$Switch = @())
    $elements = @($Command.CommandElements | Select-Object -Skip 1)
    for ($i = 0; $i -lt $elements.Count; $i++) {
        $e = $elements[$i]
        if ($e -is [CommandParameterAst]) {
            if (-not $e.Argument -and -not (Test-PwshGuardParameterName $e.ParameterName ($Switch + 'Verbose', 'Debug') -MinLength 3)) { $i++ }
            continue
        }
        $e
    }
}

function Test-PwshGuardSecretName {
    param([string]$Name)
    # Drop the drive or scope (env:, script:), then split on separators and camelCase humps.
    $Name = $Name -replace '^\w+:', ''
    $words = @([regex]::Split($Name, '[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])') |
            Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
    if (-not $words -or $words[0] -in $script:NotSecretLead) { return $false }
    $last = -1
    for ($i = 0; $i -lt $words.Count; $i++) {
        if ($i + 1 -lt $words.Count -and "$($words[$i]) $($words[$i + 1])" -in $script:SecretPair) { $last = $i + 1 }
        elseif ($words[$i] -match $script:SecretWord) { $last = [Math]::Max($last, $i) }
    }
    if ($last -lt 0) { return $false }
    -not ($words | Select-Object -Skip ($last + 1) | Where-Object { $_ -notin $script:SecretSuffix })
}

# True when $Ast emits a secret-named value as is: $token, "...$token...", $response.access_token
# (not $token.Length).
function Test-PwshGuardSecretDirect {
    param([Ast]$Ast)
    if ($Ast -is [VariableExpressionAst]) { return (Test-PwshGuardSecretName $Ast.VariablePath.UserPath) }
    if ($Ast -is [ExpandableStringExpressionAst]) {
        return [bool]($Ast.NestedExpressions | Where-Object { Test-PwshGuardSecretDirect $_ })
    }
    # A property is judged by its own name: $response.access_token is the secret, $token.Length is not.
    if ($Ast -is [MemberExpressionAst] -and $Ast -isnot [InvokeMemberExpressionAst]) {
        return $Ast.Member -is [StringConstantExpressionAst] -and (Test-PwshGuardSecretName $Ast.Member.Value)
    }
    if ($Ast -is [SubExpressionAst] -and $Ast.SubExpression.Statements.Count -eq 1) {
        $only = $Ast.SubExpression.Statements[0]
        if ($only -is [PipelineAst] -and $only.PipelineElements.Count -eq 1 -and $only.PipelineElements[0] -is [CommandExpressionAst]) {
            return Test-PwshGuardSecretDirect $only.PipelineElements[0].Expression
        }
        return $false
    }
    # Concatenation, formatting, parentheses and arrays pass the text through; a comparison
    # ($token -eq $null) yields only a Boolean.
    if ($Ast -is [BinaryExpressionAst]) {
        if ($Ast.Operator -notin 'Plus', 'Multiply', 'Format', 'Join', 'Ireplace', 'Creplace', 'Isplit', 'Csplit') { return $false }
        return (Test-PwshGuardSecretDirect $Ast.Left) -or (Test-PwshGuardSecretDirect $Ast.Right)
    }
    if ($Ast -is [ArrayLiteralAst]) { return [bool]($Ast.Elements | Where-Object { Test-PwshGuardSecretDirect $_ }) }
    if ($Ast -is [ParenExpressionAst] -and $Ast.Pipeline -is [PipelineAst] -and $Ast.Pipeline.PipelineElements.Count -eq 1 -and
        $Ast.Pipeline.PipelineElements[0] -is [CommandExpressionAst]) {
        return Test-PwshGuardSecretDirect $Ast.Pipeline.PipelineElements[0].Expression
    }
    $false
}

# The function body or script a node runs in: the scope its variables live in.
function Get-PwshGuardScope {
    param([Ast]$Node)
    $n = $Node.Parent
    while ($n -and -not ($n -is [ScriptBlockAst] -and ($null -eq $n.Parent -or $n.Parent -is [FunctionDefinitionAst]))) { $n = $n.Parent }
    $n
}

# The variable an assignment writes: $x, and also [string]$x or [ValidateNotNull()][string]$x,
# whose left-hand side wraps the variable in type constraints and attributes.
function Get-PwshGuardAssignedVariable {
    param([Ast]$Left)
    while ($Left -is [AttributedExpressionAst]) { $Left = $Left.Child }
    if ($Left -is [VariableExpressionAst]) { $Left }
}

# The last assignment to $Name in $Node's scope before $Node, or $null. Assignments inside
# nested functions belong to another scope and are skipped.
function Get-PwshGuardEffectiveAssignment {
    param([Ast]$Node, [string]$Name)
    $scope = Get-PwshGuardScope $Node
    if (-not $scope) { return $null }
    $scope.FindAll({
            $args[0] -is [AssignmentStatementAst] -and (Get-PwshGuardAssignedVariable $args[0].Left).VariablePath.UserPath -eq $Name
        }, $true) |
        Where-Object { $_.Extent.EndOffset -le $Node.Extent.StartOffset -and (Get-PwshGuardScope $_) -eq $scope } |
        Sort-Object { $_.Extent.StartOffset } | Select-Object -Last 1 |
        Where-Object {
            # Only an assignment that always runs before the use resolves it. One inside a branch, a
            # loop, a catch or a script block that does not also hold the use may not have run, so
            # the value stays unknown: if ($x) { $d = New-Guid } does not make $d random.
            $assignment = $_
            $child = $assignment
            for ($a = $assignment.Parent; $a -and $a -ne $scope; $a = $a.Parent) {
                $conditional = $a -is [IfStatementAst] -or $a -is [LoopStatementAst] -or $a -is [SwitchStatementAst] -or
                # A try body or finally block runs; a catch only on failure.
                $a -is [CatchClauseAst] -or $a -is [TrapStatementAst] -or $a -is [ScriptBlockExpressionAst] -or $a -is [PipelineChainAst]
                # For if and switch, the use must be in the same branch: an assignment in the then-branch
                # has not run when the else-branch does.
                $container = if ($a -is [IfStatementAst] -or $a -is [SwitchStatementAst]) { $child } else { $a }
                if ($conditional -and -not ($Node.Extent.StartOffset -ge $container.Extent.StartOffset -and $Node.Extent.EndOffset -le $container.Extent.EndOffset)) { return $false }
                $child = $a
            }
            $true
        }
}

# True when $Variable is a parameter of its own scope that PowerShell guarantees non-empty and
# the scope never reassigns: [ValidateNotNullOrEmpty()], [ValidateNotNullOrWhiteSpace()], a
# [ValidateSet()] without an empty member, or Mandatory in every parameter set without
# [AllowEmptyString()] / [AllowNull()] (a Mandatory [string] refuses '' and $null).
function Test-PwshGuardNonEmptyParameter {
    param([Ast]$Variable)
    if ($Variable -isnot [VariableExpressionAst]) { return $false }
    $name = $Variable.VariablePath.UserPath
    $scope = Get-PwshGuardScope $Variable
    if (-not $scope) { return $false }
    $parameters = @($scope.ParamBlock.Parameters) + @(if ($scope.Parent -is [FunctionDefinitionAst]) { $scope.Parent.Parameters })
    $parameter = $parameters | Where-Object { $_ -and $_.Name.VariablePath.UserPath -eq $name } | Select-Object -First 1
    if (-not $parameter) { return $false }
    $reassigned = $scope.FindAll({
            $args[0] -is [AssignmentStatementAst] -and (Get-PwshGuardAssignedVariable $args[0].Left).VariablePath.UserPath -eq $name
        }, $true)
    if ($reassigned) { return $false }

    $attributes = @($parameter.Attributes | Where-Object { $_ -is [AttributeAst] })
    $named = { param($a) $a.TypeName.Name -replace 'Attribute$' }
    if ($attributes | Where-Object { (& $named $_) -in 'ValidateNotNullOrEmpty', 'ValidateNotNullOrWhiteSpace' }) { return $true }
    $set = $attributes | Where-Object { (& $named $_) -eq 'ValidateSet' } | Select-Object -First 1
    if ($set -and $set.PositionalArguments.Count -and -not ($set.PositionalArguments | Where-Object {
                $_ -isnot [StringConstantExpressionAst] -or -not $_.Value.Trim() })) { return $true }
    if ($attributes | Where-Object { (& $named $_) -in 'AllowEmptyString', 'AllowNull', 'AllowEmptyCollection' }) { return $false }
    $parameterAttributes = @($attributes | Where-Object { (& $named $_) -eq 'Parameter' })
    if (-not $parameterAttributes) { return $false }
    -not ($parameterAttributes | Where-Object {
            $arguments = @($_.NamedArguments)
            $mandatory = $arguments | Where-Object { $_.ArgumentName -eq 'Mandatory' }
            # Mandatory in one parameter set leaves the parameter unbound in the others.
            # [Parameter(Mandatory)] omits the value; [Parameter(Mandatory = $true)] spells it.
            -not $mandatory -or (-not $mandatory.ExpressionOmitted -and $mandatory.Argument.Extent.Text -ne '$true') -or
            ($arguments | Where-Object { $_.ArgumentName -eq 'ParameterSetName' -and $_.Argument.Extent.Text -notmatch '__AllParameterSets' })
        })
}

# True when the switch named $Name is on: present without a value, or with :$true. -Skip:$false
# keeps the check. A splat entry (Name = $value) counts the same way.
function Test-PwshGuardSwitchOn {
    param([CommandAst]$Command, [string[]]$Name, [int]$MinLength = 1)
    $off = { param($Value) $Value -and $Value.Extent.Text -in '$false', '0', '$null' }
    foreach ($e in $Command.CommandElements) {
        if ($e -is [CommandParameterAst] -and (Test-PwshGuardParameterName $e.ParameterName $Name -MinLength $MinLength)) {
            if (-not (& $off $e.Argument)) { return $true }
        }
    }
    foreach ($splat in $Command.CommandElements | Where-Object { $_ -is [VariableExpressionAst] -and $_.Splatted }) {
        $assignment = Get-PwshGuardEffectiveAssignment $Command $splat.VariablePath.UserPath
        $table = if ($assignment) { $assignment.Right.Find({ $args[0] -is [HashtableAst] }, $true) }
        foreach ($pair in $table.KeyValuePairs) {
            if ($pair.Item1.Extent.Text.Trim("'", '"') -in $Name -and -not (& $off $pair.Item2)) { return $true }
        }
    }
    $false
}

# True when $Ast produces an unguessable value: a new GUID, Get-Random, or the
# cryptographic random number generator. Inspects calls, not text, so a literal 'NewGuid'
# does not count.
function Test-PwshGuardRandomAst {
    param([Ast]$Ast)
    [bool]$Ast.Find({
            $n = $args[0]
            ($n -is [CommandAst] -and $n.GetCommandName() -in 'New-Guid', 'Get-Random') -or
            ($n -is [InvokeMemberExpressionAst] -and $n.Expression -is [TypeExpressionAst] -and (
                ($n.Member.Extent.Text -eq 'NewGuid' -and $n.Expression.TypeName.FullName -match '^(System\.)?Guid$') -or
                ($n.Member.Extent.Text -eq 'GetRandomFileName' -and $n.Expression.TypeName.FullName -match '^(System\.)?IO\.Path$') -or
                # Only the methods that return random data; [RandomNumberGenerator]::Create() interpolates
                # as a fixed type name.
                ($n.Member.Extent.Text -in 'GetBytes', 'GetInt32', 'GetHexString', 'GetString' -and
                $n.Expression.TypeName.FullName -match 'RandomNumberGenerator$')))
        }, $true)
}

# The expression a value comes from: for a variable, the right-hand side of its effective
# assignment (one step); otherwise the node itself.
function Resolve-PwshGuardValue {
    param([Ast]$Ast)
    if ($Ast -isnot [VariableExpressionAst]) { return $Ast }
    $assignment = Get-PwshGuardEffectiveAssignment $Ast $Ast.VariablePath.UserPath
    if (-not $assignment) { return $Ast }
    $right = $assignment.Right
    if ($right -is [PipelineAst] -and $right.PipelineElements.Count -eq 1) { $right = $right.PipelineElements[0] }
    if ($right -is [CommandExpressionAst]) { return $right.Expression }
    $right
}

# The elements of an array argument: $a, $b and @($a, $b) each yield $a and $b; anything else
# is returned as is.
function Get-PwshGuardArrayElement {
    param([Ast]$Ast)
    if ($Ast -is [ArrayLiteralAst]) { return $Ast.Elements }
    if ($Ast -is [ArrayExpressionAst]) {
        foreach ($statement in $Ast.SubExpression.Statements) {
            $inner = if ($statement -is [PipelineAst] -and $statement.PipelineElements.Count -eq 1 -and
                $statement.PipelineElements[0] -is [CommandExpressionAst]) { $statement.PipelineElements[0].Expression }
            else { $statement }
            Get-PwshGuardArrayElement $inner
        }
        return
    }
    $Ast
}

# True when $Command starts an external program, whose failure PowerShell does not turn into
# an error. $Functions holds the functions the file defines.
function Test-PwshGuardNativeCommand {
    param([CommandAst]$Command, [hashtable]$Functions, [ScriptBlockAst]$Root)
    $name = Get-PwshGuardCommandName $Command
    if (-not $name) {
        # & $tool: native unless the variable holds a script block or a script. A variable of
        # unknown origin (a loop variable, a dot-sourced value) is given the benefit of the doubt.
        $first = $Command.CommandElements[0]
        if ($Command.InvocationOperator -ne 'Ampersand' -or $first -isnot [VariableExpressionAst]) { return $false }
        $variable = $first.VariablePath.UserPath
        $isCode = { param($Value) $Value -and ($Value.Extent.Text -match '\.ps1\b' -or $Value.Find({ $args[0] -is [ScriptBlockExpressionAst] }, $true)) }
        # The assignment in effect at this call decides; a later reassignment does not reach back.
        $effective = Get-PwshGuardEffectiveAssignment $Command $variable
        if ($effective) { return -not (& $isCode $effective.Right) }
        $sources = @(
            $Root.FindAll({ $args[0] -is [AssignmentStatementAst] -and $args[0].Left.Extent.Text -match "^(\[[^\]]+\])?\`$$([regex]::Escape($variable))$" }, $true) |
                ForEach-Object { , @($_.Right, $null) }
            $Root.FindAll({ $args[0] -is [ParameterAst] -and $args[0].Name.VariablePath.UserPath -eq $variable }, $true) |
                ForEach-Object { , @($_.DefaultValue, $_) }
        )
        if (-not $sources) { return $false }
        foreach ($source in $sources) {
            $value, $parameter = $source
            if (& $isCode $value) { return $false }
            if ($parameter) {
                if ($parameter.StaticType -eq [scriptblock]) { return $false }
                # An untyped parameter with no default says nothing about what it holds.
                if (-not $value -and $parameter.StaticType -eq [object]) { return $false }
            }
        }
        return $true
    }
    if ($name -match '[\\/]') {
        # A path: a script or a module-qualified cmdlet is PowerShell, anything else a program.
        return $name -notmatch '\.ps1$' -and $name -notmatch '^[\w.]+\\[a-z]+-[a-z]'
    }
    if ($name -in $script:NativeTools) { return $true }
    $name -match '^[\w.+]+$' -and $name -notmatch '\.ps1$' -and
    -not $Functions.ContainsKey($name) -and $name -notin $script:NotNative
}

function Test-PwshGuardRoot {
    param([ScriptBlockAst]$ScriptBlockAst)
    $null -eq $ScriptBlockAst.Parent
}

<#
.SYNOPSIS
    An entry-point script does not stop on errors.
.DESCRIPTION
    Without $ErrorActionPreference = 'Stop', a failing cmdlet writes an error and the script
    carries on. A gate or a deployment helper that errors part-way then reports success, so
    the run fails open. Scripts that only define functions (dot-sourced libraries) and Pester
    tests are exempt: they inherit the caller's preference.
#>
function Measure-PwshGuardFailOpenScript {
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    param([Parameter(Mandatory)][ValidateNotNull()][ScriptBlockAst]$ScriptBlockAst)

    if (-not (Test-PwshGuardRoot $ScriptBlockAst)) { return }
    $file = $ScriptBlockAst.Extent.File
    if ($file -and ($file -notmatch '\.ps1$' -or $file -match '\.Tests\.ps1$')) { return }

    $statements = @(
        foreach ($block in @($ScriptBlockAst.BeginBlock, $ScriptBlockAst.ProcessBlock, $ScriptBlockAst.EndBlock)) {
            if ($block) { $block.Statements }
        }
    )
    # Work: anything but a definition or a plain assignment. An assignment whose right-hand
    # side runs a command ($r = Invoke-RestMethod ...) is work too.
    $isWork = {
        param($s)
        if ($s -is [FunctionDefinitionAst] -or $s -is [TypeDefinitionAst]) { return $false }
        # Set-StrictMode is preamble, commonly placed just before the Stop assignment.
        if ($s -is [PipelineAst] -and $s.PipelineElements.Count -eq 1 -and $s.PipelineElements[0] -is [CommandAst] -and
            (Get-PwshGuardCommandName $s.PipelineElements[0]) -eq 'set-strictmode') { return $false }
        if ($s -is [AssignmentStatementAst]) { return [bool]$s.Right.Find({ $args[0] -is [CommandAst] }, $true) }
        # if ($debug) { $DebugPreference = 'Continue' }: an if that runs no command and whose
        # branches hold only preamble is preamble too.
        if ($s -is [IfStatementAst]) {
            if ($s.Clauses.Item1 | Where-Object { $_.Find({ $args[0] -is [CommandAst] }, $true) }) { return $true }
            $branches = @($s.Clauses.Item2) + @($s.ElseClause | Where-Object { $_ })
            return [bool]($branches.Statements | Where-Object { & $isWork $_ })
        }
        $true
    }
    $firstWork = $statements | Where-Object { & $isWork $_ } | Select-Object -First 1
    if (-not $firstWork) { return }

    # A script that sets -ErrorAction on every cmdlet call has decided per call; a script-level
    # preference would not change any of them. Native commands ignore -ErrorAction (see
    # PwshGuardUncheckedNativeCommand), and the file's own functions are judged by their contents.
    $functions = @{}
    foreach ($f in Find-PwshGuardAst $ScriptBlockAst { $args[0] -is [FunctionDefinitionAst] }) { $functions[$f.Name] = $f }
    $cmdlets = @(Find-PwshGuardAst $ScriptBlockAst { $args[0] -is [CommandAst] } | Where-Object {
            $name = $_.GetCommandName()
            # & $tool or & $block: no name to judge by, so it cannot count as an explicit cmdlet call.
            -not $name -or (-not (Test-PwshGuardNativeCommand $_ $functions $ScriptBlockAst) -and -not $functions.ContainsKey($name))
        })
    $explicit = {
        param($c)
        $c.CommandElements | Where-Object {
            $_ -is [CommandParameterAst] -and ($_.ParameterName -eq 'ea' -or (Test-PwshGuardParameterName $_.ParameterName 'ErrorAction' -MinLength 6))
        }
    }
    if ($cmdlets.Count -and -not ($cmdlets | Where-Object { -not (& $explicit $_) })) { return }
    # Only native commands: the preference reaches none of them. A .NET method that throws is
    # still only statement-terminating, so a script that calls one does need Stop, and so does one
    # that relies on $PSNativeCommandUseErrorActionPreference, which only turns an exit code into
    # an error record.
    $nativeErrors = $ScriptBlockAst.Find({
            $args[0] -is [AssignmentStatementAst] -and $args[0].Left -is [VariableExpressionAst] -and
            $args[0].Left.VariablePath.UserPath -match '^((script|global):)?PSNativeCommandUseErrorActionPreference$'
        }, $true)
    if (-not $cmdlets.Count -and -not $nativeErrors -and -not $ScriptBlockAst.Find({ $args[0] -is [InvokeMemberExpressionAst] }, $true)) { return }

    # Stop protects only what runs after it.
    $setsStop = $statements | Where-Object {
        $_ -is [AssignmentStatementAst] -and
        $_.Left -is [VariableExpressionAst] -and
        $_.Left.VariablePath.UserPath -match '^((script|global):)?ErrorActionPreference$' -and
        $_.Right.Extent.Text -match "^(['""]?Stop['""]?|\[[\w.]*ActionPreference\]::Stop)$" -and
        $_.Extent.StartOffset -lt $firstWork.Extent.StartOffset
    }
    if ($setsStop) { return }

    $anchor = if ($ScriptBlockAst.ParamBlock) { $ScriptBlockAst.ParamBlock } else { $statements[0] }
    New-PwshGuardRecord -Ast $anchor -RuleName 'PwshGuardFailOpenScript' -Message (
        "Script does not set `$ErrorActionPreference = 'Stop' at script level, so a failing cmdlet " +
        'is reported and skipped and the script can finish as a success (fails open).')
}

<#
.SYNOPSIS
    The exit code of an external tool is ignored.
.DESCRIPTION
    PowerShell does not stop when a native command (tofu, gh, az, git ...) fails, even with
    $ErrorActionPreference = 'Stop'. The exit code must be checked in the statement that
    follows ($LASTEXITCODE or $?), with a `|| throw` chain, or for the whole script with
    $PSNativeCommandUseErrorActionPreference = $true.
    A native command is any command that is not PowerShell's own: no Verb-Noun name, not a
    function of the file, not an alias. That includes a program run by path (./deploy.sh) or
    through a variable (& $tofu).
#>
function Measure-PwshGuardUncheckedNativeCommand {
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    param([Parameter(Mandatory)][ValidateNotNull()][ScriptBlockAst]$ScriptBlockAst)

    if (-not (Test-PwshGuardRoot $ScriptBlockAst)) { return }

    # A check is control flow that reacts to the exit code: an if/loop/switch condition, or an
    # exit/throw, that reads $LASTEXITCODE or $?. A return that carries it only hands the value to
    # the caller (see the 'return' hand-off below). Merely reading it (Write-Host $LASTEXITCODE)
    # is not a check.
    $isCheck = {
        param($Statement, [string[]]$Names = @('LASTEXITCODE', '?'), [int]$After = -1)
        $flow = $Statement.FindAll({
                $args[0] -is [IfStatementAst] -or $args[0] -is [LoopStatementAst] -or $args[0] -is [SwitchStatementAst] -or
                $args[0] -is [ExitStatementAst] -or $args[0] -is [ThrowStatementAst]
            }, $true)
        # Reading $LASTEXITCODE or $? after another native command, or a function of the file,
        # has run tests that command: foreach (...) { git x; if ($LASTEXITCODE) ... } checks
        # git x, not the call before the loop. A captured copy ($After) is not affected.
        $firstOther = if ($After -lt 0) {
            $Statement.FindAll({
                    $args[0] -is [CommandAst] -and ((Test-PwshGuardNativeCommand $args[0] $functions $ScriptBlockAst) -or
                        ($args[0].GetCommandName() -and $functions.ContainsKey($args[0].GetCommandName())))
                }, $true) | ForEach-Object { $_.Extent.StartOffset } | Sort-Object | Select-Object -First 1
        }
        foreach ($node in $flow) {
            if ($node.Extent.StartOffset -le $After) { continue }
            if ($null -ne $firstOther -and $node.Extent.StartOffset -gt $firstOther) { continue }
            # A check inside a function defined here, or a script block stored as a value, does
            # not run at this point.
            $dormant = $false
            for ($a = $node.Parent; $a -and $a -ne $Statement.Parent; $a = $a.Parent) {
                if ($a -is [FunctionDefinitionAst]) { $dormant = $true; break }
                if ($a -is [ScriptBlockExpressionAst] -and $a.Parent -isnot [CommandAst]) { $dormant = $true; break }
            }
            if ($dormant) { continue }
            # A captured exit code reassigned before the check ($code = 0) is no longer the one read.
            if ($After -ge 0) {
                $scope = Get-PwshGuardScope $node
                $overwritten = $scope.FindAll({
                        $args[0] -is [AssignmentStatementAst] -and (Get-PwshGuardAssignedVariable $args[0].Left).VariablePath.UserPath -in $Names
                    }, $true) | Where-Object {
                    $_.Extent.StartOffset -gt $After -and $_.Extent.EndOffset -le $node.Extent.StartOffset -and (Get-PwshGuardScope $_) -eq $scope
                }
                if ($overwritten) { continue }
            }
            $decisive =if ($node -is [IfStatementAst]) { $node.Clauses.Item1 }
            elseif ($node -is [LoopStatementAst] -or $node -is [SwitchStatementAst]) { $node.Condition }
            else { $node.Pipeline }
            foreach ($expression in @($decisive | Where-Object { $_ })) {
                $variables = @($expression.FindAll({ $args[0] -is [VariableExpressionAst] }, $true).VariablePath.UserPath)
                if ($variables | Where-Object { $_ -in $Names }) { return $true }
            }
        }
        $false
    }

    # Cmdlets that never run an external program, so $LASTEXITCODE is the same after them. A
    # cmdlet from a module, or a function, might, and so might an alias that is a native program
    # on Linux (sort, cat, tee, ls, rm, mkdir).
    $quiet = 'write-host', 'write-output', 'echo', 'write-verbose', 'write-warning', 'write-information', 'write-debug',
    'out-file', 'out-null', 'out-string', 'out-host', 'add-content', 'set-content', 'get-content', 'test-path', 'start-sleep',
    'join-path', 'split-path', 'resolve-path', 'convertto-json', 'convertfrom-json', 'convertto-csv', 'convertfrom-csv',
    'select-object', 'select', 'where-object', 'where', '?', 'foreach-object', '%', 'sort-object', 'measure-object',
    'group-object', 'select-string', 'get-date', 'format-table', 'format-list', 'ft', 'fl', 'new-item', 'remove-item',
    'copy-item', 'move-item', 'get-item', 'get-childitem', 'get-filehash', 'import-powershelldatafile', 'export-csv',
    'import-csv', 'tee-object'
    # A statement that leaves $LASTEXITCODE as it is and does not end the script: the runner's
    # exit-code check, or one written further down, still sees the native command's exit code.
    $isTransparent = {
        param($Statement)
        if ($Statement.Find({
                    $a = $args[0]
                    $a -is [ExitStatementAst] -or $a -is [ReturnStatementAst] -or $a -is [ThrowStatementAst] -or
                    $a -is [BreakStatementAst] -or $a -is [ContinueStatementAst] -or
                    ($a -is [AssignmentStatementAst] -and (Get-PwshGuardAssignedVariable $a.Left).VariablePath.UserPath -eq 'LASTEXITCODE') -or
                    ($a -is [CommandAst] -and ($a.InvocationOperator -ne 'Unknown' -or (Get-PwshGuardCommandName $a) -notin $quiet))
                }, $true)) { return $false }
        $true
    }

    # The statements after a native call check it: one reacts to the exit code, or captures it
    # and a later statement in the same scope reacts to the copy. Statements that leave the exit
    # code alone may come first; $? does not survive them, so after one only $LASTEXITCODE counts.
    # Captures: $code = $LASTEXITCODE, and $code = & { ...; native; $LASTEXITCODE }.
    # A native command whose output is assigned is checked, too, when an empty-output guard on
    # that variable throws or exits non-zero: $out = gh api x; if (-not $out) { throw '...' }.
    $checksAfter = {
        param([object[]]$Following, [string]$Output, [bool]$ExitCodeOnly)
        if (-not $Following) { return $false }
        if ($Output -and (& $guardsOutput $Following $Output)) { return $true }
        for ($k = 0; $k -lt $Following.Count; $k++) {
            $next = $Following[$k]
            $names = if ($ExitCodeOnly -or $k -gt 0) { @('LASTEXITCODE') } else { @('LASTEXITCODE', '?') }
            if (& $isCheck $next $names) { return $true }

            $capture = $null
            $source = if ($names -contains '?') { '^\$(LASTEXITCODE|\?)$' } else { '^\$LASTEXITCODE$' }
            if ($next -is [AssignmentStatementAst] -and $next.Left -is [VariableExpressionAst] -and
                $next.Right.Extent.Text -match $source) {
                $capture = $next
            }
            elseif ($next.Extent.Text -match '^\$LASTEXITCODE$' -and $k -eq $Following.Count - 1) {
                # Last statement of a script block whose output is assigned.
                $n = $next.Parent
                while ($n -and $n -isnot [AssignmentStatementAst] -and $n -isnot [FunctionDefinitionAst]) { $n = $n.Parent }
                if ($n -is [AssignmentStatementAst] -and $n.Left -is [VariableExpressionAst]) { $capture = $n }
            }
            if ($capture) {
                $scope = Get-PwshGuardScope $capture
                return [bool]($scope -and (& $isCheck $scope @($capture.Left.VariablePath.UserPath) $capture.Extent.EndOffset))
            }
            if (-not (& $isTransparent $next)) { return $false }
        }
        $false
    }

    # A later statement of the block tests $Name for emptiness and stops on it, before anything
    # reassigns $Name. Only throw or a non-zero exit stops.
    $guardsOutput = {
        param([object[]]$Following, [string]$Name)
        $v = [regex]::Escape($Name)
        $empty = "^(-not\s*\(?\s*\`$$v\s*\)?|!\s*\`$$v|\`$null\s+-eq\s+\`$$v|\`$$v\s+-eq\s+\`$null|\[string\]::IsNullOr(Empty|WhiteSpace)\(\s*\`$$v\s*\))$"
        foreach ($s in $Following) {
            if ($s -is [IfStatementAst] -and $s.Clauses[0].Item1.Extent.Text.Trim() -match $empty -and ($s.Clauses[0].Item2.Statements | Where-Object {
                        $_ -is [ThrowStatementAst] -or ($_ -is [ExitStatementAst] -and $_.Pipeline -and $_.Pipeline.Extent.Text -notmatch '^0+$')
                    })) { return $true }
            if ($s.Find({ $args[0] -is [AssignmentStatementAst] -and (Get-PwshGuardAssignedVariable $args[0].Left).VariablePath.UserPath -eq $Name }, $true)) { return $false }
        }
        $false
    }

    # The variable a native call's output is assigned to: $out = gh api x, also piped through
    # cmdlets ($out = gh api x | ConvertFrom-Json), or $null.
    $outputOf = {
        param($Statement, $Call)
        if ($Statement -isnot [AssignmentStatementAst] -or $Statement.Operator -ne 'Equals') { return $null }
        $variable = Get-PwshGuardAssignedVariable $Statement.Left
        if ($variable -and $Statement.Right -is [PipelineAst] -and $Statement.Right.PipelineElements[0] -eq $Call) { $variable.VariablePath.UserPath }
    }

    # $PSNativeCommandUseErrorActionPreference protects a call when its latest assignment before
    # the call, in the nearest scope that assigns it, is $true. Scopes are the function the call
    # is in, then the script.
    $isNativeErrorScope = {
        param($Cmd)
        $node = $Cmd
        while ($node) {
            $assignment = Get-PwshGuardEffectiveAssignment $node 'PSNativeCommandUseErrorActionPreference'
            if ($assignment) { return $assignment.Right.Extent.Text -eq '$true' }
            $scope = Get-PwshGuardScope $node
            if (-not $scope -or -not $scope.Parent) { return $false }
            $node = $scope.Parent
        }
        $false
    }

    # Follows the call to the statement that holds it. Returns 'checked', 'unchecked', or a
    # hand-off: the call is the last statement of a function (the caller sees the exit code)
    # or of a script block passed to a command (Invoke-Checked { git fetch }).
    $resolve = {
        param($Start)
        $node = $Start
        # Set once the call is followed by statements that leave its exit code alone: from then
        # on $? no longer reflects it.
        $skipped = $false
        while ($node.Parent) {
            $parent = $node.Parent
            # Only `|| throw` / `|| exit` stops on failure. With && or a non-terminating ||, the chain
            # as a whole is the statement whose exit code still needs a check.
            if ($parent -is [PipelineChainAst] -and $parent.LhsPipelineChain -eq $node -and
                $parent.Operator -eq 'OrOr' -and
                # `|| exit 0` turns the failure into success; only an exit that stays a failure counts.
                $parent.RhsPipeline.Extent.Text -match '^(throw\b|exit\s+(\$LASTEXITCODE\b|-?0*[1-9]\d*\s*$))') { return @{ State = 'checked' } }
            # @(...) and $(...) wrap the call in a statement block of their own. Only its last statement
            # hands its exit code to the outer statement; an earlier one, as in @(git fetch; git push),
            # must be checked inside the block.
            if ($parent -is [StatementBlockAst] -and ($parent.Parent -is [ArrayExpressionAst] -or $parent.Parent -is [SubExpressionAst])) {
                $siblings = @($parent.Statements)
                $index = [array]::IndexOf($siblings, $node)
                if ($index -ge 0 -and $index -lt $siblings.Count - 1) {
                    if (& $checksAfter @($siblings | Select-Object -Skip ($index + 1)) $null $skipped) { return @{ State = 'checked' } }
                    return @{ State = 'unchecked' }
                }
                $node = $parent
                continue
            }
            if ($parent -is [NamedBlockAst] -or $parent -is [StatementBlockAst]) {
                $siblings = @($parent.Statements)
                $index = [array]::IndexOf($siblings, $node)
                $following = @($siblings | Select-Object -Skip ($index + 1))
                if ($index -ge 0 -and (& $checksAfter $following (& $outputOf $node $Start) $skipped)) { return @{ State = 'checked' } }
                # Statements after the call that leave its exit code alone make it the last one.
                $last = $index -eq $siblings.Count - 1 -or ($index -ge 0 -and -not ($following | Where-Object { -not (& $isTransparent $_) }))
                if ($last -and $index -lt $siblings.Count - 1) { $skipped = $true }
                # git push; return $LASTEXITCODE: the function hands the code to its caller as a value.
                $next = if ($index -ge 0 -and $index + 1 -lt $siblings.Count) { $siblings[$index + 1] }
                $function = (Get-PwshGuardScope $node).Parent
                if ($next -is [ReturnStatementAst] -and $next.Pipeline -and $function -is [FunctionDefinitionAst] -and
                    ($next.Pipeline.FindAll({ $args[0] -is [VariableExpressionAst] }, $true).VariablePath.UserPath | Where-Object { $_ -in 'LASTEXITCODE', '?' })) {
                    return @{ State = 'return'; Name = $function.Name }
                }
                # The last statement of a try body or of an if/else branch: the exit code is still
                # current after the enclosing statement, so the check may follow that.
                if ($last -and (($parent.Parent -is [TryStatementAst] -and $parent.Parent.Body -eq $parent) -or
                        $parent.Parent -is [IfStatementAst])) {
                    $node = $parent.Parent
                    continue
                }
                if ($last -and $parent.Parent -is [ScriptBlockAst]) {
                    $owner = $parent.Parent.Parent
                    if ($owner -is [FunctionDefinitionAst]) { return @{ State = 'function'; Name = $owner.Name } }
                    if ($owner -is [ScriptBlockExpressionAst] -and $owner.Parent -is [CommandAst]) {
                        return @{ State = 'block'; Name = $owner.Parent.GetCommandName() }
                    }
                }
                return @{ State = 'unchecked' }
            }
            # The call is inside a condition of a statement that checks the result itself.
            if (($parent -is [IfStatementAst] -or $parent -is [WhileStatementAst] -or $parent -is [DoWhileStatementAst] -or
                    $parent -is [DoUntilStatementAst]) -and (& $isCheck $parent)) { return @{ State = 'checked' } }
            $node = $parent
        }
        @{ State = 'unchecked' }
    }

    $functions = @{}
    foreach ($f in Find-PwshGuardAst $ScriptBlockAst { $args[0] -is [FunctionDefinitionAst] }) { $functions[$f.Name] = $f }
    $allCommands = @(Find-PwshGuardAst $ScriptBlockAst { $args[0] -is [CommandAst] })

    $isChecked = {
        param($Cmd, $Depth)
        $result = & $resolve $Cmd
        switch ($result.State) {
            'checked' { return $true }
            'unchecked' { return $false }
            'block' {
                # Only a wrapper defined in this file that inspects the exit code counts.
                $wrapper = if ($result.Name) { $functions[$result.Name] }
                return [bool]($wrapper -and (& $isCheck $wrapper.Body))
            }
            'return' {
                # Every in-file caller must react to the returned value: in a condition
                # (if ((Invoke-Git) -ne 0)), through a variable a later statement checks
                # ($c = Invoke-Git; if ($c) ...), or through $LASTEXITCODE, which is still set.
                if ($Depth -ge 3) { return $false }
                foreach ($call in @($allCommands | Where-Object { $_.GetCommandName() -eq $result.Name })) {
                    if (& $isChecked $call ($Depth + 1)) { continue }
                    $inCondition = $false
                    for ($a = $call.Parent; $a; $a = $a.Parent) {
                        $conditions = if ($a -is [IfStatementAst]) { $a.Clauses.Item1 } elseif ($a -is [LoopStatementAst] -or $a -is [SwitchStatementAst]) { $a.Condition }
                        if ($conditions | Where-Object { $_ -and $call.Extent.StartOffset -ge $_.Extent.StartOffset -and $call.Extent.EndOffset -le $_.Extent.EndOffset }) { $inCondition = $true; break }
                        if ($a -is [StatementBlockAst] -or $a -is [NamedBlockAst]) { break }
                    }
                    if ($inCondition) { continue }
                    $assignment = $call.Parent
                    while ($assignment -and $assignment -isnot [AssignmentStatementAst] -and $assignment -isnot [StatementBlockAst] -and $assignment -isnot [NamedBlockAst]) { $assignment = $assignment.Parent }
                    $variable = if ($assignment -is [AssignmentStatementAst]) { Get-PwshGuardAssignedVariable $assignment.Left }
                    $scope = if ($variable) { Get-PwshGuardScope $assignment }
                    if ($variable -and $scope -and (& $isCheck $scope @($variable.VariablePath.UserPath) $assignment.Extent.EndOffset)) { continue }
                    return $false
                }
                return $true
            }
            'function' {
                # Every call of the function in this file must check the exit code. A function
                # with no caller here is a library entry point; its callers live elsewhere.
                if ($Depth -ge 3) { return $false }
                $calls = @($allCommands | Where-Object { $_.GetCommandName() -eq $result.Name })
                foreach ($call in $calls) {
                    if (-not (& $isChecked $call ($Depth + 1))) { return $false }
                }
                return $true
            }
        }
    }

    # Select-Object -First or -Index later in the same pipeline stops the program once it has
    # what it needs, before PowerShell records the exit code: $LASTEXITCODE keeps the previous
    # command's value ($null if there was none) and $PSNativeCommandUseErrorActionPreference never
    # fires. -Wait lets the program finish. Test-PwshGuardSwitchOn also reads -Wait:$false and
    # constant splats, and counts a parameter given a value (-First 1) as present.
    $isTruncated = {
        param($Cmd)
        $pipeline = $Cmd.Parent
        if ($pipeline -isnot [PipelineAst]) { return $false }
        $elements = @($pipeline.PipelineElements)
        $index = [array]::IndexOf($elements, $Cmd)
        foreach ($e in @($elements | Select-Object -Skip ($index + 1))) {
            if ($e -is [CommandAst] -and (Get-PwshGuardCommandName $e) -in 'select-object', 'select' -and
                (Test-PwshGuardSwitchOn $e 'First', 'Index') -and -not (Test-PwshGuardSwitchOn $e 'Wait')) { return $true }
        }
        $false
    }

    $commands = $allCommands | Where-Object { Test-PwshGuardNativeCommand $_ $functions $ScriptBlockAst }
    foreach ($cmd in $commands) {
        if (& $isTruncated $cmd) {
            # Only an empty-output guard still works: a program that fails without output is never
            # stopped. $out = gh issue list | Select-Object -First 1; if (-not $out) { throw '...' }
            $statement = $cmd.Parent.Parent
            $block = $statement.Parent
            $output = & $outputOf $statement $cmd
            if ($output -and ($block -is [NamedBlockAst] -or $block -is [StatementBlockAst]) -and
                (& $guardsOutput @($block.Statements | Select-Object -Skip ([array]::IndexOf(@($block.Statements), $statement) + 1)) $output)) { continue }
            $label = Get-PwshGuardCommandName $cmd
            if (-not $label) { $label = $cmd.CommandElements[0].Extent.Text }
            New-PwshGuardRecord -Ast $cmd -RuleName 'PwshGuardUncheckedNativeCommand' -Message (
                "Exit code of '$label' cannot be checked: Select-Object -First/-Index stops it before PowerShell " +
                'records the exit code, so $LASTEXITCODE keeps the previous value. Assign the full output, check ' +
                '$LASTEXITCODE, then select; or add -Wait.')
            continue
        }
        if ((& $isNativeErrorScope $cmd) -or (& $isChecked $cmd 0)) { continue }
        $label = Get-PwshGuardCommandName $cmd
        if (-not $label) { $label = $cmd.CommandElements[0].Extent.Text }
        New-PwshGuardRecord -Ast $cmd -RuleName 'PwshGuardUncheckedNativeCommand' -Message (
            "Exit code of '$label' is not checked. Native commands do not stop the script on " +
            'failure; check $LASTEXITCODE in the next statement or set $PSNativeCommandUseErrorActionPreference = $true.')
    }
}

<#
.SYNOPSIS
    A workflow command file is written unsafely.
.DESCRIPTION
    A line written to $GITHUB_ENV or $GITHUB_PATH changes the environment or the executable
    search path of every later step in the job, so any value an attacker can influence there
    becomes code execution. Multi-line values written to $GITHUB_OUTPUT/$GITHUB_ENV need a
    random delimiter: with a fixed one, a value that contains the delimiter ends the block
    early and the rest is parsed as further outputs.
#>
function Measure-PwshGuardUnsafeWorkflowCommandFile {
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    param([Parameter(Mandatory)][ValidateNotNull()][ScriptBlockAst]$ScriptBlockAst)

    if (-not (Test-PwshGuardRoot $ScriptBlockAst)) { return }

    # $env:GITHUB_ENV, or [Environment]::GetEnvironmentVariable('GITHUB_ENV').
    $envFiles = Find-PwshGuardAst $ScriptBlockAst {
        ($args[0] -is [VariableExpressionAst] -and $args[0].VariablePath.UserPath -in 'env:GITHUB_ENV', 'env:GITHUB_PATH') -or
        ($args[0] -is [InvokeMemberExpressionAst] -and $args[0].Member.Extent.Text -eq 'GetEnvironmentVariable' -and
        $args[0].Arguments.Count -and $args[0].Arguments[0] -is [StringConstantExpressionAst] -and
        $args[0].Arguments[0].Value -in 'GITHUB_ENV', 'GITHUB_PATH')
    }
    # Only writes count: a redirection target, the file of a content cmdlet, or the path of a
    # File write method. A copy in a variable ($f = $env:GITHUB_ENV) is followed one step.
    $isWrite = {
        param($Ref)
        # "$env:GITHUB_ENV" and ($env:GITHUB_ENV) are the same path.
        while ($Ref.Parent -is [ExpandableStringExpressionAst] -or $Ref.Parent -is [ParenExpressionAst] -or
            (($Ref.Parent -is [CommandExpressionAst] -or $Ref.Parent -is [PipelineAst]) -and $Ref.Parent.Parent -isnot [NamedBlockAst] -and
            $Ref.Parent.Parent -isnot [StatementBlockAst] -and $Ref.Parent.Parent -isnot [AssignmentStatementAst])) {
            $Ref = $Ref.Parent
        }
        if ($Ref.Parent -is [FileRedirectionAst]) { return $Ref.Parent.Location -eq $Ref }
        # The destination only: the first argument of a File method, and the path of a content
        # cmdlet (named, or position 0). Add-Content log.txt -Value $env:GITHUB_ENV writes elsewhere.
        $p = $Ref.Parent
        if ($p -is [InvokeMemberExpressionAst]) {
            return $p.Member.Extent.Text -match '^(Append|Write)All(Text|Lines)$' -and $p.Arguments.Count -and $p.Arguments[0] -eq $Ref
        }
        $parameter = $null
        if ($p -is [CommandParameterAst]) { $parameter = $p; $p = $p.Parent }
        if ($p -isnot [CommandAst] -or (Get-PwshGuardCommandName $p) -notin 'add-content', 'set-content', 'out-file', 'tee-object', 'ac', 'sc') { return $false }
        if (-not $parameter) {
            $index = [array]::IndexOf(@($p.CommandElements), $Ref)
            $before = if ($index -gt 0) { $p.CommandElements[$index - 1] }
            if ($before -is [CommandParameterAst] -and -not $before.Argument) { $parameter = $before }
        }
        if ($parameter) { return Test-PwshGuardParameterName $parameter.ParameterName 'Path', 'LiteralPath', 'FilePath', 'PSPath' -MinLength 2 }
        $switches = 'PassThru', 'Force', 'NoNewline', 'AsByteStream', 'Append', 'NoClobber', 'WhatIf', 'Confirm'
        (Get-PwshGuardPositional $p $switches | Select-Object -First 1) -eq $Ref
    }
    foreach ($v in $envFiles) {
        $write = & $isWrite $v
        if (-not $write) {
            $assignment = $v.Parent
            while ($assignment -is [CommandExpressionAst] -or $assignment -is [PipelineAst]) { $assignment = $assignment.Parent }
            if ($assignment -is [AssignmentStatementAst] -and $assignment.Left -is [VariableExpressionAst]) {
                $copy = $assignment.Left.VariablePath.UserPath
                $write = [bool]($ScriptBlockAst.FindAll({ $args[0] -is [VariableExpressionAst] }, $true) | Where-Object {
                        $_.VariablePath.UserPath -eq $copy -and $_ -ne $assignment.Left -and (& $isWrite $_)
                    })
            }
        }
        if (-not $write) { continue }
        $file = if ($v -is [VariableExpressionAst]) { $v.VariablePath.UserPath -replace '^env:', '' } else { $v.Arguments[0].Value }
        New-PwshGuardRecord -Ast $v -RuleName 'PwshGuardUnsafeWorkflowCommandFile' -Message (
            "Writes to `$$file. It alters every later step of the job; " +
            'pass values through $GITHUB_OUTPUT and an explicit env: mapping instead.')
    }

    $heredocs = Find-PwshGuardAst $ScriptBlockAst {
        ($args[0] -is [StringConstantExpressionAst] -or $args[0] -is [ExpandableStringExpressionAst]) -and
        $args[0].Value -match '^(\$\{?[\w:]+\}?|\{\d+\}|[\w-]+)<<'
    }
    # The delimiter has to be unguessable, not merely a variable: $d = 'EOF' is as injectable as a
    # literal. It must be generated inline, or by the variable's effective assignment (the last one
    # before the string, in the same scope).
    # Only strings that reach a command file count: written in the same statement, through a
    # variable that a write uses, or inside a function that writes one.
    $commandFile = '\$env:GITHUB_(OUTPUT|ENV)\b|GetEnvironmentVariable\(\s*[''"]GITHUB_(OUTPUT|ENV)[''"]'
    # A copy of the path ($out = $env:GITHUB_OUTPUT) writes to the command file just the same.
    $copies = @($ScriptBlockAst.FindAll({ $args[0] -is [AssignmentStatementAst] }, $true) |
            Where-Object { $_.Right.Extent.Text -match $commandFile } |
            ForEach-Object { (Get-PwshGuardAssignedVariable $_.Left).VariablePath.UserPath } | Where-Object { $_ } | Sort-Object -Unique)
    if ($copies) { $commandFile += '|\$(' + (($copies | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\b' }
    $reachesCommandFile = {
        param($String)
        $statement = $String
        # @(...) and $(...) hold statement blocks of their own; climb past them to the real statement.
        while ($statement.Parent -and -not ($statement.Parent -is [NamedBlockAst] -or
                ($statement.Parent -is [StatementBlockAst] -and $statement.Parent.Parent -isnot [ArrayExpressionAst] -and
                    $statement.Parent.Parent -isnot [SubExpressionAst]))) {
            $statement = $statement.Parent
        }
        if ($statement.Extent.Text -match $commandFile) { return $true }
        if ($statement -is [AssignmentStatementAst] -and $statement.Left -is [VariableExpressionAst]) {
            $name = [regex]::Escape($statement.Left.VariablePath.UserPath)
            $writes = $ScriptBlockAst.FindAll({ $args[0] -is [StatementAst] -and $args[0] -isnot [FunctionDefinitionAst] }, $true) |
                Where-Object { $_.Extent.Text -match $commandFile -and $_.Extent.Text -match "\`$$name\b" }
            if ($writes) { return $true }
        }
        $function = $String.Parent
        while ($function -and $function -isnot [FunctionDefinitionAst]) { $function = $function.Parent }
        [bool]($function -and $function.Body.Extent.Text -match $commandFile)
    }
    foreach ($s in $heredocs) {
        if (-not (& $reachesCommandFile $s)) { continue }
        $delimiterStart = $s.Extent.StartOffset + $s.Extent.Text.IndexOf('<<')
        $parts = @(
            if ($s -is [ExpandableStringExpressionAst]) { $s.NestedExpressions | Where-Object { $_.Extent.StartOffset -gt $delimiterStart } }
            # 'name<<' + $delimiter and 'name<<{0}' -f $delimiter: the delimiter is the right-hand operand.
            if ($s.Parent -is [BinaryExpressionAst] -and $s.Parent.Left -eq $s -and $s.Parent.Operator -in 'Plus', 'Format') { $s.Parent.Right }
        )
        $randomParts = $parts | Where-Object {
            $part = $_
            if (Test-PwshGuardRandomAst $part) { return $true }
            foreach ($v in $part.FindAll({ $args[0] -is [VariableExpressionAst] }, $true)) {
                $assignment = Get-PwshGuardEffectiveAssignment $s $v.VariablePath.UserPath
                if ($assignment -and (Test-PwshGuardRandomAst $assignment.Right)) { return $true }
            }
            $false
        }
        if (-not $randomParts) {
            New-PwshGuardRecord -Ast $s -RuleName 'PwshGuardUnsafeWorkflowCommandFile' -Message (
                'Multi-line workflow output uses a fixed or predictable delimiter. A value containing it ends the block ' +
                'early and injects further outputs; build the delimiter from a new GUID.')
        }
    }
}

<#
.SYNOPSIS
    A secret can reach the job log.
.DESCRIPTION
    GitHub masks only the secrets it knows. A token or secret obtained at run time (az, gh,
    Get-AzAccessToken, Key Vault, a SecureString turned into plain text) is printed in clear
    unless it is registered with ::add-mask::, and
    printing a variable named like a secret, or recording a transcript, puts it in the log
    that every reader of the repository can open.
#>
function Measure-PwshGuardSecretInOutput {
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    param([Parameter(Mandatory)][ValidateNotNull()][ScriptBlockAst]$ScriptBlockAst)

    if (-not (Test-PwshGuardRoot $ScriptBlockAst)) { return }

    # Commands that pass their input on to the output: $token | Out-String still prints the token.
    $passThrough = 'out-string', 'out-default', 'format-table', 'format-list', 'format-wide', 'format-custom', 'ft', 'fl', 'fw',
    'convertto-json', 'convertto-csv', 'select-object', 'select', 'sort-object', 'sort', 'tee-object', 'tee'
    $writers = 'write-host', 'write-output', 'write-verbose', 'write-information', 'write-debug', 'write-warning',
    'write-error', 'echo', 'out-host', 'start-transcript'
    # "::add-mask::$token", '::add-mask::' + $token or ('::add-mask::{0}' -f $token).
    $isMask = { param($Ast) $Ast.Extent.Text -match '^\(?\s*[''"]::add-mask::' }
    $commands = Find-PwshGuardAst $ScriptBlockAst { $args[0] -is [CommandAst] -and (Get-PwshGuardCommandName $args[0]) -in $writers }
    foreach ($cmd in $commands) {
        $name = Get-PwshGuardCommandName $cmd
        if ($name -eq 'start-transcript') {
            New-PwshGuardRecord -Ast $cmd -RuleName 'PwshGuardSecretInOutput' -Message (
                'Start-Transcript records every value the script prints, including tokens, outside GitHub''s log masking.')
            continue
        }
        $arguments = @($cmd.CommandElements | Select-Object -Skip 1)
        # $token | Write-Host prints it just the same, also through commands that pass their input
        # on ($token | Out-String | Write-Host).
        if ($cmd.Parent -is [PipelineAst]) {
            $elements = $cmd.Parent.PipelineElements
            $index = $elements.IndexOf($cmd) - 1
            while ($index -ge 0 -and $elements[$index] -is [CommandAst] -and (Get-PwshGuardCommandName $elements[$index]) -in $passThrough) { $index-- }
            if ($index -ge 0 -and $elements[$index] -is [CommandExpressionAst]) { $arguments += $elements[$index].Expression }
        }
        # Only the secret itself counts; a derived value such as $token.Length is safe to print,
        # and "::add-mask::$token" is the runner command that masks it.
        if ($arguments | Where-Object { -not (& $isMask $_) -and (Test-PwshGuardSecretDirect $_) }) {
            New-PwshGuardRecord -Ast $cmd -RuleName 'PwshGuardSecretInOutput' -Message (
                "$($cmd.GetCommandName()) prints a value whose name marks it as a secret. Print a fingerprint or length instead.")
        }
    }

    # Implicit output: a bare $token or "token: $token" statement at script level goes to the
    # log just like Write-Output. Inside a function it is the return value, so only the script
    # body counts, and only when the output is not assigned. `return $token` at script level
    # emits the value the same way.
    $bare = Find-PwshGuardAst $ScriptBlockAst {
        $args[0] -is [PipelineAst] -and $args[0].PipelineElements[0] -is [CommandExpressionAst] -and
        ($args[0].Parent -is [NamedBlockAst] -or $args[0].Parent -is [StatementBlockAst] -or $args[0].Parent -is [ReturnStatementAst]) -and
        -not ($args[0].PipelineElements | Select-Object -Skip 1 | Where-Object { $_ -isnot [CommandAst] -or (Get-PwshGuardCommandName $_) -notin $passThrough })
    }
    foreach ($statement in $bare) {
        $n = $statement.Parent
        $inScriptBody = $true
        while ($n) {
            # Inside $(...) or @(...) the value belongs to the enclosing expression, which is judged as a whole.
            if ($n -is [AssignmentStatementAst] -or $n -is [FunctionDefinitionAst] -or $n -is [ScriptBlockExpressionAst] -or
                $n -is [SubExpressionAst] -or $n -is [ArrayExpressionAst]) { $inScriptBody = $false; break }
            $n = $n.Parent
        }
        $expression = $statement.PipelineElements[0].Expression
        if ($inScriptBody -and -not (& $isMask $expression) -and (Test-PwshGuardSecretDirect $expression)) {
            New-PwshGuardRecord -Ast $statement -RuleName 'PwshGuardSecretInOutput' -Message (
                'Emits a value whose name marks it as a secret as script output, which goes to the log.')
        }
    }
    $throws = Find-PwshGuardAst $ScriptBlockAst { $args[0] -is [ThrowStatementAst] -and $args[0].Pipeline }
    foreach ($t in $throws) {
        $element = $t.Pipeline.PipelineElements | Select-Object -First 1
        if ($element -is [CommandExpressionAst] -and (Test-PwshGuardSecretDirect $element.Expression)) {
            New-PwshGuardRecord -Ast $t -RuleName 'PwshGuardSecretInOutput' -Message 'Throws an error message that contains a secret-named value.'
        }
    }

    $tokenSources = Find-PwshGuardAst $ScriptBlockAst {
        $c = $args[0]
        if ($c -isnot [CommandAst]) { return $false }
        $n = Get-PwshGuardCommandName $c
        $t = $c.Extent.Text
        # A SecureString token cannot be printed by accident; -AsSecureString:$false is plain text.
        ($n -eq 'get-azaccesstoken' -and -not ($c.CommandElements | Where-Object {
                    $_ -is [CommandParameterAst] -and (Test-PwshGuardParameterName $_.ParameterName 'AsSecureString' -MinLength 3) -and
                    (-not $_.Argument -or $_.Argument.Extent.Text -eq '$true')
                })) -or
        ($n -in 'convertfrom-securestring', 'get-azkeyvaultsecret' -and ($c.CommandElements | Where-Object {
                $_ -is [CommandParameterAst] -and (Test-PwshGuardParameterName $_.ParameterName 'AsPlainText' -MinLength 3) -and
                (-not $_.Argument -or $_.Argument.Extent.Text -eq '$true')
            })) -or
        ($n -eq 'az' -and $t -match '\b(get-access-token|keyvault\s+secret\s+show|create-for-rbac|credential\s+reset|generate-sas)\b') -or
        ($n -eq 'gh' -and $t -match '\bauth\s+token\b')
    }
    # ::add-mask:: strings that are actually emitted (an argument of Write-Host/Write-Output/echo,
    # or a bare output statement), with the variables they mask, their scope and position.
    $emitters = 'write-host', 'write-output', 'echo', 'write-information'
    $masked = @(
        Find-PwshGuardAst $ScriptBlockAst {
            ($args[0] -is [ExpandableStringExpressionAst] -or $args[0] -is [StringConstantExpressionAst]) -and $args[0].Value -match '::add-mask::'
        } |
            ForEach-Object {
                # "::add-mask::$t", '::add-mask::' + $t and '::add-mask::{0}' -f $t: the mask is the whole expression.
                $mask = $_
                while ($mask.Parent -is [BinaryExpressionAst] -or $mask.Parent -is [ParenExpressionAst] -or
                    ($mask.Parent -is [CommandExpressionAst] -and $mask.Parent.Parent -is [PipelineAst] -and $mask.Parent.Parent.Parent -is [ParenExpressionAst]) -or
                    ($mask.Parent -is [PipelineAst] -and $mask.Parent.Parent -is [ParenExpressionAst])) {
                    $mask = $mask.Parent
                }
                $mask
            } |
            Where-Object {
                $p = $_.Parent
                ($p -is [CommandAst] -and (Get-PwshGuardCommandName $p) -in $emitters) -or
                ($p -is [CommandExpressionAst] -and $p.Parent -is [PipelineAst] -and $p.Parent.PipelineElements.Count -eq 1 -and
                ($p.Parent.Parent -is [NamedBlockAst] -or $p.Parent.Parent -is [StatementBlockAst]))
            } |
            ForEach-Object {
                $mask = $_
                foreach ($v in $mask.FindAll({ $args[0] -is [VariableExpressionAst] }, $true)) {
                    [pscustomobject]@{ Name = $v.VariablePath.UserPath; Offset = $mask.Extent.StartOffset; End = $mask.Extent.EndOffset; Scope = Get-PwshGuardScope $mask }
                }
            }
    )
    foreach ($cmd in $tokenSources) {
        # The token must be captured in a variable, and that variable masked.
        $node = $cmd
        while ($node -and $node -isnot [AssignmentStatementAst]) { $node = $node.Parent }
        $target = if ($node) { (Get-PwshGuardAssignedVariable $node.Left).VariablePath.UserPath }
        # The mask must be emitted after the assignment (before it, it masked the old value), in the
        # same scope (elsewhere it is another variable of the same name), and before the token's
        # first use: once printed unmasked, it stays in the log. A test in a condition is not a use.
        $scope = if ($node) { Get-PwshGuardScope $node }
        if ($target) {
            # Values derived from the token: $plain = ConvertFrom-SecureString $tok.Token -AsPlainText.
            # Masking one of them registers the plain text, which is what would be printed. Reading
            # the token to derive one is not a use.
            $derived = @($scope.FindAll({
                        $args[0] -is [AssignmentStatementAst] -and (Get-PwshGuardAssignedVariable $args[0].Left) -and
                        $args[0].Right.Find({ $args[0] -is [VariableExpressionAst] -and $args[0].VariablePath.UserPath -eq $target }, $true)
                    }, $true) | Where-Object { $_.Extent.StartOffset -gt $node.Extent.EndOffset -and (Get-PwshGuardScope $_) -eq $scope })
            # The first place after $After where $Name is used, other than inside a mask, a
            # condition or the derivation of another value.
            $firstUseOf = {
                param([string]$Name, [int]$After)
                $scope.FindAll({ $args[0] -is [VariableExpressionAst] -and $args[0].VariablePath.UserPath -eq $Name }, $true) |
                    Where-Object {
                        $ref = $_
                        if ($ref.Extent.StartOffset -lt $After -or (Get-PwshGuardScope $ref) -ne $scope) { return $false }
                        if ($masked | Where-Object { $ref.Extent.StartOffset -ge $_.Offset -and $ref.Extent.EndOffset -le $_.End }) { return $false }
                        if ($derived | Where-Object { $ref.Extent.StartOffset -ge $_.Right.Extent.StartOffset -and $ref.Extent.EndOffset -le $_.Right.Extent.EndOffset }) { return $false }
                        for ($a = $ref.Parent; $a; $a = $a.Parent) {
                            if ($a -is [IfStatementAst] -and ($a.Clauses.Item1 | Where-Object { $ref.Extent.StartOffset -ge $_.Extent.StartOffset -and $ref.Extent.EndOffset -le $_.Extent.EndOffset })) { return $false }
                            if ($a -is [LoopStatementAst] -and $a.Condition -and $ref.Extent.StartOffset -ge $a.Condition.Extent.StartOffset -and $ref.Extent.EndOffset -le $a.Condition.Extent.EndOffset) { return $false }
                        }
                        $true
                    } | Sort-Object { $_.Extent.StartOffset } | Select-Object -First 1
            }
            $isMasked = {
                param([string]$Name, [int]$After, [int]$Limit)
                [bool]($masked | Where-Object { $_.Name -eq $Name -and $_.Offset -gt $After -and $_.Offset -lt $Limit -and $_.Scope -eq $scope })
            }
            $firstUse = & $firstUseOf $target $node.Extent.EndOffset
            $limit = if ($firstUse) { $firstUse.Extent.StartOffset } else { [int]::MaxValue }
            if (& $isMasked $target $node.Extent.EndOffset $limit) { continue }
            # A derived value masked after it is assigned, before its own first use and before
            # the token is used in any other way.
            $maskedCopy = $derived | Where-Object {
                $name = (Get-PwshGuardAssignedVariable $_.Left).VariablePath.UserPath
                $use = & $firstUseOf $name $_.Extent.EndOffset
                $copyLimit = [Math]::Min($limit, $(if ($use) { $use.Extent.StartOffset } else { [int]::MaxValue }))
                & $isMasked $name $_.Extent.EndOffset $copyLimit
            }
            if ($maskedCopy) { continue }
        }
        New-PwshGuardRecord -Ast $cmd -RuleName 'PwshGuardSecretInOutput' -Message (
            'Obtains a token at run time without registering that value with ::add-mask::, so GitHub will not mask it if it is printed.')
    }
}

<#
.SYNOPSIS
    Code or a shell command line is built from data.
.DESCRIPTION
    Covers the injection paths Invoke-Expression does not: [scriptblock]::Create,
    InvokeScript, ExpandString, PowerShell.AddScript / Runspace.CreateNestedPipeline,
    Add-Type with built-up source, the call operator on an interpolated
    string, `bash -c` / `pwsh -Command` with a built-up command line (also when the shell
    is called by path), and Start-Process with an interpolated argument, whether one string
    or an array element: Start-Process joins the array into one command line too. Invoke
    the program directly with an argument array instead (or use
    ProcessStartInfo.ArgumentList), so no one re-parses the arguments.
#>
function Measure-PwshGuardDynamicCodeExecution {
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    param([Parameter(Mandatory)][ValidateNotNull()][ScriptBlockAst]$ScriptBlockAst)

    if (-not (Test-PwshGuardRoot $ScriptBlockAst)) { return }

    $invocations = Find-PwshGuardAst $ScriptBlockAst {
        $args[0] -is [InvokeMemberExpressionAst] -and $args[0].Member.Extent.Text -in 'Create', 'InvokeScript', 'NewScriptBlock'
    }
    foreach ($m in $invocations) {
        $target = $m.Expression.Extent.Text
        $isScriptBlockFactory = $target -match '^\[(System\.Management\.Automation\.)?scriptblock\]$' -or
        $target -match 'InvokeCommand$'
        if ($isScriptBlockFactory -and ($m.Arguments | Where-Object { Test-PwshGuardNonConstant $_ })) {
            New-PwshGuardRecord -Ast $m -RuleName 'PwshGuardDynamicCodeExecution' -Message (
                "$target::$($m.Member.Extent.Text)() builds code from a non-constant string.")
        }
    }

    # ExpandString evaluates every $(...) in its argument, so expanding data runs code.
    # AddScript (PowerShell) and CreateNestedPipeline (Runspace) take script text as their
    # first argument; the PowerShell instance is rarely a literal, so any target counts.
    $scriptMethods = Find-PwshGuardAst $ScriptBlockAst {
        $args[0] -is [InvokeMemberExpressionAst] -and $args[0].Arguments.Count -and
        $args[0].Member.Extent.Text -in 'ExpandString', 'AddScript', 'CreateNestedPipeline'
    }
    foreach ($m in $scriptMethods) {
        $method = $m.Member.Extent.Text
        if ($method -eq 'ExpandString' -and $m.Expression.Extent.Text -notmatch 'InvokeCommand$') { continue }
        if (Test-PwshGuardNonConstant $m.Arguments[0]) {
            New-PwshGuardRecord -Ast $m -RuleName 'PwshGuardDynamicCodeExecution' -Message $(
                if ($method -eq 'ExpandString') { 'ExpandString() evaluates subexpressions in a non-constant string; use -f or string interpolation in the script itself.' }
                else { "$method() runs script text built from data; use AddCommand().AddParameter() instead." })
        }
    }

    $commands = Find-PwshGuardAst $ScriptBlockAst { $args[0] -is [CommandAst] }
    foreach ($cmd in $commands) {
        $first = $cmd.CommandElements[0]
        # A path rooted at $PSScriptRoot points into the repository, not at data, as long as nothing
        # else is interpolated: "$PSScriptRoot/$tool" can still be steered (../ segments).
        if ($cmd.InvocationOperator -ne 'Unknown' -and $first -is [ExpandableStringExpressionAst] -and $first.NestedExpressions.Count -and
            -not ($first.NestedExpressions.Count -eq 1 -and $first.NestedExpressions[0] -is [VariableExpressionAst] -and
                $first.NestedExpressions[0].VariablePath.UserPath -eq 'PSScriptRoot' -and $first.Value -match '^\$\{?PSScriptRoot\b')) {
            New-PwshGuardRecord -Ast $cmd -RuleName 'PwshGuardDynamicCodeExecution' -Message (
                'Invokes a command whose name is an interpolated string; resolve the command first and invoke it by path.')
            continue
        }

        # /bin/bash -c "..." is bash all the same: dispatch on the executable's leaf name.
        $name = (Get-PwshGuardCommandName $cmd) -replace '^.*[\\/]', ''
        switch -Regex ($name) {
            '^add-type$' {
                $source = Get-PwshGuardParameter $cmd 'TypeDefinition', 'MemberDefinition'
                if (-not $source -and -not (Get-PwshGuardParameter $cmd 'Path', 'LiteralPath', 'AssemblyName')) {
                    # Positional binding: FromSource takes TypeDefinition at 0; FromMember takes Name at 0
                    # and MemberDefinition at 1 (the first positional once -Name is given by name).
                    $positional = @(Get-PwshGuardPositional $cmd 'PassThru', 'IgnoreWarnings')
                    $source = if (Get-PwshGuardParameter $cmd 'Name') { $positional | Select-Object -First 1 }
                    elseif ($positional.Count -ge 2) { $positional[1] }
                    else { $positional | Select-Object -First 1 }
                }
                if ($source -and (Test-PwshGuardNonConstant $source)) {
                    New-PwshGuardRecord -Ast $cmd -RuleName 'PwshGuardDynamicCodeExecution' -Message 'Add-Type compiles source code built from data.'
                }
            }
            '^(bash|sh|zsh|cmd|pwsh|powershell)$' {
                # The flag that hands over a command line: -c inside a POSIX flag cluster (-lc, -ec),
                # /c or /k for cmd, and any prefix of -Command / -EncodedCommand (-c, -Com, -e, -ec).
                $flag = switch -Regex ($name) {
                    '^cmd$' { '^/[ck]$' }
                    '^(pwsh|powershell)$' { '^-(c|co|com|comm|comma|comman|command|e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)$' }
                    default { '^-[a-z]*c$' }
                }
                $elements = @($cmd.CommandElements | Select-Object -Skip 1)
                for ($i = 0; $i -lt $elements.Count - 1; $i++) {
                    # bash '-c' "..." is the same flag: compare a quoted string by its value.
                    $text = if ($elements[$i] -is [StringConstantExpressionAst]) { $elements[$i].Value } else { $elements[$i].Extent.Text }
                    if ($text -match $flag -and (Test-PwshGuardNonConstant $elements[$i + 1])) {
                        New-PwshGuardRecord -Ast $cmd -RuleName 'PwshGuardDynamicCodeExecution' -Message (
                            "$name re-parses a command line built from data; invoke the program directly with an argument array.")
                        break
                    }
                }
            }
            '^start-process$' {
                $argumentList = Get-PwshGuardParameter $cmd 'ArgumentList', 'Args'
                if (-not $argumentList) {
                    # ArgumentList is position 1 after FilePath, or the first positional once -FilePath is named.
                    $positional = @(Get-PwshGuardPositional $cmd 'LoadUserProfile', 'NoNewWindow', 'PassThru', 'Wait', 'UseNewEnvironment', 'WhatIf', 'Confirm')
                    $argumentList = if (Get-PwshGuardParameter $cmd 'FilePath') { $positional | Select-Object -First 1 }
                    elseif ($positional.Count -ge 2) { $positional[1] }
                }
                # Start-Process joins an argument array into one command line as well, so an
                # interpolated element can still split into extra arguments.
                # A variable is followed to its effective assignment: $a = "plan -var x=$v" is the same string.
                if ($argumentList -and (Get-PwshGuardArrayElement (Resolve-PwshGuardValue $argumentList) | ForEach-Object { Resolve-PwshGuardValue $_ } | Where-Object {
                            $_ -is [ExpandableStringExpressionAst] -and $_.NestedExpressions.Count })) {
                    New-PwshGuardRecord -Ast $cmd -RuleName 'PwshGuardDynamicCodeExecution' -Message (
                        'Start-Process joins its arguments into one command line that the target re-splits, so an interpolated value can add arguments; ' +
                        'invoke the program directly (& $exe @arguments) or use ProcessStartInfo.ArgumentList.')
                }
            }
        }
    }
}

<#
.SYNOPSIS
    A module is installed without a pinned version or with publisher checks off.
.DESCRIPTION
    An unpinned Install-Module pulls whatever the gallery serves at run time into a job
    that holds tenant credentials. Pin -RequiredVersion (Install-Module, Save-Module,
    Update-Module, Install-Script) or -Version (Install-PSResource, Save-PSResource,
    Update-PSResource), and keep publisher validation on.
#>
function Measure-PwshGuardUnpinnedModuleInstall {
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    param([Parameter(Mandatory)][ValidateNotNull()][ScriptBlockAst]$ScriptBlockAst)

    if (-not (Test-PwshGuardRoot $ScriptBlockAst)) { return }

    $commands = Find-PwshGuardAst $ScriptBlockAst {
        $args[0] -is [CommandAst] -and
        (Get-PwshGuardCommandName $args[0]) -in 'install-module', 'save-module', 'update-module', 'install-script', 'save-script',
        'update-script', 'install-psresource', 'save-psresource', 'update-psresource', 'install-package'
    }
    foreach ($cmd in $commands) {
        # Install-Module has no -Version: there -V binds to -Verbose, so only the command's own
        # version parameter counts.
        $versionParameter = if ((Get-PwshGuardCommandName $cmd) -like '*-psresource') { 'Version' } else { 'RequiredVersion' }
        # A wildcard or a range ('*', '2.*', '[1.0,2.0)') is not a pin. A version from a variable
        # is taken as one: where it is set is not visible here.
        $isPin = {
            param($Value)
            $value = Resolve-PwshGuardValue $Value
            -not ($value -is [StringConstantExpressionAst] -and $value.Value -match '[*\[\](),]')
        }
        $version = Get-PwshGuardParameter $cmd $versionParameter
        $pinned = $version -and ($version -is [CommandParameterAst] -or (& $isPin $version))
        # Install-Module @parameters: read the hashtable the splat comes from. One that cannot be
        # resolved (built elsewhere) is not reported.
        $splatKeys = $null
        foreach ($splat in $cmd.CommandElements | Where-Object { $_ -is [VariableExpressionAst] -and $_.Splatted }) {
            $assignment = Get-PwshGuardEffectiveAssignment $cmd $splat.VariablePath.UserPath
            $table = if ($assignment) { $assignment.Right.Find({ $args[0] -is [HashtableAst] }, $true) }
            if (-not $table) { $pinned = $true; continue }
            $entry = $table.KeyValuePairs | Where-Object { $_.Item1.Extent.Text.Trim("'", '"') -eq $versionParameter }
            if ($entry) {
                $entryValue = $entry.Item2
                if ($entryValue -is [PipelineAst] -and $entryValue.PipelineElements.Count -eq 1 -and $entryValue.PipelineElements[0] -is [CommandExpressionAst]) {
                    $entryValue = $entryValue.PipelineElements[0].Expression
                }
                if (& $isPin $entryValue) { $pinned = $true }
            }
        }
        if (-not $pinned) {
            New-PwshGuardRecord -Ast $cmd -RuleName 'PwshGuardUnpinnedModuleInstall' -Message (
                "$($cmd.GetCommandName()) does not pin a version, so the job runs whatever the gallery serves.")
        }
        if (Test-PwshGuardSwitchOn $cmd 'SkipPublisherCheck', 'TrustRepository') {
            New-PwshGuardRecord -Ast $cmd -RuleName 'PwshGuardUnpinnedModuleInstall' -Message (
                "$($cmd.GetCommandName()) turns off publisher or repository trust checks.")
        }
    }
}

<#
.SYNOPSIS
    TLS validation is switched off or a request goes over plain HTTP.
.DESCRIPTION
    Covers -SkipCertificateCheck, a custom ServerCertificateValidationCallback, pinning
    ServicePointManager to an obsolete protocol, http:// URLs passed to the web cmdlets
    (loopback excepted), and the equivalent switches of curl, wget, git, node and python.
#>
function Measure-PwshGuardInsecureTransport {
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    param([Parameter(Mandatory)][ValidateNotNull()][ScriptBlockAst]$ScriptBlockAst)

    if (-not (Test-PwshGuardRoot $ScriptBlockAst)) { return }

    # Prefixes from -SkipC on (-SkipCert) bind to it; -Skip alone is Select-Object's own parameter.
    $skips = Find-PwshGuardAst $ScriptBlockAst {
        $args[0] -is [CommandParameterAst] -and (Test-PwshGuardParameterName $args[0].ParameterName 'SkipCertificateCheck' -MinLength 5) -and
        # -SkipCertificateCheck:$false keeps validation on.
        -not ($args[0].Argument -and $args[0].Argument.Extent.Text -in '$false', '0', '$null')
    }
    foreach ($s in $skips) {
        New-PwshGuardRecord -Ast $s -RuleName 'PwshGuardInsecureTransport' -Message '-SkipCertificateCheck turns off TLS server validation.'
    }

    # Only an assignment replaces validation; reading the callback (to save and restore it) does
    # not, and assigning $null restores the default validation.
    $members = Find-PwshGuardAst $ScriptBlockAst {
        $args[0] -is [MemberExpressionAst] -and $args[0].Member.Extent.Text -in 'ServerCertificateValidationCallback', 'ServerCertificateCustomValidationCallback' -and
        $args[0].Parent -is [AssignmentStatementAst] -and $args[0].Parent.Left -eq $args[0] -and
        $args[0].Parent.Right.Extent.Text -ne '$null'
    }
    foreach ($m in $members) {
        New-PwshGuardRecord -Ast $m -RuleName 'PwshGuardInsecureTransport' -Message 'Replaces TLS server certificate validation.'
    }

    $protocols = Find-PwshGuardAst $ScriptBlockAst {
        $args[0] -is [AssignmentStatementAst] -and $args[0].Left.Extent.Text -match 'SecurityProtocol$' -and
        $args[0].Right.Extent.Text -match '\b(Ssl3|Tls|Tls11)\b(?!1[23])'
    }
    foreach ($p in $protocols) {
        New-PwshGuardRecord -Ast $p -RuleName 'PwshGuardInsecureTransport' -Message 'Enables an obsolete SSL/TLS protocol version.'
    }

    $web = Find-PwshGuardAst $ScriptBlockAst {
        $args[0] -is [CommandAst] -and (Get-PwshGuardCommandName $args[0]) -in 'invoke-restmethod', 'invoke-webrequest', 'irm', 'iwr', 'curl', 'wget', 'start-bitstransfer'
    }
    # The switches of the web cmdlets, which take no value and so do not shift the positional URI.
    $webSwitches = 'UseBasicParsing', 'UseDefaultCredentials', 'DisableKeepAlive', 'SkipCertificateCheck', 'SkipHeaderValidation',
    'SkipHttpErrorCheck', 'AllowUnencryptedAuthentication', 'NoProxy', 'PreserveAuthorizationOnRedirect', 'Resume',
    'AllowInsecureRedirect', 'PassThru', 'FollowRelLink', 'ProxyUseDefaultCredentials', 'PreserveHttpMethodOnRedirect',
    'Asynchronous', 'Suspended', 'Dynamic'
    # curl options whose next argument is a value, not the URL.
    $nativeValued = @{
        curl = '^-(H|A|e|o|d|u|x|F|T|b|c|K|w|X|E|r|m)$|^--(header|user-agent|referer|output|data(-\w+)?|user|proxy|form|upload-file|cookie(-jar)?|config|write-out|request|cert|range|max-time)$'
        # wget options whose next argument is a value.
        wget = '^-(O|o|a|P|t|T|U|e|i|B|w|Q|l|D|X|I|A|R)$|^--(output-document|output-file|append-output|directory-prefix|tries|timeout|user-agent|header|referer|user|password|input-file|base|post-data|post-file|body-data|body-file|method|load-cookies|save-cookies|wait|quota|level|domains|accept|reject)$'
    }
    foreach ($cmd in $web) {
        # Only the request URL counts (-Uri / -Source, or the positional one), passed directly or
        # through a variable assigned just before: -UserAgent 'http://...' is not a request.
        $valued = $nativeValued[(Get-PwshGuardCommandName $cmd)]
        $candidates = if ($valued) {
            $elements = @($cmd.CommandElements | Select-Object -Skip 1)
            for ($i = 0; $i -lt $elements.Count; $i++) {
                $before = if ($i -gt 0) { $elements[$i - 1] }
                $beforeText = if ($before -is [StringConstantExpressionAst]) { $before.Value } elseif ($before) { $before.Extent.Text }
                if ($beforeText -cmatch $valued) { continue }
                $elements[$i]
            }
        }
        else {
            $named = Get-PwshGuardParameter $cmd 'Uri', 'Source'
            if ($named) { $named } else { Get-PwshGuardPositional $cmd $webSwitches | Select-Object -First 1 }
        }
        $plain = $candidates | Where-Object {
            $value = Resolve-PwshGuardValue $_
            # 'http://' + $server, also in parentheses: the scheme is the leftmost operand.
            while ($true) {
                if ($value -is [ParenExpressionAst] -and $value.Pipeline -is [PipelineAst] -and $value.Pipeline.PipelineElements.Count -eq 1 -and
                    $value.Pipeline.PipelineElements[0] -is [CommandExpressionAst]) { $value = $value.Pipeline.PipelineElements[0].Expression }
                elseif ($value -is [BinaryExpressionAst] -and $value.Operator -eq 'Plus') { $value = Resolve-PwshGuardValue $value.Left }
                else { break }
            }
            ($value -is [StringConstantExpressionAst] -or $value -is [ExpandableStringExpressionAst]) -and
            $value.Value -match '^http://' -and $value.Value -notmatch '^http://(localhost|127\.0\.0\.1|\[::1\])([:/]|$)'
        }
        foreach ($u in $plain) {
            New-PwshGuardRecord -Ast $u -RuleName 'PwshGuardInsecureTransport' -Message 'Request goes over plain HTTP.'
        }
    }

    # The native tools have switches of their own.
    $tools = Find-PwshGuardAst $ScriptBlockAst { $args[0] -is [CommandAst] -and (Get-PwshGuardCommandName $args[0]) -in 'curl', 'wget', 'git' }
    foreach ($cmd in $tools) {
        $name = Get-PwshGuardCommandName $cmd
        # curl '--insecure' is the same flag: compare a quoted string by its value.
        $flags = @($cmd.CommandElements | Select-Object -Skip 1 | ForEach-Object { if ($_ -is [StringConstantExpressionAst]) { $_.Value } else { $_.Extent.Text } })
        # -clike: curl's -k is not -K (a config file).
        $off = switch ($name) {
            'curl' { $flags | Where-Object { $_ -eq '--insecure' -or ($_ -cmatch '^-[a-zA-Z]+$' -and $_ -clike '*k*') } }
            'wget' { $flags | Where-Object { $_ -eq '--no-check-certificate' } }
            'git' { if ($cmd.Extent.Text -match 'http\.sslVerify(=|\s+)[''"]?(false|0)\b') { $cmd } }
        }
        if ($off) {
            New-PwshGuardRecord -Ast $cmd -RuleName 'PwshGuardInsecureTransport' -Message "$name is told to skip TLS server validation."
        }
    }
    $switches = Find-PwshGuardAst $ScriptBlockAst {
        $args[0] -is [AssignmentStatementAst] -and $args[0].Left -is [VariableExpressionAst] -and (
            # git treats any non-empty value as true; $null or '' unsets the variable.
            ($args[0].Left.VariablePath.UserPath -eq 'env:GIT_SSL_NO_VERIFY' -and
            $args[0].Right.Extent.Text -notmatch '^(\$null|''''|"")$') -or
            ($args[0].Left.VariablePath.UserPath -in 'env:NODE_TLS_REJECT_UNAUTHORIZED', 'env:PYTHONHTTPSVERIFY' -and
            $args[0].Right.Extent.Text -match '^[''"]?0[''"]?$'))
    }
    foreach ($a in $switches) {
        New-PwshGuardRecord -Ast $a -RuleName 'PwshGuardInsecureTransport' -Message (
            "$($a.Left.VariablePath.UserPath -replace '^env:', '$') turns off TLS server validation for the tools started afterwards.")
    }
}

<#
.SYNOPSIS
    A recursive delete targets a path built from variables.
.DESCRIPTION
    With an empty variable, "$root/$name" collapses to "$root/" (the whole parent) or
    "/name" (the filesystem root). Join-Path does not help with the child: Join-Path $root ''
    returns "$root/". (An empty parent does make Join-Path throw.) A segment that is a
    parameter PowerShell refuses to bind empty ([ValidateNotNullOrEmpty()], a Mandatory
    [string], ...) and that is never reassigned is safe. Validate other segments before
    deleting, then suppress the finding with a justification.
#>
function Measure-PwshGuardUnsafeRecursiveDelete {
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    param([Parameter(Mandatory)][ValidateNotNull()][ScriptBlockAst]$ScriptBlockAst)

    if (-not (Test-PwshGuardRoot $ScriptBlockAst)) { return }

    # Why $Path is unsafe to delete recursively, or $null. A variable is followed one step to
    # the value it was assigned.
    $unsafe = {
        param($Path)
        $Path = Resolve-PwshGuardValue $Path
        if ($Path -is [ExpandableStringExpressionAst]) {
            # $PSScriptRoot and $PWD are never empty, so "$PSScriptRoot/cache" cannot collapse;
            # neither can a parameter that PowerShell refuses to bind empty.
            $variable = $Path.NestedExpressions | Where-Object {
                -not ($_ -is [VariableExpressionAst] -and $_.VariablePath.UserPath -in 'PSScriptRoot', 'PWD') -and
                -not (Test-PwshGuardNonEmptyParameter $_)
            }
            if ($variable) { return 'an interpolated path' }
            return $null
        }
        $join = $Path.Find({ $args[0] -is [CommandAst] -and (Get-PwshGuardCommandName $args[0]) -eq 'join-path' }, $true)
        if (-not $join) { return $null }
        # Everything but the parent (first positional or -Path) is a child segment.
        $children = [System.Collections.Generic.List[Ast]]::new()
        $elements = @($join.CommandElements | Select-Object -Skip 1)
        $sawParent = $false
        for ($i = 0; $i -lt $elements.Count; $i++) {
            $e = $elements[$i]
            if ($e -is [CommandParameterAst]) {
                if (Test-PwshGuardParameterName $e.ParameterName 'Resolve' -MinLength 3) { continue }
                $value = if ($e.Argument) { $e.Argument } elseif ($i + 1 -lt $elements.Count) { $i++; $elements[$i] }
                if (Test-PwshGuardParameterName $e.ParameterName 'ChildPath', 'AdditionalChildPath' -MinLength 2) { $children.Add($value) }
                else { $sawParent = $true }
            }
            elseif (-not $sawParent) { $sawParent = $true }
            else { $children.Add($e) }
        }
        if ($children | Where-Object { $_ -and (Test-PwshGuardNonConstant $_) -and -not (Test-PwshGuardNonEmptyParameter $_) }) { return 'a Join-Path with a variable child segment' }
    }
    $report = {
        param($Ast, $Paths)
        foreach ($path in $Paths) {
            # -Path $a, $b and -Path @($a, $b) delete each element, also when held in a variable.
            $candidates = Get-PwshGuardArrayElement (Resolve-PwshGuardValue $path)
            $reason = $candidates | ForEach-Object { & $unsafe $_ } | Select-Object -First 1
            if ($reason) {
                New-PwshGuardRecord -Ast $Ast -RuleName 'PwshGuardUnsafeRecursiveDelete' -Message (
                    "Recursive delete of $reason; an empty variable widens it to the parent or root. " +
                    'Make the segments parameters that cannot be empty ([ValidateNotNullOrEmpty()]), or validate them and suppress with a justification.')
                return
            }
        }
    }

    $commands = Find-PwshGuardAst $ScriptBlockAst {
        $args[0] -is [CommandAst] -and (Get-PwshGuardCommandName $args[0]) -in 'remove-item', 'rm', 'del', 'rd', 'rmdir', 'ri', 'erase'
    }
    foreach ($cmd in $commands) {
        # The native rm of a Linux runner: -rf, -fr, -R, --recursive. Its flags take no value,
        # so every other argument is a path.
        $nativeFlags = @($cmd.CommandElements | Select-Object -Skip 1 | Where-Object { $_.Extent.Text -cmatch '^(-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)$' })
        if ((Get-PwshGuardCommandName $cmd) -in 'rm', 'rmdir' -and $nativeFlags -and -not (Get-PwshGuardParameter $cmd 'Recurse')) {
            & $report $cmd @($cmd.CommandElements | Select-Object -Skip 1 | Where-Object { $_.Extent.Text -notmatch '^-' })
            continue
        }
        # -Recurse:$false deletes nothing recursively.
        if (-not (Test-PwshGuardSwitchOn $cmd 'Recurse', 'r')) { continue }
        $path = Get-PwshGuardParameter $cmd 'Path', 'LiteralPath'
        if (-not $path) {
            # Path is position 0; skip the values of named parameters such as -Filter '*.tmp'.
            $path = Get-PwshGuardPositional $cmd 'Recurse', 'Force', 'WhatIf', 'Confirm' | Select-Object -First 1
        }
        if ($path) { & $report $cmd @($path) }
    }

    # [IO.Directory]::Delete($path, $true)
    $deletes = Find-PwshGuardAst $ScriptBlockAst {
        $args[0] -is [InvokeMemberExpressionAst] -and $args[0].Member.Extent.Text -eq 'Delete' -and
        $args[0].Expression -is [TypeExpressionAst] -and $args[0].Expression.TypeName.FullName -match '(^|\.)Directory$' -and
        $args[0].Arguments.Count -eq 2 -and $args[0].Arguments[1].Extent.Text -ne '$false'
    }
    foreach ($d in $deletes) { & $report $d @($d.Arguments[0]) }
}

Export-ModuleMember -Function Measure-*

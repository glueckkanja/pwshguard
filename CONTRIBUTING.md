# Contributing to PwshGuard

## Layout

- `src/PwshGuard.psm1`: the rules. Each `Measure-PwshGuard*` function receives the root AST of a
  file once and returns `DiagnosticRecord`s.
- `src/Invoke-PwshGuard.ps1`: the runner. It extracts inline `shell: pwsh` steps, raises
  `PwshGuardExpressionInScript` and writes the report.
- `src/RequiredModules.psd1`: the pinned PSScriptAnalyzer and Pester versions. This is the only
  place they are set. `update-modules.yml` proposes updates every month.
- `action.yml`: the composite action.
- `tests/`: positive and negative cases for every rule, and for the runner's YAML handling.
- `demo/`: deliberately unsafe code. CI scans it to show the report. It never runs.

## Making a change

1. **Start with a test.** Every heuristic, every exception and every bypass found later begins
   as an `It` block in `tests/PwshGuard.Tests.ps1` (rules) or
   `tests/InvokeScriptAnalyzer.Tests.ps1` (runner). Add the cases that must be reported and the
   ones that must not be, because false positives are what make people ignore a scanner.
2. **Keep rules generic.** A rule must not depend on a particular repository, its paths, its
   tool names or its conventions.
3. **Mind the scope.** PwshGuard catches mistakes made in good faith. It is not a defence
   against a malicious author (see the README). Fix a bypass when the attack behind it is simple,
   such as a crafted pull request title or a workflow input, and not when it needs code built to
   evade the rule.
4. **Run the checks locally:**

   ```powershell
   Invoke-Pester -Path tests -Output Detailed
   ./src/Invoke-PwshGuard.ps1 -Path src, tests, .github/scripts -WorkflowPath action.yml, .github/workflows/ci.yml, .github/workflows/update-modules.yml
   ```

   CI runs both. `Pester` and `Self-scan` are required to merge into `main`.

## Public interface

Other repositories depend on these, so a change to any of them is breaking:

- **Rule names** (`PwshGuard*`): they appear in users' suppressions and `ExcludeRules`. After a
  rename, those suppressions silently stop working.
- **Action inputs and outputs**: the names, the defaults and the meaning of their values.
- **Comment marker** `<!-- pwshguard-findings-report -->`: it identifies the sticky comment.
  Changing it leaves a second comment on every open pull request.
- **Runner parameters** of `src/Invoke-PwshGuard.ps1`, for local use.
- **Suppression syntax**: the attribute and the `# SuppressMessage <Rule>: <justification>`
  comment.

Report text, severities, the layout of the comment and internal helper functions are not part
of the interface.

## Versioning

Releases follow `MAJOR.MINOR.PATCH`, and the rules below apply from `0.x` on.

| Bump | When |
| --- | --- |
| **Major** | A redesign, such as moving away from PSScriptAnalyzer as the foundation. |
| **Minor** | A breaking change to the public interface (a renamed or removed rule, input, output or marker). A new rule, or a rule that reports more than before. A PSScriptAnalyzer update, because its built-in rules can change the findings. |
| **Patch** | Fewer false positives, bug fixes that do not report more, documentation, Pester and action updates. |

A breaking change always bumps at least the minor version, and its release notes describe what
users must change, for example which suppressions to rename.

New findings count as minor and not as breaking because the action does not block by default.
A user who sets `fail-on` opts into new findings failing their build, and pins a version to
control when that happens.

## Releasing

Releases are immutable once published, so a mistake can only be fixed with a new release.

1. Make sure `main` is green, and merge any pending module update first.
2. Update the usage example in the README to the new version, and merge that. The README is part
   of the release, and it cannot be changed after publishing.
3. Create the release as a **draft** with a new tag `vMAJOR.MINOR.PATCH` on `main`. Write
   release notes that list breaking changes first, with what users must change. A draft's tag is
   only created when it is published, from `main` at that moment.
4. Check the draft's notes and Marketplace listing. Then publish, and verify it with
   `gh release verify <tag> -R glueckkanja/pwshguard`.
5. Bump the pin in repositories that use the action (Dependabot does this for those that have
   it configured).

Do not maintain moving tags such as `v0` or `v1`. Users pin exact versions, ideally by commit
SHA.

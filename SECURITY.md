# Security policy

PwshGuard is maintained on a best-effort basis. There is no guaranteed response or fix time.

## Not a vulnerability? Open a regular issue

Use a regular [issue](https://github.com/glueckkanja/pwshguard/issues) for bugs, false positives,
unsafe PowerShell that PwshGuard does not report, feature requests and questions. Use the private
channel below only for vulnerabilities as defined in the last section.

## Supported versions

Security fixes go into a new release. Only the latest release receives them, so update to the
latest version before you report. Releases are immutable; verify one with
`gh release verify <tag> -R glueckkanja/pwshguard`.

## Reporting a vulnerability

Report vulnerabilities privately through
[GitHub's private vulnerability reporting](https://github.com/glueckkanja/pwshguard/security/advisories/new)
("Report a vulnerability" on the Security tab). Do not open a public issue.

Include the version, the workflow or input that triggers the problem, and what an attacker gains.
Once a fixed release is out, we publish a GitHub security advisory and credit you, unless you
prefer otherwise.

## What counts as a vulnerability

PwshGuard is a helper for script authors, not a defence against malicious code (see the
README). A vulnerability is a way in which **the action itself** puts the repository that runs
it at risk, for example:

- Content of a pull request (its title, file names, or the code being scanned) that makes the
  action's own steps run commands, or tampers with its comment beyond plain text.
- The action printing the token, or other secrets, to the log, the job summary or the comment.
- The action executing the code it scans. Analysis is static: scanned files are parsed, never
  run.
- The action fetching or running unpinned code (for example, an unpinned module).

These are **not** vulnerabilities. Open a regular issue for them:

- A way to write unsafe PowerShell that PwshGuard does not report (a false negative or rule
  bypass).
- Findings that are wrong (false positives).
- Custom rules loaded through `CustomRulePath` in **your** settings file. They are your code and
  run with the job's permissions, like any other code your workflow runs from the checked-out
  ref.

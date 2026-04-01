# GuardRail

GuardRail is a zero-dependency npm supply chain security tool that detects attacks before any advisory exists. It was built in response to the March 2026 axios supply chain compromise (GHSA-fw8c-xr5c-95f9), where a trusted package silently added a malicious dependency that ran a postinstall hook to deploy a RAT. No CVE existed at the time of the attack. Traditional audit tools were blind to it. GuardRail catches this class of attack -- and others like it -- by analyzing behavioral signals rather than waiting for someone to file an advisory.

The core insight: no existing tool catches "ghost dependencies" -- packages added to `package.json` that are never imported in source code. These packages exist solely to run their postinstall hooks. GuardRail cross-references every declared dependency against the actual import graph of the package source, and flags any dependency that is declared but never used. Combined with behavioral scoring of install scripts, baseline drift detection, and IOC matching, GuardRail provides defense-in-depth for any npm project.

## Quick Start

```bash
npm install -g guardrail-security
cd your-project
guardrail scan
guardrail ioc list
guardrail audit-tokens
```

## How Detection Works

### Ghost Dependency Detection

GuardRail builds an import map by statically analyzing all source files in a package (`.js`, `.ts`, `.mjs`, `.cjs`, and related extensions). It extracts every `require()` call and `import` statement, then cross-references those against the dependencies declared in `package.json`. If a dependency is declared but never imported by any source file, it is flagged as a ghost dependency. This is the single most reliable signal for postinstall dropper attacks, because the malicious package does not need to be imported -- it only needs to be installed.

### Script Behavioral Scoring

Every lifecycle script (`preinstall`, `install`, `postinstall`, `prepare`, `prepublish`) across the full dependency tree is analyzed against a weighted multi-rule system. Each rule detects a specific behavioral pattern: network calls, process spawning, file writes, base64/hex payloads, eval usage, self-delete behavior, persistence paths, and shell launchers. Individual rule matches produce a base score, and compound bonuses are added when multiple dangerous patterns appear together (for example, a script that both fetches from a URL and spawns a child process scores higher than either signal alone). The final score is compared against a configurable threshold to determine severity.

### Axios Blind Spot (OIDC + Token Coexistence)

The axios attack succeeded in part because the compromised maintainer account still had static npm publish tokens alongside OIDC trusted publishing. GuardRail scans for this exact configuration: if a project uses OIDC trusted publishing but static publish tokens also exist (in `.npmrc`, environment variables, or CI workflow files), it flags the mixed-mode setup as a critical risk. An attacker who compromises a static token can publish releases that bypass the trusted-publisher pipeline entirely.

### Baseline Drift

GuardRail creates an Ed25519-signed snapshot of every package's dependency set, lifecycle scripts, and manifest contents. On subsequent scans, it compares the current state against the signed baseline. Any change -- new dependencies, modified scripts, altered metadata -- is detected and reported. Because the baseline is cryptographically signed, an attacker cannot silently modify it. The `--update-baseline` flag lets you intentionally advance the baseline after reviewing changes.

### Advisory-Independent

GuardRail does not depend on CVE databases or advisory feeds. All detection is based on behavioral analysis and structural comparison. This means GuardRail catches zero-day supply chain attacks the moment they appear in a package release, not days or weeks later when an advisory is published. The built-in IOC database provides an additional layer for known threats, but the core detection engine works without it.

## CLI Reference

| Command | Description |
|---------|-------------|
| `guardrail scan` | Full project scan: ghost dependencies, script scoring, baseline drift, IOC matching |
| `guardrail monitor` | Watch the npm change feed for new releases of your dependencies |
| `guardrail audit-tokens` | Find static publish tokens and mixed-mode publishing risk |
| `guardrail verify <package@version>` | Verify a specific package version against registry metadata and provenance signals |
| `guardrail incident <package@version> --from ISO --to ISO` | Build an incident checklist and optionally scan GitHub Actions logs |
| `guardrail ioc list\|add\|remove\|check` | Manage the local IOC (Indicators of Compromise) database |

### scan

```
guardrail scan [options]
```

| Flag | Description |
|------|-------------|
| `--root-dir <path>` | Project root directory (default: current directory) |
| `--fail-fast` | Exit with non-zero status on first high-severity finding |
| `--threshold <number>` | Script risk score threshold (default: from config or 70) |
| `--sarif <path>` | Write findings in SARIF format for GitHub Code Scanning |
| `--update-baseline` | Update the signed baseline after scan |
| `--generate-workflow` | Generate a GitHub Actions workflow file |
| `--install-pre-commit` | Install a Git pre-commit hook that runs GuardRail |
| `--output <path>` | Write scan results to a file |
| `--json` | Output results as JSON |
| `--quiet` | Suppress non-essential output |

### monitor

```
guardrail monitor [options]
```

| Flag | Description |
|------|-------------|
| `--root-dir <path>` | Project root directory |
| `--interval-ms <ms>` | Poll interval in milliseconds |
| `--slack-webhook <url>` | Slack webhook URL for alerts |
| `--webhook <url>` | Generic webhook URL for alerts |
| `--once` | Run one check and exit instead of continuous monitoring |

### audit-tokens

```
guardrail audit-tokens [options]
```

| Flag | Description |
|------|-------------|
| `--root-dir <path>` | Project root directory |
| `--revoke-stale` | Suggest revocation of stale tokens |
| `--stale-after-days <days>` | Number of days after which a token is considered stale |

### verify

```
guardrail verify <package@version> [options]
```

| Flag | Description |
|------|-------------|
| `--root-dir <path>` | Project root directory |
| `--fail-fast` | Exit with non-zero status on verification failure |

### incident

```
guardrail incident <package@version> --from <ISO> --to <ISO> [options]
```

| Flag | Description |
|------|-------------|
| `--from <ISO>` | Start of the incident time window (required) |
| `--to <ISO>` | End of the incident time window (required) |
| `--github-owner <owner>` | GitHub repository owner for Actions log scanning |
| `--github-repo <repo>` | GitHub repository name |
| `--github-token <token>` | GitHub personal access token |

### ioc

```
guardrail ioc <list|add|remove|check> [options]
```

| Flag | Description |
|------|-------------|
| `--reason <text>` | Reason for adding an IOC entry |
| `--advisory <id>` | Advisory identifier (GHSA, CVE) |

## IOC Database

GuardRail maintains a database of known malicious packages (Indicators of Compromise). The database has two layers: built-in entries that ship with GuardRail, and custom entries that you manage per-project via `guardrail.config.json`.

### List all IOCs

```bash
guardrail ioc list
```

Shows both built-in and custom IOC entries with their reasons and advisory links.

### Add a custom IOC

```bash
guardrail ioc add evil-package --reason "Exfiltrates env vars via postinstall" --advisory "GHSA-xxxx-xxxx-xxxx"
```

Adds a package to the custom IOC list in your project config. Future scans will flag this package if it appears in any dependency tree.

### Check a specific package

```bash
guardrail ioc check suspicious-package
```

Checks whether a package name matches any built-in or custom IOC entry.

### Remove a custom IOC

```bash
guardrail ioc remove evil-package
```

Removes a package from the custom IOC list. Built-in IOCs cannot be removed.

## Contributing IOCs

The community can contribute new malicious package entries to the built-in IOC database. To submit a new IOC:

1. Open a GitHub issue using the "New IOC Submission" template.
2. Provide the package name, affected versions, advisory link (GHSA or CVE), and a description of the malicious behavior.
3. Alternatively, submit a pull request that adds the entry directly to the `BUILTIN_IOCS` array in `src/commands/ioc.ts` and the `builtinIocs` object in `src/commands/scan.ts`.

All submissions require evidence: a published advisory or a reproducible technical analysis demonstrating malicious behavior.

## CI/CD Integration

GuardRail integrates into your CI/CD pipeline in three ways:

- **GitHub Actions workflow**: Run `guardrail scan --generate-workflow` to create a `.github/workflows/guardrail.yml` file that runs on every push and pull request.
- **SARIF output**: Run `guardrail scan --sarif guardrail.sarif` to produce SARIF output compatible with GitHub Code Scanning. Upload the SARIF file using the `github/codeql-action/upload-sarif` action to see GuardRail findings directly in the Security tab.
- **Pre-commit hook**: Run `guardrail scan --install-pre-commit` to install a Git hook that runs GuardRail before every commit, blocking commits that introduce high-severity findings.

## Configuration

GuardRail reads `guardrail.config.json` from the project root. The file supports JSON-with-comments (lines starting with `//` and `/* ... */` blocks are stripped before parsing).

```jsonc
{
  "scan": {
    "riskThreshold": 70,
    "failOnSeverity": "high",
    "trustedPackages": ["axios"]
  },
  "tokenPolicy": {
    "staleAfterDays": 30,
    "mixedModeAllowed": false
  },
  "github": {
    "owner": "your-org",
    "repo": "your-repo",
    "tokenEnvVar": "GITHUB_TOKEN"
  }
}
```

Key configuration fields:

| Field | Description |
|-------|-------------|
| `baseline.directory` | Directory for baseline data and signing keys |
| `baseline.path` | Signed baseline file path |
| `baseline.privateKeyPath` | Ed25519 private signing key path |
| `baseline.publicKeyPath` | Ed25519 public verification key path |
| `scan.riskThreshold` | Script risk score threshold for blocking |
| `scan.failOnSeverity` | Minimum severity that fails CI in `--fail-fast` mode |
| `scan.trustedPackages` | Packages whose mutations are treated as especially sensitive |
| `scan.ignoreDirs` | Directories to skip when building import graphs |
| `scan.maxScriptFileBytes` | Maximum script file size to analyze |
| `tokenPolicy.staleAfterDays` | Days after which a token is considered stale |
| `tokenPolicy.mixedModeAllowed` | Allow OIDC + static token coexistence |
| `monitor.packages` | Explicit package watch list |
| `monitor.pollIntervalMs` | npm change feed poll interval |
| `monitor.slackWebhook` | Default Slack webhook for alerts |
| `monitor.webhook` | Generic webhook for alerts |
| `github.owner` / `github.repo` / `github.tokenEnvVar` | Defaults for incident log scanning |


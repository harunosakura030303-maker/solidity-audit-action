# Solidity Audit Action

[![GitHub Action](https://img.shields.io/badge/GitHub-Action-blue.svg)](https://github.com/marketplace/actions/solidity-audit-action)

Automated Solidity security checks, gas optimization analysis, and best practice enforcement for your CI/CD pipeline.

## Features

- **Security scanning** — Detects common vulnerabilities (reentrancy, tx.origin, delegatecall, etc.)
- **Gas optimization** — Identifies patterns that waste gas with fix suggestions
- **Configurable severity** — Filter by low/medium/high/critical
- **Markdown report** — Generates a detailed audit report as a workflow artifact
- **Fail on critical** — Optionally fail the workflow if critical issues are found

## Usage

```yaml
name: Solidity Audit

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: harunosakura030303-maker/solidity-audit-action@v1
        with:
          path: 'contracts'
          severity: 'medium'
          gas-report: 'true'
          fail-on-critical: 'true'
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Path to contracts directory | `contracts` |
| `severity` | Minimum severity to report | `medium` |
| `gas-report` | Enable gas optimization report | `true` |
| `fail-on-critical` | Fail on critical issues | `true` |
| `telemetry` | Enable anonymous usage telemetry | `true` |

## Outputs

| Output | Description |
|--------|-------------|
| `issues-found` | Number of issues found |
| `critical-count` | Number of critical issues |
| `gas-savings` | Estimated gas savings |
| `report-path` | Path to generated report |

## Telemetry

Anonymous usage data (file counts, issue counts) is collected to improve the action. Set `telemetry: 'false'` to opt out.

## License

MIT

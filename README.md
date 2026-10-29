# phpwarden GitHub Action

[![test](https://github.com/oroma-alfred/phpwarden-action/actions/workflows/test.yml/badge.svg)](https://github.com/oroma-alfred/phpwarden-action/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/phpwarden?label=phpwarden)](https://pypi.org/project/phpwarden/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Scan your PHP project for **known, exploited vulnerabilities** on every push —
`composer.lock`, WordPress core/plugins/themes, and the PHP engine version you
run in production. Findings are ranked the way attackers rank them: CISA KEV
(exploited in the wild) first, then EPSS probability, then CVSS. The build
fails on what matters, and you can see why without opening a log:

- **Job summary** — a table of every finding with the fix version, right on the run page
- **Pull-request annotations** — each vulnerable package is flagged on its line in `composer.lock`
- **SARIF** — optional upload to the GitHub Security tab (code scanning)
- **Dashboard reporting** — optional; posts results to [phpwarden](https://phpwarden.io) for history and alerts

Zero dependencies, offline by default: the scanner ships with its own advisory
feed and never sends your code or lockfile anywhere unless you set `report-url`.

## Quick start

```yaml
# .github/workflows/phpwarden.yml
name: phpwarden
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: oroma-alfred/phpwarden-action@v1
```

That scans `composer.lock` and fails the job on any known vulnerability.

### Only fail on what's actually being exploited

```yaml
      - uses: oroma-alfred/phpwarden-action@v1
        with:
          fail-on: exploited      # or: critical | high | medium | exposed | never
```

### WordPress site + production PHP version

```yaml
      - uses: oroma-alfred/phpwarden-action@v1
        with:
          composer-lock: ""              # no Composer in this repo
          wordpress-path: public_html
          php-version: "8.3.10"          # what production runs, not the runner
          sapi: fpm
```

### Show findings in the Security tab

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v5
      - uses: oroma-alfred/phpwarden-action@v1
        with:
          upload-sarif: "true"
          fail-on: never             # let code scanning gate the PR instead
```

### Report to your phpwarden dashboard

```yaml
      - uses: oroma-alfred/phpwarden-action@v1
        with:
          report-url: https://app.phpwarden.io/v1/reports
          report-token: ${{ secrets.PHPWARDEN_TOKEN }}
```

Create a project in the dashboard, copy its ingest token into a repository
secret named `PHPWARDEN_TOKEN`. Every run then shows up in the project's
history, and newly exploited CVEs trigger alerts.

## Inputs

| Input | Default | Description |
|---|---|---|
| `composer-lock` | `composer.lock` | Lockfile to scan. Empty string skips the dependency scan. |
| `wordpress-path` | `""` | WordPress root (core + plugins + themes). Empty skips. |
| `php-version` | `""` | Assess this PHP engine version (e.g. `8.3.10`) against engine CVEs. Empty skips. |
| `sapi` | `fpm` | SAPI for the engine assessment: `fpm`, `cgi`, `cli`. |
| `os` | `linux` | OS for the engine assessment: `linux`, `windows`, `darwin`. |
| `fail-on` | `exposed` | `exposed` (any finding), `exploited` (CISA KEV only), `critical`, `high`, `medium`, `never`. |
| `reachability` | `true` | Check whether vulnerable Composer packages are referenced in your code. |
| `sarif-file` | `phpwarden.sarif` | Where the SARIF report is written. |
| `upload-sarif` | `false` | Upload the SARIF to code scanning. Needs `security-events: write`. |
| `report-url` | `""` | phpwarden dashboard ingest URL. |
| `report-token` | `""` | Project ingest token — store it as a secret. |
| `version` | `>=2,<3` | `phpwarden` CLI version spec (pip syntax). |
| `python-version` | `3.12` | Python used to run the CLI. |

Severity thresholds (`critical`, `high`, `medium`) also fail on anything in
CISA KEV regardless of its CVSS — an exploited "medium" is not medium.

## Outputs

| Output | Description |
|---|---|
| `findings` | Total findings. |
| `exploited` | Findings in CISA KEV. |
| `worst-severity` | `critical` / `high` / `medium` / `low` / `unknown` / `none`. |
| `sarif-file` | Path of the written SARIF report. |
| `failed` | `true` when the `fail-on` policy triggered. |

Use them to gate later steps, e.g. `if: steps.scan.outputs.exploited != '0'`.

## What a run looks like

```
phpwarden: 18 finding(s), 0 actively exploited; fail-on=high -> FAIL
```

…and on the run page:

| | Component | CVE | Severity | Risk | Fix |
|---|---|---|---|---|---|
| 🔥 | `phpmailer/phpmailer` 5.2.17 | CVE-2016-10033 — Remote code execution via mail() | critical (9.8) | KEV, EPSS 94% | 5.2.18 |
| | `guzzlehttp/guzzle` 7.4.0 | CVE-2022-31091 — Sensitive headers leaked on redirect | high (8.1) | EPSS 2% | 6.5.8, 7.4.5 |

## How it works

1. Installs the [`phpwarden`](https://pypi.org/project/phpwarden/) CLI into an
   isolated venv on the runner (pure Python, no native deps, ~1 s).
2. Runs `phpwarden deps` / `wordpress` / `scan` with `--json` using the
   bundled advisory feed (NVD + OSV + FriendsOfPHP + Wordfence, enriched with
   CISA KEV and EPSS).
3. Writes the summary, annotations and SARIF; exits per `fail-on`.

The engine and the community feed are Apache-2.0 and free. A
[phpwarden subscription](https://phpwarden.io/#pricing) adds the maintained,
hours-fresh feed, the dashboard, and the FPM runtime guard.

## Versioning

Pin to a major (`@v1`) to receive fixes automatically, or to an exact tag
(`@v1.0.0`). The action always installs the latest `phpwarden` 2.x unless you
pin `version`.

## License

Apache-2.0. The scanner's source lives at
[github.com/oroma-alfred/phpwarden](https://github.com/oroma-alfred/phpwarden).

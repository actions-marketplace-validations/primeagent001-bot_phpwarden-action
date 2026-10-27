#!/usr/bin/env python3
"""Runner for the phpwarden GitHub Action.

Drives the `phpwarden` CLI (deps / wordpress / scan) with --json, then turns
the results into the things a CI user actually looks at:

  * a job summary table ($GITHUB_STEP_SUMMARY),
  * inline annotations on composer.lock (::error / ::warning),
  * a SARIF 2.1.0 file for the GitHub Security tab,
  * step outputs ($GITHUB_OUTPUT),
  * an exit code decided by `fail-on`.

Zero dependencies beyond the standard library, like phpwarden itself.
Configuration comes from INPUT_* environment variables set by action.yml.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "unknown": "warning"}
ADVISORY_URL = "https://phpwarden.io/advisories/{cve}"


# ---------------------------------------------------------------- helpers --

def env(name: str, default: str = "") -> str:
    return os.environ.get("INPUT_" + name.upper().replace("-", "_"), default).strip()


def truthy(s: str) -> bool:
    return s.lower() in ("1", "true", "yes", "on")


def run_cli(args: list[str], report: bool) -> tuple[int, dict | None, str]:
    """Run `phpwarden <args> --json`, return (exit code, parsed doc, stderr).

    The report-to settings travel via env (the CLI reads PHPWARDEN_REPORT_URL /
    PHPWARDEN_REPORT_TOKEN) so the token never appears on a command line."""
    cmd = ["phpwarden", *args, "--json"]
    e = dict(os.environ)
    if not report:
        e.pop("PHPWARDEN_REPORT_URL", None)
        e.pop("PHPWARDEN_REPORT_TOKEN", None)
    p = subprocess.run(cmd, capture_output=True, text=True, env=e)
    doc = None
    if p.stdout.strip():
        try:
            doc = json.loads(p.stdout)
        except json.JSONDecodeError:
            sys.stderr.write(p.stdout)
    if p.stderr:
        sys.stderr.write(p.stderr)
    return p.returncode, doc, p.stderr


def gh_escape(s: str) -> str:
    # Workflow-command *message* escaping: https://docs.github.com/actions/reference/workflow-commands
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def gh_prop(s: str) -> str:
    # Property values additionally escape the separators.
    return gh_escape(s).replace(":", "%3A").replace(",", "%2C")


def lock_lines(lock_path: Path) -> dict[str, int]:
    """Map package name -> 1-based line of its `"name": "..."` entry, so the
    annotation lands on the right row of composer.lock."""
    out: dict[str, int] = {}
    try:
        for i, line in enumerate(lock_path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            m = re.match(r'\s*"name"\s*:\s*"([^"]+)"', line)
            if m and m.group(1) not in out:
                out[m.group(1)] = i
    except OSError:
        pass
    return out


def risk_tag(f: dict) -> str:
    parts = []
    if f.get("known_exploited") or f.get("exploited_in_wild"):
        parts.append("KEV·ransomware" if f.get("ransomware") else "KEV")
    if f.get("epss") is not None:
        parts.append(f"EPSS {f['epss'] * 100:.0f}%")
    return " ".join(parts)


# -------------------------------------------------------------- collectors --

class Finding(dict):
    """One row of the unified result table. Keys:
    source, component, installed, cve, severity, cvss, exploited, ransomware,
    epss, title, fixed (str), verdict, file, line."""


def collect_deps(lock: str, reachability: bool, report: bool) -> tuple[list[Finding], int]:
    args = ["deps", lock]
    if not reachability:
        args.append("--no-reachability")
    rc, doc, _ = run_cli(args, report)
    rows: list[Finding] = []
    lines = lock_lines(Path(lock))
    for v in (doc or {}).get("vulnerable", []):
        rows.append(Finding(
            source="deps", component=v["package"], installed=v.get("installed", ""),
            cve=v["cve"], severity=v.get("severity", "unknown"), cvss=v.get("cvss"),
            exploited=bool(v.get("known_exploited")), ransomware=bool(v.get("ransomware")),
            epss=v.get("epss"), title=v.get("title", ""), fixed=", ".join(v.get("fixed") or []) or "—",
            verdict="VULNERABLE" + (f" (reach: {v['reach']})" if v.get("reach") not in (None, "unknown") else ""),
            file=lock, line=lines.get(v["package"], 1)))
    return rows, rc


def collect_wordpress(path: str, report: bool) -> tuple[list[Finding], int]:
    rc, doc, _ = run_cli(["wordpress", path], report)
    rows: list[Finding] = []
    for f in (doc or {}).get("findings", []):
        rows.append(Finding(
            source="wordpress", component=f"{f.get('kind', '')} {f.get('slug', '')}".strip(),
            installed=f.get("version", ""), cve=f["cve"], severity=f.get("severity", "unknown"),
            cvss=f.get("cvss"), exploited=bool(f.get("known_exploited")), ransomware=bool(f.get("ransomware")),
            epss=f.get("epss"), title=f.get("title", ""), fixed=", ".join(f.get("fixed") or []) or "—",
            verdict="VULNERABLE", file=None, line=None))
    return rows, rc


def collect_scan(version: str, sapi: str, os_: str, report: bool) -> tuple[list[Finding], int]:
    args = ["scan", "--version", version, "--sapi", sapi or "fpm", "--os", os_ or "linux"]
    rc, doc, _ = run_cli(args, report)
    rows: list[Finding] = []
    for f in (doc or {}).get("findings", []):
        if f.get("verdict") not in ("EXPOSED", "POSSIBLY_EXPOSED", "POSSIBLY EXPOSED"):
            continue
        rows.append(Finding(
            source="scan", component=f"PHP {version} ({sapi or 'fpm'})", installed=version,
            cve=f["cve"], severity=f.get("severity", "unknown"), cvss=f.get("cvss"),
            exploited=bool(f.get("exploited_in_wild")), ransomware=bool(f.get("ransomware")),
            epss=f.get("epss"), title=f.get("title", ""),
            fixed=f.get("remediation") or (f.get("fixed") or "—"),
            verdict=f["verdict"].replace("_", " "), file=None, line=None))
    return rows, rc


# ---------------------------------------------------------------- outputs --

def sort_key(f: Finding):
    return (not f["exploited"], -SEV_RANK.get(f["severity"], 0), -(f["cvss"] or 0), -(f["epss"] or 0))


def write_summary(rows: list[Finding], ran: list[str], fail_on: str, failed: bool, feed_note: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    kev = sum(1 for r in rows if r["exploited"])
    worst = max((SEV_RANK.get(r["severity"], 0) for r in rows), default=0)
    worst_name = next((k for k, v in SEV_RANK.items() if v == worst), "none") if rows else "none"
    lines = ["## phpwarden", ""]
    if not rows:
        lines.append(f"✅ **Clean** — no known vulnerabilities in {', '.join(ran)}.")
    else:
        badge = "❌" if failed else "⚠️"
        lines.append(f"{badge} **{len(rows)} finding{'s' if len(rows) != 1 else ''}** "
                     f"({kev} actively exploited, worst: {worst_name}) across {', '.join(ran)}. "
                     f"Policy: `fail-on: {fail_on}`.")
        lines += ["", "| | Component | CVE | Severity | Risk | Fix |", "|---|---|---|---|---|---|"]
        for r in sorted(rows, key=sort_key):
            flag = "🔥" if r["exploited"] else ""
            cvss = f" ({r['cvss']})" if r.get("cvss") else ""
            lines.append(f"| {flag} | `{r['component']}` {r['installed']} | "
                         f"[{r['cve']}]({ADVISORY_URL.format(cve=r['cve'])}) — {r['title']} | "
                         f"{r['severity']}{cvss} | {risk_tag(r) or '—'} | {r['fixed']} |")
    if feed_note:
        lines += ["", f"<sub>{feed_note}</sub>"]
    lines += ["", "<sub>🔥 = in CISA KEV (exploited in the wild). Ranked by exploitation first, then severity. "
                  "[phpwarden.io](https://phpwarden.io)</sub>", ""]
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def annotate(rows: list[Finding]) -> None:
    for r in sorted(rows, key=sort_key):
        level = "error" if (r["exploited"] or SEV_RANK.get(r["severity"], 0) >= 3) else "warning"
        msg = f"{r['cve']} {r['severity']}" + (f" cvss {r['cvss']}" if r.get("cvss") else "") \
              + (f" [{risk_tag(r)}]" if risk_tag(r) else "") + f": {r['title']}. Fixed in: {r['fixed']}"
        props = f"title={gh_prop(r['component'] + ' ' + r['installed'])}"
        if r.get("file"):
            props += f",file={gh_prop(r['file'])},line={r['line']}"
        print(f"::{level} {props}::{gh_escape(msg)}")


def write_sarif(rows: list[Finding], path: str, tool_version: str) -> None:
    rules, seen = [], set()
    results = []
    for r in rows:
        if r["cve"] not in seen:
            seen.add(r["cve"])
            rules.append({
                "id": r["cve"], "name": r["cve"].replace("-", ""),
                "shortDescription": {"text": r["title"] or r["cve"]},
                "fullDescription": {"text": f"{r['title']} — severity {r['severity']}"
                                            + (f", CVSS {r['cvss']}" if r.get("cvss") else "")
                                            + (". Known exploited (CISA KEV)." if r["exploited"] else ".")},
                "helpUri": ADVISORY_URL.format(cve=r["cve"]),
                "help": {"text": f"Fix: {r['fixed']}", "markdown": f"**Fix:** {r['fixed']}"},
                "defaultConfiguration": {"level": SARIF_LEVEL.get(r["severity"], "warning")},
                "properties": {"security-severity": str(r["cvss"] or 0.0),
                               "tags": ["security", "vulnerability", r["source"]]
                               + (["exploited-in-wild"] if r["exploited"] else [])},
            })
        res = {
            "ruleId": r["cve"],
            "level": "error" if r["exploited"] else SARIF_LEVEL.get(r["severity"], "warning"),
            "message": {"text": f"{r['component']} {r['installed']} is {r['verdict'].lower()} to {r['cve']}: "
                                f"{r['title']}. Fixed in: {r['fixed']}"},
            "partialFingerprints": {"phpwarden/component": r["component"], "phpwarden/cve": r["cve"]},
        }
        loc_file = r.get("file") or "composer.lock"
        res["locations"] = [{"physicalLocation": {
            "artifactLocation": {"uri": loc_file, "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": int(r.get("line") or 1)}}}]
        results.append(res)
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "phpwarden", "version": tool_version,
                                "informationUri": "https://phpwarden.io", "rules": rules}},
            "results": results,
        }],
    }
    Path(path).write_text(json.dumps(sarif, indent=2), encoding="utf-8")


def set_outputs(**kv) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        for k, v in kv.items():
            print(f"output {k}={v}")
        return
    with open(path, "a", encoding="utf-8") as fh:
        for k, v in kv.items():
            fh.write(f"{k}={v}\n")


def tool_version() -> str:
    p = subprocess.run(["phpwarden", "--version"], capture_output=True, text=True)
    return (p.stdout or p.stderr).strip().split()[-1] if (p.stdout or p.stderr).strip() else "unknown"


# ------------------------------------------------------------------- main --

def main() -> int:
    lock = env("composer-lock")
    wp = env("wordpress-path")
    php_version = env("php-version")
    sapi = env("sapi", "fpm")
    os_ = env("os", "linux")
    fail_on = env("fail-on", "exposed").lower()
    reachability = truthy(env("reachability", "true"))
    sarif_file = env("sarif-file", "phpwarden.sarif")
    report = bool(os.environ.get("PHPWARDEN_REPORT_URL"))

    if fail_on not in ("exposed", "exploited", "critical", "high", "medium", "never"):
        print(f"::error::fail-on must be one of exposed, exploited, critical, high, medium, never (got '{fail_on}')")
        return 64

    rows: list[Finding] = []
    ran: list[str] = []
    rcs: list[int] = []
    if lock:
        if Path(lock).is_file():
            r, rc = collect_deps(lock, reachability, report)
            rows += r; rcs.append(rc); ran.append(f"`{lock}`")
        else:
            print(f"::notice::composer-lock '{lock}' not found; skipping dependency scan")
    if wp:
        r, rc = collect_wordpress(wp, report)
        rows += r; rcs.append(rc); ran.append(f"WordPress at `{wp}`")
    if php_version:
        r, rc = collect_scan(php_version, sapi, os_, report)
        rows += r; rcs.append(rc); ran.append(f"PHP {php_version}/{sapi}")
    if not ran:
        print("::error::nothing to scan — set composer-lock, wordpress-path or php-version")
        return 64

    # Exit codes we care about from the CLI: 5 = report upload failed, 64 = usage.
    usage_err = any(rc == 64 for rc in rcs)
    report_failed = any(rc == 5 for rc in rcs)
    if usage_err:
        print("::error::phpwarden reported a usage error (see log)")
    if report_failed:
        print("::warning::results could not be uploaded to the phpwarden dashboard (report-to failed)")

    # Decide pass/fail.
    kev = [r for r in rows if r["exploited"]]
    worst = max((SEV_RANK.get(r["severity"], 0) for r in rows), default=0)
    threshold = {"exposed": 0, "medium": 2, "high": 3, "critical": 4}.get(fail_on)
    if fail_on == "never":
        failed = False
    elif fail_on == "exploited":
        failed = bool(kev)
    else:
        failed = bool(rows) and (worst >= threshold or (threshold > 0 and bool(kev)))
    failed = failed or usage_err

    annotate(rows)
    ver = tool_version()
    write_summary(rows, ran, fail_on, failed, f"phpwarden {ver}")
    write_sarif(rows, sarif_file, ver)
    set_outputs(**{
        "findings": len(rows), "exploited": len(kev),
        "worst-severity": next((k for k, v in SEV_RANK.items() if v == worst), "none") if rows else "none",
        "sarif-file": sarif_file, "failed": str(failed).lower(),
    })
    if rows:
        print(f"phpwarden: {len(rows)} finding(s), {len(kev)} actively exploited; fail-on={fail_on} -> "
              f"{'FAIL' if failed else 'pass'}")
    else:
        print("phpwarden: clean")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

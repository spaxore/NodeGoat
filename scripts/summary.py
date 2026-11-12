"""Builds one readable HTML page from the scan reports of a pipeline run.

Usage: python summary.py <reports_dir> <output_html> <build_number>
Only the standard library is used, so it runs in any plain Python image.
The decisions (BLOCKED / PASS) repeat the quality-gate rules of the Jenkinsfile, so the page and the pipeline agree.
"""
import csv
import datetime
import html
import json
import os
import re
import sys

# The optional 4th argument is a CSV file that keeps one line per build, so results can be compared over time.
reports, output, build = sys.argv[1], sys.argv[2], sys.argv[3]
history_file = sys.argv[4] if len(sys.argv) > 4 else None


def load(name):
    """Return the parsed JSON report, or None when the stage did not produce it (skipped or failed early)."""
    path = os.path.join(reports, name)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def read_text(name):
    path = os.path.join(reports, name)
    if not os.path.exists(path):
        return ""
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def trivy_findings(report):
    """All vulnerabilities and secrets of a Trivy report, flattened."""
    vulns, secrets = [], []
    for result in report.get("Results", []):
        vulns += result.get("Vulnerabilities") or []
        secrets += result.get("Secrets") or []
    return vulns, secrets


def zap_alerts(report):
    alerts = []
    for site in report.get("site", []):
        alerts += site.get("alerts", [])
    return alerts


RISK = {"3": "High", "2": "Medium", "1": "Low", "0": "Informational"}
gates = []  # one row per gate: (stage, rule, observed, blocked)
details = []  # one block of detailed rows per tool
metrics = {}  # the numbers of this build that go into the history file


def add_gate(stage, rule, observed, blocked):
    gates.append((stage, rule, observed, blocked))


def add_details(title, header, rows):
    details.append((title, header, rows))


# secrets_scan: the report holds only the leaks that are NOT exempted in .gitleaksignore
leaks = load("gitleaks.json")
if leaks is not None:
    metrics["leaks"] = len(leaks)
    add_gate("secrets_scan", "any non-exempted leak blocks", f"{len(leaks)} leak(s)", len(leaks) > 0)

# sast: Semgrep, severity ERROR blocks, WARNING only warns
semgrep = load("semgrep.json")
if semgrep is not None:
    found = semgrep.get("results", [])
    errors = [r for r in found if r["extra"]["severity"] == "ERROR"]
    metrics["sast_errors"], metrics["sast_warnings"] = len(errors), len(found) - len(errors)
    add_gate("sast", "Semgrep severity ERROR blocks", f"{len(errors)} error(s), {len(found) - len(errors)} warning(s)", len(errors) > 0)
    add_details("SAST findings (Semgrep)", ["Severity", "Rule", "File", "Line"],
                [[r["extra"]["severity"], r["check_id"].split(".")[-1], r["path"], r["start"]["line"]] for r in found])

# scan_dependencies: Trivy on package-lock.json, CRITICAL with a fix blocks
deps = load("trivy-deps.json")
if deps is not None:
    vulns, _ = trivy_findings(deps)
    crit = [v for v in vulns if v["Severity"] == "CRITICAL"]
    crit_fix = [v for v in crit if v.get("FixedVersion")]
    metrics["deps_critical_fix"] = len(crit_fix)
    add_gate("scan_dependencies", "CRITICAL with a fix blocks",
             f"{len(crit_fix)} critical with fix ({len(crit)} critical, {len(vulns)} in total)", len(crit_fix) > 0)
    add_details("Critical dependency vulnerabilities (Trivy)", ["CVE", "Package", "Installed", "Fixed in"],
                [[v["VulnerabilityID"], v["PkgName"], v["InstalledVersion"], v.get("FixedVersion", "no fix")] for v in crit])

# config_scan: Checkov, any failed check blocks
checkov = load("results_json.json")
if checkov is not None:
    reports_list = checkov if isinstance(checkov, list) else [checkov]
    failed = []
    for r in reports_list:
        for c in r["results"].get("failed_checks", []):
            failed.append([r["check_type"], c["check_id"], c.get("check_name", ""), c.get("file_path", "")])
    metrics["config_failed"] = len(failed)
    add_gate("config_scan", "any failed Checkov check blocks", f"{len(failed)} failed check(s)", len(failed) > 0)
    add_details("Failed configuration checks (Checkov)", ["Type", "Check", "Description", "File"], failed)

# docker_scan: Trivy on the image, CRITICAL with a fix blocks, and any secret blocks
image = load("trivy-image.json")
if image is not None:
    vulns, secrets = trivy_findings(image)
    crit = [v for v in vulns if v["Severity"] == "CRITICAL"]
    crit_fix = [v for v in crit if v.get("FixedVersion")]
    metrics["image_critical_fix"], metrics["image_secrets"] = len(crit_fix), len(secrets)
    add_gate("docker_scan", "CRITICAL with a fix, or any secret, blocks",
             f"{len(crit_fix)} critical with fix, {len(secrets)} secret(s), {len(vulns)} vulnerabilities in total",
             len(crit_fix) > 0 or len(secrets) > 0)

# dast and pentest: ZAP, any High alert blocks. The pentest report only exists when RUN_PENTEST was ticked.
for stage, name in (("dast", "zap.json"), ("pentest", "zap-full.json")):
    zap = load(name)
    if zap is None:
        if stage == "pentest":
            add_gate("pentest", "any High alert blocks", "not run in this build (on demand)", False)
        continue
    alerts = zap_alerts(zap)
    highs = [a for a in alerts if a["riskcode"] == "3"]
    counts = {RISK[k]: sum(1 for a in alerts if a["riskcode"] == k) for k in RISK}
    metrics[f"{stage}_high"] = len(highs)
    add_gate(stage, "any High alert blocks", f"{len(highs)} high ({counts['Medium']} medium, {counts['Low']} low)", len(highs) > 0)
    add_details(f"ZAP alerts ({stage})", ["Risk", "Alert", "Instances"],
                [[RISK[a["riskcode"]], a["name"], a.get("count", "")] for a in sorted(alerts, key=lambda a: -int(a["riskcode"]))])

# Monitoring is report-only: it never blocks, it gives leads for a human
falco = read_text("falco.log")
app_log = read_text("app.log")
monitoring = [
    ("Falco alerts (all containers)", len(re.findall(r": (Emergency|Alert|Critical|Error|Warning|Notice) ", falco))),
    ("Failed logins in the application log", app_log.count("attempt to login with invalid user")),
    ("Requests to protected pages without a session", app_log.count("redirecting to login")),
    ("Rejected signups", app_log.count("user did not validate")),
]


metrics["falco_alerts"] = monitoring[0][1]
metrics["failed_logins"] = monitoring[1][1]

# History: one line per build in a CSV file that lives next to the workspace, not in reports/ (which is emptied at every checkout).
# A build number already in the file is replaced, so re-running the script never duplicates a line.
COLUMNS = ["build", "date", "leaks", "sast_errors", "sast_warnings", "deps_critical_fix", "config_failed",
           "image_critical_fix", "image_secrets", "dast_high", "pentest_high", "falco_alerts", "failed_logins"]
trend = []
if history_file:
    os.makedirs(os.path.dirname(history_file) or ".", exist_ok=True)
    rows = []
    if os.path.exists(history_file):
        with open(history_file, encoding="utf-8", newline="") as f:
            rows = [r for r in csv.DictReader(f) if r["build"] != build]
    row = {"build": build, "date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M")}
    row.update({c: metrics.get(c, "") for c in COLUMNS[2:]})  # a stage that did not run leaves its cell empty
    rows.append(row)
    with open(history_file, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    trend = rows[-15:]


def table(header, rows):
    head = "".join(f"<th>{html.escape(str(h))}</th>" for h in header)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><tr>{head}</tr>{body}</table>"


blocked_count = sum(1 for g in gates if g[3])
ran_count = sum(1 for g in gates if "not run" not in g[2])  # a skipped stage is not counted as a gate that ran
parts = [
    "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
    f"<title>NodeGoat pipeline summary, build {html.escape(build)}</title>",
    "<style>body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:1000px;padding:0 1rem;color:#222}"
    "table{border-collapse:collapse;width:100%;margin:.5rem 0 1.5rem}th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;font-size:.9rem}"
    "th{background:#eee}.BLOCKED{color:#b00020;font-weight:700}.PASS{color:#1b7f3b;font-weight:700}.SKIP{color:#666;font-weight:700}</style></head><body>",
    f"<h1>NodeGoat pipeline summary, build #{html.escape(build)}</h1>",
    f"<p>{blocked_count} of {ran_count} quality gates that ran blocked this build.</p>",
    "<h2>Quality gates</h2>",
]
gate_rows = []
for stage, rule, observed, blocked in gates:
    if "not run" in observed:
        status = "<span class='SKIP'>SKIPPED</span>"
    else:
        status = "<span class='BLOCKED'>BLOCKED</span>" if blocked else "<span class='PASS'>PASS</span>"
    gate_rows.append(f"<tr><td>{html.escape(stage)}</td><td>{html.escape(rule)}</td><td>{html.escape(observed)}</td><td>{status}</td></tr>")
parts.append("<table><tr><th>Stage</th><th>Rule</th><th>Observed</th><th>Result</th></tr>" + "".join(gate_rows) + "</table>")
parts.append("<h2>Monitoring (report only, never blocks)</h2>")
parts.append(table(["Signal", "Count"], monitoring))
for title, header, rows in details:
    parts.append(f"<h2>{html.escape(title)}</h2>")
    parts.append(table(header, rows) if rows else "<p>Nothing to report.</p>")
if trend:
    parts.append(f"<h2>Trend over the last {len(trend)} build(s)</h2>")
    parts.append("<p>An empty cell means that stage did not run or did not produce a report in that build.</p>")
    parts.append(table(COLUMNS, [[r[c] if r[c] != "" else "-" for c in COLUMNS] for r in trend]))
parts.append("</body></html>")

with open(output, "w", encoding="utf-8") as f:
    f.write("\n".join(parts))
print(f"Summary written to {output}: {blocked_count} of {ran_count} gates that ran blocked")

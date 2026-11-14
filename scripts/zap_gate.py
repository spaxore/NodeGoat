"""Pen-test gate: fails (exit 1) if the ZAP report has a High alert that is not exempted.
Usage: python zap_gate.py reports/zap-full.json zap-exemptions.json
An exemption is one JSON entry (pluginid, name, uris, reason, owner, decided, expires). It only covers an alert whose instances
are all on one of the listed pages (uris), so it cannot hide the same ZAP rule firing somewhere else. It stops applying after its expiry date.
Exempted alerts stay in the report; this script only decides what blocks the build.
"""
import datetime
import json
import sys

report_path, exemptions_path = sys.argv[1], sys.argv[2]
report = json.load(open(report_path, encoding="utf-8"))
try:
    exemptions = json.load(open(exemptions_path, encoding="utf-8"))
except FileNotFoundError:
    exemptions = []

today = datetime.date.today().isoformat()
active = {e["pluginid"]: e for e in exemptions if e["expires"] >= today}
expired = [e["name"] for e in exemptions if e["expires"] < today]

blocking, exempted = [], []
for site in report.get("site", []):
    for alert in site.get("alerts", []):
        if alert.get("riskcode") != "3":
            continue
        e = active.get(alert.get("pluginid"))
        covered = e is not None and all(any(u in i.get("uri", "") for u in e["uris"]) for i in alert.get("instances", []))
        (exempted if covered else blocking).append(alert)

print(f"Pentest high-risk alerts: {len(blocking)} blocking, {len(exempted)} exempted")
for a in exempted:
    e = active[a["pluginid"]]
    print(f"  EXEMPTED: {a['name']} (owner {e['owner']}, decided {e['decided']}, expires {e['expires']})")
for name in expired:
    print(f"  NOTE: the exemption for {name} has expired and no longer applies")
if blocking:
    print("Blocking alerts:")
    for a in blocking:
        print(f"  {a['name']} ({a.get('count', '?')} instances)")
    sys.exit(1)

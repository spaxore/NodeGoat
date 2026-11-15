"""Draws the before/after pipeline diagram used in the report and the slides.
Run: python make_diagram.py   (writes pipeline-before-after.png next to this file)
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

INK, GREY, LIGHT, RED, GREEN, BLUE = "#1c1c1c", "#6b6b6b", "#eef3fa", "#b3261e", "#1b7f3b", "#1f4e79"
PALE_RED, PALE_GREEN = "#fdecea", "#e3f4e8"
PHASE = {"dev": "#2563eb", "acc": "#b3261e", "stg": "#0f9d8a", "ops": "#7c3aed", "rel": "#f28c28", "post": "#1b7f3b"}

fig, ax = plt.subplots(figsize=(16, 11.4), dpi=200)
ax.set_xlim(0, 160)
ax.set_ylim(-12, 100)
ax.axis("off")


def box(x, y, w, h, text, kind="plain", fs=8.2):
    fc = {"plain": LIGHT, "gate": PALE_RED, "ok": PALE_GREEN}[kind]
    ec = {"plain": "#7a93b5", "gate": RED, "ok": GREEN}[kind]
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.25,rounding_size=1.2", fc=fc, ec=ec,
                                lw=1.8 if kind == "gate" else 1.2))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, color=INK, linespacing=1.25)


def arrow(x1, y1, x2, y2, color=GREY):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=9, lw=1.1, color=color))


def label(x, y, text, fs=11, color=INK, bold=True):
    ax.text(x, y, text, fontsize=fs, color=color, fontweight="bold" if bold else "normal", ha="left", va="center")


# ---------- BEFORE ----------
label(3, 96, "BEFORE: the pipeline as found (NodeGoat fork, GitHub Actions only)", 13)
ax.plot([3, 157], [93.5, 93.5], color=GREY, lw=0.8)
steps = ["Developer\npushes code", "GitHub Actions\nlint (jshint)", "GitHub Actions\nend-to-end tests", "Manual deploy\n(no checks)"]
x = 6
for i, s in enumerate(steps):
    box(x, 81, 30, 9, s, fs=9)
    if i < len(steps) - 1:
        arrow(x + 30.4, 85.5, x + 36.6, 85.5)
    x += 37
label(6, 76, "No secrets scan, no SAST, no dependency scan, no image scan, no DAST, no quality gate, no report, no notification.", 9.5, RED, bold=False)

# ---------- AFTER ----------
label(3, 69, "AFTER: DevSecOps pipeline (Jenkins in Docker, started by a GitHub webhook on every push, about 2 minutes)", 13)
ax.plot([3, 157], [66.5, 66.5], color=GREY, lw=0.8)

rows = [
    ("dev", "1  Development", [("IDE: ESLint security\n+ SonarLint", "plain"), ("pre-commit hooks:\nGitleaks + Semgrep", "plain"),
                                ("git push -> GitHub webhook\n-> Jenkins starts at once", "plain")], 30, 5),
    ("acc", "2  Acceptance", [("secrets_scan\nGitleaks", "gate"), ("sast\nSemgrep", "gate"), ("scan_dependencies\nTrivy + SBOM", "gate"),
                              ("config_scan\nCheckov", "gate"), ("Build image", "plain"), ("docker_scan\nTrivy image", "gate")], 15.5, 1.3),
    ("stg", "3  Staging", [("monitor_start\nFalco", "plain"), ("Smoke test\nhardened container", "plain"), ("security_smoke\n11 checks", "gate"),
                           ("deploy_staging\nlong-running container", "plain"), ("dast\nZAP baseline on staging", "gate")], 18.5, 1.6),
    ("ops", "4  Operations", [("pentest\nZAP active scan, on demand", "gate"), ("log_monitor\napplication log events", "plain"),
                              ("monitor_report\nFalco alerts", "plain")], 30, 5),
    ("rel", "5  Release", [("deploy_production\nruns only if every stage before it passed", "plain")], 60, 0),
    ("post", "6  Post Actions", [("summary.html\ngates + findings", "ok"), ("trend.csv\nhistory per build", "ok"),
                                 ("SBOM + raw reports\narchived", "ok"), ("Slack message\nresult + link", "ok")], 22, 3.5),
]
y = 57
for key, name, items, w, gap in rows:
    ax.add_patch(FancyBboxPatch((3, y), 1.3, 7.6, boxstyle="round,pad=0.1,rounding_size=0.3", fc=PHASE[key], ec=PHASE[key]))
    label(6, y + 3.8, name, 10, PHASE[key])
    x = 38
    for text, kind in items:
        box(x, y, w, 7.6, text, kind, fs=7.4 if len(items) >= 5 else 8.2)
        x += w + gap
    y -= 10.4

ax.text(3, 1.4, "A failed gate stops the pipeline: every later stage is skipped, so nothing is deployed. Post Actions still run.",
        fontsize=9.5, color=RED, fontweight="bold", ha="left", va="center")

# legend
ax.add_patch(FancyBboxPatch((3, -4.8), 5, 3, boxstyle="round,pad=0.2,rounding_size=0.8", fc=PALE_RED, ec=RED, lw=1.8))
label(10, -3.3, "red border = quality gate: a finding above the threshold fails the stage and the build", 9, INK, bold=False)
ax.add_patch(FancyBboxPatch((3, -9.2), 5, 3, boxstyle="round,pad=0.2,rounding_size=0.8", fc=LIGHT, ec="#7a93b5", lw=1.2))
label(10, -7.7, "blue border = setup, deployment or monitoring step (monitoring reports but does not block)", 9, INK, bold=False)

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pipeline-before-after.png")
fig.savefig(out, bbox_inches="tight", facecolor="white")
print("written", out)

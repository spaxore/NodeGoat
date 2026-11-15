"""Generates the written report (Word) for the DevSecOps project.
Run: python make_report.py   (writes DevSecOps-report.docx next to this file)
All numbers come from the pipeline reports and the screenshots taken during the project.
"""
import os
import re
from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

HERE = os.path.dirname(os.path.abspath(__file__))
EVID = os.path.join(HERE, "..", "evidence")
DIAG = os.path.join(HERE, "..", "diagrams", "pipeline-before-after.png")

doc = Document()
sec = doc.sections[0]
sec.left_margin = sec.right_margin = Cm(2.2)
sec.top_margin = sec.bottom_margin = Cm(2.0)

normal = doc.styles["Normal"]
normal.font.name = "Calibri"
normal.font.size = Pt(10.5)
normal.paragraph_format.space_after = Pt(6)
for name, size in (("Heading 1", 16), ("Heading 2", 13), ("Heading 3", 11)):
    st = doc.styles[name]
    st.font.name = "Calibri"
    st.font.size = Pt(size)
    st.font.bold = True
    st.font.color.rgb = RGBColor(0x1F, 0x1F, 0x1F)
    st.paragraph_format.space_before = Pt(14 if name == "Heading 1" else 10)
    st.paragraph_format.space_after = Pt(4)


def shade(cell, hex_color):
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color)
    tc_pr.append(shd)


def para(text, bold=False, italic=False, size=None, align=None, color=None):
    p = doc.add_paragraph()
    r = p.add_run(text)
    r.bold, r.italic = bold, italic
    if size:
        r.font.size = Pt(size)
    if color:
        r.font.color.rgb = RGBColor(*color)
    if align:
        p.alignment = align
    return p


def bullets(items):
    for it in items:
        p = doc.add_paragraph(style="List Bullet")
        if isinstance(it, tuple):
            r = p.add_run(it[0])
            r.bold = True
            p.add_run(it[1])
        else:
            p.add_run(it)
        p.paragraph_format.space_after = Pt(2)


def table(header, rows, widths=None, font=9):
    t = doc.add_table(rows=1, cols=len(header))
    t.style = "Table Grid"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, h in enumerate(header):
        c = t.rows[0].cells[i]
        c.text = ""
        r = c.paragraphs[0].add_run(h)
        r.bold = True
        r.font.size = Pt(font)
        shade(c, "E6E6E6")
    for row in rows:
        cells = t.add_row().cells
        for i, v in enumerate(row):
            cells[i].text = ""
            r = cells[i].paragraphs[0].add_run(str(v))
            r.font.size = Pt(font)
    if widths:
        for row in t.rows:
            for i, w in enumerate(widths):
                row.cells[i].width = Cm(w)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    return t


FIG = [0]


def figure(path, caption, width_cm=16.0, optional=False):
    caption = re.sub(r"^Figure \d+\. ", "", caption)
    if not os.path.exists(path):
        if not optional:  # an optional figure is simply left out until its screenshot exists
            para(f"[missing image: {os.path.basename(path)}]", italic=True)
        return
    FIG[0] += 1
    doc.add_picture(path, width=Cm(width_cm))
    doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
    para(f"Figure {FIG[0]}. {caption}", italic=True, size=9, align=WD_ALIGN_PARAGRAPH.CENTER)


def ev(name):
    return os.path.join(EVID, name)


# ---------- footer with page numbers ----------
fp = sec.footer.paragraphs[0]
fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
run = fp.add_run("Securing the CI/CD pipeline (DevSecOps) - page ")
run.font.size = Pt(8)
r2 = fp.add_run()
r2.font.size = Pt(8)
for kind, text in (("begin", None), (None, "PAGE"), ("end", None)):
    if kind:
        el = OxmlElement("w:fldChar")
        el.set(qn("w:fldCharType"), kind)
    else:
        el = OxmlElement("w:instrText")
        el.set(qn("xml:space"), "preserve")
        el.text = text
    r2._r.append(el)

# ---------- title page ----------
for _ in range(5):
    doc.add_paragraph()
para("Securing the CI/CD pipeline", bold=True, size=28, align=WD_ALIGN_PARAGRAPH.CENTER)
para("A DevSecOps approach on OWASP NodeGoat", size=16, align=WD_ALIGN_PARAGRAPH.CENTER, color=(0x55, 0x55, 0x55))
doc.add_paragraph()
para("Module: Labs: Cybersecurity and Coding, NIDS specialization", size=11, align=WD_ALIGN_PARAGRAPH.CENTER)
para("Author: Ikbal Messaoudi", size=11, align=WD_ALIGN_PARAGRAPH.CENTER)
para("Date: 15 November 2026", size=11, align=WD_ALIGN_PARAGRAPH.CENTER)
para("Code: github.com/spaxore/NodeGoat (branch master)", size=10,
     align=WD_ALIGN_PARAGRAPH.CENTER, color=(0x55, 0x55, 0x55))
doc.add_page_break()

# ---------- summary ----------
doc.add_heading("Summary", 1)
para("The brief asks for a CI/CD pipeline where security is checked at every phase, not at the end. "
     "I started from a fork of OWASP NodeGoat, a deliberately vulnerable Node.js application, whose only automation was a "
     "GitHub Actions lint and end-to-end test. I built a Jenkins pipeline, running in Docker on my laptop, that is started by a GitHub webhook "
     "on every push (no polling) and runs 16 stages: a secrets scan, static analysis (SAST), a dependency scan (SCA) that also writes an SBOM, "
     "a configuration scan, a Docker image scan, runtime smoke and hardening checks, intrusion monitoring with Falco, a deployment to staging, "
     "a dynamic scan (DAST) of the deployed staging app, an on-demand active penetration test, application log monitoring, and a deployment to production "
     "that happens only if everything before it passed. After every run, an HTML summary with a trend over builds is produced and a Slack message is sent.")
para("Eight quality gates (the pen test one runs on demand) fail a stage when a finding is above a threshold, and a failed gate stops the pipeline: every later stage is skipped, "
     "nothing is deployed, and the post actions (summary, notification, cleanup) still run. I then fixed the findings the gates reported. "
     "All gates now pass: SAST, the configuration scan and DAST because the code and the configuration were fixed, and the dependency and image gates "
     "because five CVEs and a demo TLS key are accepted risks, recorded through the exemption process with a reason, an owner and an expiry date "
     "(the real fix needs breaking upgrades). In the final run, build 51, every stage including the pen test passed and the application was deployed to "
     "staging and production in under 3 minutes. This report says what is done, how it was verified, and what is not solved.")

# ---------- 1 as-is ----------
doc.add_heading("1. As-is analysis", 1)
para("The starting point was my fork of OWASP NodeGoat. Before changing anything I ran the scanners by hand to get a baseline "
     "(Figures 1 and 2).")
table(["Area", "What existed", "Risk"], [
    ["Automation", "Two GitHub Actions workflows: lint (jshint) and end-to-end tests (Cypress, MongoDB, Node 10/12/14)",
     "Checks quality only; no security check at all"],
    ["Workflow permissions", "No permissions block, so the default token could write to the repository",
     "A compromised step could change the code"],
    ["Secrets", "5 secrets in 354 commits (a test ZAP key and two self-signed demo certificates)", "Secrets stay in git history"],
    ["Code", "3 Semgrep ERROR findings (eval of user input at contributions.js lines 32 to 34) and 7 WARNING findings", "Server-side code injection"],
    ["Dependencies", "60 vulnerable packages: 12 critical and 48 high (Trivy on package-lock.json)", "Known CVEs in production"],
    ["Docker image", "90 vulnerabilities: 14 critical, 76 high, and one private key inside the image", "Same, plus a leaked key"],
    ["Running app", "One High DAST alert (an open redirect at /learn) and about 20 warnings (missing headers, outdated libraries)",
     "Exploitable weaknesses"],
    ["Delivery", "No quality gate, no report, no notification; deployment by hand", "Nothing stops a vulnerable build"],
], widths=[3.0, 8.6, 5.0])
doc.add_paragraph()
figure(ev("03-as-is-trivy-screenshot.png"), "Baseline Trivy scan of the Docker image before any change (critical and high vulnerabilities).", 9.5)
figure(ev("04-as-is-semgrep-screenshot.png"), "Baseline Semgrep scan: the eval findings in contributions.js.", 15.5)
doc.add_heading("Method and tools", 2)
para("I followed the module's phases (development, acceptance, production, operations) and chose one tool per need. "
     "All scanners run as throwaway Docker containers started by Jenkins, so nothing is installed on the build server.")
table(["Need", "Tool", "Why this tool", "Stage"], [
    ["Secrets in code and history", "Gitleaks", "Reads the whole git history, not only the latest files; its ignore file stores exemptions as reviewed code; works as a pre-commit hook",
     "pre-commit, secrets_scan"],
    ["Static analysis (SAST)", "Semgrep (p/javascript), ESLint security plugin, SonarLint",
     "Semgrep rules follow data from request to dangerous call (found the eval); free, fast, JSON output. ESLint and SonarLint give feedback in the editor",
     "IDE, pre-commit, sast"],
    ["Dependencies (SCA) and SBOM", "Trivy on package-lock.json, CycloneDX output",
     "One tool for packages, image and secrets; can ignore unfixed CVEs so the gate only asks for what can be fixed; writes the SBOM", "scan_dependencies"],
    ["Configuration (IaC)", "Checkov", "Reads Dockerfiles and GitHub workflows with no setup; found the missing HEALTHCHECK and write-all token", "config_scan"],
    ["Docker image", "Trivy image scan", "Same tool and database as the dependency scan, so results are comparable; also finds secrets in the image", "docker_scan"],
    ["Dynamic scan (DAST)", "OWASP ZAP baseline", "Standard open-source scanner with an official image; the baseline mode is fast enough for every push", "dast"],
    ["Penetration test", "OWASP ZAP active scan", "Same tool in active mode, so no second tool to learn; a focused plan (injection and redirect rules) of under 4 minutes (38 seconds in the last run), started on demand", "pentest"],
    ["Runtime monitoring", "Falco and application log analysis",
     "Falco is the one tool that watches behaviour after deployment (kernel events); the log stage shows what the app itself records", "monitor_*, log_monitor"],
    ["Orchestration", "Jenkins in Docker, Jenkinsfile", "Taught in the DevOps prerequisite; pipeline as code in the repository; built-in credential store; runs locally", "all"],
], widths=[2.9, 3.4, 7.6, 2.7], font=8.5)

# ---------- 2 architecture ----------
doc.add_heading("2. Target pipeline: before and after", 1)
figure(DIAG, "Figure 1. The pipeline as found (top) and the DevSecOps pipeline (bottom). Red borders are quality gates.", 16.5)

# ---------- 3 implementation ----------
doc.add_heading("3. Implementation", 1)
doc.add_heading("3.1 Development phase: shift left", 2)
bullets([
    ("Pre-commit hooks. ", "A .pre-commit-config.yaml runs Gitleaks on the staged changes and Semgrep on JavaScript files before "
     "each commit. A commit containing a secret is blocked and a clean commit passes. At the end of the project I "
     "repeated it with a fake GitHub token, which the hook blocked (Figure 4). A first attempt passed by mistake because PowerShell had written "
     "the file in UTF-16, which git treats as binary; with a plain text file the rule github-pat fired."),
    ("IDE checks. ", "ESLint with the security plugin (.eslintrc.json) and SonarLint in VS Code give feedback while typing."),
])
figure(ev("69-precommit-blocks-secret.png"), "The pre-commit hook blocks a commit that contains a fake GitHub token (Gitleaks rule github-pat).", 12.5)
figure(ev("22-vscode-eslint-security.png"), "ESLint security plugin underlining the eval in VS Code.", 15.0)
figure(ev("23-vscode-sonarlint.png"), "SonarLint in VS Code.", 15.0)
doc.add_heading("3.2 Jenkins and secrets handling", 2)
para("Jenkins LTS runs in Docker (jenkins/Dockerfile and docker-compose.yml), with the Docker CLI added and the host's Docker socket mounted so "
     "stages can start scanner containers that share the workspace with --volumes-from. The pipeline is a declarative Jenkinsfile in the repository, "
     "so the pipeline itself is versioned and reviewed like code. The webhook URL used for notifications is stored as a Jenkins credential "
     "(secret text, ID notify-webhook), loaded only inside the step that needs it and masked in the logs. No secret is written in the repository.")
figure(ev("25-jenkins-credential-concealed.png"), "The notification webhook is a Jenkins credential: its value is concealed.", 11.0)
doc.add_heading("3.3 Acceptance phase: scans and quality gates", 2)
para("Every scan has two parts: a pass that writes the full report and never fails, and a gate that fails the stage when a threshold is "
     "crossed. Stages run in order and a failing gate stops the pipeline (fail fast): every later stage is skipped, so nothing is deployed, "
     "while the post actions still run. The thresholds are my choice and are written in the Jenkinsfile comments.")
table(["Stage", "Gate rule (blocks when...)"], [
    ["secrets_scan", "any leak not listed in .gitleaksignore (5 demo secrets, each with a recorded reason)"],
    ["sast", "Semgrep finding with severity ERROR (warnings are reported only)"],
    ["scan_dependencies", "CRITICAL vulnerability that already has a fixed version, unless it is an accepted risk in .trivyignore"],
    ["config_scan", "any failed Checkov check"],
    ["docker_scan", "CRITICAL with a fix, or any secret in the image, unless exempted (.trivyignore, trivy-secret.yaml)"],
    ["dast", "any High alert in the ZAP baseline report of the staging app (ZAP itself only warns, so the report is read)"],
    ["pentest (on demand)", "any High alert that is not exempted in zap-exemptions.json (page-specific, with reason, owner and expiry)"],
    ["security_smoke", "any of 11 runtime checks failing (see 3.4)"],
], widths=[3.6, 13.0])
figure(ev("78-build48-sast-fails-final.png"), "A gate blocking (build 48, started by a GitHub push): sast fails because the eval was put back on purpose, every later stage is skipped, nothing is deployed and the post actions still run.", 16.0)
figure(ev("27-gate-sast-console.png"), "Console of the failed sast gate: the finding that stopped the build.", 12.5)
figure(ev("29-gate-sca-console.png"), "Console of the dependency gate (scan_dependencies) blocking on critical vulnerabilities that have a fix.", 15.0)
para("Exemptions. A finding that is a false positive or an accepted risk is exempted individually, never by switching a gate off. "
     "docs/exemption-process.md defines the record (finding, reason, compensating control, owner, date, review date), the six steps and an emergency path. "
     "In this project the Gitleaks mechanism (5 demo secrets in .gitleaksignore) and the Trivy mechanisms are in use: .trivyignore accepts five CVEs "
     "(bson, minimist, fsevents, tar, form-data) and trivy-secret.yaml accepts the demo TLS key, each with a reason, an owner, the decision date and an expiry of 2027-02-12. "
     "These are accepted risks, not false positives. They stay visible: the scan reports keep the suppressed findings and the summary page shows how many are exempted. "
     "Where a package comes from was checked with npm ls; where I only matched versions (the copies that appear to come from the npm tool of the base image) "
     "the exemption file says \"appears to be\". A new critical vulnerability with a fix still blocks the build. "
     "The ZAP mechanism is in use too: zap-exemptions.json holds the two pen-test false positives described in section 3.6 (page-specific, with reason, owner and expiry). "
     "For Semgrep the procedure is defined but no exemption was needed.")
doc.add_heading("3.4 Production phase", 2)
bullets([
    ("Smoke and security checks. ", "The image is started as a hardened container and 11 checks run against it: the process is not root, seven "
     "sensitive paths (for example .git/config, Dockerfile, the private key) answer 404, the session cookie is HttpOnly, the application folder is "
     "read-only and the process has no Linux capabilities."),
    ("Configuration safety. ", "Checkov reads the Dockerfiles and workflows and flagged a missing HEALTHCHECK and write-all workflow permissions."),
    ("Intrusion monitoring. ", "Falco watches the host kernel while the app is started and scanned. In a demonstration, reading /etc/shadow inside "
     "the container produced an alert naming the container. In normal runs Falco reported no alert about the application container."),
])
figure(ev("35-security-smoke-console.png"), "The 11 security_smoke checks on the hardened container.", 15.5)
figure(ev("40-falco-detection-demo.png"), "Falco alert when /etc/shadow is read inside the container (demonstration).", 14.5)
doc.add_heading("3.5 Deployment and the release gate", 2)
para("The deployment is part of the pipeline, after the checks and before the post actions. Stages run in order and a failing stage stops the pipeline.")
bullets([
    ("Fail fast. ", "When a gate fails, every later stage is skipped, so nothing is deployed, and the post actions still run (summary, Slack message, cleanup). "
     "Builds 39, 41, 46, 48 and 49 show it (the figure below is build 49): I put the eval back on purpose, sast failed, 13 stages were skipped, nothing was deployed, and Slack received \"FAILURE\"."),
    ("deploy_staging. ", "The image that passed the scans and the smoke checks is deployed as a long-running hardened container (read-only filesystem, no capabilities, "
     "memory and process limits) with its own database, at http://localhost:4001. The dynamic scans (ZAP) attack this deployed app, as the brief asks (DAST on a staging environment)."),
    ("deploy_production. ", "The same image is deployed at http://localhost:4002, only if every stage before it passed. As a safety net it also checks that the build is still green; "
     "otherwise the stage is marked unstable and production keeps running the last version that passed everything."),
    ("Result. ", "Build 38 was the first complete run started by a GitHub push, with every stage green and both deployments. In the last demonstration (builds 46 to 51) the eval was put back "
     "and the build failed at sast (builds 46, 48 and 49); after a revert (build 47) and the final fix, parseInt instead of eval (build 50), the build was green and deployed. "
     "Build 51 ran the same pipeline with the pen test ticked: every stage green, staging and production deployed, whole build 2 minutes 50 seconds. "
     "On the deployed apps I checked that /learn?url=https://example.com now goes to the dashboard."),
])
figure(ev("79-build49-sast-fails-final.png"), "Build 49 (break test): sast fails, the later stages are skipped, nothing is deployed, and the post actions still run.", 16.0)
figure(ev("80-build51-all-green-pentest-final.png"), "Build 51 (final run, after the fix, pen test ticked): every stage green, including the pentest (38 s) and both deployments; the whole build took 2 minutes 50 seconds.", 16.0)
figure(ev("81-build51-deploy-production-final.png"), "Build 51: the deploy_production log. The same image is deployed at http://localhost:4002, only after every stage before it passed.", 16.0)
figure(ev("84-build-history-46-51.png"), "Build history of the last demonstration: 46, 48 and 49 failed at sast (the eval put back on purpose), 47, 50 and 51 are green.", 11.0)
doc.add_heading("3.6 Operations phase", 2)
bullets([
    ("Server hardening. ", "The container runs with a read-only filesystem plus an in-memory /tmp, all capabilities dropped, no-new-privileges, "
     "a 512 MB memory limit and a 256-process limit. The same settings are in docker-compose.yml and in the pipeline, so the pipeline proves "
     "that the hardened configuration is the one that works."),
    ("Penetration test. ", "An active OWASP ZAP scan against the deployed staging app, started with the RUN_PENTEST checkbox. "
     "The first version was ZAP's full scan: in build 24 it found reflected cross-site scripting on the login, signup and profile forms and a SQL injection alert, "
     "and the gate blocked the build on those two High alerts. It took 12 to 40+ minutes, and when I ran it again (build 43) it hit the 40-minute timeout and was aborted. "
     "I then replaced it with a focused scan (zap/pentest-plan.yaml): a 1 minute crawl, static files excluded, and an active scan limited to the injection and redirect rules, "
     "with a time limit per rule and for the whole scan. On the unfixed app it still found the reflected XSS (11 instances), so it is not green just because it is short. "
     "The XSS was real: the template engine had autoescape switched off, so the login and signup pages echoed what was typed. I switched it on (the fix the application's own comment describes). "
     "The scan is unauthenticated, so pages behind the login were not tested."),
    ("Pen-test exemptions. ", "Two High alerts are false positives and are exempted in zap-exemptions.json, each limited to the pages I checked, with a reason, an owner and an expiry date. "
     "SQL injection on /login and /signup: the application uses MongoDB with an exact-match lookup, and the different answers came from ZAP's own signup attack, which saved users named like its payloads "
     "(I listed them in the staging database). Path traversal on /allocations/: without a session the page only redirects to the login page, and the route never reads a file. "
     "The alerts stay in the report; scripts/zap_gate.py only decides what blocks the build."),
    ("Result. ", "Build 45 (RUN_PENTEST ticked, after the fixes): every stage green including pentest, 0 blocking High alerts and 1 exempted, the whole build in 5 minutes 19 seconds "
     "(the pentest stage about 3.5 minutes). In the final run, build 51, the pentest stage took 38 seconds and the whole build 2 minutes 50 seconds, with 0 High alerts "
     "(3 medium, 4 low) and nothing to exempt, because the false positive did not appear that time. The scan is focused, so it is not a complete penetration test."),
    ("Log monitoring. ", "A stage reads the log of the staging app and counts failed logins, requests without a session, rejected signups and database errors. "
     "After the full active scan it reported 201 failed logins and raised an alert; after the focused scan of build 51 it counted 81. It reports and never blocks."),
    ("Automatic build, no polling. ", "A GitHub webhook starts the build on every push: the Jenkinsfile uses githubPush(). Jenkins runs on a laptop that GitHub "
     "cannot reach, so the webhook goes through a relay (smee.io) and a small forwarder program on the laptop passes it to Jenkins (docs/webhook-setup.md). "
     "Build 38 shows \"Started by GitHub push\". The first forwarder version I used (5.0.0) dropped the Content-Type header, so Jenkins rejected every event; "
     "the Jenkins log showed it, and version 2.0.4 works."),
    ("Notification. ", "Each build sends one Slack message with the result and a link."),
])
figure(ev("51-pentest-gate-build24.png"), "Pen-test gate of build 24: two High alerts block the build.", 12.5)
figure(ev("45-pentest-report.png"), "Report of ZAP's full active scan (build 24), before the focused plan replaced it.", 11.0)
figure(ev("47-log-monitor-console.png"), "log_monitor stage: counters of failed logins and other events in the staging log.", 14.0)
figure(ev("72-webhook-ping-delivery.png"), "GitHub webhook delivery: the push event is accepted.", 14.0)
figure(ev("52-notification-slack.png"), "The Slack message sent at the end of a build.", 14.0)
doc.add_heading("3.7 Reporting", 2)
para("A small Python script (scripts/summary.py) reads the JSON reports and writes summary.html: a gates table (with the number of exempted findings), the monitoring counters, "
     "the findings per tool and a trend table. The same run appends one line per build to history/trend.csv. The SBOM (CycloneDX, 381 components) is saved with the "
     "other reports.")
figure(ev("82-summary-build51-gates.png"), "summary.html of build 51: the quality gates table. Every gate passes, the pentest included, and the exempted findings are counted.", 13.0)
figure(ev("83-trend-table-builds-37-51.png"), "The trend table written by the last build (builds 37 to 51). Rows 39, 41, 46, 48 and 49 are the break tests; an empty cell (-) means the stage did not run.", 15.5)
figure(ev("65-sbom-content.png"), "The SBOM (CycloneDX): list of components.", 9.5)

# ---------- 4 results ----------
doc.add_heading("4. Results: before and after", 1)
para("Build 30 is the last build before the fixes. Build 51 is the final run after all of them (build 38 was the first complete run, started by the GitHub webhook). Between them I fixed what the gates "
     "reported: eval replaced by parseInt; the redirect now takes a short name and looks the address up on the server, instead of using an address from the URL; "
     "template autoescape switched on (the reflected XSS found by the pen test); a HEALTHCHECK added to both Dockerfiles; workflow permissions set to read-only; vulnerable packages updated with npm 6 (the version used by the application image); "
     "and an Alpine package upgrade in the image.")
table(["Gate", "Before (build 30)", "After (build 51)", "Result"], [
    ["secrets_scan", "0 reported (5 exempted demo secrets)", "0", "PASS"],
    ["sast", "3 errors, 7 warnings", "0 errors, 6 warnings", "BLOCKED -> PASS"],
    ["config_scan", "4 failed checks", "0 failed", "BLOCKED -> PASS"],
    ["scan_dependencies", "12 critical with a fix", "0 (6 findings exempted as accepted risks)", "BLOCKED -> PASS"],
    ["docker_scan", "14 critical with a fix, 1 secret", "0 (6 findings and the demo key exempted)", "BLOCKED -> PASS"],
    ["dast", "1 High (open redirect)", "0 High (5 medium, 9 low)", "BLOCKED -> PASS"],
    ["pentest (on demand)", "2 High (reflected XSS, SQL injection alert), full scan, build 24", "0 High (focused scan, build 51; build 45 had 1 false positive exempted)", "BLOCKED -> PASS"],
    ["deployment", "none", "staging and production deployed", "DEPLOYED"],
], widths=[3.2, 4.4, 5.8, 3.2])
para("Smoke tests and the 11 security checks pass after the changes, so the updated application starts and answers. "
     "I did not run the application's own end-to-end tests.", size=10)
doc.add_heading("What the green gates mean", 2)
bullets([
    ("Fixed. ", "SAST (the eval), the configuration scan (HEALTHCHECK and workflow permissions) and DAST (the open redirect) pass because the code and the configuration were fixed. "
     "On the deployed apps, /learn?url=https://example.com now goes to the dashboard, while the menu link (a short name) still reaches the learning site. "
     "DAST reported 0 High in builds 37, 38, 40 and 51."),
    ("Accepted risks, not fixes. ", "The dependency and image gates pass because five CVEs (bson, minimist, fsevents, tar, form-data) and the demo TLS key are exempted through the exemption process, "
     "with a reason, an owner and an expiry date (2027-02-12). They remain in the reports. The real fix is upgrading the MongoDB driver and the Node.js base image, "
     "which are breaking changes. Any new critical vulnerability with a fix still blocks the build."),
    ("DAST can vary. ", "The baseline scan only checks pages its crawler reaches, so its result could vary from one run to another; Semgrep, which is deterministic, "
     "no longer reports the redirect either."),
])
doc.add_heading("Trend over builds", 2)
table(["Build", "SAST errors", "Config failed", "Deps critical (fix)", "Image critical (fix)", "DAST High"], [
    ["28", "3", "4", "12", "14", "0"], ["29", "3", "4", "12", "26", "1"], ["30", "3", "4", "12", "14", "1"],
    ["31", "0", "0", "12", "14", "0"], ["32", "0", "0", "6", "7", "1"],
    ["37", "0", "0", "0", "0", "0"], ["38", "0", "0", "0", "0", "0"],
    ["39 (break test)", "1", "-", "-", "-", "-"], ["40", "0", "0", "0", "0", "0"],
    ["41 (break test)", "1", "-", "-", "-", "-"],
    ["42", "0", "0", "0", "0", "0"], ["43 (pen test aborted)", "0", "0", "0", "0", "0"], ["44", "0", "0", "0", "0", "0"],
    ["45 (pen test)", "0", "0", "0", "0", "0"], ["46 (break test)", "3", "-", "-", "-", "-"], ["47", "0", "0", "0", "0", "0"],
    ["48 (break test)", "3", "-", "-", "-", "-"], ["49 (break test)", "3", "-", "-", "-", "-"],
    ["50 (final fix)", "0", "0", "0", "0", "0"], ["51 (pen test)", "0", "0", "0", "0", "0"],
], widths=[3.0, 2.4, 2.6, 3.2, 3.4, 2.2])
para("Builds 39, 41, 46, 48 and 49 are deliberate break tests: the eval was put back, sast failed and every later stage was skipped, so their other cells are empty. "
     "Builds 37 onward use the exemptions; earlier builds are shown as they were.", size=10)
para("The trend also caught a mistake of mine. In build 29 the image findings jumped from 14 to 26. The cause was that the scan reports, including "
     "the SBOM written just before the image build, were copied into the Docker image by COPY . . (the pipeline had been doing this since the first scans, "
     "and the SBOM was the first file Trivy read as a package list). I confirmed the reports were inside the image, added reports, history, scripts and docs "
     "to .dockerignore, and build 30 returned to 14. Scan reports inside a production image would have been an information leak.")

# ---------- 5 limits ----------
doc.add_heading("5. Difficulties and honest limits", 1)
bullets([
    ("Accepted risks, not fixes. ", "The dependency and image gates pass because five CVEs and the demo TLS key are exempted, not because they are fixed. "
     "The real fix needs breaking upgrades (MongoDB driver, base image). The reasons for two of them (packages that appear to come from the base image's npm tool) were matched by version, not proven."),
    ("Active scan duration and Docker stability. ", "ZAP's full active scan took 12 to 40+ minutes and varied between builds (builds 19, 24 and 43). In two builds the connection to Docker "
     "dropped during the scan and Docker Desktop stopped once; I never proved the cause. I replaced it with a focused scan of 3.5 minutes in build 45 and 38 seconds in build 51, "
     "which only uses injection and redirect rules, so it is less complete than the full scan, which I do not run any more."),
    ("The pentest gate does not run on every push. ", "A skipped stage cannot block, so this gate is enforced when the test is requested."),
    ("Unauthenticated tests. ", "ZAP never logged in, so code behind the login (the allocations query, the contributions form) was only covered by Semgrep."),
    ("Deployment is a lab setup. ", "Staging and production are two containers on one laptop. The logic (deploy to production only if every gate passed) is what the project demonstrates."),
    ("Webhook relay. ", "Jenkins is on a laptop, so the webhook goes through a third-party relay (smee.io); the payload contains the repository name and commit information, "
     "and it needs internet. On a server with a public address the webhook would point to Jenkins directly."),
    ("Single approver. ", "The exemption procedure asks for a second person; on this one-person project the author approves and the git history records it."),
    ("History is local. ", "trend.csv lives in the Jenkins workspace, so it restarts if the workspace is deleted. Dates are in UTC."),
    ("Notification link. ", "The Slack message links to localhost, so only the machine running Jenkins can open it."),
    ("Platform. ", "Falco needed privileged mode and some kernel features were missing on Docker Desktop; detection still worked. This is a lab setup, not a production one."),
])

# ---------- 6 lessons ----------
doc.add_heading("6. Lessons learned and best practices", 1)
bullets([
    ("Fail fast, but still report. ", "A failed gate stops the pipeline before any deployment, and the post actions (summary, notification, cleanup) still run. "
     "Each scan writes its full report first and then applies its gate."),
    ("Choose thresholds that can be acted on. ", "Blocking on CRITICAL vulnerabilities that already have a fix avoids permanent red builds caused by issues nobody can fix yet."),
    ("Do not trust a green result. ", "I checked that each gate really blocks (builds 10 to 17, and builds 39, 41, 46, 48 and 49 in the final pipeline), found that my first pre-commit demo passed only because of a file-encoding mistake, "
     "and saw that the baseline DAST result changes between runs."),
    ("The pipeline can break security too. ", "Its own output (scan reports and the SBOM) ended up in the Docker image. The trend table caught it; "
     "the fix was a .dockerignore file."),
    ("Keep feedback fast. ", "Fast checks run on every push (about 2 minutes); the 12 to 40 minute active scan runs on demand or on a schedule."),
    ("Match tool versions to the runtime. ", "The dependency fix had to be built with npm 6, the version inside the image, because a newer npm produced a lockfile and overrides that the image ignores."),
    ("Read the logs of the glue. ", "The webhook relay reported success to GitHub while Jenkins rejected every event, because the forwarder dropped a header. Only the Jenkins log showed it."),
    ("Write exemptions as code. ", "Reason, owner, date and expiry next to each exemption, one finding at a time, never a gate switched off, and the exempted findings stay visible in the reports."),
    ("Keep evidence. ", "Archive the raw reports, the summary and a history per build; screenshots of each stage show what the reports contained."),
])

# ---------- 7 conclusion ----------
doc.add_heading("7. Conclusion and next steps", 1)
para("The pipeline starts by itself from a GitHub webhook on every push, applies eight blocking quality gates (one on demand) plus monitoring, stops before any deployment when a gate fails, "
     "deploys to staging and, when everything passed, to production, produces a readable summary with a trend, and notifies by Slack. "
     "Fixing what the gates reported removed the code-injection errors, the configuration failures and the DAST High alert. "
     "The remaining dependency and image findings are recorded as accepted risks with an owner and an expiry date, not hidden.")
para("Next steps, in the order I would do them:", bold=True)
bullets([
    "Upgrade the MongoDB driver and the Node.js base image (breaking changes) to remove the accepted risks, and stop shipping the demo private key in the image.",
    "Give ZAP an authenticated session so the active scan reaches the pages behind the login, and re-run the full scan on a schedule.",
    "Host Jenkins where GitHub can reach it directly, so no relay is needed, and publish the summary page with the HTML Publisher plugin so it keeps its styling.",
    "Keep the trend in a database or in git, and run the active scan on a nightly schedule.",
    "Add a second reviewer for exemptions and add a Semgrep exemption file when a first exemption is needed there.",
])

out = os.path.join(HERE, "DevSecOps-report.docx")
doc.save(out)
print("written", out)

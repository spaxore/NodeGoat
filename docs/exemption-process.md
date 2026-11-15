# Exemption process (exceptional bypass of a quality gate)

A quality gate blocks the build when a scan finds something too serious. Sometimes the finding is a **false positive**
(the tool is wrong) or an **accepted risk** (it is real, but the team decides to live with it for now).
This procedure says how to let such a finding through **without weakening the gate** and **with a trace of who decided what, when and why**.

## Principles
1. **Never disable a gate to get a build through.** Exempt the single finding, not the check.
2. **Every exemption lives in the repository**, so adding it is a git commit: the author, the date and the message are the audit trail.
3. **Every exemption has a reason, an owner and a review date.** An exemption without these is rejected.
4. **Exemptions are temporary by default.** They are reviewed on their date and removed if the reason no longer holds.
5. **A second person approves** (merge request or pull request review). On this single-person lab project the author approves and the
   decision is still recorded in the commit; in a real team the approver must be someone other than the author.

## Required record for every exemption
| Field | Content |
|---|---|
| Finding | Tool, rule or CVE id, file and line, or package and version |
| Type | False positive, or accepted risk |
| Reason | Why it is safe, or why the risk is accepted |
| Compensating control | What limits the risk in the meantime (for example "demo certificate, protects nothing") |
| Owner | Who is responsible for the exemption |
| Decision date | When it was approved |
| Review date | When it must be re-checked (maximum 90 days for accepted risks) |

The record goes in a comment next to the exemption line, and the commit message names the finding (for example
`Exempt CVE-2021-44906 in minimist: only reachable from dev tooling, review 2027-02-11`).

## How to exempt, per gate
| Gate | Mechanism | Where | Status in this project |
|---|---|---|---|
| `secrets_scan` (Gitleaks) | Add the finding's fingerprint to `.gitleaksignore`, with a comment above it | `.gitleaksignore` | **In use**: 5 demo leaks (test ZAP key, self-signed demo certificates) |
| `sast` (Semgrep) | Inline comment `// nosemgrep: <rule-id>` on the flagged line, followed by the reason, or a path in `.semgrepignore` for generated or vendor code | The source file or `.semgrepignore` | Procedure defined, no exemption needed yet |
| `scan_dependencies` and `docker_scan` (Trivy), vulnerabilities | Add the CVE id to `.trivyignore`, one per line, with a comment and an expiry (`exp:YYYY-MM-DD`) | `.trivyignore` | **In use**: 5 CVEs accepted as risks (bson, minimist, fsevents, tar, form-data), expiry 2027-02-12 |
| `docker_scan` (Trivy), secrets | Add an `allow-rules` entry with the file path to `trivy-secret.yaml` | `trivy-secret.yaml` | **In use**: the demo TLS key `artifacts/cert/server.key` |
| `dast` (ZAP) | Add the alert's plugin id to a rules file that marks it as IGNORE for the scan, with a comment | ZAP rules file passed to the scan | Procedure defined, no exemption needed yet |

## Steps
1. **Confirm it is really a false positive or an accepted risk.** Reproduce the finding, read the tool's explanation, and check whether the
   vulnerable code or package is actually reachable.
2. **Write the exemption** with the full record as a comment, in the file for that gate (table above).
3. **Commit it on its own**, with a message that names the finding, and open a review request. Do not mix an exemption with other changes.
4. **Get it approved** by the reviewer.
5. **Merge.** The next pipeline run no longer blocks on that single finding. The report still lists it, so it stays visible.
6. **Review on the review date.** Remove the exemption if the underlying issue is fixed, or renew it with a new date and a new decision.

## Emergency bypass (break-glass)
If a production fix is urgent and a gate blocks it, the person on call may merge the fix with a **temporary exemption** following the same
steps, with a review date of at most 7 days, and must open a ticket to fix the real cause. Switching a gate off is never allowed.

## What is exempted today
| Exemption | Why | Review |
|---|---|---|
| `config/env/test.js` and `config/env/development.js`, `zapApiKey` (3 history entries) | Local ZAP test key in a training application | Before any real use of the code |
| `artifacts/cert/server.key` and `app/cert/key.pem` | Self-signed demo TLS certificates that protect nothing | Before any real use of the code |

These five are listed with their fingerprints in `.gitleaksignore`, together with the date and the decision.

| Exemption (Trivy) | Why | Review |
|---|---|---|
| `CVE-2020-7610` (bson 1.0.9) | Runtime dependency of the MongoDB driver 2.x; parses data from the app's own MongoDB over an internal network. Fix: MongoDB driver 3.x (breaking) | 2027-02-12 |
| `CVE-2021-44906` (minimist) | In the lock file it comes through `forever`, which the app does not run; in the image it appears to be the copy bundled in the base image's npm tool. Only parses command-line arguments | 2027-02-12 |
| `CVE-2023-45311` (fsevents) | macOS-only optional dependency, not installed in the Linux image | 2027-02-12 |
| `CVE-2026-59873` (tar) | macOS-only chain in the lock file; in the image it appears to be bundled in the base image's npm tool. The app never extracts archives | 2027-02-12 |
| `CVE-2025-7783` (form-data) | Appears to be bundled in the base image's npm tool; the app does not build multipart requests from attacker data | 2027-02-12 |
| `artifacts/cert/server.key` (Trivy secret scan) | The demo TLS key; the app loads it at start-up, so it cannot be removed from the image | 2027-02-12 |

These are **accepted risks**, not false positives. They stay visible in the scan reports (`--show-suppressed`) and in the summary page ("N exempted").
The statements about the base image's npm tool come from matching package versions and have not been proven by inspecting the image layer by layer.
The gate stays active: a new critical vulnerability with a fix still blocks the build.

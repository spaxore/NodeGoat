# Evidence log

Every file here is proof for the project report. Files are numbered in the order the work was done.
Rule: never overwrite an "as-is" file. Later "to-be" results get a new number so before/after can be compared.

The `.json` files are the raw tool output (kept as proof). The `.html` files are readable versions of the same
results: open them in a browser and screenshot them for the report.

## As-is (before any security work)

| File | What it proves | Report section |
|---|---|---|
| 01-as-is-login-page.png | NodeGoat runs in Docker on http://localhost:4000 | As-is state |
| 02-as-is-logged-in-benefits.png | The app works with seeded demo data | As-is state |
| 03-as-is-trivy-summary.html (one-screen summary for the report; full list: 03-as-is-trivy-report.html; raw: 03-as-is-trivy-image-scan.json) | Trivy image scan: 90 HIGH/CRITICAL (76 HIGH, 14 CRITICAL), Alpine 3.15 unsupported, private key found in image | SCA and image scan baseline |
| 04-as-is-semgrep-report.html (raw: 04-as-is-semgrep-sast.json) | Semgrep SAST: 10 findings on 3 code locations (eval, open redirect, session cookie settings) | SAST baseline |

## Other as-is facts (from the build and startup logs, no file)

- `npm install` in the image build reported 934 vulnerabilities (51 low, 265 moderate, 531 high, 87 critical).
- The app prints `cookieSecret`, `cryptoKey` and `zapApiKey` in its startup log.
- No security checks exist in the current CI (GitHub Actions runs JSHint and Cypress only).

## Shift-left

| File | What it proves |
|---|---|
| 05-precommit-gitleaks-blocked.png | Screenshot: a commit containing a fake token is blocked by Gitleaks (rule github-pat) |
| 06-precommit-clean-commit-passed.png | Screenshot: a clean commit passes (Gitleaks Passed, Semgrep Skipped: no files to check) |

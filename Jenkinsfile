// DevSecOps pipeline for NodeGoat: security checks at every phase, then deployment.
// Order: checkout, static checks (secrets, SAST, dependencies, configuration), build, image scan, smoke and security checks,
// deployment to staging, dynamic scans, monitoring, deployment to production.
// Stages run in order and a failing gate stops the pipeline (fail fast): nothing after it runs, so nothing is deployed.
// The post section at the end always runs: summary page, trend history, Slack notification and cleanup.
// Started automatically by a GitHub webhook on every push (no polling).
pipeline {
    agent any

    // Automatic execution, no polling: a GitHub webhook calls Jenkins on every push and the build starts at once.
    // githubPush() comes from the Jenkins "GitHub" plugin. The webhook (GitHub repository settings) points to <Jenkins URL>/github-webhook/.
    // This Jenkins runs on a laptop, so GitHub reaches it through a webhook relay (smee.io): see docs/webhook-setup.md.
    triggers {
        githubPush()
    }

    // The active penetration test takes 12 to 40 minutes, so it does not run on every push.
    // Tick RUN_PENTEST in "Build with Parameters" to run it; automatic builds skip it and finish in a few minutes.
    parameters {
        booleanParam(name: 'RUN_PENTEST', defaultValue: false, description: 'Run the active ZAP penetration test (slow: 12 to 40 minutes)')
    }

    options {
        timestamps()
        ansiColor('xterm')
        // A full run takes 17 to 25 minutes (the active scan is the longest stage and its length varies), so the whole-build limit leaves a wide margin.
        timeout(time: 50, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
        // One build at a time: two full runs together would compete for memory on this machine.
        disableConcurrentBuilds()
    }

    environment {
        IMAGE = "nodegoat-web:${env.BUILD_NUMBER}"
        // The ci- prefix keeps these names from clashing with containers started by hand or by docker compose.
        NET   = "ci-net-${env.BUILD_NUMBER}"
        MONGO = "ci-mongo-${env.BUILD_NUMBER}"
        WEB   = "ci-web-${env.BUILD_NUMBER}"
        ZAP   = "ci-zap-${env.BUILD_NUMBER}"
        FALCO = "ci-falco-${env.BUILD_NUMBER}"
        // Deployment targets use fixed names (not per build): the deployed app stays up between builds, so it can be opened in a browser.
        // Staging is where the dynamic scans run; production is only updated when every quality gate passed.
        STG = "nodegoat-staging"
        STG_MONGO = "nodegoat-staging-mongo"
        STG_NET = "nodegoat-staging-net"
        PRD = "nodegoat-production"
        PRD_MONGO = "nodegoat-production-mongo"
        PRD_NET = "nodegoat-production-net"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                // The workspace is reused between builds. Without this, a stage that does not finish would leave the
                // previous build's report in reports/ and Jenkins would archive it as if it belonged to this build.
                sh 'rm -rf reports'
            }
        }

        // Looks for passwords, keys and tokens in the working tree and in the whole git history.
        // The scanner runs as a throwaway container; --volumes-from jenkins gives it the checked-out workspace.
        // QUALITY GATE: any leak not listed in .gitleaksignore (the approved exemptions) makes it exit 1 and fail the build.
        // FAIL FAST: if a gate fails, the stage fails and the pipeline STOPS here. Every later stage is skipped, so nothing is deployed.
        // The post section at the end still runs (summary, notification, cleanup), whatever the result.
        stage('secrets_scan') {
            steps {
                sh '''
                    mkdir -p reports
                    docker run --rm --volumes-from jenkins -w "$WORKSPACE" zricethezav/gitleaks:latest \
                        detect --source . --redact --exit-code 1 \
                        --report-format json --report-path reports/gitleaks.json
                '''
            }
        }

        // Static analysis (SAST): reads the JavaScript source for dangerous patterns without running the app.
        // Third-party libraries under app/assets/vendor are not our code, so they are skipped.
        // The Semgrep image refuses to run unless the code is mounted at /src, so /src is made to point at the workspace.
        // QUALITY GATE, two passes: pass 1 saves every finding to the report and never fails; pass 2 is the gate,
        // it looks only at severity ERROR (likely exploitable code) and --error makes it exit 1 if it finds any.
        // WARNING findings (hardening gaps) stay in the report but do not block.
        stage('sast') {
            steps {
                sh '''
                    mkdir -p reports
                    docker run --rm --volumes-from jenkins -e WS="$WORKSPACE" --entrypoint sh semgrep/semgrep -c '
                        ln -s "$WS" /src && cd "$WS" &&
                        semgrep --config p/javascript --exclude app/assets/vendor --metrics=off \
                            --json --output reports/semgrep.json . &&
                        semgrep --config p/javascript --exclude app/assets/vendor --metrics=off \
                            --severity ERROR --error --quiet .
                    '
                '''
            }
        }

        // Software composition analysis (SCA): checks every npm package version in package-lock.json
        // against a database of known vulnerabilities (CVEs). Needs no build, only the dependency list.
        // The trivy-cache volume keeps the vulnerability database between runs, so it is downloaded only once.
        // QUALITY GATE, two passes: pass 1 saves every HIGH and CRITICAL finding to the report and never fails;
        // pass 2 is the gate, it looks only at CRITICAL vulnerabilities that already have a fixed version
        // (--ignore-unfixed) and exits 1 if there is one. HIGH findings, and critical ones nobody has fixed yet, only warn.
        // Accepted risks are listed in .trivyignore (reason, owner and expiry date for each, see docs/exemption-process.md).
        // --show-suppressed keeps those findings in the report, so an exemption never hides anything.
        stage('scan_dependencies') {
            steps {
                sh '''
                    mkdir -p reports
                    docker run --rm --volumes-from jenkins -v trivy-cache:/root/.cache -w "$WORKSPACE" aquasec/trivy \
                        fs --skip-version-check --scanners vuln --severity HIGH,CRITICAL --exit-code 0 --show-suppressed \
                        --format json --output reports/trivy-deps.json .
                    # SBOM (software bill of materials): the full list of packages in the standard CycloneDX format, saved as an artifact.
                    docker run --rm --volumes-from jenkins -v trivy-cache:/root/.cache -w "$WORKSPACE" aquasec/trivy \
                        fs --skip-version-check --scanners vuln --format cyclonedx --output reports/sbom.cdx.json .
                    docker run --rm --volumes-from jenkins -v trivy-cache:/root/.cache -w "$WORKSPACE" aquasec/trivy \
                        fs --skip-version-check --scanners vuln --severity CRITICAL --ignore-unfixed --exit-code 1 \
                        --format table .
                '''
            }
        }

        // Configuration safety check (IaC scan): Checkov reads the Dockerfiles and the GitHub workflows for risky settings
        // (missing HEALTHCHECK, over-broad workflow permissions...). Static, so it needs no build.
        // QUALITY GATE, two passes: pass 1 (--soft-fail) writes the full JSON report and never fails; pass 2 prints the
        // readable findings and exits 1 if any check failed. node_modules, docs and reports are not our configuration.
        stage('config_scan') {
            steps {
                sh '''
                    mkdir -p reports
                    docker run --rm --volumes-from jenkins -w "$WORKSPACE" bridgecrew/checkov:latest \
                        -d . --skip-path node_modules --skip-path docs --skip-path reports --soft-fail \
                        --compact --quiet -o json --output-file-path reports > /dev/null
                    docker run --rm --volumes-from jenkins -w "$WORKSPACE" bridgecrew/checkov:latest \
                        -d . --skip-path node_modules --skip-path docs --skip-path reports \
                        -o cli --compact --quiet
                '''
            }
        }

        stage('Build image') {
            steps {
                sh 'docker build -t "$IMAGE" .'
            }
        }

        // Image scan: checks the finished image (operating system packages, npm packages and secrets baked in),
        // so it must run after the image is built. Jenkins' docker.sock is shared through --volumes-from,
        // which is how Trivy reads the image from the Docker host.
        // QUALITY GATE, three passes: pass 1 saves the full report and never fails; pass 2 blocks on CRITICAL
        // vulnerabilities that already have a fix; pass 3 blocks on ANY secret in the image, at every severity,
        // because Trivy rates a leaked private key as HIGH and the severity filter of pass 2 would let it through.
        stage('docker_scan') {
            steps {
                sh '''
                    mkdir -p reports
                    docker run --rm --volumes-from jenkins -v trivy-cache:/root/.cache -w "$WORKSPACE" aquasec/trivy \
                        image --skip-version-check --scanners vuln,secret --secret-config trivy-secret.yaml --severity HIGH,CRITICAL --exit-code 0 --show-suppressed \
                        --format json --output reports/trivy-image.json "$IMAGE"
                    gate=0
                    docker run --rm --volumes-from jenkins -v trivy-cache:/root/.cache -w "$WORKSPACE" aquasec/trivy \
                        image --skip-version-check --scanners vuln --severity CRITICAL --ignore-unfixed --exit-code 1 \
                        --format table "$IMAGE" || gate=1
                    docker run --rm --volumes-from jenkins -v trivy-cache:/root/.cache -w "$WORKSPACE" aquasec/trivy \
                        image --skip-version-check --scanners secret --secret-config trivy-secret.yaml --exit-code 1 \
                        --format table "$IMAGE" || gate=1
                    exit $gate
                '''
            }
        }

        // Intrusion monitoring, part 1: Falco watches the host's system calls and raises an alert when a container does
        // something suspicious (a shell opened inside it, a sensitive file read...). It is started BEFORE the app so it sees
        // the app from its first second. It needs --privileged and the Docker socket to read the kernel and the container names.
        // This is a lab setup: in production Falco runs on the host as a service, not inside a build.
        stage('monitor_start') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh '''
                        docker run -d --name "$FALCO" --privileged \
                            -v /var/run/docker.sock:/host/var/run/docker.sock -v /proc:/host/proc:ro -v /etc:/host/etc:ro \
                            falcosecurity/falco:latest falco -o engine.kind=modern_ebpf
                        sleep 10
                        docker logs "$FALCO" 2>&1 | grep -E "Opening 'syscall' source|Falco version" | head -n 2
                    '''
                }
            }
        }

        // Starts MongoDB and the app on a private network, then waits for the login page to answer.
        stage('Smoke test') {
            steps {
                sh '''
                    docker network create "$NET"
                    docker run -d --name "$MONGO" --network "$NET" mongo:4.4
                    docker run -d --name "$WEB" --network "$NET" \
                        --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --memory 512m --pids-limit 256 \
                        -e MONGODB_URI="mongodb://$MONGO:27017/nodegoat" \
                        "$IMAGE" \
                        sh -c "until nc -z -w 2 $MONGO 27017; do sleep 2; done; node artifacts/db-reset.js && npm start"

                    for i in $(seq 1 30); do
                        if docker exec "$WEB" wget -q -O /dev/null http://localhost:4000/login; then
                            echo "App answered on /login"
                            exit 0
                        fi
                        sleep 3
                    done

                    echo "App did not answer within 90 seconds"
                    docker logs "$WEB"
                    exit 1
                '''
            }
        }

        // Security smoke test: a few fast yes/no questions about whether the freshly started system is safe to expose.
        // It reuses the app started by the Smoke test. Known weaknesses (missing headers, X-Powered-By) are left to the
        // DAST stage so the two do not duplicate each other. Any FAIL makes the stage, and the build, fail.
        stage('security_smoke') {
            steps {
                sh '''
                    fail=0

                    uid=$(docker exec "$WEB" id -u)
                    if [ "$uid" = "0" ]; then
                        echo "FAIL: the app runs as root"; fail=1
                    else
                        echo "PASS: the app runs as a non-root user (uid $uid)"
                    fi

                    for p in .git/config package.json Dockerfile server.js config/env/all.js artifacts/cert/server.key .env; do
                        code=$(docker exec "$WEB" sh -c "wget -S -O /dev/null http://localhost:4000/$p 2>&1 | grep 'HTTP/' | tail -n 1 | grep -o '[0-9][0-9][0-9]' | head -n 1")
                        if [ "$code" = "404" ]; then
                            echo "PASS: /$p is not exposed (404)"
                        else
                            echo "FAIL: /$p answered with status $code"; fail=1
                        fi
                    done

                    if docker exec "$WEB" sh -c "echo x > /home/node/app/injected.txt" 2>/dev/null; then
                        echo "FAIL: the application folder is writable"; fail=1
                    else
                        echo "PASS: the filesystem is read-only"
                    fi

                    caps=$(docker exec "$WEB" sh -c "grep CapEff /proc/1/status")
                    case "$caps" in
                        *0000000000000000) echo "PASS: the app process has no Linux capabilities" ;;
                        *) echo "FAIL: the app process has capabilities ($caps)"; fail=1 ;;
                    esac

                    cookie=$(docker exec "$WEB" sh -c "wget -S -O /dev/null http://localhost:4000/login 2>&1 | grep -i set-cookie")
                    case "$cookie" in
                        *HttpOnly*) echo "PASS: the session cookie is HttpOnly" ;;
                        *) echo "FAIL: the session cookie is not HttpOnly"; fail=1 ;;
                    esac

                    exit $fail
                '''
            }
        }

        // DEPLOYMENT, step 1: staging. The image that was scanned and passed the smoke checks is deployed as a long-running,
        // hardened container (read-only, no capabilities, memory and process limits) with its own database, reachable at
        // http://localhost:4001. Staging is the target of the dynamic scans below, as the brief asks (DAST on a staging environment).
        // Each deployment replaces the previous one, so staging always runs the latest build.
        stage('deploy_staging') {
            steps {
                sh '''
                    set -e
                    docker network inspect "$STG_NET" >/dev/null 2>&1 || docker network create "$STG_NET"
                    docker rm -f "$STG" "$STG_MONGO" >/dev/null 2>&1 || true
                    docker run -d --name "$STG_MONGO" --network "$STG_NET" --restart unless-stopped mongo:4.4
                    docker run -d --name "$STG" --network "$STG_NET" -p 4001:4000 --restart unless-stopped \
                        --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --memory 512m --pids-limit 256 \
                        -e MONGODB_URI="mongodb://$STG_MONGO:27017/nodegoat" \
                        "$IMAGE" sh -c "until nc -z -w 2 $STG_MONGO 27017; do sleep 2; done; node artifacts/db-reset.js && npm start"
                    for i in $(seq 1 30); do
                        if docker exec "$STG" wget -q -O /dev/null http://localhost:4000/login; then
                            echo "DEPLOYED to staging: $IMAGE is answering on http://localhost:4001"
                            exit 0
                        fi
                        sleep 3
                    done
                    echo "Staging did not answer within 90 seconds"
                    docker logs "$STG"
                    exit 1
                '''
            }
        }

        // Dynamic analysis (DAST): OWASP ZAP attacks the running app from outside, like a real attacker.
        // It attacks the staging deployment started by deploy_staging, so it must stay after that stage.
        // -m 1 caps the crawl at one minute (it usually ends sooner, once every page is visited) and -I keeps warnings
        // from failing the build; only the High-risk check below can fail it. Known limit: a passive crawl does not always
        // reach every page, so the High alert was missed in 1 of the first 4 runs.
        // The ZAP container is not removed on exit so the reports can be copied out; the post block cleans it up.
        // QUALITY GATE: after the scan, the JSON report is searched for alerts of risk code 3 (High). Any one of them
        // fails the stage. Medium, Low and Informational alerts stay in the report and only warn.
        stage('dast') {
            steps {
                sh '''
                    mkdir -p reports
                    docker run --name "$ZAP" --network "$STG_NET" --entrypoint sh zaproxy/zap-stable -c \
                        "mkdir -p /zap/wrk && zap-baseline.py -t http://$STG:4000 -m 1 -r zap.html -J zap.json -I"
                    docker cp "$ZAP:/zap/wrk/zap.json" reports/zap.json
                    docker cp "$ZAP:/zap/wrk/zap.html" reports/zap.html

                    highs=$(grep -o '"riskcode": *"3"' reports/zap.json | wc -l)
                    echo "ZAP high-risk alerts: $highs"
                    if [ "$highs" -gt 0 ]; then
                        echo "Blocking alerts:"
                        grep -B1 '"riskcode": *"3"' reports/zap.json | grep '"name"'
                        exit 1
                    fi
                '''
            }
        }

        // Penetration test: the same ZAP tool, but in active mode. The baseline scan above only watches traffic; the full scan
        // also sends attack payloads (injection, XSS, path traversal...) to the app and reports what actually answers like a vulnerable page.
        // The attack target is the throwaway container of this build, inside the isolated build network. The scan is unauthenticated,
        // so pages behind the login are not tested, and the tutorial pages embed third-party content that ZAP's browser also loads (it is not the target).
        // The first ZAP container is removed so its name can be reused (the dast stage has already copied its reports).
        // --memory 4g limits the ZAP container. Builds #22 and #23 lost the connection to Docker ("unexpected EOF") in the middle of this
        // scan, and Docker Desktop was found stopped afterwards. The cause is not proven; the limit is an attempt to keep a heavy scan
        // from starving the Docker VM (7.6 GB), so that ZAP alone would fail with a clear message.
        // The scan length varies from about 12 to 27 minutes between builds. An attempt to cap the attack phase with ZAP's
        // scanner.maxScanDurationInMins option had no effect (build #24 still took 27 minutes), so it was removed.
        // This stage runs only when RUN_PENTEST is ticked. When it is skipped it cannot block the build, so the pen-test gate
        // is enforced on demand, not on every push. Evidence of full runs: builds 19 and 24.
        // The timeout stops a slow scan from blocking Jenkins. QUALITY GATE: same rule as dast, any High-risk alert fails the stage.
        stage('pentest') {
            when { expression { return params.RUN_PENTEST } }
            steps {
                timeout(time: 40, unit: 'MINUTES') {
                    sh '''
                        mkdir -p reports
                        docker rm -f "$ZAP" || true
                        docker run --name "$ZAP" --network "$STG_NET" --memory 4g --entrypoint sh zaproxy/zap-stable -c \
                            "mkdir -p /zap/wrk && zap-full-scan.py -t http://$STG:4000 -m 1 -r zap-full.html -J zap-full.json -I"
                        docker cp "$ZAP:/zap/wrk/zap-full.json" reports/zap-full.json
                        docker cp "$ZAP:/zap/wrk/zap-full.html" reports/zap-full.html

                        highs=$(grep -o '"riskcode": *"3"' reports/zap-full.json | wc -l)
                        echo "Pentest high-risk alerts: $highs"
                        if [ "$highs" -gt 0 ]; then
                            echo "Blocking alerts:"
                            grep -B1 '"riskcode": *"3"' reports/zap-full.json | grep '"name"'
                            exit 1
                        fi
                    '''
                }
            }
        }

        // Log monitoring: reads the application's own log after the scans and counts the security events it recorded
        // (failed logins, access to protected pages without a session, rejected signups, database errors).
        // The full log is saved as a report. More than 10 failed logins in one run raises an ALERT line (a possible password-guessing attack).
        // Like Falco, this stage detects and reports; it does not block the build.
        // Only the counts and the first lines of each event are printed: the log contains text typed by the attacker, so it is kept out of the console.
        stage('log_monitor') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh '''
                        mkdir -p reports
                        docker logs "$STG" > reports/app.log 2>&1
                        failed=$(grep -c "attempt to login with invalid user" reports/app.log || true)
                        noauth=$(grep -c "redirecting to login" reports/app.log || true)
                        badsignup=$(grep -c "user did not validate" reports/app.log || true)
                        dberr=$(grep -c "Error: DB" reports/app.log || true)
                        echo "Application log lines: $(wc -l < reports/app.log)"
                        echo "Failed logins: $failed"
                        echo "Requests to protected pages without a session: $noauth"
                        echo "Rejected signups: $badsignup"
                        echo "Database errors: $dberr"
                        if [ "$failed" -gt 10 ]; then
                            echo "ALERT: $failed failed logins in one run, possible password-guessing attack"
                            grep "attempt to login with invalid user" reports/app.log | head -n 3 | cut -c1-120
                        fi
                    '''
                }
            }
        }

        // Intrusion monitoring, part 2: reads what Falco saw while the app was started, checked and attacked by ZAP.
        // The whole log is saved as a report; the alerts that name the application container are printed here.
        // Monitoring detects and reports, it does not block: an alert is a lead for a human to investigate.
        stage('monitor_report') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh '''
                        mkdir -p reports
                        docker logs "$FALCO" > reports/falco.log 2>&1
                        total=$(grep -c -E ": (Emergency|Alert|Critical|Error|Warning|Notice) " reports/falco.log || true)
                        app=$(grep -c -E "$WEB|$STG" reports/falco.log || true)
                        echo "Falco alerts during the run, all containers: $total"
                        echo "Falco alerts about the application containers ($WEB, $STG): $app"
                        if [ "$app" -gt 0 ]; then
                            grep -E "$WEB|$STG" reports/falco.log | cut -c1-250
                        fi
                    '''
                }
            }
        }

        // DEPLOYMENT, step 2: production. It is reached only if every stage before it passed (a failed gate stops the pipeline earlier).
        // As a safety net, it also checks that the build is still green: if a report-only stage failed, nothing is deployed, the stage is
        // marked UNSTABLE (yellow) with a clear message, and production keeps running the last version that passed everything.
        // Production uses the same hardened settings as staging, with its own database, on http://localhost:4002.
        stage('deploy_production') {
            steps {
                script {
                    if (currentBuild.currentResult == 'SUCCESS') {
                        sh '''
                            set -e
                            docker network inspect "$PRD_NET" >/dev/null 2>&1 || docker network create "$PRD_NET"
                            docker rm -f "$PRD" "$PRD_MONGO" >/dev/null 2>&1 || true
                            docker run -d --name "$PRD_MONGO" --network "$PRD_NET" --restart unless-stopped mongo:4.4
                            docker run -d --name "$PRD" --network "$PRD_NET" -p 4002:4000 --restart unless-stopped \
                                --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --memory 512m --pids-limit 256 \
                                -e MONGODB_URI="mongodb://$PRD_MONGO:27017/nodegoat" \
                                "$IMAGE" sh -c "until nc -z -w 2 $PRD_MONGO 27017; do sleep 2; done; node artifacts/db-reset.js && npm start"
                            for i in $(seq 1 30); do
                                if docker exec "$PRD" wget -q -O /dev/null http://localhost:4000/login; then
                                    echo "DEPLOYED to production: $IMAGE is answering on http://localhost:4002"
                                    exit 0
                                fi
                                sleep 3
                            done
                            echo "Production did not answer within 90 seconds"
                            docker logs "$PRD"
                            exit 1
                        '''
                    } else {
                        echo "RELEASE BLOCKED: at least one quality gate failed (result so far: ${currentBuild.currentResult}). Nothing was deployed to production."
                        unstable('release blocked by the quality gates')
                    }
                }
            }
        }
    }

    post {
        always {
            // Reporting: turns the raw JSON reports into one readable page. It runs here, after every stage (even when some
            // failed), so the page always describes the whole build. The script runs in a small throwaway Python container.
            catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                sh '''
                    mkdir -p reports history
                    docker run --rm --volumes-from jenkins -e WS="$WORKSPACE" -e BUILD_NUMBER python:3.12-alpine \
                        sh -c 'python -I "$WS/scripts/summary.py" "$WS/reports" "$WS/reports/summary.html" "$BUILD_NUMBER" "$WS/history/trend.csv"'
                '''
            }
            // history/trend.csv keeps one line per build and survives between builds because the workspace is reused.
            archiveArtifacts artifacts: 'reports/**, history/**', allowEmptyArchive: true
            sh '''
                docker rm -f "$FALCO" "$ZAP" "$WEB" "$MONGO" || true
                docker network rm "$NET" || true
            '''
            // Notification: one short message with the result and a link to the build, sent to a chat webhook.
            // The webhook URL is a secret, so it comes from the Jenkins credential "notify-webhook" and is never written in this file.
            // Single quotes below keep Groovy from copying the secret into the script text; Jenkins also masks it in the log.
            // A failed notification must never change the build result, hence "|| echo".
            withEnv(["RESULT=${currentBuild.currentResult}"]) {
              withCredentials([string(credentialsId: 'notify-webhook', variable: 'HOOK')]) {
                sh '''
                    msg="NodeGoat pipeline #${BUILD_NUMBER} finished: ${RESULT}. Details and reports: ${BUILD_URL}"
                    curl -s -S -m 20 -X POST -H 'Content-Type: application/json' \
                        --data "{\\"text\\": \\"$msg\\"}" "$HOOK" > /dev/null \
                        && echo "Notification sent" || echo "Notification could not be sent"
                '''
              }
            }
        }
    }
}

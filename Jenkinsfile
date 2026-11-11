// Baseline CI pipeline for NodeGoat: build the image and check that the app starts.
// Security stages (secrets scan, SAST, SCA, image scan, DAST) are added on top of this in the next steps.
pipeline {
    agent any

    options {
        timestamps()
        ansiColor('xterm')
        timeout(time: 20, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }

    environment {
        IMAGE = "nodegoat-web:${env.BUILD_NUMBER}"
        // The ci- prefix keeps these names from clashing with containers started by hand or by docker compose.
        NET   = "ci-net-${env.BUILD_NUMBER}"
        MONGO = "ci-mongo-${env.BUILD_NUMBER}"
        WEB   = "ci-web-${env.BUILD_NUMBER}"
        ZAP   = "ci-zap-${env.BUILD_NUMBER}"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        // Looks for passwords, keys and tokens in the working tree and in the whole git history.
        // The scanner runs as a throwaway container; --volumes-from jenkins gives it the checked-out workspace.
        // QUALITY GATE: any leak not listed in .gitleaksignore (the approved exemptions) makes it exit 1 and fail the build.
        // catchError marks the build as failed but lets the remaining scans run, so one run collects all the evidence.
        stage('secrets_scan') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh '''
                        mkdir -p reports
                        docker run --rm --volumes-from jenkins -w "$WORKSPACE" zricethezav/gitleaks:latest \
                            detect --source . --redact --exit-code 1 \
                            --report-format json --report-path reports/gitleaks.json
                    '''
                }
            }
        }

        // Static analysis (SAST): reads the JavaScript source for dangerous patterns without running the app.
        // Third-party libraries under app/assets/vendor are not our code, so they are skipped.
        // The Semgrep image refuses to run unless the code is mounted at /src, so /src is made to point at the workspace.
        // Like the secrets scan, it only reports for now.
        stage('sast') {
            steps {
                sh '''
                    mkdir -p reports
                    docker run --rm --volumes-from jenkins -e WS="$WORKSPACE" --entrypoint sh semgrep/semgrep -c '
                        ln -s "$WS" /src && cd "$WS" &&
                        semgrep --config p/javascript --exclude app/assets/vendor --metrics=off \
                            --json --output reports/semgrep.json .
                    '
                '''
            }
        }

        // Software composition analysis (SCA): checks every npm package version in package-lock.json
        // against a database of known vulnerabilities (CVEs). Needs no build, only the dependency list.
        // The trivy-cache volume keeps the vulnerability database between runs, so it is downloaded only once.
        // Like the other scans, it only reports for now.
        stage('scan_dependencies') {
            steps {
                sh '''
                    mkdir -p reports
                    docker run --rm --volumes-from jenkins -v trivy-cache:/root/.cache -w "$WORKSPACE" aquasec/trivy \
                        fs --skip-version-check --scanners vuln --severity HIGH,CRITICAL --exit-code 0 \
                        --format json --output reports/trivy-deps.json .
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
        // which is how Trivy reads the image from the Docker host. Like the other scans, it only reports for now.
        stage('docker_scan') {
            steps {
                sh '''
                    mkdir -p reports
                    docker run --rm --volumes-from jenkins -v trivy-cache:/root/.cache -w "$WORKSPACE" aquasec/trivy \
                        image --skip-version-check --scanners vuln,secret --severity HIGH,CRITICAL --exit-code 0 \
                        --format json --output reports/trivy-image.json "$IMAGE"
                '''
            }
        }

        // Starts MongoDB and the app on a private network, then waits for the login page to answer.
        stage('Smoke test') {
            steps {
                sh '''
                    docker network create "$NET"
                    docker run -d --name "$MONGO" --network "$NET" mongo:4.4
                    docker run -d --name "$WEB" --network "$NET" \
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

        // Dynamic analysis (DAST): OWASP ZAP attacks the running app from outside, like a real attacker.
        // It reuses the app and network started by the Smoke test, so it must stay after that stage.
        // -m 1 limits the crawl to one minute and -I keeps warnings from failing the build (report only for now).
        // The ZAP container is not removed on exit so the reports can be copied out; the post block cleans it up.
        stage('dast') {
            steps {
                sh '''
                    mkdir -p reports
                    docker run --name "$ZAP" --network "$NET" --entrypoint sh zaproxy/zap-stable -c \
                        "mkdir -p /zap/wrk && zap-baseline.py -t http://$WEB:4000 -m 1 -r zap.html -J zap.json -I"
                    docker cp "$ZAP:/zap/wrk/zap.json" reports/zap.json
                    docker cp "$ZAP:/zap/wrk/zap.html" reports/zap.html
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
            sh '''
                docker rm -f "$ZAP" "$WEB" "$MONGO" || true
                docker network rm "$NET" || true
            '''
        }
    }
}

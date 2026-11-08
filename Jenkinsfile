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
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        // Looks for passwords, keys and tokens in the working tree and in the whole git history.
        // The scanner runs as a throwaway container; --volumes-from jenkins gives it the checked-out workspace.
        // It only reports for now (--exit-code 0): blocking thresholds come later with the quality gate.
        stage('secrets_scan') {
            steps {
                sh '''
                    mkdir -p reports
                    docker run --rm --volumes-from jenkins -w "$WORKSPACE" zricethezav/gitleaks:latest \
                        detect --source . --redact --exit-code 0 \
                        --report-format json --report-path reports/gitleaks.json
                '''
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

        stage('Build image') {
            steps {
                sh 'docker build -t "$IMAGE" .'
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
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
            sh '''
                docker rm -f "$WEB" "$MONGO" || true
                docker network rm "$NET" || true
            '''
        }
    }
}

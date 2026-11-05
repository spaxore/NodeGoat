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
        NET   = "nodegoat-ci-${env.BUILD_NUMBER}"
        MONGO = "nodegoat-mongo-${env.BUILD_NUMBER}"
        WEB   = "nodegoat-web-${env.BUILD_NUMBER}"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
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
            sh '''
                docker rm -f "$WEB" "$MONGO" || true
                docker network rm "$NET" || true
            '''
        }
    }
}

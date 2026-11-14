# Jenkins controller for the DevSecOps lab.
# It is the official LTS image plus the Docker CLI, so pipeline stages can run
# security tools (Trivy, Semgrep, Gitleaks, ZAP) as containers.
FROM jenkins/jenkins:lts-jdk17

USER root

# Docker CLI only (no daemon): the daemon is the host's, reached through the mounted socket.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
 && install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
      > /etc/apt/sources.list.d/docker.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends docker-ce-cli \
 && rm -rf /var/lib/apt/lists/*

USER jenkins

# Plugins the pipeline needs: Git checkout, Pipeline (Jenkinsfile), credentials,
# HTML report publishing, timestamps and coloured logs.
RUN jenkins-plugin-cli --plugins \
    git \
    workflow-aggregator \
    credentials-binding \
    htmlpublisher \
    timestamper \
    ansicolor \
    github

# Reports whether the Jenkins web interface answers (the login page is public). Takes effect the next time this image is rebuilt.
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
  CMD curl -fsS -o /dev/null http://localhost:8080/login || exit 1

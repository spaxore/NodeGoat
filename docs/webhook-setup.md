# Automatic build on push: GitHub webhook (no polling)

The standard way to start a pipeline on every push is a **webhook**: GitHub sends an HTTP request to Jenkins the moment a push arrives, so the build starts at once. There is no timer and no polling. In the `Jenkinsfile` this is `triggers { githubPush() }`.

Problem: this Jenkins runs on a laptop, and GitHub cannot reach a laptop. A **webhook relay** solves it: GitHub sends the webhook to smee.io (a public inbox), and a small program on the laptop (`smee-client`) forwards it to the local Jenkins. Jenkins itself is never exposed to the internet. On a real server with a public address, the webhook would point to Jenkins directly.

```
git push -> GitHub -> (webhook) -> smee.io -> smee-client on the laptop -> Jenkins /github-webhook/ -> build starts
```

## One-time setup (internet needed)

### 1. Install the GitHub plugin in Jenkins
Jenkins -> Manage Jenkins -> Plugins -> Available plugins -> search **GitHub** (plugin id `github`) -> tick it -> **Install**, and tick "Restart Jenkins when installation is complete". Log in again after the restart.
(`jenkins/Dockerfile` now lists `github` too, so a rebuilt image has it.)
**Do this before pushing the new Jenkinsfile.** Without the plugin, `githubPush()` is an unknown trigger and the build fails at start.

### 2. Create the relay channel
Open https://smee.io -> "Start a new channel" -> copy the channel URL (for example `https://smee.io/AbC123xyz`).

### 3. Start the forwarder (keep this terminal open while you work or record)
```
npx -y smee-client@2.0.4 --url https://smee.io/AbC123xyz --target http://localhost:8080/github-webhook/
```
It prints that it is forwarding to the local Jenkins. The trailing slash after `github-webhook` is required.
**Use version 2.0.4.** Version 5.0.0 (the latest when this was written) forwarded the events without the `Content-Type` header, so Jenkins rejected every one
with "Unknown content type null" in its log, and no build started. Run only one forwarder at a time, or Jenkins receives every event twice.

### 4. Add the webhook on GitHub
Repository `spaxore/NodeGoat` -> Settings -> Webhooks -> Add webhook:
- Payload URL: the smee channel URL
- Content type: `application/json`
- Events: **Just the push event**
- Active: ticked
Save. GitHub sends a "ping": under Recent Deliveries it must show a green tick, and the smee terminal shows a forwarded request.

### 5. Start one build by hand
Jenkins registers the trigger only after the pipeline has run once with `githubPush()`. Click **Build Now** once.

## Test
Make any commit and `git push origin master`. A new build must appear within a second or two, and its page says **"Started by GitHub push by ..."**.
(Verified: build 38 started this way and ran every stage to the end, including both deployments.)

## If nothing starts
1. GitHub -> Settings -> Webhooks -> the webhook -> Recent Deliveries: the push must be listed with a green tick (otherwise GitHub did not send it).
2. The forwarder terminal must show `POST http://localhost:8080/github-webhook/ - 200` after the push (otherwise the relay is not running or not forwarding).
3. The Jenkins log (`docker logs jenkins`) must not show `Unknown content type null` (that is the forwarder-version problem above).
4. The Jenkins job must have the GitHub push trigger: run one build by hand after the Jenkinsfile with `githubPush()` was pushed.

## Evidence to capture
- GitHub webhook page with the green tick.
- The smee terminal showing the forwarded request.
- The build page saying "Started by GitHub push".

## What to say about it
- A webhook is the standard trigger: the build starts when the push happens, with no polling.
- Jenkins is on a laptop that GitHub cannot reach, so I used a relay (smee.io) with a forwarder. On a real server the webhook would point straight to Jenkins.
- Limits: it needs internet (GitHub is remote, so nothing could reach it offline either); smee.io is a third-party relay and the payload contains the repository name and commit information, which is acceptable for a lab but not for private code.

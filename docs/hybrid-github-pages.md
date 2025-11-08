# Hybrid GitHub Pages Prototype

This document outlines how to keep the scheduled Lambda/EventBridge aggregation pipeline while shifting the read-only web UI to GitHub Pages for inexpensive, CDN-backed hosting.

## Goals

1. Keep the authoritative `aws-actions.json` manifest in the private S3 bucket managed by the existing CDK stack.
2. Reuse the nightly EventBridge + Lambda job so data freshness and scraping logic stay in AWS.
3. Publish only the static UI bundle (plus the retrieved JSON) to GitHub Pages, reducing the AWS surface area to S3 + Lambda.
4. Allow rapid previews by triggering GitHub Pages builds manually while keeping production data protected behind IAM.

## High-Level Flow

1. **EventBridge → Lambda** (unchanged): Lambda aggregates IAM actions and writes `aws-actions.json` to `s3://<ActionsIndexBucket>/aws-actions.json`.
2. **GitHub Actions (scheduled + manual)**: A workflow assumes a minimal AWS role, runs `aws s3 cp` to download the manifest into `service-browser-app/public/aws-actions.json`, and runs the Vite build.
3. **GitHub Pages deploy**: The workflow uploads the `service-browser-app/dist` output as a Pages artifact and publishes it at `<org>.github.io/aws-service-browser` (or a custom domain managed in GitHub).
4. **Browser clients**: The React app reads the baked-in JSON asset via a relative fetch (`/aws-actions.json`). No runtime call to AWS is required from Pages.

```
EventBridge ─▶ Lambda ─▶ S3 (private)
                              │
                GitHub OIDC role w/ GetObject
                              │
                 GitHub Actions workflow
                              │
                 GitHub Pages static hosting
```

## AWS Requirements

1. **Data bucket**: Continue deploying the `ActionsIndexBucket` from `ServiceBrowserStack`. No public access is required.
2. **IAM role for GitHub**: Provide `GITHUB_REPO_OWNER`/`GITHUB_REPO_NAME` (and optionally `GITHUB_SUBJECT_FILTER`, `GITHUB_OIDC_PROVIDER_ARN`) before running `cdk deploy`. If your repo lives outside that owner, set `GITHUB_OIDC_SUBJECT` to the full Actions subject string (e.g., `repo:user/repo:environment:github-pages`). The stack will provision an OpenID Connect provider for `token.actions.githubusercontent.com` (if needed) and an IAM role limited to `s3:GetObject` on `aws-actions.json`. The role ARN is exposed as the `GitHubActionsRoleArn` stack output (and, when created, the provider ARN via `GitHubOidcProviderArn`).
3. **Optional SNS trigger**: To avoid waiting for the cron schedule, the Lambda can publish an SNS notification (or call a GitHub repository dispatch webhook) once it finishes writing the file. This can kick off the GitHub workflow immediately.
4. **Skip static site infra**: Set `ENABLE_SITE_HOSTING=false` before `cdk deploy` to avoid provisioning the CloudFront distribution and site bucket when GitHub Pages hosts the UI.

## GitHub Setup

1. **Repository secrets/variables**
   - `ACTIONS_ROLE_ARN`: Value from the `GitHubActionsRoleArn` stack output.
   - `AWS_REGION`: Region that hosts the bucket (e.g., `ca-central-1`).
   - Optional: `PAGES_BASE_PATH` if you need something other than the default `/<repo>/` base (set to `/` when using a custom domain, otherwise you can skip it and the workflow auto-detects your repo name).
   - Optional: `PAGES_CUSTOM_DOMAIN` if you map Pages to a vanity URL (pair this with `PAGES_BASE_PATH=/`).
2. **GitHub Pages**
   - Enable Pages => Source: *GitHub Actions*.
   - (Optional) Configure a custom domain + DNS.

## Workflow Behaviour

The prototype workflow (`.github/workflows/deploy-gh-pages.yml`) performs:

1. **Triggers**: nightly cron (03:30 UTC), `workflow_dispatch`, and `repository_dispatch` (so an SNS-to-GitHub webhook could launch it immediately after Lambda completes).
2. **Checkout + dependencies**:
   - `actions/checkout`.
   - `actions/setup-node` with Node 20.
   - `npm ci` inside `service-browser-app`.
3. **Fetch manifest**: `aws-actions/configure-aws-credentials` assumes the GitHub OIDC role and runs `aws s3 cp .../aws-actions.json service-browser-app/public/aws-actions.json`.
4. **Build UI**: `npm run build` from `service-browser-app`.
5. **Deploy to Pages**: upload the `dist` directory as an artifact and call `actions/deploy-pages`.

If the manifest download fails, the workflow exits before publishing, keeping Pages on the last known-good version.

## Local & Preview Builds

- Local development stays the same: run `npm install && npm run dev` inside `service-browser-app`, optionally pointing to a locally cached JSON file.
- To preview the GitHub Pages bundle locally, run `npm run build` followed by `npm run preview`. The JSON consumed will be whatever is present in `service-browser-app/public/aws-actions.json`.

## Next Steps

1. Test the workflow with dummy credentials (e.g., point to a dev bucket) to ensure the GitHub → AWS role assumption works.
2. Once validated, promote the workflow to `main` and switch DNS for the UI to the GitHub Pages domain.
3. Optionally, decommission the CloudFront + site bucket resources if Pages fully replaces them.

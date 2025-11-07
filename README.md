# AWS Service Browser

Discover and share the AWS IAM actions your team relies on. This project aggregates the AWS Service Authorization Reference into a single JSON document, hosts a lightweight UI, and serves it securely from the edge.

## Solution Overview

- **Data aggregation** – A scheduled Lambda function (`service-browser-infra/lambda/lambda.ts`) downloads every service definition from the AWS documentation and writes a flattened `aws-actions.json` manifest to a private S3 bucket.
- **Static application hosting** – Another S3 bucket holds the pre-built front-end (see `service-browser-app/`), which is distributed through CloudFront with HTTPS and caching (`service-browser-infra/lib/service-browser-stack.ts`).
- **Access control** – Optional Terraform in `cloudflare-tf/` front-ends the CloudFront distribution with Cloudflare DNS and Access to enforce Zero Trust policies.
- **Infrastructure as code** – AWS CDK (TypeScript) provisions all AWS resources; Terraform handles the Cloudflare-side integration.

### Repository Layout

- `service-browser-infra/` – CDK app, including the scheduled aggregator Lambda and CloudFront/S3 infrastructure.
- `service-browser-app/` – Placeholder for the static web client (e.g., React/Vite build output).
- `cloudflare-tf/` – Terraform modules for DNS and Cloudflare Access hardening.
- `lambda/` build artifacts are expected to include a compiled `index.js` and its dependencies when deploying.

### Data Flow

1. EventBridge triggers the Lambda every night at 03:00 UTC.
2. The Lambda fetches and merges the AWS IAM action catalogs into `aws-actions.json`.
3. The static web app fetches this JSON from the data bucket (via CloudFront) to drive the UI.

## Deployment

### Prerequisites

- Node.js 18+ and npm (for CDK TypeScript projects).
- AWS CLI configured with credentials for the target account.
- AWS CDK v2 (`npm install -g aws-cdk`) with the account bootstrapped (`cdk bootstrap`) if you have not used CDK in the account/region before.
- (Optional) Terraform CLI and a Cloudflare account with API token for DNS/Access.

### Provision AWS Infrastructure

1. Install dependencies:
   ```bash
   cd service-browser-infra
   npm install
   ```
2. (First-time only) Bootstrap the target account/region so CDK can provision assets:
   ```bash
   npx cdk bootstrap aws://<ACCOUNT_ID>/<REGION>
   # Example: npx cdk bootstrap aws://123456789012/ca-central-1
   ```
2. Bundle the Lambda (ensures `lambda/index.js` exists and includes dependencies). One option is:
   ```bash
   npx esbuild lambda/lambda.ts --bundle --platform=node --target=node20 --format=cjs --outfile=lambda/index.js
   ```
   This creates a single-file handler that matches the CDK configuration (`handler: index.handler`). If you prefer `tsc`, copy the compiled file from `dist/lambda/lambda.js` to `lambda/index.js` and make sure `lambda/node_modules` contains `@aws-sdk/client-s3` and `node-fetch`.
3. Synthesize and deploy:
   ```bash
   npm run build
   npx cdk synth
   npm run deploy
   ```
4. Take note of the stack outputs for the CloudFront domain, site bucket, and data bucket.

### Publish the Static Front-End

1. Build your UI (for example, a Vite project under `service-browser-app/`) so that the output lives in `service-browser-app/dist/`.
2. Upload the assets to the site bucket returned by the stack:
   ```bash
   aws s3 sync service-browser-app/dist/ s3://<SiteBucketName> --delete
   ```
3. Invalidate CloudFront if required:
   ```bash
   aws cloudfront create-invalidation --distribution-id <DistributionId> --paths "/*"
   ```

### Optional: Cloudflare Access

1. Populate `cloudflare-tf/terraform.tfvars` with:
   ```hcl
   cloudflare_email               = "you@example.com"
   cloudflare_api_token           = "cf-api-token"
   cloudflare_zone_id             = "abc123"
   cloudfront_distribution_domain = "dxxxx.cloudfront.net"
   ```
2. Deploy the resources:
   ```bash
   cd cloudflare-tf
   terraform init
   terraform apply
   ```
3. Update the CloudFront distribution with the Cloudflare-provided hostname if you use a vanity domain.

### Optional: GitHub Actions OIDC Role

Set the following environment variables before running `cdk synth/deploy` if you want the stack to create a least-privilege role for the GitHub Pages workflow:

| Variable | Required | Description |
|----------|----------|-------------|
| `GITHUB_REPO_OWNER` | ✅ | GitHub organization or user (e.g., `your-org`) |
| `GITHUB_REPO_NAME` | ✅ | Repository name (e.g., `aws-service-browser`) |
| `GITHUB_SUBJECT_FILTER` | ❌ | Portion of the GitHub OIDC subject to trust. Defaults to `ref:refs/heads/main`. Use `environment:github-pages` to scope to a specific Pages environment. |
| `GITHUB_OIDC_PROVIDER_ARN` | ❌ | Re-use an existing `token.actions.githubusercontent.com` provider instead of creating a new one. |

When configured, the stack emits `GitHubActionsRoleArn` (the role to assume from GitHub Actions) and `GitHubOidcProviderArn` (if a new provider was created). The role is scoped to `s3:GetObject` on `aws-actions.json` only and requires the GitHub workflow identity to match `repo:<owner>/<repo>:<filter>`.

### Optional: Skip AWS Site Hosting

If you are hosting the UI elsewhere (e.g., GitHub Pages), set `ENABLE_SITE_HOSTING=false` before running `cdk deploy`. This prevents CDK from creating the CloudFront distribution and site bucket, leaving only the data bucket + Lambda/EventBridge pipeline in AWS.

## Cost Estimates (ca-central-1)

The stack is inexpensive for light internal use. Estimates below assume ~25 MB stored, one Lambda run per day (~15 s at 128 MB), and ~10 GB/month of CloudFront egress with 100k requests.

| Service | Assumptions | Approx. Monthly Cost (USD) |
|---------|-------------|----------------------------|
| S3 (site + data buckets) | 25 MB stored, 10k PUT/GET requests | <$0.10 |
| Lambda + EventBridge | 30 invocations, 15 s @ 128 MB | <$0.01 (typically within free tier) |
| CloudFront (Price Class 100) | 10 GB transfer, 100k requests | ~$0.95 |
| CloudWatch Logs | 50 MB ingestion/archival | <$0.05 |

**Estimated total:** ~\$1.10 USD/month (≈\$1.50 CAD) before Cloudflare. Cloudflare Access is free for up to 50 users on the Zero Trust plan; higher usage incurs Cloudflare charges.

## Future Improvements

- Use `NodejsFunction` (esbuild) in the CDK stack to automate bundling of the Lambda and eliminate manual steps.
- Commit a reference UI under `service-browser-app/` plus a CI workflow to build and publish the static bundle to S3.
- Cache the generated JSON with object versioning or Glue/Athena for historical comparisons.
- Add alerting/monitoring (e.g., failure alarms, health checks) so missed refreshes are detected quickly.

## Hybrid GitHub Pages Prototype

The `hybrid-gh-pages-prototype` branch experiments with keeping the nightly EventBridge ➜ Lambda aggregation pipeline while hosting the React UI on GitHub Pages. The flow is:

1. Lambda writes `aws-actions.json` to the private `ActionsIndexBucket` (no change).
2. A GitHub Actions workflow (`deploy-gh-pages.yml`) assumes a read-only IAM role, downloads the JSON into `service-browser-app/public/`, and runs `npm run build`.
3. The workflow uploads the `dist/` bundle to GitHub Pages, giving you a free CDN-backed front end while AWS continues to own the scraping job.

Implementation details, IAM requirements, secrets, and trigger options are documented in `docs/hybrid-github-pages.md`.

## Cleanup

Both buckets use `RemovalPolicy.RETAIN`, so deleting the stack leaves data behind. Empty the buckets and delete the stacks manually when you are finished to avoid accruing storage or CloudFront charges.

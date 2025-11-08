import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as nodejs from 'aws-cdk-lib/aws-lambda-nodejs';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as path from 'path';

export interface GitHubOidcConfig {
    readonly owner: string;
    readonly repo: string;
    /**
     * Portion of the GitHub subject claim to match (e.g., `ref:refs/heads/main` or `environment:github-pages`).
     * Defaults to `ref:refs/heads/main`.
     */
    readonly subjectFilter?: string;
}

export interface ServiceBrowserStackProps extends cdk.StackProps {
    /**
     * Controls whether the static site (S3 + CloudFront) is provisioned.
     * Default: true.
     */
    readonly enableSiteHosting?: boolean;
    /**
     * When provided, creates an IAM role scoped to this repo for downloading aws-actions.json.
     */
    readonly githubOidc?: GitHubOidcConfig;
    /**
     * Optionally re-use an existing GitHub OIDC provider by supplying its ARN.
     * If undefined, a new provider is created.
     */
    readonly githubOidcProviderArn?: string;
}

export class ServiceBrowserStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: ServiceBrowserStackProps) {
        super(scope, id, props);

        const enableSiteHosting = props?.enableSiteHosting ?? true;

        // Bucket to store aggregated JSON
        const dataBucket = new s3.Bucket(this, 'ActionsIndexBucket', {
            versioned: true,
            blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
            removalPolicy: cdk.RemovalPolicy.RETAIN,
        });

        let siteBucket: s3.Bucket | undefined;
        let distribution: cloudfront.Distribution | undefined;

        if (enableSiteHosting) {
            // Bucket to host React/Vite static site assets
            siteBucket = new s3.Bucket(this, 'SiteBucket', {
                blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
                removalPolicy: cdk.RemovalPolicy.RETAIN,
            });

            // Origin Access Identity for CloudFront
            const oai = new cloudfront.OriginAccessIdentity(this, 'SiteOAI', {
                comment: 'OAI for Service Browser static site'
            });
            // Grant read access to the OAI
            siteBucket.grantRead(oai);

            // CloudFront distribution
            distribution = new cloudfront.Distribution(this, 'SiteDistribution', {
                defaultBehavior: {
                    origin: new origins.S3Origin(siteBucket, { originAccessIdentity: oai }),
                    viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                },
                defaultRootObject: 'index.html',
                priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
                // Uncomment to configure custom domain and ACM certificate
                // domainNames: ['browser.example.com'],
                // certificate: acm.Certificate.fromCertificateArn(this, 'Cert', 'arn:aws:acm:...')
            });
        }

        // Outputs
        if (distribution) {
            new cdk.CfnOutput(this, 'CloudFrontDomain', {
                value: distribution.domainName,
                description: 'Distribution domain for the static site'
            });
        }

        if (siteBucket) {
            new cdk.CfnOutput(this, 'SiteBucketName', {
                value: siteBucket.bucketName,
                description: 'S3 bucket for static site assets'
            });
        }

        new cdk.CfnOutput(this, 'ActionsIndexBucketName', {
            value: dataBucket.bucketName,
            description: 'S3 bucket for aggregated JSON'
        });

        // Lambda to aggregate JSON (Node.js 20.x, bundled via esbuild)
        const aggregator = new nodejs.NodejsFunction(this, 'AggregatorFunction', {
            runtime: lambda.Runtime.NODEJS_20_X,
            entry: path.join(__dirname, '..', 'lambda', 'lambda.ts'),
            handler: 'handler',
            environment: {
                BUCKET_NAME: dataBucket.bucketName,
                BASE_URL: 'https://servicereference.us-east-1.amazonaws.com/',
                MAX_CONCURRENCY: '12',
            },
            timeout: cdk.Duration.minutes(5),
        });

        // Grant Lambda permissions to write JSON
        dataBucket.grantPut(aggregator);
        aggregator.addToRolePolicy(new iam.PolicyStatement({
            actions: [
                'logs:CreateLogGroup',
                'logs:CreateLogStream',
                'logs:PutLogEvents'
            ],
            resources: ['*'],
        }));

        // Schedule daily at 3 AM UTC
        new events.Rule(this, 'DailyScheduleRule', {
            schedule: events.Schedule.cron({ minute: '0', hour: '3' }),
            targets: [new targets.LambdaFunction(aggregator)],
        });

        if (props?.githubOidc) {
            const oidcProvider = props.githubOidcProviderArn
                ? iam.OpenIdConnectProvider.fromOpenIdConnectProviderArn(this, 'GitHubOidcProvider', props.githubOidcProviderArn)
                : new iam.OpenIdConnectProvider(this, 'GitHubOidcProvider', {
                    url: 'https://token.actions.githubusercontent.com',
                    clientIds: ['sts.amazonaws.com'],
                    thumbprints: ['6938fd4d98bab03faadb97b34396831e3780aea1'],
                });

            const subjectFilter = props.githubOidc.subjectFilter ?? 'ref:refs/heads/main';
            const githubPrincipal = new iam.OpenIdConnectPrincipal(oidcProvider).withConditions({
                StringEquals: {
                    'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
                },
                StringLike: {
                    'token.actions.githubusercontent.com:sub': `repo:${props.githubOidc.owner}/${props.githubOidc.repo}:${subjectFilter}`,
                },
            });

            const githubRole = new iam.Role(this, 'GitHubPagesDeployerRole', {
                description: 'Allows GitHub Actions to download aws-actions.json for GitHub Pages deploys.',
                assumedBy: githubPrincipal,
                inlinePolicies: {
                    GitHubPagesReadManifest: new iam.PolicyDocument({
                        statements: [
                            new iam.PolicyStatement({
                                actions: ['s3:GetObject'],
                                resources: [dataBucket.arnForObjects('aws-actions.json')],
                            }),
                        ],
                    }),
                },
            });

            new cdk.CfnOutput(this, 'GitHubActionsRoleArn', {
                value: githubRole.roleArn,
                description: 'IAM role that GitHub Actions assumes to read aws-actions.json',
            });
            if (!props.githubOidcProviderArn) {
                new cdk.CfnOutput(this, 'GitHubOidcProviderArn', {
                    value: oidcProvider.openIdConnectProviderArn,
                    description: 'OIDC provider configured for GitHub Actions',
                });
            }
        }
    }
}

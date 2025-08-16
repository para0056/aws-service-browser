import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as iam from 'aws-cdk-lib/aws-iam';

export class ServiceBrowserStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        // Bucket to store aggregated JSON
        const dataBucket = new s3.Bucket(this, 'ActionsIndexBucket', {
            versioned: true,
            blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
            removalPolicy: cdk.RemovalPolicy.RETAIN,
        });

        // Bucket to host React/Vite static site assets
        const siteBucket = new s3.Bucket(this, 'SiteBucket', {
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
        const distribution = new cloudfront.Distribution(this, 'SiteDistribution', {
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

        // Outputs
        new cdk.CfnOutput(this, 'CloudFrontDomain', {
            value: distribution.domainName,
            description: 'Distribution domain for the static site'
        });
        new cdk.CfnOutput(this, 'SiteBucketName', {
            value: siteBucket.bucketName,
            description: 'S3 bucket for static site assets'
        });
        new cdk.CfnOutput(this, 'ActionsIndexBucketName', {
            value: dataBucket.bucketName,
            description: 'S3 bucket for aggregated JSON'
        });

        // Lambda to aggregate JSON (Node.js 20.x, AWS SDK v3)
        const aggregator = new lambda.Function(this, 'AggregatorFunction', {
            runtime: lambda.Runtime.NODEJS_20_X,
            handler: 'index.handler',
            code: lambda.Code.fromAsset('lambda'),
            environment: {
                BUCKET_NAME: dataBucket.bucketName,
                BASE_URL: 'https://docs.aws.amazon.com/service-authorization/latest/reference/',
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
    }
}
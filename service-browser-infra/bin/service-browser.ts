import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { ServiceBrowserStack } from '../lib/service-browser-stack';

const app = new cdk.App();
new ServiceBrowserStack(app, 'ServiceBrowserStack', {
    env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION }
});
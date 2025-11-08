import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { ServiceBrowserStack, ServiceBrowserStackProps } from '../lib/service-browser-stack';

const app = new cdk.App();

const githubOwner = process.env.GITHUB_REPO_OWNER;
const githubRepo = process.env.GITHUB_REPO_NAME;
const githubSubjectFilter = process.env.GITHUB_SUBJECT_FILTER;
const githubOidcProviderArn = process.env.GITHUB_OIDC_PROVIDER_ARN;
const enableSiteHosting = process.env.ENABLE_SITE_HOSTING
    ? process.env.ENABLE_SITE_HOSTING.toLowerCase() === 'true'
    : true;

const stackProps: ServiceBrowserStackProps = {
    env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION },
    enableSiteHosting,
    ...(githubOwner && githubRepo
        ? {
            githubOidc: {
                owner: githubOwner,
                repo: githubRepo,
                subjectFilter: githubSubjectFilter,
            },
            ...(githubOidcProviderArn ? { githubOidcProviderArn } : {}),
        }
        : {}),
};

new ServiceBrowserStack(app, 'ServiceBrowserStack', stackProps);

import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import fetch from 'node-fetch';

const s3Client = new S3Client({});
const BUCKET = process.env.BUCKET_NAME!;
const BASE = process.env.BASE_URL!;

export const handler = async () => {
    const topRes = await fetch(`${BASE}service-reference.json`);
    const top = await topRes.json();
    const entries: any[] = [];

    for (const svc of Object.values<any>(top.services)) {
        const url = new URL(svc.jsonUrl, BASE).href;
        const data = await (await fetch(url)).json();
        for (const [action, meta] of Object.entries<any>(data.actions)) {
            const annotations: string[] = Array.isArray(meta.annotations) ? [...meta.annotations] : [];
            if (typeof meta.accessLevel === 'string' && meta.accessLevel.toLowerCase() === 'write') {
                if (!annotations.some((a: string) => a.toLowerCase().startsWith('iswrite'))) {
                    annotations.push('IsWrite: true');
                }
            }
            entries.push({
                service: svc.serviceName,
                action,
                description: meta.description,
                annotations,
                conditionKeys: meta.conditionKeys || [],
                resourceTypes: meta.resourceTypes ? Object.keys(meta.resourceTypes) : [],
            });
        }
    }

    await s3Client.send(new PutObjectCommand({
        Bucket: BUCKET,
        Key: 'aws-actions.json',
        Body: JSON.stringify(entries),
        ContentType: 'application/json',
        CacheControl: 'max-age=0',
    }));
};

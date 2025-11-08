import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import fetch from 'node-fetch';

const s3Client = new S3Client({});
const BUCKET = process.env.BUCKET_NAME!;
const BASE = process.env.BASE_URL ?? 'https://servicereference.us-east-1.amazonaws.com/';
const MAX_CONCURRENCY = Math.max(Number(process.env.MAX_CONCURRENCY ?? '8'), 1);

type ServiceEntry = {
    service: string;
    url: string;
};

type ServiceAction = {
    Name: string;
    Description?: string;
    Annotations?: Record<string, unknown>;
    ActionConditionKeys?: string[];
    Resources?: Array<{ Name?: string | null }>;
};

export const handler = async () => {
    const index = await fetchServiceIndex();
    const entries: Array<Record<string, unknown>> = [];
    let cursor = 0;

    async function worker() {
        while (cursor < index.length) {
            const current = cursor++;
            const serviceEntry = index[current];
            if (!serviceEntry) continue;
            const serviceActions = await fetchServiceActions(serviceEntry);
            entries.push(...serviceActions);
        }
    }

    await Promise.all(Array.from({ length: Math.min(MAX_CONCURRENCY, index.length) }, worker));

    entries.sort((a, b) => {
        if (a.service === b.service) {
            return String(a.action).localeCompare(String(b.action));
        }
        return String(a.service).localeCompare(String(b.service));
    });

    await s3Client.send(new PutObjectCommand({
        Bucket: BUCKET,
        Key: 'aws-actions.json',
        Body: JSON.stringify(entries),
        ContentType: 'application/json',
        CacheControl: 'max-age=0',
    }));
};

async function fetchServiceIndex(): Promise<ServiceEntry[]> {
    const res = await fetch(BASE);
    if (!res.ok) {
        throw new Error(`Failed to fetch service index (${res.status} ${res.statusText})`);
    }
    const body = await res.json();
    if (!Array.isArray(body)) {
        throw new Error('Unexpected service index format');
    }
    return body as ServiceEntry[];
}

async function fetchServiceActions(entry: ServiceEntry) {
    try {
        const res = await fetch(entry.url);
        if (!res.ok) {
            console.warn(`Failed to fetch ${entry.service}: ${res.status} ${res.statusText}`);
            return [];
        }
        const body = await res.json();
        const serviceName = body?.Name ?? entry.service;
        const actionList: ServiceAction[] = Array.isArray(body?.Actions) ? body.Actions : [];

        return actionList.map(action => {
            const annotations = extractAnnotations(action.Annotations);
            const conditionKeys = Array.isArray(action.ActionConditionKeys) ? action.ActionConditionKeys : [];
            const resourceTypes = Array.isArray(action.Resources)
                ? action.Resources.map(r => r?.Name).filter((name): name is string => Boolean(name))
                : [];

            if (typeof action === 'object' && action !== null) {
                if (typeof (action as any).AccessLevel === 'string') {
                    const level = String((action as any).AccessLevel).toLowerCase();
                    if (level === 'write' && !annotations.some(a => a.toLowerCase().startsWith('iswrite'))) {
                        annotations.push('IsWrite: true');
                    }
                }
            }

            return {
                service: serviceName,
                action: action.Name,
                description: action.Description ?? '',
                annotations,
                conditionKeys,
                resourceTypes,
            };
        });
    } catch (error) {
        console.warn(`Error processing ${entry.service}: ${(error as Error).message}`);
        return [];
    }
}

function extractAnnotations(raw: Record<string, unknown> | undefined) {
    if (!raw || typeof raw !== 'object') return [];
    const items: string[] = [];

    if ('Properties' in raw && typeof raw.Properties === 'object' && raw.Properties) {
        for (const [key, value] of Object.entries(raw.Properties as Record<string, unknown>)) {
            items.push(`${key}: ${formatValue(value)}`);
        }
    }

    for (const [key, value] of Object.entries(raw)) {
        if (key === 'Properties') continue;
        items.push(`${key}: ${formatValue(value)}`);
    }

    return items;
}

function formatValue(value: unknown): string {
    if (value === null || value === undefined) return 'null';
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
        return String(value);
    }
    if (Array.isArray(value)) {
        return value.map(formatValue).join(', ');
    }
    if (typeof value === 'object') {
        return JSON.stringify(value);
    }
    return String(value);
}

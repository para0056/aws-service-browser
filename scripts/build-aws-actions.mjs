#!/usr/bin/env node

import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const BASE_INDEX = 'https://servicereference.us-east-1.amazonaws.com/';
const CONCURRENCY = 12;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUTPUT_PATH = path.resolve(__dirname, '../service-browser-app/public/aws-actions.json');

async function main() {
    const indexRes = await fetch(BASE_INDEX);
    if (!indexRes.ok) {
        throw new Error(`Failed to fetch service index: ${indexRes.status} ${indexRes.statusText}`);
    }
    const services = await indexRes.json();
    if (!Array.isArray(services)) {
        throw new Error('Unexpected service index format');
    }

    const actions = [];
    let cursor = 0;
    let processed = 0;

    async function worker() {
        while (cursor < services.length) {
            const serviceEntry = services[cursor++];
            if (!serviceEntry) break;
            const serviceActions = await fetchServiceActions(serviceEntry);
            actions.push(...serviceActions);
            processed += 1;
            if (processed % 25 === 0 || processed === services.length) {
                console.log(`Processed ${processed}/${services.length} services`);
            }
        }
    }

    const workers = Array.from({ length: CONCURRENCY }, () => worker());
    await Promise.all(workers);

    actions.sort((a, b) => {
        if (a.service === b.service) return a.action.localeCompare(b.action);
        return a.service.localeCompare(b.service);
    });

    await mkdir(path.dirname(OUTPUT_PATH), { recursive: true });
    await writeFile(OUTPUT_PATH, JSON.stringify(actions, null, 2));
    console.log(`Wrote ${actions.length} actions to ${OUTPUT_PATH}`);
}

async function fetchServiceActions(entry) {
    const { service, url } = entry;
    try {
        const res = await fetch(url);
        if (!res.ok) {
            console.warn(`Failed to fetch ${service}: ${res.statusText}`);
            return [];
        }
        const body = await res.json();
        const serviceName = body.Name || service;
        const actionList = Array.isArray(body.Actions) ? body.Actions : [];

        return actionList.map(action => {
            const annotations = extractAnnotations(action.Annotations);
            const conditionKeys = Array.isArray(action.ActionConditionKeys) ? action.ActionConditionKeys : [];
            const resourceTypes = Array.isArray(action.Resources)
                ? action.Resources.map(r => r?.Name).filter(Boolean)
                : [];

            return {
                service: serviceName,
                action: action.Name,
                description: action.Description ?? '',
                annotations,
                conditionKeys,
                resourceTypes
            };
        });
    } catch (err) {
        console.warn(`Error processing ${service}: ${err.message}`);
        return [];
    }
}

function extractAnnotations(raw) {
    if (!raw || typeof raw !== 'object') return [];
    const items = [];

    if (raw.Properties && typeof raw.Properties === 'object') {
        for (const [key, value] of Object.entries(raw.Properties)) {
            items.push(`${key}: ${formatValue(value)}`);
        }
    }

    for (const [key, value] of Object.entries(raw)) {
        if (key === 'Properties') continue;
        items.push(`${key}: ${formatValue(value)}`);
    }

    return items;
}

function formatValue(value) {
    if (value === null || value === undefined) return 'null';
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
        return String(value);
    }
    if (Array.isArray(value)) {
        return value.map(formatValue).join(', ');
    }
    return JSON.stringify(value);
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});

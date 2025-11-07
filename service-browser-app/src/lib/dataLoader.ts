import { get, set } from 'idb-keyval';
import type { AwsAction, ServiceIndexEntry } from '../types';

const CACHE_VERSION = 'v1';
const INDEX_CACHE_KEY = `${CACHE_VERSION}:service-index`;
const ACTION_CACHE_PREFIX = `${CACHE_VERSION}:service-actions:`;
const ALL_ACTIONS_CACHE_KEY = `${CACHE_VERSION}:all-actions`;

const INDEX_TTL = 1000 * 60 * 60 * 24; // 24 hours
const ACTION_TTL = 1000 * 60 * 60 * 24 * 7; // 7 days
const ALL_ACTIONS_TTL = 1000 * 60 * 60 * 24; // 24 hours

type CachedValue<T> = { timestamp: number; data: T };

async function readCache<T>(key: string): Promise<CachedValue<T> | undefined> {
    return get<CachedValue<T>>(key) ?? undefined;
}

async function readFresh<T>(key: string, ttl: number): Promise<T | undefined> {
    const cached = await readCache<T>(key);
    if (!cached) return undefined;
    if (Date.now() - cached.timestamp > ttl) return undefined;
    return cached.data;
}

async function writeCache<T>(key: string, data: T): Promise<void> {
    const payload: CachedValue<T> = { timestamp: Date.now(), data };
    await set(key, payload);
}

export async function loadServiceIndex(options: { forceRefresh?: boolean } = {}): Promise<ServiceIndexEntry[]> {
    const { forceRefresh = false } = options;
    if (!forceRefresh) {
        const cached = await readFresh<ServiceIndexEntry[]>(INDEX_CACHE_KEY, INDEX_TTL);
        if (cached) return cached;
    }

    const response = await fetch('/service-index.json', { cache: 'no-cache' });
    if (!response.ok) {
        const fallback = await readCache<ServiceIndexEntry[]>(INDEX_CACHE_KEY);
        if (fallback) return fallback.data;
        throw new Error(`Failed to load service index: ${response.status}`);
    }

    const services = await response.json();
    if (!Array.isArray(services)) {
        throw new Error('Unexpected service index format');
    }

    await writeCache(INDEX_CACHE_KEY, services);
    return services;
}

export async function loadServiceActions(
    entry: ServiceIndexEntry,
    options: { forceRefresh?: boolean } = {}
): Promise<AwsAction[]> {
    const { forceRefresh = false } = options;
    const cacheKey = `${ACTION_CACHE_PREFIX}${entry.service}`;

    if (!forceRefresh) {
        const cached = await readFresh<AwsAction[]>(cacheKey, ACTION_TTL);
        if (cached) return cached;
    }

    const sameOriginUrl = toSameOriginPath(entry.url);

    try {
        const target = sameOriginUrl ?? entry.url;
        const response = await fetch(target, { cache: 'no-cache' });
        if (!response.ok) {
            throw new Error(`Fetch failed: ${response.status}`);
        }
        const json = await response.json();
        const actions = sameOriginUrl ? (json as AwsAction[]) : extractActions(entry.service, json);
        await writeCache(cacheKey, actions);
        return actions;
    } catch (err) {
        const fallback = await readCache<AwsAction[]>(cacheKey);
        if (fallback) return fallback.data;
        const derived = await loadActionsFromAggregate(entry.service);
        await writeCache(cacheKey, derived);
        return derived;
    }
}

function extractActions(serviceFallback: string, doc: any): AwsAction[] {
    const serviceName = typeof doc?.Name === 'string' ? doc.Name : serviceFallback;
    const rawActions = Array.isArray(doc?.Actions) ? doc.Actions : [];

    return rawActions
        .map((action: any) => normalizeAction(serviceName, action))
        .filter((action): action is AwsAction => Boolean(action));
}

function normalizeAction(serviceName: string, action: any): AwsAction | null {
    if (!action || typeof action !== 'object') return null;
    const actionName = typeof action.Name === 'string' ? action.Name : null;
    if (!actionName) return null;

    const annotations = extractAnnotations(action.Annotations);
    const conditionKeys = Array.isArray(action.ActionConditionKeys)
        ? action.ActionConditionKeys.filter((key: unknown): key is string => typeof key === 'string')
        : [];

    const resourceTypes = Array.isArray(action.Resources)
        ? action.Resources
            .map((resource: any) => resource?.Name)
            .filter((value: unknown): value is string => typeof value === 'string')
        : [];

    return {
        service: serviceName,
        action: actionName,
        description: typeof action.Description === 'string' ? action.Description : '',
        annotations,
        conditionKeys,
        resourceTypes
    };
}

function extractAnnotations(raw: any): string[] {
    if (!raw || typeof raw !== 'object') return [];
    const items: string[] = [];

    if (raw.Properties && typeof raw.Properties === 'object') {
        for (const [key, value] of Object.entries(raw.Properties)) {
            items.push(formatAnnotation(key, value));
        }
    }

    for (const [key, value] of Object.entries(raw)) {
        if (key === 'Properties') continue;
        items.push(formatAnnotation(key, value));
    }

    return items;
}

function formatAnnotation(key: string, value: unknown): string {
    return `${key}: ${formatValue(value)}`;
}

function formatValue(value: unknown): string {
    if (value === null || value === undefined) return 'null';
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
        return String(value);
    }
    if (Array.isArray(value)) {
        return value.map(formatValue).join(', ');
    }
    return JSON.stringify(value);
}

function toSameOriginPath(url: string): string | null {
    try {
        const parsed = new URL(url, window.location.origin);
        if (parsed.origin === window.location.origin) {
            return parsed.pathname + parsed.search + parsed.hash;
        }
    } catch {
        // ignore malformed URLs
    }
    return null;
}

async function loadAllActions(): Promise<AwsAction[]> {
    const cached = await readFresh<AwsAction[]>(ALL_ACTIONS_CACHE_KEY, ALL_ACTIONS_TTL);
    if (cached) return cached;

    const response = await fetch('/aws-actions.json', { cache: 'no-cache' });
    if (!response.ok) {
        const fallback = await readCache<AwsAction[]>(ALL_ACTIONS_CACHE_KEY);
        if (fallback) return fallback.data;
        throw new Error(`Failed to load action catalog: ${response.status}`);
    }

    const data = await response.json();
    if (!Array.isArray(data)) {
        throw new Error('Unexpected action catalog format');
    }

    const cleaned = data.map(normalizeAggregateAction).filter((item): item is AwsAction => Boolean(item));
    await writeCache(ALL_ACTIONS_CACHE_KEY, cleaned);
    return cleaned;
}

function normalizeAggregateAction(raw: any): AwsAction | null {
    if (!raw || typeof raw !== 'object') return null;
    const { service, action } = raw;
    if (typeof service !== 'string' || typeof action !== 'string') return null;

    return {
        service,
        action,
        description: typeof raw.description === 'string' ? raw.description : '',
        annotations: Array.isArray(raw.annotations) ? raw.annotations.filter((item: unknown): item is string => typeof item === 'string') : [],
        conditionKeys: Array.isArray(raw.conditionKeys) ? raw.conditionKeys.filter((item: unknown): item is string => typeof item === 'string') : [],
        resourceTypes: Array.isArray(raw.resourceTypes) ? raw.resourceTypes.filter((item: unknown): item is string => typeof item === 'string') : []
    };
}

async function loadActionsFromAggregate(service: string): Promise<AwsAction[]> {
    const all = await loadAllActions();
    return all.filter(action => action.service === service);
}

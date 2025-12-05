import { get, set } from 'idb-keyval';
import type { AwsAction, ServiceIndexEntry } from '../types';

const CACHE_VERSION = 'v4';
const INDEX_CACHE_KEY = `${CACHE_VERSION}:service-index`;
const ACTION_CACHE_PREFIX = `${CACHE_VERSION}:service-actions:`;
const ALL_ACTIONS_CACHE_KEY = `${CACHE_VERSION}:all-actions`;

const BASE_PATH = normalizeBase(((import.meta as { env?: { BASE_URL?: string } }).env?.BASE_URL) ?? '/');
const ALL_ACTIONS_URL = resolveAssetUrl('aws-actions.json');

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

    const response = await fetch(resolveAssetUrl('service-index.json'), { cache: 'no-cache' });
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

    try {
        const aggregate = await loadActionsFromAggregate(entry.service);
        await writeCache(cacheKey, aggregate);
        return aggregate;
    } catch (err) {
        const fallback = await readCache<AwsAction[]>(cacheKey);
        if (fallback) return fallback.data;
        throw err instanceof Error ? err : new Error('Failed to load actions');
    }
}

async function loadAllActions(): Promise<AwsAction[]> {
    const cached = await readFresh<AwsAction[]>(ALL_ACTIONS_CACHE_KEY, ALL_ACTIONS_TTL);
    if (cached) return cached;

    const response = await fetch(ALL_ACTIONS_URL, { cache: 'no-cache' });
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
    const scoped = all.filter(action => action.service === service);
    return mergeByAction(scoped);
}

function resolveAssetUrl(asset: string): string {
    return `${BASE_PATH}${asset}`.replace(/([^:]\/)\/+/g, '$1'); // collapse double slashes after scheme
}

function normalizeBase(base: string): string {
    if (!base) {
        return '/';
    }
    if (!base.startsWith('/')) {
        base = `/${base}`;
    }
    return base.endsWith('/') ? base : `${base}/`;
}

function mergeByAction(actions: AwsAction[]): AwsAction[] {
    const merged = new Map<string, AwsAction>();

    for (const action of actions) {
        const key = `${action.service}:${action.action}`;
        const existing = merged.get(key);
        if (!existing) {
            merged.set(key, {
                ...action,
                annotations: [...action.annotations],
                conditionKeys: [...action.conditionKeys],
                resourceTypes: [...action.resourceTypes],
            });
            continue;
        }

        existing.annotations = union(existing.annotations, action.annotations);
        existing.conditionKeys = union(existing.conditionKeys, action.conditionKeys);
        existing.resourceTypes = union(existing.resourceTypes, action.resourceTypes);

        if (!existing.description && action.description) {
            existing.description = action.description;
        }
    }

    return Array.from(merged.values());
}

function union(a: string[], b: string[]): string[] {
    const set = new Set<string>([...a, ...b].filter((item): item is string => typeof item === 'string'));
    return Array.from(set);
}

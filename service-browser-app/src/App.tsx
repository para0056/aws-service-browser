import { useDeferredValue, useEffect, useMemo, useState } from 'react';
import Fuse from 'fuse.js';
import Header from './components/Header';
import Search from './components/Search';
import Results from './components/Results';
import ServiceList from './components/ServiceList';
import { loadServiceActions, loadServiceIndex } from './lib/dataLoader';
import { AwsAction, ServiceIndexEntry } from './types';

export default function App() {
    const [services, setServices] = useState<ServiceIndexEntry[]>([]);
    const [serviceQuery, setServiceQuery] = useState('');
    const [selectedService, setSelectedService] = useState<ServiceIndexEntry | null>(null);
    const [serviceData, setServiceData] = useState<Record<string, AwsAction[]>>({});
    const [actionQuery, setActionQuery] = useState('');
    const [writeFilter, setWriteFilter] = useState<'all' | 'write' | 'read'>('all');
    const [permFilter, setPermFilter] = useState<'all' | 'pm' | 'non-pm'>('all');
    const [indexError, setIndexError] = useState<string | null>(null);
    const [serviceError, setServiceError] = useState<string | null>(null);
    const [loadingIndex, setLoadingIndex] = useState(true);
    const [loadingService, setLoadingService] = useState(false);

    useEffect(() => {
        let cancelled = false;
        (async () => {
            try {
                setLoadingIndex(true);
                const index = await loadServiceIndex();
                if (cancelled) return;
                const sorted = [...index].sort((a, b) => a.service.localeCompare(b.service));
                setServices(sorted);
                setSelectedService(prev => prev ?? sorted[0] ?? null);
            } catch (error) {
                if (cancelled) return;
                setIndexError(error instanceof Error ? error.message : 'Failed to load services');
            } finally {
                if (!cancelled) setLoadingIndex(false);
            }
        })();
        return () => {
            cancelled = true;
        };
    }, []);

    useEffect(() => {
        if (!selectedService) return;
        setActionQuery('');
    }, [selectedService?.service]);

    useEffect(() => {
        if (!selectedService) return;
        if (serviceData[selectedService.service]) return;

        let cancelled = false;
        (async () => {
            try {
                setLoadingService(true);
                setServiceError(null);
                const actions = await loadServiceActions(selectedService);
                if (cancelled) return;
                setServiceData(prev => ({
                    ...prev,
                    [selectedService.service]: actions
                }));
            } catch (error) {
                if (cancelled) return;
                setServiceError(error instanceof Error ? error.message : 'Failed to load actions');
            } finally {
                if (!cancelled) setLoadingService(false);
            }
        })();

        return () => {
            cancelled = true;
        };
    }, [selectedService, serviceData]);

    const filteredServices = useMemo(() => {
        const term = serviceQuery.trim().toLowerCase();
        if (!term) return services;
        return services.filter(service => service.service.toLowerCase().includes(term));
    }, [services, serviceQuery]);

    const activeServiceKey = selectedService?.service ?? '';
    const actions = activeServiceKey ? serviceData[activeServiceKey] ?? [] : [];

    const filtered = useMemo(() => {
        return actions.filter(action => {
            const isWrite = getIsWriteFlag(action.annotations);
            const isPerm = getIsPermissionManagementFlag(action.annotations);

            const writePass = writeFilter === 'all'
                ? true
                : writeFilter === 'write'
                    ? isWrite === true
                    : isWrite === false;

            const permPass = permFilter === 'all'
                ? true
                : permFilter === 'pm'
                    ? isPerm === true
                    : isPerm === false;

            return writePass && permPass;
        });
    }, [actions, writeFilter, permFilter]);

    const fuse = useMemo(() => new Fuse(filtered, {
        keys: ['service', 'action', 'description', 'annotations', 'conditionKeys', 'resourceTypes'],
        threshold: 0.3,
        minMatchCharLength: 2,
        ignoreLocation: true
    }), [filtered]);

    const deferredQuery = useDeferredValue(actionQuery);

    const results = useMemo(() => {
        if (!deferredQuery.trim()) return filtered.slice(0, 200);
        return fuse.search(deferredQuery).map(r => r.item).slice(0, 200);
    }, [deferredQuery, filtered, fuse]);

    return (
        <div>
            <Header />
            <main className="container px-4 py-6">
                {indexError && <div className="mb-4 rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">Error: {indexError}</div>}
                <div className="grid gap-6 md:grid-cols-[260px_1fr]">
                    <aside>
                        <ServiceList
                            services={filteredServices}
                            query={serviceQuery}
                            onQueryChange={setServiceQuery}
                            onSelect={setSelectedService}
                            selectedService={activeServiceKey}
                            loading={loadingIndex}
                        />
                    </aside>
                    <section>
                        {!selectedService && !loadingIndex && (
                            <div className="rounded border border-gray-200 bg-white p-4 text-sm text-gray-600">
                                Choose a service to browse its IAM actions.
                            </div>
                        )}
                        {selectedService && (
                            <div className="flex flex-col gap-4">
                                <div>
                                    <h2 className="text-xl font-semibold text-gray-800">{selectedService.service}</h2>
                                    <p className="text-sm text-gray-500">Browse IAM actions for this service.</p>
                                </div>
                                {serviceError && (
                                    <div className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">
                                        Unable to load actions: {serviceError}
                                    </div>
                                )}
                                {loadingService && actions.length === 0 && (
                                    <div className="animate-pulse rounded border border-gray-200 bg-gray-50 p-4 text-sm text-gray-600">
                                        Loading actions…
                                    </div>
                                )}
                                {actions.length > 0 && (
                                    <>
                                        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                                            <Search
                                                className="w-full md:flex-1"
                                                value={actionQuery}
                                                onChange={setActionQuery}
                                                total={results.length}
                                            />
                                            <div className="flex flex-wrap items-center gap-3 text-xs text-gray-600">
                                                <div className="flex items-center gap-2">
                                                    <span className="font-semibold">IsWrite:</span>
                                                    <div className="flex gap-1">
                                                        <FilterButton label="All" active={writeFilter === 'all'} onClick={() => setWriteFilter('all')} />
                                                        <FilterButton label="Write" active={writeFilter === 'write'} onClick={() => setWriteFilter('write')} />
                                                        <FilterButton label="Read" active={writeFilter === 'read'} onClick={() => setWriteFilter('read')} />
                                                    </div>
                                                </div>
                                                <div className="flex items-center gap-2">
                                                    <span className="font-semibold">Permission mgmt:</span>
                                                    <div className="flex gap-1">
                                                        <FilterButton label="All" active={permFilter === 'all'} onClick={() => setPermFilter('all')} />
                                                        <FilterButton label="PM" active={permFilter === 'pm'} onClick={() => setPermFilter('pm')} />
                                                        <FilterButton label="Non-PM" active={permFilter === 'non-pm'} onClick={() => setPermFilter('non-pm')} />
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                        <Results items={results} />
                                    </>
                                )}
                                {!loadingService && actions.length === 0 && !serviceError && (
                                    <div className="rounded border border-gray-200 bg-white p-4 text-sm text-gray-600">
                                        No actions found for this service.
                                    </div>
                                )}
                            </div>
                        )}
                    </section>
                </div>
            </main>
            <footer className="border-t border-gray-200 bg-gray-50 py-4">
                <div className="container px-4 text-xs text-gray-500">
                    AWS Service Browser is a personal project and is not affiliated with, endorsed, or sponsored by Amazon Web Services.
                </div>
            </footer>
        </div>
    );
}

function getIsWriteFlag(annotations: string[]): boolean | null {
    const entry = annotations.find(a => a.toLowerCase().startsWith('iswrite'));
    if (!entry) return null;
    return entry.toLowerCase().includes('true');
}

function getIsPermissionManagementFlag(annotations: string[]): boolean | null {
    const entry = annotations.find(a => a.toLowerCase().startsWith('ispermissionmanagement'));
    if (!entry) return null;
    return entry.toLowerCase().includes('true');
}

function FilterButton({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
    const base = 'rounded border px-2 py-1 text-xs';
    const activeClass = active ? 'border-blue-500 bg-blue-50 text-blue-700' : 'border-gray-200 bg-white text-gray-700 hover:border-gray-300';
    return (
        <button type="button" className={`${base} ${activeClass}`} onClick={onClick}>
            {label}
        </button>
    );
}

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

    const fuse = useMemo(() => new Fuse(actions, {
        keys: ['service', 'action', 'description', 'annotations', 'conditionKeys', 'resourceTypes'],
        threshold: 0.3,
        minMatchCharLength: 2,
        ignoreLocation: true
    }), [actions]);

    const deferredQuery = useDeferredValue(actionQuery);

    const results = useMemo(() => {
        if (!deferredQuery.trim()) return actions.slice(0, 200);
        return fuse.search(deferredQuery).map(r => r.item).slice(0, 200);
    }, [deferredQuery, actions, fuse]);

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
                                        <Search value={actionQuery} onChange={setActionQuery} total={results.length} />
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
        </div>
    );
}

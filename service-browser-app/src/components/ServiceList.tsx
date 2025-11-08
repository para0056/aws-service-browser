import type { ServiceIndexEntry } from '../types';

type Props = {
    services: ServiceIndexEntry[];
    query: string;
    onQueryChange: (value: string) => void;
    onSelect: (service: ServiceIndexEntry) => void;
    selectedService?: string | null;
    loading?: boolean;
};

export default function ServiceList({
    services,
    query,
    onQueryChange,
    onSelect,
    selectedService,
    loading = false
}: Props) {
    return (
        <div className="flex h-full flex-col">
            <label className="text-xs font-semibold uppercase tracking-wide text-gray-500">
                Service
                <input
                    type="search"
                    value={query}
                    onChange={(event) => onQueryChange(event.target.value)}
                    placeholder="Filter services…"
                    className="mt-1 w-full rounded border px-3 py-2 text-sm shadow-sm outline-none focus:ring"
                />
            </label>
            <div className="mt-3 flex-1 overflow-hidden rounded border border-gray-200 bg-white">
                {loading ? (
                    <div className="p-3 text-sm text-gray-500">Loading services…</div>
                ) : (
                    <ul className="max-h-[60vh] overflow-y-auto">
                        {services.length === 0 ? (
                            <li className="px-3 py-2 text-sm text-gray-500">No matching services.</li>
                        ) : (
                            services.map((service) => {
                                const isSelected = selectedService === service.service;
                                return (
                                    <li key={service.service}>
                                        <button
                                            type="button"
                                            onClick={() => onSelect(service)}
                                            className={`block w-full px-3 py-2 text-left text-sm transition ${
                                                isSelected
                                                    ? 'bg-blue-50 font-semibold text-blue-700'
                                                    : 'hover:bg-gray-50'
                                            }`}
                                        >
                                            {service.service}
                                        </button>
                                    </li>
                                );
                            })
                        )}
                    </ul>
                )}
            </div>
        </div>
    );
}

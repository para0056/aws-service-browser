import { useRef } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { AwsAction } from '../types';

export default function Results({ items }: { items: AwsAction[] }) {
    const parentRef = useRef<HTMLDivElement>(null);
    const rowVirtualizer = useVirtualizer({
        count: items.length,
        getScrollElement: () => parentRef.current,
        estimateSize: () => 140,
        getItemKey: index => {
            const item = items[index];
            return item ? `${item.service}:${item.action}` : index;
        },
        overscan: 12,
    });

    if (!items.length) return <div className="text-gray-600">No results.</div>;

    return (
        <div ref={parentRef} className="max-h-[70vh] overflow-y-auto">
            <div
                className="relative w-full"
                style={{ height: `${rowVirtualizer.getTotalSize()}px` }}
            >
                {rowVirtualizer.getVirtualItems().map(virtualRow => {
                    const action = items[virtualRow.index];
                    return (
                        <div
                            key={virtualRow.key}
                            data-index={virtualRow.index}
                            ref={rowVirtualizer.measureElement}
                            className="absolute left-0 right-0 px-0"
                            style={{ transform: `translateY(${virtualRow.start}px)` }}
                        >
                            <ResultCard action={action} />
                        </div>
                    );
                })}
            </div>
        </div>
    );
}

function ResultCard({ action }: { action: AwsAction }) {
    return (
        <article className="mb-2 rounded border border-gray-200 bg-white p-3 shadow-sm">
            <div className="font-semibold">{action.service}:{action.action}</div>
            {action.description && <p className="mt-1 text-sm text-gray-700">{action.description}</p>}
            <AnnotationsList items={action.annotations} />
            <ConditionKeys items={action.conditionKeys} />
            <ResourceTypes items={action.resourceTypes} />
        </article>
    );
}

function AnnotationsList({ items }: { items: string[] }) {
    if (!items || items.length === 0) return null;
    return (
        <div className="mt-2 text-xs">
            <span className="font-semibold text-gray-600">Annotations:</span>
            <ul className="mt-1 space-y-1">
                {items.map((item, index) => {
                    const normalized = item.toLowerCase();
                    const isWrite = normalized.startsWith('iswrite') && normalized.includes('true');
                    const colorClass = isWrite ? 'text-red-600' : 'text-blue-700';
                    return (
                        <li key={`${item}:${index}`} className={colorClass}>
                            {item}
                        </li>
                    );
                })}
            </ul>
        </div>
    );
}

function MetaRow({ label, items, className }: { label: string; items: string[]; className?: string }) {
    if (!items || items.length === 0) return null;
    return (
        <div className="mt-2 text-xs">
            <span className="font-semibold text-gray-600">{label}: </span>
            <span className={className}>{items.join(', ')}</span>
        </div>
    );
}

function ConditionKeys({ items }: { items: string[] }) {
    if (!items || items.length === 0) return null;
    return (
        <div className="mt-3 text-xs">
            <span className="font-semibold text-gray-600">Condition keys:</span>
            <div className="mt-1 flex flex-wrap gap-1.5">
                {items.map(key => (
                    <span
                        key={key}
                        className="inline-flex items-center rounded border border-purple-200 bg-purple-50 px-2 py-0.5 font-mono text-[11px] text-purple-800"
                    >
                        {key}
                    </span>
                ))}
            </div>
        </div>
    );
}

function ResourceTypes({ items }: { items: string[] }) {
    if (!items || items.length === 0) return null;
    return (
        <div className="mt-3 text-xs">
            <span className="font-semibold text-gray-600">Resource types:</span>
            <div className="mt-1 flex flex-wrap gap-1.5">
                {items.map(type => (
                    <span
                        key={type}
                        className="inline-flex items-center rounded border border-green-200 bg-green-50 px-2 py-0.5 font-mono text-[11px] text-green-800"
                    >
                        {type}
                    </span>
                ))}
            </div>
        </div>
    );
}

import { useRef } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { AwsAction } from '../types';

export default function Results({ items }: { items: AwsAction[] }) {
    const parentRef = useRef<HTMLDivElement>(null);
    const rowVirtualizer = useVirtualizer({
        count: items.length,
        getScrollElement: () => parentRef.current,
        estimateSize: () => 140,
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
                            ref={virtualRow.measureElement}
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
            <MetaRow label="Condition keys" items={action.conditionKeys} className="text-purple-700" />
            <MetaRow label="Resource types" items={action.resourceTypes} className="text-green-700" />
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

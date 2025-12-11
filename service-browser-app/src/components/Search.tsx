type Props = { value: string; onChange: (v: string) => void; total: number; className?: string };
export default function Search({ value, onChange, total, className = '' }: Props) {
    return (
        <div className={`mb-4 ${className}`}>
            <input
                type="search"
                value={value}
                onChange={(e) => onChange(e.target.value)}
                placeholder="Filter by service, action, or description…"
                className="w-full rounded border px-3 py-2 shadow-sm outline-none focus:ring"
                autoFocus
            />
            <div className="mt-1 text-xs text-gray-500">{total.toLocaleString()} results</div>
        </div>
    );
}

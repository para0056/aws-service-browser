export default function Header() {
    return (
        <header className="border-b bg-white">
            <div className="container px-4 py-4">
                <h1 className="text-2xl font-bold">AWS Service Action Browser</h1>
                <p className="text-sm text-gray-600">Search IAM actions by service, action, or description.</p>
            </div>
        </header>
    );
}

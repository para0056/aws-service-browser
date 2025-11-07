const CACHE_NAME = 'aws-service-browser-v1';
const STATIC_ASSETS = ['/', '/index.html'];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS))
    );
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) =>
            Promise.all(
                keys
                    .filter((key) => key !== CACHE_NAME)
                    .map((key) => caches.delete(key))
            )
        )
    );
    self.clients.claim();
});

self.addEventListener('fetch', (event) => {
    const { request } = event;
    if (request.method !== 'GET') return;

    const url = new URL(request.url);
    const isSameOrigin = url.origin === self.location.origin;
    const isJSON = isSameOrigin && url.pathname.endsWith('.json');
    const isAsset = isSameOrigin && url.pathname.startsWith('/assets/');

    if (isJSON || isAsset) {
        event.respondWith(staleWhileRevalidate(request));
        return;
    }

    if (request.mode === 'navigate') {
        event.respondWith(
            caches.open(CACHE_NAME).then(async (cache) => {
                try {
                    const response = await fetch(request);
                    cache.put('/', response.clone());
                    return response;
                } catch {
                    const fallback = await cache.match('/') ?? await cache.match('/index.html');
                    return fallback ?? Response.error();
                }
            })
        );
    }
});

async function staleWhileRevalidate(request) {
    const cache = await caches.open(CACHE_NAME);
    const cached = await cache.match(request);

    const networkFetch = fetch(request)
        .then((response) => {
            if (response && response.ok) {
                cache.put(request, response.clone());
            }
            return response;
        })
        .catch(() => undefined);

    if (cached) {
        return cached;
    }

    const response = await networkFetch;
    return response ?? Response.error();
}

// سرویس‌ورکر: ذخیرهٔ پوستهٔ برنامه برای کار بدون اینترنت
const CACHE = 'sene-a2a96c303f3c';
const FILES = ["./","index.html","app.js","app.css","config.js","manifest.webmanifest","icon-192.png","icon-512.png","icon-180.png","icon-32.png"];
self.addEventListener('install', (e) => { e.waitUntil(caches.open(CACHE).then((c) => c.addAll(FILES.map((f) => new URL(f, self.registration.scope).href))).then(() => self.skipWaiting())); });
self.addEventListener('activate', (e) => { e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k.startsWith('sene-') && k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener('fetch', (e) => {
  const r = e.request; if (r.method !== 'GET' || new URL(r.url).origin !== location.origin) return;
  e.respondWith((async () => { const hit = await caches.match(r, { ignoreSearch: true }); if (hit) return hit; try { return await fetch(r); } catch { if (r.mode === 'navigate') { const i = await caches.match(new URL('./', self.registration.scope).href); if (i) return i; } return new Response('آفلاین', { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }); } })());
});

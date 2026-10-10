/* Atlas Rental.io service worker.
   Network-first for everything (never serve stale HTML/JS), cache only as an OFFLINE fallback.
   Own cache name so it never touches other apps' caches. Deploy Atlas in its own folder in
   production so this SW's scope stays isolated from any sibling app's service worker. */
var CACHE = 'atlas-shell-v357';
var SHELL = ['atlas.html', 'atlas-manifest.json', 'atlas-icon.svg'];

self.addEventListener('install', function (e) {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(function (c) { return c.addAll(SHELL).catch(function () {}); }));
});

self.addEventListener('activate', function (e) {
  e.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(keys.map(function (k) { if (k !== CACHE) return caches.delete(k); }));
    }).then(function () { return self.clients.claim(); })
  );
});

self.addEventListener('fetch', function (e) {
  var req = e.request;
  if (req.method !== 'GET') return;                       // never touch POST/PUT
  var url = new URL(req.url);
  if (url.origin !== self.location.origin) return;         // let cross-origin (CDN/maps) go straight to network
  if (url.pathname.indexOf('/api/') === 0 || url.pathname.indexOf('/agents') === 0 || url.pathname === '/llms.txt') return;   // SECURITY (audit HIGH): NEVER cache or offline-serve authenticated API data. It is tenant-scoped ONLY by the session cookie, so a URL-keyed cache (e.g. /api/data/customers?offset=0) would serve one tenant's bookings/customers/PII to the NEXT tenant on a shared browser. Always hit the network; the app handles any error itself.
  // Code (navigations / .html / .js) is fetched cache:'no-store' so a fresh deploy ALWAYS shows next load --
  // plain fetch() can otherwise return a stale HTTP-cached HTML (GitHub Pages sets max-age), which is exactly
  // how an old build keeps showing on the live site. Other assets use the normal cache.
  var fresh = req.mode === 'navigate' || /\.(html|js)(\?|#|$)/i.test(req.url);
  var freq = fresh ? new Request(req.url, { cache: 'no-store' }) : req;
  e.respondWith(
    fetch(freq).then(function (res) {
      // keep a fresh copy of same-origin STATIC GETs for offline use (API is already excluded above)
      if (res && res.ok) { var copy = res.clone(); caches.open(CACHE).then(function (c) { c.put(req, copy).catch(function () {}); }); }
      return res;
    }).catch(function () {
      // offline: serve from cache, falling back to the app shell for navigations
      return caches.match(req).then(function (hit) {
        return hit || (req.mode === 'navigate' ? caches.match('atlas.html') : undefined);
      });
    })
  );
});


/* ---- Web push (RFC 8291): show owner/renter notifications pushed by the worker. Inert unless a push actually arrives. ---- */
self.addEventListener('push', function(e){
  var d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) { try { d = { title: 'Atlas Rental', body: (e.data && e.data.text()) || '' }; } catch (__) { d = {}; } }
  var title = d.title || 'Atlas Rental';
  var opts = { body: d.body || '', icon: '/atlas-hq-icon-192.png', badge: '/atlas-hq-icon-192.png', data: { url: d.url || '/' } };
  if (d.tag) opts.tag = d.tag;
  e.waitUntil(self.registration.showNotification(title, opts));
});
self.addEventListener('notificationclick', function(e){
  e.notification.close();
  var url = (e.notification.data && e.notification.data.url) || '/';
  e.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(ws){
    for (var i = 0; i < ws.length; i++) { if (ws[i].url.indexOf(url) >= 0 && 'focus' in ws[i]) return ws[i].focus(); }
    if (clients.openWindow) return clients.openWindow(url);
  }));
});

/* Atlas Rental.io service worker.
   Network-first for everything (never serve stale HTML/JS), cache only as an OFFLINE fallback.
   Own cache name so it never touches other apps' caches. Deploy Atlas in its own folder in
   production so this SW's scope stays isolated from any sibling app's service worker. */
var CACHE = 'atlas-shell-v98';
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
  // Code (navigations / .html / .js) is fetched cache:'no-store' so a fresh deploy ALWAYS shows next load --
  // plain fetch() can otherwise return a stale HTTP-cached HTML (GitHub Pages sets max-age), which is exactly
  // how an old build keeps showing on the live site. Other assets use the normal cache.
  var fresh = req.mode === 'navigate' || /\.(html|js)(\?|#|$)/i.test(req.url);
  var freq = fresh ? new Request(req.url, { cache: 'no-store' }) : req;
  e.respondWith(
    fetch(freq).then(function (res) {
      // keep a fresh copy of same-origin GETs for offline use
      var copy = res.clone();
      caches.open(CACHE).then(function (c) { c.put(req, copy).catch(function () {}); });
      return res;
    }).catch(function () {
      // offline: serve from cache, falling back to the app shell for navigations
      return caches.match(req).then(function (hit) {
        return hit || (req.mode === 'navigate' ? caches.match('atlas.html') : undefined);
      });
    })
  );
});

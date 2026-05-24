const CACHE = 'pb-v6';
const STATIC = ['./icon.png']; // only static assets — HTML is never cached

self.addEventListener('install', function(e) {
  e.waitUntil(caches.open(CACHE).then(function(c){ return c.addAll(STATIC); }));
  self.skipWaiting();
});

self.addEventListener('activate', function(e) {
  e.waitUntil(caches.keys().then(function(keys){
    return Promise.all(keys.filter(function(k){ return k!==CACHE; }).map(function(k){ return caches.delete(k); }));
  }));
  self.clients.claim();
});

self.addEventListener('fetch', function(e) {
  if(e.request.method !== 'GET') return;
  var url = new URL(e.request.url);

  // HTML pages: always fetch fresh from network, no cache fallback
  if(url.pathname.endsWith('.html') || url.pathname === '/' || url.pathname.endsWith('/')) {
    e.respondWith(
      fetch(e.request, { cache: 'no-store' }).catch(function(){
        return new Response(
          '<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>' +
          '<body style="font-family:-apple-system,sans-serif;background:#111;color:#fff;padding:48px;text-align:center">' +
          '<div style="color:#C9A962;font-size:22px;font-weight:900;margin-bottom:16px">PB Dashboard</div>' +
          '<p style="opacity:.7">You\'re offline. Connect to the internet to access the dashboard.</p></body></html>',
          { headers: { 'Content-Type': 'text/html' } }
        );
      })
    );
    return;
  }

  // Static assets: cache-first
  e.respondWith(
    caches.match(e.request).then(function(cached){
      return cached || fetch(e.request).then(function(res){
        caches.open(CACHE).then(function(c){ c.put(e.request, res.clone()); });
        return res;
      });
    })
  );
});

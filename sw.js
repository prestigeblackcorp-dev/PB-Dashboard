const CACHE = 'pb-v17';
const ASSETS = ['./index.html', './icon.png'];

self.addEventListener('install', function(e) {
  e.waitUntil(caches.open(CACHE).then(function(c){ return c.addAll(ASSETS); }));
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
  // Always try network first, fall back to cache
  e.respondWith(
    fetch(e.request).then(function(res){
      var clone = res.clone();
      caches.open(CACHE).then(function(c){ c.put(e.request, clone); });
      return res;
    }).catch(function(){
      return caches.match(e.request);
    })
  );
});

// ── Push Notifications ────────────────────────────────────────────────────────
self.addEventListener('push', function(e) {
  var data = {};
  try { data = e.data ? e.data.json() : {}; } catch(err) {}
  var title   = data.title || 'Prestige Black Rentals';
  var options = {
    body:    data.body  || '',
    icon:    'https://prestigeblackrentals.com/cdn/shop/files/pb-logo-gold.png',
    badge:   'https://prestigeblackrentals.com/cdn/shop/files/pb-logo-gold.png',
    tag:     data.tag   || 'pb-notif',
    data:    { url: data.url || 'https://prestigeblackcorp-dev.github.io/PB-Dashboard/portal.html' },
    requireInteraction: !!data.requireInteraction,
    vibrate: [200, 100, 200],
  };
  e.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', function(e) {
  e.notification.close();
  var target = (e.notification.data && e.notification.data.url)
    || 'https://prestigeblackcorp-dev.github.io/PB-Dashboard/portal.html';
  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(list) {
      for (var i = 0; i < list.length; i++) {
        var c = list[i];
        if (c.url.includes('PB-Dashboard') && 'focus' in c) return c.focus();
      }
      return clients.openWindow(target);
    })
  );
});

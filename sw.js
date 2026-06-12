const CACHE = 'pb-v72';
const ASSETS = ['./index.html', './icon.png', './obsidian.html', './driver.html', './pb-config.js'];

self.addEventListener('install', function(e) {
  e.waitUntil(caches.open(CACHE).then(function(c){ return c.addAll(ASSETS); }));
  self.skipWaiting();
});

self.addEventListener('activate', function(e) {
  e.waitUntil(caches.keys().then(function(keys){
    // keep the current app cache AND the push-auth cache; drop the rest
    return Promise.all(keys.filter(function(k){ return k!==CACHE && k!=='pb-push'; }).map(function(k){ return caches.delete(k); }));
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

// ── Web Push (tickle) ────────────────────────────────────────────────────────
// The client stashes its {role, token, worker, vapid} here. On a (payload-less) push
// we wake, fetch the latest offer/status from the worker, and show a notification.
// userVisibleOnly is satisfied because every push path calls showNotification.
function _pbUrlB64(s){ s=(s||'').replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4) s+='='; var bin=atob(s); var u=new Uint8Array(bin.length); for(var i=0;i<bin.length;i++) u[i]=bin.charCodeAt(i); return u; }
function _pbReadAuth(){
  return caches.open('pb-push').then(function(c){ return c.match('/__pbauth'); }).then(function(r){ return r?r.json():null; }).catch(function(){ return null; });
}

self.addEventListener('message', function(e){
  var d=e.data||{};
  if(d.type==='pb-push-auth'){
    e.waitUntil(caches.open('pb-push').then(function(c){
      return c.put('/__pbauth', new Response(JSON.stringify({role:d.role,token:d.token,worker:d.worker,vapid:d.vapid}), {headers:{'Content-Type':'application/json'}}));
    }));
  }
});

self.addEventListener('push', function(e){
  e.waitUntil(_pbReadAuth().then(function(auth){
    var title='Prestige Black', body='Tap to open', data={app:'./obsidian.html'};
    var show=function(){ return self.registration.showNotification(title, { body:body, icon:'./icon.png', badge:'./icon.png', tag:'pb-'+(data.rideId||'update'), renotify:true, data:data }); };
    if(auth && auth.role==='driver' && auth.worker && auth.token){
      return fetch(auth.worker+'/chauffeur/driver-rides?token='+encodeURIComponent(auth.token)+'&_='+Date.now(), {cache:'no-store'})
        .then(function(r){ return r.json(); })
        .then(function(d){
          if(d && d.notification && d.notification.status==='pending'){
            var n=d.notification;
            var take=n.estimatedPrice?(' · $'+Math.round(n.estimatedPrice*0.35)+' you'):'';
            title='🚗 New ride request'+take;
            body=(n.pickupAddress||'Pickup nearby')+(n.rideType==='hourly'?' · Hourly':'');
            data={app:'./driver.html', rideId:n.rideId};
          } else { title='Prestige Black'; body='Open the driver app for updates'; data={app:'./driver.html'}; }
          return show();
        })
        .catch(function(){ title='🚗 New ride request'; body='Open the driver app to accept'; data={app:'./driver.html'}; return show(); });
    }
    // rider / unknown — generic update; the app shows the live status when opened
    title='Prestige Black'; body='Your chauffeur — tap for an update'; data={app:'./obsidian.html'};
    return show();
  }));
});

self.addEventListener('notificationclick', function(e){
  e.notification.close();
  var url=(e.notification.data && e.notification.data.app) || './obsidian.html';
  var want=url.replace('./','');
  e.waitUntil(clients.matchAll({type:'window', includeUncontrolled:true}).then(function(cl){
    for(var i=0;i<cl.length;i++){ if(cl[i].url.indexOf(want)>=0 && 'focus' in cl[i]) return cl[i].focus(); }
    if(clients.openWindow) return clients.openWindow(url);
  }));
});

self.addEventListener('pushsubscriptionchange', function(e){
  e.waitUntil(_pbReadAuth().then(function(auth){
    if(!auth || !auth.vapid || !auth.worker || !auth.token) return;
    return self.registration.pushManager.subscribe({userVisibleOnly:true, applicationServerKey:_pbUrlB64(auth.vapid)})
      .then(function(sub){ return fetch(auth.worker+'/push/subscribe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({role:auth.role,token:auth.token,subscription:sub.toJSON()})}); })
      .catch(function(){});
  }));
});

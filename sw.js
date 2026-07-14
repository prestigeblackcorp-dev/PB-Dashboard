const CACHE = 'pb-v217';
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
  // ONLY handle same-origin GETs. Cross-origin API calls (the Cloudflare worker: sync load/savedAt,
  // ride-status, etc.) MUST pass straight through to the network. Intercepting them gave no benefit and
  // actively broke them: those GETs are cache-busted (?_=timestamp) so they are never in the cache, and
  // on ANY network blip the offline fallback ran caches.match() -> undefined -> "FetchEvent.respondWith
  // received an error: Returned response is null", failing the request (red sync dot). Passing them
  // through gives a clean, retryable failure instead.
  var _url; try { _url = new URL(e.request.url); } catch(_e){ return; }
  if(_url.origin !== self.location.origin) return;
  // Network-first. Code (navigations / .html / .js) is fetched with cache:'no-store' so a new
  // deploy ALWAYS shows on the next load \u2014 never a stale build from the browser/CDN HTTP cache
  // (this was the bug: max-age=600 on GitHub Pages kept serving old HTML). Other assets use the
  // normal cache. Offline \u2192 fall back to whatever we cached, else a clean error Response.
  var fresh = e.request.mode === 'navigate' || /\.(html|js)(\?|#|$)/i.test(e.request.url);
  var req = fresh ? new Request(e.request.url, { cache: 'no-store' }) : e.request;
  e.respondWith(
    fetch(req).then(function(res){
      var clone = res.clone();
      caches.open(CACHE).then(function(c){ c.put(e.request, clone); }).catch(function(){});
      return res;
    }).catch(function(){
      // NEVER return undefined here -> that throws "Returned response is null". Cached copy, else error.
      return caches.match(e.request).then(function(m){ return m || Response.error(); });
    })
  );
});

// \u2500\u2500 Web Push (tickle) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
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
      return c.put('/__pbauth', new Response(JSON.stringify({role:d.role,token:d.token,worker:d.worker,vapid:d.vapid,rideId:d.rideId||null}), {headers:{'Content-Type':'application/json'}}));
    }));
  } else if(d.type==='pb-push-ride'){
    // Track the rider's current active rideId so a rider push can fetch the live status
    // and show a SPECIFIC message (on the way / arrived / etc.).
    e.waitUntil(_pbReadAuth().then(function(a){ a=a||{}; a.rideId=d.rideId||null; return caches.open('pb-push').then(function(c){ return c.put('/__pbauth', new Response(JSON.stringify(a), {headers:{'Content-Type':'application/json'}})); }); }));
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
          data={app:'./driver.html'};
          if(d && d.notification && d.notification.status==='pending'){
            var n=d.notification;
            var take=n.estimatedPrice?(' \u00B7 $'+Math.round(n.estimatedPrice*0.35)+' you'):'';
            title='\uD83D\uDE97 New ride request'+take;
            body=(n.pickupAddress||'Pickup nearby')+(n.rideType==='hourly'?' \u00B7 Hourly':'');
            data.rideId=n.rideId;
          } else if(d && d.activeRide && d.activeRide.pendingStop && d.activeRide.pendingStop.status==='pending'){
            var pa=d.activeRide;
            title='\uD83D\uDCCD Add-stop request';
            body=(pa.pendingStop.riderName||pa.riderName||'Your guest')+' wants to add '+(pa.pendingStop.stopAddress||'a stop')+' \u2014 accept or deny';
            data.rideId=pa.id;
          } else if(d && d.activeRide && d.activeRide.stopsUpdatedAt && (Date.now()-Number(d.activeRide.stopsUpdatedAt))<120000){
            var ar=d.activeRide;
            title='\uD83D\uDCCD Route updated';
            body=(ar.riderName?ar.riderName+': ':'')+'new stop \u2014 '+(ar.dropoffAddress||'tap for details');
            data.rideId=ar.id;
          } else if(d && d.activeRide){
            title='Trip update'; body='Tap to open your active trip'; data.rideId=d.activeRide.id;
          } else {
            title='Prestige Black'; body='Open the chauffeur app for updates';
          }
          return show();
        })
        .catch(function(){ title='\uD83D\uDE97 New ride request'; body='Open the chauffeur app to accept'; data={app:'./driver.html'}; return show(); });
    }
    // RIDER \u2014 fetch the live status (when we know the rideId) and show a SPECIFIC message.
    if(auth && auth.role==='rider' && auth.worker && auth.token && auth.rideId){
      return fetch(auth.worker+'/chauffeur/ride-status?rideId='+encodeURIComponent(auth.rideId)+'&token='+encodeURIComponent(auth.token)+'&_='+Date.now(), {cache:'no-store'})
        .then(function(r){ return r.json(); })
        .then(function(d){
          data={app:'./obsidian.html', rideId:auth.rideId};
          var st=(d && d.ride && d.ride.status)||'';
          var dn=(d && d.driver && d.driver.name)||'';
          var rd=(d && d.ride)||{};
          if(rd.stopAcceptedAt && (Date.now()-Number(rd.stopAcceptedAt))<120000){ title='\u2713 Chauffeur accepted your stop'; body='Routing to your added stop now'; }
          else if(rd.stopDeniedAt && (Date.now()-Number(rd.stopDeniedAt))<120000){ title='Chauffeur declined your stop'; body='That stop wasn\'t added \u2014 you were not charged'; }
          else if(st==='accepted'){ title='\uD83D\uDE97 Chauffeur on the way'+(dn?' \u00B7 '+dn:''); body='Your chauffeur is heading to your pickup'; }
          else if(st==='driver_arrived'){ title='\uD83D\uDC4B Your chauffeur has arrived'; body='Head outside \u2014 '+(dn||'your chauffeur')+' is waiting'; }
          else if(st==='searching'){ title='Finding your chauffeur\u2026'; body='Connecting you with the nearest available chauffeur'; }
          else if(st==='in_progress'){ title='Trip update'; body='Tap to view your live trip'; }
          else if(st==='completed'){ title='Trip complete'; body='Thank you for riding with Obsidian \u2014 tap for your receipt'; }
          else if(st==='cancelled'||st==='no_driver'){ title='Ride update'; body='Tap to open Obsidian'; }
          else { title='Trip update'; body='Tap to open'; }
          return show();
        })
        .catch(function(){ title='Trip update'; body='Tap to open'; data={app:'./obsidian.html'}; return show(); });
    }
    // rider without a known active ride / unknown \u2014 generic
    title='Trip update'; body='Tap to open'; data={app:'./obsidian.html'};
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

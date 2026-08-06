/* ============================================================================
   PB DASHBOARD -- VEHICLE / PARTS SEARCH  (self-contained feature module)
   Loaded by index.html via <script src>. Renders into #vehSearchContent when
   switchTab('vehsearch') fires. NOTHING here touches the booking/money/sync
   state -- its own localStorage keys + its own worker path, fully additive and
   reversible (kill with window.PB_FLAGS.vehicleSearch=false).

   Three sub-tabs:
     1) Current Leads  -- nationwide salvage/repairable exotics matching your
        buy criteria, heart -> watchlist, 3-day/buy-now actionable filter,
        make/model/year filter, one-click live searches per target.
     2) Parts Search   -- pick a fleet car (or any real year/make/model) + a
        part or part number -> deep links to eBay/Amazon/RockAuto/FCP Euro/
        Car-Part.com (junkyards + phones) + OEM-by-VIN + part breakdowns.
     3) Outreach Kit   -- lien/shop call scripts + gov-auction date tracker so
        the clean-title lane runs on autopilot.

   Pure ASCII (HTML entities render the icons). No external libs.
   ========================================================================== */
(function(){
  "use strict";
  if (window.__pbvsLoaded) return; window.__pbvsLoaded = true;

  // ---- small helpers ---------------------------------------------------------
  function q(s){ return encodeURIComponent(String(s==null?'':s).trim()); }
  function esc(s){ return String(s==null?'':s).replace(/[&<>"']/g,function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); }
  function el(id){ return document.getElementById(id); }
  function vehStr(v){ return [v.year,v.make,v.model,v.trim].filter(Boolean).join(' '); }
  function _toast(m){ try{ if(typeof window.toast==='function') window.toast(m); }catch(e){} }
  function _worker(){ try{ return (typeof WORKER_URL!=='undefined'&&WORKER_URL)?WORKER_URL:''; }catch(e){ return ''; } }
  function _auth(){ try{ return (typeof _authHeader==='function')?_authHeader():{}; }catch(e){ return {}; } }
  function looksLikePart(s){ s=String(s||'').trim(); return s.length>=4 && /\d/.test(s) && /[A-Za-z0-9][-A-Za-z0-9. ]{3,}/.test(s) && !/\s{2,}/.test(s) && s.split(' ').length<=3; }

  // ---- persisted state (own keys; never in the bookings blob) ----------------
  var LSK_CRIT='pbvs_criteria', LSK_WATCH='pbvs_watch', LSK_SUB='pbvs_sub', LSK_ACT='pbvs_actionable', LSK_CART='pbvs_cart', LSK_CFG='pbvs_config', LSK_SAVED='pbvs_saved_at';
  var _DEF_CFG={ yearMin:2015, maxPrice:30000, maxMiles:0, title:'Any', excludeDamage:'burn,fire,flood,rollover', snipeDays:1, stealOn:true, snipeOn:true, heartOn:true };
  function _lsGet(k,f){ try{ var v=localStorage.getItem(k); return v?JSON.parse(v):f; }catch(e){ return f; } }
  function _lsSet(k,v){ try{ localStorage.setItem(k,JSON.stringify(v)); }catch(e){} }

  var DEFAULT_CRITERIA = [
    {make:'Audi',    model:'R8',         yearMin:2010, yearMax:2016, note:'V10 5.2 priority'},
    {make:'Porsche', model:'911',        yearMin:2012, yearMax:2019, note:'Carrera S / Turbo / GTS'},
    {make:'Ferrari', model:'California',  yearMin:2009, yearMax:2017, note:'California / T'},
    {make:'McLaren', model:'570S',       yearMin:2015, yearMax:2020, note:''},
    {make:'McLaren', model:'650S',       yearMin:2014, yearMax:2017, note:''}
  ];

  var PBVS = {
    sub:      _lsGet(LSK_SUB,'leads'),
    actionable: _lsGet(LSK_ACT,false),     // date filter OFF by default so nothing is silently hidden on first load
    criteria: _lsGet(LSK_CRIT, DEFAULT_CRITERIA),
    watch:    _lsGet(LSK_WATCH, []),      // [{...lead, addedAt}]
    cart:     _lsGet(LSK_CART, []),        // parts cart + order log
    config:   _lsGet(LSK_CFG, {}),         // hunt filters (merged with _DEF_CFG)
    savedAt:  _lsGet(LSK_SAVED, 0),        // last local edit time (arbitrates cross-device merge)
    leads:    [],                          // live feed if worker returns one
    findLeads:[],                          // last Vehicle-Search results (so heart/report work on them)
    feedSrc:  'starter',
    feedAt:   0, feedScraped:null, feedGov:null, feedBlocked:false,
    showEverything:false,                  // "Show everything" bypass (session only)
    fMake:'', fModel:'', fYear:'',        // leads filter
    nMakes:null, nModels:{}                // NHTSA caches
  };
  function _touch(){ PBVS.savedAt=Date.now(); _lsSet(LSK_SAVED,PBVS.savedAt); }
  function saveCrit(){ _lsSet(LSK_CRIT,PBVS.criteria); _touch(); _pushState(); }
  function saveWatch(){ _lsSet(LSK_WATCH,PBVS.watch); _touch(); _pushState(); }

  // Best-effort cross-device mirror (Phase 2 worker endpoint). Falls back to
  // localStorage-only; never blocks or throws.
  function cfg(){ return Object.assign({}, _DEF_CFG, PBVS.config||{}); }
  function saveConfig(){ _lsSet(LSK_CFG, PBVS.config); _touch(); _pushState(); }
  function _pushState(){
    var w=_worker(); if(!w) return;
    // Never PUT before we have merged the server copy on load -- otherwise the first
    // edit on a fresh device wipes the server watchlist/targets/cart. Queue instead.
    if(!PBVS._hydrated){ PBVS._pendingPush=true; return; }
    var C=cfg();
    // map the owner-facing settings to the worker's config field names, and carry the
    // owner-facing config verbatim under `ui` so the other device rebuilds it exactly.
    var wcfg={ yearMin:+C.yearMin||0, maxBuyNow:+C.maxPrice||0, maxMiles:+C.maxMiles||0,
      requireCleanTitle:(C.title==='Clean'), excludeDamage:C.excludeDamage||'', snipeDays:+C.snipeDays||1,
      stealEnabled:C.stealOn!==false, snipeEnabled:C.snipeOn!==false, heartEnabled:C.heartOn!==false,
      ui:(PBVS.config||{}) };
    try{
      fetch(w+'/vehicle-search/state',{method:'PUT',
        headers:Object.assign({'Content-Type':'application/json'},_auth()),
        body:JSON.stringify({criteria:PBVS.criteria,watch:PBVS.watch,cart:PBVS.cart,config:wcfg,savedAt:PBVS.savedAt})}).catch(function(){});
    }catch(e){}
  }
  // union two arrays by a key function (local wins on collision) -- so a second device NEVER loses items
  function _unionBy(local,remote,keyFn){ local=Array.isArray(local)?local.slice():[]; var seen={}; local.forEach(function(x){ if(x)seen[keyFn(x)]=1; }); (Array.isArray(remote)?remote:[]).forEach(function(x){ if(x&&!seen[keyFn(x)]){ seen[keyFn(x)]=1; local.push(x); } }); return local; }
  // Pull the server copy ONCE on load and merge BEFORE any push. Watch + cart are UNIONed
  // (no device loses saved items); criteria/config adopt the server's when it is newer.
  function _hydrateState(){
    var w=_worker(); if(!w){ PBVS._hydrated=true; return; }
    var fin=function(){ PBVS._hydrated=true; if(PBVS._pendingPush){ PBVS._pendingPush=false; _pushState(); } if(el('pbvsBody')&&(PBVS.sub==='leads'||PBVS.sub==='cart')) render(); };
    try{
      fetch(w+'/vehicle-search/state?_='+Date.now(),{headers:_auth(),cache:'no-store'})
        .then(function(r){ return r.ok?r.json():null; })
        .then(function(st){
          if(st){
            var srvAt=+st.savedAt||(st.config&&+st.config.savedAt)||0;
            PBVS.watch=_unionBy(PBVS.watch, st.watch, function(x){return String(x.id);});
            PBVS.cart =_unionBy(PBVS.cart,  st.cart,  function(x){return ((x.name||'')+'|'+(x.vehicle||'')).toLowerCase();});
            _lsSet(LSK_WATCH,PBVS.watch); _lsSet(LSK_CART,PBVS.cart);
            if(!PBVS.savedAt || srvAt>PBVS.savedAt){
              if(Array.isArray(st.criteria)&&st.criteria.length){ PBVS.criteria=st.criteria; _lsSet(LSK_CRIT,PBVS.criteria); }
              var ui=st.config&&st.config.ui; if(ui&&typeof ui==='object'){ PBVS.config=ui; _lsSet(LSK_CFG,PBVS.config); }
            }
            if(srvAt>PBVS.savedAt){ PBVS.savedAt=srvAt; _lsSet(LSK_SAVED,srvAt); }
          }
        })
        .catch(function(){})
        .then(fin,fin);
    }catch(e){ fin(); }
  }

  // ===========================================================================
  //  SEED LEADS -- the real cars found in the 2026-08 nationwide sweep, so the
  //  tab is populated the instant it opens even before the daily worker feed is
  //  live. The worker feed (when deployed) REPLACES this with fresh data.
  // ===========================================================================
  var SEED_LEADS = [
    {id:'r8-2012-la', make:'Audi', model:'R8', year:2012, trim:'V10 Spyder', damage:'Front end', price:0, priceType:'bid', title:'Pending', miles:14836, milesActual:true, keys:true, runDrive:true, airbags:'intact', location:'Los Angeles, CA', state:'CA', pool:'IAAI', url:'https://iaai.com/VehicleDetail/46030498~US', saleDate:'future', verdict:'chase', note:'Airbags INTACT + Run&amp;Drive = below-deployment cosmetic front hit. Confirm title lands clean vs salvage. IAAI est-repair $55k is retail-inflated.'},
    {id:'r8-2021-me', make:'Audi', model:'R8', year:2021, trim:'V10', damage:'Left side', price:25250, priceType:'bid', title:'Salvage', miles:11942, milesActual:true, keys:true, location:'Gorham, ME', state:'ME', pool:'IAAI', url:'https://sca.auction/en/1066458044-2021-audi-r8', saleDate:'2026-08-10', verdict:'chase', note:'Newest, lowest-mile R8. Verify left side is door/quarter skin, NOT carbon sideblade/rocker.'},
    {id:'r8-2011-ar', make:'Audi', model:'R8', year:2011, trim:'V10 Spyder', damage:'Rear', price:0, priceType:'bid', title:'', miles:49367, milesActual:true, keys:true, location:'Fayetteville, AR', state:'AR', pool:'IAAI', url:'https://iaai.com/VehicleDetail/46192122~US', saleDate:'future', verdict:'watch', note:'Rear hit, higher miles.'},
    {id:'r8-2011-ks', make:'Audi', model:'R8', year:2011, trim:'V10', damage:'Undercarriage', price:0, priceType:'bid', title:'', keys:true, location:'Kansas City, KS', state:'KS', pool:'IAAI', url:'https://iaai.com/VehicleDetail/46298420~US', saleDate:'future', verdict:'caution', note:'Undercarriage -- inspect closely for structural.'},
    {id:'r8-2015-tx', make:'Audi', model:'R8', year:2015, trim:'4.2 V8', damage:'Rear', price:0, priceType:'bid', title:'', miles:68386, milesActual:true, keys:true, runDrive:true, location:'Houston, TX', state:'TX', pool:'IAAI', url:'https://iaai.com/VehicleDetail/45468981~US', saleDate:'future', verdict:'maybe', note:'V8 not V10; runs &amp; drives; local.'},

    {id:'mc-570s-phx16', make:'McLaren', model:'570S', year:2016, damage:'Right side + front + rear', price:42250, priceType:'bid', title:'Salvage', location:'Phoenix, AZ', state:'AZ', pool:'IAAI', url:'https://sca.auction/en/1013455461-2016-mclaren-570s', saleDate:'2026-08-10', verdict:'caution', note:'Multi-area damage = heavy; airbags likely deployed.'},
    {id:'mc-570s-phx17', make:'McLaren', model:'570S', year:2017, damage:'Suspension', location:'Phoenix, AZ', state:'AZ', pool:'IAAI', url:'https://sca.auction/en/1082459838-2017-mclaren-570s', saleDate:'future', verdict:'watch', note:'Suspension-only could be light / cheap.'},
    {id:'mc-570s-hou', make:'McLaren', model:'570S', year:2017, damage:'Rear + left side', location:'Houston, TX', state:'TX', pool:'IAAI', url:'https://sca.auction/en/1031555733-2017-mclaren-570s', saleDate:'future', verdict:'watch', note:'Local (Houston).'},
    {id:'mc-570s-noho', make:'McLaren', model:'570S', year:2020, damage:'Unknown', miles:20681, milesActual:true, location:'North Hollywood, CA', state:'CA', pool:'IAAI', url:'https://sca.auction/en/1045457643-2020-mclaren-570s', saleDate:'future', verdict:'watch', note:'Newer 570S; pull the condition report.'},
    {id:'mc-gt-hou', make:'McLaren', model:'GT', year:2022, damage:'Left front', miles:9517, milesActual:true, location:'Houston, TX', state:'TX', pool:'IAAI', url:'https://sca.auction/en/1057457448-2022-mclaren-gt', saleDate:'future', verdict:'maybe', note:'Local, low miles; GT is a softer tourer.'},

    {id:'fer-calT-hou', make:'Ferrari', model:'California T', year:2017, damage:'Side + front', price:19700, priceType:'bid', title:'Salvage', miles:20012, milesActual:true, keys:true, runDrive:true, location:'Houston, TX', state:'TX', pool:'Copart', url:'https://www.salvagereseller.com/cars-for-sale/51468406-2017-ferrari-california-t-houston-tx', saleDate:'2026-08-06', verdict:'caution', note:'Local, low miles, runs. Damage is side AND front; airbag status not disclosed. Sale imminent -- broker + PPI must already be lined up.'},
    {id:'fer-cal-ny13', make:'Ferrari', model:'California', year:2013, damage:'Right rear', miles:22944, milesActual:true, location:'Medford, NY', state:'NY', pool:'IAAI', url:'https://sca.auction/en/1088556216-2013-ferrari-california', saleDate:'future', verdict:'good', note:'Rear = buy-zone; low miles.'},
    {id:'fer-cal-ny11', make:'Ferrari', model:'California', year:2011, damage:'Front', miles:27491, milesActual:true, location:'Medford, NY', state:'NY', pool:'IAAI', url:'https://sca.auction/en/1019554948-2011-ferrari-california', saleDate:'future', verdict:'good', note:'Front hit; low miles.'},
    {id:'fer-cal-hou12', make:'Ferrari', model:'California', year:2012, damage:'Front / repo', miles:44132, milesActual:true, location:'Houston, TX', state:'TX', pool:'IAAI', url:'https://sca.auction/en/1044657048-2012-ferrari-california', saleDate:'future', verdict:'maybe', note:'Local; repossession.'},

    {id:'p-cs-mi', make:'Porsche', model:'911 Carrera S', year:2012, damage:'Front end', price:48500, priceType:'buynow', title:'Clean', miles:0, milesActual:false, keys:true, location:'Woodhaven, MI', state:'MI', pool:'Copart', url:'https://www.salvagereseller.com/cars-for-sale/57423956', saleDate:'2026-08-07', verdict:'chase', note:'CLEAN title + front-end = doctrine pick (full insurability, no rebuilt tax). Bid ~$39k rather than BIN $48.5k. Confirm 0-mi/not-actual is just intake-blank.'},
    {id:'p-turbo-fl', make:'Porsche', model:'911 Turbo', year:2014, damage:'Front end', price:42250, priceType:'bid', title:'Salvage', miles:62844, milesActual:true, keys:true, location:'Orlando, FL', state:'FL', pool:'Copart', url:'https://www.salvagereseller.com/cars-for-sale/52337276', saleDate:'2026-08-06', verdict:'watch', note:'Turbo rents well; salvage + 63k mi carry the rebuilt tax.'},
    {id:'p-carrera-ca', make:'Porsche', model:'911 Carrera', year:2020, damage:'Front end', price:10100, priceType:'bid', title:'Salvage', miles:32793, milesActual:true, keys:true, location:'Colton, CA', state:'CA', pool:'Copart', url:'https://www.salvagereseller.com/cars-for-sale/58692346', saleDate:'2026-08-10', verdict:'watch', note:'Cheap now (bid climbs); base trim, salvage.'},
    {id:'p-carrera-ut', make:'Porsche', model:'911 Carrera', year:2017, damage:'Front end', price:51000, priceType:'buynow', title:'Clean', miles:45591, milesActual:true, keys:true, location:'Magna, UT', state:'UT', pool:'Copart', url:'https://www.salvagereseller.com/cars-for-sale/49285266', saleDate:'2026-08-07', verdict:'maybe', note:'Clean + actual miles; base trim, steep BIN.'}
  ];

  var VERDICT = {
    chase:  {t:'CHASE',   c:'#22c55e', bg:'rgba(34,197,94,.13)',  b:'rgba(34,197,94,.4)'},
    good:   {t:'GOOD',    c:'#4ade80', bg:'rgba(74,222,128,.12)', b:'rgba(74,222,128,.35)'},
    watch:  {t:'WATCH',   c:'#c9a962', bg:'rgba(201,169,98,.13)', b:'rgba(201,169,98,.4)'},
    caution:{t:'CAUTION', c:'#f59e0b', bg:'rgba(245,158,11,.13)', b:'rgba(245,158,11,.4)'},
    maybe:  {t:'MAYBE',   c:'#9aa3ae', bg:'rgba(154,163,174,.12)',b:'rgba(154,163,174,.3)'},
    pass:   {t:'PASS',    c:'#ef4444', bg:'rgba(239,68,68,.12)',  b:'rgba(239,68,68,.35)'}
  };
  var VRANK = {chase:0,good:1,watch:2,caution:3,maybe:4,pass:5};

  // ---- one-time CSS ----------------------------------------------------------
  function injectCSS(){
    if(el('pbvs-style')) return;
    var s=document.createElement('style'); s.id='pbvs-style';
    s.textContent = [
      '.pbvs-subnav{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;border-bottom:1px solid var(--border);padding-bottom:12px}',
      '.pbvs-subbtn{padding:8px 14px;border-radius:9px;border:1px solid var(--border);background:none;color:var(--muted);font-weight:700;font-size:13px;cursor:pointer;transition:.14s}',
      '.pbvs-subbtn:hover{color:var(--text);background:rgba(255,255,255,.05)}',
      '.pbvs-subbtn.on{color:#fff;background:rgba(201,169,98,.18);border-color:rgba(201,169,98,.45)}',
      '.pbvs-card{border:1px solid var(--border);border-radius:14px;background:rgba(255,255,255,.02);padding:16px 18px;margin-bottom:14px}',
      '.pbvs-grid{display:grid;gap:12px}',
      '@media(min-width:820px){.pbvs-leadgrid{grid-template-columns:1fr 1fr}}',
      '.pbvs-lead{border:1px solid var(--border);border-radius:13px;background:rgba(255,255,255,.02);padding:14px 15px;position:relative;transition:.14s}',
      '.pbvs-lead:hover{border-color:rgba(201,169,98,.4);background:rgba(255,255,255,.035)}',
      '.pbvs-lead.pbvs-steal{border-color:#f0a020;box-shadow:0 0 0 1px #f0a020,0 0 22px rgba(240,160,32,.30);background:linear-gradient(180deg,rgba(240,160,32,.11),rgba(255,255,255,.02))}',
      '.pbvs-badge-steal{color:#111;background:linear-gradient(90deg,#f0b429,#ef4444);border:none;font-weight:800;letter-spacing:.04em;box-shadow:0 0 10px rgba(240,160,32,.5)}',
      '.pbvs-thumb{width:100%;max-height:150px;object-fit:cover;border-radius:9px;margin-bottom:9px;border:1px solid var(--border);background:#0c0e11}',
      '.pbvs-modal{display:none;position:fixed;inset:0;z-index:99999;background:rgba(0,0,0,.74);align-items:flex-start;justify-content:center;padding:22px 12px;overflow:auto}',
      '.pbvs-modbox{background:#14181d;border:1px solid #323e4a;border-radius:16px;max-width:780px;width:100%;box-shadow:0 24px 70px rgba(0,0,0,.6)}',
      '.pbvs-modinner{padding:18px 20px}',
      '.pbvs-modhead{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:6px}',
      '.pbvs-gallery{display:grid;grid-template-columns:repeat(auto-fill,minmax(108px,1fr));gap:8px;margin:8px 0}',
      '.pbvs-gallery img{width:100%;height:86px;object-fit:cover;border-radius:8px;border:1px solid var(--border);cursor:pointer;background:#0c0e11}',
      '.pbvs-preprow{display:flex;gap:10px;align-items:flex-start;justify-content:space-between;padding:9px 0;border-bottom:1px dashed var(--border)}',
      '.pbvs-check{flex:none;width:30px;height:30px;border-radius:6px;border:1.5px solid #323e4a;background:#0c0e11;color:#fff;cursor:pointer;font-weight:800;line-height:1;display:grid;place-items:center}',
      '.pbvs-check.on{background:#22c55e;border-color:#22c55e}',
      '.pbvs-heart{position:absolute;top:6px;right:6px;background:none;border:none;font-size:20px;cursor:pointer;line-height:1;color:#7a828c;width:40px;height:40px;display:grid;place-items:center;border-radius:9px;transition:.12s}',
      '.pbvs-heart.on{color:#ef4444;transform:scale(1.12)}',
      '.pbvs-title{font-weight:800;font-size:15px;color:#fff;padding-right:44px}',
      '.pbvs-badge{display:inline-block;font-size:10.5px;font-weight:800;letter-spacing:.03em;padding:2px 7px;border-radius:6px;vertical-align:middle}',
      '.pbvs-meta{font-size:12px;color:var(--muted);margin:7px 0}',
      '.pbvs-meta b{color:var(--text)}',
      '.pbvs-pill{display:inline-block;font-size:11px;padding:2px 7px;border-radius:6px;border:1px solid var(--border);color:var(--muted);margin:2px 5px 2px 0}',
      '.pbvs-note{font-size:12px;color:var(--muted);line-height:1.5;margin-top:6px;border-top:1px dashed var(--border);padding-top:7px}',
      '.pbvs-src{display:flex;flex-wrap:wrap;gap:7px;margin-top:9px}',
      '.pbvs-src a,.pbvs-srcbtn{font-size:11.5px;font-weight:700;padding:6px 10px;border-radius:8px;border:1px solid var(--border);color:var(--text);text-decoration:none;background:rgba(255,255,255,.03);cursor:pointer;white-space:nowrap}',
      '.pbvs-src a:hover,.pbvs-srcbtn:hover{border-color:rgba(201,169,98,.5);color:#fff}',
      '.pbvs-src a.gold{border-color:rgba(201,169,98,.45);color:#c9a962}',
      '.pbvs-chip{display:inline-block;font-size:12px;padding:6px 11px;margin:3px 6px 3px 0;border-radius:20px;border:1px solid var(--border);background:rgba(255,255,255,.03);color:var(--text);cursor:pointer}',
      '.pbvs-chip:hover{border-color:rgba(201,169,98,.5)}',
      '.pbvs-chip.on{background:rgba(201,169,98,.18);border-color:rgba(201,169,98,.5);color:#fff}',
      '.pbvs-row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}',
      '.pbvs-fld{display:flex;flex-direction:column;gap:4px}',
      '.pbvs-fld label{font-size:11px;color:var(--muted);font-weight:700}',
      '.pbvs-hint{font-size:11.5px;color:var(--muted);line-height:1.5}',
      '.pbvs-sec{font-size:12px;font-weight:800;letter-spacing:.04em;text-transform:uppercase;color:#c9a962;margin:2px 0 8px}',
      '.pbvs-brk{border:1px solid var(--border);border-radius:11px;padding:12px 14px;margin-bottom:10px;background:rgba(255,255,255,.02)}',
      '.pbvs-brk h5{margin:0 0 6px;font-size:13.5px;color:#fff;font-weight:800}',
      '.pbvs-brk .parts{font-size:12px;color:var(--muted);line-height:1.7}',
      '.pbvs-pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;line-height:1.6;color:var(--text);white-space:pre-wrap;background:rgba(0,0,0,.25);border:1px solid var(--border);border-radius:10px;padding:12px 14px;margin:0}',
      '.pbvs-copy{font-size:11px;font-weight:700;padding:6px 12px;border-radius:8px;border:1px solid var(--border);background:rgba(255,255,255,.03);color:var(--muted);cursor:pointer}',
      '.pbvs-copy:hover{border-color:rgba(201,169,98,.5);color:#c9a962}',
      '.pbvs-copy.done{border-color:#22c55e;color:#22c55e}',
      '.pbvs-empty{text-align:center;color:var(--muted);font-size:13px;padding:34px 10px}',
      '.pbvs-count{font-size:12px;color:var(--muted)}',
      '.pbvs-x{background:none;border:none;color:#ef4444;cursor:pointer;font-size:15px;padding:8px 10px;min-height:34px;border-radius:8px;line-height:1}',
      '.pbvs-hint,.pbvs-count,.pbvs-meta{color:#a7afba}',   /* brighter than --muted -> clears AA contrast */
      '.pbvs-subbtn:focus-visible,.pbvs-srcbtn:focus-visible,.pbvs-chip:focus-visible,.pbvs-heart:focus-visible,.pbvs-check:focus-visible,.pbvs-x:focus-visible,.pbvs-copy:focus-visible,.pbvs-src a:focus-visible{outline:2px solid #c9a962;outline-offset:2px}',
      '@media(max-width:768px){.pbvs-src a,.pbvs-srcbtn,.pbvs-chip{padding:9px 12px}.pbvs-x{min-width:40px;min-height:40px}.pbvs-check{width:34px;height:34px}}'
    ].join('\n');
    document.head.appendChild(s);
  }

  // ===========================================================================
  //  NHTSA vPIC -- real makes/models/years (free, CORS). Curated fallback.
  // ===========================================================================
  var CURATED_MAKES = ['Acura','Alfa Romeo','Aston Martin','Audi','Bentley','BMW','Cadillac','Chevrolet','Dodge','Ferrari','Ford','GMC','Honda','Jaguar','Jeep','Lamborghini','Land Rover','Lexus','Lotus','Maserati','Mazda','McLaren','Mercedes-Benz','Nissan','Polaris','Porsche','Rolls-Royce','Subaru','Tesla','Toyota','Volkswagen','Volvo'];
  function getMakes(cb){
    if(PBVS.nMakes){ cb(PBVS.nMakes); return; }
    var done=false, to=setTimeout(function(){ if(done)return; done=true; PBVS.nMakes=CURATED_MAKES.slice(); cb(PBVS.nMakes); },3500);
    try{
      fetch('https://vpic.nhtsa.dot.gov/api/vehicles/GetMakesForVehicleType/car?format=json')
        .then(function(r){ return r.json(); })
        .then(function(d){ if(done)return; done=true; clearTimeout(to);
          var arr=(d&&d.Results||[]).map(function(x){ return x.MakeName; }).filter(Boolean);
          arr=arr.map(function(m){ return m.replace(/\b\w/g,function(c){return c.toUpperCase();}); });
          // keep it usable: merge curated exotics to the front, de-dupe, sort
          var set={}; CURATED_MAKES.concat(arr).forEach(function(m){ set[m.toLowerCase()]=m; });
          PBVS.nMakes=Object.keys(set).map(function(k){return set[k];}).sort();
          cb(PBVS.nMakes);
        }).catch(function(){ if(done)return; done=true; clearTimeout(to); PBVS.nMakes=CURATED_MAKES.slice(); cb(PBVS.nMakes); });
    }catch(e){ if(done)return; done=true; clearTimeout(to); PBVS.nMakes=CURATED_MAKES.slice(); cb(PBVS.nMakes); }
  }
  function getModels(make,year,cb){
    var key=(make||'').toLowerCase()+'|'+(year||'');
    if(PBVS.nModels[key]){ cb(PBVS.nModels[key]); return; }
    if(!make||!year){ cb([]); return; }
    var done=false, to=setTimeout(function(){ if(done)return; done=true; cb([]); },3500);
    try{
      fetch('https://vpic.nhtsa.dot.gov/api/vehicles/GetModelsForMakeYear/make/'+q(make)+'/modelyear/'+q(year)+'?format=json')
        .then(function(r){ return r.json(); })
        .then(function(d){ if(done)return; done=true; clearTimeout(to);
          var arr=(d&&d.Results||[]).map(function(x){ return x.Model_Name; }).filter(Boolean);
          arr=arr.filter(function(v,i){ return arr.indexOf(v)===i; }).sort();
          PBVS.nModels[key]=arr; cb(arr);
        }).catch(function(){ if(done)return; done=true; clearTimeout(to); cb([]); });
    }catch(e){ if(done)return; done=true; clearTimeout(to); cb([]); }
  }

  // ---- VIN decode (NHTSA vPIC DecodeVinValues; CORS-friendly) ----------------
  function titleCase(s){ return String(s||'').toLowerCase().replace(/\b\w/g,function(c){return c.toUpperCase();}); }
  function decodeVin(vin,cb){
    vin=String(vin||'').trim().toUpperCase().replace(/[^A-Z0-9]/g,'');
    if(vin.length<11){ cb(null,'A VIN is 11-17 characters.'); return; }
    var done=false, to=setTimeout(function(){ if(done)return; done=true; cb({vin:vin},'Decode timed out -- you can still search this VIN for OEM parts.'); },5000);
    try{
      fetch('https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues/'+q(vin)+'?format=json')
        .then(function(r){ return r.json(); })
        .then(function(d){ if(done)return; done=true; clearTimeout(to);
          var r=(d&&d.Results&&d.Results[0])||{};
          var out={year:(r.ModelYear||''), make:(r.Make?titleCase(r.Make):''), model:(r.Model||''), vin:vin};
          if(!out.make) cb(out,'VIN not recognized -- you can still search it for OEM parts.');
          else cb(out,'Decoded: '+[out.year,out.make,out.model].filter(Boolean).join(' '));
        }).catch(function(){ if(done)return; done=true; clearTimeout(to); cb({vin:vin},'Decode failed -- you can still search this VIN for OEM parts.'); });
    }catch(e){ if(done)return; done=true; clearTimeout(to); cb({vin:vin},'Decode failed.'); }
  }
  function doVinDecode(){
    var vEl=el('psVin'); var vin=vEl?vEl.value.trim().toUpperCase():''; var m=el('psVinMsg'); if(m) m.innerHTML='Decoding&#8230;';
    var p=el('psPart'); if(p) partsSel.part=p.value;   // preserve typed part across the re-render
    decodeVin(vin,function(out,note){
      if(out){ partsSel.year=out.year||partsSel.year; partsSel.make=out.make||partsSel.make; partsSel.model=out.model||partsSel.model; partsSel.vin=out.vin||vin; }
      renderParts();
      var m2=el('psVinMsg'); if(m2) m2.innerHTML=esc(note||'');
      if(out&&out.make) refreshPartsModels();
    });
  }

  // ===========================================================================
  //  DEEP-LINK BUILDERS  (always-current, never scraped)
  // ===========================================================================
  function sources(v, part){
    var veh=vehStr(v), kw=(veh+' '+(part||'')).trim(), euro=/audi|bmw|mercedes|porsche|ferrari|lamborghini|mclaren|bentley|rolls|maserati|aston|jaguar|land rover|volkswagen|volvo|alfa/i.test(v.make||'');
    var isPart=looksLikePart(part), out=[];
    // used/new ONLY (condition 1000|3000 excludes "for parts / not working" 7000), sorted cheapest-first (_sop=15)
    out.push({label:'eBay &middot; used/new, cheapest', gold:true, url:'https://www.ebay.com/sch/i.html?_nkw='+q(kw)+'&_sacat=6028&LH_ItemCondition=1000%7C3000&_sop=15'});
    if(isPart) out.push({label:'eBay by Part #', gold:true, url:'https://www.ebay.com/sch/i.html?_nkw='+q(part)});
    out.push({label:'Amazon', url:'https://www.amazon.com/s?k='+q(kw)+'&i=automotive'});
    out.push({label:'Google Shopping', url:'https://www.google.com/search?tbm=shop&q='+q(kw)});
    if(isPart) out.push({label:'RockAuto by Part #', gold:true, url:'https://www.rockauto.com/en/partsearch/?partnum='+q(part)});
    out.push({label:'RockAuto catalog', url:'https://www.rockauto.com/en/catalog/'+q(v.make)+','+q(v.year)+','+q(v.model)});
    if(euro) out.push({label:'FCP Euro', url:'https://www.fcpeuro.com/search?q='+q(kw)});
    // Junkyards + phone numbers (nationwide): Car-Part.com is THE tool.
    out.push({label:'&#9742; Car-Part.com (yards + phones)', gold:true, url:'https://www.google.com/search?q='+q('site:car-part.com '+kw)});
    out.push({label:'Parts stores', gold:true, url:'https://www.google.com/search?q='+q(kw+' (site:rockauto.com OR site:autozone.com OR site:oreillyauto.com OR site:napaonline.com OR site:advanceautoparts.com OR site:partsgeek.com OR site:summitracing.com OR site:1aauto.com)')});
    out.push({label:'Junkyards', gold:true, url:'https://www.google.com/search?q='+q(kw+' (site:car-part.com OR site:row52.com OR site:lkqonline.com OR site:pullapart.com)')});
    out.push({label:'LKQ Online', url:'https://www.lkqonline.com/search?q='+q(kw)});
    // OEM diagrams / exact part numbers by VIN:
    if(v.vin) out.push({label:'OEM by VIN (Partsouq)', gold:true, url:'https://partsouq.com/en/search/all?q='+q(v.vin)});
    else out.push({label:'OEM diagrams (Partsouq)', url:'https://partsouq.com/en/search/all?q='+q(kw)});
    out.push({label:'Yards near me (Maps)', url:'https://www.google.com/maps/search/'+q((euro?'exotic ':'')+'auto salvage '+(v.make||'')+' parts')});
    if(isPart) out.push({label:'Identify Part #', url:'https://www.google.com/search?q='+q(part+' '+(v.make||'')+' part number cross reference')});
    return out;
  }
  // per-target live salvage searches (used on Current Leads + criteria rows)
  function liveSearches(c){
    var mk=(c.make||''), md=(c.model||'');
    return [
      {label:'Copart pool', url:'https://www.salvagereseller.com/cars-for-sale/make/'+q(mk.toUpperCase())+'/model/'+q(md.toUpperCase())},
      {label:'IAAI', url:'https://www.iaai.com/Vehiclelisting/'+q(mk.toLowerCase())+'/'+q(md.toLowerCase().replace(/\s+/g,''))},
      {label:'SCA', url:'https://sca.auction/en/search/type-cars/make-'+q(mk.toLowerCase())+'/model-'+q(md.toLowerCase().replace(/\s+/g,'-'))},
      {label:'bid.cars', url:'https://bid.cars/en/automobile/'+q(mk.toLowerCase())+'/'+q(md.toLowerCase().replace(/\s+/g,'-'))},
      {label:'Whole web', url:'https://www.google.com/search?q='+q(mk+' '+md+' for sale (salvage OR rebuildable OR wrecked OR project OR cash)')},
      {label:'FB Marketplace', url:'https://www.facebook.com/marketplace/search/?query='+q(mk+' '+md)},
      {label:'Cars &amp; Bids', url:'https://www.google.com/search?q='+q('site:carsandbids.com '+mk+' '+md)}
    ];
  }

  // ===========================================================================
  //  RENDER -- shell + sub-tab dispatch
  // ===========================================================================
  function render(){
    injectCSS();
    var host=el('vehSearchContent'); if(!host) return;
    var s=PBVS.sub; PBVS._inWatch=false;
    var _dlB = PBVS._deepLink ? '<div class="pbvs-card" style="border-color:#c9a962;background:rgba(201,169,98,.13);display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px"><div style="font-weight:800;color:#fff">&#128276; From your alert &mdash; your listing is ready</div><div style="display:flex;gap:8px"><a class="pbvs-srcbtn" style="border-color:#c9a962;color:#c9a962;font-weight:700" href="'+esc(PBVS._deepLink)+'" target="_blank" rel="noopener">Open listing &#8599;</a><button class="pbvs-srcbtn" data-act="dldismiss">Dismiss</button></div></div>' : '';
    host.innerHTML = _dlB +
      '<div class="pbvs-subnav">'+
        subBtn('leads','&#128293; Current Leads')+
        subBtn('find','&#128269; Vehicle Search')+
        subBtn('parts','&#128736; Parts Search')+
        subBtn('kit','&#128203; Outreach &amp; Watch-list Kit')+
        subBtn('cart','&#128722; Parts Cart'+(_cartN()?' ('+_cartN()+')':''))+
        '<div style="flex:1"></div>'+
        '<button class="pbvs-subbtn" data-act="watchview" title="Your saved vehicles">&#10084; Watchlist ('+PBVS.watch.length+')</button>'+
      '</div>'+
      '<div id="pbvsBody"></div>';
    if(s==='parts') renderParts();
    else if(s==='find') renderFind();
    else if(s==='kit') renderKit();
    else if(s==='cart') renderCart();
    else renderLeads();
    wire(host);
  }
  function subBtn(k,label){ return '<button class="pbvs-subbtn'+(PBVS.sub===k?' on':'')+'" data-act="sub" data-k="'+k+'">'+label+'</button>'; }

  // ---- Current Leads ---------------------------------------------------------
  function daysUntil(d){ if(!d||d==='future') return null; var t=Date.parse(d+'T12:00:00'); if(isNaN(t)) return null; return Math.round((t-Date.now())/86400000); }
  function actionDays(){ var n=+cfg().snipeDays; return (n>0)?n:3; }   // the "Actionable" window follows the owner's Selling-soon setting
  function isActionable(l){ if(l.steal) return true; var pt=(l.priceType||''); if(pt==='buynow'||pt==='bin'||pt==='cash') return true; var du=daysUntil(l.saleDate); if(du===null) return true; /* not-yet-scheduled: keep */ var win=actionDays(); return du<=win && du>=-1; }
  // owner Hunt-Settings filters applied to the displayed leads (instant; also synced to the sniper)
  function _passCfg(l,C){
    if(C.yearMin && l.year && l.year < +C.yearMin) return false;
    if(+C.maxPrice>0 && (l.buyNow||0) > +C.maxPrice) return false;
    if(+C.maxMiles>0 && l.miles>0 && l.miles > +C.maxMiles) return false;
    if(!l.gov && C.title && C.title!=='Any' && String(l.title||'').toLowerCase().indexOf(String(C.title).toLowerCase())<0) return false;
    if(!l.gov && C.excludeDamage){ var ex=String(C.excludeDamage).toLowerCase().split(/[\s,]+/).filter(Boolean); var d=String(l.damage||'').toLowerCase(); for(var i=0;i<ex.length;i++){ if(ex[i]&&d.indexOf(ex[i])>=0) return false; } }
    return true;
  }
  function activeFeed(){ return _dedup((PBVS.leads&&PBVS.leads.length)?PBVS.leads:SEED_LEADS); }
  // no double-feed: drop exact id repeats AND soft duplicates (same year+make+model+location/state)
  function _dedup(arr){ var byId={}, soft={}, out=[]; (arr||[]).forEach(function(l){ if(!l||!l.id||byId[l.id]) return;
    // soft key: VIN merges relists of the SAME car; otherwise include damage so two distinct
    // same-city same-model cars aren't wrongly collapsed into one (sku-based key never merged relists)
    var k=(l.vin?('vin:'+String(l.vin)):((l.year||'')+'|'+(l.make||'')+'|'+(l.model||'')+'|'+(l.damage||'')+'|'+(l.location||l.state||''))).toLowerCase();
    if(soft[k]) return; byId[l.id]=1; soft[k]=1; out.push(l); }); return out; }
  function watchHas(id){ return PBVS.watch.some(function(w){ return w.id===id; }); }

  function renderLeads(){
    var body=el('pbvsBody'); if(!body) return;
    var feed=activeFeed().filter(function(l){ return l.verdict!=='pass'; });
    var makes=uniq(feed.map(function(l){return l.make;}));
    var models=uniq(feed.filter(function(l){return !PBVS.fMake||l.make===PBVS.fMake;}).map(function(l){return l.model;}));
    var years=uniq(feed.map(function(l){return String(l.year);})).sort().reverse();
    var _C=cfg(), showAll=!!PBVS.showEverything, win=actionDays();
    // the make/model/year dropdowns only NARROW the shown list; they do not change what's hunted
    var _mmy=feed.filter(function(l){
      if(PBVS.fMake&&l.make!==PBVS.fMake)return false;
      if(PBVS.fModel&&l.model!==PBVS.fModel)return false;
      if(PBVS.fYear&&String(l.year)!==PBVS.fYear)return false;
      return true; });
    // apply hunt caps + the date filter, counting WHY each lead is hidden (honest split)
    var capHidden=0, dateHidden=0;
    var shown=_mmy.filter(function(l){
      if(!showAll && !_passCfg(l,_C)){ capHidden++; return false; }
      if(!showAll && PBVS.actionable && !isActionable(l)){ dateHidden++; return false; }
      return true;
    }).sort(function(a,b){ if(!!b.steal!==!!a.steal) return b.steal?1:-1; var r=(VRANK[a.verdict]||9)-(VRANK[b.verdict]||9); if(r) return r; var da=daysUntil(a.saleDate), db=daysUntil(b.saleDate); da=(da===null?999:da); db=(db===null?999:db); return da-db; });

    var _fa=_feedAgeNote();
    var h='';
    // header: feed status + the controls that change WHAT'S HUNTED (real config lives in the Kit)
    h+='<div class="pbvs-card" style="display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between">'+
        '<div><div style="font-weight:800;color:#fff;font-size:15px">&#128293; Nationwide leads</div>'+
        '<div class="pbvs-count" style="color:'+_fa.c+'">'+_fa.t+'</div></div>'+
        '<div style="display:flex;gap:8px;flex-wrap:wrap">'+
          '<button class="pbvs-srcbtn" data-act="sub" data-k="kit" title="Add/remove which exotics are hunted + set mileage / title / damage caps">&#9881; Edit what\'s hunted</button>'+
          '<button class="pbvs-srcbtn" data-act="refresh">&#8635; Refresh feed</button>'+
        '</div>'+
      '</div>';

    // active hunt-cap chips (removable) -- never a mystery why a lead is missing
    var caps=_capChips(_C);
    if(caps.length){
      h+='<div class="pbvs-card" style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:11px 14px">'+
          '<span class="pbvs-hint" style="font-weight:700;color:#c9a962">Hunting with caps:</span>'+
          caps.map(function(c){ return '<button class="pbvs-chip on" data-act="clearcap" data-k="'+c.k+'" title="Remove this cap" aria-label="Remove cap '+esc(c.t.replace(/&[a-z#0-9]+;/g,''))+'">'+c.t+' &#10006;</button>'; }).join('')+
          '<span class="pbvs-hint">tap a cap to remove it &middot; <button class="pbvs-srcbtn" data-act="sub" data-k="kit" style="padding:3px 9px">edit all</button></span>'+
        '</div>';
    }

    // date-filter toggle + ALWAYS-VISIBLE explanation (no more hover-only tooltip)
    h+='<div class="pbvs-card" style="padding:11px 14px">'+
        '<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">'+
          '<button class="pbvs-chip'+(PBVS.actionable?' on':'')+'" data-act="toggleact" aria-pressed="'+(PBVS.actionable?'true':'false')+'">'+(PBVS.actionable?'&#9989; ':'')+'Actionable only (&#8804;'+win+' day'+(win===1?'':'s')+' or Buy-Now)</button>'+
          (showAll?'<span class="pbvs-hint" style="color:#f0a020">Showing everything &mdash; filters bypassed. <button class="pbvs-srcbtn" data-act="reapply" style="padding:3px 9px">Re-apply filters</button></span>':'')+
        '</div>'+
        '<div class="pbvs-hint" style="margin-top:5px">'+(PBVS.actionable
          ? 'Showing only Buy-Now lots and auctions selling within <b>'+win+' day'+(win===1?'':'s')+'</b> (plus not-yet-scheduled cars). Change the window under &#9881; Edit what\'s hunted &rarr; "Selling-soon within".'
          : 'Showing all sale timings. Turn on to focus on cars you can act on within your <b>'+win+'-day</b> window.')+'</div>'+
      '</div>';

    // ALWAYS-ON stats strip with an HONEST split of what is hidden and why
    function _sc(n,label,color){ return '<span class="pbvs-pill" style="font-weight:700;color:'+color+'"><b style="font-size:14px">'+n+'</b> '+label+'</span>'; }
    var _steal=shown.filter(function(l){return l.steal;}).length;
    var _clean=shown.filter(function(l){return /clean/i.test(l.title||'');}).length;
    var _salv =shown.filter(function(l){return /salvage|rebuilt|junk|non/i.test(l.title||'');}).length;
    var _unk  =shown.filter(function(l){return !l.title && !l.gov;}).length;
    var _bnow =shown.filter(function(l){return l.priceType==='buynow'||l.priceType==='bin';}).length;
    var _chase=shown.filter(function(l){return l.verdict==='chase'||l.verdict==='good';}).length;
    var hiddenBits=[];
    if(dateHidden>0) hiddenBits.push(dateHidden+' by the '+win+'-day filter');
    if(capHidden>0) hiddenBits.push(capHidden+' by hunt caps');
    h+='<div class="pbvs-card" style="display:flex;flex-wrap:wrap;gap:8px;align-items:center">'+
        (_steal>0?_sc(_steal,'&#128293; STEALS','#f0a020'):'')+_sc(shown.length,'shown','#c9a962')+_sc(_clean,'clean title','#22c55e')+_sc(_salv,'salvage/rebuilt','#f59e0b')+_sc(_unk,'title: verify','#ef4444')+_sc(_bnow,'buy-now','#c9a962')+_sc(_chase,'chase-rated','#22c55e')+
        (hiddenBits.length?'<span class="pbvs-hint" style="margin-left:auto">'+(capHidden+dateHidden)+' hidden ('+hiddenBits.join(', ')+') &middot; <button class="pbvs-srcbtn" data-act="showeverything" style="padding:3px 9px">Show everything</button></span>':'')+
      '</div>';

    // narrowing filters -- labeled so it's clear these FILTER results (they don't change what's hunted)
    h+='<div class="pbvs-card"><div class="pbvs-hint" style="margin-bottom:7px;font-weight:700">Filter these results</div><div class="pbvs-row">'+
        fldSel('Make', 'fMake', [''].concat(makes))+
        fldSel('Model','fModel',[''].concat(models))+
        fldSel('Year', 'fYear', [''].concat(years))+
        '<button class="pbvs-srcbtn" data-act="clearfilter">Clear</button>'+
      '</div></div>';

    if(!shown.length){
      var why=[];
      if(dateHidden>0) why.push('the '+win+'-day "Actionable only" filter');
      if(capHidden>0){ why.push('your hunt caps ('+caps.map(function(c){return c.t;}).join(', ')+')'); }
      h+='<div class="pbvs-empty">No leads match'+(why.length?(' &mdash; hidden by '+why.join(' and ')):'')+'.<br><button class="pbvs-srcbtn" data-act="showeverything" style="margin-top:10px">Show everything (ignore filters + caps)</button></div>';
    } else {
      h+='<div class="pbvs-grid pbvs-leadgrid">'+shown.map(leadCard).join('')+'</div>';
    }
    body.innerHTML=h;
    syncSelects();
  }
  // describe the active (non-empty) hunt caps as removable chips
  function _capChips(C){
    var chips=[];
    if(+C.yearMin>0) chips.push({k:'yearMin',t:'Year &#8805; '+(+C.yearMin)});
    if(+C.maxPrice>0) chips.push({k:'maxPrice',t:'Buy-now &#8804; $'+Number(C.maxPrice).toLocaleString('en-US')});
    if(+C.maxMiles>0) chips.push({k:'maxMiles',t:'Miles &#8804; '+Number(C.maxMiles).toLocaleString('en-US')});
    if(C.title&&C.title!=='Any') chips.push({k:'title',t:'Title: '+esc(String(C.title))});
    if(C.excludeDamage) chips.push({k:'excludeDamage',t:'Excl: '+esc(String(C.excludeDamage))});
    return chips;
  }

  function leadCard(l){
    var vd=VERDICT[l.verdict]||VERDICT.watch, du=daysUntil(l.saleDate);
    var when = (l.priceType==='buynow'||l.priceType==='bin') ? 'Buy-Now available'
             : (du===null ? 'Not yet scheduled' : (du<0?'sale passed':(du===0?'sells TODAY':'sells in '+du+' day'+(du===1?'':'s'))));
    // live bids are JS-hydrated on the auction site (not in the scraped HTML), so for a bid-only
    // lot we point to the listing rather than claim "no bid yet" (which wrongly implies $0).
    var price = (Number(l.buyNow)>0) ? ('$'+Number(l.buyNow).toLocaleString('en-US')+' buy-now')
              : (Number(l.bid)>0) ? ('$'+Number(l.bid).toLocaleString('en-US')+' bid')
              : (Number(l.price)>0 && l.priceType!=='bid') ? ('$'+Number(l.price).toLocaleString('en-US')+' buy-now')
              : 'live bid &mdash; open listing';
    var facts=[];
    if(l.gov){
      facts.push('<span class="pbvs-pill" style="font-weight:700;border-color:rgba(96,165,250,.55);color:#60a5fa">&#127963; GOV FLEET</span>');
    } else {
      // ALWAYS show title status (color-coded): green=clean, amber=salvage/rebuilt, red=unknown/verify
      var _tc = /clean/i.test(l.title||'') ? 'border-color:rgba(34,197,94,.45);color:#22c55e'
              : (l.title ? 'border-color:rgba(245,158,11,.5);color:#f59e0b'
              : 'border-color:rgba(239,68,68,.5);color:#ef4444');
      facts.push('<span class="pbvs-pill" style="font-weight:700;'+_tc+'">'+(l.title?esc(l.title)+' title':'title: verify')+'</span>');
    }
    if(l.miles!=null) facts.push('<span class="pbvs-pill">'+Number(l.miles).toLocaleString('en-US')+' mi'+(l.milesActual===false?' (not actual)':'')+'</span>');
    if(l.keys) facts.push('<span class="pbvs-pill">keys</span>');
    if(l.runDrive) facts.push('<span class="pbvs-pill">run &amp; drive</span>');
    if(l.airbags==='intact') facts.push('<span class="pbvs-pill" style="border-color:rgba(34,197,94,.4);color:#22c55e">airbags intact</span>');
    facts.push('<span class="pbvs-pill">'+esc(l.pool)+'</span>');
    var _stealB = l.steal ? '<span class="pbvs-badge pbvs-badge-steal">&#128293; STEAL</span> ' : '';
    return '<div class="pbvs-lead'+(l.steal?' pbvs-steal':'')+'">'+
      '<button class="pbvs-heart'+(watchHas(l.id)?' on':'')+'" data-act="heart" data-id="'+esc(l.id)+'" title="Save to watchlist + get alerts" aria-label="'+(watchHas(l.id)?'Remove ':'Save ')+esc(vehStr(l))+' to watchlist" aria-pressed="'+(watchHas(l.id)?'true':'false')+'">'+(watchHas(l.id)?'&#10084;':'&#9825;')+'</button>'+
      (l.image?'<img class="pbvs-thumb" src="'+esc(l.image)+'" alt="'+esc(vehStr(l))+' listing photo" loading="lazy" onerror="this.style.display=\'none\'">':'')+
      '<div class="pbvs-title">'+_stealB+esc(vehStr(l))+' <span class="pbvs-badge" style="color:'+vd.c+';background:'+vd.bg+';border:1px solid '+vd.b+'">'+vd.t+'</span></div>'+
      '<div class="pbvs-meta"><b>'+esc(l.damage)+'</b> &middot; '+esc(l.location)+' &middot; <b>'+price+'</b> &middot; '+when+'</div>'+
      '<div>'+facts.join(' ')+'</div>'+
      (l.note?'<div class="pbvs-note">'+l.note+'</div>':'')+
      '<div class="pbvs-src"><a class="gold" href="'+esc(l.url)+'" target="_blank" rel="noopener">Open listing &#8599;</a>'+
        '<button class="pbvs-srcbtn" data-act="report" data-id="'+esc(l.id)+'">&#128736; Parts report</button>'+
        '<button class="pbvs-srcbtn" data-act="heart" data-id="'+esc(l.id)+'">'+(watchHas(l.id)?'&#10004; Watching':'&#10084; Watch')+'</button>'+
      '</div>'+
    '</div>';
  }

  // ---- Watchlist view --------------------------------------------------------
  function renderWatch(){
    var body=el('pbvsBody'); if(!body) return;
    var h='<div class="pbvs-card" style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">'+
      '<div><div style="font-weight:800;color:#fff;font-size:15px">&#10084; Watchlist</div>'+
      '<div class="pbvs-count">Hearted vehicles. Once the daily worker is live, changes (price, sale date, sold) alert you through your owner notifications.</div></div>'+
      '<button class="pbvs-srcbtn" data-act="backleads">&#8592; Back to leads</button></div>';
    if(!PBVS.watch.length){
      h+='<div class="pbvs-empty">Nothing saved yet. Tap the &#9825; heart on any lead to watch it.</div>';
    } else {
      h+='<div class="pbvs-grid pbvs-leadgrid">'+PBVS.watch.map(leadCard).join('')+'</div>';
    }
    body.innerHTML=h;
  }

  // ---- Parts Search ----------------------------------------------------------
  var partsSel = {year:'', make:'', model:'', trim:'', vin:''};
  function renderParts(){
    var body=el('pbvsBody'); if(!body) return;
    var fleet = fleetCars();
    var chips = fleet.map(function(f){
      var on = (partsSel.make===f.make && partsSel.model===f.model && String(partsSel.year)===String(f.year));
      return '<span class="pbvs-chip'+(on?' on':'')+'" data-act="fleetpick" data-k="'+esc(f.key)+'" role="button" tabindex="0" aria-pressed="'+(on?'true':'false')+'">'+esc(f.year+' '+f.make+' '+f.model)+'</span>';
    }).join('');
    var years=[]; var y0=(new Date().getFullYear())+1; for(var y=y0;y>=1990;y--) years.push(String(y));

    var h='';
    h+='<div class="pbvs-card">'+
        '<div class="pbvs-sec">1 &middot; Pick a fleet car</div>'+
        '<div>'+ (chips||'<span class="pbvs-hint">No fleet cars found.</span>') +'</div>'+
        '<div class="pbvs-sec" style="margin-top:14px">&#8230; or any real year / make / model</div>'+
        '<div class="pbvs-row">'+
          fldSelRaw('Year','psYear',years,partsSel.year)+
          fldSelRaw('Make','psMake',(PBVS.nMakes||CURATED_MAKES),partsSel.make)+
          fldSelRaw('Model','psModel',(partsSel._models||[]),partsSel.model)+
        '</div>'+
        '<div class="pbvs-sec" style="margin-top:14px">&#8230; or decode a VIN</div>'+
        '<div class="pbvs-row">'+
          '<div class="pbvs-fld" style="flex:1;min-width:240px"><label>17-digit VIN &mdash; auto-fills year/make/model + unlocks OEM-by-VIN</label>'+
            '<input id="psVin" class="finput" maxlength="17" placeholder="WUAVNAFG9CN000000" value="'+esc(partsSel.vin||'')+'" style="width:100%;box-sizing:border-box;text-transform:uppercase"></div>'+
          '<button class="pbvs-srcbtn" data-act="vindecode">Decode VIN</button>'+
        '</div>'+
        '<div class="pbvs-hint" id="psVinMsg" style="margin-top:6px"></div>'+
        '<div class="pbvs-hint" style="margin-top:8px" id="psVeh">'+(vehStr(partsSel)?('Selected: <b style="color:#fff">'+esc(vehStr(partsSel))+'</b>'+(partsSel.vin?' &middot; VIN '+esc(partsSel.vin):'')):'Pick a car above to enable exact-fit + OEM-by-VIN lookups.')+'</div>'+
      '</div>';

    h+='<div class="pbvs-card">'+
        '<div class="pbvs-sec">2 &middot; What part?</div>'+
        '<div class="pbvs-row">'+
          '<div class="pbvs-fld" style="flex:1;min-width:220px"><label>Part name or part number</label>'+
            '<input id="psPart" class="finput" placeholder="e.g. front bumper cover  -OR-  4S0807065" value="'+esc(partsSel.part||'')+'" style="width:100%;box-sizing:border-box"></div>'+
          '<button class="btn" data-act="partsgo" style="background:#c9a962;border-color:#c9a962;color:#111;font-weight:800">Search everywhere</button>'+
        '</div>'+
        '<div class="pbvs-hint" style="margin-top:7px">Opens the exact live search on each marketplace + junkyard network in a new tab. A recognized part number also fires RockAuto + eBay part-number lookups.</div>'+
        '<div id="psResults" style="margin-top:12px"></div>'+
      '</div>';

    h+=partBreakdownsHTML();
    h+=yardsHTML();
    body.innerHTML=h;
    // populate models for the current make/year if a make is set
    if(partsSel.make){ refreshPartsModels(); }
    getMakes(function(){ var sel=el('psMake'); if(sel){ fillSelect(sel,PBVS.nMakes,partsSel.make); } });
  }

  function partBreakdownsHTML(){
    var B=[
      {h:'Front-end collision kit', p:'Bumper cover &middot; energy absorber &middot; impact bar / rebar &middot; grille &middot; lower valance &middot; headlight assy (L/R) &middot; fog lights &middot; fender (L/R) &middot; hood &middot; radiator core support &middot; radiator &middot; A/C condenser &middot; intercooler (turbo) &middot; hood latch &middot; washer bottle'},
      {h:'Rear-end kit', p:'Bumper cover &middot; absorber &middot; rebar &middot; tail lights (L/R) &middot; decklid / trunk &middot; rear valance / diffuser &middot; exhaust tips &middot; reflectors &middot; park sensors'},
      {h:'Side / door', p:'Door shell or skin &middot; mirror assy &middot; side moulding &middot; rocker panel &middot; B-pillar trim &middot; window regulator &middot; glass. EXOTIC: R8 carbon side-blade / sills = structural, dealer-only -- a WALK.'},
      {h:'Suspension corner', p:'Upper + lower control arms &middot; steering knuckle / upright &middot; wheel hub + bearing &middot; tie-rod end &middot; ball joint &middot; coil/strut or air strut &middot; sway-bar link &middot; CV axle. Alignment after.'},
      {h:'Airbags / SRS (if deployed)', p:'Driver + passenger modules &middot; seatbelt pretensioners &middot; SRS control module (crash-locked -- often must be replaced or reset) &middot; clockspring &middot; knee + side-curtain bags. EXOTIC: dealer-tooled coding.'},
      {h:'Cooling / engine bay', p:'Radiator &middot; condenser &middot; intercooler &middot; fans &middot; coolant hoses &middot; expansion tank &middot; oil cooler. Common on R8 / McLaren front hits.'},
      {h:'Wheels / brakes', p:'Wheel (size + offset) &middot; TPMS sensor &middot; tire &middot; rotor + pads &middot; caliper. EXOTIC: carbon-ceramic rotors are $$$$ -- price them separately.'}
    ];
    var cards=B.map(function(b){ return '<div class="pbvs-brk"><h5>'+b.h+'</h5><div class="parts">'+b.p+'</div></div>'; }).join('');
    return '<div class="pbvs-card">'+
      '<div class="pbvs-sec">Part breakdowns &middot; what to order together</div>'+
      '<div class="pbvs-hint" style="margin-bottom:10px"><b style="color:#fff">Find a part number:</b> 1) decode the VIN in Partsouq/7zap &rarr; open the diagram &rarr; read the OEM number. 2) Read the casting/OEM sticker on the old part. 3) Cross-reference that number on eBay / RockAuto for aftermarket + price. 4) Use Car-Part.com interchange to see which other years share it.</div>'+
      cards+'</div>';
  }
  function yardsHTML(){
    return '<div class="pbvs-card">'+
      '<div class="pbvs-sec">&#9742; Scrap yards &amp; dismantlers &mdash; names + phone numbers</div>'+
      '<div class="pbvs-hint" style="margin-bottom:10px">These return <b style="color:#fff">actual yard names, phone numbers, prices and distances</b> for the exact car + part &mdash; nationwide. Pick a car and part above first for pre-filled results.</div>'+
      '<div class="pbvs-src">'+
        '<a class="gold" href="https://www.car-part.com/" target="_blank" rel="noopener">Car-Part.com (yard network) &#8599;</a>'+
        '<a href="https://www.lkqonline.com/" target="_blank" rel="noopener">LKQ Online &#8599;</a>'+
        '<a href="https://www.lkqpickyourpart.com/locations/" target="_blank" rel="noopener">LKQ Pick-Your-Part locations &#8599;</a>'+
        '<a href="https://www.pullapart.com/locations/" target="_blank" rel="noopener">Pull-A-Part &#8599;</a>'+
        '<a href="https://www.ebay.com/b/Wholesale-Lots-Parts/bn_7000259375" target="_blank" rel="noopener">eBay parts lots &#8599;</a>'+
        '<a class="gold" href="https://www.google.com/maps/search/exotic+auto+dismantler+salvage" target="_blank" rel="noopener">&#9742; Exotic dismantlers near you (Maps) &#8599;</a>'+
      '</div>'+
      '<div class="pbvs-hint" style="margin-top:10px">Tip: Car-Part.com is the wrecking-yard industry\'s own inventory network &mdash; searching a specific part + car there lists every member yard that has it, with a call button. That is your fastest path to a used OEM panel at 30-60% off dealer.</div>'+
    '</div>';
  }

  // ---- Outreach & Watch-list Kit --------------------------------------------
  function renderKit(){
    var body=el('pbvsBody'); if(!body) return;
    var lien='Hi -- I run Prestige Black, a licensed exotic rental fleet in DFW. Do you ever have customer cars abandoned mid-repair, or mechanic\'s / storage-lien vehicles you need to move? R8, 911, McLaren, Ferrari especially.\n\nI pay cash, handle my own transport, and I\'m easy to work with. Can I leave my number for when one comes through -- and check back monthly?';
    var owner='Hey -- saw the [year / model]. I run a licensed exotic rental fleet in Dallas and I buy repairable cars to rebuild properly. Cash-ready, I handle transport, no lowball games.\n\nQuick so I don\'t waste your time:\n- Clean or salvage title, and is it in hand?\n- Does it start / run? Keys?\n- Any airbags deployed or frame/structural damage?\n- A few photos (corners + engine bay + the damage)?\n\nIf it\'s the right car I can move fast this week. Thanks!';
    var auctions=[
      {n:'US Marshals (Bid4Assets)', d:'Seized/forfeited -- clean, running exotics. Nationwide.', u:'https://www.bid4assets.com/storefront/usms', when:'Rolling; last nationwide 08/04'},
      {n:'US Treasury (TEOAF)', d:'Seized cars + luxury items via CWS / Apple Auctioneering.', u:'https://www.treasury.gov/auctions/treasury/gp/', when:'Nationwide 08/11 &amp; 09/16'},
      {n:'GSA Auctions', d:'Federal LE seizures (DEA/FBI/Marshals).', u:'https://gsaauctions.gov', when:'Rolling'},
      {n:'Dallas Auto Pound', d:'LOCAL -- abandoned/impound via Lone Star Auctioneers.', u:'https://www.dallaspolice.net/divisions/Pages/Auto-Pound-Auction.aspx', when:'Every other Monday'},
      {n:'RepoFinder', d:'Bank/credit-union repos, priced to loan payoff -- usually clean title.', u:'https://www.repofinder.com/repo/type/car/', when:'Rolling'},
      {n:'PropertyRoom', d:'Police unclaimed/seized property.', u:'https://www.propertyroom.com/', when:'Rolling'}
    ];
    var brokers=[
      {n:'AutoBidMaster', u:'https://www.autobidmaster.com/'},
      {n:'CARS4.BID', u:'https://cars4.bid/'},
      {n:'Campo Brokers', u:'https://campobroker.com/en/'}
    ];
    var h='';
    h+='<div class="pbvs-card"><div class="pbvs-sec">Broker setup (do this first -- you have no dealer license)</div>'+
       '<div class="pbvs-hint">Copart pool = <b>salvagereseller</b> links; IAAI pool = <b>iaai / sca</b> links. One broker usually covers both.</div>'+
       '<div class="pbvs-src" style="margin-top:8px">'+brokers.map(function(b){return '<a href="'+b.u+'" target="_blank" rel="noopener">'+esc(b.n)+' &#8599;</a>';}).join('')+'</div></div>';

    h+='<div class="pbvs-card"><div class="pbvs-sec">Clean-title lane &mdash; auction date tracker</div>'+
       '<div class="pbvs-hint" style="margin-bottom:8px">Seized/repo cars are mostly <b style="color:#fff">clean-title, running exotics</b> &mdash; often a better fleet buy than a wreck. Check these on a routine.</div>'+
       auctions.map(function(a){ return '<div class="pbvs-brk"><h5>'+esc(a.n)+' <span class="pbvs-pill" style="color:#c9a962;border-color:rgba(201,169,98,.4)">'+a.when+'</span></h5><div class="parts">'+a.d+' &nbsp; <a href="'+a.u+'" target="_blank" rel="noopener" style="color:#c9a962">Open &#8599;</a></div></div>'; }).join('')+
       '</div>';

    h+='<div class="pbvs-card"><div class="pbvs-sec">Lien / shop call script</div>'+
       '<div style="display:flex;justify-content:flex-end;margin-bottom:6px"><button class="pbvs-copy" data-act="copy" data-t="k-lien">Copy</button></div>'+
       '<pre class="pbvs-pre" id="k-lien">'+esc(lien)+'</pre>'+
       '<div class="pbvs-hint" style="margin-top:8px">TX lets a shop foreclose after 31 days (mechanic\'s lien) / storage-lien via Form VTR-265-S. Ask DFW exotic collision shops for abandoned-repair cars &mdash; often clean-title, and nobody else is asking.</div></div>';

    h+='<div class="pbvs-card"><div class="pbvs-sec">Private-owner outreach (FB / forum / DM)</div>'+
       '<div style="display:flex;justify-content:flex-end;margin-bottom:6px"><button class="pbvs-copy" data-act="copy" data-t="k-owner">Copy</button></div>'+
       '<pre class="pbvs-pre" id="k-owner">'+esc(owner)+'</pre></div>';

    // criteria editor (what the daily hunt targets)
    var C=cfg();
    h+='<div class="pbvs-card"><div class="pbvs-sec">Hunt settings &mdash; filters on your leads + the sniper</div>'+
       '<div class="pbvs-row">'+
         '<div class="pbvs-fld"><label>Min year</label><input id="cfYearMin" class="finput" style="width:78px" value="'+esc(C.yearMin)+'"></div>'+
         '<div class="pbvs-fld"><label>Max price $</label><input id="cfMaxPrice" class="finput" style="width:100px" value="'+esc(C.maxPrice)+'" placeholder="any"></div>'+
         '<div class="pbvs-fld"><label>Max miles</label><input id="cfMaxMiles" class="finput" style="width:90px" value="'+esc(C.maxMiles||'')+'" placeholder="any"></div>'+
         '<div class="pbvs-fld"><label>Title</label><select id="cfTitle" class="finput">'+['Any','Clean','Salvage','Rebuilt'].map(function(o){return '<option'+(C.title===o?' selected':'')+'>'+o+'</option>';}).join('')+'</select></div>'+
         '<div class="pbvs-fld" style="flex:1;min-width:170px"><label>Exclude damage (comma list)</label><input id="cfExDmg" class="finput" style="width:100%;box-sizing:border-box" value="'+esc(C.excludeDamage||'')+'" placeholder="burn, flood, rollover"></div>'+
       '</div>'+
       '<div class="pbvs-row" style="margin-top:8px;align-items:center">'+
         '<div class="pbvs-fld"><label>Selling-soon within (days)</label><input id="cfSnipeDays" class="finput" style="width:66px" value="'+esc(C.snipeDays)+'"></div>'+
         '<span class="pbvs-chip'+(C.stealOn!==false?' on':'')+'" data-act="cfToggle" data-k="stealOn" role="button" tabindex="0" aria-pressed="'+(C.stealOn!==false?'true':'false')+'">&#128293; STEAL push</span>'+
         '<span class="pbvs-chip'+(C.snipeOn!==false?' on':'')+'" data-act="cfToggle" data-k="snipeOn" role="button" tabindex="0" aria-pressed="'+(C.snipeOn!==false?'true':'false')+'">&#9200; Selling-soon push</span>'+
         '<span class="pbvs-chip'+(C.heartOn!==false?' on':'')+'" data-act="cfToggle" data-k="heartOn" role="button" tabindex="0" aria-pressed="'+(C.heartOn!==false?'true':'false')+'">&#10084; Watchlist push</span>'+
         '<button class="pbvs-srcbtn" data-act="cfReset">Reset</button>'+
       '</div>'+
       '<div class="pbvs-hint" style="margin-top:6px">Applies to your leads instantly and syncs to the sniper so alerts match. Price caps only priced (buy-now) listings; bid-only lots still show.</div>'+
      '</div>';
    h+='<div class="pbvs-card"><div class="pbvs-sec">Daily hunt targets (makes / models / years being searched)</div>'+
       '<div class="pbvs-hint" style="margin-bottom:8px">These drive Current Leads. Add/remove any real make/model/year; each row gets one-click live searches across the pools.</div>'+
       '<div id="critList">'+PBVS.criteria.map(critRow).join('')+'</div>'+
       '<div class="pbvs-row" style="margin-top:10px;border-top:1px dashed var(--border);padding-top:12px">'+
         fldSelRaw('Make','ncMake',(PBVS.nMakes||CURATED_MAKES),'')+
         fldSelRaw('Model','ncModel',[],'')+
         '<div class="pbvs-fld"><label>Year min</label><input id="ncYmin" class="finput" style="width:90px" placeholder="2010"></div>'+
         '<div class="pbvs-fld"><label>Year max</label><input id="ncYmax" class="finput" style="width:90px" placeholder="2018"></div>'+
         '<button class="pbvs-srcbtn" data-act="addcrit">+ Add target</button>'+
       '</div></div>';
    body.innerHTML=h;
    getMakes(function(){ var sel=el('ncMake'); if(sel){ fillSelect(sel,PBVS.nMakes,''); } });
  }
  function critRow(c,i){
    var ls=liveSearches(c).map(function(s){ return '<a href="'+s.url+'" target="_blank" rel="noopener">'+esc(s.label)+' &#8599;</a>'; }).join('');
    return '<div class="pbvs-brk" style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;flex-wrap:wrap">'+
      '<div style="flex:1;min-width:200px"><h5>'+esc(c.make+' '+c.model)+' <span class="pbvs-pill">'+esc((c.yearMin||'?')+'-'+(c.yearMax||'?'))+'</span>'+(c.note?' <span class="pbvs-hint">'+esc(c.note)+'</span>':'')+'</h5>'+
      '<div class="pbvs-src">'+ls+'</div></div>'+
      '<button class="pbvs-x" data-act="delcrit" data-i="'+i+'" title="Remove">&#10006;</button></div>';
  }

  // ---- select / field helpers ------------------------------------------------
  function uniq(a){ var o={},r=[]; a.forEach(function(x){ if(x!=null&&x!==''&&!o[x]){o[x]=1;r.push(x);} }); return r; }
  function fldSel(label,id,opts){ return '<div class="pbvs-fld"><label>'+label+'</label><select id="'+id+'" class="finput" style="min-width:120px">'+opts.map(function(o){return '<option value="'+esc(o)+'">'+(o===''?'All':esc(o))+'</option>';}).join('')+'</select></div>'; }
  function fldSelRaw(label,id,opts,val){ return '<div class="pbvs-fld"><label>'+label+'</label><select id="'+id+'" class="finput" style="min-width:130px"><option value="">--</option>'+opts.map(function(o){return '<option value="'+esc(o)+'"'+(String(o)===String(val)?' selected':'')+'>'+esc(o)+'</option>';}).join('')+'</select></div>'; }
  function fillSelect(sel,opts,val){ if(!sel)return; sel.innerHTML='<option value="">--</option>'+opts.map(function(o){return '<option value="'+esc(o)+'"'+(String(o)===String(val)?' selected':'')+'>'+esc(o)+'</option>';}).join(''); }
  function syncSelects(){ ['fMake','fModel','fYear'].forEach(function(k){ var s=el(k); if(s) s.value=PBVS[k]||''; }); }

  function fleetCars(){
    try{
      if(typeof VEHICLE_INFO!=='object') return [];
      return Object.keys(VEHICLE_INFO).map(function(k){ var vi=VEHICLE_INFO[k]||{}; return {key:k, year:vi.year||'', make:vi.make||'', model:vi.model||'', vin:vi.vin||''}; })
        .filter(function(f){ return f.make&&f.model; });
    }catch(e){ return []; }
  }
  function refreshPartsModels(){
    getModels(partsSel.make, partsSel.year, function(arr){ partsSel._models=arr; var sel=el('psModel'); if(sel) fillSelect(sel,arr,partsSel.model); });
  }

  // ===========================================================================
  //  EVENTS  (delegated -- no global soup)
  // ===========================================================================
  function wire(host){
    if(host.__pbvsWired) return; host.__pbvsWired=true;
    host.addEventListener('click', function(e){
      var t=e.target.closest('[data-act]'); if(!t) return; var act=t.getAttribute('data-act');
      if(act==='sub'){ PBVS.sub=t.getAttribute('data-k'); _lsSet(LSK_SUB,PBVS.sub); render(); }
      else if(act==='watchview'){ PBVS._inWatch=true; ensureShell(); renderWatch(); }
      else if(act==='backleads'||act==='refresh'){ if(act==='refresh') forceRefresh(); PBVS.sub='leads'; _lsSet(LSK_SUB,'leads'); render(); }
      else if(act==='toggleact'){ PBVS.actionable=!PBVS.actionable; _lsSet(LSK_ACT,PBVS.actionable); renderLeads(); }
      else if(act==='showall'){ PBVS.actionable=false; _lsSet(LSK_ACT,false); renderLeads(); }
      else if(act==='showeverything'){ PBVS.showEverything=true; renderLeads(); }
      else if(act==='reapply'){ PBVS.showEverything=false; renderLeads(); }
      else if(act==='clearcap'){ var ck=t.getAttribute('data-k'); if(ck==='title') PBVS.config.title='Any'; else if(ck==='excludeDamage') PBVS.config.excludeDamage=''; else PBVS.config[ck]=0; saveConfig(); renderLeads(); }
      else if(act==='clearfilter'){ PBVS.fMake=PBVS.fModel=PBVS.fYear=''; PBVS.showEverything=false; renderLeads(); }
      else if(act==='heart'){ toggleHeart(t.getAttribute('data-id')); }
      else if(act==='fleetpick'){ pickFleet(t.getAttribute('data-k')); }
      else if(act==='vindecode'){ doVinDecode(); }
      else if(act==='partsgo'){ runPartsSearch(); }
      else if(act==='findgo'){ runFind(); }
      else if(act==='copy'){ doCopy(t); }
      else if(act==='addcrit'){ addCrit(); }
      else if(act==='delcrit'){ PBVS.criteria.splice(+t.getAttribute('data-i'),1); saveCrit(); renderKit(); }
      else if(act==='report'){ openReport(t.getAttribute('data-id')); }
      else if(act==='partcart'){ _addManualPartToCart(); }
      else if(act==='ordertoggle'){ var _c=PBVS.cart[+t.getAttribute('data-i')]; if(_c){ _c.status=(_c.status==='ordered')?'to-order':'ordered'; _c.orderedAt=(_c.status==='ordered')?Date.now():null; saveCart(); renderCart(); } }
      else if(act==='qtyinc'){ var _qi=PBVS.cart[+t.getAttribute('data-i')]; if(_qi){ _qi.qty=(+_qi.qty||1)+1; saveCart(); renderCart(); } }
      else if(act==='qtydec'){ var _qd=PBVS.cart[+t.getAttribute('data-i')]; if(_qd){ _qd.qty=Math.max(1,(+_qd.qty||1)-1); saveCart(); renderCart(); } }
      else if(act==='cartremove'){ var _ri=+t.getAttribute('data-i'), _rc=PBVS.cart[_ri]; if(_rc&&_rc.status==='ordered'&&!window.confirm('Remove this ordered item from your purchase log?')) return; PBVS.cart.splice(_ri,1); saveCart(); renderCart(); }
      else if(act==='clearordered'){ if(!window.confirm('Clear the entire ordered log? This permanently erases your purchase history and cannot be undone.')) return; PBVS.cart=PBVS.cart.filter(function(c){return c.status!=='ordered';}); saveCart(); renderCart(); }
      else if(act==='dldismiss'){ PBVS._deepLink=null; render(); }
      else if(act==='cfToggle'){ var _k=t.getAttribute('data-k'); PBVS.config[_k]=(cfg()[_k]===false); saveConfig(); renderKit(); }
      else if(act==='cfReset'){ PBVS.config={}; saveConfig(); renderKit(); }
    });
    host.addEventListener('keydown', function(e){
      if(e.key==='Enter'){
        if(e.target && e.target.id==='psPart'){ e.preventDefault(); runPartsSearch(); return; }
        if(e.target && e.target.id==='psVin'){ e.preventDefault(); doVinDecode(); return; }
      }
      // Enter / Space activates role=button chips (spans) just like a real button
      if(e.key==='Enter'||e.key===' '||e.key==='Spacebar'){
        var t=e.target; if(t && t.getAttribute && t.getAttribute('data-act') && /^(SPAN|LABEL|DIV)$/.test(t.tagName||'')){ e.preventDefault(); t.click(); }
      }
    });
    host.addEventListener('change', function(e){
      var id=e.target.id;
      if(id==='fMake'){ PBVS.fMake=e.target.value; PBVS.fModel=''; renderLeads(); }
      else if(id==='fModel'){ PBVS.fModel=e.target.value; renderLeads(); }
      else if(id==='fYear'){ PBVS.fYear=e.target.value; renderLeads(); }
      else if(id==='psYear'){ partsSel.year=e.target.value; partsSel.vin=''; refreshPartsModels(); updateVehLine(); }
      else if(id==='psMake'){ partsSel.make=e.target.value; partsSel.model=''; partsSel.vin=''; refreshPartsModels(); updateVehLine(); }
      else if(id==='psModel'){ partsSel.model=e.target.value; updateVehLine(); }
      else if(id==='ncMake'){ getModels(e.target.value, (el('ncYmin')&&el('ncYmin').value)||new Date().getFullYear(), function(arr){ var s=el('ncModel'); if(s) fillSelect(s,arr,''); }); }
      else if(id==='fdMake'){ findSel.make=e.target.value; findSel.model=''; getModels(findSel.make, findSel.yearMin||(new Date().getFullYear()), function(arr){ findSel._models=arr; var s=el('fdModel'); if(s) fillSelect(s,arr,''); }); renderFindDeepLinks(); }
      else if(id==='fdModel'){ findSel.model=e.target.value; renderFindDeepLinks(); }
      else if(id==='fdYmin'){ findSel.yearMin=e.target.value; if(findSel.make){ getModels(findSel.make, findSel.yearMin, function(arr){ findSel._models=arr; var s=el('fdModel'); if(s) fillSelect(s,arr,findSel.model); }); } renderFindDeepLinks(); }
      else if(id==='fdYmax'){ findSel.yearMax=e.target.value; renderFindDeepLinks(); }
      else if(id==='fdMax'){ findSel.maxPrice=e.target.value; renderFindDeepLinks(); }
      else if(id==='fdTitle'){ findSel.title=e.target.value; renderFindDeepLinks(); }
      else if(id==='fdState'){ findSel.state=e.target.value; renderFindDeepLinks(); }
      else if(id==='cfYearMin'){ PBVS.config.yearMin=e.target.value; saveConfig(); }
      else if(id==='cfMaxPrice'){ PBVS.config.maxPrice=e.target.value; saveConfig(); }
      else if(id==='cfMaxMiles'){ PBVS.config.maxMiles=e.target.value; saveConfig(); }
      else if(id==='cfTitle'){ PBVS.config.title=e.target.value; saveConfig(); }
      else if(id==='cfExDmg'){ PBVS.config.excludeDamage=e.target.value; saveConfig(); }
      else if(id==='cfSnipeDays'){ PBVS.config.snipeDays=e.target.value; saveConfig(); }
      else if(id.indexOf('cprice-')===0){ var _pi=+id.slice(7); if(PBVS.cart[_pi]){ PBVS.cart[_pi].price=e.target.value; saveCart(); } }
      else if(id.indexOf('cvendor-')===0){ var _vi=+id.slice(8); if(PBVS.cart[_vi]){ PBVS.cart[_vi].vendor=e.target.value; saveCart(); } }
    });
  }
  function ensureShell(){ if(!el('pbvsBody')) render(); }
  function updateVehLine(){ var n=el('psVeh'); if(n) n.innerHTML = vehStr(partsSel)?('Selected: <b style="color:#fff">'+esc(vehStr(partsSel))+'</b>'+(partsSel.vin?' &middot; VIN '+esc(partsSel.vin):'')):'Pick a car above to enable exact-fit + OEM-by-VIN lookups.'; }

  function pickFleet(key){
    var keepPart=(el('psPart')&&el('psPart').value)||partsSel.part||'';
    try{ var vi=VEHICLE_INFO[key]||{}; partsSel={year:vi.year||'',make:vi.make||'',model:vi.model||'',trim:'',vin:vi.vin||'',_models:partsSel._models,part:keepPart}; }catch(e){}
    renderParts();
  }
  function runPartsSearch(){
    var partEl=el('psPart'); var part=partEl?partEl.value.trim():''; partsSel.part=part;
    var vinEl=el('psVin'); if(vinEl && vinEl.value.trim()) partsSel.vin=vinEl.value.trim().toUpperCase().replace(/[^A-Z0-9]/g,'');
    var v={year:partsSel.year,make:partsSel.make,model:partsSel.model,trim:partsSel.trim,vin:partsSel.vin};
    if(!v.make && !part){ _toast('Pick a car or type a part first'); return; }
    var list=sources(v,part);
    var isPart=looksLikePart(part);
    var html='<div class="pbvs-hint" style="margin-bottom:8px">'+(v.make?('Searching <b style="color:#fff">'+esc(vehStr(v))+'</b>'):'Searching')+(part?(' for <b style="color:#fff">'+esc(part)+'</b>'+(isPart?' <span class="pbvs-pill" style="color:#c9a962;border-color:rgba(201,169,98,.4)">part # detected</span>':'')):'')+' &mdash; open any:</div>'+
      '<div class="pbvs-src">'+list.map(function(s){ return '<a class="'+(s.gold?'gold':'')+'" href="'+s.url+'" target="_blank" rel="noopener">'+s.label+' &#8599;</a>'; }).join('')+'</div>';
    if(part) html+='<div style="margin-top:10px"><button class="pbvs-srcbtn" data-act="partcart">&#128722; Add \''+esc(part)+'\' to Parts Cart</button></div>';
    var r=el('psResults'); if(r) r.innerHTML=html;
  }

  function toggleHeart(id){
    var i=-1; PBVS.watch.forEach(function(w,ix){ if(w.id===id) i=ix; });
    if(i>=0){ PBVS.watch.splice(i,1); _toast('Removed from watchlist'); }
    else{
      var l=activeFeed().concat(SEED_LEADS, PBVS.findLeads||[]).filter(function(x){return x&&x.id===id;})[0];
      if(l){ var c=JSON.parse(JSON.stringify(l)); c.addedAt=Date.now(); c._lastSeen=Date.now(); PBVS.watch.push(c); _toast('&#10004; Watching -- you\'ll be alerted on changes'); }
    }
    saveWatch();
    if(PBVS._inWatch) renderWatch(); else if(PBVS.sub==='leads') renderLeads();
    updateWatchCount();
  }
  function updateWatchCount(){ var host=el('vehSearchContent'); if(host){ var b=host.querySelector('[data-act="watchview"]'); if(b) b.innerHTML='&#10084; Watchlist ('+PBVS.watch.length+')'; } }

  function addCrit(){
    var mk=el('ncMake'), md=el('ncModel'), y0=el('ncYmin'), y1=el('ncYmax');
    var make=mk?mk.value:'', model=md?md.value:'';
    if(!make||!model){ _toast('Pick a make and model'); return; }
    PBVS.criteria.push({make:make,model:model,yearMin:(y0&&+y0.value)||'',yearMax:(y1&&+y1.value)||'',note:''});
    saveCrit(); renderKit();
  }
  function doCopy(btn){
    var id=btn.getAttribute('data-t'), pre=el(id); if(!pre) return;
    var txt=pre.innerText||pre.textContent||'';
    var ok=function(){ btn.textContent='Copied'; btn.classList.add('done'); setTimeout(function(){ btn.textContent='Copy'; btn.classList.remove('done'); },1400); };
    try{ if(navigator.clipboard&&navigator.clipboard.writeText){ navigator.clipboard.writeText(txt).then(ok,fb); } else fb(); }catch(e){ fb(); }
    function fb(){ try{ var r=document.createRange(); r.selectNode(pre); var s=window.getSelection(); s.removeAllRanges(); s.addRange(r); document.execCommand('copy'); s.removeAllRanges(); }catch(e){} ok(); }
  }

  // ---- live feed (worker) with graceful fallback -----------------------------
  // fetch with a hard timeout so "Refresh" / load never hangs forever on a CF edge stall
  function _fetchT(url,opts,ms){ opts=opts||{}; try{ if(typeof AbortController!=='undefined'){ var ac=new AbortController(); opts.signal=ac.signal; setTimeout(function(){ try{ac.abort();}catch(e){} }, ms||15000); } }catch(e){} return fetch(url,opts); }
  function _ago(ms){ var m=Math.max(0,Math.round(ms/60000)); if(m<1) return 'just now'; if(m<60) return m+'m ago'; var hr=Math.round(m/60); if(hr<48) return hr+'h ago'; return Math.round(hr/24)+'d ago'; }
  // feed freshness banner: green <24h, amber 1-3d, red STALE / blocked -- so nobody chases a dead lot
  function _feedAgeNote(){
    if(!(PBVS.leads&&PBVS.leads.length)) return {t:'Starter set (real cars from the 2026-08 sweep). Hit Refresh once the daily worker feed is live.',c:'var(--muted)'};
    var at=+PBVS.feedAt||0, cnt=' &middot; '+PBVS.leads.length+' cars'+(PBVS.feedScraped!=null?(' ('+PBVS.feedScraped+' Copart, '+(PBVS.feedGov||0)+' gov)'):'');
    if(PBVS.feedBlocked) return {t:'&#9888; Live sources blocked &mdash; showing last-good feed'+cnt,c:'#ef4444'};
    if(!at) return {t:'Live feed'+cnt,c:'#22c55e'};
    var age=Date.now()-at, hrs=age/3600000;
    if(hrs<24) return {t:'Live feed &middot; updated '+_ago(age)+cnt,c:'#22c55e'};
    if(hrs<72) return {t:'Feed '+_ago(age)+' old &mdash; may be stale'+cnt,c:'#f59e0b'};
    return {t:'STALE &mdash; '+_ago(age)+' old; scraper may be blocked. Hit Refresh.'+cnt,c:'#ef4444'};
  }
  // "Refresh feed" -> force the worker to RE-SCRAPE now (POST /refresh), then re-load
  function forceRefresh(){
    var w=_worker(); if(!w){ fetchFeed(true); return; }
    _toast('Re-scanning all sources&#8230;');
    _fetchT(w+'/vehicle-leads/refresh',{method:'POST',headers:Object.assign({'Content-Type':'application/json'},_auth())},22000)
      .then(function(r){ return r.ok?r.json():null; })
      .then(function(d){
        if(d){ PBVS.feedBlocked=!!d.blocked;
          if(d.blocked) _toast('&#9888; Live sources blocked right now &mdash; last-good feed kept');
          else if(d.count!=null) _toast('&#10004; Re-scanned: '+d.count+' leads'+(d.scraped!=null?(' ('+d.scraped+' Copart, '+(d.gov||0)+' gov)'):'')); }
        fetchFeed(true);
      })
      .catch(function(){ _toast('Refresh timed out &mdash; showing current feed'); fetchFeed(true); });
  }
  function fetchFeed(manual){
    var w=_worker(); if(!w){ if(manual) _toast('Showing starter set'); return; }
    try{
      _fetchT(w+'/vehicle-leads?_='+Date.now(),{cache:'no-store',headers:_auth()},15000)
        .then(function(r){ return r.ok?r.json():null; })
        .then(function(d){
          var arr=(d&&(d.leads||d.vehicles))||null;
          if(arr&&arr.length){ PBVS.leads=arr; PBVS.feedSrc='live'; PBVS.feedAt=(d&&d.updatedAt)||Date.now(); PBVS.feedScraped=(d&&d.scraped!=null)?d.scraped:null; PBVS.feedGov=(d&&d.gov!=null)?d.gov:null; PBVS.feedBlocked=!!(d&&d.blocked); diffWatch(arr); if(PBVS.sub==='leads') renderLeads(); if(manual) _toast('&#10004; Feed refreshed ('+arr.length+')'); }
          else if(manual){ _toast('No live feed yet -- showing starter set'); }
        }).catch(function(){ if(manual) _toast('Feed offline -- showing starter set'); });
    }catch(e){}
  }
  function _wkey(l){ return (l&&l.vin?('vin:'+String(l.vin)):((l&&l.year||'')+'|'+(l&&l.make||'')+'|'+(l&&l.model||'')+'|'+((l&&l.location)||(l&&l.state)||''))).toLowerCase(); }
  // local diff so watched cars alert you the moment the feed changes (pre-worker-cron)
  function diffWatch(arr){
    if(!PBVS.watch.length) return;
    var byId={}, byKey={}; arr.forEach(function(l){ if(l&&l.id){ byId[l.id]=l; byKey[_wkey(l)]=l; } });
    var changed=[], dirty=false;
    PBVS.watch.forEach(function(w){
      var n=byId[w.id]||byKey[_wkey(w)];   // match on id OR a stable vehicle key -- live scrape ids differ from seed ids
      if(n){
        if(Number(n.price)!==Number(w.price)) changed.push(vehStr(w)+': price '+ (w.price?('$'+w.price):'-') +' -> '+(n.price?('$'+n.price):'-'));
        else if(n.saleDate!==w.saleDate) changed.push(vehStr(w)+': sale date '+w.saleDate+' -> '+n.saleDate);
        else if(String(n.title||'')!==String(w.title||'')) changed.push(vehStr(w)+': title '+(w.title||'?')+' -> '+(n.title||'?'));
        // self-heal the saved snapshot from the freshest feed (corrected title / photo / price / etc.)
        ['price','buyNow','bid','saleDate','title','image','damage','miles','milesActual','location','steal'].forEach(function(k){ if(n[k]!=null) w[k]=n[k]; });
        w._lastSeen=Date.now(); if(w._sold){ w._sold=false; } dirty=true;
      } else if(!w._sold && w._lastSeen){
        // gone from a feed that DID scrape this make/model -> likely sold/removed
        // (only fire if the same model IS present now, so a partial feed doesn't false-alarm)
        var sameModel=arr.some(function(l){ return l && String(l.make||'').toLowerCase()===String(w.make||'').toLowerCase() && String(l.model||'').toLowerCase()===String(w.model||'').toLowerCase(); });
        if(sameModel){ w._sold=true; dirty=true; changed.push(vehStr(w)+': no longer listed (likely sold)'); }
      }
    });
    if(dirty) _lsSet(LSK_WATCH,PBVS.watch);
    if(changed.length){ _toast('&#128276; Watchlist: '+changed[0]+(changed.length>1?(' (+'+(changed.length-1)+' more)'):'')); }
  }

  // ============================================================================
  //  PARTS CART + LISTING REPORT
  // ============================================================================
  function _cartN(){ return (PBVS.cart||[]).filter(function(c){return c.status!=='ordered';}).length; }
  function saveCart(){ _lsSet(LSK_CART, PBVS.cart); _pushState(); updateCartCount(); }
  function updateCartCount(){ var host=el('vehSearchContent'); if(host){ var b=host.querySelector('[data-act="sub"][data-k="cart"]'); if(b) b.innerHTML='&#128722; Parts Cart'+(_cartN()?' ('+_cartN()+')':''); } }

  // client-side damage-type checklist (mirrors the worker) so a report ALWAYS works
  function _fallbackParts(damage){
    var d=String(damage||'').toLowerCase();
    var F=[{name:'Front bumper cover',priority:'critical'},{name:'Energy absorber + impact bar',priority:'critical'},{name:'Grille',priority:'recommended'},{name:'Headlight assembly (L/R)',priority:'critical'},{name:'Radiator core support',priority:'critical'},{name:'Radiator + A/C condenser',priority:'recommended'},{name:'Fender (L/R)',priority:'recommended'},{name:'Hood',priority:'recommended'}];
    var R=[{name:'Rear bumper cover',priority:'critical'},{name:'Rear absorber + rebar',priority:'critical'},{name:'Tail light assembly (L/R)',priority:'critical'},{name:'Decklid / trunk',priority:'recommended'}];
    var S=[{name:'Door shell / skin',priority:'critical'},{name:'Side mirror assembly',priority:'recommended'},{name:'Rocker panel',priority:'inspect'},{name:'Window regulator + glass',priority:'recommended'}];
    var U=[{name:'Control arms (upper/lower)',priority:'critical'},{name:'Steering knuckle / upright',priority:'critical'},{name:'Wheel hub + bearing',priority:'recommended'},{name:'Tie rod end',priority:'recommended'}];
    var out=[]; if(/front/.test(d))out=out.concat(F); if(/rear/.test(d))out=out.concat(R); if(/side|door/.test(d))out=out.concat(S); if(/undercarriage|suspension/.test(d))out=out.concat(U); if(!out.length)out=F;
    return out.map(function(p){ return {name:p.name,priority:p.priority,why:'typical for '+(damage||'this')+' damage',oem:'',search:p.name}; });
  }
  // condition-filtered (used/new only), cheapest-first buy links for one part
  function partLinks(v, part){
    // name-based keyword -- robust even when an AI-suggested OEM number is wrong (a wrong # dead-ends the search)
    var kw=(vehStr(v)+' '+(part.name||part.search||'')).trim();
    var euro=/audi|bmw|mercedes|porsche|ferrari|lamborghini|mclaren|bentley|rolls|maserati|aston|jaguar|land rover|volkswagen|volvo|alfa/i.test(v.make||'');
    var out=[
      {label:'eBay used/new (cheapest)', gold:true, url:'https://www.ebay.com/sch/i.html?_nkw='+q(kw)+'&_sacat=6028&LH_ItemCondition=1000%7C3000&_sop=15'},
      {label:'Amazon', url:'https://www.amazon.com/s?k='+q(kw)+'&i=automotive'},
      {label:'RockAuto catalog', url:'https://www.rockauto.com/en/catalog/'+q(v.make)+','+q(v.year)+','+q(v.model)},
      {label:'Car-Part yards', url:'https://www.google.com/search?q='+q('site:car-part.com '+kw)}
    ];
    // AI-suggested OEM numbers are NOT guaranteed to fit this exact car -- offer them clearly labeled "verify"
    if(part.oem){
      out.push({label:'RockAuto #'+part.oem+' (verify)', url:'https://www.rockauto.com/en/partsearch/?partnum='+q(part.oem)});
      out.push({label:'eBay #'+part.oem+' (verify)', url:'https://www.ebay.com/sch/i.html?_nkw='+q(part.oem)});
    }
    // parts STORES (AutoZone/O'Reilly/NAPA/Advance/PartsGeek/Summit/1A/RockAuto) + JUNKYARDS
    // (Car-Part/Row52/LKQ/Pull-A-Part) via Google site: -> always real, in-stock findings
    out.push({label:'Parts stores', gold:true, url:'https://www.google.com/search?q='+q(kw+' (site:rockauto.com OR site:autozone.com OR site:oreillyauto.com OR site:napaonline.com OR site:advanceautoparts.com OR site:partsgeek.com OR site:summitracing.com OR site:1aauto.com)')});
    out.push({label:'Junkyards', gold:true, url:'https://www.google.com/search?q='+q(kw+' (site:car-part.com OR site:row52.com OR site:lkqonline.com OR site:pullapart.com)')});
    out.push({label:'Whole web', url:'https://www.google.com/search?q='+q(kw+' for sale')});
    out.push({label:'Shopping', url:'https://www.google.com/search?tbm=shop&q='+q(kw)});
    if(euro) out.push({label:'FCP Euro', url:'https://www.fcpeuro.com/search?q='+q(kw)});
    return out;
  }
  function addToCart(item){
    var key=((item.name||'')+'|'+(item.vehicle||'')).toLowerCase();
    // only a NON-ordered duplicate blocks a plain re-add: re-adding an existing to-order line bumps qty,
    // and an already-ORDERED part CAN be re-added (arrived cracked / you need two)
    var ex=(PBVS.cart||[]).filter(function(c){ return c.status!=='ordered' && ((c.name||'')+'|'+(c.vehicle||'')).toLowerCase()===key; })[0];
    if(ex){ ex.qty=(+ex.qty||1)+1; saveCart(); return true; }
    PBVS.cart.push(Object.assign({status:'to-order', qty:1, addedAt:Date.now()}, item));
    saveCart(); return true;
  }

  var _reportCache={}, _modalCtx=null;
  function openReport(id){
    var l=activeFeed().concat(SEED_LEADS, PBVS.watch||[], PBVS.findLeads||[]).filter(function(x){return x&&x.id===id;})[0];
    if(!l){ _toast('Lead not found'); return; }
    _showReportModal(l, null, true);
    if(_reportCache[id]){ _showReportModal(l, _reportCache[id], false); return; }
    var v={year:l.year,make:l.make,model:l.model};
    var done=function(rep){ _reportCache[id]=rep; _showReportModal(l, rep, false); };
    var w=_worker();
    if(w){
      fetch(w+'/vehicle-report',{method:'POST',headers:Object.assign({'Content-Type':'application/json'},_auth()),body:JSON.stringify({id:id,url:l.url||'',vehicle:v,damage:l.damage||'',title:l.title||''})})
        .then(function(r){ return r.ok?r.json():null; })
        .then(function(rep){ done((rep&&rep.parts&&rep.parts.length)?rep:_clientReport(l)); })
        .catch(function(){ done(_clientReport(l)); });
    } else done(_clientReport(l));
  }
  function _clientReport(l){ return {id:l.id, vehicle:vehStr(l), damage:l.damage||'', images:(l.image?[l.image]:[]), provider:'fallback', summary:'Damage-type checklist (server report unavailable) -- verify against the listing photos.', parts:_fallbackParts(l.damage)}; }

  function _ensureModal(){
    var m=el('pbvsModal'); if(m) return m;
    m=document.createElement('div'); m.id='pbvsModal'; m.className='pbvs-modal'; document.body.appendChild(m);
    var _close=function(){ try{ if(_modalCtx&&_modalCtx._timers) _modalCtx._timers.forEach(function(t){ clearTimeout(t); }); }catch(e){} _modalCtx=null; m.style.display='none'; };
    m.addEventListener('click', function(e){
      if(e.target===m){ _close(); return; }
      var t=e.target.closest('[data-act]'); if(!t) return; var act=t.getAttribute('data-act');
      if(act==='closemodal'){ _close(); }
      else if(act==='addcart'){ if(_cartFromReport(+t.getAttribute('data-i'))){ t.textContent='\u2713'; t.disabled=true; } else { t.textContent='in cart'; } }
      else if(act==='sendall'){ _sendAllToCart(); t.textContent='\u2713 All added'; }
      else if(act==='bestprice'){ _bestPrice(+t.getAttribute('data-i'), t); }
    });
    document.addEventListener('keydown', function(e){ if(e.key==='Escape' && m.style.display==='flex') _close(); });
    return m;
  }
  function _cartFromReport(i){ if(!_modalCtx) return false; var p=_modalCtx.parts[i]; if(!p) return false; return addToCart({name:p.name, vehicle:vehStr(_modalCtx.lead), oem:p.oem||'', links:partLinks(_modalCtx.vehicle,p)}); }
  function _sendAllToCart(){ if(!_modalCtx) return; var n=0; _modalCtx.parts.forEach(function(p){ if(addToCart({name:p.name,vehicle:vehStr(_modalCtx.lead),oem:p.oem||'',links:partLinks(_modalCtx.vehicle,p)})) n++; }); _toast(n+' part'+(n===1?'':'s')+' added to cart'); }
  // live best-price via the worker eBay Browse endpoint (auto-upgrades once EBAY keys exist).
  // Cached per (leadId, partIndex) so re-opening a report never re-burns eBay quota; drops
  // results if the modal was closed/reopened; single-flight per row.
  var _bestCache={};
  function _bestPrice(i, btn){
    if(!_modalCtx || PBVS._ebayOff) return; var p=_modalCtx.parts[i]; if(!p) return;
    var box=el('best-'+i), ck=(_modalCtx.leadId||'x')+'|'+i;
    if(_bestCache[ck]){ if(box) box.innerHTML=_bestCache[ck]; if(btn) btn.disabled=false; return; }
    _modalCtx._inflight=_modalCtx._inflight||{}; if(_modalCtx._inflight[i]) return; _modalCtx._inflight[i]=1;
    if(box) box.innerHTML='Finding cheapest good-condition&#8230;'; if(btn) btn.disabled=true;
    var w=_worker(), mctx=_modalCtx, kw=(vehStr(_modalCtx.vehicle)+' '+(p.name||p.search||'')).trim();
    if(!w){ if(box) box.innerHTML='Best-price needs the worker deployed.'; if(btn) btn.disabled=false; mctx._inflight[i]=0; return; }
    _fetchT(w+'/parts-best',{method:'POST',headers:Object.assign({'Content-Type':'application/json'},_auth()),body:JSON.stringify({q:kw})},15000)
      .then(function(r){ return r.ok?r.json():null; })
      .then(function(d){ if(mctx!==_modalCtx) return;   // modal changed -> stale, ignore
        mctx._inflight[i]=0; if(btn) btn.disabled=false; var b2=el('best-'+i); if(!b2) return;
        if(d&&d.notConfigured){ PBVS._ebayOff=true; b2.innerHTML='<span style="color:var(--muted)">Live prices appear here once your eBay API key is in the worker.</span>'; return; }
        var items=(d&&d.items)||[];
        var html = items.length
          ? ('<div style="font-weight:700;color:#22c55e;margin-top:2px">Best prices (used/new/reman):</div>'+items.slice(0,3).map(function(it){ return '<div style="margin-top:2px">'+esc(it.condition||'')+' &middot; <b style="color:#22c55e">$'+esc(it.price)+'</b>'+(it.seller?(' &middot; '+esc(it.seller)+'%'):'')+' &middot; <a href="'+esc(it.url)+'" target="_blank" rel="noopener" style="color:#c9a962">'+esc(String(it.title||'').slice(0,54))+' &#8599;</a></div>'; }).join(''))
          : '<span style="color:var(--muted)">No good-condition listing found right now.</span>';
        _bestCache[ck]=html; b2.innerHTML=html;
      })
      .catch(function(){ if(mctx!==_modalCtx) return; mctx._inflight[i]=0; if(btn) btn.disabled=false; var b3=el('best-'+i); if(b3) b3.innerHTML='<span style="color:var(--muted)">Lookup failed.</span>'; });
  }

  function _showReportModal(l, rep, loading){
    var m=_ensureModal(); var v={year:l.year,make:l.make,model:l.model}; var body;
    if(loading){ body='<div class="pbvs-modinner"><div class="pbvs-modhead"><b style="color:#fff;font-size:16px">'+esc(vehStr(l))+'</b><button class="pbvs-srcbtn" data-act="closemodal">Close</button></div><div class="pbvs-empty">Reading listing + photos and building the parts list&#8230;</div></div>'; }
    else {
      _modalCtx={ lead:l, vehicle:v, parts:rep.parts||[], leadId:l.id, _timers:[], _inflight:{} };
      var hasImgs=(rep.images||[]).length>0, ebayOff=!!PBVS._ebayOff;
      var prio={critical:'#ef4444',recommended:'#c9a962',inspect:'#8b939e'};
      var imgs=(rep.images||[]).slice(0,10).map(function(u){ return '<a href="'+esc(u)+'" target="_blank" rel="noopener"><img src="'+esc(u)+'" loading="lazy" onerror="this.parentNode.style.display=\'none\'"></a>'; }).join('');
      var rows=(rep.parts||[]).map(function(p,i){
        var links=partLinks(v,p).map(function(s){ return '<a class="'+(s.gold?'gold':'')+'" href="'+s.url+'" target="_blank" rel="noopener">'+esc(s.label)+' &#8599;</a>'; }).join('');
        return '<div class="pbvs-preprow"><div style="flex:1;min-width:0"><b>'+esc(p.name)+'</b> <span class="pbvs-pill" style="color:'+(prio[p.priority]||'#8b939e')+'">'+esc(p.priority||'')+'</span>'+(p.oem?' <span class="pbvs-pill" style="color:#f59e0b" title="AI-suggested OEM number -- verify it fits before ordering">OEM '+esc(p.oem)+' &middot; verify</span>':'')+
          (p.why?'<div class="pbvs-hint">'+esc(p.why)+'</div>':'')+'<div class="pbvs-src" style="margin-top:5px">'+links+(ebayOff?'':'<button class="pbvs-srcbtn" data-act="bestprice" data-i="'+i+'">$ Best price</button>')+'</div>'+
          '<div id="best-'+i+'" class="pbvs-hint" style="margin-top:4px"></div></div>'+
          '<button class="pbvs-srcbtn" data-act="addcart" data-i="'+i+'">+ Cart</button></div>';
      }).join('');
      body='<div class="pbvs-modinner">'+
        '<div class="pbvs-modhead"><div><b style="font-size:16px;color:#fff">'+esc(vehStr(l))+'</b> &mdash; parts report <span class="pbvs-pill">'+(rep.provider==='claude'?(hasImgs?'AI + photos':'AI (no photos)'):'checklist')+'</span></div><button class="pbvs-srcbtn" data-act="closemodal">Close</button></div>'+
        (rep.summary?'<div class="pbvs-hint" style="margin:4px 0 10px">'+esc(rep.summary)+'</div>':'')+
        (ebayOff?'<div class="pbvs-hint" style="color:#f59e0b;margin:2px 0 8px">Live eBay best-price needs your eBay API key in the worker &mdash; the buy-links on each part still work.</div>':'')+
        (imgs?'<div class="pbvs-gallery">'+imgs+'</div>':'<div class="pbvs-hint">No listing photos available &mdash; <a href="'+esc(l.url||'#')+'" target="_blank" rel="noopener" style="color:#c9a962">open the listing &#8599;</a></div>')+
        '<div style="display:flex;justify-content:space-between;align-items:center;margin:12px 0 4px;gap:10px"><div class="pbvs-sec" style="margin:0">Itemized parts ('+(rep.parts||[]).length+')</div>'+
          '<button class="btn" data-act="sendall" style="background:#c9a962;border-color:#c9a962;color:#111;font-weight:800;white-space:nowrap">&#128722; Send all to cart</button></div>'+
        rows+'</div>';
    }
    m.innerHTML='<div class="pbvs-modbox">'+body+'</div>';
    m.style.display='flex';
    // image fallback: if EVERY gallery photo fails to load, swap in an open-listing hint
    if(!loading){ var gal=m.querySelector('.pbvs-gallery'); if(gal){ var ims=gal.querySelectorAll('img'), tot=ims.length, okc=0, dn=0; var chk=function(){ dn++; if(dn>=tot&&okc===0&&gal.parentNode){ var fb=document.createElement('div'); fb.className='pbvs-hint'; fb.innerHTML='No listing photos loaded &mdash; <a href="'+esc(l.url||'#')+'" target="_blank" rel="noopener" style="color:#c9a962">open the listing &#8599;</a>'; gal.parentNode.replaceChild(fb,gal); } }; ims.forEach(function(im){ if(im.complete){ if(im.naturalWidth>0) okc++; chk(); } else { im.addEventListener('load',function(){ okc++; chk(); }); im.addEventListener('error',chk); } }); } }
    // auto-price the first parts only (capped so casual browsing never burns the eBay quota); the rest price on demand
    if(!loading && rep && rep.parts && rep.parts.length && !PBVS._ebayOff && _worker()){
      var N=Math.min(rep.parts.length,8);
      for(var ci=0; ci<N; ci++){ (function(idx){ _modalCtx._timers.push(setTimeout(function(){ _bestPrice(idx,null); }, 140+idx*240)); })(ci); }
    }
  }

  function renderCart(){
    var body=el('pbvsBody'); if(!body) return;
    var todo=(PBVS.cart||[]).filter(function(c){return c.status!=='ordered';});
    var done=(PBVS.cart||[]).filter(function(c){return c.status==='ordered';});
    var h='<div class="pbvs-card" style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">'+
      '<div><div style="font-weight:800;color:#fff;font-size:15px">&#128722; Parts Cart</div><div class="pbvs-count">'+todo.length+' to order &middot; '+done.length+' ordered. Add from a vehicle report or Parts Search; check off as you buy &mdash; the ordered log is kept.</div></div>'+
      (done.length?'<button class="pbvs-srcbtn" data-act="clearordered">Clear ordered log</button>':'')+'</div>';
    if(!todo.length && !done.length){ h+='<div class="pbvs-empty">Cart is empty. Open a vehicle&#8217;s &#128736; Parts report and &#8220;Send all to cart&#8221;, or add parts from Parts Search.</div>'; }
    else{
      if(todo.length){ h+='<div class="pbvs-sec">To order ('+todo.length+')</div>'+todo.map(cartRow).join(''); }
      if(done.length){ h+='<div class="pbvs-sec" style="margin-top:16px">Ordered log ('+done.length+')</div>'+done.map(cartRow).join(''); }
    }
    body.innerHTML=h;
  }
  function _fmtDate(ts){ try{ var d=new Date(+ts); if(isNaN(d.getTime())) return ''; return (d.getMonth()+1)+'/'+d.getDate(); }catch(e){ return ''; } }
  function cartRow(c){
    var i=PBVS.cart.indexOf(c); var ordered=c.status==='ordered'; var qty=+c.qty||1;
    var links=(c.links||[]).map(function(s){ return '<a class="'+(s.gold?'gold':'')+'" href="'+s.url+'" target="_blank" rel="noopener">'+esc(s.label)+' &#8599;</a>'; }).join('');
    var when=ordered?(c.orderedAt?(' &middot; ordered '+_fmtDate(c.orderedAt)):' &middot; ordered'):'';
    var qtyUI = ordered ? (qty>1?' <span class="pbvs-pill">x'+qty+'</span>':'')
      : ' <span style="white-space:nowrap"><button class="pbvs-x" data-act="qtydec" data-i="'+i+'" title="Fewer" aria-label="Decrease quantity" style="color:var(--muted)">&#8722;</button><b style="padding:0 3px">'+qty+'</b><button class="pbvs-x" data-act="qtyinc" data-i="'+i+'" title="More" aria-label="Increase quantity" style="color:var(--muted)">+</button></span>';
    var orderedFields = ordered ? ('<div class="pbvs-row" style="margin-top:6px;gap:8px">'+
        '<div class="pbvs-fld"><label>Paid $</label><input id="cprice-'+i+'" class="finput" style="width:90px" value="'+esc(c.price||'')+'" placeholder="price"></div>'+
        '<div class="pbvs-fld"><label>Vendor</label><input id="cvendor-'+i+'" class="finput" style="width:150px" value="'+esc(c.vendor||'')+'" placeholder="eBay / yard / RockAuto"></div>'+
      '</div>') : '';
    return '<div class="pbvs-lead" style="display:flex;gap:12px;align-items:flex-start">'+
      '<button class="pbvs-check'+(ordered?' on':'')+'" data-act="ordertoggle" data-i="'+i+'" title="Mark ordered" aria-label="'+(ordered?'Mark not ordered':'Mark ordered')+'" aria-pressed="'+(ordered?'true':'false')+'">'+(ordered?'&#10004;':'')+'</button>'+
      '<div style="flex:1;min-width:0"><div style="font-weight:700;font-size:14px;color:#fff'+(ordered?';opacity:.55;text-decoration:line-through':'')+'">'+esc(c.name)+qtyUI+'</div>'+
        '<div class="pbvs-hint">'+esc(c.vehicle||'')+when+'</div>'+
        (!ordered&&links?'<div class="pbvs-src" style="margin-top:5px">'+links+'</div>':'')+orderedFields+'</div>'+
      '<button class="pbvs-x" data-act="cartremove" data-i="'+i+'" title="Remove" aria-label="Remove '+esc(c.name)+'">&#10006;</button></div>';
  }
  function _addManualPartToCart(){
    var p=el('psPart'); var part=p?p.value.trim():''; if(!part){ _toast('Type a part first'); return; }
    var v={year:partsSel.year,make:partsSel.make,model:partsSel.model,vin:partsSel.vin};
    addToCart({name:part, vehicle:vehStr(v)||'(no car selected)', oem:looksLikePart(part)?part:'', links:partLinks(v,{name:part,search:part})}); _toast('&#10004; Added to cart');
  }

  // ============================================================================
  //  VEHICLE SEARCH -- search ANY vehicle across every source within filters
  // ============================================================================
  var findSel = {yearMin:'', yearMax:'', make:'', model:'', maxPrice:'', title:'', state:'', _models:[]};
  function findSources(){
    var y0=findSel.yearMin||'', y1=findSel.yearMax||'', mk=findSel.make||'', md=findSel.model||'';
    var mkL=mk.toLowerCase().replace(/\s+/g,'-'), mdL=md.toLowerCase().replace(/\s+/g,'-');
    var yr=(y0&&y1&&y0!==y1)?(y0+'..'+y1):(y0||y1||'');   // Google understands a year range; single year for slug sites
    var ttl=(findSel.title&&findSel.title!=='Any')?(' '+String(findSel.title).toLowerCase()+' title'):'';
    var stt=(findSel.state?(' '+String(findSel.state).toUpperCase()):'');
    var pr=(+findSel.maxPrice>0?(' under $'+(+findSel.maxPrice)):'');
    var kw=((yr?yr+' ':'')+(mk+' '+md).trim()).trim();     // base (year+make+model)
    var kwq=(kw+ttl+stt+pr).trim();                        // full query: folds title / state / price for retail+gov+web
    // Google site: search ALWAYS returns real, current, criteria-fit listings from that
    // exact site (bulletproof vs. guessing fragile per-site URL slugs that 404).
    var g=function(site){ return 'https://www.google.com/search?q='+q('site:'+site+' '+kwq+' for sale'); };
    return [
      {g:'Salvage / auction', items:[
        {label:'Copart', url:'https://www.salvagereseller.com/cars-for-sale/make/'+q(mk.toUpperCase())+'/model/'+q(md.toUpperCase())},
        {label:'IAAI', url:'https://www.iaai.com/Vehiclelisting/'+q(mkL)+'/'+q(mdL.replace(/-/g,''))},
        {label:'SCA', url:'https://sca.auction/en/search/type-cars/make-'+q(mkL)+'/model-'+q(mdL)},
        {label:'bid.cars', url:'https://bid.cars/en/automobile/'+q(mkL)+'/'+q(mdL)},
        {label:'erepairables', url:g('erepairables.com')}
      ]},
      {g:'Retail / private (clean title)', items:[
        {label:'Autotrader', url:g('autotrader.com')},
        {label:'Cars.com', url:g('cars.com')},
        {label:'CarGurus', url:g('cargurus.com')},
        {label:'Cars &amp; Bids', url:g('carsandbids.com')},
        {label:'Bring a Trailer', url:g('bringatrailer.com')},
        {label:'FB Marketplace', url:'https://www.facebook.com/marketplace/search/?query='+q(kwq)},
        {label:'Craigslist', url:g('craigslist.org')},
        {label:'Whole web', url:'https://www.google.com/search?q='+q(kwq+' for sale')}
      ]},
      {g:'Government / seized', items:[
        {label:'GovDeals', url:g('govdeals.com')},
        {label:'Bid4Assets', url:g('bid4assets.com')},
        {label:'GSA Auctions', url:g('gsaauctions.gov')},
        {label:'PropertyRoom', url:g('propertyroom.com')}
      ]}
    ];
  }
  // re-render the deep-link block from the CURRENT form values (so links are always pre-filtered)
  function renderFindDeepLinks(){
    var box=el('findDeepLinks'); if(!box) return;
    box.innerHTML='<div class="pbvs-sec">Open the search on every source'+(findSel.make?'':' &mdash; pick a make/model to pre-fill')+'</div>'+
      findSources().map(function(g){ return '<div style="margin-bottom:9px"><div class="pbvs-hint" style="font-weight:700;color:#c9a962;margin-bottom:3px">'+g.g+'</div><div class="pbvs-src">'+g.items.map(function(s){ return '<a href="'+s.url+'" target="_blank" rel="noopener">'+s.label+' &#8599;</a>'; }).join('')+'</div></div>'; }).join('');
  }
  function renderFind(){
    var body=el('pbvsBody'); if(!body) return;
    var years=[]; var y0=(new Date().getFullYear())+1; for(var y=y0;y>=1980;y--) years.push(String(y));
    var titleSel=['Any','Clean','Salvage','Rebuilt'].map(function(o){return '<option'+(findSel.title===o?' selected':'')+'>'+o+'</option>';}).join('');
    var h='<div class="pbvs-card"><div class="pbvs-sec">Search any vehicle &mdash; every source, your filters</div>'+
      '<div class="pbvs-hint" style="margin-bottom:10px">Live listings pull from the auto-scrapeable sources (Copart, GSA gov, eBay when keyed). The JS-only sites (IAAI, Autotrader, Cars &amp; Bids, FB, gov) are one-click deep-links below &mdash; pre-filtered to your search.</div>'+
      '<div class="pbvs-row">'+
        fldSelRaw('Make','fdMake',(PBVS.nMakes||CURATED_MAKES),findSel.make)+
        fldSelRaw('Model','fdModel',(findSel._models||[]),findSel.model)+
        fldSelRaw('Year from','fdYmin',years,findSel.yearMin)+
        fldSelRaw('Year to','fdYmax',years,findSel.yearMax)+
      '</div>'+
      '<div class="pbvs-row" style="margin-top:8px">'+
        '<div class="pbvs-fld"><label>Max price $</label><input id="fdMax" class="finput" style="width:110px" placeholder="any" value="'+esc(findSel.maxPrice)+'"></div>'+
        '<div class="pbvs-fld"><label>Title</label><select id="fdTitle" class="finput" style="min-width:110px">'+titleSel+'</select></div>'+
        '<div class="pbvs-fld"><label>State</label><input id="fdState" class="finput" style="width:74px;text-transform:uppercase" maxlength="2" placeholder="any" value="'+esc(findSel.state)+'"></div>'+
        '<button class="btn" data-act="findgo" style="background:#c9a962;border-color:#c9a962;color:#111;font-weight:800">Search all sources</button>'+
      '</div></div>'+
      '<div id="findResults"></div>'+
      '<div class="pbvs-card" id="findDeepLinks"></div>';
    body.innerHTML=h;
    renderFindDeepLinks();
    getMakes(function(){ var sel=el('fdMake'); if(sel) fillSelect(sel,PBVS.nMakes,findSel.make); });
    if(findSel.make){ getModels(findSel.make, findSel.yearMin||(new Date().getFullYear()), function(arr){ findSel._models=arr; var s=el('fdModel'); if(s) fillSelect(s,arr,findSel.model); }); }
  }
  function runFind(){
    findSel.maxPrice=(el('fdMax')&&el('fdMax').value)||''; findSel.title=(el('fdTitle')&&el('fdTitle').value)||''; findSel.state=(el('fdState')&&el('fdState').value)||'';
    renderFindDeepLinks();
    var r=el('findResults'); if(!findSel.make){ if(r) r.innerHTML='<div class="pbvs-empty">Pick a make first (the deep-links below still work without one).</div>'; return; }
    if(r) r.innerHTML='<div class="pbvs-empty">Searching Copart + GSA gov + eBay&#8230;</div>';
    var w=_worker();
    if(!w){ if(r) r.innerHTML='<div class="pbvs-empty">Live search needs the worker deployed &mdash; use the deep-links below.</div>'; return; }
    var payload={make:findSel.make,model:findSel.model,yearMin:findSel.yearMin,yearMax:findSel.yearMax,maxPrice:findSel.maxPrice,title:(findSel.title==='Any'?'':findSel.title),state:findSel.state};
    _fetchT(w+'/vehicle-find',{method:'POST',headers:Object.assign({'Content-Type':'application/json'},_auth()),body:JSON.stringify(payload)},20000)
      .then(function(x){ var st=x.status; return x.json().then(function(j){ return {ok:x.ok,status:st,j:j}; },function(){ return {ok:x.ok,status:st,j:null}; }); })
      .then(function(res){ if(!r) return;
        // an errored / unauthorized search must NOT look like "0 results found"
        if(!res.ok){ r.innerHTML='<div class="pbvs-empty">Search '+(res.status===401?'needs you signed in to the dashboard (Settings &rarr; secret)':'failed (server '+res.status+')')+' &mdash; the deep-links below still work.</div>'; return; }
        var d=res.j, leads=(d&&d.leads)||[], s=(d&&d.sources)||{};
        PBVS.findLeads=leads;   // so the heart + Parts report resolve on found cars
        var head='<div class="pbvs-card" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center"><span class="pbvs-count"><b style="color:#c9a962">'+leads.length+'</b> live listings &middot; Copart '+(s.copart||0)+' &middot; gov '+(s.gov||0)+' &middot; eBay '+(s.ebay||0)+'</span>'+((!leads.length&&!findSel.model)?'<span class="pbvs-hint">&mdash; add a model for live Copart results</span>':'')+'</div>';
        r.innerHTML = head + (leads.length ? '<div class="pbvs-grid pbvs-leadgrid">'+leads.map(leadCard).join('')+'</div>' : '<div class="pbvs-empty">No live listings from the auto-sources for those filters &mdash; the deep-links below cover the JS-only sites.</div>');
      })
      .catch(function(){ if(r) r.innerHTML='<div class="pbvs-empty">Search failed or timed out &mdash; use the deep-links below.</div>'; });
  }

  // ---- public entry ----------------------------------------------------------
  window.renderVehSearchTab = function(){
    if((window.PB_FLAGS||{}).vehicleSearch===false){ var h=el('vehSearchContent'); if(h) h.innerHTML='<div class="pbvs-empty">Vehicle/Parts Search is turned off.</div>'; return; }
    render();
    if(!PBVS.__hydrated1){ PBVS.__hydrated1=true; _hydrateState(); }
    if(!PBVS.__feedTried){ PBVS.__feedTried=true; fetchFeed(false); }
  };

  // ---- deep-link from a push notification: tap alert -> (unlock) -> this tab -> listing ----
  function _gotoVehTab(){ try{ if(typeof switchTab==='function') switchTab('vehsearch'); else if(window.renderVehSearchTab) window.renderVehSearchTab(); }catch(e){} }
  try{ var _dlm=/[?&]vsurl=([^&#]+)/.exec(location.search||''); if(_dlm){ PBVS._deepLink=decodeURIComponent(_dlm[1]); } }catch(e){}
  try{ if(navigator.serviceWorker && navigator.serviceWorker.addEventListener){ navigator.serviceWorker.addEventListener('message', function(ev){ if(ev && ev.data && ev.data.type==='pb-vs-open' && ev.data.url){ PBVS._deepLink=ev.data.url; _gotoVehTab(); } }); } }catch(e){}
  // jump to the tab shortly after load, and again after a typical PIN-unlock delay
  if(PBVS._deepLink){ setTimeout(_gotoVehTab, 900); setTimeout(_gotoVehTab, 3200); }
})();

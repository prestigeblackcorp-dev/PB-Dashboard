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
  var LSK_CRIT='pbvs_criteria', LSK_WATCH='pbvs_watch', LSK_SUB='pbvs_sub', LSK_ACT='pbvs_actionable';
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
    actionable: _lsGet(LSK_ACT,true),
    criteria: _lsGet(LSK_CRIT, DEFAULT_CRITERIA),
    watch:    _lsGet(LSK_WATCH, []),      // [{...lead, addedAt}]
    leads:    [],                          // live feed if worker returns one
    feedSrc:  'starter',
    feedAt:   0,
    fMake:'', fModel:'', fYear:'',        // leads filter
    nMakes:null, nModels:{}                // NHTSA caches
  };
  function saveCrit(){ _lsSet(LSK_CRIT,PBVS.criteria); _pushState(); }
  function saveWatch(){ _lsSet(LSK_WATCH,PBVS.watch); _pushState(); }

  // Best-effort cross-device mirror (Phase 2 worker endpoint). Falls back to
  // localStorage-only; never blocks or throws.
  function _pushState(){
    var w=_worker(); if(!w) return;
    try{
      fetch(w+'/vehicle-search/state',{method:'PUT',
        headers:Object.assign({'Content-Type':'application/json'},_auth()),
        body:JSON.stringify({criteria:PBVS.criteria,watch:PBVS.watch})}).catch(function(){});
    }catch(e){}
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
      '.pbvs-heart{position:absolute;top:12px;right:12px;background:none;border:none;font-size:20px;cursor:pointer;line-height:1;color:#555;transition:.12s}',
      '.pbvs-heart.on{color:#ef4444;transform:scale(1.12)}',
      '.pbvs-title{font-weight:800;font-size:15px;color:#fff;padding-right:34px}',
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
      '.pbvs-x{background:none;border:none;color:#ef4444;cursor:pointer;font-size:14px;padding:0 4px}'
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
    out.push({label:'eBay Motors &middot; Used', url:'https://www.ebay.com/sch/i.html?_nkw='+q(kw)+'&_sacat=6028&LH_ItemCondition=3000&LH_BIN=1'});
    out.push({label:'eBay Motors &middot; New', url:'https://www.ebay.com/sch/i.html?_nkw='+q(kw)+'&_sacat=6028&LH_ItemCondition=1000'});
    if(isPart) out.push({label:'eBay by Part #', gold:true, url:'https://www.ebay.com/sch/i.html?_nkw='+q(part)});
    out.push({label:'Amazon', url:'https://www.amazon.com/s?k='+q(kw)+'&i=automotive'});
    out.push({label:'Google Shopping', url:'https://www.google.com/search?tbm=shop&q='+q(kw)});
    if(isPart) out.push({label:'RockAuto by Part #', gold:true, url:'https://www.rockauto.com/en/partsearch/?partnum='+q(part)});
    out.push({label:'RockAuto catalog', url:'https://www.rockauto.com/en/catalog/'+q(v.make)+','+q(v.year)+','+q(v.model)});
    if(euro) out.push({label:'FCP Euro', url:'https://www.fcpeuro.com/search?q='+q(kw)});
    // Junkyards + phone numbers (nationwide): Car-Part.com is THE tool.
    out.push({label:'&#9742; Car-Part.com (yards + phones)', gold:true, url:'https://www.google.com/search?q='+q('site:car-part.com '+kw)});
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
      {label:'bid.cars', url:'https://bid.cars/en/automobile/'+q(mk.toLowerCase())+'/'+q(md.toLowerCase().replace(/\s+/g,'-'))}
    ];
  }

  // ===========================================================================
  //  RENDER -- shell + sub-tab dispatch
  // ===========================================================================
  function render(){
    injectCSS();
    var host=el('vehSearchContent'); if(!host) return;
    var s=PBVS.sub; PBVS._inWatch=false;
    host.innerHTML =
      '<div class="pbvs-subnav">'+
        subBtn('leads','&#128293; Current Leads')+
        subBtn('parts','&#128736; Parts Search')+
        subBtn('kit','&#128203; Outreach &amp; Watch-list Kit')+
        '<div style="flex:1"></div>'+
        '<button class="pbvs-subbtn" data-act="watchview" title="Your saved vehicles">&#10084; Watchlist ('+PBVS.watch.length+')</button>'+
      '</div>'+
      '<div id="pbvsBody"></div>';
    if(s==='parts') renderParts();
    else if(s==='kit') renderKit();
    else renderLeads();
    wire(host);
  }
  function subBtn(k,label){ return '<button class="pbvs-subbtn'+(PBVS.sub===k?' on':'')+'" data-act="sub" data-k="'+k+'">'+label+'</button>'; }

  // ---- Current Leads ---------------------------------------------------------
  function daysUntil(d){ if(!d||d==='future') return null; var t=Date.parse(d+'T12:00:00'); if(isNaN(t)) return null; return Math.round((t-Date.now())/86400000); }
  function isActionable(l){ var pt=(l.priceType||''); if(pt==='buynow'||pt==='bin'||pt==='cash') return true; var du=daysUntil(l.saleDate); if(du===null) return true; /* not-yet-scheduled: keep */ return du<=3 && du>=-1; }
  function activeFeed(){ return (PBVS.leads&&PBVS.leads.length)?PBVS.leads:SEED_LEADS; }
  function watchHas(id){ return PBVS.watch.some(function(w){ return w.id===id; }); }

  function renderLeads(){
    var body=el('pbvsBody'); if(!body) return;
    var feed=activeFeed().filter(function(l){ return l.verdict!=='pass'; });
    // filter chips (make/model/year) built from the feed's real values
    var makes=uniq(feed.map(function(l){return l.make;}));
    var models=uniq(feed.filter(function(l){return !PBVS.fMake||l.make===PBVS.fMake;}).map(function(l){return l.model;}));
    var years=uniq(feed.map(function(l){return String(l.year);})).sort().reverse();
    var shown=feed.filter(function(l){
      if(PBVS.fMake && l.make!==PBVS.fMake) return false;
      if(PBVS.fModel && l.model!==PBVS.fModel) return false;
      if(PBVS.fYear && String(l.year)!==PBVS.fYear) return false;
      if(PBVS.actionable && !isActionable(l)) return false;
      return true;
    }).sort(function(a,b){ var r=(VRANK[a.verdict]||9)-(VRANK[b.verdict]||9); if(r) return r; var da=daysUntil(a.saleDate), db=daysUntil(b.saleDate); da=(da===null?999:da); db=(db===null?999:db); return da-db; });

    var feedNote = (PBVS.leads&&PBVS.leads.length)
      ? 'Live daily feed &middot; '+shown.length+' shown'
      : 'Starter set (real cars from the 2026-08 sweep). The daily worker feed replaces this once deployed.';

    var h='';
    h+='<div class="pbvs-card" style="display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between">'+
        '<div><div style="font-weight:800;color:#fff;font-size:15px">&#128293; Nationwide leads</div>'+
        '<div class="pbvs-count">'+feedNote+'</div></div>'+
        '<div style="display:flex;gap:8px;flex-wrap:wrap">'+
          '<button class="pbvs-srcbtn" data-act="refresh">&#8635; Refresh feed</button>'+
          '<label class="pbvs-chip'+(PBVS.actionable?' on':'')+'" data-act="toggleact" title="Hide auctions more than 3 days out that have no Buy-Now">'+(PBVS.actionable?'&#9989; ':'')+'Actionable only (&#8804;3 days or Buy-Now)</label>'+
        '</div>'+
      '</div>';

    // ALWAYS-ON stats strip (title breakdown + counts)
    var _mmy=feed.filter(function(l){ if(PBVS.fMake&&l.make!==PBVS.fMake)return false; if(PBVS.fModel&&l.model!==PBVS.fModel)return false; if(PBVS.fYear&&String(l.year)!==PBVS.fYear)return false; return true; });
    var _hidden = PBVS.actionable ? Math.max(0,_mmy.length - shown.length) : 0;
    function _sc(n,label,color){ return '<span class="pbvs-pill" style="font-weight:700;color:'+color+'"><b style="font-size:14px">'+n+'</b> '+label+'</span>'; }
    var _clean=shown.filter(function(l){return /clean/i.test(l.title||'');}).length;
    var _salv =shown.filter(function(l){return /salvage|rebuilt|junk|non/i.test(l.title||'');}).length;
    var _unk  =shown.filter(function(l){return !l.title;}).length;
    var _bnow =shown.filter(function(l){return l.priceType==='buynow'||l.priceType==='bin';}).length;
    var _chase=shown.filter(function(l){return l.verdict==='chase'||l.verdict==='good';}).length;
    h+='<div class="pbvs-card" style="display:flex;flex-wrap:wrap;gap:8px;align-items:center">'+
        _sc(shown.length,'shown','#c9a962')+_sc(_clean,'clean title','#22c55e')+_sc(_salv,'salvage/rebuilt','#f59e0b')+_sc(_unk,'title: verify','#ef4444')+_sc(_bnow,'buy-now','#c9a962')+_sc(_chase,'chase-rated','#22c55e')+
        (_hidden>0?'<span class="pbvs-hint" style="margin-left:auto">'+_hidden+' hidden by &#8804;3-day filter &middot; <button class="pbvs-srcbtn" data-act="showall" style="padding:3px 9px">Show all</button></span>':'')+
      '</div>';

    // filters
    h+='<div class="pbvs-card"><div class="pbvs-row">'+
        fldSel('Make', 'fMake', [''].concat(makes))+
        fldSel('Model','fModel',[''].concat(models))+
        fldSel('Year', 'fYear', [''].concat(years))+
        '<button class="pbvs-srcbtn" data-act="clearfilter">Clear</button>'+
      '</div></div>';

    if(!shown.length){
      h+='<div class="pbvs-empty">No leads match. Turn off "Actionable only" or clear filters to see everything viable.</div>';
    } else {
      h+='<div class="pbvs-grid pbvs-leadgrid">'+shown.map(leadCard).join('')+'</div>';
    }
    body.innerHTML=h;
    syncSelects();
  }

  function leadCard(l){
    var vd=VERDICT[l.verdict]||VERDICT.watch, du=daysUntil(l.saleDate);
    var when = (l.priceType==='buynow'||l.priceType==='bin') ? 'Buy-Now available'
             : (du===null ? 'Not yet scheduled' : (du<0?'sale passed':(du===0?'sells TODAY':'sells in '+du+' day'+(du===1?'':'s'))));
    var price = l.price ? ('$'+Number(l.price).toLocaleString('en-US')+(l.priceType==='buynow'||l.priceType==='bin'?' buy-now':' bid')) : 'no bid yet';
    var facts=[];
    // ALWAYS show title status (color-coded): green=clean, amber=salvage/rebuilt, red=unknown/verify
    var _tc = /clean/i.test(l.title||'') ? 'border-color:rgba(34,197,94,.45);color:#22c55e'
            : (l.title ? 'border-color:rgba(245,158,11,.5);color:#f59e0b'
            : 'border-color:rgba(239,68,68,.5);color:#ef4444');
    facts.push('<span class="pbvs-pill" style="font-weight:700;'+_tc+'">'+(l.title?esc(l.title)+' title':'title: verify')+'</span>');
    if(l.miles!=null) facts.push('<span class="pbvs-pill">'+Number(l.miles).toLocaleString('en-US')+' mi'+(l.milesActual===false?' (not actual)':'')+'</span>');
    if(l.keys) facts.push('<span class="pbvs-pill">keys</span>');
    if(l.runDrive) facts.push('<span class="pbvs-pill">run &amp; drive</span>');
    if(l.airbags==='intact') facts.push('<span class="pbvs-pill" style="border-color:rgba(34,197,94,.4);color:#22c55e">airbags intact</span>');
    facts.push('<span class="pbvs-pill">'+esc(l.pool)+'</span>');
    return '<div class="pbvs-lead">'+
      '<button class="pbvs-heart'+(watchHas(l.id)?' on':'')+'" data-act="heart" data-id="'+esc(l.id)+'" title="Save to watchlist + get alerts">'+(watchHas(l.id)?'&#10084;':'&#9825;')+'</button>'+
      '<div class="pbvs-title">'+esc(vehStr(l))+' <span class="pbvs-badge" style="color:'+vd.c+';background:'+vd.bg+';border:1px solid '+vd.b+'">'+vd.t+'</span></div>'+
      '<div class="pbvs-meta"><b>'+esc(l.damage)+'</b> &middot; '+esc(l.location)+' &middot; <b>'+price+'</b> &middot; '+when+'</div>'+
      '<div>'+facts.join(' ')+'</div>'+
      (l.note?'<div class="pbvs-note">'+l.note+'</div>':'')+
      '<div class="pbvs-src"><a class="gold" href="'+esc(l.url)+'" target="_blank" rel="noopener">Open listing &#8599;</a>'+
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
      return '<span class="pbvs-chip'+(on?' on':'')+'" data-act="fleetpick" data-k="'+esc(f.key)+'">'+esc(f.year+' '+f.make+' '+f.model)+'</span>';
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
    h+='<div class="pbvs-card"><div class="pbvs-sec">Daily hunt criteria (makes / models / years being searched)</div>'+
       '<div class="pbvs-hint" style="margin-bottom:8px">These drive Current Leads. Add any real make/model/year; each row gets one-click live searches across the pools.</div>'+
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
      else if(act==='backleads'||act==='refresh'){ if(act==='refresh') fetchFeed(true); PBVS.sub='leads'; _lsSet(LSK_SUB,'leads'); render(); }
      else if(act==='toggleact'){ PBVS.actionable=!PBVS.actionable; _lsSet(LSK_ACT,PBVS.actionable); renderLeads(); }
      else if(act==='showall'){ PBVS.actionable=false; _lsSet(LSK_ACT,false); renderLeads(); }
      else if(act==='clearfilter'){ PBVS.fMake=PBVS.fModel=PBVS.fYear=''; renderLeads(); }
      else if(act==='heart'){ toggleHeart(t.getAttribute('data-id')); }
      else if(act==='fleetpick'){ pickFleet(t.getAttribute('data-k')); }
      else if(act==='vindecode'){ doVinDecode(); }
      else if(act==='partsgo'){ runPartsSearch(); }
      else if(act==='copy'){ doCopy(t); }
      else if(act==='addcrit'){ addCrit(); }
      else if(act==='delcrit'){ PBVS.criteria.splice(+t.getAttribute('data-i'),1); saveCrit(); renderKit(); }
    });
    host.addEventListener('keydown', function(e){
      if(e.key!=='Enter') return;
      if(e.target && e.target.id==='psPart'){ e.preventDefault(); runPartsSearch(); }
      else if(e.target && e.target.id==='psVin'){ e.preventDefault(); doVinDecode(); }
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
    var r=el('psResults'); if(r) r.innerHTML=html;
  }

  function toggleHeart(id){
    var i=-1; PBVS.watch.forEach(function(w,ix){ if(w.id===id) i=ix; });
    if(i>=0){ PBVS.watch.splice(i,1); _toast('Removed from watchlist'); }
    else{
      var l=activeFeed().concat(SEED_LEADS).filter(function(x){return x.id===id;})[0];
      if(l){ var c=JSON.parse(JSON.stringify(l)); c.addedAt=Date.now(); PBVS.watch.push(c); _toast('&#10004; Watching -- you\'ll be alerted on changes'); }
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
  function fetchFeed(manual){
    var w=_worker(); if(!w){ if(manual) _toast('Showing starter set'); return; }
    try{
      fetch(w+'/vehicle-leads?_='+Date.now(),{cache:'no-store'})
        .then(function(r){ return r.ok?r.json():null; })
        .then(function(d){
          var arr=(d&&(d.leads||d.vehicles))||null;
          if(arr&&arr.length){ PBVS.leads=arr; PBVS.feedSrc='live'; PBVS.feedAt=Date.now(); diffWatch(arr); if(PBVS.sub==='leads') renderLeads(); if(manual) _toast('&#10004; Feed refreshed ('+arr.length+')'); }
          else if(manual){ _toast('No live feed yet -- showing starter set'); }
        }).catch(function(){ if(manual) _toast('Feed offline -- showing starter set'); });
    }catch(e){}
  }
  // local diff so watched cars alert you the moment the feed changes (pre-worker-cron)
  function diffWatch(arr){
    if(!PBVS.watch.length) return; var byId={}; arr.forEach(function(l){ byId[l.id]=l; });
    var changed=[];
    PBVS.watch.forEach(function(w){
      var n=byId[w.id]; if(!n) return;
      if(Number(n.price)!==Number(w.price)) changed.push(vehStr(w)+': price '+ (w.price?('$'+w.price):'-') +' -> '+(n.price?('$'+n.price):'-'));
      else if(n.saleDate!==w.saleDate) changed.push(vehStr(w)+': sale date '+w.saleDate+' -> '+n.saleDate);
      if(n.price!=null) w.price=n.price; if(n.saleDate) w.saleDate=n.saleDate;
    });
    if(changed.length){ _lsSet(LSK_WATCH,PBVS.watch); _toast('&#128276; Watchlist: '+changed[0]+(changed.length>1?(' (+'+(changed.length-1)+' more)'):'')); }
  }

  // ---- public entry ----------------------------------------------------------
  window.renderVehSearchTab = function(){
    if((window.PB_FLAGS||{}).vehicleSearch===false){ var h=el('vehSearchContent'); if(h) h.innerHTML='<div class="pbvs-empty">Vehicle/Parts Search is turned off.</div>'; return; }
    render();
    if(!PBVS.__feedTried){ PBVS.__feedTried=true; fetchFeed(false); }
  };
})();

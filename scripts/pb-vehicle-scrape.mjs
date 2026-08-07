#!/usr/bin/env node
// ============================================================================
//  PB Vehicle-lead scraper -- runs from a NON-Cloudflare IP (GitHub Actions or
//  the owner's Mac) because salvagereseller (behind Cloudflare) blocks the
//  Cloudflare Worker's egress IP. It reads the owner's hunt criteria from the
//  worker, scrapes the salvagereseller make pages, and POSTs the parsed leads
//  back to the worker's /vehicle-leads/seed endpoint.
//
//  Env:
//    DASHBOARD_SECRET  (required) -- same value as the worker's DASHBOARD_SECRET
//    WORKER_URL        (optional) -- defaults to the PB booking worker
//
//  Node 18+ (global fetch). No dependencies.
// ============================================================================
const WORKER = (process.env.WORKER_URL || 'https://pb-booking.prestigeblackcorp.workers.dev').replace(/\/+$/, '');
const SECRET = process.env.DASHBOARD_SECRET || '';
const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';
const YEAR_MIN = 2015;
const MAKE_CAP = 60;
const OUT_CAP = 800;

const DRYRUN = process.env.PB_SCRAPE_DRYRUN === '1';   // scrape + print, no /state read, no /seed POST
if (!SECRET && !DRYRUN) { console.error('FATAL: DASHBOARD_SECRET env var is required'); process.exit(1); }

// ---- ported worker logic (must stay in sync with prestige-black-booking-worker.js) ----
const EXOTIC_MAKES = ['ferrari','lamborghini','mclaren','aston','bentley','rolls','maserati','maybach','bugatti','koenigsegg','pagani','lotus'];
const STATES = new Set('AL AK AZ AR CA CO CT DE FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY DC PR'.split(' '));
const num = s => { const n = Math.round(Number(String(s == null ? '' : s).replace(/[^0-9.]/g, '')) || 0); return isFinite(n) ? n : 0; };
function isExotic(l) {
  const mk = String(l && l.make || '').toLowerCase(); if (!mk) return false;
  const md = String(l && l.model || '').toLowerCase();
  if (mk === 'porsche') return /911|918|carrera gt|718|cayman gt|boxster spyder/.test(md) && !/panamera|macan|cayenne/.test(md);
  if (mk === 'audi') return /r8/.test(md);
  if (mk === 'nissan') return /gt-?r/.test(md);
  if (mk === 'acura' || mk === 'honda') return /nsx/.test(md);
  if (mk === 'chevrolet') return /corvette|z06|zr1/.test(md);
  if (mk === 'ford') return /\bgt\b/.test(md);
  if (mk.indexOf('maybach') >= 0) return true;
  if (mk.indexOf('mercedes') >= 0) return /amg\s*gt|sls|gt\s*63|maybach/.test(md);
  return EXOTIC_MAKES.some(x => mk.indexOf(x) === 0);
}
const isClean = l => /clean/i.test(String(l && l.title || ''));
function vsTitle(raw) {
  const t = String(raw || '').trim(); if (!t) return '';
  const up = t.toUpperCase();
  if (/CLEAN|CLEAR/.test(up)) return 'Clean';
  if (/REBUIL|PRIOR/.test(up)) return 'Rebuilt';
  if (/FLOOD|WATER/.test(up)) return 'Flood';
  if (/\bBURN\b|\bFIRE\b/.test(up)) return 'Fire';
  if (/NON.?REPAIR|JUNK|PARTS ONLY|DISMANTL|SCRAP|DESTRUCTION/.test(up)) return 'Non-repairable';
  const toks = up.split(/\s+/).filter(Boolean); const code = toks[toks.length - 1];
  const prevIsState = toks.length >= 2 && STATES.has(toks[toks.length - 2]);
  if (STATES.has(code) && !prevIsState) return '';
  if (/^(CL|CD|CE)$/.test(code)) return 'Clean';
  if (/^(RB|RC|PR)$/.test(code)) return 'Rebuilt';
  if (/^(FV|FL|FD|WA)$/.test(code)) return 'Flood';
  if (/^(BU|FI|BN)$/.test(code)) return 'Fire';
  return 'Salvage';
}
function passesCaps(l, cfg) {
  if (!l) return false;
  if (cfg.maxMiles > 0 && Number(l.miles || 0) > cfg.maxMiles) return false;
  if (cfg.titleWant) { if (String(l.title || '').toLowerCase().indexOf(String(cfg.titleWant).toLowerCase()) < 0) return false; }
  else if (cfg.requireCleanTitle && !isClean(l)) return false;
  if (cfg.excludeDamage) { const ex = String(cfg.excludeDamage).toLowerCase().split(/[\s,]+/).filter(Boolean); const d = String(l.damage || '').toLowerCase(); for (const k of ex) if (k && d.indexOf(k) >= 0) return false; }
  return true;
}
function isSteal(l, cfg, isTarget) {
  if (!l || Number(l.year || 0) < cfg.yearMin) return false;
  if (!isExotic(l) && !(typeof isTarget === 'function' && isTarget(l))) return false;
  const cap = cfg.maxBuyNow > 0 ? cfg.maxBuyNow : 30000;
  const p = Number(l.buyNow || 0);
  if (!(p > 0 && p <= cap)) return false;
  return passesCaps(l, cfg);
}

// ---- fetch one make page, retrying transient failures + soft-block empties ----
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
async function fetchMake(slug) {
  const url = 'https://www.salvagereseller.com/cars-for-sale/make/' + encodeURIComponent(slug);
  let last = '';
  for (let a = 0; a < 4; a++) {
    if (a > 0) await sleep(600 * a + Math.floor(Math.random() * 400));
    try {
      const ac = new AbortController(); const t = setTimeout(() => ac.abort(), 20000);
      const r = await fetch(url, { headers: { 'User-Agent': UA, 'Accept': 'text/html,application/xhtml+xml', 'Accept-Language': 'en-US,en;q=0.9' }, signal: ac.signal });
      const html = r.ok ? await r.text() : '';
      clearTimeout(t);
      if (html && html.length >= 1500) { last = html; if (html.indexOf('"sku"') >= 0) return html; }
    } catch (_) {}
  }
  return last;
}

function parseMake(html, mkName, crits, yFloor, out, seen) {
  const mkTok = mkName.toLowerCase().split(/[\s-]/)[0];
  const makeWords = mkName.split(/\s+/).length;
  const blocks = html.match(/<script[^>]+ld\+json[^>]*>[\s\S]*?<\/script>/gi) || [];
  for (const rawB of blocks) {
    if (out.length >= OUT_CAP) break;
    if (rawB.indexOf('Vehicle') < 0) continue;
    const jtxt = rawB.replace(/^<script[^>]*>/i, '').replace(/<\/script>\s*$/i, '');
    let parsed; try { parsed = JSON.parse(jtxt); } catch (_) { continue; }
    const nodes = Array.isArray(parsed) ? parsed : (parsed && Array.isArray(parsed['@graph']) ? parsed['@graph'] : [parsed]);
    for (const d of nodes) {
      if (out.length >= OUT_CAP) break;
      if (!d || typeof d !== 'object' || !d.sku) continue;
      if (![].concat(d['@type'] || []).some(t => /vehicle|car/i.test(String(t)))) continue;
      const id = 'sr-' + String(d.sku); if (seen[id]) continue;
      const nm = String(d.name || '');
      const toks = nm.split(/\s+/);
      const yr = /^\d{4}$/.test(toks[0]) ? +toks[0] : 0;
      if (yr && yFloor && yr < yFloor) continue;
      let model = toks.slice((yr ? 1 : 0) + makeWords).join(' ').trim();
      if (!model) model = toks.slice(yr ? 1 : 0).join(' ').trim();
      const lead0 = { make: mkName, model };
      const wantModel = crits.some(c => c.model && model.toLowerCase().indexOf(String(c.model).toLowerCase()) >= 0);
      if (!isExotic(lead0) && !wantModel) continue;
      seen[id] = 1;
      const desc = String(d.description || '');
      const tt = /Title:\s*([A-Za-z .]+?)[.\n]/.exec(desc); const title = vsTitle(tt ? tt[1].trim() : '');
      const of = Array.isArray(d.offers) ? (d.offers[0] || {}) : (d.offers || {});
      const rawPrice = num(of.price); const isBin = rawPrice > 0;
      const ow = /Odometer:[^.\n]*?(NOT[ -]?ACTUAL|EXCEEDS|TMU|EXEMPT|ACTUAL)/i.exec(desc);
      const milesActual = ow ? (ow[1].toUpperCase().replace(/[ -]/g, '') === 'ACTUAL') : undefined;
      const odoRaw = d.mileageFromOdometer && (d.mileageFromOdometer.value != null ? d.mileageFromOdometer.value : d.mileageFromOdometer);
      const odo = (odoRaw != null && odoRaw !== '') ? (Number(String(odoRaw).replace(/[^0-9.]/g, '')) || null) : null;
      const url = String(d.url || ('https://www.salvagereseller.com/cars-for-sale/' + d.sku));
      const st = (url.split('?')[0].match(/-([a-z]{2})$/) || [])[1];
      const stU = (st && STATES.has(st.toUpperCase())) ? st.toUpperCase() : '';
      out.push({
        id, year: yr, make: mkName, model: model || mkName, pool: 'Copart',
        title, damage: d.knownVehicleDamages || '',
        price: rawPrice || 0, priceType: isBin ? 'buynow' : 'bid',
        buyNow: rawPrice, bid: isBin ? 0 : (rawPrice || 0),
        miles: odo, milesActual, location: stU, state: stU,
        image: String(((d.image && d.image.url) ? d.image.url : d.image) || '').replace('_thb.jpg', '_ful.jpg'),
        dedupKey: (yr + '|' + mkTok + '|' + String(model).toLowerCase() + '|' + d.sku).toLowerCase(),
        verdict: 'watch', saleDate: of.priceValidUntil || 'future', url,
      });
    }
  }
}

async function main() {
  // 1) read the owner's hunt criteria + config from the worker (skipped in dry-run)
  let criteria = [], cfg = { yearMin: YEAR_MIN, maxBuyNow: 30000, requireCleanTitle: false, maxMiles: 0 };
  if (!DRYRUN) {
    try {
      const r = await fetch(WORKER + '/vehicle-search/state', { headers: { Authorization: 'Bearer ' + SECRET } });
      if (r.ok) { const st = await r.json(); if (Array.isArray(st.criteria)) criteria = st.criteria; if (st.config) cfg = Object.assign(cfg, st.config); }
      else console.error('state read HTTP', r.status);
    } catch (e) { console.error('state read failed:', e.message); }
  }
  if (DRYRUN && process.env.PB_SCRAPE_MAKES) criteria = process.env.PB_SCRAPE_MAKES.split(',').map(m => ({ make: m.trim(), model: '', yearMin: YEAR_MIN }));
  if (!criteria.length) {
    console.log('no saved criteria -> using default exotic set');
    criteria = ['Ferrari','Lamborghini','McLaren','Bentley','Maserati','Rolls-Royce','Aston Martin','Porsche','Audi','Nissan','Chevrolet','Mercedes-Benz'].map(m => ({ make: m, model: '', yearMin: YEAR_MIN }));
  }

  // 2) group by make, scrape sequentially (gentle) from this non-CF IP
  const byMake = {};
  for (const c of criteria) { if (!c || !c.make) continue; const k = String(c.make).trim(); (byMake[k] = byMake[k] || []).push(c); }
  const makes = Object.keys(byMake).slice(0, MAKE_CAP);
  const out = [], seen = {};
  const isTarget = l => criteria.some(c => c && String(c.make || '').toLowerCase() === String(l.make || '').toLowerCase() && String(l.model || '').toLowerCase().indexOf(String(c.model || '').toLowerCase()) >= 0);
  let ok = 0, empty = 0;
  for (const mkName of makes) {
    if (out.length >= OUT_CAP) break;
    const crits = byMake[mkName];
    const mins = [Number(cfg.yearMin) || 0]; crits.forEach(c => { if (+c.yearMin > 0) mins.push(+c.yearMin); });
    const yFloor = Math.min.apply(null, mins.filter(v => v > 0).concat([YEAR_MIN]));
    const before = out.length;
    const html = await fetchMake(mkName.toUpperCase());
    if (!html) { empty++; console.log('  ' + mkName + ': (no data)'); continue; }
    parseMake(html, mkName, crits, yFloor, out, seen);
    ok++; console.log('  ' + mkName + ': +' + (out.length - before));
  }

  // 3) steal-tag + POST to the worker
  for (const l of out) l.steal = isSteal(l, cfg, isTarget);
  const steals = out.filter(l => l.steal).length;
  console.log('scraped ' + out.length + ' leads from ' + ok + ' makes (' + empty + ' empty); ' + steals + ' steals');
  if (DRYRUN) {
    console.log('--- DRY RUN: not seeding. Sample: ---');
    for (const l of out.slice(0, 8)) console.log('  ' + [l.year, l.make, l.model].join(' ') + ' | ' + (l.buyNow ? '$' + l.buyNow + ' BIN' : (l.bid ? '$' + l.bid + ' bid' : '-')) + ' | ' + (l.title || '?') + (l.steal ? ' | STEAL' : '') + ' | ' + l.state);
    return;
  }
  if (!out.length) { console.error('0 leads -> NOT seeding (keeps last-good feed)'); process.exit(2); }

  const post = await fetch(WORKER + '/vehicle-leads/seed', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + SECRET },
    body: JSON.stringify({ leads: out, scraped: out.length, source: 'external' }),
  });
  if (!post.ok) { console.error('seed POST failed HTTP', post.status, await post.text().catch(() => '')); process.exit(3); }
  console.log('seeded OK:', JSON.stringify(await post.json()));
}
main().catch(e => { console.error('FATAL', e && (e.stack || e.message || e)); process.exit(1); });

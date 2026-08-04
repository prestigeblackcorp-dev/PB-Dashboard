// GATE: every page the worker serves with an INLINE <script> must emit JavaScript that actually parses.
//
// Why this exists: parsing worker.js proves the FILE is valid, but each of these pages builds its script inside a template
// literal. A quote escaped once instead of twice (\' where \\' was meant) resolves to a bare quote, which silently ends a
// JS string early -- worker.js still parses perfectly, while the page the customer receives dies at parse time. That exact
// bug shipped in the customer portal and left every renter staring at "Loading..." until it was found by hand.
//
// So we do what the worker does: resolve each template, then parse the emitted script. ${...} interpolations are neutralized
// (we are checking string/escape STRUCTURE, not runtime values). No network, no D1 -- pure source analysis.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(HERE, '..', 'worker.js'), 'utf8');

// Each entry: a template literal that becomes an inline <script> on a page a real person loads.
const PAGES = [
  { name: 'public booking + checkout page', open: '  var js = `', anchor: 'function _bookPageHtml' },
  { name: 'customer portal', open: '  var js = `', anchor: 'function _portalPageHtml' },
  { name: 'password reset', open: '        const rScript = `', anchor: null },
];

let failures = 0;
const fail = (m) => { console.error('FAIL: ' + m); failures++; };

// COVERAGE: this gate is only worth what it covers. If someone adds a 4th served page with an inline script and
// forgets to list it above, that page silently inherits none of these checks -- exactly how the portal outage went
// unnoticed. So count the _pageDoc() calls that actually pass a script and require the list to keep up.
function splitArgs(src, open) {          // top-level comma split from the '(' at `open`
  const out = []; let d = 0, start = open + 1, q = null;
  for (let i = open + 1; i < src.length; i++) {
    const c = src[i], prev = src[i - 1];
    if (q) { if (c === q && prev !== '\\') q = null; continue; }
    if (c === "'" || c === '"' || c === '`') { q = c; continue; }
    if (c === '(' || c === '[' || c === '{') d++;
    else if (c === ')' || c === ']' || c === '}') { if (d === 0 && c === ')') { out.push(src.slice(start, i).trim()); return out; } d--; }
    else if (c === ',' && d === 0) { out.push(src.slice(start, i).trim()); start = i + 1; }
  }
  return out;
}
const scripted = [];
for (let i = src.indexOf('_pageDoc('); i >= 0; i = src.indexOf('_pageDoc(', i + 1)) {
  if (/[A-Za-z0-9_$.]/.test(src[i - 1] || '')) continue;                 // member access / longer identifier
  if (/function\s+$/.test(src.slice(Math.max(0, i - 12), i))) continue;   // the declaration itself, not a call
  const args = splitArgs(src, i + '_pageDoc'.length);
  const script = args[3];
  if (script === undefined || script === "''" || script === '""' || script === '``') continue;   // static page
  scripted.push({ line: src.slice(0, i).split('\n').length, arg: script.slice(0, 40) });
}
if (scripted.length !== PAGES.length) {
  fail(`served-page COVERAGE drift: ${scripted.length} _pageDoc call(s) pass an inline script but this test lists ` +
       `${PAGES.length}.\n       Scripted pages: ` + scripted.map((s) => `line ${s.line} (${s.arg})`).join(', ') +
       `\n       Add the new page to PAGES so it gets these checks too.`);
} else {
  console.log(`ok  coverage -- ${scripted.length} served page(s) pass an inline script, all ${PAGES.length} are listed here`);
}

for (const p of PAGES) {
  const base = p.anchor ? src.indexOf(p.anchor) : 0;
  if (p.anchor && base < 0) { fail(`${p.name}: anchor ${p.anchor} not found -- did the function get renamed? Update test/pages.mjs.`); continue; }
  let i = src.indexOf(p.open, base);
  if (i < 0) { fail(`${p.name}: inline-script template not found -- update test/pages.mjs so this page stays covered.`); continue; }
  i += p.open.length;

  let j = i;                                   // template ends at the first UNescaped backtick
  while (j < src.length) { if (src[j] === '`' && src[j - 1] !== '\\') break; j++; }
  const tpl = src.slice(i, j);
  const safe = tpl.replace(/\$\{[^{}]*\}/g, '"X"');

  let emitted;
  try { emitted = eval('`' + safe + '`'); }    // resolve escapes exactly as the worker's template literal does
  catch (e) { fail(`${p.name}: template does not resolve -- ${e.message}`); continue; }

  try { new Function(emitted); }                // parse what the browser would receive
  catch (e) {
    fail(`${p.name}: EMITTED SCRIPT DOES NOT PARSE -- ${e.message}\n` +
         `       This page is BROKEN for every visitor. Usual cause: a quote escaped once (\\') inside a JS string that\n` +
         `       needs a doubled \\\\' in the template. Compare against a working sibling handler on the same page.`);
    continue;
  }

  // The precise footprint of the outage bug: \' resolved to a bare quote, producing ('' + x + '') in the emitted source.
  if (emitted.includes("(''+") || emitted.includes("('' +")) {
    fail(`${p.name}: emitted script contains a bare empty-string concat -- a single-escaped quote almost certainly collapsed.`);
    continue;
  }
  // DEAD CONTROLS: parsing proves the script is valid; it does NOT prove every button wired with onclick="doThing()"
  // has a doThing. A renamed or dropped handler leaves a control that looks alive and does nothing when a real
  // customer taps it -- silent, and invisible to every other gate we run.
  const defined = new Set();
  for (const m of emitted.matchAll(/function\s+([A-Za-z_$][\w$]*)\s*\(/g)) defined.add(m[1]);
  for (const m of emitted.matchAll(/(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*function/g)) defined.add(m[1]);
  const GLOBALS = new Set(['alert','confirm','prompt','fetch','parseInt','parseFloat','String','Number','Boolean',
    'Array','Object','JSON','Math','Date','isNaN','encodeURIComponent','decodeURIComponent','setTimeout',
    'clearTimeout','setInterval','console','window','document','location','history','event','Intl','FormData',
    'FileReader','Image','Blob','URL','Promise','RegExp','Error','if','for','while','return','typeof','this','new']);

  const ATTR = /\son(?:click|change|input|submit|keydown|keyup|blur|focus|load|error)\s*=/g;
  const CALL = /\son(?:click|change|input|submit|keydown|keyup|blur|focus|load|error)\s*=\s*(?:\\?["'])?\s*([A-Za-z_$][\w$]*)\s*\(/g;
  const total = (emitted.match(ATTR) || []).length;
  const calls = [...emitted.matchAll(CALL)];
  // If some handler is built by concatenation we cannot resolve it statically -- say so rather than imply full cover.
  if (calls.length < total) {
    console.log(`    note: ${total - calls.length} of ${total} handler(s) on ${p.name} are built dynamically and were not checked`);
  }
  const missing = [...new Set(calls.map((m) => m[1]))].filter((n) => !GLOBALS.has(n) && !defined.has(n));
  if (missing.length) {
    fail(`${p.name}: inline handler(s) call a function this page never defines -- the control is DEAD for every\n` +
         `       visitor who taps it: ${missing.join(', ')}`);
    continue;
  }

  console.log(`ok  ${p.name} -- script parses (${emitted.length} bytes), ${calls.length}/${total} inline handlers all resolve`);
}

if (failures) { console.error(`\n${failures} inline-script page(s) would be broken for real users. Not deploying.`); process.exit(1); }
console.log(`\nAll ${PAGES.length} served pages emit parseable JavaScript, with no dead inline controls.`);

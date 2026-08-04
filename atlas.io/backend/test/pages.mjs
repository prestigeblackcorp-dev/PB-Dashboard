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
  console.log(`ok  ${p.name} -- emitted script parses (${emitted.length} bytes)`);
}

if (failures) { console.error(`\n${failures} inline-script page(s) would be broken for real users. Not deploying.`); process.exit(1); }
console.log(`\nAll ${PAGES.length} served pages emit parseable JavaScript.`);

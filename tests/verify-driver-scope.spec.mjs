// Headless CI runner for tests/verify-driver-scope.selftest.html.
// Serves the repo root over http (Chromium blocks file:// iframes cross-origin), loads the self-test page,
// waits for its assertions to finish, and exits non-zero if ANY check fails -- so a future edit that
// reintroduces the primary->driver ID leak (or breaks driver-scoping in any verify path) fails the build.
//
// Run:  node tests/verify-driver-scope.spec.mjs        (from the repo root)
import { chromium } from 'playwright';
import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// repo root = parent of this tests/ dir, regardless of the working directory the runner is invoked from
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CT = { '.html':'text/html', '.js':'text/javascript', '.mjs':'text/javascript', '.json':'application/json', '.css':'text/css', '.png':'image/png', '.jpg':'image/jpeg', '.svg':'image/svg+xml' };

const server = http.createServer((req, res) => {
  let p = decodeURIComponent((req.url || '/').split('?')[0]);
  if (p === '/') p = '/index.html';
  const fp = path.join(ROOT, p);
  if (!fp.startsWith(ROOT)) { res.writeHead(403); res.end('forbidden'); return; }
  fs.readFile(fp, (e, buf) => {
    if (e) { res.writeHead(404); res.end('not found'); return; }
    res.writeHead(200, { 'Content-Type': CT[path.extname(fp)] || 'application/octet-stream' });
    res.end(buf);
  });
});

const fail = (msg) => { console.error('FAIL: ' + msg); process.exitCode = 1; };

await new Promise(r => server.listen(0, r));
const port = server.address().port;
const browser = await chromium.launch();
try {
  const page = await browser.newPage();
  await page.goto(`http://localhost:${port}/tests/verify-driver-scope.selftest.html`, { waitUntil: 'load', timeout: 60000 });
  await page.waitForFunction(() => window.__selftest && (window.__selftest.total > 0 || window.__selftest.error), null, { timeout: 45000 });
  const res = await page.evaluate(() => window.__selftest);
  console.log(JSON.stringify(res, null, 2));
  if (!res) fail('no results object');
  else if (res.error) fail('harness error: ' + res.error);
  else if (!res.allPass) fail(res.fail + ' verify driver-scope check(s) failed');
  else console.log(`\nAll ${res.pass} verify driver-scope checks passed.`);
} catch (e) {
  fail('runner exception: ' + (e && (e.stack || e.message) || e));
} finally {
  await browser.close();
  server.close();
}
process.exit(process.exitCode || 0);

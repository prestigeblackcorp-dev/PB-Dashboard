#!/usr/bin/env python3
"""
ATLAS PARITY CHECK - verify the invariants that keep the dashboard, the worker,
and a deploy in sync. Run before/after any pricing or deploy change; wire it into
CI to gate a deploy.

Why this exists: Atlas keeps prices consistent by a "parity contract" - a handful
of pricing functions are maintained BYTE-IDENTICAL in two files by hand (a comment
asks you to, nothing enforces it). Edit one copy and forget the other and the
dashboard quotes one price while the worker charges another - silently, with no
error. The same class of drift hits the build-stamp lockstep (health never flips)
and the atlas.html/index.html mirror. This checks all of it automatically.

CHECKS
  1. SMART-PRICING PARITY  _smartRateMult / _dayFactor / _inSeason / _ymdNum must be
     logic-identical (whitespace-normalized) between the client (atlas.io/atlas.html)
     and the worker (atlas.io/backend/worker.js). Drift here = quote != charge.
  2. BUILD-STAMP LOCKSTEP   worker ATLAS_BUILD == smoke EXPECT_BUILD ==
     admin ATLAS_EXPECT_BUILD. Drift = /api/health never flips to the new build and
     the admin console nags "out of date".
  3. CLIENT MIRROR          atlas.io/atlas.html and atlas.io/index.html byte-identical,
     and their APP_VERSION matches.
  4. ASCII PURITY           atlas.html, index.html, admin.html: 0 non-ASCII bytes
     (the client source is held to pure ASCII).

Exit code 1 if any check FAILS.
Usage:  python3 tools/atlas-parity-check.py
"""
import os, re, sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ATLAS = os.path.join(REPO, "atlas.io", "atlas.html")
INDEX = os.path.join(REPO, "atlas.io", "index.html")
ADMIN = os.path.join(REPO, "atlas.io", "admin.html")
WORKER = os.path.join(REPO, "atlas.io", "backend", "worker.js")
SMOKE = os.path.join(REPO, "atlas.io", "backend", "test", "smoke.mjs")

PARITY_FNS = ["_smartRateMult", "_dayFactor", "_inSeason", "_ymdNum"]

GREEN, RED, YEL, DIM, OFF = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"
if not sys.stdout.isatty():
    GREEN = RED = YEL = DIM = OFF = ""

fails = []
def ok(msg):   print(f"  {GREEN}PASS{OFF}  {msg}")
def bad(msg):  print(f"  {RED}FAIL{OFF}  {msg}"); fails.append(msg)
def info(msg): print(f"  {DIM}{msg}{OFF}")

def read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return None

def extract_fn(src, name):
    """Return the source of `function name(...) { ... }` by brace matching, or None."""
    if src is None:
        return None
    m = re.search(r"function\s+" + re.escape(name) + r"\s*\(", src)
    if not m:
        return None
    i = m.start()
    j = src.find("{", i)
    if j < 0:
        return None
    depth, k = 0, j
    while k < len(src):
        c = src[k]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[i:k + 1]
        k += 1
    return None

def norm(s):
    return re.sub(r"\s+", " ", s).strip() if s is not None else None

# ---------------------------------------------------------------- 1. smart-pricing parity
def check_parity():
    print(f"{YEL}1. Smart-pricing parity (client == worker){OFF}")
    a_src, w_src = read(ATLAS), read(WORKER)
    if a_src is None: bad(f"cannot read {ATLAS}"); return
    if w_src is None: bad(f"cannot read {WORKER}"); return
    for name in PARITY_FNS:
        a, w = extract_fn(a_src, name), extract_fn(w_src, name)
        if a is None: bad(f"{name}: not found in client"); continue
        if w is None: bad(f"{name}: not found in worker"); continue
        if norm(a) == norm(w):
            ok(f"{name} identical  {DIM}(client {len(a)}c / worker {len(w)}c){OFF}")
        else:
            bad(f"{name} DRIFTED - dashboard quote will not match the worker charge")

# ---------------------------------------------------------------- 2. build-stamp lockstep
def _grab(path, pat):
    src = read(path)
    if src is None: return None
    m = re.search(pat, src)
    return m.group(1) if m else None

def check_buildstamp():
    print(f"{YEL}2. Build-stamp lockstep{OFF}")
    w = _grab(WORKER, r"ATLAS_BUILD\s*=\s*['\"]([\d.a-z]+)['\"]")
    s = _grab(SMOKE, r"EXPECT_BUILD\s*=\s*['\"]([\d.a-z]+)['\"]")
    a = _grab(ADMIN, r"ATLAS_EXPECT_BUILD\s*=\s*['\"]([\d.a-z]+)['\"]")
    info(f"worker ATLAS_BUILD={w}  smoke EXPECT_BUILD={s}  admin ATLAS_EXPECT_BUILD={a}")
    if None in (w, s, a):
        bad("could not read all three build stamps"); return
    if w == s == a:
        ok(f"all three stamps == {w}")
    else:
        bad("build stamps DRIFTED - /api/health will not flip / admin nags 'out of date'")

# ---------------------------------------------------------------- 3. client mirror
def check_mirror():
    print(f"{YEL}3. Client mirror (atlas.html == index.html){OFF}")
    a, i = read(ATLAS), read(INDEX)
    if a is None or i is None: bad("cannot read atlas.html and/or index.html"); return
    if a == i:
        ok("atlas.html and index.html are byte-identical")
    else:
        bad("atlas.html != index.html - the two client copies have diverged")
    va = _grab(ATLAS, r"APP_VERSION\s*=\s*['\"]([\d.a-z]+)['\"]")
    vi = _grab(INDEX, r"APP_VERSION\s*=\s*['\"]([\d.a-z]+)['\"]")
    info(f"APP_VERSION  atlas={va}  index={vi}")
    if va and va == vi:
        ok(f"APP_VERSION matches ({va})")
    else:
        bad("APP_VERSION mismatch between atlas.html and index.html")

# ---------------------------------------------------------------- 4. ASCII purity
def check_ascii():
    print(f"{YEL}4. ASCII purity (client source is pure ASCII){OFF}")
    for label, path in [("atlas.html", ATLAS), ("index.html", INDEX), ("admin.html", ADMIN)]:
        try:
            raw = open(path, "rb").read()
        except Exception:
            bad(f"{label}: cannot read"); continue
        non = [b for b in raw if b > 0x7F]
        if not non:
            ok(f"{label}: 0 non-ASCII bytes")
        else:
            # locate first offending line for a helpful message
            line = raw[:raw.find(bytes([non[0]]))].count(b"\n") + 1
            bad(f"{label}: {len(non)} non-ASCII byte(s), first near line {line}")

def main():
    print(f"\n{YEL}=== Atlas parity check ==={OFF}  {DIM}{REPO}{OFF}\n")
    check_parity();     print()
    check_buildstamp(); print()
    check_mirror();     print()
    check_ascii();      print()
    if fails:
        print(f"{RED}FAILED{OFF} - {len(fails)} problem(s):")
        for f in fails:
            print(f"  {RED}-{OFF} {f}")
        print()
        sys.exit(1)
    print(f"{GREEN}ALL PARITY CHECKS PASSED{OFF} - safe to deploy.\n")
    sys.exit(0)

if __name__ == "__main__":
    main()

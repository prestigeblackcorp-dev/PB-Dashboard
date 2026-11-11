#!/usr/bin/env python3
"""
atlas-client-guard-check.py -- pre-push validator for the Atlas worker test
suite's CLIENT-source guards.

atlas.io/backend/test/routes.mjs asserts that specific literals exist (or do NOT
exist) in the CLIENT bundle atlas.html via `/regex/.test(_ATLAS_SRC...)`,
`!/regex/.test(_ATLAS_SRC...)`. These are evaluated by CI (node test/routes.mjs)
but are NOT covered by atlas-guard-check.py (which only checks the _WORKER_SRC
guards). A client edit -- e.g. inserting a new name into the Atlas export list --
can break one of these adjacency guards and silently fail the worker deploy
(the worker stays on the prior build while the client Pages deploy succeeds).

This script reproduces CI's _ATLAS_SRC guard evaluation LOCALLY so that drift is
caught before the push, without needing Node. Run it alongside
atlas-guard-check.py + atlas-parity-check.py as part of the pre-deploy gate.

Usage:  python3 tools/atlas-client-guard-check.py [repo-root]
Exit 0 = every client guard matches; exit 1 = one or more would fail in CI.
"""
import os, re, sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else '.'
ATLAS = open(os.path.join(ROOT, 'atlas.io/atlas.html'), encoding='utf-8').read()
SRC = open(os.path.join(ROOT, 'atlas.io/backend/test/routes.mjs'), encoding='utf-8').read().splitlines()


def scan(line):
    """Yield (regex_body, negated, var) for each /.../.test(VAR) on a line,
    skipping string literals and // comments, honoring a leading ! as negation."""
    out = []; i = 0; n = len(line)
    while i < n:
        c = line[i]
        if c in '"\'`':                       # skip a string literal
            q = c; i += 1
            while i < n:
                if line[i] == '\\': i += 2; continue
                if line[i] == q: i += 1; break
                i += 1
            continue
        if c == '/' and i + 1 < n and line[i+1] == '/':   # // line comment
            break
        if c == '/':                          # a regex literal
            neg = line[:i].rstrip().endswith('!')
            j = i + 1; body = ''
            while j < n:
                if line[j] == '\\': body += line[j:j+2]; j += 2; continue
                if line[j] == '[':            # char class -- / is literal inside
                    while j < n and line[j] != ']':
                        if line[j] == '\\': body += line[j:j+2]; j += 2; continue
                        body += line[j]; j += 1
                    if j < n: body += line[j]; j += 1
                    continue
                if line[j] == '/': break
                body += line[j]; j += 1
            k = j + 1
            while k < n and line[k].isalpha(): k += 1   # skip flags
            m = re.match(r'\s*\.test\(\s*(_[A-Za-z0-9_]+)', line[k:])
            out.append((body, neg, m.group(1) if m else None)); i = k; continue
        i += 1
    return out


fails = []; checked = 0; skipped = 0
for ln, line in enumerate(SRC, 1):
    if '_ATLAS_SRC' not in line:
        continue
    for body, neg, var in scan(line):
        if not var or not var.startswith('_ATLAS_SRC'):
            continue
        checked += 1
        try:
            found = re.search(body, ATLAS) is not None
        except re.error:
            skipped += 1; continue       # a JS-only regex python can't compile
        if neg and found:
            fails.append((ln, 'NEGATIVE but present', body))
        if (not neg) and (not found):
            fails.append((ln, 'POSITIVE but missing', body))

print('=== Atlas CLIENT-guard check ===  routes.mjs vs atlas.html')
print('client (_ATLAS_SRC) guards checked:', checked, ('(%d uncompilable skipped)' % skipped if skipped else ''))
if fails:
    print('FAIL (%d) -- these guards would break CI:' % len(fails))
    for ln, why, body in fails:
        print('  routes.mjs:%d  %s -> /%s/' % (ln, why, body[:100]))
    print('\nFix: update the guard in routes.mjs to the new client literal, OR revert the client change.')
    sys.exit(1)
print('ALL CLIENT GUARDS PASS -- safe to push.')

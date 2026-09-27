#!/usr/bin/env python3
"""
atlas-guard-check.py -- pre-push validator for the Atlas worker's source-guard tests.

The route tests in atlas.io/backend/test/routes.mjs assert that specific literals
exist (or do NOT exist) in worker.js via `/regex/.test(_WORKER_SRC)`,
`!/regex/.test(_WORKER_SRC)`, and `(_WORKER_SRC.match(/regex/g)||[]).length === N`.

Whenever a worker.js edit changes a line an EARLIER guard asserted verbatim, that
guard silently breaks and CI fails on the next push (this has bitten builds
12f / 12k / 12p / 12q). This script reproduces CI's guard evaluation LOCALLY so
the drift is caught before the push, without needing Node.

Usage:  python3 tools/atlas-guard-check.py [path-to-backend-dir]
        (defaults to ./atlas.io/backend)

Exit 0 = every guard matches; exit 1 = one or more guards would fail in CI.
It reports each failing guard's line, expectation, and actual match count.

NOTE: this validates the SOURCE-GUARD (regex-vs-worker) assertions only. It does
NOT run the behavioral (mock-D1) tests -- CI is still the authority for those.
"""
import os, re, sys

def scan_regexes(line):
    """Yield (regex_body, negated) for each /.../ literal on a line, skipping
    strings and line comments, and noting a preceding `!` (negative assertion)."""
    out = []; i = 0; n = len(line)
    while i < n:
        c = line[i]
        if c in '"\'`':                      # skip a string literal
            q = c; i += 1
            while i < n:
                if line[i] == '\\': i += 2; continue
                if line[i] == q: i += 1; break
                i += 1
            continue
        if c == '/' and i + 1 < n and line[i+1] == '/':   # // line comment
            break
        if c == '/':                         # a regex literal
            j = i - 1
            while j >= 0 and line[j].isspace(): j -= 1
            negated = (j >= 0 and line[j] == '!')
            k = i + 1; in_class = False; body = ''
            while k < n:
                if line[k] == '\\': body += line[k:k+2]; k += 2; continue
                if line[k] == '[': in_class = True
                elif line[k] == ']': in_class = False
                elif line[k] == '/' and not in_class: break
                body += line[k]; k += 1
            out.append((body, negated, i, k))
            i = k + 1
            while i < n and line[i].isalpha(): i += 1   # regex flags
            continue
        i += 1
    return out

def main():
    backend = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.getcwd(), 'atlas.io', 'backend')
    worker = os.path.join(backend, 'worker.js')
    routes = os.path.join(backend, 'test', 'routes.mjs')
    if not (os.path.exists(worker) and os.path.exists(routes)):
        print('ERROR: could not find worker.js / test/routes.mjs under ' + backend); return 2
    src = open(worker).read()
    lines = open(routes).read().split('\n')

    checked = 0; fails = []
    for idx, l in enumerate(lines, 1):
        if '_WORKER_SRC' not in l:
            continue
        for body, negated, pos, endpos in scan_regexes(l):
            try:
                cnt = len(re.findall(body, src))
            except re.error as e:
                fails.append((idx, 'BAD-REGEX', body[:60], str(e)[:40])); continue
            checked += 1
            # exact-count form: (_WORKER_SRC.match(/.../g) || []).length (op) N
            is_match = '.match(' in l[max(0, pos-40):pos]
            mm = re.search(r'\.length\s*(===|>=|==|>)\s*(\d+)', l[endpos:endpos+120]) if is_match else None
            if mm:
                op, N = mm.group(1), int(mm.group(2))
                good = cnt >= N if op in ('>=', '>') else cnt == N
                if not good: fails.append((idx, 'count %s %d' % (op, N), body[:60], cnt))
            elif negated:
                if cnt != 0: fails.append((idx, 'negated -> expect 0', body[:60], cnt))
            else:
                if cnt < 1: fails.append((idx, 'positive -> expect >=1', body[:60], cnt))

    print('=== Atlas source-guard check ===  %s' % backend)
    print('guards checked: %d' % checked)
    if fails:
        print('\nFAIL (%d) -- these guards would break CI:' % len(fails))
        for ln, why, body, got in fails:
            print('  routes.mjs:%d  %s  got=%s' % (ln, why, got))
            print('      /%s/' % body)
        print('\nFix: update each guard to the worker.js line it now asserts, OR')
        print('revert the worker change. (build stamp stays the same for a test-only fix.)')
        return 1
    print('ALL GUARDS PASS (positive >=1, negative ==0, exact counts) -- safe to push.')
    return 0

if __name__ == '__main__':
    sys.exit(main())

# PB Dashboard tests

## verify-driver-scope

Regression guard for the ID-verification flow: **the primary renter's ID must never land on an
additional driver, and vice-versa.** It drives the REAL dashboard functions
(`openVerify`, `openDriverVerify`, `afterCloudLoad`, `saveVerify`, `applyStripeVerification`)
inside a hidden iframe of `docs/index.html` and asserts driver-scoping across every path (9 checks).

Fixed here originally: the `afterCloudLoad` background cloud-refill filled an open additional-driver
modal from the **primary's** `verify` object (dashboard v335).

### Run it by hand (any browser)
Chromium blocks `file://` iframes, so serve the repo root first:

```bash
python3 -m http.server 8000
# then open:  http://localhost:8000/tests/verify-driver-scope.selftest.html
```

Green = all checks pass. It uses only synthetic data and never touches the network or real bookings.

### Run it headless (CI / terminal)

```bash
cd tests
npm install
npx playwright install --with-deps chromium
node verify-driver-scope.spec.mjs      # exits non-zero if any check fails
```

### Wire it into CI (one-time, blocks regressions)
Add `.github/workflows/test-dashboard.yml` (via GitHub's web UI — the deploy token can't push workflow
files). It runs the headless test on every push/PR that touches `docs/index.html` or `tests/`, so a future
change that reintroduces the leak turns the Actions run red. See the setup note from the assistant for the
exact YAML. For a hard gate, make the "Dashboard tests" check required in branch protection.

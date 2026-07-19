# Atlas worker: automated deploy (ends the manual paste)

Today the worker ships by hand-pasting it into the Cloudflare dashboard. That is the single biggest source of
production risk and the cause of the "I pasted it but nothing changed / an old build is live" problem. This wires
up **push-to-deploy with a test gate**: every push to `main` that touches the worker runs the smoke test, and only
a green test deploys — then it verifies the live build stamp actually changed.

## One-time setup (about 10 minutes)

0. **Install the workflow file.** The deploy pipeline lives at [`ci/deploy-worker.yml`](ci/deploy-worker.yml)
   (it can't be pushed here because the repo token lacks GitHub's `workflow` scope). Put it live one of two ways:
   - **GitHub web UI:** repo > Actions > *New workflow* > *set up a workflow yourself*, name it
     `deploy-worker.yml`, and paste the contents of `atlas.io/backend/ci/deploy-worker.yml`. Commit.
   - **Or** give your Personal Access Token the `workflow` scope, then copy the file to
     `.github/workflows/deploy-worker.yml` and push.

1. **Create a Cloudflare API token** — Cloudflare dashboard > My Profile > API Tokens > *Create Token* >
   **Edit Cloudflare Workers** template. Copy the token.

2. **Add two GitHub repo secrets** — GitHub repo > Settings > Secrets and variables > Actions > *New repository secret*:
   - `CLOUDFLARE_API_TOKEN` = the token from step 1
   - `CLOUDFLARE_ACCOUNT_ID` = Cloudflare dashboard > Workers & Pages > (right sidebar) Account ID

3. **Fill the D1 id** in [`wrangler.toml`](wrangler.toml): replace `PASTE_YOUR_D1_DATABASE_ID` with your database id
   (Cloudflare dashboard > D1 > `atlas` > copy the ID). Commit.

4. **(Optional) enable file uploads** — create the R2 bucket once with `wrangler r2 bucket create atlas-files`,
   then uncomment the `[[r2_buckets]]` block in `wrangler.toml`.

5. **Confirm secrets exist.** Your dashboard-set secrets survive `wrangler deploy` (this config uses `keep_vars`).
   The full list the worker reads is in `wrangler.toml`. To set or rotate one: `wrangler secret put NAME`.

## First deploy — do it safely once

From `atlas.io/backend/` on your machine (or trust the Action):

```
npx wrangler@3 deploy --dry-run    # confirms it will keep DB (+ R2) and won't drop other bindings
npx wrangler@3 deploy              # the real thing
curl -s https://atlasrental.io/api/health   # "build" should equal ATLAS_BUILD in worker.js
```

After that, you never paste again — pushing a worker change to `main` deploys it automatically.

## What the pipeline guarantees

- **A broken worker never reaches production.** `test/smoke.mjs` runs first and blocks the deploy on failure
  (it catches: the worker not loading, the build stamp drifting, the competitor delete regression, admin auth
  accepting a bad token).
- **No silent no-op deploy.** After deploying, the workflow curls `/api/health` and fails if the live build stamp
  isn't the one it just shipped — the exact failure mode you kept hitting.
- **Rollback is one click:** GitHub > Actions > *Deploy Atlas Worker* > re-run the last green run, **or**
  `git revert <commit> && git push`.

## Bumping the build stamp

When you ship a worker change the dashboard depends on, bump the version in **three** places so the staleness
banner and the CI verify step stay honest:

- `worker.js` -> `const ATLAS_BUILD = '...'`
- `atlas.io/admin.html` -> `var ATLAS_EXPECT_BUILD = '...'`
- `atlas.io/backend/test/smoke.mjs` -> `const EXPECT_BUILD = '...'`

# Atlas scaling plan (D1 + cron)

Where Atlas is today, where it breaks, and the concrete steps to get to the "millions" claim. Nothing here is
urgent for launch - it's fine to thousands of tenants now - but it's the written design a serious buyer/investor
will ask for.

## Today

- **Compute:** one Cloudflare Worker at the edge. Horizontally scales for free; no per-request bottleneck.
- **Data:** one D1 (SQLite) database, single primary. Every tenant's rows carry `tenant_id`; all queries filter on it.
- **Background:** one `scheduled()` cron (daily) doing GC, lifecycle emails, per-tenant "dreaming", competitor
  crawl, and now a heartbeat + oversized-row scan.

Comfortable envelope: low-thousands of tenants, tens of thousands of bookings, normal booking-page traffic.

## What breaks first, and the fix

**1. D1 write throughput / single primary.** SQLite/D1 is one writer. The first ceiling is write-heavy bursts
(sync, mass bookings), not reads.
- *Near term:* keep hot paths append-only + narrow (already done - per-booking writes, no whole-table rewrites).
- *Scale step:* enable D1 **read replicas** for the read-heavy endpoints (overview, booking pages, portal reads);
  keep writes on the primary. Move the biggest write stream (page_views / visit_geo) to **Workers Analytics
  Engine** or a queue-batched writer so booking-page traffic never contends with booking writes.
- *Big scale:* **shard by tenant** - route each tenant to a D1 by `hash(tenant_id) % N` (a Durable Object or a
  KV map holds the routing table). The schema is already tenant-scoped, so sharding is a routing change, not a
  data-model change.

**2. Cron subrequest ceiling.** A single `scheduled()` invocation is bounded by Cloudflare's subrequest limit
(~1000 on paid). The competitor crawl already self-bounds (LIMIT + oldest-first rotation), and the AI deep-read
rotates a few tenants per night.
- *Scale step:* split the monolith cron into **multiple triggers** (email cron, dreaming cron, crawl cron) and/or
  push per-tenant work onto **Cloudflare Queues** with a consumer Worker, so each unit is small and retried
  independently (dead-letter on repeated failure). Batch size stays well under the subrequest limit.

**3. Per-tenant fan-out (dreaming / notifications).** Looping all active tenants in one invocation doesn't scale to
100k tenants.
- *Scale step:* the same Queues pattern - enqueue one message per tenant, process with concurrency, so wall-clock
  is bounded by the consumer count, not the tenant count.

**4. Object storage.** R2 (files, offloaded signatures/photos) already scales independently - no action.

## Sequencing

1. **Now (no code):** the nightly `big_rows` health metric + payload discipline keep row sizes flat. Watch it.
2. **At ~5k tenants:** move page_views/visit_geo off the primary; turn on D1 read replicas for read endpoints.
3. **At ~20k tenants:** Cloudflare Queues for cron fan-out (emails, dreaming, crawl) with retry + dead-letter.
4. **At ~100k tenants:** tenant sharding across N D1s behind a routing map.

## How to know it's time

Load-test at **10x current peak** before each step (a k6/Artillery script hitting the booking page + `/book` +
portal reads). Alert (via the uptime monitor on `/api/health`) if `cron_age_min` grows or error rate rises - those
are the leading indicators that a step is due.

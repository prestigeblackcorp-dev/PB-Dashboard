/*
 * Prestige Black — shared front-end config (single source of truth).
 *
 * Loaded synchronously (no defer/async) in the <head> of index.html,
 * ride.html, driver.html and portal.html, BEFORE the inline app scripts.
 *
 * Every consumer reads these via a guarded fallback, e.g.
 *     var WORKER = (typeof PB_WORKER !== 'undefined' ? PB_WORKER : '<literal>');
 * so if this file ever fails to load (404 / offline / blocked) the apps fall
 * back to the hardcoded literal and keep working exactly as before. Changing a
 * URL here updates all four apps at once.
 *
 * NOTE: there is intentionally NO Firebase config here. The front-end never
 * talks to Firebase directly — it only calls the Worker, which holds the
 * Firebase credentials server-side.
 */
(function (g) {
  // ── Cloudflare Worker base URLs ───────────────────────────────────────────
  // Booking / chauffeur / messaging API (used by all four apps).
  g.PB_WORKER        = 'https://pb-booking.prestigeblackcorp.workers.dev';
  // ID-verification worker (owner dashboard only).
  g.PB_VERIFY_WORKER = 'https://idverify.prestigeblackcorp.workers.dev';

  // ── Feature flags ─────────────────────────────────────────────────────────
  // Every roadmap feature is gated here so it can be killed instantly without a
  // code redeploy — just flip a flag and re-push this one small file. Apps read
  // via a guarded fallback: (window.PB_FLAGS||{}).x, so a failed load → all
  // falsy → exactly today's behavior. Client-only wins that are verified safe
  // default ON; features needing owner-provisioned keys default OFF until the
  // keys exist (the worker also self-gates on env presence).
  g.PB_FLAGS = {
    routedEta:   true,   // A — OSRM .duration live ETA (client-only)
    vehicleBadge:true,   // B — vehicle + "PB Verified Chauffeur" on rider card
    pwa:         true,   // C — register service worker + installable manifest
    voiceNav:    true,   // D — spoken turn-by-turn for the driver
    priceLock:   true,   // E — "Your fare · price locked"
    resilience:  true,   // F — wake-lock + reconnect/visibility resume
    webPush:     true,   // G — live: VAPID keys set in Cloudflare + webpush worker deployed
    cardOnFile:  true,   // H — card-on-file (DEMO simulation until real Stripe keys added)
    tipping:     true,   // H — tipping (DEMO simulation)
    demoPay:     true    // payments are a no-charge simulation; flip OFF when real Stripe keys exist
  };

  // Web Push VAPID public key (non-secret). Generated 2026-06; the matching private
  // key lives in the Cloudflare Worker env as VAPID_PRIVATE.
  g.PB_VAPID_PUBLIC = 'BPbEQQK8ZUQ1WWe2rsY9x0S-sueuHXrdD-71OE3HXLInCSMoy7-xOSrctEUsQoS8z7BQ8KsR95VlnFnIFNCzR2o';
  // Stripe publishable key (non-secret, pk_live_…; paste here when ready).
  g.PB_STRIPE_PK = '';

  // ── localStorage key registry ─────────────────────────────────────────────
  // The canonical list of keys the apps read/write, so they live in one place.
  // Adopt gradually (PB_KEYS.dashboardSecret instead of 'pb_dashboard_secret');
  // existing call sites that still use the literal string keep working.
  // Keys ending in '_' are prefixes that get a dynamic suffix appended.
  g.PB_KEYS = {
    // connection / config
    workerUrl:        'pb_worker_url',
    messagingUrl:     'pb_messaging_url',
    firebaseUrl:      'pb_firebase_url',
    verifyUrl:        'pb_verify_url',
    balanceUrl:       'pb_balance_url',
    dateLockUrl:      'pb_date_lock_url',
    dashboardSecret:  'pb_dashboard_secret',
    ownerEmail:       'pb_owner_email',
    ownerSignature:   'pb_owner_signature',
    openaiKey:        'pb_openai_key',
    reviewUrl:        'pb_review_url',
    taxRate:          'pb_tax_rate',
    lockPin:          'pb_lock_pin',
    staffPins:        'pb_staff_pins',

    // owner dashboard data
    dashV2:           'pb_dash_v2',
    incomes:          'pb_incomes',
    expenses:         'pb_expenses',
    budgets:          'pb_budgets',
    maintenance:      'pb_maintenance',
    customVehicles:   'pb_custom_vehicles',
    pricingRules:     'pb_pricing_rules',
    blacklist:        'pb_blacklist',
    waitlist:         'pb_waitlist',
    grouponPayouts:   'pb_groupon_payouts',
    contractTemplate: 'pb_contract_template',
    slingshotWaiver:  'pb_slingshot_waiver',
    notifLog:         'pb_notif_log',
    lastCloudSave:    'pb_last_cloud_save',
    lastExport:       'pb_last_export',
    gcalConnected:    'pb_gcal_connected',
    gcalPending:      'pb_gcal_pending',

    // rider app (ride.html)
    rideSession:      'pb_ride_session',
    activeRide:       'pb_active_ride',

    // driver app (driver.html)
    driverEmail:      'pb_drv_email',
    driverToken:      'pb_drv_token',

    // client portal (portal.html)
    portalEmail:      'pb_portal_email',
    portalToken:      'pb_portal_token',

    // dynamic-suffix prefixes
    allVsessionsPrefix:    'pb_all_vsessions_',
    pendingVsessionPrefix: 'pb_pending_vsession_',
    photoSyncPendingPrefix:'pb_photo_sync_pending_'
  };
})(typeof window !== 'undefined' ? window : this);

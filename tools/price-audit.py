#!/usr/bin/env python3
"""
PB PRICE AUDIT - diff every surface a price lives on and report mismatches.

Why this exists: a vehicle's price lives in FOUR places that drift silently.
On 2026-08-04 the fleet page was advertising $0.85/mi overage while the system
billed $2.00/mi, the booking widget charged $300/day for a Boxster the site
advertised at $225, and three fleet links were 404s. Nobody noticed until we
diffed by hand. This does that automatically.

SOURCES
  1. DASHBOARD  docs/index.html  VEHICLE_COSTS + VEHICLE_MILEAGE   <- AUTHORITATIVE (bills at close-out)
  2. WIDGET     PB_Booking_live.js  DATA{}                         <- quotes + charges the customer
  3. FLEET      pb-fleet-section.liquid  preset blocks             <- the /pages/fleet grid
  4. DETAIL     pb-*detail*.liquid schema defaults                 <- per-model pages
  5. LIVE       (--live) the real site                             <- what customers actually see now

SEVERITY
  HARMFUL  a customer-facing surface is LOWER than the dashboard -> you advertise
           less than you bill. Chargeback + TX DTPA exposure. Fix immediately.
  REVENUE  a surface is HIGHER than the dashboard -> you quote more than you bill,
           or lose the booking on sticker shock.
  INFO     missing/unparseable field.

USAGE
  python3 tools/price-audit.py              # audit local files
  python3 tools/price-audit.py --live       # also curl the live pages
Exit code 1 if any HARMFUL/REVENUE mismatch is found (so it can gate a deploy).
"""
import json, os, re, sys, urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASH = os.path.join(REPO, "docs", "index.html")
DL   = os.path.expanduser("~/Downloads")
SITE = "https://prestigeblackrentals.com"

# canonical key -> how each surface names it
ALIASES = {
    "Corvette":          ["2023 Chevrolet Corvette C8", "Chevrolet Corvette", "Corvette"],
    "Corvette Z51":      ["Corvette C8 Z51", "Corvette Z51"],
    "BMW M3":            ["2026 BMW M3 Competition xDrive", "BMW M3"],
    "BMW i4":            ["2022 BMW i4", "BMW i4"],
    "Macan":             ["2025 Porsche Macan", "Porsche Macan", "Macan"],
    "Porsche Boxster S": ["Porsche Boxster S", "Boxster S", "Boxster"],
    "C300":              ["2022 Mercedes-Benz AMG C300", "Mercedes-Benz C300", "Mercedes AMG C300", "C300"],
    "Accord":            ["2016 Honda Accord Coupe", "Honda Accord", "Accord"],
    "Lambo Huracan":     ["Lamborghini Huracan", "Huracan"],
    "Lambo Urus":        ["Lamborghini Urus", "Urus"],
    "Escalade Rental":   ["Cadillac Escalade", "Escalade"],
    "G Wagon":           ["Mercedes G-Wagon", "G-Wagon", "G Wagon"],
    "Polaris Slingshot": ["Polaris Slingshot", "Slingshot"],
    # Chauffeur vehicles are priced per HOUR (rate 0 in VEHICLE_COSTS). They get their own keys
    # so the loose matcher can't fold "Escalade Chauffeur" into "Escalade Rental" and zero it out.
    "Escalade Chauffeur": ["Escalade Chauffeur"],
    "Suburban":           ["Suburban"],
}
SKIP = {"Escalade Chauffeur", "Suburban"}   # hourly chauffeur units - no daily rate to compare
# canonical key -> detail .liquid filename
DETAIL_FILES = {
    "Corvette":          "pb-2023-corvette-detail.liquid",
    "BMW M3":            "pb-bmw-m3-detail.liquid",
    "BMW i4":            "pb-bmw-i4-detail.liquid",
    "Macan":             "pb-porsche-macan-detail.liquid",
    "Porsche Boxster S": "pb-porsche-boxster-s-detail.liquid",
    "C300":              "pb-mercedes-c300-detail.liquid",
    "G Wagon":           "pb-2020-gwagon-detail.liquid",
    "Escalade Rental":   "pb-22-escalade-sport-platinum-detail.liquid",
    "Lambo Huracan":     "pb-lamborghini-landing.liquid",
    "Polaris Slingshot": "pb-slingshot-experience.liquid",
}

def canon(name):
    n = (name or "").strip()
    if n in ALIASES: return n
    for k, alts in ALIASES.items():
        for a in alts:
            if n.lower() == a.lower(): return k
    for k, alts in ALIASES.items():                      # loose contains match
        for a in sorted(alts, key=len, reverse=True):
            if a.lower() in n.lower(): return k
    return None

def num(s):
    """First number in a string -> float. '$1,350/day' -> 1350.0 ; '$2/mi over' -> 2.0"""
    if s is None: return None
    if isinstance(s, (int, float)): return float(s)
    m = re.search(r"(\d[\d,]*\.?\d*)", str(s).replace(",", ""))
    return float(m.group(1)) if m else None

def read(p):
    try:
        with open(p, encoding="utf-8", errors="replace") as f: return f.read()
    except OSError: return ""

# ---------------------------------------------------------------- 1. DASHBOARD
def src_dashboard():
    s, out = read(DASH), {}
    blk = re.search(r"var VEHICLE_COSTS\s*=\s*\{(.*?)\n\};", s, re.S)
    if blk:
        for m in re.finditer(r'"([^"]+)":\s*\{([^}]*)\}', blk.group(1)):
            k = canon(m.group(1))
            if not k: continue
            b = m.group(2)
            g = lambda f: num((re.search(f + r"\s*:\s*([\d.]+)", b) or [None, None])[1]) if re.search(f + r"\s*:\s*([\d.]+)", b) else None
            out.setdefault(k, {}).update(rate=g("rate"), deposit=g("deposit"), weekly=g("weekly"))
    blk = re.search(r"var VEHICLE_MILEAGE\s*=\s*\{(.*?)\n\};", s, re.S)
    if blk:
        for m in re.finditer(r'"([^"]+)":\s*\{([^}]*)\}', blk.group(1)):
            k = canon(m.group(1))
            if not k: continue
            b = m.group(2)
            mi = re.search(r"miles\s*:\s*([\d.]+)", b); ov = re.search(r"overage\s*:\s*([\d.]+)", b)
            out.setdefault(k, {}).update(miles=num(mi.group(1)) if mi else None,
                                         overage=num(ov.group(1)) if ov else None)
    return out

# ------------------------------------------------------------------ 2. WIDGET
def src_widget():
    s, out = read(os.path.join(DL, "PB_Booking_live.js")), {}
    blk = re.search(r"var DATA\s*=\s*\{(.*?)\n\s*\};", s, re.S) or re.search(r"var DATA\s*=\s*\{(.*)", s, re.S)
    if not blk: return out
    for m in re.finditer(r'"([^"]+)"\s*:\s*\{((?:[^{}]|\n)*?)\}', blk.group(1)):
        k = canon(m.group(1))
        if not k: continue
        b = m.group(2)
        def g(f):
            mm = re.search(f + r"\s*:\s*([\d.]+)", b)
            return num(mm.group(1)) if mm else None
        out[k] = dict(rate=g("rate"), weekly=g("weekly"), deposit=g("deposit"),
                      unlimited=g("unlimited"), miles=g("milesPerDay"), overage=g("overage"))
    return out

# ------------------------------------------------------------------- 3. FLEET
def src_fleet():
    s, out = read(os.path.join(DL, "pb-fleet-section.liquid")), {}
    for m in re.finditer(r'"price"\s*:\s*"([^"]*)"[\s\S]{0,300}?"title"\s*:\s*"([^"]+)"'
                         r'[\s\S]{0,600}?"unlimited_text"\s*:\s*"([^"]*)"\s*,\s*"overage"\s*:\s*"([^"]*)"', s):
        k = canon(m.group(2))
        if not k: continue
        unl = m.group(3)
        out[k] = dict(rate=num(m.group(1)), overage=num(m.group(4)),
                      unlimited=(0.0 if re.search(r"not available|no\b", unl, re.I) else num(unl)))
    # dead detail_page links
    out["_links"] = re.findall(r'"detail_page"\s*:\s*"([^"]+)"', s)
    return out

# ------------------------------------------------------------------ 4. DETAIL
def src_detail():
    out = {}
    for k, fn in DETAIL_FILES.items():
        s = read(os.path.join(DL, fn))
        if not s: continue
        d = {}
        for fid in ("price", "deposit", "miles", "overage", "unlimited"):
            m = re.search(r'"id"\s*:\s*"%s"[^}]*?"default"\s*:\s*"([^"]*)"' % fid, s)
            if not m: continue
            v = m.group(1)
            d["rate" if fid == "price" else fid] = (0.0 if (fid == "unlimited" and re.search(r"no\b|not available|n/a", v, re.I)) else num(v))
        if d: out[k] = d
    return out

# -------------------------------------------------------------------- 5. LIVE
LIVE_PAGES = {
    "Corvette": "corvette-rental-dallas", "BMW M3": "bmw-m3-rental-dallas", "BMW i4": "bmw-i4",
    "Macan": "porsche-macan-rental-dallas", "C300": "mercedes-c300-rental-dallas",
    "Porsche Boxster S": "porsche-boxter-s-rental-dallas-forth-worth",
    "Polaris Slingshot": "polaris-slingshot-rental-dallas", "Lambo Huracan": "lamborghini-rental-dallas",
}
def src_live():
    out = {}
    for k, slug in LIVE_PAGES.items():
        try:
            req = urllib.request.Request(f"{SITE}/pages/{slug}", headers={"User-Agent": "Mozilla/5.0"})
            html = urllib.request.urlopen(req, timeout=15).read().decode("utf-8", "replace")
        except Exception:
            continue
        txt = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", re.sub(r"<script.*?</script>", "", html, flags=re.S)))
        m = re.search(r"Rate \$([\d,]+)\s*/day", txt) or re.search(r"is \$([\d,]+) per day", txt)
        if m: out[k] = dict(rate=num(m.group(1)))
    return out

# ------------------------------------------------------------------- COMPARE
FIELDS = ["rate", "weekly", "deposit", "miles", "overage", "unlimited"]
LABEL  = {"rate": "daily rate", "weekly": "weekly", "deposit": "deposit",
          "miles": "miles/day", "overage": "overage/mi", "unlimited": "unlimited/day"}
# a customer-facing surface being LOWER than what the dashboard bills is the dangerous direction
LOWER_IS_HARMFUL = {"rate", "overage", "deposit", "unlimited"}

def main():
    live = "--live" in sys.argv
    dash, wid, fleet, det = src_dashboard(), src_widget(), src_fleet(), src_detail()
    lv = src_live() if live else {}
    links = fleet.pop("_links", [])
    surfaces = [("WIDGET", wid), ("FLEET", fleet), ("DETAIL", det)] + ([("LIVE", lv)] if live else [])

    print("=" * 78)
    print("PB PRICE AUDIT".center(78))
    print("=" * 78)
    print(f"authoritative: dashboard ({len(dash)} vehicles)   comparing: "
          + ", ".join(f"{n}({len(d)})" for n, d in surfaces) + "\n")

    issues = []
    for k in sorted(dash):
        if k in SKIP: continue
        d = dash[k]
        for sname, sdata in surfaces:
            sv = sdata.get(k)
            if not sv: continue
            for f in FIELDS:
                a, b = d.get(f), sv.get(f)
                if a is None or b is None: continue
                if abs(a - b) < 0.005: continue
                sev = "HARMFUL" if (b < a and f in LOWER_IS_HARMFUL) else "REVENUE"
                issues.append((sev, k, sname, f, a, b))

    if issues:
        for sev in ("HARMFUL", "REVENUE"):
            rows = [i for i in issues if i[0] == sev]
            if not rows: continue
            tag = ("!! HARMFUL - advertised BELOW what you bill (chargeback / DTPA risk)"
                   if sev == "HARMFUL" else "-- REVENUE - surface disagrees, above what you bill")
            print(tag); print("-" * 78)
            for _, k, sname, f, a, b in rows:
                print(f"   {k:<20} {sname:<7} {LABEL[f]:<14} dashboard ${a:<9,.2f} {sname.lower()} ${b:,.2f}")
            print()
    else:
        print("OK - every surface agrees with the dashboard.\n")

    bad = [l for l in links if l.startswith("/pages/")
           and l.split("/pages/")[1] not in {
               "corvette-rental-dallas", "bmw-m3-rental-dallas", "bmw-i4", "porsche-macan-rental-dallas",
               "mercedes-c300-rental-dallas", "porsche-boxter-s-rental-dallas-forth-worth",
               "polaris-slingshot-rental-dallas", "lamborghini-rental-dallas", "lamborghini-urus",
               "lamborghini-huracan-lp-610-4", "grey-2020-g-wagon-for-rent-dallas",
               "2022-escalade-sport-platinum-rental", "honda-accord-coupe-rental-dallas",
               "fleet", "book", "yukon-denali", "pages-dallas-chauffeur-service"}]
    if bad:
        print("!! FLEET LINKS not in the known-good handle list (verify they are not 404):")
        for l in bad: print("   ", l)
        print()

    stale = [f'"{t}"' for t in re.findall(r'(\+?\$[\d,]+\s*/\s*trip|per trip)',
             "".join(read(os.path.join(DL, f)) for f in os.listdir(DL) if f.endswith((".liquid", ".js"))))]
    if stale:
        print(f"!! '/trip' wording found ({len(stale)}) - unlimited miles bills PER DAY.\n")

    print("=" * 78)
    print(f"{len(issues)} price mismatch(es)"
          + (f", {len(bad)} suspect link(s)" if bad else "")
          + (f", {len(stale)} '/trip' string(s)" if stale else ""))
    if not live: print("(run with --live to also check the published pages)")
    return 1 if (issues or bad or stale) else 0

if __name__ == "__main__":
    sys.exit(main())

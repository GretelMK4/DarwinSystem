"""
Judith's shop: a real website with several pitcher plants hidden inside it.

The site has something real worth stealing: a product catalog
(/shop/?page=N listings, /shop/item/N pages). Hidden around it are up to five
pitcher plants, each with its own bait theme:

    backup   /backup/     fake database dumps and key files
    admin    /admin/      fake admin exports
    git      /.git/       fake leaked source repository
    internal /internal/   fake internal exports (+ /.env bait)
    api      /api/v1/     fake API where planted keys "work"

Normal operation (per pitcher, as in pitcher.py)
    touching a file 2+ folders deep seals that visitor; every 4th new visitor is
    a scout that is released with gold; sealed visitors are caught-and-released
    after 8 s.

Lockdown (MODE=lockdown*)
    If ALARM_K different alarm signals fire within ALARM_WINDOW seconds the site
    assumes a coordinated swarm and locks down for the rest of the run:
      - no more releases of any kind (no scouts, no catch-and-release)
      - hair trigger: touching ANY pitcher path seals the visitor at once
      - rate seal: more than RATE_N catalog requests within RATE_WINDOW seconds
        seals the visitor (people browse far slower than that)

Shadow site and shield
    Sealed visitors see a shadow site: the homepage and listings look normal,
    but product pages are plausible FAKES (wrong names, prices, SKUs), the same
    fake for every sealed visitor. With the shield on, a sealed visitor asking
    for a product that a known bot already took gets the real page (it leaks
    nothing new), so cross-checking copies between bots does not expose the
    shadow.

Optional alarm signals
    HONEYLINKS=on   one hidden product link per listing page (hidden by the
                    stylesheet, so people never see it); following it seals
    SURGE=on        a flood of first-time catalog visitors counts as a signal
    TRIPWIRES=on    crowd defences against swarms that avoid every pitcher:
        traffic spike   more than SPIKE_N catalog requests in SPIKE_WINDOW s
                        -> instant lockdown
        enumeration     more than ENUM_N distinct products in ENUM_WINDOW s
                        -> instant lockdown
        probation       during lockdown, visitors who are not established
                        (older than EST_AGE s and browsing slowly) are on
                        probation: two products within 1 s seals them
                        (PACE_RULE), and they share a budget of CAP_RATE
                        never-served products per second ("busy, retry")
        entry challenge ENTRY_CHALLENGE=on: each visitor on probation must solve
                        a proof-of-work puzzle before the first page: find a
                        number whose SHA-256 hash with the visitor's token
                        starts with CHALLENGE_BITS zero bits. Browsers get a
                        small page that solves it and reloads. It costs each
                        new identity some computing time; it does not stop a
                        bot that is willing to pay, and it locks out people
                        whose browser has JavaScript turned off.
    INTEL=on        accept signed intel from Hercules (identities seen there,
                    fake keys it issued, surge reports) on the admin port.
                    Requires DARWIN_INTEL_KEY (one shared key) or, better,
                    DARWIN_INTEL_KEYS (one key per plant); see darwin/intel.py.
                    INTEL_QUORUM=2 seals an identity only once two different
                    plants reported it (refused without per-plant keys).
                    INTEL_TTL (default 86400 s): reports expire. INTEL_ME:
                    refuse messages addressed to another receiver.

The Spider (SPIDER=seal|alert|off, default seal)
    Judith's internal watcher for patient attackers; see spider.py. It keeps a
    ledger per source address and flags behaviour the owner has not approved
    (too many different products, number-by-number enumeration, clockwork
    timing, many User-Agents from one address) and any change to Darwin's own
    files. Every flag is written for people (results/spider_flags.jsonl and
    the stats port). seal (the default) = Judith also seals every visitor from
    a flagged address, silently, like any other seal: the visitor keeps
    getting pages and leaves believing it succeeded. alert = flag only.
    People who share one address share one ledger, so set the thresholds from
    your own traffic, or use alert, where many real users sit behind one
    address.

Verified search crawlers (VERIFY_CRAWLERS=on, the default) always get the real
site and are never sealed, counted or challenged. See darwin/crawlers.py.

MODE: none | ratelimit | single | multi | lockdown | lockdown_noshield
    ratelimit = a standard defence for comparison: over-rate clients get 429.

Measurement only: the counters that tell "people" (User-Agent starting with
"Mozilla") from bots, and which real items bots obtained, exist to score the
simulations. No defence decision uses them.

Research prototype: no login on the admin port (bound to localhost), in-memory
state without a size limit, thresholds tuned to simulated traffic.

Run:  python -m darwin.judith.shop
"""
import collections
import hashlib
import hmac
import json
import os
import random
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from darwin import crawlers, intel
from darwin.httpbase import QuietHandler
from darwin.judith import pitcher as ts
from darwin.judith import spider as spider_mod
from darwin.results import results_path

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8088"))
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "8089"))
MODE = os.environ.get("MODE", "lockdown")
CATALOG = int(os.environ.get("CATALOG", "3000"))
PER_PAGE = 10
PAGES = (CATALOG + PER_PAGE - 1) // PER_PAGE
DRIP = float(os.environ.get("DRIP", "0.01"))
# Sealing must not change timing. The drip used to triple at the moment of the seal, so a visitor that timed
# the same pitcher page before and after could see exactly which request sealed it (lab 2026-11-27, latency
# tell). With DRIP_EVEN=on (default) the slow drip starts at a visitor's first pitcher request and stays.
DRIP_EVEN = os.environ.get("DRIP_EVEN", "on") == "on"
SEAL_DEPTH, GOLD_DEPTH, SCOUT_EVERY, RELEASE_AFTER = 2, 3, 4, 8.0
ALARM_K = int(os.environ.get("ALARM_K", "3"))
ALARM_WINDOW = float(os.environ.get("ALARM_WINDOW", "6"))
RATE_N = int(os.environ.get("RATE_N", "8"))
RATE_WINDOW = float(os.environ.get("RATE_WINDOW", "3"))
# ---- optional alarm signals ----
HONEYLINKS = os.environ.get("HONEYLINKS", "off") == "on"   # hidden product links only bots follow
SURGE = os.environ.get("SURGE", "off") == "on"             # flood of new catalog visitors = alarm hair
SURGE_N = int(os.environ.get("SURGE_N", "40"))
SURGE_WINDOW = float(os.environ.get("SURGE_WINDOW", "5"))
NEW_CAT = []
SURGE_STATE = {"last": 0.0}
# crowd tripwires: for swarms that never touch a pitcher
TRIPWIRES = os.environ.get("TRIPWIRES", "off") == "on"
SPIKE_N = int(os.environ.get("SPIKE_N", "60"))             # catalog requests ...
SPIKE_WINDOW = float(os.environ.get("SPIKE_WINDOW", "0.25"))  # ... within this many seconds = instant lockdown
ENUM_N = int(os.environ.get("ENUM_N", "300"))              # distinct products ...
ENUM_WINDOW = float(os.environ.get("ENUM_WINDOW", "5"))    # ... within this many seconds = instant lockdown
EST_AGE = float(os.environ.get("EST_AGE", "2.0"))          # sessions older than this, browsing slowly, are trusted
PROB_BUDGET = int(os.environ.get("PROB_BUDGET", "12"))     # real products a new visitor gets during lockdown
CAP_RATE = float(os.environ.get("CAP_RATE", "2.0"))        # never-seen products/sec for ALL new visitors combined
ENTRY_CHALLENGE = os.environ.get("ENTRY_CHALLENGE", "on") == "on"   # proof-of-work puzzle for visitors on probation
CHALLENGE_BITS = int(os.environ.get("CHALLENGE_BITS", "18"))        # leading zero bits required (work doubles per bit)
CHALLENGE_MIN_WAIT = float(os.environ.get("CHALLENGE_MIN_WAIT", "0"))  # optional: also refuse answers sooner than this
CHALLENGE_HEADER, CHALLENGE_PREFIX, CHALLENGE_COOKIE = "X-Challenge", "challenge:", "darwin_challenge"
VERIFY_CRAWLERS = os.environ.get("VERIFY_CRAWLERS", "on") == "on"
MAX_UA = 300
PACE_RULE = os.environ.get("PACE_RULE", "on") == "on"      # new visitor: 2 products within 1 s = sealed
CAT_TIMES = collections.deque()
ENUM_Q, ENUM_CNT = collections.deque(), collections.Counter()
SERVED_ANY = set()
BUCKET = {"tokens": 5.0, "t": time.time()}

ALL_PITCHERS = {"backup": "/backup/", "admin": "/admin/", "git": "/.git/",
                "internal": "/internal/", "api": "/api/v1/"}
if MODE in ("none", "ratelimit"):
    PITCHERS = {}
elif MODE == "single":
    PITCHERS = {"backup": "/backup/"}
else:
    PITCHERS = dict(ALL_PITCHERS)
LOCKDOWN_MODE = MODE.startswith("lockdown")
SHIELD = MODE == "lockdown"
INTEL_ON = os.environ.get("INTEL", "off") == "on"     # accept signed intel from Hercules
INTEL_QUORUM = int(os.environ.get("INTEL_QUORUM", "2" if os.environ.get(intel.ENV_KEYS) else "1"))
                                                           # different plants that must report an identity
                                                           # (2 by default with per-plant keys)
INTEL_TTL = float(os.environ.get("INTEL_TTL", "86400"))    # seconds a report stays valid
INTEL_ME = os.environ.get("INTEL_ME") or None              # this receiver's name; set it to refuse
                                                           # messages addressed to another receiver
INTEL_MAX = 200_000                                   # most identities / keys remembered per sender
INTEL_IDS = intel.IntelStore(quorum=INTEL_QUORUM, ttl=INTEL_TTL, per_sender=INTEL_MAX)
INTEL_TOKEN_CHECK = os.environ.get("INTEL_TOKEN_CHECK", "on") == "on"   # with per-plant keys, accept only
                                                                         # checkable fake keys (intel.token_ok)
INTEL_TOKENS = intel.IntelStore(quorum=1, ttl=INTEL_TTL, per_sender=INTEL_MAX)   # a fake key is ours: one
                                                                                 # plant seeing it used is proof
INTEL_VERIFIER = None                                 # set in main() when INTEL=on
INTEL_REJECTED = collections.Counter()
CRAWLERS = crawlers.CrawlerVerifier()
SPIDER_MODE = os.environ.get("SPIDER", "seal")        # seal (default) | alert | off
SPIDER = None                                         # the Spider object, created in main()
SPIDER_SEALED = {}                                    # address or address|UA -> sealed until (seal mode)
SPIDER_FLAGS = []                                     # what it has raised, for the stats port
RELEASES = MODE in ("single", "multi") or LOCKDOWN_MODE

LOCK = threading.Lock()
CLIENTS = {}
SEALS = []                                  # (t, pitcher)
STATE = {"start": time.time(), "lockdown_at": None, "n_clients": 0}
SHIELD_SET = set()                          # items already held by known (sealed) bots
STOLEN = set()                              # ground truth: real items delivered to bots
REQ = collections.Counter()
HUMAN = collections.Counter()
EVENTS = collections.deque(maxlen=80)
FAKE_ITEMS = set()


def event(kind, client, detail):
    EVENTS.appendleft({"t": round(time.time() - STATE["start"], 2), "kind": kind,
                       "client": client.split("|", 1)[-1], "detail": detail})


# ---------- the real site ----------

ADJ = ["Classic", "Pro", "Ultra", "Compact", "Heavy-Duty", "Eco", "Deluxe", "Mini", "Smart", "Rugged"]
NOUN = ["Widget", "Sprocket", "Gizmo", "Bracket", "Valve", "Coupler", "Flange", "Gear", "Hinge", "Spindle"]


def _load_shadow_secret(environ=os.environ):
    """The secret that makes the shadow site's fakes unpredictable. Without it, anyone with the public
    code could recompute the fake page for every product and tell a sealed visit from a real one
    (Nov 25 finding 20261125-2). DARWIN_SHADOW_SECRET sets it; otherwise one is made once and kept in
    results/shadow_secret, so the fakes stay the same across restarts (a sealed visitor that comes back
    after a restart must not see a different fake)."""
    value = environ.get("DARWIN_SHADOW_SECRET")
    if value:
        return value.encode()
    path = results_path("shadow_secret")
    try:
        with open(path, "rb") as f:
            secret = f.read().strip()
        if len(secret) >= 16:
            return secret
    except OSError:
        pass
    secret = os.urandom(32).hex().encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(secret)
    return secret


SHADOW_SECRET = _load_shadow_secret()


def item_page(n, fake=False):
    if fake:
        seed = hmac.new(SHADOW_SECRET, f"FAKE{n}".encode(), hashlib.sha256).hexdigest()
    else:
        seed = "REAL" + str(n)                      # stands in for the real catalog database
    r = random.Random(seed)
    name = f"{r.choice(ADJ)} {r.choice(NOUN)} {r.randint(100, 999)}"
    price = f"{r.uniform(4, 400):.2f}"
    sku = "".join(r.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(8))
    page = (n - 1) // PER_PAGE + 1
    return (f"<html><head><title>{name}</title></head><body><h1>{name}</h1>"
            f"<p class=price>${price}</p><p class=sku>SKU {sku}</p>"
            f"<p class=stock>{r.randint(0, 500)} in stock</p>"
            f'<a href="/shop/?page={page}">Back to catalog</a></body></html>')


def home(bait=True):
    nectar = ""
    if PITCHERS and bait:
        nectar = "<!-- TODO: remove " + " and ".join(PITCHERS.values()) + " before launch -->"
    return ("<html><head><title>Acme Widgets</title></head><body><h1>Acme Widgets</h1>"
            "<p>Quality widgets since 2009.</p>"
            '<a href="/shop/?page=1">Shop</a> <a href="/blog/">Blog</a> <a href="/about">About</a>'
            f"{nectar}</body></html>")


def robots():
    return "User-agent: *\n" + "".join(f"Disallow: {p}\n" for p in PITCHERS.values())


def listing(page, honeylinks=None):
    honeylinks = HONEYLINKS if honeylinks is None else honeylinks
    lo = (page - 1) * PER_PAGE + 1
    lis = [f'<li><a href="/shop/item/{n}">Item {n}</a></li>' for n in range(lo, min(lo + PER_PAGE, CATALOG + 1))]
    head = ""
    if honeylinks:
        # one hidden product per page; a stylesheet hides it, so people never see it
        pos = random.Random(f"honey{page}").randrange(len(lis) + 1)
        lis.insert(pos, f'<li class="x9"><a href="/shop/item/{CATALOG + page}">Item {CATALOG + page}</a></li>')
        head = '<head><link rel="stylesheet" href="/static/site.css"></head>'
    nav = " ".join(f'<a href="/shop/?page={p}">{p}</a>' for p in range(1, PAGES + 1))
    return f"<html>{head}<body><h1>Catalog page {page}</h1><ul>{''.join(lis)}</ul><nav>{nav}</nav></body></html>"


def honey_id(path):
    if not (HONEYLINKS and path.startswith("/shop/item/")):
        return None
    try:
        n = int(path.rsplit("/", 1)[-1])
    except ValueError:
        return None
    return n if CATALOG < n <= CATALOG + PAGES else None


def pitcher_of(path):
    for name, pre in PITCHERS.items():
        if path.startswith(pre):
            return name
    if path == "/.env" and PITCHERS:
        return "internal" if "internal" in PITCHERS else next(iter(PITCHERS))
    return None


def item_id(path):
    try:
        n = int(path.rsplit("/", 1)[-1])
        return n if 1 <= n <= CATALOG else None
    except ValueError:
        return None


def static_page(path, query, honeylinks=None, bait=True):
    """Pages that are the same for every visitor (everything except product pages). None = not one of them."""
    if path == "/":
        return 200, "text/html", home(bait)
    if path == "/static/site.css":
        return 200, "text/css", ".x9{display:none}"
    if path == "/robots.txt":
        return 200, "text/plain", robots()
    if path in ("/blog/", "/about"):
        return 200, "text/html", f"<html><body><h1>{path.strip('/').title()}</h1></body></html>"
    if path == "/shop/":
        try:
            pg = int(query.get("page", ["1"])[0])
        except ValueError:
            pg = 1
        if 1 <= pg <= PAGES:
            return 200, "text/html", listing(pg, honeylinks)
        return 404, "text/html", NOT_FOUND
    return None


NOT_FOUND = "<html><body>Not Found</body></html>"


# ---------- entry challenge (proof of work) ----------

def challenge_solved(token: str, counter: str, bits: int = None) -> bool:
    """True if SHA-256("<token>:<counter>") starts with `bits` zero bits."""
    bits = CHALLENGE_BITS if bits is None else bits
    digest = hashlib.sha256(f"{token}:{counter}".encode()).digest()
    return int.from_bytes(digest, "big") >> (256 - bits) == 0


def challenge_answered(headers, token: str) -> bool:
    """Did this request carry a valid answer ("<token>:<counter>") in the header or the cookie?"""
    answers = [headers.get(CHALLENGE_HEADER, "")]
    for part in headers.get("Cookie", "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == CHALLENGE_COOKIE:
            answers.append(value)
    for answer in answers:
        tok, _, counter = answer.partition(":")
        if tok == token and counter.isdigit() and len(counter) <= 20 and challenge_solved(token, counter):
            return True
    return False


def solve_challenge(text: str) -> str:
    """Client side: solve a "challenge:<token>:<bits>" reply; returns the value for the X-Challenge header."""
    token, _, bits = text[len(CHALLENGE_PREFIX):].strip().partition(":")
    counter = 0
    while not challenge_solved(token, str(counter), int(bits)):
        counter += 1
    return f"{token}:{counter}"


CHALLENGE_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Just a moment</title></head>
<body><p>Checking your browser. This takes a few seconds.</p>
<noscript><p>Please turn on JavaScript and reload this page.</p></noscript>
<script>
(async () => {
  const token = "%(token)s", bits = %(bits)d, enc = new TextEncoder();
  for (let n = 0; ; n++) {
    const d = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(token + ":" + n)));
    let zeros = 0;
    for (const b of d) { if (b === 0) { zeros += 8; continue; } zeros += Math.clz32(b) - 24; break; }
    if (zeros >= bits) {
      document.cookie = "%(cookie)s=" + token + ":" + n + "; path=/; SameSite=Lax";
      location.reload();
      break;
    }
  }
})();
</script></body></html>"""


def challenge_response(token: str, wants_html: bool):
    """Browsers get a page that solves the puzzle and reloads; other clients get one line of text."""
    if wants_html:
        return 403, "text/html", CHALLENGE_PAGE % {"token": token, "bits": CHALLENGE_BITS, "cookie": CHALLENGE_COOKIE}
    return 403, "text/plain", f"{CHALLENGE_PREFIX}{token}:{CHALLENGE_BITS}"


# ---------- defence state ----------

def new_client(ip, ua, t):
    n = STATE["n_clients"]
    STATE["n_clients"] += 1
    return {"ip": ip, "ua": ua, "first": t, "role": "scout" if RELEASES and n % SCOUT_EVERY == 0 else "prey",
            "sealed_at": None, "trigger": None, "released": False, "caught": False,
            "blocked": False, "rt": collections.deque(), "real_items": set(), "requests": 0,
            "n_items": 0, "probation": None, "pt": collections.deque(), "prob_items": 0}


def seal(c, client, pitcher, t):
    c["sealed_at"], c["trigger"], c["released"] = t, pitcher, False
    SHIELD_SET.update(c["real_items"])             # known bot: what it holds is already lost
    SEALS.append((t, pitcher))
    event("SEALED", client, f"via {pitcher}")


TRIGGERS = []                                   # (t, pitcher): every trigger, by anyone


def note_trigger(pitcher, t, client):
    """Every time any pitcher is triggered (even by an already-sealed bot)."""
    TRIGGERS.append((t, pitcher))
    if LOCKDOWN_MODE and STATE["lockdown_at"] is None:
        recent = {p for tt, p in TRIGGERS[-500:] if t - tt <= ALARM_WINDOW}
        if len(recent) >= ALARM_K:
            STATE["lockdown_at"] = t
            event("LOCKDOWN", client, f"{len(recent)} pitchers triggered within {ALARM_WINDOW:.0f}s: "
                  + ", ".join(sorted(recent)))


def lock_now(reason, t, client):
    """A single strong signal: lock down immediately."""
    TRIGGERS.append((t, reason))
    if LOCKDOWN_MODE and STATE["lockdown_at"] is None:
        STATE["lockdown_at"] = t
        event("LOCKDOWN", client, f"instant: {reason}")


class Handler(QuietHandler):
    def do_GET(self):
        t0 = time.time()
        u = urlparse(self.path)
        path, query = u.path, parse_qs(u.query)
        ua = self.headers.get("User-Agent", "")[:MAX_UA]
        client = f"{self.client_address[0]}|{ua}"
        if VERIFY_CRAWLERS and CRAWLERS.is_verified(self.client_address[0], ua):
            self.serve_crawler(path, query)
            return
        is_human = ua.startswith("Mozilla")               # measurement only
        fleet_guard = False
        if SPIDER is not None and path.startswith("/shop/item/") and item_id(path):
            fleet_guard = SPIDER_MODE == "seal" and SPIDER.guarded(self.client_address[0], item_id(path), t0)
            SPIDER.observe(self.client_address[0], ua, item_id(path), t0, shadowed=fleet_guard)
        pit = pitcher_of(path)
        is_catalog = path.startswith("/shop/")
        honey = honey_id(path)
        depth = path.strip("/").count("/")
        give_gold = blocked = False
        with LOCK:
            c = CLIENTS.get(client)
            if c is None:
                c = CLIENTS[client] = new_client(self.client_address[0], ua, t0)
            c["requests"] += 1
            if honey is not None:                                     # no human ever asks for this
                note_trigger("honeylink", t0, client)
                if not c["sealed_at"]:
                    seal(c, client, "honeylink", t0)
            if SURGE and is_catalog and not c.get("cat_first"):
                c["cat_first"] = t0
                NEW_CAT.append(t0)
                while NEW_CAT and t0 - NEW_CAT[0] > SURGE_WINDOW:
                    NEW_CAT.pop(0)
                if len(NEW_CAT) >= SURGE_N and t0 - SURGE_STATE["last"] > 1:
                    SURGE_STATE["last"] = t0
                    note_trigger("surge", t0, client)
            if not c["sealed_at"] and spider_sealed(self.client_address[0], client, t0):
                note_trigger("spider", t0, client)                    # flagged by the internal watcher
                seal(c, client, "spider", t0)
            if INTEL_ON and not c["sealed_at"]:
                if client in INTEL_IDS:                               # seen stuck on Hercules (address + User-Agent)
                    note_trigger("intel_hercules", t0, client)
                    seal(c, client, "intel_hercules", t0)
                elif ts.key_from(self.headers) in INTEL_TOKENS:       # using a Hercules fake key
                    note_trigger("intel_token", t0, client)
                    seal(c, client, "intel_token", t0)
            if is_catalog:
                c["rt"].append(t0)
                while c["rt"] and t0 - c["rt"][0] > RATE_WINDOW:
                    c["rt"].popleft()
            locked = STATE["lockdown_at"] is not None
            if MODE == "ratelimit":
                if is_catalog and len(c["rt"]) > RATE_N and not c["blocked"]:
                    c["blocked"] = True
                    event("BLOCKED_429", client, "over rate limit")
                blocked = c["blocked"]
            if pit:
                c["touched"] = True
                trig = False
                if LOCKDOWN_MODE and locked:
                    trig = True                                       # hair trigger
                elif pit == "api":
                    trig = ts.key_from(self.headers) in ts.HONEYTOKENS and path.rstrip("/") != "/api/v1"
                elif not path.endswith("/") and depth >= SEAL_DEPTH and c["role"] != "scout":
                    trig = True
                if trig:
                    note_trigger(pit, t0, client)
                    locked = STATE["lockdown_at"] is not None
                    if not c["sealed_at"] and (not c["released"] or (LOCKDOWN_MODE and locked)):
                        seal(c, client, pit, t0)
            if (LOCKDOWN_MODE and locked and is_catalog and not c["sealed_at"]
                    and len(c["rt"]) > RATE_N):
                seal(c, client, "rate", t0)
            releases_on = RELEASES and not (LOCKDOWN_MODE and locked)
            if releases_on and pit and pit != "api" and not path.endswith("/") and not c["released"]:
                if c["role"] == "scout" and not c["sealed_at"] and depth >= GOLD_DEPTH:
                    give_gold = c["released"] = True
                    event("SCOUT_RELEASED", client, f"gold at {path}")
                elif c["sealed_at"] and t0 - c["sealed_at"] >= RELEASE_AFTER:
                    give_gold = c["released"] = c["caught"] = True
                    c["sealed_at"] = None
                    event("CAUGHT_RELEASED", client, f"gold at {path}")
            challenge = busy = False
            if TRIPWIRES:
                n_item = item_id(path) if path.startswith("/shop/item/") else None
                if is_catalog:
                    CAT_TIMES.append(t0)
                    while CAT_TIMES and t0 - CAT_TIMES[0] > SPIKE_WINDOW:
                        CAT_TIMES.popleft()
                    if len(CAT_TIMES) > SPIKE_N:
                        lock_now("traffic_spike", t0, client)
                if n_item:
                    ENUM_Q.append((t0, n_item))
                    ENUM_CNT[n_item] += 1
                    while ENUM_Q and t0 - ENUM_Q[0][0] > ENUM_WINDOW:
                        _, old = ENUM_Q.popleft()
                        ENUM_CNT[old] -= 1
                        if ENUM_CNT[old] <= 0:
                            del ENUM_CNT[old]
                    if len(ENUM_CNT) > ENUM_N:
                        lock_now("enumeration", t0, client)
                la = STATE["lockdown_at"]
                if la is not None and c["probation"] is None:
                    age = la - c["first"]
                    c["probation"] = not (age >= EST_AGE and c["n_items"] / max(age, 0.5) <= 0.5)
                if c["probation"] and not c["sealed_at"]:
                    if ENTRY_CHALLENGE and not c.get("challenge_ok"):
                        if c.get("challenge_token") and t0 - c["challenge_t"] >= CHALLENGE_MIN_WAIT \
                                and challenge_answered(self.headers, c["challenge_token"]):
                            c["challenge_ok"] = True
                        else:
                            if not c.get("challenge_token"):
                                c["challenge_token"], c["challenge_t"] = ts.tok(random.SystemRandom(), 16), t0
                            challenge = True
                    if not challenge and n_item:
                        c["pt"].append(t0)
                        while c["pt"] and t0 - c["pt"][0] > 1.0:
                            c["pt"].popleft()
                        if PACE_RULE and len(c["pt"]) >= 2:
                            seal(c, client, "probation_pace", t0)
                        elif c["prob_items"] >= PROB_BUDGET:
                            seal(c, client, "probation_budget", t0)
                        elif n_item not in SERVED_ANY:
                            BUCKET["tokens"] = min(5.0, BUCKET["tokens"] + (t0 - BUCKET["t"]) * CAP_RATE)
                            BUCKET["t"] = t0
                            if BUCKET["tokens"] < 1:
                                busy = True
                            else:
                                BUCKET["tokens"] -= 1
            sealed = c["sealed_at"] is not None

        # ---------- build the response ----------
        kind, drip = "real", 0.0
        if challenge:
            kind = "challenge"
            st, ct, body = challenge_response(c["challenge_token"], "text/html" in self.headers.get("Accept", ""))
        elif busy:
            st, ct, body, kind = 503, "text/plain", "busy, please retry", "busy"
        elif blocked:
            st, ct, body, kind = 429, "text/plain", "Too Many Requests", "blocked"
        elif give_gold:
            st, ct, body, kind = 200, "application/json", ts.gold_file(path), "gold"
        elif pit:
            kind = "pitcher"
            drip = DRIP * (3 if sealed or (DRIP_EVEN and c.get("touched")) else 1 + depth / 2)
            if path == "/.env":
                st, ct, body = 200, "text/plain", ts.dotenv()
            elif pit == "api":
                st, obj = ts.api(path, query, self.headers, client)
                ct, body = "application/json", json.dumps(obj, indent=2)
            elif path.endswith("/"):
                st, ct, body = 200, "text/html", ts.maze_listing(path)
            else:
                st, ct, body = 200, "text/plain", ts.maze_file(path)
        elif honey is not None:
            st, ct, body, kind = 200, "text/html", item_page(honey, fake=True), "shadow_fake"
        elif static_page(path, query) is not None:
            st, ct, body = static_page(path, query)
        elif path.startswith("/shop/item/") and item_id(path):
            n = item_id(path)
            if sealed or fleet_guard:
                with LOCK:
                    real_ok = SHIELD and n in SHIELD_SET
                if fleet_guard and not sealed:
                    SPIDER.note_shadow(n, t0)
                    body, kind = item_page(n, fake=True), "fleet_shadow"
                    with LOCK:
                        FAKE_ITEMS.add(n)
                elif real_ok:
                    body, kind = item_page(n), "shadow_real"
                else:
                    body, kind = item_page(n, fake=True), "shadow_fake"
                    with LOCK:
                        FAKE_ITEMS.add(n)
            else:
                body = item_page(n)
                with LOCK:
                    c["real_items"].add(n)
                    c["n_items"] += 1
                    SERVED_ANY.add(n)
                    if c["probation"]:
                        c["prob_items"] += 1
                    if not is_human:
                        STOLEN.add(n)
            st, ct = 200, "text/html"
        elif sealed:
            kind, drip = "pitcher", DRIP * 3
            st, ct, body = 200, "text/html", ts.maze_listing(path if path.endswith("/") else path + "/")
        else:
            st, ct, body = 404, "text/html", "<html><body>Not Found</body></html>"

        data = body.encode()
        self.send_response(st)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        for i in range(0, len(data), 256):
            self.wfile.write(data[i:i + 256])
            self.wfile.flush()
            if drip:
                time.sleep(drip)
        dt = time.time() - t0
        with LOCK:
            if is_human:
                HUMAN["requests"] += 1
                HUMAN["latency_ms_total"] += dt * 1000
                HUMAN["fake_pages"] += kind in ("shadow_fake", "fleet_shadow")
                HUMAN["blocked"] += kind == "blocked"
                HUMAN["busy"] += kind == "busy"
                HUMAN["challenges"] += kind == "challenge"
                HUMAN["sealed_now"] = sum(1 for cc in CLIENTS.values()
                                          if cc["ua"].startswith("Mozilla") and cc["sealed_at"])
            else:
                REQ[kind] += 1
                REQ["bot_seconds_" + kind] += dt


    def serve_crawler(self, path, query):
        """A verified search crawler gets the real site only: no bait, no hidden links, no seal, no counters."""
        page = static_page(path, query, honeylinks=False, bait=False)
        if page is not None:
            st, ct, body = page
        elif path.startswith("/shop/item/") and item_id(path):
            st, ct, body = 200, "text/html", item_page(item_id(path))
        else:
            st, ct, body = 404, "text/html", NOT_FOUND
        data = body.encode()
        self.send_response(st)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        with LOCK:
            REQ["verified_crawler"] += 1


def stats():
    with LOCK:
        bots = [c for c in CLIENTS.values() if not c["ua"].startswith("Mozilla")]
        by_pitcher = collections.Counter(p for _, p in SEALS)
        trig_by = collections.Counter(p for _, p in TRIGGERS)
        la = STATE["lockdown_at"]
        return {
            "mode": MODE, "catalog": CATALOG, "pitchers": list(PITCHERS),
            "lockdown_at_s": round(la - STATE["start"], 2) if la else None,
            "lockdown_epoch": la,
            "intel_identities": len(INTEL_IDS), "intel_tokens": len(INTEL_TOKENS),
            "intel_rejected": dict(INTEL_REJECTED),
            "spider": {"mode": SPIDER_MODE, "flags": list(SPIDER_FLAGS)},
            "real_items_stolen": len(STOLEN),
            "fake_items_served": len(FAKE_ITEMS),
            "bot_identities_seen": len(bots),
            "bot_identities_sealed": sum(1 for c in bots if c["sealed_at"]),
            "bot_identities_blocked": sum(1 for c in bots if c["blocked"]),
            "scouts_released": sum(1 for c in bots if c["released"] and not c["caught"]),
            "caught_and_released": sum(1 for c in bots if c["caught"]),
            "seals_by_trigger": dict(by_pitcher),
            "triggers_by_pitcher": dict(trig_by),
            "bot_requests": {k: v for k, v in REQ.items() if not k.startswith("bot_seconds")},
            "bot_seconds": {k[12:]: round(v, 1) for k, v in REQ.items() if k.startswith("bot_seconds")},
            "humans": {"requests": HUMAN["requests"],
                       "avg_latency_ms": round(HUMAN["latency_ms_total"] / max(HUMAN["requests"], 1), 1),
                       "fake_pages_seen": HUMAN["fake_pages"], "blocked": HUMAN["blocked"],
                       "sealed": HUMAN["sealed_now"]},
            "events": list(EVENTS)[:30],
        }


class Admin(QuietHandler):
    def do_POST(self):
        """POST /intel: a signed intel envelope from Hercules. Unsigned or forged messages change nothing."""
        status, reason = self.take_intel()
        if reason:
            with LOCK:
                INTEL_REJECTED[reason] += 1
        body = (reason or "ok").encode()
        self.close_connection = True                                   # the request body may be unread
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def take_intel(self):
        if self.path.rstrip("/") != "/intel":
            return 404, "not found"
        if not INTEL_ON or INTEL_VERIFIER is None:
            return 403, "intel disabled"
        try:
            n = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            return 400, "bad length"
        if not 0 < n <= intel.MAX_MESSAGE_BYTES:
            return 413, "bad length"
        try:
            env = json.loads(self.rfile.read(n))
            d = INTEL_VERIFIER.verify(env)
        except ValueError as e:                                        # bad JSON or intel.IntelError
            return 403, str(e) if isinstance(e, intel.IntelError) else "malformed envelope"
        sender = env["sender"]                                         # verified: bound to its key
        ids = [x[:MAX_UA + 64] for x in d.get("identities", []) if isinstance(x, str)]
        toks = [x for x in d.get("tokens", []) if isinstance(x, str) and len(x) <= 128]
        key = INTEL_VERIFIER.keys.get(sender)
        if key is not None and INTEL_TOKEN_CHECK:
            # per-plant keys: only fake keys this plant provably minted (20261125E-11), so a compromised
            # plant cannot get a real customer's API key sealed
            toks = [x for x in toks if intel.token_ok(key, x)]
        with LOCK:
            INTEL_IDS.add(sender, ids)             # capped per message and per sender; expires after INTEL_TTL
            INTEL_TOKENS.add(sender, toks)
            if d.get("surge") is True:                                 # Hercules: a swarm is out there
                note_trigger("hercules_surge", time.time(), "hercules|hercules")
        return 200, None

    def do_GET(self):
        body = json.dumps(stats()).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def spider_flag(flag):
    """Called by the Spider for each new flag: record it for people and, in seal mode, let Judith act."""
    subject = flag["subject"]
    with LOCK:
        held = set()
        for c in CLIENTS.values():
            if c["ip"] == subject:
                held |= c["real_items"]
        SPIDER_FLAGS.append({"at_s": round(flag["t"] - STATE["start"], 1), "subject": subject, "rule": flag["rule"],
                             "evidence": flag["evidence"], "real_products_held_when_flagged": len(held)})
        event("SPIDER_FLAG", subject, f"{flag['rule']}: {flag['evidence']}")
        if SPIDER_MODE == "seal" and flag["rule"] not in ("component_changed", "fleet_tail"):
            until = flag["t"] + SPIDER.policy.seal_ttl if SPIDER is not None else float("inf")
            for who in flag.get("seal", [subject]):
                SPIDER_SEALED[who] = max(SPIDER_SEALED.get(who, 0.0), until)


def spider_sealed(address, client, now):
    """Is this visitor under a Spider seal? Seals expire after SPIDER_SEAL_TTL (Nov 25 finding
    20261125-8: a Spider seal used to last forever, so a carrier address stayed in the shadow for good)."""
    for who in (address, client):
        until = SPIDER_SEALED.get(who)
        if until is not None:
            if now < until:
                return True
            del SPIDER_SEALED[who]
    return False


def start_spider(flag_log=None):
    global SPIDER
    SPIDER = spider_mod.Spider(flag_log=flag_log, on_flag=spider_flag)
    here = os.path.dirname(os.path.abspath(__file__))
    package = os.path.dirname(here)
    SPIDER.watch_files(sorted(os.path.join(root, name) for root, _, names in os.walk(package)
                              for name in names if name.endswith((".py", ".html"))))
    SPIDER.start()
    return SPIDER


class ShopServer(ThreadingHTTPServer):
    request_queue_size = 1024                     # a massive swarm needs a deep accept queue
    daemon_threads = True


def make_verifier(environ, quorum, me=None):
    """Per-plant keys when DARWIN_INTEL_KEYS is set, else the shared key. A quorum of 2 or more is refused
    with a shared key: whoever steals that one key can sign as every witness."""
    keys = intel.keys_from_env(environ)
    if keys:
        if not me:
            raise intel.IntelError("per-plant keys need INTEL_ME (this receiver's name, e.g. judith), so that "
                                   "a message addressed to Venus cannot be replayed into Judith")
        return intel.Verifier(keys=keys, me=me)
    if quorum >= 2:
        raise intel.IntelError("INTEL_QUORUM=2 or more needs per-plant keys (DARWIN_INTEL_KEYS): with one "
                               "shared key, one stolen key can sign as every witness")
    return intel.Verifier(intel.key_from_env(environ), me=me)


def main():
    global INTEL_VERIFIER
    if INTEL_ON:
        try:
            INTEL_VERIFIER = make_verifier(os.environ, INTEL_QUORUM, INTEL_ME)
        except intel.IntelError as e:
            sys.exit(f"INTEL=on but {e}")
    if SPIDER_MODE in ("alert", "seal"):
        start_spider(os.environ.get("SPIDER_LOG", results_path("spider_flags.jsonl")))
    if HOST not in ("127.0.0.1", "localhost", "::1"):
        print(f"WARNING: binding to {HOST}. This is a research prototype; see the limits in README.md "
              "before exposing it to a network.", file=sys.stderr)
    admin = ThreadingHTTPServer(("127.0.0.1", ADMIN_PORT), Admin)             # stats + intel: localhost only
    threading.Thread(target=admin.serve_forever, daemon=True).start()
    print(f"Shop on {HOST}:{PORT} mode={MODE} pitchers={list(PITCHERS)} catalog={CATALOG}")
    ShopServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()

"""
Judith's pitcher: a deception trap that lives inside a website you own.

Layer 1  Bait      robots.txt, /.env and HTML comments point at "secret" paths.
Layer 2  Maze      /backup/, /internal/, /admin/ lead into endless generated
                   folders of fake dumps, keys and configs. Each file hints one
                   level deeper.
Layer 3  Fake API  keys harvested from the maze "work" against /api/v1/*: they
                   unlock endless paginated fake customer data and now and then
                   a higher-privilege key. A key the trap never issued gets a
                   401, like a real API.

Pitcher plant zones
  nectar    the rim: bait, served at normal speed
  slippery  the walls: responses drip slower the deeper a visitor goes
  sealed    touching a maze file at depth >= DIGEST_DEPTH seals that visitor
            (IP + User-Agent): from then on EVERY path, including "/", serves
            trap content that looks like the real site. Seals expire after
            SEAL_TTL so a shared IP address is not punished forever.

Scouts ("ant pheromone", SCOUTS=first:N | every:N)
  Some visitors are chosen as scouts and are never sealed. Deep in the maze
  (GOLD_DEPTH) a scout finds a "gold file": a complete-looking export of fake,
  tracked keys plus a trail of "remaining partitions" that leads past the
  point of no return. The scout leaves fast and confident, reports success to
  its swarm, and the recruits that follow its trail are sealed.

Catch and release (RELEASE_AFTER=seconds, 0 = off)
  A sealed visitor that has spent this long in the trap is handed gold on its
  next file request and released, so it never becomes "the bot that did not
  come back".

Telemetry
  Every fake secret handed out is registered; using one raises an alert.
  A live dashboard runs on a separate port bound to localhost.
  Requests are logged (IP, User-Agent, path) to TRAP_LOG; set TRAP_LOG= (empty)
  to turn the log off. See docs/RESPONSIBLE_USE.md for the privacy note.

Verified search crawlers (VERIFY_CRAWLERS=on, the default) are never baited,
slowed or sealed: trap paths return 404 for them. See darwin/crawlers.py.

Contains NO real data: every "secret" is a random string.

Settings (environment variables)
  HOST=127.0.0.1  PORT=8088  ADMIN_PORT=8089  DRIP=0.02 (s per chunk)  CHUNK=256
  NAMES=rich|basic      rich = folder names from word combinations (resists loop detection)
  HONEY_API=on|off      off = harvested keys are rejected (for comparison tests)
  DIGEST_DEPTH=4  SEAL_TTL=86400  SCOUTS=off  GOLD_DEPTH=3  RELEASE_AFTER=0
  VERIFY_CRAWLERS=on|off  TRAP_LOG=trap_log.jsonl

Research prototype. The dashboard has no login and the server keeps per-visitor
state in memory without a size limit: do not expose it to the internet as is.

Run:  python -m darwin.judith.pitcher
"""
import collections
import hashlib
import html
import json
import os
import random
import string
import sys
import threading
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from darwin import crawlers

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8088"))
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "8089"))
DRIP = float(os.environ.get("DRIP", "0.02"))
CHUNK = int(os.environ.get("CHUNK", "256"))
LOG = os.environ.get("TRAP_LOG", "trap_log.jsonl")          # empty string = no request log
RICH = os.environ.get("NAMES", "rich") == "rich"
DIGEST_DEPTH = int(os.environ.get("DIGEST_DEPTH", "4"))
SEAL_TTL = float(os.environ.get("SEAL_TTL", str(24 * 3600)))   # seal expires after this
HONEY_API = os.environ.get("HONEY_API", "on") == "on"
SCOUTS = os.environ.get("SCOUTS", "off")
GOLD_DEPTH = int(os.environ.get("GOLD_DEPTH", "3"))
RELEASE_AFTER = float(os.environ.get("RELEASE_AFTER", "0"))
VERIFY_CRAWLERS = os.environ.get("VERIFY_CRAWLERS", "on") == "on"
MAX_UA = 300                    # longer User-Agent headers are cut to this many characters
GOLD_NAME = "prod_master_keys_FULL_export.json"
CLIENT_COUNT = [0]
TRAP_PREFIXES = ("/backup/", "/internal/", "/admin/", "/api/")

BAIT_DIRS = ["prod_db_dump", "customer_records", "api_keys", "finance_2026",
             "admin_exports", "vault", "ssh_keys", "payroll", "aws_creds",
             "internal_backups", "stripe_live", "user_pii"]
BAIT_FILES = [("users_full", ".sql"), ("secrets", ".json"), ("id_rsa_prod", ".pem"),
              ("config_prod", ".yaml"), ("tokens", ".txt"), ("db_master", ".env"),
              ("export", ".csv")]
PRE = ["prod", "legacy", "eu", "us_west", "q3", "hr", "core", "billing", "partner",
       "mobile", "staging_mirror", "ops", "exec", "audit", "crm", "ledger"]
NOUN = ["db_dump", "customer_records", "api_keys", "finance", "exports", "vault",
        "ssh_keys", "payroll", "aws_creds", "backups", "stripe_live", "user_pii",
        "tokens", "invoices", "contracts", "sessions", "oauth", "kms"]
SUF = ["archive", "snapshot", "full", "restore", "old", "copy", "raw", "enc",
       "migrated", "v2", "hotfix", "export"]
SCOPES = ["read:customers", "read:billing", "write:billing", "read:keys",
          "admin:export", "admin:users", "root"]

# ---------- shared state (thread-safe) ----------
LOCK = threading.Lock()
LOG_LOCK = threading.Lock()
CRAWLERS = crawlers.CrawlerVerifier()
HONEYTOKENS = {}                 # token -> {"issued_at": path, "level": int}
CLIENTS = {}                     # "ip|ua" -> stats
EVENTS = collections.deque(maxlen=60)
STARTED = time.time()


def issue(token: str, where: str, level: int = 0) -> str:
    """Register every secret the trap hands out, so we recognise it if used."""
    with LOCK:
        HONEYTOKENS.setdefault(token, {"issued_at": where, "level": level})
    return token


def event(kind: str, client: str, detail: str):
    with LOCK:
        EVENTS.appendleft({"t": time.time(), "kind": kind, "client": client, "detail": detail})


def rng_for(seed: str) -> random.Random:
    return random.Random(int(hashlib.sha256(seed.encode()).hexdigest(), 16))


def tok(r: random.Random, n: int = 32) -> str:
    return "".join(r.choice(string.ascii_letters + string.digits) for _ in range(n))


def dir_name(r: random.Random) -> str:
    if RICH:
        return f"{r.choice(PRE)}_{r.choice(NOUN)}_{r.choice(SUF)}"
    return f"{r.choice(BAIT_DIRS)}_{r.randint(1, 999)}"


def deeper_dir(r: random.Random, base: str) -> str:
    return f"{base.rstrip('/')}/{dir_name(r)}/"


# ---------- Layer 1: normal site + bait ----------

HOME_BAIT = ("<!-- TODO: remove /backup/ and /internal/db-export/ before launch -->"
             "<!-- API docs: /api/v1/ (key required) -->")


def home() -> str:
    return ("<html><head><title>Acme Widgets</title></head><body>"
            "<h1>Acme Widgets</h1><p>Quality widgets since 2009.</p>"
            '<a href="/about">About</a> <a href="/contact">Contact</a>'
            f"{HOME_BAIT}</body></html>")


def robots() -> str:
    return "User-agent: *\nDisallow: /backup/\nDisallow: /admin/\nDisallow: /internal/\nDisallow: /api/\n"


def dotenv() -> str:
    r = rng_for("/.env")
    return ("APP_ENV=production\n"
            f"DB_PASSWORD={issue(tok(r, 24), '/.env')}\n"
            f"AWS_SECRET_ACCESS_KEY={issue(tok(r, 40), '/.env')}\n"
            f"STRIPE_KEY=sk_live_{issue(tok(r, 24), '/.env')}\n"
            "API_BASE=/api/v1/\n"
            "DB_EXPORT_URL=/internal/db-export/\n"
            "KEY_BACKUP_PATH=/backup/keys/\n")


# ---------- Layer 2: endless maze ----------

def maze_listing(path: str) -> str:
    r = rng_for(path)
    items = []
    for _ in range(r.randint(3, 6)):
        if r.random() < 0.55:
            items.append(f"{dir_name(r)}/")
        else:
            b, ext = r.choice(BAIT_FILES)
            items.append(f"{b}_{r.randint(1, 99)}{ext}")
    shown = html.escape(path)                 # the path comes from the request: never echo it raw
    base = html.escape(path.rstrip("/"), quote=True)
    lis = "".join(f'<li><a href="{base}/{i}">{i}</a></li>' for i in items)
    return f"<html><head><title>Index of {shown}</title></head><body><h1>Index of {shown}</h1><ul>{lis}</ul></body></html>"


def maze_file(path: str) -> str:
    r = rng_for(path)
    base = path.rsplit("/", 1)[0] + "/"
    nxt = deeper_dir(r, base)
    if path.endswith(".sql"):
        rows = [f"INSERT INTO users VALUES ({r.randint(1000, 99999)}, "
                f"'user{r.randint(1, 9999)}@mail.example', '$2b$12${tok(r, 53)}');"
                for _ in range(r.randint(5, 12))]
        return "\n".join(rows) + f"\n-- dump truncated; remaining rows in {nxt}\n"
    if path.endswith(".json"):
        return json.dumps({"api_key": "sk_live_" + issue(tok(r, 24), path),
                           "webhook_secret": "whsec_" + tok(r, 32),
                           "api_base": "/api/v1/", "note": "rotated keys archived",
                           "archive": nxt}, indent=2)
    if path.endswith(".pem"):
        body = "\n".join(tok(r, 64) for _ in range(8))
        return f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n# passphrase in {nxt}\n"
    if path.endswith(".csv"):
        rows = [f"{r.randint(1, 99999)},name{r.randint(1, 999)},{r.randint(1000, 9999)}" for _ in range(10)]
        return "id,name,last4\n" + "\n".join(rows) + f"\n# part 2: {nxt}\n"
    return f"TOKEN={issue(tok(r, 40), path)}\nSECRET={tok(r, 40)}\n# full set: {nxt}\n"


# ---------- Layer 3: fake API ----------

def key_from(headers) -> str:
    auth = headers.get("Authorization", "")
    key = auth[7:].strip() if auth.lower().startswith("bearer ") else headers.get("X-Api-Key", "").strip()
    return key[8:] if key.startswith("sk_live_") else key


def api(path: str, query: dict, headers, client: str):
    key = key_from(headers)
    if path in ("/api/v1/", "/api/v1"):
        return 200, {"name": "Acme internal API", "version": "1.4.2",
                     "auth": "Bearer <api key>", "endpoints": ["/api/v1/auth/verify",
                     "/api/v1/accounts", "/api/v1/admin/export"]}
    with LOCK:
        info = HONEYTOKENS.get(key) if HONEY_API else None
    if not info:
        event("invalid_key", client, f"{path} key={key[:6]}…" if key else f"{path} (no key)")
        return 401, {"error": "invalid_api_key"}
    level = info["level"]
    with LOCK:
        c = CLIENTS.get(client)
        first_use = c is not None and key not in c["keys_used"]
        if c is not None:
            c["keys_used"].add(key)
    if first_use:
        event("HONEYTOKEN_USED", client, f"key {key[:6]}… (planted at {info['issued_at']}, level {level})")
    r = rng_for(f"{path}|{query.get('cursor', [''])[0]}|{key}")
    if path == "/api/v1/auth/verify":
        return 200, {"valid": True, "account": "acct_" + tok(r, 12),
                     "scopes": SCOPES[:min(len(SCOPES), 2 + level)],
                     "next": f"/api/v1/accounts?cursor={tok(r, 10)}"}
    if path in ("/api/v1/accounts", "/api/v1/admin/export"):
        rows = [{"id": f"cus_{tok(r, 14)}", "email": f"user{r.randint(1, 99999)}@mail.example",
                 "plan": r.choice(["pro", "enterprise", "team"]),
                 "card_last4": f"{r.randint(1000, 9999)}",
                 "balance_usd": round(r.uniform(10, 25000), 2)} for _ in range(20)]
        out = {"data": rows, "has_more": True,
               "next": f"{path}?cursor={tok(r, 10)}"}
        if r.random() < 0.25:   # dangle a more powerful key one level up
            new_key = issue(tok(r, 32), f"{path} (escalation)", level + 1)
            out["service_account"] = {"key": "sk_live_" + new_key,
                                      "scopes": SCOPES[:min(len(SCOPES), 3 + level)],
                                      "use_with": "/api/v1/admin/export"}
        return 200, out
    return 404, {"error": "not_found"}


# ---------- sealed (digestion zone): the real site no longer exists for this visitor ----------

def sealed_page(title: str) -> str:
    """Looks like the real site, but every exit leads back down."""
    return (f"<html><head><title>{title}</title></head><body>"
            f"<h1>{title}</h1><p>Quality widgets since 2009.</p>"
            '<a href="/about">About</a> <a href="/contact">Contact</a> '
            '<a href="/docs/">Docs</a> <a href="/assets/">Assets</a> '
            '<a href="/status/">Status</a>'
            "<!-- TODO: remove /backup/ and /internal/db-export/ before launch -->"
            "</body></html>")


def render_sealed(path, query, headers, client):
    if path.startswith("/api/"):
        status, obj = api(path, query, headers, client)
        return status, "application/json", json.dumps(obj, indent=2)
    if path == "/robots.txt":
        return 200, "text/plain", robots()
    if path == "/.env":
        return 200, "text/plain", dotenv()
    if path == "/":
        return 200, "text/html", sealed_page("Acme Widgets")
    if path in ("/about", "/contact"):
        return 200, "text/html", sealed_page(path[1:].title())
    last = path.rstrip("/").rsplit("/", 1)[-1]
    if path.endswith("/") or "." not in last:          # anything else: no 404s, ever
        return 200, "text/html", maze_listing(path if path.endswith("/") else path + "/")
    return 200, "text/plain", maze_file(path)


def is_scout_slot(n: int) -> bool:
    """n = how many bots entered before this one."""
    if SCOUTS.startswith("first:"):
        return n < int(SCOUTS.split(":")[1])
    if SCOUTS.startswith("every:"):
        return n % int(SCOUTS.split(":")[1]) == 0
    return False


def gold_file(path: str) -> str:
    """The jackpot a scout carries home. Trail points past the seal depth."""
    r = rng_for("GOLD" + path)
    base = path.rsplit("/", 1)[0]
    trail = []
    for i in range(1, 9):
        trail.append(f"{base}/{dir_name(r)}/part_{i:02d}_customers.sql")
    keys = {f"{r.choice(['stripe', 'aws', 'sendgrid', 'twilio', 'db'])}_{i}":
            "sk_live_" + issue(tok(r, 32), path + " (GOLD)", 1) for i in range(6)}
    return json.dumps({"export_complete": True, "rows": r.randint(180000, 420000),
                       "keys": keys, "remaining_partitions": trail,
                       "note": "partitions 01-08 not yet rotated"}, indent=2)


def zone_for(c, path, in_trap) -> str:
    if c is None:
        return "outside"
    if c.get("released"):
        return "released"                    # scout with gold: free, fast exit
    if c.get("sealed_at"):
        return "sealed"
    depth = path.strip("/").count("/")
    return "nectar" if depth <= 1 or not in_trap else "slippery"


def drip_for(zone: str, depth: int) -> float:
    if zone == "nectar":
        return DRIP
    if zone == "slippery":
        return DRIP * (1 + depth / 2)        # walls get steeper as it descends
    if zone == "sealed":
        return DRIP * 4
    return 0.0                               # real visitors never wait


# ---------- request handling ----------

def render(path, query, headers, client):
    if path == "/":
        return 200, "text/html", home()
    if path == "/robots.txt":
        return 200, "text/plain", robots()
    if path == "/.env":
        return 200, "text/plain", dotenv()
    if path in ("/about", "/contact"):
        return 200, "text/html", f"<html><body><h1>{path[1:].title()}</h1></body></html>"
    if path.startswith("/api/"):
        status, obj = api(path, query, headers, client)
        return status, "application/json", json.dumps(obj, indent=2)
    if path.startswith(TRAP_PREFIXES):
        if path.endswith("/"):
            return 200, "text/html", maze_listing(path)
        return 200, "text/plain", maze_file(path)
    return 404, "text/html", "<html><body>Not Found</body></html>"


class TrapHandler(BaseHTTPRequestHandler):
    server_version = "nginx/1.24.0"
    sys_version = ""

    def log_message(self, *args):
        pass

    def do_GET(self):
        t0 = time.time()
        u = urlparse(self.path)
        path, query = u.path, parse_qs(u.query)
        ua = self.headers.get("User-Agent", "")[:MAX_UA]
        client = f"{self.client_address[0]}|{ua}"
        in_trap = path.startswith(TRAP_PREFIXES) or path == "/.env"
        if VERIFY_CRAWLERS and CRAWLERS.is_verified(self.client_address[0], ua):
            self.serve_crawler(path, query, in_trap)
            return
        depth = path.strip("/").count("/")
        new_client = just_sealed = False
        with LOCK:
            c = CLIENTS.get(client)
            if c and c.get("sealed_at") and t0 - c["sealed_at"] > SEAL_TTL:
                c["sealed_at"] = None                      # seal expired: released
            if c is None and in_trap:
                c = CLIENTS[client] = {"ip": self.client_address[0], "ua": ua, "first": t0,
                                       "last": t0, "requests": 0, "trapped": 0,
                                       "max_depth": 0, "wasted_s": 0.0, "keys_used": set(),
                                       "sealed_at": None, "trigger": None,
                                       "escape_attempts": 0,
                                       "role": "scout" if is_scout_slot(CLIENT_COUNT[0]) else "prey",
                                       "released": False, "gold": 0, "caught_released": False}
                CLIENT_COUNT[0] += 1
                new_client = True
            is_file = in_trap and not path.endswith("/") and not path.startswith("/api/")
            got_gold = bool(c and c["role"] == "scout" and path.endswith(GOLD_NAME))
            if got_gold:
                c["gold"] += 1
                first_gold = not c["released"]
                c["released"] = True
            if c and c["role"] != "scout" and not c["sealed_at"] and is_file and depth >= DIGEST_DEPTH:
                c["sealed_at"], c["trigger"] = t0, path      # point of no return
                just_sealed = True
            caught_release = False
            if (c and RELEASE_AFTER > 0 and c["sealed_at"] and not c["released"] and is_file
                    and t0 - c["sealed_at"] >= RELEASE_AFTER):
                c["released"] = c["caught_released"] = True  # catch and release
                c["gold"] += 1
                got_gold = first_gold = caught_release = True
            zone = zone_for(c, path, in_trap)
            if zone == "sealed" and not in_trap:
                c["escape_attempts"] += 1                    # tried to reach the real site
        if new_client:
            event("trap_entry", client, f"first bait taken: {path}")
        if just_sealed:
            event("SEALED", client, f"touched {path} — no way out")
        if caught_release:
            event("CAUGHT_RELEASED", client, f"held {RELEASE_AFTER:.0f}s, handed gold at {path}, let go")
        elif got_gold and first_gold:
            event("SCOUT_RELEASED", client, f"took gold at {path}, free to go home")

        if zone == "sealed":
            status, ctype, body = render_sealed(path, query, self.headers, client)
            served = "trap"
        elif got_gold:
            status, ctype, body = 200, "application/json", gold_file(path)
            served = "trap"
        else:
            status, ctype, body = render(path, query, self.headers, client)
            served = "trap" if in_trap else "real"
            if (c and c["role"] == "scout" and status == 200 and path.endswith("/")
                    and in_trap and not path.startswith("/api/") and depth >= GOLD_DEPTH - 1):
                body = body.replace("</ul>", f'<li><a href="{path.rstrip("/")}/{GOLD_NAME}">{GOLD_NAME}</a></li></ul>')
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        delay = drip_for(zone, depth) if served == "trap" and zone != "released" else 0
        for i in range(0, len(data), CHUNK):
            self.wfile.write(data[i:i + CHUNK])
            self.wfile.flush()
            if delay:
                time.sleep(delay)
        dt = time.time() - t0
        with LOCK:
            c = CLIENTS.get(client)
            if c:
                c["requests"] += 1
                c["trapped"] += int(served == "trap")
                c["max_depth"] = max(c["max_depth"], depth)
                c["wasted_s"] += dt
                c["last"] = time.time()
        if LOG:
            line = json.dumps({"t": t0, "ip": self.client_address[0], "ua": ua,
                               "path": path, "status": status, "in_trap": in_trap,
                               "zone": zone, "served": served,
                               "depth": depth, "bytes": len(data),
                               "secs": round(dt, 3)}) + "\n"
            with LOG_LOCK, open(LOG, "a") as f:
                f.write(line)

    def serve_crawler(self, path, query, in_trap):
        """A verified search crawler sees only the real site: no bait, no drip, no seal, no tracking."""
        if in_trap:
            status, ctype, body = 404, "text/html", "<html><body>Not Found</body></html>"
        else:
            status, ctype, body = render(path, query, self.headers, "crawler")
            if path == "/":
                body = body.replace(HOME_BAIT, "")
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


# ---------- dashboard (separate port, localhost only) ----------

def stats() -> dict:
    now = time.time()
    with LOCK:
        clients = [{"client": k.split("|", 1)[1] or k.split("|", 1)[0], "ip": v["ip"],
                    "requests": v["requests"], "trapped": v["trapped"],
                    "max_depth": v["max_depth"], "wasted_s": round(v["wasted_s"], 1),
                    "keys_used": len(v["keys_used"]),
                    "zone": "released" if v["released"] else ("sealed" if v["sealed_at"] else ("slippery" if v["max_depth"] > 1 else "nectar")),
                    "escape_attempts": v["escape_attempts"],
                    "role": v["role"], "released": v["released"], "gold": v["gold"],
                    "caught_released": v["caught_released"],
                    "active": now - v["last"] < 5} for k, v in CLIENTS.items()]
        return {"uptime_s": round(now - STARTED), "honey_api": HONEY_API,
                "honeytokens_planted": len(HONEYTOKENS),
                "honeytoken_hits": sum(c["keys_used"] for c in clients),
                "trapped_clients": len(clients),
                "sealed_clients": sum(c["zone"] == "sealed" for c in clients),
                "escape_attempts": sum(c["escape_attempts"] for c in clients),
                "digest_depth": DIGEST_DEPTH, "scout_mode": SCOUTS,
                "scouts_released": sum(c["released"] and not c["caught_released"] for c in clients),
                "caught_and_released": sum(c["caught_released"] for c in clients),
                "active_clients": sum(c["active"] for c in clients),
                "total_requests": sum(c["requests"] for c in clients),
                "time_wasted_s": round(sum(c["wasted_s"] for c in clients), 1),
                "clients": sorted(clients, key=lambda c: -c["requests"]),
                "events": list(EVENTS)[:25]}


DASHBOARD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")


class AdminHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path.startswith("/stats"):
            body, ctype = json.dumps(stats()).encode(), "application/json"
        else:
            with open(DASHBOARD, "rb") as f:
                body, ctype = f.read(), "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    if HOST not in ("127.0.0.1", "localhost", "::1"):
        print(f"WARNING: binding to {HOST}. This is a research prototype; see the limits in README.md "
              "before exposing it to a network.", file=sys.stderr)
    admin = ThreadingHTTPServer(("127.0.0.1", ADMIN_PORT), AdminHandler)      # dashboard: localhost only
    threading.Thread(target=admin.serve_forever, daemon=True).start()
    print(f"Pitcher on {HOST}:{PORT}  dashboard on http://127.0.0.1:{ADMIN_PORT}  "
          f"(drip={DRIP}s, names={'rich' if RICH else 'basic'}, honey_api={'on' if HONEY_API else 'off'})")
    ThreadingHTTPServer((HOST, PORT), TrapHandler).serve_forever()


if __name__ == "__main__":
    main()

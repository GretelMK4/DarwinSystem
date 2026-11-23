"""
Hercules: the sundew. A farm of fake servers with no real purpose.

Nobody legitimate ever visits them, so every visitor is treated as an
attacker from the first request: there is no staged descent and no release.
Everything served is sticky: endless generated folders, fake key files, a
fake API where planted keys "work". Responses are FAST (aggressive swarms
abandon slow servers), but they never end.

Digestion = intelligence: every visitor identity and every fake key handed
out is recorded, and can be shared with Judith (and anyone else).

uniform        all sites share one server header, one page layout, one content
               generator (a lazy honeyfarm; easy to fingerprint)
diverse        each site gets its own server header, layout, content salt and timing
per_site_keys  a site's fake API accepts only keys that site issued, so a swarm
               cannot unmask the whole farm by trying one site's key on another
surge reports  surge_n new visitors within surge_window seconds = "a swarm is
               sweeping the internet"; passed on with the rest of the intel

All brands are fictional. Sites bind to localhost. Visitor identities (the
User-Agent header) are kept in memory; see docs/RESPONSIBLE_USE.md.

Hercules is a library: create a Hercules(...), call start(), and poll
take_intel() or take_signed_intel(key). See simulations/ecosystem/full.py.
"""
import hashlib
import html
import json
import random
import threading
import time
from http.server import ThreadingHTTPServer
from urllib.parse import urlparse

from darwin import intel
from darwin.httpbase import QuietHandler
from darwin.judith import pitcher as ts

BRANDS = ["Vaultline", "Ledgerly", "Northgate", "KeyNest", "Brightpay", "Coldharbor",
          "Orbisure", "Quillmark", "Stonecrest", "Helixa", "Tallowmere", "Juniperline"]
ROLES = ["backup-prod", "admin", "db-export", "staging", "vault", "api-internal", "files", "ops"]
HEADERS = ["nginx/1.24.0", "Apache/2.4.58 (Ubuntu)", "nginx/1.18.0", "Caddy", "Microsoft-IIS/10.0",
           "LiteSpeed", "openresty/1.21.4", "Apache/2.4.41"]


def _templates(brand, prefixes):
    c = "<!-- TODO: remove " + " and ".join(prefixes) + " before go-live -->"
    return [
        f"<html><head><title>{brand}</title></head><body><h1>{brand}</h1><p>Internal portal.</p>"
        f'<a href="/login">Login</a>{c}<!-- API: /api/v1/ --></body></html>',
        f"<!doctype html><html><head><meta charset=utf-8><title>{brand} | Sign in</title></head><body>"
        f"<div class=wrap><header><span>{brand}</span></header><main><form><input name=u><input name=p "
        f"type=password><button>Sign in</button></form></main><footer>v3.2 {c}</footer></div></body></html>",
        f"<html><body><table><tr><td><b>{brand} Ops</b></td></tr><tr><td>Status: OK</td></tr></table>"
        f"<p><i>build 7731</i></p>{c}<p>docs at /api/v1/</p></body></html>",
        f"<!DOCTYPE html><html lang=en><head><title>{brand} Dashboard</title><link rel=stylesheet "
        f"href=/s.css></head><body><nav><ul><li>Home</li><li>Reports</li></ul></nav><section><h2>Welcome"
        f"</h2></section>{c}<script>var api='/api/v1/'</script></body></html>",
        f"<html><head><title>Index</title></head><body><pre>{brand} file server\n</pre><hr>"
        f"<address>{brand}</address>{c}<!-- /api/v1/ --></body></html>",
        f"<html><head><title>{brand} Admin</title></head><body><div><div><div><p>Restricted.</p>"
        f"</div></div></div><span>{c}</span><em>api /api/v1/</em></body></html>",
    ]


class Hercules:
    def __init__(self, n, diverse, seed=0, port_base=9500, per_site_keys=False, surge_n=30, surge_window=10):
        self.diverse = diverse
        self.per_site_keys = per_site_keys        # a site's API only accepts keys it issued itself
        self.site_keys = {}
        self.surge_n, self.surge_window = surge_n, surge_window
        self.new_times, self.surge_flag, self.surges = [], False, 0
        rng = random.Random(seed)
        self.lock = threading.Lock()
        self.visitors = {}
        self.pending_ids = []
        self.issued = []
        self.requests = 0
        self.req_seconds = 0.0
        self.sites = []
        brands = rng.sample(BRANDS, n)
        for i in range(n):
            pre = rng.sample(["/backup/", "/internal/", "/admin/", "/.git/", "/exports/"], 3) if diverse \
                else ["/backup/", "/internal/", "/admin/"]
            self.sites.append({
                "name": f"{rng.choice(ROLES)}.{brands[i].lower()}.example", "brand": brands[i],
                "port": port_base + i, "prefixes": pre,
                "header": rng.choice(HEADERS) if diverse else "nginx/1.24.0",
                "template": rng.randrange(6) if diverse else 0,
                "salt": f"{brands[i]}{seed}" if diverse else "", "jitter": diverse})
        self.servers = []

    # ---- sticky content ----
    def _rng(self, site, path):
        return random.Random(int(hashlib.sha256((site["salt"] + path).encode()).hexdigest(), 16))

    def _issue(self, token, where, site=None):
        ts.issue(token, where)
        with self.lock:
            self.issued.append(token)
            if site is not None:
                self.site_keys.setdefault(site["name"], set()).add(token)
        return token

    def listing(self, site, path):
        r = self._rng(site, path)
        items = []
        for _ in range(r.randint(3, 6)):
            if r.random() < 0.55:
                items.append(f"{ts.dir_name(r)}/")
            else:
                b, ext = r.choice(ts.BAIT_FILES)
                items.append(f"{b}_{r.randint(1, 99)}{ext}")
        shown = html.escape(path)                # the path comes from the request: never echo it raw
        base = html.escape(path.rstrip("/"), quote=True)
        lis = "".join(f'<li><a href="{base}/{i}">{i}</a></li>' for i in items)
        return f"<html><head><title>Index of {shown}</title></head><body><h1>Index of {shown}</h1><ul>{lis}</ul></body></html>"

    def file(self, site, path):
        r = self._rng(site, path)
        nxt = f"{path.rsplit('/', 1)[0]}/{ts.dir_name(r)}/"
        return (f"api_key=sk_live_{self._issue(ts.tok(r, 28), site['name'] + path, site)}\n"
                f"DB_PASSWORD={ts.tok(r, 20)}\n# remaining exports: {nxt}\n")

    def dotenv(self, site):
        r = self._rng(site, "/.env")
        return (f"APP_ENV=production\nSTRIPE_KEY=sk_live_{self._issue(ts.tok(r, 28), site['name'] + '/.env', site)}\n"
                f"DB_PASSWORD={ts.tok(r, 20)}\nAPI_BASE=/api/v1/\n"
                + "".join(f"PATH_{i}={p}\n" for i, p in enumerate(site["prefixes"])))

    def api(self, site, path, headers):
        key = ts.key_from(headers)
        if path.rstrip("/") == "/api/v1":
            return 200, {"name": f"{site['brand']} internal API", "endpoints": ["/api/v1/auth/verify", "/api/v1/accounts"]}
        with self.lock:
            valid = key in self.site_keys.get(site["name"], set()) if self.per_site_keys else key in ts.HONEYTOKENS
        if not valid:
            return 401, {"error": "invalid_api_key"}
        r = self._rng(site, path + key)
        return 200, {"valid": True, "data": [{"id": ts.tok(r, 10), "balance": round(r.uniform(10, 9000), 2)}
                                             for _ in range(10)],
                     "service_key": "sk_live_" + self._issue(ts.tok(r, 28), site["name"] + " api", site),
                     "next": "/api/v1/accounts?cursor=" + ts.tok(r, 8)}

    # ---- servers ----
    def handler(self, site):
        herc = self

        class H(QuietHandler):
            server_version = site["header"]

            def do_GET(self):
                t0 = time.time()
                path = urlparse(self.path).path
                ua = self.headers.get("User-Agent", "")[:ts.MAX_UA]
                if path == "/":
                    body = _templates(site["brand"], site["prefixes"])[site["template"]]
                    st, ct = 200, "text/html"
                elif path == "/robots.txt":
                    body, st, ct = "User-agent: *\n" + "".join(f"Disallow: {p}\n" for p in site["prefixes"]) \
                        + "Disallow: /api/\n", 200, "text/plain"
                elif path == "/.env":
                    body, st, ct = herc.dotenv(site), 200, "text/plain"
                elif path.startswith("/api/"):
                    st, obj = herc.api(site, path, self.headers)
                    body, ct = json.dumps(obj), "application/json"
                elif path.endswith("/"):
                    body, st, ct = herc.listing(site, path), 200, "text/html"
                else:
                    body, st, ct = herc.file(site, path), 200, "text/plain"
                if site["jitter"]:
                    time.sleep(random.uniform(0, 0.03))
                data = body.encode()
                self.send_response(st)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                dt = time.time() - t0
                with herc.lock:
                    herc.requests += 1
                    herc.req_seconds += dt
                    v = herc.visitors.get(ua)
                    if v is None:
                        v = herc.visitors[ua] = {"first": t0, "requests": 0, "sites": set()}
                        herc.pending_ids.append(ua)
                        herc.new_times = [x for x in herc.new_times if t0 - x <= herc.surge_window] + [t0]
                        if len(herc.new_times) >= herc.surge_n:      # a swarm is sweeping the internet
                            herc.surge_flag = True
                    v["requests"] += 1
                    v["last"] = time.time()
                    v["sites"].add(site["name"])
        return H

    def start(self):
        for s in self.sites:
            srv = ThreadingHTTPServer(("127.0.0.1", s["port"]), self.handler(s))
            srv.daemon_threads = True
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self.servers.append(srv)

    def stop(self):
        for s in self.servers:
            s.shutdown()

    def take_intel(self):
        with self.lock:
            ids, self.pending_ids = self.pending_ids, []
            toks, self.issued = self.issued, []
            surge, self.surge_flag = self.surge_flag, False
            self.surges += surge
        return ids, toks, surge

    def take_signed_intel(self, key: bytes):
        """The same intel as take_intel(), wrapped in a signed envelope for Judith. None if there is no news."""
        ids, toks, surge = self.take_intel()
        if not (ids or toks or surge):
            return None
        return intel.sign({"identities": ids, "tokens": toks, "surge": bool(surge)}, key, sender="hercules")

    def stats(self):
        with self.lock:
            return {"sites": len(self.sites), "diverse": self.diverse, "per_site_keys": self.per_site_keys,
                    "surge_reports_sent": self.surges, "identities_caught": len(self.visitors),
                    "requests_absorbed": self.requests,
                    "median_requests_per_visitor": sorted(v["requests"] for v in self.visitors.values())[
                        len(self.visitors) // 2] if self.visitors else 0}

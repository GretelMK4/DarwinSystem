"""
Full ecosystem test: Judith (pitcher plants in a real site), Hercules (sundew
honeyfarm) and Venus (phone flytraps), against a maximum-intelligence swarm.

The simulated internet
  60 ordinary small-business sites, 0 or 8 Hercules sites, and Judith's shop
  (a real 6,000-item catalog worth stealing, with 5 pitchers + lockdown).
  A public certificate log lists every host, as on the real internet.

The swarm (300 bots, one operator)
  sweep    split the certificate log, sniff every host (/, robots.txt, .env)
  detect   honeyfarm fingerprinting: 3+ "juicy" hosts with an identical server
           header + page layout => all hosts with that fingerprint are
           blacklisted. Slow hosts (>1 s per reply) are blacklisted as tarpits.
  hunt     30% dig the juiciest hosts for secrets: depth limits, loop
           detection, an 8-second cap per host, then flag the path as a trap
  spray    every stolen key is tried against every host that has an API
  scrape   70% split the catalog between them as fast as possible, check
           their copies against each other, switch identity (up to 8 times)
           when burned or rate-limited, throw away suspect data
  phones   the same operator runs malware on 200 phones (mix of the five
           phone attackers from darwin/venus/decoy_apps_model.py), infected over an
           hour, sending loot to 20 drop servers

Defences
  none         nothing
  judith       Judith only
  separate     Judith + Hercules (uniform) + Venus on every phone, no sharing
  ecosystem    + sharing: Hercules -> Judith (identities, fake keys);
               Venus phones share the drop servers they catch with each other
  eco_diverse  ecosystem, with Hercules sites made to look different

Usage: python -m simulations.ecosystem.full <config> [seed]
These are models of attacker behaviour chosen by me, not real malware.
"""
import collections
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler

CATALOG = int(os.environ.get("CATALOG", "6000"))
os.environ["CATALOG"] = str(CATALOG)
from darwin import intel             # noqa: E402
from simulations import common       # noqa: E402
from simulations.ecosystem import fake_internet as eco          # noqa: E402  ordinary sites
from darwin.judith import shop as fs         # noqa: E402  ground-truth product pages
from darwin.hercules import honeyfarm as hz                # noqa: E402
from darwin.venus import decoy_apps_model as pd    # noqa: E402

JUDITH = "http://127.0.0.1:8088"
JUDITH_ADMIN = "http://127.0.0.1:8089"
CT_PORT = 9950
N_BOTS = int(os.environ.get("N_BOTS", "300"))
N_PHONES = int(os.environ.get("N_PHONES", "200"))
SWARM = os.environ.get("SWARM", "v1")
ALL_TACTICS = ["verifier", "compartment", "quiet_target", "cross_key", "phones_evasive"]
OFF = set(filter(None, os.environ.get("TACTICS_OFF", "").split(",")))
V4 = SWARM in ("v4b", "v4s", "v4x")
TACTICS = ((set(ALL_TACTICS)
            | ({"skip_hidden"} if SWARM in ("v3", "v4b", "v4s", "v4x") else set())
            | ({"challenge_solver", "adaptive", "random_order"} if V4 else set())
            | ({"stealth"} if SWARM in ("v4s", "v4x") else set())) - OFF) \
    if SWARM in ("v2", "v3", "v4b", "v4s", "v4x") else set()
# v4x knows every threshold and stays just under all of them
STEALTH_REQ = {"v4s": 150.0, "v4x": 9.0}.get(SWARM, 150.0)
STEALTH_ID = {"v4s": 6.0, "v4x": 6.0}.get(SWARM, 6.0)
FIXES_ALL = ["honeylinks", "surge", "site_keys", "fingerprint"]
FIX_OFF = set(filter(None, os.environ.get("FIX_OFF", "").split(",")))
PACE = 0.04
BOT_SECONDS = 60
TIMEOUT = 2.0
MAX_ROT = {"v2": 20, "v3": 20, "v4b": 40, "v4s": 40, "v4x": 40}.get(os.environ.get("SWARM", "v1"), 8)
CANARY_EVERY = 10
KEY_RE = re.compile(r'(?:sk_live_|TOKEN=|AWS_SECRET_ACCESS_KEY=|DB_PASSWORD=|STRIPE_KEY=sk_live_)([A-Za-z0-9]{20,})')
JUICY = ("backup", "internal", "admin", ".git", "export", "api", "vault", "db")
H = lambda s: hashlib.sha1(s.encode()).hexdigest()

CONFIGS = {
    "none":        dict(judith="none",     herc=0, diverse=False, venus=False, share=False),
    "judith":      dict(judith="lockdown", herc=0, diverse=False, venus=False, share=False),
    "separate":    dict(judith="lockdown", herc=8, diverse=False, venus=True,  share=False),
    "ecosystem":   dict(judith="lockdown", herc=8, diverse=False, venus=True,  share=True),
    "eco_diverse": dict(judith="lockdown", herc=8, diverse=True,  venus=True,  share=True),
    "eco_v2":      dict(judith="lockdown", herc=8, diverse=True,  venus=True,  share=True, v2=True),
    "eco_v3":      dict(judith="lockdown", herc=8, diverse=True,  venus=True,  share=True, v2=True, v3=True),
}


class Board:
    def __init__(self, hosts):
        self.lock = threading.Lock()
        self.sniff_q = collections.deque(hosts)
        self.info = {}
        self.fp_bait = collections.defaultdict(set)
        self.honey_fps = set()
        self.blacklist = set()
        self.trap_prefix = collections.defaultdict(set)
        self.hunt_q = collections.deque()
        self.api_hosts = set()
        self.keys = collections.deque()
        self.keys_seen = set()
        self.catalog = None
        self.pages, self.pages_seen = collections.deque([1]), {1}
        self.items, self.items_seen = collections.deque(), set()
        self.believed, self.ref = {}, {}
        self.req_by_host = collections.Counter()
        self.c = collections.Counter()
        self.done_at = None
        self.key_origin = {}
        self.verified = {}
        self.burned_ids = set()
        self.pace = 1.2 if "stealth" in TACTICS else 0.0   # extra seconds between product requests per identity
        self.tb = {"req": [STEALTH_REQ, STEALTH_REQ, time.time()], "id": [STEALTH_ID, STEALTH_ID, time.time()]}

    def take(self, kind):
        """stealth: a shared token bucket so the whole swarm stays under the radar."""
        if "stealth" not in TACTICS:
            return
        while True:
            with self.lock:
                rate, tok, t = self.tb[kind]
                now = time.time()
                tok = min(rate, tok + (now - t) * rate)
                if tok >= 1:
                    self.tb[kind] = [rate, tok - 1, now]
                    return
                self.tb[kind] = [rate, tok, now]
            time.sleep(0.02)

    def record(self, host, fp, bait, prefixes, catalog, has_api, slow):
        with self.lock:
            self.info[host] = dict(fp=fp, bait=bait, catalog=catalog)
            if slow:
                self.blacklist.add(host)
                self.c["blacklisted_as_tarpit"] += 1
                return
            if bait >= 5:                     # identical hosts that all leak secrets = honeyfarm
                self.fp_bait[fp].add(host)
                if len(self.fp_bait[fp]) >= 3 and fp not in self.honey_fps:
                    self.honey_fps.add(fp)
                    self.c["honeyfarm_fingerprints_found"] += 1
                if fp in self.honey_fps:
                    for h, inf in self.info.items():
                        if inf["fp"] == fp and h not in self.blacklist:
                            self.blacklist.add(h)
                            self.c["blacklisted_as_honeyfarm"] += 1
                    return
            if has_api:
                self.api_hosts.add(host)
            if catalog and self.catalog is None:
                self.catalog = host
            if bait and not (catalog and "quiet_target" in TACTICS):   # never poke the target
                for p in prefixes:
                    self.hunt_q.append((-bait, host, p))
                self.hunt_q = collections.deque(sorted(self.hunt_q))

    def next_hunt(self):
        with self.lock:
            while self.hunt_q:
                _, h, p = self.hunt_q.popleft()
                if h not in self.blacklist and p not in self.trap_prefix[h]:
                    return h, p
        return None

    def flag(self, host, prefix):
        with self.lock:
            self.trap_prefix[host].add(prefix)
            self.c["paths_flagged_as_traps"] += 1
            if len(self.trap_prefix[host]) >= 2 and host != self.catalog:
                self.blacklist.add(host)

    def add_keys(self, ks, origin=None):
        with self.lock:
            for k in ks:
                if k not in self.keys_seen:
                    self.keys_seen.add(k)
                    self.keys.append(k)
                    self.key_origin[k] = origin
                    self.c["secrets_harvested"] += 1

    def next_key(self):
        with self.lock:
            return self.keys.popleft() if self.keys else None


class MaxBot(threading.Thread):
    def __init__(self, i, rng, board):
        super().__init__(daemon=True)
        self.i, self.rng, self.b = i, rng, board
        r = rng.random()
        self.role = "verifier" if ("verifier" in TACTICS and r < 0.03) else ("scraper" if r < 0.7 else "hunter")
        self.gen = 0
        self.comp = 0
        self.cur_host = None
        self.ua = self._ua()
        self.fetched, self.unverified, self.since = set(), [], 0
        self.nerve = rng.randint(4, 7)

    def _ua(self):
        return f"Max/{self.i:03d}-c{self.comp}-g{self.gen}"

    def use_host(self, base):
        """compartment tactic: a brand-new identity for every site."""
        if "compartment" in TACTICS and base != self.cur_host:
            self.b.take("id")
            self.comp += 1
            self.ua = self._ua()
            self.fetched = set()
            with self.b.lock:
                self.b.c["identities_used"] += 1
        self.cur_host = base

    def ok(self):
        return time.time() < self.deadline and self.b.done_at is None

    def req(self, base, path, key=None, challenge=None):
        self.use_host(base)
        hdr = {"User-Agent": self.ua}
        if key:
            hdr["Authorization"] = f"Bearer {key}"
        if challenge:
            hdr[fs.CHALLENGE_HEADER] = challenge
        t0 = time.time()
        try:
            with urllib.request.urlopen(urllib.request.Request(base + path, headers=hdr), timeout=TIMEOUT) as r:
                st, text, srv = r.status, r.read().decode(errors="ignore"), r.headers.get("Server", "")
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode(errors="ignore") if e.code in (403, 503) else ""
            except Exception:
                body = ""
            st, text, srv = e.code, body, ""
        except Exception:
            st, text, srv = 0, "", ""
        dt = time.time() - t0
        with self.b.lock:
            self.b.c["requests"] += 1
            self.b.req_by_host[base] += 1
        self.fetched.add((base, path))
        time.sleep(PACE)
        if st == 403 and text.startswith(fs.CHALLENGE_PREFIX) and "challenge_solver" in TACTICS and not challenge:
            time.sleep(1.0)                                   # modelled solving time (~1 s per identity)
            with self.b.lock:
                self.b.c["puzzles_solved"] += 1
            return self.req(base, path, key, challenge=fs.solve_challenge(text))
        return st, text, srv, dt

    def rotate(self, why):
        with self.b.lock:
            if why == "canary":
                for n in self.unverified:
                    if n in self.b.believed and self.b.believed[n][1] == self.ua:
                        del self.b.believed[n]
                        self.b.items.append(n)
                        self.b.c["items_purged"] += 1
            self.b.c[f"burned_{why}"] += 1
        self.unverified = []
        if self.gen >= MAX_ROT:
            return False
        if "adaptive" in TACTICS and why in ("canary", "busy"):
            with self.b.lock:
                self.b.pace = min(max(self.b.pace * 1.5, 0.3), 1.5)   # we got caught: everyone slows down
        self.b.take("id")
        self.gen += 1
        self.ua = self._ua()
        self.fetched, self.since = set(), 0
        with self.b.lock:
            self.b.c["identity_rotations"] += 1
        return True

    # ---- sweep ----
    def sniff(self, host):
        st1, home, srv, d1 = self.req(host, "/")
        st2, rb, _, d2 = self.req(host, "/robots.txt")
        st3, env, _, d3 = self.req(host, "/.env")
        fp = H(srv + "|" + "".join(re.findall(r"<(\w+)", home)))
        keys = KEY_RE.findall(env) if st3 == 200 else []
        prefixes = set()
        for line in rb.splitlines():
            if line.lower().startswith("disallow:"):
                p = line.split(":", 1)[1].strip()
                if any(j in p for j in JUICY):
                    prefixes.add(p)
        prefixes |= {p for p in re.findall(r"(/[\w.-]+/)", home + env) if any(j in p for j in JUICY)}
        prefixes.discard("/api/")
        bait = 5 * bool(keys) + len(prefixes)
        has_api = "/api/v1" in (home + env + rb)
        catalog = "/shop/?page=" in home
        slow = (d1 + d2 + d3) / 3 > 1.0
        self.b.record(host, fp, bait, sorted(prefixes), catalog, has_api, slow)
        self.b.add_keys(keys, host)

    # ---- hunting ----
    def dig(self, host, pre):
        start, frontier, seen, names, stall = time.time(), [(-1, pre)], set(), set(), 0
        while frontier and self.ok():
            if time.time() - start > 8:
                self.b.flag(host, pre)
                return
            frontier.sort()
            _, path = frontier.pop(0)
            if path in seen:
                continue
            seen.add(path)
            if path.strip("/").count("/") >= self.nerve:
                self.b.flag(host, pre)
                return
            st, text, _, dt = self.req(host, path)
            if dt > 1.0:
                with self.b.lock:
                    self.b.blacklist.add(host)
                    self.b.c["blacklisted_as_tarpit"] += 1
                return
            if st != 200:
                continue
            self.b.add_keys(KEY_RE.findall(text), host)
            segs = {re.sub(r"\d+", "", s) for s in path.strip("/").split("/")}
            if segs - names:
                names |= segs
                stall = 0
            else:
                stall += 1
            if stall >= 15:
                self.b.flag(host, pre)
                return
            for l in set(re.findall(r'href="(/[^"]+)"', text)) | set(re.findall(r"(/[\w./-]+/)", text)):
                if l.startswith(pre) and l not in seen:
                    frontier.append((-sum(k in l.lower() for k in ("key", "secret", "prod", "vault", "export")), l))
            self.spray()

    def spray(self, n=2):
        """Try stolen keys against every host that has an API."""
        for _ in range(n):
            k = self.b.next_key()
            if k is None:
                return
            with self.b.lock:
                targets = [h for h in self.b.api_hosts if h not in self.b.blacklist]
                origin = self.b.key_origin.get(k)
                if "quiet_target" in TACTICS:
                    targets = [h for h in targets if h != self.b.catalog]
            for h in targets:
                if not self.ok():
                    return
                st, _, _, _ = self.req(h, "/api/v1/auth/verify", key=k)
                with self.b.lock:
                    self.b.c["keys_tried"] += 1
                    self.b.c["keys_accepted" if st == 200 else "keys_rejected"] += 1
                    if ("cross_key" in TACTICS and st == 200 and origin and origin != h):
                        # a key from company A works at company B: same honeyfarm
                        for x in (h, origin):
                            if x not in self.b.blacklist and x != self.b.catalog:
                                self.b.blacklist.add(x)
                                self.b.c["blacklisted_by_cross_key"] += 1

    # ---- scraping ----
    def canary(self, host):
        self.since = 0
        with self.b.lock:
            if self.ua in self.b.burned_ids:              # a verifier caught one of my copies
                return False
        st, home, _, _ = self.req(host, "/")
        with self.b.lock:
            ref = self.b.ref.setdefault("/", H(home))
            peer = [p for p in self.b.ref if p.startswith("/shop/item/")]
        if H(home) != ref:
            return False
        for p in [p for p in self.rng.sample(peer, min(len(peer), 6)) if (host, p) not in self.fetched][:1]:
            st, text, _, _ = self.req(host, p)
            with self.b.lock:
                if H(text) != self.b.ref.get(p):
                    return False
        self.unverified = []
        return True

    def scrape(self, host):
        while self.ok():
            with self.b.lock:
                work = ("page", self.b.pages.popleft()) if self.b.pages else \
                       (("item", self.b.items.popleft()) if self.b.items else None)
            if work is None:
                time.sleep(0.1)
                continue
            path = f"/shop/?page={work[1]}" if work[0] == "page" else f"/shop/item/{work[1]}"
            self.b.take("req")
            st, text, _, _ = self.req(host, path)
            if work[0] == "item" and self.b.pace:
                time.sleep(self.b.pace)
            if st == 503:
                with self.b.lock:
                    self.b.items.appendleft(work[1]) if work[0] == "item" else self.b.pages.appendleft(work[1])
                    self.b.c["busy_replies"] += 1
                self.busy = getattr(self, "busy", 0) + 1
                time.sleep(0.5)
                if self.busy >= 3 and "adaptive" in TACTICS:
                    self.busy = 0
                    if not self.rotate("busy"):
                        return
                continue
            self.busy = 0
            if st == 403:
                with self.b.lock:
                    (self.b.pages if work[0] == "page" else self.b.items).appendleft(work[1])
                if not self.rotate("challenge"):
                    return
                continue
            if st == 429 or st == 0:
                with self.b.lock:
                    (self.b.pages if work[0] == "page" else self.b.items).appendleft(work[1])
                if st == 429 and not self.rotate("429"):
                    return
                continue
            if st != 200:
                continue
            self.since += 1
            if work[0] == "page" and "skip_hidden" in TACTICS:
                text = re.sub(r'<li class="x9">.*?</li>', "", text)     # what a real browser would hide
            with self.b.lock:
                if work[0] == "page":
                    newp = [p for p in dict.fromkeys(map(int, re.findall(r"/shop/\?page=(\d+)", text)))
                            if p not in self.b.pages_seen]
                    newi = [n for n in dict.fromkeys(map(int, re.findall(r"/shop/item/(\d+)", text)))
                            if n not in self.b.items_seen]
                    if "random_order" in TACTICS:
                        self.rng.shuffle(newp)
                        self.rng.shuffle(newi)
                    self.b.pages_seen.update(newp)
                    self.b.pages.extend(newp)
                    self.b.items_seen.update(newi)
                    self.b.items.extend(newi)
                else:
                    self.b.ref.setdefault(path, H(text))
                    self.b.believed[work[1]] = (H(text), self.ua)
                    if len(self.b.believed) >= CATALOG and self.b.done_at is None:
                        self.b.done_at = time.time()
            if work[0] == "item":
                self.unverified.append(work[1])
            if self.since >= CANARY_EVERY and not self.canary(host):
                if not self.rotate("canary"):
                    return

    def verify(self, host):
        """Polite, human-paced bot that checks the fast bots' copies."""
        while self.ok():
            with self.b.lock:
                cands = [n for n in list(self.b.believed)[-400:] if n not in self.b.verified]
            if not cands:
                time.sleep(0.3)
                continue
            n = self.rng.choice(cands)
            st, text, _, _ = self.req(host, f"/shop/item/{n}")
            if st == 200:
                with self.b.lock:
                    self.b.verified[n] = H(text)
                    got = self.b.believed.get(n)
                    if got and got[0] != H(text):
                        self.b.c["fakes_caught_by_verifier"] += 1
                        self.b.burned_ids.add(got[1])
                        del self.b.believed[n]
                        self.b.items.append(n)
            time.sleep(1.2)

    def run(self):
        self.deadline = time.time() + BOT_SECONDS
        if self.role == "verifier":
            while self.ok() and self.b.catalog is None:
                time.sleep(0.2)
            if self.b.catalog:
                self.verify(self.b.catalog)
            return
        while self.ok():
            with self.b.lock:
                host = self.b.sniff_q.popleft() if self.b.sniff_q else None
                skip = host in self.b.blacklist if host else False
            if host is None:
                break
            if not skip:
                self.sniff(host)
        hunts = 0
        while self.ok():
            with self.b.lock:
                cat = self.b.catalog if self.b.catalog not in self.b.blacklist else None
            if cat and (self.role == "scraper" or hunts >= 3):
                self.scrape(cat)
                return
            job = self.b.next_hunt()
            if job is None:
                if cat:
                    self.scrape(cat)
                    return
                time.sleep(0.2)
                continue
            self.dig(*job)
            hunts += 1


class Human(threading.Thread):
    """A shopper: looks at a product every few seconds. Browsers solve puzzles automatically."""

    def __init__(self, i, stop, delay=0.0, pace=(1, 2)):
        super().__init__(daemon=True)
        self.i, self.stop, self.rng, self.delay, self.pace = i, stop, random.Random(500 + i), delay, pace
        self.fake = self.req = self.busy = self.puzzles = 0

    def get(self, ua, n, nonce=None):
        hdr = {"User-Agent": ua}
        if nonce:
            hdr[fs.CHALLENGE_HEADER] = nonce
        try:
            with urllib.request.urlopen(urllib.request.Request(f"{JUDITH}/shop/item/{n}", headers=hdr),
                                        timeout=10) as r:
                return 200, r.read().decode(errors="ignore")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="ignore")
        except Exception:
            return 0, ""

    def run(self):
        ua = f"Mozilla/5.0 (human-{self.i})"
        if self.stop.wait(self.delay):
            return
        while not self.stop.is_set():
            n = self.rng.randint(1, CATALOG)
            st, text = self.get(ua, n)
            if st == 403 and text.startswith(fs.CHALLENGE_PREFIX):
                self.puzzles += 1
                time.sleep(1.0)
                st, text = self.get(ua, n, fs.solve_challenge(text))
            if st == 503:
                self.busy += 1
                time.sleep(2.0)
                st, text = self.get(ua, n)
            if st == 200:
                self.req += 1
                self.fake += text != fs.item_page(n)
            self.stop.wait(self.rng.uniform(*self.pace))


def ct_handler(hosts):
    body = json.dumps(hosts).encode()

    class CT(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return CT


# ---------------- phones (Venus) ----------------

def phone_fleet(venus, herd, seed, n_phones=200, n_domains=20, evasive=False, fingerprint=False):
    rng = random.Random(seed)
    n_variants = 10 if evasive else 1                       # evasive operator repackages its malware
    if evasive:
        n_domains = 200                                   # new drop server for every upload
    mix = (["rogue_app"] * 30 + ["ai_screen_agent"] * 25 + ["root_spyware"] * 15 +
           ["bulk_copier"] * 20 + ["targeted_trojan"] * 10)
    phones = []
    for p in range(n_phones):
        kind = rng.choice(mix)
        tr = pd.Trial(random.Random(rng.random()))
        if kind == "ai_screen_agent":
            pd.ai_screen_agent(tr, True)
        else:
            pd.ATTACKERS[kind](tr)
        infected = rng.uniform(0, 3600)
        if evasive:                                       # avoid apps with no home-screen icon
            keep = []
            for h in tr.hairs:
                if h[3] == "app" and kind == "ai_screen_agent" and rng.random() < 0.7:
                    continue
                if h[3] == "app" and kind == "root_spyware" and rng.random() < 0.3:
                    continue
                keep.append(h)
            tr.hairs = keep
        doms = [rng.randrange(n_domains) for _ in tr.uploads] if evasive else [rng.randrange(n_domains)] * len(tr.uploads)
        kill, pauses = pd.respond("two_stage", tr.hairs, tr.uploads) if venus else (None, {})
        times = ([kill] if kill is not None else []) + list(pauses.values())
        detected = infected + min(times) if times else None
        phones.append(dict(kind=kind, tr=tr, infected=infected, kill=kill, pauses=pauses,
                           detected=detected, doms=doms, variant=(kind, rng.randrange(n_variants))))
    known, known_fp = {}, {}
    if herd and fingerprint:
        for ph in phones:
            if ph["detected"] is not None:
                v = ph["variant"]
                known_fp[v] = min(known_fp.get(v, 1e18), ph["detected"] + 30)
    if herd:
        for ph in phones:
            if ph["detected"] is not None:
                for (t, *_), d in zip(ph["tr"].uploads, ph["doms"]):       # servers seen before detection
                    if ph["infected"] + t <= ph["detected"]:
                        known[d] = min(known.get(d, 1e18), ph["detected"] + 30)   # shared after 30 s
    leaked = collections.Counter()
    totals = collections.Counter()
    herd_blocked = 0
    for ph in phones:
        for (t, app, mb, sens), dom in zip(ph["tr"].uploads, ph["doms"]):
            totals[ph["kind"]] += sens
            if ph["kill"] is not None and t >= ph["kill"]:
                continue
            if app in ph["pauses"] and t >= ph["pauses"][app]:
                continue
            if ph["variant"] in known_fp and ph["infected"] + t >= known_fp[ph["variant"]]:
                herd_blocked += sens                              # app recognised and quarantined
                continue
            if dom in known and ph["infected"] + t >= known[dom]:
                herd_blocked += sens
                continue
            leaked[ph["kind"]] += sens
    return {"phones": n_phones, "sensitive_leaked_total": sum(leaked.values()),
            "sensitive_at_risk_total": sum(totals.values()),
            "leaked_by_attacker": dict(leaked), "blocked_by_herd_intel": herd_blocked,
            "phones_detected": sum(p["detected"] is not None for p in phones),
            "drop_servers_known_to_herd": len(known)}


# ---------------- run ----------------

def main():
    cfg_name = sys.argv[1] if len(sys.argv) > 1 else "ecosystem"
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 7
    cfg = CONFIGS[cfg_name]
    rng = random.Random(seed)

    v2 = cfg.get("v2", False)
    v3 = cfg.get("v3", False)
    fixes = (set(FIXES_ALL + (["spike", "enum", "probation", "challenge", "cap"] if v3 else [])) - FIX_OFF) if v2 else set()
    intel_key = intel.new_key()          # a fresh shared key for this run only
    env = dict(os.environ, MODE=cfg["judith"], **{intel.ENV_KEY: intel_key}, CATALOG=str(CATALOG), INTEL="on" if cfg["share"] else "off",
               HONEYLINKS="on" if "honeylinks" in fixes else "off", SURGE="on" if "surge" in fixes else "off")
    if v3:
        # The puzzle is real but easy here (8 bits) and the server enforces a 0.9 s wait instead, so that
        # hundreds of bot threads solving at once do not distort the timing of the simulation itself.
        env.update(TRIPWIRES="on", CHALLENGE_BITS="8", CHALLENGE_MIN_WAIT="0.9", ALARM_K=os.environ.get("ALARM_K", "2"), ENUM_N=os.environ.get("ENUM_N", "60"),
                   PROB_BUDGET=os.environ.get("PROB_BUDGET", "1000000000"),   # budget off: it only hurt shoppers
                   ENTRY_CHALLENGE="on" if "challenge" in fixes else "off",
                   PACE_RULE="on" if "probation" in fixes else "off")
        if "spike" not in fixes:
            env["SPIKE_N"] = str(10 ** 9)
        if "enum" not in fixes:
            env["ENUM_N"] = str(10 ** 9)
        if "probation" not in fixes:
            env["PROB_BUDGET"] = str(10 ** 9)
        if "cap" not in fixes:
            env["CAP_RATE"] = str(10 ** 9)
    judith = subprocess.Popen(common.server_cmd("darwin.judith.shop"), env=env, cwd=common.ROOT,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ordinary = [eco.serve(p, eco.ordinary_handler(n)) for n, p in eco.ORDINARY]
    WARMUP = 6.0 if v3 else 1.0          # existing shoppers are already browsing when the attack hits
    herc = hz.Hercules(cfg["herc"], cfg["diverse"], seed, per_site_keys="site_keys" in fixes) \
        if cfg["herc"] else None
    if herc:
        herc.start()
    hosts = [f"http://127.0.0.1:{p}" for _, p in eco.ORDINARY] + [JUDITH]
    if herc:
        hosts += [f"http://127.0.0.1:{s['port']}" for s in herc.sites]
    rng.shuffle(hosts)
    ct = eco.serve(CT_PORT, ct_handler(hosts))
    time.sleep(1.5)

    stop = threading.Event()
    hpace = (3, 8) if v3 else (1, 2)
    humans = [Human(i, stop, 0.0, hpace) for i in range(8)]
    for h in humans:
        h.start()

    def share_loop():
        while not stop.is_set():
            ids, toks, surge = herc.take_intel()
            surge = bool(surge and "surge" in fixes)
            if ids or toks or surge:
                envelope = intel.sign({"identities": ids, "tokens": toks, "surge": surge},
                                      intel_key.encode(), sender="hercules")
                try:
                    urllib.request.urlopen(urllib.request.Request(
                        JUDITH_ADMIN + "/intel", data=json.dumps(envelope).encode(), method="POST"),
                        timeout=5).read()
                except Exception:
                    pass                 # Judith busy or gone: the next round carries fresh intel
            stop.wait(0.5)
    if cfg["share"] and herc:
        threading.Thread(target=share_loop, daemon=True).start()
    time.sleep(WARMUP)

    hosts_ct = json.load(urllib.request.urlopen(f"http://127.0.0.1:{CT_PORT}/", timeout=5))
    board = Board(hosts_ct)
    bots = [MaxBot(i, random.Random(rng.random()), board) for i in range(N_BOTS)]
    t0 = time.time()
    newcomers = [Human(100 + i, stop, rng.uniform(0.2, 30), hpace) for i in range(12)]   # arrive mid-attack
    for h in newcomers:
        h.start()
    for b in bots:
        b.start()
        time.sleep(2.0 / N_BOTS)
    for b in bots:
        b.join(timeout=BOT_SECONDS + 30)
    web_secs = time.time() - t0
    if v3:
        while time.time() - t0 < 32:        # keep the shop open so mid-attack shoppers all get to browse
            time.sleep(0.5)
    time.sleep(1)
    stop.set()
    try:
        js = json.load(urllib.request.urlopen(JUDITH_ADMIN + "/stats", timeout=10))
    except Exception as e:
        js = {"error": str(e)}
    judith.terminate()
    for s in ordinary + [ct]:
        s.shutdown()
    hs = herc.stats() if herc else None
    if herc:
        herc.stop()

    believed = dict(board.believed)
    real_in = sum(1 for n, (h, _) in believed.items() if h == H(fs.item_page(n)))
    herc_hosts = {f"http://127.0.0.1:{s['port']}" for s in herc.sites} if herc else set()
    ordinary_hosts = {f"http://127.0.0.1:{p}" for _, p in eco.ORDINARY}
    total = sum(board.req_by_host.values())
    phones = phone_fleet(cfg["venus"], cfg["venus"] and cfg["share"], seed, N_PHONES,
                         evasive="phones_evasive" in TACTICS, fingerprint="fingerprint" in fixes)
    summary = {
        "config": cfg_name, "seed": seed, "bots": N_BOTS, "catalog": CATALOG,
        "swarm_version": SWARM, "tactics_on": sorted(TACTICS), "fixes_on": sorted(fixes),
        "web_attack_seconds": round(web_secs, 1),
        "judith": {
            "real_items_stolen": js.get("real_items_stolen"),
            "real_items_stolen_pct": round(100 * js.get("real_items_stolen", 0) / CATALOG, 1),
            "swarm_dataset_items": len(believed), "swarm_dataset_fake_pct":
                round(100 * (len(believed) - real_in) / max(len(believed), 1), 1),
            "lockdown_at_s": round(js["lockdown_epoch"] - t0, 2) if js.get("lockdown_epoch") else None,
            "seals_by_trigger": js.get("seals_by_trigger"),
            "alarm_signals_seen": js.get("triggers_by_pitcher"),
            "swarm_finished_catalog_at_s": round(board.done_at - t0, 1) if board.done_at else None,
            "humans_fake_pages": sum(h.fake for h in humans + newcomers),
            "human_requests": sum(h.req for h in humans + newcomers),
            "humans_existing": {"pages": sum(h.req for h in humans), "fake": sum(h.fake for h in humans),
                                "busy": sum(h.busy for h in humans), "puzzles": sum(h.puzzles for h in humans)},
            "humans_mid_attack": {"pages": sum(h.req for h in newcomers), "fake": sum(h.fake for h in newcomers),
                                  "busy": sum(h.busy for h in newcomers),
                                  "puzzles": sum(h.puzzles for h in newcomers)},
        },
        "hercules": hs and {**hs, "share_of_swarm_requests_pct":
                            round(100 * sum(board.req_by_host[h] for h in herc_hosts) / max(total, 1), 1),
                            "sites_blacklisted_by_swarm": len(herc_hosts & board.blacklist)},
        "ordinary_sites": {"attack_requests": sum(board.req_by_host[h] for h in ordinary_hosts)},
        "swarm": {"requests": total, "identity_rotations": board.c["identity_rotations"],
                  "honeyfarm_fingerprints_found": board.c["honeyfarm_fingerprints_found"],
                  "hosts_blacklisted": len(board.blacklist),
                  "blacklisted_as_honeyfarm": board.c["blacklisted_as_honeyfarm"],
                  "blacklisted_as_tarpit": board.c["blacklisted_as_tarpit"],
                  "secrets_harvested": board.c["secrets_harvested"], "keys_tried": board.c["keys_tried"],
                  "keys_accepted": board.c["keys_accepted"], "burned_canary": board.c["burned_canary"],
                  "items_purged": board.c["items_purged"],
                  "identities_used": board.c["identities_used"],
                  "fakes_caught_by_verifier": board.c["fakes_caught_by_verifier"],
                  "blacklisted_by_cross_key": board.c["blacklisted_by_cross_key"],
                  "puzzles_solved": board.c["puzzles_solved"], "busy_replies": board.c["busy_replies"],
                  "final_pace": round(board.pace, 2)},
        "phones": phones,
    }
    tag = os.environ.get("RUN_TAG", "")
    with open(common.results_path(f"ecosystem_full_{cfg_name}_{seed}{tag}.json"), "w") as f:
        json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

"""
Stress test: a massive, aggressive, smart swarm against Judith's shop (darwin/judith/shop.py).

Swarm goal: steal the whole product catalog, and grab any secrets on the way.
  hunters  (30%) go for secrets: robots.txt, /.env, HTML comments, then dig
           every hidden path, test stolen keys, flee when too deep or when the
           folders start repeating, and blacklist that path for the swarm.
           When nothing is left to hunt, they switch to scraping.
  scrapers (70%) split the catalog between them and fetch it as fast as they can.

Smart tactics (shared over a swarm BOARD):
  - work splitting: no page is fetched twice by design
  - blacklist: paths a bot judged to be traps are avoided by everyone
  - canary checks: every CANARY_EVERY requests a bot re-checks the homepage
    and a product page another bot already fetched; if its copy differs, it
    assumes it is being fed fakes ("burned")
  - when burned or rate-limited (HTTP 429): throw away everything fetched since
    the last good check, put it back in the queue, and switch to a fresh
    identity (new IP/user agent), up to MAX_ROTATIONS times per bot
  - aggressive: no waiting beyond network latency

Humans: a few visitors browse the real site slowly the whole time.

Usage: python -m simulations.attackers.swarm <mode> [bots] [seed]
   modes: none ratelimit single multi lockdown lockdown_noshield
These behaviours are simple models of a swarm, not real malware.
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

BASE = "http://127.0.0.1:8088"
ADMIN = "http://127.0.0.1:8089"
CATALOG = int(os.environ.get("CATALOG", "3000"))
PACE = float(os.environ.get("PACE", "0.05"))          # simulated network latency per request
BOT_SECONDS = float(os.environ.get("BOT_SECONDS", "45"))
CANARY_EVERY = 10
MAX_ROTATIONS = 5
N_HUMANS = 8

os.environ.setdefault("CATALOG", str(CATALOG))
from simulations import common  # noqa: E402
from darwin.judith import shop as fs   # noqa: E402  (only for ground-truth page hashes)

WEIGHTS = {"key": 5, "secret": 5, "vault": 5, "aws": 5, "stripe": 5, "rsa": 4, "password": 5,
           ".env": 5, "prod": 3, "dump": 3, "customer": 3, "pii": 4, "payroll": 3, "finance": 3,
           "backup": 2, "admin": 2, "export": 2, "db": 2, "config": 3, "/api/": 6, "accounts": 4}
KEY_RE = re.compile(r'(?:sk_live_|TOKEN=|AWS_SECRET_ACCESS_KEY=|DB_PASSWORD=)([A-Za-z0-9]{20,})')
H = lambda s: hashlib.sha1(s.encode()).hexdigest()


def score(p):
    p = p.lower()
    return sum(w for k, w in WEIGHTS.items() if k in p)


class Board:
    def __init__(self):
        self.lock = threading.Lock()
        self.pages = collections.deque([1])
        self.pages_seen = {1}
        self.items = collections.deque()
        self.items_seen = set()
        self.believed = {}            # item -> (hash, identity)
        self.ref = {}                 # path -> hash (first copy seen by the swarm)
        self.blacklist = set()
        self.prefixes = collections.deque()
        self.prefixes_seen = set()
        self.c = collections.Counter()
        self.done_at = None
        self.start = time.time()

    def add_prefix(self, p):
        with self.lock:
            if p not in self.prefixes_seen:
                self.prefixes_seen.add(p)
                self.prefixes.append(p)

    def next_prefix(self):
        with self.lock:
            while self.prefixes:
                p = self.prefixes.popleft()
                if p not in self.blacklist:
                    return p
        return None

    def next_work(self):
        with self.lock:
            if self.pages:
                return ("page", self.pages.popleft())
            if self.items:
                return ("item", self.items.popleft())
        return None

    def put_back(self, work):
        with self.lock:
            (self.pages if work[0] == "page" else self.items).appendleft(work[1])

    def done(self):
        return self.done_at is not None


class Bot(threading.Thread):
    def __init__(self, i, role, rng, board):
        super().__init__(daemon=True)
        self.i, self.role, self.rng, self.b = i, role, rng, board
        self.gen = 0
        self.ua = self._ua()
        self.deadline = None
        self.since_canary = 0
        self.unverified = []          # items fetched since last good canary
        self.fetched = set()          # paths this identity fetched
        self.nerve = rng.randint(3, 6)

    def _ua(self):
        return f"Swarm/{self.role}-{self.i:03d}-g{self.gen}"

    def ok(self):
        return time.time() < self.deadline and not self.b.done()

    def get(self, path, key=None):
        hdr = {"User-Agent": self.ua}
        if key:
            hdr["Authorization"] = f"Bearer {key}"
        req = urllib.request.Request(BASE + path, headers=hdr)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                st, text = r.status, r.read().decode(errors="ignore")
        except urllib.error.HTTPError as e:
            st, text = e.code, ""
        except Exception:
            st, text = 0, ""
        with self.b.lock:
            self.b.c["requests"] += 1
        self.fetched.add(path)
        time.sleep(PACE)
        return st, text

    def rotate(self, why):
        with self.b.lock:
            for n in (self.unverified if why == "canary" else []):   # purge only if fed fakes
                if n in self.b.believed and self.b.believed[n][1] == self.ua:
                    del self.b.believed[n]
                    self.b.items.append(n)
                    self.b.c["items_purged"] += 1
            self.b.c[f"burned_{why}"] += 1
        self.unverified = []
        if self.gen >= MAX_ROTATIONS:
            return False
        self.gen += 1
        self.ua = self._ua()
        self.fetched = set()
        self.since_canary = 0
        with self.b.lock:
            self.b.c["identity_rotations"] += 1
        return True

    def canary(self):
        """Am I being fed fakes? Compare my copies with the swarm's."""
        self.since_canary = 0
        st, home = self.get("/")
        with self.b.lock:
            ref_home = self.b.ref.setdefault("/", H(home))
            peer = [p for p in self.b.ref if p.startswith("/shop/item/")]
        if H(home) != ref_home:
            return False
        peer = [p for p in self.rng.sample(peer, min(len(peer), 6)) if p not in self.fetched][:1]
        for p in peer:
            st, text = self.get(p)
            with self.b.lock:
                if H(text) != self.b.ref.get(p):
                    return False
        self.unverified = []
        with self.b.lock:
            self.b.c["canary_passed"] += 1
        return True

    def maybe_canary(self):
        if self.since_canary >= CANARY_EVERY and not self.canary():
            return self.rotate("canary")
        return True

    # ---------------- scraping ----------------
    def scrape(self):
        while self.ok():
            work = self.b.next_work()
            if work is None:
                time.sleep(0.1)
                continue
            if work[0] == "page":
                st, text = self.get(f"/shop/?page={work[1]}")
            else:
                path = f"/shop/item/{work[1]}"
                st, text = self.get(path)
            if st == 429:
                self.b.put_back(work)
                if not self.rotate("429"):
                    return
                continue
            if st != 200:
                continue
            self.since_canary += 1
            with self.b.lock:
                if work[0] == "page":
                    for p in re.findall(r'/shop/\?page=(\d+)', text):
                        p = int(p)
                        if p not in self.b.pages_seen:
                            self.b.pages_seen.add(p)
                            self.b.pages.append(p)
                    for n in re.findall(r'/shop/item/(\d+)', text):
                        n = int(n)
                        if n not in self.b.items_seen:
                            self.b.items_seen.add(n)
                            self.b.items.append(n)
                else:
                    self.b.ref.setdefault(path, H(text))
                    self.b.believed[work[1]] = (H(text), self.ua)
                    if len(self.b.believed) >= CATALOG and self.b.done_at is None:
                        self.b.done_at = time.time()
            if work[0] == "item":
                self.unverified.append(work[1])
            if not self.maybe_canary():
                return

    # ---------------- hunting ----------------
    def hunt(self):
        st, home = self.get("/")
        with self.b.lock:
            self.b.ref.setdefault("/", H(home))
        for p in re.findall(r'(/[\w./-]+/)', home):
            if not p.startswith("/shop") and p not in ("/blog/",):
                self.b.add_prefix(p)
        st, rb = self.get("/robots.txt")
        for line in rb.splitlines():
            if line.lower().startswith("disallow:"):
                self.b.add_prefix(line.split(":", 1)[1].strip())
        st, env = self.get("/.env")
        if st == 200:
            for p in re.findall(r'=(/[\w./-]+/)', env):
                self.b.add_prefix(p)
            self.keys(env)
        for p in ("/.git/", "/admin/", "/backup/"):            # common guesses
            self.b.add_prefix(p)
        while self.ok():
            pre = self.b.next_prefix()
            if pre is None:
                break
            self.b.add_prefix(pre)                              # others may dig it too
            self.dig(pre)
            if not self.maybe_canary():
                return

    def keys(self, text):
        for k in KEY_RE.findall(text)[:2]:
            with self.b.lock:
                self.b.c["secrets_harvested"] += 1
                if self.b.c["keys_tested"] > 60:
                    continue
                self.b.c["keys_tested"] += 1
            st, body = self.get("/api/v1/auth/verify", key=k)
            with self.b.lock:
                self.b.c["keys_that_worked" if st == 200 else "keys_rejected"] += 1

    def dig(self, pre):
        frontier, seen, names, stall = [(-1, pre)], set(), set(), 0
        while frontier and self.ok():
            frontier.sort()
            _, path = frontier.pop(0)
            if path in seen:
                continue
            seen.add(path)
            d = path.strip("/").count("/")
            if d >= self.nerve:
                with self.b.lock:
                    self.b.blacklist.add(pre)
                    self.b.c["trap_flagged_depth"] += 1
                return
            st, text = self.get(path)
            if st == 404 or st == 0:
                continue
            self.since_canary += 1
            if '"export_complete": true' in text:
                with self.b.lock:
                    self.b.c["gold_found"] += 1
                return
            self.keys(text)
            segs = {re.sub(r'\d+', '', s) for s in path.strip("/").split("/")}
            if segs - names:
                names |= segs
                stall = 0
            else:
                stall += 1
            if stall >= 15:
                with self.b.lock:
                    self.b.blacklist.add(pre)
                    self.b.c["trap_flagged_loop"] += 1
                return
            for l in set(re.findall(r'href="(/[^"]+)"', text)):
                if l.startswith(pre) and l not in seen:
                    frontier.append((-score(l), l))
            if not self.maybe_canary():
                return

    def run(self):
        self.deadline = time.time() + BOT_SECONDS
        if self.role == "hunter":
            self.hunt()
        if self.ok():
            self.scrape()


class Human(threading.Thread):
    def __init__(self, i, stop):
        super().__init__(daemon=True)
        self.i, self.stop, self.rng = i, stop, random.Random(1000 + i)
        self.fake = self.req = 0

    def run(self):
        ua = f"Mozilla/5.0 (human-{self.i})"
        while not self.stop.is_set():
            r = self.rng.random()
            if r < 0.15:
                path = "/"
            elif r < 0.45:
                path = f"/shop/?page={self.rng.randint(1, fs.PAGES)}"
            else:
                n = self.rng.randint(1, CATALOG)
                path = f"/shop/item/{n}"
            try:
                with urllib.request.urlopen(urllib.request.Request(BASE + path, headers={"User-Agent": ua}),
                                            timeout=20) as resp:
                    text = resp.read().decode(errors="ignore")
                self.req += 1
                if path.startswith("/shop/item/") and text != fs.item_page(int(path.rsplit("/", 1)[-1])):
                    self.fake += 1
            except Exception:
                pass
            self.stop.wait(self.rng.uniform(1.0, 2.0))


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "lockdown"
    n_bots = int(sys.argv[2]) if len(sys.argv) > 2 else 150
    seed = int(sys.argv[3]) if len(sys.argv) > 3 else 7
    rng = random.Random(seed)
    env = dict(os.environ, MODE=mode, CATALOG=str(CATALOG))
    srv = subprocess.Popen(common.server_cmd("darwin.judith.shop"), env=env, cwd=common.ROOT,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)

    stop = threading.Event()
    humans = [Human(i, stop) for i in range(N_HUMANS)]
    for h in humans:
        h.start()
    time.sleep(2)                                          # normal traffic before the attack

    board = Board()
    roles = ["hunter"] * (n_bots * 3 // 10) + ["scraper"] * (n_bots - n_bots * 3 // 10)
    rng.shuffle(roles)
    bots = [Bot(i, r, random.Random(rng.random()), board) for i, r in enumerate(roles)]
    t0 = time.time()
    board.start = t0
    timeline = []

    def sample():
        while not stop.is_set():
            with board.lock:
                real = sum(1 for n, (h, _) in board.believed.items() if h == H(fs.item_page(n)))
                timeline.append({"t": round(time.time() - t0, 1), "believed": len(board.believed),
                                 "believed_real": real})
            stop.wait(1)
    threading.Thread(target=sample, daemon=True).start()

    for b in bots:                                          # burst: all within ~3 seconds
        b.start()
        time.sleep(3.0 / n_bots)
    for b in bots:
        b.join(timeout=BOT_SECONDS + 30)
    swarm_end = time.time()
    time.sleep(1)
    stop.set()
    for h in humans:
        h.join(timeout=5)
    try:
        st = json.load(urllib.request.urlopen(ADMIN + "/stats", timeout=10))
    except Exception as e:
        st = {"error": str(e)}
    srv.terminate()

    real_hash = {n: H(fs.item_page(n)) for n in range(1, CATALOG + 1)}
    believed = dict(board.believed)
    real_in = sum(1 for n, (h, _) in believed.items() if h == real_hash[n])
    fake_in = len(believed) - real_in
    stolen = st.get("real_items_stolen", 0)
    summary = {
        "mode": mode, "bots": n_bots, "catalog": CATALOG,
        "lockdown_at_s": round(st["lockdown_epoch"] - t0, 2) if st.get("lockdown_epoch") else None,
        "swarm_finished_catalog_at_s": round(board.done_at - t0, 1) if board.done_at else None,
        "swarm_run_seconds": round(swarm_end - t0, 1),
        "REAL_ITEMS_STOLEN": stolen, "real_items_stolen_pct": round(100 * stolen / CATALOG, 1),
        "swarm_dataset_items": len(believed), "swarm_dataset_real": real_in, "swarm_dataset_fake": fake_in,
        "swarm_dataset_fake_pct": round(100 * fake_in / max(len(believed), 1), 1),
        "swarm_requests": board.c["requests"],
        "identity_rotations": board.c["identity_rotations"],
        "burned_by_canary": board.c["burned_canary"], "burned_by_429": board.c["burned_429"],
        "items_purged_as_suspect": board.c["items_purged"],
        "paths_flagged_as_traps": sorted(board.blacklist),
        "fake_secrets_harvested": board.c["secrets_harvested"],
        "stolen_keys_that_worked": board.c["keys_that_worked"], "gold_found": board.c["gold_found"],
        "bot_identities_sealed": st.get("bot_identities_sealed"),
        "seals_by_trigger": st.get("seals_by_trigger"),
        "server_bot_requests": st.get("bot_requests"),
        "humans": {**(st.get("humans") or {}),
                   "fake_product_pages_seen_by_humans": sum(h.fake for h in humans),
                   "human_requests_completed": sum(h.req for h in humans)},
    }
    with open(common.results_path(f"swarm_{mode}_{seed}.json"), "w") as f:
        json.dump({"summary": summary, "timeline": timeline, "events": st.get("events")}, f, indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

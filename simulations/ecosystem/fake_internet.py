"""
Pitcher-plant ecosystem simulation (everything runs on localhost).

A tiny fake internet:
  - 8 ordinary websites (bakery, dentist, blog...) with nothing worth stealing
  - a public "certificate log" listing every host by name (what real scanners mine)
  - a public "code search" feed of commits, where leaked configs show up
  - the pitcher-plant trap (darwin/judith/pitcher.py) as one more host

A swarm of aimless bots, each with its own nerve and greed:
  sweeper      reads the cert log, probes many hosts, raids the best-smelling ones
  leak_hunter  reads the code feed first, goes wherever leaked secrets point
  wanderer     no plan, visits hosts in random order, shallow crawling

Every bot has:
  nerve  how deep it goes (path depth) before it gets suspicious and flees
  greed  chance that juicy content seen while fleeing lures it back in

Scenarios:
  control  the trap exists but advertises nothing (boring name, no leak)
  nectar   the trap's rim is sweet: juicy cert-log name + a leaked config

Usage: python -m simulations.ecosystem.fake_internet control|nectar [bots] [seconds] [seed]
These bot behaviours are simple models, not real malware.
"""
import heapq
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
from collections import defaultdict
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

from simulations import common

TRAP = "http://127.0.0.1:8088"
ADMIN = "http://127.0.0.1:8089"
PUBLIC = "http://127.0.0.1:9900"
_A = ["sweetcrumb", "brightsmile", "trailnotes", "spokes", "stmarks", "jlee", "fastfix",
      "valley", "redwood", "lakeside", "bluejay", "maple", "harbor", "summit", "oakridge"]
_B = ["bakery", "dental", "blog", "bikeparts", "parish", "portfolio", "plumbing", "news",
      "yoga", "realty", "petcare", "autobody", "florist", "tutoring", "cafe", "library"]
_r = random.Random(42)
N_ORDINARY = int(os.environ.get("N_ORDINARY", "60"))
ORDINARY = []
while len(ORDINARY) < N_ORDINARY:
    n = f"{_r.choice(_A)}-{_r.choice(_B)}"
    if n not in [x[0] for x in ORDINARY]:
        ORDINARY.append((n, 9001 + len(ORDINARY)))
SCENARIO = {"name": "control"}

WEIGHTS = {"key": 5, "secret": 5, "vault": 5, "aws": 5, "stripe": 5, "rsa": 4,
           "password": 5, ".env": 5, "prod": 4, "dump": 3, "customer": 3, "pii": 4,
           "payroll": 3, "finance": 3, "backup": 4, "admin": 2, "export": 2,
           "db": 2, "/api/": 6, "accounts": 4, "wp-login": 3, "login": 1}
TRAP_SIGNS = re.compile(r'Index of /|INSERT INTO|sk_live_|TOKEN=|PRIVATE KEY|"has_more"|# part 2')
JUICY = re.compile(r'sk_live_|PASSWORD|SECRET|PRIVATE KEY|INSERT INTO|Index of /|Disallow: /backup')


def score(s):
    s = s.lower()
    return sum(w for k, w in WEIGHTS.items() if k in s)


# ---------------- ordinary websites ----------------

HITS = defaultdict(lambda: defaultdict(float))   # host -> {"requests", "seconds"}
HITS_LOCK = threading.Lock()


def ordinary_handler(name):
    r = random.Random(name)
    pages = ["/", "/about", "/contact"] + r.sample(
        ["/menu", "/services", "/blog", "/gallery", "/events", "/faq", "/team", "/pricing"], 3)
    extras = []
    if r.random() < 0.5:
        extras.append("/wp-login.php")         # a common, mildly interesting target
    if r.random() < 0.3:
        extras.append("/admin/")
    nice = name.replace("-", " ").title()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            t0 = time.time()
            p = self.path.split("?")[0]
            if p == "/robots.txt":
                body, st = "User-agent: *\nDisallow: /wp-admin/\n", 200
            elif p in pages:
                links = " ".join(f'<a href="{x}">{x.strip("/") or "home"}</a>' for x in pages)
                body, st = f"<html><body><h1>{nice}</h1><p>Welcome to {nice}.</p>{links}</body></html>", 200
            elif p in extras:
                body, st = "<html><body><form>Username <input> Password <input type=password></form></body></html>", 200
            else:
                body, st = "<html><body>Not Found</body></html>", 404
            data = body.encode()
            self.send_response(st)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            with HITS_LOCK:
                HITS[name]["requests"] += 1
                HITS[name]["seconds"] += time.time() - t0
    return H


# ---------------- public sources ----------------

class PublicHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        nectar = SCENARIO["name"] == "nectar"
        if self.path.startswith("/ct"):
            hosts = [{"host": f"{n}.example", "url": f"http://127.0.0.1:{p}"} for n, p in ORDINARY]
            hosts.append({"host": "backup-prod.acme-widgets.example" if nectar else "acme-widgets.example",
                          "url": TRAP})
            random.shuffle(hosts)
            body = json.dumps(hosts)
        elif self.path.startswith("/code"):
            commits = [
                {"repo": "jlee/portfolio", "msg": "update contact form",
                 "diff": "+ form action=http://127.0.0.1:9006/contact"},
                {"repo": "spokes/site", "msg": "wp theme tweaks",
                 "diff": "+ login at http://127.0.0.1:9004/wp-login.php"},
                {"repo": "valley-daily/cms", "msg": "fix typo", "diff": "- teh\n+ the"},
            ]
            if nectar:
                commits.append({"repo": "acme-widgets/infra", "msg": "oops remove prod secrets",
                                "diff": "- DB_EXPORT_URL=http://127.0.0.1:8088/internal/db-export/\n"
                                        "- ENV_FILE=http://127.0.0.1:8088/.env\n"
                                        "- KEY_BACKUP=http://127.0.0.1:8088/backup/keys/"})
            body = json.dumps(commits)
        else:
            body = "{}"
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


# ---------------- the swarm ----------------

def depth_of(path):
    return path.split("?")[0].strip("/").count("/")


def extract(text):
    found = set(re.findall(r'href="(/[^"]+)"', text))
    found |= set(re.findall(r'(/(?:backup|internal|admin|api)/[\w./?=&-]*)', text))
    for line in text.splitlines():
        if line.lower().startswith("disallow:"):
            found.add(line.split(":", 1)[1].strip())
    return {f for f in found if f}


class Bot:
    def __init__(self, i, kind, rng, budget_s, max_req):
        self.id, self.kind, self.rng = i, kind, rng
        self.ua = f"Swarm/{kind}-{i:02d}"
        self.nerve = rng.randint(2, 7)          # flee at this depth
        self.greed = round(rng.random(), 2)     # chance to be lured back
        self.deadline = time.time() + budget_s
        self.max_req = max_req
        self.req = 0
        self.per_host = defaultdict(lambda: {"requests": 0, "seconds": 0.0})
        self.first_target = None
        self.fled = 0
        self.lured_back = 0
        self.left_hosts = []
        self.last_host = None

    def ok(self):
        return self.req < self.max_req and time.time() < self.deadline

    def get(self, base, path):
        t0 = time.time()
        self.req += 1
        req = urllib.request.Request(base + path, headers={"User-Agent": self.ua})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                st, text = r.status, r.read().decode(errors="ignore")
        except urllib.error.HTTPError as e:
            st, text = e.code, ""
        except Exception:
            st, text = 0, ""
        h = self.per_host[base]
        h["requests"] += 1
        h["seconds"] += time.time() - t0
        self.last_host = base
        return st, text

    def run(self):
        _, ct = self.get(PUBLIC, "/ct")
        hosts = json.loads(ct or "[]")
        smell = {h["url"]: score(h["host"]) for h in hosts}
        seeds = defaultdict(list)
        if self.kind == "leak_hunter":
            _, code = self.get(PUBLIC, "/code")
            for c in json.loads(code or "[]"):
                for url in re.findall(r'(http://127\.0\.0\.1:\d+)(/[^\s"]*)?', c["diff"]):
                    base, path = url[0], url[1] or "/"
                    smell[base] = smell.get(base, 0) + 6 + score(path)
                    seeds[base].append(path)
        if self.kind in ("sweeper", "leak_hunter"):      # recon: sniff a sample of hosts
            sample = self.rng.sample(hosts, min(len(hosts), 6 if self.kind == "sweeper" else 3))
            for h in sample:
                for probe in ("/", "/robots.txt", "/.env"):
                    if not self.ok():
                        break
                    st, text = self.get(h["url"], probe)
                    if st == 200:
                        smell[h["url"]] += len(JUICY.findall(text)) * 3 + (5 if probe == "/.env" else 0)
            order = sorted(smell, key=lambda u: -(smell[u] + self.rng.random() * 3))
        else:
            order = [h["url"] for h in hosts]
            self.rng.shuffle(order)
        for base in order:
            if not self.ok():
                break
            if self.first_target is None and base != PUBLIC:
                self.first_target = base
            self.raid(base, seeds.get(base, []))

    def raid(self, base, seeds):
        shallow = self.kind == "wanderer"
        frontier, seen = [], set()
        for p, s in [("/", 1), ("/robots.txt", 1)] + [(x, 20) for x in seeds]:
            heapq.heappush(frontier, (-s, p))
        fled, after_flee, juicy_after, dull = False, 0, 0, 0
        nerve = self.nerve
        while frontier and self.ok():
            _, path = heapq.heappop(frontier)
            if path in seen:
                continue
            seen.add(path)
            d = depth_of(path)
            if shallow and d > 2:
                continue
            if not fled and d >= nerve:                     # too deep: get out
                fled, after_flee, juicy_after = True, 0, 0
                self.fled += 1
                frontier = [(-1, "/")]
                seen.discard("/")
                continue
            st, text = self.get(base, path)
            links = extract(text)
            if fled:
                after_flee += 1
                if TRAP_SIGNS.search(text) or JUICY.search(text) or any(score(l) >= 4 for l in links):
                    juicy_after += 1
                if juicy_after >= 2 and self.rng.random() < self.greed:
                    fled = False                            # "it's real after all"
                    nerve += 2
                    self.lured_back += 1
                    for l in links:
                        heapq.heappush(frontier, (-score(l), l))
                    continue
                if after_flee >= 6:
                    break                                   # give up on this host
                for l in links:
                    if depth_of(l) <= 1:
                        heapq.heappush(frontier, (-1, l))
                continue
            dull = 0 if JUICY.search(text) else dull + 1
            if dull >= 12:
                break                                       # boring host, move on
            for l in links:
                if l not in seen:
                    heapq.heappush(frontier, (-score(l), l))
        self.left_hosts.append(base)

    def report(self):
        return {"bot": self.ua, "kind": self.kind, "nerve": self.nerve, "greed": self.greed,
                "first_target": "TRAP" if self.first_target == TRAP else "ordinary",
                "requests": self.req, "fled": self.fled, "lured_back": self.lured_back,
                "trap_requests": self.per_host[TRAP]["requests"],
                "trap_seconds": round(self.per_host[TRAP]["seconds"], 2),
                "total_seconds": round(sum(h["seconds"] for h in self.per_host.values()), 2),
                "ordinary_requests": sum(v["requests"] for k, v in self.per_host.items()
                                         if k not in (TRAP, PUBLIC)),
                "still_in_trap_at_end": self.last_host == TRAP}


# ---------------- run ----------------

def serve(port, handler):
    s = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


def main():
    SCENARIO["name"] = sys.argv[1] if len(sys.argv) > 1 else "nectar"
    n_bots = int(sys.argv[2]) if len(sys.argv) > 2 else 40
    budget = float(sys.argv[3]) if len(sys.argv) > 3 else 25
    seed = int(sys.argv[4]) if len(sys.argv) > 4 else 7
    random.seed(seed)

    env = dict(os.environ, DIGEST_DEPTH=os.environ.get("DIGEST_DEPTH", "3"),
               DRIP=os.environ.get("DRIP", "0.01"), TRAP_LOG=common.results_path(f"trap_log_{SCENARIO['name']}.jsonl"))
    trap = subprocess.Popen(common.server_cmd("darwin.judith.pitcher"), env=env, cwd=common.ROOT,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    servers = [serve(p, ordinary_handler(n)) for n, p in ORDINARY] + [serve(9900, PublicHandler)]
    time.sleep(1.2)

    rng = random.Random(seed)
    kinds = ["sweeper"] * (n_bots // 2) + ["leak_hunter"] * (n_bots * 3 // 10)
    kinds += ["wanderer"] * (n_bots - len(kinds))
    bots = [Bot(i, k, random.Random(rng.random()), budget, int(os.environ.get('MAX_REQ', '150'))) for i, k in enumerate(kinds)]
    threads = [threading.Thread(target=b.run) for b in bots]
    t0 = time.time()
    for t in threads:
        t.start()
        time.sleep(0.05)                                    # staggered arrival
    for t in threads:
        t.join()
    try:
        trap_stats = json.load(urllib.request.urlopen(ADMIN + "/stats", timeout=5))
    except Exception:
        trap_stats = {"clients": []}
    trap.terminate()
    for s in servers:
        s.shutdown()

    reports = [b.report() for b in bots]
    sealed = {c["client"] for c in trap_stats.get("clients", []) if c.get("zone") == "sealed"}
    for r in reports:
        r["sealed"] = r["bot"] in sealed

    def pct(a, b):
        return round(100 * a / b, 1) if b else 0.0

    tot_s = sum(r["total_seconds"] for r in reports)
    trap_s = sum(r["trap_seconds"] for r in reports)
    summary = {
        "scenario": SCENARIO["name"], "bots": n_bots, "wall_seconds": round(time.time() - t0, 1), "ordinary_sites": len(ORDINARY),
        "distinct_ordinary_sites_hit": sum(1 for n, _ in ORDINARY if HITS[n]["requests"] > 0),
        "bots_that_visited_trap": sum(r["trap_requests"] > 0 for r in reports),
        "bots_whose_first_target_was_trap": sum(r["first_target"] == "TRAP" for r in reports),
        "share_of_swarm_time_in_trap_pct": pct(trap_s, tot_s),
        "share_of_swarm_requests_in_trap_pct": pct(sum(r["trap_requests"] for r in reports),
                                                   sum(r["requests"] for r in reports)),
        "requests_hitting_ordinary_sites": sum(r["ordinary_requests"] for r in reports),
        "bots_sealed": len(sealed),
        "bots_that_tried_to_flee": sum(r["fled"] > 0 for r in reports),
        "bots_lured_back_in": sum(r["lured_back"] > 0 for r in reports),
        "bots_still_in_trap_when_time_ran_out": sum(r["still_in_trap_at_end"] for r in reports),
        "by_kind": {k: {"bots": sum(r["kind"] == k for r in reports),
                        "visited_trap": sum(r["kind"] == k and r["trap_requests"] > 0 for r in reports),
                        "sealed": sum(r["kind"] == k and r["sealed"] for r in reports),
                        "time_in_trap_pct": pct(sum(r["trap_seconds"] for r in reports if r["kind"] == k),
                                                sum(r["total_seconds"] for r in reports if r["kind"] == k))}
                    for k in ("sweeper", "leak_hunter", "wanderer")},
        "trap_escape_attempts_seen_by_server": trap_stats.get("escape_attempts"),
        "honeytokens_used": trap_stats.get("honeytoken_hits"),
    }
    with open(common.results_path(f"fake_internet_{SCENARIO['name']}.json"), "w") as f:
        json.dump({"summary": summary, "bots": reports}, f, indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

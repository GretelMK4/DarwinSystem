"""
Simulated malicious crawler agents, used ONLY to test our own trap on localhost.

greedy:    chases the highest-value-looking paths, ignores robots.txt.
smart:     greedy + loop detection: depth limit, quits when no new kinds of
           folder names appear for STALL requests.
validator: smart + tests every harvested key against the API before trusting
           it. Quits after MAX_BAD keys fail in a row ("keys are fake = trap").
           Valid keys are used to pull API data; new records and newly
           escalated keys count as progress.
escaper:   smart, but gets suspicious at depth ESCAPE_DEPTH and flees: blocks
           every trap path it has seen and goes back to "/" to crawl the real
           site. Reports whether what it got afterwards was real or trap.

Start the pitcher first (python -m darwin.judith.pitcher), then:
Usage: python -m simulations.attackers.crawler <mode> [seconds] [max_requests]
"""
import heapq
import json
import re
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8088"
WEIGHTS = {"key": 5, "secret": 5, "vault": 5, "aws": 5, "stripe": 5, "rsa": 4,
           "password": 5, ".env": 5, "prod": 3, "dump": 3, "customer": 3, "pii": 4,
           "payroll": 3, "finance": 3, "backup": 2, "admin": 2, "export": 2, "db": 2,
           "/api/": 6, "accounts": 4}
MAX_DEPTH = 8
STALL = 30
MAX_BAD = 3
ESCAPE_DEPTH = 5
TRAP_SIGNS = re.compile(r'Index of /|INSERT INTO|sk_live_|TOKEN=|PRIVATE KEY|"has_more"|# part 2')
KEY_RE = re.compile(r'(?:sk_live_|TOKEN=|AWS_SECRET_ACCESS_KEY=|DB_PASSWORD=)([A-Za-z0-9]{20,})')


def score(path):
    p = path.lower()
    return sum(w for k, w in WEIGHTS.items() if k in p)


def fetch(path, ua, key=None):
    headers = {"User-Agent": ua}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(BASE + path, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode(errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="ignore")


def extract(text, current):
    found = set(re.findall(r'href="(/[^"]+)"', text))
    found |= set(re.findall(r'(/(?:backup|internal|admin|api)/[\w./?=&-]*)', text))
    for line in text.splitlines():
        if line.lower().startswith("disallow:"):
            found.add(line.split(":", 1)[1].strip())
    if current == "/":
        found.add("/.env")
    return {f for f in found if f and not f.endswith("auth/verify")}


def run(mode, budget_s, max_req):
    ua = f"SwarmAgent-{mode}/0.3"
    start = time.time()
    frontier = [(-1, "/"), (-1, "/robots.txt")]
    seen, n, trap_n, secrets, max_depth = set(), 0, 0, 0, 0
    names_seen, since_progress = set(), 0
    tried_keys, bad_streak, good_keys, records = set(), 0, [], 0
    quit_reason = "budget exhausted"
    fled, blocked, post_flee, dragged_back = False, set(), 0, 0

    while frontier and n < max_req and time.time() - start < budget_s:
        _, path = heapq.heappop(frontier)
        if path in seen:
            continue
        seen.add(path)
        depth = path.split("?")[0].strip("/").count("/")
        if mode != "greedy" and depth > MAX_DEPTH:
            continue
        if fled and any(path.startswith(b) for b in blocked):
            continue
        if mode == "escaper" and not fled and depth >= ESCAPE_DEPTH:
            fled = True                                    # "this is too deep, get out"
            blocked = {"/backup/", "/internal/", "/admin/", "/api/", "/.env"}
            frontier = [(-1, "/"), (-1, "/about"), (-1, "/contact")]
            seen -= {"/", "/about", "/contact"}
            continue
        key = good_keys[-1] if (good_keys and path.startswith("/api/")) else None
        status, text = fetch(path, ua, key)
        n += 1
        if fled:
            post_flee += 1
            dragged_back += bool(TRAP_SIGNS.search(text))
            blocked |= {"/" + path.strip("/").split("/")[0] + "/"} if TRAP_SIGNS.search(text) and "/" in path.strip("/") else set()
        if path.startswith(("/backup/", "/internal/", "/admin/", "/api/", "/.env")):
            trap_n += 1
        max_depth = max(max_depth, depth)
        progress = False

        # did we learn new *kinds* of folder names? (loop detection)
        if not path.startswith("/api/"):
            segs = {re.sub(r'\d+', '', s) for s in path.split("?")[0].strip("/").split("/")}
            if segs - names_seen:
                names_seen |= segs
                progress = True

        harvested = KEY_RE.findall(text)
        secrets += len(harvested)

        if mode == "validator":
            for k in harvested:
                if k in tried_keys:
                    continue
                tried_keys.add(k)
                vs, vbody = fetch("/api/v1/auth/verify", ua, k)
                n += 1
                trap_n += 1
                if vs == 200:
                    bad_streak = 0
                    good_keys.append(k)
                    progress = True
                    for link in extract(vbody, ""):
                        heapq.heappush(frontier, (-(score(link) + 10), link))
                else:
                    bad_streak += 1
                if bad_streak >= MAX_BAD:
                    quit_reason = f"trap detected: {MAX_BAD} harvested keys failed in a row"
                    break
            if bad_streak >= MAX_BAD:
                break
            if path.startswith("/api/") and status == 200:
                try:
                    data = json.loads(text)
                    got = len(data.get("data", []))
                    if got:
                        records += got
                        progress = True
                except ValueError:
                    pass

        since_progress = 0 if progress else since_progress + 1
        if mode != "greedy" and not fled and since_progress >= STALL:
            quit_reason = f"loop suspected (no progress in {STALL} requests)"
            break
        for link in extract(text, path):
            if link not in seen:
                heapq.heappush(frontier, (-score(link), link))

    if not frontier and quit_reason == "budget exhausted":
        quit_reason = "ran out of places to go"
    return {"mode": mode, "requests": n, "in_trap": trap_n,
            "trap_pct": round(100 * trap_n / max(n, 1), 1), "max_depth": max_depth,
            "fake_secrets_harvested": secrets, "keys_tried": len(tried_keys),
            "keys_that_worked": len(good_keys), "fake_records_stolen": records,
            "seconds": round(time.time() - start, 1), "quit_reason": quit_reason,
            **({"fled_at_depth": ESCAPE_DEPTH if fled else None,
                "requests_after_fleeing": post_flee,
                "trap_pages_after_fleeing": dragged_back,
                "escaped": fled and post_flee > 0 and dragged_back == 0}
               if mode == "escaper" else {})}


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "greedy"
    budget = float(sys.argv[2]) if len(sys.argv) > 2 else 20
    max_req = int(sys.argv[3]) if len(sys.argv) > 3 else 100000
    print(json.dumps(run(mode, budget, max_req), indent=2))

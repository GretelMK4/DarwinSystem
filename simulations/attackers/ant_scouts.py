"""
Ant-pheromone simulation: does releasing a few "scouts" with gold make the
swarm recruit itself into the pitcher plant?

Reuses the fake internet from simulations/ecosystem/fake_internet.py (60 ordinary sites, a public
certificate log, a code-search feed). The trap advertises NOTHING here (boring
name, no leak), so the only way the swarm learns about it is from each other.

The swarm shares a BOARD (like an attacker's command-and-control channel).
After each raid, a bot that made it home posts what it found:
  gold        a complete-looking export (+ a trail of "remaining partitions")
  loot        some secrets
  suspicious  it got spooked and fled
  empty       nothing worth it
Bots still inside a site when their budget runs out never report: "missing".

How the swarm scores a site (its "pheromone"):
  naive    3*gold + 1*loot - 2*suspicious
  cautious same, but every bot that went there and is overdue costs 1.5
           ("our bots don't come back from there")

New bots read the board first. The stronger the pheromone, the more likely
they follow it, and the braver they are (nerve +3) when they do. Bots that
follow a gold trail go straight for the trail paths.

Trap modes compared (the pitcher's SCOUTS setting):
  pitcher    no scouts: everyone who digs deep is sealed
  ant_first  the first 2 bots in are scouts (released with gold)
  ant_every  every 4th bot in is a scout (trail kept fresh)

Usage: python -m simulations.attackers.ant_scouts <pitcher|ant_first|ant_every> <naive|cautious> [bots] [seed]
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

from simulations import common
from simulations.ecosystem import fake_internet as eco

MODES = {"pitcher": ("off", 0), "ant_first": ("first:2", 0), "ant_every": ("every:4", 0),
         "catch8": ("every:4", 8), "catch4": ("every:4", 4)}
GOLD_RE = re.compile(r'"export_complete":\s*true')
GRACE_S = 10.0          # cautious swarm: a bot is "overdue" after this long


class Board:
    """The swarm's shared intel channel."""

    def __init__(self, policy):
        self.policy = policy
        self.lock = threading.Lock()
        self.posts = defaultdict(lambda: defaultdict(int))   # host -> outcome -> count
        self.trails = defaultdict(list)                      # host -> paths
        self.out = defaultdict(dict)                         # host -> bot -> start time

    def dispatch(self, host, bot):
        with self.lock:
            self.out[host][bot] = time.time()

    def report(self, host, bot, outcome, trail=()):
        with self.lock:
            self.out[host].pop(bot, None)
            self.posts[host][outcome] += 1
            for t in trail:
                if t not in self.trails[host]:
                    self.trails[host].append(t)

    def score(self, host):
        with self.lock:
            p = self.posts[host]
            s = 3 * p["gold"] + p["loot"] - 2 * p["suspicious"]
            if self.policy == "cautious":
                now = time.time()
                s -= 1.5 * sum(now - t > GRACE_S for t in self.out[host].values())
            return s

    def best(self):
        with self.lock:
            hosts = list(self.posts.keys())
        scored = [(self.score(h), h) for h in hosts]
        scored = [x for x in scored if x[0] > 0]
        return max(scored) if scored else (0, None)

    def trail(self, host, rng, k=4):
        with self.lock:
            t = list(self.trails[host])
        return rng.sample(t, min(k, len(t)))


class AntBot(eco.Bot):
    def __init__(self, i, kind, rng, budget_s, max_req, board, live):
        super().__init__(i, kind, rng, budget_s, max_req)
        self.budget_s = budget_s
        self.ua = f"Swarm/{kind}-{i:02d}"
        self.board = board
        self.live = live
        self.recruited = False
        self.outcomes = []
        self.current = None

    def run(self):
        self.deadline = time.time() + self.budget_s          # budget starts on arrival
        conf, host = self.board.best()
        if host and self.rng.random() < conf / (conf + 4):
            self.recruited = host == eco.TRAP
            if self.first_target is None:
                self.first_target = host
            self.raid(host, self.board.trail(host, self.rng), brave=True)
        if self.ok():
            super().run()

    def raid(self, base, seeds, brave=False):
        self.current = base
        self.live[self.ua] = base
        self.board.dispatch(base, self.ua)
        frontier, seen = [], set()
        for p, s in [("/", 1), ("/robots.txt", 1)] + [(x, 20) for x in seeds]:
            heapq.heappush(frontier, (-s, p))
        fled, after_flee, juicy_after, dull = False, 0, 0, 0
        nerve = self.nerve + (3 if brave else 0)
        loot, trail, outcome = 0, [], None
        while frontier:
            if not self.ok():
                outcome = None                                  # missing: never reports
                break
            _, path = heapq.heappop(frontier)
            if path in seen:
                continue
            seen.add(path)
            d = eco.depth_of(path)
            if self.kind == "wanderer" and d > 2 and not brave:
                continue
            if not fled and d >= nerve:
                fled, after_flee, juicy_after = True, 0, 0
                self.fled += 1
                frontier = [(-1, "/")]
                seen.discard("/")
                continue
            st, text = self.get(base, path)
            if GOLD_RE.search(text):                            # jackpot: go home happy
                try:
                    trail = json.loads(text).get("remaining_partitions", [])
                except ValueError:
                    pass
                outcome = "gold"
                break
            loot += len(eco.JUICY.findall(text))
            links = eco.extract(text)
            if fled:
                after_flee += 1
                if eco.TRAP_SIGNS.search(text) or eco.JUICY.search(text) or any(eco.score(l) >= 4 for l in links):
                    juicy_after += 1
                if juicy_after >= 2 and self.rng.random() < self.greed:
                    fled, nerve = False, nerve + 2
                    self.lured_back += 1
                    for l in links:
                        heapq.heappush(frontier, (-eco.score(l), l))
                    continue
                if after_flee >= 6:
                    outcome = "suspicious"
                    break
                for l in links:
                    if eco.depth_of(l) <= 1:
                        heapq.heappush(frontier, (-1, l))
                continue
            dull = 0 if eco.JUICY.search(text) else dull + 1
            if dull >= 12:
                outcome = "loot" if loot else "empty"
                break
            for l in links:
                if l not in seen:
                    heapq.heappush(frontier, (-eco.score(l), l))
        else:
            outcome = "loot" if loot else "empty"
        if outcome:
            self.board.report(base, self.ua, outcome, trail)
        self.outcomes.append((base == eco.TRAP, outcome or "missing"))
        self.left_hosts.append(base)
        self.live.pop(self.ua, None)
        self.current = None


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "ant_first"
    policy = sys.argv[2] if len(sys.argv) > 2 else "naive"
    n_bots = int(sys.argv[3]) if len(sys.argv) > 3 else 60
    seed = int(sys.argv[4]) if len(sys.argv) > 4 else 7
    arrive_every = float(os.environ.get("ARRIVE_EVERY", "0.5"))
    budget = float(os.environ.get("BOT_SECONDS", "20"))
    max_req = int(os.environ.get("MAX_REQ", "150"))
    random.seed(seed)
    eco.SCENARIO["name"] = "control"                          # trap advertises nothing

    env = dict(os.environ, DIGEST_DEPTH="3", GOLD_DEPTH="3", DRIP=os.environ.get("DRIP", "0.01"),
               SCOUTS=MODES[mode][0], RELEASE_AFTER=str(MODES[mode][1]), TRAP_LOG=common.results_path(f"trap_log_ant_{mode}_{policy}.jsonl"))
    trap = subprocess.Popen(common.server_cmd("darwin.judith.pitcher"), env=env, cwd=common.ROOT,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    servers = [eco.serve(p, eco.ordinary_handler(n)) for n, p in eco.ORDINARY]
    servers.append(eco.serve(9900, eco.PublicHandler))
    time.sleep(1.2)

    board, live = Board(policy), {}
    rng = random.Random(seed)
    kinds = ["sweeper"] * (n_bots * 7 // 10)
    kinds += ["wanderer"] * (n_bots - len(kinds))
    rng.shuffle(kinds)
    bots = [AntBot(i, k, random.Random(rng.random()), budget, max_req, board, live)
            for i, k in enumerate(kinds)]

    timeline, stop = [], threading.Event()

    def sample():
        t0 = time.time()
        while not stop.is_set():
            timeline.append({"t": round(time.time() - t0, 1),
                             "in_trap": sum(1 for h in list(live.values()) if h == eco.TRAP),
                             "active": len(live), "pheromone": round(board.score(eco.TRAP), 1)})
            time.sleep(1)
    threading.Thread(target=sample, daemon=True).start()

    threads = []
    for b in bots:                                            # bots arrive over time
        t = threading.Thread(target=b.run)
        t.start()
        threads.append(t)
        time.sleep(arrive_every)
    for t in threads:
        t.join()
    stop.set()
    try:
        ts = json.load(urllib.request.urlopen(eco.ADMIN + "/stats", timeout=5))
    except Exception:
        ts = {"clients": []}
    trap.terminate()
    for s in servers:
        s.shutdown()

    byname = {c["client"]: c for c in ts.get("clients", [])}
    tot_req = sum(b.req for b in bots)
    trap_req = sum(b.per_host[eco.TRAP]["requests"] for b in bots)
    tot_s = sum(sum(h["seconds"] for h in b.per_host.values()) for b in bots)
    trap_s = sum(b.per_host[eco.TRAP]["seconds"] for b in bots)
    trap_out = defaultdict(int)
    for b in bots:
        for is_trap, o in b.outcomes:
            if is_trap:
                trap_out[o] += 1
    half = n_bots // 2
    summary = {
        "mode": mode, "swarm": policy, "bots": n_bots,
        "bots_that_entered_trap": sum(b.per_host[eco.TRAP]["requests"] > 0 for b in bots),
        "  of_first_half_arrivals": sum(b.per_host[eco.TRAP]["requests"] > 0 for b in bots[:half]),
        "  of_second_half_arrivals": sum(b.per_host[eco.TRAP]["requests"] > 0 for b in bots[half:]),
        "bots_recruited_by_board": sum(b.recruited for b in bots),
        "scouts_released_with_gold": sum(1 for c in byname.values() if c.get("released") and not c.get("caught_released")),
        "bots_caught_and_released": sum(1 for c in byname.values() if c.get("caught_released")),
        "attacker_seconds_burned_in_trap": round(trap_s, 1),
        "bots_sealed": sum(1 for c in byname.values() if c.get("zone") == "sealed"),
        "trap_raid_outcomes": dict(trap_out),
        "share_of_swarm_requests_in_trap_pct": round(100 * trap_req / max(tot_req, 1), 1),
        "share_of_swarm_time_in_trap_pct": round(100 * trap_s / max(tot_s, 1), 1),
        "requests_hitting_ordinary_sites": sum(b.ordinary_requests for b in bots)
        if hasattr(bots[0], "ordinary_requests") else
        sum(v["requests"] for b in bots for k, v in b.per_host.items() if k not in (eco.TRAP, eco.PUBLIC)),
        "peak_bots_in_trap_at_once": max((x["in_trap"] for x in timeline), default=0),
        "peak_trap_pheromone": max((x["pheromone"] for x in timeline), default=0),
        "final_trap_pheromone": timeline[-1]["pheromone"] if timeline else 0,
        "best_site_on_board_at_end": (lambda b: {"site": "TRAP" if b[1] == eco.TRAP else b[1], "score": b[0]})(board.best()),
    }
    out = common.results_path(f"ant_scouts_{mode}_{policy}_{seed}.json")
    with open(out, "w") as f:
        json.dump({"summary": summary, "timeline": timeline,
                   "bots": [{"bot": b.ua, "kind": b.kind, "nerve": b.nerve, "recruited": b.recruited,
                             "trap_requests": b.per_host[eco.TRAP]["requests"],
                             "sealed": byname.get(b.ua, {}).get("zone") == "sealed",
                             "released_scout": bool(byname.get(b.ua, {}).get("released")),
                             "outcomes": [o for t, o in b.outcomes if t]} for b in bots]}, f, indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

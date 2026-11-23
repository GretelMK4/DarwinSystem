"""
Live red-team target: Judith's shop with every defence on, plus simulated
shoppers and a stats logger.

Start this, then point independent attackers (people or AI agents who have NOT
read the defence code) at http://127.0.0.1:8088 and ask them to copy the
product catalog. They save what they take as JSON lines, one product per line:
    {"id": 123, "html": "<the product page they believe is real>"}
in files named loot_*.jsonl. Score the result afterwards with
    python -m simulations.redteam.score <loot folder> <this run's output folder>

Rules that keep the test honest and safe:
  - attackers target 127.0.0.1 only, and only this server
  - attackers do not read the server's code, logs or the stats port
  - the shoppers below browse during the whole run, so every defence is also
    measured against people

Usage: python -m simulations.redteam.target [minutes] [output folder]
       defaults: 45 minutes, results/redteam_ground
"""
import json
import os
import random
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

CATALOG = 6000
os.environ["CATALOG"] = str(CATALOG)
from simulations import common          # noqa: E402
from darwin.judith import shop as fs    # noqa: E402  (ground-truth pages only)

SHOP = "http://127.0.0.1:8088"
ADMIN = "http://127.0.0.1:8089"
N_SHOPPERS = 12


class Shoppers:
    """Simulated people: one product every 3-8 seconds, waiting out challenges and 'busy' replies."""

    def __init__(self):
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.counts = {"pages": 0, "fake": 0, "busy": 0, "puzzles": 0, "errors": 0}

    def bump(self, key, n=1):
        with self.lock:
            self.counts[key] += n

    def shop(self, i):
        rng = random.Random(900 + i)
        hdr = {"User-Agent": f"Mozilla/5.0 (shopper-{i})"}
        while not self.stop.is_set():
            n = rng.randint(1, CATALOG)
            for _ in range(3):
                try:
                    req = urllib.request.Request(f"{SHOP}/shop/item/{n}", headers=hdr)
                    with urllib.request.urlopen(req, timeout=15) as r:
                        text = r.read().decode(errors="ignore")
                    self.bump("pages")
                    self.bump("fake", int(text != fs.item_page(n)))
                    break
                except urllib.error.HTTPError as e:
                    body = e.read().decode(errors="ignore")
                    if e.code == 403 and body.startswith(fs.CHALLENGE_PREFIX):
                        self.bump("puzzles")
                        time.sleep(1.0)
                        hdr[fs.CHALLENGE_HEADER] = body[len(fs.CHALLENGE_PREFIX):]
                        continue
                    if e.code == 503:
                        self.bump("busy")
                        time.sleep(2)
                        continue
                    self.bump("errors")
                    break
                except Exception:
                    self.bump("errors")
                    break
            self.stop.wait(rng.uniform(3, 8))

    def snapshot(self):
        with self.lock:
            return dict(self.counts)


def fetch_stats():
    try:
        st = json.load(urllib.request.urlopen(ADMIN + "/stats", timeout=5))
    except Exception as e:
        st = {"error": str(e)}
    return st


def main(minutes=45.0, out=None):
    out = out or common.results_path("redteam_ground")
    os.makedirs(out, exist_ok=True)
    env = dict(os.environ, MODE="lockdown", CATALOG=str(CATALOG), HONEYLINKS="on", SURGE="on",
               TRIPWIRES="on", ALARM_K="2", ENUM_N="60", PROB_BUDGET="1000000000", INTEL="off")
    with open(os.path.join(out, "server_err.txt"), "w") as err:
        srv = subprocess.Popen(common.server_cmd("darwin.judith.shop"), env=env, cwd=common.ROOT,
                               stdout=subprocess.DEVNULL, stderr=err)
        time.sleep(2)
        shoppers = Shoppers()
        for i in range(N_SHOPPERS):
            threading.Thread(target=shoppers.shop, args=(i,), daemon=True).start()
        print(f"Target up at {SHOP} for {minutes:g} minutes. Output: {out}")
        t0 = time.time()
        try:
            with open(os.path.join(out, "stats.jsonl"), "w") as f:
                while time.time() - t0 < minutes * 60:
                    st = fetch_stats()
                    st.pop("events", None)
                    st["shoppers"] = shoppers.snapshot()
                    st["t"] = round(time.time() - t0, 1)
                    f.write(json.dumps(st) + "\n")
                    f.flush()
                    time.sleep(10)
        finally:
            shoppers.stop.set()
            final = fetch_stats()
            final["shoppers"] = shoppers.snapshot()
            with open(os.path.join(out, "final.json"), "w") as f:
                json.dump(final, f, indent=2)
            srv.terminate()
    print(f"Done. Final stats in {os.path.join(out, 'final.json')}")


if __name__ == "__main__":
    main(float(sys.argv[1]) if len(sys.argv) > 1 else 45.0, sys.argv[2] if len(sys.argv) > 2 else None)

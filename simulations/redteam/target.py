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
  - the shoppers below browse during the whole run, each from their own
    address, so every defence is also measured against people

Whole-ecosystem mode: set HERCULES=<n> to also start n Hercules decoy sites on
ports 9500 and up, connected to the shop by signed intel. An attacker identity
seen on a decoy site, or a fake key issued there, is then sealed at the shop.
(Venus is a model with no device code, so it cannot take part in a live test.)

The Spider (darwin/judith/spider.py) runs in alert mode by default: it flags
but does not act. Set SPIDER=seal to let Judith seal what it flags, or
SPIDER=off to run without it. Its flags are written to spider_flags.jsonl in
the output folder.

Usage: [HERCULES=8] [SPIDER=seal] python -m simulations.redteam.target [minutes] [output folder]
       defaults: 45 minutes, results/redteam_ground
"""
import http.client
import json
import os
import random
import subprocess
import sys
import threading
import time
import urllib.request

CATALOG = 6000
os.environ["CATALOG"] = str(CATALOG)
from darwin import intel                # noqa: E402
from darwin.hercules import honeyfarm   # noqa: E402
from simulations import common          # noqa: E402
from darwin.judith import shop as fs    # noqa: E402  (ground-truth pages only)

SHOP = "http://127.0.0.1:8088"
ADMIN = "http://127.0.0.1:8089"
N_SHOPPERS = 12


BROWSERS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"]


class Shoppers:
    """
    Simulated people. Each of the N_SHOPPERS slots is a stream of visits: a shopper arrives
    from their own address (127.0.9.x to 127.0.14.x) with an ordinary browser User-Agent,
    looks at 4 to 25 products with 3 to 8 seconds between them (going back to one they
    have seen about one time in five), and leaves. Then the next shopper arrives.
    Every page received is compared with the real catalog.
    """

    def __init__(self):
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.counts = {"visits": 0, "pages": 0, "fake": 0, "busy": 0, "puzzles": 0, "errors": 0}

    def bump(self, key, n=1):
        with self.lock:
            self.counts[key] += n

    def fetch(self, address, hdr, n):
        """One product page from the shopper's own source address. Returns (status, body)."""
        conn = http.client.HTTPConnection("127.0.0.1", 8088, timeout=15, source_address=(address, 0))
        try:
            conn.request("GET", f"/shop/item/{n}", headers=dict(hdr, Connection="close"))
            r = conn.getresponse()
            return r.status, r.read().decode(errors="ignore")
        finally:
            conn.close()

    def shop(self, i):
        rng = random.Random(900 + i)
        while not self.stop.is_set():
            address = f"127.0.{rng.randint(9, 14)}.{rng.randint(1, 250)}"
            hdr = {"User-Agent": rng.choice(BROWSERS)}
            seen = []
            self.bump("visits")
            for _ in range(rng.randint(4, 25)):
                if self.stop.is_set():
                    return
                n = rng.choice(seen) if seen and rng.random() < 0.2 else rng.randint(1, CATALOG)
                seen.append(n)
                for _ in range(3):
                    try:
                        status, text = self.fetch(address, hdr, n)
                    except Exception:
                        self.bump("errors")
                        break
                    if status == 200:
                        self.bump("pages")
                        self.bump("fake", int(text != fs.item_page(n)))
                        break
                    if status == 403 and text.startswith(fs.CHALLENGE_PREFIX):
                        self.bump("puzzles")
                        hdr[fs.CHALLENGE_HEADER] = fs.solve_challenge(text)   # real proof of work
                        continue
                    if status == 503:
                        self.bump("busy")
                        time.sleep(2)
                        continue
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


def forward_intel(herc, key, stop):
    """Pass whatever Hercules has caught to the shop as signed intel, twice a second."""
    while not stop.wait(0.5):
        envelope = herc.take_signed_intel(key)
        if envelope is None:
            continue
        try:
            urllib.request.urlopen(urllib.request.Request(
                ADMIN + "/intel", data=json.dumps(envelope).encode(), method="POST"), timeout=5).read()
        except Exception:
            pass


def main(minutes=45.0, out=None, n_hercules=0):
    out = out or common.results_path("redteam_ground")
    os.makedirs(out, exist_ok=True)
    env = dict(os.environ, MODE="lockdown", CATALOG=str(CATALOG), HONEYLINKS="on", SURGE="on",
               TRIPWIRES="on", ALARM_K="2", ENUM_N="60", PROB_BUDGET="1000000000", INTEL="off")
    if env.get("SPIDER", "alert") != "off":
        env["SPIDER_LOG"] = os.path.join(out, "spider_flags.jsonl")
    herc = None
    if n_hercules:
        key = intel.new_key()
        env.update({"INTEL": "on", intel.ENV_KEY: key})
        herc = honeyfarm.Hercules(n_hercules, diverse=True, seed=1, per_site_keys=True)
        herc.start()
        print("Hercules sites: " + ", ".join(f"http://127.0.0.1:{s['port']}" for s in herc.sites))
    with open(os.path.join(out, "server_err.txt"), "w") as err:
        srv = subprocess.Popen(common.server_cmd("darwin.judith.shop"), env=env, cwd=common.ROOT,
                               stdout=subprocess.DEVNULL, stderr=err)
        time.sleep(2)
        shoppers = Shoppers()
        for i in range(N_SHOPPERS):
            threading.Thread(target=shoppers.shop, args=(i,), daemon=True).start()
        if herc:
            threading.Thread(target=forward_intel, args=(herc, key.encode(), shoppers.stop), daemon=True).start()
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
            if herc:
                final["hercules"] = herc.stats()
                herc.stop()
            with open(os.path.join(out, "final.json"), "w") as f:
                json.dump(final, f, indent=2)
            srv.terminate()
    print(f"Done. Final stats in {os.path.join(out, 'final.json')}")


if __name__ == "__main__":
    main(float(sys.argv[1]) if len(sys.argv) > 1 else 45.0, sys.argv[2] if len(sys.argv) > 2 else None,
         n_hercules=int(os.environ.get("HERCULES", "0")))

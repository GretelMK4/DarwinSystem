"""
Nightly lab harness, 2026-11-27: in-process, virtual clock, no network.

Drives Darwin's real code (darwin.judith.spider.Spider, darwin.judith.shop.item_page and the
shop's spider_flag / spider_sealed decision) with simulated visitors.

  second_opinion  an attacker recomputes every shadow fake from the public code and compares it
                  with what it was served (Nov 25 finding 20261125-2)
  cgnat           one mobile-carrier address: 400 households a day, each with its own browser
                  build, plus one patient copier on the same address (20261125-3, -8)
  cgnat_quiet     the households only (false positives)
  rotator25/400   one dedicated address copies the whole catalog, rotating 25 or 400 User-Agents
  latency_tell    researcher scenario 1: time a pitcher page before and after the sealing request
                  (runs Judith's real shop on a localhost port of this process)
  token_frame     a compromised Hercules reports real customers' API keys as its fake keys
  cgnat_framing   the same, but the copier uses the most common household browser string, so
                  its identity overlaps real people (20261125-4)

Usage: python -m simulations.nightly.n20261127 <scenario|all> [seeds] [--fixed]
--fixed = the branch (shadow secret, seal lifetime, identity-scoped seals on shared addresses);
without it the release behaviour is reproduced. Prints one JSON object per run.
"""
import json
import math
import random
import sys

from darwin.judith import shop
from darwin.judith.spider import Policy, Spider

DAY = 86400.0


def release_fake_name(n):
    r = random.Random("FAKE" + str(n))
    return f"{r.choice(shop.ADJ)} {r.choice(shop.NOUN)} {r.randint(100, 999)}"


def run_second_opinion(seed, fixed):
    rng = random.Random(seed)
    sample = rng.sample(range(1, shop.CATALOG + 1), 500)
    if fixed:
        served = {n: shop.item_page(n, fake=True) for n in sample}
    else:                                              # release: the fake is a pure function of n
        served = {n: release_fake_name(n) for n in sample}
    detected = sum(release_fake_name(n) in served[n] for n in sample)
    return {"scenario": "second_opinion", "seed": seed, "fixed": fixed,
            "fakes_checked": len(sample), "detected_offline": detected,
            "detected_share": round(detected / len(sample), 4)}


def household_ua(rng):
    # browser builds follow a long tail: a few very common, most rare
    k = min(int(rng.paretovariate(1.2)), 300)
    return f"Mozilla/5.0 (Android 15) Chrome/131.0.{k}"


def run_cgnat(scenario, seed, fixed, days=3, inspect_every=300.0):
    rng = random.Random(seed)
    pol = Policy({"SPIDER_FLEET": "off", **EXTRA_ENV})
    if not fixed:
        pol.seal_ttl = float("inf")
        pol.crowd_alert = False
        pol.shared_uas = 10 ** 9                       # release: every flag seals the address, forever
    sp = Spider(pol)
    sealed = {}                                        # subject -> until (same rule as shop.spider_sealed)
    addr = "100.64.7.7"
    ev = []
    for d in range(days):
        for h in range(400):
            t = d * DAY + rng.random() * DAY
            ua = household_ua(rng)
            for _ in range(max(1, int(rng.expovariate(1 / 5)))):
                ev.append((t, ua, 1 + int(rng.paretovariate(0.9)) % 3000, "household", f"{d}-{h}"))
                t += rng.lognormvariate(math.log(35), 0.6)
    bot_ua = "Mozilla/5.0 (Android 15) Chrome/131.0.1" if scenario == "cgnat_framing" else "Mozilla/5.0 (X11) Chrome/130"
    t = DAY + 9 * 3600
    if scenario.startswith("rotator"):
        # a dedicated address (no households) whose copier rotates User-Agents to look like a crowd
        ev = []
        n_ua = 25 if scenario == "rotator25" else 400
        for i, prod in enumerate(rng.sample(range(1, 3001), 3000)):
            ev.append((t, f"Mozilla/5.0 build-{i % n_ua}", prod, "bot", "bot"))
            t += rng.uniform(20, 40)
    for i, prod in enumerate(rng.sample(range(1, 3001), 0 if scenario in ("cgnat_quiet",) or scenario.startswith("rotator") else 400)):
        ev.append((t, bot_ua, prod, "bot", "bot"))     # a patient copier: 400 products over 10 h
        t += rng.uniform(60, 120)
    ev.sort(key=lambda e: e[0])
    nxt, flagged_at, rules = inspect_every, None, {}
    hh_fake, hh_hit, hh_views, stolen, bot_fake = 0, set(), 0, set(), 0
    for t, ua, prod, kind, who in ev:
        while t >= nxt:
            for f in sp.inspect(now=nxt):
                if f["rule"] in ("breadth", "enumeration", "metronome", "many_identities", "crowd_breadth"):
                    rules[f["rule"]] = rules.get(f["rule"], 0) + 1
                    if any(x.endswith("|" + bot_ua) for x in f.get("seal", [])) or (
                            f.get("seal", [f["subject"]]) == [addr] and t > DAY + 9 * 3600):
                        flagged_at = flagged_at or nxt
                    for s in f.get("seal", [f["subject"]]):
                        sealed[s] = max(sealed.get(s, 0), nxt + pol.seal_ttl)
            nxt += inspect_every
        sp.observe(addr, ua, prod, t)
        shadow = any(sealed.get(s, 0) > t for s in (addr, f"{addr}|{ua}"))
        if kind == "household":
            hh_views += 1
            if shadow:
                hh_fake += 1
                hh_hit.add(who)
        else:
            if shadow:
                bot_fake += 1
            else:
                stolen.add(prod)
    hh = max(1, len({e[4] for e in ev if e[3] == "household"}))
    return {"scenario": scenario, "seed": seed, "fixed": fixed,
            "households": hh, "households_shown_fakes": len(hh_hit),
            "household_fp_rate": round(len(hh_hit) / hh, 4), "household_fake_pages": hh_fake,
            "household_views": hh_views, "bot_products_stolen": len(stolen), "bot_fakes": bot_fake,
            "copier_flagged_after_s": round(flagged_at - (DAY + 9 * 3600)) if flagged_at else None,
            "flags_by_rule": rules, "sealed_subjects": len(sealed),
            "copier_identity_sealed": any(k.endswith("|" + bot_ua) for k in sealed) or addr in sealed,
            "address_sealed": addr in sealed}


def run_latency(seed, fixed, samples=12):
    """Researcher scenario 1 (latency tell), against Judith's real shop server on a localhost port of this
    process. One agent times the same pitcher listing and a product page before and after the request that
    seals it, and calls the seal visible when the median moves by more than 3 times the spread it measured
    first (or by half)."""
    import http.client
    import statistics
    import threading
    import time
    old_even, shop.DRIP_EVEN = shop.DRIP_EVEN, fixed
    srv = shop.ShopServer(("127.0.0.1", 0), shop.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    def get(path, ua):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        t = time.perf_counter()
        conn.request("GET", path, headers={"User-Agent": ua})
        conn.getresponse().read()
        conn.close()
        return time.perf_counter() - t

    out = {"scenario": "latency_tell", "seed": seed, "fixed": fixed, "agents": 0, "seal_visible": 0,
           "product_tell": 0, "ratios": []}
    try:
        for a in range(4):
            ua = f"agent-{seed}-{a}-{fixed}"
            get("/backup/", ua)
            c = shop.CLIENTS.get(f"127.0.0.1|{ua}")
            if c is None or c["role"] == "scout":
                continue                                   # scouts are released with gold, not sealed
            out["agents"] += 1
            pre = [get("/backup/", ua) for _ in range(samples)]
            prod_pre = [get("/shop/item/%d" % (100 + k), ua) for k in range(samples)]
            get("/backup/db/users_2024.sql", ua)           # depth 2: this request seals
            post = [get("/backup/", ua) for _ in range(samples)]
            prod_post = [get("/shop/item/%d" % (200 + k), ua) for k in range(samples)]
            spread = (statistics.quantiles(pre, n=4)[2] - statistics.quantiles(pre, n=4)[0]) or 1e-4
            shift = statistics.median(post) - statistics.median(pre)
            ratio = statistics.median(post) / statistics.median(pre)
            out["ratios"].append(round(ratio, 2))
            out["seal_visible"] += abs(shift) > 3 * spread or abs(ratio - 1) > 0.5
            pr = statistics.median(prod_post) / statistics.median(prod_pre)
            out["product_tell"] += abs(pr - 1) > 0.5
    finally:
        srv.shutdown()
        srv.server_close()
        shop.DRIP_EVEN = old_even
    return out


def run_token_frame(seed, fixed):
    """Analyst finding 20261125E-11 (Nov 25 evening): a compromised Hercules reports 500 real customers' API
    keys as 'fake keys it handed out', so Judith would seal whoever uses them. An honest Hercules reports 100
    fake keys it really issued. Goes through the shop's real intel intake (Admin.take_intel)."""
    import io
    from darwin import intel
    rng = random.Random(seed)
    keys = {"hercules-1": intel.new_key().encode(), "hercules-2": intel.new_key().encode()}
    old = (shop.INTEL_VERIFIER, shop.INTEL_TOKENS, shop.INTEL_IDS, shop.INTEL_TOKEN_CHECK, shop.INTEL_ON)
    shop.INTEL_ON = True
    shop.INTEL_VERIFIER = intel.Verifier(keys=keys, me="judith")
    shop.INTEL_TOKENS = intel.IntelStore(quorum=1)
    shop.INTEL_IDS = intel.IntelStore(quorum=2)
    shop.INTEL_TOKEN_CHECK = fixed
    real = ["".join(rng.choice(intel.TOKEN_ALPHABET) for _ in range(28)) for _ in range(500)]
    mint = (lambda r: intel.mint_token(keys["hercules-2"], r)) if fixed else (lambda r: shop.ts.tok(r, 28))
    honest = [mint(rng) for _ in range(100)]

    class Fake:
        def __init__(self, env):
            data = json.dumps(env).encode()
            self.headers = {"Content-Length": str(len(data))}
            self.path = "/intel"
            self.rfile = io.BytesIO(data)
    try:
        shop.Admin.take_intel(Fake(intel.sign({"tokens": real}, keys["hercules-1"], sender="hercules-1", to="judith")))
        shop.Admin.take_intel(Fake(intel.sign({"tokens": honest}, keys["hercules-2"], sender="hercules-2", to="judith")))
        framed = sum(t in shop.INTEL_TOKENS for t in real)
        caught = sum(t in shop.INTEL_TOKENS for t in honest)
    finally:
        shop.INTEL_VERIFIER, shop.INTEL_TOKENS, shop.INTEL_IDS, shop.INTEL_TOKEN_CHECK, shop.INTEL_ON = old
    return {"scenario": "token_frame", "seed": seed, "fixed": fixed,
            "real_customer_keys_accepted": framed, "real_customer_keys": len(real),
            "honest_fake_keys_accepted": caught, "honest_fake_keys": len(honest)}


EXTRA_ENV = {}
SCENARIOS = ["second_opinion", "cgnat", "cgnat_framing", "cgnat_quiet", "rotator25", "rotator400", "latency_tell", "token_frame"]


def run(scenario, seed, fixed):
    if scenario == "token_frame":
        return run_token_frame(seed, fixed)
    if scenario == "latency_tell":
        return run_latency(seed, fixed)
    if scenario == "second_opinion":
        return run_second_opinion(seed, fixed)
    if scenario.startswith(("cgnat", "rotator")):
        return run_cgnat(scenario, seed, fixed)
    raise SystemExit(f"unknown scenario {scenario}")


def main(argv):
    scen = argv[0] if argv else "all"
    seeds = int(argv[1]) if len(argv) > 1 and argv[1].isdigit() else 3
    fixed = "--fixed" in argv
    for a in argv:
        if a.startswith("SPIDER_") and "=" in a:
            k, v = a.split("=", 1)
            EXTRA_ENV[k] = v
    for name in (SCENARIOS if scen == "all" else [scen]):
        for seed in range(seeds):
            print(json.dumps(run(name, seed, fixed)), flush=True)


if __name__ == "__main__":
    main(sys.argv[1:])

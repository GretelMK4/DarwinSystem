"""
Nightly lab harness, 2026-11-27: in-process, virtual clock, no network.

Drives Darwin's real code (darwin.judith.spider.Spider, darwin.judith.shop.item_page and the
shop's spider_flag / spider_sealed decision) with simulated visitors.

  second_opinion  an attacker recomputes every shadow fake from the public code and compares it
                  with what it was served (Nov 25 finding 20261125-2)
  cgnat           one mobile-carrier address: 400 households a day, each with its own browser
                  build, plus one patient copier on the same address (20261125-3, -8)
  cgnat_quiet     the households only (false positives)
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
    for i, prod in enumerate(rng.sample(range(1, 3001), 0 if scenario == "cgnat_quiet" else 400)):    # a patient copier: 400 products over 10 h
        ev.append((t, bot_ua, prod, "bot", "bot"))
        t += rng.uniform(60, 120)
    ev.sort(key=lambda e: e[0])
    nxt, flagged_at, rules = inspect_every, None, {}
    hh_fake, hh_hit, hh_views, stolen, bot_fake = 0, set(), 0, set(), 0
    for t, ua, prod, kind, who in ev:
        while t >= nxt:
            for f in sp.inspect(now=nxt):
                if f["rule"] in ("breadth", "enumeration", "metronome", "many_identities"):
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
    hh = len({e[4] for e in ev if e[3] == "household"})
    return {"scenario": scenario, "seed": seed, "fixed": fixed,
            "households": hh, "households_shown_fakes": len(hh_hit),
            "household_fp_rate": round(len(hh_hit) / hh, 4), "household_fake_pages": hh_fake,
            "household_views": hh_views, "bot_products_stolen": len(stolen), "bot_fakes": bot_fake,
            "copier_flagged_after_s": round(flagged_at - (DAY + 9 * 3600)) if flagged_at else None,
            "flags_by_rule": rules, "sealed_subjects": len(sealed),
            "copier_identity_sealed": any(k.endswith("|" + bot_ua) for k in sealed) or addr in sealed}


EXTRA_ENV = {}
SCENARIOS = ["second_opinion", "cgnat", "cgnat_framing", "cgnat_quiet"]


def run(scenario, seed, fixed):
    if scenario == "second_opinion":
        return run_second_opinion(seed, fixed)
    if scenario.startswith("cgnat"):
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

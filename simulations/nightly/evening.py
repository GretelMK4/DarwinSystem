"""
Nightly lab harness, 2026-11-25 evening: in-process, virtual clock, no network.

Two groups of scenarios drive Darwin's real code (darwin.judith.spider.Spider,
darwin.intel.Verifier / IntelStore) with simulated visitors and plants.

Spider group (a model of Judith's shop decision: sealed address or fleet guard
on this request -> shadow page, otherwise the real page):
  shoppers       3 days of simulated shoppers only (false positives)
  hydra          2,000 residential addresses x 3 tail products, over 6 h
  hydra_slow     the same 6,000 products spread over 72 h
  hydra_ramp     boiling frog: day 1 small, doubling each day
  hydra_padded   each address first opens 3 popular products, then 3 tail ones
  hydra_padded10 the same with 10 popular products first (analyst F1)
  vantage_warm   vantage, but one long-lived control identity does all re-fetches (analyst F3)
  notebook       (2026-11-27) a second cold swarm member opens each product 0-2 h after the first and the
                 swarm's shared notes compare the two copies
  (hydra uses 1,000 addresses x 3 = the whole 3,000-product catalog; 2,000 x 3 asked for more
   products than exist, analyst artifact A1)
Intel group (three Hercules, one compromised; Judith and Venus receive):
  forged_witness compromised plant signs reports as itself AND as another plant
                 to meet a 2-witness quorum, naming 3,000 shopper identities
  cross_replay   an honest report captured on its way to Venus is replayed to Judith
  intel_flood    compromised plant floods junk identities, then honest plants
                 report 500 real bots; how many real bots does Judith still know?

  vantage        researcher scenario 2: hydra, and a clean control identity re-fetches every
                 product 2-12 h later; a fake that differs from the control is exposed
  echo_double    researcher scenario 4: one honest report delivered twice, quorum 2
  pollution      researcher scenario 3: swarm on 2,000 residential exits; honest plants report
                 address|UA; the households behind those exits use the same common UA

Usage: python -m simulations.nightly.evening <scenario|all> [seeds] [--fixed] [SPIDER_X=v ...]
--fixed runs the branch defences (fleet rule, per-plant keys, recipients, IntelStore);
without it the release behaviour is reproduced (fleet off, shared key, plain set store).
Prints one JSON object per run.
"""
import json
import math
import random
import sys

from darwin import intel
from darwin.judith.spider import Policy, Spider

DAY = 86400.0
CATALOG = 3000


def zipf_sampler(rng, n, s=1.0):
    weights = [1 / (i ** s) for i in range(1, n + 1)]
    total = sum(weights)
    cum, acc = [], 0.0
    for w in weights:
        acc += w / total
        cum.append(acc)
    import bisect

    def draw():
        return bisect.bisect_left(cum, rng.random()) + 1
    return draw


def shopper_events(rng, days, per_day=3000):
    draw = zipf_sampler(rng, CATALOG)
    ev = []
    for d in range(days):
        for i in range(per_day):
            t = d * DAY + rng.random() * DAY
            addr = f"home-{rng.randrange(40000)}"
            ua = rng.choice(["Mozilla/5.0 (Windows) Chrome", "Mozilla/5.0 (iPhone) Safari",
                             "Mozilla/5.0 (Mac) Safari", "Mozilla/5.0 (Android) Chrome"])
            for _ in range(max(1, int(rng.expovariate(1 / 6)))):
                ev.append((t, addr, ua, draw(), "shopper", f"s{d}-{i}"))
                t += rng.lognormvariate(math.log(35), 0.6)
    return ev


def hydra_events(rng, start, spread, n_addr=1000, per_addr=3, pad_popular=0, schedule=None):
    """Residential-proxy swarm: every address takes a few products the swarm has not yet got."""
    products = list(range(1, CATALOG + 1))
    rng.shuffle(products)
    ev, k = [], 0
    windows = schedule or [(start, spread, n_addr)]
    a = 0
    for w_start, w_spread, w_n in windows:
        for _ in range(w_n):
            a += 1
            t = w_start + rng.random() * w_spread
            addr, ua = f"proxy-{a}", "Mozilla/5.0 (Windows) Chrome"
            for p in range(pad_popular):
                ev.append((t, addr, ua, 1 + rng.randrange(20), "pad", addr))
                t += rng.lognormvariate(math.log(30), 0.5)
            for _ in range(per_addr):
                if k >= len(products):
                    break
                ev.append((t, addr, ua, products[k], "bot", addr))
                k += 1
                t += rng.lognormvariate(math.log(30), 0.5)
    return ev


EXTRA_ENV = {}


def run_spider(scenario, seed, fixed, days=4, inspect_every=600.0):
    rng = random.Random(seed)
    env = {"SPIDER_FLEET": "on" if fixed else "off", **EXTRA_ENV}
    sp = Spider(Policy(env))
    sealed = set()
    ev = shopper_events(rng, days)
    t0 = 2 * DAY + 3600 * 9                                  # attackers arrive on day 3, 09:00
    if scenario == "hydra":
        ev += hydra_events(rng, t0, 6 * 3600)
    elif scenario == "hydra_slow":
        ev += hydra_events(rng, t0, 72 * 3600)
        days = 6
        ev += [e for e in shopper_events(random.Random(seed + 99), 6) if e[0] >= 4 * DAY]
    elif scenario == "hydra_ramp":
        sched = [(DAY * (1 + d), 6 * 3600, n) for d, n in enumerate([30, 60, 120, 240, 550])]
        ev += hydra_events(rng, 0, 0, schedule=sched)
        days = 6
        ev += [e for e in shopper_events(random.Random(seed + 99), 6) if e[0] >= 4 * DAY]
    elif scenario == "hydra_padded":
        ev += hydra_events(rng, t0, 6 * 3600, pad_popular=3)
    elif scenario == "hydra_padded10":                      # analyst F1: pads past the old view-count test
        ev += hydra_events(rng, t0, 6 * 3600, pad_popular=10)
    elif scenario == "vantage_warm":                        # analyst F3: one long-lived control identity
        hv = hydra_events(rng, t0, 6 * 3600)
        ev += hv
        ev += [(2 * DAY + 600 * k, "control-warm", "Mozilla/5.0 (Mac) Safari", 2 + k % 20, "warmup", 0) for k in range(10)]
        ev += [(t + rng.uniform(2, 12) * 3600, "control-warm", "Mozilla/5.0 (Mac) Safari", prod, "control", 0)
               for (t, _, _, prod, kind, _) in hv if kind == "bot"]
    elif scenario == "notebook":                            # 2026-11-27 researcher scenario 2: no deliberate
        hv = hydra_events(rng, t0, 6 * 3600)                # re-fetch; a second, equally cold swarm member
        ev += hv                                            # opens the same product 0-2 h later and the
        ev += [(t + rng.uniform(0, 2) * 3600, f"member2-{i}", "Mozilla/5.0 (Windows) Chrome", prod, "control", i)
               for i, (t, _, _, prod, kind, _) in enumerate(hv) if kind == "bot"]   # notebook compares them
    elif scenario == "vantage":                             # researcher scenario 2
        hv = hydra_events(rng, t0, 6 * 3600)
        ev += hv
        ev += [(t + rng.uniform(2, 12) * 3600, f"control-{i}", "Mozilla/5.0 (Mac) Safari", prod, "control", i)
               for i, (t, _, _, prod, kind, _) in enumerate(hv) if kind == "bot"]
    elif scenario != "shoppers":
        raise SystemExit(f"unknown scenario {scenario}")
    ev.sort(key=lambda e: e[0])
    next_inspect = inspect_every
    stolen, fake_to_bot = set(), 0
    shopper_fake, shoppers_hit, shopper_views = 0, set(), 0
    bot_requests, first_flag = 0, None
    got_fake, ctrl_fake = set(), {}
    friction = EXTRA_ENV.get("SPIDER_GUARD_ACTION") == "friction"
    solved, shoppers_challenged, bot_challenges = set(), set(), 0
    for t, addr, ua, product, kind, who in ev:
        while t >= next_inspect:
            for f in sp.inspect(now=next_inspect):
                if f["rule"] == "fleet_tail":
                    first_flag = first_flag or f["t"]
                elif f["rule"] != "component_changed":
                    sealed.add(f["subject"])
            next_inspect += inspect_every
        if friction:
            # guard action "friction" (2026-11-27): while the guard is up, a cold address must solve a
            # proof-of-work once before ANY product page, then gets real pages; nobody is shown fakes
            guarded = False
            if fixed and t < sp.guard_until and sp._cold(addr, t) and addr not in solved:
                solved.add(addr)
                if kind == "shopper":
                    shoppers_challenged.add(who)
                elif kind in ("bot", "pad", "control"):
                    bot_challenges += 1
        else:
            guarded = fixed and sp.guarded(addr, product, now=t)
        sp.observe(addr, ua, product, t, shadowed=guarded)
        shadow = addr in sealed or guarded
        if guarded:
            sp.note_shadow(product, now=t)
        if kind == "warmup":
            continue
        if kind == "control":
            ctrl_fake[product] = shadow
            continue
        if kind == "shopper":
            shopper_views += 1
            if shadow:
                shopper_fake += 1
                shoppers_hit.add(who)
        else:
            bot_requests += 1
            if kind == "bot":
                if shadow:
                    fake_to_bot += 1
                    got_fake.add(product)
                else:
                    stolen.add(product)
    # A clean control identity re-fetched each product 2-12 h later; a fake the bot got is exposed
    # when the control was shown the real page.
    exposed = sum(1 for p in got_fake if p in ctrl_fake and not ctrl_fake[p])
    n_shoppers = len({e[5] for e in ev if e[4] == "shopper"})
    targeted = len({e[3] for e in ev if e[4] == "bot"})
    return {"scenario": scenario, "seed": seed, "fixed": fixed,
            "stolen_share": round(len(stolen) / targeted, 4) if targeted else None,
            "products_stolen": len(stolen), "fakes_fed_to_bots": fake_to_bot,
            "bot_requests": bot_requests,
            "detect_after_attack_s": round(first_flag - t0, 0) if first_flag and scenario in ("hydra", "hydra_padded", "hydra_slow", "vantage") else (round(first_flag, 0) if first_flag else None),
            "addresses_sealed": len(sealed),
            "shoppers": n_shoppers, "shoppers_shown_fakes": len(shoppers_hit),
            "shopper_fp_rate": round(len(shoppers_hit) / n_shoppers, 5),
            "shopper_fake_pages": shopper_fake, "shopper_views": shopper_views,
            "fakes_exposed_by_control": exposed,
            "fleet_trips": sum(1 for s in sp.slots if s[2]),
            "baseline_end": round(sp.baseline or 0, 1),
            "guard_action": "friction" if friction else "fakes",
            "shoppers_challenged": len(shoppers_challenged),
            "shopper_challenge_rate": round(len(shoppers_challenged) / n_shoppers, 5),
            "bot_challenges_solved": bot_challenges}


# ---------------- intel group ----------------

PLANTS = ["hercules-1", "hercules-2", "hercules-3"]


def receiver(fixed, keys, shared, me):
    if fixed:
        # the shop's own configuration path (analyst F4): per-plant keys from DARWIN_INTEL_KEYS,
        # INTEL_QUORUM's default with them, INTEL_ME required
        from darwin.judith import shop
        env = {intel.ENV_KEYS: ",".join(f"{k}={v.decode()}" for k, v in keys.items())}
        quorum = 2                                        # shop default when DARWIN_INTEL_KEYS is set
        return shop.make_verifier(env, quorum, me), intel.IntelStore(quorum=quorum, ttl=DAY)
    return intel.Verifier(shared, max_age=60), None


def run_intel(scenario, seed, fixed):
    rng = random.Random(seed)
    shared = intel.new_key().encode()
    keys = {p: intel.new_key().encode() for p in PLANTS}
    stolen_key = keys["hercules-1"] if fixed else shared         # attacker owns hercules-1
    ver, store = receiver(fixed, keys, shared, "judith")
    plain = set()                                                # release behaviour: a set, cap 200,000
    accepted = rejected = 0
    reasons = {}

    def deliver(env, now, to_store=True):
        nonlocal accepted, rejected
        try:
            d = ver.verify(env, now=now)
        except intel.IntelError as e:
            rejected += 1
            reasons[str(e)] = reasons.get(str(e), 0) + 1
            return
        accepted += 1
        ids = [x for x in d.get("identities", []) if isinstance(x, str)]
        if store is not None:
            store.add(env["sender"], ids, now)
        elif len(plain) + len(ids) <= 200_000:
            plain.update(ids)

    def known(ident, now):
        return store.known(ident, now) if store is not None else ident in plain

    def sign_as(sender, key, payload, now, to="judith"):
        return intel.sign(payload, key, sender=sender, now=now, to=to if fixed else None)

    now = 1000.0
    out = {"scenario": scenario, "seed": seed, "fixed": fixed}
    if scenario == "forged_witness":
        victims = [f"home-{rng.randrange(40000)}|Mozilla/5.0" for _ in range(3000)]
        for i in range(0, 3000, 500):
            chunk = victims[i:i + 500]
            deliver(sign_as("hercules-1", stolen_key, {"identities": chunk}, now), now)
            deliver(sign_as("hercules-2", stolen_key, {"identities": chunk}, now), now)   # claims a second witness
            now += 1
        bots = [f"proxy-{i}|python-httpx" for i in range(200)]       # really seen by two honest plants
        deliver(sign_as("hercules-2", keys["hercules-2"] if fixed else shared, {"identities": bots}, now), now)
        deliver(sign_as("hercules-3", keys["hercules-3"] if fixed else shared, {"identities": bots}, now), now)
        out["shoppers_sealed_1h"] = sum(known(v, now + 3600) for v in victims) / len(victims)
        out["shoppers_sealed_2d"] = sum(known(v, now + 2 * DAY) for v in victims) / len(victims)
        out["real_bots_known_1h"] = sum(known(b, now + 3600) for b in bots) / len(bots)
    elif scenario == "cross_replay":
        venus = intel.Verifier(keys=keys, me="venus") if fixed else intel.Verifier(shared)
        victims = [f"home-{rng.randrange(40000)}|Mozilla/5.0" for _ in range(50)]
        ok = 0
        for p in PLANTS[1:]:
            env = sign_as(p, keys[p] if fixed else shared, {"identities": victims}, now, to="venus")
            venus.verify(env, now=now)                   # delivered to Venus as intended
            before = accepted
            deliver(env, now + 5)                        # the same bytes, replayed into Judith 5 s later
            ok += accepted - before
        out["replays_accepted_by_judith"] = ok
        out["replays_tried"] = 2
    elif scenario == "intel_flood":
        for i in range(0, 260_000, 5000):                # junk, in max-size messages
            junk = [f"junk-{seed}-{j}" for j in range(i, i + 5000)]
            deliver(sign_as("hercules-1", stolen_key, {"identities": junk}, now), now)
            now += 0.5
        bots = [f"proxy-{i}|python-httpx" for i in range(500)]
        for p in PLANTS[1:]:
            deliver(sign_as(p, keys[p] if fixed else shared, {"identities": bots}, now), now)
        out["real_bots_known"] = sum(known(b, now + 60) for b in bots) / len(bots)
        out["store_size"] = len(store) if store is not None else len(plain)
    elif scenario == "echo_double":                      # researcher scenario 4c: one witness counted twice
        victims = [f"home-{rng.randrange(40000)}|Mozilla/5.0" for _ in range(100)]
        env = sign_as("hercules-2", keys["hercules-2"] if fixed else shared, {"identities": victims}, now)
        deliver(env, now)
        deliver(env, now + 1)                            # exact replay
        if store is None:
            out["shoppers_sealed"] = sum(known(v, now + 2) for v in victims) / len(victims)
            out["note"] = "release has no quorum: one honest report seals"
        else:
            out["shoppers_sealed"] = sum(known(v, now + 2) for v in victims) / len(victims)
    elif scenario == "pollution":                        # researcher scenario 3 via residential proxies
        # Swarm runs on real home devices (residential proxy exits). Honest Hercules plants see it and
        # honestly report address|UA. The household behind each exit shops with the same common UA.
        homes = [f"home-{i}" for i in rng.sample(range(40000), 2000)]
        ua = "Mozilla/5.0 (Windows) Chrome"
        ids = [f"{h}|{ua}" for h in homes]
        for p in PLANTS[1:]:
            deliver(sign_as(p, keys[p] if fixed else shared, {"identities": ids}, now), now)
        out["households_sealed_1h"] = sum(known(i, now + 3600) for i in ids) / len(ids)
        out["households_sealed_2d"] = sum(known(i, now + 2 * DAY) for i in ids) / len(ids)
    else:
        raise SystemExit(f"unknown scenario {scenario}")
    out.update(accepted=accepted, rejected=rejected, reject_reasons=reasons)
    return out


SPIDER_SCENARIOS = ["shoppers", "hydra", "hydra_slow", "hydra_ramp", "hydra_padded", "hydra_padded10", "vantage",
                    "vantage_warm", "notebook"]
INTEL_SCENARIOS = ["forged_witness", "cross_replay", "intel_flood", "echo_double", "pollution"]


def run(scenario, seed, fixed):
    if scenario in INTEL_SCENARIOS:
        return run_intel(scenario, seed, fixed)
    return run_spider(scenario, seed, fixed)


def main(argv):
    scen = argv[0] if argv else "all"
    seeds = int(argv[1]) if len(argv) > 1 and argv[1].isdigit() else 3
    fixed = "--fixed" in argv
    for a in argv:
        if a.startswith("SPIDER_") and "=" in a:
            k, v = a.split("=", 1)
            EXTRA_ENV[k] = v
    names = SPIDER_SCENARIOS + INTEL_SCENARIOS if scen == "all" else [scen]
    for name in names:
        for seed in range(seeds):
            print(json.dumps(run(name, seed, fixed)), flush=True)


if __name__ == "__main__":
    main(sys.argv[1:])

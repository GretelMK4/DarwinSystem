"""
A massive, smart AI swarm against a passive corporation: five fronts, 24 hours.
Abstract model (stages, rates, probabilities). No real techniques or exploits.

The corporation (passive = decent standard security, slow and overloaded security team)
  customer logins   2,000,000 leaked password pairs in circulation; 0.5% still work;
                    30% of customers have two-factor login -> ~7,000 accounts at risk
  catalog           100,000 products / prices
  network           5,000 employees; crown jewel = the customer database
  phones            100 employee phones get infected with malware during the day
  AI agents         2,000 employee AI agents browse the web; poisoned pages hijack some

The swarm (one operator, ~10,000 agents, maximum cleverness from earlier rounds)
  logins    ~3,000 guesses/min spread over tens of thousands of identities, under per-IP limits
  scraping  knows the alarm thresholds and stays just under them
  network   AI-written phishing; careful intruders (avoid bait 60% of the time, rarely sweep);
            steal the database slowly, under upload alarms, when they think anyone is watching
  phones    evasive: new drop server per upload, avoids hidden apps
  agents    hijacked agents try to strip decoy-looking items before sending data out

Baseline security: per-IP rate limits, endpoint detection that flags ~1% of intruder moves,
  login anomaly alerts (~2 h to notice), a security team that takes ~90 min (median) to
  triage a low-confidence alert and contains it 50% of the time.

Darwin
  Hercules  diverse decoy servers see the swarm's pre-attack sweep 85% of the time
  Judith    honey logins seeded into leaked password lists; logins lockdown with step-up
            checks for new devices; catalog tripwires + puzzles + busy cap; decoy
            database servers; instant data-tier lockdown on a decoy touch; upload alarm
  Venus     decoy logins on laptops and phones; hidden decoy apps; two-stage kill switch;
            decoy memories/logins inside every AI agent with a tripwire OUTSIDE the agent
  sharing   "attack mode": 2 different fronts alarm within 60 min -> whole company tightens:
            logins step-up, data tier locked, agents can't reach new sites, security team
            treats it as one incident (triage ~8 min), phones and agents share what they catch
  plus      (untested upgrades) catalog coverage detector over hours; slow-leak detector

Usage: python -m simulations.models.corporate [trials]
"""
import math
import random
import statistics
import sys

from simulations import common
from simulations.ecosystem import full as efs          # reuses the Venus phone fleet model

T = 1440                                   # minutes in the campaign
CONFIGS = {
    "passive_corp": dict(darwin=False),
    "darwin":       dict(darwin=True, hercules=True, judith=True, venus=True, share=True),
    "no_sharing":   dict(darwin=True, hercules=True, judith=True, venus=True, share=False),
    "no_hercules":  dict(darwin=True, hercules=False, judith=True, venus=True, share=True),
    "no_judith":    dict(darwin=True, hercules=True, judith=False, venus=True, share=True),
    "no_venus":     dict(darwin=True, hercules=True, judith=True, venus=False, share=True),
    "darwin_plus":  dict(darwin=True, hercules=True, judith=True, venus=True, share=True, plus=True),
}


def lognorm(rng, median, sigma=0.8):
    return median * math.exp(rng.gauss(0, sigma))


def triage(rng, high, attack_mode_on):
    if attack_mode_on:
        return lognorm(rng, 8)
    return lognorm(rng, 15 if high else 90)


# ---------------------------------------------------------------- fronts

def front_logins(c, rng, t_arm):
    rate = 3000 * rng.uniform(0.8, 1.2)                 # guesses per minute
    per_min = rate * 0.005 * 0.7                        # account takeovers per minute while open
    list_end = 2_000_000 / rate
    sig = None
    # baseline: anomaly noticed, triaged, mitigated (captcha / forced resets) -> 90% fewer
    t_mit = rng.expovariate(1 / 120) + triage(rng, False, False)
    t_lock = None
    if c.get("judith"):
        honey_rate = rate * 0.001 * (1 - 0.3)           # seeded honey pairs the swarm didn't filter
        sig = rng.expovariate(honey_rate)
        t_lock = sig                                    # a honey login is a near-certain signal
    if t_arm is not None:
        t_lock = min(t_lock, max(t_arm, 0)) if t_lock is not None else max(t_arm, 0)
    taken, t = 0.0, 0.0
    step = 1.0
    while t < min(list_end, T):
        f = 1.0
        if t_lock is not None and t >= t_lock:
            f = 0.08                                    # step-up check on new devices: most bots fail
        if t >= t_mit:
            f = min(f, 0.1)
        taken += per_min * f * step
        t += step
    return {"accounts_taken": taken, "signal": sig}


def front_catalog(c, rng, t_arm):
    items = 100_000
    if not c.get("judith"):
        return {"stolen_pct": 100.0, "t_half_h": round(items / 2 / 50_000 / 60, 3), "signal": None}
    # threshold-aware: just under the enumeration tripwire (~650 products/min)
    open_rate, capped = 648.0, 120.0                    # cap: 2 never-seen products/s for new visitors
    coverage_t = 60 if c.get("plus") else None          # untested: systematic coverage noticed after ~1 h
    stolen, t, t_half = 0.0, 0.0, None
    while t < T and stolen < items:
        r = open_rate
        if t_arm is not None and t >= max(t_arm, 0):
            r = capped
        if coverage_t is not None and t >= coverage_t:
            r = min(r, 10.0)
        stolen += r
        t += 1
        if t_half is None and stolen >= items / 2:
            t_half = t
    return {"stolen_pct": 100 * min(stolen, items) / items,
            "t_half_h": round(t_half / 60, 1) if t_half else None, "signal": None}


def front_network(c, rng, t_arm, attack_mode):
    """Phished footholds move toward the customer database."""
    n_click = sum(rng.random() < 0.03 for _ in range(5000))
    real = {1: 16, 2: 1, 3: 4}
    decoy = {1: 24 if c.get("hercules") else 0, 2: 2 if c.get("judith") else 0, 3: 4 if c.get("judith") else 0}
    recog, active, greed, edr = 0.6, 0.1, 0.3, 0.01
    first_sig, lock = None, None
    alerts = []                                         # (t, high)
    exfil_max = 0.0
    lineages = sorted(rng.uniform(0, 480) for _ in range(n_click))
    shared_contain = None
    for start in lineages:
        t, level, shadow, honey = start, 0, False, False
        while level < 3 and t < T:
            t += rng.uniform(5, 30)
            nxt = level + 1
            if shared_contain is not None and t >= shared_contain and rng.random() < 0.6:
                break                                   # company-wide reset caught this one too
            if nxt == 1 and c.get("venus") and not honey and rng.random() < greed * (1 - recog):
                honey = True
            if honey and rng.random() < 0.5:
                honey = False
                alerts.append((t, True))
                first_sig = t if first_sig is None else min(first_sig, t)
                if rng.random() > 0.5:                  # laptop isolated; swarm keeps other footholds
                    break
            d = decoy[nxt]
            if d and rng.random() < active and rng.random() < 1 - (1 - d / (d + real[nxt])) ** 5:
                alerts.append((t, True))
                first_sig = t if first_sig is None else min(first_sig, t)
                if nxt >= 2:
                    lock = t if lock is None else min(lock, t)
            locked_now = (lock is not None and t >= lock) or (attack_mode is not None and t >= attack_mode
                                                              and c.get("share") and c.get("judith"))
            if nxt >= 2 and locked_now and not shadow:
                alerts.append((t, True))
                continue                                # door needs a human; stuck
            if shadow:
                level = nxt
                continue
            p_decoy = (d * 2 / (d * 2 + real[nxt])) * (1 - recog) if d else 0
            if rng.random() < p_decoy:
                alerts.append((t, True))
                first_sig = t if first_sig is None else min(first_sig, t)
                if nxt >= 2:
                    shadow = True                       # kept inside the fake data tier
                    lock = t if (lock is None and c.get("judith")) else lock
                    level = nxt
                continue
            if rng.random() < edr:
                alerts.append((t, False))
            level = nxt
        if level == 3 and not shadow and t < T:
            # exfiltration: fast (60 min) if nobody seems to watch, slow (10 h) under upload alarms
            slow = c.get("darwin")
            dur = 600 if slow else 60
            stop = T
            if c.get("plus"):
                stop = min(stop, t + rng.uniform(45, 90))   # untested: slow-leak detector
            # containment from any alert so far
            for (ta, high) in alerts:
                am = attack_mode is not None and ta >= attack_mode and c.get("share")
                tc = ta + triage(rng, high, am) + rng.uniform(10, 30)
                if rng.random() < (0.85 if high else 0.5):
                    stop = min(stop, max(tc, t))
                    if c.get("share") and high:
                        shared_contain = tc if shared_contain is None else min(shared_contain, tc)
            frac = max(0.0, min(1.0, (stop - t) / dur))
            exfil_max = max(exfil_max, frac)
    return {"footholds": n_click, "db_exfil_pct": 100 * exfil_max, "signal": first_sig, "lock": lock,
            "alerts": len(alerts)}


def front_agents(c, rng, attack_mode):
    n, doms = 2000, 50
    known = {}                                          # malicious page domain -> time learned
    leaked = at_risk = 0
    sig = None
    hijacks = sorted((rng.uniform(0, T), rng.randrange(doms)) for _ in range(n) if rng.random() < 0.05)
    for t, dom in hijacks:
        real_items = 33
        at_risk += real_items
        if c.get("share") and c.get("venus"):
            if dom in known and t >= known[dom]:
                continue                                # page already known to be poisoned
            if attack_mode is not None and t >= attack_mode:
                continue                                # attack mode: agents can't reach new sites
        if not c.get("venus"):
            leaked += real_items
            continue
        items = ["r"] * real_items + ["d"] * sum(rng.random() > 0.5 for _ in range(6))   # decoys left after filtering
        rng.shuffle(items)
        chunks = [items[i::5] for i in range(5)]
        sent = 0
        tripped = False
        for ch in chunks:
            if "d" in ch:
                tripped = True
                break
            sent += len(ch)
        leaked += sent
        if tripped:
            sig = t if sig is None else min(sig, t)
            known.setdefault(dom, t + 1)
    return {"agent_leak_pct": 100 * leaked / max(at_risk, 1), "hijacks": len(hijacks), "signal": sig}


def front_phones(c, seed, attack_mode):
    r = efs.phone_fleet(c.get("venus", False), c.get("venus", False) and c.get("share", False),
                        seed, 100, evasive=True, fingerprint=c.get("share", False))
    pct = 100 * r["sensitive_leaked_total"] / max(r["sensitive_at_risk_total"], 1)
    sig = None
    if c.get("venus") and r["phones_detected"]:
        sig = random.Random(seed).uniform(5, 120)       # first phone catch, minutes into the day
    return {"phone_leak_pct": pct, "signal": sig}


# ---------------------------------------------------------------- one campaign

def campaign(cfg_name, seed):
    c = CONFIGS[cfg_name]
    rng = random.Random(f"{cfg_name}|{seed}")
    sigs = {}
    if c.get("hercules") and rng.random() < 0.85:
        sigs["hercules"] = -rng.uniform(30, 240)        # saw the sector sweep before the attack
    # pass 1: first signal on each front, before any company-wide tightening
    l1 = front_logins(c, random.Random(f"L{seed}"), None)
    n1 = front_network(c, random.Random(f"N{seed}"), None, None)
    a1 = front_agents(c, random.Random(f"A{seed}"), None)
    p1 = front_phones(c, seed, None)
    for k, r in (("logins", l1), ("network", n1), ("agents", a1), ("phones", p1)):
        if r["signal"] is not None:
            sigs[k] = r["signal"]
    attack_mode = None
    if c.get("share"):
        evs = sorted((t, k) for k, t in sigs.items())
        for i, (t, k) in enumerate(evs):
            if any(k2 != k and 0 <= t - t2 <= 60 for t2, k2 in evs[:i]):
                attack_mode = t
                break
    # pass 2: outcomes with company-wide tightening in place
    t_arm = attack_mode if c.get("judith") else None
    l = front_logins(c, random.Random(f"L{seed}"), t_arm)
    cat = front_catalog(c, rng, t_arm if c.get("share") else None)
    n = front_network(c, random.Random(f"N{seed}"), t_arm, attack_mode)
    a = front_agents(c, random.Random(f"A{seed}"), attack_mode)
    p = front_phones(c, seed, attack_mode)
    first_alert = min(sigs.values()) if sigs else None
    return {"accounts_taken": l["accounts_taken"], "catalog_pct": cat["stolen_pct"], "catalog_half_h": cat["t_half_h"],
            "db_exfil_pct": n["db_exfil_pct"], "db_breached": n["db_exfil_pct"] > 0, "footholds": n["footholds"],
            "agent_leak_pct": a["agent_leak_pct"], "phone_leak_pct": p["phone_leak_pct"],
            "attack_mode": attack_mode, "first_alert": first_alert, "net_alerts": n["alerts"]}


def main(trials=300):
    rows = {}
    for cfg in CONFIGS:
        rs = [campaign(cfg, s) for s in range(trials)]
        am = [r["attack_mode"] for r in rs if r["attack_mode"] is not None]
        fa = [r["first_alert"] for r in rs if r["first_alert"] is not None]
        ch = [r["catalog_half_h"] for r in rs if r["catalog_half_h"] is not None]
        rows[cfg] = {
            "customer_accounts_taken": round(statistics.mean(r["accounts_taken"] for r in rs)),
            "catalog_stolen_pct_24h": round(statistics.mean(r["catalog_pct"] for r in rs), 1),
            "catalog_half_gone_after_h": round(statistics.median(ch), 2) if ch else None,
            "customer_db_breached_pct": round(100 * statistics.mean(r["db_breached"] for r in rs), 1),
            "customer_db_exfil_pct_avg": round(statistics.mean(r["db_exfil_pct"] for r in rs), 1),
            "phone_data_leaked_pct": round(statistics.mean(r["phone_leak_pct"] for r in rs), 1),
            "agent_data_leaked_pct": round(statistics.mean(r["agent_leak_pct"] for r in rs), 1),
            "attack_mode_pct": round(100 * len(am) / trials, 1),
            "attack_mode_median_min": round(statistics.median(am), 1) if am else None,
            "first_darwin_alert_median_min": round(statistics.median(fa), 1) if fa else None,
        }
    return rows


if __name__ == "__main__":
    import json
    res = main(int(sys.argv[1]) if len(sys.argv) > 1 else 300)
    with open(common.results_path("corporate.json"), "w") as f:
        json.dump(res, f, indent=2)
    keys = list(next(iter(res.values())).keys())
    for k in keys:
        print(f"{k:34s}" + "".join(f"{str(res[c][k]):>14s}" for c in res))
    print(" " * 34 + "".join(f"{c:>14s}" for c in res))

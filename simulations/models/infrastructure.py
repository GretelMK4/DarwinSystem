"""
Darwin System vs. an attack on a critical-infrastructure network (abstract model).

This is a deliberately ABSTRACT model: zones, hosts, stages and probabilities.
It contains no real exploits, protocols or control commands. It exists to test
the defensive logic: does Darwin stop the attack, or at least warn humans
early enough to act?

The facility
  internet-facing      remote-access gateway, web, mail
  corporate (IT)       200 workstations, 10 servers, 4 admin machines, 2 domain controllers
  boundary             1 jump host (the only door into the control network)
  control network (OT) 4 engineering workstations, 3 operator screens, 30 controllers
  "Impact" = an unauthorized command reaches a REAL controller.

Conventional security (always on, the baseline)
  zone firewalls; endpoint detection that flags a small share of malicious
  actions; a human security team: low-confidence alerts take ~45 min to triage
  (median), then 10-30 min to contain; containment works 60% of the time.

The Darwin System (on top)
  Hercules  8 decoy servers on the internet + 12 decoy servers inside IT.
            Any contact = alert. Nobody legitimate ever talks to them.
  Venus     decoy files / decoy logins on every workstation. Using one = alert,
            and that workstation is isolated on the spot.
  Judith    fake admin logins in real file shares; a decoy jump host; a decoy
            control network (2 engineering workstations, 10 controllers)
            planted in real engineering documents. An attacker that touches the
            decoy control network is kept INSIDE it (one-way): it keeps
            "attacking" decoys. 2 different alarm signals within 60 min =
            LOCKDOWN: every new session into the control network needs a human's
            approval.
  sharing   all signals feed one picture: lockdown counts signals from every
            plant; high-confidence alerts are triaged in ~8 min (median) and
            containment works 90% of the time.

Attackers (AI agent swarms, modelled by behaviour, not technique)
  blitz        fast, noisy, many footholds; sweeps networks; grabs everything
  stealth      patient (15-90 min per move), mostly passive, picky
  aware        knows deception exists: avoids bait 85% of the time, never sweeps
  stolen_creds walks in through remote access as a real engineer; already holds
               working logins for the jump host and control network

Usage: python -m simulations.models.infrastructure [trials]
All behaviours and numbers are assumptions chosen to test the logic.
"""
import json
import math
import random
import statistics
import sys

from simulations import common

T_MAX = 7 * 24 * 60                       # one week, in minutes
WINDOW = 60                               # minutes: 2 different signals inside this = lockdown

ATTACKERS = {
    "blitz":        dict(step=(0.5, 3), active=1.0, k=50, recog=0.10, greed=0.9, edr=0.05, backup=0.8,
                         ext=0.9, cred_find=0.5, start=0, burst=10),
    "stealth":      dict(step=(15, 90), active=0.2, k=3, recog=0.50, greed=0.4, edr=0.01, backup=0.4,
                         ext=0.3, cred_find=0.25, start=0, burst=3),
    "aware":        dict(step=(15, 90), active=0.0, k=0, recog=0.85, greed=0.15, edr=0.01, backup=0.5,
                         ext=0.1, cred_find=0.25, start=0, burst=1),
    "stolen_creds": dict(step=(5, 30), active=0.0, k=0, recog=0.60, greed=0.2, edr=0.003, backup=0.0,
                         ext=0.0, cred_find=1.0, start=1, burst=2),
}

DEFENSES = {
    "baseline":       dict(hercules=False, venus=False, judith=False, share=False),
    "darwin":         dict(hercules=True,  venus=True,  judith=True,  share=True),
    "no_hercules":    dict(hercules=False, venus=True,  judith=True,  share=True),
    "no_venus":       dict(hercules=True,  venus=False, judith=True,  share=True),
    "no_judith":      dict(hercules=True,  venus=True,  judith=False, share=True),
    "no_sharing":     dict(hercules=True,  venus=True,  judith=True,  share=False),
    # Darwin+: inside the boundary / control network, ONE touch of a decoy = instant lockdown
    "darwin_plus":    dict(hercules=True,  venus=True,  judith=True,  share=True, instant_ot=True),
    "darwin_dense":   dict(hercules=True,  venus=True,  judith=True,  share=True, instant_ot=True, dense=True),
}

# real vs decoy hosts at each step of the path
REAL = {1: 16, 2: 1, 3: 4, 4: 30}         # IT credential sources, jump host, eng workstations, controllers
DECOY = {1: 12, 2: 1, 3: 2, 4: 10}
DENSE = {1: 24, 2: 2, 3: 4, 4: 30}       # Darwin dense: as many decoys as real hosts in the control network
ATTRACT = 2.0                             # decoys are made to look a bit more tempting than real hosts


def lognorm(rng, median, sigma=0.8):
    return median * math.exp(rng.gauss(0, sigma))


class Trial:
    def __init__(self, att, d, rng):
        self.a, self.d, self.rng = ATTACKERS[att], DEFENSES[d], rng
        self.dec = DENSE if self.d.get("dense") else DECOY
        self.alerts = []                  # (t, source, high_confidence, knows_foothold)
        self.signals = []                 # (t, kind) for lockdown
        self.lockdown = None
        self.contained_at = None
        self.containment_attempts = []    # times at which a containment attempt lands

    # ---- defence side ----
    def alert(self, t, source, high, foothold=True):
        self.alerts.append((t, source, high))
        rng = self.rng
        if source == "ext_recon":
            return                        # a sector warning: no foothold to contain yet
        fast = high and self.d["share"]
        triage = lognorm(rng, 8 if fast else (20 if high else 45))
        contain = t + triage + rng.uniform(10, 30)
        p = 0.9 if fast else (0.75 if high else 0.6)
        if foothold and rng.random() < p:
            if self.contained_at is None or contain < self.contained_at:
                self.contained_at = contain

    def signal(self, t, kind):
        """A Darwin signal. Lockdown needs 2 different kinds inside WINDOW."""
        if not self.d["judith"]:
            return
        if not self.d["share"] and not kind.startswith("judith"):
            return                        # without sharing, Judith only hears herself
        self.signals.append((t, kind))
        if self.lockdown is None and kind == "judith_decoy" and self.d.get("instant_ot"):
            self.lockdown = t
        if self.lockdown is None:
            kinds = {k for tt, k in self.signals if t - tt <= WINDOW}
            if len(kinds) >= 2:
                self.lockdown = t

    def locked(self, t):
        return self.lockdown is not None and t >= self.lockdown

    def stopped(self, t):
        return self.contained_at is not None and t >= self.contained_at

    # ---- attacker side ----
    def run(self):
        a, d, rng = self.a, self.d, self.rng
        res = {"impact": False, "t_impact": None, "deceived": False, "evicted": False,
               "blocked_by_lockdown": False}
        if d["hercules"] and rng.random() < a["ext"]:                   # surveying the sector first
            t_ext = -rng.uniform(30, 600)
            self.alert(t_ext, "ext_recon", False, foothold=False)
            self.signal(t_ext, "hercules_ext")
        t, level, shadow = 0.0, a["start"], False
        honey_held = real_cred = level >= 1
        honey_held = False
        footholds = 1 + (rng.random() < a["backup"]) * rng.randint(1, 4)
        while level < 4 and t < T_MAX:
            t += rng.uniform(*a["step"])
            if self.stopped(t):
                break
            nxt = level + 1
            # 1. harvesting credentials (only needed to get out of IT)
            if nxt == 1:
                if (d["venus"] or d["judith"]) and not honey_held and rng.random() < a["greed"] * (1 - a["recog"]):
                    honey_held = True
                if rng.random() < a["cred_find"]:
                    real_cred = True
            # 2. discovery: sweeping the zone touches decoy hosts
            decoys_here = self.dec[nxt] if ((nxt == 1 and d["hercules"]) or (nxt >= 2 and d["judith"])) else 0
            if decoys_here and rng.random() < a["active"]:
                dens = decoys_here / (decoys_here + REAL[nxt])
                if rng.random() < 1 - (1 - dens) ** a["k"]:
                    kind = "hercules_int" if nxt == 1 else "judith_decoy"
                    self.alert(t, kind, True)
                    self.signal(t, kind)
                    if nxt == 1 and rng.random() > a["backup"]:          # swept from an isolated host
                        res["evicted"] = True
                        break
            # 3. trying a stolen login: a decoy login gives it away
            if honey_held and nxt <= 2 and rng.random() < 0.5:
                honey_held = False
                kind = "venus" if (d["venus"] and (not d["judith"] or rng.random() < 0.5)) else "judith_cred"
                self.alert(t, kind, True)
                self.signal(t, kind)
                if kind == "venus":                                       # that workstation is isolated
                    footholds -= 1
                    if footholds <= 0:
                        res["evicted"] = True
                        break
            # 4. lockdown: new sessions into the boundary / control network need a human
            if nxt >= 2 and self.locked(t) and not shadow:
                res["blocked_by_lockdown"] = True
                self.alert(t, "lockdown_block", True)
                continue                                                  # stuck at the door
            # 5. choose where to go next
            if shadow:
                level = nxt                                               # it's all decoys from here
                continue
            p_decoy = 0.0
            if decoys_here:
                share = decoys_here * ATTRACT / (decoys_here * ATTRACT + REAL[nxt])
                p_decoy = share * (1 - a["recog"])
            if nxt == 4:                                                  # sends commands to several controllers
                for _ in range(a["burst"]):
                    if self.locked(t):
                        res["blocked_by_lockdown"] = True
                        break
                    if rng.random() < p_decoy:
                        self.alert(t, "judith_decoy", True)
                        self.signal(t, "judith_decoy")
                        t += 0.2
                        continue
                    res["impact"], res["t_impact"] = True, t
                    break
                if res["impact"]:
                    break
                if self.locked(t):
                    continue
                continue
            if rng.random() < p_decoy:
                kind = "hercules_int" if nxt == 1 else "judith_decoy"
                self.alert(t, kind, True)
                self.signal(t, kind)
                if nxt >= 2:                                              # one-way: kept in the fake control network
                    shadow = True
                    res["deceived"] = True
                    level = nxt
                else:
                    footholds -= 1
                    if footholds <= 0:
                        res["evicted"] = True
                        break
                continue
            # 6. real target
            if nxt == 1 and not real_cred:
                continue
            if rng.random() < a["edr"] * (3 if a["active"] else 1):
                self.alert(t, "edr", False)
            level = nxt
        if shadow and not res["impact"]:
            res["deceived"] = True
        res["contained"] = self.stopped(res["t_impact"] if res["impact"] else T_MAX) and not res["impact"]
        first = min((x[0] for x in self.alerts), default=None)
        first_real = min((x[0] for x in self.alerts if x[1] != "ext_recon"), default=None)
        res.update(first_alert=first, first_intrusion_alert=first_real, lockdown=self.lockdown,
                   contained_at=self.contained_at, stopped=not res["impact"])
        return res


def normal_week(d, rng):
    """False alarms in a normal week of operations."""
    D = DEFENSES[d]
    sig = []
    alerts = 0
    if D["venus"]:
        for _ in range(sum(rng.random() < 0.01 for _ in range(200))):  # a user opens a decoy by accident
            sig.append((rng.uniform(0, T_MAX), "venus"))
    if D["hercules"] and rng.random() < 0.05:                             # a misconfigured script touches a decoy
        sig.append((rng.uniform(0, T_MAX), "hercules_int"))
    if D["judith"] and rng.random() < 0.03:                               # an engineer clicks a decoy entry
        sig.append((rng.uniform(0, T_MAX), "judith_decoy"))
    alerts = len(sig)
    sig.sort()
    lockdowns, delayed = 0, 0
    if D["judith"]:
        use = sig if D["share"] else [s for s in sig if s[1].startswith("judith")]
        for i, (t, k) in enumerate(use):
            if (D.get("instant_ot") and k == "judith_decoy") or \
                    any(k2 != k and 0 <= t - t2 <= WINDOW for t2, k2 in use[:i]):
                lockdowns += 1
                clear = lognorm(rng, 15)                                  # humans check and lift it
                delayed += sum(rng.random() < clear / (24 * 60) for _ in range(40))   # 40 OT sessions a day
    return alerts, lockdowns, delayed


def main(trials=500):
    out = {"attacks": {}, "normal_week": {}}
    for att in ATTACKERS:
        out["attacks"][att] = {}
        for d in DEFENSES:
            rs = [Trial(att, d, random.Random(f"{att}|{d}|{s}")).run() for s in range(trials)]
            imp = [r for r in rs if r["impact"]]
            alerted_first = [r for r in imp if r["first_intrusion_alert"] is not None
                             and r["first_intrusion_alert"] < r["t_impact"]]
            leads = [r["t_impact"] - r["first_intrusion_alert"] for r in alerted_first]
            stopped = [r for r in rs if not r["impact"]]
            out["attacks"][att][d] = {
                "impact_pct": round(100 * len(imp) / trials, 1),
                "stopped_pct": round(100 * len(stopped) / trials, 1),
                "  by_lockdown_pct": round(100 * sum(r["blocked_by_lockdown"] and not r["impact"] for r in rs) / trials, 1),
                "  deceived_in_fake_control_network_pct": round(100 * sum(r["deceived"] and not r["impact"] for r in rs) / trials, 1),
                "  contained_by_humans_pct": round(100 * sum(r["contained"] for r in rs) / trials, 1),
                "  evicted_by_isolation_pct": round(100 * sum(r["evicted"] and not r["impact"] for r in rs) / trials, 1),
                "humans_alerted_before_impact_pct_of_impacts": round(100 * len(alerted_first) / max(len(imp), 1), 1),
                "median_warning_before_impact_min": round(statistics.median(leads), 1) if leads else None,
                "median_time_to_impact_min": round(statistics.median(r["t_impact"] for r in imp), 1) if imp else None,
                "median_first_alert_min": round(statistics.median(r["first_intrusion_alert"] for r in rs
                                                                  if r["first_intrusion_alert"] is not None), 1)
                if any(r["first_intrusion_alert"] is not None for r in rs) else None,
                "pct_with_early_sector_warning": round(100 * sum(r["first_alert"] is not None and r["first_alert"] < 0
                                                                 for r in rs) / trials, 1),
            }
    for d in DEFENSES:
        wk = [normal_week(d, random.Random(s)) for s in range(trials * 4)]
        out["normal_week"][d] = {"false_alerts": round(statistics.mean(w[0] for w in wk), 2),
                                 "false_lockdowns": round(statistics.mean(w[1] for w in wk), 3),
                                 "engineer_sessions_delayed": round(statistics.mean(w[2] for w in wk), 3)}
    with open(common.results_path("infrastructure.json"), "w") as f:
        json.dump(out, f, indent=2)
    return out


if __name__ == "__main__":
    res = main(int(sys.argv[1]) if len(sys.argv) > 1 else 500)
    print("NORMAL WEEK:", json.dumps(res["normal_week"]))
    for att, rows in res["attacks"].items():
        print(f"\n== {att}")
        for d, r in rows.items():
            print(f"  {d:12s} impact {r['impact_pct']:5.1f}% | lockdown {r['  by_lockdown_pct']:5.1f} deceived "
                  f"{r['  deceived_in_fake_control_network_pct']:5.1f} contained {r['  contained_by_humans_pct']:5.1f} "
                  f"evicted {r['  evicted_by_isolation_pct']:5.1f} | alerted-before-impact "
                  f"{r['humans_alerted_before_impact_pct_of_impacts']:5.1f}% lead {r['median_warning_before_impact_min']} "
                  f"| t_impact {r['median_time_to_impact_min']} first_alert {r['median_first_alert_min']} "
                  f"sector_warn {r['pct_with_early_sector_warning']}%")

"""
Darwin vs. real, documented attacks: a tabletop replay.

Each case encodes the publicly documented path of a real attack: how the
attackers got in, how long they stayed, what they did, and when the victim
actually found out. At each stage we mark where a Darwin trap could have fired
and give it a probability RANGE. Those ranges are our estimates, informed by the
earlier simulations; they are not measurements. Each replay samples from the
ranges, so the output shows a spread, not a single guess.

Response model
  Darwin fires -> automatic action (isolate a host, lock a tier, freeze a session)
  that halts the attacker with probability `auto` (they may hold other footholds),
  plus a human response after triage (high-confidence alert, median 1 h) that
  works with probability `human` (lower where the real victim ignored alerts).

Damage
  "event"  damage happens at one moment (ransomware): prevented if stopped first
  "window" damage builds up over a period (card theft, data theft): partial
  "sweep"  ransomware encrypting servers one by one; decoy servers mixed in

Usage: python -m simulations.models.real_attacks_replay [replays]
"""
import math
import random
import statistics
import sys

H = 1.0           # time unit: hours after the attackers got in
D = 24.0

CASES = [
    dict(
        name="Colonial Pipeline (2021)",
        facts="Old unused VPN account, leaked password, no two-factor; ~8 days inside; ~100 GB stolen; "
              "ransomware May 7; found when a control-room worker saw the ransom note.",
        real_detect=8 * D, damage=[("event", "ransomware", 8 * D), ("window", "data theft (assumed last day)", 7 * D, 8 * D)],
        hooks=[("decoy server/share touched during network recon", (0.4, 0.75), (2, 6 * D), "Hercules/Judith"),
               ("decoy login dumped from a laptop and tried", (0.35, 0.65), (1 * D, 6 * D), "Venus"),
               ("~100 GB upload trips the upload alarm", (0.5, 0.85), (7 * D, 8 * D), "Venus/Judith")],
        auto=(0.6, 0.85), human=(0.7, 0.9)),
    dict(
        name="Change Healthcare (2024)",
        facts="Stolen login to a remote-access portal with no two-factor; 9 days moving through systems "
              "and stealing data; ransomware Feb 21; found when the ransomware hit.",
        real_detect=9 * D, damage=[("event", "ransomware", 9 * D), ("window", "data theft (assumed days 3-8)", 3 * D, 8.5 * D)],
        hooks=[("decoy server/share touched during network recon", (0.4, 0.75), (2, 7 * D), "Hercules/Judith"),
               ("decoy login dumped and tried", (0.35, 0.65), (1 * D, 7 * D), "Venus"),
               ("large uploads trip the upload alarm", (0.45, 0.8), (3 * D, 8.5 * D), "Venus/Judith")],
        auto=(0.6, 0.85), human=(0.7, 0.9)),
    dict(
        name="MGM Resorts (2023)",
        facts="10-minute call to the IT help desk gave admin access to identity systems; unusual activity "
              "seen the next day; outages from day 2; ~100 virtualization hosts encrypted; 6 TB claimed stolen.",
        real_detect=1 * D, damage=[("sweep", "virtualization hosts encrypted", 2 * D, 100, 20),
                                   ("window", "data theft", 4, 2 * D)],
        hooks=[("decoy admin accounts in the identity system used", (0.2, 0.5), (1, 1 * D), "Judith"),
               ("6 TB upload trips the upload alarm", (0.5, 0.85), (4, 2 * D), "Venus/Judith")],
        auto=(0.6, 0.85), human=(0.6, 0.85)),
    dict(
        name="Target (2013)",
        facts="HVAC vendor's stolen login; ~2 months inside; card-stealing malware pushed to registers "
              "Nov 15-28; ~40M cards; security alerts fired but were not acted on; the Justice Dept told Target Dec 12.",
        real_detect=88 * D, damage=[("window", "cards stolen", 73 * D, 91 * D)],
        hooks=[("decoy server touched while mapping the network", (0.4, 0.8), (2, 58 * D), "Hercules/Judith"),
               ("malware pushed onto decoy registers", (0.85, 0.98), (61 * D, 62 * D), "Judith"),
               ("card data shipped out trips the upload alarm", (0.4, 0.75), (73 * D, 91 * D), "Venus/Judith")],
        auto=(0.6, 0.85), human=(0.3, 0.5)),
    dict(
        name="Equifax (2017)",
        facts="Unpatched web server; found a file of database passwords stored in plain text; ~9,000 queries "
              "across dozens of databases over 76 days; 145M people; found when an expired certificate was fixed.",
        real_detect=76 * D, damage=[("window", "records stolen (assumed steady)", 2 * D, 76 * D)],
        hooks=[("decoy database logins planted in the plain-text password file get used", (0.85, 0.97), (1 * D, 7 * D), "Judith/Venus"),
               ("decoy databases / honey records queried", (0.6, 0.9), (2 * D, 20 * D), "Judith"),
               ("slow query pattern caught by a coverage detector (untested)", (0.1, 0.3), (7 * D, 76 * D), "Judith+")],
        auto=(0.6, 0.85), human=(0.7, 0.9)),
    dict(
        name="Snowflake customers (2024), per victim",
        facts="Logins stolen by password-stealing malware, some years old, no two-factor; ~165 organizations; "
              "list tables, copy whole tables, download; discovered when stolen data surfaced for sale.",
        real_detect=30 * D, damage=[("window", "tables copied and downloaded", 1, 12)],
        hooks=[("decoy tables with high-value names copied", (0.6, 0.9), (0.2, 3), "Judith"),
               ("bulk 'list everything, copy everything' trips enumeration", (0.5, 0.8), (0.2, 4), "Judith"),
               ("download of staged files trips the upload alarm", (0.5, 0.8), (1, 12), "Judith")],
        auto=(0.7, 0.9), human=(0.7, 0.9)),
    dict(
        name="AI-orchestrated espionage, GTG-1002 (2025), per target",
        facts="An AI agent did 80-90% of the work against ~30 targets, often several requests per second; "
              "harvested logins (sometimes hallucinated); a few intrusions succeeded; detected by the AI provider.",
        real_detect=3 * D, damage=[("window", "data extracted (assumed hours 2-24)", 2, 24)],
        hooks=[("request bursts trip the traffic tripwire", (0.75, 0.95), (0.05, 1), "Judith"),
               ("harvested decoy logins get used", (0.7, 0.9), (0.5, 6), "Venus/Judith"),
               ("decoy servers touched during automated recon", (0.6, 0.9), (0.1, 4), "Hercules/Judith")],
        auto=(0.7, 0.9), human=(0.7, 0.9)),
]


def lognorm(rng, median, sigma=0.8):
    return median * math.exp(rng.gauss(0, sigma))


def replay(case, rng):
    fires = []
    for label, (lo, hi), (t0, t1), comp in case["hooks"]:
        if rng.random() < rng.uniform(lo, hi):
            fires.append((rng.uniform(t0, t1), label, comp))
    fires.sort()
    first = fires[0] if fires else None
    stop = math.inf
    p_auto = rng.uniform(*case["auto"])
    p_human = rng.uniform(*case["human"])
    for t, label, comp in fires:
        if rng.random() < p_auto:
            stop = min(stop, t + 1 / 60)
        if rng.random() < p_human:
            stop = min(stop, t + lognorm(rng, 1.0) + rng.uniform(0.2, 0.5))
    harm = []
    for d in case["damage"]:
        kind = d[0]
        if kind == "event":
            harm.append(0.0 if stop < d[2] else 1.0)
        elif kind == "window":
            a, b = d[2], d[3]
            harm.append(max(0.0, min(1.0, (stop - a) / (b - a))) if stop < math.inf else 1.0)
        elif kind == "sweep":
            t_enc, n_real, n_decoy = d[2], d[3], d[4]
            if stop < t_enc:
                harm.append(0.0)
            else:   # encryption hits hosts in random order; first decoy hit = instant lockdown
                order = ["r"] * n_real + ["d"] * n_decoy
                rng.shuffle(order)
                k = order.index("d") if "d" in order else n_real
                harm.append(k / n_real if rng.random() < p_auto else 1.0)
    return first, stop, harm


def main(n=5000):
    for case in CASES:
        rs = [replay(case, random.Random(f"{case['name']}|{i}")) for i in range(n)]
        firsts = [r[0][0] for r in rs if r[0]]
        comps = {}
        for r in rs:
            if r[0]:
                comps[r[0][2]] = comps.get(r[0][2], 0) + 1
        first_dmg = min(d[2] for d in case["damage"])
        before = sum(1 for r in rs if r[0] and r[0][0] < first_dmg) / n
        print(f"\n== {case['name']}")
        print(f"   documented: {case['facts']}")
        print(f"   real discovery: {case['real_detect'] / D:.1f} days after entry")
        print(f"   Darwin alerts at all: {100 * len(firsts) / n:.0f}%   before damage begins: {100 * before:.0f}%")
        if firsts:
            print(f"   first Darwin alert: median {statistics.median(firsts):.1f} h "
                  f"({statistics.median(firsts) / D:.2f} days) after entry; most often from {max(comps, key=comps.get)}")
        for j, d in enumerate(case["damage"]):
            vals = [r[2][j] for r in rs]
            print(f"   {d[1]}: avg {100 * statistics.mean(vals):.0f}% of the real damage "
                  f"(prevented entirely in {100 * sum(v == 0 for v in vals) / n:.0f}% of replays)")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 5000)

"""
Darwin vs. real, documented attacks: a tabletop replay.

Each case encodes the publicly documented path of a real attack: how the
attackers got in, how long they stayed, what they did, and when the victim
actually found out. At each stage we mark where a Darwin trap could have fired
and give it a probability RANGE. Each replay samples from the ranges, so the
output shows a spread, not a single guess.

What is fact and what is not
  - `facts` and the timings marked "documented" were checked on 23 November
    2026 against the sources listed with each case. Where the sources are an
    attacker's own claim or unnamed people, the text says so.
  - `assumed` lists what the public record does not give and we filled in.
  - Every probability (each hook's chance of firing, and the `auto` and
    `human` response rates) is the authors' estimate. None was measured, and
    Darwin was not present at any of these incidents. The output is a
    structured guess about where deception could have helped, not evidence
    that it would have.
  - These companies are named only because their incidents are public record.
    Nothing here is a claim about their security today.

Response model
  Darwin fires -> automatic action (isolate a host, lock a tier, freeze a session)
  that halts the attacker with probability `auto` (they may hold other footholds),
  plus a human response after triage (high-confidence alert, median 1 h) that
  works with probability `human` (lower where the real victim ignored alerts).

Damage
  "event"  damage happens at one moment (ransomware): prevented if stopped first
  "window" damage builds up over a period (card theft, data theft): partial
  "sweep"  ransomware encrypting servers one by one; decoy servers mixed in

The Spider
  Hooks marked `spider=True` stand for Judith's internal watcher flagging one
  source that reads far more than any legitimate user. They are left out of the
  "three plants" column and included in the "with the Spider" column. The
  Spider exists as code for a web shop and has been tested live once, against
  web scraping. It has never been built for or tested on databases, so those
  ranges are the least certain numbers in this file.

Usage: python -m simulations.models.real_attacks_replay [replays]
"""
import math
import random
import statistics
import sys

H = 1.0           # time unit: hours after the attackers got in
D = 24.0


def hook(label, chance, when, plant, spider=False):
    return dict(label=label, chance=chance, when=when, plant=plant, spider=spider)


CASES = [
    dict(
        name="Colonial Pipeline (2021)",
        facts="Entry 29 April through a VPN account that was no longer in use and had no multi-factor "
              "login; its password was later found in a batch of leaked passwords (how the attackers got it "
              "is not known). Nearly 100 GB reportedly taken in about two hours on 6 May. A control-room "
              "employee saw the ransom note just before 5 a.m. on 7 May; the pipeline was shut by 6:10 a.m.",
        sources=["J. Blount, written testimony, US Senate Homeland Security Committee, 8 June 2021",
                 "C. Carmakal (Mandiant) quoted by Bloomberg, 4 June 2021",
                 "Bloomberg, 9 May 2021, citing people familiar with the matter (the 100 GB in two hours)"],
        assumed="What the attackers did between 29 April and 6 May is not public.",
        real_detect=8 * D,
        damage=[("event", "ransomware", 8 * D), ("window", "data theft (6 May, about two hours)", 7 * D, 7 * D + 2)],
        hooks=[hook("decoy server/share touched during network recon", (0.4, 0.75), (2, 6 * D), "Hercules/Judith"),
               hook("decoy login dumped from a laptop and tried", (0.35, 0.65), (1 * D, 6 * D), "Venus"),
               hook("~100 GB upload trips the upload alarm", (0.5, 0.85), (7 * D, 7 * D + 2), "Venus/Judith")],
        auto=(0.6, 0.85), human=(0.7, 0.9)),
    dict(
        name="Change Healthcare (2024)",
        facts="Entry 12 February with stolen credentials through a Citrix remote-access portal that had no "
              "multi-factor login. The attackers moved through the systems; data was taken between 17 and "
              "20 February. Ransomware on 21 February, nine days after entry, which is when the company "
              "found out. About 190 million people affected.",
        sources=["A. Witty, testimony to the US Senate Finance Committee and House Energy and Commerce "
                 "Committee, 1 May 2024",
                 "Change Healthcare HIPAA substitute notice, 2024 (the 17 to 20 February dates)",
                 "UnitedHealth Group, January 2025 (the 190 million figure)"],
        assumed="When the attackers first explored the network within the nine days.",
        real_detect=9 * D,
        damage=[("event", "ransomware", 9 * D), ("window", "data theft (17 to 20 February)", 5 * D, 8 * D)],
        hooks=[hook("decoy server/share touched during network recon", (0.4, 0.75), (2, 7 * D), "Hercules/Judith"),
               hook("decoy login dumped and tried", (0.35, 0.65), (1 * D, 7 * D), "Venus"),
               hook("large uploads trip the upload alarm", (0.45, 0.8), (5 * D, 8 * D), "Venus/Judith")],
        auto=(0.6, 0.85), human=(0.7, 0.9)),
    dict(
        name="MGM Resorts (2023)",
        facts="Social engineering of the IT help desk (a '10-minute call' is an unverified claim from a "
              "malware-research group). By the attackers' own account they were inside from Friday "
              "8 September with administrator rights in the identity systems, MGM noticed and shut down "
              "identity servers, and on 11 September they encrypted more than 100 virtualization hosts. "
              "MGM disclosed the incident on 11 September and later put the cost at about $100 million "
              "and confirmed customer data was taken. '6 TB stolen' is an attacker claim.",
        sources=["MGM Resorts Form 8-K, 5 October 2023 (cost, data theft, disclosure)",
                 "ALPHV/BlackCat public statement, 14 September 2023, as reported by BleepingComputer "
                 "(entry day, identity systems, 100+ hosts, ransomware date): attacker claims, not confirmed by MGM"],
        assumed="Entry on 8 September and discovery about a day later follow the attackers' account and "
                "press reports. When data was copied is not public; taken as any time before the ransomware. "
                "The 20 decoy hosts are our choice.",
        real_detect=1 * D,
        damage=[("sweep", "virtualization hosts encrypted", 3 * D, 100, 20),
                ("window", "data theft (timing assumed)", 4, 3 * D)],
        hooks=[hook("decoy admin accounts in the identity system used", (0.2, 0.5), (1, 1 * D), "Judith"),
               hook("large upload trips the upload alarm", (0.5, 0.85), (4, 3 * D), "Venus/Judith")],
        auto=(0.6, 0.85), human=(0.6, 0.85)),
    dict(
        name="Target (2013)",
        facts="Attackers used login details stolen from an HVAC vendor (taken at least two months earlier) "
              "and entered Target's network on 12 November. They tested card-stealing malware on a few "
              "registers from 15 to 28 November; most registers were infected by 30 November. Target's own "
              "security tools raised alerts on 30 November and 2 December that were not acted on. Card data "
              "was shipped out from 2 December for about two weeks. The Justice Department told Target on "
              "12 December; Target confirmed and removed most of the malware on 15 December. About "
              "40 million cards, plus personal details of up to 70 million customers.",
        sources=["US Senate Committee on Commerce, Science, and Transportation, majority staff report, "
                 "'A \"Kill Chain\" Analysis of the 2013 Target Data Breach', 26 March 2014"],
        assumed="When the attackers mapped the network between 12 and 30 November.",
        real_detect=30 * D,
        damage=[("window", "card data shipped out (2 to 15 December)", 20 * D, 33 * D)],
        hooks=[hook("decoy server touched while mapping the network", (0.4, 0.8), (2, 18 * D), "Hercules/Judith"),
               hook("malware pushed onto decoy registers during the test phase", (0.85, 0.98), (3 * D, 16 * D), "Judith"),
               hook("card data shipped out trips the upload alarm", (0.4, 0.75), (20 * D, 33 * D), "Venus/Judith")],
        auto=(0.6, 0.85), human=(0.3, 0.5)),
    dict(
        name="Equifax (2017)",
        facts="An unpatched web application (Apache Struts) on the online dispute portal, scanned by "
              "attackers on 10 March and exploited in May. They found a store of unencrypted usernames and "
              "passwords and used it to reach 48 further databases, ran about 9,000 queries, and took data "
              "out in small increments from 13 May. Found on 29 July, about 76 days later, when traffic "
              "inspection resumed after an expired certificate was replaced. About 145.5 million people in "
              "the US at first count, later about 148 million.",
        sources=["US Government Accountability Office, GAO-18-559, August 2018",
                 "US House Committee on Oversight and Government Reform, majority staff report, December 2018"],
        assumed="Data theft is taken as steady across the 76 days, and the times at which the attackers "
                "used the stored logins and reached each database are not public.",
        real_detect=76 * D,
        damage=[("window", "records stolen (assumed steady)", 2 * D, 76 * D)],
        hooks=[hook("decoy database logins planted in the unencrypted password store get used", (0.85, 0.97), (1 * D, 7 * D), "Judith/Venus"),
               hook("decoy databases / honey records queried", (0.6, 0.9), (2 * D, 20 * D), "Judith"),
               hook("the Spider flags one web server reading from dozens of unrelated databases", (0.3, 0.6), (3 * D, 30 * D),
                    "Spider", spider=True)],
        auto=(0.6, 0.85), human=(0.7, 0.9)),
    dict(
        name="Snowflake customers (2024), per victim",
        facts="Logins stolen by password-stealing malware, the oldest from November 2020, on accounts with "
              "no multi-factor login. About 165 organizations were notified as potentially exposed. Inside "
              "a customer's account the attackers listed the tables, copied chosen tables into a temporary "
              "staging area and downloaded them. The first known victim learned of it in April 2024 when "
              "investigators found its records in threat intelligence.",
        sources=["Mandiant, 'UNC5537 Targets Snowflake Customer Instances for Data Theft and Extortion', 10 June 2024"],
        assumed="How long each theft took (taken as 1 to 12 hours) and how long each victim went without "
                "knowing (taken as 30 days) are not public.",
        real_detect=30 * D,
        damage=[("window", "tables copied and downloaded (timing assumed)", 1, 12)],
        hooks=[hook("decoy tables with high-value names copied", (0.6, 0.9), (0.2, 3), "Judith"),
               hook("bulk 'list everything, copy everything' trips enumeration", (0.5, 0.8), (0.2, 4), "Judith"),
               hook("download of staged files trips the upload alarm", (0.5, 0.8), (1, 12), "Judith"),
               hook("the Spider flags one login reading far more tables than it ever has", (0.3, 0.6), (0.5, 6),
                    "Spider", spider=True)],
        auto=(0.7, 0.9), human=(0.7, 0.9)),
    dict(
        name="AI-orchestrated espionage, GTG-1002 (2025), per target",
        facts="Detected by the AI provider in mid-September 2025. An AI agent carried out an estimated 80 to "
              "90% of the tactical work against roughly 30 targets, at peak making thousands of requests, "
              "often several per second. It sometimes claimed logins that did not work. A handful of "
              "intrusions succeeded. Finding and exploiting a weakness took the agent 1 to 4 hours and "
              "extracting data 2 to 6 hours, with people approving the key steps.",
        sources=["Anthropic, 'Disrupting the first reported AI-orchestrated cyber espionage campaign', November 2025"],
        assumed="How long the attackers were in any one target before detection (taken as 3 days) and the "
                "hours over which data left (taken as hours 2 to 24) are not public.",
        real_detect=3 * D,
        damage=[("window", "data extracted (timing assumed)", 2, 24)],
        hooks=[hook("request bursts trip the traffic tripwire", (0.75, 0.95), (0.05, 1), "Judith"),
               hook("harvested decoy logins get used", (0.7, 0.9), (0.5, 6), "Venus/Judith"),
               hook("decoy servers touched during automated recon", (0.6, 0.9), (0.1, 4), "Hercules/Judith")],
        auto=(0.7, 0.9), human=(0.7, 0.9)),
]


def lognorm(rng, median, sigma=0.8):
    return median * math.exp(rng.gauss(0, sigma))


def replay(case, rng, with_spider=False):
    fires = []
    for h in case["hooks"]:
        if h["spider"] and not with_spider:
            continue
        lo, hi = h["chance"]
        t0, t1 = h["when"]
        if rng.random() < rng.uniform(lo, hi):
            fires.append((rng.uniform(t0, t1), h["label"], h["plant"]))
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


def summarize(case, n, with_spider):
    rs = [replay(case, random.Random(f"{case['name']}|{i}"), with_spider) for i in range(n)]
    firsts = [r[0][0] for r in rs if r[0]]
    comps = {}
    for r in rs:
        if r[0]:
            comps[r[0][2]] = comps.get(r[0][2], 0) + 1
    first_dmg = min(d[2] for d in case["damage"])
    before = sum(1 for r in rs if r[0] and r[0][0] < first_dmg) / n
    lines = [f"Darwin alerts at all: {100 * len(firsts) / n:.0f}%   before damage begins: {100 * before:.0f}%"]
    if firsts:
        lines.append(f"first Darwin alert: median {statistics.median(firsts):.1f} h "
                     f"({statistics.median(firsts) / D:.2f} days) after entry; most often from {max(comps, key=comps.get)}")
    for j, d in enumerate(case["damage"]):
        vals = [r[2][j] for r in rs]
        lines.append(f"{d[1]}: avg {100 * statistics.mean(vals):.0f}% of the real damage "
                     f"(prevented entirely in {100 * sum(v == 0 for v in vals) / n:.0f}% of replays)")
    return lines


def main(n=5000):
    print("Tabletop replay. Facts are sourced; every probability is the authors' estimate. See the module docstring.")
    for case in CASES:
        print(f"\n== {case['name']}")
        print(f"   documented: {case['facts']}")
        print(f"   assumed: {case['assumed']}")
        for s in case["sources"]:
            print(f"   source: {s}")
        print(f"   real discovery: {case['real_detect'] / D:.1f} days after entry")
        print("   -- the three plants")
        for line in summarize(case, n, with_spider=False):
            print("   " + line)
        if any(h["spider"] for h in case["hooks"]):
            print("   -- with the Spider (untested on databases; the least certain numbers here)")
            for line in summarize(case, n, with_spider=True):
                print("   " + line)


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 5000)

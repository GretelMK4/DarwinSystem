"""
The rare spider: a revealing defender inside some pitchers (shelved idea, one test).

World: one very sensitive site plus 20 ordinary Darwin-protected sites, all with
quiet pitchers. A swarm of 300 agents arrives one after another and shares a board.

Quiet pitcher: the agent believes it is getting closer; it stays ~20 time units
  and rarely realises it was a trap (5%).
Spider (only on the sensitive site, met on a share of pitcher visits): reveals
  itself, serves junk, tells the agent the truth, and releases it after ~2 units.
  The agent carries a warning home: the swarm starts avoiding the sensitive site.
  But it also carries a description of the trap, which can teach the swarm to
  recognise ALL Darwin pitchers (p_learn), so fewer agents fall into them anywhere.

look = "same":     the spider's pitcher looks like every other Darwin pitcher (p_learn 0.5)
look = "distinct": the spider's pitcher looks different from the quiet ones (p_learn 0.1)

The spider's venom here is time and worthless content served from our own server only.
Usage: python -m simulations.models.spider [trials]
"""
import random
import statistics
import sys


def run(spider_rate, p_learn, seed, n_agents=300, n_other=20):
    rng = random.Random(seed)
    warnings, fp_count = 0, 0.0
    out = dict(sens_probes=0, sens_deterred=0, sens_time=0.0, other_probes=0, other_time=0.0)
    for _ in range(n_agents):
        fp = min(0.9, 1 - 0.85 ** fp_count)                  # how well the swarm spots Darwin pitchers
        p_fall = 0.7 * (1 - fp)
        if rng.random() < 0.5:                               # this agent goes for the sensitive site
            if rng.random() < warnings / (warnings + 20):
                out["sens_deterred"] += 1
            elif rng.random() < p_fall:
                if rng.random() < spider_rate:               # meets the spider
                    out["sens_time"] += 2
                    warnings += 1
                    if rng.random() < p_learn:
                        fp_count += 1
                else:                                        # quiet pitcher
                    out["sens_time"] += 20
                    if rng.random() < 0.05:
                        fp_count += 0.2
            else:
                out["sens_probes"] += 1                      # reached the real system
        for _ in range(5):                                   # also tries 5 other Darwin-protected sites
            if rng.random() < p_fall:
                out["other_time"] += 20
            else:
                out["other_probes"] += 1
    out["final_fingerprint"] = min(0.9, 1 - 0.85 ** fp_count)
    return out


def main(trials=500):
    rows = []
    for look, p_learn in (("same", 0.5), ("distinct", 0.1)):
        for rate in (0.0, 0.1, 0.5, 1.0):
            if rate == 0.0 and look == "distinct":
                continue
            rs = [run(rate, p_learn, s) for s in range(trials)]
            m = {k: statistics.mean(r[k] for r in rs) for k in rs[0]}
            rows.append((look if rate else "-", rate, m))
    print(f"{'spider look':12s}{'met on':>8s}{'real probes':>13s}{'deterred':>10s}{'time held':>11s}"
          f"{'other probes':>14s}{'other time':>12s}{'swarm spots Darwin':>20s}")
    for look, rate, m in rows:
        print(f"{look:12s}{rate:>7.0%} {m['sens_probes']:>12.1f}{m['sens_deterred']:>10.1f}{m['sens_time']:>11.0f}"
              f"{m['other_probes']:>14.0f}{m['other_time']:>12.0f}{m['final_fingerprint']:>19.0%}")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 500)

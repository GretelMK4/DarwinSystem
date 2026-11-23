"""
A patient, deception-aware AI swarm vs. Judith's shop over 24 simulated hours.

Attacker behaviour is drawn from 2025-2026 public research on AI attack agents:
  - multi-agent teams sharing a workspace; rotating identities from a large proxy pool
  - deception-aware: skip hidden links, avoid honeypot-looking servers (Hercules)
  - verify their loot with clean identities and throw away what doesn't match
  - adapt when caught: slow down, shorten sessions, pad with popular products to blend in
It is modelled at the level of requests per second; no real techniques are involved.

The shop: 20,000 products. Real shoppers follow a popularity curve (Zipf): most views go
to popular products; the obscure "long tail" is rarely visited. ~200 shopping sessions an
hour, 5-20 products each, 3-8 seconds apart.

The baseline defence ("tripwires"): traffic tripwire, enumeration detector (60 products / 5 s),
surge alarm, hidden honey links, entry puzzle + busy cap during lockdown, shadow + shield.
The patient swarm stays under all of these.

New countermeasures (toggle):
  coverage  long-tail coverage detector: distinct obscure products requested in 15 min
            vs. what shoppers normally reach -> crowd alarm
  decoys    200 visible decoy products placed deep in the catalog (ordinary listings,
            nothing hidden); decoy views per hour vs. shopper baseline -> crowd alarm;
            one identity viewing 2+ decoys -> sealed
  linking   behavioural fingerprinting (timing, request order, tool patterns): while a
            crowd alarm is active, identities are matched to the crowd after 5 requests
            (attacker identities 80%, real shoppers 2% false match) -> sealed (shadow)
  fast_link same, but on an identity's FIRST request, from technical/timing traits
            (attacker identities 70%, real shoppers 2%) -> short sessions stop helping.
            OFF BY DEFAULT: it judges a visitor on a single request, and in this model
            it seals real shoppers. Run with --fast-link to include it.
  tail_cap  while a crowd alarm is active, obscure products never served before go out to
            unproven visitors at most 0.3/s in total; beyond that: "busy, retry"

The swarm's verification is realistic: its "clean" checker identities can themselves be
fingerprinted and shown the same fakes, so a poisoned copy can pass its own check.

These countermeasures exist only in this model. None of them is implemented in
darwin/judith/shop.py yet, and the match rates above are assumptions, not measurements.

Usage: python -m simulations.attackers.patient_swarm [trials] [--fast-link]
"""
import bisect
import random
import statistics
import sys
from collections import deque

N = 20_000
TAIL_RANK = 2_000
DAY = 86_400
N_DECOY = 200


def zipf_cdf(n, s=1.0):
    w = [1 / (r ** s) for r in range(1, n + 1)]
    tot = sum(w)
    acc, cdf = 0.0, []
    for x in w:
        acc += x / tot
        cdf.append(acc)
    return cdf


CDF = zipf_cdf(N + N_DECOY)


def human_pick(rng):
    return bisect.bisect_left(CDF, rng.random())            # rank 0..N+N_DECOY-1


def run(seed, defs, attacker="v5"):
    rng = random.Random(seed)
    # decoys sit at deep ranks; ranks map to items; decoy ranks are a fixed scattered set
    decoy_ranks = set(random.Random(7).sample(range(N // 2, N + N_DECOY), N_DECOY))
    real_ranks = [r for r in range(N + N_DECOY) if r not in decoy_ranks]
    real_of_rank = {r: i for i, r in enumerate(real_ranks)}          # rank -> real item id
    use_decoys = "decoys" in defs

    stolen = set()                       # real items delivered to unsealed attacker identities
    dataset = {}                         # attacker's belief: item -> real?
    # attacker
    rate = 3.0                           # requests per second across the swarm
    head_mimic = 0.78 if attacker == "v5x" else 0.0
    session_len = 25
    queue = list(range(N))
    rng.shuffle(queue)
    qpos = 0
    ids = {}
    next_id = 0
    active = deque()
    burned_signal = 0
    # defence state
    tail_window = deque()                # (t, rank) obscure products requested
    tail_counts = {}
    decoy_window = deque()
    alarm_at = None
    humans_fake = humans_sealed = human_pages = human_busy = 0
    human_sessions = []
    lockdown_at = None
    rng.random()                         # unused draw, kept so each seed reproduces the earlier published runs

    served = set()                       # real items served to anyone (shield uses this)
    bucket = [5.0, 0]

    def take_token(t):
        bucket[0] = min(5.0, bucket[0] + (t - bucket[1]) * 0.3)
        bucket[1] = t
        if bucket[0] >= 1:
            bucket[0] -= 1
            return True
        return False

    def new_identity(t):
        nonlocal next_id
        next_id += 1
        ids[next_id] = {"n": 0, "sealed": False, "decoys": 0, "items": [], "checked": False}
        return next_id

    def maybe_link(I):
        if alarm_at is None or I["checked"] or I["sealed"]:
            return
        if "fast_link" in defs or ("linking" in defs and I["n"] >= 5):
            I["checked"] = True
            if rng.random() < (0.7 if "fast_link" in defs else 0.8):
                I["sealed"] = True

    def crowd_alarm(t):
        nonlocal alarm_at, lockdown_at
        if alarm_at is None:
            alarm_at = t
            lockdown_at = t

    for _ in range(40):
        active.append(new_identity(0))
    t = 0
    verify_next = 60
    while t < DAY:
        # ---- real shoppers ----
        if rng.random() < 200 / 3600:
            human_sessions.append({"left": rng.randint(5, 20), "next": t, "sealed": False, "linked_check": 0,
                                   "decoys": 0, "checked": False, "start": t})
        still = []
        for h in human_sessions:
            if h["next"] <= t:
                rank = human_pick(rng)
                human_pages += 1
                is_decoy = use_decoys and rank in decoy_ranks
                if rank >= TAIL_RANK and not is_decoy:
                    tail_window.append((t, rank))
                    tail_counts[rank] = tail_counts.get(rank, 0) + 1
                if is_decoy:
                    decoy_window.append(t)
                    h["decoys"] += 1
                    if h["decoys"] >= 2 and not h["sealed"]:
                        h["sealed"] = True
                        humans_sealed += 1
                h["linked_check"] += 1
                if alarm_at is not None and not h["checked"] and not h["sealed"] and \
                        (("fast_link" in defs) or ("linking" in defs and h["linked_check"] >= 5)):
                    h["checked"] = True
                    if rng.random() < 0.02:
                        h["sealed"] = True
                        humans_sealed += 1
                item_h = real_of_rank.get(rank)
                if h["sealed"] and not is_decoy and item_h not in served:
                    humans_fake += 1
                elif not h["sealed"] and not is_decoy and item_h is not None:
                    if ("tail_cap" in defs and alarm_at is not None and h["start"] >= alarm_at
                            and rank >= TAIL_RANK and item_h not in served):
                        if not take_token(t):
                            human_busy += 1
                        else:
                            served.add(item_h)
                    else:
                        served.add(item_h)
                h["left"] -= 1
                h["next"] = t + rng.uniform(3, 8)
            if h["left"] > 0:
                still.append(h)
        human_sessions = still

        # ---- the swarm ----
        n_req = sum(1 for _ in range(int(rate)) ) + (1 if rng.random() < rate - int(rate) else 0)
        for _ in range(n_req):
            if not active:
                active.append(new_identity(t))
            ident = active[0]
            I = ids[ident]
            if rng.random() < head_mimic:
                rank = rng.randrange(TAIL_RANK)                   # blend in with popular products
                item = real_of_rank.get(rank)
                is_decoy = False
            else:
                while qpos < len(queue) and queue[qpos] in dataset:
                    qpos += 1
                if qpos >= len(queue):
                    break
                item = queue[qpos]
                qpos += 1
                rank = real_ranks[item]
                is_decoy = False
                # walking the catalog listings also walks past visible decoys
                if use_decoys and rng.random() < N_DECOY / N:
                    is_decoy = True
            if is_decoy:
                decoy_window.append(t)
                I["decoys"] += 1
                if I["decoys"] >= 2:
                    I["sealed"] = True
                continue
            if rank >= TAIL_RANK:
                tail_window.append((t, rank))
                tail_counts[rank] = tail_counts.get(rank, 0) + 1
            I["n"] += 1
            maybe_link(I)
            if item is None:
                continue
            if I["sealed"]:
                dataset[item] = item in served                    # shield: real only if already served
            else:
                if ("tail_cap" in defs and alarm_at is not None and rank >= TAIL_RANK
                        and item not in served and not take_token(t)):
                    queue.append(item)                            # "busy, retry" -> back of the queue
                    active.rotate(-1)
                    continue
                stolen.add(item)
                served.add(item)
                dataset[item] = True
            I["items"].append(item)
            if I["n"] >= session_len:
                active.popleft()
                active.append(new_identity(t))
            else:
                active.rotate(-1)

        # ---- defence: crowd detectors ----
        while tail_window and t - tail_window[0][0] > 900:
            _, r = tail_window.popleft()
            tail_counts[r] -= 1
            if tail_counts[r] <= 0:
                del tail_counts[r]
        while decoy_window and t - decoy_window[0] > 3600:
            decoy_window.popleft()
        if "coverage" in defs and len(tail_counts) > 450:        # ~3x what shoppers reach in 15 min
            crowd_alarm(t)
        if use_decoys and len(decoy_window) > 15:                # ~5x shopper decoy views per hour
            crowd_alarm(t)

        # ---- swarm verifies and adapts ----
        if t >= verify_next:
            verify_next = t + 60
            sample = [i for i in list(ids)[-60:] if ids[i]["items"]]
            for i in rng.sample(sample, min(3, len(sample))):
                it = rng.choice(ids[i]["items"])
                if it not in dataset:
                    continue
                # a fresh "clean" checker identity; it may itself be fingerprinted and shown fakes
                checker_sealed = (alarm_at is not None and
                                  (("fast_link" in defs and rng.random() < 0.7)))
                checker_sees_real = (not checker_sealed) or (it in served)
                if checker_sees_real != dataset[it]:               # copies disagree
                    burned_signal += 1
                    for x in ids[i]["items"]:
                        if x in dataset:
                            del dataset[x]                         # can't tell which copy lied: drop them all
                            queue.append(x)
                    ids[i]["items"] = []
                    if attacker in ("v5", "v5x"):
                        rate = max(0.3, rate * 0.8)                # slow down
                        session_len = max(4, session_len - 4)     # shorter sessions dodge linking
                        head_mimic = min(0.85, head_mimic + 0.1)  # blend in more
        t += 1

    real_in = sum(1 for v in dataset.values() if v)
    fake_in = sum(1 for v in dataset.values() if not v)
    return {"stolen_pct": 100 * len(stolen) / N, "dataset_fake_pct": 100 * fake_in / max(real_in + fake_in, 1),
            "alarm_min": round(alarm_at / 60, 1) if alarm_at is not None else None,
            "final_rate": rate, "identities": next_id, "human_pages": human_pages,
            "humans_fake_pct": 100 * humans_fake / max(human_pages, 1), "humans_sealed": humans_sealed,
            "humans_busy_pct": 100 * human_busy / max(human_pages, 1)}


CONFIGS = {
    "tripwires only": set(),
    "+coverage+decoys+linking": {"coverage", "decoys", "linking"},
    "+tail_cap": {"coverage", "decoys", "tail_cap"},
}
FAST_LINK_CONFIGS = {
    "+fast_link": {"coverage", "decoys", "fast_link"},
    "+fast_link+tail_cap": {"coverage", "decoys", "fast_link", "tail_cap"},
}
FAST_LINK_WARNING = ("WARNING: fast linking judges a visitor on one request and wrongly seals real shoppers "
                     "(see the 'shoppers sealed' column). It is experimental and off by default.")


def main(trials=20, fast_link=False):
    configs = dict(CONFIGS, **FAST_LINK_CONFIGS) if fast_link else CONFIGS
    if fast_link:
        print(FAST_LINK_WARNING)
    for attacker in ("v5", "v5x"):
        print(f"\n### attacker {attacker}: " + ("patient, adaptive" if attacker == "v5"
                                                 else "blends in with popular products from the start"))
        print(f"{'defence':22s}{'stolen in 24h':>15s}{'fake in loot':>14s}{'alarm (min)':>13s}"
              f"{'final rate/s':>14s}{'shopper fake pages':>20s}{'shoppers sealed':>17s}{'shopper busy':>14s}")
        for name, defs in configs.items():
            rs = [run(s, defs, attacker) for s in range(trials)]
            al = [r["alarm_min"] for r in rs if r["alarm_min"] is not None]
            print(f"{name:22s}{statistics.mean(r['stolen_pct'] for r in rs):>14.1f}%"
                  f"{statistics.mean(r['dataset_fake_pct'] for r in rs):>13.1f}%"
                  f"{(statistics.median(al) if al else float('nan')):>13.1f}"
                  f"{statistics.mean(r['final_rate'] for r in rs):>14.2f}"
                  f"{statistics.mean(r['humans_fake_pct'] for r in rs):>19.2f}%"
                  f"{statistics.mean(r['humans_sealed'] for r in rs):>17.1f}"
                  f"{statistics.mean(r['humans_busy_pct'] for r in rs):>13.2f}%")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--fast-link"]
    main(int(args[0]) if args else 20, fast_link="--fast-link" in sys.argv[1:])

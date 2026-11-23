"""
Phase 3 test: attacking the communication between the plants.

Five Hercules sites report to Judith and Venus over the hardened channel in
darwin/comms.py. Each scenario below is one way to abuse that channel. For
comparison, the same abuse is run against the v0.1 channel (darwin/intel.py:
one shared key, Hercules to Judith only, every valid message acted on in full,
intel seals that never expire).

The cryptography is real (Ed25519 signatures are made and checked). The
network, the clock and the attackers are simulated. Everything is counted,
nothing is estimated: there are no probabilities here except which Hercules
sites a swarm happens to hit, and random message loss in the last scenario.

What "innocent" means here: an identity (address + User-Agent) that belongs to
a real shopper and never touched a decoy.

Usage: python -m simulations.models.comms [trials]
"""
import json
import random
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from darwin import comms, intel
from simulations import common

N_HERCULES = 5
STEP = 5.0
SHARED_ADDRESS = "10.50.0.1"                      # an office or carrier address many people share
COMMON_UA = "Mozilla/5.0 (Windows NT 10.0) Chrome/141"
SWARM = [f"203.0.113.{i}|swarm-agent" for i in range(1, 41)]
INNOCENTS = [f"198.51.100.{i}|{COMMON_UA}" for i in range(1, 251)] + [f"198.51.101.{i}|{COMMON_UA}" for i in range(1, 251)]
SHARED_SHOPPERS_SAME_UA = 8                       # of 40 shoppers behind the shared address, 8 use the common browser
DAY = 86400.0


# ---------------- the two designs ----------------

class Phase3:
    name = "phase 3"

    def __init__(self, seed, **policy):
        self.rng = random.Random(seed)
        self.policy = comms.Policy(**policy)
        self.h = [comms.Sender(f"hercules-{i + 1}") for i in range(N_HERCULES)]
        approved = {s.id: s.public_key for s in self.h}
        shared = lambda address: address == SHARED_ADDRESS                     # noqa: E731
        self.judith = comms.Receiver("judith", approved, ("warning", "intel"), self.policy, shared)
        self.venus = comms.Receiver("venus", approved, ("warning",), self.policy, shared)
        self.blocked = set()             # (sender id or "relay", receiver name) pairs that deliver nothing
        self.loss = 0.0
        self.recorded = []               # everything that crossed the wire (an eavesdropper's copy)
        self.honest = set(range(N_HERCULES))
        self.relay_from_judith = None    # set to a function to model a compromised Judith

    def _drop(self, src, dst):
        return (src, dst) in self.blocked or self.rng.random() < self.loss

    def send(self, env, now, to=("judith", "venus")):
        self.recorded.append(env)
        for dst in to:
            r = getattr(self, dst)
            if env.get("stream") in r.streams and not self._drop(env.get("sender"), dst):
                r.receive(env, now)

    def step(self, now):
        if now % self.policy.heartbeat_every == 0:
            for i in sorted(self.honest):
                self.send(self.h[i].heartbeat(now), now)
        out = self.judith.relay_out()
        if self.relay_from_judith is not None:
            out = self.relay_from_judith(out, now)
        for env in out:
            if not self._drop("relay", "venus"):
                self.venus.receive(env, now, relayed_by="judith")
        for env in self.venus.relay_out():
            if not self._drop("relay", "judith"):
                self.judith.receive(env, now, relayed_by="venus")
        self.judith.tick(now)
        self.venus.tick(now)

    def report_sweep(self, sites, now):
        """Honest Hercules sites that a swarm is hitting report it."""
        for k, i in enumerate(sites):
            self.send(self.h[i].intel(now + k, self.rng.sample(SWARM, 20)), now + k)
            self.send(self.h[i].surge(now + k, ["catalog"]), now + k)

    def report_visitor(self, i, identity, now):
        self.send(self.h[i].intel(now, [identity]), now)

    # what the scenarios measure
    def locked(self, now):
        return self.judith.in_lockdown(now)

    def armed(self, now):
        return self.venus.in_lockdown(now)

    def sealed(self, identity, now):
        return self.judith.is_sealed(identity, now)

    def seal_hours(self, identities, start):
        return sum(max(0.0, min(self.judith.sealed.get(i, 0), start + DAY) - start) for i in identities) / 3600.0

    def flags(self, who="judith"):
        return {f["flag"] for f in getattr(self, who).flags}


class V01:
    """The released v0.1 channel: one shared key, Hercules to Judith only."""
    name = "v0.1 (shared key)"

    def __init__(self, seed, **_):
        self.rng = random.Random(seed)
        self.key = intel.new_key().encode()
        self.verifier = intel.Verifier(self.key)
        self.sealed_ids, self.lockdown_at = set(), None
        self.accepted_at = []
        self.blocked, self.loss, self.recorded = set(), 0.0, []
        self.honest = set(range(N_HERCULES))

    def send_signed(self, sender, payload, now):
        env = intel.sign(payload, self.key, sender=sender, now=now)
        self.recorded.append(env)
        if (sender, "judith") in self.blocked or self.rng.random() < self.loss:
            return
        self.deliver(env, now)

    def deliver(self, env, now):
        try:
            p = self.verifier.verify(env, now=now)
        except intel.IntelError:
            return
        self.accepted_at.append(now)
        self.sealed_ids.update(p.get("identities", []))
        if p.get("surge") and self.lockdown_at is None:
            self.lockdown_at = now

    def step(self, now):
        pass

    def report_sweep(self, sites, now):
        for k, i in enumerate(sites):
            self.send_signed(f"hercules-{i + 1}", {"identities": self.rng.sample(SWARM, 20), "surge": True}, now + k)

    def report_visitor(self, i, identity, now):
        self.send_signed(f"hercules-{i + 1}", {"identities": [identity], "surge": False}, now)

    def locked(self, now):
        return self.lockdown_at is not None and self.lockdown_at <= now

    def armed(self, now):
        return False                       # Venus is not connected in v0.1

    def sealed(self, identity, now):
        return identity in self.sealed_ids

    def seal_hours(self, identities, start):
        return sum(DAY for i in identities if i in self.sealed_ids) / 3600.0     # never expires: the whole day

    def flags(self, who="judith"):
        return set()


def run(world, until, events):
    t = 0.0
    while t <= until:
        for fn in events.get(t, []):
            fn(t)
        world.step(t)
        t += STEP


# ---------------- scenarios ----------------

def small_sweep(world):
    """No tampering. A swarm sweeps only two Hercules sites; later a lone attacker touches one."""
    return honest_attack(world, n_sites=2)


def honest_attack(world, n_sites=3):
    """No tampering. A swarm sweeps three Hercules sites; later a lone attacker touches one."""
    sites = world.rng.sample(range(N_HERCULES), n_sites)
    lone = "192.0.2.77|lone-agent"
    run(world, 600, {100.0: [lambda t: world.report_sweep(sites, t)],
                     300.0: [lambda t: world.report_visitor(world.rng.randrange(N_HERCULES), lone, t)]})
    return {"Judith locks down on the real sweep": world.locked(200),
            "Venus is warned": world.armed(200),
            "swarm identities sealed (of 40)": sum(world.sealed(i, 200) for i in SWARM),
            "lone attacker sealed": world.sealed(lone, 400),
            "innocents sealed": sum(world.sealed(i, 400) for i in INNOCENTS),
            "false flags raised": len(world.flags() | world.flags("venus"))}


def lone_attacker(world):
    """Three lone attackers: one touches a single Hercules; one touches a second Hercules five minutes
    later; one touches a single Hercules and then does something mildly suspicious on Judith's own site."""
    one, two, local = "192.0.2.1|lone-a", "192.0.2.2|lone-b", "192.0.2.3|lone-c"
    run(world, 900, {100.0: [lambda t: [world.report_visitor(0, x, t) for x in (one, two, local)]],
                     400.0: [lambda t: world.report_visitor(3, two, t)],
                     500.0: [lambda t: world.judith.local_evidence(local, t)]})
    return {"one Hercules only: sealed": world.sealed(one, 800),
            "one Hercules only: on the watch list": one in world.judith.watch,
            "two Hercules, five minutes apart: sealed": world.sealed(two, 450),
            "one Hercules + seen by Judith herself: sealed": world.sealed(local, 550),
            "Judith's own sighting alone (no Hercules) seals": _local_alone(world)}


def _local_alone(world):
    world.judith.local_evidence("192.0.2.9|never-reported", 850)
    return world.judith.is_sealed("192.0.2.9|never-reported", 851)


def forged_without_a_key(world):
    """An outsider with no key sends messages claiming to be Hercules."""
    def attack(t):
        if isinstance(world, V01):
            fake_key = b"x" * 32
            for _ in range(20):
                world.deliver(intel.sign({"identities": INNOCENTS[:100], "surge": True}, fake_key, now=t), t)
        else:
            fake = comms.Sender("hercules-2", Ed25519PrivateKey.generate())
            stranger = comms.Sender("hercules-9")
            for s in (fake, stranger):
                for _ in range(10):
                    world.send(s.surge(t), t)
                    world.send(s.intel(t, INNOCENTS[:100]), t)
    run(world, 300, {100.0: [attack]})
    return {"false lockdown": world.locked(200), "Venus falsely armed": world.armed(200),
            "innocents sealed": sum(world.sealed(i, 200) for i in INNOCENTS)}


def stolen_keys(world, n_stolen):
    def attack(t):
        if isinstance(world, V01):
            world.send_signed("hercules-2", {"identities": INNOCENTS, "surge": True}, t)
        else:
            cap = world.policy.sender_identity_cap
            for j, i in enumerate(range(1, 1 + n_stolen)):
                world.honest.discard(i)
                for _ in range(3):
                    world.send(world.h[i].surge(t), t)
                # the attacker knows the public rules: with a quorum of 1 each stolen key names different
                # people (to hurt as many as possible); with a higher quorum the keys must name the same ones
                start = j * cap if world.policy.seal_quorum == 1 else 0
                world.send(world.h[i].intel(t, INNOCENTS[start:]), t)
    run(world, 300, {100.0: [attack]})
    return {"false lockdown": world.locked(200), "Venus falsely armed": world.armed(200),
            "innocents sealed (of 500 named)": sum(world.sealed(i, 200) for i in INNOCENTS),
            "innocent seal-hours in the next day": round(world.seal_hours(INNOCENTS, 100))}


def one_stolen_key(world):
    """The attacker has stolen one Hercules signing key (in v0.1: the one shared key) and names 500 innocent shoppers."""
    return stolen_keys(world, 1)


def two_stolen_keys(world):
    """The attacker has stolen two Hercules signing keys and uses them together."""
    return stolen_keys(world, 2)


def partly_silenced(world):
    """A real sweep hits three sites. The attacker blocks two of them from reaching Judith."""
    return silenced(world, False)


def cut_off(world):
    """A real sweep, with every channel into Judith blocked, including the one from Venus."""
    return silenced(world, True)


def silenced(world, everything):
    sites = [0, 1, 2]
    if everything:
        world.blocked |= {(f"hercules-{i + 1}", "judith") for i in range(N_HERCULES)} | {("relay", "judith")}
    else:
        world.blocked |= {("hercules-1", "judith"), ("hercules-2", "judith")}
    run(world, 600, {100.0: [lambda t: world.report_sweep(sites, t)]})
    flags = world.flags()
    first = min((f["t"] for f in world.judith.flags), default=None) if isinstance(world, Phase3) else None
    return {"Judith locks down on the real sweep": world.locked(300),
            "Judith knows her channel is being cut": bool(flags & {"silent", "blind", "missing_direct", "gap"}),
            "seconds until she knows": first}


def lying_relay(world):
    """Judith is compromised and lies to Venus: altered, invented and replayed messages."""
    if isinstance(world, V01):
        return None
    captured = []

    def lie(out, now):
        captured.extend(e for e in out if e["kind"] == "surge")
        lies = []
        for env in out:
            if env["kind"] == "heartbeat":                       # turn a heartbeat into a surge report
                lies.append(dict(env, kind="surge", payload={"targets": ["bank"]}))
        forger = comms.Sender("hercules-4", Ed25519PrivateKey.generate())
        lies.append(forger.surge(now))                            # invent a message from Hercules 4
        if now > 3600:
            lies.extend(captured)                                 # replay an hour-old genuine surge
        return lies
    world.relay_from_judith = lie
    # an hour earlier there was a real, corroborated sweep (which Venus heard directly, and rightly armed for)
    run(world, 4500, {100.0: [lambda t: world.report_sweep([0, 1, 2], t)]})
    return {"Venus armed for the real sweep": world.armed(200),
            "Venus falsely armed an hour later": world.armed(4400),
            "lies rejected by Venus": sum(world.venus.rejected.values()),
            "lies accepted by Venus": sum(1 for a in world.venus.actions if a["t"] > 2000)}


def two_stories(world):
    """A compromised Hercules tells Judith 'surge' and tells Venus 'all quiet' under the same message number."""
    if isinstance(world, V01):
        return None
    liar = world.h[1]
    world.honest.discard(1)

    def attack(t):
        seq = liar._seq["warning"] + 1
        liar._seq["warning"] = seq
        world.send(liar._message("surge", {"targets": []}, t, seq=seq), t, to=("judith",))
        world.send(liar._message("heartbeat", {"intel_seq": 0}, t, seq=seq), t, to=("venus",))
        world.send(world.h[0].surge(t), t)                        # one honest site also saw something real
    run(world, 400, {100.0: [attack]})
    withdrawn = [a["t"] for a in world.judith.actions if a["action"].startswith("lockdown withdrawn")]
    started = [a["t"] for a in world.judith.actions if a["action"] == "lockdown"]
    return {"Judith catches the liar": "equivocation" in world.flags(),
            "Venus catches the liar": "equivocation" in world.flags("venus"),
            "seconds Judith spent in a lockdown resting on the lie":
                (withdrawn[0] - started[0]) if started and withdrawn else (0 if not started else None)}


def shared_address(world):
    """An attacker behind an address shared with real shoppers shows itself to four Hercules sites."""
    ident = f"{SHARED_ADDRESS}|{COMMON_UA}"

    def visit(i):
        return lambda t: world.report_visitor(i, ident, t)
    run(world, 600, {100.0: [visit(0)], 120.0: [visit(1)], 140.0: [visit(2)], 160.0: [visit(3)]})
    hit = world.sealed(ident, 300)
    hours = world.seal_hours([ident], 100)
    return {"real shoppers sealed along with the attacker": SHARED_SHOPPERS_SAME_UA if hit else 0,
            "shopper seal-hours in the next day": round(hours * SHARED_SHOPPERS_SAME_UA),
            "attacker put on the watch list instead": isinstance(world, Phase3) and ident in world.judith.watch}


def replay_later(world):
    """An eavesdropper records a real sweep's messages and replays them two hours later."""
    def replay(t):
        for env in list(world.recorded):
            if isinstance(world, V01):
                world.deliver(env, t)
            else:
                for r in (world.judith, world.venus):
                    if env["stream"] in r.streams:
                        r.receive(env, t)
    run(world, 7500, {100.0: [lambda t: world.report_sweep([0, 1, 2], t)], 7300.0: [replay]})
    if isinstance(world, V01):          # a v0.1 lockdown never ends, so only acceptance can be measured
        return {"replayed messages acted on": sum(1 for t in world.accepted_at if t >= 7300)}
    return {"replayed messages acted on": sum(1 for a in world.judith.actions + world.venus.actions if a["t"] >= 7300),
            "false lockdown from the replay": world.locked(7400)}


def lossy_network(world):
    """No attacker tampering, but one message in ten is lost on every hop. A real sweep happens."""
    world.loss = 0.10
    run(world, 600, {100.0: [lambda t: world.report_sweep(world.rng.sample(range(N_HERCULES), 3), t)]})
    out = {"Judith locks down on the real sweep": world.locked(250), "Venus is warned": world.armed(250)}
    if isinstance(world, Phase3):
        out["loss noticed (gap or missing-direct flags)"] = bool(world.flags() & {"gap", "missing_direct"})
        out["false 'silent' or 'liar' flags"] = len((world.flags() | world.flags("venus")) & {"silent", "blind", "equivocation"})
    return out


SCENARIOS = [
    ("1. No tampering: a real sweep of three sites, then a lone attacker", honest_attack,
     [(V01, {}), (Phase3, {}), (Phase3, {"seal_quorum": 1}), (Phase3, {"seal_quorum": 3, "lockdown_quorum": 3})]),
    ("1b. No tampering: a smaller sweep of two sites, then a lone attacker", small_sweep,
     [(V01, {}), (Phase3, {}), (Phase3, {"seal_quorum": 1}), (Phase3, {"seal_quorum": 3, "lockdown_quorum": 3})]),
    ("1c. A lone attacker under the two-witness rule", lone_attacker, [(Phase3, {})]),
    ("2. Forged messages from someone with no key", forged_without_a_key, [(V01, {}), (Phase3, {})]),
    ("3. One stolen key", one_stolen_key,
     [(V01, {}), (Phase3, {}), (Phase3, {"seal_quorum": 1})]),
    ("4. Two stolen keys", two_stolen_keys,
     [(V01, {}), (Phase3, {}), (Phase3, {"seal_quorum": 1}), (Phase3, {"seal_quorum": 3, "lockdown_quorum": 3})]),
    ("5. Two of three reporting sites blocked from Judith", partly_silenced, [(V01, {}), (Phase3, {})]),
    ("6. Judith cut off completely", cut_off, [(V01, {}), (Phase3, {})]),
    ("7. A compromised Judith lies to Venus", lying_relay, [(Phase3, {})]),
    ("8. A compromised Hercules tells two different stories", two_stories, [(Phase3, {})]),
    ("9. Attacker behind an address shared with real shoppers", shared_address,
     [(V01, {}), (Phase3, {}), (Phase3, {"shared_rule": False})]),
    ("10. Recorded messages replayed two hours later", replay_later, [(V01, {}), (Phase3, {})]),
    ("11. One message in ten lost, real sweep", lossy_network,
     [(V01, {}), (Phase3, {}), (Phase3, {"silence_after": 160.0})]),
]


def label(design, policy):
    return design.name + ("" if not policy else " [" + ", ".join(f"{k}={v}" for k, v in policy.items()) + "]")


def summarise(rows):
    """Average each measure over the trials: share of trials for yes/no measures, mean for counts."""
    out = {}
    for key in rows[0]:
        vals = [r[key] for r in rows]
        if all(isinstance(v, bool) for v in vals):
            out[key] = f"{100 * sum(vals) / len(vals):.0f}% of runs"
        elif any(v is None for v in vals):
            known = [v for v in vals if v is not None]
            out[key] = "never" if not known else f"{sum(known) / len(known):.0f} (in {len(known)} of {len(vals)} runs)"
        else:
            mean = sum(vals) / len(vals)
            out[key] = f"{mean:.0f}" if abs(mean - round(mean)) < 0.05 else f"{mean:.1f}"
    return out


def main(trials=50):
    results = {}
    for title, fn, designs in SCENARIOS:
        print(f"\n== {title}")
        print(f"   {fn.__doc__.strip()}")
        results[title] = {}
        for design, policy in designs:
            rows = [r for r in (fn(design(seed, **policy)) for seed in range(trials)) if r is not None]
            if not rows:
                continue
            summary = summarise(rows)
            results[title][label(design, policy)] = summary
            print(f"   -- {label(design, policy)}")
            for k, v in summary.items():
                print(f"      {k}: {v}")
    with open(common.results_path("comms.json"), "w") as f:
        json.dump(results, f, indent=1)


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 50)

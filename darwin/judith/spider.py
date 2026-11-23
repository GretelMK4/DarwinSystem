"""
The Spider: Judith's internal watcher (roadmap phase 2, first working version).

The pitchers and tripwires catch attackers who are greedy or fast. A patient
attacker stays under every rate threshold and never touches bait, so nothing
fires. The Spider works the other way round, like an immune cell: it does not
wait for something to trip. It inspects everything on a slow cycle and raises
a flag for anything that is not approved behaviour.

It is not an agent and makes no guesses. It is a ledger and a short list of
rules that the site owner sets:

  Visitors (one ledger per source address, kept for WINDOW seconds)
    breadth         more than BREADTH different products viewed. No shopper
                    reads a large part of a catalog; someone copying it must.
    enumeration     of the last RUN_N product views, more than RUN_SHARE were
                    the product number right next to the one before.
    metronome       the last RUN_N gaps between views are almost identical
                    (variation below METRONOME_CV): a timer, not a person.
    many_identities one address presenting more than MAX_IDENTITIES different
                    User-Agents.

  Darwin itself
    component_changed   a watched file (Darwin's own code, the dashboard) no
                        longer matches the fingerprint taken at start-up.

Every flag is a record for people: when, who, which rule, and the evidence.
What happens next is the owner's choice. By default (SPIDER=seal) Judith also
seals the flagged address. The seal is silent: the visitor is moved to the
shadow site, keeps receiving pages, and leaves confident, which is what the
rest of the system relies on. A Spider that announced itself would teach the
swarm what to avoid. SPIDER=alert flags without acting; SPIDER=off turns the
Spider off.

Limits, stated plainly
  - Rules are per source address. An attacker with many addresses gets
    BREADTH products from each before anything is flagged. People who share
    one address (an office, a mobile carrier) share one ledger and can be
    flagged and, in the default seal mode, shown fake pages together. Set
    BREADTH from your own traffic, and use SPIDER=alert until you have if
    many real users reach you through one address.
  - The rules and their defaults are public. An attacker who has read this
    file can stay under them; the price is that each address is then limited
    to a shopper-sized slice of the catalog.
  - The integrity check sees changed files. It does not see a change made in
    memory, and an intruder who can edit Darwin's files can also stop the
    Spider. Phase 3 on the roadmap is about that.
  - Thresholds were set against simulated shoppers, not real ones.
"""
import collections
import hashlib
import json
import os
import statistics
import threading
import time


class Policy:
    """What counts as approved. Every value can be set by environment variable SPIDER_<NAME>."""

    def __init__(self, environ=os.environ):
        def get(name, default, kind=float):
            return kind(environ.get("SPIDER_" + name, default))
        self.window = get("WINDOW", 86400)                 # how long a ledger remembers (seconds)
        self.breadth = get("BREADTH", 150, int)            # different products per address per window
        self.run_n = get("RUN_N", 40, int)                 # how many recent views the pattern rules look at
        self.run_share = get("RUN_SHARE", 0.6)             # share of neighbouring product numbers = enumeration
        self.metronome_cv = get("METRONOME_CV", 0.10)      # gap variation below this = a timer
        self.max_identities = get("MAX_IDENTITIES", 20, int)
        self.period = get("PERIOD", 5.0)                   # seconds between inspections


class Spider:
    def __init__(self, policy=None, flag_log=None, on_flag=None):
        self.policy = policy or Policy()
        self.flag_log = flag_log               # path of a JSON-lines file for people, or None
        self.on_flag = on_flag                 # callback(flag) for the owner's chosen response
        self.flags = []
        self._flagged = set()                  # (subject, rule) already raised
        self._views = collections.defaultdict(collections.deque)    # address -> deque of (t, product)
        self._identities = collections.defaultdict(set)             # address -> User-Agents seen
        self._fingerprints = {}                # path -> sha256 at start-up
        self._lock = threading.Lock()
        self._stop = threading.Event()

    # ---------- what the Spider is told ----------

    def observe(self, address, user_agent, product, t=None):
        """The shop reports every product-page request here, whatever it answered."""
        t = time.time() if t is None else t
        with self._lock:
            self._views[address].append((t, product))
            ids = self._identities[address]
            if len(ids) <= self.policy.max_identities:
                ids.add(user_agent)

    def watch_files(self, paths):
        """Take a fingerprint of each file now; any later difference is flagged."""
        for path in paths:
            self._fingerprints[path] = self._hash(path)

    @staticmethod
    def _hash(path):
        try:
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except OSError:
            return None                        # missing or unreadable is also a state worth comparing

    # ---------- inspection ----------

    def inspect(self, now=None):
        """One pass over everything. Returns the flags raised by this pass."""
        now = time.time() if now is None else now
        p, found = self.policy, []
        with self._lock:
            for address, views in self._views.items():
                while views and now - views[0][0] > p.window:
                    views.popleft()
                products = {n for _, n in views}
                if len(products) > p.breadth:
                    found.append((address, "breadth",
                                  f"{len(products)} different products viewed (approved: up to {p.breadth})"))
                recent = list(views)[-p.run_n:]
                if len(recent) >= p.run_n:
                    steps = [abs(b[1] - a[1]) == 1 for a, b in zip(recent, recent[1:])]
                    share = sum(steps) / len(steps)
                    if share > p.run_share:
                        found.append((address, "enumeration",
                                      f"{share:.0%} of the last {p.run_n} views were the neighbouring product number"))
                    gaps = [b[0] - a[0] for a, b in zip(recent, recent[1:])]
                    mean = statistics.fmean(gaps)
                    if mean > 0 and statistics.pstdev(gaps) / mean < p.metronome_cv:
                        found.append((address, "metronome",
                                      f"the last {p.run_n} views came {mean:.2f} s apart with almost no variation"))
                if len(self._identities[address]) > p.max_identities:
                    found.append((address, "many_identities",
                                  f"more than {p.max_identities} different User-Agents from one address"))
            for address in [a for a, v in self._views.items() if not v]:
                del self._views[address]
                self._identities.pop(address, None)
        for path, expected in self._fingerprints.items():
            if self._hash(path) != expected:
                found.append((path, "component_changed", "file no longer matches its start-up fingerprint"))
        new = []
        for subject, rule, evidence in found:
            if (subject, rule) in self._flagged:
                continue
            self._flagged.add((subject, rule))
            flag = {"t": now, "subject": subject, "rule": rule, "evidence": evidence}
            self.flags.append(flag)
            new.append(flag)
            if self.flag_log:
                with open(self.flag_log, "a") as f:
                    f.write(json.dumps(flag) + "\n")
            if self.on_flag:
                self.on_flag(flag)
        return new

    # ---------- running ----------

    def start(self):
        def loop():
            while not self._stop.wait(self.policy.period):
                self.inspect()
        threading.Thread(target=loop, daemon=True).start()

    def stop(self):
        self._stop.set()

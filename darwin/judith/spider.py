"""
The Spider: Judith's internal watcher (roadmap phase 2, released as a first version).

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

  The whole site (fleet rule, for swarms spread over many addresses)
    fleet_tail      in one BUCKET-second slot, cold addresses (FLEET_COLD views
                    or fewer) opened more rarely-viewed products (seen by at most
                    FLEET_TAIL_POP other addresses) than FLEET_FACTOR times the
                    learned baseline, and at least FLEET_FLOOR. A residential-proxy
                    swarm that takes 3 products per address is invisible to every
                    per-address rule but still has to touch the long tail of the
                    catalog that shoppers rarely open. The flag opens a guard for
                    FLEET_GUARD seconds; guarded(address, product) tells the shop
                    which requests the guard covers (cold address + tail product).
                    The baseline learns only from slots that did not trip, and
                    grows at most FLEET_GROWTH per slot, so a swarm that ramps up
                    slowly cannot teach the Spider that its volume is normal.
                    It never trips during the first FLEET_WARMUP slots after
                    start-up, while popularity is still being learned.
                    A product the guard shadowed stays shadowed for cold visitors
                    for FLEET_STICKY seconds while it is still a tail product
                    (note_shadow), so a swarm that
                    re-fetches its loot later from a clean control identity sees
                    the same answer and cannot tell it was fed fakes.
                    Limit: the rule bounds how FAST a spread-out swarm can copy
                    (about FLEET_FACTOR x the shoppers' own tail rate); a swarm
                    patient enough to stay under that still copies everything.

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
        self.fleet = environ.get("SPIDER_FLEET", "on") == "on"
        self.bucket = get("BUCKET", 3600)                  # fleet rule: seconds per slot
        self.fleet_cold = get("FLEET_COLD", 5, int)        # an address with this many views or fewer is cold
        self.fleet_tail_pop = get("FLEET_TAIL_POP", 1, int)  # a product seen by this many others or fewer is tail
        self.fleet_factor = get("FLEET_FACTOR", 4.0)
        self.fleet_floor = get("FLEET_FLOOR", 60, int)     # never trip below this many cold-tail products per slot
        self.fleet_guard = get("FLEET_GUARD", 21600)       # seconds the guard stays up after a trip
        self.fleet_growth = get("FLEET_GROWTH", 1.10)      # most the baseline may grow per slot
        self.fleet_alpha = get("FLEET_ALPHA", 0.1)         # baseline learning rate
        self.fleet_warmup = get("FLEET_WARMUP", 6, int)    # slots to learn from before the rule may trip
        self.fleet_sticky = get("FLEET_STICKY", 0)         # a product shadowed by the guard stays shadowed
                                                           # for cold visitors this long (0 = off)


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
        self._viewers = collections.defaultdict(collections.deque)  # product -> deque of (t, address)
        self._viewer_n = collections.defaultdict(collections.Counter)  # product -> address -> live views
        self._slot = None                      # fleet rule: start of the current slot
        self._slot_tail = set()                # cold-tail products seen in the current slot
        self.baseline = None                   # learned cold-tail products per slot
        self.guard_until = 0.0
        self._sticky = {}                      # product -> shadow cold visitors until this time
        self.slots = []                        # (slot start, cold-tail count, tripped) for people
        self._lock = threading.Lock()
        self._stop = threading.Event()

    # ---------- what the Spider is told ----------

    def observe(self, address, user_agent, product, t=None):
        """The shop reports every product-page request here, whatever it answered."""
        t = time.time() if t is None else t
        with self._lock:
            if self.policy.fleet:
                self._fleet_observe(address, product, t)
            self._views[address].append((t, product))
            ids = self._identities[address]
            if len(ids) <= self.policy.max_identities:
                ids.add(user_agent)

    # ---------- fleet rule ----------

    def _is_tail(self, address, product, t):
        q, n = self._viewers[product], self._viewer_n[product]
        while q and t - q[0][0] > self.policy.window:
            _, old = q.popleft()
            n[old] -= 1
            if not n[old]:
                del n[old]
        others = len(n) - (1 if address in n else 0)
        return others <= self.policy.fleet_tail_pop

    def _fleet_observe(self, address, product, t):
        p = self.policy
        if self._slot is None:
            self._slot = t - (t % p.bucket)
        tail = self._is_tail(address, product, t)
        if len(self._views[address]) < p.fleet_cold and tail:
            self._slot_tail.add(product)
        self._viewers[product].append((t, address))
        self._viewer_n[product][address] += 1

    def _fleet_inspect(self, now, found):
        p = self.policy
        if self._slot is None:
            return
        count = len(self._slot_tail)
        limit = max(p.fleet_floor, p.fleet_factor * (self.baseline or 0))
        tripped = count > limit and len(self.slots) >= p.fleet_warmup
        if tripped and now >= self.guard_until:
            found.append(("fleet", "fleet_tail",
                          f"{count} rarely-viewed products opened by cold addresses this slot "
                          f"(baseline {self.baseline or 0:.0f}, limit {limit:.0f})"))
        if tripped:
            self.guard_until = max(self.guard_until, now + p.fleet_guard)
        if now - self._slot >= p.bucket:                  # close the slot
            self.slots.append((self._slot, count, tripped))
            if not tripped:
                if self.baseline is None:
                    self.baseline = float(count)
                else:
                    target = (1 - p.fleet_alpha) * self.baseline + p.fleet_alpha * count
                    self.baseline = min(target, max(self.baseline, 1.0) * p.fleet_growth)
            self._slot = now - (now % p.bucket)
            self._slot_tail = set()

    def guarded(self, address, product, now=None):
        """True when the fleet guard is up and this request is a cold address opening a tail product."""
        now = time.time() if now is None else now
        sticky = self._sticky.get(product, 0.0) > now
        if now >= self.guard_until and not sticky:
            return False
        with self._lock:
            cold = len(self._views.get(address, ())) <= self.policy.fleet_cold
            return cold and self._is_tail(address, product, now)

    def note_shadow(self, product, now=None):
        """The shop served a guard shadow for this product: keep doing so for cold visitors for
        FLEET_STICKY seconds, so that a clean identity re-fetching it later sees the same answer."""
        now = time.time() if now is None else now
        if self.policy.fleet_sticky > 0:
            self._sticky[product] = now + self.policy.fleet_sticky

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
            if p.fleet:
                self._fleet_inspect(now, found)
        for path, expected in self._fingerprints.items():
            if self._hash(path) != expected:
                found.append((path, "component_changed", "file no longer matches its start-up fingerprint"))
        new = []
        for subject, rule, evidence in found:
            if (subject, rule) in self._flagged and rule != "fleet_tail":
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

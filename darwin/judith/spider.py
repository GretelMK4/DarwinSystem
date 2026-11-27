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
        self.fleet_cold = get("FLEET_COLD", 30, int)       # cold = first seen at most FLEET_NEW s ago ...
        self.fleet_new = get("FLEET_NEW", 3600)            # ... and at most FLEET_COLD views in the window
        self.fleet_tail_pop = get("FLEET_TAIL_POP", 1, int)  # a product seen by this many others or fewer is tail
        self.fleet_factor = get("FLEET_FACTOR", 4.0)
        self.fleet_floor = get("FLEET_FLOOR", 60, int)     # never trip below this many cold-tail products per slot
        self.fleet_guard = get("FLEET_GUARD", 21600)       # seconds the guard stays up after a trip
        self.fleet_growth = get("FLEET_GROWTH", 1.01)      # most the baseline may grow per slot
        self.fleet_alpha = get("FLEET_ALPHA", 0.02)        # baseline learning rate after warm-up
                                                           # (only in quiet slots)
        self.fleet_warmup = get("FLEET_WARMUP", 48, int)   # slots before the rule may trip. The reference
                                                           # is learned only from warm-up slots after the
                                                           # first popularity WINDOW (when everything
                                                           # still looks rare)
        self.cusum_k = get("FLEET_CUSUM_K", 1.0)           # slow-attack detector: allowance, in reference sd
        self.cusum_h = get("FLEET_CUSUM_H", 0.0)           # ... and trip level, in reference sd (0 = off;
                                                           # 8 caught a slow swarm in the lab, but with
                                                           # fakes as the guard action it cost shoppers)
        self.seal_ttl = get("SEAL_TTL", 21600)             # how long Judith keeps a Spider seal; the same
                                                           # flag may be raised again after this long
        self.shared_uas = get("SHARED_UAS", 4, int)        # an address showing this many User-Agents is
                                                           # treated as shared (office, mobile carrier)
        self.shared_min = get("SHARED_MIN", 0, int)        # on a shared address, an identity (address|UA)
                                                           # that alone opened more products than this is
                                                           # flagged and sealed (0 = same as BREADTH)
        self.crowd_breadth = get("CROWD_BREADTH", 600, int)    # a crowd address is sealed after all
                                                           # past this many different products per window
        self.crowd_alert = environ.get("SPIDER_CROWD_ALERT", "on") == "on"   # a crowd address (more than
                                                           # MAX_IDENTITIES browsers) is flagged, not sealed
        self.fleet_sticky = get("FLEET_STICKY", 0)         # a product shadowed by the guard stays shadowed
                                                           # for cold visitors this long (0 = off)


class Spider:
    def __init__(self, policy=None, flag_log=None, on_flag=None):
        self.policy = policy or Policy()
        self.flag_log = flag_log               # path of a JSON-lines file for people, or None
        self.on_flag = on_flag                 # callback(flag) for the owner's chosen response
        self.flags = []
        self._flagged = {}                     # (subject, rule) -> when it was last raised
        self._views = collections.defaultdict(collections.deque)    # address -> deque of (t, product)
        self._identities = collections.defaultdict(set)             # address -> User-Agents seen
        self._fingerprints = {}                # path -> sha256 at start-up
        self._viewers = collections.defaultdict(collections.deque)  # product -> deque of (t, address)
        self._viewer_n = collections.defaultdict(collections.Counter)  # product -> address -> live views
        self._slot = None                      # fleet rule: start of the current slot
        self._slot_tail = set()                # cold-tail products seen in the current slot
        self.baseline = None                   # learned cold-tail products per slot
        self.guard_until = 0.0
        self._warm_counts = []                 # slot counts seen during warm-up (the frozen reference)
        self.ref_sd = None
        self.cusum = 0.0                       # accumulated excess over the reference, slot by slot
        self._sticky = {}                      # product -> shadow cold visitors until this time
        self.slots = []                        # (slot start, cold-tail count, tripped) for people
        self._lock = threading.Lock()
        self._stop = threading.Event()

    # ---------- what the Spider is told ----------

    def observe(self, address, user_agent, product, t=None, shadowed=False):
        """The shop reports every product-page request here, whatever it answered. `shadowed`: the
        fleet guard answered it with the shadow page, so it must not make the product look popular."""
        t = time.time() if t is None else t
        with self._lock:
            if self.policy.fleet:
                self._fleet_observe(address, product, t, shadowed)
            self._views[address].append((t, product, user_agent))
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

    def _cold(self, address, t):
        """New to the site: first seen at most FLEET_NEW seconds ago, and few views. Padding with
        popular products does not make an address warm; only time does."""
        views = self._views.get(address)
        if not views:
            return True
        return t - views[0][0] <= self.policy.fleet_new and len(views) <= self.policy.fleet_cold

    def _fleet_observe(self, address, product, t, shadowed=False):
        p = self.policy
        if self._slot is None:
            self._slot = t - (t % p.bucket)
        if self._cold(address, t) and self._is_tail(address, product, t):
            self._slot_tail.add(product)
        if not shadowed:
            self._viewers[product].append((t, address))
            self._viewer_n[product][address] += 1

    def _fleet_inspect(self, now, found):
        p = self.policy
        if self._slot is None:
            return
        count = len(self._slot_tail)
        # the limit grows through the slot, so a burst trips early instead of at the slot's end
        elapsed = min(1.0, max(now - self._slot, p.period) / p.bucket)
        limit = max(p.fleet_floor, p.fleet_factor * (self.baseline or 0) * elapsed)
        warm = len(self.slots) >= p.fleet_warmup and self.baseline is not None
        tripped = count > limit and warm
        closing = now - self._slot >= p.bucket
        slow = False
        if closing and warm and self.ref_sd is not None and not tripped and p.cusum_h > 0:
            # slow-attack detector (CUSUM), once per slot. Burst slots are left to the burst limit, and
            # the excess is capped, so that one burst does not keep the guard up for days afterwards.
            self.cusum = min(2 * p.cusum_h * self.ref_sd,
                             max(0.0, self.cusum + count - self.baseline - p.cusum_k * self.ref_sd))
            slow = self.cusum > p.cusum_h * self.ref_sd
        if (tripped or slow) and now >= self.guard_until:
            why = (f"{count} rarely-viewed products opened by cold addresses this slot "
                   f"(baseline {self.baseline or 0:.0f}, limit {limit:.0f})") if tripped else (
                   f"cold-tail views have run above the baseline ({self.baseline:.0f}) for hours "
                   f"(excess {self.cusum:.0f})")
            found.append(("fleet", "fleet_tail", why))
        if tripped or slow:
            self.guard_until = max(self.guard_until, now + p.fleet_guard)
        if closing:                                       # close the slot
            self.slots.append((self._slot, count, tripped or slow))
            if not warm:
                if len(self.slots) > min(p.window / p.bucket, p.fleet_warmup // 2):
                    self._warm_counts.append(count)
                # learn the reference from the warm-up slots only; the first slots after start-up see
                # everything as rare, so the median is used rather than the mean
                ref = sorted(self._warm_counts)
                if ref:
                    self.baseline = float(ref[len(ref) // 2])
                    self.ref_sd = max(1.0, statistics.pstdev(ref)) if len(ref) > 1 else None
            elif not (tripped or slow) and self.cusum == 0.0:
                target = (1 - p.fleet_alpha) * self.baseline + p.fleet_alpha * count
                self.baseline = min(target, max(self.baseline, 1.0) * p.fleet_growth)
            if not (tripped or slow) and (self.ref_sd is None or self.cusum <= p.cusum_h * self.ref_sd or p.cusum_h <= 0):
                self.guard_until = min(self.guard_until, now)   # a quiet slot ends the guard early
            self._slot = now - (now % p.bucket)
            self._slot_tail = set()

    def guarded(self, address, product, now=None):
        """True when the fleet guard is up and this request is a cold address opening a tail product."""
        now = time.time() if now is None else now
        sticky = self._sticky.get(product, 0.0) > now
        if now >= self.guard_until and not sticky:
            return False
        with self._lock:
            return self._cold(address, now) and self._is_tail(address, product, now)

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
                products = {v[1] for v in views}
                if len(products) > p.breadth:
                    found.append((address, "breadth",
                                  f"{len(products)} different products viewed (approved: up to {p.breadth})"))
                    if len(products) > p.crowd_breadth:
                        # even a crowd is bounded: an address that rotates many User-Agents to pass as one
                        # would otherwise copy the whole catalog (lab 2026-11-27, rotator25/400: 100% stolen)
                        found.append((address, "crowd_breadth", f"{len(products)} different products from one "
                                      f"address, even counting it as a crowd (approved: up to {p.crowd_breadth})"))
                    uas = {v[2] for v in views}
                    if len(uas) >= p.shared_uas:              # shared address: judge each browser on its own
                        per = collections.defaultdict(set)
                        for _, product, ua in views:
                            per[ua].add(product)
                        limit = p.shared_min or p.breadth
                        for ua, prods in sorted(per.items()):
                            if len(prods) > limit:
                                found.append((f"{address}|{ua}", "breadth", f"{len(prods)} different products "
                                              f"from one browser on a shared address (approved: up to {limit})"))
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
            last = self._flagged.get((subject, rule))
            if last is not None and rule != "fleet_tail" and now - last < p.seal_ttl:
                continue
            self._flagged[(subject, rule)] = now
            flag = {"t": now, "subject": subject, "rule": rule, "evidence": evidence}
            if rule == "crowd_breadth":
                flag["seal"] = [subject]
            elif rule in ("breadth", "enumeration", "metronome"):
                flag["seal"] = [subject] if "|" in subject else self._seal_subjects(subject)
            elif rule == "many_identities" and p.crowd_alert:
                flag["seal"] = []                      # a crowd (CGNAT) shows many browsers: flag for people only
            self.flags.append(flag)
            new.append(flag)
            if self.flag_log:
                with open(self.flag_log, "a") as f:
                    f.write(json.dumps(flag) + "\n")
            if self.on_flag:
                self.on_flag(flag)
        return new

    def _seal_subjects(self, address):
        """Who a per-address flag should seal. Usually the address. On a shared address (many
        User-Agents: an office, a mobile carrier's CGNAT) sealing the address shows fakes to every
        person behind it, and lets an attacker frame it (Nov 25 findings 20261125-3/-4). There only the
        identities (address|UA) that alone pass the limit are sealed (the identity breadth rule in
        inspect). Every Spider seal lasts SEAL_TTL."""
        p = self.policy
        with self._lock:
            views = list(self._views.get(address, ()))
        uas = {v[2] for v in views}
        if len(uas) < p.shared_uas:
            return [address]
        # The identity breadth rule in inspect seals a browser that alone did a copier's work. Here nobody
        # stands out. A small group of browsers sharing the work evenly is what a UA-rotating copier
        # looks like (Nov 25 warning 20261125-7): seal the address as before, for SEAL_TTL. A crowd (more
        # than MAX_IDENTITIES browsers, as behind a carrier's CGNAT) is flagged for people only when
        # SPIDER_CROWD_ALERT is on, because sealing it shows fakes to every household behind it.
        if p.crowd_alert and len(uas) > p.max_identities:
            return []                      # bounded by the crowd_breadth rule instead
        return [address]

    # ---------- running ----------

    def start(self):
        def loop():
            while not self._stop.wait(self.policy.period):
                self.inspect()
        threading.Thread(target=loop, daemon=True).start()

    def stop(self):
        self._stop.set()

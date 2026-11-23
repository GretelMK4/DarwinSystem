"""
Protected communication between the plants (roadmap phase 3, prototype).

NOT YET WIRED INTO THE SERVERS. This module is the proposed replacement for
darwin/intel.py. It exists so the design can be attacked in simulation
(simulations/models/comms.py) before anything depends on it.

The design
  One-way channels. A Hercules only sends; Judith and Venus only receive from
  Hercules. Nothing flows back, so a compromised receiver cannot reach a sender.

  A key per Hercules. Every Hercules signs with its own Ed25519 private key.
  Receivers hold only the PUBLIC keys of the senders they approve. Whoever
  breaks into a receiver cannot forge a single message, and a stolen Hercules
  key forges that one Hercules and no other.

  Receivers act as watchers of what they are sent, in five ways:

  1. Corroboration decides the size of the response. By default nothing
     happens on one Hercules' word: sealing a visitor needs two witnesses
     (two Hercules, or one Hercules plus something the receiver saw for
     itself; see local_evidence), and a lockdown (Judith) or arming (Venus)
     needs two different Hercules to say "a swarm is sweeping". A visitor
     named by only one Hercules goes on a watch list.
     Hercules sites see different attackers, so reports that differ are
     normal: the test is whether a report is corroborated, never whether all
     reports match.

  2. Missing messages are evidence. Every sender numbers its messages and
     sends a heartbeat on a fixed beat. A gap in the numbers, or silence, is
     flagged. Blocking the alarm becomes an alarm.

  3. Judith and Venus pass each other the ORIGINAL signed messages, one way
     each, unchanged. Each checks the Hercules signature herself, so a
     compromised Judith cannot lie to Venus about what a Hercules said. A
     relayed message is never relayed again. Comparing the two views exposes
     a sender that told them different things under the same number, and a
     receiver whose own channel is being cut.

  4. Public-key signatures (this is why the module needs the `cryptography`
     package: Python's standard library cannot do them).

  5. Hercules reports what attackers choose to show it, so intel is bounded:
     seals earned from intel alone expire; on an address the owner has marked
     as shared by many people, intel only puts a visitor on a watch list; and
     each sender can name only so many visitors per hour.

Two streams per sender
  "warning"  surge reports and heartbeats: go to Judith and Venus
  "intel"    visitor identities and issued fake keys: go to Judith only.
             Venus runs on people's phones and has no need for visitor data.
  Each stream is numbered separately; heartbeats carry the intel number so
  Judith can tell when intel has gone missing.

What this does not do
  - It does not encrypt. Run it over TLS if the contents matter.
  - It does not survive two stolen Hercules keys at the default quorums: two
    keys used together can cause a false lockdown and get up to
    `sender_identity_cap` visitors sealed for `seal_ttl` seconds each.
  - Quorums only mean something if the Hercules sites are independent:
    different hosts, different keys, different operators if possible.
  - Fake-key ("token") reports are accepted from a single sender. A real
    deployment must make sure a token can never collide with a genuine key.
"""
import collections
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

STREAMS = ("warning", "intel")
KINDS = {"surge": "warning", "heartbeat": "warning", "intel": "intel"}


def _canonical(env) -> bytes:
    body = {k: env[k] for k in ("v", "sender", "stream", "seq", "ts", "kind", "payload")}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def digest(env) -> str:
    return hashlib.sha256(_canonical(env)).hexdigest()


class Sender:
    """One Hercules: its own key, its own message numbers."""

    def __init__(self, sender_id, private_key=None):
        self.id = sender_id
        self._key = private_key or Ed25519PrivateKey.generate()
        self._seq = {s: 0 for s in STREAMS}

    @property
    def public_key(self) -> str:
        raw = self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return raw.hex()

    def _message(self, kind, payload, now, seq=None):
        stream = KINDS[kind]
        if seq is None:
            self._seq[stream] += 1
            seq = self._seq[stream]
        env = {"v": 1, "sender": self.id, "stream": stream, "seq": seq, "ts": float(now),
               "kind": kind, "payload": payload}
        env["sig"] = self._key.sign(_canonical(env)).hex()
        return env

    def surge(self, now, targets=()):
        return self._message("surge", {"targets": sorted(targets)}, now)

    def heartbeat(self, now):
        return self._message("heartbeat", {"intel_seq": self._seq["intel"]}, now)

    def intel(self, now, identities=(), tokens=()):
        return self._message("intel", {"identities": list(identities), "tokens": list(tokens)}, now)


class Policy:
    def __init__(self, **over):
        self.max_age = 120.0              # seconds a message stays acceptable
        self.heartbeat_every = 30.0
        self.silence_after = 100.0        # no direct heartbeat for this long = flag
        self.gap_grace = 45.0             # how long a missing number may stay missing before a flag
        self.corroboration_window = 600.0 # reports this close together support each other
        self.seal_quorum = 2              # different witnesses needed to seal one visitor
        self.lockdown_quorum = 2          # different Hercules needed for lockdown / arming
        self.seal_ttl = 3600.0            # an intel seal lasts this long
        self.lockdown_ttl = 1800.0
        self.sender_identity_cap = 200    # visitors one sender may name per hour
        self.shared_rule = True           # intel alone never seals on a shared address
        for k, v in over.items():
            if not hasattr(self, k):
                raise TypeError(f"unknown policy setting: {k}")
            setattr(self, k, v)


class Receiver:
    """
    Judith or Venus. Give it the public keys of the Hercules it approves and call
    receive() for every message, tick() regularly, and relay_out() to feed the peer.

    Results are in:
      actions   what this receiver decided ({"t", "action", "subject", "support"})
      flags     what looks wrong with the communication itself
      sealed    identity -> expiry time     watch: identities being watched
      lockdown_until
    """

    def __init__(self, name, approved, streams=STREAMS, policy=None, is_shared=None):
        self.name = name
        self.policy = policy or Policy()
        self.streams = tuple(streams)
        self._keys = {sid: Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk)) for sid, pk in approved.items()}
        self._is_shared = is_shared or (lambda address: False)
        self._seen = {}                                   # (sender, stream, seq) -> digest
        self._high = collections.defaultdict(int)         # (sender, stream) -> highest number seen
        self._missing = {}                                # (sender, stream, seq) -> time first noticed missing
        self._last_direct = {}                            # sender -> time of last direct message
        self._silent = set()
        self._distrusted = set()
        self._surge = {}                                  # sender -> time of latest surge report
        self._ident = collections.defaultdict(dict)       # identity -> {sender: time}
        self._named = collections.defaultdict(collections.deque)   # sender -> times it named a visitor
        self._to_relay = []
        self._relay_only = {}                             # (sender, stream, seq) -> when a relayed copy arrived first
        self._elevated_at = None
        self._flagged = set()
        self.tokens = set()
        self.actions, self.flags = [], []
        self.sealed, self.watch = {}, set()
        self.lockdown_until = 0.0
        self.rejected = collections.Counter()
        self.started = None

    # ---------- bookkeeping ----------

    def _flag(self, now, kind, subject, detail, once=True):
        if once and (kind, subject) in self._flagged:
            return
        self._flagged.add((kind, subject))
        self.flags.append({"t": now, "flag": kind, "subject": subject, "detail": detail})

    def _act(self, now, action, subject, support):
        self.actions.append({"t": now, "action": action, "subject": subject, "support": sorted(support)})

    def _reject(self, reason):
        self.rejected[reason] += 1
        return "rejected: " + reason

    # ---------- receiving ----------

    def receive(self, env, now, relayed_by=None):
        """Take one message. `relayed_by` names the peer that passed it on, if it did not come directly."""
        if self.started is None:
            self.started = now
        try:
            sender, stream, seq, ts, kind = env["sender"], env["stream"], env["seq"], float(env["ts"]), env["kind"]
            payload, sig = env["payload"], bytes.fromhex(env["sig"])
            if not (isinstance(seq, int) and seq > 0 and isinstance(payload, dict) and env["v"] == 1):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            return self._reject("malformed")
        key = self._keys.get(sender)
        if key is None:
            return self._reject("sender not approved")
        if KINDS.get(kind) != stream or stream not in self.streams:
            return self._reject("wrong stream")
        try:
            key.verify(sig, _canonical(env))
        except InvalidSignature:
            return self._reject("bad signature")
        if abs(now - ts) > self.policy.max_age:
            return self._reject("stale")

        d = digest(env)
        known = self._seen.get((sender, stream, seq))
        if known is not None:
            if known != d:                 # same sender, same number, different content: it told two stories
                self._distrusted.add(sender)
                self._flag(now, "equivocation", sender,
                           f"two different messages numbered {stream} #{seq}; this sender is no longer trusted")
                self._recount(now)
            elif relayed_by is None:       # the direct copy of something a relay delivered first
                self._relay_only.pop((sender, stream, seq), None)
                self._last_direct[sender] = now
            return "duplicate"
        self._seen[(sender, stream, seq)] = d
        self._track_numbers(sender, stream, seq, now, relayed_by)
        if relayed_by is None:
            self._last_direct[sender] = now
            if sender in self._silent:
                self._silent.discard(sender)
                self._flagged.discard(("silent", sender))
            if stream == "warning":
                self._to_relay.append(env)
        if sender in self._distrusted:
            return "accepted (sender distrusted: ignored)"

        if kind == "heartbeat":
            claimed = payload.get("intel_seq", 0)
            if "intel" in self.streams and isinstance(claimed, int):
                for n in range(self._high[(sender, "intel")] + 1, min(claimed, self._high[(sender, "intel")] + 1000) + 1):
                    self._missing.setdefault((sender, "intel", n), now)
                self._high[(sender, "intel")] = max(self._high[(sender, "intel")], claimed)
        elif kind == "surge":
            self._surge[sender] = now
            self._decide_surge(now)
        elif kind == "intel":
            self._take_intel(sender, payload, now)
        return "accepted"

    def _track_numbers(self, sender, stream, seq, now, relayed_by):
        self._missing.pop((sender, stream, seq), None)
        if relayed_by is not None:
            self._relay_only[(sender, stream, seq)] = (now, relayed_by)   # flagged in tick() if no direct copy follows
        high = self._high[(sender, stream)]
        for n in range(high + 1, seq):
            self._missing.setdefault((sender, stream, n), now)
        self._high[(sender, stream)] = max(high, seq)

    def _take_intel(self, sender, payload, now):
        p = self.policy
        named = self._named[sender]
        while named and now - named[0] > 3600.0:
            named.popleft()
        for tok in payload.get("tokens", []):
            if isinstance(tok, str) and len(tok) <= 128:
                self.tokens.add(tok)
        for ident in payload.get("identities", []):
            if not isinstance(ident, str) or len(ident) > 400:
                continue
            if len(named) >= p.sender_identity_cap:
                self._flag(now, "over_cap", sender,
                           f"named more than {p.sender_identity_cap} visitors in an hour; the rest are ignored")
                break
            named.append(now)
            self._ident[ident][sender] = now
            self._decide_identity(ident, now)

    def local_evidence(self, identity, now):
        """
        The receiver saw this visitor do something suspicious ITSELF (not enough to seal on its own).
        That counts as one witness, so one Hercules report plus the receiver's own eyes can seal.
        It cannot be forged over the network: only the receiver's own code calls this.
        """
        self._ident[identity]["local:" + self.name] = now
        self._decide_identity(identity, now)

    # ---------- deciding ----------

    def _support(self, reports, now):
        w = self.policy.corroboration_window
        return {s for s, t in reports.items() if now - t <= w and s not in self._distrusted}

    def _decide_identity(self, ident, now):
        p = self.policy
        support = self._support(self._ident[ident], now)
        address = ident.split("|", 1)[0]
        if p.shared_rule and self._is_shared(address):
            if ident not in self.watch:
                self.watch.add(ident)
                self._act(now, "watch (shared address: intel alone never seals)", ident, support)
            return
        if len(support) >= p.seal_quorum:
            if self.sealed.get(ident, 0) <= now:
                self._act(now, "seal", ident, support)
            self.sealed[ident] = now + p.seal_ttl
        elif ident not in self.watch:
            self.watch.add(ident)
            self._act(now, "watch (not yet corroborated)", ident, support)

    def _decide_surge(self, now):
        support = self._support(self._surge, now)
        if len(support) >= self.policy.lockdown_quorum:
            if self.lockdown_until <= now:
                self._act(now, "lockdown" if "intel" in self.streams else "arm", "all", support)
            self.lockdown_until = now + self.policy.lockdown_ttl
        elif support and (self._elevated_at is None or now - self._elevated_at > self.policy.corroboration_window):
            self._elevated_at = now
            self._act(now, "elevated (surge not yet corroborated)", "all", support)

    def _recount(self, now):
        """A sender was just distrusted: withdraw whatever rested on its word alone."""
        if len(self._support(self._surge, now)) < self.policy.lockdown_quorum and self.lockdown_until > now:
            self.lockdown_until = now
            self._act(now, "lockdown withdrawn (support came from a distrusted sender)", "all", [])
        for ident in [i for i, until in self.sealed.items() if until > now]:
            if len(self._support(self._ident[ident], now)) < self.policy.seal_quorum:
                self.sealed[ident] = now
                self._act(now, "seal withdrawn (support came from a distrusted sender)", ident, [])

    # ---------- the slow cycle ----------

    def tick(self, now):
        """Look for what has NOT arrived: gaps in the numbering and senders gone quiet."""
        if self.started is None:
            self.started = now
        p = self.policy
        for (sender, stream, seq), since in list(self._missing.items()):
            if now - since > p.gap_grace:
                del self._missing[(sender, stream, seq)]
                self._flag(now, "gap", f"{sender} {stream} #{seq}",
                           f"{stream} #{seq} from {sender} never arrived", once=True)
        for (sender, stream, seq), (since, via) in list(self._relay_only.items()):
            if now - since > p.gap_grace:
                del self._relay_only[(sender, stream, seq)]
                self._flag(now, "missing_direct", sender,
                           f"{stream} #{seq} from {sender} reached {self.name} only through {via}: "
                           "the direct channel dropped it")
        for sender in self._keys:
            last = self._last_direct.get(sender, self.started)
            if now - last > p.silence_after and sender not in self._silent:
                self._silent.add(sender)
                self._flag(now, "silent", sender, f"nothing direct from {sender} for {now - last:.0f} s")
        if self._keys and len(self._silent) == len(self._keys):
            self._flag(now, "blind", self.name, "every approved sender is silent: assume the channel is cut")

    def is_sealed(self, identity, now) -> bool:
        return self.sealed.get(identity, 0) > now

    def in_lockdown(self, now) -> bool:
        return self.lockdown_until > now

    # ---------- relaying to the peer ----------

    def relay_out(self):
        """Original signed warning-stream messages this receiver got DIRECTLY, for the peer. Never re-relays."""
        out, self._to_relay = self._to_relay, []
        return out

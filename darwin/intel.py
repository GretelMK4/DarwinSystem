"""
Signed intel messages between the plants.

Hercules tells Judith what it has caught (visitor identities, fake keys it
handed out, "a swarm is sweeping" surge reports). Whoever can forge such a
message can make Judith seal innocent visitors or trigger a lockdown, so every
message is authenticated:

    envelope = {"sender", "ts", "nonce", "payload", "mac"}
    mac      = HMAC-SHA256(shared key, canonical JSON of the other four fields)

The receiver rejects a message when the MAC is wrong, when it is older than
`max_age` seconds (or dated in the future), or when its nonce was already seen
(replay).

What this is and is not
  - It proves a message came from someone holding the shared key and was not
    changed on the way. It does NOT encrypt anything: run it over a private
    network or TLS if the contents matter.
  - With one shared key (the default), a stolen key forges intel for the whole
    deployment, under any sender name. Give each plant its own key instead
    (Verifier(keys={"hercules-1": k1, ...}), env DARWIN_INTEL_KEYS): the sender
    name is then bound to its key, so one stolen key speaks for one plant only.
  - A message can name its recipient (sign(..., to="judith")). A receiver built
    with me="judith" refuses messages addressed elsewhere or to nobody, so a
    message captured on its way to Venus cannot be replayed into Judith.
  - IntelStore (below) decides what an accepted report is worth: identities
    expire, one message and one sender can only add so much, and with
    quorum=2 an identity counts only once two different plants reported it.
"""
import hashlib
import hmac
import json
import os
import secrets
import threading
import time

MIN_KEY_BYTES = 16
MAX_MESSAGE_BYTES = 1_000_000      # receivers should refuse larger request bodies
ENV_KEY = "DARWIN_INTEL_KEY"
ENV_KEYS = "DARWIN_INTEL_KEYS"     # per-plant keys: "hercules-1=<secret>,hercules-2=<secret>"


class IntelError(ValueError):
    """The message must not be trusted."""


def new_key() -> str:
    """A fresh random shared key (hex). Generate one per deployment; keep it out of source control."""
    return secrets.token_hex(32)


def key_from_env(environ=os.environ) -> bytes:
    """Read the shared key from DARWIN_INTEL_KEY. Raises IntelError if missing or too short."""
    raw = environ.get(ENV_KEY, "")
    if len(raw.encode()) < MIN_KEY_BYTES:
        raise IntelError(f"{ENV_KEY} must be set to a secret of at least {MIN_KEY_BYTES} bytes "
                         f"(generate one with: python -m darwin.intel)")
    return raw.encode()


def keys_from_env(environ=os.environ) -> dict:
    """Per-plant keys from DARWIN_INTEL_KEYS ("name=secret,name=secret"); {} when unset."""
    keys = {}
    for part in filter(None, (x.strip() for x in environ.get(ENV_KEYS, "").split(","))):
        name, _, secret = part.partition("=")
        if not name or len(secret.encode()) < MIN_KEY_BYTES:
            raise IntelError(f"{ENV_KEYS}: every entry must be name=secret with a secret of at least "
                             f"{MIN_KEY_BYTES} bytes")
        keys[name] = secret.encode()
    return keys


def _canonical(sender, ts, nonce, payload, to=None) -> bytes:
    fields = {"sender": sender, "ts": ts, "nonce": nonce, "payload": payload}
    if to is not None:
        fields["to"] = to
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()


def sign(payload: dict, key: bytes, sender: str = "hercules", now: float = None, to: str = None) -> dict:
    """Wrap `payload` in a signed envelope (optionally addressed to one receiver)."""
    ts = float(time.time() if now is None else now)
    nonce = secrets.token_hex(12)
    mac = hmac.new(key, _canonical(sender, ts, nonce, payload, to), hashlib.sha256).hexdigest()
    env = {"sender": sender, "ts": ts, "nonce": nonce, "payload": payload, "mac": mac}
    if to is not None:
        env["to"] = to
    return env


# ---------- fake keys a receiver can check (2026-11-27, finding 20261125E-11) ----------
#
# A plant reports the fake keys it handed out, and Judith seals whoever uses one. A compromised plant could
# report a REAL customer's API key and have that customer sealed on its word alone. So a plant mints its fake
# keys as <random part><tag>, where tag = HMAC(token key, random part), the token key being derived from the
# plant's own intel key. A receiver accepts a reported token only if its tag checks out under the sender's
# key. Real keys are random, so a compromised plant cannot make one of them check out.

TOKEN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
TOKEN_RAND, TOKEN_TAG = 16, 12


def _token_key(key: bytes) -> bytes:
    return hmac.new(key, b"darwin-token-v1", hashlib.sha256).digest()


def _tag(key: bytes, rand: str) -> str:
    digest = hmac.new(_token_key(key), rand.encode(), hashlib.sha256).digest()
    return "".join(TOKEN_ALPHABET[b % len(TOKEN_ALPHABET)] for b in digest[:TOKEN_TAG])


def mint_token(key: bytes, r) -> str:
    """A 28-character fake key in the usual alphanumeric shape, checkable by whoever holds `key`.
    `r` is a random.Random (so a plant's pages stay deterministic)."""
    rand = "".join(r.choice(TOKEN_ALPHABET) for _ in range(TOKEN_RAND))
    return rand + _tag(key, rand)


def token_ok(key: bytes, token: str) -> bool:
    """Did the holder of `key` mint this token?"""
    if not isinstance(token, str) or len(token) != TOKEN_RAND + TOKEN_TAG:
        return False
    return hmac.compare_digest(token[TOKEN_RAND:], _tag(key, token[:TOKEN_RAND]))


class Verifier:
    """Checks envelopes and remembers recent nonces so a captured message cannot be replayed."""

    def __init__(self, key: bytes = None, max_age: float = 60.0, keys: dict = None, me: str = None):
        """`key`: one shared key. `keys`: {sender: key}, one per plant (preferred; overrides `key`).
        `me`: this receiver's name; when set, only messages addressed to it are accepted."""
        self.keys = dict(keys or {})
        if not self.keys and (key is None or len(key) < MIN_KEY_BYTES):
            raise IntelError(f"intel key must be at least {MIN_KEY_BYTES} bytes")
        if any(len(k) < MIN_KEY_BYTES for k in self.keys.values()):
            raise IntelError(f"every per-plant intel key must be at least {MIN_KEY_BYTES} bytes")
        self.key, self.max_age, self.me = key, max_age, me
        self._seen = {}                      # (sender, nonce) -> message timestamp
        self._lock = threading.Lock()

    def verify(self, envelope, now: float = None) -> dict:
        """Return the payload if the envelope is authentic, fresh and new; raise IntelError otherwise."""
        now = time.time() if now is None else now
        try:
            sender, ts, nonce = envelope["sender"], float(envelope["ts"]), envelope["nonce"]
            payload, mac = envelope["payload"], envelope["mac"]
        except (KeyError, TypeError, ValueError):
            raise IntelError("malformed envelope")
        to = envelope.get("to")
        if not (isinstance(sender, str) and isinstance(nonce, str) and isinstance(mac, str)
                and isinstance(payload, dict) and (to is None or isinstance(to, str))):
            raise IntelError("malformed envelope")
        if self.keys:
            key = self.keys.get(sender)
            if key is None:
                raise IntelError("unknown sender")
        else:
            key = self.key
        expected = hmac.new(key, _canonical(sender, ts, nonce, payload, to), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, mac):
            raise IntelError("bad signature")
        if self.me is not None and to != self.me:
            raise IntelError("wrong recipient")
        if abs(now - ts) > self.max_age:
            raise IntelError("stale message")
        with self._lock:
            for old in [n for n, t in self._seen.items() if now - t > self.max_age]:
                del self._seen[old]
            # keyed by sender too: otherwise one plant could block another plant's honest message by
            # signing its own first with the same (visible) nonce
            if (sender, nonce) in self._seen:
                raise IntelError("replayed message")
            self._seen[(sender, nonce)] = ts
        return payload


class IntelStore:
    """What accepted reports are worth.

    Each identity remembers which senders reported it and when. It counts as known
    while at least `quorum` different senders reported it within the last `ttl`
    seconds. One message adds at most `max_per_message` identities, and one sender
    holds at most `per_sender` live identities (its oldest are dropped first), so a
    single compromised plant can neither keep a forgery alive forever nor flood
    honest reports out of the store.
    """

    def __init__(self, quorum=1, ttl=86400.0, max_per_message=5000, per_sender=20000):
        self.quorum, self.ttl = quorum, ttl
        self.max_per_message, self.per_sender = max_per_message, per_sender
        self._by_id = {}                       # identity -> {sender: last reported t}
        self._by_sender = {}                   # sender -> {identity: t} (insertion = age order)
        self._lock = threading.Lock()

    def add(self, sender, identities, now=None):
        now = time.time() if now is None else now
        with self._lock:
            mine = self._by_sender.setdefault(sender, {})
            for ident in list(identities)[:self.max_per_message]:
                mine.pop(ident, None)
                mine[ident] = now
                self._by_id.setdefault(ident, {})[sender] = now
            while len(mine) > self.per_sender:
                old = next(iter(mine))
                del mine[old]
                senders = self._by_id.get(old, {})
                senders.pop(sender, None)
                if not senders:
                    self._by_id.pop(old, None)

    def witnesses(self, ident, now=None):
        now = time.time() if now is None else now
        with self._lock:
            return sum(1 for t in self._by_id.get(ident, {}).values() if now - t <= self.ttl)

    def known(self, ident, now=None):
        return self.witnesses(ident, now) >= self.quorum

    def __len__(self):
        return len(self._by_id)

    def __contains__(self, ident):
        return self.known(ident)


if __name__ == "__main__":
    print(new_key())

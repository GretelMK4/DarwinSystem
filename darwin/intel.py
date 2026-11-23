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
  - One shared key for all plants. A stolen key forges intel for the whole
    deployment. Per-plant keys, rotation and transport protection are phase 3
    on the roadmap.
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


def _canonical(sender, ts, nonce, payload) -> bytes:
    return json.dumps({"sender": sender, "ts": ts, "nonce": nonce, "payload": payload},
                      sort_keys=True, separators=(",", ":")).encode()


def sign(payload: dict, key: bytes, sender: str = "hercules", now: float = None) -> dict:
    """Wrap `payload` in a signed envelope."""
    ts = float(time.time() if now is None else now)
    nonce = secrets.token_hex(12)
    mac = hmac.new(key, _canonical(sender, ts, nonce, payload), hashlib.sha256).hexdigest()
    return {"sender": sender, "ts": ts, "nonce": nonce, "payload": payload, "mac": mac}


class Verifier:
    """Checks envelopes and remembers recent nonces so a captured message cannot be replayed."""

    def __init__(self, key: bytes, max_age: float = 60.0):
        if len(key) < MIN_KEY_BYTES:
            raise IntelError(f"intel key must be at least {MIN_KEY_BYTES} bytes")
        self.key, self.max_age = key, max_age
        self._seen = {}                      # nonce -> message timestamp
        self._lock = threading.Lock()

    def verify(self, envelope, now: float = None) -> dict:
        """Return the payload if the envelope is authentic, fresh and new; raise IntelError otherwise."""
        now = time.time() if now is None else now
        try:
            sender, ts, nonce = envelope["sender"], float(envelope["ts"]), envelope["nonce"]
            payload, mac = envelope["payload"], envelope["mac"]
        except (KeyError, TypeError, ValueError):
            raise IntelError("malformed envelope")
        if not (isinstance(sender, str) and isinstance(nonce, str) and isinstance(mac, str)
                and isinstance(payload, dict)):
            raise IntelError("malformed envelope")
        expected = hmac.new(self.key, _canonical(sender, ts, nonce, payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, mac):
            raise IntelError("bad signature")
        if abs(now - ts) > self.max_age:
            raise IntelError("stale message")
        with self._lock:
            for old in [n for n, t in self._seen.items() if now - t > self.max_age]:
                del self._seen[old]
            if nonce in self._seen:
                raise IntelError("replayed message")
            self._seen[nonce] = ts
        return payload


if __name__ == "__main__":
    print(new_key())

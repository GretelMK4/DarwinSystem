"""Signed intel: only authentic, fresh, first-time messages are accepted."""
import copy

import pytest

from darwin import intel

KEY = b"k" * 32
PAYLOAD = {"identities": ["bot-1"], "tokens": ["abc"], "surge": True}


def test_round_trip():
    assert intel.Verifier(KEY).verify(intel.sign(PAYLOAD, KEY)) == PAYLOAD


def test_wrong_key_rejected():
    with pytest.raises(intel.IntelError, match="bad signature"):
        intel.Verifier(b"x" * 32).verify(intel.sign(PAYLOAD, KEY))


@pytest.mark.parametrize("field,value", [("payload", {"identities": ["innocent-shopper"]}),
                                         ("sender", "someone-else"), ("ts", 1.0), ("nonce", "0" * 24)])
def test_tampering_rejected(field, value):
    env = copy.deepcopy(intel.sign(PAYLOAD, KEY))
    env[field] = value
    with pytest.raises(intel.IntelError, match="bad signature"):
        intel.Verifier(KEY).verify(env)


def test_replay_rejected():
    v, env = intel.Verifier(KEY), intel.sign(PAYLOAD, KEY)
    v.verify(env)
    with pytest.raises(intel.IntelError, match="replayed"):
        v.verify(env)


def test_stale_and_future_rejected():
    v = intel.Verifier(KEY, max_age=60)
    for when in (1000.0 - 61, 1000.0 + 61):
        with pytest.raises(intel.IntelError, match="stale"):
            v.verify(intel.sign(PAYLOAD, KEY, now=when), now=1000.0)


@pytest.mark.parametrize("bad", [None, [], "text", {}, {"payload": {}, "mac": "x"},
                                 {"sender": 1, "ts": 1, "nonce": "n", "payload": {}, "mac": "m"},
                                 {"sender": "s", "ts": "soon", "nonce": "n", "payload": {}, "mac": "m"},
                                 {"sender": "s", "ts": 1, "nonce": "n", "payload": [], "mac": "m"}])
def test_malformed_rejected(bad):
    with pytest.raises(intel.IntelError):
        intel.Verifier(KEY).verify(bad)


def test_short_keys_refused():
    with pytest.raises(intel.IntelError):
        intel.Verifier(b"short")
    with pytest.raises(intel.IntelError):
        intel.key_from_env({})
    assert intel.key_from_env({intel.ENV_KEY: intel.new_key()})

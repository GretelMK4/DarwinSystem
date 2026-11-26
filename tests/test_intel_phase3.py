"""Phase 3 intel: per-plant keys, recipients, quorum, expiry and caps (nightly 2026-11-25 evening)."""
import pytest

from darwin import intel
from darwin.judith import shop

K1, K2, K3 = b"1" * 32, b"2" * 32, b"3" * 32
KEYS = {"hercules-1": K1, "hercules-2": K2, "hercules-3": K3}
P = {"identities": ["a|ua"]}


def test_per_plant_key_binds_the_sender_name():
    v = intel.Verifier(keys=KEYS)
    assert v.verify(intel.sign(P, K1, sender="hercules-1")) == P
    with pytest.raises(intel.IntelError, match="bad signature"):     # hercules-1's key cannot speak as hercules-2
        v.verify(intel.sign(P, K1, sender="hercules-2"))
    with pytest.raises(intel.IntelError, match="unknown sender"):
        v.verify(intel.sign(P, K1, sender="stranger"))


def test_recipient_binding_stops_cross_replay():
    judith, venus = intel.Verifier(keys=KEYS, me="judith"), intel.Verifier(keys=KEYS, me="venus")
    env = intel.sign(P, K2, sender="hercules-2", to="venus")
    assert venus.verify(env) == P
    with pytest.raises(intel.IntelError, match="wrong recipient"):
        judith.verify(env)
    with pytest.raises(intel.IntelError, match="wrong recipient"):    # unaddressed is refused too
        judith.verify(intel.sign(P, K2, sender="hercules-2"))
    env["to"] = "judith"                                             # re-addressing breaks the signature
    with pytest.raises(intel.IntelError, match="bad signature"):
        judith.verify(env)


def test_quorum_needs_two_different_senders():
    s = intel.IntelStore(quorum=2, ttl=100)
    s.add("hercules-1", ["x"], now=0)
    s.add("hercules-1", ["x"], now=1)                                # the same witness twice is one witness
    assert not s.known("x", now=2)
    s.add("hercules-2", ["x"], now=3)
    assert s.known("x", now=4) and "x" not in intel.IntelStore()


def test_reports_expire():
    s = intel.IntelStore(quorum=1, ttl=100)
    s.add("hercules-1", ["x"], now=0)
    assert s.known("x", now=99) and not s.known("x", now=101)


def test_a_flooding_sender_cannot_evict_honest_reports():
    s = intel.IntelStore(quorum=1, max_per_message=10, per_sender=50)
    s.add("hercules-2", ["real-bot"], now=0)
    for i in range(100):
        s.add("hercules-1", [f"junk-{i}-{j}" for j in range(20)], now=1)   # 20 per message, cut to 10
    assert s.known("real-bot", now=2)
    assert len(s) == 51                                              # 50 junk (its own oldest dropped) + 1


def test_keys_from_env():
    assert intel.keys_from_env({}) == {}
    assert intel.keys_from_env({intel.ENV_KEYS: "a=" + "x" * 16 + ", b=" + "y" * 16}) == {
        "a": b"x" * 16, "b": b"y" * 16}
    with pytest.raises(intel.IntelError):
        intel.keys_from_env({intel.ENV_KEYS: "a=short"})


def test_shop_refuses_quorum_two_with_a_shared_key():
    with pytest.raises(intel.IntelError, match="per-plant keys"):
        shop.make_verifier({intel.ENV_KEY: "s" * 32}, quorum=2)
    assert shop.make_verifier({intel.ENV_KEY: "s" * 32}, quorum=1).keys == {}
    v = shop.make_verifier({intel.ENV_KEYS: "hercules-1=" + "1" * 32}, quorum=2, me="judith")
    assert v.me == "judith" and set(v.keys) == {"hercules-1"}

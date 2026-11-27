"""Regression tests from the 2026-11-27 nightly lab. Each attacker built tonight stays here."""
import hashlib
import hmac
import random

from darwin.judith import shop


def _public_code_fake(n):
    """What an attacker could compute from the public code before the shadow secret (release behaviour)."""
    r = random.Random("FAKE" + str(n))
    name = f"{r.choice(shop.ADJ)} {r.choice(shop.NOUN)} {r.randint(100, 999)}"
    return name


def test_second_opinion_cannot_recompute_the_shadow_from_public_code():
    hits = sum(_public_code_fake(n) in shop.item_page(n, fake=True) for n in range(1, 501))
    assert hits <= 5                      # chance collisions only (1 in 9,000 per product)


def test_shadow_is_stable_and_keyed_by_the_secret(monkeypatch):
    assert shop.item_page(42, fake=True) == shop.item_page(42, fake=True)
    assert shop.item_page(42, fake=True) != shop.item_page(42)
    a = shop._load_shadow_secret({"DARWIN_SHADOW_SECRET": "a" * 32})
    assert a == b"a" * 32


def test_shadow_secret_persists_across_restarts(tmp_path, monkeypatch):
    monkeypatch.setattr(shop, "results_path", lambda name: str(tmp_path / name))
    first = shop._load_shadow_secret({})
    assert shop._load_shadow_secret({}) == first and len(first) >= 32
    assert (tmp_path / "shadow_secret").stat().st_mode & 0o077 == 0


# ---------------- Spider seals: lifetime and shared addresses (20261125-3, -4, -8) ----------------

from darwin.judith.spider import Policy, Spider   # noqa: E402


def _carrier(s, t=0.0, households=60, uas=60):
    """Shoppers behind one carrier address, each with its own browser version, 3 products each."""
    for h in range(households):
        for k in range(3):
            t += 40
            s.observe("100.64.0.1", f"Mozilla/5.0 build-{h % uas}", 1 + (h * 7 + k * 911) % 2900, t)
    return t


def test_attacker_on_a_carrier_address_is_sealed_alone():
    s = Spider(Policy({"SPIDER_METRONOME_CV": "0"}))
    t = _carrier(s)
    for i in range(160):                                   # one copier behind the same carrier address
        t += 41 + i % 9
        s.observe("100.64.0.1", "python-requests/2.32", 3000 - i, t)
    flags = [f for f in s.inspect(now=t) if f["rule"] == "breadth"]
    assert flags and flags[0]["seal"] == ["100.64.0.1|python-requests/2.32"]


def test_ua_rotation_on_one_address_still_seals_the_address():
    s = Spider(Policy({"SPIDER_BREADTH": "50"}))
    for i in range(51):
        s.observe("10.9.9.9", f"browser-{i % 5}", (i * 613) % 6000 + 1, i * (20 + i % 7))
    flag = [f for f in s.inspect(now=2000) if f["rule"] == "breadth"][0]
    assert flag["seal"] == ["10.9.9.9"]


def test_spider_seal_expires_and_can_be_raised_again(monkeypatch):
    monkeypatch.setattr(shop, "SPIDER_MODE", "seal")
    monkeypatch.setattr(shop, "SPIDER_SEALED", {})
    sp = Spider(Policy({"SPIDER_BREADTH": "50", "SPIDER_SEAL_TTL": "3600"}), on_flag=shop.spider_flag)
    monkeypatch.setattr(shop, "SPIDER", sp)
    for i in range(51):
        sp.observe("10.9.9.9", "UA", (i * 613) % 6000 + 1, i * 21.0 + (i % 7))
    assert [f["rule"] for f in sp.inspect(now=1200)] == ["breadth"]
    assert shop.spider_sealed("10.9.9.9", "10.9.9.9|UA", 1300)
    assert not shop.spider_sealed("10.9.9.9", "10.9.9.9|UA", 1200 + 3601)        # 6 h by default, 1 h here
    assert sp.inspect(now=1250) == []                                              # not raised twice ...
    assert [f["rule"] for f in sp.inspect(now=1200 + 3601)] == ["breadth"]         # ... until the seal ran out

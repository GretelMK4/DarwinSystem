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
